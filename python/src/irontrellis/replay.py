"""The replay reducer (spec 01 §D.5–D.6): one event at a time, in the exact check
order of the reference engine, over a :class:`ReplayState`. Chain hashes come
from the incremental history hasher; a rejected event never touches the state.
Signed transitions are delegated to the authority engine through
:class:`ReplayHooks`, and format-1 control events are checked here against the
owner keys in force at their position (docs/HISTORY-FORMAT.md §7, ``owner_keys_at``).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .canonical import CanonicalError
from .events import CONTROL_EVENT_TYPES, format_of_schema_version, legacy_projection, validate_event
from .hashing import LEGACY_FORMAT, TRELLIS_FORMAT
from .owner_keys import control_signature_failure, owner_keys_at
from .state import ReplayHooks, ReplayState, apply_transition

REPLAY_VERSION = "continuity-replay/0.2"


@dataclass(frozen=True)
class ReplayResult:
    status: str  # ACCEPTED | REJECTED
    state: ReplayState | None = None
    head: dict[str, Any] | None = None
    event_count: int = 0
    code: str | None = None
    position: int | None = None
    reason: str | None = None

    @property
    def accepted(self) -> bool:
        return self.status == "ACCEPTED"


@dataclass(frozen=True)
class ApplyResult:
    ok: bool
    event: dict[str, Any] | None = None
    head: dict[str, Any] | None = None
    code: str | None = None
    reason: str | None = None


def _rejected(code: str, reason: str) -> ApplyResult:
    return ApplyResult(False, None, None, code, reason)


def detect_format(events: list[Any]) -> str | None:
    """Which format a raw history claims, read loosely from the genesis ``versions.eventSchemaVersion``."""
    if not events or not isinstance(events[0], dict):
        return None
    data = events[0].get("data")
    if not isinstance(data, dict):
        return None
    versions = data.get("versions")
    if not isinstance(versions, dict):
        return None
    return format_of_schema_version(versions.get("eventSchemaVersion"))


def _control_authorization_failure(state: ReplayState, event: dict[str, Any], position: int) -> str | None:
    """docs/HISTORY-FORMAT.md §7: every format-1 control event is signed, over the head *before* it, by an owner key in force at its
    position (``owner_keys_at``: the genesis set until the first OWNER_KEYS_ROTATED, whose own signature is checked
    against the set before it)."""
    return control_signature_failure(
        event, state.genesis["domain"], None if position == 0 else {"hash": state.head["hash"], "position": state.head["position"]},
        owner_keys_at(state, position), state.hash_algorithm)


def default_hooks() -> ReplayHooks:
    from .authority import validate_administrative_transition, validate_intent_admission_transition
    return ReplayHooks(validate_intent_admission_transition, validate_administrative_transition)


_DEFAULT_HOOKS: ReplayHooks | None = None


def _hooks(hooks: ReplayHooks | None) -> ReplayHooks:
    global _DEFAULT_HOOKS
    if hooks is not None:
        return hooks
    if _DEFAULT_HOOKS is None:
        _DEFAULT_HOOKS = default_hooks()
    return _DEFAULT_HOOKS


def apply_event(state: ReplayState, raw: Any, hooks: ReplayHooks | None = None) -> ApplyResult:
    """Validate and apply one raw event at the next position (spec 01 §G.10 check order).
    On failure the state is unchanged."""
    hooks = _hooks(hooks)
    position = len(state.events)
    # Inside a migrated prefix the transition sees the legacy shadow: source domain, keccak, and the source's pre-event head.
    shadow = state.shadow if state.shadow is not None and 1 <= position <= state.shadow.until else None
    validation = validate_event(raw, state.format, position, shadow is not None)
    if not validation.ok:
        return _rejected(validation.code or "INVALID_INPUT", validation.reason or "")
    event = validation.event
    assert event is not None
    if position > 0 and event["type"] == "DEPLOYMENT_INITIALIZED":
        return _rejected("GENESIS_DUPLICATE", "a second genesis is not allowed")
    if event["id"] in state.event_positions_by_id:
        return _rejected("EVENT_ID_DUPLICATE", f"event id {event['id']} already accepted")
    if state.last_timestamp is not None and event["timestamp"] < state.last_timestamp:
        return _rejected("EVENT_TIME_REGRESSION", "timestamps must not decrease")
    if state.format == TRELLIS_FORMAT and event["type"] in CONTROL_EVENT_TYPES:
        failure = _control_authorization_failure(state, event, position)
        if failure is not None:
            return _rejected("CONTROL_AUTHORIZATION_INVALID", failure)
    # Hash into a clone so a rejected transition leaves the running hasher untouched.
    hasher = state.hasher.clone()
    try:
        history_hash = hasher.push(event)
    except CanonicalError as error:
        return _rejected("INVALID_INPUT", error.reason)
    next_head = {"hash": history_hash, "position": position, "canonicalTime": event["timestamp"]}
    shadow_hasher = shadow_head = None
    if shadow is not None:
        shadow_hasher = shadow.hasher.clone()
        try:
            shadow_hash = shadow_hasher.push(legacy_projection(event))
        except CanonicalError as error:
            return _rejected("INVALID_INPUT", error.reason)
        if position == shadow.until and shadow_hash != shadow.expected_hash:
            return _rejected("TRANSITION_INVALID", "the re-recorded prefix does not reproduce migratedFrom.historyHash")
        shadow_head = {"hash": shadow_hash, "position": position, "canonicalTime": event["timestamp"]}
    failure = apply_transition(shadow.view if shadow is not None else state, event, position, shadow_head if shadow_head is not None else next_head, hooks)
    if failure is not None:
        return _rejected("TRANSITION_INVALID", failure)
    if shadow is not None and shadow_hasher is not None and shadow_head is not None:
        shadow.hasher = shadow_hasher
        shadow.hashes.append(shadow_head["hash"])
        shadow.view.head = shadow_head
    state.hasher = hasher
    state.events.append(event)
    state.event_history_hashes.append(history_hash)
    state.event_positions_by_id[event["id"]] = position
    state.last_timestamp = event["timestamp"]
    state.head = next_head
    return ApplyResult(True, event, next_head)


def incomplete_migration(state: ReplayState) -> tuple[str, str] | None:
    """A *completed* replay of a migrated history must have consumed the whole declared
    legacy prefix (docs/HISTORY-FORMAT.md §11); a shorter history is rejected with ``(code, reason)``.
    :func:`apply_event` stays incremental so the prefix can be written event by event."""
    migrated = state.genesis.get("migratedFrom") if isinstance(state.genesis, dict) else None
    until = migrated.get("position") if isinstance(migrated, dict) else None
    if isinstance(until, int) and len(state.events) > 0 and len(state.events) - 1 < until:
        return ("TRANSITION_INVALID", "migrated prefix incomplete")
    return None


def replay_from(state: ReplayState, events: list[Any], hooks: ReplayHooks | None = None) -> ReplayResult:
    """Continue replaying ``events`` onto ``state``; rejection positions are absolute.
    A completed replay of a migrated history whose head is still inside the declared
    prefix is rejected (see :func:`incomplete_migration`), exactly as the Node engine does."""
    hooks = _hooks(hooks)
    for raw in events:
        result = apply_event(state, raw, hooks)
        if not result.ok:
            return ReplayResult("REJECTED", code=result.code, position=len(state.events), reason=result.reason)
    if len(state.events) == 0:
        return ReplayResult("REJECTED", code="GENESIS_REQUIRED")
    incomplete = incomplete_migration(state)
    if incomplete is not None:
        return ReplayResult("REJECTED", code=incomplete[0], position=len(state.events), reason=incomplete[1])
    return ReplayResult("ACCEPTED", state, state.head, len(state.events))


def replay(events: Any, hooks: ReplayHooks | None = None) -> ReplayResult:
    """Replay a raw history from scratch; the format is detected from the genesis (absent or malformed → legacy rules decide the rejection; a string
    ``eventSchemaVersion`` this package does not implement, such as the format-2 one, is UNSUPPORTED_VERSION at position 0)."""
    if not isinstance(events, list):
        return ReplayResult("REJECTED", code="INVALID_INPUT", reason="events must be an array")
    return replay_from(ReplayState(detect_format(events) or LEGACY_FORMAT), events, hooks)


def replay_portable(operation_version: Any, events: Any) -> ReplayResult:
    """The legacy ``replayPortable`` façade: the operation version must be ``continuity-replay/0.2``."""
    if operation_version != REPLAY_VERSION:
        return ReplayResult("REJECTED", code="UNSUPPORTED_VERSION", reason="unsupported replay operation version")
    return replay(events)
