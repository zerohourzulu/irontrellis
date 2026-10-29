"""Result shaping for the authority engine: evidence references, their exact
ordering, failure sorting and the bounded result envelopes (spec 02 §6).

Every evidence list is "events matching a predicate, plus the head event,
sorted by event id (byte order) and de-duplicated" — the head therefore
appears even when its type is outside the predicate. The ordering is by id
string, not by position, because that is what the legacy engine emits.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .hashing import TRELLIS_FORMAT

MAX_RESULT_EVIDENCE = 4096
NO_IDS: list[str] = []


def compare_ids(left: str, right: str) -> int:
    """Code-point order = UTF-8 byte order for well-formed strings."""
    return -1 if left < right else 1 if left > right else 0


def compare_id_sequences(left: list[str], right: list[str]) -> int:
    for a, b in zip(left, right):
        c = compare_ids(a, b)
        if c != 0:
            return c
    return len(left) - len(right)


def evidence_key(reference: dict[str, Any]) -> tuple:
    return (reference["eventId"], reference["eventType"], reference["position"], reference["historyHash"])


FAILURE_RANK = {
    "PROHIBITED": 0, "REVOKED": 1, "NOT_YET_VALID": 2, "EXPIRED": 3, "MISSING_INTERSECTION": 4, "ACTION_NOT_ALLOWED": 5,
    "RESOURCE_NOT_ALLOWED": 6, "AMOUNT_REQUIRED": 7, "AMOUNT_EXCEEDED": 8, "CUMULATIVE_AMOUNT_EXCEEDED": 9,
    "TRANSACTION_COUNT_EXCEEDED": 10, "NO_AUTHORITY": 11,
}


def _optional_id_key(value: str | None) -> tuple:
    # An absent id sorts before any present id.
    return (0, "") if value is None else (1, value)


def denial_sort_key(failure: dict[str, Any]) -> tuple:
    """Spec 02 §6.1 ordering: rank, root, terminal, failing authority, path ids, subject, evidence."""
    return (
        FAILURE_RANK.get(failure["code"], -1),
        _optional_id_key(failure.get("rootAuthorityId")),
        _optional_id_key(failure.get("terminalAuthorityId")),
        _optional_id_key(failure.get("failingAuthorityId")),
        tuple(failure["authorityPathIds"]),
        _optional_id_key(failure.get("subjectId")),
        tuple(evidence_key(reference) for reference in failure["evidence"]),
    )


# ---------------------------------------------------------------- replay evidence

DECISION_TYPES = frozenset(("DEPLOYMENT_INITIALIZED", "PRINCIPAL_CREATED", "AGENT_CREATED", "AGENT_TERMINATED", "AUTHORITY_GRANTED", "AUTHORITY_REVOKED", "TRANSACTION_INTENT_ADMITTED"))
_TENURE_TYPES = frozenset(("ROLE_CREATED", "AGENT_APPOINTED", "AGENT_UNAPPOINTED", "ROLE_TRANSFERRED"))


@dataclass
class EvidenceContext:
    state: Any
    refs: dict[int, dict[str, Any]] = field(default_factory=dict)
    decision_positions: list[int] = field(default_factory=list)
    decision: list[dict[str, Any]] | None = None
    # Format 1 only: decision evidence is narrowed to the request (see narrowed_decision_evidence), using a per-actor lifecycle index.
    narrowed: bool = False
    lifecycle_by_agent: dict[str, list[int]] = field(default_factory=dict)


# Actor lifecycle for the narrowed decision evidence: creation, termination and control-epoch advances.
_ACTOR_LIFECYCLE_TYPES = frozenset(("AGENT_CREATED", "AGENT_TERMINATED", "CONTROL_EPOCH_ADVANCED"))


def create_evidence_context(state: Any) -> EvidenceContext:
    hashes = state.event_history_hashes
    if len(hashes) != len(state.events) or hashes[-1] != state.head["hash"]:
        raise TypeError("Replay evidence prefix commitments disagree with the authoritative state head.")
    ctx = EvidenceContext(state, narrowed=state.format == TRELLIS_FORMAT)
    for position in range(len(state.events)):
        note_evidence_event(ctx, position)
    return ctx


def note_evidence_event(ctx: EvidenceContext, position: int) -> None:
    """Registers one appended event (incremental growth, as the TypeScript engine's ``noteEvidenceEvent``)."""
    event = ctx.state.events[position]
    if event["type"] in DECISION_TYPES:
        ctx.decision_positions.append(position)
    agent_id = event["data"].get("agentId")
    if ctx.narrowed and event["type"] in _ACTOR_LIFECYCLE_TYPES and isinstance(agent_id, str):
        ctx.lifecycle_by_agent.setdefault(agent_id, []).append(position)
    ctx.decision = None


def event_reference(ctx: EvidenceContext, position: int) -> dict[str, Any]:
    cached = ctx.refs.get(position)
    if cached is not None:
        return cached
    event = ctx.state.events[position]
    ref = {"kind": "EVENT", "eventId": event["id"], "eventType": event["type"], "position": position, "historyHash": ctx.state.event_history_hashes[position]}
    ctx.refs[position] = ref
    return ref


def sorted_distinct_references(refs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    refs.sort(key=evidence_key)
    out: list[dict[str, Any]] = []
    for ref in refs:
        if not out or evidence_key(out[-1]) != evidence_key(ref):
            out.append(ref)
    return out


def evidence_where(ctx: EvidenceContext, predicate: Callable[[dict[str, Any]], bool]) -> list[dict[str, Any]]:
    events = ctx.state.events
    refs = [event_reference(ctx, i) for i, event in enumerate(events) if predicate(event)]
    refs.append(event_reference(ctx, len(events) - 1))
    return sorted_distinct_references(refs)


def decision_evidence(ctx: EvidenceContext) -> list[dict[str, Any]]:
    if ctx.decision is None:
        refs = [event_reference(ctx, p) for p in ctx.decision_positions]
        refs.append(event_reference(ctx, len(ctx.state.events) - 1))
        ctx.decision = sorted_distinct_references(refs)
    return ctx.decision


def decision_evidence_length(ctx: EvidenceContext) -> int:
    return len(ctx.decision_positions) + (0 if ctx.state.events[-1]["type"] in DECISION_TYPES else 1)


def _is_agent_lifecycle(e: dict[str, Any], actor_id: str) -> bool:
    return e["type"] in ("AGENT_CREATED", "AGENT_TERMINATED") and e["data"].get("agentId") == actor_id


def agent_lifecycle_evidence(ctx: EvidenceContext, actor_id: str) -> list[dict[str, Any]]:
    return evidence_where(ctx, lambda e: _is_agent_lifecycle(e, actor_id))


def _session_lifecycle_predicate(actor_id: str, session_id: str) -> Callable[[dict[str, Any]], bool]:
    return lambda e: _is_agent_lifecycle(e, actor_id) or (
        e["type"] in ("RUNTIME_SESSION_ADMITTED", "CONTROL_EPOCH_ADVANCED") and (e["data"].get("agentId") == actor_id or e["data"].get("sessionId") == session_id))


def _tenure_lifecycle_predicate(role_id: str, tenure_id: str) -> Callable[[dict[str, Any]], bool]:
    return lambda e: e["type"] in _TENURE_TYPES and (
        e["data"].get("roleId") == role_id or e["data"].get("roleTenureId") == tenure_id
        or e["data"].get("fromRoleTenureId") == tenure_id or e["data"].get("toRoleTenureId") == tenure_id)


def session_lifecycle_evidence(ctx: EvidenceContext, actor_id: str, session_id: str) -> list[dict[str, Any]]:
    return evidence_where(ctx, _session_lifecycle_predicate(actor_id, session_id))


def tenure_lifecycle_evidence(ctx: EvidenceContext, role_id: str, tenure_id: str) -> list[dict[str, Any]]:
    return evidence_where(ctx, _tenure_lifecycle_predicate(role_id, tenure_id))


def _intent_values(e: dict[str, Any]) -> tuple[Any, Any, Any]:
    """(intentId, actorId, nonce) as recorded by a declaration or an admission (spec 02 §6.2)."""
    if e["type"] == "TRANSACTION_INTENT_DECLARED":
        return e["data"].get("intentId"), e["data"].get("actorId"), e["data"].get("nonce")
    proof = e["data"].get("authorizationProof")
    proof = proof if isinstance(proof, dict) else None
    request = proof.get("request") if proof is not None and isinstance(proof.get("request"), dict) else None
    return e["data"].get("intentId"), None if request is None else request.get("actorId"), None if proof is None else proof.get("nonce")


def _intent_decision_predicate(actor_id: str, intent_id: str | None = None, nonce: str | None = None) -> Callable[[dict[str, Any]], bool]:
    def predicate(e: dict[str, Any]) -> bool:
        if e["type"] not in ("TRANSACTION_INTENT_DECLARED", "TRANSACTION_INTENT_ADMITTED"):
            return False
        v_intent, v_actor, v_nonce = _intent_values(e)
        selected = v_actor == actor_id if intent_id is None else v_intent == intent_id
        return selected or (nonce is not None and v_actor == actor_id and v_nonce == nonce)
    return predicate


def intent_decision_evidence(ctx: EvidenceContext, actor_id: str, intent_id: str | None = None, nonce: str | None = None) -> list[dict[str, Any]]:
    return evidence_where(ctx, _intent_decision_predicate(actor_id, intent_id, nonce))


def narrowed_decision_evidence(ctx: EvidenceContext, actor_id: str, authority_positions: list[int], binding: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Format-1 decision evidence (replaces :func:`decision_evidence`, which cites every authority event): the genesis,
    the head, the actor's lifecycle (AGENT_CREATED, AGENT_TERMINATED, CONTROL_EPOCH_ADVANCED), the caller-selected
    authority event positions and, with a consequential binding, the session/tenure/intent evidence. Same ordering rule."""
    refs = [event_reference(ctx, 0)]
    refs.extend(event_reference(ctx, p) for p in ctx.lifecycle_by_agent.get(actor_id, []))
    refs.extend(event_reference(ctx, p) for p in authority_positions)
    if binding is not None:
        session = _session_lifecycle_predicate(actor_id, binding["runtimeSessionId"])
        tenure = _tenure_lifecycle_predicate(binding["roleId"], binding["roleTenureId"])
        intent = _intent_decision_predicate(actor_id, binding.get("intentId"), binding.get("nonce"))
        refs.extend(event_reference(ctx, i) for i, e in enumerate(ctx.state.events) if session(e) or tenure(e) or intent(e))
    refs.append(event_reference(ctx, len(ctx.state.events) - 1))
    return sorted_distinct_references(refs)


def colliding_event_evidence(ctx: EvidenceContext, event_id: str) -> list[dict[str, Any]]:
    refs = []
    index = next((i for i, e in enumerate(ctx.state.events) if e["id"] == event_id), -1)
    if index >= 0:
        refs.append(event_reference(ctx, index))
    refs.append(event_reference(ctx, len(ctx.state.events) - 1))
    return sorted_distinct_references(refs)


# ---------------------------------------------------------------- result envelopes


def indeterminate(operation_version: str, code: str, assurance: str = "SUPPLIED_SCOPE", evidence: list[dict[str, Any]] | None = None,
                  subject_id: str | None = None) -> dict[str, Any]:
    failure: dict[str, Any] = {"code": code}
    if subject_id is not None:
        failure["subjectId"] = subject_id
    failure["evidence"] = evidence if evidence is not None else []
    return {"operationVersion": operation_version, "decision": "INDETERMINATE", "scopeAssurance": assurance, "consequential": False, "code": code, "failures": [failure]}


def denial_result(operation_version: str, assurance: str, failures: list[dict[str, Any]]) -> dict[str, Any]:
    """Sorts the failures (spec 02 §6.1); the headline code is the first failure's code."""
    failures.sort(key=denial_sort_key)
    return {"code": failures[0]["code"], "consequential": False, "decision": "DENY", "failures": failures, "operationVersion": operation_version, "scopeAssurance": assurance}


def simple_denial(operation_version: str, assurance: str, code: str, evidence: list[dict[str, Any]] | None = None, subject_id: str | None = None) -> dict[str, Any]:
    failure: dict[str, Any] = {"authorityPathIds": [], "code": code, "evidence": evidence if evidence is not None else []}
    if subject_id is not None:
        failure["subjectId"] = subject_id
    return denial_result(operation_version, assurance, [failure])


def bounded_result(result: dict[str, Any], operation_version: str, assurance: str) -> dict[str, Any]:
    """A DENY/INDETERMINATE whose evidence references exceed the output budget collapses to OUTPUT_LIMIT_EXCEEDED."""
    if result["decision"] == "ALLOW":
        return result
    count = 0
    for failure in result["failures"]:
        count += len(failure["evidence"])
        if count > MAX_RESULT_EVIDENCE:
            return indeterminate(operation_version, "OUTPUT_LIMIT_EXCEEDED", assurance)
    return result
