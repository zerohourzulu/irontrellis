"""Hashing (spec 01 §B): every hash is over the UTF-8 bytes of the canonical text.

keccak-256 serves ``continuity-event/0.2``, sha256 serves ``irontrellis-event/1``.
History heads are prefix hashes of the wrapper ``[<wrapper>,[<e0>,<e1>,…]]``,
absorbed incrementally so a prefix hash costs one clone-and-finalise rather
than a re-hash of everything before it.
"""
from __future__ import annotations

import hashlib
from typing import Any

from .canonical import MAX_LIST_MEMBERS, MAX_TOTAL_BYTES, CanonicalError, canonical_encode
from .crypto.keccak import KeccakState, keccak256

LEGACY_FORMAT = "continuity-event/0.2"
TRELLIS_FORMAT = "irontrellis-event/1"
_FORMATS = {
    LEGACY_FORMAT: ("keccak256", "continuity-event-history/0.2"),
    TRELLIS_FORMAT: ("sha256", "irontrellis-event-history/1"),
}
# Every event sits inside `[wrapper,[…]]`, two containers deep (spec 01 A.8).
_EVENT_ANCESTOR_DEPTH = 2


def hash_bytes(data: bytes, algorithm: str) -> str:
    if algorithm == "keccak256":
        return "0x" + keccak256(data).hex()
    if algorithm == "sha256":
        return "0x" + hashlib.sha256(data).hexdigest()
    raise CanonicalError(f"Unsupported hash algorithm {algorithm}.")


def hash_canonical(value: Any, algorithm: str) -> str:
    """canonical_encode → UTF-8 → hash. Raises CanonicalError for values the canonical form rejects."""
    return hash_bytes(canonical_encode(value).encode("utf-8"), algorithm)


def history_hash_algorithm(history_format: str) -> str:
    return _format_of(history_format)[0]


def _format_of(history_format: str) -> tuple[str, str]:
    entry = _FORMATS.get(history_format)
    if entry is None:
        raise CanonicalError(f"Unsupported history format {history_format}.")
    return entry


class _Absorber:
    __slots__ = ("kind", "state")

    def __init__(self, algorithm: str, state: Any = None) -> None:
        self.kind = algorithm
        self.state = state if state is not None else (KeccakState() if algorithm == "keccak256" else hashlib.sha256())

    def update(self, data: bytes) -> None:
        self.state.update(data)

    def clone(self) -> _Absorber:
        return _Absorber(self.kind, self.state.clone() if self.kind == "keccak256" else self.state.copy())

    def finalize(self) -> str:
        return "0x" + (self.state.finalize().hex() if self.kind == "keccak256" else self.state.hexdigest())


class HistoryHasher:
    """Incremental prefix hashes (spec 01 B.3): ``push(event)`` returns the hash of the history up to and including it.

    The legacy format keeps the reference's whole-history bounds (4096 events, 16 MiB of
    canonical text); format 1 has no whole-history bound.
    """

    __slots__ = ("format", "algorithm", "_absorber", "count", "_bytes")

    def __init__(self, history_format: str) -> None:
        algorithm, wrapper = _format_of(history_format)
        self.format = history_format
        self.algorithm = algorithm
        self._absorber = _Absorber(algorithm)
        prefix = f'["{wrapper}",['.encode("utf-8")
        self._absorber.update(prefix)
        self.count = 0
        self._bytes = len(prefix) + 2

    def push(self, event: Any) -> str:
        legacy = self.format == LEGACY_FORMAT
        if legacy and self.count >= MAX_LIST_MEMBERS:
            raise CanonicalError(f"Canonical array at $[1] exceeds the {MAX_LIST_MEMBERS}-member bound.", "$[1]", True)
        budget = MAX_TOTAL_BYTES - self._bytes - (1 if self.count > 0 else 0) if legacy else MAX_TOTAL_BYTES
        text = canonical_encode(event, ancestor_depth=_EVENT_ANCESTOR_DEPTH, max_total_bytes=budget).encode("utf-8")
        if self.count > 0:
            self._absorber.update(b",")
            self._bytes += 1
        self._absorber.update(text)
        self._bytes += len(text)
        self.count += 1
        finalizable = self._absorber.clone()
        finalizable.update(b"]]")
        return finalizable.finalize()

    def clone(self) -> HistoryHasher:
        copy = HistoryHasher.__new__(HistoryHasher)
        copy.format = self.format
        copy.algorithm = self.algorithm
        copy._absorber = self._absorber.clone()
        copy.count = self.count
        copy._bytes = self._bytes
        return copy


def hash_event_history(events: list[Any], history_format: str) -> str:
    """Hash of the whole history: ``hash_canonical([wrapper, events])``."""
    algorithm, wrapper = _format_of(history_format)
    if history_format == LEGACY_FORMAT and len(events) > MAX_LIST_MEMBERS:
        raise CanonicalError(f"Canonical array at $[1] exceeds the {MAX_LIST_MEMBERS}-member bound.", "$[1]", True)
    if len(events) == 0:
        return hash_canonical([wrapper, []], algorithm)
    hasher = HistoryHasher(history_format)
    head = "0x"
    for event in events:
        head = hasher.push(event)
    return head


def hash_event_history_prefixes(events: list[Any], history_format: str) -> list[str]:
    hasher = HistoryHasher(history_format)
    return [hasher.push(event) for event in events]
