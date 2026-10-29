"""IronTrellis (formerly Continuity) — verifier and evaluator for captured histories.

Agents change. The structure holds. This package replays a history (either the
legacy ``continuity-event/0.2`` format or ``irontrellis-event/1``), verifies its
chain, its runtime signatures and, for format 1, its owner-signed control
events, and answers ``authorize`` and ``survives`` questions with the exact
decisions of the TypeScript reference engine. ``irontrellis.transparency``
verifies remote witness receipts, signed checkpoints and Merkle proofs. It
never writes a history.
"""
from .authority import (
    AUTHORIZATION_VERSION, authorize_portable, authorize_state, combine_constraints, constraints_are_attenuated, normalized_grant, same_domain,
)
from .canonical import (
    BigInt, CanonicalError, canonical_encode, capture_value, compare_protocol_strings, from_plain, is_amount, is_content_hash, is_identifier, is_u53,
    json_dumps_with_bigints, json_loads_with_bigints, to_plain,
)
from .events import CONTROL_EVENT_TYPES, EVENT_TYPES, control_authorization_hash, validate_event
from .hashing import LEGACY_FORMAT, TRELLIS_FORMAT, HistoryHasher, hash_canonical, hash_event_history, hash_event_history_prefixes
from .owner_keys import (
    owner_key_digest, owner_key_event_transition, owner_keys_at, verify_head_attestation, verify_head_attestation_at, verify_rotation_event, keeps_every_owner_key,
)
from .replay import REPLAY_VERSION, ReplayResult, ReplayState, apply_event, detect_format, replay, replay_from, replay_portable
from .store import HistoryRejected, StoredHistory, StoreError, load_events, read_history, read_history_text, replay_history, replay_history_bytes
from .survives import QUERY_VERSION, SurvivesResult, derive_survives, survives_portable
from .transparency import (
    NoteError, open_note, parse_checkpoint, parse_verifier_key, verify_consistency, verify_inclusion, verify_signed_head_statement, verify_witness_receipt,
)

__version__ = "1.0.0rc1"
__all__ = [
    "AUTHORIZATION_VERSION", "authorize_portable", "authorize_state", "combine_constraints", "constraints_are_attenuated", "normalized_grant", "same_domain",
    "BigInt", "CanonicalError", "canonical_encode", "capture_value", "compare_protocol_strings", "from_plain", "is_amount", "is_content_hash", "is_identifier",
    "is_u53", "json_dumps_with_bigints", "json_loads_with_bigints", "to_plain",
    "CONTROL_EVENT_TYPES", "EVENT_TYPES", "control_authorization_hash", "validate_event",
    "LEGACY_FORMAT", "TRELLIS_FORMAT", "HistoryHasher", "hash_canonical", "hash_event_history", "hash_event_history_prefixes",
    "owner_key_digest", "owner_key_event_transition", "owner_keys_at", "verify_head_attestation", "verify_head_attestation_at", "keeps_every_owner_key",
    "verify_rotation_event",
    "REPLAY_VERSION", "ReplayResult", "ReplayState", "apply_event", "detect_format", "replay", "replay_from", "replay_portable",
    "HistoryRejected", "StoredHistory", "StoreError", "load_events", "read_history", "read_history_text", "replay_history", "replay_history_bytes",
    "QUERY_VERSION", "SurvivesResult", "derive_survives", "survives_portable",
    "NoteError", "open_note", "parse_checkpoint", "parse_verifier_key", "verify_consistency", "verify_inclusion", "verify_signed_head_statement",
    "verify_witness_receipt",
]
