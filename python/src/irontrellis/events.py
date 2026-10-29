"""Event envelope and closed per-type data schemas (spec 01 §C) for both formats,
plus the genesis probe, the format-1 control-authorization challenge and the
named-limit preflight that decides INVALID_INPUT vs EVENT_DATA_INVALID.

Validation runs in two passes over a captured ``data`` record, like the
reference engine: a preflight over *named limit slots* (identifier length,
bigint magnitude, list size) whose failures are LIMIT-branded, then the closed
schema pass that stops at the first defect. Replay maps LIMIT failures to
``INVALID_INPUT`` and everything else to ``EVENT_DATA_INVALID``.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any

from .adapters import (
    REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION, resolve_adapter_policy, validate_adapter_acknowledgment_shape,
    validate_adapter_no_effect_shape, validate_known_adapter_profile,
)
from .canonical import (
    MAX_PROTOCOL_BIGINT, BigInt, CanonicalError, capture_value, is_content_hash, is_ethereum_address, is_public_key_hex, is_u53,
)
from .crypto.suites import SIGNATURE_SCHEMES, is_signature_65
from .hashing import LEGACY_FORMAT, TRELLIS_FORMAT, hash_canonical
from .transparency import NoteError, parse_verifier_key

EVENT_TYPES = (
    "DEPLOYMENT_INITIALIZED", "PRINCIPAL_CREATED", "AGENT_CREATED", "ROLE_CREATED", "SUCCESSION_RULE_DECLARED", "AGENT_APPOINTED",
    "AGENT_UNAPPOINTED", "ROLE_TRANSFERRED", "RUNTIME_SESSION_ADMITTED", "CONTROL_EPOCH_ADVANCED", "AUTHORITY_GRANTED", "AUTHORITY_REVOKED",
    "TRANSACTION_INTENT_DECLARED", "TRANSACTION_INTENT_ADMITTED", "TRANSACTION_INTENT_CONSUMED", "TRANSACTION_OUTCOME_RECORDED",
    "RECEIPT_RECORDED", "OBLIGATION_CREATED", "OBLIGATION_PERFORMANCE_ASSIGNED", "OBLIGATION_STATUS_RECORDED", "AGENT_TERMINATED",
    "OUTCOME_OBSERVATION_RECORDED", "ATTEMPT_DUTY_CREATED", "ATTEMPT_DUTY_ASSIGNED", "ATTEMPT_DUTY_REVIEW_CLOSED", "ANCHOR_RECORDED",
    "OWNER_KEYS_ROTATED", "WITNESSES_BOUND", "WITNESSES_UNBOUND",
)
CONTROL_EVENT_TYPES = frozenset((
    "PRINCIPAL_CREATED", "AGENT_CREATED", "ROLE_CREATED", "SUCCESSION_RULE_DECLARED", "AGENT_APPOINTED", "AGENT_UNAPPOINTED", "ROLE_TRANSFERRED",
    "RUNTIME_SESSION_ADMITTED", "CONTROL_EPOCH_ADVANCED", "AUTHORITY_GRANTED", "AUTHORITY_REVOKED", "AGENT_TERMINATED", "ANCHOR_RECORDED",
    "OWNER_KEYS_ROTATED", "WITNESSES_BOUND", "WITNESSES_UNBOUND",
))
# Event types a legacy (continuity-event/0.2) history may not carry (UNSUPPORTED_EVENT_TYPE).
TRELLIS_ONLY_EVENT_TYPES = frozenset(("ANCHOR_RECORDED", "OWNER_KEYS_ROTATED", "WITNESSES_BOUND", "WITNESSES_UNBOUND"))
ROOT_RECOGNITION_POLICY = "declared-principal-root/0.2"
CONTROL_AUTHORIZATION_VERSION = "irontrellis-control-authorization/1"
MAX_EVENT_DATA_BYTES = 1_048_576
LEGACY_VERSIONS = {
    "eventSchemaVersion": "continuity-event/0.2",
    "receiptSchemaVersion": "continuity-receipt/0.2",
    "queryEnvelopeVersion": "continuity-query-envelope/0.2",
    "authorizationProofVersion": "continuity-authorization-proof/0.2",
    "runtimeAuthorizationVersion": "continuity-runtime-authorization/0.2",
    "administrativeAuthorizationVersion": "continuity-administrative-authorization/0.2",
    "signatureScheme": "eip191-personal-sign-keccak256",
}
# Format-1 genesis versions: every literal is the one actually used on the wire (proofs, runtime and
# administrative challenges, query envelopes keep the reference's continuity-.../0.2 literals).
TRELLIS_VERSIONS = {
    "eventSchemaVersion": "irontrellis-event/1",
    "historyHashAlgorithm": "sha256",
    "receiptSchemaVersion": "irontrellis-receipt/1",
    "controlAuthorizationVersion": "irontrellis-control-authorization/1",
    "queryEnvelopeVersion": "continuity-query-envelope/0.2",
    "authorizationProofVersion": "continuity-authorization-proof/0.2",
    "runtimeAuthorizationVersion": "continuity-runtime-authorization/0.2",
    "administrativeAuthorizationVersion": "continuity-administrative-authorization/0.2",
}
_TRELLIS_VERSION_KEYS = (*TRELLIS_VERSIONS.keys(), "signatureScheme")
_LEGACY_VERSION_KEYS = tuple(LEGACY_VERSIONS.keys())
ADMINISTRATIVE_EVENT_TYPES = (
    "OBLIGATION_CREATED", "OBLIGATION_PERFORMANCE_ASSIGNED", "OBLIGATION_STATUS_RECORDED", "OUTCOME_OBSERVATION_RECORDED",
    "ATTEMPT_DUTY_CREATED", "ATTEMPT_DUTY_ASSIGNED", "ATTEMPT_DUTY_REVIEW_CLOSED",
)
OBLIGATION_STATUSES = ("OPEN", "OUTCOME_UNKNOWN", "DISPUTED", "DISCHARGED", "IMPOSSIBLE_OR_ESCALATED")
# The ``data.anchor`` literals of ANCHOR_RECORDED (the anchor kind). Remote witnesses are bound by their own events, never by an anchor.
ANCHOR_NAMES = ("local-head-file", "rekor-v2", "custom")
# At most this many remote witnesses are bound to a history, and named by one binding event.
MAX_BOUND_WITNESSES = 16
OWNER_KEY_DIGEST_VERSION = "irontrellis-owner-key-digest/1"
_CONTROL_CHARS = re.compile("[\u0000-\u001f\u007f]")


def owner_key_digest(key: dict[str, Any]) -> str:
    """Pre-rotation: ``hash_canonical({version: "irontrellis-owner-key-digest/1", scheme, credential}, "sha256")`` with the
    credential normalised (lowercase); the key id is not part of it."""
    return hash_canonical({"version": OWNER_KEY_DIGEST_VERSION, "scheme": key["scheme"], "credential": key["credential"].lower()}, "sha256")


def declared_digest_failure(what: str, declared: list[dict[str, Any]], digests: list[str]) -> str | None:
    """A commitment that names a key the history already declared can never be revealed: the reason, or None."""
    for key in declared:
        digest = owner_key_digest(key)
        if digest in digests:
            return f"{what}: next-key digest {digest} names owner key {key['keyId']}, which this history already declared; commit to a new key"
    return None


def format_of_schema_version(version: Any) -> str | None:
    return LEGACY_FORMAT if version == LEGACY_FORMAT else TRELLIS_FORMAT if version == TRELLIS_FORMAT else None


def hash_algorithm_of(history_format: str) -> str:
    return "sha256" if history_format == TRELLIS_FORMAT else "keccak256"


def is_event_type(value: Any) -> bool:
    return isinstance(value, str) and value in EVENT_TYPES


# ---------------------------------------------------------------- validator core


@dataclass
class V:
    """Validation context: the first problem wins; a LIMIT problem overrides a SEMANTIC one."""

    format: str
    shadow: bool = False
    problem: str | None = None
    kind: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


def _legacy_shapes(v: V) -> bool:
    return v.format == LEGACY_FORMAT or v.shadow


def _fail(v: V, path: str, message: str) -> bool:
    if v.problem is None:
        v.problem = f"{path}: {message}"
        v.kind = "SEMANTIC"
    return False


def _fail_limit(v: V, path: str, message: str) -> bool:
    if v.kind != "LIMIT":
        v.problem = f"{path}: {message}"
        v.kind = "LIMIT"
    return False


def _is_record(value: Any) -> bool:
    return isinstance(value, dict)


def _rec(v: V, value: Any, path: str, required: tuple[str, ...], optional: tuple[str, ...] = ()) -> dict[str, Any] | None:
    """Closed record: every key declared, every required key present."""
    if not _is_record(value):
        _fail(v, path, "must be a plain protocol record")
        return None
    for key in value:
        if key not in required and key not in optional:
            _fail(v, f"{path}.{key}", "is not a declared field")
            return None
    for key in required:
        if key not in value:
            _fail(v, f"{path}.{key}", "is required")
            return None
    return value


def _utf8_status(value: str, maximum: int) -> str:
    if len(value) > maximum:
        return "LIMIT"
    try:
        length = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        return "MALFORMED"
    return "LIMIT" if length > maximum else "VALID"


def _identifier(v: V, value: Any, path: str) -> bool:
    if not isinstance(value, str):
        return _fail(v, path, "must be an Identifier")
    status = _utf8_status(value, 256)
    if status == "LIMIT":
        return _fail_limit(v, path, "must be an Identifier")
    if status == "MALFORMED" or len(value) == 0 or _CONTROL_CHARS.search(value):
        return _fail(v, path, "must be an Identifier")
    return True


def _protocol_string(v: V, value: Any, path: str) -> bool:
    if not isinstance(value, str):
        return _fail(v, path, "must be a bounded ProtocolString")
    status = _utf8_status(value, 4096)
    if status == "LIMIT":
        return _fail_limit(v, path, "must be a bounded ProtocolString")
    return _fail(v, path, "must be a bounded ProtocolString") if status == "MALFORMED" else True


def _u53(v: V, value: Any, path: str) -> bool:
    return True if is_u53(value) else _fail(v, path, "must be a U53")


def _amount(v: V, value: Any, path: str) -> bool:
    if not isinstance(value, BigInt):
        return _fail(v, path, "must be an Amount")
    if value.value < -MAX_PROTOCOL_BIGINT or value.value > MAX_PROTOCOL_BIGINT:
        return _fail_limit(v, path, "exceeds the 256-bit BigInt magnitude bound")
    return _fail(v, path, "must be an Amount") if value.value < 0 else True


def _content_hash(v: V, value: Any, path: str) -> bool:
    return True if is_content_hash(value) else _fail(v, path, "must be a lowercase ContentHash")


def _ethereum_address(v: V, value: Any, path: str) -> bool:
    return True if is_ethereum_address(value) else _fail(v, path, "must be an EthereumAddress")


def _public_key_hex(v: V, value: Any, path: str) -> bool:
    return True if is_public_key_hex(value) else _fail(v, path, "must be a 32-byte public key")


def _chain_id(v: V, value: Any, path: str) -> bool:
    if not isinstance(value, str) or not value.isdigit() or not value.isascii() or value[0] == "0":
        return _fail(v, path, "must be a canonical ChainId string")
    parsed = int(value)
    return _fail(v, path, "is outside the ChainId bound") if parsed < 1 or parsed > MAX_PROTOCOL_BIGINT else True


def _is_signature_64(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 130 and value.startswith("0x") and all(c in "0123456789abcdef" for c in value[2:])


def _is_hex130(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 132 and value.startswith("0x") and all(c in "0123456789abcdef" for c in value[2:])


def _signature(v: V, value: Any, path: str) -> bool:
    """A runtime signature: legacy demands a low-s secp256k1 signature; format 1 also admits Ed25519's 64 bytes."""
    if is_signature_65(value):
        return True
    if not _legacy_shapes(v) and _is_signature_64(value):
        return True
    if _is_hex130(value):
        return _fail(v, path, "must use a low-s value and recovery byte 27 or 28")
    return _fail(v, path, "must be a lowercase 65-byte signature")


def is_hex_signature(value: Any, scheme: str) -> bool:
    return _is_signature_64(value) if scheme == "ed25519" else is_signature_65(value)


def _literal(v: V, value: Any, path: str, allowed: tuple[str, ...]) -> bool:
    return True if isinstance(value, str) and value in allowed else _fail(v, path, f"must be one of {', '.join(allowed)}")


def _identifier_list(v: V, value: Any, path: str, nonempty: bool = False, maximum: int = 4096) -> bool:
    if not isinstance(value, list):
        return _fail(v, path, "must be a dense Identifier list")
    if len(value) > maximum:
        return _fail_limit(v, path, f"exceeds the {maximum}-member set bound")
    if nonempty and len(value) == 0:
        return _fail(v, path, "has invalid list cardinality")
    seen: set[str] = set()
    for index, member in enumerate(value):
        if not _identifier(v, member, f"{path}[{index}]"):
            return False
        if member in seen:
            return _fail(v, f"{path}[{index}]", "duplicates an Identifier")
        seen.add(member)
    return True


def _strictly_sorted(ids: list[str]) -> bool:
    return all(ids[i - 1] < ids[i] for i in range(1, len(ids)))


def _review_observation_ids(v: V, value: Any, path: str) -> bool:
    return _identifier_list(v, value, path, maximum=128) and (_strictly_sorted(value) or _fail(v, path, "must be strictly sorted"))


def _enum_list(v: V, value: Any, path: str, allowed: tuple[str, ...], nonempty: bool = False) -> bool:
    if not isinstance(value, list) or (nonempty and len(value) == 0):
        return _fail(v, path, "must be a dense nonempty enum list")
    seen: set[str] = set()
    for index, member in enumerate(value):
        if not _literal(v, member, f"{path}[{index}]", allowed):
            return False
        if member in seen:
            return _fail(v, f"{path}[{index}]", "duplicates a member")
        seen.add(member)
    return True


# ---------------------------------------------------------------- shared sub-records (spec 01 §C.5)


def _domain(v: V, value: Any, path: str) -> bool:
    if not _legacy_shapes(v):
        r = _rec(v, value, path, ("protocol", "version", "deploymentId"))
        return r is not None and r["protocol"] == "irontrellis" and r["version"] == "1" and _identifier(v, r["deploymentId"], f"{path}.deploymentId")
    r = _rec(v, value, path, ("protocol", "version", "deploymentId", "chainId", "verifyingContract"))
    return (r is not None and r["protocol"] == "continuity" and r["version"] == "0.2" and _identifier(v, r["deploymentId"], f"{path}.deploymentId")
            and _chain_id(v, r["chainId"], f"{path}.chainId") and _ethereum_address(v, r["verifyingContract"], f"{path}.verifyingContract"))


def _version_keys(v: V) -> tuple[str, ...]:
    return _TRELLIS_VERSION_KEYS if v.format == TRELLIS_FORMAT else _LEGACY_VERSION_KEYS


def _version_set(v: V, value: Any, path: str) -> bool:
    r = _rec(v, value, path, _version_keys(v))
    if r is None:
        return False
    expected = TRELLIS_VERSIONS if v.format == TRELLIS_FORMAT else LEGACY_VERSIONS
    for key, expected_value in expected.items():
        if r[key] != expected_value:
            return _fail(v, f"{path}.{key}", f"must equal {expected_value}")
    return v.format == LEGACY_FORMAT or _literal(v, r["signatureScheme"], f"{path}.signatureScheme", SIGNATURE_SCHEMES)


def _declared_version_set(v: V, value: Any, path: str) -> bool:
    r = _rec(v, value, path, _version_keys(v))
    return r is not None and all(_identifier(v, r[key], f"{path}.{key}") for key in _version_keys(v))


def _history_head(v: V, value: Any, path: str) -> bool:
    r = _rec(v, value, path, ("hash", "position", "canonicalTime"))
    return (r is not None and _content_hash(v, r["hash"], f"{path}.hash") and _u53(v, r["position"], f"{path}.position")
            and _u53(v, r["canonicalTime"], f"{path}.canonicalTime"))


def _action_request(v: V, value: Any, path: str) -> bool:
    r = _rec(v, value, path, ("actorId", "action", "resource", "claimedAt"), ("amount", "counterpartyId", "termsCommitment"))
    return (r is not None and _identifier(v, r["actorId"], f"{path}.actorId") and _identifier(v, r["action"], f"{path}.action")
            and _identifier(v, r["resource"], f"{path}.resource") and _u53(v, r["claimedAt"], f"{path}.claimedAt")
            and ("amount" not in r or _amount(v, r["amount"], f"{path}.amount"))
            and ("counterpartyId" not in r or _identifier(v, r["counterpartyId"], f"{path}.counterpartyId"))
            and ("termsCommitment" not in r or _content_hash(v, r["termsCommitment"], f"{path}.termsCommitment")))


def _evidence_reference(v: V, value: Any, path: str) -> bool:
    if not _is_record(value) or not isinstance(value.get("kind"), str):
        return _fail(v, path, "must be a tagged EvidenceReference record")
    kind = value["kind"]
    if kind == "EVENT":
        r = _rec(v, value, path, ("kind", "eventId", "eventType", "position", "historyHash"))
        return (r is not None and _identifier(v, r["eventId"], f"{path}.eventId")
                and (is_event_type(r["eventType"]) or _fail(v, f"{path}.eventType", "is not an EventType"))
                and _u53(v, r["position"], f"{path}.position") and _content_hash(v, r["historyHash"], f"{path}.historyHash"))
    if kind == "AUTHORITY":
        r = _rec(v, value, path, ("kind", "authorityId", "grantEventId"))
        return r is not None and _identifier(v, r["authorityId"], f"{path}.authorityId") and _identifier(v, r["grantEventId"], f"{path}.grantEventId")
    if kind == "RUNTIME_CREDENTIAL":
        r = _rec(v, value, path, ("kind", "keyId", "sessionId", "admissionEventId"))
        return (r is not None and _identifier(v, r["keyId"], f"{path}.keyId") and _identifier(v, r["sessionId"], f"{path}.sessionId")
                and _identifier(v, r["admissionEventId"], f"{path}.admissionEventId"))
    if kind == "RECEIPT_COMMITMENT":
        r = _rec(v, value, path, ("kind", "receiptContentHash", "eventId", "position"))
        return (r is not None and _content_hash(v, r["receiptContentHash"], f"{path}.receiptContentHash")
                and _identifier(v, r["eventId"], f"{path}.eventId") and _u53(v, r["position"], f"{path}.position"))
    if kind == "EXTERNAL":
        r = _rec(v, value, path, ("kind", "evidenceType", "reference", "attesterId"))
        return (r is not None and _identifier(v, r["evidenceType"], f"{path}.evidenceType") and _identifier(v, r["reference"], f"{path}.reference")
                and _identifier(v, r["attesterId"], f"{path}.attesterId"))
    return _fail(v, f"{path}.kind", "is not an EvidenceReference kind")


def _authority_constraints(v: V, value: Any, path: str, intersection_maximum: int = 32) -> bool:
    r = _rec(v, value, path, ("actions", "resources", "quantitative", "maxDelegationDepth", "requiredIntersectionIds"),
             ("notBefore", "expiresAt", "maxAmount", "maxCumulativeAmount", "maxTransactions"))
    if r is None:
        return False
    if isinstance(r["actions"], list) and len(r["actions"]) > 256:
        return _fail_limit(v, f"{path}.actions", "exceeds the 256-member action set bound")
    if isinstance(r["resources"], list) and len(r["resources"]) > 256:
        return _fail_limit(v, f"{path}.resources", "exceeds the 256-member resource set bound")
    if isinstance(r["requiredIntersectionIds"], list) and len(r["requiredIntersectionIds"]) > intersection_maximum:
        return _fail_limit(v, f"{path}.requiredIntersectionIds", f"exceeds the {intersection_maximum}-member required-intersection bound")
    if (not _identifier_list(v, r["actions"], f"{path}.actions", True, 256)
            or not _identifier_list(v, r["resources"], f"{path}.resources", True, 256)
            or not isinstance(r["quantitative"], bool) or not _u53(v, r["maxDelegationDepth"], f"{path}.maxDelegationDepth")
            or not _identifier_list(v, r["requiredIntersectionIds"], f"{path}.requiredIntersectionIds", False, intersection_maximum)
            or ("notBefore" in r and not _u53(v, r["notBefore"], f"{path}.notBefore"))
            or ("expiresAt" in r and not _u53(v, r["expiresAt"], f"{path}.expiresAt"))
            or ("maxAmount" in r and not _amount(v, r["maxAmount"], f"{path}.maxAmount"))
            or ("maxCumulativeAmount" in r and not _amount(v, r["maxCumulativeAmount"], f"{path}.maxCumulativeAmount"))
            or ("maxTransactions" in r and not _u53(v, r["maxTransactions"], f"{path}.maxTransactions"))):
        if v.problem is None and not isinstance(r["quantitative"], bool):
            _fail(v, f"{path}.quantitative", "must be boolean")
        return False
    if r["quantitative"] is False and ("maxAmount" in r or "maxCumulativeAmount" in r):
        return _fail(v, path, "nonquantitative constraints cannot carry amount ceilings")
    return True


def _permission_grant(v: V, value: Any, path: str) -> bool:
    r = _rec(v, value, path, ("kind", "authorityId", "grantorId", "granteeId", "rootAuthorityId", "independent", "constraints"), ("parentAuthorityId",))
    return (r is not None and r["kind"] == "PERMISSION" and _identifier(v, r["authorityId"], f"{path}.authorityId")
            and _identifier(v, r["grantorId"], f"{path}.grantorId") and _identifier(v, r["granteeId"], f"{path}.granteeId")
            and _identifier(v, r["rootAuthorityId"], f"{path}.rootAuthorityId")
            and ("parentAuthorityId" not in r or _identifier(v, r["parentAuthorityId"], f"{path}.parentAuthorityId"))
            and (isinstance(r["independent"], bool) or _fail(v, f"{path}.independent", "must be boolean"))
            and _authority_constraints(v, r["constraints"], f"{path}.constraints"))


def _prohibition_grant(v: V, value: Any, path: str) -> bool:
    if not _is_record(value) or value.get("kind") != "PROHIBITION":
        return _fail(v, f"{path}.kind", "must be PROHIBITION")
    scope = value.get("scope")
    if scope == "ROOT":
        r = _rec(v, value, path, ("kind", "scope", "authorityId", "grantorId", "rootAuthorityId", "constraints"), ("subjectActorId", "parentAuthorityId"))
        return (r is not None and _identifier(v, r["authorityId"], f"{path}.authorityId") and _identifier(v, r["grantorId"], f"{path}.grantorId")
                and _identifier(v, r["rootAuthorityId"], f"{path}.rootAuthorityId")
                and ("subjectActorId" not in r or _identifier(v, r["subjectActorId"], f"{path}.subjectActorId"))
                and ("parentAuthorityId" not in r or _identifier(v, r["parentAuthorityId"], f"{path}.parentAuthorityId"))
                and _authority_constraints(v, r["constraints"], f"{path}.constraints"))
    if scope == "GLOBAL":
        r = _rec(v, value, path, ("kind", "scope", "authorityId", "grantorId", "constraints"), ("subjectActorId",))
        return (r is not None and _identifier(v, r["authorityId"], f"{path}.authorityId") and _identifier(v, r["grantorId"], f"{path}.grantorId")
                and ("subjectActorId" not in r or _identifier(v, r["subjectActorId"], f"{path}.subjectActorId"))
                and _authority_constraints(v, r["constraints"], f"{path}.constraints"))
    return _fail(v, f"{path}.scope", "must be ROOT or GLOBAL")


def _authority_grant(v: V, value: Any, path: str) -> bool:
    if not _is_record(value):
        return _fail(v, path, "must be an authority grant record")
    kind = value.get("kind")
    if kind == "PERMISSION":
        return _permission_grant(v, value, path)
    if kind == "PROHIBITION":
        return _prohibition_grant(v, value, path)
    return _fail(v, f"{path}.kind", "must be PERMISSION or PROHIBITION")


_ROOT_KEYS = ("rootAuthorityId", "principalId", "principalRecognitionEventId", "rootGrantEventId")


def _recognized_root(v: V, value: Any, path: str) -> bool:
    r = _rec(v, value, path, _ROOT_KEYS)
    return r is not None and all(_identifier(v, r[key], f"{path}.{key}") for key in _ROOT_KEYS)


def _authority_usage(v: V, value: Any, path: str) -> bool:
    r = _rec(v, value, path, ("authorityId", "admittedTransactionCount", "admittedCumulativeAmount"))
    return (r is not None and _identifier(v, r["authorityId"], f"{path}.authorityId")
            and _u53(v, r["admittedTransactionCount"], f"{path}.admittedTransactionCount")
            and _amount(v, r["admittedCumulativeAmount"], f"{path}.admittedCumulativeAmount"))


def _authority_evidence(v: V, value: Any, path: str) -> bool:
    r = _rec(v, value, path, ("authorityId", "grantEventId", "grantEventPosition"))
    return (r is not None and _identifier(v, r["authorityId"], f"{path}.authorityId") and _identifier(v, r["grantEventId"], f"{path}.grantEventId")
            and _u53(v, r["grantEventPosition"], f"{path}.grantEventPosition"))


def _distinct_list(v: V, value: list[Any], path: str, member: Any, id_key: str, duplicate: str) -> bool:
    seen: set[Any] = set()
    for index, item in enumerate(value):
        if not member(v, item, f"{path}[{index}]"):
            return False
        identity = item[id_key]
        if identity in seen:
            return _fail(v, f"{path}[{index}]", duplicate)
        seen.add(identity)
    return True


def _permission_grant_list(v: V, value: Any, path: str, nonempty: bool) -> bool:
    if not isinstance(value, list):
        return _fail(v, path, "must be a bounded permission path")
    if len(value) > 32:
        return _fail_limit(v, path, "exceeds the 32-member authority-path bound")
    if nonempty and len(value) == 0:
        return _fail(v, path, "must be a bounded permission path")
    return _distinct_list(v, value, path, _permission_grant, "authorityId", "duplicates a path authority")


def _intersection_proof(v: V, value: Any, path: str) -> bool:
    r = _rec(v, value, path, ("requiredAuthorityId", "requiredByAuthorityIds", "recognizedRoot", "path", "effectiveConstraints"))
    return (r is not None and _identifier(v, r["requiredAuthorityId"], f"{path}.requiredAuthorityId")
            and _identifier_list(v, r["requiredByAuthorityIds"], f"{path}.requiredByAuthorityIds", True, 256)
            and _recognized_root(v, r["recognizedRoot"], f"{path}.recognizedRoot") and _permission_grant_list(v, r["path"], f"{path}.path", True)
            and _authority_constraints(v, r["effectiveConstraints"], f"{path}.effectiveConstraints", 256))


_CONSEQUENTIAL_FIELDS = ("runtimeSessionId", "credentialKeyId", "controlEpoch", "roleId", "roleTenureId", "intentId", "nonce")


def _authorization_proof(v: V, value: Any, path: str) -> bool:
    r = _rec(v, value, path, (
        "proofVersion", "domain", "policyVersion", "rootRecognitionPolicy", "historyHead", "evaluationTime", "request", "recognizedRoot", "permissionPath",
        "intersections", "effectiveConstraints", "controllingAuthorityIds", "usageSnapshot", "authorityEvidence", "checkedProhibitionIds", "consequential",
    ), _CONSEQUENTIAL_FIELDS)
    if r is None:
        return False
    if isinstance(r["intersections"], list) and len(r["intersections"]) > 256:
        return _fail_limit(v, f"{path}.intersections", "exceeds the 256-member proof-intersection bound")
    if isinstance(r["usageSnapshot"], list) and len(r["usageSnapshot"]) > 256:
        return _fail_limit(v, f"{path}.usageSnapshot", "exceeds the 256-member authority-usage bound")
    if isinstance(r["authorityEvidence"], list) and len(r["authorityEvidence"]) > 1024:
        return _fail_limit(v, f"{path}.authorityEvidence", "exceeds the 1024-member authority-evidence bound")
    if (r["proofVersion"] != "continuity-authorization-proof/0.2" or not _domain(v, r["domain"], f"{path}.domain")
            or not _identifier(v, r["policyVersion"], f"{path}.policyVersion") or r["rootRecognitionPolicy"] != ROOT_RECOGNITION_POLICY
            or not _history_head(v, r["historyHead"], f"{path}.historyHead") or not _u53(v, r["evaluationTime"], f"{path}.evaluationTime")
            or not _action_request(v, r["request"], f"{path}.request") or not _recognized_root(v, r["recognizedRoot"], f"{path}.recognizedRoot")
            or not _permission_grant_list(v, r["permissionPath"], f"{path}.permissionPath", True) or not isinstance(r["intersections"], list)
            or not _authority_constraints(v, r["effectiveConstraints"], f"{path}.effectiveConstraints", 256)
            or not _identifier_list(v, r["controllingAuthorityIds"], f"{path}.controllingAuthorityIds", True, 256)
            or not isinstance(r["usageSnapshot"], list) or not isinstance(r["authorityEvidence"], list) or len(r["authorityEvidence"]) == 0
            or not _identifier_list(v, r["checkedProhibitionIds"], f"{path}.checkedProhibitionIds", False, 256) or not isinstance(r["consequential"], bool)):
        if v.problem is None:
            _fail(v, path, "contains an invalid AuthorizationProof field")
        return False
    if (not _distinct_list(v, r["intersections"], f"{path}.intersections", _intersection_proof, "requiredAuthorityId", "duplicates a required authority")
            or not _distinct_list(v, r["usageSnapshot"], f"{path}.usageSnapshot", _authority_usage, "authorityId", "duplicates an authority")
            or not _distinct_list(v, r["authorityEvidence"], f"{path}.authorityEvidence", _authority_evidence, "authorityId", "duplicates an authority")):
        return False
    for name in _CONSEQUENTIAL_FIELDS:
        if (name in r) != r["consequential"]:
            return _fail(v, f"{path}.{name}", "is required for a consequential proof" if r["consequential"] else "must be absent from a nonconsequential proof")
    return not r["consequential"] or (
        _identifier(v, r["runtimeSessionId"], f"{path}.runtimeSessionId") and _identifier(v, r["credentialKeyId"], f"{path}.credentialKeyId")
        and _u53(v, r["controlEpoch"], f"{path}.controlEpoch") and _identifier(v, r["roleId"], f"{path}.roleId") and _identifier(v, r["roleTenureId"], f"{path}.roleTenureId")
        and _identifier(v, r["intentId"], f"{path}.intentId") and _identifier(v, r["nonce"], f"{path}.nonce"))


def _adapter_profile(v: V, value: Any, path: str) -> bool:
    r = _rec(v, value, path, ("profileId", "profileVersion", "descriptorHash"))
    return r is not None and validate_known_adapter_profile(r)


_RESULT_DIGESTS = {"LOCAL_PACKET_CREATED": "manifestDigest", "REMOTE_SERVICE_REPORTED": "reportDigest",
                   "LOCAL_DOCUMENT_RELEASED": "publicationManifestDigest", "LOCAL_ENDPOINT_STATE_CHANGED": "transitionDigest"}


def _adapter_evidence(v: V, value: Any, path: str, no_effect: bool = False) -> bool:
    r = _rec(v, value, path, ("schemaVersion", "kind", "adapterProfile", "domain", "intentId", "admissionHead", "idempotencyKey", "submissionFingerprint", "result"))
    if (r is None or not _adapter_profile(v, r["adapterProfile"], f"{path}.adapterProfile") or not _domain(v, r["domain"], f"{path}.domain")
            or not _history_head(v, r["admissionHead"], f"{path}.admissionHead")):
        return False
    result = r["result"]
    if not _is_record(result):
        return False
    if no_effect:
        return _rec(v, result, f"{path}.result", ("kind", "reference")) is not None and validate_adapter_no_effect_shape(r)
    if result.get("kind") == "SIMULATED_SUBMISSION":
        if _rec(v, result, f"{path}.result", ("kind", "submissionReference")) is None:
            return False
    else:
        digest_key = _RESULT_DIGESTS.get(result.get("kind")) if isinstance(result.get("kind"), str) else None
        if (digest_key is None or _rec(v, result, f"{path}.result", ("kind", digest_key)) is None
                or _rec(v, result[digest_key], f"{path}.result.{digest_key}", ("algorithm", "value")) is None):
            return False
    return validate_adapter_acknowledgment_shape(r)


def _transaction_intent(v: V, value: Any, path: str) -> bool:
    r = _rec(v, value, path, ("intentId", "nonce", "actorId", "action", "resource", "roleId", "roleTenureId", "adapterProfile"), ("amount", "counterpartyId", "termsCommitment"))
    return (r is not None and _adapter_profile(v, r["adapterProfile"], f"{path}.adapterProfile")
            and all(_identifier(v, r[key], f"{path}.{key}") for key in ("intentId", "nonce", "actorId", "action", "resource", "roleId", "roleTenureId"))
            and ("amount" not in r or _amount(v, r["amount"], f"{path}.amount"))
            and ("counterpartyId" not in r or _identifier(v, r["counterpartyId"], f"{path}.counterpartyId"))
            and ("termsCommitment" not in r or _content_hash(v, r["termsCommitment"], f"{path}.termsCommitment")))


def _obligation_transition_policy(v: V, value: Any, path: str) -> bool:
    r = _rec(v, value, path, ("fromStatus", "toStatus", "acceptedAttesterIds", "action", "requiredAuthorityIds"))
    return (r is not None and _literal(v, r["fromStatus"], f"{path}.fromStatus", OBLIGATION_STATUSES) and _literal(v, r["toStatus"], f"{path}.toStatus", OBLIGATION_STATUSES)
            and _identifier_list(v, r["acceptedAttesterIds"], f"{path}.acceptedAttesterIds", True, 256) and _identifier(v, r["action"], f"{path}.action")
            and _identifier_list(v, r["requiredAuthorityIds"], f"{path}.requiredAuthorityIds", True, 256))


def _obligation_record(v: V, value: Any, path: str) -> bool:
    r = _rec(v, value, path, ("obligationId", "sourceIntentId", "causalReceiptContentHash", "durableRoleId", "creationRoleTenureId", "description", "trigger",
                              "deadline", "status", "beneficiaryId", "termsCommitment", "performanceAssigneeId", "successionRuleId", "transitionPolicies"), ("counterpartyId",))
    if r is None:
        return False
    if (not _identifier(v, r["obligationId"], f"{path}.obligationId") or not _identifier(v, r["sourceIntentId"], f"{path}.sourceIntentId")
            or not _content_hash(v, r["causalReceiptContentHash"], f"{path}.causalReceiptContentHash") or not _identifier(v, r["durableRoleId"], f"{path}.durableRoleId")
            or not _identifier(v, r["creationRoleTenureId"], f"{path}.creationRoleTenureId") or not _protocol_string(v, r["description"], f"{path}.description")
            or not _identifier(v, r["trigger"], f"{path}.trigger") or not _u53(v, r["deadline"], f"{path}.deadline")
            or not _literal(v, r["status"], f"{path}.status", ("OPEN", "OUTCOME_UNKNOWN")) or not _identifier(v, r["beneficiaryId"], f"{path}.beneficiaryId")
            or ("counterpartyId" in r and not _identifier(v, r["counterpartyId"], f"{path}.counterpartyId"))
            or not _content_hash(v, r["termsCommitment"], f"{path}.termsCommitment") or not _identifier(v, r["performanceAssigneeId"], f"{path}.performanceAssigneeId")
            or not _identifier(v, r["successionRuleId"], f"{path}.successionRuleId") or not isinstance(r["transitionPolicies"], list) or len(r["transitionPolicies"]) == 0):
        if v.problem is None:
            _fail(v, path, "contains an invalid ObligationRecord field")
        return False
    pairs: set[tuple[str, str]] = set()
    for index, member in enumerate(r["transitionPolicies"]):
        if not _obligation_transition_policy(v, member, f"{path}.transitionPolicies[{index}]"):
            return False
        pair = (member["fromStatus"], member["toStatus"])
        if pair in pairs:
            return _fail(v, f"{path}.transitionPolicies[{index}]", "duplicates a status-transition pair")
        pairs.add(pair)
    return True


def _administrative_challenge(v: V, value: Any, path: str) -> bool:
    r = _rec(v, value, path, ("version", "domain", "request", "authoritative", "consequential", "evaluationTime", "policyVersion", "rootRecognitionPolicy",
                              "eventHistoryHash", "eventHistoryPosition", "transitionEventId", "transitionEventType", "transitionEffectHash", "runtimeSessionId",
                              "credentialKeyId", "controlEpoch", "roleId", "roleTenureId", "authorityProofHash"))
    return (r is not None and r["version"] == "continuity-administrative-authorization/0.2" and _domain(v, r["domain"], f"{path}.domain")
            and _action_request(v, r["request"], f"{path}.request") and (r["authoritative"] is True or _fail(v, f"{path}.authoritative", "must be true"))
            and (r["consequential"] is True or _fail(v, f"{path}.consequential", "must be true")) and _u53(v, r["evaluationTime"], f"{path}.evaluationTime")
            and _identifier(v, r["policyVersion"], f"{path}.policyVersion") and r["rootRecognitionPolicy"] == ROOT_RECOGNITION_POLICY
            and _content_hash(v, r["eventHistoryHash"], f"{path}.eventHistoryHash") and _u53(v, r["eventHistoryPosition"], f"{path}.eventHistoryPosition")
            and _identifier(v, r["transitionEventId"], f"{path}.transitionEventId")
            and _literal(v, r["transitionEventType"], f"{path}.transitionEventType", ADMINISTRATIVE_EVENT_TYPES)
            and _content_hash(v, r["transitionEffectHash"], f"{path}.transitionEffectHash") and _identifier(v, r["runtimeSessionId"], f"{path}.runtimeSessionId")
            and _identifier(v, r["credentialKeyId"], f"{path}.credentialKeyId") and _u53(v, r["controlEpoch"], f"{path}.controlEpoch")
            and _identifier(v, r["roleId"], f"{path}.roleId") and _identifier(v, r["roleTenureId"], f"{path}.roleTenureId")
            and _content_hash(v, r["authorityProofHash"], f"{path}.authorityProofHash"))


def _administrative_authorization(v: V, value: Any, path: str) -> bool:
    r = _rec(v, value, path, ("challenge", "authorityProof", "runtimeSignature"))
    return (r is not None and _administrative_challenge(v, r["challenge"], f"{path}.challenge")
            and _authorization_proof(v, r["authorityProof"], f"{path}.authorityProof") and _signature(v, r["runtimeSignature"], f"{path}.runtimeSignature"))


def _attempt_duty_record(v: V, value: Any, path: str) -> bool:
    r = _rec(v, value, path, ("dutyId", "sourceIntentId", "sourceAdmissionEventId", "durableRoleId", "creationRoleTenureId", "description", "deadline", "performanceAssigneeId", "status"))
    return (r is not None and all(_identifier(v, r[key], f"{path}.{key}") for key in ("dutyId", "sourceIntentId", "sourceAdmissionEventId", "durableRoleId", "creationRoleTenureId"))
            and _protocol_string(v, r["description"], f"{path}.description") and _u53(v, r["deadline"], f"{path}.deadline")
            and _identifier(v, r["performanceAssigneeId"], f"{path}.performanceAssigneeId") and _literal(v, r["status"], f"{path}.status", ("OPEN",)))


def _owner_keys(v: V, value: Any, path: str) -> bool:
    if not isinstance(value, list) or len(value) == 0:
        return _fail(v, path, "must be a nonempty owner-key list")
    if len(value) > 64:
        return _fail_limit(v, path, "exceeds the 64-member owner-key bound")
    seen: set[Any] = set()
    for index, member in enumerate(value):
        p = f"{path}[{index}]"
        r = _rec(v, member, p, ("keyId", "scheme", "credential"))
        if (r is None or not _identifier(v, r["keyId"], f"{p}.keyId") or not _literal(v, r["scheme"], f"{p}.scheme", SIGNATURE_SCHEMES)
                or not (_public_key_hex(v, r["credential"], f"{p}.credential") if r["scheme"] == "ed25519" else _ethereum_address(v, r["credential"], f"{p}.credential"))):
            return False
        if r["keyId"] in seen:
            return _fail(v, f"{p}.keyId", "duplicates an owner key id")
        seen.add(r["keyId"])
    return True


def _next_key_digests(v: V, value: Any, path: str) -> bool:
    """Pre-rotation: 1..64 distinct next-key digests (``owner_key_digest``)."""
    if not isinstance(value, list) or len(value) == 0:
        return _fail(v, path, "must be a nonempty next-key digest list")
    if len(value) > 64:
        return _fail_limit(v, path, "exceeds the 64-member next-key digest bound")
    seen: set[Any] = set()
    for index, member in enumerate(value):
        if not _content_hash(v, member, f"{path}[{index}]"):
            return False
        if member in seen:
            return _fail(v, f"{path}[{index}]", "duplicates a next-key digest")
        seen.add(member)
    return True


def _next_key_authorizations(v: V, value: Any, path: str) -> bool:
    """Pre-rotation: 1..64 proofs of possession ``{keyId, scheme, signature}`` by the revealed keys, one per key id."""
    if not isinstance(value, list) or len(value) == 0:
        return _fail(v, path, "must be a nonempty next-key authorization list")
    if len(value) > 64:
        return _fail_limit(v, path, "exceeds the 64-member next-key authorization bound")
    seen: set[Any] = set()
    for index, member in enumerate(value):
        p = f"{path}[{index}]"
        r = _rec(v, member, p, ("keyId", "scheme", "signature"))
        if r is None or not _identifier(v, r["keyId"], f"{p}.keyId") or not _literal(v, r["scheme"], f"{p}.scheme", SIGNATURE_SCHEMES):
            return False
        if not is_hex_signature(r["signature"], r["scheme"]):
            return _fail(v, f"{p}.signature", f"must be a lowercase {'64' if r['scheme'] == 'ed25519' else '65'}-byte signature")
        if r["keyId"] in seen:
            return _fail(v, f"{p}.keyId", "duplicates a next-key authorization key id")
        seen.add(r["keyId"])
    return True


# ---------------------------------------------------------------- remote witness bindings (WITNESSES_BOUND / WITNESSES_UNBOUND)

_WITNESS_URL = re.compile(r"https?://[^/@]+(?:/.*)?", re.S)


def _witness_url(v: V, value: Any, path: str) -> bool:
    """A remote witness URL as the witness client normalises it: printable ASCII, http(s), an authority without userinfo,
    no query, fragment or backslash, no trailing slash, at most 2048 characters."""
    if (isinstance(value, str) and len(value) <= 2048 and len(value) > 0 and all(0x21 <= ord(c) <= 0x7E for c in value)
            and _WITNESS_URL.fullmatch(value) is not None and not any(c in value for c in "?#\\") and not value.endswith("/")):
        return True
    return _fail(v, path, "must be a normalised http(s) witness URL")


def _witness_verifier_key(v: V, value: Any, path: str) -> bool:
    if not isinstance(value, str):
        return _fail(v, path, "must be a note verifier key")
    try:
        parse_verifier_key(value)
    except (NoteError, ValueError):
        return _fail(v, path, "must be a note verifier key")
    return True


def _bound_witness(v: V, value: Any, path: str) -> bool:
    r = _rec(v, value, path, ("url", "verifierKey"), ("name", "allowInsecureHttp", "registration"))
    return (r is not None and _witness_url(v, r["url"], f"{path}.url") and _witness_verifier_key(v, r["verifierKey"], f"{path}.verifierKey")
            and ("name" not in r or _identifier(v, r["name"], f"{path}.name"))
            and ("allowInsecureHttp" not in r or r["allowInsecureHttp"] is True or _fail(v, f"{path}.allowInsecureHttp", "must be true when present"))
            and ("registration" not in r or _is_record(r["registration"]) or _fail(v, f"{path}.registration", "must be a witness receipt record")))


def _witness_policy(v: V, value: Any, path: str) -> bool:
    """The owner-signed policy minimum: quorum 1..16, requireOnOpen, maxUnwitnessedEvents >= 1 (a safe integer)."""
    r = _rec(v, value, path, ("quorum", "requireOnOpen", "maxUnwitnessedEvents"))
    return (r is not None
            and ((_u53(v, r["quorum"], f"{path}.quorum") and 1 <= r["quorum"] <= MAX_BOUND_WITNESSES) or _fail(v, f"{path}.quorum", f"must be an integer in 1..{MAX_BOUND_WITNESSES}"))
            and (isinstance(r["requireOnOpen"], bool) or _fail(v, f"{path}.requireOnOpen", "must be boolean"))
            and ((_u53(v, r["maxUnwitnessedEvents"], f"{path}.maxUnwitnessedEvents") and r["maxUnwitnessedEvents"] >= 1)
                 or _fail(v, f"{path}.maxUnwitnessedEvents", "must be a positive integer")))


def _witness_list(v: V, value: Any, path: str, member: Any, key_of: Any, what: str) -> bool:
    if not isinstance(value, list):
        return _fail(v, path, f"must be a nonempty {what} list")
    if len(value) > MAX_BOUND_WITNESSES:
        return _fail_limit(v, path, f"exceeds the {MAX_BOUND_WITNESSES}-member {what} bound")
    if len(value) == 0:
        return _fail(v, path, f"must be a nonempty {what} list")
    seen: set[Any] = set()
    for index, item in enumerate(value):
        if not member(v, item, f"{path}[{index}]"):
            return False
        key = key_of(item)
        if key in seen:
            return _fail(v, f"{path}[{index}]", "duplicates a verifier key")
        seen.add(key)
    return True


def _loss_head(v: V, value: Any, path: str) -> bool:
    h = _rec(v, value, path, ("verifierKey", "head"))
    return h is not None and _witness_verifier_key(v, h["verifierKey"], f"{path}.verifierKey") and _history_head(v, h["head"], f"{path}.head")


def _accepted_loss(v: V, value: Any, path: str) -> bool:
    r = _rec(v, value, path, ("reason", "heads"))
    return (r is not None and _identifier(v, r["reason"], f"{path}.reason")
            and _witness_list(v, r["heads"], f"{path}.heads", _loss_head, lambda item: item["verifierKey"], "accepted-loss head"))


# ---------------------------------------------------------------- named-limit preflight (spec 01 §C.7)
# Limit nodes: "I" identifier, "B" bigint, ("r", {field: node}), ("l", node|None, max, name), ("t", tag, common|None, {variant: node})


def _R(fields: dict[str, Any]) -> tuple:
    return ("r", fields)


def _L(node: Any, maximum: int | None = None, name: str | None = None) -> tuple:
    return ("l", node, maximum, name)


def _T(tag: str, variants: dict[str, Any], common: Any = None) -> tuple:
    return ("t", tag, common, variants)


def _ids(*names: str) -> dict[str, Any]:
    return {name: "I" for name in names}


def _id_set(name: str) -> tuple:
    return _L("I", 256, name)


_LIMIT_DOMAIN = _R(_ids("deploymentId"))
_LIMIT_ADAPTER_PROFILE = _R(_ids("profileId", "profileVersion"))
_LIMIT_DIGEST = _R(_ids("algorithm"))
_LIMIT_ADAPTER_EVIDENCE = _R({**_ids("schemaVersion", "kind", "intentId"), "adapterProfile": _LIMIT_ADAPTER_PROFILE, "domain": _LIMIT_DOMAIN,
                              "result": _R({"kind": "I", "reportDigest": _LIMIT_DIGEST, "publicationManifestDigest": _LIMIT_DIGEST, "manifestDigest": _LIMIT_DIGEST, "transitionDigest": _LIMIT_DIGEST})})
_LIMIT_VERSION_SET = _R(_ids(*_LEGACY_VERSION_KEYS, *_TRELLIS_VERSION_KEYS))
_LIMIT_ACTION_REQUEST = _R({**_ids("actorId", "action", "resource", "counterpartyId"), "amount": "B"})
_LIMIT_EVIDENCE_REFERENCE = _T("kind", {
    "EVENT": _R(_ids("eventId")), "AUTHORITY": _R(_ids("authorityId", "grantEventId")), "RUNTIME_CREDENTIAL": _R(_ids("keyId", "sessionId", "admissionEventId")),
    "RECEIPT_COMMITMENT": _R(_ids("eventId")), "EXTERNAL": _R(_ids("evidenceType", "reference", "attesterId")),
})


def _limit_constraints(n: int) -> tuple:
    return _R({"actions": _id_set("action set"), "resources": _id_set("resource set"), "requiredIntersectionIds": _L("I", n, "required-intersection set"),
               "maxAmount": "B", "maxCumulativeAmount": "B"})


_LIMIT_GRANT_CONSTRAINTS = _limit_constraints(32)
_LIMIT_PERMISSION_GRANT = _R({**_ids("authorityId", "grantorId", "granteeId", "rootAuthorityId", "parentAuthorityId"), "constraints": _LIMIT_GRANT_CONSTRAINTS})
_LIMIT_AUTHORITY_GRANT = _T("kind", {
    "PERMISSION": _R(_ids("granteeId", "rootAuthorityId", "parentAuthorityId")),
    "PROHIBITION": _T("scope", {"ROOT": _R(_ids("rootAuthorityId", "parentAuthorityId")), "GLOBAL": _R({})}, _R(_ids("subjectActorId"))),
}, _R({**_ids("authorityId", "grantorId"), "constraints": _LIMIT_GRANT_CONSTRAINTS}))
_LIMIT_RECOGNIZED_ROOT = _R(_ids(*_ROOT_KEYS))
_LIMIT_PERMISSION_PATH = _L(_LIMIT_PERMISSION_GRANT, 32, "authority path")
_LIMIT_AUTHORIZATION_PROOF = _R({
    "domain": _LIMIT_DOMAIN, "policyVersion": "I", "request": _LIMIT_ACTION_REQUEST, "recognizedRoot": _LIMIT_RECOGNIZED_ROOT, "permissionPath": _LIMIT_PERMISSION_PATH,
    "intersections": _L(_R({"requiredAuthorityId": "I", "requiredByAuthorityIds": _id_set("required-by authority set"), "recognizedRoot": _LIMIT_RECOGNIZED_ROOT,
                            "path": _LIMIT_PERMISSION_PATH, "effectiveConstraints": _limit_constraints(256)}), 256, "proof-intersection set"),
    "effectiveConstraints": _limit_constraints(256), "controllingAuthorityIds": _id_set("controlling-authority set"),
    "usageSnapshot": _L(_R({"authorityId": "I", "admittedCumulativeAmount": "B"}), 256, "authority-usage set"),
    "authorityEvidence": _L(_R(_ids("authorityId", "grantEventId")), 1024, "authority-evidence set"),
    "checkedProhibitionIds": _id_set("checked-prohibition set"), **_ids("runtimeSessionId", "credentialKeyId", "roleId", "roleTenureId", "intentId", "nonce"),
})
_LIMIT_TRANSACTION_INTENT = _R({"adapterProfile": _LIMIT_ADAPTER_PROFILE, **_ids("intentId", "nonce", "actorId", "action", "resource", "roleId", "roleTenureId", "counterpartyId"), "amount": "B"})
_LIMIT_OBLIGATION_RECORD = _R({**_ids("obligationId", "sourceIntentId", "durableRoleId", "creationRoleTenureId", "trigger", "beneficiaryId", "counterpartyId", "performanceAssigneeId", "successionRuleId"),
                               "transitionPolicies": _L(_R({"acceptedAttesterIds": _id_set("accepted-attester set"), "action": "I", "requiredAuthorityIds": _id_set("required-authority set")}))})
_LIMIT_ADMINISTRATIVE_AUTHORIZATION = _R({
    "challenge": _R({"domain": _LIMIT_DOMAIN, "request": _LIMIT_ACTION_REQUEST, **_ids("policyVersion", "transitionEventId", "runtimeSessionId", "credentialKeyId", "roleId", "roleTenureId")}),
    "authorityProof": _LIMIT_AUTHORIZATION_PROOF,
})
_ADMIN = {"administrativeAuthorization": _LIMIT_ADMINISTRATIVE_AUTHORIZATION}
NAMED_LIMITS: dict[str, tuple] = {
    "DEPLOYMENT_INITIALIZED": _R({"domain": _LIMIT_DOMAIN, **_ids("canonicalLineageId", "policyVersion", "globalPolicySourceId"), "versions": _LIMIT_VERSION_SET,
                                  "ownerKeys": _L(_R(_ids("keyId")), 64, "owner-key set"), "nextKeyDigests": _L(None, 64, "next-key digest set")}),
    "PRINCIPAL_CREATED": _R(_ids("principalId")),
    "AGENT_CREATED": _R(_ids("agentId", "principalId", "controllerId")),
    "ROLE_CREATED": _R(_ids("roleId", "principalId")),
    "SUCCESSION_RULE_DECLARED": _R(_ids("ruleId", "principalId", "predecessorAgentId", "successorAgentId", "roleId")),
    "AGENT_APPOINTED": _R(_ids("agentId", "roleId", "roleTenureId", "principalId", "successionRuleId")),
    "AGENT_UNAPPOINTED": _R(_ids("agentId", "roleId", "roleTenureId", "principalId")),
    "ROLE_TRANSFERRED": _R(_ids("roleId", "fromAgentId", "fromRoleTenureId", "toAgentId", "toRoleTenureId", "principalId", "successionRuleId")),
    "RUNTIME_SESSION_ADMITTED": _R(_ids("sessionId", "agentId", "controllerId", "credentialKeyId")),
    "CONTROL_EPOCH_ADVANCED": _R(_ids("agentId", "controllerId")),
    "AUTHORITY_GRANTED": _R({"grant": _LIMIT_AUTHORITY_GRANT}),
    "AUTHORITY_REVOKED": _R(_ids("authorityId", "revokerId")),
    "TRANSACTION_INTENT_DECLARED": _LIMIT_TRANSACTION_INTENT,
    "TRANSACTION_INTENT_ADMITTED": _R({"intentId": "I", "authorizationProof": _LIMIT_AUTHORIZATION_PROOF}),
    "TRANSACTION_INTENT_CONSUMED": _R({**_ids("intentId", "adapterId", "transactionReference"), "acknowledgment": _LIMIT_ADAPTER_EVIDENCE, "evidenceReference": _LIMIT_EVIDENCE_REFERENCE}),
    "TRANSACTION_OUTCOME_RECORDED": _R({**_ids("intentId", "attesterId"), "noEffect": _LIMIT_ADAPTER_EVIDENCE, "evidenceReference": _LIMIT_EVIDENCE_REFERENCE}),
    "RECEIPT_RECORDED": _R(_ids("intentId", "issuerAgentId", "runtimeSessionId", "roleId", "roleTenureId")),
    "OBLIGATION_CREATED": _R({"record": _LIMIT_OBLIGATION_RECORD, "actorId": "I", **_ADMIN}),
    "OBLIGATION_PERFORMANCE_ASSIGNED": _R({**_ids("obligationId", "fromAgentId", "toAgentId", "successionRuleId", "actorId"), **_ADMIN}),
    "OBLIGATION_STATUS_RECORDED": _R({**_ids("obligationId", "actorId", "action", "attesterId"), **_ADMIN, "evidenceReference": _LIMIT_EVIDENCE_REFERENCE}),
    "AGENT_TERMINATED": _R(_ids("agentId", "principalId", "successionRuleId", "roleId", "roleTenureId")),
    "OUTCOME_OBSERVATION_RECORDED": _R({**_ids("intentId", "sourceAdmissionEventId", "actorId"), "acknowledgment": _LIMIT_ADAPTER_EVIDENCE, **_ADMIN}),
    "ATTEMPT_DUTY_CREATED": _R({"record": _R(_ids("dutyId", "sourceIntentId", "sourceAdmissionEventId", "durableRoleId", "creationRoleTenureId", "performanceAssigneeId")), "actorId": "I", **_ADMIN}),
    "ATTEMPT_DUTY_ASSIGNED": _R({**_ids("dutyId", "fromAgentId", "toAgentId", "actorId"), **_ADMIN}),
    "ATTEMPT_DUTY_REVIEW_CLOSED": _R({**_ids("dutyId", "actorId"), "observationEventIds": _L("I", 128, "attempt-review-observations"), **_ADMIN}),
    "ANCHOR_RECORDED": _R(_ids("anchor")),
    "OWNER_KEYS_ROTATED": _R({"ownerKeys": _L(_R(_ids("keyId")), 64, "owner-key set"), "reason": "I", "nextKeyDigests": _L(None, 64, "next-key digest set"),
                              "nextKeyAuthorizations": _L(_R(_ids("keyId")), 64, "next-key authorization set")}),
    "WITNESSES_BOUND": _R({"witnesses": _L(_R(_ids("name")), MAX_BOUND_WITNESSES, "remote witness set")}),
    "WITNESSES_UNBOUND": _R({"verifierKeys": _L(None, MAX_BOUND_WITNESSES, "remote witness set"),
                             "acceptedLoss": _R({"reason": "I", "heads": _L(None, MAX_BOUND_WITNESSES, "accepted-loss head set")})}),
}


def _preflight(v: V, value: Any, path: str, node: Any) -> bool:
    if node == "I":
        return not isinstance(value, str) or _utf8_status(value, 256) != "LIMIT" or _fail_limit(v, path, "must be an Identifier")
    if node == "B":
        return (not isinstance(value, BigInt) or (-MAX_PROTOCOL_BIGINT <= value.value <= MAX_PROTOCOL_BIGINT)
                or _fail_limit(v, path, "exceeds the 256-bit BigInt magnitude bound"))
    kind = node[0]
    if kind == "r":
        if not _is_record(value):
            return True
        for name, child in node[1].items():
            if name in value and not _preflight(v, value[name], f"{path}.{name}", child):
                return False
        return True
    if kind == "l":
        _, child, maximum, name = node
        if not isinstance(value, list):
            return True
        if maximum is not None and len(value) > maximum:
            return _fail_limit(v, path, f"exceeds the {maximum}-member {name or 'named list'} bound")
        if child is None:
            return True
        return all(_preflight(v, member, f"{path}[{index}]", child) for index, member in enumerate(value))
    _, tag, common, variants = node
    if not _is_record(value):
        return True
    if common is not None and not _preflight(v, value, path, common):
        return False
    variant = variants.get(value.get(tag)) if isinstance(value.get(tag), str) else None
    return variant is None or _preflight(v, value, path, variant)


# ---------------------------------------------------------------- per-type data shapes (spec 01 §C.6)

P = "$.data"
_GENESIS_REQUIRED = ("domain", "adapterPolicyHash", "canonicalLineageId", "versions", "policyVersion", "rootRecognitionPolicy", "globalPolicySourceId", "timeSource", "finality")


def _id_fields(v: V, r: dict[str, Any], *keys: str) -> bool:
    return all(_identifier(v, r[key], f"{P}.{key}") for key in keys)


def _genesis_data(v: V, value: Any) -> bool:
    trellis = v.format == TRELLIS_FORMAT
    r = _rec(v, value, P, (*_GENESIS_REQUIRED, "ownerKeys") if trellis else _GENESIS_REQUIRED, ("nextKeyDigests", "capacity", "migratedFrom") if trellis else ())
    if (r is None or not _domain(v, r["domain"], f"{P}.domain") or resolve_adapter_policy(r["adapterPolicyHash"]) is None
            or not _identifier(v, r["canonicalLineageId"], f"{P}.canonicalLineageId") or not _version_set(v, r["versions"], f"{P}.versions")
            or not _identifier(v, r["policyVersion"], f"{P}.policyVersion") or r["rootRecognitionPolicy"] != ROOT_RECOGNITION_POLICY
            or r["timeSource"] != "EVENT_TIMESTAMP" or r["finality"] != "LOCAL_ONLY" or not _identifier(v, r["globalPolicySourceId"], f"{P}.globalPolicySourceId")):
        return False
    if not trellis:
        return True
    if not _owner_keys(v, r["ownerKeys"], f"{P}.ownerKeys"):
        return False
    if "nextKeyDigests" in r:
        # Pre-rotation from the start: epoch 0's commitment, committed by the history id. It may not name a genesis owner key.
        if not _next_key_digests(v, r["nextKeyDigests"], f"{P}.nextKeyDigests"):
            return False
        clash = declared_digest_failure("genesis", r["ownerKeys"], r["nextKeyDigests"])
        if clash is not None:
            return _fail(v, f"{P}.nextKeyDigests", clash)
    if "capacity" in r:
        c = _rec(v, r["capacity"], f"{P}.capacity", ("maxEvents",))
        if c is None or not (c["maxEvents"] is None or _u53(v, c["maxEvents"], f"{P}.capacity.maxEvents")):
            return False
    if "migratedFrom" in r:
        m = _rec(v, r["migratedFrom"], f"{P}.migratedFrom", ("format", "historyHash", "position", "recordHash", "genesis", "genesisEventId", "genesisTimestamp"))
        if (m is None or not _literal(v, m["format"], f"{P}.migratedFrom.format", (LEGACY_FORMAT,)) or not _content_hash(v, m["historyHash"], f"{P}.migratedFrom.historyHash")
                or not _u53(v, m["position"], f"{P}.migratedFrom.position") or not _content_hash(v, m["recordHash"], f"{P}.migratedFrom.recordHash")
                or not _identifier(v, m["genesisEventId"], f"{P}.migratedFrom.genesisEventId") or not _u53(v, m["genesisTimestamp"], f"{P}.migratedFrom.genesisTimestamp")):
            return False
        legacy = V(LEGACY_FORMAT)
        if not _preflight(legacy, m["genesis"], P, NAMED_LIMITS["DEPLOYMENT_INITIALIZED"]) or not _genesis_data(legacy, m["genesis"]):
            problem = legacy.problem or ""
            if legacy.kind == "LIMIT":
                return _fail_limit(v, f"{P}.migratedFrom.genesis{problem[len(P):]}", "invalid legacy genesis")
            location = re.sub(r": .*$", "", problem[len(P):]) if problem else ""
            return _fail(v, f"{P}.migratedFrom.genesis{location}", re.sub(r"^[^:]*: ", "", problem) if problem else "invalid legacy genesis")
    return True


def _session_data(v: V, value: Any) -> bool:
    base = ("sessionId", "agentId", "controllerId", "controlEpoch", "credentialKeyId")
    if v.format == LEGACY_FORMAT:
        r = _rec(v, value, P, (*base, "credentialAddress"), ("expiresAt",))
        return (r is not None and _id_fields(v, r, "sessionId", "agentId", "controllerId") and _u53(v, r["controlEpoch"], f"{P}.controlEpoch")
                and _identifier(v, r["credentialKeyId"], f"{P}.credentialKeyId") and _ethereum_address(v, r["credentialAddress"], f"{P}.credentialAddress")
                and ("expiresAt" not in r or _u53(v, r["expiresAt"], f"{P}.expiresAt")))
    r = _rec(v, value, P, (*base, "credentialScheme"), ("expiresAt", "credentialAddress", "credentialPublicKey"))
    if (r is None or not _id_fields(v, r, "sessionId", "agentId", "controllerId") or not _u53(v, r["controlEpoch"], f"{P}.controlEpoch")
            or not _identifier(v, r["credentialKeyId"], f"{P}.credentialKeyId") or not _literal(v, r["credentialScheme"], f"{P}.credentialScheme", SIGNATURE_SCHEMES)
            or ("expiresAt" in r and not _u53(v, r["expiresAt"], f"{P}.expiresAt"))):
        return False
    # A migrated legacy prefix re-records legacy admissions, whose credential is always an Ethereum address; the shadow's
    # legacy view could not hold an ed25519 key (it read `credentialAddress` of such an event and raised KeyError).
    if v.shadow and r["credentialScheme"] != "eip191-personal-sign-keccak256":
        return _fail(v, f"{P}.credentialScheme", "must be eip191-personal-sign-keccak256 in a migrated legacy prefix")
    if r["credentialScheme"] == "ed25519":
        return _public_key_hex(v, r.get("credentialPublicKey"), f"{P}.credentialPublicKey") and ("credentialAddress" not in r or _fail(v, f"{P}.credentialAddress", "must be absent for ed25519"))
    return _ethereum_address(v, r.get("credentialAddress"), f"{P}.credentialAddress") and ("credentialPublicKey" not in r or _fail(v, f"{P}.credentialPublicKey", "must be absent for eip191"))


def _validate_event_data(v: V, event_type: str, value: Any) -> bool:
    if event_type == "DEPLOYMENT_INITIALIZED":
        return _genesis_data(v, value)
    if event_type == "PRINCIPAL_CREATED":
        r = _rec(v, value, P, ("principalId",))
        return r is not None and _id_fields(v, r, "principalId")
    if event_type == "AGENT_CREATED":
        r = _rec(v, value, P, ("agentId", "principalId", "controllerId", "initialControlEpoch"))
        return r is not None and _id_fields(v, r, "agentId", "principalId", "controllerId") and _u53(v, r["initialControlEpoch"], f"{P}.initialControlEpoch")
    if event_type == "ROLE_CREATED":
        r = _rec(v, value, P, ("roleId", "principalId", "exclusive"))
        return r is not None and _id_fields(v, r, "roleId", "principalId") and (r["exclusive"] is True or _fail(v, f"{P}.exclusive", "must be true"))
    if event_type == "SUCCESSION_RULE_DECLARED":
        r = _rec(v, value, P, ("ruleId", "principalId", "predecessorAgentId", "successorAgentId", "roleId", "trigger", "permittedEventTypes"))
        return (r is not None and _id_fields(v, r, "ruleId", "principalId", "predecessorAgentId", "successorAgentId", "roleId") and r["trigger"] == "AGENT_TERMINATED"
                and _enum_list(v, r["permittedEventTypes"], f"{P}.permittedEventTypes", ("AGENT_TERMINATED", "ROLE_TRANSFERRED", "OBLIGATION_PERFORMANCE_ASSIGNED"), True))
    if event_type == "AGENT_APPOINTED":
        r = _rec(v, value, P, ("agentId", "roleId", "roleTenureId", "tenureNumber", "principalId"), ("successionRuleId",))
        return (r is not None and _id_fields(v, r, "agentId", "roleId", "roleTenureId") and _u53(v, r["tenureNumber"], f"{P}.tenureNumber")
                and _id_fields(v, r, "principalId") and ("successionRuleId" not in r or _id_fields(v, r, "successionRuleId")))
    if event_type == "AGENT_UNAPPOINTED":
        r = _rec(v, value, P, ("agentId", "roleId", "roleTenureId", "principalId"))
        return r is not None and _id_fields(v, r, "agentId", "roleId", "roleTenureId", "principalId")
    if event_type == "ROLE_TRANSFERRED":
        r = _rec(v, value, P, ("roleId", "fromAgentId", "fromRoleTenureId", "toAgentId", "toRoleTenureId", "toTenureNumber", "principalId", "transferKind"), ("successionRuleId",))
        return (r is not None and _id_fields(v, r, "roleId", "fromAgentId", "fromRoleTenureId", "toAgentId", "toRoleTenureId")
                and _u53(v, r["toTenureNumber"], f"{P}.toTenureNumber") and _id_fields(v, r, "principalId")
                and _literal(v, r["transferKind"], f"{P}.transferKind", ("SUCCESSION", "REASSIGNMENT")) and ("successionRuleId" not in r or _id_fields(v, r, "successionRuleId")))
    if event_type == "RUNTIME_SESSION_ADMITTED":
        return _session_data(v, value)
    if event_type == "CONTROL_EPOCH_ADVANCED":
        r = _rec(v, value, P, ("agentId", "controllerId", "fromEpoch", "toEpoch"))
        return r is not None and _id_fields(v, r, "agentId", "controllerId") and _u53(v, r["fromEpoch"], f"{P}.fromEpoch") and _u53(v, r["toEpoch"], f"{P}.toEpoch")
    if event_type == "AUTHORITY_GRANTED":
        r = _rec(v, value, P, ("grant",))
        return r is not None and _authority_grant(v, r["grant"], f"{P}.grant")
    if event_type == "AUTHORITY_REVOKED":
        r = _rec(v, value, P, ("authorityId", "revokerId"))
        return r is not None and _id_fields(v, r, "authorityId", "revokerId")
    if event_type == "TRANSACTION_INTENT_DECLARED":
        return _transaction_intent(v, value, P)
    if event_type == "TRANSACTION_INTENT_ADMITTED":
        r = _rec(v, value, P, ("intentId", "evaluationTime", "expectedHistoryHead", "authorizationProof", "runtimeAuthorizationHash", "runtimeSignature"))
        return (r is not None and _id_fields(v, r, "intentId") and _u53(v, r["evaluationTime"], f"{P}.evaluationTime")
                and _history_head(v, r["expectedHistoryHead"], f"{P}.expectedHistoryHead") and _authorization_proof(v, r["authorizationProof"], f"{P}.authorizationProof")
                and _content_hash(v, r["runtimeAuthorizationHash"], f"{P}.runtimeAuthorizationHash") and _signature(v, r["runtimeSignature"], f"{P}.runtimeSignature"))
    if event_type == "TRANSACTION_INTENT_CONSUMED":
        r = _rec(v, value, P, ("intentId", "adapterId", "idempotencyKey", "submissionFingerprint", "status", "evidenceReference", "acknowledgment", "transactionReference"))
        return (r is not None and _id_fields(v, r, "intentId", "adapterId") and _content_hash(v, r["idempotencyKey"], f"{P}.idempotencyKey")
                and _content_hash(v, r["submissionFingerprint"], f"{P}.submissionFingerprint") and r["status"] == "SUBMITTED" and _id_fields(v, r, "transactionReference")
                and _adapter_evidence(v, r["acknowledgment"], f"{P}.acknowledgment") and _evidence_reference(v, r["evidenceReference"], f"{P}.evidenceReference"))
    if event_type == "TRANSACTION_OUTCOME_RECORDED":
        keys = ("intentId", "status", "attesterId", "evidenceReference")
        r = _rec(v, value, P, keys, ("noEffect",))
        if r is not None and r["status"] != "FAILED" and _rec(v, value, P, keys) is None:
            return False
        return (r is not None and _id_fields(v, r, "intentId") and _literal(v, r["status"], f"{P}.status", ("CONFIRMED", "FAILED", "DISPUTED", "OUTCOME_UNKNOWN"))
                and (_adapter_evidence(v, r.get("noEffect"), f"{P}.noEffect", True) if r["status"] == "FAILED" else "noEffect" not in r)
                and _id_fields(v, r, "attesterId") and _evidence_reference(v, r["evidenceReference"], f"{P}.evidenceReference"))
    if event_type == "RECEIPT_RECORDED":
        r = _rec(v, value, P, ("receiptContentHash", "receiptArtifactCommitment", "intentId", "issuerAgentId", "runtimeSessionId", "controlEpoch", "roleId", "roleTenureId", "authorizationProofHash"))
        return (r is not None and _content_hash(v, r["receiptContentHash"], f"{P}.receiptContentHash") and _content_hash(v, r["receiptArtifactCommitment"], f"{P}.receiptArtifactCommitment")
                and _id_fields(v, r, "intentId", "issuerAgentId", "runtimeSessionId") and _u53(v, r["controlEpoch"], f"{P}.controlEpoch") and _id_fields(v, r, "roleId", "roleTenureId")
                and _content_hash(v, r["authorizationProofHash"], f"{P}.authorizationProofHash"))
    if event_type == "OBLIGATION_CREATED":
        r = _rec(v, value, P, ("record", "actorId", "administrativeAuthorization"))
        return (r is not None and _obligation_record(v, r["record"], f"{P}.record") and _id_fields(v, r, "actorId")
                and _administrative_authorization(v, r["administrativeAuthorization"], f"{P}.administrativeAuthorization"))
    if event_type == "OUTCOME_OBSERVATION_RECORDED":
        r = _rec(v, value, P, ("intentId", "sourceAdmissionEventId", "acknowledgment", "actorId", "administrativeAuthorization"))
        return (r is not None and _id_fields(v, r, "intentId", "sourceAdmissionEventId") and _is_record(r["acknowledgment"])
                and r["acknowledgment"].get("schemaVersion") == REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION and _adapter_evidence(v, r["acknowledgment"], f"{P}.acknowledgment")
                and _id_fields(v, r, "actorId") and _administrative_authorization(v, r["administrativeAuthorization"], f"{P}.administrativeAuthorization"))
    if event_type == "ATTEMPT_DUTY_CREATED":
        r = _rec(v, value, P, ("record", "actorId", "administrativeAuthorization"))
        return (r is not None and _attempt_duty_record(v, r["record"], f"{P}.record") and _id_fields(v, r, "actorId")
                and _administrative_authorization(v, r["administrativeAuthorization"], f"{P}.administrativeAuthorization"))
    if event_type == "ATTEMPT_DUTY_REVIEW_CLOSED":
        r = _rec(v, value, P, ("dutyId", "actorId", "observationEventIds", "summaryDigest", "administrativeAuthorization"))
        return (r is not None and _id_fields(v, r, "dutyId", "actorId") and _review_observation_ids(v, r["observationEventIds"], f"{P}.observationEventIds")
                and _content_hash(v, r["summaryDigest"], f"{P}.summaryDigest") and _administrative_authorization(v, r["administrativeAuthorization"], f"{P}.administrativeAuthorization"))
    if event_type == "ATTEMPT_DUTY_ASSIGNED":
        r = _rec(v, value, P, ("dutyId", "fromAgentId", "toAgentId", "actorId", "administrativeAuthorization"))
        return (r is not None and _id_fields(v, r, "dutyId", "fromAgentId", "toAgentId", "actorId")
                and _administrative_authorization(v, r["administrativeAuthorization"], f"{P}.administrativeAuthorization"))
    if event_type == "OBLIGATION_PERFORMANCE_ASSIGNED":
        r = _rec(v, value, P, ("obligationId", "fromAgentId", "toAgentId", "successionRuleId", "actorId", "administrativeAuthorization"))
        return (r is not None and _id_fields(v, r, "obligationId", "fromAgentId", "toAgentId", "successionRuleId", "actorId")
                and _administrative_authorization(v, r["administrativeAuthorization"], f"{P}.administrativeAuthorization"))
    if event_type == "OBLIGATION_STATUS_RECORDED":
        r = _rec(v, value, P, ("obligationId", "fromStatus", "toStatus", "actorId", "action", "administrativeAuthorization", "attesterId", "evidenceReference"))
        return (r is not None and _id_fields(v, r, "obligationId") and _literal(v, r["fromStatus"], f"{P}.fromStatus", OBLIGATION_STATUSES)
                and _literal(v, r["toStatus"], f"{P}.toStatus", OBLIGATION_STATUSES) and _id_fields(v, r, "actorId", "action")
                and _administrative_authorization(v, r["administrativeAuthorization"], f"{P}.administrativeAuthorization") and _id_fields(v, r, "attesterId")
                and _evidence_reference(v, r["evidenceReference"], f"{P}.evidenceReference"))
    if event_type == "AGENT_TERMINATED":
        r = _rec(v, value, P, ("agentId", "principalId", "successionRuleId", "roleId", "roleTenureId"))
        return r is not None and _id_fields(v, r, "agentId", "principalId", "successionRuleId", "roleId", "roleTenureId")
    if event_type == "ANCHOR_RECORDED":
        r = _rec(v, value, P, ("anchoredHead", "anchor", "receipt", "anchoredAt"))
        return (r is not None and _history_head(v, r["anchoredHead"], f"{P}.anchoredHead") and _literal(v, r["anchor"], f"{P}.anchor", ANCHOR_NAMES)
                and (_is_record(r["receipt"]) or _fail(v, f"{P}.receipt", "must be a plain protocol record")) and _u53(v, r["anchoredAt"], f"{P}.anchoredAt"))
    if event_type == "OWNER_KEYS_ROTATED":
        # The new set has the genesis owner-key shape; `reason` is identifier-shaped text (1..256 UTF-8 bytes, no control characters).
        # Pre-rotation: `nextKeyDigests` commits the new epoch to its next keys; `nextKeyAuthorizations` proves possession of the revealed keys.
        r = _rec(v, value, P, ("ownerKeys",), ("reason", "nextKeyDigests", "nextKeyAuthorizations"))
        return (r is not None and _owner_keys(v, r["ownerKeys"], f"{P}.ownerKeys")
                and ("reason" not in r or _identifier(v, r["reason"], f"{P}.reason"))
                and ("nextKeyDigests" not in r or _next_key_digests(v, r["nextKeyDigests"], f"{P}.nextKeyDigests"))
                and ("nextKeyAuthorizations" not in r or _next_key_authorizations(v, r["nextKeyAuthorizations"], f"{P}.nextKeyAuthorizations")))
    if event_type == "WITNESSES_BOUND":
        # Each witness (url, verifier key, optional name, allowInsecureHttp and its signed REGISTERED receipt) and the policy minimum.
        r = _rec(v, value, P, ("witnesses", "policy"))
        return (r is not None and _witness_list(v, r["witnesses"], f"{P}.witnesses", _bound_witness, lambda item: item["verifierKey"], "remote witness")
                and _witness_policy(v, r["policy"], f"{P}.policy"))
    if event_type == "WITNESSES_UNBOUND":
        r = _rec(v, value, P, ("verifierKeys", "policy"), ("acceptedLoss",))
        return (r is not None and _witness_list(v, r["verifierKeys"], f"{P}.verifierKeys", _witness_verifier_key, lambda item: item, "remote witness")
                and _witness_policy(v, r["policy"], f"{P}.policy") and ("acceptedLoss" not in r or _accepted_loss(v, r["acceptedLoss"], f"{P}.acceptedLoss")))
    return False


# ---------------------------------------------------------------- envelope, genesis probe, public API


@dataclass(frozen=True)
class EventValidation:
    ok: bool
    event: dict[str, Any] | None = None
    code: str | None = None
    reason: str | None = None


def _invalid(code: str, reason: str) -> EventValidation:
    return EventValidation(False, None, code, reason)


def _schema_failure(v: V, fallback: str) -> EventValidation:
    return _invalid("INVALID_INPUT" if v.kind == "LIMIT" else "EVENT_DATA_INVALID", v.problem or fallback)


_SCALAR_DEFECT = re.compile("finite|safe integer|negative zero|well-formed|256-bit|bigint", re.IGNORECASE)


def _capture_failure(error: Exception) -> EventValidation:
    if isinstance(error, CanonicalError):
        return _invalid("EVENT_DATA_INVALID" if not error.limit and _SCALAR_DEFECT.search(error.reason) else "INVALID_INPUT", f"$.data: {error.reason}")
    return _invalid("INVALID_INPUT", "$.data: failed canonical capture")


def legacy_projection(event: dict[str, Any]) -> dict[str, Any]:
    """A re-recorded event as the legacy source held it: without the format-1 additions (docs/HISTORY-FORMAT.md §11)."""
    added = [key for key in ("controlAuthorization", *(("credentialScheme",) if event["type"] == "RUNTIME_SESSION_ADMITTED" else ())) if key in event["data"]]
    if not added:
        return event
    data = {key: member for key, member in event["data"].items() if key not in added}
    return {"id": event["id"], "type": event["type"], "timestamp": event["timestamp"], "data": data}


def control_effect(data: dict[str, Any]) -> dict[str, Any]:
    """The data a control event commits to: everything except its own authorization.

    A captured ``data`` that is not a record (a bigint-marker-shaped ``data`` captures to a BigInt) is returned as it is,
    as the TypeScript ``controlEffect`` does, so the closed schema rejects it (EVENT_DATA_INVALID) instead of raising."""
    if not isinstance(data, dict) or "controlAuthorization" not in data:
        return data
    return {key: member for key, member in data.items() if key != "controlAuthorization"}


def signed_control_effect(data: dict[str, Any]) -> dict[str, Any]:
    """The data the owner signatures over a control event cover: the effect without the signatures made over that same
    challenge (``controlAuthorization`` and, on a pre-rotated OWNER_KEYS_ROTATED, ``nextKeyAuthorizations``)."""
    if not isinstance(data, dict) or ("controlAuthorization" not in data and "nextKeyAuthorizations" not in data):
        return data
    return {key: member for key, member in data.items() if key not in ("controlAuthorization", "nextKeyAuthorizations")}


def control_effect_hash(event: dict[str, Any], algorithm: str) -> str:
    return hash_canonical(signed_control_effect(event["data"]), algorithm)


def control_authorization_challenge(domain: dict[str, Any], event_id: str, event_type: str, timestamp: int,
                                    previous_head: dict[str, Any] | None, effect_hash: str) -> dict[str, Any]:
    """The structure an owner key signs for a control event (docs/HISTORY-FORMAT.md §7); ``previous_head`` is the head *before* the event."""
    return {
        "version": CONTROL_AUTHORIZATION_VERSION, "domain": domain, "eventId": event_id, "eventType": event_type, "timestamp": timestamp,
        "previousHead": None if previous_head is None else {"hash": previous_head["hash"], "position": previous_head["position"]},
        "effectHash": effect_hash,
    }


def control_authorization_hash(domain: dict[str, Any], event_id: str, event_type: str, timestamp: int, previous_head: dict[str, Any] | None,
                               effect_hash: str, algorithm: str) -> str:
    return hash_canonical(control_authorization_challenge(domain, event_id, event_type, timestamp, previous_head, effect_hash), algorithm)


def _genesis_probe(v: V, data: Any) -> dict[str, Any] | None:
    """Genesis probe (spec 01 §C.8): closed record with well-formed declared versions, before the exact version comparison."""
    path = "$.data"
    if not _preflight(v, data, path, NAMED_LIMITS["DEPLOYMENT_INITIALIZED"]):
        return None
    trellis = v.format == TRELLIS_FORMAT
    r = _rec(v, data, path, (*_GENESIS_REQUIRED, "ownerKeys") if trellis else _GENESIS_REQUIRED, ("nextKeyDigests", "capacity", "migratedFrom") if trellis else ())
    if (r is None or not _domain(v, r["domain"], f"{path}.domain") or not _content_hash(v, r["adapterPolicyHash"], f"{path}.adapterPolicyHash")
            or not _identifier(v, r["canonicalLineageId"], f"{path}.canonicalLineageId") or not _declared_version_set(v, r["versions"], f"{path}.versions")
            or not _identifier(v, r["policyVersion"], f"{path}.policyVersion")
            or (r["rootRecognitionPolicy"] != ROOT_RECOGNITION_POLICY and not _fail(v, f"{path}.rootRecognitionPolicy", f"must equal {ROOT_RECOGNITION_POLICY}"))
            or not _identifier(v, r["globalPolicySourceId"], f"{path}.globalPolicySourceId")
            or (r["timeSource"] != "EVENT_TIMESTAMP" and not _fail(v, f"{path}.timeSource", "must equal EVENT_TIMESTAMP"))
            or (r["finality"] != "LOCAL_ONLY" and not _fail(v, f"{path}.finality", "must equal LOCAL_ONLY"))):
        return None
    return r["versions"]


def _genesis_version_check(v: V, data: Any) -> EventValidation | None:
    versions = _genesis_probe(v, data)
    if versions is None:
        return _schema_failure(v, "$.data: invalid genesis version probe")
    expected = TRELLIS_VERSIONS if v.format == TRELLIS_FORMAT else LEGACY_VERSIONS
    if versions["eventSchemaVersion"] != expected["eventSchemaVersion"]:
        return _invalid("UNSUPPORTED_EVENT_SCHEMA", f"$.data.versions.eventSchemaVersion: {versions['eventSchemaVersion']}")
    for key, value in expected.items():
        if versions[key] != value:
            return _invalid("UNSUPPORTED_VERSION", f"$.data.versions.{key}: {versions[key]}")
    if v.format == TRELLIS_FORMAT and versions.get("signatureScheme") not in SIGNATURE_SCHEMES:
        return _invalid("UNSUPPORTED_VERSION", f"$.data.versions.signatureScheme: {versions.get('signatureScheme')}")
    return None


def validate_event(raw: Any, history_format: str, position: int, shadow: bool = False) -> EventValidation:
    """Envelope + closed per-type schema for one raw event at ``position`` (spec 01 §D.6 steps 1–3).

    The returned event carries captured data (canonical key order, markers decoded)."""
    if not _is_record(raw):
        return _invalid("INVALID_INPUT", "$: event must be a plain protocol record")
    if len(raw) != 4 or any(key not in ("id", "type", "timestamp", "data") for key in raw):
        return _invalid("INVALID_INPUT", "$: event has an invalid envelope")
    v = V(history_format, shadow=(shadow and history_format == TRELLIS_FORMAT))
    event_id, event_type, timestamp = raw["id"], raw["type"], raw["timestamp"]
    if isinstance(timestamp, float) and timestamp.is_integer() and abs(timestamp) <= 2**53 - 1 and not (timestamp == 0 and math.copysign(1.0, timestamp) < 0):
        timestamp = int(timestamp)  # a JSON `5.0` is the JavaScript number 5
    if not _identifier(v, event_id, "$.id") or not _protocol_string(v, event_type, "$.type") or not _u53(v, timestamp, "$.timestamp"):
        return _invalid("INVALID_INPUT", v.problem or "$: invalid envelope")
    if not _is_record(raw["data"]):
        return _invalid("INVALID_INPUT", "$.data: must be a plain protocol record")
    try:
        # Replay bodies nest `data` four containers deep (spec 01 §A.8), leaving 28 levels under it.
        data = capture_value(raw["data"], max_total_bytes=MAX_EVENT_DATA_BYTES, max_depth=29)
    except CanonicalError as error:
        return _capture_failure(error)
    if position == 0:
        if event_type != "DEPLOYMENT_INITIALIZED":
            return _invalid("GENESIS_REQUIRED", "$.type: history must begin with DEPLOYMENT_INITIALIZED")
        # An event format this package does not implement (format 2) is refused as such, before the
        # schema of the fallback format would misreport it as EVENT_DATA_INVALID (G0 Q4).
        versions = data.get("versions") if isinstance(data, dict) else None
        schema_version = versions.get("eventSchemaVersion") if isinstance(versions, dict) else None
        if isinstance(schema_version, str) and format_of_schema_version(schema_version) is None:
            return _invalid("UNSUPPORTED_VERSION", f"$.data.versions.eventSchemaVersion: {schema_version} is not an event format this package implements")
        failure = _genesis_version_check(v, data)
        if failure is not None:
            return failure
    if not is_event_type(event_type) or (history_format == LEGACY_FORMAT and event_type in TRELLIS_ONLY_EVENT_TYPES):
        return _invalid("UNSUPPORTED_EVENT_TYPE", f"$.type: unsupported EventType {event_type!r}")
    # Format-1 control events carry `controlAuthorization` beside their effect; the schema sees only the effect.
    effect = control_effect(data) if history_format == TRELLIS_FORMAT and event_type in CONTROL_EVENT_TYPES else data
    if not _preflight(v, effect, P, NAMED_LIMITS[event_type]) or not _validate_event_data(v, event_type, effect):
        return _schema_failure(v, "$.data: invalid closed event payload")
    return EventValidation(True, {"id": event_id, "type": event_type, "timestamp": timestamp, "data": data})


def session_credential(data: dict[str, Any], history_format: str) -> tuple[str, str]:
    """The (scheme, key) a RUNTIME_SESSION_ADMITTED event registers, normalised for comparison with recovered signers."""
    if history_format == LEGACY_FORMAT or data.get("credentialScheme") != "ed25519":
        return "eip191-personal-sign-keccak256", data["credentialAddress"].lower()
    return "ed25519", data["credentialPublicKey"].lower()
