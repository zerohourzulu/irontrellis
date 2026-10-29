"""Adapter editions E1–E6 (spec 03 §H, spec 01 §F.2–F.5, §D.11).

The fixed adapter profiles a genesis may select, the adapter identity derived
for an accepted admission, and the acknowledgment / no-effect shapes replay
validates on consumption, outcome and observation events.

Policy and descriptor hashes are keccak constants: they are identifiers chosen
once in Continuity and stay byte-identical in every format. Values derived per
history (idempotency key, submission fingerprint, no-effect reference, evidence
references) use the history's hash algorithm, which the authorization domain
determines: ``continuity`` → keccak-256, ``irontrellis`` → sha256.
"""
from __future__ import annotations

from typing import Any

from .canonical import (
    MAX_PROTOCOL_BIGINT, CanonicalError, canonical_encode, capture_value, is_content_hash, is_identifier, is_u53, utf8_length,
)
from .hashing import hash_canonical

ADAPTER_IDEMPOTENCY_VERSION = "continuity-adapter-idempotency/0.2"
ADAPTER_SUBMISSION_VERSION = "continuity-adapter-submission/0.2"
ADAPTER_NO_EFFECT_VERSION = "continuity-adapter-no-effect/0.2"
ADAPTER_ACKNOWLEDGMENT_VERSION = "continuity-adapter-acknowledgment/0.2"
ADAPTER_POLICY_SCHEMA_VERSION = "continuity-adapter-policy/0.2"
SIMULATED_ADAPTER_ID = "adapter:simulated"
LOCAL_EVIDENCE_PACKET_ADAPTER_ID = "adapter:local-evidence-packet"
LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID = "adapter:local-synthetic-endpoint-state"
LOCAL_SYNTHETIC_ENDPOINT_STATE_ACKNOWLEDGMENT_VERSION = "continuity-local-endpoint-state-ack/1"
LOCAL_DOCUMENT_RELEASE_ADAPTER_ID = "adapter:local-document-release"
LOCAL_DOCUMENT_RELEASE_ACKNOWLEDGMENT_VERSION = "continuity-local-document-release-ack/1"
REMOTE_SERVICE_REPORT_ADAPTER_ID = "adapter:remote-service-report"
REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION = "continuity-remote-service-report-ack/1"
ATTEMPT_OBSERVATION_DUTY_EXTENSION = "continuity-attempt-observation-duty/1"
ATTEMPT_DUTY_REVIEW_EXTENSION = "continuity-attempt-duty-review/1"
MAX_ADAPTER_EVIDENCE_BYTES = 4096


class AdapterError(ValueError):
    pass


# ---------------------------------------------------------------- descriptors, profiles, policies


def _descriptor(profile_id: str, acknowledgment_version: str, rule: str) -> dict[str, Any]:
    return {"profileId": profile_id, "profileVersion": "1", "acknowledgmentSchemaVersion": acknowledgment_version,
            "replayRuleId": f"continuity-adapter-replay/{rule}/1"}


_PACKET = _descriptor(LOCAL_EVIDENCE_PACKET_ADAPTER_ID, ADAPTER_ACKNOWLEDGMENT_VERSION, "local-packet")
_SIMULATED = _descriptor(SIMULATED_ADAPTER_ID, ADAPTER_ACKNOWLEDGMENT_VERSION, "simulated")
_ENDPOINT_STATE = _descriptor(LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID, LOCAL_SYNTHETIC_ENDPOINT_STATE_ACKNOWLEDGMENT_VERSION, "local-endpoint-state")
_DOCUMENT_RELEASE = _descriptor(LOCAL_DOCUMENT_RELEASE_ADAPTER_ID, LOCAL_DOCUMENT_RELEASE_ACKNOWLEDGMENT_VERSION, "local-document-release")
_REMOTE_REPORT = _descriptor(REMOTE_SERVICE_REPORT_ADAPTER_ID, REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION, "remote-service-report")
ADAPTER_DESCRIPTORS = {d["profileId"]: d for d in (_PACKET, _SIMULATED, _ENDPOINT_STATE, _DOCUMENT_RELEASE, _REMOTE_REPORT)}


def _profile_of(descriptor: dict[str, Any]) -> dict[str, Any]:
    return {"profileId": descriptor["profileId"], "profileVersion": "1", "descriptorHash": hash_canonical(descriptor, "keccak256")}


PROFILES = {profile_id: _profile_of(d) for profile_id, d in ADAPTER_DESCRIPTORS.items()}
_E4_DESCRIPTORS = [_DOCUMENT_RELEASE, _PACKET, _ENDPOINT_STATE, _REMOTE_REPORT, _SIMULATED]


def _policy(edition: str, descriptors: list[dict[str, Any]], extra: dict[str, Any] | None = None) -> dict[str, Any]:
    extra = extra or {}
    return {
        "edition": edition,
        "hash": hash_canonical({"schemaVersion": ADAPTER_POLICY_SCHEMA_VERSION, "profiles": descriptors, **extra}, "keccak256"),
        "profiles": [PROFILES[d["profileId"]] for d in descriptors],
        **extra,
    }


POLICIES = [
    _policy("E1", [_PACKET, _SIMULATED]),
    _policy("E2", [_PACKET, _ENDPOINT_STATE, _SIMULATED]),
    _policy("E3", [_DOCUMENT_RELEASE, _PACKET, _ENDPOINT_STATE, _SIMULATED]),
    _policy("E4", _E4_DESCRIPTORS),
    _policy("E5", _E4_DESCRIPTORS, {"semanticExtension": ATTEMPT_OBSERVATION_DUTY_EXTENSION}),
    _policy("E6", _E4_DESCRIPTORS, {"semanticExtensions": [ATTEMPT_OBSERVATION_DUTY_EXTENSION, ATTEMPT_DUTY_REVIEW_EXTENSION]}),
]
ADAPTER_POLICY_HASHES = {p["edition"]: p["hash"] for p in POLICIES}
ADAPTER_POLICY_E5_HASH = ADAPTER_POLICY_HASHES["E5"]
ADAPTER_POLICY_E6_HASH = ADAPTER_POLICY_HASHES["E6"]


def resolve_adapter_policy(policy_hash: Any) -> dict[str, Any] | None:
    for policy in POLICIES:
        if policy["hash"] == policy_hash:
            return policy
    return None


def policy_enables_attempt_duties(policy_hash: Any) -> bool:
    return policy_hash in (ADAPTER_POLICY_E5_HASH, ADAPTER_POLICY_E6_HASH)


def policy_enables_attempt_reviews(policy_hash: Any) -> bool:
    return policy_hash == ADAPTER_POLICY_E6_HASH


def approved_adapter_profile_for_policy(policy_hash: Any, profile_id: Any) -> dict[str, Any]:
    policy = resolve_adapter_policy(policy_hash)
    if policy is not None:
        for profile in policy["profiles"]:
            if profile["profileId"] == profile_id:
                return profile
    raise AdapterError("Profile is not a member of the selected fixed adapter policy.")


def known_adapter_profile(profile_id: Any) -> dict[str, Any]:
    if not isinstance(profile_id, str) or profile_id not in PROFILES:
        raise AdapterError("Unsupported fixed adapter profile.")
    return PROFILES[profile_id]


# ---------------------------------------------------------------- adapter input capture (spec 03 §H.3)


def capture_adapter_value(value: Any) -> Any:
    """Descriptor-only snapshot: plain records and scalars (no arrays), ≤ 256 keys, depth ≤ 16,
    ≤ 4096 units, then a strict canonical capture bounded to 4096 canonical bytes."""
    units = 0

    def fail(message: str) -> None:
        raise AdapterError(message)

    def string(text: str) -> None:
        nonlocal units
        if len(text) > MAX_ADAPTER_EVIDENCE_BYTES:
            fail("Adapter input exceeds its finite bound.")
        length = utf8_length(text, 10**9)
        units += len(text) if length is None else length
        if units > MAX_ADAPTER_EVIDENCE_BYTES:
            fail("Adapter input exceeds its finite bound.")

    def visit(current: Any, depth: int) -> Any:
        nonlocal units
        units += 1
        if units > MAX_ADAPTER_EVIDENCE_BYTES or depth > 16:
            fail("Adapter input exceeds its finite bound.")
        if isinstance(current, str):
            string(current)
            return current
        if current is None or isinstance(current, (bool, int, float)):
            return current
        if not isinstance(current, dict):
            fail("Adapter fields must be data records or scalars.")
        if len(current) > 256:
            fail("Adapter record has too many fields.")
        copy: dict[str, Any] = {}
        for key, member in current.items():
            if not isinstance(key, str):
                fail("Adapter keys must be strings.")
            string(key)
            copy[key] = visit(member, depth + 1)
        return copy

    try:
        return capture_value(visit(value, 0), max_total_bytes=MAX_ADAPTER_EVIDENCE_BYTES)
    except CanonicalError as error:
        raise AdapterError(error.reason) from error


def _record(value: Any) -> bool:
    return isinstance(value, dict)


def _closed(value: Any, keys: tuple[str, ...]) -> bool:
    return isinstance(value, dict) and len(value) == len(keys) and all(k in value for k in keys)


def _same(left: Any, right: Any) -> bool:
    return canonical_encode(left) == canonical_encode(right)


_PROFILE_KEYS = ("profileId", "profileVersion", "descriptorHash")
_HEAD_KEYS = ("hash", "position", "canonicalTime")


def _guarded(check: Any) -> bool:
    try:
        return bool(check())
    except Exception:
        return False


def validate_adapter_profile_for_policy(policy_hash: Any, value: Any) -> bool:
    def check() -> bool:
        v = capture_adapter_value(value)
        return _closed(v, _PROFILE_KEYS) and _same(v, approved_adapter_profile_for_policy(policy_hash, v["profileId"]))
    return _guarded(check)


def validate_known_adapter_profile(value: Any) -> bool:
    """Shape-only recognition, deliberately distinct from genesis membership."""
    def check() -> bool:
        v = capture_adapter_value(value)
        return _closed(v, _PROFILE_KEYS) and _same(v, known_adapter_profile(v["profileId"]))
    return _guarded(check)


# ---------------------------------------------------------------- domains and derived identity values


def _legacy_domain_valid(v: dict[str, Any]) -> bool:
    return (_closed(v, ("protocol", "version", "deploymentId", "chainId", "verifyingContract")) and v["protocol"] == "continuity"
            and v["version"] == "0.2" and is_identifier(v["deploymentId"]) and isinstance(v["chainId"], str) and len(v["chainId"]) <= 78
            and v["chainId"].isdigit() and v["chainId"].isascii() and v["chainId"][0] != "0" and int(v["chainId"]) <= MAX_PROTOCOL_BIGINT
            and isinstance(v["verifyingContract"], str) and len(v["verifyingContract"]) == 42 and v["verifyingContract"].startswith("0x")
            and all(c in "0123456789abcdefABCDEF" for c in v["verifyingContract"][2:]))


def _trellis_domain_valid(v: dict[str, Any]) -> bool:
    return _closed(v, ("protocol", "version", "deploymentId")) and v["protocol"] == "irontrellis" and v["version"] == "1" and is_identifier(v["deploymentId"])


def validate_adapter_domain(value: Any) -> bool:
    return _record(value) and (_trellis_domain_valid(value) if value.get("protocol") == "irontrellis" else _legacy_domain_valid(value))


def hash_algorithm_for_domain(domain: dict[str, Any]) -> str:
    return "sha256" if domain.get("protocol") == "irontrellis" else "keccak256"


def derive_adapter_idempotency_key(domain: dict[str, Any], intent_id: str) -> str:
    algorithm = hash_algorithm_for_domain(domain)
    if "verifyingContract" in domain:
        return hash_canonical([ADAPTER_IDEMPOTENCY_VERSION, domain["protocol"], domain["version"], domain["deploymentId"], domain["chainId"],
                               domain["verifyingContract"].lower(), intent_id], algorithm)
    return hash_canonical([ADAPTER_IDEMPOTENCY_VERSION, domain["protocol"], domain["version"], domain["deploymentId"], intent_id], algorithm)


def derive_adapter_no_effect_reference(idempotency_key: str, submission_fingerprint: str, algorithm: str) -> str:
    return hash_canonical([ADAPTER_NO_EFFECT_VERSION, SIMULATED_ADAPTER_ID, idempotency_key, submission_fingerprint], algorithm)


_IDENTITY_KEYS = ("idempotencyKey", "submissionFingerprint", "durableEventHistoryHash", "adapterNoEffectReference", "adapterProfile", "domain", "intentId", "admissionHead")


def _identity_snapshot(identity: Any) -> dict[str, Any]:
    v = capture_adapter_value(identity)
    if not _record(v):
        raise AdapterError("Invalid or inconsistent adapter identity.")
    keys = list(_IDENTITY_KEYS)
    if "operationVersion" in v:
        if v["operationVersion"] != ADAPTER_SUBMISSION_VERSION:
            raise AdapterError("Invalid or inconsistent adapter identity.")
        keys.append("operationVersion")
    if (not _closed(v, tuple(keys)) or not validate_known_adapter_profile(v["adapterProfile"]) or not validate_adapter_domain(v["domain"])
            or not is_identifier(v["intentId"]) or not _closed(v["admissionHead"], _HEAD_KEYS) or not is_content_hash(v["admissionHead"]["hash"])
            or not is_u53(v["admissionHead"]["position"]) or not is_u53(v["admissionHead"]["canonicalTime"])
            or not is_content_hash(v["submissionFingerprint"]) or v["durableEventHistoryHash"] != v["admissionHead"]["hash"]
            or v["idempotencyKey"] != derive_adapter_idempotency_key(v["domain"], v["intentId"])
            or v["adapterNoEffectReference"] != derive_adapter_no_effect_reference(v["idempotencyKey"], v["submissionFingerprint"], hash_algorithm_for_domain(v["domain"]))):
        raise AdapterError("Invalid or inconsistent adapter identity.")
    return v


def derive_adapter_identity_for_accepted_admission(admission_event: dict[str, Any], admission_head: dict[str, Any], adapter_profile: dict[str, Any],
                                                   adapter_policy_hash: str) -> dict[str, Any]:
    """The identity of an accepted admission; ``admission_head`` is the head *including* the admission event."""
    if (admission_event["type"] != "TRANSACTION_INTENT_ADMITTED" or admission_head["canonicalTime"] != admission_event["timestamp"]
            or not validate_adapter_profile_for_policy(adapter_policy_hash, adapter_profile)):
        raise AdapterError("Adapter identity requires an accepted admission, inclusive head and declared profile.")
    data = admission_event["data"]
    domain = data["authorizationProof"]["domain"]
    intent_id = data["intentId"]
    algorithm = hash_algorithm_for_domain(domain)
    idempotency_key = derive_adapter_idempotency_key(domain, intent_id)
    submission_fingerprint = hash_canonical(
        {"version": ADAPTER_SUBMISSION_VERSION, "intentId": intent_id, "admissionEvent": admission_event, "durableEventHistoryHash": admission_head["hash"]}, algorithm)
    return {
        "idempotencyKey": idempotency_key,
        "submissionFingerprint": submission_fingerprint,
        "durableEventHistoryHash": admission_head["hash"],
        "adapterNoEffectReference": derive_adapter_no_effect_reference(idempotency_key, submission_fingerprint, algorithm),
        "adapterProfile": approved_adapter_profile_for_policy(adapter_policy_hash, adapter_profile["profileId"]),
        "domain": domain,
        "intentId": intent_id,
        "admissionHead": admission_head,
    }


# ---------------------------------------------------------------- acknowledgment and no-effect shapes (spec 03 §H.5)


def _evidence_identity(i: dict[str, Any]) -> dict[str, Any]:
    return {"adapterProfile": i["adapterProfile"], "domain": i["domain"], "intentId": i["intentId"], "admissionHead": i["admissionHead"],
            "idempotencyKey": i["idempotencyKey"], "submissionFingerprint": i["submissionFingerprint"]}


def _ack_of(schema_version: str, i: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    return capture_adapter_value({"schemaVersion": schema_version, "kind": "ACKNOWLEDGMENT", **_evidence_identity(i), "result": result})


def _no_effect_of(i: dict[str, Any]) -> dict[str, Any]:
    if i["adapterProfile"]["profileId"] != SIMULATED_ADAPTER_ID:
        raise AdapterError("Only the simulated profile can establish no effect.")
    return capture_adapter_value({"schemaVersion": ADAPTER_NO_EFFECT_VERSION, "kind": "NO_EFFECT", **_evidence_identity(i),
                                  "result": {"kind": "SIMULATED_NO_EFFECT", "reference": i["adapterNoEffectReference"]}})


# (schemaVersion, result kind, digest key, digest algorithm or "" for a bare reference)
_ACK_SHAPES = {
    SIMULATED_ADAPTER_ID: (ADAPTER_ACKNOWLEDGMENT_VERSION, "SIMULATED_SUBMISSION", "submissionReference", ""),
    LOCAL_EVIDENCE_PACKET_ADAPTER_ID: (ADAPTER_ACKNOWLEDGMENT_VERSION, "LOCAL_PACKET_CREATED", "manifestDigest", "sha256"),
    LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID: (LOCAL_SYNTHETIC_ENDPOINT_STATE_ACKNOWLEDGMENT_VERSION, "LOCAL_ENDPOINT_STATE_CHANGED", "transitionDigest", "keccak256"),
    LOCAL_DOCUMENT_RELEASE_ADAPTER_ID: (LOCAL_DOCUMENT_RELEASE_ACKNOWLEDGMENT_VERSION, "LOCAL_DOCUMENT_RELEASED", "publicationManifestDigest", "sha256"),
    REMOTE_SERVICE_REPORT_ADAPTER_ID: (REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION, "REMOTE_SERVICE_REPORTED", "reportDigest", "sha256"),
}


def _expected_ack(i: dict[str, Any], digest: Any) -> dict[str, Any]:
    shape = _ACK_SHAPES.get(i["adapterProfile"]["profileId"])
    if shape is None or not is_content_hash(digest):
        raise AdapterError("Unsupported adapter profile or malformed digest.")
    schema_version, kind, digest_key, algorithm = shape
    result = {"kind": kind, digest_key: digest} if algorithm == "" else {"kind": kind, digest_key: {"algorithm": algorithm, "value": digest}}
    return _ack_of(schema_version, i, result)


def _carried_digest(v: Any, shape: tuple[str, str, str, str]) -> Any:
    if not _record(v) or not _record(v.get("result")):
        return None
    slot = v["result"].get(shape[2])
    if shape[3] == "":
        return slot
    return slot.get("value") if _record(slot) else None


def evaluate_adapter_acknowledgment(value: Any, identity: Any) -> dict[str, Any] | None:
    """The captured acknowledgment, its transaction reference and the EXTERNAL evidence it
    produces, or None when it is not the one the identity's profile prescribes."""
    try:
        v = capture_adapter_value(value)
        i = _identity_snapshot(identity)
        shape = _ACK_SHAPES.get(i["adapterProfile"]["profileId"])
        if shape is None:
            return None
        digest = i["submissionFingerprint"] if i["adapterProfile"]["profileId"] == SIMULATED_ADAPTER_ID else _carried_digest(v, shape)
        if not is_content_hash(digest) or not _same(v, _expected_ack(i, digest)):
            return None
        return {
            "acknowledgment": v,
            "transactionReference": digest,
            "evidence": {"kind": "EXTERNAL", "evidenceType": v["schemaVersion"], "reference": hash_canonical(v, hash_algorithm_for_domain(i["domain"])),
                         "attesterId": i["adapterProfile"]["profileId"]},
        }
    except Exception:
        return None


def validate_adapter_acknowledgment(value: Any, identity: Any) -> bool:
    return evaluate_adapter_acknowledgment(value, identity) is not None


def evaluate_adapter_no_effect(value: Any, identity: Any) -> dict[str, Any] | None:
    try:
        v = capture_adapter_value(value)
        i = _identity_snapshot(identity)
        if not _same(v, _no_effect_of(i)):
            return None
        return {"noEffect": v, "evidence": {"kind": "EXTERNAL", "evidenceType": ADAPTER_NO_EFFECT_VERSION,
                                            "reference": hash_canonical(v, hash_algorithm_for_domain(i["domain"])), "attesterId": SIMULATED_ADAPTER_ID}}
    except Exception:
        return None


def _shape_identity(v: Any) -> dict[str, Any]:
    """Shape-only identity rebuilt from the evidence's own fields; it authenticates no admission."""
    if (not _record(v) or not _record(v.get("admissionHead")) or not is_content_hash(v.get("idempotencyKey"))
            or not is_content_hash(v.get("submissionFingerprint")) or not _record(v.get("domain"))):
        raise AdapterError("Malformed evidence identity.")
    return _identity_snapshot({
        "adapterProfile": v.get("adapterProfile"), "domain": v["domain"], "intentId": v.get("intentId"), "admissionHead": v["admissionHead"],
        "idempotencyKey": v["idempotencyKey"], "submissionFingerprint": v["submissionFingerprint"], "durableEventHistoryHash": v["admissionHead"].get("hash"),
        "adapterNoEffectReference": derive_adapter_no_effect_reference(v["idempotencyKey"], v["submissionFingerprint"], hash_algorithm_for_domain(v["domain"])),
    })


def validate_adapter_acknowledgment_shape(value: Any) -> bool:
    def check() -> bool:
        v = capture_adapter_value(value)
        return validate_adapter_acknowledgment(v, _shape_identity(v))
    return _guarded(check)


def validate_adapter_no_effect_shape(value: Any) -> bool:
    def check() -> bool:
        v = capture_adapter_value(value)
        return evaluate_adapter_no_effect(v, _shape_identity(v)) is not None
    return _guarded(check)


def same_adapter_evidence(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return (left.get("kind") == right["kind"] and left.get("evidenceType") == right["evidenceType"]
            and left.get("reference") == right["reference"] and left.get("attesterId") == right["attesterId"])
