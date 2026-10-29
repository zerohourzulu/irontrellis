"""Owner key epochs (format 1): which owner keys are in force at a history
position, the key-set rules of ``OWNER_KEYS_ROTATED``, head attestations judged by
position, and a standalone check of a rotation event — the same rules as the
TypeScript engine (``packages/core/src/owner-keys.ts``).

Positions. The genesis key set governs from position 0. A rotation at position ``r``
is itself authorized by the set in force at ``r`` (the set before it) and opens a new
epoch with ``fromPosition: r + 1``. The set "at position p" is the epoch with the
greatest ``fromPosition <= p``: it must sign a control event at position p and a head
attestation of the head at position p. The head that ends with the rotation (position
r) is still attested under the old set; an attestation of an older head keeps
verifying after its key was retired.

Pre-rotation (docs/HISTORY-FORMAT.md §7). An epoch may carry ``nextKeyDigests``: a commitment to the digests
(``owner_key_digest``) of its next keys, fixed by the event that opens it (the genesis for epoch 0, the rotation for any
later one). A rotation out of a committed epoch must reveal committed keys, prove possession of one
(``nextKeyAuthorizations``: signatures over the event's own control-authorization challenge) and commit again. An
uncommitted epoch rotates freely; a rotation out of it that keeps every key must add a commitment (a commitment-only
rotation).
"""
from __future__ import annotations

from typing import Any

from .canonical import is_content_hash
from .crypto.suites import suite_for
from .events import OWNER_KEY_DIGEST_VERSION, control_authorization_hash, control_effect_hash, declared_digest_failure, owner_key_digest, validate_event  # noqa: F401 (re-exported)
from .hashing import TRELLIS_FORMAT, hash_canonical

HEAD_ATTESTATION_VERSION = "irontrellis-head-attestation/1"

Epoch = dict[str, Any]  # {"fromPosition": int, "keys": [owner key, ...], "nextKeyDigests"?: [digest, ...]}


def _epochs_of(source: Any) -> list[Epoch]:
    """A replay state's ``owner_key_epochs``, or the epoch list itself."""
    return source if isinstance(source, list) else source.owner_key_epochs


def _is_position(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2**53 - 1


def owner_keys_at(source: Any, position: Any) -> list[dict[str, Any]]:
    """The owner keys in force at ``position`` (a replay state or its ``owner_key_epochs``);
    a negative or non-integer position gets none; a position past the head gets the current set."""
    if not _is_position(position):
        return []
    for epoch in reversed(_epochs_of(source)):
        if epoch["fromPosition"] <= position:
            return epoch["keys"]
    return []


def _same_key(a: dict[str, Any], b: dict[str, Any]) -> bool:
    return a["scheme"] == b["scheme"] and a["credential"].lower() == b["credential"].lower()


def owner_key_in_force(source: Any, position: Any, key: dict[str, Any]) -> bool:
    return any(candidate["keyId"] == key.get("keyId") and candidate["scheme"] == key.get("scheme") and isinstance(key.get("credential"), str)
               and candidate["credential"].lower() == key["credential"].lower() for candidate in owner_keys_at(source, position))


def owner_key_rotation_failure(epochs: list[Epoch], keys: list[dict[str, Any]]) -> str | None:
    """The key-set rules of OWNER_KEYS_ROTATED against the epochs before it (``TRANSITION_INVALID`` reason):
    an id seen before keeps its key and must be current (a retired id never returns); a new id must not carry a
    credential any earlier epoch declared."""
    current = epochs[-1]["keys"] if epochs else []
    seen: dict[str, dict[str, Any]] = {}
    for epoch in epochs:
        for key in epoch["keys"]:
            seen.setdefault(key["keyId"], key)
    for key in keys:
        earlier = seen.get(key["keyId"])
        if earlier is not None:
            if not _same_key(earlier, key):
                return f"owner key rotation: key id {key['keyId']} was already bound to a different key"
            if not any(candidate["keyId"] == key["keyId"] for candidate in current):
                return f"owner key rotation: retired owner key id {key['keyId']} cannot return"
            continue
        for other in seen.values():
            if _same_key(other, key):
                return f"owner key rotation: the key of new key id {key['keyId']} was already declared as {other['keyId']}"
    return None


def control_signature_failure(event: dict[str, Any], domain: dict[str, Any], previous_head: dict[str, Any] | None,
                              keys: list[dict[str, Any]], algorithm: str) -> str | None:
    """docs/HISTORY-FORMAT.md §7 control authorization of one schema-valid format-1 control event by one of ``keys``."""
    authorization = event["data"].get("controlAuthorization")
    if not isinstance(authorization, dict):
        return "control event is unsigned"
    key_id, signature = authorization.get("keyId"), authorization.get("signature")
    if len(authorization) != 2 or not isinstance(key_id, str):
        return "control authorization is malformed"
    owner_key = next((key for key in keys if key["keyId"] == key_id), None)
    position = 0 if previous_head is None else previous_head["position"] + 1
    if owner_key is None:
        return f"owner key {key_id} is not an owner key in force at position {position}"
    suite = suite_for(owner_key["scheme"])
    if not suite.is_signature(signature):
        return "control signature is malformed"
    challenge_hash = control_authorization_hash(
        domain, event["id"], event["type"], event["timestamp"],
        None if previous_head is None else {"hash": previous_head["hash"], "position": previous_head["position"]},
        control_effect_hash(event, algorithm), algorithm)
    return None if suite.verify(challenge_hash, signature, suite.normalize_credential(owner_key["credential"])) else "control signature does not verify"


def head_attestation_hash(domain: dict[str, Any], head: dict[str, Any], algorithm: str) -> str:
    return hash_canonical({"version": HEAD_ATTESTATION_VERSION, "domain": domain,
                           "head": {"hash": head["hash"], "position": head["position"], "canonicalTime": head["canonicalTime"]}}, algorithm)


def _safe_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and -(2**53 - 1) <= value <= 2**53 - 1


def verify_head_attestation(attestation: Any, domain: dict[str, Any], keys: list[dict[str, Any]], algorithm: str) -> bool:
    """True iff ``attestation`` is a well-formed head attestation signed by one of ``keys`` (id and scheme match). Never raises."""
    if not isinstance(attestation, dict):
        return False
    head, key_id = attestation.get("head"), attestation.get("keyId")
    if attestation.get("version") != HEAD_ATTESTATION_VERSION or not isinstance(head, dict) or not isinstance(key_id, str):
        return False
    key = next((candidate for candidate in keys if candidate["keyId"] == key_id and candidate["scheme"] == attestation.get("scheme")), None)
    if key is None:
        return False
    if not is_content_hash(head.get("hash")) or not _safe_int(head.get("position")) or not _safe_int(head.get("canonicalTime")):
        return False
    try:
        suite = suite_for(key["scheme"])
        signature = attestation.get("signature")
        if not suite.is_signature(signature):
            return False
        return suite.verify(head_attestation_hash(domain, head, algorithm), signature, suite.normalize_credential(key["credential"]))
    except Exception:
        return False


def verify_head_attestation_at(attestation: Any, state: Any) -> bool:
    """A head attestation signed by an owner key in force at the position of the head it names (``owner_keys_at``)."""
    if not isinstance(attestation, dict) or not isinstance(attestation.get("head"), dict):
        return False
    position = attestation["head"].get("position")
    if not _is_position(position):
        return False
    return verify_head_attestation(attestation, state.genesis["domain"], owner_keys_at(state, position), state.hash_algorithm)


def keeps_every_owner_key(current: list[dict[str, Any]], keys: list[dict[str, Any]]) -> bool:
    """True iff ``keys`` is exactly the current set: every key carried over, none added (a rotation that changes no key)."""
    return len(keys) == len(current) and all(any(candidate["keyId"] == key["keyId"] and _same_key(candidate, key) for candidate in current) for key in keys)


def owner_key_event_transition(epochs: list[Epoch], event: dict[str, Any], domain: dict[str, Any], previous_head: dict[str, Any],
                               algorithm: str) -> dict[str, Any]:
    """The owner-key rules of a schema-valid, owner-signed OWNER_KEYS_ROTATED at ``previous_head.position + 1``
    (TRANSITION_INVALID reasons, the TypeScript ``ownerKeyEventTransition``): the key-set rules, the proofs by revealed keys,
    pre-rotation when the epoch being left has a commitment, and no commitment-less rotation that keeps every key. Returns
    ``{"ok": True, "epochs", "fromPosition", "keys", "preRotated", "commitmentOnly", "nextKeyDigests"?}`` or
    ``{"ok": False, "reason"}``."""
    current = epochs[-1] if epochs else None
    position = previous_head["position"] + 1
    if current is None:
        return {"ok": False, "reason": "no owner keys are in force"}
    declared = [key for epoch in epochs for key in epoch["keys"]]
    if event["type"] != "OWNER_KEYS_ROTATED":
        return {"ok": False, "reason": f"{event['type']} is not an owner key event"}
    keys = [{"keyId": key["keyId"], "scheme": key["scheme"], "credential": key["credential"]} for key in event["data"]["ownerKeys"]]
    rule = owner_key_rotation_failure(epochs, keys)
    if rule is not None:
        return {"ok": False, "reason": rule}
    revealed = [key for key in keys if not any(candidate["keyId"] == key["keyId"] for candidate in current["keys"])]
    authorizations = event["data"].get("nextKeyAuthorizations", [])
    if authorizations:
        challenge = control_authorization_hash(domain, event["id"], event["type"], event["timestamp"],
                                               {"hash": previous_head["hash"], "position": previous_head["position"]}, control_effect_hash(event, algorithm), algorithm)
        for proof in authorizations:
            key = next((candidate for candidate in revealed if candidate["keyId"] == proof["keyId"]), None)
            if key is None:
                return {"ok": False, "reason": f"owner key rotation: next-key authorization by {proof['keyId']} names no owner key this rotation reveals"}
            if proof["scheme"] != key["scheme"]:
                return {"ok": False, "reason": f"owner key rotation: next-key authorization by {proof['keyId']} uses scheme {proof['scheme']}, not the key's {key['scheme']}"}
            suite = suite_for(key["scheme"])
            if not suite.is_signature(proof["signature"]) or not suite.verify(challenge, proof["signature"], suite.normalize_credential(key["credential"])):
                return {"ok": False, "reason": f"owner key rotation: next-key authorization by {proof['keyId']} does not verify"}
    commitment = current.get("nextKeyDigests")
    if commitment is not None:
        for key in revealed:
            if owner_key_digest(key) not in commitment:
                return {"ok": False, "reason": f"owner key rotation: new owner key {key['keyId']} is not one of the next keys the owner keys in force committed to (pre-rotation)"}
        if not revealed:
            return {"ok": False, "reason": "owner key rotation: the owner keys in force committed to next keys; the rotation must reveal at least one of them"}
        if not authorizations:
            return {"ok": False, "reason": "owner key rotation: no revealed next key signed nextKeyAuthorizations; a rotation out of a committed epoch must prove possession of a committed key"}
        if "nextKeyDigests" not in event["data"]:
            return {"ok": False, "reason": "owner key rotation: a pre-rotated rotation must commit to the next keys of the new owner key set (nextKeyDigests)"}
    commitment_only = keeps_every_owner_key(current["keys"], keys)
    if commitment_only and "nextKeyDigests" not in event["data"]:
        return {"ok": False, "reason": "owner key rotation: a rotation that keeps every owner key changes nothing unless it adds a next-key commitment (nextKeyDigests)"}
    following = list(event["data"]["nextKeyDigests"]) if "nextKeyDigests" in event["data"] else None
    if following is not None:
        clash = declared_digest_failure("owner key rotation", [*declared, *keys], following)
        if clash is not None:
            return {"ok": False, "reason": clash}
    epoch: Epoch = {"fromPosition": position + 1, "keys": keys, **({} if following is None else {"nextKeyDigests": following})}
    return {"ok": True, "epochs": [*epochs, epoch], "fromPosition": position + 1, "keys": keys, "preRotated": commitment is not None,
            "commitmentOnly": commitment_only, **({} if following is None else {"nextKeyDigests": following})}


def _epochs_shape_failure(epochs: Any) -> str | None:
    """Why ``epochs`` is not a usable epoch list (non-empty, genesis first, increasing positions, key sets,
    commitments), or None."""
    if not isinstance(epochs, list) or not epochs:
        return "epochs must be a non-empty list"
    previous = -1
    for index, epoch in enumerate(epochs):
        if not isinstance(epoch, dict):
            return f"epoch {index} is not a record"
        start = epoch.get("fromPosition")
        if not _is_position(start):
            return f"epoch {index} has no fromPosition"
        if index == 0 and start != 0:
            return "the first epoch must start at the genesis (fromPosition 0)"
        if index > 0 and start <= previous:
            return f"epoch {index} does not start after epoch {index - 1}"
        previous = start
        keys = epoch.get("keys")
        if not isinstance(keys, list) or not keys:
            return f"epoch {index} has no owner keys"
        if "nextKeyDigests" in epoch:
            digests = epoch["nextKeyDigests"]
            if not isinstance(digests, list) or not digests or not all(is_content_hash(d) for d in digests):
                return f"epoch {index} has a malformed nextKeyDigests"
    return None


def verify_rotation_event(event: Any, domain: dict[str, Any], previous_head: dict[str, Any], epochs: list[Epoch], algorithm: str = "sha256") -> dict[str, Any]:
    """Checks an OWNER_KEYS_ROTATED event without the history (as a remote witness must): schema at
    ``previous_head.position + 1``, the owner signature over the challenge with ``previous_head`` by a key in force
    there, the key-set rules and the pre-rotation rules against ``epochs``. Returns ``{"ok": True, "position",
    "fromPosition", "keys", "epochs", "preRotated", "commitmentOnly", "nextKeyDigests"?, "reason"?}`` or
    ``{"ok": False, "code", "reason"}``.

    ``epochs`` is required and must start at the genesis with its commitment (``{"fromPosition": 0, "keys":
    genesis ownerKeys, "nextKeyDigests": genesis nextKeyDigests}``), so that epoch 0's commitment is enforced. There
    is no bare key-set form; a malformed epoch list is ``INVALID_INPUT``."""
    expected = "OWNER_KEYS_ROTATED"
    what = "a rotation"
    if not isinstance(previous_head, dict) or not _is_position(previous_head.get("position")):
        return {"ok": False, "code": "INVALID_INPUT", "reason": f"{what} needs the head before it"}
    position = previous_head["position"] + 1
    validation = validate_event(event, TRELLIS_FORMAT, position)
    if not validation.ok or validation.event is None:
        return {"ok": False, "code": validation.code, "reason": validation.reason}
    valid = validation.event
    if valid["type"] != expected:
        return {"ok": False, "code": "INVALID_INPUT", "reason": f"expected {expected}, got {valid['type']}"}
    shape = _epochs_shape_failure(epochs)
    if shape is not None:
        return {"ok": False, "code": "INVALID_INPUT", "reason": f"{what} needs the owner key epochs in force before it: {shape}"}
    head = {"hash": previous_head.get("hash"), "position": previous_head["position"]}
    failure = control_signature_failure(valid, domain, head, owner_keys_at(epochs, position), algorithm)
    if failure is not None:
        return {"ok": False, "code": "CONTROL_AUTHORIZATION_INVALID", "reason": failure}
    outcome = owner_key_event_transition(epochs, valid, domain, head, algorithm)
    if not outcome["ok"]:
        return {"ok": False, "code": "TRANSITION_INVALID", "reason": outcome["reason"]}
    result = {"ok": True, "position": position, "fromPosition": outcome["fromPosition"], "keys": outcome["keys"], "epochs": outcome["epochs"],
              "preRotated": outcome["preRotated"], "commitmentOnly": outcome["commitmentOnly"]}
    if "nextKeyDigests" in outcome:
        result["nextKeyDigests"] = outcome["nextKeyDigests"]
    if isinstance(valid["data"].get("reason"), str):
        result["reason"] = valid["data"]["reason"]
    return result

