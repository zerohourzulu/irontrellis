"""Pre-rotation: the genesis commitment (``nextKeyDigests``), epochs whose commitment is fixed by the event that opens
them, the commitment-only rotation, and the rotation rules when the epoch being left has a commitment, on events signed
here in Python, independently of the TypeScript engine; plus the conformance history the TypeScript engine wrote."""
from __future__ import annotations

import pytest

from irontrellis import keeps_every_owner_key, owner_key_digest, replay, verify_rotation_event
from irontrellis.crypto import ed25519
from irontrellis.events import (
    CONTROL_EVENT_TYPES, EVENT_TYPES, TRELLIS_ONLY_EVENT_TYPES, control_authorization_hash, control_effect, control_effect_hash, signed_control_effect, validate_event,
)
from irontrellis.hashing import hash_canonical

SEEDS = {"owner:1": 0x1001, "owner:2": 0x7002, "owner:3": 0x7003, "owner:4": 0x7004, "owner:x": 0x7009}


def seed(key_id: str) -> bytes:
    return bytes.fromhex(f"{SEEDS[key_id]:064x}")


def key(key_id: str, seed_of: str | None = None) -> dict:
    return {"keyId": key_id, "scheme": "ed25519", "credential": "0x" + ed25519.public_key_from_seed(seed(seed_of or key_id)).hex()}


def digest(key_id: str) -> str:
    return owner_key_digest(key(key_id))


def signed(events: list, event: dict, by: str, reveal: tuple = ()) -> list:
    """``event`` signed by ``by`` as the next control event of ``events``, with proofs by the ``(keyId, seed id)`` pairs in ``reveal``."""
    result = replay(events)
    assert result.accepted, (result.code, result.reason)
    state = result.state
    event = {**event, "timestamp": max(event["timestamp"], state.head["canonicalTime"])}
    effect = control_effect(event["data"])
    challenge = control_authorization_hash(state.genesis["domain"], event["id"], event["type"], event["timestamp"],
                                           {"hash": state.head["hash"], "position": state.head["position"]}, control_effect_hash({**event, "data": effect}, "sha256"), "sha256")
    sign = lambda who: "0x" + ed25519.sign(seed(who), bytes.fromhex(challenge[2:])).hex()  # noqa: E731
    data = {**effect, "controlAuthorization": {"keyId": by, "signature": sign(by)}}
    if reveal:
        data["nextKeyAuthorizations"] = [{"keyId": key_id, "scheme": "ed25519", "signature": sign(who)} for key_id, who in reveal]
    return [*events, {**event, "data": data}]


def commit_only(event_id: str, digests: list) -> dict:
    """A commitment-only rotation: owner:1 kept, the commitment added."""
    return {"id": event_id, "type": "OWNER_KEYS_ROTATED", "timestamp": 200, "data": {"ownerKeys": [key("owner:1")], "reason": "next-key commitment", "nextKeyDigests": digests}}


def rotation(event_id: str, keys: list, **extra) -> dict:
    return {"id": event_id, "type": "OWNER_KEYS_ROTATED", "timestamp": 210, "data": {"ownerKeys": keys, **extra}}


def agent(name: str) -> dict:
    return {"id": f"agent:{name}", "type": "AGENT_CREATED", "timestamp": 300, "data": {"agentId": name, "principalId": "operations", "controllerId": "operator", "initialControlEpoch": 1}}


def rejected(events: list, code: str, prefix: str | None = None) -> None:
    result = replay(events)
    assert not result.accepted
    assert result.code == code, result.reason
    if prefix is not None:
        assert result.reason.startswith(prefix), result.reason


@pytest.fixture()
def base(v1_histories):
    """The conformance rotation history up to its rotation: genesis owner key owner:1 (seed 0x1001), no commitment."""
    events = v1_histories["rotation-v1"]
    index = next(i for i, e in enumerate(events) if e["type"] == "OWNER_KEYS_ROTATED")
    return events[:index]


def with_genesis_commitment(events: list, digests: list) -> list:
    """``events`` (genesis + owner:1 control events) with the genesis committed to ``digests``, every later event re-signed."""
    genesis = {**events[0], "data": {**events[0]["data"], "nextKeyDigests": digests}}
    out = [genesis]
    for event in events[1:]:
        out = signed(out, event, "owner:1")
    return out


@pytest.fixture()
def committed(base):
    """The same prefix with a genesis committed to owner:2 (pre-rotation from the first event)."""
    return with_genesis_commitment(base, [digest("owner:2")])


def test_digest_and_vocabulary():
    assert digest("owner:2") == hash_canonical({"version": "irontrellis-owner-key-digest/1", "scheme": "ed25519", "credential": key("owner:2")["credential"]}, "sha256")
    assert owner_key_digest({**key("owner:2"), "keyId": "other", "credential": key("owner:2")["credential"].upper().replace("0X", "0x")}) == digest("owner:2")
    assert "OWNER_NEXT_KEYS_COMMITTED" not in EVENT_TYPES and "OWNER_KEYS_ROTATED" in CONTROL_EVENT_TYPES and "OWNER_KEYS_ROTATED" in TRELLIS_ONLY_EVENT_TYPES
    commit_event = {"id": "c", "type": "OWNER_NEXT_KEYS_COMMITTED", "timestamp": 200, "data": {"nextKeyDigests": [digest("owner:2")]}}
    assert validate_event(commit_event, "irontrellis-event/1", 3).code == "UNSUPPORTED_EVENT_TYPE"


def test_schema(base):
    def check(event):
        return validate_event(event, "irontrellis-event/1", 3)

    def genesis(digests):
        return validate_event({**base[0], "data": {**base[0]["data"], "nextKeyDigests": digests}}, "irontrellis-event/1", 0)
    sig = "0x" + "11" * 64
    assert genesis([digest("owner:2")]).ok
    assert genesis([]).code == "EVENT_DATA_INVALID"
    assert genesis([digest("owner:2"), digest("owner:2")]).code == "EVENT_DATA_INVALID"
    assert genesis([digest("owner:2").upper().replace("0X", "0x")]).code == "EVENT_DATA_INVALID"
    assert genesis([f"0x{i:064x}" for i in range(65)]).code == "INVALID_INPUT"
    clash = genesis([digest("owner:2"), digest("owner:1")])
    assert clash.code == "EVENT_DATA_INVALID" and "names owner key owner:1" in clash.reason
    assert check(commit_only("c", [digest("owner:2")])).ok
    assert check(rotation("r", [key("owner:2")], nextKeyDigests=[])).code == "EVENT_DATA_INVALID"
    proof = {"keyId": "owner:2", "scheme": "ed25519", "signature": sig}
    assert check(rotation("r", [key("owner:2")], nextKeyDigests=[digest("owner:3")], nextKeyAuthorizations=[proof])).ok
    assert check(rotation("r", [key("owner:2")], nextKeyAuthorizations=[])).code == "EVENT_DATA_INVALID"
    assert check(rotation("r", [key("owner:2")], nextKeyAuthorizations=[{**proof, "signature": "0x" + "11" * 65}])).code == "EVENT_DATA_INVALID"
    assert check(rotation("r", [key("owner:2")], nextKeyAuthorizations=[proof, proof])).code == "EVENT_DATA_INVALID"
    assert check({**agent("a"), "data": {**agent("a")["data"], "nextKeyAuthorizations": [proof]}}).code == "EVENT_DATA_INVALID"


def test_effect_hash_leaves_out_both_signatures():
    base = rotation("r", [key("owner:2")], nextKeyDigests=[digest("owner:3")])
    with_sigs = {**base, "data": {**base["data"], "controlAuthorization": {"keyId": "owner:1", "signature": "0x00"}, "nextKeyAuthorizations": []}}
    assert control_effect_hash(with_sigs, "sha256") == control_effect_hash(base, "sha256")
    assert sorted(signed_control_effect(with_sigs["data"])) == ["nextKeyDigests", "ownerKeys"]


def test_genesis_commitment_and_commitment_only_rotation(base, committed):
    result = replay(committed)
    assert result.accepted, result.reason
    assert result.state.owner_key_epochs == [{"fromPosition": 0, "keys": [key("owner:1")], "nextKeyDigests": [digest("owner:2")]}]
    assert replay(base).state.owner_key_epochs == [{"fromPosition": 0, "keys": [key("owner:1")]}]
    # A commitment-only rotation gives an uncommitted epoch its commitment (the same key keeps signing) ...
    later = signed(base, commit_only("commit:py", [digest("owner:2")]), "owner:1")
    state = replay(later).state
    assert state.owner_key_epochs == [{"fromPosition": 0, "keys": [key("owner:1")]},
                                      {"fromPosition": len(base) + 1, "keys": [key("owner:1")], "nextKeyDigests": [digest("owner:2")]}]
    assert replay(signed(later, agent("after"), "owner:1")).accepted
    # ... without nextKeyDigests it changes nothing and is refused ...
    rejected(signed(base, rotation("noop", [key("owner:1")]), "owner:1"), "TRANSITION_INVALID", "owner key rotation: a rotation that keeps every owner key changes nothing")
    # ... and out of a committed epoch it reveals no committed key: a leaked current key cannot replace the commitment.
    rejected(signed(committed, commit_only("commit:2", [digest("owner:x")]), "owner:1"), "TRANSITION_INVALID", "owner key rotation: the owner keys in force committed to next keys")
    rejected(signed(base, commit_only("commit:own", [digest("owner:1")]), "owner:1"), "TRANSITION_INVALID", "owner key rotation: next-key digest")
    assert keeps_every_owner_key([key("owner:1"), key("owner:2")], [key("owner:2"), key("owner:1")])
    assert not keeps_every_owner_key([key("owner:1"), key("owner:2")], [key("owner:2")])


def test_pre_rotated_rotation_accepted_and_chains(committed):
    events = signed(committed, rotation("rotation:1", [key("owner:2")], nextKeyDigests=[digest("owner:3")]), "owner:1", (("owner:2", "owner:2"),))
    events = signed(events, agent("after"), "owner:2")
    events = signed(events, rotation("rotation:2", [key("owner:3")], nextKeyDigests=[digest("owner:4")]), "owner:2", (("owner:3", "owner:3"),))
    result = replay(events)
    assert result.accepted, result.reason
    epochs = result.state.owner_key_epochs
    assert [e.get("nextKeyDigests") for e in epochs] == [[digest("owner:2")], [digest("owner:3")], [digest("owner:4")]]
    assert [e["keys"][0]["keyId"] for e in epochs] == ["owner:1", "owner:2", "owner:3"]
    # A fresh key id for the revealed key is fine: the commitment covers the key, not its id.
    renamed = signed(committed, rotation("rotation:1", [key("hsm:7", "owner:2")], nextKeyDigests=[digest("owner:3")]), "owner:1", (("hsm:7", "owner:2"),))
    assert replay(renamed).accepted


def test_leaked_current_key_cannot_rotate_a_committed_epoch(committed):
    rejected(signed(committed, rotation("r", [key("owner:x")], nextKeyDigests=[digest("owner:4")]), "owner:1", (("owner:x", "owner:x"),)),
             "TRANSITION_INVALID", "owner key rotation: new owner key owner:x is not one of the next keys")
    rejected(signed(committed, rotation("r", [key("owner:2")], nextKeyDigests=[digest("owner:4")]), "owner:1"),
             "TRANSITION_INVALID", "owner key rotation: no revealed next key signed")
    rejected(signed(committed, rotation("r", [key("owner:2")], nextKeyDigests=[digest("owner:4")]), "owner:1", (("owner:2", "owner:x"),)),
             "TRANSITION_INVALID", "owner key rotation: next-key authorization by owner:2 does not verify")
    rejected(signed(committed, rotation("r", [key("owner:1")], nextKeyDigests=[digest("owner:4")]), "owner:1"),
             "TRANSITION_INVALID", "owner key rotation: the owner keys in force committed to next keys; the rotation must reveal")
    rejected(signed(committed, rotation("r", [key("owner:2")]), "owner:1", (("owner:2", "owner:2"),)),
             "TRANSITION_INVALID", "owner key rotation: a pre-rotated rotation must commit")
    rejected(signed(committed, rotation("r", [key("owner:1"), key("owner:2")], nextKeyDigests=[digest("owner:3")]), "owner:1", (("owner:2", "owner:2"), ("owner:1", "owner:1"))),
             "TRANSITION_INVALID", "owner key rotation: next-key authorization by owner:1 names no owner key")


def test_epoch_without_commitment_rotates_as_before(base):
    assert replay(signed(base, rotation("r", [key("owner:2")]), "owner:1")).accepted
    assert replay(signed(base, rotation("r", [key("owner:2")], nextKeyDigests=[digest("owner:3")]), "owner:1")).accepted
    rejected(signed(base, rotation("r", [key("owner:2")]), "owner:1", (("owner:2", "owner:x"),)), "TRANSITION_INVALID", "owner key rotation: next-key authorization")


def test_standalone_checks(committed):
    state = replay(committed).state
    head = {"hash": state.head["hash"], "position": state.head["position"]}
    events = signed(committed, rotation("rotation:1", [key("owner:2")], nextKeyDigests=[digest("owner:3")]), "owner:1", (("owner:2", "owner:2"),))
    verdict = verify_rotation_event(events[-1], state.genesis["domain"], head, state.owner_key_epochs)
    assert verdict["ok"] and verdict["preRotated"] is True and verdict["nextKeyDigests"] == [digest("owner:3")]
    assert verdict["fromPosition"] == head["position"] + 2
    unaware = verify_rotation_event(events[-1], state.genesis["domain"], head, [{"fromPosition": 0, "keys": [key("owner:1")]}])
    assert unaware["ok"] and unaware["preRotated"] is False
    assert verdict["commitmentOnly"] is False
    base_state = replay(committed[:1]).state
    # A commitment-only rotation, checked standalone against an uncommitted epoch and against a committed one.
    uncommitted = replay([{**committed[0], "data": {k: v for k, v in committed[0]["data"].items() if k != "nextKeyDigests"}}]).state
    event = signed([uncommitted.events[0]], commit_only("commit:alone", [digest("owner:2")]), "owner:1")[-1]
    alone = verify_rotation_event(event, uncommitted.genesis["domain"], {"hash": uncommitted.head["hash"], "position": 0}, uncommitted.owner_key_epochs)
    assert alone["ok"] and alone["commitmentOnly"] is True and alone["preRotated"] is False and alone["fromPosition"] == 2
    assert alone["epochs"][-1] == {"fromPosition": 2, "keys": [key("owner:1")], "nextKeyDigests": [digest("owner:2")]}
    refused = verify_rotation_event(event, uncommitted.genesis["domain"], {"hash": uncommitted.head["hash"], "position": 0}, base_state.owner_key_epochs)
    assert refused["code"] == "TRANSITION_INVALID"


def test_conformance_pre_rotation_history(v1_histories):
    events = v1_histories["pre-rotation-v1"]
    result = replay(events)
    assert result.accepted, (result.code, result.reason)
    epochs = result.state.owner_key_epochs
    assert len(epochs) == 2 and all("nextKeyDigests" in epoch for epoch in epochs)
    assert events[0]["data"]["nextKeyDigests"] == epochs[0]["nextKeyDigests"], "the genesis carries epoch 0's commitment"
    rotation_event = next(e for e in events if e["type"] == "OWNER_KEYS_ROTATED")
    assert owner_key_digest(rotation_event["data"]["ownerKeys"][0]) in epochs[0]["nextKeyDigests"]


def test_standalone_never_drops_the_genesis_commitment(committed):
    """The leaked current key of a genesis-committed epoch re-commits (commitment-only): replay refuses it, and so does
    the standalone check seeded from the genesis; a key set without its commitment is not a valid epoch list."""
    state = replay(committed).state
    head = {"hash": state.head["hash"], "position": state.head["position"]}
    leaked = signed(committed, commit_only("leak", [digest("owner:3")]), "owner:1")
    assert not replay(leaked).accepted
    genesis = committed[0]["data"]
    assert genesis.get("nextKeyDigests"), "the genesis commits"
    seeded = [{"fromPosition": 0, "keys": genesis["ownerKeys"], "nextKeyDigests": genesis["nextKeyDigests"]}]
    verdict = verify_rotation_event(leaked[-1], state.genesis["domain"], head, seeded)
    assert verdict["ok"] is False and verdict["code"] == "TRANSITION_INVALID"
    for bad in ([], None, {"fromPosition": 0, "keys": genesis["ownerKeys"]}, genesis["ownerKeys"],
                [{"fromPosition": 1, "keys": genesis["ownerKeys"]}], [{"fromPosition": 0, "keys": []}],
                [{"fromPosition": 0, "keys": genesis["ownerKeys"]}, {"fromPosition": 0, "keys": genesis["ownerKeys"]}],
                [{"fromPosition": 0, "keys": genesis["ownerKeys"], "nextKeyDigests": []}],
                [{"fromPosition": 0, "keys": genesis["ownerKeys"], "nextKeyDigests": ["owner:2"]}]):
        result = verify_rotation_event(leaked[-1], state.genesis["domain"], head, bad)
        assert result["ok"] is False and result["code"] == "INVALID_INPUT", bad

