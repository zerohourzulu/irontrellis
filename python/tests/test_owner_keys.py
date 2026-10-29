"""Owner key rotation: OWNER_KEYS_ROTATED replay rules, owner key epochs, head attestations judged by
position and the standalone rotation check — on events signed here in Python, independently of the TypeScript engine."""
from __future__ import annotations

import pytest

from irontrellis import from_plain, replay
from irontrellis.crypto import ed25519
from irontrellis.events import CONTROL_EVENT_TYPES, EVENT_TYPES, TRELLIS_ONLY_EVENT_TYPES, control_authorization_hash, control_effect, validate_event
from irontrellis.hashing import hash_canonical
from irontrellis.owner_keys import (
    head_attestation_hash, owner_key_rotation_failure, owner_keys_at, verify_head_attestation, verify_head_attestation_at, verify_rotation_event,
)
from conftest import LEGACY_FIXTURES, load_json

SEEDS = {"owner:1": 0x1001, "owner:2": 0x1002, "owner:3": 0x5003, "owner:x": 0x5009}


def seed(key_id: str) -> bytes:
    return bytes.fromhex(f"{SEEDS[key_id]:064x}")


def key(key_id: str, seed_of: str | None = None) -> dict:
    return {"keyId": key_id, "scheme": "ed25519", "credential": "0x" + ed25519.public_key_from_seed(seed(seed_of or key_id)).hex()}


def signed(events: list, event: dict, by: str) -> list:
    """``event`` signed by ``by`` as the next control event of ``events`` (which must replay)."""
    result = replay(events)
    assert result.accepted, (result.code, result.reason)
    state = result.state
    effect = control_effect(event["data"])
    challenge = control_authorization_hash(state.genesis["domain"], event["id"], event["type"], event["timestamp"],
                                           {"hash": state.head["hash"], "position": state.head["position"]}, hash_canonical(effect, "sha256"), "sha256")
    signature = "0x" + ed25519.sign(seed(by), bytes.fromhex(challenge[2:])).hex()
    return [*events, {**event, "data": {**effect, "controlAuthorization": {"keyId": by, "signature": signature}}}]


def rotation(event_id: str, keys: list, timestamp: int = 200, **extra) -> dict:
    return {"id": event_id, "type": "OWNER_KEYS_ROTATED", "timestamp": timestamp, "data": {"ownerKeys": keys, **extra}}


def agent(name: str, timestamp: int = 300) -> dict:
    return {"id": f"agent:{name}", "type": "AGENT_CREATED", "timestamp": timestamp, "data": {"agentId": name, "principalId": "operations", "controllerId": "operator", "initialControlEpoch": 1}}


@pytest.fixture()
def base(v1_histories):
    """The conformance rotation history up to (not including) its rotation: genesis owner key owner:1 (seed 0x1001)."""
    events = v1_histories["rotation-v1"]
    index = next(i for i, e in enumerate(events) if e["type"] == "OWNER_KEYS_ROTATED")
    return events[:index]


def test_vocabulary():
    assert "OWNER_KEYS_ROTATED" in EVENT_TYPES and "OWNER_KEYS_ROTATED" in CONTROL_EVENT_TYPES and "OWNER_KEYS_ROTATED" in TRELLIS_ONLY_EVENT_TYPES


def test_schema():
    def check(data):
        return validate_event({"id": "r", "type": "OWNER_KEYS_ROTATED", "timestamp": 1, "data": data}, "irontrellis-event/1", 5)
    assert check({"ownerKeys": [key("owner:2")]}).ok
    assert check({"ownerKeys": [key("owner:2")], "reason": "key compromise"}).ok
    assert check({"ownerKeys": []}).code == "EVENT_DATA_INVALID"
    assert check({"ownerKeys": [key("owner:2"), key("owner:2")]}).code == "EVENT_DATA_INVALID"
    assert check({"ownerKeys": [key("owner:2")], "extra": True}).code == "EVENT_DATA_INVALID"
    assert check({"ownerKeys": [key("owner:2")], "reason": ""}).code == "EVENT_DATA_INVALID"
    assert check({"ownerKeys": [key("owner:2")], "reason": "a\nb"}).code == "EVENT_DATA_INVALID"
    assert check({"ownerKeys": [key("owner:2")], "reason": "x" * 257}).code == "INVALID_INPUT"
    assert check({"ownerKeys": [{**key("owner:2"), "keyId": f"k:{i}"} for i in range(65)]}).code == "INVALID_INPUT"
    assert validate_event({"id": "r", "type": "OWNER_KEYS_ROTATED", "timestamp": 1, "data": {"ownerKeys": [key("owner:2")]}}, "continuity-event/0.2", 5).code == "UNSUPPORTED_EVENT_TYPE"


def test_rotation_opens_an_epoch_and_retires_the_old_key(base):
    rotated = signed(base, rotation("rotation:py", [key("owner:3")], reason="python"), "owner:1")
    at = len(rotated) - 1
    after = signed(rotated, agent("carol"), "owner:3")
    result = replay(after)
    assert result.accepted, (result.code, result.reason)
    state = result.state
    assert state.owner_key_epochs == [{"fromPosition": 0, "keys": [key("owner:1")]}, {"fromPosition": at + 1, "keys": [key("owner:3")]}]
    assert owner_keys_at(state, at) == [key("owner:1")] and owner_keys_at(state, at + 1) == [key("owner:3")]
    assert owner_keys_at(state, -1) == [] and owner_keys_at(state, 10**6) == [key("owner:3")]
    retired = replay(signed(rotated, agent("carol"), "owner:1"))
    assert (retired.code, retired.position) == ("CONTROL_AUTHORIZATION_INVALID", at + 1)
    carried = signed(base, rotation("rotation:py", [key("owner:1"), key("owner:3")]), "owner:1")
    assert replay(signed(carried, agent("carol"), "owner:1")).accepted
    assert replay(signed(carried, agent("carol"), "owner:3")).accepted


def test_rotation_signatures(base):
    assert replay(signed(base, rotation("rotation:py", [key("owner:3")]), "owner:x")).code == "CONTROL_AUTHORIZATION_INVALID"
    assert replay(signed(base, rotation("rotation:py", [key("owner:3")]), "owner:3")).code == "CONTROL_AUTHORIZATION_INVALID"


def test_key_set_rules(base):
    once = signed(base, rotation("rotation:1", [key("owner:3")]), "owner:1")
    position = len(once)
    for keys in ([key("owner:1")], [key("owner:3"), key("owner:1")], [key("owner:9", "owner:1")]):
        result = replay(signed(once, rotation("rotation:2", keys, 201), "owner:3"))
        assert (result.code, result.position) == ("TRANSITION_INVALID", position), keys
    rebound = replay(signed(base, rotation("rotation:1", [key("owner:1", "owner:3")]), "owner:1"))
    assert rebound.code == "TRANSITION_INVALID" and "different key" in rebound.reason
    alias = replay(signed(base, rotation("rotation:1", [key("owner:1"), key("owner:alias", "owner:1")]), "owner:1"))
    assert alias.code == "TRANSITION_INVALID"
    epochs = [{"fromPosition": 0, "keys": [key("owner:1")]}]
    assert owner_key_rotation_failure(epochs, [key("owner:1")]) is None


def test_rotation_in_a_legacy_history_is_unsupported():
    legacy = from_plain(load_json(LEGACY_FIXTURES / "handover-history.json"))
    result = replay([*legacy, rotation("rotation:legacy", [key("owner:2")], legacy[-1]["timestamp"])])
    assert (result.code, result.position) == ("UNSUPPORTED_EVENT_TYPE", len(legacy))


def test_attestations_by_position(base):
    rotated = signed(base, rotation("rotation:py", [key("owner:3")]), "owner:1")
    events = signed(rotated, agent("carol"), "owner:3")
    state = replay(events).state
    domain = state.genesis["domain"]
    r = len(rotated) - 1

    def attest(by: str, position: int) -> dict:
        head = {"hash": state.event_history_hashes[position], "position": position, "canonicalTime": events[position]["timestamp"]}
        signature = "0x" + ed25519.sign(seed(by), bytes.fromhex(head_attestation_hash(domain, head, "sha256")[2:])).hex()
        return {"version": "irontrellis-head-attestation/1", "head": head, "keyId": by, "scheme": "ed25519", "signature": signature}

    assert verify_head_attestation_at(attest("owner:1", r - 1), state)
    assert verify_head_attestation_at(attest("owner:1", r), state)
    assert not verify_head_attestation_at(attest("owner:3", r), state)
    assert not verify_head_attestation_at(attest("owner:1", r + 1), state)
    assert verify_head_attestation_at(attest("owner:3", r + 1), state)
    assert verify_head_attestation(attest("owner:1", r + 1), domain, [key("owner:1")], "sha256"), "the signature itself is fine; only the position rules it out"
    assert not verify_head_attestation_at(None, state)
    assert not verify_head_attestation_at({**attest("owner:3", r + 1), "head": {**attest("owner:3", r + 1)["head"], "position": -1}}, state)


def test_verify_rotation_event_standalone(v1_histories):
    events = v1_histories["rotation-v1"]
    index = next(i for i, e in enumerate(events) if e["type"] == "OWNER_KEYS_ROTATED")
    prefix = replay(events[:index])
    previous = {"hash": prefix.head["hash"], "position": prefix.head["position"]}
    epochs = [{"fromPosition": 0, "keys": [key("owner:1")]}]
    domain = events[0]["data"]["domain"]
    verified = verify_rotation_event(events[index], domain, previous, epochs)
    assert verified["ok"] and verified["fromPosition"] == index + 1 and verified["keys"] == [key("owner:2")]
    assert verified["epochs"] == replay(events).state.owner_key_epochs
    assert verify_rotation_event(events[index], domain, {**previous, "hash": "0x" + "ab" * 32}, epochs)["code"] == "CONTROL_AUTHORIZATION_INVALID"
    assert verify_rotation_event(events[index], domain, previous, [{"fromPosition": 0, "keys": [key("owner:3")]}])["code"] == "CONTROL_AUTHORIZATION_INVALID"
    assert verify_rotation_event(events[index - 1], domain, previous, epochs)["code"] in ("INVALID_INPUT", "EVENT_DATA_INVALID")
    back = signed(events, rotation("rotation:back", [key("owner:1")], events[-1]["timestamp"]), "owner:2")
    head = replay(events).head
    again = verify_rotation_event(back[-1], domain, {"hash": head["hash"], "position": head["position"]}, verified["epochs"])
    assert again["ok"] is False and again["code"] == "TRANSITION_INVALID"
