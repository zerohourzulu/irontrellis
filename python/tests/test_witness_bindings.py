"""Remote witness bindings: the owner-signed WITNESSES_BOUND / WITNESSES_UNBOUND control events, signed here in Python
over the conformance handover history, independently of the TypeScript engine: the closed schema (URL, verifier key,
name, allowInsecureHttp, registration record, policy minimum, accepted loss), the transition rules (the registration
receipt verified with the bound witness's key against this very genesis, at most 16 bound, the quorum against the
witnesses bound after the event, unbinding only bound witnesses, an accepted loss only of a head this copy lacks), and
that no anchor, whatever its receipt, binds anything."""
from __future__ import annotations

import pytest

from irontrellis import replay
from irontrellis.crypto import ed25519
from irontrellis.events import CONTROL_EVENT_TYPES, TRELLIS_ONLY_EVENT_TYPES, control_authorization_hash, control_effect, control_effect_hash, validate_event
from irontrellis.transparency import bound_policy_of, bound_witnesses_of

OWNER_SEED = bytes.fromhex(f"{0x1001:064x}")


def signed(events: list, event: dict) -> list:
    """``event`` signed by the conformance owner key (owner:1) as the next control event of ``events``."""
    result = replay(events)
    assert result.accepted, (result.code, result.reason)
    state = result.state
    event = {**event, "timestamp": max(event.get("timestamp", 0), state.head["canonicalTime"])}
    effect = control_effect(event["data"])
    challenge = control_authorization_hash(state.genesis["domain"], event["id"], event["type"], event["timestamp"],
                                           {"hash": state.head["hash"], "position": state.head["position"]}, control_effect_hash({**event, "data": effect}, "sha256"), "sha256")
    signature = "0x" + ed25519.sign(OWNER_SEED, bytes.fromhex(challenge[2:])).hex()
    return [*events, {**event, "data": {**effect, "controlAuthorization": {"keyId": "owner:1", "signature": signature}}}]


def policy(quorum: int = 1) -> dict:
    return {"quorum": quorum, "requireOnOpen": True, "maxUnwitnessedEvents": 100}


@pytest.fixture()
def material(v1_histories):
    """The handover history (no binding), and the witnesses and REGISTERED receipt the TypeScript core bound over it."""
    base = v1_histories["handover-v1"]
    bound = v1_histories["witness-bound-v1"]
    binding = bound[len(base)]
    assert binding["type"] == "WITNESSES_BOUND"
    a, b = binding["data"]["witnesses"]
    return {"base": base, "a": a, "b": b, "plain_a": {k: v for k, v in a.items() if k != "registration"}}


def bind(events: list, witnesses: list, quorum: int = 1, event_id: str = "binding:py") -> list:
    return signed(events, {"id": event_id, "type": "WITNESSES_BOUND", "data": {"witnesses": witnesses, "policy": policy(quorum)}})


def unbind(events: list, keys: list, quorum: int = 1, event_id: str = "unbinding:py", **extra) -> list:
    return signed(events, {"id": event_id, "type": "WITNESSES_UNBOUND", "data": {"verifierKeys": keys, "policy": policy(quorum), **extra}})


def rejected(events: list, code: str, fragment: str | None = None) -> None:
    result = replay(events)
    assert not result.accepted
    assert result.code == code, result.reason
    if fragment is not None:
        assert fragment in result.reason, result.reason


def test_vocabulary():
    assert {"WITNESSES_BOUND", "WITNESSES_UNBOUND"} <= CONTROL_EVENT_TYPES and {"WITNESSES_BOUND", "WITNESSES_UNBOUND"} <= TRELLIS_ONLY_EVENT_TYPES


def test_bind_rebind_unbind(material):
    base, a, b = material["base"], material["a"], material["b"]
    events = bind(base, [a, b], quorum=2)
    state = replay(events).state
    assert [w["verifierKey"] for w in state.bound_witnesses] == [a["verifierKey"], b["verifierKey"]]
    assert state.bound_witnesses[0]["registration"]["index"] == 0 and "registration" not in state.bound_witnesses[1]
    assert bound_policy_of(state) == policy(2)
    assert bound_witnesses_of(state) == [{"url": a["url"], "verifierKey": a["verifierKey"], "name": a["name"]}, {"url": b["url"], "verifierKey": b["verifierKey"]}]
    # A re-binding replaces the record in place (here: without the receipt, at another URL).
    moved = bind(events, [{**material["plain_a"], "url": "https://witness-a.example.org/v2"}], quorum=2, event_id="binding:again")
    state = replay(moved).state
    assert [w["url"] for w in state.bound_witnesses] == ["https://witness-a.example.org/v2", b["url"]]
    assert "registration" not in state.bound_witnesses[0]
    after = unbind(moved, [b["verifierKey"]])
    assert [w["verifierKey"] for w in replay(after).state.bound_witnesses] == [a["verifierKey"]]


def test_schema(material):
    base, a = material["base"], material["plain_a"]

    def check(data: dict, event_type: str = "WITNESSES_BOUND"):
        return validate_event({"id": "x", "type": event_type, "timestamp": 1, "data": data}, "irontrellis-event/1", 5)
    assert check({"witnesses": [a], "policy": policy()}).ok
    for bad_url in ["ftp://witness", "https://witness/", "https://user@witness", "https://witness?x=1", "https://witness#f", "https://wit ness", "https://wïtness", "https://", ""]:
        assert check({"witnesses": [{**a, "url": bad_url}], "policy": policy()}).code == "EVENT_DATA_INVALID", bad_url
    assert check({"witnesses": [{**a, "url": "http://127.0.0.1:8080/w"}], "policy": policy()}).ok
    assert check({"witnesses": [{**a, "verifierKey": "not+a+key"}], "policy": policy()}).code == "EVENT_DATA_INVALID"
    assert check({"witnesses": [{**a, "allowInsecureHttp": False}], "policy": policy()}).code == "EVENT_DATA_INVALID"
    assert check({"witnesses": [{**a, "registration": "receipt"}], "policy": policy()}).code == "EVENT_DATA_INVALID"
    assert check({"witnesses": [{**a, "extra": 1}], "policy": policy()}).code == "EVENT_DATA_INVALID"
    assert check({"witnesses": [a, a], "policy": policy()}).code == "EVENT_DATA_INVALID"
    assert check({"witnesses": [], "policy": policy()}).code == "EVENT_DATA_INVALID"
    assert check({"witnesses": [a] * 17, "policy": policy()}).code == "INVALID_INPUT"
    assert check({"witnesses": [{**a, "name": "n" * 257}], "policy": policy()}).code == "INVALID_INPUT"
    for bad_policy in [{"quorum": 0, "requireOnOpen": True, "maxUnwitnessedEvents": 1}, {"quorum": 17, "requireOnOpen": True, "maxUnwitnessedEvents": 1},
                       {"quorum": 1, "requireOnOpen": 1, "maxUnwitnessedEvents": 1}, {"quorum": 1, "requireOnOpen": True, "maxUnwitnessedEvents": 0},
                       {"quorum": 1, "requireOnOpen": True}, {"quorum": 1, "requireOnOpen": True, "maxUnwitnessedEvents": 1, "cacheMs": 1}]:
        assert check({"witnesses": [a], "policy": bad_policy}).code == "EVENT_DATA_INVALID", bad_policy
    assert check({"witnesses": [a]}).code == "EVENT_DATA_INVALID"
    assert check({"witnesses": [a], "policy": policy(), "acceptedLoss": {"reason": "r", "heads": []}}).code == "EVENT_DATA_INVALID", "only an unbinding records a loss"
    head = {"hash": "0x" + "ee" * 32, "position": 40, "canonicalTime": 1}
    loss = {"reason": "restored", "heads": [{"verifierKey": a["verifierKey"], "head": head}]}
    assert check({"verifierKeys": [a["verifierKey"]], "policy": policy(), "acceptedLoss": loss}, "WITNESSES_UNBOUND").ok
    assert check({"verifierKeys": [a["verifierKey"]], "policy": policy(), "acceptedLoss": {**loss, "reason": ""}}, "WITNESSES_UNBOUND").code == "EVENT_DATA_INVALID"
    assert check({"verifierKeys": [a["verifierKey"]], "policy": policy(), "acceptedLoss": {**loss, "heads": []}}, "WITNESSES_UNBOUND").code == "EVENT_DATA_INVALID"
    assert check({"verifierKeys": [], "policy": policy()}, "WITNESSES_UNBOUND").code == "EVENT_DATA_INVALID"
    assert check({"verifierKeys": [a["verifierKey"]] * 2, "policy": policy()}, "WITNESSES_UNBOUND").code == "EVENT_DATA_INVALID"
    assert validate_event({"id": "x", "type": "WITNESSES_BOUND", "timestamp": 1, "data": {"witnesses": [a], "policy": policy()}}, "continuity-event/0.2", 5).code == "UNSUPPORTED_EVENT_TYPE"
    assert replay(bind(base, [a])).accepted


def test_transition_rules(material):
    base, a, b = material["base"], material["a"], material["b"]
    # The receipt: verified with the bound witness's own key, and naming this very genesis.
    rejected(bind(base, [{**b, "registration": a["registration"]}]), "TRANSITION_INVALID", "does not verify")
    broken = {**a["registration"], "inclusionProof": ["AAAA"]}
    rejected(bind(base, [{**a, "registration": broken}]), "TRANSITION_INVALID", "does not verify")
    renamed_genesis = [{**base[0], "id": "another-genesis"}]
    rejected(bind(renamed_genesis, [a]), "TRANSITION_INVALID", "not the REGISTERED leaf of this history")
    # The quorum counts the witnesses bound after the event.
    rejected(bind(base, [a], quorum=2), "TRANSITION_INVALID", "exceeds the 1 witness(es)")
    events = bind(base, [a, b], quorum=2)
    rejected(unbind(events, [b["verifierKey"]], quorum=2), "TRANSITION_INVALID", "exceeds the 1 witness(es)")
    assert replay(unbind(events, [a["verifierKey"], b["verifierKey"]], quorum=1)).accepted, "unbinding every witness leaves quorum 1"
    # Only bound witnesses are unbound; an accepted loss names an unbound witness and a head this copy lacks.
    rejected(unbind(base, [a["verifierKey"]]), "TRANSITION_INVALID", "is not bound")
    head = replay(events).state.head
    contained = {"reason": "restored", "heads": [{"verifierKey": b["verifierKey"], "head": head}]}
    rejected(unbind(events, [b["verifierKey"]], acceptedLoss=contained), "TRANSITION_INVALID", "nothing was lost")
    foreign = {"reason": "restored", "heads": [{"verifierKey": a["verifierKey"], "head": {**head, "position": head["position"] + 3}}]}
    rejected(unbind(events, [b["verifierKey"]], acceptedLoss=foreign), "TRANSITION_INVALID", "does not unbind")
    lost = {"reason": "restored", "heads": [{"verifierKey": b["verifierKey"], "head": {**head, "hash": "0x" + "ee" * 32}}]}
    assert replay(unbind(events, [b["verifierKey"]], acceptedLoss=lost)).accepted
    # More than 16 bound in total (each event names at most 16): refused.
    from irontrellis.transparency import note_signer_from_seed, verifier_key
    many = []
    for n in range(17):
        signer = note_signer_from_seed(f"w{n}.example", bytes([n + 1]) * 32)
        many.append({"url": f"https://w{n}.example", "verifierKey": verifier_key(signer.name, signer.public_key)})
    sixteen = bind(base, many[:16])
    assert len(replay(sixteen).state.bound_witnesses) == 16
    rejected(bind(sixteen, many[16:], event_id="binding:17"), "TRANSITION_INVALID", "at most 16")


def test_anchors_never_bind(material):
    base, a = material["base"], material["a"]
    events = bind(base, [a])
    head = replay(events).state.head
    shaped = {"version": "irontrellis-witness-binding/1", "action": "UNBIND", "witnesses": [{"url": a["url"], "verifierKey": a["verifierKey"]}], "policy": policy()}
    anchored = signed(events, {"id": "anchor:py", "type": "ANCHOR_RECORDED", "data": {"anchoredHead": head, "anchor": "custom", "receipt": shaped, "anchoredAt": head["canonicalTime"]}})
    state = replay(anchored).state
    assert [w["verifierKey"] for w in state.bound_witnesses] == [a["verifierKey"]] and state.bound_policy == policy()
    assert len(state.anchors) == 1
    http = signed(events, {"id": "anchor:http", "type": "ANCHOR_RECORDED", "data": {"anchoredHead": head, "anchor": "http-witness", "receipt": shaped, "anchoredAt": head["canonicalTime"]}})
    rejected(http, "EVENT_DATA_INVALID")
