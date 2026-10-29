"""Store readers on the fixtures, replay of both formats, and the conformance vectors run in-process."""
from __future__ import annotations

import json
import subprocess
import sys

import pytest
from conftest import CONFORMANCE, LEGACY_FIXTURES, PYTHON_ROOT, load_json

from irontrellis import BigInt, StoreError, from_plain, read_history, read_history_text, replay, replay_portable, to_plain
from irontrellis.authority import authorize_portable
from irontrellis.owner_keys import verify_head_attestation_at
from irontrellis.store import decode_tagged, encode_tagged
from irontrellis.survives import survives_portable


def test_legacy_store_reader_verifies_chain_and_matches_json_fixture():
    stored = read_history(str(LEGACY_FIXTURES / "handover-history.jsonl"))
    assert stored.format == "continuity-event/0.2"
    assert stored.events == from_plain(load_json(LEGACY_FIXTURES / "handover-history.json"))
    assert len(stored.record_hashes) == 26 and all(h.startswith("0x") and len(h) == 66 for h in stored.record_hashes)


def test_legacy_store_reader_rejects_tampering():
    text = (LEGACY_FIXTURES / "handover-history.jsonl").read_text("utf-8")
    lines = text.split("\n")
    with pytest.raises(StoreError, match="chain mismatch"):
        read_history_text("\n".join([lines[0], *lines[2:]]))
    corrupted = lines[3].replace('["number",3]', '["number",4]')
    assert corrupted != lines[3]
    with pytest.raises(StoreError, match="integrity"):
        read_history_text("\n".join([*lines[:3], corrupted, *lines[4:]]))
    with pytest.raises(StoreError, match="newline"):
        read_history_text(text.rstrip("\n"))
    with pytest.raises(StoreError, match="unknown store format"):
        read_history_text('{"version":"other"}\n')


def test_tagged_tuple_round_trip():
    value = {"a": BigInt(5), "b": [None, True, "s", 7, {"c": []}]}
    assert decode_tagged(encode_tagged(value)) == value
    with pytest.raises(StoreError):
        decode_tagged(["number", -1])
    with pytest.raises(StoreError):
        decode_tagged(["object", [["k", ["string", "a"]], ["k", ["string", "b"]]]])


@pytest.mark.parametrize("name", ["handover-v1", "handover-anchored-v1", "authority-v1", "migrated-v1", "rotation-v1"])
def test_format1_store_reader(name, v1_histories):
    path = CONFORMANCE / "v1" / "histories" / f"{name}.jsonl"
    stored = read_history(str(path))
    assert stored.format == "irontrellis-event/1"
    assert stored.events == v1_histories[name]
    assert replay(stored.events).accepted


def test_format1_store_reader_rejects_chain_break():
    text = (CONFORMANCE / "v1" / "histories" / "handover-v1.jsonl").read_text("utf-8")
    lines = text.split("\n")
    with pytest.raises(StoreError, match="chain mismatch"):
        read_history_text("\n".join([lines[0], *lines[2:]]))


def test_legacy_fixtures_replay_to_the_vector_heads(legacy_histories):
    heads = {
        "first-look": ("0x4958d40342fc047d3fff0d3ab0f36e572ea28d9a1bb6dcbfbc1961c52231b779", 25),
        "no-review-power": ("0x619595a06c77d03ddd90f2ed006c88626e9cc346fd236c6916b28606126e4501", 26),
        "mandate": ("0x6dae6c5c5dfd6d606dc7ce93c81d5f684a1c4d9536320929865d3b62517fb563", 6),
    }
    for name, (hash_, position) in heads.items():
        result = replay(legacy_histories[name])
        assert result.accepted, (name, result)
        assert result.head == {"hash": hash_, "position": position, "canonicalTime": position}
        state = result.state
        assert state.head is result.head and len(state.events) == position + 1 and state.format == "continuity-event/0.2"


def test_replay_rejections(legacy_histories):
    events = legacy_histories["first-look"]
    assert replay([]).code == "GENESIS_REQUIRED"
    assert replay(events[1:]).code == "GENESIS_REQUIRED"
    assert replay([events[0], events[0]]).code == "GENESIS_DUPLICATE"
    assert replay([*events[:5], events[4]]).code == "EVENT_ID_DUPLICATE"
    rewound = {**events[5], "timestamp": 2}
    assert replay([*events[:5], rewound]).code == "EVENT_TIME_REGRESSION"
    swapped = [*events[:8], events[9], events[8], *events[10:]]
    assert replay(swapped).status == "REJECTED"
    assert replay([*events[:2], {"id": "x", "type": "NOPE", "timestamp": 2, "data": {}}]).code == "UNSUPPORTED_EVENT_TYPE"
    assert replay([*events[:2], {"id": "x", "type": "AGENT_CREATED", "timestamp": 2, "data": {"agentId": "a"}}]).code == "EVENT_DATA_INVALID"
    assert replay([*events[:2], {"id": "x", "type": "AGENT_CREATED", "timestamp": 2, "data": {"agentId": "a" * 300, "principalId": "p", "controllerId": "c", "initialControlEpoch": 1}}]).code == "INVALID_INPUT"
    assert replay("nope").code == "INVALID_INPUT"
    assert replay_portable("continuity-replay/0.1", events).code == "UNSUPPORTED_VERSION"


def test_format1_replay_verifies_control_signatures(v1_histories):
    events = v1_histories["handover-v1"]
    result = replay(events)
    assert result.accepted and result.state.format == "irontrellis-event/1" and result.state.hash_algorithm == "sha256"
    index = next(i for i, e in enumerate(events) if e["type"] == "AUTHORITY_GRANTED")
    unsigned = {**events[index], "data": {k: v for k, v in events[index]["data"].items() if k != "controlAuthorization"}}
    rejected = replay([*events[:index], unsigned, *events[index + 1:]])
    assert rejected.code == "CONTROL_AUTHORIZATION_INVALID" and rejected.position == index and "unsigned" in rejected.reason
    signature = events[index]["data"]["controlAuthorization"]["signature"]
    tampered = {**events[index], "data": {**events[index]["data"], "controlAuthorization": {"keyId": "owner:1", "signature": signature[:-1] + ("0" if signature[-1] != "0" else "1")}}}
    assert replay([*events[:index], tampered, *events[index + 1:]]).code == "CONTROL_AUTHORIZATION_INVALID"


def test_migrated_history_keeps_legacy_shadow(v1_histories):
    result = replay(v1_histories["migrated-v1"])
    assert result.accepted
    state = result.state
    assert state.shadow is not None and state.shadow_hashes is not None
    assert state.shadow_hashes[25] == "0x4958d40342fc047d3fff0d3ab0f36e572ea28d9a1bb6dcbfbc1961c52231b779"
    assert state.genesis["migratedFrom"]["historyHash"] == state.shadow_hashes[25]


def test_truncated_migrated_prefix_is_rejected(v1_histories):
    """A completed replay must consume the whole declared prefix, as the Node engine requires (``incompleteMigration``)."""
    events = v1_histories["migrated-v1"]
    until = events[0]["data"]["migratedFrom"]["position"]
    for length in (1, 2, until // 2, until):
        result = replay(events[:length])
        assert (result.status, result.code, result.position, result.reason) == ("REJECTED", "TRANSITION_INVALID", length, "migrated prefix incomplete")
    assert replay(events[:until + 1]).accepted


def test_cli_verify_rejects_truncated_migrated_store(tmp_path):
    lines = (CONFORMANCE / "v1" / "histories" / "migrated-v1.jsonl").read_text("utf-8").splitlines(keepends=True)
    truncated = tmp_path / "migrated-truncated.jsonl"
    truncated.write_text("".join(lines[:-1]), "utf-8")
    run = _cli("verify", str(truncated))
    report = json.loads(run.stdout)
    assert run.returncode == 1 and report["status"] == "REJECTED"
    assert report["code"] == "TRANSITION_INVALID" and report["reason"] == "migrated prefix incomplete"


# ---------------------------------------------------------------- conformance vectors, in-process


def _project_authorize(result):
    return {
        "decision": result["decision"], "code": result.get("code"), "scopeAssurance": result.get("scopeAssurance"),
        "controllingAuthorityIds": result["proof"]["controllingAuthorityIds"] if result["decision"] == "ALLOW" else None,
        "failureCodes": [f["code"] for f in result.get("failures", [])],
    }


def _project_survives(result):
    if not result.established:
        return {"established": False, "code": result.code, "epistemicStatus": result.epistemic_status}
    a = result.answer
    return {
        "established": True, "exists": a["exists"], "lifecycleStatus": a["lifecycleStatus"], "obligationIds": sorted(r["obligationId"] for r in a["obligations"]),
        "currentAssignments": [{"obligationId": r["obligationId"], "assigneeId": r["assigneeId"], "successionRuleId": r.get("successionRuleId")} for r in a["currentPerformanceAssignments"]],
        "currentRoleTenureCount": len(a["currentRoleTenures"]), "transferredRoleTenureCount": len(a["transferredRoleTenures"]),
        "invalidatedAuthorityIds": sorted(r["authorityId"] for r in a["invalidatedAuthorityDependencies"]), "unresolvedIntentIds": sorted(r["intentId"] for r in a["unresolvedIntents"]),
    }


def _project(expected, actual):
    """The runner's projection: only the expected fields, arrays and scalars exact."""
    if isinstance(expected, dict):
        return {key: _project(value, actual.get(key)) if key in actual else "<missing>" for key, value in expected.items()}
    if isinstance(expected, list) and isinstance(actual, list):
        return [_project(e, a) for e, a in zip(expected, actual)] if len(expected) == len(actual) else actual
    return actual


def _run_vector(vector, histories):
    kind = vector["kind"]
    if kind == "replay":
        result = replay_portable(vector["input"]["operationVersion"], from_plain(vector["events"]))
        state = result.state if result.accepted else None
        epochs = state.owner_key_epochs if state is not None else []
        # The format-1 replay facts the adapters report (a vector declares the ones it tests).
        return {
            "status": result.status, "head": result.head if result.accepted else None, "code": None if result.accepted else result.code,
            "boundWitnesses": [w["verifierKey"] for w in state.bound_witnesses] if state is not None else None,
            "boundPolicy": state.bound_policy if state is not None else None,
            "nextKeyDigests": (epochs[-1].get("nextKeyDigests") if epochs else None) if state is not None else None,
        }
    events = histories[vector["history"]["ref"]][:vector["history"]["eventCount"]]
    if kind == "attestation":
        state, attestation = replay(events).state, vector["input"]["attestation"]
        position = attestation["head"]["position"]
        signature_valid = verify_head_attestation_at(attestation, state)
        prefix = 0 <= position <= state.head["position"] and state.event_history_hashes[position] == attestation["head"]["hash"]
        return {"valid": signature_valid and prefix, "signatureValid": signature_valid, "prefix": prefix}
    if kind == "authorization":
        return _project_authorize(authorize_portable({**from_plain(vector["input"]), "events": events}))
    return _project_survives(survives_portable(vector["input"]["operationVersion"], events, vector["input"]["targetAgentId"], vector["input"]["evaluationTime"]))


def _vectors(suite):
    path = CONFORMANCE / suite / "vectors.json"
    if not path.exists():
        return []
    return [pytest.param(v, id=v["id"]) for v in load_json(path)]


@pytest.mark.parametrize("vector", _vectors("legacy"))
def test_legacy_conformance_vector(vector, legacy_histories):
    assert to_plain(_project(vector["expect"], _run_vector(vector, legacy_histories))) == vector["expect"], vector["purpose"]


@pytest.mark.parametrize("vector", _vectors("v1"))
def test_v1_conformance_vector(vector, v1_histories):
    assert to_plain(_project(vector["expect"], _run_vector(vector, v1_histories))) == vector["expect"], vector["purpose"]


# ---------------------------------------------------------------- CLI


def _cli(*args):
    return subprocess.run([sys.executable, "-m", "irontrellis", *args], cwd=PYTHON_ROOT / "src", capture_output=True, text=True, encoding="utf-8", check=False)


def test_cli_verify_authorize_survives():
    history = str(LEGACY_FIXTURES / "handover-history.jsonl")
    verify = _cli("verify", history)
    assert verify.returncode == 0
    report = json.loads(verify.stdout)
    assert report["status"] == "ACCEPTED" and report["head"]["position"] == 25 and report["chain"] == "OK" and report["store"]["records"] == 26
    allow = _cli("authorize", history, "--actor", "b:first-look", "--action", "record-review-progress", "--resource", "obligation:first-look")
    assert allow.returncode == 0 and json.loads(allow.stdout)["controllingAuthorityIds"] == ["progress-b-authority:first-look"]
    deny = _cli("authorize", history, "--actor", "a:first-look", "--action", "collect-evidence-packet", "--resource", "resource:first-look")
    assert deny.returncode == 2 and json.loads(deny.stdout)["code"] == "AGENT_INACTIVE"
    survives = _cli("survives", history, "--agent", "a:first-look")
    assert survives.returncode == 0
    answer = json.loads(survives.stdout)["answer"]
    assert answer["lifecycleStatus"] == "TERMINATED" and answer["currentPerformanceAssignments"][0]["assigneeId"] == "b:first-look"
    v1 = str(CONFORMANCE / "v1" / "histories" / "authority-v1.jsonl")
    quantity = _cli("authorize", v1, "--actor", "spender", "--action", "spend", "--resource", "petty-cash", "--amount", "20")
    assert json.loads(quantity.stdout)["code"] == "CUMULATIVE_AMOUNT_EXCEEDED"
    broken = _cli("verify", str(PYTHON_ROOT / "pyproject.toml"))
    assert broken.returncode == 1


def test_witness_bindings_replay_and_are_reported_not_consulted():
    """A history that binds remote witnesses (owner-signed WITNESSES_BOUND then WITNESSES_UNBOUND; conformance/v1
    history witness-bound-v1, written by the TypeScript core) replays as in TS: the REGISTERED receipt of the first
    witness is verified at replay, the bindings are reported, and ``verify`` notes REMOTE_WITNESS_NOT_CONSULTED (the TS
    code for a check that did not ask the witnesses)."""
    from irontrellis.transparency import bound_policy_of, bound_witnesses_of
    path = CONFORMANCE / "v1" / "histories" / "witness-bound-v1.json"
    events = from_plain(load_json(path))
    result = replay(events)
    assert result.accepted
    assert [e["type"] for e in result.state.events[-2:]] == ["WITNESSES_BOUND", "WITNESSES_UNBOUND"]
    assert result.state.anchors == [], "a binding is not an anchor"
    registration = result.state.bound_witnesses[0]["registration"]
    assert registration["index"] == 0 and registration["receipt"]["entry"]["kind"] == "REGISTERED"
    bound = bound_witnesses_of(result.state)
    assert [w["url"] for w in bound] == ["https://witness-a.example.org"] and bound[0]["name"] == "witness-a"
    # The owner-signed policy minimum of the newest binding (docs/reference/witness-policy.md §5.3), as the TypeScript boundPolicyOf.
    assert bound_policy_of(result.state) == {"quorum": 1, "requireOnOpen": True, "maxUnwitnessedEvents": 100}
    assert bound_policy_of(replay(from_plain(load_json(CONFORMANCE / "v1" / "histories" / "handover-v1.json"))).state) is None
    run = _cli("verify", str(path))
    assert run.returncode == 0, run.stderr
    report = json.loads(run.stdout)
    assert report["status"] == "ACCEPTED" and report["witnessBindings"] == bound
    assert report["witnessPolicyMinimum"] == {"quorum": 1, "requireOnOpen": True, "maxUnwitnessedEvents": 100}
    assert len(report["notes"]) == 1 and report["notes"][0].startswith("REMOTE_WITNESS_NOT_CONSULTED: 1 remote witness(es) are bound in this history")
    plain = json.loads(_cli("verify", str(CONFORMANCE / "v1" / "histories" / "handover-v1.json")).stdout)
    assert plain["witnessBindings"] == [] and plain["notes"] == [] and plain["witnessPolicyMinimum"] is None
