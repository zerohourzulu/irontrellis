"""Decision-procedure details the conformance projection does not pin down: proofs, failure ordering, capture."""
from __future__ import annotations

from irontrellis import BigInt, replay
from irontrellis.authority import AUTHORIZATION_VERSION, authorize_portable, authorize_state, combine_constraints, constraints_are_attenuated, normalized_grant
from irontrellis.canonical import canonical_encode


def _body(state, request, **extra):
    return {
        "expectedHistoryHead": state.head, "domain": state.genesis["domain"], "policyVersion": state.genesis["policyVersion"],
        "rootRecognitionPolicy": state.genesis["rootRecognitionPolicy"], "request": request, "evaluationTime": state.head["canonicalTime"], "consequential": False, **extra,
    }


def test_allow_proof_structure(v1_histories):
    state = replay(v1_histories["authority-v1"]).state
    result = authorize_state(state, _body(state, {"actorId": "analyst", "action": "write", "resource": "ledger", "claimedAt": state.head["canonicalTime"], "amount": BigInt(50)}))
    assert result["decision"] == "ALLOW" and result["scopeAssurance"] == "REPLAY_VERIFIED" and result["consequential"] is False
    proof = result["proof"]
    assert proof["proofVersion"] == "continuity-authorization-proof/0.2"
    assert [g["authorityId"] for g in proof["permissionPath"]] == ["root", "write-with-dual"]
    assert [i["requiredAuthorityId"] for i in proof["intersections"]] == ["dual"]
    assert proof["intersections"][0]["requiredByAuthorityIds"] == ["write-with-dual"]
    assert proof["controllingAuthorityIds"] == ["dual", "root", "write-with-dual"]
    assert proof["effectiveConstraints"]["actions"] == ["write"] and proof["effectiveConstraints"]["maxAmount"] == BigInt(500)
    assert [e["authorityId"] for e in proof["authorityEvidence"]] == ["dual", "root", "write-with-dual"]
    assert proof["usageSnapshot"] == [] and proof["checkedProhibitionIds"] == []
    # The proof is canonical: sorted constraint arrays, no undefined members.
    assert canonical_encode(proof)


def test_usage_snapshot_reflects_admissions(v1_histories):
    state = replay(v1_histories["authority-v1"]).state
    result = authorize_state(state, _body(state, {"actorId": "spender", "action": "spend", "resource": "petty-cash", "claimedAt": state.head["canonicalTime"], "amount": BigInt(10)}))
    assert result["decision"] == "ALLOW"
    assert result["proof"]["usageSnapshot"] == [{"authorityId": "metered", "admittedTransactionCount": 2, "admittedCumulativeAmount": BigInt(90)}]


def test_failures_are_sorted_by_precedence(legacy_histories):
    state = replay(legacy_histories["no-review-power"]).state
    result = authorize_state(state, _body(state, {"actorId": "b:no-review-power", "action": "record-review-progress", "resource": "obligation:no-review-power", "claimedAt": state.head["canonicalTime"]}))
    assert result["decision"] == "DENY" and result["code"] == "REVOKED"
    assert [f["code"] for f in result["failures"]] == ["REVOKED", "ACTION_NOT_ALLOWED"]
    first = result["failures"][0]
    assert first["failingAuthorityId"] == "progress-b-authority:no-review-power" and first["rootAuthorityId"] == first["terminalAuthorityId"]
    assert all(ref["kind"] == "EVENT" and ref["historyHash"].startswith("0x") for ref in first["evidence"])
    assert first["evidence"] == sorted(first["evidence"], key=lambda r: (r["eventId"], r["eventType"], r["position"], r["historyHash"]))


def test_indeterminate_inputs(legacy_histories):
    events = legacy_histories["first-look"]
    state = replay(events).state
    head = state.head
    base = {"operationVersion": AUTHORIZATION_VERSION, "events": events, "expectedHistoryHead": head, "domain": state.genesis["domain"], "policyVersion": state.genesis["policyVersion"],
            "rootRecognitionPolicy": state.genesis["rootRecognitionPolicy"], "request": {"actorId": "b:first-look", "action": "x", "resource": "y", "claimedAt": 25},
            "evaluationTime": 25, "authoritative": True, "consequential": False}
    assert authorize_portable(base)["decision"] == "DENY"
    assert authorize_portable({**base, "operationVersion": "continuity-authorization/0.1"})["code"] == "UNSUPPORTED_VERSION"
    assert authorize_portable({**base, "authoritative": False})["code"] == "INVALID_INPUT"
    assert authorize_portable({**base, "extra": 1})["code"] == "INVALID_INPUT"
    assert authorize_portable({**base, "request": {**base["request"], "amount": 5}})["code"] == "INVALID_AMOUNT"  # a number is not a bigint
    assert authorize_portable({**base, "events": events[:-1]})["code"] == "HISTORY_RELATION_UNVERIFIED"
    assert authorize_portable({**base, "events": [events[0], events[0]]})["code"] == "STATE_NOT_AUTHORITATIVE"
    assert authorize_portable({**base, "evaluationTime": 3})["code"] == "CAUSAL_TIME_INVALID"
    assert authorize_portable({**base, "request": {**base["request"], "actorId": "a" * 300}})["code"] == "INVALID_INPUT"
    assert authorize_portable({**base, "request": {**base["request"], "actorId": ""}})["code"] == "INVALID_REQUEST"
    assert authorize_portable({**base, "request": {**base["request"], "amount": BigInt(-1)}})["code"] == "INVALID_AMOUNT"


def test_consequential_binding_denials(legacy_histories):
    state = replay(legacy_histories["first-look"]).state
    request = {"actorId": "b:first-look", "action": "record-review-progress", "resource": "obligation:first-look", "claimedAt": 25}
    binding = {"runtimeSessionId": "session:first-look:b", "controlEpoch": 1, "roleId": "role:first-look", "roleTenureId": "tenure-b:first-look"}
    assert authorize_state(state, _body(state, request, consequential=True, binding={**binding, "runtimeSessionId": "nope"}))["code"] == "SESSION_NOT_FOUND"
    assert authorize_state(state, _body(state, request, consequential=True, binding=binding))["code"] == "SESSION_CREDENTIAL_REQUIRED"
    assert authorize_state(state, _body(state, request, consequential=True))["code"] == "INVALID_INPUT"


def test_constraint_algebra():
    parent = {"actions": ["a", "b"], "resources": ["r"], "quantitative": True, "maxDelegationDepth": 2, "requiredIntersectionIds": [], "expiresAt": 100, "maxAmount": BigInt(10)}
    child = {"actions": ["a"], "resources": ["r"], "quantitative": True, "maxDelegationDepth": 1, "requiredIntersectionIds": ["x"], "expiresAt": 50, "maxAmount": BigInt(5)}
    assert constraints_are_attenuated(parent, child)
    assert not constraints_are_attenuated(parent, {**child, "maxAmount": BigInt(11)})
    assert not constraints_are_attenuated(parent, {**child, "quantitative": False})
    assert not constraints_are_attenuated(parent, {**child, "maxDelegationDepth": 2})
    combined = combine_constraints([{"constraints": parent}, {"constraints": child}])
    assert combined == {"actions": ["a"], "resources": ["r"], "quantitative": True, "expiresAt": 50, "maxAmount": BigInt(5), "maxDelegationDepth": 1, "requiredIntersectionIds": ["x"]}
    grant = {"kind": "PERMISSION", "authorityId": "g", "grantorId": "p", "granteeId": "a", "rootAuthorityId": "g", "independent": True, "constraints": {**parent, "actions": ["b", "a"]}}
    assert normalized_grant(grant)["constraints"]["actions"] == ["a", "b"]
