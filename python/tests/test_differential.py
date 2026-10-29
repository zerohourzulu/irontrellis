"""Differential test: the Python engine against the TypeScript engine over every fixture
history × a grid of requests. Full results are compared (proofs and failure lists after
JSON normalisation), not only the conformance projection."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from conftest import NODE, requires_node

from irontrellis import BigInt, from_plain, replay, to_plain
from irontrellis.authority import authorize_state
from irontrellis.survives import derive_survives

HELPER = Path(__file__).with_name("differential_node.mjs")


def _grid(name, events):
    """Agents × actions × resources × amounts × times drawn from the history itself, plus foreign ids."""
    state = replay(events).state
    assert state is not None, name
    actions, resources = {"nope"}, {"nowhere"}
    for record in state.authorities.values():
        actions.update(record.grant["constraints"]["actions"])
        resources.update(record.grant["constraints"]["resources"])
    agents = [*sorted(state.agents), "unknown-agent", *sorted(state.principals)[:1]]
    head_time = state.head["canonicalTime"]
    body = lambda request, at: {  # noqa: E731
        "expectedHistoryHead": state.head, "domain": state.genesis["domain"], "policyVersion": state.genesis["policyVersion"],
        "rootRecognitionPolicy": state.genesis["rootRecognitionPolicy"], "request": request, "evaluationTime": at, "consequential": False,
    }
    requests = []
    for agent in agents:
        for action in sorted(actions):
            for resource in sorted(resources):
                for amount in (None, BigInt(50)):
                    for at in (head_time, head_time + 1000):
                        request = {"actorId": agent, "action": action, "resource": resource, "claimedAt": at}
                        if amount is not None:
                            request["amount"] = amount
                        requests.append({"op": "authorize", "history": name, "body": body(request, at)})
    for agent in agents:
        for at in (head_time, head_time + 1000):
            requests.append({"op": "survives", "history": name, "agent": agent, "at": at})
    return state, requests


def _strip_evidence(value):
    if isinstance(value, list):
        return [_strip_evidence(v) for v in value]
    if isinstance(value, dict):
        return {k: _strip_evidence(v) for k, v in value.items() if k != "evidence"}
    return value


@pytest.fixture(scope="module")
def corpus(legacy_histories, v1_histories):
    requires_node()
    histories = {**legacy_histories, **v1_histories}
    states, requests = {}, []
    for name, events in histories.items():
        state, grid = _grid(name, events)
        states[name] = state
        requests.extend(grid)
    payload = json.dumps({"histories": to_plain(histories), "requests": to_plain(requests)})
    completed = subprocess.run([NODE, str(HELPER)], input=payload, capture_output=True, text=True, encoding="utf-8", check=True)
    return states, requests, json.loads(completed.stdout)


def test_grid_is_substantial(corpus):
    _, requests, expected = corpus
    assert len(requests) == len(expected) >= 2000


def test_authorize_matches_typescript_engine(corpus):
    states, requests, expected = corpus
    mismatches = []
    decisions = {"ALLOW": 0, "DENY": 0, "INDETERMINATE": 0}
    for request, reference in zip(requests, expected):
        if request["op"] != "authorize":
            continue
        actual = to_plain(authorize_state(states[request["history"]], from_plain(to_plain(request["body"]))))
        decisions[actual["decision"]] += 1
        if actual != reference:
            mismatches.append((request["history"], request["body"]["request"], actual.get("code"), reference.get("code")))
    assert not mismatches, mismatches[:5]
    assert decisions["ALLOW"] > 20 and decisions["DENY"] > 100


def test_authorize_matches_typescript_engine_with_the_plausible_candidate_pass_forced(corpus, monkeypatch):
    """Block 3.2: ``_evaluate_algebra`` looks at the plausible candidates first for actors with many candidates. Forced
    on for every actor (threshold 0; the grid's states are fresh memo keys per test), decisions must not change."""
    import irontrellis.authority as authority
    monkeypatch.setattr(authority, "_RESOURCE_INDEX_MIN_CANDIDATES", 0)
    states, requests, expected = corpus
    compared = 0
    for state in states.values():
        state.memo = None  # rebuild each corpus (the per-resource index is built on first use under the forced threshold)
    for request, reference in zip(requests, expected):
        if request["op"] != "authorize":
            continue
        state = states[request["history"]]
        actual = to_plain(authorize_state(state, from_plain(to_plain(request["body"]))))
        assert actual == reference, (request["history"], request["body"]["request"])
        compared += 1
    assert compared > 1000


def test_survives_matches_typescript_engine(corpus):
    states, requests, expected = corpus
    for request, reference in zip(requests, expected):
        if request["op"] != "survives":
            continue
        actual = to_plain(_strip_evidence(derive_survives(states[request["history"]], request["agent"], request["at"])))
        assert reference["established"] is True
        expected = {k: v for k, v in reference["answer"].items() if k not in ("historicalIdentity", "receiptCommitments")}  # evidence-only lists
        assert actual == expected, (request["history"], request["agent"])
