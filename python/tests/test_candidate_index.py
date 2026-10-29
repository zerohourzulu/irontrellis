"""The per-resource candidate index of the plausible-candidate pass, grown event by event (review block 3, M3).

Mirrors packages/core/test/candidate-index.test.mjs for the Python engine: one ``ReplayState`` grown with
``apply_event`` (so ``_extend_memo`` maintains the memo and ``_index_candidate`` the per-resource index built on the
first query) against a naive reference, the full candidate loop over a corpus validated from scratch. The histories are
the seeded random format-1 ones of packages/core/test/helpers/candidate-history.mjs (random grant ids, so a grant added
late can win), written by the TypeScript owner API. The test fails when ``_index_candidate`` stops adding a new path to
an already-built index (checked by mutation when it was written).
"""
from __future__ import annotations

import copy
import json
import subprocess

import pytest
from conftest import CORE_DIST, NODE, REPO_ROOT, requires_node

from irontrellis import authority, json_loads_with_bigints, to_plain
from irontrellis.replay import apply_event
from irontrellis.state import ReplayState

GENERATOR = REPO_ROOT / "packages" / "core" / "test" / "helpers" / "candidate-history.mjs"
ACTIONS, RESOURCES = ("read", "write", "pay"), ("r0", "r1", "r2", "r3")
GRID = [{"actorId": actor, "action": action, "resource": resource, **({} if amount is None else {"amount": amount})}
        for actor in ("w", "a1") for action in (*ACTIONS, "nope") for resource in (*RESOURCES, "rx") for amount in (None, 120)]
OFFSETS = (0, 150)


def _history(seed: int, operations: int) -> list:
    requires_node()
    if not GENERATOR.exists() or not CORE_DIST.exists():
        pytest.skip("the TypeScript generator or the built core is not available")
    run = subprocess.run([NODE, str(GENERATOR), str(seed), str(operations)], capture_output=True, text=True, encoding="utf-8", timeout=300, check=True)
    return json_loads_with_bigints(run.stdout)


def _body(state, request, at):
    from irontrellis import BigInt
    req = {**request, "claimedAt": at}
    if "amount" in req:
        req["amount"] = BigInt(req["amount"])
    return {"expectedHistoryHead": state.head, "domain": state.genesis["domain"], "policyVersion": state.genesis["policyVersion"],
            "rootRecognitionPolicy": state.genesis["rootRecognitionPolicy"], "request": req, "evaluationTime": at, "consequential": False}


def _decisions(state, at):
    return [json.dumps(to_plain(authority.authorize_state(state, _body(state, request, t))), sort_keys=True) for request in GRID for t in at]


def _differential(monkeypatch, events, threshold, label):
    grown = ReplayState(events[0]["data"]["versions"]["eventSchemaVersion"])
    compared = allows = 0
    for k, event in enumerate(events, start=1):
        result = apply_event(grown, event)
        assert result.ok, f"{label}: event {k - 1} {result.code}"
        at = [grown.head["canonicalTime"] + dt for dt in OFFSETS]
        monkeypatch.setattr(authority, "_RESOURCE_INDEX_MIN_CANDIDATES", threshold)
        actual = _decisions(grown, at)
        # The reference: the pass off, over a corpus built from scratch (a shallow copy without the grown state's memo).
        monkeypatch.setattr(authority, "_RESOURCE_INDEX_MIN_CANDIDATES", float("inf"))
        fresh = copy.copy(grown)
        fresh.memo = None
        expected = _decisions(fresh, at)
        for i, (a, b) in enumerate(zip(actual, expected)):
            assert a == b, f"{label}: after event {k - 1} ({event['type']}), {GRID[i // len(at)]} at {at[i % len(at)]}:\n grown     {a[:500]}\n reference {b[:500]}"
            allows += '"decision": "ALLOW"' in a
        compared += len(actual)
    return compared, allows


def test_candidate_index_grown_state_decides_as_the_full_loop(monkeypatch):
    compared = allows = 0
    for seed in (1, 2):
        c, a = _differential(monkeypatch, _history(seed, 70), 0, f"seed {seed} threshold 0")
        compared += c
        allows += a
    assert compared > 10_000 and allows > 500, (compared, allows)


def test_generator_is_deterministic():
    assert NODE is not None or pytest.skip("node is not available")
    assert _history(3, 12) == _history(3, 12)
