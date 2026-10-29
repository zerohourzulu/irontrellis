#!/usr/bin/env python3
"""Conformance adapter for the Python `irontrellis` package (conformance/legacy/ADAPTER.md).

One JSON request per line on stdin, one JSON response per line on stdout:
`{"ok":true,"result":{...}}` or `{"ok":false,"error":"reason"}`. Diagnostics go
to stderr only. The adapter runs from a source checkout (python/src is put on
sys.path) or from an installed `irontrellis` distribution.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(os.path.dirname(os.path.dirname(HERE)), "python", "src")
if os.path.isdir(SRC):
    sys.path.insert(0, SRC)

from irontrellis import __version__, from_plain, to_plain  # noqa: E402
from irontrellis.authority import authorize_portable  # noqa: E402
from irontrellis.canonical import CanonicalError, json_loads  # noqa: E402
from irontrellis.owner_keys import verify_head_attestation_at  # noqa: E402
from irontrellis.replay import replay, replay_portable  # noqa: E402
from irontrellis.survives import survives_portable  # noqa: E402


def revive(value):
    """Amounts arrive as {"$continuity.bigint":"…"}; a malformed tag is an adapter input error."""
    try:
        return from_plain(value)
    except CanonicalError as error:
        raise ValueError("INVALID_QUANTITY_ENCODING") from error


def handle(request: dict) -> dict:
    op = request.get("op")
    if op == "describe":
        return {
            "implementation": "irontrellis-python", "language": "python", "version": __version__,
            "levels": ["verifier", "evaluator"], "operations": ["replay", "authorize", "survives", "verify-attestation"],
            "formats": ["continuity-event/0.2", "irontrellis-event/1"],
        }
    if op == "replay":
        result = replay_portable(request.get("operationVersion"), revive(request.get("events")))
        state = result.state if result.accepted else None
        epochs = state.owner_key_epochs if state is not None else []
        # Format-1 facts a replay establishes (declared in `expect` when a vector tests them): the bound witnesses in binding
        # order, the owner-signed witness policy minimum, and the next-key commitment of the owner keys in force.
        return {
            "status": result.status, "head": to_plain(result.head) if result.accepted else None, "code": None if result.accepted else result.code,
            "boundWitnesses": [w["verifierKey"] for w in state.bound_witnesses] if state is not None else None,
            "boundPolicy": (dict(state.bound_policy) if state.bound_policy is not None else None) if state is not None else None,
            "nextKeyDigests": (list(epochs[-1]["nextKeyDigests"]) if epochs and "nextKeyDigests" in epochs[-1] else None) if state is not None else None,
            # Format 2 (SPEC-IRONTRELLIS-CORE-v2 §17): null unless the history is format 2 and accepted; this package reads formats 0.2 and 1 only.
            "stateRoot": None, "projectionHead": None,
        }
    if op == "verify-attestation":
        # An owner head attestation against the history: signed by an owner key in force at its position, and a prefix of the history.
        result = replay(revive(request.get("events")))
        if not result.accepted:
            raise ValueError(f"history rejected: {result.code}")
        state, attestation = result.state, request.get("attestation")
        head = attestation.get("head") if isinstance(attestation, dict) else None
        position = head.get("position") if isinstance(head, dict) else None
        signature_valid = verify_head_attestation_at(attestation, state)
        prefix = (isinstance(position, int) and not isinstance(position, bool) and 0 <= position <= state.head["position"]
                  and state.event_history_hashes[position] == head.get("hash"))
        # Format 2 also binds the attested stateRoot and projectionHead; both are true for the formats this package reads.
        return {"valid": signature_valid and prefix, "signatureValid": signature_valid, "prefix": prefix, "stateRootValid": True, "projectionValid": True}
    if op == "authorize":
        body = {key: request[key] for key in ("operationVersion", "events", "expectedHistoryHead", "domain", "policyVersion", "rootRecognitionPolicy",
                                              "request", "evaluationTime", "authoritative", "consequential", "binding") if key in request}
        result = authorize_portable(revive(body))
        return {
            "decision": result["decision"], "code": result.get("code"), "scopeAssurance": result.get("scopeAssurance"),
            "controllingAuthorityIds": to_plain(result["proof"]["controllingAuthorityIds"]) if result["decision"] == "ALLOW" else None,
            "failureCodes": [failure["code"] for failure in result.get("failures", [])],
            "budgetId": None,  # format-2 budgets decide nothing in formats 0.2 and 1
        }
    if op == "survives":
        result = survives_portable(request.get("operationVersion"), revive(request.get("events")), request.get("targetAgentId"), request.get("evaluationTime"))
        if not result.established or result.answer is None:
            return {"established": False, "code": result.code, "epistemicStatus": result.epistemic_status}
        answer = result.answer
        return {
            "established": True, "exists": answer["exists"], "lifecycleStatus": answer["lifecycleStatus"],
            "obligationIds": sorted(row["obligationId"] for row in answer["obligations"]),
            "currentAssignments": [{"obligationId": row["obligationId"], "assigneeId": row["assigneeId"], "successionRuleId": row.get("successionRuleId")}
                                   for row in answer["currentPerformanceAssignments"]],
            "currentRoleTenureCount": len(answer["currentRoleTenures"]), "transferredRoleTenureCount": len(answer["transferredRoleTenures"]),
            "invalidatedAuthorityIds": sorted(row["authorityId"] for row in answer["invalidatedAuthorityDependencies"]),
            "unresolvedIntentIds": sorted(row["intentId"] for row in answer["unresolvedIntents"]),
        }
    raise ValueError(f"unsupported op: {op}")


def main() -> None:
    # The protocol is UTF-8 with LF line ends on every platform; Windows would otherwise decode the pipe with the ANSI
    # code page and write CRLF.
    for stream in (sys.stdin, sys.stdout):
        stream.reconfigure(encoding="utf-8", newline="\n")  # type: ignore[union-attr]
    for line in sys.stdin:
        if line.strip() == "":
            continue
        try:
            # json_loads reads `-0` as JavaScript does (negative zero, refused as a U53), as the TypeScript adapter sees it (fuzz F4).
            response = {"ok": True, "result": handle(json_loads(line))}
        except Exception as error:  # a broken adapter reports, never crashes the runner
            response = {"ok": False, "error": f"{type(error).__name__}: {error}"[:500]}
        sys.stdout.write(json.dumps(response, separators=(",", ":"), allow_nan=False) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
