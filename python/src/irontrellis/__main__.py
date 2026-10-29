"""``python -m irontrellis verify|authorize|survives <history>`` and ``verify-receipt <receipt.json>``.

The history commands read a history in either store format (``.jsonl``, chain
verified) or a plain event array (``.json``), replay it and print a JSON report.
``verify-receipt`` checks a remote witness receipt (its signed checkpoint, the
entry and the inclusion proof) against the witness verifier keys you trust.
Every decision reads captured data; nothing here executes anything.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any

from .authority import AUTHORIZATION_VERSION, authorize_state
from .canonical import BigInt, json_loads, to_plain
from .replay import replay
from .store import StoreError, load_events, replay_history
from .survives import derive_survives
from .transparency import bound_policy_of, bound_witnesses_of, encode_base64, verify_witness_receipt


def _utf8_output() -> None:
    """The reports are JSON, which is UTF-8 (RFC 8259) whatever the console: on Windows, Python would otherwise encode
    stdout with the ANSI code page and fail on the first identifier outside it."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8")
            except (OSError, ValueError):  # a stream that is already in use or detached keeps its encoding
                pass


def _emit(value: Any) -> None:
    sys.stdout.write(json.dumps(to_plain(value), indent=2, ensure_ascii=False) + "\n")


def _replayed(path: str) -> tuple[Any, dict[str, Any]]:
    """Replays the history. A JSONL store is read and replayed line by line, exactly as the TypeScript store reads it, so
    the defect reported is the first one in file order (a record defect is an ERROR, a replay rejection REJECTED)."""
    started = time.perf_counter()
    if path.endswith(".json"):
        facts: dict[str, Any] = {"store": None}
        result = replay(load_events(path))
    else:
        stored, result = replay_history(path)
        facts = {"store": {"format": stored.format, "records": len(stored.record_hashes), "lastRecordHash": stored.record_hashes[-1] if stored.record_hashes else None}}
    facts["replayMilliseconds"] = round((time.perf_counter() - started) * 1000, 1)
    if not result.accepted:
        _emit({"status": "REJECTED", "code": result.code, "position": result.position, "reason": result.reason, **facts})
        sys.exit(1)
    return result, facts


def cmd_verify(args: argparse.Namespace) -> int:
    result, facts = _replayed(args.history)
    state = result.state
    bound = bound_witnesses_of(state)
    notes: list[str] = []
    if bound:
        # Same code as the TypeScript core's synchronous verify: the history names remote witnesses this check did not ask.
        notes.append(f"REMOTE_WITNESS_NOT_CONSULTED: {len(bound)} remote witness(es) are bound in this history but were not asked: this verifier does not speak "
                     "the witness protocol, so a restored older copy is not ruled out; verify with the witnesses (irontrellis verify) for that")
    _emit({
        "status": "ACCEPTED", "format": state.format, "head": state.head, "eventCount": result.event_count, "chain": "OK",
        "agents": sorted(state.agents), "authorities": len(state.authorities), "anchors": [{"head": a.head, "anchor": a.anchor, "eventId": a.event_id} for a in state.anchors],
        # The owner-signed policy minimum the newest binding records ({quorum, requireOnOpen, maxUnwitnessedEvents}; null without one).
        "witnessBindings": bound, "witnessPolicyMinimum": bound_policy_of(state), "notes": notes,
        **facts,
    })
    return 0


def cmd_authorize(args: argparse.Namespace) -> int:
    result, facts = _replayed(args.history)
    state = result.state
    request: dict[str, Any] = {"actorId": args.actor, "action": args.action, "resource": args.resource, "claimedAt": args.at if args.at is not None else state.head["canonicalTime"]}
    if args.amount is not None:
        request["amount"] = BigInt(int(args.amount))
    if args.counterparty is not None:
        request["counterpartyId"] = args.counterparty
    body = {
        "expectedHistoryHead": state.head, "domain": state.genesis["domain"], "policyVersion": state.genesis["policyVersion"],
        "rootRecognitionPolicy": state.genesis["rootRecognitionPolicy"], "request": request,
        "evaluationTime": args.at if args.at is not None else state.head["canonicalTime"], "consequential": False,
    }
    decision = authorize_state(state, body)
    out: dict[str, Any] = {"operationVersion": AUTHORIZATION_VERSION, "decision": decision["decision"], "code": decision.get("code"), "scopeAssurance": decision["scopeAssurance"],
                           "controllingAuthorityIds": decision["proof"]["controllingAuthorityIds"] if decision["decision"] == "ALLOW" else None,
                           "failureCodes": [f["code"] for f in decision.get("failures", [])], "head": state.head, **facts}
    if args.full:
        out["result"] = decision
    _emit(out)
    return 0 if decision["decision"] == "ALLOW" else 2


def cmd_survives(args: argparse.Namespace) -> int:
    result, facts = _replayed(args.history)
    state = result.state
    at = args.at if args.at is not None else state.head["canonicalTime"]
    if at < state.head["canonicalTime"]:
        _emit({"established": False, "code": "CAUSAL_TIME_INVALID", **facts})
        return 2
    answer = derive_survives(state, args.agent, at)
    _emit({"established": True, "head": state.head, "answer": answer, **facts})
    return 0


def _entry_summary(entry: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {"kind": entry["kind"], "historyId": entry["historyId"], "receivedAt": entry["receivedAt"]}
    if entry["kind"] == "HEAD":
        signed = entry["signedStatement"]
        summary.update(head=signed["statement"]["head"], previous=signed["statement"]["previous"], keyId=signed["keyId"])
    elif entry["kind"] == "ROTATED":
        summary.update(previousHead=entry["previousHead"], rotationHead=entry["rotationHead"], rotationEventId=entry["rotation"].get("id"))
    elif entry["kind"] == "EQUIVOCATION":
        summary.update(position=entry["first"]["statement"]["head"]["position"],
                       heads=[entry["first"]["statement"]["head"]["hash"], entry["second"]["statement"]["head"]["hash"]])
    return summary


def cmd_verify_receipt(args: argparse.Namespace) -> int:
    try:
        with open(args.receipt, encoding="utf-8") as handle:
            document = json_loads(handle.read())  # as JSON.parse reads it: `-0` stays negative zero
    except (ValueError, RecursionError) as error:
        _emit({"status": "ERROR", "error": f"{args.receipt} is not JSON: {error}"})
        return 1
    # A witness response ({"receipt": …} or {"latest": {"receipt": …}}) is accepted as well as a bare receipt.
    receipt = document
    if isinstance(document, dict) and "version" not in document:
        if isinstance(document.get("receipt"), dict):
            receipt = document["receipt"]
        elif isinstance(document.get("latest"), dict) and isinstance(document["latest"].get("receipt"), dict):
            receipt = document["latest"]["receipt"]
    result = verify_witness_receipt(receipt, args.verifier_key)
    if not result["ok"]:
        _emit({"status": "INVALID", "reason": result["reason"], "message": result["message"]})
        return 1
    checkpoint = result["checkpoint"]
    _emit({"status": "VALID", "index": result["index"], "checkpoint": {"origin": checkpoint["origin"], "size": checkpoint["size"], "root": encode_base64(checkpoint["root"])},
           "verifiedBy": result["verifiedBy"], "entry": _entry_summary(receipt["entry"])})
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m irontrellis", description="IronTrellis verifier: replay, authorize and survives over a captured history; verify witness receipts.")
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", help="replay the history and report its head")
    verify.add_argument("history")
    verify.set_defaults(run=cmd_verify)
    authorize = commands.add_parser("authorize", help="evaluate a non-consequential request at the head")
    authorize.add_argument("history")
    authorize.add_argument("--actor", required=True)
    authorize.add_argument("--action", required=True)
    authorize.add_argument("--resource", required=True)
    authorize.add_argument("--amount", help="decimal quantity for quantitative authorities")
    authorize.add_argument("--counterparty")
    authorize.add_argument("--at", type=int, help="evaluation time (defaults to the head's canonical time)")
    authorize.add_argument("--full", action="store_true", help="include the full authorization result (proof or failures)")
    authorize.set_defaults(run=cmd_authorize)
    survives = commands.add_parser("survives", help="what an agent's departure leaves behind")
    survives.add_argument("history")
    survives.add_argument("--agent", required=True)
    survives.add_argument("--at", type=int)
    survives.set_defaults(run=cmd_survives)
    receipt = commands.add_parser("verify-receipt", help="verify a remote witness receipt against trusted witness verifier keys")
    receipt.add_argument("receipt", help="a receipt JSON file (or a witness response carrying one)")
    receipt.add_argument("--verifier-key", action="append", required=True, metavar="VKEY",
                         help="a trusted witness verifier key <name>+<hash>+<key> (repeatable)")
    receipt.set_defaults(run=cmd_verify_receipt)
    args = parser.parse_args(argv)
    _utf8_output()
    try:
        return args.run(args)
    except (StoreError, OSError) as error:
        code = getattr(error, "code", None) if isinstance(error, StoreError) else None
        _emit({"status": "ERROR", "error": str(error), **({"code": code} if code is not None else {})})
        return 1


if __name__ == "__main__":
    sys.exit(main())
