#!/usr/bin/env python3
"""Persistent Python side of the IronTrellis differential fuzzer.

One JSON request per line on stdin, one JSON response per line on stdout (the
conformance adapter protocol, conformance/legacy/ADAPTER.md), so one process
serves a whole campaign. The adapter-level operations (``adapter``: replay,
authorize, survives, verify-attestation) go through the conformance adapter's
own ``handle`` (conformance/adapters/python.py) unchanged; the other operations
reach the package entry points the conformance protocol does not cover: the
direct replay (with the rejection position), the JSONL store reader, the
``python -m irontrellis`` CLI, the canonical encoder, event validation and the
witness wire formats.

Every result carries ``crash`` when the entry point raised something other
than the package's documented rejections: that is an invariant violation the
harness reports, not an answer.
"""
from __future__ import annotations

import base64
import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "python", "src"))

from irontrellis import transparency as t  # noqa: E402
from irontrellis.__main__ import main as cli_main  # noqa: E402
from irontrellis.canonical import CanonicalError, _parse_int, canonical_encode, json_loads_with_bigints, to_plain  # noqa: E402
from irontrellis.events import validate_event  # noqa: E402
from irontrellis.replay import REPLAY_VERSION, replay_portable  # noqa: E402
from irontrellis.store import StoreError, replay_history_bytes  # noqa: E402

_spec = importlib.util.spec_from_file_location("irontrellis_conformance_adapter", os.path.join(ROOT, "conformance", "adapters", "python.py"))
adapter = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(adapter)  # type: ignore[union-attr]


def crash(error: BaseException) -> dict:
    frames = traceback.extract_tb(error.__traceback__)
    where = [f"{os.path.basename(f.filename)}:{f.lineno}:{f.name}" for f in frames[-4:]]
    return {"crash": f"{type(error).__name__}: {error}"[:300], "where": where}


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def replay_outcome(events) -> dict:
    result = replay_portable(REPLAY_VERSION, events)
    if result.accepted:
        return {"status": "ACCEPTED", "head": to_plain(result.head), "eventCount": result.event_count}
    return {"status": "REJECTED", "code": result.code, "position": result.position}


def op_replay(request: dict) -> dict:
    """The direct replay of the wire events (markers left for the capture to decode), and the conformance adapter's answer."""
    out: dict = {}
    try:
        out["direct"] = replay_outcome(request["events"])
    except Exception as error:  # noqa: BLE001 - the invariant is exactly that this never happens
        out["direct"] = crash(error)
    try:
        out["adapter"] = {"ok": True, "result": adapter.handle({"op": "replay", "operationVersion": request.get("operationVersion", REPLAY_VERSION), "events": request["events"]})}
    except Exception as error:  # the adapter reports these as {"ok": false}
        out["adapter"] = {"ok": False, "error": f"{type(error).__name__}: {error}"[:200]}
    return out


def op_adapter(request: dict) -> dict:
    try:
        return {"ok": True, "result": adapter.handle(request["request"])}
    except Exception as error:
        return {"ok": False, "error": f"{type(error).__name__}: {error}"[:300]}


def op_store(request: dict) -> dict:
    """The store file as ``python -m irontrellis verify`` reads it (``replay_history_bytes``: record checks and replay, line
    by line)."""
    data = base64.b64decode(request["b64"])
    try:
        stored, result = replay_history_bytes(data)
    except StoreError as error:
        return {"layer": "store", "message": str(error)[:300]}
    except Exception as error:  # noqa: BLE001
        return crash(error)
    if result.accepted:
        return {"layer": "replay", "status": "ACCEPTED", "head": to_plain(result.head), "eventCount": result.event_count, "format": stored.format}
    return {"layer": "replay", "status": "REJECTED", "code": result.code, "position": result.position, "format": stored.format}


def op_cli(request: dict) -> dict:
    """``python -m irontrellis <argv>`` in-process; files are written to a temporary directory named by {dir}."""
    with tempfile.TemporaryDirectory(prefix="irontrellis-fuzz-py-") as directory:
        for name, content in (request.get("files") or {}).items():
            with open(os.path.join(directory, name), "wb") as handle:
                handle.write(base64.b64decode(content))
        argv = [arg.replace("{dir}", directory) for arg in request["argv"]]
        stdout, stderr = io.StringIO(), io.StringIO()
        code = None
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = cli_main(argv)
        except SystemExit as exit_:
            code = exit_.code if isinstance(exit_.code, int) else (0 if exit_.code is None else 2)
        except Exception as error:  # noqa: BLE001
            return {**crash(error), "stdout": stdout.getvalue()[:500]}
        for name, stream in (("stdout", stdout), ("stderr", stderr)):
            try:  # a real stdout is UTF-8: text a StringIO accepts (lone surrogates) would raise there
                stream.getvalue().encode("utf-8")
            except UnicodeEncodeError as error:
                return {"crash": f"UnicodeEncodeError writing {name}: {error}"[:300], "where": ["__main__.py:_emit"]}
        return {"exit": code, "stdout": stdout.getvalue()[:20000], "stderr": stderr.getvalue()[:2000]}


def op_canonical(request: dict) -> dict:
    try:
        value = json_loads_with_bigints(request["text"])
    except (ValueError, CanonicalError) as error:  # JSONDecodeError is a ValueError
        return {"ok": False, "stage": "parse", "error": type(error).__name__}
    except Exception as error:  # noqa: BLE001
        return crash(error)
    try:
        return {"ok": True, "encoded": canonical_encode(value)}
    except CanonicalError as error:
        return {"ok": False, "stage": "encode", "error": "CanonicalError", "limit": error.limit}
    except Exception as error:  # noqa: BLE001
        return crash(error)


def op_event(request: dict) -> dict:
    try:
        result = validate_event(request["event"], request["format"], request["position"])
    except Exception as error:  # noqa: BLE001
        return crash(error)
    if result.ok:
        return {"ok": True, "event": to_plain(result.event)}
    return {"ok": False, "code": result.code}


def keys_at(epochs, position):
    """The harness's key-epoch lookup, written to behave exactly like its JavaScript twin in targets/transparency.mjs."""
    keys = []
    for epoch in epochs if isinstance(epochs, list) else []:
        start = epoch.get("fromPosition") if isinstance(epoch, dict) else None
        if isinstance(start, (int, float)) and not isinstance(start, bool) and start <= position:
            keys = epoch.get("keys")
    return keys


def op_transparency(request: dict) -> dict:
    kind = request.get("kind")
    try:
        if kind == "receipt":
            r = t.verify_witness_receipt(request.get("receipt"), request.get("keys"))
            return {"ok": True, "index": r["index"], "size": r["checkpoint"]["size"], "root": b64(r["checkpoint"]["root"]), "verifiedBy": r["verifiedBy"]} \
                if r["ok"] else {"ok": False, "reason": r["reason"]}
        if kind == "note":
            try:
                opened = t.open_note(request.get("note"), request.get("keys"))
                return {"ok": True, "body": opened.body, "verifiedBy": opened.verified_by}
            except t.NoteError as error:
                return {"ok": False, "error": error.code}
        if kind == "checkpoint":
            try:
                c = t.parse_checkpoint(request.get("body"))
                return {"ok": True, "origin": c.origin, "size": c.size, "root": b64(c.root), "extensions": c.extensions}
            except t.NoteError as error:
                return {"ok": False, "error": error.code}
        if kind == "latest":
            try:
                parsed = t.parse_latest_note(request.get("body"))
                return {"ok": True, "latest": parsed}
            except t.NoteError as error:
                return {"ok": False, "error": error.code}
        if kind == "latestVerify":
            r = t.verify_latest_note(request.get("note"), request.get("keys"), request.get("expect"))
            return {"ok": True, "latest": r["latest"], "verifiedBy": r["verifiedBy"]} if r["ok"] else {"ok": False, "reason": r["reason"]}
        if kind == "statement":
            r = t.verify_signed_head_statement(request.get("signed"), lambda p: keys_at(request.get("epochs"), p))
            return {"result": "OK" if r["ok"] else r["reason"]}
        if kind == "entry":
            reason = t.validate_entry(request.get("entry"))
            return {"valid": True, "leafHash": t.entry_leaf_hash(request.get("entry")).hex()} if reason is None else {"valid": False}
        if kind == "verifierKey":
            try:
                parsed = t.parse_verifier_key(request.get("key"))
                return {"ok": True, "name": parsed.name, "keyHash": parsed.key_hash.hex(), "publicKey": parsed.public_key.hex()}
            except t.NoteError as error:
                return {"ok": False, "error": error.code}
        if kind in ("inclusion", "consistency"):
            def from_hex(text):
                if isinstance(text, str) and len(text) % 2 == 0 and all(c in "0123456789abcdef" for c in text):
                    return bytes.fromhex(text)
                return None
            # The Python building blocks take ints (and bytes), the TypeScript ones JavaScript numbers: a JSON caller
            # converts numbers with JavaScript semantics first, as verify_witness_receipt does (-0 is 0 there).
            def number(value):
                converted = t._js_integer(value)
                return value if converted is None else converted
            proof = [from_hex(p) for p in request.get("proof")] if isinstance(request.get("proof"), list) else request.get("proof")
            if kind == "inclusion":
                return {"valid": t.verify_inclusion(from_hex(request.get("leaf")), number(request.get("index")), number(request.get("size")), proof, from_hex(request.get("root")))}
            return {"valid": t.verify_consistency(number(request.get("from")), number(request.get("to")), from_hex(request.get("fromRoot")), from_hex(request.get("toRoot")), proof)}
        if kind == "base64":
            decoded = t.decode_base64(request.get("text"))
            return {"ok": decoded is not None, **({} if decoded is None else {"hex": decoded.hex()})}
        return {"unsupported": kind}
    except Exception as error:  # noqa: BLE001
        return crash(error)


OPS = {"replay": op_replay, "adapter": op_adapter, "store": op_store, "cli": op_cli, "canonical": op_canonical, "event": op_event, "transparency": op_transparency}


def main() -> None:
    sys.setrecursionlimit(max(sys.getrecursionlimit(), 1000))
    # UTF-8 with LF line ends on every platform (Windows would decode the pipe with the ANSI code page and write CRLF).
    for stream in (sys.stdin, sys.stdout):
        stream.reconfigure(encoding="utf-8", newline="\n")  # type: ignore[union-attr]
    for line in sys.stdin:
        if line.strip() == "":
            continue
        try:
            request = json.loads(line, parse_int=_parse_int)  # `-0` is JavaScript's -0 (the harness sends it faithfully)
            op = OPS.get(request.get("op"))
            response = {"ok": True, "result": op(request) if op else {"unsupported": request.get("op")}}
        except Exception as error:  # noqa: BLE001 - the worker itself must survive
            response = {"ok": False, "error": f"{type(error).__name__}: {error}"[:500]}
        try:
            text = json.dumps(response, separators=(",", ":"), allow_nan=False)
        except ValueError as error:
            text = json.dumps({"ok": False, "error": f"unencodable response: {error}"})
        sys.stdout.write(text + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
