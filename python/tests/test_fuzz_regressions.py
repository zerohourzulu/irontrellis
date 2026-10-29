"""The fuzzer's regression vectors (fuzz/regressions/**), replayed against the Python implementation alone.

Each vector pins the verdict the TypeScript engine gives (and, since the fuzzer's fixes, the Python one): the
store reader's layer, code and position, the event validator's code, the canonical encoder's acceptance, the latest-note
verifier's reason. The fuzz harness (``node fuzz/run.mjs --regressions``) checks both engines against each other; this
module keeps the Python side of every fix covered where no Node is available. It also covers, directly, the Python
entry points those fixes touched (the CLI on malformed and deeply nested input).
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys

import pytest
from conftest import CORE_DIST, NODE, PYTHON_ROOT, REPO_ROOT

from irontrellis import CanonicalError, StoreError, load_events, replay, replay_history_bytes
from irontrellis import transparency as t
from irontrellis.canonical import canonical_encode, json_loads, json_loads_with_bigints
from irontrellis.events import validate_event

REGRESSIONS = REPO_ROOT / "fuzz" / "regressions"
VECTORS = sorted(REGRESSIONS.glob("*/*.json")) if REGRESSIONS.exists() else []


def _vector(path):
    with open(path, encoding="utf-8") as handle:
        return json_loads(handle.read())  # as the harness reads them: `-0` stays negative zero


def _file_bytes(spec) -> bytes:
    return spec["text"].encode("utf-8") if "text" in spec else base64.b64decode(spec["b64"])


def _reader(data: bytes) -> dict:
    """The store reader's verdict in the harness's vocabulary (fuzz/targets/store.mjs `readerView`)."""
    try:
        _, result = replay_history_bytes(data)
    except StoreError:
        return {"layer": "store"}
    if result.accepted:
        return {"layer": "replay", "status": "ACCEPTED"}
    return {"layer": "replay", "status": "REJECTED", "code": result.code, "position": result.position}


def _project(expected, actual):
    """The fields ``expected`` names, from ``actual`` (a projection, as the conformance runner compares)."""
    if isinstance(expected, dict) and isinstance(actual, dict):
        return {key: _project(value, actual.get(key)) for key, value in expected.items()}
    return actual


@pytest.mark.skipif(not VECTORS, reason="fuzz/regressions is not present")
@pytest.mark.parametrize("path", VECTORS, ids=[f"{p.parent.name}/{p.stem}" for p in VECTORS])
def test_regression_vector(path):
    vector = _vector(path)
    target, data, expect = vector["target"], vector["input"], vector.get("expect", {})
    if target == "canonical":
        try:
            canonical_encode(json_loads_with_bigints(data["text"]))
            ok = True
        except (ValueError, CanonicalError):
            ok = False
        assert ok == expect["ts"]["ok"], vector["id"]
    elif target == "events":
        result = validate_event(data["event"], data["format"], data["position"])
        got = {"ok": result.ok, "code": None if result.ok else result.code}
        assert _project(expect["ts"], got) == expect["ts"], vector["id"]
    elif target == "replay":
        result = replay(data["events"])
        got = {"status": result.status, "code": result.code, "position": result.position}
        assert _project(expect["ts"], got) == expect["ts"], vector["id"]
    elif target == "store":
        if "reader" in expect:
            got = _reader(_file_bytes(data["files"]["history.jsonl"]))
            assert _project(expect["reader"], got) == expect["reader"], vector["id"]
    elif target == "transparency":
        if data["kind"] == "receipt":
            result = t.verify_witness_receipt(data["receipt"], data["keys"])
            got = {"ok": result["ok"], **({} if result["ok"] else {"reason": result["reason"]})}
            assert _project(expect["ts"], got) == expect["ts"], vector["id"]
        if data["kind"] == "latestVerify":
            result = t.verify_latest_note(data["note"], data["keys"], data["expect"])
            got = {"ok": result["ok"], **({} if result["ok"] else {"reason": result["reason"]})}
            assert _project(expect["ts"], got) == expect["ts"], vector["id"]
    else:
        pytest.skip(f"no Python check for target {target}")


def test_deep_json_is_a_typed_rejection_everywhere(tmp_path):
    deep = "[" * 50_000 + "0" + "]" * 50_000
    with pytest.raises(CanonicalError):
        json_loads_with_bigints(deep)
    line = '{"version":"irontrellis-portable-file-store/1","previousHash":null,"event":' + deep + ',"recordHash":"0x00"}\n'
    with pytest.raises(StoreError):
        replay_history_bytes(line.encode())
    history = tmp_path / "deep.json"
    history.write_text(deep, encoding="utf-8")
    with pytest.raises(StoreError):
        load_events(str(history))


@pytest.mark.parametrize("content", ["[" * 50_000 + "]" * 50_000, "{not json", '[{"$continuity.bigint":"01"}]'])
def test_cli_verify_reports_unreadable_json_histories(tmp_path, content):
    history = tmp_path / "history.json"
    history.write_text(content, encoding="utf-8")
    run = subprocess.run([sys.executable, "-m", "irontrellis", "verify", str(history)], capture_output=True, text=True, encoding="utf-8", cwd=PYTHON_ROOT / "src", timeout=120)
    assert run.returncode == 1, run.stderr
    assert "Traceback" not in run.stderr
    assert json.loads(run.stdout)["status"] == "ERROR"


def test_negative_zero_is_not_the_integer_zero():
    with pytest.raises(CanonicalError):
        canonical_encode(json_loads_with_bigints('{"a":-0}'))
    assert canonical_encode(json_loads_with_bigints('{"a":0,"b":-1,"c":5.0}')) == '{"a":0,"b":-1,"c":5}'


def test_cli_verify_receipt_reads_negative_zero_like_javascript(tmp_path):
    vector = _vector(REGRESSIONS / "transparency" / "receipt-negative-zero-position.json") if VECTORS else None
    if vector is None:
        pytest.skip("fuzz/regressions is not present")
    path = tmp_path / "receipt.json"
    # The literal -0 (json.dumps writes the vector's -0.0 as "-0.0", which any JSON reader keeps negative).
    text = json.dumps(vector["input"]["receipt"]).replace('"position": -0.0', '"position": -0', 1)
    assert '"position": -0,' in text or '"position": -0}' in text
    path.write_text(text, encoding="utf-8")
    run = subprocess.run([sys.executable, "-m", "irontrellis", "verify-receipt", str(path), "--verifier-key", vector["input"]["keys"][0]],
                         capture_output=True, text=True, encoding="utf-8", cwd=PYTHON_ROOT / "src", timeout=120)
    assert run.returncode == 1 and json.loads(run.stdout)["reason"] == "ENTRY_MALFORMED", run.stdout


# ---------------------------------------------------------------- review block 3, M1: the library read API
# A format-1 store file (irontrellis-portable-file-store/1 lines, sha256 chain) carrying the legacy reference history,
# which has no owner signatures. The TypeScript store and replay_history reject it at position 0 (EVENT_DATA_INVALID).
# `replay(read_history(p).events)` and `replay(load_events(p))` (the rc.1 README quickstart) used to ACCEPT it, because
# `replay` picks its rules from the genesis. Every reader now refuses the file with the same code and position.


def _legacy_in_format1(tmp_path):
    if not VECTORS:
        pytest.skip("fuzz/regressions is not present")
    vector = _vector(REGRESSIONS / "store" / "legacy-history-in-format-1-file.json")
    data = _file_bytes(vector["input"]["files"]["history.jsonl"])
    assert data.startswith(b'{"version":"irontrellis-portable-file-store/1"') or b'"irontrellis-portable-file-store/1"' in data.split(b"\n", 1)[0]
    path = tmp_path / "history.jsonl"
    path.write_bytes(data)
    return path, data, vector


def _format1_genesis_in_legacy_lines(tmp_path):
    """The reverse mismatch: a format-1 history re-encoded as legacy lines (tagged tuples, keccak chain)."""
    from irontrellis import LEGACY_FORMAT, hash_canonical, read_history
    from irontrellis.events import hash_algorithm_of
    from irontrellis.store import LINE_VERSIONS, encode_tagged

    events = read_history(str(REPO_ROOT / "conformance" / "v1" / "histories" / "handover-v1.jsonl")).events
    version, previous, lines = LINE_VERSIONS[LEGACY_FORMAT], None, []
    for event in events:
        record_hash = hash_canonical({"version": version, "previousHash": previous, "event": event}, hash_algorithm_of(LEGACY_FORMAT))
        lines.append(json.dumps({"version": version, "previousHash": previous, "event": encode_tagged(event), "recordHash": record_hash}, separators=(",", ":")))
        previous = record_hash
    path = tmp_path / "history.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _entry_points(path):
    from irontrellis import read_history, read_history_text
    return {
        "read_history": lambda: read_history(str(path)),
        "read_history_text": lambda: read_history_text(path.read_text("utf-8")),
        "load_events": lambda: load_events(str(path)),
        "replay(read_history(p).events)": lambda: replay(read_history(str(path)).events),
        "replay(load_events(p))": lambda: replay(load_events(str(path))),
    }


def test_review_m1_poc_every_reader_rejects_legacy_history_in_format1_file(tmp_path):
    """The review's PoC (/tmp/review-b3/poc/py-loadevents.py), on the regression vector's own file."""
    from irontrellis import HistoryRejected, replay_history

    path, data, vector = _legacy_in_format1(tmp_path)
    expected = vector["expect"]["reader"]
    assert expected["code"] == "EVENT_DATA_INVALID" and expected["position"] == 0
    _, result = replay_history(str(path))
    assert (result.status, result.code, result.position) == ("REJECTED", "EVENT_DATA_INVALID", 0)
    for name, call in _entry_points(path).items():
        with pytest.raises(HistoryRejected) as caught:
            call()
        assert (caught.value.code, caught.value.position) == (expected["code"], expected["position"]), name
        assert caught.value.reason == result.reason, name
        assert isinstance(caught.value, StoreError), name  # callers catching StoreError keep working


def test_review_m1_reverse_mismatch_is_rejected_like_replay_history(tmp_path):
    from irontrellis import HistoryRejected, replay_history

    path = _format1_genesis_in_legacy_lines(tmp_path)
    _, result = replay_history(str(path))
    assert (result.status, result.code, result.position) == ("REJECTED", "EVENT_DATA_INVALID", 0)
    for name, call in _entry_points(path).items():
        with pytest.raises(HistoryRejected) as caught:
            call()
        assert (caught.value.code, caught.value.position, caught.value.reason) == (result.code, 0, result.reason), name


def test_review_m1_genesis_rejection_comes_before_a_later_record_defect(tmp_path):
    """File order, as the TypeScript store reports it: the genesis (position 0) is rejected before line 3 is read."""
    from irontrellis import HistoryRejected, read_history_text

    _, data, _ = _legacy_in_format1(tmp_path)
    lines = data.decode("utf-8").split("\n")
    broken = "\n".join([*lines[:2], lines[2].replace('"recordHash":"0x', '"recordHash":"0xff', 1), *lines[3:]])
    assert broken != data.decode("utf-8")
    with pytest.raises(HistoryRejected) as caught:
        read_history_text(broken)
    assert (caught.value.code, caught.value.position) == ("EVENT_DATA_INVALID", 0)


@pytest.mark.skipif(NODE is None or not CORE_DIST.exists(), reason="node or the built core is not available")
@pytest.mark.parametrize("which", ["legacy-in-format1", "format1-in-legacy-lines"])
def test_review_m1_typescript_store_agrees(tmp_path, which):
    from irontrellis import HistoryRejected, read_history

    path = _legacy_in_format1(tmp_path)[0] if which == "legacy-in-format1" else _format1_genesis_in_legacy_lines(tmp_path)
    script = ("import { openHistoryStore } from " + json.dumps(CORE_DIST.as_uri()) + ";"
              "try { openHistoryStore(process.argv[1], { allowUnpinned: true }).state(); console.log('OPENED'); }"
              "catch (error) { console.log(error.message); }")
    run = subprocess.run([NODE, "--input-type=module", "-e", script, str(path)], capture_output=True, text=True, encoding="utf-8", timeout=120)
    with pytest.raises(HistoryRejected) as caught:
        read_history(str(path))
    assert run.stdout.strip() == f"history rejected at position {caught.value.position}: {caught.value.code} ({caught.value.reason})", run.stdout + run.stderr
