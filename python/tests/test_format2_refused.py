"""Format 2 (``irontrellis-event/2``) is frozen out of this package: a format-2 genesis is refused with UNSUPPORTED_VERSION."""
from __future__ import annotations

import json
import subprocess
import sys

import pytest
from conftest import CONFORMANCE, PYTHON_ROOT, load_json

from irontrellis import StoreError, from_plain, read_history_text, replay
from irontrellis.canonical import canonical_encode, json_loads_with_bigints
from irontrellis.hashing import hash_canonical
from irontrellis.store import HistoryRejected, replay_history_bytes

FORMAT2_HISTORY = CONFORMANCE / "v2" / "histories" / "budget-v2.json"
FORMAT2_STORE = CONFORMANCE / "v2" / "histories" / "budget-v2.jsonl"
needs_v2 = pytest.mark.skipif(not FORMAT2_HISTORY.exists(), reason="conformance/v2 is not present")


def _format2_genesis():
    return load_json(FORMAT2_HISTORY)[0]


@needs_v2
def test_format2_genesis_is_refused_with_unsupported_version():
    genesis = _format2_genesis()
    assert genesis["data"]["versions"]["eventSchemaVersion"] == "irontrellis-event/2"
    result = replay([from_plain(genesis)])
    assert result.status == "REJECTED"
    assert result.code == "UNSUPPORTED_VERSION"
    assert result.position == 0


@needs_v2
def test_whole_format2_history_is_refused_at_position_0():
    result = replay(from_plain(load_json(FORMAT2_HISTORY)))
    assert (result.status, result.code, result.position) == ("REJECTED", "UNSUPPORTED_VERSION", 0)


@needs_v2
def test_format2_store_lines_are_an_unsupported_version():
    with pytest.raises(StoreError) as caught:
        replay_history_bytes(FORMAT2_STORE.read_bytes())
    assert caught.value.code == "UNSUPPORTED_VERSION"


@needs_v2
def test_format2_genesis_in_format1_lines_is_refused_with_unsupported_version():
    version = "irontrellis-portable-file-store/1"
    event = json_loads_with_bigints(json.dumps(_format2_genesis()))
    record_hash = hash_canonical({"version": version, "previousHash": None, "event": event}, "sha256")
    data = canonical_encode({"version": version, "previousHash": None, "event": event, "recordHash": record_hash}) + "\n"
    with pytest.raises(HistoryRejected) as caught:
        read_history_text(data)
    assert (caught.value.code, caught.value.position) == ("UNSUPPORTED_VERSION", 0)
    _, result = replay_history_bytes(data.encode("utf-8"))
    assert (result.status, result.code, result.position) == ("REJECTED", "UNSUPPORTED_VERSION", 0)


@needs_v2
@pytest.mark.parametrize("path", [FORMAT2_HISTORY, FORMAT2_STORE], ids=["json", "jsonl"])
def test_cli_verify_reports_unsupported_version(path):
    run = subprocess.run([sys.executable, "-m", "irontrellis", "verify", str(path)], capture_output=True, text=True, encoding="utf-8",
                         cwd=PYTHON_ROOT / "src", timeout=120)
    assert run.returncode == 1
    report = json.loads(run.stdout)
    assert report["code"] == "UNSUPPORTED_VERSION"
    if path.suffix == ".json":
        assert (report["status"], report["position"]) == ("REJECTED", 0)
    else:
        assert report["status"] == "ERROR"
