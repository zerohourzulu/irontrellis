"""Line endings and encodings as a Windows machine produces them (docs/PLATFORMS.md §5), with the same verdicts as the
TypeScript store (packages/core/test/platform.test.mjs): a history converted to CRLF replays to the same state (the
record hash covers the canonical encoding, not the bytes), a UTF-8 byte order mark is refused and named, and the CLI
writes its JSON report as UTF-8 whatever the console encoding."""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from conftest import CONFORMANCE, PYTHON_ROOT
from irontrellis.store import StoreError, replay_history_bytes

HISTORIES = sorted((CONFORMANCE / "v1" / "histories").glob("*.jsonl"))


@pytest.mark.parametrize("path", HISTORIES, ids=[path.name for path in HISTORIES])
def test_crlf_history_replays_to_the_same_state(path):
    lf = path.read_bytes()
    assert b"\r" not in lf, "the fixture itself must be LF (see .gitattributes)"
    crlf = lf.replace(b"\n", b"\r\n")
    stored, result = replay_history_bytes(lf)
    stored_crlf, result_crlf = replay_history_bytes(crlf)
    assert result_crlf.status == result.status
    assert stored_crlf.record_hashes == stored.record_hashes
    if result.accepted:
        assert result_crlf.head == result.head


def test_a_changed_value_is_still_caught_and_a_byte_order_mark_is_named():
    lf = HISTORIES[0].read_bytes()
    first, rest = lf.split(b"\n", 1)
    # A CR inside a string value is content: the record hash no longer matches.
    changed = first.replace(b'"version":"irontrellis-event/1"', b'"version":"irontrellis-event/1\\r"', 1)
    if changed != first:
        with pytest.raises(StoreError):
            replay_history_bytes(changed + b"\n" + rest)
    with pytest.raises(StoreError, match="byte order mark"):
        replay_history_bytes(b"\xef\xbb\xbf" + lf)


def test_cli_report_is_utf8_whatever_the_console_encoding(tmp_path):
    history = HISTORIES[0]
    env = {**os.environ, "PYTHONIOENCODING": "cp1252", "PYTHONUTF8": "0"}
    run = subprocess.run([sys.executable, "-m", "irontrellis", "verify", str(history)], cwd=PYTHON_ROOT / "src", capture_output=True, env=env, check=False)
    assert run.returncode == 0, run.stderr.decode("utf-8", "replace")
    report = json.loads(run.stdout.decode("utf-8"))
    assert report["status"] == "ACCEPTED"


def test_emit_writes_utf8_to_a_stream_opened_with_a_legacy_code_page(monkeypatch):
    import io

    from irontrellis import __main__ as cli

    out, err = io.BytesIO(), io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(out, encoding="cp1252"))
    monkeypatch.setattr(sys, "stderr", io.TextIOWrapper(err, encoding="cp1252"))
    cli._utf8_output()
    cli._emit({"agent": "агент:1", "note": "ω"})  # neither is in cp1252: this raised UnicodeEncodeError before
    sys.stdout.flush()
    assert json.loads(out.getvalue().decode("utf-8")) == {"agent": "агент:1", "note": "ω"}
