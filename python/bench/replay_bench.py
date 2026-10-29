#!/usr/bin/env python3
"""Times the Python verifier: store read, replay and one authorize per history.

    python3 python/bench/replay_bench.py [history.jsonl ...]

Defaults to the 26-event legacy handover fixture and python/bench/large-v1.jsonl
(generate it with `node python/bench/generate-large.mjs`). `--pure` disables the
optional `cryptography` accelerator so the pure-Python Ed25519 path is measured.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from irontrellis import read_history, replay  # noqa: E402
from irontrellis.authority import authorize_state  # noqa: E402


def bench(path: Path) -> None:
    started = time.perf_counter()
    stored = read_history(str(path))
    read_ms = (time.perf_counter() - started) * 1000
    started = time.perf_counter()
    result = replay(stored.events)
    replay_ms = (time.perf_counter() - started) * 1000
    assert result.accepted, result
    state = result.state
    actor = sorted(state.agents)[0] if state.agents else "nobody"
    body = {"expectedHistoryHead": state.head, "domain": state.genesis["domain"], "policyVersion": state.genesis["policyVersion"],
            "rootRecognitionPolicy": state.genesis["rootRecognitionPolicy"], "request": {"actorId": actor, "action": "read", "resource": "resource-0", "claimedAt": state.head["canonicalTime"]},
            "evaluationTime": state.head["canonicalTime"], "consequential": False}
    started = time.perf_counter()
    first = authorize_state(state, body)
    first_ms = (time.perf_counter() - started) * 1000
    started = time.perf_counter()
    for _ in range(20):
        authorize_state(state, body)
    warm_ms = (time.perf_counter() - started) * 1000 / 20
    controls = sum(1 for e in stored.events if "controlAuthorization" in e["data"])
    print(f"{path.name}: {len(stored.events)} events ({stored.format}, {controls} owner-signed) read {read_ms:.0f} ms, replay {replay_ms:.0f} ms "
          f"({replay_ms / len(stored.events):.2f} ms/event), authorize first {first_ms:.1f} ms (corpus build), warm {warm_ms:.2f} ms → {first['decision']}")


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if "--pure" in sys.argv:
        import irontrellis.crypto.ed25519 as ed
        ed._FastPublicKey = None
        print("ed25519: pure Python")
    else:
        import irontrellis.crypto.ed25519 as ed
        print("ed25519:", "cryptography (OpenSSL)" if ed._FastPublicKey is not None else "pure Python")
    paths = [Path(a) for a in args] or [HERE.parent.parent / "packages" / "reference-0.2" / "tests" / "fixtures" / "handover-history.jsonl", HERE / "large-v1.jsonl"]
    for path in paths:
        if path.exists():
            bench(path)
        else:
            print(f"{path}: missing (node python/bench/generate-large.mjs)")


if __name__ == "__main__":
    main()
