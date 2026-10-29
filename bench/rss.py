#!/usr/bin/env python3
"""Runs a command and prints one JSON line: wall time, exit status and the peak
resident set size of the child (``os.wait4`` rusage, so it is the child's own
peak, not this wrapper's). Used by ``bench/run.mjs`` for the CLI cold-start and
the Python verifier, where the process under test is not a Node child the
benchmark can instrument.

    python3 bench/rss.py [--stdin FILE] -- <command> [args...]
"""
import json
import os
import subprocess
import sys
import time


def main() -> int:
    argv = sys.argv[1:]
    stdin_path = None
    if len(argv) >= 2 and argv[0] == "--stdin":
        stdin_path, argv = argv[1], argv[2:]
    if argv[:1] == ["--"]:
        argv = argv[1:]
    if not argv:
        print("usage: rss.py [--stdin FILE] -- command [args...]", file=sys.stderr)
        return 2
    stdin = open(stdin_path, "rb") if stdin_path else subprocess.DEVNULL
    started = time.perf_counter()
    child = subprocess.Popen(argv, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = b"", b""
    # Drain the pipes ourselves (communicate() would reap the child and lose its rusage).
    import threading
    chunks = {"out": [], "err": []}
    def drain(stream, key):
        for block in iter(lambda: stream.read(65536), b""):
            chunks[key].append(block)
    threads = [threading.Thread(target=drain, args=(child.stdout, "out")), threading.Thread(target=drain, args=(child.stderr, "err"))]
    for thread in threads:
        thread.start()
    _, status, usage = os.wait4(child.pid, 0)
    elapsed = (time.perf_counter() - started) * 1000
    for thread in threads:
        thread.join()
    out, err = b"".join(chunks["out"]), b"".join(chunks["err"])
    # ru_maxrss is KiB on Linux, bytes on macOS.
    maxrss = usage.ru_maxrss if sys.platform != "darwin" else usage.ru_maxrss // 1024
    code = os.waitstatus_to_exitcode(status) if hasattr(os, "waitstatus_to_exitcode") else status >> 8
    # A digest of the output with timing fields removed: the before/after differential check compares it.
    text = out.decode("utf-8", "replace")
    stable = "\n".join(line for line in text.splitlines() if "Milliseconds" not in line and "durationMs" not in line)
    import hashlib
    print(json.dumps({"ms": elapsed, "maxRssKiB": maxrss, "code": code, "stdoutDigest": hashlib.sha256(stable.encode()).hexdigest(),
                      "stdoutTail": out[-400:].decode("utf-8", "replace"), "stderrTail": err[-400:].decode("utf-8", "replace")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
