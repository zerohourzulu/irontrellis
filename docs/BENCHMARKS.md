# Benchmarks

IronTrellis (formerly Continuity) checks a history whenever it reads one: every signature, every hash, every event's rules. This page records what that costs, as measured on named machines on known dates.

There are two sets of numbers. The **format-2** set was measured on the 1.0.0-rc.2 engine on 12 October 2026. The **September 2026** sets measured legacy and format-1 implementations; they are kept as historical evidence, not relabelled as current performance. No benchmark has been run since October 12.

## One check, in numbers

A coding agent asks to write a file. The IronTrellis hook opens the history and checks the call against the agent's grants. Its budget is 20 ms; on a 10,000-event history it took 871 ms.

The hook never replayed the history from the start (0 of 14 checks did). It resumed from a saved snapshot, and the cost is that resume: it recomputes every leaf of the state root from the snapshot's records, and the format forbids trusting a saved root instead. Meeting 20 ms at this size needs a format change or a hook process that stays running between tool calls.

## Format 2 on the 1.0.0-rc.2 engine

Measured on 12 October 2026: Intel Xeon @ 2.80 GHz, 2 vCPU, no SHA-NI, Firecracker VM, ext4 on virtio, Node v22.22.2. Medians of 7 runs over one 10,000-event history (13,552 state records, 12,466,632 bytes), except three rows: the append is the median of 21 appends, the incremental update of 100 changed records, and the rollover of 101 calls. The command:

```sh
node --experimental-strip-types packages/core/bench/budgets.mjs --events 10000 --runs 7 --dir <dir>
```

The code was development commit `e2991bf`, which predates this repository's history; its engine is that of `c240673`, and `e2991bf` changed only the benchmark script. A budget is an engineering target, not a service-level promise.

| Path | Budget | Measured | Result |
| --- | --- | --- | --- |
| Control-event append at 10,000 events, fsync on, signer latency excluded | ≤ 5 ms | 4.10 ms | met |
| Hook `PreToolUse` check (one budget, two cases) | ≤ 20 ms | 871 ms with the snapshot at the head; 1,182 ms with 256 events after the snapshot's signed root | **missed** |
| Full replays during those hook checks | never with a valid snapshot | 0 of 14 | met |
| Full replay (`core.replay`) | ≤ 0.30 ms/event | 0.562 ms/event | **missed** |
| State root from scratch, 12,000 records | ≤ 5 ms | 173.1 ms | **missed** |
| Incremental root update, one record changed | ≤ 0.1 ms | 0.0501 ms | met |
| Export view, last 1,000 events, both ends cold | ≤ 80 ms | 44.6 ms | met |
| Budget rollover at period 1,000,000 | ≤ 0.1 ms | 0.0062 ms | met |

**Of eight budgets, five are met and three are missed:** the hook check (in both cases), the full replay, and a state root from scratch. Each path keeps every validation step; no check was weakened to save time.

Ed25519 signature checks alone take about 0.17 ms per event of the full replay; a state root from scratch spends about 4.4 ms on the tree and the rest on each record's canonical text and two SHA-256 hashes, on a CPU without SHA-NI.

Later engine changes, including later owner-approval-policy work, were not re-measured, so these figures describe commit `e2991bf`, not every later commit.

## Historical sets: legacy and format 1

| Measurement set | Machine and method | Retained result |
| --- | --- | --- |
| 2026-09-24 microbenchmarks | 2 vCPU Xeon 2.10 GHz, 7 GiB RAM, Linux 6.18, ext4 virtual disk; Node 22.22.2 sources, Python 3.11.15. Shared machine; the report asks readers to treat figures as approximately ±20%. | Format-1 replay at 10,000 events: 2.1–2.3 s; warm authorization: 16–20 µs. These measure distinct operations. |
| 2026-09-26 scale study | 2 vCPU Xeon 2.10 GHz, 8 GiB RAM, 5.8 GiB process memory cgroup; Node 22.22.2 built packages; fresh child processes. Median of three runs unless a row says otherwise. | Format-1 open: 1.57 s at 10,000 events, 12.9 s at 100,000, 123 s at 1,000,000; peak RSS at one million: 3,140 MiB. |

The [original microbenchmark report](history/BENCHMARKS-2026-09-24.md) keeps per-type costs, append and durability modes, the reference comparison, execution-path variants and the Python results. The [original scale report](history/PERFORMANCE-2026-09-26.md) keeps workload construction, memory limits, witness measurements, exceptions and reproduction commands. Both are unchanged; their links were written relative to their original `docs/` location, as the [history index](history/README.md) explains.

Don't combine the sets as one run. The scale report used worker-thread signature verification and cached-open verification, unlike the earlier implementation. Node and Python rows have their own algorithms, crypto paths and sample counts. An unopened history is not a warm decision, and a retained service reply is not a measured real-world outcome.

## What these numbers show, and what they don't

**Established:** these dated, finite measurements. **Not established:** a rerun, the performance of commits after `e2991bf`, a ranking against other products, behavior under production load, or a service-level agreement. Other pages must not claim measurements that aren't on this page.

## Measure it yourself

Use a disposable checkout, the runtime you mean to measure, and enough scratch storage. For format 2, run the `budgets.mjs` command above. The historical scripts are `packages/core/bench/{replay,authorize,append,reference-grants}.mjs`, `python/bench/replay_bench.py` and `bench/{generate,run}.mjs`; read the dated report before running a large generator.

A measurement of a current release must name its source and build, format, workload, machine, flush and witness modes, and sample distribution. Keep failures and resource ceilings visible.

*Last reviewed: 24 October 2026. This page is revisited at each release.*
