# Benchmarks

> **Scale figures** (10,000 to 1,000,000 events and the 1 GiB file limit, memory and heap, the witness server at 100,000 entries, the CI regression check) are in [PERFORMANCE.md](PERFORMANCE.md), measured on 2026-09-26 with signature verification on worker threads and `verify()` reusing the open's replay. The per-type, per-call and execution-path figures below are from 2026-09-24 and describe the shape of the costs; for replay and `verify` times, PERFORMANCE.md has the current, faster figures.

Measured numbers for the core engine, both history formats, the Python verifier, and the Continuity reference on the same scenario. Every figure on this page was produced by the scripts named next to it, on the machine described below, on 2026-09-24. The rows that depend on narrowed format-1 evidence, `verify()` reusing the cached replay and the state-based job path were measured with those in place, on the same machine: §3 refusal row, the `verify()` figures in §1, §4 and §7, and all of §6. Nothing is extrapolated; where a number varies between runs the range is given.

**Machine.** 2 vCPU Intel Xeon @ 2.10 GHz (`nproc` = 2), 7 GiB RAM, Linux 6.18, ext4 on a virtual disk. Node v22.22.2 (`--experimental-strip-types`, sources not `dist`), Python 3.11.15 with `cryptography` 46.0.7 for the Ed25519 fast path. A single run of each script; medians are over the sample sizes stated in the scripts. Treat everything as ±20 %: the box is small and shared.

**Scripts** (`packages/core/bench/`): `replay.mjs` (replay throughput and per-type cost), `authorize.mjs` (cold and warm decisions and queries), `append.mjs` (store-level and owner-level append latency), `reference-grants.mjs` (the evaluation scenario through the reference and through IronTrellis), `scenario.mjs` (the shared history generator). `python/bench/replay_bench.py` for Python. Run them with `node --experimental-strip-types packages/core/bench/<script>.mjs [eventCount]`.

**The scenario.** `scenario.mjs` builds a deterministic history: per agent, `AGENT_CREATED`, `ROLE_CREATED`, `AGENT_APPOINTED`, `RUNTIME_SESSION_ADMITTED`, a root grant, a delegation from the previous agent and a ROOT prohibition, every fourth agent a revocation, three intent declarations, and in format 1 one runtime-signed `TRANSACTION_INTENT_ADMITTED` per agent, an epoch advance every fifth agent and an anchor every fiftieth. At 10,000 format-1 events: 872 agents, 2,614 grants, 2,616 intents, 872 admissions, 217 revocations, 6,511 owner-signed control events. Legacy histories are capped at 4,096 events by the reference's canonical bound (393 agents, 1,177 grants). File sizes as written by the store: 8,232,965 bytes for the 10,000-event format-1 history (823 bytes per event), 2,858,520 bytes for the 4,096-event legacy history (698 bytes per event).

## 1. Summary

| operation | format 1, 10,000 events | legacy, 4,096 events |
|---|---|---|
| replay (open a file, verify every signature) | 2.1–2.3 s (0.22 ms/event) | 0.27 s (0.066 ms/event) |
| `applyEvent` of one more event | 0.05 ms | 0.04 ms |
| authorize, cold (first decision on an unseen state) | 5–6 ms median, 3 ms best | 1.5 ms |
| authorize, warm | 16–20 µs | 17 µs |
| why / responsible / survives, warm | 0.8 ms / 0.9–1.0 ms / 3.4–6.5 ms | 0.5 ms / 0.5 ms / 1.1 ms |
| store append, fsync on (file + directory + pin) | 1.7–1.8 ms median, 0.8 ms best | 1.1–1.5 ms |
| store append, fsync off | 0.37–0.40 ms | 0.26–0.29 ms |
| owner `grant()` (capture, capacity, Ed25519 signature, CAS, fsync, attested pin) | 1.9–2.1 ms, flat from 100 to 10,000 events | 1.3 ms (96-event budget) |
| `verify()` on an open handle (re-read and re-hash every line; the cached replay stands in for a second replay) | 0.49 s | 14 ms at 96 events |
| simulated job `run()` (declare, sign, admit, invoke; no event snapshot, no replay) | 12–33 ms at 2,000–5,000 events; 35–114 ms when those events are owner-signed grants (§6) | — |
| Python replay | 16.0 s (1.6 ms/event, `cryptography`) | 5.3 s (1.3 ms/event) |

The reference Core 0.3 SDK on the evaluation scenario (85 grants to one agent): **42.1 s** total, 35 ms for the first grant and 925 ms for the last. IronTrellis on the same scenario: **0.18 s** (legacy format) and **0.20 s** (format 1), about 2 ms per grant throughout.

## 2. Replay

`node --experimental-strip-types bench/replay.mjs` builds the scenario, replays it from scratch three times, then applies each event once on a fresh state to attribute the cost per type.

| | format 1, 10,000 events | legacy, 4,096 events |
|---|---|---|
| build (signing included) | 3.6 s | 0.36 s |
| replay, best / median of 3 | 2,077 / 2,202 ms | 268 / 269 ms |
| per event | 0.21 ms | 0.066 ms |

Per type (µs per event, format 1): `TRANSACTION_INTENT_ADMITTED` 797 (re-derive the proof and verify the Ed25519 runtime signature), `AUTHORITY_GRANTED` 212, `ANCHOR_RECORDED` 215, `CONTROL_EPOCH_ADVANCED` 204, `RUNTIME_SESSION_ADMITTED` 190, `AGENT_CREATED` 188, `ROLE_CREATED` 188, `AGENT_APPOINTED` 183, `AUTHORITY_REVOKED` 174, `TRANSACTION_INTENT_DECLARED` 48. Every control event costs one Ed25519 verification, about 120 µs of the 170–215 µs, which is the OpenSSL floor on this CPU; the rest is capture, schema and hashing. Legacy per type: `TRANSACTION_INTENT_DECLARED` 89, `AUTHORITY_GRANTED` 76, `AGENT_APPOINTED` 59, `RUNTIME_SESSION_ADMITTED` 57, `AGENT_CREATED` 42, `CONTROL_EPOCH_ADVANCED` 41, `ROLE_CREATED` 38, `AUTHORITY_REVOKED` 38.

Replay is linear in the number of events and dominated by signatures: a format-1 history with no admissions replays at roughly 0.18 ms per control event; a legacy history has no control signatures and replays at 0.07 ms per event.

## 3. Authorize and queries

`node --experimental-strip-types bench/authorize.mjs`. The actor is the second-to-last agent (three candidate authorities: its root grant, a delegation, and a prohibition on `write`). **Cold** is the first decision on a state object the engine has never seen (the memoized corpus and indexes are built from the whole `authorities` map); **warm** is every later decision on that state. Two runs:

| | format 1, 10,000 events (2,614 grants) | legacy, 4,096 events (1,177 grants) |
|---|---|---|
| cold ALLOW, median of 15 / best | 5.1–6.5 ms / 3.1–3.6 ms | 1.5–1.6 ms / 1.1–1.2 ms |
| warm ALLOW, median of 100 | 16–20 µs | 17 µs |
| warm refusal, median of 100 | 17 µs (`DENY / PROHIBITED`, 7 evidence references per failure) | 10–13 µs (`DENY / PROHIBITED`) |
| WHY, warm, median of 20 | 0.82–0.83 ms | 0.52–0.59 ms |
| RESPONSIBLE, warm | 0.91–1.04 ms | 0.50–0.52 ms |
| SURVIVES, warm | 3.4–6.5 ms | 1.1–1.2 ms |

Two things worth knowing:

* On a format-1 history with admissions, **replay already warms the memo**, because replaying each admission re-derives its proof through the same decision engine. The cold figure was therefore taken on a shallow copy of the state (a new object, the memo's `WeakMap` key), which is the worst case: building the corpus from scratch.
* The refusal's evidence depends on the format. A format-1 DENY cites only the events relevant to the request (the genesis, the head, the actor's lifecycle, the candidate paths' grants and revocations, their intersection partners and the prohibitions considered): the refusal above is `DENY / PROHIBITED` with 7 evidence references per failure at 500 events and still 7 at 10,000. A legacy DENY keeps the reference's specified evidence (spec 02 §6.2), every authority event in the history: 204 references per failure at 500 events and 1,666 at 4,096, so on a legacy history with enough grants and failures a refusal crosses the 4,096-reference budget and is reported as `INDETERMINATE / OUTPUT_LIMIT_EXCEEDED`. Before the evidence was narrowed, the format-1 refusal at 10,000 events was `INDETERMINATE / OUTPUT_LIMIT_EXCEEDED` for that reason. ALLOW proofs are bounded by the path and are not affected.

The queries are dominated by evidence collection (WHY and RESPONSIBLE) and by the scan of intents, obligations and outcomes for the target agent (SURVIVES), and grow with the history; they are still single-digit milliseconds at 10,000 events.

## 4. Append

`node --experimental-strip-types bench/append.mjs`. Store level: the last 200 scenario events are appended one at a time with `store.append` (lock, CAS, incremental validation, one line, pin) onto a file that already holds the other 9,800 (legacy: 3,896). Owner level: a history is built entirely through `createLocalOwner(...)` calls (fsync on), and the per-call latency is sampled along the way.

| store level, per append | format 1 | legacy |
|---|---|---|
| fsync on: median / p90 / best | 1.73–1.80 ms / 2.8–3.9 ms / 0.81–0.87 ms | 1.14–1.49 ms / 1.5–2.3 ms / 0.76–0.90 ms |
| fsync off: median / p90 / best | 0.37–0.40 ms / 1.0–1.1 ms / 0.17–0.18 ms | 0.26–0.29 ms / 0.33–0.40 ms / 0.16–0.18 ms |

The difference between the rows is three fsyncs (file, directory, pin). Nothing in the append depends on the history length: the same figures hold at 100 events.

| owner level, format 1 (fsync on, Ed25519 control signature, attested pin) | median | p90 |
|---|---|---|
| `createAgent` (1,213 calls) | 1.88 ms | 2.65 ms |
| `createRole` (1,213) | 1.85 ms | 2.66 ms |
| `appoint` (1,213) | 1.86 ms | 2.70 ms |
| `grant` (3,639) | 1.98 ms | 2.82 ms |
| `delegate` (1,212) | 1.98 ms | 2.85 ms |
| `prohibit` (1,212) | 1.99 ms | 2.81 ms |
| `revoke` (303) | 1.82 ms | 2.56 ms |

`grant` latency sampled at 90, 107, 1,006, 2,004, 4,001 and 10,007 events: 1.99, 2.03, 1.90, 2.00, 2.36, 1.90 ms — flat. Through the same owner handle at 10,007 events: `authorize` 29–67 µs (median of 20; includes the store's `stat` and tail check), `why` 0.8–4.0 ms, `verify()` 0.49 s (a full re-read and re-hash of every line; before `verify()` reused the cached replay it took 2.45 s). Legacy owner histories stop at their 96-event managed budget: `grant` 1.28 ms, `verify()` 14–16 ms.

## 5. Before and after: the Continuity evaluation scenario

The Continuity evaluation measured one agent receiving 85 grants through the Core 0.3 SDK: 43 ms per grant at 4 events rising to 1.3 s per grant at 83 events, 45 s for the 85 grants, because every write re-captured and re-replayed the whole history and every replay re-validated every grant. `node --experimental-strip-types bench/reference-grants.mjs` runs that scenario through the frozen reference (`packages/reference-0.2`, Core 0.3 `createLocalOwner`, legacy format) and through the IronTrellis owner API in both formats, on this machine:

| | 85 grants, total | first grant | median | last grant (88 events) |
|---|---|---|---|---|
| reference Core 0.3 SDK, legacy format | **42.1 s** | 35 ms | 497 ms | 925 ms |
| IronTrellis owner API, legacy format | **0.18 s** | 2.9 ms | 1.9 ms | 1.8 ms |
| IronTrellis owner API, format 1 (signed) | **0.20 s** | 2.4 ms | 2.0 ms | 2.3 ms |

All three histories end at 88 events and answer `ALLOW` for the last grant. The reference's per-grant cost grows linearly with the history (quadratically in total); IronTrellis's does not grow, and format 1's signature and attestation cost about 0.1–0.4 ms on top of the legacy write.

## 6. The execution path

The execution path (`openLocalSimulation` / `openLocalExecution` / `openLocalEvidenceTool`: `run`, `recordReceipt`, `collect`), the session-signed duty writes (`openLocalRuntime.obligate` / `assign`, the attempt recorder) and the gateway's exactly-once jobs built on them work on the store's cached replay state: the coordinators read `store.state()`, admissions, receipts and administrative events are proposed through the engine's `*State` entry points, and every prospective event is checked on a copy-on-write fork. Nothing on this path takes an event snapshot or replays the history (a fork shallow-copies the state's arrays, which is pointer work), so a job's cost no longer grows measurably with the number of events. Opening a handle replays the file once.

Measured with a script over the built package (`dist`) that sets up the lifecycle test's scenario (two agents, a role, a succession rule, a session, two grants), pads the history, then times a fresh `openLocalSimulation`, a first `run()`, a second `run()` of a new operation, `recordReceipt()` and `openLocalRuntime(...).obligate()`, with fsync on; two runs each. The same bounds are asserted by `packages/core/test/lifecycle.test.mjs` (a job on a 2,000-event history under 200 ms; a job, receipt and duty on a 5,000-event history, past the old 4,096-event adapter bound; `TRACE=1` prints the timings).

| history (format 1) | open | first `run()` | later `run()` | `recordReceipt()` | `obligate()` |
|---|---|---|---|---|---|
| 2,000 events, padded with unsigned intent declarations | 225–287 ms (110–145 µs/event) | 25–31 ms | 12–15 ms | 14–17 ms | 9–10 ms |
| 5,000 events, padded with unsigned intent declarations | 402–442 ms (80–88 µs/event) | 27–33 ms | 14–19 ms | 13–21 ms | 12–18 ms |
| 2,000 events, padded with owner-signed grants | 636–655 ms (0.32 ms/event) | 66 ms (one outlier at 669 ms) | 35–48 ms | 33–45 ms | 24–27 ms |
| 5,000 events, padded with owner-signed grants | 1,204–1,301 ms (0.24–0.26 ms/event) | 89–114 ms | 42–50 ms | 35–48 ms | 51–95 ms |

The first `run()` on a handle includes the first consequential decision on the cached state, which builds the memoized authority corpus (§3); that part grows with the number of grants, not with the number of events. The job path itself is flat: on the intent-padded histories a job takes the same time at 2,000 and 5,000 events. Under `node --test`, with the other lifecycle tests in the same process, `lifecycle.test.mjs` reported `run()` at 62 ms (2,000 events) and 53 ms (5,000 events) and an open of about 115 µs per event; the test's own comment estimates the open at about 70 µs per event. Opening is the replay cost of §2: about 0.1 ms per unsigned event and 0.2–0.3 ms per owner-signed control event.

Before this change the path handed an event snapshot to the engine's portable façades, which replayed it several times per call: about 1.5 ms per event in the history per call (`run()` took 53 ms at 11 events, 844 ms at 511 and 3,153 ms at 2,011).

## 7. Migration and verification

`migrateHistory` of the 4,096-event legacy scenario (re-record every event, sign 2,920 control events, dry-run the whole target, write it): 2.65–2.98 s. The migrated file is 2,667,522 bytes (651 bytes per event; smaller than the legacy source because plain JSON is denser than tagged tuples, despite the added signatures).

`verifyHistory` replays the file once (the open) and then re-reads it and re-checks every record hash, chain link and prefix hash against that replay (`verify()`), instead of replaying it a second time: 3.6 s for the 10,000-event format-1 file (3.2 s open, 0.66 s `verify()`), 1.2 s for the 4,096-event legacy file (0.78 s open, 0.56 s `verify()`), 1.3 s for the 4,096-event migrated file (whose replay also maintains the legacy shadow hasher). Measured with `openHistoryStore` / `verifyHistory` on files written from `scenario.mjs`; before the change, which replayed twice, the figures were 5.3 s, 1.07 s and 2.0 s.

## 8. Python

`python3 python/bench/replay_bench.py [history.jsonl …]`, Python 3.11, one core. `read` is the store read with chain and record-hash checks; `replay` includes every signature verification and proof re-derivation.

| history | read | replay | per event | first `authorize_state` (corpus build) | warm |
|---|---|---|---|---|---|
| legacy handover fixture, 26 events (pure-Python secp256k1 recovery) | 69 ms | 153 ms | 5.9 ms | 0.1 ms | 0.04 ms |
| `python/bench/large-v1.jsonl`, 2,001 format-1 events, 2,000 owner-signed, `cryptography` | 267 ms | 1,066 ms | 0.53 ms | 5.7 ms | 0.11 ms |
| the same, pure-Python Ed25519 (`--pure`) | 359 ms | 4,886 ms | 2.44 ms | 7.7 ms | 0.14 ms |
| scenario, 10,000 format-1 events (6,511 owner-signed, 872 admissions), `cryptography` | 1,829 ms | 15,981 ms | 1.60 ms | 19.1 ms | 0.03 ms |
| scenario, 4,096 legacy events | 5,513 ms | 5,334 ms | 1.30 ms | 18.8 ms | 0.48 ms |

Python is 7–20× slower than Node on replay (pure-Python keccak and canonical encoding; the legacy store read is slow because every line is keccak-hashed in Python), which is fine for its purpose: an independent verifier that shares no code with the writer. A warm decision is well under a millisecond in both.

## 9. Reproducing

```sh
pnpm install && pnpm build
node --experimental-strip-types packages/core/bench/replay.mjs            # §2
node --experimental-strip-types packages/core/bench/authorize.mjs         # §3
node --experimental-strip-types packages/core/bench/append.mjs            # §4 (writes to a temp dir)
node --experimental-strip-types packages/core/bench/reference-grants.mjs  # §5 (about 45 s, mostly the reference)
TRACE=1 node --test --experimental-strip-types packages/core/test/lifecycle.test.mjs   # §6 (the job-path bounds; prints run() timings)
python3 python/bench/replay_bench.py                                      # §8 (node python/bench/generate-large.mjs first if large-v1.jsonl is missing)
```

The scripts print what they measured and the scenario statistics; compare the shape of the numbers, not the third digit.
