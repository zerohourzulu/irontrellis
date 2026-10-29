# Performance and scale

How IronTrellis behaves on large histories: 10,000, 100,000 and 1,000,000 events, and a history grown to the 1 GiB format-1 file limit. Every figure on this page was measured with the scripts in `bench/` on the machine in §2, on 2026-09-26, on an otherwise idle machine (§2 notes two exceptions). The micro-level numbers for 10,000-event histories (per event type, per owner call, the execution path) are in `docs/BENCHMARKS.md`; this page is about scale, memory and the limits an operator plans around.

**Summary.** Opening a format-1 history (a full replay: every line parsed and hashed, every signature verified, every transition re-checked) costs about 0.13 ms per event on this 2-vCPU machine, linear up to the file limit: 1.6 s at 10,000 events, 13 s at 100,000, 123 s at 1,000,000. A 1,000,000-event history opens under Node's default heap (2 GiB on this 8 GiB machine) with 1.4 GiB of heap in use and 3.1 GiB peak RSS; a history at the 1 GiB limit (1.4 million events) still opens under it (1.9 GiB of heap in use, 182 s) but `irontrellis verify` of it runs out of heap there and needs `--max-old-space-size=3072` (§6). Once open, nothing grows with the history: an append takes 0.5 ms (1.5 ms with fsync), an owner `grant()` 1.6 ms, a warm `authorize` 30–75 µs, and `store.verify()` on the open handle a fraction of a second. Signature verification runs on worker threads during an open, `verify()` on an open handle reuses the open's replay, and SURVIVES, decisions for an actor with thousands of grants and the Python verifier's replay are linear in the history (§5).

## 1. Budgets

What to expect, and what the CI regression check (§10) holds the code to. "Measured" is this machine (§2); a slower or busier host scales these roughly with its single-core speed.

| operation | 10,000 events | 100,000 events | 1,000,000 events | expectation |
|---|---|---|---|---|
| open (full replay) | 1.57 s | 12.9 s | 123 s | linear, about 0.13 ms per event (0.25 ms on one core, §5.1) |
| `verifyHistory` / `irontrellis verify` | 1.49 s / 1.70 s | 12.8 s / 13.0 s | 129 s / 125 s | open + a SHA-256 of the file |
| `store.verify()` on an open handle | 16 ms | 159 ms | 1.86 s | a re-read and a SHA-256 of the file (§5.4) |
| `irontrellis status` | 1.74 s | 13.1 s | 134 s | an open |
| peak RSS of an open / heap in use after it | 149 / 33 MiB | 444 / 169 MiB | 3,140 / 1,384 MiB | about 3.2 KiB RSS and 1.4 KiB heap per event (§6) |
| `store.append`, fsync off / on (p50) | 0.55 / 1.39 ms | 0.56 / 1.53 ms | — | flat |
| owner `grant()` (p50) | 1.56 ms | 1.64 ms | — | flat |
| owner `grant()` with a witness on loopback, sync / async (p50) | 15.0 / 2.9 ms (fresh history; 2.4 ms without) | | | flat; sync is fsync-bound on both sides (§7) |
| `authorize`, warm (p50) | 39 µs | 36 µs | 75 µs | flat (the 1M figure is one run, with a 1.4 GiB heap) |
| `authorize` for an actor with 536 / 5,352 / 5,352 grants, warm (p50) | 33 µs | 30 µs | 30 µs | flat in the actor's grants (§5.2) |
| WHY / RESPONSIBLE (p50) | 1.4 / 1.8 ms | 10.5 / 13.3 ms | 52 / 119 ms | linear in the history |
| SURVIVES of the busiest agent (p50) | 56 ms | 219 ms | 966 ms | linear in the history (§5.3) |
| `irontrellis --version` (cold start) | 140 ms | 139 ms | 117 ms | independent of the history |
| Python `python -m irontrellis verify` | 5.9 s | 63 s | not run (memory, §8) | about 0.6 ms per event with `cryptography` |
| witness server, 100,000 entries / 1,000 histories: start-up / RSS | | 4.2 s / 274 MiB | | linear in the log (§7) |
| witness inclusion / consistency proof (p50) | | 0.82 / 0.75 ms | | logarithmic |

## 2. Machine and method

**Machine.** 2 vCPU Intel Xeon @ 2.10 GHz (`nproc` = 2), 8 GiB RAM (no swap; the benchmark's processes were limited to 5.8 GiB by the host's memory cgroup), Linux 6.18, ext4 on a virtual disk (an fsync costs about 1 ms). Node v22.22.2 running the built packages (`dist`), Python 3.11.15 with `cryptography` for Ed25519. Nothing else ran during a measurement.

**Histories.** `bench/generate.mjs` writes a realistic format-1 history. The first 100,000 events go through the real owner API (`createLocalOwner`: owner key file, next-key commitment, fsync, attested pin on every write): per unit an agent, a role, an appointment, an Ed25519 runtime session, a root grant, a delegation from the previous agent, a ROOT prohibition, a revocation every 4th unit, an epoch advance every 5th, an unappointment every 7th, and every 4th unit a job by one long-lived worker agent (two grants, `openLocalSimulation().run()`: intent declared, runtime-signed admission, consumption; `recordReceipt()`; a session-signed `obligate()`), plus a local-witness anchor every 5,000 events. The rest continues the same file through one store handle with the same unit mix: control events signed with the core's `signControlEvent`, jobs as a declared intent plus a runtime-signed `TRANSACTION_INTENT_ADMITTED` whose proof comes from `authorizeState`. Every appended event is validated by the store (signatures, prefix hashes, transitions) and the generator ends with `verifyHistory` on the finished file, so the result is a genuine history. The 1,000,000-event file (733 MiB): 371,015 grants (permissions, delegations, prohibitions, the worker's job grants), 121,890 agents, 121,889 roles, appointments and runtime sessions, 30,472 intents declared and admitted, 30,472 revocations, 24,377 epoch advances, 17,412 unappointments, 2,676 consumptions, receipts and duties, 198 anchors; all but the 30,472 intent declarations and a few thousand job records carry an owner, runtime or session signature. The worker holds 5,352 grants from the 100,000th event on.

**Measurements.** `bench/run.mjs` runs every measurement in a fresh child process (so peak RSS is that measurement's own and nothing is warm), `--runs` times, and reports the median over runs (for latency distributions, the median of each run's p50 / p99 / mean over 200–300 samples). Child processes run with Node's default heap (an inherited `NODE_OPTIONS` is dropped; see §6). Peak RSS is the kernel's high-water mark (`VmHWM`, or `wait4` rusage for the CLI and Python). `--root <tree>` runs the same measurement against another checkout's build on the same files, which is how a change is compared. Each child also emits a digest of the replayed state (every prefix hash, the size of every derived map) and of the verification report, so two checkouts can be shown to reach identical results at every size (the CLI's and the Python verifier's outputs likewise, timing fields removed).

## 3. Results

Median of 3 runs unless stated.

| | 10k | 100k | 1M |
|---|---|---|---|
| file size | 8.2 MiB | 82.7 MiB | 733 MiB |
| open (full replay) | **1.57 s** | **12.9 s** | **123 s** |
| per event | 157 µs | 129 µs | 123 µs |
| peak RSS / heap after open | 149 / 33 MiB | 444 / 169 MiB | 3,140 / 1,384 MiB |
| `store.verify()` on the open handle | **16 ms** | **159 ms** | **1.86 s** |
| `verifyHistory` (fresh open + verify) | **1.49 s** | **12.8 s** | **129 s** |
| `irontrellis status --json` | 1.74 s | 13.1 s | 134 s (1 run), 3,132 MiB |
| `irontrellis verify --json` | 1.70 s | 13.0 s | 125 s (1 run), 3,126 MiB |
| `irontrellis --version` | 140 ms | 139 ms | 117 ms |
| authorize, first on a handle | 775 µs | 973 µs | 1.00 ms |
| authorize ALLOW, warm p50 / p99 | 39 / 697 µs | 36 / 236 µs | 75 / 241 µs |
| authorize refusal, warm p50 | 38 µs | 36 µs | 50 µs |
| authorize the worker (536 / 5,352 / 5,352 grants): first; warm p50 | 122 µs; 33 µs | 136 µs; 30 µs | 127 µs; 30 µs |
| `observe()` p50 | 16 µs | 16 µs | 22 µs |
| WHY / RESPONSIBLE p50 | 1.42 / 1.77 ms | 10.5 / 13.3 ms | 52 / 119 ms |
| SURVIVES (worker) p50 | **56 ms** | **219 ms** | **966 ms** |
| `store.append` fsync off, p50 / p99 | 546 µs / 2.57 ms | 561 µs / 2.78 ms | |
| `store.append` fsync on, p50 / p99 | 1.39 / 4.84 ms | 1.53 / 3.97 ms | |
| owner `grant()`, p50 / p99 | 1.56 / 4.27 ms | 1.64 / 3.74 ms | |
| Python `verify` | **5.9 s** | **62.8 s** | not run (§8) |
| Python peak RSS | 97 MiB | 727 MiB | |

The queries were measured in three runs of 200 samples each (10–20 for WHY, RESPONSIBLE and SURVIVES; one run at 1M, 20 samples, 3 for SURVIVES). The CLI rows at 10k and 100k ran with the environment's `--max-old-space-size=8192` (it does not change their timing: their heap stays far below 2 GiB); the 1M CLI rows ran with the default heap.

**At the file limit.** `bench/generate.mjs --extend-from 1m --until-limit` continued the 1M history until an append was refused with `HISTORY_FILE_LIMIT`: 1,400,071 events, 1,073,741,756 bytes (68 bytes under the cap; the refused append left the file and the head unchanged, as the generator checks). One run each, after:

| at the limit (1,400,071 events, 1,024 MiB) | result |
|---|---|
| open with Node's default heap (2,096 MiB here) | **182 s** (130 µs per event), 1,906 MiB heap in use (91 % of the limit), 3,222 MiB peak RSS |
| `irontrellis verify --json`, default heap | **fails**: V8 out of memory after 227 s (3,341 MiB RSS) |
| `irontrellis verify --json`, `NODE_OPTIONS=--max-old-space-size=3072` | OK in **185 s**, 4,494 MiB peak RSS |
| the refused append itself | the handle's state already held the refused event, so it is marked stale and its next use replays the whole file again: 3.5 min and, while the old state is still referenced, about twice the memory (the generator reached 6 GiB and was then killed by the host's 5.8 GiB memory limit in its final self-check) |

Extrapolating the 10k–1M figures linearly (they are linear from 100k on, §4) predicts 172 s for the open at 1.4M; measured 182 s, the extra being garbage-collection pressure near the heap limit.

## 4. Scaling

Cost per event of an open, and memory:

| events | open | µs per event | peak RSS | heap after open | RSS per event |
|---|---|---|---|---|---|
| 1,504 (quick) | 0.33 s | 216 | 101 MiB | 14 MiB | — (start-up dominated) |
| 10,000 | 1.57 s | 157 | 149 MiB | 33 MiB | |
| 100,009 | 12.9 s | 129 | 444 MiB | 169 MiB | 4.5 KiB |
| sequential (`IRONTRELLIS_VERIFY_THREADS=0`): 10,000 / 100,009 | 2.65 s / 24.2 s | 265 / 242 | 131 / 423 MiB | 38 / 161 MiB | |
| 1,000,007 | 123 s | 123 | 3,140 MiB | 1,384 MiB | 3.2 KiB |
| 1,400,071 (the 1 GiB limit, 1 run) | 182 s | 130 | 3,222 MiB | 1,906 MiB | 2.4 KiB |

The open is linear from 100,000 events on. The per-event cost falls from 10k to 100k because start-up (module load, worker start, the owner-API phase's pin and key files) is spread over more events and because the direct-phase events (from the 100,000th on) carry fewer runtime-signed admissions. It does not rise with the number of grants an actor holds, because the proof each admission and duty re-derives considers only the actor's plausible candidates (§5.2).

## 5. Where the time goes, and why no check is skipped

Profiles (`node --cpu-prof` on the 100,000-event open, the witness start-up and a witnessed write; `cProfile` on the Python verifier; heap statistics per measurement and a heap snapshot of the witness) decide where the engine spends effort. In a sequential open, Ed25519 verification is the largest single cost, followed by garbage collection, canonical encoding for the record, prefix and control-signature hashes, event validation and JSON parsing. None of the techniques below changes a file format, wire message, signature, check or verdict; each is justified here and tested for results identical to the straightforward implementation.

### 5.1 Ed25519 verification in parallel, speculatively (`crypto/parallel-verify.ts`)

A format-1 replay verifies one owner signature per control event and one runtime or session signature per admission and duty: about 0.12 ms each on this CPU, the largest single cost. For files of at least 1,024 records, the store's open replays the file *speculatively*: the Ed25519 suite does every check it always does (syntax, key import) but, instead of calling OpenSSL, it queues (hash, signature, key) and answers `true`, while worker threads verify the queue with the same `node:crypto` call. The replay's result is used only if **every** queued verification succeeded: then the speculative run saw exactly the answers a sequential run would have seen and took exactly the same path, so its state, heads and errors are the sequential ones. If any verification failed, or the pool stalls or dies, the result is discarded and the file is replayed again sequentially, which reports the exact first error. Nothing is cached across replays; the calling thread verifies whatever no worker has claimed at the end, so a busy or dead pool never blocks it. Caller-supplied replay hooks never see a speculative run (it only runs with the engine's own validators). Pool size: `IRONTRELLIS_VERIFY_THREADS` (0 turns it off; capped at `os.availableParallelism()` and 16), default `min(4, cores − 1)`, so a single-core host runs sequentially; the hook's process defaults to one worker (§5.1.1). On this 2-vCPU machine (one worker) it about halves an open (24.2 → 12.9 s at 100,000 events, §4); with more cores the verification leaves the critical path entirely. Tests (`packages/core/test/parallel-verify.test.mjs`) compare pool and sequential replays on the same bytes: valid files, a bad signature (the speculation is discarded, the sequential error reported), bad transitions before and after a bad signature, a pool that stops answering.

#### 5.1.1 Thread count, the break-even and the hook

Measured with `bench/threads.mjs` (below) on the machine of §2 with nothing else running (the 10,000- and 100,000-event histories regenerated by `bench/generate.mjs`), median of 5 runs (3 at 100,000), each a fresh process. "Process" is the whole process's wall time, start-up and worker start included.

**Break-even.** The first N records of the 10,000-event history, opened with no worker and with one, with the record threshold lowered to 64 for the measurement (a scratch copy of the build):

| records | 64 | 128 | 256 | 384 | 512 | 768 | 1,024 | 2,048 | 4,096 | 10,000 |
|---|---|---|---|---|---|---|---|---|---|---|
| process, no worker | 195 ms | 206 ms | 266 ms | 317 ms | 340 ms | 455 ms | 485 ms | 827 ms | 1.33 s | 2.85 s |
| process, one worker | 201 ms | 222 ms | 271 ms | 284 ms | 318 ms | 417 ms | 433 ms | 615 ms | 930 ms | 1.71 s |
| peak RSS, no worker / one worker | 69 / 82 MiB | | 71 / 84 MiB | | 73 / 85 MiB | | 76 / 89 MiB | 88 / 103 MiB | 97 / 112 MiB | 139 / 156 MiB |

A worker costs about 13–17 MiB and starts in a few milliseconds; it pays for itself from about 300–400 records here. The threshold stays at **1,024 records** (`SPECULATIVE_REPLAY_MIN_RECORDS`): about three times the break-even, because the break-even moves up on a loaded machine and with every extra worker, and below 1,024 records an open takes under 0.5 s either way. Files below it never start a pool.

**More workers than CPUs.** Uncapped, opening 3,000 and 10,000 records on this 2-vCPU host with `IRONTRELLIS_VERIFY_THREADS=0 / 1 / 4 / 16` takes 1.00 / 0.74 / 0.90 / 1.22 s and 92 / 108 / 141 / 271 MiB (3,000), 2.85 / 1.72 / 2.15 / 2.64 s and 139 / 156 / 195 / 327 MiB (10,000): extra workers only cost. The variable is therefore capped at the CPU count (here 2), where 4 and 16 give 0.81 s / 120 MiB and 1.95–2.05 s / 170 MiB. On this host one worker is the fastest setting: the calling thread replays while one worker verifies.

**The hook.** `irontrellis-hook` opens (replays) the history on every tool call and exits, so it pays the open each time, and with the library default it would start `min(4, cores − 1)` workers per call (four on a developer machine with 5 cores or more). Its process defaults to **one** worker (`HOOK_VERIFY_THREADS`, applied by the bin through `setDefaultVerifyThreads`; still capped at cores − 1, so a single-core host is sequential; `IRONTRELLIS_VERIFY_THREADS` overrides it). Sequential verification was measured and rejected: it is the slowest setting. `irontrellis-hook check claude-code Write …` (config, open, rules, decision: a PreToolUse without the host's session check), whole process:

| history | hook default (1 worker) | 0 (sequential) | 1 | 2 | 4 (capped to 2 here) |
|---|---|---|---|---|---|
| 10,000 events | 1.70 s | 2.78 s | 1.67 s | 1.91 s | 2.00 s |
| 100,009 events | 12.9 s | 24.7 s | 12.8 s | | 14.9 s |

What the default buys is the many-core case: with the library default a hook on an 8-core machine would start four workers per tool call; on this host four workers (capped to two) cost 15–20 % more wall time than one, and each worker adds about 13–17 MiB. The hook's latency is dominated by the open itself: about 170 µs per event here with one worker, so keep a hook-driven history small (§9: about 10,000–50,000 events).

**The worst case.** A file whose only bad signature is its last one costs a full speculative replay, then a full sequential replay to report the exact error: about 1.5× a sequential open, before the error is reported. Only an invalid file pays this; no verdict depends on it.

### 5.2 Decisions for an actor with many candidates (`authority.ts`, `authority.py`)

Evaluating every candidate authority of the actor to find the winner would make each decision cost O(the actor's grants). During replay every intent admission and duty creation re-derives its proof, so for a long-lived worker that receives a grant per job, replay would be quadratic in its jobs, in both engines. A candidate can only succeed if its terminal grant names the requested action and resource (`evaluateCandidate` fails it with ACTION or RESOURCE otherwise). For actors with more than 32 candidates the engine keeps a per-resource index of their candidates (built on first use, maintained as grants are added) and first evaluates only those plausible ones: they include every candidate that can succeed, in the same relative order, so the successes are compared in the same sequence and the winner is the one the full loop picks. Without a winner, the full loop runs over every candidate (a refusal lists every candidate's failure). The administrative-requirements filter is computed only when that loop needs it. Tests: the generated-corpora and fixture differentials against the frozen reference engine with the pass forced on for every actor (threshold 0), including a state grown event by event (the index is maintained incrementally), and a 1,200-candidate actor with ties, revocations, expiries and prohibitions decided identically with the pass forced on, off and at the default threshold; the Python differential against the TypeScript engine likewise.

### 5.3 SURVIVES without a whole-history scan per row (`query-survives.ts`, `survives.py`)

A direct SURVIVES scans every event of the history once per intent, tenure and linked obligation of the target, once per grant touching it (the terminated-agent check), and once per obligation of the history (`obligationLinksTarget`): O(rows × events), tens of seconds for the worker at 100,000 events and hours at 1,000,000. SURVIVES instead builds, once per call, an index of event positions by type and by (type, field value) and looks the cited events up: exactly the positions the scans find, in the same (history) order. Checked against the direct scan on the 100,000-event history (43 agents), the 10,000-event one, and every conformance and legacy fixture history: 272 derivations byte-identical (evidence included); the queries tests compare every SURVIVES envelope with the frozen reference engine. Python's SURVIVES (which has no evidence lists) uses the same index.

### 5.4 `verify()` on an open handle: a SHA-256 instead of a re-parse (`store.ts`)

`verify()` re-reads the file and must know that the bytes are the ones the cached replay stands for. Re-parsing every line and recomputing every record and prefix hash costs seconds at 100k. The handle therefore keeps a running SHA-256 of exactly the bytes its replay parsed (the whole file at open, then each tail it read from another writer); when the file has that length and that digest, the bytes are identical, so re-parsing them would reproduce the cached chain line for line, and the cached replay stands. Any other file falls through to the per-line re-check, and from there to a full replay. The pin, its attestation, anchors and witnesses are judged on every call. A handle that wrote lines itself (encoded, not parsed back) drops the digest and re-parses. Retries inside a snapshot (a pin read that raced a writer) reuse a replay of byte-identical content instead of replaying again. Adversarial tests: a same-size, same-mtime byte edit (in place and by rename), a same-size swap to another fully valid history, truncation at and inside a line, extension by garbage and by a line that does not chain, an edit inside the already-verified part after the handle read another writer's tail.

**No persistent verification cache.** A cache that lets a *later process* skip verifying a prefix (keyed by the prefix's hash, say) was considered and not built. Such a cache can only skip work if the verifier trusts it, and a file beside the history is writable by anyone who can tamper with the history: they can write a cache entry that vouches for the tampered bytes' hash. Keying the entry by the content hash does not help (the attacker computes the hash of their own bytes); only an authenticator the attacker cannot produce would, i.e. a secret held outside the history's directory, which moves the problem to key management for a verifier that today needs no key. It also would not remove the replay: continuing a verified prefix needs its replayed state, which is as large as the history and would itself have to be trusted. The in-process digest of §5.4 has neither problem: the trusted party is the process's own memory of what it parsed. The answer to slow opens is a successor history (§9).

### 5.5 Canonical encoding (`canonical.ts`)

Every record key is validated before any field (the reference's error order). So that this does not scan each key twice, keys are scanned once per process: a bounded map (at most 4,096 keys of at most 128 UTF-16 units) holds each key's escaped byte length and whether it needs escaping, which depends on the key's text alone; errors are never cached. Micro-benchmarks (`bench/micro.mjs`, the format-1 conformance histories, TypeScript sources):

| µs per item (median of 9 rounds) | |
|---|---|
| `canonicalEncode(event)` | 6.82 |
| `captureValue(event)` | 6.39 |
| `hashCanonical(event, "sha256")` | 11.96 |
| `jsonParseWithBigints(store line)` | 3.37 |

### 5.6 The Python verifier (`python/src/irontrellis`)

Rebuilding the whole authority corpus for every admission and duty during replay would make `verify` quadratic in the number of grants (more than 27 minutes at 100,000 events). The Python engine extends the memo event by event exactly as the TypeScript engine's `extendMemo` does, and has the candidate pass of §5.2. The canonical string scan uses `str.isascii()` and a compiled regular expression instead of a per-character loop. Result: 5.9 s at 10,000 events and 63 s at 100,000. pytest (including the differential against the TypeScript engine, also with the candidate pass forced on) and both conformance suites pass.

### 5.7 Left as they are

- Each event is canonically encoded three times during replay (record hash, control-signature hash, prefix hash): about 9 % of an open. Reusing the record hash's encoding for the prefix hash is possible in principle but would have to reproduce the depth and size bounds of both contexts exactly; not worth the risk to the error semantics, which follow the reference.
- Garbage collection is 10–12 % of an open; the replay state holds every event as a frozen deep copy (§6).
- A sync witness write costs about 13 ms more than a plain one on this disk, almost all of it fsyncs on both sides (§7); the durability protocol is deliberate.
- A refused append (the file limit, or a batch whose later event is invalid) leaves the handle's state holding the events it applied, so the handle is marked stale and its next use replays the whole file (3.5 minutes at the limit, with the old state still referenced meanwhile). Correct, and rare; undoing an applied event in place is not supported by the state, and applying every append to a copy would cost more than it saves. At the limit the answer is the successor history (§9).
- The witness's Merkle tree stores each node as its own 32-byte `Uint8Array` (about 180 bytes per node, §7); contiguous per-level buffers would save about 35 MiB per 100,000 entries.
- The Python verifier holds about 7 KiB per event (§8).

## 6. Memory and the heap

**What an open holds.** The replayed state keeps every event (a frozen deep copy, as validated), its prefix hash and record hash, the id index and the derived maps (agents, roles, tenures, authorities, sessions, intents, duties): about **1.4 KiB of heap per event** once the replay is done (1,384 MiB at 1M, 1,906 MiB at 1.4M, on this mix). Peak RSS is about twice that during the open: the file's bytes are held while it is replayed (733 MiB at 1M), plus the young generation and garbage. Nothing else grows: appends, decisions and queries add memos per state, not per call. The handle's verification digest is one SHA-256 state; the worker threads hold their own small heaps and a few 32 KiB batches.

**Node's default heap** is derived from physical memory (a quarter of it, capped at about 4 GiB on 64-bit): 2,096 MiB on this 8 GiB machine, about 1 GiB on a 4 GiB host. Measured minimum for the open at 1M: a 1,536 MiB heap opens it (156 s: more garbage collection), 1,280 MiB runs out of memory. So:

| history | heap needed to open (`--max-old-space-size`) | for `verify`, `status` and long-running handles |
|---|---|---|
| 100,000 events | under 256 MiB | the default everywhere |
| 500,000 events | about 800 MiB | the default on hosts with 4 GiB or more |
| 1,000,000 events | about 1,400 MiB (1,536 measured OK, 1,280 fails) | 2,048 MiB (the default on 8 GiB hosts) |
| 1.4 million (the file limit) | about 1,950 MiB (the 2,096 MiB default opens it, with 9 % left) | 3,072 MiB (measured: `verify` fails with the default, passes with 3,072) |

Rule of thumb: `--max-old-space-size` ≥ 1.5 KiB × events + 512 MiB, and RAM ≥ 3.5 KiB × events for the whole process (the Python verifier: 7 KiB × events, §8). The CLI, the hook, the gateway and scripts all honour `NODE_OPTIONS=--max-old-space-size=<MiB>`.


## 7. The witness server at scale

A witness data directory built through the server's HTTP API (`bench/run.mjs --only witness-scale`): 1,000 histories, each registered and then advanced by 98 owner-signed head statements, 100,000 log entries, an 81 MiB `log.jsonl`. Median of 3 runs of: start the real `irontrellis-witness serve` on a copy and time it until it listens, then 300 random inclusion proofs, 300 random consistency proofs and 300 head POSTs (random histories, each a new signed statement, fsynced before the reply) from one sequential client.

| 100,000 entries | |
|---|---|
| start-up (replay the log, rebuild the tree, check the last checkpoint, until listening) | **4.21 s** |
| RSS after start-up / peak | 274 / 273 MiB |
| GET inclusion proof p50 / p99 | 815 µs / 6.76 ms |
| GET consistency proof p50 / p99 | 749 µs / 4.53 ms |
| POST head (verify, append, fsync, checkpoint) p50 / p99 | 2.66 / 10.1 ms |

Start-up re-reads every line, checks it is canonical, validates the entry, re-applies it to the state (without re-verifying signatures; `irontrellis-witness check-log` does that offline) and rebuilds the Merkle tree, then compares the tree with the last signed checkpoint. Canonical encoding dominates it, so no line is encoded twice: the leaf bytes are cut out of the checked line (a line is exactly `{"entry":<canonical entry>,"index":<n>}`; `entryBytesOfLine` in `packages/witness/src/log.ts`, tested byte for byte against `encodeEntry` for every entry kind, escapes and non-ASCII text, and the checkpoint comparison would refuse to start on any difference). `check-log` encodes each entry independently.

**Scaling.** Everything at start-up is per entry (parse, validate, apply, one leaf hash and on average one interior hash): about 42 µs per entry here, so about 42 s for a million entries. Proofs are logarithmic in the tree size (every aligned subtree is stored). Memory: a heap snapshot after start-up shows 78 MiB live for 100,000 entries (0.8 KiB per entry): 35 MiB of it the Merkle tree's 200,000 nodes (each a 32-byte `Uint8Array` with its own `ArrayBuffer`, about 180 bytes per node), the rest the per-history head records and strings; RSS is about 2.7 KiB per entry. A witness serving millions of entries therefore needs a heap of about 1 GiB per million entries (`--max-old-space-size`) and starts in about 40 s per million. Storing each tree level in one contiguous buffer would cut the tree's share to 64 bytes per leaf (§5.7).

Writes through a witness, from the client side (`bench/run.mjs --only witness`, owner `grant()` on a fresh history, 200 samples, median of 3 runs):

| owner `grant()` | p50 | p99 |
|---|---|---|
| no witness | 2.38 ms | 5.80 ms |
| async witness (the default): the head is submitted by a background worker | 2.89 ms | 6.06 ms |
| sync witness: the write returns once the witness holds the head | 15.0 ms | 23.1 ms |

A sync write adds a round trip in which the server verifies the statement, appends and fsyncs the log and the checkpoint, and the client verifies the receipt, the checkpoint and the latest note and records them durably in its side file (`<history>.witness.json`, written atomically with a file and a directory fsync). The profile of the client puts a quarter of its time in fsync and another quarter waiting for the server; the rest is the store's own write. That is the price of the durability the protocol requires (docs/WITNESS.md §5), and it does not grow with the history. Use `async` (the default) for high-rate writers.

## 8. The Python verifier at scale

`python -m irontrellis verify <history.jsonl>` (`cryptography` installed; median of 3 runs):

| events | time | peak RSS |
|---|---|---|
| 10,000 | **5.94 s** (0.59 ms per event) | 97 MiB |
| 100,009 | **62.8 s** (0.63 ms per event) | 727 MiB |
| 300,000 (a prefix of the 1M history, one run) | 165 s (0.55 ms per event) | 1,968 MiB |

The Python verifier is linear (§5.6) but keeps every event as nested dicts: about 6.6–7.3 KiB of RSS per event, so a 1,000,000-event history needs about 7 GiB and was not run here (this machine's processes are limited to 5.8 GiB); linear extrapolation from 100k and 300k puts it at about 9–10 minutes. It is the independent second opinion (docs/OPERATOR.md §3), not the everyday path: run it on a host with the memory, or on the histories small enough to verify twice.

## 9. Operator guidance

- **Open cost is the planning number.** Every command, the hook, the gateway and every owner or runtime handle replays the file once when it opens it (about 0.13 ms per event here, 0.25–0.3 ms on a single core); after that, nothing replays. A long-running writer (the gateway, a service holding an owner handle) pays it once; a short-lived one (each `irontrellis` command, each hook invocation) pays it every time. Keep a history whose open sits on a latency path (the hook runs on every tool call) small enough that its open fits the latency you accept: about 10,000–50,000 events for a hook-driven case, far more for a long-lived writer.
- **When to start a successor history.** Start one (a fresh `irontrellis init`; re-create the live agents, roles and grants; keep the old history as a read-only archive, OPERATOR.md §4) when any of these is near: the open or `verify` time you accept (1M events: about 2 minutes here, 4–5 on one core); the memory the host can give a reader (§6: about 1.5 KiB of heap and 3.5 KiB of RAM per event); or the 1 GiB format-1 file limit (`HISTORY_FILE_LIMIT`, about 1.4 million events at 760 bytes per event; watch the file size, OPERATOR.md §5). A practical rule: plan the successor at 500,000 events or 500 MiB, well before the limit.
- **Heap.** Node's default heap is a quarter of physical memory, capped at about 4 GiB (2 GiB on this 8 GiB machine, about 1 GiB on a 4 GiB host). A history of N events needs about 1.5 KiB × N of heap plus 512 MiB of headroom; above the default, run readers with `NODE_OPTIONS=--max-old-space-size=<MiB>` (the CLI, the hook, the gateway and scripts all honour it), e.g. 3072 for a history at the file limit, where `irontrellis verify` fails with the default 2 GiB heap (§3). The Python verifier needs about 7 KiB of RSS per event (§8).
- **Cores.** Replay verifies signatures on `min(4, cores − 1)` worker threads (the hook: one, §5.1.1): a 4-core host opens large histories noticeably faster than this 2-vCPU one. `IRONTRELLIS_VERIFY_THREADS=0` turns it off (a host where extra threads are unwelcome), `=<n>` sets the pool (at most 16, and never more than the CPU count). Small files (under 1,024 records) are always replayed on the calling thread.
- **Verification cadence.** A scheduled `irontrellis verify` of a 1M-event history costs about 2 minutes of two cores and 3.1 GiB of RAM here; run it from a host that has them, or verify a copy.
- **Witness mode.** A `sync` witness adds about 13 ms per owner write on this disk (both sides fsync); `async` (the default) keeps writes at local speed. A witness server's start-up and memory grow with its log (§7).

## 10. The regression check

`pnpm bench` (or `pnpm bench:quick`; `node bench/run.mjs --quick`) is the CI-friendly check: it generates a 1,500-event history through the owner API (with jobs and anchors), then measures open, `verifyHistory`, `store.verify()`, the queries, appends (fsync off and on, owner `grant()`), a sync and an async witness on loopback, the CLI cold start, `status` and `verify`, the Python verifier, and a witness server with 400 entries over 20 histories, once each, and exits 1 when a result exceeds its budget. About 15 s here; the CI job (`bench (quick)` in `.github/workflows/ci.yml`, Ubuntu, Node 24) has a 10-minute timeout. The budgets (`QUICK_BUDGETS` in `bench/run.mjs`) are 5–20× above what a 2-vCPU runner measures, so noise never fails the job and an order-of-magnitude regression (an accidental O(n²), a lost cache, a replay on every write, a verification that stopped reusing the open) always does:

| check | this machine | budget |
|---|---|---|
| open, µs per event | 216 | 3,000 |
| `store.verify()` on the open handle | 3 ms | 3,000 ms |
| `verifyHistory` | 373 ms | 8,000 ms |
| authorize warm p50 | 40 µs | 5 ms |
| WHY p50 | 1.1 ms | 100 ms |
| SURVIVES (worker) p50 | 14 ms | 500 ms |
| `store.append` fsync off p50 | 0.55 ms | 25 ms |
| owner `grant()` p50 | 1.8 ms | 100 ms |
| owner `grant()` with a sync / async witness p50 | 16 / 3 ms | 250 / 100 ms |
| `irontrellis --version` | 139 ms | 3,000 ms |
| `irontrellis verify` (1,500 events) | 505 ms | 10,000 ms |
| Python verify (1,500 events) | 0.98 s | 30,000 ms (pure-Python Ed25519 on CI) |
| witness start-up / inclusion proof p50 / head POST p50 | 195 ms / 0.87 ms / 3.3 ms | 5,000 / 50 / 250 ms |

The unit suites keep their own timing assertions (canonical encoding, append latency, authorize on 3,000 grants); their bounds are multiplied by a load factor (`packages/core/test/helpers/timing.mjs`: a fixed SHA-256 and JSON calibration, best of five, relative to this machine), so they scale with the host's current speed instead of failing under load, and a regression of an order of magnitude still fails them.

## 11. Reproducing

```sh
pnpm install && pnpm -r build
# histories (0.8 GiB of disk for the first three, 1 GiB more for the limit one; the 1M one takes about 25 minutes, the limit one 10 more)
node bench/generate.mjs --events 10000   --out /data/hist/10k
node bench/generate.mjs --events 100000  --out /data/hist/100k
node bench/generate.mjs --events 1000000 --out /data/hist/1m --owner-events 100000
node bench/generate.mjs --events 1500000 --out /data/hist/limit --extend-from /data/hist/1m --until-limit
# measurements (medians of 3 runs; --root <tree> measures another checkout on the same files)
node bench/run.mjs --histories /data/hist --sizes 10k,100k --runs 3 --out results.json
node bench/run.mjs --histories /data/hist --sizes 10k --only witness-scale --runs 3      # builds a 100,000-entry witness log first
node bench/run.mjs --histories /data/hist --sizes 1m --only open,verify,queries,cli --cli-sizes 1m --runs 3
node bench/micro.mjs                                                                     # canonical layer
node bench/threads.mjs open --history /data/hist/10k/history.jsonl --runs 5                  # verification threads by record count
node bench/threads.mjs hook --history /data/hist/100k/history.jsonl --runs 3                 # hook latency by thread count
pnpm bench:quick                                                                         # the CI check
```

`bench/generate.mjs` prints its progress and writes `manifest.json` (counts by type, phases, timings) next to the history; `bench/run.mjs --help`-style usage is in its header comment. Delete the generated histories afterwards: they are large, and the owner key files next to them are real keys.
