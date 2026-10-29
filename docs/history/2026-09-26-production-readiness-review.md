> **Pre-release internal review.** This report was written while IronTrellis 1.0.0-rc.1 was being built, before its first public release, and is kept verbatim as a record. Its findings were fixed before 1.0.0-rc.1 or are listed as known limitations in [docs/SECURITY.md](../SECURITY.md) §8. Paths under `/home/claude` and `/tmp`, internal build-stage names (an "rc.1" baseline, "blocks", "rc.2"), and design notes it cites (such as WITNESS-DESIGN or WIRE-DEVIATIONS) belonged to that development process and are not part of this repository. Code names, error codes and wire fields may differ from the released ones; [CHANGELOG.md](../../CHANGELOG.md) and the docs describe what shipped. See [README.md](README.md) in this folder.

# Block 3 review (production readiness): independent adversarial review

Reviewer: independent (did not write the code). Date: 2026-09-26.
Scope: `diff -ruN irontrellis-block2-snapshot irontrellis-next` (13,842 lines), NOTES-3.1/3.2/3.3/3.4, with the pre-3.2
tree (`…/scratchpad/pre32`, with its `dist`) as the "before" engine for differentials.

Method: I copied the tree to `/tmp/review-b3/tree` and built it there (`pnpm install --frozen-lockfile --offline && pnpm -r build`,
exit 0). Nothing under `/home/claude/irontrellis-next` was edited or rebuilt, and the background fuzz campaign was left
alone. Every PoC is under `/tmp/review-b3/poc/` and runs against the copy's `dist`. Outputs are saved beside the scripts
(`*.out`, `diff/*.log`).

## Summary

| Severity | Count |
|---|---|
| Blocker | 0 |
| High | 0 |
| Medium | 3 |
| Low | 5 |
| Nits | 4 |

I found no verdict change from the performance work. The parallel verification, the `verify()` digest shortcut, the
plausible-candidate pass, the SURVIVES index, the canonical key cache, the Python memo and the witness leaf bytes are
all equivalent to the pre-3.2 engine on everything I tried. That covers about 450,000 authorization comparisons, 2,514
mutated fuzz-corpus histories, and a TypeScript/Python comparison on actors with more than 230 candidates. The Medium
findings are about three things:

- a sibling of the "legacy history in a format-1 file" security fix that is still open in the Python library API;
- a release gate that does not gate the artifacts that actually get published;
- a test that claims to guard the riskiest part of the performance work but does not detect its removal.

---

## Medium

### M1. The Python library API still ACCEPTS an unsigned legacy history stored in a format-1 file (sibling of fuzz fix #4)

- **Where:** `python/src/irontrellis/store.py:136-167` (`read_history_text` / `read_history`) and `:223-232` (`load_events`).
  The rc.1 README quickstart was `stored = read_history(...); result = replay(stored.events)` (block-2 `python/README.md:16-19`).
- **Failure scenario:** Fix #4 changed only the CLI (`python -m irontrellis verify` now uses `replay_history`). The public
  functions still return a bare event list, and `replay(events)` picks its rules from the genesis. Take a file with
  `irontrellis-portable-file-store/1` lines (sha256 record chain) that carries a legacy history with no owner signatures:
  - `replay(read_history(p).events)` and `replay(load_events(p))` return ACCEPTED, format `continuity-event/0.2`.
  - The TypeScript store and `replay_history` reject it at position 0 with `EVENT_DATA_INVALID`.

  Any integrator who followed the rc.1 quickstart, or who uses the obvious `replay(load_events(p))`, keeps the
  behaviour the CHANGELOG calls a security fix. The new README sentence that tells users to use
  `replay_from(ReplayState(stored.format), …)` instead is easy to miss.
- **PoC:** `/tmp/review-b3/poc/py-loadevents.py`, which uses the regression vector's own file
  (`/tmp/review-b3/poc/legacy-in-f1.jsonl`). Output (`py-loadevents.out`):
  ```
  read_history format: irontrellis-event/1
  replay(load_events(p)): ACCEPTED None format continuity-event/0.2
  replay_history(p): REJECTED EVENT_DATA_INVALID 0
  ```
- **Suggested fix:**
  - Make `read_history_text` raise `StoreError` when `detect_format(events)` (the genesis) disagrees with the line
    format. TypeScript rejects such a file at position 0 anyway, so no valid file is lost, and every composition of the
    read API becomes safe.
  - Add a regression test for `replay(read_history(p).events)` and `replay(load_events(p))`.
  - Say in the CHANGELOG Security entry that code following the rc.1 quickstart was affected.

### M2. The release "verify-install" gate does not verify what is published

- **Where:** `.github/workflows/release.yml:75-80` (verify job) and `:131-138` (publish job).
- **Failure scenario:**
  - The `verify` job builds, packs and installs its own tarballs, then throws them away.
  - The `publish` job, a different runner, runs `pnpm install`, then `pnpm -r build`, then `pnpm publish -r`, which
    packs again. The tarballs that reach npm were never installed or checked by `verify-install`.
  - The comment "No release publishes what has not been installed from its own tarballs" is therefore not true.
  - Anything that differs between the two jobs goes to npm unverified: a non-deterministic build output, a different
    pnpm/Node patch release resolved by `pnpm/action-setup@v4` / `setup-node` (`PNPM_VERSION: 10`, `node-version: 22`),
    or a poisoned or stale pnpm cache (`cache: pnpm`).

  The gate is also not reproducible. At release time `verify-install` resolves the MCP SDK and TypeScript from ranges,
  `@types/node` can fall back to `*` (`scripts/verify-install.mjs:433-435`), and it runs `pip install build twine`
  unpinned (`:921`). So a release can fail, or run new third-party code, because of an upstream release on the day.
- **PoC:** reasoning, from the workflow text above.
- **Suggested fix:**
  - Pack once in `verify` and upload the `.tgz` files and their sha512 values as a workflow artifact.
  - In `publish`, download them and run `npm publish <file>.tgz --provenance --tag …` for each (provenance works with
    tarballs). As a minimum, repack in `publish` and refuse to publish unless every integrity matches the verified one.
  - Pin the third-party versions `verify-install` installs (a lockfile or exact versions) and the Python `build`/`twine`.

### M3. The plausible-candidate test does not detect removal of the incremental index maintenance (test quality, verdict-relevant path)

- **Where:** `packages/core/test/authority.test.mjs:1239-1256`, which is described as "Grown event by event: the index
  is built on first use and then maintained by indexCandidate (extendMemo)". The code it should protect is
  `packages/core/src/authority.ts:525-533` (`indexCandidate`, the `candidatesByResource` update).
- **Failure scenario:** I commented out the two lines that append a new path to an already-built per-resource index
  (in the copy's `dist/authority.js`; restored afterwards). With that mutant:
  - All 23 tests in `authority.test.mjs` pass, including both plausible-candidate tests.
  - My grown-state differential finds **618 wrong decisions** out of 12,600 for seed 1: different ALLOW proofs, and the
    wrong winner or a DENY where the pre-3.2 engine allows.

  The current code is correct: the same differential gives 0 differences on the unmodified build (below). But the
  regression test for the most verdict-sensitive performance change would not catch a future edit that breaks it. The
  likely reasons are that the grown-state loop runs only on the legacy-format generated corpora, and that its filtered
  grid rarely makes a newly added grant the unique or smallest successful candidate.
- **PoC:** `/tmp/review-b3/poc/diff/authz-diff.mjs <seed>`. It builds a random format-1 history through the owner API:
  many grants to one actor with overlapping actions and resources, `notBefore`/`expiresAt`, `maxTransactions`,
  `maxAmount`, delegations, non-independent partners, `requires`, ROOT and GLOBAL prohibitions, and revocations. It then
  compares, on a grid of actor × action × resource × time × amount, the pre-3.2 engine on a fresh replay, the new engine
  on one state grown event by event, and the new engine on a fresh replay.
  - Mutant: `diffs: 618`.
  - Original: 0 differences (see "Verified OK").
- **Suggested fix:** Add this differential, or an equivalent, to `authority.test.mjs`: a format-1 history, one actor with
  more than 32 candidates, a state grown with `applyEvent`, and queries both before and after grants are added. Mirror it
  in `python/tests/test_differential.py` (`/tmp/review-b3/poc/diff/py-incremental.py` does this for Python). Confirm
  that the new test kills the mutant above.

---

## Low

### L1. The hook tripwire's command rule is still easy to evade. Nothing new was introduced, but the Windows work left these open

- **Where:** `packages/hooks/src/protect.ts:141-167` (`SEGMENT`, `unquote`, `binaryOf`, `controlCommand`) and
  `packages/hooks/src/paths.ts:114-126` (`realpathLoose`).
- **Failure scenario:** Each of these writing commands passes `controlCommand` (rule 2) unflagged:
  - Package specs: `npx irontrellis@next grant …` (the docs' own invocation style) and `pnpm dlx irontrellis@1.0.0-rc.1 revoke g:1`.
  - The bin target: `node node_modules/irontrellis/dist/cli.js grant`.
  - Command substitution: `node $(command -v irontrellis) grant`. `SEGMENT` splits on `$(`/`)`, so the binary and the
    subcommand end up in different segments.
  - Shell quote concatenation: `irontrel''lis grant`, `irontrellis gr''ant`, `irontrellis 'gr'ant`, `irontrellis $'grant'`.
  - `echo grant | xargs irontrellis`.
  - Windows `cmd.exe` caret escapes: `iron^trellis grant`, `irontrellis gr^ant`.
  - PowerShell backtick escapes: ``iron`trellis grant``.

  On Windows the path rule (rule 1) can also be evaded with 8.3 short names (`…\IRONTR~1\HISTOR~1.JSO`, where
  `.irontrellis` becomes `IRONTR~1`). `realpathLoose` uses the JavaScript `realpathSync`, which does not expand short
  names, and the string check never sees `.irontrellis`. (Reasoning only; there is no Windows host here.)

  All of these bypasses are pre-existing, and the docs say the rules are a tripwire, not a boundary. Block 3 did not
  make anything worse: over 300,000 random commands, block 3 caught a strict superset of what block 2 caught (22,321
  more), and it closes `IRONTRELLIS grant` on case-insensitive macOS and Windows shims.
- **PoC:** `/tmp/review-b3/poc/hook-bypass.mjs` (block 3 against block 2, table in `hook-bypass.out`) and
  `/tmp/review-b3/poc/hook-superset.mjs`.
- **Suggested fix:** These are cheap and remove the common evasions:
  - In `binaryOf`, strip a `@version` suffix and the package scope.
  - Before matching, normalize each word by deleting every `'`, `"`, `^` and backtick, plus `$'…'` quoting.
  - Do not split `$( … )` away from the arguments that follow it. Better, flag any segment that contains a control
    binary name together with a writing subcommand anywhere in the command.
  - On win32, use `realpathSync.native`, which expands 8.3 names.
  - Keep the "tripwire" wording.

### L2. `verifyLatestNote` / `verify_latest_note` fail open on a non-plain expectation

- **Where:** `packages/core/src/transparency/latest.ts:146` and `python/src/irontrellis/transparency.py:952`.
- **Failure scenario:** Fix #9 made "a non-record expectation expects nothing" the rule in both languages. A caller who
  passes the nonce in any shape other than a plain dict or object gets every check skipped, so a replayed answer to
  another nonce is accepted. That includes a Python `MappingProxyType`, a `UserDict` subclass or a list, and a
  TypeScript `Map` or array. Internal callers pass literals, so this is API hardening.
- **PoC:** `/tmp/review-b3/poc/latest-expect.py` and `latest-expect.mjs` (`latest-expect.out`):
  - A dict or object with the wrong nonce gives `NONCE_MISMATCH`.
  - `MappingProxyType`, `UserDict` and a list give `ok: True`.
  - A TypeScript `Map` and an array give `true`.
- **Suggested fix:** Treat `undefined`/`None` as "no expectation" and check a plain record. Answer anything else with a
  fail-closed result, such as a new reason `EXPECTATION_INVALID`. Do this in both languages and add a vector.

### L3. Speculative verification: CPU over-subscription and cost for short-lived hook processes

- **Where:** `packages/core/src/crypto/parallel-verify.ts:84-94` (`verifyThreads`) and `packages/core/src/store.ts:397,430`.
- **Failure scenario:** `IRONTRELLIS_VERIFY_THREADS` is capped at 16 but not at the number of CPUs. Opening a
  3,011-event history on this 2-vCPU host (the fuzz campaign was running):

  | threads | wall | RSS |
  |---|---|---|
  | 0 | 1.17–1.25 s | 87 MiB |
  | 1 | 1.03–1.12 s | 103 MiB |
  | 4 | 1.24–1.28 s | 134 MiB |
  | 16 | 1.63–1.90 s | 250 MiB |

  With the default of `min(4, cores-1)`, every hook invocation (once per tool call) on a developer machine starts four
  workers, about 16 MiB each, for any history of 1,024 records or more.

  There is also a worst case for files with a bad signature. If the only bad signature is the last one, the open costs
  a full speculative replay plus a full sequential replay: roughly 1.5× the old cost before the error is reported.

  These are performance costs only. No verdict can change: a speculative result is used only when every queued
  verification succeeded, and I checked the discard paths.
- **PoC:** `/tmp/review-b3/poc/open-time.mjs <history>` with `IRONTRELLIS_VERIFY_THREADS=0|1|4|16`.
- **Suggested fix:** Clamp the thread count to `availableParallelism() - 1`. Consider a store option, or a higher record
  threshold, so the hook's short-lived process does not start a pool. Document the hook cost in PERFORMANCE.md.

### L4. `serve --reload-interval` accepts values that round to 0 ms, which gives a busy polling loop

- **Where:** `packages/witness/src/cli.ts:378-379,399`.
- **Failure scenario:** `--reload-interval 0.0001` passes validation. `Math.round(0.1)` is 0, so `setInterval(0)` calls
  `statSync` roughly every millisecond, forever.
- **PoC:** Serving with `--reload-interval 5` used 0 CPU ticks in 3 s. With `--reload-interval 0.0001` it used 21 ticks
  in 3 s (about 7% of a core, all polling).
- **Suggested fix:** Require either 0 (off) or at least 0.1 s, or reject values below 1 ms.

### L5. CI and release actions are pinned by tag, not by commit SHA (pre-existing convention, extended to the new jobs)

- **Where:** `.github/workflows/ci.yml` (`windows`, `verify-install`, `bench-quick`) and `release.yml`.
- **Failure scenario:** A moved or compromised tag of `pnpm/action-setup@v4`, `actions/setup-python@v5` and similar would
  run in the release pipeline. The `publish` job holds `NPM_TOKEN` and `id-token: write`.
- **Suggested fix:** Pin third-party actions by SHA, at least in `release.yml`, and let Dependabot update them.

---

## Nits

- **N1.** The lock reclaim compares `BigIntStats.mtimeMs`, which is integer milliseconds, where it used to compare
  fractional milliseconds. That loosens the "same file" check slightly. The pid and content comparison makes this
  harmless, but `mtimeNs` is the exact field. Locations: `packages/core/src/store.ts:1284` and
  `packages/witness/src/log.ts:461`.
- **N2.** The canonical key cache fills once and never evicts (`canonical.ts:264`). In a long-lived process (the witness
  server or the gateway), the first 4,096 distinct short keys stay forever. Attacker-chosen keys received early would
  permanently remove the speed-up. Memory stays bounded (≤ 4,096 keys of ≤ 128 characters) and correctness is
  unaffected.
- **N3.** The `jsonParseWithBigints` doc comment says the walk visits markers in "the order a `JSON.parse` reviver visits
  them" (`canonical.ts:691`). The new walk is pre-order: it checks the parent before its children. The old reviver was
  post-order. The new order matches Python's `from_plain`, which is the order that matters, and it only changes which
  error message or `limit` flag is reported for a malformed marker nested inside another malformed marker. Store
  verdicts are unaffected. Fix the comment.
- **N4.** A pin whose `previousPin` is an array or `{}` gives the note "the previous pin was at position undefined".
  Cosmetic.

---

## Verified OK (with evidence)

### Performance changes never change a verdict

**Parallel verification (`parallel-verify.ts`, `suites.ts`, `store.ts`)**
- The speculative result is used only when `settle()` finds every queued triple VALID. Then every answer the replay saw
  was the sequential answer, so its state or error is the sequential one.
- Every other path replays sequentially: any failure, `#failed`, or a pool that was dead or retired. Later answers after
  a failure are `false`, which only shortens the discarded run.
- The worker verifies exactly the queued bytes with the same `node:crypto` primitive and the same SPKI wrapping. An
  invalid point gives `null`, then `false`, in both threads. Uppercase credentials decode identically (Buffer hex).
- Claims use `compareExchange`, so each item is counted exactly once. On stall recovery the calling thread re-verifies
  CLAIMED items; a late worker write carries the same answer.
- No verification result is cached anywhere. The discarded speculative state is thrown away, and `MEMO` is keyed by
  state object, so nothing leaks into the sequential run.
- Custom hooks are never speculated. Only `defaultReplayHooks` is identity-checked.
- The worker is evaluated from a string, so no module is resolved in a packaged install.
- Restricted Node modes are safe:
  - Under `--permission`, `new Worker` throws, the pool is empty and replay is sequential.
  - Under `--disallow-code-generation-from-strings`, the worker still runs and produces the correct result.
- The environment variable is parsed as follows: NaN, negative and empty values give 0; values are capped at 16.
- Their test file `parallel-verify.test.mjs` is meaningful. It asserts `runs`/`discarded`/`queued`, the first error in
  both orders, and a stalled pool.

**`verify()` shortcut (`store.ts:449-458, 597-605`)**
- The digest is the running SHA-256 of exactly the bytes that were parsed:
  - `loadBytes` hashes the same buffer it replays.
  - `#extend` updates the digest with the same `readRange` buffer it applies.
  - Own writes set the digest to `undefined`.
  - A stale handle, `#error`, or a refused reload (`#stale = true`) disables the cache.
- `verify()` reads the file once and compares that buffer's length and SHA-256, so there is no gap between hashing and
  using the bytes (TOCTOU).
- An edit to the prefix after another writer's tail was read changes the hash, and the file falls through to a full
  recheck or replay (their test, plus my reasoning).
- Pin, attestation, anchors and witnesses are still judged on every call.

**Plausible candidates (`authority.ts`, `authority.py`)**
- A SUCCESS requires `c.actions.includes` and `c.resources.includes` on every grant of the graph, the main path's
  terminal grant included. Matching is exact; there are no wildcards.
- The plausible subset keeps its relative order, and `compareCandidates` is a total order ending in `candidateHash`.
- Administrative filtering is applied in the same way. Evidence is still computed lazily from the same candidate list.
- Differential against the pre-3.2 engine (`/tmp/review-b3/poc/diff/authz-diff.mjs`):
  - 29 seeds with the pass forced on (threshold 0): about 12,000 requests each, on a state grown event by event and on
    a fresh replay, 0 differences (`run-t0.log`).
  - 6 seeds at the default threshold of 32, with 400 operations: about 290 events and more than 200 candidates for one
    actor, 0 differences (`run-t32.log`).
- TypeScript against Python on actors with 231 and 238 candidates (600 cases each): 0 differences (`py-authz.py`).
- Python state grown event by event, with the memo and per-resource index extended by `_extend_memo`, against a fresh
  replay, at thresholds 0 and 32: 0 differences (`py-incremental.py`).
- A malformed request resource (a list, dict, number or `None`) is refused before the index is used: `INVALID_REQUEST`.
  No `TypeError`.

**SURVIVES index (`query-survives.ts`, `survives.py`)**
- Each `where` lookup is exactly `type === t && data[f] === v`. `undefined` behaves the same way on both sides, and
  SameValueZero differs from `===` only for NaN and -0, which are not protocol values.
- Results come back in ascending, de-duplicated order. The last assignment's `successionRuleId` and the first duty per
  intent (in insertion order) are preserved.
- Fuzz-corpus differential over 2,514 mutated and re-signed histories plus the v1 histories
  (`/tmp/review-b3/poc/diff/survives-diff.mjs`):
  - Replay verdict, code and position are identical between the pre-3.2 and current engines on every history.
  - On the 48 accepted histories, SURVIVES for every agent at two times and a full authorize grid: 0 differences out of
    8,478 comparisons.

**Other performance changes**
- **Canonical key cache:** the value depends only on the key text, `LIMITS` is frozen, errors throw before insertion,
  and memory is bounded.
- **Python `_scan_string` fast path:** ASCII strings cannot contain surrogates, and the escape count is identical.
- **Witness leaf bytes:** a line accepted by `parseLogLine` is exactly `canonicalEncode({entry, index})`. The keys are
  in order `entry`, `index` with no whitespace, so the slice equals `canonicalEncode(entry)`.

### Fuzz fixes (complete for their siblings, except M1 and L2)

- **Negative zero:** 10 spellings in a format-1 store line (`-0`, `-0.0`, `-0e0`, `-0E+0`, `-0.000e-3`, `-0e-0`, and
  the valid `0`, `0.0`, `0e5`, `0E-0`). TypeScript and Python agree on every one (`/tmp/review-b3/poc/negzero-diff.mjs`).
  Python's `json.loads` does accept `NaN`/`Infinity` literals, but the canonical layer rejects them, so the verdicts
  agree.
- **Legacy tagged numbers:** 19 spellings, including `24E+0`, `2.4e1`, `23.9999999999999999`, `0024`, `24.`, `NaN`,
  `1e400` and `-0.0`. TypeScript and Python agree on every one (`/tmp/review-b3/poc/tagged-diff.mjs`).
- **Pin fields of any JSON shape** (`null`, a string, an array, a number, `{head:null}` and similar, for both
  `attestation` and `previousPin`): strict open, inspect+verify, `allowUnpinned` and `acceptRollback` all give typed
  results, with no untyped exceptions (`/tmp/review-b3/poc/pin-shapes.mjs`).
- **`verify_latest_note` with a `None` expectation:** checked by key presence, which fails closed. The remaining gap is L2.
- **Record key validation order:** keys that look like integers (which JavaScript's `ownKeys` puts first) can never fail
  validation, so the first failing key is the same in both languages.
- **Long campaign seed 41:** `replay` (51,362 iterations) and `store` (33,829 iterations) finished with 0 failures. No
  failure files are newer than the ones already accounted for in NOTES-3.3.

### Windows changes

- **Mode checks are skipped only when `process.platform === "win32"`**, through `ownerOnlyModeEnforced()`. No
  environment variable, WSL detection or filesystem probe can turn them off. WSL and Cygwin report `linux`/`cygwin`, and
  `options.platform` is never taken from configuration.
- **`isFullyQualifiedPath` on POSIX** is exactly `path.posix.isAbsolute`, so the policy-file, gateway and hooks
  behaviour on POSIX is unchanged.
- **`replaceFileSync`:**
  - On POSIX it makes one attempt, and every error propagates.
  - On win32 it retries only EPERM/EACCES/EBUSY, then rethrows the last error.
  - Each attempt is an atomic rename, and the temporary file is removed on failure. No real error is masked; it is only
    delayed by up to 3 s on Windows.
- **Lock identity as bigint:** the store lock and stale-lock tests pass on POSIX (4/4 on the copy), and the reclaim
  comparisons use bigint on both sides. See N1 for the precision nit.
- **CRLF:** I inserted a single CR at every byte offset of the first five lines of a real history, 3,505 variants in
  total (`/tmp/review-b3/poc/crlf-proof.mjs`):
  - 362 were accepted, all with a state (head, prefix hashes, count) identical to the original.
  - 3,143 were rejected.
  - 0 were accepted with a different state.

  A whole file converted to CRLF gives the same state. A BOM is rejected with `INVALID_HISTORY`.
- **`.gitattributes`:** the only file containing CR is the OFL licence, which is marked `-text`.
- **Hook tripwire:** strictly stronger than in block 2 (see L1).

### Packaging and CI

- **Source maps:** all 107 shipped maps have relative sources only. `sourcesContent` contains no home, `/tmp` or
  scratchpad paths, no private keys and no npm, GitHub or AWS tokens. The only 64-hex constants are curve orders and
  protocol policy hashes. The test-only hooks (`setCandidateIndexThresholdForTests`, `setVerifyThreadsForTests`) are not
  reachable through the `exports` map.
- **`verify-install`:**
  - The registry listens on `127.0.0.1:0` only, and tarball paths are reduced to their basename.
  - The script never runs a publish command. Global installs go to temporary prefixes.
  - `@ramex-labs` is scoped to either the local registry or a dead port, with no fallback to npmjs. The unscoped
    `irontrellis` returns 404 from the local registry instead of being redirected.
  - The script removes npm, pnpm and IronTrellis variables from the environment, so npm tokens are never sent to the
    local registry.
- **CI:** `permissions: contents: read` and the `pull_request` trigger (not `pull_request_target`). The new jobs use no
  secrets. The `publish` job still requires `verify` and `test` and the `npm` environment. See M2 and L5.

### Tests run on the copy

- `parallel-verify.test.mjs`, `platform.test.mjs` and `fuzz-findings.test.mjs`: 26/26.
- `store.test.mjs` lock and stale tests: 4/4.
- `authority.test.mjs`: 23/23, and also 23/23 with the M3 mutant, which is the M3 finding.

I found no Linux skip that hides a failure. The new skips are win32-only, or apply when Python is absent, which the CI
test job cannot hit because it inserts `PYTHON_SRC` into `sys.path` and `cryptography` is optional.

---

## Fixes (2026-09-26, after the review)

Every fix is in `/home/claude/irontrellis-next` (no commits, no publish). The PoCs were copied to
`/tmp/claude-0/-home-claude/023dc7b3-a3f3-5640-a076-db2cd3e93baa/scratchpad/poc-now/` with `/tmp/review-b3/tree`
replaced by the fixed tree and rerun against its build. Their new outputs are saved there (`*.out`). The pre-fix
source is snapshotted beside them in `…/scratchpad/pre-fix/`. Build checkpoints: `pnpm -r build` at 09:48:40 and
09:57:06 (PDT). The long fuzz campaign (seed 41) finished at 09:46, so most of the measurements below ran on a quiet
machine; the exceptions are noted.

| Finding | Status | Evidence |
|---|---|---|
| M1 | Fixed | See M1 below: the PoC now raises `HistoryRejected` (`EVENT_DATA_INVALID`, position 0), and 5 new pytest cases |
| M2 | Fixed | See M2: the publish job publishes the verified tarballs; verify-install PASS 52/52 in both modes; actionlint clean |
| M3 | Fixed | See M3: the review's mutant now fails the new TS and Python differentials. The SURVIVES tests were checked by mutation: 3 mutants killed, 1 equivalent |
| L1 | Fixed (best effort, documented as such) | The PoC now flags 27 of the 29 cases; the 2 left are documented gaps. The new tripwire is a strict superset of both block 2 and pre-fix block 3 over 300,000 random commands |
| L2 | Fixed | TS and Python PoCs: `false` / `False` for every non-plain shape; new reason `EXPECTATION_INVALID`; vectors added |
| L3 | Fixed | Thread count capped at the CPU count; break-even measured (about 300–400 records); hook uses 1 worker; PERFORMANCE.md §5.1.1 |
| L4 | Fixed | `--reload-interval 0.0001` and `0.5` now exit 2 with a clear message; `0` and `1` still serve |
| L5 | Fixed | Every `uses:` in the 3 workflows pinned by commit SHA with a `# vX.Y.Z` comment; `.github/dependabot.yml`; actionlint clean |
| N1–N4 | Fixed | See Nits |

### M1: the Python library API

- **Fix.** `python/src/irontrellis/store.py`.
  - `read_history_text`, and so `read_history` and the `.jsonl` branch of `load_events`, now checks the genesis right
    after line 1 is parsed.
  - If `detect_format(genesis)` differs from the line format (in either direction), the reader raises
    `HistoryRejected`, a new `StoreError` subclass exported from `irontrellis`. It carries `code`, `position` and
    `reason`, obtained by applying the genesis to an empty `ReplayState` of the line format, so they are exactly the
    TypeScript store's values.
  - The check runs before later lines are read, so defects are still reported in file order.
  - `replay_history(_bytes)` already used the line format.
  - The `.json` branch of `load_events` is a bare event array with no line format, so `replay` reads the format from
    the genesis there, as TypeScript's `replay` does.
  - The CLI, the conformance adapter and the fuzz worker go through `replay_history` or event arrays.
  - These are all the Python entry points that read a store.
- **Tests.** `python/tests/test_fuzz_regressions.py` has 4 new test functions (5 test cases): `review_m1_*`.
  - The review's PoC, on the regression vector's own file: `read_history`, `read_history_text`, `load_events`,
    `replay(read_history(p).events)` and `replay(load_events(p))` all raise `HistoryRejected(EVENT_DATA_INVALID, 0)`
    with `replay_history`'s reason.
  - The reverse mismatch: a format-1 history re-encoded as legacy lines.
  - The file order: a genesis rejection comes before a later record defect.
  - A check against the TypeScript store's message for both files. That test found that `openHistoryStore` is lazy,
    so the test calls `state()`.
- **PoC rerun** (`poc-now/py-loadevents.out`): `read_history(p)` raises
  `HistoryRejected: line 1: history rejected at position 0: EVENT_DATA_INVALID: $.data.ownerKeys: is required`.
  TypeScript reports `history rejected at position 0: EVENT_DATA_INVALID ($.data.ownerKeys: is required)`.
- **Docs.** `python/README.md` and the CHANGELOG Security entry, which says that code following the rc.1 quickstart
  was affected.

### M2: the release gate publishes what it verified

- **`release.yml`.**
  - `verify` packs every publishable package once into `$RUNNER_TEMP/release-tarballs`, with `pnpm pack` per package
    (which rewrites `workspace:*`), and writes `SHA512SUMS`.
  - It then runs `node scripts/verify-install.mjs --tarballs <dir> --json …`, runs `sha512sum -c` to confirm the
    tarballs are unchanged, and uploads `*.tgz` and `SHA512SUMS` (`actions/upload-artifact`, 14 days).
  - `publish` has no checkout, install, build or pack. It downloads the artifact and checks:
    - `sha512sum -c`;
    - that the file set equals the list;
    - that each tarball's `package.json` version equals the tag's.
  - It then runs `npm publish "$PWD/<file>.tgz" --provenance --access public --tag <next|latest>` for each tarball,
    core first. The path is absolute so npm 12 cannot read it as a git shorthand (EALLOWGIT).
  - A version already on npm is skipped only if `npm view … dist.integrity` equals the local sha512. Otherwise the
    job fails, so a re-run after a partial publish never publishes different bytes.
  - "Verify what npm now serves" now compares integrities, not just versions.
  - `github-release` attaches the same tarballs and `SHA512SUMS`.
  - The release jobs no longer use `cache: pnpm`, and pnpm is pinned to `10.17.1` (= `packageManager`) in all
    workflows.
- **Provenance.**
  - npm documents `--provenance` with `id-token: write` on GitHub-hosted runners and npm ≥ 9.5; `setup-node` 22 ships
    npm 10.
  - The statement's subject is the published tarball's sha512, signed with the publishing run's OIDC identity.
  - The npm docs do not discuss `npm publish <tarball>` explicitly, but the CLI's `<tarball file>` form goes through
    the same libnpmpublish path.
  - An independent project publishes verified tarballs this way with provenance in its publish job, using the
    `./`/absolute path workaround (see Sources).
  - Build and publish run in the same workflow run, so the attestation names the tag's commit and this run.
  - Sources: https://docs.npmjs.com/generating-provenance-statements/,
    https://github.com/npm/provenance/blob/main/README.md,
    https://github.com/Nick2bad4u/stylelint-plugin-file-progress/pull/10.
- **`scripts/verify-install.mjs`.**
  - New `--tarballs <dir>` mode. It implies `--skip-build`, skips `pnpm pack`, and requires exactly one
    `<name>-<version>.tgz` per publishable package and no other `.tgz`.
  - The pack row now prints each tarball's sha512, and `--json` includes `tarballs`.
  - The MCP SDK, TypeScript and `@types/node` are read from `pnpm-lock.yaml` (1.30.1, 5.9.3, 24.13.6). The script
    throws if the lockfile does not name them; there is no range or `*` fallback.
  - Python release tooling:
    - New `scripts/requirements-release.in` and `.txt`: `build` 1.6.1, `twine` 7.0.0 and `setuptools` 84.0.0 with
      every transitive dependency, exact versions and sha256 hashes. The `.txt` is generated with
      `uv pip compile --universal --generate-hashes`.
    - They are installed with `--require-hashes --only-binary :all:`, and the build runs with
      `python -m build --no-isolation`, so the pinned setuptools is the backend.
    - In CI (`CI` set), a failure to install them fails the row instead of falling back to the unpinned backend.
    - One step is deliberately left unpinned: "a second venv installs from the sdist (isolated build)". It checks what
      a user's `pip install <sdist>` does, and that includes fetching setuptools.
- **Python release.** There is no Python release workflow; it is manual (CHECKLIST.md §6). CHECKLIST now tells the
  release manager to build with the same pinned tooling and upload exactly the verified files. The CHECKLIST text on
  `release.yml` was updated too.
- **Runs.**
  - `CI=1 node scripts/verify-install.mjs --tarballs <scratch>/release-tarballs`: PASS, 52 passed, 0 failed.
    `sha512sum -c` afterwards: all OK.
  - `node scripts/verify-install.mjs --skip-build`: PASS, 52 passed, 0 failed.
  - The Python row reports `pinned build 1.6.1 setuptools 84.0.0 twine 7.0.0; twine check --strict passes`.
  - actionlint, with shellcheck, is clean.

### M3: the per-resource candidate index, tested by a differential

- **New tests.**
  - `packages/core/test/candidate-index.test.mjs` (about 15 s under load, 2 tests; `IRONTRELLIS_INDEX_DIFF=full`
    for about 10× more).
  - The generator is shared in `test/helpers/candidate-history.mjs`. It builds seeded random format-1 histories
    through the owner API: overlapping grants to one actor, `notBefore`/`expiresAt`, transaction and amount caps,
    delegations, non-independent grants, `requires`, ROOT and GLOBAL prohibitions and revocations.
  - The grant ids are random. This is essential: with increasing ids a late grant almost never sorts first, and a
    first version of the test passed with the mutant for that reason.
  - One state is grown with `applyEvent`. After **every** event, a grid (2 actors × 4 actions × 5 resources × 2
    amounts × 2 times) is decided on the grown state and compared, byte for byte (proofs included), with the naive
    reference: the full linear candidate loop (threshold `Infinity`) on a corpus validated from scratch. The
    reference is `{ ...state }`, a new memo key; every 25th event it is a fresh `replay`.
  - Two configurations:
    - the pass forced on (threshold 0: the index exists from the first query and must be maintained), 2 seeds;
    - the default threshold 32, where the actor crosses it mid-history (index built mid-growth, then extended).
  - Python mirror: `python/tests/test_candidate_index.py`. It gets the same histories from the generator via node
    and runs the threshold-0 differential against a memo-less copy with the pass off.
- **Mutation, TypeScript** (`src/authority.ts`, restored afterwards; `cmp` against the saved original):
  - The review's mutant (no `addByResource` on grant add): both new tests fail. Forced-on: after event 14. Default
    threshold: after event 78. The old `authority.test.mjs` still passes 23/23 with it.
  - Index keeps only the first resource: killed.
  - No action filter: survives, but it is equivalent (the pass only evaluates more candidates).
  - Index never stored (rebuilt per query): survives, but it is equivalent.
- **Mutation, Python** (`_index_candidate` without the index append; restored): fails after event 14.
- **SURVIVES index**, mutation-tested against `queries.test.mjs` and `owner.test.mjs`:
  - `where` key without the field: killed (3 and 1 failures).
  - `linksThroughAssignment` always false: killed (4 and 1 failures).
  - `where` ignoring the value: killed (4 and 2 failures).
  - `positionsIn` without the sort: survives. It is equivalent: the projection writer sorts every row's evidence in
    `finish()`, and the output budget is all or nothing.
  - Those tests were therefore not weak. I still added histories with chained `REASSIGNMENT` transfers to the
    reference differential (`queries.test.mjs` `reassigned-seed-1..6`), since the generator never produced a tenure
    that is opened by one transfer and closed by another.
  - Python's `survives.py` has no event index, so there was nothing to mutate there.
- **PoC reruns.**
  - `authz-diff.mjs`: seeds 1–10 at threshold 0 (11,700–12,600 comparisons each) and seeds 101 and 102 at threshold
    32 with 400 operations: **0 differences**.
  - `survives-diff.mjs 0 3000`: 2,507 histories, 41 accepted, 6,918 comparisons, **0 differences**, 0 replay
    differences.
  - `py-authz.py`: 600 + 600 cases, 0 differences.
  - `py-incremental.py` at thresholds 0 and 32: 1,152 checks each, 0 differences.

### L1: the hook tripwire

- **`packages/hooks/src/protect.ts`.**
  - `commandSpellings(command)` (exported) returns the command in several spellings:
    - as written;
    - POSIX-normalized: `$'…'`/`$"…"` become plain quotes; every `'` and `"` is deleted; backslash escapes are
      resolved; `$(`, `<(`, `>(`, backticks and parentheses become spaces, so a substitution no longer separates the
      binary from its subcommand;
    - Windows-normalized: `^`, backticks and quotes are deleted, and backslashes are kept;
    - the POSIX spelling with carets deleted.
  - Rule 2 flags a command if any spelling matches.
  - `binaryOf` now also recognizes:
    - a version or tag suffix (`@next`, `@1.0.0-rc.1`);
    - package names: `irontrellis`, and scoped `@ramex-labs/irontrellis-hooks` → `irontrellis-hook`;
    - a package's bin target run by `node`: `…/irontrellis/dist/cli.js`, `…/irontrellis-hooks/dist/cli.js`,
      `…/irontrellis-mcp-gateway/dist/ops-cli.js`, and `packages/cli|hooks|mcp-gateway/…` in a checkout.
  - `xargs <binary>` with no non-option argument is flagged: the arguments come from xargs's input.
  - The `env`/`command`/`exec`/`nice`/`timeout`/`sudo` prefixes were already covered, because the binary is looked up
    anywhere in the segment. They are now tested.
  - Rule 1 (paths) also matches the normalized spellings (`cat ~/.iron''trellis/…`).
  - On win32, `realpathLoose` uses `realpathSync.native` (8.3 short names). This is reasoning only; there is no
    Windows host here.
- **Tests.** `packages/hooks/test/tripwire.test.mjs` (7 tests) contains:
  - the whole review corpus (`hook-bypass.mjs` cases);
  - package runners (`yarn dlx`, `bunx`, `npm exec`, scoped, version-suffixed);
  - bin targets;
  - 15 prefixes;
  - allowed reading commands through the same wrappers (no false positives: `npx irontrellis@next verify`,
    `ls | xargs irontrellis verify`, `git grant-access; echo irontrellis`, `npm run grant`, …);
  - rule 1 through quote splicing;
  - a "known gaps" test that asserts what is **not** seen: a variable, an alias, PowerShell `("iron"+"trellis")`,
    `$(printf …)`, a script written earlier.
- **PoC reruns.**
  - `hook-bypass-now.out`: every case is flagged except `i=irontrellis; $i grant` and
    `& ("iron"+"trellis") grant`, the two documented gaps.
  - `hook-superset.mjs` against block 2: `missedByBlock3: 0, newlyCaught: 26794`.
  - The same against the pre-fix block 3 tripwire: `missed: 0, newlyCaught: 4473`, a strict superset.
- **Docs.**
  - `docs/SECURITY.md` and the hooks README now call the rules best-effort defence in depth.
  - The boundary is owner-key custody (the agent's OS user must not be able to read the owner key files) plus the
    hook's protected-path checks.
  - Both documents recommend running the agent as a different OS user than the owner.

### L2: `verifyLatestNote` / `verify_latest_note`

- **Fix.** The expectation is now required and must be a plain object: prototype `Object.prototype` or `null` in
  TypeScript, exactly `dict` in Python.
  - Its own keys must be exactly `historyId` (content-hash regex) and `nonce` (`isValidNonce`), plus an optional
    `origin` (a note line that is not a version line). Each field is type-checked.
  - TypeScript also refuses accessors, symbol keys and non-enumerable fields, and reads each field once.
  - Anything else is `{ ok: false, reason: "EXPECTATION_INVALID" }`, checked before the note. This covers: omitted,
    `null`, `{}`, `Map`, array, class instance, `MappingProxyType`, `UserDict`, a dict subclass, a missing, `null`,
    mistyped or malformed field, and an unknown or misspelt key.
  - `LatestNoteExpectation` is exported. `witness-client.ts` already passed `{ historyId, nonce, origin? }`.
  - The witness tests that passed `{ nonce }` only now pass `historyId`.
- **Vectors.**
  - `conformance/transparency/vectors.json`: 11 new or changed `latestNotes.verify` vectors. "No expectations" now
    expects `EXPECTATION_INVALID`. The conventions text was updated, and `--check` is clean.
  - Fuzz regressions: `latest-note-null-expectation` and `latest-note-null-nonce-expected` now expect
    `EXPECTATION_INVALID`, and `latest-note-array-expectation` is new. `make-regressions --check` is clean, with 17
    vectors.
- **Unit tests.** 24 shapes in `transparency-conformance.test.mjs` and 23 in `test_transparency.py`, including the
  review's PoC shapes.
- **PoC reruns** (`latest-expect.out`): a TS object with a wrong nonce gives `NONCE_MISMATCH`; a TS `Map` and an array
  give `false`; a Python dict with a wrong nonce gives `NONCE_MISMATCH`; `MappingProxyType`, `UserDict` and a list
  give `False`.

### L3: verification threads

- **Cap.** `IRONTRELLIS_VERIFY_THREADS` is capped at `os.availableParallelism()` (and 16). New
  `setDefaultVerifyThreads(n)` (exported) sets a process default, used only when the variable is unset and capped at
  cores − 1. It is tested in `parallel-verify.test.mjs`.
- **PoC** (`open-time.out`, 3,011 events): `=16` now runs 2 workers at 112 MiB, where the review saw 250 MiB.
- **Break-even** (`bench/threads.mjs open`, new; threshold lowered to 64 in a scratch copy of the build; quiet
  machine; process wall time without → with one worker):

  | records | without | with one worker |
  |---|---|---|
  | 256 | 266 ms | 271 ms |
  | 384 | 317 ms | 284 ms |
  | 512 | 340 ms | 318 ms |
  | 1,024 | 485 ms | 433 ms |
  | 10,000 | 2.85 s | 1.71 s |

  - A worker costs 13–17 MiB.
  - The break-even is about 300–400 records here. `SPECULATIVE_REPLAY_MIN_RECORDS` stays at 1,024: about 3× margin
    for loaded hosts and extra workers, and opens below it take under 0.5 s either way. This is documented.
- **Methodology note.** Under `node -e`, the pool's workers did not take work off the calling thread: the same open
  took as long with one worker as without. The bench therefore runs its probe from a file.
- **Hook.**
  - The bin calls `setDefaultVerifyThreads(HOOK_VERIFY_THREADS = 1)`. `IRONTRELLIS_VERIFY_THREADS` still overrides
    it, and a single-core host stays sequential.
  - Sequential verification was measured and rejected: it is the slowest setting.
- **Hook latency** (`bench/threads.mjs hook`: `irontrellis-hook check claude-code Write`, a whole process):

  | history | before, unset | after, unset | `=0` | `=1` | `=2` | `=4` (capped to 2) |
  |---|---|---|---|---|---|---|
  | 10k events | 1.97 s | 1.70 s | 2.78 s | 1.67 s | 1.91 s | 2.00 s |
  | 100k events | 13.9 s | 12.9 s | 24.7 s | 12.8 s | | 14.9 s |

  - The "before" column ran with the fuzz campaign on the other core; the rest ran on a quiet machine.
  - On this 2-vCPU host the default was already one worker, so the gap between the first two columns is load. The
    change matters on machines with 5 or more cores, which previously started four workers per tool call.
- **Docs.** `docs/PERFORMANCE.md` §5.1.1 (new) and the §9 "Cores" guidance, the hooks README, and
  `bench/threads.mjs`, whose usage is in §11.

### L4: `serve --reload-interval`

- **Fix.** `0`, or at least `MIN_RELOAD_INTERVAL_SECONDS = 1`. A smaller value is refused with a usage error, not
  clamped: `--reload-interval 0.0001 is below the minimum of 1 second (0 turns the reload off)`, exit 2.
- **Tests.** `platform.test.mjs` covers 0.0001, 0.0004, 0.05, 0.5 and 0.999. The Windows serve test now uses 1 s,
  with a longer wait.
- **Docs.** The help text, the witness README, `docs/WITNESS.md` and `docs/PLATFORMS.md`.
- **PoC** (`l4.out`): 0.0001 and 0.5 exit 2 with the message; 1 and 0 serve.

### L5: actions pinned

All 3 workflows pin every `uses:` to a 40-hex commit SHA with a `# vX.Y.Z` comment. For annotated tags, the commit
is resolved with `git ls-remote … refs/tags/<tag>` and the peeled `^{}` form.

| Action | Pinned tag |
|---|---|
| checkout | v4.4.0 |
| setup-node | v4.4.0 |
| setup-python | v5.6.0 |
| upload-artifact | v4.6.2 |
| download-artifact | v4.3.0 |
| softprops/action-gh-release | v2.6.2 |
| docker/setup-qemu-action | v3.7.0 |
| docker/setup-buildx-action | v3.12.0 |
| docker/build-push-action | v6.19.2 |
| docker/metadata-action | v5.10.0 |
| docker/login-action | v3.7.0 |
| pnpm/action-setup | v4.3.0 |
| sigstore/cosign-installer | v3.9.1 |

- For `pnpm/action-setup` and `sigstore/cosign-installer`, the floating major tag pointed at an older patch than the
  newest one, so they are pinned to the commit that CI was already running.
- `.github/dependabot.yml`: weekly updates for `github-actions` (grouped), `npm` (/) and `pip` (`/scripts` and
  `/python`).
- actionlint is clean.

### Nits

- **N1.** Lock reclaim in `store.ts` and the witness `log.ts` now compares `mtimeNs`.
- **N2.** The canonical key cache is cleared and refilled when full.
- **N3.** The `jsonParseWithBigints` comment now says pre-order (parent before children, as `from_plain`).
- **N4.** A `previousPin` that is not a record with a whole-number position now gives "there was no readable previous
  pin". There is a regression test in the `store.test.mjs` rollback test, and `n4.out` shows the note for `[]` and
  `{}`.

### Found along the way

- **Fuzz harness bug.** The long campaign of seed 41 (finished 09:46) recorded one new failure,
  `transparency/failures/d319bb376d19dd5f.json`: `HARNESS_ERROR: Cannot convert object to primitive value`.
  - Cause: the harness's `mutate` could overwrite `kind` with a dictionary value, and its feature label then threw.
  - Fix in `fuzz/targets/transparency.mjs`: `kind` is spread last, and the label is safe for any value. The input now
    checks cleanly.
  - It is not a product defect. Every other target in that campaign had 0 failures.
- **`pin-shapes.mjs`** gives typed results for every shape, as in the review.
- **`crlf-proof.mjs`**: 420 accepted, 3,622 rejected, **0 accepted with a different state**. A whole file in CRLF
  gives the same state, and a BOM gives `INVALID_HISTORY`.
- **`negzero-diff.mjs` and `tagged-diff.mjs`**: TypeScript and Python agree on every spelling.

### Full matrix (after the fixes)

- `pnpm -r build` and `pnpm -r lint`: clean. ruff: clean.
- Core suite, run alone: **547/547** (14 min 37 s).
- Other packages:

  | Package | Result |
  |---|---|
  | witness (e2e included) | 79/79 |
  | cli | 21/21 |
  | hooks | 35/35 |
  | mcp-gateway | 69/69 |
  | mcp-evidence | 11/11 |

- pytest: **247 passed, 3 skipped** (`cli-args` vectors have no Python check), 0 failed.
- Conformance, legacy 34/34 and v1 66/66 MATCH for each adapter:
  - node adapter;
  - python adapter.
- `conformance/transparency/generate.mjs --check`: up to date.
- Fuzz: `--smoke` gives 0 failure keys on every target; `--regressions` passes 17/17.
- Install and packaging checks:
  - `verify-install`: PASS 52/52, in both `--tarballs` and default modes;
  - `check-pack`: OK;
  - `check-versions`: OK (6 packages at 1.0.0-rc.1);
  - `pnpm install --frozen-lockfile`: up to date;
  - actionlint: clean.
