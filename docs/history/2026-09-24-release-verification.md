> **Pre-release internal review.** This report was written while IronTrellis 1.0.0-rc.1 was being built, before its first public release, and is kept verbatim as a record. Its findings were fixed before 1.0.0-rc.1 or are listed as known limitations in [docs/SECURITY.md](../SECURITY.md) §8. Paths under `/home/claude` and `/tmp`, internal build-stage names (an "rc.1" baseline, "blocks", "rc.2"), and design notes it cites (such as WITNESS-DESIGN or WIRE-DEVIATIONS) belonged to that development process and are not part of this repository. Code names, error codes and wire fields may differ from the released ones; [CHANGELOG.md](../../CHANGELOG.md) and the docs describe what shipped. See [README.md](README.md) in this folder.

# IronTrellis 1.0.0-rc.1: release verification

Verifier: release verifier. Date: 2026-09-24.
Scope: re-check the fixes reported for REVIEW.md (B1, B2, H1, H2, H3, M1–M10) on a fresh copy, run every build, lint and test gate, and judge whether rc.1 is ready for customers to pilot under the npm `next` tag.
Environment: Linux, Node 22.22.2, pnpm 10.17.1, Python 3.11.15 (pytest 9.1.1), 7 GiB RAM, 28 GiB free disk. I ran as root.
Working copy: `/tmp/it-verify`, a fresh `cp -r` of `/home/claude/irontrellis` with `node_modules`, `packages/*/node_modules`, `packages/*/dist` and `python/.pytest_cache` removed. Reproduction data is under `/tmp/it-repro/`, and logs are under `/tmp/it-verify-logs/` and `/tmp/it-verify-core.log`. **The repository was not modified.**

**Summary.**
- All 15 gate commands pass, including the full core suite: 328 pass, 0 fail, 1 skip, and the skipped 600 MB test passes when run on its own.
- B2, H1, H2, H3 and M1, M2, M4, M6, M7 and M10 are fixed as described.
- **B1 is only partly fixed.** `verify` now fails with exit 1 in every variant. But writing a forged pin **without an attestation** at the truncated head (one small file write, no key) still makes the CLI readers and the hook answer ALLOW for a revoked grant. The next write, or the documented remedy `repin`, then launders the truncation so that `verify` passes, unless a witness log survives.

---

## 1. Command log

| # | Command | Result |
|---|---|---|
| 1 | `pnpm install --frozen-lockfile` | PASS (108 packages, 2 s) |
| 2 | `pnpm -r build` | PASS (6 projects, 13 s) |
| 3 | `pnpm -r lint` | PASS |
| 4 | `node scripts/check-versions.mjs` | PASS: `OK: 5 publishable package(s) at 1.0.0-rc.1, engines {"node":">=22.18.0"}` |
| 5 | `node scripts/check-pack.mjs` | PASS: 5 × `OK` (32 / 118 / 44 / 26 / 53 files) |
| 6 | `pnpm test` in `packages/cli` | PASS: 12/12 |
| 7 | `pnpm test` in `packages/hooks` | PASS: 22/22 |
| 8 | `pnpm test` in `packages/mcp-gateway` | PASS: 60/60. I ran it 3 times in full, and ran the previously flaky test "timeout is not cancellation…" 5 times on its own while the core suite loaded the machine: 5/5 |
| 9 | `pnpm test` in `packages/mcp-evidence` | PASS: 8/8 |
| 10 | `node conformance/run.mjs --adapter conformance/adapters/node.mjs --suite all` | PASS: legacy 34/34, v1 44/44 |
| 11 | `node conformance/run.mjs --adapter conformance/adapters/python.py --suite all` | PASS: legacy 34/34, v1 44/44 |
| 12 | `pnpm test:conformance:legacy` (extra) | PASS: 34/34 |
| 13 | `python3 -m pytest python/tests -q` | PASS: 140 passed (12 s). pytest was already installed |
| 14 | Core suite: `IRONTRELLIS_SKIP_LARGE_TESTS=1 node --test --experimental-strip-types --test-concurrency=1 'test/**/*.test.mjs'` | PASS: `# tests 329`, `# pass 328`, `# fail 0`, `# skipped 1` (the 600 MB test), no `not ok`, 13 min 01 s |
| 15 | Core large test run on its own (`--test-name-pattern="600 MB" test/large-history.test.mjs`) | PASS: wrote 620 MiB (10,708 events) in 31.6 s; open and replay took 17.2 s; verify OK; tail extension OK; torn tail reported as "incomplete record" |

Other checks:
- **CI.** The Python conformance step is now gated on `conformance/adapters/python.py`, which exists, so it will run (REVIEW setup item 4 is fixed).
- **`.gitignore`.** It now lists `.ruff_cache/`.
- **Git.** The repository still has **zero commits**. This is release mechanics, not a code defect.

---

## 2. Reproductions

### B1: rollback and truncation bypass. **Partly fixed**

Setup: a CLI history of 10 lines. `g1` is revoked at line 8, `g2` is revoked at line 9, and line 10 is `anchor --witness local`. Before tampering, `authorize --actor a2 --action read --resource r:1` gives DENY REVOKED (exit 2).

| Variant | `verify` | CLI readers (`authorize`, `why`, `status`, `export`, `handover`, `survives`, `responsible`) | Writers | Verdict |
|---|---|---|---|---|
| (a) Cut lines 9–10 and `rm h.jsonl.head`; the witness log stays | **exit 1**. `ROLLBACK_DETECTED`, with `PIN_MISSING` and `WITNESS_ROLLBACK` (the witness holds position 8 and the file ends at 7) | All exit 1, `ROLLBACK_DETECTED` / `PIN_MISSING`. No ALLOW | `grant` and `agent create` exit 1; nothing written | **Fixed** |
| (b) Strip `attestation` from the pin (file intact) | **exit 1**, `PIN_ATTESTATION_MISSING` | `authorize` DENY REVOKED (the file is intact) | — | **Fixed** (verify) |
| (b′) Cut lines 9–10 and write an **unattested pin** at the truncated head. The pin's fields are all public, so no key is needed | **exit 1**: `PIN_ATTESTATION_MISSING` + `WITNESS_ROLLBACK`. After also removing the witness log: exit 1, `PIN_ATTESTATION_MISSING` | **`authorize` → ALLOW (exit 0), `why` → ALLOW.** `status` exits 0 but prints `integrity 1 failed check` | **`grant` succeeds and re-pins the truncated head with an owner attestation.** With no witness log, the next `verify` exits **0** and a2 stays **ALLOW**. `repin`, the remedy the CLI README gives for `PIN_ATTESTATION_MISSING`, does the same: it writes an attested pin at the truncated head even while it reports `WITNESS_ROLLBACK` (exit 1, but the pin is written). With no witness log, `repin` exits 0 and the next `verify` exits 0 | **Not fixed: see R1** |
| (c) Restore an older history **and its older, validly attested pin**, while the local witness log holds a newer head (position 6 against a file ending at 4) | **exit 1**, `WITNESS_ROLLBACK` | **`authorize` → ALLOW for the revoked `g1`**, and `why` → ALLOW. `status` exits 0 and shows `witness ROLLBACK` | not tested | verify is fixed. Readers do not consult the witness: **see R2** |
| (c) in the hooks setup: revoke the hook's grant, `anchor`, then restore the older history and pin | `verify` exit 1 | **The hook's PreToolUse `Write` changes from `deny REVOKED` to ALLOW (no decision, deferred to the host)** | — | R2 applies to the hook gate too |

Also: in (a), a revoked grant never became ALLOW through the CLI readers. The `--json` error carries `reason: PIN_MISSING`.

### B2: the hooks quickstart lets the agent grant itself anything. **Fixed as a tripwire, disclosed as a boundary**

- **`init --allow run-shell`** without `--i-understand-same-user-risk` is refused (exit 1) with a clear explanation. With the flag, `init` prints a prominent same-user WARNING.
- **Default state location.** State lives in `$IRONTRELLIS_HOME/projects/<hash>/`, a 0700 directory with 0600 files. The project holds only `irontrellis-hook.json`.
- **PreToolUse results** after SessionStart (the same set the task asked for):
  - Bash `irontrellis --history <abs> grant esc …`: **deny `PROTECTED_COMMAND`**.
  - `npx irontrellis grant …`: deny `PROTECTED_COMMAND`.
  - `node …/irontrellis.mjs revoke g1`: deny `PROTECTED_COMMAND`.
  - Bash `cat <history>.owner-key.json`: **deny `PROTECTED_PATH`**.
  - Read of the owner key: **deny**.
  - Write to the history file: **deny**.
  - Write to `irontrellis-hook.json`, absolute or relative path: **deny**.
- **Documented bypass, confirmed.** A glob (`cat …/projects/*/history.jsonl.owner-k*`) gets past the rules, as the hooks README says ("tripwire, not a boundary"). The README now states plainly that "any run-shell grant is equivalent to owner authority" under the single-user layout.

### H1: ALLOW auto-approves in the host. **Fixed**

- An ALLOWed `Write` or `Bash` call gets exit 0, **no stdout** (no decision), and a reason on stderr: "left to the host's own permission check".
- Read-only tools (`Read`, `WebFetch`) also get no decision.
- `decisions.onAllow` / `onReadOnly` default to `"defer"`. The trade-off is documented.

### H2: malformed tool events fail open. **Fixed**

- **Claude Code.** Each of these gives **exit 2** with a reason on stderr:
  - no `session_id`
  - a numeric `session_id`
  - a numeric `tool_name`
  - a string `tool_input`
  - invalid JSON
  - empty stdin
  - a JSON array
- **Codex.** A malformed PreToolUse gives exit 2.
- **Cursor.** `beforeShellExecution` without a conversation id gives exit 2 and `{"permission":"deny",…}`.
- **Unknown session.** An unknown `session_id` gives **deny `SESSION_NOT_FOUND`**, so the session check now affects decisions (REVIEW M3).

### H3: Python accepts a truncated migrated history. **Fixed**

- Steps: `init --legacy`, a grant, a revoke, then `migrate legacy.jsonl new.jsonl`, then `head -n -1` to drop the last line.
- Node rejects it: `INVALID_HISTORY … TRANSITION_INVALID (migrated prefix incomplete)`.
- `python -m irontrellis verify` gives `REJECTED` / `TRANSITION_INVALID` / "migrated prefix incomplete", exit 1. `authorize` is also REJECTED, exit 1.
- The untruncated migrated file is `ACCEPTED`.
- The conformance v1 corpus now has 44 vectors, including this case.

### Mediums

| Item | Result | Verdict |
|---|---|---|
| M1 (512 MiB ceiling) | The line reader splits on 0x0A and never decodes the whole file. The 620 MiB test passes (see §1 #15) | **Fixed** |
| M2 (ops at 8 MiB) | History grown to 9.0 MB / 10,893 events with real grants. `irontrellis-mcp-ops inspect` exit 0 (4.1 s, `pinnedHeadStatus: MATCHES`), `revoke` exit 0 (6.1 s), `snapshot` exit 0 | **Fixed** |
| M4 (`init --history <existing>`) | For a history made with `--owner alice`, the config gets `"owner": "alice"`, and SessionStart and PreToolUse work (ALLOW, deferred). A mismatched `--owner bob` is refused, exit 1, and no config is written | **Fixed** |
| M6 (errors hidden as `HISTORY_EMPTY`) | A torn last line: `status`, `authorize`, `why` and `agent create` all report `INVALID_HISTORY … incomplete record`, exit 1. Bad UTF-8 in record 4: `INVALID_HISTORY … record 4: not valid UTF-8`. Recovery: cutting the partial line by hand restores the file (DENY REVOKED, `export` OK). There is no repair command, and OPERATOR.md does not spell out the torn-tail case (see R6) | **Fixed** (diagnosis) |
| M7 (keys committed by `git add -A`) | Default state is outside the project. `init --history .irontrellis/history.jsonl` writes `.irontrellis/.gitignore` (`*`), and `git add -A` then stages only `irontrellis-hook.json` | **Fixed** |
| M8 (snapshot contents, extra) | The snapshot now reports `pinnedHead: true` and `configuration: true`, with `gateway.json` and `history.jsonl.head` present | Fixed |
| M10 (parallel writers) | 4 concurrent loops × 8 `grant`: **32/32 succeeded**. Then 6 × 6: 36/36. Every `verify` exits 0. With a held lock, the command retries for about 2.2 s, then reports `HISTORY_CONFLICT` naming the lock path and the holder's pid and host. A garbage lock is named by path | **Fixed** |

### README

- **"Not published yet" note.** It is present, accurate and specific: it names CHECKLIST §C step 12 (Tag and publish), gives the from-clone path, and states that the `next` tag and `pip install --pre` apply once published.
- **Registry state.** `npm view irontrellis` returns E404, and PyPI `irontrellis` returns 404, as the note says.
- **Install lines.** Every install line in README.md and the package READMEs uses `@next`: `npx irontrellis@next demo`, `npm install @ramex-labs/irontrellis@next`, `npm install -g irontrellis@next @ramex-labs/irontrellis-mcp-gateway@next`, and the hooks, gateway and evidence installs. The Python README uses `pip install --pre`.
- **Developer example, verbatim**, against the packed core tarball in an empty npm project: it prints `ALLOW` / `DENY ACTION_NOT_ALLOWED` / `ESTABLISHED [ 'collect' ]` / `REVOKED`, exit 0. **A second run still crashes with a raw `IronTrellisError: HISTORY_EXISTS` stack trace**, and the README does not say the example runs only once (REVIEW setup item 5, still open; see R5).
- **Other quick checks.** `irontrellis demo --quiet` exits 0. `irontrellis-evidence-setup --help` prints usage and creates no directory. `irontrellis-evidence-demo --help` prints usage. A bad config path gives a one-line coded `REFUSED` (REVIEW setup items 6 and 7 are fixed).

---

## 3. Regressions and new findings (ranked)

No test regressions. Every suite passed, and the one flaky gateway test is now stable.

**R1 (High, blocking). An unattested pin is trusted on open. This still lets someone without the key undo a revocation, and the next write launders it.**

- **What happens.** The store's open path compares a pin only with the file's content (`pinStatus`, `packages/core/src/store.ts:485-489`) and never checks its attestation. The attestation is checked only in `verify()` (`store.ts:1113`).
- **Who can do it.** Anyone who can write the history directory can truncate the file and write a pin without an attestation at the new head. Every field of that pin is public (the head hash from `verify --json` or the error context, and the record hash from the next line's `previousHash`).
- **The results** (variant b′ above):
  - CLI readers, the hook and, by the same code path, the gateway answer **ALLOW for a revoked grant**.
  - The next writer (any `grant`) appends and re-pins **with the owner's attestation**, and so does `repin`, which the CLI README gives as the remedy for `PIN_ATTESTATION_MISSING`. From then on, `verify` passes unless a witness log that holds the removed head survives.
- **Why this is still B1.** The bypass costs the same as the original one (a file write in the same directory). It contradicts CHANGELOG §Security ("a party who can only write the history file can no longer … drop a revocation or roll the file back without detection") and SECURITY.md:15 ("refused on open").
- **Where it matters most.** The KMS signer deployment, which the hooks README recommends as the real boundary. There the file writer does not have the key, which is exactly the threat model the pin is meant to cover.
- **Suggested fix** (small):
  - Writers and `repin` must refuse to extend or re-attest a format-1 file whose pin has no valid attestation, unless the operator explicitly accepts it. `repin` must also refuse while any witness reports `ROLLBACK`.
  - Readers should treat `PIN_ATTESTATION_MISSING` like `PIN_MISSING`: refuse unless `allowUnpinned` is set.
  - For the KMS window, keep the previous attested pin in place until the new attestation arrives. `AHEAD` already covers the gap.

**R2 (Medium, acceptable for rc with disclosure). Decisions never consult the witness log.**

- **What happens.** Restoring an older history together with its own validly attested pin gives ALLOW for a revoked grant through `authorize`, `why` and the hook, even though `<history>.anchors` sits in the same directory and holds a newer owner-attested head.
- **What is correct.** `verify` fails (exit 1), and `status` shows `witness ROLLBACK`, but `status` exits 0.
- **Why it can wait.** SECURITY.md:17 promises this only for `verify()`, and SECURITY.md:35 puts "a backup restore" outside the model for local pins.
- **Disclose** plainly in SECURITY.md, OPERATOR.md and the hooks and gateway READMEs that decisions check the pin but not the pin's attestation (until R1 is fixed) and not the witnesses, and that only `irontrellis verify` does. So `verify` must run after every restore and on a schedule, as OPERATOR §3 already says.
- **Consider** consulting `<history>.anchors` on open (it is small), or at least making `status` exit non-zero when its integrity line reports a failure.

**R3 (Low, disclose). Legacy-format histories can still be truncated with the pin deleted, and it is undetectable.**
- `init --legacy`, a grant, a revoke, then cut the revoke and `rm l.jsonl.head`: `verify` exits 0 (with the note `PIN_UNPINNED`), and `authorize` gives ALLOW.
- This is by design and documented (SECURITY.md:88: legacy is unsigned; migrate).
- `init --legacy` still exists for new histories, and its help does not warn about this.

**R4 (Low). The hook's protective rules do not cover the host's own hook settings.**
- An `Edit` of `.claude/settings.json` (which holds the IronTrellis hook registration) gets "no decision" and is left to Claude Code's prompt. With `decisions.onAllow: "allow"` it would be auto-approved.
- The README's real-boundary section already says to keep the host hook settings where the agent cannot edit them. Adding `.claude/settings*.json`, `.codex/hooks.json` and `.cursor/hooks.json` to the protected paths would make the tripwire match.

**R5 (Low, docs). Carry-overs and stale counts.**
- The README developer example crashes with a raw `HISTORY_EXISTS` trace when run twice (REVIEW setup item 5).
- CHANGELOG.md:22 and HANDOFF.md:16 still say "26 commands". The CLI now has 27 (`repin` was added) and README.md:82 correctly says 27.
- The git repository still has no commits.

**R6 (Low, docs). A torn last record has no repair path.**
- A crash in mid-append leaves every reader and writer failing with `INVALID_HISTORY … incomplete record`.
- The fix is to cut the partial line: I checked that this restores a working file, because the pin is at the last complete record. OPERATOR.md "Corrupt file" says instead to restore from a copy or export the valid prefix to a new history, which is heavier than needed.
- Document the one-line cut, or add `irontrellis repair --drop-incomplete-tail`.

Not re-verified, per scope: M3 beyond the session-not-found check, M5 (now documented in OPERATOR §3), M9 (Windows; only HANDOFF.md:120 mentions it, and there is no `"os"` field), and L1–L12.

---

## 4. Verdict

**Not ready to tag rc.1 for customer pilots until R1 is fixed. R1 is the one blocking item, and it is small.**

The rest of the release is in good shape:
- Every build, lint, pack, version, package, conformance (Node and Python, 34 + 44), pytest (140) and full core (328/0/1, plus the 620 MiB test) gate passes on a clean copy.
- The previously flaky gateway test is stable.
- B2, H1, H2, H3 and every medium I re-tested (M1, M2, M4, M6, M7, M10, plus M8) are fixed as described.
- The README's "Not published yet" note and the `@next` / `--pre` install lines are accurate.

**Blocking: R1.** B1's own acceptance criterion ("a revoked grant must not become ALLOW through the CLI readers") fails. Writing a pin without an attestation, instead of deleting the pin, gives the same keyless undo of a revocation. The next ordinary write, or the documented `repin`, turns it into a history that `verify` passes when no witness survives. Making writers and `repin` refuse an unattested format-1 pin, and making readers treat it like a missing pin, closes this. I would re-run §2 B1 (b′) after the fix.

**Acceptable for rc with disclosure:**
- R2: decisions do not consult witnesses; say so and require `verify` after restores and on a schedule.
- R3: legacy truncation is undetectable.
- R4: host hook-settings files are not protected.
- R5 and R6: docs and ergonomics.
- The already-documented limits: same-user hooks are a tripwire, not a boundary; Rekor is beta; no Windows coverage.
