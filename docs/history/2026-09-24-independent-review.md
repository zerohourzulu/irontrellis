> **Pre-release internal review.** This report was written while IronTrellis 1.0.0-rc.1 was being built, before its first public release, and is kept verbatim as a record. Its findings were fixed before 1.0.0-rc.1 or are listed as known limitations in [docs/SECURITY.md](../SECURITY.md) §8. Paths under `/home/claude` and `/tmp`, internal build-stage names (an "rc.1" baseline, "blocks", "rc.2"), and design notes it cites (such as WITNESS-DESIGN or WIRE-DEVIATIONS) belonged to that development process and are not part of this repository. Code names, error codes and wire fields may differ from the released ones; [CHANGELOG.md](../../CHANGELOG.md) and the docs describe what shipped. See [README.md](README.md) in this folder.

# IronTrellis 1.0.0-rc.1: independent pre-release review

Reviewer: independent, fresh eyes. Date: 2026-09-24.
Method: a copy of `/home/claude/irontrellis` at `/tmp/it-review` (with `node_modules` and `dist` removed). I followed the repository's own instructions the way a stranger would, then tried to break it as an attacker and as an operator would. **The original repository was not modified.**
Environment: Linux, Node 22.22.2, pnpm 10.17.1, Python 3.11.15. I ran as root, so the read-only tests used `runuser -u nobody`.

---

## 1. Setup experience

### What worked (exact commands)

| Step | Command | Result |
|---|---|---|
| Install | `pnpm install --frozen-lockfile` | OK, 4 s, 108 packages |
| Build | `pnpm -r build` | OK, all 6 projects |
| Lint | `pnpm -r lint` | OK |
| Versions | `node scripts/check-versions.mjs` | `OK: 5 publishable package(s) at 1.0.0-rc.1, engines {"node":">=22.18.0"}` |
| Pack | `node scripts/check-pack.mjs` | All 5 `OK` (32/118/38/26/53 files) |
| Tarball install | `pnpm pack` for each package, then `npm install <5 tgz>` in an empty project | OK. `workspace:*` is rewritten to `1.0.0-rc.1`, and every bin is present and has a shebang |
| Novice | `node packages/cli/bin/irontrellis.mjs demo` | Works. The WHY/WHO/WHAT output is clear, and every follow-up command it prints works (`verify` exit 0, `authorize --actor alex …` exit 2 DENY) |
| Operator | `init`, `agent create`, `grant … --expires +7d`, `authorize` (exit 0), `why --json`, `verify --json`, `anchor --witness local --json`, `verify` | All work. `verify` shows `anchors position 3 via local-head-file: PREFIX_OK` |
| Developer | The README gate example, verbatim, as `gate.mjs` against the built core | Prints exactly `ALLOW` / `DENY ACTION_NOT_ALLOWED` / `ESTABLISHED [ 'collect' ]` / `REVOKED` |
| Hooks | `irontrellis-hook init --agent claude-code --allow run-shell --expires +7d`; `install claude-code --write`; `check … Bash` → ALLOW exit 0; `check … Write` → DENY exit 2; SessionStart and PreToolUse JSON on stdin | Work as documented. `install --write` merges into an existing settings file and is idempotent |
| Gateway | `irontrellis-mcp-gateway setup /abs/case` (both modes), driven by an SDK MCP client; `irontrellis-mcp-ops inspect`/`revoke` | Works. Exactly-once returns `RESPONSE_RETAINED`, then `RECONCILIATION_ONLY`; changed arguments are refused with `OPERATION_CONFLICT`. Per-call mode creates one ticket per call |
| Evidence MCP | `irontrellis-evidence-setup /abs/case`; `irontrellis-evidence-demo /abs/case/gateway.json` | `RECORDED`, then `RECONCILIATION_ONLY`, `packetVerified: true` |
| Python | `python -m venv`; `pip install -e python`; `python -m irontrellis verify|authorize|survives` on CLI-made histories | Works; the answers agree with Node |
| Conformance | `node conformance/run.mjs --suite all` with `adapters/node.mjs` and `adapters/python.py`; `pnpm test:conformance:legacy` | node 34/34 + 43/43; python 34/34 + 43/43; legacy reference 34/34 |
| Package tests | `pnpm test` in cli / hooks / mcp-evidence | 7/7, 13/13, 8/8 |
| Core subset | `node --test … test/owner.test.mjs test/store.test.mjs test/queries.test.mjs` | 70/70 (272 s) |

### What did not work

1. **Nothing is published.** `npm view` returns 404 for `irontrellis`, `@ramex-labs/irontrellis`, `-hooks`, `-mcp-gateway` and `-mcp`, and PyPI returns 404 for `irontrellis`. So today every quickstart in README fails for a customer: `npx irontrellis demo`, `npm install …` and `pip install irontrellis`. The names are free (not squatted). CHECKLIST item 11 already tracks this. The README also omits the `@next` tag an rc needs.
2. **The mcp-gateway test suite fails intermittently.** It gave 55/56. `timeout is not cancellation or permission to resend` (`packages/mcp-gateway/test/gateway.test.mjs:155-161`) failed 3 of 5 isolated runs with `actual: 'REFUSED'` (`reason: GATEWAY_UNAVAILABLE`, after about 315 ms). The test sets `timeoutMs: 300`, but that timeout also covers spawning the upstream, MCP initialize and `listTools`, and on this machine those take more than 300 ms. CI will go red at random.
3. **The git repository has zero commits.** Everything is untracked. `.ruff_cache/` sits in the tree and is not in `.gitignore`.
4. **CI never runs Python conformance.** `.github/workflows/ci.yml:81-82` and `:161-162` are gated on `hashFiles('conformance/run.py')`, and that file does not exist (the runner is `conformance/run.mjs`). The step is silently skipped in both jobs, including the "python-only" job.
5. Re-running the README developer example exits with a raw `IronTrellisError: HISTORY_EXISTS` stack trace. README does not say the example is one-shot.
6. `irontrellis-evidence-setup --help` **creates a case directory literally named `--help`** in the current directory (`packages/mcp-evidence/src/setup.ts:41-42`).
7. `irontrellis-evidence-demo --help`, or any bad config path, crashes with a raw `McpError: MCP error -32000: Connection closed` stack trace (`packages/mcp-evidence/src/client.ts`, no catch).

---

## 2. Findings ranked by severity

### Blocker

**B1. Rollback and truncation detection can be bypassed by deleting the pin. `verify` passes, and a revoked grant becomes ALLOW again.**
- Reproduction (a 10-event history in which `g2` is revoked at line 8 and an anchor is recorded at line 9):
  ```
  sed -i '8,10d' h.jsonl; rm h.jsonl.head          # the local witness log h.jsonl.anchors is left in place
  irontrellis --history h.jsonl verify              # VERIFIED, pinned head UNPINNED, anchors none — exit 0
  irontrellis --history h.jsonl authorize --actor a2 --action read --resource r:1   # ALLOW, exit 0 (was DENY REVOKED)
  ```
- Two variants give the same result:
  - Stripping `attestation` from a pin: verify passes, exit 0.
  - Restoring an old history together with its old pin while the local witness log holds a later owner-attested head (position 14 against a file of 11 events): `VERIFIED`, exit 0, and a revoked `g1` becomes ALLOW.
- Root causes:
  - A missing pin is `UNPINNED` and treated as fine (`packages/core/src/store.ts:374-391`, `:415`; `packages/cli/src/commands.ts:179-183`).
  - A missing attestation is not reported (`store.ts:820-823`).
  - The anchor check reads only `ANCHOR_RECORDED` events from inside the history (`store.ts:827-830`), so it can never disagree with the chain it is part of.
  - Nothing ever reads the witness log: `localWitness(...).verify` in `packages/core/src/anchor.ts:98` is not called from any verification path.
- Also, the next writer re-pins an `UNPINNED` file at its truncated head, which launders the truncation.
- Why this is a blocker: removing revocations is the attack the pin and the anchors exist to stop. SECURITY.md §"Head pinning" says the pin "closes the one gap chain hashing leaves open: silent truncation". An unprivileged writer defeats it by deleting one file in the same directory.
- Fix before release:
  - Treat `UNPINNED` (on a format-1 history with any control event after genesis) and a missing attestation as verification failures unless the operator passes an explicit flag.
  - Have `verify` consult the configured witness (at minimum `<history>.anchors`) and fail when the witness holds a head that is not a prefix of the file, or that is newer than the file's head.

**B2. Hooks quickstart: the supervised agent can grant itself any power, and the history verifies clean.**
- Reproduction, after `irontrellis-hook init --agent claude-code --allow run-shell`:
  - A PreToolUse for `Bash` with `irontrellis --history .irontrellis/history.jsonl grant esc --to claude-code --actions write-file --resources repo:/tmp/itw/app --expires +1d` is answered `allow`.
  - Running that command records a validly owner-signed grant.
  - The next `Write` is answered `allow (authority esc)`, and `irontrellis verify` reports `VERIFIED`.
  - `Read` of `.irontrellis/history.jsonl.owner-key.json` is also answered `allow` ("read-only under the policy").
- The documented mitigation does not work:
  - With `init --history /outside/…` the config `irontrellis-hook.json` still lives in the project, and it is not protected (mode 0644). Appending `"*"` to `policy.readOnly` turns `Write` into `allow` ("Write is read-only under the policy").
  - The hook runs as the same OS user as the agent, so a key under `~/.irontrellis/` can still be read by `run-shell`.
- Code: `packages/hooks/src/setup.ts:28` (default under `.irontrellis/`); owner key next to the history (`owner.ts:586-591`); config found by walking up from the cwd.
- HANDOFF lists "keys in the project directory" as a known limitation. SECURITY.md:39 and the hooks README ("the pinned head and the signed control events detect edits and rollbacks") suggest a signed record still protects you. In the default quickstart it does not: the agent's self-grants are indistinguishable from the owner's.
- Must fix or disclose prominently:
  - Default the owner key and config to a location the agent cannot write, with a separate OS user for real boundaries.
  - Refuse to `init` with `--allow run-shell` while the key is readable by the same user, or at least print a loud warning.
  - State plainly that "any run-shell grant is equivalent to owner authority under the default layout".

### High

**H1. A hook ALLOW is Claude Code's "allow", which (per the Claude Code hooks documentation) skips the host's own permission prompt.**
- The hook answers `permissionDecision: "allow"` for every ALLOWed side-effecting call, and for every tool on the `readOnly` list (including `WebFetch`, `WebSearch`, `Task`).
- After the quickstart (`--allow run-shell`), every Bash command, `rm -rf` included, is auto-approved where Claude Code would normally ask the user. `WebFetch` to any domain is also auto-approved.
- Installing the product therefore widens what the agent can do without asking. The README never says this.
- Code: `packages/hooks/src/hook.ts:168-179`; `protocols/claude-code.ts` `replyTool`.
- Not verified against a live Claude Code; the finding rests on the host's documented semantics.
- Recommended: on ALLOW and on read-only tools, return no decision (defer to the host), with "allow" as an explicit opt-in; document the trade-off.

**H2. The hook fails open on malformed tool events, which contradicts the README's "a broken gate that lets everything through is not a gate".**
- `PreToolUse` without `session_id`, with a non-string `session_id`, or with a non-string `tool_name`: the event is `ignored`, the hook exits 0 and prints nothing, so the host proceeds (`packages/hooks/src/protocols/claude-code.ts:45-46`).
- Invalid JSON on stdin gives exit 1 (`packages/hooks/src/cli.ts:152`), and the top-level catch also exits 1 (`cli.ts:160-162`). For Claude Code, exit 1 is a non-blocking error.
- Reproduction: `echo '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"x"}}' | irontrellis-hook claude-code PreToolUse` prints nothing and exits 0, while the same input with `session_id` gives `deny REVOKED`.
- The decision does not even use the session (see M3), so requiring it only creates a fail-open path.
- Fix: on tool events, any parse or validation failure should exit 2 (or answer deny) unless `failOpen` is set.

**H3. The Python verifier accepts a truncated migrated history that the Node engine rejects.**
- Reproduction: `irontrellis migrate legacy.jsonl new.jsonl`, then `sed '$d'` so the re-recorded prefix is incomplete.
  - Node: `INVALID_HISTORY … TRANSITION_INVALID (migrated prefix incomplete)`.
  - `python -m irontrellis verify n2.jsonl`: `"status": "ACCEPTED"`. `authorize` then gives ALLOW for an action whose revocation was cut off.
- Cause: TS `incompleteMigration` (`packages/core/src/replay.ts:124-138`) has no Python counterpart in `replay_from` (`python/src/irontrellis/replay.py` around lines 155-163). No conformance vector covers it.
- This breaks the claim that the two implementations accept or reject "at the same position with the same code". It also matters because OPERATOR.md §3 recommends the Python verifier as the independent scheduled check.

### Medium

**M1. Histories larger than about 512 MiB cannot be read, although the writer and the docs allow 1 GiB.** `splitLines` decodes the whole file into one JS string (`store.ts:208-216`), and V8's limit is 0x1fffffe8 characters. A 600 MB file gives `INVALID_HISTORY (history file is not valid UTF-8)`, a wrong diagnosis; `new TextDecoder().decode` throws `Cannot create a string longer than 0x1fffffe8 characters`. `FILE_CAPS` (`store.ts:77`) and `#write` (`store.ts:623`) let the store grow past that point, so the store can brick its own history. Fix: cap at 512 MiB, or parse line by line.

**M2. The gateway operator tool breaks at 8 MiB (about 10k events) while the gateway keeps writing.** `HISTORY_LIMIT = 8388608` (`packages/mcp-gateway/src/operations.ts:14`, `:64`, `:109`). `irontrellis-mcp-ops inspect` on an 8.5 MB history returns `{"status":"REFUSED","reason":"PRIVATE_FILE_INVALID"}`. `revoke` still works. The limit is not documented, and the error does not name it.

**M3. The hook's session admission and epoch "fencing" have no effect on decisions.** `decideTool` authorizes on `config.agentId` only (`packages/hooks/src/hook.ts:175`). A fenced, expired or never-admitted session gets the same answers. The README ("the older session is fenced, the new one supersedes it") suggests fenced sessions lose authority. Each SessionStart while another session is live also advances the epoch, so two parallel sessions fence each other on every start.

**M4. `irontrellis-hook init --history <existing file>` writes a config that cannot work, and reports success.** `packages/hooks/src/setup.ts:48-49` opens the history with the recorded owner, but `:62` writes `owner: options.owner ?? "principal:owner"`. Every later hook call fails `PROFILE_MISMATCH`: fail-closed on tool events, so it blocks everything. The init output still says "config … written" after recording a grant.

**M5. The pin and the anchors are only meaningful if every consumer runs the Node verifier.** The Python verifier does no pin or rollback check. That is documented in `python/README.md`, but OPERATOR.md §3 recommends it for scheduled checks without saying truncation will pass. Confirmed: after `sed -i '$d'`, `python -m irontrellis verify` reports `ACCEPTED`, exit 0.

**M6. Two consistency problems in how errors are reported.**
- `status`, `authorize`, `why` and the other readers report `HISTORY_EMPTY — The history file has no events` for a file with an incomplete last record or bad UTF-8, instead of `INVALID_HISTORY`. `packages/cli/src/history.ts:48` checks `store.format === undefined` before surfacing `store.#error`. OPERATOR §2 and §6 tell operators to expect `INVALID_HISTORY`.
- A crash in the middle of an append (a torn last line) bricks every reader and writer. `export` cannot be used to recover the prefix ("export on a truncated copy" means editing by hand), and there is no repair command.

**M7. No `.gitignore` is created for `.irontrellis/`.** `irontrellis-hook init` only prints "keep … out of version control". A routine `git add -A` commits the owner private key and the session keys.

**M8. The snapshot does not contain what OPERATOR.md says it does.** OPERATOR §7 says `snapshot` is "a consistent offline copy of history, records and configuration", and §2 recommends it for backups. The actual snapshot holds `history.jsonl`, the records and `snapshot.json` only. There is no `.head` pin, no anchors file, no owner key and no `gateway.json` (the gateway's own OPERATIONS.md:44 says so correctly). A restore from a snapshot is `UNPINNED` and cannot revoke.

**M9. Windows is likely broken for writes (not tested, plausible).** `fsyncDirectory` opens a directory with `openSync(dir, "r")` (`store.ts:320-327`), which fails on Windows. Every append would then report `WRITE_UNCONFIRMED` after the line was written, and the pin would never be written. No `"os"` field guards the packages, and HANDOFF says there is no Windows coverage.

**M10. Parallel writers fail instead of waiting.** Four concurrent CLI loops of 6 to 8 appends each: 3 writes per run failed with `HISTORY_CONFLICT` and no retry. Integrity held (verify OK, 40 lines). The message "Another writer changed the history while this command was running" is also shown for a held or garbage lock file, with no lock path in it.

### Low

- **L1. Lock reclaim race.** In `store.ts:744-761`, two processes can both judge a stale lock stale. One unlinks the other's fresh lock, and both then write. The chain check catches the second append, but the result is an `INVALID_HISTORY` file. A rename-based reclaim would avoid it.
- **L2. A pre-existing owner key file is reused silently.** `creationSigner` (`packages/core/src/owner.ts:586-591`) adopts a `<history>.owner-key.json` that is already there, so a planted or stale key becomes the new history's owner. OPERATOR §4 warns against reusing keys, but `init` does it for you.
- **L3. Key file permissions are not checked.** `loadOwnerKeyFile` (`packages/core/src/signer.ts:79-101`) accepts a world-readable key (tested with mode 0644) without a warning.
- **L4. Unsigned events can be appended by anyone who can write the file.** `TRANSACTION_INTENT_DECLARED` needs no signature (`packages/core/src/state.ts:492-498`). A file writer can squat intent ids or fill a `maxEvents` budget. This is minor next to B1 and B2.
- **L5. `migrate` accepts an unpinned or tampered legacy source and signs it under the new owner key.** `head -5 legacy.jsonl > l2.jsonl; migrate l2.jsonl n3.jsonl` succeeds and the revoked grant is ALLOW. Legacy files are unsigned, so migration launders edits. Require a `MATCHES` pin, or a flag.
- **L6. Non-constant-time secp256k1 signing is used outside tests.** The code says it is "for tests, tooling and local dev keys" (`crypto/secp256k1.ts`), but it also signs legacy (eip191) session keys in the hook, `session admit --new-key` and the gateway.
- **L7. Hook file-writing weaknesses.** `safeName` maps different host session ids to one key file (`a/b` and `a_b`, `hook.ts:79`). `writePrivate` and the handover writer open with `"w"` and follow symlinks (`hook.ts:80-85`, `:208`).
- **L8. Most CLI input errors are one opaque sentence.** `INVALID_INPUT — An argument is missing, malformed or refers to something the history does not know.` does not name the argument or the limit. Examples: an undocumented cap of 32 actions per grant (`packages/core/src/input.ts:129`), a 129-character id, a 100 KB id. `FAILED — fetch failed` and `FAILED — EEXIST…` also have no coded category.
- **L9. Gateway configuration errors carry no detail.** Every problem prints `GATEWAY_CONFIGURATION_UNAVAILABLE` with no reason: bad JSON, a relative path, mode 0644, an unknown flag, `setup --help`. `snapshot` into a non-0700 parent prints `STORAGE_UNAVAILABLE` without saying why.
- **L10. Some reports mislabel what they found.**
  - A malformed pin is reported as "the history file is shorter than its pinned head: events were removed".
  - After `verify --accept-rollback`, later `verify` runs show `rollback none`. The new pin has no attestation, and nothing shows `rollbackAcceptedAt` or the previous pin.
  - `WRITE_UNCONFIRMED … inspect the history file before retrying` is shown when `open()` itself failed with EACCES, so nothing could have been written.
- **L11. Performance on large histories.** Every hook invocation and every CLI command replays the whole history: about 3 s per call at 10.5k events. This is documented as O(history), but it is not visible from the hooks README, where it matters most.
- **L12. The reconcile-after-revoke case is not documented.** The gateway README says "after the revoke, the next `create_incident_ticket` answers DENIED". That holds only if the job never ran. A job that already ran answers `RECONCILIATION_ONLY` with the retained reply, which is correct behaviour but not what the README describes.

### Things I tried that held

- **Tampering the history file.** Editing a line, deleting a middle line, swapping two lines, dropping the trailing newline and cutting mid-record all fail `verify` with exit 1 and a coded `INVALID_HISTORY`.
- **Tampering the pin and the owner key.**
  - Bumping the pin's position or writing garbage into the pin gives `ROLLBACK_DETECTED`.
  - An altered pin signature gives `PINNED_ATTESTATION_INVALID`, exit 1.
  - With the wrong owner key, a write is refused before anything is written (`CONTROL_AUTHORIZATION_INVALID`).
- **Forgeries.** A control event forged with an attacker key claiming `owner:1` is rejected by both Node and Python.
- **Migrated prefixes.** Modified migrated-prefix control events fail their signatures.
- **Concurrent writers.** They never corrupted the chain.
- **Stale locks.** A lock left by a dead process on this host is reclaimed after 60 s; a live pid's lock is not.
- **Read-only files and directories.** Writes are refused cleanly, with no damage.
- **Oversized input.** Huge identifiers and lists are refused before they are written.
- **Large histories.** The engine handled 10,000 events: open 2.9 s, verify 3.4 s, DENY becomes `INDETERMINATE OUTPUT_LIMIT_EXCEEDED` as documented.
- **Gateway input guards.** The stdio guard refuses a 1 MB frame and duplicate JSON keys (`INPUT_REFUSED`).
- **Evidence packet copier.** It uses `O_NOFOLLOW`, rejects symlinks and hard links, and runs inode checks.
- **Hook paths and templates.** Hook session file names are sanitised against path traversal. Template rendering is single-pass, so there is no recursive `${}` injection. The per-call gateway `{arg}` resolution is limited to identifiers.
- **CLI argument parsing.** It is strict: unknown and duplicate options, bad times, negative positions and `1e5` amounts are all refused with coded `USAGE` errors.

---

## 3. Documentation checks (17 claims)

| # | Claim (where) | Verdict |
|---|---|---|
| 1 | "The CLI has 26 commands" (README) | **True.** `--help` lists 26 |
| 2 | "34 legacy vectors … 43 format-1 vectors", both implementations pass (README) | **True**, run for node and python |
| 3 | Developer example output (README) | **True**, verbatim |
| 4 | `@ramex-labs/irontrellis` has zero runtime dependencies; the CLI depends on core only | **True** |
| 5 | Store files (history, pin, lock, owner key, anchors) are mode 0600 (SECURITY.md:77) | **True.** `irontrellis-hook.json` is 0644, which the docs do not claim otherwise |
| 6 | HISTORY-FORMAT.md §3.2 two-line example is a complete valid history | **True.** Both Node and Python verify it |
| 7 | Exit codes 0/2/3 for ALLOW/DENY/INDETERMINATE; `--json` errors are one document (CLI README) | **True** |
| 8 | Stale lock older than 60 s from a dead local pid is reclaimed (OPERATOR §6) | **True** |
| 9 | Hooks: "Revocation takes effect at the next tool call" | **True** |
| 10 | Pinning "closes the one gap … silent truncation" (SECURITY.md:15) | **False.** Deleting the pin defeats it (B1) |
| 11 | "`verify()` shows that every anchored head is a prefix … a witness you trust lets you show that a copy is not older than the last anchor" (SECURITY.md:17). `anchor` prints "verify checks that every anchored head stays a prefix". README: `anchor` pins the head "somewhere the host cannot quietly rewrite" | **Misleading or false.** verify never reads the witness; the default local witness sits in the same directory (B1) |
| 12 | "files may grow to 1 GiB" / "1 GiB (format 1) is a hard stop" (OPERATOR §1, §5; SECURITY) | **False in practice.** About 512 MiB (M1) |
| 13 | "A history copied mid-append … which the store refuses as `INVALID_HISTORY`" (OPERATOR §2) | **Partly.** `verify` says so; every other command says `HISTORY_EMPTY` (M6) |
| 14 | `snapshot` is "a consistent offline copy of history, records and configuration" (OPERATOR §7) | **False.** No configuration, pin, anchors or key (M8) |
| 15 | Hooks: "a missing config, a missing history or a replay error refuses the call … because a broken gate that lets everything through is not a gate" | **Partly.** Malformed or incomplete events fail open (H2) |
| 16 | Hooks and SECURITY: move the history outside the working tree "when the agent must not be able to edit its own record" | **Insufficient.** The config stays in the tree, and the same OS user can still read the key (B2) |
| 17 | Gateway README: "After the `revoke`, the next `create_incident_ticket` answers `DENIED`" | **Only if the job never ran** (L12) |

Other inaccuracies:
- The README install lines (`npm install @ramex-labs/irontrellis`, `npm install -g irontrellis …`, `npx irontrellis demo`) will not resolve until something is published, and an rc may need `@next`.
- OPERATOR §3 recommends the Python verifier for scheduled checks without saying it ignores the pin (M5).
- SECURITY's "lists 4,096 members (smaller bounds for the authority sets)" hides a 32-actions-per-grant cap that a user hits with a generic error.
- CONTRIBUTING and CI imply Python conformance runs in CI; it is skipped (setup item 4).

---

## 4. Verdict: **not yet deployable to customers**

The engine itself is in good shape. Replay, signatures, the conformance vectors, the CLI's argument handling and the fail-closed decisions all held up under direct attack, and the setup paths work from a clean checkout. The problems are in the safety story around it: three promises customers will rely on do not hold today.
- **Rollback and anchoring:** deleting the pin defeats truncation detection, and `verify` never reads the witness (B1).
- **The hooks as a boundary:** the default layout lets the agent grant itself anything (B2). An ALLOW auto-approves calls in the host (H1). Malformed events fail open (H2).
- **The independent verifier:** the Python verifier disagrees with Node on migrated histories (H3).

### Must fix before release
1. **B1.** `verify` must fail, or at least exit non-zero, on `UNPINNED` format-1 histories and on missing pin attestations. It must check the configured witness log and fail on any head newer than the file or not a prefix of it. Correct SECURITY.md, OPERATOR.md, README and the `anchor` output to match.
2. **B2.** Change the hooks defaults so the owner key and the hook config are not writable or readable by the supervised agent, or refuse `--allow run-shell` in that layout without an explicit acknowledgement. Rewrite the Limitations section to say plainly that run-shell under the default layout equals owner authority.
3. **H1.** Stop auto-approving: defer to the host on ALLOW and read-only tools, with auto-allow as an opt-in, and document the behaviour.
4. **H2.** Make every malformed tool event fail closed (exit 2 / deny) unless `failOpen` is set.
5. **H3.** Port `incompleteMigration` to Python, add a conformance vector for it, and fix the CI step so Python conformance actually runs.
6. **The flaky gateway test** (setup item 2): fix it, or make the timeout exclude spawn and `listTools`.
7. **Release mechanics:** publish (or reserve) the names, make the first commit with the chosen identity, add `.ruff_cache/` to `.gitignore`, and add `@next` to the rc install lines.

### Should fix before 1.0.0
- M1 through M10, above all M1 (the 512 MiB ceiling), M2 (the 8 MiB ops limit), M4 (the `init` owner mismatch), M6 (`HISTORY_EMPTY` masking corruption) and M7 (no `.gitignore` for keys). Also the doc corrections in section 3, and L2 (silent key reuse) and L5 (migration laundering).
- The evidence CLI rough edges: `--help` creating a directory, and the raw McpError stack trace.
