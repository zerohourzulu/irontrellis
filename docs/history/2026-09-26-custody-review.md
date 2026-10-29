> **Pre-release internal review.** This report was written while IronTrellis 1.0.0-rc.1 was being built, before its first public release, and is kept verbatim as a record. Its findings were fixed before 1.0.0-rc.1 or are listed as known limitations in [docs/SECURITY.md](../SECURITY.md) §8. Paths under `/home/claude` and `/tmp`, internal build-stage names (an "rc.1" baseline, "blocks", "rc.2"), and design notes it cites (such as WITNESS-DESIGN or WIRE-DEVIATIONS) belonged to that development process and are not part of this repository. Code names, error codes and wire fields may differ from the released ones; [CHANGELOG.md](../../CHANGELOG.md) and the docs describe what shipped. See [README.md](README.md) in this folder.

# Block 4 (owner-key custody): independent adversarial review

Reviewer: independent (did not write this code). Date: 2026-09-26. Time box: about 60 minutes.
Tree under review: `/home/claude/irontrellis-next` (read-only). I copied it to `/tmp/review-b4/tree` and rebuilt it there with `pnpm -r build`.
PoCs are in `/tmp/review-b4/poc/`. Each `poc-*.out` file is the captured run.

Setup for the cross-user PoCs: `poc-00-setup.sh`, run as root. It creates the users `ownr` (the owner) and `agnt` (the agent) in the group `itg`, starts a `hashicorp/vault:1.20` dev container on 127.0.0.1:18200 with `transit/owner` (ed25519), and gives the owner a least-privilege token in `~ownr/.vault-token`. Teardown: `poc-99-teardown.sh`, which has been run. No container, user or listener I started is still running. The ssh-agent at `/tmp/claude-0/sshproto` belongs to an earlier session and was left alone.

## Summary

The core signing path is solid:
- Every backend signature goes through `referenceSigner`, which verifies it locally.
- The reference loader's mode and uid checks are done on the opened fd.
- The ssh-agent parser survived a malicious-agent fuzz.
- The Vault client keeps the token out of every output.

The weak spot is **`irontrellis doctor`**:
- **H1:** it contacts the signer named in a reference *before* checking that reference. The owner's Vault token, or any single-line file the owner can read, can therefore be sent to an agent-chosen address.
- **H2:** in exactly the recommended two-user layout, `--as-agent` never looks at the signers. It exits 0 while the agent holds a working owner Vault token.

## High

### H1. `doctor` sends the owner's Vault token, or any single-line file the owner can read, to an address chosen by the agent
- **Where:**
  - `packages/cli/src/doctor.ts:82-88`: `referenceIn` parses plain JSON with no mode or uid check.
  - `doctor.ts:385-388`: `signerFindings` runs on that parsed reference.
  - `doctor.ts:392`: the loader check comes afterwards and is only a WARN (`REFERENCE_REFUSED`).
  - `packages/core/src/custody/vault-transit.ts` `tokenOf`: the token comes from the reference's `tokenFile`, else `VAULT_TOKEN`, else `~/.vault-token`.
- **Scenario:**
  - The agent runs as a separate user but can write the history directory. Doctor does not flag this (see M1). A group-writable directory with no sticky bit is enough.
  - The agent renames `h.jsonl.owner-key.json` away and plants its own `vault-transit` reference at that path. The planted file is mode 0644 and owned by the agent. It names `address: http://127.0.0.1:<agent port>` (loopback, so the https rule passes), and optionally a `tokenFile` pointing at any file the owner can read.
  - The owner runs `irontrellis doctor h.jsonl`. `checkVaultKey` then does `GET /v1/transit/keys/owner` with `X-Vault-Token: <owner token>` to the agent's listener.
  - The owner loader itself refuses that file (mode 0644, foreign uid), so only doctor is exposed. That contradicts CUSTODY.md §1: "a reference … is refused unless it is 0600 and owned by the user running IronTrellis".
- **PoC:** `poc-01-doctor-vault-token-exfil.sh` → `poc-01.out`
  ```
  FAIL SIGNER_KEY_UNAVAILABLE … at http://127.0.0.1:18299 …
  WARN REFERENCE_REFUSED … has mode 0644 …
  agent captured token: hvs.CAESIIVD...
  RESULT: agent got owner signature vault:v1:LjQaa5Jh…
  ```
  The agent then signs with the real owner Transit key.
- **Variant:** `tokenFile: "/home/ownr/.git-credentials"` (see `poc-01b.out`). The agent's listener received `https://ownr:ghp_SECRET…@github.com`. Any file the owner can read whose trimmed content matches `^[\x21-\x7e]{1,4096}$` is exfiltrated: `.git-credentials`, `.npmrc` auth lines, other token files.
- **Fix:**
  1. In doctor, obtain references only through `loadOwnerKeyFile` / `loadNextOwnerKeyFile`.
  2. When the loader refuses a reference, report `REFERENCE_REFUSED` as **FAIL** and do not contact its signer. Never read its `tokenFile` or `caFile`.
  3. Consider `O_NOFOLLOW` in the loader (see L4).
  4. Change the test at `packages/cli/test/doctor.test.mjs:121`, which currently only expects a WARN for a 0644 reference. It should assert that the socket or Vault named by the loose reference received **zero** requests.

### H2. `doctor --as-agent` gives a false OK in the recommended layout: the agent's user holds a working owner Vault token and doctor exits 0
- **Where:** `packages/cli/src/doctor.ts:385-388`.
  - The signer checks run only on references the *current* user can read.
  - In the CUSTODY.md §8 layout (reference 0600, owned by the owner), the agent's user cannot read the reference. `referenceIn` returns `undefined` and no signer finding is produced at all.
  - `VAULT_TOKEN_IN_ENVIRONMENT` is also suppressed under `--as-agent` (`&& !asAgent`, around line 400).
  - The same applies to an `SSH_AUTH_SOCK` in the agent's environment that reaches the owner's agent.
- **PoC:** `poc-02-doctor-as-agent-false-ok.sh` → `poc-02.out`. The layout is directory 0750 `ownr:itg`, history 0640, reference 0600. The agent has `VAULT_TOKEN=<owner token>`.
  ```
  6 OK · 2 WARN · 0 FAIL   exit=0
  --- the same agent signs as the owner:  {"data":{"key_version":1,"signature":"vault:v1:…"}}
  ```
  - `KEY_MATERIAL_NOT_READABLE` also says "cannot read the owner key material in …owner-key.json", but that file is a reference (see L7).
- **Related, code-read only, not run:** when the reference is readable, `checkVaultKey` probes with a key *read*. A token whose policy is `update` on `transit/sign/<key>` only, with no `read`, gets `PERMISSION_DENIED`. That maps to `OK SIGNER_NOT_REACHABLE` even though the token can sign.
- **Fix:**
  - Under `--as-agent`, when a reference exists but is unreadable, emit `SIGNER_NOT_EVALUATED` (WARN) rather than nothing.
  - Independently of the reference, probe what the agent's environment offers:
    - If `SSH_AUTH_SOCK` is reachable and lists an in-force owner or next public key from the history: FAIL.
    - If `VAULT_TOKEN` or a readable `~/.vault-token` is present: at least WARN, and FAIL when `VAULT_ADDR` answers a key read or sign for an in-force key.
  - Keep `VAULT_TOKEN_IN_ENVIRONMENT` under `--as-agent`, as a FAIL.
  - For Vault, treat `PERMISSION_DENIED` on the key read as "not proven unusable", not OK.
  - Add a cross-user doctor test that gives the agent's user a token and a socket (see M3).

## Medium

### M1. `doctor --as-agent` does not check whether the agent can write the history directory
- **Where:** `packages/cli/src/doctor.ts` has no directory-access finding.
- **Scenario:** with a group-writable directory, the agent can do all of the following:
  - rename or replace references (the precondition for H1);
  - delete `owner-next-key.json`, the only key able to rotate;
  - replace pins.
- **PoC:** during the H1 setup (`/srv/itpoc`, mode 0770), `doctor --as-agent --offline` run as `agnt` reported `7 OK · 4 WARN · 0 FAIL` (exit 0). The run is shown in the session log; reproduce with `poc-01` setup plus `runuser -u agnt -- … doctor … --as-agent --offline`.
- **Fix:**
  - FAIL `HISTORY_DIR_WRITABLE` when `access(dirname(history), W_OK)` succeeds under `--as-agent`.
  - When run as the owner, WARN if the directory is group- or other-writable without the sticky bit.

### M2. Command signer: relative argv elements and the inherited cwd and PATH can make the owner run a program the agent controls
- **Where:** `packages/core/src/custody/command.ts:42` checks only `argv[0]` for being absolute. `command.ts:104` calls `spawn` with no `cwd`, so the child inherits the owner process's cwd and PATH (`commandEnvironment`).
- **Scenario:** the operator writes `argv: ["/usr/bin/node", "signer.mjs"]`. `signer ref` accepts it without a warning.
  - The owner runs `irontrellis grant …` from the agent's project directory, or the hook's SessionStart runs with cwd set to the project.
  - Node then executes `./signer.mjs` from the agent-writable cwd, as the owner.
  - Separately, the shipped examples resolve `gcloud` and `aws` through the inherited PATH (`examples/signers/gcp-kms-sign.mjs:37`, `aws-kms-sign.mjs:35`). A writable or relative PATH entry has the same effect.
  - The hooks' protect list only includes absolute argv elements (`packages/hooks/src/protect.ts` `custodyOf`), so a relative script is not protected either.
- **PoC:** `poc-03-command-signer.mjs`, case (a), run with cwd `cwdattack/` → `cwd-pwned.txt`: `ran as uid 0 cwd /tmp/review-b4/poc/cwdattack`.
- **Fix:**
  - Spawn with a fixed `cwd` (for example `/`, or the directory of `argv[0]`).
  - Refuse, or at least warn about, relative non-option arguments in `parse` and `signer ref`.
  - Pass a fixed PATH (`/usr/local/bin:/usr/bin:/bin`) unless `passEnv` names PATH.
  - Make the examples require `--gcloud` / `--aws` as absolute paths, or default them to absolute paths.

### M3. Test quality: the tests encode the H1 behaviour and never exercise H2
Specific gaps:
- `packages/cli/test/doctor.test.mjs:121` checks only that a 0644 reference produces WARN `REFERENCE_REFUSED`. It does not check that the loose reference's signer was *not* contacted, so the test passes against the H1 behaviour.
- The only real second-OS-user test (`doctor.test.mjs:325`):
  - checks only whether the history is readable;
  - never gives the agent a token or a socket;
  - skips on GitHub runners ("needs root").
  Nothing in CI therefore exercises `--as-agent` across users.
- The Vault `--as-agent` FAIL test runs as the same user (the reference is readable), which hides H2.
- `pnpm test:async-signers`, the §4.1 test-mode switch, is not run anywhere in `.github/workflows/ci.yml`. A regression to a sync-only path would pass CI.
- Positive: the Vault CI job uses external mode (`IRONTRELLIS_VAULT_ADDR`), so the Vault suites cannot skip silently in that job.

**Fix:**
- Add a "no contact on a refused reference" assertion.
- Add a cross-user doctor test that does not need root: use a matrix step with `sudo useradd` on ubuntu runners, or a container.
- Add `pnpm test:async-signers` to the ubuntu `test` job.

## Low

### L1. A pin attestation that fails after the write is reported the same way as a failure before the write
- **Where:** `packages/cli/src/history.ts:224`.
- **What happens:** a revocation whose post-write attestation is declined *is* recorded. Only the prose distinguishes this from a failure that wrote nothing. The CLI `--json` output is `{"error":{"code":"SIGNER_FAILED","context":{"reason":"EXIT",…}}}` with exit 1, the same code, shape and exit status as a signer failure before the write.
- **PoC:** `poc-07-post-write-attestation.sh` → `poc-07.out`. The history contains `AUTHORITY_REVOKED`, and a retry is rejected with "already revoked".
- **Risk direction:** safe. The history has the revocation and no caller is told a revocation happened when it did not. But scripts and the gateway may mis-handle it (alarms, retries, fallbacks).
- **Fix:** give it its own code (for example `WRITTEN_UNATTESTED`), or add `context.written: true` together with the event id and head, and a distinct exit code.

### L2. Command signer timeout does not bound the process lifetime, and stderr is echoed
- **Where:** `command.ts:109`, `command.ts:126`.
- **Problem:** `SIGKILL` reaches only the direct child. A grandchild keeps the pipes open, so the IronTrellis process lingers until the grandchild exits. The grandchild (for example `aws kms sign`) may even finish signing after IronTrellis has reported "nothing was signed".
- **PoC:** `poc-03`, case (b): the error came after 503 ms, but the process exited only after 5005 ms.
- **stderr:** the last three lines of the signer's stderr go into error messages and `--json`. Via SessionStart they can reach the agent's context, and a verbose cloud CLI's stderr may contain sensitive data.
- **Fix:**
  - Spawn `detached: true` and kill the process group; destroy the stdio streams on timeout.
  - Redact or cap stderr, or put it only in `detail` behind a debug flag.

### L3. Vault client: a synchronous `http.request` throw turns into a ReferenceError
- **Where:** `vault-transit.ts:181` calls `finish()` → `clearTimeout(timer)` before `const timer` is initialised at line 184.
- **Trigger:** an invalid header value, for example a `VAULT_NAMESPACE` from the environment with CR/LF or non-latin1 characters. The environment namespace is never validated, unlike `spec.namespace`.
- **Result:** `SIGNER_FAILED/BACKEND_ERROR: Cannot access 'timer' before initialization`. There is no header injection, because Node rejects the value.
- **PoC:** `poc-06-vault-tdz.mjs` → `poc-06.out`.
- **Fix:** declare `timer` before the `try`, and validate `VAULT_NAMESPACE` with the same rule as `spec.namespace`.

### L4. The loader follows symlinks; no in-force check before a signer is asked; CLI reference files are copied without checks
- **Where:** `packages/core/src/signer.ts:268` (`openSync(path, "r")`), `owner.ts:774`, `packages/cli/src/custody.ts:121`.
- **Symlinks:** an agent that can write the directory can point `h.owner-key.json` at *any* 0600 reference the owner owns (another history's reference, a retired archive). The fd owner check passes. `signControl` then asks that signer before checking that its key is in force. The signature is useless, but the owner may get a 1Password prompt or YubiKey touch request for a key that is not in force, or run that other reference's command.
- **CLI reference files:** `init --owner-key-ref`, `signer test --ref` and `--next-key-ref` read the operator-given file with no mode or uid check. They then copy its `signer` (argv, address, tokenFile) into the owner's own 0600 reference, which launders a reference kept in an agent-writable place.
- **Fix:**
  - Open with `O_NOFOLLOW`.
  - Check `ownerKeyInForce(state, next, signer)` before `signHash` in `signControl` and `signWith`.
  - Apply the loader's mode and uid rule, or at least warn, in `readReferenceFile`.

### L5. Hooks tripwires
- **PoC:** `poc-05-hooks.mjs` → `poc-05.out`.
- **Not flagged:**
  - `s=ssh-add; $s -D`
  - `ssh-keygen -Y sign …` (it uses the agent)
  - a raw `AF_UNIX` connect to `os.environ["SSH_AUTH_SOCK"]`
  - `curl -H "X-Vault-Token: $VAULT_TOKEN" $VAULT_ADDR/v1/transit/sign/owner`
  - `bao …` (OpenBao)
- **Separate-user layout:** `custodyOf` (`packages/hooks/src/protect.ts:111`) reads the references as the hook's user. In the §8 layout it cannot read the 0600 references, so the socket, token and command rules are silently empty. Doctor's `HOOKS_PROTECT_COVERS` is computed as the owner and does not show this. Code-read only, not run.
- These are documented as tripwires.
- **Cheap additions:** the literals `SSH_AUTH_SOCK`, `VAULT_TOKEN` and `/transit/sign/`; `bao` in `VAULT_BINARIES`; `ssh-keygen -Y sign`.

### L6. ssh-agent client robustness
- **Where:** `packages/core/src/custody/ssh-agent.ts:186` (`#receive`).
- **PoC:** `poc-04-ssh-agent-fuzz.mjs` → `poc-04.out`: 16 malicious-agent cases, with no crash, no uncaught exception, and every result within the timeout.
- **Minor issues:**
  - A second message delivered in the same chunk is never parsed. The client times out instead of failing at once.
  - Growing `Buffer.concat` is quadratic: a 100 KB list delivered in 64-byte drips added about 37 MB RSS before the timeout.
  - Trailing bytes after the outer signature string are accepted. This is harmless, because the signature is verified.
- **Fix:** loop in `#receive` while a full frame is buffered, and collect chunks in a list.

### L7. Doctor cosmetic issues
- `holdsMaterial` counts an *unreadable* file as key material. As a result `KEY_MATERIAL_NOT_READABLE` names the owner's 0600 **reference** as "owner key material" (`poc-02.out`).
- Code-read observation, not stress-tested: owner writes await the pin attestation inside `withExclusiveWriter` (`store.ts` `#underPinLock`, "at once when this instance holds it"). The writer lock is therefore held across an async signer, for example a 60 s 1Password prompt. Other writers (the gateway, hooks) get `STORE_BUSY` meanwhile. This is not a deadlock, but it is worth documenting or restructuring (sign outside the lock, then re-take the lock).

## Verified OK (with the evidence)

**Reference loader**
- Mode 0600 and owner uid are checked with `fstat` on the fd that is then read, so there is no check/use race (`signer.ts:268-297`).
- A foreign-owned or 0644 reference is refused by every owner path: `grant` and the other writes use `loadOwnerKeyFile`.
- Doctor is the exception (H1).

**Local verification**
- `backend.sign` has exactly one call site, `reference.ts:145`. It is followed by a length-64 check and Ed25519 verification against the reference's `publicKey`.
- Control authorizations, next-key proofs, rotation seals, pin attestations and witness-cache seals all go through `Signer.signHash`.
- I found no path that persists an unverified signature.
- `publicKeySigner` always throws `KEY_UNAVAILABLE`.
- `registerSignerBackend` cannot replace a built-in backend.

**ssh-agent parser (`poc-04.out`)**
- Length fields are capped: `0xffffffff` → MALFORMED at once.
- A count of `0xffffffff` → "too many keys".
- Truncated replies → CLOSED or TIMEOUT.
- `rsa-sha2-512` signature type → MALFORMED.
- A wrong signature → SIGNATURE_INVALID.
- An inner signature with trailing data → MALFORMED.
- A key blob with trailing data does not match (KEY_NOT_IN_AGENT).
- An sk-only key → KEY_UNAVAILABLE/FIDO_KEY.
- Unsolicited messages → MALFORMED.

**Vault**
- Plain http is allowed only to loopback (`localhost`, `127/8`, `[::1]`).
- 3xx answers are not followed (REDIRECT).
- Proxy environment variables are ignored.
- Token-like fields in a reference are refused.
- The token was absent from `doctor --json` and from `signer test --json` with a bad token (grep for `hvs.` and the bogus token found 0 matches).
- `key_version` is pinned, and the version in `vault:vN` is checked.
- A signature from another key is caught by local verification.
- Header injection through the namespace is blocked by Node (but see L3).

**Command signer**
- The environment is minimal. The PoC 03 child environment held only PATH, HOME and PWD. `SSH_AUTH_SOCK`, `VAULT_TOKEN` and `AWS_SECRET_ACCESS_KEY` set in the parent were **not** passed.
- No shell is used, and `argv[0]` must be absolute.
- stdout is capped at 64 KiB, and the child is killed with SIGKILL at the timeout.
- Node reaps the child, so no zombie is left.

**Doctor side effects**
- Doctor never starts a command signer (only `existsSync` and `access(X_OK)`).
- It never sends an ssh-agent sign request (only `REQUEST_IDENTITIES`).
- It never asks Vault to sign (only a key read).
- `--offline` contacts nothing.
- It opens the store with `inspect: true`.
- Its `KEY_MATERIAL_READABLE` check uses `access(2)`, which honours ACLs and group bits.

**Revocation**
- A revocation is in the history before the call returns: the control event is signed before the append, and the append is durable. An attestation failure after the write is surfaced (`poc-07.out`, see L1 for the wording).

**Pin rewrite**
- The late attestation re-reads, judges and writes the pin under the writer lock, and only replaces a pin for the same head or a later head that carries an older attestation. Checked by code review of `store.ts` around line 1120.

**CI**
- The Vault job uses the external service with `IRONTRELLIS_VAULT_*` set, so its Vault tests cannot skip silently.
- The ssh-agent tests skip only when OpenSSH is missing.

## Not covered in the time box
- Windows named pipe and ACLs.
- A real 1Password or gpg-agent.
- An independent re-run of the rotation crash windows.
- A concurrency stress test of the async attestation.
- Python verifier changes (none were made).
- The gateway's `ops revoke` JSON handling of L1.

## Fixes (2026-09-26, after the review)

Tree: `/home/claude/irontrellis-next`. Every PoC was re-run against it: copies with the tree path replaced are in `/tmp/rv-b4-poc/`, with the new outputs in `*.new`. The setup and teardown scripts were run, and no user, container or listener is left.

| finding | fix | PoC re-run |
|---|---|---|
| **H1** | Doctor reads every key file and reference through the core loaders only (`inspectKeyFile`: no symlink, 0600, a reference owned by this user, all checked on the opened fd). If the loader refuses a reference, doctor reports **FAIL `REFERENCE_REFUSED`** and contacts nothing: no socket, no Vault, and no `tokenFile`/`caFile` read. Signer paths for the protect list also come only from loaded references. A key file the owner cannot read is a FAIL in the owner's run (`KEY_FILES_NOT_READABLE`). | `poc-01` (0644 planted reference): `FAIL REFERENCE_REFUSED … its signer was not contacted`, plus `WARN HISTORY_DIR_LOOSE`, exit 1. Captured token: empty, and the agent's sign attempt fails. `poc-01b` (an agent-owned 0600 reference with `tokenFile: ~/.git-credentials`): `FAIL KEY_FILES_NOT_READABLE`, exit 1, and the listener got nothing. |
| **H2** | Under `--as-agent`, independently of the references: FAIL `VAULT_TOKEN_IN_ENVIRONMENT` (no longer suppressed) and FAIL `VAULT_TOKEN_FILE_READABLE` (`~/.vault-token`). `SSH_AUTH_SOCK` is listed only; FAIL `SSH_AGENT_HOLDS_OWNER_KEY` when the agent holds an in-force owner key or the committed next key (matched by digest). For a readable reference: FAIL `VAULT_TOKEN_READABLE` / `VAULT_CA_FILE_WRITABLE`, and an ssh-agent signer the agent can use is now a FAIL. A Vault `PERMISSION_DENIED` on the key read is WARN `SIGNER_NOT_PROVEN_UNUSABLE`, not OK. A reference unreadable as the agent is WARN `SIGNER_NOT_EVALUATED` ("not checked: … unreadable as this user"), so the best possible result is a WARN. The two-run procedure (owner run + agent run) is in CUSTODY.md §8. | `poc-02` with the owner's token: `FAIL VAULT_TOKEN_IN_ENVIRONMENT`, `WARN SIGNER_NOT_EVALUATED`, exit 1 (was 0). Same result with the sign-only token. |
| **M1** | `--as-agent`: FAIL `HISTORY_DIR_WRITABLE` and `SIDE_FILE_WRITABLE` (the history, pin, anchors, witness state, rotation record, lock, every key file); OK `HISTORY_NOT_WRITABLE` otherwise. Owner run: WARN `HISTORY_DIR_LOOSE` for a group- or other-writable directory without the sticky bit. | Covered by `doctor-users.test.mjs` (agent in a 0770 directory → FAIL); `poc-01`'s owner run → `WARN HISTORY_DIR_LOOSE`. |
| **M2** | The command signer runs with `cwd` set to the file-system root. `PATH` is `/usr/bin:/bin` (Windows: the system directories) unless the reference sets the new absolute `path` field; PATH can no longer come from `passEnv`/`env`. Every file-like argument must be absolute: it starts with `.` or `~`, or has a script or key extension, also inside `--opt=value`. Resource names, ARNs and URLs pass. The GCP/AWS examples require `--gcloud`/`GCLOUD` and `--aws`/`AWS` as absolute paths. | `poc-03` (a): refused at parse ("names a file by a relative path"), and `cwd-pwned.txt` is not written. |
| **M3** | The doctor test now asserts **zero** connections to the socket named by a refused reference, and a new same-user test asserts zero HTTP requests to a planted Vault reference. New `packages/cli/test/doctor-users.test.mjs` runs PoC 01/01b/02 with a real second user (uid 65534) and no Vault needed. CI (ubuntu `test` job) gains `pnpm test:async-signers` and a "Two OS users" step (`sudo node --test …doctor-users.test.mjs`). | — |
| **L1** | Chosen approach: a CLI code of its own. **`WRITTEN_UNATTESTED`**, exit status **4**, with `context.written: true`, `eventId`, `head` and `cause` (the signer's code and detail). The sentence says the event IS recorded and must not be retried. A failure before the write stays `SIGNER_FAILED`, exit 1. The library's `flush()` keeps its signer error, and its message already says "after the write". | `poc-07`: `WRITTEN_UNATTESTED`, exit 4, and the history holds `AUTHORITY_REVOKED`. |
| **L2** | The command signer is spawned detached. On timeout the whole group is killed (`kill(-pid)`; win32 `taskkill /T /F`) and its stdio is destroyed. stderr in messages is at most 3 lines and 240 characters, with control characters removed and credential-like runs replaced by `[redacted]` (`stderrTail`). | `poc-03` (b): rejected after 506 ms, and the process exits after 507 ms (was 5005 ms). |
| **L3** | `timer` is declared before anything can call `finish`. `VAULT_NAMESPACE` is validated with the `spec.namespace` rule (`SIGNER_FAILED`/`NAMESPACE_INVALID`). | `poc-06`: `SIGNER_FAILED NAMESPACE_INVALID` for both sign and the doctor check (was a ReferenceError). |
| **L4** | Loaders open with `O_NOFOLLOW` (elsewhere: an lstat refusal plus `isFile()` on the fd), reason `SYMLINK`. New `readKeyReferenceFile` applies the loaders' checks, and CLI `--owner-key-ref`, `--next-key-ref` and `signer test --ref` use it. `signControl` asks an external signer only when its key is in force (`CONTROL_AUTHORIZATION_INVALID`, nobody asked). | `custody-review.test.mjs`; `doctor-users.test.mjs` (a symlinked reference → `REFERENCE_REFUSED … symbolic link`, no request). |
| **L5** | `bao` added to the Vault binaries. With an ssh-agent key: `ssh-keygen -Y sign` and any mention of `SSH_AUTH_SOCK` (socat, nc, raw sockets). With a Vault key: `VAULT_TOKEN`, `X-Vault-Token`, `.vault-token`, `/v1/…/sign/`, `transit/sign/`. Variable and alias indirection of ssh-add/vault/bao and of the IronTrellis control programs (`i=irontrellis; $i grant`, which moves out of the known-gaps test). When the hook cannot read a reference (EACCES), every custody rule applies and `$SSH_AUTH_SOCK` and `~/.vault-token` are protected. The rest (string arithmetic, scripts written earlier, programs opening the socket without naming it) is documented as the best-effort limit. | `poc-05` (custodyCommand alone): indirection and `bao` are flagged. `poc-05b-protection.mjs` (the whole rule): all 5 previously unflagged commands → `PROTECTED_COMMAND`. |
| **L6** | `#receive` keeps a chunk list, joins once per frame, and handles every complete frame in the buffer. A second, unsolicited frame fails at once. | `poc-04`: `twoAnswersOneChunk` → MALFORMED in 1 ms (was a timeout); `slowDrip` +4.4 MB RSS (was about 37 MB). The other cases are unchanged. |
| **L7** | Labels: an unreadable file is reported as "key files or key references" (`KEY_FILES_NOT_READABLE`), never as key material. Writer lock: checked, and owner writes do **not** hold it while awaiting a signer. `withExclusiveWriter` callbacks are synchronous, the pin attestation is signed first, and only the pin rewrite takes the lock. The misleading comment in `store.ts` is corrected, and a regression test shows another store taking the lock while an attestation is pending. | `custody-review.test.mjs` "L7". |

Deviation: the review asks to FAIL on a *readable* Vault CA file. A CA bundle is public, so reading it gives nothing; what matters is *writing* it, which would let the agent's user make the owner trust its server. Doctor therefore FAILs `VAULT_CA_FILE_WRITABLE`.

Matrix after the fixes: see below.

### Matrix after the fixes (2026-09-26)

| check | result |
|---|---|
| `pnpm -r build`, `pnpm -r lint` | OK |
| core suite, run alone | 583/584, 13 m 47 s. The one failure was the timing-liveness test `store.test.mjs` "two processes reclaiming the same stale lock" ("only 42 of 120 rounds were won", **0 violations**). It re-ran green 3/3 alone, and the whole `store.test.mjs` is 26/26. Neither the test nor the lock code changed; this is a load-dependent flake on 2 CPUs. New in core: `custody-review.test.mjs` (7). |
| witness (incl. e2e) | 81/81 |
| cli | 41/42 on the full run. The one failure was the Vault CLI test's expectation `OK SIGNER_NOT_REACHABLE` for a bad token under `--as-agent`, which the H2 fix deliberately changes to `WARN SIGNER_NOT_PROVEN_UNUSABLE`. The test was updated and re-run green (2/2). New: `doctor-users.test.mjs` (2, real second user), plus 2 doctor tests and 1 L1 test. |
| hooks | 39/39 (the L5 test is new; the known-gaps test now asserts that variable and alias indirection are caught) |
| mcp-gateway / mcp-evidence | 70/70 / 11/11 |
| `pnpm test:async-signers` | core 252, witness 78, cli 37, hooks 39: all pass |
| pytest | 247 passed, 3 skipped (pre-existing) |
| conformance | node adapter 34 + 66 MATCH, python adapter 34 + 66 MATCH, legacy runner 34 MATCH |
| `transparency --check` | up to date |
| fuzz smoke / `--regressions` | 8 targets with 0 failure keys / 17/17 |
| `pnpm verify:install` | PASS 53/53 |
| check-pack, check-versions, frozen install, actionlint | OK (actionlint includes the new async-signers and two-OS-user CI steps) |

Cleanup: `poc-99-teardown.sh` has been run. Users `ownr`/`agnt`, group `itg` and container `rv-b4` are removed, and `/srv/itpoc*` is deleted. No Vault container, ssh-agent or listener from this work is still running. The PoC copies and their new outputs are kept in `/tmp/rv-b4-poc/` (`*.new`).
