# Custody diagnostics and failure reference

> Reference from `CUSTODY.md` at `00ca4c0` (SHA-256 `cd491c6547c2a2de0a0153060cc77539eb80aedd95d028b5d9f287f1632e66ab`). Established scope: the retained field, byte, code, limit and ordered-check contracts below. Not established: a new engine audit, deployment test or broader edition coverage.

Source section numbers are retained for cross-reference with [CUSTODY.md](../CUSTODY.md). Operational guidance stays in the narrative page. Format-2 owner-policy rules remain in the unchanged [owner-policy reference](owner-policy.md).

<!-- source: CUSTODY.md:246-267; exact text except relative Markdown links -->

## 11. `irontrellis doctor`

```sh
irontrellis doctor h.jsonl                       # as the owner: where each key lives, is its signer reachable, what is weak
sudo -u agent -H irontrellis doctor h.jsonl --as-agent   # as the agent's OS user: what it can read or use becomes a FAIL
irontrellis doctor h.jsonl --json                # { history, user, asAgent, platform, findings: [{ level, area, code, message, fix }], summary, ok }
```

Read-only: doctor never signs, never writes (not even the witness cache), and never contacts a signer in a way a person would have to approve. It reads key files and references **only through the loaders' checks** (no symbolic link, 0600, a reference owned by the user running doctor): a signer named by a file the loaders would refuse is never contacted, and no token or CA file it names is read (`REFERENCE_REFUSED`, FAIL). For an ssh-agent it only **lists** identities; for Vault it only **reads** the key (`GET <mount>/keys/<key>`); a command signer is never started (`SIGNER_NOT_CHECKED`: `signer test` runs it once, deliberately). A bound witness gets one `GET /v1/witness`. `--offline` contacts nothing; `--hook-config <file>` names the hook config (default `IRONTRELLIS_HOOK_CONFIG`, else `irontrellis-hook.json` found upward from the working directory). Exit status: 0 without a FAIL, 1 with one, 2 on a usage error. `irontrellis init` ends with the doctor command to run.

| area | findings (level) | what it checks |
|---|---|---|
| platform | `PLATFORM_POSIX` (OK), `PLATFORM_WIN32_MODES_OFF` (WARN), `RUNNING_AS_ROOT` (WARN) | mode checks on or off; root sees everything |
| history | `HISTORY_NOT_FOUND`, `HISTORY_UNREADABLE`, `HISTORY_VERIFY_FAILED`, `HISTORY_NEAR_FILE_LIMIT` (FAIL); `HISTORY_SUCCESSOR_ADVISED`, `LEGACY_FORMAT` (WARN); `HISTORY_SIZE`, `HISTORY_VERIFIES` (OK) | opens and verifies locally; size against the successor guideline (about 500,000 events or 500 MiB) and 90 % of the hard file limit |
| custody | per key, as `owner status`: `OWNER_KEY_REFERENCE`, `NEXT_KEY_REFERENCE`, `NEXT_KEY_OFF_HOST`, `RETIRED_KEY_REFERENCE`, `OWNER_KEY_ELSEWHERE` (OK); `OWNER_KEY_FILE_ON_HOST`, `NO_NEXT_KEY_COMMITMENT`, `NEXT_KEY_ON_HOST`, `NEXT_KEY_SAME_SIGNER`, `RETIRED_KEY_FILE`, `KEY_FILE_UNREADABLE`, `NEXT_KEY_STALE` / `_RETIRED` / `_UNCOMMITTED` / `_UNREADABLE`, `KEY_FILE_PENDING` (WARN) | who holds the current, next and retired keys; pre-rotation |
| access | `KEY_MATERIAL_READABLE` (WARN; FAIL with `--as-agent`), `KEY_FILE_MODE`, `REFERENCE_REFUSED` (FAIL); `KEY_FILES_NOT_READABLE` (OK with `--as-agent`, FAIL for the owner), `NO_KEY_MATERIAL_ON_HOST` (OK); `HISTORY_DIR_LOOSE` (WARN, owner run); `HISTORY_DIR_WRITABLE`, `SIDE_FILE_WRITABLE` (FAIL) / `HISTORY_NOT_WRITABLE` (OK) with `--as-agent` | can **this OS user** read owner key material or change the history's files? (every key file, pending file and retired archive, through the loaders) |
| signer | `SIGNER_REACHABLE`, `SIGNER_NOT_REACHABLE`, `SIGNER_NOT_CHECKED` (OK); `SIGNER_UNREACHABLE`, `SIGNER_KEY_NOT_LISTED`, `SIGNER_PROGRAM_MISSING`, `VAULT_TOKEN_FILE_LOOSE`, `VAULT_CA_FILE_MISSING` (WARN); with `--as-agent`: `SIGNER_USABLE_BY_THIS_USER` (FAIL for an ssh-agent or Vault, WARN for a command, which may still need a credential or a person), `VAULT_TOKEN_READABLE`, `VAULT_CA_FILE_WRITABLE` (FAIL), `SIGNER_NOT_PROVEN_UNUSABLE` (WARN: Vault refused the key read, the token may still sign), `SIGNER_NOT_EVALUATED` (WARN: the reference is unreadable as this user); `SIGNER_KEY_UNAVAILABLE` (FAIL: Vault answers that the key, version or public key is not there) | can this OS user **reach the signer** of the current and the next key, and does it hold the key? |
| witness | `WITNESS_POLICY_NOT_SET`, `WITNESS_POLICY`, `WITNESS_REACHABLE`, `WITNESS_BOUND`, `WITNESS_NOT_CHECKED` (OK); `NO_WITNESS`, `WITNESS_POLICY_RELATIVE`, `WITNESS_UNREACHABLE`, `WITNESS_INSECURE_HTTP`, `WITNESS_UNREGISTERED`, `UNWITNESSED_EVENTS`, `ROTATION_PENDING`, `ROTATION_INCOMPLETE` (WARN); `WITNESS_POLICY_MISSING`, `WITNESS_KEY_MISMATCH`, `WITNESS_ALARM`, `WITNESS_REJECTED` (FAIL); `WITNESS_POLICY_WRITABLE` (WARN, or FAIL when the agent's user can write it) | bound witnesses reachable, https, registered, rotations recorded; the out-of-band policy file (`IRONTRELLIS_WITNESS_POLICY`): present, absolute, not writable by others |
| environment (`--as-agent`) | `VAULT_TOKEN_IN_ENVIRONMENT`, `VAULT_TOKEN_FILE_READABLE`, `SSH_AGENT_HOLDS_OWNER_KEY` (FAIL); `SSH_AUTH_SOCK_NOT_CHECKED` (WARN, `--offline`); `SSH_AGENT_NO_OWNER_KEY`, `NO_SIGNER_CREDENTIALS` (OK) | signer credentials the agent's user's environment offers, whatever the references say |
| hooks | `HOOKS_INSTALLED`, `HOOKS_PROTECT_COVERS` (OK); `HOOKS_NOT_FOUND`, `HOOKS_CONFIG_INVALID`, `HOOKS_OTHER_HISTORY`, `HOOKS_NOT_INSTALLED`, `HOOKS_PROTECT_GAP`, `VAULT_TOKEN_IN_ENVIRONMENT` (WARN) | a hook config names this history, a host's settings run `irontrellis-hook`, and the protect list covers the key files and every signer path (sockets, programs, token and CA files, the witness policy) |

Every WARN and FAIL carries a `fix`. The two runs are §8. What doctor cannot see: whether an ssh-agent or a command asks a person for each use, what a Vault token's policy allows beyond reading the key, the IAM behind a KMS command, and anything about another host. Run it as the agent's user to see the agent's side.


## Signer failures and recorded writes

| Condition | Contract / code | Baseline source |
|---|---|---|
| Signer does not hold the selected key | `KEY_UNAVAILABLE`; no control event appended | CUSTODY 56, 238 |
| Other signing failure before control signature | `SIGNER_FAILED`; no control event appended | CUSTODY 56, 238 |
| Pin attestation fails after append | CLI `WRITTEN_UNATTESTED`, exit 4; `context.written: true`, event ID, head and `context.cause`; library `flush()` throws the signer error with the durable-write qualification | CUSTODY 239 |
| Earlier attestation retained after that failure | `PIN_ATTESTED_EARLIER`; `repin` requests an attestation of the recorded head | CUSTODY 239 |
| Vault version trimmed or below `min_encryption_version` | `KEY_UNAVAILABLE`, `VERSION_UNAVAILABLE`; a reference remains pinned across a Vault-side rotation | CUSTODY 243 |
| Reference lost | It contains no secret; replacement must identify the existing public key and pinned backend version | CUSTODY 244 |

Lost-key authorization is an epoch/policy question, not a signer error override. A committed next key signs a rotation alone only where the rules let it: in format 2, under `recovery: "COMMITTED_NEXT_KEYS"`, a revealed committed key counts toward the rotation quorum and must prove possession ([owner-policy](owner-policy.md) §4). Without that, current-owner approval is still required. If every committed successor is lost and the current keys cannot approve, no rotation is possible for that epoch.
