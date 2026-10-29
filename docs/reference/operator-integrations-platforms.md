# Gateway, hook, witness and Windows command contracts

Reference from master `00ca4c0` OPERATOR. See the [operator guide](../OPERATOR.md) for procedures and trust boundaries. Placeholders in command templates require deployment-specific values. No command or live service was exercised in this docs pass.

**Edition boundary:** Current control writes must target format 2; legacy/format-1 histories are read-only (`FORMAT_READ_ONLY`). Old creation and legacy→format-1 migration templates are historical, not current setup instructions; the current commands are `irontrellis init` and `irontrellis migrate` ([MIGRATION](../MIGRATION.md)).

## Gateway operations

<!-- Source OPERATOR.md:196-196; command-field-and-lifecycle-contracts-condensed -->

| `irontrellis-mcp-ops` subcommand | Contract |
|---|---|
| `inspect --config <gateway.json>` | Counts, capacity, head, pin status, lease and warnings; no identities or arguments |
| `revoke --config <gateway.json> --authority <id>` | Idempotent signed `AUTHORITY_REVOKED`; pending work returns `DENIED` on the next call, already-run work returns `RECONCILIATION_ONLY` with its retained reply |
| `snapshot --config <gateway.json> --directory <dir>` | Writers must be stopped; new directory under a 0700 parent; history, `.head`, available `.anchors`/`.witness.json`, records and `gateway.json`; excludes owner/session key files |
| `verify --directory <dir>` | Checks snapshot checksums and replays history against its copied pin |
| `recover-dead-host --config <gateway.json>` | Removes the host lease of a provably dead local process |

A snapshot's copy of `<history>.witness.json` has every registration `token` removed; `gateway.json` is copied as it is, and key files are never copied. Retained job results after crashes are `RECONCILIATION_ONLY` or `OUTCOME_UNKNOWN`; they do not authorize resending work under a new business key. Full package operations and recovery contracts remain in the gateway's `docs/OPERATIONS.md` and `docs/RECOVERY.md`.

## Hook files and session commands

<!-- Source OPERATOR.md:200-213; path-field-and-command-contracts-condensed -->

`irontrellis-hook init` creates `~/.irontrellis/projects/<first 16 hex of sha256(project path)>/` with mode 0700 and prints that path. `IRONTRELLIS_HOME` moves the home root. `--history <path>` moves the history-prefixed files.

| File | Fields / role |
|---|---|
| `history.jsonl`, `.head`, `.writer-lock`, `.anchors` | History and side files |
| `history.jsonl.owner-key.json` | Owner key, mode 0600 |
| `history.jsonl.sessions/<sha256(host session id)>.json` | Session key, 0600; private key removed at end/release |
| `history.jsonl.handovers/<sha256(host session id)>.json` | Handover record, 0600 |
| Project `irontrellis-hook.json` | Absolute history path |
| In-project state `.gitignore` | `*`, generated when init places state in the project |

Handover output is rewritten after each turn (`final: false`) and at session end (`final: true`). It contains open duties/assignees/deadlines, live grants, sessions, tenures and SURVIVES; grants do not follow a successor and the file grants no authority.

Sessions of one agent are serialized while an earlier key is held. `irontrellis-hook session list` reports live/stale/released keys. `irontrellis-hook session release <host-session-id>` or `--all` removes private keys; the next admission advances the epoch and fences the prior session.

## Witness commands and policy

<!-- Source OPERATOR.md:225-246; witness-command-policy-and-side-file-contracts-condensed -->

```sh
irontrellis witness add https://witness.example.com --verifier-key '<selected verifier key>' --token <token> [--mode sync] [--quorum <n>] [--require-on-open] [--max-unwitnessed <n>]
irontrellis witness status
irontrellis witness sync
```

`add` checks the selected verifier key, registration, prefix and availability of signatures for needed key events before writing. Refusals are `WITNESS_REJECTED`, `KEY_UNAVAILABLE`, `ROLLBACK_DETECTED` or `WITNESS_UNAVAILABLE`; `--allow-offline` binds an unreachable witness and registers later. `init --witness <url> --verifier-key <key> [--token <token>]` binds at creation. HTTPS is required except loopback or explicit `--allow-insecure-http`; current latest-answer freshness uses nonce-bound signatures (the baseline TLS wording is questioned separately).

`IRONTRELLIS_WITNESS_POLICY=<absolute path>` selects a minimum policy, e.g. `{ "witnesses": [{ "url": "…", "verifierKey": "…" }], "requireOnOpen": true }`. Each witness may also carry a token. Every open merges the minimum by adding witnesses/raising requirements; an unusable file is `WITNESS_UNREADABLE`, reason `WITNESS_POLICY_UNREADABLE`. POSIX requires an operator/root-owned 0600 or 0644 file in a directory the agent cannot write; Windows uses administrator-controlled ACLs. `async` is the default mode. `sync` submits before returning, after the local append; an unreachable witness does not fail the write and its statement stays queued, while rollback or split-view evidence throws. Inspect the returned state rather than infer every event is witnessed on return. See [WITNESS §5](../WITNESS.md#5-connect-a-history-and-choose-policy). `maxUnwitnessedEvents` defaults to 1000.

`verify --no-remote` skips consultation; `--allow-unreachable-witness` accepts an outage as a note. `witness sync` needs an owner key. Side-file writes use `<history>.witness.json.lock`; malformed side state is `WITNESS_STATE_UNREADABLE`. `<history>.rotation.pending.json` stores a sealed prepared rotation and blocks writes with `ROTATION_PENDING`. `<history>.key-event-<position>.bundle.json` holds signed data, never a private key. Retired key archives can be needed even for a witness added later.

## Rotation outcomes and offline delivery

<!-- Source OPERATOR.md:250-269; rotation-result-and-import-command-contracts-condensed -->

| Outcome / command | Meaning |
|---|---|
| `ROTATION_NEEDS_WITNESSES` | Preflight failed before preparation |
| `ROTATION_ABORTED` | No witness accepted, every refusal definite; no local event appended |
| `ROTATION_OUTCOME_UNKNOWN` / `ROTATION_PENDING` | Prepared record retained; an owner command asks witnesses before deciding whether to append/discard it |
| `ROTATION INCOMPLETE` / `REMOTE_WITNESS_ROTATION_INCOMPLETE` | Local rotation recorded, some bound witness still lacks it |
| `owner rotate-key --emergency --next-key <file> --reason "key compromise"` | Local-first rotation; queues missing delivery. A committed-key rotation can supersede the retired key's later witness heads; without that commitment conflict may require a successor |
| `irontrellis owner export-key-events [--since <position>]` | One bundle per rotation, including commitment-only rotations; each rotation already writes its own bundle |
| `irontrellis-witness import-key-events --data <dir> <bundle>… [--json]` | Offline import, oldest first, server stopped; takes server lock |
| `POST /v1/admin/key-events` with admin bearer token and JSON bundle | Running-server import; same checks as network delivery |
| `irontrellis witness remove <old-url>` | Owner-signed unbinding; older copies still name that witness |

`MAX_UNWITNESSED` pauses writes, not reads. `REGISTRATION_REFUSED` is sticky until corrected policy; `REGISTRATION_DENIED` means a witness denied a registration it signed. `WITNESS_SPLIT_VIEW` reports inconsistent logs. `WITNESS_AHEAD`/`WITNESS_FORK` and equivocation warnings require investigation. `REMOTE_WITNESS_SUPERSEDED` warns that a pre-rotated rotation overrode old-key heads; `NO_NEXT_KEY_COMMITMENT` identifies an uncommitted epoch. Offline import reports `IMPORTED`, `ALREADY RECORDED` or `REFUSED` with the per-file code; forged or altered signatures are refused. A bundle includes the rotation-head statement and, when supersede may be needed, a `chain` from the last head known at that witness. Exact bundle validation is in [WITNESS](../WITNESS.md).

```sh
curl -X POST -H "Authorization: Bearer <admin token>" -H "content-type: application/json" --data-binary @<bundle> https://witness.example.com/v1/admin/key-events
```

## Windows-specific contracts

<!-- Source OPERATOR.md:275-279; platform-command-and-byte-contracts-condensed -->

- POSIX key/config/policy mode checks do not apply. Set inherited ACLs before key creation, e.g. `icacls … /inheritance:r /grant:r "<account>:(OI)(CI)F"`; policy writes are administrator-only and reads available to the agent.
- `IRONTRELLIS_WITNESS_POLICY` must be drive-qualified or UNC. Gateway upstreams name an executable such as `node.exe`, not `.cmd`/`.bat`.
- Witness shutdown handles Ctrl+C, Ctrl+Break and console close. Forced termination relies on fsync before acknowledgement plus torn-tail/stale-lock recovery. There is no SIGHUP; admin-token reload defaults to 5 seconds (`serve --reload-interval`).
- Replacement retries Windows sharing violations for up to 3 seconds; a failed pin replacement is `WRITE_UNCONFIRMED`.
- A CRLF-converted history still verifies; a byte-order mark is refused. A witness `log.jsonl` with CRLF is refused until restored to LF.

Windows CI-tested status is conditional on the first green documented Windows job; production exercise is not claimed.
