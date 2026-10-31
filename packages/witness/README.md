# IronTrellis witness server

IronTrellis (formerly Continuity) keeps a checkable record of who may act for whom, and which duties survive when an AI agent is replaced. `@ramex-labs/irontrellis-witness` provides `irontrellis-witness`, a small, self-hostable HTTP server that records owner-signed head statements for IronTrellis histories in an append-only RFC 6962 Merkle log and returns signed receipts. With it, a history file cannot be rolled back to an older attested state without the owner's own tools noticing. This is version 1.0.0-rc.2.1, installed from the `next` tag.

## The problem: a genuine copy that is only old

An IronTrellis history is a hash-chained, signed file on the agent's host. Suppose an agent's grant is revoked on Monday. On Tuesday, someone who controls the host copies back Friday's backup. Every line is genuine and every signature checks, so the file replays cleanly; the revocation is simply gone. Chain hashing cannot tell a history from the same history with its newest records cut off.

A witness keeps the evidence where the agent host cannot reach it: the latest owner-signed head of each history. When Friday's copy is next checked against it (by `irontrellis verify`, or by the owner's next write), Monday's head is missing from the file, and the check stops.

Run it in a different trust domain from the agent host (another machine, account or provider). Clients (the IronTrellis core, CLI, hooks and gateway) submit a statement after each owner-signed write; the witness accepts it only if it extends the head it already holds for that history. Protocol and threat model: [docs/WITNESS.md](../../docs/WITNESS.md).

## 60-second quickstart

```sh
npm install -g @ramex-labs/irontrellis-witness@next
irontrellis-witness init --data ./witness-data --name witness.example.com   # prints the verifier key
irontrellis-witness token create --data ./witness-data                     # prints an admin token (shown once)
irontrellis-witness serve --data ./witness-data                            # http://127.0.0.1:8411
curl -s http://127.0.0.1:8411/v1/witness
```

`init` prints a verifier key such as `witness.example.com+1a2b3c4d+AR…`; `serve` logs one JSON line per event to stderr. Give clients the URL (behind TLS) and the verifier key, and whoever registers histories the admin token. Then bind it to a history: `irontrellis witness add https://witness.example.com --verifier-key <vkey> --token <token>`.

## What it establishes, and what it does not

A receipt proves that this witness recorded the entry at a leaf of its log, and the signed checkpoint commits to the whole log up to that size. The witness accepts a head only if it extends the head it holds, and honest owner code signs only statements that extend its own replayed history, so the heads it holds for a history form one chain. An attacker who can rewrite every file on the agent host but holds no owner key cannot make a reader that asks the witness accept an older state than the witness's latest. Every answer about a history's latest head also carries a **latest note** signed over the client's random nonce (the IronTrellis client sends one with each such request), so a replayed older answer is detected.

| Question | What the witness gives you |
|---|---|
| Is this file older than the latest head the witness holds? | Yes, for whoever asks: `irontrellis verify` (unless `--no-remote`), an owner's first write in each process, and readers whose policy requires it (`requireOnOpen`, on by default for a history created with `irontrellis init --witness`). A reader that does not ask is not stopped. |
| Is this answer fresh, or an old one replayed? | Detected: the latest note is signed over the client's nonce. |
| Did the owner key sign two different heads at one position? | Recorded as `EQUIVOCATION` evidence (below). |
| Are the recorded events true? | Not established: the witness never sees event contents beyond the genesis and rotation events. |
| Is the owner key safe? | Not established: a stolen key can sign statements, and rotation retires the key only at witnesses that recorded the rotation. |
| Does the witness show every client the same log? | Not established by one witness: clients check consistency against the checkpoints they remember; several witnesses with a quorum close the gap. |
| Are records written without the owner key witnessed? | Not until the next owner write: only owner-keyed writers submit heads. What the coding-agent hook and the gateway write with a runtime session's key (recorded refusals, for example) stays unwitnessed, and unattested, until then; `irontrellis witness sync` sends it to the witnesses sooner. |

**Equivocation is evidence, not a freeze.** A validly signed statement that conflicts with a head the witness holds at that position is recorded as an `EQUIVOCATION` leaf and answered 409 with that receipt. The evidence is capped (one entry per position, 64 per history), so a stolen owner key cannot grow the log without bound. The history stays open; an owner whose file was rolled back recovers by restoring a copy on the witness chain.

## Histories it accepts

- **Format 2** (`irontrellis-event/2`) and **format 1** (`irontrellis-event/1`) histories are registered by their genesis. A format-2 history is registered under `historyId` = its first record hash, and its owner key rotations are checked against the format-2 control signature. Under a format-2 owner approval policy the witness also checks who signed a head statement: never an `AGENT` key, and under `ATTESTED` only a `HUMAN` one (`WITNESS_SIGNER_UNQUALIFIED`).
- **Legacy** (`continuity-event/0.2`) histories cannot be witnessed (`UNSUPPORTED_FORMAT`).
- **The wire protocol is unchanged** (`irontrellis-witness/1`, head statements `irontrellis-head-statement/1`); a format-2 statement carries the history's format-2 domain.

The witness holds heads, not state roots: it detects a rollback of the head, and the owner's pin and checkpoints (checked by the client) carry the state root. The Python package's receipt verifier is still format 1 and does not read receipts of format-2 statements.

## Commands

| command | what it does |
|---|---|
| `init --data <dir> --name <name> [--origin <origin>]` | Creates the data directory (0700), the checkpoint key and the config (0600); prints the verifier key. Refuses a directory that is already initialized. |
| `serve --data <dir> [--config <file>] [--listen host:port] [--force-unlock] [--reload-interval <s>]` | Replays the log, then serves the API. SIGTERM/SIGINT stop it cleanly (exit 0). SIGHUP reloads the admin token hashes, and so does `--reload-interval` (seconds between checks of the config: 0 = off, else 1 to 86400; default 0, and 5 on Windows, which has no SIGHUP). `--force-unlock` overrides a lock whose holder cannot be judged dead. |
| `token create --data <dir> [--config <file>]` | Prints a new admin token once and stores its hash. Revoke by deleting the hash and reloading. |
| `verifier-key --data <dir>` | Prints the verifier key. |
| `import-key-events --data <dir> [--config <file>] [--force-unlock] <bundle>…` | Imports owner key-event bundles (`irontrellis owner export-key-events`) with the server stopped, with exactly the checks of the network route. |
| `check-log --data <dir> [--verifier-key <vkey> --origin <origin>]` | Offline audit: replays the log under the acceptance rules, re-verifies every owner signature and rotation, recomputes the tree and checks every checkpoint. Exit 0 `VALID`, 1 `INVALID`. |

Every command takes `--json`, `--help` and `--version`. Usage errors exit 2.

## Configuration (`config.json`, 0600)

| key | default | meaning |
|---|---|---|
| `name` | required | witness name and checkpoint key name |
| `origin` | `irontrellis-witness/<name>` | first line of every checkpoint |
| `listen` | `127.0.0.1:8411` | plain HTTP; put TLS in front |
| `registration` | `"token"` | `"token"` (registration needs the admin token) or `"open"` |
| `adminTokenHashes` | `[]` | SHA-256 of accepted admin tokens |
| `rateLimit` | 1200 per address, 600 per history, 6000 monitoring, per minute | token buckets; `0` disables |
| `maxHistories` | `10000` | further registrations get `HISTORY_LIMIT_REACHED` |
| `checkpointIntervalMs` | `0` | `0`: a checkpoint after every append; at most 60000 |
| `trustProxy` | `false` | `true` or a list of proxy addresses: take the client address from `X-Forwarded-For` |
| `requestTimeoutMs` | `10000` | whole-request receive timeout |
| `metricsToken` | none | bearer token for `GET /metrics` |

Unknown keys are refused, so a typo cannot silently weaken a limit.

## HTTP API (`irontrellis-witness/1`)

JSON bodies up to 64 KiB (1 MiB for registration). `POST /v1/histories`, `GET /v1/histories/:id` and the `POST` routes for heads and key events take `?nonce=…`; their replies then carry the `latestNote`. Receipts verify with the core's `verifyWitnessReceipt(receipt, [verifierKey])`, latest notes with `verifyLatestNote`.

| route | reply |
|---|---|
| `GET /v1/witness` | `{ version, origin, verifierKey, software }` |
| `POST /v1/histories` `{ genesis }` | 201 new / 200 existing: `{ historyId, receipt, checkpoint }`; format-2 and format-1 genesis events |
| `GET /v1/histories/:id` | domain, owner key epochs, equivocation and supersede counts, the latest head and its receipt |
| `POST /v1/histories/:id/heads` | a signed statement: 201 `APPENDED` / 200 `ALREADY_WITNESSED`; 409 `STALE_PREVIOUS`, `EQUIVOCATION`, `SUPERSEDED` |
| `POST /v1/histories/:id/key-events` | an owner key rotation, checked against the epochs and next-key commitments the witness knows; with `chain`, a pre-rotated rotation can supersede heads a stolen old key signed (once per rotation) |
| `POST /v1/admin/key-events` | a key-event bundle, with the admin token |
| `GET /v1/histories/:id/heads/:position`, `GET /v1/checkpoint`, `GET /v1/proofs/inclusion`, `GET /v1/proofs/consistency`, `GET /v1/entries` | the log, its proofs and checkpoints |
| `GET /healthz`, `GET /metrics` | health; Prometheus metrics |

Errors are `{ error: { code, message, hint? } }`. Codes include `INVALID_GENESIS`, `UNSUPPORTED_FORMAT`, `NOT_REGISTERED`, `INVALID_STATEMENT`, `SIGNATURE_INVALID` (hint `ROTATION_REQUIRED`), `STALE_PREVIOUS`, `EQUIVOCATION`, `KEY_EVENT_INVALID`, `SUPERSEDED`, `WITNESS_SIGNER_UNQUALIFIED`, `RATE_LIMITED` and `INTERNAL` (never a stack trace).

Library: `import { Witness, createWitnessServer, serve, checkLog, decideRegister, decideHead, decideKeyEvent, applyEntry } from "@ramex-labs/irontrellis-witness"`. The acceptance rules are pure functions over the state derived from the log.

## Operations

**Data directory.** `log.jsonl` (one canonical line per leaf, the only source of truth), `checkpoints.jsonl`, `witness-key.json`, `config.json`, `server.lock`. Each append is fsynced before anything that depends on it is answered. At start the log is replayed; a torn last line (never acknowledged) is cut off, and any other bad line stops the server with the file and line named.

**Backup.** Copy `checkpoints.jsonl` first, then `log.jsonl`, and run `check-log` on the copy. Restoring an older copy is itself a rollback of the witness: clients that saw later checkpoints report a split view.

**Key custody.** `witness-key.json` signs every checkpoint. Keep it 0600 (the server refuses a key others can read; on Windows the file's ACL protects it instead), out of images and repositories, backed up apart from the log. A new key means a new origin and a new data directory.

**Deployment.** Serve on loopback behind a TLS proxy (`deploy/Caddyfile.example`, `deploy/nginx.conf.example`) with `trustProxy`. The IronTrellis client refuses a plain `http:` witness URL whose host is not loopback unless told otherwise. The repository has a hardened systemd unit (`deploy/irontrellis-witness.service`) and a container image (`deploy/Dockerfile`; run it with a fixed `--hostname` and, on first start, `IRONTRELLIS_WITNESS_NAME`). `deploy/smoke.sh <image>` tests an image end to end. Step by step: [docs/WITNESS.md](../../docs/WITNESS.md).

**Monitoring.** Alert on `irontrellis_witness_storage_failed == 1`, a failing `/healthz`, rising equivocation counts (an owner key signed a conflicting head: tell that owner), an old checkpoint and disk space for `log.jsonl`. Access log lines never carry bodies or tokens.

## Check it yourself

- Audit a data directory, or a copy of it, offline with `check-log`. It is read-only: it never truncates or locks anything.
- Verify a receipt only with a verifier key you obtained independently, never one the receipt merely names.
- The protocol, threat model and incident runbook are in [docs/WITNESS.md](../../docs/WITNESS.md); report a security problem as [SECURITY.md](../../SECURITY.md) describes.

Runtime dependency: `@ramex-labs/irontrellis` only. Apache-2.0.

*Last reviewed: 24 October 2026. This page is revisited at each release.*
