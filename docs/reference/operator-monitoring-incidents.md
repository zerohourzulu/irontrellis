# Monitoring fields, failure codes and recovery command contracts

Reference from master `00ca4c0` OPERATOR. The [operator incident playbook](../OPERATOR.md#6-incident-playbook) owns the response sequence. These are exact field/code contracts and command templates, not a renewed engine or performance test.

**Edition boundary:** Current control writes must target format 2; legacy/format-1 histories are read-only (`FORMAT_READ_ONLY`). Old creation and legacy→format-1 migration templates are historical, not current setup instructions; the current commands are `irontrellis init` and `irontrellis migrate` ([MIGRATION](../MIGRATION.md)).

## Monitoring fields

<!-- Source OPERATOR.md:114-125; field-table-with-performance-advice-removed -->

| signal | where | meaning |
|---|---|---|
| `capacity.mode` | `irontrellis capacity`, `irontrellis-mcp-ops inspect`, `owner.capacity()` | `OPEN` or `CONTROL_ONLY`. In `CONTROL_ONLY` new agents, roles, grants, sessions and jobs are refused (`CAPACITY_CONTROL_ONLY`); withdrawals still work. Alert before it flips: `remainingPhysicalEvents` and `canDeclareJob` |
| `verify` | scheduled, §3 | exit code / `ok`; `failures` names each failed check (§6). Also worth graphing: `pinnedHeadStatus`, `pinnedAttestation`, `anchorLogStatus`, and `notes` such as `PIN_ATTESTED_EARLIER`, `ANCHOR_LOG_NONE`, `ROLLBACK_ACCEPTED` |
| `status` | `irontrellis status` | head, event count, format, owner keys, capacity, pinned head status and attestation, witness status, anchors, the failed checks if any (then run `verify`), counts of agents, grants, sessions, open duties |
| file size | `stat` | 64 MiB (legacy) / 1 GiB (format 1) hard limit: `HISTORY_FILE_LIMIT` |
| session expiry | `handover <agent>`, `status` | sessions are admitted with `expiresAt`; an expired session's calls are `RUNTIME_NOT_CURRENT` or `DENY / SESSION_EXPIRED`. The hook refuses an expired session's tool calls (`SESSION_EXPIRED`) and admits a fresh session when the host starts or resumes it; other hosts must re-admit themselves |
| open duties | `handover <agent>` | obligations and attempt duties with deadlines; a handover report with open duties for a terminated agent is work nobody holds |
| the writer lock | `<history>.writer-lock` present for more than a minute | a stuck or crashed writer (§6) |
| remote witnesses | `irontrellis witness status` (exit 1 on a rollback, split view or invalid answer), `verify` notes `UNWITNESSED_TAIL n` | per witness: the latest witnessed head, receipt and consistency checks, the queue. A growing `unwitnessedEvents` means the witness is not accepting statements; owner writes stop at `maxUnwitnessedEvents`. A WARNING about recorded equivocations means the owner key signed a conflicting head (§10) |
| the witness server | its `/healthz` and `/metrics` (`docs/WITNESS.md` §4.7) | storage failures, checkpoint age, recorded equivocations, disk use |
| `HISTORY_CONFLICT` / `STORE_BUSY` rate | your logs | writers racing on one file. CLI writes retry up to 5 times (about 1.5 s) before failing, and the message names the lock file and its holder; occasional failures are expected, a pattern means two hosts think they own the history |

## Format-2 bounds

<!-- Source OPERATOR.md:131-131; exact-bound-and-side-file-contracts-condensed -->

| Field / file | Bound or behavior |
|---|---|
| Refusal coalescing / per-actor rate | 60 seconds / 6 per minute |
| `snapshot.maxBytes` | Default 2 GiB (`2 × HARD_BYTES`); a larger snapshot is discarded unread |
| `HARD_RECORDS` | A snapshot with more entries is discarded unread; `SNAPSHOT_STALE`, full replay |
| `<history>.state` and journal | Disposable cache; corruption requires replay and rebuilding |
| Genesis `maxStateRecords` | Immutable within the history; a non-control event exceeding the resulting count is refused |
| Record removal / absolute cap | Control events that remove records can restore room; no permanent control-only latch; the absolute cap refuses every event |
| `<history>.refusals.spool` | Refusals not recorded in time, recorded on the next call |
| `<history>.refusals.log`, `<history>.refusals.rendered.log` | Disposable local side logs |

## Verification failures

<!-- Source OPERATOR.md:135-155; exact-code-table-and-exit-contract -->

`verify` prints `CODE: explanation`, returns failures with `--json`, and exits 1 on a failure. Other commands refuse pin/anchor problems on open; `repin` uses `REPIN_REFUSED` with the same reason. The hook refuses tools with exit 2 and names the reason on stderr. `INVALID_HISTORY` throws with the store reason/position rather than producing a verification report.

| failure | what was found | first response |
|---|---|---|
| `PIN_ROLLBACK` (open: `ROLLBACK_DETECTED`, reason `BEHIND_PIN`) | the file does not contain its pinned head: it is shorter than the pin, or holds a different event at the pinned position | "Rollback detected" below |
| `PIN_MISSING` (open: reason `PIN_MISSING`) | a format-1 history with events after genesis and no `<history>.head` | "Rollback detected": a deleted pin is how a truncation would be hidden. If you know the pin was simply not restored, restore it with the history |
| `PIN_MALFORMED` (open: reason `PIN_MALFORMED`) | the pin file cannot be parsed | restore the pin from the same backup as the history; otherwise "Rollback detected" |
| `PIN_ATTESTATION_MISSING` (open: reason `PIN_UNATTESTED`) | the pin carries no owner attestation, so anyone who can write the pin file could have written it, at any truncated head | "Rollback detected": this is exactly what a truncation with a forged pin looks like. If the file is right, `irontrellis repin --accept-rollback` (§3) |
| `PIN_ATTESTATION_INVALID` (open: reason `PIN_ATTESTATION_INVALID`, or `PIN_ATTESTED_NOT_PREFIX` when the signature is the owner's but its head is not in the file) | the attestation is not an owner signature over a head of this history; `PIN_ATTESTED_NOT_PREFIX`: the owner attested a head the file no longer contains | tampering, a pin copied from another history, or events the owner vouched for were removed: "Rollback detected" |
| `ANCHOR_MISMATCH` | an `ANCHOR_RECORDED` event names a head that is not a prefix of the file | the store never writes this; treat as tampering or corruption (see "Control signature invalid") |
| `ANCHOR_LOG_ROLLBACK` (open: reason `ANCHOR_LOG_ROLLBACK`, from `<history>.anchors`) | an anchor log holds an owner-attested head that the file no longer contains (newer than the file, or a different history at that position) | "Rollback detected": this is how a restored older copy with its own older pin is caught |
| `ANCHOR_LOG_INVALID` | an anchor log holds a head no owner key in force at its position signed | the log was edited, or belongs to another history: keep it as evidence and find out which |
| `ANCHOR_LOG_UNREADABLE` (open: `ANCHOR_LOG_UNREADABLE`, for `<history>.anchors`) | an anchor log exists but cannot be read or parsed (permissions, a torn last line) | fix the permissions or restore the log; rollback cannot be excluded until it reads, so every command refuses the history meanwhile (`--accept-rollback` does not pass it) |
| `ANCHOR_LOG_MISSING` | the history records local anchors, but their log (by the file name in the receipt) was not found next to the history or among `--anchors-file` | restore the log, or pass the copy you keep elsewhere with `--anchors-file`; a deleted log is how a rollback would be hidden |
| `REMOTE_WITNESS_ROLLBACK` (open or write: `ROLLBACK_DETECTED`, reason `WITNESS_AHEAD` or `WITNESS_FORK`) | a remote witness holds an owner-signed head that the file does not contain (past its end, or a different head at that position) | "Remote witness rollback" below |
| `REMOTE_WITNESS_SPLIT_VIEW` (any command: `WITNESS_SPLIT_VIEW`) | a remote witness could not prove its log consistent with a checkpoint seen before: it showed two logs | stop trusting that witness; `docs/WITNESS.md` §6.1 |
| `REMOTE_WITNESS_INVALID` (write: `WITNESS_UNAVAILABLE`, reason `INVALID_ANSWER`) | a remote witness's answer does not verify with its configured verifier key (a receipt, a checkpoint, or the latest note signed over the request's nonce: an older answer replayed by something on the path fails it), or a witness the history binds with its signed registration receipt answers that it does not know the history ("denies a registration it signed") | check the URL, the key and the proxy in front of the witness; for a denial, ask the witness's operator whether its data was restored or lost (`docs/WITNESS.md` §6.1) |
| `ROLLBACK_DETECTED`, reason `FILE_CHANGED_UNDER_WRITER` | the history file was swapped for another copy behind a running owner process, between its append and its submission to the witness; that process signs nothing more | treat it as tampering; find the real copy (`irontrellis witness status`), restore it and start a new process (`docs/WITNESS.md` §6.1) |
| `REMOTE_WITNESS_UNREACHABLE` | fewer remote witnesses answered than a check needs, so a restored older copy cannot be ruled out | bring the witness back and verify again; `--allow-unreachable-witness` makes it a note when you accept that |

## Recovery command contracts

<!-- Source OPERATOR.md:159-192; recovery-command-signatures-and-failure-qualifications-condensed -->

| Template | Effect and conditions |
|---|---|
| `cat <history>.head`; `irontrellis status`; `irontrellis verify --json` | Compare pinned and actual head; JSON contains `{ ok, path, failures, notes, report }`; a JSON detail field is not inferred from a missing table cell |
| `irontrellis verify --accept-rollback` / `irontrellis repin --accept-rollback` | Re-pin as-is; record `rollbackAcceptedAt` and previous pin. `ROLLBACK_ACCEPTED` is visible until the next write. Without an owner key, the pin remains unattested and refused until signed. |
| `irontrellis anchor` after deliberately archiving an obsolete local log | Establishes a new log. Until then the obsolete log gives `ANCHOR_LOG_ROLLBACK` / `ANCHOR_LOG_AFTER_ACCEPTED_ROLLBACK`; removing it without replacement gives `ANCHOR_LOG_MISSING`. Preserve the archived evidence. |
| `irontrellis witness remove <url> [<url>…] --accept-loss --reason "<what happened>"` | Owner-signed unbinding of every witness holding lost heads, together. Continues on a branch they did not see; other witnesses apply, and removed witnesses cannot be added back. Local `--accept-rollback` cannot waive a remote rollback. |
| `irontrellis epoch advance <agent> --from <n> --to <n+1>` | Fences sessions of the prior epoch; admit a fresh key/session. Event-budget admissibility does not waive current policy/time or absolute state limits. |
| `irontrellis owner rotate-key --next-key <file> --reason "key compromise"` | Uses committed key; without a commitment, omit `--next-key`; bound-witness normal, incomplete and emergency outcomes remain distinct. |
| `irontrellis-mcp-ops recover-dead-host` | Gateway's separate host-lease recovery; not a history writer-lock override |
| Query `--position` | Evaluates a selected prefix; a legacy evidence-budget refusal remains indeterminate, never ALLOW |

A writer lock exposes `lockPath` and, when readable, `pid`, `hostname`, `createdAt`. Automatic reclaim requires a dead process on the same host and age over 60 seconds. Another host or younger lock is not automatically reclaimed. Reclaim renames the exact stale file before deleting it; manual deletion requires independently confirming the writer is gone.

A zero-byte file is `HISTORY_EMPTY`; a defective record is `INVALID_HISTORY` with position. A torn final line is `INVALID_HISTORY: history file has an incomplete record`, and there is no automatic repair command. With writers stopped and damaged bytes retained, the baseline's exact last-newline operation is:

```sh
python3 -c "import sys;p=sys.argv[1];b=open(p,'rb').read();open(p,'wb').write(b[:b.rfind(b'\n')+1])" <history>
irontrellis verify
```

The pin should then be `MATCHES` or `AHEAD`; another outcome requires investigation of more than a torn append. Valid-prefix salvage, when no verified complete copy exists, uses a scratch copy and accepts loss after the last good line:

```sh
head -n <position> history.jsonl > scratch/history.jsonl
# Place the owner key beside the scratch history, mode 0600, for this operation.
irontrellis --history scratch/history.jsonl verify --accept-rollback
irontrellis --history scratch/history.jsonl export
# Remove the scratch key after export under the custody policy.
```

The cut is before the invalid position. A copy without its pin is `PIN_MISSING`; re-pinning without a key leaves `PIN_UNATTESTED`. Exported valid-prefix events can be re-recorded into a successor by the operator's script; this is explicit loss handling, not an automatic repair or general migration command.
