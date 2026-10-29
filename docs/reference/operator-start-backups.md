# Backup files and verification command contracts

Reference from master `00ca4c0` OPERATOR. Operating choices and restore procedure are in the [operator guide](../OPERATOR.md). This page specifies file roles, command outputs and refusal conditions; it claims no new runtime or performance verification.

**Edition boundary:** Current control writes must target format 2; legacy/format-1 histories are read-only (`FORMAT_READ_ONLY`). Old creation and legacy→format-1 migration templates are historical, not current setup instructions; the current commands are `irontrellis init` and `irontrellis migrate` ([MIGRATION](../MIGRATION.md)).

## File inventory

<!-- Source OPERATOR.md:27-38; retained-file-table-with-operational-prose-condensed -->

| File | Required role and boundary |
|---|---|
| `<history>` | Append-only JSONL history; immutable complete lines end in `\n` |
| `<history>.head` | Matched pinned head and owner attestation; missing, malformed or mismatched pins are not ordinary restore success |
| `<history>.owner-key.json` | Current key file or signer reference; contains secrets for a file key, not for a reference |
| `<history>.owner-next-key.json` | Committed next-key material/reference; a file key belongs offline, outside ordinary host backups |
| `<history>.owner-key.<keyId>.retired.json` | Retired key archive used for statements a witness still needs, including a later-added witness |
| `<history>.anchors` | Local anchor log; independent copies can be passed as `--anchors-file` |
| `<history>.witness.json` | Policy, registration tokens, remembered checkpoints/answers and queued work; no private keys; mode 0600 |
| Session key files, such as `<history>.sessions/` | Needed separately to resume retained sessions |
| Gateway `storage` | Retained attempt and reply records used to reconcile outcomes |

Snapshot keys and witness-token redaction are different questions: snapshots exclude key files, while the exported token descriptions conflict (OPERATOR 36/40 versus 196). Do not infer token absence from key exclusion.

## CLI outputs and flags

<!-- Source OPERATOR.md:40-61; exact-command-and-pin-contracts-condensed -->

| Command / flag | Contract |
|---|---|
| `irontrellis verify [--json]` | Replays once, rereads hashes/links/prefixes, checks signatures, pin and anchors; `ok`, `failures`, `notes`; exit 0 iff `ok`, otherwise 1. Ordinary verification is read-only and needs no key. |
| `--anchors-file <file>` | Consults an additional local anchor log; `<history>.anchors` is consulted whenever present |
| `--expect-history-id <0x…>`, `--expect-owner-key <0x…>` (repeatable) or `--expect-owner-keys <file>` | Checked first: refuses a history whose id or first owner key set (compared as a set) is not the published one, with `HISTORY_ID_MISMATCH` / `OWNER_KEYS_MISMATCH`; without them the identity is read from the file and the report says it is unconfirmed. `export verify` takes the same options |
| `--no-remote` | Skips the witness check normally made by witness-aware CLI verification |
| `--allow-unreachable-witness` | Accepts an outage as a note; does not accept rollback, split view or invalid signed evidence |
| `--allow-unpinned` | Missing pin/attestation may be a note for inspection; does not enable writes |
| `irontrellis repin` | Updates attestation of a valid pinned prefix; refuses rollback or an unattested pin with `REPIN_REFUSED` |
| `verify --accept-rollback` / `repin --accept-rollback` | Explicitly accepts loss, records `rollbackAcceptedAt` and previous pin; without a usable owner key the replacement is unattested and readers still refuse it |
| `irontrellis anchor [--kind local] [--anchors-file <file>]` | Signs the head, appends to the selected log, records `ANCHOR_RECORDED`; the receipt's filename must be available to verification or `ANCHOR_LOG_MISSING` results |
| `irontrellis anchor --kind rekor` | Experimental, not exercised against a live service; local verification cannot enumerate the remote log |
| `python -m irontrellis verify history.jsonl` | Frozen legacy/format-1 verifier, not format 2; independent chain/signature/migrated-prefix check; does not consult `.head` or `.anchors`, so a valid truncated prefix may be `ACCEPTED` |

`anchor` and `repin` wait about 1.5 seconds for the writer lock and do not submit the same anchor twice. An anchor costs one event and remains admissible under the documented event-budget rules. These are command limits, not measured performance claims.

A writer without an owner key carries the previous owner attestation; verification reports `PIN_ATTESTED_EARLIER`. A KMS writer can temporarily do the same until its signature arrives. `owner.flush()` waits for pending work; a failed or interrupted flush does not mean the event was undone. Full pin fields and codes are in [signing contracts](api-observations-signing.md).
