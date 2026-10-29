# J, the full Mac run: every crash point, both short stories (shadownet-01 c5939c8)

*The Builder (Mac), 2026-10-24, 07:42–08:07Z (the first plan file and the last summary file), 8 shards. Each case: a fresh local chain and folder, one crash at that (point, occurrence), then up to 3 resumes; a case stopping at an rc.2 `HALTED` runs the guided clearance. COMPLETED and COMPLETED_AFTER_CLEARANCE both require each account's nonce to equal the clean run's and the reconstruction to verify (availability, anchors, and for the receipt story the closure).*

## The short Dana story with receipts (stand-in keys; heads 16, 25, 29, 30, 38, 45)
**508 cases: 490 COMPLETED, 12 COMPLETED_AFTER_CLEARANCE, 6 SAFE_STOP, 0 VIOLATION.**

| Crash point | Cases | COMPLETED | after clearance | SAFE_STOP | VIOLATION |
|---|---|---|---|---|---|
| `after:ACCOUNT_RESERVATION` | 6 | 6 | 0 | 0 | 0 |
| `after:ATTEMPT` | 6 | 6 | 0 | 0 | 0 |
| `after:DIRECTORY_SYNC` | 23 | 23 | 0 | 0 | 0 |
| `after:JOB` | 6 | 6 | 0 | 0 | 0 |
| `after:JOURNAL_INTENT` | 58 | 58 | 0 | 0 | 0 |
| `after:JOURNAL_RESULT` | 58 | 58 | 0 | 0 | 0 |
| `after:JOURNAL_SEND` | 58 | 58 | 0 | 0 | 0 |
| `after:JOURNAL_SEND_STARTED` | 58 | 58 | 0 | 0 | 0 |
| `after:JOURNAL_SIGNED` | 58 | 58 | 0 | 0 | 0 |
| `after:NONCE_RESERVATION` | 6 | 6 | 0 | 0 | 0 |
| `after:OBSERVATION` | 12 | 12 | 0 | 0 | 0 |
| `after:PREDECESSOR_INDEX` | 6 | 6 | 0 | 0 | 0 |
| `after:PROFILE` | 1 | 1 | 0 | 0 | 0 |
| `after:PROFILE_OBSERVATION` | 1 | 1 | 0 | 0 | 0 |
| `after:SEQUENCE_INDEX` | 6 | 6 | 0 | 0 | 0 |
| `after:SIGNED` | 6 | 6 | 0 | 0 | 0 |
| `after:SIGN_STARTED` | 6 | 0 | 6 | 0 | 0 |
| `after:SUBMISSION_STARTED` | 6 | 0 | 0 | 6 | 0 |
| `after:TERMINAL` | 6 | 6 | 0 | 0 | 0 |
| `before:ACCOUNT_RESERVATION` | 6 | 6 | 0 | 0 | 0 |
| `before:ATTEMPT` | 18 | 18 | 0 | 0 | 0 |
| `before:DIRECTORY_SYNC` | 23 | 23 | 0 | 0 | 0 |
| `before:JOB` | 6 | 6 | 0 | 0 | 0 |
| `before:NONCE_RESERVATION` | 18 | 18 | 0 | 0 | 0 |
| `before:OBSERVATION` | 12 | 12 | 0 | 0 | 0 |
| `before:PREDECESSOR_INDEX` | 6 | 6 | 0 | 0 | 0 |
| `before:PROFILE` | 1 | 1 | 0 | 0 | 0 |
| `before:PROFILE_OBSERVATION` | 1 | 1 | 0 | 0 | 0 |
| `before:SEQUENCE_INDEX` | 6 | 6 | 0 | 0 | 0 |
| `before:SIGNED` | 6 | 0 | 6 | 0 | 0 |
| `before:SIGN_STARTED` | 6 | 6 | 0 | 0 | 0 |
| `before:SUBMISSION_STARTED` | 6 | 6 | 0 | 0 | 0 |
| `before:TERMINAL` | 6 | 6 | 0 | 0 | 0 |

## rich-v2 (conformance; heads 15, 31, 47, 61; no receipts, so BODIES)
**494 cases: 482 COMPLETED, 8 COMPLETED_AFTER_CLEARANCE, 4 SAFE_STOP, 0 VIOLATION.**

| Crash point | Cases | COMPLETED | after clearance | SAFE_STOP | VIOLATION |
|---|---|---|---|---|---|
| `after:ACCOUNT_RESERVATION` | 4 | 4 | 0 | 0 | 0 |
| `after:ATTEMPT` | 4 | 4 | 0 | 0 | 0 |
| `after:DIRECTORY_SYNC` | 19 | 19 | 0 | 0 | 0 |
| `after:JOB` | 4 | 4 | 0 | 0 | 0 |
| `after:JOURNAL_INTENT` | 68 | 68 | 0 | 0 | 0 |
| `after:JOURNAL_RESULT` | 68 | 68 | 0 | 0 | 0 |
| `after:JOURNAL_SEND` | 68 | 68 | 0 | 0 | 0 |
| `after:JOURNAL_SEND_STARTED` | 68 | 68 | 0 | 0 | 0 |
| `after:JOURNAL_SIGNED` | 68 | 68 | 0 | 0 | 0 |
| `after:NONCE_RESERVATION` | 4 | 4 | 0 | 0 | 0 |
| `after:OBSERVATION` | 8 | 8 | 0 | 0 | 0 |
| `after:PREDECESSOR_INDEX` | 4 | 4 | 0 | 0 | 0 |
| `after:PROFILE` | 1 | 1 | 0 | 0 | 0 |
| `after:PROFILE_OBSERVATION` | 1 | 1 | 0 | 0 | 0 |
| `after:SEQUENCE_INDEX` | 4 | 4 | 0 | 0 | 0 |
| `after:SIGNED` | 4 | 4 | 0 | 0 | 0 |
| `after:SIGN_STARTED` | 4 | 0 | 4 | 0 | 0 |
| `after:SUBMISSION_STARTED` | 4 | 0 | 0 | 4 | 0 |
| `after:TERMINAL` | 4 | 4 | 0 | 0 | 0 |
| `before:ACCOUNT_RESERVATION` | 4 | 4 | 0 | 0 | 0 |
| `before:ATTEMPT` | 12 | 12 | 0 | 0 | 0 |
| `before:DIRECTORY_SYNC` | 19 | 19 | 0 | 0 | 0 |
| `before:JOB` | 4 | 4 | 0 | 0 | 0 |
| `before:NONCE_RESERVATION` | 12 | 12 | 0 | 0 | 0 |
| `before:OBSERVATION` | 8 | 8 | 0 | 0 | 0 |
| `before:PREDECESSOR_INDEX` | 4 | 4 | 0 | 0 | 0 |
| `before:PROFILE` | 1 | 1 | 0 | 0 | 0 |
| `before:PROFILE_OBSERVATION` | 1 | 1 | 0 | 0 | 0 |
| `before:SEQUENCE_INDEX` | 4 | 4 | 0 | 0 | 0 |
| `before:SIGNED` | 4 | 0 | 4 | 0 | 0 |
| `before:SIGN_STARTED` | 4 | 4 | 0 | 0 | 0 |
| `before:SUBMISSION_STARTED` | 4 | 4 | 0 | 0 | 0 |
| `before:TERMINAL` | 4 | 4 | 0 | 0 | 0 |

## Reading it
- **No violation anywhere:** no account ever passed the clean run's nonce, and every completed run reconstructs and verifies.
- **The safe stops** are only the rc.2 outbox's `OUTCOME_UNKNOWN` after `SUBMISSION_STARTED`, one per statement: the transaction is recorded as handed over but was never broadcast. rc.2 has no clearance for that case, so it waits and escalates (path (i)), and live-run explains it.
- **The guided clearance** completes every `after:SIGN_STARTED` and `before:SIGNED` case (rc.2's `SIGNING_UNCERTAIN`).
- **Every body-writer journal point completes,** including `after:JOURNAL_SEND_STARTED` (one identical-byte rebroadcast), as do the receipt uploads.
