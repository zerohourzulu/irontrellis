# J, sampled, on the chapter 1 pilot story with sealed-note/2 (shadownet-02 2a584b8)

*The Builder (Mac), 2026-10-24, 15:44:53–16:03:55Z (`started.txt`, `finished.txt`), 8 shards (`run-sampled.sh`), head 2a584b88c5451fbcb835522820da36baf9589535 (`head.txt`). For the coordinator 20261024T153437Z, item 5: the dry-run checks re-run after the sealed note gained its salted commitment and its binding.*

- **The story:** `stories/chapter1-pilot.json` (the reviewer is the successor), both switches on, E5 genesis. It was made by `run-sampled.sh` itself (`make-story.json`) with stand-in keys, a stand-in bureau key (`standin-bureau-key/`), a stand-in note and a stand-in salt. 177 entries; checkpoints at 27, 129, 133, 134, 158 and 176; the sealed description is 393 characters.
- **The design:** the same as `sampled-mac-chapter1-b855c4d`: `--occurrences first,middle,last --every-outbox`, 233 of the trace's cases, each with a fresh local chain and folder, one crash, then up to 3 resumes, and the guided clearance where rc.2 stops at `HALTED`.
- **Priority:** normal; the sandbox refuses nice.

| Cases | COMPLETED | after clearance | SAFE_STOP | VIOLATION |
|---|---|---|---|---|
| 233 (all unique by point and occurrence) | 215 | 12 | 6 | **0** |

- **SAFE_STOP:** only at `after:SUBMISSION_STARTED`, one per checkpoint (statements 0–5), each "statement N stopped (rerun to reconcile): OUTCOME_UNKNOWN". That's rc.2's reconcile-only case.
- **COMPLETED_AFTER_CLEARANCE:** only at `after:SIGN_STARTED` and `before:SIGNED`, 6 each.
- **Reconstruction:** for all 227 completed cases, availability, anchors and closure verify, with no failures and the same trust root.
- **Against b855c4d:** the same counts, at the same points, as the run before the sealed note changed. Only the sealed entry's description differs, and it is one body-writer entry like any other.
