# J, sampled, on the exact version that will run (shadownet-02 f2f5dd4, on master 88ae768)

*The Builder (Mac), 2026-10-24, 12:41:19–12:52:28Z (`started.txt`, `finished.txt`), 8 shards (`run-sampled.sh`), head f2f5dd43a2cfc79ad19c523f38365c686720ee5c (`head.txt`). The coordinator 20261024T123946Z, item 2.*

**The design:** the `--occurrences first,middle,last --every-outbox` selection Astra accepted on 2026-10-24 (the f11c60f review): the first, middle and last occurrence of each crash point kind, plus every occurrence of the rc.2 outbox's points. Each case gets a fresh local chain and folder, one crash, then up to 3 resumes; a case stopping at an rc.2 `HALTED` runs the guided clearance.

COMPLETED and COMPLETED_AFTER_CLEARANCE both require each account's nonce to equal the clean run's, and the reconstruction to verify: availability, anchors and the same trust root, plus the closure for the receipt story.

**nice:** asked for 19, but the sandbox refuses it (`nice.txt`: "setpriority: Operation not permitted"), so the shards ran at normal priority. This is on the Mac, not the cloud instance.

| Story | Cases (of the full trace) | COMPLETED | after clearance | SAFE_STOP | VIOLATION |
|---|---|---|---|---|---|
| Dana, with receipts (`story-short-r/`, stand-in keys; heads 16,25,29,30,38,45) | 233 (of 508) | 215 | 12 | 6 | **0** |
| rich-v2 (conformance; heads 15,31,47,61; no receipts) | 169 (of 494) | 157 | 8 | 4 | **0** |
| **Both** | **402** | 372 | 20 | 10 | **0** |

- **Every case is unique by (point, occurrence)** (233 and 169), and the selections match `plan-short/` and `plan-rich/` (`--plan-only`). The Dana count is the 233 Astra reviewed.
- **SAFE_STOP:** only at `after:SUBMISSION_STARTED`, one per checkpoint (6 and 4), each "statement N stopped (rerun to reconcile): OUTCOME_UNKNOWN". That's rc.2's reconcile-only case after a recorded hand-off, which can't be cleared (path (i): wait and escalate). It's the same pattern as the full run at c5939c8.
- **COMPLETED_AFTER_CLEARANCE:** only at `after:SIGN_STARTED` and `before:SIGNED`, one each per checkpoint. The guided clearance completed the record in every case.
- **Reconstruction:** it verifies for every COMPLETED and COMPLETED_AFTER_CLEARANCE case. For the Dana story, the closure verifies on all 227 completed cases, and the trust root is the same in every case.
- **Compared with full-mac-c5939c8 (1,002 cases, every occurrence, at the earlier version):** the same outcome classes at the same points, and no VIOLATION in either run.

Files:
- `jsamp-<story>-s<k>/` (plan, clean run, cases, summary) and `jsamp-*.log`;
- `story-short-r/`, the copy of the stand-in story used by both runs (history.json 15a767e1…).
