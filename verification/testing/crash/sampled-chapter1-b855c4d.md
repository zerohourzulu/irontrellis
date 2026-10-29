# J, sampled, on the chapter 1 pilot story (shadownet-02 b855c4d)

*The Builder (Mac), 2026-10-24, 15:07:13–15:26:00Z (`started.txt`, `finished.txt`), 8 shards (`run-sampled.sh`), head b855c4dac3276735dda8e512f0b2e6f779f61799 (`head.txt`). For the coordinator 20261024T144935Z, item 5.*

**The story:** `stories/chapter1-pilot.json`, with both switches on: the sealed entry, the open investigation, and the attempt-policy (E5) genesis. It was made with stand-in keys and a stand-in bureau key (`story-chapter1/`, `standin-bureau-key/`, `standin-note.txt`): 177 entries, checkpoints at 27, 129, 133, 134, 158 and 176.

**The design:** the accepted `--occurrences first,middle,last --every-outbox` selection, **233 of the trace's 1,283 cases**. Each case gets a fresh local chain and folder, one crash, then up to 3 resumes; a case stopping at an rc.2 `HALTED` runs the guided clearance.

**nice:** asked for 19, but the sandbox refuses it (`nice.txt`), so the shards ran at normal priority, on the Mac.

| Cases | COMPLETED | after clearance | SAFE_STOP | VIOLATION |
|---|---|---|---|---|
| 233 (all unique by point and occurrence) | 215 | 12 | 6 | **0** |

- **SAFE_STOP:** only at `after:SUBMISSION_STARTED`, one per checkpoint, each "statement N stopped (rerun to reconcile): OUTCOME_UNKNOWN". That's rc.2's reconcile-only case, path (i).
- **COMPLETED_AFTER_CLEARANCE:** only at `after:SIGN_STARTED` and `before:SIGNED`, one each per checkpoint.
- **Reconstruction:** for all 227 completed cases, availability, anchors and closure verify, with the same trust root throughout.
- **Compared with the earlier runs** (c5939c8 at full size, f2f5dd4 sampled, on the Dana and rich-v2 stories): the same outcome classes at the same points, with the two new elements (the agent's OBLIGATION_CREATED and the desk's attempt duty and policy activation) among the body-writer entries.
