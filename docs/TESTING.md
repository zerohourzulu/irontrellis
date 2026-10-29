# How IronTrellis was tested

*RAmEx Labs, 2026-10-26. For developers. Every number below is copied from a recorded result. The result files are in `verification/testing/`, each listed with its SHA-256 under [Evidence](#evidence).*

**What was tested:** the code in this release, 1.0.0-rc.2, unless a row says otherwise. Earlier versions are named where a row ran on one.

**What testing can and can't show:** it finds bugs; it can't show that none are left. No external security audit has been done yet. We say what we found, what we fixed, and what is still open, with its known-issue (KI) number in `docs/records/KNOWN-ISSUES-r2.5.md`.

## Summary

| Kind | Scale | Why it matters | Result | What it found |
|---|---|---|---|---|
| Unit and integration tests | 1,800 tests in 14 packages, plus a 70-step fresh-install check | Every rule, refusal and error code, and that the packages work as the READMEs say once installed | Linux: 1,787 pass, 0 fail, 13 skipped; install check 70/70 | Nothing new |
| Conformance vectors | 706 vectors in 7 suites | Each vector fixes the exact expected result for one input; any implementation must match it field by field | 706 of 706 match | Nothing new |
| An independent checker | 4 suites, re-checked on 2026-10-24 | A second implementation, written from the specification text alone without seeing the engine, catches ambiguities in the spec as well as bugs | v2-regenerated 446 of 460 checks agree; the other 3 suites agree in full | The 14 differences are the newest vectors (session time horizon), which the checker predates. Its own gaps are listed for the next release |
| Comparison with the earlier engine | 53,984 authorization decisions, 8,932 incremental ones and 773 queries | Format 2 must decide exactly as the frozen Continuity 0.2 engine did, wherever their rules overlap | All agree | The old engine crashed 7 times on unsorted grants; the tests cover those inputs |
| Fuzzing, first campaign | 336,201,610 iterations over 7 targets, 23 hours | Random, structure-aware damage to histories, files, commands and network requests: nothing may crash untyped or accept an altered signature | 17 of 17 regressions pass; 27 failure records | 3 bugs, fixed (a command-line option order, a line-splitting rule, a `-0` position); 3 code differences kept as KI 72, 74 and 75 |
| Fuzzing, format 2 against the independent checker | 880,839,324 iterations, 23 hours | Two readers must never disagree on whether a history is valid | 327 failure groups | **1 engine bug:** a migrated history could carry a version list that contradicts its own source. Fixed in this release, with 4 test vectors. The rest are gaps in the independent checker, or refusal-code differences from the Python verifier (KI 88–90) |
| Crash recovery: every crash point | 3,088 cases | Power loss or a crash at any write must never lose a record, send twice or corrupt the history | 0 violations | Nothing in the shipped outbox |
| Crash recovery: random kills | 200 `kill -9` at random moments | The same, at moments nobody chose | 1 violation | A kill in a window of microseconds left an empty journal file in the **experimental** sending tool, and resume then stopped. Nothing was sent twice. Fixed in the tool's next version, under review |
| Earlier crash runs | 1,002 cases, then 868 on later versions | The same checks on earlier versions of the sending tool | 0 violations | The first 12-case trial found 2 resume bugs, fixed before the full run |
| Public test network | 64, then 219 transactions on Etherlink Shadownet | The real chain: fees, delays and node errors | Both readers agree; 21, then 93 negative controls pass | A gas cap and a posting-lag stop, both fixed |
| Mainnet, chapter 1 | 219 transactions on Etherlink mainnet | The [chapter 1 record](examples/chapter-1-record.md), checkable by anyone | VERIFIED; all six statements also matched through a second, independent node | A node error mid-send (resumed), a funds check that stopped safely, and a wrong label in the summary file; none affected the record |
| Rehearsals before mainnet | 15, then 60 offline runs | The full sending sequence, repeated until clean | 60 of 60 clean | 2 of the first 15 failed on a false conflict in the shipped outbox (a signature value with a leading zero byte). Fixed |
| Security reviews | 7 reviews before and after the first commit | Attackers' view: custody, installation, witnesses and key rotation, release checks, the agent plugin | Findings with proof-of-concept attacks, re-run after the fixes | Listed below |
| Rebuilding the proof program | 2 fresh builds with the pinned recipe; 1 rebuild on Linux at the earlier macOS build's exact paths | Zero-knowledge proofs mean something only if the proved program comes from the published source | Two pinned-recipe builds of an earlier candidate, on one machine, gave the identical program (SHA-256 `b9efb822…`) and the same derived identity | Our Linux rebuild did not reproduce the earlier macOS build byte for byte, even at the same paths, because Cargo mixes the build machine's platform into crate hashes. The release therefore uses the pinned Linux recipe at fixed paths that anyone can rerun. The release edition, with regenerated test inputs, changes the program and still needs its own matching builds |
| Machine-checked proofs (Lean) | 15 headline theorems in 32 source files, selected from larger checked editions (2,048 theorems in the 17 October edition) | The core rules stated precisely and proved, not sampled | The source editions were kernel-checked and rebuilt independently on a separate Linux virtual machine; the published selection was then built from clean on Linux, and each theorem uses only Lean's standard axioms | See `verification/SelectLeanProofs/` |
| Zero-knowledge proofs | 7 workloads | A history can be checked without revealing it | Being produced for this release's program; published in `verification/SelectZKProofs/` when verified | The release's test inputs had to be regenerated under the current rules, so the proofs follow the launch |

## Notes for developers

**Mac versus Linux.** On a macOS arm64 Mac the same suite gives 1,760 pass and 26 fail. All 26 pass on Linux, by name: 24 need Unix sockets, which the Mac's sandbox refuses, and 2 are timing budgets missed under load (KI 43). The Linux run is the reference.

**The conformance suites** were generated by the engine, except the legacy suite (Continuity's own vectors) and v2 (made by the specification's generator). Every run prints "Finite selected-vector evidence, not full protocol certification", and we mean it.

**The independent checker** is advisory, not a proof. It was written by a separate AI agent (OpenAI Codex) from the specification alone. Where it and the engine disagree, we decide from the specification which one is wrong, and record the answer.

**Fuzzing.** The fuzzer is in the repository (`fuzz/`). Its format-2 extension, which ran the second campaign, is on a branch that joins the repository in the next release. A third campaign is still running and isn't counted here.

**Rebuilding the proof program.** The recipe pins Linux x86-64, the toolchain release, the sources and four fixed build paths (`/src/irontrellis`, `/src/registry`, `/toolchain/rust`, `/build/irontrellis`). Two fresh builds of an earlier candidate with it, on one machine, gave the identical program, and the release edition, whose regenerated inputs change the program, needs its own matching builds; an outside rebuild by someone else is what would make that independent, and the published recipe allows one. We don't claim the program rebuilds identically on other platforms or at other paths, or that the earlier macOS build and the Linux build are equivalent: their identities differ. The tool that derives the program's identity gave the same result on Linux as on macOS for the same program.

**Crash recovery.** Each case stops the sending tool at one recorded save point, or kills it at a random moment, then resumes it up to three times. A case passes when every account's nonce equals the clean run's and the rebuilt history verifies, or when the tool stops safely in a documented way. The harness is ours, and it joins the repository in the next release, cleaned so it runs outside our machines.

## Security reviews

| Review | When | What it found | Status |
|---|---|---|---|
| Independent code review | 2026-09 | 2 blocking, 3 high, 10 medium, 12 low | Fixed, with four qualifications: 2 are documented limitations ([M5](history/2026-09-24-independent-review.md#medium), [L6](history/2026-09-24-independent-review.md#low), in SECURITY.md); [L4](history/2026-09-24-independent-review.md#low) is fixed for format 2, and format-1 files, which still accept an unsigned declaration, can now only be read; [M9](history/2026-09-24-independent-review.md#medium) (Windows directory sync) is tested only by simulating Windows |
| Release verification | 2026-09 | 1 high ([R1](history/2026-09-24-release-verification.md#3-regressions-and-new-findings-ranked)): a history could be opened from a pin without a valid owner attestation | Fixed: the opener refuses such a pin; tests named for R1 pass |
| Witness and key rotation | 2026-09 | 11 proof-of-concept attacks | [B1](history/2026-09-25-witness-and-rotation-review.md#b1-a-witness-bound-history-is-silently-rolled-back-with-no-owner-key-and-no-tls-break--the-witnesss-latest-is-not-proven-to-be-the-latest-and-the-attacker-writable-side-file-can-relocate-a-bound-witnesss-endpoint) and [H1](history/2026-09-25-witness-and-rotation-review.md#h1-the-attacker-writable-side-file-can-inflate-quorum-and-add-witnesses-so-the-honest-bound-witnesss-answer-is-no-longer-required--defeating-the-bound-witness-without-removing-it) fixed; [M2](history/2026-09-25-witness-and-rotation-review.md#m2-a-retired-owner-key-is-still-accepted-by-any-witness-that-has-not-yet-recorded-the-rotation-and-the-attacker-can-keep-it-that-way) closed as designed; [N1](history/2026-09-25-witness-and-rotation-review.md#n1-medium-the-owner-seal-on-a-cached-latest-is-not-bound-to-the-witnesss-identity-and-a-fresh-reader-maps-a-witness-to-its-cache-entry-through-the-side-file-this-is-a-possible-bypass-of-the-latest-note-protection-for-requireonopen-readers), [N2](history/2026-09-25-witness-and-rotation-review.md#n2-low-the-residual-the-fixer-flagged-is-confirmed-from-the-code-a-bound-witness-without-a-registration-receipt-that-answers-with-an-unsigned-404-counts-as-answered-no-head-for-readers) and [F1](history/2026-09-25-witness-and-rotation-review.md#f1-medium-the-one-supersede-per-epoch-rule-plus-the-1024-head-cap-lets-a-leaked-key-holder-pin-a-forged-head-as-a-witnesss-latest-defeating-supersede-recovery-for-that-witness) fixed, with tests named for them passing |
| Custody | 2026-09 | 7 cross-user attacks, 16 malicious-agent cases, 12 findings | All 12 fixed; attacks re-run |
| Installation and migration | 2026-09 | 1 high, 4 medium, 5 low | All fixed |
| Production readiness | 2026-09 | 0 blocking, 0 high, 3 medium, 5 low; about 450,000 authorization comparisons | All fixed |
| Agent plugin and hook | 2026-10-23 | 13 findings | Fixed, except one kept as KI 70 |

Where a fix is shown by tests named for the finding rather than by a second review, the table says so.

One measure of the readiness review: a deliberately broken engine (a mutant) made 618 wrong decisions in 12,600, while all 23 tests that existed then still passed. That is why the comparison tests above exist.

## Run it yourself

```sh
pnpm install --frozen-lockfile && pnpm build
pnpm test                                   # the 1,800 tests
pnpm verify:install                         # the fresh-install check
node conformance/run.mjs --suite v2-regenerated --adapter …   # one conformance suite
node fuzz/run.mjs …                         # the fuzzer (format 1 in this release)
```

The chapter 1 check is on [its own page](examples/chapter-1-record.md).

## Evidence

Every result file is listed with its SHA-256, what it shows and any redaction in [verification/testing/MANIFEST.md](../verification/testing/MANIFEST.md): the test and install results (Linux and Mac), the conformance results, the independent checker's results, both fuzz campaign reports, the crash and kill audit, and the network runs. The published Lean selection, with the commands to rebuild it and print each theorem's axioms, is in [verification/SelectLeanProofs/](../verification/SelectLeanProofs/).
