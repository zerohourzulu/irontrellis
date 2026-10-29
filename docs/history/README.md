# Historical reviews: a reader's guide

IronTrellis keeps an append-only, signed history of what an AI agent was allowed to do, what it was refused, and what it still owes when it is replaced. That history is only useful if a quiet change to it gets noticed, whether the agent makes it, someone else on the machine, or a careless operator.

This folder holds eight documents that tested how far that holds. They were written between 24 and 26 September 2026, while the first release candidate, 1.0.0-rc.1, was being built. Six are reviews: the reviewers had not written the code they reviewed, and were asked to break it. They installed it as a stranger would, attacked it as an attacker or a careless operator would, and wrote down steps that reproduce each failure. The other two are measurement reports.

## Why we publish them

A security project asks you to trust its claims. These reports show how the claims were tested, including where they failed. In the first review, deleting one small file made a revoked permission work again, and the history still checked out as clean. We publish the reports as written, failures included, with this guide to where each serious finding stands today.

## Read them as history

**Kept word for word.** The eight reports are preserved byte for byte. To check, run `shasum -a 256` (or `sha256sum`) on them and compare:

| File | SHA-256 |
|---|---|
| `2026-09-24-independent-review.md` | `f47530a3b3c4e10e54690127a5fd913fb20a4db2701c6b224c957556cc71565a` |
| `2026-09-24-release-verification.md` | `d29e05c9cd99a6b8b0276a54781f16e9d3870fe1b9af4fe62430b50b193dabf4` |
| `2026-09-25-witness-and-rotation-review.md` | `ff032083cf2acabb2b3018740e437ab45c78ebb83fbdeb499b623cc1c33f0544` |
| `2026-09-26-custody-review.md` | `f5d53931525bd9e7e81c7e62e6cd8405a42b84ad7c00eb936c80f72dea9824ba` |
| `2026-09-26-install-and-migrate-review.md` | `04c2737adbb414fb621c469a8eaa58f8c0713729ebbe0c8517a45ce7bc347da7` |
| `2026-09-26-production-readiness-review.md` | `72ce72444f17cd0f162dc7261b64809630a6408761c4ec6164ba26c10991fad0` |
| `BENCHMARKS-2026-09-24.md` | `7fe8115413cfc1af474f55d62c9066f8849408397de4392b9f7c0f87985d7b74` |
| `PERFORMANCE-2026-09-26.md` | `71e62f8d5c97d853bbba275a66113df747f4c2c9bdd4fe4b2458914c693f533f` |

The six reviews moved here from `docs/reviews/` (a [pointer](../reviews/README.md) remains), and the two measurement reports from `docs/`, with names and contents unchanged. The move and its hashes are recorded in MOVE-FILES.json, part of the documentation handoff rather than this repository; the table lets you check without it.

**Old names, paths and terms.** The reports use September's vocabulary: build stages, the reviewers' working folders, unpublished notes and since-renamed error codes. "How to read a finding" at the end decodes them.

**The code then, not now.** Since September, 1.0.0-rc.2 writes history format 2, and format-1 and legacy files open read only ([CHANGELOG](../../CHANGELOG.md), line 93). Each review opens with a note saying its findings "were fixed before 1.0.0-rc.1 or are listed as known limitations in docs/SECURITY.md §8". That note was written for all six at once; this guide checks each serious finding on its own, and today's limitations are spread across sections 2 to 7 of [Security](../SECURITY.md).

For current behavior, start with [the root README](../../README.md), [Security](../SECURITY.md), [History format](../HISTORY-FORMAT.md), [API](../API.md) and the [CHANGELOG](../../CHANGELOG.md).

## How this guide traces a finding

Each serious finding gets one answer: **fixed**, with the evidence (a CHANGELOG entry, a test, the code or a docs section); a **known limitation**, with where it is written down ([Security](../SECURITY.md) or the [known issues](../records/KNOWN-ISSUES-r2.5.md)); **superseded**, when the code no longer exists or no longer writes; or **status not traced here**.

Evidence is cited as `path:line` from the repository root, as of 28 October 2026. We traced it by reading code, tests and documents, not by rerunning tests or the reviewers' reproductions, and a passing test shows only the case it covers. "Fixed" means the problem as reported is handled, not that the area has no other problems. These reports don't certify the current code, and no external security audit has been reported ([Security](../SECURITY.md) §8).

## Words you will meet

- **Owner key:** signs every change of power, such as a grant or a revocation. Agents sign their own records with **session keys**.
- **Format 1, legacy, format 2:** history formats. Legacy is the format of Continuity, IronTrellis's former name, and doesn't sign changes of power. September's code wrote format 1 by default.
- **Pin:** a small file beside the history (`<history>.head`) recording its latest head, the position and hash of the last event. A cut-short history no longer matches its pin. An **attested** pin also carries the owner's signature.
- **Anchor log:** a file (`<history>.anchors`) recording heads the owner vouched for, so a later copy can be compared with them.
- **Witness:** a separate server, run outside the agent's host, that keeps its own signed log of a history's heads, so a reader can tell whether a copy is the latest. A history **binds** its witnesses in owner-signed events. The **side file** (`<history>.witness.json`) is local witness state that an attacker on the host can edit.
- **Rotation, pre-rotation:** replacing the owner key. With pre-rotation, the history commits to the next key in advance, so a thief holding only the current key can't choose its successor.
- **Custody, key reference:** custody is who holds the owner's private key. A key reference names where the key lives (an ssh-agent, HashiCorp Vault, a signing program) instead of holding it.
- **Hook, gateway:** the hook (`irontrellis-hook`) checks a coding agent's tool calls in Claude Code, Codex or Cursor. The MCP gateway checks calls to MCP tools.
- **Tripwire:** a best-effort rule that catches common attempts but is not a security boundary.

## The six reviews at a glance

| Date | Report | What it tried to break | Verdict then | Serious findings today |
|---|---|---|---|---|
| 24 September 2026 | [Independent review](2026-09-24-independent-review.md) | The whole product, from a clean copy | "Not yet deployable to customers" | 2 blockers, 3 highs: all fixed, one only in part |
| 24 September 2026 | [Release verification](2026-09-24-release-verification.md) | The fixes for the review above | One blocking hole left | Fixed; one medium fixed in part |
| 25 September 2026 | [Witness and rotation](2026-09-25-witness-and-rotation-review.md) | The remote witness and key rotation, in three rounds | A blocker in round one, fixed in round two | All fixed; one also a documented limit |
| 26 September 2026 | [Custody](2026-09-26-custody-review.md) | Keeping the owner key from the agent | "The core signing path is solid" | Both highs fixed |
| 26 September 2026 | [Install and migrate](2026-09-26-install-and-migrate-review.md) | Installing the guard; migrating histories | One high, four mediums | All fixed |
| 26 September 2026 | [Production readiness](2026-09-26-production-readiness-review.md) | Performance work, Windows, the release pipeline | No blockers or highs | Three mediums, all fixed |

## 24 September 2026: independent review

**What it checked.** Installation, the command line, the hook, the gateway, the Python verifier and the documentation's claims, attacked from a clean copy.

**Verdict then.** "Not yet deployable to customers." The engine was "in good shape", but "three promises customers will rely on do not hold today": rollback detection, the hook as a boundary, and agreement between the two verifiers.

| Finding | In plain words | Today |
|---|---|---|
| **B1** (blocker) | Cut a revocation off the end of a history, delete the pin, and the history still verified; the revoked grant answered ALLOW. Stripping the pin's signature, or restoring an old copy with its old pin, also worked. | **Fixed.** Every opener refuses a history with events but no pin, or with a pin the owner didn't attest: `packages/core/src/store.ts:16-22`, CHANGELOG line 155. Tests `packages/core/test/store.test.mjs:597` and `packages/core/test/signer-anchor.test.mjs:321` use format-1 files; the same rules apply to format 2. |
| **B2** (blocker) | In the hook's quickstart, the agent's shell could read the owner key and edit the hook's configuration, so it could grant itself anything and the history verified clean. | **Fixed in part; a known limitation.** The hook's state now lives outside the project, and `init --allow run-shell` needs `--i-understand-same-user-risk`: `packages/hooks/src/setup.ts:136-138`, test `packages/hooks/test/hook.test.mjs:144`. On one OS user, a shell grant can still expose owner authority ([Security](../SECURITY.md) lines 71-77). |
| **H1** (high) | Answering "allow" skipped Claude Code's own permission prompt, so installing the guard widened what the agent could do unasked. | **Fixed.** Allowed calls go to the host's own check by default: `packages/hooks/src/config.ts:91`, test `packages/hooks/test/hook.test.mjs:323`. |
| **H2** (high) | A malformed tool event, such as one without a session id, was let through. | **Fixed** in the hook: malformed events are refused unless `failOpen`, off by default, is set (test `packages/hooks/test/hook.test.mjs:668`; CHANGELOG line 113). Under Codex, a hook that times out or crashes still lets the call through ([known issues 61 and 77](../records/KNOWN-ISSUES-r2.5.md)). |
| **H3** (high) | The Python verifier accepted a cut-short migrated history, losing a revocation, where Node rejected it. | **Fixed.** `python/src/irontrellis/replay.py:144`, test `python/tests/test_store_and_replay.py:118`, conformance vector `replay/v1/rejects-incomplete-migrated-prefix` (`conformance/v1/generate.mjs:534`). |

**Lower-severity findings.** Ten mediums, twelve lows and seven setup problems; see the report. The release verification found seven of the mediums fixed. Three remain as documented limits: the Python verifier doesn't check pins or witnesses (M5; [Security](../SECURITY.md) line 148); migration signs whatever an older history contains, so an unpinned source now needs an explicit opt-in (L5; `packages/core/src/migrate.ts:316-321`, Security line 200); and an older signing path is not claimed to be constant-time (L6; Security line 200).

## 24 September 2026: release verification

**What it checked.** A fresh copy: all 15 build, lint and test gates, then the first review's attacks rerun against the fixes.

**Verdict then.** Every gate passed and most fixes held, but B1 was "only partly fixed": "R1 is the one blocking item, and it is small."

| Finding | In plain words | Today |
|---|---|---|
| **R1** (high, blocking) | Instead of deleting the pin, write an unsigned one at the cut-down head; a pin's fields are public, so no key is needed. Readers answered ALLOW for the revoked grant, and the next write, or `repin`, re-signed the cut-down history. | **Fixed.** Every opener refuses a pin without a valid owner attestation, and writers and `repin` won't build on it: `packages/core/src/store.ts:1089-1096`; tests `packages/core/test/store.test.mjs:707`, `packages/hooks/test/hook.test.mjs:361`. A narrower window is documented: records written without the owner key, such as the hook's and gateway's, aren't covered by an attestation until the next owner write ([Security](../SECURITY.md) lines 119-123). |
| **R2** (medium) | Decisions never read the anchor log. Restoring an older history with its own genuinely signed pin brought a revoked grant back, although `verify` failed. | **Fixed in part; a known limitation.** Every open now reads the local anchor log and refuses a copy it shows was cut back: test `packages/cli/test/cli.test.mjs:441`; CHANGELOG lines 155-156. Someone who restores the history, its pin and every local anchor log can still hide later events ([Security](../SECURITY.md) line 129); a remote witness addresses that. |

**Lower-severity findings.** Four lows; see the report. R3 (cutting a legacy history goes unnoticed) is superseded: legacy files open read only (CHANGELOG lines 39 and 91). R4 (the host's own settings were unprotected) is fixed (CHANGELOG lines 53 and 108). R6 (no repair for a torn last line) is documented in [Operator](../OPERATOR.md) lines 235-237. R5 concerned text since rewritten.

## 25 September 2026: witness and owner-key rotation review

**What it checked.** The remote witness and owner-key rotation, in three rounds: a review, a re-review after fixes, and a review of pre-rotation and recovery. The attacker controlled every file on the agent's host and its network, but held no owner key unless a finding says so.

**Verdict then.** Round two confirmed round one's blocker and high fixed. Round three closed the leaked-key finding for histories with a committed next key, and found one new medium.

| Finding | In plain words | Today |
|---|---|---|
| **B1** (blocker) | With no owner key, an attacker restored an old copy, pointed the side file at a relay, and replayed the witness's genuine older answer as the newest. | **Fixed.** Witness answers are signed over a fresh random value from the client, and a bound witness's address comes only from the owner-signed binding: CHANGELOG lines 180 and 182; tests `packages/core/test/witness-review.test.mjs:105`, `:169`. |
| **H1** (high) | The side file could raise the number of answers needed and add the attacker's own witness, so the honest one was no longer required. | **Fixed.** Every check needs answers from the bound witnesses themselves: CHANGELOG line 182; test `packages/core/test/witness-review.test.mjs:221`. |
| **M1** (medium) | The owner's software read the file several times while preparing a witness statement, so a file swapped in between could get a different branch signed. | **Fixed.** Statements are signed under the writer lock from one read: CHANGELOG line 181; test `packages/core/test/witness-review.test.mjs:322`. |
| **M2** (medium) | After a leaked owner key was rotated out, a witness that hadn't heard of the rotation still accepted the old key, and an attacker could keep it that way. | **Fixed with a committed next key** (test `packages/witness/test/e2e-prerotation.test.mjs:133`); **otherwise a known limitation** ([Security](../SECURITY.md) §2.1, lines 98-111). |
| **N1** (medium, round two) | A cached witness answer, sealed by the owner, wasn't tied to the witness it came from. | **Fixed.** Test `packages/core/test/witness-review.test.mjs:422`. Related and open: a writable side file can stretch how long a cached answer is trusted, up to 24 hours ([known issue 83](../records/KNOWN-ISSUES-r2.5.md)). |
| **F1** (medium, round three) | A thief could push more than 1,024 heads to a witness, past a limit that then blocked the owner's recovery. | **Fixed.** Test `packages/witness/test/e2e-prerotation.test.mjs:444` pushes 1,100, and recovery still works. |

**Lower-severity findings.** Three lows, each fixed: `packages/witness/test/state.test.mjs:428`, `packages/witness/test/http.test.mjs:352`, `packages/core/test/witness-review.test.mjs:509`.

## 26 September 2026: owner-key custody review

**What it checked.** Whether the owner key stays out of the agent's reach when an ssh-agent, Vault or a signing program holds it, with a real second OS user for the agent. `irontrellis doctor` audits that setup; `--as-agent` runs it as the agent's user.

**Verdict then.** "The core signing path is solid." The weak spot was `doctor`.

| Finding | In plain words | Today |
|---|---|---|
| **H1** (high) | `doctor` contacted the signer a key reference named before checking the reference. A planted reference could send the owner's Vault token, or any one-line file the owner can read, to the agent. | **Fixed.** `doctor` reads references only through the signing loaders and contacts nothing for a refused one: `packages/cli/src/doctor.ts:516`; test `packages/cli/test/doctor-users.test.mjs:56`, with a real second OS user. |
| **H2** (high) | In the recommended two-user layout, `doctor --as-agent` passed while the agent held a working owner Vault token. | **Fixed.** A token in the agent's environment fails, and a signer it can't see is reported as not checked: `packages/cli/src/doctor.ts:396`; test `packages/cli/test/doctor-users.test.mjs:90`, run in CI with two users (`.github/workflows/ci.yml:73-77`). `doctor` supports a review; it doesn't prove isolation ([Security](../SECURITY.md) line 77). |

**Lower-severity findings.** Three mediums and seven lows, fixed in the report's own table (tests `packages/core/test/custody-review.test.mjs:23-163`, `packages/hooks/test/custody.test.mjs:140`). For L1, the `irontrellis` command now reports a write whose pin signature failed afterwards as recorded but unattested, exit code 4 (`packages/cli/test/custody.test.mjs:248`). The review did not cover the gateway's operator tool, `irontrellis-mcp-ops revoke`, which still reports such a revocation as done; that is [known issue 94](../records/KNOWN-ISSUES-r2.5.md).

## 26 September 2026: install and migrate review

**What it checked.** `irontrellis-hook install --write`, which adds the guard to a coding agent's settings file; `migrate`, which re-records an older history in a newer format, with the owner key held by a signer; and a writer-lock test.

**Verdict then.** One high, four mediums, five lows, all fixed the same day.

| Finding | In plain words | Today |
|---|---|---|
| **H1** (high) | If the agent planted a copy of the guard limited to a nonexistent tool, reinstalling as a "repair" deleted the real guard and reported success. | **Fixed.** The guard counts as installed only where it runs for every tool; anything else is refused: `packages/hooks/src/setup.ts:472-508`; test `packages/hooks/test/hook.test.mjs:979`. |
| **M1** (medium) | `migrate` could adopt a private key file on disk while saying the key was held by a signer. | **Fixed.** `packages/core/src/migrate.ts:348`. |
| **M2** (medium) | `migrate` could write the new history before proving the signer could sign. | **Fixed.** A signed challenge comes first: `packages/core/src/migrate.ts:558`. |
| **M3** (medium) | The lock test missed a lock that deleted another writer's live lock. | **Fixed.** `packages/core/test/store.test.mjs:388`. |
| **M4** (medium) | Install rewrote the settings file in place; a crash could leave it empty, which means no guard. | **Fixed.** It writes a copy and renames it into place (test `packages/hooks/test/hook.test.mjs:979`). |

**Lower-severity findings.** Five lows, fixed and covered by the same test. 1.0.0-rc.2 later changed what install writes for Claude Code (CHANGELOG line 98); the rule from H1 still applies.

## 26 September 2026: production-readiness review

**What it checked.** Performance work, Windows support, and packaging and release. The reviewer compared the new engine with the old one on about 450,000 authorization decisions and 2,514 deliberately damaged histories.

**Verdict then.** "I found no verdict change from the performance work." No blockers or highs.

| Finding | In plain words | Today |
|---|---|---|
| **M1** (medium) | The Python library's reading functions still accepted an unsigned legacy history disguised as a format-1 file. | **Fixed.** Tests `python/tests/test_fuzz_regressions.py:181-225`. |
| **M2** (medium) | The release check installed one set of package files; the publish step built and published another, unchecked. | **Fixed in the workflow:** it packs once, checks those files and checksums, and publishes exactly them (`.github/workflows/release.yml:90-107`; CHANGELOG line 213). |
| **M3** (medium) | A test meant to guard a speed-up didn't notice when it was broken; the broken version gave 618 wrong answers. | **Fixed.** `packages/core/test/candidate-index.test.mjs:104`, mirrored in `python/tests/test_candidate_index.py:72`. |

**Lower-severity findings.** Five lows and four nits, fixed in the report's own table. Evading the hook's command rules (L1) is fixed as far as a tripwire can be (`packages/hooks/test/tripwire.test.mjs:10`; limit in [Security](../SECURITY.md) line 73).

## The measurement reports

Both measured September's format-1 and legacy builds on a small 2-vCPU machine. Neither describes today's format-2 engine: see [Benchmarks](../BENCHMARKS.md) for current figures and [Performance](../PERFORMANCE.md) for planning. The sets used different machines and methods, so they don't compare number for number, and September's figures may not hold: on 12 October 2026 a full format-2 replay took 0.562 ms per event, and a hook check on a 10,000-event history 871 ms, both over budget. These two files carry no note at the top, their titles look current, and their links point at old locations ([known issue 68](../records/KNOWN-ISSUES-r2.5.md)).

**[Benchmarks, 24 September 2026](BENCHMARKS-2026-09-24.md):** the cost of each operation, within about 20 percent. On a 10,000-event format-1 history, opening it and checking every signature took 2.1 to 2.3 s, a warm permission decision 16 to 20 µs, and an owner grant about 2 ms, flat as the history grew. For one agent receiving 85 grants, Continuity's earlier SDK took 42.1 s and IronTrellis 0.18 to 0.20 s.

**[Performance and scale, 26 September 2026](PERFORMANCE-2026-09-26.md):** how cost grows with size. Opening a format-1 history took about 0.13 ms per event: 1.57 s at 10,000 events, 12.9 s at 100,000 and 123 s at 1,000,000, with a 3,140 MiB memory peak. At the 1 GiB file limit, about 1.4 million events, an open took 182 s, and `verify` needed more memory than Node's default. Once open, a warm decision took 30 to 75 µs, and a write that waits for a witness 15.0 ms, against 2.9 ms in the background.

## What these findings left open

Most findings were fixed. These documented limits trace back to them:

- **One OS user is not a boundary:** an agent running as you can reach your owner key (B2; [Security](../SECURITY.md) §2).
- **Freshness rests on evidence kept from the attacker:** a restored copy with its old pin and anchor logs can hide later events, and records written without the owner key stay unattested until the next owner write (B1, R1, R2; Security §3).
- **A leaked key with no committed next key** can still mislead a witness that hasn't recorded the rotation (witness M2; Security §2.1).
- **The Python verifier** reads legacy and format 1 only, without pins or witnesses (Security line 148).
- **Under Codex,** a hook that times out or crashes lets the call through ([known issues 61 and 77](../records/KNOWN-ISSUES-r2.5.md)).
- **Cached witness answers** can be trusted longer than intended ([known issue 83](../records/KNOWN-ISSUES-r2.5.md)).
- **The gateway's operator tool** can report a revocation as done when the owner's signer failed to sign the pin afterwards; the `irontrellis` command reports the same case as exit code 4 ([known issue 94](../records/KNOWN-ISSUES-r2.5.md)).

## How to read a finding

- **Ids are local to each report.** H1 in the independent review is the hook's "allow" problem; H1 in the witness review is the side file raising the quorum. Cite the report with the id. Test names follow the same rule, and some tests use B-numbers for unrelated work.
- **Old paths.** Paths under `/home/claude`, such as `/home/claude/irontrellis-next`, were the reviewers' sandbox working folders, holding the code under review; `/tmp` held their copies and reproduction scripts. None of these ship, and the reports' line numbers refer to the code as it was.
- **Build stages.** Block 2 was the witness and rotation work, block 3 production readiness, block 4 custody, block 5 install and migrate. REVIEW.md was the independent review's original name.
- **Unpublished notes.** WITNESS-DESIGN, WIRE-DEVIATIONS, HANDOFF and NOTES-3.x were internal notes; checklist items refer to the release checklist as it was then.
- **Tooling.** IronTrellis is built with substantial AI assistance ([How this project is built](../HOW-THIS-IS-BUILT.md)); a "fixing agent" or "safety classifier" in a report means that tooling.
- **Links** inside the reports were written for their old folders.

Found something these reviews missed? Report it privately, as [Security](../SECURITY.md) §10 describes.

*Last reviewed: 28 October 2026. This page is revisited at each release.*
