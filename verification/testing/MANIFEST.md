# Testing evidence: files and hashes

These files are the raw records behind our testing summary: unit and install-check runs on a Mac and on a Linux machine, conformance runs, an independent checker written from the specification alone, two fuzzing campaigns, crash and kill enumeration of the experimental anchoring send tool, and runs on the Shadownet test network. Each file is published as it was recorded, except for the redactions listed below, and the table gives every file's sha256. The unit, install-check and conformance runs test the 1.0.0-rc.2 code in this release; the other lines name their own version where one applies.

Paths are relative to this folder. This file is not in its own table.

The short hexadecimal ids in the table (such as `56d7e99`) are internal development commit ids. The public repository starts with a fresh history, so they don't resolve in it.

| public path | sha256 | description |
|---|---|---|
| `unit/mac-test-gate.json` | `7104acdd9288ac89d82736cc5ddb003fc0f7821bc0d67d94ec994f2f16a96c24` | Mac test gate record: 1,800 tests, 1,760 pass, 26 fail, 14 skipped (status FAILED); the 26 are 24 Unix-socket refusals by the Mac sandbox and 2 timing limits |
| `unit/mac-test.log` | `728fdea1a7da21f481a56939c5e9ffeca2f4d7219ae4840ad26fb67e6c8c8209` | Mac test run log, 1,800 tests in 14 package runs, the 1.0.0-rc.2 code in this release |
| `unit/mac-verify-install-gate.json` | `35c97244f3ee064779503949f4310b17ed8cd2591fddf9c2115eda7478713812` | Mac install-check gate record (status FAILED: 1 check failed because the Mac sandbox refused a temporary folder) |
| `unit/mac-verify-install.log` | `3707c755dc7294ae235c5dc509ccd67f25e510dfb625b2c57185d6c40591cb1c` | Mac install-check log: 69 of 70 checks pass, 11 packages at 1.0.0-rc.2 |
| `unit/linux-test.log` | `4e619cf97a1715684ca27ccb4fc61340d470097f9bc6c8cfcb9e48a0ec438c00` | Linux test run log, 1,800 tests: 1,787 pass, 0 fail, 13 skipped, the 1.0.0-rc.2 code in this release |
| `unit/linux-verify-install.log` | `36f7ffdc1cd497c9367a2c6c9bcba7f1bf81911550da53225f5f8b6cfe76e2ad` | Linux install-check log: 70 of 70 checks pass, 11 packages at 1.0.0-rc.2 |
| `unit/linux-verify-install.json` | `a6218cdd51c85b9c410ea0ee76dcde76f39e7d2948bb382699f13deb08bc5ea8` | Linux install-check results, machine-readable: verdict PASS, 70 rows, with each package tarball's size and integrity hash |
| `unit/linux-summary.tsv` | `951105cb8acae6d6870b1f57462084b3591eee793f9cac95328b1d8127a6fa51` | Linux run steps with exit codes and times: tests, install check, scratch-folder probe, Python conformance (all exit 0) |
| `unit/mac-linux-failure-compare.txt` | `b8cf8e133f34a4a34d4dba20a302954890b95513be1ab1f051a41257fcfe9fc6` | Comparison by name: each of the 26 Mac test failures and the 1 Mac install-check failure passes on Linux |
| `conformance/mac-conformance-gate.json` | `ff2c73f2a8847df6b1e1b32f2b104d3a671578af67f294e9acdd110270021f20` | Mac conformance gate record: 7 suites through the TypeScript adapter, all exit 0 (status PASS), the 1.0.0-rc.2 code in this release |
| `conformance/mac-conformance.log` | `56ea9e439e38dbd66771145e5435e7c3eb8b651d87f6a03a6fec4e021f4075f4` | Mac conformance log: 706 of 706 vectors pass (legacy 34, v1 90, v2 86, v2-g3 86, v2-regenerated 253, v2-owner-policy 89, v2-human-attestation 68) |
| `conformance/linux-python-conformance.log` | `02101068f663c6b75068d8a36caa54dd430749275360fbc8ee2c05a94f2e25e1` | Linux conformance log, Python adapter: legacy 34 of 34 and v1 90 of 90 match |
| `checker/v2-g3.json` | `4585145981f40aa12f64b68ee9bcb2f0767ea4813d24d6a9deb2d156189148f0` | Independent checker written from the specification alone, v2-g3 vectors: 130 of 130 checks agree (full report) |
| `checker/v2-g3.txt` | `94ddc90441a2293ab782b03bf6cd2b69a2d85ec0f5c1030faae896965a9f45c0` | Summary of the v2-g3 checker run |
| `checker/v2-owner-policy.json` | `f9ae8eef9fbc60554aee602f73456ec6a843d860ac237a96bb78d36d300d6466` | Independent checker, v2-owner-policy vectors: 170 of 170 checks agree (full report) |
| `checker/v2-owner-policy.txt` | `3fd871107d0a7dacd8974d9fa9cad11425cc592d9ff1e2edeced9169d63b3756` | Summary of the v2-owner-policy checker run |
| `checker/v2-human-attestation.json` | `244bb69ef799c3d4e02c5b280ea352149321c9234004d533737f2517e2609de7` | Independent checker, v2-human-attestation vectors: 146 of 146 checks agree (full report) |
| `checker/v2-human-attestation.txt` | `0f9c12d96d5bb5564db975177343c43b444891940ecb5e8a854a940c0bb63edd` | Summary of the v2-human-attestation checker run |
| `checker/v2-regenerated.json` | `aa69a1c94f8c8d7608ec60fa6098df7bbd4386263e32aa3ce249796e8c3e6193` | Independent checker, v2-regenerated vectors: 446 of 460 checks agree; the 14 that differ are the session-time-horizon vectors, which are newer than the checker (full report) |
| `checker/v2-regenerated.txt` | `ad3c81482d931ccc3014a93defba5564241892f38e07a6b510f3da4a0d218f08` | Summary of the v2-regenerated checker run, with its first 5 differences |
| `fuzz-1/cli-args.json` | `5b7b0a8f9246f794adec293aa719037cb110e05a44692c743ea007fc5f9b7d76` | First fuzzing campaign (master 56d7e99, 23 hours on a cloud Linux machine), cli-args target: 10,227,287 iterations, 4 unique failures |
| `fuzz-1/events.json` | `2122c25a8665c7b0e5ca0e93ce069ca820ca8b6584b976b3e5ffff598c8acea4` | First fuzzing campaign, events target: 137,447,183 iterations, 1 unique failure |
| `fuzz-1/replay.json` | `c7cdf695d178d6b3328eb52cb31a26c35d6170b60db5de0dead6d19f3fab4438` | First fuzzing campaign, replay target: 1,593,745 iterations, 18 unique failures |
| `fuzz-1/sidefile.json` | `302af4beae5344cd5e0347f07d5ea548766dcf9a017afe0c48d425fcbf1468c6` | First fuzzing campaign, sidefile target: 6,679,118 iterations, 0 failures |
| `fuzz-1/store.json` | `7dd129b27d78399c23d257cfcf3ad593e16ef383397a8aea7bf0c7af84aad71f` | First fuzzing campaign, store target: 1,124,324 iterations, 1 unique failure |
| `fuzz-1/transparency.json` | `6e1f5a9229510de0031dd92683149e778fd82a701d4c2d29b221a871508bc863` | First fuzzing campaign, transparency target: 164,157,702 iterations, 2 unique failures |
| `fuzz-1/witness-http.json` | `e818b52c1bd3015616f28a269d05944be1ef463fa69cd4d8c28cc96906492c67` | First fuzzing campaign, witness-http target: 14,972,251 iterations, 0 failures |
| `fuzz-1/recheck.jsonl` | `ae77268612cbcf78ab2f41a03f2701f6079a1182aad6d28fb3c597eddc2aff59` | Re-check of the first campaign's 27 failure records on master 3866a75: 22 now pass, 5 still differ (both engines refuse; only the codes differ) |
| `fuzz-2/results.md` | `459a368d67e0249056188c82c975b42aa9edc023dc2806efb3df02f746e05709` | Write-up of the 23-hour format-2 differential fuzzing campaign (unmerged branch fuzz-format2-01 at 5835c26, Linux test machine): campaigns, failure tiers and the one engine finding |
| `fuzz-2/replay-reports.tgz` | `571c12fcecb38e89577ec5d6d7db722b6729b039c06de09cfb2fe0ae993c982a` | Format-2 campaign, replay target, seeds 311, 312 and 313: 1,197,924, 1,193,504 and 1,183,349 iterations; 99, 98 and 104 unique failures (three reports, packed; members below) |
| `fuzz-2/events-341-1.json` | `31069c829b3d7ff2d93d360b232480d04be55cf93b6fdf391ea7e52be5886f9e` | Format-2 campaign, events target, seed 341: 428,576,812 iterations, 23 unique failures |
| `fuzz-2/store-321-1.json` | `4b852851a5c47f0c77edd8bfb70470d281d90ea89187d4c3a4da06da1f1e554b` | Format-2 campaign, store target, seed 321: 2,002,816 iterations, 2 unique failures |
| `fuzz-2/store-322-1.json` | `306bf8e4b737af96a6ee6ca605e3d35e348178fd2d0c22c3522dc553ea04d213` | Format-2 campaign, store target, seed 322: 2,018,752 iterations, 1 unique failure |
| `fuzz-2/transparency-331-1.json` | `5b53b1b65ad79817eddec23347d50eb960c745ba72db746093e5cb384d6143b1` | Format-2 campaign, transparency target, seed 331: 438,853,713 iterations, 0 failures |
| `fuzz-2/canonical-351-7.json` | `e6228eb4e00043622bc03ea038d7a6e81d1ea78ac3f8005ff1fdd372f98cfe99` | Format-2 campaign, canonical target, seed 351, run 7: 5,812,454 iterations, 0 failures (runs 1 to 6 stopped at the 2 GiB memory cap) |
| `crash/kill-audit-result.json` | `6247fb2785df881c0514ee651bcba2a0822515a21acca38364b07b822d5fa5d5` | Crash and kill enumeration audit of the experimental send tool (bad18f8, cloud Linux machine): 3,288 cases, every crash point plus 200 kill -9s; 1 violation, a stuck resume, never a double send |
| `crash/full-mac-c5939c8.md` | `1c0468484819af6e2698b0458e6046c24ebc190f72b7922fa77465c91303986f` | Crash enumeration on a Mac, every crash point of two short stories, send tool at c5939c8: 1,002 cases, 0 violations |
| `crash/sampled-mac-f2f5dd4.md` | `8e6aa29ab80fa74cee26715dfd2dc01d9c2b9694df9716fe12816c6f0b539af1` | Sampled crash enumeration at f2f5dd4, the version used for the Shadownet live run: 402 cases, 0 violations |
| `crash/sampled-chapter1-b855c4d.md` | `de69a42d81603f65b9e854f4ea1e1f9c69695e74ad358b5a5f32b47d2420ce30` | Sampled crash enumeration on the chapter 1 story at b855c4d: 233 cases, 0 violations |
| `crash/sampled-chapter1-2a584b8.md` | `66f487cd9a45a466c7ad38ba73f5e0b79ebff3c0222939d0d48ad00996f65430` | Sampled crash enumeration on the chapter 1 story at 2a584b8, after the sealed-note change: 233 cases, 0 violations |
| `shadownet/live-run-summary.json` | `4dc91218a25a5db7f3d6227a6e682b0c26719b0ccbda3ea8dae12c0d7000d96e` | Shadownet live run summary (send tool at f2f5dd4): 6 statements, all L1_FINAL; availability, anchors and closure verified; 0.479853634 test XTZ |
| `shadownet/reader2-result.json` | `7d14878427de949a9215f9f3287ab122570bc610225cda27e5b12eb90f94a018` | Second, separately written reader's check of the same live run: the readers agree; 6 head attestations and 4 receipt artifacts verified, 21 negative controls |
| `shadownet/chapter1-rehearsal-result.json` | `e2426f3d1718c4a45405c4c8ba59e116cea3fb2c5e0695d5c0bc061587653aef` | Shadownet rehearsal of the exact chapter 1 record: 177 events, 219 transactions, both readers pass, 28 receipt artifacts verified, 93 negative controls, 2.036660219 test XTZ |

**Members of `fuzz-2/replay-reports.tgz`** (unpack it in `fuzz-2/` to get the three reports):

| member | bytes | sha256 |
|---|---:|---|
| `replay-311-1.json` | 4,265,521 | `a9ab1972a948883fe8422ac27f12d6c6a92903d8dc3a9ad2305fb8f04cdd7d32` |
| `replay-312-1.json` | 5,330,072 | `329a7e751340bfbff60402b3c41dcd287783b396a017db08ff71ba017718d30a` |
| `replay-313-1.json` | 6,202,510 | `293c6b267e393e8cc2cc29ecacbfa2f2fdc26bcc91a3408f89dee9615ef65be0` |

The archive is reproducible: members in name order, owner and group 0, mode 0644, a fixed time of 2026-10-26T00:00:00Z, and gzip level 9 with no stored name or time.

## Redactions

A few files contained local folder paths and one machine name. Each was replaced, as literal text, with what is shown below; nothing else in those files was changed, and every redacted JSON file still parses. The number after each file is how many times the rule applied.

- `<WORK>` replaces the Mac's local build folder: unit/mac-test.log (64), unit/mac-verify-install.log (1).
- `<TMP>` replaces the Mac's temporary folder for each run: unit/mac-test.log (19), unit/mac-verify-install.log (1), unit/mac-test-gate.json (1), unit/mac-verify-install-gate.json (1), conformance/mac-conformance-gate.json (1).
- `<RUN>` replaces the Linux test machine's run folder: unit/linux-test.log (6), unit/linux-verify-install.log (1).
- `<FUZZ-TMP>` replaces the cloud fuzzing machine's temporary folder: fuzz-1/cli-args.json (3).
- `<RUNS>` replaces the local folder that holds the Shadownet run folders: shadownet/reader2-result.json (12), shadownet/chapter1-rehearsal-result.json (14).
- The words "our Linux test VM" replace the Linux test machine's host name in one sentence: fuzz-2/results.md (1).

`WORK/` in the gate records (for example `"cwd": "WORK/tree"`) is the run tool's own short name for the build folder, as recorded, not a redaction.

## Hashes inside the gate records

logSha256 inside a gate record is the hash of the unredacted log; the published log is a redacted copy (rules above). The same is true of each step's outputSha256, the hash of that command's output, which the log holds between the `$ command` line and the line break before `[exit N]`. The conformance log needed no redaction, so the hashes in `conformance/mac-conformance-gate.json` match the published `conformance/mac-conformance.log`.
