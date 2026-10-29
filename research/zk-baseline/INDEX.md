<!-- research/zk-baseline/INDEX.md — final text ruled by the architect 2026-10-10 (addendum A-14). Copy verbatim. Names and sha256 identities only; no paths. -->

# ZK baseline index

This file lists the identities of the Continuity ZK baseline: the Continuity Core proof work that the founder keeps as a separate option for users who want ZK despite slower performance.
- IronTrellis does not vendor, build or verify these artifacts.
- This index lets anyone match an artifact to its identity later.
- Every digest is SHA-256, written as 64 lowercase hex characters.

**Archive location:** founder's Continuity deliverables (pending brand launch).

**Status of each entry**
- **V**: recomputed from the file on 2026-10-10 (by the drafter, and again by the architect for every V and C entry of §1–§3 and §7); equal to the sha256 and byte count in its packet manifest.
- **C**: recomputed from the file; the file is not listed in a packet manifest (it is the manifest itself, or a container zip).
- **P**: pinned by a record whose own status is V. The body is not in the deliverables, so it was not recomputed.
- **S**: an identity value stated in a record with status V. It is not a file digest.

## 1. Finite closeout packet — `continuity-zk-finite-closeout-2026-10-07-r1`

| artifact | bytes | sha256 | status |
|---|---:|---|---|
| `MANIFEST.record` | 1,181 | `fe9caafb9507f5e2c3a029cd1f9f8c2eb8bf349a2360f413a0844a8af9dd51da` | C; also equals `closeoutManifestSha256` in §2 `PEER-RETURN-MANIFEST.record` |
| `REPORT.md` | 4,312 | `8c0240e285b42a6bb378c129bab387f27b6bcb5301e95e5a0bcd908c0bf8fc21` | V |
| `PHASE-MAP.json` | 12,395 | `e806310a1aa9f15af70524f0976d1f737c36771ccc9d1534eb4b9b08ed5e0faa` | V |
| `READ-PINS.json` | 6,647 | `6d2ce2af3ac89664cc599172939bc3e96cae3283a339f992064af4f182389363` | V |
| `FULL100-MEASUREMENTS.json` | 930 | `854f9bc7bf39d7ad6885a1b330fda4651859c63fa47a362d68d425abb98f70c3` | V |
| `ROOT-FINAL-FINITE-FREEZE.json` | 2,761 | `6d7bff86f3ee29ed65e25dbac0a5aa5422bea87fd547737b9d8cd5aac107eb87` | V |
| `PACKAGE-INDEX.record` | 546 | `35ee8560ffbf86c38736e424244e02d84a5862f5b44d2e303bf5bd5b392ccbaa` | V |
| signed-exhaustion results archive (`continuity-signed-exhaustion-results-2026-10-07-r2`) | — | `8358e1566432d8bfecacc6a9c514313ad41a506e784a6d797e3cfdd5937c4d50` | P (`PACKAGE-INDEX.record`) |

## 2. Final review addendum — `continuity-zk-final-review-addendum-2026-10-07-r1`

| artifact | bytes | sha256 | status |
|---|---:|---|---|
| `MANIFEST.record` | 1,722 | `e4698028bb1cfe785b587a5f19bd2958f3e8a7434835f07052de94e43b30ca60` | C |
| `PEER-01-CLAUDE-FINAL.md` | 3,910 | `88df8c1f1629df09adabb951809f8cd26e45429d715cc25abcdd55b645c2a68c` | V |
| `PEER-02-FABLE-FINAL.md` | 3,582 | `dca477b118881233d0410362c2237371f2fb111ebc465f28426242ec43619e01` | V |
| `PEER-RETURN-MANIFEST.record` | 758 | `66c8705add992ae11547625e66ed9da7e518067612224623f43c73dcd7c2a853` | V |
| `PROOF-VERIFIER-PHASE-CENSUS.json` | 14,273 | `50202c790908a31bfc9dc61e3e904eb18bba066cef149458ae42ab2dc17e22e4` | V |
| `REPORT.md` | 5,063 | `44b1d29512cc87067ccb56850599c7085d13a95f8fa3129649bde982c34d6814` | V |
| `ROOT-CASE-DISPOSITION-v2.json` | 11,928 | `17fd668ac9799c93a2a9f4271b2ccddf6819920f45d3907fcb49e0d3aa371396` | V |
| `ROOT-FINITE-FREEZE-NOTES-v2.json` | 10,427 | `264305239939ef26124b35b709f86ee9bb2de1625f2af41d5cd096a3824b45cd` | V |
| `ROOT-REVIEW-RECONCILIATION.json` | 5,520 | `9504e295969c4f9cffac69e79f7d3bdfb425e03e67350203766efee8099f7df0` | V |
| `SOURCE-READ-PINS.json` | 12,893 | `051f1049661809721034a39970b0eae8d208cbce9941308efbb24ae985c06cd8` | V |
| signed case manifest | — | `d4b4329edfe0d522ab8abce4cb8203711be717f915041db35d3ee5a47debd3bd` | P (`PEER-RETURN-MANIFEST.record`) |

## 3. Roadmap closure — `continuity-zk-roadmap-closure-2026-10-07-r1`

| artifact | bytes | sha256 | status |
|---|---:|---|---|
| `MANIFEST.record` | 515 | `d2a994c5aacc2d16a0f52386f660e8516af0cde533e2ac58e0e5abede7cbe767` | C |
| `CLOSURE.json` | 2,525 | `56026a44c7b0c189c2b44ce614d084e5e6bde28b762a233cb10a8d6bf10fe10e` | V |
| `FUTURE-WORK.md` | 2,538 | `9cd926d32fa4d1e736835bb48de80829c002c30438901e804b27c0bbd3ff7234` | V |
| `README.md` | 800 | `63351a080c96127e94eebd91d555d8196abfcbf7c4a9a6a6c0ea471ebfa609d5` | V |
| `ROADMAP-CLOSURE.zip` | 3,668 | `afb859608f4432ec8d996512356b9a037d9107f0ac9730c973b4970594900289` | C; contains the four files above, byte-identical |

## 4. Final dispositions (pinned in §1 `READ-PINS.json`)

| artifact | bytes | sha256 | status |
|---|---:|---|---|
| r3 first-count — final disposition (`ROOT-FINAL-DISPOSITION.json`) | 5,555 | `e94f34752776a8127ffd619f6ba58ffabe3238b5671799a6acf8a0d7e62ab2a7` | P |
| r3 core-cumulative-both — final disposition (`ROOT-FINAL-DISPOSITION.json`) | 8,460 | `495fb116f3464095fda3744d8df5209cd2f7daf739b2b0846bf0fb65b4e0dada` | P |
| r3 handover-both — final disposition (`ROOT-FINAL-DISPOSITION.json`) | 6,008 | `9856f6a8c61b1b12a8c5645eae1710cf975c0f971330b2dbea42fb6150cf8ecd` | P |
| r3 handover-state — final disposition (`ROOT-FINAL-DISPOSITION.json`) | 6,500 | `3f4e181121540958bd0088bfbda91bb193d2b398a99f683ae17bbadb9c735587` | P |
| r3 threeperiod-both — final disposition (`ROOT-FINAL-DISPOSITION.json`) | 8,260 | `1d1368da4a6ef41de68f51935bf309bf9039d3732b5696f91237530793b2fd5c` | P |
| r3 revocation-both — final disposition (`ROOT-FINAL-DISPOSITION.json`) | 7,951 | `275c958692100b8ce825975c6926d01da462745bc95a3eb9f413281aa355419b` | P |
| r3 full100-budget — final disposition (`ROOT-FINAL-DISPOSITION.json`) | 7,648 | `623fcb62059d7812c68b8202a36fc8276c7071371198f233297328e905eb7775` | P |
| r3.1 uncapped, final results review — final disposition (`ROOT-FINAL-DISPOSITION.json`) | 9,148 | `26e5582963f3f8a6e1591c3551da88ce021a1be3405c40b59747cefbd65abaf4` | P |

The r3.1 disposition's documentary labels are superseded by §2 `ROOT-CASE-DISPOSITION-v2.json`. Its digest is unchanged.

## 5. Sealed program identities and r3.1 proof artifacts

The `app_exe_commit`/`app_vm_commit` identities come from §2 `ROOT-FINITE-FREEZE-NOTES-v2.json` (two sealed program identities share one VM commit); the r3.1 `programId` and the proof artifacts come from §2 `ROOT-CASE-DISPOSITION-v2.json`.

| identity or artifact | bytes | value / sha256 | status |
|---|---:|---|---|
| r3 `app_exe_commit` (seven r3 rows) | — | `0x0017f8d39deabb152b0fe1d25020a20b5e9d6307a712091213f6187abf57dc7c` | S |
| r3.1 `app_exe_commit` (one r3.1 row) | — | `0x002212903b5c3c9d68ac8f4fc4075e1d09863790ec33c2753dd494ea48398e2d` | S |
| shared `app_vm_commit` | — | `0x00664689458909ebe486a253ee0e3d67e8bc873b6d4a0f8a28090d0dbe99233e` | S |
| r3.1 `programId` | — | `d6de3d6877f10990d79ed8a95a552d8185953a6eadecf596b2c71418bb334a25` | S |
| r3.1 static proof (`static.snark`) | 6,129 | `d2be0bd6a1b0ff12a1d3abf1e9d290bae127ef8fa873e70396e96a09f6855e4b` | P |
| r3.1 root proof (`root.proof`) | 229,722 | `e7c14611c1203cb61009b36874f7d589133a8caf939bb41c0923627751e9b5d7` | P |
| r3.1 application proof (`private-app.proof`) | 216,724,645 | `75f6d46564504ae35d82b95711a2372dffd2a677d720f514bdd242fc41ab4b62` | P |
| r3.1 wrap proof (`candidate.evm.proof`) | 3,846 | `f1d444bdfac6213b6f602ed79d607b13cd68436aac7ba1dd4436380d3a473c46` | P |
| r3.1 final verification pins (`ROOT-COMPLETED-FINAL-VERIFICATION-PINS.json`) | 43,818 | `030f41318e0ae461c3e8453fbecbc43d4459ab8e9bf02c410464cb277e9e4fa3` | P |

## 6. Q suite

| item | value | status |
|---|---|---|
| suite identity | `cq-case-range64-ristretto255-bulletproofs5-v2` | S |
| parameter digest (as written in the sources, without `0x`) | `ef32743e75dba42eef6488dcbc7273b6d4a12d920a735d0126ddd86e672febce` | S: stated identically in three documents of the §7 design-review package |

## 7. Earlier deliverable zips

| artifact | bytes | sha256 | status |
|---|---:|---|---|
| `continuity-core-zk-design-review-2026-10-04-r1.zip` | 2,202,068 | `58f1f20e09573c9a2f00dea81f6ea1e903b3f69724da87f72f1ce39d29fe1438` | C |
| — its internal `MANIFEST.json` (619 entries; all match the extracted files) | 177,722 | `c86a84529090748c03da2e7d2d2d333b48aa367c0ed6a25744d03d2eeeb9d33e` | C |
| `continuity-core-zk-compatibility-2026-10-06-r1.zip` | 99,339 | `5b5d7677a5c658d3ac474ae5135c6944dc6cf3d0c78a8d17a6059f487e7318c5` | C |
| — its internal `SHA256SUMS` (19 entries; all match the extracted files) | 1,692 | `f383ac9e3b0a6ee7914f1d0c30b429e17290489280f9853940ae198c4f1f42bd` | C |

## 8. Sealed kit

| item | sha256 | status |
|---|---|---|
| sealed r2.2 ZK kit ZIP (`continuity-openvm-private-workflow-2026-10-01-r2.2`) | `9b02dceae05d2fb1ca7bd6b02559bbe70eb26b4952063a33dc9bac74a4608730` | stated in `SEALED-KIT-SELECTION.json` (`kitArchiveSha256`); verified against the ZIP by its keeper |
| sealed kit `MANIFEST.json` | `b3522e5a1c684114e9846ea8ebb743287efa8545a002014c9b66610ac08bb8b2` | C (recomputed from the copy of `SEALED-KIT-MANIFEST.json`; equals `kitManifestSha256` in `SEALED-KIT-SELECTION.json`) |

---

**Where the bodies are.** The bodies stay with the founder until the IronTrellis brand launch. At that launch, a separate set of summary (root) proofs and the program that checks them go to the IronTrellis GitHub as a founder action; none of the files listed here is among them. Until then the archive location is "founder's Continuity deliverables (pending brand launch)". The builder publishes nothing.
