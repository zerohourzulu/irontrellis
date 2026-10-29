# Where the IronTrellis Core specification r5.2 comes from

This note records how the specification in `docs/spec/` was produced. It lists the exact source files by SHA-256, so that anyone holding them can confirm that nothing else went in.

## What is in `docs/spec/`

- **`SPEC-IRONTRELLIS-CORE-v2-EFFECTIVE-r5.2.md`:** the consolidated IronTrellis Core specification, history format 2. It is the r5 text plus two corrections editions (r5.1, r5.2); see its Preamble.
- **`SPEC-IRONTRELLIS-ANCHORING-PROFILES-r2.md`:** a companion document. It holds the rules for anchoring a history on a public chain, for federation and for chain connectors, which are deliberately kept outside Core.
- **`SPEC-IRONTRELLIS-ZK-ABI-v2-r1.md`:** a companion document. It holds the rulings that amend the zero-knowledge proof interface: the exact data a proving program receives and returns, and how each piece is fingerprinted.
- **`zk-abi-base/ABI-v1.md` and `ABI-v2.md`:** the base texts that this ZK companion amends, byte-identical to the versions the rulings cite.

## How the text was made

1. **Rulings.** Every change to the specification was first ruled by the project's architect (an AI model acting in that role), in the numbered rulings files below. No model is treated as a proof or policy authority: rulings are text, and the project's conformance vectors and reviews check them.
2. **Drafting.** The architect wrote r5 in seven batches. Each batch replaced only whole sections, anchored on exact heading lines. A mechanical assembler refused any change outside those sections.
3. **Mechanical checks.** Each batch was checked for:
   - word-level differences against its base;
   - coverage: every required ruling appears, and no withdrawn ruling is tagged;
   - internal cross-references.
4. **Sign-off.** The architect reviewed r5 as a whole and signed it with five corrections, which were applied.
5. **Independent review.** A different model (Claude Opus 5.5, at extra-high effort) reviewed r5 independently. The verdict was no blocking findings: three medium and nine minor. Its corrections and the architect's rulings on them (`ADDENDA-AS02.md`, A-192…A-198) make up r5.1.
6. **A fidelity review and a further sitting (r5.2).** Four reviewers read the project's Lean models and zero-knowledge program against the specification. The architect's rulings on the questions they raised (`ADDENDA-AS03.md`, A-199…A-208) make up r5.2. They state exactly which theorem carries the "revocation never expands authority" claim, settle five rule questions, and correct the formal-methods appendix (F) so that it says only what the Lean edition proves.
7. **The founder's names.** The founder named the post-rc.2 milestone for live public-chain anchoring **IronTrellisLiveChainAnchor**, and the word a verifier report prints for an anchor found final in consensus-verified mode **LiveChainFinalized**. r5.1 and the anchoring companion use these names.

## Source rulings files (SHA-256)

The rulings are numbered A-0 to A-208 across these files, in order; r4 integrated A-0…A-85, r5 integrated A-86…A-191, r5.1 applies A-192…A-198, and r5.2 applies A-199…A-208.

| file | SHA-256 |
|---|---|
| `ADDENDA-G0.md` | `3a3988d98c014da3ee08fcff8c5dc9cbf7115881778c7254f0800f00824e404d` |
| `ADDENDA-G1.md` | `eafb11248262ecc4ce385f028a41a3e2664ecd8583dc5f8e2d1a6ae6c7131d47` |
| `ADDENDA-G2.md` | `4cf789f9493008b6aaa37883c2546f56622f7f25c140a90953f99aa308bcfa1e` |
| `ADDENDA-G3.md` | `17cdf49dcf7c38f5af8f27b4d923b0f6c432e0a7faa7649bce9f5bb1346da346` |
| `ADDENDA-G4.md` | `1e1ceb1ece3b94fbb6ed2b65b30ea5e84eaad547653b6d55c307db4e56712c44` |
| `ADDENDA-G5.md` | `8589fa07317891970289f77c34dc1d4639e4e301c1f38eaccde4508373562688` |
| `ADDENDA-G6.md` | `f3abf9f188500733bad27e3170770815fbed61f34f22bdead1517fb56154ade3` |
| `ADDENDA-G6.1.md` | `7c77f672dbbd7827a10840b755ecc89fe2af78cb3c2ffd12b382999c29734f49` |
| `ADDENDA-G6.2.md` | `f1a4dcd905de6156f8c8b910264b879a55f847e993417b8cea69f8aed3c5feff` |
| `ADDENDA-G6.3.md` | `2fb07bfc6dc709728569b744c9629986c33df090e42c2e9beb59a81af01240a2` |
| `ADDENDA-G6.4.md` | `fdeca0be426927b16ca82f163c9af8dac2ce4a754b573e6efbab075730828158` |
| `ADDENDA-G6.5.md` | `d681a9b885129bd708492c5d3636099d8343b193823fefbebcb0e478942a9f18` |
| `ADDENDA-G6.6-FEDERATION.md` | `26efc9c8545de00d68838d7eaeb6c770cc3a84ef1393f847d85520455f9317aa` |
| `ADDENDA-G6.7.md` | `9ec1d67bea827154da2f337ccadea2cc9e26d18bd00bda6ba4177c37f8f43cd9` |
| `ADDENDA-G6.8.md` | `8107a0b80900345da5b2a4332a9d17e45af667428189231c6a8557944a684dc8` |
| `ADDENDA-G6.9.md` | `2a003a87f26f991f6c47e5c251cd9070544f03a3969a8cbe1ee398ba09a3be60` |
| `ADDENDA-G6.10.md` | `4bc2a9c01c1f243184ae14733e353cc885982b376cc1bc19abf9ecdfbc57f4d8` |
| `ADDENDA-AS01.md` | `96252e99160e2c83be4bec3b3b456a756954283de4da8df04acaf70af576e36f` |
| `ADDENDA-AS01-PART2.md` | `e3b0a09dda01984eb663b9956651377e747cb0a723ee2f0de832f0b828c8ad02` |
| `ADDENDA-AS02.md` | `ea66b4f9b4456136d0a3e42a41d4f83c5cce0cd52fd70d925a563e41ea1ec357` |
| `ADDENDA-AS03.md` | `580485b4696e18f20fce29bf30707b416562dc8d9e350ce8d61e1ada8f436854` |

**Issued after r5.2, without changing its text:** `ADDENDA-AS03-ERRATUM-01.md` (`e3313f0480547f594ce4a3286337c662eb89095f90a37bdd4d650c8ebe251f8a`).
- It contains A-199.5: the ASM-1 witness list is revised, and the theorem statement and r5.2's claim wording are unchanged.
- ASM-1 itself was accepted on 22 Oct 2026 (the coordinator's verification record). The final wording of A-199 §6 enters the next edition.

## Records kept in `docs/records/`

- **`KNOWN-ISSUES-r2.2.md`:** the known issues of this tree after the step 5 builder fixes (5, 5b, 5c, 5d), as reconciled against the specification.
- **`DEVIATIONS-r2.2.md`:** the places where the implementation records a deliberate, ruled difference or detail, including the coordinator's applications and the breaking changes against the 1.0.0-rc.1 API.

The r1 editions are in the repository history.
