# SPEC-IRONTRELLIS-ZK-ABI-v2-r1 — Companion document to Core EFFECTIVE r5: the format-2 ZK guest ABI rulings (A-146, A-147, A-152, A-153)

## 0. Front matter

**Status.** Revision r1, drafted after Core EFFECTIVE r5 (2026-10-22) as the second of the two companion documents named by A-186.4 and Core P.9. It carries the architect rulings A-146, A-147, A-152 and A-153 as amendments over Astra's format-2 ZK guest ABI. It is a specification of wire shapes, fixture requirements and verifier obligations; it enrolls nothing, credits no proof, and no LLM output, this document included, is a proof or a policy authority. Nothing here is Core text: Core r5 holds only its pointers to this document (P.9, the informative paragraph of §7.4, §15 and Appendix E E-21) [A-186.4].

**Base documents.** This document does not reprint its base. It amends:

- **`ABI-v1.md`** (sha256 `072ec6b0…`, 12 Oct 2026): "Exact experimental ABI proposal — format2 ZK family v1". Its line 235 is the `componentBoundsManifest` derivation (replaced by §3) and its line 239 is the qBackend rule (applied to the numeric closures by §2.3).
- **`ABI-v2.md`** (sha256 `ef0170ef…`, 13 Oct 2026 00:07): Astra's "restricted Ed25519 format-2 experimental revision". It inherits ABI-v1 (the bounds manifest at its line 274, the qBackend rule at its line 278) and adds the section "Numeric Q census (A-147)" (its lines 229–265), written before A-152 and A-153.

Only the first eight hex digits of each digest are among this document's inputs; the full digests are the ABI registry's.

**Precedence.** Where ABI-v2 differs from a ruling, the ruling governs. Within the rulings, the latest text of every chain governs: A-152 amends A-147.1, and a passage produced by such a chain is tagged with the chain, for example `[A-147.1 as amended by A-152.1]`; every other passage carries its final ruling's tag `[A-n.m]` [A-186.3]. The proposals (`ASTRA-Q-SHAPE-DELTAS.md`, `ZK-REVIEW-ERRATA.md`, `ASTRA-Q-NUMERIC-CENSUS.md`, `ASTRA-ZK-A147-RECEIPT-QUESTION.md`, `BOUNDS-LOCATOR-QUESTION.md`) are binding only where a ruling adopts their words; §3.2 carries the one text adopted "exactly as proposed", with the ruling's amendments marked. The design (`FORMAT2-BINDING-DESIGN-v2.md`), the batch-14 review and Astra's G6.8 contract notes are background and rule nothing.

**Conventions.** MUST, MUST NOT, SHOULD and MAY are RFC 2119, used as the rulings use them. `H`, `U53`, `I`, `S`, `T`, `B`, `R`, `SHAFile`, C2 and the codec table are ABI-v1's (its "Hash functions and codecs"). Core rules are cited by section ("Core §9.6") and never restated. "Design §n" and "C1…C13" are the design's sections and change items. Every tag, schema name and codec id is carried byte for byte as the ruling gives it. A conflict between two texts, or a needed rule that no ruling gives, is marked `[GAP: …]` and listed in §5; no gap is resolved silently. The human-attestation feature is PHL (Proof of Human Lineage).

**Core's pointers to this document.** Core P.9 (the pointer list) and §7.4 (the informative anchoring paragraph) name this document and its four rulings; Core §15 says a ZK profile MAY refuse a disclosure field that disagrees with the applied range as a rule of that profile [A-148.2], and §1.6 carries that rule [A-198.4]; Core Appendix E E-21 records the PHL ZK relation as open and outside Core. See §5 for what this document does with each. This revision was signed by the architect at AS-02 with the corrections of A-198 applied (`ZK-ABI-SIGNOFF.md`) [A-198.5].

---

## 1. A-146 — Fixture requirements of the format-2 rows

**1.0 Ruling.** [A-146.0] Astra's measurement is accepted and the batch-14 review is corrected (`ZK-REVIEW-ERRATA.md`): the measured captures carry **no** `budget`/`budgetUsage` record and **no** signed `REQUEST_REFUSED`; their caps are authority caps (rc.1 `authorityUsage`), not Core §9 budgets. The review's statements for `full100-budget` and `headroom-exhaustion-both` therefore describe fixtures that do not yet exist, and its "307-event, meaning unchanged" claim for full100 cannot hold together with those statements. The proposed deltas are approved as fixture requirements of the format-2 rows, with the amendments of 1.1–1.5. The 307 and 50 figures are withdrawn as format-2 censuses; they stand only as the censuses of the historical captures.

**1.1 `full100-budget` (BUDGET / CAPTURED_HISTORY).** [A-146.1] Fixture: bootstrap; at least one `BUDGET_DECLARED` (type 32) whose selectors match the 100 admissions, declared before the first admission; the preserved 100 × (declare, admit, consume) workload; at least one session-signed `REQUEST_REFUSED {refusalSource: BUDGET}` (type 38) that replay re-derives (Core §10.1, `REFUSAL_NOT_REPRODUCED` otherwise). The authority cap of the historical capture MAY stay, strictly looser than the budget, so that the stop rule exercised is Core §9 (Core §8.1 step 2 is reached only on ALLOW). Statement: every admission is charged once per Core §9.6 at its `evaluationTime` to every matching budget; `budgetUsage` at `to` equals the sum of charged amounts and counts; each BUDGET refusal re-derives; the authority `usage` counters (Core §7.2) and the capped `authorityUsage` are bound separately, as in count-both. The `BUDGET_SET_TOO_LARGE` (17th matching budget) and the 256-budget cap are removed from this row's statement; they are two separate adversarial controls (`control/budget-set-17`, `control/budget-cap-257`: the 17th match is `DENY BUDGET_SET_TOO_LARGE`, the 257th declaration is `TRANSITION_INVALID`), never part of the 100-admission chain.

**1.2 `headroom-exhaustion-both` (BOTH / CAPTURED_HEADROOM_EXHAUSTION).** [A-146.2] Fixture: one `BUDGET_DECLARED` with `amountCap` such that one amount-3 admission leaves `remaining < 3`; the amount-3 declare/admit; a second amount-3 declare; a signed `REQUEST_REFUSED {BUDGET, code: BUDGET_AMOUNT_EXCEEDED, budgetId, evaluationTime = timestamp, expectedHistoryHead = head before}`; no second admission, charge or dispatch. Any retained authority cap MUST be strictly looser than the budget, else Core §8.1 yields a CORE refusal and the row proves authority exhaustion, not Core §9.7 headroom. Statement: `budgetUsage` gains exactly one charge; the refusal re-derives; `headroom(state@to, budgetId, at = refusal.evaluationTime).remainingAmount < 3`; the second decision link stays `NOT_EVALUATED_NATIVE`; dispatch absence stays a custody claim. The design §5 clause "retain the 10-event shape or report a delta" is satisfied by reporting the delta in `shapeReviewDigest`.

**1.3 `handover-both` / `handover-state` (CAPTURED_ENGINE).** [A-146.3] Fixture: a role budget (`subjects.roleIds = [role]`) declared before the handover; at least one predecessor admission and one successor admission charged to it; and, for the predecessor's sessions, fence or expiry evidence that is a state fact at `to`: either a `CONTROL_TRANSFERRED` (type 9) of the predecessor after the handover (`session.controlEpoch ≠ agent.controlEpoch`), or sessions whose `expiresAt ≤ e_to.timestamp`. A refused event cannot appear in an accepted history, so "fenced or expired" is provable only from the records at `to`; the review's phrasing is corrected accordingly. Statement: predecessor tenure `ENDED`, successor `CURRENT`, `role.currentTenureId` the successor's; duty/obligation assignee records; every predecessor session fenced or expired at `to`; for BOTH, the successor's admission charged to the inherited budget (Core §9.2 `tenure.status = CURRENT`), `budgetUsage` at `to` summing both tenures. The STATE row carries the same history, derives BOTH from the authenticated session and discloses no budget content (unchanged). Role-budget inheritance and the fence/expiry evidence are format-2 deltas recorded in `shapeReviewDigest` (design C10 stands).

**1.4 `threeperiod-both`.** [A-146.4] Unchanged from design C11: the Q `endCarry` is cumulative-usage carry; Core §9.5 rollover is proved only by a separate optional fixture that declares a `FIXED_WINDOW` `carryUnused` budget. The two are never merged into one row.

**1.5 Censuses and signing.** [A-146.5] Every affected history is re-signed with RAM-only test keys and replayed; unchanged cases (count-both, cumulative-both, revocation-both) are compared with the pinned build1/g25 results; new G6.5 cases (A-134 capture failure, A-135 candidate-local overflow, A-136 precedence) are disclosed explicitly. Each row publishes its **measured** event census and `shapeReviewDigest`; a census stated in any review, including this one, is not evidence. The base this applies to is ABI-v1's enrollment rule that a row lacking a measured census is not yet enrollable (ABI-v1 line 81; ABI-v2 line 96).

**1.6 Export-view disclosure fields (profile rule).** [A-148.2] [A-198.4] The normative content of the Core §15 export verifier is Core's (its Verification paragraph, the A-65.1 shape refusals and the Core §17 comparison list); `eventCount`, `checkpointIds` and `checkpoints` are disclosure fields there. As a rule of this profile (design C4), the guest MAY refuse an export view whose disclosure field disagrees with the applied range (`eventCount ≠ to − from + 1`, or `checkpointIds`/`checkpoints` unequal to the `STATE_CHECKPOINT` events within `from … to`), reported as a profile refusal and never as a Core verdict; no verifier outside this profile is obliged to.

---

## 2. A-147 as amended by A-152 — the numeric-complement Q census

**2.0 Ruling.** [A-147.0] Approved. The ordinary StableQ census does not cover the separately typed numeric headroom proofs (`AMOUNT_SUFFICIENT` / `AMOUNT_INSUFFICIENT`); treating it as the complete external P+Q join omits cryptographic checks. ABI-v2 gains an exact ordered `numericQ` census. The revision literals are `irontrellis-zk-f2-question/2`, `irontrellis-zk-f2-witness/2` and `irontrellis-zk-f2-pq-join/2`; ABI-v1 artefacts stay diagnostics [A-147 code and stage] [A-152.4].

**2.1 Question.** [A-147.1] Question gains `numericQSetDigest: H|null`: `null` iff `numericWitnessSetDigest` is `null` (numeric not configured), else `T("irontrellis-zk-f2/numeric-q-set/1", numericQ)` over the exact ordered array. An empty array has its tagged digest; empty is allowed only when the independently derived relation selects no numeric obligation. (ABI-v2's Question `/2` already carries the field and nulls it for the three CAPTURED_HISTORY rows; that text agrees with this ruling.)

**2.2 Witness.** [A-147.1] Witness gains `numericQ: [NumericQ]`, ordered by `(obligationId, groupId)` UTF-8, unique.

```
NumericQ = {obligationId: I, groupId: I,
            claim: "AMOUNT_SUFFICIENT"|"AMOUNT_INSUFFICIENT"|"COUNT",
            statementDigest: H, proofDigest: H|null, backend: H|null,
            parameters: H|null, verifierClosure: H|null,
            historicalAudience: I, historicalNonce: I}
NumericQDigest = T("irontrellis-zk-f2/numeric-q/1", item)
```

Missing, duplicate, extra, reordered or wrong-claim entries refuse the whole join; a failing numeric proof refuses, never degrades. The `numeric-q/1` and `numeric-q-set/1` tag domains are unchanged by A-152 [A-152.4].

ABI-v2's census section (line 241) also writes "substituted-context" among the refusal grounds: that word names the refusal A-147.4 and A-147.2 give, not a sixth ground. An item whose `historicalAudience`, `historicalNonce` or captured context differs from the signed evidence yields a reconstructed statement whose digest is not the item's `statementDigest`, or a proof that fails under it; either refuses the whole join. The A-147 control "rewritten historical nonce" is its instance [A-147.4] [A-198.1].

**2.3 Backend and verifier closure.** [A-147.1] `backend`/`verifierClosure` equal the enrolled `componentClosures.numericBackend`/`numericContract`; the ABI-v1 qBackend rule (line 239) applies verbatim, read with those two closures in place of `qBackend`/`qContract`: the numeric backend is a source/binary/config closure, including suite and parameter identities; it is not a proof-supplied path; the local verifier resolves only enrolled installation paths. A proof-supplied path never resolves.

**`parameters`.** [A-198.2] For an amount claim, `parameters: H` is the identity of the proof-system parameter set the numeric backend reports for that proof (ABI-v1 line 207: the backend "suite/parameters" that must match exactly, as the pinned numeric verifier reports them). It MUST be one of the suite and parameter identities the enrolled `componentClosures.numericBackend` closure contains (line 239 as applied above); an identity not in the closure refuses; it is an equality against the enrolled set, never a proof-supplied path. For COUNT it is `null` (2.4). It does not appear in the receipt (2.7): the receipt's `backend` closure fixes the admissible set and `verified: true` states that the equality was checked.

**`statementDigest`, `proofDigest` and `proofSHA256`.** [A-198.3] `proofDigest` (Witness) and `proofSHA256` (receipt) are one value under two field names: SHAFile of the exact numeric proof bytes the numeric bridge retains for that obligation and group, outer-H normalized; unequal values refuse the join. `statementDigest` is the pinned numeric component's own statement digest of the reconstructed statement, the value the proof and the backend response carry after outer-H normalization (the pattern of ABI-v1's `fullStatementDigest`, line 207), never a generic C2 re-hash of a rewritten object (ABI-v1: no generic C2 replacement is permitted). *Status: Astra names the exact source file and function of that digest in the next ABI-v2 edition, and this paragraph gains the citation then (A-198.3).*

**2.4 COUNT in the Witness.** [A-147.3] A COUNT obligation has no range proof: its item carries `claim: "COUNT"` and explicit `proofDigest: null`, `backend: null`, `parameters: null`, `verifierClosure: null`; the verifier checks the count by exact equality against the authenticated dossier rows. A missing key is never equivalent to `null`; a COUNT item with a non-null proof refuses.

**2.5 Historical audience and nonce.** [A-147.4] Numeric selection audience/nonce are signed cadence/receipt fields. They are preserved as written, bound in the item (`historicalAudience`, `historicalNonce`) and used in the reconstructed statement; the fresh outer `Question.audience`/`nonce` bind the P proof and the fresh Q contexts only. The receipt labels every numeric proof `HISTORICAL`; no historical proof is claimed to be generated for the new Question. (ABI-v2 "Exact external Q join": fresh context audience equals `Question.audience` and challenge equals `Question.nonce`; that rule is for the fresh Q contexts and is untouched.)

**2.6 Verifier scope.** [A-147.2] The external verifier reconstructs each numeric statement from the bound obligation/group/claim and the captured context and verifies **every** numeric proof as it verifies every ordinary Q proof. The guest result keeps `quantitativeQVerified: false` (the guest verifies no Q cryptography, design §6); the receipt, not the guest, states numeric verification.

**2.7 The external receipt.** [A-147.1 as amended by A-152.1, A-152.2, A-152.3, A-152.4]

*Revision.* [A-152.4] The receipt that carries `numericQ` is `irontrellis-zk-f2-pq-join/2`; A-147.1's "`irontrellis-zk-f2-pq-join/1`" is corrected to `/2`. `/1` receipts remain diagnostics for ordinary-only rows and never carry `numericQ`.

*Placement.* [A-152.3] `numericQ` and `completeNumericQSet` are top-level receipt fields beside `q` and `completeQSet`. Both are `null` iff `Question.numericQSetDigest` is `null` (numeric not configured); otherwise `numericQ` is the exact ordered census (empty allowed only as 2.1 states) and `completeNumericQSet: true`, recomputed by the verifier, never accepted from the producer. This refines A-147.1's "gains … `completeNumericQSet: true`" for the unconfigured case.

*Item.* [A-152.1, replacing the item of A-147.1's receipt sentence]

```
numericQ: [{obligationId: I, groupId: I,
            claim: "AMOUNT_SUFFICIENT"|"AMOUNT_INSUFFICIENT"|"COUNT",
            statementDigest: H, proofSHA256: H|null, backend: H|null,
            verifierClosure: H|null, provenance: "HISTORICAL", verified: true}]
```

`provenance` is the A-147.4 label: a required string field of **every** item, COUNT included, whose only admitted literal is `"HISTORICAL"`; any other value, or a missing key, refuses the join. No `"FRESH"` literal exists (no numeric proof is generated for the new Question). The historical audience and nonce are not repeated in the receipt; they are bound by `statementDigest` through the reconstructed statement and are present in the Witness item.

*COUNT in the receipt.* [A-152.2] A COUNT item carries explicit `proofSHA256: null`, `backend: null`, `verifierClosure: null` (2.4 applied to the receipt; a missing key is never `null`; a COUNT item with a non-null value in any of the three refuses). Its `verified: true` states that the exact-equality count check against the authenticated dossier rows passed; its `provenance` is `"HISTORICAL"` like every other item. `parameters` is a Witness field and does not appear in the receipt.

*Recomputation.* [A-147.1] `numericQ` and `completeNumericQSet` are recomputed by the verifier, never accepted from the producer; missing, duplicate, extra, reordered or wrong-claim entries refuse the whole join; a failing numeric proof refuses, never degrades. The ordinary rows of the receipt (`p`, `q`, `completeQSet`, the three scope flags) are ABI-v2's and are unchanged.

**2.8 C6 mapping.** [A-147.5] Confirmed: each ordinary `StableQ.position = Question.to.position` and its `stateRoot`, `projectionHead`, `coreHeadDigest` are the guest-derived values at `to`; any other value refuses. Historical interval closing heads are checked at their own replay prefixes `p_i ≤ to` against `head(p_i)` from the guest's replay; an interval's own signed head is evidence inside the dossier and is never relabelled as the terminal head. Configured-row P+Q verification stays **open** until A-147.1 is implemented; ordinary-Q history rows proceed independently (§5).

---

## 3. A-153 — `componentBoundsManifest` /2 and the adopted locator rules

**3.0 Ruling.** [A-153.0] Option 1 of `BOUNDS-LOCATOR-QUESTION.md` is adopted. A declared-constant name cannot identify an inline guard or a generated JSON field, and renaming unchanged literals for the sake of a name re-fingerprints every component for zero semantic change; the identity ABI-v2 wants is "which exact expression bounds what at which source hash", which a locator states and a name only points at. Option 2 is declined. The inventory's 262 comparison sites, 115 validator calls, 45 constants and 243 table fields are **candidates**; nothing here enrols any of them.

**3.1 The manifest (replaces ABI-v1 line 235; ABI-v2 line 274).** [A-153.1]

```
componentBoundsManifest =
  T("irontrellis-zk-f2/component-bounds/2",
    {schema: "irontrellis-zk-f2-component-bounds/2", censusReviewDigest: H,
     components: [{name: I, sourceClosure: H,
                   bounds: [{id: I, locator: Locator, value: U53, unit: Unit, comparison: Comparison}]}]})
```

`Locator`, `S`, byte-range, symbol, pointer, uniqueness, sort and refusal rules are exactly as proposed (3.2), with the amendments (i)–(vi) marked there. Omission of any exercised bound of the selected profile refuses enrollment, as before. The Enrollment slot `bounds.componentBoundsManifest: H` (ABI-v2 "Enrollment") is the slot this value fills; no ruling changes the slot's name or the enrollment schema literal.

**3.2 Locator rules, exactly as proposed, with A-153.1's amendments.** The paragraphs below are the proposal's words; each `[A-153.1 (n) …]` note is the ruling's amendment and governs the sentence it follows.

`Locator` is one of these closed objects:

```
{kind:"RUST_CONST",path:I,symbol:S,sourceSHA256:H}
{kind:"RUST_LITERAL",path:I,byteStart:U53,byteEnd:U53,sourceSHA256:H}
{kind:"JSON_FIELD",path:I,pointer:S,sourceSHA256:H}
```

[A-153.1 (i): a bound whose value is a declared constant is located by `RUST_CONST` at its definition, never by `RUST_LITERAL` at a use site; `RUST_LITERAL` is for an expression that declares no constant.]

`S` is a C2 ProtocolString, at most 4096 UTF-8 bytes. `path` is a unique file entry in that component's SourceManifest. [A-153.1 (ii): every `path`, including a generated table and its generator source, is an entry of the component's SourceManifest.] The source SHA must equal that entry. Byte ranges are half-open UTF-8 byte offsets in the exact source file, select one complete unsigned integer/arithmetic limit expression, and must evaluate to `value` under its declared Rust type without truncation or overflow. Constant `symbol` is fully qualified and unique in the pinned file; repeated local constants require the enclosing function's path. JSON pointers use RFC6901 and resolve to an actual integer field, never a string or absent key. A name or error-message substring is not a locator. Duplicate locators or duplicate IDs refuse.

Components sort by UTF-8 name; bound IDs sort by UTF-8 ID. IDs are inventory identifiers, not claimed validator constants. A verifier must validate exact path/hash/locator/value and the reviewed complete exercised census before accepting the digest. Source position is stable only under the pinned source SHA. No witness-selected location can substitute for the enrolled manifest.

[A-153.1 (iii): `censusReviewDigest` is SHAFile of the accepted exercised-bound census review, the artefact that classifies every lexical candidate as exercised resource bound, encoding/shape, semantic domain or unreachable; an unaccepted draft does not satisfy it. This field is the ruling's addition to the proposed wire.]

Proposed `Unit` closed literals: `BYTES`, `UTF8_BYTES`, `UTF16_CODE_UNITS`, `EVENTS`, `RECORDS`, `NODES`, `DEPTH`, `MEMBERS`, `ITEMS`, `PROOF_CHUNKS`, `RANGES`. Proposed `Comparison`: `LE`, `LT`, `GE`, `GT`. [A-153.1 (vi): `Unit` and `Comparison` literals as proposed, closed; an unknown literal refuses.] Resource minima are included with their real comparison; fixed digest widths, projection offsets, cryptographic field moduli, Amount maxima, and exact finite-workload counts remain in their existing schema/semantic/workload commitments, not fabricated U53 resource limits. [A-153.1 (iv): `==`/`!=` sites and fixed widths are never bounds here (they stay in the schema and workload commitments, as proposed); minima enter with `GE`/`GT`.] Host watchdog/VM memory limits remain in their configuration bundles unless the architect explicitly requires them here. [A-153.1 (v) replaces the conditional clause: host watchdog and VM memory limits stay in `program.vmConfiguration` and the configuration bundles; the architect does not require them in this manifest.]

**3.3 Scope.** [A-153.2] This representation certifies no classification, makes no present pinset enrollable, changes no guard, and turns no native or VM run into a proof. A fresh build and enrollment remain required for any amended outer verifier (§5).

---

## 4. Base passages replaced or amended

| # | Base file, heading, line | Base text (as it stands) | Replaced or amended by | Ruling |
|---|---|---|---|---|
| 1 | ABI-v1 "Remaining identity registry and equality constraints", line 235 (ABI-v2 line 274) | `componentBoundsManifest = T under irontrellis-zk-f2/component-bounds/1 over {schema:"irontrellis-zk-f2-component-bounds/1", components:[{name, sourceClosure, bounds:[{name, value}]}]}`; sort by name; names match exact validator constants; omissions refuse enrollment | **Replaced** by §3.1–3.2: tag `irontrellis-zk-f2/component-bounds/2`, schema `irontrellis-zk-f2-component-bounds/2`, `censusReviewDigest`, bounds `{id, locator, value, unit, comparison}`, sort by UTF-8 name and UTF-8 ID; omission of any exercised bound refuses, as before | [A-153.1] |
| 2 | ABI-v1 same section, line 239 (ABI-v2 line 278) | `StableQ.backend equals Enrollment.componentClosures.qBackend; contractClosure equals …qContract. qBackend is a source/binary/config closure …; not a proof-supplied path. The local verifier resolves only enrolled installation paths.` | **Unchanged** for StableQ; **applied verbatim** to the numeric item's `backend`/`verifierClosure` against `componentClosures.numericBackend`/`numericContract` (§2.3) | [A-147.1] |
| 3 | ABI-v1 "Exact external Q join", receipt layout, line 216: `schema:"irontrellis-zk-f2-pq-join/1"` | `/1` receipt with `p`, `q`, `completeQSet`, scope flags | `/1` stays a diagnostic for ordinary-only rows and never carries `numericQ`; the receipt that carries `numericQ` is `irontrellis-zk-f2-pq-join/2` (§2.7). A-147.1's own "`pq-join/1`" wording is the erratum corrected | [A-152.4] |
| 4 | ABI-v2 front status, line 3: "full external verification, its exact historical-label receipt shape, and bounded-manifest completion remain open gates" | three open gates | The receipt shape gate is **closed** by §2.7; full external verification stays open (A-147.5, §5); bounded-manifest completion stays open (A-153.2, §5) | [A-152.1] [A-147.5] [A-153.2] |
| 5 | ABI-v2 "Numeric Q census (A-147)", line 241: "Missing, duplicate, extra, reordered, wrong-claim or substituted-context entries refuse." | adds "substituted-context" | **Unchanged**: "substituted-context" names the A-147.4 refusal (§2.2), not a sixth ground | [A-147.1] [A-147.4] [A-198.1] |
| 6 | ABI-v2 same section, line 243: "A-147 requires the external receipt to label each numeric proof HISTORICAL; the exact closed receipt location for that label is awaiting clarification." | location open | **Replaced**: the label is the required item field `provenance: "HISTORICAL"` of every receipt item, COUNT included (§2.7 *Item*) | [A-147.1 as amended by A-152.1] |
| 7 | ABI-v2 same section, line 243: "This is an external-receipt wire gate, not permission to skip a verification." | gate sentence | Gate **closed** by A-152.1; the second clause stands (A-147.2: every numeric proof is verified) | [A-152.1] [A-147.2] |
| 8 | ABI-v2 same section, line 249: "A-147's footer selects revision 2. Its earlier receipt paragraph still names /1 and its listed closed item has no HISTORICAL field; the exact field and revision confirmation have been requested. The partial layout below is a review reference, not a sealed verifier schema." | request paragraph | **Replaced**: revision confirmed `/2`; field confirmed `provenance`; the layout of §2.7 is the ruled receipt shape | [A-152.1] [A-152.4] |
| 9 | ABI-v2 same section, receipt layout line 258: `numericQ:[{… claim:I, …}]` | `claim` typed `I` | **Amended**: `claim` is the closed literal set `"AMOUNT_SUFFICIENT"\|"AMOUNT_INSUFFICIENT"\|"COUNT"` | [A-147.1 as amended by A-152.1] |
| 10 | ABI-v2 same layout, lines 258–259: item `{obligationId, groupId, claim, statementDigest, proofSHA256, backend, verifierClosure, verified:true}` | no `provenance` key | **Amended**: `provenance: "HISTORICAL"` is a required key of every item; a missing key refuses | [A-147.1 as amended by A-152.1] |
| 11 | ABI-v2 same layout, line 258 and line 260: `numericQ:[…]`, `completeNumericQSet:true` unconditional | always an array and `true` | **Amended**: both are `null` iff `Question.numericQSetDigest` is `null`; otherwise the exact ordered census and `true`, recomputed by the verifier | [A-147.1 as amended by A-152.3] |
| 12 | ABI-v2 same section, line 243: "COUNT carries explicit null proofDigest/backend/parameters/verifierClosure" | Witness nulls | **Unchanged** for the Witness; **extended** to the receipt as `proofSHA256: null`, `backend: null`, `verifierClosure: null`, with `parameters` absent from the receipt; `verified: true` states the exact-equality count check passed | [A-147.3] [A-152.2] |
| 13 | ABI-v2 same section, line 243: "Historical audience and nonce remain exactly those in the signed evidence; the fresh outer Question never rewrites or relabels them." | Witness binding | **Unchanged**; **added**: they are not repeated in the receipt and are bound by `statementDigest` through the reconstructed statement | [A-147.4] [A-152.1] |
| 14 | ABI-v2 same section, line 245: "Configured-row P+Q qualification remains open until all these checks pass; ordinary-Q history-only rows can proceed independently." | open gate | **Unchanged**; the ruled form is A-147.5's (§5) | [A-147.5] |
| 15 | ABI-v1 "Enrollment", line 81 (ABI-v2 line 96): "No unknown count becomes zero: a row lacking a measured census is not yet enrollable"; ABI-v1 line 234: `workload.shapeReviewDigest` is SHAFile of the accepted review artifact | census and review rules | **Unchanged**; the per-row fixture requirements and the withdrawal of 307 and 50 as format-2 censuses are §1 | [A-146.0] [A-146.5] |

---

## 5. Status: what stays open, and what this document does not do

- **Configured-row P+Q verification is open.** [A-147.5] It stays open until A-147.1 is implemented; ordinary-Q history rows proceed independently. Core A-186.5 records A-147.5 as an open hold, not ruled. A-152 settled the receipt wire; it did not implement or credit any verification, and no complete external numeric P+Q claim exists.
- **A-153 authorizes a representation only.** [A-153.2] It certifies no classification, makes no present pinset enrollable, changes no guard, and turns no native or VM run into a proof. A fresh build and enrollment remain required for any amended outer verifier. The accepted exercised-bound census review that `censusReviewDigest` names does not yet exist as an accepted artefact (ABI-v2 status line: bounded-manifest completion is an open gate).
- **A-146 enrolls nothing.** [A-146.5] The format-2 censuses are published measured; until a row's census is measured and its `shapeReviewDigest` accepted, the row is not enrollable (ABI-v2 "Enrollment").
- **No proof or policy authority.** Nothing in this document, and no LLM output, is a proof; every numeric and ordinary proof is verified by the external verifier, never by the guest (§2.6).
- **PHL.** Core Appendix E E-21 records the PHL ZK relation as open and outside Core and names this document as where such a relation would be specified. No ruling in scope specifies it; this document carries no PHL relation. The enrolled profile `native-f2-ed25519-policy-free/2` excludes PHL attestation (ABI-v2 "Source closure and fixed profile"; design C13).
- **A-148.2's profile rule** (design C4) is carried as §1.6 [A-198.4]; Core §15's pointer stands and A-148 stays a Core ruling.
- **The former gaps of §2.2 and §2.3** are ruled: "substituted-context" names the A-147.4 refusal [A-198.1]; `parameters` binds the backend's reported parameter-set identity against the enrolled closure [A-198.2]; `proofDigest` and `proofSHA256` are one value, and `statementDigest` is the pinned numeric component's own statement digest [A-198.3]. *Status: the source citation for that digest is Astra's, due in the next ABI-v2 edition (A-198.3).* No `[GAP]` marker remains.

---

## 6. Vector and control impact

**A-146.** [A-146 code and stage] Code: none in Core; ZK fixture/enrollment (`shapeReviewDigest`, selection manifests). Additive: n/a (outside Core). Vector impact: none in `conformance/v2`; ZK fixtures re-measured; two new ZK controls, `control/budget-set-17` and `control/budget-cap-257` (§1.1).

**A-147.** [A-147 code and stage] Code: none in Core; ABI-v2 (new revision, `irontrellis-zk-f2-question/2`, `…-witness/2`, `…-pq-join/2`). Additive: n/a (ABI revision; ABI-v1 artefacts stay diagnostics). Vector impact: none in Core; ABI-v2 controls: missing/duplicate/extra/reordered/wrong-claim numeric item, COUNT with a proof, failing numeric proof, rewritten historical nonce.

**A-152.** [A-152 code and stage] Code: none in Core; ABI-v2 external receipt. Additive: n/a (ABI revision, unsealed). Vector impact: none in Core; ABI-v2 controls gain `numeric item without provenance`, `numeric item provenance not HISTORICAL`, `COUNT item with non-null backend`, `numericQ present with null numericQSetDigest`.

**A-153.** [A-153 code and stage] Code: none in Core; ABI-v2 enrollment. Additive: n/a (ABI-v2, unsealed). Vector impact: none in Core; ABI-v2 controls gain `locator hash mismatch`, `literal range not a complete expression`, `JSON pointer to a string`, `duplicate bound id`, `exercised bound omitted`.

**Core.** No frozen vector, root, row or Core code changes under any ruling of this document; Core P.8's frozen 86 and nine pinned roots are untouched [A-146 … A-153 code and stage] [Core P.8].
