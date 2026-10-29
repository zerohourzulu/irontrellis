# ABI-v2 — restricted Ed25519 format-2 experimental revision

Status: implementation and test work in progress; not enrolled, not production qualified, and no new VM proof claimed. This document supersedes ABI-v1 only for newly built revision2 programs. Old captures, executable commitments and receipts remain under their original identities. The compiled workload registry stays fail-closed until fresh signed captures and explicit shape reviews supply measured censuses. A previously compiled one-row revocation diagnostic predates the new signed CORE refusal requirement and is not G6.7 qualification. A-148.1 confirms C7’s non-null Amount rule. A-147’s numeric census is approved and being implemented; full external verification, its exact historical-label receipt shape, and bounded-manifest completion remain open gates.

The inherited detailed ABI follows, with the outer namespace and explicit changes below. Inner custody, Q and component codecs retain their separately versioned identities.

# Exact experimental ABI proposal — format2 ZK family v1

This appendix makes the M1 design's **new** guest boundary precise. It is a proposed ABI, not a built or proved guest. Changes require a new ABI revision and newly enrolled executable. `binding.py` uses a separate, narrower native-test ABI and does not implement this guest ABI.

All objects below are closed: every displayed key is required, no other key is allowed. A displayed `null` is present JSON null. Lists retain order. Hash `H` is `0x` plus exactly 64 lowercase hex digits. `U53` is an integer in 0..9007199254740991, never Boolean. `I` is §3.3 Identifier. `S` is well-formed UTF-8 string. Dates/times in this ABI are **milliseconds** unless explicitly named `observedTimeSeconds`. Amounts use §3.3 strings. Enum values are literal strings. These rules, the object shapes and constraints below together define the wire grammar.

## Hash functions and codecs

`C2(x)` is r4 §3.1 canonical bytes, with UTF-8 key ordering and every C0 as lowercase six-byte `\u00xx`. It is used for the new outer ABI, format2 Core events/records/challenges, and newly defined digests below.

The **whole Witness is transport, not a C2-hashed record**. Its JSON is strictly parsed under the UTF-8/duplicate-key/integer/surrogate rules; raw envelope length is capped before parsing. `captureWire` is the sole top-level raw capture string; imported nested strings retain their explicitly pinned component bounds. The captureWire slot may occupy up to the remaining16776192-byte envelope capacity (including its JSON escaping overhead). Do not apply the per-ProtocolString4096-byte bound to this raw transport slot. Hash it with R over its decoded exact UTF-8 content. Other imported large document slots are structured objects/arrays with their pinned component-specific bounds; no canonicalization of the entire Witness container is required. Enrollment, Question, Result and each T operand use C2; B operands use their pinned component codec and must fit the applicable bounds; individual C2 strings/keys are ≤4096 UTF-8 bytes. No general relaxation of format2 event/state string limits follows from the transport exception.

`T(tag,x) = H(SHA256(UTF8(tag) || 00 || C2(x)))`.

`R(tag,s) = H(SHA256(UTF8(tag) || 00 || UTF8(s)))`, hashing the exact raw string bytes, **without JSON quotes or recanonicalization**. `SHAFile` is ordinary untagged SHA256 over every file byte, represented as H. Source manifests use T, not a concatenation of informal printed hashes. All tags below are literal and include no terminal newline.

For imported component bodies define `B(tag,codecID,x) = H(SHA256(UTF8(tag) || 00 || UTF8(codecID) || 00 || u64be(length(bytes)) || bytes))`, where `bytes` is exactly the canonical output of that **pinned component codec**, after its own bounded schema validation. codecID is one literal from the table below; no fallback. B does **not** impose C2's4096-string/4096-array limits on a valid legacy body. The raw envelope and component-specific bounds still apply before allocation/hashing. This is necessary for retained interval wires, replica lines, base64 custody chunks (up to49152 decoded bytes), reviewer local-record lists (up to8192 entries), and the legacy Q all-row bound (262144), not a relaxation of any format2 Core record bound.

| Slot | Codec | Escaping/order contract |
|---|---|---|
| Format2 Core + outer ABI | C2 | UTF-8 keys; all C0 `\u00xx`; §3.1 integers/strict parser |
| Existing engine capture/request/cadence signed objects | `capture-engine-json/1` | Original guest `common.rs::canonical`: UTF-8 keys, **serde_json string escaping** (short escapes where supplied by that implementation). Exact pinned code, not C2. |
| Existing custody journal signed objects | `legacy-custody-json/1` | Original custody canonical function: UTF-16 ordering and its JSON escaping; pin code and test both ordering and escaping. |
| Existing external Q contract | `legacy-q-json/1` | Original strict/context/quantitative-statement modules' UTF-16 ordering and escaping; exact module closure and backend pinned. |
| New Core store line | `irontrellis-portable-file-store/2` | Fixed four-key line order, canonical event, one LF (§4.1). |
| Retained legacy replica file | `legacy-replica-json/1` | Original fixed insertion-order JSON+LF and marker codec. Only that separately enrolled capture slot; never format2 Core input. |

No slot tries a second codec after failure. Switching an engine capture to C2 requires new signed capture schema/domain/version and recapture, not a permissive fallback. A raw capture has `R("irontrellis-zk-f2/capture-raw/1",captureWire)` as its new outer input identity. Inner capture validation retains its enrolled slot codecs. Neither `T(tag,parse(captureWire))` nor SHA256 of a rewritten JSON file is this raw identity.

Before M2 closes, test U+E000 versus U+10000 key ordering **and** strings containing U+0000, backspace, tab, newline, formfeed, carriage return, quote and backslash in each actual codec slot. Include same-semantic-value/different-byte negative tests for short versus `\u00xx` escape swaps. The historical five guards remain five; these are additional controls. The native C2 probe's escape test does not itself test the retained capture/Q/custody implementations.

## Source closure and fixed profile

`SourceManifest = {schema:"irontrellis-zk-f2-source/1", files:[{path:I,sha256:H,bytes:U53}]}`. Sort paths by UTF-8 bytes, unique relative slash paths, no dot/dotdot/absolute/link traversal. Every local module, generated source, configuration, lockfile and verifier executable used by a component belongs to its manifest. Tag: `irontrellis-zk-f2/source/1`. The **spec** manifest has the same file-entry shape and schema `irontrellis-zk-f2-spec/1`, tag `irontrellis-zk-f2/spec/1`. Referenced immutable normative texts (including HF1/spec02) are in that manifest, not omitted because another document says unchanged.

The new experimental profile is `native-f2-ed25519-policy-free/2`. It excludes owner policy, PHL attestation, reconciliation, migrated prefixes and checkpoint resume. Core owner, runtime and counterparty declarations use Ed25519 only. The exact editions list includes the subsequently supplied G6.5/G6.6/G6.7; naming a normative text does not enable excluded federation or policy branches. A genesis or owner rotation carrying ownerPolicy, additionalControlAuthorizations, humanFloor, recovery or migratedFrom refuses by field presence, including null. Any additionalControlAuthorizations on a control event, non-Ed25519 declared Core key, event outside 0..40, or explicit projection other than the required literal refuses as UNSUPPORTED_PROFILE. No G6.2 policy counting is reachable through this profile. Original build1 remains a differential baseline, not proof of G6.5 overflow fidelity.

Initial general ceilings (not demonstrated capacity): raw envelope 16776192 bytes; Core event count131072; Core canonical event/data §4.5 limits; state records1048576; per-record §3.1 limits; configured capture/cadence/numeric/receipt bounds retain their existing module limits. Entire witness must fit the raw envelope before allocation. These ceilings do not promise that every combination fits. The native probe alone is narrower (4096 events) and claims only its measured fixtures. Each named chain also has a separately pinned **exact** workload census. New format2-required event additions are a shape delta: that row cannot qualify until reviewed and accepted against its historical behavioral contract.

## Enrollment

```
{
  schema: "irontrellis-zk-f2-enrollment/2",
  abi: "irontrellis-zk-f2/2",
  profile: "native-f2-ed25519-policy-free/2",
  semantics: {
    ownerPolicy:"REFUSE", humanAttestation:"REFUSE", reconciliation:"REFUSE",
    migratedPrefix:"REFUSE", checkpointResume:"REFUSE",
    projection:"irontrellis-projection/2", signatureSchemes:["ed25519"],
    eventTypes:[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,
                21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40]
  },
  editions: {spec:"r4", addenda:["G4","G5","G6","G6.1","G6.2","G6.3",
                              "G6.4","G6.5","G6.6","G6.7"], vectors:"v2-g3+A-71"},
  relation: I, revision: 2,
  sourceClosure: H, specClosure: H, workloadManifest: H,
  componentClosures: {
    replay: H, capture: H, authorityReceipts: H, counterpartyReceipts: H,
    cadence: H, numericBridge: H, exhaustion: H, modeRelation: H,
    qContract: H, qBackend: H, numericBackend: H, numericContract: H
  },
  codecs: {
    core: "irontrellis-canonical/2-a49",
    outer: "irontrellis-canonical/2-a49",
    capture: "capture-engine-json/1",
    custody: "legacy-custody-json/1",
    q: "legacy-q-json/1",
    coreStore: "irontrellis-portable-file-store/2",
    retainedReplica: "legacy-replica-json/1"
  },
  program: {
    executableCommitment: H, vmCommitment: H, vmConfiguration: H,
    applicationVerifier: H, rootVerifier: H, staticVerifier: H, wrapVerifier: H
  },
  trust: {
    capture: H, cadence: H|null, authorityReceipts: H|null,
    counterpartyReceipts: H|null, numeric: H|null, denialSigner: H|null
  },
  bounds: {
    rawEnvelopeBytes: 16776192, coreEvents: 131072, stateRecords: 1048576,
    coreDataBytes: 1048576, recordCanonicalBytes: 16777216,
    recordDepth: 32, recordArrayMembers: 4096, recordKeys: 256,
    componentBoundsManifest: H
  },
  permitsExecution: false
}
```

`relation` is exactly one of the eight complete IDs listed in FORMAT2-BINDING-DESIGN §5. `workloadManifest` is `T("irontrellis-zk-f2/workload/2", W)` where W is `{schema:"irontrellis-zk-f2-workload/2", relation:I, historicalRow:I, nativeCoreEventCount:U53, intervalCount:U53, cadenceRecordCount:U53, decisionLinkCount:U53, numericWitnessCount:U53, authorityReceiptCount:U53, counterpartyReceiptCount:U53, coreEventSequenceDigest:H, requestSequenceDigest:H, shapeReviewDigest:H}`. No unknown count becomes zero: a row lacking a measured census is not yet enrollable. `shapeReviewDigest` identifies the explicit review of unchanged shape or a proposed format2 delta.

Component manifests also identify their exact input/output schemas and byte codecs by source file/hash. All trust hashes use `B("irontrellis-zk-f2/trust/1","capture-engine-json/1",{component:I,body:<the exact closed object accepted by that pinned component>})`. Inner Q/custody signatures retain their own codecs even when their objects appear inside that commitment. The component's own schema checker runs before this hash; an arbitrary JSON object with the same hash field is not trusted. Enrollment digest E is `T("irontrellis-zk-f2/enrollment/2", enrollment)`. Enrollment is external to the executable; actual proof commitments must match `program`.

## Question

`End = {position:U53, head:{hash:H,position:U53,canonicalTime:U53}, stateRoot:H, projectionHead:H, recordCount:U53}` with head.position=position. All endpoints are non-null for this projection-enabled profile.

```
{
  schema: "irontrellis-zk-f2-question/2", enrollmentDigest: H,
  relation: I, mode: "STATE"|"BUDGET"|"BOTH",
  predicate: "CAPTURED_ENGINE"|"CAPTURED_HISTORY"|"CAPTURED_HEADROOM_EXHAUSTION",
  domain: {protocol:"irontrellis",version:"2",deploymentId:I},
  historyId: H, genesisEventHash: H, from: End, to: End,
  observedTimeSeconds: U53, cadenceObservedTimeMs: U53|null,
  captureRawDigest: H, captureEnrollmentDigest: H, captureExpectationDigest: H,
  authorityReceiptSetDigest: H, counterpartyReceiptSetDigest: H,
  cadenceJournalDigest: H|null, pendingRequestDigest: H|null,
  numericWitnessSetDigest: H|null, numericQSetDigest: H|null,
  stableQSetDigest: H, freshQContextSetDigest: H,
  assurance: {initial:"NOT_CONFIGURED"|"CAPTURED_HISTORY_ONLY"|"NUMERIC_FULFILLED",
              obligations:[{id:I,status:I,proofBinding:"PROOF_BOUND"|"UNAVAILABLE"}]},
  audience: I, nonce: I, permitsExecution: false
}
```

Q = `T("irontrellis-zk-f2/question/2",question)`. `from.position=0`; all expected domains/ends are verifier-owned. `observedTimeSeconds=floor(cadenceObservedTimeMs/1000)` when the latter is non-null. **Core evaluation times use the explicitly captured millisecond `evaluationTime`**, not this historical seconds field. They must bind to the exact captured source tuple and its Core head. The capture/receipt/Q native modules must not silently multiply or divide Core times.

Legacy-Q-compatible outer grammar further restricts audience and relation/purpose to1..128 ASCII bytes matching `[A-Za-z0-9][A-Za-z0-9._:/-]*` over the whole string. Question.nonce and FreshQContext.challenge are exactly64 lowercase hex digits **without0x**. These are the intersections with the original Q context validator, so an otherwise valid generic Identifier such as a spaced Unicode audience or nonce `x` is not a valid question in this profile.

Capture enrollment/expectation hashes use B with codecID `capture-engine-json/1`, tags `irontrellis-zk-f2/capture-enrollment/1` and `irontrellis-zk-f2/capture-expectation/1`, over parsedCapture.enrollment and parsedCapture.expectation, **in addition to** the inner module's old-codec checks. Set digests use the same B codec under `irontrellis-zk-f2/authority-receipts/1`, `…/counterparty-receipts/1`, `…/numeric-witnesses/1` over their exact ordered witness arrays. Cadence digest uses B with that codec under `…/cadence/1` over the exact parsed cadence object; pending-request digest uses B under `…/pending-request/1` over its exact parsed request. Components validate their original closed schema and inner signatures/codec before a slot passes. Empty arrays have their actual tagged-array digest; never null. Numeric witness custody.intervalArtifacts[].wire, custody.blobRecords[].record.base64 and coreEvents[] remain exact strings under their original bounds; do not run C2 over that whole array.

Mode/presence rules:

- Count, cumulative, handover-both: BOTH/CAPTURED_ENGINE, configured trust; cadence/numeric fields non-null; pending request/context follow their exact enrolled capture, with null represented by present null and corresponding pendingRequestDigest=null. Assurance initial one of the two configured values.
- Handover-state: STATE/CAPTURED_ENGINE, configured trust, authenticatedSessionMode=BOTH and narrow mode-relationship rule; **pendingRequest and pendingContext null and pendingRequestDigest null**. Private numeric context remains required.
- Threeperiod, revocation: BOTH/CAPTURED_HISTORY; full100: BUDGET/CAPTURED_HISTORY. `cadenceObservedTimeMs`, `cadenceJournalDigest`, `pendingRequestDigest`, `numericWitnessSetDigest`, `numericQSetDigest` null; configured trust slots null; witness authority/counterparty/decision/numeric lists empty; cadence/pendingRequest/pendingContext null; assurance `{initial:"NOT_CONFIGURED",obligations:[]}`. Original retained capture can still contain its private Q context: outer empty configured lists do not remove it.
- Exhaustion: BOTH/CAPTURED_HEADROOM_EXHAUSTION, configured trust, exact exhaustion workload and final-contract guards, NUMERIC_FULFILLED initial assurance and the declared obligations. The NOT_EVALUATED_NATIVE link stays distinguished from EVALUATED_NATIVE.

## Witness and result

```
Witness = {
  schema:"irontrellis-zk-f2-witness/2", enrollment:Enrollment, question:Question,
  trustBodies:{capture:<pinned capture trust schema>,
               cadence:<pinned cadence trust schema>|null,
               authorityReceipts:<pinned authority-receipt trust schema>|null,
               counterpartyReceipts:<pinned counterparty trust schema>|null,
               numeric:<pinned numeric enrollment schema>|null,
               denialSigner:<pinned denial-signer schema>|null},
  exportView:<exact genesis-start §15 profile described in design>,
  captureWire:S,
  authorityReceipts:[<pinned authority-receipt schema>],
  counterpartyReceipts:[<pinned counterparty-receipt schema>],
  cadence:<pinned cadence schema>|null,
  decisionLinks:[<pinned decision-link schema with native format2 source tuple>],
  pendingRequest:<pinned pending-request schema>|null,
  pendingContext:<pinned pending-context schema>|null,
  numericWitnesses:[<pinned numeric-bridge schema>], numericQ:[NumericQ],
  stableQ:[StableQ], freshQContexts:[FreshQContext]
}
```

Angle-bracket component types are **versioned schema imports**, resolved to the original manifest-pinned strict validators; they are not permissive JSON holes. Porting any of their inner Core fields to format2 requires a new schema revision in the component closure. M2 cannot claim closure while any such import still delegates format2 semantics to legacy c05 code. Every list's bound comes from the pinned component-bounds manifest; each slot is checked before computation. Unknown or unimplemented imported schema refuses.

For each trustBodies slot, require present null iff the corresponding Enrollment.trust slot is null; otherwise run the imported closed schema validator and require the exact B trust hash above with component equal to the slot name and body equal to that slot body. Check it against the enrolled digest before using any key/configuration. The verifier chose/enrolled those digests; accepting an arbitrary prover-created digest/body pair is forbidden. The explicit bodies supply the original cadenceTrust/counterpartyTrust/numericEnrollment/denialSigner data previously carried in the old application enrollment; no implicit global trust store is allowed. They are private witness inputs and are excluded from the review ZIP.

Result's public outer wire is fixed, including nulls:

```
{
  schema:"irontrellis-zk-f2-result/2", enrollmentDigest:H, questionDigest:H,
  components: {
    replay:H, capture:H, authorityReceipts:H, counterpartyReceipts:H,
    cadence:H, numericCorrespondence:H, modeRelationship:H,
    pendingAuthorization:H|null, expectedAssurance:H,
    stateContent:H|null, budgetContent:H|null, negativeOutcome:H|null
  },
  authenticatedSessionMode:"STATE"|"BUDGET"|"BOTH"|null,
  proofMode:"STATE"|"BUDGET"|"BOTH",
  requiredPredicateSatisfied:true,
  coreContentChecked:true, privateQContextRequired:true,
  stateSelected:boolean, budgetSelected:boolean,
  quantitativeQVerified:false, policyCompositionVerified:false,
  currentCustody:"UNAVAILABLE", permitsExecution:false
}
```

Each component digest uses `B("irontrellis-zk-f2/component/1","capture-engine-json/1",{name:<slot name>,value:<fully computed component result>})`. Preserve the original typed component result and its strict schema; native auditors can reconstruct this digest. A format2 record nested in a result was already validated/hashed as C2 by replay; its representation in a B result digest does not replace its normative record hash. Its hash is not itself proof acceptance. StateContent commits the newly derived format2 root/count and relevant typed state result, never the old root format. BudgetContent commits the full capture quantitative result, not just a chosen balance. `stateSelected=(mode!=BUDGET)` and `budgetSelected=(mode!=STATE)`; state/budget component is null iff unselected. `negativeOutcome` is non-null iff exhaustion. PendingAuthorization null iff no pending request is selected. Under A-147 the numericCorrespondence component hashes {evidence:[<derived bridge results ordered by obligation id>],numericQ:<independently derived census summary>}. The exact compiled summary schema is pinned in its component closure; no summary substitutes for actual external verification. Cadence/receipt/numeric component digests always exist, including the original explicit not-configured/empty results. `proofMode=Question.mode`. Mode-relationship validator alone derives authenticatedSessionMode; it cannot be user-selected independently.

For the three retained CAPTURED_HISTORY rows, authenticatedSessionMode is **null** and the committed modeRelationship result has the original `NOT_CONFIGURED` relationship. For configured rows it is non-null and must equal the mode derived from the authenticated session; the handover-state exception specifically derives BOTH while proofMode=STATE. A missing key is never equivalent to null.

Journal D = `T("irontrellis-zk-f2-result/2",{question:Question,result:Result})`. Result enrollmentDigest must equal E and questionDigest must equal Q. The native verifier reconstructs D from the verifier's Question and complete derived/expected Result and checks all32 bytes of actual P public output under enrolled executable and VM commitments. No producer-supplied component digest substitutes for a computation inside the guest.

## Exact external Q join

Original capture `derive_expectation` removes caller audience/purpose/challenge from Q expected context, and removes contextDigest from the quantitative statement before computing stable q-content/q-statement-content. Preserve that split explicitly; do not compare old whole-statement hashes to new hashes and call them equal.

```
StableQ = {
  id:I, ordinal:U53, position:U53, backend:H, contractClosure:H,
  stableExpectedDigest:H, stableStatementDigest:H,
  authenticatedRowsDigest:H, authenticatedRowCount:U53,
  startCheckpointDigest:H, endCheckpointDigest:H, coreHeadDigest:H, captureRawDigest:H,
  domainDigest:H, historyId:H, stateRoot:H, projectionHead:H,
  observedTimeSeconds:U53, mode:"STATE"|"BUDGET"|"BOTH", predicate:I
}
FreshQContext = {
  id:I, stableQDigest:H, audience:I, purpose:I, challenge:I,
  contextDigest:H, fullStatementDigest:H
}
```

C6: `position` is mandatory and equals Question.to.position. stateRoot, projectionHead and coreHeadDigest are independently replay-derived at that terminal position; the complete terminal endpoint must equal Question.to. A different position or any substituted commitment refuses. Historical interval closing heads remain checked against their own fully replayed prefixes and committed inside the original signed interval dossier and checkpoint digests. Those historical interval heads are not relabelled as terminal heads. The outer tuple attests inclusion of that verified interval in the final captured selection, not a claim that the interval itself closed at the final position.

`StableQDigest=T("irontrellis-zk-f2/stable-q/2",StableQ)`. Ordered `stableQ` sorts by ordinal then UTF-8 id, both unique, and is complete according to the capture relation's independently derived Q census. `stableQSetDigest=T("irontrellis-zk-f2/stable-q-set/2",stableQ)`. `freshQContexts` is in exactly the same id order and cardinality; `freshQContextSetDigest=T("irontrellis-zk-f2/fresh-q-context-set/2",freshQContexts)`. Both digests are bound by Question and therefore P. Fresh context audience equals Question.audience; challenge equals Question.nonce; purpose equals Question.relation. This is a **new stronger outer binding**, so a changed nonce/context needs a fresh P; the old ability to reuse P with another caller context is not assumed.

`authenticatedRowsDigest` is a **new outer digest**, `B("irontrellis-zk-f2/q-authenticated-rows/1","legacy-q-json/1",{rows:<the exact full ordered authenticated row array>})`; it is not the name of a historical function and retains that codec's262144-row bound subject to the enclosing input bound. Include denial/status/control rows, in signed order; row count equals that same full population, not admitted-only filtering. The inner original Q verifier independently recomputes its own contextDigest/fullStatementDigest and stable normalization, then all outer values must equal the guest-derived values. `coreHeadDigest=T("irontrellis-zk-f2/core-head/1",fullHead)` at `position = Question.to.position`; domainDigest uses T under `…/domain/1`. Capture/head/history/root/projection/time/mode/predicate must refer to the same bound selection, not merely equal arithmetic. Full original expected/statement/context objects are retained privately so every normalization/digest can be rederived.

Where an original digest API returns64 lowercase hex without `0x`, normalize **only the outer H representation** by decoding exactly32 bytes then re-encoding `0x` plus those same64 hex digits. Do not prepend `0x` to an inner signed field or hash a newly rewritten inner object. Source/domain-specific derivations for stableExpectedDigest, stableStatementDigest and start/endCheckpointDigest are listed below; no generic C2 replacement is permitted.

Exact mapping, with `L(tag,x)=SHA256(UTF8(tag+"\0") || UTF8(legacyQCanonical(x)))`, the original `contracts/strict.mjs::digest` (UTF-16 key sorting/JSON escaping), then outer-H normalization:

- `stableExpectedDigest` is the historical **qContentDigest**, despite its shorter new field name. Copy the whole closed q object `{expected,trust,dossier}`; remove **only** `expected.audience`, `expected.purpose`, `expected.challenge`. Hash with `L("continuity/private-policy-content/v1/q-content", stable_q)`. Never hash just expected or strip any trust/dossier field.
- `stableStatementDigest` is historical **qStatementContentDigest**. Derive the full statement using `contracts/quantitative-statement.mjs::deriveStatement(expected,trust,dossier)`; remove only its `contextDigest`; hash with `L("continuity/private-policy-content/v1/q-statement-content", stable_statement)`.
- `startCheckpointDigest=L("continuity/private-case/v1/checkpoint-envelope",dossier.start)`; `endCheckpointDigest` uses exactly the same domain and dossier.end. Each is the **whole signed envelope** `{keyId,payload,signature}`, as `contracts/context.mjs::hashCheckpoint` defines it. Compare both to the inner expected.startDigest/endDigest after outer normalization. This is not a payload-only hash.
- Fresh `contextDigest` is `L("continuity/private-case/v1/proof-context",{expected,inventoryRoot:root,inventoryCount:dossier.rows.length})`, with root independently derived by the pinned context verifier over the authenticated inventory.
- `fullStatementDigest` is **untagged SHA256** of `legacyQCanonical(fullDerivedStatement)`; this equals both proof.statementDigest and the backend response.statementDigest after outer normalization. Backend suite/parameters and returned endCarry must also match exactly, as the pinned verifier requires.
- `authenticatedRowsDigest` uses the new outer B definition above over **dossier.rows**, not over a filtered set or the derived statement's narrower numeric projection. Every source row maps into deriveStatement.rows including its denial/status/control case; verify the complete cardinality/order correspondence.

These derivations are the exact `native-content/relation/src/lib.rs::derive_expectation` and Q contract mapping recorded in `evidence/historical-r3-source-and-q.json`. Do not confuse either Q checkpoint digest with `numeric_bridge.rs`'s `ordinaryCheckpointDigest`, which is an **untagged SHA256 of capture-engine-canonical bytes of the whole cadence CHECKPOINT journal envelope**. That latter value remains an independently checked field inside the pinned numeric correspondence component, not a replacement for start/endCheckpointDigest.

## Numeric Q census (A-147)

```
NumericQ = {
 obligationId:I, groupId:I,
 claim:"AMOUNT_SUFFICIENT"|"AMOUNT_INSUFFICIENT"|"COUNT",
 statementDigest:H, proofDigest:H|null, backend:H|null,
 parameters:H|null, verifierClosure:H|null,
 historicalAudience:I, historicalNonce:I
}
```

The list is ordered by `(obligationId, groupId)` in UTF-8 and unique. `numericQSetDigest` is null iff `numericWitnessSetDigest` is null; otherwise it is `T("irontrellis-zk-f2/numeric-q-set/1", numericQ)`. An empty configured array has that real digest and is allowed only when the independently derived relation selects no numeric obligation. Each item has `NumericQDigest = T("irontrellis-zk-f2/numeric-q/1", item)`. Missing, duplicate, extra, reordered, wrong-claim or substituted-context entries refuse. The guest derives the selected obligations and reconstructed numeric statements from authenticated component evidence; a producer-authored list cannot define its own completeness.

For amount claims, backend and verifierClosure equal the enrolled numericBackend and numericContract; proof-supplied paths never resolve. The external verifier reconstructs the complete statement and verifies every proof under those closures and parameters. COUNT carries explicit null proofDigest/backend/parameters/verifierClosure and is checked by exact equality against authenticated dossier rows. Missing keys never mean null. Historical audience and nonce remain exactly those in the signed evidence; the fresh outer Question never rewrites or relabels them. A-147 requires the external receipt to label each numeric proof HISTORICAL; the exact closed receipt location for that label is awaiting clarification. This is an external-receipt wire gate, not permission to skip a verification.

The guest still returns `quantitativeQVerified:false`. Numeric cryptographic verification belongs to the independently recomputed external receipt. Configured-row P+Q qualification remains open until all these checks pass; ordinary-Q history-only rows can proceed independently.

External verification receipt (not itself a cryptographic proof):

A-147’s footer selects revision 2. Its earlier receipt paragraph still names /1 and its listed closed item has no HISTORICAL field; the exact field and revision confirmation have been requested. The partial layout below is a review reference, not a sealed verifier schema.

```
{
 schema:"irontrellis-zk-f2-pq-join/2", enrollmentDigest:H, questionDigest:H,
 p:{journalDigest:H,executableCommitment:H,vmCommitment:H,
    wrappedProofSHA256:H,verifierClosure:H,verified:true},
 q:[{id:I,stableQDigest:H,contextDigest:H,fullStatementDigest:H,
     proofSHA256:H,backend:H,verifierClosure:H,verified:true}],
 numericQ:[{obligationId:I,groupId:I,claim:I,statementDigest:H,
            proofSHA256:H|null,backend:H|null,verifierClosure:H|null,verified:true}],
 completeNumericQSet:true, completeQSet:true, guestQuantitativeQVerified:false,
 policyCompositionVerified:false, permitsExecution:false
}
```

Verifier recomputes every receipt field, equality join and q-list completeness from Question, derived StableQ, full Q objects and actual proofs. The q-list is exact ordered census; zero is allowed only when the independently derived relation needs no Q. It does not accept an arbitrary producer's `completeQSet` or `verified`. Every false/missing/duplicate/extra/wrong-format/context/head row refuses. All-row Q coverage does not become a claim about unrecorded outside actions.

## Remaining identity registry and equality constraints

All build-dependent **values** are pending M2, but their derivations are fixed:

- workload.coreEventSequenceDigest = `B("irontrellis-zk-f2/core-event-sequence/1","capture-engine-json/1",[EH(0),...,EH(to)])`, with each EH represented as H, exact event order and count. It commits the already C2-hashed Core events, not reserialized event bodies.
- workload.requestSequenceDigest = B under `irontrellis-zk-f2/request-sequence/1` with codec `capture-engine-json/1` over the exact ordered broker REQUEST records, selected from the authenticated broker stream in its signed sequence order. Include every request, including the denied/non-admitted request. Selection checks duplicate logicalId/sequence and original closed request schema.
- workload.shapeReviewDigest = SHAFile of the accepted review artifact's exact bytes. An unaccepted draft review does not satisfy this field.
- componentBoundsManifest = T under `irontrellis-zk-f2/component-bounds/1` over `{schema:"irontrellis-zk-f2-component-bounds/1",components:[{name:I,sourceClosure:H,bounds:[{name:I,value:U53}]}]}`. Components and their bounds sort by UTF-8 name, no duplicate; names match exact validator constants in the enrolled closure. All original exercised bounds are represented; omissions refuse enrollment.
- program.vmConfiguration = SHAFile of the exact configuration artifact consumed by the OpenVM builder. Generated init/extension sources additionally belong to sourceClosure; no equivalence-by-text-formatting claim.
- program.applicationVerifier/rootVerifier/staticVerifier/wrapVerifier are T source-closure digests of their **complete verifier bundles** using SourceManifest. Bundles include executable/configuration/parameter identity manifests; SRS/key material itself stays local, only identities are shared. Their actual verifier inputs and keys must match those manifests.
- executableCommitment and vmCommitment use the pinned OpenVM `CommitBytes` encoding, not file SHA or eight concatenated u32 values. For eight canonical BabyBear limbs d[0..7], each0≤d[i]<p=2013265921, compute N=sum(d[i]*p^i), emit N as32-byte big-endian zero-padded bytes, then H. Decoding requires N<p^8 and an exact eight-base-p-digit roundtrip. Reject noncanonical limbs/encodings; never reduce them. `to_field_le_bytes` is a different conversion and is not this ABI. Source `upstream/crates/continuations/src/commit_bytes.rs` is pinned in evidence/openvm-commitment-encoding.json. M2 must test the new encoder against that pinned API. A changed OpenVM encoding requires a new ABI revision.
- StableQ.backend equals Enrollment.componentClosures.qBackend; contractClosure equals Enrollment.componentClosures.qContract. qBackend is a source/binary/config closure, including suite and parameter identities; it is not a proof-supplied path. The local verifier resolves only enrolled installation paths.
- Receipt.p.executableCommitment/vmCommitment equal Enrollment.program and the actual verified proof. Receipt.p.verifierClosure equals Enrollment.program.wrapVerifier, whose complete bundle also binds the application/root/static checks required by that wrapped proof. Receipt.q[].backend equals its StableQ.backend; verifierClosure equals Enrollment.componentClosures.qContract **and** the verified qBackend is independently matched as above. Enrollment/question/journal/stableQ/context/statement digests all equal the previously defined E/Q/D and derived values.
- No guest executable's own bytes belong to a source manifest embedded as that executable's fixed constant. Compile from source/config first, obtain actual commitments, then form external Enrollment. Witness carries that enrollment and the proof verifier checks it against its out-of-band expected enrollment; this removes source/executable self-reference.
