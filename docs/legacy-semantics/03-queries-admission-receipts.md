# Spec 03 — Queries, Intent Admission, Receipts, Adapter Editions, Administrative Authorization, Durable Coordinators

Re-implementation specification derived from the reference TypeScript engine at
`packages/core-0.2/src` (core 0.2). Everything below was read from source and, where marked
**[verified]**, exercised with Node experiments against the reference engine. Items marked
**[unverified]** are derived from source reading alone.

Companion specs cover canonical encoding / capture (spec 01) and replay + authority evaluation
(spec 02). This spec references those primitives but does not re-specify them except where a
detail is load-bearing for the behaviour specified here.

---

## 0. Shared primitives and conventions

### 0.1 Canonical encoding and hashing

* `canonicalEncode(value)` — the `continuity-canonical/0.2` text: JSON without whitespace,
  **record keys sorted by unsigned UTF-8 byte order**, arrays in supplied order (NOT sorted),
  `undefined`-valued keys omitted, bigint encoded as `{"$continuity.bigint":"<decimal>"}`.
  **[verified]** `canonicalEncode({ b: 1, a: [2, 1], c: { z: 1, y: 2 } })` →
  `{"a":[2,1],"b":1,"c":{"y":2,"z":1}}`; `{a: undefined, b: 1n, c:"xé", d:true, e:null}` →
  `{"b":{"$continuity.bigint":"1"},"c":"xé","d":true,"e":null}`.
* `hashCanonical(value)` = `0x` + lowercase hex keccak256(UTF-8(canonicalEncode(value))).
  A `ContentHash` is always `/^0x[0-9a-f]{64}$/`.
* `hashEventHistoryPrefixes(events)[i]` = `hashCanonical(["continuity-event-history/0.2", events.slice(0, i+1)])`.
  The replay state exposes these as `state.eventHistoryHashes[i]`; `state.head` =
  `{ hash: eventHistoryHashes[last], position: last, canonicalTime: events[last].timestamp }`.
* `compareProtocolStrings(a, b)`: compare the UTF-8 byte sequences unsigned-lexicographically;
  shorter prefix sorts first. Both strings must be ≤ 4096 UTF-8 bytes (throws otherwise).
  **[verified]** `compare('a','B') = 1`, `compare('ab','a') = 1`, `compare('é','z') = 1`.
  This is the only string order used for sorting throughout this spec ("protocol order").

### 0.2 Scalar vocabularies

* **Identifier**: string, non-empty, ≤ 256 UTF-8 bytes, well-formed Unicode (no lone
  surrogates), no code points in U+0000–U+001F or U+007F.
* **U53**: JS number, `Number.isSafeInteger`, ≥ 0, not `-0`.
* **ContentHash**: `/^0x[0-9a-f]{64}$/` (lowercase only).
* **Signature65**: `/^0x[0-9a-f]{130}$/` (lowercase; `r‖s‖v`), `s` in `1..MAX_LOW_S`
  (secp256k1 low-s), recovery byte `1b` or `1c`. The administrative producer accepts
  mixed-case `/^0x[0-9a-fA-F]{130}$/` at the "attach" stage (see §I) but replay's schema then
  rejects uppercase.
* **EthereumAddress** (in events): `/^0x[0-9a-fA-F]{40}$/`; the replay state stores
  `credentialAddressKey = lowercase(credentialAddress)`.
* **PortableAuthorizationDomain**: closed record `{protocol:"continuity", version:"0.2",
  deploymentId: Identifier, chainId: /^[1-9][0-9]*$/ with value ≤ 2^256−1, verifyingContract:
  EthereumAddress}`. "Domain equality" (`domainEqual`) compares protocol, version,
  deploymentId, chainId exactly and verifyingContract case-insensitively.
* **PortableHistoryHead**: `{ hash: ContentHash, position: U53, canonicalTime: U53 }`.
  `sameHead` compares all three fields.

### 0.3 Evidence references (`PortableReplayEvidenceReference`)

A closed tagged union; `kind` is one of:

| kind | fields |
|---|---|
| `EVENT` | `eventId`, `eventType`, `position`, `historyHash` |
| `AUTHORITY` | `authorityId`, `grantEventId` |
| `RUNTIME_CREDENTIAL` | `keyId`, `sessionId`, `admissionEventId` |
| `RECEIPT_COMMITMENT` | `receiptContentHash`, `eventId`, `position` |
| `EXTERNAL` | `evidenceType`, `reference`, `attesterId` |

`queryEventReference(state, position)` = `{kind:"EVENT", eventId: state.events[position].id,
eventType: state.events[position].type, position, historyHash: state.eventHistoryHashes[position]}`.
`queryReceiptReference(record)` = `{kind:"RECEIPT_COMMITMENT", receiptContentHash:
record.receiptContentHash, eventId: record.eventId, position: record.eventPosition}`.

**Query evidence order** (`compareQueryEvidence`), used for every evidence list produced by the
query engine (§A–§E): first by kind rank `EVENT < AUTHORITY < RUNTIME_CREDENTIAL <
RECEIPT_COMMITMENT < EXTERNAL`; then lexicographically over the tuple
`EVENT:[eventId, eventType, position, historyHash]`, `AUTHORITY:[authorityId, grantEventId]`,
`RUNTIME_CREDENTIAL:[keyId, sessionId, admissionEventId]`,
`RECEIPT_COMMITMENT:[receiptContentHash, eventId, position]`,
`EXTERNAL:[evidenceType, reference, attesterId]`, where string components use protocol order
and numeric components numeric order.
**[verified]** sorting `[EXTERNAL a, RECEIPT z@1, EVENT b@5, EVENT a@9, EVENT a@2, AUTHORITY x,
RUNTIME_CREDENTIAL k]` gives `EVENT a@2, EVENT a@9, EVENT b@5, AUTHORITY x, RUNTIME_CREDENTIAL k,
RECEIPT z@1, EXTERNAL a`. Note that events are ordered by **eventId string**, not by position.

`queryEvidence(...groups)` = union of all references, deduplicated by `canonicalEncode`
identity, sorted by `compareQueryEvidence`.

**Receipt evidence order** (§G) is different: `materialize` sorts EVENT references by
`[eventId, eventType, position, historyHash]` with protocol-order strings — effectively the same
order for EVENT-only lists, but it is a separate routine and only ever produces EVENT
references.

### 0.4 Replay state fields used here

The accepted replay state (spec 02) exposes maps keyed by identifier. Field names used below:

* `events`, `eventHistoryHashes`, `head`, `genesis` (`{adapterPolicyHash, domain,
  canonicalLineageId, versions, policyVersion, rootRecognitionPolicy, globalPolicySourceId,
  timeSource, finality}`)
* `principals: id → {id, creationEventId, creationEventPosition}`
* `agents: id → {id, principalId, controllerId, currentControlEpoch, terminated}`
* `roles: id → {id, principalId, currentTenureId?, latestTenureNumber}`
* `tenures: id → {id, roleId, agentId, principalId, tenureNumber, successionRuleId?, closed, successionLock?}`
* `runtimeSessions: id → {id, agentId, controllerId, controlEpoch, credentialKeyId,
  credentialAddressKey, admissionEventId, admissionEventPosition, expiresAt?}`
* `intentDeclarations: intentId → {data: PortableTransactionIntent}` where
  `PortableTransactionIntent = {adapterProfile, intentId, nonce, actorId, action, resource, roleId,
  roleTenureId, amount?, counterpartyId?, termsCommitment?}`
* `intentAdmissions: intentId → {intentId, actorId, nonce, admissionEventId,
  admissionEventPosition, admissionHead, runtimeSessionId, credentialKeyId, controlEpoch, roleId,
  roleTenureId, adapterIdentity}`
* `intentConsumptions: intentId → {intentId, eventId, eventPosition, head, adapterId,
  idempotencyKey, submissionFingerprint, transactionReference, acknowledgment, evidenceReference}`
* `intentOutcomeStates: intentId → {latest: OutcomeRecord, terminal?: OutcomeRecord}` with
  `OutcomeRecord = {noEffect?, intentId, eventId, eventPosition, head, status, attesterId,
  evidenceReference}`, `status ∈ CONFIRMED|FAILED|DISPUTED|OUTCOME_UNKNOWN`
* `receiptCommitments: receiptContentHash → {receiptContentHash, receiptArtifactCommitment,
  intentId, issuerAgentId, runtimeSessionId, controlEpoch, roleId, roleTenureId,
  authorizationProofHash, eventId, eventPosition, head}`
* `obligations: obligationId → {record, status, performanceAssigneeId, creationEventId,
  creationEventPosition, creationHead}`
* `outcomeObservations: intentId → [{intentId, sourceAdmissionEventId, acknowledgment, actorId,
  eventId, eventPosition, observedAt}]` (append order)
* `attemptDuties: dutyId → {record, creationEventId, creationEventPosition, creationActorId,
  currentAssigneeId, assignments: [{fromAgentId, toAgentId, actorId, eventId, eventPosition, assignedAt}]}`
* `attemptDutyReviews: dutyId → [{dutyId, actorId, observationEventIds, summaryDigest, eventId,
  eventPosition, reviewedAt}]` (append order)
* `authorities: authorityId → {grant, grantEventId, grantEventPosition, revocationEventId?,
  revocationEventPosition?, revokerId?}` — **`grant` is stored exactly as it appeared in the
  AUTHORITY_GRANTED event** (constraint lists in event order).
* `recognizedRoots: rootAuthorityId → {rootAuthorityId, principalId,
  principalRecognitionEventId, rootGrantEventId}`
* `nonceReservationsByActor`, `authorityUsage`.

Map iteration order is insertion order (first acceptance order in the history). Where the spec
says "for each X in state.X" the iteration order does not affect output because outputs are
sorted afterwards, except where explicitly noted.

### 0.5 Version constants

```
PORTABLE_REPLAY_VERSION                  = "continuity-replay/0.2"
PORTABLE_AUTHORIZATION_VERSION           = "continuity-authorization/0.2"
PORTABLE_INTENT_ADMISSION_VERSION        = "continuity-intent-admission/0.2"
PORTABLE_AUTHORIZATION_PROOF_VERSION     = "continuity-authorization-proof/0.2"
PORTABLE_RUNTIME_AUTHORIZATION_VERSION   = "continuity-runtime-authorization/0.2"
PORTABLE_ROOT_RECOGNITION_POLICY         = "declared-principal-root/0.2"
PORTABLE_QUERY_VERSION                   = "continuity-query-envelope/0.2"
PORTABLE_RECEIPT_VERIFICATION_VERSION    = "continuity-receipt-verification/0.2"
PORTABLE_RECEIPT_RECORD_ADMISSION_VERSION= "continuity-receipt-record-admission/0.2"
PORTABLE_ADAPTER_IDEMPOTENCY_VERSION     = "continuity-adapter-idempotency/0.2"
PORTABLE_ADAPTER_SUBMISSION_VERSION      = "continuity-adapter-submission/0.2"
PORTABLE_ADAPTER_NO_EFFECT_VERSION       = "continuity-adapter-no-effect/0.2"
PORTABLE_ADAPTER_ACKNOWLEDGMENT_VERSION  = "continuity-adapter-acknowledgment/0.2"
LOCAL_SYNTHETIC_ENDPOINT_STATE_ACKNOWLEDGMENT_VERSION = "continuity-local-endpoint-state-ack/1"
LOCAL_DOCUMENT_RELEASE_ACKNOWLEDGMENT_VERSION        = "continuity-local-document-release-ack/1"
REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION         = "continuity-remote-service-report-ack/1"
PORTABLE_ATTEMPT_OBSERVATION_DUTY_EXTENSION          = "continuity-attempt-observation-duty/1"
PORTABLE_ATTEMPT_DUTY_REVIEW_EXTENSION               = "continuity-attempt-duty-review/1"
receipt payload schemaVersion  = "continuity-receipt/0.2"
receipt signatureScheme        = "eip191-personal-sign-keccak256"
administrative challenge version = "continuity-administrative-authorization/0.2"
receipt artifact commitment tag  = "continuity-receipt-artifact-commitment/0.2"
```

The genesis `versions` record that the query engine treats as "supported" (`VERSIONS`):

```
{ eventSchemaVersion: "continuity-event/0.2", receiptSchemaVersion: "continuity-receipt/0.2",
  queryEnvelopeVersion: "continuity-query-envelope/0.2",
  authorizationProofVersion: "continuity-authorization-proof/0.2",
  runtimeAuthorizationVersion: "continuity-runtime-authorization/0.2",
  administrativeAuthorizationVersion: "continuity-administrative-authorization/0.2",
  signatureScheme: "eip191-personal-sign-keccak256" }
```

### 0.6 EIP-191 signatures

`portableEip191Digest(hash32)` = keccak256(`"\x19Ethereum Signed Message:\n32"` ‖ bytes(hash32)).
`recoverPortableContentHashSigner(contentHash, signature)` → lowercase `0x`+40-hex address of
the secp256k1 public key recovered from `(r, s, v)` over that digest, or `undefined` if the
signature is malformed / not recoverable. Signatures are produced by signing the raw 32-byte
`hashCanonical(...)` with an EIP-191 personal-sign (viem `signMessage({message:{raw: hash}})`).

---

## A. Query envelope (`continuity-query-envelope/0.2`)

Entry points: `whyPortable(input)`, `responsiblePortable(input)`, `survivesPortable(input)`.
All three run the same coordinator (`query(input, kind)`) with `kind ∈ WHY | RESPONSIBLE |
SURVIVES`. Every call returns a frozen envelope; nothing throws for bad input **except the
RESPONSIBLE invariant bug described in §C.6**.

### A.1 Constants

* `PORTABLE_QUERY_VERSION = "continuity-query-envelope/0.2"`.
* `PORTABLE_QUERY_EXTERNAL_ASSUMPTIONS` (frozen; emitted verbatim on every envelope):

```
{ trust:        "LOCAL_REPLAY_UNDER_DECLARED_ROOTS_NOT_INDEPENDENTLY_AUTHENTICATED",
  identity:     "PROTOCOL_IDENTIFIERS_NOT_REAL_WORLD_IDENTITY",
  observation:  "SUPPLIED_HISTORY_MAY_NOT_BE_LATEST_PUBLIC_HISTORY",
  availability: "REPLAY_REQUIRES_EVENTS_AND_INTERPRETATION_RULES" }
```

### A.2 Input shapes

WHY and RESPONSIBLE (`PortableWhyInput` = `PortableResponsibleInput`), a closed record with
exactly these keys (order irrelevant):

| key | required | type |
|---|---|---|
| `operationVersion` | yes | must be the string `"continuity-query-envelope/0.2"` |
| `evaluationEvents` | yes | dense array of events |
| `observedEvents` | yes | dense array of events |
| `authorizationDomain` | yes | PortableAuthorizationDomain |
| `request` | yes | `{actorId, action, resource, claimedAt, amount?, counterpartyId?, termsCommitment?}` |
| `evaluationTime` | yes | see A.5 |
| `consequentialBinding` | optional | `{runtimeSessionId, controlEpoch, roleId, roleTenureId, credentialKeyId?, intentId?, nonce?, runtimeSignature?}` |
| `disclosure` | yes | `PortableDisclosureScope` |

SURVIVES (`PortableSurvivesInput`):

| key | required | type |
|---|---|---|
| `operationVersion` | yes | `"continuity-query-envelope/0.2"` |
| `evaluationEvents` | optional | dense array of events; defaults to `observedEvents` |
| `observedEvents` | yes | dense array of events |
| `targetAgentId` | yes | Identifier |
| `evaluationTime` | yes | see A.5 |
| `disclosure` | yes | `PortableDisclosureScope` |

`consequentialBinding` is **not** allowed on SURVIVES (→ INVALID_INPUT **[verified]**);
`evaluationEvents` is **not** optional on WHY/RESPONSIBLE.

`PortableDisclosureScope = { mode: "PUBLIC_MINIMAL", includedFields: string[], withheldFields: string[] }`.

### A.3 Capture phase (input → INVALID_INPUT / UNSUPPORTED_VERSION)

Order of checks (first failure wins):

1. Input must be a non-null, non-array object whose prototype is `Object.prototype` or `null`
   → else `INVALID_INPUT`.
2. `operationVersion` is read first (must be a string). If it is not exactly
   `"continuity-query-envelope/0.2"` → `UNSUPPORTED_VERSION` (checked **before** any other key).
3. Own keys must all be in required ∪ optional for the kind; every required key must be present
   → else `INVALID_INPUT`. A required key present with value `undefined` → `INVALID_INPUT`.
4. Members are captured in this fixed order (each caller property is read exactly once, via own
   data descriptor; accessors/proxies are refused): SURVIVES: `targetAgentId, evaluationTime,
   disclosure, evaluationEvents, observedEvents`; WHY/RESPONSIBLE: `authorizationDomain,
   request, evaluationTime, consequentialBinding, disclosure, evaluationEvents, observedEvents`.
   `evaluationEvents`/`observedEvents` must be arrays. Structural limits (record ≤ 256 fields,
   list ≤ 4096 members, depth ≤ 32, strings ≤ 4096 bytes, total ≤ 16 MiB, no cycles, no
   symbol keys, plain records only) → `INVALID_INPUT`.
5. `validateCapturedPortableQueryInput`:
   * for each event in either history that is a plain record: `event.id` must satisfy the
     Identifier *length* bound; if position 0 has `type === "DEPLOYMENT_INITIALIZED"` its `data`
     must satisfy the genesis named limits;
   * if `disclosure` is a record, each member of `includedFields`/`withheldFields` must satisfy
     the Identifier length bound;
   * `evaluationTime` must be a string, number or bigint (else INVALID_INPUT; a string or bigint
     gets past capture and later fails as `CAUSAL_TIME_INVALID` **[verified]**);
   * SURVIVES: `targetAgentId` must be an Identifier;
   * WHY/RESPONSIBLE: `authorizationDomain` must be a valid domain; `request` must be a closed
     record with required `actorId, action, resource, claimedAt` and optional `amount,
     counterpartyId, termsCommitment`; `actorId, action, resource, claimedAt, amount,
     counterpartyId` must be scalars (string/number/bigint) when present; `actorId, action,
     resource, counterpartyId` must satisfy the Identifier length bound; `consequentialBinding`
     if present must be a closed record with required `runtimeSessionId (Identifier),
     controlEpoch (U53), roleId, roleTenureId (Identifiers)` and optional `credentialKeyId,
     intentId, nonce (Identifiers), runtimeSignature (Signature65)`.
   Any failure → `INVALID_INPUT`.
6. `preflightCapturedPortableReceiptHistoryLimits([evaluation, observed])` → if it reports
   `LIMIT` → `INVALID_INPUT`. (For each history whose first event is a supported genesis, every
   core-typed event's `data` is scanned for named hard limits; a limit breach is
   INVALID_INPUT rather than a replay rejection.)

### A.4 Discovery and replay (→ STATE_NOT_AUTHORITATIVE / EVIDENCE_UNAVAILABLE)

`evaluationEvents = value.evaluationEvents ?? value.observedEvents`.

`discover(events)`: returns `undefined` if `events.length === 0`, if any event fails the base
envelope check (closed record `{id, type, timestamp, data}` with `id` Identifier, `type` a
ProtocolString, `timestamp` U53, `data` a plain record ≤ 1 MiB canonical), or if event 0 is not a
`DEPLOYMENT_INITIALIZED` with a structurally valid genesis probe. Otherwise returns
`{supported: canonicalEncode(genesis.data.versions) === canonicalEncode(VERSIONS), genesis}`.

1. Both probes are computed first. If either is `undefined` → `STATE_NOT_AUTHORITATIVE`
   (blank scope, no evidence).
2. For each supported branch, replay it (`createPortableReplayKernel` + incremental capture; a
   capture failure yields "not ACCEPTED"). If a supported branch does not replay to `ACCEPTED`
   → `STATE_NOT_AUTHORITATIVE`.
3. If either branch is unsupported (foreign `versions`) → `EVIDENCE_UNAVAILABLE`, with
   `evidence` = `scope.unavailableEvidence` = `queryEvidence(genesisRefs)` where each
   unsupported branch contributes `{kind:"EVENT", eventId: genesis.id, eventType:
   "DEPLOYMENT_INITIALIZED", position: 0, historyHash: hashCanonical(["continuity-event-history/0.2",[genesis]])}`.
   **[verified]** evidence `[('first-look:genesis', 0)]`, `epistemicStatus: "UNAVAILABLE"`.

### A.5 Identity, relationship, time and authorization

Let `evaluation`, `observed` be the two accepted replay states.

**Identity** (`PortableQueryIdentity`), all taken from the *evaluation* state:
```
domain: evaluation.genesis.domain
versions: evaluation.genesis.versions
policyVersion: evaluation.genesis.policyVersion
rootRecognitionPolicy: evaluation.genesis.rootRecognitionPolicy
recognizedRootIds: [...evaluation.recognizedRoots.keys()].sort(compareProtocolStrings)
canonicalLineageId: evaluation.genesis.canonicalLineageId
evaluationHead: evaluation.head
observedHead: observed.head
```
`compactIdentity` = identity without `recognizedRootIds`.

**headRelationship**:
* `SAME_HEAD` iff `observed.head.position === evaluation.head.position && observed.head.hash === evaluation.head.hash`;
* else `STRICT_EXTENSION` iff `observed.head.position > evaluation.head.position &&
  observed.eventHistoryHashes[evaluation.head.position] === evaluation.head.hash`;
* else `UNVERIFIED` (including the case where *evaluation* is longer than *observed* **[verified]**).

**Disclosure** (`disclosureFor`): valid iff `disclosure` is a closed record `{mode, includedFields,
withheldFields}` with `mode === "PUBLIC_MINIMAL"`, each list an array of ≤ 4096 Identifiers
**strictly increasing in protocol order** (no duplicates, no unsorted), no member of
`withheldFields` in `includedFields`, and **no member of `withheldFields` is a "core field"**.
Core fields = `PORTABLE_QUERY_ANSWER_FIELD_PATHS` ∪ `{version, kind, epistemicStatus, scope,
answer, code, evidence, externalAssumptions}` ∪ `answer.<p>` for each answer path p ∪
`scope.{domain,versions,policyVersion,rootRecognitionPolicy,recognizedRootIds,canonicalLineageId,
evaluationHead,observedHead,headRelationship,freshness,finality,disclosure,unavailableEvidence,
withheldEvidence,externalAssumptions}` ∪ `scope.domain.{protocol,version,deploymentId,chainId,
verifyingContract}` ∪ `scope.versions.<each VERSIONS key>` ∪ `scope.{evaluationHead,observedHead}.{hash,position,canonicalTime}`
∪ `{scope.externalAssumptions,externalAssumptions}.{trust,identity,observation,availability}` ∪
`scope.disclosure.{mode,includedFields,withheldFields}` ∪
`{scope.unavailableEvidence,scope.withheldEvidence,evidence}.{kind,eventId,eventType,position,historyHash,authorityId,grantEventId,keyId,sessionId,admissionEventId,receiptContentHash,evidenceType,reference,attesterId}`.
**[verified]** withholding `"answer"` → DISCLOSURE_INVALID; withholding `"zzz"` → fine.
An invalid disclosure is *remembered* but reported only at step (c) below.

**Complete scope** = `blankScope ∪ identity ∪ {disclosure: valid disclosure or
EMPTY_DISCLOSURE}` where `EMPTY_DISCLOSURE = {mode:"PUBLIC_MINIMAL", includedFields:[],
withheldFields:[]}` and `blankScope = {headRelationship:"UNVERIFIED", freshness:"UNVERIFIED",
finality:"LOCAL_ONLY", unavailableEvidence:[], withheldEvidence:[], externalAssumptions}`.

Then, in this order:

(a) **Causal time.** `time = value.evaluationTime`. Fail with `CAUSAL_TIME_INVALID` (scope =
blankScope ∪ compactIdentity, evidence = `causalEvidence()` =
`queryEvidence([ref(evaluation, evaluation.head.position), ref(observed, observed.head.position)])`)
iff `typeof time !== "number" || !Number.isSafeInteger(time) || Object.is(time,-0) ||
time < evaluation.head.canonicalTime || (kind === "SURVIVES" && relationship === "UNVERIFIED"
&& time < observed.head.canonicalTime)`.
**[verified]** float, string, bigint, `-0`, behind-head all → CAUSAL_TIME_INVALID with evidence
= the single head event when SAME_HEAD (dedup), or two events when heads differ.
Note: WHY/RESPONSIBLE only require `time ≥ evaluation.head.canonicalTime`; a SURVIVES over an
UNVERIFIED pair must also satisfy the observed head time.

(b) **Authorization** (WHY/RESPONSIBLE only): call `authorizePortable` (spec 02) with
```
{ operationVersion: "continuity-authorization/0.2", events: evaluationEvents,
  expectedHistoryHead: evaluation.head, domain: value.authorizationDomain,
  policyVersion: evaluation.genesis.policyVersion,
  rootRecognitionPolicy: evaluation.genesis.rootRecognitionPolicy,
  request: value.request, evaluationTime: time, authoritative: true,
  consequential: value.consequentialBinding !== undefined,
  binding: value.consequentialBinding (only if present) }
```
Note `policyVersion`/`rootRecognitionPolicy` come from the genesis, not from the caller, so a
`POLICY_MISMATCH` denial cannot arise from the query itself. The caller's
`authorizationDomain` is passed through, so a mismatching domain yields an ESTABLISHED answer
whose authorization is `DENY / DOMAIN_MISMATCH` **[verified]**; an unknown actor yields
`DENY / AGENT_INACTIVE`; `claimedAt: -1` yields `DENY / INVALID_REQUEST`; `amount` on a
non-quantitative grant is ignored (ALLOW) **[verified]**.
If the authorization is `INDETERMINATE`:
   * code `CAUSAL_TIME_INVALID` → fail `CAUSAL_TIME_INVALID` (early scope, causal evidence);
   * code ∈ `{INVALID_INPUT, UNSUPPORTED_VERSION, STATE_NOT_AUTHORITATIVE}` → fail with that
     code and **blank** scope;
   * other codes are handled at (d).

(c) **Disclosure** invalid → `DISCLOSURE_INVALID` with scope = blankScope ∪ compactIdentity
(no `disclosure`, no `recognizedRootIds`), evidence `[]`.

(d) **Relationship branch.**
   * `UNVERIFIED`: run `findPortableQueryConflict(evaluation, observed, selection)` (§E) with
     selection `{kind:"SURVIVES", targetAgentId, evaluationTime: time}` or
     `{kind, binding?: consequentialBinding}`. If a conflict pair is returned → fail
     `EVIDENCE_DISPUTED` (epistemicStatus `DISPUTED`), scope = complete scope (with
     `headRelationship:"UNVERIFIED", freshness:"UNVERIFIED"` forced), evidence = the pair.
     Otherwise → `HISTORY_RELATION_UNVERIFIED`, complete scope, evidence = if the first
     divergent position `p` (first index where `canonicalEncode(evaluation.events[p]) !==
     canonicalEncode(observed.events[p])`) is `< min(lengths)`, then
     `queryEvidence([ref(evaluation,p), ref(observed,p)])`, else `causalEvidence()`.
     **[verified]** fork at 13 → evidence `[('first-look:declared',13), ('fork:agent',13)]`;
     evaluation longer than observed (observed is a prefix) → evidence = the two heads
     `[(…progress-b-authority,12), (…stale-declared,25)]`.
   * else if authorization is `INDETERMINATE` (remaining codes): fail with
     `authorization.code === "EVIDENCE_DISPUTED" ? "HISTORY_RELATION_UNVERIFIED" : authorization.code`,
     complete scope, evidence `[]`; but if the code is `OUTPUT_LIMIT_EXCEEDED` return the
     output-failure envelope (scope = blankScope ∪ compactIdentity). **[unverified]** —
     `authorizePortable` cannot in practice return HISTORY_RELATION_UNVERIFIED here because the
     query passes the replayed head, so this branch is effectively reachable only for
     `OUTPUT_LIMIT_EXCEEDED`/`EVIDENCE_*`.
   * else build the answer (§B/§C/§D) → `{answer, includedFields, overflow}`.
     1. If any path in `includedFields` is not in `disclosure.includedFields` →
        `DISCLOSURE_INVALID` (early scope). This check runs **before** the overflow check.
     2. If `overflow || answer === undefined` → `OUTPUT_LIMIT_EXCEEDED` (early scope).
     3. Else result = `{version, kind, epistemicStatus:"ESTABLISHED", scope: completeScope ∪
        {headRelationship: relationship, freshness: relationship === "SAME_HEAD" ? "CURRENT" :
        "AT_EVALUATION"}, answer}`.

(e) **Final output bound.** If `identity.recognizedRootIds.length > 256` or `!fits(result)`
→ `OUTPUT_LIMIT_EXCEEDED` (early scope). `fits` = (number of evidence-shaped records anywhere in
the result — any plain record with `kind ∈ {EVENT, AUTHORITY, RUNTIME_CREDENTIAL,
RECEIPT_COMMITMENT, EXTERNAL}`, counted recursively, capped at 4097 — is ≤ 4096) and
`measureReferenceOutput(result)` does not overflow (§A.8). This applies to *every* envelope,
including failure envelopes.

### A.6 Envelope shapes

Established (`PortableEstablishedQueryEnvelope`):
```
{ version: "continuity-query-envelope/0.2", kind, epistemicStatus: "ESTABLISHED",
  scope: PortableQueryScope, answer }
```
`PortableQueryScope` = identity fields + `headRelationship ∈ SAME_HEAD|STRICT_EXTENSION`,
`freshness ∈ CURRENT|AT_EVALUATION`, `finality: "LOCAL_ONLY"`, `disclosure` (the caller's
validated disclosure, echoed), `unavailableEvidence: []`, `withheldEvidence: []`,
`externalAssumptions`. There is **no** top-level `code`, `evidence` or `externalAssumptions` on
an established envelope.

Non-established (`PortableNonEstablishedQueryEnvelope`):
```
{ version, kind, epistemicStatus, scope, code, evidence, externalAssumptions }
```
`epistemicStatus` = `"UNAVAILABLE"` iff code `EVIDENCE_UNAVAILABLE`; `"DISPUTED"` iff code
`EVIDENCE_DISPUTED`; otherwise `"INDETERMINATE"`. `scope.headRelationship` and
`scope.freshness` are always forced to `"UNVERIFIED"` on failures. Three scope "sizes" occur
**[verified]**:

| scope kind | keys | used by |
|---|---|---|
| blank | `externalAssumptions, finality, freshness, headRelationship, unavailableEvidence, withheldEvidence` | INVALID_INPUT, UNSUPPORTED_VERSION, STATE_NOT_AUTHORITATIVE, EVIDENCE_UNAVAILABLE (with `unavailableEvidence` filled) |
| early (blank ∪ compactIdentity) | blank + `canonicalLineageId, domain, evaluationHead, observedHead, policyVersion, rootRecognitionPolicy, versions` (no `recognizedRootIds`, no `disclosure`) | CAUSAL_TIME_INVALID, DISCLOSURE_INVALID, OUTPUT_LIMIT_EXCEEDED |
| complete | early + `recognizedRootIds, disclosure` | HISTORY_RELATION_UNVERIFIED, EVIDENCE_DISPUTED, post-authorization INDETERMINATE |

All envelopes are deeply frozen (`immutableProtocolValue`); assignment to a field throws
TypeError in strict mode **[verified by test]**.

### A.7 `PortableQueryFailureCode` summary

| code | epistemicStatus | when |
|---|---|---|
| `INVALID_INPUT` | INDETERMINATE | capture/shape failures (A.3), or authorization INDETERMINATE INVALID_INPUT |
| `UNSUPPORTED_VERSION` | INDETERMINATE | `operationVersion` ≠ envelope version, or authorization INDETERMINATE UNSUPPORTED_VERSION |
| `STATE_NOT_AUTHORITATIVE` | INDETERMINATE | empty history, base-envelope failure, non-genesis first event, supported branch fails replay, or authorization says so |
| `EVIDENCE_UNAVAILABLE` | UNAVAILABLE | a branch's genesis declares a `versions` set ≠ VERSIONS |
| `CAUSAL_TIME_INVALID` | INDETERMINATE | A.5(a) or authorization INDETERMINATE CAUSAL_TIME_INVALID |
| `DISCLOSURE_INVALID` | INDETERMINATE | disclosure malformed, withholds a core field, or omits a path the answer needs |
| `HISTORY_RELATION_UNVERIFIED` | INDETERMINATE | UNVERIFIED relationship without a detected conflict |
| `EVIDENCE_DISPUTED` | DISPUTED | UNVERIFIED relationship with a detected conflict (§E) |
| `OUTPUT_LIMIT_EXCEEDED` | INDETERMINATE | projection overflow, > 256 recognized roots, > 4096 evidence occurrences, or result exceeds output metrics |

### A.8 Output budget (`reference-output-budget.ts`)

`REFERENCE_OUTPUT_LIMITS = { bytes: 16_777_216, stringBytes: 4_096, listMembers: 4_096,
recordFields: 256, depth: 32, evidenceOccurrences: 4_096 }`.

`measureReferenceOutput(value)` walks the value and returns `{bytes, depth}` where `bytes` is
the exact canonical-encoding byte length and `depth` the container nesting depth (scalars 0,
a record/array = 1 + max child depth; a record with any key starting `"$continuity."` is
treated as a scalar). It throws the overflow token when cumulative bytes exceed 16 MiB, a list
has > 4096 members, a record has > 256 own keys, or `ancestorDepth + 1 > 32` for a container
(an already-measured (memoised) container re-encountered at a different depth is checked as
`ancestorDepth + cachedDepth > 32`). Aliases (the same object at multiple places) are charged
at every occurrence. Non-plain records, sparse arrays, symbol keys, accessor properties and
cycles throw a `TypeError` (not the overflow token). Keys with `undefined` values are skipped
(not charged, and do not count toward the comma separators).

`createReferenceOutputBudget(skeleton, evidenceOccurrences = 0)`: starts `used =
measure(skeleton).bytes`, `evidenceUsed = evidenceOccurrences`. `append(value, currentLength,
ancestorDepth, occurrences)`: fail if `currentLength >= 4096`; measure `value` (overflow → fail);
reserve `bytes + (currentLength === 0 ? 0 : 1)` with depth check `value.depth + ancestorDepth >
32 → fail`, `bytes > 16 MiB − used → fail`, `occurrences > 4096 − evidenceUsed → fail`. After
any failure the budget is dead (`used` set past the limit) and every later call fails.

**Projection writer** (`createPortableQueryProjectionWriter(skeleton)`), used by RESPONSIBLE and
SURVIVES:

* `fields` (the eventual `includedFields`) starts as every dotted path of a non-undefined
  member in the skeleton (arrays contribute their element paths without an index; empty arrays
  contribute only their own key). E.g. the SURVIVES skeleton contributes
  `targetAgentId, exists, lifecycleStatus, historicalIdentity, currentRoleTenures, …`.
* `evidence(field, refs)`: appends references to the top-level list `answer[field]`;
  group key = `field`; each reference observed as paths `field.<key>`; dedup within the group by
  `canonicalEncode(ref)`; each *new* reference is `budget.append(ref, list.length, 2, 1)`.
* `row(field, key, members, refs)`: identity = `canonicalEncode([field, key])`; observes paths
  `field.<member>` (recursively for nested members) and `field.evidence`; if no row with that
  identity exists, the candidate `{...members, evidence: []}` is `budget.append(candidate,
  list.length, 2, nestedEvidenceOccurrences(candidate))` and pushed; then references are
  appended to the row's `evidence` (group key = identity, paths `field.evidence.<key>`, depth 4,
  1 occurrence each, dedup within the row).
  **Rows with the same (field, key) merge: their evidence lists are unioned; member fields
  from the second call are NOT re-applied** (the first row's members win, but `observe` still
  records the second call's member paths).
* On the first overflow: `overflow = true`, **every top-level array in the skeleton is
  truncated to length 0**, row and group maps cleared; subsequent calls still record `fields`
  but store nothing.
* `finish(sortRows)`: if not overflowed, sort each row's `evidence` by `compareQueryEvidence`,
  sort each non-empty top-level list that received `evidence()` calls by `compareQueryEvidence`,
  then call the kind-specific `sortRows`. Returns `{answer?: skeleton (absent on overflow),
  includedFields: sorted(fields), outputLimitExceeded}`.

Consequences: `includedFields` for RESPONSIBLE/SURVIVES always contains every top-level
skeleton key plus `<list>.evidence` for every list that had a row and `<list>.evidence.<k>` for
every reference key actually emitted (`kind, eventId, eventType, position, historyHash` for
EVENT refs; `kind, receiptContentHash, eventId, position` for RECEIPT_COMMITMENT refs), plus
every member path present in any row (including nested paths such as
`adapterOutcomes.acknowledgment.result.submissionReference`). **[verified]** a SURVIVES for a
non-existent agent needs only the 12 (E1–E4) top-level keys in the disclosure; removing
`"exists"` → DISCLOSURE_INVALID.

### A.9 `portablePublicQueryDisclosure(kind)` and `PORTABLE_QUERY_ANSWER_FIELD_PATHS`

`PORTABLE_QUERY_ANSWER_FIELD_PATHS` is the protocol-sorted union of the paths generated by the
following table (`fields(prefix, names)` adds `prefix.name` for each space-separated name, or
`name` when prefix is empty). **[verified]** the full list has **485** entries and
`hashCanonical(list) = 0xcf32ec76f16d5729d18b566261110a21fae4d95590a2e6dd790a9b4a4d8e244e`.

```
EVID = "kind eventId eventType position historyHash authorityId grantEventId keyId sessionId admissionEventId receiptContentHash evidenceType reference attesterId"
CONS = "actions resources quantitative notBefore expiresAt maxAmount maxCumulativeAmount maxTransactions maxDelegationDepth requiredIntersectionIds"
ROOT = "rootAuthorityId principalId principalRecognitionEventId rootGrantEventId"
DOM  = "protocol version deploymentId chainId verifyingContract"
GRANT= "kind authorityId grantorId granteeId rootAuthorityId parentAuthorityId independent constraints"
PROF = "profileId profileVersion descriptorHash"

fields("", "authorization presentConsequentialUse authorizationDecision attributions targetAgentId exists lifecycleStatus historicalIdentity currentRoleTenures transferredRoleTenures unresolvedIntents adapterOutcomes outcomeObservations attemptDuties receiptCommitments obligations currentPerformanceAssignments invalidatedAuthorityDependencies")
fields("authorization", "operationVersion decision scopeAssurance consequential proof code failures")
fields("authorization.failures", "code subjectId rootAuthorityId terminalAuthorityId failingAuthorityId authorityPathIds evidence")
fields("authorization.failures.evidence", EVID)
fields("authorization.proof", "proofVersion domain policyVersion rootRecognitionPolicy historyHead evaluationTime request recognizedRoot permissionPath intersections effectiveConstraints controllingAuthorityIds usageSnapshot authorityEvidence checkedProhibitionIds consequential runtimeSessionId credentialKeyId controlEpoch roleId roleTenureId intentId nonce")
fields("authorization.proof.domain", DOM)
fields("authorization.proof.historyHead", "hash position canonicalTime")
fields("authorization.proof.request", "actorId action resource claimedAt amount counterpartyId termsCommitment")
fields("authorization.proof.recognizedRoot", ROOT)
fields("authorization.proof.permissionPath", GRANT)
fields("authorization.proof.permissionPath.constraints", CONS)
fields("authorization.proof.intersections", "requiredAuthorityId requiredByAuthorityIds recognizedRoot path effectiveConstraints")
fields("authorization.proof.intersections.recognizedRoot", ROOT)
fields("authorization.proof.intersections.path", GRANT)
fields("authorization.proof.intersections.path.constraints", CONS)
fields("authorization.proof.intersections.effectiveConstraints", CONS)
fields("authorization.proof.effectiveConstraints", CONS)
fields("authorization.proof.usageSnapshot", "authorityId admittedTransactionCount admittedCumulativeAmount")
fields("authorization.proof.authorityEvidence", "authorityId grantEventId grantEventPosition")
fields("attributions", "kind subjectId temporalBasis evidence")
fields("attributions.evidence", EVID)
fields("historicalIdentity", EVID); fields("receiptCommitments", EVID)
for P in [currentRoleTenures, transferredRoleTenures]: fields(P, "roleId agentId roleTenureId tenureNumber status evidence"); fields(P+".evidence", EVID)
fields("unresolvedIntents", "intentId actorId nonce state evidence")
fields("outcomeObservations", "observationEventId intentId sourceAdmissionEventId originalActorId recorderId recordedAt reportDigest reportStatus externalOutcome evidence")
fields("outcomeObservations.reportDigest", "algorithm value")
fields("outcomeObservations.evidence", EVID)
fields("attemptDuties", "dutyId sourceIntentId sourceAdmissionEventId originalActorId durableRoleId creationActorId initialAssigneeId currentAssigneeId deadline status externalOutcome evidence reviewStatus reviews")
fields("attemptDuties.reviews", "dutyId actorId observationEventIds summaryDigest eventId eventPosition reviewedAt")
fields("attemptDuties.evidence", EVID)
fields("adapterOutcomes", "intentId actorId adapterProfile state acknowledgment latestOutcome evidence")
fields("adapterOutcomes.adapterProfile", PROF)
fields("adapterOutcomes.evidence", EVID)
fields("adapterOutcomes.latestOutcome", "intentId eventId eventPosition head status attesterId evidenceReference noEffect")
fields("adapterOutcomes.latestOutcome.head", "hash position canonicalTime")
fields("adapterOutcomes.latestOutcome.evidenceReference", EVID)
for P in [adapterOutcomes.acknowledgment, adapterOutcomes.latestOutcome.noEffect]:
  fields(P, "schemaVersion kind adapterProfile domain intentId admissionHead idempotencyKey submissionFingerprint result")
  fields(P+".adapterProfile", PROF); fields(P+".domain", DOM); fields(P+".admissionHead", "hash position canonicalTime")
fields("adapterOutcomes.acknowledgment.result", "kind submissionReference manifestDigest transitionDigest publicationManifestDigest reportDigest")
fields("adapterOutcomes.acknowledgment.result.reportDigest", "algorithm value")
fields("adapterOutcomes.acknowledgment.result.manifestDigest", "algorithm value")
fields("adapterOutcomes.acknowledgment.result.publicationManifestDigest", "algorithm value")
fields("adapterOutcomes.acknowledgment.result.transitionDigest", "algorithm value")
fields("adapterOutcomes.latestOutcome.noEffect.result", "kind reference")
fields("obligations", "obligationId durableRoleId performanceAssigneeId status deadline evidence")
fields("currentPerformanceAssignments", "obligationId assigneeId successionRuleId evidence")
fields("invalidatedAuthorityDependencies", "authorityId state evidence")
for P in [unresolvedIntents, obligations, currentPerformanceAssignments, invalidatedAuthorityDependencies]: fields(P+".evidence", EVID)
```

`portablePublicQueryDisclosure(kind)` = `{mode:"PUBLIC_MINIMAL", withheldFields: [],
includedFields: filter(PORTABLE_QUERY_ANSWER_FIELD_PATHS, …)}` where the filter keeps:
* WHY: `path === "presentConsequentialUse" || path === "authorization" || path.startsWith("authorization.")` → **143** paths;
* RESPONSIBLE: `path === "authorizationDecision" || path === "attributions" || path.startsWith("attributions.")` → **20** paths;
* SURVIVES: everything else → **322** paths.

(The list is already sorted, so the filtered list stays strictly sorted.)

### A.10 Verified established scope example

For the handover fixture (`tests/fixtures/handover-history.json`, 26 events, head position 25,
canonicalTime 25, hash `0x4958d40342fc047d3fff0d3ab0f36e572ea28d9a1bb6dcbfbc1961c52231b779`)
`scope` of every SAME_HEAD established answer is:

```
canonicalLineageId: "lineage:first-look"
disclosure: <echo of input>
domain: {chainId:"31337", deploymentId:"core-0.2-reference:first-look", protocol:"continuity",
         verifyingContract:"0x0000000000000000000000000000000000003002", version:"0.2"}
evaluationHead = observedHead = {canonicalTime:25, hash:"0x4958…b779", position:25}
externalAssumptions: <A.1>
finality: "LOCAL_ONLY", freshness: "CURRENT", headRelationship: "SAME_HEAD"
policyVersion: "local-evidence-intake-policy:first-look/0.2"
recognizedRootIds: ["collect-authority:first-look","obligate-authority:first-look",
  "progress-a-authority:first-look","progress-b-authority:first-look","review-authority:first-look"]
rootRecognitionPolicy: "declared-principal-root/0.2"
unavailableEvidence: [], versions: <VERSIONS>, withheldEvidence: []
```

With `evaluationEvents = events.slice(0,13)` and `observedEvents = full`: `headRelationship:
"STRICT_EXTENSION"`, `freshness: "AT_EVALUATION"`, `evaluationHead.position 12`,
`observedHead.position 25`; the answer is computed from the evaluation state only **[verified]**
(SURVIVES for `a` at time 12 reports `ACTIVE` with one current tenure). `evaluationTime` may
exceed the observed head time (30 → still ESTABLISHED).

---

## B. WHY

### B.1 Answer shape

```
PortableWhyAnswer = { authorization: PortableQueryAuthorization, presentConsequentialUse: boolean }
PortableQueryAuthorization = the ALLOW or DENY result of authorizePortable (spec 02) with
  operationVersion "continuity-authorization/0.2" and scopeAssurance "REPLAY_VERIFIED"
```

WHY has no projection writer. `answer = { authorization, presentConsequentialUse }` where
`presentConsequentialUse = authorization.decision === "ALLOW" && authorization.consequential
&& relationship === "SAME_HEAD"`.

`includedFields` = `answerFieldPaths(answer)`: every dotted path of a non-`undefined` value in
the answer, visiting arrays element-wise without indices, protocol-sorted. All must be present
in `disclosure.includedFields` or the query fails `DISCLOSURE_INVALID`. **[verified]** an empty
`includedFields` → `DISCLOSURE_INVALID`; removing one used path
(`authorization.proof.request.claimedAt`) → `DISCLOSURE_INVALID`; a superset (SURVIVES paths
added) is fine.

### B.2 Relationship to the authorization result

The `authorization` member is the verbatim frozen `authorizePortable` result (ALLOW:
`{operationVersion, decision:"ALLOW", scopeAssurance:"REPLAY_VERIFIED", consequential, proof}`;
DENY: `{operationVersion, decision:"DENY", scopeAssurance:"REPLAY_VERIFIED", consequential:false,
code, failures}`). A DENY is an ESTABLISHED answer, not a failure. The proof's
`permissionPath[i].constraints` lists are **normalized (sorted)** even when the underlying
grant event had them unsorted **[verified]**.

### B.3 Verified example (handover fixture)

`why(b, "record-review-progress", "obligation:first-look")` at time 25 → ESTABLISHED, ALLOW,
`presentConsequentialUse:false`, `proof.permissionPath.length 1` (authority
`progress-b-authority:first-look`, granted at position 12), `controllingAuthorityIds:
["progress-b-authority:first-look"]`, `recognizedRoot: {principalId:"principal:first-look",
principalRecognitionEventId:"first-look:principal", rootAuthorityId:"progress-b-authority:first-look",
rootGrantEventId:"first-look:progress-b-authority"}`, `usageSnapshot: []`, `intersections: []`,
`checkedProhibitionIds: []`, `consequential:false`, no runtime/intent fields on the proof.

`why(b, "collect-evidence-packet", "resource:first-look")` → ESTABLISHED, DENY,
`code: "ACTION_NOT_ALLOWED"`, two failures (one per candidate path,
`progress-b-authority:first-look` then `review-authority:first-look`), each with 13 evidence
references (all authority-decision events) sorted by eventId.

With a consequential binding on the pre-admission prefix (14 events of
`core02-simulated-r1`, evaluationTime 14): SAME_HEAD → `ALLOW`, `consequential:true`,
`presentConsequentialUse:true`; with observed = extended history → STRICT_EXTENSION,
`presentConsequentialUse:false`. Evaluating the same binding against a prefix that already
contains the admission → DENY `SESSION_CREDENTIAL_INVALID` (signature bound to the older head).
A binding without `intentId`/`nonce` → DENY `SESSION_CREDENTIAL_REQUIRED` (no
`credentialKeyId`) **[verified]**.

---

## C. RESPONSIBLE

### C.1 Types

```
PortableResponsibilityKind (ordered): ACTOR, RUNTIME_SESSION, ROLE, DECLARED_PRINCIPAL, MANDATOR,
  AUTHORITY_SOURCE, CONTROLLER, DURABLE_OBLIGOR, PERFORMANCE_ASSIGNEE, BENEFICIARY, COUNTERPARTY
PortableResponsibilityAttribution = { kind, subjectId, temporalBasis: "ACTION_PREFIX"|"LATER_CAUSAL_STATE", evidence: Evidence[] }
PortableResponsibleAnswer = { authorizationDecision: "ALLOW"|"DENY", attributions: PortableResponsibilityAttribution[] }
```

### C.2 Algorithm (`derivePortableResponsibility(evaluationState, observedState, authorization)`)

Inputs: both replay states (relationship SAME_HEAD or STRICT_EXTENSION guaranteed by the
coordinator) and the ALLOW/DENY authorization computed at the evaluation head.

Skeleton `{authorizationDecision: authorization.decision, attributions: []}`.
If `DENY` → finish immediately: `attributions: []` **[verified]** (FINDING-005: a denied action
attributes to nobody).

Otherwise let `proof = authorization.proof`, `agent = evaluation.agents.get(proof.request.actorId)`,
`E(p) = queryEventReference(evaluationState, p)`, `O(p) = queryEventReference(observedState, p)`,
`finalEvent = E(evaluation.head.position)`, `eventFor(state, pred)` = reference to the first
event (lowest position) satisfying `pred`.

`add(kind, subjectId, basis, evidence)` writes a row keyed by `canonicalEncode([kind, subjectId,
basis])` — repeated adds with the same key **merge evidence** (set union); `evidence` must be
non-empty.

1. `agentCreation = eventFor(AGENT_CREATED with data.agentId === agent.id)`;
   `principalCreation = eventFor(PRINCIPAL_CREATED with data.principalId === agent.principalId)`.
2. `ACTOR ← agent.id, ACTION_PREFIX, [agentCreation, finalEvent]`.
3. `DECLARED_PRINCIPAL ← agent.principalId, ACTION_PREFIX,
   proof.consequential ? [principalCreation, agentCreation] : [principalCreation, agentCreation, finalEvent]`.
4. For each `selection` in `[{recognizedRoot: proof.recognizedRoot, path: proof.permissionPath},
   ...proof.intersections]` (intersections have `recognizedRoot` and `path`):
   * `root = evaluation.recognizedRoots.get(selection.recognizedRoot.rootAuthorityId)`;
     `rootPrincipal = E(evaluation.principals.get(root.principalId).creationEventPosition)`;
   * `grants = selection.path.map(grant → E(evaluation.authorities.get(grant.authorityId).grantEventPosition))`
     (see C.6 for the invariant that guards this lookup);
   * `rootGrant = eventFor(event.id === root.rootGrantEventId)`;
   * `MANDATOR ← root.principalId, ACTION_PREFIX, [rootPrincipal, rootGrant, finalEvent]`;
   * `AUTHORITY_SOURCE ← root.rootAuthorityId, ACTION_PREFIX,
     proof.consequential ? [rootPrincipal, ...grants] : [rootPrincipal, ...grants, finalEvent]`.
5. If `!proof.consequential`: `CONTROLLER ← agent.controllerId, ACTION_PREFIX, [agentCreation, finalEvent]`.
   Done (go to sort).
6. Consequential (`proof.runtimeSessionId, controlEpoch, roleId, roleTenureId, intentId, nonce`
   all present): `session = evaluation.runtimeSessions.get(proof.runtimeSessionId)`,
   `tenure = evaluation.tenures.get(proof.roleTenureId)`,
   `intent = evaluation.intentDeclarations.get(proof.intentId).data`.
   * `declaration = eventFor(TRANSACTION_INTENT_DECLARED with data.intentId === proof.intentId)`;
   * `sessionAdmission = E(session.admissionEventPosition)`;
   * `advances` = references (ascending position) to every `CONTROL_EPOCH_ADVANCED` in the
     evaluation history with `data.agentId === agent.id && data.toEpoch <= proof.controlEpoch`;
   * `roleCreation = eventFor(ROLE_CREATED with data.roleId === proof.roleId)`;
   * `opening = eventFor(AGENT_APPOINTED with data.roleTenureId === proof.roleTenureId, OR
     ROLE_TRANSFERRED with data.toRoleTenureId === proof.roleTenureId)` (first match of either);
   * `ACTOR ← agent.id, ACTION_PREFIX, [declaration]` (merges into row from step 2);
   * `RUNTIME_SESSION ← session.id, ACTION_PREFIX, [sessionAdmission, advances.at(-1) ?? agentCreation, finalEvent]`;
   * `ROLE ← proof.roleId, ACTION_PREFIX, [roleCreation, opening, finalEvent]`;
   * `CONTROLLER ← agent.controllerId, ACTION_PREFIX, [agentCreation, sessionAdmission, ...advances, finalEvent]`;
   * if `intent.counterpartyId !== undefined`: `COUNTERPARTY ← intent.counterpartyId, ACTION_PREFIX, [declaration, finalEvent]`.
7. Later causal state (uses the **observed** state): `admission =
   observed.intentAdmissions.get(proof.intentId)`. Only if it exists **and**
   `canonicalEncode(observed.events[admission.admissionEventPosition].data.authorizationProof)
   === canonicalEncode(proof)` (the admitted proof is exactly this proof):
   `proofHash = hashCanonical(proof)`; for each `obligation` in `observed.obligations.values()`
   with `record.sourceIntentId === proof.intentId`:
   * `receipt = observed.receiptCommitments.get(record.causalReceiptContentHash)`;
   * `chain = [O(admission.admissionEventPosition), receiptRef(receipt), roleCreation, opening, O(obligation.creationEventPosition)]`;
   * scan observed events after `obligation.creationEventPosition` whose `data.obligationId ===
     record.obligationId`: maintain `performer` (initially `record.performanceAssigneeId`) and
     `performerEvidence: Map<agentId, Evidence[]>` seeded `performer → [...chain]`;
     for `OBLIGATION_PERFORMANCE_ASSIGNED`: push ref to current performer's list, set
     `performer = toAgentId`, create its list `[...chain]` if absent, push ref to it;
     for `OBLIGATION_STATUS_RECORDED`: push ref to `statusEvidence` and to the current
     performer's list; other types ignored;
   * `DURABLE_OBLIGOR ← record.durableRoleId, LATER_CAUSAL_STATE, [...chain, ...statusEvidence]`;
   * `BENEFICIARY ← record.beneficiaryId, LATER_CAUSAL_STATE, same`;
   * if `record.counterpartyId !== undefined`: `COUNTERPARTY ← record.counterpartyId, LATER_CAUSAL_STATE, same`;
   * for each `(subject, evidence)` in `performerEvidence` (insertion order):
     `PERFORMANCE_ASSIGNEE ← subject, LATER_CAUSAL_STATE, evidence`.
   If the admission is absent or carries a different proof, no LATER_CAUSAL_STATE rows exist.
8. Finish: each row's evidence sorted by `compareQueryEvidence`; rows sorted by
   (kind rank in the `PortableResponsibilityKind` order, then `subjectId` protocol order, then
   `ACTION_PREFIX` before `LATER_CAUSAL_STATE`).

### C.3 Verified example — non-consequential ALLOW (handover, b / record-review-progress)

Five attributions, in this order, with evidence `[eventId@position]` sorted by eventId:

```
ACTOR              b:first-look           ACTION_PREFIX  [first-look:b@3, first-look:stale-declared@25]
DECLARED_PRINCIPAL principal:first-look   ACTION_PREFIX  [first-look:b@3, first-look:principal@1, first-look:stale-declared@25]
MANDATOR           principal:first-look   ACTION_PREFIX  [first-look:principal@1, first-look:progress-b-authority@12, first-look:stale-declared@25]
AUTHORITY_SOURCE   progress-b-authority:first-look ACTION_PREFIX [first-look:principal@1, first-look:progress-b-authority@12, first-look:stale-declared@25]
CONTROLLER         controller:first-look  ACTION_PREFIX  [first-look:b@3, first-look:stale-declared@25]
```
(`first-look:stale-declared@25` is the evaluation head event = `finalEvent`.)

### C.4 Verified example — consequential ALLOW with later obligation

Evaluation = 14-event prefix of `core02-simulated-r1` (head 13), observed = that prefix plus
admission(14), consumption(15), RECEIPT_RECORDED(16), OBLIGATION_CREATED(17); binding =
the admitted binding; time 14. Result STRICT_EXTENSION, attributions (positions only):

```
ACTOR                a          ACTION_PREFIX       [2, 13]            (AGENT_CREATED, declared)
RUNTIME_SESSION      session:a  ACTION_PREFIX       [2, 13, 7]         (no epoch advance → agentCreation stands in)
ROLE                 role       ACTION_PREFIX       [6, 13, 4]
DECLARED_PRINCIPAL   principal  ACTION_PREFIX       [2, 1]             (no finalEvent when consequential)
MANDATOR             principal  ACTION_PREFIX       [8, 13, 1]
AUTHORITY_SOURCE     collect-authority ACTION_PREFIX [8, 1]           (no finalEvent when consequential)
CONTROLLER           controller ACTION_PREFIX       [2, 13, 7]
DURABLE_OBLIGOR      role       LATER_CAUSAL_STATE  [14, 6, 4, 17, receipt@16]
PERFORMANCE_ASSIGNEE a          LATER_CAUSAL_STATE  [14, 6, 4, 17, receipt@16]
BENEFICIARY          principal  LATER_CAUSAL_STATE  [14, 6, 4, 17, receipt@16]
```
(Ordering within a list is by eventId string; the `RECEIPT_COMMITMENT` reference sorts after all
EVENT references.)

### C.5 `projectPortableResponsibility` / `requirePortableQueryProjection`

Internal helpers: the latter throws the overflow token if `outputLimitExceeded || answer ===
undefined`; not part of the public surface.

### C.6 The invariant at `portable-query-responsibility.ts:71` — known bug

```
for (const grant of selection.path) {
  const stored = evaluationState.authorities.get(grant.authorityId);
  invariant(stored !== undefined && canonicalEncode(stored.grant) === canonicalEncode(grant));
  grants.push(eventReference(evaluationState, stored.grantEventPosition));
}
```

The two copies compared are:

1. `grant` — a member of `proof.permissionPath` (or `intersection.path`). The authority engine
   builds these with `normalizedPermission`, which copies the grant and **sorts** the
   `constraints.actions`, `constraints.resources` and `constraints.requiredIntersectionIds`
   arrays into protocol order (`sortedIdentifiers`), and re-emits the optional fields only when
   present.
2. `stored.grant` — the grant **exactly as recorded** in the accepted `AUTHORITY_GRANTED` event.
   The event schema requires those three lists to be distinct Identifiers but does **not**
   require sorted order (`identifierList` checks only duplicates), and replay stores the event's
   record verbatim.

`canonicalEncode` sorts record keys but preserves array order, so when a grant was recorded
with any of the three lists unsorted, the two encodings differ and the reference engine throws
`TypeError("Inconsistent internal responsibility projection inputs.")` out of
`responsiblePortable` (no envelope is returned). **[verified]** appending an
`AUTHORITY_GRANTED` with `actions: ["zeta","alpha"]` (or sorted actions but
`resources: ["resource:first-look","aaa:first-look"]`) to the handover fixture replays
`ACCEPTED`, `whyPortable` for that action returns ESTABLISHED/ALLOW with the proof showing the
*sorted* lists, and `responsiblePortable` throws. With the same grant recorded sorted,
`responsiblePortable` returns ESTABLISHED with the expected five ACTION_PREFIX attributions
(`AUTHORITY_SOURCE` = the new authority id).

**Required behaviour for the re-implementation:** never throw. Treat the invariant as satisfied
whenever `stored !== undefined` and `canonicalEncode(normalize(stored.grant)) ===
canonicalEncode(grant)` (normalization = sort the three identifier lists), or equivalently
simply look up `stored` by `grant.authorityId` and use `stored.grantEventPosition`. The
produced answer must be identical to what the reference engine produces for the same history
with the lists sorted (the evidence only uses `grantEventPosition`, which is independent of
list order). All other invariants in this file are guaranteed by replay and by the coordinator
(the authorization is always computed at the evaluation head; `proof.historyHead` equals
`evaluation.head`; the recognized root in the proof is byte-identical to the stored root; for a
consequential ALLOW the session/tenure/intent facts always agree; obligation chains created by
replay always satisfy the receipt/admission/position checks). A robust implementation may still
convert any other unexpected inconsistency into an `OUTPUT_LIMIT_EXCEEDED`-free established
answer by skipping the offending row, but no such case is reachable from accepted histories.

---

## D. SURVIVES

### D.1 Answer shape

```
PortableSurvivesAnswer = {
  targetAgentId: string, exists: boolean, lifecycleStatus: "ABSENT"|"ACTIVE"|"TERMINATED",
  historicalIdentity: Evidence[],
  currentRoleTenures: RoleTenureProjection[], transferredRoleTenures: RoleTenureProjection[],
  unresolvedIntents: IntentProjection[], adapterOutcomes: AdapterOutcomeProjection[],
  outcomeObservations?: OutcomeObservationProjection[],   // only when genesis policy is E5 or E6
  attemptDuties?: AttemptDutyProjection[],                // only when genesis policy is E5 or E6
  receiptCommitments: Evidence[], obligations: ObligationProjection[],
  currentPerformanceAssignments: PerformanceAssignmentProjection[],
  invalidatedAuthorityDependencies: AuthorityDependencyProjection[] }
RoleTenureProjection = { roleId, agentId, roleTenureId, tenureNumber, status:"CURRENT"|"CLOSED", evidence }
IntentProjection = { intentId, actorId, nonce, state: "DECLARED"|"ADMITTED"|"SUBMITTED"|"OUTCOME_UNKNOWN"|"DISPUTED", evidence }
AdapterOutcomeProjection = { intentId, actorId, adapterProfile, state: "SUBMITTED"|OutcomeStatus, acknowledgment?, latestOutcome?, evidence }
OutcomeObservationProjection = { observationEventId, intentId, sourceAdmissionEventId, originalActorId, recorderId, recordedAt, reportDigest:{algorithm:"sha256", value}, reportStatus:"REPORT_RECORDED"|"DIVERGENT_REPORTS", externalOutcome:"NOT_PROVEN", evidence }
AttemptDutyProjection = { dutyId, sourceIntentId, sourceAdmissionEventId, originalActorId, durableRoleId, creationActorId, initialAssigneeId, currentAssigneeId, deadline, status:"OPEN", externalOutcome:"NOT_PROVEN", evidence, reviewStatus? ("UNREVIEWED"|"REVIEW_CLOSED"|"NEEDS_REVIEW", E6 only), reviews? (E6 only) }
ObligationProjection = { obligationId, durableRoleId, performanceAssigneeId, status, deadline, evidence }
PerformanceAssignmentProjection = { obligationId, assigneeId, successionRuleId, evidence }
AuthorityDependencyProjection = { authorityId, state: "REVOKED"|"EXPIRED"|"AGENT_TERMINATED", evidence }
```

### D.2 Skeleton

```
targetAgentId, exists: state.agents.has(target),
lifecycleStatus: !exists ? "ABSENT" : agent.terminated ? "TERMINATED" : "ACTIVE",
historicalIdentity: [], currentRoleTenures: [], transferredRoleTenures: [], unresolvedIntents: [],
adapterOutcomes: [],
(if genesis.adapterPolicyHash ∈ {E5_HASH, E6_HASH}) outcomeObservations: [], attemptDuties: [],
receiptCommitments: [], obligations: [], currentPerformanceAssignments: [], invalidatedAuthorityDependencies: []
```
The E5/E6 keys are present (and thus required in the disclosure) even when empty
**[verified]**; for E1–E4 genesis they are absent. If the agent does not exist the walk stops
after the skeleton (all lists empty) **[verified]** for `nobody:first-look`.

### D.3 Walk (`walkPortableSurvives(state, target, evaluationTime, writer)`)

All references below are `ref(p) = queryEventReference(state, p)` (cached per position) or
`receiptRef(record)`. `matching(pred)` = refs to every event (ascending position) satisfying
`pred`.

1. **historicalIdentity** ← `writer.evidence("historicalIdentity", matching(
   PRINCIPAL_CREATED with principalId === agent.principalId,
   OR (AGENT_CREATED|AGENT_TERMINATED) with agentId === target))`.
2. **Tenures**: for each `tenure` in `state.tenures.values()` with `tenure.agentId === target`:
   evidence = `matching(ROLE_CREATED with roleId === tenure.roleId, OR (AGENT_APPOINTED|
   AGENT_UNAPPOINTED) with roleTenureId === tenure.id, OR ROLE_TRANSFERRED with
   fromRoleTenureId === tenure.id or toRoleTenureId === tenure.id)`; row into
   `transferredRoleTenures` if `tenure.closed` else `currentRoleTenures`, key `tenure.id`,
   members `{roleId, agentId: target, roleTenureId: tenure.id, tenureNumber, status: closed ?
   "CLOSED" : "CURRENT"}`. Note: an unappointed (closed, not transferred) tenure also lands in
   `transferredRoleTenures` (the list name is historical).
3. **Intents**: for each `[intentId, declaration]` in `state.intentDeclarations` with
   `declaration.data.actorId === target`:
   * `latestOutcome = state.intentOutcomeStates.get(intentId)?.latest`, `outcome =
     latestOutcome?.status`, `consumption = state.intentConsumptions.get(intentId)`;
   * evidence = `matching(event.data.intentId === intentId AND type ∈ {TRANSACTION_INTENT_DECLARED,
     TRANSACTION_INTENT_ADMITTED, TRANSACTION_INTENT_CONSUMED, TRANSACTION_OUTCOME_RECORDED})`
     (every outcome record for the intent, not just the latest);
   * if `consumption !== undefined || latestOutcome !== undefined`: row `adapterOutcomes` key
     `intentId`, members `{intentId, actorId: target, adapterProfile: declaration.data.adapterProfile,
     state: outcome ?? "SUBMITTED", acknowledgment: consumption.acknowledgment (if consumed),
     latestOutcome (if any)}`, with that evidence;
   * if `outcome ∈ {CONFIRMED, FAILED}` → continue (terminal; **not** unresolved) **[verified]**;
   * else `intentState = outcome ?? (consumption ? "SUBMITTED" : state.intentAdmissions.has(intentId)
     ? "ADMITTED" : "DECLARED")`; row `unresolvedIntents` key `intentId`, members `{intentId,
     actorId: target, nonce: declaration.data.nonce, state: intentState}`, same evidence; remember
     `intentId` in `includedIntentIds`.
   So `DISPUTED` and `OUTCOME_UNKNOWN` outcomes appear in **both** `adapterOutcomes` and
   `unresolvedIntents`; a bare declaration appears only in `unresolvedIntents` (state
   `DECLARED`); a consumed intent without outcome appears in both (`SUBMITTED`).
4. **outcomeObservations** (only populated on E5/E6; the loop runs regardless but the map is
   empty otherwise): for each `[intentId, observations]` in `state.outcomeObservations`:
   `originalActorId = intentDeclarations.get(intentId).data.actorId`; `relatedDuty` = the
   attempt duty (first in map order) with `record.sourceIntentId === intentId`;
   `linkedAssignee = relatedDuty && (relatedDuty.record.performanceAssigneeId === target ||
   relatedDuty.assignments.some(a → a.fromAgentId === target || a.toAgentId === target))`.
   Skip unless `originalActorId === target || observations.some(o → o.actorId === target) ||
   linkedAssignee`. `digests = Set(observations.map(o → o.acknowledgment.result.reportDigest.value))`;
   `source = state.intentAdmissions.get(intentId)`. For each observation: row
   `outcomeObservations` key `observation.eventId`, members `{observationEventId: eventId,
   intentId, sourceAdmissionEventId, originalActorId, recorderId: observation.actorId,
   recordedAt: observedAt, reportDigest: acknowledgment.result.reportDigest, reportStatus:
   digests.size > 1 ? "DIVERGENT_REPORTS" : "REPORT_RECORDED", externalOutcome: "NOT_PROVEN"}`,
   evidence `[ref(source.admissionEventPosition), ref(observation.eventPosition)]`.
   **[verified]** two observations with different digests → both `DIVERGENT_REPORTS`; a third
   with a repeated digest keeps all three `DIVERGENT_REPORTS` (size of the set is 2).
5. **attemptDuties**: for each `[dutyId, duty]` in `state.attemptDuties`: `record = duty.record`,
   `source = intentAdmissions.get(record.sourceIntentId)`, `originalActorId =
   intentDeclarations.get(record.sourceIntentId).data.actorId`. Skip unless
   `originalActorId === target || record.performanceAssigneeId === target ||
   duty.assignments.some(a → a.fromAgentId === target || a.toAgentId === target)`.
   Row key `dutyId`, members `{dutyId, sourceIntentId, sourceAdmissionEventId, originalActorId,
   durableRoleId, creationActorId: duty.creationActorId, initialAssigneeId:
   record.performanceAssigneeId, currentAssigneeId: duty.currentAssigneeId, deadline,
   status: record.status ("OPEN"), externalOutcome: "NOT_PROVEN", (E6 only:) reviewStatus:
   portableAttemptDutyReviewStatus(state, dutyId), reviews: state.attemptDutyReviews.get(dutyId) ?? []}`.
   Evidence: `[ref(source.admissionEventPosition), ref(duty.creationEventPosition),
   ...assignments.map(a → ref(a.eventPosition))]` plus, on E6 only, refs of every review event
   and every outcome-observation event for the source intent.
   **[verified]** E5 duty evidence = `[admission, ATTEMPT_DUTY_CREATED]` and the row has no
   `reviewStatus`/`reviews`; E6 duty after two observations and one review = `[admission,
   review, created, obs a, obs z]` (sorted by eventId).
   `reviews` entries are the replay records verbatim: `{dutyId, actorId, observationEventIds,
   summaryDigest, eventId, eventPosition, reviewedAt}`.
6. **obligations / currentPerformanceAssignments**: for each `[obligationId, obligation]` in
   `state.obligations`: skip if `obligation.status ∈ {DISCHARGED, IMPOSSIBLE_OR_ESCALATED}` or
   `!portableObligationLinksTarget(state, obligationId, target)` where the link predicate is:
   `intentDeclarations.get(record.sourceIntentId)?.data.actorId === target` OR
   `tenures.get(record.creationRoleTenureId)?.agentId === target` OR
   `record.performanceAssigneeId === target` OR any `OBLIGATION_PERFORMANCE_ASSIGNED` event in
   the history with `obligationId === obligationId && toAgentId === target`.
   * `receipt = receiptCommitments.get(record.causalReceiptContentHash)`;
     `causal = [receiptRef(receipt), ref(obligation.creationEventPosition)]`;
   * `assignments = matching(OBLIGATION_PERFORMANCE_ASSIGNED with obligationId)`;
     `statuses = matching(OBLIGATION_STATUS_RECORDED with obligationId)`;
   * `targetLinks = matching(TRANSACTION_INTENT_DECLARED with intentId === record.sourceIntentId
     && actorId === target, OR AGENT_APPOINTED with roleTenureId === record.creationRoleTenureId
     && agentId === target, OR ROLE_TRANSFERRED with toRoleTenureId === record.creationRoleTenureId
     && toAgentId === target)`;
   * row `obligations` key `obligationId`, members `{obligationId, durableRoleId,
     performanceAssigneeId: obligation.performanceAssigneeId (current), status: obligation.status
     (current), deadline: record.deadline}`, evidence `[...causal, ...assignments, ...statuses, ...targetLinks]`;
   * `successionRuleId = record.successionRuleId`, overridden by the `successionRuleId` of the
     **last** `OBLIGATION_PERFORMANCE_ASSIGNED` event for this obligation (scan all events);
   * row `currentPerformanceAssignments` key `obligationId`, members `{obligationId,
     assigneeId: obligation.performanceAssigneeId, successionRuleId}`, evidence `[...causal, ...assignments]`;
   * remember `record.causalReceiptContentHash` in `includedReceiptHashes`.
7. **receiptCommitments** ← for each receipt in `state.receiptCommitments.values()` with
   `includedIntentIds.has(receipt.intentId) || includedReceiptHashes.has(receipt.receiptContentHash)`:
   `writer.evidence("receiptCommitments", [receiptRef(receipt)])`. (A receipt for a terminal
   CONFIRMED/FAILED intent with no surviving obligation is therefore **not** listed
   **[verified]**: after a simulated FAILED outcome, `receiptCommitments` is empty.)
8. **invalidatedAuthorityDependencies**: for each `[authorityId, record]` in
   `state.authorities` with `record.grant.kind === "PERMISSION"`:
   * `path = parentPath(record)` = the record followed by its `parentAuthorityId` chain while
     each is a PERMISSION;
   * skip unless some grant in `path` has `grantorId === target || granteeId === target`;
   * `graph = dependencies(path)`: BFS starting from `path`, adding for every visited record the
     `parentPath` of each `requiredIntersectionIds` member that is a PERMISSION (dedup by
     authorityId; order = path order, then discovered dependencies);
   * `pathEvidence = graph.map(r → ref(r.grantEventPosition))`;
   * `revocations = graph.filter(r → r.revocationEventPosition !== undefined).map(ref)`; if
     non-empty → row `{authorityId, state:"REVOKED"}`, evidence `[...pathEvidence,
     leastEvidence(revocations)]`; continue;
   * if `graph.some(r → r.grant.constraints.expiresAt !== undefined && evaluationTime >=
     r.grant.constraints.expiresAt)` → row `{authorityId, state:"EXPIRED"}`, evidence
     `pathEvidence`; continue;
   * `terminatedIds` = every `grantorId`/`granteeId` of PERMISSION grants in `graph` for which
     `state.agents.get(id)?.terminated === true` (principals are not agents and never count);
     `terminations = matching(AGENT_TERMINATED with agentId ∈ terminatedIds)`; if non-empty →
     row `{authorityId, state:"AGENT_TERMINATED"}`, evidence `[...pathEvidence, leastEvidence(terminations)]`.
   `leastEvidence` = minimum under `compareQueryEvidence`.
   Rows are keyed by `authorityId`; the three states are mutually exclusive per authority with
   precedence REVOKED > EXPIRED > AGENT_TERMINATED.

### D.4 Sorting (`sortSurvives`)

* `outcomeObservations`: by `intentId`, then `observationEventId` (protocol order).
* `attemptDuties`: by `dutyId`.
* `currentRoleTenures`, `transferredRoleTenures`: by `roleId`, then `tenureNumber` (numeric),
  then `roleTenureId`.
* `unresolvedIntents`, `adapterOutcomes`: by `intentId`.
* `obligations`, `currentPerformanceAssignments`: by `obligationId`.
* `invalidatedAuthorityDependencies`: by `authorityId`.
* Every `evidence` list (rows and the two top-level lists) by `compareQueryEvidence`.

### D.5 Effects of lifecycle events (summary)

* `AGENT_TERMINATED` → `lifecycleStatus:"TERMINATED"`, the termination event joins
  `historicalIdentity`, and every PERMISSION whose dependency graph touches the terminated agent
  as grantor/grantee is reported `AGENT_TERMINATED` (unless already REVOKED/EXPIRED).
* `ROLE_TRANSFERRED` (succession) closes the predecessor's tenure → it moves to
  `transferredRoleTenures` with `status:"CLOSED"` and the transfer event in its evidence; the
  successor gets a `currentRoleTenures` row whose evidence is `ROLE_CREATED` +
  `ROLE_TRANSFERRED` (no `AGENT_APPOINTED`).
* `OBLIGATION_PERFORMANCE_ASSIGNED` changes `obligations[].performanceAssigneeId` and
  `currentPerformanceAssignments[].assigneeId` to `toAgentId`, links the obligation to the new
  assignee (so it also appears in the successor's answer), and its `successionRuleId` replaces
  the record's.
* Obligations stay listed for the predecessor after handover (relevance includes historical
  assignments) as long as status is unresolved.
* Attempt duties: `ATTEMPT_DUTY_ASSIGNED` updates `currentAssigneeId` and links both parties;
  `ATTEMPT_DUTY_REVIEW_CLOSED` appends to `reviews` and changes `reviewStatus`.

### D.6 `portableAttemptDutyReviewStatus(state, dutyId)`

```
duty = attemptDuties.get(dutyId); reviews = attemptDutyReviews.get(dutyId) ?? []; latest = reviews.at(-1)
if (!duty || !latest) return "UNREVIEWED"
latestAssignment = duty.assignments.at(-1)
if (latestAssignment && latest.eventPosition <= latestAssignment.eventPosition) return "NEEDS_REVIEW"
ids = (outcomeObservations.get(duty.record.sourceIntentId) ?? []).map(o → o.eventId).sort(compareProtocolStrings)
return latest.actorId === duty.currentAssigneeId && ids.length === latest.observationEventIds.length
       && ids.every((id, i) → id === latest.observationEventIds[i]) ? "REVIEW_CLOSED" : "NEEDS_REVIEW"
```
**[verified]**: UNREVIEWED → REVIEW_CLOSED after a review covering both observations →
NEEDS_REVIEW after an `ATTEMPT_DUTY_ASSIGNED` to a successor → REVIEW_CLOSED after the
successor's review covering the (now three) observations.

### D.7 Verified outputs (handover fixture, time 25) and the conformance projection

`survives(a:first-look)`: `exists:true`, `TERMINATED`; `historicalIdentity` =
`[first-look:a@2 AGENT_CREATED, first-look:principal@1, first-look:terminated@20]`;
`currentRoleTenures: []`; `transferredRoleTenures: [{roleId:"role:first-look", agentId:a,
roleTenureId:"tenure-a:first-look", tenureNumber:1, status:"CLOSED", evidence:[appointment@6,
role@4, transfer@21]}]`; `unresolvedIntents: [{intent:first-look, nonce:"nonce:first-look",
state:"OUTCOME_UNKNOWN", evidence:[consumption@15, admission@14, declared@13, outcome-unknown@17]},
{stale-intent:first-look, nonce:"stale-nonce:first-look", state:"DECLARED", evidence:[stale-declared@25]}]`;
`adapterOutcomes: [{intent:first-look, state:"OUTCOME_UNKNOWN", acknowledgment: <simulated ack>,
latestOutcome: <OUTCOME_UNKNOWN record with EXTERNAL evidenceReference>, evidence: same 4}]`;
`receiptCommitments: [{RECEIPT_COMMITMENT case:first-look:receipt @16, receiptContentHash 0xae4e…1189}]`;
`obligations: [{obligation:first-look, durableRoleId:"role:first-look", performanceAssigneeId: b,
status:"OPEN", deadline:1000, evidence:[appointment@6, assignment@23, declared@13, obligation@18, receipt@16]}]`;
`currentPerformanceAssignments: [{obligation:first-look, assigneeId: b, successionRuleId:
"succession:first-look", evidence:[assignment@23, obligation@18, receipt@16]}]`;
`invalidatedAuthorityDependencies: [collect-authority (REVOKED, evidence [grant@8, revoke@24]),
obligate-authority (AGENT_TERMINATED, [grant@9, terminated@20]), progress-a-authority
(AGENT_TERMINATED, [grant@11, terminated@20])]`.

`survives(b:first-look)`: `ACTIVE`; `historicalIdentity [b@3, principal@1]`;
`currentRoleTenures [{tenure-b, tenureNumber 2, CURRENT, evidence [role@4, transfer@21]}]`;
`transferredRoleTenures []`, `unresolvedIntents []`, `adapterOutcomes []`;
`obligations [{… performanceAssigneeId b, OPEN, evidence [assignment@23, obligation@18, receipt@16]}]`
(no targetLinks for b); `currentPerformanceAssignments` as for a; `receiptCommitments` (linked
through the obligation); `invalidatedAuthorityDependencies []`.

The conformance adapter (`conformance/adapters/node.mjs`, op `survives`) projects:
```
established:false → { established:false, code, epistemicStatus }
established:true  → { established:true, exists, lifecycleStatus,
   obligationIds: obligations.map(o → o.obligationId).sort()           (JS default sort),
   currentAssignments: currentPerformanceAssignments.map(r → {obligationId, assigneeId, successionRuleId}),
   currentRoleTenureCount: currentRoleTenures.length,
   transferredRoleTenureCount: transferredRoleTenures.length,
   invalidatedAuthorityIds: invalidatedAuthorityDependencies.map(r → r.authorityId).sort(),
   unresolvedIntentIds: unresolvedIntents.map(r → r.intentId).sort() }
```
It always passes `portablePublicQueryDisclosure('SURVIVES')` and `observedEvents` only.
Expected vectors: predecessor-after-handover `{TERMINATED, [obligation:first-look],
[{obligation:first-look, b:first-look, succession:first-look}], 0, 1,
[collect-authority, obligate-authority, progress-a-authority], [intent:first-look, stale-intent:first-look]}`;
successor `{ACTIVE, [obligation], same assignment, 1, 0, [], []}`; predecessor-before-handover
(13 events, time 12) `{ACTIVE, [], [], 1, 0, [], []}`; unknown agent `{exists:false, ABSENT, all empty}`.

---

## E. Conflict classification (`findPortableQueryConflict`)

Called only when `headRelationship === "UNVERIFIED"`. Input: two accepted replay states
(`left` = evaluation, `right` = observed) and a selection
`{kind:"SURVIVES", targetAgentId, evaluationTime}` or `{kind:"WHY"|"RESPONSIBLE", binding?}`.
Returns either `undefined` (→ HISTORY_RELATION_UNVERIFIED) or a pair
`[EventRef, EventRef]` (→ EVIDENCE_DISPUTED with `evidence` = the pair). `pairFor(left, x,
right, y)` builds both references and orders them by `compareQueryEvidence` (smaller first);
`leastPair` keeps the lexicographically least pair.

Pre-conditions (any failing → `undefined`):

1. Both genesis domains equal (`domainEqual`, i.e. verifyingContract case-insensitive) and both
   `canonicalLineageId` equal.
2. `prefixLength` = length of the longest common prefix by `canonicalEncode(event)`. Must
   satisfy `0 < prefixLength < left.events.length` and `< right.events.length` (i.e. a genuine
   fork with a shared genesis; a pure prefix relation or a different genesis is not a fork).
3. For WHY/RESPONSIBLE: `binding?.intentId` must be present, otherwise `undefined`
   **[verified]** (a WHY over a forked pair with no binding, or a binding without `intentId`,
   reports HISTORY_RELATION_UNVERIFIED even when both branches admit the same intent).
4. For SURVIVES: `evaluationTime` must be a safe integer ≥ both heads' `canonicalTime` (throws a
   TypeError otherwise — unreachable from the coordinator because A.5(a) already enforced it),
   and `portableSurvivesAnswersDiffer(left, right, target, evaluationTime)` must be true. That
   predicate walks §D.3 on both states into comparison plans (rows keyed by `(field,key)` with
   `canonicalEncode(members)` and the set of interned evidence identities); plans differ if the
   skeletons differ, group counts differ, any group is missing, has different member bytes, or a
   different evidence set. Since evidence identity includes `historyHash`, any row touching a
   post-fork event differs.

Relevance predicates (`x`/`y` are the left/right items):
* `admissionRelevant(x,y)`: SURVIVES → `x.intent.actorId === target || y.intent.actorId === target`;
  WHY/RESPONSIBLE → `x.intent.intentId === binding.intentId || y.intent.intentId === binding.intentId`.
* `creationRelevant(x,y)`: SURVIVES → `portableObligationLinksTarget(left, x.obligationId, target)
  || portableObligationLinksTarget(right, y.obligationId, target)`; WHY/RESPONSIBLE →
  `x.record.sourceIntentId === binding.intentId || y.record.sourceIntentId === binding.intentId`.
* `laterRelevant(firstLeft, firstRight)` (`obligationId = firstLeft.data.obligationId`):
  SURVIVES → `obligationLinksTargetAtPrefix(left, obligationId, target, prefixLength)`
  (obligation created before the fork, linked to target via the creation facts or an
  `OBLIGATION_PERFORMANCE_ASSIGNED` *before* the fork) `|| (firstLeft.type ===
  "OBLIGATION_PERFORMANCE_ASSIGNED" && (firstLeft.data.toAgentId === target ||
  firstRight.data.toAgentId === target))`; WHY/RESPONSIBLE →
  `obligationLinksIntentAtPrefix(left, obligationId, binding.intentId, prefixLength)` (the
  obligation was created before the fork and its full causal identity chain — declaration,
  admission, consumption, receipt, tenure, proof hash, issuer, role/tenure, trigger — matches
  the intent).

Suffix indexes: `suffixAdmissions(state)` = every `intentAdmissions` record with
`admissionEventPosition >= prefixLength`, as `{position, intent: declaration.data, proof:
event.data.authorizationProof}` keyed by intentId; `suffixCreations(state)` = every obligation
with `creationEventPosition >= prefixLength` as `{position, record, effectHash:
event.data.administrativeAuthorization.challenge.transitionEffectHash}`.

The six closed fork classes, evaluated in order; the first class yielding a pair returns:

1. **SAME_INTENT_ADMISSION**: for each left suffix admission `x` with a right suffix admission
   `y` of the same `intentId`, if `admissionRelevant` and (`canonicalEncode(x.intent) !==
   canonicalEncode(y.intent) || canonicalEncode(x.proof) !== canonicalEncode(y.proof)`) → candidate
   `pairFor(x.position, y.position)`; return the least. **[verified]** two branches admitting
   the same intent at evaluationTime 14 vs 15 → `EVIDENCE_DISPUTED` with the two admission
   events (both position 14, different historyHash) for SURVIVES of the actor and for WHY with
   the intent binding; SURVIVES for an unrelated target → HISTORY_RELATION_UNVERIFIED.
2. **SAME_NONCE_ADMISSION**: index right suffix admissions by `canonicalEncode([actorId,
   nonce])`; for each left suffix admission with the same actor/nonce but a *different*
   `intentId`, if relevant → candidate; return the least. **[verified]**.
3. **CAPACITY_RESERVATION**: only if the first post-fork event on *both* sides is a
   `TRANSACTION_INTENT_ADMITTED`; let `x`,`y` be those admissions; require different intentIds,
   not the same actor+nonce, both proofs bound to the common head (`proof.historyHead.position
   === prefixLength−1`, `.hash === left.eventHistoryHashes[prefixLength−1]`, `.canonicalTime ===
   left.events[prefixLength−1].timestamp`), and relevant. Let `shared` = ids in both proofs'
   `controllingAuthorityIds` (sorted); for each shared id: `authority = left.authorities.get(id)`
   must be a PERMISSION granted before the fork with a usage entry `prior` in `x.proof.usageSnapshot`;
   conflict if `constraints.maxTransactions !== undefined && prior.admittedTransactionCount + 2 >
   maxTransactions`, or `constraints.quantitative && maxCumulativeAmount !== undefined &&
   x.intent.amount !== undefined && y.intent.amount !== undefined &&
   prior.admittedCumulativeAmount + x.amount + y.amount > maxCumulativeAmount` → return
   `pairFor(prefixLength, prefixLength)` immediately. **[unverified]**
4. **ADMINISTRATIVE_CREATION**: index right suffix obligation creations by `sourceIntentId`
   and by `obligationId`; for each left suffix creation `x`, for `y` in `[bySource.get(x.sourceIntentId),
   byObligation.get(x.obligationId)]`: if `y` exists, `x.effectHash !== y.effectHash` and
   `creationRelevant` → candidate; return the least. **[unverified]**
5/6. **STATUS / ASSIGNMENT at the fork**: only if the first post-fork events on both sides are
   both `OBLIGATION_STATUS_RECORDED` with equal `fromStatus`, or both
   `OBLIGATION_PERFORMANCE_ASSIGNED` with equal `fromAgentId`; and same `obligationId`; and both
   challenges have `eventHistoryPosition === prefixLength−1` and `eventHistoryHash === common
   hash`; and `transitionEffectHash` differs; and `laterRelevant` → return
   `pairFor(prefixLength, prefixLength)`. **[unverified]**

Otherwise `undefined`. **[verified]** a fork where each side appends a different
`AGENT_CREATED` → HISTORY_RELATION_UNVERIFIED.

---

## F. Intent admission (`continuity-intent-admission/0.2`)

### F.1 Lifecycle overview

```
TRANSACTION_INTENT_DECLARED  (actor-signed? no: an ordinary event; binds intent content + adapterProfile)
   → TRANSACTION_INTENT_ADMITTED (carries the authorization proof + runtime signature; reserves nonce & capacity)
      → TRANSACTION_INTENT_CONSUMED (exactly once; the adapter acknowledgment, requires current control)
         → RECEIPT_RECORDED (optional; commitment to a signed receipt artifact)
      → TRANSACTION_OUTCOME_RECORDED (0..n; CONFIRMED/FAILED are terminal; DISPUTED may follow a terminal; OUTCOME_UNKNOWN non-terminal)
```

Replay rules relevant here (spec 02 owns the full set): a declaration requires an existing
agent, role and tenure and an adapter profile that is a member of the genesis policy edition;
an admission requires `event.timestamp === data.evaluationTime === proof.evaluationTime`,
`data.intentId === proof.intentId`, `data.expectedHistoryHead` and `proof.historyHead` equal to
the pre-event head, `proof.consequential === true`, a Signature65 `runtimeSignature`,
`data.runtimeAuthorizationHash === hashCanonical(challenge)` for the challenge rebuilt from the
proof (F.4), the session's credential address recovering from the signature over that hash,
an `authorizePortableState` re-evaluation that yields ALLOW with a byte-identical proof, a
matching declaration (`sameIntent(declaration, projection(proof.request, binding,
declaration.adapterProfile))`), no prior admission for the intent, no prior reservation of
`(actorId, nonce)`, and capacity (`maxTransactions`/`maxCumulativeAmount`) not exceeded.
Replay then stores the admission record with `adapterIdentity =
derivePortableAdapterIdentityForAcceptedAdmission(event, admissionHead, declaration.adapterProfile,
genesis.adapterPolicyHash)` (§F.7).

A consumption requires: admission exists, no prior consumption, no terminal outcome,
`admissionBoundControlTupleIsCurrent(admission, event.timestamp)` (F.6), `data.adapterId ===
identity.adapterProfile.profileId`, `idempotencyKey`/`submissionFingerprint` equal to the
identity's, `validatePortableAdapterAcknowledgment(data.acknowledgment, identity)`,
`data.transactionReference === portableAdapterAcknowledgmentTransactionReference(ack, identity)`,
and `data.evidenceReference` equal (kind/evidenceType/reference/attesterId) to
`portableAdapterAcknowledgmentEvidence(identity, ack)`.

An outcome requires an admission; if a terminal already exists only `DISPUTED` is accepted;
`FAILED` requires `noEffect` present, `attesterId === "adapter:simulated"`,
`validatePortableAdapterNoEffect(noEffect, identity)` and evidenceReference equal to
`portableAdapterNoEffectEvidence`; any other status requires `noEffect` absent and an
`evidenceReference` that is either `EXTERNAL` or an EVENT/AUTHORITY/RUNTIME_CREDENTIAL/
RECEIPT_COMMITMENT reference that resolves in the prefix. `terminal` is set the first time a
CONFIRMED/FAILED is recorded and never replaced; `latest` is always the newest record.

A `RECEIPT_RECORDED` requires `receiptContentHash` unused, and the `intentId`, `issuerAgentId`,
`runtimeSessionId`, `roleId`, `roleTenureId` to exist (no further congruence is checked by replay).

### F.2 `proposePortableIntentAdmission(input)` — input

Closed record with exactly:
```
operationVersion: "continuity-intent-admission/0.2"
events: Event[]                       — the history (must replay ACCEPTED)
expectedHistoryHead: PortableHistoryHead
admissionEventId: Identifier          — id for the new event
domain: PortableAuthorizationDomain
policyVersion: Identifier
request: { actorId, action, resource, claimedAt, amount?, counterpartyId?, termsCommitment? }
evaluationTime: U53
binding: { runtimeSessionId, controlEpoch, roleId, roleTenureId, credentialKeyId?, intentId?, nonce?, runtimeSignature? }
```
(`binding` is required for INTENT_ADMISSION; no other keys are permitted.)

### F.3 Result union (`PortableIntentAdmissionResult`)

All carry `operationVersion: "continuity-intent-admission/0.2"` and are bounded by
`captureBoundedCanonicalValue` (an over-limit result collapses to INDETERMINATE
OUTPUT_LIMIT_EXCEEDED).

| status | fields |
|---|---|
| `PROPOSED` | `authorization: PortableAuthorizationProof`, `expectedHead`, `admissionEvent`, `prospectiveHead` |
| `RETRY` | `intentId`, `existingAdmissionEventId`, `existingAdmissionHead` |
| `DENIED` | `authorization: <DENY result>` |
| `INDETERMINATE` | `authorization: <INDETERMINATE result>` |
| `CONFLICT` | `expectedHead`, `observedHead` |

Decision order:

1. Capture (`capturePortableAuthorityOperation(input, "INTENT_ADMISSION", kernel.visit)`):
   not a plain record / wrong keys / accessor / limit → INDETERMINATE `INVALID_INPUT`
   (`scopeAssurance:"SUPPLIED_SCOPE"`, `failures:[{code, evidence:[]}]`); `operationVersion`
   wrong → INDETERMINATE `UNSUPPORTED_VERSION`; an event failing schema during incremental
   capture → INDETERMINATE `STATE_NOT_AUTHORITATIVE`.
2. Structural validity (`capturedPortableIntentAdmissionInputIsStructurallyValid`): events is
   an array, domain valid, head valid, `admissionEventId` and `policyVersion` Identifiers,
   request exact shape, binding structurally valid → else INDETERMINATE `INVALID_INPUT`.
3. Replay of `events`: REJECTED with `UNSUPPORTED_VERSION|UNSUPPORTED_EVENT_SCHEMA|
   UNSUPPORTED_EVENT_TYPE` → INDETERMINATE `UNSUPPORTED_VERSION`; other rejection →
   INDETERMINATE `STATE_NOT_AUTHORITATIVE` **[verified]** (history without genesis).
4. `evaluateCapturedPortableIntentAdmissionState(capture, state)`:
   a. `evaluationTime` not U53 or `< state.head.canonicalTime` → INDETERMINATE
      `CAUSAL_TIME_INVALID` with evidence `[ref(head event)]` **[verified]**.
   b. `scopeMatches = sameDomain(domain, genesis.domain) && policyVersion === genesis.policyVersion
      && genesis.rootRecognitionPolicy === "declared-principal-root/0.2"`.
   c. **RETRY check (before the head check):** if `scopeMatches`, the request has no problem
      (`requestProblem` undefined), `binding.intentId` and `binding.nonce` present, a declaration
      exists for `intentId`, and `sameIntent(declaration.data, portableIntentProjection(request,
      binding, declaration.data.adapterProfile))`, and `state.intentAdmissions.has(intentId)` →
      `RETRY {intentId, existingAdmissionEventId, existingAdmissionHead}`. **[verified]** RETRY is
      returned even when `expectedHistoryHead` is stale, provided the supplied `events` already
      contain the admission.
      `portableIntentProjection(request, binding, adapterProfile)` = `{adapterProfile, intentId,
      nonce, actorId, action, resource, roleId, roleTenureId, amount?, counterpartyId?,
      termsCommitment?}`; `sameIntent` compares all scalar fields incl. optional presence but
      **not** `adapterProfile`.
   d. `!sameHead(expectedHistoryHead, state.head)` → `CONFLICT {expectedHead, observedHead}` **[verified]**.
   e. If the declaration exists but does *not* match the projection → DENIED `INTENT_MISMATCH`
      (`REPLAY_VERIFIED`, evidence = intent decision evidence, `subjectId: intentId`) **[verified]**.
   f. `stagePortableStateAuthorization(state, {expectedHistoryHead, domain, policyVersion,
      rootRecognitionPolicy, request, evaluationTime, consequential: true, binding})` → any
      non-`ALLOW_CANDIDATE` result → DENIED / INDETERMINATE accordingly (e.g. DENY
      `SESSION_CREDENTIAL_INVALID` for a bad signature **[verified]**, `INTENT_REQUIRED`,
      `INTENT_NOT_DECLARED`, `INTENT_REPLAY`, `NONCE_ALREADY_ADMITTED`, `ROLE_TENURE_NOT_CURRENT`,
      `STALE_EPOCH`, `SESSION_EXPIRED`, …).
   g. Occupied nonce → DENIED `NONCE_ALREADY_ADMITTED`.
   h. Binding must now have `credentialKeyId, intentId, nonce, runtimeSignature` (guaranteed by
      the ALLOW candidate).
   i. If any existing event has `id === admissionEventId` → INDETERMINATE `INVALID_INPUT`
      (`REPLAY_VERIFIED`, evidence `[colliding event ref, head ref]`, `subjectId: admissionEventId`)
      **[verified]**.
   j. `finalizeSuccessfulAuthorityCandidate` → ALLOW with `proof`.
5. Build the admission event:
   ```
   challenge = createPortableRuntimeAuthorizationChallenge({domain: proof.domain, request: proof.request,
       evaluationTime, policyVersion: proof.policyVersion, historyHead: expectedHead, binding})
   data = { intentId: binding.intentId, evaluationTime, expectedHistoryHead: expectedHead,
            authorizationProof: proof, runtimeAuthorizationHash: hashCanonical(challenge),
            runtimeSignature: binding.runtimeSignature }
   admissionEvent = { id: admissionEventId, type: "TRANSACTION_INTENT_ADMITTED", timestamp: evaluationTime, data }
   ```
   `data` is captured with a 1 MiB event-data bound; the prospective replay input
   `{operationVersion:"continuity-replay/0.2", events:[...events, admissionEvent]}` is captured;
   a capture limit → INDETERMINATE `OUTPUT_LIMIT_EXCEEDED` (`REPLAY_VERIFIED`).
6. Replay the prospective history; not ACCEPTED → INDETERMINATE `STATE_NOT_AUTHORITATIVE`
   (`REPLAY_VERIFIED`).
7. `PROPOSED {authorization: proof, expectedHead, admissionEvent, prospectiveHead: replay.head}`.

The proposal owns no persistence; the SDK (§J) appends the event.

### F.4 Runtime authorization challenge

```
PortableRuntimeAuthorizationChallenge = {
  version: "continuity-runtime-authorization/0.2",
  domain: normalizedDomain, request: normalizedRequest (actorId, action, resource, claimedAt, amount?, counterpartyId?, termsCommitment?),
  authoritative: true, consequential: true,
  evaluationTime, policyVersion, rootRecognitionPolicy: "declared-principal-root/0.2",
  eventHistoryHash: historyHead.hash, eventHistoryPosition: historyHead.position,
  runtimeSessionId, credentialKeyId, controlEpoch, roleId, roleTenureId, intentId, nonce }
```
`createPortableRuntimeAuthorizationChallenge` throws if `credentialKeyId`, `intentId` or
`nonce` is absent. `hashPortableRuntimeAuthorizationChallenge = hashCanonical(challenge)`; the
runtime signs that hash (EIP-191 personal sign). **[verified]** the challenge hash for the
`core02-simulated-r1` admission (head 13, evaluationTime 14) is
`0x29bb9b3681eb91e17829aa05f77b459e9392c6efd48b34310b7c1f64d4133696` and the fixture
signature `0x8587e2…8a151c` verifies against credential address
`0x5935897A39AFABbedA5a599D38236E7Df151C8b8` (public dev key scalar 1001).

### F.5 Bindings and nonces

`PortableConsequentialBinding` fields and what they bind:
* `runtimeSessionId` — a `RUNTIME_SESSION_ADMITTED` record; the proof carries it.
* `credentialKeyId` — must equal the session's `credentialKeyId` (else DENY
  `SESSION_CREDENTIAL_INVALID`; absent → `SESSION_CREDENTIAL_REQUIRED`).
* `controlEpoch` — must equal both the session's and the agent's current epoch (else
  `STALE_EPOCH`/`SESSION_FENCED`).
* `roleId`, `roleTenureId` — the tenure must be the role's current tenure, open, for this agent
  (else `ROLE_TENURE_NOT_CURRENT`).
* `intentId`, `nonce` — required for admission (`INTENT_REQUIRED`); the declaration must exist
  (`INTENT_NOT_DECLARED`) and match (`INTENT_MISMATCH`); the intent must not be admitted
  (`INTENT_REPLAY`); the `(actorId, nonce)` pair must not be reserved (`NONCE_ALREADY_ADMITTED`).
* `runtimeSignature` — EIP-191 signature by the session credential over the challenge hash.

Exactly-once: replay admits an intent at most once and reserves `(actorId, nonce)` for ever
(a terminal FAILED outcome does **not** release the nonce). The proposal returns `RETRY` for a
repeated request instead of re-proposing; the SDK converts that into a read-only
reconciliation. Consumption happens at most once per intent and is refused after any terminal
outcome.

### F.6 Control currency (`portableAdmissionControlIsCurrent(state, intentId, useTime)`)

True iff the admission exists and, with `agent = agents.get(admission.actorId)`, `session =
runtimeSessions.get(admission.runtimeSessionId)`, `role = roles.get(admission.roleId)`,
`tenure = tenures.get(admission.roleTenureId)`: agent exists and not terminated; session
exists with `agentId === actorId`, `credentialKeyId === admission.credentialKeyId`,
`(expiresAt === undefined || useTime < expiresAt)`, `controlEpoch === admission.controlEpoch`;
`agent.currentControlEpoch === admission.controlEpoch`; role and tenure exist,
`role.currentTenureId === admission.roleTenureId`, `!tenure.closed`, `tenure.roleId ===
roleId`, `tenure.agentId === actorId`. The same predicate gates consumption at replay.

### F.7 Adapter identity

```
derivePortableAdapterIdempotencyKey(domain, intentId) =
  hashCanonical(["continuity-adapter-idempotency/0.2", domain.protocol, domain.version,
                 domain.deploymentId, domain.chainId, lowercase(domain.verifyingContract), intentId])
submissionFingerprint = hashCanonical({ version: "continuity-adapter-submission/0.2", intentId,
                 admissionEvent (the whole accepted event), durableEventHistoryHash: admissionHead.hash })
derivePortableAdapterNoEffectReference(key, fingerprint) =
  hashCanonical(["continuity-adapter-no-effect/0.2", "adapter:simulated", key, fingerprint])
PortableAdapterIdentity = { idempotencyKey, submissionFingerprint, durableEventHistoryHash: admissionHead.hash,
  adapterNoEffectReference, adapterProfile (the policy's frozen profile record), domain (proof.domain),
  intentId, admissionHead }
```
**[verified]** both derivations reproduce the fixture identity.

`derivePortableAdapterIdentity(input)` (public, `PortableAdapterIdentityInput`): input must be a
closed record with exactly `{operationVersion: "continuity-adapter-submission/0.2", domain,
intentId (Identifier), admissionEvent, admittedHistory}`; `admittedHistory` must replay
ACCEPTED (else `TypeError`), the admission for `intentId` must exist **and be the last event**
(`admissionEventPosition === head.position`, else `TypeError("Adapter identity requires the
exact admission-inclusive prefix.")` **[verified]**); `admissionEvent` must be a valid event
canonically equal to the stored one; `domain` must be a closed 5-key record canonically equal
to `admissionEvent.data.authorizationProof.domain`. Returns
`{operationVersion: "continuity-adapter-submission/0.2", ...admission.adapterIdentity}`.

### F.8 `inspectPortableAdmittedIntent(events, intentId, useTime)`

Throws `TypeError` if `intentId` is not an Identifier, `useTime` not U53, the history cannot
be captured/replayed, or `useTime < head.canonicalTime` **[verified]**. Returns
`{status:"ABSENT", head}` when no admission; otherwise
```
{ status:"ADMITTED", head, admissionEvent (the stored event), admissionHead, adapterIdentity,
  currentControl: portableAdmissionControlIsCurrent(state, intentId, useTime),
  consumption? (record), terminal? (outcome record), latestOutcome? (outcome record) }
```
(`terminal` present only if a CONFIRMED/FAILED exists; `latestOutcome` present iff any outcome).

---

## G. Receipts (`continuity-receipt/0.2`)

### G.1 Artifact and payload

```
PortableReceiptArtifact = { payload: PortableReceiptPayload, contentHash: ContentHash, signature: Signature65 }
PortableReceiptPayload = {
  schemaVersion: "continuity-receipt/0.2", signatureScheme: "eip191-personal-sign-keccak256",
  domain: PortableAuthorizationDomain,
  issuer: { keyId, agentId, runtimeSessionId, controlEpoch: U53, roleId, roleTenureId },
  intent: PortableTransactionIntent (the declaration data verbatim, incl. adapterProfile),
  authorization: { authorizationTime: U53, policyVersion, rootRecognitionPolicy: "declared-principal-root/0.2",
                   historyHead, proof: PortableAuthorizationProof },
  issuance: { historyHead, issuedAt: U53 },
  result: { status: "SUBMITTED", consumptionEventId, adapterId, idempotencyKey, submissionFingerprint,
            transactionReference: Identifier, acknowledgment: PortableAdapterAcknowledgment },
  assurance: { finality: "LOCAL_ONLY", freshness: "CURRENT_AT_ISSUANCE", externalOutcome: "NOT_PROVEN"|"SIMULATED" } }
```
All records are closed (exact key sets). `contentHash = hashCanonical(payload)`. `signature`
is the issuer credential's EIP-191 signature over `contentHash`.

### G.2 `createPortableReceipt(input, signer)` (async)

`input = { events, intentId, issuedAt, externalOutcome }` (exact keys; `intentId` string,
`issuedAt` U53, `externalOutcome ∈ NOT_PROVEN|SIMULATED`), `signer = { keyId, signHash(hash) →
Promise<Signature65> }`. Throws `TypeError` with these messages (in order of checks):

1. `"Malformed local receipt creation input."`
2. `"Receipt issuance requires a causally valid accepted prefix."` — events not ACCEPTED or
   `issuedAt < head.canonicalTime` **[verified]**.
3. `"Receipt issuance requires exact admitted and consumed intent evidence."` — admission,
   consumption or declaration missing.
4. `"Receipt assurance must match the admitted adapter profile."` — `externalOutcome !==
   assuranceFor(consumption.adapterId)` where `assuranceFor("adapter:simulated") = "SIMULATED"`,
   `assuranceFor(remote-service-report | local-evidence-packet | local-document-release |
   local-synthetic-endpoint-state) = "NOT_PROVEN"`, otherwise undefined. **[verified]** checked
   before the signer is invoked.
5. Payload built as in G.1 from: `proof = admissionEvent.data.authorizationProof`;
   `issuer = {keyId: admission.credentialKeyId, agentId: admission.actorId, runtimeSessionId,
   controlEpoch, roleId, roleTenureId}` (all from the admission record); `intent =
   declaration.data`; `authorization = {authorizationTime: proof.evaluationTime, policyVersion:
   proof.policyVersion, rootRecognitionPolicy: proof.rootRecognitionPolicy, historyHead:
   proof.historyHead, proof}`; `issuance = {historyHead: state.head, issuedAt}`; `result =
   {status:"SUBMITTED", consumptionEventId: consumption.eventId, adapterId, idempotencyKey,
   submissionFingerprint, transactionReference, acknowledgment}` from the consumption record;
   `assurance = {finality:"LOCAL_ONLY", freshness:"CURRENT_AT_ISSUANCE", externalOutcome}`.
6. `"Receipt signer or issuance authority is not current."` — `!currentControl(state, payload,
   issuedAt)` (G.4) or `!evaluatePortableReceiptPolicy(state, proof, issuedAt).live` or
   `signer.keyId !== admission.credentialKeyId` **[verified]** or `signHash` not a function.
7. `contentHash = hashCanonical(payload)`; `signature = await signer.signHash(contentHash)`.
8. Self-verification: `verifyPortableReceipt({artifact, issuanceEvents: state.events,
   observedEvents: state.events, expectedDomain: proof.domain, verifierTime: issuedAt})` must be
   EVALUATED with `historical === true`, else `"Signer did not return a valid historically
   authorized receipt artifact."` (a wrong-key signature ends here).
9. Returns the frozen artifact.

Note that `createPortableReceipt` takes the *whole* current history as `events`; the receipt's
`issuance.historyHead` is that history's head (position `p`). Recording the receipt then
appends `RECEIPT_RECORDED` at position `p+1`.

### G.3 `verifyPortableReceipt(input)`

Input (closed record, exactly 6 keys): `{operationVersion: "continuity-receipt-verification/0.2",
artifact, issuanceEvents, observedEvents, expectedDomain, verifierTime}`.

INDETERMINATE results `{operationVersion, status:"INDETERMINATE", code, limitations:
PORTABLE_RECEIPT_LIMITATIONS}` with `PORTABLE_RECEIPT_LIMITATIONS =
["NO_CANONICAL_ISSUANCE_WITNESS", "NO_PUBLIC_FINALITY_PROOF", "NO_EXTERNAL_OUTCOME_PROOF"]`:

| code | when |
|---|---|
| `UNSUPPORTED_RECEIPT_VERSION` | `operationVersion` wrong **[verified]**, or payload `schemaVersion`/`signatureScheme` present but not the supported pair |
| `INVALID_INPUT` | outer record wrong (extra/missing keys, accessor, limit), `expectedDomain` invalid, `verifierTime` not U53, history not a dense list, named-limit breach in a history, or a limit breach inside the artifact payload |
| `MALFORMED_ARTIFACT` | artifact fails closed-shape validation (missing signature, non-record payload, bad hash spelling, …) **[verified]** |
| `UNSUPPORTED_VERSION` | either history's *first event* replays to `UNSUPPORTED_VERSION`/`UNSUPPORTED_EVENT_SCHEMA` (foreign genesis) **[verified]** |
| `STATE_NOT_AUTHORITATIVE` | the issuance prefix `issuance.slice(0, min(p+1, len))` or the full observed history fails replay (incl. empty issuance **[verified]**), or `issuance[p+1]` exists but is not a core event type |
| `OUTPUT_LIMIT_EXCEEDED` | total planned evidence across the four axes > 4096, or the result exceeds capture bounds |

Capture ordering: `operationVersion` → `expectedDomain` → `verifierTime` → `issuanceEvents`
→ `observedEvents` → history limit preflight → `artifact`. A structural failure *during the
artifact phase* yields `MALFORMED_ARTIFACT`; before it, `INVALID_INPUT`.

Evaluation (all names refer to the payload `P`, `p = P.issuance.historyHead.position`):

* `old` = replay of `issuance.slice(0, min(p+1, issuance.length))`; `current` = replay of
  `observed`.
* `related` = `(issuance.length === p+1 || issuance.length === p+2) && p < issuance.length &&
  sameHead(P.issuance.historyHead, old.head)` — the issuance history must be exactly the signed
  prefix, optionally plus one candidate record event.
* `divergentPosition` = first `i < min(p+1, issuance.length)` where `observed[i]` is missing or
  `canonicalEncode(issuance[i]) !== canonicalEncode(observed[i])`; if none and both histories
  have an event at `p+1` that differ, `divergentPosition = p+1`. `divergent = divergentPosition ≥ 0`.
* `domainMismatch` = `!same(P.domain, P.authorization.proof.domain) || !domainEqual(P.domain,
  expectedDomain) || !domainEqual(P.domain, old.genesis.domain) || !domainEqual(P.domain,
  current.genesis.domain) || !domainEqual(P.authorization.proof.domain, expectedDomain)`.
* `integrity = hashCanonical(P) === artifact.contentHash`.
* `recovered = recoverPortableContentHashSigner(artifact.contentHash, artifact.signature)`.
* `session = old.runtimeSessions.get(P.issuer.runtimeSessionId)`; `credentialMissing = !session`;
  `issuerMatches = recovered && session && session.agentId === P.issuer.agentId &&
  session.credentialKeyId === P.issuer.keyId && session.credentialAddressKey === recovered`.
  **This is the check that needs the history prefix**: the signer address is compared with the
  session admitted in the *issuance prefix* (`old`), not with anything inside the artifact.
* `fieldsMatch = intrinsicFieldsMatch(P) && (!related || canonicalFieldsMatch(old, P))`:
  * intrinsic: `P.intent` canonically equals the projection `{intentId: proof.intentId, nonce:
    proof.nonce, actorId, action, resource: request…, roleId, roleTenureId: proof…, adapterProfile:
    ack.adapterProfile, amount?/counterpartyId?/termsCommitment? from request}`; `ack.domain ==
    P.domain`; `ack.intentId === P.intent.intentId`; `ack.adapterProfile.profileId ===
    P.result.adapterId`; `assuranceFor(P.result.adapterId)` defined and equal to
    `P.assurance.externalOutcome`; `authorizationTime === proof.evaluationTime`; policyVersion,
    rootRecognitionPolicy, historyHead equal proof's; `issuer.agentId === request.actorId`;
    `issuer.keyId/runtimeSessionId/controlEpoch/roleId/roleTenureId` equal the proof's.
  * canonical (only when related): if a declaration exists in `old` it must canonically equal
    `P.intent`; if the session exists its agentId/credentialKeyId/controlEpoch must match the
    issuer; if the tenure exists its agentId/roleId must match the issuer.
* `submission = !related || submissionMatches(old, P)` — the consumption in `old` must exist
  with equal `eventId, adapterId, idempotencyKey, submissionFingerprint, transactionReference`
  and canonically equal `acknowledgment`.
* `proofMissing = related && (no declaration in old || no admission in old)`.
* `admittedProofMatches = boundProof(old, P)` — the admission's stored `authorizationProof`
  canonically equals `P.authorization.proof`.
* `oldPolicy = evaluatePortableReceiptPolicy(old, proof, P.issuance.issuedAt)`; `newPolicy =
  evaluatePortableReceiptPolicy(current, proof, verifierTime)` (§G.5).
* `historicalLive = related && issuedAt >= old.head.canonicalTime && admittedProofMatches &&
  currentControl(old, P, issuedAt) && oldPolicy.live`.
* `newLive = currentControl(current, P, verifierTime) && newPolicy.live`.
* `occupant = observed[p+1]`; `recordMatches = occupant && occupant.type === "RECEIPT_RECORDED"
  && occupant.timestamp === issuedAt && same(occupant.data, receiptRecordDataForArtifact(artifact))`.

Evidence plans (positions into a source; `bindHead(source, items)` = items ∪ the source's last
event):
* `oldSource` = old.events/hashes; `currentSource` = current.events/hashes; `issuanceSource` =
  `oldSource` if `issuance.length === old.events.length` else the raw issuance list with freshly
  computed prefix hashes.
* `domainPlans = union(plan(issuanceSource,0), plan(currentSource,0))`.
* `controlEvidence(source, state, issuer, time)`: AGENT_CREATED of issuer.agentId,
  RUNTIME_SESSION_ADMITTED of the session, ROLE_CREATED of the role, AGENT_APPOINTED/
  ROLE_TRANSFERRED(to) opening the tenure; plus `latestEpoch` (last of AGENT_CREATED or
  CONTROL_EPOCH_ADVANCED for the agent) and `firstFailure` (first of AGENT_TERMINATED for the
  agent, CONTROL_EPOCH_ADVANCED with `toEpoch > issuer.controlEpoch`, AGENT_UNAPPOINTED of the
  tenure, ROLE_TRANSFERRED from the tenure); plus the session admission if the session has
  expired at `time`; then `bindHead`.
* `authorityEvidence(source, state, proof, policy)`: grant events named in
  `proof.authorityEvidence` (only if the stored record agrees on grantEventId/position); grant
  (+ revocation for PROHIBITIONs) of every id in `proof.checkedProhibitionIds ∪
  policy.checkedProhibitionIds`; grant (+ revocation) of `policy.decisiveAuthorityIds`; the
  AGENT_TERMINATED of each `policy.decisiveAgentIds`; `bindHead`.
* `intentEvidence(source, intentId)`: every DECLARED/ADMITTED/CONSUMED for the intent; `bindHead`.
* `relationshipPlans = union(occupant ? plan(currentSource, p+1) : plan(oldSource, last),
  divergent ? plan(issuanceSource, divergentPosition) : [], divergent ? plan(currentSource, divergentPosition) : [])`.
* `issuerPlans = domainMismatch ? domainPlans : union(domainPlans, controlEvidence(oldSource, old, issuer, issuedAt))`
* `historicalPlans = domainMismatch ? domainPlans : union(issuerPlans, authorityEvidence(oldSource, old, proof, oldPolicy), intentEvidence(oldSource, intentId))`
* `inclusionPlans = domainMismatch ? domainPlans : relationshipPlans`
* `freshnessPlans = domainMismatch ? domainPlans : union(relationshipPlans, controlEvidence(currentSource, current, issuer, verifierTime), authorityEvidence(currentSource, current, proof, newPolicy))`
* if the four plan lengths sum to > 4096 → INDETERMINATE `OUTPUT_LIMIT_EXCEEDED`.
Plans are deduplicated by `[eventId, eventType, position, historyHash]` and materialised as
EVENT references sorted by that tuple.

Axes: `axis(status, primaryCode, evidence, future=false) = {status, primaryCode, causes:
future ? [primaryCode, "FUTURE_ISSUANCE"] : [primaryCode], evidence}`. Statuses:
`PASS|FAIL|UNAVAILABLE|UNVERIFIED`.

```
contentIntegrity     = integrity ? PASS/CONTENT_HASH_MATCH : FAIL/CONTENT_HASH_MISMATCH   (evidence [])
signaturePossession  = recovered ? PASS/SIGNATURE_VALID : FAIL/SIGNATURE_INVALID          (evidence [])
issuerAuthentication = domainMismatch ? FAIL/DOMAIN_MISMATCH
                     : !related ? UNVERIFIED/ISSUANCE_HISTORY_UNVERIFIED
                     : credentialMissing ? UNVERIFIED/DEPENDENCY_UNAVAILABLE
                     : !issuerMatches ? FAIL/ISSUER_NOT_AUTHENTICATED
                     : PASS/ISSUER_AUTHENTICATED                                          (issuerPlans)
historicalAuthorization = domainMismatch ? FAIL/DOMAIN_MISMATCH
                     : !fieldsMatch ? FAIL/RECEIPT_FIELDS_MISMATCH
                     : !submission ? FAIL/SUBMISSION_EVIDENCE_MISSING
                     : !integrity ? FAIL/DEPENDENCY_FAILED
                     : related && !proofMissing && (!admittedProofMatches || ((!historicalLive || issuerAxis.status === "FAIL") && !credentialMissing))
                         ? FAIL/HISTORICAL_AUTHORIZATION_INVALID
                     : !related ? UNVERIFIED/ISSUANCE_HISTORY_UNVERIFIED
                     : proofMissing || credentialMissing ? UNVERIFIED/DEPENDENCY_UNAVAILABLE
                     : PASS/HISTORICAL_AUTHORIZATION_VALID                                (historicalPlans)
canonicalInclusion   = domainMismatch ? FAIL/DOMAIN_MISMATCH
                     : divergent ? UNVERIFIED/OBSERVED_HISTORY_DIVERGES
                     : !related ? UNVERIFIED/ISSUANCE_HISTORY_UNVERIFIED
                     : occupant && !recordMatches ? FAIL/RECORDED_POSITION_MISMATCH
                     : !occupant ? UNAVAILABLE/RECORD_NOT_AVAILABLE
                     : PASS/RECORDED_HASH_MATCH                                           (inclusionPlans)
finality             = PASS/LOCAL_ONLY (evidence [])
freshness            = domainMismatch ? UNVERIFIED/DOMAIN_MISMATCH
                     : divergent ? UNVERIFIED/OBSERVED_HISTORY_DIVERGES
                     : !related ? UNVERIFIED/ISSUANCE_HISTORY_UNVERIFIED
                     : verifierTime < current.head.canonicalTime ? UNVERIFIED/VERIFIER_TIME_BEHIND_OBSERVED_HEAD (+FUTURE_ISSUANCE cause iff issuedAt > verifierTime)
                     : issuedAt > verifierTime ? FAIL/FUTURE_ISSUANCE
                     : !newLive ? FAIL/STALE : PASS/CURRENT                               (freshnessPlans)
externalOutcome      = UNVERIFIED / (P.assurance.externalOutcome === "SIMULATED" ? SIMULATED : NOT_PROVEN) (evidence [])
authentic  = integrity && recovered !== undefined && issuerAuthentication.status === "PASS"
historical = authentic && historicalAuthorization.status === "PASS"
valid      = historical
current    = historical && canonicalInclusion.status === "PASS" && freshness.status === "PASS"
limitations = canonicalInclusion.status === "PASS" ? ["NO_PUBLIC_FINALITY_PROOF","NO_EXTERNAL_OUTCOME_PROOF"] : all three
```
Result `{operationVersion, status:"EVALUATED", contentIntegrity, signaturePossession,
issuerAuthentication, historicalAuthorization, canonicalInclusion, finality, freshness,
externalOutcome, authentic, historical, valid, current, limitations}`; an over-limit result →
INDETERMINATE `OUTPUT_LIMIT_EXCEEDED`.

**Verified matrix** (fixture `core02-simulated-r1`, receipt issued at 16 over the 16-event
prefix, recorded at position 16; notation `status/code [evidence positions]`):

| case | issuer | historical | inclusion | freshness | authentic/historical/valid/current |
|---|---|---|---|---|---|
| issuance=prefix17, observed=full26, time 25 | PASS [2,6,0,4,7,15] | PASS [2,14,6,8,13,0,4,7,15] | PASS/RECORDED_HASH_MATCH [16] | FAIL/STALE [16,2,6,8,19,25,4,7,20] | T/T/T/F |
| issuance=prefix16, observed=prefix16, time 25 | PASS | PASS | UNAVAILABLE/RECORD_NOT_AVAILABLE [15] | PASS/CURRENT [2,6,8,4,7,15] | T/T/T/F (limitations: all three) |
| issuance=prefix15 (too short) | UNVERIFIED/ISSUANCE_HISTORY_UNVERIFIED | UNVERIFIED/ISSUANCE_HISTORY_UNVERIFIED | UNVERIFIED/… | UNVERIFIED/… | F/F/F/F |
| issuance=prefix18 (too long) | same as above | | | | |
| observed=prefix17, time 16 | PASS | PASS | PASS | PASS/CURRENT [16,2,6,8,4,7] | T/T/T/**T** |
| time 10 (< observed head) | PASS | PASS | PASS | UNVERIFIED/VERIFIER_TIME_BEHIND_OBSERVED_HEAD +FUTURE_ISSUANCE | T/T/T/F |
| expectedDomain.deploymentId changed | FAIL/DOMAIN_MISMATCH [0] | FAIL/DOMAIN_MISMATCH [0] | FAIL/DOMAIN_MISMATCH [0] | UNVERIFIED/DOMAIN_MISMATCH [0] | F/F/F/F |
| payload.issuance.issuedAt changed (hash stale) | PASS | FAIL/DEPENDENCY_FAILED | FAIL/RECORDED_POSITION_MISMATCH | FAIL/STALE | F/F/F/F (contentIntegrity FAIL) |
| signature garbage | FAIL/ISSUER_NOT_AUTHENTICATED | FAIL/HISTORICAL_AUTHORIZATION_INVALID | FAIL/RECORDED_POSITION_MISMATCH | FAIL/STALE | F/F/F/F (signaturePossession FAIL) |
| issuer.keyId changed + rehash | FAIL/ISSUER_NOT_AUTHENTICATED | FAIL/RECEIPT_FIELDS_MISMATCH | FAIL/RECORDED_POSITION_MISMATCH | FAIL/STALE | F/F/F/F |
| observed forks at p+1 (other event) | PASS | PASS | UNVERIFIED/OBSERVED_HISTORY_DIVERGES [16,16] | UNVERIFIED/OBSERVED_HISTORY_DIVERGES | T/T/T/F |
| issuance=prefix16, observed=other event at 16 | PASS | PASS | FAIL/RECORDED_POSITION_MISMATCH [16] | PASS/CURRENT | T/T/T/F |
| observed = 10 events (shorter than prefix) | PASS | PASS | UNVERIFIED/OBSERVED_HISTORY_DIVERGES [10,15] | UNVERIFIED/OBSERVED_HISTORY_DIVERGES | T/T/T/F |

Evidence lists inside axes are sorted by eventId string (hence `[2,14,6,8,13,0,4,7,15]`).

### G.4 `currentControl(state, P, time)` (receipt variant)

`agent` exists, not terminated, `agent.currentControlEpoch === issuer.controlEpoch`; session
exists with matching agentId/credentialKeyId/controlEpoch and `(expiresAt === undefined ||
time < expiresAt)`; role exists with `currentTenureId === issuer.roleTenureId`; tenure exists,
open, matching roleId/agentId; `proof.request.actorId === issuer.agentId`;
`state.genesis.policyVersion === P.authorization.policyVersion`;
`state.genesis.rootRecognitionPolicy === P.authorization.rootRecognitionPolicy`.

### G.5 `evaluatePortableReceiptPolicy(state, proof, time)` (summary)

Returns `{live, checkedProhibitionIds, decisiveAuthorityIds, decisiveAgentIds}` (ids sorted).
`live` is true iff `time` is U53 and ≥ `state.head.canonicalTime`, the proof's domain/policy
version/root policy match the genesis, the proof's terminal permission still exists, is
effectively independent and granted to `proof.request.actorId`, the proof's recognized root,
permission path (compared after normalization), intersections and effective constraints are
byte-identical to the current state's candidate graph for that terminal, no relevant global
prohibition is active, and the candidate evaluation (activity, expiry, revocation, action/resource,
amounts, delegation) succeeds. Decisive ids collect every authority/agent whose state caused a
failure; `checkedProhibitionIds` collects relevant candidate and global prohibitions regardless of
activity.

### G.6 Record data and commitment

```
receiptRecordDataForArtifact(artifact) = {
  receiptContentHash: artifact.contentHash,
  receiptArtifactCommitment: hashCanonical(["continuity-receipt-artifact-commitment/0.2", artifact.contentHash, artifact.signature]),
  intentId: P.intent.intentId, issuerAgentId: P.issuer.agentId, runtimeSessionId: P.issuer.runtimeSessionId,
  controlEpoch: P.issuer.controlEpoch, roleId: P.issuer.roleId, roleTenureId: P.issuer.roleTenureId,
  authorizationProofHash: hashCanonical(P.authorization.proof) }
```
`portableReceiptArtifactCommitment(artifact)`: captures and validates the artifact shape (any
status other than VALID → `TypeError("Invalid portable receipt artifact: <status>.")`) and
returns the commitment hash. **[verified]** equals the fixture's recorded
`receiptArtifactCommitment` (`0x774f22…fe663`).

### G.7 `proposePortableReceiptRecord(input)`

Input (closed, 6 keys): `{operationVersion: "continuity-receipt-record-admission/0.2",
artifact, events, expectedHistoryHead, expectedDomain, recordEventId}`.

Results (`PortableReceiptRecordProposal`):
* `INDETERMINATE {operationVersion, status, code ∈ INVALID_INPUT|UNSUPPORTED_VERSION|
  STATE_NOT_AUTHORITATIVE|OUTPUT_LIMIT_EXCEEDED, verification?}` — `verification` (the inner
  INDETERMINATE verification) is attached only when it came from `verifyPortableReceipt`;
  codes map `MALFORMED_ARTIFACT → INVALID_INPUT`, `UNSUPPORTED_RECEIPT_VERSION →
  UNSUPPORTED_VERSION`, others unchanged.
* `CONFLICT {expectedHead, observedHead}` when `!sameHead(replay(events).head, expectedHistoryHead)` **[verified]**.
* `REJECTED {verification}` when the prospective verification is EVALUATED but not `current`.
* `PROPOSED {expectedHead, recordEvent, newHead, verification}` **[verified]**.

Steps: capture (wrong version → UNSUPPORTED_VERSION; else INVALID_INPUT); replay `events`
(foreign genesis → UNSUPPORTED_VERSION; rejected → STATE_NOT_AUTHORITATIVE); head check →
CONFLICT; `recordEventId` already used by an event → INVALID_INPUT **[verified]**; artifact
shape (UNSUPPORTED → UNSUPPORTED_VERSION, else INVALID_INPUT); `events.length >= 4096 ||
(events.length+1)*2 > 4096` → OUTPUT_LIMIT_EXCEEDED (i.e. at most 2047 existing events);
`recordEvent = {id: recordEventId, type:"RECEIPT_RECORDED", timestamp: P.issuance.issuedAt,
data: receiptRecordDataForArtifact(artifact)}`; `prospective = [...events, recordEvent]`;
bound-capture the record event, the prospective list and the replay input (limit →
OUTPUT_LIMIT_EXCEEDED; the event failing schema → INVALID_INPUT); build the verification
input `{artifact, issuanceEvents: prospective, observedEvents: prospective, expectedDomain,
verifierTime: issuedAt}` and pre-capture it (limit → OUTPUT_LIMIT_EXCEEDED, other capture
failure → INVALID_INPUT); run `verifyPortableReceipt` → INDETERMINATE mapped as above;
`!verification.current` → REJECTED; replay `prospective` (not ACCEPTED →
STATE_NOT_AUTHORITATIVE — e.g. the receipt hash already recorded **[verified]**); bound the
would-be ADMITTED wrapper and the PROPOSED result (limit → OUTPUT_LIMIT_EXCEEDED); return
PROPOSED with `newHead = replay(prospective).head`.

Note the record's `timestamp` is `issuedAt`, so `issuedAt` must be ≥ the current head time for
replay to accept; verification at `verifierTime = issuedAt` over the prospective history makes
`current` require `freshness PASS` and `canonicalInclusion PASS` (record at `p+1` matches).

---

## H. Adapter editions E1–E6 (`portable-adapter-engine.ts`)

### H.1 Adapter ids and descriptors

```
SIMULATED_ADAPTER_ID                      = "adapter:simulated"
LOCAL_EVIDENCE_PACKET_ADAPTER_ID          = "adapter:local-evidence-packet"
LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID = "adapter:local-synthetic-endpoint-state"
LOCAL_DOCUMENT_RELEASE_ADAPTER_ID         = "adapter:local-document-release"
REMOTE_SERVICE_REPORT_ADAPTER_ID          = "adapter:remote-service-report"
MAX_PORTABLE_ADAPTER_EVIDENCE_BYTES       = 4096
```

Descriptors (frozen records; `descriptorHash = hashCanonical(descriptor)`):

| profileId | acknowledgmentSchemaVersion | replayRuleId | descriptorHash |
|---|---|---|---|
| adapter:local-evidence-packet | continuity-adapter-acknowledgment/0.2 | continuity-adapter-replay/local-packet/1 | `0xd4b988c1f23603cf35d9abd0db5a7eb56ef7a5fba1a8f3e904490c1ce4458d64` |
| adapter:simulated | continuity-adapter-acknowledgment/0.2 | continuity-adapter-replay/simulated/1 | `0xa9f3354121fdbc4d983093e34684d5ddc841874f8fccadbafe30df65f2e16ac2` |
| adapter:local-synthetic-endpoint-state | continuity-local-endpoint-state-ack/1 | continuity-adapter-replay/local-endpoint-state/1 | `0x486bad2029389663117b06785e641f3a6ec2a90ca89b60e95267965ddc5977ed` |
| adapter:local-document-release | continuity-local-document-release-ack/1 | continuity-adapter-replay/local-document-release/1 | `0x9749dc03bd4db3c4a1f8eba707fa5ab49ea02f0a948b22697a3b7152a01393bc` |
| adapter:remote-service-report | continuity-remote-service-report-ack/1 | continuity-adapter-replay/remote-service-report/1 | `0xa86975f20bd2cac74ab19ccfed948a18c8c85c05407ca925dc685ac4b5d460c0` |

Each descriptor is `{profileId, profileVersion:"1", acknowledgmentSchemaVersion, replayRuleId}`.
A `PortableAdapterProfile` is `{profileId, profileVersion:"1", descriptorHash}`.

### H.2 Policy editions **[verified hashes]**

`policyHash = hashCanonical({schemaVersion:"continuity-adapter-policy/0.2", profiles: <descriptor list in order>, ...})`:

| edition | descriptor order | extra field | hash |
|---|---|---|---|
| E1 (`PORTABLE_ADAPTER_POLICY_HASH`) | packet, simulated | — | `0x00c3498e2744943663475d0187ca979cdd09763b88427781883693c4b8c163a7` |
| E2 | packet, endpoint-state, simulated | — | `0x22eb40a92e50c998e007f67f0af0bc584e25f4b21c9bd802cbebe5981828810e` |
| E3 | document-release, packet, endpoint-state, simulated | — | `0xda1ac0f7af67e35a2acd3e213089bafd65204e4bb50e6a0823f8e7e941168666` |
| E4 | document-release, packet, endpoint-state, remote-service-report, simulated | — | `0xe332eb30cd57a0106582649f124d33d17272096cd42b96d9155b53594a3894a5` |
| E5 | same as E4 | `semanticExtension: "continuity-attempt-observation-duty/1"` | `0x32c2a5608c7110f1a291517e136cedf62d59a2cb81be1141dd2705bce307ab29` |
| E6 | same as E4 | `semanticExtensions: ["continuity-attempt-observation-duty/1", "continuity-attempt-duty-review/1"]` | `0xa90baac702f22f5a5f71141318a7651c1d963bbbee28138bbea835d942d0114c` |

`resolvePortableAdapterPolicy(hash)` → `ImmutablePolicy {edition, hash, profiles (frozen
profile records in the descriptor order), semanticExtension? (E5), semanticExtensions? (E6)}`
or `undefined` for anything else (no default). Genesis `adapterPolicyHash` must resolve or the
genesis event is rejected (`EVENT_DATA_INVALID`).

What each edition permits:
* Profiles declarable in `TRANSACTION_INTENT_DECLARED.data.adapterProfile` = the edition's
  profile set (`validatePortableAdapterProfileForPolicy`). A profile outside the edition →
  replay `TRANSITION_INVALID`.
* E5 additionally accepts `OUTCOME_OBSERVATION_RECORDED`, `ATTEMPT_DUTY_CREATED`,
  `ATTEMPT_DUTY_ASSIGNED` (only for intents declared with `adapter:remote-service-report`), and
  SURVIVES answers gain `outcomeObservations`/`attemptDuties`.
* E6 additionally accepts `ATTEMPT_DUTY_REVIEW_CLOSED`, and attempt-duty projections gain
  `reviewStatus`/`reviews`.
* `approvedPortableAdapterProfileForPolicy(hash, profileId)` returns the edition's frozen
  profile record or throws; `approvedPortableAdapterProfile(profileId)` (E1-only helper)
  accepts only packet and simulated; `knownPortableAdapterProfile(profileId)` accepts all five
  (configuration only — never authority).
* `knownPortableAdapterAcknowledgmentVersion(profile)`: packet/simulated →
  `continuity-adapter-acknowledgment/0.2`; document-release → `…document-release-ack/1`;
  endpoint-state → `…endpoint-state-ack/1`; remote-service-report → `…remote-service-report-ack/1`.

### H.3 Adapter input capture

Every adapter-engine function first snapshots its input (`snapshot` + `capture`): plain
records/scalars only (no arrays!, no proxies, no accessors, no non-enumerable keys, ≤ 256 keys,
depth ≤ 16, ≤ 4096 "units" where each node and each UTF-8 byte of strings/keys counts), then
canonical-captures it with `maxCanonicalBytes = 4096`, and refuses any record that had an
`undefined`-valued key. Validators return `false` on any exception; constructors throw
`HostTypeError`.

### H.4 Identity snapshot (`identitySnapshot`)

An identity is valid iff it is a closed record with keys `idempotencyKey, submissionFingerprint,
durableEventHistoryHash, adapterNoEffectReference, adapterProfile, domain, intentId,
admissionHead` (plus `operationVersion` allowed only if equal to
`continuity-adapter-submission/0.2`), `adapterProfile` a known profile tuple, `domain` valid,
`intentId` an Identifier, `admissionHead` `{hash: ContentHash, position: U53, canonicalTime:
U53}`, `submissionFingerprint` a ContentHash, `durableEventHistoryHash === admissionHead.hash`,
`idempotencyKey === derivePortableAdapterIdempotencyKey(domain, intentId)`, and
`adapterNoEffectReference === derivePortableAdapterNoEffectReference(idempotencyKey, submissionFingerprint)`.

`evidenceIdentity(i) = {adapterProfile, domain, intentId, admissionHead, idempotencyKey, submissionFingerprint}`.

### H.5 Acknowledgment and no-effect shapes

All acknowledgments are `{schemaVersion, kind:"ACKNOWLEDGMENT", ...evidenceIdentity, result}`:

| profile | schemaVersion | result |
|---|---|---|
| simulated | continuity-adapter-acknowledgment/0.2 | `{kind:"SIMULATED_SUBMISSION", submissionReference: submissionFingerprint}` |
| local-evidence-packet | continuity-adapter-acknowledgment/0.2 | `{kind:"LOCAL_PACKET_CREATED", manifestDigest:{algorithm:"sha256", value: <0x+64hex>}}` |
| local-synthetic-endpoint-state | continuity-local-endpoint-state-ack/1 | `{kind:"LOCAL_ENDPOINT_STATE_CHANGED", transitionDigest:{algorithm:"keccak256", value}}` |
| local-document-release | continuity-local-document-release-ack/1 | `{kind:"LOCAL_DOCUMENT_RELEASED", publicationManifestDigest:{algorithm:"sha256", value}}` |
| remote-service-report | continuity-remote-service-report-ack/1 | `{kind:"REMOTE_SERVICE_REPORTED", reportDigest:{algorithm:"sha256", value}}` |

No-effect (simulated only): `{schemaVersion:"continuity-adapter-no-effect/0.2",
kind:"NO_EFFECT", ...evidenceIdentity, result:{kind:"SIMULATED_NO_EFFECT", reference:
adapterNoEffectReference}}`.

Constructors: `createPortableAdapterAcknowledgment(identity, transactionReference?)` — simulated
(reference must be absent or equal to the fingerprint) or packet (reference must be a
`0x`+64-hex digest); other profiles throw. `createLocalSyntheticEndpointStateAcknowledgment(identity,
digest)`, `createLocalDocumentReleaseAcknowledgment(identity, digest)`,
`createRemoteServiceReportAcknowledgment(identity, digest)` require their exact profile and a
64-hex digest. `createPortableAdapterNoEffect(identity)` requires the simulated profile.

Validation: `validatePortableAdapterAcknowledgment(value, identity)` = canonical equality with
the constructor's output for the identity's profile and the digest found in the value (returns
false for any deviation: extra key, wrong schemaVersion, wrong algorithm string, foreign
profile/domain/intentId/head/key/fingerprint) **[verified by tests]**.
`validatePortableAdapterNoEffect(value, identity)` similarly. The `*Shape` variants rebuild an
identity from the value's own fields (`durableEventHistoryHash := admissionHead.hash`,
`adapterNoEffectReference` derived) and validate against it — shape only.

`portableAdapterAcknowledgmentTransactionReference(ack, identity)` = the digest/reference
carried by the result (`submissionReference`, `manifestDigest.value`,
`publicationManifestDigest.value`, `transitionDigest.value`, `reportDigest.value`).

External evidence: `portableAdapterAcknowledgmentEvidence(identity, ack) = {kind:"EXTERNAL",
evidenceType: ack.schemaVersion, reference: hashCanonical(ack), attesterId: profileId}`;
`portableAdapterNoEffectEvidence(identity, noEffect) = {kind:"EXTERNAL", evidenceType:
"continuity-adapter-no-effect/0.2", reference: hashCanonical(noEffect), attesterId:
"adapter:simulated"}`. `samePortableAdapterEvidence` compares the four fields.

**[verified]** for the `core02-simulated-r1` admission: ack evidence reference
`0x8eaddd06f358f01cc4cb166d95abcce9ab43aa8f7a9c19880466041f239197ed`, no-effect reference
`0x3a116592953fcd0f5ed805101b9063f2ce2c0e7bce9d8273f1d0cbb0f9f8c23d`, identity
`idempotencyKey 0x77a16b35…15ac`, `submissionFingerprint 0x9d830aa0…2862`,
`adapterNoEffectReference 0x7537dc1f…b260`.

### H.6 Receipt assurance per profile

`assuranceFor(adapterId)`: simulated → `SIMULATED`; the four others → `NOT_PROVEN`. A receipt's
`assurance.externalOutcome` must equal it (G.2 step 4, G.3 intrinsic fields). The
`externalOutcome` verification axis is always `UNVERIFIED` with primaryCode `SIMULATED` or
`NOT_PROVEN`.

---

## I. Administrative authorization (`continuity-administrative-authorization/0.2`)

### I.1 Wrapper shape

Every administrative event (`OBLIGATION_CREATED`, `OBLIGATION_PERFORMANCE_ASSIGNED`,
`OBLIGATION_STATUS_RECORDED`, `OUTCOME_OBSERVATION_RECORDED`, `ATTEMPT_DUTY_CREATED`,
`ATTEMPT_DUTY_ASSIGNED`, `ATTEMPT_DUTY_REVIEW_CLOSED`) carries
`data.administrativeAuthorization = { challenge, authorityProof, runtimeSignature }`:

```
challenge = {
  version: "continuity-administrative-authorization/0.2",
  domain: genesis.domain, request: <derived request>, authoritative: true, consequential: true,
  evaluationTime: event.timestamp, policyVersion: genesis.policyVersion,
  rootRecognitionPolicy: genesis.rootRecognitionPolicy,
  eventHistoryHash: preHead.hash, eventHistoryPosition: preHead.position,
  transitionEventId: event.id, transitionEventType: event.type,
  transitionEffectHash: hashCanonical(portableAdministrativeTransitionEffect(event)),
  runtimeSessionId, credentialKeyId, controlEpoch, roleId, roleTenureId,
  authorityProofHash: hashCanonical(authorityProof) }
authorityProof   = a NON-consequential ALLOW proof (PortableAuthorizationProof) for the derived request
runtimeSignature = EIP-191 signature by the session credential over hashCanonical(challenge)
```

The **transition effect** (what `transitionEffectHash` commits to) is the event's data minus the
wrapper, projected into a closed record with `transitionEventType` first:

| type | effect |
|---|---|
| OBLIGATION_CREATED | `{transitionEventType, record, actorId}` |
| OBLIGATION_PERFORMANCE_ASSIGNED | `{transitionEventType, obligationId, fromAgentId, toAgentId, successionRuleId, actorId}` |
| OBLIGATION_STATUS_RECORDED | `{transitionEventType, obligationId, fromStatus, toStatus, actorId, action, attesterId, evidenceReference}` |
| OUTCOME_OBSERVATION_RECORDED | `{transitionEventType, intentId, sourceAdmissionEventId, acknowledgment, actorId}` |
| ATTEMPT_DUTY_CREATED | `{transitionEventType, record, actorId}` |
| ATTEMPT_DUTY_ASSIGNED | `{transitionEventType, dutyId, fromAgentId, toAgentId, actorId}` |
| ATTEMPT_DUTY_REVIEW_CLOSED | `{transitionEventType, dutyId, actorId, observationEventIds, summaryDigest}` |

(Key order is irrelevant for hashing since canonical encoding sorts keys.)

### I.2 Derived request and requirements (`deriveRequirements`) — what is authorized

| type | request | requiredPrincipalId | requiredAuthorityIds | roleId / roleTenureId |
|---|---|---|---|---|
| OBLIGATION_CREATED | `{actorId, action:"OBLIGATE", resource: sourceIntent.resource, claimedAt: ts, termsCommitment: record.termsCommitment, counterpartyId?: record.counterpartyId}` | role(record.durableRoleId).principalId | [] | record.durableRoleId / record.creationRoleTenureId |
| OBLIGATION_PERFORMANCE_ASSIGNED | `{actorId, action:"ASSIGN_PERFORMANCE", resource: obligationId, claimedAt: ts}` | role.principalId | [] | role.id / role.currentTenureId |
| OBLIGATION_STATUS_RECORDED | `{actorId, action:"record-collection-disposition", resource: obligationId, claimedAt: ts}` | role.principalId | policy.requiredAuthorityIds (the matching OPEN→OUTCOME_UNKNOWN policy) | role.id / role.currentTenureId |
| OUTCOME_OBSERVATION_RECORDED | `{actorId, action:"OBSERVE_OUTCOME", resource: intentId, claimedAt: ts, termsCommitment?: intent.termsCommitment}` | role(intent.roleId).principalId | [] | role.id / role.currentTenureId |
| ATTEMPT_DUTY_CREATED | action `"CREATE_ATTEMPT_DUTY"`, otherwise as above | | [] | |
| ATTEMPT_DUTY_ASSIGNED | action `"ASSIGN_ATTEMPT_DUTY"` | | [] | |
| ATTEMPT_DUTY_REVIEW_CLOSED | action `"CLOSE_ATTEMPT_DUTY"` | | [] | |

`createPortableAdministrativePolicyProof(state, requirements, evaluationTime)`: returns
`undefined` if `requirements.request` has an `amount`; stages a **non-consequential**
authorization at `state.head` with the genesis domain/policy, restricting candidate permission
paths to those whose recognized root's `principalId === requiredPrincipalId` and whose
candidate graph's controlling authority ids include every `requiredAuthorityIds` member; then
rejects (`undefined`) if any grant on any path of the winning candidate graph is `quantitative`
or has `maxAmount`/`maxCumulativeAmount`/`maxTransactions`; finalizes and returns the proof only
if `decision === "ALLOW"`, `scopeAssurance === "REPLAY_VERIFIED"`, `consequential === false`,
`usageSnapshot.length === 0`. **[verified]** the fixture's OBLIGATION_CREATED proof has
`consequential:false`, `controllingAuthorityIds:["obligate-authority:…"]`, `usageSnapshot:[]`,
and no runtime/intent fields.

### I.3 Replay verification (`validatePortableAdministrativeTransition(state, event, requirements)`)

Replay recomputes `requirements` from the exact pre-event state (the reducers in §K derive the
same request), then checks all of the following (any failure rejects the event with
`TRANSITION_INVALID`):

1. Event type is one of the seven; E5-only types require an E5/E6 genesis; REVIEW_CLOSED
   requires E6.
2. `challenge.domain` and `proof.domain` canonically equal `genesis.domain`;
   `challenge.request` canonically equals `requirements.request`;
   `challenge.request.actorId === data.actorId`; `challenge.policyVersion ===
   genesis.policyVersion`; `challenge.rootRecognitionPolicy === genesis.rootRecognitionPolicy`;
   `challenge.eventHistoryHash === state.head.hash`; `challenge.eventHistoryPosition ===
   state.head.position`; `challenge.evaluationTime === event.timestamp`;
   `challenge.transitionEventId === event.id`; `challenge.transitionEventType === event.type`;
   `challenge.transitionEffectHash === hashCanonical(effect(event))`;
   `challenge.authorityProofHash === hashCanonical(proof)`; `challenge.roleId ===
   requirements.roleId`; `challenge.roleTenureId === requirements.roleTenureId`.
3. Actor exists and not terminated; session `challenge.runtimeSessionId` exists for the actor,
   not expired at `event.timestamp` (`timestamp >= expiresAt` fails), `credentialKeyId ===
   challenge.credentialKeyId`, `controlEpoch === challenge.controlEpoch ===
   actor.currentControlEpoch`; role exists with `currentTenureId === requirements.roleTenureId`;
   tenure exists, open, matches role and actor.
4. `recoverPortableContentHashSigner(hashCanonical(challenge), runtimeSignature) ===
   session.credentialAddressKey`.
5. `createPortableAdministrativePolicyProof(state, requirements, event.timestamp)` is defined and
   canonically equals `proof`.

### I.4 Producer (`packages/core-0.2/src/administration/index.ts`)

`prepareAdministrativeEvent(input)` (sync) and `produceAdministrativeEvent(input, {signHash})`
(async), `attachAdministrativeSignature(input, signature)`. Errors are
`AdministrativeProducerError` with `phase ∈ CAPTURE|PREPARE|SIGN|VERIFY` and `code`;
`message = "<phase>:<code>"`.

Input: closed record `{events, expectedDomain, expectedHistoryHead, transition, runtimeSessionId}`
captured with a 1 MiB bound (`CAPTURE:INPUT_LIMIT`), original `undefined` keys refused
(`CAPTURE:INVALID_INPUT`), `events` an array of ≤ 128 events (`CAPTURE:INPUT_LIMIT` beyond),
`runtimeSessionId` a non-empty string. `transition` must be a closed `{id, type, timestamp,
data}` (`PREPARE:INVALID_TRANSITION`); `type` one of the seven (`PREPARE:UNSUPPORTED_OPERATION`);
`data` must have exactly the type's fields:
`OBLIGATION_CREATED: record, actorId`; `OBLIGATION_PERFORMANCE_ASSIGNED: obligationId,
fromAgentId, toAgentId, successionRuleId, actorId`; `OBLIGATION_STATUS_RECORDED: obligationId,
fromStatus, toStatus, actorId, action, attesterId, evidenceReference`;
`OUTCOME_OBSERVATION_RECORDED: intentId, sourceAdmissionEventId, acknowledgment, actorId`;
`ATTEMPT_DUTY_CREATED: record, actorId`; `ATTEMPT_DUTY_ASSIGNED: dutyId, fromAgentId, toAgentId,
actorId`; `ATTEMPT_DUTY_REVIEW_CLOSED: dutyId, actorId, observationEventIds, summaryDigest`.
`id` non-empty string, `timestamp` U53, `actorId` string. Creation records must have
`status === "OPEN"` (`PREPARE:UNSUPPORTED_STATUS` **[verified]**); a status record must be
`OPEN → OUTCOME_UNKNOWN` with action `record-collection-disposition` (else UNSUPPORTED_STATUS).

Prepare: replay `events` (`PREPARE:PREFIX_REJECTED`); `expectedDomain` canonically equal
genesis domain (`DOMAIN_MISMATCH`); `expectedHistoryHead` canonically equal head
(`HEAD_MISMATCH` **[verified]**); `timestamp >= head.canonicalTime` (`INVALID_TRANSITION`);
derive requirements (`INVALID_TRANSITION` for missing source/role/duty/obligation or field
inconsistencies; `POLICY_UNAVAILABLE` for wrong edition or missing status policy); session/actor/
role/tenure checks as in I.3 step 3 (`SESSION_INVALID` **[verified]**); policy proof
(`POLICY_UNAVAILABLE` when undefined); build the base challenge with placeholder zero hashes,
validate the would-be event's shape with a placeholder signature
(`0x` + 63 zeros + `1` + 63 zeros + `1` + `1b`) (`INVALID_TRANSITION`); then fill
`transitionEffectHash` and `authorityProofHash`. Any other exception → `PREPARE:PREPARATION_FAILED`.
Returns `{transition, challenge, authorityProof, signingHash: hashCanonical(challenge)}`.

Sign: `options` must be a plain record with exactly one own data property `signHash` that is a
function (`SIGN:SIGNER_INVALID` **[verified]**); callback rejection → `SIGN:SIGNER_FAILED`
**[verified]**.

Attach/verify: signature must match `/^0x[0-9a-fA-F]{130}$/` (`VERIFY:INVALID_SIGNATURE`); the
event `{...transition, data:{...data, administrativeAuthorization:{challenge, authorityProof,
runtimeSignature}}}` appended to `events` must replay ACCEPTED (`VERIFY:SIGNED_EVENT_REJECTED`
**[verified]** for a wrong-key/garbage signature). Returns `{event, challenge, authorityProof,
signingHash, replayHead}`. `attachAdministrativeSignature` re-derives the preparation from the
input rather than trusting a caller-supplied one.

**[verified]** producing OBLIGATION_CREATED over the 17-event history (head 16) yields a
challenge with `evaluationTime 17`, `eventHistoryPosition 16`, `transitionEventType
"OBLIGATION_CREATED"`, request `{action:"OBLIGATE", actorId:a, claimedAt:17, resource:
"resource:core02-simulated-r1", termsCommitment: …}`, and the appended history replays ACCEPTED.

---

## J. Durable coordinators (SDK)

### J.1 Store contract (`PortableFileEventStore`)

* `readAll(): Event[]` — parses the JSONL hash-chained file, replays it (throws if not
  ACCEPTED), returns a deep-frozen array (empty array when the file does not exist).
* `withExclusiveWriter(cb)` — takes a cooperative lock file `<path>.writer-lock` (`wx`; an
  existing lock → `PortableStoreBusyError`), passes `{readAll, appendAtExpectedHead}`, releases
  the lock in `finally`. Writer methods are non-reentrant and expire after the callback.
* `writer.appendAtExpectedHead(event, expected)` — re-reads the file, replays it, and throws
  `PortableStoreConflictError(observedHead)` (`observedHead` undefined when the store is empty)
  unless `expected` equals the observed head (hash, position, canonicalTime); otherwise
  replays `[...events, event]` (throws on rejection), appends one line, fsyncs file and
  directory, and returns the new head.
* `appendAtExpectedHead`, `append`, `appendAll` — top-level conveniences that take the lock.

### J.2 Adapter interface (`TransactionAdapter`)

```
interface TransactionAdapter {
  readonly adapterProfile: PortableAdapterProfile          // MUST be an own data property (no getter)
  submit(input: AdmittedTransactionSubmission): Promise<AdapterSubmissionResult>
  reconcile(input: AdmittedTransactionSubmission): AdapterSubmissionResult | Promise<AdapterSubmissionResult>
}
AdmittedTransactionSubmission = PortableAdapterIdentityInput = { operationVersion:"continuity-adapter-submission/0.2", domain, intentId, admissionEvent, admittedHistory }
AdapterSubmissionResult =
  | { status:"SUBMITTED",  idempotencyKey, submissionFingerprint, evidence: EXTERNAL ref, acknowledgment }
  | { status:"RETRY",      idempotencyKey, submissionFingerprint, retainedEvidence: EXTERNAL ref, acknowledgment }
  | { status:"RETRY",      idempotencyKey, submissionFingerprint, retainedEvidence: EXTERNAL ref, noEffect }
  | { status:"FAILED",     idempotencyKey, submissionFingerprint, evidence: EXTERNAL ref, noEffect }
  | { status:"OUTCOME_UNKNOWN", idempotencyKey, submissionFingerprint, latestEvidence?: EXTERNAL ref }
  | { status:"IDEMPOTENCY_FINGERPRINT_CONFLICT", idempotencyKey, retainedFingerprint, suppliedFingerprint }
```

`DeterministicSimulatedAdapter({failIntentIds?})` (reference adapter): profile =
E1 simulated profile; `submit` derives the identity (profile must be the simulated profile),
returns a retained result if one exists for the idempotency key (`RETRY` with the retained
acknowledgment/noEffect, or `IDEMPOTENCY_FINGERPRINT_CONFLICT` when the fingerprint differs),
else creates `FAILED` (no-effect) for listed intent ids or `SUBMITTED` (acknowledgment), caches
it by idempotency key and records an attempt; `reconcile` returns the retained result or
`OUTCOME_UNKNOWN` (never submits).

### J.3 `DurableAdmissionCoordinator(store, adapter, {authoritativeNow})`

Construction validates `adapter.adapterProfile` (`configuredProfile`): own data descriptor,
captured with ≤ 32 keys / depth 12 / 256 nodes / ≤ 1024 canonical bytes, exactly
`{profileId, profileVersion, descriptorHash}`, and `hashCanonical(profile) ===
hashCanonical(knownPortableAdapterProfile(profileId))` — any of the five known profiles. The
profile is re-read and re-compared (`#assertAdapterProfile`) at every step; an admitted
identity's profile must also equal it.

Results:
```
DurableAdmissionCommitResult =
  | { status:"INVALID_PREPARATION", reason }
  | { status:"UNAVAILABLE", reason, admissionMayHavePersisted: boolean }
  | { status:"NOT_ADMITTED", result: <RETRY|DENIED|INDETERMINATE|CONFLICT proposal> }
  | { status:"ADMITTED", result: { operationVersion:"continuity-intent-admission/0.2", status:"ADMITTED", authorization: proof, admissionEvent, newHead }, capability: { intentId, admissionEventId, admissionHead } }
PortableInvocationResult =
  | { status:"NOT_INVOKED", reason }
  | { status:"OUTCOME_UNKNOWN", reason, idempotencyKey?, submissionFingerprint? }
  | { status:"TERMINAL", head, evidence }
  | { status:"IDEMPOTENCY_FINGERPRINT_CONFLICT", disposition }
  | { status:"SUBMITTED"|"FAILED"|"RETRY", disposition, recorded: true, head }
DurableAdmissionResult = { admission, invocation? }
```

**prepare(input)** → `{proposal: proposePortableIntentAdmission(input)}` (frozen), remembered in
a WeakMap keyed by the returned object. **The proposal is computed from `input.events`, not from
the store.** **[verified]** re-running `execute(input)` with the original (pre-admission)
`events` after an admission yields `NOT_ADMITTED/CONFLICT`, not RETRY; RETRY only arises when
the caller supplies a history that already contains the admission.

**admit(prepared)**:
1. Not an object or not a known unused preparation → `INVALID_PREPARATION` ("An unused
   preparation from this coordinator is required."). The preparation is consumed (a second
   `admit` with the same object → INVALID_PREPARATION **[verified]**).
2. Adapter profile changed → `UNAVAILABLE` ("The configured adapter profile changed.", `false`).
3. Proposal not PROPOSED: if RETRY, under the writer lock read the store, `inspectPortableAdmittedIntent(events,
   intentId, head.canonicalTime)` must be ADMITTED with the same `admissionEvent.id` and
   `admissionHead` and a matching adapter identity profile, else `UNAVAILABLE` ("The supplied
   retry does not establish this store's original admission.", `false`). Then return
   `NOT_ADMITTED {result: proposal}`.
4. PROPOSED: under the writer lock: read events; `observedHead` (undefined if empty) must equal
   `proposal.expectedHead` else throw `PortableStoreConflictError(observedHead)`; build
   `prospective = [...events, admissionEvent]`, `inspectPortableAdmittedIntent(prospective,
   intentId, admissionEvent.timestamp)` must be ADMITTED; derive the adapter identity from the
   submission `{operationVersion, domain: proof.domain, intentId, admissionEvent, admittedHistory:
   prospective.slice(0, admissionHead.position+1)}`; assert profile; **then** append
   (`appendStarted = true`); the returned head must equal `proposal.prospectiveHead`; assert
   profile again. Record `{submission, identity, admissionHead}` under a fresh capability object.
   Return `ADMITTED`.
5. Errors: a `PortableStoreConflictError` with an observed head *before* the append started →
   `NOT_ADMITTED {result: {operationVersion, status:"CONFLICT", expectedHead, observedHead}}`
   **[verified]**; anything else → `UNAVAILABLE` ("Durable admission could not be established;
   reconcile before any retry.", `admissionMayHavePersisted: appendStarted`).

**invoke(capability)** (async):
1. Unknown/used capability → `NOT_INVOKED` ("An unused invocation capability is required.").
   The capability is consumed immediately (a second `invoke` → NOT_INVOKED **[verified]**).
2. Under the writer lock: `current = inspectPortableAdmittedIntent(history, intentId, now())`;
   require ADMITTED, same `admissionHead`, same admission event id, no `consumption`, no
   `terminal`, `currentControl === true`; else `NOT_INVOKED` ("The original admission is
   consumed, terminal, replaced or no longer under its admitted control tuple.") **[verified]**
   after a CONTROL_EPOCH_ADVANCED. If `inspect` throws (e.g. `now() < head.canonicalTime`
   **[verified]**, or the profile assertion fails) before `adapter.submit` is entered →
   `NOT_INVOKED` ("Current durable history, time or serialized control could not be
   established."); if it throws after → `OUTCOME_UNKNOWN` ("Adapter invocation may have
   started.", with key/fingerprint). `adapter.submit(submission)` is *called* synchronously
   inside the lock; its promise is awaited outside.
3. The awaited response is validated by `captureDisposition` (J.4); failure/rejection →
   `OUTCOME_UNKNOWN` ("The adapter response is missing, invalid or exceptional.").
4. `#recordDisposition`.

**#recordDisposition(record, disposition)**:
* profile changed → `OUTCOME_UNKNOWN` ("The configured adapter profile changed before recording.").
* `OUTCOME_UNKNOWN` → `OUTCOME_UNKNOWN` ("The adapter cannot establish a definitive outcome.").
* `IDEMPOTENCY_FINGERPRINT_CONFLICT` → `{status, disposition}`.
* Otherwise `evidence = RETRY ? retainedEvidence : evidence`, `acknowledgment`/`noEffect` as
  present. Under the writer lock: `now = now()`, `current = inspect(events, intentId, now)` must
  be ADMITTED with the same admissionHead (else throw); profile assert; if an acknowledgment is
  supplied and a consumption already exists: it must have identical `evidenceReference` and
  `acknowledgment` (hash-compare) → return `current.head` without writing (else throw); if a
  noEffect is supplied and `terminal.status === "FAILED"`: same identity check → return head;
  else require `currentControl` (throw otherwise); event id = `` `event:local:${ack ?
  "consumption" : "failure"}:${hashCanonical([intentId, admissionEventId]).slice(2)}` ``;
  event = acknowledgment ?
  `{id, type:"TRANSACTION_INTENT_CONSUMED", timestamp: now, data:{intentId, adapterId:
  identity.adapterProfile.profileId, idempotencyKey, submissionFingerprint, status:"SUBMITTED",
  evidenceReference: evidence, transactionReference:
  portableAdapterAcknowledgmentTransactionReference(ack, identity), acknowledgment}}` :
  `{id, type:"TRANSACTION_OUTCOME_RECORDED", timestamp: now, data:{intentId, status:"FAILED",
  attesterId:"adapter:simulated", evidenceReference: evidence, noEffect}}`; `appendAtExpectedHead(event,
  current.head)`. Return `{status: disposition.status, disposition, recorded: true, head}`.
  Any throw → `OUTCOME_UNKNOWN` ("The acknowledgment or simulator no-effect outcome could not
  be durably recorded.", with key/fingerprint). **[verified]** SUBMITTED path appends
  `event:local:consumption:a163f47b…` at position 15 with timestamp `now`; the FAILED path
  appends a `TRANSACTION_OUTCOME_RECORDED/FAILED` and the result is `{status:"FAILED",
  recorded:true, head}`.

**reconcile(intentId)** (async):
1. Under the writer lock: `current = inspect(events, intentId, head.canonicalTime)` must be
   ADMITTED; rebuild submission/identity; profile assert. Failure → `OUTCOME_UNKNOWN` ("The
   original durable admission is unavailable.") **[verified]** for an unknown intent.
2. If `terminal` exists and is not FAILED → `{status:"TERMINAL", head, evidence: terminal.evidenceReference}`.
3. If a FAILED terminal or a consumption is retained → synthesize a `RETRY` disposition from the
   retained evidence and typed record, validate it with `captureDisposition`, return
   `{status:"RETRY", recorded:true, head: current.head, disposition}` **[verified]** (no write).
4. Otherwise (admitted, nothing recorded): profile assert; `disposition =
   captureDisposition(await adapter.reconcile(submission))`; a `SUBMITTED`/`FAILED` disposition
   from reconcile is an error → `OUTCOME_UNKNOWN` ("Retained adapter evidence is unavailable or
   invalid."); then `#recordDisposition` (a RETRY from the adapter is recorded as a
   consumption/outcome **[verified by tests]**; an `OUTCOME_UNKNOWN` propagates with the reason
   "The adapter cannot establish a definitive outcome." **[verified]**).

**commit(prepared)** = `admit`; if ADMITTED → `{admission, invocation: await invoke(capability)}`;
if NOT_ADMITTED with RETRY → `{admission, invocation: await reconcile(intentId)}`; else
`{admission}` (no `invocation` key **[verified]** for DENIED). **execute(input)** =
`commit(prepare(input))`.

Crash recovery: every step re-reads the durable history under the lock and re-derives facts
from replay; nothing is cached across steps except the WeakMap-held preparation/capability
objects (which do not survive a process restart). After a crash between `admit` and `invoke`,
a fresh `execute` with a history that includes the admission yields RETRY → `reconcile` →
adapter `reconcile` (never `submit`) → if the adapter retains nothing, `OUTCOME_UNKNOWN` and the
history stays without a consumption **[verified by tests]**; a first-invocation capability can
never be re-minted from replay facts alone.

### J.4 `captureDisposition(value, identity)`

`captureAdapterData` snapshot: acyclic non-proxy plain records/scalars, ≤ 256 nodes, depth ≤ 12,
≤ 32 keys per record, strings ≤ 4096 chars, ≤ 16 384 canonical bytes, no accessors (original
`undefined` keys preserved). Then: `idempotencyKey === identity.idempotencyKey` (else throw);
`IDEMPOTENCY_FINGERPRINT_CONFLICT` requires exactly `{status, idempotencyKey, retainedFingerprint,
suppliedFingerprint}` with `suppliedFingerprint === identity.submissionFingerprint`,
`retainedFingerprint` a 64-hex hash ≠ supplied; otherwise `submissionFingerprint ===
identity.submissionFingerprint`, and by status: `SUBMITTED` exactly
`{status, idempotencyKey, submissionFingerprint, evidence, acknowledgment}` with
`validatePortableAdapterAcknowledgment(ack, identity)` and `evidence` a closed
`{kind, evidenceType, reference, attesterId}` hash-equal to
`portableAdapterAcknowledgmentEvidence(identity, ack)`; `FAILED` likewise with `noEffect`;
`RETRY` with `retainedEvidence` and either acknowledgment or noEffect; `OUTCOME_UNKNOWN` exactly
the three keys plus optional `latestEvidence` which must be a closed EXTERNAL reference with
`attesterId === profileId`, a 64-hex `reference`, and `evidenceType` equal to the profile's
acknowledgment schema (or the no-effect version for the simulated profile) **[verified by
tests]**: a wrong `evidenceType` makes the whole response invalid ("…missing, invalid or
exceptional."). Unknown status → throw.

### J.5 `DurableReceiptCoordinator(store).record(input)`

```
DurableReceiptRecordResult = PortableReceiptRecordAdmissionResult | { status:"UNAVAILABLE", recordMayHavePersisted, reason }
```
`proposal = proposePortableReceiptRecord(input)` (a thrown exception → `UNAVAILABLE(false)`);
non-PROPOSED proposals are returned verbatim (INDETERMINATE / CONFLICT / REJECTED); PROPOSED →
`store.appendAtExpectedHead(recordEvent, expectedHead)`; the acknowledged head must be a valid
head equal to `proposal.newHead` (else `UNAVAILABLE(true)`); success →
`{operationVersion:"continuity-receipt-record-admission/0.2", status:"ADMITTED", recordEvent,
newHead, verification}` **[verified]**; a `PortableStoreConflictError` with a valid observed head
→ `{…, status:"CONFLICT", expectedHead, observedHead}` **[verified]** (without a head →
`UNAVAILABLE(false)`); any other error → `UNAVAILABLE(true)` with reason "Receipt persistence
could not be established; inspect the durable history before another attempt."

---

## K. Obligations and attempt duties

### K.1 `PortableObligationRecord` (immutable creation record)

```
{ obligationId, sourceIntentId, causalReceiptContentHash: ContentHash, durableRoleId, creationRoleTenureId,
  description, trigger (= the consumption event id), deadline: U53, status: "OPEN"|"OUTCOME_UNKNOWN",
  beneficiaryId, counterpartyId?, termsCommitment: ContentHash, performanceAssigneeId, successionRuleId,
  transitionPolicies: [{ fromStatus, toStatus, acceptedAttesterIds: string[], action, requiredAuthorityIds: string[] }] }
```
`PortableObligationStatus = OPEN | OUTCOME_UNKNOWN | DISPUTED | DISCHARGED | IMPOSSIBLE_OR_ESCALATED`
with ranks 0..4. Unresolved = not DISCHARGED and not IMPOSSIBLE_OR_ESCALATED.

Replay `OBLIGATION_CREATED` (data `{record, actorId}`) requires: no existing obligation or
attempt duty with that id, no obligation already created for the source intent; declaration,
admission, consumption, receipt commitment (by `causalReceiptContentHash`), role, tenure and
succession rule all exist; intent ids agree across declaration/admission/consumption/receipt;
`admissionPosition < consumptionPosition < receiptPosition < creationPosition`; `record.trigger
=== consumption.eventId`; `durableRoleId === intent.roleId === receipt.roleId`;
`creationRoleTenureId === intent.roleTenureId === receipt.roleTenureId`; the role's current
tenure is that tenure, open, for that role; `performanceAssigneeId === intent.actorId ===
tenure.agentId === data.actorId`; `termsCommitment` equals the intent's; `counterpartyId`
presence and value equal the intent's; the succession rule has `roleId === durableRoleId`,
`predecessorAgentId === performanceAssigneeId`, `principalId === role.principalId`, `trigger ===
"AGENT_TERMINATED"`, and `permittedEventTypes ⊇ {AGENT_TERMINATED, ROLE_TRANSFERRED,
OBLIGATION_PERFORMANCE_ASSIGNED}`; `transitionPolicies` non-empty, each with an unresolved
`fromStatus`, strictly sorted `acceptedAttesterIds` and `requiredAuthorityIds` (which must all
exist), policies strictly ordered by `(fromRank, toRank)`; the declaration event precedes the
admission; the receipt commitment's `authorizationProofHash === hashCanonical(admission proof)`
and its issuer/session/epoch/role/tenure equal the proof's; and the administrative
authorization validates for request `{actorId, action:"OBLIGATE", resource: intent.resource,
claimedAt: ts, termsCommitment, counterpartyId?}`. Stored state:
`{record, status: record.status, performanceAssigneeId: record.performanceAssigneeId,
creationEventId, creationEventPosition, creationHead}`.

`OBLIGATION_PERFORMANCE_ASSIGNED` (`{obligationId, fromAgentId, toAgentId, successionRuleId,
actorId}`): obligation exists and unresolved; `fromAgentId === current performanceAssigneeId`;
`successionRuleId === record.successionRuleId`; the role's current tenure is open, held by
`toAgentId`; the rule names `fromAgentId → toAgentId` for that role/principal with trigger
AGENT_TERMINATED and permits OBLIGATION_PERFORMANCE_ASSIGNED; an `AGENT_TERMINATED` for
`fromAgentId` with matching principal/rule/role/creation tenure exists **before** a
`ROLE_TRANSFERRED` of kind SUCCESSION with the same rule from the creation tenure to the current
tenure; administrative authorization for `{actorId, action:"ASSIGN_PERFORMANCE", resource:
obligationId, claimedAt}` with `requiredPrincipalId = rule.principalId`, role/tenure = current.
Effect: `performanceAssigneeId := toAgentId`.

`OBLIGATION_STATUS_RECORDED` (`{obligationId, fromStatus, toStatus, actorId, action, attesterId,
evidenceReference}`): obligation unresolved; `fromStatus === current status`; a policy with
that `(fromStatus, toStatus, action)` exists and lists `attesterId` in `acceptedAttesterIds`;
`evidenceReference` attributes the attester (an EXTERNAL reference with that `attesterId`, or a
valid EVENT reference whose event has `data.attesterId === attesterId` or an EXTERNAL
`data.evidenceReference` with that attester); administrative authorization for `{actorId,
action, resource: obligationId, claimedAt}` with `requiredAuthorityIds = policy.requiredAuthorityIds`
(so the actor's winning path must control those authorities). Effect: `status := toStatus`.
The producer (§I.4) only prepares `OPEN → OUTCOME_UNKNOWN / record-collection-disposition`.

### K.2 Attempt duties (E5/E6)

`PortableAttemptDutyRecord = { dutyId, sourceIntentId, sourceAdmissionEventId, durableRoleId,
creationRoleTenureId, description, deadline, performanceAssigneeId, status:"OPEN" }`.

`attemptSource(intentId)`: defined only on an E5/E6 genesis when the intent is declared and
admitted with profile `adapter:remote-service-report`, the intent's role has an open current
tenure whose agent is active; returns `{intent, admission, role, tenure}`. All four reducers
require `data.actorId === tenure.agentId` (the current role holder) and an administrative
authorization for `{actorId, action, resource: intentId, claimedAt, termsCommitment?}` with
`requiredPrincipalId = role.principalId`, `roleId = role.id`, `roleTenureId = tenure.id`.

* `OUTCOME_OBSERVATION_RECORDED` (`{intentId, sourceAdmissionEventId, acknowledgment, actorId}`):
  `sourceAdmissionEventId === admission.admissionEventId`; acknowledgment validates against the
  admission's identity and has `result.kind === "REMOTE_SERVICE_REPORTED"`; action
  `OBSERVE_OUTCOME`. Appends `{intentId, sourceAdmissionEventId, acknowledgment, actorId, eventId,
  eventPosition, observedAt: timestamp}`. Observations never consume the intent; any number may
  be recorded (by any current role holder), including repeated digests.
* `ATTEMPT_DUTY_CREATED` (`{record, actorId}`): `sourceAdmissionEventId`, `durableRoleId ===
  role.id`, `creationRoleTenureId === tenure.id`, `performanceAssigneeId === tenure.agentId`,
  `status === "OPEN"`, no duty/obligation with that id, at most one duty per source intent;
  action `CREATE_ATTEMPT_DUTY`. Stored `{record, creationEventId, creationEventPosition,
  creationActorId: actorId, currentAssigneeId: performanceAssigneeId, assignments: []}`.
* `ATTEMPT_DUTY_ASSIGNED` (`{dutyId, fromAgentId, toAgentId, actorId}`): duty exists;
  `fromAgentId === currentAssigneeId`; `toAgentId !== fromAgentId`; `toAgentId ===
  tenure.agentId` (the current holder assigns to themself); action `ASSIGN_ATTEMPT_DUTY`.
  Appends `{fromAgentId, toAgentId, actorId, eventId, eventPosition, assignedAt}`,
  `currentAssigneeId := toAgentId`.
* `ATTEMPT_DUTY_REVIEW_CLOSED` (`{dutyId, actorId, observationEventIds, summaryDigest}`), E6
  only: duty exists; `actorId === currentAssigneeId`; `observationEventIds` has exactly the
  observations' event ids for the source intent, strictly sorted (≤ 128); action
  `CLOSE_ATTEMPT_DUTY`. Appends a review record; the duty record is unchanged (status stays
  OPEN; a review is recordkeeping, not discharge).

The attempt-duty SURVIVES projection and `reviewStatus` are in §D.3/§D.6.

---

## L. Traps and subtle behaviours

1. **`responsiblePortable` throws on unsorted grant constraint lists** (§C.6). Replay accepts
   `AUTHORITY_GRANTED` with unsorted `actions`/`resources`/`requiredIntersectionIds`; WHY works;
   RESPONSIBLE crashes with `TypeError: Inconsistent internal responsibility projection
   inputs.` The re-implementation must compare normalized grants (or skip the comparison) and
   return the same ESTABLISHED answer the reference would give for the sorted history.
2. **Evidence order is by eventId string, not position.** `compareQueryEvidence` compares
   `eventId` first; e.g. `event:local:consumption:…` sorts before `first-look:admission` because
   `e` < `f`; `attempt-duty-…` (hyphen 0x2d) sorts before `attempt-duty:…` (colon 0x3a).
   `RECEIPT_COMMITMENT` references always follow EVENT references.
3. **Row merging.** Same `(field,key)` rows union their evidence; the *first* row's members win.
   In RESPONSIBLE the consequential `ACTOR` row is written twice (`[agentCreation, finalEvent]`
   then `[declaration]`), giving three references after merge. Comparison plans (used by conflict
   detection) instead throw on differing members for the same key — unreachable for real
   projections.
4. **`presentConsequentialUse`** is `true` only for `ALLOW && consequential && SAME_HEAD`. A
   STRICT_EXTENSION query with the same binding gives `false` even though the answer is ALLOW.
5. **Disclosure check precedes overflow.** An overflowing projection reports
   `DISCLOSURE_INVALID` if any observed path is missing from the disclosure, otherwise
   `OUTPUT_LIMIT_EXCEEDED`. An overflow clears every top-level answer list but keeps collecting
   `includedFields`.
6. **Disclosure must include every top-level skeleton key**, including `outcomeObservations`
   and `attemptDuties` on E5/E6 histories even when empty, and `<list>.evidence` for every list
   that got a row. Extra (unused) paths in `includedFields` are harmless; `withheldFields` may
   contain only non-core names and is otherwise informational.
7. **`CAUSAL_TIME_INVALID` for non-numbers.** `evaluationTime` as a string/bigint passes input
   capture and fails as `CAUSAL_TIME_INVALID` (with the early scope), not INVALID_INPUT; an
   object/array/boolean fails as INVALID_INPUT.
8. **Observed shorter than evaluation is UNVERIFIED**, not an error; the evidence pair is then
   the two heads (positions 12 and 25 in the verified case). `STRICT_EXTENSION` only holds when
   *observed* extends *evaluation*.
9. **SURVIVES over an UNVERIFIED pair needs `evaluationTime ≥ both heads`**; WHY/RESPONSIBLE
   only need `≥ evaluation head`. A SURVIVES fork query with `time` below the observed head
   is CAUSAL_TIME_INVALID even though the evaluation head is satisfied.
10. **Conflict detection for WHY/RESPONSIBLE requires `consequentialBinding.intentId`.**
    Without it a same-intent fork is reported as HISTORY_RELATION_UNVERIFIED. For SURVIVES,
    conflicts are only reported when the two branches' SURVIVES answers actually differ for the
    target and the admissions involve the target as actor.
11. **Terminal outcomes hide intents but keep receipts out.** CONFIRMED/FAILED intents leave
    `unresolvedIntents` but stay in `adapterOutcomes`; their receipt commitments are listed only
    if an unresolved obligation still references the receipt hash.
12. **`transferredRoleTenures` includes any closed tenure** (unappointed as well as transferred).
13. **AGENT_TERMINATED invalidation only counts agents**: a permission whose grantor is a
    principal is invalidated only through its grantee/children. Precedence
    REVOKED > EXPIRED > AGENT_TERMINATED; expiry uses `evaluationTime >= expiresAt`; `notBefore`
    is ignored by SURVIVES.
14. **RESPONSIBLE with DENY returns no attributions** at all (empty list), including no ACTOR.
15. **`policyVersion` for the query's authorization comes from the genesis**, so a caller cannot
    trigger POLICY_MISMATCH; `authorizationDomain` however is the caller's and produces an
    ESTABLISHED `DENY/DOMAIN_MISMATCH`.
16. **`proposePortableIntentAdmission` RETRY precedes the head check** and is derived from the
    supplied `events`, not from any store; the SDK's `prepare` therefore cannot notice an
    admission that the caller's event list omits (→ CONFLICT at `admit`).
17. **Nonce reservations are permanent**; a FAILED simulated outcome (or a DISPUTED one) never
    frees `(actorId, nonce)`; the same intent id can never be re-admitted (`INTENT_REPLAY`).
18. **`sameIntent` ignores `adapterProfile`**, but replay's declaration transition binds the
    profile to the genesis edition, and the admission binds the declaration's profile into the
    adapter identity.
19. **Signature verification in admission is against the head at signing time**: a binding
    signed for head 13 evaluated over a 15-event history yields `SESSION_CREDENTIAL_INVALID`
    (not INTENT_REPLAY), because the challenge embeds `eventHistoryHash/Position`.
20. **Receipt `related` is strict**: `issuanceEvents` must be exactly the signed prefix
    (length `p+1`) or that prefix plus one core-typed event; anything else makes issuer,
    historical, inclusion and freshness all `ISSUANCE_HISTORY_UNVERIFIED` (authentic=false)
    even though the signature is valid.
21. **Issuer authentication needs the prefix**: the recovered signer is compared with
    `session.credentialAddressKey` of the session admitted in the issuance prefix; a receipt
    over a foreign prefix without that session is `DEPENDENCY_UNAVAILABLE`, and a mismatched
    `issuer.keyId` is `ISSUER_NOT_AUTHENTICATED` + `RECEIPT_FIELDS_MISMATCH`.
22. **Verifier time behind the observed head** makes freshness `UNVERIFIED` (with an extra
    `FUTURE_ISSUANCE` cause when `issuedAt > verifierTime`) rather than a failure; `current`
    is then false. `valid === historical` never depends on freshness or inclusion.
23. **Receipt evidence in axes** is sorted by eventId string; `contentIntegrity`,
    `signaturePossession`, `finality`, `externalOutcome` always have empty evidence; on domain
    mismatch every other axis has evidence = the two genesis events (deduplicated to one when
    the prefixes coincide).
24. **`proposePortableReceiptRecord` limits**: at most 2047 existing events (`(n+1)*2 > 4096`
    → OUTPUT_LIMIT_EXCEEDED); recording the same receipt twice → INDETERMINATE
    STATE_NOT_AUTHORITATIVE with the nested verification attached; the record event's
    `timestamp` is `issuedAt`.
25. **Administrative proofs are non-consequential** (`consequential:false`, no
    runtime/intent fields, empty `usageSnapshot`) while the *challenge* says
    `consequential:true`; quantitative/capped grants can never authorize administrative
    transitions (`POLICY_UNAVAILABLE`).
26. **`ASSIGN_ATTEMPT_DUTY` self-assignment**: `toAgentId` must be the current role holder and
    the actor; `fromAgentId` must be the current assignee and differ from `toAgentId`.
27. **Review status is positional**: a review recorded before or at the last assignment's
    position is `NEEDS_REVIEW`; equality with the sorted observation id list is required for
    `REVIEW_CLOSED`; a review with zero observations is valid and closes the duty until the
    next observation.
28. **SDK reasons are exact strings** (see §J.3); tests assert them (e.g. "The adapter cannot
    establish a definitive outcome." vs "The adapter response is missing, invalid or
    exceptional."). `NOT_INVOKED` when `now() < head.canonicalTime` ("Current durable history,
    time or serialized control could not be established.").
29. **Consumption/outcome event ids** are deterministic:
    `event:local:consumption:<hex>` / `event:local:failure:<hex>` with
    `hex = hashCanonical([intentId, admissionEventId]).slice(2)`; a duplicate id would be
    rejected by replay, which is why an idempotent re-record returns the existing head instead.
30. **`DeterministicSimulatedAdapter.reconcile` never submits**; a coordinator `reconcile` after
    a crash with nothing retained yields `OUTCOME_UNKNOWN` and leaves the history untouched.
31. **Genesis `versions` mismatch is EVIDENCE_UNAVAILABLE, not STATE_NOT_AUTHORITATIVE**, and it
    is discovered for both branches before either is replayed; a branch that is both foreign
    and malformed still reports STATE_NOT_AUTHORITATIVE if the base envelope check fails first.
32. **Output limits apply to failure envelopes too** (`fits(result)` runs on every envelope),
    and `recognizedRootIds.length > 256` turns an otherwise established answer into
    `OUTPUT_LIMIT_EXCEEDED` (unverified: no fixture with > 256 roots).
33. **Frozen outputs**: every public result is deeply frozen; callers mutating them get a
    `TypeError`. Inputs are captured once (own data descriptors only); getters and proxies are
    rejected without being invoked.
