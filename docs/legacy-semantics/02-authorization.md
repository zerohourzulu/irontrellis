# 02 — Authorization engine (`portable-authority-engine.ts` + `portable-authority.ts`)

Re-implementation specification, written from the source of
`packages/core-0.2/src/core/portable-authority-engine.ts` (4853 lines),
`packages/core-0.2/src/core/portable-authority.ts` (54 lines) and the
authority-related parts of `packages/core-0.2/src/core/portable-replay.ts`,
cross-checked against `tests/authority.test.mjs`, `tests/quantitative.test.mjs`,
`tests/revocation-context.test.mjs`, `tests/invariants.test.mjs`,
`tests/generators.mjs`, the 19 `kind: "authorization"` vectors in
`conformance/vectors.json`, and ~150 small Node experiments run against the
real engine (marked **[verified]** below; anything not run is marked
**[from source]** and anything I could not settle is marked **[unverified]**).

The goal is bit-for-bit reproduction of observable behaviour: decisions,
codes, `failures` arrays (contents *and order*), proof contents (contents *and
order*), thrown exceptions, and the runtime-challenge hashing/signing.

---

## 0. Vocabulary, constants and scalar predicates

### 0.1 Versions / literals

| Constant | Value |
|---|---|
| `PORTABLE_AUTHORITY_EVALUATION_VERSION` | `"continuity-authority-evaluation/0.2"` |
| `PORTABLE_AUTHORIZATION_VERSION` | `"continuity-authorization/0.2"` |
| `PORTABLE_INTENT_ADMISSION_VERSION` | `"continuity-intent-admission/0.2"` |
| `PORTABLE_AUTHORIZATION_PROOF_VERSION` | `"continuity-authorization-proof/0.2"` |
| `PORTABLE_RUNTIME_AUTHORIZATION_VERSION` | `"continuity-runtime-authorization/0.2"` |
| `PORTABLE_ROOT_RECOGNITION_POLICY` | `"declared-principal-root/0.2"` |

### 0.2 Limits

| Constant | Value | Where it bites |
|---|---|---|
| `MAX_IDENTIFIER_BYTES` | 256 | every Identifier (both UTF-16 length and UTF-8 byte length) |
| `MAX_PROTOCOL_STRING_BYTES` | 4096 | `operationVersion` string; canonical strings generally |
| `MAX_AUTHORITIES` | 1024 | `permissions.length + prohibitions.length` (raw path); evidence list in proof |
| `MAX_PATH_DEPTH` | 32 | grants on one delegation path |
| `MAX_REQUIRED_INTERSECTIONS` | 32 | `requiredIntersectionIds` per grant |
| `MAX_SET_MEMBERS` | 256 | `actions`, `resources`, intersections in proof, checked prohibitions, controlling ids |
| `MAX_RESULT_EVIDENCE` | 4096 | total evidence references across a DENY/INDETERMINATE result |
| `MAX_BIGINT` | 2^256 − 1 | Amount upper bound |
| `SECP256K1_ORDER` (n) | `0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141` | |
| `SECP256K1_FIELD` (p) | `0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f` | |
| `MAX_LOW_S` | `0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0` (= (n−1)/2) | |

### 0.3 Scalar predicates (exact)

* **Identifier** `isIdentifier(v)`: `typeof v === "string"`, `v.length > 0`,
  `v.length <= 256` (UTF-16 units), well-formed Unicode (no lone surrogates),
  UTF-8 byte length ≤ 256, and no code unit in `U+0000..U+001F` or `U+007F`.
  Anything else (spaces, non-ASCII, `:`/`/` etc.) is allowed. Case-sensitive.
* **U53** `isU53(v)`: `typeof v === "number"`, `Number.isSafeInteger(v)`, `v >= 0`, not `-0`.
* **Amount** `isAmount(v)`: `typeof v === "bigint"`, `0n <= v <= MAX_BIGINT`.
* **ContentHash**: string matching `/^0x[0-9a-f]{64}$/` (lowercase only).
* **EthereumAddress**: `/^0x[0-9a-fA-F]{40}$/` (either case).
* **ChainId**: string matching `/^[1-9][0-9]*$/` whose BigInt value is in `[1, MAX_BIGINT]`.
  `"0"`, `"01"`, numbers → invalid.
* **Signature65** `isSignature65(v)`: string matching `/^0x[0-9a-f]{130}$/`
  (lowercase hex only), with `r = v[2..66)`, `s = v[66..130)`, `v[130..132)`:
  `0 < r < n`, `0 < s <= MAX_LOW_S`, recovery byte is exactly `"1b"` or `"1c"`.
  High-s, `v=00/01`, uppercase hex → **not** a signature (structural INVALID_INPUT).

### 0.4 Three-valued validation status

Many validators return `"VALID" | "INVALID" | "LIMIT"`. `mergeStatus` is
`LIMIT` if either is `LIMIT`, else `INVALID` if either is `INVALID`, else `VALID`.
`LIMIT` maps to `INDETERMINATE/INVALID_INPUT`; `INVALID` maps (in the raw path)
to `DENY/INVALID_DELEGATION`.

* `identifierStatus(v)`: non-string → INVALID. If it fails the 256 bound: `LIMIT`
  when `v.length > 256`, or when well-formed and UTF-8 bytes > 256; otherwise
  (malformed Unicode) INVALID. Then empty / control chars → INVALID, else VALID.
* `amountStatus(v)`: bigint outside `[-MAX_BIGINT, MAX_BIGINT]` → LIMIT; else
  `isAmount` ? VALID : INVALID (so a negative bigint ≥ −MAX_BIGINT is INVALID,
  a number is INVALID).
* `identifierListStatus(v, max, nonempty)`: not an array → INVALID; length > max →
  LIMIT; nonempty && length 0 → INVALID; each member `identifierStatus`, merged;
  a **duplicate** valid member → INVALID.

### 0.5 String ordering

Every sort in this engine uses `compareProtocolStrings`: compare UTF-8 byte
sequences lexicographically as unsigned bytes; shorter prefix first. So
`"Alpha" < "alpha" < "zeta"`, `"a" < "ab"`. It is *not* locale or UTF-16 order
(they differ for astral characters vs. U+E000–U+FFFF). The comparator throws a
TypeError for strings longer than 4096 UTF-8 bytes or malformed Unicode (cannot
happen for already-validated identifiers).

`compareIdentifierSequences(a, b)`: element-wise `compareProtocolStrings`; if
one is a prefix of the other, the shorter is less.

`sortedIdentifiers(list)` = copy sorted by `compareProtocolStrings` (no dedup).

### 0.6 Canonical encoding (used for hashing and the output re-capture)

`canonicalEncode(value)` (defined in `canonical.ts`, summarised here):
JSON-like text with no whitespace; record keys sorted by
`compareProtocolStrings`; fields whose value is `undefined` are omitted;
strings escaped with only `"`→`\"`, `\`→`\\`, code units `< 0x20` →
`\u00XX` (lowercase hex, 2 digits) and everything else (including non-ASCII)
emitted raw; numbers must be safe integers (decimal); `bigint` encodes as the
record `{"$continuity.bigint":"<decimal>"}`; `true/false/null` as usual.
`hashCanonical(v) = keccak256(utf8(canonicalEncode(v)))` as `0x` + 64 lowercase hex.

Every ALLOW and every DENY result (but not most INDETERMINATE results, see
§6.4) is passed through `captureBoundedCanonicalValue`, which returns a deep
frozen, **null-prototype** copy whose record keys are in canonical (sorted)
order. Consequently `Object.keys(result)` on an ALLOW is
`["consequential","decision","operationVersion","proof","scopeAssurance"]` and
on a DENY `["code","consequential","decision","failures","operationVersion","scopeAssurance"]`
**[verified]**. BigInts stay BigInts.

---

## 1. Data model (replay types the engine consumes)

```ts
PortableAuthorizationDomain = { protocol:"continuity"; version:"0.2"; deploymentId; chainId; verifyingContract }
PortableHistoryHead        = { hash: ContentHash; position: U53; canonicalTime: U53 }

PortableAuthorityConstraints = {
  actions: string[]; resources: string[];          // required, nonempty, ≤256, no duplicates
  quantitative: boolean;                            // required
  notBefore?: U53; expiresAt?: U53;                 // if both present: notBefore < expiresAt
  maxAmount?: Amount; maxCumulativeAmount?: Amount; // only allowed when quantitative === true
  maxTransactions?: U53;
  maxDelegationDepth: U53;                          // required
  requiredIntersectionIds: string[];                // required, ≤32, no duplicates (may be empty)
}
PortablePermissionGrant = { kind:"PERMISSION"; authorityId; grantorId; granteeId; rootAuthorityId;
                            parentAuthorityId?; independent: boolean; constraints }
PortableRootProhibitionGrant   = { kind:"PROHIBITION"; scope:"ROOT"; authorityId; grantorId; subjectActorId?;
                                   rootAuthorityId; parentAuthorityId?; constraints }
PortableGlobalProhibitionGrant = { kind:"PROHIBITION"; scope:"GLOBAL"; authorityId; grantorId; subjectActorId?; constraints }
PortableRecognizedRoot   = { rootAuthorityId; principalId; principalRecognitionEventId; rootGrantEventId }
PortableAuthorityUsage   = { authorityId; admittedTransactionCount: U53; admittedCumulativeAmount: Amount }
PortableAuthorityEvidence= { authorityId; grantEventId; grantEventPosition: U53 }
PortableAuthorityRecord  = { grant; grantEventId; grantEventPosition; revocationEventId?; revocationEventPosition?; revokerId? }
PortableAgentRecord      = { id; principalId; controllerId; currentControlEpoch; terminated: boolean }
PortablePrincipalRecord  = { id; creationEventId; creationEventPosition }
PortableRoleRecord       = { id; principalId; currentTenureId?; latestTenureNumber }
PortableRoleTenureRecord = { id; roleId; agentId; principalId; tenureNumber; successionRuleId?; closed: boolean; successionLock? }
PortableRuntimeSessionRecord = { id; agentId; controllerId; controlEpoch; credentialKeyId; credentialAddressKey /*lowercased address*/;
                                 admissionEventId; admissionEventPosition; expiresAt? }
PortableIntentDeclarationRecord = { data: PortableTransactionIntent }
PortableTransactionIntent = { adapterProfile; intentId; nonce; actorId; action; resource; roleId; roleTenureId;
                              amount?; counterpartyId?; termsCommitment? }
PortableIntentAdmissionRecord = { intentId; actorId; nonce; admissionEventId; admissionEventPosition; admissionHead;
                                  runtimeSessionId; credentialKeyId; controlEpoch; roleId; roleTenureId; adapterIdentity }
PortableNonceReservation = { intentId; admissionEventId; admissionEventPosition; admissionHead }
PortableGenesisRecord    = { adapterPolicyHash; domain; canonicalLineageId; versions; policyVersion;
                             rootRecognitionPolicy:"declared-principal-root/0.2"; globalPolicySourceId; timeSource; finality }
```

`PortableAuthorityReplayState` (what the engine reads from replay):
`events`, `eventHistoryHashes` (one prefix hash per accepted event; the last
equals `head.hash`), `head`, `genesis`, `principals`, `agents`, `roles`,
`tenures`, `runtimeSessions`, `intentDeclarations`, `intentAdmissions`,
`nonceReservationsByActor` (actorId → nonce → reservation), `authorities`
(authorityId → record), `recognizedRoots`, `authorityUsage`.

### 1.1 How replay builds the authority state (needed to reproduce decisions)

**[from source, portable-replay.ts]**, all cross-checked by experiments where noted.

* `head = { hash: eventHistoryHashes[last], position: events.length-1, canonicalTime: lastEvent.timestamp }`.
  Event timestamps must be non-decreasing (equal allowed **[verified]**).
* `PRINCIPAL_CREATED` → principal record (id must not collide with an existing
  principal, agent or reserved successor id).
* `AGENT_CREATED` → agent `{ currentControlEpoch: 1, terminated: false }`;
  `initialControlEpoch` must be 1; principal must exist; id must not be a principal.
* `CONTROL_EPOCH_ADVANCED` → `currentControlEpoch = toEpoch` (must be `fromEpoch+1`
  and `fromEpoch` must equal the current epoch; agent must be active).
* `AGENT_TERMINATED` → `terminated = true` (plus tenure lock). Termination does
  **not** touch grants or sessions.
* `RUNTIME_SESSION_ADMITTED` → session `{ credentialAddressKey: lowercase(credentialAddress), ... }`.
  Accepted only if agent active, `controllerId` matches, `controlEpoch ===
  agent.currentControlEpoch`, session id new, `credentialKeyId` globally unused,
  the address unused for that agent, and no other session of that agent in the
  same epoch is still unexpired at the event timestamp.
* `ROLE_CREATED` / `AGENT_APPOINTED` / `AGENT_UNAPPOINTED` / `ROLE_TRANSFERRED`
  maintain `roles.currentTenureId` and `tenures.closed`.
* `TRANSACTION_INTENT_DECLARED` → `intentDeclarations[intentId] = { data }`
  (intent id new; actor, role, tenure must exist; adapter profile valid for policy).
* `AUTHORITY_GRANTED` (data `{ grant }`), position = index of the event:
  * rejected if genesis missing, `authorityId` already used (**any** kind, even
    if revoked — **[verified]** `TRANSITION_INVALID`), or `notBefore >= expiresAt`.
  * PERMISSION: `grantorId` and `granteeId` must each be an existing principal
    **or** agent (terminated agents still count **[verified]**: a grant to a
    terminated agent replays). Every `requiredIntersectionIds` member must be an
    existing PERMISSION authority (so self-reference and forward references are
    rejected **[verified]**). No `parentAuthorityId` ⇒ `grantorId` must be a
    principal. With `parentAuthorityId` ⇒ parent must be an existing PERMISSION,
    the resulting path depth ≤ 32, `grantorId === parent.granteeId`,
    `rootAuthorityId === parent.rootAuthorityId`, and
    `constraintsAreAttenuated(parent.constraints, grant.constraints)` (§3.3).
  * PROHIBITION: constraints must have `requiredIntersectionIds.length === 0`,
    `maxDelegationDepth === 0`, no `maxCumulativeAmount`, no `maxTransactions`;
    `subjectActorId` (if present) must be an existing **agent**. GLOBAL ⇒
    `grantorId === genesis.globalPolicySourceId`. ROOT ⇒ `grantorId` is a
    principal or agent, `rootAuthorityId` must be a **recognized root**; if
    `grantorId === root.principalId` then no `parentAuthorityId` and
    `constraintsAreAttenuated(rootGrant.constraints, prohibition.constraints)`;
    otherwise `parentAuthorityId` required, parent must be a PERMISSION with the
    same `rootAuthorityId`, `parent.granteeId === grantorId`, and attenuated
    against the parent.
  * After acceptance: record stored; if PERMISSION with no `parentAuthorityId`
    **and** `authorityId === rootAuthorityId` **and** `grantorId` is a principal
    ⇒ `recognizedRoots[rootAuthorityId] = { rootAuthorityId, principalId: grantor,
    principalRecognitionEventId: principal.creationEventId, rootGrantEventId: event.id }`.
    If PERMISSION with `maxTransactions` or `maxCumulativeAmount` ⇒
    `authorityUsage[authorityId] = { authorityId, 0, 0n }`.
  * Consequence: a parent-less PERMISSION whose `authorityId !== rootAuthorityId`
    is accepted by replay but never becomes a recognized root (**[verified]**,
    see §8 trap 11).
* `AUTHORITY_REVOKED` (`{ authorityId, revokerId }`): record must exist and not
  already be revoked (re-revocation → `TRANSITION_INVALID` **[verified]**).
  GLOBAL prohibition ⇒ `revokerId === globalPolicySourceId`. Anything else ⇒
  its `rootAuthorityId` must be a recognized root and `revokerId ===
  root.principalId`, or (only when the grant has a `parentAuthorityId`)
  `revokerId === grant.grantorId` **[verified]**. Sets `revocationEventId`.
* `TRANSACTION_INTENT_ADMITTED` → validated by
  `validatePortableIntentAdmissionTransition` (§7.4); on success stores the
  admission record, reserves `(actorId, nonce)`, and **replaces**
  `authorityUsage[id]` for each capped controlling authority. This is the
  **only** event that changes usage. `TRANSACTION_INTENT_CONSUMED`,
  `TRANSACTION_OUTCOME_RECORDED`, `RECEIPT_RECORDED` never touch usage
  **[from source]**.

---

## 2. Public entry points and input capture

Public (via `core/index.ts`): `authorizePortable`, `evaluatePortableAuthorityPath`,
`createPortableRuntimeAuthorizationChallenge`, `hashPortableRuntimeAuthorizationChallenge`
plus the constants. Package-internal but specified here because they live in
the same file: `capturePortableAuthorityOperation`, `authorizeCapturedPortableState`,
`evaluateCapturedPortableIntentAdmissionState`, `validatePortableIntentAdmissionTransition`,
`evaluatePortableReceiptPolicy`, `createPortableAdministrativePolicyProof`,
`validatePortableAdministrativeTransition`, `recoverPortableContentHashSigner`,
`verifyPortableRuntimeAuthorizationSignature`, `portableEip191Digest`,
`portableIntentProjection`.

### 2.1 `PortableAuthorizeInput` (kind `AUTHORIZE`)

```ts
{
  operationVersion: "continuity-authorization/0.2";
  events: AcceptedCanonicalEventShape[];      // the full history, replayed inside the call
  expectedHistoryHead: PortableHistoryHead;   // pin
  domain: PortableAuthorizationDomain;
  policyVersion: string;                      // Identifier
  rootRecognitionPolicy: "declared-principal-root/0.2";
  request: PortableActionRequest;
  evaluationTime: number;                     // U53, >= head.canonicalTime
  authoritative: true;                        // literal true
  consequential: boolean;
  binding?: PortableConsequentialBinding;     // present  iff  consequential === true
}
PortableActionRequest = { actorId; action; resource; claimedAt: U53; amount?: Amount; counterpartyId?; termsCommitment?: ContentHash }
PortableConsequentialBinding = { runtimeSessionId; credentialKeyId?; controlEpoch: U53; roleId; roleTenureId;
                                 intentId?; nonce?; runtimeSignature?: Signature65 }
```

### 2.2 Outer capture (`captureAuthorityOuter`) — applies to all three kinds

Order of checks, first hit wins:

1. Input not a plain record (null, primitive, array, or prototype other than
   `Object.prototype`/`null`) ⇒ **throws `TypeError`** ("Portable authority input must be a plain record.") **[verified]** for `undefined, null, 42, "nope", []` and for an object with a custom prototype.
2. Any own symbol key ⇒ **throws `TypeError`** **[verified]**.
3. No own key `operationVersion` ⇒ `INDETERMINATE/INVALID_INPUT`.
4. `operationVersion` value (read via its descriptor — getters are invoked
   once) not a string, or > 4096 bytes / malformed ⇒ `INVALID_INPUT`.
5. `operationVersion !== expected` for the kind ⇒ `INDETERMINATE/UNSUPPORTED_VERSION`.
6. Key set must be exactly the required keys plus optionally `binding`
   (AUTHORIZE only). Required for AUTHORIZE: `operationVersion, events,
   expectedHistoryHead, domain, policyVersion, rootRecognitionPolicy, request,
   evaluationTime, authoritative, consequential`. Missing key or unknown key ⇒
   `INVALID_INPUT`. A required key whose value is `undefined` ⇒ `INVALID_INPUT`;
   an optional key whose value is `undefined` is treated as absent.
   For AUTHORITY_PATH_EVALUATION: `operationVersion, scope, request, permissions,
   prohibitions, authorityEvidence, revokedAuthorityIds, usage`, no optionals.
   For INTENT_ADMISSION: `operationVersion, events, expectedHistoryHead,
   admissionEventId, domain, policyVersion, request, evaluationTime, binding`.
7. The body is deep-captured (`captureBoundedCanonicalAuthorityOperationIncrementally`,
   mode STRUCTURAL_PHASE_ONE). Every nested object must be a plain record or a
   dense array; class instances, Maps, proxies etc. **throw `TypeError`**
   (e.g. "Canonical value at $.request is not a plain record." **[verified]**).
   Record keys whose value is `undefined` are remembered as *captured keys* but
   the captured record has no such own property (so `{ amount: undefined }`
   behaves as "amount absent" **[verified]**). Designated scalar slots
   (`claimedAt`, `amount`, `evaluationTime`, `controlEpoch`, `position`,
   `canonicalTime`, constraint numbers/amounts) accept any primitive but
   **throw `TypeError`** if given an object — in particular the JSON BigInt
   marker `{"$continuity.bigint":"5"}` as `request.amount` throws
   "Canonical designated scalar at $.request.amount has an unsupported host kind." **[verified]**
   (markers *inside events* are decoded normally). Identifier slots (`actorId`,
   `action`, `resource`, `counterpartyId`, `policyVersion`, `deploymentId`,
   binding ids, grant ids, list members) longer than 256 UTF-16 units or 256
   UTF-8 bytes raise a **limit** error ⇒ `INVALID_INPUT` (not `INVALID_REQUEST`)
   **[verified]** (`action` of 257 `a`s ⇒ INVALID_INPUT; 129 `é` = 258 bytes ⇒
   INVALID_INPUT; 128 `é` = 256 bytes ⇒ evaluated normally). Lists: `actions`/
   `resources` > 256 members, `requiredIntersectionIds` > 32, permissions +
   prohibitions > 1024 (raw path), any list > 4096, records > 256 fields,
   nesting > 32, total > 16 MiB ⇒ limit error ⇒ `INVALID_INPUT`.
   Capture failures classified as replay schema failures ⇒
   `STATE_NOT_AUTHORITATIVE` (AUTHORIZE/INTENT_ADMISSION only). Any other
   capture error is re-thrown.
   For AUTHORIZE / INTENT_ADMISSION the `events` array is reduced by the replay
   kernel *during* capture (one visit per event); the kernel remembers the
   first failure but capture continues.

### 2.3 `authorizePortable(input)` — façade order

```
outer/deep capture ─┬─ INVALID_INPUT / UNSUPPORTED_VERSION / STATE_NOT_AUTHORITATIVE (INDETERMINATE, SUPPLIED_SCOPE, evidence [])
structural check ───┴─ INVALID_INPUT                                     (before replay result is consulted!)
kernel.finish() ─── REJECTED: code ∈ {UNSUPPORTED_VERSION, UNSUPPORTED_EVENT_SCHEMA, UNSUPPORTED_EVENT_TYPE} ⇒ UNSUPPORTED_VERSION
                              otherwise (INVALID_INPUT, GENESIS_REQUIRED, GENESIS_DUPLICATE, EVENT_ID_DUPLICATE,
                              EVENT_TIME_REGRESSION, EVENT_DATA_INVALID, TRANSITION_INVALID) ⇒ STATE_NOT_AUTHORITATIVE
authorizeCapturedPortableState(capture, state)   (§4)
```

**[verified]**: `events: []` ⇒ STATE_NOT_AUTHORITATIVE; events missing genesis ⇒
STATE_NOT_AUTHORITATIVE; an event of unknown type ⇒ UNSUPPORTED_VERSION;
`events: {}` ⇒ INVALID_INPUT.

### 2.4 Structural check (`capturedPortableAuthorizeInputIsStructurallyValid`) ⇒ `INDETERMINATE/INVALID_INPUT` if any fails

* `events` is an array.
* `domain` is an exact record with keys `{protocol, version, deploymentId, chainId, verifyingContract}`,
  `protocol === "continuity"`, `version === "0.2"`, `deploymentId` Identifier,
  `chainId` ChainId, `verifyingContract` EthereumAddress (either case).
* `expectedHistoryHead` exact record `{hash, position, canonicalTime}`; hash
  ContentHash (lowercase — uppercase ⇒ INVALID_INPUT **[verified]**), position and
  canonicalTime U53 (`-0` ⇒ INVALID_INPUT **[verified]**).
* `policyVersion` Identifier (empty, control chars, > 256 ⇒ INVALID_INPUT).
* `rootRecognitionPolicy` Identifier (any identifier passes here; the literal is
  checked later ⇒ POLICY_MISMATCH).
* `request` exact record: required `{actorId, action, resource, claimedAt}`,
  optional `{amount, counterpartyId, termsCommitment}`; extra key or missing
  required key ⇒ INVALID_INPUT. **Values are not validated here** (bad values ⇒
  DENY `INVALID_REQUEST`/`INVALID_AMOUNT`, §4 step 5).
* `authoritative === true` (literal); `typeof consequential === "boolean"`.
* `hasOwn(body, "binding") === consequential` — binding present with
  `consequential:false`, or absent with `consequential:true` ⇒ INVALID_INPUT **[verified]**.
* If binding present: exact record required `{runtimeSessionId, controlEpoch,
  roleId, roleTenureId}` optional `{credentialKeyId, intentId, nonce,
  runtimeSignature}`; `runtimeSessionId/roleId/roleTenureId` Identifier,
  `controlEpoch` U53, optional ids Identifier, `runtimeSignature` Signature65
  (malformed/high-s/`v=00` ⇒ INVALID_INPUT **[verified]**).

"Exact record" (`exactRecord`) means: plain record; the *captured* key list
(which includes keys whose value was `undefined`) has length between
`required.length` and `required.length + optional.length`; every captured key
is required or optional; every required key is an *own* property (so a required
key set to `undefined` fails, an optional set to `undefined` is fine).

Note `evaluationTime` is **not** type-checked structurally: a string/NaN/2^53
`evaluationTime` reaches §4 step 2 and yields `CAUSAL_TIME_INVALID` **[verified]**.

---

## 3. The authority corpus, paths and attenuation

### 3.1 Corpus

```
AuthorityCorpus = { permissions: Map<id, PermissionGrant>; prohibitions: Map<id, ProhibitionGrant>;
                    roots: Map<id, RecognizedRoot>; evidence: Map<id, AuthorityEvidence>;
                    revoked: Set<id>; usage: Map<id, AuthorityUsage>; globalPolicySourceId;
                    replayAgents?; replayPrincipals?; replayRecords? }   // the replay* maps only in the replay path
```

`replayCorpus(state)`: iterate `state.authorities` in insertion (grant) order;
PERMISSION grants → `permissions`, others → `prohibitions`; `evidence[id] =
{authorityId, grantEventId, grantEventPosition}`; `revoked` = ids with a
`revocationEventId`; `roots = state.recognizedRoots`; `usage = state.authorityUsage`;
`globalPolicySourceId = genesis.globalPolicySourceId`; plus the three replay maps.
Grants are stored **as captured from the event** (constraint arrays keep their
event order — they are only sorted when written into a proof).

### 3.2 Path construction (`buildPermissionPath(terminal, permissions)`)

Walk `parentAuthorityId` links from the terminal upward:
* revisiting an id ⇒ `INVALID_DELEGATION` (cycle);
* 32 grants collected and another parent needed ⇒ `INVALID_INPUT`;
* parent id not in `permissions` ⇒ `INVALID_DELEGATION`.

Reverse to root-first order `grants[0..n)`. `effectivelyIndependent` = every
grant on the path has `independent === true`. For each `i ≥ 1` require
`grants[i].grantorId === grants[i-1].granteeId`,
`grants[i].rootAuthorityId === grants[i-1].rootAuthorityId`, and
`constraintsAreAttenuated(grants[i-1].constraints, grants[i].constraints)`;
else `INVALID_DELEGATION`. Result:
`{ rootAuthorityId: grants[0].rootAuthorityId, grants, authorityIds, effectivelyIndependent }`.
Note `rootAuthorityId` is taken from the first grant's *field*, not its
`authorityId`.

### 3.3 Attenuation (`constraintsAreAttenuated(parent, child)`) — engine version

Returns false (⇒ not attenuated) if any of:
* `child.actions ⊄ parent.actions` or `child.resources ⊄ parent.resources`
  (subset by exact string equality);
* `parent.requiredIntersectionIds ⊄ child.requiredIntersectionIds`
  (child must **inherit every** required intersection; it may add more);
* `parent.maxDelegationDepth === 0`;
* `child.maxDelegationDepth > parent.maxDelegationDepth - 1`;
* `parent.quantitative && !child.quantitative` (child may *become* quantitative under a non-quantitative parent **[verified]**);
* `parent.notBefore` defined and (`child.notBefore` undefined or `< parent.notBefore`);
* `parent.expiresAt` defined and (`child.expiresAt` undefined or `> parent.expiresAt`);
* `parent.maxAmount` defined and (`child.maxAmount` undefined or `> parent.maxAmount`);
* `parent.maxCumulativeAmount` defined and (child's undefined or greater);
* `parent.maxTransactions` defined and (child's undefined or greater).

So a child may not *drop* a parent's bound, may not widen sets, must lose at
least one delegation level. The replay-side copy additionally requires
`child.notBefore < child.expiresAt` when both present. Because a prohibition
must attenuate against its root/parent grant, **a ROOT prohibition can only be
attached under a grant with `maxDelegationDepth ≥ 1`** (`parent.maxDelegationDepth === 0` fails) **[verified]**: replay rejects a root prohibition on a depth-0 root with `TRANSITION_INVALID`.

### 3.4 Corpus validation (`validateAuthorityCorpus`)

1. Build a path for every permission (map order). First non-VALID status wins
   (`INVALID_INPUT` beats `INVALID_DELEGATION` only in the sense that once
   INVALID_INPUT is seen the loop stops; otherwise the first failure's code is
   returned).
2. `validateIntersectionGraph`: DFS over `requiredIntersectionIds` edges
   restricted to ids that are permissions; a cycle ⇒ `INVALID_DELEGATION`.
   (Unknown ids are ignored here.)
3. Then a single boolean `valid`, any failure ⇒ `INVALID_DELEGATION`:
   * `evidence.size === permissions.size + prohibitions.size`, every permission
     and prohibition has evidence, every evidence id is a permission or prohibition.
   * For every recognized root `r`: `permissions[r.rootAuthorityId]` exists, has
     evidence, has no `parentAuthorityId`, `authorityId === r.rootAuthorityId`,
     `rootAuthorityId === r.rootAuthorityId`, `grantorId === r.principalId`,
     `evidence.grantEventId === r.rootGrantEventId`. In the replay path also:
     principal exists, `r.principalRecognitionEventId === principal.creationEventId`,
     `r.rootGrantEventId === record.grantEventId`,
     `evidence.grantEventPosition === record.grantEventPosition`.
   * Every prohibition: GLOBAL ⇒ `grantorId === globalPolicySourceId`. ROOT ⇒ its
     `rootAuthorityId` is a recognized root; if `grantorId === root.principalId`
     ⇒ no `parentAuthorityId`, root grant exists, attenuated vs root grant;
     else `parentAuthorityId` required, parent permission and its path exist,
     `parent.granteeId === grantorId`, `path.rootAuthorityId === rootAuthorityId`,
     attenuated vs parent.
   * Every revoked id is a permission or prohibition.
   * `usage` keys must be **exactly** the set of permissions having
     `maxTransactions` or `maxCumulativeAmount` (extra ⇒ invalid, missing ⇒ invalid).

Returns `{ corpus, paths: Map<terminalId, PermissionPath> }`.

For replay-derived state these checks always pass in practice (replay enforces
the same rules), so `INVALID_DELEGATION` is practically unreachable via
`authorizePortable`; it is reachable via `evaluatePortableAuthorityPath`.

### 3.5 Root recognition (`recognizedRootForPath`) — policy `declared-principal-root/0.2`

A path is *recognized* iff `roots[path.rootAuthorityId]` exists and the path's
first grant `g0` satisfies `g0.authorityId === root.rootAuthorityId`,
`g0.rootAuthorityId === root.rootAuthorityId`, `g0.grantorId === root.principalId`,
and `g0.parentAuthorityId` is absent. In replay terms: the root of the chain
must be a parent-less permission granted **by a principal** whose
`authorityId === rootAuthorityId`. A path whose chain starts at a parent-less
grant with `authorityId !== rootAuthorityId` is unrecognized ⇒ candidate fails
with `NO_AUTHORITY`, `failingAuthorityId = path.rootAuthorityId` (the *field*
value) **[verified]**.

### 3.6 Combining constraints (`combineConstraints(grants)`)

Over the grants in the given order:
* `actions` = intersection, **order = order of the first grant's sorted list**
  (first list is sorted via `sortedIdentifiers`, later lists filter it) — so the
  result is sorted **[verified]**; likewise `resources`;
* `quantitative` = OR;
* `notBefore` = max of present values; `expiresAt`, `maxAmount`,
  `maxCumulativeAmount`, `maxTransactions`, `maxDelegationDepth` = min of
  present values (`maxDelegationDepth` always present; result `?? 0`);
* `requiredIntersectionIds` = sorted union.
Absent optionals stay absent. Field order in the produced record:
`actions, resources, quantitative, notBefore?, expiresAt?, maxAmount?,
maxCumulativeAmount?, maxTransactions?, maxDelegationDepth, requiredIntersectionIds`
(irrelevant after canonical re-capture, which sorts keys).

### 3.7 Normalized grants in proofs

`normalizedConstraints`: same fields, `actions`/`resources`/`requiredIntersectionIds`
sorted (no dedup — duplicates cannot exist by then). `normalizedPermission`:
`{kind:"PERMISSION", authorityId, grantorId, granteeId, rootAuthorityId,
parentAuthorityId?, independent, constraints: normalized}` — unknown keys dropped.
`normalizedRequest`: `{actorId, action, resource, claimedAt, amount?,
counterpartyId?, termsCommitment?}` (optionals only when present).
`normalizedDomain`: the five domain fields, verifyingContract **as given**
(not lowercased).

---

## 4. Replay-bound decision procedure (`stagePortableStateAuthorization`)

Input: `state` (replay), `body` = `{ expectedHistoryHead, domain, policyVersion,
rootRecognitionPolicy, request, evaluationTime, consequential, binding? }`,
optional `administrativeRequirements`. `operationVersion =
"continuity-authorization/0.2"` on every result.

Let `headRef = replayEventReference(last event)`, `genesisRef =
replayEventReference(event 0)` where
`replayEventReference(i) = { kind:"EVENT", eventId: events[i].id, eventType:
events[i].type, position: i, historyHash: state.eventHistoryHashes[i] }`.
Throws TypeError if `eventHistoryHashes.length !== events.length` or the last
hash ≠ `head.hash` (cannot happen with a genuine replay state).

Steps in order (first hit returns):

1. **Head pin.** `expectedHistoryHead` must equal `state.head` in all of
   `hash`, `position`, `canonicalTime` ⇒ else
   `INDETERMINATE / HISTORY_RELATION_UNVERIFIED`, `scopeAssurance:"SUPPLIED_SCOPE"`,
   `failures: [{ code, evidence: [headRef] }]` **[verified]**.
2. **Causal time.** `!isU53(evaluationTime) || evaluationTime < head.canonicalTime`
   ⇒ `INDETERMINATE / CAUSAL_TIME_INVALID`, `SUPPLIED_SCOPE`, evidence `[headRef]`.
   `evaluationTime === head.canonicalTime` is allowed **[verified]**.
   From here `scopeAssurance = "REPLAY_VERIFIED"` for DENY/ALLOW.
3. **Domain.** `sameDomain(domain, genesis.domain)`: `protocol`, `version`,
   `deploymentId`, `chainId` exact; `verifyingContract` compared
   **case-insensitively** ⇒ else `DENY / DOMAIN_MISMATCH`, single failure
   `{ code, authorityPathIds: [], evidence: [genesisRef] }` (no subjectId).
4. **Policy.** `policyVersion !== genesis.policyVersion ||
   rootRecognitionPolicy !== genesis.rootRecognitionPolicy` ⇒
   `DENY / POLICY_MISMATCH`, evidence `[genesisRef]`.
   (`genesis.rootRecognitionPolicy` is always the literal.)
5. **Request values** (`requestProblem`): in order, `actorId`, `action`,
   `resource` Identifier; `claimedAt` U53; `counterpartyId` (if own) Identifier;
   `termsCommitment` (if own) ContentHash ⇒ else `DENY / INVALID_REQUEST`,
   failure `{ code, authorityPathIds: [], evidence: [] }`. Then `amount` (if
   own) must be Amount ⇒ else `DENY / INVALID_AMOUNT` (same shape).
   `INVALID_REQUEST` wins over `INVALID_AMOUNT` when both apply **[verified]**.
   Note: a `number` amount, negative bigint or bigint > 2^256−1 ⇒ INVALID_AMOUNT
   **[verified]**.
6. **Corpus.** `validateAuthorityCorpus(replayCorpus(state))`:
   `INVALID_INPUT` ⇒ `INDETERMINATE / STATE_NOT_AUTHORITATIVE`, **SUPPLIED_SCOPE**,
   evidence `[]`; `INVALID_DELEGATION` ⇒ `DENY / INVALID_DELEGATION` with
   evidence `authorityDecisionEvidence` (§6.2). (Both practically unreachable
   from replay.)
7. **Actor.** `agent = state.agents.get(request.actorId)`; missing **or**
   `terminated` ⇒ `DENY / AGENT_INACTIVE`, failure
   `{ code, subjectId: actorId, authorityPathIds: [], evidence:
   agentLifecycleEvidence(actorId) }`. Principals are not agents ⇒ a principal
   as actor gets AGENT_INACTIVE **[verified]**. An unknown actor gets evidence
   `[headRef]` only.
8. **Runtime binding** (only when `consequential && binding !== undefined`;
   all denials use `subjectId` as noted and evidence
   `sessionLifecycleEvidence(actorId, binding.runtimeSessionId)` unless stated):
   1. `session = runtimeSessions.get(binding.runtimeSessionId)`; missing or
      `session.agentId !== agent.id` ⇒ `SESSION_NOT_FOUND` (subject = session id).
   2. `session.expiresAt` defined and `evaluationTime >= session.expiresAt` ⇒
      `SESSION_EXPIRED` (exclusive bound **[verified]**).
   3. `binding.credentialKeyId` or `binding.runtimeSignature` absent ⇒
      `SESSION_CREDENTIAL_REQUIRED`.
   4. `credentialKeyId !== session.credentialKeyId` ⇒ `SESSION_CREDENTIAL_INVALID`.
   5. If **both** `intentId` and `nonce` present: build the challenge (§5.1)
      with `historyHead: state.head` and verify the signature against
      `session.credentialAddressKey`; failure ⇒ `SESSION_CREDENTIAL_INVALID`.
      If either is absent the signature is **not** verified here.
   6. `session.controlEpoch < agent.currentControlEpoch` ⇒ `SESSION_FENCED`
      (checked before the binding epoch; a binding claiming the new epoch still
      gets SESSION_FENCED **[verified]**).
   7. `binding.controlEpoch !== session.controlEpoch || binding.controlEpoch !==
      agent.currentControlEpoch` ⇒ `STALE_EPOCH`.
   8. `role = roles.get(binding.roleId)`, `tenure = tenures.get(binding.roleTenureId)`;
      missing role or tenure, `role.currentTenureId !== binding.roleTenureId`,
      `tenure.closed`, `tenure.roleId !== binding.roleId`, or
      `tenure.agentId !== agent.id` ⇒ `ROLE_TENURE_NOT_CURRENT`, subject =
      roleTenureId, evidence `tenureLifecycleEvidence(roleId, roleTenureId)`.
   9. `intentId` or `nonce` absent ⇒ `INTENT_REQUIRED`, subject = actorId,
      evidence `intentDecisionEvidence(actorId)`.
   10. `intentDeclarations.get(intentId)` missing ⇒ `INTENT_NOT_DECLARED`,
       subject = intentId, evidence `intentDecisionEvidence(actorId, intentId, nonce)`.
   11. `!sameIntent(declaration.data, portableIntentProjection(request, binding,
       declaration.data.adapterProfile))` ⇒ `INTENT_MISMATCH` (same subject/evidence).
       `sameIntent` compares `intentId, nonce, actorId, action, resource, roleId,
       roleTenureId` and the optional `amount, counterpartyId, termsCommitment`
       by presence-and-value (`===`, so bigint equality). `claimedAt` is *not*
       part of the intent.
   12. `intentAdmissions.has(intentId)` ⇒ `INTENT_REPLAY` (same subject/evidence).
9. **Authority algebra** (§4.1) with context `{ operationVersion, assurance:
   REPLAY_VERIFIED, validated, domain (as given), policyVersion, historyHead:
   state.head, evaluationTime, request, consequential, binding?, replayEvidence,
   administrativeRequirements? }`.
10. (in `authorizePortableState`) If the algebra returned an ALLOW candidate and
    `consequential && binding.nonce` defined and
    `nonceReservationsByActor[actorId]` has that nonce ⇒
    `DENY / NONCE_ALREADY_ADMITTED`, subject = nonce, evidence
    `intentDecisionEvidence(actorId, binding.intentId, nonce)` **[verified]**.
    Otherwise finalize (§6.3).

### 4.1 Authority algebra (`evaluateAuthorityAlgebra`)

Let `decisionEvidence = authorityDecisionEvidence(ctx)` in the replay path, `[]`
in the raw path.

**A. Global prohibitions.** `relevantGlobalProhibitions` = all GLOBAL
prohibitions with `prohibitionRequestRelevant` (§4.3), sorted by `authorityId`.
`matching` = those that are `prohibitionIsActive` (§4.4) **and**
`prohibitionMatchesAmount` (§4.5). If any ⇒
```
DENY / PROHIBITED, failures: [{ code:"PROHIBITED", subjectId: actorId,
  failingAuthorityId: least matching id, authorityPathIds: [], evidence: decisionEvidence }]
```
This happens **before** candidate enumeration, so an actor holding no grant at
all is `PROHIBITED` rather than `NO_AUTHORITY` **[verified]**, but after
`AGENT_INACTIVE` **[verified]**.

**B. Candidates.** Iterate `validated.paths` (map order = permission order);
a path is a candidate iff `path.effectivelyIndependent` (every grant on it has
`independent: true`) **and** `terminal.granteeId === request.actorId` (and, if
`administrativeRequirements` given, §7.5 holds). A grant with
`independent: false` anywhere on the chain is never a main candidate.

**C. Evaluate each candidate** (§4.2). Successful ones become
`SuccessfulAuthorityCandidate`s; the winner is the minimum under
`compareSuccessfulCandidates` (§4.6). If a winner exists ⇒ ALLOW candidate.

**D. No candidates at all** ⇒ `DENY / NO_AUTHORITY`, failure
`{ code, subjectId: actorId, authorityPathIds: [], evidence: decisionEvidence }`.

**E. Otherwise** one failure **per failed candidate main path**:
```
{ code: evaluation.code, rootAuthorityId: path.rootAuthorityId, terminalAuthorityId: terminal.authorityId,
  failingAuthorityId: evaluation.failingAuthorityId, authorityPathIds: path.authorityIds, evidence: decisionEvidence }
```
sorted by `compareDenialEvidence` (§6.1); `result.code = failures[0].code`.

### 4.2 Candidate evaluation (`evaluateCandidate(validated, main, request, evaluationTime, globalProhibitions)`)

1. `recognizedRootForPath(main)` undefined ⇒ FAILURE `NO_AUTHORITY`,
   `failingAuthorityId = main.rootAuthorityId` (no graph).
2. `graph = selectCandidateGraph(validated, main, actorId)` (§4.7): main path,
   selected intersection paths, `missingIntersectionIds`.
3. Prohibitions: `checked` = ids of all relevant global prohibitions (regardless
   of activity) ∪ ids of `relevantCandidateProhibitions` (§4.8, regardless of
   activity). `matchingProhibitions` = candidate (ROOT) prohibitions that are
   active and match the amount. If non-empty ⇒ FAILURE `PROHIBITED`,
   `failingAuthorityId` = least id (byte order), graph attached.
4. Otherwise compute, over **every grant of every path in the graph** (main +
   selected partners), the following id sets:
   * `revoked`: id ∈ corpus.revoked
   * `notYetValid`: `notBefore` defined and `evaluationTime < notBefore`
   * `expired`: `expiresAt` defined and `evaluationTime >= expiresAt`
   * `actionFailures`: `request.action ∉ constraints.actions` (exact string)
   * `resourceFailures`: `request.resource ∉ constraints.resources`
   * `amountRequired`: `constraints.quantitative && amount === undefined`
   * `amountExceeded`: `maxAmount` defined, amount defined, `amount > maxAmount`
   * `cumulativeExceeded`: usage entry exists, `maxCumulativeAmount` defined,
     amount defined, `usage.admittedCumulativeAmount + amount > maxCumulativeAmount`
   * `transactionExceeded`: usage exists, `maxTransactions` defined,
     `usage.admittedTransactionCount >= maxTransactions` (independent of amount)
   * `inactiveAgent`: replay path only — grantor or grantee of the grant is a
     terminated agent.
   Plus `missingIntersectionFailures = graph.missingIntersectionIds`.
5. Return the first non-empty set in this fixed order, with
   `failingAuthorityId` = its least member:
   `REVOKED, NOT_YET_VALID, EXPIRED, MISSING_INTERSECTION, ACTION_NOT_ALLOWED,
   RESOURCE_NOT_ALLOWED, AMOUNT_REQUIRED, AMOUNT_EXCEEDED, CUMULATIVE_AMOUNT_EXCEEDED,
   TRANSACTION_COUNT_EXCEEDED, NO_AUTHORITY` (the last is the terminated-agent case).
6. Else SUCCESS with `checkedProhibitionIds = sorted(checked)`.

Time semantics: `notBefore` **inclusive** (`evaluationTime >= notBefore` valid),
`expiresAt` **exclusive** (`evaluationTime >= expiresAt` expired) **[verified]**
at 9/10/19/20. `request.claimedAt` is **never** consulted **[verified]**.

Examples **[verified]**: a path whose grant is both expired and lacks the action
⇒ `EXPIRED`; both root and delegate exceed `maxAmount` ⇒ `failingAuthorityId` is
the byte-least id (`"del" < "root"`); cumulative and count both exceeded ⇒
`CUMULATIVE_AMOUNT_EXCEEDED`.

### 4.3 `prohibitionRequestRelevant(p, request)`

`(p.subjectActorId undefined || === request.actorId) && request.action ∈
p.constraints.actions && request.resource ∈ p.constraints.resources &&
(!p.constraints.quantitative || request.amount !== undefined)`.
A quantitative prohibition is simply *not relevant* (not checked, not listed)
to a request without an amount **[verified]**.

### 4.4 `prohibitionIsActive(validated, p, evaluationTime)`

false if revoked or outside `[notBefore, expiresAt)`. GLOBAL ⇒ true. ROOT
without `parentAuthorityId` ⇒ true. ROOT with `parentAuthorityId` ⇒ the anchor
path `validated.paths[parentAuthorityId]` must exist and
`permissionPathActive(anchor, evaluationTime, parentAuthorityId)`: every grant
from the anchor's root down to and including the anchor grant is not revoked,
within its time window, and (replay) not tied to a terminated agent.
Revoking the anchor deactivates the prohibition — but the path through the
anchor is then `REVOKED` anyway (`tests/revocation-context.test.mjs`, **[verified]**).

### 4.5 `prohibitionMatchesAmount(p, request)`

`p.constraints.maxAmount === undefined || (amount !== undefined && amount <= maxAmount)`.
**Counter-intuitive**: a prohibition with `maxAmount: 10` blocks amounts `≤ 10`
and does *not* block `11` **[verified]**.

### 4.6 Winner selection (`compareSuccessfulCandidates(a, b)`), smaller wins

1. `recognizedRoot.rootAuthorityId` (byte order);
2. `main.authorityIds` sequence (`compareIdentifierSequences`; a prefix is
   smaller, so root `[root]` beats `[root, del]` for the same actor **[verified]**);
3. intersections pairwise (`compareCandidateIntersectionPlans`: requiredAuthorityId,
   requiredByAuthorityIds sequence, partner root id, partner path ids, then
   `hashCanonical(effectiveConstraints)` of the partner); fewer intersections
   smaller when one list is a prefix;
4. `hashCanonical(effectiveConstraints)` of the whole candidate.

A winner beats any failing candidate: prohibitions/revocations on other paths
do not matter if one path succeeds **[verified]**.

### 4.7 Intersection graph (`selectCandidateGraph(validated, main, actorId)`)

`directRequiredIds(path, i)` = for `i === 0` the grant's
`requiredIntersectionIds`; for `i > 0` the ids **not already present in the
parent grant's** `requiredIntersectionIds` (inherited requirements are
attributed to the ancestor that introduced them).

BFS: `queue` seeded with the direct ids of every grant in `main` (each id
recorded in `requiredBy[id] += grant.authorityId`). For each queued id:
`path = validated.paths[id]` (the id must be a **terminal**, i.e. a permission
id); `root = recognizedRootForPath(path)`; `terminal = last grant`. The id is
**missing** if the path/root/terminal is undefined, **or `path.effectivelyIndependent`
is true**, **or `terminal.granteeId !== actorId`**. Otherwise select it (first
time only), and enqueue its own direct ids.

So an intersection partner must be held by the **same actor** and its chain
must contain **at least one `independent: false` grant** — an `independent:
true` partner is reported `MISSING_INTERSECTION` **[verified]**. (Conversely an
`independent:false` grant can *only* be used as a partner.)

Output: `paths = [main, ...selected in byte order of id]`, `intersections =
[{ requiredAuthorityId, requiredByAuthorityIds: sorted, path, recognizedRoot }]`
in that order, `missingIntersectionIds` sorted.

### 4.8 Root prohibitions applying to a graph (`relevantCandidateProhibitions`)

A ROOT prohibition applies iff its `rootAuthorityId` is the `rootAuthorityId`
of **any** path in the graph (main or partner) and, if it has a
`parentAuthorityId`, some graph path with that root **contains** the anchor id
in its `authorityIds`; and it is request-relevant (§4.3). Sorted by id. All
applying prohibitions are listed in `checkedProhibitionIds` even if expired or
revoked **[verified]** (an expired one still appears in the proof and its
grant event lands in `authorityEvidence`).

---

## 5. Runtime authorization challenge and signatures

### 5.1 `createPortableRuntimeAuthorizationChallenge({ domain, request, evaluationTime, policyVersion, historyHead, binding })`

Throws `TypeError("Runtime authorization challenge requires credential, intent, and nonce identifiers.")`
if `binding.credentialKeyId`, `binding.intentId` or `binding.nonce` is absent.
Otherwise returns (insertion order shown; canonical hashing sorts keys anyway):

```json
{ "version": "continuity-runtime-authorization/0.2",
  "domain": { "protocol","version","deploymentId","chainId","verifyingContract" },   // verifyingContract as supplied
  "request": { "actorId","action","resource","claimedAt", "amount"?, "counterpartyId"?, "termsCommitment"? },
  "authoritative": true, "consequential": true,
  "evaluationTime": <U53>, "policyVersion": "<string>",
  "rootRecognitionPolicy": "declared-principal-root/0.2",
  "eventHistoryHash": historyHead.hash, "eventHistoryPosition": historyHead.position,   // canonicalTime NOT included
  "runtimeSessionId", "credentialKeyId", "controlEpoch", "roleId", "roleTenureId", "intentId", "nonce" }
```
`runtimeSignature` is never part of the challenge. **[verified]** sample in the
experiments matches this exactly (with `amount` present as a bigint).

`hashPortableRuntimeAuthorizationChallenge(c) = hashCanonical(c)`, e.g. the
canonical text begins `{"authoritative":true,"consequential":true,"controlEpoch":1,"credentialKeyId":"K1","domain":{"chainId":"31337",...`
and an amount is encoded `"amount":{"$continuity.bigint":"60"}`.

### 5.2 Signing scheme `eip191-personal-sign-keccak256`

`portableEip191Digest(hash)`: `keccak256( 0x19 ‖ "Ethereum Signed Message:\n32" ‖ bytes32(hash) )`
— the 28-byte prefix is exactly
`19 45 74 68 65 72 65 75 6d 20 53 69 67 6e 65 64 20 4d 65 73 73 61 67 65 3a 0a 33 32`.
**[verified]** identical to viem's `hashMessage({ raw: hash })`, i.e. a wallet
`personal_sign` over the 32 raw hash bytes. The hash string must be a
ContentHash (else TypeError).

`recoverPortableContentHashSigner(hash, sig)` → lowercase `0x` + 40 hex address
or `undefined`:
* `isContentHash(hash) && isSignature65(sig)` else undefined.
* `r`, `s` from the hex; `recovery = (sig[130..132) === "1b") ? 0 : 1`.
* `e = digest mod n`; `y² = r³ + 7 mod p`; `yRoot = (y²)^((p+1)/4) mod p`; if
  `yRoot² ≠ y²` ⇒ undefined; `y = (yRoot odd) === (recovery === 1) ? yRoot : p − yRoot`;
  `R = (r, y)`; `Q = (s·r⁻¹)·R + ((n − e)·r⁻¹)·G` (Jacobian arithmetic, then
  affine; point at infinity or off-curve ⇒ undefined);
  address = `0x` + last 40 hex chars of `keccak256(x‖y)` (64-byte uncompressed key, no 04 prefix).
* Any exception ⇒ undefined.

`verifyPortableRuntimeAuthorizationSignature(expectedAddress, challenge, sig)`:
`isEthereumAddress(expectedAddress) && isSignature65(sig)` and
`recover(hashCanonical(challenge), sig) === lowercase(expectedAddress)`.
The engine passes `session.credentialAddressKey` (already lowercase).

**[verified]** outcomes in `authorizePortable` (consequential, intent + nonce present):
correct signer ⇒ ALLOW; well-formed signature by another key, or over a
different request/head ⇒ `SESSION_CREDENTIAL_INVALID`; flipped `v` ⇒
`SESSION_CREDENTIAL_INVALID`; uppercase hex, `v=00`, high-s ⇒ structural
`INDETERMINATE/INVALID_INPUT`.

### 5.3 Where signatures are verified

* `stagePortableStateAuthorization` step 8.5 (only when intentId and nonce present).
* `validatePortableIntentAdmissionTransition` (§7.4): the stored
  `runtimeSignature` must verify against the challenge rebuilt from the proof
  with `historyHead = state.head`, and `data.runtimeAuthorizationHash` must equal
  the challenge hash.
* `validatePortableAdministrativeTransition` (§7.6): `recover(hashCanonical(challenge), wrapper.runtimeSignature) === session.credentialAddressKey`.

---

## 6. Results, proofs, failures and evidence

### 6.1 Result union

```ts
| { operationVersion; decision:"ALLOW"; scopeAssurance:"SUPPLIED_SCOPE"|"REPLAY_VERIFIED"; consequential: boolean; proof }
| { operationVersion; decision:"DENY"; scopeAssurance; consequential:false; code: PortableDenialCode; failures: PortableDenialEvidence[] }
| { operationVersion; decision:"INDETERMINATE"; scopeAssurance; consequential:false; code: PortableIndeterminateCode; failures: PortableIndeterminateEvidence[] }
PortableDenialEvidence        = { code; subjectId?; rootAuthorityId?; terminalAuthorityId?; failingAuthorityId?; authorityPathIds: string[]; evidence: PortableEvidenceReference[] }
PortableIndeterminateEvidence = { code; subjectId?; evidence }
PortableEvidenceReference     = { kind:"EVENT"; eventId; eventType; position; historyHash }
```
`operationVersion` is `"continuity-authorization/0.2"` for `authorizePortable`
and admission; `"continuity-authority-evaluation/0.2"` for
`evaluatePortableAuthorityPath`. `consequential` on ALLOW echoes the input;
on DENY/INDETERMINATE it is always `false`.

**Denial codes (30)** and their single trigger site:
`DOMAIN_MISMATCH`, `POLICY_MISMATCH`, `INVALID_REQUEST`, `INVALID_AMOUNT`,
`INVALID_DELEGATION` (§4 steps 3–6 / §7.1), `AGENT_INACTIVE` (step 7),
`SESSION_NOT_FOUND`, `SESSION_EXPIRED`, `SESSION_CREDENTIAL_REQUIRED`,
`SESSION_CREDENTIAL_INVALID`, `SESSION_FENCED`, `STALE_EPOCH`,
`ROLE_TENURE_NOT_CURRENT`, `INTENT_REQUIRED`, `INTENT_NOT_DECLARED`,
`INTENT_MISMATCH`, `INTENT_REPLAY` (step 8), `NONCE_ALREADY_ADMITTED` (step 10),
`PROHIBITED` (global §4.1A or candidate §4.2.3), `REVOKED`, `NOT_YET_VALID`,
`EXPIRED`, `MISSING_INTERSECTION`, `ACTION_NOT_ALLOWED`, `RESOURCE_NOT_ALLOWED`,
`AMOUNT_REQUIRED`, `AMOUNT_EXCEEDED`, `CUMULATIVE_AMOUNT_EXCEEDED`,
`TRANSACTION_COUNT_EXCEEDED` (§4.2.5), `NO_AUTHORITY` (no candidates,
unrecognized root, or terminated grant party).

**Indeterminate codes (8)**: `INVALID_INPUT`, `UNSUPPORTED_VERSION`,
`OUTPUT_LIMIT_EXCEEDED`, `STATE_NOT_AUTHORITATIVE`, `CAUSAL_TIME_INVALID`,
`HISTORY_RELATION_UNVERIFIED`, `EVIDENCE_UNAVAILABLE`, `EVIDENCE_DISPUTED`
(the last two are declared but **never emitted** by this file).

**Failure ordering** (`compareDenialEvidence`, applied to every multi- or
single-entry DENY): rank of `code` in
`PROHIBITED:0, REVOKED:1, NOT_YET_VALID:2, EXPIRED:3, MISSING_INTERSECTION:4,
ACTION_NOT_ALLOWED:5, RESOURCE_NOT_ALLOWED:6, AMOUNT_REQUIRED:7,
AMOUNT_EXCEEDED:8, CUMULATIVE_AMOUNT_EXCEEDED:9, TRANSACTION_COUNT_EXCEEDED:10,
NO_AUTHORITY:11`, any other code `-1`; then `rootAuthorityId` (undefined
first, then byte order), `terminalAuthorityId`, `failingAuthorityId`,
`authorityPathIds` sequence, `subjectId`, then the evidence sequence
(`compareEvidenceReferences` element-wise, shorter first). The headline `code`
is `failures[0].code` — i.e. **the lowest-ranked code across all candidate
paths, not the "most relevant" one** (FINDING-006 in `quantitative.test.mjs`;
conformance vector `authorization/unknown-resource-refused` expects
`ACTION_NOT_ALLOWED` headline with failures `["ACTION_NOT_ALLOWED","RESOURCE_NOT_ALLOWED"]`).

### 6.2 Evidence assembly and ORDER

All evidence lists are produced by `evidenceForEventPredicate`: collect
`replayEventReference(i)` for every event `i` satisfying the predicate, **always
append the head event** (last position), then sort by
`compareEvidenceReferences` = (`eventId` byte order, `eventType` byte order,
`position` numeric, `historyHash`) and drop adjacent duplicates. Hence evidence
is **ordered by event id string, not by position** **[verified]** (e.g.
`first-look:a`(2), `first-look:admission`(14), `first-look:b`(3), …).

Predicates:
* `authorityDecisionEvidence`: `type ∈ {DEPLOYMENT_INITIALIZED, PRINCIPAL_CREATED,
  AGENT_CREATED, AGENT_TERMINATED, AUTHORITY_GRANTED, AUTHORITY_REVOKED,
  TRANSACTION_INTENT_ADMITTED}` (all of them, not filtered by actor) — used for
  every candidate-path failure, `NO_AUTHORITY`, global `PROHIBITED`, `INVALID_DELEGATION`.
* `agentLifecycleEvidence(actorId)`: `AGENT_CREATED|AGENT_TERMINATED` with `data.agentId === actorId`.
* `sessionLifecycleEvidence(actorId, sessionId)`: agent lifecycle for the actor
  **or** `RUNTIME_SESSION_ADMITTED|CONTROL_EPOCH_ADVANCED` with
  `data.agentId === actorId || data.sessionId === sessionId`.
* `tenureLifecycleEvidence(roleId, tenureId)`: `ROLE_CREATED|AGENT_APPOINTED|
  AGENT_UNAPPOINTED|ROLE_TRANSFERRED` with `data.roleId === roleId ||
  data.roleTenureId === tenureId || data.fromRoleTenureId === tenureId ||
  data.toRoleTenureId === tenureId`.
* `intentDecisionEvidence(actorId, intentId?, nonce?)`: only
  `TRANSACTION_INTENT_DECLARED` / `TRANSACTION_INTENT_ADMITTED`. Values: for
  DECLARED `{intentId: data.intentId, actorId: data.actorId, nonce: data.nonce}`;
  for ADMITTED `{intentId: data.intentId, actorId: data.authorizationProof.request.actorId,
  nonce: data.authorizationProof.nonce}`. Include if
  (`intentId === undefined ? values.actorId === actorId : values.intentId === intentId`)
  **or** (`nonce !== undefined && values.actorId === actorId && values.nonce === nonce`).
* `collidingEventEvidence(eventId)` (admission only): the first event with that
  id plus the head.
* Simple denials `DOMAIN_MISMATCH`/`POLICY_MISMATCH`: `[genesisRef]`;
  `INVALID_REQUEST`/`INVALID_AMOUNT`: `[]`; head-pin/causal indeterminates: `[headRef]`.

`historyHash` for position `i` is `state.eventHistoryHashes[i]` — the replay
prefix commitment (`keccak256` of `["continuity-event-history/0.2",[e0,…,ei]]`
canonical text); at the head it equals `head.hash`.

Every DENY/INDETERMINATE result whose total evidence count (sum over failures)
exceeds 4096 becomes `INDETERMINATE / OUTPUT_LIMIT_EXCEEDED` (same
operationVersion/assurance, evidence `[]`).

### 6.3 ALLOW proof (`proofForCandidate`) — exact contents

Preflight (`preflightCandidateProof`) ⇒ `INDETERMINATE/OUTPUT_LIMIT_EXCEEDED`
if: main path empty or > 32; intersections > 256; checkedProhibitionIds > 256;
effective constraints have > 256 actions/resources/requiredIntersectionIds; any
path in the graph empty or > 32 grants, or any grant's constraints > 256
actions/resources or > 32 requiredIntersectionIds; distinct controlling ids >
256; any intersection with empty or > 256 `requiredByAuthorityIds` or oversized
effective constraints; usage entries > 256; evidence ids > 1024.

```ts
proof = {
  proofVersion: "continuity-authorization-proof/0.2",
  domain,                       // as given in the input (NOT normalized/lowercased)
  policyVersion,                // as given
  rootRecognitionPolicy: "declared-principal-root/0.2",
  historyHead,                  // state.head (replay) / scope.historyHead (raw)
  evaluationTime,
  request: normalizedRequest(request),
  recognizedRoot,               // the main path's recognized root record
  permissionPath: main.grants.map(normalizedPermission),           // root first
  intersections: [...] sorted by compareIntersectionProofs,
  effectiveConstraints: combineConstraints([...main.grants, ...each selected partner path's grants in graph order]),
  controllingAuthorityIds: sorted distinct ids of every grant on every graph path (main + partners),
  usageSnapshot: for each controlling id in that sorted order that has a usage entry → { authorityId, admittedTransactionCount, admittedCumulativeAmount },
  authorityEvidence: for each id in (controllingIds ∪ checkedProhibitionIds) that has evidence → { authorityId, grantEventId, grantEventPosition },
                     sorted by authorityId, then grantEventId, then grantEventPosition,
  checkedProhibitionIds: sorted,
  consequential,
  // only when consequential && binding: (values copied from the binding; credentialKeyId/intentId/nonce are guaranteed present by step 8)
  runtimeSessionId, credentialKeyId, controlEpoch, roleId, roleTenureId, intentId, nonce
}
```
Intersection proof entries: `{ requiredAuthorityId, requiredByAuthorityIds
(sorted), recognizedRoot (partner's), path: partner grants normalized (root
first), effectiveConstraints: combineConstraints(partner path only) }`, sorted
by (requiredAuthorityId, requiredByAuthorityIds seq, partner root id, partner
path ids seq, hashCanonical(effectiveConstraints)).

Then `boundedResult` re-captures (keys sorted, frozen, null-prototype). The
final object is `{ operationVersion, decision:"ALLOW", scopeAssurance,
consequential, proof }`.

Real example **[verified]** (handover fixture, `b:first-look` /
`record-review-progress` / `obligation:first-look` at 25, conformance vector
`authorization/successor-may-exercise-its-own-grant`):

```json
{"consequential":false,"decision":"ALLOW","operationVersion":"continuity-authorization/0.2",
 "proof":{"authorityEvidence":[{"authorityId":"progress-b-authority:first-look","grantEventId":"first-look:progress-b-authority","grantEventPosition":12}],
  "checkedProhibitionIds":[],"consequential":false,"controllingAuthorityIds":["progress-b-authority:first-look"],
  "domain":{"chainId":"31337","deploymentId":"core-0.2-reference:first-look","protocol":"continuity","verifyingContract":"0x0000000000000000000000000000000000003002","version":"0.2"},
  "effectiveConstraints":{"actions":["record-review-progress"],"expiresAt":1000,"maxDelegationDepth":0,"quantitative":false,"requiredIntersectionIds":[],"resources":["obligation:first-look"]},
  "evaluationTime":25,
  "historyHead":{"canonicalTime":25,"hash":"0x4958d40342fc047d3fff0d3ab0f36e572ea28d9a1bb6dcbfbc1961c52231b779","position":25},
  "intersections":[],
  "permissionPath":[{"authorityId":"progress-b-authority:first-look","constraints":{"actions":["record-review-progress"],"expiresAt":1000,"maxDelegationDepth":0,"quantitative":false,"requiredIntersectionIds":[],"resources":["obligation:first-look"]},"granteeId":"b:first-look","grantorId":"principal:first-look","independent":true,"kind":"PERMISSION","rootAuthorityId":"progress-b-authority:first-look"}],
  "policyVersion":"local-evidence-intake-policy:first-look/0.2","proofVersion":"continuity-authorization-proof/0.2",
  "recognizedRoot":{"principalId":"principal:first-look","principalRecognitionEventId":"first-look:principal","rootAuthorityId":"progress-b-authority:first-look","rootGrantEventId":"first-look:progress-b-authority"},
  "request":{"action":"record-review-progress","actorId":"b:first-look","claimedAt":25,"resource":"obligation:first-look"},
  "rootRecognitionPolicy":"declared-principal-root/0.2","usageSnapshot":[]},
 "scopeAssurance":"REPLAY_VERIFIED"}
```

Delegated + intersection example **[verified]** (custom history: root `gated`
held by A requiring dependent partners `p2`,`p1`; `p1` has `expiresAt 50`,
actions `[read,write]`; `p2` has `notBefore 3`, resources `[r1,r2]`; `gated`
has `maxDelegationDepth 3`), evaluated at 10 for `read`/`r1`:
`controllingAuthorityIds = ["gated","p1","p2"]`, `permissionPath = [gated]`,
`intersections = [{requiredAuthorityId:"p1", requiredByAuthorityIds:["gated"], path:[p1], effectiveConstraints:{actions:[read,write],expiresAt:50,...}}, {requiredAuthorityId:"p2", ..., effectiveConstraints:{actions:[read],notBefore:3,resources:[r1,r2],...}}]`,
`effectiveConstraints = {actions:["read"], resources:["r1"], quantitative:false, notBefore:3, expiresAt:50, maxDelegationDepth:0, requiredIntersectionIds:["p1","p2"]}`.

Conformance expectations (from `conformance/vectors.json`, all REPLAY_VERIFIED):
`quantitative/delegated-budget-honoured` (researcher, 400) ⇒ ALLOW,
`controllingAuthorityIds ["mandate-authority:mandate","research-authority:mandate"]`;
`quantitative/within-the-per-purchase-cap` (buyer, 1999) ⇒ ALLOW `["mandate-authority:mandate"]`
with `usageSnapshot [{authorityId:"mandate-authority:mandate", admittedTransactionCount:0, admittedCumulativeAmount:0n}]`
and effective `maxAmount 2500n, maxCumulativeAmount 5000n, maxTransactions 3`.

### 6.4 DENY / INDETERMINATE shapes with real output

Real DENY **[verified]** (`handoverDenied`, `b:no-review-power` /
`record-review-progress` / `obligation:no-review-power`, vector
`authorization/revoked-successor-review` expects code `REVOKED`, failure codes
`["REVOKED","ACTION_NOT_ALLOWED"]`):

```json
{"code":"REVOKED","consequential":false,"decision":"DENY",
 "failures":[
  {"authorityPathIds":["progress-b-authority:no-review-power"],"code":"REVOKED",
   "evidence":[{"eventId":"no-review-power:a","eventType":"AGENT_CREATED","historyHash":"0x…","kind":"EVENT","position":2},
               {"eventId":"no-review-power:admission","eventType":"TRANSACTION_INTENT_ADMITTED","historyHash":"0x…","kind":"EVENT","position":14},
               {"eventId":"no-review-power:b","eventType":"AGENT_CREATED","historyHash":"0x…","kind":"EVENT","position":3},
               {"eventId":"no-review-power:collect-authority","eventType":"AUTHORITY_GRANTED","historyHash":"0x…","kind":"EVENT","position":8},
               {"eventId":"no-review-power:genesis","eventType":"DEPLOYMENT_INITIALIZED","historyHash":"0x…","kind":"EVENT","position":0},
               {"eventId":"no-review-power:obligate-authority","eventType":"AUTHORITY_GRANTED","historyHash":"0x…","kind":"EVENT","position":9},
               {"eventId":"no-review-power:principal","eventType":"PRINCIPAL_CREATED","historyHash":"0x…","kind":"EVENT","position":1},
               {"eventId":"no-review-power:progress-a-authority","eventType":"AUTHORITY_GRANTED","historyHash":"0x…","kind":"EVENT","position":11},
               {"eventId":"no-review-power:progress-b-authority","eventType":"AUTHORITY_GRANTED","historyHash":"0x…","kind":"EVENT","position":12},
               {"eventId":"no-review-power:review-authority","eventType":"AUTHORITY_GRANTED","historyHash":"0x…","kind":"EVENT","position":10},
               {"eventId":"no-review-power:stale-declared","eventType":"TRANSACTION_INTENT_DECLARED","historyHash":"0x619595a0…","kind":"EVENT","position":26},
               {"eventId":"no-review-power:terminated","eventType":"AGENT_TERMINATED","historyHash":"0x…","kind":"EVENT","position":20},
               {"eventId":"no-review-power:tutorial-revoke-a","eventType":"AUTHORITY_REVOKED","historyHash":"0x…","kind":"EVENT","position":24},
               {"eventId":"no-review-power:tutorial-revoke-b-review","eventType":"AUTHORITY_REVOKED","historyHash":"0x…","kind":"EVENT","position":25}],
   "failingAuthorityId":"progress-b-authority:no-review-power","rootAuthorityId":"progress-b-authority:no-review-power","terminalAuthorityId":"progress-b-authority:no-review-power"},
  {"authorityPathIds":["review-authority:no-review-power"],"code":"ACTION_NOT_ALLOWED","evidence":[/* identical list */],
   "failingAuthorityId":"review-authority:no-review-power","rootAuthorityId":"review-authority:no-review-power","terminalAuthorityId":"review-authority:no-review-power"}],
 "operationVersion":"continuity-authorization/0.2","scopeAssurance":"REPLAY_VERIFIED"}
```
(The head event `stale-declared` at 26 is included because the head is always
appended; note the `TRANSACTION_INTENT_DECLARED` type is otherwise not in the
decision predicate.)

Real `AGENT_INACTIVE` **[verified]** (handover, `a:first-look`):
```json
{"code":"AGENT_INACTIVE","consequential":false,"decision":"DENY",
 "failures":[{"authorityPathIds":[],"code":"AGENT_INACTIVE",
   "evidence":[{"eventId":"first-look:a","eventType":"AGENT_CREATED","position":2,…},
               {"eventId":"first-look:stale-declared","eventType":"TRANSACTION_INTENT_DECLARED","position":25,…},
               {"eventId":"first-look:terminated","eventType":"AGENT_TERMINATED","position":20,…}],
   "subjectId":"a:first-look"}],
 "operationVersion":"continuity-authorization/0.2","scopeAssurance":"REPLAY_VERIFIED"}
```
Unknown actor `ghost:first-look` ⇒ same shape, evidence = head event only.

Real INDETERMINATE **[verified]** (evaluationTime 10 < head 50):
```json
{"operationVersion":"continuity-authorization/0.2","decision":"INDETERMINATE","scopeAssurance":"SUPPLIED_SCOPE","consequential":false,
 "code":"CAUSAL_TIME_INVALID","failures":[{"code":"CAUSAL_TIME_INVALID","evidence":[{"kind":"EVENT","eventId":"p2","eventType":"PRINCIPAL_CREATED","position":4,"historyHash":"0x…"}]}]}
```
INDETERMINATE results produced by `indeterminate()` are plain frozen objects in
this insertion order (not canonically re-captured) except the admission-event
collision case which is bounded. `INVALID_INPUT`/`UNSUPPORTED_VERSION`/
`STATE_NOT_AUTHORITATIVE` from the façade carry `failures: [{code, evidence: []}]`
and `scopeAssurance: "SUPPLIED_SCOPE"`.

`simpleDenial` shape: `{ code, subjectId?, authorityPathIds: [], evidence }`.

---

## 7. Other functions in the file

### 7.1 `evaluatePortableAuthorityPath(input)` (raw, supplied scope)

Input `PortableAuthorityPathEvaluationInput`:
```ts
{ operationVersion: "continuity-authority-evaluation/0.2",
  scope: { domain, policyVersion, rootRecognitionPolicy, historyHead, evaluationTime, recognizedRoots: RecognizedRoot[], globalPolicySourceId },
  request, permissions: PermissionGrant[], prohibitions: ProhibitionGrant[], authorityEvidence: AuthorityEvidence[],
  revokedAuthorityIds: string[], usage: AuthorityUsage[] }
```
Always `scopeAssurance: "SUPPLIED_SCOPE"`, `consequential: false`, no
binding allowed (`binding` key ⇒ INVALID_INPUT), no replay evidence (all
`evidence: []`), no agent checks, no `NONCE_ALREADY_ADMITTED`. Order:

1. Outer/deep capture (§2.2) ⇒ `INVALID_INPUT` / `UNSUPPORTED_VERSION`.
2. Phase-1 (`rawCaptureTimeCollectionsAreValid`) ⇒ `INDETERMINATE/INVALID_INPUT`:
   `scope.recognizedRoots`, `permissions`, `prohibitions`, `authorityEvidence`,
   `revokedAuthorityIds`, `usage` must be arrays; `permissions.length +
   prohibitions.length ≤ 1024`; no duplicate valid `rootAuthorityId` among
   roots, `authorityId` among evidence, `authorityId` among usage, or member
   among revoked ids; every permission's parent chain (by id, ignoring
   malformed entries, ambiguous duplicate ids treated as dead ends) must stay
   ≤ 32 deep.
3. `scope` exact record with the 7 keys; `domainIsValid`; `historyHeadIsValid`;
   `recognizedRoots` array; `policyVersion`, `rootRecognitionPolicy`,
   `globalPolicySourceId` Identifiers; `request` exact shape ⇒ else `INVALID_INPUT`.
4. `scope.evaluationTime` not U53 ⇒ `CAUSAL_TIME_INVALID`; `< historyHead.canonicalTime` ⇒ `CAUSAL_TIME_INVALID`.
5. `rootRecognitionPolicy !== literal` ⇒ `DENY / POLICY_MISMATCH` (evidence `[]`).
   The domain is **not** compared to anything (no genesis) **[verified]**.
6. `requestProblem` ⇒ `DENY / INVALID_REQUEST` | `INVALID_AMOUNT`.
7. `rawCorpusFromCapture`: validate every permission (`permissionStatus`),
   prohibition (`prohibitionStatus`), root, evidence, usage record and revoked
   id with the three-valued validators. Any `LIMIT` or a duplicate among valid
   roots/evidence/usage/revoked ⇒ `INDETERMINATE/INVALID_INPUT`. Any `INVALID`
   or an `authorityId` shared by two grants (permission/permission,
   permission/prohibition) ⇒ `DENY / INVALID_DELEGATION` **[verified]**
   (duplicate `actions`, empty `actions`, `notBefore >= expiresAt`, non-quantitative
   with `maxAmount`, wrong `kind`, prohibition with `requiredIntersectionIds`/
   `maxDelegationDepth ≠ 0`/`maxCumulativeAmount`/`maxTransactions`, all ⇒
   INVALID_DELEGATION; 257 actions, 33 intersections, 257-byte ids, 1025
   authorities ⇒ INVALID_INPUT).
   Permission record: exact keys `{kind, authorityId, grantorId, granteeId,
   rootAuthorityId, independent, constraints}` + optional `parentAuthorityId`;
   `kind === "PERMISSION"`, `independent` boolean. Prohibition record: `kind ===
   "PROHIBITION"`, `scope` `"ROOT"` (keys `kind, scope, authorityId, grantorId,
   rootAuthorityId, constraints` + optional `subjectActorId, parentAuthorityId`)
   or `"GLOBAL"` (`kind, scope, authorityId, grantorId, constraints` + optional
   `subjectActorId`). Constraints record: required `{actions, resources,
   quantitative, maxDelegationDepth, requiredIntersectionIds}`, optional
   `{notBefore, expiresAt, maxAmount, maxCumulativeAmount, maxTransactions}`,
   with the §1 rules; `identifierListStatus(actions/resources, 256, nonempty)`,
   `identifierListStatus(requiredIntersectionIds, 32)`.
8. `validateAuthorityCorpus` (§3.4): `INVALID_INPUT` ⇒ INDETERMINATE (path > 32
   deep); `INVALID_DELEGATION` ⇒ DENY (evidence `[]`).
9. `evaluateAuthorityAlgebra` with `historyHead = scope.historyHead`,
   `domain = scope.domain`; finalize as §6.3.

Real output **[verified]** (single root `root` for `A`, actions `[read,write]`,
`maxDelegationDepth 1`, head `{0xabab…, 7, 100}`, evaluationTime 100):
```json
{"consequential":false,"decision":"ALLOW","operationVersion":"continuity-authority-evaluation/0.2",
 "proof":{"authorityEvidence":[{"authorityId":"root","grantEventId":"ev-root","grantEventPosition":3}],"checkedProhibitionIds":[],"consequential":false,
  "controllingAuthorityIds":["root"],"domain":{…},"effectiveConstraints":{"actions":["read","write"],"maxDelegationDepth":1,"quantitative":false,"requiredIntersectionIds":[],"resources":["r1"]},
  "evaluationTime":100,"historyHead":{"canonicalTime":100,"hash":"0xabab…","position":7},"intersections":[],
  "permissionPath":[{"authorityId":"root","constraints":{…},"granteeId":"A","grantorId":"P","independent":true,"kind":"PERMISSION","rootAuthorityId":"root"}],
  "policyVersion":"exp-policy/0.2","proofVersion":"continuity-authorization-proof/0.2",
  "recognizedRoot":{"principalId":"P","principalRecognitionEventId":"ev-p","rootAuthorityId":"root","rootGrantEventId":"ev-root"},
  "request":{"action":"read","actorId":"A","claimedAt":100,"resource":"r1"},"rootRecognitionPolicy":"declared-principal-root/0.2","usageSnapshot":[]},
 "scopeAssurance":"SUPPLIED_SCOPE"}
```
and a raw `POLICY_MISMATCH`:
`{"operationVersion":"continuity-authority-evaluation/0.2","decision":"DENY","scopeAssurance":"SUPPLIED_SCOPE","consequential":false,"code":"POLICY_MISMATCH","failures":[{"code":"POLICY_MISMATCH","authorityPathIds":[],"evidence":[]}]}`.

### 7.2 `capturePortableAuthorityOperation(input, kind, replayVisitor?)`

Returns `{status:"INVALID_INPUT"}`, `{status:"UNSUPPORTED_VERSION"}`,
`{status:"STATE_NOT_AUTHORITATIVE"}` (schema failure inside `events`, not for
AUTHORITY_PATH_EVALUATION) or `{status:"CAPTURED", capture}`. Throws if the
capture visitor stopped (never, for the kernel visitor) or on non-limit,
non-schema capture errors.

### 7.3 `evaluateCapturedPortableIntentAdmissionState(capture, state)` (kind `INTENT_ADMISSION`)

Structural check (`INVALID_INPUT` INDETERMINATE otherwise): `events` array,
domain, head, `admissionEventId` Identifier, `policyVersion` Identifier,
request exact shape, **binding required and structurally valid**. Then:

1. `evaluationTime` not U53 or `< head.canonicalTime` ⇒ INDETERMINATE `CAUSAL_TIME_INVALID`, SUPPLIED_SCOPE, evidence `[headRef]`.
2. `scopeMatches = sameDomain(domain, genesis.domain) && policyVersion === genesis.policyVersion && genesis.rootRecognitionPolicy === literal`.
3. **RETRY** short-circuit (before the head pin!): if `scopeMatches`, request
   valid, `intentId` & `nonce` present, the declaration exists and
   `sameIntent(declaration, projection)` and `intentAdmissions[intentId]` exists
   ⇒ `{status:"RETRY", intentId, existingAdmissionEventId, existingAdmissionHead}`.
4. `expectedHistoryHead ≠ state.head` ⇒ `{status:"CONFLICT", expectedHead, observedHead: state.head}`.
5. If scope matches, request valid, intent+nonce present, declaration exists but
   `!sameIntent` ⇒ DENIED `INTENT_MISMATCH` (REPLAY_VERIFIED, subject intentId,
   `intentDecisionEvidence(actorId, intentId, nonce)`).
6. `stagePortableStateAuthorization(state, {…, rootRecognitionPolicy: literal, consequential: true, binding})`;
   non-ALLOW ⇒ `{status:"DENIED"|"INDETERMINATE", authorization}`.
7. `occupiedCandidateNonceDenial` ⇒ DENIED `NONCE_ALREADY_ADMITTED`.
8. Binding must now have credentialKeyId/intentId/nonce/runtimeSignature (else TypeError).
9. If any existing event has `id === admissionEventId` ⇒ INDETERMINATE
   `INVALID_INPUT`, **REPLAY_VERIFIED**, subject admissionEventId, evidence
   `collidingEventEvidence`.
10. Finalize ⇒ `{status:"AUTHORIZED", authorization: proof, admissionEventId, expectedHead, evaluationTime, binding}`
    (or the OUTPUT_LIMIT indeterminate).

`proposePortableIntentAdmission` (in `portable-admission.ts`) wraps this and
builds the event `TRANSACTION_INTENT_ADMITTED` with data
`{ intentId, evaluationTime, expectedHistoryHead, authorizationProof: proof,
runtimeAuthorizationHash: hash(challenge(proof.domain, proof.request,
evaluationTime, proof.policyVersion, expectedHead, binding)), runtimeSignature }`
**[verified]** key set.

### 7.4 `validatePortableIntentAdmissionTransition(state, event)` → `{status:"VALID", intentId, actorId, nonce, usage[]}` | `{status:"INVALID"}`

All must hold: `event.type === "TRANSACTION_INTENT_ADMITTED"`;
`event.timestamp === data.evaluationTime === proof.evaluationTime`;
`data.intentId === proof.intentId`; `data.expectedHistoryHead` and
`proof.historyHead` both equal `state.head`; `proof.consequential === true`;
`proof.rootRecognitionPolicy === literal`; `data.runtimeSignature` Signature65;
`data.runtimeAuthorizationHash === hash(challenge rebuilt from the proof's
domain/request/evaluationTime/policyVersion, historyHead = state.head, binding
from the proof's seven runtime fields)`; actor exists (terminated allowed here —
the re-authorization below denies it), session exists, `session.agentId ===
actor.id`, `session.credentialKeyId === proof.credentialKeyId`, signature
verifies against `session.credentialAddressKey`; re-running
`authorizePortableState` with the proof's inputs (consequential, binding
including the signature) yields ALLOW **and** `canonicalEncode(result.proof)
=== canonicalEncode(proof)`; declaration exists, `sameIntent`, not already
admitted. Then usage: for each `proof.controllingAuthorityIds` id: authority
must exist and be a PERMISSION; skip if it has neither `maxTransactions` nor
`maxCumulativeAmount`; else current usage must exist and, if
`maxCumulativeAmount` defined, `amount` must be present;
`count' = count + (maxTransactions defined ? 1 : 0)`,
`cum' = cum + (maxCumulativeAmount defined ? amount : 0n)`; `count'` must be a
safe integer and `≤ maxTransactions` (if defined), `cum' ≤ maxCumulativeAmount`
(if defined) and `≤ MAX_BIGINT`. Returned usage entries replace the state's.

Thus **usage is accumulated only from accepted `TRANSACTION_INTENT_ADMITTED`
events, per controlling authority (including intersection partners), and only
for the dimension each authority caps** **[verified]**: after admitting 60 under
`{maxAmount 100, maxCumulativeAmount 150, maxTransactions 2}` the next
authorization shows `usageSnapshot [{q, 1, 60n}]`; 100 more ⇒
`CUMULATIVE_AMOUNT_EXCEEDED`; after a second admission any amount ⇒
`TRANSACTION_COUNT_EXCEEDED` (or `CUMULATIVE_AMOUNT_EXCEEDED` if that also
trips, rank order).

### 7.5 Administrative requirements

`PortableAdministrativeRequirements = { request, requiredPrincipalId,
requiredAuthorityIds, roleId, roleTenureId }`. A candidate qualifies only if
its recognized root's `principalId === requiredPrincipalId` and every
`requiredAuthorityIds` member is among the grants of its selected graph.

`createPortableAdministrativePolicyProof(state, requirements, evaluationTime)`
⇒ proof or `undefined`: request must have no `amount`; stage with
`expectedHistoryHead = state.head`, genesis domain/policy, `consequential:false`;
must be ALLOW_CANDIDATE; every grant in the graph must be non-quantitative with
no `maxAmount/maxCumulativeAmount/maxTransactions`; finalized result must be
ALLOW, REPLAY_VERIFIED, non-consequential with empty `usageSnapshot`.

### 7.6 `validatePortableAdministrativeTransition(state, event, requirements)` → boolean

Event type ∈ {OBLIGATION_CREATED, OBLIGATION_PERFORMANCE_ASSIGNED,
OBLIGATION_STATUS_RECORDED, OUTCOME_OBSERVATION_RECORDED, ATTEMPT_DUTY_CREATED,
ATTEMPT_DUTY_ASSIGNED, ATTEMPT_DUTY_REVIEW_CLOSED} (the last four gated by the
genesis adapter policy hash E5/E6). `wrapper = data.administrativeAuthorization
= { challenge, authorityProof, runtimeSignature }`. Requires canonical equality
of challenge/proof domain with genesis, `challenge.request` with
`requirements.request`, `challenge.request.actorId === data.actorId`, policy
literals, `eventHistoryHash/Position === state.head`, `challenge.evaluationTime
=== event.timestamp`, `transitionEventId/Type === event`,
`transitionEffectHash === hashCanonical(portableAdministrativeTransitionEffect(event))`,
`authorityProofHash === hashCanonical(proof)`, role/tenure ids; actor active,
session of actor unexpired at `event.timestamp` with matching credentialKeyId
and epoch (session and actor), role current tenure and tenure open/for that
role and agent; `recover(hashCanonical(challenge), runtimeSignature) ===
session.credentialAddressKey`; and `canonicalEncode(createPortableAdministrativePolicyProof(state,
requirements, event.timestamp)) === canonicalEncode(proof)`.

### 7.7 `evaluatePortableReceiptPolicy(state, proof, evaluationTime)` → `{ live, checkedProhibitionIds, decisiveAuthorityIds, decisiveAgentIds }` (all sorted)

`live=false` immediately if `evaluationTime` not U53, domain/policy/rootRecognitionPolicy
mismatch with genesis, or corpus invalid. `terminal = last of proof.permissionPath`;
`main = validated.paths[terminal.authorityId]`; if missing, not effectively
independent, or `terminal.granteeId !== proof.request.actorId` ⇒ decisive
`terminal.authorityId`, live=false. Else rebuild graph and compare identity:
root canonical-equal to `proof.recognizedRoot`, main grants equal to
`proof.permissionPath` (normalized), same number of intersections, each
intersection equal (requiredAuthorityId, requiredBy, root, path, effective
constraints), whole effective constraints equal; mismatches add decisive ids
(`main.rootAuthorityId`, the intersection's required id, or the terminal).
Terminated grantors/grantees of graph grants → `decisiveAgentIds`. Relevant
candidate prohibitions and relevant globals → `checkedProhibitionIds`; an
active+matching global ⇒ blocked and decisive. Then `evaluateCandidate(...,
checkCapacity=false, collector)` (capacity/usage **not** rechecked; every
failing set member and every matching prohibition collected as decisive).
`live = evaluationTime >= state.head.canonicalTime && identityMatches &&
!globalBlocked && evaluation SUCCESS`.

### 7.8 `portableIntentProjection(request, binding, adapterProfile)`

`{ adapterProfile, intentId, nonce, actorId, action, resource, roleId,
roleTenureId, amount?, counterpartyId?, termsCommitment? }`; throws TypeError if
intentId/nonce absent. `claimedAt` deliberately excluded.

---

## 8. Traps and subtle behaviours (all **[verified]** unless noted)

1. **Headline code is the lowest rank across all of the actor's candidate
   paths.** Buyer with a budgeted `purchase` mandate and an unrelated `report`
   grant asks to purchase 2501 ⇒ `code: ACTION_NOT_ALLOWED` (from the report
   grant), while `failures` contains `AMOUNT_EXCEEDED` for the mandate. Read
   `failures`, not `code`.
2. **`independent` semantics.** Main candidates require *every* grant on the
   chain to be `independent: true`. Intersection partners require *at least one*
   `independent: false` grant on their chain and the same grantee as the actor;
   an `independent: true` partner ⇒ `MISSING_INTERSECTION` (and if that partner
   covers the request it simply wins on its own). The generated corpus in
   `tests/generators.mjs` therefore never satisfies its gated grant.
3. **Prohibition attenuation needs a delegable anchor.** A ROOT prohibition
   granted by the principal must attenuate against the root grant, and
   attenuation fails when `parent.maxDelegationDepth === 0` ⇒ replay
   `TRANSITION_INVALID`; same for prohibitions with `maxDelegationDepth ≠ 0`,
   wider sets, or missing inherited bounds.
4. **Matching is exact, case-sensitive string equality** (`arrayIncludes`,
   SameValueZero). No wildcards, no prefixes, no normalization. `"beta"` does
   not match `["Beta"]`.
5. **Sorting.** Input grants may carry constraint arrays in any order (schema
   forbids duplicates but not disorder); proofs always emit them sorted by
   UTF-8 byte order (`"Beta" < "alpha" < "zeta"`). Effective constraints inherit
   the first path grant's sorted order and are therefore sorted. Do not compare a
   sorted copy against an unsorted one anywhere; the engine never sorts in place
   on input data (all sorts are on copies).
6. **Evidence order is by `eventId` string, not by position**, with the head
   event always appended (so the head appears even when its type is not in the
   predicate). Deduplication is on the full 4-tuple.
7. **`claimedAt` is inert** for decisions; it is echoed in `proof.request` and
   bound by the runtime challenge, but excluded from the intent projection.
8. **Time bounds**: `notBefore` inclusive, `expiresAt` exclusive, session
   `expiresAt` exclusive. `evaluationTime === head.canonicalTime` is valid;
   `evaluationTime < head.canonicalTime` (including "before genesis") is
   `INDETERMINATE/CAUSAL_TIME_INVALID` with `SUPPLIED_SCOPE`, never a DENY.
   Non-number/NaN/non-integer evaluationTime ⇒ `CAUSAL_TIME_INVALID` (replay
   and raw paths), not `INVALID_INPUT`.
9. **Head pin**: any of hash/position/canonicalTime differing ⇒
   `HISTORY_RELATION_UNVERIFIED` (`SUPPLIED_SCOPE`, evidence = head event);
   an uppercase hash is `INVALID_INPUT` instead (ContentHash is lowercase-only).
10. **Terminated agents**: actor terminated/unknown/principal ⇒ `AGENT_INACTIVE`
    (before global prohibitions). A path whose grantor *or* grantee is terminated
    fails with `NO_AUTHORITY` (rank 11, `failingAuthorityId` = that grant); a
    grant *to* a terminated agent still replays. The raw path has no agents and
    never produces this.
11. **`authorityId !== rootAuthorityId` on a parent-less grant** replays fine
    but is never a recognized root ⇒ every path from it fails `NO_AUTHORITY`
    with `failingAuthorityId = rootAuthorityId` (the dangling field value).
12. **Principals** may be grantees (and thus grantors of delegations) but can
    never act (`AGENT_INACTIVE`).
13. **Self-delegation** (grantor = grantee) replays and evaluates; the shorter
    root path wins over `[root, self]` (prefix rule).
14. **Cycles** cannot arise via replay (parents must pre-exist); in the raw path
    they yield `INVALID_DELEGATION`. Depth > 32 ⇒ `INVALID_INPUT`.
15. **Authority ids are single-use forever**: re-granting a revoked id ⇒
    `TRANSITION_INVALID`; re-revoking ⇒ `TRANSITION_INVALID`. "Renewal" needs a
    new id; the old expired grant then just contributes an `EXPIRED` failure
    entry while the new one wins.
16. **Revocation**: revoking any grant on a path fails the whole path with
    `REVOKED` (`failingAuthorityId` = least revoked id on it); there is no
    cascade in state — descendants stay unrevoked records and appear as
    `REVOKED` only through their ancestor. Revoking a prohibition or its anchor
    deactivates it (permission restored unless the anchor path is what the
    actor needed). Revocation never resets usage. Revoker rules: principal of
    the root for anything under a root; the grantor only for delegated grants;
    `globalPolicySourceId` for GLOBAL prohibitions.
17. **Prohibition precedence**: global prohibitions deny before any candidate
    is considered (even for actors with zero grants, even if the actor would be
    `NO_AUTHORITY`); candidate ROOT prohibitions rank 0 ahead of `REVOKED`; but
    *any* other succeeding path beats a prohibited one.
18. **`subjectActorId`** restricts a prohibition to one actor; without it the
    prohibition applies to everyone (for ROOT: everyone whose graph touches that root).
19. **Quantitative prohibitions** are ignored (not even "checked") for requests
    without an amount, and `maxAmount` on a prohibition is an *inclusive upper
    bound on what is blocked* (`amount <= maxAmount` blocks; larger passes).
20. **`checkedProhibitionIds`/`authorityEvidence`** include relevant prohibitions
    that are expired or revoked; a prohibition on an action other than the
    requested one is not listed at all.
21. **Amounts**: `amount` on a non-quantitative grant is accepted and echoed;
    `quantitative: true` without ceilings still demands an amount
    (`AMOUNT_REQUIRED`); `maxTransactions: 0` denies from the first use;
    `maxCumulativeAmount: 0n` allows amount `0n`; `AMOUNT_EXCEEDED` is inclusive
    (`2500 ≤ 2500` allowed, `2501` denied). `maxTransactions` is checked even
    when no amount is supplied and even on non-quantitative grants.
22. **Invalid amount vs invalid request**: negative/oversized/non-bigint amount
    ⇒ DENY `INVALID_AMOUNT` (after `INVALID_REQUEST` checks); a JSON BigInt
    marker object as `request.amount` **throws** TypeError; `amount: undefined`
    behaves as absent.
23. **Over-long identifiers** (> 256 bytes/units) at designated slots ⇒
    `INDETERMINATE/INVALID_INPUT`, while control characters, empty strings or
    lone surrogates in request fields ⇒ DENY `INVALID_REQUEST`.
24. **Binding presence must equal `consequential`**; malformed signature
    strings are structural `INVALID_INPUT`; a syntactically valid but wrong
    signature is `SESSION_CREDENTIAL_INVALID`; the signature is only verified
    when both `intentId` and `nonce` are present (otherwise the flow reaches
    `INTENT_REQUIRED` with an unverified signature); `credentialKeyId` and
    `runtimeSignature` must both be present before any signature/epoch/tenure
    check (`SESSION_CREDENTIAL_REQUIRED`).
25. **Epoch order**: `SESSION_FENCED` (session behind the agent's epoch) is
    checked before `STALE_EPOCH` (binding epoch ≠ session/agent epoch).
26. **Domain**: `verifyingContract` case-insensitive in the replay comparison
    but the proof/challenge keep the caller's spelling (so two callers with
    different casing produce different challenge hashes); `chainId` must be a
    canonical decimal string.
27. **Output objects** from ALLOW/DENY are canonically re-captured: frozen,
    null-prototype, keys in byte order (`Object.keys` order differs from the
    TypeScript declaration order). INDETERMINATE objects keep insertion order
    and `Object.prototype`.
28. **Winner determinism**: root id, then main path id sequence, then
    intersections, then constraint hash — the first grant in event order has no
    priority; `"Alpha"` beats `"alpha"` beats `"zeta"`.
29. **One failure entry per failed *main* candidate**, never per partner path;
    partner problems surface via `failingAuthorityId` on the main entry
    (e.g. `MISSING_INTERSECTION` with `failingAuthorityId = partner`, or
    `EXPIRED` with `failingAuthorityId = p1` while `authorityPathIds = [gated]`).
30. **Inherited intersections**: a delegation must repeat its parent's
    `requiredIntersectionIds`; in the proof `requiredByAuthorityIds` names only
    the grant that *introduced* the requirement (the ancestor), not the
    repeating descendants.
31. **`effectiveConstraints.maxDelegationDepth`** is the minimum over main
    *and partner* grants; `requiredIntersectionIds` is the union; `quantitative`
    the OR — so a non-quantitative main path with a quantitative partner becomes
    quantitative.
32. **Structural INVALID_INPUT wins over replay rejection** in `authorizePortable`
    (the structural check runs before `kernel.finish()`), and both run after
    the whole input was captured.
33. **Unverified by experiment** (from source only): `OUTPUT_LIMIT_EXCEEDED`
    thresholds; `INVALID_DELEGATION` through the replay path; the exact
    `EVIDENCE_UNAVAILABLE`/`EVIDENCE_DISPUTED` codes (never emitted here);
    `evaluatePortableReceiptPolicy`, `createPortableAdministrativePolicyProof`
    and `validatePortableAdministrativeTransition` behaviour beyond what is
    stated in §7.

---

## 9. Compact reference pseudocode

This condenses §2–§6 into one procedure. Names match the source.

```
authorizePortable(input):
  outer = captureAuthorityOuter(input, AUTHORIZE)          # may THROW TypeError
  if outer is INVALID_INPUT/UNSUPPORTED_VERSION: return indeterminate(AUTHZ, code)     # SUPPLIED_SCOPE, evidence []
  cap = deepCapture(outer.body, replayKernel.visit)        # limit error → INVALID_INPUT; schema error → STATE_NOT_AUTHORITATIVE; else THROW
  if !structurallyValid(cap): return indeterminate(AUTHZ, INVALID_INPUT)
  rep = kernel.finish()
  if rep REJECTED: return indeterminate(AUTHZ, code ∈ {UNSUPPORTED_VERSION,UNSUPPORTED_EVENT_SCHEMA,UNSUPPORTED_EVENT_TYPE} ? UNSUPPORTED_VERSION : STATE_NOT_AUTHORITATIVE)
  state = rep.state
  # stagePortableStateAuthorization
  if body.expectedHistoryHead != state.head:            return indeterminate(HISTORY_RELATION_UNVERIFIED, SUPPLIED_SCOPE, [headRef])
  if !isU53(t) || t < head.canonicalTime:               return indeterminate(CAUSAL_TIME_INVALID, SUPPLIED_SCOPE, [headRef])
  if !sameDomain(domain, genesis.domain):               return deny(DOMAIN_MISMATCH, [genesisRef])
  if policyVersion != genesis.policyVersion || rrp != genesis.rootRecognitionPolicy: return deny(POLICY_MISMATCH, [genesisRef])
  if p = requestProblem(request):                       return deny(p, [])
  v = validateAuthorityCorpus(replayCorpus(state))
  if v INVALID_INPUT:                                   return indeterminate(STATE_NOT_AUTHORITATIVE, SUPPLIED_SCOPE)
  if v INVALID_DELEGATION:                              return deny(INVALID_DELEGATION, decisionEvidence)
  agent = state.agents[actorId]; if !agent || agent.terminated: return deny(AGENT_INACTIVE, agentLifecycle(actorId), subject=actorId)
  if consequential:                                     # binding present by structure
    session = runtimeSessions[b.runtimeSessionId]; if !session || session.agentId != agent.id: deny(SESSION_NOT_FOUND, sessionEv, subject=sessionId)
    if session.expiresAt? && t >= session.expiresAt:                                              deny(SESSION_EXPIRED, ...)
    if !b.credentialKeyId || !b.runtimeSignature:                                                 deny(SESSION_CREDENTIAL_REQUIRED, ...)
    if b.credentialKeyId != session.credentialKeyId:                                              deny(SESSION_CREDENTIAL_INVALID, ...)
    if b.intentId && b.nonce && !verify(session.credentialAddressKey, challenge(domain, request, t, policyVersion, head, b), sig): deny(SESSION_CREDENTIAL_INVALID, ...)
    if session.controlEpoch < agent.currentControlEpoch:                                          deny(SESSION_FENCED, ...)
    if b.controlEpoch != session.controlEpoch || b.controlEpoch != agent.currentControlEpoch:      deny(STALE_EPOCH, ...)
    role = roles[b.roleId]; tenure = tenures[b.roleTenureId]
    if !role || !tenure || role.currentTenureId != b.roleTenureId || tenure.closed || tenure.roleId != b.roleId || tenure.agentId != agent.id:
                                                                                                  deny(ROLE_TENURE_NOT_CURRENT, tenureEv, subject=roleTenureId)
    if !b.intentId || !b.nonce:                          deny(INTENT_REQUIRED, intentEv(actorId), subject=actorId)
    decl = intentDeclarations[b.intentId]; if !decl:     deny(INTENT_NOT_DECLARED, intentEv(actorId, intentId, nonce), subject=intentId)
    if !sameIntent(decl.data, projection(request, b, decl.data.adapterProfile)): deny(INTENT_MISMATCH, ..., subject=intentId)
    if intentAdmissions.has(intentId):                   deny(INTENT_REPLAY, ..., subject=intentId)
  r = evaluateAuthorityAlgebra(ctx)                      # §4.1
  if r is ALLOW_CANDIDATE:
    if consequential && b.nonce && nonceReservationsByActor[actorId]?.has(b.nonce): return deny(NONCE_ALREADY_ADMITTED, intentEv(actorId, b.intentId, b.nonce), subject=nonce)
    return finalize(r)                                   # preflight → OUTPUT_LIMIT_EXCEEDED, else ALLOW + proof, bounded
  return r                                               # DENY (already sorted & bounded)

evaluateAuthorityAlgebra(ctx):
  globals = sorted(GLOBAL prohibitions relevant to request)
  if any g in globals active && matchesAmount: return deny(PROHIBITED, subject=actorId, failing=min id, path=[], decisionEvidence)
  candidates = [p in validated.paths if p.effectivelyIndependent && terminal(p).granteeId == actorId (&& adminOK)]
  results = candidates.map(evaluateCandidate)
  if any SUCCESS: return min over SUCCESS by compareSuccessfulCandidates
  if candidates empty: return deny(NO_AUTHORITY, subject=actorId, path=[], decisionEvidence)
  return denyMany(sort([ {code, rootAuthorityId, terminalAuthorityId, failingAuthorityId, authorityPathIds, decisionEvidence} per failure ]))

evaluateCandidate(main):
  if !recognizedRootForPath(main): FAIL(NO_AUTHORITY, main.rootAuthorityId)
  graph = selectCandidateGraph(main, actorId)
  rootProhs = sorted(ROOT prohibitions applying to graph && relevant)
  checked = ids(globals) ∪ ids(rootProhs)
  matching = { p in rootProhs : active(p) && matchesAmount(p) }
  if matching: FAIL(PROHIBITED, min(matching))
  sets in order: REVOKED, NOT_YET_VALID, EXPIRED, MISSING_INTERSECTION(graph.missing), ACTION_NOT_ALLOWED, RESOURCE_NOT_ALLOWED,
                 AMOUNT_REQUIRED, AMOUNT_EXCEEDED, CUMULATIVE_AMOUNT_EXCEEDED, TRANSACTION_COUNT_EXCEEDED, NO_AUTHORITY(terminated party)
  for each grant on each path in graph: populate sets (§4.2.4)
  first nonempty set → FAIL(code, min(set)); else SUCCESS(graph, sorted(checked))
```

---

## 10. Worked traces of the 19 conformance vectors (`conformance/vectors.json`, kind `authorization`)

History `first-look` (26 events, head `{0x4958d4…, 25, 25}`): principal
`principal:first-look`; agents `a`, `b`; grants (all root, depth 0,
`expiresAt 1000`, non-quantitative): `collect-authority` (a: collect-evidence-packet
on resource), `obligate-authority` (a: OBLIGATE on resource), `review-authority`
(b: ASSIGN_PERFORMANCE, record-collection-disposition on obligation),
`progress-a-authority` (a: record-review-progress on obligation),
`progress-b-authority` (b: record-review-progress on obligation); an admitted
intent at 14; `a` epoch-advanced at 19 and terminated at 20; role transferred to
`b`; `collect-authority` revoked at 24. History `no-review-power` = the same plus
`progress-b-authority:no-review-power` revoked at 25 (27 events, head at 26).
History `mandate` (7 events): `mandate-authority` (buyer: purchase on plush,
quantitative, maxAmount 2500, maxCumulativeAmount 5000, maxTransactions 3,
depth 2), `research-authority` (researcher, delegated from buyer under
mandate-authority, maxAmount 500, maxCumulativeAmount 1000, maxTransactions 2,
depth 1), `report-authority` (buyer: report on plush, non-quantitative).
`mandate-quantitative-only` = the first 6 events (no report grant).

| Vector | Trace | Expected |
|---|---|---|
| successor-may-exercise-its-own-grant | b / record-review-progress / obligation @25. Candidates for b: `review-authority` (ACTION_NOT_ALLOWED), `progress-b-authority` (SUCCESS). Winner ⇒ ALLOW, controlling `["progress-b-authority:first-look"]`. | ALLOW |
| successor-does-not-inherit-collection | b / collect-evidence-packet / resource. Both b-candidates fail ACTION_NOT_ALLOWED (also RESOURCE, but action set ranks first per path). Failures sorted by root id: `progress-b…` then `review…`. | DENY ACTION_NOT_ALLOWED, `[ACTION_NOT_ALLOWED, ACTION_NOT_ALLOWED]` |
| successor-may-not-obligate | b / OBLIGATE / resource — same as above. | DENY ACTION_NOT_ALLOWED ×2 |
| predecessor-refused-after-handover | a is terminated ⇒ step 7. | DENY AGENT_INACTIVE, 1 failure |
| revoked-successor-review | no-review-power: `progress-b…` is revoked ⇒ REVOKED (rank 1); `review…` ⇒ ACTION_NOT_ALLOWED (rank 5). | DENY REVOKED, `[REVOKED, ACTION_NOT_ALLOWED]` |
| unknown-action-refused | b / delete-everything / obligation. | DENY ACTION_NOT_ALLOWED ×2 |
| unknown-resource-refused | b / record-review-progress / `other:first-look`. `review-authority` ⇒ ACTION_NOT_ALLOWED (5); `progress-b…` ⇒ RESOURCE_NOT_ALLOWED (6). Headline is the lower rank from the *other* grant. | DENY ACTION_NOT_ALLOWED, `[ACTION_NOT_ALLOWED, RESOURCE_NOT_ALLOWED]` |
| unknown-actor-refused | `ghost:first-look` not an agent. | DENY AGENT_INACTIVE |
| expired-grant-refused | @5000 ≥ expiresAt 1000 for both b grants; EXPIRED (3) outranks ACTION_NOT_ALLOWED for `review…`. | DENY EXPIRED, `[EXPIRED, EXPIRED]` |
| domain-mismatch-refused | chainId `1` ≠ genesis `31337`, step 3. | DENY DOMAIN_MISMATCH |
| policy-mismatch-refused | policyVersion `other-policy/9.9`, step 4. | DENY POLICY_MISMATCH |
| quantitative/within-the-per-purchase-cap | buyer / purchase / plush / 1999 @5 (quant-only). 1999 ≤ 2500, usage 0+1999 ≤ 5000, count 0 < 3. | ALLOW `["mandate-authority:mandate"]` |
| quantitative/exactly-at-the-cap | 2500 ≤ 2500. | ALLOW |
| quantitative/one-over-the-cap | 2501 > 2500 ⇒ AMOUNT_EXCEEDED; only one candidate. | DENY AMOUNT_EXCEEDED, 1 failure |
| quantitative/zero-is-a-valid-amount | 0n is an Amount. | ALLOW |
| quantitative/amount-required | no amount, `quantitative: true` ⇒ AMOUNT_REQUIRED. | DENY AMOUNT_REQUIRED |
| quantitative/delegated-budget-narrows | researcher / 600 @6 (full mandate). Path `[mandate-authority, research-authority]`: 600 ≤ 2500 but 600 > 500 ⇒ AMOUNT_EXCEEDED with `failingAuthorityId research-authority:mandate`. Researcher has no other grant ⇒ one failure. | DENY AMOUNT_EXCEEDED |
| quantitative/delegated-budget-honoured | researcher / 400: passes both; `controllingAuthorityIds` sorted `["mandate-authority:mandate","research-authority:mandate"]`; effective maxAmount 500n, maxCumulativeAmount 1000n, maxTransactions 2; usageSnapshot has both authorities (0/0n). | ALLOW |
| quantitative/non-quantitative-authority-ignores-amounts | buyer / report / plush, no amount. `mandate-authority` ⇒ ACTION_NOT_ALLOWED (and AMOUNT_REQUIRED, but action ranks first); `report-authority` ⇒ SUCCESS. | ALLOW `["report-authority:mandate"]`, effective `quantitative:false` |

And the test-suite case behind FINDING-006 (not a vector): buyer / purchase /
2501 on the full `mandate` history ⇒ `mandate-authority` fails AMOUNT_EXCEEDED
(8), `report-authority` fails ACTION_NOT_ALLOWED (5) ⇒ headline
`ACTION_NOT_ALLOWED`, failures `[ACTION_NOT_ALLOWED(report), AMOUNT_EXCEEDED(mandate)]`.
