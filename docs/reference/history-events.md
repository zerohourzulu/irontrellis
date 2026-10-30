# Legacy and format-1 event schema reference

> Reference from `HISTORY-FORMAT.md` at `00ca4c0` (SHA-256 `aecc62db80fda785ca06b60107097316cdc453416d0fa61baef42c6e903bc35b`). Established scope: the retained field, byte, code, limit and ordered-check contracts below. Not established: a new engine audit, deployment test or broader edition coverage.

Source section numbers are retained for cross-reference with [HISTORY-FORMAT.md](../HISTORY-FORMAT.md). Operational guidance stays in the narrative page. Format-2 owner-policy rules remain in the unchanged [owner-policy reference](owner-policy.md).

**Edition boundary:** Historical legacy/format-1 catalog, not the current format-2 type/field catalog. Retained writer descriptions apply to the historical profile only.

<!-- source: HISTORY-FORMAT.md:112-245; exact text except relative Markdown links -->

## 5. The event envelope

An event is a record with exactly the four keys `id`, `type`, `timestamp`, `data`:

| field | rule |
|---|---|
| `id` | Identifier: 1..256 UTF-8 bytes, well-formed, no C0 control character and no DEL; unique across the history (`EVENT_ID_DUPLICATE`) |
| `type` | one of the 29 event types (§6); position 0 must be `DEPLOYMENT_INITIALIZED` (`GENESIS_REQUIRED`), no later event may be (`GENESIS_DUPLICATE`) |
| `timestamp` | non-negative safe integer (a *U53*); must not be smaller than the previous event's (`EVENT_TIME_REGRESSION`). Units are the application's; the local API uses milliseconds |
| `data` | a plain record, captured with the canonical rules, at most 1 MiB of canonical text, closed per-type schema (§6) |

Replay checks, in order: envelope and capture (`INVALID_INPUT`), genesis position and version probe (`GENESIS_REQUIRED`, `UNSUPPORTED_EVENT_SCHEMA`, `UNSUPPORTED_VERSION`), type (`UNSUPPORTED_EVENT_TYPE`), closed schema (`EVENT_DATA_INVALID`; named-limit overruns such as an over-long identifier or an oversize list are `INVALID_INPUT`), duplicate genesis, duplicate id, time regression, control authorization in format 1 (`CONTROL_AUTHORIZATION_INVALID`), then the transition preconditions (`TRANSITION_INVALID`). A rejected event leaves the state unchanged and the rejection names the position.

Scalar types used below: **Identifier** as for `id`; **ProtocolString** (≤ 4,096 bytes, well-formed); **U53**; **Amount** (bigint, `0 … 2^256-1`); **ContentHash** (`0x` + 64 lowercase hex); **EthereumAddress** (`0x` + 40 hex, any case); **PublicKey32** (`0x` + 64 hex); **Signature** (§8).

## 6. Event types

There are 29 types. The first 25 are the Continuity 0.2 vocabulary and have the same closed schema in both formats; `ANCHOR_RECORDED`, `OWNER_KEYS_ROTATED`, `WITNESSES_BOUND` and `WITNESSES_UNBOUND` exist in format 1 only (a legacy history carrying any of them is `UNSUPPORTED_EVENT_TYPE`). Every key listed is required unless marked `?`; a key not listed is a schema violation. In format 1, the sixteen **control events** (marked ◆) additionally carry `controlAuthorization` (§7), which the schema ignores and the replay verifies.

| type | `data` fields |
|---|---|
| `DEPLOYMENT_INITIALIZED` | the genesis record, §6.1 |
| `PRINCIPAL_CREATED` ◆ | `principalId` |
| `AGENT_CREATED` ◆ | `agentId`, `principalId`, `controllerId`, `initialControlEpoch` (U53) |
| `ROLE_CREATED` ◆ | `roleId`, `principalId`, `exclusive` (must be `true`) |
| `SUCCESSION_RULE_DECLARED` ◆ | `ruleId`, `principalId`, `predecessorAgentId`, `successorAgentId`, `roleId`, `trigger` (`"AGENT_TERMINATED"`), `permittedEventTypes` (non-empty distinct list over `AGENT_TERMINATED`, `ROLE_TRANSFERRED`, `OBLIGATION_PERFORMANCE_ASSIGNED`) |
| `AGENT_APPOINTED` ◆ | `agentId`, `roleId`, `roleTenureId`, `tenureNumber` (U53), `principalId`, `successionRuleId?` |
| `AGENT_UNAPPOINTED` ◆ | `agentId`, `roleId`, `roleTenureId`, `principalId` |
| `ROLE_TRANSFERRED` ◆ | `roleId`, `fromAgentId`, `fromRoleTenureId`, `toAgentId`, `toRoleTenureId`, `toTenureNumber` (U53), `principalId`, `transferKind` (`SUCCESSION` \| `REASSIGNMENT`), `successionRuleId?` |
| `RUNTIME_SESSION_ADMITTED` ◆ | `sessionId`, `agentId`, `controllerId`, `controlEpoch` (U53), `credentialKeyId`, `expiresAt?` (U53); **legacy**: `credentialAddress` (EthereumAddress); **format 1**: `credentialScheme` (`ed25519` \| `eip191-personal-sign-keccak256`) plus `credentialPublicKey` (PublicKey32, ed25519) or `credentialAddress` (eip191), never both |
| `CONTROL_EPOCH_ADVANCED` ◆ | `agentId`, `controllerId`, `fromEpoch`, `toEpoch` (U53) |
| `AUTHORITY_GRANTED` ◆ | `grant`: a permission or prohibition record, §6.2 |
| `AUTHORITY_REVOKED` ◆ | `authorityId`, `revokerId` |
| `TRANSACTION_INTENT_DECLARED` | `intentId`, `nonce`, `actorId`, `action`, `resource`, `roleId`, `roleTenureId`, `adapterProfile` (`{profileId, profileVersion, descriptorHash}`, a known profile), `amount?` (Amount), `counterpartyId?`, `termsCommitment?` (ContentHash) |
| `TRANSACTION_INTENT_ADMITTED` | `intentId`, `evaluationTime` (U53), `expectedHistoryHead` (head), `authorizationProof` (§8.3), `runtimeAuthorizationHash` (ContentHash), `runtimeSignature` (Signature) |
| `TRANSACTION_INTENT_CONSUMED` | `intentId`, `adapterId`, `idempotencyKey` (ContentHash), `submissionFingerprint` (ContentHash), `status` (`"SUBMITTED"`), `evidenceReference` (§6.3), `acknowledgment` (adapter acknowledgment, spec 01 §F.5), `transactionReference` |
| `TRANSACTION_OUTCOME_RECORDED` | `intentId`, `status` (`CONFIRMED` \| `FAILED` \| `DISPUTED` \| `OUTCOME_UNKNOWN`), `attesterId`, `evidenceReference`, `noEffect` (adapter no-effect record; present iff `status` is `FAILED`) |
| `RECEIPT_RECORDED` | `receiptContentHash`, `receiptArtifactCommitment` (ContentHash), `intentId`, `issuerAgentId`, `runtimeSessionId`, `controlEpoch` (U53), `roleId`, `roleTenureId`, `authorizationProofHash` (ContentHash) |
| `OBLIGATION_CREATED` | `record` (§6.4), `actorId`, `administrativeAuthorization` (§8.4) |
| `OBLIGATION_PERFORMANCE_ASSIGNED` | `obligationId`, `fromAgentId`, `toAgentId`, `successionRuleId`, `actorId`, `administrativeAuthorization` |
| `OBLIGATION_STATUS_RECORDED` | `obligationId`, `fromStatus`, `toStatus` (each one of `OPEN`, `OUTCOME_UNKNOWN`, `DISPUTED`, `DISCHARGED`, `IMPOSSIBLE_OR_ESCALATED`), `actorId`, `action`, `administrativeAuthorization`, `attesterId`, `evidenceReference` |
| `AGENT_TERMINATED` ◆ | `agentId`, `principalId`, `successionRuleId`, `roleId`, `roleTenureId` |
| `OUTCOME_OBSERVATION_RECORDED` | `intentId`, `sourceAdmissionEventId`, `acknowledgment` (a `continuity-remote-service-report-acknowledgment/1` record), `actorId`, `administrativeAuthorization` (E5/E6 histories only) |
| `ATTEMPT_DUTY_CREATED` | `record` (`dutyId`, `sourceIntentId`, `sourceAdmissionEventId`, `durableRoleId`, `creationRoleTenureId`, `description` (ProtocolString), `deadline` (U53), `performanceAssigneeId`, `status` (`"OPEN"`)), `actorId`, `administrativeAuthorization` (E5/E6) |
| `ATTEMPT_DUTY_ASSIGNED` | `dutyId`, `fromAgentId`, `toAgentId`, `actorId`, `administrativeAuthorization` (E5/E6) |
| `ATTEMPT_DUTY_REVIEW_CLOSED` | `dutyId`, `actorId`, `observationEventIds` (strictly sorted Identifier list, ≤ 128), `summaryDigest` (ContentHash), `administrativeAuthorization` (E6) |
| `ANCHOR_RECORDED` ◆ | `anchoredHead` (head), `anchor` (the anchor kind: `local-head-file` \| `rekor-v2` \| `custom`), `receipt` (plain record, ≤ 64 KiB canonical), `anchoredAt` (U53). Format 1 only, §10 |
| `OWNER_KEYS_ROTATED` ◆ | `ownerKeys` (1..64 owner keys, the genesis `ownerKeys` shape, §6.1), `reason?` (Identifier-shaped: 1..256 UTF-8 bytes, no control characters; an over-long one is `INVALID_INPUT`), `nextKeyDigests?` (1..64 distinct lowercase ContentHash: the new epoch's next-key commitment, §7.2), `nextKeyAuthorizations?` (1..64 records `{keyId, scheme, signature}`, distinct `keyId`, `signature` a Signature of the scheme's length: proofs of possession by the keys it reveals, §7.2). Format 1 only; always admitted by the capacity policy; §7.1, §7.2 |
| `WITNESSES_BOUND` ◆ | `witnesses` (1..16 records `{url, verifierKey, name?, allowInsecureHttp?, registration?}`, distinct `verifierKey`), `policy` (`{quorum, requireOnOpen, maxUnwitnessedEvents}`). Format 1 only; always admitted by the capacity policy; §10.1 |
| `WITNESSES_UNBOUND` ◆ | `verifierKeys` (1..16 distinct verifier keys), `policy` (as for `WITNESSES_BOUND`), `acceptedLoss?` (`{reason, heads: [{verifierKey, head}] (1..16)}`). Format 1 only; always admitted by the capacity policy; §10.1 |

Unless stated otherwise, every field above is an Identifier. The transition preconditions of each type (which agents must exist, which tenure must be current, how usage counters move, how a succession lock is resolved) are spec 01 §D.7–D.13 and spec 03 §K; they are identical in both formats.

### 6.1 Genesis (`DEPLOYMENT_INITIALIZED.data`)

Common to both formats, all required:

| field | value |
|---|---|
| `domain` | legacy: `{protocol:"continuity", version:"0.2", deploymentId, chainId (decimal string ≥ 1), verifyingContract (EthereumAddress)}`; format 1: `{protocol:"irontrellis", version:"1", deploymentId}` |
| `adapterPolicyHash` | one of the six known adapter policy hashes E1–E6 (spec 01 §F.3); E1 (`0x00c3498e…`) is the default profile |
| `canonicalLineageId` | Identifier |
| `versions` | the exact literal set below |
| `policyVersion` | Identifier; the local API writes `continuity-local-owner/0.3-preview.1` (legacy) or `irontrellis-local-owner/1` (format 1) and refuses to open a file with another literal (`PROFILE_MISMATCH`) |
| `rootRecognitionPolicy` | `"declared-principal-root/0.2"` (unchanged literal in both formats) |
| `globalPolicySourceId` | Identifier; the `grantorId` of GLOBAL prohibitions |
| `timeSource` | `"EVENT_TIMESTAMP"` |
| `finality` | `"LOCAL_ONLY"` |

`versions`, legacy (every key required, every value exact):

```
eventSchemaVersion: "continuity-event/0.2"
receiptSchemaVersion: "continuity-receipt/0.2"
queryEnvelopeVersion: "continuity-query-envelope/0.2"
authorizationProofVersion: "continuity-authorization-proof/0.2"
runtimeAuthorizationVersion: "continuity-runtime-authorization/0.2"
administrativeAuthorizationVersion: "continuity-administrative-authorization/0.2"
signatureScheme: "eip191-personal-sign-keccak256"
```

`versions`, format 1:

```
eventSchemaVersion: "irontrellis-event/1"
historyHashAlgorithm: "sha256"
receiptSchemaVersion: "irontrellis-receipt/1"
controlAuthorizationVersion: "irontrellis-control-authorization/1"
queryEnvelopeVersion: "continuity-query-envelope/0.2"
authorizationProofVersion: "continuity-authorization-proof/0.2"
runtimeAuthorizationVersion: "continuity-runtime-authorization/0.2"
administrativeAuthorizationVersion: "continuity-administrative-authorization/0.2"
signatureScheme: "ed25519" | "eip191-personal-sign-keccak256"
```

Format 1 adds:

| field | value |
|---|---|
| `ownerKeys` | required; 1..64 records `{keyId, scheme, credential}` with distinct `keyId`; `credential` is a PublicKey32 for `ed25519` or an EthereumAddress for `eip191-personal-sign-keccak256`. The first owner key set: the keys that may sign control events and head attestations until an `OWNER_KEYS_ROTATED` event replaces them (§7.1) |
| `nextKeyDigests?` | 1..64 distinct lowercase ContentHash, each the `ownerKeyDigest` (§7.2) of a key that may replace the genesis owner keys: the next-key commitment of the first owner key epoch, committed by the history id like every other genesis field. None may be the digest of a genesis owner key (`EVENT_DATA_INVALID` at `$.data.nextKeyDigests`); more than 64 is `INVALID_INPUT`. The local API writes it by default (§7.2) |
| `capacity?` | `{ maxEvents: U53 \| null }`; absent or `null` means unlimited |
| `migratedFrom?` | `{ format: "continuity-event/0.2", historyHash, position, recordHash, genesis, genesisEventId, genesisTimestamp }` — §11 |

A note on version literals. Every literal in the format-1 `versions` block is the one actually used on the wire. Format 1 changes only the event schema (`irontrellis-event/1`), the history hash (`sha256`) and the receipt schema (`irontrellis-receipt/1`, §8.5), and adds the control-authorization challenge (`irontrellis-control-authorization/1`, §7). The signed and emitted authorization structures keep the reference's literals in **both** formats, and the genesis declares exactly those: an `authorizationProof.proofVersion` is `continuity-authorization-proof/0.2`, a runtime challenge's `version` is `continuity-runtime-authorization/0.2`, an administrative challenge's `version` is `continuity-administrative-authorization/0.2`, and a query envelope's `version` is `continuity-query-envelope/0.2`. An authorization result's `operationVersion` (`continuity-authorization/0.2`) is an operation literal, not a genesis version.

### 6.2 Grants

`AUTHORITY_GRANTED.data.grant` is one of:

```
PERMISSION:  { kind:"PERMISSION", authorityId, grantorId, granteeId, rootAuthorityId, parentAuthorityId?, independent: boolean, constraints }
ROOT prohibition:   { kind:"PROHIBITION", scope:"ROOT", authorityId, grantorId, rootAuthorityId, parentAuthorityId?, subjectActorId?, constraints }
GLOBAL prohibition: { kind:"PROHIBITION", scope:"GLOBAL", authorityId, grantorId, subjectActorId?, constraints }
```

`constraints` = `{ actions (1..256 distinct Identifiers), resources (1..256), quantitative: boolean, maxDelegationDepth: U53, requiredIntersectionIds (0..32 Identifiers), notBefore?: U53, expiresAt?: U53, maxAmount?: Amount, maxCumulativeAmount?: Amount, maxTransactions?: U53 }`. Amount ceilings require `quantitative: true`. A root permission has `rootAuthorityId === authorityId` and no `parentAuthorityId`; a delegation names its parent and inherits the parent's root, and replay requires its constraints to be *attenuated* relative to the parent (spec 01 §D.8). The proof structures (§8.3) carry grants in **normalized** form (constraint lists sorted); the history carries them as written.

### 6.3 Evidence references

A tagged record, one of:

```
{ kind:"EVENT", eventId, eventType, position: U53, historyHash: ContentHash }
{ kind:"AUTHORITY", authorityId, grantEventId }
{ kind:"RUNTIME_CREDENTIAL", keyId, sessionId, admissionEventId }
{ kind:"RECEIPT_COMMITMENT", receiptContentHash: ContentHash, eventId, position: U53 }
{ kind:"EXTERNAL", evidenceType, reference, attesterId }
```

### 6.4 Obligation record

`{ obligationId, sourceIntentId, causalReceiptContentHash: ContentHash, durableRoleId, creationRoleTenureId, description: ProtocolString, trigger, deadline: U53, status: "OPEN" | "OUTCOME_UNKNOWN", beneficiaryId, termsCommitment: ContentHash, performanceAssigneeId, successionRuleId, counterpartyId?, transitionPolicies: [{ fromStatus, toStatus, acceptedAttesterIds (1..256), action, requiredAuthorityIds (1..256) }, …] (non-empty, distinct (from,to) pairs) }`.


