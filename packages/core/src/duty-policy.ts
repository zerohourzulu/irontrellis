/**
 * The ported duty-policy machinery (SPEC-IRONTRELLIS-CORE-v2 §13; LEFT-OUT-SWEEP B1–B7, B9, B14), ported line for
 * line from Continuity v0.3.0-preview.10.2 (`packages/reference-0.3/packages/core-0.2/src/core/duty-policy.ts` and
 * `duty-disposition.ts`, cited below as `duty-policy.ts:N` / `duty-disposition.ts:N`). The frozen source is normative
 * for the rules; this module is the pure half: the rules record and its hash, the descriptor derivation, the activation
 * requirements, the evidence index, the finding challenge, the eligibility rules, the fresh-eligibility writer check and
 * the duty view. The replay transitions are in `state.ts` (types 29–31), the two-phase producer in `administration.ts`,
 * the host API in `duties.ts`.
 *
 * Format-2 adaptations (SPEC §13.1–13.2), each marked `[F2]` where it applies:
 * - `genesisHash = state.eventHistoryHashes[0]` — the chain hash `recordHash(0)` in format 2 (E1 keeps
 *   `eventHistoryHashes[p] = recordHash(p)`), the wrapper hash the frozen code used in legacy (`duty-policy.ts:144`);
 * - `domain` is the history's own (format-2) domain, `dutyRecordHash = hashCanonical(duty.record)` over the record as
 *   written (Amount strings in format 2 — the duty record carries none);
 * - every hash uses the history's algorithm (`state.hashAlgorithm`: sha256 in format 2, keccak in legacy), so the evidence
 *   index's `contentHash` is `eventHash(e)` in format 2 (SPEC §13.2: "the two coincide");
 * - `priorHead` of the finding challenge is the §4.4 head (`state.head`, the full head);
 * - `runtimeSignature` is a §6.3 signature of the attester session's scheme (64 or 65 bytes), verified through the suite;
 * - the administrative proof whose hash the finding carries uses the `/2` literals of the history (the authority engine
 *   keys the literals on the genesis);
 * - the actions are `ACTIVATE_DUTY_POLICY`, `ATTEST_DUTY_FINDING` and `RECORD_DUTY_DISPOSITION` (B14: there is no
 *   `RECORD_DUTY_CONTEST`).
 * Nothing here appends, signs or grants authority.
 */
import { canonicalEncode, captureValue } from "./canonical.ts";
import { hashCanonical } from "./hash.ts";
import { createAdministrativePolicyProof, verifySessionSignature } from "./authority.ts";
import { ADAPTER_POLICY_E5_HASH, ADAPTER_POLICY_E6_HASH, REMOTE_SERVICE_REPORT_ADAPTER_ID, type AdapterIdentity } from "./adapter-editions.ts";
import { DUTY_CRITERIA, DUTY_FINDING_VERSION, DUTY_POLICY_RULES_HASH, DUTY_POLICY_VERSION } from "./events.ts";
import { identifier, record } from "./input.ts";
import { sessionExpiredAt } from "./session-auth.ts";
import type {
  AdministrativeRequirements, AttemptDutyState, AuthorizationDomain, AuthorizationProof, CanonicalEvent, ContentHash, HistoryHead, ReplayState, RuntimeSessionRecord, U53,
} from "./types.ts";

type Rec = Readonly<Record<string, unknown>>;

// ---------------------------------------------------------------- SPEC §13.0: the rules record (sweep row B1), carried verbatim

export const DUTY_VIEW_VERSION = "continuity-attempt-duty-view/1" as const;
export const DUTY_EVIDENCE_INDEX_VERSION = "continuity-duty-evidence-index/1" as const;
export const DUTY_CRITERIA_PROFILE = "local-investigation/1" as const;
export { DUTY_POLICY_VERSION, DUTY_POLICY_RULES_HASH, DUTY_FINDING_VERSION, DUTY_CRITERIA };

/**
 * `duty-policy.ts:12-96`, verbatim (its `writerProfile` keeps the string `"continuity-segmented-local/1"` because it is
 * inside the hashed record). The pinned literal `DUTY_POLICY_RULES_HASH` is Continuity's `hashCanonical` of this record,
 * i.e. **keccak256** of its canonical text (the legacy engine's hash; sha256 gives 0xd6e5…1ce7): the literal is what every
 * descriptor and finding carries, in every format, so it is never re-hashed with the history's algorithm.
 * `dutyPolicyRulesHashIsPinned` asserts it at load and the tests assert it again.
 */
export const DUTY_POLICY_RULES = captureValue({
  "version": "continuity-attempt-disposition/1",
  "criteriaProfile": "local-investigation/1",
  "scope": "ONE_EXISTING_E5_OR_E6_ATTEMPT_DUTY",
  "eventTypes": [
    "ATTEMPT_DUTY_POLICY_ACTIVATED",
    "ATTEMPT_DUTY_DISPOSITION_RECORDED",
    "ATTEMPT_DUTY_CONTEST_RECORDED"
  ],
  "activation": {
    "action": "ACTIVATE_DUTY_POLICY",
    "resourcePrefix": "duty-policy:",
    "principal": "EXISTING_SOURCE_ROLE_PRINCIPAL",
    "grant": "EXACT_NONDELEGABLE_UNCAPPED_RECOGNIZED_ROOT",
    "signer": "CURRENT_DUTY_ROLE_OCCUPANT_RUNTIME",
    "activationLimit": 1,
    "changesGenesisOrAdapterPolicy": false
  },
  "attestation": {
    "version": "continuity-duty-finding/1",
    "purposes": [
      "DISPOSITION",
      "CONTEST"
    ],
    "action": "ATTEST_DUTY_FINDING",
    "resourcePrefix": "duty:",
    "acceptedRole": "ONE_PREEXISTING_ROLE_UNDER_SOURCE_PRINCIPAL",
    "findingProof": "RECOMPUTED_FROM_PRIOR_STATE_HASH_BOUND"
  },
  "transition": {
    "action": "RECORD_DUTY_DISPOSITION",
    "resourcePrefix": "duty:",
    "signer": "CURRENT_ASSIGNEE_AND_DUTY_ROLE_OCCUPANT_RUNTIME",
    "signatureOrder": [
      "FINDING",
      "OUTER_EFFECT_INCLUDING_FINDING_SIGNATURE"
    ],
    "postSignEligibility": "BOTH_SIGNERS_AT_FRESH_TIME_AND_UNCHANGED_HEAD"
  },
  "criteria": [
    "SOURCE_REVIEWED",
    "HISTORY_REVIEWED",
    "FINDING_RECORDED",
    "CONTROL_REVIEWED"
  ],
  "criterionStates": [
    "SATISFIED",
    "UNAVAILABLE",
    "UNRESOLVED"
  ],
  "criterionReasonMaxUtf8Bytes": 256,
  "nextStepMaxUtf8Bytes": 512,
  "dispositions": [
    "COMPLETED_UNDER_POLICY",
    "ESCALATED"
  ],
  "viewVersion": "continuity-attempt-duty-view/1",
  "currentViews": [
    "OPEN",
    "COMPLETED_UNDER_POLICY",
    "ESCALATED",
    "NEEDS_REVIEW",
    "CONTESTED"
  ],
  "completion": "ALL_CRITERIA_SATISFIED_WITHOUT_ACCEPTED_CONTEST",
  "outstandingFalseOnlyFor": "CURRENT_COMPLETED_UNDER_POLICY",
  "externalOutcome": "NOT_PROVEN",
  "contest": "PERSISTENT_NO_WITHDRAWAL_OR_ADJUDICATION",
  "documentDigestAlgorithm": "sha256",
  "evidenceIndexVersion": "continuity-duty-evidence-index/1",
  "freshness": "COMPLETE_SOURCE_LIFECYCLE_OBSERVATIONS_REVIEWS_ASSIGNMENTS_AND_CONTESTS",
  "excludeFromFreshness": [
    "DISPOSITIONS",
    "UNRELATED_EVENTS",
    "LATER_CREDENTIAL_OR_AUTHORITY_CHANGES_ALONE"
  ],
  "writerProfile": "continuity-segmented-local/1",
  "limits": {
    "dispositions": 4,
    "contests": 2,
    "reservedAtActivation": 6,
    "releaseUnusedOnCompletion": false,
    "raiseExistingStorageOrShapeLimits": false
  }
}) as Rec;
/** SPEC §13.0: the builder re-hashes the rules record and must obtain the pinned literal (checked once at load, and by the tests). */
export const DUTY_POLICY_RULES_HASH_ALGORITHM = "keccak256" as const;
export const dutyPolicyRulesHashIsPinned = (): boolean => hashCanonical(DUTY_POLICY_RULES, DUTY_POLICY_RULES_HASH_ALGORITHM) === DUTY_POLICY_RULES_HASH;
if (!dutyPolicyRulesHashIsPinned()) throw new Error(`DUTY_POLICY_RULES does not hash to ${DUTY_POLICY_RULES_HASH} (SPEC §13.0)`);

/** SPEC §13.2 / `duty-disposition.ts:62,67`: the per-duty limits (also `DUTY_POLICY_RULES.limits`, and the capacity quota of `capacity.ts`). */
export const DUTY_DISPOSITION_LIMIT = 4;
export const DUTY_CONTEST_LIMIT = 2;
export const ACTIVATE_DUTY_POLICY_ACTION = "ACTIVATE_DUTY_POLICY" as const;
export const ATTEST_DUTY_FINDING_ACTION = "ATTEST_DUTY_FINDING" as const;
export const RECORD_DUTY_DISPOSITION_ACTION = "RECORD_DUTY_DISPOSITION" as const;

// ---------------------------------------------------------------- types (duty-policy.ts:97-124, duty-disposition.ts:9-26)

export type DutyDocumentDigest = Readonly<{ algorithm: "sha256"; value: ContentHash }>;
export type DutyPolicySelection = Readonly<{ dutyId: string; incidentSourceDigest: DutyDocumentDigest; acceptedAttesterRoleId: string }>;
export type DutyPolicyDescriptor = Readonly<{
  version: typeof DUTY_POLICY_VERSION; rulesHash: typeof DUTY_POLICY_RULES_HASH; criteriaProfile: typeof DUTY_CRITERIA_PROFILE;
  domain: AuthorizationDomain; genesisHash: ContentHash; baseAdapterPolicyHash: ContentHash;
  dutyId: string; dutyCreationEventId: string; dutyRecordHash: ContentHash;
  sourceIntentId: string; sourceAdmissionEventId: string; durableRoleId: string; principalId: string;
  incidentSourceDigest: DutyDocumentDigest; acceptedAttesterRoleId: string;
  dispositionLimit: 4; contestLimit: 2;
}>;
/** `ATTEMPT_DUTY_POLICY_ACTIVATED.data` without the administrative wrapper (`duty-policy.ts:109-112`). */
export type DutyPolicyActivatedEffect = Readonly<{ actorId: string; descriptor: DutyPolicyDescriptor; descriptorHash: ContentHash; activationAuthorityId: string }>;
/**
 * The in-memory activation record (`duty-policy.ts:113-117`, the frozen `PortableDutyPolicyActivation`): `priorHead` is the
 * full head before the activation and `eventPosition` its position. The §7.2 `duty.policy` record (state-records.ts) is
 * derived from it with `position` and the short head.
 */
export type DutyPolicyActivation = Readonly<{
  descriptor: DutyPolicyDescriptor; descriptorHash: ContentHash; activationAuthorityId: string; actorId: string;
  eventId: string; eventPosition: U53; activatedAt: U53; priorHead: HistoryHead; dispositionCount: U53; contestCount: U53;
}>;
/** One accepted disposition or contest of a duty (the §7.2 `duty.dispositions` row; kept per duty in position order). */
export type DutyDispositionRef = Readonly<{ eventId: string; position: U53; type: DutyTransitionType; findingHash: ContentHash }>;
export type DutyCriterion = "SOURCE_REVIEWED" | "HISTORY_REVIEWED" | "FINDING_RECORDED" | "CONTROL_REVIEWED";
export type DutyChecklist = Readonly<Record<DutyCriterion, Readonly<{ state: "SATISFIED" | "UNAVAILABLE" | "UNRESOLVED"; reason: string }>>>;
export type DutyDispositionOperation = Readonly<{ disposition: "COMPLETED_UNDER_POLICY" | "ESCALATED"; checklist: DutyChecklist; reportDigest: DutyDocumentDigest; nextStep: string | null }>;
export type DutyContestOperation = Readonly<{ targetDispositionEventId: string; reason: string; reportDigest: DutyDocumentDigest }>;
export type DutyOperation = DutyDispositionOperation | DutyContestOperation;
export type DutyTransitionType = "ATTEMPT_DUTY_DISPOSITION_RECORDED" | "ATTEMPT_DUTY_CONTEST_RECORDED";
export type DutyFindingChallenge = Readonly<{
  version: typeof DUTY_FINDING_VERSION; purpose: "DISPOSITION" | "CONTEST"; domain: AuthorizationDomain;
  rulesHash: typeof DUTY_POLICY_RULES_HASH; descriptorHash: ContentHash; activationEventId: string; dutyId: string; sourceAdmissionEventId: string;
  transitionEventId: string; transitionEventType: DutyTransitionType; evaluationTime: U53; priorHead: HistoryHead;
  latestAssignmentEventId: string; previousDispositionEventId: string | null; evidenceIndexHash: ContentHash; operation: DutyOperation;
  attesterId: string; runtimeSessionId: string; credentialKeyId: string; controlEpoch: U53; roleId: string; roleTenureId: string;
  attestationAuthorityId: string; dispositionAuthorityId: string; authorityProofHash: ContentHash;
}>;
export type DutyFinding = Readonly<{ challenge: DutyFindingChallenge; runtimeSignature: string }>;
/** `ATTEMPT_DUTY_DISPOSITION_RECORDED` / `…_CONTEST_RECORDED` data without the administrative wrapper (`duty-disposition.ts:23`). */
export type DutyDispositionEffect = Readonly<{
  version: typeof DUTY_POLICY_VERSION; rulesHash: typeof DUTY_POLICY_RULES_HASH; dutyId: string; actorId: string; dispositionAuthorityId: string; finding: DutyFinding;
}>;
/** The writer's request for a finding (`duty-disposition.ts:24`). */
export type DutyFindingRequest = Readonly<{
  dutyId: string; actorId: string; attesterId: string; attesterRuntimeSessionId: string; attestationAuthorityId: string; dispositionAuthorityId: string; operation: DutyOperation;
}>;
export type DutyUnsignedTransition = Readonly<{ id: string; type: DutyTransitionType; timestamp: U53; data: DutyDispositionEffect }>;
export type DutyEvidenceIndex = Readonly<{
  version: typeof DUTY_EVIDENCE_INDEX_VERSION; domain: AuthorizationDomain; dutyId: string; dutyCreationEventId: string; activationEventId: string;
  sourceAdmissionEventId: string; latestAssignmentEventId: string; recordCount: U53; counts: Readonly<Record<string, U53>>;
  records: readonly Readonly<{ eventId: string; eventType: string; contentHash: ContentHash }>[];
}>;
export type DutyDispositionView = "OPEN" | "COMPLETED_UNDER_POLICY" | "ESCALATED" | "NEEDS_REVIEW" | "CONTESTED";
export type DutyLastRecordedDisposition = Readonly<{
  eventId: string; eventPosition: U53; timestamp: U53; disposition: "COMPLETED_UNDER_POLICY" | "ESCALATED"; findingHash: ContentHash; evidenceIndexHash: ContentHash; reportDigest: DutyDocumentDigest;
}>;
export type DutyPolicyView = Readonly<{
  version: typeof DUTY_VIEW_VERSION; dutyId: string; dutyDisposition: DutyDispositionView; outstanding: boolean;
  lastRecordedDisposition: DutyLastRecordedDisposition | null; reasons: readonly string[];
  externalOutcome: "NOT_PROVEN"; policy: DutyPolicyActivation; observedHead: HistoryHead; currentAssigneeId: string; latestAssignmentEventId: string;
  evidenceScope: Readonly<{ kind: "COMPLETE_CAPTURED_HISTORY"; head: HistoryHead }>;
}>;

const same = (a: unknown, b: unknown): boolean => canonicalEncode(a) === canonicalEncode(b);
const hashOf = (state: ReplayState, value: unknown): ContentHash => hashCanonical(value, state.hashAlgorithm);

// ---------------------------------------------------------------- SPEC §13.1 (sweep row B2): descriptor derivation (duty-policy.ts:131-149)

/** `duty-policy.ts:131-149`: every source fact derived from the verified prefix; `undefined` when the selection does not match an existing E5/E6 duty. */
export function deriveDutyPolicyDescriptor(state: ReplayState, selection: DutyPolicySelection): DutyPolicyDescriptor | undefined {
  // duty-policy.ts:132-133 — E5 or E6 genesis only
  if (state.genesis.adapterPolicyHash !== ADAPTER_POLICY_E5_HASH && state.genesis.adapterPolicyHash !== ADAPTER_POLICY_E6_HASH) return undefined;
  const duty = state.attemptDuties.get(selection.dutyId); // :134-135
  if (duty === undefined) return undefined;
  const source = state.intentDeclarations.get(duty.record.sourceIntentId)?.data; // :136
  const admission = state.intentAdmissions.get(duty.record.sourceIntentId); // :137
  const role = state.roles.get(duty.record.durableRoleId as string), attester = state.roles.get(selection.acceptedAttesterRoleId); // :138
  // :139-141 — source intent admitted under the remote-service-report adapter, durable role = the source role, attester role under the same principal
  if (source === undefined || admission === undefined || role === undefined || source.roleId !== role.id || attester === undefined ||
      attester.principalId !== role.principalId || duty.record.sourceAdmissionEventId !== admission.admissionEventId ||
      (admission.adapterIdentity as AdapterIdentity).adapterProfile.profileId !== REMOTE_SERVICE_REPORT_ADAPTER_ID) return undefined;
  // :142-148 — [F2] genesisHash = eventHistoryHashes[0] (recordHash(0) in format 2), domain = the history's domain, dutyRecordHash over the record as written
  return captureValue({
    version: DUTY_POLICY_VERSION, rulesHash: DUTY_POLICY_RULES_HASH, criteriaProfile: DUTY_CRITERIA_PROFILE, domain: state.genesis.domain,
    genesisHash: state.eventHistoryHashes[0], baseAdapterPolicyHash: state.genesis.adapterPolicyHash,
    dutyId: duty.record.dutyId, dutyCreationEventId: duty.creationEventId, dutyRecordHash: hashOf(state, duty.record),
    sourceIntentId: duty.record.sourceIntentId, sourceAdmissionEventId: admission.admissionEventId,
    durableRoleId: role.id, principalId: role.principalId, incidentSourceDigest: selection.incidentSourceDigest,
    acceptedAttesterRoleId: attester.id, dispositionLimit: 4, contestLimit: 2,
  }) as DutyPolicyDescriptor;
}

/** `duty-policy.ts:152-171` (`buildPortableDutyPolicyDescriptor`): the selection helper with its closed-shape checks; throws TypeError on a bad selection. Confers no authority. */
export function buildDutyPolicyDescriptor(state: ReplayState, input: unknown): DutyPolicyDescriptor {
  const isRecord = (v: unknown): v is Rec => v !== null && typeof v === "object" && !Array.isArray(v);
  const exact = (item: unknown, keys: readonly string[]): item is Rec => isRecord(item) && Object.keys(item).length === keys.length && keys.every((k) => Object.hasOwn(item, k));
  let value: unknown;
  try { value = captureValue(input, { maxTotalBytes: 2048 }); } catch { throw new TypeError("Invalid duty policy selection."); }
  if (!exact(value, ["dutyId", "incidentSourceDigest", "acceptedAttesterRoleId"]) || typeof value.dutyId !== "string" || typeof value.acceptedAttesterRoleId !== "string" ||
      !exact(value.incidentSourceDigest, ["algorithm", "value"])) throw new TypeError("Invalid duty policy selection.");
  const digest = value.incidentSourceDigest;
  if (digest.algorithm !== "sha256" || typeof digest.value !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(digest.value)) throw new TypeError("Invalid incident document digest.");
  const descriptor = deriveDutyPolicyDescriptor(state, value as unknown as DutyPolicySelection);
  if (descriptor === undefined) throw new TypeError("Duty policy selection does not match the existing case.");
  return descriptor;
}

// ---------------------------------------------------------------- SPEC §13.1 (sweep row B3): activation requirements (duty-policy.ts:174-207)

/**
 * `duty-policy.ts:174-201`: the exact-root and immutable-selection requirements of an activation, re-run during replay;
 * `undefined` when any check fails (the reducer answers TRANSITION_INVALID). In SPEC §13.1 order after the schema and the
 * E5/E6 check: no policy yet (:177), the descriptor equals the re-derived one and `descriptorHash` is its hash (:178-179),
 * the actor is the current occupant of the duty role and not terminated (:180-183), `activationAuthorityId` is an unrevoked
 * root PERMISSION from the source principal to the actor (:184-189) with exactly the one action and resource, depth 0, an
 * `expiresAt` after the event time, inside `notBefore`, and no quantitative constraint (:190-194).
 */
export function dutyPolicyActivationRequirements(state: ReplayState, data: DutyPolicyActivatedEffect, timestamp: U53): AdministrativeRequirements | undefined {
  const d = data.descriptor;
  if (state.attemptDutyPolicies.has(d.dutyId)) return undefined; // :177 — one activation per duty
  const expected = deriveDutyPolicyDescriptor(state, d); // :178
  if (expected === undefined || !same(d, expected) || data.descriptorHash !== hashOf(state, expected)) return undefined; // :179
  const role = state.roles.get(expected.durableRoleId); // :180
  const tenure = role?.currentTenureId === undefined ? undefined : state.tenures.get(role.currentTenureId); // :181
  const actor = state.agents.get(data.actorId); // :182
  if (role === undefined || tenure === undefined || tenure.closed || tenure.agentId !== data.actorId || actor === undefined || actor.terminated) return undefined; // :183
  const record = state.authorities.get(data.activationAuthorityId), grant = record?.grant; // :184
  const root = state.recognizedRoots.get(data.activationAuthorityId); // :185
  if (record === undefined || record.revocationEventId !== undefined || grant === undefined || grant.kind !== "PERMISSION" || // :186
      Object.hasOwn(grant, "parentAuthorityId") || grant.authorityId !== grant.rootAuthorityId || // :187
      grant.grantorId !== role.principalId || grant.granteeId !== data.actorId || root === undefined || root.principalId !== role.principalId || // :188
      root.rootGrantEventId !== record.grantEventId) return undefined; // :189
  const c = grant.constraints, resource = `duty-policy:${data.descriptorHash}`; // :190
  if (c.quantitative || c.actions.length !== 1 || c.actions[0] !== ACTIVATE_DUTY_POLICY_ACTION || // :191
      c.resources.length !== 1 || c.resources[0] !== resource || c.maxDelegationDepth !== 0 || // :192
      c.expiresAt === undefined || timestamp >= c.expiresAt || (c.notBefore !== undefined && timestamp < c.notBefore) || // :193
      Object.hasOwn(c, "maxAmount") || Object.hasOwn(c, "maxCumulativeAmount") || Object.hasOwn(c, "maxTransactions")) return undefined; // :194
  // :195-200 — the ordinary canonical source-principal winner is selected first; `dutyPolicyActivationProofMatches` then requires this exact root.
  return Object.freeze({
    request: Object.freeze({ actorId: data.actorId, action: ACTIVATE_DUTY_POLICY_ACTION, resource, claimedAt: timestamp }),
    requiredPrincipalId: role.principalId, requiredAuthorityIds: Object.freeze([]), roleId: role.id, roleTenureId: tenure.id,
  });
}

/** `duty-policy.ts:204-207`: the selected root must be the main permission path (recognized root = the grant, path of length 1), never an alternate root. */
export function dutyPolicyActivationProofMatches(proof: AuthorizationProof, authorityId: string): boolean {
  return proof.recognizedRoot.rootAuthorityId === authorityId && proof.permissionPath.length === 1 && proof.permissionPath[0]!.authorityId === authorityId;
}

// ---------------------------------------------------------------- SPEC §13.2 (sweep row B4): evidence index and the finding (duty-disposition.ts:28-97)

const SOURCE_TYPES: ReadonlySet<string> = new Set(["TRANSACTION_INTENT_DECLARED", "TRANSACTION_INTENT_ADMITTED", "TRANSACTION_INTENT_CONSUMED", "TRANSACTION_OUTCOME_RECORDED", "RECEIPT_RECORDED", "OUTCOME_OBSERVATION_RECORDED"]); // :34
const DUTY_TYPES: ReadonlySet<string> = new Set(["ATTEMPT_DUTY_ASSIGNED", "ATTEMPT_DUTY_REVIEW_CLOSED", "ATTEMPT_DUTY_CONTEST_RECORDED"]); // :35

/** `duty-disposition.ts:28-30`: the accepted dispositions (or contests) of a duty, in position order (kept per duty by the reducer instead of a filter over every event). */
export const dutyRecordsOf = (state: ReplayState, dutyId: string, type: DutyTransitionType): readonly DutyDispositionRef[] =>
  (state.attemptDutyDispositions?.get(dutyId) ?? []).filter((r) => r.type === type);
const eventOf = (state: ReplayState, ref: DutyDispositionRef): CanonicalEvent => state.events[ref.position]!;
const latestAssignmentEventId = (duty: AttemptDutyState): string => (duty.assignments.at(-1)?.eventId as string | undefined) ?? duty.creationEventId;

/**
 * `duty-disposition.ts:31-43`: the evidence index of a duty with an active policy, over the accepted events in position order —
 * the creation event, the activation event, every lifecycle record of the source intent (the six `SOURCE_TYPES` with
 * `data.intentId`), and every assignment, review and contest of the duty; dispositions are excluded. [F2] `contentHash`
 * is the history's hash of the canonical event (`eventHash` in format 2). Throws when the duty has no policy.
 */
export function deriveDutyEvidenceIndex(state: ReplayState, dutyId: string): DutyEvidenceIndex {
  const duty = state.attemptDuties.get(dutyId), policy = state.attemptDutyPolicies.get(dutyId);
  if (duty === undefined || policy === undefined) throw new TypeError("Duty policy unavailable."); // :33
  const sourceIntentId = duty.record.sourceIntentId;
  const records: { eventId: string; eventType: string; contentHash: ContentHash }[] = [];
  const counts: Record<string, number> = {};
  for (const e of state.events) { // :36-38
    const d = e.data;
    if (e.id === duty.creationEventId || e.id === policy.eventId || (SOURCE_TYPES.has(e.type) && d.intentId === sourceIntentId) || (DUTY_TYPES.has(e.type) && d.dutyId === dutyId)) {
      records.push({ eventId: e.id, eventType: e.type, contentHash: hashOf(state, e) });
      counts[e.type] = (counts[e.type] ?? 0) + 1; // :39
    }
  }
  return captureValue({ // :40-42
    version: DUTY_EVIDENCE_INDEX_VERSION, domain: state.genesis.domain, dutyId, dutyCreationEventId: duty.creationEventId, activationEventId: policy.eventId,
    sourceAdmissionEventId: duty.record.sourceAdmissionEventId, latestAssignmentEventId: latestAssignmentEventId(duty), recordCount: records.length, counts, records,
  }) as DutyEvidenceIndex;
}

/**
 * `duty-disposition.ts:44-53`: the requirements of the attester (`attestation: true`, action ATTEST_DUTY_FINDING, role = the
 * descriptor's attester role) or of the outer signer (RECORD_DUTY_DISPOSITION, role = the durable role, who must also be the
 * duty's current assignee), resource `duty:<descriptorHash>`; `undefined` when the actor is not the current occupant.
 */
export function dutyRequirements(state: ReplayState, dutyId: string, actorId: string, authorityId: string, attestation: boolean, time: U53): AdministrativeRequirements | undefined {
  const policy = state.attemptDutyPolicies.get(dutyId), duty = state.attemptDuties.get(dutyId); // :45
  if (policy === undefined || duty === undefined) return undefined;
  const role = state.roles.get(attestation ? policy.descriptor.acceptedAttesterRoleId : (duty.record.durableRoleId as string)); // :46
  const tenure = role?.currentTenureId === undefined ? undefined : state.tenures.get(role.currentTenureId); // :47
  const actor = state.agents.get(actorId); // :48
  if (role === undefined || role.principalId !== policy.descriptor.principalId || tenure === undefined || tenure.closed || tenure.agentId !== actorId || actor === undefined || actor.terminated ||
      (!attestation && duty.currentAssigneeId !== actorId)) return undefined; // :49-50
  return Object.freeze({ // :51-52
    request: Object.freeze({ actorId, action: attestation ? ATTEST_DUTY_FINDING_ACTION : RECORD_DUTY_DISPOSITION_ACTION, resource: `duty:${policy.descriptorHash}`, claimedAt: time }),
    requiredPrincipalId: role.principalId, requiredAuthorityIds: Object.freeze([authorityId]), roleId: role.id, roleTenureId: tenure.id,
  });
}

/** `duty-disposition.ts:54-58`: the session is the actor's, in the actor's current epoch and unexpired at `time`. */
export function dutySessionEligible(state: ReplayState, requirements: AdministrativeRequirements, sessionId: string, time: U53): RuntimeSessionRecord | undefined {
  const session = state.runtimeSessions.get(sessionId), actor = state.agents.get(requirements.request.actorId);
  // G6.7 A-149 (r4 §6.2 step 4, §16.2 step 3, A-52.2): in a format-2 state a session without an expiry (a migrated prefix
  // session, `expiresAt: null` in its §7.2 record) is expired at every post-prefix position, for the attester as for
  // every other purpose; before G6.7 this helper treated it as never expiring.
  return session !== undefined && actor !== undefined && !actor.terminated && session.agentId === actor.id && session.controlEpoch === actor.currentControlEpoch &&
    !sessionExpiredAt(state, session, time) ? session : undefined;
}

/**
 * `duty-disposition.ts:59-68` (sweep row B5): a disposition needs `dispositionCount < 4`; COMPLETED_UNDER_POLICY needs all four
 * criteria SATISFIED, no accepted contest and `nextStep: null`; ESCALATED needs a non-blank `nextStep` and (a criterion not
 * SATISFIED or a contest). A contest needs `contestCount < 2` and a target that is an accepted disposition of this duty.
 */
export function dutyOperationEligible(state: ReplayState, dutyId: string, type: DutyTransitionType, operation: DutyOperation): boolean {
  const policy = state.attemptDutyPolicies.get(dutyId);
  if (policy === undefined) return false; // :60
  if (type === "ATTEMPT_DUTY_DISPOSITION_RECORDED") {
    if (policy.dispositionCount >= DUTY_DISPOSITION_LIMIT || !("disposition" in operation)) return false; // :62
    const all = DUTY_CRITERIA.every((k) => operation.checklist[k as DutyCriterion].state === "SATISFIED"); // :63
    return operation.disposition === "COMPLETED_UNDER_POLICY" ? all && policy.contestCount === 0 && operation.nextStep === null // :64
      : (!all || policy.contestCount > 0) && typeof operation.nextStep === "string" && operation.nextStep.trim().length > 0; // :65
  }
  return policy.contestCount < DUTY_CONTEST_LIMIT && "targetDispositionEventId" in operation && // :67
    dutyRecordsOf(state, dutyId, "ATTEMPT_DUTY_DISPOSITION_RECORDED").some((r) => r.eventId === operation.targetDispositionEventId);
}

/**
 * `duty-disposition.ts:70-87`: the finding challenge of a request against the pre-event state (`event.data` is the writer's
 * request, already shape-checked). Throws TypeError when the operation is ineligible, the authorities are unavailable or
 * the attester session is not eligible at `evaluationTime = event.timestamp`. [F2] `priorHead` is the full §4.4 head,
 * `authorityProofHash` hashes the `/2` administrative proof, `evidenceIndexHash` the index with `eventHash` content hashes.
 */
export function deriveDutyFinding(state: ReplayState, event: Readonly<{ id: string; type: DutyTransitionType; timestamp: U53; data: DutyFindingRequest }>): DutyFindingChallenge {
  const d = event.data, policy = state.attemptDutyPolicies.get(d.dutyId); // :71
  if (policy === undefined || event.timestamp < state.head.canonicalTime || !dutyOperationEligible(state, d.dutyId, event.type, d.operation)) throw new TypeError("Invalid duty operation."); // :72
  const req = dutyRequirements(state, d.dutyId, d.attesterId, d.attestationAuthorityId, true, event.timestamp); // :73
  const outer = dutyRequirements(state, d.dutyId, d.actorId, d.dispositionAuthorityId, false, event.timestamp); // :74
  if (req === undefined || outer === undefined || createAdministrativePolicyProof(state, outer, event.timestamp) === undefined) throw new TypeError("Duty authority unavailable."); // :75
  const session = dutySessionEligible(state, req, d.attesterRuntimeSessionId, event.timestamp); // :76
  const proof = createAdministrativePolicyProof(state, req, event.timestamp); // :77
  if (session === undefined || proof === undefined) throw new TypeError("Finding authority unavailable."); // :78
  const index = deriveDutyEvidenceIndex(state, d.dutyId); // :79
  return captureValue({ // :80-86
    version: DUTY_FINDING_VERSION, purpose: event.type === "ATTEMPT_DUTY_DISPOSITION_RECORDED" ? "DISPOSITION" : "CONTEST",
    domain: state.genesis.domain, rulesHash: DUTY_POLICY_RULES_HASH, descriptorHash: policy.descriptorHash, activationEventId: policy.eventId, dutyId: d.dutyId,
    sourceAdmissionEventId: policy.descriptor.sourceAdmissionEventId, transitionEventId: event.id, transitionEventType: event.type, evaluationTime: event.timestamp,
    priorHead: state.head, latestAssignmentEventId: index.latestAssignmentEventId,
    previousDispositionEventId: dutyRecordsOf(state, d.dutyId, "ATTEMPT_DUTY_DISPOSITION_RECORDED").at(-1)?.eventId ?? null,
    evidenceIndexHash: hashOf(state, index), operation: d.operation, attesterId: d.attesterId, runtimeSessionId: session.id, credentialKeyId: session.credentialKeyId,
    controlEpoch: session.controlEpoch, roleId: req.roleId, roleTenureId: req.roleTenureId, attestationAuthorityId: d.attestationAuthorityId,
    dispositionAuthorityId: d.dispositionAuthorityId, authorityProofHash: hashOf(state, proof),
  }) as DutyFindingChallenge;
}

/** The writer's request a recorded finding implies (`duty-disposition.ts:92-93`); the shape `validateDutyFinding` re-derives from. */
export const dutyFindingRequestOf = (data: DutyDispositionEffect): DutyFindingRequest => {
  const c = data.finding.challenge;
  return Object.freeze({
    dutyId: data.dutyId, actorId: data.actorId, attesterId: c.attesterId, attesterRuntimeSessionId: c.runtimeSessionId,
    attestationAuthorityId: c.attestationAuthorityId, dispositionAuthorityId: data.dispositionAuthorityId, operation: c.operation,
  });
};

/**
 * `duty-disposition.ts:88-97`: the recorded finding equals the re-derived challenge byte for byte and its `runtimeSignature`
 * verifies under the attester session ([F2] through the session's own suite: ed25519 or EIP-191). Never throws.
 */
export function validateDutyFinding(state: ReplayState, event: DutyUnsignedTransition): boolean {
  try {
    const d = event.data, c = d.finding.challenge;
    if (d.version !== DUTY_POLICY_VERSION || d.rulesHash !== DUTY_POLICY_RULES_HASH) return false; // :91
    const expected = deriveDutyFinding(state, { id: event.id, type: event.type, timestamp: event.timestamp, data: dutyFindingRequestOf(d) }); // :92-93
    const session = state.runtimeSessions.get(c.runtimeSessionId); // :94
    return same(c, expected) && session !== undefined && verifySessionSignature(session, hashOf(state, c), d.finding.runtimeSignature); // :95
  } catch {
    return false; // :96
  }
}

// ---------------------------------------------------------------- SPEC §13.4 (sweep row B7): fresh eligibility (duty-disposition.ts:98-119)

/** `duty-disposition.ts:100-104`: the stable identity of a selected grant route (time-dependent request/evaluation fields are not compared). */
const authorityRoute = (proof: AuthorizationProof): Rec => ({
  recognizedRoot: proof.recognizedRoot, permissionPath: proof.permissionPath.map((grant) => grant.authorityId),
  intersections: proof.intersections.map((part) => ({
    requiredAuthorityId: part.requiredAuthorityId, requiredByAuthorityIds: part.requiredByAuthorityIds, recognizedRoot: part.recognizedRoot, path: part.path.map((grant) => grant.authorityId),
  })),
});

/**
 * `duty-disposition.ts:106-119`: the writer's post-signing check, never a replay rule. At `freshTime` (≥ the signed time and
 * ≥ the head's time, a safe integer) over a state at the same head: the signed finding still validates, both the attester
 * and the outer signer are still eligible (requirements and sessions), and the authority routes of both proofs at the
 * original time and at the fresh time are the same. The signed challenges are never altered.
 */
export function validateDutyFreshEligibility(state: ReplayState, event: DutyUnsignedTransition, outerRuntimeSessionId: string, freshTime: number): boolean {
  if (!Number.isSafeInteger(freshTime) || Object.is(freshTime, -0) || freshTime < event.timestamp || freshTime < state.head.canonicalTime || !validateDutyFinding(state, event)) return false; // :107
  const d = event.data, c = d.finding.challenge; // :108
  const att = dutyRequirements(state, d.dutyId, c.attesterId, c.attestationAuthorityId, true, freshTime); // :109
  const outer = dutyRequirements(state, d.dutyId, d.actorId, d.dispositionAuthorityId, false, freshTime); // :110
  if (att === undefined || outer === undefined || dutySessionEligible(state, att, c.runtimeSessionId, freshTime) === undefined || dutySessionEligible(state, outer, outerRuntimeSessionId, freshTime) === undefined) return false; // :111
  const originalAtt = dutyRequirements(state, d.dutyId, c.attesterId, c.attestationAuthorityId, true, event.timestamp); // :112
  const originalOuter = dutyRequirements(state, d.dutyId, d.actorId, d.dispositionAuthorityId, false, event.timestamp); // :113
  if (originalAtt === undefined || originalOuter === undefined) return false; // :114
  const oldAttProof = createAdministrativePolicyProof(state, originalAtt, event.timestamp), oldOuterProof = createAdministrativePolicyProof(state, originalOuter, event.timestamp); // :115
  const freshAttProof = createAdministrativePolicyProof(state, att, freshTime), freshOuterProof = createAdministrativePolicyProof(state, outer, freshTime); // :116
  return oldAttProof !== undefined && oldOuterProof !== undefined && freshAttProof !== undefined && freshOuterProof !== undefined && // :117
    same(authorityRoute(oldAttProof), authorityRoute(freshAttProof)) && same(authorityRoute(oldOuterProof), authorityRoute(freshOuterProof)); // :118
}

// ---------------------------------------------------------------- SPEC §13.3 (sweep row B6): the duty view (duty-policy.ts:209-217, duty-disposition.ts:120-129)

/**
 * `duty-disposition.ts:120-129`: no disposition → OPEN (CONTESTED when a contest exists), `outstanding: true`; else CONTESTED when
 * `contestCount > 0`, NEEDS_REVIEW when the current evidence-index hash differs from the last finding's, else the last
 * disposition; `outstanding = dutyDisposition ≠ COMPLETED_UNDER_POLICY`.
 */
export function dutyDispositionProjection(state: ReplayState, dutyId: string): Pick<DutyPolicyView, "dutyDisposition" | "outstanding" | "lastRecordedDisposition" | "reasons"> {
  const policy = state.attemptDutyPolicies.get(dutyId)!;
  const last = dutyRecordsOf(state, dutyId, "ATTEMPT_DUTY_DISPOSITION_RECORDED").at(-1); // :121
  if (last === undefined) return { dutyDisposition: policy.contestCount ? "CONTESTED" : "OPEN", outstanding: true, lastRecordedDisposition: null, reasons: ["NO_DISPOSITION_RECORDED"] }; // :122
  const event = eventOf(state, last), finding = event.data.finding as DutyFinding, c = finding.challenge, operation = c.operation as DutyDispositionOperation; // :123
  const contested = policy.contestCount > 0; // :124
  const stale = c.evidenceIndexHash !== hashOf(state, deriveDutyEvidenceIndex(state, dutyId)); // :125
  const disposition: DutyDispositionView = contested ? "CONTESTED" : stale ? "NEEDS_REVIEW" : operation.disposition; // :126
  return { // :127-128
    dutyDisposition: disposition, outstanding: disposition !== "COMPLETED_UNDER_POLICY",
    lastRecordedDisposition: {
      eventId: last.eventId, eventPosition: last.position, timestamp: event.timestamp, disposition: operation.disposition, findingHash: last.findingHash,
      evidenceIndexHash: c.evidenceIndexHash, reportDigest: operation.reportDigest,
    },
    reasons: [contested ? "ACCEPTED_CONTEST" : stale ? "RELEVANT_EVIDENCE_CHANGED" : operation.disposition === "ESCALATED" ? "ATTENTION_REQUESTED" : "ALL_LOCAL_CRITERIA_SATISFIED"],
  };
}

/** `duty-policy.ts:209-217` (`inspectPortableDutyPolicy`): the `continuity-attempt-duty-view/1` record of a duty with an active policy, else `null` (SPEC §13.3). */
export function inspectDutyPolicyState(state: ReplayState, dutyId: string): DutyPolicyView | null {
  const policy = state.attemptDutyPolicies?.get(dutyId), duty = state.attemptDuties.get(dutyId); // :211 (a reference-shaped state may lack the map)
  if (policy === undefined || duty === undefined) return null; // :212
  return captureValue({ // :213-216
    version: DUTY_VIEW_VERSION, dutyId, ...dutyDispositionProjection(state, dutyId), externalOutcome: "NOT_PROVEN", policy, observedHead: state.head,
    currentAssigneeId: duty.currentAssigneeId, latestAssignmentEventId: latestAssignmentEventId(duty), evidenceScope: { kind: "COMPLETE_CAPTURED_HISTORY", head: state.head },
  }) as DutyPolicyView;
}

/** The read-only `inspectDutyPolicy({dutyId})` of the owner and runtime handles (SPEC §13.3): the captured input's duty, or `null` without a policy. */
export const inspectDutyPolicyOf = (state: ReplayState, input: Readonly<{ dutyId: string }>): DutyPolicyView | null =>
  inspectDutyPolicyState(state, identifier(record(input, ["dutyId"]).dutyId));
