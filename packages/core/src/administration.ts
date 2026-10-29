/**
 * Administrative authorization production (spec 03 §I, spec 04 §C.3): derive
 * the requirements of an obligation / attempt-duty transition from the exact
 * pre-event state, build the challenge, let the session credential sign it and
 * verify the signed event replays. Nothing here appends.
 */
import { canonicalEncode, captureValue, CanonicalError, compareProtocolStrings, isU53 } from "./canonical.ts";
import { hashCanonical } from "./hash.ts";
import { assertSessionWriteTime, isSessionWriteTimeRefusal } from "./session-write-checks.ts";
import { replay as replayEvents, withProspectiveEvent } from "./replay.ts";
import { isFormat2, validateEvent } from "./events.ts";
import { administrativeTransitionEffect, createAdministrativePolicyProof } from "./authority.ts";
export { administrativeTransitionEffect } from "./authority.ts";
import {
  deriveDutyFinding, dutyPolicyActivationProofMatches, dutyPolicyActivationRequirements, dutyRequirements, validateDutyFinding, DUTY_POLICY_RULES_HASH, DUTY_POLICY_VERSION,
  type DutyFindingChallenge, type DutyFindingRequest, type DutyPolicyActivatedEffect, type DutyTransitionType, type DutyUnsignedTransition,
} from "./duty-policy.ts";
import { ADAPTER_POLICY_E5_HASH, ADAPTER_POLICY_E6_HASH, REMOTE_SERVICE_REPORT_ADAPTER_ID, validateAdapterAcknowledgment, type AdapterIdentity } from "./adapter-editions.ts";
import type { ReplayFn } from "./admission.ts";
import type { AdministrativeRequirements, AuthorizationDomain, AuthorizationProof, CanonicalEvent, ContentHash, HexSignature, HistoryHead, ObligationRecord, ReplayState, U53 } from "./types.ts";

export const ADMINISTRATIVE_AUTHORIZATION_VERSION = "continuity-administrative-authorization/0.2" as const;
export type AdministrativeProducerPhase = "CAPTURE" | "PREPARE" | "SIGN" | "VERIFY";
export type AdministrativeProducerCode =
  | "INVALID_INPUT" | "INPUT_LIMIT" | "UNSUPPORTED_OPERATION" | "UNSUPPORTED_STATUS" | "INVALID_TRANSITION" | "DOMAIN_MISMATCH" | "HEAD_MISMATCH"
  | "SESSION_INVALID" | "POLICY_UNAVAILABLE" | "PREFIX_REJECTED" | "SIGNER_INVALID" | "SIGNER_FAILED" | "INVALID_SIGNATURE" | "SIGNED_EVENT_REJECTED" | "PREPARATION_FAILED";
export class AdministrativeProducerError extends Error {
  readonly phase: AdministrativeProducerPhase;
  readonly code: AdministrativeProducerCode;
  constructor(phase: AdministrativeProducerPhase, code: AdministrativeProducerCode) {
    super(`${phase}:${code}`);
    this.name = "AdministrativeProducerError";
    this.phase = phase;
    this.code = code;
  }
}
export type AdministrativeChallenge = Readonly<{
  /** The genesis `versions.administrativeAuthorizationVersion` (`irontrellis-administrative-authorization/2` in format 2, SPEC §8.4; the legacy literal before). */
  version: string; domain: AuthorizationDomain; request: AdministrativeRequirements["request"]; authoritative: true; consequential: true;
  evaluationTime: U53; policyVersion: string; rootRecognitionPolicy: string; eventHistoryHash: ContentHash; eventHistoryPosition: U53;
  transitionEventId: string; transitionEventType: AdministrativeEventType; transitionEffectHash: ContentHash;
  runtimeSessionId: string; credentialKeyId: string; controlEpoch: U53; roleId: string; roleTenureId: string; authorityProofHash: ContentHash;
}>;
export type AdministrativeAuthorization = Readonly<{ challenge: AdministrativeChallenge; authorityProof: AuthorizationProof; runtimeSignature: HexSignature }>;
export type PreparedAdministrativeEvent = Readonly<{ transition: UnsignedTransition; challenge: AdministrativeChallenge; authorityProof: AuthorizationProof; signingHash: ContentHash }>;
export type ProducedAdministrativeEvent = Readonly<{ event: CanonicalEvent; challenge: AdministrativeChallenge; authorityProof: AuthorizationProof; signingHash: ContentHash; replayHead: HistoryHead }>;

const DATA_FIELDS = Object.freeze({
  OBLIGATION_CREATED: ["record", "actorId"],
  OBLIGATION_PERFORMANCE_ASSIGNED: ["obligationId", "fromAgentId", "toAgentId", "successionRuleId", "actorId"],
  OBLIGATION_STATUS_RECORDED: ["obligationId", "fromStatus", "toStatus", "actorId", "action", "attesterId", "evidenceReference"],
  OUTCOME_OBSERVATION_RECORDED: ["intentId", "sourceAdmissionEventId", "acknowledgment", "actorId"],
  ATTEMPT_DUTY_CREATED: ["record", "actorId"],
  ATTEMPT_DUTY_ASSIGNED: ["dutyId", "fromAgentId", "toAgentId", "actorId"],
  ATTEMPT_DUTY_REVIEW_CLOSED: ["dutyId", "actorId", "observationEventIds", "summaryDigest"],
  // SPEC §13 (E4), `administration/index.ts:54-56`: the ported duty-policy events.
  ATTEMPT_DUTY_POLICY_ACTIVATED: ["actorId", "descriptor", "descriptorHash", "activationAuthorityId"],
  ATTEMPT_DUTY_DISPOSITION_RECORDED: ["version", "rulesHash", "dutyId", "actorId", "dispositionAuthorityId", "finding"],
  ATTEMPT_DUTY_CONTEST_RECORDED: ["version", "rulesHash", "dutyId", "actorId", "dispositionAuthorityId", "finding"],
} as const);
const DUTY_FINDING_TYPES: ReadonlySet<string> = new Set(["ATTEMPT_DUTY_DISPOSITION_RECORDED", "ATTEMPT_DUTY_CONTEST_RECORDED"]);
/** The two-phase finding request (`duty-disposition.ts:24`; `administration/index.ts:379`): the data of an unsigned duty transition before the finding exists. */
const FINDING_REQUEST_FIELDS = ["dutyId", "actorId", "attesterId", "attesterRuntimeSessionId", "attestationAuthorityId", "dispositionAuthorityId", "operation"] as const;
export type AdministrativeEventType = keyof typeof DATA_FIELDS;
export const ADMINISTRATIVE_EVENT_TYPES = Object.freeze(Object.keys(DATA_FIELDS) as AdministrativeEventType[]);
export type UnsignedTransition = Readonly<{ id: string; type: AdministrativeEventType; timestamp: U53; data: Readonly<Record<string, unknown>> }>;
type Captured = Readonly<{ events?: readonly CanonicalEvent[]; expectedDomain: unknown; expectedHistoryHead: unknown; transition: UnsignedTransition; runtimeSessionId: string }>;
const INPUT_KEYS = ["expectedDomain", "expectedHistoryHead", "transition", "runtimeSessionId"];
type Rec = Record<string, unknown>;
// The reference capped the prefix at 128 events; replay never did, so only the byte bound remains (histories are bounded by the store).
const INPUT_BYTES = 1_048_576;
const record = (v: unknown): v is Rec => v !== null && typeof v === "object" && !Array.isArray(v);
function fail(phase: AdministrativeProducerPhase, code: AdministrativeProducerCode): never { throw new AdministrativeProducerError(phase, code); }
const exactKeys = (v: unknown, keys: readonly string[], phase: AdministrativeProducerPhase, code: AdministrativeProducerCode): Rec => {
  if (!record(v) || Object.keys(v).length !== keys.length || keys.some((k) => !Object.hasOwn(v, k))) fail(phase, code);
  return v as Rec;
};
/** Original `undefined`-valued keys must not silently vanish in capture: the closed shapes below would then lie. */
const hasUndefinedField = (v: unknown): boolean =>
  Array.isArray(v) ? v.some(hasUndefinedField) : record(v) ? Object.keys(v).some((k) => v[k] === undefined || hasUndefinedField(v[k])) : false;

/** `withEvents` selects the portable shape; the state entry points take the same input without `events`. */
function captureInput(input: unknown, withEvents: boolean): Captured {
  if (hasUndefinedField(input)) fail("CAPTURE", "INVALID_INPUT");
  let value: unknown;
  try { value = captureValue(input, { maxTotalBytes: INPUT_BYTES }); } catch (error) { return fail("CAPTURE", error instanceof CanonicalError && error.limit ? "INPUT_LIMIT" : "INVALID_INPUT"); }
  const body = exactKeys(value, withEvents ? ["events", ...INPUT_KEYS] : INPUT_KEYS, "CAPTURE", "INVALID_INPUT");
  if (withEvents && !Array.isArray(body.events)) fail("CAPTURE", "INVALID_INPUT");
  if (typeof body.runtimeSessionId !== "string" || body.runtimeSessionId.length === 0) fail("CAPTURE", "INVALID_INPUT");
  const transition = exactKeys(body.transition, ["id", "type", "timestamp", "data"], "PREPARE", "INVALID_TRANSITION");
  if (typeof transition.type !== "string" || !Object.hasOwn(DATA_FIELDS, transition.type)) fail("PREPARE", "UNSUPPORTED_OPERATION");
  const data = exactKeys(transition.data, DATA_FIELDS[transition.type as AdministrativeEventType], "PREPARE", "INVALID_TRANSITION");
  if (typeof transition.id !== "string" || transition.id.length === 0 || !isU53(transition.timestamp) || typeof data.actorId !== "string") fail("PREPARE", "INVALID_TRANSITION");
  if (transition.type === "OBLIGATION_CREATED" || transition.type === "ATTEMPT_DUTY_CREATED") {
    if (!record(data.record)) fail("PREPARE", "INVALID_TRANSITION");
    if (data.record.status !== "OPEN") fail("PREPARE", "UNSUPPORTED_STATUS");
  } else if (transition.type === "OBLIGATION_STATUS_RECORDED" && (data.fromStatus !== "OPEN" || data.toStatus !== "OUTCOME_UNKNOWN" || data.action !== "record-collection-disposition")) {
    fail("PREPARE", "UNSUPPORTED_STATUS");
  }
  return body as unknown as Captured;
}

/** Spec 03 §I.2: what an administrative transition asks the actor's authority for; throws the producer's PREPARE errors. */
export function deriveAdministrativeRequirements(state: ReplayState, transition: UnsignedTransition): AdministrativeRequirements {
  const data = transition.data, actorId = data.actorId as string, claimedAt = transition.timestamp;
  // SPEC §13 (E4), `administration/index.ts:134-142`: the outer signer of a disposition/contest, and the activation's exact-grant requirements.
  if (DUTY_FINDING_TYPES.has(transition.type)) {
    const requirements = typeof data.dutyId === "string" && typeof data.dispositionAuthorityId === "string" ? dutyRequirements(state, data.dutyId, actorId, data.dispositionAuthorityId, false, claimedAt) : undefined;
    if (requirements === undefined) fail("PREPARE", "INVALID_TRANSITION");
    return requirements;
  }
  if (transition.type === "ATTEMPT_DUTY_POLICY_ACTIVATED") {
    if (!record(data.descriptor) || typeof data.descriptorHash !== "string" || typeof data.activationAuthorityId !== "string") fail("PREPARE", "INVALID_TRANSITION");
    const requirements = dutyPolicyActivationRequirements(state, data as unknown as DutyPolicyActivatedEffect, claimedAt);
    if (requirements === undefined) fail("PREPARE", "INVALID_TRANSITION");
    return requirements;
  }
  const attempt = transition.type === "OUTCOME_OBSERVATION_RECORDED" || transition.type === "ATTEMPT_DUTY_CREATED" || transition.type === "ATTEMPT_DUTY_ASSIGNED" || transition.type === "ATTEMPT_DUTY_REVIEW_CLOSED";
  if (attempt) {
    const policyHash = state.genesis.adapterPolicyHash;
    if (policyHash !== ADAPTER_POLICY_E5_HASH && policyHash !== ADAPTER_POLICY_E6_HASH) fail("PREPARE", "POLICY_UNAVAILABLE");
    if (transition.type === "ATTEMPT_DUTY_REVIEW_CLOSED" && policyHash !== ADAPTER_POLICY_E6_HASH) fail("PREPARE", "POLICY_UNAVAILABLE");
    let intentId: string, action: string;
    if (transition.type === "OUTCOME_OBSERVATION_RECORDED") {
      if (typeof data.intentId !== "string") fail("PREPARE", "INVALID_TRANSITION");
      intentId = data.intentId; action = "OBSERVE_OUTCOME";
    } else if (transition.type === "ATTEMPT_DUTY_CREATED") {
      if (!record(data.record) || typeof data.record.sourceIntentId !== "string") fail("PREPARE", "INVALID_TRANSITION");
      intentId = data.record.sourceIntentId; action = "CREATE_ATTEMPT_DUTY";
    } else {
      const duty = typeof data.dutyId === "string" ? state.attemptDuties.get(data.dutyId) : undefined;
      if (duty === undefined) fail("PREPARE", "INVALID_TRANSITION");
      intentId = duty.record.sourceIntentId;
      if (transition.type === "ATTEMPT_DUTY_REVIEW_CLOSED") {
        const ids = (state.outcomeObservations.get(intentId) ?? []).map((o) => o.eventId).sort(compareProtocolStrings);
        if (duty.currentAssigneeId !== actorId || canonicalEncode(data.observationEventIds) !== canonicalEncode(ids)) fail("PREPARE", "INVALID_TRANSITION");
        action = "CLOSE_ATTEMPT_DUTY";
      } else {
        if (data.fromAgentId !== duty.currentAssigneeId || data.toAgentId !== actorId) fail("PREPARE", "INVALID_TRANSITION");
        action = "ASSIGN_ATTEMPT_DUTY";
      }
    }
    const source = state.intentDeclarations.get(intentId), admission = state.intentAdmissions.get(intentId);
    const identity = admission?.adapterIdentity as AdapterIdentity | undefined;
    if (source === undefined || admission === undefined || identity?.adapterProfile.profileId !== REMOTE_SERVICE_REPORT_ADAPTER_ID) fail("PREPARE", "INVALID_TRANSITION");
    const role = state.roles.get(source.data.roleId);
    if (role === undefined || role.currentTenureId === undefined) fail("PREPARE", "INVALID_TRANSITION");
    if (transition.type === "OUTCOME_OBSERVATION_RECORDED" && (data.sourceAdmissionEventId !== admission.admissionEventId || !validateAdapterAcknowledgment(data.acknowledgment, identity))) fail("PREPARE", "INVALID_TRANSITION");
    if (transition.type === "ATTEMPT_DUTY_CREATED") {
      const creation = data.record as Rec;
      if (creation.sourceAdmissionEventId !== admission.admissionEventId || creation.durableRoleId !== role.id || creation.creationRoleTenureId !== role.currentTenureId || creation.performanceAssigneeId !== actorId) fail("PREPARE", "INVALID_TRANSITION");
    }
    return Object.freeze({
      request: Object.freeze({ actorId, action, resource: intentId, claimedAt, ...(Object.hasOwn(source.data, "termsCommitment") ? { termsCommitment: source.data.termsCommitment as ContentHash } : {}) }),
      requiredPrincipalId: role.principalId, requiredAuthorityIds: [], roleId: role.id, roleTenureId: role.currentTenureId,
    });
  }
  if (transition.type === "OBLIGATION_CREATED") {
    const creation = data.record as ObligationRecord, source = state.intentDeclarations.get(creation.sourceIntentId), role = state.roles.get(creation.durableRoleId);
    if (source === undefined || role === undefined) fail("PREPARE", "INVALID_TRANSITION");
    return Object.freeze({
      request: Object.freeze({ actorId, action: "OBLIGATE", resource: source.data.resource, claimedAt, termsCommitment: creation.termsCommitment, ...(Object.hasOwn(creation, "counterpartyId") ? { counterpartyId: creation.counterpartyId as string } : {}) }),
      requiredPrincipalId: role.principalId, requiredAuthorityIds: [], roleId: role.id, roleTenureId: creation.creationRoleTenureId,
    });
  }
  const obligation = typeof data.obligationId === "string" ? state.obligations.get(data.obligationId) : undefined;
  if (obligation === undefined) fail("PREPARE", "INVALID_TRANSITION");
  const role = state.roles.get(obligation.record.durableRoleId);
  if (role === undefined || role.currentTenureId === undefined) fail("PREPARE", "INVALID_TRANSITION");
  let requiredAuthorityIds: readonly string[] = [], action = "ASSIGN_PERFORMANCE";
  if (transition.type === "OBLIGATION_STATUS_RECORDED") {
    action = "record-collection-disposition";
    const policy = obligation.record.transitionPolicies.find((p) => p.fromStatus === "OPEN" && p.toStatus === "OUTCOME_UNKNOWN" && p.action === action);
    if (policy === undefined || obligation.status !== "OPEN") fail("PREPARE", "POLICY_UNAVAILABLE");
    requiredAuthorityIds = policy.requiredAuthorityIds;
  }
  return Object.freeze({ request: Object.freeze({ actorId, action, resource: data.obligationId as string, claimedAt }), requiredPrincipalId: role.principalId, requiredAuthorityIds, roleId: role.id, roleTenureId: role.currentTenureId });
}

const ZERO_HASH = `0x${"0".repeat(64)}` as ContentHash;
/** The portable forms' single replay of `input.events` (PREPARE:PREFIX_REJECTED when it is not accepted). */
function replayPrefix(input: Captured, replayFn: ReplayFn): ReplayState {
  try {
    const replayed = replayFn(input.events as readonly CanonicalEvent[]);
    if (replayed.status !== "ACCEPTED") fail("PREPARE", "PREFIX_REJECTED");
    return replayed.state;
  } catch (error) {
    if (error instanceof AdministrativeProducerError) throw error;
    return fail("PREPARE", "PREPARATION_FAILED");
  }
}
/** `findingShapeOnly` (`administration/index.ts:239-241`): the two-phase producer prepares the outer shape around a placeholder finding; otherwise a recorded finding must validate. */
function prepareOnState(state: ReplayState, input: Captured, findingShapeOnly = false): PreparedAdministrativeEvent {
  try {
    const transition = input.transition;
    if (canonicalEncode(input.expectedDomain) !== canonicalEncode(state.genesis.domain)) fail("PREPARE", "DOMAIN_MISMATCH");
    if (canonicalEncode(input.expectedHistoryHead) !== canonicalEncode(state.head)) fail("PREPARE", "HEAD_MISMATCH");
    if (transition.timestamp < state.head.canonicalTime) fail("PREPARE", "INVALID_TRANSITION");
    if (!findingShapeOnly && DUTY_FINDING_TYPES.has(transition.type) && !validateDutyFinding(state, transition as unknown as DutyUnsignedTransition)) fail("PREPARE", "INVALID_TRANSITION"); // :240-241
    const requirements = deriveAdministrativeRequirements(state, transition);
    const session = state.runtimeSessions.get(input.runtimeSessionId), actor = state.agents.get(requirements.request.actorId);
    const role = state.roles.get(requirements.roleId), tenure = state.tenures.get(requirements.roleTenureId);
    if (session === undefined || actor === undefined || actor.terminated || session.agentId !== actor.id || session.controlEpoch !== actor.currentControlEpoch ||
        // A-149.0 / A-149.1 (a) (JOB75-04): in format 2 a session without an expiry is not live after a migrated prefix.
        (session.expiresAt === undefined ? isFormat2(state.format) : transition.timestamp >= session.expiresAt) || role === undefined || role.currentTenureId !== requirements.roleTenureId ||
        tenure === undefined || tenure.closed || tenure.roleId !== role.id || tenure.agentId !== actor.id) fail("PREPARE", "SESSION_INVALID");
    // A-109.1 / A-179.4 (JOB75-05): the ▲ pre-checks of rules T1 and T3, before anything is signed (duty and coordinator writers
    // append without appendEvent).
    assertSessionWriteTime(state, transition, state.head.position + 1);
    const authorityProof = createAdministrativePolicyProof(state, requirements, transition.timestamp);
    // `administration/index.ts:252-255`: an activation's proof must select the activation grant itself (`duty-policy.ts:204-207`).
    if (authorityProof === undefined || (transition.type === "ATTEMPT_DUTY_POLICY_ACTIVATED" && !dutyPolicyActivationProofMatches(authorityProof, transition.data.activationAuthorityId as string))) fail("PREPARE", "POLICY_UNAVAILABLE");
    const base = {
      // The literal the genesis declares (format 2: `/2`, SPEC §8.4); legacy and format-1 histories declare the Continuity literal.
      version: state.genesis.versions.administrativeAuthorizationVersion ?? ADMINISTRATIVE_AUTHORIZATION_VERSION, domain: state.genesis.domain, request: requirements.request, authoritative: true as const, consequential: true as const,
      evaluationTime: transition.timestamp, policyVersion: state.genesis.policyVersion, rootRecognitionPolicy: state.genesis.rootRecognitionPolicy,
      eventHistoryHash: state.head.hash, eventHistoryPosition: state.head.position, transitionEventId: transition.id, transitionEventType: transition.type,
      transitionEffectHash: ZERO_HASH, runtimeSessionId: session.id, credentialKeyId: session.credentialKeyId, controlEpoch: session.controlEpoch,
      roleId: requirements.roleId, roleTenureId: requirements.roleTenureId, authorityProofHash: ZERO_HASH,
    };
    // A private r=s=1/v=27 (or all-zero Ed25519) stand-in: closed-shape validation only, never authentication.
    const placeholder = session.credentialScheme === "ed25519" ? `0x${"0".repeat(128)}` : `0x${"0".repeat(63)}1${"0".repeat(63)}11b`;
    const shaped = validateEvent({ ...transition, data: { ...transition.data, administrativeAuthorization: { challenge: base, authorityProof, runtimeSignature: placeholder } } }, state.format, state.events.length);
    if (!shaped.ok) fail("PREPARE", "INVALID_TRANSITION");
    const challenge = captureValue({ ...base, transitionEffectHash: hashCanonical(administrativeTransitionEffect(shaped.event), state.hashAlgorithm), authorityProofHash: hashCanonical(authorityProof, state.hashAlgorithm) }) as AdministrativeChallenge;
    return Object.freeze({ transition, challenge, authorityProof, signingHash: hashCanonical(challenge, state.hashAlgorithm) });
  } catch (error) {
    if (error instanceof AdministrativeProducerError) throw error;
    if (isSessionWriteTimeRefusal(error)) throw error; // A-179.4 / A-172.2: the T1 and T3 refusals keep their API form
    return fail("PREPARE", "PREPARATION_FAILED");
  }
}

function attachOnState(state: ReplayState, prepared: PreparedAdministrativeEvent, runtimeSignature: unknown): ProducedAdministrativeEvent {
  if (typeof runtimeSignature !== "string" || !/^0x([0-9a-fA-F]{128}|[0-9a-fA-F]{130})$/.test(runtimeSignature)) fail("VERIFY", "INVALID_SIGNATURE");
  try {
    const event = captureValue({ ...prepared.transition, data: { ...prepared.transition.data, administrativeAuthorization: { challenge: prepared.challenge, authorityProof: prepared.authorityProof, runtimeSignature } } }) as CanonicalEvent;
    // The signed event must be accepted as the next event of the prefix: applied to a private fork, never a replay.
    const prospective = withProspectiveEvent(state, event);
    if (!prospective.ok) fail("VERIFY", "SIGNED_EVENT_REJECTED");
    return Object.freeze({ event, challenge: prepared.challenge, authorityProof: prepared.authorityProof, signingHash: prepared.signingHash, replayHead: prospective.head });
  } catch (error) {
    if (error instanceof AdministrativeProducerError) throw error;
    return fail("VERIFY", "SIGNED_EVENT_REJECTED");
  }
}

/** The callback receives exactly one hash; no retry, alternate session or signing implementation. */
async function signPrepared(prepared: PreparedAdministrativeEvent, options: unknown): Promise<unknown> {
  let callback: (hash: ContentHash) => unknown;
  try {
    if (!record(options) || ![Object.prototype, null].includes(Object.getPrototypeOf(options))) fail("SIGN", "SIGNER_INVALID");
    const keys = Reflect.ownKeys(options), descriptor = Reflect.getOwnPropertyDescriptor(options, "signHash");
    if (keys.length !== 1 || keys[0] !== "signHash" || descriptor === undefined || !Object.hasOwn(descriptor, "value") || typeof descriptor.value !== "function") fail("SIGN", "SIGNER_INVALID");
    callback = descriptor.value as (hash: ContentHash) => unknown;
  } catch { return fail("SIGN", "SIGNER_INVALID"); }
  try { return await callback(prepared.signingHash); } catch { return fail("SIGN", "SIGNER_FAILED"); }
}

/** Unsigned historical-prefix preparation; neither permission nor an append capability. Replays `input.events` once. */
export function prepareAdministrativeEvent(input: unknown, replayFn: ReplayFn = replayEvents): PreparedAdministrativeEvent {
  const captured = captureInput(input, true);
  return prepareOnState(replayPrefix(captured, replayFn), captured);
}
/** Re-derives the preparation rather than trusting a caller-supplied one; appends nothing. Replays `input.events` once. */
export function attachAdministrativeSignature(input: unknown, runtimeSignature: unknown, replayFn: ReplayFn = replayEvents): ProducedAdministrativeEvent {
  const captured = captureInput(input, true), state = replayPrefix(captured, replayFn);
  return attachOnState(state, prepareOnState(state, captured), runtimeSignature);
}
/** The callback receives exactly one hash; no retry, alternate session or signing implementation. Replays `input.events` once. */
export async function produceAdministrativeEvent(input: unknown, options: unknown, replayFn: ReplayFn = replayEvents): Promise<ProducedAdministrativeEvent> {
  const captured = captureInput(input, true), state = replayPrefix(captured, replayFn), prepared = prepareOnState(state, captured);
  return attachOnState(state, prepared, await signPrepared(prepared, options));
}

/**
 * The state entry points: the same operations over an already-replayed,
 * accepted `state` (the prefix the transition extends), with `input` =
 * `{ expectedDomain, expectedHistoryHead, transition, runtimeSessionId }` (the
 * portable input without `events`). They never replay: preparation reads
 * `state`, and the signed event is checked by applying it to a private fork.
 */
export function prepareAdministrativeEventState(state: ReplayState, input: unknown): PreparedAdministrativeEvent {
  return prepareOnState(state, captureInput(input, false));
}
export function attachAdministrativeSignatureState(state: ReplayState, input: unknown, runtimeSignature: unknown): ProducedAdministrativeEvent {
  return attachOnState(state, prepareOnState(state, captureInput(input, false)), runtimeSignature);
}
/** `state` must not change while the signer runs: a head that moved meanwhile fails with `VERIFY:HEAD_MISMATCH`. */
export async function produceAdministrativeEventState(state: ReplayState, input: unknown, options: unknown): Promise<ProducedAdministrativeEvent> {
  const prepared = prepareOnState(state, captureInput(input, false)), head = state.head;
  const signature = await signPrepared(prepared, options);
  if (state.head.hash !== head.hash || state.head.position !== head.position) fail("VERIFY", "HEAD_MISMATCH");
  return attachOnState(state, prepared, signature);
}

// ---------------------------------------------------------------- SPEC §13.4 (sweep row B8): the two-phase finding producer (`administration/index.ts:370-413`)

export type DutyFindingInput = Readonly<{ expectedDomain: unknown; expectedHistoryHead: unknown; runtimeSessionId: string; transition: Readonly<{ id: string; type: DutyTransitionType; timestamp: U53; data: DutyFindingRequest }> }>;
export type PreparedDutyFinding = Readonly<{ challenge: DutyFindingChallenge; signingHash: ContentHash }>;
/** The administrative input of the outer signature: the transition with the signed finding in its data (`administration/index.ts:388-394`). */
export type DutyFindingAdministrativeInput = Readonly<{ expectedDomain: unknown; expectedHistoryHead: unknown; runtimeSessionId: string; transition: DutyUnsignedTransition }>;

/** `administration/index.ts:370-386` (`captureDutyFindingInput`) on an already-replayed state: the request's closed shape, then the finding challenge against `state`. */
function captureDutyFindingInput(state: ReplayState, input: unknown): Readonly<{ body: Captured; transition: DutyFindingInput["transition"]; challenge: DutyFindingChallenge }> {
  if (hasUndefinedField(input)) fail("CAPTURE", "INVALID_INPUT");
  let value: unknown;
  try { value = captureValue(input, { maxTotalBytes: 16_384 }); } catch (error) { return fail("CAPTURE", error instanceof CanonicalError && error.limit ? "INPUT_LIMIT" : "INVALID_INPUT"); }
  const body = exactKeys(value, INPUT_KEYS, "CAPTURE", "INVALID_INPUT");
  if (typeof body.runtimeSessionId !== "string" || body.runtimeSessionId.length === 0) fail("CAPTURE", "INVALID_INPUT");
  const t = exactKeys(body.transition, ["id", "type", "timestamp", "data"], "PREPARE", "INVALID_TRANSITION");
  if (t.type !== "ATTEMPT_DUTY_DISPOSITION_RECORDED" && t.type !== "ATTEMPT_DUTY_CONTEST_RECORDED") fail("PREPARE", "UNSUPPORTED_OPERATION"); // :378
  exactKeys(t.data, FINDING_REQUEST_FIELDS, "PREPARE", "INVALID_TRANSITION"); // :379
  if (canonicalEncode(body.expectedDomain) !== canonicalEncode(state.genesis.domain)) fail("PREPARE", "DOMAIN_MISMATCH"); // :381
  if (canonicalEncode(body.expectedHistoryHead) !== canonicalEncode(state.head)) fail("PREPARE", "HEAD_MISMATCH"); // :382
  if (typeof t.id !== "string" || !isU53(t.timestamp)) fail("PREPARE", "INVALID_TRANSITION"); // :383
  const transition = t as unknown as DutyFindingInput["transition"];
  let challenge: DutyFindingChallenge;
  try { challenge = deriveDutyFinding(state, transition); } catch { return fail("PREPARE", "INVALID_TRANSITION"); } // :385
  return Object.freeze({ body: body as unknown as Captured, transition, challenge });
}
/** `administration/index.ts:388-395`: the outer administrative input around a finding carrying `signature`. */
function dutyFindingAdministrativeInput(captured: ReturnType<typeof captureDutyFindingInput>, signature: string): DutyFindingAdministrativeInput {
  const { body, transition, challenge } = captured;
  return captureValue({
    expectedDomain: body.expectedDomain, expectedHistoryHead: body.expectedHistoryHead, runtimeSessionId: body.runtimeSessionId,
    transition: { id: transition.id, type: transition.type, timestamp: transition.timestamp, data: {
      version: DUTY_POLICY_VERSION, rulesHash: DUTY_POLICY_RULES_HASH, dutyId: transition.data.dutyId, actorId: transition.data.actorId,
      dispositionAuthorityId: transition.data.dispositionAuthorityId, finding: { challenge, runtimeSignature: signature },
    } },
  }) as DutyFindingAdministrativeInput;
}
/** A private all-zero stand-in of the attester session's signature size: closed-shape validation only, never authentication. */
const placeholderSignatureFor = (state: ReplayState, sessionId: string): string =>
  state.runtimeSessions.get(sessionId)?.credentialScheme === "ed25519" ? `0x${"0".repeat(128)}` : `0x${"0".repeat(63)}1${"0".repeat(63)}11b`;

/**
 * SPEC §13.4, `administration/index.ts:397-405` (`prepareHistoryDutyFinding`): preflights the complete dual-signature event —
 * the finding challenge against `state`, both authorities, the outer proof and the closed shape of the finished event with
 * a placeholder finding signature — before either signer is asked. Returns the challenge and its signing hash.
 */
export function prepareDutyFinding(state: ReplayState, input: unknown): PreparedDutyFinding {
  const captured = captureDutyFindingInput(state, input);
  const administrative = dutyFindingAdministrativeInput(captured, placeholderSignatureFor(state, captured.challenge.runtimeSessionId));
  prepareOnState(state, captureInput(administrative, false), true); // :401-402
  return Object.freeze({ challenge: captured.challenge, signingHash: hashCanonical(captured.challenge, state.hashAlgorithm) });
}
/**
 * SPEC §13.4, `administration/index.ts:407-413` (`attachHistoryDutyFinding`): re-derives the finding, authenticates
 * `runtimeSignature` under the attester session (`VERIFY:INVALID_SIGNATURE` otherwise) and prepares the outer event, then
 * returns the outer administrative input for `prepareAdministrativeEventState` / `attachAdministrativeSignatureState`.
 */
export function attachDutyFinding(state: ReplayState, input: unknown, runtimeSignature: unknown): DutyFindingAdministrativeInput {
  const captured = captureDutyFindingInput(state, input);
  if (typeof runtimeSignature !== "string" || !/^0x([0-9a-fA-F]{128}|[0-9a-fA-F]{130})$/.test(runtimeSignature)) fail("VERIFY", "INVALID_SIGNATURE"); // :409 [F2: 64 or 65 bytes]
  const administrative = dutyFindingAdministrativeInput(captured, runtimeSignature);
  if (!validateDutyFinding(state, administrative.transition)) fail("VERIFY", "INVALID_SIGNATURE"); // :411
  prepareOnState(state, captureInput(administrative, false)); // :412
  return administrative;
}
