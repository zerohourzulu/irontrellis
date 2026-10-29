import { derivePortableDutyFinding, validatePortableDutyFinding, portableDutyRequirements,
 type PortableDutyFindingRequest, type DutyUnsignedTransition, type PortableDutyTransitionType } from "../core/duty-disposition.ts";
import { DUTY_POLICY_VERSION, DUTY_POLICY_RULES_HASH } from "../core/duty-policy.ts";
import { portableDutyPolicyActivationRequirements, portableDutyPolicyActivationProofMatches,
  type PortableDutyPolicyActivatedData } from "../core/duty-policy.ts";
/** Repository-local preparation only; never a durable append or authority capability. */
import {
  captureBoundedCanonicalValue, captureBoundedCanonicalReplayBodyIncrementally,
  canonicalEncode, compareProtocolStrings, hashCanonical, immutableProtocolValue, isCanonicalCaptureLimitError,
  type BoundedCanonicalCapture, type ContentHash,
} from "../core/canonical.ts";
import { validateCanonicalEventShape, type AcceptedCanonicalEventShape as Event } from "../core/event-schema.ts";
import { createPortableReplayKernel, replayPortable, PORTABLE_REPLAY_VERSION, type PortableReplayState } from "../core/portable-replay.ts";
import { createPortableAdministrativePolicyProof, type PortableAdministrativeRequirements } from "../core/portable-authority-engine.ts";
import { portableAdministrativeTransitionEffect, type PortableObligationRecord } from "../core/portable-administration-codec.ts";
import {
  PORTABLE_ADAPTER_POLICY_E5_HASH, PORTABLE_ADAPTER_POLICY_E6_HASH, REMOTE_SERVICE_REPORT_ADAPTER_ID,
  validatePortableAdapterAcknowledgment,
} from "../core/portable-adapter-engine.ts";

export type AdministrativeProducerPhase = "CAPTURE" | "PREPARE" | "SIGN" | "VERIFY";
export type AdministrativeProducerCode =
  | "INVALID_INPUT" | "INPUT_LIMIT" | "UNSUPPORTED_OPERATION" | "UNSUPPORTED_STATUS"
  | "INVALID_TRANSITION" | "DOMAIN_MISMATCH" | "HEAD_MISMATCH" | "SESSION_INVALID"
  | "POLICY_UNAVAILABLE" | "PREFIX_REJECTED" | "SIGNER_INVALID" | "SIGNER_FAILED"
  | "INVALID_SIGNATURE" | "SIGNED_EVENT_REJECTED" | "PREPARATION_FAILED";

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

import { CONTINUATION_PROFILE, verifiedHistorySnapshot, captureHistoryAncillary, historyDataFields,
  checkContinuationAppendShape, appendContinuationEvent } from "../history/index.ts";

const INPUT_BYTES = 1_048_576;
const PREFIX_EVENTS = 128;
const INPUT_FIELDS = ["events", "expectedDomain", "expectedHistoryHead", "transition", "runtimeSessionId"] as const;
const TRANSITION_FIELDS = ["id", "type", "timestamp", "data"] as const;
const DATA_FIELDS = {
  OBLIGATION_CREATED: ["record", "actorId"],
  OBLIGATION_PERFORMANCE_ASSIGNED: ["obligationId", "fromAgentId", "toAgentId", "successionRuleId", "actorId"],
  OBLIGATION_STATUS_RECORDED: ["obligationId", "fromStatus", "toStatus", "actorId", "action", "attesterId", "evidenceReference"],
  OUTCOME_OBSERVATION_RECORDED: ["intentId", "sourceAdmissionEventId", "acknowledgment", "actorId"],
  ATTEMPT_DUTY_CREATED: ["record", "actorId"],
  ATTEMPT_DUTY_ASSIGNED: ["dutyId", "fromAgentId", "toAgentId", "actorId"],
  ATTEMPT_DUTY_REVIEW_CLOSED: ["dutyId", "actorId", "observationEventIds", "summaryDigest"],
  ATTEMPT_DUTY_DISPOSITION_RECORDED: ["version","rulesHash","dutyId","actorId","dispositionAuthorityId","finding"],
  ATTEMPT_DUTY_CONTEST_RECORDED: ["version","rulesHash","dutyId","actorId","dispositionAuthorityId","finding"],
  ATTEMPT_DUTY_POLICY_ACTIVATED: ["actorId", "descriptor", "descriptorHash", "activationAuthorityId"],
} as const;
type TransitionKind = keyof typeof DATA_FIELDS;
type UnsignedTransition = Readonly<{ id: string; type: TransitionKind; timestamp: number; data: Readonly<Record<string, unknown>> }>;
type CapturedInput = Readonly<{
  events: readonly Event[];
  expectedDomain: unknown;
  expectedHistoryHead: unknown;
  transition: UnsignedTransition;
  runtimeSessionId: string;
}>;

function fail(phase: AdministrativeProducerPhase, code: AdministrativeProducerCode): never {
  throw new AdministrativeProducerError(phase, code);
}
const record = (value: unknown): value is Readonly<Record<string, unknown>> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

// Strict canonical capture can omit undefined-valued record properties. Its
// retained key metadata lets this closed facade reject that normalization,
// without touching any original accessor or object a second time.
const requireOriginalPresence = (capture: BoundedCanonicalCapture<unknown>, value: unknown): void => {
  if (Array.isArray(value)) {
    for (const member of value) requireOriginalPresence(capture, member);
  } else if (record(value)) {
    const originalKeys = capture.capturedRecordKeys(value);
    if (!originalKeys || originalKeys.length !== Object.keys(value).length ||
        originalKeys.some(key => !Object.hasOwn(value, key))) fail("CAPTURE", "INVALID_INPUT");
    for (const key of originalKeys) requireOriginalPresence(capture, value[key]);
  }
};
const exactKeys = (value: unknown, keys: readonly string[], phase: AdministrativeProducerPhase, code: AdministrativeProducerCode): void => {
  if (!record(value) || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) fail(phase, code);
};

function captureInput(input: unknown, historyProfile = false): CapturedInput {
  const inputBytes = historyProfile ? CONTINUATION_PROFILE.maxCanonicalHistoryBytes + CONTINUATION_PROFILE.maxAncillaryBytes + 16384 : INPUT_BYTES;
  let capture: BoundedCanonicalCapture<unknown>;
  try { capture = captureBoundedCanonicalValue(input, { maxCanonicalBytes: inputBytes }); }
  catch (error) { return fail("CAPTURE", isCanonicalCaptureLimitError(error, "$", inputBytes) ? "INPUT_LIMIT" : "INVALID_INPUT"); }
  requireOriginalPresence(capture, capture.value);
  exactKeys(capture.value, INPUT_FIELDS, "CAPTURE", "INVALID_INPUT");
  const body = capture.value as Readonly<Record<string, unknown>>;
  if (!Array.isArray(body.events)) fail("CAPTURE", "INVALID_INPUT");
  if (body.events.length > (historyProfile ? CONTINUATION_PROFILE.maxEvents : PREFIX_EVENTS)) fail("CAPTURE", "INPUT_LIMIT");
  if (typeof body.runtimeSessionId !== "string" || body.runtimeSessionId.length === 0) fail("CAPTURE", "INVALID_INPUT");
  exactKeys(body.transition, TRANSITION_FIELDS, "PREPARE", "INVALID_TRANSITION");
  const transition = body.transition as Readonly<Record<string, unknown>>;
  if (typeof transition.type !== "string" || !Object.hasOwn(DATA_FIELDS, transition.type)) fail("PREPARE", "UNSUPPORTED_OPERATION");
  if (!historyProfile && ["ATTEMPT_DUTY_POLICY_ACTIVATED","ATTEMPT_DUTY_DISPOSITION_RECORDED","ATTEMPT_DUTY_CONTEST_RECORDED"].includes(transition.type)) fail("PREPARE", "UNSUPPORTED_OPERATION");
  exactKeys(transition.data, DATA_FIELDS[transition.type as TransitionKind], "PREPARE", "INVALID_TRANSITION");
  if (typeof transition.id !== "string" || transition.id.length === 0 ||
      typeof transition.timestamp !== "number" || !Number.isSafeInteger(transition.timestamp) ||
      transition.timestamp < 0 || Object.is(transition.timestamp, -0)) fail("PREPARE", "INVALID_TRANSITION");
  const data = transition.data as Readonly<Record<string, unknown>>;
  if (typeof data.actorId !== "string") fail("PREPARE", "INVALID_TRANSITION");
  if (transition.type === "OBLIGATION_CREATED" || transition.type === "ATTEMPT_DUTY_CREATED") {
    if (!record(data.record)) fail("PREPARE", "INVALID_TRANSITION");
    if (data.record.status !== "OPEN") fail("PREPARE", "UNSUPPORTED_STATUS");
  } else if (transition.type === "OBLIGATION_STATUS_RECORDED" &&
      (data.fromStatus !== "OPEN" || data.toStatus !== "OUTCOME_UNKNOWN" || data.action !== "record-collection-disposition")) {
    fail("PREPARE", "UNSUPPORTED_STATUS");
  }
  return capture.value as CapturedInput;
}

function replayPrefix(events: readonly Event[]): PortableReplayState {
  const kernel = createPortableReplayKernel();
  const capture = captureBoundedCanonicalReplayBodyIncrementally(events,
    Object.freeze({ operationVersion: PORTABLE_REPLAY_VERSION, events }), kernel.visit);
  if (capture.status !== "CAPTURED") fail("PREPARE", "PREFIX_REJECTED");
  const result = kernel.finish();
  if (result.status !== "ACCEPTED") fail("PREPARE", "PREFIX_REJECTED");
  return result.state;
}

function deriveRequirements(state: PortableReplayState, transition: UnsignedTransition): PortableAdministrativeRequirements {
  const data = transition.data, actorId = data.actorId as string;
  if (transition.type === "ATTEMPT_DUTY_DISPOSITION_RECORDED" || transition.type === "ATTEMPT_DUTY_CONTEST_RECORDED") {
    const requirements=portableDutyRequirements(state,data.dutyId as string,actorId,data.dispositionAuthorityId as string,false,transition.timestamp);
    if(!requirements)fail("PREPARE","INVALID_TRANSITION");return requirements;
  }
  if (transition.type === "ATTEMPT_DUTY_POLICY_ACTIVATED") {
    const requirements = portableDutyPolicyActivationRequirements(state, data as unknown as PortableDutyPolicyActivatedData, transition.timestamp);
    if (!requirements) fail("PREPARE", "INVALID_TRANSITION");
    return requirements;
  }
  if (transition.type === "OUTCOME_OBSERVATION_RECORDED" ||
      transition.type === "ATTEMPT_DUTY_CREATED" || transition.type === "ATTEMPT_DUTY_ASSIGNED" ||
      transition.type === "ATTEMPT_DUTY_REVIEW_CLOSED") {
    if (state.genesis.adapterPolicyHash !== PORTABLE_ADAPTER_POLICY_E5_HASH &&
        state.genesis.adapterPolicyHash !== PORTABLE_ADAPTER_POLICY_E6_HASH) fail("PREPARE", "POLICY_UNAVAILABLE");
    if (transition.type === "ATTEMPT_DUTY_REVIEW_CLOSED" &&
        state.genesis.adapterPolicyHash !== PORTABLE_ADAPTER_POLICY_E6_HASH) fail("PREPARE", "POLICY_UNAVAILABLE");
    let intentId: string;
    let action: string;
    if (transition.type === "OUTCOME_OBSERVATION_RECORDED") {
      if (typeof data.intentId !== "string") fail("PREPARE", "INVALID_TRANSITION");
      intentId = data.intentId;
      action = "OBSERVE_OUTCOME";
    } else if (transition.type === "ATTEMPT_DUTY_CREATED") {
      if (!record(data.record) || typeof data.record.sourceIntentId !== "string") fail("PREPARE", "INVALID_TRANSITION");
      intentId = data.record.sourceIntentId;
      action = "CREATE_ATTEMPT_DUTY";
    } else {
      if (typeof data.dutyId !== "string") fail("PREPARE", "INVALID_TRANSITION");
      const duty = state.attemptDuties.get(data.dutyId);
      if (!duty) fail("PREPARE", "INVALID_TRANSITION");
      intentId = duty.record.sourceIntentId;
      if (transition.type === "ATTEMPT_DUTY_REVIEW_CLOSED") {
        const ids = (state.outcomeObservations.get(intentId) ?? []).map(item => item.eventId).sort(compareProtocolStrings);
        if (duty.currentAssigneeId !== actorId || canonicalEncode(data.observationEventIds) !== canonicalEncode(ids)) {
          fail("PREPARE", "INVALID_TRANSITION");
        }
        action = "CLOSE_ATTEMPT_DUTY";
      } else {
        if (data.fromAgentId !== duty.currentAssigneeId || data.toAgentId !== actorId) fail("PREPARE", "INVALID_TRANSITION");
        action = "ASSIGN_ATTEMPT_DUTY";
      }
    }
    const source = state.intentDeclarations.get(intentId);
    const admission = state.intentAdmissions.get(intentId);
    if (!source || !admission || admission.adapterIdentity.adapterProfile.profileId !== REMOTE_SERVICE_REPORT_ADAPTER_ID) {
      fail("PREPARE", "INVALID_TRANSITION");
    }
    const role = state.roles.get(source.data.roleId);
    if (!role || role.currentTenureId === undefined) fail("PREPARE", "INVALID_TRANSITION");
    if (transition.type === "OUTCOME_OBSERVATION_RECORDED") {
      if (data.sourceAdmissionEventId !== admission.admissionEventId ||
          !validatePortableAdapterAcknowledgment(data.acknowledgment, admission.adapterIdentity)) {
        fail("PREPARE", "INVALID_TRANSITION");
      }
    } else if (transition.type === "ATTEMPT_DUTY_CREATED") {
      const creation = data.record as Readonly<Record<string, unknown>>;
      if (creation.sourceAdmissionEventId !== admission.admissionEventId || creation.durableRoleId !== role.id ||
          creation.creationRoleTenureId !== role.currentTenureId || creation.performanceAssigneeId !== actorId) {
        fail("PREPARE", "INVALID_TRANSITION");
      }
    }
    return {
      request: { actorId, action, resource: intentId, claimedAt: transition.timestamp,
        ...(Object.hasOwn(source.data, "termsCommitment") ? { termsCommitment: source.data.termsCommitment! } : {}) },
      requiredPrincipalId: role.principalId, requiredAuthorityIds: [], roleId: role.id, roleTenureId: role.currentTenureId,
    };
  }
  if (transition.type === "OBLIGATION_CREATED") {
    const creation = data.record as PortableObligationRecord;
    const source = state.intentDeclarations.get(creation.sourceIntentId);
    const role = state.roles.get(creation.durableRoleId);
    if (!source || !role) fail("PREPARE", "INVALID_TRANSITION");
    return {
      request: { actorId, action: "OBLIGATE", resource: source.data.resource, claimedAt: transition.timestamp,
        termsCommitment: creation.termsCommitment,
        ...(Object.hasOwn(creation, "counterpartyId") ? { counterpartyId: creation.counterpartyId } : {}) },
      requiredPrincipalId: role.principalId, requiredAuthorityIds: [], roleId: role.id, roleTenureId: creation.creationRoleTenureId,
    };
  }
  if (typeof data.obligationId !== "string") fail("PREPARE", "INVALID_TRANSITION");
  const obligation = state.obligations.get(data.obligationId);
  if (!obligation) fail("PREPARE", "INVALID_TRANSITION");
  const role = state.roles.get(obligation.record.durableRoleId);
  if (!role || role.currentTenureId === undefined) fail("PREPARE", "INVALID_TRANSITION");
  let requiredAuthorityIds: readonly string[] = [];
  let action = "ASSIGN_PERFORMANCE";
  if (transition.type === "OBLIGATION_STATUS_RECORDED") {
    action = "record-collection-disposition";
    const policy = obligation.record.transitionPolicies.find(policy =>
      policy.fromStatus === "OPEN" && policy.toStatus === "OUTCOME_UNKNOWN" && policy.action === action);
    if (!policy || obligation.status !== "OPEN") fail("PREPARE", "POLICY_UNAVAILABLE");
    requiredAuthorityIds = policy.requiredAuthorityIds;
  }
  return {
    request: { actorId, action, resource: data.obligationId, claimedAt: transition.timestamp },
    requiredPrincipalId: role.principalId, requiredAuthorityIds, roleId: role.id, roleTenureId: role.currentTenureId,
  };
}

function prepareCaptured(input: CapturedInput, findingShapeOnly = false) {
  try {
    const state = replayPrefix(input.events);
    if (canonicalEncode(input.expectedDomain) !== canonicalEncode(state.genesis.domain)) fail("PREPARE", "DOMAIN_MISMATCH");
    if (canonicalEncode(input.expectedHistoryHead) !== canonicalEncode(state.head)) fail("PREPARE", "HEAD_MISMATCH");
    const transition = input.transition;
    if (transition.timestamp < state.head.canonicalTime) fail("PREPARE", "INVALID_TRANSITION");
    if (!findingShapeOnly && (transition.type === "ATTEMPT_DUTY_DISPOSITION_RECORDED" || transition.type === "ATTEMPT_DUTY_CONTEST_RECORDED") &&
        !validatePortableDutyFinding(state,transition as unknown as DutyUnsignedTransition))fail("PREPARE","INVALID_TRANSITION");
    const requirements = deriveRequirements(state, transition);
    const session = state.runtimeSessions.get(input.runtimeSessionId);
    const actor = state.agents.get(requirements.request.actorId);
    const role = state.roles.get(requirements.roleId);
    const tenure = state.tenures.get(requirements.roleTenureId);
    if (!session || !actor || actor.terminated || session.agentId !== actor.id ||
        session.controlEpoch !== actor.currentControlEpoch ||
        (session.expiresAt !== undefined && transition.timestamp >= session.expiresAt) ||
        !role || role.currentTenureId !== requirements.roleTenureId || !tenure || tenure.closed ||
        tenure.roleId !== role.id || tenure.agentId !== actor.id) fail("PREPARE", "SESSION_INVALID");
    const authorityProof = createPortableAdministrativePolicyProof(state, requirements, transition.timestamp);
    if (authorityProof === undefined || (transition.type === "ATTEMPT_DUTY_POLICY_ACTIVATED" &&
        !portableDutyPolicyActivationProofMatches(authorityProof, transition.data.activationAuthorityId as string))) {
      fail("PREPARE", "POLICY_UNAVAILABLE");
    }
    const baseChallenge = {
      version: "continuity-administrative-authorization/0.2" as const, domain: state.genesis.domain,
      request: requirements.request, authoritative: true as const, consequential: true as const,
      evaluationTime: transition.timestamp, policyVersion: state.genesis.policyVersion,
      rootRecognitionPolicy: state.genesis.rootRecognitionPolicy,
      eventHistoryHash: state.head.hash, eventHistoryPosition: state.head.position,
      transitionEventId: transition.id, transitionEventType: transition.type,
      transitionEffectHash: `0x${"0".repeat(64)}` as ContentHash,
      runtimeSessionId: session.id, credentialKeyId: session.credentialKeyId, controlEpoch: session.controlEpoch,
      roleId: requirements.roleId, roleTenureId: requirements.roleTenureId,
      authorityProofHash: `0x${"0".repeat(64)}` as ContentHash,
    };
    // Private r=s=1/v=27 stand-in: closed-shape validation only. Never replay,
    // sign, export or treat this value as authentication.
    const placeholder = `0x${"0".repeat(63)}1${"0".repeat(63)}11b`;
    const shaped = validateCanonicalEventShape({ ...transition, data: { ...transition.data,
      administrativeAuthorization: { challenge: baseChallenge, authorityProof, runtimeSignature: placeholder } } });
    if (!shaped.ok) fail("PREPARE", "INVALID_TRANSITION");
    const challenge = immutableProtocolValue({ ...baseChallenge,
      transitionEffectHash: hashCanonical(portableAdministrativeTransitionEffect(shaped.event)),
      authorityProofHash: hashCanonical(authorityProof),
    });
    return immutableProtocolValue({ transition, challenge, authorityProof, signingHash: hashCanonical(challenge) });
  } catch (error) {
    if (error instanceof AdministrativeProducerError) throw error;
    return fail("PREPARE", "PREPARATION_FAILED");
  }
}

type Prepared = ReturnType<typeof prepareCaptured>;
function attachCaptured(input: CapturedInput, prepared: Prepared, runtimeSignature: unknown) {
  if (typeof runtimeSignature !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(runtimeSignature)) fail("VERIFY", "INVALID_SIGNATURE");
  try {
    const event = immutableProtocolValue({ ...prepared.transition, data: { ...prepared.transition.data,
      administrativeAuthorization: { challenge: prepared.challenge, authorityProof: prepared.authorityProof, runtimeSignature } } });
    const replay = replayPortable({ operationVersion: PORTABLE_REPLAY_VERSION, events: [...input.events, event] });
    if (replay.status !== "ACCEPTED") fail("VERIFY", "SIGNED_EVENT_REJECTED");
    return immutableProtocolValue({ event, challenge: prepared.challenge, authorityProof: prepared.authorityProof,
      signingHash: prepared.signingHash, replayHead: replay.head });
  } catch (error) {
    if (error instanceof AdministrativeProducerError) throw error;
    return fail("VERIFY", "SIGNED_EVENT_REJECTED");
  }
}

/** Unsigned historical-prefix preparation; not permission or an append capability. */
export function prepareAdministrativeEvent(input: unknown) {
  return prepareCaptured(captureInput(input));
}

/** Re-derive rather than trust a caller-supplied preparation; append nothing. */
export function attachAdministrativeSignature(input: unknown, runtimeSignature: unknown) {
  const captured = captureInput(input);
  return attachCaptured(captured, prepareCaptured(captured), runtimeSignature);
}

/** The callback receives only one hash. No retry, alternate session or signing implementation. */
export async function produceAdministrativeEvent(input: unknown, options: unknown) {
  const captured = captureInput(input);
  const prepared = prepareCaptured(captured);
  return signCaptured(captured, prepared, options);
}

async function signCaptured(captured: CapturedInput, prepared: Prepared, options: unknown) {
  let callback: (hash: ContentHash) => unknown;
  try {
    if (!record(options) || ![Object.prototype, null].includes(Object.getPrototypeOf(options))) fail("SIGN", "SIGNER_INVALID");
    const keys = Reflect.ownKeys(options);
    const descriptor = Reflect.getOwnPropertyDescriptor(options, "signHash");
    if (keys.length !== 1 || keys[0] !== "signHash" || !descriptor ||
        !Object.hasOwn(descriptor, "value") || typeof descriptor.value !== "function") fail("SIGN", "SIGNER_INVALID");
    callback = descriptor.value as (hash: ContentHash) => unknown;
  } catch { return fail("SIGN", "SIGNER_INVALID"); }
  let signature: unknown;
  try { signature = await callback(prepared.signingHash); }
  catch { return fail("SIGN", "SIGNER_FAILED"); }
  return attachCaptured(captured, prepared, signature);
}


/** New bounded profile; the original producer's 128-event/1MiB contract is unchanged. */
function captureHistoryInput(history: unknown, input: unknown) {
  const snapshot = verifiedHistorySnapshot(history); // Identity check before inspecting input/signer.
  const fields = historyDataFields(input, ["expectedDomain", "expectedHistoryHead", "transition", "runtimeSessionId"]);
  const stable = captureHistoryAncillary(fields);
  return captureInput({ ...stable, events: snapshot.events }, true);
}
function checkPreparedShape(history: unknown, prepared: Prepared) {
  const placeholder = `0x${"0".repeat(63)}1${"0".repeat(63)}11b`;
  checkContinuationAppendShape(history, { ...prepared.transition, data: { ...prepared.transition.data,
    administrativeAuthorization: { challenge: prepared.challenge, authorityProof: prepared.authorityProof, runtimeSignature: placeholder } } });
}
export function prepareHistoryAdministrativeEvent(history: unknown, input: unknown) {
  const captured = captureHistoryInput(history, input), prepared = prepareCaptured(captured);
  checkPreparedShape(history, prepared);
  return prepared;
}
export function attachHistoryAdministrativeSignature(history: unknown, input: unknown, signature: unknown) {
  const captured = captureHistoryInput(history, input), prepared = prepareCaptured(captured);
  checkPreparedShape(history, prepared);
  const result = attachCaptured(captured, prepared, signature);
  appendContinuationEvent(history, result.event);
  return result;
}
export async function produceHistoryAdministrativeEvent(history: unknown, input: unknown, options: unknown) {
  const captured = captureHistoryInput(history, input), prepared = prepareCaptured(captured);
  checkPreparedShape(history, prepared); // Reject unsupported constructed size BEFORE asking for a signature.
  const result = await signCaptured(captured, prepared, options);
  appendContinuationEvent(history, result.event);
  return result; // Still historical preparation only; live post-signing checks belong to the store coordinator.
}


// These helpers accept only a provenance-checked continuation handle. Raw-file producers stay refused.
function captureDutyFindingInput(history:unknown,input:unknown) {
 const snapshot=verifiedHistorySnapshot(history);
 const stable=captureHistoryAncillary(historyDataFields(input,["expectedDomain","expectedHistoryHead","transition","runtimeSessionId"]));
 const captured=captureBoundedCanonicalValue(stable,{maxCanonicalBytes:16384});requireOriginalPresence(captured,captured.value);
 const body=captured.value as Record<string,unknown>;
 exactKeys(body.transition,TRANSITION_FIELDS,"PREPARE","INVALID_TRANSITION");
 const t=body.transition as Record<string,unknown>;
 if(t.type!=="ATTEMPT_DUTY_DISPOSITION_RECORDED"&&t.type!=="ATTEMPT_DUTY_CONTEST_RECORDED")fail("PREPARE","UNSUPPORTED_OPERATION");
 exactKeys(t.data,["dutyId","actorId","attesterId","attesterRuntimeSessionId","attestationAuthorityId","dispositionAuthorityId","operation"],"PREPARE","INVALID_TRANSITION");
 const state=replayPrefix(snapshot.events);
 if(canonicalEncode(body.expectedDomain)!==canonicalEncode(state.genesis.domain))fail("PREPARE","DOMAIN_MISMATCH");
 if(canonicalEncode(body.expectedHistoryHead)!==canonicalEncode(state.head))fail("PREPARE","HEAD_MISMATCH");
 if(typeof t.id!=="string"||typeof t.timestamp!=="number"||!Number.isSafeInteger(t.timestamp)||t.timestamp<0||Object.is(t.timestamp,-0)||typeof body.runtimeSessionId!=="string")fail("PREPARE","INVALID_TRANSITION");
 const transition=t as unknown as Readonly<{id:string;type:PortableDutyTransitionType;timestamp:number;data:PortableDutyFindingRequest}>;
 let challenge:ReturnType<typeof derivePortableDutyFinding>;
 try {challenge=derivePortableDutyFinding(state,transition);}catch{ return fail("PREPARE","INVALID_TRANSITION"); }
 return {state,snapshot,body,transition,challenge};
}
function dutyFindingAdministrativeInput(captured:ReturnType<typeof captureDutyFindingInput>,signature:`0x${string}`) {
 const {body,transition,challenge}=captured;
 return immutableProtocolValue({expectedDomain:body.expectedDomain,expectedHistoryHead:body.expectedHistoryHead,runtimeSessionId:body.runtimeSessionId,
  transition:{id:transition.id,type:transition.type,timestamp:transition.timestamp,data:{version:DUTY_POLICY_VERSION,rulesHash:DUTY_POLICY_RULES_HASH,
   dutyId:transition.data.dutyId,actorId:transition.data.actorId,dispositionAuthorityId:transition.data.dispositionAuthorityId,
   finding:{challenge,runtimeSignature:signature}}}});
}
/** Preflights the complete dual-signature event and outer proof before either callback. */
export function prepareHistoryDutyFinding(history:unknown,input:unknown) {
 const captured=captureDutyFindingInput(history,input);
 const placeholder=`0x${"0".repeat(63)}1${"0".repeat(63)}11b` as const;
 const administrative=dutyFindingAdministrativeInput(captured,placeholder);
 const prepared=prepareCaptured(captureHistoryInput(history,administrative),true);
 checkPreparedShape(history,prepared);
 return immutableProtocolValue({challenge:captured.challenge,signingHash:hashCanonical(captured.challenge)});
}
/** Re-derives the signed finding and authenticates it before any outer challenge is returned. */
export function attachHistoryDutyFinding(history:unknown,input:unknown,runtimeSignature:unknown) {
 const captured=captureDutyFindingInput(history,input);
 if(typeof runtimeSignature!=="string"||!/^0x[0-9a-fA-F]{130}$/.test(runtimeSignature))fail("VERIFY","INVALID_SIGNATURE");
 const administrative=dutyFindingAdministrativeInput(captured,runtimeSignature as `0x${string}`);
 if(!validatePortableDutyFinding(captured.state,administrative.transition as unknown as DutyUnsignedTransition))fail("VERIFY","INVALID_SIGNATURE");
 prepareHistoryAdministrativeEvent(history,administrative);
 return administrative;
}
