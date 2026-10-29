/** Repository-local preparation only; never a durable append or authority capability. */
import { captureBoundedCanonicalValue, captureBoundedCanonicalReplayBodyIncrementally, canonicalEncode, compareProtocolStrings, hashCanonical, immutableProtocolValue, isCanonicalCaptureLimitError, } from "../core/canonical.js";
import { validateCanonicalEventShape } from "../core/event-schema.js";
import { createPortableReplayKernel, replayPortable, PORTABLE_REPLAY_VERSION } from "../core/portable-replay.js";
import { createPortableAdministrativePolicyProof } from "../core/portable-authority-engine.js";
import { portableAdministrativeTransitionEffect } from "../core/portable-administration-codec.js";
import { PORTABLE_ADAPTER_POLICY_E5_HASH, PORTABLE_ADAPTER_POLICY_E6_HASH, REMOTE_SERVICE_REPORT_ADAPTER_ID, validatePortableAdapterAcknowledgment, } from "../core/portable-adapter-engine.js";
export class AdministrativeProducerError extends Error {
    phase;
    code;
    constructor(phase, code) {
        super(`${phase}:${code}`);
        this.name = "AdministrativeProducerError";
        this.phase = phase;
        this.code = code;
    }
}
import { CONTINUATION_PROFILE, verifiedHistorySnapshot, captureHistoryAncillary, historyDataFields, checkContinuationAppendShape, appendContinuationEvent } from "../history/index.js";
const INPUT_BYTES = 1_048_576;
const PREFIX_EVENTS = 128;
const INPUT_FIELDS = ["events", "expectedDomain", "expectedHistoryHead", "transition", "runtimeSessionId"];
const TRANSITION_FIELDS = ["id", "type", "timestamp", "data"];
const DATA_FIELDS = {
    OBLIGATION_CREATED: ["record", "actorId"],
    OBLIGATION_PERFORMANCE_ASSIGNED: ["obligationId", "fromAgentId", "toAgentId", "successionRuleId", "actorId"],
    OBLIGATION_STATUS_RECORDED: ["obligationId", "fromStatus", "toStatus", "actorId", "action", "attesterId", "evidenceReference"],
    OUTCOME_OBSERVATION_RECORDED: ["intentId", "sourceAdmissionEventId", "acknowledgment", "actorId"],
    ATTEMPT_DUTY_CREATED: ["record", "actorId"],
    ATTEMPT_DUTY_ASSIGNED: ["dutyId", "fromAgentId", "toAgentId", "actorId"],
    ATTEMPT_DUTY_REVIEW_CLOSED: ["dutyId", "actorId", "observationEventIds", "summaryDigest"],
};
function fail(phase, code) {
    throw new AdministrativeProducerError(phase, code);
}
const record = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
// Strict canonical capture can omit undefined-valued record properties. Its
// retained key metadata lets this closed facade reject that normalization,
// without touching any original accessor or object a second time.
const requireOriginalPresence = (capture, value) => {
    if (Array.isArray(value)) {
        for (const member of value)
            requireOriginalPresence(capture, member);
    }
    else if (record(value)) {
        const originalKeys = capture.capturedRecordKeys(value);
        if (!originalKeys || originalKeys.length !== Object.keys(value).length ||
            originalKeys.some(key => !Object.hasOwn(value, key)))
            fail("CAPTURE", "INVALID_INPUT");
        for (const key of originalKeys)
            requireOriginalPresence(capture, value[key]);
    }
};
const exactKeys = (value, keys, phase, code) => {
    if (!record(value) || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key)))
        fail(phase, code);
};
function captureInput(input, historyProfile = false) {
    const inputBytes = historyProfile ? CONTINUATION_PROFILE.maxCanonicalHistoryBytes + CONTINUATION_PROFILE.maxAncillaryBytes + 16384 : INPUT_BYTES;
    let capture;
    try {
        capture = captureBoundedCanonicalValue(input, { maxCanonicalBytes: inputBytes });
    }
    catch (error) {
        return fail("CAPTURE", isCanonicalCaptureLimitError(error, "$", inputBytes) ? "INPUT_LIMIT" : "INVALID_INPUT");
    }
    requireOriginalPresence(capture, capture.value);
    exactKeys(capture.value, INPUT_FIELDS, "CAPTURE", "INVALID_INPUT");
    const body = capture.value;
    if (!Array.isArray(body.events))
        fail("CAPTURE", "INVALID_INPUT");
    if (body.events.length > (historyProfile ? CONTINUATION_PROFILE.maxEvents : PREFIX_EVENTS))
        fail("CAPTURE", "INPUT_LIMIT");
    if (typeof body.runtimeSessionId !== "string" || body.runtimeSessionId.length === 0)
        fail("CAPTURE", "INVALID_INPUT");
    exactKeys(body.transition, TRANSITION_FIELDS, "PREPARE", "INVALID_TRANSITION");
    const transition = body.transition;
    if (typeof transition.type !== "string" || !Object.hasOwn(DATA_FIELDS, transition.type))
        fail("PREPARE", "UNSUPPORTED_OPERATION");
    exactKeys(transition.data, DATA_FIELDS[transition.type], "PREPARE", "INVALID_TRANSITION");
    if (typeof transition.id !== "string" || transition.id.length === 0 ||
        typeof transition.timestamp !== "number" || !Number.isSafeInteger(transition.timestamp) ||
        transition.timestamp < 0 || Object.is(transition.timestamp, -0))
        fail("PREPARE", "INVALID_TRANSITION");
    const data = transition.data;
    if (typeof data.actorId !== "string")
        fail("PREPARE", "INVALID_TRANSITION");
    if (transition.type === "OBLIGATION_CREATED" || transition.type === "ATTEMPT_DUTY_CREATED") {
        if (!record(data.record))
            fail("PREPARE", "INVALID_TRANSITION");
        if (data.record.status !== "OPEN")
            fail("PREPARE", "UNSUPPORTED_STATUS");
    }
    else if (transition.type === "OBLIGATION_STATUS_RECORDED" &&
        (data.fromStatus !== "OPEN" || data.toStatus !== "OUTCOME_UNKNOWN" || data.action !== "record-collection-disposition")) {
        fail("PREPARE", "UNSUPPORTED_STATUS");
    }
    return capture.value;
}
function replayPrefix(events) {
    const kernel = createPortableReplayKernel();
    const capture = captureBoundedCanonicalReplayBodyIncrementally(events, Object.freeze({ operationVersion: PORTABLE_REPLAY_VERSION, events }), kernel.visit);
    if (capture.status !== "CAPTURED")
        fail("PREPARE", "PREFIX_REJECTED");
    const result = kernel.finish();
    if (result.status !== "ACCEPTED")
        fail("PREPARE", "PREFIX_REJECTED");
    return result.state;
}
function deriveRequirements(state, transition) {
    const data = transition.data, actorId = data.actorId;
    if (transition.type === "OUTCOME_OBSERVATION_RECORDED" ||
        transition.type === "ATTEMPT_DUTY_CREATED" || transition.type === "ATTEMPT_DUTY_ASSIGNED" ||
        transition.type === "ATTEMPT_DUTY_REVIEW_CLOSED") {
        if (state.genesis.adapterPolicyHash !== PORTABLE_ADAPTER_POLICY_E5_HASH &&
            state.genesis.adapterPolicyHash !== PORTABLE_ADAPTER_POLICY_E6_HASH)
            fail("PREPARE", "POLICY_UNAVAILABLE");
        if (transition.type === "ATTEMPT_DUTY_REVIEW_CLOSED" &&
            state.genesis.adapterPolicyHash !== PORTABLE_ADAPTER_POLICY_E6_HASH)
            fail("PREPARE", "POLICY_UNAVAILABLE");
        let intentId;
        let action;
        if (transition.type === "OUTCOME_OBSERVATION_RECORDED") {
            if (typeof data.intentId !== "string")
                fail("PREPARE", "INVALID_TRANSITION");
            intentId = data.intentId;
            action = "OBSERVE_OUTCOME";
        }
        else if (transition.type === "ATTEMPT_DUTY_CREATED") {
            if (!record(data.record) || typeof data.record.sourceIntentId !== "string")
                fail("PREPARE", "INVALID_TRANSITION");
            intentId = data.record.sourceIntentId;
            action = "CREATE_ATTEMPT_DUTY";
        }
        else {
            if (typeof data.dutyId !== "string")
                fail("PREPARE", "INVALID_TRANSITION");
            const duty = state.attemptDuties.get(data.dutyId);
            if (!duty)
                fail("PREPARE", "INVALID_TRANSITION");
            intentId = duty.record.sourceIntentId;
            if (transition.type === "ATTEMPT_DUTY_REVIEW_CLOSED") {
                const ids = (state.outcomeObservations.get(intentId) ?? []).map(item => item.eventId).sort(compareProtocolStrings);
                if (duty.currentAssigneeId !== actorId || canonicalEncode(data.observationEventIds) !== canonicalEncode(ids)) {
                    fail("PREPARE", "INVALID_TRANSITION");
                }
                action = "CLOSE_ATTEMPT_DUTY";
            }
            else {
                if (data.fromAgentId !== duty.currentAssigneeId || data.toAgentId !== actorId)
                    fail("PREPARE", "INVALID_TRANSITION");
                action = "ASSIGN_ATTEMPT_DUTY";
            }
        }
        const source = state.intentDeclarations.get(intentId);
        const admission = state.intentAdmissions.get(intentId);
        if (!source || !admission || admission.adapterIdentity.adapterProfile.profileId !== REMOTE_SERVICE_REPORT_ADAPTER_ID) {
            fail("PREPARE", "INVALID_TRANSITION");
        }
        const role = state.roles.get(source.data.roleId);
        if (!role || role.currentTenureId === undefined)
            fail("PREPARE", "INVALID_TRANSITION");
        if (transition.type === "OUTCOME_OBSERVATION_RECORDED") {
            if (data.sourceAdmissionEventId !== admission.admissionEventId ||
                !validatePortableAdapterAcknowledgment(data.acknowledgment, admission.adapterIdentity)) {
                fail("PREPARE", "INVALID_TRANSITION");
            }
        }
        else if (transition.type === "ATTEMPT_DUTY_CREATED") {
            const creation = data.record;
            if (creation.sourceAdmissionEventId !== admission.admissionEventId || creation.durableRoleId !== role.id ||
                creation.creationRoleTenureId !== role.currentTenureId || creation.performanceAssigneeId !== actorId) {
                fail("PREPARE", "INVALID_TRANSITION");
            }
        }
        return {
            request: { actorId, action, resource: intentId, claimedAt: transition.timestamp,
                ...(Object.hasOwn(source.data, "termsCommitment") ? { termsCommitment: source.data.termsCommitment } : {}) },
            requiredPrincipalId: role.principalId, requiredAuthorityIds: [], roleId: role.id, roleTenureId: role.currentTenureId,
        };
    }
    if (transition.type === "OBLIGATION_CREATED") {
        const creation = data.record;
        const source = state.intentDeclarations.get(creation.sourceIntentId);
        const role = state.roles.get(creation.durableRoleId);
        if (!source || !role)
            fail("PREPARE", "INVALID_TRANSITION");
        return {
            request: { actorId, action: "OBLIGATE", resource: source.data.resource, claimedAt: transition.timestamp,
                termsCommitment: creation.termsCommitment,
                ...(Object.hasOwn(creation, "counterpartyId") ? { counterpartyId: creation.counterpartyId } : {}) },
            requiredPrincipalId: role.principalId, requiredAuthorityIds: [], roleId: role.id, roleTenureId: creation.creationRoleTenureId,
        };
    }
    if (typeof data.obligationId !== "string")
        fail("PREPARE", "INVALID_TRANSITION");
    const obligation = state.obligations.get(data.obligationId);
    if (!obligation)
        fail("PREPARE", "INVALID_TRANSITION");
    const role = state.roles.get(obligation.record.durableRoleId);
    if (!role || role.currentTenureId === undefined)
        fail("PREPARE", "INVALID_TRANSITION");
    let requiredAuthorityIds = [];
    let action = "ASSIGN_PERFORMANCE";
    if (transition.type === "OBLIGATION_STATUS_RECORDED") {
        action = "record-collection-disposition";
        const policy = obligation.record.transitionPolicies.find(policy => policy.fromStatus === "OPEN" && policy.toStatus === "OUTCOME_UNKNOWN" && policy.action === action);
        if (!policy || obligation.status !== "OPEN")
            fail("PREPARE", "POLICY_UNAVAILABLE");
        requiredAuthorityIds = policy.requiredAuthorityIds;
    }
    return {
        request: { actorId, action, resource: data.obligationId, claimedAt: transition.timestamp },
        requiredPrincipalId: role.principalId, requiredAuthorityIds, roleId: role.id, roleTenureId: role.currentTenureId,
    };
}
function prepareCaptured(input) {
    try {
        const state = replayPrefix(input.events);
        if (canonicalEncode(input.expectedDomain) !== canonicalEncode(state.genesis.domain))
            fail("PREPARE", "DOMAIN_MISMATCH");
        if (canonicalEncode(input.expectedHistoryHead) !== canonicalEncode(state.head))
            fail("PREPARE", "HEAD_MISMATCH");
        const transition = input.transition;
        if (transition.timestamp < state.head.canonicalTime)
            fail("PREPARE", "INVALID_TRANSITION");
        const requirements = deriveRequirements(state, transition);
        const session = state.runtimeSessions.get(input.runtimeSessionId);
        const actor = state.agents.get(requirements.request.actorId);
        const role = state.roles.get(requirements.roleId);
        const tenure = state.tenures.get(requirements.roleTenureId);
        if (!session || !actor || actor.terminated || session.agentId !== actor.id ||
            session.controlEpoch !== actor.currentControlEpoch ||
            (session.expiresAt !== undefined && transition.timestamp >= session.expiresAt) ||
            !role || role.currentTenureId !== requirements.roleTenureId || !tenure || tenure.closed ||
            tenure.roleId !== role.id || tenure.agentId !== actor.id)
            fail("PREPARE", "SESSION_INVALID");
        const authorityProof = createPortableAdministrativePolicyProof(state, requirements, transition.timestamp);
        if (authorityProof === undefined)
            fail("PREPARE", "POLICY_UNAVAILABLE");
        const baseChallenge = {
            version: "continuity-administrative-authorization/0.2", domain: state.genesis.domain,
            request: requirements.request, authoritative: true, consequential: true,
            evaluationTime: transition.timestamp, policyVersion: state.genesis.policyVersion,
            rootRecognitionPolicy: state.genesis.rootRecognitionPolicy,
            eventHistoryHash: state.head.hash, eventHistoryPosition: state.head.position,
            transitionEventId: transition.id, transitionEventType: transition.type,
            transitionEffectHash: `0x${"0".repeat(64)}`,
            runtimeSessionId: session.id, credentialKeyId: session.credentialKeyId, controlEpoch: session.controlEpoch,
            roleId: requirements.roleId, roleTenureId: requirements.roleTenureId,
            authorityProofHash: `0x${"0".repeat(64)}`,
        };
        // Private r=s=1/v=27 stand-in: closed-shape validation only. Never replay,
        // sign, export or treat this value as authentication.
        const placeholder = `0x${"0".repeat(63)}1${"0".repeat(63)}11b`;
        const shaped = validateCanonicalEventShape({ ...transition, data: { ...transition.data,
                administrativeAuthorization: { challenge: baseChallenge, authorityProof, runtimeSignature: placeholder } } });
        if (!shaped.ok)
            fail("PREPARE", "INVALID_TRANSITION");
        const challenge = immutableProtocolValue({ ...baseChallenge,
            transitionEffectHash: hashCanonical(portableAdministrativeTransitionEffect(shaped.event)),
            authorityProofHash: hashCanonical(authorityProof),
        });
        return immutableProtocolValue({ transition, challenge, authorityProof, signingHash: hashCanonical(challenge) });
    }
    catch (error) {
        if (error instanceof AdministrativeProducerError)
            throw error;
        return fail("PREPARE", "PREPARATION_FAILED");
    }
}
function attachCaptured(input, prepared, runtimeSignature) {
    if (typeof runtimeSignature !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(runtimeSignature))
        fail("VERIFY", "INVALID_SIGNATURE");
    try {
        const event = immutableProtocolValue({ ...prepared.transition, data: { ...prepared.transition.data,
                administrativeAuthorization: { challenge: prepared.challenge, authorityProof: prepared.authorityProof, runtimeSignature } } });
        const replay = replayPortable({ operationVersion: PORTABLE_REPLAY_VERSION, events: [...input.events, event] });
        if (replay.status !== "ACCEPTED")
            fail("VERIFY", "SIGNED_EVENT_REJECTED");
        return immutableProtocolValue({ event, challenge: prepared.challenge, authorityProof: prepared.authorityProof,
            signingHash: prepared.signingHash, replayHead: replay.head });
    }
    catch (error) {
        if (error instanceof AdministrativeProducerError)
            throw error;
        return fail("VERIFY", "SIGNED_EVENT_REJECTED");
    }
}
/** Unsigned historical-prefix preparation; not permission or an append capability. */
export function prepareAdministrativeEvent(input) {
    return prepareCaptured(captureInput(input));
}
/** Re-derive rather than trust a caller-supplied preparation; append nothing. */
export function attachAdministrativeSignature(input, runtimeSignature) {
    const captured = captureInput(input);
    return attachCaptured(captured, prepareCaptured(captured), runtimeSignature);
}
/** The callback receives only one hash. No retry, alternate session or signing implementation. */
export async function produceAdministrativeEvent(input, options) {
    const captured = captureInput(input);
    const prepared = prepareCaptured(captured);
    return signCaptured(captured, prepared, options);
}
async function signCaptured(captured, prepared, options) {
    let callback;
    try {
        if (!record(options) || ![Object.prototype, null].includes(Object.getPrototypeOf(options)))
            fail("SIGN", "SIGNER_INVALID");
        const keys = Reflect.ownKeys(options);
        const descriptor = Reflect.getOwnPropertyDescriptor(options, "signHash");
        if (keys.length !== 1 || keys[0] !== "signHash" || !descriptor ||
            !Object.hasOwn(descriptor, "value") || typeof descriptor.value !== "function")
            fail("SIGN", "SIGNER_INVALID");
        callback = descriptor.value;
    }
    catch {
        return fail("SIGN", "SIGNER_INVALID");
    }
    let signature;
    try {
        signature = await callback(prepared.signingHash);
    }
    catch {
        return fail("SIGN", "SIGNER_FAILED");
    }
    return attachCaptured(captured, prepared, signature);
}
/** New bounded profile; the original producer's 128-event/1MiB contract is unchanged. */
function captureHistoryInput(history, input) {
    const snapshot = verifiedHistorySnapshot(history); // Identity check before inspecting input/signer.
    const fields = historyDataFields(input, ["expectedDomain", "expectedHistoryHead", "transition", "runtimeSessionId"]);
    const stable = captureHistoryAncillary(fields);
    return captureInput({ ...stable, events: snapshot.events }, true);
}
function checkPreparedShape(history, prepared) {
    const placeholder = `0x${"0".repeat(63)}1${"0".repeat(63)}11b`;
    checkContinuationAppendShape(history, { ...prepared.transition, data: { ...prepared.transition.data,
            administrativeAuthorization: { challenge: prepared.challenge, authorityProof: prepared.authorityProof, runtimeSignature: placeholder } } });
}
export function prepareHistoryAdministrativeEvent(history, input) {
    const captured = captureHistoryInput(history, input), prepared = prepareCaptured(captured);
    checkPreparedShape(history, prepared);
    return prepared;
}
export function attachHistoryAdministrativeSignature(history, input, signature) {
    const captured = captureHistoryInput(history, input), prepared = prepareCaptured(captured);
    checkPreparedShape(history, prepared);
    const result = attachCaptured(captured, prepared, signature);
    appendContinuationEvent(history, result.event);
    return result;
}
export async function produceHistoryAdministrativeEvent(history, input, options) {
    const captured = captureHistoryInput(history, input), prepared = prepareCaptured(captured);
    checkPreparedShape(history, prepared); // Reject unsupported constructed size BEFORE asking for a signature.
    const result = await signCaptured(captured, prepared, options);
    appendContinuationEvent(history, result.event);
    return result; // Still historical preparation only; live post-signing checks belong to the store coordinator.
}
