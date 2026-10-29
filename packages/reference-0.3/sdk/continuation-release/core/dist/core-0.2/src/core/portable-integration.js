/** Reference integration facts; these do not attest durability or issue authority. */
import { canonicalEncode, captureBoundedCanonicalReplayBodyIncrementally, immutableProtocolInput, immutableProtocolValue, isWellFormedUnicode, } from "./canonical.js";
import { validateCanonicalEventShape } from "./event-schema.js";
import { PORTABLE_ADAPTER_SUBMISSION_VERSION, } from "./portable-adapter-engine.js";
import { PORTABLE_REPLAY_VERSION, createPortableReplayKernel, portableAdmissionControlIsCurrent, } from "./portable-replay.js";
const acceptedState = (events) => {
    const source = Object.freeze({ operationVersion: PORTABLE_REPLAY_VERSION, events });
    const kernel = createPortableReplayKernel();
    const capture = captureBoundedCanonicalReplayBodyIncrementally(events, source, kernel.visit);
    if (capture.status !== "CAPTURED") {
        throw new TypeError("Portable history could not be captured.");
    }
    const result = kernel.finish();
    if (result.status !== "ACCEPTED") {
        throw new TypeError("Portable history is not replay-authoritative.");
    }
    return result.state;
};
const identifier = (value) => typeof value === "string" && value.length > 0 && value.length <= 256 &&
    isWellFormedUnicode(value) && !/[\u0000-\u001f\u007f]/u.test(value) &&
    new TextEncoder().encode(value).byteLength <= 256;
/**
 * Reconstruct one admission and its current consumption-control facts from the
 * supplied history. Only the configured coordinator can establish durability,
 * serialize a fresh observation and mint its separate local invocation token.
 */
export const inspectPortableAdmittedIntent = (events, intentId, useTime) => {
    if (!identifier(intentId))
        throw new TypeError("Invalid portable intent identifier.");
    if (typeof useTime !== "number" || !Number.isSafeInteger(useTime) ||
        useTime < 0 || Object.is(useTime, -0)) {
        throw new TypeError("Invalid authoritative use time.");
    }
    const state = acceptedState(events);
    if (useTime < state.head.canonicalTime) {
        throw new TypeError("Authoritative use time precedes the observed durable head.");
    }
    const admission = state.intentAdmissions.get(intentId);
    if (admission === undefined)
        return Object.freeze({ status: "ABSENT", head: state.head });
    const admissionEvent = state.events[admission.admissionEventPosition];
    const consumption = state.intentConsumptions.get(intentId);
    const outcome = state.intentOutcomeStates.get(intentId);
    return immutableProtocolValue({
        status: "ADMITTED",
        head: state.head,
        admissionEvent,
        admissionHead: admission.admissionHead,
        adapterIdentity: admission.adapterIdentity,
        currentControl: portableAdmissionControlIsCurrent(state, intentId, useTime),
        ...(consumption === undefined ? {} : { consumption }),
        ...(outcome?.terminal === undefined ? {} : { terminal: outcome.terminal }),
        ...(outcome === undefined ? {} : { latestOutcome: outcome.latest }),
    });
};
/** Valid-input-only Portable Contract §10.1 derivation; rejects before returning. */
export const derivePortableAdapterIdentity = (input) => {
    const captured = immutableProtocolInput(input);
    if (captured === null || typeof captured !== "object" || Array.isArray(captured)) {
        throw new TypeError("Adapter identity input must be a closed record.");
    }
    const value = captured;
    const required = ["operationVersion", "domain", "intentId", "admissionEvent", "admittedHistory"];
    const keys = Object.keys(value);
    if (keys.length !== required.length || required.some((key) => !Object.hasOwn(value, key)) ||
        value.operationVersion !== PORTABLE_ADAPTER_SUBMISSION_VERSION || !identifier(value.intentId)) {
        throw new TypeError("Unsupported or malformed adapter identity input.");
    }
    const state = acceptedState(value.admittedHistory);
    const admission = state.intentAdmissions.get(value.intentId);
    if (admission === undefined || admission.admissionEventPosition !== state.head.position) {
        throw new TypeError("Adapter identity requires the exact admission-inclusive prefix.");
    }
    const event = state.events[admission.admissionEventPosition];
    const suppliedEvent = validateCanonicalEventShape(value.admissionEvent);
    const domain = value.domain;
    const domainKeys = ["protocol", "version", "deploymentId", "chainId", "verifyingContract"];
    if (!suppliedEvent.ok || domain === null || typeof domain !== "object" || Array.isArray(domain) ||
        Object.keys(domain).length !== domainKeys.length || domainKeys.some(key => !Object.hasOwn(domain, key)) ||
        canonicalEncode(suppliedEvent.event) !== canonicalEncode(event) ||
        canonicalEncode(value.domain) !== canonicalEncode(event.data.authorizationProof.domain)) {
        throw new TypeError("Adapter identity does not match the exact admitted event and proof domain.");
    }
    return Object.freeze({
        operationVersion: PORTABLE_ADAPTER_SUBMISSION_VERSION,
        ...admission.adapterIdentity,
    });
};
