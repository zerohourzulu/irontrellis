import { captureBoundedCanonicalEventData, captureBoundedCanonicalValue, getCanonicalCaptureLimitErrorMetadata, } from "./canonical.js";
import { PORTABLE_INTENT_ADMISSION_VERSION, capturePortableAuthorityOperation, capturedPortableIntentAdmissionInputIsStructurallyValid, createPortableRuntimeAuthorizationChallenge, evaluateCapturedPortableIntentAdmissionState, hashPortableRuntimeAuthorizationChallenge, portableAdmissionOutputLimit, portableReplayAuthorizationIndeterminate, } from "./portable-authority-engine.js";
import { PORTABLE_REPLAY_VERSION, createPortableReplayKernel, isPortableReplayState, replayPortable, } from "./portable-replay.js";
import { arrayPush, copyArray, objectFreeze, } from "./host-intrinsics.js";
export { PORTABLE_INTENT_ADMISSION_VERSION } from "./portable-authority-engine.js";
const Object = objectFreeze({ freeze: objectFreeze });
const MAX_EVENT_DATA_BYTES = 1_048_576;
const indeterminateResult = (authorization) => Object.freeze({
    operationVersion: PORTABLE_INTENT_ADMISSION_VERSION,
    status: "INDETERMINATE",
    authorization,
});
const outputLimitResult = () => indeterminateResult(portableAdmissionOutputLimit());
const boundedAdmissionResult = (result) => {
    try {
        return captureBoundedCanonicalValue(result).value;
    }
    catch (error) {
        if (getCanonicalCaptureLimitErrorMetadata(error) !== undefined) {
            return outputLimitResult();
        }
        throw error;
    }
};
const wrapStateResult = (result) => {
    switch (result.status) {
        case "RETRY":
            return Object.freeze({
                operationVersion: PORTABLE_INTENT_ADMISSION_VERSION,
                status: "RETRY",
                intentId: result.intentId,
                existingAdmissionEventId: result.existingAdmissionEventId,
                existingAdmissionHead: result.existingAdmissionHead,
            });
        case "DENIED":
            return Object.freeze({
                operationVersion: PORTABLE_INTENT_ADMISSION_VERSION,
                status: "DENIED",
                authorization: result.authorization,
            });
        case "INDETERMINATE":
            return indeterminateResult(result.authorization);
        case "CONFLICT":
            return Object.freeze({
                operationVersion: PORTABLE_INTENT_ADMISSION_VERSION,
                status: "CONFLICT",
                expectedHead: result.expectedHead,
                observedHead: result.observedHead,
            });
    }
};
/**
 * Pure Section 7.4 preparation. It captures and evaluates one operation but
 * owns no durable append capability; therefore success is only PROPOSED.
 */
export const proposePortableIntentAdmission = (input) => {
    const kernel = createPortableReplayKernel();
    const captured = capturePortableAuthorityOperation(input, "INTENT_ADMISSION", kernel.visit);
    if (captured.status !== "CAPTURED") {
        return boundedAdmissionResult(indeterminateResult(portableReplayAuthorizationIndeterminate(captured.status === "UNSUPPORTED_VERSION"
            ? "UNSUPPORTED_VERSION"
            : captured.status === "STATE_NOT_AUTHORITATIVE"
                ? "STATE_NOT_AUTHORITATIVE"
                : "INVALID_INPUT")));
    }
    if (!capturedPortableIntentAdmissionInputIsStructurallyValid(captured.capture)) {
        return boundedAdmissionResult(indeterminateResult(portableReplayAuthorizationIndeterminate("INVALID_INPUT")));
    }
    const replay = kernel.finish();
    if (replay.status === "REJECTED") {
        const replayCode = replay.result.status === "REJECTED"
            ? replay.result.code
            : undefined;
        return boundedAdmissionResult(indeterminateResult(portableReplayAuthorizationIndeterminate(replayCode === "UNSUPPORTED_VERSION" ||
            replayCode === "UNSUPPORTED_EVENT_SCHEMA" ||
            replayCode === "UNSUPPORTED_EVENT_TYPE"
            ? "UNSUPPORTED_VERSION"
            : "STATE_NOT_AUTHORITATIVE")));
    }
    if (!isPortableReplayState(replay.state)) {
        return boundedAdmissionResult(indeterminateResult(portableReplayAuthorizationIndeterminate("STATE_NOT_AUTHORITATIVE")));
    }
    const evaluation = evaluateCapturedPortableIntentAdmissionState(captured.capture, replay.state);
    if (evaluation.status !== "AUTHORIZED") {
        return boundedAdmissionResult(wrapStateResult(evaluation));
    }
    const challenge = createPortableRuntimeAuthorizationChallenge({
        domain: evaluation.authorization.domain,
        request: evaluation.authorization.request,
        evaluationTime: evaluation.evaluationTime,
        policyVersion: evaluation.authorization.policyVersion,
        historyHead: evaluation.expectedHead,
        binding: evaluation.binding,
    });
    const data = Object.freeze({
        intentId: evaluation.binding.intentId,
        evaluationTime: evaluation.evaluationTime,
        expectedHistoryHead: evaluation.expectedHead,
        authorizationProof: evaluation.authorization,
        runtimeAuthorizationHash: hashPortableRuntimeAuthorizationChallenge(challenge),
        runtimeSignature: evaluation.binding.runtimeSignature,
    });
    const uncapturedEvent = Object.freeze({
        id: evaluation.admissionEventId,
        type: "TRANSACTION_INTENT_ADMITTED",
        timestamp: evaluation.evaluationTime,
        data,
    });
    let admissionEvent;
    let prospectiveReplayInput;
    try {
        const capturedData = captureBoundedCanonicalEventData(data, uncapturedEvent, MAX_EVENT_DATA_BYTES).value;
        admissionEvent = Object.freeze({
            id: uncapturedEvent.id,
            type: uncapturedEvent.type,
            timestamp: uncapturedEvent.timestamp,
            data: capturedData,
        });
        const prospectiveEvents = copyArray(replay.state.events);
        arrayPush(prospectiveEvents, admissionEvent);
        prospectiveReplayInput = captureBoundedCanonicalValue(Object.freeze({
            operationVersion: PORTABLE_REPLAY_VERSION,
            events: Object.freeze(prospectiveEvents),
        })).value;
    }
    catch (error) {
        if (getCanonicalCaptureLimitErrorMetadata(error) !== undefined) {
            return outputLimitResult();
        }
        throw error;
    }
    const prospective = replayPortable(prospectiveReplayInput);
    if (prospective.status !== "ACCEPTED") {
        return boundedAdmissionResult(indeterminateResult(portableReplayAuthorizationIndeterminate("STATE_NOT_AUTHORITATIVE", "REPLAY_VERIFIED")));
    }
    return boundedAdmissionResult(Object.freeze({
        operationVersion: PORTABLE_INTENT_ADMISSION_VERSION,
        status: "PROPOSED",
        authorization: evaluation.authorization,
        expectedHead: evaluation.expectedHead,
        admissionEvent,
        prospectiveHead: prospective.head,
    }));
};
