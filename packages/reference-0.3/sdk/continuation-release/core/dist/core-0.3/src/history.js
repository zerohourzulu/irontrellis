/** Experimental history-aware pure operations. No durable writes or adapter dispatch. */
import * as core from "../../core-0.2/src/core/index.js";
import { captureContinuationHistory, continuationPrefix, exportContinuationEvents, appendContinuationEvent, verifiedHistorySnapshot, historyDataFields, captureHistoryAncillary, CONTINUATION_HISTORY_VERSION, CONTINUATION_PROFILE, HistoryError, } from "../../core-0.2/src/history/index.js";
import { prepareHistoryAdministrativeEvent, attachHistoryAdministrativeSignature, produceHistoryAdministrativeEvent } from "../../core-0.2/src/administration/index.js";
export { captureContinuationHistory, continuationPrefix, exportContinuationEvents, appendContinuationEvent, CONTINUATION_HISTORY_VERSION, CONTINUATION_PROFILE, HistoryError };
export const HISTORY_OPERATION_VERSION = "continuity-history-operation/1";
function envelope(history, result) {
    const { state } = verifiedHistorySnapshot(history);
    return Object.freeze({ version: HISTORY_OPERATION_VERSION, profile: CONTINUATION_PROFILE.version,
        historyHead: state.head, scope: "CAPTURED_HISTORY_ONLY", executionCapability: false, result });
}
function argumentsFor(history, input, required, optional = []) {
    const snapshot = verifiedHistorySnapshot(history);
    return { snapshot, args: captureHistoryAncillary(historyDataFields(input, required, optional)) };
}
export function authorizeContinuation(history, input) {
    const { snapshot, args } = argumentsFor(history, input, ["domain", "policyVersion", "rootRecognitionPolicy", "request", "evaluationTime", "authoritative", "consequential"], ["binding"]);
    return envelope(history, core.authorizePortable({ ...args, operationVersion: core.PORTABLE_AUTHORIZATION_VERSION,
        events: snapshot.events, expectedHistoryHead: snapshot.state.head }));
}
export function proposeContinuationAdmission(history, input) {
    const { snapshot, args } = argumentsFor(history, input, ["admissionEventId", "domain", "policyVersion", "request", "evaluationTime", "binding"]);
    const result = core.proposePortableIntentAdmission({ ...args, operationVersion: core.PORTABLE_INTENT_ADMISSION_VERSION,
        events: snapshot.events, expectedHistoryHead: snapshot.state.head });
    if (result.status === "PROPOSED")
        appendContinuationEvent(history, result.admissionEvent);
    return envelope(history, result);
}
export function continuationRuntimeChallenge(history, input) {
    const { snapshot, args } = argumentsFor(history, input, ["domain", "request", "evaluationTime", "policyVersion", "binding"]);
    // Project the existing challenge fields. Admission validates the signed request; this projection is not permission.
    return envelope(history, core.createPortableRuntimeAuthorizationChallenge({ ...args, historyHead: snapshot.state.head }));
}
export function prepareContinuationAdministration(history, input) {
    return envelope(history, prepareHistoryAdministrativeEvent(history, input));
}
export function attachContinuationAdministration(history, input, signature) {
    return envelope(history, attachHistoryAdministrativeSignature(history, input, signature));
}
export async function produceContinuationAdministration(history, input, options) {
    return envelope(history, await produceHistoryAdministrativeEvent(history, input, options));
}
export async function createContinuationReceipt(history, input, signer) {
    const { snapshot, args } = argumentsFor(history, input, ["intentId", "issuedAt", "externalOutcome"]);
    // Read signer once through descriptors; no accessor-supplied executable integration.
    const fields = historyDataFields(signer, ["keyId", "signHash"]);
    if (typeof fields.keyId !== "string" || typeof fields.signHash !== "function")
        throw new HistoryError("INVALID_INPUT");
    const result = await core.createPortableReceipt({ ...args, events: snapshot.events }, Object.freeze({ keyId: fields.keyId, signHash: fields.signHash }));
    return envelope(history, result);
}
export function verifyContinuationReceipt(issuance, observed, input) {
    const first = verifiedHistorySnapshot(issuance), second = verifiedHistorySnapshot(observed);
    const args = captureHistoryAncillary(historyDataFields(input, ["artifact", "expectedDomain", "verifierTime"]));
    return envelope(observed, core.verifyPortableReceipt({ ...args, operationVersion: core.PORTABLE_RECEIPT_VERIFICATION_VERSION,
        issuanceEvents: first.events, observedEvents: second.events }));
}
export function proposeContinuationReceiptRecord(history, input) {
    const { snapshot, args } = argumentsFor(history, input, ["artifact", "expectedDomain", "recordEventId"]);
    const result = core.proposePortableReceiptRecord({ ...args, operationVersion: core.PORTABLE_RECEIPT_RECORD_ADMISSION_VERSION,
        events: snapshot.events, expectedHistoryHead: snapshot.state.head });
    if (result.status === "PROPOSED")
        appendContinuationEvent(history, result.recordEvent);
    return envelope(history, result);
}
export function queryContinuation(kind, evaluation, observed, input) {
    const first = verifiedHistorySnapshot(evaluation), second = verifiedHistorySnapshot(observed);
    if (!["WHY", "RESPONSIBLE", "SURVIVES"].includes(kind))
        throw new HistoryError("INVALID_INPUT");
    const required = kind === "SURVIVES" ? ["targetAgentId", "evaluationTime", "disclosure"] : ["authorizationDomain", "request", "evaluationTime", "disclosure"];
    const args = captureHistoryAncillary(historyDataFields(input, required, kind === "SURVIVES" ? [] : ["consequentialBinding"]));
    const operation = { ...args, operationVersion: core.PORTABLE_QUERY_VERSION, evaluationEvents: first.events, observedEvents: second.events };
    const result = kind === "WHY" ? core.whyPortable(operation) : kind === "RESPONSIBLE" ? core.responsiblePortable(operation) : core.survivesPortable(operation);
    return envelope(observed, result);
}
