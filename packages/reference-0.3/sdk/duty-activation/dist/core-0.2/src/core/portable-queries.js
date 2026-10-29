import { DUTY_POLICY_VERSION, DUTY_POLICY_RULES_HASH } from "./duty-policy.js";
/** Total Section9 query operations over captured canonical event histories. */
import { canonicalEncode, captureBoundedCanonicalReplayBodyIncrementally, compareProtocolStrings, hashCanonical, immutableProtocolValue, } from "./canonical.js";
import { validateCapturedReplayBaseCandidate, validateCapturedGenesisVersionProbe, validateCapturedPortableQueryDisclosure, } from "./event-schema.js";
import { authorizePortable } from "./portable-authority.js";
import { createPortableReplayKernel, PORTABLE_REPLAY_VERSION } from "./portable-replay.js";
import { capturePortableQueryInput } from "./portable-query-capture.js";
import { findPortableQueryConflict } from "./portable-query-conflicts.js";
import { derivePortableResponsibility } from "./portable-query-responsibility.js";
import { derivePortableSurvives } from "./portable-query-survives.js";
import { PORTABLE_QUERY_VERSION, PORTABLE_QUERY_EXTERNAL_ASSUMPTIONS, PORTABLE_QUERY_ANSWER_FIELD_PATHS, PORTABLE_DUTY_QUERY_FIELD_PATHS, queryEventReference, queryEvidence, } from "./portable-query-codec.js";
import { measureReferenceOutput, isReferenceOutputOverflow } from "./reference-output-budget.js";
const EMPTY = Object.freeze([]);
const EMPTY_DISCLOSURE = Object.freeze({ mode: "PUBLIC_MINIMAL", includedFields: Object.freeze([]), withheldFields: Object.freeze([]) });
const blankScope = (unavailableEvidence = EMPTY) => ({
    headRelationship: "UNVERIFIED", freshness: "UNVERIFIED", finality: "LOCAL_ONLY",
    unavailableEvidence, withheldEvidence: EMPTY, externalAssumptions: PORTABLE_QUERY_EXTERNAL_ASSUMPTIONS,
});
const failure = (kind, code, scope = blankScope(), evidence = EMPTY) => immutableProtocolValue({
    version: PORTABLE_QUERY_VERSION, kind,
    epistemicStatus: code === "EVIDENCE_UNAVAILABLE" ? "UNAVAILABLE" : code === "EVIDENCE_DISPUTED" ? "DISPUTED" : "INDETERMINATE",
    scope: { ...scope, headRelationship: "UNVERIFIED", freshness: "UNVERIFIED" }, code, evidence,
    externalAssumptions: PORTABLE_QUERY_EXTERNAL_ASSUMPTIONS,
});
const identityFor = (evaluation, observed) => ({
    domain: evaluation.genesis.domain, versions: evaluation.genesis.versions,
    policyVersion: evaluation.genesis.policyVersion, rootRecognitionPolicy: evaluation.genesis.rootRecognitionPolicy,
    recognizedRootIds: [...evaluation.recognizedRoots.keys()].sort(compareProtocolStrings),
    canonicalLineageId: evaluation.genesis.canonicalLineageId,
    evaluationHead: evaluation.head, observedHead: observed.head,
    ...((evaluation.attemptDutyPolicies.size > 0 || observed.attemptDutyPolicies.size > 0) ? {
        recognizedExtensions: [{ version: DUTY_POLICY_VERSION, rulesHash: DUTY_POLICY_RULES_HASH }],
    } : {}),
});
const compactIdentity = ({ recognizedRootIds: _roots, ...identity }) => identity;
const replay = (events) => {
    const kernel = createPortableReplayKernel();
    const input = Object.freeze({ operationVersion: PORTABLE_REPLAY_VERSION, events });
    const capture = captureBoundedCanonicalReplayBodyIncrementally(events, input, kernel.visit);
    return capture.status === "CAPTURED" ? kernel.finish() : undefined;
};
const VERSIONS = Object.freeze({
    eventSchemaVersion: "continuity-event/0.2", receiptSchemaVersion: "continuity-receipt/0.2",
    queryEnvelopeVersion: "continuity-query-envelope/0.2", authorizationProofVersion: "continuity-authorization-proof/0.2",
    runtimeAuthorizationVersion: "continuity-runtime-authorization/0.2", administrativeAuthorizationVersion: "continuity-administrative-authorization/0.2",
    signatureScheme: "eip191-personal-sign-keccak256",
});
const discover = (events, capture) => {
    if (events.length === 0)
        return undefined;
    let genesis;
    for (let position = 0; position < events.length; position += 1) {
        const base = validateCapturedReplayBaseCandidate(events[position], position, capture);
        if (!base.ok)
            return undefined;
        if (position === 0)
            genesis = validateCapturedGenesisVersionProbe(base.baseEvent);
    }
    if (genesis === undefined || !genesis.ok)
        return undefined;
    return { supported: canonicalEncode(genesis.versions) === canonicalEncode(VERSIONS), genesis: genesis.probe };
};
const genesisReference = (genesis) => ({
    kind: "EVENT", eventId: genesis.id, eventType: "DEPLOYMENT_INITIALIZED", position: 0,
    historyHash: hashCanonical(["continuity-event-history/0.2", [genesis]]),
});
const answerFieldPaths = (answer) => {
    const fields = new Set();
    const visit = (value, prefix) => {
        if (Array.isArray(value)) {
            for (const item of value)
                visit(item, prefix);
        }
        else if (value !== null && typeof value === "object") {
            for (const [key, child] of Object.entries(value)) {
                if (child === undefined)
                    continue;
                const path = prefix ? `${prefix}.${key}` : key;
                fields.add(path);
                visit(child, path);
            }
        }
    };
    visit(answer, "");
    return [...fields].sort(compareProtocolStrings);
};
const coreFields = new Set([...PORTABLE_QUERY_ANSWER_FIELD_PATHS, ...PORTABLE_DUTY_QUERY_FIELD_PATHS]);
for (const key of PORTABLE_DUTY_QUERY_FIELD_PATHS)
    coreFields.add(`answer.${key}`);
for (const key of ["recognizedExtensions", "recognizedExtensions.version", "recognizedExtensions.rulesHash"])
    coreFields.add(`scope.${key}`);
for (const key of ["version", "kind", "epistemicStatus", "scope", "answer", "code", "evidence", "externalAssumptions"])
    coreFields.add(key);
for (const key of PORTABLE_QUERY_ANSWER_FIELD_PATHS)
    coreFields.add(`answer.${key}`);
for (const key of ["domain", "versions", "policyVersion", "rootRecognitionPolicy", "recognizedRootIds", "canonicalLineageId", "evaluationHead", "observedHead", "headRelationship", "freshness", "finality", "disclosure", "unavailableEvidence", "withheldEvidence", "externalAssumptions"])
    coreFields.add(`scope.${key}`);
for (const key of ["protocol", "version", "deploymentId", "chainId", "verifyingContract"])
    coreFields.add(`scope.domain.${key}`);
for (const key of Object.keys(VERSIONS))
    coreFields.add(`scope.versions.${key}`);
for (const head of ["evaluationHead", "observedHead"])
    for (const key of ["hash", "position", "canonicalTime"])
        coreFields.add(`scope.${head}.${key}`);
for (const prefix of ["scope.externalAssumptions", "externalAssumptions"])
    for (const key of Object.keys(PORTABLE_QUERY_EXTERNAL_ASSUMPTIONS))
        coreFields.add(`${prefix}.${key}`);
for (const key of ["mode", "includedFields", "withheldFields"])
    coreFields.add(`scope.disclosure.${key}`);
for (const prefix of ["scope.unavailableEvidence", "scope.withheldEvidence", "evidence"]) {
    for (const key of ["kind", "eventId", "eventType", "position", "historyHash", "authorityId", "grantEventId", "keyId", "sessionId", "admissionEventId", "receiptContentHash", "evidenceType", "reference", "attesterId"])
        coreFields.add(`${prefix}.${key}`);
}
const disclosureFor = (capture) => {
    if (!validateCapturedPortableQueryDisclosure(capture, capture.value.disclosure))
        return undefined;
    const value = capture.value.disclosure;
    if (value.withheldFields.some(path => coreFields.has(path)))
        return undefined;
    return value;
};
const evidenceOccurrences = (value) => {
    let count = 0;
    const visit = (current) => {
        if (count > 4096)
            return;
        if (Array.isArray(current)) {
            for (const child of current)
                visit(child);
        }
        else if (current !== null && typeof current === "object") {
            const record = current;
            if (typeof record.kind === "string" && ["EVENT", "AUTHORITY", "RUNTIME_CREDENTIAL", "RECEIPT_COMMITMENT", "EXTERNAL"].includes(record.kind))
                count += 1;
            for (const child of Object.values(record))
                visit(child);
        }
    };
    visit(value);
    return count;
};
const fits = (result) => {
    if (evidenceOccurrences(result) > 4096)
        return false;
    try {
        measureReferenceOutput(result);
        return true;
    }
    catch (error) {
        if (isReferenceOutputOverflow(error))
            return false;
        throw error;
    }
};
const query = (input, kind) => {
    const captured = capturePortableQueryInput(input, kind);
    if (captured.status !== "CAPTURED")
        return failure(kind, captured.status);
    const capture = captured.capture, value = capture.value;
    const observedEvents = value.observedEvents;
    const evaluationEvents = (value.evaluationEvents ?? observedEvents);
    // Both probes precede either branch's current-schema interpretation.
    const evaluationProbe = discover(evaluationEvents, capture), observedProbe = discover(observedEvents, capture);
    if (evaluationProbe === undefined || observedProbe === undefined)
        return failure(kind, "STATE_NOT_AUTHORITATIVE");
    const evaluationReplay = evaluationProbe.supported ? replay(evaluationEvents) : undefined;
    const observedReplay = observedProbe.supported ? replay(observedEvents) : undefined;
    if ((evaluationProbe.supported && evaluationReplay?.status !== "ACCEPTED") ||
        (observedProbe.supported && observedReplay?.status !== "ACCEPTED"))
        return failure(kind, "STATE_NOT_AUTHORITATIVE");
    if (!evaluationProbe.supported || !observedProbe.supported) {
        const evidence = queryEvidence(!evaluationProbe.supported ? [genesisReference(evaluationProbe.genesis)] : [], !observedProbe.supported ? [genesisReference(observedProbe.genesis)] : []);
        return failure(kind, "EVIDENCE_UNAVAILABLE", blankScope(evidence), evidence);
    }
    if (evaluationReplay?.status !== "ACCEPTED" || observedReplay?.status !== "ACCEPTED")
        return failure(kind, "STATE_NOT_AUTHORITATIVE");
    const evaluation = evaluationReplay.state, observed = observedReplay.state;
    const identity = identityFor(evaluation, observed);
    const earlyFailureScope = { ...blankScope(), ...compactIdentity(identity) };
    const relationship = observed.head.position === evaluation.head.position && observed.head.hash === evaluation.head.hash ? "SAME_HEAD" :
        observed.head.position > evaluation.head.position && observed.eventHistoryHashes[evaluation.head.position] === evaluation.head.hash ? "STRICT_EXTENSION" : "UNVERIFIED";
    const disclosure = disclosureFor(capture);
    const completeScope = { ...blankScope(), ...identity, disclosure: disclosure ?? EMPTY_DISCLOSURE };
    const time = value.evaluationTime;
    const causalEvidence = () => queryEvidence([queryEventReference(evaluation, evaluation.head.position), queryEventReference(observed, observed.head.position)]);
    if (typeof time !== "number" || !Number.isSafeInteger(time) || Object.is(time, -0) || time < evaluation.head.canonicalTime ||
        (kind === "SURVIVES" && relationship === "UNVERIFIED" && time < observed.head.canonicalTime)) {
        return failure(kind, "CAUSAL_TIME_INVALID", earlyFailureScope, causalEvidence());
    }
    let authorization;
    if (kind !== "SURVIVES") {
        authorization = authorizePortable({
            operationVersion: "continuity-authorization/0.2", events: evaluationEvents,
            expectedHistoryHead: evaluation.head, domain: value.authorizationDomain,
            policyVersion: evaluation.genesis.policyVersion, rootRecognitionPolicy: evaluation.genesis.rootRecognitionPolicy,
            request: value.request, evaluationTime: time, authoritative: true,
            consequential: value.consequentialBinding !== undefined,
            ...(value.consequentialBinding === undefined ? {} : { binding: value.consequentialBinding }),
        });
        if (authorization.decision === "INDETERMINATE" && authorization.code === "CAUSAL_TIME_INVALID") {
            return failure(kind, "CAUSAL_TIME_INVALID", earlyFailureScope, causalEvidence());
        }
        if (authorization.decision === "INDETERMINATE" && ["INVALID_INPUT", "UNSUPPORTED_VERSION", "STATE_NOT_AUTHORITATIVE"].includes(authorization.code)) {
            return failure(kind, authorization.code);
        }
    }
    if (disclosure === undefined)
        return failure(kind, "DISCLOSURE_INVALID", earlyFailureScope);
    const outputFailure = () => failure(kind, "OUTPUT_LIMIT_EXCEEDED", { ...blankScope(), ...compactIdentity(identity) });
    let result;
    if (relationship === "UNVERIFIED") {
        const conflict = findPortableQueryConflict(evaluation, observed, kind === "SURVIVES"
            ? { kind, targetAgentId: value.targetAgentId, evaluationTime: time }
            : { kind, ...(value.consequentialBinding === undefined ? {} : { binding: value.consequentialBinding }) });
        if (conflict !== undefined)
            result = failure(kind, "EVIDENCE_DISPUTED", completeScope, conflict);
        else {
            let position = 0;
            while (position < Math.min(evaluation.events.length, observed.events.length) && canonicalEncode(evaluation.events[position]) === canonicalEncode(observed.events[position]))
                position += 1;
            const evidence = position < Math.min(evaluation.events.length, observed.events.length)
                ? queryEvidence([queryEventReference(evaluation, position), queryEventReference(observed, position)])
                : causalEvidence();
            result = failure(kind, "HISTORY_RELATION_UNVERIFIED", completeScope, evidence);
        }
    }
    else if (authorization?.decision === "INDETERMINATE") {
        // Required Core proof/event dependencies are inline or replay-validated;
        // current engine has no standalone unavailable/disputed dependency branch.
        result = failure(kind, authorization.code === "EVIDENCE_DISPUTED" ? "HISTORY_RELATION_UNVERIFIED" : authorization.code, completeScope);
        if (authorization.code === "OUTPUT_LIMIT_EXCEEDED")
            return outputFailure();
    }
    else {
        let answer, includedFields, overflow = false;
        if (kind === "SURVIVES") {
            const projection = derivePortableSurvives(evaluation, value.targetAgentId, time);
            answer = projection.answer;
            includedFields = projection.includedFields;
            overflow = projection.outputLimitExceeded;
        }
        else if (kind === "RESPONSIBLE") {
            const projection = derivePortableResponsibility(evaluation, observed, authorization);
            answer = projection.answer;
            includedFields = projection.includedFields;
            overflow = projection.outputLimitExceeded;
        }
        else {
            answer = { authorization: authorization, presentConsequentialUse: authorization?.decision === "ALLOW" && authorization.consequential && relationship === "SAME_HEAD" };
            includedFields = answerFieldPaths(answer);
        }
        const selected = new Set(disclosure.includedFields);
        if (includedFields.some(path => !selected.has(path)))
            return failure(kind, "DISCLOSURE_INVALID", earlyFailureScope);
        if (overflow || answer === undefined)
            return outputFailure();
        result = { version: PORTABLE_QUERY_VERSION, kind, epistemicStatus: "ESTABLISHED",
            scope: { ...completeScope, headRelationship: relationship, freshness: relationship === "SAME_HEAD" ? "CURRENT" : "AT_EVALUATION" }, answer };
    }
    return identity.recognizedRootIds.length > 256 || !fits(result) ? outputFailure() : immutableProtocolValue(result);
};
export const whyPortable = (input) => query(input, "WHY");
export const responsiblePortable = (input) => query(input, "RESPONSIBLE");
export const survivesPortable = (input) => query(input, "SURVIVES");
