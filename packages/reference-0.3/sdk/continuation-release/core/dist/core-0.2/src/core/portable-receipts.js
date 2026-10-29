/** Portable artifact verification and pure reference producer composition. */
import { canonicalEncode, captureBoundedCanonicalValue, captureBoundedCanonicalReplayBodyIncrementally, compareProtocolStrings, getCanonicalCaptureLimitErrorMetadata, hashCanonical, hashEventHistoryPrefixes, immutableProtocolInput, immutableProtocolValue, } from "./canonical.js";
import { isCoreEventType, validateCanonicalEventShape, validateCapturedPortableReceiptValue } from "./event-schema.js";
import { capturePortableReceiptInput } from "./portable-receipt-capture.js";
import { PORTABLE_RECEIPT_VERIFICATION_VERSION as VERIFY_VERSION, PORTABLE_RECEIPT_RECORD_ADMISSION_VERSION as RECORD_VERSION, PORTABLE_RECEIPT_LIMITATIONS, receiptRecordDataForArtifact, } from "./portable-receipt-codec.js";
import { evaluatePortableReceiptPolicy, recoverPortableContentHashSigner } from "./portable-authority-engine.js";
import { REMOTE_SERVICE_REPORT_ADAPTER_ID, LOCAL_DOCUMENT_RELEASE_ADAPTER_ID, SIMULATED_ADAPTER_ID, LOCAL_EVIDENCE_PACKET_ADAPTER_ID, LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID } from "./portable-adapter-engine.js";
import { createPortableReplayKernel, PORTABLE_REPLAY_VERSION, } from "./portable-replay.js";
const same = (a, b) => canonicalEncode(a) === canonicalEncode(b);
const sameHead = (a, b) => a.hash === b.hash && a.position === b.position && a.canonicalTime === b.canonicalTime;
const domainEqual = (a, b) => a.protocol === b.protocol && a.version === b.version && a.deploymentId === b.deploymentId &&
    a.chainId === b.chainId && a.verifyingContract.toLowerCase() === b.verifyingContract.toLowerCase();
const indeterminate = (code) => Object.freeze({ operationVersion: VERIFY_VERSION, status: "INDETERMINATE", code, limitations: PORTABLE_RECEIPT_LIMITATIONS });
const replayState = (events) => {
    const source = Object.freeze({ operationVersion: PORTABLE_REPLAY_VERSION, events });
    const kernel = createPortableReplayKernel();
    const capture = captureBoundedCanonicalReplayBodyIncrementally(events, source, kernel.visit);
    if (capture.status !== "CAPTURED")
        return Object.freeze({ status: "CAPTURE_FAILED" });
    return kernel.finish();
};
const unavailableVersion = (result) => result.status === "REJECTED" && result.result.status === "REJECTED" &&
    (result.result.code === "UNSUPPORTED_VERSION" || result.result.code === "UNSUPPORTED_EVENT_SCHEMA");
const sourceFor = (events, hashes) => Object.freeze({ events, hashes: hashes ?? hashEventHistoryPrefixes(events) });
const plan = (source, position) => position >= 0 && position < source.events.length ? [{ source, position }] : [];
const planKey = (item) => {
    const event = item.source.events[item.position];
    return canonicalEncode([event.id, event.type, item.position, item.source.hashes[item.position]]);
};
const union = (...groups) => {
    const unique = new Map();
    for (const group of groups)
        for (const item of group)
            unique.set(planKey(item), item);
    return [...unique.values()];
};
const bindHead = (source, items) => union(items, plan(source, source.events.length - 1));
const findPlan = (source, predicate) => plan(source, source.events.findIndex(predicate));
const controlEvidence = (source, state, issuer, time) => {
    const items = [];
    let latestEpoch = -1;
    let firstFailure = -1;
    for (let position = 0; position < source.events.length; position += 1) {
        const e = source.events[position], d = e.data;
        if (e.type === "AGENT_CREATED" && d.agentId === issuer.agentId) {
            items.push(...plan(source, position));
            latestEpoch = position;
        }
        if (e.type === "RUNTIME_SESSION_ADMITTED" && d.sessionId === issuer.runtimeSessionId)
            items.push(...plan(source, position));
        if (e.type === "ROLE_CREATED" && d.roleId === issuer.roleId)
            items.push(...plan(source, position));
        if ((e.type === "AGENT_APPOINTED" && d.roleTenureId === issuer.roleTenureId) ||
            (e.type === "ROLE_TRANSFERRED" && d.toRoleTenureId === issuer.roleTenureId))
            items.push(...plan(source, position));
        if (e.type === "CONTROL_EPOCH_ADVANCED" && d.agentId === issuer.agentId)
            latestEpoch = position;
        const failure = (e.type === "AGENT_TERMINATED" && d.agentId === issuer.agentId) ||
            (e.type === "CONTROL_EPOCH_ADVANCED" && d.agentId === issuer.agentId && typeof d.toEpoch === "number" && d.toEpoch > issuer.controlEpoch) ||
            (e.type === "AGENT_UNAPPOINTED" && d.roleTenureId === issuer.roleTenureId) ||
            (e.type === "ROLE_TRANSFERRED" && d.fromRoleTenureId === issuer.roleTenureId);
        if (failure && firstFailure < 0)
            firstFailure = position;
    }
    items.push(...plan(source, latestEpoch), ...plan(source, firstFailure));
    const session = state.runtimeSessions.get(issuer.runtimeSessionId);
    if (session?.expiresAt !== undefined && time >= session.expiresAt)
        items.push(...plan(source, session.admissionEventPosition));
    return bindHead(source, items);
};
const authorityEvidence = (source, state, proof, policy) => {
    const items = [];
    const records = state.authorities;
    for (const named of proof.authorityEvidence) {
        const record = records.get(named.authorityId);
        if (record !== undefined && record.grantEventId === named.grantEventId && record.grantEventPosition === named.grantEventPosition)
            items.push(...plan(source, record.grantEventPosition));
    }
    for (const id of new Set([...proof.checkedProhibitionIds, ...policy.checkedProhibitionIds])) {
        const record = records.get(id);
        if (record !== undefined) {
            items.push(...plan(source, record.grantEventPosition));
            if (record.grant.kind === "PROHIBITION" && record.revocationEventPosition !== undefined)
                items.push(...plan(source, record.revocationEventPosition));
        }
    }
    for (const id of policy.decisiveAuthorityIds) {
        const record = records.get(id);
        if (record !== undefined) {
            items.push(...plan(source, record.grantEventPosition));
            if (record.revocationEventPosition !== undefined)
                items.push(...plan(source, record.revocationEventPosition));
        }
    }
    for (const id of policy.decisiveAgentIds)
        items.push(...findPlan(source, event => event.type === "AGENT_TERMINATED" && event.data.agentId === id));
    return bindHead(source, items);
};
const intentEvidence = (source, intentId) => {
    const items = [];
    for (let position = 0; position < source.events.length; position += 1) {
        const event = source.events[position];
        if (["TRANSACTION_INTENT_DECLARED", "TRANSACTION_INTENT_ADMITTED", "TRANSACTION_INTENT_CONSUMED"].includes(event.type) && event.data.intentId === intentId)
            items.push(...plan(source, position));
    }
    return bindHead(source, items);
};
const materialize = (items) => {
    const refs = items.map(({ source, position }) => Object.freeze({
        kind: "EVENT", eventId: source.events[position].id,
        eventType: source.events[position].type, position, historyHash: source.hashes[position],
    }));
    refs.sort((a, b) => compareProtocolStrings(a.eventId, b.eventId) || compareProtocolStrings(a.eventType, b.eventType) ||
        a.position - b.position || compareProtocolStrings(a.historyHash, b.historyHash));
    return Object.freeze(refs);
};
const axis = (status, primaryCode, evidence = [], future = false) => Object.freeze({
    status, primaryCode,
    causes: Object.freeze(future ? [primaryCode, "FUTURE_ISSUANCE"] : [primaryCode]),
    evidence: materialize(evidence),
});
const policyAt = (state, proof, time) => evaluatePortableReceiptPolicy(state, proof, time);
const boundProof = (state, payload) => {
    const admitted = state.intentAdmissions.get(payload.intent.intentId);
    return admitted !== undefined && same(state.events[admitted.admissionEventPosition].data.authorizationProof, payload.authorization.proof);
};
const assuranceFor = (adapterId) => {
    switch (adapterId) {
        case SIMULATED_ADAPTER_ID: return "SIMULATED";
        case REMOTE_SERVICE_REPORT_ADAPTER_ID:
        case LOCAL_EVIDENCE_PACKET_ADAPTER_ID:
        case LOCAL_DOCUMENT_RELEASE_ADAPTER_ID:
        case LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID: return "NOT_PROVEN";
        default: return undefined;
    }
};
const intrinsicFieldsMatch = (payload) => {
    const p = payload.authorization.proof, i = payload.issuer, r = p.request;
    const projection = {
        intentId: p.intentId, nonce: p.nonce, actorId: r.actorId, action: r.action, resource: r.resource,
        roleId: p.roleId, roleTenureId: p.roleTenureId,
        adapterProfile: payload.result.acknowledgment.adapterProfile,
        ...(r.amount === undefined ? {} : { amount: r.amount }),
        ...(r.counterpartyId === undefined ? {} : { counterpartyId: r.counterpartyId }),
        ...(r.termsCommitment === undefined ? {} : { termsCommitment: r.termsCommitment }),
    };
    const ack = payload.result.acknowledgment;
    return same(payload.intent, projection) && same(ack.domain, payload.domain) && ack.intentId === payload.intent.intentId &&
        ack.adapterProfile.profileId === payload.result.adapterId &&
        assuranceFor(payload.result.adapterId) !== undefined && payload.assurance.externalOutcome === assuranceFor(payload.result.adapterId) &&
        payload.authorization.authorizationTime === p.evaluationTime &&
        payload.authorization.policyVersion === p.policyVersion && payload.authorization.rootRecognitionPolicy === p.rootRecognitionPolicy &&
        sameHead(payload.authorization.historyHead, p.historyHead) && i.agentId === r.actorId &&
        i.keyId === p.credentialKeyId && i.runtimeSessionId === p.runtimeSessionId && i.controlEpoch === p.controlEpoch &&
        i.roleId === p.roleId && i.roleTenureId === p.roleTenureId;
};
const canonicalFieldsMatch = (state, payload) => {
    const declaration = state.intentDeclarations.get(payload.intent.intentId);
    const session = state.runtimeSessions.get(payload.issuer.runtimeSessionId);
    const tenure = state.tenures.get(payload.issuer.roleTenureId);
    return (declaration === undefined || same(payload.intent, declaration.data)) &&
        (session === undefined || (session.agentId === payload.issuer.agentId && session.credentialKeyId === payload.issuer.keyId && session.controlEpoch === payload.issuer.controlEpoch)) &&
        (tenure === undefined || (tenure.agentId === payload.issuer.agentId && tenure.roleId === payload.issuer.roleId));
};
const submissionMatches = (state, payload) => {
    const consumption = state.intentConsumptions.get(payload.intent.intentId), r = payload.result;
    return consumption !== undefined && consumption.eventId === r.consumptionEventId && consumption.adapterId === r.adapterId &&
        consumption.idempotencyKey === r.idempotencyKey && consumption.submissionFingerprint === r.submissionFingerprint &&
        consumption.transactionReference === r.transactionReference && same(consumption.acknowledgment, r.acknowledgment);
};
const currentControl = (state, payload, time) => {
    const issuer = payload.issuer, agent = state.agents.get(issuer.agentId);
    const session = state.runtimeSessions.get(issuer.runtimeSessionId);
    const role = state.roles.get(issuer.roleId), tenure = state.tenures.get(issuer.roleTenureId);
    // Freshness evaluates the artifact's actual issuer against this state. The
    // historical axis separately checks congruence with the admitted proof.
    return agent !== undefined && !agent.terminated && agent.currentControlEpoch === issuer.controlEpoch &&
        session !== undefined && session.agentId === issuer.agentId && session.credentialKeyId === issuer.keyId &&
        session.controlEpoch === issuer.controlEpoch && (session.expiresAt === undefined || time < session.expiresAt) &&
        role !== undefined && role.currentTenureId === issuer.roleTenureId &&
        tenure !== undefined && !tenure.closed && tenure.roleId === issuer.roleId && tenure.agentId === issuer.agentId &&
        payload.authorization.proof.request.actorId === issuer.agentId &&
        state.genesis.policyVersion === payload.authorization.policyVersion &&
        state.genesis.rootRecognitionPolicy === payload.authorization.rootRecognitionPolicy;
};
/** Exact Section8.3/8.4 operation. Every independently checkable axis is retained. */
export const verifyPortableReceipt = (input) => {
    const captured = capturePortableReceiptInput(input, "VERIFY");
    if (captured.status === "UNSUPPORTED_OPERATION")
        return indeterminate("UNSUPPORTED_RECEIPT_VERSION");
    if (captured.status === "MALFORMED_ARTIFACT")
        return indeterminate("MALFORMED_ARTIFACT");
    if (captured.status !== "CAPTURED")
        return indeterminate("INVALID_INPUT");
    const value = captured.capture.value;
    const artifactStatus = validateCapturedPortableReceiptValue(captured.capture, "ARTIFACT", value.artifact);
    if (artifactStatus === "LIMIT")
        return indeterminate("INVALID_INPUT");
    if (artifactStatus === "UNSUPPORTED")
        return indeterminate("UNSUPPORTED_RECEIPT_VERSION");
    if (artifactStatus !== "VALID")
        return indeterminate("MALFORMED_ARTIFACT");
    const artifact = value.artifact, payload = artifact.payload;
    const issuance = value.issuanceEvents, observed = value.observedEvents;
    const expectedDomain = value.expectedDomain, time = value.verifierTime;
    // Discover both genesis interpreters before either supported-schema replay.
    const issuanceVersion = replayState(issuance.slice(0, 1)), observedVersion = replayState(observed.slice(0, 1));
    if (unavailableVersion(issuanceVersion) || unavailableVersion(observedVersion))
        return indeterminate("UNSUPPORTED_VERSION");
    const p = payload.issuance.historyHead.position;
    const prefix = issuance.slice(0, Math.min(p + 1, issuance.length));
    const historicalReplay = replayState(prefix), currentReplay = replayState(observed);
    if (historicalReplay.status !== "ACCEPTED" || currentReplay.status !== "ACCEPTED")
        return indeterminate("STATE_NOT_AUTHORITATIVE");
    // The optional base-captured candidate is relationship evidence only. Its
    // content never enters the signed prefix's schema or transition predicates.
    // It must still name a supported envelope type before a closed EVENT
    // reference can describe it; no payload or transition is replayed here.
    if (issuance.length > p + 1 && !isCoreEventType(issuance[p + 1].type))
        return indeterminate("STATE_NOT_AUTHORITATIVE");
    const old = historicalReplay.state, current = currentReplay.state;
    const related = (issuance.length === p + 1 || issuance.length === p + 2) && p < issuance.length && sameHead(payload.issuance.historyHead, old.head);
    let divergentPosition = -1;
    const requiredAvailable = Math.min(p + 1, issuance.length);
    for (let index = 0; index < requiredAvailable; index += 1) {
        if (observed[index] === undefined || !same(issuance[index], observed[index])) {
            divergentPosition = index;
            break;
        }
    }
    if (divergentPosition < 0 && issuance.length > p + 1 && observed.length > p + 1 && !same(issuance[p + 1], observed[p + 1]))
        divergentPosition = p + 1;
    const divergent = divergentPosition >= 0;
    const oldSource = sourceFor(old.events, old.eventHistoryHashes), currentSource = sourceFor(current.events, current.eventHistoryHashes);
    const issuanceSource = issuance.length === old.events.length ? oldSource : sourceFor(issuance);
    const domainPlans = union(plan(issuanceSource, 0), plan(currentSource, 0));
    const domainMismatch = !same(payload.domain, payload.authorization.proof.domain) || !domainEqual(payload.domain, expectedDomain) ||
        !domainEqual(payload.domain, old.genesis.domain) || !domainEqual(payload.domain, current.genesis.domain) ||
        !domainEqual(payload.authorization.proof.domain, expectedDomain);
    const integrity = hashCanonical(payload) === artifact.contentHash;
    const recovered = recoverPortableContentHashSigner(artifact.contentHash, artifact.signature);
    const session = old.runtimeSessions.get(payload.issuer.runtimeSessionId);
    const credentialMissing = session === undefined;
    const issuerMatches = recovered !== undefined && session !== undefined && session.agentId === payload.issuer.agentId &&
        session.credentialKeyId === payload.issuer.keyId && session.credentialAddressKey === recovered;
    const fieldsMatch = intrinsicFieldsMatch(payload) && (!related || canonicalFieldsMatch(old, payload));
    const submission = !related || submissionMatches(old, payload);
    const proofMissing = related && (old.intentDeclarations.get(payload.intent.intentId) === undefined || old.intentAdmissions.get(payload.intent.intentId) === undefined);
    const admittedProofMatches = boundProof(old, payload);
    const oldPolicy = policyAt(old, payload.authorization.proof, payload.issuance.issuedAt);
    const newPolicy = policyAt(current, payload.authorization.proof, time);
    const historicalLive = related && payload.issuance.issuedAt >= old.head.canonicalTime && admittedProofMatches &&
        currentControl(old, payload, payload.issuance.issuedAt) && oldPolicy.live;
    const newLive = currentControl(current, payload, time) && newPolicy.live;
    const occupant = observed[p + 1];
    const recordMatches = occupant !== undefined && occupant.type === "RECEIPT_RECORDED" &&
        occupant.timestamp === payload.issuance.issuedAt && same(occupant.data, receiptRecordDataForArtifact(artifact));
    const relationshipPlans = union(occupant === undefined ? plan(oldSource, oldSource.events.length - 1) : plan(currentSource, p + 1), divergent ? plan(issuanceSource, divergentPosition) : [], divergent ? plan(currentSource, divergentPosition) : []);
    const issuerPlans = domainMismatch ? domainPlans : union(domainPlans, controlEvidence(oldSource, old, payload.issuer, payload.issuance.issuedAt));
    const historicalPlans = domainMismatch ? domainPlans : union(issuerPlans, authorityEvidence(oldSource, old, payload.authorization.proof, oldPolicy), intentEvidence(oldSource, payload.intent.intentId));
    const inclusionPlans = domainMismatch ? domainPlans : relationshipPlans;
    const freshnessPlans = domainMismatch ? domainPlans : union(relationshipPlans, controlEvidence(currentSource, current, payload.issuer, time), authorityEvidence(currentSource, current, payload.authorization.proof, newPolicy));
    if (issuerPlans.length + historicalPlans.length + inclusionPlans.length + freshnessPlans.length > 4_096)
        return indeterminate("OUTPUT_LIMIT_EXCEEDED");
    const issuerAxis = domainMismatch ? axis("FAIL", "DOMAIN_MISMATCH", issuerPlans)
        : !related ? axis("UNVERIFIED", "ISSUANCE_HISTORY_UNVERIFIED", issuerPlans)
            : credentialMissing ? axis("UNVERIFIED", "DEPENDENCY_UNAVAILABLE", issuerPlans)
                : !issuerMatches ? axis("FAIL", "ISSUER_NOT_AUTHENTICATED", issuerPlans)
                    : axis("PASS", "ISSUER_AUTHENTICATED", issuerPlans);
    const historicalAxis = domainMismatch ? axis("FAIL", "DOMAIN_MISMATCH", historicalPlans)
        : !fieldsMatch ? axis("FAIL", "RECEIPT_FIELDS_MISMATCH", historicalPlans)
            : !submission ? axis("FAIL", "SUBMISSION_EVIDENCE_MISSING", historicalPlans)
                : !integrity ? axis("FAIL", "DEPENDENCY_FAILED", historicalPlans)
                    // An available admission can contradict this proof even when the claimed
                    // credential is absent; that established contradiction remains definitive.
                    : related && !proofMissing && (!admittedProofMatches || ((!historicalLive || issuerAxis.status === "FAIL") && !credentialMissing))
                        ? axis("FAIL", "HISTORICAL_AUTHORIZATION_INVALID", historicalPlans)
                        : !related ? axis("UNVERIFIED", "ISSUANCE_HISTORY_UNVERIFIED", historicalPlans)
                            : proofMissing || credentialMissing ? axis("UNVERIFIED", "DEPENDENCY_UNAVAILABLE", historicalPlans)
                                : axis("PASS", "HISTORICAL_AUTHORIZATION_VALID", historicalPlans);
    const inclusionAxis = domainMismatch ? axis("FAIL", "DOMAIN_MISMATCH", inclusionPlans)
        : divergent ? axis("UNVERIFIED", "OBSERVED_HISTORY_DIVERGES", inclusionPlans)
            : !related ? axis("UNVERIFIED", "ISSUANCE_HISTORY_UNVERIFIED", inclusionPlans)
                : occupant !== undefined && !recordMatches ? axis("FAIL", "RECORDED_POSITION_MISMATCH", inclusionPlans)
                    : occupant === undefined ? axis("UNAVAILABLE", "RECORD_NOT_AVAILABLE", inclusionPlans)
                        : axis("PASS", "RECORDED_HASH_MATCH", inclusionPlans);
    const freshnessAxis = domainMismatch ? axis("UNVERIFIED", "DOMAIN_MISMATCH", freshnessPlans)
        : divergent ? axis("UNVERIFIED", "OBSERVED_HISTORY_DIVERGES", freshnessPlans)
            : !related ? axis("UNVERIFIED", "ISSUANCE_HISTORY_UNVERIFIED", freshnessPlans)
                : time < current.head.canonicalTime ? axis("UNVERIFIED", "VERIFIER_TIME_BEHIND_OBSERVED_HEAD", freshnessPlans, payload.issuance.issuedAt > time)
                    : payload.issuance.issuedAt > time ? axis("FAIL", "FUTURE_ISSUANCE", freshnessPlans)
                        : !newLive ? axis("FAIL", "STALE", freshnessPlans) : axis("PASS", "CURRENT", freshnessPlans);
    const authentic = integrity && recovered !== undefined && issuerAxis.status === "PASS";
    const historical = authentic && historicalAxis.status === "PASS";
    const result = {
        operationVersion: VERIFY_VERSION, status: "EVALUATED",
        contentIntegrity: axis(integrity ? "PASS" : "FAIL", integrity ? "CONTENT_HASH_MATCH" : "CONTENT_HASH_MISMATCH"),
        signaturePossession: axis(recovered === undefined ? "FAIL" : "PASS", recovered === undefined ? "SIGNATURE_INVALID" : "SIGNATURE_VALID"),
        issuerAuthentication: issuerAxis, historicalAuthorization: historicalAxis, canonicalInclusion: inclusionAxis,
        finality: axis("PASS", "LOCAL_ONLY"), freshness: freshnessAxis,
        externalOutcome: axis("UNVERIFIED", payload.assurance.externalOutcome === "SIMULATED" ? "SIMULATED" : "NOT_PROVEN"),
        authentic, historical, valid: historical,
        current: historical && inclusionAxis.status === "PASS" && freshnessAxis.status === "PASS",
        limitations: inclusionAxis.status === "PASS" ? PORTABLE_RECEIPT_LIMITATIONS.slice(1) : PORTABLE_RECEIPT_LIMITATIONS,
    };
    try {
        return captureBoundedCanonicalValue(result).value;
    }
    catch (error) {
        if (getCanonicalCaptureLimitErrorMetadata(error) !== undefined)
            return indeterminate("OUTPUT_LIMIT_EXCEEDED");
        throw error;
    }
};
const recordIndeterminate = (code, verification) => Object.freeze({ operationVersion: RECORD_VERSION, status: "INDETERMINATE", code, ...(verification === undefined ? {} : { verification }) });
const mapVerificationCode = (code) => code === "MALFORMED_ARTIFACT" ? "INVALID_INPUT" : code === "UNSUPPORTED_RECEIPT_VERSION" ? "UNSUPPORTED_VERSION" : code;
/** Pure prospective Section8.5 composition; PROPOSED never claims persistence. */
export const proposePortableReceiptRecord = (input) => {
    const captured = capturePortableReceiptInput(input, "RECORD");
    if (captured.status === "UNSUPPORTED_OPERATION")
        return recordIndeterminate("UNSUPPORTED_VERSION");
    if (captured.status !== "CAPTURED")
        return recordIndeterminate("INVALID_INPUT");
    const value = captured.capture.value, events = value.events;
    const replay = replayState(events);
    if (unavailableVersion(replay))
        return recordIndeterminate("UNSUPPORTED_VERSION");
    if (replay.status !== "ACCEPTED")
        return recordIndeterminate("STATE_NOT_AUTHORITATIVE");
    const expectedHead = value.expectedHistoryHead;
    if (!sameHead(replay.state.head, expectedHead))
        return Object.freeze({ operationVersion: RECORD_VERSION, status: "CONFLICT", expectedHead, observedHead: replay.state.head });
    if (events.some(event => event.id === value.recordEventId))
        return recordIndeterminate("INVALID_INPUT");
    const artifactStatus = validateCapturedPortableReceiptValue(captured.capture, "ARTIFACT", value.artifact);
    if (artifactStatus === "UNSUPPORTED")
        return recordIndeterminate("UNSUPPORTED_VERSION");
    if (artifactStatus !== "VALID")
        return recordIndeterminate("INVALID_INPUT");
    const artifact = value.artifact;
    if (events.length >= 4_096 || (events.length + 1) * 2 > 4_096)
        return recordIndeterminate("OUTPUT_LIMIT_EXCEEDED");
    const recordEvent = Object.freeze({ id: value.recordEventId, type: "RECEIPT_RECORDED",
        timestamp: artifact.payload.issuance.issuedAt, data: receiptRecordDataForArtifact(artifact) });
    const prospective = Object.freeze([...events, recordEvent]);
    const verificationInput = Object.freeze({ operationVersion: VERIFY_VERSION, artifact,
        issuanceEvents: prospective, observedEvents: prospective,
        expectedDomain: value.expectedDomain, verifierTime: artifact.payload.issuance.issuedAt });
    try {
        captureBoundedCanonicalValue(recordEvent);
        if (!validateCanonicalEventShape(recordEvent).ok)
            return recordIndeterminate("INVALID_INPUT");
        captureBoundedCanonicalValue(prospective);
        captureBoundedCanonicalValue({ operationVersion: PORTABLE_REPLAY_VERSION, events: prospective });
        const construction = capturePortableReceiptInput(verificationInput, "VERIFY");
        if (construction.status === "INVALID_INPUT" && construction.limitExceeded)
            return recordIndeterminate("OUTPUT_LIMIT_EXCEEDED");
        if (construction.status !== "CAPTURED")
            return recordIndeterminate("INVALID_INPUT");
    }
    catch (error) {
        if (getCanonicalCaptureLimitErrorMetadata(error) !== undefined)
            return recordIndeterminate("OUTPUT_LIMIT_EXCEEDED");
        throw error;
    }
    const verification = verifyPortableReceipt(verificationInput);
    if (verification.status === "INDETERMINATE")
        return recordIndeterminate(mapVerificationCode(verification.code), verification);
    if (!verification.current) {
        try {
            return captureBoundedCanonicalValue({ operationVersion: RECORD_VERSION, status: "REJECTED", verification }).value;
        }
        catch (error) {
            if (getCanonicalCaptureLimitErrorMetadata(error) !== undefined)
                return recordIndeterminate("OUTPUT_LIMIT_EXCEEDED");
            throw error;
        }
    }
    const finalReplay = replayState(prospective);
    if (finalReplay.status !== "ACCEPTED")
        return recordIndeterminate("STATE_NOT_AUTHORITATIVE");
    try {
        // Bound the actual portable winner wrapper before an SDK can append.
        captureBoundedCanonicalValue({ operationVersion: RECORD_VERSION, status: "ADMITTED", recordEvent, newHead: finalReplay.state.head, verification });
        return captureBoundedCanonicalValue({ operationVersion: RECORD_VERSION, status: "PROPOSED",
            expectedHead, recordEvent, newHead: finalReplay.state.head, verification }).value;
    }
    catch (error) {
        if (getCanonicalCaptureLimitErrorMetadata(error) !== undefined)
            return recordIndeterminate("OUTPUT_LIMIT_EXCEEDED");
        throw error;
    }
};
/** Configured local signing helper; a returned artifact is not a record witness. */
export const createPortableReceipt = async (input, signer) => {
    const stable = immutableProtocolInput(input);
    const keys = Object.keys(stable);
    if (!keys.every(key => ["events", "intentId", "issuedAt", "externalOutcome"].includes(key)) ||
        !["events", "intentId", "issuedAt", "externalOutcome"].every(key => Object.hasOwn(stable, key)) ||
        typeof stable.intentId !== "string" || !Number.isSafeInteger(stable.issuedAt) || stable.issuedAt < 0 || Object.is(stable.issuedAt, -0) ||
        (stable.externalOutcome !== "NOT_PROVEN" && stable.externalOutcome !== "SIMULATED"))
        throw new TypeError("Malformed local receipt creation input.");
    const replay = replayState(stable.events);
    if (replay.status !== "ACCEPTED" || stable.issuedAt < replay.state.head.canonicalTime)
        throw new TypeError("Receipt issuance requires a causally valid accepted prefix.");
    const state = replay.state, admission = state.intentAdmissions.get(stable.intentId), consumption = state.intentConsumptions.get(stable.intentId);
    const declaration = state.intentDeclarations.get(stable.intentId);
    if (admission === undefined || consumption === undefined || declaration === undefined)
        throw new TypeError("Receipt issuance requires exact admitted and consumed intent evidence.");
    if (stable.externalOutcome !== assuranceFor(consumption.adapterId))
        throw new TypeError("Receipt assurance must match the admitted adapter profile.");
    const proof = state.events[admission.admissionEventPosition].data.authorizationProof;
    const payload = immutableProtocolValue({
        schemaVersion: "continuity-receipt/0.2", signatureScheme: "eip191-personal-sign-keccak256", domain: proof.domain,
        issuer: { keyId: admission.credentialKeyId, agentId: admission.actorId, runtimeSessionId: admission.runtimeSessionId,
            controlEpoch: admission.controlEpoch, roleId: admission.roleId, roleTenureId: admission.roleTenureId },
        intent: declaration.data,
        authorization: { authorizationTime: proof.evaluationTime, policyVersion: proof.policyVersion,
            rootRecognitionPolicy: proof.rootRecognitionPolicy, historyHead: proof.historyHead, proof },
        issuance: { historyHead: state.head, issuedAt: stable.issuedAt },
        result: { status: "SUBMITTED", consumptionEventId: consumption.eventId, adapterId: consumption.adapterId,
            idempotencyKey: consumption.idempotencyKey, submissionFingerprint: consumption.submissionFingerprint,
            transactionReference: consumption.transactionReference, acknowledgment: consumption.acknowledgment },
        assurance: { finality: "LOCAL_ONLY", freshness: "CURRENT_AT_ISSUANCE",
            externalOutcome: stable.externalOutcome },
    });
    if (!currentControl(state, payload, stable.issuedAt) || !policyAt(state, proof, stable.issuedAt).live ||
        signer.keyId !== admission.credentialKeyId || typeof signer.signHash !== "function")
        throw new TypeError("Receipt signer or issuance authority is not current.");
    const contentHash = hashCanonical(payload);
    const signature = await signer.signHash(contentHash);
    const artifact = immutableProtocolInput({ payload, contentHash, signature });
    const verification = verifyPortableReceipt({ operationVersion: VERIFY_VERSION, artifact, issuanceEvents: state.events,
        observedEvents: state.events, expectedDomain: proof.domain, verifierTime: stable.issuedAt });
    if (verification.status !== "EVALUATED" || !verification.historical)
        throw new TypeError("Signer did not return a valid historically authorized receipt artifact.");
    return immutableProtocolValue(artifact);
};
