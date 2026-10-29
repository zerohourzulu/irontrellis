import { inspectPortableDutyPolicy } from "./duty-policy.js";
/** Internal Contract 9.4 projection. The coordinator supplies replayed heads and recomputed authorization. */
import { canonicalEncode, compareProtocolStrings, hashCanonical } from "./canonical.js";
import { PORTABLE_RESPONSIBILITY_KINDS, } from "./portable-query-codec.js";
import { createPortableQueryEvidenceCache, createPortableQueryProjectionWriter, requirePortableQueryProjection } from "./portable-query-output.js";
const data = (event) => event.data;
function invariant(condition) {
    if (!condition)
        throw new TypeError("Inconsistent internal responsibility projection inputs.");
}
;
export const derivePortableResponsibility = (evaluationState, observedState, authorization) => {
    invariant(authorization.scopeAssurance === "REPLAY_VERIFIED" &&
        authorization.operationVersion === "continuity-authorization/0.2" &&
        observedState.head.position >= evaluationState.head.position &&
        observedState.eventHistoryHashes[evaluationState.head.position] === evaluationState.head.hash);
    const writer = createPortableQueryProjectionWriter({
        authorizationDecision: authorization.decision, attributions: [],
        ...(observedState.attemptDutyPolicies.size > 0 ? { attemptDuties: [] } : {}),
    });
    if (authorization.decision === "DENY")
        return writer.finish(() => { });
    const cache = createPortableQueryEvidenceCache();
    const eventReference = cache.event;
    const receiptReference = cache.receipt;
    const eventFor = (state, match) => {
        const position = state.events.findIndex(match);
        invariant(position >= 0);
        return eventReference(state, position);
    };
    const tenureOpening = (state, tenureId) => eventFor(state, e => (e.type === "AGENT_APPOINTED" && data(e).roleTenureId === tenureId) ||
        (e.type === "ROLE_TRANSFERRED" && data(e).toRoleTenureId === tenureId));
    const proof = authorization.proof;
    invariant(canonicalEncode(proof.historyHead) === canonicalEncode(evaluationState.head) &&
        proof.consequential === authorization.consequential);
    const finalEvent = eventReference(evaluationState, evaluationState.head.position);
    const add = (kind, subjectId, temporalBasis, evidence) => {
        invariant(evidence.length > 0);
        const key = canonicalEncode([kind, subjectId, temporalBasis]);
        writer.row("attributions", key, { kind, subjectId, temporalBasis }, evidence);
    };
    const action = (kind, subjectId, evidence) => add(kind, subjectId, "ACTION_PREFIX", evidence);
    const later = (kind, subjectId, evidence) => add(kind, subjectId, "LATER_CAUSAL_STATE", evidence);
    const agent = evaluationState.agents.get(proof.request.actorId);
    invariant(agent !== undefined);
    const agentCreation = eventFor(evaluationState, e => e.type === "AGENT_CREATED" && data(e).agentId === agent.id);
    const principalCreation = eventFor(evaluationState, e => e.type === "PRINCIPAL_CREATED" && data(e).principalId === agent.principalId);
    action("ACTOR", agent.id, [agentCreation, finalEvent]);
    action("DECLARED_PRINCIPAL", agent.principalId, proof.consequential ? [principalCreation, agentCreation] : [principalCreation, agentCreation, finalEvent]);
    for (const selection of [{ recognizedRoot: proof.recognizedRoot, path: proof.permissionPath }, ...proof.intersections]) {
        const root = evaluationState.recognizedRoots.get(selection.recognizedRoot.rootAuthorityId);
        invariant(root !== undefined && canonicalEncode(root) === canonicalEncode(selection.recognizedRoot));
        const principal = evaluationState.principals.get(root.principalId);
        invariant(principal !== undefined);
        const rootPrincipal = eventReference(evaluationState, principal.creationEventPosition);
        const grants = [];
        for (const grant of selection.path) {
            const stored = evaluationState.authorities.get(grant.authorityId);
            invariant(stored !== undefined && canonicalEncode(stored.grant) === canonicalEncode(grant));
            grants.push(eventReference(evaluationState, stored.grantEventPosition));
        }
        const rootGrant = eventFor(evaluationState, e => e.id === root.rootGrantEventId);
        action("MANDATOR", root.principalId, [rootPrincipal, rootGrant, finalEvent]);
        action("AUTHORITY_SOURCE", root.rootAuthorityId, proof.consequential ? [rootPrincipal, ...grants] : [rootPrincipal, ...grants, finalEvent]);
    }
    if (!proof.consequential) {
        action("CONTROLLER", agent.controllerId, [agentCreation, finalEvent]);
    }
    else {
        invariant(proof.runtimeSessionId !== undefined && proof.controlEpoch !== undefined && proof.roleId !== undefined &&
            proof.roleTenureId !== undefined && proof.intentId !== undefined);
        const session = evaluationState.runtimeSessions.get(proof.runtimeSessionId);
        const tenure = evaluationState.tenures.get(proof.roleTenureId);
        const intent = evaluationState.intentDeclarations.get(proof.intentId)?.data;
        invariant(session !== undefined && session.agentId === agent.id && session.controllerId === agent.controllerId &&
            session.controlEpoch === proof.controlEpoch && session.credentialKeyId === proof.credentialKeyId &&
            agent.currentControlEpoch === proof.controlEpoch && tenure !== undefined && tenure.agentId === agent.id &&
            tenure.roleId === proof.roleId && !tenure.closed && intent !== undefined && intent.actorId === agent.id &&
            intent.roleId === proof.roleId && intent.roleTenureId === proof.roleTenureId && intent.nonce === proof.nonce);
        const declaration = eventFor(evaluationState, e => e.type === "TRANSACTION_INTENT_DECLARED" && data(e).intentId === proof.intentId);
        const sessionAdmission = eventReference(evaluationState, session.admissionEventPosition);
        const advances = [];
        for (let position = 0; position < evaluationState.events.length; position += 1) {
            const event = evaluationState.events[position];
            if (event.type === "CONTROL_EPOCH_ADVANCED" && data(event).agentId === agent.id &&
                data(event).toEpoch <= proof.controlEpoch)
                advances.push(eventReference(evaluationState, position));
        }
        const roleCreation = eventFor(evaluationState, e => e.type === "ROLE_CREATED" && data(e).roleId === proof.roleId);
        const opening = tenureOpening(evaluationState, proof.roleTenureId);
        action("ACTOR", agent.id, [declaration]);
        action("RUNTIME_SESSION", session.id, [sessionAdmission, advances.at(-1) ?? agentCreation, finalEvent]);
        action("ROLE", proof.roleId, [roleCreation, opening, finalEvent]);
        action("CONTROLLER", agent.controllerId, [agentCreation, sessionAdmission, ...advances, finalEvent]);
        if (intent.counterpartyId !== undefined)
            action("COUNTERPARTY", intent.counterpartyId, [declaration, finalEvent]);
        // Absence or a different admitted proof has no later causal attribution.
        const admission = observedState.intentAdmissions.get(proof.intentId);
        if (admission !== undefined) {
            const admissionEvent = observedState.events[admission.admissionEventPosition];
            if (canonicalEncode(data(admissionEvent).authorizationProof) === canonicalEncode(proof)) {
                const proofHash = hashCanonical(proof);
                for (const [dutyId, duty] of observedState.attemptDuties) {
                    const record = duty.record, currentView = inspectPortableDutyPolicy(observedState, dutyId);
                    if (!currentView || record.sourceIntentId !== proof.intentId || record.sourceAdmissionEventId !== admission.admissionEventId)
                        continue;
                    writer.row("attemptDuties", dutyId, { dutyId, sourceIntentId: record.sourceIntentId,
                        sourceAdmissionEventId: record.sourceAdmissionEventId, originalActorId: agent.id,
                        durableRoleId: record.durableRoleId, creationActorId: duty.creationActorId,
                        initialAssigneeId: record.performanceAssigneeId, currentAssigneeId: duty.currentAssigneeId,
                        deadline: record.deadline, currentView, externalOutcome: "NOT_PROVEN" }, [
                        eventReference(observedState, admission.admissionEventPosition), eventReference(observedState, duty.creationEventPosition),
                        eventReference(observedState, currentView.policy.eventPosition),
                        ...duty.assignments.map(item => eventReference(observedState, item.eventPosition)),
                    ]);
                }
                for (const obligation of observedState.obligations.values()) {
                    const record = obligation.record;
                    if (record.sourceIntentId !== proof.intentId)
                        continue;
                    const receipt = observedState.receiptCommitments.get(record.causalReceiptContentHash);
                    invariant(receipt !== undefined && receipt.intentId === proof.intentId && receipt.authorizationProofHash === proofHash &&
                        receipt.issuerAgentId === agent.id && receipt.runtimeSessionId === proof.runtimeSessionId && receipt.controlEpoch === proof.controlEpoch &&
                        receipt.roleId === proof.roleId && receipt.roleTenureId === proof.roleTenureId && record.durableRoleId === proof.roleId &&
                        record.creationRoleTenureId === proof.roleTenureId && admission.admissionEventPosition < receipt.eventPosition &&
                        receipt.eventPosition < obligation.creationEventPosition);
                    const chain = [eventReference(observedState, admission.admissionEventPosition),
                        receiptReference(receipt), roleCreation, opening, eventReference(observedState, obligation.creationEventPosition)];
                    const statusEvidence = [];
                    const performerEvidence = new Map();
                    let performer = record.performanceAssigneeId;
                    performerEvidence.set(performer, [...chain]);
                    for (let position = obligation.creationEventPosition + 1; position < observedState.events.length; position += 1) {
                        const event = observedState.events[position], eventData = data(event);
                        if (eventData.obligationId !== record.obligationId)
                            continue;
                        const reference = eventReference(observedState, position);
                        if (event.type === "OBLIGATION_PERFORMANCE_ASSIGNED") {
                            invariant(eventData.fromAgentId === performer);
                            performerEvidence.get(performer).push(reference);
                            performer = eventData.toAgentId;
                            if (!performerEvidence.has(performer))
                                performerEvidence.set(performer, [...chain]);
                            performerEvidence.get(performer).push(reference);
                        }
                        else if (event.type === "OBLIGATION_STATUS_RECORDED") {
                            statusEvidence.push(reference);
                            performerEvidence.get(performer).push(reference);
                        }
                    }
                    invariant(performer === obligation.performanceAssigneeId);
                    later("DURABLE_OBLIGOR", record.durableRoleId, [...chain, ...statusEvidence]);
                    later("BENEFICIARY", record.beneficiaryId, [...chain, ...statusEvidence]);
                    if (record.counterpartyId !== undefined)
                        later("COUNTERPARTY", record.counterpartyId, [...chain, ...statusEvidence]);
                    for (const [subject, evidence] of performerEvidence)
                        later("PERFORMANCE_ASSIGNEE", subject, evidence);
                }
            }
        }
    }
    return writer.finish(answer => {
        answer.attemptDuties?.sort((a, b) => compareProtocolStrings(a.dutyId, b.dutyId));
        answer.attributions.sort((a, b) => PORTABLE_RESPONSIBILITY_KINDS.indexOf(a.kind) - PORTABLE_RESPONSIBILITY_KINDS.indexOf(b.kind) ||
            compareProtocolStrings(a.subjectId, b.subjectId) || (a.temporalBasis === b.temporalBasis ? 0 : a.temporalBasis === "ACTION_PREFIX" ? -1 : 1));
    });
};
export const projectPortableResponsibility = (evaluationState, observedState, authorization) => requirePortableQueryProjection(derivePortableResponsibility(evaluationState, observedState, authorization));
