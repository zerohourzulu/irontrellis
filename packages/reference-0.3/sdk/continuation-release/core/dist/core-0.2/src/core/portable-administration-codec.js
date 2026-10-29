import { objectFreeze } from "./host-intrinsics.js";
/**
 * @internal Section 7.5 projection of an already captured, schema-validated event.
 * This is neither raw-input validation nor evidence of transition authority.
 * Nested values retain the accepted snapshot, including the entire creation record.
 */
export const portableAdministrativeTransitionEffect = (event) => {
    const data = event.data;
    switch (event.type) {
        case "OUTCOME_OBSERVATION_RECORDED":
            return objectFreeze({
                transitionEventType: event.type,
                intentId: data.intentId,
                sourceAdmissionEventId: data.sourceAdmissionEventId,
                acknowledgment: data.acknowledgment,
                actorId: data.actorId,
            });
        case "ATTEMPT_DUTY_CREATED":
            return objectFreeze({
                transitionEventType: event.type,
                record: data.record,
                actorId: data.actorId,
            });
        case "ATTEMPT_DUTY_REVIEW_CLOSED":
            return objectFreeze({ transitionEventType: event.type, dutyId: data.dutyId,
                actorId: data.actorId, observationEventIds: data.observationEventIds,
                summaryDigest: data.summaryDigest });
        case "ATTEMPT_DUTY_ASSIGNED":
            return objectFreeze({
                transitionEventType: event.type,
                dutyId: data.dutyId,
                fromAgentId: data.fromAgentId,
                toAgentId: data.toAgentId,
                actorId: data.actorId,
            });
        case "OBLIGATION_CREATED":
            return objectFreeze({
                transitionEventType: event.type,
                record: data.record,
                actorId: data.actorId,
            });
        case "OBLIGATION_PERFORMANCE_ASSIGNED":
            return objectFreeze({
                transitionEventType: event.type,
                obligationId: data.obligationId,
                fromAgentId: data.fromAgentId,
                toAgentId: data.toAgentId,
                successionRuleId: data.successionRuleId,
                actorId: data.actorId,
            });
        case "OBLIGATION_STATUS_RECORDED":
            return objectFreeze({
                transitionEventType: event.type,
                obligationId: data.obligationId,
                fromStatus: data.fromStatus,
                toStatus: data.toStatus,
                actorId: data.actorId,
                action: data.action,
                attesterId: data.attesterId,
                evidenceReference: data.evidenceReference,
            });
        default:
            throw new TypeError("Event is not a supported administrative obligation transition.");
    }
};
