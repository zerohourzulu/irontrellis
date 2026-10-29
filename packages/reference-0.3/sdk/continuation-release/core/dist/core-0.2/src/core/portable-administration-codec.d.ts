import type { ContentHash } from "./canonical.ts";
import type { AcceptedCanonicalEventShape } from "./event-schema.ts";
import type { PortableActionRequest, PortableAuthorizationProof } from "./portable-authority-engine.ts";
import type { PortableAuthorizationDomain, PortableReplayEvidenceReference } from "./portable-replay.ts";
import type { RemoteServiceReportAcknowledgment } from "./portable-adapter-engine.ts";
export type PortableObligationStatus = "OPEN" | "OUTCOME_UNKNOWN" | "DISPUTED" | "DISCHARGED" | "IMPOSSIBLE_OR_ESCALATED";
export type PortableObligationTransitionPolicy = Readonly<{
    fromStatus: PortableObligationStatus;
    toStatus: PortableObligationStatus;
    acceptedAttesterIds: readonly string[];
    action: string;
    requiredAuthorityIds: readonly string[];
}>;
/** Immutable creation record; subsequent status and assignee are separate replay state. */
export type PortableObligationRecord = Readonly<{
    obligationId: string;
    sourceIntentId: string;
    causalReceiptContentHash: ContentHash;
    durableRoleId: string;
    creationRoleTenureId: string;
    description: string;
    trigger: string;
    deadline: number;
    status: "OPEN" | "OUTCOME_UNKNOWN";
    beneficiaryId: string;
    counterpartyId?: string;
    termsCommitment: ContentHash;
    performanceAssigneeId: string;
    successionRuleId: string;
    transitionPolicies: readonly PortableObligationTransitionPolicy[];
}>;
/** Immutable E5 attempt-duty creation facts; subsequent assignment is separate replay state. */
export type PortableAttemptDutyRecord = Readonly<{
    dutyId: string;
    sourceIntentId: string;
    sourceAdmissionEventId: string;
    durableRoleId: string;
    creationRoleTenureId: string;
    description: string;
    deadline: number;
    performanceAssigneeId: string;
    status: "OPEN";
}>;
export type PortableOutcomeObservationRecordedData = Readonly<{
    intentId: string;
    sourceAdmissionEventId: string;
    acknowledgment: RemoteServiceReportAcknowledgment;
    actorId: string;
    administrativeAuthorization: PortableAdministrativeAuthorization;
}>;
export type PortableAttemptDutyCreatedData = Readonly<{
    record: PortableAttemptDutyRecord;
    actorId: string;
    administrativeAuthorization: PortableAdministrativeAuthorization;
}>;
export type PortableAttemptDutyAssignedData = Readonly<{
    dutyId: string;
    fromAgentId: string;
    toAgentId: string;
    actorId: string;
    administrativeAuthorization: PortableAdministrativeAuthorization;
}>;
export type PortableAttemptDutyReviewClosedData = Readonly<{
    dutyId: string;
    actorId: string;
    observationEventIds: readonly string[];
    summaryDigest: ContentHash;
    administrativeAuthorization: PortableAdministrativeAuthorization;
}>;
export type PortableAdministrativeTransitionEffect = Readonly<{
    transitionEventType: "ATTEMPT_DUTY_REVIEW_CLOSED";
    dutyId: string;
    actorId: string;
    observationEventIds: readonly string[];
    summaryDigest: ContentHash;
}> | Readonly<{
    transitionEventType: "OUTCOME_OBSERVATION_RECORDED";
    intentId: string;
    sourceAdmissionEventId: string;
    acknowledgment: RemoteServiceReportAcknowledgment;
    actorId: string;
}> | Readonly<{
    transitionEventType: "ATTEMPT_DUTY_CREATED";
    record: PortableAttemptDutyRecord;
    actorId: string;
}> | Readonly<{
    transitionEventType: "ATTEMPT_DUTY_ASSIGNED";
    dutyId: string;
    fromAgentId: string;
    toAgentId: string;
    actorId: string;
}> | Readonly<{
    transitionEventType: "OBLIGATION_CREATED";
    record: PortableObligationRecord;
    actorId: string;
}> | Readonly<{
    transitionEventType: "OBLIGATION_PERFORMANCE_ASSIGNED";
    obligationId: string;
    fromAgentId: string;
    toAgentId: string;
    successionRuleId: string;
    actorId: string;
}> | Readonly<{
    transitionEventType: "OBLIGATION_STATUS_RECORDED";
    obligationId: string;
    fromStatus: PortableObligationStatus;
    toStatus: PortableObligationStatus;
    actorId: string;
    action: string;
    attesterId: string;
    evidenceReference: PortableReplayEvidenceReference;
}>;
export type PortableAdministrativeAuthorizationChallenge = Readonly<{
    version: "continuity-administrative-authorization/0.2";
    domain: PortableAuthorizationDomain;
    request: PortableActionRequest;
    authoritative: true;
    consequential: true;
    evaluationTime: number;
    policyVersion: string;
    rootRecognitionPolicy: "declared-principal-root/0.2";
    eventHistoryHash: ContentHash;
    eventHistoryPosition: number;
    transitionEventId: string;
    transitionEventType: PortableAdministrativeTransitionEffect["transitionEventType"];
    transitionEffectHash: ContentHash;
    runtimeSessionId: string;
    credentialKeyId: string;
    controlEpoch: number;
    roleId: string;
    roleTenureId: string;
    authorityProofHash: ContentHash;
}>;
export type PortableAdministrativeAuthorization = Readonly<{
    challenge: PortableAdministrativeAuthorizationChallenge;
    authorityProof: PortableAuthorizationProof;
    runtimeSignature: `0x${string}`;
}>;
/**
 * @internal Section 7.5 projection of an already captured, schema-validated event.
 * This is neither raw-input validation nor evidence of transition authority.
 * Nested values retain the accepted snapshot, including the entire creation record.
 */
export declare const portableAdministrativeTransitionEffect: (event: AcceptedCanonicalEventShape) => PortableAdministrativeTransitionEffect;
