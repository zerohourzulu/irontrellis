import { DUTY_POLICY_VERSION, type PortableDutyPolicyView } from "./duty-policy.ts";
/** Internal Section 9 projection vocabulary; public query dispatch is staged separately. */
import type { ContentHash } from "./canonical.ts";
import type { PortableActionRequest, PortableConsequentialBinding, PortableAuthorizationResult } from "./portable-authority-engine.ts";
import type { AcceptedCanonicalEventShape } from "./event-schema.ts";
import type { PortableAuthorizationDomain, PortableHistoryHead } from "./portable-replay.ts";
import type { PortableObligationStatus } from "./portable-administration-codec.ts";
import type { PortableAdapterAcknowledgment, PortableAdapterProfile } from "./portable-adapter-engine.ts";
import type { PortableReplayState, PortableReplayEvidenceReference, PortableReceiptCommitmentRecord, PortableIntentOutcomeRecord } from "./portable-replay.ts";
export declare const PORTABLE_QUERY_VERSION: "continuity-query-envelope/0.2";
export declare const PORTABLE_QUERY_EXTERNAL_ASSUMPTIONS: Readonly<{
    readonly trust: "LOCAL_REPLAY_UNDER_DECLARED_ROOTS_NOT_INDEPENDENTLY_AUTHENTICATED";
    readonly identity: "PROTOCOL_IDENTIFIERS_NOT_REAL_WORLD_IDENTITY";
    readonly observation: "SUPPLIED_HISTORY_MAY_NOT_BE_LATEST_PUBLIC_HISTORY";
    readonly availability: "REPLAY_REQUIRES_EVENTS_AND_INTERPRETATION_RULES";
}>;
export type PortableResponsibilityKind = "ACTOR" | "RUNTIME_SESSION" | "ROLE" | "DECLARED_PRINCIPAL" | "MANDATOR" | "AUTHORITY_SOURCE" | "CONTROLLER" | "DURABLE_OBLIGOR" | "PERFORMANCE_ASSIGNEE" | "BENEFICIARY" | "COUNTERPARTY";
export declare const PORTABLE_RESPONSIBILITY_KINDS: readonly PortableResponsibilityKind[];
export type PortableResponsibilityAttribution = Readonly<{
    kind: PortableResponsibilityKind;
    subjectId: string;
    temporalBasis: "ACTION_PREFIX" | "LATER_CAUSAL_STATE";
    evidence: readonly PortableReplayEvidenceReference[];
}>;
export type PortableResponsibleAnswer = Readonly<{
    authorizationDecision: "ALLOW" | "DENY";
    attributions: readonly PortableResponsibilityAttribution[];
    attemptDuties?: readonly PortableAttemptDutyProjection[];
}>;
export type PortableRoleTenureProjection = Readonly<{
    roleId: string;
    agentId: string;
    roleTenureId: string;
    tenureNumber: number;
    status: "CURRENT" | "CLOSED";
    evidence: readonly PortableReplayEvidenceReference[];
}>;
export type PortableIntentProjection = Readonly<{
    intentId: string;
    actorId: string;
    nonce: string;
    state: "DECLARED" | "ADMITTED" | "SUBMITTED" | "OUTCOME_UNKNOWN" | "DISPUTED";
    evidence: readonly PortableReplayEvidenceReference[];
}>;
/** Current retained adapter facts; neither a duty nor fresh submission permission. */
export type PortableAdapterOutcomeProjection = Readonly<{
    intentId: string;
    actorId: string;
    adapterProfile: PortableAdapterProfile;
    state: "SUBMITTED" | PortableIntentOutcomeRecord["status"];
    acknowledgment?: PortableAdapterAcknowledgment;
    latestOutcome?: PortableIntentOutcomeRecord;
    evidence: readonly PortableReplayEvidenceReference[];
}>;
export type PortableObligationProjection = Readonly<{
    obligationId: string;
    durableRoleId: string;
    performanceAssigneeId: string;
    status: PortableObligationStatus;
    deadline: number;
    evidence: readonly PortableReplayEvidenceReference[];
}>;
export type PortablePerformanceAssignmentProjection = Readonly<{
    obligationId: string;
    assigneeId: string;
    successionRuleId: string;
    evidence: readonly PortableReplayEvidenceReference[];
}>;
export type PortableAuthorityDependencyProjection = Readonly<{
    authorityId: string;
    state: "REVOKED" | "EXPIRED" | "AGENT_TERMINATED";
    evidence: readonly PortableReplayEvidenceReference[];
}>;
export type PortableOutcomeObservationProjection = Readonly<{
    observationEventId: string;
    intentId: string;
    sourceAdmissionEventId: string;
    originalActorId: string;
    recorderId: string;
    recordedAt: number;
    reportDigest: Readonly<{
        algorithm: "sha256";
        value: ContentHash;
    }>;
    reportStatus: "REPORT_RECORDED" | "DIVERGENT_REPORTS";
    externalOutcome: "NOT_PROVEN";
    evidence: readonly PortableReplayEvidenceReference[];
}>;
export type PortableAttemptDutyReviewProjection = Readonly<{
    dutyId: string;
    actorId: string;
    observationEventIds: readonly string[];
    summaryDigest: ContentHash;
    eventId: string;
    eventPosition: number;
    reviewedAt: number;
}>;
export type PortableAttemptDutyProjection = Readonly<{
    dutyId: string;
    sourceIntentId: string;
    sourceAdmissionEventId: string;
    originalActorId: string;
    durableRoleId: string;
    creationActorId: string;
    initialAssigneeId: string;
    currentAssigneeId: string;
    deadline: number;
    status?: "OPEN";
    currentView?: PortableDutyPolicyView;
    externalOutcome: "NOT_PROVEN";
    evidence: readonly PortableReplayEvidenceReference[];
    reviewStatus?: "UNREVIEWED" | "REVIEW_CLOSED" | "NEEDS_REVIEW";
    reviews?: readonly PortableAttemptDutyReviewProjection[];
}>;
export type PortableSurvivesAnswer = Readonly<{
    targetAgentId: string;
    exists: boolean;
    lifecycleStatus: "ABSENT" | "ACTIVE" | "TERMINATED";
    historicalIdentity: readonly PortableReplayEvidenceReference[];
    currentRoleTenures: readonly PortableRoleTenureProjection[];
    transferredRoleTenures: readonly PortableRoleTenureProjection[];
    unresolvedIntents: readonly PortableIntentProjection[];
    adapterOutcomes: readonly PortableAdapterOutcomeProjection[];
    outcomeObservations?: readonly PortableOutcomeObservationProjection[];
    attemptDuties?: readonly PortableAttemptDutyProjection[];
    receiptCommitments: readonly PortableReplayEvidenceReference[];
    obligations: readonly PortableObligationProjection[];
    currentPerformanceAssignments: readonly PortablePerformanceAssignmentProjection[];
    invalidatedAuthorityDependencies: readonly PortableAuthorityDependencyProjection[];
}>;
/** Section 4.3: text components use unsigned UTF-8; positions remain numeric. */
export declare const compareQueryEvidence: (a: PortableReplayEvidenceReference, b: PortableReplayEvidenceReference) => number;
/** Deduplicate only already-derived identical facts; this is not input validation. */
export declare const queryEvidence: (...groups: readonly (readonly PortableReplayEvidenceReference[])[]) => readonly PortableReplayEvidenceReference[];
export declare const queryEventReference: (state: PortableReplayState, position: number) => Extract<PortableReplayEvidenceReference, {
    kind: "EVENT";
}>;
export declare const queryReceiptReference: (receipt: PortableReceiptCommitmentRecord) => Extract<PortableReplayEvidenceReference, {
    kind: "RECEIPT_COMMITMENT";
}>;
export type PortableQueryKind = "WHY" | "RESPONSIBLE" | "SURVIVES";
export type PortableQueryFailureCode = "INVALID_INPUT" | "UNSUPPORTED_VERSION" | "STATE_NOT_AUTHORITATIVE" | "CAUSAL_TIME_INVALID" | "HISTORY_RELATION_UNVERIFIED" | "DISCLOSURE_INVALID" | "OUTPUT_LIMIT_EXCEEDED" | "EVIDENCE_UNAVAILABLE" | "EVIDENCE_DISPUTED";
export type PortableDisclosureScope = Readonly<{
    mode: "PUBLIC_MINIMAL";
    includedFields: readonly string[];
    withheldFields: readonly string[];
}>;
export type PortableQueryIdentity = Readonly<{
    domain: PortableAuthorizationDomain;
    versions: Readonly<Record<string, string>>;
    policyVersion: string;
    rootRecognitionPolicy: "declared-principal-root/0.2";
    recognizedRootIds: readonly string[];
    canonicalLineageId: string;
    evaluationHead: PortableHistoryHead;
    observedHead: PortableHistoryHead;
    recognizedExtensions?: readonly Readonly<{
        version: typeof DUTY_POLICY_VERSION;
        rulesHash: ContentHash;
    }>[];
}>;
export type PortableQueryScope = PortableQueryIdentity & Readonly<{
    headRelationship: "SAME_HEAD" | "STRICT_EXTENSION" | "UNVERIFIED";
    freshness: "CURRENT" | "AT_EVALUATION" | "UNVERIFIED";
    finality: "LOCAL_ONLY";
    disclosure: PortableDisclosureScope;
    unavailableEvidence: readonly PortableReplayEvidenceReference[];
    withheldEvidence: readonly PortableReplayEvidenceReference[];
    externalAssumptions: typeof PORTABLE_QUERY_EXTERNAL_ASSUMPTIONS;
}>;
export type PortablePartialQueryScope = Partial<PortableQueryIdentity> & Readonly<{
    headRelationship: "UNVERIFIED";
    freshness: "UNVERIFIED";
    finality: "LOCAL_ONLY";
    disclosure?: PortableDisclosureScope;
    unavailableEvidence: readonly PortableReplayEvidenceReference[];
    withheldEvidence: readonly PortableReplayEvidenceReference[];
    externalAssumptions: typeof PORTABLE_QUERY_EXTERNAL_ASSUMPTIONS;
}>;
export type PortableEstablishedQueryEnvelope<K extends PortableQueryKind, T> = Readonly<{
    version: typeof PORTABLE_QUERY_VERSION;
    kind: K;
    epistemicStatus: "ESTABLISHED";
    scope: PortableQueryScope;
    answer: T;
}>;
export type PortableNonEstablishedQueryEnvelope<K extends PortableQueryKind> = Readonly<{
    version: typeof PORTABLE_QUERY_VERSION;
    kind: K;
    epistemicStatus: "INDETERMINATE" | "UNAVAILABLE" | "DISPUTED";
    scope: PortablePartialQueryScope | PortableQueryScope;
    code: PortableQueryFailureCode;
    evidence: readonly PortableReplayEvidenceReference[];
    externalAssumptions: typeof PORTABLE_QUERY_EXTERNAL_ASSUMPTIONS;
}>;
export type PortableWhyInput = Readonly<{
    operationVersion: typeof PORTABLE_QUERY_VERSION;
    evaluationEvents: readonly AcceptedCanonicalEventShape[];
    observedEvents: readonly AcceptedCanonicalEventShape[];
    authorizationDomain: PortableAuthorizationDomain;
    request: PortableActionRequest;
    evaluationTime: number;
    consequentialBinding?: PortableConsequentialBinding;
    disclosure: PortableDisclosureScope;
}>;
export type PortableResponsibleInput = PortableWhyInput;
export type PortableSurvivesInput = Readonly<{
    operationVersion: typeof PORTABLE_QUERY_VERSION;
    evaluationEvents?: readonly AcceptedCanonicalEventShape[];
    observedEvents: readonly AcceptedCanonicalEventShape[];
    targetAgentId: string;
    evaluationTime: number;
    disclosure: PortableDisclosureScope;
}>;
export type PortableQueryAuthorization = Extract<PortableAuthorizationResult, {
    decision: "ALLOW" | "DENY";
}> & Readonly<{
    scopeAssurance: "REPLAY_VERIFIED";
    operationVersion: "continuity-authorization/0.2";
}>;
export type PortableWhyAnswer = Readonly<{
    authorization: PortableQueryAuthorization;
    presentConsequentialUse: boolean;
}>;
export type PortableWhyQueryResult = PortableEstablishedQueryEnvelope<"WHY", PortableWhyAnswer> | PortableNonEstablishedQueryEnvelope<"WHY">;
export type PortableResponsibleQueryResult = PortableEstablishedQueryEnvelope<"RESPONSIBLE", PortableResponsibleAnswer> | PortableNonEstablishedQueryEnvelope<"RESPONSIBLE">;
export type PortableSurvivesQueryResult = PortableEstablishedQueryEnvelope<"SURVIVES", PortableSurvivesAnswer> | PortableNonEstablishedQueryEnvelope<"SURVIVES">;
export declare const PORTABLE_QUERY_ANSWER_FIELD_PATHS: readonly string[];
/** D1 vocabulary is opt-in so every unextended default disclosure retains its original bytes. */
export declare const PORTABLE_DUTY_QUERY_FIELD_PATHS: readonly string[];
/** A complete per-kind default within the generic disclosure-list bound. */
export declare const portablePublicQueryDisclosure: (kind: PortableQueryKind, extensions?: readonly (typeof DUTY_POLICY_VERSION)[]) => PortableDisclosureScope;
