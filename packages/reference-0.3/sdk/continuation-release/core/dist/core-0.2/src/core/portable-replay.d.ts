import { type CanonicalReplayCaptureVisitDecision, type CapturedCanonicalReplayEvent, type ContentHash } from "./canonical.ts";
import { type AcceptedCanonicalEventShape } from "./event-schema.ts";
import type { PortableAttemptDutyRecord, PortableObligationRecord, PortableObligationStatus } from "./portable-administration-codec.ts";
import { type RemoteServiceReportAcknowledgment, type PortableAdapterProfile, type PortableAdapterAcknowledgment, type PortableAdapterNoEffect, type PortableAdapterIdentity } from "./portable-adapter-engine.ts";
export declare const PORTABLE_REPLAY_VERSION: "continuity-replay/0.2";
export type PortableReplayCode = "INVALID_INPUT" | "UNSUPPORTED_VERSION" | "UNSUPPORTED_EVENT_SCHEMA" | "UNSUPPORTED_EVENT_TYPE" | "GENESIS_REQUIRED" | "GENESIS_DUPLICATE" | "EVENT_ID_DUPLICATE" | "EVENT_TIME_REGRESSION" | "EVENT_DATA_INVALID" | "TRANSITION_INVALID";
export type PortableHistoryHead = Readonly<{
    hash: ContentHash;
    position: number;
    canonicalTime: number;
}>;
export type PortableReplayInput = Readonly<{
    operationVersion: typeof PORTABLE_REPLAY_VERSION;
    events: readonly AcceptedCanonicalEventShape[];
}>;
export type PortableReplayResult = Readonly<{
    operationVersion: typeof PORTABLE_REPLAY_VERSION;
    status: "ACCEPTED";
    head: PortableHistoryHead;
    eventCount: number;
}> | Readonly<{
    operationVersion: typeof PORTABLE_REPLAY_VERSION;
    status: "REJECTED";
    code: PortableReplayCode;
    eventPosition?: number;
    eventId?: string;
}>;
export type PortableGenesisRecord = Readonly<{
    adapterPolicyHash: ContentHash;
    domain: PortableAuthorizationDomain;
    canonicalLineageId: string;
    versions: Readonly<Record<string, string>>;
    policyVersion: string;
    rootRecognitionPolicy: "declared-principal-root/0.2";
    globalPolicySourceId: string;
    timeSource: "EVENT_TIMESTAMP";
    finality: "LOCAL_ONLY";
}>;
export type PortableAuthorizationDomain = Readonly<{
    protocol: "continuity";
    version: "0.2";
    deploymentId: string;
    chainId: string;
    verifyingContract: string;
}>;
export type PortableAuthorityConstraints = Readonly<{
    actions: readonly string[];
    resources: readonly string[];
    quantitative: boolean;
    notBefore?: number;
    expiresAt?: number;
    maxAmount?: bigint;
    maxCumulativeAmount?: bigint;
    maxTransactions?: number;
    maxDelegationDepth: number;
    requiredIntersectionIds: readonly string[];
}>;
export type PortablePermissionGrant = Readonly<{
    kind: "PERMISSION";
    authorityId: string;
    grantorId: string;
    granteeId: string;
    rootAuthorityId: string;
    parentAuthorityId?: string;
    independent: boolean;
    constraints: PortableAuthorityConstraints;
}>;
export type PortableRootProhibitionGrant = Readonly<{
    kind: "PROHIBITION";
    scope: "ROOT";
    authorityId: string;
    grantorId: string;
    subjectActorId?: string;
    rootAuthorityId: string;
    parentAuthorityId?: string;
    constraints: PortableAuthorityConstraints;
}>;
export type PortableGlobalProhibitionGrant = Readonly<{
    kind: "PROHIBITION";
    scope: "GLOBAL";
    authorityId: string;
    grantorId: string;
    subjectActorId?: string;
    constraints: PortableAuthorityConstraints;
}>;
export type PortableProhibitionGrant = PortableRootProhibitionGrant | PortableGlobalProhibitionGrant;
export type PortableAuthorityGrant = PortablePermissionGrant | PortableProhibitionGrant;
export type PortableRecognizedRoot = Readonly<{
    rootAuthorityId: string;
    principalId: string;
    principalRecognitionEventId: string;
    rootGrantEventId: string;
}>;
export type PortableAuthorityUsage = Readonly<{
    authorityId: string;
    admittedTransactionCount: number;
    admittedCumulativeAmount: bigint;
}>;
export type PortableAuthorityEvidence = Readonly<{
    authorityId: string;
    grantEventId: string;
    grantEventPosition: number;
}>;
type SuccessionRuleDeclaredData = Readonly<{
    ruleId: string;
    principalId: string;
    predecessorAgentId: string;
    successorAgentId: string;
    roleId: string;
    trigger: "AGENT_TERMINATED";
    permittedEventTypes: readonly ("AGENT_TERMINATED" | "ROLE_TRANSFERRED" | "OBLIGATION_PERFORMANCE_ASSIGNED")[];
}>;
export type PortableTransactionIntent = Readonly<{
    adapterProfile: PortableAdapterProfile;
    intentId: string;
    nonce: string;
    actorId: string;
    action: string;
    resource: string;
    roleId: string;
    roleTenureId: string;
    amount?: bigint;
    counterpartyId?: string;
    termsCommitment?: ContentHash;
}>;
export type PortableReplayEvidenceReference = Readonly<{
    kind: "EVENT";
    eventId: string;
    eventType: AcceptedCanonicalEventShape["type"];
    position: number;
    historyHash: ContentHash;
}> | Readonly<{
    kind: "AUTHORITY";
    authorityId: string;
    grantEventId: string;
}> | Readonly<{
    kind: "RUNTIME_CREDENTIAL";
    keyId: string;
    sessionId: string;
    admissionEventId: string;
}> | Readonly<{
    kind: "RECEIPT_COMMITMENT";
    receiptContentHash: ContentHash;
    eventId: string;
    position: number;
}> | Readonly<{
    kind: "EXTERNAL";
    evidenceType: string;
    reference: string;
    attesterId: string;
}>;
export type PortableTransactionOutcomeStatus = "CONFIRMED" | "FAILED" | "DISPUTED" | "OUTCOME_UNKNOWN";
type ReceiptRecordedData = Readonly<{
    receiptContentHash: ContentHash;
    receiptArtifactCommitment: ContentHash;
    intentId: string;
    issuerAgentId: string;
    runtimeSessionId: string;
    controlEpoch: number;
    roleId: string;
    roleTenureId: string;
    authorizationProofHash: ContentHash;
}>;
/** Opaque canonical commitments, never an authenticated receipt artifact. */
export type PortableReceiptCommitmentRecord = ReceiptRecordedData & Readonly<{
    eventId: string;
    eventPosition: number;
    head: PortableHistoryHead;
}>;
export type PortableOutcomeObservation = Readonly<{
    intentId: string;
    sourceAdmissionEventId: string;
    acknowledgment: RemoteServiceReportAcknowledgment;
    actorId: string;
    eventId: string;
    eventPosition: number;
    observedAt: number;
}>;
export type PortableAttemptDutyAssignment = Readonly<{
    fromAgentId: string;
    toAgentId: string;
    actorId: string;
    eventId: string;
    eventPosition: number;
    assignedAt: number;
}>;
export type PortableAttemptDutyReview = Readonly<{
    dutyId: string;
    actorId: string;
    observationEventIds: readonly string[];
    summaryDigest: ContentHash;
    eventId: string;
    eventPosition: number;
    reviewedAt: number;
}>;
export type PortableAttemptDutyState = Readonly<{
    record: PortableAttemptDutyRecord;
    creationEventId: string;
    creationEventPosition: number;
    creationActorId: string;
    currentAssigneeId: string;
    assignments: readonly PortableAttemptDutyAssignment[];
}>;
export type PortableObligationState = Readonly<{
    record: PortableObligationRecord;
    status: PortableObligationStatus;
    performanceAssigneeId: string;
    creationEventId: string;
    creationEventPosition: number;
    creationHead: PortableHistoryHead;
}>;
export type PortablePrincipalRecord = Readonly<{
    id: string;
    creationEventId: string;
    creationEventPosition: number;
}>;
export type PortableAgentRecord = Readonly<{
    id: string;
    principalId: string;
    controllerId: string;
    currentControlEpoch: number;
    terminated: boolean;
}>;
export type PortableRoleRecord = Readonly<{
    id: string;
    principalId: string;
    currentTenureId?: string;
    latestTenureNumber: number;
}>;
type SuccessionRuleRecord = Readonly<{
    data: SuccessionRuleDeclaredData;
}>;
type TerminationLock = Readonly<{
    agentId: string;
    principalId: string;
    successionRuleId: string;
    roleId: string;
    roleTenureId: string;
}>;
export type PortableRoleTenureRecord = Readonly<{
    id: string;
    roleId: string;
    agentId: string;
    principalId: string;
    tenureNumber: number;
    successionRuleId?: string;
    closed: boolean;
    successionLock?: TerminationLock;
}>;
export type PortableRuntimeSessionRecord = Readonly<{
    id: string;
    agentId: string;
    controllerId: string;
    controlEpoch: number;
    credentialKeyId: string;
    credentialAddressKey: string;
    admissionEventId: string;
    admissionEventPosition: number;
    expiresAt?: number;
}>;
export type PortableIntentDeclarationRecord = Readonly<{
    data: PortableTransactionIntent;
}>;
export type PortableIntentAdmissionRecord = Readonly<{
    intentId: string;
    actorId: string;
    nonce: string;
    admissionEventId: string;
    admissionEventPosition: number;
    admissionHead: PortableHistoryHead;
    runtimeSessionId: string;
    credentialKeyId: string;
    controlEpoch: number;
    roleId: string;
    roleTenureId: string;
    adapterIdentity: PortableAdapterIdentity;
}>;
export type PortableIntentConsumptionRecord = Readonly<{
    intentId: string;
    eventId: string;
    eventPosition: number;
    head: PortableHistoryHead;
    adapterId: PortableAdapterProfile["profileId"];
    idempotencyKey: ContentHash;
    submissionFingerprint: ContentHash;
    transactionReference: string;
    acknowledgment: PortableAdapterAcknowledgment;
    evidenceReference: PortableReplayEvidenceReference;
}>;
export type PortableIntentOutcomeRecord = Readonly<{
    noEffect?: PortableAdapterNoEffect;
    intentId: string;
    eventId: string;
    eventPosition: number;
    head: PortableHistoryHead;
    status: PortableTransactionOutcomeStatus;
    attesterId: string;
    evidenceReference: PortableReplayEvidenceReference;
}>;
export type PortableIntentOutcomeState = Readonly<{
    latest: PortableIntentOutcomeRecord;
    terminal?: PortableIntentOutcomeRecord;
}>;
export type PortableNonceReservation = Readonly<{
    intentId: string;
    admissionEventId: string;
    admissionEventPosition: number;
    admissionHead: PortableHistoryHead;
}>;
export type PortableAuthorityRecord = Readonly<{
    grant: PortableAuthorityGrant;
    grantEventId: string;
    grantEventPosition: number;
    revocationEventId?: string;
    revocationEventPosition?: number;
    revokerId?: string;
}>;
declare const portableReplayStateBrand: unique symbol;
export type PortableReplayState = Readonly<{
    readonly [portableReplayStateBrand]: true;
    readonly events: readonly AcceptedCanonicalEventShape[];
    readonly eventHistoryHashes: readonly ContentHash[];
    readonly head: PortableHistoryHead;
    readonly genesis: PortableGenesisRecord;
    readonly principals: ReadonlyMap<string, PortablePrincipalRecord>;
    readonly agents: ReadonlyMap<string, PortableAgentRecord>;
    readonly reservedAgentIds: ReadonlyMap<string, readonly string[]>;
    readonly roles: ReadonlyMap<string, PortableRoleRecord>;
    readonly successionRules: ReadonlyMap<string, SuccessionRuleRecord>;
    readonly tenures: ReadonlyMap<string, PortableRoleTenureRecord>;
    readonly runtimeSessions: ReadonlyMap<string, PortableRuntimeSessionRecord>;
    readonly intentDeclarations: ReadonlyMap<string, PortableIntentDeclarationRecord>;
    readonly intentAdmissions: ReadonlyMap<string, PortableIntentAdmissionRecord>;
    readonly intentConsumptions: ReadonlyMap<string, PortableIntentConsumptionRecord>;
    readonly intentOutcomeStates: ReadonlyMap<string, PortableIntentOutcomeState>;
    readonly outcomeObservations: ReadonlyMap<string, readonly PortableOutcomeObservation[]>;
    readonly attemptDuties: ReadonlyMap<string, PortableAttemptDutyState>;
    readonly attemptDutyReviews: ReadonlyMap<string, readonly PortableAttemptDutyReview[]>;
    readonly receiptCommitments: ReadonlyMap<ContentHash, PortableReceiptCommitmentRecord>;
    readonly obligations: ReadonlyMap<string, PortableObligationState>;
    readonly nonceReservationsByActor: ReadonlyMap<string, ReadonlyMap<string, PortableNonceReservation>>;
    readonly authorities: ReadonlyMap<string, PortableAuthorityRecord>;
    readonly recognizedRoots: ReadonlyMap<string, PortableRecognizedRoot>;
    readonly authorityUsage: ReadonlyMap<string, PortableAuthorityUsage>;
}>;
/** @internal The reference integration uses the same predicate as consumption. */
export declare const portableAdmissionControlIsCurrent: (state: PortableReplayState, intentId: string, useTime: number) => boolean;
export type PortableReplayKernelResult = Readonly<{
    readonly status: "ACCEPTED";
    readonly state: PortableReplayState;
}> | Readonly<{
    readonly status: "REJECTED";
    readonly result: PortableReplayResult;
}>;
export type PortableReplayKernel = Readonly<{
    visit(capturedEvent: CapturedCanonicalReplayEvent): CanonicalReplayCaptureVisitDecision<never>;
    finish(): PortableReplayKernelResult;
}>;
/** Package-internal provenance check for the replay-derived authority state. */
export declare const isPortableReplayState: (value: unknown) => value is PortableReplayState;
/**
 * @internal Reducer for an event list captured as part of a larger operation.
 * It never stops structural capture: the first semantic replay failure is
 * retained while the canonical layer finishes observing the complete input.
 */
export declare const createPortableReplayKernel: () => PortableReplayKernel;
/**
 * Common Core 0.2 replay for lifecycle, Runtime control, authority, intent,
 * consumption, outcome, receipt commitments, and signed obligation transitions.
 * Every event must pass the supported schema and its complete transition rules.
 */
export declare const replayPortable: (input: unknown) => PortableReplayResult;
export {};
