import { type PortableAdapterProfile } from "./portable-adapter-engine.ts";
import { type CanonicalReplayCaptureVisitDecision, type CapturedCanonicalAuthorityOperation, type CapturedCanonicalReplayEvent, type ContentHash, type PortableAuthorityCaptureKind } from "./canonical.ts";
import type { PortableAgentRecord, PortableAuthorityConstraints, PortableAuthorityEvidence, PortableAuthorityRecord, PortableAuthorityUsage, PortableAuthorizationDomain, PortableGenesisRecord, PortableHistoryHead, PortableIntentAdmissionRecord, PortableIntentDeclarationRecord, PortablePermissionGrant, PortablePrincipalRecord, PortableProhibitionGrant, PortableNonceReservation, PortableRecognizedRoot, PortableRoleRecord, PortableRoleTenureRecord, PortableRuntimeSessionRecord, PortableTransactionIntent } from "./portable-replay.ts";
import type { AcceptedCanonicalEventShape, CoreEventType } from "./event-schema.ts";
export declare const PORTABLE_AUTHORITY_EVALUATION_VERSION: "continuity-authority-evaluation/0.2";
export declare const PORTABLE_AUTHORIZATION_VERSION: "continuity-authorization/0.2";
export declare const PORTABLE_INTENT_ADMISSION_VERSION: "continuity-intent-admission/0.2";
export declare const PORTABLE_AUTHORIZATION_PROOF_VERSION: "continuity-authorization-proof/0.2";
export declare const PORTABLE_RUNTIME_AUTHORIZATION_VERSION: "continuity-runtime-authorization/0.2";
export declare const PORTABLE_ROOT_RECOGNITION_POLICY: "declared-principal-root/0.2";
export type PortableActionRequest = Readonly<{
    actorId: string;
    action: string;
    resource: string;
    claimedAt: number;
    amount?: bigint;
    counterpartyId?: string;
    termsCommitment?: ContentHash;
}>;
export type PortableConsequentialBinding = Readonly<{
    runtimeSessionId: string;
    credentialKeyId?: string;
    controlEpoch: number;
    roleId: string;
    roleTenureId: string;
    intentId?: string;
    nonce?: string;
    runtimeSignature?: `0x${string}`;
}>;
export type PortableAuthorityPathEvaluationInput = Readonly<{
    operationVersion: typeof PORTABLE_AUTHORITY_EVALUATION_VERSION;
    scope: Readonly<{
        domain: PortableAuthorizationDomain;
        policyVersion: string;
        rootRecognitionPolicy: typeof PORTABLE_ROOT_RECOGNITION_POLICY;
        historyHead: PortableHistoryHead;
        evaluationTime: number;
        recognizedRoots: readonly PortableRecognizedRoot[];
        globalPolicySourceId: string;
    }>;
    request: PortableActionRequest;
    permissions: readonly PortablePermissionGrant[];
    prohibitions: readonly PortableProhibitionGrant[];
    authorityEvidence: readonly PortableAuthorityEvidence[];
    revokedAuthorityIds: readonly string[];
    usage: readonly PortableAuthorityUsage[];
}>;
export type PortableAuthorizeInput = Readonly<{
    operationVersion: typeof PORTABLE_AUTHORIZATION_VERSION;
    events: readonly AcceptedCanonicalEventShape[];
    expectedHistoryHead: PortableHistoryHead;
    domain: PortableAuthorizationDomain;
    policyVersion: string;
    rootRecognitionPolicy: typeof PORTABLE_ROOT_RECOGNITION_POLICY;
    request: PortableActionRequest;
    evaluationTime: number;
    authoritative: true;
    consequential: boolean;
    binding?: PortableConsequentialBinding;
}>;
/**
 * Package-internal replay projection consumed by deterministic authority
 * evaluation. The lower engine deliberately depends on replay types only;
 * replay-state provenance remains the responsibility of its outer caller.
 */
export type PortableAuthorityReplayState = Readonly<{
    events: readonly AcceptedCanonicalEventShape[];
    eventHistoryHashes: readonly ContentHash[];
    head: PortableHistoryHead;
    genesis: PortableGenesisRecord;
    principals: ReadonlyMap<string, PortablePrincipalRecord>;
    agents: ReadonlyMap<string, PortableAgentRecord>;
    roles: ReadonlyMap<string, PortableRoleRecord>;
    tenures: ReadonlyMap<string, PortableRoleTenureRecord>;
    runtimeSessions: ReadonlyMap<string, PortableRuntimeSessionRecord>;
    intentDeclarations: ReadonlyMap<string, PortableIntentDeclarationRecord>;
    intentAdmissions: ReadonlyMap<string, PortableIntentAdmissionRecord>;
    nonceReservationsByActor: ReadonlyMap<string, ReadonlyMap<string, PortableNonceReservation>>;
    authorities: ReadonlyMap<string, PortableAuthorityRecord>;
    recognizedRoots: ReadonlyMap<string, PortableRecognizedRoot>;
    authorityUsage: ReadonlyMap<string, PortableAuthorityUsage>;
}>;
/** Event-specific requirements derived by replay from the exact prior state. */
export type PortableAdministrativeRequirements = Readonly<{
    request: PortableActionRequest;
    requiredPrincipalId: string;
    requiredAuthorityIds: readonly string[];
    roleId: string;
    roleTenureId: string;
}>;
export type PortableEvidenceReference = Readonly<{
    kind: "EVENT";
    eventId: string;
    eventType: CoreEventType;
    position: number;
    historyHash: ContentHash;
}>;
export type PortableIntersectionProof = Readonly<{
    requiredAuthorityId: string;
    requiredByAuthorityIds: readonly string[];
    recognizedRoot: PortableRecognizedRoot;
    path: readonly PortablePermissionGrant[];
    effectiveConstraints: PortableAuthorityConstraints;
}>;
export type PortableAuthorizationProof = Readonly<{
    proofVersion: typeof PORTABLE_AUTHORIZATION_PROOF_VERSION;
    domain: PortableAuthorizationDomain;
    policyVersion: string;
    rootRecognitionPolicy: typeof PORTABLE_ROOT_RECOGNITION_POLICY;
    historyHead: PortableHistoryHead;
    evaluationTime: number;
    request: PortableActionRequest;
    recognizedRoot: PortableRecognizedRoot;
    permissionPath: readonly PortablePermissionGrant[];
    intersections: readonly PortableIntersectionProof[];
    effectiveConstraints: PortableAuthorityConstraints;
    controllingAuthorityIds: readonly string[];
    usageSnapshot: readonly PortableAuthorityUsage[];
    authorityEvidence: readonly PortableAuthorityEvidence[];
    checkedProhibitionIds: readonly string[];
    consequential: boolean;
    runtimeSessionId?: string;
    credentialKeyId?: string;
    controlEpoch?: number;
    roleId?: string;
    roleTenureId?: string;
    intentId?: string;
    nonce?: string;
}>;
export type PortableDenialCode = "DOMAIN_MISMATCH" | "POLICY_MISMATCH" | "INVALID_REQUEST" | "INVALID_AMOUNT" | "INVALID_DELEGATION" | "AGENT_INACTIVE" | "SESSION_NOT_FOUND" | "SESSION_EXPIRED" | "SESSION_CREDENTIAL_REQUIRED" | "SESSION_CREDENTIAL_INVALID" | "SESSION_FENCED" | "STALE_EPOCH" | "ROLE_TENURE_NOT_CURRENT" | "INTENT_REQUIRED" | "INTENT_NOT_DECLARED" | "INTENT_MISMATCH" | "INTENT_REPLAY" | "NONCE_ALREADY_ADMITTED" | "PROHIBITED" | "REVOKED" | "NOT_YET_VALID" | "EXPIRED" | "MISSING_INTERSECTION" | "ACTION_NOT_ALLOWED" | "RESOURCE_NOT_ALLOWED" | "AMOUNT_REQUIRED" | "AMOUNT_EXCEEDED" | "CUMULATIVE_AMOUNT_EXCEEDED" | "TRANSACTION_COUNT_EXCEEDED" | "NO_AUTHORITY";
export type PortableIndeterminateCode = "INVALID_INPUT" | "UNSUPPORTED_VERSION" | "OUTPUT_LIMIT_EXCEEDED" | "STATE_NOT_AUTHORITATIVE" | "CAUSAL_TIME_INVALID" | "HISTORY_RELATION_UNVERIFIED" | "EVIDENCE_UNAVAILABLE" | "EVIDENCE_DISPUTED";
export type PortableDenialEvidence = Readonly<{
    code: PortableDenialCode;
    subjectId?: string;
    rootAuthorityId?: string;
    terminalAuthorityId?: string;
    failingAuthorityId?: string;
    authorityPathIds: readonly string[];
    evidence: readonly PortableEvidenceReference[];
}>;
export type PortableIndeterminateEvidence = Readonly<{
    code: PortableIndeterminateCode;
    subjectId?: string;
    evidence: readonly PortableEvidenceReference[];
}>;
export type PortableAuthorizationResult = Readonly<{
    operationVersion: typeof PORTABLE_AUTHORITY_EVALUATION_VERSION | typeof PORTABLE_AUTHORIZATION_VERSION;
    decision: "ALLOW";
    scopeAssurance: "SUPPLIED_SCOPE" | "REPLAY_VERIFIED";
    consequential: boolean;
    proof: PortableAuthorizationProof;
}> | Readonly<{
    operationVersion: typeof PORTABLE_AUTHORITY_EVALUATION_VERSION | typeof PORTABLE_AUTHORIZATION_VERSION;
    decision: "DENY";
    scopeAssurance: "SUPPLIED_SCOPE" | "REPLAY_VERIFIED";
    consequential: false;
    code: PortableDenialCode;
    failures: readonly PortableDenialEvidence[];
}> | Readonly<{
    operationVersion: typeof PORTABLE_AUTHORITY_EVALUATION_VERSION | typeof PORTABLE_AUTHORIZATION_VERSION;
    decision: "INDETERMINATE";
    scopeAssurance: "SUPPLIED_SCOPE" | "REPLAY_VERIFIED";
    consequential: false;
    code: PortableIndeterminateCode;
    failures: readonly PortableIndeterminateEvidence[];
}>;
export type PortableRuntimeAuthorizationChallenge = Readonly<{
    version: typeof PORTABLE_RUNTIME_AUTHORIZATION_VERSION;
    domain: PortableAuthorizationDomain;
    request: PortableActionRequest;
    authoritative: true;
    consequential: true;
    evaluationTime: number;
    policyVersion: string;
    rootRecognitionPolicy: typeof PORTABLE_ROOT_RECOGNITION_POLICY;
    eventHistoryHash: ContentHash;
    eventHistoryPosition: number;
    runtimeSessionId: string;
    credentialKeyId: string;
    controlEpoch: number;
    roleId: string;
    roleTenureId: string;
    intentId: string;
    nonce: string;
}>;
export type CapturedPortableAuthorityInput = CapturedCanonicalAuthorityOperation<Record<string, unknown>>;
export type PortableAuthorityOperationCapture = Readonly<{
    status: "INVALID_INPUT";
}> | Readonly<{
    status: "UNSUPPORTED_VERSION";
}> | Readonly<{
    status: "STATE_NOT_AUTHORITATIVE";
}> | Readonly<{
    status: "CAPTURED";
    capture: CapturedPortableAuthorityInput;
}>;
/**
 * One-graph caller capture shared by the raw, replay-bound, and admission
 * façades. Replay supplies its own visitor, so this lower engine never imports
 * replay runtime code.
 */
export declare const capturePortableAuthorityOperation: (input: unknown, kind: PortableAuthorityCaptureKind, replayVisitor?: (capturedEvent: CapturedCanonicalReplayEvent) => CanonicalReplayCaptureVisitDecision<never>) => PortableAuthorityOperationCapture;
export type PortableReceiptPolicyEvaluation = Readonly<{
    live: boolean;
    checkedProhibitionIds: readonly string[];
    decisiveAuthorityIds: readonly string[];
    decisiveAgentIds: readonly string[];
}>;
/**
 * Package-internal receipt recheck over accepted state and its admitted proof.
 * Select the original terminal/path, never a newly preferred candidate. Only
 * already reserved nonce/capacity are outside this policy liveness predicate;
 * the caller separately rechecks the exact admitted control tuple.
 */
export declare const evaluatePortableReceiptPolicy: (state: PortableAuthorityReplayState, proof: PortableAuthorizationProof, evaluationTime: number) => PortableReceiptPolicyEvaluation;
export type PortableRuntimeChallengeInput = Readonly<{
    domain: PortableAuthorizationDomain;
    request: PortableActionRequest;
    evaluationTime: number;
    policyVersion: string;
    historyHead: PortableHistoryHead;
    binding: PortableConsequentialBinding;
}>;
/** Package-internal exact Section 7.1 challenge projection. */
export declare const createPortableRuntimeAuthorizationChallenge: (input: PortableRuntimeChallengeInput) => PortableRuntimeAuthorizationChallenge;
export declare const hashPortableRuntimeAuthorizationChallenge: (challenge: PortableRuntimeAuthorizationChallenge) => ContentHash;
export declare const portableEip191Digest: (messageHash: ContentHash) => ContentHash;
/** Package-internal strict EIP-191 recovery shared by Runtime and receipt verification. */
export declare const recoverPortableContentHashSigner: (contentHash: unknown, signature: unknown) => string | undefined;
export declare const verifyPortableRuntimeAuthorizationSignature: (expectedAddress: string, challenge: PortableRuntimeAuthorizationChallenge, signature: unknown) => boolean;
/** Exact immutable intent content; actor-claimed time is intentionally absent. */
export declare const portableIntentProjection: (request: PortableActionRequest, binding: PortableConsequentialBinding, adapterProfile: PortableAdapterProfile) => PortableTransactionIntent;
/**
 * Raw supplied-scope authority evaluation. It never claims consequential or
 * replay-verified authority.
 */
export declare const evaluatePortableAuthorityPath: (input: unknown) => PortableAuthorizationResult;
/**
 * Package-internal policy component for a signed administrative event. Replay
 * owns input capture and state provenance; this proof alone grants no authority
 * to append an event and never reserves a nonce or controlling capacity.
 */
export declare const createPortableAdministrativePolicyProof: (state: PortableAuthorityReplayState, requirements: PortableAdministrativeRequirements, evaluationTime: number) => PortableAuthorizationProof | undefined;
/** Validate a closed administrative event against replay's exact prior state. */
export declare const validatePortableAdministrativeTransition: (state: PortableAuthorityReplayState, event: AcceptedCanonicalEventShape, requirements: PortableAdministrativeRequirements) => boolean;
export type PortableReplayAuthorizationDeny = Extract<PortableAuthorizationResult, {
    decision: "DENY";
}>;
export type PortableReplayAuthorizationIndeterminate = Extract<PortableAuthorizationResult, {
    decision: "INDETERMINATE";
}>;
/** Evaluate one provenance-bound, structurally captured AUTHORIZE body. */
export declare const capturedPortableAuthorizeInputIsStructurallyValid: (capture: CapturedPortableAuthorityInput) => boolean;
/** Evaluate one provenance-bound, structurally captured AUTHORIZE body. */
export declare const authorizeCapturedPortableState: (capture: CapturedPortableAuthorityInput, state: PortableAuthorityReplayState) => PortableAuthorizationResult;
export type PortableIntentAdmissionStateEvaluation = Readonly<{
    status: "AUTHORIZED";
    authorization: PortableAuthorizationProof;
    admissionEventId: string;
    expectedHead: PortableHistoryHead;
    evaluationTime: number;
    binding: PortableConsequentialBinding & Readonly<{
        credentialKeyId: string;
        intentId: string;
        nonce: string;
        runtimeSignature: `0x${string}`;
    }>;
}> | Readonly<{
    status: "RETRY";
    intentId: string;
    existingAdmissionEventId: string;
    existingAdmissionHead: PortableHistoryHead;
}> | Readonly<{
    status: "DENIED";
    authorization: PortableReplayAuthorizationDeny;
}> | Readonly<{
    status: "INDETERMINATE";
    authorization: PortableReplayAuthorizationIndeterminate;
}> | Readonly<{
    status: "CONFLICT";
    expectedHead: PortableHistoryHead;
    observedHead: PortableHistoryHead;
}>;
/**
 * Exact pre-proposal admission state machine after one caller capture and one
 * authoritative replay. Prospective event capture/replay remains in the outer
 * admission façade to keep this engine below replay at runtime.
 */
export declare const capturedPortableIntentAdmissionInputIsStructurallyValid: (capture: CapturedPortableAuthorityInput) => boolean;
export declare const evaluateCapturedPortableIntentAdmissionState: (capture: CapturedPortableAuthorityInput, state: PortableAuthorityReplayState) => PortableIntentAdmissionStateEvaluation;
export type PortableAdmissionTransitionValidation = Readonly<{
    status: "VALID";
    intentId: string;
    actorId: string;
    nonce: string;
    usage: readonly PortableAuthorityUsage[];
}> | Readonly<{
    status: "INVALID";
}>;
/**
 * Replay-side validation of the complete stored admission evidence at its
 * exact pre-event state. The returned reservations are applied atomically by
 * replay only after every predicate succeeds.
 */
export declare const validatePortableIntentAdmissionTransition: (state: PortableAuthorityReplayState, event: AcceptedCanonicalEventShape) => PortableAdmissionTransitionValidation;
/** Compact, replay-verified output-limit result used by admission orchestration. */
export declare const portableAdmissionOutputLimit: () => PortableReplayAuthorizationIndeterminate;
/** Closed replay-authorization indeterminate projection for outer façades. */
export declare const portableReplayAuthorizationIndeterminate: (code: PortableIndeterminateCode, assurance?: "SUPPLIED_SCOPE" | "REPLAY_VERIFIED") => PortableReplayAuthorizationIndeterminate;
