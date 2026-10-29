/** Fixed prospective D1 bridge. No caller-supplied policy program or global edition switch. */
import { type ContentHash } from "./canonical.ts";
import { type PortableReplayState, type PortableAuthorizationDomain, type PortableHistoryHead } from "./portable-replay.ts";
import type { PortableAdministrativeRequirements, PortableAuthorizationProof } from "./portable-authority-engine.ts";
import type { PortableAdministrativeAuthorization } from "./portable-administration-codec.ts";
export declare const DUTY_POLICY_VERSION: "continuity-attempt-disposition/1";
export declare const DUTY_POLICY_RULES_HASH: "0xf7fb2b7de27abb77c6c3d03af6f61dce11afda5a510af20c8036085cd10a5f94";
export declare const DUTY_VIEW_VERSION: "continuity-attempt-duty-view/1";
export declare const DUTY_POLICY_RULES: {
    readonly version: "continuity-attempt-disposition/1";
    readonly criteriaProfile: "local-investigation/1";
    readonly scope: "ONE_EXISTING_E5_OR_E6_ATTEMPT_DUTY";
    readonly eventTypes: readonly ["ATTEMPT_DUTY_POLICY_ACTIVATED", "ATTEMPT_DUTY_DISPOSITION_RECORDED", "ATTEMPT_DUTY_CONTEST_RECORDED"];
    readonly activation: {
        readonly action: "ACTIVATE_DUTY_POLICY";
        readonly resourcePrefix: "duty-policy:";
        readonly principal: "EXISTING_SOURCE_ROLE_PRINCIPAL";
        readonly grant: "EXACT_NONDELEGABLE_UNCAPPED_RECOGNIZED_ROOT";
        readonly signer: "CURRENT_DUTY_ROLE_OCCUPANT_RUNTIME";
        readonly activationLimit: 1;
        readonly changesGenesisOrAdapterPolicy: false;
    };
    readonly attestation: {
        readonly version: "continuity-duty-finding/1";
        readonly purposes: readonly ["DISPOSITION", "CONTEST"];
        readonly action: "ATTEST_DUTY_FINDING";
        readonly resourcePrefix: "duty:";
        readonly acceptedRole: "ONE_PREEXISTING_ROLE_UNDER_SOURCE_PRINCIPAL";
        readonly findingProof: "RECOMPUTED_FROM_PRIOR_STATE_HASH_BOUND";
    };
    readonly transition: {
        readonly action: "RECORD_DUTY_DISPOSITION";
        readonly resourcePrefix: "duty:";
        readonly signer: "CURRENT_ASSIGNEE_AND_DUTY_ROLE_OCCUPANT_RUNTIME";
        readonly signatureOrder: readonly ["FINDING", "OUTER_EFFECT_INCLUDING_FINDING_SIGNATURE"];
        readonly postSignEligibility: "BOTH_SIGNERS_AT_FRESH_TIME_AND_UNCHANGED_HEAD";
    };
    readonly criteria: readonly ["SOURCE_REVIEWED", "HISTORY_REVIEWED", "FINDING_RECORDED", "CONTROL_REVIEWED"];
    readonly criterionStates: readonly ["SATISFIED", "UNAVAILABLE", "UNRESOLVED"];
    readonly criterionReasonMaxUtf8Bytes: 256;
    readonly nextStepMaxUtf8Bytes: 512;
    readonly dispositions: readonly ["COMPLETED_UNDER_POLICY", "ESCALATED"];
    readonly viewVersion: "continuity-attempt-duty-view/1";
    readonly currentViews: readonly ["OPEN", "COMPLETED_UNDER_POLICY", "ESCALATED", "NEEDS_REVIEW", "CONTESTED"];
    readonly completion: "ALL_CRITERIA_SATISFIED_WITHOUT_ACCEPTED_CONTEST";
    readonly outstandingFalseOnlyFor: "CURRENT_COMPLETED_UNDER_POLICY";
    readonly externalOutcome: "NOT_PROVEN";
    readonly contest: "PERSISTENT_NO_WITHDRAWAL_OR_ADJUDICATION";
    readonly documentDigestAlgorithm: "sha256";
    readonly evidenceIndexVersion: "continuity-duty-evidence-index/1";
    readonly freshness: "COMPLETE_SOURCE_LIFECYCLE_OBSERVATIONS_REVIEWS_ASSIGNMENTS_AND_CONTESTS";
    readonly excludeFromFreshness: readonly ["DISPOSITIONS", "UNRELATED_EVENTS", "LATER_CREDENTIAL_OR_AUTHORITY_CHANGES_ALONE"];
    readonly writerProfile: "continuity-segmented-local/1";
    readonly limits: {
        readonly dispositions: 4;
        readonly contests: 2;
        readonly reservedAtActivation: 6;
        readonly releaseUnusedOnCompletion: false;
        readonly raiseExistingStorageOrShapeLimits: false;
    };
};
export type PortableDutyDocumentDigest = Readonly<{
    algorithm: "sha256";
    value: ContentHash;
}>;
export type PortableDutyPolicySelection = Readonly<{
    dutyId: string;
    incidentSourceDigest: PortableDutyDocumentDigest;
    acceptedAttesterRoleId: string;
}>;
export type PortableDutyPolicyDescriptor = Readonly<{
    version: typeof DUTY_POLICY_VERSION;
    rulesHash: typeof DUTY_POLICY_RULES_HASH;
    criteriaProfile: "local-investigation/1";
    domain: PortableAuthorizationDomain;
    genesisHash: ContentHash;
    baseAdapterPolicyHash: ContentHash;
    dutyId: string;
    dutyCreationEventId: string;
    dutyRecordHash: ContentHash;
    sourceIntentId: string;
    sourceAdmissionEventId: string;
    durableRoleId: string;
    principalId: string;
    incidentSourceDigest: PortableDutyDocumentDigest;
    acceptedAttesterRoleId: string;
    dispositionLimit: 4;
    contestLimit: 2;
}>;
export type PortableDutyPolicyActivatedData = Readonly<{
    actorId: string;
    descriptor: PortableDutyPolicyDescriptor;
    descriptorHash: ContentHash;
    activationAuthorityId: string;
    administrativeAuthorization: PortableAdministrativeAuthorization;
}>;
export type PortableDutyPolicyActivation = Readonly<{
    descriptor: PortableDutyPolicyDescriptor;
    descriptorHash: ContentHash;
    activationAuthorityId: string;
    actorId: string;
    eventId: string;
    eventPosition: number;
    activatedAt: number;
    priorHead: PortableHistoryHead;
    dispositionCount: 0;
    contestCount: 0;
}>;
export type PortableDutyPolicyView = Readonly<{
    version: typeof DUTY_VIEW_VERSION;
    dutyId: string;
    dutyDisposition: "OPEN";
    outstanding: true;
    externalOutcome: "NOT_PROVEN";
    policy: PortableDutyPolicyActivation;
    observedHead: PortableHistoryHead;
    currentAssigneeId: string;
    latestAssignmentEventId: string;
    lastRecordedDisposition: null;
    evidenceScope: Readonly<{
        kind: "COMPLETE_CAPTURED_HISTORY";
        head: PortableHistoryHead;
    }>;
    reasons: readonly ["NO_DISPOSITION_RECORDED"];
}>;
/** Internal structural view; only replay/administration owns its provenance. */
type DutyPolicyState = Pick<PortableReplayState, "events" | "eventHistoryHashes" | "genesis" | "head" | "attemptDuties" | "attemptDutyPolicies" | "roles" | "tenures" | "agents" | "intentDeclarations" | "intentAdmissions" | "authorities" | "recognizedRoots">;
/** Internal: derive every source fact from a previously verified complete prefix. */
export declare function derivePortableDutyPolicyDescriptor(state: DutyPolicyState, selection: PortableDutyPolicySelection): PortableDutyPolicyDescriptor | undefined;
/** Pure selection helper; it does not confer authority or mutate a history. */
export declare function buildPortableDutyPolicyDescriptor(state: PortableReplayState, input: PortableDutyPolicySelection): PortableDutyPolicyDescriptor;
/** Internal exact-root and immutable-selection requirements, independently rerun during replay. */
export declare function portableDutyPolicyActivationRequirements(state: DutyPolicyState, data: Omit<PortableDutyPolicyActivatedData, "administrativeAuthorization">, timestamp: number): PortableAdministrativeRequirements | undefined;
/** The selected root must be the main permission path, never a convenient alternate root. */
export declare function portableDutyPolicyActivationProofMatches(proof: PortableAuthorizationProof, authorityId: string): boolean;
export declare function inspectPortableDutyPolicy(state: PortableReplayState, dutyId: string): PortableDutyPolicyView | undefined;
export {};
