/** Repository-local preparation only; never a durable append or authority capability. */
import { type ContentHash } from "../core/canonical.ts";
export type AdministrativeProducerPhase = "CAPTURE" | "PREPARE" | "SIGN" | "VERIFY";
export type AdministrativeProducerCode = "INVALID_INPUT" | "INPUT_LIMIT" | "UNSUPPORTED_OPERATION" | "UNSUPPORTED_STATUS" | "INVALID_TRANSITION" | "DOMAIN_MISMATCH" | "HEAD_MISMATCH" | "SESSION_INVALID" | "POLICY_UNAVAILABLE" | "PREFIX_REJECTED" | "SIGNER_INVALID" | "SIGNER_FAILED" | "INVALID_SIGNATURE" | "SIGNED_EVENT_REJECTED" | "PREPARATION_FAILED";
export declare class AdministrativeProducerError extends Error {
    readonly phase: AdministrativeProducerPhase;
    readonly code: AdministrativeProducerCode;
    constructor(phase: AdministrativeProducerPhase, code: AdministrativeProducerCode);
}
declare const DATA_FIELDS: {
    readonly OBLIGATION_CREATED: readonly ["record", "actorId"];
    readonly OBLIGATION_PERFORMANCE_ASSIGNED: readonly ["obligationId", "fromAgentId", "toAgentId", "successionRuleId", "actorId"];
    readonly OBLIGATION_STATUS_RECORDED: readonly ["obligationId", "fromStatus", "toStatus", "actorId", "action", "attesterId", "evidenceReference"];
    readonly OUTCOME_OBSERVATION_RECORDED: readonly ["intentId", "sourceAdmissionEventId", "acknowledgment", "actorId"];
    readonly ATTEMPT_DUTY_CREATED: readonly ["record", "actorId"];
    readonly ATTEMPT_DUTY_ASSIGNED: readonly ["dutyId", "fromAgentId", "toAgentId", "actorId"];
    readonly ATTEMPT_DUTY_REVIEW_CLOSED: readonly ["dutyId", "actorId", "observationEventIds", "summaryDigest"];
};
type TransitionKind = keyof typeof DATA_FIELDS;
/** Unsigned historical-prefix preparation; not permission or an append capability. */
export declare function prepareAdministrativeEvent(input: unknown): {
    transition: Readonly<{
        id: string;
        type: TransitionKind;
        timestamp: number;
        data: Readonly<Record<string, unknown>>;
    }>;
    challenge: {
        transitionEffectHash: `0x${string}`;
        authorityProofHash: `0x${string}`;
        version: "continuity-administrative-authorization/0.2";
        domain: Readonly<{
            protocol: "continuity";
            version: "0.2";
            deploymentId: string;
            chainId: string;
            verifyingContract: string;
        }>;
        request: Readonly<{
            actorId: string;
            action: string;
            resource: string;
            claimedAt: number;
            amount?: bigint;
            counterpartyId?: string;
            termsCommitment?: ContentHash;
        }>;
        authoritative: true;
        consequential: true;
        evaluationTime: number;
        policyVersion: string;
        rootRecognitionPolicy: "declared-principal-root/0.2";
        eventHistoryHash: `0x${string}`;
        eventHistoryPosition: number;
        transitionEventId: string;
        transitionEventType: "OBLIGATION_CREATED" | "OBLIGATION_PERFORMANCE_ASSIGNED" | "OBLIGATION_STATUS_RECORDED" | "OUTCOME_OBSERVATION_RECORDED" | "ATTEMPT_DUTY_CREATED" | "ATTEMPT_DUTY_ASSIGNED" | "ATTEMPT_DUTY_REVIEW_CLOSED";
        runtimeSessionId: string;
        credentialKeyId: string;
        controlEpoch: number;
        roleId: string;
        roleTenureId: string;
    };
    authorityProof: Readonly<{
        proofVersion: typeof import("../core/portable-authority-engine.ts").PORTABLE_AUTHORIZATION_PROOF_VERSION;
        domain: import("../core/portable-replay.ts").PortableAuthorizationDomain;
        policyVersion: string;
        rootRecognitionPolicy: typeof import("../core/portable-authority-engine.ts").PORTABLE_ROOT_RECOGNITION_POLICY;
        historyHead: import("../core/portable-replay.ts").PortableHistoryHead;
        evaluationTime: number;
        request: import("../core/portable-authority-engine.ts").PortableActionRequest;
        recognizedRoot: import("../core/portable-replay.ts").PortableRecognizedRoot;
        permissionPath: readonly import("../core/portable-replay.ts").PortablePermissionGrant[];
        intersections: readonly import("../core/portable-authority-engine.ts").PortableIntersectionProof[];
        effectiveConstraints: import("../core/portable-replay.ts").PortableAuthorityConstraints;
        controllingAuthorityIds: readonly string[];
        usageSnapshot: readonly import("../core/portable-replay.ts").PortableAuthorityUsage[];
        authorityEvidence: readonly import("../core/portable-replay.ts").PortableAuthorityEvidence[];
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
    signingHash: `0x${string}`;
};
/** Re-derive rather than trust a caller-supplied preparation; append nothing. */
export declare function attachAdministrativeSignature(input: unknown, runtimeSignature: unknown): {
    event: {
        data: {
            administrativeAuthorization: {
                challenge: {
                    transitionEffectHash: `0x${string}`;
                    authorityProofHash: `0x${string}`;
                    version: "continuity-administrative-authorization/0.2";
                    domain: Readonly<{
                        protocol: "continuity";
                        version: "0.2";
                        deploymentId: string;
                        chainId: string;
                        verifyingContract: string;
                    }>;
                    request: Readonly<{
                        actorId: string;
                        action: string;
                        resource: string;
                        claimedAt: number;
                        amount?: bigint;
                        counterpartyId?: string;
                        termsCommitment?: ContentHash;
                    }>;
                    authoritative: true;
                    consequential: true;
                    evaluationTime: number;
                    policyVersion: string;
                    rootRecognitionPolicy: "declared-principal-root/0.2";
                    eventHistoryHash: `0x${string}`;
                    eventHistoryPosition: number;
                    transitionEventId: string;
                    transitionEventType: "OBLIGATION_CREATED" | "OBLIGATION_PERFORMANCE_ASSIGNED" | "OBLIGATION_STATUS_RECORDED" | "OUTCOME_OBSERVATION_RECORDED" | "ATTEMPT_DUTY_CREATED" | "ATTEMPT_DUTY_ASSIGNED" | "ATTEMPT_DUTY_REVIEW_CLOSED";
                    runtimeSessionId: string;
                    credentialKeyId: string;
                    controlEpoch: number;
                    roleId: string;
                    roleTenureId: string;
                };
                authorityProof: Readonly<{
                    proofVersion: typeof import("../core/portable-authority-engine.ts").PORTABLE_AUTHORIZATION_PROOF_VERSION;
                    domain: import("../core/portable-replay.ts").PortableAuthorizationDomain;
                    policyVersion: string;
                    rootRecognitionPolicy: typeof import("../core/portable-authority-engine.ts").PORTABLE_ROOT_RECOGNITION_POLICY;
                    historyHead: import("../core/portable-replay.ts").PortableHistoryHead;
                    evaluationTime: number;
                    request: import("../core/portable-authority-engine.ts").PortableActionRequest;
                    recognizedRoot: import("../core/portable-replay.ts").PortableRecognizedRoot;
                    permissionPath: readonly import("../core/portable-replay.ts").PortablePermissionGrant[];
                    intersections: readonly import("../core/portable-authority-engine.ts").PortableIntersectionProof[];
                    effectiveConstraints: import("../core/portable-replay.ts").PortableAuthorityConstraints;
                    controllingAuthorityIds: readonly string[];
                    usageSnapshot: readonly import("../core/portable-replay.ts").PortableAuthorityUsage[];
                    authorityEvidence: readonly import("../core/portable-replay.ts").PortableAuthorityEvidence[];
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
                runtimeSignature: string;
            };
        };
        id: string;
        type: TransitionKind;
        timestamp: number;
    };
    challenge: {
        transitionEffectHash: `0x${string}`;
        authorityProofHash: `0x${string}`;
        version: "continuity-administrative-authorization/0.2";
        domain: Readonly<{
            protocol: "continuity";
            version: "0.2";
            deploymentId: string;
            chainId: string;
            verifyingContract: string;
        }>;
        request: Readonly<{
            actorId: string;
            action: string;
            resource: string;
            claimedAt: number;
            amount?: bigint;
            counterpartyId?: string;
            termsCommitment?: ContentHash;
        }>;
        authoritative: true;
        consequential: true;
        evaluationTime: number;
        policyVersion: string;
        rootRecognitionPolicy: "declared-principal-root/0.2";
        eventHistoryHash: `0x${string}`;
        eventHistoryPosition: number;
        transitionEventId: string;
        transitionEventType: "OBLIGATION_CREATED" | "OBLIGATION_PERFORMANCE_ASSIGNED" | "OBLIGATION_STATUS_RECORDED" | "OUTCOME_OBSERVATION_RECORDED" | "ATTEMPT_DUTY_CREATED" | "ATTEMPT_DUTY_ASSIGNED" | "ATTEMPT_DUTY_REVIEW_CLOSED";
        runtimeSessionId: string;
        credentialKeyId: string;
        controlEpoch: number;
        roleId: string;
        roleTenureId: string;
    };
    authorityProof: Readonly<{
        proofVersion: typeof import("../core/portable-authority-engine.ts").PORTABLE_AUTHORIZATION_PROOF_VERSION;
        domain: import("../core/portable-replay.ts").PortableAuthorizationDomain;
        policyVersion: string;
        rootRecognitionPolicy: typeof import("../core/portable-authority-engine.ts").PORTABLE_ROOT_RECOGNITION_POLICY;
        historyHead: import("../core/portable-replay.ts").PortableHistoryHead;
        evaluationTime: number;
        request: import("../core/portable-authority-engine.ts").PortableActionRequest;
        recognizedRoot: import("../core/portable-replay.ts").PortableRecognizedRoot;
        permissionPath: readonly import("../core/portable-replay.ts").PortablePermissionGrant[];
        intersections: readonly import("../core/portable-authority-engine.ts").PortableIntersectionProof[];
        effectiveConstraints: import("../core/portable-replay.ts").PortableAuthorityConstraints;
        controllingAuthorityIds: readonly string[];
        usageSnapshot: readonly import("../core/portable-replay.ts").PortableAuthorityUsage[];
        authorityEvidence: readonly import("../core/portable-replay.ts").PortableAuthorityEvidence[];
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
    signingHash: `0x${string}`;
    replayHead: Readonly<{
        hash: ContentHash;
        position: number;
        canonicalTime: number;
    }>;
};
/** The callback receives only one hash. No retry, alternate session or signing implementation. */
export declare function produceAdministrativeEvent(input: unknown, options: unknown): Promise<{
    event: {
        data: {
            administrativeAuthorization: {
                challenge: {
                    transitionEffectHash: `0x${string}`;
                    authorityProofHash: `0x${string}`;
                    version: "continuity-administrative-authorization/0.2";
                    domain: Readonly<{
                        protocol: "continuity";
                        version: "0.2";
                        deploymentId: string;
                        chainId: string;
                        verifyingContract: string;
                    }>;
                    request: Readonly<{
                        actorId: string;
                        action: string;
                        resource: string;
                        claimedAt: number;
                        amount?: bigint;
                        counterpartyId?: string;
                        termsCommitment?: ContentHash;
                    }>;
                    authoritative: true;
                    consequential: true;
                    evaluationTime: number;
                    policyVersion: string;
                    rootRecognitionPolicy: "declared-principal-root/0.2";
                    eventHistoryHash: `0x${string}`;
                    eventHistoryPosition: number;
                    transitionEventId: string;
                    transitionEventType: "OBLIGATION_CREATED" | "OBLIGATION_PERFORMANCE_ASSIGNED" | "OBLIGATION_STATUS_RECORDED" | "OUTCOME_OBSERVATION_RECORDED" | "ATTEMPT_DUTY_CREATED" | "ATTEMPT_DUTY_ASSIGNED" | "ATTEMPT_DUTY_REVIEW_CLOSED";
                    runtimeSessionId: string;
                    credentialKeyId: string;
                    controlEpoch: number;
                    roleId: string;
                    roleTenureId: string;
                };
                authorityProof: Readonly<{
                    proofVersion: typeof import("../core/portable-authority-engine.ts").PORTABLE_AUTHORIZATION_PROOF_VERSION;
                    domain: import("../core/portable-replay.ts").PortableAuthorizationDomain;
                    policyVersion: string;
                    rootRecognitionPolicy: typeof import("../core/portable-authority-engine.ts").PORTABLE_ROOT_RECOGNITION_POLICY;
                    historyHead: import("../core/portable-replay.ts").PortableHistoryHead;
                    evaluationTime: number;
                    request: import("../core/portable-authority-engine.ts").PortableActionRequest;
                    recognizedRoot: import("../core/portable-replay.ts").PortableRecognizedRoot;
                    permissionPath: readonly import("../core/portable-replay.ts").PortablePermissionGrant[];
                    intersections: readonly import("../core/portable-authority-engine.ts").PortableIntersectionProof[];
                    effectiveConstraints: import("../core/portable-replay.ts").PortableAuthorityConstraints;
                    controllingAuthorityIds: readonly string[];
                    usageSnapshot: readonly import("../core/portable-replay.ts").PortableAuthorityUsage[];
                    authorityEvidence: readonly import("../core/portable-replay.ts").PortableAuthorityEvidence[];
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
                runtimeSignature: string;
            };
        };
        id: string;
        type: TransitionKind;
        timestamp: number;
    };
    challenge: {
        transitionEffectHash: `0x${string}`;
        authorityProofHash: `0x${string}`;
        version: "continuity-administrative-authorization/0.2";
        domain: Readonly<{
            protocol: "continuity";
            version: "0.2";
            deploymentId: string;
            chainId: string;
            verifyingContract: string;
        }>;
        request: Readonly<{
            actorId: string;
            action: string;
            resource: string;
            claimedAt: number;
            amount?: bigint;
            counterpartyId?: string;
            termsCommitment?: ContentHash;
        }>;
        authoritative: true;
        consequential: true;
        evaluationTime: number;
        policyVersion: string;
        rootRecognitionPolicy: "declared-principal-root/0.2";
        eventHistoryHash: `0x${string}`;
        eventHistoryPosition: number;
        transitionEventId: string;
        transitionEventType: "OBLIGATION_CREATED" | "OBLIGATION_PERFORMANCE_ASSIGNED" | "OBLIGATION_STATUS_RECORDED" | "OUTCOME_OBSERVATION_RECORDED" | "ATTEMPT_DUTY_CREATED" | "ATTEMPT_DUTY_ASSIGNED" | "ATTEMPT_DUTY_REVIEW_CLOSED";
        runtimeSessionId: string;
        credentialKeyId: string;
        controlEpoch: number;
        roleId: string;
        roleTenureId: string;
    };
    authorityProof: Readonly<{
        proofVersion: typeof import("../core/portable-authority-engine.ts").PORTABLE_AUTHORIZATION_PROOF_VERSION;
        domain: import("../core/portable-replay.ts").PortableAuthorizationDomain;
        policyVersion: string;
        rootRecognitionPolicy: typeof import("../core/portable-authority-engine.ts").PORTABLE_ROOT_RECOGNITION_POLICY;
        historyHead: import("../core/portable-replay.ts").PortableHistoryHead;
        evaluationTime: number;
        request: import("../core/portable-authority-engine.ts").PortableActionRequest;
        recognizedRoot: import("../core/portable-replay.ts").PortableRecognizedRoot;
        permissionPath: readonly import("../core/portable-replay.ts").PortablePermissionGrant[];
        intersections: readonly import("../core/portable-authority-engine.ts").PortableIntersectionProof[];
        effectiveConstraints: import("../core/portable-replay.ts").PortableAuthorityConstraints;
        controllingAuthorityIds: readonly string[];
        usageSnapshot: readonly import("../core/portable-replay.ts").PortableAuthorityUsage[];
        authorityEvidence: readonly import("../core/portable-replay.ts").PortableAuthorityEvidence[];
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
    signingHash: `0x${string}`;
    replayHead: Readonly<{
        hash: ContentHash;
        position: number;
        canonicalTime: number;
    }>;
}>;
export declare function prepareHistoryAdministrativeEvent(history: unknown, input: unknown): {
    transition: Readonly<{
        id: string;
        type: TransitionKind;
        timestamp: number;
        data: Readonly<Record<string, unknown>>;
    }>;
    challenge: {
        transitionEffectHash: `0x${string}`;
        authorityProofHash: `0x${string}`;
        version: "continuity-administrative-authorization/0.2";
        domain: Readonly<{
            protocol: "continuity";
            version: "0.2";
            deploymentId: string;
            chainId: string;
            verifyingContract: string;
        }>;
        request: Readonly<{
            actorId: string;
            action: string;
            resource: string;
            claimedAt: number;
            amount?: bigint;
            counterpartyId?: string;
            termsCommitment?: ContentHash;
        }>;
        authoritative: true;
        consequential: true;
        evaluationTime: number;
        policyVersion: string;
        rootRecognitionPolicy: "declared-principal-root/0.2";
        eventHistoryHash: `0x${string}`;
        eventHistoryPosition: number;
        transitionEventId: string;
        transitionEventType: "OBLIGATION_CREATED" | "OBLIGATION_PERFORMANCE_ASSIGNED" | "OBLIGATION_STATUS_RECORDED" | "OUTCOME_OBSERVATION_RECORDED" | "ATTEMPT_DUTY_CREATED" | "ATTEMPT_DUTY_ASSIGNED" | "ATTEMPT_DUTY_REVIEW_CLOSED";
        runtimeSessionId: string;
        credentialKeyId: string;
        controlEpoch: number;
        roleId: string;
        roleTenureId: string;
    };
    authorityProof: Readonly<{
        proofVersion: typeof import("../core/portable-authority-engine.ts").PORTABLE_AUTHORIZATION_PROOF_VERSION;
        domain: import("../core/portable-replay.ts").PortableAuthorizationDomain;
        policyVersion: string;
        rootRecognitionPolicy: typeof import("../core/portable-authority-engine.ts").PORTABLE_ROOT_RECOGNITION_POLICY;
        historyHead: import("../core/portable-replay.ts").PortableHistoryHead;
        evaluationTime: number;
        request: import("../core/portable-authority-engine.ts").PortableActionRequest;
        recognizedRoot: import("../core/portable-replay.ts").PortableRecognizedRoot;
        permissionPath: readonly import("../core/portable-replay.ts").PortablePermissionGrant[];
        intersections: readonly import("../core/portable-authority-engine.ts").PortableIntersectionProof[];
        effectiveConstraints: import("../core/portable-replay.ts").PortableAuthorityConstraints;
        controllingAuthorityIds: readonly string[];
        usageSnapshot: readonly import("../core/portable-replay.ts").PortableAuthorityUsage[];
        authorityEvidence: readonly import("../core/portable-replay.ts").PortableAuthorityEvidence[];
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
    signingHash: `0x${string}`;
};
export declare function attachHistoryAdministrativeSignature(history: unknown, input: unknown, signature: unknown): {
    event: {
        data: {
            administrativeAuthorization: {
                challenge: {
                    transitionEffectHash: `0x${string}`;
                    authorityProofHash: `0x${string}`;
                    version: "continuity-administrative-authorization/0.2";
                    domain: Readonly<{
                        protocol: "continuity";
                        version: "0.2";
                        deploymentId: string;
                        chainId: string;
                        verifyingContract: string;
                    }>;
                    request: Readonly<{
                        actorId: string;
                        action: string;
                        resource: string;
                        claimedAt: number;
                        amount?: bigint;
                        counterpartyId?: string;
                        termsCommitment?: ContentHash;
                    }>;
                    authoritative: true;
                    consequential: true;
                    evaluationTime: number;
                    policyVersion: string;
                    rootRecognitionPolicy: "declared-principal-root/0.2";
                    eventHistoryHash: `0x${string}`;
                    eventHistoryPosition: number;
                    transitionEventId: string;
                    transitionEventType: "OBLIGATION_CREATED" | "OBLIGATION_PERFORMANCE_ASSIGNED" | "OBLIGATION_STATUS_RECORDED" | "OUTCOME_OBSERVATION_RECORDED" | "ATTEMPT_DUTY_CREATED" | "ATTEMPT_DUTY_ASSIGNED" | "ATTEMPT_DUTY_REVIEW_CLOSED";
                    runtimeSessionId: string;
                    credentialKeyId: string;
                    controlEpoch: number;
                    roleId: string;
                    roleTenureId: string;
                };
                authorityProof: Readonly<{
                    proofVersion: typeof import("../core/portable-authority-engine.ts").PORTABLE_AUTHORIZATION_PROOF_VERSION;
                    domain: import("../core/portable-replay.ts").PortableAuthorizationDomain;
                    policyVersion: string;
                    rootRecognitionPolicy: typeof import("../core/portable-authority-engine.ts").PORTABLE_ROOT_RECOGNITION_POLICY;
                    historyHead: import("../core/portable-replay.ts").PortableHistoryHead;
                    evaluationTime: number;
                    request: import("../core/portable-authority-engine.ts").PortableActionRequest;
                    recognizedRoot: import("../core/portable-replay.ts").PortableRecognizedRoot;
                    permissionPath: readonly import("../core/portable-replay.ts").PortablePermissionGrant[];
                    intersections: readonly import("../core/portable-authority-engine.ts").PortableIntersectionProof[];
                    effectiveConstraints: import("../core/portable-replay.ts").PortableAuthorityConstraints;
                    controllingAuthorityIds: readonly string[];
                    usageSnapshot: readonly import("../core/portable-replay.ts").PortableAuthorityUsage[];
                    authorityEvidence: readonly import("../core/portable-replay.ts").PortableAuthorityEvidence[];
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
                runtimeSignature: string;
            };
        };
        id: string;
        type: TransitionKind;
        timestamp: number;
    };
    challenge: {
        transitionEffectHash: `0x${string}`;
        authorityProofHash: `0x${string}`;
        version: "continuity-administrative-authorization/0.2";
        domain: Readonly<{
            protocol: "continuity";
            version: "0.2";
            deploymentId: string;
            chainId: string;
            verifyingContract: string;
        }>;
        request: Readonly<{
            actorId: string;
            action: string;
            resource: string;
            claimedAt: number;
            amount?: bigint;
            counterpartyId?: string;
            termsCommitment?: ContentHash;
        }>;
        authoritative: true;
        consequential: true;
        evaluationTime: number;
        policyVersion: string;
        rootRecognitionPolicy: "declared-principal-root/0.2";
        eventHistoryHash: `0x${string}`;
        eventHistoryPosition: number;
        transitionEventId: string;
        transitionEventType: "OBLIGATION_CREATED" | "OBLIGATION_PERFORMANCE_ASSIGNED" | "OBLIGATION_STATUS_RECORDED" | "OUTCOME_OBSERVATION_RECORDED" | "ATTEMPT_DUTY_CREATED" | "ATTEMPT_DUTY_ASSIGNED" | "ATTEMPT_DUTY_REVIEW_CLOSED";
        runtimeSessionId: string;
        credentialKeyId: string;
        controlEpoch: number;
        roleId: string;
        roleTenureId: string;
    };
    authorityProof: Readonly<{
        proofVersion: typeof import("../core/portable-authority-engine.ts").PORTABLE_AUTHORIZATION_PROOF_VERSION;
        domain: import("../core/portable-replay.ts").PortableAuthorizationDomain;
        policyVersion: string;
        rootRecognitionPolicy: typeof import("../core/portable-authority-engine.ts").PORTABLE_ROOT_RECOGNITION_POLICY;
        historyHead: import("../core/portable-replay.ts").PortableHistoryHead;
        evaluationTime: number;
        request: import("../core/portable-authority-engine.ts").PortableActionRequest;
        recognizedRoot: import("../core/portable-replay.ts").PortableRecognizedRoot;
        permissionPath: readonly import("../core/portable-replay.ts").PortablePermissionGrant[];
        intersections: readonly import("../core/portable-authority-engine.ts").PortableIntersectionProof[];
        effectiveConstraints: import("../core/portable-replay.ts").PortableAuthorityConstraints;
        controllingAuthorityIds: readonly string[];
        usageSnapshot: readonly import("../core/portable-replay.ts").PortableAuthorityUsage[];
        authorityEvidence: readonly import("../core/portable-replay.ts").PortableAuthorityEvidence[];
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
    signingHash: `0x${string}`;
    replayHead: Readonly<{
        hash: ContentHash;
        position: number;
        canonicalTime: number;
    }>;
};
export declare function produceHistoryAdministrativeEvent(history: unknown, input: unknown, options: unknown): Promise<{
    event: {
        data: {
            administrativeAuthorization: {
                challenge: {
                    transitionEffectHash: `0x${string}`;
                    authorityProofHash: `0x${string}`;
                    version: "continuity-administrative-authorization/0.2";
                    domain: Readonly<{
                        protocol: "continuity";
                        version: "0.2";
                        deploymentId: string;
                        chainId: string;
                        verifyingContract: string;
                    }>;
                    request: Readonly<{
                        actorId: string;
                        action: string;
                        resource: string;
                        claimedAt: number;
                        amount?: bigint;
                        counterpartyId?: string;
                        termsCommitment?: ContentHash;
                    }>;
                    authoritative: true;
                    consequential: true;
                    evaluationTime: number;
                    policyVersion: string;
                    rootRecognitionPolicy: "declared-principal-root/0.2";
                    eventHistoryHash: `0x${string}`;
                    eventHistoryPosition: number;
                    transitionEventId: string;
                    transitionEventType: "OBLIGATION_CREATED" | "OBLIGATION_PERFORMANCE_ASSIGNED" | "OBLIGATION_STATUS_RECORDED" | "OUTCOME_OBSERVATION_RECORDED" | "ATTEMPT_DUTY_CREATED" | "ATTEMPT_DUTY_ASSIGNED" | "ATTEMPT_DUTY_REVIEW_CLOSED";
                    runtimeSessionId: string;
                    credentialKeyId: string;
                    controlEpoch: number;
                    roleId: string;
                    roleTenureId: string;
                };
                authorityProof: Readonly<{
                    proofVersion: typeof import("../core/portable-authority-engine.ts").PORTABLE_AUTHORIZATION_PROOF_VERSION;
                    domain: import("../core/portable-replay.ts").PortableAuthorizationDomain;
                    policyVersion: string;
                    rootRecognitionPolicy: typeof import("../core/portable-authority-engine.ts").PORTABLE_ROOT_RECOGNITION_POLICY;
                    historyHead: import("../core/portable-replay.ts").PortableHistoryHead;
                    evaluationTime: number;
                    request: import("../core/portable-authority-engine.ts").PortableActionRequest;
                    recognizedRoot: import("../core/portable-replay.ts").PortableRecognizedRoot;
                    permissionPath: readonly import("../core/portable-replay.ts").PortablePermissionGrant[];
                    intersections: readonly import("../core/portable-authority-engine.ts").PortableIntersectionProof[];
                    effectiveConstraints: import("../core/portable-replay.ts").PortableAuthorityConstraints;
                    controllingAuthorityIds: readonly string[];
                    usageSnapshot: readonly import("../core/portable-replay.ts").PortableAuthorityUsage[];
                    authorityEvidence: readonly import("../core/portable-replay.ts").PortableAuthorityEvidence[];
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
                runtimeSignature: string;
            };
        };
        id: string;
        type: TransitionKind;
        timestamp: number;
    };
    challenge: {
        transitionEffectHash: `0x${string}`;
        authorityProofHash: `0x${string}`;
        version: "continuity-administrative-authorization/0.2";
        domain: Readonly<{
            protocol: "continuity";
            version: "0.2";
            deploymentId: string;
            chainId: string;
            verifyingContract: string;
        }>;
        request: Readonly<{
            actorId: string;
            action: string;
            resource: string;
            claimedAt: number;
            amount?: bigint;
            counterpartyId?: string;
            termsCommitment?: ContentHash;
        }>;
        authoritative: true;
        consequential: true;
        evaluationTime: number;
        policyVersion: string;
        rootRecognitionPolicy: "declared-principal-root/0.2";
        eventHistoryHash: `0x${string}`;
        eventHistoryPosition: number;
        transitionEventId: string;
        transitionEventType: "OBLIGATION_CREATED" | "OBLIGATION_PERFORMANCE_ASSIGNED" | "OBLIGATION_STATUS_RECORDED" | "OUTCOME_OBSERVATION_RECORDED" | "ATTEMPT_DUTY_CREATED" | "ATTEMPT_DUTY_ASSIGNED" | "ATTEMPT_DUTY_REVIEW_CLOSED";
        runtimeSessionId: string;
        credentialKeyId: string;
        controlEpoch: number;
        roleId: string;
        roleTenureId: string;
    };
    authorityProof: Readonly<{
        proofVersion: typeof import("../core/portable-authority-engine.ts").PORTABLE_AUTHORIZATION_PROOF_VERSION;
        domain: import("../core/portable-replay.ts").PortableAuthorizationDomain;
        policyVersion: string;
        rootRecognitionPolicy: typeof import("../core/portable-authority-engine.ts").PORTABLE_ROOT_RECOGNITION_POLICY;
        historyHead: import("../core/portable-replay.ts").PortableHistoryHead;
        evaluationTime: number;
        request: import("../core/portable-authority-engine.ts").PortableActionRequest;
        recognizedRoot: import("../core/portable-replay.ts").PortableRecognizedRoot;
        permissionPath: readonly import("../core/portable-replay.ts").PortablePermissionGrant[];
        intersections: readonly import("../core/portable-authority-engine.ts").PortableIntersectionProof[];
        effectiveConstraints: import("../core/portable-replay.ts").PortableAuthorityConstraints;
        controllingAuthorityIds: readonly string[];
        usageSnapshot: readonly import("../core/portable-replay.ts").PortableAuthorityUsage[];
        authorityEvidence: readonly import("../core/portable-replay.ts").PortableAuthorityEvidence[];
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
    signingHash: `0x${string}`;
    replayHead: Readonly<{
        hash: ContentHash;
        position: number;
        canonicalTime: number;
    }>;
}>;
export {};
