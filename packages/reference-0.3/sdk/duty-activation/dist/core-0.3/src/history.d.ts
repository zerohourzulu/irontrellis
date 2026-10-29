/** Experimental history-aware pure operations. No durable writes or adapter dispatch. */
import * as core from "../../core-0.2/src/core/index.ts";
import { captureContinuationHistory, continuationPrefix, exportContinuationEvents, appendContinuationEvent, CONTINUATION_HISTORY_VERSION, CONTINUATION_PROFILE, HistoryError, type VerifiedHistory } from "../../core-0.2/src/history/index.ts";
export { captureContinuationHistory, continuationPrefix, exportContinuationEvents, appendContinuationEvent, CONTINUATION_HISTORY_VERSION, CONTINUATION_PROFILE, HistoryError };
export type { VerifiedHistory };
export declare const HISTORY_OPERATION_VERSION: "continuity-history-operation/1";
export declare function authorizeContinuation(history: unknown, input: unknown): Readonly<{
    version: "continuity-history-operation/1";
    profile: "continuity-segmented-local/1";
    historyHead: Readonly<{
        hash: core.ContentHash;
        position: number;
        canonicalTime: number;
    }>;
    scope: "CAPTURED_HISTORY_ONLY";
    executionCapability: false;
    result: core.PortableAuthorizationResult;
}>;
export declare function proposeContinuationAdmission(history: unknown, input: unknown): Readonly<{
    version: "continuity-history-operation/1";
    profile: "continuity-segmented-local/1";
    historyHead: Readonly<{
        hash: core.ContentHash;
        position: number;
        canonicalTime: number;
    }>;
    scope: "CAPTURED_HISTORY_ONLY";
    executionCapability: false;
    result: core.PortableIntentAdmissionResult;
}>;
export declare function continuationRuntimeChallenge(history: unknown, input: unknown): Readonly<{
    version: "continuity-history-operation/1";
    profile: "continuity-segmented-local/1";
    historyHead: Readonly<{
        hash: core.ContentHash;
        position: number;
        canonicalTime: number;
    }>;
    scope: "CAPTURED_HISTORY_ONLY";
    executionCapability: false;
    result: Readonly<{
        version: typeof core.PORTABLE_RUNTIME_AUTHORIZATION_VERSION;
        domain: core.PortableAuthorizationDomain;
        request: core.PortableActionRequest;
        authoritative: true;
        consequential: true;
        evaluationTime: number;
        policyVersion: string;
        rootRecognitionPolicy: typeof core.PORTABLE_ROOT_RECOGNITION_POLICY;
        eventHistoryHash: core.ContentHash;
        eventHistoryPosition: number;
        runtimeSessionId: string;
        credentialKeyId: string;
        controlEpoch: number;
        roleId: string;
        roleTenureId: string;
        intentId: string;
        nonce: string;
    }>;
}>;
export declare function prepareContinuationAdministration(history: unknown, input: unknown): Readonly<{
    version: "continuity-history-operation/1";
    profile: "continuity-segmented-local/1";
    historyHead: Readonly<{
        hash: core.ContentHash;
        position: number;
        canonicalTime: number;
    }>;
    scope: "CAPTURED_HISTORY_ONLY";
    executionCapability: false;
    result: {
        transition: Readonly<{
            id: string;
            type: "OBLIGATION_CREATED" | "OBLIGATION_PERFORMANCE_ASSIGNED" | "OBLIGATION_STATUS_RECORDED" | "OUTCOME_OBSERVATION_RECORDED" | "ATTEMPT_DUTY_CREATED" | "ATTEMPT_DUTY_ASSIGNED" | "ATTEMPT_DUTY_REVIEW_CLOSED" | "ATTEMPT_DUTY_POLICY_ACTIVATED";
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
                termsCommitment?: core.ContentHash;
            }>;
            authoritative: true;
            consequential: true;
            evaluationTime: number;
            policyVersion: string;
            rootRecognitionPolicy: "declared-principal-root/0.2";
            eventHistoryHash: `0x${string}`;
            eventHistoryPosition: number;
            transitionEventId: string;
            transitionEventType: "OBLIGATION_CREATED" | "OBLIGATION_PERFORMANCE_ASSIGNED" | "OBLIGATION_STATUS_RECORDED" | "OUTCOME_OBSERVATION_RECORDED" | "ATTEMPT_DUTY_CREATED" | "ATTEMPT_DUTY_ASSIGNED" | "ATTEMPT_DUTY_REVIEW_CLOSED" | "ATTEMPT_DUTY_POLICY_ACTIVATED";
            runtimeSessionId: string;
            credentialKeyId: string;
            controlEpoch: number;
            roleId: string;
            roleTenureId: string;
        };
        authorityProof: Readonly<{
            proofVersion: typeof core.PORTABLE_AUTHORIZATION_PROOF_VERSION;
            domain: core.PortableAuthorizationDomain;
            policyVersion: string;
            rootRecognitionPolicy: typeof core.PORTABLE_ROOT_RECOGNITION_POLICY;
            historyHead: core.PortableHistoryHead;
            evaluationTime: number;
            request: core.PortableActionRequest;
            recognizedRoot: core.PortableRecognizedRoot;
            permissionPath: readonly core.PortablePermissionGrant[];
            intersections: readonly core.PortableIntersectionProof[];
            effectiveConstraints: core.PortableAuthorityConstraints;
            controllingAuthorityIds: readonly string[];
            usageSnapshot: readonly core.PortableAuthorityUsage[];
            authorityEvidence: readonly core.PortableAuthorityEvidence[];
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
}>;
export declare function attachContinuationAdministration(history: unknown, input: unknown, signature: unknown): Readonly<{
    version: "continuity-history-operation/1";
    profile: "continuity-segmented-local/1";
    historyHead: Readonly<{
        hash: core.ContentHash;
        position: number;
        canonicalTime: number;
    }>;
    scope: "CAPTURED_HISTORY_ONLY";
    executionCapability: false;
    result: {
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
                            termsCommitment?: core.ContentHash;
                        }>;
                        authoritative: true;
                        consequential: true;
                        evaluationTime: number;
                        policyVersion: string;
                        rootRecognitionPolicy: "declared-principal-root/0.2";
                        eventHistoryHash: `0x${string}`;
                        eventHistoryPosition: number;
                        transitionEventId: string;
                        transitionEventType: "OBLIGATION_CREATED" | "OBLIGATION_PERFORMANCE_ASSIGNED" | "OBLIGATION_STATUS_RECORDED" | "OUTCOME_OBSERVATION_RECORDED" | "ATTEMPT_DUTY_CREATED" | "ATTEMPT_DUTY_ASSIGNED" | "ATTEMPT_DUTY_REVIEW_CLOSED" | "ATTEMPT_DUTY_POLICY_ACTIVATED";
                        runtimeSessionId: string;
                        credentialKeyId: string;
                        controlEpoch: number;
                        roleId: string;
                        roleTenureId: string;
                    };
                    authorityProof: Readonly<{
                        proofVersion: typeof core.PORTABLE_AUTHORIZATION_PROOF_VERSION;
                        domain: core.PortableAuthorizationDomain;
                        policyVersion: string;
                        rootRecognitionPolicy: typeof core.PORTABLE_ROOT_RECOGNITION_POLICY;
                        historyHead: core.PortableHistoryHead;
                        evaluationTime: number;
                        request: core.PortableActionRequest;
                        recognizedRoot: core.PortableRecognizedRoot;
                        permissionPath: readonly core.PortablePermissionGrant[];
                        intersections: readonly core.PortableIntersectionProof[];
                        effectiveConstraints: core.PortableAuthorityConstraints;
                        controllingAuthorityIds: readonly string[];
                        usageSnapshot: readonly core.PortableAuthorityUsage[];
                        authorityEvidence: readonly core.PortableAuthorityEvidence[];
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
            type: "OBLIGATION_CREATED" | "OBLIGATION_PERFORMANCE_ASSIGNED" | "OBLIGATION_STATUS_RECORDED" | "OUTCOME_OBSERVATION_RECORDED" | "ATTEMPT_DUTY_CREATED" | "ATTEMPT_DUTY_ASSIGNED" | "ATTEMPT_DUTY_REVIEW_CLOSED" | "ATTEMPT_DUTY_POLICY_ACTIVATED";
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
                termsCommitment?: core.ContentHash;
            }>;
            authoritative: true;
            consequential: true;
            evaluationTime: number;
            policyVersion: string;
            rootRecognitionPolicy: "declared-principal-root/0.2";
            eventHistoryHash: `0x${string}`;
            eventHistoryPosition: number;
            transitionEventId: string;
            transitionEventType: "OBLIGATION_CREATED" | "OBLIGATION_PERFORMANCE_ASSIGNED" | "OBLIGATION_STATUS_RECORDED" | "OUTCOME_OBSERVATION_RECORDED" | "ATTEMPT_DUTY_CREATED" | "ATTEMPT_DUTY_ASSIGNED" | "ATTEMPT_DUTY_REVIEW_CLOSED" | "ATTEMPT_DUTY_POLICY_ACTIVATED";
            runtimeSessionId: string;
            credentialKeyId: string;
            controlEpoch: number;
            roleId: string;
            roleTenureId: string;
        };
        authorityProof: Readonly<{
            proofVersion: typeof core.PORTABLE_AUTHORIZATION_PROOF_VERSION;
            domain: core.PortableAuthorizationDomain;
            policyVersion: string;
            rootRecognitionPolicy: typeof core.PORTABLE_ROOT_RECOGNITION_POLICY;
            historyHead: core.PortableHistoryHead;
            evaluationTime: number;
            request: core.PortableActionRequest;
            recognizedRoot: core.PortableRecognizedRoot;
            permissionPath: readonly core.PortablePermissionGrant[];
            intersections: readonly core.PortableIntersectionProof[];
            effectiveConstraints: core.PortableAuthorityConstraints;
            controllingAuthorityIds: readonly string[];
            usageSnapshot: readonly core.PortableAuthorityUsage[];
            authorityEvidence: readonly core.PortableAuthorityEvidence[];
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
            hash: core.ContentHash;
            position: number;
            canonicalTime: number;
        }>;
    };
}>;
export declare function produceContinuationAdministration(history: unknown, input: unknown, options: unknown): Promise<Readonly<{
    version: "continuity-history-operation/1";
    profile: "continuity-segmented-local/1";
    historyHead: Readonly<{
        hash: core.ContentHash;
        position: number;
        canonicalTime: number;
    }>;
    scope: "CAPTURED_HISTORY_ONLY";
    executionCapability: false;
    result: {
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
                            termsCommitment?: core.ContentHash;
                        }>;
                        authoritative: true;
                        consequential: true;
                        evaluationTime: number;
                        policyVersion: string;
                        rootRecognitionPolicy: "declared-principal-root/0.2";
                        eventHistoryHash: `0x${string}`;
                        eventHistoryPosition: number;
                        transitionEventId: string;
                        transitionEventType: "OBLIGATION_CREATED" | "OBLIGATION_PERFORMANCE_ASSIGNED" | "OBLIGATION_STATUS_RECORDED" | "OUTCOME_OBSERVATION_RECORDED" | "ATTEMPT_DUTY_CREATED" | "ATTEMPT_DUTY_ASSIGNED" | "ATTEMPT_DUTY_REVIEW_CLOSED" | "ATTEMPT_DUTY_POLICY_ACTIVATED";
                        runtimeSessionId: string;
                        credentialKeyId: string;
                        controlEpoch: number;
                        roleId: string;
                        roleTenureId: string;
                    };
                    authorityProof: Readonly<{
                        proofVersion: typeof core.PORTABLE_AUTHORIZATION_PROOF_VERSION;
                        domain: core.PortableAuthorizationDomain;
                        policyVersion: string;
                        rootRecognitionPolicy: typeof core.PORTABLE_ROOT_RECOGNITION_POLICY;
                        historyHead: core.PortableHistoryHead;
                        evaluationTime: number;
                        request: core.PortableActionRequest;
                        recognizedRoot: core.PortableRecognizedRoot;
                        permissionPath: readonly core.PortablePermissionGrant[];
                        intersections: readonly core.PortableIntersectionProof[];
                        effectiveConstraints: core.PortableAuthorityConstraints;
                        controllingAuthorityIds: readonly string[];
                        usageSnapshot: readonly core.PortableAuthorityUsage[];
                        authorityEvidence: readonly core.PortableAuthorityEvidence[];
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
            type: "OBLIGATION_CREATED" | "OBLIGATION_PERFORMANCE_ASSIGNED" | "OBLIGATION_STATUS_RECORDED" | "OUTCOME_OBSERVATION_RECORDED" | "ATTEMPT_DUTY_CREATED" | "ATTEMPT_DUTY_ASSIGNED" | "ATTEMPT_DUTY_REVIEW_CLOSED" | "ATTEMPT_DUTY_POLICY_ACTIVATED";
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
                termsCommitment?: core.ContentHash;
            }>;
            authoritative: true;
            consequential: true;
            evaluationTime: number;
            policyVersion: string;
            rootRecognitionPolicy: "declared-principal-root/0.2";
            eventHistoryHash: `0x${string}`;
            eventHistoryPosition: number;
            transitionEventId: string;
            transitionEventType: "OBLIGATION_CREATED" | "OBLIGATION_PERFORMANCE_ASSIGNED" | "OBLIGATION_STATUS_RECORDED" | "OUTCOME_OBSERVATION_RECORDED" | "ATTEMPT_DUTY_CREATED" | "ATTEMPT_DUTY_ASSIGNED" | "ATTEMPT_DUTY_REVIEW_CLOSED" | "ATTEMPT_DUTY_POLICY_ACTIVATED";
            runtimeSessionId: string;
            credentialKeyId: string;
            controlEpoch: number;
            roleId: string;
            roleTenureId: string;
        };
        authorityProof: Readonly<{
            proofVersion: typeof core.PORTABLE_AUTHORIZATION_PROOF_VERSION;
            domain: core.PortableAuthorizationDomain;
            policyVersion: string;
            rootRecognitionPolicy: typeof core.PORTABLE_ROOT_RECOGNITION_POLICY;
            historyHead: core.PortableHistoryHead;
            evaluationTime: number;
            request: core.PortableActionRequest;
            recognizedRoot: core.PortableRecognizedRoot;
            permissionPath: readonly core.PortablePermissionGrant[];
            intersections: readonly core.PortableIntersectionProof[];
            effectiveConstraints: core.PortableAuthorityConstraints;
            controllingAuthorityIds: readonly string[];
            usageSnapshot: readonly core.PortableAuthorityUsage[];
            authorityEvidence: readonly core.PortableAuthorityEvidence[];
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
            hash: core.ContentHash;
            position: number;
            canonicalTime: number;
        }>;
    };
}>>;
export declare function createContinuationReceipt(history: unknown, input: unknown, signer: core.PortableReceiptSigner): Promise<Readonly<{
    version: "continuity-history-operation/1";
    profile: "continuity-segmented-local/1";
    historyHead: Readonly<{
        hash: core.ContentHash;
        position: number;
        canonicalTime: number;
    }>;
    scope: "CAPTURED_HISTORY_ONLY";
    executionCapability: false;
    result: Readonly<{
        payload: core.PortableReceiptPayload;
        contentHash: core.ContentHash;
        signature: `0x${string}`;
    }>;
}>>;
export declare function verifyContinuationReceipt(issuance: unknown, observed: unknown, input: unknown): Readonly<{
    version: "continuity-history-operation/1";
    profile: "continuity-segmented-local/1";
    historyHead: Readonly<{
        hash: core.ContentHash;
        position: number;
        canonicalTime: number;
    }>;
    scope: "CAPTURED_HISTORY_ONLY";
    executionCapability: false;
    result: core.PortableReceiptVerificationResult;
}>;
export declare function proposeContinuationReceiptRecord(history: unknown, input: unknown): Readonly<{
    version: "continuity-history-operation/1";
    profile: "continuity-segmented-local/1";
    historyHead: Readonly<{
        hash: core.ContentHash;
        position: number;
        canonicalTime: number;
    }>;
    scope: "CAPTURED_HISTORY_ONLY";
    executionCapability: false;
    result: core.PortableReceiptRecordProposal;
}>;
export declare function queryContinuation(kind: "WHY" | "RESPONSIBLE" | "SURVIVES", evaluation: unknown, observed: unknown, input: unknown): Readonly<{
    version: "continuity-history-operation/1";
    profile: "continuity-segmented-local/1";
    historyHead: Readonly<{
        hash: core.ContentHash;
        position: number;
        canonicalTime: number;
    }>;
    scope: "CAPTURED_HISTORY_ONLY";
    executionCapability: false;
    result: core.PortableWhyQueryResult | core.PortableResponsibleQueryResult | core.PortableSurvivesQueryResult;
}>;
