import * as core from "../../core-0.2/src/core/index.ts";
import type { TransactionAdapter } from "../../core-0.2/src/adapters/index.ts";
import { type AdditionalPolicy } from "./policy.ts";
import type { LocalOwnerOptions } from "./local-owner.ts";
/** An application-owned signing callback. Private keys never enter the history. */
export type SignHash = (hash: core.ContentHash) => Promise<`0x${string}`>;
export type LocalExecutionOptions = LocalOwnerOptions & Readonly<{
    session: string;
    signHash: SignHash;
    additionalPolicy?: AdditionalPolicy;
}>;
export type LocalOperation = Readonly<{
    id: string;
    action: string;
    resource: string;
    role: string;
    tenure: string;
    termsCommitment: core.ContentHash;
    /** Unsigned integer in the application's declared smallest unit. No currency conversion. */
    amount?: bigint;
    counterparty?: string;
}>;
/** Hash only bounded data. Keep the actual private terms in application storage. */
export declare function commitTerms(terms: unknown): core.ContentHash;
/**
 * Trusted local application configuration, not an untrusted-agent boundary.
 * This internal constructor accepts approved executable configuration only.
 * Public factories pin the supported adapter; no agent can inject one.
 */
export declare function openLocalExecution(options: LocalExecutionOptions, adapter: TransactionAdapter, mode: "SIMULATION" | "LOCAL_PACKET" | "REMOTE_REPORT"): Readonly<{
    profile: "EFFECT_FREE_SIMULATION" | "REMOTE_REPORTED_OUTCOME" | "LOCAL_EVIDENCE_PACKET";
    /** A committed admission is never re-invoked, including after a restart. */
    run(input: LocalOperation): Promise<Readonly<{
        status: "RECONCILIATION_ONLY";
        operationId: string;
        externalEffect: "LOCAL_PACKET" | "REMOTE_REPORTED_OUTCOME" | "NONE_SIMULATED";
        result: import("../../core-0.2/src/sdk/durable-admission.ts").PortableInvocationResult;
    }> | Readonly<{
        status: "NOT_AUTHORIZED";
        operationId: string;
        evidence: Readonly<{
            operationVersion: typeof core.PORTABLE_AUTHORITY_EVALUATION_VERSION | typeof core.PORTABLE_AUTHORIZATION_VERSION;
            decision: "DENY";
            scopeAssurance: "SUPPLIED_SCOPE" | "REPLAY_VERIFIED";
            consequential: false;
            code: core.PortableDenialCode;
            failures: readonly core.PortableDenialEvidence[];
        }> | Readonly<{
            operationVersion: typeof core.PORTABLE_AUTHORITY_EVALUATION_VERSION | typeof core.PORTABLE_AUTHORIZATION_VERSION;
            decision: "INDETERMINATE";
            scopeAssurance: "SUPPLIED_SCOPE" | "REPLAY_VERIFIED";
            consequential: false;
            code: core.PortableIndeterminateCode;
            failures: readonly core.PortableIndeterminateEvidence[];
        }>;
    }> | Readonly<{
        status: "POLICY_REFUSED";
        operationId: string;
        policyIdentity: string;
        reason: "DENY" | "ERROR";
    }> | Readonly<{
        status: "NOT_ADMITTED";
        operationId: string;
        admission: Readonly<{
            status: "INVALID_PREPARATION";
            reason: string;
        }> | Readonly<{
            status: "UNAVAILABLE";
            reason: string;
            admissionMayHavePersisted: boolean;
        }> | Readonly<{
            status: "NOT_ADMITTED";
            result: Exclude<core.PortableIntentAdmissionResult, {
                status: "PROPOSED";
            }>;
        }>;
    }> | Readonly<{
        status: "SIMULATION_RESULT" | "EXECUTION_RESULT";
        operationId: string;
        externalEffect: "LOCAL_PACKET" | "REMOTE_REPORTED_OUTCOME" | "NONE_SIMULATED";
        admission: Readonly<{
            operationVersion: "continuity-intent-admission/0.2";
            status: "ADMITTED";
            authorization: Extract<core.PortableIntentAdmissionResult, {
                status: "PROPOSED";
            }>["authorization"];
            admissionEvent: core.PortableIntentAdmissionEvent;
            newHead: core.PortableHistoryHead;
        }>;
        invocation: import("../../core-0.2/src/sdk/durable-admission.ts").PortableInvocationResult;
    }>>;
    /** Issue and record a signed receipt only for this session's actual simulated acknowledgment. */
    recordReceipt(input: LocalOperation): Promise<Readonly<{
        status: "ALREADY_RECORDED";
        contentHash: `0x${string}`;
        eventId: string;
        artifactAvailable: false;
    }> | Readonly<{
        status: "RECEIPT_RESULT";
        artifact: Readonly<{
            payload: core.PortableReceiptPayload;
            contentHash: core.ContentHash;
            signature: `0x${string}`;
        }>;
        recording: import("../../core-0.2/src/sdk/durable-receipt.ts").DurableReceiptRecordResult;
    }>>;
}>;
export type LocalExecution = ReturnType<typeof openLocalExecution>;
