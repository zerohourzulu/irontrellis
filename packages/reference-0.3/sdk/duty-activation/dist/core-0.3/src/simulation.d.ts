import { type LocalExecutionOptions } from "./execution.ts";
export { commitTerms } from "./execution.ts";
export type { SignHash, LocalExecutionOptions as LocalSimulationOptions, LocalOperation as SimulationOperation, } from "./execution.ts";
/** Effect-free, signed local execution example; no adapter injection. */
export declare function openLocalSimulation(options: LocalExecutionOptions): Readonly<{
    profile: "EFFECT_FREE_SIMULATION" | "REMOTE_REPORTED_OUTCOME" | "LOCAL_EVIDENCE_PACKET";
    run(input: import("./execution.ts").LocalOperation): Promise<Readonly<{
        status: "RECONCILIATION_ONLY";
        operationId: string;
        externalEffect: "LOCAL_PACKET" | "REMOTE_REPORTED_OUTCOME" | "NONE_SIMULATED";
        result: import("../../core-0.2/src/sdk/durable-admission.ts").PortableInvocationResult;
    }> | Readonly<{
        status: "NOT_AUTHORIZED";
        operationId: string;
        evidence: Readonly<{
            operationVersion: typeof import("../../core-0.2/src/core/portable-authority-engine.ts").PORTABLE_AUTHORITY_EVALUATION_VERSION | typeof import("../../core-0.2/src/core/portable-authority-engine.ts").PORTABLE_AUTHORIZATION_VERSION;
            decision: "DENY";
            scopeAssurance: "SUPPLIED_SCOPE" | "REPLAY_VERIFIED";
            consequential: false;
            code: import("../../core-0.2/src/core/portable-authority-engine.ts").PortableDenialCode;
            failures: readonly import("../../core-0.2/src/core/portable-authority-engine.ts").PortableDenialEvidence[];
        }> | Readonly<{
            operationVersion: typeof import("../../core-0.2/src/core/portable-authority-engine.ts").PORTABLE_AUTHORITY_EVALUATION_VERSION | typeof import("../../core-0.2/src/core/portable-authority-engine.ts").PORTABLE_AUTHORIZATION_VERSION;
            decision: "INDETERMINATE";
            scopeAssurance: "SUPPLIED_SCOPE" | "REPLAY_VERIFIED";
            consequential: false;
            code: import("../../core-0.2/src/core/portable-authority-engine.ts").PortableIndeterminateCode;
            failures: readonly import("../../core-0.2/src/core/portable-authority-engine.ts").PortableIndeterminateEvidence[];
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
            result: Exclude<import("../../core-0.2/src/core/portable-admission.ts").PortableIntentAdmissionResult, {
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
            authorization: Extract<import("../../core-0.2/src/core/portable-admission.ts").PortableIntentAdmissionResult, {
                status: "PROPOSED";
            }>["authorization"];
            admissionEvent: import("../../core-0.2/src/core/portable-admission.ts").PortableIntentAdmissionEvent;
            newHead: import("./adapter.ts").PortableHistoryHead;
        }>;
        invocation: import("../../core-0.2/src/sdk/durable-admission.ts").PortableInvocationResult;
    }>>;
    recordReceipt(input: import("./execution.ts").LocalOperation): Promise<Readonly<{
        status: "ALREADY_RECORDED";
        contentHash: `0x${string}`;
        eventId: string;
        artifactAvailable: false;
    }> | Readonly<{
        status: "RECEIPT_RESULT";
        artifact: Readonly<{
            payload: import("../../core-0.2/src/core/portable-receipt-codec.ts").PortableReceiptPayload;
            contentHash: import("../../core-0.2/src/core/canonical.ts").ContentHash;
            signature: `0x${string}`;
        }>;
        recording: import("../../core-0.2/src/sdk/durable-receipt.ts").DurableReceiptRecordResult;
    }>>;
}>;
export type LocalSimulation = ReturnType<typeof openLocalSimulation>;
