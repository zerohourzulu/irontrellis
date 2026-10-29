import { type LocalExecutionOptions } from "./execution.ts";
export type EvidenceSelection = readonly Readonly<{
    name: string;
    bytes: number;
    sha256: string;
}>[];
export type EvidenceToolOptions = LocalExecutionOptions & Readonly<{
    inputDirectory: string;
    outputDirectory: string;
    selection: EvidenceSelection;
    resource: string;
    role: string;
    tenure: string;
}>;
/** Trusted setup only. Persist this selection; reopening must not select changed files. */
export declare function selectEvidence(inputDirectory: string): EvidenceSelection;
/** A fixed local evidence tool. No caller paths, arbitrary adapter or tool dispatch. */
export declare function openLocalEvidenceTool(options: EvidenceToolOptions): Readonly<{
    resource: string;
    /** Fresh admission or reconciliation of the same attempt; never a new-ID retry. */
    collect(input: Readonly<{
        operationId: string;
        resource: string;
    }>): Promise<Readonly<{
        result: Readonly<{
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
        }>;
        packet: any;
    }>>;
    recordReceipt(input: Readonly<{
        operationId: string;
        resource: string;
    }>): Promise<Readonly<{
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
    /** Privileged application inspection. It is not an agent-facing tool. */
    inspect(input: Readonly<{
        operationId: string;
        resource: string;
    }>): any;
}>;
export type LocalEvidenceTool = ReturnType<typeof openLocalEvidenceTool>;
