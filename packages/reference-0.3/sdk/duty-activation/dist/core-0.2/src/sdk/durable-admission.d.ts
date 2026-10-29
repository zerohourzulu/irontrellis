import type { PortableHistoryHead, PortableIntentAdmissionEvent, PortableIntentAdmissionInput, PortableIntentAdmissionResult, PortableReplayEvidenceReference } from "../core/index.ts";
import { PortableFileEventStore } from "../indexer/portable-file-event-store.ts";
import type { AdapterSubmissionResult, TransactionAdapter } from "../adapters/index.ts";
export type DurableAdmissionInput = PortableIntentAdmissionInput;
export interface PreparedDurableAdmission {
    readonly proposal: PortableIntentAdmissionResult;
}
export interface AdmittedInvocationCapability {
    readonly intentId: string;
    readonly admissionEventId: string;
    readonly admissionHead: PortableHistoryHead;
}
export type PortableAdmittedResult = Readonly<{
    operationVersion: "continuity-intent-admission/0.2";
    status: "ADMITTED";
    authorization: Extract<PortableIntentAdmissionResult, {
        status: "PROPOSED";
    }>["authorization"];
    admissionEvent: PortableIntentAdmissionEvent;
    newHead: PortableHistoryHead;
}>;
export type DurableAdmissionCommitResult = Readonly<{
    status: "INVALID_PREPARATION";
    reason: string;
}> | Readonly<{
    status: "UNAVAILABLE";
    reason: string;
    admissionMayHavePersisted: boolean;
}> | Readonly<{
    status: "NOT_ADMITTED";
    result: Exclude<PortableIntentAdmissionResult, {
        status: "PROPOSED";
    }>;
}> | Readonly<{
    status: "ADMITTED";
    result: PortableAdmittedResult;
    capability: AdmittedInvocationCapability;
}>;
export type PortableInvocationResult = Readonly<{
    status: "NOT_INVOKED";
    reason: string;
}> | Readonly<{
    status: "OUTCOME_UNKNOWN";
    reason: string;
    idempotencyKey?: string;
    submissionFingerprint?: string;
}> | Readonly<{
    status: "TERMINAL";
    head: PortableHistoryHead;
    evidence: PortableReplayEvidenceReference;
}> | Readonly<{
    status: "IDEMPOTENCY_FINGERPRINT_CONFLICT";
    disposition: Extract<AdapterSubmissionResult, {
        status: "IDEMPOTENCY_FINGERPRINT_CONFLICT";
    }>;
}> | Readonly<{
    status: "SUBMITTED" | "FAILED" | "RETRY";
    disposition: Extract<AdapterSubmissionResult, {
        status: "SUBMITTED" | "FAILED" | "RETRY";
    }>;
    recorded: true;
    head: PortableHistoryHead;
}>;
export type DurableAdmissionResult = Readonly<{
    admission: DurableAdmissionCommitResult;
    invocation?: PortableInvocationResult;
}>;
/**
 * Controlled local reference integration. The store, adapter and clock are
 * approved executable configuration. Only data and identity tokens enter the
 * public methods; replay facts alone never issue first-invocation authority.
 */
export declare class DurableAdmissionCoordinator {
    #private;
    readonly store: PortableFileEventStore;
    readonly adapter: TransactionAdapter;
    constructor(store: PortableFileEventStore, adapter: TransactionAdapter, options: {
        authoritativeNow: () => number;
    });
    prepare(input: unknown): PreparedDurableAdmission;
    admit(prepared: unknown): DurableAdmissionCommitResult;
    invoke(capability: unknown): Promise<PortableInvocationResult>;
    reconcile(intentId: string): Promise<PortableInvocationResult>;
    commit(prepared: unknown): Promise<DurableAdmissionResult>;
    execute(input: unknown): Promise<DurableAdmissionResult>;
}
