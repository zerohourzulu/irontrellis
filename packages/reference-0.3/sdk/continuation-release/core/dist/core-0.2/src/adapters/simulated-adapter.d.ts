import type { ContentHash, PortableAuthorizationDomain, PortableAdapterProfile } from "../core/index.ts";
import type { AdapterSubmissionResult, AdmittedTransactionSubmission, TransactionAdapter } from "./index.ts";
export interface SimulatedAdapterAttempt {
    readonly intentId: string;
    readonly authorizationDomain: PortableAuthorizationDomain;
    readonly idempotencyKey: ContentHash;
    readonly submissionFingerprint: ContentHash;
    readonly admissionEventId: string;
    readonly durableEventHistoryHash: ContentHash;
    readonly result: AdapterSubmissionResult;
}
/**
 * Effect-free simulator with process-local retention. Its cache establishes
 * neither durable admission nor current pre-use authority; the coordinator
 * owns those boundaries. Reconciliation never manufactures a new result.
 */
export declare class DeterministicSimulatedAdapter implements TransactionAdapter {
    #private;
    readonly adapterProfile: PortableAdapterProfile;
    constructor(options?: {
        failIntentIds?: readonly string[];
    });
    get attempts(): readonly SimulatedAdapterAttempt[];
    reconcile(input: AdmittedTransactionSubmission): AdapterSubmissionResult;
    submit(input: AdmittedTransactionSubmission): Promise<AdapterSubmissionResult>;
}
