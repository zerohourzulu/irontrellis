/** Fixed approved common-engine adapter contracts; configuration is not authority. */
import type { ContentHash, PortableAdapterIdentityInput, PortableReplayEvidenceReference, PortableAdapterProfile, PortableAdapterAcknowledgment, PortableAdapterNoEffect } from "../core/index.ts";
export type AdmittedTransactionSubmission = PortableAdapterIdentityInput;
export type AdapterSubmissionResult = {
    status: "SUBMITTED";
    idempotencyKey: ContentHash;
    submissionFingerprint: ContentHash;
    evidence: PortableReplayEvidenceReference;
    acknowledgment: PortableAdapterAcknowledgment;
} | {
    status: "RETRY";
    idempotencyKey: ContentHash;
    submissionFingerprint: ContentHash;
    retainedEvidence: PortableReplayEvidenceReference;
    acknowledgment: PortableAdapterAcknowledgment;
} | {
    status: "RETRY";
    idempotencyKey: ContentHash;
    submissionFingerprint: ContentHash;
    retainedEvidence: PortableReplayEvidenceReference;
    noEffect: PortableAdapterNoEffect;
} | {
    status: "FAILED";
    idempotencyKey: ContentHash;
    submissionFingerprint: ContentHash;
    evidence: PortableReplayEvidenceReference;
    noEffect: PortableAdapterNoEffect;
} | {
    status: "OUTCOME_UNKNOWN";
    idempotencyKey: ContentHash;
    submissionFingerprint: ContentHash;
    latestEvidence?: PortableReplayEvidenceReference;
} | {
    status: "IDEMPOTENCY_FINGERPRINT_CONFLICT";
    idempotencyKey: ContentHash;
    retainedFingerprint: ContentHash;
    suppliedFingerprint: ContentHash;
};
export interface TransactionAdapter {
    readonly adapterProfile: PortableAdapterProfile;
    submit(input: AdmittedTransactionSubmission): Promise<AdapterSubmissionResult>;
    reconcile(input: AdmittedTransactionSubmission): AdapterSubmissionResult | Promise<AdapterSubmissionResult>;
}
export { DeterministicSimulatedAdapter } from "./simulated-adapter.ts";
export type { SimulatedAdapterAttempt } from "./simulated-adapter.ts";
