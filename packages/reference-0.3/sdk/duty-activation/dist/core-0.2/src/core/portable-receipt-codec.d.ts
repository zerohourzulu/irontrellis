import { type ContentHash } from "./canonical.ts";
import { type AcceptedCanonicalEventShape } from "./event-schema.ts";
import type { PortableAuthorizationProof } from "./portable-authority-engine.ts";
import type { PortableAdapterAcknowledgment } from "./portable-adapter-engine.ts";
import type { PortableAuthorizationDomain, PortableHistoryHead, PortableReplayEvidenceReference, PortableTransactionIntent } from "./portable-replay.ts";
export declare const PORTABLE_RECEIPT_VERIFICATION_VERSION: "continuity-receipt-verification/0.2";
export declare const PORTABLE_RECEIPT_RECORD_ADMISSION_VERSION: "continuity-receipt-record-admission/0.2";
export type PortableReceiptResult = Readonly<{
    status: "SUBMITTED";
    consumptionEventId: string;
    adapterId: string;
    idempotencyKey: ContentHash;
    submissionFingerprint: ContentHash;
    transactionReference: string;
    acknowledgment: PortableAdapterAcknowledgment;
}>;
export type PortableReceiptAssurance = Readonly<{
    finality: "LOCAL_ONLY";
    freshness: "CURRENT_AT_ISSUANCE";
    externalOutcome: "NOT_PROVEN" | "SIMULATED";
}>;
export type PortableReceiptPayload = Readonly<{
    schemaVersion: "continuity-receipt/0.2";
    signatureScheme: "eip191-personal-sign-keccak256";
    domain: PortableAuthorizationDomain;
    issuer: Readonly<{
        keyId: string;
        agentId: string;
        runtimeSessionId: string;
        controlEpoch: number;
        roleId: string;
        roleTenureId: string;
    }>;
    intent: PortableTransactionIntent;
    authorization: Readonly<{
        authorizationTime: number;
        policyVersion: string;
        rootRecognitionPolicy: "declared-principal-root/0.2";
        historyHead: PortableHistoryHead;
        proof: PortableAuthorizationProof;
    }>;
    issuance: Readonly<{
        historyHead: PortableHistoryHead;
        issuedAt: number;
    }>;
    result: PortableReceiptResult;
    assurance: PortableReceiptAssurance;
}>;
export type PortableReceiptArtifact = Readonly<{
    payload: PortableReceiptPayload;
    contentHash: ContentHash;
    signature: `0x${string}`;
}>;
export type PortableReceiptAxisStatus = "PASS" | "FAIL" | "UNAVAILABLE" | "UNVERIFIED";
export declare const PORTABLE_RECEIPT_AXIS_CODES: readonly ["CONTENT_HASH_MATCH", "CONTENT_HASH_MISMATCH", "SIGNATURE_VALID", "SIGNATURE_INVALID", "ISSUER_AUTHENTICATED", "ISSUER_NOT_AUTHENTICATED", "HISTORICAL_AUTHORIZATION_VALID", "HISTORICAL_AUTHORIZATION_INVALID", "RECORDED_HASH_MATCH", "RECORDED_POSITION_MISMATCH", "RECORD_NOT_AVAILABLE", "LOCAL_ONLY", "NOT_PROVEN", "SIMULATED", "CURRENT", "STALE", "VERIFIER_TIME_BEHIND_OBSERVED_HEAD", "FUTURE_ISSUANCE", "DEPENDENCY_FAILED", "DEPENDENCY_UNAVAILABLE", "DOMAIN_MISMATCH", "RECEIPT_FIELDS_MISMATCH", "SUBMISSION_EVIDENCE_MISSING", "ISSUANCE_HISTORY_UNVERIFIED", "OBSERVED_HISTORY_DIVERGES"];
export type PortableReceiptAxisCode = (typeof PORTABLE_RECEIPT_AXIS_CODES)[number];
export type PortableReceiptAxis = Readonly<{
    status: PortableReceiptAxisStatus;
    primaryCode: PortableReceiptAxisCode;
    causes: readonly [PortableReceiptAxisCode, ...PortableReceiptAxisCode[]];
    evidence: readonly PortableReplayEvidenceReference[];
}>;
export declare const PORTABLE_RECEIPT_LIMITATIONS: readonly ["NO_CANONICAL_ISSUANCE_WITNESS", "NO_PUBLIC_FINALITY_PROOF", "NO_EXTERNAL_OUTCOME_PROOF"];
export type PortableReceiptLimitation = (typeof PORTABLE_RECEIPT_LIMITATIONS)[number];
export type PortableReceiptVerificationInput = Readonly<{
    operationVersion: typeof PORTABLE_RECEIPT_VERIFICATION_VERSION;
    artifact: PortableReceiptArtifact;
    issuanceEvents: readonly AcceptedCanonicalEventShape[];
    observedEvents: readonly AcceptedCanonicalEventShape[];
    expectedDomain: PortableAuthorizationDomain;
    verifierTime: number;
}>;
export type PortableReceiptVerificationEvaluated = Readonly<{
    operationVersion: typeof PORTABLE_RECEIPT_VERIFICATION_VERSION;
    status: "EVALUATED";
    contentIntegrity: PortableReceiptAxis;
    signaturePossession: PortableReceiptAxis;
    issuerAuthentication: PortableReceiptAxis;
    historicalAuthorization: PortableReceiptAxis;
    canonicalInclusion: PortableReceiptAxis;
    finality: PortableReceiptAxis;
    freshness: PortableReceiptAxis;
    externalOutcome: PortableReceiptAxis;
    authentic: boolean;
    historical: boolean;
    valid: boolean;
    current: boolean;
    limitations: readonly PortableReceiptLimitation[];
}>;
export type PortableReceiptVerificationIndeterminate = Readonly<{
    operationVersion: typeof PORTABLE_RECEIPT_VERIFICATION_VERSION;
    status: "INDETERMINATE";
    code: "INVALID_INPUT" | "MALFORMED_ARTIFACT" | "UNSUPPORTED_RECEIPT_VERSION" | "UNSUPPORTED_VERSION" | "STATE_NOT_AUTHORITATIVE" | "OUTPUT_LIMIT_EXCEEDED";
    limitations: readonly PortableReceiptLimitation[];
}>;
export type PortableReceiptVerificationResult = PortableReceiptVerificationEvaluated | PortableReceiptVerificationIndeterminate;
export type PortableReceiptRecordAdmissionInput = Readonly<{
    operationVersion: typeof PORTABLE_RECEIPT_RECORD_ADMISSION_VERSION;
    artifact: PortableReceiptArtifact;
    events: readonly AcceptedCanonicalEventShape[];
    expectedHistoryHead: PortableHistoryHead;
    expectedDomain: PortableAuthorizationDomain;
    recordEventId: string;
}>;
export type PortableReceiptRecordAdmissionResult = Readonly<{
    operationVersion: typeof PORTABLE_RECEIPT_RECORD_ADMISSION_VERSION;
    status: "ADMITTED";
    recordEvent: AcceptedCanonicalEventShape;
    newHead: PortableHistoryHead;
    verification: PortableReceiptVerificationEvaluated;
}> | Readonly<{
    operationVersion: typeof PORTABLE_RECEIPT_RECORD_ADMISSION_VERSION;
    status: "REJECTED";
    verification: PortableReceiptVerificationEvaluated;
}> | Readonly<{
    operationVersion: typeof PORTABLE_RECEIPT_RECORD_ADMISSION_VERSION;
    status: "INDETERMINATE";
    code: "INVALID_INPUT" | "UNSUPPORTED_VERSION" | "STATE_NOT_AUTHORITATIVE" | "OUTPUT_LIMIT_EXCEEDED";
    verification?: PortableReceiptVerificationIndeterminate;
}> | Readonly<{
    operationVersion: typeof PORTABLE_RECEIPT_RECORD_ADMISSION_VERSION;
    status: "CONFLICT";
    expectedHead: PortableHistoryHead;
    observedHead: PortableHistoryHead;
}>;
/** @internal Requires an artifact already validated from one immutable capture. */
export declare const receiptRecordDataForArtifact: (artifact: PortableReceiptArtifact) => Readonly<{
    receiptContentHash: `0x${string}`;
    receiptArtifactCommitment: `0x${string}`;
    intentId: string;
    issuerAgentId: string;
    runtimeSessionId: string;
    controlEpoch: number;
    roleId: string;
    roleTenureId: string;
    authorizationProofHash: `0x${string}`;
}>;
/**
 * Valid-input-only commitment derivation. Schema acceptance is not content
 * integrity, signature possession, issuer authentication, or an authority grant.
 * Hash and signature spelling remain exact even when the payload hash differs.
 */
export declare const portableReceiptArtifactCommitment: (artifact: unknown) => ContentHash;
