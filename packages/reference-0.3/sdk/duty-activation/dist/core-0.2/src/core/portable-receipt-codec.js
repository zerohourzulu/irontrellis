import { captureBoundedCanonicalValue, hashCanonical } from "./canonical.js";
import { validateCapturedPortableReceiptValue, } from "./event-schema.js";
import { objectFreeze } from "./host-intrinsics.js";
export const PORTABLE_RECEIPT_VERIFICATION_VERSION = "continuity-receipt-verification/0.2";
export const PORTABLE_RECEIPT_RECORD_ADMISSION_VERSION = "continuity-receipt-record-admission/0.2";
export const PORTABLE_RECEIPT_AXIS_CODES = objectFreeze([
    "CONTENT_HASH_MATCH", "CONTENT_HASH_MISMATCH", "SIGNATURE_VALID", "SIGNATURE_INVALID",
    "ISSUER_AUTHENTICATED", "ISSUER_NOT_AUTHENTICATED", "HISTORICAL_AUTHORIZATION_VALID",
    "HISTORICAL_AUTHORIZATION_INVALID", "RECORDED_HASH_MATCH", "RECORDED_POSITION_MISMATCH",
    "RECORD_NOT_AVAILABLE", "LOCAL_ONLY", "NOT_PROVEN", "SIMULATED", "CURRENT", "STALE",
    "VERIFIER_TIME_BEHIND_OBSERVED_HEAD", "FUTURE_ISSUANCE", "DEPENDENCY_FAILED",
    "DEPENDENCY_UNAVAILABLE", "DOMAIN_MISMATCH", "RECEIPT_FIELDS_MISMATCH",
    "SUBMISSION_EVIDENCE_MISSING", "ISSUANCE_HISTORY_UNVERIFIED", "OBSERVED_HISTORY_DIVERGES",
]);
export const PORTABLE_RECEIPT_LIMITATIONS = objectFreeze([
    "NO_CANONICAL_ISSUANCE_WITNESS", "NO_PUBLIC_FINALITY_PROOF", "NO_EXTERNAL_OUTCOME_PROOF",
]);
/** @internal Requires an artifact already validated from one immutable capture. */
export const receiptRecordDataForArtifact = (artifact) => objectFreeze({
    receiptContentHash: artifact.contentHash,
    receiptArtifactCommitment: hashCanonical([
        "continuity-receipt-artifact-commitment/0.2", artifact.contentHash, artifact.signature,
    ]),
    intentId: artifact.payload.intent.intentId,
    issuerAgentId: artifact.payload.issuer.agentId,
    runtimeSessionId: artifact.payload.issuer.runtimeSessionId,
    controlEpoch: artifact.payload.issuer.controlEpoch,
    roleId: artifact.payload.issuer.roleId,
    roleTenureId: artifact.payload.issuer.roleTenureId,
    authorizationProofHash: hashCanonical(artifact.payload.authorization.proof),
});
/**
 * Valid-input-only commitment derivation. Schema acceptance is not content
 * integrity, signature possession, issuer authentication, or an authority grant.
 * Hash and signature spelling remain exact even when the payload hash differs.
 */
export const portableReceiptArtifactCommitment = (artifact) => {
    const capture = captureBoundedCanonicalValue(artifact);
    const status = validateCapturedPortableReceiptValue(capture, "ARTIFACT", capture.value);
    if (status !== "VALID")
        throw new TypeError(`Invalid portable receipt artifact: ${status}.`);
    const accepted = capture.value;
    return hashCanonical([
        "continuity-receipt-artifact-commitment/0.2", accepted.contentHash, accepted.signature,
    ]);
};
