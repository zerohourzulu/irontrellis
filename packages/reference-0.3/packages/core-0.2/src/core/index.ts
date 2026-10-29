/** Common Core 0.2 Node reference surface; fixed adapter editions selected by genesis. */
export { canonicalEncode, hashCanonical, hashEventHistory, compareProtocolStrings, immutableProtocolValue, immutableProtocolInput } from "./canonical.ts";
export type { ContentHash } from "./canonical.ts";
export { PORTABLE_REPLAY_VERSION, replayPortable } from "./portable-replay.ts";
export type { AcceptedCanonicalEventShape as PortableCanonicalEvent } from "./event-schema.ts";
export type {
  PortableHistoryHead, PortableAuthorizationDomain, PortableReplayEvidenceReference,
  PortableReplayInput, PortableReplayResult, PortableReplayCode,
  PortableAuthorityConstraints, PortablePermissionGrant, PortableProhibitionGrant,
  PortableRecognizedRoot, PortableAuthorityEvidence, PortableAuthorityUsage,
} from "./portable-replay.ts";
export {
  authorizePortable, evaluatePortableAuthorityPath,
  createPortableRuntimeAuthorizationChallenge, hashPortableRuntimeAuthorizationChallenge,
  PORTABLE_AUTHORITY_EVALUATION_VERSION, PORTABLE_AUTHORIZATION_VERSION,
  PORTABLE_AUTHORIZATION_PROOF_VERSION, PORTABLE_RUNTIME_AUTHORIZATION_VERSION, PORTABLE_ROOT_RECOGNITION_POLICY,
} from "./portable-authority.ts";
export type {
  PortableActionRequest, PortableConsequentialBinding, PortableAuthorizeInput,
  PortableAuthorityPathEvaluationInput, PortableAuthorizationResult, PortableAuthorizationProof,
  PortableIntersectionProof, PortableDenialCode, PortableIndeterminateCode,
  PortableDenialEvidence, PortableIndeterminateEvidence, PortableRuntimeChallengeInput, PortableRuntimeAuthorizationChallenge,
} from "./portable-authority-engine.ts";
export { PORTABLE_INTENT_ADMISSION_VERSION, proposePortableIntentAdmission } from "./portable-admission.ts";
export type { PortableIntentAdmissionInput, PortableIntentAdmissionEvent, PortableIntentAdmissionResult } from "./portable-admission.ts";
export { derivePortableAdapterIdentity, inspectPortableAdmittedIntent } from "./portable-integration.ts";
export type { PortableAdapterIdentityInput, PortableAdapterIdentityResult, PortableAdmittedIntentInspection } from "./portable-integration.ts";
export { verifyPortableReceipt, proposePortableReceiptRecord, createPortableReceipt } from "./portable-receipts.ts";
export type { PortableReceiptRecordProposal, CreatePortableReceiptInput, PortableReceiptSigner } from "./portable-receipts.ts";
export { PORTABLE_RECEIPT_VERIFICATION_VERSION, PORTABLE_RECEIPT_RECORD_ADMISSION_VERSION, portableReceiptArtifactCommitment } from "./portable-receipt-codec.ts";
export type {
  PortableReceiptArtifact, PortableReceiptPayload, PortableReceiptResult, PortableReceiptAssurance,
  PortableReceiptAxis, PortableReceiptAxisStatus, PortableReceiptAxisCode,
  PortableReceiptVerificationInput, PortableReceiptVerificationResult, PortableReceiptVerificationEvaluated,
  PortableReceiptVerificationIndeterminate, PortableReceiptRecordAdmissionInput, PortableReceiptRecordAdmissionResult,
} from "./portable-receipt-codec.ts";
export type { PortableObligationRecord, PortableObligationStatus, PortableObligationTransitionPolicy } from "./portable-administration-codec.ts";
export type { PortableAttemptDutyRecord, PortableOutcomeObservationRecordedData, PortableAttemptDutyCreatedData,
  PortableAttemptDutyAssignedData, PortableAttemptDutyReviewClosedData } from "./portable-administration-codec.ts";
export { whyPortable, responsiblePortable, survivesPortable } from "./portable-queries.ts";
export { PORTABLE_QUERY_VERSION, PORTABLE_QUERY_EXTERNAL_ASSUMPTIONS, portablePublicQueryDisclosure } from "./portable-query-codec.ts";
export type {
  PortableQueryKind, PortableQueryFailureCode, PortableDisclosureScope, PortableQueryIdentity,
  PortableQueryScope, PortablePartialQueryScope, PortableEstablishedQueryEnvelope, PortableNonEstablishedQueryEnvelope,
  PortableWhyInput, PortableResponsibleInput, PortableSurvivesInput, PortableQueryAuthorization,
  PortableWhyAnswer, PortableResponsibleAnswer, PortableSurvivesAnswer,
  PortableWhyQueryResult, PortableResponsibleQueryResult, PortableSurvivesQueryResult,
  PortableResponsibilityKind, PortableResponsibilityAttribution, PortableRoleTenureProjection,
  PortableAdapterOutcomeProjection, PortableIntentProjection, PortableObligationProjection, PortablePerformanceAssignmentProjection, PortableAuthorityDependencyProjection,
} from "./portable-query-codec.ts";
export {
  REMOTE_SERVICE_REPORT_ADAPTER_ID, REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION, PORTABLE_ADAPTER_POLICY_E4_HASH,
  PORTABLE_ADAPTER_POLICY_E5_HASH, PORTABLE_ATTEMPT_OBSERVATION_DUTY_EXTENSION,
  PORTABLE_ADAPTER_POLICY_E6_HASH, PORTABLE_ATTEMPT_DUTY_REVIEW_EXTENSION,
  createRemoteServiceReportAcknowledgment,
  LOCAL_DOCUMENT_RELEASE_ADAPTER_ID, LOCAL_DOCUMENT_RELEASE_ACKNOWLEDGMENT_VERSION, PORTABLE_ADAPTER_POLICY_E3_HASH,
  createLocalDocumentReleaseAcknowledgment,
  SIMULATED_ADAPTER_ID, LOCAL_EVIDENCE_PACKET_ADAPTER_ID, LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID,
  PORTABLE_ADAPTER_POLICY_HASH, PORTABLE_ADAPTER_POLICY_E2_HASH, LOCAL_SYNTHETIC_ENDPOINT_STATE_ACKNOWLEDGMENT_VERSION,
  resolvePortableAdapterPolicy, approvedPortableAdapterProfileForPolicy, validatePortableAdapterProfileForPolicy,
  PORTABLE_ADAPTER_ACKNOWLEDGMENT_VERSION, PORTABLE_ADAPTER_NO_EFFECT_VERSION,
  approvedPortableAdapterProfile, validatePortableAdapterProfile, isLocalPacketManifestReference,
  createPortableAdapterAcknowledgment, createPortableAdapterNoEffect, createLocalSyntheticEndpointStateAcknowledgment,
  portableAdapterAcknowledgmentTransactionReference,
  validatePortableAdapterAcknowledgment, validatePortableAdapterNoEffect,
  validatePortableAdapterAcknowledgmentShape, validatePortableAdapterNoEffectShape,
  portableAdapterAcknowledgmentEvidence, portableAdapterNoEffectEvidence,
} from "./portable-adapter-engine.ts";
export type { PortableAdapterProfile, PortableAdapterAcknowledgment, PortableAdapterNoEffect, PortableAdapterIdentity,
  RemoteServiceReportAcknowledgment, LocalDocumentReleaseAcknowledgment, ImmutablePolicy, PortableSimulatedAdapterAcknowledgment, PortableLocalPacketAdapterAcknowledgment, LocalSyntheticEndpointStateAcknowledgment } from "./portable-adapter-engine.ts";

export { DUTY_POLICY_VERSION, DUTY_POLICY_RULES_HASH, DUTY_POLICY_RULES, DUTY_VIEW_VERSION,
  buildPortableDutyPolicyDescriptor, inspectPortableDutyPolicy } from "./duty-policy.ts";
export type { PortableDutyPolicyDescriptor, PortableDutyPolicySelection, PortableDutyDocumentDigest,
  PortableDutyPolicyActivation, PortableDutyPolicyActivatedData, PortableDutyPolicyView } from "./duty-policy.ts";

export { DUTY_FINDING_VERSION, DUTY_CRITERIA } from './duty-disposition.ts';
export type { PortableDutyChecklist, PortableDutyDispositionOperation, PortableDutyContestOperation,
  PortableDutyFindingChallenge, PortableDutyFinding, PortableDutyTransitionType } from './duty-disposition.ts';
