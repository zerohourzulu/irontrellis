/**
 * `@ramex-labs/irontrellis`: the engine surface (the Core 0.2 names without
 * the `Portable` prefix), the store, signing and anchoring layer, and the local
 * host API. Reading a captured history needs nothing beyond `replay`,
 * `authorizePortable`, `whyPortable` / `responsiblePortable` / `survivesPortable`
 * and `observeHistory`.
 */
// ---------------------------------------------------------------- shared vocabulary
export * from "./types.ts";
export { EngineError } from "./errors.ts";

// ---------------------------------------------------------------- canonical form, hashing, crypto
export {
  canonicalEncode, captureValue, compareProtocolStrings, CanonicalError, LIMITS, isIdentifier, isProtocolString, codePointLength, isU53, isAmount, isAmountString, parseAmountString, amountOf, wireAmounts, AMOUNT_STRING, RESERVED_KEY_PREFIX, isContentHash, isEthereumAddress, isChainId,
  sortedIdentifiers, jsonStringifyWithBigints, jsonParseWithBigints,
} from "./canonical.ts";
export { hashCanonical, hashEventHistory, hashEventHistoryPrefixes, hashBytes, sha256Hex, historyHashAlgorithm, HistoryHasher, RecordChain, createHistoryHasher, historyIdOfGenesis, eventHash, recordHash, RECORD_CHAIN_VERSION } from "./hash.ts";
export type { PrefixHasher } from "./hash.ts";
export { suiteFor, eip191Digest, generateKeyPair, keyPairFromPrivateKey, signHashWith, recoverContentHashSigner } from "./crypto/suites.ts";
export type { SignatureSuite, KeyPair } from "./crypto/suites.ts";
/** The Ed25519 public-key test (SPEC §3.3: on the curve, canonical, not small order, in the prime subgroup). */
export { ed25519KeyCheck } from "./crypto/ed25519-point.ts";
export type { KeyCheck } from "./crypto/ed25519-point.ts";

// ---------------------------------------------------------------- events, replay
export {
  LEGACY_FORMAT, TRELLIS_FORMAT, TRELLIS2_FORMAT, isTrellis, isFormat2, LEGACY_VERSIONS, TRELLIS_VERSIONS, FORMAT2_VERSIONS, expectedVersionsOf, ROOT_RECOGNITION_POLICY,
  CONTROL_AUTHORIZATION_VERSION, CONTROL_AUTHORIZATION_VERSION_2, controlAuthorizationVersionOf, INTENT_DECLARATION_VERSION, LIFECYCLE_AUTHORIZATION_VERSION, STATE_DERIVATION_VERSION, PROJECTION_VERSION,
  COUNTERPARTY_RECEIPT_VERSION, DUTY_POLICY_VERSION, DUTY_POLICY_RULES_HASH, DUTY_FINDING_VERSION, DUTY_CRITERIA, SIGNATURE_SCHEMES, ADMINISTRATIVE_EVENT_TYPES,
  FORMAT2_ADMINISTRATIVE_EVENT_TYPES, administrativeEventTypesOf, DUTY_POLICY_EVENT_TYPES, LEGACY_DUTY_POLICY_EVENTS,
  OBLIGATION_STATUSES, ANCHOR_NAMES, MAX_BOUND_WITNESSES, ADAPTER_POLICY_HASHES, validateEvent, validateGenesis, isEventType, isControlEvent, hashAlgorithmOf, formatOfSchemaVersion,
  controlEffect, signedControlEffect, controlEffectHash, ADDITIONAL_CONTROL_AUTHORIZATIONS, controlAuthorizationChallenge, controlAuthorizationHash, sessionCredential, OBSERVATION_UNSUPPLIABLE,
} from "./events.ts";
export {
  sessionAuthorizationFailure, sessionFailureCode, sessionExpiredAt, intentDeclarationChallenge, intentDeclarationHash, lifecycleChallenge, lifecycleAuthorizationHash, lifecycleEffectHash,
  CHALLENGE_PROFILES, challengeProfile, setChallengeProfile,
  refusalChallenge, effectChallenge, counterpartyRecordChallenge, envelopeDigest, envelopeSigningHash,
  RECONCILIATION_AUTHORIZATION_VERSION, reconciliationChallenge, OBSERVATION_ID_VERSION, derivedObservationId,
} from "./session-auth.ts";
export type { SessionBinding, IntentDeclarationFields, LifecycleAuthorization, SessionAuthorizationOutcome } from "./session-auth.ts";
export { MAX_OUTCOMES_PER_INTENT, MAX_OBSERVATIONS_PER_INTENT, MAX_ASSIGNMENTS_PER_DUTY, MAX_REVIEWS_PER_DUTY, MAX_RECEIPTS_PER_INTENT, receiptCountOf, observationIndexOf } from "./state.ts";
export { observationNotes, timeListings, TIME_LISTING_SKEW_MS, type SessionTimeAdvance, type OwnerEventAtHeadTime } from "./verify-notes.ts";
export {
  STATE_RECORD_KINDS, recordKey, positionKey, leafOf, rootOfLeaves, stateRootOfRecords, projectionFields, projectionRow, projectionHeadAfter, projectionHeadsOf, eventRecord,
  deriveRecord, deriveAllRecords, stateRecordsOf, stateRootOf, rootAt, projectionHeadAt, reconciliationCursorKey,
} from "./state-records.ts";
export type { StateRecordKind } from "./state-records.ts";
export { rebuildReplayState, recomputeRoot } from "./state-rebuild.ts";
export type { RecordInput, RebuildOptions } from "./state-rebuild.ts";
export { AMOUNT_PATHS, convertAmounts, markerOutsideAmountPaths, transcribeData, invertTranscription } from "./transcription.ts";
export type { AmountDirection } from "./transcription.ts";
export { budgetCheckAfterAllow, headroom, carryIn, remainingAmount, periodIndex, budgetMatches, matchingBudgets, rolesHeldBy, chargedUsage, MAX_AMOUNT, MAX_MATCHING_BUDGETS } from "./budgets.ts";
export type { BudgetVerdict, BudgetRecord, BudgetUsageRecord, BudgetPeriod } from "./budgets.ts";
export { exportView, exportViewState, verifyExportView, EXPORT_VERSION } from "./export-view.ts";
export type { ExportView, ExportViewInput, ExportViewContext, ExportEnd, ExportedRecord, ExportedEvent, ExportAttestation, ExportAttestations, ExportKeyEvent, ExportVerification, ExportVerificationOptions, ExportEndAuthentication } from "./export-view.ts";
// ---------------------------------------------------------------- SPEC §13 (E4): the ported duty-policy machinery (pure state API)
export {
  DUTY_POLICY_RULES, DUTY_VIEW_VERSION, DUTY_EVIDENCE_INDEX_VERSION, DUTY_CRITERIA_PROFILE, DUTY_DISPOSITION_LIMIT, DUTY_CONTEST_LIMIT,
  ACTIVATE_DUTY_POLICY_ACTION, ATTEST_DUTY_FINDING_ACTION, RECORD_DUTY_DISPOSITION_ACTION, DUTY_POLICY_RULES_HASH_ALGORITHM, dutyPolicyRulesHashIsPinned,
  deriveDutyPolicyDescriptor, buildDutyPolicyDescriptor, dutyPolicyActivationRequirements, dutyPolicyActivationProofMatches,
  deriveDutyEvidenceIndex, dutyRequirements, dutySessionEligible, dutyOperationEligible, deriveDutyFinding, dutyFindingRequestOf, validateDutyFinding,
  validateDutyFreshEligibility, dutyDispositionProjection, inspectDutyPolicyState, inspectDutyPolicyOf, dutyRecordsOf,
} from "./duty-policy.ts";
export type {
  DutyDocumentDigest, DutyPolicySelection, DutyPolicyDescriptor, DutyPolicyActivatedEffect, DutyPolicyActivation, DutyDispositionRef, DutyCriterion, DutyChecklist,
  DutyDispositionOperation, DutyContestOperation, DutyOperation, DutyTransitionType, DutyFindingChallenge, DutyFinding, DutyDispositionEffect, DutyFindingRequest,
  DutyUnsignedTransition, DutyEvidenceIndex, DutyDispositionView, DutyLastRecordedDisposition, DutyPolicyView,
} from "./duty-policy.ts";
export { MAX_BUDGETS, MAX_EFFECTS_PER_INTENT } from "./state.ts";
export { POWER_REDUCING_TYPES, enforcementWarning, OWNER_POLICY_RECOVERY_NO_WRITER } from "./owner.ts";
export { MAX_UNWITNESSED_EXEMPT_TYPES } from "./types.ts";
export {
  MAX_STATE_RECORDS, MAX_FILE_BYTES, RESERVED_STATE_RECORDS, RESERVED_FILE_BYTES, DUTY_DISPOSITION_QUOTA, DUTY_CONTEST_QUOTA, capacityLimits, capacityVerdict, boundedCapacityVerdict, formatTwoLineBytes,
  HARD_RECORDS, HARD_BYTES, RESERVE_THRESHOLD_RECORDS, RESERVE_THRESHOLD_BYTES, RESERVE_CLASS, ALWAYS_ADMITTED_NON_CONTROL,
  newCapacityLedger, accountCapacity, reservationDelta,
} from "./capacity.ts";
export type { CapacityLimits, CapacityLedger } from "./capacity.ts";
export type { EventValidation, ControlAuthorizationInput } from "./events.ts";
export { REPLAY_VERSION, replay, replayFrom, applyEvent, withProspectiveEvent, forkReplayState, detectFormat, createReplayState, defaultReplayHooks, EMPTY_HEAD } from "./replay.ts";
export type { ApplyResult, ProspectiveResult, MutableReplayState, ReplayHooks, TransitionFailure } from "./replay.ts";

// ---------------------------------------------------------------- authority, queries, admission, receipts, administration
export {
  AUTHORIZATION_VERSION, AUTHORITY_EVALUATION_VERSION, AUTHORIZATION_PROOF_VERSION, RUNTIME_AUTHORIZATION_VERSION, AUTHORIZATION_PROOF_VERSION_2, RUNTIME_AUTHORIZATION_VERSION_2,
  authorizeState, authorizePortable, evaluateAuthorityPath, createRuntimeAuthorizationChallenge, hashRuntimeAuthorizationChallenge, verifyRuntimeAuthorizationSignature,
  normalizedGrant, normalizedConstraints, constraintsAreAttenuated, combineConstraints, sameDomain, evaluateReceiptPolicy, createAdministrativePolicyProof,
  validateIntentAdmissionTransition, validateAdministrativeTransition, administrativeTransitionEffect,
} from "./authority.ts";
export type { AuthorizeBody, AuthorizeOptions, RuntimeChallengeInput, ReceiptPolicyEvaluation } from "./authority.ts";
export {
  QUERY_VERSION, QUERY_EXTERNAL_ASSUMPTIONS, RESPONSIBILITY_KINDS, QUERY_ANSWER_FIELD_PATHS, QUERY_ANSWER_FIELD_PATHS_2, FORMAT2_ANSWER_FIELD_PATHS, DUTY_QUERY_FIELD_PATHS, queryAnswerFieldPaths, publicQueryDisclosure, whyState, responsibleState, survivesState, whyPortable, responsiblePortable, survivesPortable,
  deriveResponsibility, deriveSurvives, attemptDutyReviewStatus,
} from "./queries.ts";
export type {
  QueryKind, QueryFailureCode, Disclosure, QueryIdentity, QueryScope, PartialQueryScope, EstablishedQueryEnvelope, NonEstablishedQueryEnvelope, QueryEvidenceReference,
  WhyInput, ResponsibleInput, SurvivesInput, WhyStateInput, ResponsibleStateInput, SurvivesStateInput, QueryAuthorization, WhyAnswer, ResponsibleAnswer, SurvivesAnswer,
  WhyQueryResult, ResponsibleQueryResult, SurvivesQueryResult, ResponsibilityKind, ResponsibilityAttribution, RoleTenureProjection, IntentProjection,
  AdapterOutcomeProjection, ObligationProjection, PerformanceAssignmentProjection, AuthorityDependencyProjection,
} from "./queries.ts";
export {
  INTENT_ADMISSION_VERSION, proposeIntentAdmission, proposeIntentAdmissionState, inspectAdmittedIntent, inspectAdmittedIntentState, deriveAdapterIdentity, deriveAdapterIdentityState,
  admissionControlIsCurrent, sameHead, isDomain, isHead,
} from "./admission.ts";
export type { IntentAdmissionInput, IntentAdmissionEvent, IntentAdmissionResult, AdapterIdentityInput, AdapterIdentityResult, AdmittedIntentInspection, ReplayFn } from "./admission.ts";
export {
  RECEIPT_VERIFICATION_VERSION, RECEIPT_RECORD_ADMISSION_VERSION, RECEIPT_ARTIFACT_COMMITMENT_TAG, RECEIPT_ARTIFACT_COMMITMENT_TAG_2, RECEIPT_SCHEMA_VERSION_2, RECEIPT_LIMITATIONS, RECEIPT_AXIS_CODES,
  validateReceiptArtifact, receiptArtifactCommitment, verifyReceipt, verifyReceiptState, proposeReceiptRecord, proposeReceiptRecordState, createReceipt, createReceiptState,
} from "./receipts.ts";
export type {
  ReceiptArtifact, ReceiptPayload, ReceiptAxis, ReceiptAxisStatus, ReceiptAxisCode, ReceiptLimitation, ReceiptVerificationInput, ReceiptVerificationResult,
  ReceiptVerificationEvaluated, ReceiptVerificationIndeterminate, ReceiptRecordAdmissionInput, ReceiptRecordAdmissionResult, ReceiptRecordProposal, CreateReceiptInput, ReceiptSigner,
} from "./receipts.ts";
export {
  ADMINISTRATIVE_AUTHORIZATION_VERSION, AdministrativeProducerError, prepareAdministrativeEvent, attachAdministrativeSignature, produceAdministrativeEvent, deriveAdministrativeRequirements,
  prepareAdministrativeEventState, attachAdministrativeSignatureState, produceAdministrativeEventState, prepareDutyFinding, attachDutyFinding,
} from "./administration.ts";
export type {
  AdministrativeChallenge, AdministrativeAuthorization, PreparedAdministrativeEvent, ProducedAdministrativeEvent, AdministrativeEventType, UnsignedTransition,
  AdministrativeProducerPhase, AdministrativeProducerCode, DutyFindingInput, PreparedDutyFinding, DutyFindingAdministrativeInput,
} from "./administration.ts";

// ---------------------------------------------------------------- adapter editions, coordinators
export {
  ADAPTER_IDEMPOTENCY_VERSION, ADAPTER_SUBMISSION_VERSION, ADAPTER_NO_EFFECT_VERSION, ADAPTER_ACKNOWLEDGMENT_VERSION, ADAPTER_POLICY_SCHEMA_VERSION,
  SIMULATED_ADAPTER_ID, LOCAL_EVIDENCE_PACKET_ADAPTER_ID, LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID, LOCAL_SYNTHETIC_ENDPOINT_STATE_ACKNOWLEDGMENT_VERSION,
  LOCAL_DOCUMENT_RELEASE_ADAPTER_ID, LOCAL_DOCUMENT_RELEASE_ACKNOWLEDGMENT_VERSION, REMOTE_SERVICE_REPORT_ADAPTER_ID, REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION,
  ATTEMPT_OBSERVATION_DUTY_EXTENSION, ATTEMPT_DUTY_REVIEW_EXTENSION, ADAPTER_DESCRIPTORS, ADAPTER_POLICY_HASH, ADAPTER_POLICY_E2_HASH, ADAPTER_POLICY_E3_HASH,
  ADAPTER_POLICY_E4_HASH, ADAPTER_POLICY_E5_HASH, ADAPTER_POLICY_E6_HASH, resolveAdapterPolicy, approvedAdapterProfileForPolicy, approvedAdapterProfile,
  validateAdapterProfile, validateAdapterProfileForPolicy, isLocalPacketManifestReference, createAdapterAcknowledgment, createAdapterNoEffect,
  createLocalSyntheticEndpointStateAcknowledgment, createLocalDocumentReleaseAcknowledgment, createRemoteServiceReportAcknowledgment,
  adapterAcknowledgmentTransactionReference, validateAdapterAcknowledgment, validateAdapterNoEffect, validateAdapterAcknowledgmentShape, validateAdapterNoEffectShape,
  adapterAcknowledgmentEvidence, adapterNoEffectEvidence, hashAlgorithmForDomain,
} from "./adapter-editions.ts";
export type { AdapterId, AdapterEdition, AdapterDescriptor, AdapterPolicy, AdapterIdentity, AdapterExternalEvidence, AdapterAcknowledgment, AdapterNoEffect } from "./adapter-editions.ts";
export { DurableAdmissionCoordinator, DurableReceiptCoordinator, StoreConflictError, captureDisposition, admittedSubmissionIdentity } from "./coordinators.ts";
export type {
  EventStore, EventStoreWriter, TransactionAdapter, AdmittedTransactionSubmission, AdmittedSubmissionFields, AdapterSubmissionResult, PreparedDurableAdmission, AdmittedInvocationCapability,
  AdmittedResult, DurableAdmissionCommitResult, InvocationResult, DurableAdmissionResult, DurableReceiptRecordResult, ResumeInvocationRequest, ResumeInvocationResult,
} from "./coordinators.ts";

// ---------------------------------------------------------------- store, signer, anchors (layer 2)
export { openHistoryStore, createHistoryStore } from "./store-public.ts";
export { readGenesisLine, HISTORY_FILE_LIMITS, FORMAT_READ_ONLY_DEFAULT, MIGRATED_MARKER_VERSION, migratedMarkerPathFor, readMigratedMarker, markerTargetPath, canonicalPath, storeCounters, resetStoreCountersForTests } from "./store.ts";
export type { TrustMode, MigratedMarker } from "./store.ts";
export { SNAPSHOT_VERSION, SNAPSHOT_JOURNAL_LIMIT, SNAPSHOT_MAX_BYTES_DEFAULT, SNAPSHOT_MAX_ENTRIES, setSnapshotMaxBytes, snapshotPathFor, journalPathFor, readSnapshotBase, readSnapshotFiles } from "./snapshot.ts";
export { parseStrictJson, strictJsonProblem, StrictJsonError, STRICT_JSON_MAX_DEPTH } from "./strict-json.ts";
export { migrationStatus, MIGRATION_PLAN_VERSION, migrationPlanPathFor } from "./migrate.ts";
export type { MigrationPlan, MigrationStatus, MigrationPhase } from "./migrate.ts";
export { setDefaultVerifyThreads, verifyThreads } from "./crypto/parallel-verify.ts";
export type { HistoryStore, StoreFormat, StoreOptions, RepinOptions, RemoteVerifyOptions, PinnedHead, HeadAttestation } from "./store.ts";
export {
  createOwnerKeyFile, loadOwnerKeyFile, ownerKeyPathFor, pendingOwnerKeyPathFor, retiredOwnerKeyPathFor, retiredOwnerKeyFilesFor, signControlEvent, attestHead, attestHeadSync, verifyHeadAttestation,
  headAttestationHash, headAttestationBody2, HEAD_ATTESTATION_VERSION, HEAD_ATTESTATION_VERSION_2,
  createNextOwnerKeyFile, loadNextOwnerKeyFile, promoteNextOwnerKeyFile, nextOwnerKeyPathFor, pendingNextOwnerKeyPathFor, OWNER_KEY_VERSION, OWNER_NEXT_KEY_VERSION,
} from "./signer.ts";
export type { Signer, SignContext, SignerCustody, AttestationCommitment } from "./signer.ts";
export { writeKeyReferenceFile, keyFileHolder, readKeyReferenceFile, inspectKeyFile } from "./signer.ts";
// ---------------------------------------------------------------- owner-key custody (docs/CUSTODY.md); also `@ramex-labs/irontrellis/custody`
export {
  OWNER_KEY_REF_VERSION, OWNER_NEXT_KEY_REF_VERSION, parseKeyReference, keyReference, keyReferenceText, withReferenceVersion, referenceSigner, publicKeySigner, parsePublicKey, sshPublicKeyOf,
  registerSignerBackend, signerBackend, signerBackendKinds, SIGN_PURPOSES, agentSocketPath, listAgentIdentities, parseSshPublicKey, sshPublicKeyLine, openSshPrivateKey, WINDOWS_AGENT_PIPE,
  SIGN_REQUEST_VERSION, DEFAULT_COMMAND_TIMEOUT_MS, DEFAULT_AGENT_TIMEOUT_MS,
  DEFAULT_VAULT_MOUNT, DEFAULT_VAULT_TIMEOUT_MS, normalizeVaultAddress, readVaultKey, checkVaultKey, vaultTokenSource, vaultCaFile,
} from "./custody/index.ts";
export type { OwnerKeyReference, KeyReferenceVersion, SignerBackend, SignerSpec, SignPurpose, ReferencedKey, AgentIdentity, VaultKeyInfo } from "./custody/index.ts";
export {
  ownerKeysAt, ownerKeyInForce, ownerKeyRotationFailure, controlSignatureFailure, checkpointAuthorizationFailure, resumeRootFailure, unqualifiedHeadSigner, verifyHeadAttestationAt, verifyHeadAttestationFacts, verifyRotationEvent, ownerKeyDigest,
  ownerKeyEventTransition, keepsEveryOwnerKey, OWNER_KEY_DIGEST_VERSION, ownerKeyEpochAt, ownerPolicyAt, controlQuorum, controlQuorumFailure, ownerKeyRotationCounts,
  admissibleKeys, isRecoveryRotation, isRestoration, epochOpenedAt, controlRuleAt, eligibleSigners, singleSignerTimeFailure, attestationExpiryFailure, humanClassCount,
} from "./owner-keys.ts";
export {
  DEFAULT_OWNER_POLICY, MAX_ADDITIONAL_CONTROL_AUTHORIZATIONS, effectiveThreshold, rotationThreshold, ownerKeyClass, ownerPolicyFailure, sameOwnerPolicy, isDefaultOwnerPolicy,
  prEffective, controlThreshold, PR_TYPES, LOW_TYPES, HUMAN_ATTESTATION_VERSION, MAX_TIME, humanAttestationHash, signerClass, attestationHorizon, isAttestedPolicy, statementOf,
  attestationFailure, checkpointPolicyListings,
} from "./owner-policy.ts";
export type { SignerClass, PolicySetting, CheckpointPolicyListing } from "./owner-policy.ts";
export type {
  ControlSigner, ControlQuorumFailure, QuorumRule,
} from "./owner-keys.ts";
export type {
  ControlSignatureContext, RotationContext, RotationVerification, KeyEventContext, KeyEventVerification, OwnerKeyEventContext, OwnerKeyEventOutcome, HeadAttestationFacts,
} from "./owner-keys.ts";
// ---------------------------------------------------------------- anchoring: the local anchor log and anchor targets (docs/HISTORY-FORMAT.md §10)
export { localAnchorLog, rekorAnchor, anchorRecordedEvent, anchorHead, anchorsPathFor, anchorContextOf, contextKeysAt } from "./anchor.ts";
// A-183.1 / A-195.2: the closed anchoring-profile class table, shared by the outbox, the gateway and verify.
export { anchoringProfileClass, ANCHORING_PROFILE_CLASSES, PRODUCTION_ANCHORING_PROFILE, TEST_ANCHORING_PROFILE, TEST_PROFILE_LABEL, TEST_TRUSTED_NODE_BARRIER_LABEL } from "./anchoring-profiles.ts";
export type { AnchoringProfileClass, AnchoringProfilePair } from "./anchoring-profiles.ts";
// ---------------------------------------------------------------- remote witness client (docs/WITNESS.md)
export {
  remoteWitness, normalizeWitnessPolicy, normalizeWitnessConfig, normalizeWitnessUrl, isLoopbackHost, memoryCheckpointTracker, witnessesToConsult, WITNESS_PROTOCOL_VERSION,
  DEFAULT_WITNESS_TIMEOUT_MS, DEFAULT_MAX_UNWITNESSED_EVENTS, DEFAULT_WITNESS_CACHE_MS, MAX_REMOTE_WITNESSES,
} from "./witness-client.ts";
export type {
  RemoteWitness, RemoteWitnessConfig, WitnessPolicy, ResolvedWitnessPolicy, WitnessMode, WitnessFetch, CheckpointTracker, StoredCheckpoint, VerifiedCheckpoint,
  RemoteWitnessedHead, WitnessHistoryInfo, SubmitResult as WitnessSubmitResult, WitnessInfo,
  KeyEventResult as WitnessKeyEventResult, KeyEventDelivery as WitnessKeyEventDelivery,
} from "./witness-client.ts";
export { PENDING_ROTATION_VERSION, pendingRotationPathFor, readPendingRotation, judgePendingRotation } from "./rotation-pending.ts";
export type { PendingRotationRecord, PendingRotationJudgement } from "./rotation-pending.ts";
export { witnessStatePathFor, readWitnessState, minimumWitnessPolicy, WITNESS_POLICY_ENV, WITNESS_STATE_VERSION, WITNESS_CACHE_SEAL_VERSION } from "./witness-state.ts";
export type {
  WitnessStateDoc, StoredPolicy as StoredWitnessPolicy, StoredWitnessConfig, PendingItem as PendingWitnessItem, CachedLatest as CachedWitnessLatest, MinimumWitnessPolicy,
} from "./witness-state.ts";
export {
  EQUIVOCATION_WARNING, SUPERSEDE_WARNING, NO_COMMITMENT_WARNING, boundWitnessesOf, boundRegistrationOf, boundPolicyOf, bindingPolicyOf, witnessBindingEvent, signStatement, verifySignedStatement,
} from "./witness-session.ts";
export type { RemoteWitnessReport, RemoteWitnessStatus, WitnessStatusReport, WitnessView, WitnessBindingAction, BindingWitness, AcceptedLossRecord } from "./witness-session.ts";
export type { AnchorTarget, AnchorKind, AnchorContext, AnchorLogEntry, AnchorLogHead, AnchorLogStatus, AnchorResult, VerifyOptions, PinnedHeadStatus, VerificationReport } from "./anchor.ts";

// ---------------------------------------------------------------- local host API, capacity, migration
export {
  createLocalOwner, createLocalAttemptOwner, createLocalReviewOwner, openLocalOwner, createLocalDomain, verifyHistory, verifyHistoryAsync, verifyHistoryWithWitnesses, POLICY_VERSIONS, POLICY,
  ownerKeyStatusOf, NEXT_KEY_ON_HOST_WARNING, authorizeControlEvent,
  openLocalRuntime, openLocalSimulation, createSimulatedAdapter, commitTerms, openLocalExecution, openLocalEvidenceTool, selectEvidence,
  openLocalAttemptRecorder, inspectAttemptHistory, openLocalDutyPolicy, capturePolicy, evaluatePolicy, observeHistory, observeState, captureHistory, replayHistory,
  capacityOf, assertCapacityTransition, CAPACITY_PROFILE, LEGACY_CAPACITY_PROFILE, migrateHistory, IronTrellisError, ContinuityError,
  REFUSAL_NOT_RECORDED_REASONS, REFUSAL_POLICY_DEFAULTS, DERIVED_ID_LITERALS, derivedId, REFUSAL_SPOOL_VERSION, refusalSpoolPathFor, refusalSideLogPathFor, spooledRefusalCount, boundedRefusal, drainRefusalSpool, MAX_CLOCK_SKEW_MS, clockAheadOfReader,
} from "./local.ts";
export type {
  LocalOwner, LocalOwnerOptions, WriteResult, Grant, Delegation, Prohibition, Appointment, Unappointment, Termination, RuntimeAdmission, Succession, HandoverReport, RuntimeSessionView, OwnerVerification, VerifyHistoryOptions,
  CheckpointResult, StateRootReport, BudgetDeclaration, BudgetUpdate, CounterpartyKey, HeadroomInput, Headroom, RefusalInput, RefusalResult, RefusalNotRecorded, RefusalNotRecordedReason, RefusalPolicy, RunRefusalReport, EffectInput, CounterpartyEnvelope, CounterpartyReceiptInput, ObservationInput, ObservationResult, SessionWrites,
  OwnerKeyRotation, OwnerKeyRotationResult, PreparedOwnerKeyRotation, NextKeyCommitment, NextKeyCommitmentResult, KeyEventExport, OwnerKeyStatus, OwnerKeyWarning, KeyCustody, NextKeyFileState, WitnessPolicyUpdate, WitnessChange, AddWitnessOptions, RemoveWitnessOptions, VerifyHistoryWithWitnessesOptions,
  PreparedControlEvent, ControlAuthorizationEntry, OwnerPolicyRotation,
  LocalRuntime, LocalRuntimeOptions, Obligation, Assignment, LocalSimulation, LocalSimulationOptions, SimulationOperation, SimulatedAdapter, SimulatedAdapterAttempt,
  LocalExecution, LocalExecutionOptions, LocalOperation, ExecutionMode, SignHash, ExecutionDispatchContext, ExecutionDispatchDecision, LocalExecutionDispatchHooks, LocalEvidenceTool, EvidenceToolOptions, EvidenceSelection, EvidenceRequest,
  LocalAttemptRecorder, OutcomeObservation, AttemptDuty, AttemptDutyAssignment, AttemptDutyReview as AttemptDutyReviewInput, AdditionalPolicy, PolicyRequest, PolicyDecision, PolicyEvidence,
  LocalDutyPolicy, LocalDutyPolicyOptions, DutyFindingSigner, DutyDisposition, DutyContest, DutyPolicyActivation as DutyPolicyActivationInput, DutyDescription, DutyWriteResult, DutyInspection, PreparedDutyOperation,
  Action, Decision as ObservationDecision, Observation, ObservationOptions, CapacityReport, CapacityProfile, MigrationOptions, MigrationResult, IronTrellisErrorCode, ContinuityErrorCode,
} from "./local.ts";
export { createPacketExecutor, selectInput } from "./adapters/packet-executor.ts";
export type { PacketExecutor, PacketExecutorOptions, PacketInspection } from "./adapters/packet-executor.ts";

// ---------------------------------------------------------------- transparency: witness wire formats (docs/WITNESS.md §9)
// Also available as `@ramex-labs/irontrellis/transparency`, under the same names.
export {
  MERKLE_HASH_SIZE, emptyRoot, leafHash, nodeHash, rootOf, MerkleTree, verifyInclusion, verifyConsistency,
  ALG_ED25519, MAX_NOTE_SIGNATURES, NoteError, isValidNoteKeyName, noteKeyHash, verifierKey, parseVerifierKey, noteSignerFromSeed, noteSignerFromKeyObject,
  parseSignerKey, formatSignerKey, generateNoteKey, signNote, openNote, formatCheckpoint, parseCheckpoint,
  HEAD_STATEMENT_VERSION, validateHeadStatement, headStatementHash, signHeadStatement, signHeadStatementSync, validateSignedHeadStatement, verifySignedHeadStatement,
  WITNESS_ENTRY_VERSION, WITNESS_ENTRY_KINDS, encodeEntry, entryLeafHash, validateEntry, WITNESS_RECEIPT_VERSION, buildReceipt, verifyWitnessReceipt, encodeBase64, decodeBase64,
  LATEST_NOTE_VERSION, isValidNonce, newNonce, formatLatestNote, parseLatestNote, verifyLatestNote,
  KEY_EVENT_BUNDLE_VERSION, validateKeyEventBundle, keyEventBundlePathFor,
} from "./transparency/index.ts";
export type {
  NoteSigner, NoteErrorCode, ParsedVerifierKey, OpenedNote, Checkpoint, HeadStatement, SignedHeadStatement, StatementHead, StatementPrevious, SignedHeadStatementVerification,
  WitnessEntry, WitnessEntryKind, RegisteredEntry, HeadEntry, RotatedEntry, EquivocationEntry, SupersededEntry, KeyEventBundle,
  WitnessReceipt, WitnessReceiptFailure, WitnessReceiptVerification, LatestNote, LatestNoteFailure, LatestNoteVerification,
} from "./transparency/index.ts";
// ---------------------------------------------------------------- end transparency
