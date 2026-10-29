/**
 * `@ramex-labs/irontrellis/local`: the privileged host surface — owner handles,
 * signed runtime/simulation/execution handles and the evidence tool. Keep every
 * handle, history path, clock and signer callback outside agent control.
 */
export {
  createLocalOwner, createLocalAttemptOwner, createLocalReviewOwner, openLocalOwner, createLocalDomain, verifyHistory, verifyHistoryAsync, verifyHistoryWithWitnesses, POLICY_VERSIONS, POLICY,
  ownerKeyStatusOf, NEXT_KEY_ON_HOST_WARNING, authorizeControlEvent,
} from "./owner.ts";
export type {
  LocalOwner, LocalOwnerOptions, WriteResult, Grant, Delegation, Prohibition, Appointment, Unappointment, Termination, RuntimeAdmission, Succession,
  HandoverReport, RuntimeSessionView, OwnerVerification, VerifyHistoryOptions, Signer, OwnerKeyRotation, OwnerKeyRotationResult, PreparedOwnerKeyRotation, NextKeyCommitment, NextKeyCommitmentResult, KeyEventExport, OwnerKeyStatus, OwnerKeyWarning, KeyCustody, NextKeyFileState, WitnessPolicyUpdate, WitnessChange, AddWitnessOptions, RemoveWitnessOptions, VerifyHistoryWithWitnessesOptions,
  CheckpointResult, StateRootReport, BudgetDeclaration, BudgetUpdate, CounterpartyKey, HeadroomInput, Headroom,
  PreparedControlEvent, ControlAuthorizationEntry, OwnerPolicyRotation,
} from "./owner.ts";
export type { RefusalInput, RefusalResult, RefusalNotRecorded, RefusalNotRecordedReason, RefusalPolicy, EffectInput, CounterpartyEnvelope, CounterpartyReceiptInput, ObservationInput, ObservationResult, SessionWrites } from "./session-writes.ts";
export { REFUSAL_NOT_RECORDED_REASONS, REFUSAL_POLICY_DEFAULTS, DERIVED_ID_LITERALS, derivedId } from "./session-writes.ts";
export { REFUSAL_SPOOL_VERSION, refusalSpoolPathFor, refusalSideLogPathFor, spooledRefusalCount, boundedRefusal, drainRefusalSpool } from "./refusal-spool.ts";
export { openLocalRuntime } from "./runtime.ts";
export type { LocalRuntime, LocalRuntimeOptions, Obligation, Assignment } from "./runtime.ts";
export { openLocalSimulation, createSimulatedAdapter, commitTerms } from "./simulation.ts";
export type { LocalSimulation, LocalSimulationOptions, SimulationOperation, SimulatedAdapter, SimulatedAdapterAttempt } from "./simulation.ts";
export { openLocalExecution, MAX_CLOCK_SKEW_MS, clockAheadOfReader } from "./execution.ts";
export type { RunRefusalReport } from "./execution.ts";
export type { LocalExecution, LocalExecutionOptions, LocalOperation, ExecutionMode, SignHash, ExecutionDispatchContext, ExecutionDispatchDecision, LocalExecutionDispatchHooks } from "./execution.ts";
export { openLocalEvidenceTool, selectEvidence } from "./evidence.ts";
export type { LocalEvidenceTool, EvidenceToolOptions, EvidenceSelection, EvidenceRequest } from "./evidence.ts";
export { openLocalAttemptRecorder, inspectAttemptHistory } from "./attempts.ts";
export type { LocalAttemptRecorder, OutcomeObservation, AttemptDuty, AttemptDutyAssignment, AttemptDutyReview } from "./attempts.ts";
export { openLocalDutyPolicy } from "./duties.ts";
export type {
  LocalDutyPolicy, LocalDutyPolicyOptions, DutyFindingSigner, DutyPolicySelection, DutyPolicyActivation, DutyDisposition, DutyContest, DutyChecklist, DutyCriterion,
  DutyDescription, DutyWriteResult, DutyInspection, PreparedDutyOperation, DutyPolicyDescriptor, DutyPolicyView,
} from "./duties.ts";
export { capturePolicy, evaluatePolicy } from "./policy.ts";
export type { AdditionalPolicy, PolicyRequest, PolicyDecision, PolicyEvidence } from "./policy.ts";
export { observeHistory, observeState, captureHistory, replayHistory } from "./observation.ts";
export type { Action, Decision, Observation, ObservationOptions } from "./observation.ts";
export { capacityOf, assertCapacityTransition, CAPACITY_PROFILE, LEGACY_CAPACITY_PROFILE } from "./capacity.ts";
export type { CapacityReport, CapacityProfile } from "./capacity.ts";
export { migrateHistory } from "./migrate.ts";
export type { MigrationOptions, MigrationResult } from "./migrate.ts";
export { IronTrellisError, ContinuityError } from "./input.ts";
export type { IronTrellisErrorCode, ContinuityErrorCode } from "./input.ts";

export type { ResumeInvocationRequest, ResumeInvocationResult } from "./coordinators.ts";
