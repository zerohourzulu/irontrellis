/**
 * Attempt records (port of Core 0.3 `attempts.ts`): signed observations of
 * remote-service reports, investigation duties over them, their assignment and
 * (E6) evidence review. Recorded reports establish neither truth nor power.
 */
import { compareProtocolStrings } from "./canonical.ts";
import { ADAPTER_POLICY_E6_HASH, REMOTE_SERVICE_REPORT_ADAPTER_ID, policyEnablesAttemptDuties, validateAdapterAcknowledgment, type AdapterAcknowledgment } from "./adapter-editions.ts";
import type { AdministrativeEventType } from "./administration.ts";
import { attemptDutyReviewStatus } from "./queries.ts";
import { inspectDutyPolicyState } from "./duty-policy.ts";
import { contentHash, identifier, record, requireCondition, time } from "./input.ts";
import { replayHistory } from "./observation.ts";
import { configuration, currentState, openStore, type WriteResult } from "./owner.ts";
import { administrativeEffect, description, type LocalRuntimeOptions } from "./runtime.ts";
import { sessionOf, signedTransition } from "./runtime-writes.ts";
import type { AttemptDutyRecord, CanonicalEvent, ContentHash, IntentAdmissionRecord, ReplayState, TransactionIntent } from "./types.ts";

export type OutcomeObservation = Readonly<{ id: string; intent: string; acknowledgment: AdapterAcknowledgment }>;
export type AttemptDuty = Readonly<{ id: string; intent: string; description: string; deadline: number }>;
export type AttemptDutyAssignment = Readonly<{ id: string; duty: string }>;
export type AttemptDutyReview = Readonly<{ id: string; duty: string; summaryDigest: ContentHash }>;

const requireAttemptPolicy = (state: ReplayState): void => requireCondition(policyEnablesAttemptDuties(state.genesis.adapterPolicyHash), "PROFILE_MISMATCH");
type Source = Readonly<{ intent: TransactionIntent; admission: IntentAdmissionRecord; sourceAdmissionEventId: string }>;
function selectedSource(state: ReplayState, intentId: string): Source {
  requireAttemptPolicy(state);
  const intent = state.intentDeclarations.get(intentId)?.data, admission = state.intentAdmissions.get(intentId);
  requireCondition(intent !== undefined && admission !== undefined && intent.adapterProfile.profileId === REMOTE_SERVICE_REPORT_ADAPTER_ID, "TRANSITION_REJECTED");
  return { intent, admission, sourceAdmissionEventId: (state.events[admission.admissionEventPosition] as CanonicalEvent).id };
}
const existingEffect = (state: ReplayState, eventId: string, type: AdministrativeEventType): Readonly<Record<string, unknown>> | undefined => {
  const position = state.eventPositionsById.get(eventId);
  if (position === undefined) return undefined;
  const existing = state.events[position] as CanonicalEvent;
  requireCondition(existing.type === type, "OPERATION_CONFLICT");
  return administrativeEffect(existing);
};

/** Application-owned recording authority. No adapter, URL or dispatch callback. */
export function openLocalAttemptRecorder(options: LocalRuntimeOptions) {
  const config = configuration(options), sessionId = identifier(options.session), signer = options.signHash;
  requireCondition(typeof signer === "function");
  const store = openStore(config);
  requireAttemptPolicy(currentState(store, config));
  const session = sessionOf(store, config, sessionId);
  const signed = (id: string, type: AdministrativeEventType, data: Readonly<Record<string, unknown>>) => signedTransition(store, config, sessionId, signer, id, type, data);
  return Object.freeze({
    async observe(input: OutcomeObservation): Promise<WriteResult> {
      const value = record(input, ["id", "intent", "acknowledgment"]);
      const id = identifier(value.id), intentId = identifier(value.intent);
      const source = selectedSource(currentState(store, config), intentId);
      requireCondition(validateAdapterAcknowledgment(value.acknowledgment, source.admission.adapterIdentity), "TRANSITION_REJECTED");
      const acknowledgment = value.acknowledgment as AdapterAcknowledgment;
      requireCondition(acknowledgment.result.kind === "REMOTE_SERVICE_REPORTED", "TRANSITION_REJECTED");
      return signed(`attempt-observation:${id}`, "OUTCOME_OBSERVATION_RECORDED", { intentId, sourceAdmissionEventId: source.sourceAdmissionEventId, acknowledgment, actorId: session.agentId });
    },
    async createDuty(input: AttemptDuty): Promise<WriteResult> {
      const value = record(input, ["id", "intent", "description", "deadline"]);
      const dutyId = identifier(value.id), intentId = identifier(value.intent), text = description(value.description), deadline = time(value.deadline);
      const state = currentState(store, config), source = selectedSource(state, intentId);
      const eventId = `attempt-duty:${dutyId}:create`;
      const effect = existingEffect(state, eventId, "ATTEMPT_DUTY_CREATED");
      // Repetition compares the originally requested creation, even after the role has moved. It must not reconstruct a different creation tenure.
      if (effect !== undefined) {
        const original = effect.record as AttemptDutyRecord;
        requireCondition(original.dutyId === dutyId && original.sourceIntentId === intentId && original.sourceAdmissionEventId === source.sourceAdmissionEventId &&
          original.description === text && original.deadline === deadline && effect.actorId === session.agentId, "OPERATION_CONFLICT");
        return signed(eventId, "ATTEMPT_DUTY_CREATED", effect);
      }
      const role = state.roles.get(source.intent.roleId);
      const tenure = role?.currentTenureId === undefined ? undefined : state.tenures.get(role.currentTenureId);
      requireCondition(role !== undefined && tenure !== undefined && !tenure.closed && tenure.agentId === session.agentId, "RUNTIME_NOT_CURRENT");
      const duty: AttemptDutyRecord = {
        dutyId, sourceIntentId: intentId, sourceAdmissionEventId: source.sourceAdmissionEventId, durableRoleId: source.intent.roleId, creationRoleTenureId: tenure.id,
        description: text, deadline, performanceAssigneeId: session.agentId, status: "OPEN",
      };
      return signed(eventId, "ATTEMPT_DUTY_CREATED", { record: duty, actorId: session.agentId });
    },
    async reviewDuty(input: AttemptDutyReview): Promise<WriteResult> {
      const value = record(input, ["id", "duty", "summaryDigest"]);
      const id = identifier(value.id), dutyId = identifier(value.duty), summaryDigest = contentHash(value.summaryDigest);
      const state = currentState(store, config);
      requireCondition(state.genesis.adapterPolicyHash === ADAPTER_POLICY_E6_HASH, "PROFILE_MISMATCH");
      const duty = state.attemptDuties.get(dutyId);
      requireCondition(duty !== undefined, "TRANSITION_REJECTED");
      selectedSource(state, duty.record.sourceIntentId);
      const eventId = `attempt-duty-review:${id}`;
      const effect = existingEffect(state, eventId, "ATTEMPT_DUTY_REVIEW_CLOSED");
      if (effect !== undefined) {
        requireCondition(effect.dutyId === dutyId && effect.actorId === session.agentId && effect.summaryDigest === summaryDigest, "OPERATION_CONFLICT");
        // Observe the original signed record after later evidence, assignment or retirement.
        return signed(eventId, "ATTEMPT_DUTY_REVIEW_CLOSED", effect);
      }
      const observationEventIds = (state.outcomeObservations.get(duty.record.sourceIntentId) ?? []).map((item) => item.eventId).sort(compareProtocolStrings);
      return signed(eventId, "ATTEMPT_DUTY_REVIEW_CLOSED", { dutyId, actorId: session.agentId, observationEventIds, summaryDigest });
    },
    async assignDuty(input: AttemptDutyAssignment): Promise<WriteResult> {
      const value = record(input, ["id", "duty"]);
      const id = identifier(value.id), dutyId = identifier(value.duty);
      const state = currentState(store, config), duty = state.attemptDuties.get(dutyId);
      requireCondition(duty !== undefined, "TRANSITION_REJECTED");
      selectedSource(state, duty.record.sourceIntentId);
      const eventId = `attempt-duty-assignment:${id}`;
      const effect = existingEffect(state, eventId, "ATTEMPT_DUTY_ASSIGNED");
      if (effect !== undefined) {
        requireCondition(effect.dutyId === dutyId && effect.toAgentId === session.agentId && effect.actorId === session.agentId, "OPERATION_CONFLICT");
        return signed(eventId, "ATTEMPT_DUTY_ASSIGNED", effect);
      }
      return signed(eventId, "ATTEMPT_DUTY_ASSIGNED", { dutyId, fromAgentId: duty.currentAssigneeId, toAgentId: session.agentId, actorId: session.agentId });
    },
  });
}
export type LocalAttemptRecorder = ReturnType<typeof openLocalAttemptRecorder>;

/** Replay-only inspection. Recorded reports establish neither truth nor power. */
export function inspectAttemptHistory(input: unknown) {
  const state = replayHistory(input);
  requireAttemptPolicy(state);
  const e6 = state.genesis.adapterPolicyHash === ADAPTER_POLICY_E6_HASH;
  const attempts = [...state.intentAdmissions.values()]
    .filter((admission) => state.intentDeclarations.get(admission.intentId)?.data.adapterProfile.profileId === REMOTE_SERVICE_REPORT_ADAPTER_ID)
    .map((admission) => {
      const source = selectedSource(state, admission.intentId);
      const observations = state.outcomeObservations.get(admission.intentId) ?? [];
      const digests = new Set(observations.map((o) => ((o.acknowledgment.result as Readonly<Record<string, unknown>>).reportDigest as Readonly<Record<string, unknown>>).value));
      const duty = [...state.attemptDuties.values()].find((item) => item.record.sourceIntentId === admission.intentId);
      return Object.freeze({
        intentId: admission.intentId, sourceAdmissionEventId: source.sourceAdmissionEventId, originalActorId: source.intent.actorId, originalSessionId: admission.runtimeSessionId,
        originalControlEpoch: admission.controlEpoch, durableRoleId: source.intent.roleId, observations,
        reportStatus: digests.size === 0 ? ("NO_RECORDED_REPORTS" as const) : digests.size === 1 ? ("REPORT_RECORDED" as const) : ("DIVERGENT_REPORTS" as const),
        // SPEC §13.6 (E4), `core-0.3/src/attempts.ts:213-217`: a duty with an active policy carries `disposition: <view>`; E6 reviews otherwise.
        duty: duty === undefined ? null : state.attemptDutyPolicies?.has(duty.record.dutyId)
          ? Object.freeze({ ...duty, disposition: inspectDutyPolicyState(state, duty.record.dutyId) })
          : e6
          ? Object.freeze({ ...duty, reviews: state.attemptDutyReviews.get(duty.record.dutyId) ?? [], reviewStatus: attemptDutyReviewStatus(state, duty.record.dutyId) })
          : duty,
        externalOutcome: "NOT_PROVEN" as const,
      });
    })
    .sort((a, b) => compareProtocolStrings(a.intentId, b.intentId));
  return Object.freeze({ scope: "CAPTURED_HISTORY_ONLY" as const, executionCapability: false as const, head: state.head, attempts: Object.freeze(attempts) });
}
