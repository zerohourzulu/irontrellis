import { inspectPortableDutyPolicy } from "./duty-policy.ts";
// Package-internal projection over an already accepted replay snapshot. The
// query coordinator owns capture, replay provenance, time and output limits.
import { portableAttemptDutyReviewStatus } from "./portable-attempt-review.ts";
import { PORTABLE_ADAPTER_POLICY_E5_HASH, PORTABLE_ADAPTER_POLICY_E6_HASH } from "./portable-adapter-engine.ts";
import { canonicalEncode, compareProtocolStrings } from "./canonical.ts";
import type { PortableAuthorityRecord, PortableReplayEvidenceReference, PortableReplayState } from "./portable-replay.ts";
import {
  compareQueryEvidence,
  type PortableSurvivesAnswer, type PortableRoleTenureProjection,
  type PortableIntentProjection, type PortableObligationProjection,
  type PortableAdapterOutcomeProjection,
  type PortablePerformanceAssignmentProjection, type PortableAuthorityDependencyProjection,
} from "./portable-query-codec.ts";
import { createPortableQueryEvidenceCache, createPortableQueryProjectionWriter, requirePortableQueryProjection,
  createPortableQueryComparisonPlan, portableQueryComparisonPlansDiffer,
  type PortableQueryProjectionWriter, type PortableQueryDerivation } from "./portable-query-output.ts";

type Evidence = PortableReplayEvidenceReference;
const eventsMatching = (state: PortableReplayState, reference: (position: number) => Evidence, predicate: (event: PortableReplayState["events"][number]) => boolean): Evidence[] => {
  const result: Evidence[] = [];
  for (let position = 0; position < state.events.length; position += 1) {
    if (predicate(state.events[position]!)) result.push(reference(position));
  }
  return result;
};

/** The relevance relation includes historical assignments, even after closure. */
export const portableObligationLinksTarget = (state: PortableReplayState, obligationId: string, targetAgentId: string): boolean => {
  const obligation = state.obligations.get(obligationId);
  if (obligation === undefined) return false;
  const record = obligation.record;
  if (state.intentDeclarations.get(record.sourceIntentId)?.data.actorId === targetAgentId ||
      state.tenures.get(record.creationRoleTenureId)?.agentId === targetAgentId ||
      record.performanceAssigneeId === targetAgentId) return true;
  for (const event of state.events) {
    if (event.type === "OBLIGATION_PERFORMANCE_ASSIGNED" && event.data.obligationId === obligationId &&
        event.data.toAgentId === targetAgentId) return true;
  }
  return false;
};

const parentPath = (state: PortableReplayState, record: PortableAuthorityRecord): PortableAuthorityRecord[] => {
  const result: PortableAuthorityRecord[] = [];
  let cursor: PortableAuthorityRecord | undefined = record;
  while (cursor?.grant.kind === "PERMISSION") {
    result.push(cursor);
    cursor = cursor.grant.parentAuthorityId === undefined ? undefined : state.authorities.get(cursor.grant.parentAuthorityId);
  }
  return result;
};

const dependencies = (state: PortableReplayState, path: readonly PortableAuthorityRecord[]): PortableAuthorityRecord[] => {
  const result: PortableAuthorityRecord[] = [];
  const seen = new Set<string>();
  const queue = [...path];
  const enqueued = new Set(path.map(record => record.grant.authorityId));
  for (let index = 0; index < queue.length; index += 1) {
    const record = queue[index]!;
    if (seen.has(record.grant.authorityId)) continue;
    seen.add(record.grant.authorityId);
    result.push(record);
    for (const identifier of record.grant.constraints.requiredIntersectionIds) {
      const required = state.authorities.get(identifier);
      if (required?.grant.kind === "PERMISSION") for (const dependency of parentPath(state, required)) {
        if (enqueued.has(dependency.grant.authorityId)) continue;
        enqueued.add(dependency.grant.authorityId); queue.push(dependency);
      }
    }
  }
  return result;
};

const leastEvidence = (references: readonly Evidence[]): Evidence => {
  let least = references[0]!;
  for (const reference of references) if (compareQueryEvidence(reference, least) < 0) least = reference;
  return least;
};

const skeletonFor = (state: PortableReplayState, targetAgentId: string): PortableSurvivesAnswer => ({
  targetAgentId, exists: state.agents.has(targetAgentId),
  lifecycleStatus: !state.agents.has(targetAgentId) ? "ABSENT" : state.agents.get(targetAgentId)!.terminated ? "TERMINATED" : "ACTIVE",
  historicalIdentity: [], currentRoleTenures: [], transferredRoleTenures: [], unresolvedIntents: [],
  adapterOutcomes: [],
  ...((state.genesis.adapterPolicyHash === PORTABLE_ADAPTER_POLICY_E5_HASH || state.genesis.adapterPolicyHash === PORTABLE_ADAPTER_POLICY_E6_HASH) ? {outcomeObservations: [], attemptDuties: []} : {}),
  receiptCommitments: [], obligations: [], currentPerformanceAssignments: [], invalidatedAuthorityDependencies: [],
});

const walkPortableSurvives = (state: PortableReplayState, targetAgentId: string, evaluationTime: number,
  writer: PortableQueryProjectionWriter): void => {
  const agent = state.agents.get(targetAgentId);
  const cache = createPortableQueryEvidenceCache();
  const eventReference = (position: number) => cache.event(state, position);
  const receiptReference = cache.receipt;
  const matching = (predicate: (event: PortableReplayState["events"][number]) => boolean) => eventsMatching(state, eventReference, predicate);
  if (agent === undefined) return;

  writer.evidence("historicalIdentity", matching(event =>
    (event.type === "PRINCIPAL_CREATED" && event.data.principalId === agent.principalId) ||
    ((event.type === "AGENT_CREATED" || event.type === "AGENT_TERMINATED") && event.data.agentId === targetAgentId)));

  for (const tenure of state.tenures.values()) {
    if (tenure.agentId !== targetAgentId) continue;
    const evidence = matching(event =>
      (event.type === "ROLE_CREATED" && event.data.roleId === tenure.roleId) ||
      ((event.type === "AGENT_APPOINTED" || event.type === "AGENT_UNAPPOINTED") && event.data.roleTenureId === tenure.id) ||
      (event.type === "ROLE_TRANSFERRED" && (event.data.fromRoleTenureId === tenure.id || event.data.toRoleTenureId === tenure.id)));
    writer.row(tenure.closed ? "transferredRoleTenures" : "currentRoleTenures", tenure.id,
      { roleId: tenure.roleId, agentId: targetAgentId, roleTenureId: tenure.id,
        tenureNumber: tenure.tenureNumber, status: tenure.closed ? "CLOSED" : "CURRENT" }, evidence);
  }
  const includedIntentIds = new Set<string>();
  for (const [intentId, declaration] of state.intentDeclarations) {
    if (declaration.data.actorId !== targetAgentId) continue;
    const latestOutcome = state.intentOutcomeStates.get(intentId)?.latest;
    const outcome = latestOutcome?.status, consumption = state.intentConsumptions.get(intentId);
    const evidence = matching(event => event.data.intentId === intentId &&
      (event.type === "TRANSACTION_INTENT_DECLARED" || event.type === "TRANSACTION_INTENT_ADMITTED" ||
       event.type === "TRANSACTION_INTENT_CONSUMED" || event.type === "TRANSACTION_OUTCOME_RECORDED"));
    if (consumption !== undefined || latestOutcome !== undefined) {
      writer.row("adapterOutcomes", intentId, {
        intentId, actorId: targetAgentId, adapterProfile: declaration.data.adapterProfile,
        state: outcome ?? "SUBMITTED",
        ...(consumption === undefined ? {} : { acknowledgment: consumption.acknowledgment }),
        ...(latestOutcome === undefined ? {} : { latestOutcome }),
      }, evidence);
    }
    // Terminal adapter outcomes remain visible above, without becoming an
    // unresolved intent or restoring the admitted nonce/submission authority.
    if (outcome === "CONFIRMED" || outcome === "FAILED") continue;
    const intentState = outcome ?? (consumption !== undefined ? "SUBMITTED" : state.intentAdmissions.has(intentId) ? "ADMITTED" : "DECLARED");
    writer.row("unresolvedIntents", intentId, { intentId, actorId: targetAgentId, nonce: declaration.data.nonce, state: intentState }, evidence);
    includedIntentIds.add(intentId);
  }

  // E5 adds recordkeeping and responsibility without changing execution state.
  // Keep every recorder and digest visible; differing bytes are not a verdict.
  for (const [intentId, observations] of state.outcomeObservations) {
    const originalActorId = state.intentDeclarations.get(intentId)!.data.actorId;
    const relatedDuty = [...state.attemptDuties.values()].find(item => item.record.sourceIntentId === intentId);
    const linkedAssignee = relatedDuty !== undefined && (relatedDuty.record.performanceAssigneeId === targetAgentId ||
      relatedDuty.assignments.some(item => item.fromAgentId === targetAgentId || item.toAgentId === targetAgentId));
    if (originalActorId !== targetAgentId && !observations.some(item => item.actorId === targetAgentId) && !linkedAssignee) continue;
    const digests = new Set(observations.map(item => item.acknowledgment.result.reportDigest.value));
    const source = state.intentAdmissions.get(intentId)!;
    for (const observation of observations) writer.row("outcomeObservations", observation.eventId, {
      observationEventId: observation.eventId, intentId, sourceAdmissionEventId: observation.sourceAdmissionEventId,
      originalActorId, recorderId: observation.actorId, recordedAt: observation.observedAt,
      reportDigest: observation.acknowledgment.result.reportDigest,
      reportStatus: digests.size > 1 ? "DIVERGENT_REPORTS" : "REPORT_RECORDED", externalOutcome: "NOT_PROVEN",
    }, [eventReference(source.admissionEventPosition), eventReference(observation.eventPosition)]);
  }
  for (const [dutyId, duty] of state.attemptDuties) {
    const record = duty.record, source = state.intentAdmissions.get(record.sourceIntentId)!;
    const originalActorId = state.intentDeclarations.get(record.sourceIntentId)!.data.actorId;
    if (originalActorId !== targetAgentId && record.performanceAssigneeId !== targetAgentId &&
        !duty.assignments.some(item => item.fromAgentId === targetAgentId || item.toAgentId === targetAgentId)) continue;
    const currentView = inspectPortableDutyPolicy(state, dutyId);
    writer.row("attemptDuties", dutyId, {
      dutyId, sourceIntentId: record.sourceIntentId, sourceAdmissionEventId: record.sourceAdmissionEventId,
      originalActorId, durableRoleId: record.durableRoleId, creationActorId: duty.creationActorId,
      initialAssigneeId: record.performanceAssigneeId, currentAssigneeId: duty.currentAssigneeId,
      deadline: record.deadline, ...(currentView ? { currentView } : { status: record.status }), externalOutcome: "NOT_PROVEN",
      ...(state.genesis.adapterPolicyHash === PORTABLE_ADAPTER_POLICY_E6_HASH ? {
        reviewStatus: portableAttemptDutyReviewStatus(state, dutyId), reviews: state.attemptDutyReviews.get(dutyId) ?? [],
      } : {}),
    }, [eventReference(source.admissionEventPosition), eventReference(duty.creationEventPosition),
      ...(currentView ? [eventReference(currentView.policy.eventPosition), ...state.events.flatMap((event,position) =>
        (event.type === "ATTEMPT_DUTY_DISPOSITION_RECORDED" || event.type === "ATTEMPT_DUTY_CONTEST_RECORDED") && event.data.dutyId === dutyId ? [eventReference(position)] : [])] : []),
      ...duty.assignments.map(item => eventReference(item.eventPosition)),
      ...(state.genesis.adapterPolicyHash === PORTABLE_ADAPTER_POLICY_E6_HASH ? [
        ...(state.attemptDutyReviews.get(dutyId) ?? []).map(item => eventReference(item.eventPosition)),
        ...(state.outcomeObservations.get(record.sourceIntentId) ?? []).map(item => eventReference(item.eventPosition)),
      ] : [])]);
  }

  const includedReceiptHashes = new Set<string>();
  for (const [obligationId, obligation] of state.obligations) {
    if (obligation.status === "DISCHARGED" || obligation.status === "IMPOSSIBLE_OR_ESCALATED" ||
        !portableObligationLinksTarget(state, obligationId, targetAgentId)) continue;
    const record = obligation.record;
    const receipt = state.receiptCommitments.get(record.causalReceiptContentHash)!;
    const causal = [receiptReference(receipt), eventReference(obligation.creationEventPosition)];
    const assignments = matching(event => event.type === "OBLIGATION_PERFORMANCE_ASSIGNED" && event.data.obligationId === obligationId);
    const statuses = matching(event => event.type === "OBLIGATION_STATUS_RECORDED" && event.data.obligationId === obligationId);
    const targetLinks = matching(event =>
      (event.type === "TRANSACTION_INTENT_DECLARED" && event.data.intentId === record.sourceIntentId && event.data.actorId === targetAgentId) ||
      (event.type === "AGENT_APPOINTED" && event.data.roleTenureId === record.creationRoleTenureId && event.data.agentId === targetAgentId) ||
      (event.type === "ROLE_TRANSFERRED" && event.data.toRoleTenureId === record.creationRoleTenureId && event.data.toAgentId === targetAgentId));
    writer.row("obligations", obligationId, { obligationId, durableRoleId: record.durableRoleId,
      performanceAssigneeId: obligation.performanceAssigneeId, status: obligation.status, deadline: record.deadline },
      [...causal, ...assignments, ...statuses, ...targetLinks]);
    let successionRuleId = record.successionRuleId;
    for (const event of state.events) {
      if (event.type === "OBLIGATION_PERFORMANCE_ASSIGNED" && event.data.obligationId === obligationId) successionRuleId = event.data.successionRuleId as string;
    }
    writer.row("currentPerformanceAssignments", obligationId,
      { obligationId, assigneeId: obligation.performanceAssigneeId, successionRuleId }, [...causal, ...assignments]);
    includedReceiptHashes.add(record.causalReceiptContentHash);
  }
  for (const receipt of state.receiptCommitments.values()) {
    if (includedIntentIds.has(receipt.intentId) || includedReceiptHashes.has(receipt.receiptContentHash)) writer.evidence("receiptCommitments", [receiptReference(receipt)]);
  }

  for (const [authorityId, record] of state.authorities) {
    if (record.grant.kind !== "PERMISSION") continue;
    const path = parentPath(state, record);
    if (!path.some(item => item.grant.kind === "PERMISSION" &&
      (item.grant.grantorId === targetAgentId || item.grant.granteeId === targetAgentId))) continue;
    const graph = dependencies(state, path);
    const pathEvidence = graph.map(item => eventReference(item.grantEventPosition));
    const revocations = graph.flatMap(item => item.revocationEventPosition === undefined ? [] : [eventReference(item.revocationEventPosition)]);
    if (revocations.length !== 0) {
      writer.row("invalidatedAuthorityDependencies", authorityId, { authorityId, state: "REVOKED" }, [...pathEvidence, leastEvidence(revocations)]);
      continue;
    }
    if (graph.some(item => item.grant.constraints.expiresAt !== undefined && evaluationTime >= item.grant.constraints.expiresAt)) {
      writer.row("invalidatedAuthorityDependencies", authorityId, { authorityId, state: "EXPIRED" }, pathEvidence);
      continue;
    }
    const terminatedIds = new Set<string>();
    for (const item of graph) {
      if (item.grant.kind !== "PERMISSION") continue;
      for (const id of [item.grant.grantorId, item.grant.granteeId]) {
        if (state.agents.get(id)?.terminated === true) terminatedIds.add(id);
      }
    }
    const terminations = matching(event => event.type === "AGENT_TERMINATED" && terminatedIds.has(event.data.agentId as string));
    if (terminations.length !== 0) writer.row("invalidatedAuthorityDependencies", authorityId, { authorityId, state: "AGENT_TERMINATED" },
      [...pathEvidence, leastEvidence(terminations)]);
  }
};

const sortSurvives = (answer: PortableSurvivesAnswer): void => {
  (answer.outcomeObservations as import("./portable-query-codec.ts").PortableOutcomeObservationProjection[] | undefined)?.sort((a,b) =>
    compareProtocolStrings(a.intentId,b.intentId) || compareProtocolStrings(a.observationEventId,b.observationEventId));
  (answer.attemptDuties as import("./portable-query-codec.ts").PortableAttemptDutyProjection[] | undefined)?.sort((a,b) => compareProtocolStrings(a.dutyId,b.dutyId));
  const compareTenures = (left: PortableRoleTenureProjection, right: PortableRoleTenureProjection) =>
    compareProtocolStrings(left.roleId, right.roleId) || left.tenureNumber - right.tenureNumber ||
    compareProtocolStrings(left.roleTenureId, right.roleTenureId);
  (answer.currentRoleTenures as PortableRoleTenureProjection[]).sort(compareTenures);
  (answer.transferredRoleTenures as PortableRoleTenureProjection[]).sort(compareTenures);
  (answer.unresolvedIntents as PortableIntentProjection[]).sort((a, b) => compareProtocolStrings(a.intentId, b.intentId));
  (answer.adapterOutcomes as PortableAdapterOutcomeProjection[]).sort((a, b) => compareProtocolStrings(a.intentId, b.intentId));
  (answer.obligations as PortableObligationProjection[]).sort((a, b) => compareProtocolStrings(a.obligationId, b.obligationId));
  (answer.currentPerformanceAssignments as PortablePerformanceAssignmentProjection[]).sort((a, b) => compareProtocolStrings(a.obligationId, b.obligationId));
  (answer.invalidatedAuthorityDependencies as PortableAuthorityDependencyProjection[]).sort((a, b) => compareProtocolStrings(a.authorityId, b.authorityId));
};

export const derivePortableSurvives = (state: PortableReplayState, targetAgentId: string,
  evaluationTime: number): PortableQueryDerivation<PortableSurvivesAnswer> => {
  const writer = createPortableQueryProjectionWriter(skeletonFor(state, targetAgentId));
  walkPortableSurvives(state, targetAgentId, evaluationTime, writer);
  return writer.finish(sortSurvives);
};

export const projectPortableSurvives = (state: PortableReplayState, targetAgentId: string,
  evaluationTime: number): PortableSurvivesAnswer => requirePortableQueryProjection(derivePortableSurvives(state, targetAgentId, evaluationTime));

export const portableSurvivesAnswersDiffer = (left: PortableReplayState, right: PortableReplayState,
  targetAgentId: string, evaluationTime: number): boolean => {
  if (canonicalEncode(skeletonFor(left, targetAgentId)) !== canonicalEncode(skeletonFor(right, targetAgentId))) return true;
  const intern = new Map<string, number>();
  const a = createPortableQueryComparisonPlan(intern), b = createPortableQueryComparisonPlan(intern);
  walkPortableSurvives(left, targetAgentId, evaluationTime, a);
  walkPortableSurvives(right, targetAgentId, evaluationTime, b);
  return portableQueryComparisonPlansDiffer(a, b);
};
