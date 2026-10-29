/**
 * SURVIVES projection (spec 03 §D) and fork-conflict classification (§E) over
 * accepted replay states. The coordinator in queries.ts owns capture, time,
 * disclosure and the final output bound.
 */
import { canonicalEncode, compareProtocolStrings } from "./canonical.ts";
import { hashCanonical } from "./hash.ts";
import { inspectDutyPolicyState } from "./duty-policy.ts";
import type { AuthorityRecord, CanonicalEvent, ConsequentialBinding, ReplayState, TransactionIntent, ObligationRecord } from "./types.ts";
import {
  compareQueryEvidence, createComparisonPlan, comparisonPlansDiffer, createEvidenceCache, createProjectionWriter, eventReference,
  type AuthorizationProofView, type EventReference, type ProjectionWriter, type QueryDerivation, type QueryEvidenceReference,
  type SurvivesAnswer, type RoleTenureProjection, type IntentProjection, type AdapterOutcomeProjection, type ObligationProjection,
  type PerformanceAssignmentProjection, type AuthorityDependencyProjection, type OutcomeObservationProjection, type AttemptDutyProjection,
} from "./query-codec.ts";

type Evidence = QueryEvidenceReference;
type Data = Readonly<Record<string, unknown>>;
export const ADAPTER_POLICY_E5_HASH = "0x32c2a5608c7110f1a291517e136cedf62d59a2cb81be1141dd2705bce307ab29";
export const ADAPTER_POLICY_E6_HASH = "0xa90baac702f22f5a5f71141318a7651c1d963bbbee28138bbea835d942d0114c";
const isAttemptPolicy = (state: ReplayState): boolean =>
  state.genesis.adapterPolicyHash === ADAPTER_POLICY_E5_HASH || state.genesis.adapterPolicyHash === ADAPTER_POLICY_E6_HASH;

const NO_POSITIONS: readonly number[] = Object.freeze([]);

/**
 * Event positions by type and by `(type, data field value)`, built lazily, once per SURVIVES walk: each projection
 * looks up the few events it cites instead of scanning the whole history per row (an agent with n intents, duties or
 * grants made SURVIVES O(n × events): minutes at 100,000 events, hours at 1,000,000). `where(type, field, value)` is
 * exactly the ascending positions of the events with `event.type === type && event.data[field] === value` (a `Map`
 * compares keys with SameValueZero, which differs from `===` only for NaN and -0, and neither is a protocol value).
 */
type EventIndex = Readonly<{
  ofType(type: string): readonly number[];
  where(type: string, field: string, value: unknown): readonly number[];
}>;
const createEventIndex = (state: ReplayState): EventIndex => {
  let types: Map<string, number[]> | undefined;
  const fields = new Map<string, Map<unknown, number[]>>();
  const ofType = (type: string): readonly number[] => {
    if (types === undefined) {
      types = new Map();
      for (let position = 0; position < state.events.length; position += 1) {
        const event = state.events[position] as CanonicalEvent;
        const list = types.get(event.type);
        if (list === undefined) types.set(event.type, [position]);
        else list.push(position);
      }
    }
    return types.get(type) ?? NO_POSITIONS;
  };
  return {
    ofType,
    where(type, field, value) {
      const key = `${type}\u0000${field}`;
      let index = fields.get(key);
      if (index === undefined) {
        index = new Map();
        for (const position of ofType(type)) {
          const fieldValue = ((state.events[position] as CanonicalEvent).data as Data)[field];
          const list = index.get(fieldValue);
          if (list === undefined) index.set(fieldValue, [position]);
          else list.push(position);
        }
        fields.set(key, index);
      }
      return index.get(value) ?? NO_POSITIONS;
    },
  };
};
/** Ascending, duplicate-free union of position lists (the order a whole-history scan finds them in). */
const positionsIn = (...lists: readonly (readonly number[])[]): number[] => {
  if (lists.length === 1) return [...(lists[0] as readonly number[])];
  const set = new Set<number>();
  for (const list of lists) for (const position of list) set.add(position);
  return [...set].sort((a, b) => a - b);
};

const linksThroughAssignment = (state: ReplayState, index: EventIndex, obligationId: string, targetAgentId: string): boolean =>
  index.where("OBLIGATION_PERFORMANCE_ASSIGNED", "obligationId", obligationId)
    .some((position) => (state.events[position] as CanonicalEvent).data.toAgentId === targetAgentId);

/** `obligationLinksTarget` with the assignment lookup served by `index` (null: scan the history). */
const linksTarget = (state: ReplayState, obligationId: string, targetAgentId: string, index: EventIndex | null): boolean => {
  const obligation = state.obligations.get(obligationId);
  if (obligation === undefined) return false;
  const record = obligation.record;
  if (state.intentDeclarations.get(record.sourceIntentId)?.data.actorId === targetAgentId ||
      state.tenures.get(record.creationRoleTenureId)?.agentId === targetAgentId || record.performanceAssigneeId === targetAgentId) return true;
  if (index !== null) return linksThroughAssignment(state, index, obligationId, targetAgentId);
  for (const event of state.events) {
    if (event.type === "OBLIGATION_PERFORMANCE_ASSIGNED" && event.data.obligationId === obligationId && event.data.toAgentId === targetAgentId) return true;
  }
  return false;
};

/** Relevance includes historical assignments, even after the tenure closed. */
export const obligationLinksTarget = (state: ReplayState, obligationId: string, targetAgentId: string): boolean =>
  linksTarget(state, obligationId, targetAgentId, null);

/** Review status is positional: a review at or before the last assignment never counts (spec 03 §D.6). */
export const attemptDutyReviewStatus = (state: ReplayState, dutyId: string): "UNREVIEWED" | "REVIEW_CLOSED" | "NEEDS_REVIEW" => {
  const duty = state.attemptDuties.get(dutyId), reviews = state.attemptDutyReviews.get(dutyId) ?? [];
  const latest = reviews[reviews.length - 1];
  if (duty === undefined || latest === undefined) return "UNREVIEWED";
  const latestAssignment = duty.assignments[duty.assignments.length - 1];
  if (latestAssignment !== undefined && latest.eventPosition <= (latestAssignment.eventPosition as number)) return "NEEDS_REVIEW";
  const ids = (state.outcomeObservations.get(duty.record.sourceIntentId) ?? []).map(item => item.eventId).sort(compareProtocolStrings);
  return latest.actorId === duty.currentAssigneeId && ids.length === latest.observationEventIds.length &&
    ids.every((id, index) => id === latest.observationEventIds[index]) ? "REVIEW_CLOSED" : "NEEDS_REVIEW";
};

const parentPath = (state: ReplayState, record: AuthorityRecord): AuthorityRecord[] => {
  const result: AuthorityRecord[] = [];
  let cursor: AuthorityRecord | undefined = record;
  while (cursor?.grant.kind === "PERMISSION") {
    result.push(cursor);
    cursor = cursor.grant.parentAuthorityId === undefined ? undefined : state.authorities.get(cursor.grant.parentAuthorityId);
  }
  return result;
};

/** BFS from the path over required-intersection partners (their own parent paths), deduplicated by authority id. */
const dependencies = (state: ReplayState, path: readonly AuthorityRecord[]): AuthorityRecord[] => {
  const result: AuthorityRecord[] = [], seen = new Set<string>(), queue = [...path];
  const enqueued = new Set(path.map(record => record.grant.authorityId));
  for (let index = 0; index < queue.length; index += 1) {
    const record = queue[index] as AuthorityRecord;
    if (seen.has(record.grant.authorityId)) continue;
    seen.add(record.grant.authorityId); result.push(record);
    for (const identifier of record.grant.constraints.requiredIntersectionIds) {
      const required = state.authorities.get(identifier);
      if (required?.grant.kind !== "PERMISSION") continue;
      for (const dependency of parentPath(state, required)) {
        if (enqueued.has(dependency.grant.authorityId)) continue;
        enqueued.add(dependency.grant.authorityId); queue.push(dependency);
      }
    }
  }
  return result;
};

const leastEvidence = (references: readonly Evidence[]): Evidence => {
  let least = references[0] as Evidence;
  for (const reference of references) if (compareQueryEvidence(reference, least) < 0) least = reference;
  return least;
};

const skeletonFor = (state: ReplayState, targetAgentId: string): SurvivesAnswer => {
  const agent = state.agents.get(targetAgentId);
  return {
    targetAgentId, exists: agent !== undefined, lifecycleStatus: agent === undefined ? "ABSENT" : agent.terminated ? "TERMINATED" : "ACTIVE",
    historicalIdentity: [], currentRoleTenures: [], transferredRoleTenures: [], unresolvedIntents: [], adapterOutcomes: [],
    ...(isAttemptPolicy(state) ? { outcomeObservations: [], attemptDuties: [] } : {}),
    receiptCommitments: [], obligations: [], currentPerformanceAssignments: [], invalidatedAuthorityDependencies: [],
  };
};

const walkSurvives = (state: ReplayState, targetAgentId: string, evaluationTime: number, writer: ProjectionWriter): void => {
  const agent = state.agents.get(targetAgentId);
  if (agent === undefined) return;
  const cache = createEvidenceCache(state);
  const ref = cache.event, receiptRef = cache.receipt;
  const index = createEventIndex(state);
  const at = (position: number): CanonicalEvent => state.events[position] as CanonicalEvent;
  /** The evidence of the union of position lists, in history order (what a whole-history scan with the same predicate found). */
  const cited = (...lists: readonly (readonly number[])[]): Evidence[] => positionsIn(...lists).map(ref);

  writer.evidence("historicalIdentity", cited(
    index.where("PRINCIPAL_CREATED", "principalId", agent.principalId),
    index.where("AGENT_CREATED", "agentId", targetAgentId), index.where("AGENT_TERMINATED", "agentId", targetAgentId)));

  for (const tenure of state.tenures.values()) {
    if (tenure.agentId !== targetAgentId) continue;
    const evidence = cited(
      index.where("ROLE_CREATED", "roleId", tenure.roleId),
      index.where("AGENT_APPOINTED", "roleTenureId", tenure.id), index.where("AGENT_UNAPPOINTED", "roleTenureId", tenure.id),
      index.where("ROLE_TRANSFERRED", "fromRoleTenureId", tenure.id), index.where("ROLE_TRANSFERRED", "toRoleTenureId", tenure.id));
    // Any closed tenure lands in "transferred"; the list name is historical.
    writer.row(tenure.closed ? "transferredRoleTenures" : "currentRoleTenures", tenure.id,
      { roleId: tenure.roleId, agentId: targetAgentId, roleTenureId: tenure.id, tenureNumber: tenure.tenureNumber, status: tenure.closed ? "CLOSED" : "CURRENT" }, evidence);
  }

  const includedIntentIds = new Set<string>();
  for (const [intentId, declaration] of state.intentDeclarations) {
    if (declaration.data.actorId !== targetAgentId) continue;
    const latestOutcome = state.intentOutcomeStates.get(intentId)?.latest;
    const outcome = latestOutcome?.status, consumption = state.intentConsumptions.get(intentId);
    const evidence = cited(
      index.where("TRANSACTION_INTENT_DECLARED", "intentId", intentId), index.where("TRANSACTION_INTENT_ADMITTED", "intentId", intentId),
      index.where("TRANSACTION_INTENT_CONSUMED", "intentId", intentId), index.where("TRANSACTION_OUTCOME_RECORDED", "intentId", intentId));
    if (consumption !== undefined || latestOutcome !== undefined) {
      writer.row("adapterOutcomes", intentId, {
        intentId, actorId: targetAgentId, adapterProfile: declaration.data.adapterProfile, state: outcome ?? "SUBMITTED",
        ...(consumption === undefined ? {} : { acknowledgment: consumption.acknowledgment }),
        ...(latestOutcome === undefined ? {} : { latestOutcome }),
      }, evidence);
    }
    // Terminal outcomes stay visible above without becoming unresolved intents.
    if (outcome === "CONFIRMED" || outcome === "FAILED") continue;
    const intentState = outcome ?? (consumption !== undefined ? "SUBMITTED" : state.intentAdmissions.has(intentId) ? "ADMITTED" : "DECLARED");
    writer.row("unresolvedIntents", intentId, { intentId, actorId: targetAgentId, nonce: declaration.data.nonce, state: intentState }, evidence);
    includedIntentIds.add(intentId);
  }

  // E5/E6: every recorder and digest stays visible; differing bytes are not a verdict.
  // The first duty (in insertion order) per source intent, as `[...attemptDuties.values()].find(...)` per intent was.
  let firstDutyByIntent: Map<string, NonNullable<ReturnType<ReplayState["attemptDuties"]["get"]>>> | undefined;
  for (const [intentId, observations] of state.outcomeObservations) {
    const originalActorId = state.intentDeclarations.get(intentId)?.data.actorId;
    if (firstDutyByIntent === undefined) {
      firstDutyByIntent = new Map();
      for (const duty of state.attemptDuties.values()) if (!firstDutyByIntent.has(duty.record.sourceIntentId)) firstDutyByIntent.set(duty.record.sourceIntentId, duty);
    }
    const relatedDuty = firstDutyByIntent.get(intentId);
    const linkedAssignee = relatedDuty !== undefined && (relatedDuty.record.performanceAssigneeId === targetAgentId ||
      relatedDuty.assignments.some(item => item.fromAgentId === targetAgentId || item.toAgentId === targetAgentId));
    if (originalActorId !== targetAgentId && !observations.some(item => item.actorId === targetAgentId) && !linkedAssignee) continue;
    const digestOf = (acknowledgment: Data): unknown => ((acknowledgment.result as Data | undefined)?.reportDigest as Data | undefined);
    const digests = new Set(observations.map(item => (digestOf(item.acknowledgment) as Data | undefined)?.value));
    const source = state.intentAdmissions.get(intentId);
    if (source === undefined) continue;
    for (const observation of observations) writer.row("outcomeObservations", observation.eventId, {
      observationEventId: observation.eventId, intentId, sourceAdmissionEventId: observation.sourceAdmissionEventId,
      originalActorId, recorderId: observation.actorId, recordedAt: observation.observedAt,
      reportDigest: digestOf(observation.acknowledgment),
      reportStatus: digests.size > 1 ? "DIVERGENT_REPORTS" : "REPORT_RECORDED", externalOutcome: "NOT_PROVEN",
    }, [ref(source.admissionEventPosition), ref(observation.eventPosition)]);
  }
  for (const [dutyId, duty] of state.attemptDuties) {
    const record = duty.record, source = state.intentAdmissions.get(record.sourceIntentId);
    const originalActorId = state.intentDeclarations.get(record.sourceIntentId)?.data.actorId;
    if (source === undefined || (originalActorId !== targetAgentId && record.performanceAssigneeId !== targetAgentId &&
        !duty.assignments.some(item => item.fromAgentId === targetAgentId || item.toAgentId === targetAgentId))) continue;
    const e6 = state.genesis.adapterPolicyHash === ADAPTER_POLICY_E6_HASH;
    // SPEC §13.6 (E4), `portable-query-survives.ts:158-169`: a duty with an active policy carries `currentView` in place of `status`,
    // and cites its activation and every disposition and contest.
    const currentView = inspectDutyPolicyState(state, dutyId);
    writer.row("attemptDuties", dutyId, {
      dutyId, sourceIntentId: record.sourceIntentId, sourceAdmissionEventId: record.sourceAdmissionEventId, originalActorId,
      durableRoleId: record.durableRoleId, creationActorId: duty.creationActorId, initialAssigneeId: record.performanceAssigneeId,
      currentAssigneeId: duty.currentAssigneeId, deadline: record.deadline, ...(currentView !== null ? { currentView } : { status: record.status }), externalOutcome: "NOT_PROVEN",
      ...(e6 ? { reviewStatus: attemptDutyReviewStatus(state, dutyId), reviews: state.attemptDutyReviews.get(dutyId) ?? [] } : {}),
    }, [ref(source.admissionEventPosition), ref(duty.creationEventPosition),
      ...(currentView !== null ? [ref(currentView.policy.eventPosition), ...(state.attemptDutyDispositions.get(dutyId) ?? []).map((row) => ref(row.position))] : []),
      ...duty.assignments.map(item => ref(item.eventPosition as number)),
      ...(e6 ? [
        ...(state.attemptDutyReviews.get(dutyId) ?? []).map(item => ref(item.eventPosition)),
        ...(state.outcomeObservations.get(record.sourceIntentId) ?? []).map(item => ref(item.eventPosition)),
      ] : [])]);
  }

  const includedReceiptHashes = new Set<string>();
  for (const [obligationId, obligation] of state.obligations) {
    if (obligation.status === "DISCHARGED" || obligation.status === "IMPOSSIBLE_OR_ESCALATED" || !linksTarget(state, obligationId, targetAgentId, index)) continue;
    const record = obligation.record, receipt = state.receiptCommitments.get(record.causalReceiptContentHash);
    if (receipt === undefined) continue; // replay guarantees the receipt; never throw on a malformed state
    const causal = [receiptRef(receipt), ref(obligation.creationEventPosition)];
    const assignmentPositions = index.where("OBLIGATION_PERFORMANCE_ASSIGNED", "obligationId", obligationId);
    const assignments = cited(assignmentPositions);
    const statuses = cited(index.where("OBLIGATION_STATUS_RECORDED", "obligationId", obligationId));
    const targetLinks = cited(
      index.where("TRANSACTION_INTENT_DECLARED", "intentId", record.sourceIntentId).filter((position) => at(position).data.actorId === targetAgentId),
      index.where("AGENT_APPOINTED", "roleTenureId", record.creationRoleTenureId).filter((position) => at(position).data.agentId === targetAgentId),
      index.where("ROLE_TRANSFERRED", "toRoleTenureId", record.creationRoleTenureId).filter((position) => at(position).data.toAgentId === targetAgentId));
    writer.row("obligations", obligationId, { obligationId, durableRoleId: record.durableRoleId,
      performanceAssigneeId: obligation.performanceAssigneeId, status: obligation.status, deadline: record.deadline },
      [...causal, ...assignments, ...statuses, ...targetLinks]);
    // The last assignment's rule, else the obligation's own.
    const lastAssignment = assignmentPositions.at(-1);
    const successionRuleId = lastAssignment === undefined ? record.successionRuleId : at(lastAssignment).data.successionRuleId as string;
    writer.row("currentPerformanceAssignments", obligationId, { obligationId, assigneeId: obligation.performanceAssigneeId, successionRuleId }, [...causal, ...assignments]);
    includedReceiptHashes.add(record.causalReceiptContentHash);
  }
  for (const receipt of state.receiptCommitments.values()) {
    if (includedIntentIds.has(receipt.intentId) || includedReceiptHashes.has(receipt.receiptContentHash)) writer.evidence("receiptCommitments", [receiptRef(receipt)]);
  }

  // REVOKED > EXPIRED > AGENT_TERMINATED; only agents (never principals) count as terminated parties.
  for (const [authorityId, record] of state.authorities) {
    if (record.grant.kind !== "PERMISSION") continue;
    const path = parentPath(state, record);
    if (!path.some(item => item.grant.kind === "PERMISSION" && (item.grant.grantorId === targetAgentId || item.grant.granteeId === targetAgentId))) continue;
    const graph = dependencies(state, path);
    const pathEvidence = graph.map(item => ref(item.grantEventPosition));
    const revocations = graph.flatMap(item => item.revocationEventPosition === undefined ? [] : [ref(item.revocationEventPosition)]);
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
      for (const id of [item.grant.grantorId, item.grant.granteeId]) if (state.agents.get(id)?.terminated === true) terminatedIds.add(id);
    }
    const terminations = terminatedIds.size === 0 ? [] : cited(index.ofType("AGENT_TERMINATED").filter((position) => terminatedIds.has(at(position).data.agentId as string)));
    if (terminations.length !== 0) writer.row("invalidatedAuthorityDependencies", authorityId, { authorityId, state: "AGENT_TERMINATED" }, [...pathEvidence, leastEvidence(terminations)]);
  }
};

const sortSurvives = (answer: SurvivesAnswer): void => {
  const byId = <K extends string>(key: K) => (a: Readonly<Record<K, string>>, b: Readonly<Record<K, string>>) => compareProtocolStrings(a[key], b[key]);
  (answer.outcomeObservations as OutcomeObservationProjection[] | undefined)?.sort((a, b) =>
    compareProtocolStrings(a.intentId, b.intentId) || compareProtocolStrings(a.observationEventId, b.observationEventId));
  (answer.attemptDuties as AttemptDutyProjection[] | undefined)?.sort(byId("dutyId"));
  const compareTenures = (a: RoleTenureProjection, b: RoleTenureProjection) =>
    compareProtocolStrings(a.roleId, b.roleId) || a.tenureNumber - b.tenureNumber || compareProtocolStrings(a.roleTenureId, b.roleTenureId);
  (answer.currentRoleTenures as RoleTenureProjection[]).sort(compareTenures);
  (answer.transferredRoleTenures as RoleTenureProjection[]).sort(compareTenures);
  (answer.unresolvedIntents as IntentProjection[]).sort(byId("intentId"));
  (answer.adapterOutcomes as AdapterOutcomeProjection[]).sort(byId("intentId"));
  (answer.obligations as ObligationProjection[]).sort(byId("obligationId"));
  (answer.currentPerformanceAssignments as PerformanceAssignmentProjection[]).sort(byId("obligationId"));
  (answer.invalidatedAuthorityDependencies as AuthorityDependencyProjection[]).sort(byId("authorityId"));
};

export const deriveSurvives = (state: ReplayState, targetAgentId: string, evaluationTime: number): QueryDerivation<SurvivesAnswer> => {
  const writer = createProjectionWriter(skeletonFor(state, targetAgentId));
  walkSurvives(state, targetAgentId, evaluationTime, writer);
  return writer.finish(sortSurvives);
};

/** True when the two branches would answer SURVIVES differently for the target (compared by row identity and evidence sets). */
export const survivesAnswersDiffer = (left: ReplayState, right: ReplayState, targetAgentId: string, evaluationTime: number): boolean => {
  if (canonicalEncode(skeletonFor(left, targetAgentId)) !== canonicalEncode(skeletonFor(right, targetAgentId))) return true;
  const intern = new Map<string, number>();
  const a = createComparisonPlan(intern), b = createComparisonPlan(intern);
  walkSurvives(left, targetAgentId, evaluationTime, a);
  walkSurvives(right, targetAgentId, evaluationTime, b);
  return comparisonPlansDiffer(a, b);
};

// ------------------------------------------------------------------ conflict classification (spec 03 §E)

export type QueryConflictPair = readonly [EventReference, EventReference];
export type QueryConflictSelection =
  | Readonly<{ kind: "WHY" | "RESPONSIBLE"; binding?: ConsequentialBinding }>
  | Readonly<{ kind: "SURVIVES"; targetAgentId: string; evaluationTime: number }>;
type Admission = Readonly<{ position: number; intent: TransactionIntent; proof: AuthorizationProofView }>;
type Creation = Readonly<{ position: number; record: ObligationRecord; effectHash: unknown }>;

const proofOf = (event: CanonicalEvent): AuthorizationProofView => event.data.authorizationProof as AuthorizationProofView;
const challengeOf = (event: CanonicalEvent): Data => ((event.data.administrativeAuthorization as Data | undefined)?.challenge as Data | undefined) ?? {};
const pairFor = (left: ReplayState, x: number, right: ReplayState, y: number): QueryConflictPair => {
  const a = eventReference(left, x), b = eventReference(right, y);
  return Object.freeze(compareQueryEvidence(a, b) <= 0 ? [a, b] : [b, a]);
};
const leastPair = (previous: QueryConflictPair | undefined, candidate: QueryConflictPair): QueryConflictPair =>
  previous === undefined || compareQueryEvidence(candidate[0], previous[0]) < 0 ||
    (compareQueryEvidence(candidate[0], previous[0]) === 0 && compareQueryEvidence(candidate[1], previous[1]) < 0) ? candidate : previous;

/** Domains are opaque records; only a legacy `verifyingContract` compares case-insensitively. */
export const domainEqual = (a: Data, b: Data): boolean => {
  if (typeof a.verifyingContract === "string" && typeof b.verifyingContract === "string") {
    return canonicalEncode({ ...a, verifyingContract: a.verifyingContract.toLowerCase() }) === canonicalEncode({ ...b, verifyingContract: b.verifyingContract.toLowerCase() });
  }
  return canonicalEncode(a) === canonicalEncode(b);
};

const suffixAdmissions = (state: ReplayState, prefixLength: number): Map<string, Admission> => {
  const result = new Map<string, Admission>();
  for (const admission of state.intentAdmissions.values()) {
    if (admission.admissionEventPosition < prefixLength) continue;
    const intent = state.intentDeclarations.get(admission.intentId)?.data;
    if (intent !== undefined) result.set(intent.intentId, { position: admission.admissionEventPosition, intent, proof: proofOf(state.events[admission.admissionEventPosition] as CanonicalEvent) });
  }
  return result;
};
const suffixCreations = (state: ReplayState, prefixLength: number): Creation[] => {
  const result: Creation[] = [];
  for (const obligation of state.obligations.values()) {
    if (obligation.creationEventPosition < prefixLength) continue;
    result.push({ position: obligation.creationEventPosition, record: obligation.record,
      effectHash: challengeOf(state.events[obligation.creationEventPosition] as CanonicalEvent).transitionEffectHash });
  }
  return result;
};

/** Prefix membership uses immutable creation facts and only assignments already accepted before the fork. */
const obligationLinksTargetAtPrefix = (state: ReplayState, obligationId: string, target: string, prefixLength: number): boolean => {
  const obligation = state.obligations.get(obligationId);
  if (obligation === undefined || obligation.creationEventPosition >= prefixLength) return false;
  const record = obligation.record;
  if (state.intentDeclarations.get(record.sourceIntentId)?.data.actorId === target ||
      state.tenures.get(record.creationRoleTenureId)?.agentId === target || record.performanceAssigneeId === target) return true;
  for (let position = obligation.creationEventPosition + 1; position < prefixLength; position += 1) {
    const event = state.events[position] as CanonicalEvent;
    if (event.type === "OBLIGATION_PERFORMANCE_ASSIGNED" && event.data.obligationId === obligationId && event.data.toAgentId === target) return true;
  }
  return false;
};

/** The complete causal identity chain of a pre-fork obligation must match the intent. */
const obligationLinksIntentAtPrefix = (state: ReplayState, obligationId: string, intentId: string, prefixLength: number): boolean => {
  const obligation = state.obligations.get(obligationId);
  if (obligation === undefined || obligation.creationEventPosition >= prefixLength || obligation.record.sourceIntentId !== intentId) return false;
  const record = obligation.record, intent = state.intentDeclarations.get(intentId)?.data;
  const admission = state.intentAdmissions.get(intentId), receipt = state.receiptCommitments.get(record.causalReceiptContentHash);
  const consumption = state.intentConsumptions.get(intentId), tenure = state.tenures.get(record.creationRoleTenureId);
  if (intent === undefined || admission === undefined || receipt === undefined || consumption === undefined || tenure === undefined ||
      !(admission.admissionEventPosition < consumption.eventPosition && consumption.eventPosition < receipt.eventPosition &&
        receipt.eventPosition < obligation.creationEventPosition)) return false;
  const proof = proofOf(state.events[admission.admissionEventPosition] as CanonicalEvent);
  return receipt.intentId === intentId && proof.intentId === intentId && receipt.authorizationProofHash === hashCanonical(proof, state.hashAlgorithm) &&
    receipt.issuerAgentId === intent.actorId && receipt.issuerAgentId === proof.request.actorId &&
    receipt.runtimeSessionId === proof.runtimeSessionId && receipt.controlEpoch === proof.controlEpoch &&
    receipt.roleId === proof.roleId && receipt.roleTenureId === proof.roleTenureId &&
    record.durableRoleId === intent.roleId && record.durableRoleId === receipt.roleId &&
    record.creationRoleTenureId === intent.roleTenureId && record.creationRoleTenureId === receipt.roleTenureId &&
    record.performanceAssigneeId === intent.actorId && tenure.agentId === intent.actorId &&
    tenure.roleId === record.durableRoleId && record.trigger === consumption.eventId;
};

/**
 * The six closed fork classes, in order; the first class yielding a pair wins.
 * Indexes and a running least pair avoid materialising every candidate pair.
 */
export const findQueryConflict = (left: ReplayState, right: ReplayState, query: QueryConflictSelection): QueryConflictPair | undefined => {
  if (!domainEqual(left.genesis.domain, right.genesis.domain) || left.genesis.canonicalLineageId !== right.genesis.canonicalLineageId) return undefined;
  let prefixLength = 0;
  while (prefixLength < left.events.length && prefixLength < right.events.length &&
      canonicalEncode(left.events[prefixLength]) === canonicalEncode(right.events[prefixLength])) prefixLength += 1;
  if (prefixLength === 0 || prefixLength === left.events.length || prefixLength === right.events.length) return undefined;
  if (query.kind !== "SURVIVES" && query.binding?.intentId === undefined) return undefined;
  if (query.kind === "SURVIVES") {
    if (!Number.isSafeInteger(query.evaluationTime) || query.evaluationTime < left.head.canonicalTime || query.evaluationTime < right.head.canonicalTime) {
      throw new TypeError("Conflict projection requires causal time at both heads.");
    }
    if (!survivesAnswersDiffer(left, right, query.targetAgentId, query.evaluationTime)) return undefined;
  }
  const intentId = query.kind === "SURVIVES" ? undefined : query.binding?.intentId;
  const admissionRelevant = (x: Admission, y: Admission): boolean => query.kind === "SURVIVES"
    ? x.intent.actorId === query.targetAgentId || y.intent.actorId === query.targetAgentId
    : x.intent.intentId === intentId || y.intent.intentId === intentId;
  const creationRelevant = (x: Creation, y: Creation): boolean => query.kind === "SURVIVES"
    ? obligationLinksTarget(left, x.record.obligationId, query.targetAgentId) || obligationLinksTarget(right, y.record.obligationId, query.targetAgentId)
    : x.record.sourceIntentId === intentId || y.record.sourceIntentId === intentId;
  const laterRelevant = (x: CanonicalEvent, y: CanonicalEvent): boolean => {
    const obligationId = x.data.obligationId as string;
    return query.kind === "SURVIVES"
      ? obligationLinksTargetAtPrefix(left, obligationId, query.targetAgentId, prefixLength) ||
        (x.type === "OBLIGATION_PERFORMANCE_ASSIGNED" && (x.data.toAgentId === query.targetAgentId || y.data.toAgentId === query.targetAgentId))
      : obligationLinksIntentAtPrefix(left, obligationId, intentId as string, prefixLength);
  };

  const leftAdmissions = suffixAdmissions(left, prefixLength), rightAdmissions = suffixAdmissions(right, prefixLength);
  let selected: QueryConflictPair | undefined;
  // 1. SAME_INTENT_ADMISSION: complete declarations and proofs, not just ids.
  for (const x of leftAdmissions.values()) {
    const y = rightAdmissions.get(x.intent.intentId);
    if (y !== undefined && admissionRelevant(x, y) && (canonicalEncode(x.intent) !== canonicalEncode(y.intent) || canonicalEncode(x.proof) !== canonicalEncode(y.proof))) {
      selected = leastPair(selected, pairFor(left, x.position, right, y.position));
    }
  }
  if (selected !== undefined) return selected;
  // 2. SAME_NONCE_ADMISSION: one reservation per actor/nonce per branch.
  const rightNonces = new Map<string, Admission>();
  for (const y of rightAdmissions.values()) rightNonces.set(canonicalEncode([y.intent.actorId, y.intent.nonce]), y);
  for (const x of leftAdmissions.values()) {
    const y = rightNonces.get(canonicalEncode([x.intent.actorId, x.intent.nonce]));
    if (y !== undefined && x.intent.intentId !== y.intent.intentId && admissionRelevant(x, y)) selected = leastPair(selected, pairFor(left, x.position, right, y.position));
  }
  if (selected !== undefined) return selected;

  const firstLeft = left.events[prefixLength] as CanonicalEvent, firstRight = right.events[prefixLength] as CanonicalEvent;
  const commonHash = left.eventHistoryHashes[prefixLength - 1];
  const boundToCommon = (proof: AuthorizationProofView): boolean =>
    proof.historyHead.position === prefixLength - 1 && proof.historyHead.hash === commonHash &&
    proof.historyHead.canonicalTime === (left.events[prefixLength - 1] as CanonicalEvent).timestamp;
  // 3. CAPACITY_RESERVATION: both first post-fork admissions bound to the common head exhaust a shared capped authority.
  if (firstLeft.type === "TRANSACTION_INTENT_ADMITTED" && firstRight.type === "TRANSACTION_INTENT_ADMITTED") {
    const x = leftAdmissions.get(firstLeft.data.intentId as string), y = rightAdmissions.get(firstRight.data.intentId as string);
    if (x !== undefined && y !== undefined && x.intent.intentId !== y.intent.intentId &&
        !(x.intent.actorId === y.intent.actorId && x.intent.nonce === y.intent.nonce) && boundToCommon(x.proof) && boundToCommon(y.proof) && admissionRelevant(x, y)) {
      const rightIds = new Set(y.proof.controllingAuthorityIds);
      const usage = new Map(x.proof.usageSnapshot.map(value => [value.authorityId, value]));
      const shared = x.proof.controllingAuthorityIds.filter(id => rightIds.has(id)).sort(compareProtocolStrings);
      for (const id of shared) {
        const authority = left.authorities.get(id), prior = usage.get(id);
        if (authority === undefined || authority.grant.kind !== "PERMISSION" || authority.grantEventPosition >= prefixLength || prior === undefined) continue;
        const constraints = authority.grant.constraints;
        if ((constraints.maxTransactions !== undefined && prior.admittedTransactionCount + 2 > constraints.maxTransactions) ||
            (constraints.quantitative && constraints.maxCumulativeAmount !== undefined && x.intent.amount !== undefined && y.intent.amount !== undefined &&
              prior.admittedCumulativeAmount + x.intent.amount + y.intent.amount > constraints.maxCumulativeAmount)) {
          return pairFor(left, prefixLength, right, prefixLength);
        }
      }
    }
  }
  // 4. ADMINISTRATIVE_CREATION spans both entire divergent suffixes.
  const rightSources = new Map<string, Creation>(), rightObligations = new Map<string, Creation>();
  for (const y of suffixCreations(right, prefixLength)) { rightSources.set(y.record.sourceIntentId, y); rightObligations.set(y.record.obligationId, y); }
  for (const x of suffixCreations(left, prefixLength)) {
    for (const y of [rightSources.get(x.record.sourceIntentId), rightObligations.get(x.record.obligationId)]) {
      if (y !== undefined && x.effectHash !== y.effectHash && creationRelevant(x, y)) selected = leastPair(selected, pairFor(left, x.position, right, y.position));
    }
  }
  if (selected !== undefined) return selected;
  // 5/6. STATUS / ASSIGNMENT at the exact first post-fork position.
  if ((firstLeft.type === "OBLIGATION_STATUS_RECORDED" && firstRight.type === "OBLIGATION_STATUS_RECORDED" && firstLeft.data.fromStatus === firstRight.data.fromStatus) ||
      (firstLeft.type === "OBLIGATION_PERFORMANCE_ASSIGNED" && firstRight.type === "OBLIGATION_PERFORMANCE_ASSIGNED" && firstLeft.data.fromAgentId === firstRight.data.fromAgentId)) {
    const x = challengeOf(firstLeft), y = challengeOf(firstRight);
    if (firstLeft.data.obligationId === firstRight.data.obligationId &&
        x.eventHistoryPosition === prefixLength - 1 && y.eventHistoryPosition === prefixLength - 1 &&
        x.eventHistoryHash === commonHash && y.eventHistoryHash === commonHash &&
        x.transitionEffectHash !== y.transitionEffectHash && laterRelevant(firstLeft, firstRight)) {
      return pairFor(left, prefixLength, right, prefixLength);
    }
  }
  return undefined;
};
