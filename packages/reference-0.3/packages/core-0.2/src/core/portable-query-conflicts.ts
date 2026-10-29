/** Internal Contract 9.2 classifier. Only independently accepted local replay states enter here. */
import { canonicalEncode, compareProtocolStrings, hashCanonical } from "./canonical.ts";
import type { AcceptedCanonicalEventShape } from "./event-schema.ts";
import type { PortableAdministrativeAuthorization, PortableObligationRecord } from "./portable-administration-codec.ts";
import type { PortableAuthorizationProof, PortableConsequentialBinding } from "./portable-authority-engine.ts";
import { isPortableReplayState, type PortableReplayState, type PortableReplayEvidenceReference,
  type PortableTransactionIntent } from "./portable-replay.ts";
import { compareQueryEvidence, queryEventReference } from "./portable-query-codec.ts";
import { portableObligationLinksTarget, portableSurvivesAnswersDiffer } from "./portable-query-survives.ts";

type Event = AcceptedCanonicalEventShape;
type EventReference = Extract<PortableReplayEvidenceReference, { kind: "EVENT" }>;
export type PortableQueryConflictPair = readonly [EventReference, EventReference];
export type PortableQueryConflictSelection =
  | Readonly<{ kind: "WHY" | "RESPONSIBLE"; binding?: PortableConsequentialBinding }>
  | Readonly<{ kind: "SURVIVES"; targetAgentId: string; evaluationTime: number }>;
type Admission = Readonly<{ position: number; intent: PortableTransactionIntent; proof: PortableAuthorizationProof }>;
type Creation = Readonly<{ position: number; record: PortableObligationRecord; effectHash: string }>;

const proofOf = (event: Event): PortableAuthorizationProof => event.data.authorizationProof as PortableAuthorizationProof;
const wrapperOf = (event: Event): PortableAdministrativeAuthorization => event.data.administrativeAuthorization as PortableAdministrativeAuthorization;
const pairFor = (left: PortableReplayState, x: number, right: PortableReplayState, y: number): PortableQueryConflictPair => {
  const a = queryEventReference(left, x), b = queryEventReference(right, y);
  return Object.freeze(compareQueryEvidence(a, b) <= 0 ? [a, b] : [b, a]);
};
const leastPair = (previous: PortableQueryConflictPair | undefined, candidate: PortableQueryConflictPair): PortableQueryConflictPair =>
  previous === undefined || compareQueryEvidence(candidate[0], previous[0]) < 0 ||
    (compareQueryEvidence(candidate[0], previous[0]) === 0 && compareQueryEvidence(candidate[1], previous[1]) < 0)
    ? candidate : previous;

const suffixAdmissions = (state: PortableReplayState, prefixLength: number): Map<string, Admission> => {
  const result = new Map<string, Admission>();
  for (const admission of state.intentAdmissions.values()) {
    if (admission.admissionEventPosition < prefixLength) continue;
    const intent = state.intentDeclarations.get(admission.intentId)!.data;
    result.set(intent.intentId, { position: admission.admissionEventPosition, intent,
      proof: proofOf(state.events[admission.admissionEventPosition]!) });
  }
  return result;
};
const suffixCreations = (state: PortableReplayState, prefixLength: number): Creation[] => {
  const result: Creation[] = [];
  for (const obligation of state.obligations.values()) {
    if (obligation.creationEventPosition < prefixLength) continue;
    result.push({ position: obligation.creationEventPosition, record: obligation.record,
      effectHash: wrapperOf(state.events[obligation.creationEventPosition]!).challenge.transitionEffectHash });
  }
  return result;
};

/** Prefix membership uses immutable creation facts and only assignments already accepted at C. */
const obligationLinksTargetAtPrefix = (state: PortableReplayState, obligationId: string, target: string, prefixLength: number): boolean => {
  const obligation = state.obligations.get(obligationId);
  if (obligation === undefined || obligation.creationEventPosition >= prefixLength) return false;
  const record = obligation.record;
  if (state.intentDeclarations.get(record.sourceIntentId)?.data.actorId === target ||
      state.tenures.get(record.creationRoleTenureId)?.agentId === target || record.performanceAssigneeId === target) return true;
  for (let position = obligation.creationEventPosition + 1; position < prefixLength; position += 1) {
    const event = state.events[position]!;
    if (event.type === "OBLIGATION_PERFORMANCE_ASSIGNED" && event.data.obligationId === obligationId &&
        event.data.toAgentId === target) return true;
  }
  return false;
};

/** Recheck the exact causal identity chain, without treating a suffix-created obligation as present at C. */
const obligationLinksIntentAtPrefix = (state: PortableReplayState, obligationId: string, intentId: string, prefixLength: number): boolean => {
  const obligation = state.obligations.get(obligationId);
  if (obligation === undefined || obligation.creationEventPosition >= prefixLength || obligation.record.sourceIntentId !== intentId) return false;
  const record = obligation.record, intent = state.intentDeclarations.get(intentId)?.data;
  const admission = state.intentAdmissions.get(intentId), receipt = state.receiptCommitments.get(record.causalReceiptContentHash);
  const consumption = state.intentConsumptions.get(intentId), tenure = state.tenures.get(record.creationRoleTenureId);
  if (intent === undefined || admission === undefined || receipt === undefined || consumption === undefined || tenure === undefined ||
      !(admission.admissionEventPosition < consumption.eventPosition && consumption.eventPosition < receipt.eventPosition &&
        receipt.eventPosition < obligation.creationEventPosition)) return false;
  const proof = proofOf(state.events[admission.admissionEventPosition]!);
  return receipt.intentId === intentId && proof.intentId === intentId && receipt.authorizationProofHash === hashCanonical(proof) &&
    receipt.issuerAgentId === intent.actorId && receipt.issuerAgentId === proof.request.actorId &&
    receipt.runtimeSessionId === proof.runtimeSessionId && receipt.controlEpoch === proof.controlEpoch &&
    receipt.roleId === proof.roleId && receipt.roleTenureId === proof.roleTenureId &&
    record.durableRoleId === intent.roleId && record.durableRoleId === receipt.roleId &&
    record.creationRoleTenureId === intent.roleTenureId && record.creationRoleTenureId === receipt.roleTenureId &&
    record.performanceAssigneeId === intent.actorId && tenure.agentId === intent.actorId &&
    tenure.roleId === record.durableRoleId && record.trigger === consumption.eventId;
};

/**
 * Select only the six closed authenticated fork classes. Replay already verified
 * each complete proof and signature at its own exact pre-event head. Indexes and
 * a running least pair avoid materializing a quadratic list of possible pairs.
 * The coordinator owns earlier time/disclosure failures and final output limits.
 */
export const findPortableQueryConflict = (
  evaluationState: PortableReplayState,
  observedState: PortableReplayState,
  query: PortableQueryConflictSelection,
): PortableQueryConflictPair | undefined => {
  if (!isPortableReplayState(evaluationState) || !isPortableReplayState(observedState)) {
    throw new TypeError("Conflict classification requires authoritative replay states.");
  }
  const left = evaluationState, right = observedState, a = left.genesis.domain, b = right.genesis.domain;
  if (a.protocol !== b.protocol || a.version !== b.version || a.deploymentId !== b.deploymentId || a.chainId !== b.chainId ||
      a.verifyingContract.toLowerCase() !== b.verifyingContract.toLowerCase() ||
      left.genesis.canonicalLineageId !== right.genesis.canonicalLineageId) return undefined;
  let prefixLength = 0;
  while (prefixLength < left.events.length && prefixLength < right.events.length &&
      canonicalEncode(left.events[prefixLength]) === canonicalEncode(right.events[prefixLength])) prefixLength += 1;
  if (prefixLength === 0 || prefixLength === left.events.length || prefixLength === right.events.length) return undefined;
  if (query.kind !== "SURVIVES" && query.binding?.intentId === undefined) return undefined;
  if (query.kind === "SURVIVES") {
    if (!Number.isSafeInteger(query.evaluationTime) || query.evaluationTime < left.head.canonicalTime ||
        query.evaluationTime < right.head.canonicalTime) throw new TypeError("Conflict projection requires causal time at both heads.");
    if (!portableSurvivesAnswersDiffer(left, right, query.targetAgentId, query.evaluationTime)) return undefined;
  }
  const admissionRelevant = (x: Admission, y: Admission): boolean => query.kind === "SURVIVES"
    ? x.intent.actorId === query.targetAgentId || y.intent.actorId === query.targetAgentId
    : x.intent.intentId === query.binding!.intentId || y.intent.intentId === query.binding!.intentId;
  const creationRelevant = (x: Creation, y: Creation): boolean => query.kind === "SURVIVES"
    ? portableObligationLinksTarget(left, x.record.obligationId, query.targetAgentId) ||
      portableObligationLinksTarget(right, y.record.obligationId, query.targetAgentId)
    : x.record.sourceIntentId === query.binding!.intentId || y.record.sourceIntentId === query.binding!.intentId;
  const laterRelevant = (x: Event, y: Event): boolean => {
    const obligationId = x.data.obligationId as string;
    return query.kind === "SURVIVES"
      ? obligationLinksTargetAtPrefix(left, obligationId, query.targetAgentId, prefixLength) ||
        (x.type === "OBLIGATION_PERFORMANCE_ASSIGNED" &&
          (x.data.toAgentId === query.targetAgentId || y.data.toAgentId === query.targetAgentId))
      : obligationLinksIntentAtPrefix(left, obligationId, query.binding!.intentId!, prefixLength);
  };

  const leftAdmissions = suffixAdmissions(left, prefixLength), rightAdmissions = suffixAdmissions(right, prefixLength);
  let selected: PortableQueryConflictPair | undefined;
  // 1. SAME_INTENT_ADMISSION: complete declarations and proofs, not just IDs or challenges.
  for (const x of leftAdmissions.values()) {
    const y = rightAdmissions.get(x.intent.intentId);
    if (y !== undefined && admissionRelevant(x, y) &&
        (canonicalEncode(x.intent) !== canonicalEncode(y.intent) || canonicalEncode(x.proof) !== canonicalEncode(y.proof))) {
      selected = leastPair(selected, pairFor(left, x.position, right, y.position));
    }
  }
  if (selected !== undefined) return selected;
  // 2. SAME_NONCE_ADMISSION: replay permits only one reservation per actor/nonce per branch.
  const rightNonces = new Map<string, Admission>();
  for (const y of rightAdmissions.values()) rightNonces.set(canonicalEncode([y.intent.actorId, y.intent.nonce]), y);
  for (const x of leftAdmissions.values()) {
    const y = rightNonces.get(canonicalEncode([x.intent.actorId, x.intent.nonce]));
    if (y !== undefined && x.intent.intentId !== y.intent.intentId && admissionRelevant(x, y)) {
      selected = leastPair(selected, pairFor(left, x.position, right, y.position));
    }
  }
  if (selected !== undefined) return selected;

  const firstLeft = left.events[prefixLength]!, firstRight = right.events[prefixLength]!;
  const commonHash = left.eventHistoryHashes[prefixLength - 1]!;
  const boundToCommon = (proof: PortableAuthorizationProof): boolean =>
    proof.historyHead.position === prefixLength - 1 && proof.historyHead.hash === commonHash &&
    proof.historyHead.canonicalTime === left.events[prefixLength - 1]!.timestamp;
  // 3. CAPACITY_RESERVATION. Replayed first-admission proofs contain the exact
  // replay-derived usage snapshot at C, before either branch reserves capacity.
  if (firstLeft.type === "TRANSACTION_INTENT_ADMITTED" && firstRight.type === "TRANSACTION_INTENT_ADMITTED") {
    const x = leftAdmissions.get(firstLeft.data.intentId as string)!, y = rightAdmissions.get(firstRight.data.intentId as string)!;
    if (x.intent.intentId !== y.intent.intentId &&
        !(x.intent.actorId === y.intent.actorId && x.intent.nonce === y.intent.nonce) &&
        boundToCommon(x.proof) && boundToCommon(y.proof) && admissionRelevant(x, y)) {
      const rightIds = new Set(y.proof.controllingAuthorityIds);
      const usage = new Map(x.proof.usageSnapshot.map(value => [value.authorityId, value]));
      const shared = x.proof.controllingAuthorityIds.filter(id => rightIds.has(id)).sort(compareProtocolStrings);
      for (const id of shared) {
        const authority = left.authorities.get(id)!, prior = usage.get(id);
        if (authority.grant.kind !== "PERMISSION" || authority.grantEventPosition >= prefixLength || prior === undefined) continue;
        const constraints = authority.grant.constraints;
        if ((constraints.maxTransactions !== undefined && prior.admittedTransactionCount + 2 > constraints.maxTransactions) ||
            (constraints.quantitative && constraints.maxCumulativeAmount !== undefined && x.intent.amount !== undefined &&
              y.intent.amount !== undefined && prior.admittedCumulativeAmount + x.intent.amount + y.intent.amount > constraints.maxCumulativeAmount)) {
          return pairFor(left, prefixLength, right, prefixLength);
        }
      }
    }
  }

  // 4. ADMINISTRATIVE_CREATION spans both entire divergent suffixes.
  const rightCreations = suffixCreations(right, prefixLength), rightSources = new Map<string, Creation>(), rightObligations = new Map<string, Creation>();
  for (const y of rightCreations) {
    rightSources.set(y.record.sourceIntentId, y);
    rightObligations.set(y.record.obligationId, y);
  }
  for (const x of suffixCreations(left, prefixLength)) {
    for (const y of [rightSources.get(x.record.sourceIntentId), rightObligations.get(x.record.obligationId)]) {
      if (y !== undefined && x.effectHash !== y.effectHash && creationRelevant(x, y)) {
        selected = leastPair(selected, pairFor(left, x.position, right, y.position));
      }
    }
  }
  if (selected !== undefined) return selected;
  // 5 and 6 require matching families and the exact first post-C position.
  if ((firstLeft.type === "OBLIGATION_STATUS_RECORDED" && firstRight.type === "OBLIGATION_STATUS_RECORDED" &&
        firstLeft.data.fromStatus === firstRight.data.fromStatus) ||
      (firstLeft.type === "OBLIGATION_PERFORMANCE_ASSIGNED" && firstRight.type === "OBLIGATION_PERFORMANCE_ASSIGNED" &&
        firstLeft.data.fromAgentId === firstRight.data.fromAgentId)) {
    const x = wrapperOf(firstLeft).challenge, y = wrapperOf(firstRight).challenge;
    if (firstLeft.data.obligationId === firstRight.data.obligationId &&
        x.eventHistoryPosition === prefixLength - 1 && y.eventHistoryPosition === prefixLength - 1 &&
        x.eventHistoryHash === commonHash && y.eventHistoryHash === commonHash &&
        x.transitionEffectHash !== y.transitionEffectHash && laterRelevant(firstLeft, firstRight)) {
      return pairFor(left, prefixLength, right, prefixLength);
    }
  }
  return undefined;
};
