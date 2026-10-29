/** Internal Section 9 projection vocabulary; public query dispatch is staged separately. */
import type { ContentHash } from "./canonical.ts";
import { canonicalEncode, compareProtocolStrings, immutableProtocolValue } from "./canonical.ts";
import type { PortableActionRequest, PortableConsequentialBinding, PortableAuthorizationResult } from "./portable-authority-engine.ts";
import type { AcceptedCanonicalEventShape } from "./event-schema.ts";
import type { PortableAuthorizationDomain, PortableHistoryHead } from "./portable-replay.ts";
import type { PortableObligationStatus } from "./portable-administration-codec.ts";
import type { PortableAdapterAcknowledgment, PortableAdapterProfile } from "./portable-adapter-engine.ts";
import type {
  PortableReplayState, PortableReplayEvidenceReference, PortableReceiptCommitmentRecord,
  PortableIntentOutcomeRecord,
} from "./portable-replay.ts";

export const PORTABLE_QUERY_VERSION = "continuity-query-envelope/0.2" as const;
export const PORTABLE_QUERY_EXTERNAL_ASSUMPTIONS = Object.freeze({
  trust: "LOCAL_REPLAY_UNDER_DECLARED_ROOTS_NOT_INDEPENDENTLY_AUTHENTICATED",
  identity: "PROTOCOL_IDENTIFIERS_NOT_REAL_WORLD_IDENTITY",
  observation: "SUPPLIED_HISTORY_MAY_NOT_BE_LATEST_PUBLIC_HISTORY",
  availability: "REPLAY_REQUIRES_EVENTS_AND_INTERPRETATION_RULES",
} as const);

export type PortableResponsibilityKind =
  | "ACTOR" | "RUNTIME_SESSION" | "ROLE" | "DECLARED_PRINCIPAL"
  | "MANDATOR" | "AUTHORITY_SOURCE" | "CONTROLLER" | "DURABLE_OBLIGOR"
  | "PERFORMANCE_ASSIGNEE" | "BENEFICIARY" | "COUNTERPARTY";
export const PORTABLE_RESPONSIBILITY_KINDS: readonly PortableResponsibilityKind[] = Object.freeze([
  "ACTOR", "RUNTIME_SESSION", "ROLE", "DECLARED_PRINCIPAL", "MANDATOR", "AUTHORITY_SOURCE",
  "CONTROLLER", "DURABLE_OBLIGOR", "PERFORMANCE_ASSIGNEE", "BENEFICIARY", "COUNTERPARTY",
]);
export type PortableResponsibilityAttribution = Readonly<{
  kind: PortableResponsibilityKind;
  subjectId: string;
  temporalBasis: "ACTION_PREFIX" | "LATER_CAUSAL_STATE";
  evidence: readonly PortableReplayEvidenceReference[];
}>;
export type PortableResponsibleAnswer = Readonly<{
  authorizationDecision: "ALLOW" | "DENY";
  attributions: readonly PortableResponsibilityAttribution[];
}>;
export type PortableRoleTenureProjection = Readonly<{
  roleId: string; agentId: string; roleTenureId: string; tenureNumber: number;
  status: "CURRENT" | "CLOSED"; evidence: readonly PortableReplayEvidenceReference[];
}>;
export type PortableIntentProjection = Readonly<{
  intentId: string; actorId: string; nonce: string;
  state: "DECLARED" | "ADMITTED" | "SUBMITTED" | "OUTCOME_UNKNOWN" | "DISPUTED";
  evidence: readonly PortableReplayEvidenceReference[];
}>;
/** Current retained adapter facts; neither a duty nor fresh submission permission. */
export type PortableAdapterOutcomeProjection = Readonly<{
  intentId: string; actorId: string; adapterProfile: PortableAdapterProfile;
  state: "SUBMITTED" | PortableIntentOutcomeRecord["status"];
  acknowledgment?: PortableAdapterAcknowledgment;
  latestOutcome?: PortableIntentOutcomeRecord;
  evidence: readonly PortableReplayEvidenceReference[];
}>;
export type PortableObligationProjection = Readonly<{
  obligationId: string; durableRoleId: string; performanceAssigneeId: string;
  status: PortableObligationStatus; deadline: number; evidence: readonly PortableReplayEvidenceReference[];
}>;
export type PortablePerformanceAssignmentProjection = Readonly<{
  obligationId: string; assigneeId: string; successionRuleId: string;
  evidence: readonly PortableReplayEvidenceReference[];
}>;
export type PortableAuthorityDependencyProjection = Readonly<{
  authorityId: string; state: "REVOKED" | "EXPIRED" | "AGENT_TERMINATED";
  evidence: readonly PortableReplayEvidenceReference[];
}>;
export type PortableOutcomeObservationProjection = Readonly<{
  observationEventId: string; intentId: string; sourceAdmissionEventId: string;
  originalActorId: string; recorderId: string; recordedAt: number;
  reportDigest: Readonly<{algorithm: "sha256"; value: ContentHash}>;
  reportStatus: "REPORT_RECORDED" | "DIVERGENT_REPORTS";
  externalOutcome: "NOT_PROVEN"; evidence: readonly PortableReplayEvidenceReference[];
}>;
export type PortableAttemptDutyReviewProjection = Readonly<{
  dutyId: string; actorId: string; observationEventIds: readonly string[]; summaryDigest: ContentHash;
  eventId: string; eventPosition: number; reviewedAt: number;
}>;
export type PortableAttemptDutyProjection = Readonly<{
  dutyId: string; sourceIntentId: string; sourceAdmissionEventId: string;
  originalActorId: string; durableRoleId: string; creationActorId: string;
  initialAssigneeId: string; currentAssigneeId: string; deadline: number;
  status: "OPEN"; externalOutcome: "NOT_PROVEN"; evidence: readonly PortableReplayEvidenceReference[];
  reviewStatus?: "UNREVIEWED" | "REVIEW_CLOSED" | "NEEDS_REVIEW";
  reviews?: readonly PortableAttemptDutyReviewProjection[];
}>;
export type PortableSurvivesAnswer = Readonly<{
  targetAgentId: string; exists: boolean; lifecycleStatus: "ABSENT" | "ACTIVE" | "TERMINATED";
  historicalIdentity: readonly PortableReplayEvidenceReference[];
  currentRoleTenures: readonly PortableRoleTenureProjection[];
  transferredRoleTenures: readonly PortableRoleTenureProjection[];
  unresolvedIntents: readonly PortableIntentProjection[];
  adapterOutcomes: readonly PortableAdapterOutcomeProjection[];
  outcomeObservations?: readonly PortableOutcomeObservationProjection[];
  attemptDuties?: readonly PortableAttemptDutyProjection[];
  receiptCommitments: readonly PortableReplayEvidenceReference[];
  obligations: readonly PortableObligationProjection[];
  currentPerformanceAssignments: readonly PortablePerformanceAssignmentProjection[];
  invalidatedAuthorityDependencies: readonly PortableAuthorityDependencyProjection[];
}>;

const evidenceKinds = ["EVENT", "AUTHORITY", "RUNTIME_CREDENTIAL", "RECEIPT_COMMITMENT", "EXTERNAL"] as const;
const evidenceTuple = (value: PortableReplayEvidenceReference): readonly (string | number)[] => {
  switch (value.kind) {
    case "EVENT": return [value.eventId, value.eventType, value.position, value.historyHash];
    case "AUTHORITY": return [value.authorityId, value.grantEventId];
    case "RUNTIME_CREDENTIAL": return [value.keyId, value.sessionId, value.admissionEventId];
    case "RECEIPT_COMMITMENT": return [value.receiptContentHash, value.eventId, value.position];
    case "EXTERNAL": return [value.evidenceType, value.reference, value.attesterId];
  }
};

/** Section 4.3: text components use unsigned UTF-8; positions remain numeric. */
export const compareQueryEvidence = (a: PortableReplayEvidenceReference, b: PortableReplayEvidenceReference): number => {
  const rank = evidenceKinds.indexOf(a.kind) - evidenceKinds.indexOf(b.kind);
  if (rank !== 0) return rank;
  const left = evidenceTuple(a), right = evidenceTuple(b);
  for (let index = 0; index < left.length; index += 1) {
    const x = left[index]!, y = right[index]!;
    const order = typeof x === "number" && typeof y === "number"
      ? x - y : compareProtocolStrings(x as string, y as string);
    if (order !== 0) return order;
  }
  return 0;
};

/** Deduplicate only already-derived identical facts; this is not input validation. */
export const queryEvidence = (...groups: readonly (readonly PortableReplayEvidenceReference[])[]): readonly PortableReplayEvidenceReference[] => {
  const unique = new Map<string, PortableReplayEvidenceReference>();
  for (const group of groups) for (const item of group) unique.set(canonicalEncode(item), item);
  return immutableProtocolValue([...unique.values()].sort(compareQueryEvidence));
};

export const queryEventReference = (state: PortableReplayState, position: number): Extract<PortableReplayEvidenceReference, { kind: "EVENT" }> => {
  const event = state.events[position], historyHash = state.eventHistoryHashes[position];
  if (!Number.isSafeInteger(position) || position < 0 || event === undefined || historyHash === undefined) {
    throw new TypeError("Query evidence requires an accepted event position.");
  }
  return Object.freeze({ kind: "EVENT", eventId: event.id, eventType: event.type, position, historyHash });
};

export const queryReceiptReference = (receipt: PortableReceiptCommitmentRecord): Extract<PortableReplayEvidenceReference, { kind: "RECEIPT_COMMITMENT" }> =>
  Object.freeze({ kind: "RECEIPT_COMMITMENT", receiptContentHash: receipt.receiptContentHash,
    eventId: receipt.eventId, position: receipt.eventPosition });

export type PortableQueryKind = "WHY" | "RESPONSIBLE" | "SURVIVES";
export type PortableQueryFailureCode = "INVALID_INPUT" | "UNSUPPORTED_VERSION" | "STATE_NOT_AUTHORITATIVE" |
  "CAUSAL_TIME_INVALID" | "HISTORY_RELATION_UNVERIFIED" | "DISCLOSURE_INVALID" |
  "OUTPUT_LIMIT_EXCEEDED" | "EVIDENCE_UNAVAILABLE" | "EVIDENCE_DISPUTED";
export type PortableDisclosureScope = Readonly<{
  mode: "PUBLIC_MINIMAL"; includedFields: readonly string[]; withheldFields: readonly string[];
}>;
export type PortableQueryIdentity = Readonly<{
  domain: PortableAuthorizationDomain; versions: Readonly<Record<string, string>>;
  policyVersion: string; rootRecognitionPolicy: "declared-principal-root/0.2";
  recognizedRootIds: readonly string[]; canonicalLineageId: string;
  evaluationHead: PortableHistoryHead; observedHead: PortableHistoryHead;
}>;
export type PortableQueryScope = PortableQueryIdentity & Readonly<{
  headRelationship: "SAME_HEAD" | "STRICT_EXTENSION" | "UNVERIFIED";
  freshness: "CURRENT" | "AT_EVALUATION" | "UNVERIFIED";
  finality: "LOCAL_ONLY"; disclosure: PortableDisclosureScope;
  unavailableEvidence: readonly PortableReplayEvidenceReference[];
  withheldEvidence: readonly PortableReplayEvidenceReference[];
  externalAssumptions: typeof PORTABLE_QUERY_EXTERNAL_ASSUMPTIONS;
}>;
export type PortablePartialQueryScope = Partial<PortableQueryIdentity> & Readonly<{
  headRelationship: "UNVERIFIED"; freshness: "UNVERIFIED"; finality: "LOCAL_ONLY";
  disclosure?: PortableDisclosureScope;
  unavailableEvidence: readonly PortableReplayEvidenceReference[];
  withheldEvidence: readonly PortableReplayEvidenceReference[];
  externalAssumptions: typeof PORTABLE_QUERY_EXTERNAL_ASSUMPTIONS;
}>;
export type PortableEstablishedQueryEnvelope<K extends PortableQueryKind, T> = Readonly<{
  version: typeof PORTABLE_QUERY_VERSION; kind: K; epistemicStatus: "ESTABLISHED";
  scope: PortableQueryScope; answer: T;
}>;
export type PortableNonEstablishedQueryEnvelope<K extends PortableQueryKind> = Readonly<{
  version: typeof PORTABLE_QUERY_VERSION; kind: K;
  epistemicStatus: "INDETERMINATE" | "UNAVAILABLE" | "DISPUTED";
  scope: PortablePartialQueryScope | PortableQueryScope; code: PortableQueryFailureCode;
  evidence: readonly PortableReplayEvidenceReference[];
  externalAssumptions: typeof PORTABLE_QUERY_EXTERNAL_ASSUMPTIONS;
}>;
export type PortableWhyInput = Readonly<{
  operationVersion: typeof PORTABLE_QUERY_VERSION;
  evaluationEvents: readonly AcceptedCanonicalEventShape[];
  observedEvents: readonly AcceptedCanonicalEventShape[];
  authorizationDomain: PortableAuthorizationDomain; request: PortableActionRequest;
  evaluationTime: number; consequentialBinding?: PortableConsequentialBinding;
  disclosure: PortableDisclosureScope;
}>;
export type PortableResponsibleInput = PortableWhyInput;
export type PortableSurvivesInput = Readonly<{
  operationVersion: typeof PORTABLE_QUERY_VERSION;
  evaluationEvents?: readonly AcceptedCanonicalEventShape[];
  observedEvents: readonly AcceptedCanonicalEventShape[];
  targetAgentId: string; evaluationTime: number; disclosure: PortableDisclosureScope;
}>;
export type PortableQueryAuthorization = Extract<PortableAuthorizationResult, {decision: "ALLOW" | "DENY"}> &
  Readonly<{ scopeAssurance: "REPLAY_VERIFIED"; operationVersion: "continuity-authorization/0.2" }>;
export type PortableWhyAnswer = Readonly<{
  authorization: PortableQueryAuthorization; presentConsequentialUse: boolean;
}>;
export type PortableWhyQueryResult = PortableEstablishedQueryEnvelope<"WHY", PortableWhyAnswer> |
  PortableNonEstablishedQueryEnvelope<"WHY">;
export type PortableResponsibleQueryResult = PortableEstablishedQueryEnvelope<"RESPONSIBLE", PortableResponsibleAnswer> |
  PortableNonEstablishedQueryEnvelope<"RESPONSIBLE">;
export type PortableSurvivesQueryResult = PortableEstablishedQueryEnvelope<"SURVIVES", PortableSurvivesAnswer> |
  PortableNonEstablishedQueryEnvelope<"SURVIVES">;

/** Field vocabulary is derived from the closed answer schemas, never caller facts. */
const answerFields = new Set<string>();
const fields = (prefix: string, names: string): void => {
  for (const name of names.split(" ")) answerFields.add(prefix ? `${prefix}.${name}` : name);
};
const evidenceFields = "kind eventId eventType position historyHash authorityId grantEventId keyId sessionId admissionEventId receiptContentHash evidenceType reference attesterId";
const constraintsFields = "actions resources quantitative notBefore expiresAt maxAmount maxCumulativeAmount maxTransactions maxDelegationDepth requiredIntersectionIds";
const rootFields = "rootAuthorityId principalId principalRecognitionEventId rootGrantEventId";
const domainFields = "protocol version deploymentId chainId verifyingContract";
const grantFields = "kind authorityId grantorId granteeId rootAuthorityId parentAuthorityId independent constraints";
fields("", "authorization presentConsequentialUse authorizationDecision attributions targetAgentId exists lifecycleStatus historicalIdentity currentRoleTenures transferredRoleTenures unresolvedIntents adapterOutcomes outcomeObservations attemptDuties receiptCommitments obligations currentPerformanceAssignments invalidatedAuthorityDependencies");
fields("authorization", "operationVersion decision scopeAssurance consequential proof code failures");
fields("authorization.failures", "code subjectId rootAuthorityId terminalAuthorityId failingAuthorityId authorityPathIds evidence");
fields("authorization.failures.evidence", evidenceFields);
fields("authorization.proof", "proofVersion domain policyVersion rootRecognitionPolicy historyHead evaluationTime request recognizedRoot permissionPath intersections effectiveConstraints controllingAuthorityIds usageSnapshot authorityEvidence checkedProhibitionIds consequential runtimeSessionId credentialKeyId controlEpoch roleId roleTenureId intentId nonce");
fields("authorization.proof.domain", domainFields);
fields("authorization.proof.historyHead", "hash position canonicalTime");
fields("authorization.proof.request", "actorId action resource claimedAt amount counterpartyId termsCommitment");
fields("authorization.proof.recognizedRoot", rootFields);
fields("authorization.proof.permissionPath", grantFields);
fields("authorization.proof.permissionPath.constraints", constraintsFields);
fields("authorization.proof.intersections", "requiredAuthorityId requiredByAuthorityIds recognizedRoot path effectiveConstraints");
fields("authorization.proof.intersections.recognizedRoot", rootFields);
fields("authorization.proof.intersections.path", grantFields);
fields("authorization.proof.intersections.path.constraints", constraintsFields);
fields("authorization.proof.intersections.effectiveConstraints", constraintsFields);
fields("authorization.proof.effectiveConstraints", constraintsFields);
fields("authorization.proof.usageSnapshot", "authorityId admittedTransactionCount admittedCumulativeAmount");
fields("authorization.proof.authorityEvidence", "authorityId grantEventId grantEventPosition");
fields("attributions", "kind subjectId temporalBasis evidence");
fields("attributions.evidence", evidenceFields);
for (const path of ["historicalIdentity", "receiptCommitments"]) fields(path, evidenceFields);
for (const path of ["currentRoleTenures", "transferredRoleTenures"]) {
  fields(path, "roleId agentId roleTenureId tenureNumber status evidence"); fields(`${path}.evidence`, evidenceFields);
}
fields("unresolvedIntents", "intentId actorId nonce state evidence");
const adapterProfileFields = "profileId profileVersion descriptorHash";
fields("outcomeObservations", "observationEventId intentId sourceAdmissionEventId originalActorId recorderId recordedAt reportDigest reportStatus externalOutcome evidence");
fields("outcomeObservations.reportDigest", "algorithm value");
fields("outcomeObservations.evidence", evidenceFields);
fields("attemptDuties", "dutyId sourceIntentId sourceAdmissionEventId originalActorId durableRoleId creationActorId initialAssigneeId currentAssigneeId deadline status externalOutcome evidence reviewStatus reviews");
fields("attemptDuties.reviews", "dutyId actorId observationEventIds summaryDigest eventId eventPosition reviewedAt");
fields("attemptDuties.evidence", evidenceFields);
fields("adapterOutcomes", "intentId actorId adapterProfile state acknowledgment latestOutcome evidence");
fields("adapterOutcomes.adapterProfile", adapterProfileFields);
fields("adapterOutcomes.evidence", evidenceFields);
fields("adapterOutcomes.latestOutcome", "intentId eventId eventPosition head status attesterId evidenceReference noEffect");
fields("adapterOutcomes.latestOutcome.head", "hash position canonicalTime");
fields("adapterOutcomes.latestOutcome.evidenceReference", evidenceFields);
for (const path of ["adapterOutcomes.acknowledgment", "adapterOutcomes.latestOutcome.noEffect"]) {
  fields(path, "schemaVersion kind adapterProfile domain intentId admissionHead idempotencyKey submissionFingerprint result");
  fields(`${path}.adapterProfile`, adapterProfileFields);
  fields(`${path}.domain`, domainFields);
  fields(`${path}.admissionHead`, "hash position canonicalTime");
}
fields("adapterOutcomes.acknowledgment.result", "kind submissionReference manifestDigest transitionDigest publicationManifestDigest reportDigest");
fields("adapterOutcomes.acknowledgment.result.reportDigest", "algorithm value");
fields("adapterOutcomes.acknowledgment.result.manifestDigest", "algorithm value");
fields("adapterOutcomes.acknowledgment.result.publicationManifestDigest", "algorithm value");
fields("adapterOutcomes.acknowledgment.result.transitionDigest", "algorithm value");
fields("adapterOutcomes.latestOutcome.noEffect.result", "kind reference");
fields("obligations", "obligationId durableRoleId performanceAssigneeId status deadline evidence");
fields("currentPerformanceAssignments", "obligationId assigneeId successionRuleId evidence");
fields("invalidatedAuthorityDependencies", "authorityId state evidence");
for (const path of ["unresolvedIntents", "obligations", "currentPerformanceAssignments", "invalidatedAuthorityDependencies"]) {
  fields(`${path}.evidence`, evidenceFields);
}
export const PORTABLE_QUERY_ANSWER_FIELD_PATHS: readonly string[] = Object.freeze([...answerFields].sort(compareProtocolStrings));
/** A complete per-kind default within the generic disclosure-list bound. */
export const portablePublicQueryDisclosure = (kind: PortableQueryKind): PortableDisclosureScope => immutableProtocolValue({
  mode: "PUBLIC_MINIMAL", includedFields: PORTABLE_QUERY_ANSWER_FIELD_PATHS.filter(path =>
    kind === "WHY" ? path === "presentConsequentialUse" || path === "authorization" || path.startsWith("authorization.") :
    kind === "RESPONSIBLE" ? path === "authorizationDecision" || path === "attributions" || path.startsWith("attributions.") :
    path !== "presentConsequentialUse" && path !== "authorizationDecision" && path !== "authorization" &&
      !path.startsWith("authorization.") && path !== "attributions" && !path.startsWith("attributions.")),
  withheldFields: [],
});
