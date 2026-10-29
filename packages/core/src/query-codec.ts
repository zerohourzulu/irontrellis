/**
 * Query vocabulary shared by WHY / RESPONSIBLE / SURVIVES (spec 03 §0, §A.6–A.9):
 * envelope and answer types, the evidence order, the answer field-path table,
 * the public disclosures, and the output budget / projection writer that bound
 * every projected answer. Nothing here touches caller input.
 */
import { canonicalEncode, CanonicalError, compareProtocolStrings } from "./canonical.ts";
import { DUTY_POLICY_VERSION } from "./events.ts";
import type {
  HistoryFormat,
  ActionRequest, AuthorizationDomain, AuthorizationResult, AuthorityConstraints, AuthorityUsage, AuthorityEvidence,
  CanonicalEvent, ConsequentialBinding, ContentHash, HistoryHead, PermissionGrant, RecognizedRoot, ReplayState,
  ReceiptCommitmentRecord, OutcomeRecord, AdapterProfile, AttemptDutyReview, U53,
} from "./types.ts";

// ------------------------------------------------------------------ constants

export const QUERY_VERSION = "continuity-query-envelope/0.2" as const;
export const QUERY_EXTERNAL_ASSUMPTIONS = Object.freeze({
  trust: "LOCAL_REPLAY_UNDER_DECLARED_ROOTS_NOT_INDEPENDENTLY_AUTHENTICATED",
  identity: "PROTOCOL_IDENTIFIERS_NOT_REAL_WORLD_IDENTITY",
  observation: "SUPPLIED_HISTORY_MAY_NOT_BE_LATEST_PUBLIC_HISTORY",
  availability: "REPLAY_REQUIRES_EVENTS_AND_INTERPRETATION_RULES",
} as const);
export const OUTPUT_LIMITS = Object.freeze({ bytes: 16_777_216, stringBytes: 4_096, listMembers: 4_096, recordFields: 256, depth: 32, evidenceOccurrences: 4_096 });

// ------------------------------------------------------------------ evidence

export type QueryEvidenceReference =
  | Readonly<{ kind: "EVENT"; eventId: string; eventType: string; position: U53; historyHash: ContentHash }>
  | Readonly<{ kind: "AUTHORITY"; authorityId: string; grantEventId: string }>
  | Readonly<{ kind: "RUNTIME_CREDENTIAL"; keyId: string; sessionId: string; admissionEventId: string }>
  | Readonly<{ kind: "RECEIPT_COMMITMENT"; receiptContentHash: ContentHash; eventId: string; position: U53 }>
  | Readonly<{ kind: "EXTERNAL"; evidenceType: string; reference: string; attesterId: string }>;
export type EventReference = Extract<QueryEvidenceReference, { kind: "EVENT" }>;

const EVIDENCE_KINDS: readonly string[] = ["EVENT", "AUTHORITY", "RUNTIME_CREDENTIAL", "RECEIPT_COMMITMENT", "EXTERNAL"];
const evidenceTuple = (value: QueryEvidenceReference): readonly (string | number)[] => {
  switch (value.kind) {
    case "EVENT": return [value.eventId, value.eventType, value.position, value.historyHash];
    case "AUTHORITY": return [value.authorityId, value.grantEventId];
    case "RUNTIME_CREDENTIAL": return [value.keyId, value.sessionId, value.admissionEventId];
    case "RECEIPT_COMMITMENT": return [value.receiptContentHash, value.eventId, value.position];
    case "EXTERNAL": return [value.evidenceType, value.reference, value.attesterId];
  }
};

/** Kind rank first, then the kind's tuple: strings in protocol order, numbers numerically (spec 03 §0.3). */
export const compareQueryEvidence = (a: QueryEvidenceReference, b: QueryEvidenceReference): number => {
  const rank = EVIDENCE_KINDS.indexOf(a.kind) - EVIDENCE_KINDS.indexOf(b.kind);
  if (rank !== 0) return rank;
  const left = evidenceTuple(a), right = evidenceTuple(b);
  for (let index = 0; index < left.length; index += 1) {
    const x = left[index] as string | number, y = right[index] as string | number;
    const order = typeof x === "number" && typeof y === "number" ? x - y : compareProtocolStrings(String(x), String(y));
    if (order !== 0) return order;
  }
  return 0;
};

/** Union of the groups, deduplicated by canonical identity, in evidence order. */
export const queryEvidence = (...groups: readonly (readonly QueryEvidenceReference[])[]): readonly QueryEvidenceReference[] => {
  const unique = new Map<string, QueryEvidenceReference>();
  for (const group of groups) for (const item of group) unique.set(canonicalEncode(item), item);
  return Object.freeze([...unique.values()].sort(compareQueryEvidence));
};

export const eventReference = (state: ReplayState, position: number): EventReference => {
  const event = state.events[position], historyHash = state.eventHistoryHashes[position];
  if (event === undefined || historyHash === undefined) throw new TypeError("Query evidence requires an accepted event position.");
  return Object.freeze({ kind: "EVENT", eventId: event.id, eventType: event.type, position, historyHash });
};

export const receiptReference = (receipt: ReceiptCommitmentRecord): QueryEvidenceReference => Object.freeze({
  kind: "RECEIPT_COMMITMENT", receiptContentHash: receipt.receiptContentHash, eventId: receipt.eventId, position: receipt.eventPosition,
});

/** Per-position references are shared between rows; the budget still charges every occurrence. */
export const createEvidenceCache = (state: ReplayState) => {
  const events = new Map<number, QueryEvidenceReference>();
  const receipts = new WeakMap<ReceiptCommitmentRecord, QueryEvidenceReference>();
  return {
    event(position: number): QueryEvidenceReference {
      let reference = events.get(position);
      if (reference === undefined) { reference = eventReference(state, position); events.set(position, reference); }
      return reference;
    },
    receipt(record: ReceiptCommitmentRecord): QueryEvidenceReference {
      let reference = receipts.get(record);
      if (reference === undefined) { reference = receiptReference(record); receipts.set(record, reference); }
      return reference;
    },
  };
};

// ------------------------------------------------------------------ envelope types

export type QueryKind = "WHY" | "RESPONSIBLE" | "SURVIVES";
export type QueryFailureCode = "INVALID_INPUT" | "UNSUPPORTED_VERSION" | "STATE_NOT_AUTHORITATIVE" | "CAUSAL_TIME_INVALID" |
  "HISTORY_RELATION_UNVERIFIED" | "DISCLOSURE_INVALID" | "OUTPUT_LIMIT_EXCEEDED" | "EVIDENCE_UNAVAILABLE" | "EVIDENCE_DISPUTED";
export type Disclosure = Readonly<{ mode: "PUBLIC_MINIMAL"; includedFields: readonly string[]; withheldFields: readonly string[] }>;
export type QueryIdentity = Readonly<{
  domain: AuthorizationDomain; versions: Readonly<Record<string, string>>; policyVersion: string;
  rootRecognitionPolicy: "declared-principal-root/0.2"; recognizedRootIds: readonly string[]; canonicalLineageId: string;
  evaluationHead: HistoryHead; observedHead: HistoryHead;
  /** SPEC §13.6: present only when a duty policy is active (`[{version: "continuity-attempt-disposition/1", rulesHash}]`). */
  recognizedExtensions?: readonly Readonly<{ version: string; rulesHash: ContentHash }>[];
}>;
export type HeadRelationship = "SAME_HEAD" | "STRICT_EXTENSION" | "UNVERIFIED";
export type QueryScope = QueryIdentity & Readonly<{
  headRelationship: HeadRelationship; freshness: "CURRENT" | "AT_EVALUATION" | "UNVERIFIED"; finality: "LOCAL_ONLY";
  disclosure: Disclosure; unavailableEvidence: readonly QueryEvidenceReference[]; withheldEvidence: readonly QueryEvidenceReference[];
  externalAssumptions: typeof QUERY_EXTERNAL_ASSUMPTIONS;
}>;
export type PartialQueryScope = Partial<QueryIdentity> & Readonly<{
  headRelationship: "UNVERIFIED"; freshness: "UNVERIFIED"; finality: "LOCAL_ONLY"; disclosure?: Disclosure;
  unavailableEvidence: readonly QueryEvidenceReference[]; withheldEvidence: readonly QueryEvidenceReference[];
  externalAssumptions: typeof QUERY_EXTERNAL_ASSUMPTIONS;
}>;
export type EstablishedQueryEnvelope<K extends QueryKind, T> = Readonly<{
  version: typeof QUERY_VERSION; kind: K; epistemicStatus: "ESTABLISHED"; scope: QueryScope; answer: T;
}>;
export type NonEstablishedQueryEnvelope<K extends QueryKind> = Readonly<{
  version: typeof QUERY_VERSION; kind: K; epistemicStatus: "INDETERMINATE" | "UNAVAILABLE" | "DISPUTED";
  scope: PartialQueryScope | QueryScope; code: QueryFailureCode; evidence: readonly QueryEvidenceReference[];
  externalAssumptions: typeof QUERY_EXTERNAL_ASSUMPTIONS;
}>;

export type WhyInput = Readonly<{
  operationVersion: typeof QUERY_VERSION; evaluationEvents: readonly CanonicalEvent[]; observedEvents: readonly CanonicalEvent[];
  authorizationDomain: AuthorizationDomain; request: ActionRequest; evaluationTime: U53;
  consequentialBinding?: ConsequentialBinding; disclosure: Disclosure;
}>;
export type ResponsibleInput = WhyInput;
export type SurvivesInput = Readonly<{
  operationVersion: typeof QUERY_VERSION; evaluationEvents?: readonly CanonicalEvent[]; observedEvents: readonly CanonicalEvent[];
  targetAgentId: string; evaluationTime: U53; disclosure: Disclosure;
}>;
/** State-level inputs: the histories are already replayed by the caller. */
export type WhyStateInput = Omit<WhyInput, "operationVersion" | "evaluationEvents" | "observedEvents">;
export type ResponsibleStateInput = WhyStateInput;
export type SurvivesStateInput = Omit<SurvivesInput, "operationVersion" | "evaluationEvents" | "observedEvents">;

/** The shape of an ALLOW proof as the queries read it (spec 02 §6.3). */
export type IntersectionProofView = Readonly<{
  requiredAuthorityId: string; requiredByAuthorityIds: readonly string[]; recognizedRoot: RecognizedRoot;
  path: readonly PermissionGrant[]; effectiveConstraints: AuthorityConstraints;
}>;
export type AuthorizationProofView = Readonly<{
  proofVersion: string; domain: AuthorizationDomain; policyVersion: string; rootRecognitionPolicy: string; historyHead: HistoryHead;
  evaluationTime: U53; request: ActionRequest; recognizedRoot: RecognizedRoot; permissionPath: readonly PermissionGrant[];
  intersections: readonly IntersectionProofView[]; effectiveConstraints: AuthorityConstraints; controllingAuthorityIds: readonly string[];
  usageSnapshot: readonly AuthorityUsage[]; authorityEvidence: readonly AuthorityEvidence[]; checkedProhibitionIds: readonly string[];
  consequential: boolean; runtimeSessionId?: string; credentialKeyId?: string; controlEpoch?: U53; roleId?: string; roleTenureId?: string;
  intentId?: string; nonce?: string;
}>;
export type QueryAuthorization = Extract<AuthorizationResult, { decision: "ALLOW" | "DENY" }> &
  Readonly<{ scopeAssurance: "REPLAY_VERIFIED"; operationVersion: "continuity-authorization/0.2" }>;

export type WhyAnswer = Readonly<{ authorization: QueryAuthorization; presentConsequentialUse: boolean }>;
export type ResponsibilityKind = "ACTOR" | "RUNTIME_SESSION" | "ROLE" | "DECLARED_PRINCIPAL" | "MANDATOR" | "AUTHORITY_SOURCE" |
  "CONTROLLER" | "DURABLE_OBLIGOR" | "PERFORMANCE_ASSIGNEE" | "BENEFICIARY" | "COUNTERPARTY";
export const RESPONSIBILITY_KINDS: readonly ResponsibilityKind[] = Object.freeze([
  "ACTOR", "RUNTIME_SESSION", "ROLE", "DECLARED_PRINCIPAL", "MANDATOR", "AUTHORITY_SOURCE",
  "CONTROLLER", "DURABLE_OBLIGOR", "PERFORMANCE_ASSIGNEE", "BENEFICIARY", "COUNTERPARTY",
]);
export type ResponsibilityAttribution = Readonly<{
  kind: ResponsibilityKind; subjectId: string; temporalBasis: "ACTION_PREFIX" | "LATER_CAUSAL_STATE"; evidence: readonly QueryEvidenceReference[];
}>;
export type ResponsibleAnswer = Readonly<{ authorizationDecision: "ALLOW" | "DENY"; attributions: readonly ResponsibilityAttribution[]; attemptDuties?: readonly AttemptDutyProjection[] }>;

export type RoleTenureProjection = Readonly<{
  roleId: string; agentId: string; roleTenureId: string; tenureNumber: U53; status: "CURRENT" | "CLOSED"; evidence: readonly QueryEvidenceReference[];
}>;
export type IntentProjection = Readonly<{
  intentId: string; actorId: string; nonce: string; state: "DECLARED" | "ADMITTED" | "SUBMITTED" | "OUTCOME_UNKNOWN" | "DISPUTED";
  evidence: readonly QueryEvidenceReference[];
}>;
export type AdapterOutcomeProjection = Readonly<{
  intentId: string; actorId: string; adapterProfile: AdapterProfile; state: string;
  acknowledgment?: Readonly<Record<string, unknown>>; latestOutcome?: OutcomeRecord; evidence: readonly QueryEvidenceReference[];
}>;
export type OutcomeObservationProjection = Readonly<{
  observationEventId: string; intentId: string; sourceAdmissionEventId: string; originalActorId: string; recorderId: string; recordedAt: U53;
  reportDigest: Readonly<{ algorithm: "sha256"; value: ContentHash }>; reportStatus: "REPORT_RECORDED" | "DIVERGENT_REPORTS";
  externalOutcome: "NOT_PROVEN"; evidence: readonly QueryEvidenceReference[];
}>;
export type AttemptDutyProjection = Readonly<{
  dutyId: string; sourceIntentId: string; sourceAdmissionEventId: string; originalActorId: string; durableRoleId: string;
  creationActorId: string; initialAssigneeId: string; currentAssigneeId: string; deadline: U53; status?: "OPEN"; externalOutcome: "NOT_PROVEN";
  /** SPEC §13.6: the `continuity-attempt-duty-view/1` record in place of `status` for a duty with an active policy. */
  currentView?: Readonly<Record<string, unknown>>;
  evidence: readonly QueryEvidenceReference[]; reviewStatus?: "UNREVIEWED" | "REVIEW_CLOSED" | "NEEDS_REVIEW"; reviews?: readonly AttemptDutyReview[];
}>;
export type ObligationProjection = Readonly<{
  obligationId: string; durableRoleId: string; performanceAssigneeId: string; status: string; deadline: U53; evidence: readonly QueryEvidenceReference[];
}>;
export type PerformanceAssignmentProjection = Readonly<{ obligationId: string; assigneeId: string; successionRuleId: string; evidence: readonly QueryEvidenceReference[] }>;
export type AuthorityDependencyProjection = Readonly<{ authorityId: string; state: "REVOKED" | "EXPIRED" | "AGENT_TERMINATED"; evidence: readonly QueryEvidenceReference[] }>;
export type SurvivesAnswer = Readonly<{
  targetAgentId: string; exists: boolean; lifecycleStatus: "ABSENT" | "ACTIVE" | "TERMINATED";
  historicalIdentity: readonly QueryEvidenceReference[];
  currentRoleTenures: readonly RoleTenureProjection[]; transferredRoleTenures: readonly RoleTenureProjection[];
  unresolvedIntents: readonly IntentProjection[]; adapterOutcomes: readonly AdapterOutcomeProjection[];
  outcomeObservations?: readonly OutcomeObservationProjection[]; attemptDuties?: readonly AttemptDutyProjection[];
  receiptCommitments: readonly QueryEvidenceReference[]; obligations: readonly ObligationProjection[];
  currentPerformanceAssignments: readonly PerformanceAssignmentProjection[];
  invalidatedAuthorityDependencies: readonly AuthorityDependencyProjection[];
}>;

export type WhyQueryResult = EstablishedQueryEnvelope<"WHY", WhyAnswer> | NonEstablishedQueryEnvelope<"WHY">;
export type ResponsibleQueryResult = EstablishedQueryEnvelope<"RESPONSIBLE", ResponsibleAnswer> | NonEstablishedQueryEnvelope<"RESPONSIBLE">;
export type SurvivesQueryResult = EstablishedQueryEnvelope<"SURVIVES", SurvivesAnswer> | NonEstablishedQueryEnvelope<"SURVIVES">;
export type QueryResult = WhyQueryResult | ResponsibleQueryResult | SurvivesQueryResult;

// ------------------------------------------------------------------ answer field paths (spec 03 §A.9)

const answerFields = new Set<string>();
const fields = (prefix: string, names: string): void => {
  for (const name of names.split(" ")) answerFields.add(prefix ? `${prefix}.${name}` : name);
};
export const EVIDENCE_FIELDS = "kind eventId eventType position historyHash authorityId grantEventId keyId sessionId admissionEventId receiptContentHash evidenceType reference attesterId";
const CONSTRAINT_FIELDS = "actions resources quantitative notBefore expiresAt maxAmount maxCumulativeAmount maxTransactions maxDelegationDepth requiredIntersectionIds";
const ROOT_FIELDS = "rootAuthorityId principalId principalRecognitionEventId rootGrantEventId";
export const DOMAIN_FIELDS = "protocol version deploymentId chainId verifyingContract";
const GRANT_FIELDS = "kind authorityId grantorId granteeId rootAuthorityId parentAuthorityId independent constraints";
const PROFILE_FIELDS = "profileId profileVersion descriptorHash";
fields("", "authorization presentConsequentialUse authorizationDecision attributions targetAgentId exists lifecycleStatus historicalIdentity currentRoleTenures transferredRoleTenures unresolvedIntents adapterOutcomes outcomeObservations attemptDuties receiptCommitments obligations currentPerformanceAssignments invalidatedAuthorityDependencies");
fields("authorization", "operationVersion decision scopeAssurance consequential proof code failures");
fields("authorization.failures", "code subjectId rootAuthorityId terminalAuthorityId failingAuthorityId authorityPathIds evidence");
fields("authorization.failures.evidence", EVIDENCE_FIELDS);
fields("authorization.proof", "proofVersion domain policyVersion rootRecognitionPolicy historyHead evaluationTime request recognizedRoot permissionPath intersections effectiveConstraints controllingAuthorityIds usageSnapshot authorityEvidence checkedProhibitionIds consequential runtimeSessionId credentialKeyId controlEpoch roleId roleTenureId intentId nonce");
fields("authorization.proof.domain", DOMAIN_FIELDS);
fields("authorization.proof.historyHead", "hash position canonicalTime");
fields("authorization.proof.request", "actorId action resource claimedAt amount counterpartyId termsCommitment");
fields("authorization.proof.recognizedRoot", ROOT_FIELDS);
fields("authorization.proof.permissionPath", GRANT_FIELDS);
fields("authorization.proof.permissionPath.constraints", CONSTRAINT_FIELDS);
fields("authorization.proof.intersections", "requiredAuthorityId requiredByAuthorityIds recognizedRoot path effectiveConstraints");
fields("authorization.proof.intersections.recognizedRoot", ROOT_FIELDS);
fields("authorization.proof.intersections.path", GRANT_FIELDS);
fields("authorization.proof.intersections.path.constraints", CONSTRAINT_FIELDS);
fields("authorization.proof.intersections.effectiveConstraints", CONSTRAINT_FIELDS);
fields("authorization.proof.effectiveConstraints", CONSTRAINT_FIELDS);
fields("authorization.proof.usageSnapshot", "authorityId admittedTransactionCount admittedCumulativeAmount");
fields("authorization.proof.authorityEvidence", "authorityId grantEventId grantEventPosition");
fields("attributions", "kind subjectId temporalBasis evidence");
fields("attributions.evidence", EVIDENCE_FIELDS);
for (const path of ["historicalIdentity", "receiptCommitments"]) fields(path, EVIDENCE_FIELDS);
for (const path of ["currentRoleTenures", "transferredRoleTenures"]) {
  fields(path, "roleId agentId roleTenureId tenureNumber status evidence"); fields(`${path}.evidence`, EVIDENCE_FIELDS);
}
fields("unresolvedIntents", "intentId actorId nonce state evidence");
fields("outcomeObservations", "observationEventId intentId sourceAdmissionEventId originalActorId recorderId recordedAt reportDigest reportStatus externalOutcome evidence");
fields("outcomeObservations.reportDigest", "algorithm value");
fields("outcomeObservations.evidence", EVIDENCE_FIELDS);
fields("attemptDuties", "dutyId sourceIntentId sourceAdmissionEventId originalActorId durableRoleId creationActorId initialAssigneeId currentAssigneeId deadline status externalOutcome evidence reviewStatus reviews");
fields("attemptDuties.reviews", "dutyId actorId observationEventIds summaryDigest eventId eventPosition reviewedAt");
fields("attemptDuties.evidence", EVIDENCE_FIELDS);
fields("adapterOutcomes", "intentId actorId adapterProfile state acknowledgment latestOutcome evidence");
fields("adapterOutcomes.adapterProfile", PROFILE_FIELDS);
fields("adapterOutcomes.evidence", EVIDENCE_FIELDS);
fields("adapterOutcomes.latestOutcome", "intentId eventId eventPosition head status attesterId evidenceReference noEffect");
fields("adapterOutcomes.latestOutcome.head", "hash position canonicalTime");
fields("adapterOutcomes.latestOutcome.evidenceReference", EVIDENCE_FIELDS);
for (const path of ["adapterOutcomes.acknowledgment", "adapterOutcomes.latestOutcome.noEffect"]) {
  fields(path, "schemaVersion kind adapterProfile domain intentId admissionHead idempotencyKey submissionFingerprint result");
  fields(`${path}.adapterProfile`, PROFILE_FIELDS); fields(`${path}.domain`, DOMAIN_FIELDS); fields(`${path}.admissionHead`, "hash position canonicalTime");
}
fields("adapterOutcomes.acknowledgment.result", "kind submissionReference manifestDigest transitionDigest publicationManifestDigest reportDigest");
for (const digest of ["reportDigest", "manifestDigest", "publicationManifestDigest", "transitionDigest"]) fields(`adapterOutcomes.acknowledgment.result.${digest}`, "algorithm value");
fields("adapterOutcomes.latestOutcome.noEffect.result", "kind reference");
fields("obligations", "obligationId durableRoleId performanceAssigneeId status deadline evidence");
fields("currentPerformanceAssignments", "obligationId assigneeId successionRuleId evidence");
fields("invalidatedAuthorityDependencies", "authorityId state evidence");
for (const path of ["unresolvedIntents", "obligations", "currentPerformanceAssignments", "invalidatedAuthorityDependencies"]) fields(`${path}.evidence`, EVIDENCE_FIELDS);
export const QUERY_ANSWER_FIELD_PATHS: readonly string[] = Object.freeze([...answerFields].sort(compareProtocolStrings));
/**
 * Format 2 adds two answer paths (SPEC §8.2, §9.6; both spelt as decimal strings or identifiers, never Amounts):
 * `authorization.budgetId` (the budget that decided, `null` otherwise) and `authorization.proof.request.metric`. The
 * legacy/format-1 table above is the reference's, unchanged, so those answers stay byte-identical.
 */
export const FORMAT2_ANSWER_FIELD_PATHS: readonly string[] = Object.freeze(["authorization.budgetId", "authorization.proof.request.metric"]);
export const QUERY_ANSWER_FIELD_PATHS_2: readonly string[] = Object.freeze([...answerFields, ...FORMAT2_ANSWER_FIELD_PATHS].sort(compareProtocolStrings));
/** The answer field paths of a history format: the format-2 table for `irontrellis-event/2`, the reference's otherwise. */
export const queryAnswerFieldPaths = (format?: HistoryFormat): readonly string[] => (format === "irontrellis-event/2" ? QUERY_ANSWER_FIELD_PATHS_2 : QUERY_ANSWER_FIELD_PATHS);
/**
 * SPEC §13.6 (E4), `portable-query-codec.ts:285-306` (`PORTABLE_DUTY_QUERY_FIELD_PATHS`): the duty-policy vocabulary is
 * opt-in so every unextended default disclosure keeps its original bytes; `publicQueryDisclosure(kind, [DUTY_POLICY_VERSION])`
 * adds it (the RESPONSIBLE answer gains `attemptDuties` rows and the SURVIVES duty rows carry `currentView`).
 */
export const DUTY_QUERY_FIELD_PATHS: readonly string[] = (() => {
  const result = new Set<string>();
  const add = (prefix: string, names: string): void => { for (const key of names.split(" ")) result.add(`${prefix}.${key}`); };
  add("attemptDuties", "currentView");
  add("attemptDuties.currentView", "version dutyId dutyDisposition outstanding externalOutcome policy observedHead currentAssigneeId latestAssignmentEventId lastRecordedDisposition reasons evidenceScope");
  add("attemptDuties.currentView.policy", "descriptor descriptorHash activationAuthorityId actorId eventId eventPosition activatedAt priorHead dispositionCount contestCount");
  add("attemptDuties.currentView.policy.descriptor", "version rulesHash criteriaProfile domain genesisHash baseAdapterPolicyHash dutyId dutyCreationEventId dutyRecordHash sourceIntentId sourceAdmissionEventId durableRoleId principalId incidentSourceDigest acceptedAttesterRoleId dispositionLimit contestLimit");
  add("attemptDuties.currentView.policy.descriptor.domain", DOMAIN_FIELDS);
  add("attemptDuties.currentView.policy.descriptor.incidentSourceDigest", "algorithm value");
  for (const head of ["observedHead", "policy.priorHead", "evidenceScope.head"]) add(`attemptDuties.currentView.${head}`, "hash position canonicalTime");
  add("attemptDuties.currentView.evidenceScope", "kind head");
  add("attemptDuties.currentView.lastRecordedDisposition", "eventId eventPosition timestamp disposition findingHash evidenceIndexHash reportDigest");
  add("attemptDuties.currentView.lastRecordedDisposition.reportDigest", "algorithm value");
  return Object.freeze([...result].sort(compareProtocolStrings));
})();

const isWhyPath = (path: string): boolean => path === "presentConsequentialUse" || path === "authorization" || path.startsWith("authorization.");
const isResponsiblePath = (path: string): boolean => path === "authorizationDecision" || path === "attributions" || path.startsWith("attributions.");
const isDutyPath = (path: string): boolean => path === "attemptDuties" || path.startsWith("attemptDuties.");
/**
 * The complete per-kind default disclosure (WHY 143 paths, RESPONSIBLE 20, SURVIVES 322; the reference's, for legacy and
 * format-1 histories). Merge of E3 and E4 (G2-APPLY §1):
 * - `format` = `irontrellis-event/2` (E3): the WHY disclosure also names the two format-2 paths (145), which a format-2
 *   answer carries (a WHY over a format-2 history with the reference's disclosure is DISCLOSURE_INVALID whenever the
 *   result names a budget or the request a metric);
 * - `extensions` naming the duty-policy version (E4, `portablePublicQueryDisclosure`, `portable-query-codec.ts:308-316`):
 *   the duty paths are listed too (RESPONSIBLE then includes `attemptDuties` and its subpaths).
 * Either argument may be given alone: `publicQueryDisclosure(kind, format)`, `publicQueryDisclosure(kind, extensions)`,
 * or both as `publicQueryDisclosure(kind, format, extensions)`.
 */
export function publicQueryDisclosure(kind: QueryKind, formatOrExtensions?: HistoryFormat | readonly string[], extensionsInput?: readonly string[]): Disclosure {
  const format = typeof formatOrExtensions === "string" ? formatOrExtensions : undefined;
  const extensions = Array.isArray(formatOrExtensions) ? formatOrExtensions as readonly string[] : (extensionsInput ?? []);
  const extended = extensions.includes(DUTY_POLICY_VERSION);
  const base = queryAnswerFieldPaths(format);
  const paths = extended ? [...base, ...DUTY_QUERY_FIELD_PATHS].sort(compareProtocolStrings) : base;
  return Object.freeze({
    mode: "PUBLIC_MINIMAL",
    includedFields: Object.freeze(paths.filter(path =>
      kind === "WHY" ? isWhyPath(path) : kind === "RESPONSIBLE" ? isResponsiblePath(path) || (extended && isDutyPath(path)) : !isWhyPath(path) && !isResponsiblePath(path))),
    withheldFields: Object.freeze([]),
  });
}

// ------------------------------------------------------------------ output budget (spec 03 §A.8)

/** The overflow token: thrown, never surfaced; every other error propagates. */
const OUTPUT_OVERFLOW: unique symbol = Symbol("irontrellis.output-overflow");
export const isOutputOverflow = (error: unknown): boolean => error === OUTPUT_OVERFLOW;
const overflow = (): never => { throw OUTPUT_OVERFLOW; };
export type OutputMetrics = Readonly<{ bytes: number; depth: number }>;

const scalarBytes = (value: unknown): number => {
  if (typeof value === "string" && Buffer.byteLength(value, "utf8") > OUTPUT_LIMITS.stringBytes) return overflow();
  try { return Buffer.byteLength(canonicalEncode(value), "utf8"); }
  catch (error) { return error instanceof CanonicalError && error.limit ? overflow() : (() => { throw error; })(); }
};

/**
 * Exact canonical byte length and container depth of an output value. Aliases
 * are charged at every occurrence; a container met again deeper than its first
 * visit is re-checked against the depth limit. Cycles are a TypeError.
 */
export const measureOutput = (value: unknown): OutputMetrics => {
  const active = new WeakSet<object>(), memo = new WeakMap<object, OutputMetrics>();
  let used = 0;
  const reserve = (bytes: number): void => {
    if (bytes > OUTPUT_LIMITS.bytes - used) { used = OUTPUT_LIMITS.bytes + 1; overflow(); }
    used += bytes;
  };
  const visit = (current: unknown, ancestorDepth: number): OutputMetrics => {
    if (current === null || typeof current !== "object") {
      const bytes = scalarBytes(current); reserve(bytes); return { bytes, depth: 0 };
    }
    if (active.has(current)) throw new TypeError("Query output contains a cycle.");
    const cached = memo.get(current);
    if (cached !== undefined) {
      if (ancestorDepth + cached.depth > OUTPUT_LIMITS.depth) overflow();
      reserve(cached.bytes); return cached;
    }
    const isArray = Array.isArray(current);
    const keys = isArray ? [] : Object.keys(current);
    if (isArray && current.length > OUTPUT_LIMITS.listMembers) overflow();
    if (!isArray && keys.length > OUTPUT_LIMITS.recordFields) overflow();
    if (!isArray && keys.some(key => key.startsWith("$continuity."))) {
      // Exact bigint wire markers have scalar depth.
      const bytes = scalarBytes(current); reserve(bytes);
      const measured = { bytes, depth: 0 }; memo.set(current, measured); return measured;
    }
    const containingDepth = ancestorDepth + 1;
    if (containingDepth > OUTPUT_LIMITS.depth) overflow();
    const started = used;
    let maximumChildDepth = 0;
    reserve(2); // both delimiters before any member
    active.add(current);
    try {
      if (isArray) {
        for (let index = 0; index < current.length; index += 1) {
          if (index > 0) reserve(1);
          const child = visit(current[index], containingDepth);
          if (child.depth > maximumChildDepth) maximumChildDepth = child.depth;
        }
      } else {
        let count = 0;
        const record = current as Record<string, unknown>;
        for (const key of keys) {
          const keyBytes = scalarBytes(key); // keys are bounded even when their undefined value is omitted
          const field = record[key];
          if (field === undefined) continue;
          if (count > 0) reserve(1);
          reserve(keyBytes + 1);
          const child = visit(field, containingDepth);
          if (child.depth > maximumChildDepth) maximumChildDepth = child.depth;
          count += 1;
        }
      }
    } finally { active.delete(current); }
    const measured = { bytes: used - started, depth: 1 + maximumChildDepth };
    memo.set(current, measured);
    return measured;
  };
  return visit(value, 0);
};

/** Count of evidence-shaped records anywhere in a value (capped just past the limit). */
export const evidenceOccurrences = (value: unknown): number => {
  let count = 0;
  const visit = (current: unknown): void => {
    if (count > OUTPUT_LIMITS.evidenceOccurrences) return;
    if (Array.isArray(current)) { for (const child of current) visit(child); }
    else if (current !== null && typeof current === "object") {
      const record = current as Record<string, unknown>;
      if (typeof record.kind === "string" && EVIDENCE_KINDS.includes(record.kind)) count += 1;
      for (const child of Object.values(record)) visit(child);
    }
  };
  visit(value); return count;
};

/** True when the value is inside every output metric; TypeErrors (cycles) propagate. */
export const fitsOutput = (value: unknown): boolean => {
  if (evidenceOccurrences(value) > OUTPUT_LIMITS.evidenceOccurrences) return false;
  try { measureOutput(value); return true; }
  catch (error) { if (isOutputOverflow(error)) return false; throw error; }
};

/** Starts from the measured skeleton; `append` charges one more list member plus its comma. Dead after any failure. */
const createOutputBudget = (skeleton: unknown) => {
  let used = measureOutput(skeleton).bytes, evidenceUsed = 0;
  const fail = (): never => { used = OUTPUT_LIMITS.bytes + 1; return overflow(); };
  return {
    append(value: unknown, currentLength: number, ancestorDepth: number, occurrences: number): void {
      if (used > OUTPUT_LIMITS.bytes) overflow();
      if (currentLength >= OUTPUT_LIMITS.listMembers) fail();
      let measured: OutputMetrics;
      try { measured = measureOutput(value); }
      catch (error) { if (isOutputOverflow(error)) fail(); throw error; }
      const bytes = measured.bytes + (currentLength === 0 ? 0 : 1);
      if (occurrences > OUTPUT_LIMITS.evidenceOccurrences) fail();
      if (measured.depth + ancestorDepth > OUTPUT_LIMITS.depth || bytes > OUTPUT_LIMITS.bytes - used ||
          occurrences > OUTPUT_LIMITS.evidenceOccurrences - evidenceUsed) fail();
      used += bytes; evidenceUsed += occurrences;
    },
  };
};

// ------------------------------------------------------------------ projection writer

type Row = Record<string, unknown> & { evidence: QueryEvidenceReference[] };
export type QueryDerivation<T> = Readonly<{ answer?: T; includedFields: readonly string[]; outputLimitExceeded: boolean }>;
export interface ProjectionWriter {
  evidence(field: string, references: Iterable<QueryEvidenceReference>): void;
  row(field: string, key: string, members: Readonly<Record<string, unknown>>, references: Iterable<QueryEvidenceReference>): void;
}

/**
 * Writes rows and evidence into the skeleton's top-level lists under the output
 * budget. Rows with the same (field, key) merge their evidence (first members
 * win); the first overflow empties every list but keeps collecting field paths,
 * so a disclosure failure still takes precedence over the output failure.
 */
export const createProjectionWriter = <T extends object>(skeleton: T) => {
  const value = skeleton as Record<string, unknown>;
  const budget = createOutputBudget(value);
  const fields = new Set<string>();
  const rows = new Map<string, Row>();
  const groups = new Map<string, Set<string>>();
  let overflowed = false;
  const observe = (path: string, current: unknown): void => {
    if (Array.isArray(current)) { for (const member of current) observe(path, member); }
    else if (current !== null && typeof current === "object") {
      for (const [key, member] of Object.entries(current)) {
        if (member === undefined) continue;
        const child = path === "" ? key : `${path}.${key}`;
        fields.add(child); observe(child, member);
      }
    }
  };
  observe("", value);
  const attempt = (reserve: () => void): boolean => {
    if (overflowed) return false;
    try { reserve(); return true; }
    catch (error) {
      if (!isOutputOverflow(error)) throw error;
      overflowed = true;
      for (const current of Object.values(value)) if (Array.isArray(current)) current.length = 0;
      rows.clear(); groups.clear();
      return false;
    }
  };
  const appendEvidence = (groupKey: string, path: string, target: QueryEvidenceReference[] | undefined,
    references: Iterable<QueryEvidenceReference>, ancestorDepth: number): void => {
    for (const reference of references) {
      observe(path, reference);
      if (overflowed || target === undefined) continue;
      let seen = groups.get(groupKey);
      if (seen === undefined) { seen = new Set(); groups.set(groupKey, seen); }
      const identity = canonicalEncode(reference);
      if (seen.has(identity)) continue;
      if (attempt(() => budget.append(reference, target.length, ancestorDepth, 1))) { seen.add(identity); target.push(reference); }
    }
  };
  return {
    evidence(field: string, references: Iterable<QueryEvidenceReference>): void {
      appendEvidence(field, field, overflowed ? undefined : value[field] as QueryEvidenceReference[], references, 2);
    },
    row(field: string, key: string, members: Readonly<Record<string, unknown>>, references: Iterable<QueryEvidenceReference>): void {
      const identity = canonicalEncode([field, key]);
      observe(field, { ...members, evidence: [] });
      let row = rows.get(identity);
      if (!overflowed && row === undefined) {
        const candidate: Row = { ...members, evidence: [] };
        const list = value[field] as Row[];
        // Only evidence already nested in the members is charged here; the row's own evidence is charged as it is appended.
        if (attempt(() => budget.append(candidate, list.length, 2, evidenceOccurrences(candidate)))) { row = candidate; rows.set(identity, row); list.push(row); }
      }
      appendEvidence(identity, `${field}.evidence`, row?.evidence, references, 4);
    },
    finish(sortRows: (answer: T) => void): QueryDerivation<T> {
      if (!overflowed) {
        for (const row of rows.values()) row.evidence.sort(compareQueryEvidence);
        for (const [key, current] of Object.entries(value)) {
          if (Array.isArray(current) && current.length !== 0 && groups.has(key)) (current as QueryEvidenceReference[]).sort(compareQueryEvidence);
        }
        sortRows(skeleton);
      }
      return { ...(overflowed ? {} : { answer: skeleton }), includedFields: [...fields].sort(compareProtocolStrings), outputLimitExceeded: overflowed };
    },
  };
};

/** Comparison-only plan: interned evidence identities per (field, key) group; used by conflict detection (spec 03 §E). */
export const createComparisonPlan = (intern: Map<string, number>) => {
  const groups = new Map<string, { fields: string; evidence: Set<number> }>();
  const identityFor = (reference: QueryEvidenceReference): number => {
    const bytes = canonicalEncode(reference);
    let identity = intern.get(bytes);
    if (identity === undefined) { identity = intern.size; intern.set(bytes, identity); }
    return identity;
  };
  const add = (key: string, members: Readonly<Record<string, unknown>>, references: Iterable<QueryEvidenceReference>): void => {
    const encoded = canonicalEncode(members);
    let group = groups.get(key);
    if (group === undefined) { group = { fields: encoded, evidence: new Set() }; groups.set(key, group); }
    else if (group.fields !== encoded) throw new TypeError("Conflicting internal projection primary identity.");
    for (const reference of references) group.evidence.add(identityFor(reference));
  };
  return {
    groups,
    evidence(field: string, references: Iterable<QueryEvidenceReference>): void { add(field, {}, references); },
    row(field: string, key: string, members: Readonly<Record<string, unknown>>, references: Iterable<QueryEvidenceReference>): void {
      add(canonicalEncode([field, key]), members, references);
    },
  };
};
export type ComparisonPlan = ReturnType<typeof createComparisonPlan>;

export const comparisonPlansDiffer = (left: ComparisonPlan, right: ComparisonPlan): boolean => {
  if (left.groups.size !== right.groups.size) return true;
  for (const [key, a] of left.groups) {
    const b = right.groups.get(key);
    if (b === undefined || a.fields !== b.fields || a.evidence.size !== b.evidence.size) return true;
    for (const reference of a.evidence) if (!b.evidence.has(reference)) return true;
  }
  return false;
};
