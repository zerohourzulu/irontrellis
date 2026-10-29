/**
 * WHY / RESPONSIBLE / SURVIVES (spec 03 §A–E). `whyState` / `responsibleState` /
 * `survivesState` run over already-replayed states; the `*Portable` façades add
 * the legacy input capture, discovery and replay (through the supplied replay
 * function) so that a caller holding raw events gets the exact legacy envelope.
 */
import {
  canonicalEncode, CanonicalError, captureValue, compareProtocolStrings, isContentHash, isIdentifier, isProtocolString, isU53,
} from "./canonical.ts";
import { hashEventHistory } from "./hash.ts";
import { authorizeState } from "./authority.ts";
import { DUTY_POLICY_RULES_HASH, DUTY_POLICY_VERSION, FORMAT2_GENESIS_OPTIONAL_KEYS, FORMAT2_VERSIONS, TRELLIS2_FORMAT } from "./events.ts";
import { inspectDutyPolicyState } from "./duty-policy.ts";
import type { AuthorizationResult, AuthorizeInput, CanonicalEvent, HistoryFormat, ReplayResult, ReplayState } from "./types.ts";
import {
  QUERY_VERSION, QUERY_EXTERNAL_ASSUMPTIONS, QUERY_ANSWER_FIELD_PATHS, FORMAT2_ANSWER_FIELD_PATHS, DUTY_QUERY_FIELD_PATHS, DOMAIN_FIELDS, EVIDENCE_FIELDS, RESPONSIBILITY_KINDS,
  compareQueryEvidence, createEvidenceCache, createProjectionWriter, eventReference, fitsOutput, queryEvidence,
  type AuthorizationProofView, type Disclosure, type QueryAuthorization, type QueryDerivation, type QueryEvidenceReference,
  type QueryFailureCode, type QueryIdentity, type QueryKind, type QueryResult, type QueryScope, type PartialQueryScope,
  type NonEstablishedQueryEnvelope, type ResponsibleAnswer, type ResponsibilityAttribution, type ResponsibilityKind,
  type WhyQueryResult, type ResponsibleQueryResult, type SurvivesQueryResult, type WhyStateInput, type SurvivesStateInput,
} from "./query-codec.ts";
import { deriveSurvives, findQueryConflict } from "./query-survives.ts";

export * from "./query-codec.ts";
export { deriveSurvives, findQueryConflict, obligationLinksTarget, attemptDutyReviewStatus, survivesAnswersDiffer } from "./query-survives.ts";

type Evidence = QueryEvidenceReference;
type Data = Readonly<Record<string, unknown>>;
export type AuthorizeBody = Omit<AuthorizeInput, "events" | "operationVersion" | "authoritative">;
export type AuthorizeFn = (state: ReplayState, body: AuthorizeBody) => AuthorizationResult;
export type ReplayFn = (events: readonly unknown[]) => ReplayResult;
export type QueryOptions = Readonly<{ authorize?: AuthorizeFn }>;

// ------------------------------------------------------------------ RESPONSIBLE (spec 03 §C)

const asData = (event: CanonicalEvent): Data => event.data;
/** Whether a duty policy is active (a reference-shaped state handed in by the differential tests may lack the map). */
const hasDutyPolicies = (state: ReplayState): boolean => (state.attemptDutyPolicies?.size ?? 0) > 0;
const defined = <T>(items: readonly (T | undefined)[]): T[] => items.filter((item): item is T => item !== undefined);

/**
 * Attribution rows keyed by (kind, subject, basis); repeated adds merge evidence.
 * Grants on the proof's paths are resolved by authority id: the proof carries the
 * normalised grant while the state stores the recorded one, so a byte comparison
 * (the legacy crash) is never the right test. Nothing in here throws on an
 * inconsistent state; a fact that cannot be resolved simply contributes no row.
 */
export const deriveResponsibility = (evaluation: ReplayState, observed: ReplayState, authorization: QueryAuthorization): QueryDerivation<ResponsibleAnswer> => {
  // SPEC §13.6 (E4), `portable-query-responsibility.ts:31`: the `attemptDuties` list exists only when a duty policy is active on the observed branch.
  const writer = createProjectionWriter<ResponsibleAnswer>({ authorizationDecision: authorization.decision, attributions: [], ...(hasDutyPolicies(observed) ? { attemptDuties: [] } : {}) });
  if (authorization.decision !== "ALLOW") return writer.finish(() => {});
  const proof = authorization.proof as unknown as AuthorizationProofView;
  const evaluationCache = createEvidenceCache(evaluation), observedCache = createEvidenceCache(observed);
  const E = evaluationCache.event, O = observedCache.event;
  const eventFor = (match: (event: CanonicalEvent) => boolean): Evidence | undefined => {
    const position = evaluation.events.findIndex(match);
    return position < 0 ? undefined : E(position);
  };
  const add = (kind: ResponsibilityKind, subjectId: string, temporalBasis: ResponsibilityAttribution["temporalBasis"], evidence: readonly (Evidence | undefined)[]): void => {
    const present = defined(evidence);
    if (present.length === 0) return;
    writer.row("attributions", canonicalEncode([kind, subjectId, temporalBasis]), { kind, subjectId, temporalBasis }, present);
  };
  const action = (kind: ResponsibilityKind, subjectId: string, evidence: readonly (Evidence | undefined)[]) => add(kind, subjectId, "ACTION_PREFIX", evidence);
  const later = (kind: ResponsibilityKind, subjectId: string, evidence: readonly (Evidence | undefined)[]) => add(kind, subjectId, "LATER_CAUSAL_STATE", evidence);
  const agent = evaluation.agents.get(proof.request.actorId);
  if (agent === undefined) return writer.finish(() => {});
  const finalEvent = E(evaluation.head.position);
  const agentCreation = eventFor(e => e.type === "AGENT_CREATED" && asData(e).agentId === agent.id);
  const principalCreation = eventFor(e => e.type === "PRINCIPAL_CREATED" && asData(e).principalId === agent.principalId);
  action("ACTOR", agent.id, [agentCreation, finalEvent]);
  action("DECLARED_PRINCIPAL", agent.principalId, proof.consequential ? [principalCreation, agentCreation] : [principalCreation, agentCreation, finalEvent]);
  for (const selection of [{ recognizedRoot: proof.recognizedRoot, path: proof.permissionPath }, ...proof.intersections]) {
    const root = evaluation.recognizedRoots.get(selection.recognizedRoot.rootAuthorityId);
    const principal = root === undefined ? undefined : evaluation.principals.get(root.principalId);
    if (root === undefined || principal === undefined) continue;
    const rootPrincipal = E(principal.creationEventPosition);
    const grants = defined(selection.path.map(grant => evaluation.authorities.get(grant.authorityId))).map(stored => E(stored.grantEventPosition));
    const rootGrant = eventFor(e => e.id === root.rootGrantEventId);
    action("MANDATOR", root.principalId, [rootPrincipal, rootGrant, finalEvent]);
    action("AUTHORITY_SOURCE", root.rootAuthorityId, proof.consequential ? [rootPrincipal, ...grants] : [rootPrincipal, ...grants, finalEvent]);
  }
  if (!proof.consequential) {
    action("CONTROLLER", agent.controllerId, [agentCreation, finalEvent]);
    return finishResponsibility(writer);
  }
  const session = proof.runtimeSessionId === undefined ? undefined : evaluation.runtimeSessions.get(proof.runtimeSessionId);
  const intent = proof.intentId === undefined ? undefined : evaluation.intentDeclarations.get(proof.intentId)?.data;
  if (session === undefined || intent === undefined || proof.roleId === undefined || proof.roleTenureId === undefined) return finishResponsibility(writer);
  const roleId = proof.roleId, tenureId = proof.roleTenureId;
  const declaration = eventFor(e => e.type === "TRANSACTION_INTENT_DECLARED" && asData(e).intentId === proof.intentId);
  const sessionAdmission = E(session.admissionEventPosition);
  const advances: Evidence[] = [];
  for (let position = 0; position < evaluation.events.length; position += 1) {
    const event = evaluation.events[position] as CanonicalEvent;
    if (event.type === "CONTROL_EPOCH_ADVANCED" && asData(event).agentId === agent.id && (asData(event).toEpoch as number) <= (proof.controlEpoch as number)) advances.push(E(position));
  }
  const roleCreation = eventFor(e => e.type === "ROLE_CREATED" && asData(e).roleId === roleId);
  const opening = eventFor(e => (e.type === "AGENT_APPOINTED" && asData(e).roleTenureId === tenureId) || (e.type === "ROLE_TRANSFERRED" && asData(e).toRoleTenureId === tenureId));
  action("ACTOR", agent.id, [declaration]);
  action("RUNTIME_SESSION", session.id, [sessionAdmission, advances[advances.length - 1] ?? agentCreation, finalEvent]);
  action("ROLE", roleId, [roleCreation, opening, finalEvent]);
  action("CONTROLLER", agent.controllerId, [agentCreation, sessionAdmission, ...advances, finalEvent]);
  if (intent.counterpartyId !== undefined) action("COUNTERPARTY", intent.counterpartyId, [declaration, finalEvent]);

  // Later causal state exists only when the observed branch admitted exactly this proof.
  const admission = observed.intentAdmissions.get(intent.intentId);
  const admissionEvent = admission === undefined ? undefined : observed.events[admission.admissionEventPosition];
  if (admission === undefined || admissionEvent === undefined || canonicalEncode(admissionEvent.data.authorizationProof) !== canonicalEncode(proof)) return finishResponsibility(writer);
  // SPEC §13.6 (E4), `portable-query-responsibility.ts:115-128`: one row per duty of this admission with an active policy, carrying its current view;
  // evidence = the admission, the duty creation, the activation, every disposition and contest of the duty, every assignment.
  for (const [dutyId, duty] of observed.attemptDuties) {
    const record = duty.record, currentView = inspectDutyPolicyState(observed, dutyId);
    if (currentView === null || record.sourceIntentId !== intent.intentId || record.sourceAdmissionEventId !== admission.admissionEventId) continue;
    writer.row("attemptDuties", dutyId, {
      dutyId, sourceIntentId: record.sourceIntentId, sourceAdmissionEventId: record.sourceAdmissionEventId, originalActorId: agent.id,
      durableRoleId: record.durableRoleId, creationActorId: duty.creationActorId, initialAssigneeId: record.performanceAssigneeId, currentAssigneeId: duty.currentAssigneeId,
      deadline: record.deadline, currentView, externalOutcome: "NOT_PROVEN",
    }, defined([
      O(admission.admissionEventPosition), O(duty.creationEventPosition), O(currentView.policy.eventPosition),
      ...(observed.attemptDutyDispositions.get(dutyId) ?? []).map((row) => O(row.position)),
      ...duty.assignments.map((item) => O(item.eventPosition as number)),
    ]));
  }
  for (const obligation of observed.obligations.values()) {
    const record = obligation.record;
    if (record.sourceIntentId !== intent.intentId) continue;
    const receipt = observed.receiptCommitments.get(record.causalReceiptContentHash);
    if (receipt === undefined) continue;
    const chain = defined([O(admission.admissionEventPosition), observedCache.receipt(receipt), roleCreation, opening, O(obligation.creationEventPosition)]);
    const statusEvidence: Evidence[] = [];
    const performerEvidence = new Map<string, Evidence[]>();
    let performer = record.performanceAssigneeId;
    performerEvidence.set(performer, [...chain]);
    for (let position = obligation.creationEventPosition + 1; position < observed.events.length; position += 1) {
      const event = observed.events[position] as CanonicalEvent, data = asData(event);
      if (data.obligationId !== record.obligationId) continue;
      const reference = O(position);
      if (event.type === "OBLIGATION_PERFORMANCE_ASSIGNED") {
        performerEvidence.get(performer)?.push(reference);
        performer = data.toAgentId as string;
        if (!performerEvidence.has(performer)) performerEvidence.set(performer, [...chain]);
        performerEvidence.get(performer)?.push(reference);
      } else if (event.type === "OBLIGATION_STATUS_RECORDED") {
        statusEvidence.push(reference);
        performerEvidence.get(performer)?.push(reference);
      }
    }
    later("DURABLE_OBLIGOR", record.durableRoleId, [...chain, ...statusEvidence]);
    later("BENEFICIARY", record.beneficiaryId, [...chain, ...statusEvidence]);
    if (record.counterpartyId !== undefined) later("COUNTERPARTY", record.counterpartyId, [...chain, ...statusEvidence]);
    for (const [subject, evidence] of performerEvidence) later("PERFORMANCE_ASSIGNEE", subject, evidence);
  }
  return finishResponsibility(writer);
};

const finishResponsibility = (writer: ReturnType<typeof createProjectionWriter<ResponsibleAnswer>>): QueryDerivation<ResponsibleAnswer> =>
  writer.finish(answer => {
    (answer.attemptDuties as { dutyId: string }[] | undefined)?.sort((a, b) => compareProtocolStrings(a.dutyId, b.dutyId)); // portable-query-responsibility.ts:169
    (answer.attributions as ResponsibilityAttribution[]).sort((a, b) =>
      RESPONSIBILITY_KINDS.indexOf(a.kind) - RESPONSIBILITY_KINDS.indexOf(b.kind) || compareProtocolStrings(a.subjectId, b.subjectId) ||
      (a.temporalBasis === b.temporalBasis ? 0 : a.temporalBasis === "ACTION_PREFIX" ? -1 : 1));
  });

// ------------------------------------------------------------------ disclosure and scope helpers (spec 03 §A.5–A.6)

const LEGACY_VERSIONS = Object.freeze({
  eventSchemaVersion: "continuity-event/0.2", receiptSchemaVersion: "continuity-receipt/0.2",
  queryEnvelopeVersion: "continuity-query-envelope/0.2", authorizationProofVersion: "continuity-authorization-proof/0.2",
  runtimeAuthorizationVersion: "continuity-runtime-authorization/0.2", administrativeAuthorizationVersion: "continuity-administrative-authorization/0.2",
  signatureScheme: "eip191-personal-sign-keccak256",
});
const LEGACY_VERSIONS_ENCODED = canonicalEncode(LEGACY_VERSIONS);
const coreFields = new Set<string>([...QUERY_ANSWER_FIELD_PATHS, ...DUTY_QUERY_FIELD_PATHS]);
// SPEC §13.6 (E4), `portable-queries.ts:98-100`: the duty paths and the scope's `recognizedExtensions` are core fields (never withheld).
for (const key of DUTY_QUERY_FIELD_PATHS) coreFields.add(`answer.${key}`);
for (const key of ["recognizedExtensions", "recognizedExtensions.version", "recognizedExtensions.rulesHash"]) coreFields.add(`scope.${key}`);
for (const key of ["version", "kind", "epistemicStatus", "scope", "answer", "code", "evidence", "externalAssumptions"]) coreFields.add(key);
for (const key of QUERY_ANSWER_FIELD_PATHS) coreFields.add(`answer.${key}`);
for (const key of ["domain", "versions", "policyVersion", "rootRecognitionPolicy", "recognizedRootIds", "canonicalLineageId", "evaluationHead", "observedHead", "headRelationship", "freshness", "finality", "disclosure", "unavailableEvidence", "withheldEvidence", "externalAssumptions"]) coreFields.add(`scope.${key}`);
for (const key of DOMAIN_FIELDS.split(" ")) coreFields.add(`scope.domain.${key}`);
for (const key of Object.keys(LEGACY_VERSIONS)) coreFields.add(`scope.versions.${key}`);
for (const head of ["evaluationHead", "observedHead"]) for (const key of ["hash", "position", "canonicalTime"]) coreFields.add(`scope.${head}.${key}`);
for (const prefix of ["scope.externalAssumptions", "externalAssumptions"]) for (const key of Object.keys(QUERY_EXTERNAL_ASSUMPTIONS)) coreFields.add(`${prefix}.${key}`);
for (const key of ["mode", "includedFields", "withheldFields"]) coreFields.add(`scope.disclosure.${key}`);
for (const prefix of ["scope.unavailableEvidence", "scope.withheldEvidence", "evidence"]) for (const key of EVIDENCE_FIELDS.split(" ")) coreFields.add(`${prefix}.${key}`);
// Format 2: the core fields a disclosure may not withhold also name the format-2 answer paths and the twelve genesis version
// keys (`scope.versions.*`); the legacy set above stays the reference's, so legacy and format-1 answers are byte-identical.
const coreFields2 = new Set<string>(coreFields);
for (const key of FORMAT2_ANSWER_FIELD_PATHS) { coreFields2.add(key); coreFields2.add(`answer.${key}`); }
for (const key of [...Object.keys(FORMAT2_VERSIONS), "signatureScheme"]) coreFields2.add(`scope.versions.${key}`);
const coreFieldsFor = (format: HistoryFormat): ReadonlySet<string> => (format === TRELLIS2_FORMAT ? coreFields2 : coreFields);

const isRecord = (value: unknown): value is Data => value !== null && typeof value === "object" && !Array.isArray(value);
const hasExactKeys = (record: Data, required: readonly string[], optional: readonly string[] = []): boolean =>
  Object.keys(record).every(key => required.includes(key) || optional.includes(key)) && required.every(key => key in record);
const strictlySortedIdentifiers = (candidate: unknown): candidate is readonly string[] =>
  Array.isArray(candidate) && candidate.length <= 4096 &&
  candidate.every((item, index) => isIdentifier(item) && (index === 0 || compareProtocolStrings(candidate[index - 1] as string, item) < 0));

/** A valid disclosure, or undefined; the failure is reported only after time and authorization checks. */
const disclosureFor = (value: unknown, format: HistoryFormat): Disclosure | undefined => {
  if (!isRecord(value) || !hasExactKeys(value, ["mode", "includedFields", "withheldFields"]) || value.mode !== "PUBLIC_MINIMAL") return undefined;
  if (!strictlySortedIdentifiers(value.includedFields) || !strictlySortedIdentifiers(value.withheldFields)) return undefined;
  const included = new Set(value.includedFields), core = coreFieldsFor(format);
  if (value.withheldFields.some(path => included.has(path) || core.has(path))) return undefined;
  return value as Disclosure;
};

const EMPTY: readonly Evidence[] = Object.freeze([]);
const NO_FIELDS: readonly string[] = Object.freeze([]);
const EMPTY_DISCLOSURE: Disclosure = Object.freeze({ mode: "PUBLIC_MINIMAL", includedFields: NO_FIELDS, withheldFields: NO_FIELDS });
const blankScope = (unavailableEvidence: readonly Evidence[] = EMPTY): PartialQueryScope => ({
  headRelationship: "UNVERIFIED", freshness: "UNVERIFIED", finality: "LOCAL_ONLY", unavailableEvidence, withheldEvidence: EMPTY, externalAssumptions: QUERY_EXTERNAL_ASSUMPTIONS,
});
const failure = (kind: QueryKind, code: QueryFailureCode, scope: PartialQueryScope | QueryScope = blankScope(), evidence: readonly Evidence[] = EMPTY): NonEstablishedQueryEnvelope<QueryKind> => ({
  version: QUERY_VERSION, kind,
  epistemicStatus: code === "EVIDENCE_UNAVAILABLE" ? "UNAVAILABLE" : code === "EVIDENCE_DISPUTED" ? "DISPUTED" : "INDETERMINATE",
  scope: { ...scope, headRelationship: "UNVERIFIED", freshness: "UNVERIFIED" }, code, evidence, externalAssumptions: QUERY_EXTERNAL_ASSUMPTIONS,
});
const identityFor = (evaluation: ReplayState, observed: ReplayState): QueryIdentity => ({
  domain: evaluation.genesis.domain, versions: evaluation.genesis.versions, policyVersion: evaluation.genesis.policyVersion,
  rootRecognitionPolicy: evaluation.genesis.rootRecognitionPolicy, recognizedRootIds: [...evaluation.recognizedRoots.keys()].sort(compareProtocolStrings),
  canonicalLineageId: evaluation.genesis.canonicalLineageId, evaluationHead: evaluation.head, observedHead: observed.head,
  // SPEC §13.6 (E4), `portable-queries.ts:50-52`: the scope names the duty-policy extension when either branch has an active policy.
  ...((hasDutyPolicies(evaluation) || hasDutyPolicies(observed)) ? { recognizedExtensions: [{ version: DUTY_POLICY_VERSION, rulesHash: DUTY_POLICY_RULES_HASH }] } : {}),
});
const compactIdentity = ({ recognizedRootIds: _roots, ...identity }: QueryIdentity): Partial<QueryIdentity> => identity;

/** Every dotted path of a defined value in the answer, arrays visited element-wise without indices. */
const answerFieldPaths = (answer: unknown): readonly string[] => {
  const fields = new Set<string>();
  const visit = (value: unknown, prefix: string): void => {
    if (Array.isArray(value)) { for (const item of value) visit(item, prefix); }
    else if (value !== null && typeof value === "object") {
      for (const [key, child] of Object.entries(value)) {
        if (child === undefined) continue;
        const path = prefix ? `${prefix}.${key}` : key;
        fields.add(path); visit(child, path);
      }
    }
  };
  visit(answer, ""); return [...fields].sort(compareProtocolStrings);
};

/** Frozen deep copy in canonical key order with undefined members dropped: the shape every public envelope has. */
const finalize = <T>(value: T): T => {
  const copy = (current: unknown): unknown => {
    if (Array.isArray(current)) return Object.freeze(current.map(copy));
    if (current === null || typeof current !== "object") return current;
    const record = current as Data, out: Record<string, unknown> = {};
    for (const key of Object.keys(record).sort(compareProtocolStrings)) if (record[key] !== undefined) out[key] = copy(record[key]);
    return Object.freeze(out);
  };
  return copy(value) as T;
};

// ------------------------------------------------------------------ coordinator (spec 03 §A.5)

type QueryValue = Readonly<{
  evaluationTime: unknown; disclosure: unknown; targetAgentId?: string;
  authorizationDomain?: AuthorizeBody["domain"]; request?: AuthorizeBody["request"]; consequentialBinding?: AuthorizeBody["binding"];
}>;

const runQuery = (kind: QueryKind, evaluation: ReplayState, observed: ReplayState, value: QueryValue, authorize: AuthorizeFn): QueryResult => {
  const identity = identityFor(evaluation, observed);
  const earlyScope: PartialQueryScope = { ...blankScope(), ...compactIdentity(identity) };
  const relationship = observed.head.position === evaluation.head.position && observed.head.hash === evaluation.head.hash ? "SAME_HEAD" :
    observed.head.position > evaluation.head.position && observed.eventHistoryHashes[evaluation.head.position] === evaluation.head.hash ? "STRICT_EXTENSION" : "UNVERIFIED";
  const disclosure = disclosureFor(value.disclosure, evaluation.format);
  const completeScope: QueryScope = { ...blankScope(), ...identity, disclosure: disclosure ?? EMPTY_DISCLOSURE };
  const time = value.evaluationTime;
  const causalEvidence = () => queryEvidence([eventReference(evaluation, evaluation.head.position), eventReference(observed, observed.head.position)]);
  const fail = (code: QueryFailureCode, scope?: PartialQueryScope | QueryScope, evidence?: readonly Evidence[]): QueryResult => finalize(failure(kind, code, scope, evidence)) as QueryResult;
  // (a) Causal time: WHY/RESPONSIBLE need the evaluation head; an UNVERIFIED SURVIVES pair also needs the observed head.
  if (typeof time !== "number" || !Number.isSafeInteger(time) || Object.is(time, -0) || time < evaluation.head.canonicalTime ||
      (kind === "SURVIVES" && relationship === "UNVERIFIED" && time < observed.head.canonicalTime)) return fail("CAUSAL_TIME_INVALID", earlyScope, causalEvidence());
  // (b) Authorization at the evaluation head; policy facts come from the genesis, the domain from the caller.
  let authorization: AuthorizationResult | undefined;
  if (kind !== "SURVIVES") {
    const binding = value.consequentialBinding;
    authorization = authorize(evaluation, {
      expectedHistoryHead: evaluation.head, domain: value.authorizationDomain as AuthorizeBody["domain"],
      policyVersion: evaluation.genesis.policyVersion, rootRecognitionPolicy: evaluation.genesis.rootRecognitionPolicy,
      request: value.request as AuthorizeBody["request"], evaluationTime: time, consequential: binding !== undefined,
      ...(binding === undefined ? {} : { binding }),
    });
    if (authorization.decision === "INDETERMINATE") {
      const code: string = authorization.code;
      if (code === "CAUSAL_TIME_INVALID") return fail("CAUSAL_TIME_INVALID", earlyScope, causalEvidence());
      if (code === "INVALID_INPUT" || code === "UNSUPPORTED_VERSION" || code === "STATE_NOT_AUTHORITATIVE") return fail(code);
    }
  }
  // (c) Disclosure.
  if (disclosure === undefined) return fail("DISCLOSURE_INVALID", earlyScope);
  const outputFailure = () => fail("OUTPUT_LIMIT_EXCEEDED", { ...blankScope(), ...compactIdentity(identity) });
  let result: QueryResult;
  // (d) Relationship branch.
  if (relationship === "UNVERIFIED") {
    const conflict = findQueryConflict(evaluation, observed, kind === "SURVIVES"
      ? { kind, targetAgentId: value.targetAgentId as string, evaluationTime: time }
      : { kind, ...(value.consequentialBinding === undefined ? {} : { binding: value.consequentialBinding }) });
    if (conflict !== undefined) result = failure(kind, "EVIDENCE_DISPUTED", completeScope, conflict) as QueryResult;
    else {
      const shared = Math.min(evaluation.events.length, observed.events.length);
      let position = 0;
      while (position < shared && canonicalEncode(evaluation.events[position]) === canonicalEncode(observed.events[position])) position += 1;
      const evidence = position < shared ? queryEvidence([eventReference(evaluation, position), eventReference(observed, position)]) : causalEvidence();
      result = failure(kind, "HISTORY_RELATION_UNVERIFIED", completeScope, evidence) as QueryResult;
    }
  } else if (authorization?.decision === "INDETERMINATE") {
    const code: string = authorization.code;
    if (code === "OUTPUT_LIMIT_EXCEEDED" || code === "OUTPUT_LIMIT") return outputFailure();
    result = failure(kind, code === "EVIDENCE_DISPUTED" ? "HISTORY_RELATION_UNVERIFIED" : authorization.code as QueryFailureCode, completeScope) as QueryResult;
  } else {
    let answer: unknown, includedFields: readonly string[], overflow = false;
    if (kind === "SURVIVES") {
      const projection = deriveSurvives(evaluation, value.targetAgentId as string, time);
      answer = projection.answer; includedFields = projection.includedFields; overflow = projection.outputLimitExceeded;
    } else if (kind === "RESPONSIBLE") {
      const projection = deriveResponsibility(evaluation, observed, authorization as QueryAuthorization);
      answer = projection.answer; includedFields = projection.includedFields; overflow = projection.outputLimitExceeded;
    } else {
      answer = { authorization, presentConsequentialUse: authorization?.decision === "ALLOW" && authorization.consequential && relationship === "SAME_HEAD" };
      includedFields = answerFieldPaths(answer);
    }
    // The disclosure check precedes the overflow check.
    const selected = new Set(disclosure.includedFields);
    if (includedFields.some(path => !selected.has(path))) return fail("DISCLOSURE_INVALID", earlyScope);
    if (overflow || answer === undefined) return outputFailure();
    result = { version: QUERY_VERSION, kind, epistemicStatus: "ESTABLISHED",
      scope: { ...completeScope, headRelationship: relationship, freshness: relationship === "SAME_HEAD" ? "CURRENT" : "AT_EVALUATION" }, answer } as QueryResult;
  }
  // (e) Every envelope, failures included, must fit the output metrics.
  return identity.recognizedRootIds.length > 256 || !fitsOutput(result) ? outputFailure() : finalize(result);
};

const defaultAuthorize: AuthorizeFn = (state, body) => authorizeState(state, body);

export const whyState = (evaluation: ReplayState, observed: ReplayState, input: WhyStateInput, options: QueryOptions = {}): WhyQueryResult =>
  runQuery("WHY", evaluation, observed, input, options.authorize ?? defaultAuthorize) as WhyQueryResult;
export const responsibleState = (evaluation: ReplayState, observed: ReplayState, input: WhyStateInput, options: QueryOptions = {}): ResponsibleQueryResult =>
  runQuery("RESPONSIBLE", evaluation, observed, input, options.authorize ?? defaultAuthorize) as ResponsibleQueryResult;
/** `evaluation` defaults to `observed` (SAME_HEAD), matching the optional `evaluationEvents` of the portable input. */
export const survivesState = (observed: ReplayState, input: SurvivesStateInput, evaluation: ReplayState = observed): SurvivesQueryResult =>
  runQuery("SURVIVES", evaluation, observed, input, defaultAuthorize) as SurvivesQueryResult;

// ------------------------------------------------------------------ portable façades: capture (spec 03 §A.3) and discovery (§A.4)

const isScalar = (value: unknown): boolean => typeof value === "string" || typeof value === "number" || typeof value === "bigint";
const withinIdentifierLength = (value: unknown): boolean => typeof value !== "string" || Buffer.byteLength(value, "utf8") <= 256;
const isDomain = (value: unknown): boolean => isRecord(value) && (
  (hasExactKeys(value, ["protocol", "version", "deploymentId", "chainId", "verifyingContract"]) && value.protocol === "continuity" && value.version === "0.2" &&
    isIdentifier(value.deploymentId) && typeof value.chainId === "string" && /^[1-9][0-9]*$/.test(value.chainId) && BigInt(value.chainId) <= (1n << 256n) - 1n &&
    typeof value.verifyingContract === "string" && /^0x[0-9a-fA-F]{40}$/.test(value.verifyingContract)) ||
  (hasExactKeys(value, ["protocol", "version", "deploymentId"]) && value.protocol === "irontrellis" && (value.version === "1" || value.version === "2") && isIdentifier(value.deploymentId)));
const isSignature = (value: unknown): boolean => typeof value === "string" && /^0x[0-9a-f]{130}$/.test(value);

type Captured = Readonly<{ status: "CAPTURED"; value: Data }> | Readonly<{ status: "INVALID_INPUT" | "UNSUPPORTED_VERSION" }>;

/** One observation of the caller's input (own properties only), then a detached canonical snapshot. */
const captureQueryInput = (input: unknown, kind: QueryKind): Captured => {
  const invalid: Captured = { status: "INVALID_INPUT" };
  if (input === null || typeof input !== "object" || Array.isArray(input)) return invalid;
  const prototype = Object.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) return invalid;
  // Own properties only (inherited members are not input); each is read exactly once.
  const own = (key: string): { value: unknown } | undefined =>
    Object.getOwnPropertyDescriptor(input, key) === undefined ? undefined : { value: (input as Record<string, unknown>)[key] };
  const version = own("operationVersion");
  if (version === undefined || typeof version.value !== "string") return invalid;
  if (version.value !== QUERY_VERSION) return { status: "UNSUPPORTED_VERSION" };
  const required = kind === "SURVIVES" ? ["operationVersion", "observedEvents", "targetAgentId", "evaluationTime", "disclosure"]
    : ["operationVersion", "evaluationEvents", "observedEvents", "authorizationDomain", "request", "evaluationTime", "disclosure"];
  const optional = kind === "SURVIVES" ? ["evaluationEvents"] : ["consequentialBinding"];
  const keys = Reflect.ownKeys(input);
  if (keys.some(key => typeof key !== "string" || (!required.includes(key) && !optional.includes(key)))) return invalid;
  const raw: Record<string, unknown> = {};
  for (const key of [...required, ...optional]) {
    const member = own(key);
    if (member === undefined || member.value === undefined) { if (required.includes(key)) return invalid; continue; }
    if ((key === "evaluationEvents" || key === "observedEvents") && !Array.isArray(member.value)) return invalid;
    raw[key] = member.value;
  }
  let value: Data;
  try { value = captureValue(raw) as Data; }
  catch (error) { if (error instanceof CanonicalError) return invalid; throw error; }
  // Named identifier bounds and closed shapes precede replay and time (spec 03 §A.3 step 5).
  for (const name of ["evaluationEvents", "observedEvents"]) {
    const history = value[name];
    if (!Array.isArray(history)) continue;
    for (const event of history) if (isRecord(event) && !withinIdentifierLength(event.id)) return invalid;
  }
  if (isRecord(value.disclosure)) {
    for (const name of ["includedFields", "withheldFields"]) {
      const list = value.disclosure[name];
      if (Array.isArray(list) && !list.every(withinIdentifierLength)) return invalid;
    }
  }
  if (!isScalar(value.evaluationTime)) return invalid;
  if (kind === "SURVIVES") return isIdentifier(value.targetAgentId) ? { status: "CAPTURED", value } : invalid;
  if (!isDomain(value.authorizationDomain)) return invalid;
  const request = value.request;
  if (!isRecord(request) || !hasExactKeys(request, ["actorId", "action", "resource", "claimedAt"], ["amount", "counterpartyId", "termsCommitment"])) return invalid;
  for (const key of ["actorId", "action", "resource", "claimedAt", "amount", "counterpartyId"]) if (request[key] !== undefined && !isScalar(request[key])) return invalid;
  for (const key of ["actorId", "action", "resource", "counterpartyId"]) if (!withinIdentifierLength(request[key])) return invalid;
  const binding = value.consequentialBinding;
  if (binding === undefined) return { status: "CAPTURED", value };
  if (!isRecord(binding) || !hasExactKeys(binding, ["runtimeSessionId", "controlEpoch", "roleId", "roleTenureId"], ["credentialKeyId", "intentId", "nonce", "runtimeSignature"])) return invalid;
  const ok = isIdentifier(binding.runtimeSessionId) && isU53(binding.controlEpoch) && isIdentifier(binding.roleId) && isIdentifier(binding.roleTenureId) &&
    (binding.credentialKeyId === undefined || isIdentifier(binding.credentialKeyId)) && (binding.intentId === undefined || isIdentifier(binding.intentId)) &&
    (binding.nonce === undefined || isIdentifier(binding.nonce)) && (binding.runtimeSignature === undefined || isSignature(binding.runtimeSignature));
  return ok ? { status: "CAPTURED", value } : invalid;
};

type Discovery = Readonly<{ supported: boolean; genesis: CanonicalEvent; format: HistoryFormat }>;
const GENESIS_KEYS = ["domain", "adapterPolicyHash", "canonicalLineageId", "versions", "policyVersion", "rootRecognitionPolicy", "globalPolicySourceId", "timeSource", "finality"];

/**
 * Base-envelope check of every event plus a structural probe of the genesis; `supported` reads the declared versions. A-185.1:
 * the envelope (`continuity-query-envelope/0.2`) accepts format-2 histories too; replay judges them in full.
 */
const discover = (events: readonly unknown[]): Discovery | undefined => {
  if (events.length === 0) return undefined;
  for (const event of events) {
    if (!isRecord(event) || !hasExactKeys(event, ["id", "type", "timestamp", "data"]) || !isIdentifier(event.id) || !isProtocolString(event.type) ||
        !isU53(event.timestamp) || !isRecord(event.data)) return undefined;
  }
  const genesis = events[0] as CanonicalEvent, data = genesis.data;
  const format2 = isRecord(data.versions) && data.versions.eventSchemaVersion === TRELLIS2_FORMAT;
  const optional = format2 ? ["ownerKeys", ...FORMAT2_GENESIS_OPTIONAL_KEYS] : ["ownerKeys", "nextKeyDigests", "capacity", "migratedFrom"];
  if (genesis.type !== "DEPLOYMENT_INITIALIZED" || !hasExactKeys(data, GENESIS_KEYS, optional) || !isDomain(data.domain) ||
      !isContentHash(data.adapterPolicyHash) || !isIdentifier(data.canonicalLineageId) || !isRecord(data.versions) ||
      !Object.values(data.versions).every(item => typeof item === "string") || !isIdentifier(data.policyVersion) ||
      data.rootRecognitionPolicy !== "declared-principal-root/0.2" || !isIdentifier(data.globalPolicySourceId) ||
      data.timeSource !== "EVENT_TIMESTAMP" || data.finality !== "LOCAL_ONLY") return undefined;
  const versions = data.versions as Readonly<Record<string, string>>;
  const trellis = versions.eventSchemaVersion === "irontrellis-event/1";
  if (format2) return { supported: true, genesis, format: TRELLIS2_FORMAT };
  return { supported: trellis || canonicalEncode(versions) === LEGACY_VERSIONS_ENCODED, genesis, format: trellis ? "irontrellis-event/1" : "continuity-event/0.2" };
};

const genesisReference = (discovery: Discovery): Evidence => ({
  kind: "EVENT", eventId: discovery.genesis.id, eventType: "DEPLOYMENT_INITIALIZED", position: 0, historyHash: hashEventHistory([discovery.genesis], discovery.format),
});

const query = (input: unknown, kind: QueryKind, replay: ReplayFn, authorize: AuthorizeFn): QueryResult => {
  const captured = captureQueryInput(input, kind);
  const fail = (code: QueryFailureCode, scope?: PartialQueryScope, evidence?: readonly Evidence[]): QueryResult => finalize(failure(kind, code, scope, evidence)) as QueryResult;
  if (captured.status !== "CAPTURED") return fail(captured.status);
  const value = captured.value;
  const observedEvents = value.observedEvents as readonly unknown[];
  const evaluationEvents = (value.evaluationEvents ?? observedEvents) as readonly unknown[];
  // Both probes precede either branch's interpretation; a foreign version set is discovered before replay.
  const evaluationProbe = discover(evaluationEvents), observedProbe = discover(observedEvents);
  if (evaluationProbe === undefined || observedProbe === undefined) return fail("STATE_NOT_AUTHORITATIVE");
  const evaluationReplay = evaluationProbe.supported ? replay(evaluationEvents) : undefined;
  const observedReplay = observedProbe.supported ? replay(observedEvents) : undefined;
  if ((evaluationProbe.supported && evaluationReplay?.status !== "ACCEPTED") || (observedProbe.supported && observedReplay?.status !== "ACCEPTED")) return fail("STATE_NOT_AUTHORITATIVE");
  if (!evaluationProbe.supported || !observedProbe.supported) {
    const evidence = queryEvidence(evaluationProbe.supported ? [] : [genesisReference(evaluationProbe)], observedProbe.supported ? [] : [genesisReference(observedProbe)]);
    return fail("EVIDENCE_UNAVAILABLE", blankScope(evidence), evidence);
  }
  if (evaluationReplay?.status !== "ACCEPTED" || observedReplay?.status !== "ACCEPTED") return fail("STATE_NOT_AUTHORITATIVE");
  return runQuery(kind, evaluationReplay.state, observedReplay.state, value as QueryValue, authorize);
};

export const whyPortable = (input: unknown, replay: ReplayFn, options: QueryOptions = {}): WhyQueryResult =>
  query(input, "WHY", replay, options.authorize ?? defaultAuthorize) as WhyQueryResult;
export const responsiblePortable = (input: unknown, replay: ReplayFn, options: QueryOptions = {}): ResponsibleQueryResult =>
  query(input, "RESPONSIBLE", replay, options.authorize ?? defaultAuthorize) as ResponsibleQueryResult;
export const survivesPortable = (input: unknown, replay: ReplayFn): SurvivesQueryResult =>
  query(input, "SURVIVES", replay, defaultAuthorize) as SurvivesQueryResult;
