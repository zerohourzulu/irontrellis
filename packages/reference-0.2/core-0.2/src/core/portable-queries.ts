/** Total Section9 query operations over captured canonical event histories. */
import {
  canonicalEncode, captureBoundedCanonicalReplayBodyIncrementally, compareProtocolStrings,
  hashCanonical, immutableProtocolValue, type CapturedCanonicalQueryOperation,
} from "./canonical.ts";
import {
  validateCapturedReplayBaseCandidate, validateCapturedGenesisVersionProbe,
  validateCapturedPortableQueryDisclosure, type AcceptedCanonicalBaseEventShape,
} from "./event-schema.ts";
import { authorizePortable } from "./portable-authority.ts";
import type { PortableAuthorizationResult } from "./portable-authority-engine.ts";
import { createPortableReplayKernel, PORTABLE_REPLAY_VERSION, type PortableReplayState, type PortableReplayEvidenceReference } from "./portable-replay.ts";
import { capturePortableQueryInput } from "./portable-query-capture.ts";
import { findPortableQueryConflict } from "./portable-query-conflicts.ts";
import { derivePortableResponsibility } from "./portable-query-responsibility.ts";
import { derivePortableSurvives } from "./portable-query-survives.ts";
import {
  PORTABLE_QUERY_VERSION, PORTABLE_QUERY_EXTERNAL_ASSUMPTIONS, PORTABLE_QUERY_ANSWER_FIELD_PATHS,
  queryEventReference, queryEvidence,
  type PortableQueryKind, type PortableQueryFailureCode, type PortableDisclosureScope,
  type PortablePartialQueryScope, type PortableQueryIdentity, type PortableQueryScope,
  type PortableNonEstablishedQueryEnvelope, type PortableWhyQueryResult, type PortableResponsibleQueryResult,
  type PortableSurvivesQueryResult, type PortableQueryAuthorization,
} from "./portable-query-codec.ts";
import { measureReferenceOutput, isReferenceOutputOverflow } from "./reference-output-budget.ts";

type Evidence = PortableReplayEvidenceReference;
type Result = PortableWhyQueryResult | PortableResponsibleQueryResult | PortableSurvivesQueryResult;
const EMPTY: readonly Evidence[] = Object.freeze([]);
const EMPTY_DISCLOSURE: PortableDisclosureScope = Object.freeze({ mode: "PUBLIC_MINIMAL", includedFields: Object.freeze([]), withheldFields: Object.freeze([]) });
const blankScope = (unavailableEvidence: readonly Evidence[] = EMPTY): PortablePartialQueryScope => ({
  headRelationship: "UNVERIFIED", freshness: "UNVERIFIED", finality: "LOCAL_ONLY",
  unavailableEvidence, withheldEvidence: EMPTY, externalAssumptions: PORTABLE_QUERY_EXTERNAL_ASSUMPTIONS,
});
const failure = (kind: PortableQueryKind, code: PortableQueryFailureCode,
  scope: PortablePartialQueryScope | PortableQueryScope = blankScope(), evidence: readonly Evidence[] = EMPTY,
): PortableNonEstablishedQueryEnvelope<PortableQueryKind> => immutableProtocolValue({
  version: PORTABLE_QUERY_VERSION, kind,
  epistemicStatus: code === "EVIDENCE_UNAVAILABLE" ? "UNAVAILABLE" : code === "EVIDENCE_DISPUTED" ? "DISPUTED" : "INDETERMINATE",
  scope: { ...scope, headRelationship: "UNVERIFIED", freshness: "UNVERIFIED" }, code, evidence,
  externalAssumptions: PORTABLE_QUERY_EXTERNAL_ASSUMPTIONS,
});
const identityFor = (evaluation: PortableReplayState, observed: PortableReplayState): PortableQueryIdentity => ({
  domain: evaluation.genesis.domain, versions: evaluation.genesis.versions,
  policyVersion: evaluation.genesis.policyVersion, rootRecognitionPolicy: evaluation.genesis.rootRecognitionPolicy,
  recognizedRootIds: [...evaluation.recognizedRoots.keys()].sort(compareProtocolStrings),
  canonicalLineageId: evaluation.genesis.canonicalLineageId,
  evaluationHead: evaluation.head, observedHead: observed.head,
});
const compactIdentity = ({recognizedRootIds: _roots, ...identity}: PortableQueryIdentity): Partial<PortableQueryIdentity> => identity;
const replay = (events: readonly unknown[]) => {
  const kernel = createPortableReplayKernel();
  const input = Object.freeze({ operationVersion: PORTABLE_REPLAY_VERSION, events });
  const capture = captureBoundedCanonicalReplayBodyIncrementally(events, input, kernel.visit);
  return capture.status === "CAPTURED" ? kernel.finish() : undefined;
};
const VERSIONS = Object.freeze({
  eventSchemaVersion: "continuity-event/0.2", receiptSchemaVersion: "continuity-receipt/0.2",
  queryEnvelopeVersion: "continuity-query-envelope/0.2", authorizationProofVersion: "continuity-authorization-proof/0.2",
  runtimeAuthorizationVersion: "continuity-runtime-authorization/0.2", administrativeAuthorizationVersion: "continuity-administrative-authorization/0.2",
  signatureScheme: "eip191-personal-sign-keccak256",
});
type Discovery = { supported: boolean; genesis: AcceptedCanonicalBaseEventShape };
const discover = (events: readonly unknown[], capture: CapturedCanonicalQueryOperation): Discovery | undefined => {
  if (events.length === 0) return undefined;
  let genesis: ReturnType<typeof validateCapturedGenesisVersionProbe> | undefined;
  for (let position = 0; position < events.length; position += 1) {
    const base = validateCapturedReplayBaseCandidate(events[position], position, capture);
    if (!base.ok) return undefined;
    if (position === 0) genesis = validateCapturedGenesisVersionProbe(base.baseEvent);
  }
  if (genesis === undefined || !genesis.ok) return undefined;
  return { supported: canonicalEncode(genesis.versions) === canonicalEncode(VERSIONS), genesis: genesis.probe };
};
const genesisReference = (genesis: AcceptedCanonicalBaseEventShape): Evidence => ({
  kind: "EVENT", eventId: genesis.id, eventType: "DEPLOYMENT_INITIALIZED", position: 0,
  historyHash: hashCanonical(["continuity-event-history/0.2", [genesis]]),
});
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
const coreFields = new Set(PORTABLE_QUERY_ANSWER_FIELD_PATHS);
for (const key of ["version", "kind", "epistemicStatus", "scope", "answer", "code", "evidence", "externalAssumptions"]) coreFields.add(key);
for (const key of PORTABLE_QUERY_ANSWER_FIELD_PATHS) coreFields.add(`answer.${key}`);
for (const key of ["domain", "versions", "policyVersion", "rootRecognitionPolicy", "recognizedRootIds", "canonicalLineageId", "evaluationHead", "observedHead", "headRelationship", "freshness", "finality", "disclosure", "unavailableEvidence", "withheldEvidence", "externalAssumptions"]) coreFields.add(`scope.${key}`);
for (const key of ["protocol", "version", "deploymentId", "chainId", "verifyingContract"]) coreFields.add(`scope.domain.${key}`);
for (const key of Object.keys(VERSIONS)) coreFields.add(`scope.versions.${key}`);
for (const head of ["evaluationHead", "observedHead"]) for (const key of ["hash", "position", "canonicalTime"]) coreFields.add(`scope.${head}.${key}`);
for (const prefix of ["scope.externalAssumptions", "externalAssumptions"]) for (const key of Object.keys(PORTABLE_QUERY_EXTERNAL_ASSUMPTIONS)) coreFields.add(`${prefix}.${key}`);
for (const key of ["mode", "includedFields", "withheldFields"]) coreFields.add(`scope.disclosure.${key}`);
for (const prefix of ["scope.unavailableEvidence", "scope.withheldEvidence", "evidence"]) {
  for (const key of ["kind", "eventId", "eventType", "position", "historyHash", "authorityId", "grantEventId", "keyId", "sessionId", "admissionEventId", "receiptContentHash", "evidenceType", "reference", "attesterId"]) coreFields.add(`${prefix}.${key}`);
}
const disclosureFor = (capture: CapturedCanonicalQueryOperation): PortableDisclosureScope | undefined => {
  if (!validateCapturedPortableQueryDisclosure(capture, capture.value.disclosure)) return undefined;
  const value = capture.value.disclosure as PortableDisclosureScope;
  if (value.withheldFields.some(path => coreFields.has(path))) return undefined;
  return value;
};
const evidenceOccurrences = (value: unknown): number => {
  let count = 0;
  const visit = (current: unknown): void => {
    if (count > 4096) return;
    if (Array.isArray(current)) { for (const child of current) visit(child); }
    else if (current !== null && typeof current === "object") {
      const record = current as Record<string, unknown>;
      if (typeof record.kind === "string" && ["EVENT", "AUTHORITY", "RUNTIME_CREDENTIAL", "RECEIPT_COMMITMENT", "EXTERNAL"].includes(record.kind)) count += 1;
      for (const child of Object.values(record)) visit(child);
    }
  };
  visit(value); return count;
};
const fits = (result: unknown): boolean => {
  if (evidenceOccurrences(result) > 4096) return false;
  try { measureReferenceOutput(result); return true; }
  catch (error) { if (isReferenceOutputOverflow(error)) return false; throw error; }
};

const query = (input: unknown, kind: PortableQueryKind): Result => {
  const captured = capturePortableQueryInput(input, kind);
  if (captured.status !== "CAPTURED") return failure(kind, captured.status) as Result;
  const capture = captured.capture, value = capture.value;
  const observedEvents = value.observedEvents as readonly unknown[];
  const evaluationEvents = (value.evaluationEvents ?? observedEvents) as readonly unknown[];
  // Both probes precede either branch's current-schema interpretation.
  const evaluationProbe = discover(evaluationEvents, capture), observedProbe = discover(observedEvents, capture);
  if (evaluationProbe === undefined || observedProbe === undefined) return failure(kind, "STATE_NOT_AUTHORITATIVE") as Result;
  const evaluationReplay = evaluationProbe.supported ? replay(evaluationEvents) : undefined;
  const observedReplay = observedProbe.supported ? replay(observedEvents) : undefined;
  if ((evaluationProbe.supported && evaluationReplay?.status !== "ACCEPTED") ||
      (observedProbe.supported && observedReplay?.status !== "ACCEPTED")) return failure(kind, "STATE_NOT_AUTHORITATIVE") as Result;
  if (!evaluationProbe.supported || !observedProbe.supported) {
    const evidence = queryEvidence(!evaluationProbe.supported ? [genesisReference(evaluationProbe.genesis)] : [],
      !observedProbe.supported ? [genesisReference(observedProbe.genesis)] : []);
    return failure(kind, "EVIDENCE_UNAVAILABLE", blankScope(evidence), evidence) as Result;
  }
  if (evaluationReplay?.status !== "ACCEPTED" || observedReplay?.status !== "ACCEPTED") return failure(kind, "STATE_NOT_AUTHORITATIVE") as Result;
  const evaluation = evaluationReplay.state, observed = observedReplay.state;
  const identity = identityFor(evaluation, observed);
  const earlyFailureScope = { ...blankScope(), ...compactIdentity(identity) };
  const relationship = observed.head.position === evaluation.head.position && observed.head.hash === evaluation.head.hash ? "SAME_HEAD" :
    observed.head.position > evaluation.head.position && observed.eventHistoryHashes[evaluation.head.position] === evaluation.head.hash ? "STRICT_EXTENSION" : "UNVERIFIED";
  const disclosure = disclosureFor(capture);
  const completeScope: PortableQueryScope = { ...blankScope(), ...identity, disclosure: disclosure ?? EMPTY_DISCLOSURE };
  const time = value.evaluationTime;
  const causalEvidence = () => queryEvidence([queryEventReference(evaluation, evaluation.head.position), queryEventReference(observed, observed.head.position)]);
  if (typeof time !== "number" || !Number.isSafeInteger(time) || Object.is(time, -0) || time < evaluation.head.canonicalTime ||
      (kind === "SURVIVES" && relationship === "UNVERIFIED" && time < observed.head.canonicalTime)) {
    return failure(kind, "CAUSAL_TIME_INVALID", earlyFailureScope, causalEvidence()) as Result;
  }
  let authorization: PortableAuthorizationResult | undefined;
  if (kind !== "SURVIVES") {
    authorization = authorizePortable({
      operationVersion: "continuity-authorization/0.2", events: evaluationEvents,
      expectedHistoryHead: evaluation.head, domain: value.authorizationDomain,
      policyVersion: evaluation.genesis.policyVersion, rootRecognitionPolicy: evaluation.genesis.rootRecognitionPolicy,
      request: value.request, evaluationTime: time, authoritative: true,
      consequential: value.consequentialBinding !== undefined,
      ...(value.consequentialBinding === undefined ? {} : { binding: value.consequentialBinding }),
    });
    if (authorization.decision === "INDETERMINATE" && authorization.code === "CAUSAL_TIME_INVALID") {
      return failure(kind, "CAUSAL_TIME_INVALID", earlyFailureScope, causalEvidence()) as Result;
    }
    if (authorization.decision === "INDETERMINATE" && ["INVALID_INPUT", "UNSUPPORTED_VERSION", "STATE_NOT_AUTHORITATIVE"].includes(authorization.code)) {
      return failure(kind, authorization.code) as Result;
    }
  }
  if (disclosure === undefined) return failure(kind, "DISCLOSURE_INVALID", earlyFailureScope) as Result;
  const outputFailure = () => failure(kind, "OUTPUT_LIMIT_EXCEEDED", { ...blankScope(), ...compactIdentity(identity) }) as Result;
  let result: Result;
  if (relationship === "UNVERIFIED") {
    const conflict = findPortableQueryConflict(evaluation, observed, kind === "SURVIVES"
      ? { kind, targetAgentId: value.targetAgentId as string, evaluationTime: time }
      : { kind, ...(value.consequentialBinding === undefined ? {} : { binding: value.consequentialBinding as import("./portable-authority-engine.ts").PortableConsequentialBinding }) });
    if (conflict !== undefined) result = failure(kind, "EVIDENCE_DISPUTED", completeScope, conflict) as Result;
    else {
      let position = 0;
      while (position < Math.min(evaluation.events.length, observed.events.length) && canonicalEncode(evaluation.events[position]) === canonicalEncode(observed.events[position])) position += 1;
      const evidence = position < Math.min(evaluation.events.length, observed.events.length)
        ? queryEvidence([queryEventReference(evaluation, position), queryEventReference(observed, position)])
        : causalEvidence();
      result = failure(kind, "HISTORY_RELATION_UNVERIFIED", completeScope, evidence) as Result;
    }
  } else if (authorization?.decision === "INDETERMINATE") {
    // Required Core proof/event dependencies are inline or replay-validated;
    // current engine has no standalone unavailable/disputed dependency branch.
    result = failure(kind, authorization.code === "EVIDENCE_DISPUTED" ? "HISTORY_RELATION_UNVERIFIED" : authorization.code, completeScope) as Result;
    if (authorization.code === "OUTPUT_LIMIT_EXCEEDED") return outputFailure();
  } else {
    let answer: unknown, includedFields: readonly string[], overflow = false;
    if (kind === "SURVIVES") {
      const projection = derivePortableSurvives(evaluation, value.targetAgentId as string, time);
      answer = projection.answer; includedFields = projection.includedFields; overflow = projection.outputLimitExceeded;
    } else if (kind === "RESPONSIBLE") {
      const projection = derivePortableResponsibility(evaluation, observed, authorization! as PortableQueryAuthorization);
      answer = projection.answer; includedFields = projection.includedFields; overflow = projection.outputLimitExceeded;
    } else {
      answer = { authorization: authorization as PortableQueryAuthorization, presentConsequentialUse:
        authorization?.decision === "ALLOW" && authorization.consequential && relationship === "SAME_HEAD" };
      includedFields = answerFieldPaths(answer);
    }
    const selected = new Set(disclosure.includedFields);
    if (includedFields.some(path => !selected.has(path))) return failure(kind, "DISCLOSURE_INVALID", earlyFailureScope) as Result;
    if (overflow || answer === undefined) return outputFailure();
    result = { version: PORTABLE_QUERY_VERSION, kind, epistemicStatus: "ESTABLISHED",
      scope: { ...completeScope, headRelationship: relationship, freshness: relationship === "SAME_HEAD" ? "CURRENT" : "AT_EVALUATION" }, answer } as Result;
  }
  return identity.recognizedRootIds.length > 256 || !fits(result) ? outputFailure() : immutableProtocolValue(result);
};

export const whyPortable = (input: unknown): PortableWhyQueryResult => query(input, "WHY") as PortableWhyQueryResult;
export const responsiblePortable = (input: unknown): PortableResponsibleQueryResult => query(input, "RESPONSIBLE") as PortableResponsibleQueryResult;
export const survivesPortable = (input: unknown): PortableSurvivesQueryResult => query(input, "SURVIVES") as PortableSurvivesQueryResult;
