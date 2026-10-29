/**
 * Intent admission (spec 03 §F): the proposal state machine, admitted-intent
 * inspection and the public adapter-identity derivation. Nothing here
 * persists; the coordinators (coordinators.ts) append what is proposed.
 */
import { canonicalEncode, captureValue, CanonicalError, isIdentifier, isU53, isAmount, isContentHash, isEthereumAddress, isChainId } from "./canonical.ts";
import { replay as replayEvents, admissionControlIsCurrent as controlRecordsMatch, withProspectiveEvent } from "./replay.ts";
import { AUTHORIZATION_VERSION, ROOT_RECOGNITION_POLICY, admissionEventCollision, createRuntimeAuthorizationChallenge, hashRuntimeAuthorizationChallenge, intentProjection, sameDomain, sameIntent, stageAuthorization } from "./authority.ts";
export { intentProjection, sameDomain, sameIntent } from "./authority.ts";
import { boundedResult, createEvidenceContext, eventReference, indeterminate, intentDecisionEvidence, simpleDenial } from "./authority-evidence.ts";
import { suiteFor } from "./crypto/suites.ts";
import { ADAPTER_SUBMISSION_VERSION, type AdapterIdentity } from "./adapter-editions.ts";
import type {
  ActionRequest, AuthorizationDomain, AuthorizationProof, AuthorizationResult, CanonicalEvent, ConsequentialBinding, ContentHash,
  HexSignature, HistoryHead, IndeterminateCode, IntentAdmissionRecord, IntentConsumptionRecord, OutcomeRecord, ReplayCode, ReplayResult, ReplayState, U53,
} from "./types.ts";

export const INTENT_ADMISSION_VERSION = "continuity-intent-admission/0.2" as const;
export type ReplayFn = (events: readonly unknown[]) => ReplayResult;
type Indeterminate = Extract<AuthorizationResult, { decision: "INDETERMINATE" }>;
type Deny = Extract<AuthorizationResult, { decision: "DENY" }>;

export type IntentAdmissionInput = Readonly<{
  operationVersion: typeof INTENT_ADMISSION_VERSION; events: readonly CanonicalEvent[]; expectedHistoryHead: HistoryHead;
  admissionEventId: string; domain: AuthorizationDomain; policyVersion: string; request: ActionRequest; evaluationTime: U53; binding: ConsequentialBinding;
}>;
export type IntentAdmissionEvent = Readonly<{
  id: string; type: "TRANSACTION_INTENT_ADMITTED"; timestamp: U53;
  data: Readonly<{ intentId: string; evaluationTime: U53; expectedHistoryHead: HistoryHead; authorizationProof: AuthorizationProof; runtimeAuthorizationHash: ContentHash; runtimeSignature: HexSignature }>;
}>;
export type IntentAdmissionResult =
  | Readonly<{ operationVersion: typeof INTENT_ADMISSION_VERSION; status: "PROPOSED"; authorization: AuthorizationProof; expectedHead: HistoryHead; admissionEvent: IntentAdmissionEvent; prospectiveHead: HistoryHead }>
  | Readonly<{ operationVersion: typeof INTENT_ADMISSION_VERSION; status: "RETRY"; intentId: string; existingAdmissionEventId: string; existingAdmissionHead: HistoryHead }>
  | Readonly<{ operationVersion: typeof INTENT_ADMISSION_VERSION; status: "DENIED"; authorization: Deny }>
  /** `replayCode`: set when the proposed admission event itself was refused by the replay rules (format 2 capacity, SPEC §5.2) — the authorization code is then STATE_NOT_AUTHORITATIVE. */
  | Readonly<{ operationVersion: typeof INTENT_ADMISSION_VERSION; status: "INDETERMINATE"; authorization: Indeterminate; replayCode?: ReplayCode }>
  | Readonly<{ operationVersion: typeof INTENT_ADMISSION_VERSION; status: "CONFLICT"; expectedHead: HistoryHead; observedHead: HistoryHead }>;

const INPUT_KEYS = ["operationVersion", "events", "expectedHistoryHead", "admissionEventId", "domain", "policyVersion", "request", "evaluationTime", "binding"];
const MAX_EVENT_DATA_BYTES = 1_048_576;
const isRecord = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const closed = (v: unknown, required: readonly string[], optional: readonly string[] = []): v is Record<string, unknown> =>
  isRecord(v) && required.every((k) => Object.hasOwn(v, k)) && Object.keys(v).every((k) => required.includes(k) || optional.includes(k));
export const sameHead = (a: HistoryHead | undefined, b: HistoryHead | undefined): boolean =>
  a !== undefined && b !== undefined && a.hash === b.hash && a.position === b.position && a.canonicalTime === b.canonicalTime;
export const isDomain = (v: unknown): v is AuthorizationDomain =>
  (closed(v, ["protocol", "version", "deploymentId", "chainId", "verifyingContract"]) && v.protocol === "continuity" && v.version === "0.2" && isIdentifier(v.deploymentId) && isChainId(v.chainId) && isEthereumAddress(v.verifyingContract)) ||
  (closed(v, ["protocol", "version", "deploymentId"]) && v.protocol === "irontrellis" && (v.version === "1" || v.version === "2") && isIdentifier(v.deploymentId));
export const isHead = (v: unknown): v is HistoryHead => closed(v, ["hash", "position", "canonicalTime"]) && isContentHash(v.hash) && isU53(v.position) && isU53(v.canonicalTime);
// Format 2 (SPEC §8.2) admits `metric` in the request (G2-APPLY fix: E2's run({metric}) was refused here with INVALID_INPUT);
// a request naming a metric over a non-format-2 history is refused once the state is known (`proposeOnState`).
const requestShaped = (v: unknown): v is Record<string, unknown> => closed(v, ["actorId", "action", "resource", "claimedAt"], ["amount", "counterpartyId", "termsCommitment", "metric"]);
const requestProblem = (r: Record<string, unknown>): "INVALID_REQUEST" | "INVALID_AMOUNT" | undefined =>
  !isIdentifier(r.actorId) || !isIdentifier(r.action) || !isIdentifier(r.resource) || !isU53(r.claimedAt) ||
  (Object.hasOwn(r, "counterpartyId") && !isIdentifier(r.counterpartyId)) || (Object.hasOwn(r, "termsCommitment") && !isContentHash(r.termsCommitment))
    ? "INVALID_REQUEST" : Object.hasOwn(r, "amount") && !isAmount(r.amount) ? "INVALID_AMOUNT" : undefined;
const bindingShaped = (v: unknown, isSignature: (s: unknown) => boolean): v is ConsequentialBinding =>
  closed(v, ["runtimeSessionId", "controlEpoch", "roleId", "roleTenureId"], ["credentialKeyId", "intentId", "nonce", "runtimeSignature"]) &&
  isIdentifier(v.runtimeSessionId) && isU53(v.controlEpoch) && isIdentifier(v.roleId) && isIdentifier(v.roleTenureId) &&
  (!Object.hasOwn(v, "credentialKeyId") || isIdentifier(v.credentialKeyId)) && (!Object.hasOwn(v, "intentId") || isIdentifier(v.intentId)) &&
  (!Object.hasOwn(v, "nonce") || isIdentifier(v.nonce)) && (!Object.hasOwn(v, "runtimeSignature") || isSignature(v.runtimeSignature));
/** Spec 03 §F.6: the admitted control tuple (agent, session, epoch, role tenure) is still current at `useTime`. */
export const admissionControlIsCurrent = (state: ReplayState, intentId: string, useTime: U53): boolean => {
  const admission = state.intentAdmissions.get(intentId);
  return admission !== undefined && controlRecordsMatch(state, admission, useTime);
};

const wrap = (version: typeof INTENT_ADMISSION_VERSION, r: AuthorizationResult): IntentAdmissionResult =>
  r.decision === "DENY" ? Object.freeze({ operationVersion: version, status: "DENIED", authorization: r })
    : Object.freeze({ operationVersion: version, status: "INDETERMINATE", authorization: r as Indeterminate });
const unresolved = (code: IndeterminateCode, assurance: "SUPPLIED_SCOPE" | "REPLAY_VERIFIED" = "SUPPLIED_SCOPE"): IntentAdmissionResult =>
  wrap(INTENT_ADMISSION_VERSION, indeterminate(AUTHORIZATION_VERSION, code, assurance));
const bounded = (result: IntentAdmissionResult): IntentAdmissionResult => {
  try { return captureValue(result) as IntentAdmissionResult; } catch (error) {
    if (error instanceof CanonicalError && error.limit) return unresolved("OUTPUT_LIMIT_EXCEEDED", "REPLAY_VERIFIED");
    throw error;
  }
};

const STATE_INPUT_KEYS = INPUT_KEYS.filter((key) => key !== "events");
type AdmissionBody = Omit<IntentAdmissionInput, "events" | "operationVersion">;

/** Capture and structure (spec 03 §F.3 steps 1–2); `withEvents` selects the portable shape. */
const captureAdmission = (input: unknown, withEvents: boolean): Readonly<{ body: Record<string, unknown> }> | Readonly<{ result: IntentAdmissionResult }> => {
  const done = (result: IntentAdmissionResult) => Object.freeze({ result: bounded(result) });
  if (!isRecord(input) || !Object.hasOwn(input, "operationVersion") || typeof input.operationVersion !== "string") return done(unresolved("INVALID_INPUT"));
  if (input.operationVersion !== INTENT_ADMISSION_VERSION) return done(unresolved("UNSUPPORTED_VERSION"));
  if (!closed(input, withEvents ? INPUT_KEYS : STATE_INPUT_KEYS)) return done(unresolved("INVALID_INPUT"));
  let body: Record<string, unknown>;
  try { body = captureValue(input) as Record<string, unknown>; } catch (error) {
    if (error instanceof CanonicalError) return done(unresolved("INVALID_INPUT"));
    throw error;
  }
  if ((withEvents && !Array.isArray(body.events)) || !isDomain(body.domain) || !isHead(body.expectedHistoryHead) || !isIdentifier(body.admissionEventId) ||
      !isIdentifier(body.policyVersion) || !requestShaped(body.request)) return done(unresolved("INVALID_INPUT"));
  return Object.freeze({ body });
};

/**
 * Spec 03 §F.3: capture → structure → replay → evaluate (RETRY before the head
 * pin, then CONFLICT, INTENT_MISMATCH, the authorization itself, event-id
 * collision) → build and replay the prospective admission event → PROPOSED.
 * Replays `input.events` once; see `proposeIntentAdmissionState` for the
 * replay-free form.
 */
export const proposeIntentAdmission = (input: unknown, replayFn: ReplayFn = replayEvents): IntentAdmissionResult => {
  const captured = captureAdmission(input, true);
  if ("result" in captured) return captured.result;
  const replayed = replayFn(captured.body.events as readonly unknown[]);
  if (replayed.status !== "ACCEPTED") {
    const foreign = replayed.code === "UNSUPPORTED_VERSION" || replayed.code === "UNSUPPORTED_EVENT_SCHEMA" || replayed.code === "UNSUPPORTED_EVENT_TYPE";
    return bounded(unresolved(foreign ? "UNSUPPORTED_VERSION" : "STATE_NOT_AUTHORITATIVE"));
  }
  return proposeOnState(replayed.state, captured.body);
};

/**
 * `proposeIntentAdmission` over an already-replayed, accepted `state` (e.g. a
 * store's cached `state()`); `input` is the portable input without `events`.
 * Never replays: the prospective admission event is applied to a private fork
 * of `state` (`withProspectiveEvent`). Results equal the portable form's for
 * `events = state.events`.
 */
export const proposeIntentAdmissionState = (state: ReplayState, input: unknown): IntentAdmissionResult => {
  const captured = captureAdmission(input, false);
  return "result" in captured ? captured.result : proposeOnState(state, captured.body);
};

const proposeOnState = (state: ReplayState, body: Record<string, unknown>): IntentAdmissionResult => {
  if (!bindingShaped(body.binding, suiteFor(state.signatureScheme).isSignature)) return bounded(unresolved("INVALID_INPUT"));
  if (Object.hasOwn(body.request as Record<string, unknown>, "metric") && state.format !== "irontrellis-event/2") return bounded(unresolved("INVALID_INPUT"));
  const evaluation = evaluateAdmission(state, body as unknown as AdmissionBody);
  if (evaluation.status !== "AUTHORIZED") return bounded(evaluation.result);

  const { proof, binding, expectedHead, evaluationTime, admissionEventId } = evaluation;
  const challenge = createRuntimeAuthorizationChallenge({ domain: proof.domain, request: proof.request, evaluationTime, policyVersion: proof.policyVersion, historyHead: expectedHead, binding });
  const data = { intentId: binding.intentId, evaluationTime, expectedHistoryHead: expectedHead, authorizationProof: proof,
    runtimeAuthorizationHash: hashRuntimeAuthorizationChallenge(challenge, state.hashAlgorithm), runtimeSignature: binding.runtimeSignature };
  let admissionEvent: IntentAdmissionEvent;
  try {
    admissionEvent = Object.freeze({ id: admissionEventId, type: "TRANSACTION_INTENT_ADMITTED", timestamp: evaluationTime,
      data: captureValue(data, { maxTotalBytes: MAX_EVENT_DATA_BYTES }) as IntentAdmissionEvent["data"] });
  } catch (error) {
    if (error instanceof CanonicalError && error.limit) return unresolved("OUTPUT_LIMIT_EXCEEDED", "REPLAY_VERIFIED");
    throw error;
  }
  const prospective = withProspectiveEvent(state, admissionEvent);
  if (!prospective.ok) return bounded(Object.freeze({ ...unresolved("STATE_NOT_AUTHORITATIVE", "REPLAY_VERIFIED"), replayCode: prospective.code }));
  return bounded(Object.freeze({ operationVersion: INTENT_ADMISSION_VERSION, status: "PROPOSED", authorization: proof, expectedHead, admissionEvent, prospectiveHead: prospective.head }));
};

type Authorized = Readonly<{ status: "AUTHORIZED"; proof: AuthorizationProof; admissionEventId: string; expectedHead: HistoryHead; evaluationTime: U53;
  binding: ConsequentialBinding & Readonly<{ credentialKeyId: string; intentId: string; nonce: string; runtimeSignature: HexSignature }> }>;
const evaluateAdmission = (state: ReplayState, body: AdmissionBody): Authorized | Readonly<{ status: "RESOLVED"; result: IntentAdmissionResult }> => {
  const done = (result: IntentAdmissionResult) => Object.freeze({ status: "RESOLVED" as const, result });
  const ctx = createEvidenceContext(state), version = AUTHORIZATION_VERSION;
  const evaluationTime: unknown = body.evaluationTime;
  if (!isU53(evaluationTime) || evaluationTime < state.head.canonicalTime) {
    return done(wrap(INTENT_ADMISSION_VERSION, indeterminate(version, "CAUSAL_TIME_INVALID", "SUPPLIED_SCOPE", [eventReference(ctx, state.events.length - 1)])));
  }
  const { domain, policyVersion, expectedHistoryHead: expectedHead, request, binding } = body;
  const scopeMatches = sameDomain(domain, state.genesis.domain) && policyVersion === state.genesis.policyVersion && state.genesis.rootRecognitionPolicy === ROOT_RECOGNITION_POLICY;
  const requestFailure = requestProblem(request as unknown as Record<string, unknown>);
  const { intentId, nonce } = binding;
  const declaration = intentId === undefined ? undefined : state.intentDeclarations.get(intentId);
  const comparable = scopeMatches && requestFailure === undefined && intentId !== undefined && nonce !== undefined && declaration !== undefined;
  const matches = comparable && sameIntent(declaration.data, intentProjection(request, binding, declaration.data.adapterProfile));
  if (matches) {
    const existing = state.intentAdmissions.get(intentId);
    if (existing !== undefined) return done(Object.freeze({ operationVersion: INTENT_ADMISSION_VERSION, status: "RETRY", intentId, existingAdmissionEventId: existing.admissionEventId, existingAdmissionHead: existing.admissionHead }));
  }
  if (!sameHead(expectedHead, state.head)) return done(Object.freeze({ operationVersion: INTENT_ADMISSION_VERSION, status: "CONFLICT", expectedHead, observedHead: state.head }));
  if (comparable && !matches) {
    return done(wrap(INTENT_ADMISSION_VERSION, boundedResult(simpleDenial(version, "REPLAY_VERIFIED", "INTENT_MISMATCH", intentDecisionEvidence(ctx, request.actorId, intentId, nonce), intentId), version, "REPLAY_VERIFIED")));
  }
  const staged = stageAuthorization(state, { expectedHistoryHead: expectedHead, domain, policyVersion, rootRecognitionPolicy: ROOT_RECOGNITION_POLICY, request, evaluationTime, consequential: true, binding });
  if (staged.status !== "ALLOW_CANDIDATE") return done(wrap(INTENT_ADMISSION_VERSION, staged.result));
  if (binding.credentialKeyId === undefined || binding.intentId === undefined || binding.nonce === undefined || binding.runtimeSignature === undefined) {
    throw new TypeError("Portable admission ALLOW lost consequential binding fields.");
  }
  const admissionEventId = body.admissionEventId;
  const collision = admissionEventCollision(state, admissionEventId);
  if (collision !== undefined) return done(wrap(INTENT_ADMISSION_VERSION, boundedResult(collision, version, "REPLAY_VERIFIED")));
  const authorization = staged.finalize();
  if (authorization.decision !== "ALLOW") return done(wrap(INTENT_ADMISSION_VERSION, authorization));
  return Object.freeze({ status: "AUTHORIZED", proof: authorization.proof, admissionEventId, expectedHead, evaluationTime, binding: binding as Authorized["binding"] });
};

// ---------------------------------------------------------------- inspection and adapter identity (spec 03 §F.7, §F.8)

export type AdapterIdentityInput = Readonly<{ operationVersion: typeof ADAPTER_SUBMISSION_VERSION; domain: AuthorizationDomain; intentId: string; admissionEvent: IntentAdmissionEvent; admittedHistory: readonly CanonicalEvent[] }>;
export type AdapterIdentityResult = Readonly<AdapterIdentity & { operationVersion: typeof ADAPTER_SUBMISSION_VERSION }>;
export type AdmittedIntentInspection =
  | Readonly<{ status: "ABSENT"; head: HistoryHead }>
  | Readonly<{ status: "ADMITTED"; head: HistoryHead; admissionEvent: IntentAdmissionEvent; admissionHead: HistoryHead; adapterIdentity: AdapterIdentity; currentControl: boolean;
      consumption?: IntentConsumptionRecord; terminal?: OutcomeRecord; latestOutcome?: OutcomeRecord }>;

const acceptedState = (events: unknown, replayFn: ReplayFn): ReplayState => {
  if (!Array.isArray(events)) throw new TypeError("Portable history could not be captured.");
  const result = replayFn(events);
  if (result.status !== "ACCEPTED") throw new TypeError("Portable history is not replay-authoritative.");
  return result.state;
};

/** Reconstructs one admission and its consumption-control facts from a history (throws TypeError on bad input). Replays once. */
export const inspectAdmittedIntent = (events: unknown, intentId: unknown, useTime: unknown, replayFn: ReplayFn = replayEvents): AdmittedIntentInspection => {
  const [id, time] = inspectionArguments(intentId, useTime);
  return inspectOnState(acceptedState(events, replayFn), id, time);
};

/** `inspectAdmittedIntent` over an already-replayed, accepted `state`; never replays. */
export const inspectAdmittedIntentState = (state: ReplayState, intentId: unknown, useTime: unknown): AdmittedIntentInspection => {
  const [id, time] = inspectionArguments(intentId, useTime);
  return inspectOnState(state, id, time);
};

const inspectionArguments = (intentId: unknown, useTime: unknown): readonly [string, U53] => {
  if (!isIdentifier(intentId)) throw new TypeError("Invalid portable intent identifier.");
  if (!isU53(useTime)) throw new TypeError("Invalid authoritative use time.");
  return [intentId, useTime];
};
const inspectOnState = (state: ReplayState, intentId: string, useTime: U53): AdmittedIntentInspection => {
  if (useTime < state.head.canonicalTime) throw new TypeError("Authoritative use time precedes the observed durable head.");
  const admission = state.intentAdmissions.get(intentId);
  if (admission === undefined) return Object.freeze({ status: "ABSENT", head: state.head });
  const consumption = state.intentConsumptions.get(intentId), outcome = state.intentOutcomeStates.get(intentId);
  return Object.freeze({
    status: "ADMITTED", head: state.head, admissionEvent: state.events[admission.admissionEventPosition] as unknown as IntentAdmissionEvent,
    admissionHead: admission.admissionHead, adapterIdentity: admission.adapterIdentity as unknown as AdapterIdentity,
    currentControl: admissionControlIsCurrent(state, intentId, useTime),
    ...(consumption === undefined ? {} : { consumption }), ...(outcome?.terminal === undefined ? {} : { terminal: outcome.terminal }),
    ...(outcome === undefined ? {} : { latestOutcome: outcome.latest }),
  });
};

const IDENTITY_KEYS = ["operationVersion", "domain", "intentId", "admissionEvent"];
const captureIdentityInput = (input: unknown, keys: readonly string[]): Record<string, unknown> => {
  let value: unknown;
  try { value = captureValue(input); } catch { throw new TypeError("Adapter identity input must be a closed record."); }
  if (!closed(value, keys) || value.operationVersion !== ADAPTER_SUBMISSION_VERSION || !isIdentifier(value.intentId)) {
    throw new TypeError("Unsupported or malformed adapter identity input.");
  }
  return value;
};
const identityOf = (state: ReplayState, value: Record<string, unknown>, admission: IntentAdmissionRecord): AdapterIdentityResult => {
  const event = state.events[admission.admissionEventPosition] as CanonicalEvent;
  const proof = event.data.authorizationProof as AuthorizationProof;
  if (!isDomain(value.domain) || canonicalEncode(value.admissionEvent) !== canonicalEncode(event) || canonicalEncode(value.domain) !== canonicalEncode(proof.domain)) {
    throw new TypeError("Adapter identity does not match the exact admitted event and proof domain.");
  }
  return Object.freeze({ operationVersion: ADAPTER_SUBMISSION_VERSION, ...(admission.adapterIdentity as unknown as AdapterIdentity) });
};

/**
 * The portable part of an adapter submission: a coordinator-supplied `state`
 * (see `AdmittedTransactionSubmission` in coordinators.ts) is not identity
 * input and is dropped. Own property descriptors are copied, never read, so
 * capture still sees the other fields (and refuses accessors) as before.
 */
export const portableSubmission = (input: unknown): unknown => {
  if (!isRecord(input) || !Object.hasOwn(input, "state")) return input;
  const copy = Object.create(Object.getPrototypeOf(input) as object | null) as object;
  for (const key of Reflect.ownKeys(input)) if (key !== "state") Object.defineProperty(copy, key, Reflect.getOwnPropertyDescriptor(input, key) as PropertyDescriptor);
  return copy;
};

/** Spec 03 §F.7: the identity of an admission that is the last event of `admittedHistory` (a submission's `state`, see `portableSubmission`, is ignored). */
export const deriveAdapterIdentity = (input: unknown, replayFn: ReplayFn = replayEvents): AdapterIdentityResult => {
  const value = captureIdentityInput(portableSubmission(input), [...IDENTITY_KEYS, "admittedHistory"]);
  const state = acceptedState(value.admittedHistory, replayFn);
  const admission = state.intentAdmissions.get(value.intentId as string);
  if (admission === undefined || admission.admissionEventPosition !== state.head.position) throw new TypeError("Adapter identity requires the exact admission-inclusive prefix.");
  return identityOf(state, value, admission);
};

/**
 * `deriveAdapterIdentity` without `admittedHistory`: the admission-inclusive
 * prefix is `state.events.slice(0, admissionPosition + 1)`, so `state` may be
 * that prefix or any accepted extension of it (admission records never change
 * once written). Never replays; equals `deriveAdapterIdentity({ ...input,
 * admittedHistory: <that prefix> })`, including its refusal of a prefix that
 * ends inside a migrated legacy prefix.
 */
export const deriveAdapterIdentityState = (state: ReplayState, input: unknown): AdapterIdentityResult => {
  const value = captureIdentityInput(input, IDENTITY_KEYS);
  const admission = state.intentAdmissions.get(value.intentId as string);
  if (admission === undefined) throw new TypeError("Adapter identity requires the exact admission-inclusive prefix.");
  const migratedUntil = state.genesis.migratedFrom?.position;
  if (migratedUntil !== undefined && admission.admissionEventPosition < migratedUntil) throw new TypeError("Portable history is not replay-authoritative.");
  return identityOf(state, value, admission);
};
