/**
 * Durable coordinators (spec 03 §J): the only components that turn a proposal
 * into an appended event. Every step re-reads the store under its writer lock
 * and re-derives its facts from replay: the store's cached `state()` when it
 * has one (a `HistoryStore`), otherwise one replay of `readAll()` per step;
 * prospective events are checked on a private fork (`withProspectiveEvent`),
 * never by replaying the history again. The only process-local state is the
 * WeakMap-held preparation and invocation capability objects, which cannot be
 * re-minted after a restart (crash recovery goes through `reconcile`).
 */
import { captureValue } from "./canonical.ts";
import { hashCanonical } from "./hash.ts";
import { replay as replayEvents, withProspectiveEvent } from "./replay.ts";
import { EngineError } from "./errors.ts";
import {
  ADAPTER_NO_EFFECT_VERSION, ADAPTER_SUBMISSION_VERSION, SIMULATED_ADAPTER_ID, adapterAcknowledgmentEvidence, adapterAcknowledgmentTransactionReference, adapterNoEffectEvidence,
  hashAlgorithmForDomain, knownAdapterAcknowledgmentVersion, knownAdapterProfile, validateAdapterAcknowledgment, validateAdapterNoEffect,
  type AdapterAcknowledgment, type AdapterExternalEvidence, type AdapterNoEffect,
} from "./adapter-editions.ts";
import {
  deriveAdapterIdentity, deriveAdapterIdentityState, inspectAdmittedIntentState, portableSubmission, proposeIntentAdmission, proposeIntentAdmissionState, sameHead, INTENT_ADMISSION_VERSION,
  type AdapterIdentityInput, type AdapterIdentityResult, type AdmittedIntentInspection, type IntentAdmissionEvent, type IntentAdmissionResult, type ReplayFn,
} from "./admission.ts";
import { proposeReceiptRecord, proposeReceiptRecordState, RECEIPT_RECORD_ADMISSION_VERSION, type ReceiptRecordAdmissionResult, type ReceiptRecordProposal } from "./receipts.ts";
import type { AdapterProfile, AuthorizationDomain, AuthorizationProof, CanonicalEvent, ContentHash, HexSignature, HistoryHead, ReplayState } from "./types.ts";
import { TRELLIS2_FORMAT } from "./events.ts";
import { lifecycleAuthorizationHash, type SessionBinding } from "./session-auth.ts";
import { assertSessionWriteTime, isSessionWriteTimeRefusal } from "./session-write-checks.ts";

// ---------------------------------------------------------------- store contract (spec 03 §J.1)
export interface EventStoreWriter {
  readAll(): readonly CanonicalEvent[];
  /** Appends iff the store's head equals `expectedHead`; otherwise throws a `StoreConflictError`. Returns the new head. */
  appendAtExpectedHead(event: CanonicalEvent, expectedHead: HistoryHead): HistoryHead;
}
export interface EventStore extends EventStoreWriter {
  /** Runs `callback` under the store's cooperative writer lock; writer methods expire with the callback. */
  withExclusiveWriter<T>(callback: (writer: EventStoreWriter) => T): T;
  /**
   * Optional: the store's current replayed state (a `HistoryStore` keeps it
   * cached and extends it on append). When present — and no custom `replay`
   * is configured — the coordinators read it instead of `readAll()` + replay.
   */
  state?(): ReplayState;
}
/** Thrown by a store when the expected head is not the observed one (`observedHead` absent for an empty store). */
export class StoreConflictError extends EngineError {
  readonly observedHead: HistoryHead | undefined;
  constructor(observedHead?: HistoryHead) {
    super("STORE_CONFLICT", "The durable history head differs from the expected head.");
    this.name = "StoreConflictError";
    this.observedHead = observedHead;
  }
}
const isStoreConflict = (error: unknown): error is Readonly<{ observedHead?: unknown }> =>
  error instanceof Error && (error as { code?: unknown }).code === "STORE_CONFLICT";

// ---------------------------------------------------------------- adapter contract (spec 03 §J.2)
/**
 * What an adapter's `submit` / `reconcile` receives: the portable submission
 * (spec 03 §J.2) plus, when a coordinator of this process made it, `state` —
 * a non-enumerable, read-only reference to the replayed durable state that
 * contains the admission (the store's cached `state()`, or an accepted
 * extension of the admission-inclusive prefix). Adapters derive the identity
 * from it with `admittedSubmissionIdentity` (no replay of `admittedHistory`,
 * no history-length bound); portable adapters may ignore it, and
 * `deriveAdapterIdentity` does. Treat it as read-only and do not retain it.
 */
export type AdmittedTransactionSubmission = AdapterIdentityInput & Readonly<{ state?: ReplayState }>;
/** The portable fields an adapter needs besides the identity (`admittedHistory` is left out). */
export type AdmittedSubmissionFields = Omit<AdapterIdentityInput, "admittedHistory">;
export type AdapterSubmissionResult =
  | Readonly<{ status: "SUBMITTED"; idempotencyKey: ContentHash; submissionFingerprint: ContentHash; evidence: AdapterExternalEvidence; acknowledgment: AdapterAcknowledgment }>
  | Readonly<{ status: "RETRY"; idempotencyKey: ContentHash; submissionFingerprint: ContentHash; retainedEvidence: AdapterExternalEvidence; acknowledgment: AdapterAcknowledgment }>
  | Readonly<{ status: "RETRY"; idempotencyKey: ContentHash; submissionFingerprint: ContentHash; retainedEvidence: AdapterExternalEvidence; noEffect: AdapterNoEffect }>
  | Readonly<{ status: "FAILED"; idempotencyKey: ContentHash; submissionFingerprint: ContentHash; evidence: AdapterExternalEvidence; noEffect: AdapterNoEffect }>
  | Readonly<{ status: "OUTCOME_UNKNOWN"; idempotencyKey: ContentHash; submissionFingerprint: ContentHash; latestEvidence?: AdapterExternalEvidence }>
  | Readonly<{ status: "IDEMPOTENCY_FINGERPRINT_CONFLICT"; idempotencyKey: ContentHash; retainedFingerprint: ContentHash; suppliedFingerprint: ContentHash }>;
export interface TransactionAdapter {
  /** MUST be an own data property (no getter). */
  readonly adapterProfile: AdapterProfile;
  submit(input: AdmittedTransactionSubmission): Promise<AdapterSubmissionResult>;
  reconcile(input: AdmittedTransactionSubmission): AdapterSubmissionResult | Promise<AdapterSubmissionResult>;
}

// ---------------------------------------------------------------- results (spec 03 §J.3)
export type PreparedDurableAdmission = Readonly<{ proposal: IntentAdmissionResult }>;
export type AdmittedInvocationCapability = Readonly<{ intentId: string; admissionEventId: string; admissionHead: HistoryHead }>;
/** Builder G66-B1: recover only the process-local right to try an existing admission. */
export type ResumeInvocationRequest = Readonly<{
  intentId: string; admissionEventId: string; admissionHead: HistoryHead;
  submissionIdentity: Readonly<{ idempotencyKey: ContentHash; submissionFingerprint: ContentHash }>;
  /** Synchronous, read-only attempt-absence check; evaluated under the writer lock. */
  noDispatchStart: () => boolean;
}>;
export type ResumeInvocationResult =
  | Readonly<{ status: "RESUMABLE"; capability: AdmittedInvocationCapability }>
  | Readonly<{ status: "NOT_RESUMABLE"; reason: "ADMISSION_MISMATCH" | "HISTORY_DIVERGED" | "INTENT_NOT_OPEN" | "ADAPTER_PROFILE_CHANGED" | "DISPATCH_STARTED" | "UNAVAILABLE" }>;
export type AdmittedResult = Readonly<{ operationVersion: typeof INTENT_ADMISSION_VERSION; status: "ADMITTED"; authorization: AuthorizationProof; admissionEvent: IntentAdmissionEvent; newHead: HistoryHead }>;
export type DurableAdmissionCommitResult =
  | Readonly<{ status: "INVALID_PREPARATION"; reason: string }>
  /** `code`: the replay code when the admission event itself was refused before the append (e.g. a format-2 capacity verdict, SPEC §5.2). */
  | Readonly<{ status: "UNAVAILABLE"; reason: string; admissionMayHavePersisted: boolean; code?: string }>
  | Readonly<{ status: "NOT_ADMITTED"; result: Exclude<IntentAdmissionResult, { status: "PROPOSED" }> }>
  | Readonly<{ status: "ADMITTED"; result: AdmittedResult; capability: AdmittedInvocationCapability }>;
export type InvocationResult =
  | Readonly<{ status: "NOT_INVOKED"; reason: string }>
  | Readonly<{ status: "OUTCOME_UNKNOWN"; reason: string; idempotencyKey?: string; submissionFingerprint?: string;
      /** Set when the disposition record was refused before signing (r5.2 §10.1.1 item 7's not-recorded form, as run()'s refusal report). */
      recorded?: false; notRecorded?: Readonly<{ reason: string; message?: string }> }>
  | Readonly<{ status: "TERMINAL"; head: HistoryHead; evidence: Readonly<Record<string, unknown>> }>
  | Readonly<{ status: "IDEMPOTENCY_FINGERPRINT_CONFLICT"; disposition: Extract<AdapterSubmissionResult, { status: "IDEMPOTENCY_FINGERPRINT_CONFLICT" }> }>
  | Readonly<{ status: "SUBMITTED" | "FAILED" | "RETRY"; disposition: Extract<AdapterSubmissionResult, { status: "SUBMITTED" | "FAILED" | "RETRY" }>; recorded: true; head: HistoryHead }>;
export type DurableAdmissionResult = Readonly<{ admission: DurableAdmissionCommitResult; invocation?: InvocationResult }>;

type Admitted = Extract<AdmittedIntentInspection, { status: "ADMITTED" }>;
type InvocationRecord = Readonly<{ submission: AdmittedTransactionSubmission; identity: AdapterIdentityResult; admissionHead: HistoryHead }>;
type Rec = Record<string, unknown>;
const PREPARATION_REQUIRED = "An unused preparation from this coordinator is required.";
const CAPABILITY_REQUIRED = "An unused invocation capability is required.";
const isRecord = (v: unknown): v is Rec => v !== null && typeof v === "object" && !Array.isArray(v);
const exactKeys = (v: Rec, required: readonly string[], optional: readonly string[] = []): boolean =>
  required.every((k) => Object.hasOwn(v, k)) && Object.keys(v).every((k) => required.includes(k) || optional.includes(k));
const hashOf = (value: unknown): ContentHash => hashCanonical(value, "sha256");
/** Submissions minted by a coordinator of this process: only their `state` is trusted by `admittedSubmissionIdentity`. */
const minted = new WeakSet<object>();
/** The portable submission of an observed admission; with `state`, the attested form handed to the adapter. */
const submissionFor = (events: readonly CanonicalEvent[], observed: Admitted, state?: ReplayState): AdmittedTransactionSubmission => {
  const submission = {
    operationVersion: ADAPTER_SUBMISSION_VERSION, domain: observed.admissionEvent.data.authorizationProof.domain, intentId: observed.admissionEvent.data.intentId,
    admissionEvent: observed.admissionEvent, admittedHistory: events.slice(0, observed.admissionHead.position + 1),
  } as const;
  return state === undefined ? Object.freeze(submission) : attested(submission, state);
};
/** `submission` with a non-enumerable `state` (invisible to spreads, JSON and deep equality), registered as coordinator-made. */
const attested = (submission: AdapterIdentityInput, state: ReplayState): AdmittedTransactionSubmission => {
  const copy = { operationVersion: submission.operationVersion, domain: submission.domain, intentId: submission.intentId, admissionEvent: submission.admissionEvent, admittedHistory: submission.admittedHistory };
  Object.defineProperty(copy, "state", { value: state, enumerable: false, writable: false, configurable: false });
  Object.freeze(copy);
  minted.add(copy);
  return copy;
};
/**
 * The adapter side of `AdmittedTransactionSubmission.state`: the admitted
 * identity of `input` and its captured portable fields. A submission a
 * coordinator of this process made is resolved against its `state`
 * (`deriveAdapterIdentityState`: no replay, no bound on the history length);
 * any other input (including a caller-made `state`, which is never trusted)
 * takes the portable path, one replay of `admittedHistory`
 * (`deriveAdapterIdentity`). Throws TypeError like `deriveAdapterIdentity`.
 */
export const admittedSubmissionIdentity = (input: unknown): Readonly<{ submission: AdmittedSubmissionFields; identity: AdapterIdentityResult }> => {
  if (input !== null && typeof input === "object" && minted.has(input)) {
    const trusted = input as AdmittedTransactionSubmission & Readonly<{ state: ReplayState }>;
    let submission: AdmittedSubmissionFields;
    try {
      submission = captureValue({ operationVersion: trusted.operationVersion, domain: trusted.domain, intentId: trusted.intentId, admissionEvent: trusted.admissionEvent }) as AdmittedSubmissionFields;
    } catch { throw new TypeError("Adapter identity input must be a closed record."); }
    return Object.freeze({ submission, identity: deriveAdapterIdentityState(trusted.state, submission) });
  }
  let stable: AdapterIdentityInput;
  try { stable = captureValue(portableSubmission(input)) as AdapterIdentityInput; } catch { throw new TypeError("Adapter identity input must be a closed record."); }
  return Object.freeze({ submission: stable, identity: deriveAdapterIdentity(stable) });
};
/** The adapter identity of an observed admission, read from the state that contains it (never a replay of its prefix). */
const identityFor = (state: ReplayState, observed: Admitted): AdapterIdentityResult => deriveAdapterIdentityState(state, {
  operationVersion: ADAPTER_SUBMISSION_VERSION, domain: observed.admissionEvent.data.authorizationProof.domain, intentId: observed.admissionEvent.data.intentId, admissionEvent: observed.admissionEvent,
});
/**
 * The durable history as a replayed state: the store's own cached `state()`
 * when it has one and no custom replay is configured, otherwise one replay of
 * `readAll()`. Throws when the history is empty or not replay-authoritative.
 */
const currentState = (store: EventStore, writer: EventStoreWriter, replayFn: ReplayFn | undefined): ReplayState => {
  if (replayFn === undefined && typeof store.state === "function") return store.state();
  const events = writer.readAll();
  const replayed = events.length === 0 ? undefined : (replayFn ?? replayEvents)(events);
  if (replayed?.status !== "ACCEPTED") throw new Error("Durable history is unavailable.");
  return replayed.state;
};
const unknownOutcome = (reason: string, identity?: AdapterIdentityResult): InvocationResult =>
  Object.freeze({ status: "OUTCOME_UNKNOWN", reason, ...(identity === undefined ? {} : { idempotencyKey: identity.idempotencyKey, submissionFingerprint: identity.submissionFingerprint }) });

/** Adapter data is captured once, from own data descriptors, bounded to 16 KiB; arrays and accessors are refused (spec 03 §J.4). */
const captureAdapterData = (input: unknown, maxTotalBytes = 16_384): unknown => {
  let nodes = 0;
  const active = new WeakSet<object>();
  const copy = (value: unknown, depth: number): unknown => {
    if (++nodes > 256 || depth > 12) throw new TypeError("Adapter data exceeds structural limits.");
    if (value === null || value === undefined || typeof value === "boolean" || typeof value === "number") return value;
    if (typeof value === "string") { if (value.length > 4096) throw new TypeError("Adapter string exceeds finite limits."); return value; }
    if (typeof value !== "object" || Array.isArray(value) || active.has(value)) throw new TypeError("Adapter data must be acyclic non-proxy records.");
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== null && prototype !== Object.prototype) throw new TypeError("Adapter record prototype is unsupported.");
    const keys = Reflect.ownKeys(value);
    if (keys.length > 32 || keys.some((k) => typeof k !== "string")) throw new TypeError("Adapter record keys are unsupported.");
    active.add(value);
    const result: Rec = {};
    for (const key of keys as string[]) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (descriptor === undefined || !Object.hasOwn(descriptor, "value")) throw new TypeError("Adapter accessors are not data.");
      result[key] = copy(descriptor.value, depth + 1);
    }
    active.delete(value);
    return Object.freeze(result);
  };
  const captured = copy(input, 0);
  captureValue(captured, { maxTotalBytes });
  return captured;
};
const configuredProfile = (adapter: TransactionAdapter): AdapterProfile => {
  const descriptor = Object.getOwnPropertyDescriptor(adapter, "adapterProfile");
  if (descriptor === undefined || !Object.hasOwn(descriptor, "value")) throw new TypeError("Adapter requires an own data profile.");
  const profile = captureAdapterData(descriptor.value, 1024);
  if (!isRecord(profile) || !exactKeys(profile, ["profileId", "profileVersion", "descriptorHash"]) || typeof profile.profileId !== "string") throw new TypeError("Adapter profile is malformed.");
  const approved = knownAdapterProfile(profile.profileId);
  if (hashOf(profile) !== hashOf(approved)) throw new TypeError("Adapter profile is not approved.");
  return approved;
};
const evidenceEquals = (value: unknown, expected: AdapterExternalEvidence): boolean =>
  isRecord(value) && exactKeys(value, ["kind", "evidenceType", "reference", "attesterId"]) && hashOf(value) === hashOf(expected);
const acknowledgmentMatches = (v: Rec, evidence: unknown, identity: AdapterIdentityResult): boolean =>
  validateAdapterAcknowledgment(v.acknowledgment, identity) && evidenceEquals(evidence, adapterAcknowledgmentEvidence(identity, v.acknowledgment));
const noEffectMatches = (v: Rec, evidence: unknown, identity: AdapterIdentityResult): boolean =>
  validateAdapterNoEffect(v.noEffect, identity) && evidenceEquals(evidence, adapterNoEffectEvidence(identity, v.noEffect));
const validLatestEvidence = (value: unknown, identity: AdapterIdentityResult): boolean =>
  isRecord(value) && exactKeys(value, ["kind", "evidenceType", "reference", "attesterId"]) && value.kind === "EXTERNAL" && value.attesterId === identity.adapterProfile.profileId &&
  typeof value.reference === "string" && /^0x[0-9a-f]{64}$/.test(value.reference) &&
  (value.evidenceType === knownAdapterAcknowledgmentVersion(identity.adapterProfile) || (identity.adapterProfile.profileId === SIMULATED_ADAPTER_ID && value.evidenceType === ADAPTER_NO_EFFECT_VERSION));
/** Validates an adapter response against the admitted identity; throws on any deviation. */
export const captureDisposition = (input: unknown, identity: AdapterIdentityResult): AdapterSubmissionResult => {
  const v = captureAdapterData(input);
  if (!isRecord(v)) throw new TypeError("Malformed adapter response.");
  if (v.idempotencyKey !== identity.idempotencyKey) throw new TypeError("Adapter key mismatch.");
  if (v.status === "IDEMPOTENCY_FINGERPRINT_CONFLICT") {
    if (!exactKeys(v, ["status", "idempotencyKey", "retainedFingerprint", "suppliedFingerprint"]) || v.suppliedFingerprint !== identity.submissionFingerprint ||
        typeof v.retainedFingerprint !== "string" || !/^0x[0-9a-f]{64}$/.test(v.retainedFingerprint) || v.retainedFingerprint === v.suppliedFingerprint) throw new TypeError("Malformed fingerprint conflict.");
    return v as unknown as AdapterSubmissionResult;
  }
  if (v.submissionFingerprint !== identity.submissionFingerprint) throw new TypeError("Adapter fingerprint mismatch.");
  const common = ["status", "idempotencyKey", "submissionFingerprint"];
  switch (v.status) {
    case "SUBMITTED": if (!exactKeys(v, [...common, "evidence", "acknowledgment"]) || !acknowledgmentMatches(v, v.evidence, identity)) throw new TypeError("Malformed adapter acknowledgment."); break;
    case "FAILED": if (!exactKeys(v, [...common, "evidence", "noEffect"]) || !noEffectMatches(v, v.evidence, identity)) throw new TypeError("Malformed simulator no-effect evidence."); break;
    case "RETRY": {
      const ack = exactKeys(v, [...common, "retainedEvidence", "acknowledgment"]) && acknowledgmentMatches(v, v.retainedEvidence, identity);
      const noEffect = exactKeys(v, [...common, "retainedEvidence", "noEffect"]) && noEffectMatches(v, v.retainedEvidence, identity);
      if (!ack && !noEffect) throw new TypeError("Malformed retained typed evidence.");
      break;
    }
    case "OUTCOME_UNKNOWN":
      if (!exactKeys(v, common, ["latestEvidence"]) || (Object.hasOwn(v, "latestEvidence") && !validLatestEvidence(v.latestEvidence, identity))) throw new TypeError("Malformed uncertain outcome.");
      break;
    default: throw new TypeError("Unknown adapter disposition.");
  }
  return v as unknown as AdapterSubmissionResult;
};

/**
 * The reference integration: store, adapter and clock are approved
 * configuration; only data and identity tokens enter the public methods, and
 * replay facts alone never issue a first-invocation capability.
 */
/** A-51: a session that signs format-2 lifecycle records (consumption, outcome) over `irontrellis-lifecycle-authorization/2`. */
export type RecordSigner = Readonly<{ binding: SessionBinding; signHash: (hash: ContentHash) => Promise<HexSignature> }>;
export class DurableAdmissionCoordinator {
  readonly store: EventStore;
  readonly adapter: TransactionAdapter;
  readonly #now: () => number;
  /** A configured replay function; `undefined` means the engine's own (and permits the store's cached state). */
  readonly #replay: ReplayFn | undefined;
  readonly #adapterProfile: AdapterProfile;
  readonly #prepared = new WeakMap<object, IntentAdmissionResult>();
  readonly #invocations = new WeakMap<object, InvocationRecord>();

  /** A-51 (format 2): the session that signs the consumption / no-effect outcome this coordinator records (the intent's actor). */
  readonly #recordSigner: RecordSigner | undefined;

  constructor(store: EventStore, adapter: TransactionAdapter, options: Readonly<{ authoritativeNow: () => number; replay?: ReplayFn; recordSigner?: RecordSigner }>) {
    this.store = store;
    this.adapter = adapter;
    this.#adapterProfile = configuredProfile(adapter);
    Object.defineProperty(this, "adapter", { value: adapter, writable: false, configurable: false, enumerable: true });
    this.#now = options.authoritativeNow;
    this.#replay = options.replay;
    this.#recordSigner = options.recordSigner;
  }

  #state(writer: EventStoreWriter): ReplayState { return currentState(this.store, writer, this.#replay); }
  #assertAdapterProfile(identity?: AdapterIdentityResult): void {
    const actual = configuredProfile(this.adapter);
    if (hashOf(actual) !== hashOf(this.#adapterProfile) || (identity !== undefined && hashOf(identity.adapterProfile) !== hashOf(this.#adapterProfile))) {
      throw new TypeError("Configured adapter profile differs from the original admitted selection.");
    }
  }

  /** The proposal is computed from `input.events`, never from the store (spec 03 trap 16). */
  prepare(input: unknown): PreparedDurableAdmission {
    return this.#register(proposeIntentAdmission(input, this.#replay ?? replayEvents));
  }
  /**
   * `prepare` over a caller-supplied replayed `state` (typically the store's
   * `state()`) and the admission input without `events`; never replays.
   */
  prepareState(state: ReplayState, input: unknown): PreparedDurableAdmission {
    return this.#register(proposeIntentAdmissionState(state, input));
  }
  #register(proposal: IntentAdmissionResult): PreparedDurableAdmission {
    const prepared = Object.freeze({ proposal });
    this.#prepared.set(prepared, proposal);
    return prepared;
  }

  admit(prepared: unknown): DurableAdmissionCommitResult {
    const proposal = prepared !== null && typeof prepared === "object" ? this.#prepared.get(prepared) : undefined;
    if (proposal === undefined) return Object.freeze({ status: "INVALID_PREPARATION", reason: PREPARATION_REQUIRED });
    this.#prepared.delete(prepared as object);
    try { this.#assertAdapterProfile(); } catch { return Object.freeze({ status: "UNAVAILABLE", reason: "The configured adapter profile changed.", admissionMayHavePersisted: false }); }
    if (proposal.status !== "PROPOSED") {
      if (proposal.status === "RETRY") {
        try {
          const matches = this.store.withExclusiveWriter((writer) => {
            const state = this.#state(writer);
            const current = inspectAdmittedIntentState(state, proposal.intentId, state.head.canonicalTime);
            if (current.status === "ADMITTED") this.#assertAdapterProfile(identityFor(state, current));
            return current.status === "ADMITTED" && current.admissionEvent.id === proposal.existingAdmissionEventId && sameHead(current.admissionHead, proposal.existingAdmissionHead);
          });
          if (!matches) throw new Error("Supplied retry is absent from this durable history.");
        } catch { return Object.freeze({ status: "UNAVAILABLE", reason: "The supplied retry does not establish this store's original admission.", admissionMayHavePersisted: false }); }
      }
      return Object.freeze({ status: "NOT_ADMITTED", result: proposal });
    }
    let appendStarted = false;
    try {
      const record = this.store.withExclusiveWriter((writer) => {
        // An empty or unreplayable history throws here, before any append (UNAVAILABLE, nothing persisted).
        const state = this.#state(writer), observedHead = state.head;
        if (!sameHead(observedHead, proposal.expectedHead)) throw new StoreConflictError(observedHead);
        // The admission applied to a private fork of the durable state: nothing is replayed, the store is untouched.
        const prospective = withProspectiveEvent(state, proposal.admissionEvent);
        if (!prospective.ok) throw Object.assign(new Error(`Proposed admission could not be reconstructed (${prospective.code}: ${prospective.reason}).`), { replayCode: prospective.code });
        const observed = inspectAdmittedIntentState(prospective.state, proposal.admissionEvent.data.intentId, proposal.admissionEvent.timestamp);
        if (observed.status !== "ADMITTED") throw new Error("Proposed admission could not be reconstructed.");
        const submission = submissionFor(prospective.state.events, observed), identity = identityFor(prospective.state, observed);
        this.#assertAdapterProfile(identity);
        appendStarted = true;
        const newHead = writer.appendAtExpectedHead(proposal.admissionEvent as unknown as CanonicalEvent, proposal.expectedHead);
        if (!sameHead(newHead, proposal.prospectiveHead)) throw new Error("Durable append returned a different head.");
        this.#assertAdapterProfile(identity);
        return Object.freeze({ submission, identity, admissionHead: newHead });
      });
      const capability: AdmittedInvocationCapability = Object.freeze({ intentId: proposal.admissionEvent.data.intentId, admissionEventId: proposal.admissionEvent.id, admissionHead: record.admissionHead });
      this.#invocations.set(capability, record);
      return Object.freeze({ status: "ADMITTED", capability, result: Object.freeze({
        operationVersion: INTENT_ADMISSION_VERSION, status: "ADMITTED", authorization: proposal.authorization, admissionEvent: proposal.admissionEvent, newHead: record.admissionHead }) });
    } catch (error) {
      if (!appendStarted && isStoreConflict(error) && error.observedHead !== undefined) {
        return Object.freeze({ status: "NOT_ADMITTED", result: Object.freeze({ operationVersion: INTENT_ADMISSION_VERSION, status: "CONFLICT", expectedHead: proposal.expectedHead, observedHead: error.observedHead as HistoryHead }) });
      }
      const replayCode = (error as { replayCode?: unknown } | null)?.replayCode ?? (error instanceof EngineError ? error.code : undefined);
      return Object.freeze({ status: "UNAVAILABLE", reason: "Durable admission could not be established; reconcile before any retry.", admissionMayHavePersisted: appendStarted, ...(typeof replayCode === "string" ? { code: replayCode } : {}) });
    }
  }

  /**
   * Builder G66-B1 / A-163: restore an unused invocation capability after a
   * restart without appending, submitting or changing the original admission.
   * The gateway still owns the durable attempt fence and current-access checks.
   */
  resumeInvocation(request: ResumeInvocationRequest): ResumeInvocationResult {
    const refused = (reason: Extract<ResumeInvocationResult, { status: "NOT_RESUMABLE" }>['reason']): ResumeInvocationResult =>
      Object.freeze({ status: "NOT_RESUMABLE", reason });
    try {
      return this.store.withExclusiveWriter((writer): ResumeInvocationResult => {
        // 1. Profile, then the current replay-authoritative state, under one lock.
        try { this.#assertAdapterProfile(); } catch { return refused("ADAPTER_PROFILE_CHANGED"); }
        const state = this.#state(writer);
        // Capture own data once; do not invoke accessors or retain mutable caller data.
        let stable: Omit<ResumeInvocationRequest, "noDispatchStart">, noDispatchStart: () => boolean;
        try {
          if (!isRecord(request) || ![Object.prototype, null].includes(Object.getPrototypeOf(request))) return refused("ADMISSION_MISMATCH");
          const names = ["intentId", "admissionEventId", "admissionHead", "submissionIdentity", "noDispatchStart"];
          const keys = Reflect.ownKeys(request);
          if (keys.length !== names.length || keys.some((key) => typeof key !== "string" || !names.includes(key))) return refused("ADMISSION_MISMATCH");
          const data: Rec = {};
          for (const key of names) {
            const descriptor = Object.getOwnPropertyDescriptor(request, key);
            if (descriptor === undefined || !Object.hasOwn(descriptor, "value")) return refused("ADMISSION_MISMATCH");
            data[key] = descriptor.value;
          }
          if (typeof data.noDispatchStart !== "function") return refused("ADMISSION_MISMATCH");
          noDispatchStart = data.noDispatchStart as () => boolean;
          delete data.noDispatchStart;
          const captured = captureAdapterData(data) as Rec;
          if (typeof captured.intentId !== "string" || typeof captured.admissionEventId !== "string" ||
              !isRecord(captured.admissionHead) || !exactKeys(captured.admissionHead, ["hash", "position", "canonicalTime"]) ||
              !isRecord(captured.submissionIdentity) || !exactKeys(captured.submissionIdentity, ["idempotencyKey", "submissionFingerprint"])) return refused("ADMISSION_MISMATCH");
          stable = captured as unknown as typeof stable;
        } catch { return refused("ADMISSION_MISMATCH"); }
        // 2. Resolve the original admission and compare all three head fields.
        let current: AdmittedIntentInspection;
        try { current = inspectAdmittedIntentState(state, stable.intentId, state.head.canonicalTime); }
        catch { return refused("ADMISSION_MISMATCH"); }
        if (current.status !== "ADMITTED" || current.admissionEvent.id !== stable.admissionEventId ||
            !sameHead(current.admissionHead, stable.admissionHead)) return refused("ADMISSION_MISMATCH");
        // 3. Replay's stored prefix hash, not a caller-supplied reconstruction.
        if (state.head.position < current.admissionHead.position ||
            state.eventHistoryHashes[current.admissionHead.position] !== current.admissionHead.hash) return refused("HISTORY_DIVERGED");
        // 4. Any outcome closes this resume path, including a nonterminal one.
        const obligationId = state.obligationIdsBySourceIntent.get(stable.intentId);
        if (current.consumption !== undefined || current.latestOutcome !== undefined || current.terminal !== undefined ||
            [...state.effects.values()].some((effect) => effect.intentId === stable.intentId) ||
            (obligationId !== undefined && state.obligations.get(obligationId)?.status === "CANCELLED")) return refused("INTENT_NOT_OPEN");
        // 5. Recompute exactly as admit does; caller identity is only a comparison.
        const submission = submissionFor(state.events, current), identity = identityFor(state, current);
        try { this.#assertAdapterProfile(identity); } catch { return refused("ADAPTER_PROFILE_CHANGED"); }
        if (identity.idempotencyKey !== stable.submissionIdentity.idempotencyKey ||
            identity.submissionFingerprint !== stable.submissionIdentity.submissionFingerprint) return refused("ADMISSION_MISMATCH");
        // 6. Only exact true proves the gateway's observed attempt absence.
        if (noDispatchStart() !== true) return refused("DISPATCH_STARTED");
        // 7. Retain only derived facts; invoke consumes this fresh WeakMap key.
        const record = Object.freeze({ submission, identity, admissionHead: current.admissionHead });
        const capability: AdmittedInvocationCapability = Object.freeze({ intentId: current.admissionEvent.data.intentId,
          admissionEventId: current.admissionEvent.id, admissionHead: current.admissionHead });
        this.#invocations.set(capability, record);
        return Object.freeze({ status: "RESUMABLE", capability });
      });
    } catch { return refused("UNAVAILABLE"); }
  }

  async invoke(capability: unknown): Promise<InvocationResult> {
    const record = capability !== null && typeof capability === "object" ? this.#invocations.get(capability) : undefined;
    if (record === undefined) return Object.freeze({ status: "NOT_INVOKED", reason: CAPABILITY_REQUIRED });
    // A failed or stale use cannot turn the same object into another attempt.
    this.#invocations.delete(capability as object);
    let called = false, pending: Promise<AdapterSubmissionResult>;
    try {
      const start = this.store.withExclusiveWriter((writer) => {
        const state = this.#state(writer);
        const current = inspectAdmittedIntentState(state, record.submission.intentId, this.#now());
        if (current.status !== "ADMITTED" || !sameHead(current.admissionHead, record.admissionHead) || current.admissionEvent.id !== record.submission.admissionEvent.id ||
            current.consumption !== undefined || current.terminal !== undefined || !current.currentControl) return undefined;
        this.#assertAdapterProfile(record.identity);
        called = true;
        // The synchronous call entry is protected by the lock; its await is not. The adapter gets the durable state that contains the admission.
        return { pending: this.adapter.submit(attested(record.submission, state)) };
      });
      if (start === undefined) return Object.freeze({ status: "NOT_INVOKED", reason: "The original admission is consumed, terminal, replaced or no longer under its admitted control tuple." });
      pending = start.pending;
    } catch {
      return called ? unknownOutcome("Adapter invocation may have started.", record.identity)
        : Object.freeze({ status: "NOT_INVOKED", reason: "Current durable history, time or serialized control could not be established." });
    }
    let disposition: AdapterSubmissionResult;
    try { disposition = captureDisposition(await pending, record.identity); } catch { return unknownOutcome("The adapter response is missing, invalid or exceptional.", record.identity); }
    return this.#recordDisposition(record, disposition);
  }

  /**
   * Records the acknowledgment (consumption) or the simulator's no-effect outcome. Format 2 (A-51): the event is built
   * under the writer lock at the current head, signed by the record signer over the lifecycle challenge outside the lock
   * (the signer may be asynchronous), and appended under the lock only if the head is unchanged; a moved head rebuilds and
   * re-signs (bounded), never alters a signed event.
   */
  async #recordDisposition(record: InvocationRecord, disposition: AdapterSubmissionResult): Promise<InvocationResult> {
    try { this.#assertAdapterProfile(record.identity); } catch { return unknownOutcome("The configured adapter profile changed before recording.", record.identity); }
    if (disposition.status === "OUTCOME_UNKNOWN") return unknownOutcome("The adapter cannot establish a definitive outcome.", record.identity);
    if (disposition.status === "IDEMPOTENCY_FINGERPRINT_CONFLICT") return Object.freeze({ status: disposition.status, disposition });
    const evidence = disposition.status === "RETRY" ? disposition.retainedEvidence : disposition.evidence;
    const acknowledgment = "acknowledgment" in disposition ? disposition.acknowledgment : undefined;
    const noEffect = "noEffect" in disposition ? disposition.noEffect : undefined;
    for (let attempt = 0; attempt < 4; attempt += 1) {
      let prepared: Readonly<{ head: HistoryHead }> | Readonly<{ event: CanonicalEvent; head: HistoryHead; domain: AuthorizationDomain }>;
      try {
        prepared = this.store.withExclusiveWriter((writer) => {
          const state = this.#state(writer), now = this.#now();
          const current = inspectAdmittedIntentState(state, record.submission.intentId, now);
          if (current.status !== "ADMITTED" || !sameHead(current.admissionHead, record.admissionHead)) throw new Error("Original durable admission changed.");
          this.#assertAdapterProfile(record.identity);
          if (acknowledgment !== undefined && current.consumption !== undefined) {
            if (hashOf(current.consumption.evidenceReference) !== hashOf(evidence) || hashOf(current.consumption.acknowledgment) !== hashOf(acknowledgment)) throw new Error("Different acknowledgment already recorded.");
            return { head: current.head };
          }
          if (noEffect !== undefined && current.terminal?.status === "FAILED") {
            if (hashOf(current.terminal.evidenceReference) !== hashOf(evidence) || hashOf(current.terminal.noEffect) !== hashOf(noEffect)) throw new Error("Different no-effect record already retained.");
            return { head: current.head };
          }
          if (!current.currentControl) throw new Error("Original admitted control is no longer current.");
          const algorithm = hashAlgorithmForDomain(record.identity.domain);
          const id = `event:local:${acknowledgment !== undefined ? "consumption" : "failure"}:${hashCanonical([record.submission.intentId, record.submission.admissionEvent.id], algorithm).slice(2)}`;
          const event: CanonicalEvent = acknowledgment !== undefined
            ? { id, type: "TRANSACTION_INTENT_CONSUMED", timestamp: now, data: {
                intentId: record.submission.intentId, adapterId: record.identity.adapterProfile.profileId, idempotencyKey: record.identity.idempotencyKey,
                submissionFingerprint: record.identity.submissionFingerprint, status: "SUBMITTED", evidenceReference: evidence,
                transactionReference: adapterAcknowledgmentTransactionReference(acknowledgment, record.identity), acknowledgment } }
            : { id, type: "TRANSACTION_OUTCOME_RECORDED", timestamp: now, data: { intentId: record.submission.intentId, status: "FAILED", attesterId: SIMULATED_ADAPTER_ID, evidenceReference: evidence, noEffect } };
          // Replay rechecks current control and terminal order; no stale tuple by backdating.
          if (state.format !== TRELLIS2_FORMAT) return { head: writer.appendAtExpectedHead(event, current.head) };
          if (this.#recordSigner === undefined) throw new Error("A format-2 consumption or outcome needs a record signer (A-51).");
          // Independent review step 5b P1-a: T1 and T3 on the record's shape before the session signs it (A-109.1, A-179.4).
          assertSessionWriteTime(state, event, current.head.position + 1);
          return { event, head: current.head, domain: state.genesis.domain };
        });
      } catch (error) {
        if (isSessionWriteTimeRefusal(error)) {
          // r5.2 §6.5.6 (A-179.4) and §10.1.1 item 7: a record rule T3 refuses is not recorded, reason SESSION_TIME_HORIZON. A T1
          // refusal keeps the import's mapping of a refused recording write, its error code (as run()'s refusal report does).
          const rule = (error as { detail?: { reason?: string } }).detail?.reason, message = (error as Error).message;
          const reason = rule === "SESSION_TIME_HORIZON" ? "SESSION_TIME_HORIZON" : (error as { code: string }).code;
          return Object.freeze({ status: "OUTCOME_UNKNOWN" as const, reason: `The acknowledgment or no-effect outcome was not recorded: ${message}`, idempotencyKey: record.identity.idempotencyKey,
            submissionFingerprint: record.identity.submissionFingerprint, recorded: false as const, notRecorded: Object.freeze({ reason, message }) });
        }
        return unknownOutcome("The acknowledgment or simulator no-effect outcome could not be durably recorded.", record.identity);
      }
      if (!("event" in prepared)) return Object.freeze({ status: disposition.status, disposition, recorded: true, head: prepared.head });
      let signed: CanonicalEvent;
      try {
        const signer = this.#recordSigner!;
        const hash = lifecycleAuthorizationHash(prepared.domain, prepared.event, prepared.head, signer.binding);
        const signature = await signer.signHash(hash);
        signed = Object.freeze({ ...prepared.event, data: Object.freeze({ ...prepared.event.data, recordAuthorization: Object.freeze({ ...signer.binding, hash, signature }) }) });
      } catch { return unknownOutcome("The record signer failed; the acknowledgment or no-effect outcome is not recorded yet.", record.identity); }
      try {
        const head = this.store.withExclusiveWriter((writer) => {
          const state = this.#state(writer);
          return sameHead(state.head, prepared.head) ? writer.appendAtExpectedHead(signed, prepared.head) : undefined;
        });
        if (head !== undefined) return Object.freeze({ status: disposition.status, disposition, recorded: true, head });
      } catch { return unknownOutcome("The acknowledgment or simulator no-effect outcome could not be durably recorded.", record.identity); }
    }
    return unknownOutcome("The history kept moving while the record was being signed.", record.identity);
  }

  /** Read-only recovery: retained evidence is re-recorded from replay facts; the adapter is asked to reconcile, never to submit. */
  async reconcile(intentId: string): Promise<InvocationResult> {
    let record: InvocationRecord;
    try {
      const observed = this.store.withExclusiveWriter((writer) => {
        const state = this.#state(writer);
        const current = inspectAdmittedIntentState(state, intentId, state.head.canonicalTime);
        if (current.status !== "ADMITTED") throw new Error("No original admission.");
        const submission = submissionFor(state.events, current, state), identity = identityFor(state, current);
        this.#assertAdapterProfile(identity);
        return { current, record: Object.freeze({ submission, identity, admissionHead: current.admissionHead }) };
      });
      record = observed.record;
      const { current } = observed;
      if (current.terminal !== undefined && current.terminal.status !== "FAILED") return Object.freeze({ status: "TERMINAL", head: current.head, evidence: current.terminal.evidenceReference });
      const retained = current.terminal?.status === "FAILED" ? current.terminal : current.consumption;
      if (retained !== undefined) {
        const typed = current.terminal?.status === "FAILED" ? { noEffect: current.terminal.noEffect } : { acknowledgment: current.consumption?.acknowledgment };
        const disposition = captureDisposition({ status: "RETRY", idempotencyKey: record.identity.idempotencyKey, submissionFingerprint: record.identity.submissionFingerprint, retainedEvidence: retained.evidenceReference, ...typed }, record.identity);
        if (disposition.status !== "RETRY") throw new Error("Retained evidence is not a retry.");
        return Object.freeze({ status: "RETRY", recorded: true, head: current.head, disposition });
      }
    } catch { return unknownOutcome("The original durable admission is unavailable."); }
    let disposition: AdapterSubmissionResult;
    try {
      this.#assertAdapterProfile(record.identity);
      disposition = captureDisposition(await this.adapter.reconcile(record.submission), record.identity);
      if (disposition.status === "SUBMITTED" || disposition.status === "FAILED") throw new Error("Reconciliation returned a new-submission disposition.");
    } catch { return unknownOutcome("Retained adapter evidence is unavailable or invalid.", record.identity); }
    return this.#recordDisposition(record, disposition);
  }

  async commit(prepared: unknown): Promise<DurableAdmissionResult> {
    const admission = this.admit(prepared);
    if (admission.status === "ADMITTED") return Object.freeze({ admission, invocation: await this.invoke(admission.capability) });
    if (admission.status === "NOT_ADMITTED" && admission.result.status === "RETRY") return Object.freeze({ admission, invocation: await this.reconcile(admission.result.intentId) });
    return Object.freeze({ admission });
  }

  async execute(input: unknown): Promise<DurableAdmissionResult> { return this.commit(this.prepare(input)); }
}

// ---------------------------------------------------------------- receipts (spec 03 §J.5)
export type DurableReceiptRecordResult = ReceiptRecordAdmissionResult | Readonly<{ status: "UNAVAILABLE"; recordMayHavePersisted: boolean; reason: string }>;
const unavailable = (recordMayHavePersisted: boolean): DurableReceiptRecordResult =>
  Object.freeze({ status: "UNAVAILABLE", recordMayHavePersisted, reason: "Receipt persistence could not be established; inspect the durable history before another attempt." });
const capturedHead = (value: unknown): HistoryHead | undefined => {
  if (!isRecord(value) || !exactKeys(value, ["hash", "position", "canonicalTime"]) || typeof value.hash !== "string" || !/^0x[0-9a-f]{64}$/.test(value.hash)) return undefined;
  const u53 = (n: unknown): n is number => typeof n === "number" && Number.isSafeInteger(n) && n >= 0 && !Object.is(n, -0);
  return u53(value.position) && u53(value.canonicalTime) ? Object.freeze({ hash: value.hash as ContentHash, position: value.position, canonicalTime: value.canonicalTime }) : undefined;
};

/** Artifact-aware local producer; the configured store supplies conditional persistence. */
export class DurableReceiptCoordinator {
  readonly store: EventStore;
  readonly #replay: ReplayFn;
  constructor(store: EventStore, options: Readonly<{ replay?: ReplayFn }> = {}) { this.store = store; this.#replay = options.replay ?? replayEvents; }

  /** The proposal is computed from `input.events` (replayed once); the store only persists it. */
  record(input: unknown): DurableReceiptRecordResult {
    let proposal: ReceiptRecordProposal;
    try { proposal = proposeReceiptRecord(input, this.#replay); } catch { return unavailable(false); }
    return this.#persist(proposal);
  }
  /**
   * `record` over a caller-supplied replayed `state` (typically the store's
   * `state()`) and the record input without `events`; never replays the history.
   */
  recordState(state: ReplayState, input: unknown): DurableReceiptRecordResult {
    let proposal: ReceiptRecordProposal;
    try { proposal = proposeReceiptRecordState(state, input, this.#replay); } catch { return unavailable(false); }
    return this.#persist(proposal);
  }

  #persist(proposal: ReceiptRecordProposal): DurableReceiptRecordResult {
    if (proposal.status !== "PROPOSED") return proposal;
    try {
      const acknowledged = capturedHead(this.store.appendAtExpectedHead(proposal.recordEvent, proposal.expectedHead));
      if (acknowledged === undefined || !sameHead(acknowledged, proposal.newHead)) return unavailable(true);
      return Object.freeze({ operationVersion: RECEIPT_RECORD_ADMISSION_VERSION, status: "ADMITTED", recordEvent: proposal.recordEvent, newHead: acknowledged, verification: proposal.verification });
    } catch (error) {
      if (isStoreConflict(error)) {
        const observedHead = capturedHead(error.observedHead);
        return observedHead === undefined ? unavailable(false) : Object.freeze({ operationVersion: RECEIPT_RECORD_ADMISSION_VERSION, status: "CONFLICT", expectedHead: proposal.expectedHead, observedHead });
      }
      // An append can fail before writing or after fsync but before acknowledging; neither proves non-persistence.
      return unavailable(true);
    }
  }
}
