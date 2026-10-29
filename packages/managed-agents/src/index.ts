/** Trusted backend adapters. Model input never selects routes, signers, profiles or handlers. */
import { types } from "node:util";
import { mkdirSync, rmSync } from "node:fs";
import {
  admittedSubmissionIdentity,
  type ContentHash,
  type AuthorizationProof,
  type HistoryHead,
} from "@ramex-labs/irontrellis";
import {
  ADAPTER_POLICY_E5_HASH,
  REMOTE_SERVICE_REPORT_ADAPTER_ID,
  adapterAcknowledgmentEvidence,
  approvedAdapterProfileForPolicy,
  createRemoteServiceReportAcknowledgment,
  admissionControlIsCurrent,
  evaluateReceiptPolicy,
  hashCanonical,
  canonicalEncode,
  captureData,
  identifier,
  openConfiguredEventStore,
  observeState,
  openLocalExecution,
  type ReplayState,
  type AdapterSubmissionResult,
  type AdmittedTransactionSubmission,
  type TransactionAdapter,
} from "@ramex-labs/irontrellis/adapter";
import {
  openLocalRuntime,
  MAX_CLOCK_SKEW_MS,
  type LocalExecutionOptions,
  type LocalOperation,
  type LocalExecution,
  type Decision,
  type ObservationInput,
  type ObservationResult,
} from "@ramex-labs/irontrellis/local";
import { RecoveryJournal } from "./journal.js";
export type Route = Readonly<{
  tenantId: string;
  host: string;
  workflowId: string;
  sessionId: string;
  actorId: string;
}>;
export type GovernedCall = Route &
  Readonly<{
    callId: string;
    tool: string;
    arguments: Readonly<Record<string, unknown>>;
  }>;
export type Guard = () => void;
export function assertGuard(guard: Guard): void {
  const value: unknown = guard();
  if (types.isPromise(value))
    Promise.prototype.then.call(value, undefined, () => undefined);
  if (value !== undefined)
    throw new TypeError("guard must synchronously return undefined");
}
export function capture<T>(input: T): T {
  return captureData(input, 65_536, 4096, 16) as T;
}
export type DispatchContext = Readonly<{
  idempotencyKey: ContentHash;
  admissionHead: HistoryHead;
  fencingToken: string;
}>;
export type Finality =
  | Readonly<{
      status: "FINALIZED";
      idempotencyKey: ContentHash;
      admissionHeadHash: ContentHash;
      fencingToken: string;
    }>
  | Readonly<{ status: "PENDING" }>;
export type ToolMapping = Readonly<{
  version: string;
  action: string;
  role: string;
  tenure: string;
  destination: string;
  map(
    args: GovernedCall["arguments"],
  ): Readonly<{ resource: string; amount?: bigint; counterparty?: string }>;
  execute(
    args: GovernedCall["arguments"],
    context: DispatchContext,
  ): unknown | Promise<unknown>;
  status?(idempotencyKey: ContentHash): Promise<unknown | undefined>;
}>;
export type GovernedOptions = Readonly<{
  local: LocalExecutionOptions;
  route: Route;
  reconciliation?: Omit<ReconcilerOptions, "route" | "assertCurrent">;
  mappings: Readonly<Record<string, ToolMapping>>;
  journalPath: string;
  initializeJournal?: boolean;
  assertCurrent: Guard;
  awaitFinality(
    input: Readonly<{
      idempotencyKey: ContentHash;
      admissionHead: HistoryHead;
    }>,
  ): Promise<Finality>;
  assertFence(context: DispatchContext): void;
}>;
export type NativeRun = Awaited<ReturnType<LocalExecution["run"]>>;
export type NativeReceipt = Awaited<
  ReturnType<LocalExecution["recordReceipt"]>
>;
export type NativeError = Readonly<{
  code: string;
  detail: unknown;
  mayHaveCommitted: boolean;
}>;
export type GovernedResult = Readonly<{
  status: "DENIED" | "INDETERMINATE" | "CORE_RESULT" | "UNCERTAIN";
  callHash: ContentHash;
  core?: NativeRun;
  receipt?: NativeReceipt;
  receiptError?: NativeError;
  error?: NativeError;
  reason?: string;
  externalOutcome: "NOT_PROVEN";
}>;
const errorData = (e: unknown): NativeError => {
  const r = e as {
    code?: string;
    detail?: unknown;
    mayHaveCommitted?: boolean;
  };
  return {
    code:
      typeof r?.code === "string"
        ? r.code
        : e instanceof Error
          ? e.message
          : "UNKNOWN",
    detail: r?.detail,
    mayHaveCommitted: r?.mayHaveCommitted === true,
  };
};
export function captureCall(raw: GovernedCall, route: Route): GovernedCall {
  const c = capture(raw);
  for (const k of [
    "tenantId",
    "host",
    "workflowId",
    "sessionId",
    "actorId",
  ] as const) {
    identifier(c[k]);
    if (c[k] !== route[k]) throw TypeError("authenticated route mismatch");
  }
  identifier(c.callId);
  identifier(c.tool);
  if (
    !c.arguments ||
    typeof c.arguments !== "object" ||
    Array.isArray(c.arguments)
  )
    throw TypeError("arguments must be a plain record");
  return c;
}
const keyOf = (c: GovernedCall) =>
  hashCanonical(
    [
      "irontrellis-managed-call/2",
      c.tenantId,
      c.host,
      c.workflowId,
      c.sessionId,
      c.callId,
    ],
    "sha256",
  );
function sessionCurrent(s: ReplayState, o: GovernedOptions, m: ToolMapping) {
  const at = o.local.now(),
    session = s.runtimeSessions.get(o.local.session),
    a = s.agents.get(o.route.actorId),
    r = s.roles.get(m.role),
    t = s.tenures.get(m.tenure);
  return (
    !!session &&
    session.agentId === o.route.actorId &&
    session.controllerId === o.local.controller &&
    (session.expiresAt === undefined || at < session.expiresAt) &&
    !!a &&
    !a.terminated &&
    a.currentControlEpoch === session.controlEpoch &&
    r?.currentTenureId === m.tenure &&
    !!t &&
    !t.closed &&
    t.agentId === o.route.actorId
  );
}
function admittedCurrent(s: ReplayState, o: GovernedOptions, id: string) {
  const a = s.intentAdmissions.get(id);
  if (!a || !admissionControlIsCurrent(s, id, o.local.now())) return false;
  const event = s.events[a.admissionEventPosition];
  return (
    event?.type === "TRANSACTION_INTENT_ADMITTED" &&
    evaluateReceiptPolicy(
      s,
      event.data.authorizationProof as AuthorizationProof,
      o.local.now(),
    ).live
  );
}
export function governed(raw: GovernedOptions) {
  const options = Object.freeze({
    ...raw,
    local: Object.freeze({ ...raw.local, domain: capture(raw.local.domain) }),
    route: capture(raw.route),
    mappings: Object.freeze(
      Object.fromEntries(
        Object.entries(raw.mappings).map(([n, m]) => [
          n,
          Object.freeze({ ...m }),
        ]),
      ),
    ),
  });
  for (const v of Object.values(options.route)) identifier(v);
  if (
    typeof options.assertCurrent !== "function" ||
    typeof options.awaitFinality !== "function" ||
    typeof options.assertFence !== "function"
  )
    throw TypeError("route, finality and fence guards required");
  const store = openConfiguredEventStore(options.local);
  if (store.state().format !== "irontrellis-event/2") {
    store.close();
    throw Error("FORMAT_2_REQUIRED");
  }
  const profile = approvedAdapterProfileForPolicy(
    ADAPTER_POLICY_E5_HASH,
    REMOTE_SERVICE_REPORT_ADAPTER_ID,
  );
  if (store.state().genesis.adapterPolicyHash !== ADAPTER_POLICY_E5_HASH) {
    store.close();
    throw Error("REMOTE_REPORT_PROFILE_REQUIRED");
  }
  const pinnedHistoryId = store.state().eventHistoryHashes[0];
  const binding = hashCanonical(
    {
      domain: "irontrellis-adapter-route/2",
      historyId: store.state().eventHistoryHashes[0],
      route: options.route,
      session: options.local.session,
      controller: options.local.controller,
    },
    "sha256",
  );
  let journal: RecoveryJournal;
  try {
    journal = new RecoveryJournal(
      options.journalPath,
      binding,
      options.initializeJournal,
    );
  } catch (e) {
    store.close();
    throw e;
  }
  let closed = false;
  const current = () => {
    if (closed) throw Error("CLOSED");
    assertGuard(options.assertCurrent);
    if (store.state().eventHistoryHashes[0] !== pinnedHistoryId)
      throw Error("HISTORY_IDENTITY_MISMATCH");
  };
  function prepare(rawCall: GovernedCall) {
    const call = captureCall(rawCall, options.route);
    current();
    const mapping = options.mappings[call.tool];
    if (!mapping) throw Error("UNMAPPED_TOOL");
    for (const s of [
      mapping.version,
      mapping.action,
      mapping.role,
      mapping.tenure,
      mapping.destination,
    ])
      identifier(s);
    const mapped = mapping.map(call.arguments);
    if (types.isPromise(mapped)) {
      Promise.prototype.then.call(mapped, undefined, () => undefined);
      throw TypeError("map must return bounded data synchronously");
    }
    const selected = capture(mapped);
    identifier(selected.resource);
    const key = keyOf(call),
      id = `managed:${key}`;
    const operation: LocalOperation = {
      id,
      intentId: id,
      action: mapping.action,
      resource: selected.resource,
      role: mapping.role,
      tenure: mapping.tenure,
      termsCommitment: hashCanonical(
        {
          version: "managed-terms/1",
          destination: mapping.destination,
          mappingVersion: mapping.version,
          tool: call.tool,
          arguments: call.arguments,
        },
        "keccak256",
      ),
      ...(selected.amount === undefined ? {} : { amount: selected.amount }),
      ...(selected.counterparty === undefined
        ? {}
        : { counterparty: identifier(selected.counterparty) }),
    };
    const digest = hashCanonical(
      {
        version: "irontrellis-managed-call/2",
        call,
        mappingVersion: mapping.version,
        destination: mapping.destination,
        operation,
      },
      "sha256",
    );
    const prior = journal.read().calls[key];
    if (prior && prior.digest !== digest) throw Error("CALL_CONFLICT");
    return { call, mapping, key, operation, digest };
  }
  function authorize(p: ReturnType<typeof prepare>): Decision {
    current();
    const s = store.state();
    return observeState(s, { at: options.local.now() }).authorize({
      actor: options.route.actorId,
      action: p.operation.action,
      resource: p.operation.resource,
      termsCommitment: p.operation.termsCommitment,
      ...(p.operation.amount === undefined
        ? {}
        : { amount: p.operation.amount }),
      ...(p.operation.counterparty === undefined
        ? {}
        : { counterparty: p.operation.counterparty }),
    });
  }
  const decide = async (rawCall: GovernedCall) => {
    const call = captureCall(rawCall, options.route);
    try {
      const p = prepare(call),
        core = authorize(p);
      return Object.freeze({
        callHash: p.digest,
        verdict: sessionCurrent(store.state(), options, p.mapping)
          ? core.decision
          : ("DENY" as const),
        core,
      });
    } catch (error) {
      return Object.freeze({
        callHash: hashCanonical(
          { version: "irontrellis-managed-call/2", call },
          "sha256",
        ),
        verdict: "INDETERMINATE" as const,
        scope: "CAPTURED_HISTORY_ONLY" as const,
        executionCapability: false as const,
        reason: errorData(error).code,
      });
    }
  };
  const record = async (
    rawCall: GovernedCall,
    guards: Readonly<{ assertCurrent?: Guard }> = {},
  ): Promise<GovernedResult> => {
    const capturedCall = captureCall(rawCall, options.route);
    let p: ReturnType<typeof prepare>;
    try {
      p = prepare(capturedCall);
    } catch (error) {
      if (error instanceof Error && error.message === "CALL_CONFLICT")
        throw error;
      return {
        status: "INDETERMINATE",
        callHash: hashCanonical(
          { version: "irontrellis-managed-call/2", call: capturedCall },
          "sha256",
        ),
        externalOutcome: "NOT_PROVEN",
        error: errorData(error),
      };
    }
    const guard = () => {
      current();
      if (guards.assertCurrent) assertGuard(guards.assertCurrent);
    };
    guard();
    journal.update((s) => {
      const prior = s.calls[p.key];
      if (prior && prior.digest !== p.digest) throw Error("CALL_CONFLICT");
      s.calls[p.key] ??= { digest: p.digest, phase: "BOUND" };
    });
    let entered = false,
      adapterError: NativeError | undefined;
    const base = { callHash: p.digest, externalOutcome: "NOT_PROVEN" as const };
    const disposition = async (
      submission: AdmittedTransactionSubmission,
      retry: boolean,
    ): Promise<AdapterSubmissionResult> => {
      // Core invokes this callback under its writer lock. Yield before opening the deferred boundary.
      await Promise.resolve();
      const identity = admittedSubmissionIdentity(submission).identity;
      const unknown = (): AdapterSubmissionResult => ({
        status: "OUTCOME_UNKNOWN",
        idempotencyKey: identity.idempotencyKey,
        submissionFingerprint: identity.submissionFingerprint,
      });
      const acknowledge = (digest: ContentHash): AdapterSubmissionResult => {
        const acknowledgment = createRemoteServiceReportAcknowledgment(
            identity,
            digest,
          ),
          evidence = adapterAcknowledgmentEvidence(identity, acknowledgment);
        return retry
          ? {
              status: "RETRY",
              idempotencyKey: identity.idempotencyKey,
              submissionFingerprint: identity.submissionFingerprint,
              acknowledgment,
              retainedEvidence: evidence,
            }
          : {
              status: "SUBMITTED",
              idempotencyKey: identity.idempotencyKey,
              submissionFingerprint: identity.submissionFingerprint,
              acknowledgment,
              evidence,
            };
      };
      try {
        guard();
        if (
          !sessionCurrent(store.state(), options, p.mapping) ||
          !admittedCurrent(store.state(), options, p.operation.id)
        )
          return unknown();
        const prior = journal.read().calls[p.key];
        if (prior?.digest !== p.digest) throw Error("CALL_CONFLICT");
        if (prior.resultDigest) return acknowledge(prior.resultDigest);
        if (retry || prior.phase !== "BOUND") {
          if (!p.mapping.status) return unknown();
          const known = await p.mapping.status(identity.idempotencyKey);
          guard();
          if (
            !admittedCurrent(store.state(), options, p.operation.id) ||
            known === undefined
          )
            return unknown();
          const digest = hashCanonical(
            { source: "DOWNSTREAM_STATUS", result: capture({ value: known }) },
            "sha256",
          );
          journal.update((s) => {
            s.calls[p.key] = {
              digest: p.digest,
              phase: "RESULT",
              resultDigest: digest,
            };
          });
          return acknowledge(digest);
        }
        journal.update((s) => {
          if (s.calls[p.key]?.phase !== "BOUND") throw Error("CALL_BUSY");
          s.calls[p.key] = { digest: p.digest, phase: "PREPARED" };
        });
        const finality = capture(
          await options.awaitFinality({
            idempotencyKey: identity.idempotencyKey,
            admissionHead: identity.admissionHead,
          }),
        );
        guard();
        if (finality.status !== "FINALIZED") {
          adapterError = errorData(
            Error(
              finality.status === "PENDING"
                ? "FINALITY_PENDING"
                : "FINALITY_INVALID",
            ),
          );
          return unknown();
        }
        if (
          finality.idempotencyKey !== identity.idempotencyKey ||
          finality.admissionHeadHash !== identity.admissionHead.hash
        )
          throw Error("FINALITY_BINDING");
        identifier(finality.fencingToken);
        const context = Object.freeze({
          idempotencyKey: identity.idempotencyKey,
          admissionHead: identity.admissionHead,
          fencingToken: finality.fencingToken,
        });
        const started = store.withExclusiveWriter(() => {
          guard();
          const state = store.state(),
            admission = state.intentAdmissions.get(p.operation.id);
          if (
            !sessionCurrent(state, options, p.mapping) ||
            !admittedCurrent(state, options, p.operation.id) ||
            admission?.adapterIdentity.idempotencyKey !==
              identity.idempotencyKey
          )
            throw Error("ADMISSION_NO_LONGER_CURRENT");
          assertGuard(() => options.assertFence(context));
          journal.update((s) => {
            if (s.calls[p.key]?.phase !== "PREPARED") throw Error("CALL_BUSY");
            s.calls[p.key] = { digest: p.digest, phase: "DISPATCHED" };
          });
          guard();
          if (
            !sessionCurrent(store.state(), options, p.mapping) ||
            !admittedCurrent(store.state(), options, p.operation.id)
          )
            throw Error("ADMISSION_NO_LONGER_CURRENT");
          assertGuard(() => options.assertFence(context));
          entered = true;
          return { pending: p.mapping.execute(p.call.arguments, context) };
        });
        const result = await started.pending;
        guard();
        if (
          !sessionCurrent(store.state(), options, p.mapping) ||
          !admittedCurrent(store.state(), options, p.operation.id)
        )
          return unknown();
        const digest = hashCanonical(
          { source: "LOCAL_HANDLER", result: capture({ value: result }) },
          "sha256",
        );
        journal.update((s) => {
          s.calls[p.key] = {
            digest: p.digest,
            phase: "RESULT",
            resultDigest: digest,
          };
        });
        return acknowledge(digest);
      } catch (error) {
        adapterError = errorData(error);
        return unknown();
      }
    };
    const adapter: TransactionAdapter = {
      adapterProfile: profile,
      submit: (s) => disposition(s, false),
      reconcile: (s) => disposition(s, true),
    };
    const execution = openLocalExecution(
      {
        ...options.local,
        signHash: async (hash) => {
          guard();
          const sig = await options.local.signHash(hash);
          guard();
          return sig;
        },
      },
      adapter,
      "REMOTE_REPORT",
    );
    try {
      guard();
      const core = await execution.run(p.operation);
      guard();
      if (core.status === "NOT_AUTHORIZED" || core.status === "POLICY_REFUSED")
        return { ...base, status: "DENIED", core, reason: core.status };
      if (core.status === "NOT_ADMITTED")
        return {
          ...base,
          status:
            core.admission.status === "UNAVAILABLE" &&
            core.admission.admissionMayHavePersisted
              ? "UNCERTAIN"
              : "INDETERMINATE",
          core,
          reason: core.status,
        };
      const invocation =
        core.status === "RECONCILIATION_ONLY" ? core.result : core.invocation;
      if (!["SUBMITTED", "RETRY", "TERMINAL"].includes(invocation.status))
        return {
          ...base,
          status: "UNCERTAIN",
          core,
          reason: invocation.status,
          ...(adapterError ? { error: adapterError } : {}),
        };
      if (
        !sessionCurrent(store.state(), options, p.mapping) ||
        !admittedCurrent(store.state(), options, p.operation.id)
      )
        return {
          ...base,
          status: "UNCERTAIN",
          core,
          reason: "AUTHORITY_CHANGED",
        };
      try {
        const receipt = await execution.recordReceipt(p.operation);
        guard();
        if (
          !sessionCurrent(store.state(), options, p.mapping) ||
          !admittedCurrent(store.state(), options, p.operation.id)
        )
          return {
            ...base,
            status: "UNCERTAIN",
            core,
            reason: "AUTHORITY_CHANGED",
          };
        return { ...base, status: "CORE_RESULT", core, receipt };
      } catch (error) {
        return {
          ...base,
          status: "UNCERTAIN",
          core,
          receiptError: errorData(error),
          reason: "RECEIPT_OR_OUTPUT_UNAVAILABLE",
        };
      }
    } catch (error) {
      const admitted = store.state().intentAdmissions.has(p.operation.id);
      return {
        ...base,
        status: admitted || entered ? "UNCERTAIN" : "INDETERMINATE",
        error: errorData(error),
      };
    }
  };
  const { actorId, ...streamRoute } = options.route;
  let reconciler: ReturnType<typeof createManagedReconciler> | undefined;
  try {
    if (options.reconciliation)
      reconciler = createManagedReconciler({
        ...options.reconciliation,
        route: streamRoute,
        assertCurrent: current,
      });
  } catch (error) {
    store.close();
    throw error;
  }
  return Object.freeze({
    decide,
    record,
    async reconcile(input: ReconcileInput): Promise<ReconcileResult> {
      current();
      if (!reconciler) throw Error("RECONCILIATION_NOT_CONFIGURED");
      return reconciler.reconcile(input);
    },
    close() {
      closed = true;
      reconciler?.close();
      store.close();
    },
  });
}

export type ManagedHostEvent = Readonly<{
  id: string;
  type: string;
  data?: Readonly<Record<string, unknown>>;
}>;
export type StreamRoute = Omit<Route, "actorId">;
export type ReconcileInput = StreamRoute &
  Readonly<{
    after: string | null;
    nextCursor: string;
    providerDeclaredComplete: boolean;
    events: readonly ManagedHostEvent[];
  }>;
export type EventOutcome = Readonly<{
  sourceEventIndex: number;
  sourceFile: string;
  eventRef: string;
  eventDigest: ContentHash;
  status: "ACCEPTED" | "DUPLICATE" | "BLOCKED" | "UNREPRESENTABLE";
  observation?: ObservationResult;
  error?: NativeError;
  reason?: string;
}>;
export type ReconcileResult = Readonly<{
  outcomes: readonly EventOutcome[];
  checkpointAdvanced: boolean;
  cursor: string | null;
  providerDeclaredComplete: boolean;
  coverage: "SUPPLIED_HOST_EVENTS_ONLY";
}>;
export type ReconcilerOptions = Readonly<{
  local: LocalExecutionOptions;
  route: StreamRoute;
  journalPath: string;
  initializeJournal?: boolean;
  assertCurrent: Guard;
  repeatedCursorPolicy?: "REJECT" | "ALLOW_EMPTY_STABLE";
  match?(event: ManagedHostEvent): ObservationInput["decision"];
  afterObservation?(outcome: EventOutcome): Promise<void>;
}>;
/** Source digest: Core canonical encoding of this captured envelope, SHA-256. No source item is dropped or sorted. */
export function sourceEventDigest(event: ManagedHostEvent): ContentHash {
  return hashCanonical(
    { version: "managed-host-event/1", event: capture(event) },
    "sha256",
  );
}
export function createManagedReconciler(raw: ReconcilerOptions) {
  const o = {
    ...raw,
    local: Object.freeze({ ...raw.local, domain: capture(raw.local.domain) }),
    route: capture(raw.route),
  };
  for (const v of Object.values(o.route)) identifier(v);
  if (
    o.repeatedCursorPolicy !== undefined &&
    !["REJECT", "ALLOW_EMPTY_STABLE"].includes(o.repeatedCursorPolicy)
  )
    throw TypeError("invalid repeated cursor policy");
  const store = openConfiguredEventStore(o.local),
    stream = hashCanonical(
      { version: "irontrellis-managed-stream/2", route: o.route },
      "sha256",
    );
  const pinnedHistoryId = store.state().eventHistoryHashes[0];
  let journal: RecoveryJournal;
  try {
    const state = store.state(),
      session = state.runtimeSessions.get(o.local.session),
      agent = session && state.agents.get(session.agentId);
    if (
      state.format !== "irontrellis-event/2" ||
      !session ||
      session.controllerId !== o.local.controller ||
      !agent ||
      agent.terminated ||
      agent.currentControlEpoch !== session.controlEpoch ||
      (session.expiresAt !== undefined && o.local.now() >= session.expiresAt)
    )
      throw Error("RECONCILER_SESSION_NOT_CURRENT");
    journal = new RecoveryJournal(
      o.journalPath,
      hashCanonical(
        {
          version: "irontrellis-reconciliation-cursor/2",
          historyId: state.eventHistoryHashes[0],
          route: o.route,
        },
        "sha256",
      ),
      o.initializeJournal,
    );
  } catch (e) {
    store.close();
    throw e;
  }
  let closed = false,
    busy = false;
  const guard = () => {
    if (closed) throw Error("CLOSED");
    assertGuard(o.assertCurrent);
    const state = store.state(),
      session = state.runtimeSessions.get(o.local.session),
      agent = session && state.agents.get(session.agentId),
      at = o.local.now();
    if (!Number.isSafeInteger(at) || at < 0) throw Error("CLOCK_INVALID");
    if (state.head.canonicalTime > at + MAX_CLOCK_SKEW_MS)
      throw Error("CLOCK_AHEAD_OF_READER");
    if (state.eventHistoryHashes[0] !== pinnedHistoryId)
      throw Error("HISTORY_IDENTITY_MISMATCH");
    if (
      state.format !== "irontrellis-event/2" ||
      !session ||
      session.controllerId !== o.local.controller ||
      !agent ||
      agent.terminated ||
      agent.currentControlEpoch !== session.controlEpoch ||
      (session.expiresAt !== undefined && at >= session.expiresAt)
    )
      throw Error("RECONCILER_SESSION_NOT_CURRENT");
  };
  const runtime = openLocalRuntime({
    ...o.local,
    signHash: async (h) => {
      guard();
      const sig = await o.local.signHash(h);
      guard();
      return sig;
    },
  });
  const reconcile = async (
    rawBatch: ReconcileInput,
  ): Promise<ReconcileResult> => {
    const b = capture(rawBatch);
    guard();
    for (const k of ["tenantId", "host", "workflowId", "sessionId"] as const)
      if (b[k] !== o.route[k]) throw TypeError("unauthorized stream route");
    if (
      !Array.isArray(b.events) ||
      b.events.length > 1000 ||
      typeof b.providerDeclaredComplete !== "boolean" ||
      (b.after !== null && typeof b.after !== "string")
    )
      throw TypeError("invalid page");
    identifier(b.nextCursor);
    for (const e of b.events) {
      if (!e || typeof e !== "object" || Array.isArray(e))
        throw TypeError("INVALID_PAGE_ENVELOPE");
      try {
        identifier(e.id);
        identifier(e.type);
      } catch {
        throw TypeError("INVALID_PAGE_ENVELOPE");
      }
    }
    if (
      b.nextCursor === b.after &&
      !(
        o.repeatedCursorPolicy === "ALLOW_EMPTY_STABLE" && b.events.length === 0
      )
    )
      throw TypeError("repeated cursor");
    if (busy) throw Error("RECONCILIATION_BUSY");
    busy = true;
    const lock = o.journalPath + ".page";
    try {
      guard();
      mkdirSync(lock, { mode: 0o700 });
    } catch (e) {
      busy = false;
      throw e;
    }
    try {
      const previous = journal.read().cursors[stream] ?? null;
      if (previous !== b.after) throw Error("CURSOR_GAP");
      const outcomes: EventOutcome[] = [];
      for (const [sourceEventIndex, e] of b.events.entries()) {
        const digest = sourceEventDigest(e);
        const sourceFile = journal.retainSource(
          digest,
          Buffer.from(
            canonicalEncode({ version: "managed-host-event/1", event: e }),
            "utf8",
          ),
        );
        let outcome: EventOutcome;
        const data = e.data ?? {};
        if (typeof data.actorId !== "string") {
          outcome = {
            sourceEventIndex,
            sourceFile,
            eventRef: e.id,
            eventDigest: digest,
            status: "UNREPRESENTABLE",
            reason: "OBSERVED_ACTOR_REQUIRED",
          };
        } else {
          try {
            guard();
            const decision = o.match?.(e);
            const call = {
              actorId: data.actorId,
              ...(Object.hasOwn(data, "action")
                ? { action: data.action as string }
                : {}),
              ...(Object.hasOwn(data, "resource")
                ? { resource: data.resource as string }
                : {}),
              ...(Object.hasOwn(data, "observedAt")
                ? { observedAt: data.observedAt as number }
                : {}),
              ...(Object.hasOwn(data, "amount")
                ? { amount: data.amount as string | bigint }
                : {}),
            };
            let observation: ObservationResult | undefined;
            for (let attempt = 0; attempt < 3; attempt++) {
              try {
                observation = await runtime.recordObservation({
                  source: {
                    streamId: stream,
                    eventRef: e.id,
                    eventDigest: digest,
                  },
                  call,
                  ...(decision === undefined ? {} : { decision }),
                });
                guard();
                break;
              } catch (error) {
                guard();
                if (
                  errorData(error).code === "HISTORY_CONFLICT" &&
                  !errorData(error).mayHaveCommitted &&
                  attempt < 2
                )
                  continue;
                throw error;
              }
            }
            if (!observation) throw Error("OBSERVATION_UNAVAILABLE");
            outcome = {
              sourceEventIndex,
              sourceFile,
              eventRef: e.id,
              eventDigest: digest,
              status: "ACCEPTED",
              observation,
            };
          } catch (error) {
            const details = errorData(error);
            outcome = {
              sourceEventIndex,
              sourceFile,
              eventRef: e.id,
              eventDigest: digest,
              status:
                details.code === "OBSERVATION_DUPLICATE"
                  ? "DUPLICATE"
                  : "BLOCKED",
              error: details,
            };
          }
        }
        outcomes.push(outcome);
        if (o.afterObservation) {
          await o.afterObservation(outcome);
          guard();
        }
      }
      guard();
      const accepted = outcomes.every(
        (x) => x.status === "ACCEPTED" || x.status === "DUPLICATE",
      );
      if (accepted)
        journal.update((s) => {
          if ((s.cursors[stream] ?? null) !== b.after)
            throw Error("CURSOR_CONFLICT");
          s.cursors[stream] = b.nextCursor;
        });
      guard();
      return {
        outcomes,
        checkpointAdvanced: accepted,
        cursor: accepted ? b.nextCursor : previous,
        providerDeclaredComplete: b.providerDeclaredComplete,
        coverage: "SUPPLIED_HOST_EVENTS_ONLY",
      };
    } finally {
      rmSync(lock, { recursive: true });
      busy = false;
    }
  };
  return Object.freeze({
    reconcile,
    streamId: stream,
    cursor: () => journal.read().cursors[stream] ?? null,
    close() {
      closed = true;
      store.close();
    },
  });
}

/** A provider-mediated veto only. The caller owns sending the confirmation through its authenticated API. */
export async function resolveAlwaysAsk(
  options: Readonly<{
    backend: Pick<ReturnType<typeof governed>, "decide">;
    route: Route;
    assertCurrent: Guard;
    effectiveConfig: () => Promise<unknown>;
    pinnedConfigHash: ContentHash;
    selectedTools: readonly string[];
    assertAlwaysAsk(config: unknown, tools: readonly string[]): void;
  }>,
  raw: ManagedHostEvent,
) {
  const route = capture(options.route),
    selectedTools = capture(options.selectedTools),
    event = capture(raw),
    data = event.data ?? {};
  identifier(event.id);
  if (route.host !== "claude-managed-agents")
    throw TypeError("Claude route required");
  for (const k of [
    "tenantId",
    "host",
    "workflowId",
    "sessionId",
    "actorId",
  ] as const)
    if (Object.hasOwn(data, k) && data[k] !== route[k])
      throw TypeError("event route mismatch");
  if (
    !["agent.tool_use", "agent.mcp_tool_use"].includes(event.type) ||
    data.evaluated_permission !== "ask"
  )
    throw TypeError("actual ask event required");
  const call = captureCall(
    {
      ...route,
      callId: identifier(data.tool_use_id ?? data.id),
      tool: identifier(data.name),
      arguments: data.input as GovernedCall["arguments"],
    },
    route,
  );
  if (!selectedTools.includes(call.tool) || selectedTools.length === 0)
    throw TypeError("unselected tool");
  for (const name of selectedTools) identifier(name);
  const guard = () => assertGuard(options.assertCurrent);
  guard();
  let reason = "CONFIG_UNAVAILABLE";
  let core:
    | Awaited<ReturnType<ReturnType<typeof governed>["decide"]>>
    | undefined;
  try {
    const first = capture(await options.effectiveConfig());
    guard();
    assertGuard(() => options.assertAlwaysAsk(first, selectedTools));
    if (hashCanonical(first, "sha256") !== options.pinnedConfigHash)
      reason = "CONFIG_DRIFT";
    else {
      core = await options.backend.decide(call);
      guard();
      const last = capture(await options.effectiveConfig());
      guard();
      assertGuard(() => options.assertAlwaysAsk(last, selectedTools));
      if (hashCanonical(last, "sha256") !== options.pinnedConfigHash)
        reason = "CONFIG_DRIFT";
      else {
        core = await options.backend.decide(call);
        guard();
        reason = core.verdict;
      }
    }
  } catch {
    reason = "AUTHORITY_OR_CONFIG_UNAVAILABLE";
  }
  guard();
  return Object.freeze({
    type: "user.tool_confirmation" as const,
    tool_use_id: call.callId,
    allow: reason === "ALLOW",
    reason,
    ...(core && "core" in core ? { core: core.core } : {}),
    scope: "CAPTURED_HISTORY_ONLY" as const,
    executionCapability: false as const,
  });
}
