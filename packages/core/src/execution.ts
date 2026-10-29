/**
 * Signed local execution (port of Core 0.3 `execution.ts`): declare an
 * operation, sign the runtime challenge, durably admit it through the
 * coordinator and invoke the fixed adapter. Dispatched admissions reconcile the
 * original attempt; a trusted host may enable A-163/A-168 undispatched resume.
 */
import { canonicalEncode, wireAmounts } from "./canonical.ts";
import { assertSessionWriteTime } from "./session-write-checks.ts";
import { hashCanonical } from "./hash.ts";
import { TRELLIS2_FORMAT } from "./events.ts";
import { intentDeclarationHash, lifecycleAuthorizationHash, sessionExpiredAt } from "./session-auth.ts";
import { derivedId, sessionWrites } from "./session-writes.ts";
import { boundedRefusal, drainRefusalSpool, REFUSAL_SPOOL_VERSION, refusalSpoolPathFor, type DrainReport } from "./refusal-spool.ts";
import { existsSync } from "node:fs";
import { ROOT_RECOGNITION_POLICY, authorizeState, createRuntimeAuthorizationChallenge, hashRuntimeAuthorizationChallenge } from "./authority.ts";
import { INTENT_ADMISSION_VERSION, sameHead } from "./admission.ts";
import { DurableAdmissionCoordinator, DurableReceiptCoordinator, type TransactionAdapter } from "./coordinators.ts";
import { createReceiptState, receiptRecordDataForArtifact, RECEIPT_RECORD_ADMISSION_VERSION, type ReceiptArtifact } from "./receipts.ts";
import type { HistoryStore } from "./store.ts";
import { IronTrellisError, amount, captureData, contentHash, identifier, optional, record, requireCondition } from "./input.ts";
import { appendEvent, assertEnforceable, configuration, currentState, newEvent, openStore, type Config, type LocalOwnerOptions, type WriteResult } from "./owner.ts";
import { capturePolicy, evaluatePolicy, type AdditionalPolicy } from "./policy.ts";
import type { ActionRequest, CanonicalEvent, AuthorizationResult, ContentHash, HexSignature, HistoryHead, ReplayState, RuntimeSessionRecord } from "./types.ts";

/**
 * A-11 (as amended by A-23, A-56.3): what a `NOT_AUTHORIZED` run says about its refusal record — `refusalRecorded: true`
 * with the `refusal` write, or `refusalRecorded: false` with the reason (`COALESCED`, `RATE_LIMITED`, or the code of the
 * failed write: a capacity code, `HISTORY_CONFLICT`, `SIGNER_FAILED`, `WRITE_UNCONFIRMED`, …). Absent with `refusals: "off"`
 * and for format 1/legacy.
 */
export type RunRefusalReport =
  | Readonly<{ refusalRecorded: true; refusal: WriteResult }>
  | Readonly<{ refusalRecorded: false; refusalNotRecorded: Readonly<{ reason: string; message?: string }> }>;
/** A-22.4: the default bound on how far a history's head may be dated ahead of an enforcement reader's clock. */
export const MAX_CLOCK_SKEW_MS = 300_000;
/** A-22.4: whether `head.canonicalTime > now + maxClockSkewMs` (the reader reports CLOCK_AHEAD_OF_READER and denies, regardless of failOpen). */
export const clockAheadOfReader = (head: Readonly<{ canonicalTime: number }>, now: number, maxClockSkewMs: number = MAX_CLOCK_SKEW_MS): boolean => head.canonicalTime > now + maxClockSkewMs;
/** An application-owned signing callback. Private keys never enter the history. */
export type SignHash = (hash: ContentHash) => Promise<HexSignature>;
export type LocalExecutionOptions = LocalOwnerOptions & Readonly<{ session: string; signHash: SignHash; additionalPolicy?: AdditionalPolicy }>;
export type LocalOperation = Readonly<{
  id: string;
  action: string;
  resource: string;
  role: string;
  tenure: string;
  termsCommitment: ContentHash;
  /** Unsigned integer in the application's declared smallest unit. No currency conversion. */
  amount?: bigint;
  counterparty?: string;
  /** Format 2 (SPEC §8.2, §8.6): the metric the amount is measured in (absent ≡ `"amount"`); matched against budgets. */
  metric?: string;
  /**
   * A-37.2: a raw intent id (the caller owns its collision risk). Absent: format 2 derives it from the actor and `id`
   * (`hashCanonical(["irontrellis-intent-id/2", actorId, id])`, A-69); format 1 uses `id`.
   */
  intentId?: string;
}>;
export type ExecutionMode = "SIMULATION" | "LOCAL_PACKET" | "REMOTE_REPORT";
/** Trusted host dispatch configuration; never supplied by the requesting agent. No replay input. */
export type ExecutionDispatchContext = Readonly<{
  operationId: string; intentId: string; admissionEventId: string; admissionHead: HistoryHead;
  submissionIdentity: Readonly<{ idempotencyKey: ContentHash; submissionFingerprint: ContentHash }>;
  resumed: boolean;
}>;
export type ExecutionDispatchDecision = Readonly<{ status: "READY" }> | Readonly<{ status: "NOT_DISPATCHED"; reason: string }>;
export type LocalExecutionDispatchHooks = Readonly<{
  /** Default on when these live-anchoring hooks are supplied; absent hooks keep reconciliation-only. */
  resumeUndispatched?: boolean;
  /** Runs after durable admission, outside the writer lock. It cannot confer authority or call the adapter. */
  beforeInvoke(context: ExecutionDispatchContext): Promise<ExecutionDispatchDecision>;
  /** True only for proven absence of attempt.json; errors must not be collapsed into absence. */
  noDispatchStart(operationId: string): boolean;
}>;


/** Hash only bounded data (keccak-256, as Core 0.3 did). Keep the actual private terms in application storage. */
export function commitTerms(terms: unknown): ContentHash {
  return hashCanonical(captureData(terms), "keccak256");
}
function operation(input: LocalOperation): LocalOperation {
  const r = record(input, ["id", "action", "resource", "role", "tenure", "termsCommitment"], ["amount", "counterparty", "metric", "intentId"]);
  return Object.freeze({
    id: identifier(r.id), ...optional(r, "intentId", identifier), action: identifier(r.action), resource: identifier(r.resource), role: identifier(r.role), tenure: identifier(r.tenure),
    termsCommitment: contentHash(r.termsCommitment), ...optional(r, "amount", amount), ...optional(r, "counterparty", identifier), ...optional(r, "metric", identifier),
  });
}

/**
 * The store's cached replay state and the head it had when read. The state is
 * the store's live object (extended in place by every append, never copied or
 * replayed here), so `head` is what pins the view: `assertFresh` refuses to use
 * it once the store moved on, and every write path re-reads the store after an
 * `await` and compares heads (`sameHead`) before it proposes or appends.
 */
export type Snapshot = Readonly<{ state: ReplayState; head: HistoryHead }>;
export const snapshotOf = (store: HistoryStore, config: Config): Snapshot => {
  const state = currentState(store, config);
  return Object.freeze({ state, head: state.head });
};
export const assertFresh = (snapshot: Snapshot): void => requireCondition(sameHead(snapshot.state.head, snapshot.head), "HISTORY_CONFLICT");
/** The store's current state after an `await`, provided it is still at `snapshot`'s head (HISTORY_CONFLICT otherwise). */
export const unchangedSince = (store: HistoryStore, config: Config, snapshot: Snapshot): Snapshot => {
  const latest = snapshotOf(store, config);
  requireCondition(sameHead(latest.head, snapshot.head), "HISTORY_CONFLICT");
  return latest;
};

/** The session's signer, guarded: a malformed or throwing callback surfaces as SIGNER_FAILED without leaking its error. */
export const guardedSigner = (signHash: SignHash, session: RuntimeSessionRecord): SignHash => {
  const shape = session.credentialScheme === "ed25519" ? /^0x[0-9a-fA-F]{128}$/ : /^0x[0-9a-fA-F]{130}$/;
  return async (hash) => {
    try {
      const result: unknown = await signHash(hash);
      requireCondition(typeof result === "string" && shape.test(result));
      return result as HexSignature;
    } catch {
      throw new IronTrellisError("SIGNER_FAILED");
    }
  };
};

/**
 * Trusted local application configuration, not an untrusted-agent boundary.
 * This internal constructor accepts approved executable configuration only;
 * public factories pin the supported adapter so no agent can inject one.
 */
function localExecutionWithHooks(options: LocalExecutionOptions, adapter: TransactionAdapter, mode: ExecutionMode, dispatchHooks?: LocalExecutionDispatchHooks) {
  const config = configuration(options), sessionId = identifier(options.session), signHash = options.signHash;
  const beforeInvoke = dispatchHooks?.beforeInvoke, noDispatchStart = dispatchHooks?.noDispatchStart;
  requireCondition(dispatchHooks === undefined || (mode === "REMOTE_REPORT" && typeof beforeInvoke === "function" && typeof noDispatchStart === "function" &&
    (dispatchHooks.resumeUndispatched === undefined || typeof dispatchHooks.resumeUndispatched === "boolean")));
  const resumeUndispatched = dispatchHooks !== undefined && dispatchHooks.resumeUndispatched !== false;

  requireCondition(typeof signHash === "function");
  const additionalPolicy = capturePolicy(options.additionalPolicy);
  const store = openStore(config);
  // A-41: run(), authorize and the execution API are enforcement callers: no fenced history, and no legacy or format-1
  // history without the opt-in (or the earlier writer named by `format`, A-30).
  assertEnforceable(store, config);
  const initial = currentState(store, config);
  const session = initial.runtimeSessions.get(sessionId);
  requireCondition(session !== undefined && session.controllerId === config.controller, "RUNTIME_NOT_CURRENT");
  const algorithm = initial.hashAlgorithm;
  // No custom replay: both coordinators read the store's cached `state()` under the writer lock.
  const sign = guardedSigner(signHash, session);
  const format2 = store.format === TRELLIS2_FORMAT;
  // A-51: in format 2 this session (the intent's actor) signs the consumption and the no-effect outcome the coordinator records.
  const recordSigner = Object.freeze({ binding: Object.freeze({ runtimeSessionId: sessionId, credentialKeyId: session.credentialKeyId, controlEpoch: session.controlEpoch }), signHash: sign });
  const coordinator = new DurableAdmissionCoordinator(store, adapter, { authoritativeNow: config.now, ...(format2 ? { recordSigner } : {}) });
  const receipts = new DurableReceiptCoordinator(store);
  const writes = sessionWrites(store, config, sessionId, session, sign);
  const externalEffect = mode === "SIMULATION" ? ("NONE_SIMULATED" as const) : mode === "REMOTE_REPORT" ? ("REMOTE_REPORTED_OUTCOME" as const) : ("LOCAL_PACKET" as const);

  const current = (snapshot: Snapshot, at: number): ReplayState => {
    assertFresh(snapshot);
    const state = snapshot.state, agent = state.agents.get(session.agentId);
    // A-22.4: a head dated beyond the reader's skew bound is CLOCK_AHEAD_OF_READER (deny), a smaller lag is the format-1 engine's CLOCK_INVALID.
    if (state.head.canonicalTime > at + MAX_CLOCK_SKEW_MS) throw new IronTrellisError("CLOCK_AHEAD_OF_READER", false, `the history's head is dated ${state.head.canonicalTime - at} ms ahead of this reader's clock (bound ${MAX_CLOCK_SKEW_MS} ms)`, { skewMs: state.head.canonicalTime - at });
    requireCondition(at >= state.head.canonicalTime, "CLOCK_INVALID");
    // A-149.0: in format 2 a session without expiresAt (a migrated prefix session) is expired after the prefix.
    requireCondition(agent !== undefined && !agent.terminated && agent.currentControlEpoch === session.controlEpoch && !sessionExpiredAt(state, session, at), "RUNTIME_NOT_CURRENT");
    return state;
  };
  const requestFor = (op: LocalOperation, at: number): ActionRequest => Object.freeze({
    actorId: session.agentId, action: op.action, resource: op.resource, termsCommitment: op.termsCommitment, claimedAt: at,
    ...(Object.hasOwn(op, "amount") ? { amount: op.amount } : {}), ...(Object.hasOwn(op, "counterparty") ? { counterpartyId: op.counterparty } : {}),
    ...(Object.hasOwn(op, "metric") ? { metric: op.metric } : {}),
  }) as ActionRequest;
  // A-37.2 / A-69 (format 2): the intent id is derived from the actor and the caller's operation id, so another actor
  // cannot take it first; the nonce is derived from that id. Format 1 keeps the format-1 engine's ids (`op.id`).
  const intentIdOf = (op: LocalOperation): string => op.intentId ?? (format2 ? derivedId("intent", session.agentId, op.id) : op.id);
  const declarationFor = (op: LocalOperation) => Object.freeze({
    intentId: intentIdOf(op), nonce: `operation:${intentIdOf(op)}`, adapterProfile: adapter.adapterProfile, actorId: session.agentId, action: op.action, resource: op.resource,
    roleId: op.role, roleTenureId: op.tenure, termsCommitment: op.termsCommitment,
    ...(Object.hasOwn(op, "amount") ? { amount: op.amount } : {}), ...(Object.hasOwn(op, "counterparty") ? { counterpartyId: op.counterparty } : {}),
    ...(Object.hasOwn(op, "metric") ? { metric: op.metric } : {}),
  });
  /**
   * The declaration event. Format 2 (SPEC §8.6): the fields are session-signed over the intent-declaration challenge
   * bound to the head before the event (`declarationAuthorization`), and the amount is written as a decimal string.
   */
  const declarationEvent = async (op: LocalOperation, at: number, head: HistoryHead) => {
    const fields = declarationFor(op);
    if (!format2) return Object.freeze({ ...newEvent(config, "TRANSACTION_INTENT_DECLARED", at, fields), id: declarationId(op) });
    const binding = { runtimeSessionId: sessionId, credentialKeyId: session.credentialKeyId, controlEpoch: session.controlEpoch };
    // A-54: the envelope (id, timestamp) is fixed before the signature.
    const hash = intentDeclarationHash(config.domain, fields, { hash: head.hash, position: head.position }, binding, { id: declarationId(op), timestamp: at });
    const signature = await sign(hash);
    return Object.freeze({ ...newEvent(config, "TRANSACTION_INTENT_DECLARED", at, { ...wireAmounts(fields), declarationAuthorization: { ...binding, hash, signature } }), id: declarationId(op) });
  };
  /**
   * docs/API.md §2: a DENY/INDETERMINATE decided before executing is recorded as a `REQUEST_REFUSED` (source CORE or
   * BUDGET, signed by this session) unless `refusals: "off"`; a failure to record it is reported, never hidden.
   */
  /** A-51: the nested `recordAuthorization` of a format-2 type 14–16 event signed by this session over the head before it. */
  const lifecycleBinding = Object.freeze({ runtimeSessionId: sessionId, credentialKeyId: session.credentialKeyId, controlEpoch: session.controlEpoch });
  const lifecycleAuthorizationOf = async (event: Readonly<Pick<CanonicalEvent, "id" | "type" | "timestamp" | "data">>, head: HistoryHead) => {
    const hash = lifecycleAuthorizationHash(config.domain, event, head, lifecycleBinding);
    return Object.freeze({ ...lifecycleBinding, hash, signature: await sign(hash) });
  };
  const recordedRefusal = async (op: LocalOperation, at: number, budgetMs?: number): Promise<RunRefusalReport | undefined> => {
    if (!format2 || config.refusals === "off") return undefined;
    // A-11 / A-56.3: recording never turns the decision into an exception; the result says whether it was recorded and, if not, why.
    try {
      const request = wireAmounts(requestFor(op, at)) as unknown as Parameters<typeof writes.recordRefusal>[0]["request"];
      // A-38.1: with an explicit `refusalPolicy` (hooks, the gateway) the write is bounded by `recordBudgetMs`; past it the
      // input is spooled (SPOOLED / RECORD_DEADLINE). The refusal id is derived first so the spooled entry and the slow
      // write name the same refusal.
      const refusalId = derivedId("refusal", session.agentId);
      const attempt = writes.recordRefusal({ refusalId, request });
      const { claimedAt: _time, ...timeless } = request;
      const result = config.refusalPolicy === undefined ? await attempt
        : await boundedRefusal(config.historyFile, attempt, Object.freeze({ version: REFUSAL_SPOOL_VERSION, refusalId, attemptedAt: at, request: timeless }), budgetMs ?? config.refusalPolicy.recordBudgetMs);
      if ("recorded" in result && result.recorded === false) return Object.freeze({ refusalRecorded: false as const, refusalNotRecorded: Object.freeze({ reason: result.reason }) });
      return Object.freeze({ refusalRecorded: true as const, refusal: result as WriteResult });
    } catch (error) {
      const reason = error instanceof IronTrellisError ? error.code : "WRITE_UNCONFIRMED";
      return Object.freeze({ refusalRecorded: false as const, refusalNotRecorded: Object.freeze({ reason, message: error instanceof Error ? error.message : String(error) }) });
    }
  };
  const declarationId = (op: LocalOperation): string => `operation:${hashCanonical({
    version: "continuity-simulation-operation/1", domain: config.domain, session: sessionId, epoch: session.controlEpoch, key: session.credentialKeyId,
    declaration: declarationFor(op), ...(additionalPolicy === undefined ? {} : { additionalPolicy: additionalPolicy.identity }),
  }, algorithm)}`;
  /** An operation id is bound to its first declaration; any other arguments under the same id are refused. */
  const match = (op: LocalOperation, snapshot: Snapshot): ReplayState => {
    const state = snapshot.state, found = state.intentDeclarations.get(intentIdOf(op));
    if (found !== undefined) {
      const position = state.eventPositionsById.get(declarationId(op));
      requireCondition(position !== undefined && state.events[position]?.type === "TRANSACTION_INTENT_DECLARED" &&
        canonicalEncode(found.data) === canonicalEncode(declarationFor(op)), "OPERATION_CONFLICT");
    }
    return state;
  };
  const policyAt = (op: LocalOperation, snapshot: Snapshot, at: number): AuthorizationResult => {
    const state = current(snapshot, at);
    const role = state.roles.get(op.role), tenure = state.tenures.get(op.tenure);
    requireCondition(role?.currentTenureId === op.tenure && tenure !== undefined && !tenure.closed && tenure.agentId === session.agentId && tenure.roleId === op.role, "RUNTIME_NOT_CURRENT");
    return authorizeState(state, {
      expectedHistoryHead: snapshot.head, domain: config.domain, policyVersion: state.genesis.policyVersion, rootRecognitionPolicy: ROOT_RECOGNITION_POLICY,
      request: requestFor(op, at), evaluationTime: at, consequential: false,
    });
  };

  /** A-38.2 / A-68: drain the refusals this actor spooled (re-derived now; the attempt time goes to the side log). */
  const drainSpool = async (options: Readonly<{ deadlineMs?: number; report?: DrainReport }> = {}) => (existsSync(refusalSpoolPathFor(config.historyFile))
    ? drainRefusalSpool(config.historyFile, writes, session.agentId, config.now, (id) => store.state().refusals.has(id), options)
    : Object.freeze([]));
  const drainRefusals = async () => drainSpool();
  const undispatched = (op: LocalOperation, reason: string) => Object.freeze({
    status: "NOT_DISPATCHED" as const, operationId: op.id, dispatchPerformed: false as const, reason,
  });
  const dispatchContext = (op: LocalOperation, state: ReplayState, resumed: boolean): ExecutionDispatchContext => {
    const admitted = state.intentAdmissions.get(intentIdOf(op));
    requireCondition(admitted !== undefined, "HISTORY_CONFLICT");
    return Object.freeze({ operationId: op.id, intentId: admitted.intentId, admissionEventId: admitted.admissionEventId,
      admissionHead: Object.freeze({ ...admitted.admissionHead }), resumed,
      submissionIdentity: Object.freeze({ idempotencyKey: contentHash(admitted.adapterIdentity.idempotencyKey), submissionFingerprint: contentHash(admitted.adapterIdentity.submissionFingerprint) }),
    });
  };
  const waitBeforeInvoke = async (op: LocalOperation, context: ExecutionDispatchContext) => {
    if (beforeInvoke === undefined) return undefined;
    try {
      const answer = await beforeInvoke(context);
      if (answer?.status === "READY") return undefined;
      return undispatched(op, answer?.status === "NOT_DISPATCHED" && typeof answer.reason === "string" ? answer.reason : "ACCESS_NOT_CURRENT");
    } catch { return undispatched(op, "ACCESS_NOT_CURRENT"); }
  };
  return Object.freeze({
    ...writes,
    drainRefusals,
    profile: mode === "SIMULATION" ? ("EFFECT_FREE_SIMULATION" as const) : mode === "REMOTE_REPORT" ? ("REMOTE_REPORTED_OUTCOME" as const) : ("LOCAL_EVIDENCE_PACKET" as const),
    /** a committed admission whose dispatch-start record (`attempt.json`) exists is never re-invoked, including after a restart; a committed admission with no `attempt.json` has not been dispatched, whatever barrier records exist, and MAY be dispatched once, by a later `run` of the same job that passes the barrier and A-163.2, appends its own barrier record and then creates `attempt.json` with the same O_EXCL create. Exactly-once is the O_EXCL attempt file, not the process lifetime. */
    async run(input: LocalOperation) {
      const op = operation(input);
      // A-38.2: a bounded caller (hooks, the gateway) drains this actor's spooled refusals first. A-38.1: the drain and this
      // call's own refusal share one recordBudgetMs. The refusal gets what the drain left; when the drain reached its deadline
      // (a write of it may still be running), it waits no further: it is spooled at once, while its own write may still start.
      let drainedMs = 0;
      const drained: DrainReport = { deadlineReached: false, writeStillRunning: false };
      if (format2 && config.refusalPolicy !== undefined && config.refusals !== "off" &&
          !(resumeUndispatched && snapshotOf(store, config).state.intentAdmissions.has(intentIdOf(op)))) {
        const draining = performance.now();
        await drainSpool({ deadlineMs: config.refusalPolicy.recordBudgetMs, report: drained });
        drainedMs = performance.now() - draining;
      }
      const ownBudget = (): number | undefined => config.refusalPolicy === undefined ? undefined
        : drained.deadlineReached ? 0 : Math.max(0, config.refusalPolicy.recordBudgetMs - drainedMs);
      let snapshot = snapshotOf(store, config), state: ReplayState;
      try { state = match(op, snapshot); } catch (error) {
        if (resumeUndispatched && snapshot.state.intentAdmissions.has(intentIdOf(op))) return undispatched(op, "ADMISSION_MISMATCH");
        throw error;
      }
      if (state.intentAdmissions.has(intentIdOf(op))) {
        let absent = false;
        if (resumeUndispatched) {
          try { absent = noDispatchStart!(op.id) === true; } catch {
            return Object.freeze({ status: "RECONCILIATION_ONLY" as const, operationId: op.id, externalEffect, result: Object.freeze({ status: "OUTCOME_UNKNOWN" as const, reason: "Dispatch-start state is unavailable." }) });
          }
        }
        if (!absent) {
          // Observation/reconciliation is allowed after retirement and never creates a new invocation capability.
          return Object.freeze({ status: "RECONCILIATION_ONLY" as const, operationId: op.id, externalEffect, result: await coordinator.reconcile(intentIdOf(op)) });
        }
        const context = dispatchContext(op, state, true), stopped = await waitBeforeInvoke(op, context);
        if (stopped !== undefined) return stopped;
        const resumed = coordinator.resumeInvocation({ intentId: context.intentId, admissionEventId: context.admissionEventId,
          admissionHead: context.admissionHead, submissionIdentity: context.submissionIdentity, noDispatchStart: () => noDispatchStart!(op.id) });
        if (resumed.status === "NOT_RESUMABLE") return undispatched(op, resumed.reason);
        const invocation = await coordinator.invoke(resumed.capability);
        return Object.freeze({ status: "EXECUTION_RESULT" as const, operationId: op.id, externalEffect, resumed: true as const, invocation });
      }
      let at = config.now();
      const policy = policyAt(op, snapshot, at);
      if (policy.decision !== "ALLOW") {
        const refusal = await recordedRefusal(op, at, ownBudget());
        return Object.freeze({ status: "NOT_AUTHORIZED" as const, operationId: op.id, evidence: policy, ...(refusal ?? {}) });
      }
      if (!state.intentDeclarations.has(intentIdOf(op))) {
        // JOB75-03: T1 and T3 on the declaration's shape before the session signs it (A-179.4).
        assertSessionWriteTime(snapshot.state, { type: "TRANSACTION_INTENT_DECLARED", timestamp: at }, snapshot.head.position + 1);
        const next = await declarationEvent(op, at, snapshot.head);
        // The declaration signature (format 2) is an async boundary: the event binds the head it was signed over, so a moved history refuses it (HISTORY_CONFLICT).
        const latest = unchangedSince(store, config, snapshot);
        current(latest, config.now());
        await appendEvent(store, config, latest.state, next, snapshot.head);
        snapshot = snapshotOf(store, config);
        state = match(op, snapshot);
      }
      at = config.now();
      current(snapshot, at);
      const binding = { runtimeSessionId: sessionId, credentialKeyId: session.credentialKeyId, controlEpoch: session.controlEpoch, roleId: op.role, roleTenureId: op.tenure, intentId: intentIdOf(op), nonce: `operation:${intentIdOf(op)}` };
      const request = requestFor(op, at), policyVersion = state.genesis.policyVersion;
      const challenge = createRuntimeAuthorizationChallenge({ domain: config.domain, request, evaluationTime: at, policyVersion, historyHead: snapshot.head, binding });
      // JOB75-03: T1 and T3 on the admission's shape (timestamp = evaluationTime) before the session signs its authorization.
      assertSessionWriteTime(snapshot.state, { type: "TRANSACTION_INTENT_ADMITTED", timestamp: at }, snapshot.head.position + 1);
      const runtimeSignature = await sign(hashRuntimeAuthorizationChallenge(challenge, algorithm));
      // Signing is an async boundary. A stale prefix must not authorize a new operation, and expiry while the signer waited must not be ignored.
      if (additionalPolicy !== undefined) {
        const evidence = await evaluatePolicy(additionalPolicy, {
          domain: config.domain, actor: session.agentId, action: op.action, resource: op.resource, session: sessionId, epoch: session.controlEpoch, role: op.role, tenure: op.tenure,
          operationId: op.id, termsCommitment: op.termsCommitment, historyHead: snapshot.head.hash,
          ...(Object.hasOwn(op, "amount") ? { amount: op.amount } : {}), ...(Object.hasOwn(op, "counterparty") ? { counterparty: op.counterparty } : {}),
        }, config.now);
        if (evidence.result.decision !== "ALLOW") {
          return Object.freeze({ status: "POLICY_REFUSED" as const, operationId: op.id, policyIdentity: evidence.result.identity, reason: evidence.result.decision });
        }
      }
      // Policy evaluation and durable audit are asynchronous too. Recheck Core only after both complete; the policy result cannot revive a stale actor.
      const latest = unchangedSince(store, config, snapshot);
      const freshAt = config.now();
      const freshPolicy = policyAt(op, latest, freshAt);
      if (freshPolicy.decision !== "ALLOW") {
        const refusal = await recordedRefusal(op, freshAt, ownBudget());
        return Object.freeze({ status: "NOT_AUTHORIZED" as const, operationId: op.id, evidence: freshPolicy, ...(refusal ?? {}) });
      }
      // Proposed over the store's cached state (unchanged since the challenge was signed): no history snapshot, no replay.
      const prepared = coordinator.prepareState(latest.state, {
        operationVersion: INTENT_ADMISSION_VERSION, expectedHistoryHead: snapshot.head,
        admissionEventId: `admission:${hashCanonical({ declarationId: declarationId(op), head: snapshot.head }, algorithm)}`,
        domain: config.domain, policyVersion, request, evaluationTime: at, binding: { ...binding, runtimeSignature },
      });
      const admitted = coordinator.admit(prepared);
      if (admitted.status !== "ADMITTED") return Object.freeze({ status: "NOT_ADMITTED" as const, operationId: op.id, admission: admitted });
      // Admission released the writer lock before this await, so stops and power-reducing writes remain possible.
      const stopped = await waitBeforeInvoke(op, dispatchContext(op, snapshotOf(store, config).state, false));
      if (stopped !== undefined) return stopped;
      const invocation = await coordinator.invoke(admitted.capability);
      return Object.freeze({
        status: mode === "SIMULATION" ? ("SIMULATION_RESULT" as const) : ("EXECUTION_RESULT" as const), operationId: op.id, externalEffect, admission: admitted.result, invocation,
      });
    },
    /** Issue and record a signed receipt only for this session's actual acknowledgment. */
    async recordReceipt(input: LocalOperation) {
      const op = operation(input), snapshot = snapshotOf(store, config), state = match(op, snapshot);
      const intentId = intentIdOf(op);
      const admitted = state.intentAdmissions.get(intentId);
      requireCondition(admitted !== undefined && admitted.runtimeSessionId === sessionId && state.intentConsumptions.has(intentId), "RECEIPT_UNAVAILABLE");
      const existing = [...state.receiptCommitments.values()].find((r) => r.intentId === intentId);
      if (existing !== undefined) {
        return Object.freeze({ status: "ALREADY_RECORDED" as const, contentHash: existing.receiptContentHash, eventId: existing.eventId, artifactAvailable: false as const });
      }
      const at = config.now();
      current(snapshot, at);
      // JOB75-03: T1 and T3 on the receipt record's shape before the session signs the receipt and its record (A-179.4).
      if (format2) assertSessionWriteTime(snapshot.state, { type: "RECEIPT_RECORDED", timestamp: at }, snapshot.head.position + 1);
      let artifact: ReceiptArtifact;
      try {
        artifact = await createReceiptState(snapshot.state, { intentId: intentIdOf(op), issuedAt: at, externalOutcome: mode === "SIMULATION" ? "SIMULATED" : "NOT_PROVEN" }, { keyId: session.credentialKeyId, signHash: sign });
      } catch (error) {
        // The cached state is live: an append while the signer ran is a conflict, not a malformed receipt.
        if (error instanceof TypeError && !sameHead(snapshot.state.head, snapshot.head)) throw new IronTrellisError("HISTORY_CONFLICT", false, "the history changed while the receipt was being signed");
        throw error;
      }
      const recordEventId = `receipt:${artifact.contentHash}`;
      // A-51 (format 2): the record is session-signed by the issuer over the lifecycle challenge at the head it extends.
      const recordAuthorization = format2 ? await lifecycleAuthorizationOf({ id: recordEventId, type: "RECEIPT_RECORDED", timestamp: artifact.payload.issuance.issuedAt, data: receiptRecordDataForArtifact(artifact, algorithm) }, snapshot.head) : undefined;
      const latest = unchangedSince(store, config, snapshot);
      current(latest, config.now());
      const recording = receipts.recordState(latest.state, {
        operationVersion: RECEIPT_RECORD_ADMISSION_VERSION, artifact, expectedHistoryHead: snapshot.head, expectedDomain: config.domain,
        recordEventId, ...(recordAuthorization === undefined ? {} : { recordAuthorization }),
      });
      return Object.freeze({ status: "RECEIPT_RESULT" as const, artifact, recording });
    },
  });
}
type HookedLocalExecution = ReturnType<typeof localExecutionWithHooks>;
/** Existing callers without dispatch hooks cannot produce NOT_DISPATCHED. */
export type LocalExecution = Omit<HookedLocalExecution, "run"> & Readonly<{
  run(input: LocalOperation): Promise<Exclude<Awaited<ReturnType<HookedLocalExecution["run"]>>, { status: "NOT_DISPATCHED" }>>;
}>;
export function openLocalExecution(options: LocalExecutionOptions, adapter: TransactionAdapter, mode: ExecutionMode): LocalExecution;
export function openLocalExecution(options: LocalExecutionOptions, adapter: TransactionAdapter, mode: ExecutionMode, dispatchHooks: LocalExecutionDispatchHooks | undefined): HookedLocalExecution;
export function openLocalExecution(options: LocalExecutionOptions, adapter: TransactionAdapter, mode: ExecutionMode, dispatchHooks?: LocalExecutionDispatchHooks) {
  return localExecutionWithHooks(options, adapter, mode, dispatchHooks);
}
