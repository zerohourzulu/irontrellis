/**
 * Session-signed writes of the runtime handles (SPEC §10–§11; docs/API.md §2; G0 §2): `recordRefusal`,
 * `recordEffect`, `recordCounterpartyReceipt` and `recordObservation` (A-71), plus the read-only `headroom` and `exportView`. Shared by
 * `openLocalRuntime` and `openLocalExecution`.
 *
 * Every write is two-phase, like `signedTransition`: the event data is built against the store's cached state at the
 * current head (`expectedHistoryHead` / the challenge's head fields), the §6.2 challenge is signed by the session's
 * `signHash`, the head is re-checked after the asynchronous signature (`HISTORY_CONFLICT` when the history moved) and
 * the event is appended at exactly that head (the store checks it again under the writer lock). A refusal of source
 * CORE or BUDGET is re-derived through `authorizeState` with `consequential: false` before signing: a request the
 * state ALLOWs is refused with `REFUSAL_NOT_REPRODUCED` and nothing is signed or written. A-23 / A-56.3 (supersede
 * A-12.5): a refusal is coalesced against the actor's latest `refusal` record when the key `(actorId, action, resource,
 * code, budgetId ?? null, connector.refusalCode ?? null)` is identical and that record is younger than
 * `refusalPolicy.coalesceMs` (default 60 s), and rate-limited per actor (`refusalPolicy.maxPerMinute`, default 6, a token
 * bucket per history file and actor in this process); a skipped refusal reports `{recorded: false, reason: "COALESCED" |
 * "RATE_LIMITED"}` (A-11's one list of not-recorded reasons). The A-12.5 process-lifetime key is kept as a fast path and
 * reports `COALESCED`; `{deduplicated: true}` is withdrawn.
 * Idempotency: a write whose id (`refusalId`, `effectId`, the envelope digest) is already recorded with the same effect
 * returns the recorded event; a different effect under the same id is `OPERATION_CONFLICT`.
 */
import { randomBytes } from "node:crypto";
import { sessionTimeHorizonFailure } from "./session-time.ts";
import { assertSessionWriteTime } from "./session-write-checks.ts";
import { wireAmounts } from "./canonical.ts";
import { ROOT_RECOGNITION_POLICY, authorizeState } from "./authority.ts";
import { budgetConcernsActor, headroom as headroomState, type BudgetRecord } from "./budgets.ts";
import { OBSERVATION_UNSUPPLIABLE, TRELLIS2_FORMAT, validateEvent } from "./events.ts";
import { exportViewState, type ExportView, type ExportViewInput } from "./export-view.ts";
import { inspectDutyPolicyOf, type DutyPolicyView } from "./duty-policy.ts";
import { hashCanonical } from "./hash.ts";
import { IronTrellisError, captureData, contentHash, identifier, record, requireCondition, time } from "./input.ts";
import { appendEvent, assertWritable, newEvent, newEventId, translate, type Config, type Headroom, type HeadroomInput, type WriteResult } from "./owner.ts";
import { counterpartyRecordChallenge, derivedObservationId, effectChallenge, envelopeDigest, reconciliationChallenge, refusalChallenge, sessionExpiredAt } from "./session-auth.ts";
import { observationIndexOf } from "./state.ts";
import type { HistoryStore } from "./store.ts";
import { assertFresh, snapshotOf, unchangedSince, type SignHash, type Snapshot } from "./execution.ts";
import type { ActionRequest, CanonicalEvent, ContentHash, HexSignature, ReplayState, RuntimeSessionRecord, U53 } from "./types.ts";

type Rec = Readonly<Record<string, unknown>>;
export type RefusalInput = Readonly<{
  /** A raw id (the caller owns its collision risk); absent → derived (A-37.2) from `request.actorId` and `operationId`. */
  refusalId?: string;
  /** A-37.2: the caller's operation id the refusal id is derived from (absent → a fresh random value). */
  operationId?: string;
  /** The refused request (`amount` as a decimal string or a bigint). */
  request: Readonly<{ actorId: string; action: string; resource: string; claimedAt: U53; amount?: string | bigint; counterpartyId?: string; termsCommitment?: ContentHash; metric?: string }>;
  /** CORE or BUDGET: checked against the re-derived decision (the state decides the source; a disagreement is REFUSAL_NOT_REPRODUCED). */
  source?: "CORE" | "BUDGET";
  /** A CONNECTOR refusal (SPEC §10.1): attested, not re-derived; the signing session's agent must be `connectorId`. */
  connector?: Readonly<{ connectorId: string; refusalCode: string; detailDigest: ContentHash }>;
}>;
/**
 * A-11 / A-56.3: the ONE list of reasons a refusal (or an effect) was not recorded. The writer reports `COALESCED` and
 * `RATE_LIMITED` (A-23); the hooks and the gateway add `SPOOLED`, `RECORD_DEADLINE`, `NOT_REPRODUCED_AT_DRAIN` (A-38);
 * `run()` adds the code of a failed write (a capacity code, `HISTORY_CONFLICT`, a signer failure, `WRITE_UNCONFIRMED`, …).
 * A-179.4: `SESSION_TIME_HORIZON` when the refusal event would fail rule T3 (nothing is signed; a spooled entry stays spooled).
 */
export const REFUSAL_NOT_RECORDED_REASONS = Object.freeze(["COALESCED", "RATE_LIMITED", "SPOOLED", "RECORD_DEADLINE", "NOT_REPRODUCED_AT_DRAIN", "SESSION_TIME_HORIZON"] as const);
export type RefusalNotRecordedReason = (typeof REFUSAL_NOT_RECORDED_REASONS)[number];
export type RefusalNotRecorded = Readonly<{ recorded: false; reason: RefusalNotRecordedReason | string }>;
export type RefusalResult = WriteResult | RefusalNotRecorded;
/** A-23 defaults (`refusalPolicy` in the owner/runtime options). */
export const REFUSAL_POLICY_DEFAULTS = Object.freeze({ coalesceMs: 60_000, maxPerMinute: 6, recordBudgetMs: 250 });
export type RefusalPolicy = Readonly<{ coalesceMs: number; maxPerMinute: number; recordBudgetMs: number }>;

/** A-23.1: the coalescing key of a refusal (`budgetId ?? null`, `connector.refusalCode ?? null`). */
const coalescingKey = (actorId: unknown, action: unknown, resource: unknown, code: unknown, budgetId: unknown, connectorCode: unknown): string =>
  JSON.stringify([actorId, action, resource, code, budgetId ?? null, connectorCode ?? null]);
/** A-23.1: the actor's latest refusal record, an index rebuilt from the `refusal` records (cached per refusal map and size). */
const latestIndexCache = new WeakMap<object, Readonly<{ size: number; index: Map<string, Rec> }>>();
export const latestRefusalOf = (state: ReplayState, actorId: string): Rec | undefined => {
  const refusals = state.refusals as ReadonlyMap<string, Rec>;
  let cached = latestIndexCache.get(refusals);
  if (cached === undefined || cached.size !== refusals.size) {
    const index = new Map<string, Rec>();
    for (const r of refusals.values()) { const previous = index.get(r.actorId as string); if (previous === undefined || (previous.position as number) < (r.position as number)) index.set(r.actorId as string, r); }
    cached = Object.freeze({ size: refusals.size, index });
    latestIndexCache.set(refusals, cached);
  }
  return cached.index.get(actorId);
};
/** A-23.2: per-actor token buckets, per history file, in this process. */
const buckets = new Map<string, { tokens: number; at: number }>();
const takeToken = (file: string, actorId: string, at: number, perMinute: number): boolean => {
  const key = `${file}\u0000${actorId}`;
  const bucket = buckets.get(key) ?? { tokens: perMinute, at };
  bucket.tokens = Math.min(perMinute, bucket.tokens + Math.max(0, at - bucket.at) * perMinute / 60_000);
  bucket.at = Math.max(bucket.at, at);
  if (bucket.tokens < 1) { buckets.set(key, bucket); return false; }
  bucket.tokens -= 1;
  buckets.set(key, bucket);
  return true;
};
/** TEST ONLY: forget the A-23 rate-limit buckets of this process. */
export const resetRefusalRateLimitsForTests = (): void => buckets.clear();
export type EffectInput = Readonly<{
  /** A raw id; absent → derived (A-37.2) from the signing agent and `operationId` (absent → random). */
  effectId?: string; operationId?: string;
  intentId: string; measurer: Readonly<{ kind: "SESSION" | "CONNECTOR" | "COUNTERPARTY"; id: string }>; metric: string; unit: string;
  amount: string | bigint; observedAt: U53; detailDigest?: ContentHash;
}>;
export type CounterpartyEnvelope = Readonly<{
  version: "irontrellis-counterparty-receipt/2"; historyId: ContentHash; counterpartyId: string; keyId: string; logicalId: string; intentDigest: ContentHash;
  payloadDigest: ContentHash; amount: string | bigint; outcome: "DELIVERED" | "REFUSED" | "UNKNOWN"; observedAt: U53; previousReceiptDigest: ContentHash | null; signature: HexSignature;
}>;
export type CounterpartyReceiptInput = Readonly<{ intentId: string; envelope: CounterpartyEnvelope }>;
/** A-71.6: one provider-stream event as a reconciler saw it. */
export type ObservationInput = Readonly<{
  /** A raw id; absent → derived (A-71.6) from the reconciler and `source`, so a re-emission after a crash gets the same id. */
  observationId?: string;
  /** Optional; when given it must be the handle session's agent (the reconciler). */
  reconcilerAgentId?: string;
  /** The stream, the provider's event reference and the adapter's `sha256` of the event as retrieved (only this digest enters the history). */
  source: Readonly<{ streamId: string; eventRef: string; eventDigest: ContentHash }>;
  /** The call as the provider reports it; an absent `action`, `resource` or `observedAt` is recorded as unsupplied. */
  call: Readonly<{ actorId: string; action?: string; resource?: string; observedAt?: U53; amount?: string | bigint }>;
  /** The decision the event answers to, looked up at the head appended to (absent, or not in the history yet → UNMATCHED). */
  decision?: Readonly<{ intentId: string }> | Readonly<{ refusalId: string }>;
}>;
/** `recordObservation`'s result: the write, the observation id and what was recorded (`equivocates`: the earliest observation of the key with another digest). */
export type ObservationResult = WriteResult & Readonly<{ observationId: string; match: Readonly<{ result: "MATCHED" | "UNMATCHED"; position?: U53 }>; equivocates: U53 | null }>;

export type SessionWrites = Readonly<{
  recordRefusal(input: RefusalInput): Promise<RefusalResult>;
  recordEffect(input: EffectInput): Promise<WriteResult>;
  recordCounterpartyReceipt(input: CounterpartyReceiptInput): Promise<WriteResult>;
  /** A-71.6: a `RECONCILIATION_OBSERVED` signed by this session; `OBSERVATION_DUPLICATE` means "already recorded: advance the checkpoint". */
  recordObservation(input: ObservationInput): Promise<ObservationResult>;
  headroom(input: HeadroomInput): Headroom | null;
  /** A-45.4 (read-only): a counterparty's chain state, or `null` when it was never registered. */
  counterpartyState(counterpartyId: string): CounterpartyState | null;
  /** SPEC §13.3 (read-only, synchronous): the `continuity-attempt-duty-view/1` record of a duty with an active policy, else `null`. */
  inspectDutyPolicy(input: Readonly<{ dutyId: string }>): DutyPolicyView | null;
}>;

const PLACEHOLDER_HASH = `0x${"0".repeat(64)}` as ContentHash;
const PLACEHOLDER_SIGNATURE = `0x${"0".repeat(128)}` as HexSignature;
/** The schema of the finished event, checked with a placeholder signature before anything is signed (INVALID_INPUT with the schema's reason). */
const schemaChecked = (type: CanonicalEvent["type"], data: Rec, what: string): void => {
  const validation = validateEvent({ id: "event:probe", type, timestamp: 0, data }, TRELLIS2_FORMAT, 1);
  if (!validation.ok) throw new IronTrellisError("INVALID_INPUT", false, `${what}: ${validation.reason}`, { code: validation.code });
};
const requestOf = (value: unknown): Rec => {
  const r = record(value, ["actorId", "action", "resource", "claimedAt"], ["amount", "counterpartyId", "termsCommitment", "metric"]);
  const out: Record<string, unknown> = { actorId: identifier(r.actorId), action: identifier(r.action), resource: identifier(r.resource), claimedAt: time(r.claimedAt) };
  if (Object.hasOwn(r, "amount")) out.amount = typeof r.amount === "bigint" ? r.amount.toString() : r.amount;
  for (const key of ["counterpartyId", "termsCommitment", "metric"]) if (Object.hasOwn(r, key)) out[key] = r[key];
  return Object.freeze(out);
};
/** The engine form of a wire request (amount as a bigint) for `authorizeState`. */
const engineRequest = (request: Rec): ActionRequest => Object.freeze({ ...request, ...(typeof request.amount === "string" ? { amount: BigInt(request.amount) } : {}) }) as unknown as ActionRequest;

/**
 * The session-signed writes of a runtime handle over `store` for `sessionId`, signing with `signHash` (already guarded).
 * `session` is the admitted session record the handle was opened with.
 */
/** A-45.4: `{counterpartyId, status, lastReceiptDigest, receiptCount, keyIds}` (minor, non-format). */
export type CounterpartyState = Readonly<{ counterpartyId: string; status: string; lastReceiptDigest: ContentHash | null; receiptCount: number; keyIds: readonly string[] }>;
export function counterpartyStateOf(state: ReplayState, counterpartyId: string): CounterpartyState | null {
  const c = state.counterparties.get(counterpartyId) as Rec | undefined;
  if (c === undefined) return null;
  return Object.freeze({ counterpartyId, status: c.status as string, lastReceiptDigest: (c.lastReceiptDigest ?? null) as ContentHash | null, receiptCount: c.receiptCount as number,
    keyIds: Object.freeze(((c.keys as readonly Rec[] | undefined) ?? []).map((k) => k.keyId as string)) });
}
/** A-37.2 / A-69: the kind literals of derived ids (shared with the Python port). */
export const DERIVED_ID_LITERALS = Object.freeze({ intent: "irontrellis-intent-id/2", effect: "irontrellis-effect-id/2", refusal: "irontrellis-refusal-id/2" } as const);
/**
 * A-37.2: `hashCanonical([<kind literal>, actorId, operationId])` — the id the API derives when the caller supplies none;
 * `operationId` absent → a fresh 128-bit random value. Actor-scoped, so one actor cannot take another's derived ids.
 */
export function derivedId(kind: keyof typeof DERIVED_ID_LITERALS, actorId: string, operationId?: string): string {
  return hashCanonical([DERIVED_ID_LITERALS[kind], actorId, operationId ?? randomBytes(16).toString("hex")], "sha256");
}

export function sessionWrites(store: HistoryStore, config: Config, sessionId: string, session: RuntimeSessionRecord, sign: SignHash): SessionWrites {
  const binding = Object.freeze({ runtimeSessionId: sessionId, credentialKeyId: session.credentialKeyId, controlEpoch: session.controlEpoch });
  const requireFormat2 = (what: string): void => {
    assertWritable(store);
    if (store.format !== TRELLIS2_FORMAT) throw new IronTrellisError("INVALID_INPUT", false, `${what} needs a format-2 history; this file is ${store.format ?? "empty"} (migrate it)`);
  };
  /** The session must be usable at `at` on `state` (SPEC §6.2: agent active in the session's epoch, not expired). */
  const usable = (state: ReplayState, at: number): void => {
    const agent = state.agents.get(session.agentId);
    requireCondition(at >= state.head.canonicalTime, "CLOCK_INVALID");
    // A-149.0: in format 2 a session without expiresAt (a migrated prefix session) is expired after the prefix.
    requireCondition(agent !== undefined && !agent.terminated && agent.currentControlEpoch === session.controlEpoch && !sessionExpiredAt(state, session, at), "RUNTIME_NOT_CURRENT");
  };
  /**
   * Signs `hash`, re-checks the head after the signature and appends `event` at it. T1 and T3 run on the event's shape before
   * the signature is asked for (A-179.4: a writer of an event that would fail T3 does not sign; JOB75-03).
   */
  const signedAppend = async (snapshot: Snapshot, hash: ContentHash, build: (signature: HexSignature) => CanonicalEvent): Promise<WriteResult> => {
    assertSessionWriteTime(snapshot.state, build("0x" as HexSignature), snapshot.head.position + 1);
    const signature = await sign(hash);
    const latest = unchangedSince(store, config, snapshot);
    usable(latest.state, config.now());
    return appendEvent(store, config, latest.state, build(signature), snapshot.head);
  };
  // A-12.5's per-handle fast path (A-23: coalescing against the history is the rule; the fast path reports COALESCED).
  let lastRefusalKey: string | undefined;
  const policy: RefusalPolicy = config.refusalPolicy ?? REFUSAL_POLICY_DEFAULTS;

  const recordRefusal = async (input: RefusalInput): Promise<RefusalResult> => {
    requireFormat2("recordRefusal");
    const r = record(input, ["request"], ["refusalId", "operationId", "source", "connector"]);
    const request = requestOf(r.request);
    requireCondition(r.source === undefined || r.source === "CORE" || r.source === "BUDGET");
    const connector = Object.hasOwn(r, "connector") ? (() => {
      const c = record(r.connector, ["connectorId", "refusalCode", "detailDigest"]);
      return Object.freeze({ connectorId: identifier(c.connectorId), refusalCode: identifier(c.refusalCode), detailDigest: c.detailDigest });
    })() : undefined;
    requireCondition(connector === undefined || r.source === undefined, "INVALID_INPUT");
    const snapshot = snapshotOf(store, config), state = snapshot.state;
    const at = config.now();
    usable(state, at);
    let decision: "DENY" | "INDETERMINATE", code: string, budgetId: string | null = null, source: "CORE" | "BUDGET" | "CONNECTOR";
    if (connector !== undefined) {
      // SPEC §10.1: a CONNECTOR refusal is attested by the connector's own session, not re-derived.
      requireCondition(session.agentId === connector.connectorId, "TRANSITION_REJECTED");
      source = "CONNECTOR"; decision = "DENY"; code = "CONNECTOR_REFUSED";
    } else {
      requireCondition(session.agentId === request.actorId, "TRANSITION_REJECTED");
      const result = authorizeState(state, {
        expectedHistoryHead: snapshot.head, domain: config.domain, policyVersion: state.genesis.policyVersion, rootRecognitionPolicy: ROOT_RECOGNITION_POLICY,
        request: engineRequest(request), evaluationTime: at, consequential: false,
      });
      if (result.decision === "ALLOW") throw new IronTrellisError("REFUSAL_NOT_REPRODUCED", false, "the state ALLOWs this request; a refusal of it would not replay", { decision: "ALLOW" });
      decision = result.decision; code = result.code;
      budgetId = result.decision === "DENY" ? (result.budgetId ?? null) : null;
      source = budgetId === null ? "CORE" : "BUDGET";
      if (r.source !== undefined && r.source !== source) {
        throw new IronTrellisError("REFUSAL_NOT_REPRODUCED", false, `the state refuses with ${decision} ${code} from ${source}, not from ${String(r.source)}`, { decision, code, budgetId, source });
      }
    }
    const key = coalescingKey(request.actorId, request.action, request.resource, code, budgetId, connector?.refusalCode);
    // A-37.2: a caller-supplied raw id, else derived from the actor and the caller's operation id (or a fresh random value).
    const refusalId = Object.hasOwn(r, "refusalId") ? identifier(r.refusalId) : derivedId("refusal", request.actorId as string, Object.hasOwn(r, "operationId") ? identifier(r.operationId) : undefined);
    const existing = state.refusals.get(refusalId) as Rec | undefined;
    if (existing !== undefined) {
      requireCondition(existing.actorId === request.actorId && existing.action === request.action && existing.resource === request.resource && existing.code === code && existing.refusalSource === source, "OPERATION_CONFLICT");
      return Object.freeze({ eventId: existing.eventId as string, head: snapshot.head });
    }
    if (lastRefusalKey === key) return Object.freeze({ recorded: false as const, reason: "COALESCED" });
    // A-23.1: coalesce against the actor's latest refusal record in the history.
    const latest = latestRefusalOf(state, request.actorId as string);
    if (latest !== undefined && at - (latest.evaluationTime as number) < policy.coalesceMs) {
      const latestConnector = (state.events[latest.position as number]?.data as Rec | undefined)?.connector as Rec | undefined;
      if (coalescingKey(latest.actorId, latest.action, latest.resource, latest.code, latest.budgetId, latestConnector?.refusalCode) === key) return Object.freeze({ recorded: false as const, reason: "COALESCED" });
    }
    // A-23.2: the per-actor rate limit.
    if (!takeToken(config.historyFile, request.actorId as string, at, policy.maxPerMinute)) return Object.freeze({ recorded: false as const, reason: "RATE_LIMITED" });
    // A-179.4: a refusal event that would fail rule T3 is not signed; the decision is unaffected.
    if (sessionTimeHorizonFailure(state, { type: "REQUEST_REFUSED", timestamp: at }, snapshot.head.position + 1) !== undefined) return Object.freeze({ recorded: false as const, reason: "SESSION_TIME_HORIZON" });
    const d: Rec = Object.freeze({
      refusalId, refusalSource: source, request, evaluationTime: at, expectedHistoryHead: snapshot.head, decision, code,
      ...(source === "BUDGET" ? { budgetId } : {}), ...(source === "CONNECTOR" ? { connector } : {}), ...binding,
    });
    // A-54 / A-59: the final envelope (id, timestamp) is fixed before the signature.
    const id = newEventId(config);
    const hash = hashCanonical(refusalChallenge(config.domain, d, { id, timestamp: at }), "sha256");
    schemaChecked("REQUEST_REFUSED", { ...d, refusalAuthorization: { hash, signature: PLACEHOLDER_SIGNATURE } }, "recordRefusal");
    // The event's timestamp is its evaluation time (SPEC §10.1); the store refuses it if the head moved meanwhile.
    const result = await signedAppend(snapshot, hash, (signature) => Object.freeze({ id, type: "REQUEST_REFUSED" as const, timestamp: at, data: Object.freeze({ ...d, refusalAuthorization: { hash, signature } }) }));
    lastRefusalKey = key;
    return result;
  };

  const recordEffect = async (input: EffectInput): Promise<WriteResult> => {
    requireFormat2("recordEffect");
    const r = record(input, ["intentId", "measurer", "metric", "unit", "amount", "observedAt"], ["effectId", "operationId", "detailDigest"]);
    const measurer = record(r.measurer, ["kind", "id"]);
    // A-37.2: a caller-supplied raw effectId, else derived from the signing agent and the caller's operation id (or random).
    const effectId = Object.hasOwn(r, "effectId") ? identifier(r.effectId) : derivedId("effect", session.agentId, Object.hasOwn(r, "operationId") ? identifier(r.operationId) : undefined);
    const d: Rec = Object.freeze({
      effectId, intentId: identifier(r.intentId), measurer: { kind: measurer.kind, id: identifier(measurer.id) }, metric: identifier(r.metric), unit: identifier(r.unit),
      amount: typeof r.amount === "bigint" ? r.amount.toString() : r.amount, observedAt: time(r.observedAt), detailDigest: r.detailDigest ?? null, ...binding,
    });
    schemaChecked("EFFECT_RECORDED", { ...d, effectAuthorization: { hash: PLACEHOLDER_HASH, signature: PLACEHOLDER_SIGNATURE } }, "recordEffect");
    const snapshot = snapshotOf(store, config), state = snapshot.state;
    const at = config.now();
    usable(state, at);
    const existing = state.effects.get(d.effectId as string) as Rec | undefined;
    if (existing !== undefined) {
      const same = ["intentId", "metric", "unit", "amount", "observedAt"].every((k) => existing[k] === d[k]) && existing.measurerKind === measurer.kind && existing.measurerId === measurer.id;
      requireCondition(same, "OPERATION_CONFLICT");
      return Object.freeze({ eventId: existing.eventId as string, head: snapshot.head });
    }
    requireCondition((d.observedAt as number) <= at, "CLOCK_INVALID");
    const id = newEventId(config);
    const hash = hashCanonical(effectChallenge(config.domain, d, snapshot.head, { id, timestamp: at }), "sha256");
    return signedAppend(snapshot, hash, (signature) => Object.freeze({ id, type: "EFFECT_RECORDED" as const, timestamp: at, data: Object.freeze({ ...d, effectAuthorization: { hash, signature } }) }));
  };

  const recordCounterpartyReceipt = async (input: CounterpartyReceiptInput): Promise<WriteResult> => {
    requireFormat2("recordCounterpartyReceipt");
    const r = record(input, ["intentId", "envelope"]);
    const envelope = wireAmounts(captureData(r.envelope) as Rec) as Rec;
    const d: Rec = Object.freeze({ intentId: identifier(r.intentId), envelope, ...binding });
    schemaChecked("COUNTERPARTY_RECEIPT_RECORDED", { ...d, recordAuthorization: { hash: PLACEHOLDER_HASH, signature: PLACEHOLDER_SIGNATURE } }, "recordCounterpartyReceipt");
    const snapshot = snapshotOf(store, config), state = snapshot.state;
    const at = config.now();
    usable(state, at);
    const digest = envelopeDigest(envelope);
    // Idempotent re-record: the chain already holds this envelope (it is the counterparty's latest or an earlier one).
    for (let position = state.head.position; position >= 1; position -= 1) {
      const event = state.events[position]!;
      if (event.type !== "COUNTERPARTY_RECEIPT_RECORDED") continue;
      if (envelopeDigest(event.data.envelope as Rec) === digest) {
        requireCondition(event.data.intentId === d.intentId, "OPERATION_CONFLICT");
        return Object.freeze({ eventId: event.id, head: snapshot.head });
      }
    }
    // A-45.2: the writer never advances its own time to admit an envelope observed later; the counterparty re-issues.
    if (typeof envelope.observedAt === "number" && envelope.observedAt > at) {
      throw new IronTrellisError("INVALID_INPUT", false, `the envelope was observed at ${envelope.observedAt}, after this writer's time ${at}; the counterparty re-issues it (A-45.2)`, { reason: "OBSERVED_AT_AHEAD" });
    }
    const id = newEventId(config);
    const hash = hashCanonical(counterpartyRecordChallenge(config.domain, d, snapshot.head, { id, timestamp: at }), "sha256");
    return signedAppend(snapshot, hash, (signature) => Object.freeze({ id, type: "COUNTERPARTY_RECEIPT_RECORDED" as const, timestamp: at, data: Object.freeze({ ...d, recordAuthorization: { hash, signature } }) }));
  };

  const recordObservation = async (input: ObservationInput): Promise<ObservationResult> => {
    requireFormat2("recordObservation");
    const r = record(input, ["source", "call"], ["observationId", "reconcilerAgentId", "decision"]);
    requireCondition(!Object.hasOwn(r, "reconcilerAgentId") || identifier(r.reconcilerAgentId) === session.agentId, "TRANSITION_REJECTED");
    const s = record(r.source, ["streamId", "eventRef", "eventDigest"]);
    const source = Object.freeze({ streamId: identifier(s.streamId), eventRef: identifier(s.eventRef), eventDigest: contentHash(s.eventDigest) });
    const c = record(r.call, ["actorId"], ["action", "resource", "observedAt", "amount"]);
    const call: Record<string, unknown> = { actorId: identifier(c.actorId) };
    if (Object.hasOwn(c, "action")) call.action = identifier(c.action);
    if (Object.hasOwn(c, "resource")) call.resource = c.resource;
    if (Object.hasOwn(c, "observedAt")) call.observedAt = time(c.observedAt);
    if (Object.hasOwn(c, "amount")) call.amount = typeof c.amount === "bigint" ? c.amount.toString() : c.amount;
    call.unsupplied = OBSERVATION_UNSUPPLIABLE.filter((name) => !Object.hasOwn(c, name));
    const decision = Object.hasOwn(r, "decision") ? record(r.decision, [], ["intentId", "refusalId"]) : undefined;
    requireCondition(decision === undefined || Object.keys(decision).length === 1);
    const observationId = Object.hasOwn(r, "observationId") ? identifier(r.observationId) : derivedObservationId(session.agentId, source);
    const snapshot = snapshotOf(store, config), state = snapshot.state;
    const at = config.now();
    usable(state, at);
    // A-86.2: an accepted observation of this (streamId, eventRef, eventDigest) — a re-emission — is OBSERVATION_DUPLICATE, before signing.
    const accepted = observationIndexOf(state, source.streamId, source.eventRef)?.digests[source.eventDigest];
    if (accepted !== undefined) {
      const event = state.events[accepted]!;
      throw new IronTrellisError("OBSERVATION_DUPLICATE", false, `an observation of ${source.streamId}/${source.eventRef} with this digest is already recorded at position ${accepted}; advance the checkpoint (A-86)`,
        { position: accepted, eventId: event.id, observationId: event.data.observationId });
    }
    requireCondition(!state.reconciliationObservations.has(observationId), "OPERATION_CONFLICT");
    // The match, at the head appended to: the intent's admission or the refusal, when the history holds it (else UNMATCHED).
    const matched = decision === undefined ? undefined
      : Object.hasOwn(decision, "intentId") ? state.intentAdmissions.get(identifier(decision.intentId))?.admissionEventPosition
      : (state.refusals.get(identifier(decision.refusalId)) as Rec | undefined)?.position as U53 | undefined;
    if (matched !== undefined) {
      const cited = state.events[matched]!.data as Rec;
      const actor = cited.authorizationProof === undefined ? (cited.request as Rec).actorId : ((cited.authorizationProof as Rec).request as Rec).actorId;
      requireCondition(actor === call.actorId, "TRANSITION_REJECTED");
    }
    const match = Object.freeze(matched === undefined ? { result: "UNMATCHED" as const } : { result: "MATCHED" as const, position: matched });
    const d: Rec = Object.freeze({ observationId, reconcilerAgentId: session.agentId, source, call: Object.freeze(call), match, expectedHistoryHead: snapshot.head, ...binding });
    const id = newEventId(config);
    const hash = hashCanonical(reconciliationChallenge(config.domain, d, { id, timestamp: at }), "sha256");
    schemaChecked("RECONCILIATION_OBSERVED", { ...d, observationAuthorization: { hash, signature: PLACEHOLDER_SIGNATURE } }, "recordObservation");
    const equivocates = observationIndexOf(state, source.streamId, source.eventRef)?.earliest ?? null;
    const result = await signedAppend(snapshot, hash, (signature) => Object.freeze({ id, type: "RECONCILIATION_OBSERVED" as const, timestamp: at, data: Object.freeze({ ...d, observationAuthorization: { hash, signature } }) }));
    return Object.freeze({ ...result, observationId, match, equivocates });
  };

  return Object.freeze({
    recordRefusal, recordEffect, recordCounterpartyReceipt, recordObservation,
    /** A-45.4: the counterparty's chain state, or `null` when it was never registered. */
    counterpartyState(counterpartyId: string): CounterpartyState | null { return counterpartyStateOf(snapshotOf(store, config).state, identifier(counterpartyId)); },
    /**
     * A-43.2: a runtime handle's headroom answers only for budgets a request by its own actor at `at` could match
     * (other ids are `null`, as if unknown). A-43.1: a runtime handle has no `exportView` (owner and auditor handles only).
     */
    headroom(input: HeadroomInput): Headroom | null {
      const r = record(input, ["budgetId"], ["at"]);
      const snapshot = snapshotOf(store, config);
      assertFresh(snapshot);
      const budgetId = identifier(r.budgetId), at = Object.hasOwn(r, "at") ? time(r.at) : config.now();
      const budget = snapshot.state.budgets.get(budgetId) as BudgetRecord | undefined;
      if (budget === undefined || !budgetConcernsActor(snapshot.state, budget, session.agentId, at)) return null;
      return headroomState(snapshot.state, budgetId, at) as Headroom | null;
    },
    inspectDutyPolicy(input) { return inspectDutyPolicyOf(snapshotOf(store, config).state, input); },
  });
}
