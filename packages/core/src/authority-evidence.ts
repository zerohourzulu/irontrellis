/**
 * Result shaping for the authority engine: evidence references, their exact
 * ordering, failure sorting and the bounded result envelopes (spec 02 §6).
 *
 * Every evidence list is "events matching a predicate, plus the head event,
 * sorted by event id (byte order) and de-duplicated" — the head therefore
 * appears even when its type is outside the predicate. The ordering is by id
 * string, not by position, because that is what the legacy engine emits.
 *
 * The format-dependent lists are the decision evidence of candidate-path,
 * NO_AUTHORITY and global PROHIBITED denials, and the INTENT_REQUIRED denial:
 * legacy states cite every authority event (`decisionEvidence`, spec 02 §6.2)
 * and every intent of the actor, byte-for-byte parity; format-1 states cite
 * only the events relevant to the request (`narrowedDecisionEvidence`), under
 * the same ordering rule and output budget.
 */
import type {
  AuthorizationResult, CanonicalEvent, ContentHash, DenialCode, DenialEvidence, EvidenceReference, IndeterminateCode, ReplayState, ScopeAssurance
} from "./types.ts";
import { compareProtocolStrings } from "./canonical.ts";
import { readonlySet } from "./readonly-collections.ts";

export const MAX_RESULT_EVIDENCE = 4096;

/**
 * UTF-8 byte order equals code-point order, which equals UTF-16 code-unit order
 * except when a surrogate (D800–DFFF) meets a unit in E000–FFFF. The fast path
 * compares code units and only defers to the canonical comparator on that edge.
 */
export function compareIds(left: string, right: string): number {
  if (left === right) return 0;
  const shared = left.length < right.length ? left.length : right.length;
  for (let i = 0; i < shared; i += 1) {
    const a = left.charCodeAt(i);
    const b = right.charCodeAt(i);
    if (a === b) continue;
    if (a < 0xd800 && b < 0xd800) return a - b;
    if ((a >= 0xd800 && a < 0xe000) || (b >= 0xd800 && b < 0xe000)) return compareProtocolStrings(left, right);
    return a - b;
  }
  return left.length - right.length;
}

export function compareIdSequences(left: readonly string[], right: readonly string[]): number {
  const shared = left.length < right.length ? left.length : right.length;
  for (let i = 0; i < shared; i += 1) {
    const c = compareIds(left[i] as string, right[i] as string);
    if (c !== 0) return c;
  }
  return left.length - right.length;
}

const compareOptionalId = (left: string | undefined, right: string | undefined): number =>
  left === undefined ? (right === undefined ? 0 : -1) : right === undefined ? 1 : compareIds(left, right);

export function compareEvidenceReferences(left: EvidenceReference, right: EvidenceReference): number {
  let c = compareIds(left.eventId, right.eventId);
  if (c !== 0) return c;
  c = compareIds(left.eventType, right.eventType);
  if (c !== 0) return c;
  if (left.position !== right.position) return left.position - right.position;
  return compareIds(left.historyHash, right.historyHash);
}

const compareEvidenceSequences = (left: readonly EvidenceReference[], right: readonly EvidenceReference[]): number => {
  const shared = left.length < right.length ? left.length : right.length;
  for (let i = 0; i < shared; i += 1) {
    const c = compareEvidenceReferences(left[i] as EvidenceReference, right[i] as EvidenceReference);
    if (c !== 0) return c;
  }
  return left.length - right.length;
};

/** Rank of the candidate-path failure codes; every other denial code ranks −1 (spec 02 §6.1). */
export const FAILURE_RANK: Readonly<Record<string, number>> = Object.freeze({
  PROHIBITED: 0,
  REVOKED: 1,
  NOT_YET_VALID: 2,
  EXPIRED: 3,
  MISSING_INTERSECTION: 4,
  ACTION_NOT_ALLOWED: 5,
  RESOURCE_NOT_ALLOWED: 6,
  AMOUNT_REQUIRED: 7,
  AMOUNT_EXCEEDED: 8,
  CUMULATIVE_AMOUNT_EXCEEDED: 9,
  AMOUNT_OVERFLOW: 10, // G6.5 A-135.1: a candidate failure set since G6.5
  TRANSACTION_COUNT_EXCEEDED: 11,
  NO_AUTHORITY: 12,
});

export function compareDenialEvidence(left: DenialEvidence, right: DenialEvidence): number {
  const lr = FAILURE_RANK[left.code] ?? -1;
  const rr = FAILURE_RANK[right.code] ?? -1;
  if (lr !== rr) return lr - rr;
  let c = compareOptionalId(left.rootAuthorityId, right.rootAuthorityId);
  if (c !== 0) return c;
  c = compareOptionalId(left.terminalAuthorityId, right.terminalAuthorityId);
  if (c !== 0) return c;
  c = compareOptionalId(left.failingAuthorityId, right.failingAuthorityId);
  if (c !== 0) return c;
  c = compareIdSequences(left.authorityPathIds, right.authorityPathIds);
  if (c !== 0) return c;
  c = compareOptionalId(left.subjectId, right.subjectId);
  return c !== 0 ? c : compareEvidenceSequences(left.evidence, right.evidence);
}

// ---------------------------------------------------------------- replay evidence

export type EvidenceContext = {
  readonly state: ReplayState;
  readonly refs: (EvidenceReference | undefined)[];
  /** Positions of the events `authorityDecisionEvidence` selects; appended as the state grows. */
  readonly decisionPositions: number[];
  /** The sorted decision evidence (legacy variant), memoised until the state grows. */
  decision: readonly EvidenceReference[] | undefined;
  /**
   * Formats 1 and 2: the decision evidence is narrowed to the request (see
   * `narrowedDecisionEvidence`), so instead of one memoised list the context
   * keeps a per-actor index of lifecycle event positions, grown with the state.
   */
  readonly narrowed: boolean;
  readonly lifecycleByAgent: Map<string, number[]>;
};

export const DECISION_TYPES: ReadonlySet<string> = readonlySet([
  "DEPLOYMENT_INITIALIZED",
  "PRINCIPAL_CREATED",
  "AGENT_CREATED",
  "AGENT_TERMINATED",
  "AUTHORITY_GRANTED",
  "AUTHORITY_REVOKED",
  "TRANSACTION_INTENT_ADMITTED",
]);
const TENURE_TYPES: ReadonlySet<string> = new Set(["ROLE_CREATED", "AGENT_APPOINTED", "AGENT_UNAPPOINTED", "ROLE_TRANSFERRED"]);

export function createEvidenceContext(state: ReplayState): EvidenceContext {
  const hashes = state.eventHistoryHashes;
  if (hashes.length !== state.events.length || hashes[hashes.length - 1] !== state.head.hash) {
    throw new TypeError("Replay evidence prefix commitments disagree with the authoritative state head.");
  }
  const ctx: EvidenceContext = {
    state,
    refs: [],
    decisionPositions: [],
    decision: undefined,
    // Formats 1 and 2 narrow; format 2 keeps the format-1 decision semantics (BUILD §4: answers equal to the format-1 twin).
    narrowed: state.format === "irontrellis-event/1" || state.format === "irontrellis-event/2",
    lifecycleByAgent: new Map(),
  };
  for (let i = 0; i < state.events.length; i += 1) noteEvidenceEvent(ctx, i);
  return ctx;
}

/** Actor lifecycle for the narrowed decision evidence: creation, termination and control-epoch advances. */
const ACTOR_LIFECYCLE_TYPES: ReadonlySet<string> = new Set(["AGENT_CREATED", "AGENT_TERMINATED", "CONTROL_EPOCH_ADVANCED"]);

/** Registers one appended event (incremental growth). The head is always part of the decision evidence, so it is always stale. */
export function noteEvidenceEvent(ctx: EvidenceContext, position: number): void {
  const event = ctx.state.events[position] as CanonicalEvent;
  if (DECISION_TYPES.has(event.type)) ctx.decisionPositions.push(position);
  if (ctx.narrowed && ACTOR_LIFECYCLE_TYPES.has(event.type) && typeof event.data.agentId === "string") {
    const list = ctx.lifecycleByAgent.get(event.data.agentId);
    if (list === undefined) ctx.lifecycleByAgent.set(event.data.agentId, [position]);
    else list.push(position);
  }
  ctx.decision = undefined;
}

export function eventReference(ctx: EvidenceContext, position: number): EvidenceReference {
  const cached = ctx.refs[position];
  if (cached !== undefined) return cached;
  const event = ctx.state.events[position] as CanonicalEvent;
  const historyHash = ctx.state.eventHistoryHashes[position] as ContentHash;
  const ref: EvidenceReference = Object.freeze({ kind: "EVENT", eventId: event.id, eventType: event.type, position, historyHash });
  ctx.refs[position] = ref;
  return ref;
}

const sameReference = (a: EvidenceReference, b: EvidenceReference): boolean =>
  a.eventId === b.eventId && a.eventType === b.eventType && a.position === b.position && a.historyHash === b.historyHash;

export function sortedDistinctReferences(refs: EvidenceReference[]): readonly EvidenceReference[] {
  refs.sort(compareEvidenceReferences);
  const out: EvidenceReference[] = [];
  for (const ref of refs) {
    if (out.length === 0 || !sameReference(out[out.length - 1] as EvidenceReference, ref)) out.push(ref);
  }
  return Object.freeze(out);
}

export function evidenceWhere(ctx: EvidenceContext, predicate: (event: CanonicalEvent) => boolean): readonly EvidenceReference[] {
  const events = ctx.state.events;
  const refs: EvidenceReference[] = [];
  for (let i = 0; i < events.length; i += 1) {
    if (predicate(events[i] as CanonicalEvent)) refs.push(eventReference(ctx, i));
  }
  refs.push(eventReference(ctx, events.length - 1));
  return sortedDistinctReferences(refs);
}

export function decisionEvidence(ctx: EvidenceContext): readonly EvidenceReference[] {
  if (ctx.decision === undefined) {
    const refs = ctx.decisionPositions.map((p) => eventReference(ctx, p));
    refs.push(eventReference(ctx, ctx.state.events.length - 1));
    ctx.decision = sortedDistinctReferences(refs);
  }
  return ctx.decision;
}

/** Length of `decisionEvidence` without building it: the decision events plus the head unless it is one. */
export const decisionEvidenceLength = (ctx: EvidenceContext): number =>
  ctx.decisionPositions.length + (DECISION_TYPES.has((ctx.state.events[ctx.state.events.length - 1] as CanonicalEvent).type) ? 0 : 1);

const isAgentLifecycle = (e: CanonicalEvent, actorId: string): boolean =>
  (e.type === "AGENT_CREATED" || e.type === "AGENT_TERMINATED") && e.data.agentId === actorId;

export const agentLifecycleEvidence = (ctx: EvidenceContext, actorId: string): readonly EvidenceReference[] =>
  evidenceWhere(ctx, (e) => isAgentLifecycle(e, actorId));

type EventPredicate = (event: CanonicalEvent) => boolean;

const sessionLifecyclePredicate = (actorId: string, sessionId: string): EventPredicate => (e) =>
  isAgentLifecycle(e, actorId) ||
  ((e.type === "RUNTIME_SESSION_ADMITTED" || e.type === "CONTROL_EPOCH_ADVANCED") && (e.data.agentId === actorId || e.data.sessionId === sessionId));

const tenureLifecyclePredicate = (roleId: string, tenureId: string): EventPredicate => (e) =>
  TENURE_TYPES.has(e.type) &&
  (e.data.roleId === roleId || e.data.roleTenureId === tenureId || e.data.fromRoleTenureId === tenureId || e.data.toRoleTenureId === tenureId);

export const sessionLifecycleEvidence = (ctx: EvidenceContext, actorId: string, sessionId: string): readonly EvidenceReference[] =>
  evidenceWhere(ctx, sessionLifecyclePredicate(actorId, sessionId));

export const tenureLifecycleEvidence = (ctx: EvidenceContext, roleId: string, tenureId: string): readonly EvidenceReference[] =>
  evidenceWhere(ctx, tenureLifecyclePredicate(roleId, tenureId));

const isRecord = (v: unknown): v is Readonly<Record<string, unknown>> => v !== null && typeof v === "object" && !Array.isArray(v);

/** `{intentId, actorId, nonce}` as recorded by a declaration or an admission (spec 02 §6.2). */
const intentValues = (e: CanonicalEvent): { intentId?: unknown; actorId?: unknown; nonce?: unknown } => {
  if (e.type === "TRANSACTION_INTENT_DECLARED") return { intentId: e.data.intentId, actorId: e.data.actorId, nonce: e.data.nonce };
  const proof = isRecord(e.data.authorizationProof) ? e.data.authorizationProof : undefined;
  const request = proof !== undefined && isRecord(proof.request) ? proof.request : undefined;
  return { intentId: e.data.intentId, actorId: request?.actorId, nonce: proof?.nonce };
};

const intentDecisionPredicate = (actorId: string, intentId?: string, nonce?: string): EventPredicate => (e) => {
  if (e.type !== "TRANSACTION_INTENT_DECLARED" && e.type !== "TRANSACTION_INTENT_ADMITTED") return false;
  const v = intentValues(e);
  const selected = intentId === undefined ? v.actorId === actorId : v.intentId === intentId;
  return selected || (nonce !== undefined && v.actorId === actorId && v.nonce === nonce);
};

export const intentDecisionEvidence = (
  ctx: EvidenceContext,
  actorId: string,
  intentId?: string,
  nonce?: string,
): readonly EvidenceReference[] => evidenceWhere(ctx, intentDecisionPredicate(actorId, intentId, nonce));

/** The consequential control tuple whose session, tenure and intent evidence a narrowed decision cites. */
export type EvidenceBinding = Readonly<{ runtimeSessionId: string; roleId: string; roleTenureId: string; intentId?: string; nonce?: string }>;

/**
 * Format-1 and format-2 decision evidence (replaces `authorityDecisionEvidence`, which cites
 * every authority event of the history): the genesis, the head, the actor's
 * lifecycle (AGENT_CREATED, AGENT_TERMINATED, CONTROL_EPOCH_ADVANCED), the
 * caller-selected authority event positions (grants and revocations of the
 * candidate paths, their intersection partners and the prohibitions
 * considered) and, with a binding, the session/tenure/intent evidence the
 * binding-specific denials cite. Same ordering rule: sorted by event id, deduplicated.
 */
export function narrowedDecisionEvidence(
  ctx: EvidenceContext,
  actorId: string,
  authorityPositions: readonly number[],
  binding?: EvidenceBinding,
): readonly EvidenceReference[] {
  const refs: EvidenceReference[] = [eventReference(ctx, 0)];
  for (const p of ctx.lifecycleByAgent.get(actorId) ?? []) refs.push(eventReference(ctx, p));
  for (const p of authorityPositions) refs.push(eventReference(ctx, p));
  if (binding !== undefined) {
    const session = sessionLifecyclePredicate(actorId, binding.runtimeSessionId);
    const tenure = tenureLifecyclePredicate(binding.roleId, binding.roleTenureId);
    const intent = intentDecisionPredicate(actorId, binding.intentId, binding.nonce);
    const events = ctx.state.events;
    for (let i = 0; i < events.length; i += 1) {
      const e = events[i] as CanonicalEvent;
      if (session(e) || tenure(e) || intent(e)) refs.push(eventReference(ctx, i));
    }
  }
  refs.push(eventReference(ctx, ctx.state.events.length - 1));
  return sortedDistinctReferences(refs);
}

/** The first event with `eventId` plus the head (admission-id collisions). */
export function collidingEventEvidence(ctx: EvidenceContext, eventId: string): readonly EvidenceReference[] {
  const refs: EvidenceReference[] = [];
  const index = ctx.state.events.findIndex((e) => e.id === eventId);
  if (index >= 0) refs.push(eventReference(ctx, index));
  refs.push(eventReference(ctx, ctx.state.events.length - 1));
  return sortedDistinctReferences(refs);
}

// ---------------------------------------------------------------- result envelopes

const NO_EVIDENCE: readonly EvidenceReference[] = Object.freeze([]);
const NO_IDS: readonly string[] = Object.freeze([]);

export function indeterminate(
  operationVersion: string,
  code: IndeterminateCode,
  assurance: ScopeAssurance = "SUPPLIED_SCOPE",
  evidence: readonly EvidenceReference[] = NO_EVIDENCE,
  subjectId?: string,
): AuthorizationResult {
  return Object.freeze({
    operationVersion,
    decision: "INDETERMINATE",
    scopeAssurance: assurance,
    consequential: false,
    code,
    failures: Object.freeze([Object.freeze({ code, ...(subjectId === undefined ? {} : { subjectId }), evidence })]),
  });
}

/** Sorts the failures (spec 02 §6.1); the headline code is the first failure's code. */
export function denialResult(operationVersion: string, assurance: ScopeAssurance, failures: DenialEvidence[]): AuthorizationResult {
  failures.sort(compareDenialEvidence);
  return Object.freeze({
    code: (failures[0] as DenialEvidence).code,
    consequential: false,
    decision: "DENY",
    failures: Object.freeze(failures),
    operationVersion,
    scopeAssurance: assurance,
  });
}

export const simpleDenial = (
  operationVersion: string,
  assurance: ScopeAssurance,
  code: DenialCode,
  evidence: readonly EvidenceReference[] = NO_EVIDENCE,
  subjectId?: string,
): AuthorizationResult =>
  denialResult(operationVersion, assurance, [
    Object.freeze({ authorityPathIds: NO_IDS, code, evidence, ...(subjectId === undefined ? {} : { subjectId }) }),
  ]);

/** A DENY/INDETERMINATE whose evidence references exceed the output budget collapses to OUTPUT_LIMIT_EXCEEDED. */
export function boundedResult(result: AuthorizationResult, operationVersion: string, assurance: ScopeAssurance): AuthorizationResult {
  if (result.decision === "ALLOW") return result;
  let count = 0;
  for (const failure of result.failures) {
    count += failure.evidence.length;
    if (count > MAX_RESULT_EVIDENCE) return indeterminate(operationVersion, "OUTPUT_LIMIT_EXCEEDED", assurance);
  }
  return result;
}
