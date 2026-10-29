/**
 * Replay state model and the per-type transitions (spec 01 §D.4, §D.7, §D.8,
 * §D.10–D.13; spec 03 §K). The state is mutated in place by the reducer in
 * `replay.ts`; every transition checks all of its preconditions before writing,
 * so a rejected event leaves the state untouched. Records inside the maps are
 * replaced, never mutated, so snapshots handed out earlier stay valid.
 */
import { amountOf, canonicalEncode, compareProtocolStrings, parseAmountString } from "./canonical.ts";
import { createHistoryHasher, hashCanonical, HistoryHasher, type PrefixHasher } from "./hash.ts";
import { counterpartyRecordChallenge, effectChallenge, envelopeSigningHash, envelopeDigest, intentDeclarationHash, lifecycleAuthorizationHash, reconciliationChallenge, refusalChallenge, sessionAuthorizationFailure, sessionFailureCode, type LifecycleAuthorization, type SessionBinding } from "./session-auth.ts";
import { chargedUsage, closedBudgetRecord, declaredBudgetRecord, updatedBudgetRecord, usageKey, type BudgetRecord } from "./budgets.ts";
import { suiteFor } from "./crypto/suites.ts";
import { authorizeState } from "./authority.ts";
import {
  type AdapterIdentity, evaluateAdapterAcknowledgment, evaluateAdapterNoEffect, policyEnablesAttemptDuties, policyEnablesAttemptReviews,
  REMOTE_SERVICE_REPORT_ADAPTER_ID, resolveAdapterPolicy, sameAdapterEvidence, SIMULATED_ADAPTER_ID, validateAdapterAcknowledgment, validateAdapterProfileForPolicy,
} from "./adapter-editions.ts";
import { controlEffect, hashAlgorithmOf, isFormat2, LEGACY_FORMAT, MAX_BOUND_WITNESSES, ownerKeyDigest, sessionCredential, TRELLIS2_FORMAT, dutyLiteralFailure } from "./events.ts";
import { ownerKeyEpochAt, ownerKeyEventTransition } from "./owner-keys.ts";
import { credentialId } from "./owner-policy.ts";
import {
  dutyPolicyActivationProofMatches, dutyPolicyActivationRequirements, dutyRequirements, validateDutyFinding,
  type DutyPolicyActivatedEffect, type DutyUnsignedTransition,
} from "./duty-policy.ts";
import { verifyWitnessReceipt, type WitnessReceipt } from "./transparency/receipt.ts";
import { reconciliationCursorKey, type RecordChange } from "./state-records.ts";
import { lazyStateRoots, RootLog } from "./state-roots.ts";
import type {
  AdministrativeRequirements, AgentRecord, AttemptDutyRecord, BoundPolicy, BoundWitness, AttemptDutyReview, AttemptDutyState, AuthorityConstraints, AuthorityGrant, AuthorityRecord, AuthorityUsage, AuthorizationProof,
  CanonicalEvent, ContentHash, DutyDispositionRefRecord, DutyPolicyActivationRecord, EventType, EvidenceReference, GenesisRecord, HistoryFormat, HistoryHead, IntentAdmissionRecord,
  IntentConsumptionRecord, IntentDeclarationRecord, IntentOutcomeState, MigratedFrom, NonceRecord, NonceReservation, ObligationRecord, ObligationState,
  ObligationTransitionPolicy, OutcomeObservationRecord, OutcomeRecord, OwnerKey, OwnerKeyEpoch, PermissionGrant, PrincipalRecord, ReceiptCommitmentRecord, RecognizedRoot,
  ReplayCode, ReplayState, RoleRecord, RoleTenureRecord, RuntimeSessionRecord, SignatureScheme, StateRecordEntry, SuccessionRuleData, TransactionIntent, U53, UsageCounter,
} from "./types.ts";

export type AnchorRecord = Readonly<{ head: HistoryHead; anchor: string; eventId: string; eventPosition: U53 }>;
export type IntentAdmissionValidation =
  | Readonly<{ ok: true; admission: IntentAdmissionRecord; usage: readonly AuthorityUsage[] }>
  | Readonly<{ ok: false; reason: string }>;
export type AdministrativeValidation = Readonly<{ ok: true }> | Readonly<{ ok: false; reason: string }>;
/** The signed-transition validators replay delegates to (spec 02 §7.4, §7.6); injected so the authority engine can load lazily. */
export type ReplayHooks = Readonly<{
  validateIntentAdmissionTransition: (state: ReplayState, event: CanonicalEvent, position: U53, nextHead: HistoryHead) => IntentAdmissionValidation;
  validateAdministrativeTransition: (state: ReplayState, event: CanonicalEvent, position: U53, requirements: AdministrativeRequirements) => AdministrativeValidation;
}>;

/**
 * The legacy "shadow" of a migrated prefix (docs/HISTORY-FORMAT.md §11): the source's prefix
 * hashes rebuilt from the verbatim re-recorded events, and a view of the state
 * whose head, domain, genesis, format and hash algorithm are the source's, so
 * that runtime-signed events at positions 1..`until` validate exactly as they
 * did in the source. Maps and events are shared with the real state.
 */
export type ShadowContext = {
  readonly view: MutableReplayState;
  hasher: HistoryHasher;
  readonly hashes: ContentHash[];
  readonly until: U53;
  readonly expectedHash: ContentHash;
  /** The source format (legacy for a format-1 host; legacy or format 1 for a format-2 host, SPEC §16.2 step 3). */
  readonly sourceFormat: HistoryFormat;
  /**
   * Format-2 host only: the prefix events as the source held them (the inversion of the transcription, SPEC §16.2 step
   * 3), the view's `events`; the real state keeps the transcribed events. Emptied once the prefix is complete.
   */
  readonly events: CanonicalEvent[] | undefined;
};

export interface MutableReplayState extends ReplayState {
  signatureScheme: SignatureScheme;
  events: CanonicalEvent[];
  eventHistoryHashes: ContentHash[];
  eventPositionsById: Map<string, U53>;
  head: HistoryHead;
  genesis: GenesisRecord;
  /** The prefix hasher of the format: the wrapper hasher (legacy, format 1) or the record chain (format 2). */
  hasher: PrefixHasher;
  lastTimestamp: number | undefined;
  /**
   * A-179.2: `ownerTime` at the head, a derived index (not a state record): the timestamp of the latest accepted control
   * event that advanced time, or the genesis timestamp; rebuilt from the `event` records on a resume (`state-rebuild.ts`).
   */
  ownerTime: number | undefined;
  principals: Map<string, PrincipalRecord>;
  agents: Map<string, AgentRecord>;
  reservedAgentIds: Map<string, Set<string>>;
  roles: Map<string, RoleRecord>;
  successionRules: Map<string, Readonly<{ data: SuccessionRuleData }>>;
  tenures: Map<string, RoleTenureRecord>;
  currentTenureIdsByAgent: Map<string, Set<string>>;
  runtimeSessions: Map<string, RuntimeSessionRecord>;
  runtimeSessionIdsByAgent: Map<string, string[]>;
  credentialKeyIds: Set<string>;
  credentialAddressKeysByAgent: Map<string, Set<string>>;
  intentDeclarations: Map<string, IntentDeclarationRecord>;
  intentAdmissions: Map<string, IntentAdmissionRecord>;
  intentConsumptions: Map<string, IntentConsumptionRecord>;
  intentOutcomeStates: Map<string, IntentOutcomeState>;
  outcomeObservations: Map<string, readonly OutcomeObservationRecord[]>;
  attemptDuties: Map<string, AttemptDutyState>;
  attemptDutyReviews: Map<string, readonly AttemptDutyReview[]>;
  attemptDutyIdsBySourceIntent: Map<string, string>;
  /** SPEC §13 (E4): active duty policies by dutyId and, per duty, the accepted dispositions and contests in position order. */
  attemptDutyPolicies: Map<string, DutyPolicyActivationRecord>;
  attemptDutyDispositions: Map<string, readonly DutyDispositionRefRecord[]>;
  receiptCommitments: Map<string, ReceiptCommitmentRecord>;
  obligations: Map<string, ObligationState>;
  obligationIdsBySourceIntent: Map<string, string>;
  nonceReservationsByActor: Map<string, Map<string, NonceReservation>>;
  authorities: Map<string, AuthorityRecord>;
  recognizedRoots: Map<string, RecognizedRoot>;
  authorityUsage: Map<string, AuthorityUsage>;
  anchors: AnchorRecord[];
  ownerKeyEpochs: OwnerKeyEpoch[];
  /** Replaced (never mutated) by each binding event, so snapshots and forks share it safely. */
  boundWitnesses: readonly BoundWitness[];
  boundPolicy: BoundPolicy | undefined;
  /** Position of each intent's declaration event: lets OBLIGATION_CREATED avoid rescanning the history. */
  declarationPositions: Map<string, U53>;
  shadow: ShadowContext | undefined;
  shadowHashes?: readonly ContentHash[];
  /**
   * Set on the shadow *view* of a format-2 host only: the view carries the source's format, domain, heads and hashing
   * (so the verbatim runtime-signed structures validate as in the source) while the transitions keep the format-2
   * bookkeeping (record references, nonce records, usage counters) on the shared maps.
   */
  readonly prefixOfFormat2?: true;
  /** Format 2: the records the last accepted event created, changed or removed (`applyStateRecords`); the store's snapshot journal takes them. */
  lastRecordChanges?: readonly RecordChange[] | undefined;
  // ---- format 2 (SPEC §7, §9–§12)
  recordRefs: Map<string, Rec>;
  nonceRecords: Map<string, NonceRecord>;
  usageCounters: Map<string, UsageCounter>;
  stateRecords: Map<string, StateRecordEntry>;
  /** The record keys (`kind\u0000key`) in (kind, key) byte order: the leaf order of SPEC §7.1. */
  sortedRecordKeys: string[];
  /** `rootAt(p)` by position, computed on first read by `rootLog` (an array-shaped view; `state-roots.ts`). */
  stateRoots: ContentHash[];
  /** Format 2: the per-position undo lists, the roots computed so far and the head's aligned-subtree cache (A-67). */
  rootLog: RootLog;
  projectionHeads: ContentHash[];
  /** The position of the newest witness binding event (the `witnessPolicy` record's `position`). */
  boundPolicyPosition?: U53;
  budgets: Map<string, Readonly<Record<string, unknown>>>;
  budgetUsage: Map<string, Readonly<Record<string, unknown>>>;
  counterparties: Map<string, Readonly<Record<string, unknown>>>;
  refusals: Map<string, Readonly<Record<string, unknown>>>;
  effects: Map<string, Readonly<Record<string, unknown>>>;
  /** A-71.4: the `observation` and `reconciliation-cursor` records (the `(streamId, eventRef)` index lives in `recordRefs`, `observationIndexKey`). */
  reconciliationObservations: Map<string, Readonly<Record<string, unknown>>>;
  reconciliationCursors: Map<string, Readonly<Record<string, unknown>>>;
  // ---- format 2 capacity ledger (SPEC §5.2; `capacity.ts CapacityLedger`)
  canonicalBytes: number;
  capacityIntents: Map<string, Set<EventType>>;
  capacityDuties: Map<string, string>;
  capacityObligations: Map<string, string>;
  capacityDutyQuota: Map<string, Readonly<{ dispositions: number; contests: number }>>;
  lifecycleReserved: number;
  dutyReserved: number;
}

/** Placeholders until the genesis is applied; nothing reads them before `events.length > 0`. */
export const EMPTY_HEAD: HistoryHead = Object.freeze({ hash: `0x${"0".repeat(64)}` as ContentHash, position: 0, canonicalTime: 0 });
const NO_GENESIS = Object.freeze({}) as unknown as GenesisRecord;

export const createReplayState = (format: HistoryFormat): MutableReplayState => withRootLog({
  format, hashAlgorithm: hashAlgorithmOf(format), signatureScheme: "eip191-personal-sign-keccak256",
  events: [], eventHistoryHashes: [], eventPositionsById: new Map(), head: EMPTY_HEAD, genesis: NO_GENESIS,
  hasher: createHistoryHasher(format), lastTimestamp: undefined, ownerTime: undefined,
  principals: new Map(), agents: new Map(), reservedAgentIds: new Map(), roles: new Map(), successionRules: new Map(), tenures: new Map(),
  currentTenureIdsByAgent: new Map(), runtimeSessions: new Map(), runtimeSessionIdsByAgent: new Map(), credentialKeyIds: new Set(),
  credentialAddressKeysByAgent: new Map(), intentDeclarations: new Map(), intentAdmissions: new Map(), intentConsumptions: new Map(),
  intentOutcomeStates: new Map(), outcomeObservations: new Map(), attemptDuties: new Map(), attemptDutyReviews: new Map(),
  attemptDutyIdsBySourceIntent: new Map(), attemptDutyPolicies: new Map(), attemptDutyDispositions: new Map(), receiptCommitments: new Map(), obligations: new Map(), obligationIdsBySourceIntent: new Map(),
  nonceReservationsByActor: new Map(), authorities: new Map(), recognizedRoots: new Map(), authorityUsage: new Map(), anchors: [],
  ownerKeyEpochs: [], boundWitnesses: Object.freeze([]), boundPolicy: undefined, declarationPositions: new Map(), shadow: undefined,
  recordRefs: new Map(), nonceRecords: new Map(), usageCounters: new Map(), stateRecords: new Map(), sortedRecordKeys: [], projectionHeads: [],
  budgets: new Map(), budgetUsage: new Map(), counterparties: new Map(), refusals: new Map(), effects: new Map(),
  reconciliationObservations: new Map(), reconciliationCursors: new Map(),
  canonicalBytes: 0, capacityIntents: new Map(), capacityDuties: new Map(), capacityObligations: new Map(), capacityDutyQuota: new Map(), lifecycleReserved: 0, dutyReserved: 0,
});
/** Attaches the root log and the lazy `stateRoots` view to a state (its own, or a fork's reading earlier positions through `parent`). */
const withRootLog = (state: Omit<MutableReplayState, "rootLog" | "stateRoots">, parent?: RootLog, parentLimit?: number): MutableReplayState => {
  const s = state as MutableReplayState;
  s.rootLog = new RootLog(s, parent, parentLimit);
  s.stateRoots = lazyStateRoots(s.rootLog, s);
  return s;
};

// ---------------------------------------------------------------- copy-on-write forks (prospective checks)

/**
 * A map that reads through to `base` and keeps its own writes: updates of base
 * keys in `#changed` (iteration keeps the base position, as `Map#set` does),
 * new keys in `#added` (iterated after the base). A delete or clear, which the
 * transitions never issue today, materializes a private copy. Values that the
 * transitions mutate in place (sets, arrays, inner maps) are copied on first
 * access through `copy`, so the base never sees a write.
 */
class OverlayMap<K, V> extends Map<K, V> {
  readonly #base: ReadonlyMap<K, V>;
  readonly #copy: ((value: V) => V) | undefined;
  readonly #changed = new Map<K, V>();
  readonly #added = new Map<K, V>();
  #own: Map<K, V> | undefined = undefined;
  constructor(base: ReadonlyMap<K, V>, copy?: (value: V) => V) {
    super();
    this.#base = base;
    this.#copy = copy;
  }
  #baseValue(key: K, value: V): V {
    if (this.#changed.has(key)) return this.#changed.get(key) as V;
    if (this.#copy === undefined) return value;
    const copied = this.#copy(value);
    this.#changed.set(key, copied);
    return copied;
  }
  #materialize(): Map<K, V> {
    if (this.#own === undefined) this.#own = new Map(this.entries());
    return this.#own;
  }
  override get(key: K): V | undefined {
    if (this.#own !== undefined) return this.#own.get(key);
    if (this.#added.has(key)) return this.#added.get(key);
    return this.#base.has(key) ? this.#baseValue(key, this.#base.get(key) as V) : undefined;
  }
  override has(key: K): boolean {
    return this.#own !== undefined ? this.#own.has(key) : this.#added.has(key) || this.#base.has(key);
  }
  override set(key: K, value: V): this {
    if (this.#own !== undefined) this.#own.set(key, value);
    else if (this.#base.has(key)) this.#changed.set(key, value);
    else this.#added.set(key, value);
    return this;
  }
  override delete(key: K): boolean {
    return this.#materialize().delete(key);
  }
  override clear(): void {
    this.#own = new Map();
  }
  override get size(): number {
    return this.#own !== undefined ? this.#own.size : this.#base.size + this.#added.size;
  }
  override *entries(): MapIterator<[K, V]> {
    if (this.#own !== undefined) {
      yield* this.#own.entries();
      return;
    }
    for (const [key, value] of this.#base) yield [key, this.#baseValue(key, value)];
    yield* this.#added.entries();
  }
  override *keys(): MapIterator<K> {
    for (const [key] of this.entries()) yield key;
  }
  override *values(): MapIterator<V> {
    for (const [, value] of this.entries()) yield value;
  }
  override [Symbol.iterator](): MapIterator<[K, V]> {
    return this.entries();
  }
  override forEach(callback: (value: V, key: K, map: Map<K, V>) => void, thisArg?: unknown): void {
    for (const [key, value] of this.entries()) callback.call(thisArg, value, key, this);
  }
}

/** Map-valued fields whose values `applyTransition` mutates in place. */
const NESTED_COPIES: Readonly<Record<string, (value: never) => unknown>> = Object.freeze({
  reservedAgentIds: (value: Set<string>) => new Set(value),
  currentTenureIdsByAgent: (value: Set<string>) => new Set(value),
  credentialAddressKeysByAgent: (value: Set<string>) => new Set(value),
  runtimeSessionIdsByAgent: (value: string[]) => value.slice(),
  nonceReservationsByActor: (value: Map<string, NonceReservation>) => new Map(value),
  capacityIntents: (value: Set<string>) => new Set(value),
});

/**
 * A cheap private copy of `state` that `applyEvent` may extend without touching
 * `state`: maps are copy-on-write overlays, sets and arrays are shallow copies,
 * records are shared (they are replaced, never mutated). Cost is O(events)
 * pointer copies for the arrays, with no re-validation and no hashing.
 *
 * The fork reads through to `state`, so it is only meaningful while `state`
 * does not change: use it synchronously and drop it. Returns `undefined` when
 * the next event would still be inside a migrated legacy prefix (the shadow
 * view is bound to `state` itself); callers then replay instead.
 */
export const forkReplayState = (state: ReplayState): MutableReplayState | undefined => {
  const source = state as MutableReplayState;
  if (source.shadow !== undefined && source.events.length <= source.shadow.until) return undefined;
  return overlayOf(source);
};
/**
 * A scratch copy of a migrated prefix's shadow view (`ShadowContext.view`), for a transition whose event is rejected
 * whatever the transition decides (A-40.2): it learns the transition's verdict without writing to the shared maps.
 */
export const forkShadowView = (view: MutableReplayState): MutableReplayState => overlayOf(view);
const overlayOf = (source: MutableReplayState): MutableReplayState => {
  const fork: Record<string, unknown> = {};
  // Own and inherited enumerable fields: a shadow view inherits the host state's maps.
  for (const key in source) {
    // The fork's roots: earlier positions through the base (unchanged while the fork lives), its own from its own records.
    if (key === "rootLog" || key === "stateRoots") continue;
    const value: unknown = source[key as keyof MutableReplayState];
    fork[key] = value instanceof Map ? new OverlayMap(value, NESTED_COPIES[key] as ((v: unknown) => unknown) | undefined)
      : value instanceof Set ? new Set(value)
      : Array.isArray(value) ? value.slice()
      : value;
  }
  return withRootLog(fork as unknown as MutableReplayState, source.rootLog, source.events.length);
};

/**
 * Opens the shadow of a migrated history (see `ShadowContext`); the view shares every map with `state`. A format-1 host
 * shadows a legacy source exactly as docs/HISTORY-FORMAT.md §11 describes (and only when the prefix has events). A
 * format-2 host (SPEC §16.2 step 3) shadows a legacy or a format-1 source: the source genesis event opens the source's
 * own hasher (keccak wrapper for legacy, sha256 wrapper for format 1), the view carries the source's format, genesis,
 * heads and hashing plus the inverted prefix events, and it is flagged `prefixOfFormat2` so the transitions keep the
 * format-2 bookkeeping. The `shadow` record (§7.2) commits to the hashes as they grow. `undefined` on success, else the
 * reason (a format-2 source genesis that does not reproduce `migratedFrom.historyHash` when the prefix is the genesis alone).
 */
/** A-17.2 / A-52.4: the fields the migrated genesis copies as written from the source genesis, and the rewrites it must carry. */
const COPIED_GENESIS_FIELDS = ["adapterPolicyHash", "canonicalLineageId", "rootRecognitionPolicy", "globalPolicySourceId", "timeSource", "finality"] as const;
const migratedGenesisProblem = (state: MutableReplayState, migrated: MigratedFrom): string | undefined => {
  const target = state.genesis as unknown as Readonly<Record<string, unknown>>, source = migrated.genesis as unknown as Readonly<Record<string, unknown>>;
  if (target.policyVersion !== "irontrellis-local-owner/2") return "the migrated genesis must rewrite policyVersion to irontrellis-local-owner/2 (A-52.4)";
  const domain = target.domain as Readonly<Record<string, unknown>>, sourceDomain = source.domain as Readonly<Record<string, unknown>> | undefined;
  if (domain.protocol !== "irontrellis" || domain.version !== "2" || domain.deploymentId !== sourceDomain?.deploymentId) return "the migrated genesis domain must be the source deployment's under version 2 (A-17.2)";
  for (const key of COPIED_GENESIS_FIELDS) if (canonicalEncode(target[key] ?? null) !== canonicalEncode(source[key] ?? null)) return `the migrated genesis must copy ${key} as written from the source genesis (A-17.2)`;
  return undefined;
};
const openShadow = (state: MutableReplayState, migrated: MigratedFrom): string | undefined => {
  const host2 = isFormat2(state.format);
  if (host2) { const problem = migratedGenesisProblem(state, migrated); if (problem !== undefined) return problem; }
  if (!host2 && migrated.position === 0) return undefined;
  const sourceFormat = host2 ? migrated.format : LEGACY_FORMAT;
  const hasher = new HistoryHasher(sourceFormat);
  const genesisEvent: CanonicalEvent = Object.freeze({ id: migrated.genesisEventId, type: "DEPLOYMENT_INITIALIZED" as const, timestamp: migrated.genesisTimestamp, data: migrated.genesis as unknown as Readonly<Record<string, unknown>> });
  const hash = hasher.push(genesisEvent);
  if (host2 && migrated.position === 0 && hash !== migrated.historyHash) return "migratedFrom.historyHash does not reproduce the source genesis";
  const hashes = [hash];
  const events = host2 ? [genesisEvent] : undefined;
  const own = (value: unknown, writable = false): PropertyDescriptor => ({ value, writable, enumerable: true, configurable: false });
  const view = Object.create(state, {
    head: own(Object.freeze({ hash, position: 0, canonicalTime: migrated.genesisTimestamp }), true),
    genesis: own(migrated.genesis), format: own(sourceFormat), hashAlgorithm: own(hashAlgorithmOf(sourceFormat)),
    signatureScheme: own(migrated.genesis.versions.signatureScheme), eventHistoryHashes: own(hashes),
    ...(host2 ? { events: own(events), prefixOfFormat2: own(true) } : {}),
  }) as MutableReplayState;
  state.shadow = { view, hasher, hashes, until: migrated.position, expectedHash: migrated.historyHash, sourceFormat, events };
  state.shadowHashes = hashes;
  return undefined;
};
/** Builds the shadow context of a state whose events are already known (the rebuild from records, SPEC §7.5 step 4): hashes and inverted events through `through`. */
export const reopenShadow = (state: MutableReplayState, migrated: MigratedFrom, invertedPrefix: readonly CanonicalEvent[], through: U53): void => {
  const failure = openShadow(state, migrated);
  if (failure !== undefined) throw new Error(failure);
  const shadow = state.shadow;
  if (shadow === undefined) return;
  for (let position = 1; position <= Math.min(through, shadow.until); position += 1) {
    const event = invertedPrefix[position]!;
    const hash = shadow.hasher.push(event);
    shadow.hashes.push(hash);
    shadow.events?.push(event);
    shadow.view.head = Object.freeze({ hash, position, canonicalTime: event.timestamp });
  }
  if (through >= shadow.until && shadow.events !== undefined) shadow.events.length = 0;
};
/** Whether `s` is the shadow view of a format-2 host or a legacy view: the prefix rules of HF1 §11 (no rotation, no witness binding) apply. */
const insidePrefix = (s: MutableReplayState): boolean => s.format === LEGACY_FORMAT || s.prefixOfFormat2 === true;
/** Whether the format-2 bookkeeping (record references, nonce records, usage counters) applies: a format-2 state or its prefix view. */
const bookkeeping2 = (s: MutableReplayState): boolean => isFormat2(s.format) || s.prefixOfFormat2 === true;

// ---------------------------------------------------------------- small helpers

type Rec = Readonly<Record<string, unknown>>;
/** A transition failure with its replay code (format 2 names type-specific codes, SPEC §5); a bare string is `TRANSITION_INVALID`. */
export type TransitionFailure = Readonly<{ code: ReplayCode; reason: string }>;
type Result = string | TransitionFailure | undefined; // undefined = accepted, otherwise the reason
const failWith = (code: ReplayCode, reason: string): TransitionFailure => Object.freeze({ code, reason });
const own = <T extends object, K extends keyof T>(record: T, key: K): T[K] | undefined => (Object.hasOwn(record, key) ? record[key] : undefined);
const activeAgent = (s: MutableReplayState, agentId: string): AgentRecord | undefined => {
  const agent = s.agents.get(agentId);
  return agent === undefined || agent.terminated ? undefined : agent;
};
const endpointExists = (s: MutableReplayState, id: string): boolean => s.principals.has(id) || s.agents.has(id);
const permission = (s: MutableReplayState, authorityId: string): PermissionGrant | undefined => {
  const grant = s.authorities.get(authorityId)?.grant;
  return grant?.kind === "PERMISSION" ? grant : undefined;
};
const addToSet = (map: Map<string, Set<string>>, key: string, member: string): void => {
  const set = map.get(key) ?? new Set<string>();
  set.add(member);
  map.set(key, set);
};
const strictlySorted = (ids: readonly string[]): boolean =>
  ids.length > 0 && ids.every((id, index) => index === 0 || compareProtocolStrings(ids[index - 1]!, id) < 0);

// ---------------------------------------------------------------- tenures

type EventRef = Readonly<{ id: string; position: U53 }>;
/** Format 2 only: the event references the §7.2 records need (see `ReplayState.recordRefs`); a no-op for other formats. */
const ref = (s: MutableReplayState, kind: string, id: string, fields: Rec): void => {
  if (!bookkeeping2(s)) return;
  const key = `${kind}\u0000${id}`;
  s.recordRefs.set(key, Object.freeze({ ...(s.recordRefs.get(key) ?? {}), ...fields }));
};
const openTenure = (s: MutableReplayState, d: { roleId: string; agentId: string; roleTenureId: string; tenureNumber: U53; principalId: string; successionRuleId?: string }, by: EventRef): void => {
  const role = s.roles.get(d.roleId)!;
  const tenure: RoleTenureRecord = Object.freeze({
    id: d.roleTenureId, roleId: d.roleId, agentId: d.agentId, principalId: d.principalId, tenureNumber: d.tenureNumber,
    ...(d.successionRuleId === undefined ? {} : { successionRuleId: d.successionRuleId }), closed: false,
  });
  s.tenures.set(tenure.id, tenure);
  s.roles.set(role.id, Object.freeze({ ...role, currentTenureId: tenure.id, latestTenureNumber: tenure.tenureNumber }));
  addToSet(s.currentTenureIdsByAgent, tenure.agentId, tenure.id);
  ref(s, "tenure", tenure.id, { eventId: by.id, position: by.position });
};
const closeTenure = (s: MutableReplayState, role: RoleRecord, tenure: RoleTenureRecord, by: EventRef): void => {
  s.tenures.set(tenure.id, Object.freeze({ ...tenure, closed: true }));
  ref(s, "tenure", tenure.id, { endedEventId: by.id, endedPosition: by.position });
  s.roles.set(role.id, Object.freeze({ id: role.id, principalId: role.principalId, latestTenureNumber: role.latestTenureNumber }));
  const current = s.currentTenureIdsByAgent.get(tenure.agentId);
  if (current !== undefined) {
    current.delete(tenure.id);
    if (current.size === 0) s.currentTenureIdsByAgent.delete(tenure.agentId);
  }
};

// ---------------------------------------------------------------- lifecycle transitions

const applyPrincipalCreated = (s: MutableReplayState, d: { principalId: string }, event: CanonicalEvent, position: U53): Result => {
  if (s.principals.has(d.principalId) || s.agents.has(d.principalId) || s.reservedAgentIds.has(d.principalId)) return "principal id is not free";
  s.principals.set(d.principalId, Object.freeze({ id: d.principalId, creationEventId: event.id, creationEventPosition: position }));
  return undefined;
};
const applyAgentCreated = (s: MutableReplayState, d: { agentId: string; principalId: string; controllerId: string; initialControlEpoch: U53 }, by: EventRef): Result => {
  if (s.agents.has(d.agentId) || s.principals.has(d.agentId) || !s.principals.has(d.principalId) || d.initialControlEpoch !== 1) return "agent cannot be created";
  s.agents.set(d.agentId, Object.freeze({ id: d.agentId, principalId: d.principalId, controllerId: d.controllerId, currentControlEpoch: 1, terminated: false }));
  ref(s, "agent", d.agentId, { eventId: by.id, position: by.position });
  return undefined;
};
const applyRoleCreated = (s: MutableReplayState, d: { roleId: string; principalId: string }, by: EventRef): Result => {
  if (s.roles.has(d.roleId) || !s.principals.has(d.principalId)) return "role cannot be created";
  s.roles.set(d.roleId, Object.freeze({ id: d.roleId, principalId: d.principalId, latestTenureNumber: 0 }));
  ref(s, "role", d.roleId, { eventId: by.id, position: by.position });
  return undefined;
};
const applySuccessionRuleDeclared = (s: MutableReplayState, d: SuccessionRuleData, by: EventRef): Result => {
  const role = s.roles.get(d.roleId);
  if (s.successionRules.has(d.ruleId) || !s.principals.has(d.principalId) || role === undefined || role.principalId !== d.principalId ||
      !s.agents.has(d.predecessorAgentId) || s.principals.has(d.successorAgentId)) return "succession rule cannot be declared";
  s.successionRules.set(d.ruleId, Object.freeze({ data: d }));
  ref(s, "succession", d.ruleId, { eventId: by.id, position: by.position });
  addToSet(s.reservedAgentIds, d.successorAgentId, d.ruleId); // blocks a later principal with the successor's id
  return undefined;
};
const applyAgentAppointed = (s: MutableReplayState, d: { agentId: string; roleId: string; roleTenureId: string; tenureNumber: U53; principalId: string; successionRuleId?: string }, by: EventRef): Result => {
  const role = s.roles.get(d.roleId);
  const successionRuleId = own(d, "successionRuleId");
  if (activeAgent(s, d.agentId) === undefined || role === undefined || own(role, "currentTenureId") !== undefined || role.principalId !== d.principalId ||
      s.tenures.has(d.roleTenureId) || d.tenureNumber !== role.latestTenureNumber + 1) return "appointment preconditions failed";
  if (successionRuleId !== undefined) {
    const rule = s.successionRules.get(successionRuleId)?.data;
    if (rule === undefined || rule.predecessorAgentId !== d.agentId || rule.roleId !== d.roleId || rule.principalId !== d.principalId) return "succession rule does not match";
  }
  openTenure(s, d, by);
  return undefined;
};
const applyAgentUnappointed = (s: MutableReplayState, d: { agentId: string; roleId: string; roleTenureId: string; principalId: string }, by: EventRef): Result => {
  const role = s.roles.get(d.roleId), tenure = s.tenures.get(d.roleTenureId);
  if (role === undefined || tenure === undefined || own(role, "currentTenureId") !== d.roleTenureId || tenure.closed || tenure.agentId !== d.agentId ||
      tenure.roleId !== d.roleId || role.principalId !== d.principalId || tenure.principalId !== d.principalId || own(tenure, "successionLock") !== undefined) {
    return "unappointment preconditions failed";
  }
  closeTenure(s, role, tenure, by);
  return undefined;
};
const applyRoleTransferred = (s: MutableReplayState, d: { roleId: string; fromAgentId: string; fromRoleTenureId: string; toAgentId: string; toRoleTenureId: string; toTenureNumber: U53; principalId: string; transferKind: string; successionRuleId?: string }, by: EventRef): Result => {
  const role = s.roles.get(d.roleId), tenure = s.tenures.get(d.fromRoleTenureId);
  const lock = tenure === undefined ? undefined : own(tenure, "successionLock");
  const successionRuleId = own(d, "successionRuleId");
  if (role === undefined || tenure === undefined || own(role, "currentTenureId") !== d.fromRoleTenureId || tenure.closed || tenure.agentId !== d.fromAgentId ||
      tenure.roleId !== d.roleId || role.principalId !== d.principalId || activeAgent(s, d.toAgentId) === undefined || s.tenures.has(d.toRoleTenureId) ||
      d.toTenureNumber !== role.latestTenureNumber + 1) return "transfer preconditions failed";
  if (d.transferKind === "REASSIGNMENT") {
    if (successionRuleId !== undefined || lock !== undefined) return "reassignment cannot carry a succession rule or lock";
  } else {
    if (successionRuleId === undefined || lock === undefined) return "succession requires a rule and a locked tenure";
    const rule = s.successionRules.get(successionRuleId)?.data;
    if (lock.agentId !== d.fromAgentId || lock.principalId !== d.principalId || lock.successionRuleId !== successionRuleId || lock.roleId !== d.roleId ||
        lock.roleTenureId !== d.fromRoleTenureId || rule === undefined || rule.predecessorAgentId !== d.fromAgentId || rule.successorAgentId !== d.toAgentId ||
        rule.roleId !== d.roleId || rule.principalId !== d.principalId || !rule.permittedEventTypes.includes("ROLE_TRANSFERRED")) return "succession rule does not match the lock";
  }
  closeTenure(s, role, tenure, by);
  // The new tenure carries no rule: only an appointment-declared rule constrains a later termination.
  openTenure(s, { roleId: d.roleId, agentId: d.toAgentId, roleTenureId: d.toRoleTenureId, tenureNumber: d.toTenureNumber, principalId: d.principalId }, by);
  return undefined;
};
const applyRuntimeSessionAdmitted = (s: MutableReplayState, event: CanonicalEvent, position: U53): Result => {
  const d = event.data as { sessionId: string; agentId: string; controllerId: string; controlEpoch: U53; credentialKeyId: string; expiresAt?: U53 };
  const agent = activeAgent(s, d.agentId);
  const expiresAt = own(d, "expiresAt");
  const credential = sessionCredential(event.data, s.format);
  const usedKeys = s.credentialAddressKeysByAgent.get(d.agentId) ?? new Set<string>();
  if (agent === undefined || d.controllerId !== agent.controllerId || d.controlEpoch !== agent.currentControlEpoch || s.runtimeSessions.has(d.sessionId) ||
      s.credentialKeyIds.has(d.credentialKeyId) || usedKeys.has(credential.key)) return "session admission preconditions failed";
  for (const sessionId of s.runtimeSessionIdsByAgent.get(d.agentId) ?? []) {
    const prior = s.runtimeSessions.get(sessionId)!;
    const priorExpiry = own(prior, "expiresAt");
    // At most one unexpired session per agent per epoch; a session expires at `expiresAt` inclusive. A-62.3: in a format-2
    // state (after any migrated prefix; a prefix transition runs on the source-format view) a migrated session without
    // `expiresAt` is expired for every purpose, so it never blocks a fresh admission.
    const live = priorExpiry === undefined ? s.format !== TRELLIS2_FORMAT : event.timestamp < priorExpiry;
    if (prior.controlEpoch === agent.currentControlEpoch && live) return "agent already has a live session in this epoch";
  }
  const owned = ownerCredentialClash(s, position, { scheme: credential.scheme, credential: credential.key });
  if (owned !== undefined) return `session credential ${owned}`;
  const session: RuntimeSessionRecord = Object.freeze({
    id: d.sessionId, agentId: d.agentId, controllerId: d.controllerId, controlEpoch: d.controlEpoch, credentialKeyId: d.credentialKeyId,
    credentialAddressKey: credential.key, credentialScheme: credential.scheme, admissionEventId: event.id, admissionEventPosition: position,
    ...(expiresAt === undefined ? {} : { expiresAt }),
  });
  s.runtimeSessions.set(session.id, session);
  s.credentialKeyIds.add(session.credentialKeyId);
  usedKeys.add(credential.key);
  s.credentialAddressKeysByAgent.set(d.agentId, usedKeys);
  const ids = s.runtimeSessionIdsByAgent.get(d.agentId) ?? [];
  ids.push(session.id);
  s.runtimeSessionIdsByAgent.set(d.agentId, ids);
  return undefined;
};
const applyControlEpochAdvanced = (s: MutableReplayState, d: { agentId: string; controllerId: string; fromEpoch: U53; toEpoch: U53 }): Result => {
  const agent = activeAgent(s, d.agentId);
  if (agent === undefined || d.controllerId !== agent.controllerId || d.fromEpoch !== agent.currentControlEpoch || d.toEpoch !== d.fromEpoch + 1 ||
      !Number.isSafeInteger(d.fromEpoch + 1)) return "epoch advance preconditions failed";
  s.agents.set(agent.id, Object.freeze({ ...agent, currentControlEpoch: d.toEpoch })); // earlier sessions stay, fenced by their stale epoch
  return undefined;
};
const applyAgentTerminated = (s: MutableReplayState, d: { agentId: string; principalId: string; successionRuleId: string; roleId: string; roleTenureId: string }, by: EventRef): Result => {
  const agent = activeAgent(s, d.agentId), role = s.roles.get(d.roleId), tenure = s.tenures.get(d.roleTenureId);
  const rule = s.successionRules.get(d.successionRuleId)?.data, current = s.currentTenureIdsByAgent.get(d.agentId);
  const tenureRuleId = tenure === undefined ? undefined : own(tenure, "successionRuleId");
  if (agent === undefined || role === undefined || tenure === undefined || rule === undefined || current === undefined || current.size !== 1 ||
      !current.has(d.roleTenureId) || own(role, "currentTenureId") !== d.roleTenureId || tenure.closed || tenure.agentId !== d.agentId || tenure.roleId !== d.roleId ||
      agent.principalId !== d.principalId || role.principalId !== d.principalId || rule.principalId !== d.principalId || rule.predecessorAgentId !== d.agentId ||
      rule.roleId !== d.roleId || !rule.permittedEventTypes.includes("AGENT_TERMINATED") || (tenureRuleId !== undefined && tenureRuleId !== d.successionRuleId)) {
    return "termination preconditions failed";
  }
  s.agents.set(agent.id, Object.freeze({ ...agent, terminated: true }));
  ref(s, "agent", agent.id, { terminatedEventId: by.id, terminatedPosition: by.position });
  // The tenure stays open and current, locked until a SUCCESSION transfer.
  const lock = Object.freeze({ agentId: d.agentId, principalId: d.principalId, successionRuleId: d.successionRuleId, roleId: d.roleId, roleTenureId: d.roleTenureId });
  s.tenures.set(tenure.id, Object.freeze({ ...tenure, successionLock: lock }));
  return undefined;
};

// ---------------------------------------------------------------- authority transitions (spec 01 §D.7, §D.8)

const intervalValid = (c: AuthorityConstraints): boolean => {
  const notBefore = own(c, "notBefore"), expiresAt = own(c, "expiresAt");
  return notBefore === undefined || expiresAt === undefined || notBefore < expiresAt;
};
const subset = (child: readonly string[], parent: readonly string[]): boolean => child.every((id) => parent.includes(id));
const ceilingAttenuated = <T extends bigint | number>(parent: T | undefined, child: T | undefined, childMayExceed: boolean): boolean =>
  parent === undefined || (child !== undefined && (childMayExceed ? child >= parent : child <= parent));
export const constraintsAreAttenuated = (parent: AuthorityConstraints, child: AuthorityConstraints): boolean =>
  intervalValid(child) && subset(child.actions, parent.actions) && subset(child.resources, parent.resources) &&
  subset(parent.requiredIntersectionIds, child.requiredIntersectionIds) && parent.maxDelegationDepth !== 0 &&
  child.maxDelegationDepth <= parent.maxDelegationDepth - 1 && !(parent.quantitative && !child.quantitative) &&
  ceilingAttenuated(own(parent, "notBefore"), own(child, "notBefore"), true) && ceilingAttenuated(own(parent, "expiresAt"), own(child, "expiresAt"), false) &&
  ceilingAttenuated(own(parent, "maxAmount"), own(child, "maxAmount"), false) &&
  ceilingAttenuated(own(parent, "maxCumulativeAmount"), own(child, "maxCumulativeAmount"), false) &&
  ceilingAttenuated(own(parent, "maxTransactions"), own(child, "maxTransactions"), false);
const withinPathLimit = (s: MutableReplayState, parentAuthorityId: string): boolean => {
  let depth = 2;
  for (let current = permission(s, parentAuthorityId); current !== undefined; current = permission(s, own(current, "parentAuthorityId")!)) {
    if (depth > 32) return false;
    if (own(current, "parentAuthorityId") === undefined) return true;
    depth += 1;
  }
  return false;
};
/** Format 2: the grant with engine amounts (the schema admitted Amount strings; the authority engine compares bigints). */
const engineGrant = (grant: AuthorityGrant): AuthorityGrant => {
  const c = grant.constraints as AuthorityConstraints & { maxAmount?: unknown; maxCumulativeAmount?: unknown };
  const constraints: Record<string, unknown> = { ...c };
  for (const key of ["maxAmount", "maxCumulativeAmount"] as const) if (typeof c[key] === "string") constraints[key] = parseAmountString(c[key]);
  return Object.freeze({ ...grant, constraints: Object.freeze(constraints) }) as AuthorityGrant;
};
const applyAuthorityGranted = (s: MutableReplayState, written: AuthorityGrant, event: CanonicalEvent, position: U53): Result => {
  const grant = isFormat2(s.format) ? engineGrant(written) : written;
  if (s.authorities.has(grant.authorityId) || !intervalValid(grant.constraints)) return "authority id used or interval invalid";
  if (grant.kind === "PERMISSION") {
    if (!endpointExists(s, grant.grantorId) || !endpointExists(s, grant.granteeId)) return "grantor or grantee unknown";
    if (!grant.constraints.requiredIntersectionIds.every((id) => permission(s, id) !== undefined)) return "required intersection is not a permission";
    const parentId = own(grant, "parentAuthorityId");
    if (parentId === undefined) {
      if (!s.principals.has(grant.grantorId)) return "root grantor must be a principal";
    } else {
      const parent = permission(s, parentId);
      if (parent === undefined || !withinPathLimit(s, parentId) || grant.grantorId !== parent.granteeId || grant.rootAuthorityId !== parent.rootAuthorityId ||
          !constraintsAreAttenuated(parent.constraints, grant.constraints)) return "delegation is not attenuated from its parent";
    }
  } else {
    const c = grant.constraints;
    if (!(intervalValid(c) && c.requiredIntersectionIds.length === 0 && c.maxDelegationDepth === 0 && own(c, "maxCumulativeAmount") === undefined &&
        own(c, "maxTransactions") === undefined)) return "prohibition constraints invalid";
    const subject = own(grant, "subjectActorId");
    if (subject !== undefined && !s.agents.has(subject)) return "prohibition subject unknown";
    if (grant.scope === "GLOBAL") {
      if (grant.grantorId !== s.genesis.globalPolicySourceId) return "global prohibition grantor is not the policy source";
    } else {
      if (!endpointExists(s, grant.grantorId)) return "prohibition grantor unknown";
      const root = s.recognizedRoots.get(grant.rootAuthorityId);
      if (root === undefined) return "prohibition root not recognized";
      const parentId = own(grant, "parentAuthorityId");
      if (grant.grantorId === root.principalId) {
        const rootGrant = permission(s, root.rootAuthorityId);
        if (parentId !== undefined || rootGrant === undefined || !constraintsAreAttenuated(rootGrant.constraints, c)) return "root prohibition not attenuated";
      } else {
        const parent = parentId === undefined ? undefined : permission(s, parentId);
        if (parent === undefined || parent.rootAuthorityId !== grant.rootAuthorityId || parent.granteeId !== grant.grantorId ||
            !constraintsAreAttenuated(parent.constraints, c)) return "delegated prohibition not attenuated";
      }
    }
  }
  s.authorities.set(grant.authorityId, Object.freeze({ grant, grantEventId: event.id, grantEventPosition: position }));
  if (grant.kind === "PERMISSION") {
    if (own(grant, "parentAuthorityId") === undefined && grant.authorityId === grant.rootAuthorityId) {
      const principal = s.principals.get(grant.grantorId);
      if (principal !== undefined) {
        s.recognizedRoots.set(grant.rootAuthorityId, Object.freeze({
          rootAuthorityId: grant.rootAuthorityId, principalId: principal.id, principalRecognitionEventId: principal.creationEventId, rootGrantEventId: event.id,
        }));
      }
    }
    if (own(grant.constraints, "maxTransactions") !== undefined || own(grant.constraints, "maxCumulativeAmount") !== undefined) {
      s.authorityUsage.set(grant.authorityId, Object.freeze({ authorityId: grant.authorityId, admittedTransactionCount: 0, admittedCumulativeAmount: 0n }));
    }
  }
  return undefined;
};
const applyAuthorityRevoked = (s: MutableReplayState, d: { authorityId: string; revokerId: string }, event: CanonicalEvent, position: U53): Result => {
  const record = s.authorities.get(d.authorityId);
  if (record === undefined || own(record, "revocationEventId") !== undefined) return "authority unknown or already revoked";
  const grant = record.grant;
  let permitted = false;
  if (grant.kind === "PROHIBITION" && grant.scope === "GLOBAL") permitted = d.revokerId === s.genesis.globalPolicySourceId;
  else {
    const root = s.recognizedRoots.get(grant.rootAuthorityId);
    if (root !== undefined) permitted = d.revokerId === root.principalId || (own(grant, "parentAuthorityId") !== undefined && d.revokerId === grant.grantorId);
  }
  if (!permitted) return "revoker is not permitted";
  s.authorities.set(d.authorityId, Object.freeze({ ...record, revocationEventId: event.id, revocationEventPosition: position, revokerId: d.revokerId }));
  return undefined;
};

// ---------------------------------------------------------------- intents, admissions, consumptions, outcomes, receipts

const applyIntentDeclared = (s: MutableReplayState, d: TransactionIntent, position: U53): Result => {
  // A format-2 prefix (SPEC §16.2 step 8): the nonce record is created as for a native declaration (`declarationDigest` null).
  const nonceKey = s.prefixOfFormat2 === true ? hashCanonical([d.actorId, d.nonce], "sha256") : undefined;
  if (nonceKey !== undefined && s.nonceRecords.has(nonceKey)) return "nonce already declared for this actor";
  if (s.intentDeclarations.has(d.intentId) || !s.agents.has(d.actorId) || !s.roles.has(d.roleId) || !s.tenures.has(d.roleTenureId) ||
      !validateAdapterProfileForPolicy(s.genesis.adapterPolicyHash, d.adapterProfile)) return "intent declaration preconditions failed";
  s.intentDeclarations.set(d.intentId, Object.freeze(nonceKey === undefined ? { data: d } : { data: d, declarationDigest: null }));
  s.declarationPositions.set(d.intentId, position);
  if (nonceKey !== undefined) s.nonceRecords.set(nonceKey, Object.freeze({ actorId: d.actorId, nonce: d.nonce, intentId: d.intentId, position }));
  return undefined;
};
/**
 * Format 2 (SPEC §8.6), in order: the session authorization over the declaration challenge with the session's agent
 * equal to `actorId` (`DECLARATION_AUTHORIZATION_INVALID`; skipped inside a migrated prefix, where
 * `declarationAuthorization` is `null`), the nonce rule (a second declaration with the same `(actorId, nonce)` is
 * `TRANSITION_INVALID`), then the format-1 preconditions. The declaration creates the §7.2 `nonce` record; the state keeps
 * the intent with engine amounts and the declaration digest.
 */
const applyIntentDeclared2 = (s: MutableReplayState, event: CanonicalEvent, position: U53): Result => {
  const { declarationAuthorization, ...fields } = event.data as TransactionIntent & { declarationAuthorization: (SessionBinding & { hash: ContentHash; signature: string }) | null; amount?: string | bigint };
  let declarationDigest: ContentHash | null = null;
  if (declarationAuthorization !== null) {
    const previousHead = { hash: s.head.hash, position: s.head.position };
    const expected = intentDeclarationHash(s.genesis.domain, fields, previousHead, declarationAuthorization, event);
    const outcome = sessionAuthorizationFailure(s, declarationAuthorization, event.timestamp, expected, declarationAuthorization.hash, declarationAuthorization.signature);
    if (!outcome.ok) return failWith(sessionFailureCode(outcome, "DECLARATION_AUTHORIZATION_INVALID"), outcome.reason);
    if (outcome.session.agentId !== fields.actorId) return failWith("DECLARATION_AUTHORIZATION_INVALID", "the signing session's agent is not the intent's actor");
    declarationDigest = declarationAuthorization.hash;
  }
  const nonceKey = hashCanonical([fields.actorId, fields.nonce], "sha256");
  if (s.nonceRecords.has(nonceKey)) return "nonce already declared for this actor";
  const amount = fields.amount === undefined ? undefined : amountOf(fields.amount);
  const data: TransactionIntent = Object.freeze({ ...fields, ...(amount === undefined ? {} : { amount }) }) as TransactionIntent;
  const failure = applyIntentDeclared(s, data, position);
  if (failure !== undefined) return failure;
  s.intentDeclarations.set(data.intentId, Object.freeze({ data, declarationDigest }));
  s.nonceRecords.set(nonceKey, Object.freeze({ actorId: fields.actorId, nonce: fields.nonce, intentId: fields.intentId, position }));
  return undefined;
};
const applyIntentAdmitted = (s: MutableReplayState, event: CanonicalEvent, position: U53, nextHead: HistoryHead, hooks: ReplayHooks): Result => {
  const validation = hooks.validateIntentAdmissionTransition(s, event, position, nextHead);
  if (!validation.ok) return validation.reason;
  const { admission, usage } = validation;
  if (s.intentAdmissions.has(admission.intentId)) return "intent already admitted";
  const reservations = s.nonceReservationsByActor.get(admission.actorId);
  if (reservations?.has(admission.nonce)) return "nonce already reserved";
  if (!usage.every((u) => s.authorityUsage.has(u.authorityId))) return "usage update for an uncapped authority";
  if (!s.intentDeclarations.has(admission.intentId)) return "intent not declared";
  if (bookkeeping2(s)) {
    // SPEC §8.6: the intent's nonce record (created at declaration) must name this intent; SPEC §7.2 `usage` counts every controlling authority.
    const record = s.nonceRecords.get(hashCanonical([admission.actorId, admission.nonce], "sha256"));
    if (record === undefined || record.intentId !== admission.intentId) return "the nonce record does not name the admitted intent";
    const proof = event.data.authorizationProof as { controllingAuthorityIds: readonly string[]; request: { amount?: unknown } };
    const amount = proof.request.amount === undefined ? 0n : (amountOf(proof.request.amount) ?? 0n);
    for (const authorityId of proof.controllingAuthorityIds) {
      const current = s.usageCounters.get(authorityId) ?? { authorityId, admittedTransactionCount: 0, admittedCumulativeAmount: 0n };
      s.usageCounters.set(authorityId, Object.freeze({ authorityId, admittedTransactionCount: current.admittedTransactionCount + 1, admittedCumulativeAmount: current.admittedCumulativeAmount + amount }));
    }
    // SPEC §9.6: the admission charges every matching budget's current period (the metric rule made the request's metric the intent's).
    const request = { ...(proof.request as Rec), amount } as unknown as Parameters<typeof chargedUsage>[1];
    if (proof.request.amount === undefined) delete (request as { amount?: unknown }).amount;
    for (const usage of chargedUsage(s, request, event.timestamp)) s.budgetUsage.set(usageKey(usage.budgetId, usage.periodIndex), usage);
  }
  const actorReservations = reservations ?? new Map<string, NonceReservation>();
  s.intentAdmissions.set(admission.intentId, admission);
  actorReservations.set(admission.nonce, Object.freeze({
    intentId: admission.intentId, admissionEventId: event.id, admissionEventPosition: position, admissionHead: nextHead,
  }));
  s.nonceReservationsByActor.set(admission.actorId, actorReservations);
  for (const update of usage) s.authorityUsage.set(update.authorityId, update);
  return undefined;
};
/** spec 01 §D.10: the control tuple bound at admission is still current at `useTime`. */
export const admissionControlIsCurrent = (state: ReplayState, admission: IntentAdmissionRecord, useTime: U53): boolean => {
  const agent = state.agents.get(admission.actorId), session = state.runtimeSessions.get(admission.runtimeSessionId);
  const role = state.roles.get(admission.roleId), tenure = state.tenures.get(admission.roleTenureId);
  const expiresAt = session === undefined ? undefined : own(session, "expiresAt");
  return agent !== undefined && !agent.terminated && session !== undefined && session.agentId === admission.actorId &&
    session.credentialKeyId === admission.credentialKeyId && (expiresAt === undefined ? state.format !== TRELLIS2_FORMAT : useTime < expiresAt) &&
    session.controlEpoch === admission.controlEpoch && agent.currentControlEpoch === admission.controlEpoch && role !== undefined && tenure !== undefined &&
    own(role, "currentTenureId") === admission.roleTenureId && !tenure.closed && tenure.roleId === admission.roleId && tenure.agentId === admission.actorId;
};
/** The reference's `portableAdmissionControlIsCurrent(state, intentId, useTime)`. */
export const intentAdmissionIsCurrent = (state: ReplayState, intentId: string, useTime: U53): boolean => {
  const admission = state.intentAdmissions.get(intentId);
  return admission !== undefined && admissionControlIsCurrent(state, admission, useTime);
};
/** spec 01 §D.12: evidence that cites earlier history must cite it exactly. */
export const earlierEvidenceIsValid = (s: ReplayState, evidence: EvidenceReference | Rec): boolean => {
  const e = evidence as Rec;
  switch (e.kind) {
    case "EVENT": {
      const position = s.eventPositionsById.get(e.eventId as string);
      const event = position === undefined ? undefined : s.events[position];
      return position !== undefined && event !== undefined && e.position === position && e.eventType === event.type && e.historyHash === s.eventHistoryHashes[position];
    }
    case "AUTHORITY": { const a = s.authorities.get(e.authorityId as string); return a !== undefined && e.grantEventId === a.grantEventId; }
    case "RUNTIME_CREDENTIAL": {
      const session = s.runtimeSessions.get(e.sessionId as string);
      return session !== undefined && e.keyId === session.credentialKeyId && e.admissionEventId === session.admissionEventId;
    }
    case "RECEIPT_COMMITMENT": {
      const receipt = s.receiptCommitments.get(e.receiptContentHash as string);
      return receipt !== undefined && receipt.eventId === e.eventId && receipt.eventPosition === e.position;
    }
    default: return e.kind === "EXTERNAL";
  }
};
const applyIntentConsumed = (s: MutableReplayState, event: CanonicalEvent, position: U53, nextHead: HistoryHead): Result => {
  const d = event.data as { intentId: string; adapterId: string; idempotencyKey: ContentHash; submissionFingerprint: ContentHash; transactionReference: string; acknowledgment: Rec; evidenceReference: Rec };
  const admission = s.intentAdmissions.get(d.intentId);
  const outcome = s.intentOutcomeStates.get(d.intentId);
  if (admission === undefined || s.intentConsumptions.has(d.intentId) || (outcome !== undefined && own(outcome, "terminal") !== undefined) ||
      !admissionControlIsCurrent(s, admission, event.timestamp)) return "consumption preconditions failed";
  const identity = admission.adapterIdentity as unknown as AdapterIdentity;
  if (d.adapterId !== identity.adapterProfile.profileId || d.idempotencyKey !== identity.idempotencyKey || d.submissionFingerprint !== identity.submissionFingerprint) {
    return "consumption does not match the admitted identity";
  }
  const evaluation = evaluateAdapterAcknowledgment(d.acknowledgment, identity);
  if (evaluation === undefined) return "acknowledgment does not match the admitted identity";
  if (d.transactionReference !== evaluation.transactionReference) return "transaction reference mismatch";
  if (!sameAdapterEvidence(d.evidenceReference, evaluation.evidence)) return "evidence reference mismatch";
  s.intentConsumptions.set(d.intentId, Object.freeze({
    intentId: d.intentId, eventId: event.id, eventPosition: position, head: nextHead, adapterId: identity.adapterProfile.profileId,
    idempotencyKey: d.idempotencyKey, submissionFingerprint: d.submissionFingerprint, transactionReference: d.transactionReference,
    acknowledgment: d.acknowledgment, evidenceReference: d.evidenceReference,
  }));
  return undefined;
};
const applyOutcomeRecorded = (s: MutableReplayState, event: CanonicalEvent, position: U53, nextHead: HistoryHead): Result => {
  const d = event.data as { intentId: string; status: string; attesterId: string; evidenceReference: Rec; noEffect?: Rec };
  const admission = s.intentAdmissions.get(d.intentId);
  if (admission === undefined) return "intent not admitted";
  const existing = s.intentOutcomeStates.get(d.intentId);
  const existingTerminal = existing === undefined ? undefined : own(existing, "terminal");
  if (existingTerminal !== undefined && d.status !== "DISPUTED") return "terminal outcome already recorded";
  const noEffect = own(d, "noEffect");
  if (d.status === "FAILED") {
    const evaluation = noEffect === undefined ? undefined : evaluateAdapterNoEffect(noEffect, admission.adapterIdentity);
    if (evaluation === undefined || d.attesterId !== SIMULATED_ADAPTER_ID || !sameAdapterEvidence(d.evidenceReference, evaluation.evidence)) return "no-effect proof invalid";
  } else if (noEffect !== undefined || !earlierEvidenceIsValid(s, d.evidenceReference)) return "outcome evidence invalid";
  const record: OutcomeRecord = Object.freeze({
    intentId: d.intentId, eventId: event.id, eventPosition: position, head: nextHead, status: d.status, attesterId: d.attesterId,
    evidenceReference: d.evidenceReference as EvidenceReference, ...(noEffect === undefined ? {} : { noEffect }),
  });
  const terminal = existingTerminal ?? (d.status === "CONFIRMED" || d.status === "FAILED" ? record : undefined);
  s.intentOutcomeStates.set(d.intentId, Object.freeze({ latest: record, ...(terminal === undefined ? {} : { terminal }) }));
  ref(s, "intentOutcomes", d.intentId, { outcomes: Object.freeze([...((s.recordRefs.get(`intentOutcomes\u0000${d.intentId}`)?.outcomes as readonly OutcomeRecord[] | undefined) ?? []), record]) });
  return undefined;
};
const applyReceiptRecorded = (s: MutableReplayState, event: CanonicalEvent, position: U53, head: HistoryHead): Result => {
  const d = event.data as { receiptContentHash: ContentHash; intentId: string; issuerAgentId: string; runtimeSessionId: string; roleId: string; roleTenureId: string };
  // Typed existence only: no issuer/control/admission/artifact congruence is inferred here (spec 01 §G.26).
  if (s.receiptCommitments.has(d.receiptContentHash) || !s.intentDeclarations.has(d.intentId) || !s.agents.has(d.issuerAgentId) ||
      !s.runtimeSessions.has(d.runtimeSessionId) || !s.roles.has(d.roleId) || !s.tenures.has(d.roleTenureId)) return "receipt cites unknown records";
  s.receiptCommitments.set(d.receiptContentHash, Object.freeze({ ...event.data, eventId: event.id, eventPosition: position, head }) as ReceiptCommitmentRecord);
  ref(s, "intentReceipts", d.intentId, { count: receiptCountOf(s, d.intentId) + 1 }); // A-51.5 (format 2 and its prefix view)
  return undefined;
};

// ---------------------------------------------------------------- obligations (spec 01 §D.7, §D.13; spec 03 §K.1)

const STATUS_RANK: Readonly<Record<string, number>> = Object.freeze({ OPEN: 0, OUTCOME_UNKNOWN: 1, DISPUTED: 2, DISCHARGED: 3, IMPOSSIBLE_OR_ESCALATED: 4 });
const unresolved = (status: string): boolean => status !== "DISCHARGED" && status !== "IMPOSSIBLE_OR_ESCALATED";
const obligationPoliciesAreValid = (s: MutableReplayState, policies: readonly ObligationTransitionPolicy[]): boolean => {
  if (policies.length === 0) return false;
  for (let index = 0; index < policies.length; index += 1) {
    const policy = policies[index]!;
    if (!unresolved(policy.fromStatus) || !strictlySorted(policy.acceptedAttesterIds) || !strictlySorted(policy.requiredAuthorityIds) ||
        !policy.requiredAuthorityIds.every((id) => s.authorities.has(id))) return false;
    if (index === 0) continue;
    const prior = policies[index - 1]!;
    const fromDifference = STATUS_RANK[policy.fromStatus]! - STATUS_RANK[prior.fromStatus]!;
    const toDifference = STATUS_RANK[policy.toStatus]! - STATUS_RANK[prior.toStatus]!;
    if (fromDifference < 0 || (fromDifference === 0 && toDifference <= 0)) return false;
  }
  return true;
};
const administrative = (s: MutableReplayState, event: CanonicalEvent, position: U53, hooks: ReplayHooks, requirements: AdministrativeRequirements): Result => {
  const validation = hooks.validateAdministrativeTransition(s, event, position, requirements);
  return validation.ok ? undefined : validation.reason;
};
const applyObligationCreated = (s: MutableReplayState, event: CanonicalEvent, position: U53, head: HistoryHead, hooks: ReplayHooks): Result => {
  const d = event.data as { record: ObligationRecord; actorId: string };
  const record = d.record;
  const intent = s.intentDeclarations.get(record.sourceIntentId)?.data, admission = s.intentAdmissions.get(record.sourceIntentId);
  const consumption = s.intentConsumptions.get(record.sourceIntentId), receipt = s.receiptCommitments.get(record.causalReceiptContentHash);
  const role = s.roles.get(record.durableRoleId), tenure = s.tenures.get(record.creationRoleTenureId), rule = s.successionRules.get(record.successionRuleId)?.data;
  if (s.obligations.has(record.obligationId) || s.attemptDuties.has(record.obligationId) || s.obligationIdsBySourceIntent.has(record.sourceIntentId) ||
      intent === undefined || admission === undefined || consumption === undefined || receipt === undefined || role === undefined || tenure === undefined || rule === undefined ||
      intent.intentId !== admission.intentId || intent.intentId !== consumption.intentId || intent.intentId !== receipt.intentId ||
      !(admission.admissionEventPosition < consumption.eventPosition && consumption.eventPosition < receipt.eventPosition && receipt.eventPosition < position) ||
      record.trigger !== consumption.eventId || record.durableRoleId !== intent.roleId || record.durableRoleId !== receipt.roleId ||
      record.creationRoleTenureId !== intent.roleTenureId || record.creationRoleTenureId !== receipt.roleTenureId ||
      own(role, "currentTenureId") !== tenure.id || tenure.closed || tenure.roleId !== record.durableRoleId ||
      record.performanceAssigneeId !== intent.actorId || tenure.agentId !== record.performanceAssigneeId || d.actorId !== record.performanceAssigneeId ||
      own(intent, "termsCommitment") !== record.termsCommitment ||
      Object.hasOwn(intent, "counterpartyId") !== Object.hasOwn(record, "counterpartyId") || own(intent, "counterpartyId") !== own(record, "counterpartyId") ||
      rule.roleId !== record.durableRoleId || rule.predecessorAgentId !== record.performanceAssigneeId || rule.principalId !== role.principalId ||
      rule.trigger !== "AGENT_TERMINATED" || !["AGENT_TERMINATED", "ROLE_TRANSFERRED", "OBLIGATION_PERFORMANCE_ASSIGNED"].every((t) => rule.permittedEventTypes.includes(t)) ||
      !obligationPoliciesAreValid(s, record.transitionPolicies)) return "obligation creation preconditions failed";
  const declarationPosition = s.declarationPositions.get(intent.intentId);
  if (declarationPosition === undefined || declarationPosition >= admission.admissionEventPosition) return "declaration does not precede admission";
  // The receipt must commit to the admission's own proof and control tuple (spec 01 §G.27).
  const proof = s.events[admission.admissionEventPosition]!.data.authorizationProof as Rec & { request: { actorId: string } };
  if (receipt.authorizationProofHash !== hashCanonical(proof, s.hashAlgorithm) || receipt.issuerAgentId !== proof.request.actorId ||
      receipt.runtimeSessionId !== own(proof, "runtimeSessionId") || receipt.controlEpoch !== own(proof, "controlEpoch") ||
      receipt.roleId !== own(proof, "roleId") || receipt.roleTenureId !== own(proof, "roleTenureId")) return "receipt does not match the admission proof";
  const counterpartyId = own(record, "counterpartyId");
  const failure = administrative(s, event, position, hooks, {
    request: { actorId: d.actorId, action: "OBLIGATE", resource: intent.resource, claimedAt: event.timestamp, termsCommitment: record.termsCommitment,
      ...(counterpartyId === undefined ? {} : { counterpartyId }) },
    requiredPrincipalId: role.principalId, requiredAuthorityIds: [], roleId: role.id, roleTenureId: tenure.id,
  });
  if (failure !== undefined) return failure;
  s.obligations.set(record.obligationId, Object.freeze({
    record, status: record.status, performanceAssigneeId: record.performanceAssigneeId, creationEventId: event.id, creationEventPosition: position, creationHead: head,
  }));
  s.obligationIdsBySourceIntent.set(record.sourceIntentId, record.obligationId);
  return undefined;
};
const applyObligationPerformanceAssigned = (s: MutableReplayState, event: CanonicalEvent, position: U53, hooks: ReplayHooks): Result => {
  const d = event.data as { obligationId: string; fromAgentId: string; toAgentId: string; successionRuleId: string; actorId: string };
  const obligation = s.obligations.get(d.obligationId);
  if (obligation === undefined || !unresolved(obligation.status) || d.fromAgentId !== obligation.performanceAssigneeId ||
      d.successionRuleId !== obligation.record.successionRuleId) return "obligation cannot be reassigned";
  const record = obligation.record, role = s.roles.get(record.durableRoleId), rule = s.successionRules.get(d.successionRuleId)?.data;
  const currentTenureId = role === undefined ? undefined : own(role, "currentTenureId");
  const tenure = currentTenureId === undefined ? undefined : s.tenures.get(currentTenureId);
  if (role === undefined || rule === undefined || tenure === undefined || tenure.closed || tenure.agentId !== d.toAgentId || tenure.roleId !== record.durableRoleId ||
      rule.roleId !== record.durableRoleId || rule.principalId !== role.principalId || rule.predecessorAgentId !== d.fromAgentId || rule.successorAgentId !== d.toAgentId ||
      rule.trigger !== "AGENT_TERMINATED" || !rule.permittedEventTypes.includes("OBLIGATION_PERFORMANCE_ASSIGNED")) return "succession does not cover the reassignment";
  // The spec asks for the *last* matching termination and succession transfer, so the history is scanned (rare event).
  let terminationPosition: number | undefined, transferPosition: number | undefined;
  // (The body is read only for the two types the scan is about: an export-view verifier holds stand-ins for the others, export-view.ts.)
  for (let p = 0; p < s.events.length; p += 1) {
    const earlier = s.events[p]!;
    if (earlier.type === "AGENT_TERMINATED") {
      const e = earlier.data;
      if (e.agentId === d.fromAgentId && e.principalId === rule.principalId && e.successionRuleId === d.successionRuleId && e.roleId === record.durableRoleId &&
          e.roleTenureId === record.creationRoleTenureId) terminationPosition = p;
    } else if (earlier.type === "ROLE_TRANSFERRED") {
      const e = earlier.data;
      if (e.transferKind === "SUCCESSION" && own(e, "successionRuleId") === d.successionRuleId && e.principalId === rule.principalId && e.roleId === record.durableRoleId &&
          e.fromAgentId === d.fromAgentId && e.fromRoleTenureId === record.creationRoleTenureId && e.toAgentId === d.toAgentId && e.toRoleTenureId === tenure.id) transferPosition = p;
    }
  }
  if (terminationPosition === undefined || transferPosition === undefined || terminationPosition >= transferPosition) return "no termination followed by succession";
  const failure = administrative(s, event, position, hooks, {
    request: { actorId: d.actorId, action: "ASSIGN_PERFORMANCE", resource: d.obligationId, claimedAt: event.timestamp },
    requiredPrincipalId: rule.principalId, requiredAuthorityIds: [], roleId: role.id, roleTenureId: tenure.id,
  });
  if (failure !== undefined) return failure;
  s.obligations.set(d.obligationId, Object.freeze({ ...obligation, performanceAssigneeId: d.toAgentId }));
  ref(s, "obligation", d.obligationId, { assignmentEventId: event.id, assignmentPosition: position });
  return undefined;
};
const evidenceAttributesAttester = (s: MutableReplayState, evidence: Rec, attesterId: string): boolean => {
  if (evidence.kind === "EXTERNAL") return evidence.attesterId === attesterId;
  if (evidence.kind !== "EVENT" || !earlierEvidenceIsValid(s, evidence)) return false;
  const data = s.events[evidence.position as number]!.data;
  if (own(data, "attesterId") === attesterId) return true;
  const direct = own(data, "evidenceReference") as Rec | undefined;
  return direct !== undefined && direct.kind === "EXTERNAL" && direct.attesterId === attesterId;
};
const applyObligationStatusRecorded = (s: MutableReplayState, event: CanonicalEvent, position: U53, hooks: ReplayHooks): Result => {
  const d = event.data as { obligationId: string; fromStatus: string; toStatus: string; actorId: string; action: string; attesterId: string; evidenceReference: Rec };
  const obligation = s.obligations.get(d.obligationId);
  if (obligation === undefined || !unresolved(obligation.status) || d.fromStatus !== obligation.status) return "obligation status cannot change";
  const policy = obligation.record.transitionPolicies.find((p) => p.fromStatus === d.fromStatus && p.toStatus === d.toStatus && p.action === d.action);
  if (policy === undefined || !policy.acceptedAttesterIds.includes(d.attesterId) || !evidenceAttributesAttester(s, d.evidenceReference, d.attesterId)) return "no policy admits this transition";
  const role = s.roles.get(obligation.record.durableRoleId);
  const currentTenureId = role === undefined ? undefined : own(role, "currentTenureId");
  if (role === undefined || currentTenureId === undefined) return "role has no current tenure";
  const failure = administrative(s, event, position, hooks, {
    request: { actorId: d.actorId, action: d.action, resource: d.obligationId, claimedAt: event.timestamp },
    requiredPrincipalId: role.principalId, requiredAuthorityIds: policy.requiredAuthorityIds, roleId: role.id, roleTenureId: currentTenureId,
  });
  if (failure !== undefined) return failure;
  s.obligations.set(d.obligationId, Object.freeze({ ...obligation, status: d.toStatus }));
  ref(s, "obligation", d.obligationId, { statusEventId: event.id, statusPosition: position });
  return undefined;
};

// ---------------------------------------------------------------- attempt duties (E5/E6, spec 03 §K.2)

type AttemptSource = { intent: TransactionIntent; admission: IntentAdmissionRecord; role: RoleRecord; tenure: RoleTenureRecord };
const attemptSource = (s: MutableReplayState, intentId: string): AttemptSource | undefined => {
  if (!policyEnablesAttemptDuties(s.genesis.adapterPolicyHash)) return undefined;
  const intent = s.intentDeclarations.get(intentId)?.data, admission = s.intentAdmissions.get(intentId);
  if (intent === undefined || admission === undefined || (admission.adapterIdentity as unknown as AdapterIdentity).adapterProfile.profileId !== REMOTE_SERVICE_REPORT_ADAPTER_ID) return undefined;
  const role = s.roles.get(intent.roleId);
  const tenure = role?.currentTenureId === undefined ? undefined : s.tenures.get(role.currentTenureId);
  if (role === undefined || tenure === undefined || tenure.closed || activeAgent(s, tenure.agentId) === undefined) return undefined;
  return { intent, admission, role, tenure };
};
const authorizeAttempt = (s: MutableReplayState, event: CanonicalEvent, position: U53, hooks: ReplayHooks, actorId: string, source: AttemptSource, action: string): Result => {
  if (actorId !== source.tenure.agentId) return "actor is not the current role holder";
  const termsCommitment = own(source.intent, "termsCommitment");
  return administrative(s, event, position, hooks, {
    request: { actorId, action, resource: source.intent.intentId, claimedAt: event.timestamp, ...(termsCommitment === undefined ? {} : { termsCommitment }) },
    requiredPrincipalId: source.role.principalId, requiredAuthorityIds: [], roleId: source.role.id, roleTenureId: source.tenure.id,
  });
};
const applyOutcomeObservationRecorded = (s: MutableReplayState, event: CanonicalEvent, position: U53, hooks: ReplayHooks): Result => {
  const d = event.data as { intentId: string; sourceAdmissionEventId: string; acknowledgment: Rec & { result: Rec }; actorId: string };
  const source = attemptSource(s, d.intentId);
  if (source === undefined || source.admission.admissionEventId !== d.sourceAdmissionEventId ||
      !validateAdapterAcknowledgment(d.acknowledgment, source.admission.adapterIdentity) || d.acknowledgment.result.kind !== "REMOTE_SERVICE_REPORTED") {
    return "observation does not match an admitted remote-service intent";
  }
  const failure = authorizeAttempt(s, event, position, hooks, d.actorId, source, "OBSERVE_OUTCOME");
  if (failure !== undefined) return failure;
  const observation: OutcomeObservationRecord = Object.freeze({
    intentId: d.intentId, sourceAdmissionEventId: d.sourceAdmissionEventId, acknowledgment: d.acknowledgment, actorId: d.actorId,
    eventId: event.id, eventPosition: position, observedAt: event.timestamp,
  });
  s.outcomeObservations.set(d.intentId, Object.freeze([...(s.outcomeObservations.get(d.intentId) ?? []), observation]));
  return undefined;
};
const applyAttemptDutyCreated = (s: MutableReplayState, event: CanonicalEvent, position: U53, hooks: ReplayHooks): Result => {
  const d = event.data as { record: AttemptDutyRecord & { sourceAdmissionEventId: string; durableRoleId: string; creationRoleTenureId: string; performanceAssigneeId: string; status: string }; actorId: string };
  const record = d.record, source = attemptSource(s, record.sourceIntentId);
  if (source === undefined || record.sourceAdmissionEventId !== source.admission.admissionEventId || record.durableRoleId !== source.role.id ||
      record.creationRoleTenureId !== source.tenure.id || record.performanceAssigneeId !== source.tenure.agentId || record.status !== "OPEN" ||
      s.attemptDuties.has(record.dutyId) || s.obligations.has(record.dutyId) || s.attemptDutyIdsBySourceIntent.has(record.sourceIntentId)) return "attempt duty cannot be created";
  const failure = authorizeAttempt(s, event, position, hooks, d.actorId, source, "CREATE_ATTEMPT_DUTY");
  if (failure !== undefined) return failure;
  s.attemptDuties.set(record.dutyId, Object.freeze({
    record, creationEventId: event.id, creationEventPosition: position, creationActorId: d.actorId, currentAssigneeId: record.performanceAssigneeId, assignments: Object.freeze([]),
  }));
  s.attemptDutyIdsBySourceIntent.set(record.sourceIntentId, record.dutyId);
  return undefined;
};
const applyAttemptDutyAssigned = (s: MutableReplayState, event: CanonicalEvent, position: U53, hooks: ReplayHooks): Result => {
  const d = event.data as { dutyId: string; fromAgentId: string; toAgentId: string; actorId: string };
  const duty = s.attemptDuties.get(d.dutyId);
  if (duty === undefined) return "attempt duty unknown";
  const source = attemptSource(s, duty.record.sourceIntentId);
  if (source === undefined || d.fromAgentId !== duty.currentAssigneeId || d.toAgentId === d.fromAgentId || d.toAgentId !== source.tenure.agentId) return "attempt duty cannot be assigned";
  const failure = authorizeAttempt(s, event, position, hooks, d.actorId, source, "ASSIGN_ATTEMPT_DUTY");
  if (failure !== undefined) return failure;
  const assignment = Object.freeze({ fromAgentId: d.fromAgentId, toAgentId: d.toAgentId, actorId: d.actorId, eventId: event.id, eventPosition: position, assignedAt: event.timestamp });
  s.attemptDuties.set(d.dutyId, Object.freeze({ ...duty, currentAssigneeId: d.toAgentId, assignments: Object.freeze([...duty.assignments, assignment]) }));
  return undefined;
};
const applyAttemptDutyReviewClosed = (s: MutableReplayState, event: CanonicalEvent, position: U53, hooks: ReplayHooks): Result => {
  if (!policyEnablesAttemptReviews(s.genesis.adapterPolicyHash)) return "edition does not enable reviews";
  const d = event.data as { dutyId: string; actorId: string; observationEventIds: readonly string[]; summaryDigest: ContentHash };
  const duty = s.attemptDuties.get(d.dutyId);
  if (duty === undefined || duty.currentAssigneeId !== d.actorId) return "actor is not the duty assignee";
  const source = attemptSource(s, duty.record.sourceIntentId);
  const observations = s.outcomeObservations.get(duty.record.sourceIntentId) ?? [];
  if (source === undefined || observations.length !== d.observationEventIds.length || (d.observationEventIds.length > 0 && !strictlySorted(d.observationEventIds))) {
    return "review does not list the recorded observations";
  }
  const failure = authorizeAttempt(s, event, position, hooks, d.actorId, source, "CLOSE_ATTEMPT_DUTY");
  if (failure !== undefined) return failure;
  if (!observations.every((o) => d.observationEventIds.includes(o.eventId))) return "review omits an observation";
  const review = Object.freeze({ dutyId: d.dutyId, actorId: d.actorId, observationEventIds: d.observationEventIds, summaryDigest: d.summaryDigest, eventId: event.id, eventPosition: position, reviewedAt: event.timestamp });
  s.attemptDutyReviews.set(d.dutyId, Object.freeze([...(s.attemptDutyReviews.get(d.dutyId) ?? []), review]));
  return undefined;
};

// ---------------------------------------------------------------- format-1 anchors and the dispatcher

const applyAnchorRecorded = (s: MutableReplayState, event: CanonicalEvent, position: U53): Result => {
  const d = event.data as { anchoredHead: HistoryHead; anchor: string };
  // Informational: the anchored head must be a prefix of this very history.
  if (!(d.anchoredHead.position < position) || d.anchoredHead.hash !== s.eventHistoryHashes[d.anchoredHead.position]) return "anchored head is not a prefix of this history";
  s.anchors.push(Object.freeze({ head: d.anchoredHead, anchor: d.anchor, eventId: event.id, eventPosition: position }));
  return undefined;
};

/**
 * OWNER_KEYS_ROTATED (format 1): the signature was checked against the set in
 * force before the event; here the owner-key rules (`ownerKeyEventTransition`:
 * the key-set rules, pre-rotation when the epoch being left has a commitment,
 * and no commitment-less rotation that keeps every key; in format 2 also the
 * policy rotation of A-96) decide, and the epochs are replaced by the result. The head before the event is `s.head` (the
 * reducer moves it only after the transition). Never inside a migrated legacy
 * prefix (the shadow view has the legacy format).
 */
const applyOwnerKeyEvent = (s: MutableReplayState, event: CanonicalEvent, position: U53): Result => {
  if (insidePrefix(s)) return "owner key rotation is not allowed inside a migrated prefix";
  const outcome = ownerKeyEventTransition(s.ownerKeyEpochs, event, {
    domain: s.genesis.domain, previousHead: { hash: s.eventHistoryHashes[position - 1]!, position: position - 1 }, algorithm: s.hashAlgorithm,
  }, { policies: isFormat2(s.format), foreignDigests: () => new Set(foreignCredentials(s).map(ownerKeyDigest)) });
  if (!outcome.ok) return outcome.reason;
  s.ownerKeyEpochs = outcome.epochs.slice();
  return undefined;
};

/**
 * A-117.1 `foreign(σ)`: the credentials of every `session` and `counterparty` record of `s` (the state before the event,
 * whatever their status or expiry), as the foreign-credential rules compare them: by §3.3 identity (`credentialId`) or by
 * next-key digest (`ownerKeyDigest`). A derived index, not a record.
 */
export const foreignCredentials = (s: ReplayState): readonly Readonly<{ scheme: SignatureScheme; credential: string }>[] => [
  ...Array.from(s.runtimeSessions.values(), (session) => ({ scheme: session.credentialScheme, credential: session.credentialAddressKey })),
  ...Array.from(s.counterparties.values()).flatMap((record) => (record as CounterpartyRecord).keys),
];
/** `foreign(σ)` by §3.3 credential identity. */
export const foreignCredentialIds = (s: ReplayState): ReadonlySet<string> => new Set(foreignCredentials(s).map(credentialId));
/**
 * A-110.2 / A-117.4 (rows 8 and 36): while the epoch in force at `position` carries `policy`, a session or counterparty
 * credential may be neither an owner credential in force, nor committed as a next owner key, nor an attester credential
 * of that policy. The reason (TRANSITION_INVALID), or `undefined`; nothing without a policy.
 */
const ownerCredentialClash = (s: MutableReplayState, position: U53, key: Readonly<{ scheme: SignatureScheme; credential: string }>): string | undefined => {
  const epoch = ownerKeyEpochAt(s, position);
  if (epoch?.policy === undefined) return undefined;
  const id = credentialId(key);
  const owner = epoch.keys.find((ownerKey) => credentialId(ownerKey) === id);
  if (owner !== undefined) return `is the credential of owner key ${owner.keyId}; under an owner approval policy it cannot be admitted (A-110.2)`;
  if (epoch.nextKeyDigests?.includes(ownerKeyDigest(key)) === true) return "is committed as a next owner key; under an owner approval policy it cannot be admitted (A-110.2)";
  const attester = epoch.policy.attesters?.find((entry) => credentialId(entry) === id);
  return attester === undefined ? undefined : `is the credential of attester ${attester.keyId}; under an owner approval policy it cannot be admitted (A-117.4)`;
};
const isPrefixBefore = (s: MutableReplayState, head: HistoryHead, position: U53): boolean => head.position < position && s.eventHistoryHashes[head.position] === head.hash;
const sameHead = (a: HistoryHead, b: HistoryHead): boolean => a.hash === b.hash && a.position === b.position && a.canonicalTime === b.canonicalTime;
/** The quorum of a binding event's policy counts the witnesses bound after it (at least 1). */
const policyFailure = (policy: BoundPolicy, bound: number): Result =>
  policy.quorum > Math.max(1, bound) ? `witness binding: policy quorum ${policy.quorum} exceeds the ${bound} witness(es) bound after the event` : undefined;

/** The fields a registration receipt may carry (`WitnessReceipt`, docs/reference/witness-protocol.md §9.5): the record is closed. */
const REGISTRATION_FIELDS = ["version", "witness", "entry", "index", "checkpoint", "inclusionProof"] as const;
const REGISTRATION_WITNESS_FIELDS = ["origin", "verifierKey"] as const;
const registrationFieldFailure = (receipt: unknown): string | undefined => {
  const extra = (value: unknown, allowed: readonly string[]) =>
    value !== null && typeof value === "object" && !Array.isArray(value) ? Object.keys(value).filter((key) => !allowed.includes(key)) : [];
  const top = extra(receipt, REGISTRATION_FIELDS);
  if (top.length > 0) return `has an unknown field ${JSON.stringify(top[0])}`;
  const inner = extra((receipt as Readonly<Record<string, unknown>>).witness, REGISTRATION_WITNESS_FIELDS);
  return inner.length > 0 ? `has an unknown witness field ${JSON.stringify(inner[0])}` : undefined;
};

/**
 * WITNESSES_BOUND (format 1): binds each named witness (a verifier key bound already is re-bound in place: its URL,
 * name, allowInsecureHttp and registration are replaced). A `registration` must be the witness's own signed receipt
 * (`verifyWitnessReceipt` with its verifier key, and no fields beyond a receipt's) of the REGISTERED leaf of exactly this history's genesis. At most 16
 * witnesses stay bound, and the policy quorum is at most their number. Never inside a migrated legacy prefix.
 */
const applyWitnessesBound = (s: MutableReplayState, event: CanonicalEvent, position: U53): Result => {
  if (insidePrefix(s)) return "a witness binding is not allowed inside a migrated prefix";
  const d = controlEffect(event.data) as { witnesses: readonly Readonly<{ url: string; verifierKey: string; name?: string; allowInsecureHttp?: true; registration?: unknown }>[]; policy: BoundPolicy };
  const bound = s.boundWitnesses.slice();
  for (const w of d.witnesses) {
    let registration: BoundWitness["registration"];
    if (w.registration !== undefined) {
      const unknown = registrationFieldFailure(w.registration);
      if (unknown !== undefined) return `witness binding: the registration receipt of ${w.verifierKey} ${unknown}`;
      const verdict = verifyWitnessReceipt(w.registration, [w.verifierKey]);
      if (!verdict.ok) return `witness binding: the registration receipt of ${w.verifierKey} does not verify (${verdict.reason}: ${verdict.message})`;
      const entry = (w.registration as WitnessReceipt).entry as unknown as Readonly<Record<string, unknown>>;
      let sameGenesis = false;
      try { sameGenesis = canonicalEncode(entry.genesis) === canonicalEncode(s.events[0]); } catch { sameGenesis = false; }
      if (entry.kind !== "REGISTERED" || entry.historyId !== s.eventHistoryHashes[0] || !sameGenesis) {
        return `witness binding: the registration receipt of ${w.verifierKey} is not the REGISTERED leaf of this history`;
      }
      registration = Object.freeze({ receipt: w.registration as WitnessReceipt, index: verdict.index });
    }
    const record: BoundWitness = Object.freeze({
      url: w.url, verifierKey: w.verifierKey, ...(w.name === undefined ? {} : { name: w.name }), ...(w.allowInsecureHttp === true ? { allowInsecureHttp: true as const } : {}),
      ...(registration === undefined ? {} : { registration }), eventId: event.id, eventPosition: position,
    });
    const at = bound.findIndex((b) => b.verifierKey === w.verifierKey);
    if (at >= 0) bound[at] = record; else bound.push(record);
  }
  if (bound.length > MAX_BOUND_WITNESSES) return `witness binding: at most ${MAX_BOUND_WITNESSES} remote witnesses can be bound`;
  const policy = Object.freeze({ quorum: d.policy.quorum, requireOnOpen: d.policy.requireOnOpen, maxUnwitnessedEvents: d.policy.maxUnwitnessedEvents });
  const failure = policyFailure(policy, bound.length);
  if (failure !== undefined) return failure;
  s.boundWitnesses = Object.freeze(bound);
  s.boundPolicy = policy;
  s.boundPolicyPosition = position;
  return undefined;
};

/**
 * WITNESSES_UNBOUND (format 1): every named verifier key must be bound; an `acceptedLoss` names, for some of them, a head
 * the witness holds that is not a prefix of this history (the loss the owner accepts). The policy quorum is at most the
 * witnesses that stay bound (or 1). Never inside a migrated legacy prefix.
 */
const applyWitnessesUnbound = (s: MutableReplayState, event: CanonicalEvent, position: U53): Result => {
  if (insidePrefix(s)) return "a witness unbinding is not allowed inside a migrated prefix";
  const d = controlEffect(event.data) as { verifierKeys: readonly string[]; policy: BoundPolicy; acceptedLoss?: { heads: readonly Readonly<{ verifierKey: string; head: HistoryHead }>[] } };
  for (const key of d.verifierKeys) if (!s.boundWitnesses.some((b) => b.verifierKey === key)) return `witness unbinding: ${key} is not bound to this history`;
  for (const loss of d.acceptedLoss?.heads ?? []) {
    if (!d.verifierKeys.includes(loss.verifierKey)) return `witness unbinding: the accepted loss names ${loss.verifierKey}, which this event does not unbind`;
    if (isPrefixBefore(s, loss.head, position)) return `witness unbinding: the accepted loss of ${loss.verifierKey} names a head this history contains (position ${loss.head.position}): nothing was lost`;
  }
  const bound = s.boundWitnesses.filter((b) => !d.verifierKeys.includes(b.verifierKey));
  const policy = Object.freeze({ quorum: d.policy.quorum, requireOnOpen: d.policy.requireOnOpen, maxUnwitnessedEvents: d.policy.maxUnwitnessedEvents });
  const failure = policyFailure(policy, bound.length);
  if (failure !== undefined) return failure;
  s.boundWitnesses = Object.freeze(bound);
  s.boundPolicy = policy;
  s.boundPolicyPosition = position;
  return undefined;
};

// ---------------------------------------------------------------- format 2: checkpoints and the E2/E4 transitions

/**
 * STATE_CHECKPOINT (SPEC §7.3), in order after the control signature: `head` is the short head immediately before the
 * event (`TRANSITION_INVALID`); `stateRoot` and `recordCount` are `rootAt(position−1)` and its leaf count
 * (`STATE_ROOT_MISMATCH`); `projectionHead` is the §12.3 head at `position−1`, or `null` iff the projection is off
 * (`PROJECTION_HEAD_MISMATCH`). A checkpoint adds only its own `event` record.
 */
const applyStateCheckpoint = (s: MutableReplayState, event: CanonicalEvent, position: U53): Result => {
  const d = controlEffect(event.data) as { head: { hash: ContentHash; position: U53 }; stateRoot: ContentHash; recordCount: U53; projectionHead: ContentHash | null };
  if (position === 0 || d.head.position !== position - 1 || d.head.hash !== s.eventHistoryHashes[position - 1]) return "checkpoint does not cite the head immediately before it";
  // A-46.3: checkpoint ids are unique among the accepted checkpoints (TRANSITION_INVALID, after the head check).
  const checkpointId = (d as { checkpointId?: string }).checkpointId as string;
  if (s.recordRefs.has(checkpointIdKey(checkpointId))) return `checkpoint id ${checkpointId} is already used (A-46.3)`;
  if (d.stateRoot !== s.stateRoots[position - 1] || d.recordCount !== s.stateRecords.size) return failWith("STATE_ROOT_MISMATCH", "checkpoint stateRoot or recordCount differs from the state before it");
  const expected = s.genesis.projection === null ? null : s.projectionHeads[position - 1];
  if (d.projectionHead !== expected) return failWith("PROJECTION_HEAD_MISMATCH", "checkpoint projectionHead differs from the projection head before it");
  s.recordRefs.set(checkpointIdKey(checkpointId), Object.freeze({ position }));
  return undefined;
};
/** A-46.3: the accepted checkpoint ids (bookkeeping beside the records; rebuilt from the type-35 bodies). */
export const checkpointIdKey = (checkpointId: string): string => `checkpointId\u0000${checkpointId}`;
// ---- SPEC §9.1 budgets: the record transitions; the decision procedure of §9.4–9.5 is `budgets.ts`.
/** SPEC §9.1: at most 256 budgets per history, CLOSED ones included (the 257th declaration is TRANSITION_INVALID). */
export const MAX_BUDGETS = 256;
const applyBudgetDeclared = (s: MutableReplayState, event: CanonicalEvent, position: U53): Result => {
  const d = controlEffect(event.data);
  const budgetId = d.budgetId as string;
  if (s.budgets.has(budgetId)) return "budget id already declared";
  if (s.budgets.size >= MAX_BUDGETS) return `at most ${MAX_BUDGETS} budgets per history`;
  s.budgets.set(budgetId, declaredBudgetRecord(d, position, event.timestamp));
  return undefined;
};
const applyBudgetUpdated = (s: MutableReplayState, event: CanonicalEvent, position: U53): Result => {
  const d = controlEffect(event.data);
  const old = s.budgets.get(d.budgetId as string) as BudgetRecord | undefined;
  if (old === undefined || old.status !== "ACTIVE") return "budget is not active";
  try {
    s.budgets.set(old.budgetId, updatedBudgetRecord(s, old, d, position, event.timestamp));
  } catch (error) {
    return error instanceof Error ? error.message : "budget update failed";
  }
  return undefined;
};
const applyBudgetClosed = (s: MutableReplayState, event: CanonicalEvent, position: U53): Result => {
  const d = controlEffect(event.data);
  const old = s.budgets.get(d.budgetId as string) as BudgetRecord | undefined;
  if (old === undefined || old.status !== "ACTIVE") return "budget is not active";
  s.budgets.set(old.budgetId, closedBudgetRecord(old, position));
  return undefined;
};
// ---- SPEC §11.1 counterparties
type CounterpartyRecord = Readonly<{ counterpartyId: string; keys: readonly Readonly<{ keyId: string; scheme: "ed25519"; credential: string }>[]; status: "ACTIVE" | "RETIRED"; lastReceiptDigest: ContentHash | null; receiptCount: U53; position: U53 }>;
const applyCounterpartyRegistered = (s: MutableReplayState, event: CanonicalEvent, position: U53): Result => {
  const d = controlEffect(event.data) as { counterpartyId: string; keys: CounterpartyRecord["keys"] };
  const previous = s.counterparties.get(d.counterpartyId) as CounterpartyRecord | undefined;
  if (previous !== undefined && previous.status === "ACTIVE") return "counterparty is already registered";
  for (const key of d.keys) {
    const owned = ownerCredentialClash(s, position, key);
    if (owned !== undefined) return `counterparty key ${key.keyId} ${owned}`;
  }
  // Re-registration keeps the receipt chain (SPEC §11.1).
  s.counterparties.set(d.counterpartyId, Object.freeze({ counterpartyId: d.counterpartyId, keys: d.keys, status: "ACTIVE", lastReceiptDigest: previous?.lastReceiptDigest ?? null, receiptCount: previous?.receiptCount ?? 0, position }));
  return undefined;
};
const applyCounterpartyRetired = (s: MutableReplayState, event: CanonicalEvent): Result => {
  const d = controlEffect(event.data) as { counterpartyId: string };
  const current = s.counterparties.get(d.counterpartyId) as CounterpartyRecord | undefined;
  if (current === undefined || current.status !== "ACTIVE") return "counterparty is not active";
  s.counterparties.set(d.counterpartyId, Object.freeze({ ...current, status: "RETIRED" }));
  return undefined;
};
// ---- SPEC §10.1 refusals
const sameShortHead = (a: Readonly<{ hash: ContentHash; position: U53 }>, b: HistoryHead): boolean => a.hash === b.hash && a.position === b.position;
const applyRequestRefused = (s: MutableReplayState, event: CanonicalEvent, position: U53): Result => {
  const { refusalAuthorization, ...d } = event.data as Rec & { refusalAuthorization: { hash: ContentHash; signature: string }; refusalSource: string; request: Rec & { actorId: string; amount?: string }; expectedHistoryHead: HistoryHead; evaluationTime: U53; refusalId: string; decision: string; code: string; budgetId?: string; connector?: { connectorId: string } };
  const binding = d as unknown as SessionBinding;
  const outcome = sessionAuthorizationFailure(s, binding, event.timestamp, hashCanonical(refusalChallenge(s.genesis.domain, d, event), "sha256"), refusalAuthorization.hash, refusalAuthorization.signature);
  if (!outcome.ok) return failWith(sessionFailureCode(outcome, "REFUSAL_AUTHORIZATION_INVALID"), outcome.reason);
  // Actor binding: CORE/BUDGET refusals are signed by the actor's own session, CONNECTOR refusals by the connector's.
  const boundTo = d.refusalSource === "CONNECTOR" ? d.connector!.connectorId : d.request.actorId;
  if (outcome.session.agentId !== boundTo) return "the signing session's agent is not the refusal's actor";
  if (d.evaluationTime !== event.timestamp) return "refusal evaluationTime differs from the event timestamp";
  if (position === 0 || !sameHead(d.expectedHistoryHead, s.head)) return "refusal does not cite the head immediately before it";
  if (d.refusalSource !== "CONNECTOR") {
    // SPEC §10.1: replay re-runs §8.1 on the pre-event state (consequential false) and requires decision, code and
    // budgetId (null for CORE; the schema admits `budgetId` iff the source is BUDGET) to be reproduced. The §8.1 run
    // includes the budget procedure and the AMOUNT_OVERFLOW closure (`finalizeCandidate`).
    const request: Record<string, unknown> = { ...d.request };
    if (typeof request.amount === "string") request.amount = amountOf(request.amount);
    const result = authorizeState(s, {
      expectedHistoryHead: s.head, domain: s.genesis.domain, policyVersion: s.genesis.policyVersion, rootRecognitionPolicy: s.genesis.rootRecognitionPolicy,
      request, evaluationTime: d.evaluationTime, consequential: false,
    });
    const budgetId = result.decision === "DENY" ? (result.budgetId ?? null) : null;
    if (result.decision !== d.decision || (result.decision !== "ALLOW" && result.code !== d.code) || budgetId !== (d.budgetId ?? null)) {
      return failWith("REFUSAL_NOT_REPRODUCED", `the pre-event state decides ${result.decision}${result.decision === "ALLOW" ? "" : ` ${result.code}`}, not ${d.decision} ${d.code}`);
    }
  }
  if (s.refusals.has(d.refusalId)) return "refusal id already recorded";
  s.refusals.set(d.refusalId, Object.freeze({
    refusalId: d.refusalId, refusalSource: d.refusalSource, decision: d.decision, code: d.code, budgetId: d.budgetId ?? null, actorId: d.request.actorId, action: d.request.action,
    resource: d.request.resource, amount: d.request.amount ?? null, evaluationTime: d.evaluationTime, eventId: event.id, position,
  }));
  return undefined;
};
// ---- SPEC §10.2 effects
/** SPEC §10.2: at most 64 effects per intent (`EFFECT_LIMIT`). */
export const MAX_EFFECTS_PER_INTENT = 64;
const intentIsAdmitted = (s: MutableReplayState, intentId: string): boolean => s.intentAdmissions.has(intentId);
const applyEffectRecorded = (s: MutableReplayState, event: CanonicalEvent, position: U53): Result => {
  const { effectAuthorization, ...d } = event.data as Rec & { effectAuthorization: { hash: ContentHash; signature: string }; effectId: string; intentId: string; measurer: { kind: string; id: string }; metric: string; unit: string; amount: string; observedAt: U53 };
  const binding = d as unknown as SessionBinding;
  const outcome = sessionAuthorizationFailure(s, binding, event.timestamp, hashCanonical(effectChallenge(s.genesis.domain, d, s.head, event), "sha256"), effectAuthorization.hash, effectAuthorization.signature);
  if (!outcome.ok) return failWith(sessionFailureCode(outcome, "EFFECT_AUTHORIZATION_INVALID"), outcome.reason);
  if (d.measurer.kind === "COUNTERPARTY") {
    const counterparty = s.counterparties.get(d.measurer.id) as CounterpartyRecord | undefined;
    if (counterparty === undefined || counterparty.status !== "ACTIVE") return "measurer is not an active counterparty";
    // A-36.1: the effect cites an earlier recorded envelope of that counterparty for the intent and carries its amount.
    const digests = s.recordRefs.get(counterpartyEnvelopeKey(d.intentId, d.measurer.id))?.digests as Readonly<Record<string, string>> | undefined;
    const detail = (event.data as Rec).detailDigest;
    if (typeof detail !== "string" || digests === undefined || !Object.hasOwn(digests, detail)) return "a COUNTERPARTY effect's detailDigest must be the envelopeDigest of an earlier recorded receipt of that counterparty for the intent (A-36.1)";
    if (digests[detail] !== d.amount) return "a COUNTERPARTY effect's amount must equal its envelope's amount (A-36.1)";
  } else if (d.measurer.id !== outcome.session.agentId) return "measurer is not the signing session's agent";
  // A-37.1: a SESSION-measured effect is the intent's actor's own (CONNECTOR effects may concern any admitted intent).
  if (d.measurer.kind === "SESSION" && s.intentDeclarations.get(d.intentId)?.data.actorId !== outcome.session.agentId) return "a SESSION effect must be recorded by a session of the intent's actor (A-37.1)";
  if (!intentIsAdmitted(s, d.intentId)) return "effect names an intent that is not admitted";
  if (d.observedAt > event.timestamp) return "effect observedAt is after the event timestamp";
  let count = 0;
  for (const effect of s.effects.values()) if (effect.intentId === d.intentId) count += 1;
  if (count >= MAX_EFFECTS_PER_INTENT) return failWith("EFFECT_LIMIT", `at most ${MAX_EFFECTS_PER_INTENT} effects per intent`);
  if (s.effects.has(d.effectId)) return "effect id already recorded";
  s.effects.set(d.effectId, Object.freeze({
    effectId: d.effectId, intentId: d.intentId, measurerKind: d.measurer.kind, measurerId: d.measurer.id, metric: d.metric, unit: d.unit, amount: d.amount, observedAt: d.observedAt, eventId: event.id, position,
  }));
  return undefined;
};
// ---- SPEC §11.2 counterparty receipts
const applyCounterpartyReceiptRecorded = (s: MutableReplayState, event: CanonicalEvent): Result => {
  const { recordAuthorization, ...d } = event.data as Rec & { recordAuthorization: { hash: ContentHash; signature: string }; intentId: string; envelope: Rec & { counterpartyId: string; keyId: string; signature: `0x${string}`; historyId: ContentHash; logicalId: string; intentDigest: ContentHash; previousReceiptDigest: ContentHash | null } };
  const envelope = d.envelope;
  const counterparty = s.counterparties.get(envelope.counterpartyId) as CounterpartyRecord | undefined;
  const key = counterparty?.status === "ACTIVE" ? counterparty.keys.find((k) => k.keyId === envelope.keyId) : undefined;
  if (key === undefined) return "counterparty is not active or does not hold the key";
  const suite = suiteFor("ed25519");
  if (!suite.verify(envelopeSigningHash(envelope), envelope.signature, suite.normalizeCredential(key.credential))) return failWith("COUNTERPARTY_SIGNATURE_INVALID", "the envelope signature does not verify under the counterparty key");
  const binding = d as unknown as SessionBinding;
  const outcome = sessionAuthorizationFailure(s, binding, event.timestamp, hashCanonical(counterpartyRecordChallenge(s.genesis.domain, d, s.head, event), "sha256"), recordAuthorization.hash, recordAuthorization.signature);
  if (!outcome.ok) return failWith(sessionFailureCode(outcome, "RECORD_AUTHORIZATION_INVALID"), outcome.reason);
  if (envelope.historyId !== s.eventHistoryHashes[0]) return "envelope names another history";
  const declaration = s.intentDeclarations.get(d.intentId);
  if (envelope.logicalId !== d.intentId || !intentIsAdmitted(s, d.intentId) || declaration === undefined || envelope.intentDigest !== declaration.declarationDigest) return "envelope does not bind the admitted intent";
  // A-45.1: before the chain check, the envelope's observation is not after the event.
  if ((envelope.observedAt as number) > event.timestamp) return "envelope observedAt is after the event timestamp (A-45.1)";
  if (envelope.previousReceiptDigest !== counterparty!.lastReceiptDigest) return "envelope breaks the counterparty's receipt chain";
  s.counterparties.set(counterparty!.counterpartyId, Object.freeze({ ...counterparty!, lastReceiptDigest: envelopeDigest(envelope), receiptCount: counterparty!.receiptCount + 1 }));
  recordCounterpartyEnvelope(s, d.intentId, envelope.counterpartyId, envelopeDigest(envelope), envelope.amount as string);
  return undefined;
};
/**
 * A-36.1: the envelope digests (with their amounts) of the accepted type-40 events per (intentId, counterpartyId) —
 * bookkeeping beside the §7.2 records (no state record), rebuilt from the type-40 event bodies (state-rebuild.ts).
 */
export const counterpartyEnvelopeKey = (intentId: string, counterpartyId: string): string => `counterpartyEnvelopes\u0000${intentId}\u0000${counterpartyId}`;
export const recordCounterpartyEnvelope = (s: MutableReplayState, intentId: string, counterpartyId: string, digest: ContentHash, amount: string): void => {
  const key = counterpartyEnvelopeKey(intentId, counterpartyId);
  const known = (s.recordRefs.get(key)?.digests as Readonly<Record<string, string>> | undefined) ?? {};
  s.recordRefs.set(key, Object.freeze({ digests: Object.freeze({ ...known, [digest]: amount }) }));
};
// ---- SPEC §10.3 / A-71 (post-E5): reconciliation observations (type 42)
/** The `(streamId, eventRef)` index of the accepted observations (A-71.3 step 6, A-89.5: one index for the whole history). */
export const observationIndexKey = (streamId: string, eventRef: string): string => `observationIndex\u0000${streamId}\u0000${eventRef}`;
type ObservationIndex = Readonly<{ earliest: U53; digests: Readonly<Record<string, U53>> }>;
/**
 * The accepted observations of `(streamId, eventRef)`: the earliest one's position and, per `eventDigest`, the position of
 * the one accepted observation with it (A-86.1: a second one is OBSERVATION_DUPLICATE). Bookkeeping beside the records,
 * rebuilt from the `observation` records (state-rebuild.ts).
 */
export const observationIndexOf = (s: ReplayState, streamId: string, eventRef: string): ObservationIndex | undefined =>
  s.recordRefs.get(observationIndexKey(streamId, eventRef)) as ObservationIndex | undefined;
export const indexObservation = (s: MutableReplayState, streamId: string, eventRef: string, eventDigest: string, position: U53): void => {
  const key = observationIndexKey(streamId, eventRef);
  const known = s.recordRefs.get(key) as ObservationIndex | undefined;
  s.recordRefs.set(key, Object.freeze({ earliest: known?.earliest ?? position, digests: Object.freeze({ ...known?.digests, [eventDigest]: position }) }));
};
/** A-71.4 / A-89.1: the cursor after an accepted observation at `position` (created with `count = 1`). */
export const advancedCursor = (previous: Rec | undefined, reconcilerAgentId: string, streamId: string, eventRef: string, position: U53): Rec =>
  Object.freeze({ reconcilerAgentId, streamId, lastEventRef: eventRef, lastPosition: position, count: ((previous?.count as number | undefined) ?? 0) + 1 });
/** A-71.3 step 5: the §12.2 actor of an accepted decision event a MATCHED observation may cite (type 13 or 38), else `undefined`. */
const decisionActorAt = (s: MutableReplayState, position: U53): unknown => {
  const event = s.events[position];
  if (event?.type === "TRANSACTION_INTENT_ADMITTED") return ((event.data.authorizationProof as Rec).request as Rec).actorId;
  if (event?.type === "REQUEST_REFUSED") return (event.data.request as Rec).actorId;
  return undefined;
};
/**
 * A-71.3 as amended by A-86.1, after the schema: session authorization (fence first → SESSION_FENCED; every other §6.2
 * failure, the hash and the signature → OBSERVATION_AUTHORIZATION_INVALID) → reconciler binding → `expectedHistoryHead`
 * is the head before → MATCHED: `match.position < p`, a type-13 or type-38 event whose §12.2 actor is `call.actorId` →
 * duplicate (any accepted observation of the key with this digest → OBSERVATION_DUPLICATE) / equivocation (another
 * digest: accepted, `equivocates` = the earliest of the key) → unique `observationId` (all TRANSITION_INVALID unless named).
 */
const applyReconciliationObserved = (s: MutableReplayState, event: CanonicalEvent, position: U53): Result => {
  const { observationAuthorization, ...d } = event.data as Rec & {
    observationAuthorization: { hash: ContentHash; signature: string }; observationId: string; reconcilerAgentId: string; expectedHistoryHead: HistoryHead;
    source: { streamId: string; eventRef: string; eventDigest: string }; call: Rec & { actorId: string }; match: { result: string; position?: U53 };
  };
  const outcome = sessionAuthorizationFailure(s, d as unknown as SessionBinding, event.timestamp, hashCanonical(reconciliationChallenge(s.genesis.domain, d, event), "sha256"), observationAuthorization.hash, observationAuthorization.signature);
  if (!outcome.ok) return failWith(sessionFailureCode(outcome, "OBSERVATION_AUTHORIZATION_INVALID"), outcome.reason);
  if (outcome.session.agentId !== d.reconcilerAgentId) return "reconcilerAgentId is not the signing session's agent (A-71.3)";
  if (position === 0 || !sameHead(d.expectedHistoryHead, s.head)) return "observation does not cite the head immediately before it";
  if (d.match.result === "MATCHED") {
    const at = d.match.position!;
    if (at >= position) return "a MATCHED observation cites a position at or after its own";
    const actor = decisionActorAt(s, at);
    if (actor === undefined) return "a MATCHED observation must cite an accepted TRANSACTION_INTENT_ADMITTED or REQUEST_REFUSED";
    if (actor !== d.call.actorId) return "the cited decision's actor is not call.actorId";
  }
  const index = observationIndexOf(s, d.source.streamId, d.source.eventRef);
  if (index !== undefined && Object.hasOwn(index.digests, d.source.eventDigest)) {
    return failWith("OBSERVATION_DUPLICATE", `an observation of ${d.source.streamId}/${d.source.eventRef} with this digest is accepted at ${index.digests[d.source.eventDigest]} (A-86)`);
  }
  if (s.reconciliationObservations.has(d.observationId)) return "observation id already recorded";
  s.reconciliationObservations.set(d.observationId, Object.freeze({
    observationId: d.observationId, reconcilerAgentId: d.reconcilerAgentId, source: d.source, call: d.call, match: d.match, equivocates: index?.earliest ?? null, eventId: event.id, position,
  }));
  const cursorKey = reconciliationCursorKey(d.reconcilerAgentId, d.source.streamId);
  s.reconciliationCursors.set(cursorKey, advancedCursor(s.reconciliationCursors.get(cursorKey), d.reconcilerAgentId, d.source.streamId, d.source.eventRef, position));
  indexObservation(s, d.source.streamId, d.source.eventRef, d.source.eventDigest, position);
  return undefined;
};
// ---- SPEC §13 (E4): the ported duty-policy transitions (types 29–31), `portable-replay.ts:2074-2102`.
/**
 * ATTEMPT_DUTY_POLICY_ACTIVATED (SPEC §13.1), after the schema: an E5/E6 genesis; the activation requirements
 * (`duty-policy.ts:174-201`: no policy yet, the descriptor re-derives byte for byte with its hash, the actor is the
 * current occupant of the duty role, `activationAuthorityId` is the exact unrevoked root grant); the administrative
 * authorization of §8.4 (`portable-replay.ts:2080`); the proof's recognized root and single-element path are that grant
 * (`duty-policy.ts:204-207`). State: `attemptDutyPolicies` gains the activation with `priorHead` = the head before the
 * event (`portable-replay.ts:2082-2086`); the §7.2 `duty.policy` record and the capacity quota follow from it.
 */
const applyDutyPolicyActivated = (s: MutableReplayState, event: CanonicalEvent, position: U53, hooks: ReplayHooks): Result => {
  if (!policyEnablesAttemptDuties(s.genesis.adapterPolicyHash)) return "edition does not enable attempt duties"; // portable-authority-engine.ts:4252
  const d = event.data as unknown as DutyPolicyActivatedEffect & { administrativeAuthorization: { authorityProof: AuthorizationProof } };
  const requirements = dutyPolicyActivationRequirements(s, d, event.timestamp); // :2079
  if (requirements === undefined) return "duty policy activation requirements not met";
  const failure = administrative(s, event, position, hooks, requirements); // :2080
  if (failure !== undefined) return failure;
  if (!dutyPolicyActivationProofMatches(d.administrativeAuthorization.authorityProof, d.activationAuthorityId)) return "activation proof does not select the activation grant"; // :2081
  s.attemptDutyPolicies.set(d.descriptor.dutyId, Object.freeze({ // :2082-2086
    descriptor: d.descriptor, descriptorHash: d.descriptorHash, activationAuthorityId: d.activationAuthorityId, actorId: d.actorId,
    eventId: event.id, eventPosition: position, activatedAt: event.timestamp, priorHead: s.head, dispositionCount: 0, contestCount: 0,
  }));
  return undefined;
};
/**
 * ATTEMPT_DUTY_DISPOSITION_RECORDED / ATTEMPT_DUTY_CONTEST_RECORDED (SPEC §13.2), after the schema: the finding validates
 * against the pre-event state (`duty-disposition.ts:88-97`: literals, an active policy, eligibility, the re-derived
 * challenge byte for byte, the attester's signature); the outer actor is the duty's current assignee and the occupant of
 * the durable role (`duty-disposition.ts:44-53`); the outer administrative authorization under RECORD_DUTY_DISPOSITION
 * (`portable-replay.ts:2096`). State: the counts (`:2098-2100`) and the §7.2 `duty.dispositions` row.
 */
const applyDutyDisposition = (s: MutableReplayState, event: CanonicalEvent, position: U53, hooks: ReplayHooks): Result => {
  const e = event as unknown as DutyUnsignedTransition;
  if (!validateDutyFinding(s, e)) return "duty finding does not validate against the state before the event"; // :2094
  const req = dutyRequirements(s, e.data.dutyId, e.data.actorId, e.data.dispositionAuthorityId, false, event.timestamp); // :2095
  if (req === undefined) return "actor is not the duty's current assignee and role occupant";
  const failure = administrative(s, event, position, hooks, req); // :2096
  if (failure !== undefined) return failure;
  const policy = s.attemptDutyPolicies.get(e.data.dutyId)!; // :2097
  const disposition = event.type === "ATTEMPT_DUTY_DISPOSITION_RECORDED";
  s.attemptDutyPolicies.set(e.data.dutyId, Object.freeze({ ...policy, dispositionCount: policy.dispositionCount + (disposition ? 1 : 0), contestCount: policy.contestCount + (disposition ? 0 : 1) })); // :2098-2100
  const row = Object.freeze({ eventId: event.id, position, type: e.type, findingHash: hashCanonical(e.data.finding, s.hashAlgorithm) });
  s.attemptDutyDispositions.set(e.data.dutyId, Object.freeze([...(s.attemptDutyDispositions.get(e.data.dutyId) ?? []), row]));
  return undefined;
};

// ---------------------------------------------------------------- A-51 / A-58.5 (format 2): lifecycle authorization, fences, list bounds

/** A-51.5: list bounds (TRANSITION_INVALID), counted over the whole history including a migrated prefix (A-52.1). */
export const MAX_OUTCOMES_PER_INTENT = 16;
export const MAX_OBSERVATIONS_PER_INTENT = 64;
export const MAX_ASSIGNMENTS_PER_DUTY = 64;
export const MAX_REVIEWS_PER_DUTY = 64;
export const MAX_RECEIPTS_PER_INTENT = 16;
const LIFECYCLE_SIGNED: ReadonlySet<EventType> = new Set<EventType>(["TRANSACTION_INTENT_CONSUMED", "TRANSACTION_OUTCOME_RECORDED", "RECEIPT_RECORDED"]);
const ADMINISTRATIVE_OUTER: ReadonlySet<EventType> = new Set<EventType>([
  "OBLIGATION_CREATED", "OBLIGATION_PERFORMANCE_ASSIGNED", "OBLIGATION_STATUS_RECORDED", "OUTCOME_OBSERVATION_RECORDED", "ATTEMPT_DUTY_CREATED",
  "ATTEMPT_DUTY_ASSIGNED", "ATTEMPT_DUTY_REVIEW_CLOSED", "ATTEMPT_DUTY_POLICY_ACTIVATED", "ATTEMPT_DUTY_DISPOSITION_RECORDED", "ATTEMPT_DUTY_CONTEST_RECORDED",
]);
/** The fence of A-58.5 on a session named by `(runtimeSessionId, credentialKeyId)`: found, key matching, and its epoch behind its agent's. */
const fenceReason = (s: MutableReplayState, sessionId: unknown, keyId: unknown): string | undefined => {
  if (typeof sessionId !== "string") return undefined;
  const session = s.runtimeSessions.get(sessionId);
  if (session === undefined || session.credentialKeyId !== keyId) return undefined;
  const agent = s.agents.get(session.agentId);
  return agent !== undefined && session.controlEpoch !== agent.currentControlEpoch ? `session ${sessionId} belongs to control epoch ${session.controlEpoch}; its agent is at ${agent.currentControlEpoch}` : undefined;
};
/** A-58.5: SESSION_FENCED first for an admission's session and the outer session of a ▲ event (never the §13.2 finding attester's). */
const fencedOuterSession = (s: MutableReplayState, event: CanonicalEvent): string | undefined => {
  const d = event.data as Rec;
  if (event.type === "TRANSACTION_INTENT_ADMITTED") { const proof = d.authorizationProof as Rec; return fenceReason(s, proof.runtimeSessionId, proof.credentialKeyId); }
  if (ADMINISTRATIVE_OUTER.has(event.type)) { const challenge = (d.administrativeAuthorization as Rec | undefined)?.challenge as Rec | undefined; return challenge === undefined ? undefined : fenceReason(s, challenge.runtimeSessionId, challenge.credentialKeyId); }
  return undefined;
};
/** A-51.5 bounds of the ▲ list types (observations per intent, assignments and reviews per duty); exported for the unit test. */
export const adminListBound = (s: MutableReplayState, event: CanonicalEvent): TransitionFailure | undefined => {
  const d = event.data as Rec;
  if (event.type === "OUTCOME_OBSERVATION_RECORDED" && (s.outcomeObservations.get(d.intentId as string)?.length ?? 0) >= MAX_OBSERVATIONS_PER_INTENT) return failWith("TRANSITION_INVALID", `at most ${MAX_OBSERVATIONS_PER_INTENT} observations per intent (A-51.5)`);
  if (event.type === "ATTEMPT_DUTY_ASSIGNED" && (s.attemptDuties.get(d.dutyId as string)?.assignments.length ?? 0) >= MAX_ASSIGNMENTS_PER_DUTY) return failWith("TRANSITION_INVALID", `at most ${MAX_ASSIGNMENTS_PER_DUTY} assignments per duty (A-51.5)`);
  if (event.type === "ATTEMPT_DUTY_REVIEW_CLOSED" && (s.attemptDutyReviews.get(d.dutyId as string)?.length ?? 0) >= MAX_REVIEWS_PER_DUTY) return failWith("TRANSITION_INVALID", `at most ${MAX_REVIEWS_PER_DUTY} reviews per duty (A-51.5)`);
  return undefined;
};
/** The receipt count of an intent (format-2 bookkeeping, incl. a migrated prefix; rebuilt from the `receipt` records). */
export const receiptCountOf = (s: ReplayState, intentId: string): number => ((s.recordRefs.get(`intentReceipts\u0000${intentId}`)?.count as number | undefined) ?? 0);
/**
 * A-51 (format 2, after any migrated prefix), types 14–16 in A-51.4's order: (schema already checked) → SESSION_FENCED →
 * §6.2 checks, `hash` (the lifecycle challenge of A-51.2 over the head before the event) and signature → signer binding
 * (A-51.3: consumption — the intent's actor; outcome — the intent's actor, or `attesterId` when it names an admitted
 * agent; receipt — `issuerAgentId`, with the receipt's own `runtimeSessionId`/`controlEpoch` equal to the signing
 * binding) — every failure so far RECORD_AUTHORIZATION_INVALID — → the format-1 transition preconditions on the data
 * without `recordAuthorization` → the A-51.5 bounds (both TRANSITION_INVALID; the bounds are checked before the
 * transition mutates the state, which leaves the code unchanged) → capacity (replay.ts).
 */
const applyLifecycle2 = (s: MutableReplayState, event: CanonicalEvent, position: U53, nextHead: HistoryHead): Result => {
  const { recordAuthorization, ...rest } = event.data as Rec & { recordAuthorization: LifecycleAuthorization };
  const data = Object.freeze(rest) as Rec;
  const binding: SessionBinding = { runtimeSessionId: recordAuthorization.runtimeSessionId, credentialKeyId: recordAuthorization.credentialKeyId, controlEpoch: recordAuthorization.controlEpoch };
  const expected = lifecycleAuthorizationHash(s.genesis.domain, event, { hash: s.head.hash, position: s.head.position }, binding);
  const outcome = sessionAuthorizationFailure(s, binding, event.timestamp, expected, recordAuthorization.hash, recordAuthorization.signature);
  if (!outcome.ok) return failWith(sessionFailureCode(outcome, "RECORD_AUTHORIZATION_INVALID"), outcome.reason);
  const signer = outcome.session.agentId, intentId = data.intentId as string;
  // A-60: the signer-binding stage begins by resolving the intent; an absent or not-admitted intent is TRANSITION_INVALID
  // for all three types (a missing entry never selects the binding code).
  if (!s.intentDeclarations.has(intentId) || !s.intentAdmissions.has(intentId)) return failWith("TRANSITION_INVALID", `intent ${intentId} is not an admitted intent (A-60)`);
  const actor = s.intentDeclarations.get(intentId)?.data.actorId;
  const invalid = (reason: string): TransitionFailure => failWith("RECORD_AUTHORIZATION_INVALID", reason);
  if (event.type === "TRANSACTION_INTENT_CONSUMED" && signer !== actor) return invalid("a consumption must be signed by a session of the intent's actor");
  if (event.type === "TRANSACTION_OUTCOME_RECORDED" && signer !== actor && !(signer === data.attesterId && s.agents.has(data.attesterId as string))) {
    return invalid("an outcome must be signed by a session of the intent's actor or of its attester agent");
  }
  if (event.type === "RECEIPT_RECORDED") {
    if (signer !== data.issuerAgentId) return invalid("a receipt record must be signed by a session of its issuer agent");
    if (data.runtimeSessionId !== binding.runtimeSessionId || data.controlEpoch !== binding.controlEpoch) return invalid("the receipt's runtimeSessionId and controlEpoch must equal the signing binding");
  }
  // A-51.5 bounds (before any state change; TRANSITION_INVALID like the preconditions they follow).
  if (event.type === "TRANSACTION_OUTCOME_RECORDED" && (((s.recordRefs.get(`intentOutcomes\u0000${intentId}`)?.outcomes as readonly unknown[] | undefined)?.length ?? 0) >= MAX_OUTCOMES_PER_INTENT)) {
    if (s.intentAdmissions.has(intentId)) return failWith("TRANSITION_INVALID", `at most ${MAX_OUTCOMES_PER_INTENT} outcomes per intent (A-51.5)`);
  }
  if (event.type === "RECEIPT_RECORDED" && receiptCountOf(s, intentId) >= MAX_RECEIPTS_PER_INTENT && s.intentDeclarations.has(intentId)) return failWith("TRANSITION_INVALID", `at most ${MAX_RECEIPTS_PER_INTENT} receipt records per intent (A-51.5)`);
  const inner: CanonicalEvent = Object.freeze({ id: event.id, type: event.type, timestamp: event.timestamp, data });
  return event.type === "TRANSACTION_INTENT_CONSUMED" ? applyIntentConsumed(s, inner, position, nextHead)
    : event.type === "TRANSACTION_OUTCOME_RECORDED" ? applyOutcomeRecorded(s, inner, position, nextHead)
    : applyReceiptRecorded(s, inner, position, nextHead);
};

/**
 * Apply one schema-valid event at `position`; `nextHead` is the head including it. Returns `undefined` on success, or
 * the failure with its replay code (`TRANSITION_INVALID` unless the type names another code, SPEC §5).
 */
export const applyTransition = (s: MutableReplayState, event: CanonicalEvent, position: U53, nextHead: HistoryHead, hooks: ReplayHooks): TransitionFailure | undefined => {
  const result = transition(s, event, position, nextHead, hooks);
  return result === undefined ? undefined : typeof result === "string" ? failWith("TRANSITION_INVALID", result) : result;
};
const transition = (s: MutableReplayState, event: CanonicalEvent, position: U53, nextHead: HistoryHead, hooks: ReplayHooks): Result => {
  const data = event.data;
  const by: EventRef = { id: event.id, position };
  // Format 2 after any migrated prefix (a prefix transition runs on the source-format view): A-58.5's fence for the ◇
  // admission and the outer ▲ session (the other ◇ types check it inside `sessionAuthorizationFailure`), then A-51 for
  // types 14–16 and the A-51.5 list bounds of the ▲ types 21, 23, 24.
  if (s.format === TRELLIS2_FORMAT) {
    const fenced = fencedOuterSession(s, event);
    if (fenced !== undefined) return failWith("SESSION_FENCED", fenced);
    // A-202.1: types 29–31, the §13 literal fields are the first items of the type's list after the fence (events.ts).
    const literals = dutyLiteralFailure(event);
    if (literals !== undefined) return failWith("EVENT_DATA_INVALID", literals);
    if (LIFECYCLE_SIGNED.has(event.type)) return applyLifecycle2(s, event, position, nextHead);
    const bound = adminListBound(s, event);
    if (bound !== undefined) return bound;
  }
  switch (event.type) {
    case "DEPLOYMENT_INITIALIZED":
      if (position !== 0 || s.events.length !== 0 || resolveAdapterPolicy(data.adapterPolicyHash) === undefined) return "genesis misplaced or policy unknown";
      s.genesis = data as unknown as GenesisRecord;
      // The shadow opens (and can still refuse the genesis) before anything else is written (r4 §5); the view reads the
      // fields below through `s`.
      if (s.genesis.migratedFrom !== undefined) {
        const failure = openShadow(s, s.genesis.migratedFrom);
        if (failure !== undefined) { s.genesis = NO_GENESIS; return failure; }
      }
      s.signatureScheme = s.genesis.versions.signatureScheme as SignatureScheme;
      // Epoch 0: the genesis owner keys and, with pre-rotation from the start, their next-key commitment (committed by the history id).
      // Format 2 (A-91.3): and its owner approval policy, as written.
      s.ownerKeyEpochs = [Object.freeze({
        fromPosition: 0, keys: Object.freeze((s.genesis.ownerKeys ?? []).slice()),
        ...(s.genesis.nextKeyDigests === undefined ? {} : { nextKeyDigests: Object.freeze(s.genesis.nextKeyDigests.slice()) }),
        ...(s.genesis.ownerPolicy === undefined ? {} : { policy: s.genesis.ownerPolicy }),
      })];
      return undefined;
    case "PRINCIPAL_CREATED": return applyPrincipalCreated(s, data as { principalId: string }, event, position);
    case "AGENT_CREATED": return applyAgentCreated(s, data as Parameters<typeof applyAgentCreated>[1], by);
    case "ROLE_CREATED": return applyRoleCreated(s, data as Parameters<typeof applyRoleCreated>[1], by);
    case "SUCCESSION_RULE_DECLARED": return applySuccessionRuleDeclared(s, controlEffect(data) as unknown as SuccessionRuleData, by); // the rule, not its signature
    case "AGENT_APPOINTED": return applyAgentAppointed(s, data as Parameters<typeof applyAgentAppointed>[1], by);
    case "AGENT_UNAPPOINTED": return applyAgentUnappointed(s, data as Parameters<typeof applyAgentUnappointed>[1], by);
    case "ROLE_TRANSFERRED": return applyRoleTransferred(s, data as Parameters<typeof applyRoleTransferred>[1], by);
    case "RUNTIME_SESSION_ADMITTED": return applyRuntimeSessionAdmitted(s, event, position);
    case "CONTROL_EPOCH_ADVANCED": return applyControlEpochAdvanced(s, data as Parameters<typeof applyControlEpochAdvanced>[1]);
    case "TRANSACTION_INTENT_DECLARED": return isFormat2(s.format) ? applyIntentDeclared2(s, event, position) : applyIntentDeclared(s, data as unknown as TransactionIntent, position);
    case "AGENT_TERMINATED": return applyAgentTerminated(s, data as Parameters<typeof applyAgentTerminated>[1], by);
    case "AUTHORITY_GRANTED": return applyAuthorityGranted(s, data.grant as AuthorityGrant, event, position);
    case "AUTHORITY_REVOKED": return applyAuthorityRevoked(s, data as { authorityId: string; revokerId: string }, event, position);
    case "TRANSACTION_INTENT_ADMITTED": return applyIntentAdmitted(s, event, position, nextHead, hooks);
    case "TRANSACTION_INTENT_CONSUMED": return applyIntentConsumed(s, event, position, nextHead);
    case "TRANSACTION_OUTCOME_RECORDED": return applyOutcomeRecorded(s, event, position, nextHead);
    case "RECEIPT_RECORDED": return applyReceiptRecorded(s, event, position, nextHead);
    case "OUTCOME_OBSERVATION_RECORDED": return applyOutcomeObservationRecorded(s, event, position, hooks);
    case "ATTEMPT_DUTY_CREATED": return applyAttemptDutyCreated(s, event, position, hooks);
    case "ATTEMPT_DUTY_ASSIGNED": return applyAttemptDutyAssigned(s, event, position, hooks);
    case "ATTEMPT_DUTY_REVIEW_CLOSED": return applyAttemptDutyReviewClosed(s, event, position, hooks);
    case "OBLIGATION_CREATED": return applyObligationCreated(s, event, position, nextHead, hooks);
    case "OBLIGATION_PERFORMANCE_ASSIGNED": return applyObligationPerformanceAssigned(s, event, position, hooks);
    case "OBLIGATION_STATUS_RECORDED": return applyObligationStatusRecorded(s, event, position, hooks);
    case "ANCHOR_RECORDED": return applyAnchorRecorded(s, event, position);
    case "OWNER_KEYS_ROTATED": return applyOwnerKeyEvent(s, event, position);
    case "WITNESSES_BOUND": return applyWitnessesBound(s, event, position);
    case "WITNESSES_UNBOUND": return applyWitnessesUnbound(s, event, position);
    // ---- format 2 (SPEC §5 types 29–40); the schema admits them only in a format-2 history
    case "STATE_CHECKPOINT": return applyStateCheckpoint(s, event, position);
    case "BUDGET_DECLARED": return applyBudgetDeclared(s, event, position);
    case "BUDGET_UPDATED": return applyBudgetUpdated(s, event, position);
    case "BUDGET_CLOSED": return applyBudgetClosed(s, event, position);
    case "COUNTERPARTY_REGISTERED": return applyCounterpartyRegistered(s, event, position);
    case "COUNTERPARTY_RETIRED": return applyCounterpartyRetired(s, event);
    case "REQUEST_REFUSED": return applyRequestRefused(s, event, position);
    case "EFFECT_RECORDED": return applyEffectRecorded(s, event, position);
    case "COUNTERPARTY_RECEIPT_RECORDED": return applyCounterpartyReceiptRecorded(s, event);
    case "RECONCILIATION_OBSERVED": return applyReconciliationObserved(s, event, position);
    case "ATTEMPT_DUTY_POLICY_ACTIVATED": return applyDutyPolicyActivated(s, event, position, hooks);
    case "ATTEMPT_DUTY_DISPOSITION_RECORDED": case "ATTEMPT_DUTY_CONTEST_RECORDED": return applyDutyDisposition(s, event, position, hooks);
  }
};
