/**
 * Export view (SPEC §15, `irontrellis-export/2`): a projection of a history between two positions that anyone with
 * the genesis can verify — rebuild the state from `fromRecords`, check `from.stateRoot`, replay `events`, check
 * `to.stateRoot` (`verifyExportView`). This is the only interface provers, witnesses and gateways consume.
 *
 * Cost. The projection heads are kept per position by replay (`state.projectionHeads`); an end's record set and root
 * are read from the state itself (`state-roots.ts`: the live record set with every later change undone, the root
 * recomputed over it) — O(records + changes since the end), no replay. Only a state that cannot reconstruct the end
 * (a store resumed from a snapshot after it) and `referencedEvents` (which rebuilds and replays from `from`) replay the
 * prefix `events[0..position]` into a private state, with every signature re-verified. `inclusion` paths are built
 * from a Merkle tree over the sorted leaves at `to` (`transparency/merkle.ts`), verifiable with `verifyInclusion`
 * against `to.stateRoot`.
 *
 * Additive `include` options (minor per SPEC §19; addendum A-27.3 for the last two):
 *   - `referencedEvents`: the events before `from` whose *data* the §7.1 rebuild of `fromRecords` and the replay of
 *     `events` read (found by observing the exporter's own rebuild + replay through recording proxies), with the
 *     canonical byte count at `from`. The §7.2 record table keeps ids, positions and digests of the admission,
 *     consumption, outcome, observation, receipt and duty events but not their bodies (the admission's control tuple
 *     and adapter identity, the consumption's acknowledgment, …), and several transitions read earlier events
 *     directly (evidence references, the obligation's admission proof, the reassignment scan), so a verifier
 *     starting at `from > 0` needs these bodies; the other events before `from` are known to it by id, type,
 *     timestamp and hashes from the `event` records. Without this option a view from `from > 0` verifies its roots
 *     and chain but not the transition (`verifyExportView` says so and is not `ok`).
 *   - `keyEvents` (A-27.3): every `OWNER_KEYS_ROTATED` event at a position ≤ `to`, with the head before it.
 *   - `attestations` (A-27.3): the owner attestations held for `from.head` and `to.head`: the `STATE_CHECKPOINT`
 *     right after each end (its data signs the root at that end) and the `/2` head attestations the caller holds
 *     (a store's pin) that name that head.
 * Every view carries `fromAuthenticated` (A-27.1/A-27.3): `from.position = 0`, a checkpoint at `from + 1`, or a held
 * head attestation of `from.head`.
 *
 * Legacy and format-1 histories (SPEC §16.1) export with `stateRoot`/`projectionHead` `null`, `recordCount` 0,
 * `projectionRow` `null`, empty record lists, and refuse `inclusion` requests (no state root to prove against).
 */
import { captureValue, compareProtocolStrings, isContentHash } from "./canonical.ts";
import { EngineError } from "./errors.ts";
import { isFormat2, TRELLIS2_FORMAT } from "./events.ts";
import { bytesToHex, eventHash as eventHashOf, hexToBytes, recordHashBytes, type RecordChain } from "./hash.ts";
import { checkpointAuthorizationFailure, ownerKeyEpochAt, ownerKeysAt, resumeRootFailure, verifyHeadAttestationFacts, verifyRotationEvent } from "./owner-keys.ts";
import { isAttestedPolicy } from "./owner-policy.ts";
import { applyEvent, createReplayState, detectFormat, replay, replayFrom, type MutableReplayState } from "./replay.ts";
import { HEAD_ATTESTATION_VERSION_2, verifyHeadAttestation } from "./signer.ts";
import { leafOf, projectionRow, recordKey, rootAt, stateRecordsOf } from "./state-records.ts";
import { rebuildReplayState, recomputeRoot, type RecordInput } from "./state-rebuild.ts";
import { MerkleTree, verifyInclusion } from "./transparency/merkle.ts";
import type { AuthorizationDomain, CanonicalEvent, ContentHash, HistoryHead, OwnerKey, OwnerKeyEpoch, OwnerPolicy, ReplayState, StateRecordEntry, U53 } from "./types.ts";

export const EXPORT_VERSION = "irontrellis-export/2";

export type ExportViewInput = Readonly<{
  fromPosition: U53; toPosition: U53;
  include?: Readonly<{
    fromRecords?: boolean; toRecords?: boolean; inclusion?: readonly Readonly<{ kind: string; key: string }>[];
    referencedEvents?: boolean; keyEvents?: boolean; attestations?: boolean;
  }>;
}>;
/** What the exporter holds besides the state: the owner head attestations it can hand out (`include.attestations`). */
export type ExportViewContext = Readonly<{ headAttestations?: readonly unknown[] }>;
export type ExportedRecord = Readonly<{ kind: string; key: string; record: Readonly<Record<string, unknown>> }>;
export type ExportEnd = Readonly<{ position: U53; head: HistoryHead; stateRoot: ContentHash | null; projectionHead: ContentHash | null; recordCount: U53 }>;
export type ExportedEvent = Readonly<{ position: U53; event: CanonicalEvent; eventHash: ContentHash; recordHash: ContentHash }>;
/** A-65.2: the `STATE_CHECKPOINT` at `from + 1` when it lies outside the range (identity range), chained onto `from.head`. */
export type ExportAttestation = ExportedEvent;
/** A-65.2: `{from, to, fromCheckpoint}` — the owner head attestations held for the two heads, and the checkpoint evidence. */
export type ExportAttestations = Readonly<{ from: Readonly<Record<string, unknown>> | null; to: Readonly<Record<string, unknown>> | null; fromCheckpoint: ExportedEvent | null }>;
/** A-65.1: a key event `{position, event, headBefore}` (the short head before it). */
export type ExportKeyEvent = Readonly<{ position: U53; event: CanonicalEvent; headBefore: Readonly<{ hash: ContentHash; position: U53 }> }>;
export type ExportView = Readonly<{
  version: typeof EXPORT_VERSION;
  domain: ReplayState["genesis"]["domain"];
  genesisEventHash: ContentHash;
  /** A-47.1: `recordHash(0)` (format 2); the history's position-0 hash for other formats. */
  historyId: ContentHash;
  from: ExportEnd;
  to: ExportEnd;
  eventCount: U53;
  checkpointIds: readonly string[];
  events: readonly Readonly<{ position: U53; event: CanonicalEvent; eventHash: ContentHash; recordHash: ContentHash; projectionRow: string | null }>[];
  checkpoints: readonly Readonly<Record<string, unknown>>[];
  fromAuthenticated: boolean;
  fromRecords?: readonly ExportedRecord[];
  toRecords?: readonly ExportedRecord[];
  inclusion?: readonly Readonly<{ at: "to"; kind: string; key: string; leafIndex: U53; path: readonly ContentHash[] }>[];
  /** A-65.1: `[{position, event}]`, sorted by position. */
  referencedEvents?: readonly Readonly<{ position: U53; event: CanonicalEvent }>[];
  keyEvents?: readonly ExportKeyEvent[];
  attestations?: ExportAttestations;
}>;

const invalid = (reason: string): never => { throw new EngineError("INVALID_INPUT", `exportView: ${reason}`); };
const isPosition = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const INCLUDE_KEYS = ["fromRecords", "toRecords", "inclusion", "referencedEvents", "keyEvents", "attestations"];

/** The §7.2 `event` record's hashes at a position (format 2), or the event hash recomputed from the canonical text. */
const hashesAt = (state: ReplayState, position: number): { eventHash: ContentHash; recordHash: ContentHash } => {
  const record = state.stateRecords.get(recordKey("event", String(position).padStart(16, "0")))?.record as { eventHash?: ContentHash; recordHash?: ContentHash } | undefined;
  return { eventHash: record?.eventHash ?? eventHashOf(state.events[position]), recordHash: record?.recordHash ?? state.eventHistoryHashes[position]! };
};
const headAt = (state: ReplayState, position: number): HistoryHead => Object.freeze({ hash: state.eventHistoryHashes[position]!, position, canonicalTime: state.events[position]!.timestamp });
/**
 * What a view reads at one end: the record set, root and projection head at `position`, from `state` itself when it can
 * reconstruct them (format 2, `state-roots.ts entriesAt`), else from a private replay of the prefix (a resumed store's
 * state before its snapshot position); `state()` is that replayed prefix state, built on first use (`referencedEvents`).
 */
type Ended = Readonly<{ entries: readonly StateRecordEntry[]; stateRoot: ContentHash | null; projectionHead: ContentHash | null; state: () => ReplayState }>;
const endedAt = (state: ReplayState, position: number): Ended => {
  let prefix: ReplayState | undefined;
  const replayed = (): ReplayState => (prefix ??= stateAt(state, position));
  if (!isFormat2(state.format)) return { entries: Object.freeze([]), stateRoot: null, projectionHead: null, state: replayed };
  const projectionOn = state.genesis.projection !== null;
  const log = (state as MutableReplayState).rootLog;
  const head = position === state.head.position;
  const entries = head ? stateRecordsOf(state) : log?.entriesAt(position);
  // The root over exactly these entries (an earlier end: one reconstruction serves the records and the root).
  const root = entries === undefined ? undefined : head || log === undefined ? rootAt(state, position) : log.rootOfEntries(position, entries);
  const projection = state.projectionHeads[position];
  if (entries === undefined || root === undefined || (projectionOn && projection === undefined)) {
    const ended = replayed();
    return { entries: stateRecordsOf(ended), stateRoot: ended.stateRoots[position]!, projectionHead: projectionOn ? ended.projectionHeads[position]! : null, state: replayed };
  }
  return { entries, stateRoot: root, projectionHead: projectionOn ? projection! : null, state: replayed };
};
/** The end at `position` (SPEC §15). */
const endAt = (state: ReplayState, ended: Ended, position: number): ExportEnd => Object.freeze({
  position, head: headAt(state, position), stateRoot: ended.stateRoot, projectionHead: ended.projectionHead, recordCount: ended.entries.length,
});
/** The state after `events[0..position]`: the given one when it ends there, else a private replay of that prefix (see the module note on cost). */
const stateAt = (state: ReplayState, position: number): ReplayState => {
  if (position === state.head.position) return state;
  const prefix = createReplayState(state.format);
  // Event by event (an accepted history's intermediate states; a position inside a migrated prefix is one, A-65.3),
  // so the completed-replay rule "the whole migrated prefix was consumed" does not apply to the cut.
  for (let q = 0; q <= position; q += 1) {
    const result = applyEvent(prefix, state.events[q]);
    if (!result.ok) throw new EngineError("INVALID_HISTORY", `exportView: the prefix through position ${position} does not replay (${result.code} at ${q})`);
  }
  return prefix;
};
const recordsOf = (entries: readonly StateRecordEntry[]): readonly ExportedRecord[] =>
  Object.freeze(entries.map((entry) => Object.freeze({ kind: entry.kind, key: entry.key, record: entry.record })));
const exported = (state: ReplayState, position: number): ExportedEvent => Object.freeze({ position, event: state.events[position]!, ...hashesAt(state, position) });
/** A held `/2` head attestation naming exactly this head (shape only: the verifier checks the signature). */
const attestsHead = (candidate: unknown, head: HistoryHead): candidate is Readonly<Record<string, unknown>> => {
  if (candidate === null || typeof candidate !== "object") return false;
  const a = candidate as { version?: unknown; head?: { hash?: unknown; position?: unknown; canonicalTime?: unknown } | null };
  return a.version === HEAD_ATTESTATION_VERSION_2 && a.head !== null && typeof a.head === "object" && a.head.hash === head.hash && a.head.position === head.position && a.head.canonicalTime === head.canonicalTime;
};

/** A body-less stand-in for an event the verifier knows only by its `event` record (id, type, timestamp; the hashes are the record's). */
const standIn = (event: CanonicalEvent): CanonicalEvent => Object.freeze({ id: event.id, type: event.type, timestamp: event.timestamp, data: Object.freeze({}) });

/**
 * The positions before `from` whose event bodies a verifier needs: the ones the §7.1 rebuild of `fromRecords` reads
 * (observed through a recording proxy), extended until the replay of `events[from+1..to]` over stand-ins for every
 * other event reaches the root at `to` (deterministic replay: the verifier, given the same bodies, reads the same).
 * Transitions that only read an earlier event's type (evidence references, the decision-evidence index) work on the
 * stand-ins; the few that read bodies (an obligation's admission proof, the reassignment scan, an evidence event's
 * attester) make their positions needed. Self-checks that the result reaches the root at `to` (an engine invariant).
 */
const referencedPositions = (state: ReplayState, fromState: ReplayState, records: readonly ExportedRecord[], from: number, to: number, toRoot: ContentHash): ReadonlySet<number> => {
  const needed = new Set<number>();
  const options = { projectionHead: fromState.genesis.projection === null ? null : fromState.projectionHeads[from]!, canonicalBytes: fromState.canonicalBytes };
  const recording = (read: Set<number>): CanonicalEvent[] => {
    const events: CanonicalEvent[] = [];
    for (let position = 0; position <= from; position += 1) {
      const event = state.events[position]!;
      events.push(position === from || needed.has(position) ? event : new Proxy(standIn(event), {
        get(target, key, receiver) { if (key === "data") read.add(position); return Reflect.get(target, key, receiver); },
      }));
    }
    return events;
  };
  // Pass 1: what the rebuild reads (stand-ins everywhere; a stand-in read by the rebuild is needed).
  const rebuildReads = new Set<number>();
  try { rebuildReplayState(records, recording(rebuildReads), options); } catch { /* the stand-ins were insufficient: the reads say which */ }
  for (const position of rebuildReads) needed.add(position);
  const suffix = state.events.slice(from + 1, to + 1);
  for (let pass = 0; pass <= from + 1; pass += 1) {
    const read = new Set<number>();
    let reached = false, reason = "";
    try {
      const rebuilt = rebuildReplayState(records, recording(read), options);
      const result = replayFrom(rebuilt, suffix);
      reached = result.status === "ACCEPTED" && rebuilt.stateRoots[to] === toRoot;
      if (!reached) reason = result.status === "ACCEPTED" ? "root mismatch" : `${result.code} at ${result.position ?? "?"}`;
    } catch (error) { reason = error instanceof Error ? error.message : String(error); }
    const grown = [...read].filter((position) => !needed.has(position));
    // A-53.2: the set is the dependency closure — every body the rebuild or a transition in the range reads, not only the
    // ones whose absence changes the result (a verifier refuses any read of a missing body: EXPORT_DEPENDENCIES_MISSING).
    if (reached && grown.length === 0) return needed;
    if (grown.length === 0 && !reached) throw new EngineError("INVALID_HISTORY", `exportView: the rebuilt state at ${from} does not replay to the root at ${to} (${reason})`);
    for (const position of grown) needed.add(position);
  }
  throw new EngineError("INVALID_HISTORY", `exportView: the referenced events of ${from}..${to} do not converge`);
};

/**
 * SPEC §15 over a replayed state. `fromPosition ≤ toPosition ≤ head.position` (`INVALID_INPUT` otherwise; the
 * `include` record is closed, its `inclusion` entries name `(kind, key)` pairs that must exist at `to`). `context`
 * carries what the exporter holds besides the state (a store's pin attestation for `include.attestations`).
 */
export function exportViewState(state: ReplayState, input: ExportViewInput, context: ExportViewContext = {}): ExportView {
  if (input === null || typeof input !== "object") invalid("input must be a record");
  for (const key of Object.keys(input)) if (!["fromPosition", "toPosition", "include"].includes(key)) invalid(`unknown input key ${key}`);
  const { fromPosition: from, toPosition: to } = input;
  if (!isPosition(from) || !isPosition(to)) invalid("fromPosition and toPosition must be non-negative safe integers");
  if (state.events.length === 0) invalid("the history is empty");
  if (from > to || to > state.head.position) invalid(`positions must satisfy fromPosition <= toPosition <= ${state.head.position}`);
  const include = input.include ?? {};
  if (include === null || typeof include !== "object") invalid("include must be a record");
  for (const key of Object.keys(include)) if (!INCLUDE_KEYS.includes(key)) invalid(`unknown include key ${key}`);
  for (const key of ["fromRecords", "toRecords", "referencedEvents", "keyEvents", "attestations"] as const) if (include[key] !== undefined && typeof include[key] !== "boolean") invalid(`include.${key} must be a boolean`);
  const inclusion = include.inclusion ?? [];
  if (!Array.isArray(inclusion) || !inclusion.every((r) => r !== null && typeof r === "object" && typeof r.kind === "string" && typeof r.key === "string" && Object.keys(r).length === 2)) invalid("include.inclusion must list {kind, key} records");
  const format2 = isFormat2(state.format);
  if (inclusion.length > 0 && !format2) invalid("inclusion paths need a format-2 history (legacy and format-1 histories have no state root)");
  if (include.referencedEvents === true && !format2) invalid("referencedEvents need a format-2 history (nothing rebuilds from a legacy or format-1 history)");
  const held = context.headAttestations ?? [];
  if (!Array.isArray(held)) invalid("context.headAttestations must be a list");

  const fromEnd = endedAt(state, from), toEnd = endedAt(state, to);
  const events = [], checkpoints: Readonly<Record<string, unknown>>[] = [], checkpointIds: string[] = [];
  for (let position = from; position <= to; position += 1) {
    const event = state.events[position]!;
    const { eventHash, recordHash } = hashesAt(state, position);
    events.push(Object.freeze({ position, event, eventHash, recordHash, projectionRow: format2 ? `0x${bytesToHex(projectionRow(event, position, eventHash))}` : null }));
    if (event.type === "STATE_CHECKPOINT") { checkpointIds.push(event.data.checkpointId as string); checkpoints.push(event.data); }
  }
  const fromHead = headAt(state, from), toHead = headAt(state, to);
  const checkpointAfter = (position: number): ExportedEvent | undefined => {
    const next = position + 1 <= state.head.position ? state.events[position + 1] : undefined;
    return next?.type === "STATE_CHECKPOINT" ? exported(state, position + 1) : undefined;
  };
  const heldFor = (head: HistoryHead): Readonly<Record<string, unknown>> | null => (held.find((candidate) => attestsHead(candidate, head)) as Readonly<Record<string, unknown>> | undefined) ?? null;
  const fromCheckpoint = format2 ? checkpointAfter(from) : undefined;
  // A-75.2 / A-185.4: `fromAuthenticated` is true only when the view itself carries the evidence of `from`, verified: the genesis;
  // the accepted STATE_CHECKPOINT at from + 1 (in `events` when it lies in the range, else `attestations.fromCheckpoint`); or a
  // held `/2` attestation of from.head carried as `attestations.from` that verifies here (signature, prefix, root, projection
  // head) and is a resume root under the epoch at `from` and the view's last epoch (A-101.1). Nothing held but not carried, and
  // nothing unverified, sets it.
  const heldFrom = heldFor(fromHead);
  const attestedFrom = (): boolean => {
    if (heldFrom === null || !format2 || !verifyHeadAttestationFacts(heldFrom, state).valid) return false;
    const atHead = ownerKeyEpochAt(state, from), last = ownerKeyEpochAt(state, to), key = atHead?.keys.find((k) => k.keyId === heldFrom.keyId);
    return key !== undefined && last !== undefined && resumeRootFailure(key, fromHead.canonicalTime, atHead!, last) === undefined;
  };
  const fromAuthenticated = from === 0 || (fromCheckpoint !== undefined && from + 1 <= to) ||
    (include.attestations === true && (fromCheckpoint !== undefined || attestedFrom()));
  const view: Record<string, unknown> = {
    version: EXPORT_VERSION, domain: state.genesis.domain, genesisEventHash: hashesAt(state, 0).eventHash,
    // A-47.1: `historyId = recordHash(0)` beside genesisEventHash (additive; the §17 comparison list is unchanged, A-56.20).
    historyId: state.eventHistoryHashes[0]!,
    from: endAt(state, fromEnd, from), to: endAt(state, toEnd, to),
    eventCount: to - from + 1, checkpointIds: Object.freeze(checkpointIds), events: Object.freeze(events), checkpoints: Object.freeze(checkpoints),
    fromAuthenticated,
  };
  const fromRecords = include.fromRecords === true || include.referencedEvents === true ? (format2 ? recordsOf(fromEnd.entries) : Object.freeze([])) : undefined;
  if (include.fromRecords === true) view.fromRecords = fromRecords;
  if (include.toRecords === true) view.toRecords = format2 ? recordsOf(toEnd.entries) : Object.freeze([]);
  if (inclusion.length > 0) {
    // SPEC §7.1: the audit path of a leaf against rootAt(to), over the leaves in (kind, key) byte order.
    const entries = toEnd.entries;
    const tree = new MerkleTree();
    for (const entry of entries) tree.append(entry.leaf);
    view.inclusion = Object.freeze(inclusion.map((r) => {
      const wanted = recordKey(r.kind, r.key);
      const leafIndex = entries.findIndex((entry) => compareProtocolStrings(recordKey(entry.kind, entry.key), wanted) === 0);
      if (leafIndex < 0) invalid(`no record (${r.kind}, ${r.key}) at position ${to}`);
      return Object.freeze({ at: "to" as const, kind: r.kind, key: r.key, leafIndex, path: Object.freeze(tree.inclusionProof(leafIndex).map((node) => `0x${bytesToHex(node)}` as ContentHash)) });
    }));
  }
  if (include.referencedEvents === true) {
    const positions = from === 0 ? new Set<number>() : new Set(referencedPositions(state, fromEnd.state(), fromRecords!, from, to, (view.to as ExportEnd).stateRoot!));
    // A-131.1: under an ATTESTED epoch the closure gains e_{q−1} of every OWNER_KEYS_ROTATED at q ≤ from (τ for rule T2).
    for (let q = 1; q <= from; q += 1) if (state.events[q]!.type === "OWNER_KEYS_ROTATED" && isAttestedPolicy(ownerKeyEpochAt(state, q)?.policy)) positions.add(q - 1);
    view.referencedEvents = Object.freeze([...positions].sort((a, b) => a - b).map((position) => Object.freeze({ position, event: state.events[position]! })));
  }
  if (include.keyEvents === true) {
    const list = [];
    for (let position = 1; position <= to; position += 1) {
      if (state.events[position]!.type !== "OWNER_KEYS_ROTATED") continue;
      list.push(Object.freeze({ position, event: state.events[position]!, headBefore: Object.freeze({ hash: state.eventHistoryHashes[position - 1]!, position: position - 1 }) }));
    }
    view.keyEvents = Object.freeze(list);
  }
  // A-65.2: fromCheckpoint only when the checkpoint at from + 1 lies outside the range (an in-range one is in `events`).
  if (include.attestations === true) view.attestations = Object.freeze({ from: heldFor(fromHead), to: heldFor(toHead), fromCheckpoint: fromCheckpoint !== undefined && from + 1 > to ? fromCheckpoint : null });
  return Object.freeze(view) as ExportView;
}

/** SPEC §15 / §17 over raw events: replays them (`INVALID_HISTORY` when rejected) and exports the view. */
export function exportView(events: readonly unknown[], input: ExportViewInput, context: ExportViewContext = {}): ExportView {
  const result = replay(events);
  if (result.status !== "ACCEPTED") throw new EngineError("INVALID_HISTORY", `exportView: the history does not replay (${result.code} at ${result.position ?? "?"})`);
  return exportViewState(result.state, input, context);
}

// ---------------------------------------------------------------- verification (SPEC §15, addendum A-27)

export type ExportVerificationOptions = Readonly<{
  /** The hash of the genesis event the verifier trusts (`eventHash(e₀)`): the view's `genesisEventHash` must equal it. */
  genesisEventHash?: ContentHash;
}>;
/** How an end of the view is authenticated (A-27.1), or `null` when nothing in the view authenticates it. */
export type ExportEndAuthentication = "GENESIS" | "STATE_CHECKPOINT" | "HEAD_ATTESTATION" | null;
export type ExportVerification = Readonly<{
  /** Every claim the view makes was checked and holds: the chain, both roots, the transition between them, the records, paths and attestations it carries. */
  ok: boolean;
  /**
   * A-53.2: `EXPORT_DEPENDENCIES_MISSING` when the rebuild or a transition in `from+1 … to` read the body of an event before
   * `from` that `include.referencedEvents` does not carry (`missingPositions`); the transition is then not claimed valid.
   */
  code?: "EXPORT_DEPENDENCIES_MISSING" | "INVALID_INPUT";
  missingPositions?: readonly U53[];
  failures: readonly string[];
  notes: readonly string[];
  from: Readonly<{ position: U53; stateRoot: ContentHash | null; verified: boolean; authenticated: ExportEndAuthentication }>;
  to: Readonly<{ position: U53; stateRoot: ContentHash | null; verified: boolean; authenticated: ExportEndAuthentication }>;
  eventCount: U53;
  /** The owner key epochs established from the genesis through the view's `keyEvents` (A-27.1); empty without a genesis. */
  ownerKeyEpochs: readonly OwnerKeyEpoch[];
}>;

type Rec = Readonly<Record<string, unknown>>;
const isRec = (v: unknown): v is Rec => v !== null && typeof v === "object" && !Array.isArray(v);
const isHead = (v: unknown): v is HistoryHead => isRec(v) && isContentHash(v.hash) && isPosition(v.position) && isPosition(v.canonicalTime) && Object.keys(v).length === 3;
const isEnd = (v: unknown): v is ExportEnd => isRec(v) && isPosition(v.position) && isHead(v.head) && (v.stateRoot === null || isContentHash(v.stateRoot)) && (v.projectionHead === null || isContentHash(v.projectionHead)) && isPosition(v.recordCount) && Object.keys(v).length === 5;
const isExportedEvent = (v: unknown): v is ExportedEvent => isRec(v) && isPosition(v.position) && isRec(v.event) && isContentHash(v.eventHash) && isContentHash(v.recordHash);
const isExportedRecord = (v: unknown): v is ExportedRecord => isRec(v) && typeof v.kind === "string" && typeof v.key === "string" && isRec(v.record) && Object.keys(v).length === 3;
const VIEW_KEYS = new Set(["version", "domain", "genesisEventHash", "historyId", "from", "to", "eventCount", "checkpointIds", "events", "checkpoints", "fromAuthenticated", "fromRecords", "toRecords", "inclusion", "referencedEvents", "keyEvents", "attestations"]);
const chainedRecordHash = (previous: ContentHash | null, eventHash: ContentHash, position: number): ContentHash => `0x${bytesToHex(recordHashBytes(previous === null ? null : hexToBytes(previous), hexToBytes(eventHash), position))}` as ContentHash;
/** A frozen canonical copy of an event the view carries (parsed JSON is in the caller's key order; replay compares canonical text). */
const canonicalEvent = (raw: unknown, what: string): CanonicalEvent => {
  if (!isRec(raw) || typeof raw.id !== "string" || typeof raw.type !== "string" || !isPosition(raw.timestamp) || !isRec(raw.data)) throw new Error(`${what}: not an event`);
  return captureValue({ id: raw.id, type: raw.type, timestamp: raw.timestamp, data: raw.data }) as CanonicalEvent;
};

/**
 * The verifier of SPEC §15 and addendum A-27 over a view (as exported, or parsed back from JSON). With
 * `from.position = 0` it replays the genesis and every event; otherwise it recomputes `from.stateRoot` from
 * `fromRecords`, re-chains their `event` records from `genesisEventHash` to `from.head` (A-27.2), rebuilds the
 * state (§7.1) with the bodies `referencedEvents` carries, replays `events` and requires `to.stateRoot`,
 * `to.projectionHead`, `to.recordCount` and `to.head`. Every hash the view states is recomputed, never trusted.
 * `toRecords`, `inclusion` and `attestations` are checked when present; `keyEvents` establish the owner key epochs
 * the attestations are verified under (A-27.1). The result is `ok` only when every stated claim was checked; what
 * could not be checked for lack of an `include` option is a failure that names the option.
 */
export function verifyExportView(view: unknown, options: ExportVerificationOptions = {}): ExportVerification {
  const failures: string[] = [], notes: string[] = [];
  const fail = (reason: string): void => { failures.push(reason); };
  /** A-53.2: positions before `from` whose body the verification read but the view does not carry. */
  const missing = new Set<number>();
  // A-65.1: a view that is not the one wire shape (unknown key, explicit null evidence, unsorted or duplicate positions, …) is INVALID_INPUT.
  const bad = (reason: string): ExportVerification => Object.freeze({
    ok: false, code: "INVALID_INPUT" as const, failures: Object.freeze([...failures, reason]), notes: Object.freeze(notes),
    from: Object.freeze({ position: 0, stateRoot: null, verified: false, authenticated: null }), to: Object.freeze({ position: 0, stateRoot: null, verified: false, authenticated: null }),
    eventCount: 0, ownerKeyEpochs: Object.freeze([]),
  });
  // ---- shape (the closed record of §15 plus the additive include outputs)
  if (!isRec(view)) return bad("the view is not a record");
  for (const key of Object.keys(view)) if (!VIEW_KEYS.has(key)) return bad(`unknown view key ${key}`);
  for (const key of ["fromRecords", "toRecords", "inclusion", "referencedEvents", "keyEvents", "attestations"]) if (Object.hasOwn(view, key) && view[key] === null) return bad(`${key} is null (an evidence field is present iff selected, never null)`);
  const ascending = (list: readonly Rec[]): boolean => list.every((item, i) => i === 0 || (item.position as number) > (list[i - 1]!.position as number));
  if (view.version !== EXPORT_VERSION) return bad(`version ${String(view.version)} is not ${EXPORT_VERSION}`);
  if (!isRec(view.domain) || !isContentHash(view.genesisEventHash) || !isEnd(view.from) || !isEnd(view.to) || !isPosition(view.eventCount) || !Array.isArray(view.checkpointIds) || !Array.isArray(view.events) || !Array.isArray(view.checkpoints)) return bad("the view's required fields are malformed");
  const { from, to } = view, checkpointsListed = view.checkpoints as readonly unknown[];
  if (from.position > to.position || view.eventCount !== to.position - from.position + 1 || view.events.length !== view.eventCount) return bad("positions and eventCount disagree with the events listed");
  if (options.genesisEventHash !== undefined && options.genesisEventHash !== view.genesisEventHash) return bad(`genesisEventHash ${view.genesisEventHash} is not the trusted genesis ${options.genesisEventHash}`);
  if (view.historyId !== undefined && !isContentHash(view.historyId)) return bad("historyId is malformed");
  const format2 = from.stateRoot !== null;
  const entries: { position: number; event: CanonicalEvent; eventHash: ContentHash; recordHash: ContentHash; projectionRow: string | null }[] = [];
  for (let index = 0; index < view.events.length; index += 1) {
    const row = view.events[index];
    if (!isExportedEvent(row) || row.position !== from.position + index || !("projectionRow" in row) || (row.projectionRow !== null && typeof row.projectionRow !== "string")) return bad(`events[${index}] is malformed or out of order`);
    let event: CanonicalEvent;
    try { event = canonicalEvent(row.event, `events[${index}]`); } catch (error) { return bad(error instanceof Error ? error.message : "event"); }
    entries.push({ position: row.position, event, eventHash: row.eventHash, recordHash: row.recordHash, projectionRow: row.projectionRow as string | null });
  }
  // ---- the hashes the view states for its own events (the chain is checked against from.head and by the replay below)
  for (const e of entries) if (eventHashOf(e.event) !== e.eventHash) fail(`events[${e.position - from.position}]: eventHash does not hash the event`);
  if (entries[0]!.recordHash !== from.head.hash || entries.at(-1)!.recordHash !== to.head.hash) fail("the first and last recordHash must be from.head.hash and to.head.hash");
  if (from.head.position !== from.position || to.head.position !== to.position || entries[0]!.event.timestamp !== from.head.canonicalTime || entries.at(-1)!.event.timestamp !== to.head.canonicalTime) fail("the heads do not describe the events at the ends");
  const ids = entries.filter((e) => e.event.type === "STATE_CHECKPOINT").map((e) => e.event.data.checkpointId);
  if (JSON.stringify(ids) !== JSON.stringify(view.checkpointIds) || checkpointsListed.length !== ids.length || !entries.filter((e) => e.event.type === "STATE_CHECKPOINT").every((e, i) => JSON.stringify(captureValue(checkpointsListed[i])) === JSON.stringify(e.event.data))) fail("checkpointIds/checkpoints do not list the STATE_CHECKPOINT events in range");
  if (format2) {
    for (let index = 1; index < entries.length; index += 1) if (chainedRecordHash(entries[index - 1]!.recordHash, entries[index]!.eventHash, entries[index]!.position) !== entries[index]!.recordHash) fail(`events[${index}]: recordHash does not chain from the previous one`);
    for (const e of entries) if (e.projectionRow !== `0x${bytesToHex(projectionRow(e.event, e.position, e.eventHash))}`) fail(`events[${e.position - from.position}]: projectionRow is not the §12 row`);
  } else if (entries.some((e) => e.projectionRow !== null) || from.projectionHead !== null || to.projectionHead !== null || from.recordCount !== 0 || to.recordCount !== 0 || to.stateRoot !== null) fail("a view without a state root carries no rows, record counts or projection heads");

  // ---- the optional parts: shape
  let fromRecords: ExportedRecord[] | undefined, toRecords: ExportedRecord[] | undefined, referenced: { position: number; event: CanonicalEvent }[] | undefined;
  if (view.fromRecords !== undefined) { if (!Array.isArray(view.fromRecords) || !view.fromRecords.every(isExportedRecord)) return bad("fromRecords is malformed"); fromRecords = view.fromRecords.map((r) => ({ kind: r.kind, key: r.key, record: captureValue(r.record) as Rec })); }
  if (view.toRecords !== undefined) { if (!Array.isArray(view.toRecords) || !view.toRecords.every(isExportedRecord)) return bad("toRecords is malformed"); toRecords = view.toRecords.map((r) => ({ kind: r.kind, key: r.key, record: captureValue(r.record) as Rec })); }
  if (view.referencedEvents !== undefined) {
    const r = view.referencedEvents;
    if (!Array.isArray(r) || !r.every((e) => isRec(e) && isPosition(e.position) && isRec(e.event) && Object.keys(e).length === 2)) return bad("referencedEvents is malformed (A-65.1: [{position, event}])");
    if (!ascending(r as readonly Rec[])) return bad("referencedEvents is not sorted by position without duplicates");
    try { referenced = (r as readonly Rec[]).map((e) => ({ position: e.position as number, event: canonicalEvent(e.event, `referencedEvents[${String(e.position)}]`) })); } catch (error) { return bad(error instanceof Error ? error.message : "referencedEvents"); }
  }
  if (!format2 && (fromRecords?.length || toRecords?.length || referenced !== undefined)) fail("a view without a state root carries no records");

  // ---- the genesis and the owner key epochs (A-27.1): from events[0] when from = 0, else from referencedEvents (the rebuild always reads it)
  const genesis = from.position === 0 ? entries[0]!.event : referenced?.find((e) => e.position === 0)?.event;
  // A-101.1: each epoch carries the owner approval policy as written (format 2), and its t_set (`openedAt`).
  let epochs: readonly OwnerKeyEpoch[] = [];
  const openedAt: number[] = [];
  const domain = view.domain as unknown as AuthorizationDomain;
  if (genesis !== undefined) {
    if (genesis.type !== "DEPLOYMENT_INITIALIZED" || eventHashOf(genesis) !== view.genesisEventHash) fail("the genesis event does not hash to genesisEventHash");
    else if (JSON.stringify(genesis.data.domain) !== JSON.stringify(domain)) fail("the genesis domain is not the view's domain");
    else {
      const keys = (genesis.data.ownerKeys as readonly OwnerKey[] | undefined) ?? [], digests = genesis.data.nextKeyDigests as readonly ContentHash[] | undefined;
      const policy = format2 ? genesis.data.ownerPolicy as OwnerPolicy | undefined : undefined;
      epochs = [Object.freeze({
        fromPosition: 0, keys: Object.freeze(keys.map((k) => Object.freeze({ keyId: k.keyId, scheme: k.scheme, credential: k.credential }))), ...(digests === undefined ? {} : { nextKeyDigests: Object.freeze(digests.slice()) }),
        ...(policy === undefined ? {} : { policy }),
      })];
      openedAt.push(genesis.timestamp);
    }
  }
  if (view.keyEvents !== undefined) {
    const isShortHead = (v: unknown): v is { hash: ContentHash; position: number } => isRec(v) && isContentHash(v.hash) && isPosition(v.position) && Object.keys(v).length === 2;
    if (!Array.isArray(view.keyEvents) || !view.keyEvents.every((k) => isRec(k) && isPosition(k.position) && isRec(k.event) && isShortHead(k.headBefore) && Object.keys(k).length === 3)) return bad("keyEvents is malformed (A-65.1: [{position, event, headBefore}])");
    if (!ascending(view.keyEvents as readonly Rec[])) return bad("keyEvents is not sorted by position without duplicates");
    // The chain binding (A-58.10): an in-range key event against `events`, an earlier one against the `event` records of fromRecords.
    const recordAt = new Map<number, { eventHash: unknown; recordHash: unknown }>();
    for (const r of fromRecords ?? []) if (r.kind === "event" && isPosition((r.record as Rec).position)) recordAt.set((r.record as Rec).position as number, { eventHash: (r.record as Rec).eventHash, recordHash: (r.record as Rec).recordHash });
    for (const k of view.keyEvents as readonly ExportKeyEvent[]) {
      let event: CanonicalEvent;
      try { event = canonicalEvent(k.event, `keyEvents[${k.position}]`); } catch (error) { return bad(error instanceof Error ? error.message : "keyEvents"); }
      if (event.type !== "OWNER_KEYS_ROTATED" || k.position < 1 || k.position > to.position || k.headBefore.position !== k.position - 1) { fail(`keyEvents[${k.position}]: not a rotation at a position in 1..to`); continue; }
      const eventHash = eventHashOf(event), recordHash = format2 ? chainedRecordHash(k.headBefore.hash, eventHash, k.position) : undefined;
      const inRange = entries.find((e) => e.position === k.position), before = entries.find((e) => e.position === k.position - 1);
      const recorded = recordAt.get(k.position), recordedBefore = recordAt.get(k.position - 1);
      if (inRange !== undefined) {
        if (inRange.eventHash !== eventHash || (recordHash !== undefined && inRange.recordHash !== recordHash) || (before !== undefined && before.recordHash !== k.headBefore.hash)) { fail(`keyEvents[${k.position}]: differs from events[${k.position - from.position}]`); continue; }
      } else if (recorded !== undefined && recordedBefore !== undefined) {
        if (recorded.eventHash !== eventHash || recorded.recordHash !== recordHash || recordedBefore.recordHash !== k.headBefore.hash) { fail(`keyEvents[${k.position}]: does not hash to its event record`); continue; }
      } else if (format2) { notes.push(`keyEvents[${k.position}]: not bound to the chain (include fromRecords)`); continue; }
      if (epochs.length === 0) { notes.push(`keyEvents[${k.position}]: no genesis to establish epoch 0 from (include referencedEvents)`); continue; }
      // A-101.1 / A-120.1: the state-free rotation verifier under the pre-event policy. A-131.1: `headBefore` is a short head,
      // so τ (rule T2) is the timestamp of e_{q−1} when the view carries it (in `events` or `referencedEvents`); otherwise T2
      // is omitted and reported as not judged (report-level, never EXPORT_DEPENDENCIES_MISSING).
      const tau = before?.event.timestamp ?? referenced?.find((e) => e.position === k.position - 1)?.event.timestamp;
      const previousHead = { hash: k.headBefore.hash, position: k.headBefore.position, ...(tau === undefined ? {} : { canonicalTime: tau }) };
      const context = { domain, previousHead, epochs, openedAt, ...(format2 ? { historyId: chainedRecordHash(null, view.genesisEventHash as ContentHash, 0) } : {}), algorithm: "sha256" as const };
      let verdict = verifyRotationEvent(event, context);
      if (!verdict.ok && verdict.notJudged === "T2") {
        notes.push(`keyEvents[${k.position}]: rule T2 not judged: the event at ${k.position - 1} is in neither events nor referencedEvents (A-131.1)`);
        verdict = verifyRotationEvent(event, { ...context, omitT2: true });
      }
      if (!verdict.ok) { fail(`keyEvents[${k.position}]: ${verdict.reason}`); continue; }
      epochs = verdict.epochs;
      openedAt.push(verdict.openedAt);
    }
  }

  // ---- from: the genesis, or the records (root recomputed, event records re-chained: A-27.2)
  let fromVerified = false, toVerified = false;
  let state: MutableReplayState | undefined;
  const eventRecords: { position: number; eventId: string; type: string; timestamp: number; eventHash: ContentHash; recordHash: ContentHash }[] = [];
  if (from.position === 0) {
    const format = detectFormat([entries[0]!.event]);
    if (format === undefined) return bad("the genesis names no known format");
    if (format2 !== (format === TRELLIS2_FORMAT)) fail(`from.stateRoot is ${format2 ? "present" : "null"} but the genesis is ${format}`);
    state = createReplayState(format);
  } else if (!format2) {
    notes.push(`a ${String((domain as { version?: unknown }).version)}-domain view from ${from.position} has no state root and no resumable chain: only the event hashes were checked`);
  } else if (fromRecords === undefined) {
    fail("from.stateRoot cannot be checked without fromRecords (include.fromRecords)");
  } else {
    const recomputed = recomputeRoot(fromRecords);
    if (recomputed.root !== from.stateRoot) fail(`from.stateRoot ${from.stateRoot} is not the root of fromRecords (${recomputed.root})`);
    else if (recomputed.count !== from.recordCount) fail(`from.recordCount ${from.recordCount} is not the number of fromRecords (${recomputed.count})`);
    else fromVerified = true;
    for (const r of fromRecords) {
      if (r.kind !== "event") continue;
      const v = r.record as { position?: unknown; eventId?: unknown; type?: unknown; timestamp?: unknown; eventHash?: unknown; recordHash?: unknown };
      if (!isPosition(v.position) || typeof v.eventId !== "string" || typeof v.type !== "string" || !isPosition(v.timestamp) || !isContentHash(v.eventHash) || !isContentHash(v.recordHash)) { fail(`event record ${r.key} is malformed`); continue; }
      eventRecords.push({ position: v.position, eventId: v.eventId, type: v.type, timestamp: v.timestamp, eventHash: v.eventHash, recordHash: v.recordHash });
    }
    eventRecords.sort((a, b) => a.position - b.position);
    if (eventRecords.length !== from.position + 1 || eventRecords.some((r, q) => r.position !== q)) fail(`fromRecords must carry the event records 0..${from.position}`);
    else {
      let previous: ContentHash | null = null;
      for (const r of eventRecords) {
        const expected = chainedRecordHash(previous, r.eventHash, r.position);
        if (expected !== r.recordHash) { fail(`event record ${r.position}: recordHash does not chain (A-27.2)`); break; }
        previous = r.recordHash;
      }
      if (eventRecords[0]!.eventHash !== view.genesisEventHash) fail("event record 0 does not carry genesisEventHash");
      if (view.historyId !== undefined && eventRecords[0]!.recordHash !== view.historyId) fail("historyId is not recordHash(0) of the event records (A-47.1)");
      if (eventRecords.at(-1)!.recordHash !== from.head.hash) fail("the event records do not re-chain to from.head.hash (A-27.2)");
      if (eventRecords.at(-1)!.eventHash !== entries[0]!.eventHash) fail(`event record ${from.position} does not carry the hash of events[0]`);
    }
    if (failures.length === 0) {
      {
        // A-53.1/2: the events array of the rebuild — the view's event at `from` (boundary evidence, already applied through
        // its `event` record), the bodies referencedEvents carries (each checked against its event record, never applied), and
        // for every other position a body-less stand-in known by id, type, timestamp whose body, if read, is a missing
        // dependency (EXPORT_DEPENDENCIES_MISSING). A view without referencedEvents is a view with none.
        const referencedBodies = referenced ?? [];
        const events: CanonicalEvent[] = eventRecords.map((r, position) => new Proxy(standIn({ id: r.eventId, type: r.type as CanonicalEvent["type"], timestamp: r.timestamp, data: {} }), {
          get(target, key, receiver) { if (key === "data") missing.add(position); return Reflect.get(target, key, receiver); },
        }));
        events[from.position] = entries[0]!.event;
        for (const e of referencedBodies) {
          const r = eventRecords[e.position];
          if (e.position >= from.position || r === undefined) { fail(`referencedEvents[${e.position}]: not a position before from`); continue; }
          if (eventHashOf(e.event) !== r.eventHash) { fail(`referencedEvents[${e.position}]: does not hash to its event record`); continue; }
          events[e.position] = e.event;
        }
        if (failures.length === 0) {
          try {
            // Without referencedEvents the exporter states no canonicalBytes: the byte measure B(from) is then taken as 0 (the
            // byte limits of A-3 cannot be judged at the range's start; noted), never computed by reading bodies the view lacks.
            state = rebuildReplayState(fromRecords, events, { projectionHead: from.projectionHead, canonicalBytes: 0 });
            if (state.stateRoots[from.position] !== from.stateRoot) fail("the rebuilt state's root is not from.stateRoot");
            notes.push(`B(${from.position}) is not carried by the view (§15): the A-3 byte limits were not judged for the range`);
          } catch (error) {
            fail(`the state at ${from.position} does not rebuild from fromRecords: ${error instanceof Error ? error.message : String(error)}`);
            state = undefined;
          }
        }
      }
    }
  }

  // ---- the replay of events (from the genesis, or from the rebuilt state), each recordHash re-chained by the engine's own hasher
  if (state !== undefined && failures.length === 0) {
    const start = from.position === 0 ? 0 : 1;
    for (let index = start; index < entries.length; index += 1) {
      const e = entries[index]!;
      let result: ReturnType<typeof applyEvent>;
      try { result = applyEvent(state, e.event); } catch (error) { fail(`events[${index}] (position ${e.position}) could not be replayed: ${error instanceof Error ? error.message : String(error)}`); break; }
      if (!result.ok) { fail(`events[${index}] (position ${e.position}) is rejected by replay: ${result.code} ${result.reason}`); break; }
      if (result.head.hash !== e.recordHash) { fail(`events[${index}]: the replayed recordHash differs from the stated one`); break; }
      if (format2 && (state.hasher as RecordChain).lastEventHash !== e.eventHash) { fail(`events[${index}]: the replayed eventHash differs from the stated one`); break; }
      if (index === 0 && view.historyId !== undefined && result.head.hash !== view.historyId) fail("historyId is not the genesis record hash (A-47.1)");
      if (index === 0 && format2) {
        if (state.stateRoots[0] !== from.stateRoot || state.stateRecords.size !== from.recordCount || (from.projectionHead !== null && state.projectionHeads[0] !== from.projectionHead)) fail("from.stateRoot/recordCount/projectionHead are not the genesis state's");
        else fromVerified = true;
      }
    }
    if (failures.length === 0) {
      if (state.head.hash !== to.head.hash) fail("the replay does not end at to.head");
      else if (format2) {
        const root = state.stateRoots[to.position], projection = state.genesis.projection === null ? null : state.projectionHeads[to.position];
        if (root !== to.stateRoot) fail(`to.stateRoot ${to.stateRoot} is not the replayed root ${root}`);
        else if (state.stateRecords.size !== to.recordCount) fail(`to.recordCount ${to.recordCount} is not the replayed record count ${state.stateRecords.size}`);
        else if ((projection ?? null) !== to.projectionHead) fail(`to.projectionHead ${String(to.projectionHead)} is not the replayed projection head ${String(projection)}`);
        else toVerified = true;
      } else {
        toVerified = true; // nothing but the chain to verify (SPEC §16.1)
        notes.push("no state root: the replay accepted every event and ends at to.head");
      }
      if (from.position === 0 && !format2) fromVerified = true;
    }
  }

  // ---- toRecords and inclusion paths against to.stateRoot
  if (toRecords !== undefined && format2) {
    const recomputed = recomputeRoot(toRecords);
    if (recomputed.root !== to.stateRoot || recomputed.count !== to.recordCount) fail("toRecords do not reproduce to.stateRoot/recordCount");
  }
  if (view.inclusion !== undefined) {
    const paths = view.inclusion;
    if (!Array.isArray(paths) || !paths.every((p) => isRec(p) && p.at === "to" && typeof p.kind === "string" && typeof p.key === "string" && isPosition(p.leafIndex) && Array.isArray(p.path) && p.path.every(isContentHash))) return bad("inclusion is malformed");
    const leaves = toRecords !== undefined ? toRecords.map((r) => ({ k: recordKey(r.kind, r.key), leaf: leafOf(r.kind, r.key, r.record) })).sort((a, b) => compareProtocolStrings(a.k, b.k))
      : state !== undefined && toVerified ? stateRecordsOf(state).map((r) => ({ k: recordKey(r.kind, r.key), leaf: r.leaf })) : undefined;
    if (leaves === undefined || to.stateRoot === null) fail("inclusion paths cannot be checked without toRecords or a verified replay to `to`");
    else {
      for (const p of paths as readonly { kind: string; key: string; leafIndex: number; path: readonly ContentHash[] }[]) {
        const entry = leaves[p.leafIndex];
        if (entry === undefined || entry.k !== recordKey(p.kind, p.key)) { fail(`inclusion (${p.kind}, ${p.key}): leafIndex ${p.leafIndex} is not that record`); continue; }
        if (!verifyInclusion(entry.leaf, p.leafIndex, leaves.length, p.path.map(hexToBytes), hexToBytes(to.stateRoot))) fail(`inclusion (${p.kind}, ${p.key}): the path does not reach to.stateRoot`);
      }
    }
  }

  // ---- authentication of the ends (A-27.1): the genesis, a STATE_CHECKPOINT right after the end, or a held head attestation of it
  const authenticate = (end: ExportEnd, held: unknown, checkpoint: unknown, after: typeof entries[number] | undefined, label: string): ExportEndAuthentication => {
    if (end.position === 0) return "GENESIS";
    if (!format2) return null;
    let by: ExportEndAuthentication = null;
    const candidates: unknown[] = [];
    if (after !== undefined && after.event.type === "STATE_CHECKPOINT") candidates.push({ kind: "STATE_CHECKPOINT", position: after.position, event: after.event, eventHash: after.eventHash, recordHash: after.recordHash });
    if (checkpoint !== null && checkpoint !== undefined) candidates.push(isRec(checkpoint) ? { kind: "STATE_CHECKPOINT", ...checkpoint } : checkpoint);
    if (held !== null && held !== undefined) candidates.push({ kind: "HEAD_ATTESTATION", attestation: held });
    for (const c of candidates) {
      if (!isRec(c)) { fail(`attestations.${label}: malformed entry`); continue; }
      if (c.kind === "STATE_CHECKPOINT") {
        let event: CanonicalEvent;
        try { event = canonicalEvent(c.event, `attestations.${label}`); } catch { fail(`attestations.${label}: malformed checkpoint`); continue; }
        const d = event.data as { head?: HistoryHead; stateRoot?: unknown; projectionHead?: unknown; recordCount?: unknown };
        if (event.type !== "STATE_CHECKPOINT" || c.position !== end.position + 1 || eventHashOf(event) !== c.eventHash || chainedRecordHash(end.head.hash, c.eventHash as ContentHash, end.position + 1) !== c.recordHash) { fail(`attestations.${label}: the checkpoint does not sit at ${end.position + 1} after ${label}.head`); continue; }
        if (d.head?.hash !== end.head.hash || d.head.position !== end.position || d.stateRoot !== end.stateRoot || (d.projectionHead ?? null) !== end.projectionHead || d.recordCount !== end.recordCount) { fail(`attestations.${label}: the checkpoint signs another root than ${label}.stateRoot`); continue; }
        if (epochs.length === 0) { notes.push(`attestations.${label}: a checkpoint is present but no owner keys are established (include referencedEvents and keyEvents)`); continue; }
        const keys = ownerKeysAt(epochs, end.position + 1), keyId = (event.data.controlAuthorization as { keyId?: unknown } | undefined)?.keyId;
        if (!keys.some((k) => k.keyId === keyId)) { notes.push(`attestations.${label}: the checkpoint is signed by ${String(keyId)}, not a key the established epochs know (include keyEvents)`); continue; }
        // A-101.1: A-92.2 under the pre-event policy (the epoch in force at end + 1): M_eff(35) counting signatures.
        const signature = checkpointAuthorizationFailure(event, { domain, previousHead: { hash: end.head.hash, position: end.position }, epoch: ownerKeyEpochAt(epochs, end.position + 1), algorithm: "sha256" });
        if (signature !== undefined) { fail(`attestations.${label}: checkpoint ${signature}`); continue; }
        by ??= "STATE_CHECKPOINT";
      } else if (c.kind === "HEAD_ATTESTATION") {
        const a = c.attestation as { stateRoot?: unknown; projectionHead?: unknown; domain?: unknown } | undefined;
        if (!attestsHead(a, end.head)) { fail(`attestations.${label}: the head attestation does not name ${label}.head`); continue; }
        if (a.stateRoot !== end.stateRoot || (a.projectionHead ?? null) !== end.projectionHead || JSON.stringify(a.domain) !== JSON.stringify(domain)) { fail(`attestations.${label}: the head attestation signs another root or domain than ${label}`); continue; }
        if (epochs.length === 0) { notes.push(`attestations.${label}: a head attestation is present but no owner keys are established (include referencedEvents and keyEvents)`); continue; }
        const keys = ownerKeysAt(epochs, end.position), keyId = (a as { keyId?: unknown }).keyId;
        if (!keys.some((k) => k.keyId === keyId)) { notes.push(`attestations.${label}: the head attestation is signed by ${String(keyId)}, not a key the established epochs know (include keyEvents)`); continue; }
        if (!verifyHeadAttestation(a, domain, keys, "sha256")) { fail(`attestations.${label}: the head attestation does not verify under the owner keys in force at ${end.position}`); continue; }
        // A-101.1 / A-111.1 (c): the attestation of `from` is an asserted root; it satisfies A-101.0 with "file head" read as
        // the view's last epoch. Under the default policy nothing applies.
        if (label === "from") {
          const refusal = resumeRootFailure(keys.find((k) => k.keyId === keyId)!, end.head.canonicalTime, ownerKeyEpochAt(epochs, end.position)!, epochs.at(-1)!);
          if (refusal !== undefined) { fail(`attestations.from: ${refusal}`); continue; }
        }
        by ??= "HEAD_ATTESTATION";
      } else fail(`attestations.${label}: unknown kind ${String(c.kind)}`);
    }
    return by;
  };
  let attestations: { from?: unknown; to?: unknown; fromCheckpoint?: unknown } = {};
  if (view.attestations !== undefined) {
    const a = view.attestations;
    const nullOrRecord = (v: unknown): boolean => v === null || isRec(v);
    if (!isRec(a) || !nullOrRecord(a.from) || !nullOrRecord(a.to) || !nullOrRecord(a.fromCheckpoint) || Object.keys(a).length !== 3 || !["from", "to", "fromCheckpoint"].every((k) => Object.hasOwn(a, k))) return bad("attestations is malformed (A-65.2: {from, to, fromCheckpoint})");
    if (a.fromCheckpoint !== null && from.position + 1 <= to.position) return bad("attestations.fromCheckpoint is only for a checkpoint outside the range (it is in events)");
    attestations = a;
  }
  const fromAuthenticated = authenticate(from, attestations.from, attestations.fromCheckpoint, entries[1], "from");
  const toAuthenticated = authenticate(to, attestations.to, null, undefined, "to");
  if (typeof view.fromAuthenticated !== "boolean") fail("fromAuthenticated must be a boolean");
  else if (view.fromAuthenticated === false && fromAuthenticated !== null) fail("the view says fromAuthenticated: false but carries an authentication of from");
  else if (view.fromAuthenticated === true && fromAuthenticated === null) notes.push("the exporter says from is authenticated but the view carries nothing that shows it (include attestations)");

  const missingPositions = [...missing].sort((a, b) => a - b);
  if (missingPositions.length > 0) { fail(`EXPORT_DEPENDENCIES_MISSING: the bodies of positions ${missingPositions.join(", ")} are read but not carried (include.referencedEvents)`); toVerified = false; }
  return Object.freeze({
    ok: failures.length === 0 && fromVerified && toVerified, ...(missingPositions.length > 0 ? { code: "EXPORT_DEPENDENCIES_MISSING" as const, missingPositions: Object.freeze(missingPositions) } : {}),
    failures: Object.freeze(failures), notes: Object.freeze(notes),
    from: Object.freeze({ position: from.position, stateRoot: from.stateRoot, verified: fromVerified, authenticated: fromAuthenticated }),
    to: Object.freeze({ position: to.position, stateRoot: to.stateRoot, verified: toVerified, authenticated: toAuthenticated }),
    eventCount: view.eventCount, ownerKeyEpochs: Object.freeze(epochs),
  });
}
