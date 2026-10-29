/**
 * Per-history witness state and the acceptance rules (docs/reference/witness-protocol.md §9.2),
 * as pure functions. A `decide*` function reads the state and a request
 * body and returns a `Decision`: an entry to append (and the reply to give once
 * it is durable) or a reply without an append. `applyEntry` is the only thing
 * that changes the state; the server calls it after the entry is on disk and
 * the replay at start-up calls it for every log line, so the state is always a
 * function of the log.
 */
import {
  canonicalEncode, historyIdOfGenesis, isAttestedPolicy, isContentHash, isU53, ownerKeyRotationFailure, ownerKeysAt, signerClass, TRELLIS2_FORMAT, TRELLIS_FORMAT, validateEvent,
  verifyRotationEvent,
} from "@ramex-labs/irontrellis";
import type { ContentHash, HistoryFormat, OwnerKey, OwnerKeyEpoch, OwnerPolicy, RotationVerification, TrellisDomain } from "@ramex-labs/irontrellis";
import {
  validateEntry, validateKeyEventBundle, validateSignedHeadStatement, verifySignedHeadStatement, WITNESS_ENTRY_VERSION,
} from "@ramex-labs/irontrellis/transparency";
import type { KeyEventBundle, SignedHeadStatement, WitnessEntry, WitnessEntryKind } from "@ramex-labs/irontrellis/transparency";

/** Stable error codes (docs/reference/witness-protocol.md §9.2, §9.6). An equivocation is evidence and never freezes a history. */
export const ERROR_CODES = Object.freeze([
  "NOT_FOUND", "UNAUTHORIZED", "INVALID_REQUEST", "INVALID_GENESIS", "UNSUPPORTED_FORMAT", "NOT_REGISTERED", "INVALID_STATEMENT", "SIGNATURE_INVALID",
  "STALE_PREVIOUS", "EQUIVOCATION", "RATE_LIMITED", "PAYLOAD_TOO_LARGE",
  "HISTORY_LIMIT_REACHED", "INTERNAL", "KEY_EVENT_INVALID", "KEY_EVENT_HEAD_UNKNOWN", "SUPERSEDED", "SUPERSEDE_REFUSED",
  // A-100.1 and A-111.3 (format 2, owner approval policies).
  "WITNESS_POLICY_UNKNOWN", "WITNESS_SIGNER_UNQUALIFIED",
] as const);
export type WitnessErrorCode = (typeof ERROR_CODES)[number];

export type HeadRef = Readonly<{ hash: ContentHash; position: number }>;
/** A head the witness holds: the statement's head plus the leaf index of its HEAD entry. */
export type HeldHead = Readonly<{ hash: ContentHash; position: number; canonicalTime: number; index: number }>;
/** A recorded owner key event (a ROTATED leaf), by event id: what makes a repeated delivery idempotent. */
export type KeyEventRecord = Readonly<{ eventId: string; index: number; previousHead: HeadRef; eventHead: HeadRef; canonical: string }>;

/**
 * What this witness records of an owner key epoch beside the epoch itself (A-100.1, A-111.3): whether it knows the
 * policy the epoch was set with (`policyKnown`: this witness derives every epoch from the genesis or the rotation in its
 * log, so it is always `true` here; an epoch without `policy` is the default policy) and the epoch's `t_set`
 * (`openedAt`, the timestamp of the event that opened it).
 */
export type EpochFacts = Readonly<{ policyKnown: boolean; openedAt: number }>;

export type HistoryState = {
  readonly historyId: ContentHash;
  /** Format 2 (`historyId = recordHash(0)`) or format 1, from the registered genesis (SPEC §7.4); legacy is never witnessed. */
  readonly format: HistoryFormat;
  readonly domain: TrellisDomain;
  readonly registrationIndex: number;
  /** The owner key epochs: keys, next-key commitment and, in format 2, the owner approval policy as written (`policy`). */
  epochs: readonly OwnerKeyEpoch[];
  /** `epochFacts[i]` is what the witness records of `epochs[i]` beside it. */
  epochFacts: readonly EpochFacts[];
  /** Witnessed heads by position (only positions a HEAD entry names). */
  readonly heads: Map<number, HeldHead>;
  latest: HeldHead | undefined;
  /** Every recorded owner key event (rotation) by event id. */
  readonly keyEvents: Map<string, KeyEventRecord>;
  /**
   * Heads a SUPERSEDED entry overrode (docs/reference/witness-operations.md §7.4): kept as evidence in the log, never latest again, and a
   * statement that states or extends one is answered 409 SUPERSEDED. Keyed `<position>:<hash>` → the HEAD leaf index.
   */
  readonly superseded: Map<string, number>;
  /** SUPERSEDED entries recorded for the history, the newest one's leaf index, and the epochs (by `fromPosition`) they left: at most one per epoch transition. */
  supersedes: number;
  lastSupersedeIndex: number | undefined;
  readonly supersededEpochs: Set<number>;
  /**
   * EQUIVOCATION entries recorded for this history (docs/reference/witness-operations.md: evidence only; the
   * history stays open). Capped (docs/reference/witness-protocol.md §9.2 rule 4): at most one entry per position
   * (`equivocationsByPosition`: position → leaf index) and at most `MAX_EQUIVOCATIONS_PER_HISTORY`
   * per history, so a stolen owner key cannot grow the log without bound.
   */
  equivocations: number;
  lastEquivocationIndex: number | undefined;
  readonly equivocationsByPosition: Map<number, number>;
};

export type WitnessState = {
  readonly histories: Map<ContentHash, HistoryState>;
  /** Number of entries applied (the next leaf index). */
  size: number;
  readonly kinds: Record<WitnessEntryKind, number>;
  /** Histories with at least one recorded equivocation. */
  equivocatingHistories: number;
};

export type Decision = Readonly<{
  status: number;
  /** The entries to append, in order, before replying (one, or up to three for a key event: SUPERSEDED, HEAD, the key event). */
  append?: Readonly<{ entries: readonly WitnessEntry[] }>;
  /** The entry whose receipt the reply carries: an existing leaf index, or "appended" (the last entry appended). */
  receipt?: number | "appended";
  /** HEAD replies. */
  result?: "APPENDED" | "ALREADY_WITNESSED";
  /** Include `latest` (the history's latest head and its receipt, or null). */
  latest?: boolean;
  /** Include the history's owner key epochs (rotation replies). */
  epochs?: boolean;
  /** The SUPERSEDED entry this reply names (`"first"`: the first entry this decision appends). */
  superseded?: number | "first";
  /** An EQUIVOCATION answered from the cap (nothing recorded; the receipt is an earlier entry): counted in the metrics. */
  capped?: boolean;
  historyId?: ContentHash;
  error?: Readonly<{ code: WitnessErrorCode; message: string; hint?: string }>;
}>;

/** Read access to entries already in the log (the decide functions need the stored statement at a position). */
export type EntryLookup = (index: number) => WitnessEntry;

export type DecideContext = Readonly<{ now: number; lookup: EntryLookup; maxHistories?: number }>;

export function emptyState(): WitnessState {
  return { histories: new Map(), size: 0, kinds: { REGISTERED: 0, HEAD: 0, ROTATED: 0, EQUIVOCATION: 0, SUPERSEDED: 0 }, equivocatingHistories: 0 };
}

const isRecord = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const hasExactKeys = (value: Record<string, unknown>, keys: readonly string[]): boolean => {
  const own = Object.keys(value);
  return own.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
};
const isHeadRef = (value: unknown): value is HeadRef =>
  isRecord(value) && hasExactKeys(value, ["hash", "position"]) && isContentHash(value.hash) && isU53(value.position);

const reject = (status: number, code: WitnessErrorCode, message: string, extra: Omit<Decision, "status" | "error"> = {}, hint?: string): Decision =>
  Object.freeze({ status, ...extra, error: Object.freeze({ code, message, ...(hint === undefined ? {} : { hint }) }) });

const canonical = (value: unknown): string => canonicalEncode(value);

const sameDomain = (a: TrellisDomain, b: TrellisDomain): boolean => a.protocol === b.protocol && a.version === b.version && a.deploymentId === b.deploymentId;

/** At most this many EQUIVOCATION entries are recorded per history (and at most one per position). */
export const MAX_EQUIVOCATIONS_PER_HISTORY = 64;

const sameRef = (a: Readonly<{ hash: string; position: number }> | null, b: Readonly<{ hash: string; position: number }> | undefined): boolean =>
  a !== null && b !== undefined && a.hash === b.hash && a.position === b.position;

const storedStatement = (lookup: EntryLookup, index: number): SignedHeadStatement => {
  const entry = lookup(index);
  if (entry.kind !== "HEAD") throw new Error(`witness state: leaf ${index} is not a HEAD entry`);
  return entry.signedStatement;
};

const knownKeyIds = (epochs: readonly OwnerKeyEpoch[]): Set<string> => new Set(epochs.flatMap((epoch) => epoch.keys.map((key) => key.keyId)));

/**
 * A-111.3: the class of a head statement's signer under the policy of the epoch in force at `head.position`, at
 * `head.canonicalTime` (A-107.1). `DECLARED` (or no policy): qualified unless `AGENT`; `ATTESTED`: qualified only when
 * `HUMAN`. `known: false` when the witness does not know that epoch's policy. Call it after the signature verified.
 */
const signerStanding = (history: HistoryState, signed: SignedHeadStatement): Readonly<{ known: boolean; qualified: boolean; klass: string; attested: boolean }> => {
  const head = signed.statement.head;
  const index = history.epochs.findLastIndex((candidate) => candidate.fromPosition <= head.position);
  const epoch = history.epochs[index];
  if (epoch === undefined) return { known: true, qualified: false, klass: "NONE", attested: false };
  if (history.epochFacts[index]?.policyKnown !== true) return { known: false, qualified: false, klass: "NONE", attested: false };
  const key = epoch.keys.find((candidate) => candidate.keyId === signed.keyId);
  const attested = isAttestedPolicy(epoch.policy);
  if (key === undefined) return { known: true, qualified: false, klass: "NONE", attested };
  const klass = signerClass(epoch.policy as OwnerPolicy | undefined, epoch.keys, key, head.canonicalTime);
  return { known: true, qualified: attested ? klass === "HUMAN" : klass !== "AGENT", klass, attested };
};
/** `null` when the statement's signer is qualified (A-111.3), else the rejection: `WITNESS_POLICY_UNKNOWN` or `WITNESS_SIGNER_UNQUALIFIED`. */
const signerProblem = (history: HistoryState, signed: SignedHeadStatement, name?: string): Decision | null => {
  const standing = signerStanding(history, signed);
  if (standing.qualified) return null;
  const { head } = signed.statement;
  const at = name === undefined ? "" : `${name}: `;
  if (!standing.known) return reject(409, "WITNESS_POLICY_UNKNOWN", `${at}this witness does not know the owner approval policy in force at position ${head.position}; it cannot judge the signer`);
  return reject(400, "WITNESS_SIGNER_UNQUALIFIED", `${at}owner key ${signed.keyId} is ${standing.klass} at ${head.canonicalTime} under the owner approval policy in force at position ${head.position}; ${standing.attested ? "under ATTESTED a head statement needs a HUMAN signer" : "an AGENT key never signs a head statement"} (A-111.3)`);
};
/**
 * τ for rule T2 (A-119.1, A-120.1): the `canonicalTime` of the head a rotation extends, when this witness holds that
 * head or held it before a supersede; `undefined` otherwise (the verifier then refuses a rotation T2 would decide).
 */
const canonicalTimeOf = (history: HistoryState, ref: HeadRef, lookup: EntryLookup): number | undefined => {
  const held = history.heads.get(ref.position);
  if (held !== undefined && held.hash === ref.hash) return held.canonicalTime;
  const index = history.superseded.get(refKey(ref));
  return index === undefined ? undefined : storedStatement(lookup, index).statement.head.canonicalTime;
};
/** A-100.1 / A-120.1: a rotation against this witness's epochs (`acceptSF`: policy, counting, T2, policy validity, HF1). */
const verifyRotation = (history: HistoryState, rotation: unknown, previousHead: HeadRef, lookup: EntryLookup): RotationVerification => {
  const canonicalTime = canonicalTimeOf(history, previousHead, lookup);
  return verifyRotationEvent(rotation, {
    domain: history.domain, previousHead: { hash: previousHead.hash, position: previousHead.position, ...(canonicalTime === undefined ? {} : { canonicalTime }) },
    epochs: history.epochs, openedAt: history.epochFacts.map((facts) => facts.openedAt), ...(history.format === TRELLIS2_FORMAT ? { historyId: history.historyId } : {}), algorithm: "sha256",
  });
};
/** Records the epoch a rotation opened (the policy as written is in it) with this witness's facts about it. */
const recordEpoch = (history: HistoryState, epochs: readonly OwnerKeyEpoch[], openedAt: number): void => {
  history.epochs = epochs;
  history.epochFacts = Object.freeze([...history.epochFacts, Object.freeze({ policyKnown: true, openedAt })]);
};

// ---------------------------------------------------------------- REGISTER

/**
 * The format a genesis declares (`versions.eventSchemaVersion`): format 2 or format 1. Anything else (a legacy
 * Continuity genesis, an unknown literal) is checked as format 1, whose validation then names the problem.
 */
const genesisFormat = (genesis: unknown): HistoryFormat =>
  (genesis as { data?: { versions?: { eventSchemaVersion?: unknown } } } | null)?.data?.versions?.eventSchemaVersion === TRELLIS2_FORMAT ? TRELLIS2_FORMAT : TRELLIS_FORMAT;

/** `POST /v1/histories` with body `{ genesis }`. */
export function decideRegister(state: WitnessState, body: unknown, context: DecideContext): Decision {
  if (!isRecord(body) || !hasExactKeys(body, ["genesis"])) return reject(400, "INVALID_REQUEST", "the body must be { genesis }");
  const genesis = body.genesis;
  if (!isRecord(genesis)) return reject(400, "INVALID_GENESIS", "genesis must be an event record");
  const validation = validateEvent(genesis, genesisFormat(genesis), 0);
  if (!validation.ok) {
    if (validation.code === "UNSUPPORTED_EVENT_SCHEMA") {
      return reject(400, "UNSUPPORTED_FORMAT", `only format-2 (irontrellis-event/2) and format-1 (irontrellis-event/1) histories can be witnessed; migrate the history first (${validation.reason})`);
    }
    return reject(400, "INVALID_GENESIS", `${validation.code}: ${validation.reason}`);
  }
  let historyId: ContentHash;
  try {
    historyId = historyIdOfGenesis(genesis);
  } catch (error) {
    return reject(400, "INVALID_GENESIS", `genesis is not canonically encodable: ${error instanceof Error ? error.message : String(error)}`);
  }
  const existing = state.histories.get(historyId);
  if (existing !== undefined) return Object.freeze({ status: 200, receipt: existing.registrationIndex, historyId });
  if (context.maxHistories !== undefined && state.histories.size >= context.maxHistories) {
    return reject(503, "HISTORY_LIMIT_REACHED", `this witness already records its maximum of ${context.maxHistories} histories`);
  }
  const entry: WitnessEntry = Object.freeze({ version: WITNESS_ENTRY_VERSION, kind: "REGISTERED", historyId, genesis, receivedAt: context.now });
  const problem = validateEntry(entry);
  if (problem !== null) return reject(400, "INVALID_GENESIS", problem);
  return Object.freeze({ status: 201, append: Object.freeze({ entries: Object.freeze([entry]) }), receipt: "appended", historyId });
}

// ---------------------------------------------------------------- HEAD

/** `POST /v1/histories/:id/heads` with a signed head statement. */
export function decideHead(state: WitnessState, historyId: ContentHash, body: unknown, context: DecideContext): Decision {
  const history = state.histories.get(historyId);
  if (history === undefined) return reject(404, "NOT_REGISTERED", `history ${historyId} is not registered with this witness`);
  const malformed = validateSignedHeadStatement(body);
  if (malformed !== null) return reject(400, "INVALID_STATEMENT", malformed);
  const signed = body as SignedHeadStatement;
  const { statement } = signed;
  if (statement.historyId !== historyId) return reject(400, "INVALID_STATEMENT", `the statement is for history ${statement.historyId}, not ${historyId}`);
  if (!sameDomain(statement.domain, history.domain)) return reject(400, "INVALID_STATEMENT", "the statement's domain is not the domain of the registered genesis");
  const { head, previous } = statement;
  const held = history.heads.get(head.position);

  // A byte-identical resubmission of a held statement was verified when it was accepted (its key may have been retired since).
  const identical = held !== undefined && held.hash === head.hash && canonical(storedStatement(context.lookup, held.index)) === canonical(signed);
  if (!identical) {
    const verdict = verifySignedHeadStatement(signed, (position) => ownerKeysAt(history.epochs, position));
    if (!verdict.ok) {
      if (verdict.reason === "UNKNOWN_KEY") {
        const unknown = !knownKeyIds(history.epochs).has(signed.keyId);
        return reject(400, "SIGNATURE_INVALID", unknown
          ? `owner key ${signed.keyId} is unknown to this witness; post the pending owner key rotation first`
          : `owner key ${signed.keyId} is not in force at position ${head.position}`, {}, unknown ? "ROTATION_REQUIRED" : undefined);
      }
      if (verdict.reason === "SIGNATURE_INVALID") return reject(400, "SIGNATURE_INVALID", "the statement signature does not verify with the owner key it names");
      return reject(400, "INVALID_STATEMENT", "malformed signed statement");
    }
    const unqualified = signerProblem(history, signed);
    if (unqualified !== null) return unqualified;
  }

  // A head a pre-rotated rotation overrode never counts again, and nothing extends it.
  const supersededPrevious = previous !== null && history.superseded.has(refKey(previous));
  if (supersededPrevious || history.superseded.has(refKey(head))) {
    return reject(409, "SUPERSEDED", `the ${supersededPrevious ? "previous head" : "head"} of this statement (position ${supersededPrevious ? previous!.position : head.position}) was superseded by a pre-rotated owner key rotation; statements must extend the witness's latest head`, { latest: true });
  }
  const latest = history.latest;
  const appendHead = (): Decision => Object.freeze({
    status: 201, result: "APPENDED", receipt: "appended", latest: true,
    append: Object.freeze({ entries: Object.freeze([Object.freeze({ version: WITNESS_ENTRY_VERSION, kind: "HEAD", historyId, signedStatement: signed, receivedAt: context.now }) as WitnessEntry]) }),
  });
  if (latest === undefined) {
    if (previous === null) return appendHead();
    return reject(409, "STALE_PREVIOUS", "the witness holds no head for this history yet; submit with previous: null", { latest: true });
  }
  // docs/reference/witness-protocol.md §9.2 rule 3: the statement extends the latest head.
  if (sameRef(previous, latest)) {
    if (head.hash === latest.hash && head.position === latest.position) return Object.freeze({ status: 200, result: "ALREADY_WITNESSED", receipt: latest.index, latest: true });
    if (head.position > latest.position) return appendHead();
    return reject(400, "INVALID_STATEMENT", "the head must be ahead of previous");
  }
  // docs/reference/witness-protocol.md §9.2 rule 4: a different owner-signed head at a position the witness holds is evidence (recorded once), never a new state.
  if (held !== undefined && held.hash !== head.hash) {
    const message = `the owner key signed a head at position ${head.position} that differs from the head this witness holds there; the conflicting statement is recorded as evidence and the history stays open (statements that extend the latest head are accepted)`;
    // Capped evidence: one entry per position (a repeat of the recorded statement is the same answer; another conflicting
    // statement at that position gets the recorded entry, `capped`), and at most MAX_EQUIVOCATIONS_PER_HISTORY per history
    // (then the most recent recorded entry). Nothing is appended beyond the cap.
    const recorded = history.equivocationsByPosition.get(head.position);
    if (recorded !== undefined) {
      const entry = context.lookup(recorded);
      const repeat = entry.kind === "EQUIVOCATION" && canonical(entry.second) === canonical(signed);
      return reject(409, "EQUIVOCATION", message, { receipt: recorded, latest: true, ...(repeat ? {} : { capped: true }) });
    }
    if (history.equivocations >= MAX_EQUIVOCATIONS_PER_HISTORY && history.lastEquivocationIndex !== undefined) {
      return reject(409, "EQUIVOCATION", message, { receipt: history.lastEquivocationIndex, latest: true, capped: true });
    }
    const entry = Object.freeze({
      version: WITNESS_ENTRY_VERSION, kind: "EQUIVOCATION", historyId, first: storedStatement(context.lookup, held.index), second: signed, receivedAt: context.now,
    }) as WitnessEntry;
    return reject(409, "EQUIVOCATION", message, { append: Object.freeze({ entries: Object.freeze([entry]) }), receipt: "appended", latest: true });
  }
  // docs/reference/witness-protocol.md §9.2 rules 5 and 6.
  if (held !== undefined) return Object.freeze({ status: 200, result: "ALREADY_WITNESSED", receipt: held.index, latest: true });
  return reject(409, "STALE_PREVIOUS", `previous is not the witness's latest head (position ${latest.position})`, { latest: true });
}

// ---------------------------------------------------------------- KEY EVENTS (owner key rotations)

/** Which route a key event came in on: `POST …/key-events`, or the admin import of a key-event bundle. */
export type KeyEventRoute = "key-events" | "admin";

/** What a key-event request carries once its body is read (a bundle or a key-events body). */
type KeyEventRequest = Readonly<{
  event: Record<string, unknown>; previousHead: HeadRef; eventHead: HeadRef; statement?: unknown; chain?: unknown;
}>;

const refKey = (ref: Readonly<{ hash: string; position: number }>): string => `${ref.position}:${ref.hash}`;

/** `null` when `signed` is a valid owner-signed statement of this history for `head` by a key in force there (per the witness's epochs), else the rejection. */
function statementProblem(history: HistoryState, signed: unknown, head: HeadRef, name: string): Decision | null {
  const malformed = validateSignedHeadStatement(signed);
  if (malformed !== null) return reject(400, "INVALID_STATEMENT", `${name}: ${malformed}`);
  const { statement } = signed as SignedHeadStatement;
  if (statement.historyId !== history.historyId) return reject(400, "INVALID_STATEMENT", `${name} is for history ${statement.historyId}, not ${history.historyId}`);
  if (!sameDomain(statement.domain, history.domain)) return reject(400, "INVALID_STATEMENT", `${name}: the domain is not the domain of the registered genesis`);
  if (statement.head.hash !== head.hash || statement.head.position !== head.position) return reject(400, "INVALID_STATEMENT", `${name} must state the head that ends with the key event`);
  const verdict = verifySignedHeadStatement(signed as SignedHeadStatement, (position) => ownerKeysAt(history.epochs, position));
  if (!verdict.ok) {
    return reject(400, verdict.reason === "MALFORMED" ? "INVALID_STATEMENT" : "SIGNATURE_INVALID", `${name}: ${verdict.reason === "UNKNOWN_KEY" ? `owner key ${(signed as SignedHeadStatement).keyId} is not in force at position ${head.position}` : "the signature does not verify with the owner key it names"}`);
  }
  return signerProblem(history, signed as SignedHeadStatement, name);
}

/**
 * `POST /v1/histories/:id/key-events` (`{ event, previousHead, eventHead, statement?, chain? }`) and the admin import
 * of a key-event bundle (`POST /v1/admin/key-events`, `irontrellis-witness import-key-events`), docs/reference/witness-protocol.md §9.2.
 *
 * The event is an `OWNER_KEYS_ROTATED`, owner-signed at `previousHead` by a key in force there, that satisfies the
 * rotation rules against the epochs this witness knows (`verifyRotationEvent`: a rotation out of an epoch whose
 * commitment the witness knows must be pre-rotated). It is bound to a HEAD the witness holds at `eventHead`, or to one
 * delivered in the same request: `statement` (or `chain`) when it extends the witness's latest head. A `chain` whose
 * `previous` (L) is a head the witness holds but not its latest supersedes every head held after L, once per epoch
 * transition, and only for a pre-rotated rotation: SUPERSEDED, then HEAD (the chain), then ROTATED.
 */
export function decideKeyEvent(state: WitnessState, historyId: ContentHash, body: unknown, context: DecideContext, route: KeyEventRoute = "key-events"): Decision {
  const history = state.histories.get(historyId);
  if (history === undefined) return reject(404, "NOT_REGISTERED", `history ${historyId} is not registered with this witness`);
  let request: KeyEventRequest;
  if (route === "admin") {
    const problem = validateKeyEventBundle(body);
    if (problem !== null) return reject(400, "INVALID_REQUEST", `not a key-event bundle: ${problem}`);
    const bundle = body as KeyEventBundle;
    if (bundle.historyId !== historyId) return reject(400, "INVALID_REQUEST", "the bundle is for another history");
    if (typeof bundle.event.id !== "string") return reject(400, "KEY_EVENT_INVALID", "the event has no id");
    request = { event: bundle.event as Record<string, unknown>, previousHead: bundle.previousHead, eventHead: bundle.eventHead, statement: bundle.statement, ...(bundle.chain === undefined ? {} : { chain: bundle.chain }) };
  } else {
    const keys = isRecord(body) ? Object.keys(body) : [];
    if (!isRecord(body) || !["event", "previousHead", "eventHead"].every((key) => keys.includes(key)) || keys.some((key) => !["event", "previousHead", "eventHead", "statement", "chain"].includes(key))) {
      return reject(400, "INVALID_REQUEST", "the body must be { event, previousHead, eventHead, statement?, chain? }");
    }
    if (!isHeadRef(body.previousHead) || !isHeadRef(body.eventHead)) return reject(400, "INVALID_REQUEST", "previousHead and eventHead must be { hash, position }");
    if (!isRecord(body.event) || typeof body.event.id !== "string") return reject(400, "KEY_EVENT_INVALID", "event must be an OWNER_KEYS_ROTATED event");
    request = { event: body.event, previousHead: body.previousHead, eventHead: body.eventHead, ...(body.statement === undefined ? {} : { statement: body.statement }), ...(body.chain === undefined ? {} : { chain: body.chain }) };
  }
  const { event, previousHead, eventHead } = request;
  const type = event.type;
  // The only owner key event: epoch 0's next-key commitment is in the registered genesis, a later one rides on a rotation.
  if (type !== "OWNER_KEYS_ROTATED") return reject(400, "KEY_EVENT_INVALID", "event must be an OWNER_KEYS_ROTATED event");
  const eventId = event.id as string;
  let text: string;
  try {
    text = canonical(event);
  } catch (error) {
    return reject(400, "KEY_EVENT_INVALID", `event is not canonically encodable: ${error instanceof Error ? error.message : String(error)}`);
  }
  const replyExtras = (): Omit<Decision, "status" | "error"> => ({ epochs: true, latest: true });
  const existing = history.keyEvents.get(eventId);
  if (existing !== undefined) {
    if (existing.canonical === text && sameRef(existing.eventHead, eventHead) && sameRef(existing.previousHead, previousHead)) {
      return Object.freeze({ status: 200, receipt: existing.index, ...replyExtras() });
    }
    return reject(400, "KEY_EVENT_INVALID", `a different key event with event id ${eventId} is already recorded`);
  }
  if (eventHead.position !== previousHead.position + 1) return reject(400, "KEY_EVENT_INVALID", "eventHead.position must be previousHead.position + 1");
  const current = history.epochs.at(-1)!;
  if (eventHead.position < current.fromPosition) {
    return reject(400, "KEY_EVENT_INVALID", `the witness already records owner keys in force from position ${current.fromPosition}; a rotation at ${eventHead.position} is out of order`);
  }
  // A-100.1: a witness that does not know the policy of the epoch a rotation leaves is behind, not wrong.
  if (history.epochFacts.at(-1)?.policyKnown !== true) return reject(409, "WITNESS_POLICY_UNKNOWN", `this witness does not know the owner approval policy of the owner keys in force from position ${current.fromPosition}; import the epoch records first`);
  const verdict = verifyRotation(history, event, previousHead, context.lookup);
  if (!verdict.ok) {
    // G63-X-4 / A-120.1: T2 needs τ, the canonicalTime of the head before the rotation; without it nothing is accepted.
    if (verdict.notJudged === "T2") return reject(409, "KEY_EVENT_HEAD_UNKNOWN", `${verdict.reason}; submit the statement for previousHead (position ${previousHead.position}) first`);
    return reject(400, "KEY_EVENT_INVALID", verdict.reason);
  }

  const keyEntry = Object.freeze({
    version: WITNESS_ENTRY_VERSION, kind: "ROTATED", historyId, rotation: event, previousHead: Object.freeze({ hash: previousHead.hash, position: previousHead.position }),
    rotationHead: Object.freeze({ hash: eventHead.hash, position: eventHead.position }), receivedAt: context.now,
  }) as WitnessEntry;
  const appendAll = (entries: readonly WitnessEntry[], superseded = false): Decision =>
    Object.freeze({ status: 201, receipt: "appended", ...replyExtras(), ...(superseded ? { superseded: "first" as const } : {}), append: Object.freeze({ entries: Object.freeze([...entries, keyEntry]) }) });
  const headEntry = (signed: unknown): WitnessEntry => Object.freeze({ version: WITNESS_ENTRY_VERSION, kind: "HEAD", historyId, signedStatement: signed, receivedAt: context.now }) as WitnessEntry;

  const latest = history.latest;
  const held = history.heads.get(eventHead.position);
  const holdsEventHead = held !== undefined && held.hash === eventHead.hash;
  // The witness holds the event head: the key event is bound to it. With a chain, only when nothing conflicts after it.
  if (holdsEventHead && (request.chain === undefined || sameRef(eventHead, latest))) return appendAll([]);
  if (!holdsEventHead) {
    // The event head is delivered in this request: the statement (or the chain) must extend the latest head (docs/reference/witness-protocol.md §9.2 rule 3).
    for (const [name, signed] of [["statement", request.statement], ["chain", request.chain]] as const) {
      if (signed === undefined) continue;
      const problem = statementProblem(history, signed, eventHead, name);
      if (problem !== null) return problem;
      const previous = (signed as SignedHeadStatement).statement.previous;
      if (latest === undefined ? previous === null : sameRef(previous, latest) && eventHead.position > latest.position) return appendAll([headEntry(signed)]);
    }
  }
  if (request.chain === undefined || latest === undefined) {
    if (request.statement !== undefined) {
      return reject(409, "STALE_PREVIOUS", `the statement delivered with the rotation does not extend the witness's latest head${latest === undefined ? " (it holds none)" : ` (position ${latest.position})`}`, { latest: true });
    }
    return reject(409, "KEY_EVENT_HEAD_UNKNOWN", `the witness holds no head ${eventHead.hash} at position ${eventHead.position}; submit the statement for the rotation head (signed by the key in force there) first, or deliver it in the same request (statement)`);
  }

  // Supersede (docs/reference/witness-operations.md §7.4): the chain replaces every head held after its previous head.
  const chain = request.chain as SignedHeadStatement;
  const problem = statementProblem(history, chain, eventHead, "chain");
  if (problem !== null) return problem;
  const last = chain.statement.previous;
  if (last === null) return reject(400, "INVALID_STATEMENT", "chain.previous must name the last good head the witness holds");
  if (last.position > previousHead.position) return reject(400, "INVALID_STATEMENT", "chain.previous must not be after the head before the rotation");
  if (!verdict.preRotated) {
    return reject(409, "SUPERSEDE_REFUSED", "only a pre-rotated rotation (one that satisfies the next-key commitment this witness knows for the owner keys it leaves) can supersede heads; deliver the commitment first, or restore a copy on the witness chain");
  }
  const lastHeld = history.heads.get(last.position);
  if (lastHeld === undefined || lastHeld.hash !== last.hash) return reject(409, "SUPERSEDE_REFUSED", `chain.previous (position ${last.position}) is not a head this witness holds on its chain`, { latest: true });
  if (history.supersededEpochs.has(current.fromPosition)) {
    return reject(409, "SUPERSEDE_REFUSED", `a pre-rotated rotation already superseded heads of the owner keys in force from position ${current.fromPosition}; at most one supersede per owner key rotation`, { latest: true });
  }
  // The entry describes the superseded range (L's leaf, exclusive, to this entry's own leaf, exclusive), never each
  // head: however many heads a thief of the old key pushed, the supersede is one fixed-size entry.
  let count = 0;
  for (const head of history.heads.values()) if (head.index > lastHeld.index) count += 1;
  if (count === 0 || latest.index <= lastHeld.index) return reject(409, "SUPERSEDE_REFUSED", "the witness holds no head after chain.previous: nothing to supersede; deliver the rotation without a chain", { latest: true });
  const supersededEntry = Object.freeze({
    version: WITNESS_ENTRY_VERSION, kind: "SUPERSEDED", historyId, rotation: event, previousHead: Object.freeze({ hash: previousHead.hash, position: previousHead.position }),
    rotationHead: Object.freeze({ hash: eventHead.hash, position: eventHead.position }), chain,
    supersededFromIndex: lastHeld.index, supersededToIndex: state.size,
    supersededLatest: Object.freeze({ position: latest.position, hash: latest.hash, index: latest.index }), supersededCount: count, receivedAt: context.now,
  }) as WitnessEntry;
  return appendAll([supersededEntry, headEntry(chain)], true);
}

// ---------------------------------------------------------------- apply / replay

export type ApplyOptions = Readonly<{
  /** Re-verify owner signatures and rotation authorizations (the offline audit); the live server has already done so. */
  verify?: boolean;
  lookup: EntryLookup;
}>;

/**
 * Applies the entry at leaf `index` to `state`. Returns `null`, or a reason
 * when the entry could not have been produced by the rules above (a corrupt or
 * forged log); the state is unchanged in that case.
 */
export function applyEntry(state: WitnessState, entry: unknown, index: number, options: ApplyOptions): string | null {
  if (index !== state.size) return `leaf index ${index} out of order (expected ${state.size})`;
  const malformed = validateEntry(entry);
  if (malformed !== null) return malformed;
  const value = entry as WitnessEntry;
  const history = state.histories.get(value.historyId);
  if (value.kind === "REGISTERED") {
    if (history !== undefined) return `history ${value.historyId} is registered twice`;
    const format = genesisFormat(value.genesis);
    const validation = validateEvent(value.genesis, format, 0);
    if (!validation.ok) return `genesis: ${validation.code}: ${validation.reason}`;
    const data = validation.event.data as Readonly<{ domain: TrellisDomain; ownerKeys: readonly OwnerKey[]; nextKeyDigests?: readonly ContentHash[]; ownerPolicy?: OwnerPolicy }>;
    // Epoch 0 from the genesis: its owner keys and, when the genesis carries them, their next-key commitment and the
    // owner approval policy as written (A-100.1: Register {genesis} seeds epoch 0's policy).
    const epoch0: OwnerKeyEpoch = Object.freeze({
      fromPosition: 0, keys: data.ownerKeys, ...(data.nextKeyDigests === undefined ? {} : { nextKeyDigests: Object.freeze(data.nextKeyDigests.slice()) }),
      ...(format === TRELLIS2_FORMAT && data.ownerPolicy !== undefined ? { policy: data.ownerPolicy } : {}),
    });
    state.histories.set(value.historyId, {
      historyId: value.historyId, format, domain: data.domain, registrationIndex: index, epochs: Object.freeze([epoch0]),
      epochFacts: Object.freeze([Object.freeze({ policyKnown: true, openedAt: validation.event.timestamp })]),
      heads: new Map(), latest: undefined, equivocations: 0, lastEquivocationIndex: undefined, equivocationsByPosition: new Map(),
      keyEvents: new Map(), superseded: new Map(), supersedes: 0, lastSupersedeIndex: undefined, supersededEpochs: new Set(),
    });
    return finish(state, value);
  }
  if (history === undefined) return `history ${value.historyId} is not registered before this entry`;
  switch (value.kind) {
    case "HEAD": {
      const signed = value.signedStatement;
      const { head, previous, domain } = signed.statement;
      if (!sameDomain(domain, history.domain)) return "statement domain differs from the registration";
      if (options.verify === true && !verifySignedHeadStatement(signed, (position) => ownerKeysAt(history.epochs, position)).ok) return "statement signature does not verify";
      if (options.verify === true && !signerStanding(history, signed).qualified) return "statement signer is not qualified under the owner approval policy (A-111.3)";
      const latest = history.latest;
      if (latest === undefined ? previous !== null : previous === null || previous.hash !== latest.hash || previous.position !== latest.position || head.position <= latest.position) {
        return "statement does not chain onto the witness's latest head";
      }
      const held = Object.freeze({ hash: head.hash, position: head.position, canonicalTime: head.canonicalTime, index });
      history.heads.set(head.position, held);
      history.latest = held;
      // A superseded head stated again on the new chain (the same head, a genuine one an old key had also stated) is held again.
      history.superseded.delete(refKey(head));
      return finish(state, value);
    }
    case "EQUIVOCATION": {
      const { first, second } = value;
      const held = history.heads.get(first.statement.head.position);
      if (held === undefined || held.hash !== first.statement.head.hash) return "equivocation.first is not a head the witness holds";
      if (canonical(storedStatement(options.lookup, held.index)) !== canonical(first)) {
        return "equivocation.first is not the stored statement";
      }
      if (!sameDomain(second.statement.domain, history.domain)) return "equivocation.second domain differs from the registration";
      const position = second.statement.head.position;
      if (history.equivocationsByPosition.has(position)) return `a second equivocation recorded at position ${position}`;
      if (history.equivocations >= MAX_EQUIVOCATIONS_PER_HISTORY) return `more than ${MAX_EQUIVOCATIONS_PER_HISTORY} equivocations recorded for the history`;
      if (options.verify === true && !verifySignedHeadStatement(second, (position) => ownerKeysAt(history.epochs, position)).ok) {
        return "equivocation.second signature does not verify";
      }
      if (options.verify === true && !signerStanding(history, second).qualified) return "equivocation.second signer is not qualified under the owner approval policy (A-111.3)";
      if (history.equivocations === 0) state.equivocatingHistories += 1;
      history.equivocations += 1;
      history.lastEquivocationIndex = index;
      history.equivocationsByPosition.set(position, index);
      return finish(state, value);
    }
    case "ROTATED": {
      const rotation = value.rotation as Record<string, unknown>;
      const eventId = rotation.id;
      if (typeof eventId !== "string") return "rotation has no event id";
      if (history.keyEvents.has(eventId)) return `key event ${eventId} is recorded twice`;
      const held = history.heads.get(value.rotationHead.position);
      if (held === undefined || held.hash !== value.rotationHead.hash) return "rotationHead is not a head the witness held";
      const current = history.epochs.at(-1)!;
      if (value.rotationHead.position < current.fromPosition) return "rotation out of order";
      let epochs: readonly OwnerKeyEpoch[], openedAt: number;
      if (options.verify === true) {
        // docs/reference/witness-protocol.md §9.3: the leaf carries the head the rotation's owner signature binds; τ for T2 is the held head before it.
        const verdict = verifyRotation(history, rotation, value.previousHead, options.lookup);
        if (!verdict.ok) return `rotation: ${verdict.reason}`;
        epochs = verdict.epochs;
        openedAt = verdict.openedAt;
      } else {
        const validation = validateEvent(rotation, history.format, value.rotationHead.position);
        if (!validation.ok || validation.event.type !== "OWNER_KEYS_ROTATED") return `rotation: ${validation.ok ? "not OWNER_KEYS_ROTATED" : validation.reason}`;
        const keys = Object.freeze((validation.event.data.ownerKeys as readonly OwnerKey[]).map((key) => Object.freeze({ keyId: key.keyId, scheme: key.scheme, credential: key.credential })));
        const rule = ownerKeyRotationFailure(history.epochs, keys);
        if (rule !== undefined) return rule;
        // The new epoch's next-key commitment (pre-rotation) and owner approval policy are kept as the verified path keeps them.
        const nextKeyDigests = validation.event.data.nextKeyDigests as readonly ContentHash[] | undefined;
        const policy = history.format === TRELLIS2_FORMAT ? validation.event.data.ownerPolicy as OwnerPolicy | undefined : undefined;
        epochs = Object.freeze([...history.epochs, Object.freeze({
          fromPosition: value.rotationHead.position + 1, keys, ...(nextKeyDigests === undefined ? {} : { nextKeyDigests: Object.freeze(nextKeyDigests.slice()) }),
          ...(policy === undefined ? {} : { policy }),
        })]);
        openedAt = validation.event.timestamp;
      }
      recordEpoch(history, epochs, openedAt);
      history.keyEvents.set(eventId, Object.freeze({ eventId, index, previousHead: value.previousHead, eventHead: value.rotationHead, canonical: canonical(rotation) }));
      return finish(state, value);
    }
    case "SUPERSEDED": {
      const rotation = value.rotation as Record<string, unknown>;
      const last = value.chain.statement.previous!;
      const lastHeld = history.heads.get(last.position);
      if (lastHeld === undefined || lastHeld.hash !== last.hash || lastHeld.index !== value.supersededFromIndex) return "supersede: chain.previous is not the held head at supersededFromIndex";
      if (!sameDomain(value.chain.statement.domain, history.domain)) return "supersede: chain domain differs from the registration";
      const latest = history.latest;
      if (latest === undefined || latest.position <= last.position) return "supersede: nothing after the last good head to supersede";
      // The range form: every head held with a leaf index in (supersededFromIndex, supersededToIndex)
      // is superseded; the range must end at this entry, and its latest and count must be what the witness held.
      if (value.supersededToIndex !== index) return "supersede: supersededToIndex is not the leaf index of the SUPERSEDED entry";
      const latestNamed = value.supersededLatest;
      if (latestNamed.index !== latest.index || latestNamed.position !== latest.position || latestNamed.hash !== latest.hash) return "supersede: supersededLatest is not the witness's latest head";
      const expected: HeldHead[] = [];
      for (const head of history.heads.values()) {
        if (head.index <= value.supersededFromIndex) continue;
        if (head.position <= last.position) return "supersede: a head held after the last good head's leaf is not after it on the chain";
        expected.push(head);
      }
      if (expected.length !== value.supersededCount) return `supersede: supersededCount ${value.supersededCount} is not the ${expected.length} heads held after the last good head`;
      const current = history.epochs.at(-1)!;
      if (value.rotationHead.position < current.fromPosition) return "supersede: rotation out of order";
      if (history.supersededEpochs.has(current.fromPosition)) return "supersede: a second supersede for one owner key rotation";
      if (typeof rotation.id !== "string" || history.keyEvents.has(rotation.id)) return "supersede: the rotation is already recorded";
      if (options.verify === true) {
        const verdict = verifyRotation(history, rotation, value.previousHead, options.lookup);
        if (!verdict.ok) return `supersede: rotation: ${verdict.reason}`;
        if (!verdict.preRotated) return "supersede: the rotation is not pre-rotated";
        if (!verifySignedHeadStatement(value.chain, (position) => ownerKeysAt(history.epochs, position)).ok) return "supersede: chain signature does not verify";
      }
      for (const head of expected) {
        history.heads.delete(head.position);
        history.superseded.set(refKey(head), head.index);
      }
      history.latest = lastHeld;
      history.supersedes += 1;
      history.lastSupersedeIndex = index;
      history.supersededEpochs.add(current.fromPosition);
      return finish(state, value);
    }
    default:
      return "unknown entry kind";
  }
}

const finish = (state: WitnessState, entry: WitnessEntry): null => {
  state.size += 1;
  state.kinds[entry.kind] += 1;
  return null;
};

/** The history's latest head as `{hash, position, canonicalTime}` (no index). */
export const headOf = (held: HeldHead): Readonly<{ hash: ContentHash; position: number; canonicalTime: number }> =>
  Object.freeze({ hash: held.hash, position: held.position, canonicalTime: held.canonicalTime });
