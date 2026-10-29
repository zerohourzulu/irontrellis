/**
 * Hashing (spec 01 §B). Every hash in the engine is over the UTF-8 bytes of the
 * canonical text: keccak-256 for `continuity-event/0.2`, sha256 for
 * `irontrellis-event/1`. History heads are prefix hashes of the wrapper
 * `[<wrapper string>,[<e0>,<e1>,…]]`, absorbed incrementally so a store never
 * re-hashes the whole history on append.
 */
import { createHash, type Hash } from "node:crypto";
import { CanonicalError, LIMITS, canonicalEncode, checkDenseArray } from "./canonical.ts";
import { cloneKeccakState, createKeccakState, finalizeKeccakState, keccak256, updateKeccakState, type KeccakState } from "./crypto/keccak.ts";
import type { ContentHash, HashAlgorithm, HistoryFormat } from "./types.ts";

const UTF8 = new TextEncoder();
const HEX = Array.from({ length: 256 }, (_, byte) => byte.toString(16).padStart(2, "0"));

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let index = 0; index < bytes.length; index += 1) out += HEX[bytes[index] as number];
  return out;
}

function toContentHash(bytes: Uint8Array): ContentHash {
  return `0x${bytesToHex(bytes)}`;
}

export function sha256Hex(bytes: Uint8Array): ContentHash {
  return `0x${createHash("sha256").update(bytes).digest("hex")}`;
}

export function hashBytes(bytes: Uint8Array, algorithm: HashAlgorithm): ContentHash {
  return algorithm === "keccak256" ? toContentHash(keccak256(bytes)) : sha256Hex(bytes);
}

/** canonicalEncode → UTF-8 → hash. Throws CanonicalError for values the canonical form rejects. */
export function hashCanonical(value: unknown, algorithm: HashAlgorithm): ContentHash {
  return hashBytes(UTF8.encode(canonicalEncode(value)), algorithm);
}

// ---------------------------------------------------------------- history prefix hashing

const FORMATS: Readonly<Record<string, Readonly<{ algorithm: HashAlgorithm; wrapper: string }>>> = Object.freeze({
  "continuity-event/0.2": Object.freeze({ algorithm: "keccak256", wrapper: "continuity-event-history/0.2" }),
  "irontrellis-event/1": Object.freeze({ algorithm: "sha256", wrapper: "irontrellis-event-history/1" }),
});
const FORMAT2 = "irontrellis-event/2";

export function historyHashAlgorithm(format: HistoryFormat): HashAlgorithm {
  return format === FORMAT2 ? "sha256" : formatOf(format).algorithm;
}

function formatOf(format: HistoryFormat): Readonly<{ algorithm: HashAlgorithm; wrapper: string }> {
  const entry = FORMATS[format];
  if (entry === undefined) throw new CanonicalError(`Unsupported history format ${String(format)}.`);
  return entry;
}

// ---------------------------------------------------------------- format 2: the record chain (SPEC §4.2–4.4)

export const RECORD_CHAIN_VERSION = "irontrellis-record/2";
const RECORD_CHAIN_PREFIX = UTF8.encode(RECORD_CHAIN_VERSION);
const ZERO32 = new Uint8Array(32);

function sha256Bytes(...parts: readonly Uint8Array[]): Uint8Array {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return new Uint8Array(hash.digest());
}
const be64 = (n: number): Uint8Array => {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n));
  return out;
};
export function hexToBytes(hash: ContentHash): Uint8Array {
  return new Uint8Array(Buffer.from(hash.slice(2), "hex"));
}

/** SPEC §4.2: `eventHash(e) = sha256(utf8(canonical(e)))` over the whole four-key event, 32 raw bytes. */
export function eventHashBytes(event: unknown): Uint8Array {
  return sha256Bytes(UTF8.encode(canonicalEncode(event)));
}
export function eventHash(event: unknown): ContentHash {
  return toContentHash(eventHashBytes(event));
}
/** SPEC §4.3: `recordHash(p) = sha256("irontrellis-record/2" ‖ 0x00 ‖ prev ‖ eventHash ‖ be64(p))`, `prev = 0^32` at p = 0 (93-byte preimage). */
export function recordHashBytes(previous: Uint8Array | null, eventHash: Uint8Array, position: number): Uint8Array {
  return sha256Bytes(RECORD_CHAIN_PREFIX, new Uint8Array([0]), previous ?? ZERO32, eventHash, be64(position));
}
export function recordHash(previous: ContentHash | null, event: unknown, position: number): ContentHash {
  return toContentHash(recordHashBytes(previous === null ? null : hexToBytes(previous), eventHashBytes(event), position));
}

/** What replay needs from a prefix hasher: the head hash after each pushed event, and a clone for a trial push. */
export interface PrefixHasher {
  readonly format: HistoryFormat;
  readonly algorithm: HashAlgorithm;
  readonly count: number;
  push(event: unknown): ContentHash;
  clone(): PrefixHasher;
}

/**
 * The format-2 chain (SPEC §4.3) with the `HistoryHasher` interface: `push(event)` returns `recordHash(p)` for the next
 * position `p`, which *is* the head hash. There is no empty-history hash (SPEC §4.4). `lastEventHash` is the
 * `eventHash` of the event last pushed (the `event` state record and the projection row need it).
 */
export class RecordChain implements PrefixHasher {
  readonly format: HistoryFormat = FORMAT2;
  readonly algorithm: HashAlgorithm = "sha256";
  #previous: Uint8Array | null = null;
  #count = 0;
  #lastEventHash: Uint8Array | undefined = undefined;
  #lastEventBytes = 0;

  get count(): number {
    return this.#count;
  }
  get lastEventHash(): ContentHash | undefined {
    return this.#lastEventHash === undefined ? undefined : toContentHash(this.#lastEventHash);
  }
  /** The UTF-8 length of the last pushed event's canonical text (the bytes its store line carries, SPEC §4.1). */
  get lastEventBytes(): number {
    return this.#lastEventBytes;
  }
  push(event: unknown): ContentHash {
    const text = UTF8.encode(canonicalEncode(event));
    const eh = sha256Bytes(text);
    const rh = recordHashBytes(this.#previous, eh, this.#count);
    this.#previous = rh;
    this.#lastEventHash = eh;
    this.#lastEventBytes = text.length;
    this.#count += 1;
    return toContentHash(rh);
  }
  clone(): RecordChain {
    const copy = new RecordChain();
    copy.#previous = this.#previous;
    copy.#count = this.#count;
    copy.#lastEventHash = this.#lastEventHash;
    copy.#lastEventBytes = this.#lastEventBytes;
    return copy;
  }
  /**
   * A chain positioned after `count` events whose last record hash is `head` and last event hash `lastEventHash` (the
   * rebuild from records, SPEC §7.5 step 4: the `event` records carry both). `lastEventBytes` is unknown (0) until the next push.
   */
  static resume(head: ContentHash, count: number, lastEventHash: ContentHash): RecordChain {
    const chain = new RecordChain();
    chain.#previous = hexToBytes(head);
    chain.#count = count;
    chain.#lastEventHash = hexToBytes(lastEventHash);
    return chain;
  }
}

/** The prefix hasher of a format: the wrapper hasher for legacy and format 1, the record chain for format 2. */
export function createHistoryHasher(format: HistoryFormat): PrefixHasher {
  return format === FORMAT2 ? new RecordChain() : new HistoryHasher(format);
}
/**
 * The id a remote witness registers a history under (WITNESS §9.1, SPEC §7.4): the position-0 head hash of `genesis` —
 * `recordHash(0)` for a format-2 genesis (`versions.eventSchemaVersion` `irontrellis-event/2`), the format-1 prefix hash
 * otherwise. Throws like `push` for a value that is not canonically encodable.
 */
export function historyIdOfGenesis(genesis: unknown): ContentHash {
  const versions = (genesis as { data?: { versions?: { eventSchemaVersion?: unknown } } } | null)?.data?.versions;
  return createHistoryHasher(versions?.eventSchemaVersion === FORMAT2 ? FORMAT2 : "irontrellis-event/1").push(genesis);
}

const SEPARATOR = UTF8.encode(",");
const SUFFIX = UTF8.encode("]]");
/** Every event sits inside `[wrapper,[…]]`, two containers deep (spec 01 A.8: 28 levels under `data`). */
const EVENT_ANCESTOR_DEPTH = 2;

/** One absorbing state for either algorithm; sha256 uses node's copyable Hash objects. */
type Absorber =
  | Readonly<{ kind: "keccak"; state: KeccakState }>
  | Readonly<{ kind: "sha256"; state: Hash }>;

function createAbsorber(algorithm: HashAlgorithm): Absorber {
  return algorithm === "keccak256"
    ? { kind: "keccak", state: createKeccakState() }
    : { kind: "sha256", state: createHash("sha256") };
}

function absorb(absorber: Absorber, bytes: Uint8Array): void {
  if (absorber.kind === "keccak") updateKeccakState(absorber.state, bytes);
  else absorber.state.update(bytes);
}

function cloneAbsorber(absorber: Absorber): Absorber {
  return absorber.kind === "keccak"
    ? { kind: "keccak", state: cloneKeccakState(absorber.state) }
    : { kind: "sha256", state: absorber.state.copy() };
}

function finalizeAbsorber(absorber: Absorber): ContentHash {
  return absorber.kind === "keccak"
    ? toContentHash(finalizeKeccakState(absorber.state))
    : `0x${absorber.state.digest("hex")}`;
}

/**
 * Incremental prefix hashes (spec 01 B.3). `push(event)` absorbs the event's
 * canonical text and returns the hash of the history up to and including it,
 * so `hasher.push(e[p]) === hashEventHistory(events.slice(0, p + 1), format)`.
 *
 * The legacy format keeps the reference's whole-history bounds (4096 events,
 * 16 MiB of canonical text) so that a history the reference rejects is
 * rejected here too; format 1 has no whole-history bound (the store's file
 * cap is the only physical limit).
 */
export class HistoryHasher implements PrefixHasher {
  readonly format: HistoryFormat;
  readonly algorithm: HashAlgorithm;
  #absorber: Absorber;
  #count: number;
  /** Canonical bytes of the wrapper absorbed so far (legacy budget accounting). */
  #bytes: number;

  constructor(format: HistoryFormat) {
    const entry = formatOf(format);
    this.format = format;
    this.algorithm = entry.algorithm;
    this.#absorber = createAbsorber(entry.algorithm);
    const prefix = UTF8.encode(`["${entry.wrapper}",[`);
    absorb(this.#absorber, prefix);
    this.#count = 0;
    this.#bytes = prefix.length + SUFFIX.length;
  }

  get count(): number {
    return this.#count;
  }

  push(event: unknown): ContentHash {
    const legacy = this.format === "continuity-event/0.2";
    if (legacy && this.#count >= LIMITS.maxListMembers) {
      throw new CanonicalError(
        `Canonical array at $[1] exceeds the ${LIMITS.maxListMembers}-member bound.`,
        "$[1]",
        true,
      );
    }
    const text = canonicalEncode(event, {
      ancestorDepth: EVENT_ANCESTOR_DEPTH,
      maxTotalBytes: legacy ? LIMITS.maxTotalBytes - this.#bytes - (this.#count > 0 ? 1 : 0) : LIMITS.maxTotalBytes,
    });
    const bytes = UTF8.encode(text);
    if (this.#count > 0) {
      absorb(this.#absorber, SEPARATOR);
      this.#bytes += 1;
    }
    absorb(this.#absorber, bytes);
    this.#bytes += bytes.length;
    this.#count += 1;
    const finalizable = cloneAbsorber(this.#absorber);
    absorb(finalizable, SUFFIX);
    return finalizeAbsorber(finalizable);
  }

  clone(): HistoryHasher {
    const copy = new HistoryHasher(this.format);
    copy.#absorber = cloneAbsorber(this.#absorber);
    copy.#count = this.#count;
    copy.#bytes = this.#bytes;
    return copy;
  }
}

/**
 * Hash of the whole history: `hashCanonical([wrapper, events])`. `events` must
 * be a dense runtime array. For the empty history the result is the hash of
 * `["<wrapper>",[]]`.
 */
export function hashEventHistory(events: readonly unknown[], format: HistoryFormat): ContentHash {
  if (!Array.isArray(events)) throw new CanonicalError("Event history must be a runtime array.");
  if (format === FORMAT2) {
    // SPEC §4.4: the head is the chain tip; an empty format-2 history has no head.
    if (events.length === 0) throw new CanonicalError("A format-2 history has no empty-history hash.");
    return hashEventHistoryPrefixes(events, format).at(-1)!;
  }
  const entry = formatOf(format);
  const legacy = format === "continuity-event/0.2";
  checkDenseArray(events, "$[1]", legacy ? LIMITS.maxListMembers : undefined);
  if (events.length === 0) return hashCanonical([entry.wrapper, []], entry.algorithm);
  const hasher = new HistoryHasher(format);
  let head: ContentHash = "0x";
  for (let index = 0; index < events.length; index += 1) {
    if (events[index] === undefined) {
      throw new CanonicalError(`Canonical array entry at $[1][${index}] is undefined.`, `$[1][${index}]`);
    }
    head = hasher.push(events[index]);
  }
  return head;
}

/** Every prefix hash of a history (reference `hashEventHistoryPrefixes`). */
export function hashEventHistoryPrefixes(events: readonly unknown[], format: HistoryFormat): readonly ContentHash[] {
  if (!Array.isArray(events)) throw new CanonicalError("Event history must be a runtime array.");
  const legacy = format === "continuity-event/0.2";
  checkDenseArray(events, "$[1]", legacy ? LIMITS.maxListMembers : undefined);
  const hasher = createHistoryHasher(format);
  const hashes: ContentHash[] = [];
  for (let index = 0; index < events.length; index += 1) {
    if (events[index] === undefined) {
      throw new CanonicalError(`Canonical array entry at $[1][${index}] is undefined.`, `$[1][${index}]`);
    }
    hashes.push(hasher.push(events[index]));
  }
  return Object.freeze(hashes);
}
