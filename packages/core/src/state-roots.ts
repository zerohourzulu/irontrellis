/**
 * The §7.1 state root, computed where it is consumed (SPEC-IRONTRELLIS-CORE-v2 §7.1, §7.3, §7.5; BUILD §6; addendum A-67).
 *
 * `rootAt(p)` is the RFC 6962 MTH over the leaves of the record set after event `p`, in (kind, key) byte order. What
 * this module changes is only WHEN and HOW OFTEN that value is computed — never its bytes:
 *
 * 1. **Lazily, per position.** Replay no longer hashes a root after every event. `state.stateRoots` keeps its shape (an
 *    array indexed by position, `length` = the event count), but an entry is computed on first read: the head's root from
 *    the live record set, an earlier position's root from the live set with the record changes after it undone (each
 *    accepted event leaves an undo list: the entries it replaced). Every consumer reads the root through it (a
 *    checkpoint's `rootAt(p−1)`, the pin's attestation at the head, `verify`, the export view, the snapshot base), so
 *    each one is still a recomputation over the actual records; a value, once computed, is kept (a history is append-only).
 * 2. **Incrementally, at the head (A-67).** `RecordTree` caches every aligned perfect subtree of the sorted leaf list
 *    (`levels[h][j]` = MTH of leaves `[j·2^h, (j+1)·2^h)`) and recomputes only the ones whose leaf range changed: an
 *    in-place record change dirties one path (h hashes), an insertion or deletion at index i dirties every subtree right
 *    of i (the leaves there moved: thoughts item 2 — RFC 6962 over sorted leaves has no O(log n) insertion). The root
 *    is the right fold of the perfect subtrees of the binary decomposition of n, which is exactly RFC 6962's MTH split.
 *
 * Forks (`forkReplayState`) read earlier positions through their base and compute their own positions from their own
 * records; they never touch the base's tree. A state rebuilt from records (§7.5 step 4) knows the root at its position
 * only (as before: earlier positions are unfilled).
 */
import { hash as oneShotHash } from "node:crypto";
import { TRELLIS2_FORMAT } from "./events.ts";
import { bytesToHex } from "./hash.ts";
import { NODE_CHUNK, nodeEngine } from "./crypto/sha256-nodes.ts";
import type { ContentHash, StateRecordEntry } from "./types.ts";

// ---------------------------------------------------------------- hashing (no allocation per node beyond the digest string)

const NODE = Buffer.alloc(65);
NODE[0] = 1;
const ACC = Buffer.alloc(32);
/** sha256("") — RFC 6962 MTH of the empty list. */
const EMPTY = Buffer.from(oneShotHash("sha256", Buffer.alloc(0), "binary"), "latin1");
const digestInto = (out: Buffer, offset: number): void => { out.write(oneShotHash("sha256", NODE, "binary"), offset, 32, "latin1"); };
const hex = (bytes: Uint8Array): ContentHash => `0x${bytesToHex(bytes)}`;

// ---------------------------------------------------------------- the aligned-subtree cache

const nextCapacity = (needed: number, current: number): number => { let c = Math.max(current, 64); while (c < needed) c *= 2; return c; };

/**
 * The sorted leaf list and its perfect aligned subtrees. `leaves[i]` is the leaf of the i-th record in (kind, key)
 * order; `levels[h]` (h ≥ 1) holds `n >> h` node hashes, of which the first `valid[h]` are current unless a leaf they
 * cover was marked: `shiftFrom` (an insertion or deletion: every leaf from there on moved) or `points` (in-place changes
 * left of `shiftFrom`). `root()` recomputes exactly the stale nodes, bottom-up, then folds the decomposition of n.
 */
export class RecordTree {
  leaves: Uint8Array[];
  #levels: Buffer[] = [];
  #valid: number[] = [];
  #shiftFrom = 0;
  #points: number[] = [];
  #root: ContentHash | undefined = undefined;
  /** Node hashes computed by this tree (a test counter: the cache-vs-scratch property test reads it). */
  hashes = 0;

  constructor(leaves: Uint8Array[]) {
    this.leaves = leaves;
  }
  insert(index: number, leaf: Uint8Array): void {
    this.leaves.splice(index, 0, leaf);
    if (index < this.#shiftFrom) this.#shiftFrom = index;
    this.#root = undefined;
  }
  remove(index: number): void {
    this.leaves.splice(index, 1);
    if (index < this.#shiftFrom) this.#shiftFrom = index;
    this.#root = undefined;
  }
  update(index: number, leaf: Uint8Array): void {
    this.leaves[index] = leaf;
    if (index < this.#shiftFrom) this.#points.push(index);
    this.#root = undefined;
  }
  /** An independent copy (the leaves are shared: they are never mutated, only replaced). */
  clone(): RecordTree {
    const copy = new RecordTree(this.leaves.slice());
    copy.#levels = this.#levels.map((level) => Buffer.from(level));
    copy.#valid = this.#valid.slice();
    copy.#shiftFrom = this.#shiftFrom;
    copy.#points = this.#points.slice();
    copy.#root = this.#root;
    return copy;
  }

  root(): ContentHash {
    if (this.#root !== undefined) return this.#root;
    const leaves = this.leaves, n = leaves.length;
    if (n === 0) return (this.#root = hex(EMPTY));
    const points = this.#points.length > 1 ? [...new Set(this.#points)].sort((a, b) => a - b) : this.#points;
    let h = 1;
    for (; n >> h > 0; h += 1) {
      const count = n >> h;
      let level = this.#levels[h];
      if (level === undefined || level.length < count * 32) {
        const grown = Buffer.allocUnsafe(nextCapacity(count * 32, level?.length ?? 0));
        if (level !== undefined) level.copy(grown, 0, 0, Math.min(level.length, (this.#valid[h] ?? 0) * 32));
        this.#levels[h] = level = grown;
      }
      const below = h === 1 ? undefined : this.#levels[h - 1]!;
      const start = Math.min(this.#shiftFrom >> h, this.#valid[h] ?? 0, count);
      // The stale nodes of this level: the parents of in-place changes left of `start`, then every node from `start` on.
      const marked: number[] = [];
      for (const p of points) { const j = p >> h; if (j >= start) break; if (marked.at(-1) !== j) marked.push(j); }
      hashLevel(leaves, below, level, marked, start, count);
      this.hashes += marked.length + count - start;
      this.#valid[h] = count;
    }
    this.#valid.length = h; // levels above the top hold nothing current (the list may have shrunk)
    this.#shiftFrom = n;
    this.#points = [];
    // The right fold of the perfect subtrees of n's binary decomposition (RFC 6962: MTH(L) = H(MTH(L[0:k]), MTH(L[k:n]))).
    let offset = n, folded = false;
    for (let b = 0; n >> b > 0; b += 1) {
      if (((n >> b) & 1) === 0) continue;
      offset -= 1 << b;
      const block = b === 0 ? leaves[offset]! : this.#levels[b]!.subarray((offset >> b) * 32, (offset >> b) * 32 + 32);
      if (!folded) { ACC.set(block, 0); folded = true; continue; }
      NODE.set(block, 1);
      NODE.set(ACC, 33);
      digestInto(ACC, 0);
      this.hashes += 1;
    }
    return (this.#root = hex(ACC));
  }
}

/**
 * The nodes `marked` and `[start, count)` of one level into `level` (32 bytes per node): their children are two leaves
 * (`below` undefined, level 1) or two adjacent nodes of `below` (64 contiguous bytes), hashed NODE_CHUNK at a time by the
 * node engine (crypto/sha256-nodes.ts); a contiguous range is copied in and out in one piece.
 */
function hashLevel(leaves: readonly Uint8Array[], below: Buffer | undefined, level: Buffer, marked: readonly number[], start: number, count: number): void {
  const e = nodeEngine();
  const children = (j: number, at: number): void => {
    if (below === undefined) { e.memory.set(leaves[2 * j]!, at); e.memory.set(leaves[2 * j + 1]!, at + 32); } else below.copy(e.memory, at, 64 * j, 64 * j + 64);
  };
  for (let from = 0; from < marked.length; from += NODE_CHUNK) {
    const n = Math.min(NODE_CHUNK, marked.length - from);
    for (let i = 0; i < n; i += 1) children(marked[from + i]!, e.children + 64 * i);
    e.run(n);
    for (let i = 0; i < n; i += 1) e.memory.copy(level, 32 * marked[from + i]!, e.digests + 32 * i, e.digests + 32 * i + 32);
  }
  for (let from = start; from < count; from += NODE_CHUNK) {
    const n = Math.min(NODE_CHUNK, count - from);
    if (below === undefined) for (let i = 0; i < n; i += 1) children(from + i, e.children + 64 * i);
    else below.copy(e.memory, e.children, 64 * from, 64 * (from + n));
    e.run(n);
    e.memory.copy(level, 32 * from, e.digests, e.digests + 32 * n);
  }
}

/** SPEC §7.1: the RFC 6962 MTH over `leaves` (already in (kind, key) order), from scratch. */
export function rootOfLeaves(leaves: readonly Uint8Array[]): ContentHash {
  return new RecordTree(leaves.slice()).root();
}

// ---------------------------------------------------------------- per-position roots, computed on first read

/** The entries one accepted event replaced: `[recordKey, previous entry or undefined when the key was absent]`, in order. */
export type UndoList = readonly (readonly [string, StateRecordEntry | undefined])[];

/** The record view a root log reads: the live maps of the state that owns it. */
export type RootSource = Readonly<{
  /** Only a format-2 state has state records and roots (other formats: every position reads `undefined`). */
  format: string;
  events: Readonly<{ length: number }>;
  stateRecords: ReadonlyMap<string, StateRecordEntry>;
  sortedRecordKeys: readonly string[];
}>;

export class RootLog {
  readonly #source: RootSource;
  readonly #known: (ContentHash | undefined)[] = [];
  readonly #undo: (UndoList | undefined)[] = [];
  readonly #parent: RootLog | undefined;
  readonly #parentLimit: number;
  /** The cache over the live record set; built on the first head root, kept in step by `inserted`/`removed`/`updated`. */
  tree: RecordTree | undefined = undefined;

  constructor(source: RootSource, parent?: RootLog, parentLimit = 0) {
    this.#source = source;
    this.#parent = parent;
    this.#parentLimit = parent === undefined ? 0 : parentLimit;
  }
  /** Records that event `position` replaced these entries (applyStateRecords). */
  logUndo(position: number, undo: UndoList): void {
    this.#undo[position] = undo;
  }
  /** A root known from elsewhere (the rebuild at its position: recomputed from the records there). */
  setKnown(position: number, root: ContentHash): void {
    this.#known[position] = root;
  }
  known(position: number): ContentHash | undefined {
    return this.#known[position];
  }
  /** `rootAt(position)` over `entries`, the record set `entriesAt(position)` returned (kept like any computed root). */
  rootOfEntries(position: number, entries: readonly StateRecordEntry[]): ContentHash {
    const known = this.rootAtIfKnown(position);
    if (known !== undefined) return known;
    const root = new RecordTree(entries.map((entry) => entry.leaf)).root();
    this.#known[position] = root;
    return root;
  }
  /** A root already computed for `position` (here or by the base of a fork), without computing one. */
  rootAtIfKnown(position: number): ContentHash | undefined {
    const known = this.#known[position];
    if (known !== undefined) return known;
    return this.#parent !== undefined && position < this.#parentLimit ? this.#parent.rootAtIfKnown(position) : undefined;
  }
  /** `rootAt(position)`, computed now if needed; `undefined` for a position this state cannot reconstruct. */
  rootAt(position: number): ContentHash | undefined {
    const known = this.#known[position];
    if (known !== undefined) return known;
    if (this.#parent !== undefined && position < this.#parentLimit) return this.#parent.rootAt(position);
    const head = this.#source.events.length - 1;
    if (this.#source.format !== TRELLIS2_FORMAT || !Number.isSafeInteger(position) || position < 0 || position > head) return undefined;
    const root = position === head ? this.#headRoot() : this.#pastRoot(position, head);
    if (root !== undefined) this.#known[position] = root;
    return root;
  }
  #headRoot(): ContentHash {
    if (this.tree === undefined) {
      const { stateRecords, sortedRecordKeys } = this.#source;
      this.tree = new RecordTree(sortedRecordKeys.map((k) => stateRecords.get(k)!.leaf));
    }
    return this.tree.root();
  }
  /** The live record set with every change after `position` undone, then the MTH from scratch over it. */
  #pastRoot(position: number, head: number): ContentHash | undefined {
    const entries = this.#entriesAt(position, head);
    return entries === undefined ? undefined : new RecordTree(entries.map((entry) => entry.leaf)).root();
  }
  /**
   * The record set after event `position`, in (kind, key) order: the live one at the head, else the live one with every
   * later change undone; `undefined` when this state cannot reconstruct it (a rebuilt state before its position).
   */
  entriesAt(position: number): readonly StateRecordEntry[] | undefined {
    if (this.#parent !== undefined && position < this.#parentLimit) return this.#parent.entriesAt(position);
    const head = this.#source.events.length - 1;
    if (this.#source.format !== TRELLIS2_FORMAT || !Number.isSafeInteger(position) || position < 0 || position > head) return undefined;
    return this.#entriesAt(position, head);
  }
  #entriesAt(position: number, head: number): StateRecordEntry[] | undefined {
    const { stateRecords, sortedRecordKeys } = this.#source;
    if (position === head) return sortedRecordKeys.map((k) => stateRecords.get(k)!);
    const before = new Map<string, StateRecordEntry | undefined>();
    for (let p = head; p > position; p -= 1) {
      const undo = this.#undo[p];
      if (undo === undefined) return undefined; // no undo information (a rebuilt state before its position)
      for (let i = undo.length - 1; i >= 0; i -= 1) before.set(undo[i]![0], undo[i]![1]);
    }
    const restored = [...before.entries()].filter((entry) => entry[1] !== undefined).map((entry) => entry[0]).sort(compareKeys);
    const out: StateRecordEntry[] = [];
    let r = 0;
    for (const k of sortedRecordKeys) {
      while (r < restored.length && compareKeys(restored[r]!, k) < 0) { out.push(before.get(restored[r]!)!); r += 1; }
      if (before.has(k)) {
        const prior = before.get(k);
        if (prior !== undefined && restored[r] === k) { out.push(prior); r += 1; }
        continue;
      }
      out.push(stateRecords.get(k)!);
    }
    while (r < restored.length) { out.push(before.get(restored[r]!)!); r += 1; }
    return out;
  }
  /** Leaf-list maintenance (`setRecord`): only an existing tree is kept in step; one is built on demand otherwise. */
  inserted(index: number, leaf: Uint8Array): void { this.tree?.insert(index, leaf); }
  removed(index: number): void { this.tree?.remove(index); }
  updated(index: number, leaf: Uint8Array): void { this.tree?.update(index, leaf); }
}

/** UTF-16 order of `kind\u0000key` with the surrogate fix-up: the byte order of SPEC §7.1 (`compareProtocolStrings`). */
const compareKeys = (left: string, right: string): number => {
  const shared = left.length < right.length ? left.length : right.length;
  for (let index = 0; index < shared; index += 1) {
    let a = left.charCodeAt(index), b = right.charCodeAt(index);
    if (a === b) continue;
    if (a >= 0xd800 || b >= 0xd800) {
      if (a >= 0xd800 && a <= 0xdfff) a += 0x2000; else if (a >= 0xe000) a -= 0x800;
      if (b >= 0xd800 && b <= 0xdfff) b += 0x2000; else if (b >= 0xe000) b -= 0x800;
    }
    return a < b ? -1 : 1;
  }
  return left.length === right.length ? 0 : left.length < right.length ? -1 : 1;
};

const INDEX = /^(?:0|[1-9][0-9]*)$/;
/**
 * `state.stateRoots`: an array-shaped view (index = position, `length` = event count) whose entries the log computes on
 * first read. Writes store a known root. Iteration and the array methods read through the same `get`.
 */
export function lazyStateRoots(log: RootLog, source: RootSource): ContentHash[] {
  // Only a format-2 state has roots: other formats keep the empty array they always had.
  const length = (): number => (source.format === TRELLIS2_FORMAT ? source.events.length : 0);
  return new Proxy([] as ContentHash[], {
    get(target, property, receiver) {
      if (typeof property === "string" && INDEX.test(property)) return log.rootAt(Number(property));
      if (property === "length") return length();
      return Reflect.get(target, property, receiver);
    },
    set(target, property, value) {
      if (typeof property === "string" && INDEX.test(property)) { log.setKnown(Number(property), value as ContentHash); return true; }
      if (property === "length") return true;
      return Reflect.set(target, property, value);
    },
    has(target, property) {
      if (typeof property === "string" && INDEX.test(property)) return Number(property) < length();
      return Reflect.has(target, property);
    },
    getOwnPropertyDescriptor(target, property) {
      if (typeof property === "string" && INDEX.test(property)) {
        return Number(property) < length() ? { value: log.rootAt(Number(property)), writable: true, enumerable: true, configurable: true } : undefined;
      }
      if (property === "length") return { value: length(), writable: true, enumerable: false, configurable: false };
      return Reflect.getOwnPropertyDescriptor(target, property);
    },
    ownKeys(target) {
      return [...Array.from({ length: length() }, (_v, i) => String(i)), ...Reflect.ownKeys(target)];
    },
  });
}
