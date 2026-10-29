/**
 * RFC 6962 / RFC 9162 §2.1 Merkle tree hashing, proofs and proof verification
 * (docs/reference/witness-protocol.md §9.3). SHA-256 throughout.
 *
 *   MTH({})    = SHA-256("")
 *   MTH({d0})  = SHA-256(0x00 || d0)
 *   MTH(D[n])  = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n])), k the largest power of two < n
 *
 * `MerkleTree` keeps every level of perfect (complete, aligned) subtree hashes,
 * so the root, inclusion proofs and consistency proofs of any historical size
 * are computed from O(log n) cached nodes per requested subtree. The verify
 * functions are the iterative algorithms of RFC 9162 §2.1.3.2 and §2.1.4.2;
 * they return false for every malformed input and never throw.
 */
import { createHash } from "node:crypto";

export const MERKLE_HASH_SIZE = 32;

const LEAF_PREFIX = Uint8Array.of(0x00);
const NODE_PREFIX = Uint8Array.of(0x01);

const sha256 = (...parts: readonly Uint8Array[]): Uint8Array => {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return new Uint8Array(hash.digest());
};

const isHash = (value: unknown): value is Uint8Array => value instanceof Uint8Array && value.length === MERKLE_HASH_SIZE;

const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let index = 0; index < a.length; index += 1) diff |= (a[index] as number) ^ (b[index] as number);
  return diff === 0;
};

const isSize = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

/** Exact for every safe integer (no 32-bit bitwise arithmetic). */
const isPowerOfTwo = (n: number): boolean => n > 0 && 2 ** Math.round(Math.log2(n)) === n;

/** Largest power of two strictly less than `n` (n ≥ 2). */
const splitPoint = (n: number): number => {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
};

/** The empty tree hash, SHA-256 of the empty string. */
export function emptyRoot(): Uint8Array {
  return sha256();
}

/** RFC 6962 leaf hash: SHA-256(0x00 || entry). */
export function leafHash(entryBytes: Uint8Array): Uint8Array {
  return sha256(LEAF_PREFIX, entryBytes);
}

/** RFC 6962 interior node hash: SHA-256(0x01 || left || right). */
export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(NODE_PREFIX, left, right);
}

/** MTH over already-hashed leaves (the root of a tree holding exactly these leaves). */
export function rootOf(leafHashes: readonly Uint8Array[]): Uint8Array {
  const tree = new MerkleTree();
  for (const hash of leafHashes) tree.append(hash);
  return tree.root();
}

/**
 * An append-only RFC 6962 tree over leaf hashes. `levels[h][i]` is the hash
 * of the perfect subtree of 2^h leaves starting at leaf i·2^h; a parent is
 * stored as soon as both children exist, so every aligned perfect subtree of
 * any prefix of the tree is available in O(1).
 */
export class MerkleTree {
  readonly #levels: Uint8Array[][];

  constructor() {
    this.#levels = [[]];
  }

  get size(): number {
    return (this.#levels[0] as Uint8Array[]).length;
  }

  /** Appends a 32-byte leaf hash (use `leafHash(entryBytes)`); returns its index. */
  append(hash: Uint8Array): number {
    if (!isHash(hash)) throw new TypeError("MerkleTree.append expects a 32-byte leaf hash");
    const index = this.size;
    let node: Uint8Array = Uint8Array.from(hash);
    let position = index;
    for (let height = 0; ; height += 1) {
      const level = this.#levels[height] ?? (this.#levels[height] = []);
      level.push(node);
      if (position % 2 === 0) break;
      node = nodeHash(level[position - 1] as Uint8Array, node);
      position = (position - 1) / 2;
    }
    return index;
  }

  /** The leaf hash at `index` (a copy). */
  leaf(index: number): Uint8Array {
    this.#checkIndex(index, this.size);
    return Uint8Array.from((this.#levels[0] as Uint8Array[])[index] as Uint8Array);
  }

  /** MTH of the first `size` leaves (default: the whole tree). */
  root(size: number = this.size): Uint8Array {
    this.#checkSize(size);
    return size === 0 ? emptyRoot() : Uint8Array.from(this.#subtree(0, size));
  }

  /** RFC 9162 §2.1.3.1 PATH(index, D[0:size]), leaf to root. */
  inclusionProof(index: number, size: number = this.size): Uint8Array[] {
    this.#checkSize(size);
    this.#checkIndex(index, size);
    const proof: Uint8Array[] = [];
    this.#path(index, 0, size, proof);
    return proof.map((node) => Uint8Array.from(node));
  }

  /** RFC 9162 §2.1.4.1 PROOF(fromSize, D[0:toSize]); empty when fromSize is 0 or equals toSize. */
  consistencyProof(fromSize: number, toSize: number = this.size): Uint8Array[] {
    this.#checkSize(toSize);
    if (!isSize(fromSize) || fromSize > toSize) throw new RangeError(`consistency proof needs 0 <= fromSize <= toSize, got ${String(fromSize)} and ${toSize}`);
    const proof: Uint8Array[] = [];
    if (fromSize > 0 && fromSize < toSize) this.#subproof(fromSize, 0, toSize, true, proof);
    return proof.map((node) => Uint8Array.from(node));
  }

  #checkSize(size: number): void {
    if (!isSize(size) || size > this.size) throw new RangeError(`tree size ${String(size)} is outside 0..${this.size}`);
  }

  #checkIndex(index: number, size: number): void {
    if (!isSize(index) || index >= size) throw new RangeError(`leaf index ${String(index)} is outside 0..${size - 1}`);
  }

  /** MTH(D[start:end]) for a subtree the RFC recursion visits (start aligned to the largest power of two ≤ end − start). */
  #subtree(start: number, end: number): Uint8Array {
    const n = end - start;
    if (isPowerOfTwo(n) && start % n === 0) {
      const height = Math.round(Math.log2(n));
      return (this.#levels[height] as Uint8Array[])[start / n] as Uint8Array;
    }
    const k = splitPoint(n);
    return nodeHash(this.#subtree(start, start + k), this.#subtree(start + k, end));
  }

  #path(index: number, start: number, end: number, out: Uint8Array[]): void {
    const n = end - start;
    if (n <= 1) return;
    const k = splitPoint(n);
    if (index - start < k) {
      this.#path(index, start, start + k, out);
      out.push(this.#subtree(start + k, end));
    } else {
      this.#path(index, start + k, end, out);
      out.push(this.#subtree(start, start + k));
    }
  }

  #subproof(m: number, start: number, end: number, complete: boolean, out: Uint8Array[]): void {
    const n = end - start;
    if (m === n) {
      if (!complete) out.push(this.#subtree(start, end));
      return;
    }
    const k = splitPoint(n);
    if (m <= k) {
      this.#subproof(m, start, start + k, complete, out);
      out.push(this.#subtree(start + k, end));
    } else {
      this.#subproof(m - k, start + k, end, false, out);
      out.push(this.#subtree(start, start + k));
    }
  }
}

/**
 * RFC 9162 §2.1.3.2: true iff `proof` shows the leaf with hash `leaf` at
 * `index` in the tree of `size` leaves with root `root`. Never throws.
 */
export function verifyInclusion(leaf: Uint8Array, index: number, size: number, proof: readonly Uint8Array[], root: Uint8Array): boolean {
  try {
    if (!isHash(leaf) || !isHash(root) || !isSize(index) || !isSize(size) || !Array.isArray(proof)) return false;
    if (index >= size) return false;
    let fn = index;
    let sn = size - 1;
    let r: Uint8Array = leaf;
    for (const p of proof) {
      if (!isHash(p)) return false;
      if (sn === 0) return false;
      if (fn % 2 === 1 || fn === sn) {
        r = nodeHash(p, r);
        if (fn % 2 === 0) {
          while (fn % 2 === 0 && fn !== 0) {
            fn = Math.floor(fn / 2);
            sn = Math.floor(sn / 2);
          }
        }
      } else {
        r = nodeHash(r, p);
      }
      fn = Math.floor(fn / 2);
      sn = Math.floor(sn / 2);
    }
    return sn === 0 && bytesEqual(r, root);
  } catch {
    return false;
  }
}

/**
 * RFC 9162 §2.1.4.2: true iff `proof` shows the tree of `fromSize` leaves with
 * root `fromRoot` is a prefix of the tree of `toSize` leaves with root
 * `toRoot`. Edge cases follow the transparency-dev verifier: fromSize 0 is
 * consistent with anything given an empty proof; equal sizes need equal roots
 * and an empty proof. Never throws.
 */
export function verifyConsistency(fromSize: number, toSize: number, fromRoot: Uint8Array, toRoot: Uint8Array, proof: readonly Uint8Array[]): boolean {
  try {
    if (!isSize(fromSize) || !isSize(toSize) || !isHash(fromRoot) || !isHash(toRoot) || !Array.isArray(proof)) return false;
    if (fromSize > toSize) return false;
    if (fromSize === toSize) return proof.length === 0 && bytesEqual(fromRoot, toRoot);
    if (fromSize === 0) return proof.length === 0;
    if (proof.length === 0) return false;
    for (const p of proof) if (!isHash(p)) return false;
    const path: Uint8Array[] = isPowerOfTwo(fromSize) ? [fromRoot, ...proof] : [...proof];
    let fn = fromSize - 1;
    let sn = toSize - 1;
    while (fn % 2 === 1) {
      fn = Math.floor(fn / 2);
      sn = Math.floor(sn / 2);
    }
    let fr = path[0] as Uint8Array;
    let sr = path[0] as Uint8Array;
    for (let i = 1; i < path.length; i += 1) {
      const c = path[i] as Uint8Array;
      if (sn === 0) return false;
      if (fn % 2 === 1 || fn === sn) {
        fr = nodeHash(c, fr);
        sr = nodeHash(c, sr);
        if (fn % 2 === 0) {
          while (fn % 2 === 0 && fn !== 0) {
            fn = Math.floor(fn / 2);
            sn = Math.floor(sn / 2);
          }
        }
      } else {
        sr = nodeHash(sr, c);
      }
      fn = Math.floor(fn / 2);
      sn = Math.floor(sn / 2);
    }
    return sn === 0 && bytesEqual(fr, fromRoot) && bytesEqual(sr, toRoot);
  } catch {
    return false;
  }
}
