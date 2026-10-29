/**
 * SHA-256 of RFC 6962 interior nodes, `sha256(0x01 ‖ left ‖ right)`, four at a time (E5, BUILD §6).
 *
 * The §7.1 state root hashes one interior node per leaf it recomputes; through `node:crypto` each 65-byte hash costs a
 * call into OpenSSL plus a digest allocation (≈ 0.8–2 µs on the reference box), which is most of an append (an insertion
 * moves every leaf right of it) and of a from-scratch root. This module computes the same function with WebAssembly
 * 128-bit SIMD: four independent messages per lane group, a fully unrolled FIPS 180-4 compression generated below as
 * bytecode (no file to load, no build step), reading the children where they lie contiguous in linear memory.
 * It is SHA-256 itself, not an approximation: the output is checked against `node:crypto` on load (a self-test over
 * fixed vectors and every lane), and the engine falls back to `node:crypto` for every node when WebAssembly SIMD is
 * unavailable or the self-test fails. The tests compare it with `node:crypto` on random inputs, and every root the
 * engine computes with it against the independent `transparency/merkle.ts` implementation.
 *
 * `hashNodes(count, fill, take)`: `fill(i, memory, offset)` writes the 64 child bytes (left ‖ right) of node i at
 * `memory[offset…offset+64)`; `take(i, memory, offset)` reads its 32-byte digest at `memory[offset…offset+32)`.
 */
import { hash as oneShotHash } from "node:crypto";

/** The part of the WebAssembly JS API used here (the engine compiles without DOM typings). */
declare const WebAssembly: {
  validate(bytes: Uint8Array): boolean;
  Module: new (bytes: Uint8Array) => object;
  Instance: new (module: object, imports: object) => { exports: unknown };
} | undefined;

// ---------------------------------------------------------------- the module, generated

const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
const IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

type Bytes = number[];
const uleb = (value: number): Bytes => { const out: Bytes = []; let n = value >>> 0; do { let b = n & 0x7f; n >>>= 7; if (n !== 0) b |= 0x80; out.push(b); } while (n !== 0); return out; };
const sleb = (value: number): Bytes => { const out: Bytes = []; let n = value | 0; for (;;) { const b = n & 0x7f; n >>= 7; if ((n === 0 && (b & 0x40) === 0) || (n === -1 && (b & 0x40) !== 0)) { out.push(b); return out; } out.push(b | 0x80); } };
const splat = (v: number): Bytes => { const b: Bytes = []; for (let lane = 0; lane < 4; lane += 1) b.push(v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff); return b; };
const simd = (op: number): Bytes => [0xfd, ...uleb(op)];
const v128Const = (v: number): Bytes => [...simd(0x0c), ...splat(v)];
const localGet = (i: number): Bytes => [0x20, ...uleb(i)], localSet = (i: number): Bytes => [0x21, ...uleb(i)], localTee = (i: number): Bytes => [0x22, ...uleb(i)];
const globalGet = (i: number): Bytes => [0x23, ...uleb(i)], globalSet = (i: number): Bytes => [0x24, ...uleb(i)];
const i32Const = (n: number): Bytes => [0x41, ...sleb(n)];
const I32_ADD = 0x6a, I32_SUB = 0x6b, I32_EQZ = 0x45, CALL = 0x10, BLOCK = 0x02, LOOP = 0x03, BR = 0x0c, BR_IF = 0x0d, END = 0x0b, VOID = 0x40, V128 = 0x7b, I32 = 0x7f;
const SHL = simd(0xab), SHR_U = simd(0xad), ADD = simd(0xae), AND = simd(0x4e), OR = simd(0x50), XOR = simd(0x51), BITSELECT = simd(0x52);
/** i8x16.shuffle reversing the bytes of every 32-bit lane (the big-endian words of SHA-256). */
const BSWAP = [...simd(0x0d), 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12];
const loadLane = (offset: number, lane: number): Bytes => [...simd(0x56), 0, ...uleb(offset), lane];
const storeLane = (offset: number, lane: number): Bytes => [...simd(0x5a), 0, ...uleb(offset), lane];
const rotr = (x: number, n: number): Bytes => [...localGet(x), ...i32Const(n), ...SHR_U, ...localGet(x), ...i32Const(32 - n), ...SHL, ...OR];
const shr = (x: number, n: number): Bytes => [...localGet(x), ...i32Const(n), ...SHR_U];

/**
 * Memory layout: the children of the nodes of one call lie contiguous, 64 bytes per node (left ‖ right), starting one
 * byte after CHILDREN_AT; the digests follow at DIGESTS_AT, 32 bytes per node. A node's message is 0x01 ‖ children,
 * so word t (t ≥ 1) of its first block is the big-endian load of children[4t−1 … 4t+2], word 0 the load of the byte
 * before the children and children[0…2] with its top byte replaced by 0x01; its second block is children[63] ‖ 0x80 ‖
 * 0^52 ‖ be64(520): word 0 = children[63] << 24 | 0x00800000, words 1…14 zero, word 15 = 520.
 */
const LANES = 4, NODE_BYTES = 64, GROUP_IN = NODE_BYTES * LANES, GROUP_OUT = 32 * LANES;
type WordSource = (t: number) => Bytes;
const loadWords = (offset: number, tmp: number, fix?: Readonly<{ keep: number; set: number }>): Bytes => {
  const out: Bytes = [...localGet(0), ...v128Const(0), ...loadLane(offset, 0), ...localSet(tmp)];
  for (let lane = 1; lane < LANES; lane += 1) out.push(...localGet(0), ...localGet(tmp), ...loadLane(offset + NODE_BYTES * lane, lane), ...localSet(tmp));
  out.push(...localGet(tmp), ...localGet(tmp), ...BSWAP);
  if (fix !== undefined) out.push(...v128Const(fix.keep), ...AND, ...v128Const(fix.set), ...OR);
  return out;
};
const FIRST_BLOCK: WordSource = (t) => (t === 0 ? loadWords(0, 25, { keep: 0x00ffffff, set: 0x01000000 }) : loadWords(4 * t, 25));
const SECOND_BLOCK: WordSource = (t) => (t === 0 ? loadWords(64, 25, { keep: 0xff000000 | 0, set: 0x00800000 }) : v128Const(t === 15 ? 520 : 0));

/**
 * compress(p): one block of four messages into the state held in globals 0…7 (`words(t)` leaves word t of every lane on
 * the stack; p, local 0, is the byte before lane 0's children). Locals: 1…16 = the rolling message schedule, 17…24 = the
 * working variables (renamed each round instead of moved), 25 = scratch.
 */
function compressBody(words: WordSource): Bytes {
  const w = (t: number): number => 1 + (t % 16);
  const out: Bytes = [];
  let v = [17, 18, 19, 20, 21, 22, 23, 24];
  for (let i = 0; i < 8; i += 1) out.push(...globalGet(i), ...localSet(v[i]!));
  for (let t = 0; t < 64; t += 1) {
    if (t < 16) out.push(...words(t), ...localSet(w(t)));
    else {
      const w2 = w(t - 2), w15 = w(t - 15);
      out.push(...rotr(w2, 17), ...rotr(w2, 19), ...XOR, ...shr(w2, 10), ...XOR, ...localGet(w(t - 7)), ...ADD);
      out.push(...rotr(w15, 7), ...rotr(w15, 18), ...XOR, ...shr(w15, 3), ...XOR, ...ADD, ...localGet(w(t - 16)), ...ADD, ...localSet(w(t)));
    }
    const [a, b, c, d, e, f, g, h] = v as [number, number, number, number, number, number, number, number];
    // T1 = h + Σ1(e) + Ch(e, f, g) + K[t] + W[t], kept in h's local.
    out.push(...localGet(h), ...rotr(e, 6), ...rotr(e, 11), ...XOR, ...rotr(e, 25), ...XOR, ...ADD);
    out.push(...localGet(f), ...localGet(g), ...localGet(e), ...BITSELECT, ...ADD, ...v128Const(K[t]!), ...ADD, ...localGet(w(t)), ...ADD, ...localSet(h));
    // e' = d + T1 (d's local); a' = T1 + Σ0(a) + Maj(a, b, c) (h's local); Maj(a, b, c) = bitselect(c, a, a ^ b).
    out.push(...localGet(d), ...localGet(h), ...ADD, ...localSet(d));
    out.push(...localGet(h), ...rotr(a, 2), ...rotr(a, 13), ...XOR, ...rotr(a, 22), ...XOR, ...ADD);
    out.push(...localGet(c), ...localGet(a), ...localGet(a), ...localGet(b), ...XOR, ...BITSELECT, ...ADD, ...localSet(h));
    v = [h, a, b, c, d, e, f, g];
  }
  for (let i = 0; i < 8; i += 1) out.push(...globalGet(i), ...localGet(v[i]!), ...ADD, ...globalSet(i));
  return out;
}
/** group(src, dst): four nodes (children from src + 1) → four digests (32 bytes each from dst). Locals: 0 = src, 1 = dst, 2 = scratch. */
function groupBody(): Bytes {
  const out: Bytes = [];
  for (let i = 0; i < 8; i += 1) out.push(...v128Const(IV[i]!), ...globalSet(i));
  out.push(...localGet(0), CALL, ...uleb(0), ...localGet(0), CALL, ...uleb(1));
  for (let i = 0; i < 8; i += 1) {
    out.push(...globalGet(i), ...localTee(2), ...localGet(2), ...BSWAP, ...localSet(2));
    for (let lane = 0; lane < LANES; lane += 1) out.push(...localGet(1), ...localGet(2), ...storeLane(32 * lane + 4 * i, lane));
  }
  return out;
}
/** run(src, dst, groups): `groups` consecutive groups. */
const runBody = (): Bytes => [
  BLOCK, VOID, LOOP, VOID,
  ...localGet(2), I32_EQZ, BR_IF, 1,
  ...localGet(0), ...localGet(1), CALL, ...uleb(2),
  ...localGet(0), ...i32Const(GROUP_IN), I32_ADD, ...localSet(0),
  ...localGet(1), ...i32Const(GROUP_OUT), I32_ADD, ...localSet(1),
  ...localGet(2), ...i32Const(1), I32_SUB, ...localSet(2),
  BR, 0, END, END,
];
const section = (id: number, bytes: Bytes): Bytes => [id, ...uleb(bytes.length), ...bytes];
const vector = (items: readonly Bytes[]): Bytes => [...uleb(items.length), ...items.flat()];
const body = (locals: readonly Bytes[], code: Bytes): Bytes => { const b = [...vector(locals), ...code, END]; return [...uleb(b.length), ...b]; };
const name = (text: string): Bytes => [...uleb(text.length), ...[...text].map((c) => c.charCodeAt(0))];

/** Nodes per call. CHILDREN_AT + 1 is where node 0's children go; the second block's load reads 4 bytes past the last node. */
export const NODE_CHUNK = 1024;
const CHILDREN_AT = 0, DIGESTS_AT = NODE_CHUNK * NODE_BYTES + 64, PAGES = 2;
function moduleBytes(): Uint8Array {
  const types = vector([[0x60, ...vector([[I32]]), 0x00], [0x60, ...vector([[I32], [I32]]), 0x00], [0x60, ...vector([[I32], [I32], [I32]]), 0x00]]);
  const functions = vector([[0], [0], [1], [2]]);
  const memory = vector([[0x00, ...uleb(PAGES)]]);
  const globals = vector(Array.from({ length: 8 }, () => [V128, 0x01, ...v128Const(0), END]));
  const exports = vector([[...name("memory"), 0x02, 0], [...name("run"), 0x00, 3]]);
  const code = vector([body([[25, V128]], compressBody(FIRST_BLOCK)), body([[25, V128]], compressBody(SECOND_BLOCK)), body([[1, V128]], groupBody()), body([], runBody())]);
  return new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, ...section(1, types), ...section(3, functions), ...section(5, memory), ...section(6, globals), ...section(7, exports), ...section(10, code)]);
}

// ---------------------------------------------------------------- the two engines

/** `run(n)`: the digests of nodes 0…n−1 whose children are at `children + 64i` into `digests + 32i` (n ≤ NODE_CHUNK). */
export type NodeEngine = Readonly<{ memory: Buffer; children: number; digests: number; run: (count: number) => void; kind: "wasm-simd" | "node-crypto" }>;
const NODE = Buffer.alloc(65);
NODE[0] = 1;
const nativeEngine = (): NodeEngine => {
  const memory = Buffer.alloc(DIGESTS_AT + NODE_CHUNK * 32);
  return Object.freeze({
    memory, children: CHILDREN_AT + 1, digests: DIGESTS_AT, kind: "node-crypto" as const,
    run(count: number) {
      for (let i = 0; i < count; i += 1) {
        memory.copy(NODE, 1, CHILDREN_AT + 1 + NODE_BYTES * i, CHILDREN_AT + 1 + NODE_BYTES * (i + 1));
        memory.write(oneShotHash("sha256", NODE, "binary"), DIGESTS_AT + 32 * i, 32, "binary");
      }
    },
  });
};
const wasmEngine = (): NodeEngine | undefined => {
  try {
    const bytes = moduleBytes();
    const wasm = typeof WebAssembly === "undefined" ? undefined : WebAssembly;
    if (wasm === undefined || !wasm.validate(bytes)) return undefined;
    const instance = new wasm.Instance(new wasm.Module(bytes), {});
    const exports = instance.exports as { memory: { buffer: ArrayBuffer }; run: (src: number, dst: number, groups: number) => void };
    const memory = Buffer.from(exports.memory.buffer, 0, exports.memory.buffer.byteLength); // the memory never grows: the view stays valid
    return Object.freeze({ memory, children: CHILDREN_AT + 1, digests: DIGESTS_AT, kind: "wasm-simd" as const, run(count: number) { exports.run(CHILDREN_AT, DIGESTS_AT, Math.ceil(count / LANES)); } });
  } catch {
    return undefined;
  }
};
/** The self-test: a full chunk and a partial group against `node:crypto`, every lane. */
const passes = (engine: NodeEngine): boolean => {
  for (const count of [NODE_CHUNK, 5]) {
    for (let i = 0; i < count * NODE_BYTES; i += 1) engine.memory[engine.children + i] = (i * 131 + count) & 0xff;
    engine.run(count);
    for (let i = 0; i < count; i += 1) {
      const expected = oneShotHash("sha256", Buffer.concat([Buffer.from([1]), engine.memory.subarray(engine.children + NODE_BYTES * i, engine.children + NODE_BYTES * (i + 1))]), "buffer");
      if (!expected.equals(engine.memory.subarray(engine.digests + 32 * i, engine.digests + 32 * (i + 1)))) return false;
    }
  }
  return true;
};
let engine: NodeEngine | undefined;
/** The engine in use: WebAssembly SIMD when available and correct, else `node:crypto`. */
export const nodeEngine = (): NodeEngine => {
  if (engine === undefined) {
    const simd = wasmEngine();
    engine = simd !== undefined && passes(simd) ? simd : nativeEngine();
  }
  return engine;
};
/** Which implementation hashes the nodes (`wasm-simd`, or `node-crypto` when SIMD is unavailable or failed its self-test). */
export const nodeHasherKind = (): NodeEngine["kind"] => nodeEngine().kind;
/** Test hook: force the `node:crypto` engine (`true`), or return to the default choice (`false`). */
export const useNodeCryptoForTests = (force: boolean): void => { engine = force ? nativeEngine() : undefined; };

/** `sha256(0x01 ‖ children(i))` for i in [0, count): `fill` writes node i's 64 child bytes, `take` reads its digest. */
export function hashNodes(count: number, fill: (i: number, memory: Buffer, offset: number) => void, take: (i: number, memory: Buffer, offset: number) => void): void {
  const e = nodeEngine();
  for (let from = 0; from < count; from += NODE_CHUNK) {
    const n = Math.min(NODE_CHUNK, count - from);
    for (let i = 0; i < n; i += 1) fill(from + i, e.memory, e.children + NODE_BYTES * i);
    e.run(n);
    for (let i = 0; i < n; i += 1) take(from + i, e.memory, e.digests + 32 * i);
  }
}
