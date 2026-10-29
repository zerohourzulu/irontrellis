/**
 * secp256k1 for the legacy scheme `eip191-personal-sign-keccak256` (spec 04 §B).
 *
 * The engine only ever *recovers* public keys (no secret material is handled
 * during verification), so the arithmetic is plain BigInt, not constant-time.
 * Signing (RFC 6979 deterministic ECDSA) exists for tests, tooling and the
 * dev-key path; it reproduces the viem/noble signatures in the spec vectors
 * byte-for-byte because both derive `k` the same way.
 *
 * Points are held in Jacobian coordinates (X, Y, Z) with x = X/Z², y = Y/Z³;
 * infinity is Z = 0. Scalar multiplication uses width-5 wNAF and Shamir's trick
 * (one shared doubling chain for u1·G + u2·R), with the odd multiples of G
 * precomputed lazily in affine form.
 */

import { createHmac } from "node:crypto";
import { keccak256 } from "./keccak.ts";

export const SECP256K1_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
export const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
/** (n − 1) / 2: the largest `s` the legacy scheme accepts (low-s rule). */
export const SECP256K1_HALF_N = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n;
const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

type Point = { x: bigint; y: bigint; z: bigint };
const INFINITY: Point = { x: 1n, y: 1n, z: 0n };
const G: Point = { x: GX, y: GY, z: 1n };

// ---------------------------------------------------------------- hex helpers

const HEX_BYTES = /^(?:0x)?(?:[0-9a-fA-F]{2})*$/;

/** Lowercase hex without prefix. */
export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) out += bytes[i]!.toString(16).padStart(2, "0");
  return out;
}

/** Decodes hex (optional `0x`, any case, even length) or throws a TypeError. */
export function hexToBytes(hex: string): Uint8Array {
  if (!HEX_BYTES.test(hex)) throw new TypeError("expected an even-length hex string");
  // Validated above, so Buffer's lenient decoder cannot silently truncate.
  return Buffer.from(hex.startsWith("0x") ? hex.slice(2) : hex, "hex");
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = 0; i < bytes.length; i += 1) value = (value << 8n) | BigInt(bytes[i]!);
  return value;
}

function bigIntTo32Bytes(value: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let remaining = value;
  for (let i = 31; i >= 0; i -= 1) {
    out[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return out;
}

// ---------------------------------------------------------------- field / scalar arithmetic

function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r < 0n ? r + m : r;
}

/** Modular inverse by extended Euclid (a must be non-zero mod m). */
function invert(a: bigint, m: bigint): bigint {
  let [old, cur] = [mod(a, m), m];
  let [oldS, s] = [1n, 0n];
  while (cur !== 0n) {
    const q = old / cur;
    [old, cur] = [cur, old - q * cur];
    [oldS, s] = [s, oldS - q * s];
  }
  if (old !== 1n) throw new RangeError("not invertible");
  return mod(oldS, m);
}

function powMod(base: bigint, exponent: bigint, m: bigint): bigint {
  let result = 1n;
  let b = mod(base, m);
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

/** Square root mod p (p ≡ 3 mod 4), or undefined when `a` is a non-residue. */
function sqrtMod(a: bigint): bigint | undefined {
  const root = powMod(a, (SECP256K1_P + 1n) >> 2n, SECP256K1_P);
  return (root * root) % SECP256K1_P === mod(a, SECP256K1_P) ? root : undefined;
}

// ---------------------------------------------------------------- Jacobian point arithmetic

const P = SECP256K1_P;

function double(p: Point): Point {
  if (p.z === 0n) return p;
  // dbl-2009-l (a = 0)
  const A = (p.x * p.x) % P;
  const B = (p.y * p.y) % P;
  const C = (B * B) % P;
  const t = (p.x + B) % P;
  const D = mod(2n * (t * t - A - C), P);
  const E = (3n * A) % P;
  const F = (E * E) % P;
  const x = mod(F - 2n * D, P);
  const y = mod(E * (D - x) - 8n * C, P);
  const z = (2n * p.y * p.z) % P;
  return { x, y, z };
}

function add(p: Point, q: Point): Point {
  if (p.z === 0n) return q;
  if (q.z === 0n) return p;
  // add-2007-bl; when q is affine (Z2 = 1, the precomputed base table) the Z2 terms vanish.
  const qAffine = q.z === 1n;
  const Z1Z1 = (p.z * p.z) % P;
  const Z2Z2 = qAffine ? 1n : (q.z * q.z) % P;
  const U1 = qAffine ? p.x : (p.x * Z2Z2) % P;
  const U2 = (q.x * Z1Z1) % P;
  const S1 = qAffine ? p.y : (((p.y * q.z) % P) * Z2Z2) % P;
  const S2 = (((q.y * p.z) % P) * Z1Z1) % P;
  const H = mod(U2 - U1, P);
  const R = mod(S2 - S1, P);
  if (H === 0n) return R === 0n ? double(p) : INFINITY;
  const HH = (H * H) % P;
  const I = (4n * HH) % P;
  const J = (H * I) % P;
  const r2 = (2n * R) % P;
  const V = (U1 * I) % P;
  const x = mod(r2 * r2 - J - 2n * V, P);
  const y = mod(r2 * (V - x) - 2n * S1 * J, P);
  const z = qAffine ? (2n * p.z * H) % P : mod(((p.z + q.z) ** 2n - Z1Z1 - Z2Z2) * H, P);
  return { x, y, z };
}

function negate(p: Point): Point {
  return { x: p.x, y: p.y === 0n ? 0n : P - p.y, z: p.z };
}

function toAffine(p: Point): { x: bigint; y: bigint } | undefined {
  if (p.z === 0n) return undefined;
  const zInv = invert(p.z, P);
  const zInv2 = (zInv * zInv) % P;
  return { x: (p.x * zInv2) % P, y: (((p.y * zInv2) % P) * zInv) % P };
}

// ---------------------------------------------------------------- scalar multiplication (wNAF + Shamir)

const WINDOW = 5;
const WINDOW_SIZE = 1 << WINDOW; // 32
const TABLE_SIZE = 1 << (WINDOW - 1); // 16 odd multiples: 1P, 3P, …, 31P

/** Odd multiples 1P, 3P, …, (2·TABLE_SIZE − 1)P of `p`. */
function oddMultiples(p: Point): Point[] {
  const table: Point[] = [p];
  const twice = double(p);
  for (let i = 1; i < TABLE_SIZE; i += 1) table.push(add(table[i - 1]!, twice));
  return table;
}

let G_TABLE: Point[] | undefined;
function baseTable(): Point[] {
  if (G_TABLE === undefined) {
    // Affine (Z = 1) entries make every addition against the base table a little cheaper.
    G_TABLE = oddMultiples(G).map((p) => {
      const a = toAffine(p)!;
      return { x: a.x, y: a.y, z: 1n };
    });
  }
  return G_TABLE;
}

/** Signed digits in {0, ±1, ±3, …, ±31}, least significant first. */
function wnaf(scalar: bigint): number[] {
  const digits: number[] = [];
  let k = scalar;
  while (k > 0n) {
    if (k & 1n) {
      let digit = Number(k & BigInt(WINDOW_SIZE - 1));
      if (digit > TABLE_SIZE) digit -= WINDOW_SIZE;
      digits.push(digit);
      k -= BigInt(digit);
    } else {
      digits.push(0);
    }
    k >>= 1n;
  }
  return digits;
}

function addDigit(acc: Point, digit: number, table: Point[]): Point {
  if (digit === 0) return acc;
  const entry = table[(Math.abs(digit) - 1) >> 1]!;
  return add(acc, digit > 0 ? entry : negate(entry));
}

/** a·G + b·Q with a single doubling chain. `b`/`q` may be omitted for a plain a·G. */
function multiplyAndAdd(a: bigint, b?: bigint, q?: Point): Point {
  const aDigits = wnaf(mod(a, SECP256K1_N));
  const bDigits = b !== undefined ? wnaf(mod(b, SECP256K1_N)) : [];
  const gTable = baseTable();
  const qTable = q !== undefined && bDigits.length > 0 ? oddMultiples(q) : [];
  let acc = INFINITY;
  for (let i = Math.max(aDigits.length, bDigits.length) - 1; i >= 0; i -= 1) {
    acc = double(acc);
    acc = addDigit(acc, aDigits[i] ?? 0, gTable);
    if (qTable.length > 0) acc = addDigit(acc, bDigits[i] ?? 0, qTable);
  }
  return acc;
}

// ---------------------------------------------------------------- public API

/** True for a private-key scalar in [1, n − 1]. */
export function isValidPrivateKey(scalar: bigint): boolean {
  return scalar > 0n && scalar < SECP256K1_N;
}

/** Uncompressed public key without the 0x04 prefix: X ‖ Y, 64 bytes. */
export function publicKeyFromPrivateKey(privateKey: bigint): Uint8Array {
  if (!isValidPrivateKey(privateKey)) throw new RangeError("private key out of range");
  const affine = toAffine(multiplyAndAdd(privateKey))!;
  return encodePoint(affine);
}

function encodePoint(affine: { x: bigint; y: bigint }): Uint8Array {
  const out = new Uint8Array(64);
  out.set(bigIntTo32Bytes(affine.x), 0);
  out.set(bigIntTo32Bytes(affine.y), 32);
  return out;
}

/** Lowercase `0x` + 40 hex: last 20 bytes of keccak256(X ‖ Y). */
export function addressFromPublicKey(publicKey64: Uint8Array): string {
  return `0x${bytesToHex(keccak256(publicKey64).subarray(12))}`;
}

/**
 * Recovers the public key from a digest and (r, s, recoveryId ∈ {0, 1}) as
 * X ‖ Y (64 bytes), or undefined when r/s are out of range, r is not an
 * x-coordinate on the curve, or the result is the point at infinity.
 * Recovery ids 2/3 (r + n overflow) are deliberately unsupported, as in the
 * legacy engine.
 */
export function recoverPublicKey(digest32: Uint8Array, r: bigint, s: bigint, recoveryId: number): Uint8Array | undefined {
  if (digest32.length !== 32) return undefined;
  if (r <= 0n || r >= SECP256K1_N || s <= 0n || s >= SECP256K1_N) return undefined;
  if (recoveryId !== 0 && recoveryId !== 1) return undefined;
  const ySquared = (((r * r) % P) * r + 7n) % P;
  const root = sqrtMod(ySquared);
  if (root === undefined) return undefined;
  const y = (root & 1n) === BigInt(recoveryId) ? root : P - root;
  const R: Point = { x: r, y, z: 1n };
  const rInv = invert(r, SECP256K1_N);
  const z = mod(bytesToBigInt(digest32), SECP256K1_N);
  const u1 = mod(-z * rInv, SECP256K1_N);
  const u2 = mod(s * rInv, SECP256K1_N);
  const affine = toAffine(multiplyAndAdd(u1, u2, R));
  return affine === undefined ? undefined : encodePoint(affine);
}

/**
 * Recovers the signer's lowercase address from a 32-byte digest and a 65-byte
 * `r ‖ s ‖ v` signature with v ∈ {27, 28}. Range checks on r/s are applied here
 * too; the low-s rule and the hex syntax are the suite's responsibility.
 */
export function recoverAddress(digest32: Uint8Array, signature65: Uint8Array): string | undefined {
  if (signature65.length !== 65) return undefined;
  const v = signature65[64]!;
  if (v !== 27 && v !== 28) return undefined;
  const r = bytesToBigInt(signature65.subarray(0, 32));
  const s = bytesToBigInt(signature65.subarray(32, 64));
  const publicKey = recoverPublicKey(digest32, r, s, v - 27);
  return publicKey === undefined ? undefined : addressFromPublicKey(publicKey);
}

export type CompactSignature = { r: bigint; s: bigint; v: 27 | 28 };

function hmacSha256(key: Uint8Array, ...parts: Uint8Array[]): Uint8Array {
  const h = createHmac("sha256", key);
  for (const part of parts) h.update(part);
  return new Uint8Array(h.digest());
}

/**
 * Deterministic ECDSA (RFC 6979, HMAC-SHA256) over a 32-byte digest, with `s`
 * normalised to the low half and `v` = 27 + parity of R.y. Not constant-time:
 * intended for tests, tooling and local dev keys.
 */
export function signDigest(digest32: Uint8Array, privateKey: bigint): CompactSignature {
  if (digest32.length !== 32) throw new RangeError("digest must be 32 bytes");
  if (!isValidPrivateKey(privateKey)) throw new RangeError("private key out of range");
  const n = SECP256K1_N;
  const z = mod(bytesToBigInt(digest32), n);
  const x = bigIntTo32Bytes(privateKey);
  const h1 = bigIntTo32Bytes(z);
  let K: Uint8Array = new Uint8Array(32);
  let V: Uint8Array = new Uint8Array(32).fill(0x01);
  K = hmacSha256(K, V, Uint8Array.of(0x00), x, h1);
  V = hmacSha256(K, V);
  K = hmacSha256(K, V, Uint8Array.of(0x01), x, h1);
  V = hmacSha256(K, V);
  for (;;) {
    V = hmacSha256(K, V);
    const k = bytesToBigInt(V);
    if (k > 0n && k < n) {
      const R = toAffine(multiplyAndAdd(k));
      if (R !== undefined) {
        const r = R.x % n;
        const s = mod(invert(k, n) * (z + r * privateKey), n);
        if (r !== 0n && s !== 0n) {
          // recovery id 2/3 (R.x ≥ n) cannot be expressed in the legacy encoding.
          if (R.x !== r) throw new RangeError("signature not recoverable with v in {27, 28}");
          const odd = (R.y & 1n) === 1n;
          return s > SECP256K1_HALF_N ? { r, s: n - s, v: odd ? 27 : 28 } : { r, s, v: odd ? 28 : 27 };
        }
      }
    }
    K = hmacSha256(K, V, Uint8Array.of(0x00));
    V = hmacSha256(K, V);
  }
}

/** r ‖ s ‖ v as 65 bytes. */
export function encodeCompactSignature(signature: CompactSignature): Uint8Array {
  const out = new Uint8Array(65);
  out.set(bigIntTo32Bytes(signature.r), 0);
  out.set(bigIntTo32Bytes(signature.s), 32);
  out[64] = signature.v;
  return out;
}
