/**
 * Ed25519 point arithmetic for the format-2 verification profile (addendum A-32, as modified by the G2 ruling).
 *
 * Pure bigint, no dependency: RFC 8032 §5.1.3 point decoding with the canonical-encoding checks (`y < p`, no sign bit
 * set for `x = 0`), extended twisted-Edwards coordinates (RFC 8032 §5.1.4 formulas), scalar multiplication, the
 * small-order test (`[8]A = identity`) and the prime-order-subgroup test (`[L]A = identity`). It is used
 *   - once per declared key (owner keys, session credentials, counterparty keys; A-32.2) — cached per encoding;
 *   - for the verifier's pre-checks (A-32.1: `S < L`, canonical `R` and `A`, `A` not of small order) in `suites.ts`.
 * The exact cofactorless equation `[S]B = R + [k]A` is OpenSSL's (`node:crypto`, ref10's encoded comparison of
 * `[S]B − [k]A` with `R`), checked by the test vectors in `test/g2-rulings.test.mjs` (a mixed-order key with a
 * signature that only a cofactored verifier accepts is refused). `verifyExact` is the same equation in this module, for
 * those tests and as a fallback reference; it is slow (bigint) and never on the replay path.
 */
const P = (1n << 255n) - 19n;
/** The prime order of the base point. */
export const ED25519_L = (1n << 252n) + 27742317777372353535851937790883648493n;
const mod = (a: bigint): bigint => { const r = a % P; return r < 0n ? r + P : r; };
const pow = (base: bigint, exponent: bigint): bigint => {
  let result = 1n, b = mod(base), e = exponent;
  while (e > 0n) { if (e & 1n) result = (result * b) % P; b = (b * b) % P; e >>= 1n; }
  return result;
};
const inv = (a: bigint): bigint => pow(a, P - 2n);
const D = mod(-121665n * inv(121666n));
const SQRT_M1 = pow(2n, (P - 1n) / 4n);

type Point = Readonly<{ X: bigint; Y: bigint; Z: bigint; T: bigint }>;
const IDENTITY: Point = { X: 0n, Y: 1n, Z: 1n, T: 0n };
const add = (p: Point, q: Point): Point => {
  const A = mod((p.Y - p.X) * (q.Y - q.X)), B = mod((p.Y + p.X) * (q.Y + q.X)), C = mod(2n * D * p.T * q.T), Dd = mod(2n * p.Z * q.Z);
  const E = B - A, F = Dd - C, G = Dd + C, H = B + A;
  return { X: mod(E * F), Y: mod(G * H), T: mod(E * H), Z: mod(F * G) };
};
const double = (p: Point): Point => {
  const A = mod(p.X * p.X), B = mod(p.Y * p.Y), C = mod(2n * p.Z * p.Z), H = A + B, E = mod(H - (p.X + p.Y) * (p.X + p.Y)), G = A - B, F = C + G;
  return { X: mod(E * F), Y: mod(G * H), T: mod(E * H), Z: mod(F * G) };
};
const negate = (p: Point): Point => ({ X: mod(-p.X), Y: p.Y, Z: p.Z, T: mod(-p.T) });
const multiply = (p: Point, scalar: bigint): Point => {
  let result = IDENTITY, addend = p, k = scalar;
  while (k > 0n) { if (k & 1n) result = add(result, addend); addend = double(addend); k >>= 1n; }
  return result;
};
const isIdentity = (p: Point): boolean => mod(p.X) === 0n && mod(p.Y - p.Z) === 0n;
const equal = (p: Point, q: Point): boolean => mod(p.X * q.Z - q.X * p.Z) === 0n && mod(p.Y * q.Z - q.Y * p.Z) === 0n;

const littleEndian = (bytes: Uint8Array): bigint => { let v = 0n; for (let i = bytes.length - 1; i >= 0; i -= 1) v = (v << 8n) | BigInt(bytes[i]!); return v; };
const toBytes = (value: bigint, length = 32): Uint8Array => { const out = new Uint8Array(length); let v = value; for (let i = 0; i < length; i += 1) { out[i] = Number(v & 0xffn); v >>= 8n; } return out; };

/** RFC 8032 §5.1.3 decoding; `undefined` for a non-canonical encoding (`y ≥ p`, or the sign bit set with `x = 0`) or a non-point. */
export function decodePoint(bytes: Uint8Array): Point | undefined {
  if (bytes.length !== 32) return undefined;
  const sign = (bytes[31]! >> 7) & 1;
  const yBytes = new Uint8Array(bytes); yBytes[31]! &= 0x7f; // a copy (Buffer#slice would alias the caller's bytes)
  const y = littleEndian(yBytes);
  if (y >= P) return undefined;
  const u = mod(y * y - 1n), v = mod(D * y * y + 1n);
  let x = mod(u * pow(v, 3n) * pow(u * pow(v, 7n), (P - 5n) / 8n));
  const vx2 = mod(v * x * x);
  if (vx2 === mod(-u)) x = mod(x * SQRT_M1);
  else if (vx2 !== u) return undefined;
  if (x === 0n && sign === 1) return undefined;
  if (Number(x & 1n) !== sign) x = mod(-x);
  return { X: x, Y: y, Z: 1n, T: mod(x * y) };
}
export function encodePoint(p: Point): Uint8Array {
  const zi = inv(p.Z), x = mod(p.X * zi), y = mod(p.Y * zi);
  const out = toBytes(y);
  out[31]! |= Number(x & 1n) << 7;
  return out;
}
/** A-32.1: the encoding is canonical — `y < p` and no sign bit for `x = 0` (`y ∈ {1, p − 1}`). Cheap: no square root. */
export function isCanonicalEncoding(bytes: Uint8Array): boolean {
  if (bytes.length !== 32) return false;
  const yBytes = new Uint8Array(bytes); yBytes[31]! &= 0x7f; // a copy (Buffer#slice would alias the caller's bytes)
  const y = littleEndian(yBytes);
  if (y >= P) return false;
  if ((bytes[31]! & 0x80) !== 0 && (y === 1n || y === P - 1n)) return false;
  return true;
}
/** `S < L` for the 32 little-endian bytes of a signature's second half (A-32.1). */
export const scalarIsCanonical = (bytes: Uint8Array): boolean => bytes.length === 32 && littleEndian(bytes) < ED25519_L;

export type KeyCheck = "OK" | "NOT_A_POINT" | "NON_CANONICAL" | "SMALL_ORDER" | "NOT_IN_PRIME_SUBGROUP";
const keyChecks = new Map<string, KeyCheck>();
const KEY_CHECK_CACHE_LIMIT = 8192;
/**
 * A-32.2: a declared Ed25519 key MUST be a canonical encoding of a point that is not of small order and lies in the
 * prime-order subgroup (`[L]A = identity`, one scalar multiplication per declared key, cached by encoding).
 */
export function ed25519KeyCheck(raw: Uint8Array): KeyCheck {
  const id = Buffer.from(raw).toString("hex");
  const known = keyChecks.get(id);
  if (known !== undefined) return known;
  let result: KeyCheck;
  if (!isCanonicalEncoding(raw)) result = "NON_CANONICAL";
  else {
    const point = decodePoint(raw);
    result = point === undefined ? "NOT_A_POINT" : isIdentity(double(double(double(point)))) ? "SMALL_ORDER" : !isIdentity(multiply(point, ED25519_L)) ? "NOT_IN_PRIME_SUBGROUP" : "OK";
  }
  if (keyChecks.size >= KEY_CHECK_CACHE_LIMIT) keyChecks.delete(keyChecks.keys().next().value!);
  keyChecks.set(id, result);
  return result;
}
/** A-32.1 pre-check of a verification key: canonical and not of small order (the subgroup test is the declaration's). */
const verifyKeyChecks = new Map<string, boolean>();
export function verificationKeyAcceptable(raw: Uint8Array): boolean {
  const id = Buffer.from(raw).toString("hex");
  const known = verifyKeyChecks.get(id);
  if (known !== undefined) return known;
  let ok = isCanonicalEncoding(raw);
  if (ok) { const point = decodePoint(raw); ok = point !== undefined && !isIdentity(double(double(double(point)))); }
  if (verifyKeyChecks.size >= KEY_CHECK_CACHE_LIMIT) verifyKeyChecks.delete(verifyKeyChecks.keys().next().value!);
  verifyKeyChecks.set(id, ok);
  return ok;
}

// ---------------------------------------------------------------- reference equation and test helpers (never on the replay path)

const BASE_Y = mod(4n * inv(5n));
export const ED25519_BASE: Point = (() => {
  const point = decodePoint(toBytes(BASE_Y));
  if (point === undefined) throw new Error("ed25519 base point");
  return point;
})();
/** RFC 8032 §5.1.7 cofactorless: `[S]B = R + [k]A` exactly, with `k = SHA-512(R ‖ A ‖ M) mod L`; the pre-checks included. */
export function verifyExact(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array, sha512: (data: Uint8Array) => Uint8Array): boolean {
  if (signature.length !== 64 || publicKey.length !== 32) return false;
  const rBytes = new Uint8Array(signature.subarray(0, 32)), sBytes = new Uint8Array(signature.subarray(32));
  if (!scalarIsCanonical(sBytes) || !isCanonicalEncoding(rBytes) || !isCanonicalEncoding(publicKey)) return false;
  const R = decodePoint(rBytes), A = decodePoint(publicKey);
  if (R === undefined || A === undefined || isIdentity(double(double(double(A))))) return false;
  const k = littleEndian(sha512(new Uint8Array([...rBytes, ...publicKey, ...message]))) % ED25519_L;
  return equal(multiply(ED25519_BASE, littleEndian(sBytes)), add(R, multiply(A, k)));
}
/** Test helpers: point operations on encodings (for constructing the A-32 negatives). */
export const ed25519PointOps = Object.freeze({
  add: (a: Uint8Array, b: Uint8Array): Uint8Array => encodePoint(add(decodePoint(a)!, decodePoint(b)!)),
  multiply: (a: Uint8Array, k: bigint): Uint8Array => encodePoint(multiply(decodePoint(a)!, k)),
  base: (k: bigint): Uint8Array => encodePoint(multiply(ED25519_BASE, k)),
  negate: (a: Uint8Array): Uint8Array => encodePoint(negate(decodePoint(a)!)),
  identity: (): Uint8Array => encodePoint(IDENTITY),
  littleEndian, toBytes,
});
