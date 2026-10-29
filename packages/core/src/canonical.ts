/**
 * Canonical encoding (`continuity-canonical/0.2`, shared by both history formats).
 *
 * The canonical text is compact JSON with record keys sorted in UTF-8 byte
 * order, integers only, and bigints spelled as `{"$continuity.bigint":"<decimal>"}`.
 * `canonicalEncode` must be byte-identical to the Continuity 0.2 reference for
 * every value the reference accepts, and must reject exactly the values it
 * rejects (spec 01 §A). `captureValue` performs the same validation but returns
 * a frozen deep copy with bigint markers decoded, which the engine treats as
 * immutable from then on.
 *
 * Both walkers are written for speed: one pass per string (validation, byte
 * count and escape detection together), no per-node location strings (a path
 * stack is only formatted when an error is thrown), no memoisation (aliases
 * are simply re-encoded; the output and the depth/byte accounting are the same
 * as the reference's memoised capture).
 */
import type { Amount, ContentHash, U53 } from "./types.ts";

export const LIMITS = Object.freeze({
  maxStringBytes: 4096,
  maxIdentifierBytes: 256,
  maxRecordKeys: 256,
  maxListMembers: 4096,
  maxDepth: 32,
  maxTotalBytes: 16_777_216,
} as const);

const MAX_PROTOCOL_BIGINT = (1n << 256n) - 1n;
const BIGINT_MARKER_KEY = "$continuity.bigint";
export const RESERVED_KEY_PREFIX = "$continuity.";
const MARKER_DECIMAL = /^(?:0|-?[1-9][0-9]*)$/;
const MARKER_PREFIX_TEXT = `{"${BIGINT_MARKER_KEY}":"`; // + decimal + `"}`

/** Thrown for every canonical rejection. `limit` marks size/depth/count overruns. */
export class CanonicalError extends Error {
  readonly reason: string;
  readonly limit: boolean;
  readonly location: string;
  constructor(reason: string, location = "$", limit = false) {
    super(reason);
    this.name = "CanonicalError";
    this.reason = reason;
    this.location = location;
    this.limit = limit;
  }
}

// ---------------------------------------------------------------- strings

/**
 * Scans a string once: rejects lone surrogates and overruns of the raw UTF-8
 * byte bound, returns the byte length of the *escaped* canonical spelling
 * (without quotes) and reports via `scan.escape` whether escaping is needed
 * (`"`, `\` or a C0 control).
 */
const scan = { escape: false };

/** `scanUtf8` results for a refused string (the first problem met, scanning left to right). */
const LONE_SURROGATE = -1;
const TOO_LONG = -2;

/**
 * The scan without the throw: the escaped byte length, or `LONE_SURROGATE` / `TOO_LONG`. Callers format the error
 * location only when they need it, so the hot path allocates nothing (no location closure per string).
 */
function scanUtf8(value: string, maximum: number): number {
  let bytes = 0;
  let extra = 0;
  const length = value.length;
  for (let index = 0; index < length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit < 0x80) {
      bytes += 1;
      if (unit < 0x20) extra += 5;
      else if (unit === 0x22 || unit === 0x5c) extra += 1;
    } else if (unit < 0x800) {
      bytes += 2;
    } else if (unit >= 0xd800 && unit <= 0xdfff) {
      const next = unit <= 0xdbff ? value.charCodeAt(index + 1) : 0;
      if (!(next >= 0xdc00 && next <= 0xdfff)) return LONE_SURROGATE;
      bytes += 4;
      index += 1;
    } else {
      bytes += 3;
    }
    if (bytes > maximum) return TOO_LONG;
  }
  scan.escape = extra !== 0;
  return bytes + extra;
}

function stringError(problem: number, maximum: number, location: string): CanonicalError {
  return problem === LONE_SURROGATE
    ? new CanonicalError(`Canonical string at ${location} is not well-formed Unicode.`, location)
    : new CanonicalError(`Canonical string at ${location} exceeds the ${maximum}-byte ProtocolString bound.`, location, true);
}

function scanString(value: string, maximum: number, location: () => string): number {
  const bytes = scanUtf8(value, maximum);
  if (bytes < 0) throw stringError(bytes, maximum, location());
  return bytes;
}

const HEX2 = Array.from({ length: 32 }, (_, unit) => unit.toString(16).padStart(2, "0"));

/** Only `"`, `\` and U+0000..U+001F are escaped (lowercase `\u00xx`); everything else is raw. */
function escapeString(value: string): string {
  let out = '"';
  let start = 0;
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0x20 && unit !== 0x22 && unit !== 0x5c) continue;
    if (start < index) out += value.slice(start, index);
    out += unit === 0x22 ? '\\"' : unit === 0x5c ? "\\\\" : `\\u00${HEX2[unit]}`;
    start = index + 1;
  }
  return `${out}${start < value.length ? value.slice(start) : ""}"`;
}

/** Quick well-formedness + byte-length probe without throwing (used by the predicates). */
function utf8Length(value: string, maximum: number): number | undefined {
  if (value.length > maximum) return undefined;
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit < 0x80) bytes += 1;
    else if (unit < 0x800) bytes += 2;
    else if (unit >= 0xd800 && unit <= 0xdfff) {
      const next = unit <= 0xdbff ? value.charCodeAt(index + 1) : 0;
      if (!(next >= 0xdc00 && next <= 0xdfff)) return undefined;
      bytes += 4;
      index += 1;
    } else bytes += 3;
    if (bytes > maximum) return undefined;
  }
  return bytes;
}

/**
 * Code-point order on well-formed strings, computed on UTF-16 code units.
 * Surrogates (astral code points) must sort after U+E000..U+FFFF, so the two
 * ranges are swapped before comparing when either unit lies in them.
 */
function compareWellFormed(left: string, right: string): number {
  const shared = left.length < right.length ? left.length : right.length;
  for (let index = 0; index < shared; index += 1) {
    let a = left.charCodeAt(index);
    let b = right.charCodeAt(index);
    if (a === b) continue;
    if (a >= 0xd800 || b >= 0xd800) {
      if (a >= 0xd800 && a <= 0xdfff) a += 0x2000;
      else if (a >= 0xe000) a -= 0x800;
      if (b >= 0xd800 && b <= 0xdfff) b += 0x2000;
      else if (b >= 0xe000) b -= 0x800;
    }
    return a < b ? -1 : 1;
  }
  return left.length < right.length ? -1 : left.length > right.length ? 1 : 0;
}

/** UTF-8 byte order (spec 01 A.1). Validates both arguments; returns -1, 0 or 1. */
export function compareProtocolStrings(a: string, b: string): number {
  scanString(a, LIMITS.maxStringBytes, () => "$left");
  scanString(b, LIMITS.maxStringBytes, () => "$right");
  return compareWellFormed(a, b);
}

// ---------------------------------------------------------------- walker context

type Context = {
  bytes: number;
  readonly maxBytes: number;
  readonly maxDepth: number;
  /** Keys / indices from the root to the node being processed; formatted only on error. */
  readonly path: (string | number)[];
  /** Containers currently being walked (cycle detection; bounded by maxDepth). */
  readonly active: object[];
};

function createContext(maxBytes: number, maxDepth: number): Context {
  return { bytes: 0, maxBytes, maxDepth, path: [], active: [] };
}

function locationOf(context: Context): string {
  let text = "$";
  for (const segment of context.path) text += typeof segment === "number" ? `[${segment}]` : `.${segment}`;
  return text;
}

function charge(context: Context, bytes: number): void {
  context.bytes += bytes;
  if (context.bytes > context.maxBytes) {
    throw new CanonicalError(
      `Canonical value at $ exceeds the ${context.maxBytes}-byte canonical capture bound.`,
      "$",
      true,
    );
  }
}

function depthError(context: Context): CanonicalError {
  const location = locationOf(context);
  return new CanonicalError(
    `Canonical value at ${location} exceeds nesting depth ${context.maxDepth}.`,
    location,
    true,
  );
}

function decimalLength(value: number): number {
  let digits = value < 0 ? 2 : 1;
  let magnitude = value < 0 ? -value : value;
  while (magnitude >= 10) {
    magnitude = Math.floor(magnitude / 10);
    digits += 1;
  }
  return digits;
}

// ---------------------------------------------------------------- scalar checks

function checkNumber(value: number, context: Context): void {
  if (!Number.isSafeInteger(value) || (value === 0 && 1 / value < 0)) {
    const location = locationOf(context);
    throw new CanonicalError(
      Number.isFinite(value)
        ? `Canonical number at ${location} must be a signed safe integer other than negative zero.`
        : `Canonical number at ${location} must be finite.`,
      location,
    );
  }
}

function checkBigInt(value: bigint, context: Context): void {
  if (value < -MAX_PROTOCOL_BIGINT || value > MAX_PROTOCOL_BIGINT) {
    const location = locationOf(context);
    throw new CanonicalError(`Canonical BigInt at ${location} exceeds the 256-bit protocol bound.`, location, true);
  }
}

function checkString(value: string, context: Context): number {
  const bytes = scanUtf8(value, LIMITS.maxStringBytes);
  if (bytes < 0) throw stringError(bytes, LIMITS.maxStringBytes, locationOf(context));
  return bytes;
}

/**
 * Record keys already validated: escaped byte length × 2, plus 1 when the key needs escaping. The result of the scan
 * depends on the key's text alone, and protocol records reuse a few hundred keys, so each is scanned once per process
 * instead of twice per record (validation, then encoding). Bounded: short keys only, and at most `KEY_INFO_LIMIT`.
 * When full it is cleared and refilled: in a long-lived process (the witness server, the gateway),
 * keys first seen early, attacker-chosen ones included, can no longer occupy it for good; the protocol's own keys
 * come back on their next use.
 */
const KEY_INFO = new Map<string, number>();
const KEY_INFO_LIMIT = 4096;
const KEY_INFO_MAX_LENGTH = 128;

function keyInfo(key: string, context: Context): number {
  const known = KEY_INFO.get(key);
  if (known !== undefined) return known;
  const bytes = scanUtf8(key, LIMITS.maxStringBytes);
  if (bytes < 0) throw stringError(bytes, LIMITS.maxStringBytes, `${locationOf(context)}.{key}`);
  const info = bytes * 2 + (scan.escape ? 1 : 0);
  if (key.length <= KEY_INFO_MAX_LENGTH) {
    if (KEY_INFO.size >= KEY_INFO_LIMIT) KEY_INFO.clear();
    KEY_INFO.set(key, info);
  }
  return info;
}

function unsupported(value: unknown, context: Context): CanonicalError {
  const location = locationOf(context);
  if (value === undefined) return new CanonicalError(`Canonical value at ${location} is undefined.`, location);
  return new CanonicalError(`Canonical value at ${location} has unsupported type ${typeof value}.`, location);
}

/** Decodes the value of a `$continuity.bigint` marker with the strict grammar. */
function parseMarker(value: unknown, context: Context): bigint {
  if (typeof value !== "string" || value.length > 79 || !MARKER_DECIMAL.test(value)) {
    const location = `${locationOf(context)}.${BIGINT_MARKER_KEY}`;
    throw new CanonicalError(`Canonical BigInt marker at ${location} has an invalid decimal value.`, location);
  }
  const parsed = BigInt(value);
  if (parsed < -MAX_PROTOCOL_BIGINT || parsed > MAX_PROTOCOL_BIGINT) {
    const location = `${locationOf(context)}.${BIGINT_MARKER_KEY}`;
    throw new CanonicalError(`Canonical BigInt at ${location} exceeds the 256-bit protocol bound.`, location, true);
  }
  return parsed;
}

// ---------------------------------------------------------------- container checks

/**
 * Validates a record's shape and returns its own keys in canonical order, or
 * `null` when the record is the exact bigint marker shape. Every own key
 * (including symbol keys and keys with undefined values) is checked, as in the
 * reference, in the reference's order (spec 01 §A.6): each key is a string and a
 * ProtocolString, then the reserved `$continuity.` prefix rule, then the depth.
 */
function recordKeys(value: object, context: Context): string[] | null {
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    const location = locationOf(context);
    throw new CanonicalError(`Canonical value at ${location} is not a plain record.`, location);
  }
  const keys = Reflect.ownKeys(value) as string[];
  const count = keys.length;
  if (count > LIMITS.maxRecordKeys) {
    const location = locationOf(context);
    throw new CanonicalError(
      `Canonical record at ${location} exceeds the ${LIMITS.maxRecordKeys}-field bound.`,
      location,
      true,
    );
  }
  let reserved = false;
  let sorted = true;
  for (let index = 0; index < count; index += 1) {
    const key = keys[index] as PropertyKey;
    if (typeof key !== "string") {
      const location = locationOf(context);
      throw new CanonicalError(`Canonical record at ${location} has a non-string key.`, location);
    }
    // Spec 01 §A.6 step 3, as the reference: every key is a ProtocolString (reported at `<record>.{key}`) before the
    // reserved-prefix rule, the depth bound and any field, whatever the key order. (The first error decides the
    // replay code; checking keys only when they needed sorting reported a later field's defect first.)
    keyInfo(key, context);
    if (key.charCodeAt(0) === 0x24 && key.startsWith(RESERVED_KEY_PREFIX)) reserved = true;
    if (sorted && index > 0 && compareWellFormed(keys[index - 1] as string, key) >= 0) sorted = false;
  }
  if (reserved) {
    if (count !== 1 || keys[0] !== BIGINT_MARKER_KEY) {
      const location = locationOf(context);
      throw new CanonicalError(
        `Canonical record at ${location} uses the reserved ${RESERVED_KEY_PREFIX} key prefix outside the exact BigInt marker shape.`,
        location,
      );
    }
    return null;
  }
  if (context.active.length >= context.maxDepth) throw depthError(context);
  return sorted ? keys : keys.sort(compareWellFormed);
}

/**
 * Validates an array's shape: at most `maximum` members (when given), own keys
 * exactly `length` plus the indices `0..length-1` (no holes, no expandos, no
 * symbol keys). Exported for the history hasher, which checks the event list
 * itself without encoding it as one value.
 */
export function checkDenseArray(value: readonly unknown[], location: string | (() => string), maximum?: number): number {
  const where = (): string => (typeof location === "string" ? location : location());
  const length = value.length;
  if (maximum !== undefined && length > maximum) {
    throw new CanonicalError(`Canonical array at ${where()} exceeds the ${maximum}-member bound.`, where(), true);
  }
  const keys = Reflect.ownKeys(value);
  // Array own keys enumerate as ascending indices, then "length" (created
  // first among the non-index keys), then expandos, then symbols. So a dense,
  // expando-free array has exactly length+1 keys with "length" last.
  if (keys.length !== length + 1 || keys[length] !== "length") {
    for (const key of keys) {
      if (typeof key !== "string") throw new CanonicalError(`Canonical array at ${where()} has a symbol key.`, where());
      if (key !== "length" && !isArrayIndex(key)) {
        throw new CanonicalError(`Canonical array at ${where()} has an unsupported expando field ${key}.`, where());
      }
    }
    throw new CanonicalError(`Canonical array at ${where()} is sparse.`, where());
  }
  for (let index = 0; index < length; index += 1) {
    const key = keys[index] as string;
    if (key.length === 1 ? key.charCodeAt(0) - 48 !== index : key !== String(index)) {
      throw new CanonicalError(`Canonical array at ${where()} is sparse.`, where());
    }
  }
  return length;
}

function checkArray(value: readonly unknown[], context: Context): number {
  if (context.active.length >= context.maxDepth) throw depthError(context);
  return checkDenseArray(value, () => locationOf(context), LIMITS.maxListMembers);
}

function isArrayIndex(key: string): boolean {
  if (key === "0") return true;
  if (!/^[1-9][0-9]*$/.test(key)) return false;
  const value = Number(key);
  return value <= 0xffff_fffe && String(value) === key;
}

function undefinedEntry(index: number, context: Context): CanonicalError {
  const location = `${locationOf(context)}[${index}]`;
  return new CanonicalError(`Canonical array entry at ${location} is undefined.`, location);
}

function cycleError(context: Context): CanonicalError {
  const location = locationOf(context);
  return new CanonicalError(`Canonical value at ${location} contains an active cycle.`, location);
}

// ---------------------------------------------------------------- encoder

function encodeNode(value: unknown, context: Context): string {
  switch (typeof value) {
    case "string": {
      const bytes = checkString(value, context);
      charge(context, bytes + 2);
      return scan.escape ? escapeString(value) : `"${value}"`;
    }
    case "number": {
      checkNumber(value, context);
      const text = String(value);
      charge(context, text.length);
      return text;
    }
    case "boolean":
      charge(context, value ? 4 : 5);
      return value ? "true" : "false";
    case "bigint": {
      checkBigInt(value, context);
      const text = `${MARKER_PREFIX_TEXT}${value.toString()}"}`;
      charge(context, text.length);
      return text;
    }
    case "object": {
      if (value === null) {
        charge(context, 4);
        return "null";
      }
      if (context.active.includes(value)) throw cycleError(context);
      return Array.isArray(value) ? encodeArray(value, context) : encodeRecord(value, context);
    }
    default:
      throw unsupported(value, context);
  }
}

function encodeArray(value: readonly unknown[], context: Context): string {
  const length = checkArray(value, context);
  charge(context, length === 0 ? 2 : length + 1);
  context.active.push(value);
  let out = "[";
  for (let index = 0; index < length; index += 1) {
    const entry = value[index];
    if (entry === undefined) throw undefinedEntry(index, context);
    context.path.push(index);
    const text = encodeNode(entry, context);
    context.path.pop();
    out += index === 0 ? text : `,${text}`;
  }
  context.active.pop();
  return `${out}]`;
}

function encodeRecord(value: object, context: Context): string {
  const keys = recordKeys(value, context);
  if (keys === null) {
    const decimal = parseMarker((value as Record<string, unknown>)[BIGINT_MARKER_KEY], context);
    const text = `${MARKER_PREFIX_TEXT}${decimal.toString()}"}`;
    charge(context, text.length);
    return text;
  }
  charge(context, 2);
  context.active.push(value);
  let out = "{";
  let members = 0;
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index] as string;
    // The key must be a ProtocolString even when its value is undefined (and omitted).
    const info = keyInfo(key, context);
    const keyBytes = info >>> 1;
    const field = (value as Record<string, unknown>)[key];
    if (field === undefined) continue;
    const keyText = (info & 1) === 1 ? escapeString(key) : `"${key}"`;
    charge(context, keyBytes + (members === 0 ? 3 : 4));
    context.path.push(key);
    const text = encodeNode(field, context);
    context.path.pop();
    out += members === 0 ? `${keyText}:${text}` : `,${keyText}:${text}`;
    members += 1;
  }
  context.active.pop();
  return `${out}}`;
}

export type CanonicalEncodeOptions = Readonly<{
  /** Containers already open around `value` (the history hasher encodes events at depth 2). */
  ancestorDepth?: number;
  /** Canonical byte budget for this call; clamped to `LIMITS.maxTotalBytes`. */
  maxTotalBytes?: number;
}>;

function budgetOf(maxTotalBytes: number | undefined): number {
  if (maxTotalBytes === undefined) return LIMITS.maxTotalBytes;
  if (!Number.isSafeInteger(maxTotalBytes) || maxTotalBytes < 0) {
    throw new CanonicalError("maxTotalBytes must be a nonnegative safe integer.");
  }
  return Math.min(maxTotalBytes, LIMITS.maxTotalBytes);
}

function depthOf(maxDepth: number | undefined): number {
  if (maxDepth === undefined) return LIMITS.maxDepth;
  if (!Number.isSafeInteger(maxDepth) || maxDepth < 0) {
    throw new CanonicalError("maxDepth must be a nonnegative safe integer.");
  }
  return Math.min(maxDepth, LIMITS.maxDepth);
}

/** Exact `continuity-canonical/0.2` text (no whitespace, no trailing newline). Throws CanonicalError. */
export function canonicalEncode(value: unknown, options?: CanonicalEncodeOptions): string {
  const context = createContext(budgetOf(options?.maxTotalBytes), LIMITS.maxDepth);
  const ancestors = options?.ancestorDepth ?? 0;
  // Ancestor containers count against the depth but are not on the cycle stack.
  for (let index = 0; index < ancestors; index += 1) context.active.push(context);
  return encodeNode(value, context);
}

// ---------------------------------------------------------------- capture

function captureNode(value: unknown, context: Context): unknown {
  switch (typeof value) {
    case "string":
      charge(context, checkString(value, context) + 2);
      return value;
    case "number":
      checkNumber(value, context);
      charge(context, decimalLength(value));
      return value;
    case "boolean":
      charge(context, value ? 4 : 5);
      return value;
    case "bigint":
      checkBigInt(value, context);
      charge(context, MARKER_PREFIX_TEXT.length + 2 + value.toString().length);
      return value;
    case "object": {
      if (value === null) {
        charge(context, 4);
        return null;
      }
      if (context.active.includes(value)) throw cycleError(context);
      return Array.isArray(value) ? captureArray(value, context) : captureRecord(value, context);
    }
    default:
      throw unsupported(value, context);
  }
}

function captureArray(value: readonly unknown[], context: Context): readonly unknown[] {
  const length = checkArray(value, context);
  charge(context, length === 0 ? 2 : length + 1);
  context.active.push(value);
  const copy: unknown[] = new Array(length);
  for (let index = 0; index < length; index += 1) {
    const entry = value[index];
    if (entry === undefined) throw undefinedEntry(index, context);
    context.path.push(index);
    copy[index] = captureNode(entry, context);
    context.path.pop();
  }
  context.active.pop();
  return Object.freeze(copy);
}

function captureRecord(value: object, context: Context): unknown {
  const keys = recordKeys(value, context);
  if (keys === null) {
    const decimal = parseMarker((value as Record<string, unknown>)[BIGINT_MARKER_KEY], context);
    charge(context, MARKER_PREFIX_TEXT.length + 2 + decimal.toString().length);
    return decimal;
  }
  charge(context, 2);
  context.active.push(value);
  const copy: Record<string, unknown> = {};
  let members = 0;
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index] as string;
    const keyBytes = keyInfo(key, context) >>> 1;
    const field = (value as Record<string, unknown>)[key];
    if (field === undefined) continue;
    charge(context, keyBytes + (members === 0 ? 3 : 4));
    context.path.push(key);
    const captured = captureNode(field, context);
    context.path.pop();
    // An own "__proto__" key is an ordinary field, so it must be defined, not assigned.
    if (key === "__proto__") Object.defineProperty(copy, key, { value: captured, enumerable: true, writable: true, configurable: true });
    else copy[key] = captured;
    members += 1;
  }
  context.active.pop();
  return Object.freeze(copy);
}

export type CaptureOptions = Readonly<{ maxDepth?: number; maxTotalBytes?: number }>;

/**
 * Validates structure and limits and returns a frozen plain deep copy (arrays
 * and `Object.prototype` records, keys in canonical order, bigint markers
 * decoded to bigints, undefined-valued fields dropped). Throws CanonicalError.
 * Because the copy is validated and frozen, callers may treat it as immutable.
 */
export function captureValue(value: unknown, options?: CaptureOptions): unknown {
  const context = createContext(budgetOf(options?.maxTotalBytes), depthOf(options?.maxDepth));
  return captureNode(value, context);
}

// ---------------------------------------------------------------- predicates

/** 1..256 UTF-8 bytes, well-formed, no C0 control (U+0000..U+001F) and no DEL. */
export function isIdentifier(v: unknown): v is string {
  if (typeof v !== "string" || v.length === 0) return false;
  if (utf8Length(v, LIMITS.maxIdentifierBytes) === undefined) return false;
  for (let index = 0; index < v.length; index += 1) {
    const unit = v.charCodeAt(index);
    if (unit < 0x20 || unit === 0x7f) return false;
  }
  return true;
}

/**
 * A-89.2: the number of Unicode code points (scalar values) of `v`, which "≤ 128 chars" counts: a surrogate pair is one.
 * Counting stops once it passes `limit`; no allocation. A string of at most `limit` UTF-16 units is answered at once.
 */
export function codePointLength(v: string, limit = Number.MAX_SAFE_INTEGER): number {
  if (v.length <= limit) {
    let pairs = 0;
    for (let index = 0; index < v.length - 1; index += 1) {
      const unit = v.charCodeAt(index);
      if (unit >= 0xd800 && unit <= 0xdbff) { const next = v.charCodeAt(index + 1); if (next >= 0xdc00 && next <= 0xdfff) { pairs += 1; index += 1; } }
    }
    return v.length - pairs;
  }
  let count = 0;
  for (let index = 0; index < v.length && count <= limit; index += 1, count += 1) {
    const unit = v.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff && index + 1 < v.length) { const next = v.charCodeAt(index + 1); if (next >= 0xdc00 && next <= 0xdfff) index += 1; }
  }
  return count;
}

/** Well-formed UTF-16, at most 4096 UTF-8 bytes. */
export function isProtocolString(v: unknown): v is string {
  return typeof v === "string" && utf8Length(v, LIMITS.maxStringBytes) !== undefined;
}

/** Safe integer in 0..2^53-1 (not -0). */
export function isU53(v: unknown): v is U53 {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0 && !(v === 0 && 1 / v < 0);
}

/** bigint in 0..2^256-1. */
export function isAmount(v: unknown): v is Amount {
  return typeof v === "bigint" && v >= 0n && v <= MAX_PROTOCOL_BIGINT;
}

/** The format-2 Amount grammar (SPEC §3.3): `^(0|[1-9][0-9]*)$`, at most 78 characters, at most 2^256−1. */
export const AMOUNT_STRING = /^(?:0|[1-9][0-9]*)$/;
export function isAmountString(v: unknown): v is string {
  return typeof v === "string" && v.length <= 78 && AMOUNT_STRING.test(v) && BigInt(v) <= MAX_PROTOCOL_BIGINT;
}
/** The engine Amount of a format-2 Amount string (`undefined` when the string is not one). */
export function parseAmountString(v: unknown): Amount | undefined {
  return isAmountString(v) ? BigInt(v) : undefined;
}
/** An Amount accepted in either form: a bigint, or (format 2) its decimal string; `undefined` otherwise. */
export function amountOf(v: unknown): Amount | undefined {
  return isAmount(v) ? v : parseAmountString(v);
}
/**
 * The wire form of a format-2 structure (SPEC §3.4): every bigint becomes its decimal string, deeply. A
 * format-2 structure holds bigints only at Amount positions, so this is exactly the §16.2 step 2(a) path list
 * applied to proofs, challenges, receipts and state records. Plain records and arrays only; frozen output.
 */
export function wireAmounts<T>(value: T): T {
  if (typeof value === "bigint") return value.toString() as unknown as T;
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return Object.freeze(value.map(wireAmounts)) as unknown as T;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(value as object)) out[key] = wireAmounts((value as Record<string, unknown>)[key]);
  return Object.freeze(out) as unknown as T;
}

export function isContentHash(v: unknown): v is ContentHash {
  return typeof v === "string" && /^0x[0-9a-f]{64}$/.test(v);
}

/** `0x` + 40 hex digits, any case (no checksum verification). */
export function isEthereumAddress(v: unknown): v is string {
  return typeof v === "string" && /^0x[0-9a-fA-F]{40}$/.test(v);
}

/** Decimal without leading zeros, value in 1..2^256-1. */
export function isChainId(v: unknown): v is string {
  if (typeof v !== "string" || v.length > 78 || !/^[1-9][0-9]*$/.test(v)) return false;
  return BigInt(v) <= MAX_PROTOCOL_BIGINT;
}

/** A frozen copy sorted in UTF-8 byte order (throws CanonicalError on a malformed member). */
export function sortedIdentifiers(list: readonly string[]): readonly string[] {
  const copy = list.slice();
  for (let index = 0; index < copy.length; index += 1) {
    scanString(copy[index] as string, LIMITS.maxStringBytes, () => `$[${index}]`);
  }
  return Object.freeze(copy.sort(compareWellFormed));
}

// ---------------------------------------------------------------- JSON with bigint markers

const bigintReplacer = (_key: string, value: unknown): unknown =>
  typeof value === "bigint" ? { [BIGINT_MARKER_KEY]: value.toString() } : value;

/** Plain JSON (keys as-is, no sorting) with bigints spelled as `{"$continuity.bigint":"…"}`. */
export function jsonStringifyWithBigints(value: unknown): string {
  return JSON.stringify(value, bigintReplacer);
}

/** The bigint a marker record stands for (strict grammar, CanonicalError otherwise); `undefined` for any other record. */
function markerValue(value: object): bigint | undefined {
  if (!Object.hasOwn(value, BIGINT_MARKER_KEY)) return undefined;
  const keys = Object.keys(value);
  const decimal = (value as Record<string, unknown>)[BIGINT_MARKER_KEY];
  if (keys.length !== 1 || typeof decimal !== "string" || decimal.length > 79 || !MARKER_DECIMAL.test(decimal)) {
    throw new CanonicalError("Canonical BigInt marker has an invalid decimal value.");
  }
  const parsed = BigInt(decimal);
  if (parsed < -MAX_PROTOCOL_BIGINT || parsed > MAX_PROTOCOL_BIGINT) {
    throw new CanonicalError("Canonical BigInt exceeds the 256-bit protocol bound.", "$", true);
  }
  return parsed;
}

const isContainer = (value: unknown): value is object => value !== null && typeof value === "object";

/**
 * Reverse of `jsonStringifyWithBigints`: marker objects become bigints (strict
 * grammar, CanonicalError otherwise). An own `__proto__` key in the text stays
 * an own data property (JSON.parse never assigns prototypes, and a marker under
 * that key is defined, not assigned), so the result is safe to hand to
 * `captureValue`. Malformed JSON throws the usual SyntaxError.
 *
 * The markers are decoded by an explicit-stack walk in document order, a
 * parent before its children (pre-order, the order of Python's `from_plain`, so
 * both report the same first malformed marker; a `JSON.parse` reviver would
 * visit children first), not by a reviver: V8's reviver recursion overflows the call
 * stack (RangeError) on deeply nested but valid JSON, which JSON.parse itself
 * reads iteratively. Depth is left to `captureValue` / `canonicalEncode`.
 */
export function jsonParseWithBigints(text: string): unknown {
  const root: unknown = JSON.parse(text);
  if (!isContainer(root)) return root;
  if (!Array.isArray(root)) {
    const marker = markerValue(root);
    if (marker !== undefined) return marker;
  }
  const stack: [Record<string, unknown> | unknown[], string | number][] = [];
  const pushChildren = (node: object): void => {
    if (Array.isArray(node)) {
      for (let index = node.length - 1; index >= 0; index -= 1) if (isContainer(node[index])) stack.push([node, index]);
      return;
    }
    const record = node as Record<string, unknown>;
    const keys = Object.keys(record);
    for (let index = keys.length - 1; index >= 0; index -= 1) if (isContainer(record[keys[index]!])) stack.push([record, keys[index]!]);
  };
  pushChildren(root);
  while (stack.length > 0) {
    const [parent, key] = stack.pop()!;
    const value = (parent as Record<string | number, unknown>)[key] as object;
    if (!Array.isArray(value)) {
      const marker = markerValue(value);
      if (marker !== undefined) {
        if (key === "__proto__") Object.defineProperty(parent, key, { value: marker, writable: true, enumerable: true, configurable: true });
        else (parent as Record<string | number, unknown>)[key] = marker;
        continue;
      }
    }
    pushChildren(value);
  }
  return root;
}
