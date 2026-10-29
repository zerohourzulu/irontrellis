/**
 * Bounded data helpers shared by every gateway module: closed-record checks,
 * canonical hashing, and private-file I/O (0600 files in 0700 directories,
 * read through O_NOFOLLOW, written create-exclusive and fsynced).
 */
import { closeSync, constants, fstatSync, fsyncSync, lstatSync, openSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { types } from "node:util";
import { captureValue, hashCanonical, hashAlgorithmForDomain, type ContentHash } from "@ramex-labs/irontrellis";
import { ownerOnlyModeEnforced } from "@ramex-labs/irontrellis/platform";
import { parseStrictJson } from "./strict-json.ts";

export type HashAlgorithm = "keccak256" | "sha256";
export type Json = Readonly<Record<string, unknown>>;

/**
 * Every refusal the gateway raises carries a stable upper-case code. `detail`
 * is an optional operator-facing sentence (why a file or setting was refused);
 * it names settings and limits, never configuration values or payloads, and
 * is printed only by the command-line tools, never returned to an MCP client.
 */
export class GatewayError extends Error {
  readonly code: string;
  readonly mayHaveCommitted: boolean;
  readonly detail: string | undefined;
  constructor(code: string, mayHaveCommitted = false, detail?: string) {
    super(code);
    this.name = "GatewayError";
    this.code = code;
    this.mayHaveCommitted = mayHaveCommitted;
    this.detail = detail;
  }
}
export const fail = (code: string, detail?: string): never => { throw new GatewayError(code, false, detail); };
export function check(ok: unknown, code = "INVALID_INPUT", detail?: string): asserts ok {
  if (!ok) fail(code, detail);
}
export const codeOf = (error: unknown): string | undefined =>
  error !== null && typeof error === "object" && typeof (error as { code?: unknown }).code === "string" ? (error as { code: string }).code : undefined;

const ERRNO: Readonly<Record<string, string>> = {
  ENOENT: "does not exist", EACCES: "permission denied", EPERM: "operation not permitted", ELOOP: "is a symbolic link (refused)",
  ENOTDIR: "a component of the path is not a directory", EISDIR: "is a directory", EEXIST: "already exists", EROFS: "is on a read-only file system",
};
const JSON_ERRORS: Readonly<Record<string, string>> = {
  INVALID_JSON: "is not valid JSON", INVALID_UTF8: "is not valid UTF-8", DUPLICATE_KEY: "has a duplicate key", INVALID_JSON_NUMBER: "has a non-finite number",
  JSON_BYTES_EXCEEDED: "is too large", JSON_NODES_EXCEEDED: "has too many values", JSON_DEPTH_EXCEEDED: "is nested too deeply",
};
/** One operator-facing sentence for a refusal: the gateway's own detail, a file-system or JSON cause, or the code. Bounded to 300 characters. */
export function describeError(error: unknown): string {
  const code = codeOf(error);
  let text: string;
  if (error instanceof GatewayError) text = error.detail ?? error.code;
  else if (code !== undefined && ERRNO[code] !== undefined) text = ERRNO[code]!;
  else if (code !== undefined && JSON_ERRORS[code] !== undefined) text = JSON_ERRORS[code]!;
  else if (code !== undefined && error instanceof Error && error.message !== code) text = `${code}: ${error.message}`;
  else text = code ?? (error instanceof Error ? error.message : "unknown error");
  return text.length > 300 ? text.slice(0, 297) + "..." : text;
}
/** Run `step` and re-raise any failure as a GatewayError keeping its code, with `label` prefixed to the detail. */
export function explained<T>(label: string, step: () => T): T {
  try { return step(); } catch (error) { throw new GatewayError(codeOf(error) ?? "INVALID_INPUT", false, `${label} ${describeError(error)}`); }
}

/** Copy `input` from own data descriptors only (no accessors, proxies, symbol keys, cycles or exotic shapes) within bounds; the copy is frozen. */
export function captureData(input: unknown, maxBytes = 131072, maxNodes = 8192, maxDepth = 24): unknown {
  let nodes = 0;
  const ancestors = new Set<object>();
  const copy = (value: unknown, depth: number): unknown => {
    check(++nodes <= maxNodes && depth <= maxDepth);
    if (value === null || ["string", "number", "bigint", "boolean"].includes(typeof value)) return value;
    check(typeof value === "object" && !types.isProxy(value) && !ancestors.has(value));
    const array = Array.isArray(value), proto = Object.getPrototypeOf(value);
    check(array ? proto === Array.prototype : proto === Object.prototype || proto === null);
    const keys = Reflect.ownKeys(value);
    check(keys.length <= maxNodes && keys.every((key) => typeof key === "string"));
    ancestors.add(value);
    try {
      if (array) {
        const length = Object.getOwnPropertyDescriptor(value, "length");
        check(length !== undefined && Object.hasOwn(length, "value") && Number.isSafeInteger(length.value) && length.value >= 0 && length.value <= maxNodes && keys.length === length.value + 1);
        const result: unknown[] = [];
        for (let i = 0; i < (length.value as number); i++) {
          const d = Object.getOwnPropertyDescriptor(value, String(i));
          check(d !== undefined && d.enumerable && Object.hasOwn(d, "value"));
          result.push(copy(d.value, depth + 1));
        }
        return result;
      }
      const result: Record<string, unknown> = {};
      for (const key of keys as string[]) {
        const d = Object.getOwnPropertyDescriptor(value, key);
        check(d !== undefined && d.enumerable && Object.hasOwn(d, "value"));
        result[key] = copy(d.value, depth + 1);
      }
      return result;
    } finally {
      ancestors.delete(value);
    }
  };
  const copied = copy(input, 0);
  try { return captureValue(copied, { maxTotalBytes: maxBytes, maxDepth }); } catch { return fail("INVALID_INPUT"); }
}
/** Capture plain data within the gateway's bounds (128 KiB, 8,192 nodes, depth 24). */
export const data = <T = unknown>(value: unknown): T => captureData(value) as T;
/** Canonical hash of captured data (sha256 unless the domain selects keccak). */
export const hash = (value: unknown, algorithm: HashAlgorithm = "sha256"): ContentHash => hashCanonical(data(value), algorithm);
export const algorithmFor = (domain: unknown): HashAlgorithm => hashAlgorithmForDomain(domain as Readonly<{ protocol?: unknown }>);
export const same = (a: unknown, b: unknown): boolean => hash(a) === hash(b);

/** A plain object with exactly the required keys plus a subset of the optional ones. */
export function exact<T extends Json = Json>(value: unknown, required: readonly string[], optional: readonly string[] = []): T {
  check(value !== null && typeof value === "object" && !Array.isArray(value), "INVALID_INPUT", "must be a JSON object");
  const keys = Object.keys(value as object);
  const missing = required.find((k) => !Object.hasOwn(value as object, k));
  check(missing === undefined, "INVALID_INPUT", `is missing the required field "${missing}"`);
  const unknown = keys.find((k) => !required.includes(k) && !optional.includes(k));
  check(unknown === undefined, "INVALID_INPUT", `has an unknown field "${String(unknown).slice(0, 64)}"`);
  return value as T;
}
/**
 * A-185.6: a path field of gateway.json (`historyFile`, `keyFile`, `connector.keyFile`, `storage`): a non-empty string without
 * NUL or other control characters, at most 4,096 UTF-8 bytes. One validator for `setup` and the loader, never `id()`.
 */
export function pathField(value: unknown): string {
  check(typeof value === "string" && value.length > 0 && Buffer.byteLength(value, "utf8") <= 4096 && !/[\u0000-\u001f\u007f]/u.test(value));
  return value;
}
/** A bounded identifier: 1–128 characters without control characters. */
export function id(value: unknown): string {
  check(typeof value === "string" && value.length > 0 && value.length <= 128 && !/[\u0000-\u001f\u007f]/u.test(value));
  return value;
}
/** Owner-only permission bits; always true on Windows, whose mode bits are synthetic (the ACL protects the file there: docs/PLATFORMS.md §3). */
export const isPrivateMode = (mode: number): boolean => !ownerOnlyModeEnforced() || (mode & 0o077) === 0;
const octal = (mode: number): string => "0" + (mode & 0o777).toString(8).padStart(3, "0");
/** Why a file is not a private single-link regular file, or undefined when it is. */
function privateFileProblem(s: ReturnType<typeof fstatSync>, maximum: number): [code: string, detail: string] | undefined {
  if (!s.isFile()) return ["PRIVATE_FILE_INVALID", "is not a regular file"];
  if (s.nlink !== 1) return ["PRIVATE_FILE_INVALID", `has ${s.nlink} hard links; it must have exactly one`];
  if (!isPrivateMode(Number(s.mode))) return ["PRIVATE_FILE_INVALID", `has mode ${octal(Number(s.mode))}; it must be owner-only (0600)`];
  if (Number(s.size) > maximum) return ["PRIVATE_FILE_TOO_LARGE", `is ${s.size} bytes; the limit is ${maximum} bytes`];
  return undefined;
}
/** Raw fs errors (ENOENT, ELOOP, …) propagate with their code: callers branch on them, and `describeError` explains them. */
const openPrivate = (path: string): number => openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);

/** An existing, canonical, owner-only directory. */
export function privateDirectory(value: string): string {
  const path = resolve(value);
  let s;
  try { s = lstatSync(path); } catch (error) { return fail("STORAGE_UNAVAILABLE", `${path} ${describeError(error)}`); }
  check(s.isDirectory(), "STORAGE_UNAVAILABLE", `${path} is not a directory`);
  check(realpathSync(path) === path, "STORAGE_UNAVAILABLE", `${path} is not a canonical path (it is or passes through a symbolic link)`);
  check(isPrivateMode(s.mode), "STORAGE_UNAVAILABLE", `${path} has mode ${octal(s.mode)}; it must be owner-only (0700)`);
  return path;
}
/** Read one owner-only regular file (no links, single hard link, unchanged while read) as strict JSON. */
export function readPrivate<T = unknown>(path: string, maximum = 131072): T {
  const fd = openPrivate(path);
  try {
    const s = fstatSync(fd), problem = privateFileProblem(s, maximum);
    check(problem === undefined, "STORAGE_UNAVAILABLE", problem?.[1]);
    const bytes = readFileSync(fd), after = fstatSync(fd), named = lstatSync(path);
    check(bytes.length === s.size && after.size === s.size && after.mtimeMs === s.mtimeMs && after.ctimeMs === s.ctimeMs &&
      named.ino === s.ino && named.dev === s.dev && !named.isSymbolicLink(), "STORAGE_UNAVAILABLE", "changed while being read");
    return parseStrictJson(bytes, { maxBytes: maximum, maxDepth: 24, maxNodes: 8192 }) as T;
  } finally {
    closeSync(fd);
  }
}
/** fsyncs a directory; skipped on Windows, which cannot open a directory for fsync (NTFS journals directory changes). */
export function syncDirectory(path: string): void {
  if (process.platform === "win32") return;
  const fd = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}
/** Create-exclusive, 0600, fsynced file and directory. Throws EEXIST (as `code`) when the path exists. */
export function durableCreate(path: string, value: unknown): void {
  const bytes = Buffer.from(JSON.stringify(data(value)));
  check(bytes.length <= 131072, "STORAGE_UNAVAILABLE");
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { writeFileSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
  syncDirectory(dirname(path));
}
/** Check, without reading it, that `path` is a private single-link regular file of at most `limit` bytes (PRIVATE_FILE_TOO_LARGE names both sizes). */
export function privateFileCheck(path: string, limit: number): void {
  const fd = openPrivate(path);
  try {
    const problem = privateFileProblem(fstatSync(fd), limit);
    if (problem !== undefined) fail(problem[0], `${path} ${problem[1]}`);
  } finally {
    closeSync(fd);
  }
}
/** Read the raw bytes of a private file (diagnostics and snapshots), refusing anything that changed while being read. */
export function privateFileBytes(path: string, limit: number): Buffer {
  const fd = openPrivate(path);
  try {
    const before = fstatSync(fd), problem = privateFileProblem(before, limit);
    if (problem !== undefined) fail(problem[0], `${path} ${problem[1]}`);
    const bytes = readFileSync(fd), after = fstatSync(fd), named = lstatSync(path);
    check(bytes.length === before.size && after.mtimeMs === before.mtimeMs && after.ctimeMs === before.ctimeMs && after.size === before.size &&
      named.ino === before.ino && named.dev === before.dev && !named.isSymbolicLink(), "FILE_CHANGED", `${path} changed while being read`);
    return bytes;
  } finally {
    closeSync(fd);
  }
}
