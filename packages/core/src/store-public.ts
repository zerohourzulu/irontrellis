/**
 * `@ramex-labs/irontrellis/store` and the package root's store entry points (A-185.3): as `store.ts`, except that
 * `openHistoryStore` refuses `readOnlyFormats: false` and `createHistoryStore` refuses a legacy or format-1 genesis. The
 * format-1-era writer is test tooling (`@ramex-labs/irontrellis/internal-format1`).
 */
import { EngineError } from "./errors.ts";
import { TRELLIS2_FORMAT } from "./events.ts";
import { detectFormat } from "./replay.ts";
import { hasFormat1TestTooling } from "./format1-tooling.ts";
import { createHistoryStore as createAny, openHistoryStore as openAny, type HistoryStore, type StoreOptions } from "./store.ts";
import { restrictToFormat2 } from "./store-fence.ts";
import { types } from "node:util";
import type { CanonicalEvent } from "./types.ts";

// Step 5d (P2-2): an explicit list, not `export *`, so a module-internal export of store.ts (witnessSessionOf, which can change the
// persisted witness side file) is never published by accident; the store writers are this module's own.
export {
  FORMAT_READ_ONLY_DEFAULT, MIGRATED_MARKER_VERSION, migratedMarkerPathFor, canonicalPath, markerTargetOf, markerTargetPath, readMigratedMarker,
  storeCounters, resetStoreCountersForTests, setStoreCutHookForTests, PINNED_HEAD_VERSION, LOCK_STALE_MS, HISTORY_FILE_LIMITS, readGenesisLine,
  SPECULATIVE_REPLAY_MIN_RECORDS,
} from "./store.ts";
export type { StoreFormat, HeadAttestation, PinnedHead, StoreOptions, TrustMode, MigratedMarker, RemoteVerifyOptions, RepinOptions, HistoryStore } from "./store.ts";
const refuse = (what: string): never => {
  throw new EngineError("INVALID_INPUT", `${what}: the public store writes format 2 only (SPEC §16.1); legacy and format-1 files open read only`);
};
/**
 * Step 5d (P0-1, P2-4): one shallow copy of the caller's options, taken once, so what is checked is what the store reads. A
 * Proxy, another prototype, an accessor, a non-enumerable or symbol key, or `__proto__` is refused (`INVALID_INPUT`). On the copy
 * `readOnlyFormats: false` is refused and `readOnlyFormats` is then forced to `true`; replay `hooks`, which replace the write-time
 * validators, are refused unless the store is opened for inspection only (it then never writes).
 */
function publicOptions(options: unknown): StoreOptions {
  if (options === undefined) return Object.freeze({ readOnlyFormats: true });
  if (options === null || typeof options !== "object" || types.isProxy(options)) return refuse("store options that are not a plain record");
  const proto = Object.getPrototypeOf(options);
  if (proto !== Object.prototype && proto !== null) refuse("store options that are not a plain record");
  const copy: Record<string, unknown> = {};
  for (const key of Reflect.ownKeys(options)) {
    const d = Object.getOwnPropertyDescriptor(options, key);
    if (typeof key !== "string" || key === "__proto__" || d === undefined || !Object.hasOwn(d, "value") || !d.enumerable) refuse("store options that are not a plain record");
    Object.defineProperty(copy, key, { value: d!.value, enumerable: true, writable: true, configurable: true });
  }
  if (copy.readOnlyFormats === false) refuse("readOnlyFormats: false");
  if (copy.hooks !== undefined && copy.inspect !== true) refuse("replay hooks on a store that can write");
  return Object.freeze({ ...copy, readOnlyFormats: true }) as StoreOptions;
}
/**
 * Opens (or prepares, when absent) the history at `path`; `readOnlyFormats: false` is not public, and a store prepared at an
 * absent path takes a format-2 first batch only (A-185.3).
 */
export function openHistoryStore(path: string, options: StoreOptions = {}): HistoryStore {
  if (hasFormat1TestTooling(options)) return openAny(path, options);
  return restrictToFormat2(openAny(path, publicOptions(options)));
}
/**
 * Independent review step 5b P1-b: one plain-data copy of the caller's genesis batch, taken once, so the format check and the
 * write read the same values. Only arrays and plain records of own, enumerable data properties with string keys are copied;
 * a Proxy, an accessor, a symbol key, another prototype or a cycle is refused (`INVALID_INPUT`) before anything is written.
 */
function genesisSnapshot(genesis: unknown): CanonicalEvent[] {
  const active = new Set<object>();
  const copy = (value: unknown, depth: number): unknown => {
    if (value === null || typeof value !== "object") return value;
    if (depth > 64 || types.isProxy(value) || active.has(value)) refuse("a genesis that is not plain data");
    const array = Array.isArray(value), proto = Object.getPrototypeOf(value);
    if (array ? proto !== Array.prototype : proto !== Object.prototype && proto !== null) refuse("a genesis that is not plain data");
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string")) refuse("a genesis that is not plain data");
    active.add(value);
    try {
      const out: Record<string, unknown> | unknown[] = array ? [] : {};
      for (const key of keys as string[]) {
        const d = Object.getOwnPropertyDescriptor(value, key)!;
        if (array && key === "length") continue;
        if (!Object.hasOwn(d, "value") || !d.enumerable || typeof d.value === "function") refuse("a genesis that is not plain data");
        // Step 5d P2-5: defineProperty, so a `__proto__` key is an own property of the copy, never its prototype.
        Object.defineProperty(out, key, { value: copy(d.value, depth + 1), enumerable: true, writable: true, configurable: true });
      }
      if (array && (out as unknown[]).length !== (value as unknown[]).length) refuse("a genesis that is not plain data");
      return out;
    } finally { active.delete(value); }
  };
  if (!Array.isArray(genesis)) refuse("a genesis that is not an array");
  return copy(genesis, 0) as CanonicalEvent[];
}
/** Creates the file exclusively and writes the genesis batch; a format-2 genesis only (A-185.3). */
export function createHistoryStore(path: string, genesis: readonly CanonicalEvent[], options: StoreOptions = {}): HistoryStore {
  if (!hasFormat1TestTooling(options)) {
    const checked = publicOptions(options);
    // Fail closed (JOB75-01): a genesis whose format is not detected is refused like a legacy or format-1 one. P1-b: the check
    // and the write use one snapshot, and the store is format-2-only before its first write.
    const events = genesisSnapshot(genesis), format = detectFormat(events);
    if (format !== TRELLIS2_FORMAT) refuse(format === undefined ? "a genesis of undetected format" : `a ${format} genesis`);
    return createAny(path, events, checked, true);
  }
  return createAny(path, genesis, options);
}
