/**
 * `@ramex-labs/irontrellis/internal-format1` — NOT PUBLIC. No semver promise. Test tooling only (A-185.3, A-194.4).
 *
 * The public API writes format 2 only. The conformance generators, the fuzz seed builder, the benchmarks and the tests that
 * create or append to legacy (`continuity-event/0.2`) or format-1 (`irontrellis-event/1`) histories use these helpers;
 * every exported name carries `Test` or `Internal`.
 */
import { createLocalOwner, openLocalOwner, type LocalOwner, type LocalOwnerOptions } from "./owner.ts";
import { createHistoryStore, openHistoryStore, type HistoryStore, type StoreOptions } from "./store.ts";
import type { CanonicalEvent } from "./types.ts";
import { FORMAT1_TEST_TOOLING } from "./format1-tooling.ts";

export { FORMAT1_TEST_TOOLING };
/** `options` with the test-tooling mark: an owner, runtime or store opened with it may write a legacy or format-1 history. */
export const format1TestOptions = <T extends object>(options: T): T => ({ ...options, [FORMAT1_TEST_TOOLING]: true }) as T;
/** `createLocalOwner` for a legacy or format-1 history (tests and generators only). */
export const createFormat1TestOwner = (options: LocalOwnerOptions): Promise<LocalOwner> => createLocalOwner(format1TestOptions(options));
/** `openLocalOwner` naming a legacy or format-1 `format` (writable; tests and generators only). */
export const openFormat1TestOwner = (options: LocalOwnerOptions): LocalOwner => openLocalOwner(format1TestOptions(options));
/** The store with `readOnlyFormats: false` allowed (the format-1-era writer). */
export const openHistoryStoreInternal = (path: string, options: StoreOptions = {}): HistoryStore => openHistoryStore(path, format1TestOptions(options));
/** `createHistoryStore` for a legacy or format-1 genesis. */
export const createHistoryStoreInternal = (path: string, genesis: readonly CanonicalEvent[], options: StoreOptions = {}): HistoryStore => createHistoryStore(path, genesis, format1TestOptions(options));
