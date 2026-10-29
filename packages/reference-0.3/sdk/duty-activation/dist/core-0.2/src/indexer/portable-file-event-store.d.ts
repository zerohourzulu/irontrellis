import type { PortableCanonicalEvent, PortableHistoryHead } from "../core/index.ts";
export declare class PortableStoreConflictError extends Error {
    readonly observedHead?: PortableHistoryHead;
    constructor(observedHead?: PortableHistoryHead);
}
export declare class PortableStoreBusyError extends Error {
    constructor();
}
export interface PortableStoreWriter {
    readAll(): readonly PortableCanonicalEvent[];
    appendAtExpectedHead(event: PortableCanonicalEvent, expected: PortableHistoryHead): PortableHistoryHead;
}
/** Local cooperative-writer reference mechanics. Parent directory must exist.
 * File limit: 64 MiB; encoded nesting: 128; replay's portable limits also apply.
 * Symlink aliases resolve to one path; hard links are unsupported. No stale-lock
 * recovery, hostile filesystem writers, public finality or crash reconciliation.
 * Hashes detect modified records/fragments, not removal of a complete valid suffix.
 */
export declare class PortableFileEventStore {
    #private;
    readonly path: string;
    constructor(path: string);
    readAll(): readonly PortableCanonicalEvent[];
    withExclusiveWriter<T>(callback: (writer: PortableStoreWriter) => T): T;
    append(event: PortableCanonicalEvent): void;
    appendAll(input: readonly PortableCanonicalEvent[]): void;
    appendAtExpectedHead(event: PortableCanonicalEvent, expected: PortableHistoryHead): PortableHistoryHead;
}
