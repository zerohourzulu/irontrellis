import { type ObservationOptions } from "./observation.ts";
/** Trusted host selection. Agent arguments cannot choose a store or a profile. */
import { PortableFileEventStore, type PortableStoreWriter } from "../../core-0.2/src/indexer/portable-file-event-store.ts";
import type { PortableCanonicalEvent, PortableHistoryHead } from "../../core-0.2/src/core/index.ts";
import { ManagedLocalEventStore } from "./capacity.ts";
import { DirectoryHistoryStore } from "./history-store/index.ts";
export declare const SEGMENTED_HISTORY_PROFILE: "continuity-segmented-local/1";
export type HistoryLocation = {
    historyFile: string;
    historyProfile?: undefined;
    historyBinding?: never;
} | {
    historyProfile: typeof SEGMENTED_HISTORY_PROFILE;
    historyBinding: string;
    historyFile?: never;
};
export declare class ConfiguredDirectoryEventStore extends PortableFileEventStore {
    readonly directoryStore: DirectoryHistoryStore;
    constructor(binding: string);
    readAll(): readonly PortableCanonicalEvent[];
    withExclusiveWriter<T>(callback: (writer: PortableStoreWriter) => T): T;
    appendAtExpectedHead(event: PortableCanonicalEvent, expected: PortableHistoryHead): Readonly<{
        hash: import("../../core-0.2/src/core/canonical.ts").ContentHash;
        position: number;
        canonicalTime: number;
    }>;
    append(_event: PortableCanonicalEvent): void;
    appendAll(_events: readonly PortableCanonicalEvent[]): void;
}
export declare function openConfiguredEventStore(location: {
    historyFile?: string;
    historyBinding?: string;
    historyProfile?: string;
}): ManagedLocalEventStore | ConfiguredDirectoryEventStore;
export declare function observeConfiguredStore(store: PortableFileEventStore, options?: ObservationOptions): import("./observation.ts").Observation;
