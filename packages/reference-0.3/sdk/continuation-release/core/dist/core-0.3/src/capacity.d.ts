import { type PortableCanonicalEvent } from "../../core-0.2/src/core/index.ts";
import { PortableFileEventStore, type PortableStoreWriter } from "../../core-0.2/src/indexer/portable-file-event-store.ts";
/** Finite ledger space, not authority, disk availability or a promise of completion. */
export declare const LOCAL_CAPACITY_PROFILE: Readonly<{
    version: "continuity-managed-capacity/1";
    maxEvents: 96;
    maxEventBytes: 8192;
    maxEventArrayMembers: 32;
    maxEventDepth: 16;
    controlEvents: 8;
}>;
/** Input must already be captured/replayed by the trusted caller; no decision authority. */
export declare function capacityOf(events: readonly PortableCanonicalEvent[]): Readonly<{
    profile: "continuity-managed-capacity/1";
    eventCount: number;
    maxEvents: 96;
    reservedByRecordType: Readonly<{
        [k: string]: number;
    }>;
    declaredJobs: number;
    lifecycleReserved: number;
    controlReserved: number;
    unreservedEvents: number;
    compatible: boolean;
    mode: "OPEN" | "INCOMPATIBLE" | "EXHAUSTED" | "DRAINING";
    canDeclareJob: boolean;
    remainingPhysicalEvents: number;
    pointInTimeOnly: true;
    grantsAuthority: false;
}>;
export declare function assertCapacityTransition(events: readonly PortableCanonicalEvent[], next: readonly PortableCanonicalEvent[]): void;
/** All managed writes check the actual prefix under the existing store lock.
 * No separate reservation file exists. Raw 0.2 writers/host rollback are outside this profile.
 */
export declare class ManagedLocalEventStore extends PortableFileEventStore {
    withExclusiveWriter<T>(callback: (writer: PortableStoreWriter) => T): T;
    appendAll(input: readonly PortableCanonicalEvent[]): void;
    append(_event: PortableCanonicalEvent): void;
}
