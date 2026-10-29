import type { PortableReceiptRecordAdmissionResult } from "../core/index.ts";
import { PortableFileEventStore } from "../indexer/portable-file-event-store.ts";
/** Local persistence uncertainty is separate from the portable result union. */
export type DurableReceiptRecordResult = PortableReceiptRecordAdmissionResult | Readonly<{
    status: "UNAVAILABLE";
    recordMayHavePersisted: boolean;
    reason: string;
}>;
/** Artifact-aware local producer. The configured store supplies conditional persistence. */
export declare class DurableReceiptCoordinator {
    readonly store: PortableFileEventStore;
    constructor(store: PortableFileEventStore);
    record(input: unknown): DurableReceiptRecordResult;
}
