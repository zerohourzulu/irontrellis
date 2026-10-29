import { CONTINUATION_HISTORY_VERSION, type VerifiedHistory } from "../history.ts";
import { type Hooks } from "./files.ts";
export declare const TRANSFER_VERSION = "continuity-checkpoint-transfer/1";
export declare const TRANSFER_STORAGE_LIMITS: Readonly<{
    bytes: number;
    chunks: 2048;
    manifests: 2048;
    manifestBytes: 65536;
}>;
export declare function createHistoryTransfer(history: VerifiedHistory): Readonly<{
    transferId: string;
    manifest: Record<string, any>;
    chunks: readonly (readonly string[])[];
}>;
export declare function openCheckpointStorage(parent: string, hooks?: Hooks): Readonly<{
    begin(input: unknown, id: string, committedReference: string | null): {
        transferId: string;
    };
    chunk(id: string, index: number, parts: readonly string[]): {
        transferId: string;
        index: number;
    };
    abort(id: string): {
        transferId: string;
    };
    ready(id: string): Readonly<{
        version: typeof CONTINUATION_HISTORY_VERSION;
        profile: "continuity-segmented-local/1";
        head: import("../../../core-0.2/src/core/portable-replay.ts").PortableHistoryHead;
        eventCount: number;
        metrics: import("../../../core-0.2/src/history/index.ts").HistoryMetrics;
        scope: "CAPTURED_HISTORY_ONLY";
        executionCapability: false;
    }>;
    load: (id: string) => VerifiedHistory;
    inspect(): {
        bytes: number;
        chunks: number;
        manifests: number;
        active: string | null;
    };
}>;
