import { type PortableHistoryHead, type PortableReplayState } from "../core/portable-replay.ts";
import type { AcceptedCanonicalEventShape as Event } from "../core/event-schema.ts";
export declare const CONTINUATION_HISTORY_VERSION: "continuity-history-snapshot/1";
export declare const CONTINUATION_PROFILE: Readonly<{
    version: "continuity-segmented-local/1";
    maxEvents: 1024;
    maxCanonicalHistoryBytes: number;
    maxEventBytes: 8192;
    maxEventNodes: 512;
    maxEventDepth: 16;
    maxEventArrayMembers: 32;
    maxHistoryNodes: 524288;
    maxAncillaryBytes: 65536;
    maxAncillaryNodes: 8192;
}>;
export type HistoryErrorCode = "INVALID_INPUT" | "UNSUPPORTED_VERSION" | "HISTORY_LIMIT" | "EVENT_LIMIT" | "INVALID_HISTORY" | "HEAD_MISMATCH" | "INVALID_HISTORY_HANDLE" | "PREFIX_INVALID" | "OUTPUT_LIMIT";
export declare class HistoryError extends Error {
    readonly code: HistoryErrorCode;
    constructor(code: HistoryErrorCode);
}
export type HistoryMetrics = Readonly<{
    canonicalBytes: number;
    nodes: number;
    maxEventBytes: number;
    maxEventNodes: number;
}>;
export type VerifiedHistory = Readonly<{
    version: typeof CONTINUATION_HISTORY_VERSION;
    profile: typeof CONTINUATION_PROFILE.version;
    head: PortableHistoryHead;
    eventCount: number;
    metrics: HistoryMetrics;
    scope: "CAPTURED_HISTORY_ONLY";
    executionCapability: false;
}>;
type Snapshot = Readonly<{
    events: readonly Event[];
    state: PortableReplayState;
}>;
/** Reject executable envelopes without reading a caller getter or proxy. */
export declare function historyDataFields(input: unknown, required: readonly string[], optional?: readonly string[]): Record<string, unknown>;
export declare function captureHistoryAncillary(input: unknown): Record<string, unknown>;
export declare function captureContinuationHistory(input: unknown): VerifiedHistory;
/** Package internal: identity check happens before reading any handle member. */
export declare function verifiedHistorySnapshot(handle: unknown): Snapshot;
export declare function exportContinuationEvents(handle: unknown): readonly Event[];
export declare function continuationPrefix(handle: unknown, position: unknown): VerifiedHistory;
/** Package-internal pre-signing size check, never transition authorization. */
export declare function checkContinuationAppendShape(handle: unknown, input: unknown): Event;
/** Pure prospective replay; no append or invocation capability. */
export declare function appendContinuationEvent(handle: unknown, event: unknown): VerifiedHistory;
export {};
