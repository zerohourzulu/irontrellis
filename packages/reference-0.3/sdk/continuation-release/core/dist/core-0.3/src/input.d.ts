export type ContinuityErrorCode = "CAPACITY_RESERVED" | "CAPACITY_INCOMPATIBLE" | "CAPACITY_EVENT_LIMIT" | "CAPACITY_BATCH_UNSUPPORTED" | "CAPACITY_EXPECTED_HEAD_REQUIRED" | "INVALID_INPUT" | "INVALID_HISTORY" | "HISTORY_LIMIT" | "HISTORY_EXISTS" | "PROFILE_MISMATCH" | "CLOCK_INVALID" | "HISTORY_CONFLICT" | "POLICY_EVIDENCE_UNAVAILABLE" | "RUNTIME_NOT_CURRENT" | "OPERATION_CONFLICT" | "SIGNER_FAILED" | "RECEIPT_UNAVAILABLE" | "TRANSITION_REJECTED" | "READ_UNAVAILABLE" | "WRITE_UNCONFIRMED";
export declare class ContinuityError extends Error {
    readonly code: ContinuityErrorCode;
    readonly mayHaveCommitted: boolean;
    constructor(code: ContinuityErrorCode, mayHaveCommitted?: boolean);
}
export declare function requireCondition(value: unknown, code?: ContinuityErrorCode): asserts value;
/** This facade accepts data, not getters, proxies or executable object shapes. */
export declare function captureData(input: unknown, maxBytes?: number, maxNodes?: number, maxDepth?: number): unknown;
export declare function record(input: unknown, required: readonly string[], optional?: readonly string[]): Record<string, unknown>;
export declare function identifier(value: unknown): string;
export declare function time(value: unknown): number;
export declare function identifiers(value: unknown): readonly string[];
