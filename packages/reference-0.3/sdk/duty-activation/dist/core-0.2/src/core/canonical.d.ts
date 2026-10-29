export type ContentHash = `0x${string}`;
/** True when a JavaScript string represents only Unicode scalar values. */
export declare const isWellFormedUnicode: (value: string) => boolean;
/** Unsigned UTF-8 lexicographic protocol-string order, without normalization. */
export declare const compareProtocolStrings: (left: string, right: string) => number;
/** Tests only the module-private identity and exact metadata of a limit failure. */
export declare const isCanonicalCaptureLimitError: (error: unknown, location: string, limit: number) => boolean;
/** @internal Exact metadata for routing a package-owned operation limit failure. */
export declare const getCanonicalCaptureLimitErrorMetadata: (error: unknown) => Readonly<{
    readonly location: string;
    readonly limit: number;
}> | undefined;
/** @internal One provenance-bound replay-event occurrence from shared capture. */
export type CapturedCanonicalReplayEvent = Readonly<{
    readonly eventPosition: number;
    readonly event: unknown;
    readonly capturedRecordKeys: (value: unknown) => readonly string[] | undefined;
    readonly capturedCanonicalBytes: (value: unknown) => number | undefined;
}>;
/** Tests module-private provenance for one incrementally captured replay event. */
export declare const isCapturedCanonicalReplayEvent: (value: unknown) => value is CapturedCanonicalReplayEvent;
export type CanonicalReplayCaptureVisitDecision<T> = Readonly<{
    readonly status: "CONTINUE";
}> | Readonly<{
    readonly status: "STOP";
    readonly result: T;
}>;
export type PortableAuthorityCaptureKind = "AUTHORITY_PATH_EVALUATION" | "AUTHORIZE" | "INTENT_ADMISSION";
export type CanonicalReplayBaseFailureMetadata = Readonly<{
    readonly eventPosition: number;
    readonly code: "EVENT_ENVELOPE_INVALID" | "EVENT_DATA_INVALID";
    readonly eventId?: string;
}>;
/** @internal True only for a capturable replay envelope's closed-schema failure. */
export declare const isCanonicalReplaySchemaFailure: (error: unknown) => boolean;
/** @internal Read-only provenance for a replay member capture/base failure. */
export declare const getCanonicalReplayBaseFailureMetadata: (error: unknown) => CanonicalReplayBaseFailureMetadata | undefined;
export type BoundedCanonicalCaptureOptions = Readonly<{
    maxCanonicalBytes?: number;
}>;
export type BoundedCanonicalCapture<T> = Readonly<{
    value: T;
    canonicalText: string;
    canonicalBytes: number;
    capturedRecordKeys: (value: unknown) => readonly string[] | undefined;
}>;
/**
 * Bounded canonical capture. It observes the supplied value itself, applies
 * the caller's complete-value byte budget incrementally, and returns both the
 * immutable snapshot and its exact canonical text without a second read of
 * caller-owned data.
 */
export declare const captureBoundedCanonicalValue: <T>(value: T, options?: BoundedCanonicalCaptureOptions) => BoundedCanonicalCapture<T>;
export type CapturedCanonicalReplayBody = Readonly<{
    readonly value: Readonly<{
        readonly operationVersion: "continuity-replay/0.2";
        readonly events: readonly unknown[];
    }>;
    readonly canonicalBytes: number;
    readonly capturedRecordKeys: (value: unknown) => readonly string[] | undefined;
    readonly capturedCanonicalBytes: (value: unknown) => number | undefined;
}>;
export type IncrementalCanonicalReplayCaptureOutcome<T> = Readonly<{
    readonly status: "CAPTURED";
    readonly capture: CapturedCanonicalReplayBody;
}> | Readonly<{
    readonly status: "STOPPED";
    readonly result: T;
}> | Readonly<{
    readonly status: "CAPTURE_FAILED";
    readonly error: unknown;
}>;
/** Tests module-private provenance for the shared replay-body snapshot. */
export declare const isCapturedCanonicalReplayBody: (value: unknown) => value is CapturedCanonicalReplayBody;
export declare const captureBoundedCanonicalReplayBody: (events: unknown, containingOperation: object) => CapturedCanonicalReplayBody;
/**
 * @internal Single-context replay capture with a synchronous position-primary
 * semantic reducer. The reducer can stop the operation only after receiving a
 * provenance-bound immutable event snapshot; it cannot influence capture.
 */
export declare const captureBoundedCanonicalReplayBodyIncrementally: <T>(events: unknown, containingOperation: object, visitor: (capture: CapturedCanonicalReplayEvent) => CanonicalReplayCaptureVisitDecision<T>) => IncrementalCanonicalReplayCaptureOutcome<T>;
export type CapturedCanonicalAuthorityOperation<T = unknown> = Readonly<{
    readonly value: T;
    readonly canonicalBytes: number;
    readonly capturedRecordKeys: (value: unknown) => readonly string[] | undefined;
    readonly capturedCanonicalBytes: (value: unknown) => number | undefined;
}>;
export type IncrementalCanonicalAuthorityCaptureOutcome<TCapture, TStop> = Readonly<{
    readonly status: "CAPTURED";
    readonly capture: CapturedCanonicalAuthorityOperation<TCapture>;
}> | Readonly<{
    readonly status: "STOPPED";
    readonly result: TStop;
}> | Readonly<{
    readonly status: "CAPTURE_FAILED";
    readonly error: unknown;
}>;
/** Tests package-internal provenance for one complete authority-operation snapshot. */
export declare const isCapturedCanonicalAuthorityOperation: (value: unknown) => value is CapturedCanonicalAuthorityOperation;
/**
 * @internal One-graph capture for the raw authority, replay-bound authority,
 * and later admission operations. The caller supplies only a package-owned
 * body whose outer fields were each observed once after version dispatch.
 * Identifier/U53/Amount slots receive structural phase-one classification;
 * an embedded event list uses the same provenance-bound replay visitor as
 * `replayPortable`.
 */
export declare const captureBoundedCanonicalAuthorityOperationIncrementally: <TCapture, TStop>(value: TCapture, containingOperation: object, kind: PortableAuthorityCaptureKind, replayVisitor?: (capture: CapturedCanonicalReplayEvent) => CanonicalReplayCaptureVisitDecision<TStop>) => IncrementalCanonicalAuthorityCaptureOutcome<TCapture, TStop>;
export type PortableReceiptCaptureKind = "VERIFY" | "RECORD";
export type CapturedCanonicalReceiptOperation = Readonly<{
    readonly value: Readonly<Record<string, unknown>>;
    readonly canonicalBytes: number;
    readonly capturedRecordKeys: (value: unknown) => readonly string[] | undefined;
    readonly capturedCanonicalBytes: (value: unknown) => number | undefined;
}>;
export type CanonicalReceiptCaptureOutcome = Readonly<{
    readonly status: "CAPTURED";
    readonly capture: CapturedCanonicalReceiptOperation;
}> | Readonly<{
    readonly status: "INVALID_INPUT";
    /** Package-internal distinction for prospective construction limits. */
    readonly limitExceeded: boolean;
}> | Readonly<{
    readonly status: "MALFORMED_ARTIFACT" | "UNSUPPORTED_OPERATION";
}>;
type ReceiptNonArtifactKind = "DOMAIN" | "HISTORY_HEAD" | "IDENTIFIER" | "TIME";
type ReceiptCapturedMemberValidator = (capture: Pick<CapturedCanonicalReceiptOperation, "capturedRecordKeys">, kind: ReceiptNonArtifactKind, value: unknown) => "VALID" | "INVALID" | "LIMIT" | "UNSUPPORTED";
type ReceiptCapturedHistoryLimitPreflight = (capture: Pick<CapturedCanonicalReceiptOperation, "capturedRecordKeys" | "capturedCanonicalBytes">, histories: readonly (readonly unknown[])[]) => "VALID" | "LIMIT";
/**
 * @internal Receipt-only staged capture. The shared graph memo is retained
 * across outer members and both event lists. An unsupported operation reads
 * no body descriptor; supported operations validate non-artifact members and
 * base envelopes before capturing artifact plain data. Artifact schema,
 * version dispatch, transition replay and axes belong to the caller.
 */
export declare const captureBoundedCanonicalReceiptOperation: (input: unknown, kind: PortableReceiptCaptureKind, validateMember: ReceiptCapturedMemberValidator, preflightHistoryLimits: ReceiptCapturedHistoryLimitPreflight) => CanonicalReceiptCaptureOutcome;
export type CapturedCanonicalQueryOperation = CapturedCanonicalReceiptOperation;
export type CanonicalQueryCaptureOutcome = Readonly<{
    status: "CAPTURED";
    capture: CapturedCanonicalQueryOperation;
}> | Readonly<{
    status: "INVALID_INPUT" | "UNSUPPORTED_VERSION";
}>;
/**
 * @internal Section9 two-stage capture. Version precedes own-key enumeration;
 * supported bodies share one graph memo, occurrence budget and original-key
 * metadata. Query histories defer base/schema semantics until both snapshots
 * are structurally captured, preserving input-before-state failure precedence.
 */
export declare const captureBoundedCanonicalQueryOperation: (input: unknown, kind: "WHY" | "RESPONSIBLE" | "SURVIVES") => CanonicalQueryCaptureOutcome;
/** Tests only the module-private identity of an event-data shape failure. */
export declare const isCanonicalEventDataShapeError: (error: unknown) => boolean;
/**
 * @internal Schema-owned event-data capture. Unlike the general public
 * capture, this boundary fixes the event container depth and directly fences
 * the one containing event. Callers cannot assert either fact or supply a
 * previously observed prototype.
 */
export declare const captureBoundedCanonicalEventData: (value: object, containingEvent: object, maxCanonicalBytes: number) => BoundedCanonicalCapture<Readonly<Record<string, unknown>>>;
/** Exact `continuity-canonical/0.2` text, with no whitespace or trailing newline. */
export declare const canonicalEncode: (value: unknown) => string;
/**
 * Deep immutable phase-one snapshot. Malformed Unicode spellings and invalid
 * numeric designated scalars remain available to later typed validation but
 * have no canonical text and count as fixed 32-byte classifications; every
 * other structural and finite bound is identical to strict canonical capture.
 */
export declare const immutableProtocolValue: <T>(value: T) => T;
/**
 * Immutable input snapshot that retains every originally present record key,
 * including undefined fields omitted by canonical encoding. This is a capture,
 * not schema validation: consumers must still validate their closed records.
 * Only the first capture observes caller-owned data; reconstruction traverses
 * its immutable snapshot and private key metadata, retaining shared aliases.
 */
export declare const immutableProtocolInput: <T>(value: T) => T;
/** Arrays entering schema-sensitive logic must contain only dense indexed data. */
export declare const isDenseArray: (value: unknown, maximumLength?: number) => value is readonly unknown[];
export declare const hashCanonical: (value: unknown) => ContentHash;
export declare const hashEventHistory: (events: readonly unknown[]) => ContentHash;
/**
 * @internal Inclusive semantic commitments for every prefix of one captured
 * event history. The complete wrapper is captured first so aliases, nesting,
 * list density, Unicode, and aggregate bytes have exactly the one-shot
 * history-hash boundary. Each provenance-bound event is then canonically
 * encoded once and absorbed into one continuing Keccak state.
 */
export declare const hashEventHistoryPrefixes: (events: readonly unknown[]) => readonly ContentHash[];
export {};
