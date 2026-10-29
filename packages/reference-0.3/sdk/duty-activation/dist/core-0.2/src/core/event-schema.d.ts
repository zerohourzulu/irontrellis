import { type CapturedCanonicalReplayEvent, type CapturedCanonicalReplayBody } from "./canonical.ts";
export declare const CORE_EVENT_TYPES: readonly ["DEPLOYMENT_INITIALIZED", "PRINCIPAL_CREATED", "AGENT_CREATED", "ROLE_CREATED", "SUCCESSION_RULE_DECLARED", "AGENT_APPOINTED", "AGENT_UNAPPOINTED", "ROLE_TRANSFERRED", "RUNTIME_SESSION_ADMITTED", "CONTROL_EPOCH_ADVANCED", "AUTHORITY_GRANTED", "AUTHORITY_REVOKED", "TRANSACTION_INTENT_DECLARED", "TRANSACTION_INTENT_ADMITTED", "TRANSACTION_INTENT_CONSUMED", "TRANSACTION_OUTCOME_RECORDED", "RECEIPT_RECORDED", "OBLIGATION_CREATED", "OBLIGATION_PERFORMANCE_ASSIGNED", "OBLIGATION_STATUS_RECORDED", "AGENT_TERMINATED", "OUTCOME_OBSERVATION_RECORDED", "ATTEMPT_DUTY_CREATED", "ATTEMPT_DUTY_ASSIGNED", "ATTEMPT_DUTY_REVIEW_CLOSED", "ATTEMPT_DUTY_POLICY_ACTIVATED"];
export type CoreEventType = (typeof CORE_EVENT_TYPES)[number];
export declare const isCoreEventType: (value: unknown) => value is CoreEventType;
/** The exact zero-based Section 5.1 rank, or undefined for an unknown type. */
export declare const coreEventTypeRank: (value: unknown) => number | undefined;
export interface AcceptedCanonicalEventShape {
    readonly id: string;
    readonly type: CoreEventType;
    readonly timestamp: number;
    readonly data: Readonly<Record<string, unknown>>;
}
export interface AcceptedCanonicalBaseEventShape {
    readonly id: string;
    readonly type: string;
    readonly timestamp: number;
    readonly data: Readonly<Record<string, unknown>>;
}
export type CapturedCanonicalBaseEvent = Readonly<{
    readonly eventPosition: number;
    readonly event: AcceptedCanonicalBaseEventShape;
}>;
export type BaseEventShapeValidationResult = {
    readonly ok: true;
    readonly baseEvent: CapturedCanonicalBaseEvent;
} | {
    readonly ok: false;
    readonly code: "EVENT_ENVELOPE_INVALID" | "EVENT_DATA_INVALID";
    readonly reason: string;
};
export interface DeclaredVersionSet {
    readonly eventSchemaVersion: string;
    readonly receiptSchemaVersion: string;
    readonly queryEnvelopeVersion: string;
    readonly authorizationProofVersion: string;
    readonly runtimeAuthorizationVersion: string;
    readonly administrativeAuthorizationVersion: string;
    readonly signatureScheme: string;
}
export interface AcceptedGenesisVersionProbe extends AcceptedCanonicalBaseEventShape {
    readonly type: "DEPLOYMENT_INITIALIZED";
    readonly data: Readonly<Record<string, unknown>> & {
        readonly versions: DeclaredVersionSet;
    };
}
export type GenesisVersionProbeValidationResult = {
    readonly ok: true;
    readonly probe: AcceptedGenesisVersionProbe;
    readonly versions: DeclaredVersionSet;
} | {
    readonly ok: false;
    readonly code: "EVENT_DATA_INVALID";
    readonly reason: string;
};
export type EventShapeFailureCode = "EVENT_ENVELOPE_INVALID" | "EVENT_TYPE_UNSUPPORTED" | "EVENT_DATA_INVALID";
export type EventShapeValidationResult = {
    readonly ok: true;
    readonly typeRank: number;
    readonly event: AcceptedCanonicalEventShape;
} | {
    readonly ok: false;
    readonly code: EventShapeFailureCode;
    readonly reason: string;
};
/** @internal Authentic provenance for one snapshot-only named hard-limit failure. */
export declare const isCoreSchemaLimitFailure: (value: unknown) => boolean;
/**
 * @internal Validate an already captured receipt value using its original field
 * presence. The capture owns generic limits; this layer adds named limits and
 * exact schema without wrapping the receipt in an event's 1 MiB data budget.
 */
export declare const validateCapturedPortableReceiptValue: (capture: {
    readonly capturedRecordKeys: (value: unknown) => readonly string[] | undefined;
}, kind: "ARTIFACT" | "DOMAIN" | "HISTORY_HEAD" | "IDENTIFIER" | "TIME", value: unknown) => "VALID" | "INVALID" | "LIMIT" | "UNSUPPORTED";
/** Query input shape, before replay; request scalars retain phase-two classification. */
export declare const validateCapturedPortableQueryInput: (capture: {
    readonly capturedRecordKeys: (value: unknown) => readonly string[] | undefined;
}, kind: "WHY" | "RESPONSIBLE" | "SURVIVES", value: Readonly<Record<string, unknown>>) => boolean;
/** Closed disclosure schema is evaluated at the later disclosure phase. */
export declare const validateCapturedPortableQueryDisclosure: (capture: {
    readonly capturedRecordKeys: (value: unknown) => readonly string[] | undefined;
}, value: unknown) => boolean;
type CapturedBaseEventSource = Readonly<{
    readonly capturedRecordKeys: (value: unknown) => readonly string[] | undefined;
    readonly capturedCanonicalBytes: (value: unknown) => number | undefined;
}>;
/**
 * @internal Validate one event envelope from the shared replay snapshot.
 * This function never observes caller-owned data and applies no event schema.
 */
export declare const validateCapturedReplayBaseCandidate: (candidate: unknown, eventPosition: number, source: CapturedBaseEventSource) => BaseEventShapeValidationResult;
export declare const validateCapturedReplayBaseEvent: (capture: CapturedCanonicalReplayBody, eventPosition: number) => BaseEventShapeValidationResult;
/** @internal Validate one provenance-bound incremental replay snapshot. */
export declare const validateIncrementallyCapturedReplayBaseEvent: (capture: CapturedCanonicalReplayEvent) => BaseEventShapeValidationResult;
/**
 * @internal Schema-independent discovery probe for a captured genesis-typed
 * base event. It accepts any well-formed declared interpreter identifiers.
 */
export declare const validateCapturedGenesisVersionProbe: (baseEvent: CapturedCanonicalBaseEvent) => GenesisVersionProbeValidationResult;
/**
 * @internal Receipt input-limit phase over already captured base histories.
 * Discover every branch before applying any current-schema payload limit.
 * Only an exact, valid VersionSet dispatches those named slots. Missing or
 * malformed discovery, unknown event types, and all ordinary payload semantics
 * remain for the consuming operation; no transition or artifact is inspected.
 */
export declare const preflightCapturedPortableReceiptHistoryLimits: (capture: CapturedBaseEventSource, histories: readonly (readonly unknown[])[]) => "VALID" | "LIMIT";
/**
 * @internal Refine one captured base event under the isolated 0.2 schema.
 * The accepted event is the same immutable object returned by base capture.
 */
export declare const refineCapturedCoreEvent: (baseEvent: CapturedCanonicalBaseEvent) => EventShapeValidationResult;
/**
 * Capture and validate one experimental 0.2 event before hashing.
 * This checks only portable shape/scalars. History order, uniqueness,
 * referential integrity, signatures, and state-transition predicates remain
 * replay responsibilities.
 */
export declare const validateCanonicalEventShape: (input: unknown) => EventShapeValidationResult;
export {};
