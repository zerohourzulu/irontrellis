import type { AcceptedCanonicalEventShape } from "./event-schema.ts";
import type { PortableIntentAdmissionEvent } from "./portable-admission.ts";
import { PORTABLE_ADAPTER_SUBMISSION_VERSION, type PortableAdapterIdentity } from "./portable-adapter-engine.ts";
import { type PortableAuthorizationDomain, type PortableHistoryHead, type PortableIntentConsumptionRecord, type PortableIntentOutcomeRecord } from "./portable-replay.ts";
export type PortableAdapterIdentityInput = Readonly<{
    operationVersion: typeof PORTABLE_ADAPTER_SUBMISSION_VERSION;
    domain: PortableAuthorizationDomain;
    intentId: string;
    admissionEvent: PortableIntentAdmissionEvent;
    admittedHistory: readonly AcceptedCanonicalEventShape[];
}>;
export type PortableAdapterIdentityResult = Readonly<PortableAdapterIdentity & {
    operationVersion: typeof PORTABLE_ADAPTER_SUBMISSION_VERSION;
}>;
export type PortableAdmittedIntentInspection = Readonly<{
    status: "ABSENT";
    head: PortableHistoryHead;
}> | Readonly<{
    status: "ADMITTED";
    head: PortableHistoryHead;
    admissionEvent: PortableIntentAdmissionEvent;
    admissionHead: PortableHistoryHead;
    adapterIdentity: PortableAdapterIdentity;
    currentControl: boolean;
    consumption?: PortableIntentConsumptionRecord;
    terminal?: PortableIntentOutcomeRecord;
    latestOutcome?: PortableIntentOutcomeRecord;
}>;
/**
 * Reconstruct one admission and its current consumption-control facts from the
 * supplied history. Only the configured coordinator can establish durability,
 * serialize a fresh observation and mint its separate local invocation token.
 */
export declare const inspectPortableAdmittedIntent: (events: unknown, intentId: unknown, useTime: unknown) => PortableAdmittedIntentInspection;
/** Valid-input-only Portable Contract §10.1 derivation; rejects before returning. */
export declare const derivePortableAdapterIdentity: (input: unknown) => PortableAdapterIdentityResult;
