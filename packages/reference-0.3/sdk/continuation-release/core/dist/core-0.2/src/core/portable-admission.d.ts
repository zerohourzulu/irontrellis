import { type ContentHash } from "./canonical.ts";
import type { AcceptedCanonicalEventShape } from "./event-schema.ts";
import { PORTABLE_INTENT_ADMISSION_VERSION, type PortableActionRequest, type PortableAuthorizationProof, type PortableConsequentialBinding, type PortableReplayAuthorizationDeny, type PortableReplayAuthorizationIndeterminate } from "./portable-authority-engine.ts";
import { type PortableAuthorizationDomain, type PortableHistoryHead } from "./portable-replay.ts";
export { PORTABLE_INTENT_ADMISSION_VERSION } from "./portable-authority-engine.ts";
export type PortableIntentAdmissionInput = Readonly<{
    operationVersion: typeof PORTABLE_INTENT_ADMISSION_VERSION;
    events: readonly AcceptedCanonicalEventShape[];
    expectedHistoryHead: PortableHistoryHead;
    admissionEventId: string;
    domain: PortableAuthorizationDomain;
    policyVersion: string;
    request: PortableActionRequest;
    evaluationTime: number;
    binding: PortableConsequentialBinding;
}>;
export type PortableIntentAdmissionEvent = Readonly<{
    id: string;
    type: "TRANSACTION_INTENT_ADMITTED";
    timestamp: number;
    data: Readonly<{
        intentId: string;
        evaluationTime: number;
        expectedHistoryHead: PortableHistoryHead;
        authorizationProof: PortableAuthorizationProof;
        runtimeAuthorizationHash: ContentHash;
        runtimeSignature: `0x${string}`;
    }>;
}>;
export type PortableIntentAdmissionResult = Readonly<{
    operationVersion: typeof PORTABLE_INTENT_ADMISSION_VERSION;
    status: "PROPOSED";
    authorization: PortableAuthorizationProof;
    expectedHead: PortableHistoryHead;
    admissionEvent: PortableIntentAdmissionEvent;
    prospectiveHead: PortableHistoryHead;
}> | Readonly<{
    operationVersion: typeof PORTABLE_INTENT_ADMISSION_VERSION;
    status: "RETRY";
    intentId: string;
    existingAdmissionEventId: string;
    existingAdmissionHead: PortableHistoryHead;
}> | Readonly<{
    operationVersion: typeof PORTABLE_INTENT_ADMISSION_VERSION;
    status: "DENIED";
    authorization: PortableReplayAuthorizationDeny;
}> | Readonly<{
    operationVersion: typeof PORTABLE_INTENT_ADMISSION_VERSION;
    status: "INDETERMINATE";
    authorization: PortableReplayAuthorizationIndeterminate;
}> | Readonly<{
    operationVersion: typeof PORTABLE_INTENT_ADMISSION_VERSION;
    status: "CONFLICT";
    expectedHead: PortableHistoryHead;
    observedHead: PortableHistoryHead;
}>;
/**
 * Pure Section 7.4 preparation. It captures and evaluates one operation but
 * owns no durable append capability; therefore success is only PROPOSED.
 */
export declare const proposePortableIntentAdmission: (input: unknown) => PortableIntentAdmissionResult;
