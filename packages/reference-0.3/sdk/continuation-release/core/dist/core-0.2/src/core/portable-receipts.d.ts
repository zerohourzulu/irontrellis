/** Portable artifact verification and pure reference producer composition. */
import { type ContentHash } from "./canonical.ts";
import { type AcceptedCanonicalEventShape } from "./event-schema.ts";
import { PORTABLE_RECEIPT_RECORD_ADMISSION_VERSION as RECORD_VERSION, type PortableReceiptArtifact, type PortableReceiptVerificationEvaluated, type PortableReceiptVerificationResult, type PortableReceiptRecordAdmissionResult } from "./portable-receipt-codec.ts";
import { type PortableHistoryHead } from "./portable-replay.ts";
type Event = AcceptedCanonicalEventShape;
/** Exact Section8.3/8.4 operation. Every independently checkable axis is retained. */
export declare const verifyPortableReceipt: (input: unknown) => PortableReceiptVerificationResult;
export type PortableReceiptRecordProposal = Exclude<PortableReceiptRecordAdmissionResult, {
    status: "ADMITTED";
}> | Readonly<{
    operationVersion: typeof RECORD_VERSION;
    status: "PROPOSED";
    expectedHead: PortableHistoryHead;
    recordEvent: Event;
    newHead: PortableHistoryHead;
    verification: PortableReceiptVerificationEvaluated;
}>;
/** Pure prospective Section8.5 composition; PROPOSED never claims persistence. */
export declare const proposePortableReceiptRecord: (input: unknown) => PortableReceiptRecordProposal;
export type CreatePortableReceiptInput = Readonly<{
    events: readonly Event[];
    intentId: string;
    issuedAt: number;
    externalOutcome: "NOT_PROVEN" | "SIMULATED";
}>;
export type PortableReceiptSigner = Readonly<{
    keyId: string;
    signHash: (hash: ContentHash) => Promise<`0x${string}`>;
}>;
/** Configured local signing helper; a returned artifact is not a record witness. */
export declare const createPortableReceipt: (input: CreatePortableReceiptInput, signer: PortableReceiptSigner) => Promise<PortableReceiptArtifact>;
export {};
