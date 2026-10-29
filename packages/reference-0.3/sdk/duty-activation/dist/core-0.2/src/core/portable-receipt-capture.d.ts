import { type CanonicalReceiptCaptureOutcome, type PortableReceiptCaptureKind } from "./canonical.ts";
/** Package-internal capture boundary; artifact semantics and replay follow it. */
export declare const capturePortableReceiptInput: (input: unknown, kind: PortableReceiptCaptureKind) => CanonicalReceiptCaptureOutcome;
