import {
  captureBoundedCanonicalReceiptOperation,
  type CanonicalReceiptCaptureOutcome,
  type PortableReceiptCaptureKind,
} from "./canonical.ts";
import {
  preflightCapturedPortableReceiptHistoryLimits,
  validateCapturedPortableReceiptValue,
} from "./event-schema.ts";

/** Package-internal capture boundary; artifact semantics and replay follow it. */
export const capturePortableReceiptInput = (
  input: unknown,
  kind: PortableReceiptCaptureKind,
): CanonicalReceiptCaptureOutcome =>
  captureBoundedCanonicalReceiptOperation(
    input,
    kind,
    validateCapturedPortableReceiptValue,
    preflightCapturedPortableReceiptHistoryLimits,
  );
