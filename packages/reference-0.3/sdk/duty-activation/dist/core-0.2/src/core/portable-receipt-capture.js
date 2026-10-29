import { captureBoundedCanonicalReceiptOperation, } from "./canonical.js";
import { preflightCapturedPortableReceiptHistoryLimits, validateCapturedPortableReceiptValue, } from "./event-schema.js";
/** Package-internal capture boundary; artifact semantics and replay follow it. */
export const capturePortableReceiptInput = (input, kind) => captureBoundedCanonicalReceiptOperation(input, kind, validateCapturedPortableReceiptValue, preflightCapturedPortableReceiptHistoryLimits);
