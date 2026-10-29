import { captureBoundedCanonicalQueryOperation } from "./canonical.js";
import { preflightCapturedPortableReceiptHistoryLimits, validateCapturedPortableQueryInput } from "./event-schema.js";
/** One caller observation; all subsequent work consumes the detached snapshot. */
export const capturePortableQueryInput = (input, kind) => {
    const captured = captureBoundedCanonicalQueryOperation(input, kind);
    if (captured.status !== "CAPTURED")
        return captured;
    const { value } = captured.capture;
    if (!validateCapturedPortableQueryInput(captured.capture, kind, value))
        return { status: "INVALID_INPUT" };
    const observed = value.observedEvents;
    const evaluation = (value.evaluationEvents ?? observed);
    if (preflightCapturedPortableReceiptHistoryLimits(captured.capture, [evaluation, observed]) === "LIMIT") {
        return { status: "INVALID_INPUT" };
    }
    return captured;
};
