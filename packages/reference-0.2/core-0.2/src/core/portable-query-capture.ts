import { captureBoundedCanonicalQueryOperation, type CanonicalQueryCaptureOutcome } from "./canonical.ts";
import { preflightCapturedPortableReceiptHistoryLimits, validateCapturedPortableQueryInput } from "./event-schema.ts";
import type { PortableQueryKind } from "./portable-query-codec.ts";

/** One caller observation; all subsequent work consumes the detached snapshot. */
export const capturePortableQueryInput = (input: unknown, kind: PortableQueryKind): CanonicalQueryCaptureOutcome => {
  const captured = captureBoundedCanonicalQueryOperation(input, kind);
  if (captured.status !== "CAPTURED") return captured;
  const { value } = captured.capture;
  if (!validateCapturedPortableQueryInput(captured.capture, kind, value)) return { status: "INVALID_INPUT" };
  const observed = value.observedEvents as readonly unknown[];
  const evaluation = (value.evaluationEvents ?? observed) as readonly unknown[];
  if (preflightCapturedPortableReceiptHistoryLimits(captured.capture, [evaluation, observed]) === "LIMIT") {
    return { status: "INVALID_INPUT" };
  }
  return captured;
};
