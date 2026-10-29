import { type CanonicalQueryCaptureOutcome } from "./canonical.ts";
import type { PortableQueryKind } from "./portable-query-codec.ts";
/** One caller observation; all subsequent work consumes the detached snapshot. */
export declare const capturePortableQueryInput: (input: unknown, kind: PortableQueryKind) => CanonicalQueryCaptureOutcome;
