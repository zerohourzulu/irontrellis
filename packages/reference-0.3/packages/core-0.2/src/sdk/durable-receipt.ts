import { immutableProtocolInput, proposePortableReceiptRecord } from "../core/index.ts";
import type { PortableHistoryHead, PortableReceiptRecordAdmissionResult } from "../core/index.ts";
import { PortableFileEventStore, PortableStoreConflictError } from "../indexer/portable-file-event-store.ts";

/** Local persistence uncertainty is separate from the portable result union. */
export type DurableReceiptRecordResult = PortableReceiptRecordAdmissionResult | Readonly<{
  status: "UNAVAILABLE";
  recordMayHavePersisted: boolean;
  reason: string;
}>;

const unavailable = (recordMayHavePersisted: boolean): DurableReceiptRecordResult =>
  Object.freeze({ status: "UNAVAILABLE", recordMayHavePersisted,
    reason: "Receipt persistence could not be established; inspect the durable history before another attempt." });

const capturedHead = (input: unknown): PortableHistoryHead | undefined => {
  try {
    const value = immutableProtocolInput(input);
    if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
    const head = value as Record<string, unknown>;
    if (Object.keys(head).length !== 3 ||
        !Object.hasOwn(head, "hash") || !Object.hasOwn(head, "position") || !Object.hasOwn(head, "canonicalTime") ||
        typeof head.hash !== "string" || !/^0x[0-9a-f]{64}$/.test(head.hash) ||
        typeof head.position !== "number" || !Number.isSafeInteger(head.position) || head.position < 0 || Object.is(head.position, -0) ||
        typeof head.canonicalTime !== "number" || !Number.isSafeInteger(head.canonicalTime) || head.canonicalTime < 0 || Object.is(head.canonicalTime, -0)) return undefined;
    return head as PortableHistoryHead;
  } catch { return undefined; }
};

const sameHead = (left: PortableHistoryHead, right: PortableHistoryHead): boolean =>
  left.hash === right.hash && left.position === right.position && left.canonicalTime === right.canonicalTime;

/** Artifact-aware local producer. The configured store supplies conditional persistence. */
export class DurableReceiptCoordinator {
  readonly store: PortableFileEventStore;

  constructor(store: PortableFileEventStore) { this.store = store; }

  record(input: unknown): DurableReceiptRecordResult {
    let proposal: ReturnType<typeof proposePortableReceiptRecord>;
    try { proposal = proposePortableReceiptRecord(input); }
    catch { return unavailable(false); }
    if (proposal.status !== "PROPOSED") return proposal;
    try {
      const acknowledged = capturedHead(this.store.appendAtExpectedHead(proposal.recordEvent, proposal.expectedHead));
      if (acknowledged === undefined || !sameHead(acknowledged, proposal.newHead)) return unavailable(true);
      return Object.freeze({ operationVersion: "continuity-receipt-record-admission/0.2", status: "ADMITTED",
        recordEvent: proposal.recordEvent, newHead: acknowledged, verification: proposal.verification });
    } catch (error) {
      if (error instanceof PortableStoreConflictError) {
        const observedHead = capturedHead(error.observedHead);
        if (observedHead === undefined) return unavailable(false);
        return Object.freeze({ operationVersion: "continuity-receipt-record-admission/0.2", status: "CONFLICT",
          expectedHead: proposal.expectedHead, observedHead });
      }
      // A configured append can fail before writing or after fsync but before
      // returning its acknowledgment. Neither exception proves non-persistence.
      return unavailable(true);
    }
  }
}
