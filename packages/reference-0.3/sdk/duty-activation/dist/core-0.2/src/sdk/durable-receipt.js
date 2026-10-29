import { immutableProtocolInput, proposePortableReceiptRecord } from "../core/index.js";
import { PortableStoreConflictError } from "../indexer/portable-file-event-store.js";
const unavailable = (recordMayHavePersisted) => Object.freeze({ status: "UNAVAILABLE", recordMayHavePersisted,
    reason: "Receipt persistence could not be established; inspect the durable history before another attempt." });
const capturedHead = (input) => {
    try {
        const value = immutableProtocolInput(input);
        if (value === null || typeof value !== "object" || Array.isArray(value))
            return undefined;
        const head = value;
        if (Object.keys(head).length !== 3 ||
            !Object.hasOwn(head, "hash") || !Object.hasOwn(head, "position") || !Object.hasOwn(head, "canonicalTime") ||
            typeof head.hash !== "string" || !/^0x[0-9a-f]{64}$/.test(head.hash) ||
            typeof head.position !== "number" || !Number.isSafeInteger(head.position) || head.position < 0 || Object.is(head.position, -0) ||
            typeof head.canonicalTime !== "number" || !Number.isSafeInteger(head.canonicalTime) || head.canonicalTime < 0 || Object.is(head.canonicalTime, -0))
            return undefined;
        return head;
    }
    catch {
        return undefined;
    }
};
const sameHead = (left, right) => left.hash === right.hash && left.position === right.position && left.canonicalTime === right.canonicalTime;
/** Artifact-aware local producer. The configured store supplies conditional persistence. */
export class DurableReceiptCoordinator {
    store;
    constructor(store) { this.store = store; }
    record(input) {
        let proposal;
        try {
            proposal = proposePortableReceiptRecord(input);
        }
        catch {
            return unavailable(false);
        }
        if (proposal.status !== "PROPOSED")
            return proposal;
        try {
            const acknowledged = capturedHead(this.store.appendAtExpectedHead(proposal.recordEvent, proposal.expectedHead));
            if (acknowledged === undefined || !sameHead(acknowledged, proposal.newHead))
                return unavailable(true);
            return Object.freeze({ operationVersion: "continuity-receipt-record-admission/0.2", status: "ADMITTED",
                recordEvent: proposal.recordEvent, newHead: acknowledged, verification: proposal.verification });
        }
        catch (error) {
            if (error instanceof PortableStoreConflictError) {
                const observedHead = capturedHead(error.observedHead);
                if (observedHead === undefined)
                    return unavailable(false);
                return Object.freeze({ operationVersion: "continuity-receipt-record-admission/0.2", status: "CONFLICT",
                    expectedHead: proposal.expectedHead, observedHead });
            }
            // A configured append can fail before writing or after fsync but before
            // returning its acknowledgment. Neither exception proves non-persistence.
            return unavailable(true);
        }
    }
}
