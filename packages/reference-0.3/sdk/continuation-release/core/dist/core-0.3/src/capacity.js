import { canonicalEncode, immutableProtocolValue } from "../../core-0.2/src/core/index.js";
import { PortableFileEventStore } from "../../core-0.2/src/indexer/portable-file-event-store.js";
import { ContinuityError } from "./input.js";
/** Finite ledger space, not authority, disk availability or a promise of completion. */
export const LOCAL_CAPACITY_PROFILE = Object.freeze({
    version: "continuity-managed-capacity/1", maxEvents: 96,
    maxEventBytes: 8192, maxEventArrayMembers: 32, maxEventDepth: 16,
    controlEvents: 8,
});
const lifecycle = new Set([
    "TRANSACTION_INTENT_ADMITTED", "TRANSACTION_INTENT_CONSUMED", "TRANSACTION_OUTCOME_RECORDED", "RECEIPT_RECORDED",
    "OUTCOME_OBSERVATION_RECORDED", "ATTEMPT_DUTY_CREATED", "ATTEMPT_DUTY_ASSIGNED", "ATTEMPT_DUTY_REVIEW_CLOSED",
    "OBLIGATION_CREATED", "OBLIGATION_PERFORMANCE_ASSIGNED", "OBLIGATION_STATUS_RECORDED",
]);
const control = new Set(["AUTHORITY_REVOKED", "CONTROL_EPOCH_ADVANCED", "AGENT_TERMINATED", "ROLE_TRANSFERRED", "AGENT_APPOINTED", "RUNTIME_SESSION_ADMITTED"]);
const error = (code) => { throw new ContinuityError(code); };
function bounded(event) {
    let arrays = 0, valid = true;
    const visit = (value, depth) => {
        if (depth > LOCAL_CAPACITY_PROFILE.maxEventDepth) {
            valid = false;
            return;
        }
        if (Array.isArray(value)) {
            arrays += value.length;
            for (const item of value)
                visit(item, depth + 1);
        }
        else if (value !== null && typeof value === "object")
            for (const item of Object.values(value))
                visit(item, depth + 1);
    };
    visit(event, 0);
    return valid && arrays <= LOCAL_CAPACITY_PROFILE.maxEventArrayMembers &&
        Buffer.byteLength(canonicalEncode(event)) <= LOCAL_CAPACITY_PROFILE.maxEventBytes;
}
/** Input must already be captured/replayed by the trusted caller; no decision authority. */
export function capacityOf(events) {
    const intents = new Map(), duties = new Map(), obligations = new Map();
    let started = false, controlsUsed = 0, shape = true;
    for (const event of events) {
        if (!bounded(event))
            shape = false;
        const d = event.data;
        if (event.type === "TRANSACTION_INTENT_DECLARED") {
            started = true;
            intents.set(d.intentId, new Set());
        }
        if (started && control.has(event.type))
            controlsUsed++;
        let intent = d.intentId;
        if (event.type === "ATTEMPT_DUTY_CREATED") {
            intent = d.record.sourceIntentId;
            duties.set(d.record.dutyId, intent);
        }
        if (event.type === "OBLIGATION_CREATED") {
            intent = d.record.sourceIntentId;
            obligations.set(d.record.obligationId, intent);
        }
        if (event.type === "ATTEMPT_DUTY_ASSIGNED" || event.type === "ATTEMPT_DUTY_REVIEW_CLOSED")
            intent = duties.get(d.dutyId);
        if (event.type === "OBLIGATION_PERFORMANCE_ASSIGNED" || event.type === "OBLIGATION_STATUS_RECORDED")
            intent = obligations.get(d.obligationId);
        if (intent && lifecycle.has(event.type))
            intents.get(intent)?.add(event.type);
    }
    const reservedByRecordType = Object.freeze(Object.fromEntries([...lifecycle].map(type => [type, [...intents.values()].filter(seen => !seen.has(type)).length])));
    const lifecycleReserved = [...intents.values()].reduce((sum, seen) => sum + lifecycle.size - seen.size, 0);
    const controlReserved = Math.max(0, LOCAL_CAPACITY_PROFILE.controlEvents - controlsUsed);
    const reserved = lifecycleReserved + controlReserved;
    const free = LOCAL_CAPACITY_PROFILE.maxEvents - events.length - reserved;
    const compatible = shape && free >= 0;
    return Object.freeze({ profile: LOCAL_CAPACITY_PROFILE.version, eventCount: events.length,
        maxEvents: LOCAL_CAPACITY_PROFILE.maxEvents, reservedByRecordType, declaredJobs: intents.size, lifecycleReserved, controlReserved,
        unreservedEvents: Math.max(0, free), compatible,
        mode: !compatible ? "INCOMPATIBLE" : events.length === LOCAL_CAPACITY_PROFILE.maxEvents ? "EXHAUSTED" : free < 1 + lifecycle.size ? "DRAINING" : "OPEN",
        canDeclareJob: compatible && free >= 1 + lifecycle.size,
        remainingPhysicalEvents: Math.max(0, LOCAL_CAPACITY_PROFILE.maxEvents - events.length),
        pointInTimeOnly: true, grantsAuthority: false });
}
export function assertCapacityTransition(events, next) {
    if (!capacityOf(events).compatible)
        error("CAPACITY_INCOMPATIBLE");
    if (next.some(event => !bounded(event)))
        error("CAPACITY_EVENT_LIMIT");
    if (!capacityOf([...events, ...next]).compatible)
        error("CAPACITY_RESERVED");
}
/** All managed writes check the actual prefix under the existing store lock.
 * No separate reservation file exists. Raw 0.2 writers/host rollback are outside this profile.
 */
export class ManagedLocalEventStore extends PortableFileEventStore {
    withExclusiveWriter(callback) {
        return super.withExclusiveWriter(writer => callback(Object.freeze({
            readAll: () => writer.readAll(),
            appendAtExpectedHead: (input, expected) => {
                const next = immutableProtocolValue(input), events = writer.readAll();
                // Base writer remains responsible for canonical validation and the exact-head CAS.
                assertCapacityTransition(events, [next]);
                return writer.appendAtExpectedHead(next, expected);
            },
        })));
    }
    appendAll(input) {
        const stable = immutableProtocolValue(input);
        // Only genesis creation uses batch append. Ordinary writes must use the managed CAS.
        if (this.readAll().length || stable.length !== 2 || stable[0]?.type !== "DEPLOYMENT_INITIALIZED" || stable[1]?.type !== "PRINCIPAL_CREATED")
            error("CAPACITY_BATCH_UNSUPPORTED");
        assertCapacityTransition([], stable);
        super.appendAll(stable);
    }
    append(_event) { error("CAPACITY_EXPECTED_HEAD_REQUIRED"); }
}
