import { capacityOf } from "../capacity.js";
import { CONTINUATION_PROFILE as P, exportContinuationEvents } from "../history.js";
import { LIMITS, encodeEvent, integer, fail } from "./codec.js";
/** Pure budget arithmetic, not a history verifier or permission to write. */
export function projectHistoryUsage(usage, reserve) {
    const project = (count) => Object.freeze({ events: usage.events + count, canonicalBytes: usage.canonicalBytes + count * P.maxEventBytes,
        nodes: usage.nodes + count * P.maxEventNodes, encodedBytes: usage.encodedBytes + count * LIMITS.eventBytes, segments: usage.segments + count });
    const fits = (value) => value.events <= P.maxEvents && value.canonicalBytes <= P.maxCanonicalHistoryBytes && value.nodes <= P.maxHistoryNodes &&
        value.encodedBytes <= LIMITS.historyBytes && value.segments <= LIMITS.segments;
    const projected = project(reserve), compatible = fits(projected);
    return Object.freeze({ projected, compatible, canDeclareJob: compatible && fits(project(reserve + 12)) });
}
/** Reuse the unchanged eleven-kind/eight-control census over the ENTIRE replayed
 * case, plus six separate future records for each activated duty. */
export function historyCapacity(history, segments) {
    const events = exportContinuationEvents(history), legacy = capacityOf(events);
    if (!integer(segments, LIMITS.segments) || segments < 1 || segments > events.length)
        fail('SEGMENT_LIMIT');
    const reserve = legacy.lifecycleReserved + legacy.controlReserved + (legacy.dutyReserved ?? 0);
    const encodedBytes = events.reduce((sum, event) => sum + encodeEvent(event).length, 0);
    const usage = { events: events.length, canonicalBytes: history.metrics.canonicalBytes, nodes: history.metrics.nodes, encodedBytes, segments };
    const { projected, compatible, canDeclareJob } = projectHistoryUsage(usage, reserve);
    return Object.freeze({ profile: P.version, compatible, canDeclareJob, mode: !compatible ? 'INCOMPATIBLE' : canDeclareJob ? 'OPEN' : 'DRAINING',
        reservedEvents: reserve, lifecycleReserved: legacy.lifecycleReserved, controlReserved: legacy.controlReserved,
        ...(legacy.dutyReserved === undefined ? {} : { activatedDuties: legacy.activatedDuties, dutyReserved: legacy.dutyReserved }),
        reservedByRecordType: legacy.reservedByRecordType, usage: Object.freeze(usage), projected: Object.freeze(projected), grantsAuthority: false });
}
/** Conservative pre-sign room check. The unsigned transition is census input only,
 * never replayed state or authentication; the actual signed event is replayed at commit. */
export function hasAdministrativeRoom(history, transition, segments) {
    const events = exportContinuationEvents(history);
    if (!integer(segments, LIMITS.segments) || segments < 1 || segments > events.length)
        return false;
    // These later event forms cannot consume or release activation reservations
    // until D03 supplies their complete interpretation.
    const type = transition?.type;
    if (type === 'ATTEMPT_DUTY_DISPOSITION_RECORDED' || type === 'ATTEMPT_DUTY_CONTEST_RECORDED')
        return false;
    const after = capacityOf([...events, transition]);
    const reserve = after.lifecycleReserved + after.controlReserved + (after.dutyReserved ?? 0);
    const encoded = events.reduce((sum, e) => sum + encodeEvent(e).length, 0);
    return projectHistoryUsage({ events: events.length + 1, canonicalBytes: history.metrics.canonicalBytes + P.maxEventBytes,
        nodes: history.metrics.nodes + P.maxEventNodes, encodedBytes: encoded + LIMITS.eventBytes, segments: segments + 1 }, reserve).compatible;
}
