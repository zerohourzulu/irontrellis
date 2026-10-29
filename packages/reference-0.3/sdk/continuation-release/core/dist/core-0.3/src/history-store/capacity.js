import { capacityOf } from "../capacity.js";
import { CONTINUATION_PROFILE as P, exportContinuationEvents } from "../history.js";
import { LIMITS, encodeEvent, integer, fail } from "./codec.js";
/** Reuse the existing eleven-kind/eight-control census over the ENTIRE replayed case. */
export function historyCapacity(history, segments) {
    const events = exportContinuationEvents(history), legacy = capacityOf(events);
    if (!integer(segments, LIMITS.segments) || segments < 1 || segments > events.length)
        fail('SEGMENT_LIMIT');
    const reserve = legacy.lifecycleReserved + legacy.controlReserved;
    const encodedBytes = events.reduce((sum, event) => sum + encodeEvent(event).length, 0);
    const usage = { events: events.length, canonicalBytes: history.metrics.canonicalBytes, nodes: history.metrics.nodes, encodedBytes, segments };
    const projected = { events: usage.events + reserve, canonicalBytes: usage.canonicalBytes + reserve * P.maxEventBytes,
        nodes: usage.nodes + reserve * P.maxEventNodes, encodedBytes: usage.encodedBytes + reserve * LIMITS.eventBytes, segments: segments + reserve };
    const compatible = projected.events <= P.maxEvents && projected.canonicalBytes <= P.maxCanonicalHistoryBytes && projected.nodes <= P.maxHistoryNodes &&
        projected.encodedBytes <= LIMITS.historyBytes && projected.segments <= LIMITS.segments;
    const canDeclareJob = compatible && projected.events + 12 <= P.maxEvents && projected.canonicalBytes + 12 * P.maxEventBytes <= P.maxCanonicalHistoryBytes &&
        projected.nodes + 12 * P.maxEventNodes <= P.maxHistoryNodes && projected.encodedBytes + 12 * LIMITS.eventBytes <= LIMITS.historyBytes && projected.segments + 12 <= LIMITS.segments;
    return Object.freeze({ profile: P.version, compatible, canDeclareJob, mode: !compatible ? 'INCOMPATIBLE' : canDeclareJob ? 'OPEN' : 'DRAINING',
        reservedEvents: reserve, lifecycleReserved: legacy.lifecycleReserved, controlReserved: legacy.controlReserved,
        reservedByRecordType: legacy.reservedByRecordType, usage: Object.freeze(usage), projected: Object.freeze(projected), grantsAuthority: false });
}
/** Conservative pre-sign room check. The unsigned transition is census input only,
 * never replayed state or authentication; the actual signed event is replayed at commit. */
export function hasAdministrativeRoom(history, transition, segments) {
    const events = exportContinuationEvents(history), after = capacityOf([...events, transition]);
    const reserve = after.lifecycleReserved + after.controlReserved;
    const encoded = events.reduce((sum, e) => sum + encodeEvent(e).length, 0);
    return events.length + 1 + reserve <= P.maxEvents && history.metrics.canonicalBytes + (1 + reserve) * P.maxEventBytes <= P.maxCanonicalHistoryBytes &&
        history.metrics.nodes + (1 + reserve) * P.maxEventNodes <= P.maxHistoryNodes && encoded + (1 + reserve) * LIMITS.eventBytes <= LIMITS.historyBytes && segments + 1 + reserve <= LIMITS.segments;
}
