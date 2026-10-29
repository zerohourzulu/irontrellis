import { capacityOf, dutyReservationOf } from '../capacity.ts';
import { CONTINUATION_PROFILE as P, exportContinuationEvents, type VerifiedHistory } from '../history.ts';
import { LIMITS, encodeEvent, integer, fail } from './codec.ts';
type Usage = Readonly<{ events: number; canonicalBytes: number; nodes: number; encodedBytes: number; segments: number }>;
/** Pure budget arithmetic, not a history verifier or permission to write. */
export function projectHistoryUsage(usage: Usage, reserve: number) {
    const project = (count: number) => Object.freeze({ events: usage.events + count, canonicalBytes: usage.canonicalBytes + count * P.maxEventBytes,
        nodes: usage.nodes + count * P.maxEventNodes, encodedBytes: usage.encodedBytes + count * LIMITS.eventBytes, segments: usage.segments + count });
    const fits = (value: Usage) => value.events <= P.maxEvents && value.canonicalBytes <= P.maxCanonicalHistoryBytes && value.nodes <= P.maxHistoryNodes &&
        value.encodedBytes <= LIMITS.historyBytes && value.segments <= LIMITS.segments;
    const projected = project(reserve), compatible = fits(projected);
    return Object.freeze({ projected, compatible, canDeclareJob: compatible && fits(project(reserve + 12)) });
}
/** Reuse the unchanged eleven-kind/eight-control census over the ENTIRE replayed
 * case, plus each activated duty's unused four-disposition/two-contest quota. */
export function historyCapacity(history: VerifiedHistory, segments: number) {
    const events = exportContinuationEvents(history), legacy = capacityOf(events);
    if (!integer(segments, LIMITS.segments) || segments < 1 || segments > events.length)
        fail('SEGMENT_LIMIT');
    const reserve = legacy.lifecycleReserved + legacy.controlReserved + (legacy.dutyReserved ?? 0);
    const encodedBytes = events.reduce((sum, event) => sum + encodeEvent(event).length, 0);
    const usage = { events: events.length, canonicalBytes: history.metrics.canonicalBytes, nodes: history.metrics.nodes, encodedBytes, segments };
    const budget = projectHistoryUsage(usage, reserve);
    const projected = budget.projected, compatible = budget.compatible && dutyReservationOf(events).withinLimits;
    const canDeclareJob = compatible && budget.canDeclareJob;
    return Object.freeze({ profile: P.version, compatible, canDeclareJob, mode: !compatible ? 'INCOMPATIBLE' : canDeclareJob ? 'OPEN' : 'DRAINING',
        reservedEvents: reserve, lifecycleReserved: legacy.lifecycleReserved, controlReserved: legacy.controlReserved,
        ...(legacy.dutyReserved === undefined ? {} : { activatedDuties: legacy.activatedDuties, dutyReserved: legacy.dutyReserved }),
        reservedByRecordType: legacy.reservedByRecordType, usage: Object.freeze(usage), projected: Object.freeze(projected), grantsAuthority: false });
}
/** Conservative pre-sign room check. The unsigned transition is census input only,
 * never replayed state or authentication; the actual signed event is replayed at commit. */
export function hasAdministrativeRoom(history: VerifiedHistory, transition: unknown, segments: number) {
    const events = exportContinuationEvents(history);
    if (!integer(segments, LIMITS.segments) || segments < 1 || segments > events.length) return false;
    const candidates = [...events, transition as any];
    // Only the corresponding activated duty's quota can fund a D1 record.
    // Eligibility, exact effect and signatures remain the engine's responsibility.
    if (!dutyReservationOf(candidates).withinLimits) return false;
    const after = capacityOf(candidates);
    const reserve = after.lifecycleReserved + after.controlReserved + (after.dutyReserved ?? 0);
    const encoded = events.reduce((sum, e) => sum + encodeEvent(e).length, 0);
    return projectHistoryUsage({ events: events.length + 1, canonicalBytes: history.metrics.canonicalBytes + P.maxEventBytes,
        nodes: history.metrics.nodes + P.maxEventNodes, encodedBytes: encoded + LIMITS.eventBytes, segments: segments + 1 }, reserve).compatible;
}
