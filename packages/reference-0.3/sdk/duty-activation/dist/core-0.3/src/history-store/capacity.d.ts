import { type VerifiedHistory } from '../history.ts';
type Usage = Readonly<{
    events: number;
    canonicalBytes: number;
    nodes: number;
    encodedBytes: number;
    segments: number;
}>;
/** Pure budget arithmetic, not a history verifier or permission to write. */
export declare function projectHistoryUsage(usage: Usage, reserve: number): Readonly<{
    projected: Readonly<{
        events: number;
        canonicalBytes: number;
        nodes: number;
        encodedBytes: number;
        segments: number;
    }>;
    compatible: boolean;
    canDeclareJob: boolean;
}>;
/** Reuse the unchanged eleven-kind/eight-control census over the ENTIRE replayed
 * case, plus six separate future records for each activated duty. */
export declare function historyCapacity(history: VerifiedHistory, segments: number): Readonly<{
    reservedByRecordType: Readonly<{
        [k: string]: number;
    }>;
    usage: Readonly<{
        events: number;
        canonicalBytes: number;
        nodes: number;
        encodedBytes: number;
        segments: number;
    }>;
    projected: Readonly<Readonly<{
        events: number;
        canonicalBytes: number;
        nodes: number;
        encodedBytes: number;
        segments: number;
    }>>;
    grantsAuthority: false;
    activatedDuties?: number | undefined;
    dutyReserved?: number | undefined;
    profile: "continuity-segmented-local/1";
    compatible: boolean;
    canDeclareJob: boolean;
    mode: "OPEN" | "INCOMPATIBLE" | "DRAINING";
    reservedEvents: number;
    lifecycleReserved: number;
    controlReserved: number;
}>;
/** Conservative pre-sign room check. The unsigned transition is census input only,
 * never replayed state or authentication; the actual signed event is replayed at commit. */
export declare function hasAdministrativeRoom(history: VerifiedHistory, transition: unknown, segments: number): boolean;
export {};
