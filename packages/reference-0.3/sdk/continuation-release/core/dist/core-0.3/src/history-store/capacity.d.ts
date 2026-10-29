import { type VerifiedHistory } from '../history.ts';
/** Reuse the existing eleven-kind/eight-control census over the ENTIRE replayed case. */
export declare function historyCapacity(history: VerifiedHistory, segments: number): Readonly<{
    profile: "continuity-segmented-local/1";
    compatible: boolean;
    canDeclareJob: boolean;
    mode: "OPEN" | "INCOMPATIBLE" | "DRAINING";
    reservedEvents: number;
    lifecycleReserved: number;
    controlReserved: number;
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
    projected: Readonly<{
        events: number;
        canonicalBytes: number;
        nodes: number;
        encodedBytes: number;
        segments: number;
    }>;
    grantsAuthority: false;
}>;
/** Conservative pre-sign room check. The unsigned transition is census input only,
 * never replayed state or authentication; the actual signed event is replayed at commit. */
export declare function hasAdministrativeRoom(history: VerifiedHistory, transition: unknown, segments: number): boolean;
