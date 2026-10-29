import type { PortableReplayEvidenceReference, PortableReplayState, PortableReceiptCommitmentRecord } from "./portable-replay.ts";
type Evidence = PortableReplayEvidenceReference;
export type PortableQueryDerivation<T> = Readonly<{
    answer?: T;
    includedFields: readonly string[];
    outputLimitExceeded: boolean;
}>;
export interface PortableQueryProjectionWriter {
    evidence(field: string, references: Iterable<Evidence>): void;
    row(field: string, key: string, fields: Readonly<Record<string, unknown>>, references: Iterable<Evidence>): void;
}
/** Repeated output occurrences may share a reference object, but are charged separately. */
export declare const createPortableQueryEvidenceCache: () => {
    event(state: PortableReplayState, position: number): Evidence;
    receipt(record: PortableReceiptCommitmentRecord): Evidence;
};
/**
 * A group is one final evidence-list location. Merging a repeated fact charges
 * only new references in that group; the same reference in another group is a
 * separate occurrence. Once saturated, only the finite field vocabulary grows.
 */
export declare const createPortableQueryProjectionWriter: <T extends object>(skeleton: T) => {
    evidence(field: string, references: Iterable<Evidence>): void;
    row(field: string, key: string, members: Readonly<Record<string, unknown>>, references: Iterable<Evidence>): void;
    finish(sortRows: (value: T) => void): PortableQueryDerivation<T>;
};
export declare const requirePortableQueryProjection: <T>(result: PortableQueryDerivation<T>) => T;
/**
 * Comparison-only plans store interned evidence identities, never an oversized
 * normal answer. Primary identities are unique in authoritative replay and the
 * normative array order is fixed by them, so equal row maps and evidence sets
 * are exactly equal canonical projections; no digest substitutes for equality.
 */
export declare const createPortableQueryComparisonPlan: (intern: Map<string, number>) => {
    groups: Map<string, {
        fields: string;
        evidence: Set<number>;
    }>;
    evidence(field: string, references: Iterable<Evidence>): void;
    row(field: string, key: string, members: Readonly<Record<string, unknown>>, references: Iterable<Evidence>): void;
};
export declare const portableQueryComparisonPlansDiffer: (left: ReturnType<typeof createPortableQueryComparisonPlan>, right: ReturnType<typeof createPortableQueryComparisonPlan>) => boolean;
export {};
