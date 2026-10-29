export declare const REFERENCE_OUTPUT_LIMITS: Readonly<{
    bytes: 16777216;
    stringBytes: 4096;
    listMembers: 4096;
    recordFields: 256;
    depth: 32;
    evidenceOccurrences: 4096;
}>;
export declare const throwReferenceOutputOverflow: () => never;
export declare const isReferenceOutputOverflow: (error: unknown) => boolean;
export interface ReferenceOutputMetrics {
    readonly bytes: number;
    readonly depth: number;
}
/** Exact canonical size/depth; aliases count at every occurrence. */
export declare const measureReferenceOutput: (value: unknown) => ReferenceOutputMetrics;
/** Each part is a whole, well-formed string; reserve the combined scalar first. */
export declare const referenceOutputString: (parts: readonly string[]) => string;
export interface ReferenceOutputBudget {
    readonly remainingBytes: number;
    reserve(value: ReferenceOutputMetrics, ancestorDepth: number, evidenceOccurrences?: number): void;
    append(value: unknown, currentLength: number, ancestorDepth: number, evidenceOccurrences?: number): void;
    replace(previous: unknown, next: unknown, ancestorDepth: number, evidenceDelta?: number): void;
}
/**
 * Start from the actual fixed skeleton with empty dynamic lists. append charges
 * the member and its preceding comma only; skeleton delimiters are not repeated.
 * ancestorDepth is the number of containing records/lists outside that member.
 * Evidence counts are schema-owned: RESPONSIBLE counts emitted references,
 * including repetitions, after deduplication of whole attributions.
 */
export declare const createReferenceOutputBudget: (skeleton: unknown, evidenceOccurrences?: number) => ReferenceOutputBudget;
