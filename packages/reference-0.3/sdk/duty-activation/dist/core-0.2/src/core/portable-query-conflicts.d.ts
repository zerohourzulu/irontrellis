import type { PortableConsequentialBinding } from "./portable-authority-engine.ts";
import { type PortableReplayState, type PortableReplayEvidenceReference } from "./portable-replay.ts";
type EventReference = Extract<PortableReplayEvidenceReference, {
    kind: "EVENT";
}>;
export type PortableQueryConflictPair = readonly [EventReference, EventReference];
export type PortableQueryConflictSelection = Readonly<{
    kind: "WHY" | "RESPONSIBLE";
    binding?: PortableConsequentialBinding;
}> | Readonly<{
    kind: "SURVIVES";
    targetAgentId: string;
    evaluationTime: number;
}>;
/**
 * Select only the six closed authenticated fork classes. Replay already verified
 * each complete proof and signature at its own exact pre-event head. Indexes and
 * a running least pair avoid materializing a quadratic list of possible pairs.
 * The coordinator owns earlier time/disclosure failures and final output limits.
 */
export declare const findPortableQueryConflict: (evaluationState: PortableReplayState, observedState: PortableReplayState, query: PortableQueryConflictSelection) => PortableQueryConflictPair | undefined;
export {};
