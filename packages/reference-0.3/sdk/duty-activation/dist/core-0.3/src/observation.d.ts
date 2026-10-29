import * as core from "../../core-0.2/src/core/index.ts";
export type Action = Readonly<{
    actor: string;
    action: string;
    resource: string;
    amount?: bigint;
    counterparty?: string;
    termsCommitment?: core.ContentHash;
}>;
export type ObservationOptions = Readonly<{
    at?: number;
}>;
export type Decision = Readonly<{
    scope: "CAPTURED_HISTORY_ONLY";
    executionCapability: false;
    head: core.PortableHistoryHead;
    evaluationTime: number;
    decision: core.PortableAuthorizationResult["decision"];
    evidence: core.PortableAuthorizationResult;
}>;
export interface Observation {
    readonly head: core.PortableHistoryHead;
    readonly evaluationTime: number;
    readonly scope: "CAPTURED_HISTORY_ONLY";
    readonly eventCount: number;
    authorize(action: Action): Decision;
    why(action: Action): core.PortableWhyQueryResult;
    responsible(action: Action): core.PortableResponsibleQueryResult;
    survives(agent: string): core.PortableSurvivesQueryResult;
}
export declare function captureHistory(input: unknown): readonly core.PortableCanonicalEvent[];
/** A frozen observation, never a live permission or execution token. */
export declare function observeHistory(input: readonly core.PortableCanonicalEvent[], options?: ObservationOptions): Observation;
/** Explicit larger historical interface; never imports serialized replay state. */
export declare function observeContinuationHistory(history: unknown, options?: ObservationOptions): Observation;
