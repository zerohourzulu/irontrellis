import type { PortableAuthorizationResult } from "./portable-authority-engine.ts";
import type { PortableReplayState } from "./portable-replay.ts";
import { type PortableResponsibleAnswer } from "./portable-query-codec.ts";
import { type PortableQueryDerivation } from "./portable-query-output.ts";
export declare const derivePortableResponsibility: (evaluationState: PortableReplayState, observedState: PortableReplayState, authorization: Extract<PortableAuthorizationResult, {
    decision: "ALLOW" | "DENY";
}>) => PortableQueryDerivation<PortableResponsibleAnswer>;
export declare const projectPortableResponsibility: (evaluationState: PortableReplayState, observedState: PortableReplayState, authorization: Extract<PortableAuthorizationResult, {
    decision: "ALLOW" | "DENY";
}>) => PortableResponsibleAnswer;
