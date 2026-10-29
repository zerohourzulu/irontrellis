import type { PortableReplayState } from "./portable-replay.ts";
import { type PortableSurvivesAnswer } from "./portable-query-codec.ts";
import { type PortableQueryDerivation } from "./portable-query-output.ts";
/** The relevance relation includes historical assignments, even after closure. */
export declare const portableObligationLinksTarget: (state: PortableReplayState, obligationId: string, targetAgentId: string) => boolean;
export declare const derivePortableSurvives: (state: PortableReplayState, targetAgentId: string, evaluationTime: number) => PortableQueryDerivation<PortableSurvivesAnswer>;
export declare const projectPortableSurvives: (state: PortableReplayState, targetAgentId: string, evaluationTime: number) => PortableSurvivesAnswer;
export declare const portableSurvivesAnswersDiffer: (left: PortableReplayState, right: PortableReplayState, targetAgentId: string, evaluationTime: number) => boolean;
