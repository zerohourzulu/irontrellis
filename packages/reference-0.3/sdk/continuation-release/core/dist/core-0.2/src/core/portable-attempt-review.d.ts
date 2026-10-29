import type { PortableReplayState } from "./portable-replay.ts";
export type PortableAttemptDutyReviewStatus = "UNREVIEWED" | "REVIEW_CLOSED" | "NEEDS_REVIEW";
/** Package-owned facts over a successfully replayed history; no authority or business discharge. */
export declare const portableAttemptDutyReviewStatus: (state: PortableReplayState, dutyId: string) => PortableAttemptDutyReviewStatus;
