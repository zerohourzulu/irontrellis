import { compareProtocolStrings } from "./canonical.ts";
import type { PortableReplayState } from "./portable-replay.ts";

export type PortableAttemptDutyReviewStatus = "UNREVIEWED" | "REVIEW_CLOSED" | "NEEDS_REVIEW";

/** Package-owned facts over a successfully replayed history; no authority or business discharge. */
export const portableAttemptDutyReviewStatus = (
  state: PortableReplayState,
  dutyId: string,
): PortableAttemptDutyReviewStatus => {
  const duty = state.attemptDuties.get(dutyId);
  const reviews = state.attemptDutyReviews.get(dutyId) ?? [];
  const latest = reviews[reviews.length - 1];
  if (duty === undefined || latest === undefined) return "UNREVIEWED";
  const latestAssignment = duty.assignments[duty.assignments.length - 1];
  // Returning to the same actor is a new assignment, not revival of an old review.
  if (latestAssignment !== undefined && latest.eventPosition <= latestAssignment.eventPosition) return "NEEDS_REVIEW";
  const ids = (state.outcomeObservations.get(duty.record.sourceIntentId) ?? [])
    .map(item => item.eventId).sort(compareProtocolStrings);
  return latest.actorId === duty.currentAssigneeId && ids.length === latest.observationEventIds.length &&
    ids.every((id, index) => id === latest.observationEventIds[index]) ? "REVIEW_CLOSED" : "NEEDS_REVIEW";
};
