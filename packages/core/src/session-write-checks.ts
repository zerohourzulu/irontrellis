/**
 * The writer's time pre-checks for a ◇ or ▲ event, run on its shape (type and timestamp) at the position it would take, before
 * any signature is asked for (A-109.1 rule T1 with A-172.2; A-179.4 rule T3: "a writer of a ◇ or ▲ event that would fail T3
 * does not sign"; independent review JOB75-03 / JOB75-05). Format 2 only; control (◆) events are checked by their own path.
 *   T1: TRANSITION_REJECTED {reason: ATTESTATION_EXPIRY, expiresAt}
 *   T3: TRANSITION_REJECTED {reason: SESSION_TIME_HORIZON, ownerTime, horizonMs}
 */
import { isFormat2 } from "./events.ts";
import { IronTrellisError } from "./input.ts";
import { attestationExpiryFailure } from "./owner-keys.ts";
import { sessionTimeHorizonFailure, sessionTimeRefusal } from "./session-time.ts";
import { CONTROL_EVENT_TYPES, type CanonicalEvent, type ReplayState, type U53 } from "./types.ts";

/** Whether `error` is one of the two refusals above, so a wrapping writer passes it through unchanged. */
export const isSessionWriteTimeRefusal = (error: unknown): boolean =>
  error instanceof IronTrellisError && error.code === "TRANSITION_REJECTED" &&
  ["ATTESTATION_EXPIRY", "SESSION_TIME_HORIZON"].includes((error.detail as { reason?: unknown } | undefined)?.reason as string);

export function assertSessionWriteTime(state: ReplayState, event: Pick<CanonicalEvent, "type" | "timestamp">, position: U53): void {
  if (!isFormat2(state.format) || CONTROL_EVENT_TYPES.has(event.type)) return;
  const expiry = attestationExpiryFailure(state, event as CanonicalEvent, position);
  if (expiry !== undefined) throw new IronTrellisError("TRANSITION_REJECTED", false, expiry.reason, { reason: "ATTESTATION_EXPIRY", expiresAt: expiry.expiresAt });
  const horizon = sessionTimeHorizonFailure(state, event, position);
  if (horizon !== undefined) throw sessionTimeRefusal(horizon);
}
