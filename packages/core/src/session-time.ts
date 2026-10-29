/**
 * A-179 (A-22.6): the session time horizon. A genesis may set `sessionTimeHorizonMs` (U53 ≥ 1, or `null`, the default);
 * when it is non-null, rule T3 bounds how far a session-signed (◇) or administrative (▲) event may carry history time past
 * `ownerTime`, the timestamp of the latest accepted time-advancing control event (A-179.2).
 *
 * - Replay (A-179.3): T3 runs for every ◇ or ▲ event at `p ≥ 1` outside a migrated prefix, right after T1 (A-172.1):
 *   `e.timestamp − ownerTime(p − 1) ≤ sessionTimeHorizonMs`, else `TRANSITION_INVALID`. Control events are not subject.
 * - Writers (A-179.4) run the same function before signing and refuse with `TRANSITION_REJECTED {reason:
 *   SESSION_TIME_HORIZON, ownerTime, horizonMs}`; refusal recording reports the not-recorded reason `SESSION_TIME_HORIZON`.
 */
import { isFormat2 } from "./events.ts";
import { IronTrellisError } from "./input.ts";
import { CONTROL_EVENT_TYPES, type CanonicalEvent, type ReplayState, type U53 } from "./types.ts";

export const SESSION_TIME_HORIZON_REASON = "time: a session-signed event may not pass the session time horizon";

/** The genesis horizon in force, or `undefined` when the history sets none (absent or `null`). */
export const sessionTimeHorizonOf = (state: ReplayState): U53 | undefined => {
  const horizon = (state.genesis as { sessionTimeHorizonMs?: U53 | null }).sessionTimeHorizonMs;
  return horizon === undefined || horizon === null ? undefined : horizon;
};

/**
 * A-179.2: `ownerTime(q)` for the state's head `q`: the timestamp of the latest accepted control event at `1 ≤ r ≤ q` with
 * `e_r.timestamp > e_{r−1}.timestamp` (a control event written at `max(now, head)` that does not advance time never moves it;
 * prefix events count), or `e_0.timestamp` when none exists. Replay keeps it as a derived index (`ownerTime`), rebuilt from
 * the `event` records on a resume; a state without the index (an older fork) derives it from its events.
 */
export const ownerTimeOf = (state: ReplayState): U53 => {
  const kept = (state as { ownerTime?: U53 }).ownerTime;
  if (kept !== undefined) return kept;
  const events = state.events;
  for (let r = events.length - 1; r >= 1; r -= 1) {
    if (CONTROL_EVENT_TYPES.has(events[r]!.type) && events[r]!.timestamp > events[r - 1]!.timestamp) return events[r]!.timestamp;
  }
  return events[0]!.timestamp;
};

/** Rule T3 for `event` at `position` on `state` (the state before the event): the refusal, or `undefined`. */
export function sessionTimeHorizonFailure(state: ReplayState, event: Pick<CanonicalEvent, "type" | "timestamp">, position: U53):
    Readonly<{ reason: string; ownerTime: U53; horizonMs: U53 }> | undefined {
  if (!isFormat2(state.format) || position === 0 || CONTROL_EVENT_TYPES.has(event.type)) return undefined;
  const horizonMs = sessionTimeHorizonOf(state);
  if (horizonMs === undefined) return undefined;
  const prefixEnd = state.genesis.migratedFrom?.position;
  if (prefixEnd !== undefined && position <= prefixEnd) return undefined; // ¬inPrefix(p)
  const ownerTime = ownerTimeOf(state);
  return event.timestamp - ownerTime <= horizonMs ? undefined : Object.freeze({ reason: SESSION_TIME_HORIZON_REASON, ownerTime, horizonMs });
}

/** A-179.4: rule T3 refused by a writer: `TRANSITION_REJECTED {reason: SESSION_TIME_HORIZON, ownerTime, horizonMs}`. */
export function sessionTimeRefusal(failure: Readonly<{ reason: string; ownerTime: U53; horizonMs: U53 }>): IronTrellisError {
  return new IronTrellisError("TRANSITION_REJECTED", false, failure.reason, { reason: "SESSION_TIME_HORIZON", ownerTime: failure.ownerTime, horizonMs: failure.horizonMs });
}
/** Whether `error` is the refusal `sessionTimeRefusal` makes (so a wrapping writer passes it through unchanged). */
export const isSessionTimeRefusal = (error: unknown): boolean =>
  error instanceof IronTrellisError && error.code === "TRANSITION_REJECTED" && (error.detail as { reason?: unknown } | undefined)?.reason === "SESSION_TIME_HORIZON";
