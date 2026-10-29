/**
 * Observations (port of Core 0.3 `observation.ts`): a frozen, read-only view of
 * one replayed history at one evaluation time. An observation answers
 * authorize / why / responsible / survives from the engine's state functions;
 * it is never a live permission or an execution token.
 */
import { ROOT_RECOGNITION_POLICY, authorizeState } from "./authority.ts";
import { publicQueryDisclosure, responsibleState, survivesState, whyState, type ResponsibleQueryResult, type SurvivesQueryResult, type WhyQueryResult } from "./queries.ts";
import { DUTY_POLICY_VERSION } from "./events.ts";
import { inspectDutyPolicyState, type DutyPolicyView } from "./duty-policy.ts";
import { replay } from "./replay.ts";
import { IronTrellisError, amount, captureData, contentHash, identifier, optional, record, requireCondition, time } from "./input.ts";
import type { ActionRequest, AuthorizationResult, CanonicalEvent, ContentHash, HistoryHead, ReplayState } from "./types.ts";

export type Action = Readonly<{
  actor: string;
  action: string;
  resource: string;
  amount?: bigint;
  counterparty?: string;
  termsCommitment?: ContentHash;
}>;
/** `at` defaults to the host clock on an owner handle and to the head time for a bare `observeHistory`; `expectHead` pins the observation. */
export type ObservationOptions = Readonly<{ at?: number; expectHead?: HistoryHead }>;
export type Decision = Readonly<{
  scope: "CAPTURED_HISTORY_ONLY";
  executionCapability: false;
  head: HistoryHead;
  evaluationTime: number;
  decision: AuthorizationResult["decision"];
  evidence: AuthorizationResult;
}>;
export interface Observation {
  readonly head: HistoryHead;
  readonly evaluationTime: number;
  readonly scope: "CAPTURED_HISTORY_ONLY";
  readonly eventCount: number;
  authorize(action: Action): Decision;
  why(action: Action): WhyQueryResult;
  responsible(action: Action): ResponsibleQueryResult;
  survives(agent: string): SurvivesQueryResult;
  /** SPEC §13.3 (read-only): the `continuity-attempt-duty-view/1` record of a duty with an active policy, else `null`. */
  inspectDutyPolicy(dutyId: string): DutyPolicyView | null;
}

/** Capture and replay a caller-supplied history; the returned events are the captured copies. */
export function captureHistory(input: unknown): readonly CanonicalEvent[] {
  return replayHistory(input).events;
}
/** Capture + replay in one step for callers that need the state. */
export function replayHistory(input: unknown): ReplayState {
  let captured: unknown;
  try {
    captured = captureData(input, 1_073_741_824, Number.MAX_SAFE_INTEGER, 64);
  } catch {
    throw new IronTrellisError("INVALID_HISTORY");
  }
  requireCondition(Array.isArray(captured) && captured.length > 0, "INVALID_HISTORY");
  const result = replay(captured);
  requireCondition(result.status === "ACCEPTED", "INVALID_HISTORY");
  return result.state;
}

/** The engine request for a facade action at `at`; `amount` keeps bigint zero distinct from absence. */
export function actionRequest(input: Action, at: number): ActionRequest {
  const r = record(input, ["actor", "action", "resource"], ["amount", "counterparty", "termsCommitment"]);
  return Object.freeze({
    actorId: identifier(r.actor), action: identifier(r.action), resource: identifier(r.resource), claimedAt: at,
    ...optional(r, "amount", amount), ...optional(r, "counterparty", identifier, "counterpartyId"), ...optional(r, "termsCommitment", contentHash),
  });
}

const sameHead = (a: HistoryHead, b: HistoryHead): boolean => a.hash === b.hash && a.position === b.position && a.canonicalTime === b.canonicalTime;

/**
 * An observation over an already replayed state; `defaultAt` applies when the
 * caller gives no `at`. The state may be a store's live state: the observation
 * pins the head it saw and, should the store move on, answers from a private
 * replay of that exact prefix, so an old observation stays old.
 */
export function observeState(state: ReplayState, options: ObservationOptions = {}, defaultAt: number = state.head.canonicalTime): Observation {
  const o = record(options, [], ["at", "expectHead"]);
  const head = state.head, events = state.events;
  const at = Object.hasOwn(o, "at") ? time(o.at) : defaultAt;
  if (Object.hasOwn(o, "expectHead")) {
    const expected = record(o.expectHead, ["hash", "position", "canonicalTime"]);
    requireCondition(sameHead({ hash: contentHash(expected.hash), position: time(expected.position), canonicalTime: time(expected.canonicalTime) }, head), "HISTORY_CONFLICT");
  }
  let pinned: ReplayState | undefined;
  const view = (): ReplayState => {
    if (state.head.hash === head.hash && state.events.length === head.position + 1) return state;
    if (pinned === undefined) {
      const result = replay(events.slice(0, head.position + 1));
      requireCondition(result.status === "ACCEPTED" && result.head.hash === head.hash, "INVALID_HISTORY");
      pinned = result.state;
    }
    return pinned;
  };
  const genesis = state.genesis;
  const query = { authorizationDomain: genesis.domain, evaluationTime: at };
  // SPEC §13.6 (`core-0.3/src/observation.ts:110`): the public disclosure names the duty-policy extension once a policy is active.
  const extensions = (state.attemptDutyPolicies?.size ?? 0) > 0 ? [DUTY_POLICY_VERSION] : [];
  return Object.freeze({
    head, evaluationTime: at, scope: "CAPTURED_HISTORY_ONLY" as const, eventCount: head.position + 1,
    authorize(action: Action): Decision {
      const evidence = authorizeState(view(), {
        expectedHistoryHead: head, domain: genesis.domain, policyVersion: genesis.policyVersion, rootRecognitionPolicy: ROOT_RECOGNITION_POLICY,
        request: actionRequest(action, at), evaluationTime: at, consequential: false,
      });
      return Object.freeze({ scope: "CAPTURED_HISTORY_ONLY", executionCapability: false, head, evaluationTime: at, decision: evidence.decision, evidence });
    },
    // The disclosure of the history's own format (E3: a format-2 WHY answer names `budgetId` and the request's `metric`, query-codec.ts)
    // plus the duty-policy extension once a policy is active (E4, SPEC §13.6).
    why(action: Action) { const s = view(); return whyState(s, s, { ...query, request: actionRequest(action, at), disclosure: publicQueryDisclosure("WHY", s.format, extensions) }); },
    responsible(action: Action) { const s = view(); return responsibleState(s, s, { ...query, request: actionRequest(action, at), disclosure: publicQueryDisclosure("RESPONSIBLE", s.format, extensions) }); },
    survives(agent: string) { const s = view(); return survivesState(s, { targetAgentId: identifier(agent), evaluationTime: at, disclosure: publicQueryDisclosure("SURVIVES", s.format, extensions) }); },
    inspectDutyPolicy(dutyId: string) { return inspectDutyPolicyState(view(), identifier(dutyId)); },
  });
}

/** A frozen observation of a caller-supplied history (no file, no owner handle). Default time is the head time. */
export function observeHistory(input: readonly CanonicalEvent[] | unknown, options: ObservationOptions = {}): Observation {
  const o = record(options, [], ["at", "expectHead"]);
  return observeState(replayHistory(input), o as ObservationOptions);
}
