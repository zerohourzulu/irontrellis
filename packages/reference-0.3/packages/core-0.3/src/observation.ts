import { verifiedHistorySnapshot } from "../../core-0.2/src/history/index.ts";
import * as core from "../../core-0.2/src/core/index.ts";
import {
  captureData,
  ContinuityError,
  identifier,
  record,
  requireCondition,
  time,
} from "./input.ts";

export type Action = Readonly<{
  actor: string;
  action: string;
  resource: string;
  amount?: bigint;
  counterparty?: string;
  termsCommitment?: core.ContentHash;
}>;
export type ObservationOptions = Readonly<{ at?: number }>;
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
export function captureHistory(
  input: unknown,
): readonly core.PortableCanonicalEvent[] {
  let captured: unknown;
  try {
    captured = captureData(input, 2_097_152, 100_000, 64);
  } catch {
    throw new ContinuityError("INVALID_HISTORY");
  }
  requireCondition(Array.isArray(captured), "INVALID_HISTORY");
  requireCondition(
    captured.length > 0 && captured.length <= 256,
    "HISTORY_LIMIT",
  );
  const events = captured as readonly core.PortableCanonicalEvent[];
  const result = core.replayPortable({
    operationVersion: core.PORTABLE_REPLAY_VERSION,
    events,
  });
  requireCondition(result.status === "ACCEPTED", "INVALID_HISTORY");
  return events;
}
function request(input: Action, at: number): core.PortableActionRequest {
  const r = record(
    input,
    ["actor", "action", "resource"],
    ["amount", "counterparty", "termsCommitment"],
  );
  if (Object.hasOwn(r, "amount"))
    requireCondition(
      typeof r.amount === "bigint" && r.amount >= 0n && r.amount < 1n << 256n,
    );
  if (Object.hasOwn(r, "termsCommitment"))
    requireCondition(
      typeof r.termsCommitment === "string" &&
        /^0x[0-9a-f]{64}$/.test(r.termsCommitment),
    );
  return Object.freeze({
    actorId: identifier(r.actor),
    action: identifier(r.action),
    resource: identifier(r.resource),
    claimedAt: at,
    ...(Object.hasOwn(r, "amount") ? { amount: r.amount as bigint } : {}),
    ...(Object.hasOwn(r, "counterparty")
      ? { counterpartyId: identifier(r.counterparty) }
      : {}),
    ...(Object.hasOwn(r, "termsCommitment")
      ? { termsCommitment: r.termsCommitment as core.ContentHash }
      : {}),
  });
}
/** A frozen observation, never a live permission or execution token. */
export function observeHistory(
  input: readonly core.PortableCanonicalEvent[],
  options: ObservationOptions = {},
): Observation {
  return observeEvents(captureHistory(input), options);
}
/** Explicit larger historical interface; never imports serialized replay state. */
export function observeContinuationHistory(history: unknown, options: ObservationOptions = {}): Observation {
  return observeEvents(verifiedHistorySnapshot(history).events, options);
}
function observeEvents(events: readonly core.PortableCanonicalEvent[], options: ObservationOptions): Observation {
  const o = record(options, [], ["at"]);
  const replay = core.replayPortable({
    operationVersion: core.PORTABLE_REPLAY_VERSION,
    events,
  });
  if (replay.status !== "ACCEPTED")
    throw new ContinuityError("INVALID_HISTORY");
  const head = replay.head;
  const extensions = events.some(event => event.type === "ATTEMPT_DUTY_POLICY_ACTIVATED") ? [core.DUTY_POLICY_VERSION] : [];
  const at = Object.hasOwn(o, "at") ? time(o.at) : head.canonicalTime;
  const genesis = events[0]!.data as unknown as {
    domain: core.PortableAuthorizationDomain;
    policyVersion: string;
  };
  const query = {
    operationVersion: core.PORTABLE_QUERY_VERSION,
    evaluationEvents: events,
    observedEvents: events,
    authorizationDomain: genesis.domain,
    evaluationTime: at,
  };
  return Object.freeze({
    head,
    evaluationTime: at,
    scope: "CAPTURED_HISTORY_ONLY" as const,
    eventCount: events.length,
    authorize(action: Action): Decision {
      const evidence = core.authorizePortable({
        operationVersion: core.PORTABLE_AUTHORIZATION_VERSION,
        events,
        expectedHistoryHead: head,
        domain: genesis.domain,
        policyVersion: genesis.policyVersion,
        rootRecognitionPolicy: core.PORTABLE_ROOT_RECOGNITION_POLICY,
        request: request(action, at),
        evaluationTime: at,
        authoritative: true,
        consequential: false,
      });
      return Object.freeze({
        scope: "CAPTURED_HISTORY_ONLY",
        executionCapability: false,
        head,
        evaluationTime: at,
        decision: evidence.decision,
        evidence,
      });
    },
    why(action: Action) {
      return core.whyPortable({
        ...query,
        request: request(action, at),
        disclosure: core.portablePublicQueryDisclosure("WHY", extensions),
      });
    },
    responsible(action: Action) {
      return core.responsiblePortable({
        ...query,
        request: request(action, at),
        disclosure: core.portablePublicQueryDisclosure("RESPONSIBLE", extensions),
      });
    },
    survives(agent: string) {
      return core.survivesPortable({
        operationVersion: core.PORTABLE_QUERY_VERSION,
        observedEvents: events,
        targetAgentId: identifier(agent),
        evaluationTime: at,
        disclosure: core.portablePublicQueryDisclosure("SURVIVES", extensions),
      });
    },
  });
}
