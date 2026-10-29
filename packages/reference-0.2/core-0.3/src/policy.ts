import * as core from "../../core-0.2/src/core/index.ts";
import {
  captureData,
  identifier,
  record,
  requireCondition,
  ContinuityError,
} from "./input.ts";

/** The trusted application supplies the evaluator and durable audit sink. */
export type PolicyRequest = Readonly<{
  identity: string;
  requestHash: core.ContentHash;
  domain: core.PortableAuthorizationDomain;
  actor: string;
  action: string;
  resource: string;
  session: string;
  epoch: number;
  role: string;
  tenure: string;
  operationId: string;
  termsCommitment: core.ContentHash;
  historyHead: core.ContentHash;
  amount?: bigint;
  counterparty?: string;
}>;
export type PolicyDecision = Readonly<{
  identity: string;
  requestHash: core.ContentHash;
  decision: "ALLOW" | "DENY" | "ERROR";
  diagnostics: readonly string[];
}>;
export type PolicyEvidence = Readonly<{
  request: PolicyRequest;
  result: PolicyDecision;
  evaluatedAt: number;
}>;
export type AdditionalPolicy = Readonly<{
  identity: string;
  evaluate: (
    request: PolicyRequest,
    signal: AbortSignal,
  ) => Promise<PolicyDecision> | PolicyDecision;
  record: (evidence: PolicyEvidence) => Promise<void> | void;
}>;

export function capturePolicy(
  value: AdditionalPolicy | undefined,
): AdditionalPolicy | undefined {
  if (value === undefined) return undefined;
  const identity = identifier(value.identity),
    evaluate = value.evaluate,
    record = value.record;
  requireCondition(
    typeof evaluate === "function" && typeof record === "function",
  );
  return Object.freeze({ identity, evaluate, record });
}

/** Five seconds bounds waiting; it cannot preempt a blocking trusted callback. */
async function bounded<T>(
  work: Promise<T>,
  controller: AbortController,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(new Error("POLICY_TIMEOUT"));
        }, 5000);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export async function evaluatePolicy(
  policy: AdditionalPolicy,
  fields: Omit<PolicyRequest, "identity" | "requestHash">,
  now: () => number,
): Promise<PolicyEvidence> {
  const body = captureData({ ...fields, identity: policy.identity }) as Omit<
    PolicyRequest,
    "requestHash"
  >;
  const request = Object.freeze({
    ...body,
    requestHash: core.hashCanonical(body),
  });
  let result: PolicyDecision;
  const controller = new AbortController();
  try {
    const r = record(
      await bounded(
        Promise.resolve().then(() =>
          policy.evaluate(request, controller.signal),
        ),
        controller,
      ),
      ["identity", "requestHash", "decision", "diagnostics"],
    );
    requireCondition(
      r.identity === policy.identity &&
        r.requestHash === request.requestHash &&
        ["ALLOW", "DENY", "ERROR"].includes(r.decision as string),
    );
    requireCondition(
      Array.isArray(r.diagnostics) &&
        r.diagnostics.length <= 32 &&
        r.diagnostics.every(
          (item) => typeof item === "string" && item.length <= 256,
        ),
    );
    result = r as PolicyDecision;
  } catch {
    // Do not expose network errors, keys, private policy text or host paths.
    result = Object.freeze({
      identity: policy.identity,
      requestHash: request.requestHash,
      decision: "ERROR" as const,
      diagnostics: Object.freeze(["POLICY_UNAVAILABLE_OR_INVALID"]),
    });
  }
  const evidence = Object.freeze({ request, result, evaluatedAt: now() });
  try {
    await bounded(
      Promise.resolve().then(() => policy.record(evidence)),
      new AbortController(),
    );
  } catch {
    throw new ContinuityError("POLICY_EVIDENCE_UNAVAILABLE");
  }
  return evidence;
}
