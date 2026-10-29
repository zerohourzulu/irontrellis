/**
 * Additional-policy composition (port of Core 0.3 `policy.ts`): the trusted
 * application supplies an evaluator and a durable audit sink; both Core and
 * that policy must allow a new effect. Requests are hashed with keccak-256 so
 * legacy audit trails stay comparable across engines.
 */
import { hashCanonical } from "./hash.ts";
import { IronTrellisError, captureData, identifier, record, requireCondition } from "./input.ts";
import type { AuthorizationDomain, ContentHash } from "./types.ts";

export type PolicyRequest = Readonly<{
  identity: string;
  requestHash: ContentHash;
  domain: AuthorizationDomain;
  actor: string;
  action: string;
  resource: string;
  session: string;
  epoch: number;
  role: string;
  tenure: string;
  operationId: string;
  termsCommitment: ContentHash;
  historyHead: ContentHash;
  amount?: bigint;
  counterparty?: string;
}>;
export type PolicyDecision = Readonly<{ identity: string; requestHash: ContentHash; decision: "ALLOW" | "DENY" | "ERROR"; diagnostics: readonly string[] }>;
export type PolicyEvidence = Readonly<{ request: PolicyRequest; result: PolicyDecision; evaluatedAt: number }>;
export type AdditionalPolicy = Readonly<{
  identity: string;
  evaluate: (request: PolicyRequest, signal: AbortSignal) => Promise<PolicyDecision> | PolicyDecision;
  record: (evidence: PolicyEvidence) => Promise<void> | void;
}>;

export function capturePolicy(value: AdditionalPolicy | undefined): AdditionalPolicy | undefined {
  if (value === undefined) return undefined;
  const identity = identifier(value.identity), evaluate = value.evaluate, recordEvidence = value.record;
  requireCondition(typeof evaluate === "function" && typeof recordEvidence === "function");
  return Object.freeze({ identity, evaluate, record: recordEvidence });
}

/** Five seconds bounds waiting; it cannot preempt a blocking trusted callback. */
async function bounded<T>(work: Promise<T>, controller: AbortController): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<never>((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(new Error("POLICY_TIMEOUT")); }, 5000); }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

export async function evaluatePolicy(policy: AdditionalPolicy, fields: Omit<PolicyRequest, "identity" | "requestHash">, now: () => number): Promise<PolicyEvidence> {
  const body = captureData({ ...fields, identity: policy.identity }) as Omit<PolicyRequest, "requestHash">;
  const request: PolicyRequest = Object.freeze({ ...body, requestHash: hashCanonical(body, "keccak256") });
  let result: PolicyDecision;
  const controller = new AbortController();
  try {
    const r = record(await bounded(Promise.resolve().then(() => policy.evaluate(request, controller.signal)), controller), ["identity", "requestHash", "decision", "diagnostics"]);
    requireCondition(r.identity === policy.identity && r.requestHash === request.requestHash && ["ALLOW", "DENY", "ERROR"].includes(r.decision as string));
    requireCondition(Array.isArray(r.diagnostics) && r.diagnostics.length <= 32 && r.diagnostics.every((item) => typeof item === "string" && item.length <= 256));
    result = r as unknown as PolicyDecision;
  } catch {
    // Do not expose network errors, keys, private policy text or host paths.
    result = Object.freeze({ identity: policy.identity, requestHash: request.requestHash, decision: "ERROR" as const, diagnostics: Object.freeze(["POLICY_UNAVAILABLE_OR_INVALID"]) });
  }
  const evidence: PolicyEvidence = Object.freeze({ request, result, evaluatedAt: now() });
  try {
    await bounded(Promise.resolve().then(() => policy.record(evidence)), new AbortController());
  } catch {
    throw new IronTrellisError("POLICY_EVIDENCE_UNAVAILABLE");
  }
  return evidence;
}
