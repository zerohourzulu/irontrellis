/**
 * Effect-free simulation (port of Core 0.3 `simulation.ts` and the reference
 * `DeterministicSimulatedAdapter`). The simulator retains results per process;
 * its cache establishes neither durable admission nor current authority — the
 * coordinator owns those boundaries, and reconciliation never manufactures a
 * new result.
 */
import { hashCanonical } from "./hash.ts";
import {
  SIMULATED_ADAPTER_ID, adapterAcknowledgmentEvidence, adapterNoEffectEvidence, approvedAdapterProfile, createAdapterAcknowledgment, createAdapterNoEffect,
} from "./adapter-editions.ts";
import type { AdapterIdentityResult } from "./admission.ts";
import { admittedSubmissionIdentity, type AdapterSubmissionResult, type AdmittedSubmissionFields, type AdmittedTransactionSubmission, type TransactionAdapter } from "./coordinators.ts";
import { openLocalExecution, type LocalExecutionOptions } from "./execution.ts";
import type { AuthorizationDomain, ContentHash } from "./types.ts";

export { commitTerms } from "./execution.ts";
export type { SignHash, LocalExecutionOptions as LocalSimulationOptions, LocalOperation as SimulationOperation } from "./execution.ts";

export type SimulatedAdapterAttempt = Readonly<{
  intentId: string;
  authorizationDomain: AuthorizationDomain;
  idempotencyKey: ContentHash;
  submissionFingerprint: ContentHash;
  admissionEventId: string;
  durableEventHistoryHash: ContentHash;
  result: AdapterSubmissionResult;
}>;
export type SimulatedAdapter = TransactionAdapter & Readonly<{ readonly attempts: readonly SimulatedAdapterAttempt[] }>;
type Definitive = Extract<AdapterSubmissionResult, { status: "SUBMITTED" | "FAILED" }>;

/** The reference simulator: SUBMITTED for every intent except the configured failures, retained per idempotency key. */
export function createSimulatedAdapter(options: Readonly<{ failIntentIds?: readonly string[] }> = {}): SimulatedAdapter {
  const adapterProfile = approvedAdapterProfile(SIMULATED_ADAPTER_ID);
  const failing = new Set(options.failIntentIds ?? []);
  const attempts: SimulatedAdapterAttempt[] = [];
  const results = new Map<ContentHash, Definitive>();
  const hashOf = (value: unknown): ContentHash => hashCanonical(value, "sha256");
  /** The coordinator's submission carries the durable state: the identity is read from it, never by replaying `admittedHistory`. */
  const identityOf = (input: unknown): Readonly<{ submission: AdmittedSubmissionFields; identity: AdapterIdentityResult }> => {
    const derived = admittedSubmissionIdentity(input);
    if (hashOf(derived.identity.adapterProfile) !== hashOf(adapterProfile)) throw new TypeError("Simulator requires its approved admitted profile.");
    return derived;
  };
  const retained = (identity: AdapterIdentityResult): AdapterSubmissionResult | undefined => {
    const prior = results.get(identity.idempotencyKey);
    if (prior === undefined) return undefined;
    if (prior.submissionFingerprint !== identity.submissionFingerprint) {
      return Object.freeze({ status: "IDEMPOTENCY_FINGERPRINT_CONFLICT" as const, idempotencyKey: identity.idempotencyKey, retainedFingerprint: prior.submissionFingerprint, suppliedFingerprint: identity.submissionFingerprint });
    }
    const common = { status: "RETRY" as const, idempotencyKey: identity.idempotencyKey, submissionFingerprint: identity.submissionFingerprint, retainedEvidence: prior.evidence };
    return prior.status === "SUBMITTED" ? Object.freeze({ ...common, acknowledgment: prior.acknowledgment }) : Object.freeze({ ...common, noEffect: prior.noEffect });
  };
  const adapter = {
    adapterProfile,
    get attempts(): readonly SimulatedAdapterAttempt[] { return Object.freeze(attempts.slice()); },
    reconcile(input: AdmittedTransactionSubmission): AdapterSubmissionResult {
      const { identity } = identityOf(input);
      return retained(identity) ?? Object.freeze({ status: "OUTCOME_UNKNOWN" as const, idempotencyKey: identity.idempotencyKey, submissionFingerprint: identity.submissionFingerprint });
    },
    async submit(input: AdmittedTransactionSubmission): Promise<AdapterSubmissionResult> {
      const { submission: stable, identity } = identityOf(input);
      const prior = retained(identity);
      if (prior !== undefined) return prior;
      const { idempotencyKey, submissionFingerprint, durableEventHistoryHash } = identity;
      let result: Definitive;
      if (failing.has(stable.intentId)) {
        const noEffect = createAdapterNoEffect(identity);
        result = Object.freeze({ status: "FAILED" as const, idempotencyKey, submissionFingerprint, evidence: adapterNoEffectEvidence(identity, noEffect), noEffect });
      } else {
        const acknowledgment = createAdapterAcknowledgment(identity);
        result = Object.freeze({ status: "SUBMITTED" as const, idempotencyKey, submissionFingerprint, evidence: adapterAcknowledgmentEvidence(identity, acknowledgment), acknowledgment });
      }
      results.set(idempotencyKey, result);
      attempts.push(Object.freeze({ intentId: stable.intentId, authorizationDomain: stable.domain, idempotencyKey, submissionFingerprint, admissionEventId: stable.admissionEvent.id, durableEventHistoryHash, result }));
      return result;
    },
  };
  // The coordinator requires `adapterProfile` as an own data property.
  Object.defineProperty(adapter, "adapterProfile", { value: adapterProfile, writable: false, configurable: false, enumerable: true });
  return adapter;
}

/** Effect-free, signed local execution example; no adapter injection. */
export function openLocalSimulation(options: LocalExecutionOptions) {
  return openLocalExecution(options, createSimulatedAdapter(), "SIMULATION");
}
export type LocalSimulation = ReturnType<typeof openLocalSimulation>;
