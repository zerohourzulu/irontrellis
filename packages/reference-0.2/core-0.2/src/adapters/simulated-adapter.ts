import {
  derivePortableAdapterIdentity, hashCanonical, immutableProtocolInput, immutableProtocolValue,
  approvedPortableAdapterProfile, SIMULATED_ADAPTER_ID, createPortableAdapterAcknowledgment,
  createPortableAdapterNoEffect, portableAdapterAcknowledgmentEvidence, portableAdapterNoEffectEvidence,
} from "../core/index.ts";
import type { ContentHash, PortableAuthorizationDomain, PortableAdapterProfile } from "../core/index.ts";
import type { AdapterSubmissionResult, AdmittedTransactionSubmission, TransactionAdapter } from "./index.ts";

export interface SimulatedAdapterAttempt {
  readonly intentId: string;
  readonly authorizationDomain: PortableAuthorizationDomain;
  readonly idempotencyKey: ContentHash;
  readonly submissionFingerprint: ContentHash;
  readonly admissionEventId: string;
  readonly durableEventHistoryHash: ContentHash;
  readonly result: AdapterSubmissionResult;
}

type Identity = ReturnType<typeof derivePortableAdapterIdentity>;
type DefinitiveResult = Extract<AdapterSubmissionResult, { status: "SUBMITTED" | "FAILED" }>;

/**
 * Effect-free simulator with process-local retention. Its cache establishes
 * neither durable admission nor current pre-use authority; the coordinator
 * owns those boundaries. Reconciliation never manufactures a new result.
 */
export class DeterministicSimulatedAdapter implements TransactionAdapter {
  readonly adapterProfile: PortableAdapterProfile;
  readonly #failIntentIds: ReadonlySet<string>;
  readonly #attempts: SimulatedAdapterAttempt[] = [];
  readonly #results = new Map<ContentHash, DefinitiveResult>();

  constructor(options: { failIntentIds?: readonly string[] } = {}) {
    this.adapterProfile = approvedPortableAdapterProfile(SIMULATED_ADAPTER_ID);
    Object.defineProperty(this, "adapterProfile", { value: this.adapterProfile, writable: false, configurable: false, enumerable: true });
    this.#failIntentIds = new Set(options.failIntentIds ?? []);
  }

  get attempts(): readonly SimulatedAdapterAttempt[] { return immutableProtocolValue(this.#attempts); }

  #identity(input: unknown): Identity {
    const identity = derivePortableAdapterIdentity(input);
    if (hashCanonical(identity.adapterProfile) !== hashCanonical(this.adapterProfile)) throw new TypeError("Simulator requires its approved admitted profile.");
    return identity;
  }

  #retained(identity: Identity): AdapterSubmissionResult | undefined {
    const prior = this.#results.get(identity.idempotencyKey);
    if (prior === undefined) return undefined;
    if (prior.submissionFingerprint !== identity.submissionFingerprint) return immutableProtocolValue({
      status: "IDEMPOTENCY_FINGERPRINT_CONFLICT" as const, idempotencyKey: identity.idempotencyKey,
      retainedFingerprint: prior.submissionFingerprint, suppliedFingerprint: identity.submissionFingerprint,
    });
    const common = { status: "RETRY" as const, idempotencyKey: identity.idempotencyKey,
      submissionFingerprint: identity.submissionFingerprint, retainedEvidence: prior.evidence };
    return prior.status === "SUBMITTED" ? immutableProtocolValue({ ...common, acknowledgment: prior.acknowledgment })
      : immutableProtocolValue({ ...common, noEffect: prior.noEffect });
  }

  reconcile(input: AdmittedTransactionSubmission): AdapterSubmissionResult {
    const identity = this.#identity(input);
    return this.#retained(identity) ?? immutableProtocolValue({ status: "OUTCOME_UNKNOWN" as const,
      idempotencyKey: identity.idempotencyKey, submissionFingerprint: identity.submissionFingerprint });
  }

  async submit(input: AdmittedTransactionSubmission): Promise<AdapterSubmissionResult> {
    const stable = immutableProtocolInput(input), identity = this.#identity(stable);
    const retained = this.#retained(identity);
    if (retained !== undefined) return retained;
    const { idempotencyKey, submissionFingerprint, durableEventHistoryHash } = identity;
    let result: DefinitiveResult;
    if (this.#failIntentIds.has(stable.intentId)) {
      const noEffect = createPortableAdapterNoEffect(identity);
      result = immutableProtocolValue({ status: "FAILED" as const, idempotencyKey, submissionFingerprint,
        evidence: portableAdapterNoEffectEvidence(identity, noEffect), noEffect });
    } else {
      const acknowledgment = createPortableAdapterAcknowledgment(identity);
      result = immutableProtocolValue({ status: "SUBMITTED" as const, idempotencyKey, submissionFingerprint,
        evidence: portableAdapterAcknowledgmentEvidence(identity, acknowledgment), acknowledgment });
    }
    this.#results.set(idempotencyKey, result);
    this.#attempts.push(immutableProtocolValue({ intentId: stable.intentId, authorizationDomain: stable.domain,
      idempotencyKey, submissionFingerprint, admissionEventId: stable.admissionEvent.id, durableEventHistoryHash, result }));
    return result;
  }
}
