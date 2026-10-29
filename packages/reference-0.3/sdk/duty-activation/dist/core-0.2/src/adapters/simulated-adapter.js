import { derivePortableAdapterIdentity, hashCanonical, immutableProtocolInput, immutableProtocolValue, approvedPortableAdapterProfile, SIMULATED_ADAPTER_ID, createPortableAdapterAcknowledgment, createPortableAdapterNoEffect, portableAdapterAcknowledgmentEvidence, portableAdapterNoEffectEvidence, } from "../core/index.js";
/**
 * Effect-free simulator with process-local retention. Its cache establishes
 * neither durable admission nor current pre-use authority; the coordinator
 * owns those boundaries. Reconciliation never manufactures a new result.
 */
export class DeterministicSimulatedAdapter {
    adapterProfile;
    #failIntentIds;
    #attempts = [];
    #results = new Map();
    constructor(options = {}) {
        this.adapterProfile = approvedPortableAdapterProfile(SIMULATED_ADAPTER_ID);
        Object.defineProperty(this, "adapterProfile", { value: this.adapterProfile, writable: false, configurable: false, enumerable: true });
        this.#failIntentIds = new Set(options.failIntentIds ?? []);
    }
    get attempts() { return immutableProtocolValue(this.#attempts); }
    #identity(input) {
        const identity = derivePortableAdapterIdentity(input);
        if (hashCanonical(identity.adapterProfile) !== hashCanonical(this.adapterProfile))
            throw new TypeError("Simulator requires its approved admitted profile.");
        return identity;
    }
    #retained(identity) {
        const prior = this.#results.get(identity.idempotencyKey);
        if (prior === undefined)
            return undefined;
        if (prior.submissionFingerprint !== identity.submissionFingerprint)
            return immutableProtocolValue({
                status: "IDEMPOTENCY_FINGERPRINT_CONFLICT", idempotencyKey: identity.idempotencyKey,
                retainedFingerprint: prior.submissionFingerprint, suppliedFingerprint: identity.submissionFingerprint,
            });
        const common = { status: "RETRY", idempotencyKey: identity.idempotencyKey,
            submissionFingerprint: identity.submissionFingerprint, retainedEvidence: prior.evidence };
        return prior.status === "SUBMITTED" ? immutableProtocolValue({ ...common, acknowledgment: prior.acknowledgment })
            : immutableProtocolValue({ ...common, noEffect: prior.noEffect });
    }
    reconcile(input) {
        const identity = this.#identity(input);
        return this.#retained(identity) ?? immutableProtocolValue({ status: "OUTCOME_UNKNOWN",
            idempotencyKey: identity.idempotencyKey, submissionFingerprint: identity.submissionFingerprint });
    }
    async submit(input) {
        const stable = immutableProtocolInput(input), identity = this.#identity(stable);
        const retained = this.#retained(identity);
        if (retained !== undefined)
            return retained;
        const { idempotencyKey, submissionFingerprint, durableEventHistoryHash } = identity;
        let result;
        if (this.#failIntentIds.has(stable.intentId)) {
            const noEffect = createPortableAdapterNoEffect(identity);
            result = immutableProtocolValue({ status: "FAILED", idempotencyKey, submissionFingerprint,
                evidence: portableAdapterNoEffectEvidence(identity, noEffect), noEffect });
        }
        else {
            const acknowledgment = createPortableAdapterAcknowledgment(identity);
            result = immutableProtocolValue({ status: "SUBMITTED", idempotencyKey, submissionFingerprint,
                evidence: portableAdapterAcknowledgmentEvidence(identity, acknowledgment), acknowledgment });
        }
        this.#results.set(idempotencyKey, result);
        this.#attempts.push(immutableProtocolValue({ intentId: stable.intentId, authorizationDomain: stable.domain,
            idempotencyKey, submissionFingerprint, admissionEventId: stable.admissionEvent.id, durableEventHistoryHash, result }));
        return result;
    }
}
