import { types } from "node:util";
import { derivePortableAdapterIdentity, hashCanonical, immutableProtocolValue, immutableProtocolInput, inspectPortableAdmittedIntent, proposePortableIntentAdmission, replayPortable, PORTABLE_REPLAY_VERSION, SIMULATED_ADAPTER_ID, portableAdapterAcknowledgmentTransactionReference, PORTABLE_ADAPTER_NO_EFFECT_VERSION, validatePortableAdapterAcknowledgment, validatePortableAdapterNoEffect, portableAdapterAcknowledgmentEvidence, portableAdapterNoEffectEvidence, } from "../core/index.js";
// Non-authorizing configuration/shape helpers; accepted history still controls membership.
import { knownPortableAdapterProfile, knownPortableAdapterAcknowledgmentVersion } from "../core/portable-adapter-engine.js";
import { captureBoundedCanonicalValue } from "../core/canonical.js";
import { PortableStoreConflictError } from "../indexer/portable-file-event-store.js";
const sameHead = (a, b) => a !== undefined && a.hash === b.hash && a.position === b.position && a.canonicalTime === b.canonicalTime;
const headOf = (events) => {
    const replay = replayPortable({ operationVersion: PORTABLE_REPLAY_VERSION, events });
    if (replay.status !== "ACCEPTED")
        throw new Error("Durable history is unavailable.");
    return replay.head;
};
const submissionFor = (events, observed) => immutableProtocolValue({
    operationVersion: "continuity-adapter-submission/0.2",
    domain: observed.admissionEvent.data.authorizationProof.domain,
    intentId: observed.admissionEvent.data.intentId,
    admissionEvent: observed.admissionEvent,
    admittedHistory: events.slice(0, observed.admissionHead.position + 1),
});
const unknownOutcome = (reason, identity) => Object.freeze({ status: "OUTCOME_UNKNOWN", reason,
    ...(identity === undefined ? {} : { idempotencyKey: identity.idempotencyKey, submissionFingerprint: identity.submissionFingerprint }) });
const exactKeys = (value, required, optional = []) => {
    const keys = Object.keys(value);
    return required.every(key => Object.hasOwn(value, key)) &&
        keys.every(key => required.includes(key) || optional.includes(key));
};
// Result/profile records contain only finite scalar/record data. Snapshot
// original descriptors once, without invoking accessors; preserve undefined
// own keys so exact schema checks cannot erase an originally supplied field.
const captureAdapterData = (input, maxCanonicalBytes = 16_384) => {
    let nodes = 0;
    const active = new WeakSet();
    const copy = (value, depth) => {
        if (++nodes > 256 || depth > 12)
            throw new TypeError("Adapter data exceeds structural limits.");
        if (value === null || value === undefined || typeof value === "boolean" || typeof value === "number")
            return value;
        if (typeof value === "string") {
            if (value.length > 4_096)
                throw new TypeError("Adapter string exceeds finite limits.");
            return value;
        }
        if (typeof value !== "object" || types.isProxy(value) || Array.isArray(value) || active.has(value))
            throw new TypeError("Adapter data must be acyclic non-proxy records.");
        const prototype = Object.getPrototypeOf(value);
        if (prototype !== null && prototype !== Object.prototype)
            throw new TypeError("Adapter record prototype is unsupported.");
        const keys = Reflect.ownKeys(value);
        if (keys.length > 32 || keys.some(key => typeof key !== "string"))
            throw new TypeError("Adapter record keys are unsupported.");
        active.add(value);
        const result = Object.create(null);
        for (const key of keys) {
            const descriptor = Object.getOwnPropertyDescriptor(value, key);
            if (descriptor === undefined || !Object.hasOwn(descriptor, "value"))
                throw new TypeError("Adapter accessors are not data.");
            Object.defineProperty(result, key, { value: copy(descriptor.value, depth + 1), enumerable: true });
        }
        active.delete(value);
        return Object.freeze(result);
    };
    const captured = copy(input, 0);
    captureBoundedCanonicalValue(captured, { maxCanonicalBytes });
    return immutableProtocolInput(captured);
};
const configuredProfile = (adapter) => {
    const descriptor = Object.getOwnPropertyDescriptor(adapter, "adapterProfile");
    if (descriptor === undefined || !Object.hasOwn(descriptor, "value"))
        throw new TypeError("Adapter requires an own data profile.");
    const profile = captureAdapterData(descriptor.value, 1_024);
    if (profile === null || typeof profile !== "object" || !exactKeys(profile, ["profileId", "profileVersion", "descriptorHash"]) ||
        typeof profile.profileId !== "string")
        throw new TypeError("Adapter profile is malformed.");
    const approved = knownPortableAdapterProfile(profile.profileId);
    if (hashCanonical(profile) !== hashCanonical(approved))
        throw new TypeError("Adapter profile is not approved.");
    return approved;
};
const evidenceEquals = (value, expected) => {
    if (value === null || typeof value !== "object" || Array.isArray(value))
        return false;
    return exactKeys(value, ["kind", "evidenceType", "reference", "attesterId"]) &&
        hashCanonical(value) === hashCanonical(expected);
};
const acknowledgmentMatches = (value, evidence, identity) => validatePortableAdapterAcknowledgment(value.acknowledgment, identity) &&
    evidenceEquals(evidence, portableAdapterAcknowledgmentEvidence(identity, value.acknowledgment));
const noEffectMatches = (value, evidence, identity) => validatePortableAdapterNoEffect(value.noEffect, identity) &&
    evidenceEquals(evidence, portableAdapterNoEffectEvidence(identity, value.noEffect));
const validLatestEvidence = (value, identity) => {
    if (value === null || typeof value !== "object" || Array.isArray(value))
        return false;
    const e = value;
    return exactKeys(e, ["kind", "evidenceType", "reference", "attesterId"]) && e.kind === "EXTERNAL" &&
        e.attesterId === identity.adapterProfile.profileId && typeof e.reference === "string" && /^0x[0-9a-f]{64}$/.test(e.reference) &&
        (e.evidenceType === knownPortableAdapterAcknowledgmentVersion(identity.adapterProfile) ||
            (identity.adapterProfile.profileId === SIMULATED_ADAPTER_ID && e.evidenceType === PORTABLE_ADAPTER_NO_EFFECT_VERSION));
};
const captureDisposition = (input, identity) => {
    const captured = captureAdapterData(input);
    if (captured === null || typeof captured !== "object" || Array.isArray(captured))
        throw new TypeError("Malformed adapter response.");
    const value = captured;
    if (value.idempotencyKey !== identity.idempotencyKey)
        throw new TypeError("Adapter key mismatch.");
    if (value.status === "IDEMPOTENCY_FINGERPRINT_CONFLICT") {
        if (!exactKeys(value, ["status", "idempotencyKey", "retainedFingerprint", "suppliedFingerprint"]) ||
            value.suppliedFingerprint !== identity.submissionFingerprint ||
            typeof value.retainedFingerprint !== "string" || !/^0x[0-9a-f]{64}$/.test(value.retainedFingerprint) ||
            value.retainedFingerprint === value.suppliedFingerprint)
            throw new TypeError("Malformed fingerprint conflict.");
        return captured;
    }
    if (value.submissionFingerprint !== identity.submissionFingerprint)
        throw new TypeError("Adapter fingerprint mismatch.");
    const common = ["status", "idempotencyKey", "submissionFingerprint"];
    switch (value.status) {
        case "SUBMITTED": {
            if (!exactKeys(value, [...common, "evidence", "acknowledgment"]) ||
                !acknowledgmentMatches(value, value.evidence, identity))
                throw new TypeError("Malformed adapter acknowledgment.");
            break;
        }
        case "FAILED":
            if (!exactKeys(value, [...common, "evidence", "noEffect"]) ||
                !noEffectMatches(value, value.evidence, identity))
                throw new TypeError("Malformed simulator no-effect evidence.");
            break;
        case "RETRY": {
            const ack = exactKeys(value, [...common, "retainedEvidence", "acknowledgment"]) && acknowledgmentMatches(value, value.retainedEvidence, identity);
            const noEffect = exactKeys(value, [...common, "retainedEvidence", "noEffect"]) && noEffectMatches(value, value.retainedEvidence, identity);
            if (!ack && !noEffect)
                throw new TypeError("Malformed retained typed evidence.");
            break;
        }
        case "OUTCOME_UNKNOWN":
            if (!exactKeys(value, common, ["latestEvidence"]) ||
                (Object.hasOwn(value, "latestEvidence") && !validLatestEvidence(value.latestEvidence, identity)))
                throw new TypeError("Malformed uncertain outcome.");
            break;
        default: throw new TypeError("Unknown adapter disposition.");
    }
    return captured;
};
/**
 * Controlled local reference integration. The store, adapter and clock are
 * approved executable configuration. Only data and identity tokens enter the
 * public methods; replay facts alone never issue first-invocation authority.
 */
export class DurableAdmissionCoordinator {
    store;
    adapter;
    #now;
    #adapterProfile;
    #prepared = new WeakMap();
    #invocations = new WeakMap();
    constructor(store, adapter, options) {
        this.store = store;
        this.adapter = adapter;
        this.#adapterProfile = configuredProfile(adapter);
        Object.defineProperty(this, "adapter", { value: adapter, writable: false, configurable: false, enumerable: true });
        this.#now = options.authoritativeNow;
    }
    #assertAdapterProfile(identity) {
        const actual = configuredProfile(this.adapter);
        if (hashCanonical(actual) !== hashCanonical(this.#adapterProfile) ||
            (identity !== undefined && hashCanonical(identity.adapterProfile) !== hashCanonical(this.#adapterProfile))) {
            throw new TypeError("Configured adapter profile differs from the original admitted selection.");
        }
    }
    prepare(input) {
        // The portable operation owns original input capture and its precedence.
        const proposal = proposePortableIntentAdmission(input);
        const prepared = Object.freeze({ proposal });
        this.#prepared.set(prepared, proposal);
        return prepared;
    }
    admit(prepared) {
        if (prepared === null || typeof prepared !== "object")
            return Object.freeze({ status: "INVALID_PREPARATION", reason: "An unused preparation from this coordinator is required." });
        const proposal = this.#prepared.get(prepared);
        if (proposal === undefined)
            return Object.freeze({ status: "INVALID_PREPARATION", reason: "An unused preparation from this coordinator is required." });
        this.#prepared.delete(prepared);
        try {
            this.#assertAdapterProfile();
        }
        catch {
            return Object.freeze({ status: "UNAVAILABLE", reason: "The configured adapter profile changed.", admissionMayHavePersisted: false });
        }
        if (proposal.status !== "PROPOSED") {
            if (proposal.status === "RETRY") {
                try {
                    const matches = this.store.withExclusiveWriter(writer => {
                        const events = writer.readAll();
                        const current = inspectPortableAdmittedIntent(events, proposal.intentId, headOf(events).canonicalTime);
                        if (current.status === "ADMITTED")
                            this.#assertAdapterProfile(derivePortableAdapterIdentity(submissionFor(events, current)));
                        return current.status === "ADMITTED" && current.admissionEvent.id === proposal.existingAdmissionEventId &&
                            sameHead(current.admissionHead, proposal.existingAdmissionHead);
                    });
                    if (!matches)
                        throw new Error("Supplied retry is absent from this durable history.");
                }
                catch {
                    return Object.freeze({ status: "UNAVAILABLE", reason: "The supplied retry does not establish this store's original admission.", admissionMayHavePersisted: false });
                }
            }
            return Object.freeze({ status: "NOT_ADMITTED", result: proposal });
        }
        let appendStarted = false;
        try {
            const record = this.store.withExclusiveWriter(writer => {
                const events = writer.readAll();
                const observedHead = events.length ? headOf(events) : undefined;
                if (!sameHead(observedHead, proposal.expectedHead))
                    throw new PortableStoreConflictError(observedHead);
                const prospective = [...events, proposal.admissionEvent];
                const observed = inspectPortableAdmittedIntent(prospective, proposal.admissionEvent.data.intentId, proposal.admissionEvent.timestamp);
                if (observed.status !== "ADMITTED")
                    throw new Error("Proposed admission could not be reconstructed.");
                const submission = submissionFor(prospective, observed);
                const identity = derivePortableAdapterIdentity(submission);
                this.#assertAdapterProfile(identity);
                appendStarted = true;
                const newHead = writer.appendAtExpectedHead(proposal.admissionEvent, proposal.expectedHead);
                if (!sameHead(newHead, proposal.prospectiveHead))
                    throw new Error("Durable append returned a different head.");
                this.#assertAdapterProfile(identity);
                return { submission, identity, admissionHead: newHead };
            });
            const capability = immutableProtocolValue({ intentId: proposal.admissionEvent.data.intentId,
                admissionEventId: proposal.admissionEvent.id, admissionHead: record.admissionHead });
            this.#invocations.set(capability, Object.freeze(record));
            return Object.freeze({ status: "ADMITTED", capability, result: Object.freeze({
                    operationVersion: "continuity-intent-admission/0.2", status: "ADMITTED",
                    authorization: proposal.authorization, admissionEvent: proposal.admissionEvent, newHead: record.admissionHead,
                }) });
        }
        catch (error) {
            if (!appendStarted && error instanceof PortableStoreConflictError && error.observedHead !== undefined) {
                return Object.freeze({ status: "NOT_ADMITTED", result: Object.freeze({ operationVersion: "continuity-intent-admission/0.2",
                        status: "CONFLICT", expectedHead: proposal.expectedHead, observedHead: error.observedHead }) });
            }
            return Object.freeze({ status: "UNAVAILABLE", reason: "Durable admission could not be established; reconcile before any retry.", admissionMayHavePersisted: appendStarted });
        }
    }
    async invoke(capability) {
        if (capability === null || typeof capability !== "object")
            return Object.freeze({ status: "NOT_INVOKED", reason: "An unused invocation capability is required." });
        const record = this.#invocations.get(capability);
        if (record === undefined)
            return Object.freeze({ status: "NOT_INVOKED", reason: "An unused invocation capability is required." });
        // A failed or stale use cannot turn the same object into another attempt.
        this.#invocations.delete(capability);
        let called = false;
        let pending;
        try {
            const start = this.store.withExclusiveWriter(writer => {
                const history = writer.readAll();
                const current = inspectPortableAdmittedIntent(history, record.submission.intentId, this.#now());
                if (current.status !== "ADMITTED" || !sameHead(current.admissionHead, record.admissionHead) ||
                    current.admissionEvent.id !== record.submission.admissionEvent.id ||
                    current.consumption !== undefined || current.terminal !== undefined || !current.currentControl)
                    return undefined;
                this.#assertAdapterProfile(record.identity);
                called = true;
                // Synchronous call entry is protected by the lock. Its await is not.
                return { pending: this.adapter.submit(record.submission) };
            });
            if (start === undefined)
                return Object.freeze({ status: "NOT_INVOKED", reason: "The original admission is consumed, terminal, replaced or no longer under its admitted control tuple." });
            pending = start.pending;
        }
        catch {
            return called ? unknownOutcome("Adapter invocation may have started.", record.identity)
                : Object.freeze({ status: "NOT_INVOKED", reason: "Current durable history, time or serialized control could not be established." });
        }
        let disposition;
        try {
            disposition = captureDisposition(await pending, record.identity);
        }
        catch {
            return unknownOutcome("The adapter response is missing, invalid or exceptional.", record.identity);
        }
        return this.#recordDisposition(record, disposition);
    }
    #recordDisposition(record, disposition) {
        try {
            this.#assertAdapterProfile(record.identity);
        }
        catch {
            return unknownOutcome("The configured adapter profile changed before recording.", record.identity);
        }
        if (disposition.status === "OUTCOME_UNKNOWN")
            return unknownOutcome("The adapter cannot establish a definitive outcome.", record.identity);
        if (disposition.status === "IDEMPOTENCY_FINGERPRINT_CONFLICT")
            return Object.freeze({ status: disposition.status, disposition });
        const evidence = disposition.status === "RETRY" ? disposition.retainedEvidence : disposition.evidence;
        const acknowledgment = "acknowledgment" in disposition ? disposition.acknowledgment : undefined;
        const noEffect = "noEffect" in disposition ? disposition.noEffect : undefined;
        try {
            const head = this.store.withExclusiveWriter(writer => {
                const events = writer.readAll();
                const now = this.#now();
                const current = inspectPortableAdmittedIntent(events, record.submission.intentId, now);
                if (current.status !== "ADMITTED" || !sameHead(current.admissionHead, record.admissionHead))
                    throw new Error("Original durable admission changed.");
                this.#assertAdapterProfile(record.identity);
                if (acknowledgment !== undefined && current.consumption !== undefined) {
                    if (hashCanonical(current.consumption.evidenceReference) !== hashCanonical(evidence) ||
                        hashCanonical(current.consumption.acknowledgment) !== hashCanonical(acknowledgment))
                        throw new Error("Different acknowledgment already recorded.");
                    return current.head;
                }
                if (noEffect !== undefined && current.terminal?.status === "FAILED") {
                    if (hashCanonical(current.terminal.evidenceReference) !== hashCanonical(evidence) ||
                        hashCanonical(current.terminal.noEffect) !== hashCanonical(noEffect))
                        throw new Error("Different no-effect record already retained.");
                    return current.head;
                }
                if (!current.currentControl)
                    throw new Error("Original admitted control is no longer current.");
                const id = `event:local:${acknowledgment !== undefined ? "consumption" : "failure"}:${hashCanonical([record.submission.intentId, record.submission.admissionEvent.id]).slice(2)}`;
                const transactionReference = acknowledgment === undefined ? undefined
                    : portableAdapterAcknowledgmentTransactionReference(acknowledgment, record.identity);
                const event = acknowledgment !== undefined ? {
                    id, type: "TRANSACTION_INTENT_CONSUMED", timestamp: now,
                    data: { intentId: record.submission.intentId, adapterId: record.identity.adapterProfile.profileId,
                        idempotencyKey: record.identity.idempotencyKey, submissionFingerprint: record.identity.submissionFingerprint,
                        status: "SUBMITTED", evidenceReference: evidence, transactionReference, acknowledgment },
                } : {
                    id, type: "TRANSACTION_OUTCOME_RECORDED", timestamp: now,
                    data: { intentId: record.submission.intentId, status: "FAILED", attesterId: SIMULATED_ADAPTER_ID,
                        evidenceReference: evidence, noEffect },
                };
                // Replay rechecks current control and terminal order; no stale tuple by backdating.
                return writer.appendAtExpectedHead(event, current.head);
            });
            return Object.freeze({ status: disposition.status, disposition, recorded: true, head });
        }
        catch {
            return unknownOutcome("The acknowledgment or simulator no-effect outcome could not be durably recorded.", record.identity);
        }
    }
    async reconcile(intentId) {
        let record;
        try {
            const observed = this.store.withExclusiveWriter(writer => {
                const events = writer.readAll();
                const current = inspectPortableAdmittedIntent(events, intentId, headOf(events).canonicalTime);
                if (current.status !== "ADMITTED")
                    throw new Error("No original admission.");
                const submission = submissionFor(events, current);
                const identity = derivePortableAdapterIdentity(submission);
                this.#assertAdapterProfile(identity);
                return { current, record: { submission, identity, admissionHead: current.admissionHead } };
            });
            record = observed.record;
            const { current } = observed;
            if (current.terminal !== undefined && current.terminal.status !== "FAILED") {
                return Object.freeze({ status: "TERMINAL", head: current.head, evidence: current.terminal.evidenceReference });
            }
            const retained = current.terminal?.status === "FAILED" ? current.terminal : current.consumption;
            if (retained !== undefined) {
                const typed = current.terminal?.status === "FAILED" ? { noEffect: current.terminal.noEffect }
                    : { acknowledgment: current.consumption.acknowledgment };
                const disposition = captureDisposition({
                    status: "RETRY", idempotencyKey: record.identity.idempotencyKey,
                    submissionFingerprint: record.identity.submissionFingerprint, retainedEvidence: retained.evidenceReference, ...typed,
                }, record.identity);
                if (disposition.status !== "RETRY")
                    throw new Error("Retained evidence is not a retry.");
                return Object.freeze({ status: "RETRY", recorded: true, head: current.head, disposition });
            }
        }
        catch {
            return unknownOutcome("The original durable admission is unavailable.");
        }
        let disposition;
        try {
            this.#assertAdapterProfile(record.identity);
            disposition = captureDisposition(await this.adapter.reconcile(record.submission), record.identity);
            if (disposition.status === "SUBMITTED" || disposition.status === "FAILED")
                throw new Error("Reconciliation returned a new-submission disposition.");
        }
        catch {
            return unknownOutcome("Retained adapter evidence is unavailable or invalid.", record.identity);
        }
        return this.#recordDisposition(record, disposition);
    }
    async commit(prepared) {
        const admission = this.admit(prepared);
        if (admission.status === "ADMITTED")
            return Object.freeze({ admission, invocation: await this.invoke(admission.capability) });
        if (admission.status === "NOT_ADMITTED" && admission.result.status === "RETRY") {
            return Object.freeze({ admission, invocation: await this.reconcile(admission.result.intentId) });
        }
        return Object.freeze({ admission });
    }
    async execute(input) { return this.commit(this.prepare(input)); }
}
