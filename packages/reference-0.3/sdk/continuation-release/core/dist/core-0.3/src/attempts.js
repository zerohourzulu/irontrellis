import { commitHistoryAdministration } from "./history-store/index.js";
import { openConfiguredEventStore, ConfiguredDirectoryEventStore } from "./configured-store.js";
import * as core from "../../core-0.2/src/core/index.js";
import { portableAttemptDutyReviewStatus } from "../../core-0.2/src/core/portable-attempt-review.js";
import { prepareAdministrativeEvent, produceAdministrativeEvent } from "../../core-0.2/src/administration/index.js";
import { ContinuityError, identifier, record, requireCondition, time } from "./input.js";
import { append, configuration, read, stateOf } from "./local-store.js";
import { exportContinuationEvents } from "./history.js";
import { captureHistory } from "./observation.js";
const attemptPolicy = (hash) => hash === core.PORTABLE_ADAPTER_POLICY_E5_HASH || hash === core.PORTABLE_ADAPTER_POLICY_E6_HASH;
function selectedSource(state, intentId) {
    requireCondition(attemptPolicy(state.genesis.adapterPolicyHash), "PROFILE_MISMATCH");
    const intent = state.intentDeclarations.get(intentId)?.data;
    const admission = state.intentAdmissions.get(intentId);
    requireCondition(intent && admission && intent.adapterProfile.profileId === "adapter:remote-service-report", "TRANSITION_REJECTED");
    const sourceAdmissionEventId = state.events[admission.admissionEventPosition].id;
    return { intent, admission, sourceAdmissionEventId };
}
/** Application-owned recording authority. No adapter, URL or dispatch callback. */
export function openLocalAttemptRecorder(options) {
    const config = configuration(options);
    const sessionId = identifier(options.session);
    const signer = options.signHash;
    requireCondition(typeof signer === "function");
    const store = openConfiguredEventStore(config);
    const initial = stateOf(read(store, config));
    requireCondition(attemptPolicy(initial.genesis.adapterPolicyHash), "PROFILE_MISMATCH");
    const session = initial.runtimeSessions.get(sessionId);
    requireCondition(session && session.controllerId === config.controller, "RUNTIME_NOT_CURRENT");
    const signed = async (id, type, data, events) => {
        const existing = events.find(event => event.id === id);
        if (existing) {
            const { administrativeAuthorization: _authorization, ...effect } = existing.data;
            requireCondition(existing.type === type && core.canonicalEncode(effect) === core.canonicalEncode(data), "OPERATION_CONFLICT");
            // An exact repeat observes a prior event; it issues no new signature/write.
            return Object.freeze({ eventId: existing.id, head: stateOf(events).head });
        }
        if (store instanceof ConfiguredDirectoryEventStore) {
            const committed = await commitHistoryAdministration(store.directoryStore, {
                expectedDomain: config.domain, runtimeSessionId: sessionId,
                transition: { id, type, timestamp: config.now(), data },
            }, { signHash: signer, now: config.now });
            return Object.freeze({ eventId: id, head: committed.history.head });
        }
        requireCondition(events.length < 128, "HISTORY_LIMIT");
        const head = stateOf(events).head;
        const transition = { id, type, timestamp: config.now(), data };
        requireCondition(transition.timestamp >= head.canonicalTime, "CLOCK_INVALID");
        const input = {
            events, expectedDomain: config.domain, expectedHistoryHead: head,
            transition, runtimeSessionId: sessionId,
        };
        const produced = await produceAdministrativeEvent(input, {
            signHash: async (hash) => {
                try {
                    return await signer(hash);
                }
                catch {
                    throw new ContinuityError("SIGNER_FAILED");
                }
            },
        });
        const latest = read(store, config);
        requireCondition(stateOf(latest).head.hash === head.hash, "HISTORY_CONFLICT");
        const now = config.now();
        requireCondition(now >= transition.timestamp, "CLOCK_INVALID");
        // The original signature binds original record time. This fresh evaluation
        // cannot change it, and prevents authority expiry during async signing.
        prepareAdministrativeEvent({ ...input, transition: { ...transition, timestamp: now } });
        return append(store, config, produced.event, events);
    };
    return Object.freeze({
        async observe(input) {
            const value = record(input, ["id", "intent", "acknowledgment"]);
            const id = identifier(value.id), intentId = identifier(value.intent);
            const events = read(store, config), state = stateOf(events);
            const source = selectedSource(state, intentId);
            requireCondition(core.validatePortableAdapterAcknowledgment(value.acknowledgment, source.admission.adapterIdentity), "TRANSITION_REJECTED");
            const acknowledgment = value.acknowledgment;
            requireCondition(acknowledgment.result.kind === "REMOTE_SERVICE_REPORTED", "TRANSITION_REJECTED");
            return signed(`attempt-observation:${id}`, "OUTCOME_OBSERVATION_RECORDED", {
                intentId, sourceAdmissionEventId: source.sourceAdmissionEventId,
                acknowledgment, actorId: session.agentId,
            }, events);
        },
        async createDuty(input) {
            const value = record(input, ["id", "intent", "description", "deadline"]);
            const dutyId = identifier(value.id), intentId = identifier(value.intent);
            requireCondition(typeof value.description === "string" && value.description.length > 0 &&
                value.description.length <= 1024 && !/[\u0000-\u001f\u007f]/.test(value.description));
            const deadline = time(value.deadline);
            const events = read(store, config), state = stateOf(events);
            const source = selectedSource(state, intentId);
            const eventId = `attempt-duty:${dutyId}:create`;
            const existing = events.find(event => event.id === eventId);
            // Repetition compares the originally requested creation, even after the
            // role has moved. It must not reconstruct a different creation tenure.
            if (existing) {
                requireCondition(existing.type === "ATTEMPT_DUTY_CREATED", "OPERATION_CONFLICT");
                const { administrativeAuthorization: _authorization, ...effect } = existing.data;
                const original = effect.record;
                requireCondition(original.dutyId === dutyId && original.sourceIntentId === intentId &&
                    original.sourceAdmissionEventId === source.sourceAdmissionEventId &&
                    original.description === value.description && original.deadline === deadline &&
                    effect.actorId === session.agentId, "OPERATION_CONFLICT");
                return signed(eventId, "ATTEMPT_DUTY_CREATED", effect, events);
            }
            const role = state.roles.get(source.intent.roleId);
            const tenure = role?.currentTenureId === undefined ? undefined : state.tenures.get(role.currentTenureId);
            requireCondition(role && tenure && !tenure.closed && tenure.agentId === session.agentId, "RUNTIME_NOT_CURRENT");
            const duty = {
                dutyId, sourceIntentId: intentId, sourceAdmissionEventId: source.sourceAdmissionEventId,
                durableRoleId: source.intent.roleId, creationRoleTenureId: tenure.id,
                description: value.description, deadline,
                performanceAssigneeId: session.agentId, status: "OPEN",
            };
            return signed(eventId, "ATTEMPT_DUTY_CREATED", { record: duty, actorId: session.agentId }, events);
        },
        async reviewDuty(input) {
            const value = record(input, ["id", "duty", "summaryDigest"]);
            const id = identifier(value.id), dutyId = identifier(value.duty);
            requireCondition(typeof value.summaryDigest === "string" && /^0x[0-9a-f]{64}$/.test(value.summaryDigest));
            const events = read(store, config), state = stateOf(events);
            requireCondition(state.genesis.adapterPolicyHash === core.PORTABLE_ADAPTER_POLICY_E6_HASH, "PROFILE_MISMATCH");
            const duty = state.attemptDuties.get(dutyId);
            requireCondition(duty, "TRANSITION_REJECTED");
            selectedSource(state, duty.record.sourceIntentId);
            const eventId = `attempt-duty-review:${id}`;
            const existing = events.find(event => event.id === eventId);
            if (existing) {
                requireCondition(existing.type === "ATTEMPT_DUTY_REVIEW_CLOSED", "OPERATION_CONFLICT");
                const { administrativeAuthorization: _authorization, ...effect } = existing.data;
                requireCondition(effect.dutyId === dutyId && effect.actorId === session.agentId &&
                    effect.summaryDigest === value.summaryDigest, "OPERATION_CONFLICT");
                // Observe the original signed record after later evidence, assignment or retirement.
                return signed(eventId, "ATTEMPT_DUTY_REVIEW_CLOSED", effect, events);
            }
            const observationEventIds = (state.outcomeObservations.get(duty.record.sourceIntentId) ?? [])
                .map(item => item.eventId).sort(core.compareProtocolStrings);
            requireCondition(observationEventIds.length <= 128, "HISTORY_LIMIT");
            return signed(eventId, "ATTEMPT_DUTY_REVIEW_CLOSED", { dutyId, actorId: session.agentId,
                observationEventIds, summaryDigest: value.summaryDigest }, events);
        },
        async assignDuty(input) {
            const value = record(input, ["id", "duty"]);
            const id = identifier(value.id), dutyId = identifier(value.duty);
            const events = read(store, config), state = stateOf(events);
            const duty = state.attemptDuties.get(dutyId);
            requireCondition(duty, "TRANSITION_REJECTED");
            selectedSource(state, duty.record.sourceIntentId);
            const eventId = `attempt-duty-assignment:${id}`;
            const existing = events.find(event => event.id === eventId);
            if (existing) {
                requireCondition(existing.type === "ATTEMPT_DUTY_ASSIGNED", "OPERATION_CONFLICT");
                const { administrativeAuthorization: _authorization, ...effect } = existing.data;
                requireCondition(effect.dutyId === dutyId && effect.toAgentId === session.agentId &&
                    effect.actorId === session.agentId, "OPERATION_CONFLICT");
                return signed(eventId, "ATTEMPT_DUTY_ASSIGNED", effect, events);
            }
            return signed(eventId, "ATTEMPT_DUTY_ASSIGNED", {
                dutyId, fromAgentId: duty.currentAssigneeId, toAgentId: session.agentId,
                actorId: session.agentId,
            }, events);
        },
    });
}
/** Replay-only inspection. Recorded reports establish neither truth nor power. */
export function inspectAttemptHistory(input) {
    return inspectAttempts(captureHistory(input));
}
export function inspectContinuationAttempts(history) {
    return inspectAttempts(exportContinuationEvents(history));
}
function inspectAttempts(events) {
    const state = stateOf(events);
    requireCondition(attemptPolicy(state.genesis.adapterPolicyHash), "PROFILE_MISMATCH");
    const attempts = [...state.intentAdmissions.values()]
        .filter(admission => state.intentDeclarations.get(admission.intentId).data.adapterProfile.profileId === "adapter:remote-service-report")
        .map(admission => {
        const source = selectedSource(state, admission.intentId);
        const observations = state.outcomeObservations.get(admission.intentId) ?? [];
        const digests = new Set(observations.map(observation => observation.acknowledgment.result.reportDigest.value));
        const duty = [...state.attemptDuties.values()].find(item => item.record.sourceIntentId === admission.intentId);
        return {
            intentId: admission.intentId, sourceAdmissionEventId: source.sourceAdmissionEventId,
            originalActorId: source.intent.actorId, originalSessionId: admission.runtimeSessionId,
            originalControlEpoch: admission.controlEpoch, durableRoleId: source.intent.roleId,
            observations, reportStatus: digests.size === 0 ? "NO_RECORDED_REPORTS"
                : digests.size === 1 ? "REPORT_RECORDED" : "DIVERGENT_REPORTS",
            duty: duty === undefined ? null : state.genesis.adapterPolicyHash === core.PORTABLE_ADAPTER_POLICY_E6_HASH
                ? { ...duty, reviews: state.attemptDutyReviews.get(duty.record.dutyId) ?? [],
                    reviewStatus: portableAttemptDutyReviewStatus(state, duty.record.dutyId) } : duty,
            externalOutcome: "NOT_PROVEN",
        };
    }).sort((a, b) => a.intentId < b.intentId ? -1 : a.intentId > b.intentId ? 1 : 0);
    return core.immutableProtocolValue({
        scope: "CAPTURED_HISTORY_ONLY", executionCapability: false,
        head: state.head, attempts,
    });
}
