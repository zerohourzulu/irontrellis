/** Host-owned policy selection for one existing investigation duty. No agent tool or dispatch. */
import * as core from "../../core-0.2/src/core/index.js";
import { buildPortableDutyPolicyDescriptor, inspectPortableDutyPolicy, } from "../../core-0.2/src/core/duty-policy.js";
import { verifiedHistorySnapshot } from "../../core-0.2/src/history/index.js";
import { openConfiguredEventStore, ConfiguredDirectoryEventStore } from "./configured-store.js";
import { commitHistoryAdministration } from "./history-store/index.js";
import { configuration, read, stateOf } from "./local-store.js";
import { identifier, record, requireCondition } from "./input.js";
/** Historical inspection only. The supplied handle must come from complete verified replay. */
export function inspectContinuationDutyPolicy(history, duty) {
    const { state } = verifiedHistorySnapshot(history);
    const dutyId = identifier(duty);
    requireCondition(state.attemptDuties.has(dutyId), "TRANSITION_REJECTED");
    return core.immutableProtocolValue({ scope: "CAPTURED_HISTORY_ONLY",
        executionCapability: false, head: state.head,
        policy: inspectPortableDutyPolicy(state, dutyId) ?? null });
}
export function openLocalDutyPolicy(options) {
    const config = configuration(options), sessionId = identifier(options.session), signer = options.signHash;
    requireCondition(typeof signer === "function");
    const store = openConfiguredEventStore(config);
    // This writer must use the durable instance/generation/head conditional append.
    requireCondition(store instanceof ConfiguredDirectoryEventStore, "PROFILE_MISMATCH");
    const initial = stateOf(read(store, config)), session = initial.runtimeSessions.get(sessionId);
    requireCondition(session && session.controllerId === config.controller, "RUNTIME_NOT_CURRENT");
    return Object.freeze({
        describe(input) {
            const value = record(input, ["duty", "incidentSourceDigest", "attesterRole"]);
            const state = stateOf(read(store, config));
            const digest = record(value.incidentSourceDigest, ["algorithm", "value"]);
            requireCondition(digest.algorithm === "sha256" && typeof digest.value === "string" && /^0x[0-9a-f]{64}$/.test(digest.value));
            const descriptor = buildPortableDutyPolicyDescriptor(state, {
                dutyId: identifier(value.duty), acceptedAttesterRoleId: identifier(value.attesterRole),
                incidentSourceDigest: { algorithm: "sha256", value: digest.value },
            });
            const descriptorHash = core.hashCanonical(descriptor);
            return core.immutableProtocolValue({ descriptor, descriptorHash,
                activationAction: "ACTIVATE_DUTY_POLICY",
                activationResource: `duty-policy:${descriptorHash}`, head: state.head,
                grantsAuthority: false });
        },
        async activate(input) {
            const value = record(input, ["id", "descriptor", "activationAuthority"]);
            const eventId = `duty-policy:${identifier(value.id)}`;
            // record() captures and freezes the entire data tree before the signer can yield.
            const descriptor = value.descriptor;
            const data = { actorId: session.agentId, descriptor, descriptorHash: core.hashCanonical(descriptor),
                activationAuthorityId: identifier(value.activationAuthority) };
            const events = read(store, config), state = stateOf(events);
            const existing = events.find(event => event.id === eventId);
            if (existing) {
                const { administrativeAuthorization: _signature, ...effect } = existing.data;
                requireCondition(existing.type === "ATTEMPT_DUTY_POLICY_ACTIVATED" &&
                    core.canonicalEncode(effect) === core.canonicalEncode(data), "OPERATION_CONFLICT");
                return core.immutableProtocolValue({ eventId, head: state.head, alreadyRecorded: true,
                    view: inspectPortableDutyPolicy(state, descriptor.dutyId) });
            }
            const result = await commitHistoryAdministration(store.directoryStore, {
                expectedDomain: config.domain, runtimeSessionId: sessionId,
                transition: { id: eventId, type: "ATTEMPT_DUTY_POLICY_ACTIVATED", timestamp: config.now(), data },
            }, { signHash: signer, now: config.now });
            const current = verifiedHistorySnapshot(result.history).state;
            return core.immutableProtocolValue({ eventId, head: current.head, alreadyRecorded: false,
                view: inspectPortableDutyPolicy(current, descriptor.dutyId) });
        },
        inspect(duty) {
            // Also validates the configured domain and host-owner binding on every read.
            const state = stateOf(read(store, config)), dutyId = identifier(duty);
            requireCondition(state.attemptDuties.has(dutyId), "TRANSITION_REJECTED");
            return core.immutableProtocolValue({ scope: "CAPTURED_HISTORY_ONLY",
                executionCapability: false, head: state.head,
                policy: inspectPortableDutyPolicy(state, dutyId) ?? null });
        },
    });
}
