import { openConfiguredEventStore, ConfiguredDirectoryEventStore } from "./configured-store.js";
import * as core from "../../core-0.2/src/core/index.js";
import { DurableAdmissionCoordinator } from "../../core-0.2/src/sdk/durable-admission.js";
import { DurableReceiptCoordinator } from "../../core-0.2/src/sdk/durable-receipt.js";
import { captureData, ContinuityError, identifier, record, requireCondition, } from "./input.js";
import { configuration, event, read, append, stateOf } from "./local-store.js";
import { capturePolicy, evaluatePolicy, } from "./policy.js";
/** Hash only bounded data. Keep the actual private terms in application storage. */
export function commitTerms(terms) {
    return core.hashCanonical(captureData(terms));
}
function operation(input) {
    const r = record(input, [
        "id",
        "action",
        "resource",
        "role",
        "tenure",
        "termsCommitment",
    ], ["amount", "counterparty"]);
    if (Object.hasOwn(r, "amount"))
        requireCondition(typeof r.amount === "bigint" && r.amount >= 0n && r.amount < (1n << 256n));
    requireCondition(typeof r.termsCommitment === "string" &&
        /^0x[0-9a-f]{64}$/.test(r.termsCommitment));
    return Object.freeze({
        id: identifier(r.id),
        action: identifier(r.action),
        resource: identifier(r.resource),
        role: identifier(r.role),
        tenure: identifier(r.tenure),
        termsCommitment: r.termsCommitment,
        ...(Object.hasOwn(r, "amount") ? { amount: r.amount } : {}),
        ...(Object.hasOwn(r, "counterparty") ? { counterparty: identifier(r.counterparty) } : {}),
    });
}
/**
 * Trusted local application configuration, not an untrusted-agent boundary.
 * This internal constructor accepts approved executable configuration only.
 * Public factories pin the supported adapter; no agent can inject one.
 */
export function openLocalExecution(options, adapter, mode) {
    const config = configuration(options), sessionId = identifier(options.session), signHash = options.signHash;
    requireCondition(typeof signHash === "function");
    const additionalPolicy = capturePolicy(options.additionalPolicy);
    const store = openConfiguredEventStore(config);
    const initial = stateOf(read(store, config));
    const session = initial.runtimeSessions.get(sessionId);
    requireCondition(session && session.controllerId === config.controller, "RUNTIME_NOT_CURRENT");
    const coordinator = new DurableAdmissionCoordinator(store, adapter, {
        authoritativeNow: config.now,
    });
    const sign = async (hash) => {
        try {
            const result = await signHash(hash);
            requireCondition(typeof result === "string" && /^0x[0-9a-fA-F]{130}$/.test(result));
            return result;
        }
        catch {
            throw new ContinuityError("SIGNER_FAILED");
        }
    };
    const current = (events, at) => {
        const state = stateOf(events), agent = state.agents.get(session.agentId);
        requireCondition(at >= state.head.canonicalTime, "CLOCK_INVALID");
        requireCondition(agent &&
            !agent.terminated &&
            agent.currentControlEpoch === session.controlEpoch &&
            (session.expiresAt === undefined || at < session.expiresAt), "RUNTIME_NOT_CURRENT");
        return state;
    };
    const requestFor = (op, at) => Object.freeze({
        actorId: session.agentId,
        action: op.action,
        resource: op.resource,
        termsCommitment: op.termsCommitment,
        claimedAt: at,
        ...(Object.hasOwn(op, "amount") ? { amount: op.amount } : {}),
        ...(Object.hasOwn(op, "counterparty") ? { counterpartyId: op.counterparty } : {}),
    });
    const declarationFor = (op) => Object.freeze({
        intentId: op.id,
        nonce: `operation:${op.id}`,
        adapterProfile: adapter.adapterProfile,
        actorId: session.agentId,
        action: op.action,
        resource: op.resource,
        roleId: op.role,
        roleTenureId: op.tenure,
        termsCommitment: op.termsCommitment,
        ...(Object.hasOwn(op, "amount") ? { amount: op.amount } : {}),
        ...(Object.hasOwn(op, "counterparty") ? { counterpartyId: op.counterparty } : {}),
    });
    const declarationId = (op) => `operation:${core.hashCanonical({
        version: "continuity-simulation-operation/1",
        domain: config.domain,
        session: sessionId,
        epoch: session.controlEpoch,
        key: session.credentialKeyId,
        declaration: declarationFor(op),
        ...(additionalPolicy
            ? { additionalPolicy: additionalPolicy.identity }
            : {}),
    })}`;
    const match = (op, events) => {
        const state = stateOf(events), found = state.intentDeclarations.get(op.id);
        if (found)
            requireCondition(events.some((e) => e.type === "TRANSACTION_INTENT_DECLARED" &&
                e.id === declarationId(op)) &&
                core.canonicalEncode(found.data) ===
                    core.canonicalEncode(declarationFor(op)), "OPERATION_CONFLICT");
        return state;
    };
    const policyAt = (op, events, at) => {
        const state = current(events, at);
        const role = state.roles.get(op.role), tenure = state.tenures.get(op.tenure);
        requireCondition(role?.currentTenureId === op.tenure &&
            tenure &&
            !tenure.closed &&
            tenure.agentId === session.agentId &&
            tenure.roleId === op.role, "RUNTIME_NOT_CURRENT");
        const genesis = events[0].data;
        return core.authorizePortable({
            operationVersion: core.PORTABLE_AUTHORIZATION_VERSION,
            events,
            expectedHistoryHead: state.head,
            domain: config.domain,
            policyVersion: genesis.policyVersion,
            rootRecognitionPolicy: core.PORTABLE_ROOT_RECOGNITION_POLICY,
            request: requestFor(op, at),
            evaluationTime: at,
            authoritative: true,
            consequential: false,
        });
    };
    return Object.freeze({
        profile: mode === "SIMULATION"
            ? "EFFECT_FREE_SIMULATION"
            : mode === "REMOTE_REPORT" ? "REMOTE_REPORTED_OUTCOME" : "LOCAL_EVIDENCE_PACKET",
        /** A committed admission is never re-invoked, including after a restart. */
        async run(input) {
            const op = operation(input);
            let events = read(store, config), state = match(op, events);
            if (state.intentAdmissions.has(op.id)) {
                // Observation/reconciliation of this original attempt is allowed even
                // after retirement. It creates no replacement invocation capability.
                return Object.freeze({
                    status: "RECONCILIATION_ONLY",
                    operationId: op.id,
                    externalEffect: mode === "SIMULATION"
                        ? "NONE_SIMULATED"
                        : mode === "REMOTE_REPORT" ? "REMOTE_REPORTED_OUTCOME" : "LOCAL_PACKET",
                    result: await coordinator.reconcile(op.id),
                });
            }
            let at = config.now();
            const policy = policyAt(op, events, at);
            if (policy.decision !== "ALLOW")
                return Object.freeze({
                    status: "NOT_AUTHORIZED",
                    operationId: op.id,
                    evidence: policy,
                });
            if (!state.intentDeclarations.has(op.id)) {
                const next = core.immutableProtocolValue({
                    ...event("TRANSACTION_INTENT_DECLARED", at, declarationFor(op)),
                    id: declarationId(op),
                });
                append(store, config, next, events);
                events = read(store, config);
                state = match(op, events);
            }
            requireCondition(events.length <= (store instanceof ConfiguredDirectoryEventStore ? 1020 : 252), "HISTORY_LIMIT");
            at = config.now();
            current(events, at);
            const binding = {
                runtimeSessionId: sessionId,
                credentialKeyId: session.credentialKeyId,
                controlEpoch: session.controlEpoch,
                roleId: op.role,
                roleTenureId: op.tenure,
                intentId: op.id,
                nonce: `operation:${op.id}`,
            };
            const request = requestFor(op, at), genesis = events[0].data;
            const challenge = core.createPortableRuntimeAuthorizationChallenge({
                domain: config.domain,
                request,
                evaluationTime: at,
                policyVersion: genesis.policyVersion,
                historyHead: state.head,
                binding,
            });
            const runtimeSignature = await sign(core.hashPortableRuntimeAuthorizationChallenge(challenge));
            // Signing is an async boundary. A stale prefix must not authorize a new
            // operation, and expiry while the signer waited must not be ignored.
            if (additionalPolicy) {
                const evidence = await evaluatePolicy(additionalPolicy, {
                    domain: config.domain,
                    actor: session.agentId,
                    action: op.action,
                    resource: op.resource,
                    session: sessionId,
                    epoch: session.controlEpoch,
                    role: op.role,
                    tenure: op.tenure,
                    operationId: op.id,
                    termsCommitment: op.termsCommitment,
                    historyHead: state.head.hash,
                    ...(Object.hasOwn(op, "amount") ? { amount: op.amount } : {}),
                    ...(Object.hasOwn(op, "counterparty") ? { counterparty: op.counterparty } : {}),
                }, config.now);
                if (evidence.result.decision !== "ALLOW")
                    return Object.freeze({
                        status: "POLICY_REFUSED",
                        operationId: op.id,
                        policyIdentity: evidence.result.identity,
                        reason: evidence.result.decision,
                    });
            }
            // Policy evaluation and durable audit are asynchronous too. Recheck Core
            // only after both complete; the policy result cannot revive a stale actor.
            const latest = read(store, config), latestState = stateOf(latest);
            requireCondition(latestState.head.hash === state.head.hash, "HISTORY_CONFLICT");
            const freshPolicy = policyAt(op, latest, config.now());
            if (freshPolicy.decision !== "ALLOW")
                return Object.freeze({
                    status: "NOT_AUTHORIZED",
                    operationId: op.id,
                    evidence: freshPolicy,
                });
            const prepared = coordinator.prepare({
                operationVersion: core.PORTABLE_INTENT_ADMISSION_VERSION,
                events,
                expectedHistoryHead: state.head,
                admissionEventId: `admission:${core.hashCanonical({ declarationId: declarationId(op), head: state.head })}`,
                domain: config.domain,
                policyVersion: genesis.policyVersion,
                request,
                evaluationTime: at,
                binding: { ...binding, runtimeSignature },
            });
            const admitted = coordinator.admit(prepared);
            if (admitted.status !== "ADMITTED")
                return Object.freeze({
                    status: "NOT_ADMITTED",
                    operationId: op.id,
                    admission: admitted,
                });
            const invocation = await coordinator.invoke(admitted.capability);
            return Object.freeze({
                status: mode === "SIMULATION"
                    ? "SIMULATION_RESULT"
                    : "EXECUTION_RESULT",
                operationId: op.id,
                externalEffect: mode === "SIMULATION"
                    ? "NONE_SIMULATED"
                    : mode === "REMOTE_REPORT" ? "REMOTE_REPORTED_OUTCOME" : "LOCAL_PACKET",
                admission: admitted.result,
                invocation,
            });
        },
        /** Issue and record a signed receipt only for this session's actual simulated acknowledgment. */
        async recordReceipt(input) {
            const op = operation(input), events = read(store, config), state = match(op, events);
            const admitted = state.intentAdmissions.get(op.id);
            requireCondition(admitted &&
                admitted.runtimeSessionId === sessionId &&
                state.intentConsumptions.has(op.id), "RECEIPT_UNAVAILABLE");
            const existing = [...state.receiptCommitments.values()].find((r) => r.intentId === op.id);
            if (existing)
                return Object.freeze({
                    status: "ALREADY_RECORDED",
                    contentHash: existing.receiptContentHash,
                    eventId: existing.eventId,
                    artifactAvailable: false,
                });
            requireCondition(events.length < (store instanceof ConfiguredDirectoryEventStore ? 1024 : 256), "HISTORY_LIMIT");
            const at = config.now();
            current(events, at);
            const artifact = await core.createPortableReceipt({
                events,
                intentId: op.id,
                issuedAt: at,
                externalOutcome: mode === "SIMULATION" ? "SIMULATED" : "NOT_PROVEN",
            }, { keyId: session.credentialKeyId, signHash: sign });
            const latest = read(store, config);
            requireCondition(stateOf(latest).head.hash === state.head.hash, "HISTORY_CONFLICT");
            current(latest, config.now());
            const recording = new DurableReceiptCoordinator(store).record({
                operationVersion: core.PORTABLE_RECEIPT_RECORD_ADMISSION_VERSION,
                artifact,
                events,
                expectedHistoryHead: state.head,
                expectedDomain: config.domain,
                recordEventId: `receipt:${artifact.contentHash}`,
            });
            return Object.freeze({
                status: "RECEIPT_RESULT",
                artifact,
                recording,
            });
        },
    });
}
