import { verifiedHistorySnapshot } from "../../core-0.2/src/history/index.js";
import * as core from "../../core-0.2/src/core/index.js";
import { captureData, ContinuityError, identifier, record, requireCondition, time, } from "./input.js";
export function captureHistory(input) {
    let captured;
    try {
        captured = captureData(input, 2_097_152, 100_000, 64);
    }
    catch {
        throw new ContinuityError("INVALID_HISTORY");
    }
    requireCondition(Array.isArray(captured), "INVALID_HISTORY");
    requireCondition(captured.length > 0 && captured.length <= 256, "HISTORY_LIMIT");
    const events = captured;
    const result = core.replayPortable({
        operationVersion: core.PORTABLE_REPLAY_VERSION,
        events,
    });
    requireCondition(result.status === "ACCEPTED", "INVALID_HISTORY");
    return events;
}
function request(input, at) {
    const r = record(input, ["actor", "action", "resource"], ["amount", "counterparty", "termsCommitment"]);
    if (Object.hasOwn(r, "amount"))
        requireCondition(typeof r.amount === "bigint" && r.amount >= 0n && r.amount < 1n << 256n);
    if (Object.hasOwn(r, "termsCommitment"))
        requireCondition(typeof r.termsCommitment === "string" &&
            /^0x[0-9a-f]{64}$/.test(r.termsCommitment));
    return Object.freeze({
        actorId: identifier(r.actor),
        action: identifier(r.action),
        resource: identifier(r.resource),
        claimedAt: at,
        ...(Object.hasOwn(r, "amount") ? { amount: r.amount } : {}),
        ...(Object.hasOwn(r, "counterparty")
            ? { counterpartyId: identifier(r.counterparty) }
            : {}),
        ...(Object.hasOwn(r, "termsCommitment")
            ? { termsCommitment: r.termsCommitment }
            : {}),
    });
}
/** A frozen observation, never a live permission or execution token. */
export function observeHistory(input, options = {}) {
    return observeEvents(captureHistory(input), options);
}
/** Explicit larger historical interface; never imports serialized replay state. */
export function observeContinuationHistory(history, options = {}) {
    return observeEvents(verifiedHistorySnapshot(history).events, options);
}
function observeEvents(events, options) {
    const o = record(options, [], ["at"]);
    const replay = core.replayPortable({
        operationVersion: core.PORTABLE_REPLAY_VERSION,
        events,
    });
    if (replay.status !== "ACCEPTED")
        throw new ContinuityError("INVALID_HISTORY");
    const head = replay.head;
    const at = Object.hasOwn(o, "at") ? time(o.at) : head.canonicalTime;
    const genesis = events[0].data;
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
        scope: "CAPTURED_HISTORY_ONLY",
        eventCount: events.length,
        authorize(action) {
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
        why(action) {
            return core.whyPortable({
                ...query,
                request: request(action, at),
                disclosure: core.portablePublicQueryDisclosure("WHY"),
            });
        },
        responsible(action) {
            return core.responsiblePortable({
                ...query,
                request: request(action, at),
                disclosure: core.portablePublicQueryDisclosure("RESPONSIBLE"),
            });
        },
        survives(agent) {
            return core.survivesPortable({
                operationVersion: core.PORTABLE_QUERY_VERSION,
                observedEvents: events,
                targetAgentId: identifier(agent),
                evaluationTime: at,
                disclosure: core.portablePublicQueryDisclosure("SURVIVES"),
            });
        },
    });
}
