import * as core from "../../core-0.2/src/core/index.js";
import { captureData, identifier, record, requireCondition, ContinuityError, } from "./input.js";
export function capturePolicy(value) {
    if (value === undefined)
        return undefined;
    const identity = identifier(value.identity), evaluate = value.evaluate, record = value.record;
    requireCondition(typeof evaluate === "function" && typeof record === "function");
    return Object.freeze({ identity, evaluate, record });
}
/** Five seconds bounds waiting; it cannot preempt a blocking trusted callback. */
async function bounded(work, controller) {
    let timer;
    try {
        return await Promise.race([
            work,
            new Promise((_, reject) => {
                timer = setTimeout(() => {
                    controller.abort();
                    reject(new Error("POLICY_TIMEOUT"));
                }, 5000);
            }),
        ]);
    }
    finally {
        if (timer)
            clearTimeout(timer);
    }
}
export async function evaluatePolicy(policy, fields, now) {
    const body = captureData({ ...fields, identity: policy.identity });
    const request = Object.freeze({
        ...body,
        requestHash: core.hashCanonical(body),
    });
    let result;
    const controller = new AbortController();
    try {
        const r = record(await bounded(Promise.resolve().then(() => policy.evaluate(request, controller.signal)), controller), ["identity", "requestHash", "decision", "diagnostics"]);
        requireCondition(r.identity === policy.identity &&
            r.requestHash === request.requestHash &&
            ["ALLOW", "DENY", "ERROR"].includes(r.decision));
        requireCondition(Array.isArray(r.diagnostics) &&
            r.diagnostics.length <= 32 &&
            r.diagnostics.every((item) => typeof item === "string" && item.length <= 256));
        result = r;
    }
    catch {
        // Do not expose network errors, keys, private policy text or host paths.
        result = Object.freeze({
            identity: policy.identity,
            requestHash: request.requestHash,
            decision: "ERROR",
            diagnostics: Object.freeze(["POLICY_UNAVAILABLE_OR_INVALID"]),
        });
    }
    const evidence = Object.freeze({ request, result, evaluatedAt: now() });
    try {
        await bounded(Promise.resolve().then(() => policy.record(evidence)), new AbortController());
    }
    catch {
        throw new ContinuityError("POLICY_EVIDENCE_UNAVAILABLE");
    }
    return evidence;
}
