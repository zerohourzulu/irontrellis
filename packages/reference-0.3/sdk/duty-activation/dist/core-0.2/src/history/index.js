/** Bounded, process-local history snapshots. Neither storage nor live authority. */
import { types } from "node:util";
import { captureBoundedCanonicalValue, captureBoundedCanonicalReplayBodyIncrementally, canonicalEncode, hashEventHistory, } from "../core/canonical.js";
import { createPortableReplayKernel, PORTABLE_REPLAY_VERSION } from "../core/portable-replay.js";
export const CONTINUATION_HISTORY_VERSION = "continuity-history-snapshot/1";
export const CONTINUATION_PROFILE = Object.freeze({
    version: "continuity-segmented-local/1",
    maxEvents: 1024, maxCanonicalHistoryBytes: 6 * 1024 * 1024,
    maxEventBytes: 8192, maxEventNodes: 512, maxEventDepth: 16, maxEventArrayMembers: 32,
    maxHistoryNodes: 524288, maxAncillaryBytes: 65536, maxAncillaryNodes: 8192,
});
export class HistoryError extends Error {
    code;
    constructor(code) { super(code); this.name = "HistoryError"; this.code = code; }
}
function fail(code) { throw new HistoryError(code); }
const snapshots = new WeakMap();
/** Reject executable envelopes without reading a caller getter or proxy. */
export function historyDataFields(input, required, optional = []) {
    if (input === null || typeof input !== "object" || types.isProxy(input) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(input)))
        fail("INVALID_INPUT");
    const keys = Reflect.ownKeys(input);
    if (keys.length > required.length + optional.length || keys.some(k => typeof k !== "string" || ![...required, ...optional].includes(k)))
        fail("INVALID_INPUT");
    const result = Object.create(null);
    for (const key of keys) {
        const d = Object.getOwnPropertyDescriptor(input, key);
        if (!d || !d.enumerable || !Object.hasOwn(d, "value"))
            fail("INVALID_INPUT");
        result[key] = d.value;
    }
    if (required.some(k => !Object.hasOwn(result, k)))
        fail("INVALID_INPUT");
    return result;
}
function presence(capture, value) {
    if (Array.isArray(value)) {
        for (const member of value)
            presence(capture, member);
    }
    else if (value !== null && typeof value === "object") {
        const keys = capture.capturedRecordKeys(value);
        if (!keys || keys.length !== Object.keys(value).length || keys.some(k => !Object.hasOwn(value, k)))
            fail("INVALID_INPUT");
        for (const key of keys)
            presence(capture, value[key]);
    }
}
function shape(value, depth = 0) {
    let nodes = 1, arrays = 0, deepest = depth;
    if (Array.isArray(value)) {
        arrays += value.length;
        for (const item of value) {
            const m = shape(item, depth + 1);
            nodes += m.nodes;
            arrays += m.arrays;
            deepest = Math.max(deepest, m.depth);
        }
    }
    else if (value !== null && typeof value === "object") {
        for (const [key, item] of Object.entries(value)) {
            nodes++;
            const m = shape(item, depth + 1);
            nodes += m.nodes;
            arrays += m.arrays;
            deepest = Math.max(deepest, m.depth);
        }
    }
    return { nodes, arrays, depth: deepest };
}
/** Captures each untrusted value once; limit/provenance validation precedes replay-state allocation. */
function captureEvent(input) {
    let capture;
    try {
        capture = captureBoundedCanonicalValue(input, { maxCanonicalBytes: CONTINUATION_PROFILE.maxEventBytes });
    }
    catch {
        return fail("EVENT_LIMIT");
    }
    presence(capture, capture.value);
    const metrics = shape(capture.value), bytes = Buffer.byteLength(canonicalEncode(capture.value));
    if (metrics.nodes > CONTINUATION_PROFILE.maxEventNodes || metrics.arrays > CONTINUATION_PROFILE.maxEventArrayMembers ||
        metrics.depth > CONTINUATION_PROFILE.maxEventDepth)
        fail("EVENT_LIMIT");
    return { event: capture.value, nodes: metrics.nodes, bytes };
}
export function captureHistoryAncillary(input) {
    let c;
    try {
        c = captureBoundedCanonicalValue(input, { maxCanonicalBytes: CONTINUATION_PROFILE.maxAncillaryBytes });
    }
    catch {
        return fail("INVALID_INPUT");
    }
    presence(c, c.value);
    if (c.value === null || typeof c.value !== "object" || Array.isArray(c.value) || shape(c.value).nodes > CONTINUATION_PROFILE.maxAncillaryNodes)
        fail("INVALID_INPUT");
    return c.value;
}
function mint(events, metrics, expected) {
    const kernel = createPortableReplayKernel();
    const capture = captureBoundedCanonicalReplayBodyIncrementally(events, Object.freeze({ operationVersion: PORTABLE_REPLAY_VERSION, events }), kernel.visit);
    if (capture.status !== "CAPTURED")
        fail("INVALID_HISTORY");
    const result = kernel.finish();
    if (result.status !== "ACCEPTED")
        fail("INVALID_HISTORY");
    if (canonicalEncode(expected) !== canonicalEncode(result.state.head))
        fail("HEAD_MISMATCH");
    const handle = Object.freeze({ version: CONTINUATION_HISTORY_VERSION, profile: CONTINUATION_PROFILE.version,
        head: result.state.head, eventCount: events.length, metrics: Object.freeze(metrics), scope: "CAPTURED_HISTORY_ONLY", executionCapability: false });
    snapshots.set(handle, Object.freeze({ events: result.state.events, state: result.state }));
    return handle;
}
export function captureContinuationHistory(input) {
    const outer = historyDataFields(input, ["operationVersion", "events", "expectedHead"]);
    if (outer.operationVersion !== CONTINUATION_HISTORY_VERSION)
        fail("UNSUPPORTED_VERSION");
    const expected = captureHistoryAncillary(outer.expectedHead);
    const array = outer.events;
    if (!Array.isArray(array) || types.isProxy(array) || Object.getPrototypeOf(array) !== Array.prototype)
        fail("INVALID_INPUT");
    const length = Object.getOwnPropertyDescriptor(array, "length")?.value;
    if (!Number.isSafeInteger(length) || length < 1 || length > CONTINUATION_PROFILE.maxEvents)
        fail("HISTORY_LIMIT");
    if (Reflect.ownKeys(array).length !== length + 1)
        fail("INVALID_INPUT");
    const events = [];
    let canonicalBytes = 0, nodes = 0, maxEventBytes = 0, maxEventNodes = 0;
    for (let i = 0; i < length; i++) {
        const descriptor = Object.getOwnPropertyDescriptor(array, String(i));
        if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value"))
            fail("INVALID_INPUT");
        const item = captureEvent(descriptor.value);
        canonicalBytes += item.bytes;
        nodes += item.nodes;
        if (canonicalBytes > CONTINUATION_PROFILE.maxCanonicalHistoryBytes || nodes > CONTINUATION_PROFILE.maxHistoryNodes)
            fail("HISTORY_LIMIT");
        maxEventBytes = Math.max(maxEventBytes, item.bytes);
        maxEventNodes = Math.max(maxEventNodes, item.nodes);
        events.push(item.event);
    }
    return mint(Object.freeze(events), { canonicalBytes, nodes, maxEventBytes, maxEventNodes }, expected);
}
/** Package internal: identity check happens before reading any handle member. */
export function verifiedHistorySnapshot(handle) {
    if (handle === null || typeof handle !== "object")
        fail("INVALID_HISTORY_HANDLE");
    const snapshot = snapshots.get(handle);
    if (!snapshot)
        fail("INVALID_HISTORY_HANDLE");
    return snapshot;
}
export function exportContinuationEvents(handle) {
    return verifiedHistorySnapshot(handle).events;
}
export function continuationPrefix(handle, position) {
    const { events, state } = verifiedHistorySnapshot(handle);
    if (typeof position !== "number" || !Number.isSafeInteger(position) || position < 0 || Object.is(position, -0) || position >= events.length)
        fail("PREFIX_INVALID");
    return captureContinuationHistory({ operationVersion: CONTINUATION_HISTORY_VERSION, events: events.slice(0, position + 1),
        expectedHead: { hash: state.eventHistoryHashes[position], position, canonicalTime: events[position].timestamp } });
}
/** Package-internal pre-signing size check, never transition authorization. */
export function checkContinuationAppendShape(handle, input) {
    const { events } = verifiedHistorySnapshot(handle);
    const metric = handle.metrics;
    if (events.length >= CONTINUATION_PROFILE.maxEvents)
        fail("HISTORY_LIMIT");
    const item = captureEvent(input);
    if (metric.canonicalBytes + item.bytes > CONTINUATION_PROFILE.maxCanonicalHistoryBytes ||
        metric.nodes + item.nodes > CONTINUATION_PROFILE.maxHistoryNodes)
        fail("HISTORY_LIMIT");
    return item.event;
}
/** Pure prospective replay; no append or invocation capability. */
export function appendContinuationEvent(handle, event) {
    const { events } = verifiedHistorySnapshot(handle);
    const stable = checkContinuationAppendShape(handle, event), next = Object.freeze([...events, stable]);
    return captureContinuationHistory({ operationVersion: CONTINUATION_HISTORY_VERSION, events: next,
        expectedHead: { hash: hashEventHistory(next), position: next.length - 1, canonicalTime: stable.timestamp } });
}
