/** Closed, deterministic disk encoding. Bigints and ordinary objects never alias. */
import { CONTINUATION_PROFILE as P } from "../history.js";
export class HistoryStoreError extends Error {
    code;
    constructor(code) { super(code); this.name = 'HistoryStoreError'; this.code = code; }
}
export function fail(code) { throw new HistoryStoreError(code); }
export const LIMITS = Object.freeze({ eventBytes: 32768, segmentEvents: 64, segmentBytes: 2 * 1024 * 1024,
    historyBytes: 32 * 1024 * 1024, manifestBytes: 1024 * 1024, descriptorBytes: 512, segments: 1024,
    orphanFiles: 32, orphanBytes: 8 * 1024 * 1024, sourceBytes: 64 * 1024 * 1024, artifacts: 64, artifactBytes: 1024 * 1024 });
export function exact(value, keys) {
    if (!value || typeof value !== 'object' || Array.isArray(value) ||
        (Object.keys(value).length !== keys.length || Object.keys(value).some(k => !keys.includes(k))))
        fail('FORMAT_INVALID');
}
export const integer = (v, max) => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && !Object.is(v, -0) && v <= max;
export const digest = (v) => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
export const uuid = (v) => typeof v === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(v);
export const json = (v) => Buffer.from(JSON.stringify(v) + '\n');
export function parse(bytes) {
    try {
        const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
        if (!json(value).equals(bytes))
            fail('ENCODING_INVALID');
        return value;
    }
    catch {
        return fail('ENCODING_INVALID');
    }
}
const encode = (v) => v === null ? ['null'] : Array.isArray(v) ? ['array', v.map(encode)] :
    typeof v === 'object' ? ['object', Object.entries(v).map(([key, value]) => [key, encode(value)])] :
        typeof v === 'bigint' ? ['bigint', v.toString()] : ['' + typeof v, v];
export function encodeEvent(event) {
    const bytes = json(encode(event));
    if (bytes.length > LIMITS.eventBytes)
        fail('ENCODED_EVENT_LIMIT');
    return bytes;
}
export function decodeEvent(bytes) {
    if (bytes.length > LIMITS.eventBytes)
        fail('ENCODED_EVENT_LIMIT');
    let nodes = 0, arrays = 0;
    function visit(value, depth) {
        if (++nodes > P.maxEventNodes || depth > P.maxEventDepth)
            fail('ENCODED_EVENT_LIMIT');
        if (!Array.isArray(value))
            fail('ENCODING_INVALID');
        const [tag, body] = value;
        if (tag === 'null' && value.length === 1)
            return null;
        if (value.length !== 2)
            fail('ENCODING_INVALID');
        if (tag === 'string' && typeof body === 'string')
            return body;
        if (tag === 'boolean' && typeof body === 'boolean')
            return body;
        if (tag === 'number' && integer(body, Number.MAX_SAFE_INTEGER))
            return body;
        if (tag === 'bigint' && typeof body === 'string' && /^(0|[1-9][0-9]*)$/.test(body) && body.length <= 78) {
            const n = BigInt(body);
            if (n < (1n << 256n))
                return n;
        }
        if (tag === 'array' && Array.isArray(body)) {
            arrays += body.length;
            if (arrays > P.maxEventArrayMembers)
                fail('ENCODED_EVENT_LIMIT');
            return body.map(v => visit(v, depth + 1));
        }
        if (tag === 'object' && Array.isArray(body)) {
            if (nodes + body.length > P.maxEventNodes)
                fail('ENCODED_EVENT_LIMIT');
            nodes += body.length;
            const result = Object.create(null);
            for (const entry of body) {
                if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== 'string' || Object.hasOwn(result, entry[0]))
                    fail('ENCODING_INVALID');
                Object.defineProperty(result, entry[0], { value: visit(entry[1], depth + 1), enumerable: true });
            }
            return result;
        }
        return fail('ENCODING_INVALID');
    }
    const decoded = visit(parse(bytes), 0);
    if (!encodeEvent(decoded).equals(bytes))
        fail('ENCODING_INVALID');
    return decoded;
}
