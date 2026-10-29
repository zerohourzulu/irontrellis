import { types } from "node:util";
import { captureBoundedCanonicalValue } from "../../core-0.2/src/core/canonical.js";
export class ContinuityError extends Error {
    code;
    mayHaveCommitted;
    constructor(code, mayHaveCommitted = false) {
        super(code);
        this.name = "ContinuityError";
        this.code = code;
        this.mayHaveCommitted = mayHaveCommitted;
    }
}
export function requireCondition(value, code = "INVALID_INPUT") {
    if (!value)
        throw new ContinuityError(code);
}
/** This facade accepts data, not getters, proxies or executable object shapes. */
export function captureData(input, maxBytes = 16_384, maxNodes = 2048, maxDepth = 16) {
    let nodes = 0;
    const ancestors = new Set();
    const copy = (value, depth) => {
        requireCondition(++nodes <= maxNodes && depth <= maxDepth);
        if (value === null ||
            ["string", "number", "bigint", "boolean"].includes(typeof value))
            return value;
        requireCondition(typeof value === "object" &&
            !types.isProxy(value) &&
            !ancestors.has(value));
        const array = Array.isArray(value), proto = Object.getPrototypeOf(value);
        requireCondition(array
            ? proto === Array.prototype
            : proto === Object.prototype || proto === null);
        const keys = Reflect.ownKeys(value);
        requireCondition(keys.length <= maxNodes && keys.every((key) => typeof key === "string"));
        ancestors.add(value);
        try {
            if (array) {
                const length = Object.getOwnPropertyDescriptor(value, "length");
                requireCondition(length &&
                    Object.hasOwn(length, "value") &&
                    Number.isSafeInteger(length.value) &&
                    length.value >= 0 &&
                    length.value <= maxNodes);
                requireCondition(keys.length === length.value + 1);
                const result = [];
                for (let i = 0; i < length.value; i++) {
                    const d = Object.getOwnPropertyDescriptor(value, String(i));
                    requireCondition(d && d.enumerable && Object.hasOwn(d, "value"));
                    result.push(copy(d.value, depth + 1));
                }
                return Object.freeze(result);
            }
            const result = Object.create(null);
            for (const key of keys) {
                const d = Object.getOwnPropertyDescriptor(value, key);
                requireCondition(d && d.enumerable && Object.hasOwn(d, "value"));
                Object.defineProperty(result, key, {
                    value: copy(d.value, depth + 1),
                    enumerable: true,
                });
            }
            return Object.freeze(result);
        }
        finally {
            ancestors.delete(value);
        }
    };
    try {
        return captureBoundedCanonicalValue(copy(input, 0), {
            maxCanonicalBytes: maxBytes,
        }).value;
    }
    catch {
        throw new ContinuityError("INVALID_INPUT");
    }
}
export function record(input, required, optional = []) {
    const value = captureData(input);
    requireCondition(value !== null && typeof value === "object" && !Array.isArray(value));
    const r = value;
    requireCondition(required.every((key) => Object.hasOwn(r, key)) &&
        Object.keys(r).every((key) => required.includes(key) || optional.includes(key)));
    return r;
}
export function identifier(value) {
    requireCondition(typeof value === "string" &&
        value.length > 0 &&
        value.length <= 128 &&
        !/[\u0000-\u001f\u007f]/.test(value));
    return value;
}
export function time(value) {
    requireCondition(typeof value === "number" &&
        Number.isSafeInteger(value) &&
        value >= 0 &&
        !Object.is(value, -0));
    return value;
}
export function identifiers(value) {
    requireCondition(Array.isArray(value) && value.length > 0 && value.length <= 32);
    const items = value.map(identifier);
    requireCondition(new Set(items).size === items.length);
    return Object.freeze(items);
}
