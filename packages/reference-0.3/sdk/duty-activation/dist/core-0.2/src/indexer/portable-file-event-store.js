import { closeSync, existsSync, fstatSync, fsyncSync, lstatSync, openSync, readSync, realpathSync, statSync, unlinkSync, writeSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { hashCanonical, immutableProtocolValue, immutableProtocolInput, replayPortable, PORTABLE_REPLAY_VERSION } from "../core/index.js";
const FORMAT = "continuity-portable-file-store/0.2";
const MAX_FILE_BYTES = 64 * 1024 * 1024;
// All nodes carry tags: an object shaped like a bigint tag remains an object.
const encode = (v) => {
    if (v === null)
        return ["null"];
    if (typeof v === "bigint")
        return ["bigint", v.toString()];
    if (Array.isArray(v))
        return ["array", v.map(encode)];
    if (typeof v === "object")
        return ["object", Object.entries(v).map(([k, x]) => [k, encode(x)])];
    if (["string", "boolean", "number"].includes(typeof v))
        return [typeof v, v];
    throw new Error("Unsupported stored value.");
};
const decode = (v, depth = 0) => {
    if (depth > 128 || !Array.isArray(v))
        throw new Error("Invalid stored encoding.");
    const [tag, body] = v;
    if (tag === "null" && v.length === 1)
        return null;
    if (v.length !== 2)
        throw new Error("Invalid stored encoding.");
    if (tag === "bigint" && typeof body === "string" && /^(0|[1-9][0-9]*)$/.test(body) && body.length <= 78)
        return BigInt(body);
    if (tag === "string" && typeof body === "string")
        return body;
    if (tag === "number" && typeof body === "number" && Number.isSafeInteger(body) && body >= 0)
        return body;
    if (tag === "boolean" && typeof body === "boolean")
        return body;
    if (tag === "array" && Array.isArray(body))
        return body.map(x => decode(x, depth + 1));
    if (tag === "object" && Array.isArray(body)) {
        const result = Object.create(null);
        for (const entry of body) {
            if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== "string" || Object.hasOwn(result, entry[0]))
                throw new Error("Invalid stored object.");
            Object.defineProperty(result, entry[0], { value: decode(entry[1], depth + 1), enumerable: true });
        }
        return result;
    }
    throw new Error("Invalid stored encoding.");
};
const replay = (events) => {
    const result = replayPortable({ operationVersion: PORTABLE_REPLAY_VERSION, events });
    if (result.status !== "ACCEPTED")
        throw new Error(`Portable store history rejected: ${result.code}.`);
    return result.head;
};
const rejectDanglingLink = (path) => {
    if (!existsSync(path)) {
        try {
            if (lstatSync(path).isSymbolicLink())
                throw new Error("Dangling store symlinks are unsupported.");
        }
        catch (error) {
            if (error.code !== "ENOENT")
                throw error;
        }
    }
};
const chainHash = (previousHash, event) => hashCanonical({ version: FORMAT, previousHash, event });
export class PortableStoreConflictError extends Error {
    constructor(observedHead) {
        super("Portable store head changed before conditional append.");
        this.name = "PortableStoreConflictError";
        if (observedHead !== undefined)
            this.observedHead = immutableProtocolValue(observedHead);
    }
}
export class PortableStoreBusyError extends Error {
    constructor() { super("Portable store already has an active cooperative writer."); this.name = "PortableStoreBusyError"; }
}
/** Local cooperative-writer reference mechanics. Parent directory must exist.
 * File limit: 64 MiB; encoded nesting: 128; replay's portable limits also apply.
 * Symlink aliases resolve to one path; hard links are unsupported. No stale-lock
 * recovery, hostile filesystem writers, public finality or crash reconciliation.
 * Hashes detect modified records/fragments, not removal of a complete valid suffix.
 */
export class PortableFileEventStore {
    path;
    constructor(path) {
        const absolute = resolve(path);
        rejectDanglingLink(absolute);
        this.path = existsSync(absolute) ? realpathSync(absolute) : resolve(realpathSync(dirname(absolute)), basename(absolute));
        this.#checkPath();
    }
    #checkPath() {
        rejectDanglingLink(this.path);
        if (existsSync(this.path)) {
            const info = statSync(this.path);
            if (!info.isFile() || info.nlink !== 1 || realpathSync(this.path) !== this.path)
                throw new Error("Portable store requires a regular, non-aliased file.");
        }
    }
    readAll() {
        this.#checkPath();
        if (!existsSync(this.path))
            return Object.freeze([]);
        const fd = openSync(this.path, "r");
        let contents;
        try {
            const size = fstatSync(fd).size;
            if (size > MAX_FILE_BYTES)
                throw new Error("Portable store file limit exceeded.");
            const bytes = Buffer.alloc(size);
            let offset = 0;
            while (offset < size) {
                const count = readSync(fd, bytes, offset, size - offset, offset);
                if (!count)
                    throw new Error("Portable store truncated during read.");
                offset += count;
            }
            contents = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        }
        finally {
            closeSync(fd);
        }
        if (contents === "")
            return Object.freeze([]);
        if (!contents.endsWith("\n"))
            throw new Error("Portable store has an incomplete record.");
        const events = [];
        let previousHash = null;
        for (const line of contents.slice(0, -1).split("\n")) {
            const record = JSON.parse(line);
            if (record === null || typeof record !== "object" || Object.keys(record).sort().join(",") !== "event,previousHash,recordHash,version" || record.version !== FORMAT || record.previousHash !== previousHash)
                throw new Error("Portable store format or hash chain mismatch.");
            const event = decode(record.event);
            if (JSON.stringify(encode(event)) !== JSON.stringify(record.event))
                throw new Error("Noncanonical store encoding.");
            const hash = chainHash(previousHash, event);
            if (record.recordHash !== hash)
                throw new Error("Portable store integrity check failed.");
            events.push(event);
            previousHash = hash;
        }
        // Replay itself validates every transition in order; a final acceptance
        // therefore validates every prefix without reprocessing earlier events.
        replay(events);
        return immutableProtocolValue(events);
    }
    #append(event, events) {
        const captured = immutableProtocolInput(event);
        const head = replay([...events, captured]);
        // Omit declared optional undefined fields only after closed-schema replay.
        const stable = immutableProtocolValue(captured);
        let previousHash = null;
        for (const item of events)
            previousHash = chainHash(previousHash, item);
        const bytes = Buffer.from(JSON.stringify({ version: FORMAT, previousHash, event: encode(stable), recordHash: chainHash(previousHash, stable) }) + "\n");
        const fd = openSync(this.path, "a");
        try {
            if (fstatSync(fd).size + bytes.length > MAX_FILE_BYTES)
                throw new Error("Portable store file limit exceeded.");
            let offset = 0;
            while (offset < bytes.length) {
                const count = writeSync(fd, bytes, offset, bytes.length - offset);
                if (count <= 0)
                    throw new Error("Portable store made no write progress.");
                offset += count;
            }
            fsyncSync(fd);
            // Also covers a prior creation whose directory sync failed.
            const directory = openSync(dirname(this.path), "r");
            try {
                fsyncSync(directory);
            }
            finally {
                closeSync(directory);
            }
        }
        finally {
            closeSync(fd);
        }
        return head;
    }
    withExclusiveWriter(callback) {
        this.#checkPath();
        const lock = `${this.path}.writer-lock`;
        let fd;
        try {
            fd = openSync(lock, "wx");
        }
        catch (error) {
            if (error.code === "EEXIST")
                throw new PortableStoreBusyError();
            throw error;
        }
        let active = true;
        let operating = false;
        const check = () => { if (operating)
            throw new Error("Portable writer operation is not reentrant."); if (!active)
            throw new Error("Portable store writer capability expired."); };
        const writer = Object.freeze({
            readAll: () => { check(); return this.readAll(); },
            appendAtExpectedHead: (event, expected) => {
                check();
                operating = true;
                try {
                    const stableExpected = immutableProtocolValue(expected);
                    const events = this.readAll();
                    const observed = events.length ? replay(events) : undefined;
                    if (observed === undefined || stableExpected.hash !== observed.hash || stableExpected.position !== observed.position || stableExpected.canonicalTime !== observed.canonicalTime)
                        throw new PortableStoreConflictError(observed);
                    return this.#append(event, events);
                }
                finally {
                    operating = false;
                }
            },
        });
        try {
            return callback(writer);
        }
        finally {
            active = false;
            try {
                closeSync(fd);
            }
            finally {
                unlinkSync(lock);
            }
        }
    }
    append(event) {
        this.withExclusiveWriter(writer => { this.#append(event, writer.readAll()); });
    }
    appendAll(input) {
        const stable = immutableProtocolInput(input);
        this.withExclusiveWriter(writer => {
            let events = writer.readAll();
            // Validate the entire batch before writing any part; I/O errors may still leave a prefix.
            // One accepted replay validates every prospective transition/prefix.
            if (stable.length > 0)
                replay([...events, ...stable]);
            for (const event of stable) {
                this.#append(event, events);
                events = [...events, event];
            }
        });
    }
    appendAtExpectedHead(event, expected) {
        return this.withExclusiveWriter(writer => writer.appendAtExpectedHead(event, expected));
    }
}
