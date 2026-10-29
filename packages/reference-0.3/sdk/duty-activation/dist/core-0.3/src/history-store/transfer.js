/** Durable staged history transfer. Only an authenticated host selects this storage. */
import * as fs from "node:fs";
import { join } from "node:path";
import { canonicalEncode } from "../../../core-0.2/src/core/index.js";
import { captureHistoryAncillary, verifiedHistorySnapshot } from "../../../core-0.2/src/history/index.js";
import { captureContinuationHistory, CONTINUATION_HISTORY_VERSION, CONTINUATION_PROFILE as P } from "../history.js";
import { directory, read, writeImmutable, rename, syncDirectory, sha, fileInfo } from "./files.js";
import { exact, json, parse, fail, integer, digest, encodeEvent, decodeEvent, LIMITS } from "./codec.js";
export const TRANSFER_VERSION = "continuity-checkpoint-transfer/1";
export const TRANSFER_STORAGE_LIMITS = Object.freeze({ bytes: 64 * 1024 * 1024, chunks: 2048, manifests: 2048, manifestBytes: 65536 });
const equal = (a, b) => canonicalEncode(a) === canonicalEncode(b);
function validate(input) {
    const m = captureHistoryAncillary(input);
    exact(m, ["version", "profile", "domain", "head", "eventCount", "encodedBytes", "segments"]);
    if (m.version !== TRANSFER_VERSION || m.profile !== P.version || !integer(m.eventCount, P.maxEvents) || !m.eventCount || !integer(m.encodedBytes, LIMITS.historyBytes))
        fail("TRANSFER_INVALID");
    exact(m.head, ["hash", "position", "canonicalTime"]);
    if (typeof m.head.hash !== "string" || !/^0x[0-9a-f]{64}$/.test(m.head.hash) || m.head.position !== m.eventCount - 1 || !integer(m.head.canonicalTime, Number.MAX_SAFE_INTEGER))
        fail("TRANSFER_INVALID");
    exact(m.domain, ["protocol", "version", "deploymentId", "chainId", "verifyingContract"]);
    if (!Array.isArray(m.segments) || m.segments.length < 1 || m.segments.length > 1024)
        fail("TRANSFER_INVALID");
    let count = 0, bytes = 0;
    const seen = new Set();
    for (const s of m.segments) {
        exact(s, ["digest", "start", "count", "bytes"]);
        if (!digest(s.digest) || seen.has(s.digest) || s.start !== count || !integer(s.count, 64) || s.count < 1 || !integer(s.bytes, LIMITS.segmentBytes) || !s.bytes)
            fail("TRANSFER_INVALID");
        seen.add(s.digest);
        count += s.count;
        bytes += s.bytes;
    }
    if (count !== m.eventCount || bytes !== m.encodedBytes || json(m).length > TRANSFER_STORAGE_LIMITS.manifestBytes)
        fail("TRANSFER_INVALID");
    return m;
}
export function createHistoryTransfer(history) {
    const { events, state } = verifiedHistorySnapshot(history), chunks = [], segments = [];
    let encodedBytes = 0;
    for (let start = 0; start < events.length; start += 64) {
        const selected = events.slice(start, start + 64), bytes = Buffer.concat(selected.map(encodeEvent));
        chunks.push(Object.freeze(bytes.toString("base64").match(/.{1,4096}/g)));
        segments.push({ digest: sha(bytes), start, count: selected.length, bytes: bytes.length });
        encodedBytes += bytes.length;
    }
    const manifest = validate({ version: TRANSFER_VERSION, profile: P.version, domain: state.genesis.domain, head: history.head, eventCount: events.length, encodedBytes, segments });
    return Object.freeze({ transferId: sha(json(manifest)), manifest, chunks: Object.freeze(chunks) });
}
export function openCheckpointStorage(parent, hooks = {}) {
    const root = join(directory(parent), "history-checkpoints");
    if (!fs.existsSync(root)) {
        fs.mkdirSync(root, { mode: 0o700 });
        syncDirectory(parent);
    }
    directory(root);
    const activePath = join(root, "active.json");
    const active = () => {
        if (!fs.existsSync(activePath))
            return null;
        const p = parse(read(activePath, 1024));
        exact(p, ["transferId"]);
        if (p.transferId !== null && !digest(p.transferId))
            fail("TRANSFER_INVALID");
        return p.transferId;
    };
    const bounded = (additionalBytes = 0, additionalChunks = 0, additionalManifests = 0) => {
        let bytes = 0, chunks = 0, manifests = 0;
        const names = fs.readdirSync(root);
        if (names.length > TRANSFER_STORAGE_LIMITS.chunks + TRANSFER_STORAGE_LIMITS.manifests + 2)
            fail("TRANSFER_STORAGE_LIMIT");
        for (const name of names) {
            let limit;
            if (/^[0-9a-f]{64}\.chunk$/.test(name)) {
                chunks++;
                limit = LIMITS.segmentBytes;
            }
            else if (/^[0-9a-f]{64}\.manifest$/.test(name)) {
                manifests++;
                limit = TRANSFER_STORAGE_LIMITS.manifestBytes;
            }
            else if (name === "active.json" || name === "active.next")
                limit = 1024;
            else
                fail("TRANSFER_STORAGE_INVALID");
            bytes += fileInfo(join(root, name), limit).size;
        }
        if (bytes + additionalBytes > TRANSFER_STORAGE_LIMITS.bytes || chunks + additionalChunks > TRANSFER_STORAGE_LIMITS.chunks || manifests + additionalManifests > TRANSFER_STORAGE_LIMITS.manifests)
            fail("TRANSFER_STORAGE_LIMIT");
        return { bytes, chunks, manifests };
    };
    const manifest = (id) => { if (!digest(id))
        fail("TRANSFER_INVALID"); const bytes = read(join(root, id + ".manifest"), TRANSFER_STORAGE_LIMITS.manifestBytes); if (sha(bytes) !== id)
        fail("TRANSFER_INVALID"); return validate(parse(bytes)); };
    const requireActive = (id) => { if (active() !== id)
        fail("TRANSFER_CONFLICT"); return manifest(id); };
    const storeImmutable = (path, bytes, kind) => {
        if (!fs.existsSync(path))
            bounded(bytes.length, kind === "chunk" ? 1 : 0, kind === "manifest" ? 1 : 0);
        else
            bounded();
        writeImmutable(path, bytes, hooks);
    };
    const load = (id) => {
        bounded();
        const m = manifest(id), events = [];
        for (const s of m.segments) {
            const bytes = read(join(root, s.digest + ".chunk"), LIMITS.segmentBytes);
            if (bytes.length !== s.bytes || sha(bytes) !== s.digest || bytes.at(-1) !== 10)
                fail("TRANSFER_CHUNK_INVALID");
            const lines = new TextDecoder("utf-8", { fatal: true }).decode(bytes).split("\n");
            lines.pop();
            if (lines.length !== s.count)
                fail("TRANSFER_CHUNK_INVALID");
            for (const line of lines)
                events.push(decodeEvent(Buffer.from(line + "\n")));
        }
        const history = captureContinuationHistory({ operationVersion: CONTINUATION_HISTORY_VERSION, events, expectedHead: m.head });
        if (!equal(verifiedHistorySnapshot(history).state.genesis.domain, m.domain))
            fail("TRANSFER_DOMAIN_MISMATCH");
        return history;
    };
    bounded();
    return Object.freeze({
        begin(input, id, committedReference) {
            const m = validate(input);
            if (!digest(id) || sha(json(m)) !== id)
                fail("TRANSFER_INVALID");
            const existing = active();
            if (existing !== null && existing !== id && existing !== committedReference)
                fail("TRANSFER_CONFLICT");
            storeImmutable(join(root, id + ".manifest"), json(m), "manifest");
            if (existing !== id) {
                bounded(1024);
                writeImmutable(join(root, "active.next"), json({ transferId: id }), hooks);
                rename(join(root, "active.next"), activePath, hooks);
                syncDirectory(root, hooks);
            }
            hooks.point?.("transfer-begin-synced");
            return { transferId: id };
        },
        chunk(id, index, parts) {
            const m = requireActive(id);
            if (!integer(index, m.segments.length - 1) || !Array.isArray(parts) || parts.length < 1 || parts.length > 683 || parts.some(p => typeof p !== "string" || !p.length || p.length > 4096))
                fail("TRANSFER_CHUNK_INVALID");
            const encoded = parts.join("");
            if (encoded.length > Math.ceil(LIMITS.segmentBytes / 3) * 4)
                fail("TRANSFER_CHUNK_INVALID");
            const bytes = Buffer.from(encoded, "base64"), s = m.segments[index];
            if (bytes.toString("base64") !== encoded || bytes.length !== s.bytes || sha(bytes) !== s.digest)
                fail("TRANSFER_CHUNK_INVALID");
            storeImmutable(join(root, s.digest + ".chunk"), bytes, "chunk");
            hooks.point?.("transfer-chunk-synced");
            return { transferId: id, index };
        },
        abort(id) {
            requireActive(id);
            bounded(1024);
            writeImmutable(join(root, "active.next"), json({ transferId: null }), hooks);
            rename(join(root, "active.next"), activePath, hooks);
            syncDirectory(root, hooks);
            return { transferId: id };
        },
        ready(id) { requireActive(id); return load(id); },
        load,
        inspect() { return { active: active(), ...bounded() }; },
    });
}
