import * as fs from 'node:fs';
import { types } from 'node:util';
import { join, resolve, dirname, basename } from 'node:path';
import { randomUUID } from 'node:crypto';
import * as core from '../../../core-0.2/src/core/index.ts';
import { CONTINUATION_PROFILE as P, CONTINUATION_HISTORY_VERSION, captureContinuationHistory, exportContinuationEvents, appendContinuationEvent, continuationPrefix, type VerifiedHistory } from '../history.ts';
import { historyDataFields, captureHistoryAncillary } from '../../../core-0.2/src/history/index.ts';
import { historyCapacity } from './capacity.ts';
import { LIMITS, fail, exact, integer, digest, uuid, json, parse, encodeEvent, decodeEvent } from './codec.ts';
import { sha, directory, read, writeNew, writeImmutable, syncDirectory, rename, withLock, fileInfo, type Hooks } from './files.ts';
export const STORE_FORMAT = 'continuity-directory-history/1';
export type Descriptor = Readonly<{
    digest: string;
    start: number;
    count: number;
    canonicalBytes: number;
    nodes: number;
    encodedBytes: number;
}>;
export type MigrationBinding = Readonly<{
    id: string;
    source: string;
    sourceDigest: string;
    sourceHead: core.PortableHistoryHead;
    configurationFiles: readonly string[];
    artifacts: readonly {
        name: string;
        digest: string;
        bytes: number;
    }[];
}>;
export type Manifest = Readonly<{
    format: typeof STORE_FORMAT;
    profile: typeof P.version;
    instance: string;
    generation: number;
    phase: 'ACTIVE' | 'INACTIVE';
    genesisHash: string;
    head: core.PortableHistoryHead;
    canonicalBytes: number;
    nodes: number;
    encodedBytes: number;
    segments: readonly Descriptor[];
    migration: MigrationBinding | null;
}>;
export type Revision = Readonly<{
    instance: string;
    generation: number;
    head: core.PortableHistoryHead;
}>;
export type Snapshot = Readonly<{
    history: VerifiedHistory;
    revision: Revision;
    manifest: Manifest;
    capacity: ReturnType<typeof historyCapacity>;
}>;
const same = (a: unknown, b: unknown) => core.canonicalEncode(a) === core.canonicalEncode(b);
export function bindingContents(path: string, m: Manifest) {
    if (!m.migration)
        fail('MIGRATION_REQUIRED');
    return { version: 'continuity-history-binding/1', profile: P.version, migrationId: m.migration.id, store: resolve(path), instance: m.instance, genesisHash: m.genesisHash };
}
export function markerContents(path: string, m: Manifest) {
    if (!m.migration)
        fail('MIGRATION_REQUIRED');
    return { version: 'continuity-migrated-file/1', migrationId: m.migration.id, target: resolve(path), instance: m.instance, sourceDigest: m.migration.sourceDigest, sourceHead: m.migration.sourceHead };
}
function checkHead(head: unknown) {
    exact(head, ['hash', 'position', 'canonicalTime']);
    if (typeof head.hash !== 'string' || !/^0x[0-9a-f]{64}$/.test(head.hash) || !integer(head.position, P.maxEvents - 1) || !integer(head.canonicalTime, Number.MAX_SAFE_INTEGER))
        fail('MANIFEST_INVALID');
}
function checkMigration(v: unknown) {
    if (v === null)
        return;
    exact(v, ['id', 'source', 'sourceDigest', 'sourceHead', 'configurationFiles', 'artifacts']);
    if (!uuid(v.id) || typeof v.source !== 'string' || v.source.length > 4096 || resolve(v.source) !== v.source || !digest(v.sourceDigest))
        fail('MANIFEST_INVALID');
    checkHead(v.sourceHead);
    if (!Array.isArray(v.configurationFiles) || v.configurationFiles.length < 1 || v.configurationFiles.length > 16 || new Set(v.configurationFiles).size !== v.configurationFiles.length)
        fail('MANIFEST_INVALID');
    for (const p of v.configurationFiles)
        if (typeof p !== 'string' || p.length > 4096 || resolve(p) !== p)
            fail('MANIFEST_INVALID');
    if (!Array.isArray(v.artifacts) || v.artifacts.length > LIMITS.artifacts)
        fail('MANIFEST_INVALID');
    const names = new Set();
    for (const a of v.artifacts) {
        exact(a, ['name', 'digest', 'bytes']);
        if (!/^artifact-[0-9]{2}\.bin$/.test(a.name) || names.has(a.name) || !digest(a.digest) || !integer(a.bytes, LIMITS.artifactBytes))
            fail('MANIFEST_INVALID');
        names.add(a.name);
    }
}
function decodeManifest(bytes: Buffer): Manifest {
    if (bytes.length > LIMITS.manifestBytes)
        fail('MANIFEST_LIMIT');
    const m = parse(bytes);
    exact(m, ['format', 'profile', 'instance', 'generation', 'phase', 'genesisHash', 'head', 'canonicalBytes', 'nodes', 'encodedBytes', 'segments', 'migration']);
    if (m.format !== STORE_FORMAT || m.profile !== P.version || !uuid(m.instance) || !integer(m.generation, 4096) || !['ACTIVE', 'INACTIVE'].includes(m.phase) ||
        typeof m.genesisHash !== 'string' || !/^0x[0-9a-f]{64}$/.test(m.genesisHash))
        fail('MANIFEST_INVALID');
    checkHead(m.head);
    checkMigration(m.migration);
    if (!integer(m.canonicalBytes, P.maxCanonicalHistoryBytes) || !integer(m.nodes, P.maxHistoryNodes) || !integer(m.encodedBytes, LIMITS.historyBytes) ||
        !Array.isArray(m.segments) || m.segments.length < 1 || m.segments.length > LIMITS.segments)
        fail('MANIFEST_INVALID');
    let position = 0, canonical = 0, nodes = 0, encoded = 0;
    const digests = new Set();
    for (const d of m.segments) {
        exact(d, ['digest', 'start', 'count', 'canonicalBytes', 'nodes', 'encodedBytes']);
        if (!digest(d.digest) || digests.has(d.digest) || d.start !== position || !integer(d.count, LIMITS.segmentEvents) || !d.count ||
            !integer(d.canonicalBytes, 512 * 1024) || !integer(d.nodes, P.maxEventNodes * LIMITS.segmentEvents) || !integer(d.encodedBytes, LIMITS.segmentBytes) || !d.encodedBytes || json(d).length > LIMITS.descriptorBytes)
            fail('MANIFEST_INVALID');
        position += d.count;
        canonical += d.canonicalBytes;
        nodes += d.nodes;
        encoded += d.encodedBytes;
        digests.add(d.digest);
    }
    if (position !== m.head.position + 1 || canonical !== m.canonicalBytes || nodes !== m.nodes || encoded !== m.encodedBytes)
        fail('MANIFEST_INVALID');
    return core.immutableProtocolValue(m) as Manifest;
}
export function readManifest(path: string) { directory(path); return decodeManifest(read(join(path, 'manifest.json'), LIMITS.manifestBytes)); }
export function verifyMigrationBinding(path: string, m: Manifest) {
    if (!m.migration)
        return;
    if (!read(m.migration.source, 4096).equals(json(markerContents(path, m))))
        fail('MIGRATION_MARKER_MISMATCH');
    if (sha(read(join(path, 'source-original.bin'), LIMITS.sourceBytes)) !== m.migration.sourceDigest)
        fail('SOURCE_BACKUP_MISMATCH');
    for (const p of m.migration.configurationFiles)
        if (!read(p, 16384).equals(json(bindingContents(path, m))))
            fail('CONFIGURATION_MISMATCH');
    for (const a of m.migration.artifacts)
        if (sha(read(join(path, 'artifacts', a.name), LIMITS.artifactBytes)) !== a.digest)
            fail('ARTIFACT_MISMATCH');
}
export function readSnapshot(path: string, allowInactive = false): Snapshot {
    path = directory(path);
    const m = readManifest(path);
    directory(join(path, 'segments'));
    if (!allowInactive) {
        if (m.phase !== 'ACTIVE')
            fail('STORE_INACTIVE');
        verifyMigrationBinding(path, m);
    }
    const events: core.PortableCanonicalEvent[] = [];
    let canonical = 0, nodes = 0;
    for (const d of m.segments) {
        const bytes = read(join(path, 'segments', d.digest + '.jsonl'), LIMITS.segmentBytes);
        if (bytes.length !== d.encodedBytes || sha(bytes) !== d.digest || bytes.at(-1) !== 10)
            fail('SEGMENT_CORRUPT');
        const lines = new TextDecoder('utf-8', { fatal: true }).decode(bytes).split('\n');
        lines.pop();
        if (lines.length !== d.count)
            fail('SEGMENT_CORRUPT');
        let segmentCanonical = 0, segmentNodes = 0;
        for (const line of lines) {
            const event = decodeEvent(Buffer.from(line + '\n')) as core.PortableCanonicalEvent;
            events.push(event);
            segmentCanonical += Buffer.byteLength(core.canonicalEncode(event));
            // Same value/key/container census as H02, counted without interpreting event semantics.
            segmentNodes += countNodes(event);
        }
        if (segmentCanonical !== d.canonicalBytes || segmentNodes !== d.nodes)
            fail('SEGMENT_CORRUPT');
        canonical += segmentCanonical;
        nodes += segmentNodes;
    }
    const history = captureContinuationHistory({ operationVersion: CONTINUATION_HISTORY_VERSION, events, expectedHead: m.head });
    if (m.migration && !same(continuationPrefix(history, m.migration.sourceHead.position).head, m.migration.sourceHead))
        fail('SOURCE_PREFIX_MISMATCH');
    if (history.metrics.canonicalBytes !== canonical || history.metrics.nodes !== nodes || continuationPrefix(history, 0).head.hash !== m.genesisHash)
        fail('MANIFEST_INVALID');
    const capacity = historyCapacity(history, m.segments.length);
    if (!capacity.compatible)
        fail('CAPACITY_INCOMPATIBLE');
    return Object.freeze({ history, revision: Object.freeze({ instance: m.instance, generation: m.generation, head: m.head }), manifest: m, capacity });
}
function countNodes(v: unknown): number { return 1 + (Array.isArray(v) ? v.reduce<number>((n, x) => n + countNodes(x), 0) : v && typeof v === 'object' ? Object.values(v).reduce<number>((n, x) => n + 1 + countNodes(x), 0) : 0); }
function segment(events: readonly core.PortableCanonicalEvent[], start: number) {
    const bytes = Buffer.concat(events.map(encodeEvent));
    if (bytes.length > LIMITS.segmentBytes)
        fail('SEGMENT_LIMIT');
    const descriptor = { digest: sha(bytes), start, count: events.length, canonicalBytes: events.reduce((n, e) => n + Buffer.byteLength(core.canonicalEncode(e)), 0), nodes: events.reduce((n, e) => n + countNodes(e), 0), encodedBytes: bytes.length };
    if (json(descriptor).length > LIMITS.descriptorBytes)
        fail('MANIFEST_LIMIT');
    return { bytes, descriptor };
}
export function inventory(path: string, m: Manifest) {
    const expected = new Set(m.segments.map(d => d.digest + '.jsonl'));
    const orphans: {
        name: string;
        bytes: number;
        sha256: string;
    }[] = [];
    const segmentNames = fs.readdirSync(join(path, 'segments'));
    if (segmentNames.length > LIMITS.segments + LIMITS.orphanFiles)
        fail('ORPHAN_LIMIT');
    for (const name of segmentNames) {
        if (!/^[0-9a-f]{64}\.jsonl$/.test(name))
            fail('UNRECOGNIZED_FILE');
        if (!expected.has(name)) {
            const bytes = read(join(path, 'segments', name), LIMITS.segmentBytes);
            orphans.push({ name: 'segments/' + name, bytes: bytes.length, sha256: sha(bytes) });
        }
    }
    const allowed = new Set(['segments', 'artifacts', 'manifest.json', 'source-original.bin', 'migration-plan.json', '.writer-lock', '.writer-lock.recovery']);
    const names = fs.readdirSync(path);
    if (names.length > LIMITS.orphanFiles + allowed.size)
        fail('ORPHAN_LIMIT');
    for (const name of names) {
        if (allowed.has(name))
            continue;
        if (!/^manifest\.[0-9a-f-]{36}\.tmp$/.test(name))
            fail('UNRECOGNIZED_FILE');
        const bytes = read(join(path, name), LIMITS.manifestBytes);
        orphans.push({ name, bytes: bytes.length, sha256: sha(bytes) });
    }
    if (orphans.length > LIMITS.orphanFiles || orphans.reduce((n, x) => n + x.bytes, 0) > LIMITS.orphanBytes)
        fail('ORPHAN_LIMIT');
    orphans.sort((a, b) => a.name.localeCompare(b.name));
    return Object.freeze(orphans.map(o => Object.freeze(o)));
}
export function publishManifest(path: string, m: Manifest, h: Hooks = {}) {
    const bytes = json(m);
    decodeManifest(bytes);
    const tmp = join(path, 'manifest.' + randomUUID() + '.tmp');
    writeNew(tmp, bytes, h);
    h.point?.('manifest-file-synced');
    h.point?.('before-manifest-replace');
    rename(tmp, join(path, 'manifest.json'), h);
    h.point?.('manifest-replaced');
    syncDirectory(path, h);
    h.point?.('manifest-directory-synced');
}
/** Internal creation. INACTIVE migration stores remain unavailable to normal opens. */
export function initializeStore(path: string, history: VerifiedHistory, options: {
    instance?: string;
    phase?: 'ACTIVE' | 'INACTIVE';
    migration?: MigrationBinding | null;
    segmentEvents?: number;
    resume?: boolean;
} = {}, h: Hooks = {}): Snapshot {
    const events = exportContinuationEvents(history), size = options.segmentEvents ?? LIMITS.segmentEvents;
    if (!integer(size, LIMITS.segmentEvents) || !size)
        fail('SEGMENT_LIMIT');
    const chunks: ReturnType<typeof segment>[] = [];
    for (let i = 0; i < events.length; i += size)
        chunks.push(segment(events.slice(i, i + size), i));
    const capacity = historyCapacity(history, chunks.length);
    if (!capacity.compatible)
        fail('CAPACITY_INCOMPATIBLE');
    path = join(directory(dirname(resolve(path))), basename(path));
    if (!options.resume || !fs.existsSync(path))
        fs.mkdirSync(path, { mode: 0o700 });
    else
        directory(path);
    for (const name of ['segments', 'artifacts']) {
        if (!fs.existsSync(join(path, name)))
            fs.mkdirSync(join(path, name), { mode: 0o700 });
        else
            directory(join(path, name));
    }
    syncDirectory(dirname(path));
    syncDirectory(path);
    const m: Manifest = { format: STORE_FORMAT, profile: P.version, instance: options.instance ?? randomUUID(), generation: 0, phase: options.phase ?? 'ACTIVE',
        genesisHash: continuationPrefix(history, 0).head.hash, head: history.head, canonicalBytes: history.metrics.canonicalBytes, nodes: history.metrics.nodes,
        encodedBytes: capacity.usage.encodedBytes, segments: chunks.map(c => c.descriptor), migration: options.migration ?? null };
    withLock(path, () => {
        if (fs.existsSync(join(path, 'manifest.json'))) {
            const actual = readSnapshot(path, true);
            if (!same(actual.manifest, m))
                fail('STAGED_TARGET_CONFLICT');
            return;
        }
        inventory(path, m);
        for (const c of chunks)
            writeImmutable(join(path, 'segments', c.descriptor.digest + '.jsonl'), c.bytes, h);
        publishManifest(path, m, h);
    }, h);
    return readSnapshot(path, options.phase === 'INACTIVE');
}
export interface HistoryWriter {
    snapshot(): Snapshot;
    append(event: unknown, expected: unknown): Snapshot;
}
/** Configuration-owned handle; never expose this writer/path to untrusted agent arguments. */
export class DirectoryHistoryStore {
    readonly path: string;
    private readonly hooks: Hooks;
    #uncertain = false;
    constructor(path: string, hooks: Hooks = {}) { this.hooks = hooks; this.path = directory(path); this.snapshot(); }
    static create(path: string, history: VerifiedHistory, options: {
        segmentEvents?: number;
    } = {}) {
        const events = exportContinuationEvents(history);
        if (events.length !== 2 || events[0]?.type !== "DEPLOYMENT_INITIALIZED" || events[1]?.type !== "PRINCIPAL_CREATED")
            fail("MIGRATION_REQUIRED");
        initializeStore(path, history, options);
        return new DirectoryHistoryStore(path);
    }
    snapshot() { if (this.#uncertain)
        fail('WRITE_UNCERTAIN'); return readSnapshot(this.path); }
    withWriter<T>(callback: (writer: HistoryWriter) => T): T {
        if (types.isAsyncFunction(callback))
            fail('ASYNC_WRITER_FORBIDDEN');
        if (this.#uncertain)
            fail('WRITE_UNCERTAIN');
        let writing = false;
        try {
            return withLock(this.path, () => {
                let active = true, operating = false;
                const check = () => { if (!active)
                    fail('WRITER_EXPIRED'); if (operating)
                    fail('WRITER_REENTRANT'); if (this.#uncertain)
                    fail('WRITE_UNCERTAIN'); };
                const writer = Object.freeze({ snapshot: () => { check(); return this.snapshot(); }, append: (event: unknown, expected: unknown) => {
                        check();
                        operating = true;
                        try {
                            const revision = captureHistoryAncillary(historyDataFields(expected, ['instance', 'generation', 'head']));
                            const current = this.snapshot();
                            if (!same(revision, current.revision))
                                fail('HISTORY_CONFLICT');
                            const next = appendContinuationEvent(current.history, event), nextEvents = exportContinuationEvents(next), c = segment([nextEvents.at(-1)!], current.history.eventCount);
                            const capacity = historyCapacity(next, current.manifest.segments.length + 1);
                            if (!capacity.compatible)
                                fail('CAPACITY_RESERVED');
                            const orphans = inventory(this.path, current.manifest);
                            if (orphans.length + 2 > LIMITS.orphanFiles || orphans.reduce((n, x) => n + x.bytes, 0) + c.bytes.length + LIMITS.manifestBytes > LIMITS.orphanBytes)
                                fail('ORPHAN_LIMIT');
                            const manifest: Manifest = { ...current.manifest, generation: current.revision.generation + 1, head: next.head, canonicalBytes: next.metrics.canonicalBytes, nodes: next.metrics.nodes, encodedBytes: capacity.usage.encodedBytes, segments: [...current.manifest.segments, c.descriptor] };
                            decodeManifest(json(manifest));
                            try {
                                writing = true;
                                this.hooks.point?.('before-segment-create');
                                writeImmutable(join(this.path, 'segments', c.descriptor.digest + '.jsonl'), c.bytes, this.hooks);
                                this.hooks.point?.('segment-synced');
                                publishManifest(this.path, manifest, this.hooks);
                                this.hooks.point?.('before-reply');
                            }
                            catch {
                                this.#uncertain = true;
                                return fail('WRITE_UNCERTAIN');
                            }
                            return readSnapshot(this.path);
                        }
                        finally {
                            operating = false;
                        }
                    } });
                try {
                    return callback(writer);
                }
                finally {
                    active = false;
                }
            }, this.hooks);
        }
        catch (error) {
            if (writing) {
                this.#uncertain = true;
                return fail('WRITE_UNCERTAIN');
            }
            throw error;
        }
    }
    append(event: unknown, expected: Revision) { return this.withWriter(w => w.append(event, expected)); }
    inspectOrphans() { const s = this.snapshot(); return inventory(this.path, s.manifest); }
    /** Explicit operator cleanup, exact inventory and revision. Never invoked automatically. */
    cleanupOrphans(expected: Revision, selected: readonly {
        name: string;
        bytes: number;
        sha256: string;
    }[]) {
        return this.withWriter(w => {
            const s = w.snapshot();
            if (!same(expected, s.revision))
                fail('HISTORY_CONFLICT');
            const all = inventory(this.path, s.manifest);
            if (!same(all, selected))
                fail('ORPHAN_INVENTORY_CHANGED');
            for (const item of all)
                fs.unlinkSync(join(this.path, item.name));
            syncDirectory(join(this.path, 'segments'));
            syncDirectory(this.path);
            return all.length;
        });
    }
}
