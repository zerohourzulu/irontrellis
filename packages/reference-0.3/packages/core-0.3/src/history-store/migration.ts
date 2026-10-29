/** Explicit local maintenance. Call only after quiescing writers/coordinators/dispatch. */
import * as fs from 'node:fs';
import { resolve, join, dirname, basename } from 'node:path';
import { randomUUID } from 'node:crypto';
import * as core from '../../../core-0.2/src/core/index.ts';
import { PortableFileEventStore } from '../../../core-0.2/src/indexer/portable-file-event-store.ts';
import { captureContinuationHistory, CONTINUATION_HISTORY_VERSION, type VerifiedHistory } from '../history.ts';
import { historyCapacity } from './capacity.ts';
import { LIMITS, fail, exact, digest, uuid, integer, json, parse } from './codec.ts';
import { sha, directory, read, fileInfo, writeImmutable, syncDirectory, rename, withLock, type Hooks } from './files.ts';
import { initializeStore, readSnapshot, readManifest, publishManifest, verifyMigrationBinding, bindingContents, markerContents, type MigrationBinding, type Manifest } from './store.ts';
export type MigrationPlan = Readonly<{
    version: 'continuity-history-migration/1';
    phase: 'PLANNED';
    id: string;
    source: string;
    target: string;
    instance: string;
    sourceDigest: string;
    sourceDevice: number;
    sourceInode: number;
    sourceHead: core.PortableHistoryHead;
    configurationFiles: readonly string[];
    artifacts: readonly {
        source: string;
        name: string;
        digest: string;
        bytes: number;
    }[];
}>;
const same = (a: unknown, b: unknown) => core.canonicalEncode(a) === core.canonicalEncode(b);
const full = (v: unknown): string => { if (typeof v !== 'string' || !v || v.length > 4096)
    fail('PATH_INVALID'); const p = resolve(v); return join(directory(dirname(p)), basename(p)); };
function sourceHistory(source: string, expected: core.PortableHistoryHead): VerifiedHistory {
    const events = new PortableFileEventStore(source).readAll();
    return captureContinuationHistory({ operationVersion: CONTINUATION_HISTORY_VERSION, events, expectedHead: expected });
}
export function readMigrationPlan(path: string): MigrationPlan {
    const p = parse(read(path, 32768));
    exact(p, ['version', 'phase', 'id', 'source', 'target', 'instance', 'sourceDigest', 'sourceDevice', 'sourceInode', 'sourceHead', 'configurationFiles', 'artifacts']);
    if (p.version !== 'continuity-history-migration/1' || p.phase !== 'PLANNED' || !uuid(p.id) || !uuid(p.instance) || !digest(p.sourceDigest) ||
        !integer(p.sourceDevice, Number.MAX_SAFE_INTEGER) || !integer(p.sourceInode, Number.MAX_SAFE_INTEGER) || full(p.source) !== p.source || full(p.target) !== p.target)
        fail('PLAN_INVALID');
    exact(p.sourceHead, ['hash', 'position', 'canonicalTime']);
    if (typeof p.sourceHead.hash !== 'string' || !/^0x[0-9a-f]{64}$/.test(p.sourceHead.hash) || !integer(p.sourceHead.position, 1023) || !integer(p.sourceHead.canonicalTime, Number.MAX_SAFE_INTEGER))
        fail('PLAN_INVALID');
    if (!Array.isArray(p.configurationFiles) || p.configurationFiles.length < 1 || p.configurationFiles.length > 16 || new Set(p.configurationFiles).size !== p.configurationFiles.length)
        fail('PLAN_INVALID');
    for (const c of p.configurationFiles)
        if (full(c) !== c)
            fail('PLAN_INVALID');
    if (!Array.isArray(p.artifacts) || p.artifacts.length > LIMITS.artifacts)
        fail('PLAN_INVALID');
    for (let i = 0; i < p.artifacts.length; i++) {
        const a = p.artifacts[i];
        exact(a, ['source', 'name', 'digest', 'bytes']);
        if (full(a.source) !== a.source || a.name !== `artifact-${String(i).padStart(2, '0')}.bin` || !digest(a.digest) || !integer(a.bytes, LIMITS.artifactBytes))
            fail('PLAN_INVALID');
    }
    return core.immutableProtocolValue(p) as MigrationPlan;
}
function metadata(p: MigrationPlan): MigrationBinding { return { id: p.id, source: p.source, sourceDigest: p.sourceDigest, sourceHead: p.sourceHead, configurationFiles: p.configurationFiles, artifacts: p.artifacts.map(({ source: _source, ...rest }) => rest) }; }
function compatibleSource(p: MigrationPlan) {
    const bytes = read(p.source, LIMITS.sourceBytes), info = fileInfo(p.source, LIMITS.sourceBytes);
    if (sha(bytes) !== p.sourceDigest || info.dev !== p.sourceDevice || info.ino !== p.sourceInode)
        fail('SOURCE_CHANGED');
    return bytes;
}
export function prepareMigration(input: {
    sourceFile: string;
    targetDirectory: string;
    planFile: string;
    expectedHead: core.PortableHistoryHead;
    configurationFiles: readonly string[];
    artifactFiles: readonly string[];
    quiesced: true;
}): MigrationPlan {
    if (input.quiesced !== true)
        fail('QUIESCENCE_REQUIRED');
    const source = full(input.sourceFile), target = full(input.targetDirectory), planFile = full(input.planFile);
    const configurationFiles = input.configurationFiles.map(full), artifactFiles = input.artifactFiles.map(full);
    if (configurationFiles.length < 1 || configurationFiles.length > 16 || artifactFiles.length > LIMITS.artifacts || new Set(configurationFiles).size !== configurationFiles.length || new Set(artifactFiles).size !== artifactFiles.length)
        fail('PLAN_INVALID');
    const destinations = [source, target, planFile, ...configurationFiles];
    if (new Set(destinations).size !== destinations.length || configurationFiles.some(p => p.startsWith(target + '/')) || planFile.startsWith(target + '/') || source.startsWith(target + '/'))
        fail('PATH_INVALID');
    for (const p of [target, planFile, ...configurationFiles])
        if (fs.existsSync(p))
            fail('DESTINATION_EXISTS');
    return withLock(dirname(source), () => {
        const bytes = read(source, LIMITS.sourceBytes), info = fileInfo(source, LIMITS.sourceBytes), history = sourceHistory(source, input.expectedHead);
        if (!historyCapacity(history, Math.ceil(history.eventCount / LIMITS.segmentEvents)).compatible)
            fail('CAPACITY_INCOMPATIBLE');
        if (!read(source, LIMITS.sourceBytes).equals(bytes))
            fail('SOURCE_CHANGED');
        const artifacts = artifactFiles.map((source, i) => { const data = read(source, LIMITS.artifactBytes); return { source, name: `artifact-${String(i).padStart(2, '0')}.bin`, digest: sha(data), bytes: data.length }; });
        const plan: MigrationPlan = { version: 'continuity-history-migration/1', phase: 'PLANNED', id: randomUUID(), instance: randomUUID(), source, target, sourceDigest: sha(bytes), sourceDevice: info.dev, sourceInode: info.ino, sourceHead: history.head, configurationFiles, artifacts };
        if (json(plan).length > 32768)
            fail('PLAN_LIMIT');
        writeImmutable(planFile, json(plan));
        return readMigrationPlan(planFile);
    }, {}, basename(source) + '.writer-lock');
}
export function stageMigration(planFile: string, options: {
    quiesced: true;
}, hooks: Hooks = {}) {
    if (options.quiesced !== true)
        fail('QUIESCENCE_REQUIRED');
    const plan = readMigrationPlan(planFile);
    return withLock(dirname(plan.source), () => {
        const bytes = compatibleSource(plan), history = sourceHistory(plan.source, plan.sourceHead);
        const staged = initializeStore(plan.target, history, { instance: plan.instance, phase: 'INACTIVE', migration: metadata(plan), resume: true }, hooks);
        writeImmutable(join(plan.target, 'migration-plan.json'), json(plan));
        writeImmutable(join(plan.target, 'source-original.bin'), bytes);
        fs.chmodSync(join(plan.target, 'source-original.bin'), 0o400);
        const backupFd = fs.openSync(join(plan.target, 'source-original.bin'), 'r');
        try {
            fs.fsyncSync(backupFd);
        }
        finally {
            fs.closeSync(backupFd);
        }
        for (const a of plan.artifacts) {
            const bytes = read(a.source, LIMITS.artifactBytes);
            if (bytes.length !== a.bytes || sha(bytes) !== a.digest)
                fail('ARTIFACT_CHANGED');
            writeImmutable(join(plan.target, 'artifacts', a.name), bytes);
        }
        syncDirectory(plan.target);
        hooks.point?.('migration-staged');
        return staged;
    }, {}, basename(plan.source) + '.writer-lock');
}
function checkTarget(plan: MigrationPlan) {
    const s = readSnapshot(plan.target, true);
    if (s.manifest.instance !== plan.instance || !same(s.manifest.migration, metadata(plan)))
        fail('STAGED_TARGET_CONFLICT');
    if (s.manifest.phase === 'INACTIVE' && !same(s.history.head, plan.sourceHead))
        fail('STAGED_TARGET_CONFLICT');
    if (sha(read(join(plan.target, 'source-original.bin'), LIMITS.sourceBytes)) !== plan.sourceDigest || !read(join(plan.target, 'migration-plan.json'), 32768).equals(json(plan)))
        fail('STAGED_TARGET_CONFLICT');
    for (const a of plan.artifacts)
        if (sha(read(join(plan.target, 'artifacts', a.name), LIMITS.artifactBytes)) !== a.digest)
            fail('ARTIFACT_MISMATCH');
    return s;
}
/** Resume is based on real marker/config/manifest bytes, never the plan's phase label. */
export function activateMigration(planFile: string, options: {
    quiesced: true;
}, hooks: Hooks = {}) {
    if (options.quiesced !== true)
        fail('QUIESCENCE_REQUIRED');
    const p = readMigrationPlan(planFile);
    return withLock(dirname(p.source), () => withLock(p.target, () => {
        const staged = checkTarget(p), m = staged.manifest;
        if (m.phase === 'ACTIVE') {
            verifyMigrationBinding(p.target, m);
            return readSnapshot(p.target);
        }
        const expectedMarker = json(markerContents(p.target, m)), source = read(p.source, LIMITS.sourceBytes);
        if (!source.equals(expectedMarker))
            compatibleSource(p);
        for (const f of p.configurationFiles)
            if (fs.existsSync(f) && !read(f, 16384).equals(json(bindingContents(p.target, m))))
                fail('CONFIGURATION_MISMATCH');
        hooks.point?.('before-source-marker');
        if (!source.equals(expectedMarker)) {
            const temporary = p.source + '.migration-' + p.id + '.tmp';
            writeImmutable(temporary, expectedMarker, hooks);
            rename(temporary, p.source, hooks);
            hooks.point?.('source-marker-replaced');
            syncDirectory(dirname(p.source), hooks);
        }
        else
            syncDirectory(dirname(p.source), hooks);
        hooks.point?.('source-marker-synced');
        for (const f of p.configurationFiles)
            writeImmutable(f, json(bindingContents(p.target, m)), hooks);
        hooks.point?.('configurations-synced');
        verifyMigrationBinding(p.target, m);
        const active: Manifest = { ...m, phase: 'ACTIVE', generation: m.generation + 1 };
        publishManifest(p.target, active, hooks);
        hooks.point?.('migration-active');
        return readSnapshot(p.target);
    }, hooks), {}, basename(p.source) + '.writer-lock');
}
export function inspectMigration(planFile: string) {
    const p = readMigrationPlan(planFile);
    let targetPhase = 'UNAVAILABLE', sourcePhase = 'UNKNOWN';
    try {
        const m = readManifest(p.target);
        targetPhase = m.phase;
        const b = read(p.source, LIMITS.sourceBytes);
        sourcePhase = b.equals(json(markerContents(p.target, m))) ? 'MARKED' : sha(b) === p.sourceDigest ? 'ORIGINAL' : 'CHANGED';
    }
    catch { /* Explicitly unavailable, never a writable fallback. */ }
    return Object.freeze({ id: p.id, source: p.source, target: p.target, sourcePhase, targetPhase, dispatchReady: targetPhase === 'ACTIVE' && sourcePhase === 'MARKED' ? (() => { try {
            checkTarget(p);
            readSnapshot(p.target);
            return true;
        }
        catch {
            return false;
        } })() : false });
}
