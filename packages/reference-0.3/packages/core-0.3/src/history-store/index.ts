import { read, directory } from './files.ts';
import { join, resolve, dirname, basename } from 'node:path';
import { parse, exact } from './codec.ts';
import { DirectoryHistoryStore } from './store.ts';
import { prepareContinuationAdministration, produceContinuationAdministration } from '../history.ts';
import { historyDataFields, captureHistoryAncillary } from '../../../core-0.2/src/history/index.ts';
import { hasAdministrativeRoom } from './capacity.ts';
import { integer, fail } from './codec.ts';
export { DirectoryHistoryStore, readSnapshot, type Snapshot, type Revision } from './store.ts';
export { historyCapacity } from './capacity.ts';
export { prepareMigration, stageMigration, activateMigration, inspectMigration, readMigrationPlan } from './migration.ts';
export { recoverLock, lockRecord } from './files.ts';
export { HistoryStoreError, LIMITS as HISTORY_STORAGE_LIMITS } from './codec.ts';
/** No lock is held while signing. Live head and time are checked again under the writer lock. */
export async function commitHistoryAdministration(store: DirectoryHistoryStore, input: unknown, options: {
    signHash: (hash: any) => Promise<any>;
    now: () => number;
}) {
    const { signHash, now: clock } = options;
    if (typeof signHash !== 'function' || typeof clock !== 'function')
        fail('CONFIGURATION_INVALID');
    const current = store.snapshot();
    const args = captureHistoryAncillary(historyDataFields(input, ['expectedDomain', 'transition', 'runtimeSessionId']));
    const type = (args.transition as { type?: string }).type;
    // D1 finding operations need two callbacks and independent fresh checks.
    // Use the dedicated host writer; this older single-signature route cannot
    // supply that contract by rewriting the finding's signed timestamp.
    if (type === 'ATTEMPT_DUTY_DISPOSITION_RECORDED' || type === 'ATTEMPT_DUTY_CONTEST_RECORDED')
        fail('DUTY_WRITER_REQUIRED');
    const preparedInput = { ...args, expectedHistoryHead: current.history.head };
    prepareContinuationAdministration(current.history, preparedInput);
    if (!hasAdministrativeRoom(current.history, args.transition, current.manifest.segments.length))
        fail('CAPACITY_RESERVED');
    const produced = (await produceContinuationAdministration(current.history, preparedInput, { signHash })).result;
    return store.withWriter(writer => {
        const actual = writer.snapshot();
        if (actual.revision.instance !== current.revision.instance || actual.revision.generation !== current.revision.generation || actual.history.head.hash !== current.history.head.hash)
            fail('HISTORY_CONFLICT');
        const now = clock();
        if (!integer(now, Number.MAX_SAFE_INTEGER) || now < produced.event.timestamp)
            fail('CLOCK_INVALID');
        prepareContinuationAdministration(actual.history, { ...preparedInput, transition: { ...(args.transition as object), timestamp: now } });
        return writer.append(produced.event, current.revision);
    });
}
/** Open the exact H03 configuration selected during migration. Remote/MCP configuration is H04 work. */
export function openHistoryBinding(configurationFile: string) {
    configurationFile = join(directory(dirname(resolve(configurationFile))), basename(configurationFile));
    const config = parse(read(configurationFile, 16384));
    exact(config, ['version', 'profile', 'migrationId', 'store', 'instance', 'genesisHash']);
    if (config.version !== 'continuity-history-binding/1' || typeof config.store !== 'string')
        fail('CONFIGURATION_INVALID');
    const store = new DirectoryHistoryStore(config.store), s = store.snapshot();
    if (!s.manifest.migration || s.manifest.migration.id !== config.migrationId || s.manifest.profile !== config.profile || s.revision.instance !== config.instance || s.manifest.genesisHash !== config.genesisHash ||
        !s.manifest.migration.configurationFiles.includes(configurationFile))
        fail('CONFIGURATION_MISMATCH');
    return store;
}
