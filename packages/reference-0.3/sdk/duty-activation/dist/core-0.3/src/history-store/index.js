import { read, directory } from "./files.js";
import { join, resolve, dirname, basename } from 'node:path';
import { parse, exact } from "./codec.js";
import { DirectoryHistoryStore } from "./store.js";
import { prepareContinuationAdministration, produceContinuationAdministration } from "../history.js";
import { historyDataFields, captureHistoryAncillary } from "../../../core-0.2/src/history/index.js";
import { hasAdministrativeRoom } from "./capacity.js";
import { integer, fail } from "./codec.js";
export { DirectoryHistoryStore, readSnapshot } from "./store.js";
export { historyCapacity } from "./capacity.js";
export { prepareMigration, stageMigration, activateMigration, inspectMigration, readMigrationPlan } from "./migration.js";
export { recoverLock, lockRecord } from "./files.js";
export { HistoryStoreError, LIMITS as HISTORY_STORAGE_LIMITS } from "./codec.js";
/** No lock is held while signing. Live head and time are checked again under the writer lock. */
export async function commitHistoryAdministration(store, input, options) {
    const { signHash, now: clock } = options;
    if (typeof signHash !== 'function' || typeof clock !== 'function')
        fail('CONFIGURATION_INVALID');
    const current = store.snapshot();
    const args = captureHistoryAncillary(historyDataFields(input, ['expectedDomain', 'transition', 'runtimeSessionId']));
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
        prepareContinuationAdministration(actual.history, { ...preparedInput, transition: { ...args.transition, timestamp: now } });
        return writer.append(produced.event, current.revision);
    });
}
/** Open the exact H03 configuration selected during migration. Remote/MCP configuration is H04 work. */
export function openHistoryBinding(configurationFile) {
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
