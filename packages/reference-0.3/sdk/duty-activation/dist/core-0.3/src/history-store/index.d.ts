import { DirectoryHistoryStore } from './store.ts';
export { DirectoryHistoryStore, readSnapshot, type Snapshot, type Revision } from './store.ts';
export { historyCapacity } from './capacity.ts';
export { prepareMigration, stageMigration, activateMigration, inspectMigration, readMigrationPlan } from './migration.ts';
export { recoverLock, lockRecord } from './files.ts';
export { HistoryStoreError, LIMITS as HISTORY_STORAGE_LIMITS } from './codec.ts';
/** No lock is held while signing. Live head and time are checked again under the writer lock. */
export declare function commitHistoryAdministration(store: DirectoryHistoryStore, input: unknown, options: {
    signHash: (hash: any) => Promise<any>;
    now: () => number;
}): Promise<Readonly<{
    history: import("../history.ts").VerifiedHistory;
    revision: import("./store.ts").Revision;
    manifest: import("./store.ts").Manifest;
    capacity: ReturnType<typeof import("./capacity.ts").historyCapacity>;
}>>;
/** Open the exact H03 configuration selected during migration. Remote/MCP configuration is H04 work. */
export declare function openHistoryBinding(configurationFile: string): DirectoryHistoryStore;
