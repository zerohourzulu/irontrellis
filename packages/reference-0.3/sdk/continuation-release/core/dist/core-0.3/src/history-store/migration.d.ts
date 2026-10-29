import * as core from '../../../core-0.2/src/core/index.ts';
import { type VerifiedHistory } from '../history.ts';
import { historyCapacity } from './capacity.ts';
import { type Hooks } from './files.ts';
import { type Manifest } from './store.ts';
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
export declare function readMigrationPlan(path: string): MigrationPlan;
export declare function prepareMigration(input: {
    sourceFile: string;
    targetDirectory: string;
    planFile: string;
    expectedHead: core.PortableHistoryHead;
    configurationFiles: readonly string[];
    artifactFiles: readonly string[];
    quiesced: true;
}): MigrationPlan;
export declare function stageMigration(planFile: string, options: {
    quiesced: true;
}, hooks?: Hooks): Readonly<{
    history: VerifiedHistory;
    revision: import("./store.ts").Revision;
    manifest: Manifest;
    capacity: ReturnType<typeof historyCapacity>;
}>;
/** Resume is based on real marker/config/manifest bytes, never the plan's phase label. */
export declare function activateMigration(planFile: string, options: {
    quiesced: true;
}, hooks?: Hooks): Readonly<{
    history: VerifiedHistory;
    revision: import("./store.ts").Revision;
    manifest: Manifest;
    capacity: ReturnType<typeof historyCapacity>;
}>;
export declare function inspectMigration(planFile: string): Readonly<{
    id: string;
    source: string;
    target: string;
    sourcePhase: string;
    targetPhase: string;
    dispatchReady: boolean;
}>;
