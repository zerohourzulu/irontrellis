import * as core from '../../../core-0.2/src/core/index.ts';
import { CONTINUATION_PROFILE as P, type VerifiedHistory } from '../history.ts';
import { historyCapacity } from './capacity.ts';
import { type Hooks } from './files.ts';
export declare const STORE_FORMAT = "continuity-directory-history/1";
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
export declare function bindingContents(path: string, m: Manifest): {
    version: string;
    profile: "continuity-segmented-local/1";
    migrationId: string;
    store: string;
    instance: string;
    genesisHash: string;
};
export declare function markerContents(path: string, m: Manifest): {
    version: string;
    migrationId: string;
    target: string;
    instance: string;
    sourceDigest: string;
    sourceHead: Readonly<{
        hash: core.ContentHash;
        position: number;
        canonicalTime: number;
    }>;
};
export declare function readManifest(path: string): Readonly<{
    format: typeof STORE_FORMAT;
    profile: typeof P.version;
    instance: string;
    generation: number;
    phase: "ACTIVE" | "INACTIVE";
    genesisHash: string;
    head: core.PortableHistoryHead;
    canonicalBytes: number;
    nodes: number;
    encodedBytes: number;
    segments: readonly Descriptor[];
    migration: MigrationBinding | null;
}>;
export declare function verifyMigrationBinding(path: string, m: Manifest): void;
export declare function readSnapshot(path: string, allowInactive?: boolean): Snapshot;
export declare function inventory(path: string, m: Manifest): readonly Readonly<{
    name: string;
    bytes: number;
    sha256: string;
}>[];
export declare function publishManifest(path: string, m: Manifest, h?: Hooks): void;
/** Internal creation. INACTIVE migration stores remain unavailable to normal opens. */
export declare function initializeStore(path: string, history: VerifiedHistory, options?: {
    instance?: string;
    phase?: 'ACTIVE' | 'INACTIVE';
    migration?: MigrationBinding | null;
    segmentEvents?: number;
    resume?: boolean;
}, h?: Hooks): Snapshot;
export interface HistoryWriter {
    snapshot(): Snapshot;
    append(event: unknown, expected: unknown): Snapshot;
}
/** Configuration-owned handle; never expose this writer/path to untrusted agent arguments. */
export declare class DirectoryHistoryStore {
    #private;
    readonly path: string;
    private readonly hooks;
    constructor(path: string, hooks?: Hooks);
    static create(path: string, history: VerifiedHistory, options?: {
        segmentEvents?: number;
    }): DirectoryHistoryStore;
    snapshot(): Readonly<{
        history: VerifiedHistory;
        revision: Revision;
        manifest: Manifest;
        capacity: ReturnType<typeof historyCapacity>;
    }>;
    withWriter<T>(callback: (writer: HistoryWriter) => T): T;
    append(event: unknown, expected: Revision): Readonly<{
        history: VerifiedHistory;
        revision: Revision;
        manifest: Manifest;
        capacity: ReturnType<typeof historyCapacity>;
    }>;
    inspectOrphans(): readonly Readonly<{
        name: string;
        bytes: number;
        sha256: string;
    }>[];
    /** Explicit operator cleanup, exact inventory and revision. Never invoked automatically. */
    cleanupOrphans(expected: Revision, selected: readonly {
        name: string;
        bytes: number;
        sha256: string;
    }[]): number;
}
