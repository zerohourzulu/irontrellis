/** Trusted local filesystem, cooperative writers. No network filesystem or hostile-admin guarantee. */
import * as fs from 'node:fs';
export declare const sha: (bytes: Buffer) => string;
export type Hooks = Readonly<{
    point?: (name: string) => void;
    write?: (fd: number, bytes: Buffer, offset: number, length: number) => number;
    sync?: (fd: number, label: string) => void;
    rename?: (from: string, to: string) => void;
}>;
export declare function directory(path: string): string;
export declare function fileInfo(path: string, max: number): fs.Stats;
export declare function read(path: string, max: number): Buffer;
export declare const sync: (fd: number, label: string, h: Hooks) => void;
export declare function syncDirectory(path: string, h?: Hooks): void;
export declare function writeNew(path: string, bytes: Buffer, h?: Hooks): void;
export declare function writeImmutable(path: string, bytes: Buffer, h?: Hooks): void;
export declare const rename: (from: string, to: string, h?: Hooks) => void;
export declare function lockRecord(path: string): Readonly<{
    bytes: Buffer<ArrayBufferLike>;
    record: Record<string, any>;
    sha256: string;
}>;
export declare function withLock<T>(dir: string, callback: () => T, h?: Hooks, lockName?: string): T;
/** Exact record + same recorded hostname + OS-confirmed absent PID; age is irrelevant. */
export declare function recoverLock(dir: string, expectedSha256: string, lockName?: string): void;
