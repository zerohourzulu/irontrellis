export declare class HistoryStoreError extends Error {
    readonly code: string;
    constructor(code: string);
}
export declare function fail(code: string): never;
export declare const LIMITS: Readonly<{
    eventBytes: 32768;
    segmentEvents: 64;
    segmentBytes: number;
    historyBytes: number;
    manifestBytes: number;
    descriptorBytes: 512;
    segments: 1024;
    orphanFiles: 32;
    orphanBytes: number;
    sourceBytes: number;
    artifacts: 64;
    artifactBytes: number;
}>;
export declare function exact(value: unknown, keys: readonly string[]): asserts value is Record<string, any>;
export declare const integer: (v: unknown, max: number) => boolean;
export declare const digest: (v: unknown) => boolean;
export declare const uuid: (v: unknown) => boolean;
export declare const json: (v: unknown) => Buffer<ArrayBuffer>;
export declare function parse(bytes: Buffer): any;
export declare function encodeEvent(event: unknown): Buffer;
export declare function decodeEvent(bytes: Buffer): unknown;
