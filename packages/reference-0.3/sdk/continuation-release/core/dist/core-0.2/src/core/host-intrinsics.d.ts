export declare const HostTypeError: TypeErrorConstructor;
export declare const hostObjectPrototype: Object;
export declare const reflectGetPrototypeOf: typeof Reflect.getPrototypeOf;
export declare const reflectOwnKeys: typeof Reflect.ownKeys;
export declare const reflectGetOwnPropertyDescriptor: typeof Reflect.getOwnPropertyDescriptor;
export declare const objectCreate: {
    (o: object | null): any;
    (o: object | null, properties: PropertyDescriptorMap & ThisType<any>): any;
};
export declare const objectDefineProperty: <T>(o: T, p: PropertyKey, attributes: PropertyDescriptor & ThisType<any>) => T;
export declare const objectFreeze: {
    <T extends Function>(f: T): T;
    <T extends {
        [idx: string]: U | null | undefined | object;
    }, U extends string | bigint | number | boolean | symbol>(o: T): Readonly<T>;
    <T>(o: T): Readonly<T>;
};
export declare const objectGetPrototypeOf: (o: any) => any;
export declare const objectHasOwn: (o: object, v: PropertyKey) => boolean;
export declare const objectIs: (value1: any, value2: any) => boolean;
export declare const objectEntries: {
    <T>(o: {
        [s: string]: T;
    } | ArrayLike<T>): [string, T][];
    (o: {}): [string, any][];
};
/** Define one data property without consulting inherited descriptor fields. */
export declare const objectDefineDataProperty: (target: object, key: PropertyKey, value: unknown, writable?: boolean, enumerable?: boolean, configurable?: boolean) => void;
export declare const arrayIsArray: (arg: any) => arg is any[];
export declare const numberIsFinite: (number: unknown) => boolean;
export declare const numberIsSafeInteger: (number: unknown) => boolean;
export declare const mathCeil: (x: number) => number;
export declare const mathMax: (...values: number[]) => number;
export declare const mathMin: (...values: number[]) => number;
export declare const jsonStringify: {
    (value: any, replacer?: (this: any, key: string, value: any) => any, space?: string | number): string;
    (value: any, replacer?: (number | string)[] | null, space?: string | number): string;
};
export declare const reflectApply: <T>(operation: (...args: never[]) => T, receiver: unknown, argumentsList: readonly unknown[]) => T;
export declare const arrayPush: <T>(target: T[], value: T) => number;
export declare const arrayPop: <T>(target: T[]) => T | undefined;
export declare const arraySort: <T>(target: T[], compare: (left: T, right: T) => number) => T[];
export declare const arrayIncludes: <T>(target: readonly T[], value: T) => boolean;
export declare const arrayJoin: (target: readonly string[], separator: string) => string;
export declare const copyArray: <T>(source: readonly T[]) => T[];
export declare const stringCharCodeAt: (value: string, index: number) => number;
export declare const stringPadStart: (value: string, targetLength: number, fill: string) => string;
export declare const stringSlice: (value: string, start: number, end?: number) => string;
export declare const stringStartsWith: (value: string, prefix: string) => boolean;
export declare const stringToLowerCase: (value: string) => string;
export declare const numberToString: (value: number, radix?: number) => string;
export declare const bigintToString: (value: bigint, radix?: number) => string;
export declare const numberFrom: (value: unknown) => number;
export declare const bigintFrom: (value: string | number | bigint | boolean) => bigint;
export declare const stringFrom: (value: unknown) => string;
export declare const regExpTest: (expression: RegExp, value: string) => boolean;
export declare const utf8Encode: (value: string) => Uint8Array;
export declare const uint8ArrayLength: (value: Uint8Array) => number;
export declare const createMap: <K, V>() => Map<K, V>;
export declare const mapGet: <K, V>(map: ReadonlyMap<K, V>, key: K) => V | undefined;
export declare const mapSet: <K, V>(map: Map<K, V>, key: K, value: V) => void;
export declare const mapHas: <K, V>(map: ReadonlyMap<K, V>, key: K) => boolean;
export declare const mapDelete: <K, V>(map: Map<K, V>, key: K) => boolean;
export declare const mapSize: <K, V>(map: ReadonlyMap<K, V>) => number;
export declare const mapForEach: <K, V>(map: ReadonlyMap<K, V>, callback: (value: V, key: K) => void) => void;
export declare const copyMap: <K, V>(source: ReadonlyMap<K, V>) => Map<K, V>;
export declare const createSet: <T>() => Set<T>;
export declare const setAdd: <T>(set: Set<T>, value: T) => void;
export declare const setHas: <T>(set: ReadonlySet<T>, value: T) => boolean;
export declare const setDelete: <T>(set: Set<T>, value: T) => boolean;
export declare const setSize: <T>(set: ReadonlySet<T>) => number;
export declare const setForEach: <T>(set: ReadonlySet<T>, callback: (value: T) => void) => void;
export declare const setToArray: <T>(source: ReadonlySet<T>) => T[];
export declare const createWeakMap: <K extends object, V>() => WeakMap<K, V>;
export declare const weakMapGet: <K extends object, V>(map: WeakMap<K, V>, key: K) => V | undefined;
export declare const weakMapSet: <K extends object, V>(map: WeakMap<K, V>, key: K, value: V) => void;
export declare const weakMapHas: <K extends object, V>(map: WeakMap<K, V>, key: K) => boolean;
export declare const createWeakSet: <T extends object>() => WeakSet<T>;
export declare const weakSetAdd: <T extends object>(set: WeakSet<T>, value: T) => void;
export declare const weakSetHas: <T extends object>(set: WeakSet<T>, value: T) => boolean;
export declare const weakSetDelete: <T extends object>(set: WeakSet<T>, value: T) => boolean;
/**
 * Opaque package-owned incremental Keccak-256 state.
 *
 * The caller-visible handle is frozen and carries no readable state. Runtime
 * provenance is the retained WeakMap entry, so a copied, spread, or forged
 * object cannot enter the hashing primitive.
 */
export type Keccak256State = Readonly<object>;
/** Creates one frozen, provenance-bound empty Keccak-256 state. */
export declare const createKeccak256State: () => Keccak256State;
/**
 * Absorbs each supplied byte exactly once into a package-owned state.
 * Prototype operations and mutable third-party dispatch are not consulted.
 */
export declare const updateKeccak256State: (handle: Keccak256State, input: Uint8Array) => Keccak256State;
/** Returns an independent state containing all 50 words and the exact rate position. */
export declare const cloneKeccak256State: (handle: Keccak256State) => Keccak256State;
/**
 * Returns the digest of an independent private clone. The caller-visible base
 * remains reusable, repeat-finalizable, and available for later updates.
 */
export declare const finalizeKeccak256State: (handle: Keccak256State) => `0x${string}`;
/** Package-owned one-shot Keccak-256 through the same incremental primitive. */
export declare const keccak256Bytes: (input: Uint8Array) => `0x${string}`;
