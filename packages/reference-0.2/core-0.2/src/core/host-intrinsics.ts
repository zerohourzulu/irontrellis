/*
 * Package-internal JavaScript host boundary.
 *
 * Continuity assumes the realm primordials are sound when this module is
 * initialized. Caller accessors may run later, so protocol-sensitive code
 * invokes only the references retained here. Nothing in this module freezes
 * or repairs the surrounding realm.
 */

const HostArray = Array;
const HostMap = Map;
const HostSet = Set;
const HostWeakMap = WeakMap;
const HostWeakSet = WeakSet;
const HostBigInt = BigInt;
const HostString = String;
const HostNumber = Number;
const HostTextEncoder = TextEncoder;
const HostUint8Array = Uint8Array;

export const HostTypeError = TypeError;
export const hostObjectPrototype = Object.prototype;

const reflectApplyOperation = Reflect.apply;
export const reflectGetPrototypeOf = Reflect.getPrototypeOf;
export const reflectOwnKeys = Reflect.ownKeys;
export const reflectGetOwnPropertyDescriptor = Reflect.getOwnPropertyDescriptor;

export const objectCreate = Object.create;
export const objectDefineProperty = Object.defineProperty;
export const objectFreeze = Object.freeze;
export const objectGetPrototypeOf = Object.getPrototypeOf;
export const objectHasOwn = Object.hasOwn;
export const objectIs = Object.is;
export const objectEntries = Object.entries;

/** Define one data property without consulting inherited descriptor fields. */
export const objectDefineDataProperty = (
  target: object,
  key: PropertyKey,
  value: unknown,
  writable = false,
  enumerable = false,
  configurable = false,
): void => {
  const descriptor = objectCreate(null) as PropertyDescriptor;
  descriptor.value = value;
  descriptor.writable = writable;
  descriptor.enumerable = enumerable;
  descriptor.configurable = configurable;
  objectDefineProperty(target, key, descriptor);
};

export const arrayIsArray = HostArray.isArray;
export const numberIsFinite = HostNumber.isFinite;
export const numberIsSafeInteger = HostNumber.isSafeInteger;
export const mathCeil = Math.ceil;
export const mathMax = Math.max;
export const mathMin = Math.min;
export const jsonStringify = JSON.stringify;

const arrayPopOperation = HostArray.prototype.pop;
const arraySortOperation = HostArray.prototype.sort;
const arrayIncludesOperation = HostArray.prototype.includes;
const arrayJoinOperation = HostArray.prototype.join;
const stringCharCodeAtOperation = HostString.prototype.charCodeAt;
const stringPadStartOperation = HostString.prototype.padStart;
const stringSliceOperation = HostString.prototype.slice;
const stringStartsWithOperation = HostString.prototype.startsWith;
const stringToLowerCaseOperation = HostString.prototype.toLowerCase;
const numberToStringOperation = HostNumber.prototype.toString;
const bigintToStringOperation = HostBigInt.prototype.toString;
const regExpExecOperation = RegExp.prototype.exec;

const mapGetOperation = HostMap.prototype.get;
const mapSetOperation = HostMap.prototype.set;
const mapHasOperation = HostMap.prototype.has;
const mapDeleteOperation = HostMap.prototype.delete;
const mapForEachOperation = HostMap.prototype.forEach;
const setAddOperation = HostSet.prototype.add;
const setHasOperation = HostSet.prototype.has;
const setDeleteOperation = HostSet.prototype.delete;
const setForEachOperation = HostSet.prototype.forEach;
const weakMapGetOperation = HostWeakMap.prototype.get;
const weakMapSetOperation = HostWeakMap.prototype.set;
const weakMapHasOperation = HostWeakMap.prototype.has;
const weakSetAddOperation = HostWeakSet.prototype.add;
const weakSetHasOperation = HostWeakSet.prototype.has;
const weakSetDeleteOperation = HostWeakSet.prototype.delete;

const mapSizeGetter = reflectGetOwnPropertyDescriptor(HostMap.prototype, "size")!
  .get!;
const setSizeGetter = reflectGetOwnPropertyDescriptor(HostSet.prototype, "size")!
  .get!;
const textEncoder = new HostTextEncoder();
const textEncoderEncodeOperation = HostTextEncoder.prototype.encode;

const uint8ArrayPrototype = HostUint8Array.prototype;
const typedArrayPrototype = reflectGetPrototypeOf(uint8ArrayPrototype)!;
const typedArrayLengthGetter = reflectGetOwnPropertyDescriptor(
  typedArrayPrototype,
  "length",
)!.get!;

export const reflectApply = <T>(
  operation: (...args: never[]) => T,
  receiver: unknown,
  argumentsList: readonly unknown[],
): T => reflectApplyOperation(operation, receiver, argumentsList) as T;

export const arrayPush = <T>(target: T[], value: T): number =>
  (() => {
    objectDefineDataProperty(target, `${target.length}`, value, true, true, true);
    return target.length;
  })();

export const arrayPop = <T>(target: T[]): T | undefined =>
  reflectApplyOperation(arrayPopOperation, target, []) as T | undefined;

export const arraySort = <T>(
  target: T[],
  compare: (left: T, right: T) => number,
): T[] => reflectApplyOperation(arraySortOperation, target, [compare]) as T[];

export const arrayIncludes = <T>(
  target: readonly T[],
  value: T,
): boolean => reflectApplyOperation(arrayIncludesOperation, target, [value]) as boolean;

export const arrayJoin = (target: readonly string[], separator: string): string =>
  reflectApplyOperation(arrayJoinOperation, target, [separator]) as string;

export const copyArray = <T>(source: readonly T[]): T[] => {
  const copy: T[] = [];
  for (let index = 0; index < source.length; index += 1) {
    arrayPush(copy, source[index]!);
  }
  return copy;
};

export const stringCharCodeAt = (value: string, index: number): number =>
  reflectApplyOperation(stringCharCodeAtOperation, value, [index]) as number;

export const stringPadStart = (
  value: string,
  targetLength: number,
  fill: string,
): string =>
  reflectApplyOperation(stringPadStartOperation, value, [targetLength, fill]) as string;

export const stringSlice = (value: string, start: number, end?: number): string =>
  reflectApplyOperation(
    stringSliceOperation,
    value,
    end === undefined ? [start] : [start, end],
  ) as string;

export const stringStartsWith = (value: string, prefix: string): boolean =>
  reflectApplyOperation(stringStartsWithOperation, value, [prefix]) as boolean;

export const stringToLowerCase = (value: string): string =>
  reflectApplyOperation(stringToLowerCaseOperation, value, []) as string;

export const numberToString = (value: number, radix = 10): string =>
  reflectApplyOperation(numberToStringOperation, value, [radix]) as string;

export const bigintToString = (value: bigint, radix = 10): string =>
  reflectApplyOperation(bigintToStringOperation, value, [radix]) as string;

export const numberFrom = (value: unknown): number => HostNumber(value);
export const bigintFrom = (value: string | number | bigint | boolean): bigint =>
  HostBigInt(value);
export const stringFrom = (value: unknown): string => HostString(value);

export const regExpTest = (expression: RegExp, value: string): boolean =>
  reflectApplyOperation(regExpExecOperation, expression, [value]) !== null;

export const utf8Encode = (value: string): Uint8Array =>
  reflectApplyOperation(textEncoderEncodeOperation, textEncoder, [value]) as Uint8Array;

export const uint8ArrayLength = (value: Uint8Array): number =>
  reflectApplyOperation(typedArrayLengthGetter, value, []) as number;

export const createMap = <K, V>(): Map<K, V> => new HostMap<K, V>();
export const mapGet = <K, V>(map: ReadonlyMap<K, V>, key: K): V | undefined =>
  reflectApplyOperation(mapGetOperation, map, [key]) as V | undefined;
export const mapSet = <K, V>(map: Map<K, V>, key: K, value: V): void => {
  reflectApplyOperation(mapSetOperation, map, [key, value]);
};
export const mapHas = <K, V>(map: ReadonlyMap<K, V>, key: K): boolean =>
  reflectApplyOperation(mapHasOperation, map, [key]) as boolean;
export const mapDelete = <K, V>(map: Map<K, V>, key: K): boolean =>
  reflectApplyOperation(mapDeleteOperation, map, [key]) as boolean;
export const mapSize = <K, V>(map: ReadonlyMap<K, V>): number =>
  reflectApplyOperation(mapSizeGetter, map, []) as number;
export const mapForEach = <K, V>(
  map: ReadonlyMap<K, V>,
  callback: (value: V, key: K) => void,
): void => {
  reflectApplyOperation(mapForEachOperation, map, [callback]);
};
export const copyMap = <K, V>(source: ReadonlyMap<K, V>): Map<K, V> => {
  const copy = createMap<K, V>();
  mapForEach(source, (value, key) => mapSet(copy, key, value));
  return copy;
};

export const createSet = <T>(): Set<T> => new HostSet<T>();
export const setAdd = <T>(set: Set<T>, value: T): void => {
  reflectApplyOperation(setAddOperation, set, [value]);
};
export const setHas = <T>(set: ReadonlySet<T>, value: T): boolean =>
  reflectApplyOperation(setHasOperation, set, [value]) as boolean;
export const setDelete = <T>(set: Set<T>, value: T): boolean =>
  reflectApplyOperation(setDeleteOperation, set, [value]) as boolean;
export const setSize = <T>(set: ReadonlySet<T>): number =>
  reflectApplyOperation(setSizeGetter, set, []) as number;
export const setForEach = <T>(
  set: ReadonlySet<T>,
  callback: (value: T) => void,
): void => {
  reflectApplyOperation(setForEachOperation, set, [callback]);
};
export const setToArray = <T>(source: ReadonlySet<T>): T[] => {
  const copy: T[] = [];
  setForEach(source, (value) => arrayPush(copy, value));
  return copy;
};

export const createWeakMap = <K extends object, V>(): WeakMap<K, V> =>
  new HostWeakMap<K, V>();
export const weakMapGet = <K extends object, V>(
  map: WeakMap<K, V>,
  key: K,
): V | undefined => reflectApplyOperation(weakMapGetOperation, map, [key]) as V | undefined;
export const weakMapSet = <K extends object, V>(
  map: WeakMap<K, V>,
  key: K,
  value: V,
): void => {
  reflectApplyOperation(weakMapSetOperation, map, [key, value]);
};
export const weakMapHas = <K extends object, V>(
  map: WeakMap<K, V>,
  key: K,
): boolean => reflectApplyOperation(weakMapHasOperation, map, [key]) as boolean;

export const createWeakSet = <T extends object>(): WeakSet<T> =>
  new HostWeakSet<T>();
export const weakSetAdd = <T extends object>(set: WeakSet<T>, value: T): void => {
  reflectApplyOperation(weakSetAddOperation, set, [value]);
};
export const weakSetHas = <T extends object>(set: WeakSet<T>, value: T): boolean =>
  reflectApplyOperation(weakSetHasOperation, set, [value]) as boolean;
export const weakSetDelete = <T extends object>(set: WeakSet<T>, value: T): boolean =>
  reflectApplyOperation(weakSetDeleteOperation, set, [value]) as boolean;

const KECCAK_PI: number[] = [];
const KECCAK_ROTL: number[] = [];
const KECCAK_IOTA_LOW: number[] = [];
const KECCAK_IOTA_HIGH: number[] = [];
const U32_MASK_BIGINT = 0xffff_ffffn;
let keccakRoundConstant = 1n;
let keccakX = 1;
let keccakY = 0;
for (let round = 0; round < 24; round += 1) {
  const nextX = keccakY;
  const nextY = (2 * keccakX + 3 * keccakY) % 5;
  keccakX = nextX;
  keccakY = nextY;
  KECCAK_PI[round] = 2 * (5 * keccakY + keccakX);
  KECCAK_ROTL[round] = (((round + 1) * (round + 2)) / 2) % 64;
  let iota = 0n;
  for (let bit = 0; bit < 7; bit += 1) {
    keccakRoundConstant =
      ((keccakRoundConstant << 1n) ^
        ((keccakRoundConstant >> 7n) * 0x71n)) %
      256n;
    if ((keccakRoundConstant & 2n) !== 0n) {
      iota ^= 1n << ((1n << BigInt(bit)) - 1n);
    }
  }
  KECCAK_IOTA_LOW[round] = Number(iota & U32_MASK_BIGINT);
  KECCAK_IOTA_HIGH[round] = Number((iota >> 32n) & U32_MASK_BIGINT);
}
objectFreeze(KECCAK_PI);
objectFreeze(KECCAK_ROTL);
objectFreeze(KECCAK_IOTA_LOW);
objectFreeze(KECCAK_IOTA_HIGH);

const rotateHigh = (high: number, low: number, shift: number): number =>
  shift === 0
    ? high
    : shift === 32
      ? low
      : shift > 32
        ? (low << (shift - 32)) | (high >>> (64 - shift))
        : (high << shift) | (low >>> (32 - shift));

const rotateLow = (high: number, low: number, shift: number): number =>
  shift === 0
    ? low
    : shift === 32
      ? high
      : shift > 32
        ? (high << (shift - 32)) | (low >>> (64 - shift))
        : (low << shift) | (high >>> (32 - shift));

type KeccakWordTable = Record<number, number>;

type Keccak256StateData = {
  readonly words: KeccakWordTable;
  readonly scratch: KeccakWordTable;
  position: number;
};

/**
 * Opaque package-owned incremental Keccak-256 state.
 *
 * The caller-visible handle is frozen and carries no readable state. Runtime
 * provenance is the retained WeakMap entry, so a copied, spread, or forged
 * object cannot enter the hashing primitive.
 */
export type Keccak256State = Readonly<object>;

const KECCAK_256_STATES = createWeakMap<object, Keccak256StateData>();

const emptyKeccakWordTable = (length: number): KeccakWordTable => {
  const words = objectCreate(null) as KeccakWordTable;
  for (let index = 0; index < length; index += 1) words[index] = 0;
  return words;
};

const copyKeccakWordTable = (
  source: KeccakWordTable,
  length: number,
): KeccakWordTable => {
  const copy = objectCreate(null) as KeccakWordTable;
  for (let index = 0; index < length; index += 1) {
    copy[index] = source[index]!;
  }
  return copy;
};

const keccak256StateHandle = (data: Keccak256StateData): Keccak256State => {
  const handle = objectFreeze(objectCreate(null));
  weakMapSet(KECCAK_256_STATES, handle, data);
  return handle;
};

const keccak256StateData = (handle: Keccak256State): Keccak256StateData => {
  const data = weakMapGet(KECCAK_256_STATES, handle);
  if (data === undefined) {
    throw new HostTypeError(
      "Keccak-256 state must be a package-owned incremental state handle.",
    );
  }
  return data;
};

const keccakPermutation = (
  state: KeccakWordTable,
  scratch: KeccakWordTable,
): void => {
  for (let round = 0; round < 24; round += 1) {
    for (let x = 0; x < 10; x += 1) {
      scratch[x] =
        state[x]! ^
        state[x + 10]! ^
        state[x + 20]! ^
        state[x + 30]! ^
        state[x + 40]!;
    }
    for (let x = 0; x < 10; x += 2) {
      const previousColumn = (x + 8) % 10;
      const nextColumn = (x + 2) % 10;
      const thetaHigh = rotateHigh(
        scratch[nextColumn]!,
        scratch[nextColumn + 1]!,
        1,
      ) ^ scratch[previousColumn]!;
      const thetaLow = rotateLow(
        scratch[nextColumn]!,
        scratch[nextColumn + 1]!,
        1,
      ) ^ scratch[previousColumn + 1]!;
      for (let y = 0; y < 50; y += 10) {
        state[x + y] = state[x + y]! ^ thetaHigh;
        state[x + y + 1] = state[x + y + 1]! ^ thetaLow;
      }
    }

    let currentHigh = state[2]!;
    let currentLow = state[3]!;
    for (let lane = 0; lane < 24; lane += 1) {
      const shift = KECCAK_ROTL[lane]!;
      const rotatedHigh = rotateHigh(currentHigh, currentLow, shift);
      const rotatedLow = rotateLow(currentHigh, currentLow, shift);
      const destination = KECCAK_PI[lane]!;
      currentHigh = state[destination]!;
      currentLow = state[destination + 1]!;
      state[destination] = rotatedHigh;
      state[destination + 1] = rotatedLow;
    }

    for (let y = 0; y < 50; y += 10) {
      for (let x = 0; x < 10; x += 1) scratch[x] = state[y + x]!;
      for (let x = 0; x < 10; x += 1) {
        state[y + x] =
          state[y + x]! ^
          (~scratch[(x + 2) % 10]! & scratch[(x + 4) % 10]!);
      }
    }
    state[0] = state[0]! ^ KECCAK_IOTA_LOW[round]!;
    state[1] = state[1]! ^ KECCAK_IOTA_HIGH[round]!;
  }
};

const KECCAK_256_RATE = 136;

const updateKeccak256StateData = (
  data: Keccak256StateData,
  input: Uint8Array,
): void => {
  const length = uint8ArrayLength(input);
  for (let inputIndex = 0; inputIndex < length; inputIndex += 1) {
    const wordIndex = data.position >>> 2;
    const shift = (data.position & 3) * 8;
    data.words[wordIndex] = data.words[wordIndex]! ^
      (input[inputIndex]! << shift);
    data.position += 1;
    if (data.position === KECCAK_256_RATE) {
      keccakPermutation(data.words, data.scratch);
      data.position = 0;
    }
  }
};

/** Creates one frozen, provenance-bound empty Keccak-256 state. */
export const createKeccak256State = (): Keccak256State =>
  keccak256StateHandle({
    words: emptyKeccakWordTable(50),
    scratch: emptyKeccakWordTable(10),
    position: 0,
  });

/**
 * Absorbs each supplied byte exactly once into a package-owned state.
 * Prototype operations and mutable third-party dispatch are not consulted.
 */
export const updateKeccak256State = (
  handle: Keccak256State,
  input: Uint8Array,
): Keccak256State => {
  const data = keccak256StateData(handle);
  updateKeccak256StateData(data, input);
  return handle;
};

/** Returns an independent state containing all 50 words and the exact rate position. */
export const cloneKeccak256State = (
  handle: Keccak256State,
): Keccak256State => {
  const data = keccak256StateData(handle);
  return keccak256StateHandle({
    words: copyKeccakWordTable(data.words, 50),
    scratch: copyKeccakWordTable(data.scratch, 10),
    position: data.position,
  });
};

/**
 * Returns the digest of an independent private clone. The caller-visible base
 * remains reusable, repeat-finalizable, and available for later updates.
 */
export const finalizeKeccak256State = (
  handle: Keccak256State,
): `0x${string}` => {
  const data = keccak256StateData(handle);
  const words = copyKeccakWordTable(data.words, 50);
  const scratch = copyKeccakWordTable(data.scratch, 10);
  const position = data.position;
  words[position >>> 2] = words[position >>> 2]! ^
    (0x01 << ((position & 3) * 8));
  const finalPosition = KECCAK_256_RATE - 1;
  words[finalPosition >>> 2] = words[finalPosition >>> 2]! ^
    (0x80 << ((finalPosition & 3) * 8));
  keccakPermutation(words, scratch);

  let hexadecimal = "0x";
  for (let index = 0; index < 32; index += 1) {
    const byte = (words[index >>> 2]! >>> ((index & 3) * 8)) & 0xff;
    hexadecimal += stringPadStart(numberToString(byte, 16), 2, "0");
  }
  return hexadecimal as `0x${string}`;
};

/** Package-owned one-shot Keccak-256 through the same incremental primitive. */
export const keccak256Bytes = (input: Uint8Array): `0x${string}` => {
  const state = createKeccak256State();
  updateKeccak256State(state, input);
  return finalizeKeccak256State(state);
};
