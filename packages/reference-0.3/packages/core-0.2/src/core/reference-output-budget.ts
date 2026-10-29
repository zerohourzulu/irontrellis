/**
 * Package-private accounting for constructed reference results. Callers must
 * pass captured or package-owned, synchronous plain data, never caller getters.
 * This measures without cloning the result or changing its record prototypes.
 */
import {
  captureBoundedCanonicalValue,
  getCanonicalCaptureLimitErrorMetadata,
} from "./canonical.ts";
import {
  HostTypeError,
  arrayIsArray,
  arrayJoin,
  createWeakMap,
  createWeakSet,
  hostObjectPrototype,
  numberIsSafeInteger,
  objectCreate,
  objectFreeze,
  objectHasOwn,
  reflectGetOwnPropertyDescriptor,
  reflectGetPrototypeOf,
  reflectOwnKeys,
  stringStartsWith,
  uint8ArrayLength,
  utf8Encode,
  weakMapGet,
  weakMapSet,
  weakSetAdd,
  weakSetDelete,
  weakSetHas,
} from "./host-intrinsics.ts";

export const REFERENCE_OUTPUT_LIMITS = objectFreeze({
  bytes: 16_777_216,
  stringBytes: 4_096,
  listMembers: 4_096,
  recordFields: 256,
  depth: 32,
  evidenceOccurrences: 4_096,
});

const OUTPUT_OVERFLOW = objectFreeze(objectCreate(null));

export const throwReferenceOutputOverflow = (): never => {
  throw OUTPUT_OVERFLOW;
};

export const isReferenceOutputOverflow = (error: unknown): boolean =>
  error === OUTPUT_OVERFLOW;

export interface ReferenceOutputMetrics {
  readonly bytes: number;
  readonly depth: number;
}

const metrics = (bytes: number, depth: number): ReferenceOutputMetrics =>
  objectFreeze({ bytes, depth });

const ownData = (value: object, key: PropertyKey): unknown => {
  const descriptor = reflectGetOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !objectHasOwn(descriptor, "value")) {
    throw new HostTypeError("Reference output accounting requires own data properties.");
  }
  return descriptor.value;
};

const canonicalScalarMetrics = (value: unknown): ReferenceOutputMetrics => {
  try {
    const captured = captureBoundedCanonicalValue(value);
    return metrics(captured.canonicalBytes, 0);
  } catch (error) {
    if (getCanonicalCaptureLimitErrorMetadata(error) !== undefined) {
      throwReferenceOutputOverflow();
    }
    throw error;
  }
};

/** Exact canonical size/depth; aliases count at every occurrence. */
export const measureReferenceOutput = (value: unknown): ReferenceOutputMetrics => {
  const active = createWeakSet<object>();
  const memo = createWeakMap<object, ReferenceOutputMetrics>();
  let used = 0;
  const reserve = (bytes: number): void => {
    if (bytes > REFERENCE_OUTPUT_LIMITS.bytes - used) {
      used = REFERENCE_OUTPUT_LIMITS.bytes + 1;
      throwReferenceOutputOverflow();
    }
    used += bytes;
  };
  const visit = (current: unknown, ancestorDepth: number): ReferenceOutputMetrics => {
    if (current === null || typeof current !== "object") {
      const measured = canonicalScalarMetrics(current);
      reserve(measured.bytes);
      return measured;
    }
    if (weakSetHas(active, current)) {
      throw new HostTypeError("Reference output contains a cycle.");
    }
    const cached = weakMapGet(memo, current);
    if (cached !== undefined) {
      if (ancestorDepth + cached.depth > REFERENCE_OUTPUT_LIMITS.depth) {
        throwReferenceOutputOverflow();
      }
      reserve(cached.bytes);
      return cached;
    }
    const isArray = arrayIsArray(current);
    if (!isArray) {
      const prototype = reflectGetPrototypeOf(current);
      if (prototype !== hostObjectPrototype && prototype !== null) {
        throw new HostTypeError("Reference output contains a non-plain record.");
      }
    }
    const arrayLength = isArray ? ownData(current, "length") : undefined;
    if (isArray) {
      if (!numberIsSafeInteger(arrayLength) || (arrayLength as number) < 0) {
        throw new HostTypeError("Reference output has invalid array length.");
      }
      if ((arrayLength as number) > REFERENCE_OUTPUT_LIMITS.listMembers) {
        throwReferenceOutputOverflow();
      }
    }
    const keys = reflectOwnKeys(current);
    if (!isArray && keys.length > REFERENCE_OUTPUT_LIMITS.recordFields) {
      throwReferenceOutputOverflow();
    }
    // Exact BigInt wire markers have scalar depth, including at depth32.
    let hasReservedKey = false;
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index]!;
      if (typeof key !== "string") {
        throw new HostTypeError("Reference output contains a symbol key.");
      }
      ownData(current, key);
      if (stringStartsWith(key, "$continuity.")) hasReservedKey = true;
    }
    if (!isArray && hasReservedKey) {
      const measured = canonicalScalarMetrics(current);
      reserve(measured.bytes);
      weakMapSet(memo, current, measured);
      return measured;
    }
    const containingDepth = ancestorDepth + 1;
    if (containingDepth > REFERENCE_OUTPUT_LIMITS.depth) {
      throwReferenceOutputOverflow();
    }
    const started = used;
    let maximumChildDepth = 0;
    reserve(2); // Both delimiters are reserved before any member.
    weakSetAdd(active, current);
    try {
      if (isArray) {
        const length = arrayLength as number;
        if (keys.length !== (length as number) + 1) {
          throw new HostTypeError("Reference output contains a sparse or expanded array.");
        }
        for (let index = 0; index < (length as number); index += 1) {
          if (index > 0) reserve(1);
          const child = visit(ownData(current, `${index}`), containingDepth);
          if (child.depth > maximumChildDepth) maximumChildDepth = child.depth;
        }
      } else {
        let fields = 0;
        for (let index = 0; index < keys.length; index += 1) {
          const key = keys[index] as string;
          // Keys are bounded even when their undefined value is omitted.
          const keyMetrics = canonicalScalarMetrics(key);
          const field = ownData(current, key);
          if (field === undefined) continue;
          if (fields > 0) reserve(1);
          reserve(keyMetrics.bytes + 1);
          const child = visit(field, containingDepth);
          if (child.depth > maximumChildDepth) maximumChildDepth = child.depth;
          fields += 1;
        }
      }
    } finally {
      weakSetDelete(active, current);
    }
    const measured = metrics(used - started, 1 + maximumChildDepth);
    weakMapSet(memo, current, measured);
    return measured;
  };
  return visit(value, 0);
};

/** Each part is a whole, well-formed string; reserve the combined scalar first. */
export const referenceOutputString = (parts: readonly string[]): string => {
  let rawBytes = 0;
  let canonicalBytes = 2;
  for (let index = 0; index < parts.length; index += 1) {
    const part = parts[index]!;
    const measured = canonicalScalarMetrics(part);
    const bytes = uint8ArrayLength(utf8Encode(part));
    if (bytes > REFERENCE_OUTPUT_LIMITS.stringBytes - rawBytes) {
      throwReferenceOutputOverflow();
    }
    rawBytes += bytes;
    const interiorBytes = measured.bytes - 2;
    if (interiorBytes > REFERENCE_OUTPUT_LIMITS.bytes - canonicalBytes) {
      throwReferenceOutputOverflow();
    }
    canonicalBytes += interiorBytes;
  }
  return arrayJoin(parts, "");
};

export interface ReferenceOutputBudget {
  readonly remainingBytes: number;
  reserve(value: ReferenceOutputMetrics, ancestorDepth: number, evidenceOccurrences?: number): void;
  append(value: unknown, currentLength: number, ancestorDepth: number, evidenceOccurrences?: number): void;
  replace(previous: unknown, next: unknown, ancestorDepth: number, evidenceDelta?: number): void;
}

/**
 * Start from the actual fixed skeleton with empty dynamic lists. append charges
 * the member and its preceding comma only; skeleton delimiters are not repeated.
 * ancestorDepth is the number of containing records/lists outside that member.
 * Evidence counts are schema-owned: RESPONSIBLE counts emitted references,
 * including repetitions, after deduplication of whole attributions.
 */
export const createReferenceOutputBudget = (
  skeleton: unknown,
  evidenceOccurrences = 0,
): ReferenceOutputBudget => {
  let used = measureReferenceOutput(skeleton).bytes;
  let evidenceUsed = evidenceOccurrences;
  const fail = (): never => {
    used = REFERENCE_OUTPUT_LIMITS.bytes + 1;
    return throwReferenceOutputOverflow();
  };
  const requireActive = (): void => {
    if (used > REFERENCE_OUTPUT_LIMITS.bytes) throwReferenceOutputOverflow();
  };
  const checkEvidence = (count: number): void => {
    if (!numberIsSafeInteger(count) || count < 0) {
      throw new HostTypeError("Reference evidence accounting must be a nonnegative integer.");
    }
    if (count > REFERENCE_OUTPUT_LIMITS.evidenceOccurrences) fail();
  };
  checkEvidence(evidenceUsed);
  const reserve = (
    value: ReferenceOutputMetrics,
    ancestorDepth: number,
    occurrences = 0,
  ): void => {
    requireActive();
    if (
      !numberIsSafeInteger(value.bytes) || value.bytes < 0 ||
      !numberIsSafeInteger(value.depth) || value.depth < 0 ||
      !numberIsSafeInteger(ancestorDepth) || ancestorDepth < 0
    ) throw new HostTypeError("Reference output reservation has invalid metrics.");
    checkEvidence(occurrences);
    if (
      value.depth + ancestorDepth > REFERENCE_OUTPUT_LIMITS.depth ||
      value.bytes > REFERENCE_OUTPUT_LIMITS.bytes - used ||
      occurrences > REFERENCE_OUTPUT_LIMITS.evidenceOccurrences - evidenceUsed
    ) {
      fail();
    }
    used += value.bytes;
    evidenceUsed += occurrences;
  };
  return objectFreeze({
    get remainingBytes(): number { return REFERENCE_OUTPUT_LIMITS.bytes - used; },
    reserve,
    append(value: unknown, currentLength: number, ancestorDepth: number, occurrences = 0): void {
      requireActive();
      if (!numberIsSafeInteger(currentLength) || currentLength < 0) {
        throw new HostTypeError("Reference output append has invalid list length.");
      }
      if (currentLength >= REFERENCE_OUTPUT_LIMITS.listMembers) fail();
      let measured: ReferenceOutputMetrics;
      try {
        measured = measureReferenceOutput(value);
      } catch (error) {
        if (isReferenceOutputOverflow(error)) fail();
        throw error;
      }
      reserve(metrics(measured.bytes + (currentLength === 0 ? 0 : 1), measured.depth), ancestorDepth, occurrences);
    },
    replace(previous: unknown, next: unknown, ancestorDepth: number, evidenceDelta = 0): void {
      requireActive();
      let priorMetrics: ReferenceOutputMetrics;
      let nextMetrics: ReferenceOutputMetrics;
      try {
        priorMetrics = measureReferenceOutput(previous);
        nextMetrics = measureReferenceOutput(next);
      } catch (error) {
        if (isReferenceOutputOverflow(error)) fail();
        throw error;
      }
      if (!numberIsSafeInteger(evidenceDelta)) {
        throw new HostTypeError("Reference evidence delta must be a safe integer.");
      }
      checkEvidence(evidenceUsed + evidenceDelta);
      if (!numberIsSafeInteger(ancestorDepth) || ancestorDepth < 0) {
        throw new HostTypeError("Reference output replacement has invalid depth.");
      }
      const replacementBytes = used - priorMetrics.bytes + nextMetrics.bytes;
      if (replacementBytes < 0) throw new HostTypeError("Reference output replacement was not reserved.");
      if (
        replacementBytes > REFERENCE_OUTPUT_LIMITS.bytes ||
        nextMetrics.depth + ancestorDepth > REFERENCE_OUTPUT_LIMITS.depth
      ) {
        fail();
      }
      used = replacementBytes;
      evidenceUsed += evidenceDelta;
    },
  });
};
