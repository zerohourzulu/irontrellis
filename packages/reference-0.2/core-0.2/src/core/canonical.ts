import { types as nodeTypes } from "node:util";
const isNodeProxy = nodeTypes.isProxy;
import {
  HostTypeError,
  arrayIncludes,
  arrayIsArray,
  arrayJoin,
  arrayPop,
  arrayPush,
  arraySort,
  bigintFrom,
  bigintToString,
  cloneKeccak256State,
  copyArray,
  createKeccak256State,
  createSet,
  createWeakMap,
  createWeakSet,
  finalizeKeccak256State,
  hostObjectPrototype,
  keccak256Bytes,
  mathCeil,
  mathMax,
  mathMin,
  numberFrom,
  numberIsFinite,
  numberIsSafeInteger,
  numberToString,
  objectCreate,
  objectDefineDataProperty,
  objectFreeze,
  objectHasOwn,
  objectIs,
  reflectApply,
  reflectGetOwnPropertyDescriptor,
  reflectGetPrototypeOf,
  reflectOwnKeys,
  regExpTest,
  setAdd,
  setHas,
  stringCharCodeAt,
  stringFrom,
  stringPadStart,
  stringStartsWith,
  utf8Encode,
  uint8ArrayLength,
  updateKeccak256State,
  weakMapGet,
  weakMapHas,
  weakMapSet,
  weakSetAdd,
  weakSetDelete,
  weakSetHas,
} from "./host-intrinsics.ts";

export type ContentHash = `0x${string}`;

const MAX_PROTOCOL_STRING_UTF8_BYTES = 4_096;
const MAX_AUTHORITY_IDENTIFIER_UTF8_BYTES = 256;
const MAX_AUTHORITY_IDENTIFIER_SET_MEMBERS = 256;
const MAX_AUTHORITY_REQUIRED_INTERSECTIONS = 32;
const MAX_RAW_AUTHORITY_OCCURRENCES = 1_024;
const MAX_CANONICAL_LIST_MEMBERS = 4_096;
const MAX_CANONICAL_RECORD_FIELDS = 256;
const MAX_CANONICAL_DEPTH = 32;
const MAX_CANONICAL_UTF8_BYTES = 16_777_216;
const MAX_REPLAY_EVENT_DATA_UTF8_BYTES = 1_048_576;
const REPLAY_OPERATION_VERSION = "continuity-replay/0.2";
const MAX_PROTOCOL_BIGINT = (1n << 256n) - 1n;
const INVALID_DESIGNATED_SCALAR_CAPTURE_BYTES = 32;
const BIGINT_MARKER_KEY = "$continuity.bigint";
const RESERVED_KEY_PREFIX = "$continuity.";

const Array = objectFreeze({ isArray: arrayIsArray });
const Math = objectFreeze({ ceil: mathCeil, max: mathMax, min: mathMin });
const Number = objectFreeze({
  isFinite: numberIsFinite,
  isSafeInteger: numberIsSafeInteger,
});
const Object = objectFreeze({
  create: objectCreate,
  defineDataProperty: objectDefineDataProperty,
  freeze: objectFreeze,
  hasOwn: objectHasOwn,
  is: objectIs,
  prototype: hostObjectPrototype,
});
const Reflect = objectFreeze({
  apply: reflectApply,
  getOwnPropertyDescriptor: reflectGetOwnPropertyDescriptor,
  getPrototypeOf: reflectGetPrototypeOf,
  ownKeys: reflectOwnKeys,
});
const TypeError = HostTypeError;
const UTF8_ENCODER = objectFreeze({ encode: utf8Encode });
const EVENT_HISTORY_CANONICAL_PREFIX = UTF8_ENCODER.encode(
  '["continuity-event-history/0.2",[',
);
const EVENT_HISTORY_CANONICAL_SEPARATOR = UTF8_ENCODER.encode(",");
const EVENT_HISTORY_CANONICAL_SUFFIX = UTF8_ENCODER.encode("]]");
const REPLAY_VISITOR_PENDING_FIXED_BYTES = uint8ArrayLength(
  UTF8_ENCODER.encode(`],"operationVersion":"${REPLAY_OPERATION_VERSION}"}`),
);

/** True when a JavaScript string represents only Unicode scalar values. */
export const isWellFormedUnicode = (value: string): boolean => {
  for (let index = 0; index < value.length; index += 1) {
    const unit = stringCharCodeAt(value, index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = stringCharCodeAt(value, index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
      continue;
    }
    if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
};

const protocolStringByteLength = (
  value: string,
  location: string,
  maximum = MAX_PROTOCOL_STRING_UTF8_BYTES,
): number => {
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const unit = stringCharCodeAt(value, index);
    if (unit <= 0x7f) {
      bytes += 1;
    } else if (unit <= 0x7ff) {
      bytes += 2;
    } else if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = stringCharCodeAt(value, index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new TypeError(`Canonical string at ${location} is not well-formed Unicode.`);
      }
      bytes += 4;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new TypeError(`Canonical string at ${location} is not well-formed Unicode.`);
    } else {
      bytes += 3;
    }
    if (bytes > maximum) {
      throw canonicalNamedLimitError(
        `Canonical string at ${location} exceeds the ${maximum}-byte ProtocolString bound.`,
        location,
        maximum,
      );
    }
  }
  return bytes;
};

/** Unsigned UTF-8 lexicographic protocol-string order, without normalization. */
export const compareProtocolStrings = (left: string, right: string): number => {
  protocolStringByteLength(left, "$left");
  protocolStringByteLength(right, "$right");
  const leftBytes = UTF8_ENCODER.encode(left);
  const rightBytes = UTF8_ENCODER.encode(right);
  const leftLength = uint8ArrayLength(leftBytes);
  const rightLength = uint8ArrayLength(rightBytes);
  const sharedLength = Math.min(leftLength, rightLength);
  for (let index = 0; index < sharedLength; index += 1) {
    const difference = leftBytes[index]! - rightBytes[index]!;
    if (difference !== 0) return difference < 0 ? -1 : 1;
  }
  return leftLength < rightLength
    ? -1
    : leftLength > rightLength
      ? 1
      : 0;
};

const escapedString = (value: string, location: string): string => {
  protocolStringByteLength(value, location);
  let result = '"';
  for (let index = 0; index < value.length; index += 1) {
    const unit = stringCharCodeAt(value, index);
    if (unit === 0x22) {
      result += '\\"';
    } else if (unit === 0x5c) {
      result += "\\\\";
    } else if (unit <= 0x1f) {
      result += `\\u00${stringPadStart(numberToString(unit, 16), 2, "0")}`;
    } else if (unit >= 0xd800 && unit <= 0xdbff) {
      result += value[index]! + value[index + 1]!;
      index += 1;
    } else {
      result += value[index]!;
    }
  }
  return `${result}"`;
};

type CaptureMode = "STRICT_CANONICAL" | "STRUCTURAL_PHASE_ONE";

type CaptureBudget = {
  readonly label: string;
  readonly limit: number;
  used: number;
};

const CANONICAL_CAPTURE_LIMIT_ERRORS = createWeakMap<
  object,
  Readonly<{ readonly location: string; readonly limit: number }>
>();

const brandCanonicalCaptureLimitError = (
  error: TypeError,
  location: string,
  limit: number,
): TypeError => {
  const metadata = {} as {
    location: string;
    limit: number;
  };
  Object.defineDataProperty(metadata, "location", location, false, true);
  Object.defineDataProperty(metadata, "limit", limit, false, true);
  Object.freeze(metadata);
  weakMapSet(CANONICAL_CAPTURE_LIMIT_ERRORS, error, metadata);
  return error;
};

const canonicalCaptureLimitError = (
  location: string,
  limit: number,
): TypeError => brandCanonicalCaptureLimitError(
  new TypeError(
    `Canonical value at ${location} exceeds the ${limit}-byte canonical capture bound.`,
  ),
  location,
  limit,
);

const canonicalNamedLimitError = (
  message: string,
  location: string,
  limit: number,
): TypeError => brandCanonicalCaptureLimitError(
  new TypeError(message),
  location,
  limit,
);

/** Tests only the module-private identity and exact metadata of a limit failure. */
export const isCanonicalCaptureLimitError = (
  error: unknown,
  location: string,
  limit: number,
): boolean => {
  if (error === null || typeof error !== "object") return false;
  const metadata = weakMapGet(CANONICAL_CAPTURE_LIMIT_ERRORS, error);
  return metadata?.location === location && metadata.limit === limit;
};

/** @internal Exact metadata for routing a package-owned operation limit failure. */
export const getCanonicalCaptureLimitErrorMetadata = (
  error: unknown,
): Readonly<{ readonly location: string; readonly limit: number }> | undefined =>
  error !== null && typeof error === "object"
    ? weakMapGet(CANONICAL_CAPTURE_LIMIT_ERRORS, error)
    : undefined;

type CanonicalRope =
  | Readonly<{
      kind: "TEXT";
      text: string;
      utf8Bytes: number;
    }>
  | Readonly<{
      kind: "SEQUENCE";
      parts: readonly CanonicalRope[];
    }>;

type CapturedNode = {
  observedAccessor?: boolean;
  readonly value: unknown;
  readonly canonicalBytes: number;
  readonly canonicalRope: CanonicalRope | null;
  /** Normative container depth contributed by this value at any occurrence. */
  readonly intrinsicDepth: number;
};

/** @internal One provenance-bound replay-event occurrence from shared capture. */
export type CapturedCanonicalReplayEvent = Readonly<{
  readonly eventPosition: number;
  readonly event: unknown;
  readonly capturedRecordKeys: (
    value: unknown,
  ) => readonly string[] | undefined;
  readonly capturedCanonicalBytes: (value: unknown) => number | undefined;
}>;

const CANONICAL_REPLAY_EVENT_CAPTURES = createWeakSet<object>();

/** Tests module-private provenance for one incrementally captured replay event. */
export const isCapturedCanonicalReplayEvent = (
  value: unknown,
): value is CapturedCanonicalReplayEvent =>
  value !== null &&
  typeof value === "object" &&
  weakSetHas(CANONICAL_REPLAY_EVENT_CAPTURES, value);

export type CanonicalReplayCaptureVisitDecision<T> =
  | Readonly<{ readonly status: "CONTINUE" }>
  | Readonly<{ readonly status: "STOP"; readonly result: T }>;

type CanonicalReplayCaptureVisitor = (
  capture: CapturedCanonicalReplayEvent,
) => CanonicalReplayCaptureVisitDecision<unknown>;

export type PortableAuthorityCaptureKind =
  | "AUTHORITY_PATH_EVALUATION"
  | "AUTHORIZE"
  | "INTENT_ADMISSION";

type PortableAuthorityCaptureState =
  | "RAW_ROOT"
  | "AUTHORIZE_ROOT"
  | "ADMISSION_ROOT"
  | "DOMAIN"
  | "HISTORY_HEAD"
  | "RAW_SCOPE"
  | "ACTION_REQUEST"
  | "CONSEQUENTIAL_BINDING"
  | "RECOGNIZED_ROOT_LIST"
  | "RECOGNIZED_ROOT"
  | "PERMISSION_LIST"
  | "PERMISSION"
  | "PROHIBITION_LIST"
  | "PROHIBITION"
  | "AUTHORITY_CONSTRAINTS"
  | "IDENTIFIER_LIST"
  | "INTERSECTION_IDENTIFIER_LIST"
  | "AUTHORITY_EVIDENCE_LIST"
  | "AUTHORITY_EVIDENCE"
  | "AUTHORITY_USAGE_LIST"
  | "AUTHORITY_USAGE";

type CaptureRole =
  | Readonly<{ readonly kind: "ADAPTER_EVIDENCE" }>
  | Readonly<{ readonly kind: "NORMAL" }>
  | Readonly<{ readonly kind: "REPLAY_ROOT" }>
  | Readonly<{ readonly kind: "REPLAY_EVENTS" }>
  | Readonly<{ readonly kind: "QUERY_EVENTS" }>
  | Readonly<{ readonly kind: "QUERY_EVENT"; readonly index: number }>
  | Readonly<{ readonly kind: "REPLAY_EVENT"; readonly index: number }>
  | Readonly<{ readonly kind: "REPLAY_EVENT_DATA"; readonly index: number }>
  | Readonly<{
      readonly kind: "REPLAY_DESIGNATED_SCALAR";
      readonly maximumStringBytes?: number;
      readonly enforceBigIntBound?: true;
    }>
  | Readonly<{
      readonly kind: "PORTABLE_AUTHORITY";
      readonly state: PortableAuthorityCaptureState;
    }>;

const ADAPTER_EVIDENCE_CAPTURE_ROLE: CaptureRole = Object.freeze({ kind: "ADAPTER_EVIDENCE" });

const NORMAL_CAPTURE_ROLE: CaptureRole = Object.freeze({ kind: "NORMAL" });
const REPLAY_ROOT_CAPTURE_ROLE: CaptureRole = Object.freeze({ kind: "REPLAY_ROOT" });
const REPLAY_EVENTS_CAPTURE_ROLE: CaptureRole = Object.freeze({ kind: "REPLAY_EVENTS" });
const REPLAY_DESIGNATED_SCALAR_CAPTURE_ROLE: CaptureRole = Object.freeze({
  kind: "REPLAY_DESIGNATED_SCALAR",
});
const AUTHORITY_IDENTIFIER_CAPTURE_ROLE: CaptureRole = Object.freeze({
  kind: "REPLAY_DESIGNATED_SCALAR",
  maximumStringBytes: MAX_AUTHORITY_IDENTIFIER_UTF8_BYTES,
});
const RAW_AUTHORITY_AMOUNT_CAPTURE_ROLE: CaptureRole = Object.freeze({
  kind: "REPLAY_DESIGNATED_SCALAR",
  enforceBigIntBound: true,
});

const portableAuthorityRole = (
  state: PortableAuthorityCaptureState,
): CaptureRole => Object.freeze({ kind: "PORTABLE_AUTHORITY", state });

const portableAuthorityRootRole = (
  kind: PortableAuthorityCaptureKind,
): CaptureRole => portableAuthorityRole(
  kind === "AUTHORITY_PATH_EVALUATION"
    ? "RAW_ROOT"
    : kind === "AUTHORIZE"
      ? "AUTHORIZE_ROOT"
      : "ADMISSION_ROOT",
);

const portableAuthorityRecordChildRole = (
  state: PortableAuthorityCaptureState,
  key: string,
): CaptureRole => {
  switch (state) {
    case "RAW_ROOT":
      if (key === "scope") return portableAuthorityRole("RAW_SCOPE");
      if (key === "request") return portableAuthorityRole("ACTION_REQUEST");
      if (key === "permissions") return portableAuthorityRole("PERMISSION_LIST");
      if (key === "prohibitions") return portableAuthorityRole("PROHIBITION_LIST");
      if (key === "authorityEvidence") {
        return portableAuthorityRole("AUTHORITY_EVIDENCE_LIST");
      }
      if (key === "revokedAuthorityIds") {
        return portableAuthorityRole("IDENTIFIER_LIST");
      }
      if (key === "usage") return portableAuthorityRole("AUTHORITY_USAGE_LIST");
      return NORMAL_CAPTURE_ROLE;
    case "AUTHORIZE_ROOT":
      if (key === "events") return REPLAY_EVENTS_CAPTURE_ROLE;
      if (key === "expectedHistoryHead") {
        return portableAuthorityRole("HISTORY_HEAD");
      }
      if (key === "domain") return portableAuthorityRole("DOMAIN");
      if (key === "policyVersion") return AUTHORITY_IDENTIFIER_CAPTURE_ROLE;
      if (key === "evaluationTime") return REPLAY_DESIGNATED_SCALAR_CAPTURE_ROLE;
      if (key === "request") return portableAuthorityRole("ACTION_REQUEST");
      if (key === "binding") {
        return portableAuthorityRole("CONSEQUENTIAL_BINDING");
      }
      return NORMAL_CAPTURE_ROLE;
    case "ADMISSION_ROOT":
      if (key === "events") return REPLAY_EVENTS_CAPTURE_ROLE;
      if (key === "expectedHistoryHead") {
        return portableAuthorityRole("HISTORY_HEAD");
      }
      if (key === "domain") return portableAuthorityRole("DOMAIN");
      if (key === "admissionEventId" || key === "policyVersion") {
        return AUTHORITY_IDENTIFIER_CAPTURE_ROLE;
      }
      if (key === "evaluationTime") return REPLAY_DESIGNATED_SCALAR_CAPTURE_ROLE;
      if (key === "request") return portableAuthorityRole("ACTION_REQUEST");
      if (key === "binding") {
        return portableAuthorityRole("CONSEQUENTIAL_BINDING");
      }
      return NORMAL_CAPTURE_ROLE;
    case "RAW_SCOPE":
      if (key === "domain") return portableAuthorityRole("DOMAIN");
      if (key === "historyHead") return portableAuthorityRole("HISTORY_HEAD");
      if (key === "recognizedRoots") {
        return portableAuthorityRole("RECOGNIZED_ROOT_LIST");
      }
      if (key === "policyVersion" || key === "globalPolicySourceId") {
        return AUTHORITY_IDENTIFIER_CAPTURE_ROLE;
      }
      if (key === "evaluationTime") return REPLAY_DESIGNATED_SCALAR_CAPTURE_ROLE;
      return NORMAL_CAPTURE_ROLE;
    case "DOMAIN":
      return key === "deploymentId"
        ? AUTHORITY_IDENTIFIER_CAPTURE_ROLE
        : NORMAL_CAPTURE_ROLE;
    case "HISTORY_HEAD":
      return key === "position" || key === "canonicalTime"
        ? REPLAY_DESIGNATED_SCALAR_CAPTURE_ROLE
        : NORMAL_CAPTURE_ROLE;
    case "ACTION_REQUEST":
      if (key === "claimedAt" || key === "amount") {
        return REPLAY_DESIGNATED_SCALAR_CAPTURE_ROLE;
      }
      return key === "actorId" ||
        key === "action" ||
        key === "resource" ||
        key === "counterpartyId"
        ? AUTHORITY_IDENTIFIER_CAPTURE_ROLE
        : NORMAL_CAPTURE_ROLE;
    case "CONSEQUENTIAL_BINDING":
      if (key === "controlEpoch") return REPLAY_DESIGNATED_SCALAR_CAPTURE_ROLE;
      return key === "runtimeSessionId" ||
        key === "credentialKeyId" ||
        key === "roleId" ||
        key === "roleTenureId" ||
        key === "intentId" ||
        key === "nonce"
        ? AUTHORITY_IDENTIFIER_CAPTURE_ROLE
        : NORMAL_CAPTURE_ROLE;
    case "RECOGNIZED_ROOT":
      return key === "rootAuthorityId" ||
        key === "principalId" ||
        key === "principalRecognitionEventId" ||
        key === "rootGrantEventId"
        ? AUTHORITY_IDENTIFIER_CAPTURE_ROLE
        : NORMAL_CAPTURE_ROLE;
    case "PERMISSION":
      if (key === "constraints") {
        return portableAuthorityRole("AUTHORITY_CONSTRAINTS");
      }
      return key === "authorityId" ||
        key === "grantorId" ||
        key === "granteeId" ||
        key === "rootAuthorityId" ||
        key === "parentAuthorityId"
        ? AUTHORITY_IDENTIFIER_CAPTURE_ROLE
        : NORMAL_CAPTURE_ROLE;
    case "PROHIBITION":
      if (key === "constraints") {
        return portableAuthorityRole("AUTHORITY_CONSTRAINTS");
      }
      return key === "authorityId" ||
        key === "grantorId" ||
        key === "subjectActorId" ||
        key === "rootAuthorityId" ||
        key === "parentAuthorityId"
        ? AUTHORITY_IDENTIFIER_CAPTURE_ROLE
        : NORMAL_CAPTURE_ROLE;
    case "AUTHORITY_CONSTRAINTS":
      if (key === "actions" || key === "resources") {
        return portableAuthorityRole("IDENTIFIER_LIST");
      }
      if (key === "requiredIntersectionIds") {
        return portableAuthorityRole("INTERSECTION_IDENTIFIER_LIST");
      }
      if (key === "maxAmount" || key === "maxCumulativeAmount") {
        return RAW_AUTHORITY_AMOUNT_CAPTURE_ROLE;
      }
      return key === "notBefore" ||
        key === "expiresAt" ||
        key === "maxTransactions" ||
        key === "maxDelegationDepth"
        ? REPLAY_DESIGNATED_SCALAR_CAPTURE_ROLE
        : NORMAL_CAPTURE_ROLE;
    case "AUTHORITY_EVIDENCE":
      if (key === "grantEventPosition") return REPLAY_DESIGNATED_SCALAR_CAPTURE_ROLE;
      return key === "authorityId" || key === "grantEventId"
        ? AUTHORITY_IDENTIFIER_CAPTURE_ROLE
        : NORMAL_CAPTURE_ROLE;
    case "AUTHORITY_USAGE":
      if (key === "authorityId") return AUTHORITY_IDENTIFIER_CAPTURE_ROLE;
      if (key === "admittedCumulativeAmount") return RAW_AUTHORITY_AMOUNT_CAPTURE_ROLE;
      return key === "admittedTransactionCount"
        ? REPLAY_DESIGNATED_SCALAR_CAPTURE_ROLE : NORMAL_CAPTURE_ROLE;
    case "RECOGNIZED_ROOT_LIST":
    case "PERMISSION_LIST":
    case "PROHIBITION_LIST":
    case "IDENTIFIER_LIST":
    case "INTERSECTION_IDENTIFIER_LIST":
    case "AUTHORITY_EVIDENCE_LIST":
    case "AUTHORITY_USAGE_LIST":
      return NORMAL_CAPTURE_ROLE;
  }
};

const portableAuthorityArrayChildRole = (
  state: PortableAuthorityCaptureState,
): CaptureRole => {
  switch (state) {
    case "RECOGNIZED_ROOT_LIST":
      return portableAuthorityRole("RECOGNIZED_ROOT");
    case "PERMISSION_LIST":
      return portableAuthorityRole("PERMISSION");
    case "PROHIBITION_LIST":
      return portableAuthorityRole("PROHIBITION");
    case "IDENTIFIER_LIST":
    case "INTERSECTION_IDENTIFIER_LIST":
      return AUTHORITY_IDENTIFIER_CAPTURE_ROLE;
    case "AUTHORITY_EVIDENCE_LIST":
      return portableAuthorityRole("AUTHORITY_EVIDENCE");
    case "AUTHORITY_USAGE_LIST":
      return portableAuthorityRole("AUTHORITY_USAGE");
    default:
      return NORMAL_CAPTURE_ROLE;
  }
};

type CaptureContext = {
  adapterDataOnlyDepth?: number;
  accessorReads?: number;
  readonly mode: CaptureMode;
  readonly budget: CaptureBudget;
  readonly active: WeakSet<object>;
  readonly memo: WeakMap<object, CapturedNode>;
  readonly recordKeysByCapturedValue: WeakMap<object, readonly string[]>;
  /** Original object members normalized to bigint; never caller references. */
  readonly normalizedObjectMembers: WeakMap<object, Readonly<Record<string, true>>>;
  readonly nodeByCapturedValue: WeakMap<object, CapturedNode>;
  readonly localBudgets: CaptureBudget[];
  readonly replayFailureToken: object;
  readonly preobservedPrototypes: WeakMap<object, object | null>;
  readonly replayVisitor: CanonicalReplayCaptureVisitor | undefined;
  /** Receipt operations count supplied event occurrences across both histories. */
  readonly receiptEventOccurrences?: { used: number };
  /** A query mixes designated request scalars with strict event payloads. */
  readonly strictQueryMemo?: true;
  /** Raw permission/prohibition occurrences share one smaller named bound. */
  readonly rawAuthorityOccurrences?: { used: number };
};

const reserveReceiptEventOccurrences = (
  context: CaptureContext,
  count: number,
  location: string,
): void => {
  const counter = context.receiptEventOccurrences;
  if (counter === undefined) return;
  if (count > MAX_CANONICAL_LIST_MEMBERS - counter.used) {
    counter.used = MAX_CANONICAL_LIST_MEMBERS + 1;
    throw canonicalNamedLimitError(
      "Receipt operation exceeds the 4096-event occurrence bound.",
      location,
      MAX_CANONICAL_LIST_MEMBERS,
    );
  }
  counter.used += count;
};

const authorityListMaximum = (role: CaptureRole): number => {
  if (role.kind !== "PORTABLE_AUTHORITY") return MAX_CANONICAL_LIST_MEMBERS;
  switch (role.state) {
    case "IDENTIFIER_LIST": return MAX_AUTHORITY_IDENTIFIER_SET_MEMBERS;
    case "INTERSECTION_IDENTIFIER_LIST": return MAX_AUTHORITY_REQUIRED_INTERSECTIONS;
    case "PERMISSION_LIST":
    case "PROHIBITION_LIST": return MAX_RAW_AUTHORITY_OCCURRENCES;
    default: return MAX_CANONICAL_LIST_MEMBERS;
  }
};

const reserveRawAuthorityOccurrences = (
  context: CaptureContext,
  count: number,
  location: string,
  role: CaptureRole,
): void => {
  const counter = context.rawAuthorityOccurrences;
  if (counter === undefined || role.kind !== "PORTABLE_AUTHORITY" ||
      (role.state !== "PERMISSION_LIST" && role.state !== "PROHIBITION_LIST")) return;
  if (count > MAX_RAW_AUTHORITY_OCCURRENCES - counter.used) {
    counter.used = MAX_RAW_AUTHORITY_OCCURRENCES + 1;
    throw canonicalNamedLimitError(
      `Raw authority input at ${location} exceeds the ${MAX_RAW_AUTHORITY_OCCURRENCES}-authority combined bound.`,
      location,
      MAX_RAW_AUTHORITY_OCCURRENCES,
    );
  }
  counter.used += count;
};

/** Named limits do not promote wrong-type scalar values to semantic validity. */
const enforceAuthorityScalarLimits = (
  value: unknown,
  role: CaptureRole,
  location: string,
): void => {
  if (role.kind !== "REPLAY_DESIGNATED_SCALAR") return;
  const maximum = role.maximumStringBytes;
  if (typeof value === "string" && maximum !== undefined) {
    if (value.length > maximum) {
      throw canonicalNamedLimitError(
        `Canonical Identifier at ${location} exceeds the ${maximum}-byte bound.`,
        location,
        maximum,
      );
    }
    // A bounded malformed string keeps its later INVALID_REQUEST/field routing.
    if (isWellFormedUnicode(value)) protocolStringByteLength(value, location, maximum);
  }
  if (role.enforceBigIntBound && typeof value === "bigint" &&
      (value < -MAX_PROTOCOL_BIGINT || value > MAX_PROTOCOL_BIGINT)) {
    bigintDecimal(value, location);
  }
};

const enforceDesignatedScalarHostKind = (
  value: unknown,
  role: CaptureRole,
  location: string,
): void => {
  if (role.kind !== "REPLAY_DESIGNATED_SCALAR") return;
  if (value === undefined) {
    throw new TypeError(`Canonical value at ${location} is undefined.`);
  }
  if (typeof value === "function" || typeof value === "symbol") {
    throw new TypeError(`Canonical value at ${location} has unsupported type ${typeof value}.`);
  }
  if (value !== null && typeof value === "object") {
    throw new TypeError(`Canonical designated scalar at ${location} has an unsupported host kind.`);
  }
};

/** Refine a member without losing the host kind erased by marker decoding. */
const enforceCapturedMemberAuthorityRole = (
  container: object,
  key: string | number,
  value: unknown,
  context: CaptureContext,
  role: CaptureRole,
  location: string,
): void => {
  if (role.kind === "REPLAY_DESIGNATED_SCALAR") {
    const normalized = weakMapGet(context.normalizedObjectMembers, container);
    if (normalized !== undefined && Object.hasOwn(normalized, key)) {
      throw new TypeError(`Canonical designated scalar at ${location} has an unsupported host kind.`);
    }
  }
  enforceMemoizedAuthorityRole(value, context, role, location);
};

/** A looser first occurrence cannot erase limits at a later authority role. */
const enforceMemoizedAuthorityRole = (
  value: unknown,
  context: CaptureContext,
  role: CaptureRole,
  location: string,
): void => {
  enforceAuthorityScalarLimits(value, role, location);
  enforceDesignatedScalarHostKind(value, role, location);
  if (value === null || typeof value !== "object") return;
  if (role.kind !== "PORTABLE_AUTHORITY") return;
  if (Array.isArray(value)) {
    const maximum = authorityListMaximum(role);
    if (value.length > maximum) {
      throw canonicalNamedLimitError(
        `Canonical array at ${location} exceeds the ${maximum}-member bound.`,
        location,
        maximum,
      );
    }
    reserveRawAuthorityOccurrences(context, value.length, location, role);
    const childRole = portableAuthorityArrayChildRole(role.state);
    for (let index = 0; index < value.length; index += 1) {
      enforceCapturedMemberAuthorityRole(value, index, value[index], context, childRole, `${location}[${index}]`);
    }
    return;
  }
  const keys = weakMapGet(context.recordKeysByCapturedValue, value);
  if (keys === undefined) throw new TypeError("Authority alias lost captured record-key metadata.");
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index]!;
    const member = (value as Record<string, unknown>)[key];
    if (member !== undefined) {
      enforceCapturedMemberAuthorityRole(
        value, key, member, context, portableAuthorityRecordChildRole(role.state, key), `${location}.${key}`,
      );
    }
  }
};

const REPLAY_CAPTURE_VISITOR_STOPS = createWeakMap<object, unknown>();
const REPLAY_CAPTURE_VISITOR_THROWS = createWeakMap<object, unknown>();

const replayCaptureVisitorToken = (): object => Object.freeze(Object.create(null));

const reserveBytes = (context: CaptureContext, amount: number): void => {
  if (!Number.isSafeInteger(amount) || amount < 0) {
    throw new TypeError("Canonical byte reservation must be a nonnegative safe integer.");
  }
  for (let index = context.localBudgets.length - 1; index >= 0; index -= 1) {
    const budget = context.localBudgets[index]!;
    if (amount > budget.limit - budget.used) {
      budget.used = budget.limit + 1;
      throw canonicalCaptureLimitError(budget.label, budget.limit);
    }
  }
  if (amount > context.budget.limit - context.budget.used) {
    context.budget.used = context.budget.limit + 1;
    throw canonicalCaptureLimitError(context.budget.label, context.budget.limit);
  }
  for (let index = 0; index < context.localBudgets.length; index += 1) {
    context.localBudgets[index]!.used += amount;
  }
  context.budget.used += amount;
};

const reserveText = (context: CaptureContext, text: string): number => {
  const bytes = uint8ArrayLength(UTF8_ENCODER.encode(text));
  reserveBytes(context, bytes);
  return bytes;
};

const textRope = (text: string, utf8Bytes: number): CanonicalRope =>
  Object.freeze({ kind: "TEXT", text, utf8Bytes });

const sequenceRope = (parts: CanonicalRope[]): CanonicalRope =>
  Object.freeze({ kind: "SEQUENCE", parts: Object.freeze(parts) });

const OPEN_LIST_ROPE = textRope("[", 1);
const CLOSE_LIST_ROPE = textRope("]", 1);
const OPEN_RECORD_ROPE = textRope("{", 1);
const CLOSE_RECORD_ROPE = textRope("}", 1);
const COMMA_ROPE = textRope(",", 1);

const CANONICAL_OUTPUT_BUFFER_BYTES = 65_536;
const MAX_CANONICAL_OUTPUT_SEGMENTS = Math.ceil(
  MAX_CANONICAL_UTF8_BYTES / CANONICAL_OUTPUT_BUFFER_BYTES,
);

const materializeCanonicalRope = (
  root: CanonicalRope,
  expectedBytes: number,
): string => {
  const stack: CanonicalRope[] = [root];
  let bufferedParts: string[] = [];
  let bufferedBytes = 0;
  const outputSegments: string[] = [];
  let emittedBytes = 0;

  const flush = (): void => {
    if (bufferedParts.length === 0) return;
    arrayPush(outputSegments, arrayJoin(bufferedParts, ""));
    if (outputSegments.length > MAX_CANONICAL_OUTPUT_SEGMENTS) {
      throw new TypeError("Canonical rope exceeded its bounded output segment count.");
    }
    bufferedParts = [];
    bufferedBytes = 0;
  };

  while (stack.length > 0) {
    const current = arrayPop(stack)!;
    if (current.kind === "SEQUENCE") {
      for (let index = current.parts.length - 1; index >= 0; index -= 1) {
        arrayPush(stack, current.parts[index]!);
      }
      continue;
    }
    if (current.utf8Bytes <= 0) {
      throw new TypeError("Canonical rope contains an empty text segment.");
    }
    emittedBytes += current.utf8Bytes;
    if (emittedBytes > expectedBytes) {
      throw new TypeError("Canonical rope exceeds its captured byte count.");
    }
    arrayPush(bufferedParts, current.text);
    bufferedBytes += current.utf8Bytes;
    if (bufferedBytes >= CANONICAL_OUTPUT_BUFFER_BYTES) flush();
  }
  flush();
  if (emittedBytes !== expectedBytes) {
    throw new TypeError("Canonical rope does not match its captured byte count.");
  }
  return arrayJoin(outputSegments, "");
};

const canonicalScalarNode = (
  value: unknown,
  text: string,
  context: CaptureContext,
): CapturedNode => {
  const bytes = reserveText(context, text);
  return {
    value,
    canonicalBytes: bytes,
    canonicalRope: textRope(text, bytes),
    intrinsicDepth: 0,
  };
};

const noncanonicalScalarNode = (
  value: string | number | bigint,
  context: CaptureContext,
): CapturedNode => {
  reserveBytes(context, INVALID_DESIGNATED_SCALAR_CAPTURE_BYTES);
  return {
    value,
    canonicalBytes: INVALID_DESIGNATED_SCALAR_CAPTURE_BYTES,
    canonicalRope: null,
    intrinsicDepth: 0,
  };
};

const bigintDecimal = (value: bigint, location: string): string => {
  if (value < -MAX_PROTOCOL_BIGINT || value > MAX_PROTOCOL_BIGINT) {
    throw canonicalNamedLimitError(
      `Canonical BigInt at ${location} exceeds the 256-bit protocol bound.`,
      location,
      256,
    );
  }
  return bigintToString(value, 10);
};

const parseMarkerBigInt = (value: unknown, location: string): bigint => {
  if (typeof value !== "string") {
    throw new TypeError(`Canonical BigInt marker at ${location} has an invalid decimal value.`);
  }
  protocolStringByteLength(value, location);
  if (value.length > 79 || !regExpTest(/^(?:0|-?[1-9][0-9]*)$/, value)) {
    throw new TypeError(`Canonical BigInt marker at ${location} has an invalid decimal value.`);
  }
  const parsed = bigintFrom(value);
  bigintDecimal(parsed, location);
  return parsed;
};

const readPrototype = (value: object, location: string): object | null => {
  try {
    return Reflect.getPrototypeOf(value);
  } catch {
    throw new TypeError(`Canonical value at ${location} failed prototype capture.`);
  }
};

const readOwnKeys = (value: object, location: string): readonly PropertyKey[] => {
  try {
    return Reflect.ownKeys(value);
  } catch {
    throw new TypeError(`Canonical value at ${location} failed own-key capture.`);
  }
};

const readDescriptor = (
  value: object,
  key: string,
  location: string,
): PropertyDescriptor => {
  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = Reflect.getOwnPropertyDescriptor(value, key);
  } catch {
    throw new TypeError(`Canonical field at ${location} failed descriptor capture.`);
  }
  if (descriptor === undefined) {
    throw new TypeError(`Canonical field at ${location} changed during descriptor capture.`);
  }
  return descriptor;
};

const descriptorValue = (
  descriptor: PropertyDescriptor,
  receiver: object,
  location: string,
): unknown => {
  if (Object.hasOwn(descriptor, "value")) return descriptor.value;
  if (descriptor.get === undefined) return undefined;
  try {
    return Reflect.apply(descriptor.get, receiver, []);
  } catch {
    throw new TypeError(`Canonical accessor at ${location} failed during its single capture.`);
  }
};

const capturedDescriptorValue = (
  context: CaptureContext, descriptor: PropertyDescriptor, receiver: object, location: string,
  adapterField = false,
): unknown => {
  if (!Object.hasOwn(descriptor, "value")) {
    if (adapterField || (context.adapterDataOnlyDepth ?? 0) > 0) {
      throw new TypeError(`Adapter data accessor at ${location} is unsupported.`);
    }
    context.accessorReads = (context.accessorReads ?? 0) + 1;
  }
  return descriptorValue(descriptor, receiver, location);
};

const canonicalArrayIndex = (key: string): number | undefined => {
  if (key === "0") return 0;
  if (!regExpTest(/^[1-9][0-9]*$/, key)) return undefined;
  const value = numberFrom(key);
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_fffe) return undefined;
  return stringFrom(value) === key ? value : undefined;
};

const reuseNode = (
  node: CapturedNode,
  context: CaptureContext,
  containerDepth: number,
  location: string,
): CapturedNode => {
  if (containerDepth + node.intrinsicDepth > MAX_CANONICAL_DEPTH) {
    throw canonicalNamedLimitError(
      `Canonical value at ${location} exceeds nesting depth ${MAX_CANONICAL_DEPTH}.`,
      location,
      MAX_CANONICAL_DEPTH,
    );
  }
  reserveBytes(context, node.canonicalBytes);
  return node;
};

const enforceMemoizedReplayEventDataBudget = (
  node: CapturedNode,
  context: CaptureContext,
  eventIndex: number,
): void => {
  if (
    node.value === null ||
    typeof node.value !== "object" ||
    Array.isArray(node.value) ||
    !Object.hasOwn(node.value, "data")
  ) {
    return;
  }
  const data = (node.value as Readonly<Record<string, unknown>>).data;
  if (data === null || typeof data !== "object") return;
  const dataBytes = weakMapGet(context.nodeByCapturedValue, data)?.canonicalBytes;
  if (
    dataBytes !== undefined &&
    dataBytes > MAX_REPLAY_EVENT_DATA_UTF8_BYTES
  ) {
    throw canonicalCaptureLimitError(
      `$.events[${eventIndex}].data`,
      MAX_REPLAY_EVENT_DATA_UTF8_BYTES,
    );
  }
};

/** Reusing a query envelope preserves only its three designated scalar slots. */
const enforceMemoizedQueryEventGrammar = (node: CapturedNode, context: CaptureContext): void => {
  if (node.value === null || typeof node.value !== "object") return;
  for (const key of ["id", "type", "timestamp"]) {
    const value = (node.value as Readonly<Record<string, unknown>>)[key];
    // Direct query records omit undefined before capturing a child role.
    if (value !== undefined) {
      enforceCapturedMemberAuthorityRole(node.value, key, value, context,
        REPLAY_DESIGNATED_SCALAR_CAPTURE_ROLE, `$.events[].${key}`);
    }
  }
  if (node.canonicalRope !== null) return;
  const keys = weakMapGet(context.recordKeysByCapturedValue, node.value);
  if (keys === undefined) throw new TypeError("Query alias is not a canonical event envelope.");
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index]!;
    if (key === "id" || key === "type" || key === "timestamp") continue;
    const value = (node.value as Readonly<Record<string, unknown>>)[key];
    // Undefined record members are absent in the canonical grammar. Original
    // key metadata still lets later closed-envelope validation reject extras.
    if (value === undefined) continue;
    const invalid = typeof value === "number" ? !Number.isSafeInteger(value) || Object.is(value, -0)
      : typeof value === "string" ? !isWellFormedUnicode(value)
      : typeof value === "bigint" ? value < -MAX_PROTOCOL_BIGINT || value > MAX_PROTOCOL_BIGINT
      : value !== null && typeof value === "object"
        ? weakMapGet(context.nodeByCapturedValue, value)?.canonicalRope === null : false;
    if (invalid) throw new TypeError("Query alias introduces a classified scalar into strict event data.");
  }
};

export type CanonicalReplayBaseFailureMetadata = Readonly<{
  readonly eventPosition: number;
  readonly code: "EVENT_ENVELOPE_INVALID" | "EVENT_DATA_INVALID";
  readonly eventId?: string;
}>;

const CANONICAL_REPLAY_BASE_FAILURES = createWeakMap<
  object,
  Readonly<{
    readonly captureToken: object;
    readonly metadata: CanonicalReplayBaseFailureMetadata;
  }>
>();

const CANONICAL_REPLAY_SCHEMA_FAILURES = createWeakSet<object>();

const canonicalReplaySchemaFailure = (message: string): TypeError => {
  const error = new TypeError(message);
  weakSetAdd(CANONICAL_REPLAY_SCHEMA_FAILURES, error);
  return error;
};

/** @internal True only for a capturable replay envelope's closed-schema failure. */
export const isCanonicalReplaySchemaFailure = (error: unknown): boolean =>
  error !== null &&
  typeof error === "object" &&
  weakSetHas(CANONICAL_REPLAY_SCHEMA_FAILURES, error);

/** @internal Read-only provenance for a replay member capture/base failure. */
export const getCanonicalReplayBaseFailureMetadata = (
  error: unknown,
): CanonicalReplayBaseFailureMetadata | undefined =>
  error !== null && typeof error === "object"
    ? weakMapGet(CANONICAL_REPLAY_BASE_FAILURES, error)?.metadata
    : undefined;

const replayBaseFailureForContext = (
  error: unknown,
  context: CaptureContext,
): CanonicalReplayBaseFailureMetadata | undefined => {
  if (error === null || typeof error !== "object") return undefined;
  const branded = weakMapGet(CANONICAL_REPLAY_BASE_FAILURES, error);
  return branded?.captureToken === context.replayFailureToken
    ? branded.metadata
    : undefined;
};

const annotateReplayBaseFailure = (
  error: unknown,
  context: CaptureContext,
  metadata: CanonicalReplayBaseFailureMetadata,
): never => {
  const throwable = error !== null && typeof error === "object"
    ? error
    : new TypeError("Canonical replay event capture failed.");
  if (replayBaseFailureForContext(throwable, context) === undefined) {
    const branded = Object.create(null) as {
      captureToken: object;
      metadata: CanonicalReplayBaseFailureMetadata;
    };
    Object.defineDataProperty(
      branded,
      "captureToken",
      context.replayFailureToken,
      false,
      true,
    );
    Object.defineDataProperty(branded, "metadata", metadata, false, true);
    Object.freeze(branded);
    weakMapSet(CANONICAL_REPLAY_BASE_FAILURES, throwable, branded);
  }
  throw throwable;
};

const replayBaseFailureMetadata = (
  eventPosition: number,
  code: CanonicalReplayBaseFailureMetadata["code"],
  eventId?: string,
): CanonicalReplayBaseFailureMetadata => {
  const metadata = {} as {
    eventPosition: number;
    code: CanonicalReplayBaseFailureMetadata["code"];
    eventId?: string;
  };
  Object.defineDataProperty(metadata, "eventPosition", eventPosition, false, true);
  Object.defineDataProperty(metadata, "code", code, false, true);
  Object.defineDataProperty(metadata, "eventId", eventId, false, eventId !== undefined);
  return Object.freeze(metadata);
};

const isReplayBaseProtocolString = (
  value: unknown,
  maximumBytes: number,
): value is string => {
  if (typeof value !== "string" || value.length > maximumBytes) return false;
  try {
    return protocolStringByteLength(value, "$.events[].base") <= maximumBytes;
  } catch {
    return false;
  }
};

const replayBaseEventId = (node: CapturedNode): string | undefined => {
  if (
    node.value === null ||
    typeof node.value !== "object" ||
    Array.isArray(node.value) ||
    !Object.hasOwn(node.value, "id")
  ) {
    return undefined;
  }
  const id = (node.value as Readonly<Record<string, unknown>>).id;
  return isReplayBaseProtocolString(id, 256) &&
    id.length > 0 &&
    !regExpTest(/[\u0000-\u001f\u007f]/u, id)
    ? id
    : undefined;
};

const failReplayBaseNode = (
  node: CapturedNode,
  context: CaptureContext,
  eventPosition: number,
  code: CanonicalReplayBaseFailureMetadata["code"],
  includeEventId = false,
): never => {
  const error = canonicalReplaySchemaFailure(
    code === "EVENT_DATA_INVALID"
      ? "Canonical replay event data capture failed."
      : "Canonical replay event base envelope is invalid.",
  );
  const eventId = includeEventId ? replayBaseEventId(node) : undefined;
  return annotateReplayBaseFailure(
    error,
    context,
    replayBaseFailureMetadata(eventPosition, code, eventId),
  );
};

const validateCapturedReplayBaseNode = (
  node: CapturedNode,
  context: CaptureContext,
  eventPosition: number,
): void => {
  if (
    node.value === null ||
    typeof node.value !== "object" ||
    Array.isArray(node.value)
  ) {
    failReplayBaseNode(node, context, eventPosition, "EVENT_ENVELOPE_INVALID");
  }
  const record = node.value as Readonly<Record<string, unknown>>;
  const keys = weakMapGet(context.recordKeysByCapturedValue, record);
  if (
    keys === undefined ||
    keys.length !== 4 ||
    keys[0] !== "data" ||
    keys[1] !== "id" ||
    keys[2] !== "timestamp" ||
    keys[3] !== "type"
  ) {
    failReplayBaseNode(node, context, eventPosition, "EVENT_ENVELOPE_INVALID");
  }
  // Match direct scalar capture in order, using only the immutable snapshot.
  const refineScalar = (key: "id" | "type" | "timestamp", role: CaptureRole): void => {
    try {
      enforceCapturedMemberAuthorityRole(record, key, record[key], context, role, `$.events[].${key}`);
    } catch (error) {
      return annotateReplayBaseFailure(error, context,
        replayBaseFailureMetadata(eventPosition, "EVENT_ENVELOPE_INVALID",
          key === "id" ? undefined : replayBaseEventId(node)));
    }
  };
  refineScalar("id", AUTHORITY_IDENTIFIER_CAPTURE_ROLE);
  const eventId = replayBaseEventId(node);
  if (eventId === undefined) {
    failReplayBaseNode(node, context, eventPosition, "EVENT_ENVELOPE_INVALID");
  }
  refineScalar("type", REPLAY_DESIGNATED_SCALAR_CAPTURE_ROLE);
  if (!isReplayBaseProtocolString(record.type, MAX_PROTOCOL_STRING_UTF8_BYTES)) {
    failReplayBaseNode(node, context, eventPosition, "EVENT_ENVELOPE_INVALID", true);
  }
  refineScalar("timestamp", REPLAY_DESIGNATED_SCALAR_CAPTURE_ROLE);
  if (
    typeof record.timestamp !== "number" ||
    !Number.isSafeInteger(record.timestamp) ||
    record.timestamp < 0 ||
    Object.is(record.timestamp, -0)
  ) {
    failReplayBaseNode(node, context, eventPosition, "EVENT_ENVELOPE_INVALID", true);
  }
  if (
    !Object.hasOwn(record, "data") ||
    record.data === null ||
    typeof record.data !== "object" ||
    Array.isArray(record.data) ||
    weakMapGet(context.recordKeysByCapturedValue, record.data) === undefined
  ) {
    failReplayBaseNode(
      node,
      context,
      eventPosition,
      "EVENT_ENVELOPE_INVALID",
      true,
    );
  }
};

const invokeReplayCaptureVisitor = (
  node: CapturedNode,
  context: CaptureContext,
  eventPosition: number,
): void => {
  if (context.replayVisitor === undefined) return;
  const capturedRecordKeys = Object.freeze((candidate: unknown) =>
    candidate !== null &&
    (typeof candidate === "object" || typeof candidate === "function")
      ? weakMapGet(context.recordKeysByCapturedValue, candidate as object)
      : undefined);
  const capturedCanonicalBytes = Object.freeze((candidate: unknown) =>
    candidate !== null &&
    (typeof candidate === "object" || typeof candidate === "function")
      ? weakMapGet(context.nodeByCapturedValue, candidate as object)?.canonicalBytes
      : undefined);
  const capture: CapturedCanonicalReplayEvent = Object.freeze({
    eventPosition,
    event: node.value,
    capturedRecordKeys,
    capturedCanonicalBytes,
  });
  weakSetAdd(CANONICAL_REPLAY_EVENT_CAPTURES, capture);
  let stopped = false;
  let stoppedResult: unknown;
  try {
    const decision = context.replayVisitor(capture);
    if (
      decision === null ||
      typeof decision !== "object" ||
      !Object.hasOwn(decision, "status")
    ) {
      throw new TypeError("Canonical replay capture visitor returned an invalid decision.");
    }
    const status = decision.status;
    if (status !== "CONTINUE" && status !== "STOP") {
      throw new TypeError("Canonical replay capture visitor returned an invalid decision.");
    }
    if (status === "STOP") {
      if (!Object.hasOwn(decision, "result")) {
        throw new TypeError("Canonical replay capture visitor returned an invalid decision.");
      }
      stopped = true;
      stoppedResult = decision.result;
    }
  } catch (error) {
    const token = replayCaptureVisitorToken();
    weakMapSet(REPLAY_CAPTURE_VISITOR_THROWS, token, error);
    throw token;
  }
  if (stopped) {
    const token = replayCaptureVisitorToken();
    weakMapSet(REPLAY_CAPTURE_VISITOR_STOPS, token, stoppedResult);
    throw token;
  }
};

const captureReplayEvent = (
  value: object,
  context: CaptureContext,
  containerDepth: number,
  location: string,
  eventPosition: number,
): CapturedNode => {
  const depth = containerDepth + 1;
  if (depth > MAX_CANONICAL_DEPTH) {
    throw canonicalNamedLimitError(
      `Canonical value at ${location} exceeds nesting depth ${MAX_CANONICAL_DEPTH}.`,
      location,
      MAX_CANONICAL_DEPTH,
    );
  }

  let eventId: string | undefined;
  try {
    const prototype = readPrototype(value, location);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError(`Canonical value at ${location} is not a plain record.`);
    }
    const rawKeys = readOwnKeys(value, location);
    if (rawKeys.length > MAX_CANONICAL_RECORD_FIELDS) {
      throw canonicalNamedLimitError(
        `Canonical record at ${location} exceeds the ${MAX_CANONICAL_RECORD_FIELDS}-field bound.`,
        location,
        MAX_CANONICAL_RECORD_FIELDS,
      );
    }
    const keys: string[] = [];
    for (let keyIndex = 0; keyIndex < rawKeys.length; keyIndex += 1) {
      const rawKey = rawKeys[keyIndex]!;
      if (typeof rawKey !== "string") {
        throw new TypeError(`Canonical record at ${location} has a non-string key.`);
      }
      protocolStringByteLength(rawKey, `${location}.{key}`);
      arrayPush(keys, rawKey);
    }
    const membership = createSet<string>();
    for (let keyIndex = 0; keyIndex < keys.length; keyIndex += 1) {
      setAdd(membership, keys[keyIndex]!);
    }
    const exactMembership =
      keys.length === 4 &&
      setHas(membership, "id") &&
      setHas(membership, "type") &&
      setHas(membership, "timestamp") &&
      setHas(membership, "data");

    if (!exactMembership) {
      throw canonicalReplaySchemaFailure(
        `Canonical replay event at ${location} has an invalid envelope.`,
      );
    }

    weakSetAdd(context.active, value);
    const startBytes = context.budget.used;
    try {
      const captureEnvelopeScalar = (key: "id" | "type" | "timestamp") => {
        if (!setHas(membership, key)) return undefined;
        const descriptor = readDescriptor(value, key, `${location}.${key}`);
        const field = capturedDescriptorValue(context, descriptor, value, `${location}.${key}`);
        return captureNode(
          field,
          context,
          depth,
          `${location}.${key}`,
          key === "id" ? AUTHORITY_IDENTIFIER_CAPTURE_ROLE : REPLAY_DESIGNATED_SCALAR_CAPTURE_ROLE,
        );
      };

      const idNode = captureEnvelopeScalar("id");
      if (
        idNode === undefined ||
        !isReplayBaseProtocolString(idNode.value, 256) ||
        idNode.value.length === 0 ||
        regExpTest(/[\u0000-\u001f\u007f]/u, idNode.value)
      ) {
        throw canonicalReplaySchemaFailure(
          `Canonical replay event at ${location} has an invalid id.`,
        );
      }
      eventId = idNode.value;
      const typeNode = captureEnvelopeScalar("type");
      if (
        typeNode === undefined ||
        !isReplayBaseProtocolString(typeNode.value, MAX_PROTOCOL_STRING_UTF8_BYTES)
      ) {
        throw canonicalReplaySchemaFailure(
          `Canonical replay event at ${location} has an invalid type.`,
        );
      }
      const timestampNode = captureEnvelopeScalar("timestamp");
      if (
        timestampNode === undefined ||
        typeof timestampNode.value !== "number" ||
        !Number.isSafeInteger(timestampNode.value) ||
        timestampNode.value < 0 ||
        Object.is(timestampNode.value, -0)
      ) {
        throw canonicalReplaySchemaFailure(
          `Canonical replay event at ${location} has an invalid timestamp.`,
        );
      }

      const dataDescriptor = readDescriptor(value, "data", `${location}.data`);
      const data = capturedDescriptorValue(context, dataDescriptor, value, `${location}.data`);
      if (
        data === null ||
        typeof data !== "object" ||
        Array.isArray(data)
      ) {
        throw canonicalReplaySchemaFailure(
          `Canonical replay event data at ${location}.data is not a plain record.`,
        );
      }
      const memoizedData = weakMapGet(context.memo, data);
      if (memoizedData === undefined && !weakSetHas(context.active, data)) {
        const dataPrototype = readPrototype(data, `${location}.data`);
        if (dataPrototype !== Object.prototype && dataPrototype !== null) {
          throw new TypeError(
            `Canonical replay event data at ${location}.data is not a plain record.`,
          );
        }
        weakMapSet(context.preobservedPrototypes, data, dataPrototype);
      } else if (
        memoizedData !== undefined &&
        (memoizedData.value === null ||
          typeof memoizedData.value !== "object" ||
          Array.isArray(memoizedData.value) ||
          weakMapGet(context.recordKeysByCapturedValue, memoizedData.value) === undefined)
      ) {
        throw canonicalReplaySchemaFailure(
          `Canonical replay event data at ${location}.data is not a plain record.`,
        );
      }
      const dataNode = captureNode(
        data,
        context,
        depth,
        `${location}.data`,
        Object.freeze({ kind: "REPLAY_EVENT_DATA", index: eventPosition }),
      );
      if (
        dataNode.value === null ||
        typeof dataNode.value !== "object" ||
        Array.isArray(dataNode.value) ||
        weakMapGet(context.recordKeysByCapturedValue, dataNode.value) === undefined
      ) {
        throw canonicalReplaySchemaFailure(
          `Canonical replay event data at ${location}.data is not a plain record.`,
        );
      }

      const immutable = Object.create(null) as Record<string, unknown>;
      Object.defineDataProperty(immutable, "id", idNode!.value, false, true);
      Object.defineDataProperty(immutable, "type", typeNode.value, false, true);
      Object.defineDataProperty(
        immutable,
        "timestamp",
        timestampNode.value,
        false,
        true,
      );
      Object.defineDataProperty(immutable, "data", dataNode.value, false, true);
      Object.freeze(immutable);

      const ropeParts: CanonicalRope[] = [];
      const appendText = (text: string): void => {
        const bytes = reserveText(context, text);
        arrayPush(ropeParts, textRope(text, bytes));
      };
      appendText('{"data":');
      if (dataNode.canonicalRope !== null) arrayPush(ropeParts, dataNode.canonicalRope);
      appendText(',"id":');
      if (idNode!.canonicalRope !== null) arrayPush(ropeParts, idNode!.canonicalRope);
      appendText(',"timestamp":');
      if (timestampNode.canonicalRope !== null) arrayPush(ropeParts, timestampNode.canonicalRope);
      appendText(',"type":');
      if (typeNode.canonicalRope !== null) arrayPush(ropeParts, typeNode.canonicalRope);
      appendText("}");
      const hasCanonicalRope =
        dataNode.canonicalRope !== null &&
        idNode!.canonicalRope !== null &&
        timestampNode.canonicalRope !== null &&
        typeNode.canonicalRope !== null;
      const result: CapturedNode = {
        value: immutable,
        canonicalBytes: context.budget.used - startBytes,
        canonicalRope: hasCanonicalRope ? sequenceRope(ropeParts) : null,
        intrinsicDepth: 1 + dataNode.intrinsicDepth,
      };
      weakMapSet(
        context.recordKeysByCapturedValue,
        immutable,
        Object.freeze(["data", "id", "timestamp", "type"]),
      );
      weakMapSet(context.nodeByCapturedValue, immutable, result);
      weakMapSet(context.memo, value, result);
      return result;
    } finally {
      weakSetDelete(context.active, value);
    }
  } catch (error) {
    if (replayBaseFailureForContext(error, context) !== undefined) throw error;
    return annotateReplayBaseFailure(
      error,
      context,
      replayBaseFailureMetadata(
        eventPosition,
        "EVENT_ENVELOPE_INVALID",
        eventId,
      ),
    );
  }
};

const captureArray = (
  value: readonly unknown[],
  context: CaptureContext,
  containerDepth: number,
  location: string,
  role: CaptureRole,
): CapturedNode => {
  const depth = containerDepth + 1;
  if (depth > MAX_CANONICAL_DEPTH) {
    throw canonicalNamedLimitError(
      `Canonical value at ${location} exceeds nesting depth ${MAX_CANONICAL_DEPTH}.`,
      location,
      MAX_CANONICAL_DEPTH,
    );
  }

  const lengthDescriptor = readDescriptor(value, "length", `${location}.length`);
  if (!Object.hasOwn(lengthDescriptor, "value")) {
    throw new TypeError(`Canonical array at ${location} has accessor-backed length metadata.`);
  }
  const length = lengthDescriptor.value;
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new TypeError(`Canonical array at ${location} has invalid length metadata.`);
  }
  const maximum = authorityListMaximum(role);
  if (length > maximum) {
    throw canonicalNamedLimitError(
      `Canonical array at ${location} exceeds the ${maximum}-member bound.`,
      location,
      maximum,
    );
  }
  reserveRawAuthorityOccurrences(context, length, location, role);
  if (role.kind === "REPLAY_EVENTS" || role.kind === "QUERY_EVENTS") {
    reserveReceiptEventOccurrences(context, length, location);
  }

  const rawKeys = readOwnKeys(value, location);
  const indexKeys: { readonly key: string; readonly index: number }[] = [];
  let hasLength = false;
  for (let rawKeyIndex = 0; rawKeyIndex < rawKeys.length; rawKeyIndex += 1) {
    const rawKey = rawKeys[rawKeyIndex]!;
    if (typeof rawKey !== "string") {
      throw new TypeError(`Canonical array at ${location} has a symbol key.`);
    }
    protocolStringByteLength(rawKey, `${location}.{key}`);
    if (rawKey === "length") {
      if (hasLength) throw new TypeError(`Canonical array at ${location} has duplicate length metadata.`);
      hasLength = true;
      continue;
    }
    const index = canonicalArrayIndex(rawKey);
    if (index === undefined) {
      throw new TypeError(`Canonical array at ${location} has an unsupported expando field ${rawKey}.`);
    }
    arrayPush(indexKeys, { key: rawKey, index });
    if (indexKeys.length > maximum) {
      throw canonicalNamedLimitError(
        `Canonical array at ${location} exceeds the ${maximum}-member bound.`,
        location,
        maximum,
      );
    }
  }
  if (!hasLength) {
    throw new TypeError(`Canonical array at ${location} has no captured length descriptor.`);
  }
  if (indexKeys.length !== length) {
    throw new TypeError(
      `Canonical array at ${location} is sparse or exceeds the ${maximum}-member bound.`,
    );
  }
  arraySort(indexKeys, (left, right) => left.index - right.index);
  for (let index = 0; index < length; index += 1) {
    if (indexKeys[index]?.index !== index) {
      throw new TypeError(`Canonical array at ${location} is sparse.`);
    }
  }

  weakSetAdd(context.active, value);
  const startBytes = context.budget.used;
  try {
    reserveBytes(context, 1);
    const childNodes: CapturedNode[] = [];
    let normalizedMembers: Record<string, true> | undefined;
    let maximumChildIntrinsicDepth = 0;
    let ropeParts: CanonicalRope[] | null = [OPEN_LIST_ROPE];
    for (let index = 0; index < length; index += 1) {
      let member: unknown;
      let child: CapturedNode | undefined;
      try {
        if (index > 0) {
          reserveBytes(context, 1);
          if (ropeParts !== null) arrayPush(ropeParts, COMMA_ROPE);
        }
        const descriptor = readDescriptor(
          value,
          stringFrom(index),
          `${location}[${index}]`,
        );
        member = capturedDescriptorValue(context, descriptor, value, `${location}[${index}]`);
        if (member === undefined) {
          throw new TypeError(`Canonical array entry at ${location}[${index}] is undefined.`);
        }
        const childRole: CaptureRole = role.kind === "REPLAY_EVENTS"
          ? Object.freeze({ kind: "REPLAY_EVENT", index })
          : role.kind === "QUERY_EVENTS"
            ? Object.freeze({ kind: "QUERY_EVENT", index })
          : role.kind === "PORTABLE_AUTHORITY"
            ? portableAuthorityArrayChildRole(role.state)
            : NORMAL_CAPTURE_ROLE;
        child = captureNode(
          member,
          context,
          depth,
          `${location}[${index}]`,
          childRole,
        );
        arrayPush(childNodes, child);
        if (member !== null && typeof member === "object" && typeof child.value === "bigint") {
          normalizedMembers ??= Object.create(null) as Record<string, true>;
          Object.defineDataProperty(normalizedMembers, stringFrom(index), true, true, true, true);
        }
        maximumChildIntrinsicDepth = Math.max(
          maximumChildIntrinsicDepth,
          child.intrinsicDepth,
        );
        if (ropeParts !== null) {
          if (child.canonicalRope === null) ropeParts = null;
          else arrayPush(ropeParts, child.canonicalRope);
        }
      } catch (error) {
        if (role.kind !== "REPLAY_EVENTS") throw error;
        if (replayBaseFailureForContext(error, context) !== undefined) {
          throw error;
        }
        const capturedMember = child ?? (
          member !== null && typeof member === "object"
            ? weakMapGet(context.memo, member)
            : undefined
        );
        const eventId = capturedMember === undefined
          ? undefined
          : replayBaseEventId(capturedMember);
        annotateReplayBaseFailure(
          error,
          context,
          replayBaseFailureMetadata(
            index,
            "EVENT_ENVELOPE_INVALID",
            eventId,
          ),
        );
      }
      if (role.kind === "REPLAY_EVENTS") {
        if (
          context.replayVisitor !== undefined &&
          REPLAY_VISITOR_PENDING_FIXED_BYTES >
            context.budget.limit - context.budget.used
        ) {
          throw canonicalCaptureLimitError(
            context.budget.label,
            context.budget.limit,
          );
        }
        invokeReplayCaptureVisitor(child!, context, index);
      }
    }
    reserveBytes(context, 1);
    if (ropeParts !== null) arrayPush(ropeParts, CLOSE_LIST_ROPE);
    const immutableValues: unknown[] = [];
    for (let index = 0; index < childNodes.length; index += 1) {
      arrayPush(immutableValues, childNodes[index]!.value);
    }
    const immutable = Object.freeze(immutableValues);
    if (normalizedMembers !== undefined) {
      weakMapSet(context.normalizedObjectMembers, immutable, Object.freeze(normalizedMembers));
    }
    const result: CapturedNode = {
      value: immutable,
      canonicalBytes: context.budget.used - startBytes,
      canonicalRope: ropeParts === null ? null : sequenceRope(ropeParts),
      intrinsicDepth: 1 + maximumChildIntrinsicDepth,
    };
    weakMapSet(context.memo, value, result);
    weakMapSet(context.nodeByCapturedValue, immutable, result);
    return result;
  } finally {
    weakSetDelete(context.active, value);
  }
};

const captureRecord = (
  value: object,
  context: CaptureContext,
  containerDepth: number,
  location: string,
  role: CaptureRole,
): CapturedNode => {
  const prototype = weakMapHas(context.preobservedPrototypes, value)
    ? weakMapGet(context.preobservedPrototypes, value)!
    : readPrototype(value, location);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`Canonical value at ${location} is not a plain record.`);
  }
  const rawKeys = readOwnKeys(value, location);
  // Explicit ECMAScript host boundary: generic records have no incremental
  // own-key iterator. Reflect.ownKeys therefore creates the one unavoidable
  // membership snapshot; its raw size is rejected before any descriptor or
  // accessor runs.
  if (rawKeys.length > MAX_CANONICAL_RECORD_FIELDS) {
    throw canonicalNamedLimitError(
      `Canonical record at ${location} exceeds the ${MAX_CANONICAL_RECORD_FIELDS}-field bound.`,
      location,
      MAX_CANONICAL_RECORD_FIELDS,
    );
  }
  const keys: string[] = [];
  for (let rawKeyIndex = 0; rawKeyIndex < rawKeys.length; rawKeyIndex += 1) {
    const rawKey = rawKeys[rawKeyIndex]!;
    if (typeof rawKey !== "string") {
      throw new TypeError(`Canonical record at ${location} has a non-string key.`);
    }
    protocolStringByteLength(rawKey, `${location}.{key}`);
    arrayPush(keys, rawKey);
  }
  const reservedKeys: string[] = [];
  for (let keyIndex = 0; keyIndex < keys.length; keyIndex += 1) {
    const key = keys[keyIndex]!;
    if (stringStartsWith(key, RESERVED_KEY_PREFIX)) arrayPush(reservedKeys, key);
  }
  if (
    reservedKeys.length > 0 &&
    (keys.length !== 1 ||
      reservedKeys.length !== 1 ||
      reservedKeys[0] !== BIGINT_MARKER_KEY)
  ) {
    throw new TypeError(
      `Canonical record at ${location} uses the reserved ${RESERVED_KEY_PREFIX} key prefix outside the exact BigInt marker shape.`,
    );
  }
  const ordered = copyArray(keys);
  arraySort(ordered, compareProtocolStrings);
  weakSetAdd(context.active, value);
  const startBytes = context.budget.used;
  try {
    reserveBytes(context, 1);
    let ropeParts: CanonicalRope[] | null = [OPEN_RECORD_ROPE];
    const immutable = Object.create(null) as Record<string, unknown>;
    let normalizedMembers: Record<string, true> | undefined;
    let ordinaryFields = 0;
    let maximumChildIntrinsicDepth = 0;
    let recognizedMarker: bigint | undefined;
    for (let keyIndex = 0; keyIndex < ordered.length; keyIndex += 1) {
      const key = ordered[keyIndex]!;
      const descriptor = readDescriptor(value, key, `${location}.${key}`);
      const field = capturedDescriptorValue(context, descriptor, value, `${location}.${key}`, key === "acknowledgment" || key === "noEffect" || key === "adapterProfile");
      if (stringStartsWith(key, RESERVED_KEY_PREFIX)) {
        if (
          key !== BIGINT_MARKER_KEY ||
          recognizedMarker !== undefined ||
          ordinaryFields !== 0
        ) {
          throw new TypeError(
            `Canonical record at ${location} uses the reserved ${RESERVED_KEY_PREFIX} key prefix.`,
          );
        }
        recognizedMarker = parseMarkerBigInt(field, `${location}.${key}`);
        const interior = `${escapedString(key, `${location}.{key}`)}:${escapedString(
          bigintToString(recognizedMarker, 10),
          `${location}.${key}`,
        )}`;
        const interiorBytes = reserveText(context, interior);
        if (ropeParts !== null) arrayPush(ropeParts, textRope(interior, interiorBytes));
        continue;
      }
      if (field === undefined) continue;
      if (recognizedMarker !== undefined) {
        throw new TypeError(
          `Canonical record at ${location} combines a reserved BigInt marker with ordinary fields.`,
        );
      }
      const depth = containerDepth + 1;
      if (depth > MAX_CANONICAL_DEPTH) {
        throw canonicalNamedLimitError(
          `Canonical value at ${location} exceeds nesting depth ${MAX_CANONICAL_DEPTH}.`,
          location,
          MAX_CANONICAL_DEPTH,
        );
      }
      if (ordinaryFields > 0) {
        reserveBytes(context, 1);
        if (ropeParts !== null) arrayPush(ropeParts, COMMA_ROPE);
      }
      const keyText = escapedString(key, `${location}.{key}`);
      const keyBytes = reserveText(context, keyText);
      reserveBytes(context, 1);
      if (ropeParts !== null) arrayPush(ropeParts, textRope(`${keyText}:`, keyBytes + 1));
      const childRole: CaptureRole =
        role.kind === "REPLAY_ROOT" && key === "events"
          ? REPLAY_EVENTS_CAPTURE_ROLE
          : (role.kind === "REPLAY_EVENT" || role.kind === "QUERY_EVENT") && key === "data"
            ? Object.freeze({ kind: "REPLAY_EVENT_DATA", index: role.index })
            : (role.kind === "REPLAY_EVENT" || role.kind === "QUERY_EVENT") &&
                (key === "id" || key === "type" || key === "timestamp")
              ? REPLAY_DESIGNATED_SCALAR_CAPTURE_ROLE
              : role.kind === "PORTABLE_AUTHORITY"
                ? portableAuthorityRecordChildRole(role.state, key)
              : key === "acknowledgment" || key === "noEffect" || key === "adapterProfile"
                ? ADAPTER_EVIDENCE_CAPTURE_ROLE
              : NORMAL_CAPTURE_ROLE;
      let node: CapturedNode;
      try {
        node = captureNode(
          field,
          context,
          depth,
          `${location}.${key}`,
          childRole,
        );
      } catch (error) {
        if (role.kind === "REPLAY_EVENT" && key === "data") {
          annotateReplayBaseFailure(
            error,
            context,
            replayBaseFailureMetadata(
              role.index,
              "EVENT_ENVELOPE_INVALID",
            ),
          );
        }
        throw error;
      }
      maximumChildIntrinsicDepth = Math.max(
        maximumChildIntrinsicDepth,
        node.intrinsicDepth,
      );
      if (ropeParts !== null) {
        if (node.canonicalRope === null) ropeParts = null;
        else arrayPush(ropeParts, node.canonicalRope);
      }
      Object.defineDataProperty(immutable, key, node.value, true, true, true);
      if (field !== null && typeof field === "object" && typeof node.value === "bigint") {
        normalizedMembers ??= Object.create(null) as Record<string, true>;
        Object.defineDataProperty(normalizedMembers, key, true, true, true, true);
      }
      ordinaryFields += 1;
    }

    const depth = containerDepth + 1;
    if (recognizedMarker === undefined && depth > MAX_CANONICAL_DEPTH) {
      throw canonicalNamedLimitError(
        `Canonical value at ${location} exceeds nesting depth ${MAX_CANONICAL_DEPTH}.`,
        location,
        MAX_CANONICAL_DEPTH,
      );
    }
    reserveBytes(context, 1);
    if (ropeParts !== null) arrayPush(ropeParts, CLOSE_RECORD_ROPE);
    const result: CapturedNode = {
      value: recognizedMarker ?? Object.freeze(immutable),
      canonicalBytes: context.budget.used - startBytes,
      canonicalRope: ropeParts === null ? null : sequenceRope(ropeParts),
      intrinsicDepth:
        recognizedMarker === undefined ? 1 + maximumChildIntrinsicDepth : 0,
    };
    if (recognizedMarker === undefined) {
      if (normalizedMembers !== undefined) {
        weakMapSet(context.normalizedObjectMembers, result.value as object, Object.freeze(normalizedMembers));
      }
      weakMapSet(
        context.recordKeysByCapturedValue,
        result.value as object,
        Object.freeze(copyArray(ordered)),
      );
      weakMapSet(context.nodeByCapturedValue, result.value as object, result);
    }
    weakMapSet(context.memo, value, result);
    return result;
  } finally {
    weakSetDelete(context.active, value);
  }
};

const captureNode = (
  value: unknown, context: CaptureContext, containerDepth: number, location: string,
  role: CaptureRole = NORMAL_CAPTURE_ROLE,
): CapturedNode => {
  const dataOnly = role.kind === "ADAPTER_EVIDENCE" || (context.adapterDataOnlyDepth ?? 0) > 0;
  if (dataOnly && value !== null && (typeof value === "object" || typeof value === "function") && isNodeProxy(value)) {
    throw new TypeError(`Adapter data proxy at ${location} is unsupported.`);
  }
  const before = context.accessorReads ?? 0;
  const result = captureNodeBody(value, context, containerDepth, location, role);
  if ((context.accessorReads ?? 0) !== before) result.observedAccessor = true;
  if (dataOnly && result.observedAccessor) throw new TypeError(`Adapter data alias at ${location} contains an accessor.`);
  return result;
};

const captureNodeBody = (
  value: unknown,
  context: CaptureContext,
  containerDepth: number,
  location: string,
  role: CaptureRole = NORMAL_CAPTURE_ROLE,
): CapturedNode => {
  enforceAuthorityScalarLimits(value, role, location);
  enforceDesignatedScalarHostKind(value, role, location);
  if (
    role.kind === "REPLAY_EVENT" &&
    (value === null || typeof value !== "object" || Array.isArray(value))
  ) {
    throw canonicalReplaySchemaFailure(
      `Canonical replay event at ${location} is not a plain record.`,
    );
  }
  if (role.kind === "REPLAY_EVENT_DATA" || role.kind === "ADAPTER_EVIDENCE") {
    const localBudget: CaptureBudget = {
      label: role.kind === "ADAPTER_EVIDENCE" ? location : `$.events[${role.index}].data`,
      limit: role.kind === "ADAPTER_EVIDENCE" ? 4096 : MAX_REPLAY_EVENT_DATA_UTF8_BYTES,
      used: 0,
    };
    arrayPush(context.localBudgets, localBudget);
    if (role.kind === "ADAPTER_EVIDENCE") context.adapterDataOnlyDepth = (context.adapterDataOnlyDepth ?? 0) + 1;
    try {
      return captureNode(
        value,
        context,
        containerDepth,
        location,
        NORMAL_CAPTURE_ROLE,
      );
    } finally {
      if (role.kind === "ADAPTER_EVIDENCE") context.adapterDataOnlyDepth = (context.adapterDataOnlyDepth ?? 0) - 1;
      const removed = arrayPop(context.localBudgets);
      if (removed !== localBudget) {
        throw new TypeError("Canonical replay capture lost its local-budget stack.");
      }
    }
  }
  if (value === null) return canonicalScalarNode(null, "null", context);
  if (typeof value === "boolean") {
    return canonicalScalarNode(value, value ? "true" : "false", context);
  }
  if (typeof value === "string") {
    if (
      context.mode === "STRUCTURAL_PHASE_ONE" ||
      role.kind === "REPLAY_DESIGNATED_SCALAR"
    ) {
      // Every UTF-16 code unit contributes at least one UTF-8 byte to any
      // well-formed interpretation. This host-size preflight therefore rejects
      // a proven ProtocolString overflow before malformed-Unicode classification
      // can collapse an arbitrarily large caller string into a 32-byte token.
      if (value.length > MAX_PROTOCOL_STRING_UTF8_BYTES) {
        throw canonicalNamedLimitError(
          `Canonical string at ${location} exceeds the ${MAX_PROTOCOL_STRING_UTF8_BYTES}-byte ProtocolString bound.`,
          location,
          MAX_PROTOCOL_STRING_UTF8_BYTES,
        );
      }
      if (!isWellFormedUnicode(value)) {
        return noncanonicalScalarNode(value, context);
      }
    }
    return canonicalScalarNode(value, escapedString(value, location), context);
  }
  if (typeof value === "number") {
    const valid = Number.isSafeInteger(value) && !Object.is(value, -0);
    if (!valid) {
      if (
        context.mode === "STRUCTURAL_PHASE_ONE" ||
        role.kind === "REPLAY_DESIGNATED_SCALAR"
      ) {
        return noncanonicalScalarNode(value, context);
      }
      if (!Number.isFinite(value)) {
        throw new TypeError(`Canonical number at ${location} must be finite.`);
      }
      throw new TypeError(
        `Canonical number at ${location} must be a signed safe integer other than negative zero.`,
      );
    }
    return canonicalScalarNode(value, numberToString(value, 10), context);
  }
  if (typeof value === "bigint") {
    if (value < -MAX_PROTOCOL_BIGINT || value > MAX_PROTOCOL_BIGINT) {
      if (
        context.mode === "STRUCTURAL_PHASE_ONE" ||
        role.kind === "REPLAY_DESIGNATED_SCALAR"
      ) {
        return noncanonicalScalarNode(value, context);
      }
      bigintDecimal(value, location);
    }
    const decimal = bigintToString(value, 10);
    return canonicalScalarNode(
      value,
      `{"${BIGINT_MARKER_KEY}":"${decimal}"}`,
      context,
    );
  }
  if (value === undefined) {
    throw new TypeError(`Canonical value at ${location} is undefined.`);
  }
  if (typeof value !== "object") {
    throw new TypeError(`Canonical value at ${location} has unsupported type ${typeof value}.`);
  }
  if (weakSetHas(context.active, value)) {
    throw new TypeError(`Canonical value at ${location} contains an active cycle.`);
  }
  const memoized = weakMapGet(context.memo, value);
  if (memoized !== undefined) {
    if (role.kind === "PORTABLE_AUTHORITY") {
      // Traverse only module-owned immutable values; never reread the caller.
      enforceMemoizedAuthorityRole(memoized.value, context, role, location);
    }
    // Reuse preserves observation identity, not a broader grammar. A request
    // classification (for example NaN Amount) is never strict event data.
    if (context.strictQueryMemo && role.kind === "NORMAL" && memoized.canonicalRope === null) {
      throw new TypeError("Query alias introduces a classified scalar into strict canonical data.");
    }
    if (role.kind === "QUERY_EVENTS") {
      if (!Array.isArray(memoized.value)) throw new TypeError("Query history must be a list.");
      reserveReceiptEventOccurrences(context, memoized.value.length, location);
      for (let index = 0; index < memoized.value.length; index += 1) {
        const member = memoized.value[index];
        const node = member !== null && typeof member === "object"
          ? weakMapGet(context.nodeByCapturedValue, member) : undefined;
        if (node !== undefined) {
          enforceMemoizedQueryEventGrammar(node, context);
          enforceMemoizedReplayEventDataBudget(node, context, index);
        }
      }
    }
    if (role.kind === "QUERY_EVENT") {
      enforceMemoizedQueryEventGrammar(memoized, context);
      enforceMemoizedReplayEventDataBudget(memoized, context, role.index);
    }
    if (
      role.kind === "REPLAY_EVENTS" &&
      context.receiptEventOccurrences !== undefined
    ) {
      // An event list may first have appeared as plain data in another event.
      // Refine its immutable snapshot without observing that original again.
      if (!Array.isArray(memoized.value)) {
        throw new TypeError("Receipt history must be a dense event list.");
      }
      reserveReceiptEventOccurrences(context, memoized.value.length, location);
      for (let index = 0; index < memoized.value.length; index += 1) {
        const member = memoized.value[index];
        const node = member !== null && typeof member === "object"
          ? weakMapGet(context.nodeByCapturedValue, member)
          : undefined;
        if (node === undefined) {
          throw new TypeError("Receipt history contains an invalid base envelope.");
        }
        validateCapturedReplayBaseNode(node, context, index);
        enforceMemoizedReplayEventDataBudget(node, context, index);
      }
    }
    if (role.kind === "REPLAY_EVENT") {
      validateCapturedReplayBaseNode(memoized, context, role.index);
      enforceMemoizedReplayEventDataBudget(memoized, context, role.index);
    }
    return reuseNode(memoized, context, containerDepth, location);
  }
  if (role.kind === "REPLAY_EVENT") {
    return captureReplayEvent(
      value,
      context,
      containerDepth,
      location,
      role.index,
    );
  }
  return Array.isArray(value)
    ? captureArray(value, context, containerDepth, location, role)
    : captureRecord(value, context, containerDepth, location, role);
};

type DeepCaptureResult<T> = {
  readonly value: T;
  readonly canonicalText: string | null;
  readonly canonicalBytes: number;
  readonly capturedRecordKeys: (
    value: unknown,
  ) => readonly string[] | undefined;
  readonly capturedCanonicalBytes: (value: unknown) => number | undefined;
};

type PrivateDeepCaptureOptions = Readonly<{
  /** Existing containing depth for one schema-owned subtree boundary. */
  ancestorContainerDepth?: number;
  /** One schema-owned containing object that the subtree may not retain. */
  forbiddenReference?: object;
  /** The exact root prototype already observed by that schema boundary. */
  preobservedRootPrototype?: Readonly<{
    readonly value: object;
    readonly prototype: object | null;
  }>;
  /** One module-owned structured root role; never supplied by public callers. */
  rootRole?: CaptureRole;
  /** One package-internal synchronous replay reducer. */
  replayVisitor?: CanonicalReplayCaptureVisitor;
}>;

const deepCapture = <T>(
  value: T,
  mode: CaptureMode,
  maxCanonicalBytes: number,
  options: PrivateDeepCaptureOptions = {},
): DeepCaptureResult<T> => {
  const preobservedRootPrototype = Object.hasOwn(
    options,
    "preobservedRootPrototype",
  )
    ? options.preobservedRootPrototype
    : undefined;
  const replayVisitor = Object.hasOwn(options, "replayVisitor")
    ? options.replayVisitor
    : undefined;
  const forbiddenReference = Object.hasOwn(options, "forbiddenReference")
    ? options.forbiddenReference
    : undefined;
  const ancestorContainerDepth = Object.hasOwn(options, "ancestorContainerDepth")
    ? options.ancestorContainerDepth
    : undefined;
  const rootRole = Object.hasOwn(options, "rootRole")
    ? options.rootRole
    : undefined;
  const preobservedPrototypes = createWeakMap<object, object | null>();
  if (preobservedRootPrototype !== undefined) {
    weakMapSet(
      preobservedPrototypes,
      preobservedRootPrototype.value,
      preobservedRootPrototype.prototype,
    );
  }
  const context: CaptureContext = {
    mode,
    budget: { label: "$", limit: maxCanonicalBytes, used: 0 },
    active: createWeakSet<object>(),
    memo: createWeakMap<object, CapturedNode>(),
    recordKeysByCapturedValue: createWeakMap<object, readonly string[]>(),
    normalizedObjectMembers: createWeakMap<object, Readonly<Record<string, true>>>(),
    nodeByCapturedValue: createWeakMap<object, CapturedNode>(),
    localBudgets: [],
    replayFailureToken: Object.freeze({}),
    preobservedPrototypes,
    replayVisitor,
    ...(rootRole?.kind === "PORTABLE_AUTHORITY" && rootRole.state === "RAW_ROOT"
      ? { rawAuthorityOccurrences: { used: 0 } }
      : {}),
  };
  if (forbiddenReference !== undefined) {
    weakSetAdd(context.active, forbiddenReference);
  }
  const node = captureNode(
    value,
    context,
    ancestorContainerDepth ?? 0,
    "$",
    rootRole ?? NORMAL_CAPTURE_ROLE,
  );
  const capturedRecordKeys = Object.freeze((candidate: unknown) =>
    candidate !== null &&
    (typeof candidate === "object" || typeof candidate === "function")
      ? weakMapGet(context.recordKeysByCapturedValue, candidate as object)
      : undefined);
  const capturedCanonicalBytes = Object.freeze((candidate: unknown) =>
    candidate !== null &&
    (typeof candidate === "object" || typeof candidate === "function")
      ? weakMapGet(context.nodeByCapturedValue, candidate as object)?.canonicalBytes
      : undefined);
  return {
    value: node.value as T,
    canonicalText:
      node.canonicalRope === null
        ? null
        : materializeCanonicalRope(node.canonicalRope, node.canonicalBytes),
    canonicalBytes: node.canonicalBytes,
    capturedRecordKeys,
    capturedCanonicalBytes,
  };
};

export type BoundedCanonicalCaptureOptions = Readonly<{
  maxCanonicalBytes?: number;
}>;

export type BoundedCanonicalCapture<T> = Readonly<{
  value: T;
  canonicalText: string;
  canonicalBytes: number;
  capturedRecordKeys: (value: unknown) => readonly string[] | undefined;
}>;

/**
 * Bounded canonical capture. It observes the supplied value itself, applies
 * the caller's complete-value byte budget incrementally, and returns both the
 * immutable snapshot and its exact canonical text without a second read of
 * caller-owned data.
 */
export const captureBoundedCanonicalValue = <T>(
  value: T,
  options: BoundedCanonicalCaptureOptions = {},
): BoundedCanonicalCapture<T> => {
  const ownSuppliedLimit = Object.hasOwn(options, "maxCanonicalBytes")
    ? options.maxCanonicalBytes
    : undefined;
  const suppliedLimit = ownSuppliedLimit ?? MAX_CANONICAL_UTF8_BYTES;
  if (!Number.isSafeInteger(suppliedLimit) || suppliedLimit < 0) {
    throw new TypeError("maxCanonicalBytes must be a nonnegative safe integer.");
  }
  const limit = Math.min(suppliedLimit, MAX_CANONICAL_UTF8_BYTES);
  const captured = deepCapture(
    value,
    "STRICT_CANONICAL",
    limit,
  );
  if (captured.canonicalText === null) {
    throw new TypeError("Strict canonical capture produced a noncanonical scalar classification.");
  }
  return Object.freeze({
    value: captured.value,
    canonicalText: captured.canonicalText,
    canonicalBytes: captured.canonicalBytes,
    capturedRecordKeys: captured.capturedRecordKeys,
  });
};

export type CapturedCanonicalReplayBody = Readonly<{
  readonly value: Readonly<{
    readonly operationVersion: "continuity-replay/0.2";
    readonly events: readonly unknown[];
  }>;
  readonly canonicalBytes: number;
  readonly capturedRecordKeys: (
    value: unknown,
  ) => readonly string[] | undefined;
  readonly capturedCanonicalBytes: (value: unknown) => number | undefined;
}>;

export type IncrementalCanonicalReplayCaptureOutcome<T> =
  | Readonly<{
      readonly status: "CAPTURED";
      readonly capture: CapturedCanonicalReplayBody;
    }>
  | Readonly<{ readonly status: "STOPPED"; readonly result: T }>
  | Readonly<{ readonly status: "CAPTURE_FAILED"; readonly error: unknown }>;

const CANONICAL_REPLAY_BODY_CAPTURES = createWeakSet<object>();

/** Tests module-private provenance for the shared replay-body snapshot. */
export const isCapturedCanonicalReplayBody = (
  value: unknown,
): value is CapturedCanonicalReplayBody =>
  value !== null &&
  typeof value === "object" &&
  weakSetHas(CANONICAL_REPLAY_BODY_CAPTURES, value);

/**
 * @internal Supported-version replay seam. The outer operation must inspect
 * its version before calling this function. This captures the constructed
 * replay body and every event in one graph, fences the caller-owned containing
 * operation, applies the complete 16 MiB bound, and applies a fresh 1 MiB
 * budget to every event-data occurrence. It does not apply an event schema.
 */
const captureReplayBodyWithVisitor = (
  events: unknown,
  containingOperation: object,
  replayVisitor?: CanonicalReplayCaptureVisitor,
): CapturedCanonicalReplayBody => {
  if (!Array.isArray(events)) {
    throw new TypeError("Canonical replay events must be a dense bounded list.");
  }
  const replayBody = Object.create(null) as Record<string, unknown>;
  Object.defineDataProperty(
    replayBody,
    "operationVersion",
    REPLAY_OPERATION_VERSION,
    false,
    true,
  );
  Object.defineDataProperty(replayBody, "events", events, false, true);
  Object.freeze(replayBody);

  const captured = deepCapture(
    replayBody,
    "STRUCTURAL_PHASE_ONE",
    MAX_CANONICAL_UTF8_BYTES,
    {
      forbiddenReference: containingOperation,
      rootRole: REPLAY_ROOT_CAPTURE_ROLE,
      replayVisitor,
    },
  );
  const value = captured.value as Readonly<{
    readonly operationVersion: "continuity-replay/0.2";
    readonly events: readonly unknown[];
  }>;
  if (!Array.isArray(value.events)) {
    throw new TypeError("Canonical replay capture lost its event-list shape.");
  }
  const result: CapturedCanonicalReplayBody = Object.freeze({
    value,
    canonicalBytes: captured.canonicalBytes,
    capturedRecordKeys: captured.capturedRecordKeys,
    capturedCanonicalBytes: captured.capturedCanonicalBytes,
  });
  weakSetAdd(CANONICAL_REPLAY_BODY_CAPTURES, result);
  return result;
};

export const captureBoundedCanonicalReplayBody = (
  events: unknown,
  containingOperation: object,
): CapturedCanonicalReplayBody =>
  captureReplayBodyWithVisitor(events, containingOperation);

/**
 * @internal Single-context replay capture with a synchronous position-primary
 * semantic reducer. The reducer can stop the operation only after receiving a
 * provenance-bound immutable event snapshot; it cannot influence capture.
 */
export const captureBoundedCanonicalReplayBodyIncrementally = <T>(
  events: unknown,
  containingOperation: object,
  visitor: (
    capture: CapturedCanonicalReplayEvent,
  ) => CanonicalReplayCaptureVisitDecision<T>,
): IncrementalCanonicalReplayCaptureOutcome<T> => {
  if (typeof visitor !== "function") {
    throw new TypeError("Canonical replay capture visitor must be a function.");
  }
  try {
    const capture = captureReplayBodyWithVisitor(
      events,
      containingOperation,
      visitor as CanonicalReplayCaptureVisitor,
    );
    return Object.freeze({ status: "CAPTURED", capture });
  } catch (error) {
    if (
      error !== null &&
      typeof error === "object" &&
      weakMapHas(REPLAY_CAPTURE_VISITOR_STOPS, error)
    ) {
      return Object.freeze({
        status: "STOPPED",
        result: weakMapGet(REPLAY_CAPTURE_VISITOR_STOPS, error) as T,
      });
    }
    if (
      error !== null &&
      typeof error === "object" &&
      weakMapHas(REPLAY_CAPTURE_VISITOR_THROWS, error)
    ) {
      throw weakMapGet(REPLAY_CAPTURE_VISITOR_THROWS, error);
    }
    return Object.freeze({ status: "CAPTURE_FAILED", error });
  }
};

export type CapturedCanonicalAuthorityOperation<T = unknown> = Readonly<{
  readonly value: T;
  readonly canonicalBytes: number;
  readonly capturedRecordKeys: (
    value: unknown,
  ) => readonly string[] | undefined;
  readonly capturedCanonicalBytes: (value: unknown) => number | undefined;
}>;

export type IncrementalCanonicalAuthorityCaptureOutcome<TCapture, TStop> =
  | Readonly<{
      readonly status: "CAPTURED";
      readonly capture: CapturedCanonicalAuthorityOperation<TCapture>;
    }>
  | Readonly<{ readonly status: "STOPPED"; readonly result: TStop }>
  | Readonly<{ readonly status: "CAPTURE_FAILED"; readonly error: unknown }>;

const CANONICAL_AUTHORITY_OPERATION_CAPTURES = createWeakSet<object>();

/** Tests package-internal provenance for one complete authority-operation snapshot. */
export const isCapturedCanonicalAuthorityOperation = (
  value: unknown,
): value is CapturedCanonicalAuthorityOperation =>
  value !== null &&
  typeof value === "object" &&
  weakSetHas(CANONICAL_AUTHORITY_OPERATION_CAPTURES, value);

/**
 * @internal One-graph capture for the raw authority, replay-bound authority,
 * and later admission operations. The caller supplies only a package-owned
 * body whose outer fields were each observed once after version dispatch.
 * Identifier/U53/Amount slots receive structural phase-one classification;
 * an embedded event list uses the same provenance-bound replay visitor as
 * `replayPortable`.
 */
export const captureBoundedCanonicalAuthorityOperationIncrementally = <
  TCapture,
  TStop,
>(
  value: TCapture,
  containingOperation: object,
  kind: PortableAuthorityCaptureKind,
  replayVisitor?: (
    capture: CapturedCanonicalReplayEvent,
  ) => CanonicalReplayCaptureVisitDecision<TStop>,
): IncrementalCanonicalAuthorityCaptureOutcome<TCapture, TStop> => {
  try {
    const captured = deepCapture(
      value,
      "STRUCTURAL_PHASE_ONE",
      MAX_CANONICAL_UTF8_BYTES,
      {
        forbiddenReference: containingOperation,
        rootRole: portableAuthorityRootRole(kind),
        ...(replayVisitor === undefined
          ? {}
          : { replayVisitor: replayVisitor as CanonicalReplayCaptureVisitor }),
      },
    );
    const capture = Object.freeze({
      value: captured.value,
      canonicalBytes: captured.canonicalBytes,
      capturedRecordKeys: captured.capturedRecordKeys,
      capturedCanonicalBytes: captured.capturedCanonicalBytes,
    });
    weakSetAdd(CANONICAL_AUTHORITY_OPERATION_CAPTURES, capture);
    return Object.freeze({ status: "CAPTURED", capture });
  } catch (error) {
    if (
      error !== null &&
      typeof error === "object" &&
      weakMapHas(REPLAY_CAPTURE_VISITOR_STOPS, error)
    ) {
      return Object.freeze({
        status: "STOPPED",
        result: weakMapGet(REPLAY_CAPTURE_VISITOR_STOPS, error) as TStop,
      });
    }
    if (
      error !== null &&
      typeof error === "object" &&
      weakMapHas(REPLAY_CAPTURE_VISITOR_THROWS, error)
    ) {
      throw weakMapGet(REPLAY_CAPTURE_VISITOR_THROWS, error);
    }
    return Object.freeze({ status: "CAPTURE_FAILED", error });
  }
};

export type PortableReceiptCaptureKind = "VERIFY" | "RECORD";

export type CapturedCanonicalReceiptOperation = Readonly<{
  readonly value: Readonly<Record<string, unknown>>;
  readonly canonicalBytes: number;
  readonly capturedRecordKeys: (value: unknown) => readonly string[] | undefined;
  readonly capturedCanonicalBytes: (value: unknown) => number | undefined;
}>;

export type CanonicalReceiptCaptureOutcome =
  | Readonly<{
      readonly status: "CAPTURED";
      readonly capture: CapturedCanonicalReceiptOperation;
    }>
  | Readonly<{
      readonly status: "INVALID_INPUT";
      /** Package-internal distinction for prospective construction limits. */
      readonly limitExceeded: boolean;
    }>
  | Readonly<{ readonly status: "MALFORMED_ARTIFACT" | "UNSUPPORTED_OPERATION" }>;

type ReceiptNonArtifactKind = "DOMAIN" | "HISTORY_HEAD" | "IDENTIFIER" | "TIME";
type ReceiptCapturedMemberValidator = (
  capture: Pick<CapturedCanonicalReceiptOperation, "capturedRecordKeys">,
  kind: ReceiptNonArtifactKind,
  value: unknown,
) => "VALID" | "INVALID" | "LIMIT" | "UNSUPPORTED";
type ReceiptCapturedHistoryLimitPreflight = (
  capture: Pick<CapturedCanonicalReceiptOperation, "capturedRecordKeys" | "capturedCanonicalBytes">,
  histories: readonly (readonly unknown[])[],
) => "VALID" | "LIMIT";

const RECEIPT_VERIFY_KEYS = Object.freeze([
  "artifact", "expectedDomain", "issuanceEvents", "observedEvents",
  "operationVersion", "verifierTime",
]);
const RECEIPT_RECORD_KEYS = Object.freeze([
  "artifact", "events", "expectedDomain", "expectedHistoryHead",
  "operationVersion", "recordEventId",
]);

/**
 * @internal Receipt-only staged capture. The shared graph memo is retained
 * across outer members and both event lists. An unsupported operation reads
 * no body descriptor; supported operations validate non-artifact members and
 * base envelopes before capturing artifact plain data. Artifact schema,
 * version dispatch, transition replay and axes belong to the caller.
 */
export const captureBoundedCanonicalReceiptOperation = (
  input: unknown,
  kind: PortableReceiptCaptureKind,
  validateMember: ReceiptCapturedMemberValidator,
  preflightHistoryLimits: ReceiptCapturedHistoryLimitPreflight,
): CanonicalReceiptCaptureOutcome => {
  let artifactPhase = false;
  const invalid = (limitExceeded = false): CanonicalReceiptCaptureOutcome =>
    Object.freeze({ status: "INVALID_INPUT", limitExceeded });
  try {
    if (input === null || typeof input !== "object" || Array.isArray(input)) {
      return invalid();
    }
    const prototype = readPrototype(input, "$");
    if (prototype !== Object.prototype && prototype !== null) return invalid();
    const rawKeys = readOwnKeys(input, "$");
    if (rawKeys.length > MAX_CANONICAL_RECORD_FIELDS) return invalid(true);
    const expectedKeys = kind === "VERIFY" ? RECEIPT_VERIFY_KEYS : RECEIPT_RECORD_KEYS;
    if (rawKeys.length !== expectedKeys.length) return invalid();
    const membership = createSet<string>();
    for (let index = 0; index < rawKeys.length; index += 1) {
      const key = rawKeys[index]!;
      if (typeof key !== "string") return invalid();
      protocolStringByteLength(key, "$.{key}");
      setAdd(membership, key);
    }
    for (let index = 0; index < expectedKeys.length; index += 1) {
      if (!setHas(membership, expectedKeys[index]!)) return invalid();
    }

    const context: CaptureContext = {
      mode: "STRICT_CANONICAL",
      budget: { label: "$", limit: MAX_CANONICAL_UTF8_BYTES, used: 0 },
      active: createWeakSet<object>(),
      memo: createWeakMap<object, CapturedNode>(),
      recordKeysByCapturedValue: createWeakMap<object, readonly string[]>(),
      normalizedObjectMembers: createWeakMap<object, Readonly<Record<string, true>>>(),
      nodeByCapturedValue: createWeakMap<object, CapturedNode>(),
      localBudgets: [],
      replayFailureToken: Object.freeze({}),
      preobservedPrototypes: createWeakMap<object, object | null>(),
      replayVisitor: undefined,
      receiptEventOccurrences: { used: 0 },
    };
    weakSetAdd(context.active, input);
    // Reserve the complete, mandatory closed-record framing before any body
    // member. All six members are required, so these bytes cannot disappear.
    reserveBytes(context, 2 + expectedKeys.length - 1);
    for (let index = 0; index < expectedKeys.length; index += 1) {
      reserveText(context, `${escapedString(expectedKeys[index]!, "$.{key}")}:`);
    }
    const capturedRecordKeys = Object.freeze((candidate: unknown) =>
      candidate !== null && typeof candidate === "object"
        ? weakMapGet(context.recordKeysByCapturedValue, candidate)
        : undefined);
    const capturedCanonicalBytes = Object.freeze((candidate: unknown) =>
      candidate !== null && typeof candidate === "object"
        ? weakMapGet(context.nodeByCapturedValue, candidate)?.canonicalBytes
        : undefined);
    const metadata = Object.freeze({ capturedRecordKeys });
    const value = Object.create(null) as Record<string, unknown>;
    let maximumChildDepth = 0;
    const captureMember = (key: string, role: CaptureRole = NORMAL_CAPTURE_ROLE) => {
      const location = `$.${key}`;
      const descriptor = readDescriptor(input, key, location);
      const original = capturedDescriptorValue(context, descriptor, input, location);
      if (key === "operationVersion" && typeof original !== "string") {
        throw new TypeError("Receipt operation version must be a ProtocolString.");
      }
      if (role.kind === "REPLAY_EVENTS" && !Array.isArray(original)) {
        throw new TypeError(`Receipt history at ${location} must be a dense list.`);
      }
      const node = captureNode(original, context, 1, location, role);
      Object.defineDataProperty(value, key, node.value, false, true);
      maximumChildDepth = Math.max(maximumChildDepth, node.intrinsicDepth);
      return node.value;
    };
    const operationVersion = captureMember("operationVersion");
    if (typeof operationVersion !== "string") return invalid();
    const supportedVersion = kind === "VERIFY"
      ? "continuity-receipt-verification/0.2"
      : "continuity-receipt-record-admission/0.2";
    if (operationVersion !== supportedVersion) {
      return Object.freeze({ status: "UNSUPPORTED_OPERATION" });
    }
    const validate = (key: string, memberKind: ReceiptNonArtifactKind) =>
      validateMember(metadata, memberKind, captureMember(key));
    const domainResult = validate("expectedDomain", "DOMAIN");
    if (domainResult !== "VALID") return invalid(domainResult === "LIMIT");
    if (kind === "VERIFY") {
      const timeResult = validate("verifierTime", "TIME");
      if (timeResult !== "VALID") return invalid(timeResult === "LIMIT");
      captureMember("issuanceEvents", REPLAY_EVENTS_CAPTURE_ROLE);
      captureMember("observedEvents", REPLAY_EVENTS_CAPTURE_ROLE);
    } else {
      const headResult = validate("expectedHistoryHead", "HISTORY_HEAD");
      if (headResult !== "VALID") return invalid(headResult === "LIMIT");
      const idResult = validate("recordEventId", "IDENTIFIER");
      if (idResult !== "VALID") return invalid(idResult === "LIMIT");
      captureMember("events", REPLAY_EVENTS_CAPTURE_ROLE);
    }

    const histories = kind === "VERIFY"
      ? Object.freeze([value.issuanceEvents as readonly unknown[], value.observedEvents as readonly unknown[]])
      : Object.freeze([value.events as readonly unknown[]]);
    if (preflightHistoryLimits(
      Object.freeze({ capturedRecordKeys, capturedCanonicalBytes }), histories,
    ) === "LIMIT") return invalid(true);

    artifactPhase = true;
    captureMember("artifact");
    Object.freeze(value);
    const rootNode: CapturedNode = {
      value,
      canonicalBytes: context.budget.used,
      // No caller of this seam requests materialized canonical text.
      canonicalRope: null,
      intrinsicDepth: 1 + maximumChildDepth,
    };
    weakMapSet(context.recordKeysByCapturedValue, value, expectedKeys);
    weakMapSet(context.nodeByCapturedValue, value, rootNode);
    // Preserve original undefined fields in the returned input graph as well
    // as in metadata. A downstream replay may capture this immutable value
    // again; it must still reject an originally present unknown field.
    const restored = createWeakMap<object, object>();
    const restorePresence = (candidate: unknown): unknown => {
      if (candidate === null || typeof candidate !== "object") return candidate;
      const prior = weakMapGet(restored, candidate);
      if (prior !== undefined) return prior;
      const sourceNode = weakMapGet(context.nodeByCapturedValue, candidate);
      if (sourceNode === undefined) {
        throw new TypeError("Receipt snapshot lost canonical-node metadata.");
      }
      let copy: object;
      if (Array.isArray(candidate)) {
        const list: unknown[] = [];
        copy = list;
        weakMapSet(restored, candidate, copy);
        for (let index = 0; index < candidate.length; index += 1) {
          arrayPush(list, restorePresence(candidate[index]));
        }
      } else {
        const keys = weakMapGet(context.recordKeysByCapturedValue, candidate);
        if (keys === undefined) {
          throw new TypeError("Receipt snapshot lost original record-key metadata.");
        }
        copy = Object.create(null) as Record<string, unknown>;
        weakMapSet(restored, candidate, copy);
        for (let index = 0; index < keys.length; index += 1) {
          const key = keys[index]!;
          Object.defineDataProperty(
            copy, key, restorePresence((candidate as Record<string, unknown>)[key]),
            false, true,
          );
        }
        weakMapSet(context.recordKeysByCapturedValue, copy, keys);
      }
      Object.freeze(copy);
      weakMapSet(context.nodeByCapturedValue, copy, {
        value: copy,
        canonicalBytes: sourceNode.canonicalBytes,
        canonicalRope: sourceNode.canonicalRope,
        intrinsicDepth: sourceNode.intrinsicDepth,
      });
      return copy;
    };
    const restoredValue = restorePresence(value) as Readonly<Record<string, unknown>>;
    const capture = Object.freeze({
      value: restoredValue,
      canonicalBytes: rootNode.canonicalBytes,
      capturedRecordKeys,
      capturedCanonicalBytes,
    });
    return Object.freeze({ status: "CAPTURED", capture });
  } catch (error) {
    if (getCanonicalCaptureLimitErrorMetadata(error) !== undefined) {
      return invalid(true);
    }
    return artifactPhase && kind === "VERIFY"
      ? Object.freeze({ status: "MALFORMED_ARTIFACT" })
      : invalid();
  }
};

export type CapturedCanonicalQueryOperation = CapturedCanonicalReceiptOperation;
export type CanonicalQueryCaptureOutcome =
  | Readonly<{ status: "CAPTURED"; capture: CapturedCanonicalQueryOperation }>
  | Readonly<{ status: "INVALID_INPUT" | "UNSUPPORTED_VERSION" }>;

/**
 * @internal Section9 two-stage capture. Version precedes own-key enumeration;
 * supported bodies share one graph memo, occurrence budget and original-key
 * metadata. Query histories defer base/schema semantics until both snapshots
 * are structurally captured, preserving input-before-state failure precedence.
 */
export const captureBoundedCanonicalQueryOperation = (
  input: unknown,
  kind: "WHY" | "RESPONSIBLE" | "SURVIVES",
): CanonicalQueryCaptureOutcome => {
  const invalid = (): CanonicalQueryCaptureOutcome => Object.freeze({ status: "INVALID_INPUT" });
  try {
    if (input === null || typeof input !== "object" || Array.isArray(input)) return invalid();
    const prototype = readPrototype(input, "$");
    if (prototype !== Object.prototype && prototype !== null) return invalid();
    const context: CaptureContext = {
      mode: "STRICT_CANONICAL",
      budget: { label: "$", limit: MAX_CANONICAL_UTF8_BYTES, used: 0 },
      active: createWeakSet<object>(), memo: createWeakMap<object, CapturedNode>(),
      recordKeysByCapturedValue: createWeakMap<object, readonly string[]>(),
      normalizedObjectMembers: createWeakMap<object, Readonly<Record<string, true>>>(),
      nodeByCapturedValue: createWeakMap<object, CapturedNode>(), localBudgets: [],
      replayFailureToken: Object.freeze({}),
      preobservedPrototypes: createWeakMap<object, object | null>(),
      replayVisitor: undefined, receiptEventOccurrences: { used: 0 }, strictQueryMemo: true,
    };
    weakSetAdd(context.active, input);
    const value = Object.create(null) as Record<string, unknown>;
    let maximumChildDepth = 0;
    const captureMember = (key: string, role: CaptureRole = NORMAL_CAPTURE_ROLE) => {
      const location = `$.${key}`;
      const original = capturedDescriptorValue(context, readDescriptor(input, key, location), input, location);
      if (key === "operationVersion" && typeof original !== "string") {
        throw new TypeError("Query operation version must be a ProtocolString.");
      }
      if (original === undefined && key !== "operationVersion") {
        Object.defineDataProperty(value, key, undefined, false, true);
        return undefined;
      }
      if (role.kind === "QUERY_EVENTS" && !Array.isArray(original)) {
        throw new TypeError("Query histories must be dense lists.");
      }
      if (key !== "operationVersion") {
        reserveBytes(context, 1);
        reserveText(context, `${escapedString(key, "$.{key}")}:`);
      }
      const node = captureNode(original, context, 1, location, role);
      Object.defineDataProperty(value, key, node.value, false, true);
      maximumChildDepth = Math.max(maximumChildDepth, node.intrinsicDepth);
      return node.value;
    };
    reserveBytes(context, 2);
    reserveText(context, `${escapedString("operationVersion", "$.{key}")}:`);
    if (captureMember("operationVersion") !== "continuity-query-envelope/0.2") {
      return Object.freeze({ status: "UNSUPPORTED_VERSION" });
    }
    const required = kind === "SURVIVES"
      ? ["operationVersion", "observedEvents", "targetAgentId", "evaluationTime", "disclosure"]
      : ["operationVersion", "evaluationEvents", "observedEvents", "authorizationDomain", "request", "evaluationTime", "disclosure"];
    const optional = kind === "SURVIVES" ? ["evaluationEvents"] : ["consequentialBinding"];
    const rawKeys = readOwnKeys(input, "$");
    if (rawKeys.length > MAX_CANONICAL_RECORD_FIELDS) return invalid();
    const membership = createSet<string>();
    const keys: string[] = [];
    for (let index = 0; index < rawKeys.length; index += 1) {
      const key = rawKeys[index]!;
      if (typeof key !== "string") return invalid();
      protocolStringByteLength(key, "$.{key}");
      if (!arrayIncludes(required, key) && !arrayIncludes(optional, key)) return invalid();
      setAdd(membership, key); arrayPush(keys, key);
    }
    for (let index = 0; index < required.length; index += 1) {
      if (!setHas(membership, required[index]!)) return invalid();
    }
    // Capture non-history fields first, but never inspect a caller member twice.
    const order = kind === "SURVIVES"
      ? ["targetAgentId", "evaluationTime", "disclosure", "evaluationEvents", "observedEvents"]
      : ["authorizationDomain", "request", "evaluationTime", "consequentialBinding", "disclosure", "evaluationEvents", "observedEvents"];
    for (let index = 0; index < order.length; index += 1) {
      const key = order[index]!;
      if (!setHas(membership, key)) continue;
      const role: CaptureRole = key === "evaluationEvents" || key === "observedEvents"
        ? Object.freeze({ kind: "QUERY_EVENTS" })
        : key === "evaluationTime" || key === "targetAgentId"
          ? REPLAY_DESIGNATED_SCALAR_CAPTURE_ROLE
          : key === "request" ? portableAuthorityRole("ACTION_REQUEST")
          : key === "consequentialBinding" ? portableAuthorityRole("CONSEQUENTIAL_BINDING")
          : NORMAL_CAPTURE_ROLE;
      const captured = captureMember(key, role);
      if (captured === undefined) {
        if (arrayIncludes(required, key)) return invalid();
      }
    }
    Object.freeze(value);
    const rootNode: CapturedNode = {
      value, canonicalBytes: context.budget.used, canonicalRope: null,
      intrinsicDepth: 1 + maximumChildDepth,
    };
    weakMapSet(context.recordKeysByCapturedValue, value, Object.freeze(keys));
    weakMapSet(context.nodeByCapturedValue, value, rootNode);
    const capturedRecordKeys = Object.freeze((candidate: unknown) =>
      candidate !== null && typeof candidate === "object"
        ? weakMapGet(context.recordKeysByCapturedValue, candidate) : undefined);
    const capturedCanonicalBytes = Object.freeze((candidate: unknown) =>
      candidate !== null && typeof candidate === "object"
        ? weakMapGet(context.nodeByCapturedValue, candidate)?.canonicalBytes : undefined);
    const restored = createWeakMap<object, object>();
    const restorePresence = (candidate: unknown): unknown => {
      if (candidate === null || typeof candidate !== "object") return candidate;
      const prior = weakMapGet(restored, candidate);
      if (prior !== undefined) return prior;
      const sourceNode = weakMapGet(context.nodeByCapturedValue, candidate);
      if (sourceNode === undefined) {
        throw new TypeError("Query snapshot lost canonical-node metadata.");
      }
      let copy: object;
      if (Array.isArray(candidate)) {
        const list: unknown[] = [];
        copy = list;
        weakMapSet(restored, candidate, copy);
        for (let index = 0; index < candidate.length; index += 1) {
          arrayPush(list, restorePresence(candidate[index]));
        }
      } else {
        const keys = weakMapGet(context.recordKeysByCapturedValue, candidate);
        if (keys === undefined) {
          throw new TypeError("Query snapshot lost original record-key metadata.");
        }
        copy = Object.create(null) as Record<string, unknown>;
        weakMapSet(restored, candidate, copy);
        for (let index = 0; index < keys.length; index += 1) {
          const key = keys[index]!;
          Object.defineDataProperty(
            copy, key, restorePresence((candidate as Record<string, unknown>)[key]),
            false, true,
          );
        }
        weakMapSet(context.recordKeysByCapturedValue, copy, keys);
      }
      Object.freeze(copy);
      weakMapSet(context.nodeByCapturedValue, copy, {
        value: copy,
        canonicalBytes: sourceNode.canonicalBytes,
        canonicalRope: sourceNode.canonicalRope,
        intrinsicDepth: sourceNode.intrinsicDepth,
      });
      return copy;
    };
    const restoredValue = restorePresence(value) as Readonly<Record<string, unknown>>;
    const capture = Object.freeze({
      value: restoredValue,
      canonicalBytes: rootNode.canonicalBytes,
      capturedRecordKeys,
      capturedCanonicalBytes,
    });
    return Object.freeze({ status: "CAPTURED", capture });
  } catch {
    return invalid();
  }
};

const CANONICAL_EVENT_DATA_SHAPE_ERRORS = createWeakSet<object>();

const canonicalEventDataShapeError = (): TypeError => {
  const error = new TypeError("Canonical event data must be a plain protocol record.");
  weakSetAdd(CANONICAL_EVENT_DATA_SHAPE_ERRORS, error);
  return error;
};

/** Tests only the module-private identity of an event-data shape failure. */
export const isCanonicalEventDataShapeError = (error: unknown): boolean =>
  error !== null &&
  typeof error === "object" &&
  weakSetHas(CANONICAL_EVENT_DATA_SHAPE_ERRORS, error);

/**
 * @internal Schema-owned event-data capture. Unlike the general public
 * capture, this boundary fixes the event container depth and directly fences
 * the one containing event. Callers cannot assert either fact or supply a
 * previously observed prototype.
 */
export const captureBoundedCanonicalEventData = (
  value: object,
  containingEvent: object,
  maxCanonicalBytes: number,
): BoundedCanonicalCapture<Readonly<Record<string, unknown>>> => {
  if (!Number.isSafeInteger(maxCanonicalBytes) || maxCanonicalBytes < 0) {
    throw new TypeError("maxCanonicalBytes must be a nonnegative safe integer.");
  }
  const limit = Math.min(maxCanonicalBytes, MAX_CANONICAL_UTF8_BYTES);
  if (value === containingEvent) {
    throw new TypeError("Canonical event data contains its containing event.");
  }
  if (Array.isArray(value)) {
    throw canonicalEventDataShapeError();
  }
  const prototype = readPrototype(value, "$");
  if (prototype !== Object.prototype && prototype !== null) {
    throw canonicalEventDataShapeError();
  }
  const captured = deepCapture(value, "STRICT_CANONICAL", limit, {
    ancestorContainerDepth: 1,
    forbiddenReference: containingEvent,
    preobservedRootPrototype: { value, prototype },
  });
  if (
    captured.value === null ||
    typeof captured.value !== "object" ||
    Array.isArray(captured.value)
  ) {
    throw canonicalEventDataShapeError();
  }
  if (captured.canonicalText === null) {
    throw new TypeError("Strict canonical capture produced a noncanonical scalar classification.");
  }
  return Object.freeze({
    value: captured.value as Readonly<Record<string, unknown>>,
    canonicalText: captured.canonicalText,
    canonicalBytes: captured.canonicalBytes,
    capturedRecordKeys: captured.capturedRecordKeys,
  });
};

/** Exact `continuity-canonical/0.2` text, with no whitespace or trailing newline. */
export const canonicalEncode = (value: unknown): string =>
  captureBoundedCanonicalValue(value).canonicalText;

/**
 * Deep immutable phase-one snapshot. Malformed Unicode spellings and invalid
 * numeric designated scalars remain available to later typed validation but
 * have no canonical text and count as fixed 32-byte classifications; every
 * other structural and finite bound is identical to strict canonical capture.
 */
export const immutableProtocolValue = <T>(value: T): T =>
  deepCapture(value, "STRUCTURAL_PHASE_ONE", MAX_CANONICAL_UTF8_BYTES).value;

/**
 * Immutable input snapshot that retains every originally present record key,
 * including undefined fields omitted by canonical encoding. This is a capture,
 * not schema validation: consumers must still validate their closed records.
 * Only the first capture observes caller-owned data; reconstruction traverses
 * its immutable snapshot and private key metadata, retaining shared aliases.
 */
export const immutableProtocolInput = <T>(value: T): T => {
  const captured = deepCapture(value, "STRUCTURAL_PHASE_ONE", MAX_CANONICAL_UTF8_BYTES);
  const copies = createWeakMap<object, object>();
  const restore = (node: unknown): unknown => {
    if (node === null || typeof node !== "object") return node;
    const prior = weakMapGet(copies, node);
    if (prior !== undefined) return prior;
    if (Array.isArray(node)) {
      const copy: unknown[] = [];
      weakMapSet(copies, node, copy);
      for (let index = 0; index < node.length; index += 1) arrayPush(copy, restore(node[index]));
      return Object.freeze(copy);
    }
    const keys = captured.capturedRecordKeys(node);
    if (keys === undefined) throw new TypeError("Input snapshot is missing record-key metadata.");
    const copy = Object.create(null) as Record<string, unknown>;
    weakMapSet(copies, node, copy);
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index]!;
      Object.defineDataProperty(copy, key, restore((node as Record<string, unknown>)[key]), false, true);
    }
    return Object.freeze(copy);
  };
  return restore(captured.value) as T;
};

/** Arrays entering schema-sensitive logic must contain only dense indexed data. */
export const isDenseArray = (
  value: unknown,
  maximumLength = MAX_CANONICAL_LIST_MEMBERS,
): value is readonly unknown[] => {
  if (!Array.isArray(value)) return false;
  let lengthDescriptor: PropertyDescriptor | undefined;
  try {
    lengthDescriptor = Reflect.getOwnPropertyDescriptor(value, "length");
  } catch {
    return false;
  }
  if (
    lengthDescriptor === undefined ||
    !Object.hasOwn(lengthDescriptor, "value")
  ) return false;
  const length = lengthDescriptor.value;
  if (!Number.isSafeInteger(length) || length < 0 || length > maximumLength) return false;
  let keys: readonly PropertyKey[];
  try {
    keys = Reflect.ownKeys(value);
  } catch {
    return false;
  }
  const fields: string[] = [];
  for (let keyIndex = 0; keyIndex < keys.length; keyIndex += 1) {
    const key = keys[keyIndex]!;
    if (typeof key !== "string") return false;
    if (key !== "length") arrayPush(fields, key);
  }
  if (fields.length !== length) return false;
  for (let fieldIndex = 0; fieldIndex < fields.length; fieldIndex += 1) {
    const index = canonicalArrayIndex(fields[fieldIndex]!);
    if (index === undefined || index >= length) return false;
  }
  return true;
};

export const hashCanonical = (value: unknown): ContentHash => {
  const encoded = UTF8_ENCODER.encode(canonicalEncode(value));
  return keccak256Bytes(encoded);
};

export const hashEventHistory = (events: readonly unknown[]): ContentHash => {
  if (!Array.isArray(events)) {
    throw new TypeError("Event history must be a runtime array.");
  }
  return hashCanonical(["continuity-event-history/0.2", events]);
};

/**
 * @internal Inclusive semantic commitments for every prefix of one captured
 * event history. The complete wrapper is captured first so aliases, nesting,
 * list density, Unicode, and aggregate bytes have exactly the one-shot
 * history-hash boundary. Each provenance-bound event is then canonically
 * encoded once and absorbed into one continuing Keccak state.
 */
export const hashEventHistoryPrefixes = (
  events: readonly unknown[],
): readonly ContentHash[] => {
  if (!Array.isArray(events)) {
    throw new TypeError("Event history must be a runtime array.");
  }

  const wrapper: unknown[] = [];
  arrayPush(wrapper, "continuity-event-history/0.2");
  arrayPush(wrapper, events);
  const capturedWrapper = captureBoundedCanonicalValue(wrapper).value;
  if (!Array.isArray(capturedWrapper)) {
    throw new TypeError("Captured event-history wrapper lost its list shape.");
  }
  const capturedEvents = capturedWrapper[1];
  if (!Array.isArray(capturedEvents)) {
    throw new TypeError("Captured event history lost its list shape.");
  }

  const continuing = createKeccak256State();
  updateKeccak256State(continuing, EVENT_HISTORY_CANONICAL_PREFIX);
  const hashes: ContentHash[] = [];
  for (let position = 0; position < capturedEvents.length; position += 1) {
    if (position > 0) {
      updateKeccak256State(continuing, EVENT_HISTORY_CANONICAL_SEPARATOR);
    }
    const eventBytes = UTF8_ENCODER.encode(
      canonicalEncode(capturedEvents[position]),
    );
    updateKeccak256State(continuing, eventBytes);
    const finalizable = cloneKeccak256State(continuing);
    updateKeccak256State(finalizable, EVENT_HISTORY_CANONICAL_SUFFIX);
    arrayPush(hashes, finalizeKeccak256State(finalizable));
  }
  return Object.freeze(hashes);
};
