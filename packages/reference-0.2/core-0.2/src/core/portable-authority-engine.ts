import { PORTABLE_ADAPTER_POLICY_E5_HASH, PORTABLE_ADAPTER_POLICY_E6_HASH, type PortableAdapterProfile } from "./portable-adapter-engine.ts";
import {
  captureBoundedCanonicalAuthorityOperationIncrementally,
  captureBoundedCanonicalValue,
  canonicalEncode,
  compareProtocolStrings,
  getCanonicalCaptureLimitErrorMetadata,
  hashCanonical,
  isCanonicalReplaySchemaFailure,
  isCapturedCanonicalAuthorityOperation,
  isWellFormedUnicode,
  type CanonicalReplayCaptureVisitDecision,
  type CapturedCanonicalAuthorityOperation,
  type CapturedCanonicalReplayEvent,
  type ContentHash,
  type PortableAuthorityCaptureKind,
} from "./canonical.ts";
import type {
  PortableAgentRecord,
  PortableAuthorityConstraints,
  PortableAuthorityEvidence,
  PortableAuthorityGrant,
  PortableAuthorityRecord,
  PortableAuthorityUsage,
  PortableAuthorizationDomain,
  PortableGlobalProhibitionGrant,
  PortableGenesisRecord,
  PortableHistoryHead,
  PortableIntentAdmissionRecord,
  PortableIntentDeclarationRecord,
  PortablePermissionGrant,
  PortablePrincipalRecord,
  PortableProhibitionGrant,
  PortableNonceReservation,
  PortableRecognizedRoot,
  PortableRoleRecord,
  PortableRoleTenureRecord,
  PortableRootProhibitionGrant,
  PortableRuntimeSessionRecord,
  PortableTransactionIntent,
} from "./portable-replay.ts";
import type { AcceptedCanonicalEventShape, CoreEventType } from "./event-schema.ts";
import {
  portableAdministrativeTransitionEffect,
  type PortableAdministrativeAuthorization,
} from "./portable-administration-codec.ts";
import {
  HostTypeError,
  arrayIncludes,
  arrayIsArray,
  arrayPush,
  arraySort,
  bigintFrom,
  copyArray,
  createMap,
  createSet,
  hostObjectPrototype,
  keccak256Bytes,
  mapForEach,
  mapGet,
  mapHas,
  mapSet,
  mapSize,
  numberFrom,
  numberIsSafeInteger,
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
  setDelete,
  setHas,
  setSize,
  setToArray,
  stringCharCodeAt,
  stringSlice,
  stringToLowerCase,
  utf8Encode,
  uint8ArrayLength,
} from "./host-intrinsics.ts";

const HostUint8Array = Uint8Array;
const Array = objectFreeze({ isArray: arrayIsArray });
const Number = objectFreeze({ isSafeInteger: numberIsSafeInteger });
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

export const PORTABLE_AUTHORITY_EVALUATION_VERSION =
  "continuity-authority-evaluation/0.2" as const;
export const PORTABLE_AUTHORIZATION_VERSION =
  "continuity-authorization/0.2" as const;
export const PORTABLE_INTENT_ADMISSION_VERSION =
  "continuity-intent-admission/0.2" as const;
export const PORTABLE_AUTHORIZATION_PROOF_VERSION =
  "continuity-authorization-proof/0.2" as const;
export const PORTABLE_RUNTIME_AUTHORIZATION_VERSION =
  "continuity-runtime-authorization/0.2" as const;
export const PORTABLE_ROOT_RECOGNITION_POLICY =
  "declared-principal-root/0.2" as const;

const MAX_IDENTIFIER_BYTES = 256;
const MAX_PROTOCOL_STRING_BYTES = 4_096;
const MAX_AUTHORITIES = 1_024;
const MAX_PATH_DEPTH = 32;
const MAX_REQUIRED_INTERSECTIONS = 32;
const MAX_SET_MEMBERS = 256;
const MAX_RESULT_EVIDENCE = 4_096;
const MAX_BIGINT = (1n << 256n) - 1n;
const SECP256K1_ORDER = bigintFrom(
  "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
);
const SECP256K1_FIELD = bigintFrom(
  "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
);
const MAX_LOW_S = bigintFrom(
  "0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
);
const SECP256K1_BASE_X = bigintFrom(
  "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
);
const SECP256K1_BASE_Y = bigintFrom(
  "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
);
const EIP191_HASH32_PREFIX = objectFreeze([
  0x19,
  0x45,
  0x74,
  0x68,
  0x65,
  0x72,
  0x65,
  0x75,
  0x6d,
  0x20,
  0x53,
  0x69,
  0x67,
  0x6e,
  0x65,
  0x64,
  0x20,
  0x4d,
  0x65,
  0x73,
  0x73,
  0x61,
  0x67,
  0x65,
  0x3a,
  0x0a,
  0x33,
  0x32,
]);
const UTF8_ENCODER = objectFreeze({ encode: utf8Encode });

export type PortableActionRequest = Readonly<{
  actorId: string;
  action: string;
  resource: string;
  claimedAt: number;
  amount?: bigint;
  counterpartyId?: string;
  termsCommitment?: ContentHash;
}>;

export type PortableConsequentialBinding = Readonly<{
  runtimeSessionId: string;
  credentialKeyId?: string;
  controlEpoch: number;
  roleId: string;
  roleTenureId: string;
  intentId?: string;
  nonce?: string;
  runtimeSignature?: `0x${string}`;
}>;

export type PortableAuthorityPathEvaluationInput = Readonly<{
  operationVersion: typeof PORTABLE_AUTHORITY_EVALUATION_VERSION;
  scope: Readonly<{
    domain: PortableAuthorizationDomain;
    policyVersion: string;
    rootRecognitionPolicy: typeof PORTABLE_ROOT_RECOGNITION_POLICY;
    historyHead: PortableHistoryHead;
    evaluationTime: number;
    recognizedRoots: readonly PortableRecognizedRoot[];
    globalPolicySourceId: string;
  }>;
  request: PortableActionRequest;
  permissions: readonly PortablePermissionGrant[];
  prohibitions: readonly PortableProhibitionGrant[];
  authorityEvidence: readonly PortableAuthorityEvidence[];
  revokedAuthorityIds: readonly string[];
  usage: readonly PortableAuthorityUsage[];
}>;

export type PortableAuthorizeInput = Readonly<{
  operationVersion: typeof PORTABLE_AUTHORIZATION_VERSION;
  events: readonly AcceptedCanonicalEventShape[];
  expectedHistoryHead: PortableHistoryHead;
  domain: PortableAuthorizationDomain;
  policyVersion: string;
  rootRecognitionPolicy: typeof PORTABLE_ROOT_RECOGNITION_POLICY;
  request: PortableActionRequest;
  evaluationTime: number;
  authoritative: true;
  consequential: boolean;
  binding?: PortableConsequentialBinding;
}>;

/**
 * Package-internal replay projection consumed by deterministic authority
 * evaluation. The lower engine deliberately depends on replay types only;
 * replay-state provenance remains the responsibility of its outer caller.
 */
export type PortableAuthorityReplayState = Readonly<{
  events: readonly AcceptedCanonicalEventShape[];
  eventHistoryHashes: readonly ContentHash[];
  head: PortableHistoryHead;
  genesis: PortableGenesisRecord;
  principals: ReadonlyMap<string, PortablePrincipalRecord>;
  agents: ReadonlyMap<string, PortableAgentRecord>;
  roles: ReadonlyMap<string, PortableRoleRecord>;
  tenures: ReadonlyMap<string, PortableRoleTenureRecord>;
  runtimeSessions: ReadonlyMap<string, PortableRuntimeSessionRecord>;
  intentDeclarations: ReadonlyMap<string, PortableIntentDeclarationRecord>;
  intentAdmissions: ReadonlyMap<string, PortableIntentAdmissionRecord>;
  nonceReservationsByActor: ReadonlyMap<
    string,
    ReadonlyMap<string, PortableNonceReservation>
  >;
  authorities: ReadonlyMap<string, PortableAuthorityRecord>;
  recognizedRoots: ReadonlyMap<string, PortableRecognizedRoot>;
  authorityUsage: ReadonlyMap<string, PortableAuthorityUsage>;
}>;

/** Event-specific requirements derived by replay from the exact prior state. */
export type PortableAdministrativeRequirements = Readonly<{
  request: PortableActionRequest;
  requiredPrincipalId: string;
  requiredAuthorityIds: readonly string[];
  roleId: string;
  roleTenureId: string;
}>;

export type PortableEvidenceReference = Readonly<{
  kind: "EVENT";
  eventId: string;
  eventType: CoreEventType;
  position: number;
  historyHash: ContentHash;
}>;

export type PortableIntersectionProof = Readonly<{
  requiredAuthorityId: string;
  requiredByAuthorityIds: readonly string[];
  recognizedRoot: PortableRecognizedRoot;
  path: readonly PortablePermissionGrant[];
  effectiveConstraints: PortableAuthorityConstraints;
}>;

export type PortableAuthorizationProof = Readonly<{
  proofVersion: typeof PORTABLE_AUTHORIZATION_PROOF_VERSION;
  domain: PortableAuthorizationDomain;
  policyVersion: string;
  rootRecognitionPolicy: typeof PORTABLE_ROOT_RECOGNITION_POLICY;
  historyHead: PortableHistoryHead;
  evaluationTime: number;
  request: PortableActionRequest;
  recognizedRoot: PortableRecognizedRoot;
  permissionPath: readonly PortablePermissionGrant[];
  intersections: readonly PortableIntersectionProof[];
  effectiveConstraints: PortableAuthorityConstraints;
  controllingAuthorityIds: readonly string[];
  usageSnapshot: readonly PortableAuthorityUsage[];
  authorityEvidence: readonly PortableAuthorityEvidence[];
  checkedProhibitionIds: readonly string[];
  consequential: boolean;
  runtimeSessionId?: string;
  credentialKeyId?: string;
  controlEpoch?: number;
  roleId?: string;
  roleTenureId?: string;
  intentId?: string;
  nonce?: string;
}>;

export type PortableDenialCode =
  | "DOMAIN_MISMATCH"
  | "POLICY_MISMATCH"
  | "INVALID_REQUEST"
  | "INVALID_AMOUNT"
  | "INVALID_DELEGATION"
  | "AGENT_INACTIVE"
  | "SESSION_NOT_FOUND"
  | "SESSION_EXPIRED"
  | "SESSION_CREDENTIAL_REQUIRED"
  | "SESSION_CREDENTIAL_INVALID"
  | "SESSION_FENCED"
  | "STALE_EPOCH"
  | "ROLE_TENURE_NOT_CURRENT"
  | "INTENT_REQUIRED"
  | "INTENT_NOT_DECLARED"
  | "INTENT_MISMATCH"
  | "INTENT_REPLAY"
  | "NONCE_ALREADY_ADMITTED"
  | "PROHIBITED"
  | "REVOKED"
  | "NOT_YET_VALID"
  | "EXPIRED"
  | "MISSING_INTERSECTION"
  | "ACTION_NOT_ALLOWED"
  | "RESOURCE_NOT_ALLOWED"
  | "AMOUNT_REQUIRED"
  | "AMOUNT_EXCEEDED"
  | "CUMULATIVE_AMOUNT_EXCEEDED"
  | "TRANSACTION_COUNT_EXCEEDED"
  | "NO_AUTHORITY";

export type PortableIndeterminateCode =
  | "INVALID_INPUT"
  | "UNSUPPORTED_VERSION"
  | "OUTPUT_LIMIT_EXCEEDED"
  | "STATE_NOT_AUTHORITATIVE"
  | "CAUSAL_TIME_INVALID"
  | "HISTORY_RELATION_UNVERIFIED"
  | "EVIDENCE_UNAVAILABLE"
  | "EVIDENCE_DISPUTED";

export type PortableDenialEvidence = Readonly<{
  code: PortableDenialCode;
  subjectId?: string;
  rootAuthorityId?: string;
  terminalAuthorityId?: string;
  failingAuthorityId?: string;
  authorityPathIds: readonly string[];
  evidence: readonly PortableEvidenceReference[];
}>;

export type PortableIndeterminateEvidence = Readonly<{
  code: PortableIndeterminateCode;
  subjectId?: string;
  evidence: readonly PortableEvidenceReference[];
}>;

export type PortableAuthorizationResult =
  | Readonly<{
      operationVersion:
        | typeof PORTABLE_AUTHORITY_EVALUATION_VERSION
        | typeof PORTABLE_AUTHORIZATION_VERSION;
      decision: "ALLOW";
      scopeAssurance: "SUPPLIED_SCOPE" | "REPLAY_VERIFIED";
      consequential: boolean;
      proof: PortableAuthorizationProof;
    }>
  | Readonly<{
      operationVersion:
        | typeof PORTABLE_AUTHORITY_EVALUATION_VERSION
        | typeof PORTABLE_AUTHORIZATION_VERSION;
      decision: "DENY";
      scopeAssurance: "SUPPLIED_SCOPE" | "REPLAY_VERIFIED";
      consequential: false;
      code: PortableDenialCode;
      failures: readonly PortableDenialEvidence[];
    }>
  | Readonly<{
      operationVersion:
        | typeof PORTABLE_AUTHORITY_EVALUATION_VERSION
        | typeof PORTABLE_AUTHORIZATION_VERSION;
      decision: "INDETERMINATE";
      scopeAssurance: "SUPPLIED_SCOPE" | "REPLAY_VERIFIED";
      consequential: false;
      code: PortableIndeterminateCode;
      failures: readonly PortableIndeterminateEvidence[];
    }>;

export type PortableRuntimeAuthorizationChallenge = Readonly<{
  version: typeof PORTABLE_RUNTIME_AUTHORIZATION_VERSION;
  domain: PortableAuthorizationDomain;
  request: PortableActionRequest;
  authoritative: true;
  consequential: true;
  evaluationTime: number;
  policyVersion: string;
  rootRecognitionPolicy: typeof PORTABLE_ROOT_RECOGNITION_POLICY;
  eventHistoryHash: ContentHash;
  eventHistoryPosition: number;
  runtimeSessionId: string;
  credentialKeyId: string;
  controlEpoch: number;
  roleId: string;
  roleTenureId: string;
  intentId: string;
  nonce: string;
}>;

const ownOptional = <T extends object, K extends keyof T>(
  value: T,
  key: K,
): T[K] | undefined => Object.hasOwn(value, key) ? value[key] : undefined;

const frozenArray = <T>(source: readonly T[]): readonly T[] =>
  Object.freeze(copyArray(source));

const isPlainRecord = (value: unknown): value is Record<string, unknown> => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Reflect.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
};

const boundedUtf8 = (value: string, maximum: number): boolean =>
  value.length <= maximum &&
  isWellFormedUnicode(value) &&
  uint8ArrayLength(UTF8_ENCODER.encode(value)) <= maximum;

const isIdentifier = (value: unknown): value is string =>
  typeof value === "string" &&
  value.length > 0 &&
  boundedUtf8(value, MAX_IDENTIFIER_BYTES) &&
  !regExpTest(/[\u0000-\u001f\u007f]/u, value);

const isU53 = (value: unknown): value is number =>
  typeof value === "number" &&
  Number.isSafeInteger(value) &&
  value >= 0 &&
  !Object.is(value, -0);

const isAmount = (value: unknown): value is bigint =>
  typeof value === "bigint" && value >= 0n && value <= MAX_BIGINT;

const isContentHash = (value: unknown): value is ContentHash =>
  typeof value === "string" && regExpTest(/^0x[0-9a-f]{64}$/, value);

const isEthereumAddress = (value: unknown): value is string =>
  typeof value === "string" && regExpTest(/^0x[0-9a-fA-F]{40}$/, value);

const isChainId = (value: unknown): value is string => {
  if (typeof value !== "string" || !regExpTest(/^[1-9][0-9]*$/, value)) {
    return false;
  }
  const parsed = bigintFrom(value);
  return parsed >= 1n && parsed <= MAX_BIGINT;
};

const isSignature65 = (value: unknown): value is `0x${string}` => {
  if (typeof value !== "string" || !regExpTest(/^0x[0-9a-f]{130}$/, value)) {
    return false;
  }
  const r = bigintFrom(`0x${stringSlice(value, 2, 66)}`);
  const s = bigintFrom(`0x${stringSlice(value, 66, 130)}`);
  const recovery = stringSlice(value, 130, 132);
  return r > 0n &&
    r < SECP256K1_ORDER &&
    s > 0n &&
    s <= MAX_LOW_S &&
    (recovery === "1b" || recovery === "1c");
};

type AuthorityOperationVersion =
  | typeof PORTABLE_AUTHORITY_EVALUATION_VERSION
  | typeof PORTABLE_AUTHORIZATION_VERSION;

const resultVersionForKind = (
  kind: PortableAuthorityCaptureKind,
): AuthorityOperationVersion =>
  kind === "AUTHORITY_PATH_EVALUATION"
    ? PORTABLE_AUTHORITY_EVALUATION_VERSION
    : PORTABLE_AUTHORIZATION_VERSION;

const expectedInputVersionForKind = (
  kind: PortableAuthorityCaptureKind,
): string =>
  kind === "AUTHORITY_PATH_EVALUATION"
    ? PORTABLE_AUTHORITY_EVALUATION_VERSION
    : kind === "AUTHORIZE"
      ? PORTABLE_AUTHORIZATION_VERSION
      : PORTABLE_INTENT_ADMISSION_VERSION;

const requiredOuterKeys = (
  kind: PortableAuthorityCaptureKind,
): readonly string[] => kind === "AUTHORITY_PATH_EVALUATION"
  ? Object.freeze([
      "operationVersion",
      "scope",
      "request",
      "permissions",
      "prohibitions",
      "authorityEvidence",
      "revokedAuthorityIds",
      "usage",
    ])
  : kind === "AUTHORIZE"
    ? Object.freeze([
        "operationVersion",
        "events",
        "expectedHistoryHead",
        "domain",
        "policyVersion",
        "rootRecognitionPolicy",
        "request",
        "evaluationTime",
        "authoritative",
        "consequential",
      ])
    : Object.freeze([
        "operationVersion",
        "events",
        "expectedHistoryHead",
        "admissionEventId",
        "domain",
        "policyVersion",
        "request",
        "evaluationTime",
        "binding",
      ]);

const optionalOuterKeys = (
  kind: PortableAuthorityCaptureKind,
): readonly string[] => kind === "AUTHORIZE" ? Object.freeze(["binding"]) : Object.freeze([]);

const descriptorValue = (source: object, key: string): unknown => {
  const descriptor = Reflect.getOwnPropertyDescriptor(source, key);
  if (descriptor === undefined) {
    throw new TypeError(`Portable authority input lost field ${key}.`);
  }
  if (Object.hasOwn(descriptor, "value")) return descriptor.value;
  const getter = ownOptional(descriptor, "get");
  return getter === undefined ? undefined : Reflect.apply(getter, source, []);
};

type OuterAuthorityCapture =
  | Readonly<{ status: "INVALID_INPUT" }>
  | Readonly<{ status: "UNSUPPORTED_VERSION" }>
  | Readonly<{ status: "CAPTURED"; source: object; body: Record<string, unknown> }>;

const captureAuthorityOuter = (
  input: unknown,
  kind: PortableAuthorityCaptureKind,
): OuterAuthorityCapture => {
  if (!isPlainRecord(input)) {
    throw new TypeError("Portable authority input must be a plain record.");
  }
  const keys = Reflect.ownKeys(input);
  for (let index = 0; index < keys.length; index += 1) {
    if (typeof keys[index] !== "string") {
      throw new TypeError("Portable authority input has a symbol key.");
    }
  }
  if (!arrayIncludes(keys, "operationVersion")) {
    return Object.freeze({ status: "INVALID_INPUT" });
  }
  const operationVersion = descriptorValue(input, "operationVersion");
  if (typeof operationVersion !== "string" || !boundedUtf8(operationVersion, MAX_PROTOCOL_STRING_BYTES)) {
    return Object.freeze({ status: "INVALID_INPUT" });
  }
  if (operationVersion !== expectedInputVersionForKind(kind)) {
    return Object.freeze({ status: "UNSUPPORTED_VERSION" });
  }
  const required = requiredOuterKeys(kind);
  const optional = optionalOuterKeys(kind);
  if (keys.length < required.length || keys.length > required.length + optional.length) {
    return Object.freeze({ status: "INVALID_INPUT" });
  }
  for (let index = 0; index < required.length; index += 1) {
    if (!arrayIncludes(keys, required[index]!)) {
      return Object.freeze({ status: "INVALID_INPUT" });
    }
  }
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index] as string;
    if (!arrayIncludes(required, key) && !arrayIncludes(optional, key)) {
      return Object.freeze({ status: "INVALID_INPUT" });
    }
  }
  const body = Object.create(null) as Record<string, unknown>;
  Object.defineDataProperty(body, "operationVersion", operationVersion, false, true);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index] as string;
    if (key === "operationVersion") continue;
    const value = descriptorValue(input, key);
    if (value === undefined) {
      if (arrayIncludes(optional, key)) continue;
      return Object.freeze({ status: "INVALID_INPUT" });
    }
    Object.defineDataProperty(body, key, value, false, true);
  }
  Object.freeze(body);
  return Object.freeze({ status: "CAPTURED", source: input, body });
};

export type CapturedPortableAuthorityInput =
  CapturedCanonicalAuthorityOperation<Record<string, unknown>>;

const indeterminate = (
  operationVersion: AuthorityOperationVersion,
  code: PortableIndeterminateCode,
  assurance: "SUPPLIED_SCOPE" | "REPLAY_VERIFIED" = "SUPPLIED_SCOPE",
  evidence: readonly PortableEvidenceReference[] = Object.freeze([]),
  subjectId?: string,
): PortableAuthorizationResult => Object.freeze({
  operationVersion,
  decision: "INDETERMINATE" as const,
  scopeAssurance: assurance,
  consequential: false as const,
  code,
  failures: Object.freeze([
    Object.freeze({
      code,
      ...(subjectId === undefined ? {} : { subjectId }),
      evidence,
    }),
  ]),
});

export type PortableAuthorityOperationCapture =
  | Readonly<{ status: "INVALID_INPUT" }>
  | Readonly<{ status: "UNSUPPORTED_VERSION" }>
  | Readonly<{ status: "STATE_NOT_AUTHORITATIVE" }>
  | Readonly<{
      status: "CAPTURED";
      capture: CapturedPortableAuthorityInput;
    }>;

/**
 * One-graph caller capture shared by the raw, replay-bound, and admission
 * façades. Replay supplies its own visitor, so this lower engine never imports
 * replay runtime code.
 */
export const capturePortableAuthorityOperation = (
  input: unknown,
  kind: PortableAuthorityCaptureKind,
  replayVisitor?: (
    capturedEvent: CapturedCanonicalReplayEvent,
  ) => CanonicalReplayCaptureVisitDecision<never>,
): PortableAuthorityOperationCapture => {
  const outer = captureAuthorityOuter(input, kind);
  if (outer.status === "INVALID_INPUT") {
    return Object.freeze({ status: "INVALID_INPUT" as const });
  }
  if (outer.status === "UNSUPPORTED_VERSION") {
    return Object.freeze({ status: "UNSUPPORTED_VERSION" as const });
  }
  const captured = captureBoundedCanonicalAuthorityOperationIncrementally(
    outer.body,
    outer.source,
    kind,
    replayVisitor,
  );
  if (captured.status === "STOPPED") {
    throw new TypeError("Portable authority replay capture stopped unexpectedly.");
  }
  if (captured.status === "CAPTURE_FAILED") {
    if (getCanonicalCaptureLimitErrorMetadata(captured.error) !== undefined) {
      return Object.freeze({ status: "INVALID_INPUT" as const });
    }
    if (
      kind !== "AUTHORITY_PATH_EVALUATION" &&
      isCanonicalReplaySchemaFailure(captured.error)
    ) {
      return Object.freeze({ status: "STATE_NOT_AUTHORITATIVE" as const });
    }
    throw captured.error;
  }
  if (!isCapturedCanonicalAuthorityOperation(captured.capture)) {
    throw new TypeError("Portable authority capture lost provenance.");
  }
  return Object.freeze({
    status: "CAPTURED" as const,
    capture: captured.capture,
  });
};

const exactRecord = (
  capture: CapturedPortableAuthorityInput,
  value: unknown,
  required: readonly string[],
  optional: readonly string[] = Object.freeze([]),
): value is Record<string, unknown> => {
  if (!isPlainRecord(value)) return false;
  const keys = capture.capturedRecordKeys(value);
  if (
    keys === undefined ||
    keys.length < required.length ||
    keys.length > required.length + optional.length
  ) return false;
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index]!;
    if (!arrayIncludes(required, key) && !arrayIncludes(optional, key)) return false;
    if (arrayIncludes(required, key) && !Object.hasOwn(value, key)) return false;
  }
  for (let index = 0; index < required.length; index += 1) {
    if (!Object.hasOwn(value, required[index]!)) return false;
  }
  return true;
};

type ValidationStatus = "VALID" | "INVALID" | "LIMIT";

const identifierStatus = (value: unknown): ValidationStatus => {
  if (typeof value !== "string") return "INVALID";
  if (!boundedUtf8(value, MAX_IDENTIFIER_BYTES)) {
    return value.length > MAX_IDENTIFIER_BYTES ||
      (isWellFormedUnicode(value) &&
        uint8ArrayLength(UTF8_ENCODER.encode(value)) > MAX_IDENTIFIER_BYTES)
      ? "LIMIT"
      : "INVALID";
  }
  return value.length > 0 && !regExpTest(/[\u0000-\u001f\u007f]/u, value)
    ? "VALID"
    : "INVALID";
};

const amountStatus = (value: unknown): ValidationStatus =>
  typeof value === "bigint" && (value < -MAX_BIGINT || value > MAX_BIGINT)
    ? "LIMIT"
    : isAmount(value)
      ? "VALID"
      : "INVALID";

const mergeStatus = (
  left: ValidationStatus,
  right: ValidationStatus,
): ValidationStatus => left === "LIMIT" || right === "LIMIT"
  ? "LIMIT"
  : left === "INVALID" || right === "INVALID"
    ? "INVALID"
    : "VALID";

const identifierListStatus = (
  value: unknown,
  maximum: number,
  nonempty = false,
): ValidationStatus => {
  if (!Array.isArray(value)) return "INVALID";
  if (value.length > maximum) return "LIMIT";
  if (nonempty && value.length === 0) return "INVALID";
  const seen = createSet<string>();
  let status: ValidationStatus = "VALID";
  for (let index = 0; index < value.length; index += 1) {
    const memberStatus = identifierStatus(value[index]);
    status = mergeStatus(status, memberStatus);
    if (memberStatus === "VALID") {
      const member = value[index] as string;
      if (setHas(seen, member)) status = mergeStatus(status, "INVALID");
      setAdd(seen, member);
    }
  }
  return status;
};

const domainIsValid = (
  capture: CapturedPortableAuthorityInput,
  value: unknown,
): value is PortableAuthorizationDomain => exactRecord(
  capture,
  value,
  Object.freeze([
    "protocol",
    "version",
    "deploymentId",
    "chainId",
    "verifyingContract",
  ]),
) &&
  value.protocol === "continuity" &&
  value.version === "0.2" &&
  isIdentifier(value.deploymentId) &&
  isChainId(value.chainId) &&
  isEthereumAddress(value.verifyingContract);

const historyHeadIsValid = (
  capture: CapturedPortableAuthorityInput,
  value: unknown,
): value is PortableHistoryHead => exactRecord(
  capture,
  value,
  Object.freeze(["hash", "position", "canonicalTime"]),
) &&
  isContentHash(value.hash) &&
  isU53(value.position) &&
  isU53(value.canonicalTime);

const requestHasExactShape = (
  capture: CapturedPortableAuthorityInput,
  value: unknown,
): value is Record<string, unknown> => exactRecord(
  capture,
  value,
  Object.freeze(["actorId", "action", "resource", "claimedAt"]),
  Object.freeze(["amount", "counterpartyId", "termsCommitment"]),
);

const requestProblem = (
  request: Record<string, unknown>,
): "INVALID_REQUEST" | "INVALID_AMOUNT" | undefined => {
  if (
    !isIdentifier(request.actorId) ||
    !isIdentifier(request.action) ||
    !isIdentifier(request.resource) ||
    !isU53(request.claimedAt) ||
    (Object.hasOwn(request, "counterpartyId") &&
      !isIdentifier(request.counterpartyId)) ||
    (Object.hasOwn(request, "termsCommitment") &&
      !isContentHash(request.termsCommitment))
  ) return "INVALID_REQUEST";
  if (Object.hasOwn(request, "amount") && !isAmount(request.amount)) {
    return "INVALID_AMOUNT";
  }
  return undefined;
};

const bindingIsStructurallyValid = (
  capture: CapturedPortableAuthorityInput,
  value: unknown,
): value is PortableConsequentialBinding => {
  if (!exactRecord(
    capture,
    value,
    Object.freeze([
      "runtimeSessionId",
      "controlEpoch",
      "roleId",
      "roleTenureId",
    ]),
    Object.freeze([
      "credentialKeyId",
      "intentId",
      "nonce",
      "runtimeSignature",
    ]),
  )) return false;
  return isIdentifier(value.runtimeSessionId) &&
    isU53(value.controlEpoch) &&
    isIdentifier(value.roleId) &&
    isIdentifier(value.roleTenureId) &&
    (!Object.hasOwn(value, "credentialKeyId") || isIdentifier(value.credentialKeyId)) &&
    (!Object.hasOwn(value, "intentId") || isIdentifier(value.intentId)) &&
    (!Object.hasOwn(value, "nonce") || isIdentifier(value.nonce)) &&
    (!Object.hasOwn(value, "runtimeSignature") || isSignature65(value.runtimeSignature));
};

const constraintsStatus = (
  capture: CapturedPortableAuthorityInput,
  value: unknown,
): ValidationStatus => {
  if (!exactRecord(
    capture,
    value,
    Object.freeze([
      "actions",
      "resources",
      "quantitative",
      "maxDelegationDepth",
      "requiredIntersectionIds",
    ]),
    Object.freeze([
      "notBefore",
      "expiresAt",
      "maxAmount",
      "maxCumulativeAmount",
      "maxTransactions",
    ]),
  )) return "INVALID";
  let status = mergeStatus(
    identifierListStatus(value.actions, MAX_SET_MEMBERS, true),
    identifierListStatus(value.resources, MAX_SET_MEMBERS, true),
  );
  status = mergeStatus(
    status,
    identifierListStatus(
      value.requiredIntersectionIds,
      MAX_REQUIRED_INTERSECTIONS,
    ),
  );
  if (typeof value.quantitative !== "boolean" || !isU53(value.maxDelegationDepth)) {
    status = mergeStatus(status, "INVALID");
  }
  if (Object.hasOwn(value, "notBefore") && !isU53(value.notBefore)) {
    status = mergeStatus(status, "INVALID");
  }
  if (Object.hasOwn(value, "expiresAt") && !isU53(value.expiresAt)) {
    status = mergeStatus(status, "INVALID");
  }
  if (Object.hasOwn(value, "maxTransactions") && !isU53(value.maxTransactions)) {
    status = mergeStatus(status, "INVALID");
  }
  if (Object.hasOwn(value, "maxAmount")) {
    status = mergeStatus(status, amountStatus(value.maxAmount));
  }
  if (Object.hasOwn(value, "maxCumulativeAmount")) {
    status = mergeStatus(status, amountStatus(value.maxCumulativeAmount));
  }
  if (
    value.quantitative === false &&
    (Object.hasOwn(value, "maxAmount") || Object.hasOwn(value, "maxCumulativeAmount"))
  ) status = mergeStatus(status, "INVALID");
  const notBefore = ownOptional(value, "notBefore");
  const expiresAt = ownOptional(value, "expiresAt");
  if (
    isU53(notBefore) &&
    isU53(expiresAt) &&
    notBefore >= expiresAt
  ) status = mergeStatus(status, "INVALID");
  return status;
};

const permissionStatus = (
  capture: CapturedPortableAuthorityInput,
  value: unknown,
): ValidationStatus => {
  if (!exactRecord(
    capture,
    value,
    Object.freeze([
      "kind",
      "authorityId",
      "grantorId",
      "granteeId",
      "rootAuthorityId",
      "independent",
      "constraints",
    ]),
    Object.freeze(["parentAuthorityId"]),
  )) return "INVALID";
  let status: ValidationStatus = value.kind === "PERMISSION" &&
    typeof value.independent === "boolean" ? "VALID" : "INVALID";
  status = mergeStatus(status, identifierStatus(value.authorityId));
  status = mergeStatus(status, identifierStatus(value.grantorId));
  status = mergeStatus(status, identifierStatus(value.granteeId));
  status = mergeStatus(status, identifierStatus(value.rootAuthorityId));
  if (Object.hasOwn(value, "parentAuthorityId")) {
    status = mergeStatus(status, identifierStatus(value.parentAuthorityId));
  }
  return mergeStatus(status, constraintsStatus(capture, value.constraints));
};

const prohibitionStatus = (
  capture: CapturedPortableAuthorityInput,
  value: unknown,
): ValidationStatus => {
  if (!isPlainRecord(value) || value.kind !== "PROHIBITION") return "INVALID";
  const root = value.scope === "ROOT";
  const global = value.scope === "GLOBAL";
  if (!root && !global) return "INVALID";
  if (!exactRecord(
    capture,
    value,
    root
      ? Object.freeze([
          "kind",
          "scope",
          "authorityId",
          "grantorId",
          "rootAuthorityId",
          "constraints",
        ])
      : Object.freeze([
          "kind",
          "scope",
          "authorityId",
          "grantorId",
          "constraints",
        ]),
    root
      ? Object.freeze(["subjectActorId", "parentAuthorityId"])
      : Object.freeze(["subjectActorId"]),
  )) return "INVALID";
  let status = mergeStatus(
    identifierStatus(value.authorityId),
    identifierStatus(value.grantorId),
  );
  if (root) status = mergeStatus(status, identifierStatus(value.rootAuthorityId));
  if (Object.hasOwn(value, "subjectActorId")) {
    status = mergeStatus(status, identifierStatus(value.subjectActorId));
  }
  if (Object.hasOwn(value, "parentAuthorityId")) {
    status = mergeStatus(status, identifierStatus(value.parentAuthorityId));
  }
  status = mergeStatus(status, constraintsStatus(capture, value.constraints));
  if (status === "VALID") {
    const constraints = value.constraints as unknown as PortableAuthorityConstraints;
    if (
      constraints.requiredIntersectionIds.length !== 0 ||
      constraints.maxDelegationDepth !== 0 ||
      ownOptional(constraints, "maxCumulativeAmount") !== undefined ||
      ownOptional(constraints, "maxTransactions") !== undefined
    ) status = "INVALID";
  }
  return status;
};

const recognizedRootStatus = (
  capture: CapturedPortableAuthorityInput,
  value: unknown,
): ValidationStatus => {
  if (!exactRecord(
    capture,
    value,
    Object.freeze([
      "rootAuthorityId",
      "principalId",
      "principalRecognitionEventId",
      "rootGrantEventId",
    ]),
  )) return "INVALID";
  let status = mergeStatus(
    identifierStatus(value.rootAuthorityId),
    identifierStatus(value.principalId),
  );
  status = mergeStatus(
    status,
    identifierStatus(value.principalRecognitionEventId),
  );
  status = mergeStatus(status, identifierStatus(value.rootGrantEventId));
  return status;
};

const authorityEvidenceStatus = (
  capture: CapturedPortableAuthorityInput,
  value: unknown,
): ValidationStatus => {
  if (!exactRecord(
    capture,
    value,
    Object.freeze(["authorityId", "grantEventId", "grantEventPosition"]),
  )) return "INVALID";
  return mergeStatus(
    mergeStatus(
      identifierStatus(value.authorityId),
      identifierStatus(value.grantEventId),
    ),
    isU53(value.grantEventPosition) ? "VALID" : "INVALID",
  );
};

const authorityUsageStatus = (
  capture: CapturedPortableAuthorityInput,
  value: unknown,
): ValidationStatus => {
  if (!exactRecord(
    capture,
    value,
    Object.freeze([
      "authorityId",
      "admittedTransactionCount",
      "admittedCumulativeAmount",
    ]),
  )) return "INVALID";
  return mergeStatus(
    mergeStatus(
      identifierStatus(value.authorityId),
      isU53(value.admittedTransactionCount) ? "VALID" : "INVALID",
    ),
    amountStatus(value.admittedCumulativeAmount),
  );
};

const sameDomain = (
  left: PortableAuthorizationDomain,
  right: PortableAuthorizationDomain,
): boolean => left.protocol === right.protocol &&
  left.version === right.version &&
  left.deploymentId === right.deploymentId &&
  left.chainId === right.chainId &&
  stringToLowerCase(left.verifyingContract) ===
    stringToLowerCase(right.verifyingContract);

const sameHistoryHead = (
  left: PortableHistoryHead,
  right: PortableHistoryHead,
): boolean => left.hash === right.hash &&
  left.position === right.position &&
  left.canonicalTime === right.canonicalTime;

const sortedIdentifiers = (values: readonly string[]): readonly string[] => {
  const copy = copyArray(values);
  arraySort(copy, compareProtocolStrings);
  return Object.freeze(copy);
};

const compareIdentifierSequences = (
  left: readonly string[],
  right: readonly string[],
): number => {
  const shared = left.length < right.length ? left.length : right.length;
  for (let index = 0; index < shared; index += 1) {
    const comparison = compareProtocolStrings(left[index]!, right[index]!);
    if (comparison !== 0) return comparison;
  }
  return left.length < right.length ? -1 : left.length > right.length ? 1 : 0;
};

const identifierSubset = (
  child: readonly string[],
  parent: readonly string[],
): boolean => {
  for (let index = 0; index < child.length; index += 1) {
    if (!arrayIncludes(parent, child[index]!)) return false;
  }
  return true;
};

const normalizedConstraints = (
  constraints: PortableAuthorityConstraints,
): PortableAuthorityConstraints => Object.freeze({
  actions: sortedIdentifiers(constraints.actions),
  resources: sortedIdentifiers(constraints.resources),
  quantitative: constraints.quantitative,
  ...(ownOptional(constraints, "notBefore") === undefined
    ? {}
    : { notBefore: constraints.notBefore }),
  ...(ownOptional(constraints, "expiresAt") === undefined
    ? {}
    : { expiresAt: constraints.expiresAt }),
  ...(ownOptional(constraints, "maxAmount") === undefined
    ? {}
    : { maxAmount: constraints.maxAmount }),
  ...(ownOptional(constraints, "maxCumulativeAmount") === undefined
    ? {}
    : { maxCumulativeAmount: constraints.maxCumulativeAmount }),
  ...(ownOptional(constraints, "maxTransactions") === undefined
    ? {}
    : { maxTransactions: constraints.maxTransactions }),
  maxDelegationDepth: constraints.maxDelegationDepth,
  requiredIntersectionIds: sortedIdentifiers(
    constraints.requiredIntersectionIds,
  ),
});

const normalizedPermission = (
  grant: PortablePermissionGrant,
): PortablePermissionGrant => Object.freeze({
  kind: "PERMISSION" as const,
  authorityId: grant.authorityId,
  grantorId: grant.grantorId,
  granteeId: grant.granteeId,
  rootAuthorityId: grant.rootAuthorityId,
  ...(ownOptional(grant, "parentAuthorityId") === undefined
    ? {}
    : { parentAuthorityId: grant.parentAuthorityId }),
  independent: grant.independent,
  constraints: normalizedConstraints(grant.constraints),
});

const normalizedProhibition = (
  grant: PortableProhibitionGrant,
): PortableProhibitionGrant => grant.scope === "GLOBAL"
  ? Object.freeze({
      kind: "PROHIBITION" as const,
      scope: "GLOBAL" as const,
      authorityId: grant.authorityId,
      grantorId: grant.grantorId,
      ...(ownOptional(grant, "subjectActorId") === undefined
        ? {}
        : { subjectActorId: grant.subjectActorId }),
      constraints: normalizedConstraints(grant.constraints),
    })
  : Object.freeze({
      kind: "PROHIBITION" as const,
      scope: "ROOT" as const,
      authorityId: grant.authorityId,
      grantorId: grant.grantorId,
      ...(ownOptional(grant, "subjectActorId") === undefined
        ? {}
        : { subjectActorId: grant.subjectActorId }),
      rootAuthorityId: grant.rootAuthorityId,
      ...(ownOptional(grant, "parentAuthorityId") === undefined
        ? {}
        : { parentAuthorityId: grant.parentAuthorityId }),
      constraints: normalizedConstraints(grant.constraints),
    });

const constraintsAreAttenuated = (
  parent: PortableAuthorityConstraints,
  child: PortableAuthorityConstraints,
): boolean => {
  if (
    !identifierSubset(child.actions, parent.actions) ||
    !identifierSubset(child.resources, parent.resources) ||
    !identifierSubset(
      parent.requiredIntersectionIds,
      child.requiredIntersectionIds,
    ) ||
    parent.maxDelegationDepth === 0 ||
    child.maxDelegationDepth > parent.maxDelegationDepth - 1 ||
    (parent.quantitative && !child.quantitative)
  ) return false;
  const parentNotBefore = ownOptional(parent, "notBefore");
  const childNotBefore = ownOptional(child, "notBefore");
  if (
    parentNotBefore !== undefined &&
    (childNotBefore === undefined || childNotBefore < parentNotBefore)
  ) return false;
  const parentExpiresAt = ownOptional(parent, "expiresAt");
  const childExpiresAt = ownOptional(child, "expiresAt");
  if (
    parentExpiresAt !== undefined &&
    (childExpiresAt === undefined || childExpiresAt > parentExpiresAt)
  ) return false;
  const parentMaxAmount = ownOptional(parent, "maxAmount");
  const childMaxAmount = ownOptional(child, "maxAmount");
  if (
    parentMaxAmount !== undefined &&
    (childMaxAmount === undefined || childMaxAmount > parentMaxAmount)
  ) return false;
  const parentMaxCumulative = ownOptional(parent, "maxCumulativeAmount");
  const childMaxCumulative = ownOptional(child, "maxCumulativeAmount");
  if (
    parentMaxCumulative !== undefined &&
    (childMaxCumulative === undefined || childMaxCumulative > parentMaxCumulative)
  ) return false;
  const parentMaxTransactions = ownOptional(parent, "maxTransactions");
  const childMaxTransactions = ownOptional(child, "maxTransactions");
  return parentMaxTransactions === undefined ||
    (childMaxTransactions !== undefined &&
      childMaxTransactions <= parentMaxTransactions);
};

type AuthorityCorpus = Readonly<{
  permissions: ReadonlyMap<string, PortablePermissionGrant>;
  prohibitions: ReadonlyMap<string, PortableProhibitionGrant>;
  roots: ReadonlyMap<string, PortableRecognizedRoot>;
  evidence: ReadonlyMap<string, PortableAuthorityEvidence>;
  revoked: ReadonlySet<string>;
  usage: ReadonlyMap<string, PortableAuthorityUsage>;
  globalPolicySourceId: string;
  replayAgents?: ReadonlyMap<string, PortableAgentRecord>;
  replayPrincipals?: ReadonlyMap<string, PortablePrincipalRecord>;
  replayRecords?: ReadonlyMap<string, PortableAuthorityRecord>;
}>;

type PermissionPath = Readonly<{
  rootAuthorityId: string;
  grants: readonly PortablePermissionGrant[];
  authorityIds: readonly string[];
  effectivelyIndependent: boolean;
}>;

type ValidatedCorpus = Readonly<{
  corpus: AuthorityCorpus;
  paths: ReadonlyMap<string, PermissionPath>;
}>;

type CorpusConstruction =
  | Readonly<{ status: "INVALID_INPUT" }>
  | Readonly<{ status: "INVALID_DELEGATION" }>
  | Readonly<{ status: "VALID"; corpus: AuthorityCorpus }>;

type CorpusValidation =
  | Readonly<{ status: "INVALID_INPUT" }>
  | Readonly<{ status: "INVALID_DELEGATION" }>
  | Readonly<{ status: "VALID"; value: ValidatedCorpus }>;

const addUniqueByIdentifier = <T>(
  target: Map<string, T>,
  identifier: string,
  value: T,
): boolean => {
  if (mapHas(target, identifier)) return false;
  mapSet(target, identifier, value);
  return true;
};

const hasCapturedIdentifierDuplicate = (
  values: readonly unknown[],
  field?: string,
): boolean => {
  const seen = createSet<string>();
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    const identifier = field === undefined
      ? value
      : isPlainRecord(value) ? ownOptional(value, field) : undefined;
    // Another malformed field must not hide a duplicate protocol identity.
    // A malformed identity scalar does not invent an identity to compare.
    if (!isIdentifier(identifier)) continue;
    if (setHas(seen, identifier)) return true;
    setAdd(seen, identifier);
  }
  return false;
};

const capturedPermissionPathsFit = (
  permissions: readonly unknown[],
): boolean => {
  const byIdentifier = createMap<
    string,
    Readonly<Record<string, unknown>> | null
  >();
  for (let index = 0; index < permissions.length; index += 1) {
    const permission = permissions[index];
    if (!isPlainRecord(permission)) continue;
    const authorityId = ownOptional(permission, "authorityId");
    if (!isIdentifier(authorityId)) continue;
    // An already-invalid duplicate authority cannot select a parent by input
    // order. Null marks an ambiguous identity; its collision remains phase 4.
    mapSet(
      byIdentifier,
      authorityId,
      mapHas(byIdentifier, authorityId) ? null : permission,
    );
  }
  for (let index = 0; index < permissions.length; index += 1) {
    const permission = permissions[index];
    if (!isPlainRecord(permission)) continue;
    let current: Readonly<Record<string, unknown>> | null | undefined = permission;
    const visited = createSet<string>();
    let depth = 0;
    while (current !== undefined && current !== null) {
      const authorityId = ownOptional(current, "authorityId");
      if (!isIdentifier(authorityId) || setHas(visited, authorityId)) break;
      if (depth === MAX_PATH_DEPTH) return false;
      setAdd(visited, authorityId);
      depth += 1;
      const parentAuthorityId: unknown = ownOptional(current, "parentAuthorityId");
      if (!isIdentifier(parentAuthorityId)) break;
      current = mapGet(byIdentifier, parentAuthorityId);
    }
  }
  return true;
};

/** Phase-1 checks over the one detached graph, without corpus interpretation. */
const rawCaptureTimeCollectionsAreValid = (
  capture: CapturedPortableAuthorityInput,
): boolean => {
  const input = capture.value;
  const scope = input.scope;
  const roots = isPlainRecord(scope)
    ? ownOptional(scope, "recognizedRoots")
    : undefined;
  const permissions = input.permissions;
  const prohibitions = input.prohibitions;
  const evidence = input.authorityEvidence;
  const revoked = input.revokedAuthorityIds;
  const usage = input.usage;
  if (
    !Array.isArray(roots) ||
    !Array.isArray(permissions) ||
    !Array.isArray(prohibitions) ||
    !Array.isArray(evidence) ||
    !Array.isArray(revoked) ||
    !Array.isArray(usage) ||
    permissions.length + prohibitions.length > MAX_AUTHORITIES
  ) return false;
  return !hasCapturedIdentifierDuplicate(roots, "rootAuthorityId") &&
    !hasCapturedIdentifierDuplicate(evidence, "authorityId") &&
    !hasCapturedIdentifierDuplicate(usage, "authorityId") &&
    !hasCapturedIdentifierDuplicate(revoked) &&
    capturedPermissionPathsFit(permissions);
};

const rawCorpusFromCapture = (
  capture: CapturedPortableAuthorityInput,
): CorpusConstruction => {
  const input = capture.value;
  const scope = input.scope;
  const permissionsValue = input.permissions;
  const prohibitionsValue = input.prohibitions;
  const rootsValue = isPlainRecord(scope) ? scope.recognizedRoots : undefined;
  const evidenceValue = input.authorityEvidence;
  const revokedValue = input.revokedAuthorityIds;
  const usageValue = input.usage;
  if (
    !Array.isArray(permissionsValue) ||
    !Array.isArray(prohibitionsValue) ||
    !Array.isArray(rootsValue) ||
    !Array.isArray(evidenceValue) ||
    !Array.isArray(revokedValue) ||
    !Array.isArray(usageValue) ||
    permissionsValue.length + prohibitionsValue.length > MAX_AUTHORITIES
  ) return Object.freeze({ status: "INVALID_INPUT" as const });

  let aggregateStatus: ValidationStatus = "VALID";
  const permissions = createMap<string, PortablePermissionGrant>();
  const prohibitions = createMap<string, PortableProhibitionGrant>();
  const roots = createMap<string, PortableRecognizedRoot>();
  const evidence = createMap<string, PortableAuthorityEvidence>();
  const revoked = createSet<string>();
  const usage = createMap<string, PortableAuthorityUsage>();
  let authorityIdentityCollision = false;
  let captureDuplicate = false;

  for (let index = 0; index < permissionsValue.length; index += 1) {
    const value = permissionsValue[index];
    const status = permissionStatus(capture, value);
    aggregateStatus = mergeStatus(aggregateStatus, status);
    if (status === "VALID") {
      const permission = value as unknown as PortablePermissionGrant;
      if (
        mapHas(permissions, permission.authorityId) ||
        mapHas(prohibitions, permission.authorityId)
      ) authorityIdentityCollision = true;
      else mapSet(permissions, permission.authorityId, permission);
    }
  }
  for (let index = 0; index < prohibitionsValue.length; index += 1) {
    const value = prohibitionsValue[index];
    const status = prohibitionStatus(capture, value);
    aggregateStatus = mergeStatus(aggregateStatus, status);
    if (status === "VALID") {
      const prohibition = value as unknown as PortableProhibitionGrant;
      if (
        mapHas(permissions, prohibition.authorityId) ||
        mapHas(prohibitions, prohibition.authorityId)
      ) authorityIdentityCollision = true;
      else mapSet(prohibitions, prohibition.authorityId, prohibition);
    }
  }
  for (let index = 0; index < rootsValue.length; index += 1) {
    const value = rootsValue[index];
    const status = recognizedRootStatus(capture, value);
    aggregateStatus = mergeStatus(aggregateStatus, status);
    if (status === "VALID") {
      const root = value as unknown as PortableRecognizedRoot;
      if (!addUniqueByIdentifier(roots, root.rootAuthorityId, root)) {
        captureDuplicate = true;
      }
    }
  }
  for (let index = 0; index < evidenceValue.length; index += 1) {
    const value = evidenceValue[index];
    const status = authorityEvidenceStatus(capture, value);
    aggregateStatus = mergeStatus(aggregateStatus, status);
    if (status === "VALID") {
      const item = value as unknown as PortableAuthorityEvidence;
      if (!addUniqueByIdentifier(evidence, item.authorityId, item)) {
        captureDuplicate = true;
      }
    }
  }
  for (let index = 0; index < usageValue.length; index += 1) {
    const value = usageValue[index];
    const status = authorityUsageStatus(capture, value);
    aggregateStatus = mergeStatus(aggregateStatus, status);
    if (status === "VALID") {
      const item = value as unknown as PortableAuthorityUsage;
      if (!addUniqueByIdentifier(usage, item.authorityId, item)) {
        captureDuplicate = true;
      }
    }
  }
  for (let index = 0; index < revokedValue.length; index += 1) {
    const status = identifierStatus(revokedValue[index]);
    aggregateStatus = mergeStatus(aggregateStatus, status);
    if (status === "VALID") {
      const identifier = revokedValue[index] as string;
      if (setHas(revoked, identifier)) captureDuplicate = true;
      else setAdd(revoked, identifier);
    }
  }

  if (aggregateStatus === "LIMIT" || captureDuplicate) {
    return Object.freeze({ status: "INVALID_INPUT" as const });
  }
  if (aggregateStatus === "INVALID" || authorityIdentityCollision) {
    return Object.freeze({ status: "INVALID_DELEGATION" as const });
  }
  return Object.freeze({
    status: "VALID" as const,
    corpus: Object.freeze({
      permissions,
      prohibitions,
      roots,
      evidence,
      revoked,
      usage,
      globalPolicySourceId: (scope as Record<string, unknown>)
        .globalPolicySourceId as string,
    }),
  });
};

const replayCorpus = (state: PortableAuthorityReplayState): AuthorityCorpus => {
  const permissions = createMap<string, PortablePermissionGrant>();
  const prohibitions = createMap<string, PortableProhibitionGrant>();
  const evidence = createMap<string, PortableAuthorityEvidence>();
  const revoked = createSet<string>();
  const replayAgents = state.agents;
  const replayPrincipals = state.principals;
  const replayRecords = state.authorities;
  const roots = state.recognizedRoots;
  const usage = state.authorityUsage;
  mapForEach(replayRecords, (record, authorityId) => {
    if (record.grant.kind === "PERMISSION") {
      mapSet(permissions, authorityId, record.grant);
    } else {
      mapSet(prohibitions, authorityId, record.grant);
    }
    mapSet(evidence, authorityId, Object.freeze({
      authorityId,
      grantEventId: record.grantEventId,
      grantEventPosition: record.grantEventPosition,
    }));
    if (ownOptional(record, "revocationEventId") !== undefined) {
      setAdd(revoked, authorityId);
    }
  });
  return Object.freeze({
    permissions,
    prohibitions,
    roots,
    evidence,
    revoked,
    usage,
    globalPolicySourceId: state.genesis.globalPolicySourceId,
    replayAgents,
    replayPrincipals,
    replayRecords,
  });
};

const buildPermissionPath = (
  terminal: PortablePermissionGrant,
  permissions: ReadonlyMap<string, PortablePermissionGrant>,
): Readonly<{
  status: "VALID";
  path: PermissionPath;
}> | Readonly<{ status: "INVALID_INPUT" | "INVALID_DELEGATION" }> => {
  const reverse: PortablePermissionGrant[] = [];
  const visited = createSet<string>();
  let current: PortablePermissionGrant | undefined = terminal;
  while (current !== undefined) {
    if (setHas(visited, current.authorityId)) {
      return Object.freeze({ status: "INVALID_DELEGATION" as const });
    }
    if (reverse.length === MAX_PATH_DEPTH) {
      return Object.freeze({ status: "INVALID_INPUT" as const });
    }
    setAdd(visited, current.authorityId);
    arrayPush(reverse, current);
    const parentAuthorityId: string | undefined = ownOptional(
      current,
      "parentAuthorityId",
    );
    if (parentAuthorityId === undefined) break;
    const parent: PortablePermissionGrant | undefined = mapGet(
      permissions,
      parentAuthorityId,
    );
    if (parent === undefined) {
      return Object.freeze({ status: "INVALID_DELEGATION" as const });
    }
    current = parent;
  }
  const grants: PortablePermissionGrant[] = [];
  for (let index = reverse.length - 1; index >= 0; index -= 1) {
    arrayPush(grants, reverse[index]!);
  }
  let effectivelyIndependent = true;
  for (let index = 0; index < grants.length; index += 1) {
    const grant = grants[index]!;
    if (!grant.independent) effectivelyIndependent = false;
    if (index === 0) continue;
    const parent = grants[index - 1]!;
    if (
      grant.grantorId !== parent.granteeId ||
      grant.rootAuthorityId !== parent.rootAuthorityId ||
      !constraintsAreAttenuated(parent.constraints, grant.constraints)
    ) {
      return Object.freeze({ status: "INVALID_DELEGATION" as const });
    }
  }
  const authorityIds: string[] = [];
  for (let index = 0; index < grants.length; index += 1) {
    arrayPush(authorityIds, grants[index]!.authorityId);
  }
  return Object.freeze({
    status: "VALID" as const,
    path: Object.freeze({
      rootAuthorityId: grants[0]!.rootAuthorityId,
      grants: Object.freeze(grants),
      authorityIds: Object.freeze(authorityIds),
      effectivelyIndependent,
    }),
  });
};

const validateIntersectionGraph = (
  permissions: ReadonlyMap<string, PortablePermissionGrant>,
): boolean => {
  const done = createSet<string>();
  const identifiers: string[] = [];
  mapForEach(permissions, (_grant, identifier) => arrayPush(identifiers, identifier));
  for (let startIndex = 0; startIndex < identifiers.length; startIndex += 1) {
    const start = identifiers[startIndex]!;
    if (setHas(done, start)) continue;
    const active = createSet<string>();
    const stack: Array<{ identifier: string; next: number }> = [];
    arrayPush(stack, { identifier: start, next: 0 });
    setAdd(active, start);
    while (stack.length > 0) {
      const frame = stack[stack.length - 1]!;
      const grant = mapGet(permissions, frame.identifier)!;
      if (frame.next >= grant.constraints.requiredIntersectionIds.length) {
        stack.length -= 1;
        setDelete(active, frame.identifier);
        setAdd(done, frame.identifier);
        continue;
      }
      const dependency = grant.constraints.requiredIntersectionIds[frame.next]!;
      frame.next += 1;
      if (!mapHas(permissions, dependency) || setHas(done, dependency)) continue;
      if (setHas(active, dependency)) return false;
      setAdd(active, dependency);
      arrayPush(stack, { identifier: dependency, next: 0 });
    }
  }
  return true;
};

const validateAuthorityCorpus = (
  corpus: AuthorityCorpus,
): CorpusValidation => {
  const paths = createMap<string, PermissionPath>();
  let pathStatus: "VALID" | "INVALID_INPUT" | "INVALID_DELEGATION" = "VALID";
  mapForEach(corpus.permissions, (permission, authorityId) => {
    if (pathStatus === "INVALID_INPUT") return;
    const built = buildPermissionPath(permission, corpus.permissions);
    if (built.status !== "VALID") {
      pathStatus = built.status;
      return;
    }
    mapSet(paths, authorityId, built.path);
  });
  if (pathStatus !== "VALID") return Object.freeze({ status: pathStatus });
  if (!validateIntersectionGraph(corpus.permissions)) {
    return Object.freeze({ status: "INVALID_DELEGATION" as const });
  }

  let valid = true;
  if (
    mapSize(corpus.evidence) !==
      mapSize(corpus.permissions) + mapSize(corpus.prohibitions)
  ) valid = false;
  mapForEach(corpus.permissions, (_grant, authorityId) => {
    if (!mapHas(corpus.evidence, authorityId)) valid = false;
  });
  mapForEach(corpus.prohibitions, (_grant, authorityId) => {
    if (!mapHas(corpus.evidence, authorityId)) valid = false;
  });
  mapForEach(corpus.evidence, (_item, authorityId) => {
    if (
      !mapHas(corpus.permissions, authorityId) &&
      !mapHas(corpus.prohibitions, authorityId)
    ) valid = false;
  });

  const replayPrincipals = ownOptional(corpus, "replayPrincipals");
  const replayRecords = ownOptional(corpus, "replayRecords");
  mapForEach(corpus.roots, (root, rootAuthorityId) => {
    const grant = mapGet(corpus.permissions, rootAuthorityId);
    const evidence = mapGet(corpus.evidence, rootAuthorityId);
    if (
      grant === undefined ||
      evidence === undefined ||
      ownOptional(grant, "parentAuthorityId") !== undefined ||
      grant.authorityId !== root.rootAuthorityId ||
      grant.rootAuthorityId !== root.rootAuthorityId ||
      grant.grantorId !== root.principalId ||
      evidence.grantEventId !== root.rootGrantEventId
    ) valid = false;
    if (replayPrincipals !== undefined) {
      const principal = mapGet(replayPrincipals, root.principalId);
      const record = replayRecords === undefined
        ? undefined
        : mapGet(replayRecords, rootAuthorityId);
      if (
        principal === undefined ||
        record === undefined ||
        evidence === undefined ||
        root.principalRecognitionEventId !== principal.creationEventId ||
        root.rootGrantEventId !== record.grantEventId ||
        evidence.grantEventPosition !== record.grantEventPosition
      ) valid = false;
    }
  });

  mapForEach(corpus.prohibitions, (prohibition) => {
    if (prohibition.scope === "GLOBAL") {
      if (prohibition.grantorId !== corpus.globalPolicySourceId) valid = false;
      return;
    }
    const root = mapGet(corpus.roots, prohibition.rootAuthorityId);
    if (root === undefined) {
      valid = false;
      return;
    }
    const parentAuthorityId = ownOptional(prohibition, "parentAuthorityId");
    if (prohibition.grantorId === root.principalId) {
      const rootGrant = mapGet(corpus.permissions, root.rootAuthorityId);
      if (
        parentAuthorityId !== undefined ||
        rootGrant === undefined ||
        !constraintsAreAttenuated(
          rootGrant.constraints,
          prohibition.constraints,
        )
      ) valid = false;
      return;
    }
    if (parentAuthorityId === undefined) {
      valid = false;
      return;
    }
    const parent = mapGet(corpus.permissions, parentAuthorityId);
    const path = mapGet(paths, parentAuthorityId);
    if (
      parent === undefined ||
      path === undefined ||
      parent.granteeId !== prohibition.grantorId ||
      path.rootAuthorityId !== prohibition.rootAuthorityId ||
      !constraintsAreAttenuated(parent.constraints, prohibition.constraints)
    ) valid = false;
  });

  const revokedAuthorityIds = setToArray(corpus.revoked);
  for (let index = 0; index < revokedAuthorityIds.length; index += 1) {
    const authorityId = revokedAuthorityIds[index]!;
    if (
      !mapHas(corpus.permissions, authorityId) &&
      !mapHas(corpus.prohibitions, authorityId)
    ) valid = false;
  }

  const requiredUsage = createSet<string>();
  mapForEach(corpus.permissions, (permission, authorityId) => {
    if (
      ownOptional(permission.constraints, "maxTransactions") !== undefined ||
      ownOptional(permission.constraints, "maxCumulativeAmount") !== undefined
    ) setAdd(requiredUsage, authorityId);
  });
  if (setSize(requiredUsage) !== mapSize(corpus.usage)) valid = false;
  mapForEach(corpus.usage, (_entry, authorityId) => {
    if (!setHas(requiredUsage, authorityId)) valid = false;
  });

  return valid
    ? Object.freeze({
        status: "VALID" as const,
        value: Object.freeze({ corpus, paths }),
      })
    : Object.freeze({ status: "INVALID_DELEGATION" as const });
};

const recognizedRootForPath = (
  validated: ValidatedCorpus,
  path: PermissionPath,
): PortableRecognizedRoot | undefined => {
  const root = mapGet(validated.corpus.roots, path.rootAuthorityId);
  const grant = path.grants[0]!;
  if (
    root === undefined ||
    grant.authorityId !== root.rootAuthorityId ||
    grant.rootAuthorityId !== root.rootAuthorityId ||
    grant.grantorId !== root.principalId ||
    ownOptional(grant, "parentAuthorityId") !== undefined
  ) return undefined;
  return root;
};

const addConstraintIdentifiers = (
  target: Set<string>,
  values: readonly string[],
): void => {
  for (let index = 0; index < values.length; index += 1) {
    setAdd(target, values[index]!);
  }
};

const intersectIdentifierValues = (
  current: readonly string[] | undefined,
  next: readonly string[],
): readonly string[] => {
  if (current === undefined) return sortedIdentifiers(next);
  const intersection: string[] = [];
  for (let index = 0; index < current.length; index += 1) {
    if (arrayIncludes(next, current[index]!)) {
      arrayPush(intersection, current[index]!);
    }
  }
  return Object.freeze(intersection);
};

const minimumOptionalNumber = (
  current: number | undefined,
  next: number | undefined,
): number | undefined => next === undefined
  ? current
  : current === undefined || next < current
    ? next
    : current;

const maximumOptionalNumber = (
  current: number | undefined,
  next: number | undefined,
): number | undefined => next === undefined
  ? current
  : current === undefined || next > current
    ? next
    : current;

const minimumOptionalAmount = (
  current: bigint | undefined,
  next: bigint | undefined,
): bigint | undefined => next === undefined
  ? current
  : current === undefined || next < current
    ? next
    : current;

const combineConstraints = (
  grants: readonly PortablePermissionGrant[],
): PortableAuthorityConstraints => {
  let actions: readonly string[] | undefined;
  let resources: readonly string[] | undefined;
  let quantitative = false;
  let notBefore: number | undefined;
  let expiresAt: number | undefined;
  let maxAmount: bigint | undefined;
  let maxCumulativeAmount: bigint | undefined;
  let maxTransactions: number | undefined;
  let maxDelegationDepth: number | undefined;
  const required = createSet<string>();
  for (let index = 0; index < grants.length; index += 1) {
    const constraints = grants[index]!.constraints;
    actions = intersectIdentifierValues(actions, constraints.actions);
    resources = intersectIdentifierValues(resources, constraints.resources);
    quantitative = quantitative || constraints.quantitative;
    notBefore = maximumOptionalNumber(
      notBefore,
      ownOptional(constraints, "notBefore"),
    );
    expiresAt = minimumOptionalNumber(
      expiresAt,
      ownOptional(constraints, "expiresAt"),
    );
    maxAmount = minimumOptionalAmount(
      maxAmount,
      ownOptional(constraints, "maxAmount"),
    );
    maxCumulativeAmount = minimumOptionalAmount(
      maxCumulativeAmount,
      ownOptional(constraints, "maxCumulativeAmount"),
    );
    maxTransactions = minimumOptionalNumber(
      maxTransactions,
      ownOptional(constraints, "maxTransactions"),
    );
    maxDelegationDepth = minimumOptionalNumber(
      maxDelegationDepth,
      constraints.maxDelegationDepth,
    );
    addConstraintIdentifiers(required, constraints.requiredIntersectionIds);
  }
  return Object.freeze({
    actions: actions ?? Object.freeze([]),
    resources: resources ?? Object.freeze([]),
    quantitative,
    ...(notBefore === undefined ? {} : { notBefore }),
    ...(expiresAt === undefined ? {} : { expiresAt }),
    ...(maxAmount === undefined ? {} : { maxAmount }),
    ...(maxCumulativeAmount === undefined ? {} : { maxCumulativeAmount }),
    ...(maxTransactions === undefined ? {} : { maxTransactions }),
    maxDelegationDepth: maxDelegationDepth ?? 0,
    requiredIntersectionIds: sortedIdentifiers(setToArray(required)),
  });
};

type IntersectionSelection = Readonly<{
  requiredAuthorityId: string;
  requiredByAuthorityIds: readonly string[];
  path: PermissionPath;
  recognizedRoot: PortableRecognizedRoot;
}>;

type CandidateGraph = Readonly<{
  main: PermissionPath;
  paths: readonly PermissionPath[];
  intersections: readonly IntersectionSelection[];
  missingIntersectionIds: readonly string[];
}>;

const directRequiredIds = (
  path: PermissionPath,
  grantIndex: number,
): readonly string[] => {
  const grant = path.grants[grantIndex]!;
  if (grantIndex === 0) return grant.constraints.requiredIntersectionIds;
  const parent = path.grants[grantIndex - 1]!;
  const direct: string[] = [];
  for (
    let index = 0;
    index < grant.constraints.requiredIntersectionIds.length;
    index += 1
  ) {
    const identifier = grant.constraints.requiredIntersectionIds[index]!;
    if (!arrayIncludes(parent.constraints.requiredIntersectionIds, identifier)) {
      arrayPush(direct, identifier);
    }
  }
  return Object.freeze(direct);
};

const selectCandidateGraph = (
  validated: ValidatedCorpus,
  main: PermissionPath,
  actorId: string,
): CandidateGraph => {
  const requiredBy = createMap<string, Set<string>>();
  const queued = createSet<string>();
  const queue: string[] = [];
  const selectedPaths = createMap<string, PermissionPath>();
  const selectedRoots = createMap<string, PortableRecognizedRoot>();
  const missing = createSet<string>();

  const collectDirect = (path: PermissionPath): void => {
    for (let grantIndex = 0; grantIndex < path.grants.length; grantIndex += 1) {
      const grant = path.grants[grantIndex]!;
      const direct = directRequiredIds(path, grantIndex);
      for (let index = 0; index < direct.length; index += 1) {
        const identifier = direct[index]!;
        const declarers = mapGet(requiredBy, identifier) ?? createSet<string>();
        setAdd(declarers, grant.authorityId);
        mapSet(requiredBy, identifier, declarers);
        if (!setHas(queued, identifier)) {
          setAdd(queued, identifier);
          arrayPush(queue, identifier);
        }
      }
    }
  };

  collectDirect(main);
  for (let queueIndex = 0; queueIndex < queue.length; queueIndex += 1) {
    const identifier = queue[queueIndex]!;
    const path = mapGet(validated.paths, identifier);
    const root = path === undefined
      ? undefined
      : recognizedRootForPath(validated, path);
    const terminal = path?.grants[path.grants.length - 1];
    if (
      path === undefined ||
      root === undefined ||
      terminal === undefined ||
      path.effectivelyIndependent ||
      terminal.granteeId !== actorId
    ) {
      setAdd(missing, identifier);
      continue;
    }
    if (!mapHas(selectedPaths, identifier)) {
      mapSet(selectedPaths, identifier, path);
      mapSet(selectedRoots, identifier, root);
      collectDirect(path);
    }
  }

  const intersectionIds: string[] = [];
  mapForEach(selectedPaths, (_path, identifier) => arrayPush(intersectionIds, identifier));
  arraySort(intersectionIds, compareProtocolStrings);
  const intersections: IntersectionSelection[] = [];
  const paths: PermissionPath[] = [main];
  for (let index = 0; index < intersectionIds.length; index += 1) {
    const identifier = intersectionIds[index]!;
    const path = mapGet(selectedPaths, identifier)!;
    arrayPush(paths, path);
    arrayPush(intersections, Object.freeze({
      requiredAuthorityId: identifier,
      requiredByAuthorityIds: sortedIdentifiers(
        setToArray(mapGet(requiredBy, identifier)!),
      ),
      path,
      recognizedRoot: mapGet(selectedRoots, identifier)!,
    }));
  }
  return Object.freeze({
    main,
    paths: Object.freeze(paths),
    intersections: Object.freeze(intersections),
    missingIntersectionIds: sortedIdentifiers(setToArray(missing)),
  });
};

const leastIdentifier = (values: ReadonlySet<string>): string | undefined => {
  const sorted = sortedIdentifiers(setToArray(values));
  return sorted[0];
};

const prohibitionRequestRelevant = (
  prohibition: PortableProhibitionGrant,
  request: PortableActionRequest,
): boolean => {
  const subjectActorId = ownOptional(prohibition, "subjectActorId");
  return (subjectActorId === undefined || subjectActorId === request.actorId) &&
    arrayIncludes(prohibition.constraints.actions, request.action) &&
    arrayIncludes(prohibition.constraints.resources, request.resource) &&
    (!prohibition.constraints.quantitative ||
      ownOptional(request, "amount") !== undefined);
};

const grantWithinTime = (
  constraints: PortableAuthorityConstraints,
  evaluationTime: number,
): boolean => {
  const notBefore = ownOptional(constraints, "notBefore");
  const expiresAt = ownOptional(constraints, "expiresAt");
  return (notBefore === undefined || evaluationTime >= notBefore) &&
    (expiresAt === undefined || evaluationTime < expiresAt);
};

const permissionDependsOnTerminatedAgent = (
  corpus: AuthorityCorpus,
  permission: PortablePermissionGrant,
): boolean => {
  const agents = ownOptional(corpus, "replayAgents");
  if (agents === undefined) return false;
  const grantor = mapGet(agents, permission.grantorId);
  const grantee = mapGet(agents, permission.granteeId);
  return grantor?.terminated === true || grantee?.terminated === true;
};

const permissionPathActive = (
  corpus: AuthorityCorpus,
  path: PermissionPath,
  evaluationTime: number,
  terminalAuthorityId?: string,
): boolean => {
  for (let index = 0; index < path.grants.length; index += 1) {
    const permission = path.grants[index]!;
    if (
      setHas(corpus.revoked, permission.authorityId) ||
      !grantWithinTime(permission.constraints, evaluationTime) ||
      permissionDependsOnTerminatedAgent(corpus, permission)
    ) return false;
    if (
      terminalAuthorityId !== undefined &&
      permission.authorityId === terminalAuthorityId
    ) return true;
  }
  return terminalAuthorityId === undefined;
};

const prohibitionMatchesAmount = (
  prohibition: PortableProhibitionGrant,
  request: PortableActionRequest,
): boolean => {
  const amount = ownOptional(request, "amount");
  const maxAmount = ownOptional(prohibition.constraints, "maxAmount");
  return maxAmount === undefined || (amount !== undefined && amount <= maxAmount);
};

const prohibitionIsActive = (
  validated: ValidatedCorpus,
  prohibition: PortableProhibitionGrant,
  evaluationTime: number,
): boolean => {
  if (
    setHas(validated.corpus.revoked, prohibition.authorityId) ||
    !grantWithinTime(prohibition.constraints, evaluationTime)
  ) return false;
  if (prohibition.scope === "GLOBAL") return true;
  const parentAuthorityId = ownOptional(prohibition, "parentAuthorityId");
  if (parentAuthorityId === undefined) return true;
  const anchor = mapGet(validated.paths, parentAuthorityId);
  return anchor !== undefined && permissionPathActive(
    validated.corpus,
    anchor,
    evaluationTime,
    parentAuthorityId,
  );
};

const participatingRootIds = (graph: CandidateGraph): ReadonlySet<string> => {
  const roots = createSet<string>();
  for (let index = 0; index < graph.paths.length; index += 1) {
    setAdd(roots, graph.paths[index]!.rootAuthorityId);
  }
  return roots;
};

const rootProhibitionApplies = (
  prohibition: PortableRootProhibitionGrant,
  graph: CandidateGraph,
): boolean => {
  if (!setHas(participatingRootIds(graph), prohibition.rootAuthorityId)) {
    return false;
  }
  const parentAuthorityId = ownOptional(prohibition, "parentAuthorityId");
  if (parentAuthorityId === undefined) return true;
  for (let pathIndex = 0; pathIndex < graph.paths.length; pathIndex += 1) {
    const path = graph.paths[pathIndex]!;
    if (
      path.rootAuthorityId === prohibition.rootAuthorityId &&
      arrayIncludes(path.authorityIds, parentAuthorityId)
    ) return true;
  }
  return false;
};

const relevantGlobalProhibitions = (
  validated: ValidatedCorpus,
  request: PortableActionRequest,
): readonly PortableGlobalProhibitionGrant[] => {
  const relevant: PortableGlobalProhibitionGrant[] = [];
  mapForEach(validated.corpus.prohibitions, (prohibition) => {
    if (
      prohibition.scope === "GLOBAL" &&
      prohibitionRequestRelevant(prohibition, request)
    ) arrayPush(relevant, prohibition);
  });
  arraySort(relevant, (left, right) =>
    compareProtocolStrings(left.authorityId, right.authorityId));
  return Object.freeze(relevant);
};

const relevantCandidateProhibitions = (
  validated: ValidatedCorpus,
  graph: CandidateGraph,
  request: PortableActionRequest,
): readonly PortableRootProhibitionGrant[] => {
  const relevant: PortableRootProhibitionGrant[] = [];
  mapForEach(validated.corpus.prohibitions, (prohibition) => {
    if (
      prohibition.scope === "ROOT" &&
      rootProhibitionApplies(prohibition, graph) &&
      prohibitionRequestRelevant(prohibition, request)
    ) arrayPush(relevant, prohibition);
  });
  arraySort(relevant, (left, right) =>
    compareProtocolStrings(left.authorityId, right.authorityId));
  return Object.freeze(relevant);
};

const PHASE_SEVEN_RANK: Readonly<Record<
  | "PROHIBITED"
  | "REVOKED"
  | "NOT_YET_VALID"
  | "EXPIRED"
  | "MISSING_INTERSECTION"
  | "ACTION_NOT_ALLOWED"
  | "RESOURCE_NOT_ALLOWED"
  | "AMOUNT_REQUIRED"
  | "AMOUNT_EXCEEDED"
  | "CUMULATIVE_AMOUNT_EXCEEDED"
  | "TRANSACTION_COUNT_EXCEEDED"
  | "NO_AUTHORITY",
  number
>> = Object.freeze({
  PROHIBITED: 0,
  REVOKED: 1,
  NOT_YET_VALID: 2,
  EXPIRED: 3,
  MISSING_INTERSECTION: 4,
  ACTION_NOT_ALLOWED: 5,
  RESOURCE_NOT_ALLOWED: 6,
  AMOUNT_REQUIRED: 7,
  AMOUNT_EXCEEDED: 8,
  CUMULATIVE_AMOUNT_EXCEEDED: 9,
  TRANSACTION_COUNT_EXCEEDED: 10,
  NO_AUTHORITY: 11,
});

type CandidateFailureCode = keyof typeof PHASE_SEVEN_RANK;

type CandidateEvaluation =
  | Readonly<{
      status: "SUCCESS";
      graph: CandidateGraph;
      checkedProhibitionIds: readonly string[];
    }>
  | Readonly<{
      status: "FAILURE";
      code: CandidateFailureCode;
      failingAuthorityId: string;
      graph?: CandidateGraph;
    }>;

const evaluateCandidate = (
  validated: ValidatedCorpus,
  main: PermissionPath,
  request: PortableActionRequest,
  evaluationTime: number,
  globalProhibitions: readonly PortableGlobalProhibitionGrant[],
  checkCapacity = true,
  collectDecisiveAuthority?: (authorityId: string) => void,
): CandidateEvaluation => {
  if (recognizedRootForPath(validated, main) === undefined) {
    return Object.freeze({
      status: "FAILURE" as const,
      code: "NO_AUTHORITY" as const,
      failingAuthorityId: main.rootAuthorityId,
    });
  }
  const graph = selectCandidateGraph(validated, main, request.actorId);
  const relevantRoot = relevantCandidateProhibitions(validated, graph, request);
  const checked = createSet<string>();
  const matchingProhibitions = createSet<string>();
  for (let index = 0; index < globalProhibitions.length; index += 1) {
    setAdd(checked, globalProhibitions[index]!.authorityId);
  }
  for (let index = 0; index < relevantRoot.length; index += 1) {
    const prohibition = relevantRoot[index]!;
    setAdd(checked, prohibition.authorityId);
    if (
      prohibitionIsActive(validated, prohibition, evaluationTime) &&
      prohibitionMatchesAmount(prohibition, request)
    ) setAdd(matchingProhibitions, prohibition.authorityId);
  }
  const prohibitedBy = leastIdentifier(matchingProhibitions);
  if (prohibitedBy !== undefined && collectDecisiveAuthority === undefined) {
    return Object.freeze({
      status: "FAILURE" as const,
      code: "PROHIBITED" as const,
      failingAuthorityId: prohibitedBy,
      graph,
    });
  }

  const revoked = createSet<string>();
  const notYetValid = createSet<string>();
  const expired = createSet<string>();
  const actionFailures = createSet<string>();
  const resourceFailures = createSet<string>();
  const amountRequired = createSet<string>();
  const amountExceeded = createSet<string>();
  const cumulativeExceeded = createSet<string>();
  const transactionExceeded = createSet<string>();
  const inactiveAgent = createSet<string>();
  const missingIntersectionFailures = createSet<string>();
  addConstraintIdentifiers(
    missingIntersectionFailures,
    graph.missingIntersectionIds,
  );
  const amount = ownOptional(request, "amount");
  for (let pathIndex = 0; pathIndex < graph.paths.length; pathIndex += 1) {
    const path = graph.paths[pathIndex]!;
    for (let index = 0; index < path.grants.length; index += 1) {
      const permission = path.grants[index]!;
      const constraints = permission.constraints;
      if (setHas(validated.corpus.revoked, permission.authorityId)) {
        setAdd(revoked, permission.authorityId);
      }
      const notBefore = ownOptional(constraints, "notBefore");
      if (notBefore !== undefined && evaluationTime < notBefore) {
        setAdd(notYetValid, permission.authorityId);
      }
      const expiresAt = ownOptional(constraints, "expiresAt");
      if (expiresAt !== undefined && evaluationTime >= expiresAt) {
        setAdd(expired, permission.authorityId);
      }
      if (!arrayIncludes(constraints.actions, request.action)) {
        setAdd(actionFailures, permission.authorityId);
      }
      if (!arrayIncludes(constraints.resources, request.resource)) {
        setAdd(resourceFailures, permission.authorityId);
      }
      if (constraints.quantitative && amount === undefined) {
        setAdd(amountRequired, permission.authorityId);
      }
      const maxAmount = ownOptional(constraints, "maxAmount");
      if (maxAmount !== undefined && amount !== undefined && amount > maxAmount) {
        setAdd(amountExceeded, permission.authorityId);
      }
      const usage = mapGet(validated.corpus.usage, permission.authorityId);
      const maxCumulative = ownOptional(constraints, "maxCumulativeAmount");
      if (
        checkCapacity &&
        usage !== undefined &&
        maxCumulative !== undefined &&
        amount !== undefined &&
        usage.admittedCumulativeAmount + amount > maxCumulative
      ) setAdd(cumulativeExceeded, permission.authorityId);
      const maxTransactions = ownOptional(constraints, "maxTransactions");
      if (
        checkCapacity &&
        usage !== undefined &&
        maxTransactions !== undefined &&
        usage.admittedTransactionCount >= maxTransactions
      ) setAdd(transactionExceeded, permission.authorityId);
      if (permissionDependsOnTerminatedAgent(validated.corpus, permission)) {
        setAdd(inactiveAgent, permission.authorityId);
      }
    }
  }

  const ordered: readonly (readonly [
    CandidateFailureCode,
    ReadonlySet<string>,
  ])[] =
    Object.freeze([
      Object.freeze(["REVOKED", revoked] as const),
      Object.freeze(["NOT_YET_VALID", notYetValid] as const),
      Object.freeze(["EXPIRED", expired] as const),
      Object.freeze([
        "MISSING_INTERSECTION",
        missingIntersectionFailures,
      ] as const),
      Object.freeze(["ACTION_NOT_ALLOWED", actionFailures] as const),
      Object.freeze(["RESOURCE_NOT_ALLOWED", resourceFailures] as const),
      Object.freeze(["AMOUNT_REQUIRED", amountRequired] as const),
      Object.freeze(["AMOUNT_EXCEEDED", amountExceeded] as const),
      Object.freeze([
        "CUMULATIVE_AMOUNT_EXCEEDED",
        cumulativeExceeded,
      ] as const),
      Object.freeze([
        "TRANSACTION_COUNT_EXCEEDED",
        transactionExceeded,
      ] as const),
      Object.freeze(["NO_AUTHORITY", inactiveAgent] as const),
    ]);
  // Receipt evidence needs every decisive fact, while ordinary authorization
  // retains its existing first-failure result and admission capacity checks.
  if (collectDecisiveAuthority !== undefined) {
    const prohibited = setToArray(matchingProhibitions);
    for (let index = 0; index < prohibited.length; index += 1) {
      collectDecisiveAuthority(prohibited[index]!);
    }
    for (let index = 0; index < ordered.length; index += 1) {
      const identifiers = setToArray(ordered[index]![1]);
      for (let item = 0; item < identifiers.length; item += 1) {
        collectDecisiveAuthority(identifiers[item]!);
      }
    }
  }
  if (prohibitedBy !== undefined) {
    return Object.freeze({ status: "FAILURE" as const, code: "PROHIBITED" as const,
      failingAuthorityId: prohibitedBy, graph });
  }
  for (let index = 0; index < ordered.length; index += 1) {
    const code = ordered[index]![0];
    const identifiers = ordered[index]![1];
    const failingAuthorityId = leastIdentifier(identifiers);
    if (failingAuthorityId !== undefined) {
      return Object.freeze({
        status: "FAILURE" as const,
        code,
        failingAuthorityId,
        graph,
      });
    }
  }
  return Object.freeze({
    status: "SUCCESS" as const,
    graph,
    checkedProhibitionIds: sortedIdentifiers(setToArray(checked)),
  });
};

export type PortableReceiptPolicyEvaluation = Readonly<{
  live: boolean;
  checkedProhibitionIds: readonly string[];
  decisiveAuthorityIds: readonly string[];
  decisiveAgentIds: readonly string[];
}>;

/**
 * Package-internal receipt recheck over accepted state and its admitted proof.
 * Select the original terminal/path, never a newly preferred candidate. Only
 * already reserved nonce/capacity are outside this policy liveness predicate;
 * the caller separately rechecks the exact admitted control tuple.
 */
export const evaluatePortableReceiptPolicy = (
  state: PortableAuthorityReplayState,
  proof: PortableAuthorizationProof,
  evaluationTime: number,
): PortableReceiptPolicyEvaluation => {
  const checkedProhibitions = createSet<string>();
  const decisiveAuthorities = createSet<string>();
  const decisiveAgents = createSet<string>();
  const result = (live: boolean): PortableReceiptPolicyEvaluation => Object.freeze({
    live,
    checkedProhibitionIds: sortedIdentifiers(setToArray(checkedProhibitions)),
    decisiveAuthorityIds: sortedIdentifiers(setToArray(decisiveAuthorities)),
    decisiveAgentIds: sortedIdentifiers(setToArray(decisiveAgents)),
  });
  if (!isU53(evaluationTime) ||
      !sameDomain(proof.domain, state.genesis.domain) ||
      proof.policyVersion !== state.genesis.policyVersion ||
      proof.rootRecognitionPolicy !== state.genesis.rootRecognitionPolicy ||
      proof.rootRecognitionPolicy !== PORTABLE_ROOT_RECOGNITION_POLICY) return result(false);
  const validation = validateAuthorityCorpus(replayCorpus(state));
  if (validation.status !== "VALID") return result(false);
  const validated = validation.value;
  const terminal = proof.permissionPath[proof.permissionPath.length - 1];
  const main = terminal === undefined ? undefined : mapGet(validated.paths, terminal.authorityId);
  if (main === undefined || !main.effectivelyIndependent || terminal!.granteeId !== proof.request.actorId) {
    if (terminal !== undefined) setAdd(decisiveAuthorities, terminal.authorityId);
    return result(false);
  }
  const graph = selectCandidateGraph(validated, main, proof.request.actorId);
  const root = recognizedRootForPath(validated, main);
  const samePath = (actual: readonly PortablePermissionGrant[], expected: readonly PortablePermissionGrant[]): boolean => {
    if (actual.length !== expected.length) return false;
    for (let index = 0; index < actual.length; index += 1) {
      // Grant sets are unordered on input and sorted in admitted proofs.
      if (canonicalEncode(normalizedPermission(actual[index]!)) !== canonicalEncode(expected[index])) return false;
    }
    return true;
  };
  let identityMatches = root !== undefined &&
    canonicalEncode(root) === canonicalEncode(proof.recognizedRoot) &&
    samePath(main.grants, proof.permissionPath) &&
    graph.intersections.length === proof.intersections.length;
  if (!identityMatches) setAdd(decisiveAuthorities, main.rootAuthorityId);
  for (let index = 0; index < graph.intersections.length; index += 1) {
    const actual = graph.intersections[index]!;
    const expected = proof.intersections[index];
    if (expected === undefined || actual.requiredAuthorityId !== expected.requiredAuthorityId ||
        canonicalEncode(actual.requiredByAuthorityIds) !== canonicalEncode(expected.requiredByAuthorityIds) ||
        canonicalEncode(actual.recognizedRoot) !== canonicalEncode(expected.recognizedRoot) ||
        !samePath(actual.path.grants, expected.path) ||
        canonicalEncode(combineConstraints(actual.path.grants)) !== canonicalEncode(expected.effectiveConstraints)) {
      identityMatches = false;
      setAdd(decisiveAuthorities, actual.requiredAuthorityId);
    }
  }
  if (canonicalEncode(combineConstraints(grantsForCandidateGraph(graph))) !== canonicalEncode(proof.effectiveConstraints)) {
    identityMatches = false;
    setAdd(decisiveAuthorities, terminal!.authorityId);
  }
  for (let pathIndex = 0; pathIndex < graph.paths.length; pathIndex += 1) {
    const grants = graph.paths[pathIndex]!.grants;
    for (let index = 0; index < grants.length; index += 1) {
      const grant = grants[index]!;
      if (mapGet(state.agents, grant.grantorId)?.terminated === true) setAdd(decisiveAgents, grant.grantorId);
      if (mapGet(state.agents, grant.granteeId)?.terminated === true) setAdd(decisiveAgents, grant.granteeId);
    }
  }
  const globals = relevantGlobalProhibitions(validated, proof.request);
  const candidateProhibitions = relevantCandidateProhibitions(validated, graph, proof.request);
  // Relevance is independent of activity: inactive prohibitions still supply
  // the exact evidence explaining why the admitted graph remains usable.
  for (let index = 0; index < candidateProhibitions.length; index += 1) {
    setAdd(checkedProhibitions, candidateProhibitions[index]!.authorityId);
  }
  let globalBlocked = false;
  for (let index = 0; index < globals.length; index += 1) {
    const prohibition = globals[index]!;
    setAdd(checkedProhibitions, prohibition.authorityId);
    if (prohibitionIsActive(validated, prohibition, evaluationTime) &&
        prohibitionMatchesAmount(prohibition, proof.request)) {
      globalBlocked = true;
      setAdd(decisiveAuthorities, prohibition.authorityId);
    }
  }
  const evaluation = evaluateCandidate(validated, main, proof.request, evaluationTime,
    globals, false, authorityId => setAdd(decisiveAuthorities, authorityId));
  // A behind-head clock cannot establish liveness, but exact receipt evidence
  // still includes the independently available policy failures in this state.
  return result(evaluationTime >= state.head.canonicalTime && identityMatches && !globalBlocked && evaluation.status === "SUCCESS");
};

const normalizedRequest = (
  request: PortableActionRequest,
): PortableActionRequest => {
  const actorId = request.actorId;
  const action = request.action;
  const resource = request.resource;
  const claimedAt = request.claimedAt;
  const amount = ownOptional(request, "amount");
  const counterpartyId = ownOptional(request, "counterpartyId");
  const termsCommitment = ownOptional(request, "termsCommitment");
  return Object.freeze({
    actorId,
    action,
    resource,
    claimedAt,
    ...(amount === undefined ? {} : { amount }),
    ...(counterpartyId === undefined ? {} : { counterpartyId }),
    ...(termsCommitment === undefined ? {} : { termsCommitment }),
  });
};

const normalizedDomain = (
  domain: PortableAuthorizationDomain,
): PortableAuthorizationDomain => {
  const protocol = domain.protocol;
  const version = domain.version;
  const deploymentId = domain.deploymentId;
  const chainId = domain.chainId;
  const verifyingContract = domain.verifyingContract;
  return Object.freeze({
    protocol,
    version,
    deploymentId,
    chainId,
    verifyingContract,
  });
};

const compareIntersectionProofs = (
  left: PortableIntersectionProof,
  right: PortableIntersectionProof,
): number => {
  let comparison = compareProtocolStrings(
    left.requiredAuthorityId,
    right.requiredAuthorityId,
  );
  if (comparison !== 0) return comparison;
  comparison = compareIdentifierSequences(
    left.requiredByAuthorityIds,
    right.requiredByAuthorityIds,
  );
  if (comparison !== 0) return comparison;
  comparison = compareProtocolStrings(
    left.recognizedRoot.rootAuthorityId,
    right.recognizedRoot.rootAuthorityId,
  );
  if (comparison !== 0) return comparison;
  const leftPath: string[] = [];
  const rightPath: string[] = [];
  for (let index = 0; index < left.path.length; index += 1) {
    arrayPush(leftPath, left.path[index]!.authorityId);
  }
  for (let index = 0; index < right.path.length; index += 1) {
    arrayPush(rightPath, right.path[index]!.authorityId);
  }
  comparison = compareIdentifierSequences(leftPath, rightPath);
  if (comparison !== 0) return comparison;
  return compareProtocolStrings(
    hashCanonical(left.effectiveConstraints),
    hashCanonical(right.effectiveConstraints),
  );
};

type CandidateIntersectionPlan = Readonly<{
  selection: IntersectionSelection;
  effectiveConstraints: PortableAuthorityConstraints;
  effectiveConstraintsHash: ContentHash;
}>;

type SuccessfulAuthorityCandidate = Readonly<{
  decision: "ALLOW_CANDIDATE";
  context: AuthorityEvaluationContext;
  evaluation: Extract<CandidateEvaluation, { status: "SUCCESS" }>;
  recognizedRoot: PortableRecognizedRoot;
  intersections: readonly CandidateIntersectionPlan[];
  effectiveConstraints: PortableAuthorityConstraints;
  effectiveConstraintsHash: ContentHash;
}>;

type AuthorityAlgebraResult =
  | PortableAuthorizationResult
  | SuccessfulAuthorityCandidate;

const grantsForCandidateGraph = (
  graph: CandidateGraph,
): readonly PortablePermissionGrant[] => {
  const grants: PortablePermissionGrant[] = [];
  for (let pathIndex = 0; pathIndex < graph.paths.length; pathIndex += 1) {
    const path = graph.paths[pathIndex]!;
    for (let index = 0; index < path.grants.length; index += 1) {
      arrayPush(grants, path.grants[index]!);
    }
  }
  return Object.freeze(grants);
};

const candidatePlan = (
  context: AuthorityEvaluationContext,
  evaluation: Extract<CandidateEvaluation, { status: "SUCCESS" }>,
): SuccessfulAuthorityCandidate => {
  const intersections: CandidateIntersectionPlan[] = [];
  for (
    let index = 0;
    index < evaluation.graph.intersections.length;
    index += 1
  ) {
    const selection = evaluation.graph.intersections[index]!;
    const effectiveConstraints = combineConstraints(selection.path.grants);
    arrayPush(intersections, Object.freeze({
      selection,
      effectiveConstraints,
      effectiveConstraintsHash: hashCanonical(effectiveConstraints),
    }));
  }
  const effectiveConstraints = combineConstraints(
    grantsForCandidateGraph(evaluation.graph),
  );
  return Object.freeze({
    decision: "ALLOW_CANDIDATE" as const,
    context,
    evaluation,
    recognizedRoot: recognizedRootForPath(
      context.validated,
      evaluation.graph.main,
    )!,
    intersections: Object.freeze(intersections),
    effectiveConstraints,
    effectiveConstraintsHash: hashCanonical(effectiveConstraints),
  });
};

const compareCandidateIntersectionPlans = (
  left: CandidateIntersectionPlan,
  right: CandidateIntersectionPlan,
): number => {
  let comparison = compareProtocolStrings(
    left.selection.requiredAuthorityId,
    right.selection.requiredAuthorityId,
  );
  if (comparison !== 0) return comparison;
  comparison = compareIdentifierSequences(
    left.selection.requiredByAuthorityIds,
    right.selection.requiredByAuthorityIds,
  );
  if (comparison !== 0) return comparison;
  comparison = compareProtocolStrings(
    left.selection.recognizedRoot.rootAuthorityId,
    right.selection.recognizedRoot.rootAuthorityId,
  );
  if (comparison !== 0) return comparison;
  comparison = compareIdentifierSequences(
    left.selection.path.authorityIds,
    right.selection.path.authorityIds,
  );
  return comparison !== 0
    ? comparison
    : compareProtocolStrings(
        left.effectiveConstraintsHash,
        right.effectiveConstraintsHash,
      );
};

const compareSuccessfulCandidates = (
  left: SuccessfulAuthorityCandidate,
  right: SuccessfulAuthorityCandidate,
): number => {
  let comparison = compareProtocolStrings(
    left.recognizedRoot.rootAuthorityId,
    right.recognizedRoot.rootAuthorityId,
  );
  if (comparison !== 0) return comparison;
  comparison = compareIdentifierSequences(
    left.evaluation.graph.main.authorityIds,
    right.evaluation.graph.main.authorityIds,
  );
  if (comparison !== 0) return comparison;
  const shared = left.intersections.length < right.intersections.length
    ? left.intersections.length
    : right.intersections.length;
  for (let index = 0; index < shared; index += 1) {
    comparison = compareCandidateIntersectionPlans(
      left.intersections[index]!,
      right.intersections[index]!,
    );
    if (comparison !== 0) return comparison;
  }
  if (left.intersections.length !== right.intersections.length) {
    return left.intersections.length < right.intersections.length ? -1 : 1;
  }
  return compareProtocolStrings(
    left.effectiveConstraintsHash,
    right.effectiveConstraintsHash,
  );
};

const constraintsFitProofLimits = (
  constraints: PortableAuthorityConstraints,
  requiredIntersectionMaximum: number,
): boolean => constraints.actions.length <= MAX_SET_MEMBERS &&
  constraints.resources.length <= MAX_SET_MEMBERS &&
  constraints.requiredIntersectionIds.length <= requiredIntersectionMaximum;

type CandidateProofProjection = Readonly<{
  controllingAuthorityIds: readonly string[];
  evidenceAuthorityIds: readonly string[];
}>;

const preflightCandidateProof = (
  candidate: SuccessfulAuthorityCandidate,
): CandidateProofProjection | undefined => {
  const graph = candidate.evaluation.graph;
  if (
    graph.main.grants.length === 0 ||
    graph.main.grants.length > MAX_PATH_DEPTH ||
    graph.intersections.length > MAX_SET_MEMBERS ||
    candidate.evaluation.checkedProhibitionIds.length > MAX_SET_MEMBERS ||
    !constraintsFitProofLimits(
      candidate.effectiveConstraints,
      MAX_SET_MEMBERS,
    )
  ) return undefined;

  const controllingIds = createSet<string>();
  for (let pathIndex = 0; pathIndex < graph.paths.length; pathIndex += 1) {
    const path = graph.paths[pathIndex]!;
    if (path.grants.length === 0 || path.grants.length > MAX_PATH_DEPTH) {
      return undefined;
    }
    for (let index = 0; index < path.grants.length; index += 1) {
      const grant = path.grants[index]!;
      if (!constraintsFitProofLimits(
        grant.constraints,
        MAX_REQUIRED_INTERSECTIONS,
      )) return undefined;
      setAdd(controllingIds, grant.authorityId);
      if (setSize(controllingIds) > MAX_SET_MEMBERS) return undefined;
    }
  }

  for (let index = 0; index < candidate.intersections.length; index += 1) {
    const intersection = candidate.intersections[index]!;
    if (
      intersection.selection.requiredByAuthorityIds.length === 0 ||
      intersection.selection.requiredByAuthorityIds.length > MAX_SET_MEMBERS ||
      !constraintsFitProofLimits(
        intersection.effectiveConstraints,
        MAX_SET_MEMBERS,
      )
    ) return undefined;
  }

  const controllingAuthorityIds = sortedIdentifiers(setToArray(controllingIds));
  let usageCount = 0;
  for (let index = 0; index < controllingAuthorityIds.length; index += 1) {
    if (mapHas(
      candidate.context.validated.corpus.usage,
      controllingAuthorityIds[index]!,
    )) usageCount += 1;
    if (usageCount > MAX_SET_MEMBERS) return undefined;
  }

  const evidenceIds = createSet<string>();
  addConstraintIdentifiers(evidenceIds, controllingAuthorityIds);
  addConstraintIdentifiers(
    evidenceIds,
    candidate.evaluation.checkedProhibitionIds,
  );
  const evidenceAuthorityIds: string[] = [];
  const evidenceIdentifiers = setToArray(evidenceIds);
  for (let index = 0; index < evidenceIdentifiers.length; index += 1) {
    const authorityId = evidenceIdentifiers[index]!;
    if (mapHas(candidate.context.validated.corpus.evidence, authorityId)) {
      arrayPush(evidenceAuthorityIds, authorityId);
      if (evidenceAuthorityIds.length > MAX_AUTHORITIES) return undefined;
    }
  }
  arraySort(evidenceAuthorityIds, compareProtocolStrings);
  return Object.freeze({
    controllingAuthorityIds,
    evidenceAuthorityIds: Object.freeze(evidenceAuthorityIds),
  });
};

const normalizedSelectedPermission = (
  memo: Map<string, PortablePermissionGrant>,
  grant: PortablePermissionGrant,
): PortablePermissionGrant => {
  const existing = mapGet(memo, grant.authorityId);
  if (existing !== undefined) return existing;
  const normalized = normalizedPermission(grant);
  mapSet(memo, grant.authorityId, normalized);
  return normalized;
};

const proofForCandidate = (
  candidate: SuccessfulAuthorityCandidate,
  projection: CandidateProofProjection,
): PortableAuthorizationProof => {
  const context = candidate.context;
  const evaluation = candidate.evaluation;
  const normalizedGrants = createMap<string, PortablePermissionGrant>();
  const intersections: PortableIntersectionProof[] = [];
  for (
    let index = 0;
    index < candidate.intersections.length;
    index += 1
  ) {
    const plannedIntersection = candidate.intersections[index]!;
    const selection = plannedIntersection.selection;
    const normalizedPath: PortablePermissionGrant[] = [];
    for (
      let pathIndex = 0;
      pathIndex < selection.path.grants.length;
      pathIndex += 1
    ) {
      arrayPush(
        normalizedPath,
        normalizedSelectedPermission(
          normalizedGrants,
          selection.path.grants[pathIndex]!,
        ),
      );
    }
    arrayPush(intersections, Object.freeze({
      requiredAuthorityId: selection.requiredAuthorityId,
      requiredByAuthorityIds: selection.requiredByAuthorityIds,
      recognizedRoot: selection.recognizedRoot,
      path: Object.freeze(normalizedPath),
      effectiveConstraints: plannedIntersection.effectiveConstraints,
    }));
  }
  arraySort(intersections, compareIntersectionProofs);

  const normalizedMain: PortablePermissionGrant[] = [];
  for (
    let index = 0;
    index < evaluation.graph.main.grants.length;
    index += 1
  ) {
    const grant = evaluation.graph.main.grants[index]!;
    arrayPush(
      normalizedMain,
      normalizedSelectedPermission(normalizedGrants, grant),
    );
  }
  const usageSnapshot: PortableAuthorityUsage[] = [];
  for (
    let index = 0;
    index < projection.controllingAuthorityIds.length;
    index += 1
  ) {
    const usage = mapGet(
      context.validated.corpus.usage,
      projection.controllingAuthorityIds[index]!,
    );
    if (usage !== undefined) {
      arrayPush(usageSnapshot, Object.freeze({
        authorityId: usage.authorityId,
        admittedTransactionCount: usage.admittedTransactionCount,
        admittedCumulativeAmount: usage.admittedCumulativeAmount,
      }));
    }
  }
  const authorityEvidence: PortableAuthorityEvidence[] = [];
  for (let index = 0; index < projection.evidenceAuthorityIds.length; index += 1) {
    const evidence = mapGet(
      context.validated.corpus.evidence,
      projection.evidenceAuthorityIds[index]!,
    );
    if (evidence !== undefined) {
      arrayPush(authorityEvidence, Object.freeze({
        authorityId: evidence.authorityId,
        grantEventId: evidence.grantEventId,
        grantEventPosition: evidence.grantEventPosition,
      }));
    }
  }
  arraySort(authorityEvidence, (left, right) => {
    const authority = compareProtocolStrings(left.authorityId, right.authorityId);
    if (authority !== 0) return authority;
    const grantEvent = compareProtocolStrings(
      left.grantEventId,
      right.grantEventId,
    );
    return grantEvent !== 0
      ? grantEvent
      : left.grantEventPosition - right.grantEventPosition;
  });
  const proof: PortableAuthorizationProof = Object.freeze({
    proofVersion: PORTABLE_AUTHORIZATION_PROOF_VERSION,
    domain: context.domain,
    policyVersion: context.policyVersion,
    rootRecognitionPolicy: PORTABLE_ROOT_RECOGNITION_POLICY,
    historyHead: context.historyHead,
    evaluationTime: context.evaluationTime,
    request: normalizedRequest(context.request),
    recognizedRoot: candidate.recognizedRoot,
    permissionPath: Object.freeze(normalizedMain),
    intersections: Object.freeze(intersections),
    effectiveConstraints: candidate.effectiveConstraints,
    controllingAuthorityIds: projection.controllingAuthorityIds,
    usageSnapshot: Object.freeze(usageSnapshot),
    authorityEvidence: Object.freeze(authorityEvidence),
    checkedProhibitionIds: evaluation.checkedProhibitionIds,
    consequential: context.consequential,
    ...(context.consequential && context.binding !== undefined
      ? {
          runtimeSessionId: context.binding.runtimeSessionId,
          credentialKeyId: context.binding.credentialKeyId!,
          controlEpoch: context.binding.controlEpoch,
          roleId: context.binding.roleId,
          roleTenureId: context.binding.roleTenureId,
          intentId: context.binding.intentId!,
          nonce: context.binding.nonce!,
        }
      : {}),
  });
  return proof;
};

const finalizeSuccessfulAuthorityCandidate = (
  candidate: SuccessfulAuthorityCandidate,
): PortableAuthorizationResult => {
  const projection = preflightCandidateProof(candidate);
  if (projection === undefined) {
    return indeterminate(
      candidate.context.operationVersion,
      "OUTPUT_LIMIT_EXCEEDED",
      candidate.context.assurance,
    );
  }
  return boundedResult(
    Object.freeze({
      operationVersion: candidate.context.operationVersion,
      decision: "ALLOW" as const,
      scopeAssurance: candidate.context.assurance,
      consequential: candidate.context.consequential,
      proof: proofForCandidate(candidate, projection),
    }),
    candidate.context.operationVersion,
    candidate.context.assurance,
  );
};

const compareOptionalIdentifier = (
  left: string | undefined,
  right: string | undefined,
): number => left === undefined
  ? right === undefined ? 0 : -1
  : right === undefined
    ? 1
    : compareProtocolStrings(left, right);

const compareEvidenceReferences = (
  left: PortableEvidenceReference,
  right: PortableEvidenceReference,
): number => {
  let comparison = compareProtocolStrings(left.eventId, right.eventId);
  if (comparison !== 0) return comparison;
  comparison = compareProtocolStrings(left.eventType, right.eventType);
  if (comparison !== 0) return comparison;
  if (left.position !== right.position) return left.position - right.position;
  return compareProtocolStrings(left.historyHash, right.historyHash);
};

const compareEvidenceSequences = (
  left: readonly PortableEvidenceReference[],
  right: readonly PortableEvidenceReference[],
): number => {
  const shared = left.length < right.length ? left.length : right.length;
  for (let index = 0; index < shared; index += 1) {
    const comparison = compareEvidenceReferences(left[index]!, right[index]!);
    if (comparison !== 0) return comparison;
  }
  return left.length < right.length ? -1 : left.length > right.length ? 1 : 0;
};

const compareDenialEvidence = (
  left: PortableDenialEvidence,
  right: PortableDenialEvidence,
): number => {
  const leftRank = Object.hasOwn(PHASE_SEVEN_RANK, left.code)
    ? PHASE_SEVEN_RANK[left.code as CandidateFailureCode]
    : -1;
  const rightRank = Object.hasOwn(PHASE_SEVEN_RANK, right.code)
    ? PHASE_SEVEN_RANK[right.code as CandidateFailureCode]
    : -1;
  if (leftRank !== rightRank) return leftRank - rightRank;
  let comparison = compareOptionalIdentifier(
    ownOptional(left, "rootAuthorityId"),
    ownOptional(right, "rootAuthorityId"),
  );
  if (comparison !== 0) return comparison;
  comparison = compareOptionalIdentifier(
    ownOptional(left, "terminalAuthorityId"),
    ownOptional(right, "terminalAuthorityId"),
  );
  if (comparison !== 0) return comparison;
  comparison = compareOptionalIdentifier(
    ownOptional(left, "failingAuthorityId"),
    ownOptional(right, "failingAuthorityId"),
  );
  if (comparison !== 0) return comparison;
  comparison = compareIdentifierSequences(
    left.authorityPathIds,
    right.authorityPathIds,
  );
  if (comparison !== 0) return comparison;
  comparison = compareOptionalIdentifier(
    ownOptional(left, "subjectId"),
    ownOptional(right, "subjectId"),
  );
  return comparison !== 0
    ? comparison
    : compareEvidenceSequences(left.evidence, right.evidence);
};

type ReplayEvidenceContext = Readonly<{
  state: PortableAuthorityReplayState;
  prefixHashes: readonly ContentHash[];
  references: Map<number, PortableEvidenceReference>;
}>;

const createReplayEvidenceContext = (
  state: PortableAuthorityReplayState,
): ReplayEvidenceContext => {
  const prefixHashes = state.eventHistoryHashes;
  if (
    prefixHashes.length !== state.events.length ||
    prefixHashes[prefixHashes.length - 1] !== state.head.hash
  ) {
    throw new TypeError(
      "Replay evidence prefix commitments disagree with the authoritative state head.",
    );
  }
  return Object.freeze({
    state,
    prefixHashes,
    references: createMap<number, PortableEvidenceReference>(),
  });
};

const replayEventReference = (
  context: ReplayEvidenceContext,
  position: number,
): PortableEvidenceReference => {
  const cached = mapGet(context.references, position);
  if (cached !== undefined) return cached;
  const event = context.state.events[position]!;
  const historyHash = context.prefixHashes[position];
  if (historyHash === undefined) {
    throw new TypeError("Replay evidence position has no prefix commitment.");
  }
  const reference = Object.freeze({
    kind: "EVENT" as const,
    eventId: event.id,
    eventType: event.type,
    position,
    historyHash,
  });
  mapSet(context.references, position, reference);
  return reference;
};

const sameEventReference = (
  left: PortableEvidenceReference,
  right: PortableEvidenceReference,
): boolean => left.eventId === right.eventId &&
  left.eventType === right.eventType &&
  left.position === right.position &&
  left.historyHash === right.historyHash;

const sortedDistinctEventReferences = (
  references: readonly PortableEvidenceReference[],
): readonly PortableEvidenceReference[] => {
  const sorted = copyArray(references);
  arraySort(sorted, compareEvidenceReferences);
  const distinct: PortableEvidenceReference[] = [];
  for (let index = 0; index < sorted.length; index += 1) {
    if (
      distinct.length === 0 ||
      !sameEventReference(distinct[distinct.length - 1]!, sorted[index]!)
    ) arrayPush(distinct, sorted[index]!);
  }
  return Object.freeze(distinct);
};

const evidenceForEventPredicate = (
  context: ReplayEvidenceContext,
  predicate: (event: AcceptedCanonicalEventShape) => boolean,
): readonly PortableEvidenceReference[] => {
  const references: PortableEvidenceReference[] = [];
  for (let index = 0; index < context.state.events.length; index += 1) {
    if (predicate(context.state.events[index]!)) {
      arrayPush(references, replayEventReference(context, index));
    }
  }
  arrayPush(
    references,
    replayEventReference(context, context.state.events.length - 1),
  );
  return sortedDistinctEventReferences(references);
};

const authorityDecisionEvidence = (
  context: ReplayEvidenceContext,
): readonly PortableEvidenceReference[] => evidenceForEventPredicate(
  context,
  (event) => arrayIncludes(Object.freeze([
    "DEPLOYMENT_INITIALIZED",
    "PRINCIPAL_CREATED",
    "AGENT_CREATED",
    "AGENT_TERMINATED",
    "AUTHORITY_GRANTED",
    "AUTHORITY_REVOKED",
    "TRANSACTION_INTENT_ADMITTED",
  ] as const), event.type),
);

const eventData = (
  event: AcceptedCanonicalEventShape,
): Record<string, unknown> => event.data as unknown as Record<string, unknown>;

const agentLifecycleEvidence = (
  context: ReplayEvidenceContext,
  actorId: string,
): readonly PortableEvidenceReference[] => evidenceForEventPredicate(
  context,
  (event) => (event.type === "AGENT_CREATED" || event.type === "AGENT_TERMINATED") &&
    eventData(event).agentId === actorId,
);

const sessionLifecycleEvidence = (
  context: ReplayEvidenceContext,
  actorId: string,
  sessionId: string,
): readonly PortableEvidenceReference[] => evidenceForEventPredicate(
  context,
  (event) =>
    ((event.type === "AGENT_CREATED" || event.type === "AGENT_TERMINATED") &&
      eventData(event).agentId === actorId) ||
    ((event.type === "RUNTIME_SESSION_ADMITTED" ||
      event.type === "CONTROL_EPOCH_ADVANCED") &&
      (eventData(event).agentId === actorId ||
        eventData(event).sessionId === sessionId)),
);

const tenureLifecycleEvidence = (
  context: ReplayEvidenceContext,
  roleId: string,
  tenureId: string,
): readonly PortableEvidenceReference[] => evidenceForEventPredicate(
  context,
  (event) => arrayIncludes(Object.freeze([
    "ROLE_CREATED",
    "AGENT_APPOINTED",
    "AGENT_UNAPPOINTED",
    "ROLE_TRANSFERRED",
  ] as const), event.type) &&
    (eventData(event).roleId === roleId ||
      eventData(event).roleTenureId === tenureId ||
      eventData(event).fromRoleTenureId === tenureId ||
      eventData(event).toRoleTenureId === tenureId),
);

const intentEventValues = (
  event: AcceptedCanonicalEventShape,
): Readonly<{
  intentId?: unknown;
  actorId?: unknown;
  nonce?: unknown;
}> => {
  const data = eventData(event);
  if (event.type === "TRANSACTION_INTENT_DECLARED") {
    return Object.freeze({
      intentId: data.intentId,
      actorId: data.actorId,
      nonce: data.nonce,
    });
  }
  if (event.type !== "TRANSACTION_INTENT_ADMITTED") return Object.freeze({});
  const proof = isPlainRecord(data.authorizationProof)
    ? data.authorizationProof
    : undefined;
  const request = proof !== undefined && isPlainRecord(proof.request)
    ? proof.request
    : undefined;
  return Object.freeze({
    intentId: data.intentId,
    actorId: request?.actorId,
    nonce: proof?.nonce,
  });
};

const intentDecisionEvidence = (
  context: ReplayEvidenceContext,
  actorId: string,
  intentId?: string,
  nonce?: string,
): readonly PortableEvidenceReference[] => evidenceForEventPredicate(
  context,
  (event) => {
    if (
      event.type !== "TRANSACTION_INTENT_DECLARED" &&
      event.type !== "TRANSACTION_INTENT_ADMITTED"
    ) return false;
    const values = intentEventValues(event);
    const selectedIntent = intentId === undefined
      ? values.actorId === actorId
      : values.intentId === intentId;
    const nonceCollision = nonce !== undefined &&
      values.actorId === actorId &&
      values.nonce === nonce;
    return selectedIntent || nonceCollision;
  },
);

const denialResult = (
  operationVersion: AuthorityOperationVersion,
  assurance: "SUPPLIED_SCOPE" | "REPLAY_VERIFIED",
  failures: readonly PortableDenialEvidence[],
): PortableAuthorizationResult => {
  const sorted = copyArray(failures);
  arraySort(sorted, compareDenialEvidence);
  return Object.freeze({
    operationVersion,
    decision: "DENY" as const,
    scopeAssurance: assurance,
    consequential: false as const,
    code: sorted[0]!.code,
    failures: Object.freeze(sorted),
  });
};

const simpleDenial = (
  operationVersion: AuthorityOperationVersion,
  assurance: "SUPPLIED_SCOPE" | "REPLAY_VERIFIED",
  code: PortableDenialCode,
  evidence: readonly PortableEvidenceReference[] = Object.freeze([]),
  subjectId?: string,
): PortableAuthorizationResult => denialResult(
  operationVersion,
  assurance,
  Object.freeze([
    Object.freeze({
      code,
      ...(subjectId === undefined ? {} : { subjectId }),
      authorityPathIds: Object.freeze([]),
      evidence,
    }),
  ]),
);

const evidenceOccurrenceCount = (
  result: PortableAuthorizationResult,
): number => {
  if (result.decision === "ALLOW") return 0;
  let count = 0;
  for (let index = 0; index < result.failures.length; index += 1) {
    count += result.failures[index]!.evidence.length;
    if (count > MAX_RESULT_EVIDENCE) return count;
  }
  return count;
};

const boundedResult = (
  result: PortableAuthorizationResult,
  operationVersion: AuthorityOperationVersion,
  assurance: "SUPPLIED_SCOPE" | "REPLAY_VERIFIED",
): PortableAuthorizationResult => {
  if (evidenceOccurrenceCount(result) > MAX_RESULT_EVIDENCE) {
    return indeterminate(operationVersion, "OUTPUT_LIMIT_EXCEEDED", assurance);
  }
  try {
    return captureBoundedCanonicalValue(result).value as PortableAuthorizationResult;
  } catch (error) {
    if (getCanonicalCaptureLimitErrorMetadata(error) !== undefined) {
      return indeterminate(operationVersion, "OUTPUT_LIMIT_EXCEEDED", assurance);
    }
    throw error;
  }
};

export type PortableRuntimeChallengeInput = Readonly<{
  domain: PortableAuthorizationDomain;
  request: PortableActionRequest;
  evaluationTime: number;
  policyVersion: string;
  historyHead: PortableHistoryHead;
  binding: PortableConsequentialBinding;
}>;

/** Package-internal exact Section 7.1 challenge projection. */
export const createPortableRuntimeAuthorizationChallenge = (
  input: PortableRuntimeChallengeInput,
): PortableRuntimeAuthorizationChallenge => {
  const domainSource = input.domain;
  const requestSource = input.request;
  const evaluationTime = input.evaluationTime;
  const policyVersion = input.policyVersion;
  const historyHeadSource = input.historyHead;
  const bindingSource = input.binding;
  const domain = normalizedDomain(domainSource);
  const request = normalizedRequest(requestSource);
  const eventHistoryHash = historyHeadSource.hash;
  const eventHistoryPosition = historyHeadSource.position;
  const runtimeSessionId = bindingSource.runtimeSessionId;
  const credentialKeyId = ownOptional(bindingSource, "credentialKeyId");
  const controlEpoch = bindingSource.controlEpoch;
  const roleId = bindingSource.roleId;
  const roleTenureId = bindingSource.roleTenureId;
  const intentId = ownOptional(bindingSource, "intentId");
  const nonce = ownOptional(bindingSource, "nonce");
  if (
    credentialKeyId === undefined ||
    intentId === undefined ||
    nonce === undefined
  ) {
    throw new TypeError(
      "Runtime authorization challenge requires credential, intent, and nonce identifiers.",
    );
  }
  return Object.freeze({
    version: PORTABLE_RUNTIME_AUTHORIZATION_VERSION,
    domain,
    request,
    authoritative: true as const,
    consequential: true as const,
    evaluationTime,
    policyVersion,
    rootRecognitionPolicy: PORTABLE_ROOT_RECOGNITION_POLICY,
    eventHistoryHash,
    eventHistoryPosition,
    runtimeSessionId,
    credentialKeyId,
    controlEpoch,
    roleId,
    roleTenureId,
    intentId,
    nonce,
  });
};

export const hashPortableRuntimeAuthorizationChallenge = (
  challenge: PortableRuntimeAuthorizationChallenge,
): ContentHash => hashCanonical(challenge);

export const portableEip191Digest = (
  messageHash: ContentHash,
): ContentHash => {
  if (!isContentHash(messageHash)) {
    throw new TypeError("EIP-191 message hash must be a ContentHash.");
  }
  const preimage = new HostUint8Array(EIP191_HASH32_PREFIX.length + 32);
  for (let index = 0; index < EIP191_HASH32_PREFIX.length; index += 1) {
    preimage[index] = EIP191_HASH32_PREFIX[index]!;
  }
  for (let index = 0; index < 32; index += 1) {
    const offset = 2 + (index * 2);
    preimage[EIP191_HASH32_PREFIX.length + index] =
      (hexadecimalNibble(stringCharCodeAt(messageHash, offset)) << 4) |
      hexadecimalNibble(stringCharCodeAt(messageHash, offset + 1));
  }
  return keccak256Bytes(preimage);
};

const modularPower = (
  base: bigint,
  exponent: bigint,
  modulus: bigint,
): bigint => {
  let factor = base % modulus;
  let remaining = exponent;
  let result = 1n;
  while (remaining > 0n) {
    if ((remaining & 1n) === 1n) result = (result * factor) % modulus;
    factor = (factor * factor) % modulus;
    remaining >>= 1n;
  }
  return result;
};

const hexadecimalNibble = (character: number): number =>
  character >= 0x30 && character <= 0x39
    ? character - 0x30
    : character >= 0x41 && character <= 0x46
      ? character - 0x37
      : character >= 0x61 && character <= 0x66
        ? character - 0x57
        : -1;

const fieldMod = (value: bigint): bigint => {
  const remainder = value % SECP256K1_FIELD;
  return remainder < 0n ? remainder + SECP256K1_FIELD : remainder;
};

type LocalSecp256k1Point = Readonly<{
  x: bigint;
  y: bigint;
  z: bigint;
}>;

const SECP256K1_INFINITY: LocalSecp256k1Point = objectFreeze({
  x: 0n,
  y: 1n,
  z: 0n,
});
const SECP256K1_BASE: LocalSecp256k1Point = objectFreeze({
  x: SECP256K1_BASE_X,
  y: SECP256K1_BASE_Y,
  z: 1n,
});

const doubleSecp256k1Point = (
  point: LocalSecp256k1Point,
): LocalSecp256k1Point => {
  if (point.z === 0n || point.y === 0n) return SECP256K1_INFINITY;
  const xx = fieldMod(point.x * point.x);
  const yy = fieldMod(point.y * point.y);
  const yyyy = fieldMod(yy * yy);
  const slopeProduct = fieldMod(4n * point.x * yy);
  const slope = fieldMod(3n * xx);
  const x = fieldMod((slope * slope) - (2n * slopeProduct));
  const y = fieldMod(
    (slope * (slopeProduct - x)) - (8n * yyyy),
  );
  const z = fieldMod(2n * point.y * point.z);
  return { x, y, z };
};

const addSecp256k1Points = (
  left: LocalSecp256k1Point,
  right: LocalSecp256k1Point,
): LocalSecp256k1Point => {
  if (left.z === 0n) return right;
  if (right.z === 0n) return left;
  const leftZSquared = fieldMod(left.z * left.z);
  const rightZSquared = fieldMod(right.z * right.z);
  const leftX = fieldMod(left.x * rightZSquared);
  const rightX = fieldMod(right.x * leftZSquared);
  const leftY = fieldMod(left.y * right.z * rightZSquared);
  const rightY = fieldMod(right.y * left.z * leftZSquared);
  const xDifference = fieldMod(rightX - leftX);
  const yDifference = fieldMod(rightY - leftY);
  if (xDifference === 0n) {
    return yDifference === 0n
      ? doubleSecp256k1Point(left)
      : SECP256K1_INFINITY;
  }
  const xDifferenceSquared = fieldMod(xDifference * xDifference);
  const xDifferenceCubed = fieldMod(
    xDifference * xDifferenceSquared,
  );
  const leftScaledX = fieldMod(leftX * xDifferenceSquared);
  const x = fieldMod(
    (yDifference * yDifference) - xDifferenceCubed - (2n * leftScaledX),
  );
  const y = fieldMod(
    (yDifference * (leftScaledX - x)) - (leftY * xDifferenceCubed),
  );
  const z = fieldMod(xDifference * left.z * right.z);
  return { x, y, z };
};

const multiplySecp256k1Point = (
  point: LocalSecp256k1Point,
  scalar: bigint,
): LocalSecp256k1Point => {
  let result = SECP256K1_INFINITY;
  let addend = point;
  let remaining = scalar;
  for (let bit = 0; bit < 256; bit += 1) {
    if ((remaining & 1n) === 1n) {
      result = addSecp256k1Points(result, addend);
    }
    remaining >>= 1n;
    if (bit < 255) addend = doubleSecp256k1Point(addend);
  }
  return remaining === 0n ? result : SECP256K1_INFINITY;
};

const affineSecp256k1Point = (
  point: LocalSecp256k1Point,
): Readonly<{ x: bigint; y: bigint }> | undefined => {
  if (point.z === 0n) return undefined;
  const inverseZ = modularPower(
    point.z,
    SECP256K1_FIELD - 2n,
    SECP256K1_FIELD,
  );
  const inverseZSquared = fieldMod(inverseZ * inverseZ);
  const x = fieldMod(point.x * inverseZSquared);
  const y = fieldMod(point.y * inverseZSquared * inverseZ);
  if (fieldMod((y * y) - (x * x * x) - 7n) !== 0n) return undefined;
  return { x, y };
};

const writeFieldElement = (
  target: Uint8Array,
  offset: number,
  value: bigint,
): void => {
  let remaining = value;
  for (let index = 31; index >= 0; index -= 1) {
    target[offset + index] = numberFrom(remaining & 0xffn);
    remaining >>= 8n;
  }
};

/** Package-internal strict EIP-191 recovery shared by Runtime and receipt verification. */
export const recoverPortableContentHashSigner = (
  contentHash: unknown,
  signature: unknown,
): string | undefined => {
  if (!isContentHash(contentHash) || !isSignature65(signature)) {
    return undefined;
  }
  try {
    const r = bigintFrom(`0x${stringSlice(signature, 2, 66)}`);
    const s = bigintFrom(`0x${stringSlice(signature, 66, 130)}`);
    const recovery = stringSlice(signature, 130, 132) === "1b" ? 0 : 1;
    const digest = portableEip191Digest(contentHash);
    const ySquared = (r * r % SECP256K1_FIELD * r + 7n) % SECP256K1_FIELD;
    const yRoot = modularPower(
      ySquared,
      (SECP256K1_FIELD + 1n) >> 2n,
      SECP256K1_FIELD,
    );
    if (yRoot * yRoot % SECP256K1_FIELD !== ySquared) return undefined;
    const rootIsOdd = (yRoot & 1n) === 1n;
    const y = rootIsOdd === (recovery === 1)
      ? yRoot
      : SECP256K1_FIELD - yRoot;
    const recoveredR: LocalSecp256k1Point = { x: r, y, z: 1n };
    const rInverse = modularPower(
      r,
      SECP256K1_ORDER - 2n,
      SECP256K1_ORDER,
    );
    const message = bigintFrom(digest) % SECP256K1_ORDER;
    const messageFactor = (
      (SECP256K1_ORDER - message) * rInverse
    ) % SECP256K1_ORDER;
    const signatureFactor = s * rInverse % SECP256K1_ORDER;
    const publicKey = addSecp256k1Points(
      multiplySecp256k1Point(recoveredR, signatureFactor),
      multiplySecp256k1Point(SECP256K1_BASE, messageFactor),
    );
    const affine = affineSecp256k1Point(publicKey);
    if (affine === undefined) return undefined;
    const publicKeyBytes = new HostUint8Array(64);
    writeFieldElement(publicKeyBytes, 0, affine.x);
    writeFieldElement(publicKeyBytes, 32, affine.y);
    return `0x${stringSlice(keccak256Bytes(publicKeyBytes), 26)}`;
  } catch {
    return undefined;
  }
};

export const verifyPortableRuntimeAuthorizationSignature = (
  expectedAddress: string,
  challenge: PortableRuntimeAuthorizationChallenge,
  signature: unknown,
): boolean => {
  if (!isEthereumAddress(expectedAddress) || !isSignature65(signature)) return false;
  try {
    const signer = recoverPortableContentHashSigner(
      hashPortableRuntimeAuthorizationChallenge(challenge),
      signature,
    );
    return signer !== undefined && signer === stringToLowerCase(expectedAddress);
  } catch {
    return false;
  }
};

/** Exact immutable intent content; actor-claimed time is intentionally absent. */
export const portableIntentProjection = (
  request: PortableActionRequest,
  binding: PortableConsequentialBinding,
  adapterProfile: PortableAdapterProfile,
): PortableTransactionIntent => {
  const actorId = request.actorId;
  const action = request.action;
  const resource = request.resource;
  const amount = ownOptional(request, "amount");
  const counterpartyId = ownOptional(request, "counterpartyId");
  const termsCommitment = ownOptional(request, "termsCommitment");
  const intentId = ownOptional(binding, "intentId");
  const nonce = ownOptional(binding, "nonce");
  const roleId = binding.roleId;
  const roleTenureId = binding.roleTenureId;
  if (intentId === undefined || nonce === undefined) {
    throw new TypeError("Intent projection requires intent and nonce identifiers.");
  }
  return Object.freeze({
    adapterProfile,
    intentId,
    nonce,
    actorId,
    action,
    resource,
    roleId,
    roleTenureId,
    ...(amount === undefined ? {} : { amount }),
    ...(counterpartyId === undefined ? {} : { counterpartyId }),
    ...(termsCommitment === undefined ? {} : { termsCommitment }),
  });
};

const sameOptionalScalar = <T extends object, K extends keyof T>(
  left: T,
  right: T,
  key: K,
): boolean => Object.hasOwn(left, key) === Object.hasOwn(right, key) &&
  (!Object.hasOwn(left, key) || left[key] === right[key]);

const sameIntent = (
  left: PortableTransactionIntent,
  right: PortableTransactionIntent,
): boolean => left.intentId === right.intentId &&
  left.nonce === right.nonce &&
  left.actorId === right.actorId &&
  left.action === right.action &&
  left.resource === right.resource &&
  left.roleId === right.roleId &&
  left.roleTenureId === right.roleTenureId &&
  sameOptionalScalar(left, right, "amount") &&
  sameOptionalScalar(left, right, "counterpartyId") &&
  sameOptionalScalar(left, right, "termsCommitment");

type AuthorityEvaluationContext = Readonly<{
  operationVersion: AuthorityOperationVersion;
  assurance: "SUPPLIED_SCOPE" | "REPLAY_VERIFIED";
  validated: ValidatedCorpus;
  domain: PortableAuthorizationDomain;
  policyVersion: string;
  historyHead: PortableHistoryHead;
  evaluationTime: number;
  request: PortableActionRequest;
  consequential: boolean;
  binding?: PortableConsequentialBinding;
  replayEvidence?: ReplayEvidenceContext;
  administrativeRequirements?: PortableAdministrativeRequirements;
}>;

const candidateMeetsAdministrativeRequirements = (
  validated: ValidatedCorpus,
  path: PermissionPath,
  requirements: PortableAdministrativeRequirements,
): boolean => {
  const root = recognizedRootForPath(validated, path);
  if (root?.principalId !== requirements.requiredPrincipalId) return false;
  const graph = selectCandidateGraph(validated, path, requirements.request.actorId);
  const controllingIds = createSet<string>();
  for (let pathIndex = 0; pathIndex < graph.paths.length; pathIndex += 1) {
    const selectedPath = graph.paths[pathIndex]!;
    for (let index = 0; index < selectedPath.grants.length; index += 1) {
      setAdd(controllingIds, selectedPath.grants[index]!.authorityId);
    }
  }
  for (let index = 0; index < requirements.requiredAuthorityIds.length; index += 1) {
    if (!setHas(controllingIds, requirements.requiredAuthorityIds[index]!)) {
      return false;
    }
  }
  return true;
};

const evaluateAuthorityAlgebra = (
  context: AuthorityEvaluationContext,
): AuthorityAlgebraResult => {
  const globalProhibitions = relevantGlobalProhibitions(
    context.validated,
    context.request,
  );
  const matchingGlobal = createSet<string>();
  for (let index = 0; index < globalProhibitions.length; index += 1) {
    const prohibition = globalProhibitions[index]!;
    if (
      prohibitionIsActive(
        context.validated,
        prohibition,
        context.evaluationTime,
      ) &&
      prohibitionMatchesAmount(prohibition, context.request)
    ) setAdd(matchingGlobal, prohibition.authorityId);
  }
  const globalFailure = leastIdentifier(matchingGlobal);
  if (globalFailure !== undefined) {
    const evidence = context.replayEvidence === undefined
      ? Object.freeze([])
      : authorityDecisionEvidence(context.replayEvidence);
    return boundedResult(
      denialResult(
        context.operationVersion,
        context.assurance,
        Object.freeze([
          Object.freeze({
            code: "PROHIBITED" as const,
            subjectId: context.request.actorId,
            failingAuthorityId: globalFailure,
            authorityPathIds: Object.freeze([]),
            evidence,
          }),
        ]),
      ),
      context.operationVersion,
      context.assurance,
    );
  }

  const candidates: PermissionPath[] = [];
  mapForEach(context.validated.paths, (path) => {
    const terminal = path.grants[path.grants.length - 1]!;
    if (
      path.effectivelyIndependent &&
      terminal.granteeId === context.request.actorId &&
      (context.administrativeRequirements === undefined ||
        candidateMeetsAdministrativeRequirements(
          context.validated,
          path,
          context.administrativeRequirements,
        ))
    ) arrayPush(candidates, path);
  });
  let winner: SuccessfulAuthorityCandidate | undefined;
  const candidateFailures: Array<{
    evaluation: Extract<CandidateEvaluation, { status: "FAILURE" }>;
    path: PermissionPath;
  }> = [];
  for (let index = 0; index < candidates.length; index += 1) {
    const candidate = candidates[index]!;
    const evaluation = evaluateCandidate(
      context.validated,
      candidate,
      context.request,
      context.evaluationTime,
      globalProhibitions,
    );
    if (evaluation.status === "SUCCESS") {
      const successful = candidatePlan(context, evaluation);
      if (
        winner === undefined ||
        compareSuccessfulCandidates(successful, winner) < 0
      ) winner = successful;
    } else {
      arrayPush(candidateFailures, { evaluation, path: candidate });
    }
  }
  if (winner !== undefined) return winner;

  const decisionEvidence = context.replayEvidence === undefined
    ? Object.freeze([])
    : authorityDecisionEvidence(context.replayEvidence);
  if (candidateFailures.length === 0) {
    return boundedResult(
      simpleDenial(
        context.operationVersion,
        context.assurance,
        "NO_AUTHORITY",
        decisionEvidence,
        context.request.actorId,
      ),
      context.operationVersion,
      context.assurance,
    );
  }
  const failures: PortableDenialEvidence[] = [];
  for (let index = 0; index < candidateFailures.length; index += 1) {
    const failure = candidateFailures[index]!;
    const terminal = failure.path.grants[failure.path.grants.length - 1]!;
    arrayPush(failures, Object.freeze({
      code: failure.evaluation.code,
      rootAuthorityId: failure.path.rootAuthorityId,
      terminalAuthorityId: terminal.authorityId,
      failingAuthorityId: failure.evaluation.failingAuthorityId,
      authorityPathIds: failure.path.authorityIds,
      evidence: decisionEvidence,
    }));
  }
  return boundedResult(
    denialResult(
      context.operationVersion,
      context.assurance,
      Object.freeze(failures),
    ),
    context.operationVersion,
    context.assurance,
  );
};

/**
 * Raw supplied-scope authority evaluation. It never claims consequential or
 * replay-verified authority.
 */
export const evaluatePortableAuthorityPath = (
  input: unknown,
): PortableAuthorizationResult => {
  const operationVersion = PORTABLE_AUTHORITY_EVALUATION_VERSION;
  const captured = capturePortableAuthorityOperation(
    input,
    "AUTHORITY_PATH_EVALUATION",
  );
  if (captured.status !== "CAPTURED") {
    return indeterminate(
      operationVersion,
      captured.status === "UNSUPPORTED_VERSION"
        ? "UNSUPPORTED_VERSION"
        : "INVALID_INPUT",
    );
  }
  const capture = captured.capture;
  const body = capture.value;
  const scopeValue = body.scope;
  const requestValue = body.request;
  if (
    !rawCaptureTimeCollectionsAreValid(capture) ||
    !exactRecord(
      capture,
      scopeValue,
      Object.freeze([
        "domain",
        "policyVersion",
        "rootRecognitionPolicy",
        "historyHead",
        "evaluationTime",
        "recognizedRoots",
        "globalPolicySourceId",
      ]),
    ) ||
    !domainIsValid(capture, scopeValue.domain) ||
    !historyHeadIsValid(capture, scopeValue.historyHead) ||
    !Array.isArray(scopeValue.recognizedRoots) ||
    identifierStatus(scopeValue.policyVersion) !== "VALID" ||
    identifierStatus(scopeValue.rootRecognitionPolicy) !== "VALID" ||
    identifierStatus(scopeValue.globalPolicySourceId) !== "VALID" ||
    !requestHasExactShape(capture, requestValue)
  ) {
    return indeterminate(operationVersion, "INVALID_INPUT");
  }
  if (!isU53(scopeValue.evaluationTime)) {
    return indeterminate(operationVersion, "CAUSAL_TIME_INVALID");
  }
  const scope = scopeValue as unknown as PortableAuthorityPathEvaluationInput["scope"];
  const request = requestValue as unknown as PortableActionRequest;
  if (scope.evaluationTime < scope.historyHead.canonicalTime) {
    return indeterminate(operationVersion, "CAUSAL_TIME_INVALID");
  }
  if (scope.rootRecognitionPolicy !== PORTABLE_ROOT_RECOGNITION_POLICY) {
    return simpleDenial(
      operationVersion,
      "SUPPLIED_SCOPE",
      "POLICY_MISMATCH",
    );
  }
  const requestFailure = requestProblem(requestValue);
  if (requestFailure !== undefined) {
    return simpleDenial(
      operationVersion,
      "SUPPLIED_SCOPE",
      requestFailure,
    );
  }
  const construction = rawCorpusFromCapture(capture);
  if (construction.status === "INVALID_INPUT") {
    return indeterminate(operationVersion, "INVALID_INPUT");
  }
  if (construction.status === "INVALID_DELEGATION") {
    return simpleDenial(
      operationVersion,
      "SUPPLIED_SCOPE",
      "INVALID_DELEGATION",
    );
  }
  const validation = validateAuthorityCorpus(construction.corpus);
  if (validation.status === "INVALID_INPUT") {
    return indeterminate(operationVersion, "INVALID_INPUT");
  }
  if (validation.status === "INVALID_DELEGATION") {
    return simpleDenial(
      operationVersion,
      "SUPPLIED_SCOPE",
      "INVALID_DELEGATION",
    );
  }
  const authority = evaluateAuthorityAlgebra(Object.freeze({
    operationVersion,
    assurance: "SUPPLIED_SCOPE" as const,
    validated: validation.value,
    domain: scope.domain,
    policyVersion: scope.policyVersion,
    historyHead: scope.historyHead,
    evaluationTime: scope.evaluationTime,
    request,
    consequential: false,
  }));
  return authority.decision === "ALLOW_CANDIDATE"
    ? finalizeSuccessfulAuthorityCandidate(authority)
    : authority;
};

type PortableStateAuthorizationInput = Readonly<{
  expectedHistoryHead: PortableHistoryHead;
  domain: PortableAuthorizationDomain;
  policyVersion: string;
  rootRecognitionPolicy: string;
  request: Record<string, unknown>;
  evaluationTime: unknown;
  consequential: boolean;
  binding?: PortableConsequentialBinding;
}>;

const stagePortableStateAuthorization = (
  state: PortableAuthorityReplayState,
  body: PortableStateAuthorizationInput,
  administrativeRequirements?: PortableAdministrativeRequirements,
): AuthorityAlgebraResult => {
  const operationVersion = PORTABLE_AUTHORIZATION_VERSION;
  const requestValue = body.request;
  const bindingValue = body.binding;
  const consequential = body.consequential;
  const binding = bindingValue;
  const evidenceContext = createReplayEvidenceContext(state);
  const expectedHistoryHead = body.expectedHistoryHead as PortableHistoryHead;
  const headEvidence = Object.freeze([
    replayEventReference(evidenceContext, state.events.length - 1),
  ]);
  if (!sameHistoryHead(expectedHistoryHead, state.head)) {
    return indeterminate(
      operationVersion,
      "HISTORY_RELATION_UNVERIFIED",
      "SUPPLIED_SCOPE",
      headEvidence,
    );
  }
  if (
    !isU53(body.evaluationTime) ||
    body.evaluationTime < state.head.canonicalTime
  ) {
    return indeterminate(
      operationVersion,
      "CAUSAL_TIME_INVALID",
      "SUPPLIED_SCOPE",
      headEvidence,
    );
  }

  const assurance = "REPLAY_VERIFIED" as const;
  const domain = body.domain as PortableAuthorizationDomain;
  const policyVersion = body.policyVersion as string;
  const evaluationTime = body.evaluationTime;
  const request = requestValue as unknown as PortableActionRequest;
  const genesisEvidence = Object.freeze([
    replayEventReference(evidenceContext, 0),
  ]);
  const replayDenial = (
    code: PortableDenialCode,
    evidence: readonly PortableEvidenceReference[] = Object.freeze([]),
    subjectId?: string,
  ): PortableAuthorizationResult => boundedResult(
    simpleDenial(
      operationVersion,
      assurance,
      code,
      evidence,
      subjectId,
    ),
    operationVersion,
    assurance,
  );

  if (!sameDomain(domain, state.genesis.domain)) {
    return replayDenial("DOMAIN_MISMATCH", genesisEvidence);
  }
  if (
    policyVersion !== state.genesis.policyVersion ||
    body.rootRecognitionPolicy !== state.genesis.rootRecognitionPolicy
  ) return replayDenial("POLICY_MISMATCH", genesisEvidence);

  const requestFailure = requestProblem(requestValue);
  if (requestFailure !== undefined) return replayDenial(requestFailure);

  const corpusValidation = validateAuthorityCorpus(replayCorpus(state));
  if (corpusValidation.status === "INVALID_INPUT") {
    return indeterminate(
      operationVersion,
      "STATE_NOT_AUTHORITATIVE",
      "SUPPLIED_SCOPE",
    );
  }
  if (corpusValidation.status === "INVALID_DELEGATION") {
    return replayDenial(
      "INVALID_DELEGATION",
      authorityDecisionEvidence(evidenceContext),
    );
  }

  const replayAgents = ownOptional(
    corpusValidation.value.corpus,
    "replayAgents",
  );
  const agent = replayAgents === undefined
    ? undefined
    : mapGet(replayAgents, request.actorId);
  if (agent === undefined || agent.terminated) {
    return replayDenial(
      "AGENT_INACTIVE",
      agentLifecycleEvidence(evidenceContext, request.actorId),
      request.actorId,
    );
  }

  if (consequential && binding !== undefined) {
    const session = mapGet(state.runtimeSessions, binding.runtimeSessionId);
    if (session === undefined || session.agentId !== agent.id) {
      return replayDenial(
        "SESSION_NOT_FOUND",
        sessionLifecycleEvidence(
          evidenceContext,
          request.actorId,
          binding.runtimeSessionId,
        ),
        binding.runtimeSessionId,
      );
    }
    if (
      ownOptional(session, "expiresAt") !== undefined &&
      evaluationTime >= session.expiresAt!
    ) {
      return replayDenial(
        "SESSION_EXPIRED",
        sessionLifecycleEvidence(
          evidenceContext,
          request.actorId,
          binding.runtimeSessionId,
        ),
        binding.runtimeSessionId,
      );
    }
    const credentialKeyId = ownOptional(binding, "credentialKeyId");
    const runtimeSignature = ownOptional(binding, "runtimeSignature");
    if (credentialKeyId === undefined || runtimeSignature === undefined) {
      return replayDenial(
        "SESSION_CREDENTIAL_REQUIRED",
        sessionLifecycleEvidence(
          evidenceContext,
          request.actorId,
          binding.runtimeSessionId,
        ),
        binding.runtimeSessionId,
      );
    }
    if (credentialKeyId !== session.credentialKeyId) {
      return replayDenial(
        "SESSION_CREDENTIAL_INVALID",
        sessionLifecycleEvidence(
          evidenceContext,
          request.actorId,
          binding.runtimeSessionId,
        ),
        binding.runtimeSessionId,
      );
    }
    const intentId = ownOptional(binding, "intentId");
    const nonce = ownOptional(binding, "nonce");
    if (intentId !== undefined && nonce !== undefined) {
      const challenge = createPortableRuntimeAuthorizationChallenge({
        domain,
        request,
        evaluationTime,
        policyVersion,
        historyHead: state.head,
        binding,
      });
      if (!verifyPortableRuntimeAuthorizationSignature(
        session.credentialAddressKey,
        challenge,
        runtimeSignature,
      )) {
        return replayDenial(
          "SESSION_CREDENTIAL_INVALID",
          sessionLifecycleEvidence(
            evidenceContext,
            request.actorId,
            binding.runtimeSessionId,
          ),
          binding.runtimeSessionId,
        );
      }
    }
    if (session.controlEpoch < agent.currentControlEpoch) {
      return replayDenial(
        "SESSION_FENCED",
        sessionLifecycleEvidence(
          evidenceContext,
          request.actorId,
          binding.runtimeSessionId,
        ),
        binding.runtimeSessionId,
      );
    }
    if (
      binding.controlEpoch !== session.controlEpoch ||
      binding.controlEpoch !== agent.currentControlEpoch
    ) {
      return replayDenial(
        "STALE_EPOCH",
        sessionLifecycleEvidence(
          evidenceContext,
          request.actorId,
          binding.runtimeSessionId,
        ),
        binding.runtimeSessionId,
      );
    }
    const role = mapGet(state.roles, binding.roleId);
    const tenure = mapGet(state.tenures, binding.roleTenureId);
    if (
      role === undefined ||
      tenure === undefined ||
      ownOptional(role, "currentTenureId") !== binding.roleTenureId ||
      tenure.closed ||
      tenure.roleId !== binding.roleId ||
      tenure.agentId !== agent.id
    ) {
      return replayDenial(
        "ROLE_TENURE_NOT_CURRENT",
        tenureLifecycleEvidence(
          evidenceContext,
          binding.roleId,
          binding.roleTenureId,
        ),
        binding.roleTenureId,
      );
    }

    if (intentId === undefined || nonce === undefined) {
      return replayDenial(
        "INTENT_REQUIRED",
        intentDecisionEvidence(evidenceContext, request.actorId),
        request.actorId,
      );
    }
    const declaration = mapGet(state.intentDeclarations, intentId);
    if (declaration === undefined) {
      return replayDenial(
        "INTENT_NOT_DECLARED",
        intentDecisionEvidence(
          evidenceContext,
          request.actorId,
          intentId,
          nonce,
        ),
        intentId,
      );
    }
    const projection = portableIntentProjection(request, binding, declaration.data.adapterProfile);
    if (!sameIntent(declaration.data, projection)) {
      return replayDenial(
        "INTENT_MISMATCH",
        intentDecisionEvidence(
          evidenceContext,
          request.actorId,
          intentId,
          nonce,
        ),
        intentId,
      );
    }
    if (mapHas(state.intentAdmissions, intentId)) {
      return replayDenial(
        "INTENT_REPLAY",
        intentDecisionEvidence(
          evidenceContext,
          request.actorId,
          intentId,
          nonce,
        ),
        intentId,
      );
    }
  }

  return evaluateAuthorityAlgebra(Object.freeze({
    operationVersion,
    assurance,
    validated: corpusValidation.value,
    domain,
    policyVersion,
    historyHead: state.head,
    evaluationTime,
    request,
    consequential,
    ...(binding === undefined ? {} : { binding }),
    replayEvidence: evidenceContext,
    ...(administrativeRequirements === undefined
      ? {}
      : { administrativeRequirements }),
  }));
};

/**
 * Package-internal policy component for a signed administrative event. Replay
 * owns input capture and state provenance; this proof alone grants no authority
 * to append an event and never reserves a nonce or controlling capacity.
 */
export const createPortableAdministrativePolicyProof = (
  state: PortableAuthorityReplayState,
  requirements: PortableAdministrativeRequirements,
  evaluationTime: number,
): PortableAuthorizationProof | undefined => {
  if (Object.hasOwn(requirements.request, "amount")) return undefined;
  const candidate = stagePortableStateAuthorization(state, Object.freeze({
    expectedHistoryHead: state.head,
    domain: state.genesis.domain,
    policyVersion: state.genesis.policyVersion,
    rootRecognitionPolicy: state.genesis.rootRecognitionPolicy,
    request: requirements.request as unknown as Record<string, unknown>,
    evaluationTime,
    consequential: false,
  }), requirements);
  if (candidate.decision !== "ALLOW_CANDIDATE") return undefined;

  // The administrative restriction applies to the ordinary canonical winner.
  // A capped winner cannot silently fall through to a second candidate.
  const paths = candidate.evaluation.graph.paths;
  for (let pathIndex = 0; pathIndex < paths.length; pathIndex += 1) {
    const path = paths[pathIndex]!;
    for (let index = 0; index < path.grants.length; index += 1) {
      const constraints = path.grants[index]!.constraints;
      if (
        constraints.quantitative ||
        Object.hasOwn(constraints, "maxAmount") ||
        Object.hasOwn(constraints, "maxCumulativeAmount") ||
        Object.hasOwn(constraints, "maxTransactions")
      ) return undefined;
    }
  }
  const authorization = finalizeSuccessfulAuthorityCandidate(candidate);
  if (
    authorization.decision !== "ALLOW" ||
    authorization.scopeAssurance !== "REPLAY_VERIFIED" ||
    authorization.consequential ||
    authorization.proof.usageSnapshot.length !== 0
  ) return undefined;
  return authorization.proof;
};

/** Validate a closed administrative event against replay's exact prior state. */
export const validatePortableAdministrativeTransition = (
  state: PortableAuthorityReplayState,
  event: AcceptedCanonicalEventShape,
  requirements: PortableAdministrativeRequirements,
): boolean => {
  if (
    event.type !== "OBLIGATION_CREATED" &&
    event.type !== "OBLIGATION_PERFORMANCE_ASSIGNED" &&
    event.type !== "OBLIGATION_STATUS_RECORDED" &&
    event.type !== "OUTCOME_OBSERVATION_RECORDED" &&
    event.type !== "ATTEMPT_DUTY_CREATED" &&
    event.type !== "ATTEMPT_DUTY_ASSIGNED" &&
    event.type !== "ATTEMPT_DUTY_REVIEW_CLOSED"
  ) return false;
  if ((event.type === "OUTCOME_OBSERVATION_RECORDED" || event.type === "ATTEMPT_DUTY_CREATED" ||
      event.type === "ATTEMPT_DUTY_ASSIGNED") && state.genesis.adapterPolicyHash !== PORTABLE_ADAPTER_POLICY_E5_HASH &&
      state.genesis.adapterPolicyHash !== PORTABLE_ADAPTER_POLICY_E6_HASH) return false;
  if (event.type === "ATTEMPT_DUTY_REVIEW_CLOSED" && state.genesis.adapterPolicyHash !== PORTABLE_ADAPTER_POLICY_E6_HASH) return false;
  const data = event.data as Readonly<Record<string, unknown>>;
  const wrapper = data.administrativeAuthorization as PortableAdministrativeAuthorization;
  const challenge = wrapper.challenge;
  const proof = wrapper.authorityProof;
  if (
    canonicalEncode(challenge.domain) !== canonicalEncode(state.genesis.domain) ||
    canonicalEncode(proof.domain) !== canonicalEncode(state.genesis.domain) ||
    canonicalEncode(challenge.request) !== canonicalEncode(requirements.request) ||
    challenge.request.actorId !== data.actorId ||
    challenge.policyVersion !== state.genesis.policyVersion ||
    challenge.rootRecognitionPolicy !== state.genesis.rootRecognitionPolicy ||
    challenge.eventHistoryHash !== state.head.hash ||
    challenge.eventHistoryPosition !== state.head.position ||
    challenge.evaluationTime !== event.timestamp ||
    challenge.transitionEventId !== event.id ||
    challenge.transitionEventType !== event.type ||
    challenge.transitionEffectHash !== hashCanonical(portableAdministrativeTransitionEffect(event)) ||
    challenge.authorityProofHash !== hashCanonical(proof) ||
    challenge.roleId !== requirements.roleId ||
    challenge.roleTenureId !== requirements.roleTenureId
  ) return false;

  const actor = mapGet(state.agents, requirements.request.actorId);
  const session = mapGet(state.runtimeSessions, challenge.runtimeSessionId);
  const role = mapGet(state.roles, requirements.roleId);
  const tenure = mapGet(state.tenures, requirements.roleTenureId);
  if (
    actor === undefined || actor.terminated ||
    session === undefined || session.agentId !== actor.id ||
    (session.expiresAt !== undefined && event.timestamp >= session.expiresAt) ||
    session.credentialKeyId !== challenge.credentialKeyId ||
    session.controlEpoch !== challenge.controlEpoch ||
    actor.currentControlEpoch !== challenge.controlEpoch ||
    role === undefined || role.currentTenureId !== requirements.roleTenureId ||
    tenure === undefined || tenure.closed ||
    tenure.roleId !== requirements.roleId || tenure.agentId !== actor.id
  ) return false;
  // Accepted replay enforces one active Session per Agent/current Epoch at
  // admission. With nondecreasing canonical time, none can become active again.
  if (recoverPortableContentHashSigner(hashCanonical(challenge), wrapper.runtimeSignature) !==
    session.credentialAddressKey) return false;

  const expected = createPortableAdministrativePolicyProof(state, requirements, event.timestamp);
  return expected !== undefined && canonicalEncode(expected) === canonicalEncode(proof);
};

const occupiedCandidateNonceDenial = (
  state: PortableAuthorityReplayState,
  candidate: SuccessfulAuthorityCandidate,
): PortableAuthorizationResult | undefined => {
  const context = candidate.context;
  const binding = ownOptional(context, "binding");
  if (!context.consequential || binding === undefined) return undefined;
  const nonce = ownOptional(binding, "nonce");
  if (nonce === undefined) return undefined;
  const actorReservations = mapGet(
    state.nonceReservationsByActor,
    context.request.actorId,
  );
  if (actorReservations === undefined || !mapHas(actorReservations, nonce)) {
    return undefined;
  }
  const evidenceContext = ownOptional(context, "replayEvidence");
  if (evidenceContext === undefined) {
    throw new TypeError("Replay authority candidate lost evidence context.");
  }
  return boundedResult(
    simpleDenial(
      context.operationVersion,
      context.assurance,
      "NONCE_ALREADY_ADMITTED",
      intentDecisionEvidence(
        evidenceContext,
        context.request.actorId,
        ownOptional(binding, "intentId"),
        nonce,
      ),
      nonce,
    ),
    context.operationVersion,
    context.assurance,
  );
};

const authorizePortableState = (
  state: PortableAuthorityReplayState,
  body: PortableStateAuthorizationInput,
): PortableAuthorizationResult => {
  const authority = stagePortableStateAuthorization(state, body);
  if (authority.decision !== "ALLOW_CANDIDATE") return authority;
  const nonceDenial = occupiedCandidateNonceDenial(state, authority);
  return nonceDenial ?? finalizeSuccessfulAuthorityCandidate(authority);
};

export type PortableReplayAuthorizationDeny = Extract<
  PortableAuthorizationResult,
  { decision: "DENY" }
>;

export type PortableReplayAuthorizationIndeterminate = Extract<
  PortableAuthorizationResult,
  { decision: "INDETERMINATE" }
>;

/** Evaluate one provenance-bound, structurally captured AUTHORIZE body. */
export const capturedPortableAuthorizeInputIsStructurallyValid = (
  capture: CapturedPortableAuthorityInput,
): boolean => {
  if (!isCapturedCanonicalAuthorityOperation(capture)) {
    throw new TypeError("Portable authority capture lost provenance.");
  }
  const body = capture.value;
  const requestValue = body.request;
  const bindingValue = body.binding;
  if (
    !Array.isArray(body.events) ||
    !domainIsValid(capture, body.domain) ||
    !historyHeadIsValid(capture, body.expectedHistoryHead) ||
    identifierStatus(body.policyVersion) !== "VALID" ||
    identifierStatus(body.rootRecognitionPolicy) !== "VALID" ||
    !requestHasExactShape(capture, requestValue) ||
    body.authoritative !== true ||
    typeof body.consequential !== "boolean"
  ) return false;
  const hasBinding = Object.hasOwn(body, "binding");
  return !(
    hasBinding !== body.consequential ||
    (hasBinding && !bindingIsStructurallyValid(capture, bindingValue))
  );
};

/** Evaluate one provenance-bound, structurally captured AUTHORIZE body. */
export const authorizeCapturedPortableState = (
  capture: CapturedPortableAuthorityInput,
  state: PortableAuthorityReplayState,
): PortableAuthorizationResult => {
  const operationVersion = PORTABLE_AUTHORIZATION_VERSION;
  if (!capturedPortableAuthorizeInputIsStructurallyValid(capture)) {
    return indeterminate(operationVersion, "INVALID_INPUT");
  }
  const body = capture.value;
  const requestValue = body.request as Record<string, unknown>;
  const bindingValue = body.binding;
  const hasBinding = Object.hasOwn(body, "binding");
  return authorizePortableState(state, Object.freeze({
    expectedHistoryHead: body.expectedHistoryHead as PortableHistoryHead,
    domain: body.domain as PortableAuthorizationDomain,
    policyVersion: body.policyVersion as string,
    rootRecognitionPolicy: body.rootRecognitionPolicy as string,
    request: requestValue,
    evaluationTime: body.evaluationTime,
    consequential: body.consequential as boolean,
    ...(hasBinding
      ? { binding: bindingValue as PortableConsequentialBinding }
      : {}),
  }));
};

export type PortableIntentAdmissionStateEvaluation =
  | Readonly<{
      status: "AUTHORIZED";
      authorization: PortableAuthorizationProof;
      admissionEventId: string;
      expectedHead: PortableHistoryHead;
      evaluationTime: number;
      binding: PortableConsequentialBinding & Readonly<{
        credentialKeyId: string;
        intentId: string;
        nonce: string;
        runtimeSignature: `0x${string}`;
      }>;
    }>
  | Readonly<{
      status: "RETRY";
      intentId: string;
      existingAdmissionEventId: string;
      existingAdmissionHead: PortableHistoryHead;
    }>
  | Readonly<{
      status: "DENIED";
      authorization: PortableReplayAuthorizationDeny;
    }>
  | Readonly<{
      status: "INDETERMINATE";
      authorization: PortableReplayAuthorizationIndeterminate;
    }>
  | Readonly<{
      status: "CONFLICT";
      expectedHead: PortableHistoryHead;
      observedHead: PortableHistoryHead;
    }>;

const admissionAuthorizationBranch = (
  result: PortableAuthorizationResult,
): Extract<
  PortableIntentAdmissionStateEvaluation,
  { status: "DENIED" | "INDETERMINATE" }
> => result.decision === "DENY"
  ? Object.freeze({ status: "DENIED" as const, authorization: result })
  : Object.freeze({ status: "INDETERMINATE" as const, authorization: result as
      PortableReplayAuthorizationIndeterminate });

const collidingEventEvidence = (
  context: ReplayEvidenceContext,
  eventId: string,
): readonly PortableEvidenceReference[] => {
  const evidence: PortableEvidenceReference[] = [];
  for (let index = 0; index < context.state.events.length; index += 1) {
    if (context.state.events[index]!.id === eventId) {
      arrayPush(evidence, replayEventReference(context, index));
      break;
    }
  }
  arrayPush(
    evidence,
    replayEventReference(context, context.state.events.length - 1),
  );
  return sortedDistinctEventReferences(evidence);
};

/**
 * Exact pre-proposal admission state machine after one caller capture and one
 * authoritative replay. Prospective event capture/replay remains in the outer
 * admission façade to keep this engine below replay at runtime.
 */
export const capturedPortableIntentAdmissionInputIsStructurallyValid = (
  capture: CapturedPortableAuthorityInput,
): boolean => {
  if (!isCapturedCanonicalAuthorityOperation(capture)) {
    throw new TypeError("Portable admission capture lost provenance.");
  }
  const body = capture.value;
  const requestValue = body.request;
  const bindingValue = body.binding;
  return Array.isArray(body.events) &&
    domainIsValid(capture, body.domain) &&
    historyHeadIsValid(capture, body.expectedHistoryHead) &&
    identifierStatus(body.admissionEventId) === "VALID" &&
    identifierStatus(body.policyVersion) === "VALID" &&
    requestHasExactShape(capture, requestValue) &&
    bindingIsStructurallyValid(capture, bindingValue);
};

export const evaluateCapturedPortableIntentAdmissionState = (
  capture: CapturedPortableAuthorityInput,
  state: PortableAuthorityReplayState,
): PortableIntentAdmissionStateEvaluation => {
  const operationVersion = PORTABLE_AUTHORIZATION_VERSION;
  if (!capturedPortableIntentAdmissionInputIsStructurallyValid(capture)) {
    return Object.freeze({
      status: "INDETERMINATE" as const,
      authorization: indeterminate(operationVersion, "INVALID_INPUT") as
        PortableReplayAuthorizationIndeterminate,
    });
  }
  const body = capture.value;
  const requestValue = body.request as Record<string, unknown>;
  const bindingValue = body.binding;

  const evidenceContext = createReplayEvidenceContext(state);
  const headEvidence = Object.freeze([
    replayEventReference(evidenceContext, state.events.length - 1),
  ]);
  if (
    !isU53(body.evaluationTime) ||
    body.evaluationTime < state.head.canonicalTime
  ) {
    return Object.freeze({
      status: "INDETERMINATE" as const,
      authorization: indeterminate(
        operationVersion,
        "CAUSAL_TIME_INVALID",
        "SUPPLIED_SCOPE",
        headEvidence,
      ) as PortableReplayAuthorizationIndeterminate,
    });
  }

  const domain = body.domain as PortableAuthorizationDomain;
  const policyVersion = body.policyVersion as string;
  const expectedHead = body.expectedHistoryHead as PortableHistoryHead;
  const request = requestValue as unknown as PortableActionRequest;
  const binding = bindingValue as PortableConsequentialBinding;
  const scopeMatches = sameDomain(domain, state.genesis.domain) &&
    policyVersion === state.genesis.policyVersion &&
    state.genesis.rootRecognitionPolicy === PORTABLE_ROOT_RECOGNITION_POLICY;
  const requestFailure = requestProblem(requestValue);
  const intentId = ownOptional(binding, "intentId");
  const nonce = ownOptional(binding, "nonce");
  const declaration = intentId === undefined
    ? undefined
    : mapGet(state.intentDeclarations, intentId);
  const retryProjection = scopeMatches &&
      requestFailure === undefined &&
      intentId !== undefined &&
      nonce !== undefined &&
      declaration !== undefined
    ? portableIntentProjection(request, binding, declaration.data.adapterProfile)
    : undefined;
  if (
    retryProjection !== undefined &&
    sameIntent(declaration!.data, retryProjection)
  ) {
    const existing = mapGet(state.intentAdmissions, intentId!);
    if (existing !== undefined) {
      return Object.freeze({
        status: "RETRY" as const,
        intentId: intentId!,
        existingAdmissionEventId: existing.admissionEventId,
        existingAdmissionHead: existing.admissionHead,
      });
    }
  }

  if (!sameHistoryHead(expectedHead, state.head)) {
    return Object.freeze({
      status: "CONFLICT" as const,
      expectedHead,
      observedHead: state.head,
    });
  }

  if (
    scopeMatches &&
    requestFailure === undefined &&
    intentId !== undefined &&
    nonce !== undefined &&
    declaration !== undefined &&
    !sameIntent(
      declaration.data,
      portableIntentProjection(request, binding, declaration.data.adapterProfile),
    )
  ) {
    const mismatch = boundedResult(
      simpleDenial(
        operationVersion,
        "REPLAY_VERIFIED",
        "INTENT_MISMATCH",
        intentDecisionEvidence(
          evidenceContext,
          request.actorId,
          intentId,
          nonce,
        ),
        intentId,
      ),
      operationVersion,
      "REPLAY_VERIFIED",
    );
    return admissionAuthorizationBranch(mismatch);
  }

  const authority = stagePortableStateAuthorization(state, Object.freeze({
    expectedHistoryHead: expectedHead,
    domain,
    policyVersion,
    rootRecognitionPolicy: PORTABLE_ROOT_RECOGNITION_POLICY,
    request: requestValue,
    evaluationTime: body.evaluationTime,
    consequential: true,
    binding,
  }));
  if (authority.decision !== "ALLOW_CANDIDATE") {
    return admissionAuthorizationBranch(authority);
  }
  const nonceDenial = occupiedCandidateNonceDenial(state, authority);
  if (nonceDenial !== undefined) {
    return admissionAuthorizationBranch(nonceDenial);
  }

  const completeCredentialKeyId = ownOptional(binding, "credentialKeyId");
  const completeIntentId = ownOptional(binding, "intentId");
  const completeNonce = ownOptional(binding, "nonce");
  const completeSignature = ownOptional(binding, "runtimeSignature");
  if (
    completeCredentialKeyId === undefined ||
    completeIntentId === undefined ||
    completeNonce === undefined ||
    completeSignature === undefined
  ) {
    throw new TypeError("Portable admission ALLOW lost consequential binding fields.");
  }

  const admissionEventId = body.admissionEventId as string;
  for (let index = 0; index < state.events.length; index += 1) {
    if (state.events[index]!.id !== admissionEventId) continue;
    const collision = boundedResult(
      indeterminate(
        operationVersion,
        "INVALID_INPUT",
        "REPLAY_VERIFIED",
        collidingEventEvidence(evidenceContext, admissionEventId),
        admissionEventId,
      ),
      operationVersion,
      "REPLAY_VERIFIED",
    );
    return Object.freeze({
      status: "INDETERMINATE" as const,
      authorization: collision as PortableReplayAuthorizationIndeterminate,
    });
  }

  const authorization = finalizeSuccessfulAuthorityCandidate(authority);
  if (authorization.decision !== "ALLOW") {
    return admissionAuthorizationBranch(authorization);
  }

  return Object.freeze({
    status: "AUTHORIZED" as const,
    authorization: authorization.proof,
    admissionEventId,
    expectedHead,
    evaluationTime: body.evaluationTime,
    binding: Object.freeze({
      ...binding,
      credentialKeyId: completeCredentialKeyId,
      intentId: completeIntentId,
      nonce: completeNonce,
      runtimeSignature: completeSignature,
    }),
  });
};

export type PortableAdmissionTransitionValidation =
  | Readonly<{
      status: "VALID";
      intentId: string;
      actorId: string;
      nonce: string;
      usage: readonly PortableAuthorityUsage[];
    }>
  | Readonly<{ status: "INVALID" }>;

const invalidAdmissionTransition = Object.freeze({
  status: "INVALID" as const,
});

/**
 * Replay-side validation of the complete stored admission evidence at its
 * exact pre-event state. The returned reservations are applied atomically by
 * replay only after every predicate succeeds.
 */
export const validatePortableIntentAdmissionTransition = (
  state: PortableAuthorityReplayState,
  event: AcceptedCanonicalEventShape,
): PortableAdmissionTransitionValidation => {
  if (event.type !== "TRANSACTION_INTENT_ADMITTED") {
    return invalidAdmissionTransition;
  }
  const data = event.data as Readonly<Record<string, unknown>>;
  const proof = data.authorizationProof as PortableAuthorizationProof;
  if (
    event.timestamp !== data.evaluationTime ||
    data.evaluationTime !== proof.evaluationTime ||
    data.intentId !== proof.intentId ||
    !sameHistoryHead(
      data.expectedHistoryHead as PortableHistoryHead,
      state.head,
    ) ||
    !sameHistoryHead(proof.historyHead, state.head) ||
    proof.consequential !== true ||
    proof.rootRecognitionPolicy !== PORTABLE_ROOT_RECOGNITION_POLICY
  ) return invalidAdmissionTransition;

  const runtimeSignature = data.runtimeSignature;
  if (!isSignature65(runtimeSignature)) return invalidAdmissionTransition;
  const binding: PortableConsequentialBinding = Object.freeze({
    runtimeSessionId: proof.runtimeSessionId!,
    credentialKeyId: proof.credentialKeyId!,
    controlEpoch: proof.controlEpoch!,
    roleId: proof.roleId!,
    roleTenureId: proof.roleTenureId!,
    intentId: proof.intentId!,
    nonce: proof.nonce!,
    runtimeSignature,
  });
  const challenge = createPortableRuntimeAuthorizationChallenge({
    domain: proof.domain,
    request: proof.request,
    evaluationTime: proof.evaluationTime,
    policyVersion: proof.policyVersion,
    historyHead: state.head,
    binding,
  });
  if (
    data.runtimeAuthorizationHash !==
      hashPortableRuntimeAuthorizationChallenge(challenge)
  ) return invalidAdmissionTransition;

  const actor = mapGet(state.agents, proof.request.actorId);
  const session = mapGet(state.runtimeSessions, proof.runtimeSessionId!);
  if (
    actor === undefined ||
    session === undefined ||
    session.agentId !== actor.id ||
    session.credentialKeyId !== proof.credentialKeyId ||
    !verifyPortableRuntimeAuthorizationSignature(
      session.credentialAddressKey,
      challenge,
      runtimeSignature,
    )
  ) return invalidAdmissionTransition;

  const authorization = authorizePortableState(state, Object.freeze({
    expectedHistoryHead: state.head,
    domain: proof.domain,
    policyVersion: proof.policyVersion,
    rootRecognitionPolicy: proof.rootRecognitionPolicy,
    request: proof.request as unknown as Record<string, unknown>,
    evaluationTime: proof.evaluationTime,
    consequential: true,
    binding,
  }));
  if (
    authorization.decision !== "ALLOW" ||
    canonicalEncode(authorization.proof) !== canonicalEncode(proof)
  ) return invalidAdmissionTransition;

  const declaration = mapGet(state.intentDeclarations, proof.intentId!);
  if (
    declaration === undefined ||
    !sameIntent(
      declaration.data,
      portableIntentProjection(proof.request, binding, declaration.data.adapterProfile),
    ) ||
    mapHas(state.intentAdmissions, proof.intentId!)
  ) return invalidAdmissionTransition;

  const usage: PortableAuthorityUsage[] = [];
  const amount = ownOptional(proof.request, "amount");
  for (
    let index = 0;
    index < proof.controllingAuthorityIds.length;
    index += 1
  ) {
    const authorityId = proof.controllingAuthorityIds[index]!;
    const authority = mapGet(state.authorities, authorityId);
    if (authority === undefined || authority.grant.kind !== "PERMISSION") {
      return invalidAdmissionTransition;
    }
    const maxTransactions = ownOptional(
      authority.grant.constraints,
      "maxTransactions",
    );
    const maxCumulativeAmount = ownOptional(
      authority.grant.constraints,
      "maxCumulativeAmount",
    );
    if (maxTransactions === undefined && maxCumulativeAmount === undefined) {
      continue;
    }
    const current = mapGet(state.authorityUsage, authorityId);
    if (
      current === undefined ||
      (maxCumulativeAmount !== undefined && amount === undefined)
    ) return invalidAdmissionTransition;
    const admittedTransactionCount = current.admittedTransactionCount +
      (maxTransactions === undefined ? 0 : 1);
    const admittedCumulativeAmount = current.admittedCumulativeAmount +
      (maxCumulativeAmount === undefined ? 0n : amount!);
    if (
      !Number.isSafeInteger(admittedTransactionCount) ||
      admittedTransactionCount > (maxTransactions ?? admittedTransactionCount) ||
      admittedCumulativeAmount >
        (maxCumulativeAmount ?? admittedCumulativeAmount) ||
      admittedCumulativeAmount > MAX_BIGINT
    ) return invalidAdmissionTransition;
    arrayPush(usage, Object.freeze({
      authorityId,
      admittedTransactionCount,
      admittedCumulativeAmount,
    }));
  }

  return Object.freeze({
    status: "VALID" as const,
    intentId: proof.intentId!,
    actorId: proof.request.actorId,
    nonce: proof.nonce!,
    usage: Object.freeze(usage),
  });
};

/** Compact, replay-verified output-limit result used by admission orchestration. */
export const portableAdmissionOutputLimit = (): PortableReplayAuthorizationIndeterminate =>
  indeterminate(
    PORTABLE_AUTHORIZATION_VERSION,
    "OUTPUT_LIMIT_EXCEEDED",
    "REPLAY_VERIFIED",
  ) as PortableReplayAuthorizationIndeterminate;

/** Closed replay-authorization indeterminate projection for outer façades. */
export const portableReplayAuthorizationIndeterminate = (
  code: PortableIndeterminateCode,
  assurance: "SUPPLIED_SCOPE" | "REPLAY_VERIFIED" = "SUPPLIED_SCOPE",
): PortableReplayAuthorizationIndeterminate => indeterminate(
  PORTABLE_AUTHORIZATION_VERSION,
  code,
  assurance,
) as PortableReplayAuthorizationIndeterminate;
