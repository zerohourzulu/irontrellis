import { PORTABLE_ADAPTER_POLICY_E5_HASH, PORTABLE_ADAPTER_POLICY_E6_HASH } from "./portable-adapter-engine.js";
import { captureBoundedCanonicalAuthorityOperationIncrementally, captureBoundedCanonicalValue, canonicalEncode, compareProtocolStrings, getCanonicalCaptureLimitErrorMetadata, hashCanonical, isCanonicalReplaySchemaFailure, isCapturedCanonicalAuthorityOperation, isWellFormedUnicode, } from "./canonical.js";
import { portableAdministrativeTransitionEffect, } from "./portable-administration-codec.js";
import { HostTypeError, arrayIncludes, arrayIsArray, arrayPush, arraySort, bigintFrom, copyArray, createMap, createSet, hostObjectPrototype, keccak256Bytes, mapForEach, mapGet, mapHas, mapSet, mapSize, numberFrom, numberIsSafeInteger, objectCreate, objectDefineDataProperty, objectFreeze, objectHasOwn, objectIs, reflectApply, reflectGetOwnPropertyDescriptor, reflectGetPrototypeOf, reflectOwnKeys, regExpTest, setAdd, setDelete, setHas, setSize, setToArray, stringCharCodeAt, stringSlice, stringToLowerCase, utf8Encode, uint8ArrayLength, } from "./host-intrinsics.js";
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
export const PORTABLE_AUTHORITY_EVALUATION_VERSION = "continuity-authority-evaluation/0.2";
export const PORTABLE_AUTHORIZATION_VERSION = "continuity-authorization/0.2";
export const PORTABLE_INTENT_ADMISSION_VERSION = "continuity-intent-admission/0.2";
export const PORTABLE_AUTHORIZATION_PROOF_VERSION = "continuity-authorization-proof/0.2";
export const PORTABLE_RUNTIME_AUTHORIZATION_VERSION = "continuity-runtime-authorization/0.2";
export const PORTABLE_ROOT_RECOGNITION_POLICY = "declared-principal-root/0.2";
const MAX_IDENTIFIER_BYTES = 256;
const MAX_PROTOCOL_STRING_BYTES = 4_096;
const MAX_AUTHORITIES = 1_024;
const MAX_PATH_DEPTH = 32;
const MAX_REQUIRED_INTERSECTIONS = 32;
const MAX_SET_MEMBERS = 256;
const MAX_RESULT_EVIDENCE = 4_096;
const MAX_BIGINT = (1n << 256n) - 1n;
const SECP256K1_ORDER = bigintFrom("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
const SECP256K1_FIELD = bigintFrom("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
const MAX_LOW_S = bigintFrom("0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");
const SECP256K1_BASE_X = bigintFrom("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
const SECP256K1_BASE_Y = bigintFrom("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
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
const ownOptional = (value, key) => Object.hasOwn(value, key) ? value[key] : undefined;
const frozenArray = (source) => Object.freeze(copyArray(source));
const isPlainRecord = (value) => {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        return false;
    }
    const prototype = Reflect.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
};
const boundedUtf8 = (value, maximum) => value.length <= maximum &&
    isWellFormedUnicode(value) &&
    uint8ArrayLength(UTF8_ENCODER.encode(value)) <= maximum;
const isIdentifier = (value) => typeof value === "string" &&
    value.length > 0 &&
    boundedUtf8(value, MAX_IDENTIFIER_BYTES) &&
    !regExpTest(/[\u0000-\u001f\u007f]/u, value);
const isU53 = (value) => typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0 &&
    !Object.is(value, -0);
const isAmount = (value) => typeof value === "bigint" && value >= 0n && value <= MAX_BIGINT;
const isContentHash = (value) => typeof value === "string" && regExpTest(/^0x[0-9a-f]{64}$/, value);
const isEthereumAddress = (value) => typeof value === "string" && regExpTest(/^0x[0-9a-fA-F]{40}$/, value);
const isChainId = (value) => {
    if (typeof value !== "string" || !regExpTest(/^[1-9][0-9]*$/, value)) {
        return false;
    }
    const parsed = bigintFrom(value);
    return parsed >= 1n && parsed <= MAX_BIGINT;
};
const isSignature65 = (value) => {
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
const resultVersionForKind = (kind) => kind === "AUTHORITY_PATH_EVALUATION"
    ? PORTABLE_AUTHORITY_EVALUATION_VERSION
    : PORTABLE_AUTHORIZATION_VERSION;
const expectedInputVersionForKind = (kind) => kind === "AUTHORITY_PATH_EVALUATION"
    ? PORTABLE_AUTHORITY_EVALUATION_VERSION
    : kind === "AUTHORIZE"
        ? PORTABLE_AUTHORIZATION_VERSION
        : PORTABLE_INTENT_ADMISSION_VERSION;
const requiredOuterKeys = (kind) => kind === "AUTHORITY_PATH_EVALUATION"
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
const optionalOuterKeys = (kind) => kind === "AUTHORIZE" ? Object.freeze(["binding"]) : Object.freeze([]);
const descriptorValue = (source, key) => {
    const descriptor = Reflect.getOwnPropertyDescriptor(source, key);
    if (descriptor === undefined) {
        throw new TypeError(`Portable authority input lost field ${key}.`);
    }
    if (Object.hasOwn(descriptor, "value"))
        return descriptor.value;
    const getter = ownOptional(descriptor, "get");
    return getter === undefined ? undefined : Reflect.apply(getter, source, []);
};
const captureAuthorityOuter = (input, kind) => {
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
        if (!arrayIncludes(keys, required[index])) {
            return Object.freeze({ status: "INVALID_INPUT" });
        }
    }
    for (let index = 0; index < keys.length; index += 1) {
        const key = keys[index];
        if (!arrayIncludes(required, key) && !arrayIncludes(optional, key)) {
            return Object.freeze({ status: "INVALID_INPUT" });
        }
    }
    const body = Object.create(null);
    Object.defineDataProperty(body, "operationVersion", operationVersion, false, true);
    for (let index = 0; index < keys.length; index += 1) {
        const key = keys[index];
        if (key === "operationVersion")
            continue;
        const value = descriptorValue(input, key);
        if (value === undefined) {
            if (arrayIncludes(optional, key))
                continue;
            return Object.freeze({ status: "INVALID_INPUT" });
        }
        Object.defineDataProperty(body, key, value, false, true);
    }
    Object.freeze(body);
    return Object.freeze({ status: "CAPTURED", source: input, body });
};
const indeterminate = (operationVersion, code, assurance = "SUPPLIED_SCOPE", evidence = Object.freeze([]), subjectId) => Object.freeze({
    operationVersion,
    decision: "INDETERMINATE",
    scopeAssurance: assurance,
    consequential: false,
    code,
    failures: Object.freeze([
        Object.freeze({
            code,
            ...(subjectId === undefined ? {} : { subjectId }),
            evidence,
        }),
    ]),
});
/**
 * One-graph caller capture shared by the raw, replay-bound, and admission
 * façades. Replay supplies its own visitor, so this lower engine never imports
 * replay runtime code.
 */
export const capturePortableAuthorityOperation = (input, kind, replayVisitor) => {
    const outer = captureAuthorityOuter(input, kind);
    if (outer.status === "INVALID_INPUT") {
        return Object.freeze({ status: "INVALID_INPUT" });
    }
    if (outer.status === "UNSUPPORTED_VERSION") {
        return Object.freeze({ status: "UNSUPPORTED_VERSION" });
    }
    const captured = captureBoundedCanonicalAuthorityOperationIncrementally(outer.body, outer.source, kind, replayVisitor);
    if (captured.status === "STOPPED") {
        throw new TypeError("Portable authority replay capture stopped unexpectedly.");
    }
    if (captured.status === "CAPTURE_FAILED") {
        if (getCanonicalCaptureLimitErrorMetadata(captured.error) !== undefined) {
            return Object.freeze({ status: "INVALID_INPUT" });
        }
        if (kind !== "AUTHORITY_PATH_EVALUATION" &&
            isCanonicalReplaySchemaFailure(captured.error)) {
            return Object.freeze({ status: "STATE_NOT_AUTHORITATIVE" });
        }
        throw captured.error;
    }
    if (!isCapturedCanonicalAuthorityOperation(captured.capture)) {
        throw new TypeError("Portable authority capture lost provenance.");
    }
    return Object.freeze({
        status: "CAPTURED",
        capture: captured.capture,
    });
};
const exactRecord = (capture, value, required, optional = Object.freeze([])) => {
    if (!isPlainRecord(value))
        return false;
    const keys = capture.capturedRecordKeys(value);
    if (keys === undefined ||
        keys.length < required.length ||
        keys.length > required.length + optional.length)
        return false;
    for (let index = 0; index < keys.length; index += 1) {
        const key = keys[index];
        if (!arrayIncludes(required, key) && !arrayIncludes(optional, key))
            return false;
        if (arrayIncludes(required, key) && !Object.hasOwn(value, key))
            return false;
    }
    for (let index = 0; index < required.length; index += 1) {
        if (!Object.hasOwn(value, required[index]))
            return false;
    }
    return true;
};
const identifierStatus = (value) => {
    if (typeof value !== "string")
        return "INVALID";
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
const amountStatus = (value) => typeof value === "bigint" && (value < -MAX_BIGINT || value > MAX_BIGINT)
    ? "LIMIT"
    : isAmount(value)
        ? "VALID"
        : "INVALID";
const mergeStatus = (left, right) => left === "LIMIT" || right === "LIMIT"
    ? "LIMIT"
    : left === "INVALID" || right === "INVALID"
        ? "INVALID"
        : "VALID";
const identifierListStatus = (value, maximum, nonempty = false) => {
    if (!Array.isArray(value))
        return "INVALID";
    if (value.length > maximum)
        return "LIMIT";
    if (nonempty && value.length === 0)
        return "INVALID";
    const seen = createSet();
    let status = "VALID";
    for (let index = 0; index < value.length; index += 1) {
        const memberStatus = identifierStatus(value[index]);
        status = mergeStatus(status, memberStatus);
        if (memberStatus === "VALID") {
            const member = value[index];
            if (setHas(seen, member))
                status = mergeStatus(status, "INVALID");
            setAdd(seen, member);
        }
    }
    return status;
};
const domainIsValid = (capture, value) => exactRecord(capture, value, Object.freeze([
    "protocol",
    "version",
    "deploymentId",
    "chainId",
    "verifyingContract",
])) &&
    value.protocol === "continuity" &&
    value.version === "0.2" &&
    isIdentifier(value.deploymentId) &&
    isChainId(value.chainId) &&
    isEthereumAddress(value.verifyingContract);
const historyHeadIsValid = (capture, value) => exactRecord(capture, value, Object.freeze(["hash", "position", "canonicalTime"])) &&
    isContentHash(value.hash) &&
    isU53(value.position) &&
    isU53(value.canonicalTime);
const requestHasExactShape = (capture, value) => exactRecord(capture, value, Object.freeze(["actorId", "action", "resource", "claimedAt"]), Object.freeze(["amount", "counterpartyId", "termsCommitment"]));
const requestProblem = (request) => {
    if (!isIdentifier(request.actorId) ||
        !isIdentifier(request.action) ||
        !isIdentifier(request.resource) ||
        !isU53(request.claimedAt) ||
        (Object.hasOwn(request, "counterpartyId") &&
            !isIdentifier(request.counterpartyId)) ||
        (Object.hasOwn(request, "termsCommitment") &&
            !isContentHash(request.termsCommitment)))
        return "INVALID_REQUEST";
    if (Object.hasOwn(request, "amount") && !isAmount(request.amount)) {
        return "INVALID_AMOUNT";
    }
    return undefined;
};
const bindingIsStructurallyValid = (capture, value) => {
    if (!exactRecord(capture, value, Object.freeze([
        "runtimeSessionId",
        "controlEpoch",
        "roleId",
        "roleTenureId",
    ]), Object.freeze([
        "credentialKeyId",
        "intentId",
        "nonce",
        "runtimeSignature",
    ])))
        return false;
    return isIdentifier(value.runtimeSessionId) &&
        isU53(value.controlEpoch) &&
        isIdentifier(value.roleId) &&
        isIdentifier(value.roleTenureId) &&
        (!Object.hasOwn(value, "credentialKeyId") || isIdentifier(value.credentialKeyId)) &&
        (!Object.hasOwn(value, "intentId") || isIdentifier(value.intentId)) &&
        (!Object.hasOwn(value, "nonce") || isIdentifier(value.nonce)) &&
        (!Object.hasOwn(value, "runtimeSignature") || isSignature65(value.runtimeSignature));
};
const constraintsStatus = (capture, value) => {
    if (!exactRecord(capture, value, Object.freeze([
        "actions",
        "resources",
        "quantitative",
        "maxDelegationDepth",
        "requiredIntersectionIds",
    ]), Object.freeze([
        "notBefore",
        "expiresAt",
        "maxAmount",
        "maxCumulativeAmount",
        "maxTransactions",
    ])))
        return "INVALID";
    let status = mergeStatus(identifierListStatus(value.actions, MAX_SET_MEMBERS, true), identifierListStatus(value.resources, MAX_SET_MEMBERS, true));
    status = mergeStatus(status, identifierListStatus(value.requiredIntersectionIds, MAX_REQUIRED_INTERSECTIONS));
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
    if (value.quantitative === false &&
        (Object.hasOwn(value, "maxAmount") || Object.hasOwn(value, "maxCumulativeAmount")))
        status = mergeStatus(status, "INVALID");
    const notBefore = ownOptional(value, "notBefore");
    const expiresAt = ownOptional(value, "expiresAt");
    if (isU53(notBefore) &&
        isU53(expiresAt) &&
        notBefore >= expiresAt)
        status = mergeStatus(status, "INVALID");
    return status;
};
const permissionStatus = (capture, value) => {
    if (!exactRecord(capture, value, Object.freeze([
        "kind",
        "authorityId",
        "grantorId",
        "granteeId",
        "rootAuthorityId",
        "independent",
        "constraints",
    ]), Object.freeze(["parentAuthorityId"])))
        return "INVALID";
    let status = value.kind === "PERMISSION" &&
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
const prohibitionStatus = (capture, value) => {
    if (!isPlainRecord(value) || value.kind !== "PROHIBITION")
        return "INVALID";
    const root = value.scope === "ROOT";
    const global = value.scope === "GLOBAL";
    if (!root && !global)
        return "INVALID";
    if (!exactRecord(capture, value, root
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
        ]), root
        ? Object.freeze(["subjectActorId", "parentAuthorityId"])
        : Object.freeze(["subjectActorId"])))
        return "INVALID";
    let status = mergeStatus(identifierStatus(value.authorityId), identifierStatus(value.grantorId));
    if (root)
        status = mergeStatus(status, identifierStatus(value.rootAuthorityId));
    if (Object.hasOwn(value, "subjectActorId")) {
        status = mergeStatus(status, identifierStatus(value.subjectActorId));
    }
    if (Object.hasOwn(value, "parentAuthorityId")) {
        status = mergeStatus(status, identifierStatus(value.parentAuthorityId));
    }
    status = mergeStatus(status, constraintsStatus(capture, value.constraints));
    if (status === "VALID") {
        const constraints = value.constraints;
        if (constraints.requiredIntersectionIds.length !== 0 ||
            constraints.maxDelegationDepth !== 0 ||
            ownOptional(constraints, "maxCumulativeAmount") !== undefined ||
            ownOptional(constraints, "maxTransactions") !== undefined)
            status = "INVALID";
    }
    return status;
};
const recognizedRootStatus = (capture, value) => {
    if (!exactRecord(capture, value, Object.freeze([
        "rootAuthorityId",
        "principalId",
        "principalRecognitionEventId",
        "rootGrantEventId",
    ])))
        return "INVALID";
    let status = mergeStatus(identifierStatus(value.rootAuthorityId), identifierStatus(value.principalId));
    status = mergeStatus(status, identifierStatus(value.principalRecognitionEventId));
    status = mergeStatus(status, identifierStatus(value.rootGrantEventId));
    return status;
};
const authorityEvidenceStatus = (capture, value) => {
    if (!exactRecord(capture, value, Object.freeze(["authorityId", "grantEventId", "grantEventPosition"])))
        return "INVALID";
    return mergeStatus(mergeStatus(identifierStatus(value.authorityId), identifierStatus(value.grantEventId)), isU53(value.grantEventPosition) ? "VALID" : "INVALID");
};
const authorityUsageStatus = (capture, value) => {
    if (!exactRecord(capture, value, Object.freeze([
        "authorityId",
        "admittedTransactionCount",
        "admittedCumulativeAmount",
    ])))
        return "INVALID";
    return mergeStatus(mergeStatus(identifierStatus(value.authorityId), isU53(value.admittedTransactionCount) ? "VALID" : "INVALID"), amountStatus(value.admittedCumulativeAmount));
};
const sameDomain = (left, right) => left.protocol === right.protocol &&
    left.version === right.version &&
    left.deploymentId === right.deploymentId &&
    left.chainId === right.chainId &&
    stringToLowerCase(left.verifyingContract) ===
        stringToLowerCase(right.verifyingContract);
const sameHistoryHead = (left, right) => left.hash === right.hash &&
    left.position === right.position &&
    left.canonicalTime === right.canonicalTime;
const sortedIdentifiers = (values) => {
    const copy = copyArray(values);
    arraySort(copy, compareProtocolStrings);
    return Object.freeze(copy);
};
const compareIdentifierSequences = (left, right) => {
    const shared = left.length < right.length ? left.length : right.length;
    for (let index = 0; index < shared; index += 1) {
        const comparison = compareProtocolStrings(left[index], right[index]);
        if (comparison !== 0)
            return comparison;
    }
    return left.length < right.length ? -1 : left.length > right.length ? 1 : 0;
};
const identifierSubset = (child, parent) => {
    for (let index = 0; index < child.length; index += 1) {
        if (!arrayIncludes(parent, child[index]))
            return false;
    }
    return true;
};
const normalizedConstraints = (constraints) => Object.freeze({
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
    requiredIntersectionIds: sortedIdentifiers(constraints.requiredIntersectionIds),
});
const normalizedPermission = (grant) => Object.freeze({
    kind: "PERMISSION",
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
const normalizedProhibition = (grant) => grant.scope === "GLOBAL"
    ? Object.freeze({
        kind: "PROHIBITION",
        scope: "GLOBAL",
        authorityId: grant.authorityId,
        grantorId: grant.grantorId,
        ...(ownOptional(grant, "subjectActorId") === undefined
            ? {}
            : { subjectActorId: grant.subjectActorId }),
        constraints: normalizedConstraints(grant.constraints),
    })
    : Object.freeze({
        kind: "PROHIBITION",
        scope: "ROOT",
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
const constraintsAreAttenuated = (parent, child) => {
    if (!identifierSubset(child.actions, parent.actions) ||
        !identifierSubset(child.resources, parent.resources) ||
        !identifierSubset(parent.requiredIntersectionIds, child.requiredIntersectionIds) ||
        parent.maxDelegationDepth === 0 ||
        child.maxDelegationDepth > parent.maxDelegationDepth - 1 ||
        (parent.quantitative && !child.quantitative))
        return false;
    const parentNotBefore = ownOptional(parent, "notBefore");
    const childNotBefore = ownOptional(child, "notBefore");
    if (parentNotBefore !== undefined &&
        (childNotBefore === undefined || childNotBefore < parentNotBefore))
        return false;
    const parentExpiresAt = ownOptional(parent, "expiresAt");
    const childExpiresAt = ownOptional(child, "expiresAt");
    if (parentExpiresAt !== undefined &&
        (childExpiresAt === undefined || childExpiresAt > parentExpiresAt))
        return false;
    const parentMaxAmount = ownOptional(parent, "maxAmount");
    const childMaxAmount = ownOptional(child, "maxAmount");
    if (parentMaxAmount !== undefined &&
        (childMaxAmount === undefined || childMaxAmount > parentMaxAmount))
        return false;
    const parentMaxCumulative = ownOptional(parent, "maxCumulativeAmount");
    const childMaxCumulative = ownOptional(child, "maxCumulativeAmount");
    if (parentMaxCumulative !== undefined &&
        (childMaxCumulative === undefined || childMaxCumulative > parentMaxCumulative))
        return false;
    const parentMaxTransactions = ownOptional(parent, "maxTransactions");
    const childMaxTransactions = ownOptional(child, "maxTransactions");
    return parentMaxTransactions === undefined ||
        (childMaxTransactions !== undefined &&
            childMaxTransactions <= parentMaxTransactions);
};
const addUniqueByIdentifier = (target, identifier, value) => {
    if (mapHas(target, identifier))
        return false;
    mapSet(target, identifier, value);
    return true;
};
const hasCapturedIdentifierDuplicate = (values, field) => {
    const seen = createSet();
    for (let index = 0; index < values.length; index += 1) {
        const value = values[index];
        const identifier = field === undefined
            ? value
            : isPlainRecord(value) ? ownOptional(value, field) : undefined;
        // Another malformed field must not hide a duplicate protocol identity.
        // A malformed identity scalar does not invent an identity to compare.
        if (!isIdentifier(identifier))
            continue;
        if (setHas(seen, identifier))
            return true;
        setAdd(seen, identifier);
    }
    return false;
};
const capturedPermissionPathsFit = (permissions) => {
    const byIdentifier = createMap();
    for (let index = 0; index < permissions.length; index += 1) {
        const permission = permissions[index];
        if (!isPlainRecord(permission))
            continue;
        const authorityId = ownOptional(permission, "authorityId");
        if (!isIdentifier(authorityId))
            continue;
        // An already-invalid duplicate authority cannot select a parent by input
        // order. Null marks an ambiguous identity; its collision remains phase 4.
        mapSet(byIdentifier, authorityId, mapHas(byIdentifier, authorityId) ? null : permission);
    }
    for (let index = 0; index < permissions.length; index += 1) {
        const permission = permissions[index];
        if (!isPlainRecord(permission))
            continue;
        let current = permission;
        const visited = createSet();
        let depth = 0;
        while (current !== undefined && current !== null) {
            const authorityId = ownOptional(current, "authorityId");
            if (!isIdentifier(authorityId) || setHas(visited, authorityId))
                break;
            if (depth === MAX_PATH_DEPTH)
                return false;
            setAdd(visited, authorityId);
            depth += 1;
            const parentAuthorityId = ownOptional(current, "parentAuthorityId");
            if (!isIdentifier(parentAuthorityId))
                break;
            current = mapGet(byIdentifier, parentAuthorityId);
        }
    }
    return true;
};
/** Phase-1 checks over the one detached graph, without corpus interpretation. */
const rawCaptureTimeCollectionsAreValid = (capture) => {
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
    if (!Array.isArray(roots) ||
        !Array.isArray(permissions) ||
        !Array.isArray(prohibitions) ||
        !Array.isArray(evidence) ||
        !Array.isArray(revoked) ||
        !Array.isArray(usage) ||
        permissions.length + prohibitions.length > MAX_AUTHORITIES)
        return false;
    return !hasCapturedIdentifierDuplicate(roots, "rootAuthorityId") &&
        !hasCapturedIdentifierDuplicate(evidence, "authorityId") &&
        !hasCapturedIdentifierDuplicate(usage, "authorityId") &&
        !hasCapturedIdentifierDuplicate(revoked) &&
        capturedPermissionPathsFit(permissions);
};
const rawCorpusFromCapture = (capture) => {
    const input = capture.value;
    const scope = input.scope;
    const permissionsValue = input.permissions;
    const prohibitionsValue = input.prohibitions;
    const rootsValue = isPlainRecord(scope) ? scope.recognizedRoots : undefined;
    const evidenceValue = input.authorityEvidence;
    const revokedValue = input.revokedAuthorityIds;
    const usageValue = input.usage;
    if (!Array.isArray(permissionsValue) ||
        !Array.isArray(prohibitionsValue) ||
        !Array.isArray(rootsValue) ||
        !Array.isArray(evidenceValue) ||
        !Array.isArray(revokedValue) ||
        !Array.isArray(usageValue) ||
        permissionsValue.length + prohibitionsValue.length > MAX_AUTHORITIES)
        return Object.freeze({ status: "INVALID_INPUT" });
    let aggregateStatus = "VALID";
    const permissions = createMap();
    const prohibitions = createMap();
    const roots = createMap();
    const evidence = createMap();
    const revoked = createSet();
    const usage = createMap();
    let authorityIdentityCollision = false;
    let captureDuplicate = false;
    for (let index = 0; index < permissionsValue.length; index += 1) {
        const value = permissionsValue[index];
        const status = permissionStatus(capture, value);
        aggregateStatus = mergeStatus(aggregateStatus, status);
        if (status === "VALID") {
            const permission = value;
            if (mapHas(permissions, permission.authorityId) ||
                mapHas(prohibitions, permission.authorityId))
                authorityIdentityCollision = true;
            else
                mapSet(permissions, permission.authorityId, permission);
        }
    }
    for (let index = 0; index < prohibitionsValue.length; index += 1) {
        const value = prohibitionsValue[index];
        const status = prohibitionStatus(capture, value);
        aggregateStatus = mergeStatus(aggregateStatus, status);
        if (status === "VALID") {
            const prohibition = value;
            if (mapHas(permissions, prohibition.authorityId) ||
                mapHas(prohibitions, prohibition.authorityId))
                authorityIdentityCollision = true;
            else
                mapSet(prohibitions, prohibition.authorityId, prohibition);
        }
    }
    for (let index = 0; index < rootsValue.length; index += 1) {
        const value = rootsValue[index];
        const status = recognizedRootStatus(capture, value);
        aggregateStatus = mergeStatus(aggregateStatus, status);
        if (status === "VALID") {
            const root = value;
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
            const item = value;
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
            const item = value;
            if (!addUniqueByIdentifier(usage, item.authorityId, item)) {
                captureDuplicate = true;
            }
        }
    }
    for (let index = 0; index < revokedValue.length; index += 1) {
        const status = identifierStatus(revokedValue[index]);
        aggregateStatus = mergeStatus(aggregateStatus, status);
        if (status === "VALID") {
            const identifier = revokedValue[index];
            if (setHas(revoked, identifier))
                captureDuplicate = true;
            else
                setAdd(revoked, identifier);
        }
    }
    if (aggregateStatus === "LIMIT" || captureDuplicate) {
        return Object.freeze({ status: "INVALID_INPUT" });
    }
    if (aggregateStatus === "INVALID" || authorityIdentityCollision) {
        return Object.freeze({ status: "INVALID_DELEGATION" });
    }
    return Object.freeze({
        status: "VALID",
        corpus: Object.freeze({
            permissions,
            prohibitions,
            roots,
            evidence,
            revoked,
            usage,
            globalPolicySourceId: scope
                .globalPolicySourceId,
        }),
    });
};
const replayCorpus = (state) => {
    const permissions = createMap();
    const prohibitions = createMap();
    const evidence = createMap();
    const revoked = createSet();
    const replayAgents = state.agents;
    const replayPrincipals = state.principals;
    const replayRecords = state.authorities;
    const roots = state.recognizedRoots;
    const usage = state.authorityUsage;
    mapForEach(replayRecords, (record, authorityId) => {
        if (record.grant.kind === "PERMISSION") {
            mapSet(permissions, authorityId, record.grant);
        }
        else {
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
const buildPermissionPath = (terminal, permissions) => {
    const reverse = [];
    const visited = createSet();
    let current = terminal;
    while (current !== undefined) {
        if (setHas(visited, current.authorityId)) {
            return Object.freeze({ status: "INVALID_DELEGATION" });
        }
        if (reverse.length === MAX_PATH_DEPTH) {
            return Object.freeze({ status: "INVALID_INPUT" });
        }
        setAdd(visited, current.authorityId);
        arrayPush(reverse, current);
        const parentAuthorityId = ownOptional(current, "parentAuthorityId");
        if (parentAuthorityId === undefined)
            break;
        const parent = mapGet(permissions, parentAuthorityId);
        if (parent === undefined) {
            return Object.freeze({ status: "INVALID_DELEGATION" });
        }
        current = parent;
    }
    const grants = [];
    for (let index = reverse.length - 1; index >= 0; index -= 1) {
        arrayPush(grants, reverse[index]);
    }
    let effectivelyIndependent = true;
    for (let index = 0; index < grants.length; index += 1) {
        const grant = grants[index];
        if (!grant.independent)
            effectivelyIndependent = false;
        if (index === 0)
            continue;
        const parent = grants[index - 1];
        if (grant.grantorId !== parent.granteeId ||
            grant.rootAuthorityId !== parent.rootAuthorityId ||
            !constraintsAreAttenuated(parent.constraints, grant.constraints)) {
            return Object.freeze({ status: "INVALID_DELEGATION" });
        }
    }
    const authorityIds = [];
    for (let index = 0; index < grants.length; index += 1) {
        arrayPush(authorityIds, grants[index].authorityId);
    }
    return Object.freeze({
        status: "VALID",
        path: Object.freeze({
            rootAuthorityId: grants[0].rootAuthorityId,
            grants: Object.freeze(grants),
            authorityIds: Object.freeze(authorityIds),
            effectivelyIndependent,
        }),
    });
};
const validateIntersectionGraph = (permissions) => {
    const done = createSet();
    const identifiers = [];
    mapForEach(permissions, (_grant, identifier) => arrayPush(identifiers, identifier));
    for (let startIndex = 0; startIndex < identifiers.length; startIndex += 1) {
        const start = identifiers[startIndex];
        if (setHas(done, start))
            continue;
        const active = createSet();
        const stack = [];
        arrayPush(stack, { identifier: start, next: 0 });
        setAdd(active, start);
        while (stack.length > 0) {
            const frame = stack[stack.length - 1];
            const grant = mapGet(permissions, frame.identifier);
            if (frame.next >= grant.constraints.requiredIntersectionIds.length) {
                stack.length -= 1;
                setDelete(active, frame.identifier);
                setAdd(done, frame.identifier);
                continue;
            }
            const dependency = grant.constraints.requiredIntersectionIds[frame.next];
            frame.next += 1;
            if (!mapHas(permissions, dependency) || setHas(done, dependency))
                continue;
            if (setHas(active, dependency))
                return false;
            setAdd(active, dependency);
            arrayPush(stack, { identifier: dependency, next: 0 });
        }
    }
    return true;
};
const validateAuthorityCorpus = (corpus) => {
    const paths = createMap();
    let pathStatus = "VALID";
    mapForEach(corpus.permissions, (permission, authorityId) => {
        if (pathStatus === "INVALID_INPUT")
            return;
        const built = buildPermissionPath(permission, corpus.permissions);
        if (built.status !== "VALID") {
            pathStatus = built.status;
            return;
        }
        mapSet(paths, authorityId, built.path);
    });
    if (pathStatus !== "VALID")
        return Object.freeze({ status: pathStatus });
    if (!validateIntersectionGraph(corpus.permissions)) {
        return Object.freeze({ status: "INVALID_DELEGATION" });
    }
    let valid = true;
    if (mapSize(corpus.evidence) !==
        mapSize(corpus.permissions) + mapSize(corpus.prohibitions))
        valid = false;
    mapForEach(corpus.permissions, (_grant, authorityId) => {
        if (!mapHas(corpus.evidence, authorityId))
            valid = false;
    });
    mapForEach(corpus.prohibitions, (_grant, authorityId) => {
        if (!mapHas(corpus.evidence, authorityId))
            valid = false;
    });
    mapForEach(corpus.evidence, (_item, authorityId) => {
        if (!mapHas(corpus.permissions, authorityId) &&
            !mapHas(corpus.prohibitions, authorityId))
            valid = false;
    });
    const replayPrincipals = ownOptional(corpus, "replayPrincipals");
    const replayRecords = ownOptional(corpus, "replayRecords");
    mapForEach(corpus.roots, (root, rootAuthorityId) => {
        const grant = mapGet(corpus.permissions, rootAuthorityId);
        const evidence = mapGet(corpus.evidence, rootAuthorityId);
        if (grant === undefined ||
            evidence === undefined ||
            ownOptional(grant, "parentAuthorityId") !== undefined ||
            grant.authorityId !== root.rootAuthorityId ||
            grant.rootAuthorityId !== root.rootAuthorityId ||
            grant.grantorId !== root.principalId ||
            evidence.grantEventId !== root.rootGrantEventId)
            valid = false;
        if (replayPrincipals !== undefined) {
            const principal = mapGet(replayPrincipals, root.principalId);
            const record = replayRecords === undefined
                ? undefined
                : mapGet(replayRecords, rootAuthorityId);
            if (principal === undefined ||
                record === undefined ||
                evidence === undefined ||
                root.principalRecognitionEventId !== principal.creationEventId ||
                root.rootGrantEventId !== record.grantEventId ||
                evidence.grantEventPosition !== record.grantEventPosition)
                valid = false;
        }
    });
    mapForEach(corpus.prohibitions, (prohibition) => {
        if (prohibition.scope === "GLOBAL") {
            if (prohibition.grantorId !== corpus.globalPolicySourceId)
                valid = false;
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
            if (parentAuthorityId !== undefined ||
                rootGrant === undefined ||
                !constraintsAreAttenuated(rootGrant.constraints, prohibition.constraints))
                valid = false;
            return;
        }
        if (parentAuthorityId === undefined) {
            valid = false;
            return;
        }
        const parent = mapGet(corpus.permissions, parentAuthorityId);
        const path = mapGet(paths, parentAuthorityId);
        if (parent === undefined ||
            path === undefined ||
            parent.granteeId !== prohibition.grantorId ||
            path.rootAuthorityId !== prohibition.rootAuthorityId ||
            !constraintsAreAttenuated(parent.constraints, prohibition.constraints))
            valid = false;
    });
    const revokedAuthorityIds = setToArray(corpus.revoked);
    for (let index = 0; index < revokedAuthorityIds.length; index += 1) {
        const authorityId = revokedAuthorityIds[index];
        if (!mapHas(corpus.permissions, authorityId) &&
            !mapHas(corpus.prohibitions, authorityId))
            valid = false;
    }
    const requiredUsage = createSet();
    mapForEach(corpus.permissions, (permission, authorityId) => {
        if (ownOptional(permission.constraints, "maxTransactions") !== undefined ||
            ownOptional(permission.constraints, "maxCumulativeAmount") !== undefined)
            setAdd(requiredUsage, authorityId);
    });
    if (setSize(requiredUsage) !== mapSize(corpus.usage))
        valid = false;
    mapForEach(corpus.usage, (_entry, authorityId) => {
        if (!setHas(requiredUsage, authorityId))
            valid = false;
    });
    return valid
        ? Object.freeze({
            status: "VALID",
            value: Object.freeze({ corpus, paths }),
        })
        : Object.freeze({ status: "INVALID_DELEGATION" });
};
const recognizedRootForPath = (validated, path) => {
    const root = mapGet(validated.corpus.roots, path.rootAuthorityId);
    const grant = path.grants[0];
    if (root === undefined ||
        grant.authorityId !== root.rootAuthorityId ||
        grant.rootAuthorityId !== root.rootAuthorityId ||
        grant.grantorId !== root.principalId ||
        ownOptional(grant, "parentAuthorityId") !== undefined)
        return undefined;
    return root;
};
const addConstraintIdentifiers = (target, values) => {
    for (let index = 0; index < values.length; index += 1) {
        setAdd(target, values[index]);
    }
};
const intersectIdentifierValues = (current, next) => {
    if (current === undefined)
        return sortedIdentifiers(next);
    const intersection = [];
    for (let index = 0; index < current.length; index += 1) {
        if (arrayIncludes(next, current[index])) {
            arrayPush(intersection, current[index]);
        }
    }
    return Object.freeze(intersection);
};
const minimumOptionalNumber = (current, next) => next === undefined
    ? current
    : current === undefined || next < current
        ? next
        : current;
const maximumOptionalNumber = (current, next) => next === undefined
    ? current
    : current === undefined || next > current
        ? next
        : current;
const minimumOptionalAmount = (current, next) => next === undefined
    ? current
    : current === undefined || next < current
        ? next
        : current;
const combineConstraints = (grants) => {
    let actions;
    let resources;
    let quantitative = false;
    let notBefore;
    let expiresAt;
    let maxAmount;
    let maxCumulativeAmount;
    let maxTransactions;
    let maxDelegationDepth;
    const required = createSet();
    for (let index = 0; index < grants.length; index += 1) {
        const constraints = grants[index].constraints;
        actions = intersectIdentifierValues(actions, constraints.actions);
        resources = intersectIdentifierValues(resources, constraints.resources);
        quantitative = quantitative || constraints.quantitative;
        notBefore = maximumOptionalNumber(notBefore, ownOptional(constraints, "notBefore"));
        expiresAt = minimumOptionalNumber(expiresAt, ownOptional(constraints, "expiresAt"));
        maxAmount = minimumOptionalAmount(maxAmount, ownOptional(constraints, "maxAmount"));
        maxCumulativeAmount = minimumOptionalAmount(maxCumulativeAmount, ownOptional(constraints, "maxCumulativeAmount"));
        maxTransactions = minimumOptionalNumber(maxTransactions, ownOptional(constraints, "maxTransactions"));
        maxDelegationDepth = minimumOptionalNumber(maxDelegationDepth, constraints.maxDelegationDepth);
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
const directRequiredIds = (path, grantIndex) => {
    const grant = path.grants[grantIndex];
    if (grantIndex === 0)
        return grant.constraints.requiredIntersectionIds;
    const parent = path.grants[grantIndex - 1];
    const direct = [];
    for (let index = 0; index < grant.constraints.requiredIntersectionIds.length; index += 1) {
        const identifier = grant.constraints.requiredIntersectionIds[index];
        if (!arrayIncludes(parent.constraints.requiredIntersectionIds, identifier)) {
            arrayPush(direct, identifier);
        }
    }
    return Object.freeze(direct);
};
const selectCandidateGraph = (validated, main, actorId) => {
    const requiredBy = createMap();
    const queued = createSet();
    const queue = [];
    const selectedPaths = createMap();
    const selectedRoots = createMap();
    const missing = createSet();
    const collectDirect = (path) => {
        for (let grantIndex = 0; grantIndex < path.grants.length; grantIndex += 1) {
            const grant = path.grants[grantIndex];
            const direct = directRequiredIds(path, grantIndex);
            for (let index = 0; index < direct.length; index += 1) {
                const identifier = direct[index];
                const declarers = mapGet(requiredBy, identifier) ?? createSet();
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
        const identifier = queue[queueIndex];
        const path = mapGet(validated.paths, identifier);
        const root = path === undefined
            ? undefined
            : recognizedRootForPath(validated, path);
        const terminal = path?.grants[path.grants.length - 1];
        if (path === undefined ||
            root === undefined ||
            terminal === undefined ||
            path.effectivelyIndependent ||
            terminal.granteeId !== actorId) {
            setAdd(missing, identifier);
            continue;
        }
        if (!mapHas(selectedPaths, identifier)) {
            mapSet(selectedPaths, identifier, path);
            mapSet(selectedRoots, identifier, root);
            collectDirect(path);
        }
    }
    const intersectionIds = [];
    mapForEach(selectedPaths, (_path, identifier) => arrayPush(intersectionIds, identifier));
    arraySort(intersectionIds, compareProtocolStrings);
    const intersections = [];
    const paths = [main];
    for (let index = 0; index < intersectionIds.length; index += 1) {
        const identifier = intersectionIds[index];
        const path = mapGet(selectedPaths, identifier);
        arrayPush(paths, path);
        arrayPush(intersections, Object.freeze({
            requiredAuthorityId: identifier,
            requiredByAuthorityIds: sortedIdentifiers(setToArray(mapGet(requiredBy, identifier))),
            path,
            recognizedRoot: mapGet(selectedRoots, identifier),
        }));
    }
    return Object.freeze({
        main,
        paths: Object.freeze(paths),
        intersections: Object.freeze(intersections),
        missingIntersectionIds: sortedIdentifiers(setToArray(missing)),
    });
};
const leastIdentifier = (values) => {
    const sorted = sortedIdentifiers(setToArray(values));
    return sorted[0];
};
const prohibitionRequestRelevant = (prohibition, request) => {
    const subjectActorId = ownOptional(prohibition, "subjectActorId");
    return (subjectActorId === undefined || subjectActorId === request.actorId) &&
        arrayIncludes(prohibition.constraints.actions, request.action) &&
        arrayIncludes(prohibition.constraints.resources, request.resource) &&
        (!prohibition.constraints.quantitative ||
            ownOptional(request, "amount") !== undefined);
};
const grantWithinTime = (constraints, evaluationTime) => {
    const notBefore = ownOptional(constraints, "notBefore");
    const expiresAt = ownOptional(constraints, "expiresAt");
    return (notBefore === undefined || evaluationTime >= notBefore) &&
        (expiresAt === undefined || evaluationTime < expiresAt);
};
const permissionDependsOnTerminatedAgent = (corpus, permission) => {
    const agents = ownOptional(corpus, "replayAgents");
    if (agents === undefined)
        return false;
    const grantor = mapGet(agents, permission.grantorId);
    const grantee = mapGet(agents, permission.granteeId);
    return grantor?.terminated === true || grantee?.terminated === true;
};
const permissionPathActive = (corpus, path, evaluationTime, terminalAuthorityId) => {
    for (let index = 0; index < path.grants.length; index += 1) {
        const permission = path.grants[index];
        if (setHas(corpus.revoked, permission.authorityId) ||
            !grantWithinTime(permission.constraints, evaluationTime) ||
            permissionDependsOnTerminatedAgent(corpus, permission))
            return false;
        if (terminalAuthorityId !== undefined &&
            permission.authorityId === terminalAuthorityId)
            return true;
    }
    return terminalAuthorityId === undefined;
};
const prohibitionMatchesAmount = (prohibition, request) => {
    const amount = ownOptional(request, "amount");
    const maxAmount = ownOptional(prohibition.constraints, "maxAmount");
    return maxAmount === undefined || (amount !== undefined && amount <= maxAmount);
};
const prohibitionIsActive = (validated, prohibition, evaluationTime) => {
    if (setHas(validated.corpus.revoked, prohibition.authorityId) ||
        !grantWithinTime(prohibition.constraints, evaluationTime))
        return false;
    if (prohibition.scope === "GLOBAL")
        return true;
    const parentAuthorityId = ownOptional(prohibition, "parentAuthorityId");
    if (parentAuthorityId === undefined)
        return true;
    const anchor = mapGet(validated.paths, parentAuthorityId);
    return anchor !== undefined && permissionPathActive(validated.corpus, anchor, evaluationTime, parentAuthorityId);
};
const participatingRootIds = (graph) => {
    const roots = createSet();
    for (let index = 0; index < graph.paths.length; index += 1) {
        setAdd(roots, graph.paths[index].rootAuthorityId);
    }
    return roots;
};
const rootProhibitionApplies = (prohibition, graph) => {
    if (!setHas(participatingRootIds(graph), prohibition.rootAuthorityId)) {
        return false;
    }
    const parentAuthorityId = ownOptional(prohibition, "parentAuthorityId");
    if (parentAuthorityId === undefined)
        return true;
    for (let pathIndex = 0; pathIndex < graph.paths.length; pathIndex += 1) {
        const path = graph.paths[pathIndex];
        if (path.rootAuthorityId === prohibition.rootAuthorityId &&
            arrayIncludes(path.authorityIds, parentAuthorityId))
            return true;
    }
    return false;
};
const relevantGlobalProhibitions = (validated, request) => {
    const relevant = [];
    mapForEach(validated.corpus.prohibitions, (prohibition) => {
        if (prohibition.scope === "GLOBAL" &&
            prohibitionRequestRelevant(prohibition, request))
            arrayPush(relevant, prohibition);
    });
    arraySort(relevant, (left, right) => compareProtocolStrings(left.authorityId, right.authorityId));
    return Object.freeze(relevant);
};
const relevantCandidateProhibitions = (validated, graph, request) => {
    const relevant = [];
    mapForEach(validated.corpus.prohibitions, (prohibition) => {
        if (prohibition.scope === "ROOT" &&
            rootProhibitionApplies(prohibition, graph) &&
            prohibitionRequestRelevant(prohibition, request))
            arrayPush(relevant, prohibition);
    });
    arraySort(relevant, (left, right) => compareProtocolStrings(left.authorityId, right.authorityId));
    return Object.freeze(relevant);
};
const PHASE_SEVEN_RANK = Object.freeze({
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
const evaluateCandidate = (validated, main, request, evaluationTime, globalProhibitions, checkCapacity = true, collectDecisiveAuthority) => {
    if (recognizedRootForPath(validated, main) === undefined) {
        return Object.freeze({
            status: "FAILURE",
            code: "NO_AUTHORITY",
            failingAuthorityId: main.rootAuthorityId,
        });
    }
    const graph = selectCandidateGraph(validated, main, request.actorId);
    const relevantRoot = relevantCandidateProhibitions(validated, graph, request);
    const checked = createSet();
    const matchingProhibitions = createSet();
    for (let index = 0; index < globalProhibitions.length; index += 1) {
        setAdd(checked, globalProhibitions[index].authorityId);
    }
    for (let index = 0; index < relevantRoot.length; index += 1) {
        const prohibition = relevantRoot[index];
        setAdd(checked, prohibition.authorityId);
        if (prohibitionIsActive(validated, prohibition, evaluationTime) &&
            prohibitionMatchesAmount(prohibition, request))
            setAdd(matchingProhibitions, prohibition.authorityId);
    }
    const prohibitedBy = leastIdentifier(matchingProhibitions);
    if (prohibitedBy !== undefined && collectDecisiveAuthority === undefined) {
        return Object.freeze({
            status: "FAILURE",
            code: "PROHIBITED",
            failingAuthorityId: prohibitedBy,
            graph,
        });
    }
    const revoked = createSet();
    const notYetValid = createSet();
    const expired = createSet();
    const actionFailures = createSet();
    const resourceFailures = createSet();
    const amountRequired = createSet();
    const amountExceeded = createSet();
    const cumulativeExceeded = createSet();
    const transactionExceeded = createSet();
    const inactiveAgent = createSet();
    const missingIntersectionFailures = createSet();
    addConstraintIdentifiers(missingIntersectionFailures, graph.missingIntersectionIds);
    const amount = ownOptional(request, "amount");
    for (let pathIndex = 0; pathIndex < graph.paths.length; pathIndex += 1) {
        const path = graph.paths[pathIndex];
        for (let index = 0; index < path.grants.length; index += 1) {
            const permission = path.grants[index];
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
            if (checkCapacity &&
                usage !== undefined &&
                maxCumulative !== undefined &&
                amount !== undefined &&
                usage.admittedCumulativeAmount + amount > maxCumulative)
                setAdd(cumulativeExceeded, permission.authorityId);
            const maxTransactions = ownOptional(constraints, "maxTransactions");
            if (checkCapacity &&
                usage !== undefined &&
                maxTransactions !== undefined &&
                usage.admittedTransactionCount >= maxTransactions)
                setAdd(transactionExceeded, permission.authorityId);
            if (permissionDependsOnTerminatedAgent(validated.corpus, permission)) {
                setAdd(inactiveAgent, permission.authorityId);
            }
        }
    }
    const ordered = Object.freeze([
        Object.freeze(["REVOKED", revoked]),
        Object.freeze(["NOT_YET_VALID", notYetValid]),
        Object.freeze(["EXPIRED", expired]),
        Object.freeze([
            "MISSING_INTERSECTION",
            missingIntersectionFailures,
        ]),
        Object.freeze(["ACTION_NOT_ALLOWED", actionFailures]),
        Object.freeze(["RESOURCE_NOT_ALLOWED", resourceFailures]),
        Object.freeze(["AMOUNT_REQUIRED", amountRequired]),
        Object.freeze(["AMOUNT_EXCEEDED", amountExceeded]),
        Object.freeze([
            "CUMULATIVE_AMOUNT_EXCEEDED",
            cumulativeExceeded,
        ]),
        Object.freeze([
            "TRANSACTION_COUNT_EXCEEDED",
            transactionExceeded,
        ]),
        Object.freeze(["NO_AUTHORITY", inactiveAgent]),
    ]);
    // Receipt evidence needs every decisive fact, while ordinary authorization
    // retains its existing first-failure result and admission capacity checks.
    if (collectDecisiveAuthority !== undefined) {
        const prohibited = setToArray(matchingProhibitions);
        for (let index = 0; index < prohibited.length; index += 1) {
            collectDecisiveAuthority(prohibited[index]);
        }
        for (let index = 0; index < ordered.length; index += 1) {
            const identifiers = setToArray(ordered[index][1]);
            for (let item = 0; item < identifiers.length; item += 1) {
                collectDecisiveAuthority(identifiers[item]);
            }
        }
    }
    if (prohibitedBy !== undefined) {
        return Object.freeze({ status: "FAILURE", code: "PROHIBITED",
            failingAuthorityId: prohibitedBy, graph });
    }
    for (let index = 0; index < ordered.length; index += 1) {
        const code = ordered[index][0];
        const identifiers = ordered[index][1];
        const failingAuthorityId = leastIdentifier(identifiers);
        if (failingAuthorityId !== undefined) {
            return Object.freeze({
                status: "FAILURE",
                code,
                failingAuthorityId,
                graph,
            });
        }
    }
    return Object.freeze({
        status: "SUCCESS",
        graph,
        checkedProhibitionIds: sortedIdentifiers(setToArray(checked)),
    });
};
/**
 * Package-internal receipt recheck over accepted state and its admitted proof.
 * Select the original terminal/path, never a newly preferred candidate. Only
 * already reserved nonce/capacity are outside this policy liveness predicate;
 * the caller separately rechecks the exact admitted control tuple.
 */
export const evaluatePortableReceiptPolicy = (state, proof, evaluationTime) => {
    const checkedProhibitions = createSet();
    const decisiveAuthorities = createSet();
    const decisiveAgents = createSet();
    const result = (live) => Object.freeze({
        live,
        checkedProhibitionIds: sortedIdentifiers(setToArray(checkedProhibitions)),
        decisiveAuthorityIds: sortedIdentifiers(setToArray(decisiveAuthorities)),
        decisiveAgentIds: sortedIdentifiers(setToArray(decisiveAgents)),
    });
    if (!isU53(evaluationTime) ||
        !sameDomain(proof.domain, state.genesis.domain) ||
        proof.policyVersion !== state.genesis.policyVersion ||
        proof.rootRecognitionPolicy !== state.genesis.rootRecognitionPolicy ||
        proof.rootRecognitionPolicy !== PORTABLE_ROOT_RECOGNITION_POLICY)
        return result(false);
    const validation = validateAuthorityCorpus(replayCorpus(state));
    if (validation.status !== "VALID")
        return result(false);
    const validated = validation.value;
    const terminal = proof.permissionPath[proof.permissionPath.length - 1];
    const main = terminal === undefined ? undefined : mapGet(validated.paths, terminal.authorityId);
    if (main === undefined || !main.effectivelyIndependent || terminal.granteeId !== proof.request.actorId) {
        if (terminal !== undefined)
            setAdd(decisiveAuthorities, terminal.authorityId);
        return result(false);
    }
    const graph = selectCandidateGraph(validated, main, proof.request.actorId);
    const root = recognizedRootForPath(validated, main);
    const samePath = (actual, expected) => {
        if (actual.length !== expected.length)
            return false;
        for (let index = 0; index < actual.length; index += 1) {
            // Grant sets are unordered on input and sorted in admitted proofs.
            if (canonicalEncode(normalizedPermission(actual[index])) !== canonicalEncode(expected[index]))
                return false;
        }
        return true;
    };
    let identityMatches = root !== undefined &&
        canonicalEncode(root) === canonicalEncode(proof.recognizedRoot) &&
        samePath(main.grants, proof.permissionPath) &&
        graph.intersections.length === proof.intersections.length;
    if (!identityMatches)
        setAdd(decisiveAuthorities, main.rootAuthorityId);
    for (let index = 0; index < graph.intersections.length; index += 1) {
        const actual = graph.intersections[index];
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
        setAdd(decisiveAuthorities, terminal.authorityId);
    }
    for (let pathIndex = 0; pathIndex < graph.paths.length; pathIndex += 1) {
        const grants = graph.paths[pathIndex].grants;
        for (let index = 0; index < grants.length; index += 1) {
            const grant = grants[index];
            if (mapGet(state.agents, grant.grantorId)?.terminated === true)
                setAdd(decisiveAgents, grant.grantorId);
            if (mapGet(state.agents, grant.granteeId)?.terminated === true)
                setAdd(decisiveAgents, grant.granteeId);
        }
    }
    const globals = relevantGlobalProhibitions(validated, proof.request);
    const candidateProhibitions = relevantCandidateProhibitions(validated, graph, proof.request);
    // Relevance is independent of activity: inactive prohibitions still supply
    // the exact evidence explaining why the admitted graph remains usable.
    for (let index = 0; index < candidateProhibitions.length; index += 1) {
        setAdd(checkedProhibitions, candidateProhibitions[index].authorityId);
    }
    let globalBlocked = false;
    for (let index = 0; index < globals.length; index += 1) {
        const prohibition = globals[index];
        setAdd(checkedProhibitions, prohibition.authorityId);
        if (prohibitionIsActive(validated, prohibition, evaluationTime) &&
            prohibitionMatchesAmount(prohibition, proof.request)) {
            globalBlocked = true;
            setAdd(decisiveAuthorities, prohibition.authorityId);
        }
    }
    const evaluation = evaluateCandidate(validated, main, proof.request, evaluationTime, globals, false, authorityId => setAdd(decisiveAuthorities, authorityId));
    // A behind-head clock cannot establish liveness, but exact receipt evidence
    // still includes the independently available policy failures in this state.
    return result(evaluationTime >= state.head.canonicalTime && identityMatches && !globalBlocked && evaluation.status === "SUCCESS");
};
const normalizedRequest = (request) => {
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
const normalizedDomain = (domain) => {
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
const compareIntersectionProofs = (left, right) => {
    let comparison = compareProtocolStrings(left.requiredAuthorityId, right.requiredAuthorityId);
    if (comparison !== 0)
        return comparison;
    comparison = compareIdentifierSequences(left.requiredByAuthorityIds, right.requiredByAuthorityIds);
    if (comparison !== 0)
        return comparison;
    comparison = compareProtocolStrings(left.recognizedRoot.rootAuthorityId, right.recognizedRoot.rootAuthorityId);
    if (comparison !== 0)
        return comparison;
    const leftPath = [];
    const rightPath = [];
    for (let index = 0; index < left.path.length; index += 1) {
        arrayPush(leftPath, left.path[index].authorityId);
    }
    for (let index = 0; index < right.path.length; index += 1) {
        arrayPush(rightPath, right.path[index].authorityId);
    }
    comparison = compareIdentifierSequences(leftPath, rightPath);
    if (comparison !== 0)
        return comparison;
    return compareProtocolStrings(hashCanonical(left.effectiveConstraints), hashCanonical(right.effectiveConstraints));
};
const grantsForCandidateGraph = (graph) => {
    const grants = [];
    for (let pathIndex = 0; pathIndex < graph.paths.length; pathIndex += 1) {
        const path = graph.paths[pathIndex];
        for (let index = 0; index < path.grants.length; index += 1) {
            arrayPush(grants, path.grants[index]);
        }
    }
    return Object.freeze(grants);
};
const candidatePlan = (context, evaluation) => {
    const intersections = [];
    for (let index = 0; index < evaluation.graph.intersections.length; index += 1) {
        const selection = evaluation.graph.intersections[index];
        const effectiveConstraints = combineConstraints(selection.path.grants);
        arrayPush(intersections, Object.freeze({
            selection,
            effectiveConstraints,
            effectiveConstraintsHash: hashCanonical(effectiveConstraints),
        }));
    }
    const effectiveConstraints = combineConstraints(grantsForCandidateGraph(evaluation.graph));
    return Object.freeze({
        decision: "ALLOW_CANDIDATE",
        context,
        evaluation,
        recognizedRoot: recognizedRootForPath(context.validated, evaluation.graph.main),
        intersections: Object.freeze(intersections),
        effectiveConstraints,
        effectiveConstraintsHash: hashCanonical(effectiveConstraints),
    });
};
const compareCandidateIntersectionPlans = (left, right) => {
    let comparison = compareProtocolStrings(left.selection.requiredAuthorityId, right.selection.requiredAuthorityId);
    if (comparison !== 0)
        return comparison;
    comparison = compareIdentifierSequences(left.selection.requiredByAuthorityIds, right.selection.requiredByAuthorityIds);
    if (comparison !== 0)
        return comparison;
    comparison = compareProtocolStrings(left.selection.recognizedRoot.rootAuthorityId, right.selection.recognizedRoot.rootAuthorityId);
    if (comparison !== 0)
        return comparison;
    comparison = compareIdentifierSequences(left.selection.path.authorityIds, right.selection.path.authorityIds);
    return comparison !== 0
        ? comparison
        : compareProtocolStrings(left.effectiveConstraintsHash, right.effectiveConstraintsHash);
};
const compareSuccessfulCandidates = (left, right) => {
    let comparison = compareProtocolStrings(left.recognizedRoot.rootAuthorityId, right.recognizedRoot.rootAuthorityId);
    if (comparison !== 0)
        return comparison;
    comparison = compareIdentifierSequences(left.evaluation.graph.main.authorityIds, right.evaluation.graph.main.authorityIds);
    if (comparison !== 0)
        return comparison;
    const shared = left.intersections.length < right.intersections.length
        ? left.intersections.length
        : right.intersections.length;
    for (let index = 0; index < shared; index += 1) {
        comparison = compareCandidateIntersectionPlans(left.intersections[index], right.intersections[index]);
        if (comparison !== 0)
            return comparison;
    }
    if (left.intersections.length !== right.intersections.length) {
        return left.intersections.length < right.intersections.length ? -1 : 1;
    }
    return compareProtocolStrings(left.effectiveConstraintsHash, right.effectiveConstraintsHash);
};
const constraintsFitProofLimits = (constraints, requiredIntersectionMaximum) => constraints.actions.length <= MAX_SET_MEMBERS &&
    constraints.resources.length <= MAX_SET_MEMBERS &&
    constraints.requiredIntersectionIds.length <= requiredIntersectionMaximum;
const preflightCandidateProof = (candidate) => {
    const graph = candidate.evaluation.graph;
    if (graph.main.grants.length === 0 ||
        graph.main.grants.length > MAX_PATH_DEPTH ||
        graph.intersections.length > MAX_SET_MEMBERS ||
        candidate.evaluation.checkedProhibitionIds.length > MAX_SET_MEMBERS ||
        !constraintsFitProofLimits(candidate.effectiveConstraints, MAX_SET_MEMBERS))
        return undefined;
    const controllingIds = createSet();
    for (let pathIndex = 0; pathIndex < graph.paths.length; pathIndex += 1) {
        const path = graph.paths[pathIndex];
        if (path.grants.length === 0 || path.grants.length > MAX_PATH_DEPTH) {
            return undefined;
        }
        for (let index = 0; index < path.grants.length; index += 1) {
            const grant = path.grants[index];
            if (!constraintsFitProofLimits(grant.constraints, MAX_REQUIRED_INTERSECTIONS))
                return undefined;
            setAdd(controllingIds, grant.authorityId);
            if (setSize(controllingIds) > MAX_SET_MEMBERS)
                return undefined;
        }
    }
    for (let index = 0; index < candidate.intersections.length; index += 1) {
        const intersection = candidate.intersections[index];
        if (intersection.selection.requiredByAuthorityIds.length === 0 ||
            intersection.selection.requiredByAuthorityIds.length > MAX_SET_MEMBERS ||
            !constraintsFitProofLimits(intersection.effectiveConstraints, MAX_SET_MEMBERS))
            return undefined;
    }
    const controllingAuthorityIds = sortedIdentifiers(setToArray(controllingIds));
    let usageCount = 0;
    for (let index = 0; index < controllingAuthorityIds.length; index += 1) {
        if (mapHas(candidate.context.validated.corpus.usage, controllingAuthorityIds[index]))
            usageCount += 1;
        if (usageCount > MAX_SET_MEMBERS)
            return undefined;
    }
    const evidenceIds = createSet();
    addConstraintIdentifiers(evidenceIds, controllingAuthorityIds);
    addConstraintIdentifiers(evidenceIds, candidate.evaluation.checkedProhibitionIds);
    const evidenceAuthorityIds = [];
    const evidenceIdentifiers = setToArray(evidenceIds);
    for (let index = 0; index < evidenceIdentifiers.length; index += 1) {
        const authorityId = evidenceIdentifiers[index];
        if (mapHas(candidate.context.validated.corpus.evidence, authorityId)) {
            arrayPush(evidenceAuthorityIds, authorityId);
            if (evidenceAuthorityIds.length > MAX_AUTHORITIES)
                return undefined;
        }
    }
    arraySort(evidenceAuthorityIds, compareProtocolStrings);
    return Object.freeze({
        controllingAuthorityIds,
        evidenceAuthorityIds: Object.freeze(evidenceAuthorityIds),
    });
};
const normalizedSelectedPermission = (memo, grant) => {
    const existing = mapGet(memo, grant.authorityId);
    if (existing !== undefined)
        return existing;
    const normalized = normalizedPermission(grant);
    mapSet(memo, grant.authorityId, normalized);
    return normalized;
};
const proofForCandidate = (candidate, projection) => {
    const context = candidate.context;
    const evaluation = candidate.evaluation;
    const normalizedGrants = createMap();
    const intersections = [];
    for (let index = 0; index < candidate.intersections.length; index += 1) {
        const plannedIntersection = candidate.intersections[index];
        const selection = plannedIntersection.selection;
        const normalizedPath = [];
        for (let pathIndex = 0; pathIndex < selection.path.grants.length; pathIndex += 1) {
            arrayPush(normalizedPath, normalizedSelectedPermission(normalizedGrants, selection.path.grants[pathIndex]));
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
    const normalizedMain = [];
    for (let index = 0; index < evaluation.graph.main.grants.length; index += 1) {
        const grant = evaluation.graph.main.grants[index];
        arrayPush(normalizedMain, normalizedSelectedPermission(normalizedGrants, grant));
    }
    const usageSnapshot = [];
    for (let index = 0; index < projection.controllingAuthorityIds.length; index += 1) {
        const usage = mapGet(context.validated.corpus.usage, projection.controllingAuthorityIds[index]);
        if (usage !== undefined) {
            arrayPush(usageSnapshot, Object.freeze({
                authorityId: usage.authorityId,
                admittedTransactionCount: usage.admittedTransactionCount,
                admittedCumulativeAmount: usage.admittedCumulativeAmount,
            }));
        }
    }
    const authorityEvidence = [];
    for (let index = 0; index < projection.evidenceAuthorityIds.length; index += 1) {
        const evidence = mapGet(context.validated.corpus.evidence, projection.evidenceAuthorityIds[index]);
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
        if (authority !== 0)
            return authority;
        const grantEvent = compareProtocolStrings(left.grantEventId, right.grantEventId);
        return grantEvent !== 0
            ? grantEvent
            : left.grantEventPosition - right.grantEventPosition;
    });
    const proof = Object.freeze({
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
                credentialKeyId: context.binding.credentialKeyId,
                controlEpoch: context.binding.controlEpoch,
                roleId: context.binding.roleId,
                roleTenureId: context.binding.roleTenureId,
                intentId: context.binding.intentId,
                nonce: context.binding.nonce,
            }
            : {}),
    });
    return proof;
};
const finalizeSuccessfulAuthorityCandidate = (candidate) => {
    const projection = preflightCandidateProof(candidate);
    if (projection === undefined) {
        return indeterminate(candidate.context.operationVersion, "OUTPUT_LIMIT_EXCEEDED", candidate.context.assurance);
    }
    return boundedResult(Object.freeze({
        operationVersion: candidate.context.operationVersion,
        decision: "ALLOW",
        scopeAssurance: candidate.context.assurance,
        consequential: candidate.context.consequential,
        proof: proofForCandidate(candidate, projection),
    }), candidate.context.operationVersion, candidate.context.assurance);
};
const compareOptionalIdentifier = (left, right) => left === undefined
    ? right === undefined ? 0 : -1
    : right === undefined
        ? 1
        : compareProtocolStrings(left, right);
const compareEvidenceReferences = (left, right) => {
    let comparison = compareProtocolStrings(left.eventId, right.eventId);
    if (comparison !== 0)
        return comparison;
    comparison = compareProtocolStrings(left.eventType, right.eventType);
    if (comparison !== 0)
        return comparison;
    if (left.position !== right.position)
        return left.position - right.position;
    return compareProtocolStrings(left.historyHash, right.historyHash);
};
const compareEvidenceSequences = (left, right) => {
    const shared = left.length < right.length ? left.length : right.length;
    for (let index = 0; index < shared; index += 1) {
        const comparison = compareEvidenceReferences(left[index], right[index]);
        if (comparison !== 0)
            return comparison;
    }
    return left.length < right.length ? -1 : left.length > right.length ? 1 : 0;
};
const compareDenialEvidence = (left, right) => {
    const leftRank = Object.hasOwn(PHASE_SEVEN_RANK, left.code)
        ? PHASE_SEVEN_RANK[left.code]
        : -1;
    const rightRank = Object.hasOwn(PHASE_SEVEN_RANK, right.code)
        ? PHASE_SEVEN_RANK[right.code]
        : -1;
    if (leftRank !== rightRank)
        return leftRank - rightRank;
    let comparison = compareOptionalIdentifier(ownOptional(left, "rootAuthorityId"), ownOptional(right, "rootAuthorityId"));
    if (comparison !== 0)
        return comparison;
    comparison = compareOptionalIdentifier(ownOptional(left, "terminalAuthorityId"), ownOptional(right, "terminalAuthorityId"));
    if (comparison !== 0)
        return comparison;
    comparison = compareOptionalIdentifier(ownOptional(left, "failingAuthorityId"), ownOptional(right, "failingAuthorityId"));
    if (comparison !== 0)
        return comparison;
    comparison = compareIdentifierSequences(left.authorityPathIds, right.authorityPathIds);
    if (comparison !== 0)
        return comparison;
    comparison = compareOptionalIdentifier(ownOptional(left, "subjectId"), ownOptional(right, "subjectId"));
    return comparison !== 0
        ? comparison
        : compareEvidenceSequences(left.evidence, right.evidence);
};
const createReplayEvidenceContext = (state) => {
    const prefixHashes = state.eventHistoryHashes;
    if (prefixHashes.length !== state.events.length ||
        prefixHashes[prefixHashes.length - 1] !== state.head.hash) {
        throw new TypeError("Replay evidence prefix commitments disagree with the authoritative state head.");
    }
    return Object.freeze({
        state,
        prefixHashes,
        references: createMap(),
    });
};
const replayEventReference = (context, position) => {
    const cached = mapGet(context.references, position);
    if (cached !== undefined)
        return cached;
    const event = context.state.events[position];
    const historyHash = context.prefixHashes[position];
    if (historyHash === undefined) {
        throw new TypeError("Replay evidence position has no prefix commitment.");
    }
    const reference = Object.freeze({
        kind: "EVENT",
        eventId: event.id,
        eventType: event.type,
        position,
        historyHash,
    });
    mapSet(context.references, position, reference);
    return reference;
};
const sameEventReference = (left, right) => left.eventId === right.eventId &&
    left.eventType === right.eventType &&
    left.position === right.position &&
    left.historyHash === right.historyHash;
const sortedDistinctEventReferences = (references) => {
    const sorted = copyArray(references);
    arraySort(sorted, compareEvidenceReferences);
    const distinct = [];
    for (let index = 0; index < sorted.length; index += 1) {
        if (distinct.length === 0 ||
            !sameEventReference(distinct[distinct.length - 1], sorted[index]))
            arrayPush(distinct, sorted[index]);
    }
    return Object.freeze(distinct);
};
const evidenceForEventPredicate = (context, predicate) => {
    const references = [];
    for (let index = 0; index < context.state.events.length; index += 1) {
        if (predicate(context.state.events[index])) {
            arrayPush(references, replayEventReference(context, index));
        }
    }
    arrayPush(references, replayEventReference(context, context.state.events.length - 1));
    return sortedDistinctEventReferences(references);
};
const authorityDecisionEvidence = (context) => evidenceForEventPredicate(context, (event) => arrayIncludes(Object.freeze([
    "DEPLOYMENT_INITIALIZED",
    "PRINCIPAL_CREATED",
    "AGENT_CREATED",
    "AGENT_TERMINATED",
    "AUTHORITY_GRANTED",
    "AUTHORITY_REVOKED",
    "TRANSACTION_INTENT_ADMITTED",
]), event.type));
const eventData = (event) => event.data;
const agentLifecycleEvidence = (context, actorId) => evidenceForEventPredicate(context, (event) => (event.type === "AGENT_CREATED" || event.type === "AGENT_TERMINATED") &&
    eventData(event).agentId === actorId);
const sessionLifecycleEvidence = (context, actorId, sessionId) => evidenceForEventPredicate(context, (event) => ((event.type === "AGENT_CREATED" || event.type === "AGENT_TERMINATED") &&
    eventData(event).agentId === actorId) ||
    ((event.type === "RUNTIME_SESSION_ADMITTED" ||
        event.type === "CONTROL_EPOCH_ADVANCED") &&
        (eventData(event).agentId === actorId ||
            eventData(event).sessionId === sessionId)));
const tenureLifecycleEvidence = (context, roleId, tenureId) => evidenceForEventPredicate(context, (event) => arrayIncludes(Object.freeze([
    "ROLE_CREATED",
    "AGENT_APPOINTED",
    "AGENT_UNAPPOINTED",
    "ROLE_TRANSFERRED",
]), event.type) &&
    (eventData(event).roleId === roleId ||
        eventData(event).roleTenureId === tenureId ||
        eventData(event).fromRoleTenureId === tenureId ||
        eventData(event).toRoleTenureId === tenureId));
const intentEventValues = (event) => {
    const data = eventData(event);
    if (event.type === "TRANSACTION_INTENT_DECLARED") {
        return Object.freeze({
            intentId: data.intentId,
            actorId: data.actorId,
            nonce: data.nonce,
        });
    }
    if (event.type !== "TRANSACTION_INTENT_ADMITTED")
        return Object.freeze({});
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
const intentDecisionEvidence = (context, actorId, intentId, nonce) => evidenceForEventPredicate(context, (event) => {
    if (event.type !== "TRANSACTION_INTENT_DECLARED" &&
        event.type !== "TRANSACTION_INTENT_ADMITTED")
        return false;
    const values = intentEventValues(event);
    const selectedIntent = intentId === undefined
        ? values.actorId === actorId
        : values.intentId === intentId;
    const nonceCollision = nonce !== undefined &&
        values.actorId === actorId &&
        values.nonce === nonce;
    return selectedIntent || nonceCollision;
});
const denialResult = (operationVersion, assurance, failures) => {
    const sorted = copyArray(failures);
    arraySort(sorted, compareDenialEvidence);
    return Object.freeze({
        operationVersion,
        decision: "DENY",
        scopeAssurance: assurance,
        consequential: false,
        code: sorted[0].code,
        failures: Object.freeze(sorted),
    });
};
const simpleDenial = (operationVersion, assurance, code, evidence = Object.freeze([]), subjectId) => denialResult(operationVersion, assurance, Object.freeze([
    Object.freeze({
        code,
        ...(subjectId === undefined ? {} : { subjectId }),
        authorityPathIds: Object.freeze([]),
        evidence,
    }),
]));
const evidenceOccurrenceCount = (result) => {
    if (result.decision === "ALLOW")
        return 0;
    let count = 0;
    for (let index = 0; index < result.failures.length; index += 1) {
        count += result.failures[index].evidence.length;
        if (count > MAX_RESULT_EVIDENCE)
            return count;
    }
    return count;
};
const boundedResult = (result, operationVersion, assurance) => {
    if (evidenceOccurrenceCount(result) > MAX_RESULT_EVIDENCE) {
        return indeterminate(operationVersion, "OUTPUT_LIMIT_EXCEEDED", assurance);
    }
    try {
        return captureBoundedCanonicalValue(result).value;
    }
    catch (error) {
        if (getCanonicalCaptureLimitErrorMetadata(error) !== undefined) {
            return indeterminate(operationVersion, "OUTPUT_LIMIT_EXCEEDED", assurance);
        }
        throw error;
    }
};
/** Package-internal exact Section 7.1 challenge projection. */
export const createPortableRuntimeAuthorizationChallenge = (input) => {
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
    if (credentialKeyId === undefined ||
        intentId === undefined ||
        nonce === undefined) {
        throw new TypeError("Runtime authorization challenge requires credential, intent, and nonce identifiers.");
    }
    return Object.freeze({
        version: PORTABLE_RUNTIME_AUTHORIZATION_VERSION,
        domain,
        request,
        authoritative: true,
        consequential: true,
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
export const hashPortableRuntimeAuthorizationChallenge = (challenge) => hashCanonical(challenge);
export const portableEip191Digest = (messageHash) => {
    if (!isContentHash(messageHash)) {
        throw new TypeError("EIP-191 message hash must be a ContentHash.");
    }
    const preimage = new HostUint8Array(EIP191_HASH32_PREFIX.length + 32);
    for (let index = 0; index < EIP191_HASH32_PREFIX.length; index += 1) {
        preimage[index] = EIP191_HASH32_PREFIX[index];
    }
    for (let index = 0; index < 32; index += 1) {
        const offset = 2 + (index * 2);
        preimage[EIP191_HASH32_PREFIX.length + index] =
            (hexadecimalNibble(stringCharCodeAt(messageHash, offset)) << 4) |
                hexadecimalNibble(stringCharCodeAt(messageHash, offset + 1));
    }
    return keccak256Bytes(preimage);
};
const modularPower = (base, exponent, modulus) => {
    let factor = base % modulus;
    let remaining = exponent;
    let result = 1n;
    while (remaining > 0n) {
        if ((remaining & 1n) === 1n)
            result = (result * factor) % modulus;
        factor = (factor * factor) % modulus;
        remaining >>= 1n;
    }
    return result;
};
const hexadecimalNibble = (character) => character >= 0x30 && character <= 0x39
    ? character - 0x30
    : character >= 0x41 && character <= 0x46
        ? character - 0x37
        : character >= 0x61 && character <= 0x66
            ? character - 0x57
            : -1;
const fieldMod = (value) => {
    const remainder = value % SECP256K1_FIELD;
    return remainder < 0n ? remainder + SECP256K1_FIELD : remainder;
};
const SECP256K1_INFINITY = objectFreeze({
    x: 0n,
    y: 1n,
    z: 0n,
});
const SECP256K1_BASE = objectFreeze({
    x: SECP256K1_BASE_X,
    y: SECP256K1_BASE_Y,
    z: 1n,
});
const doubleSecp256k1Point = (point) => {
    if (point.z === 0n || point.y === 0n)
        return SECP256K1_INFINITY;
    const xx = fieldMod(point.x * point.x);
    const yy = fieldMod(point.y * point.y);
    const yyyy = fieldMod(yy * yy);
    const slopeProduct = fieldMod(4n * point.x * yy);
    const slope = fieldMod(3n * xx);
    const x = fieldMod((slope * slope) - (2n * slopeProduct));
    const y = fieldMod((slope * (slopeProduct - x)) - (8n * yyyy));
    const z = fieldMod(2n * point.y * point.z);
    return { x, y, z };
};
const addSecp256k1Points = (left, right) => {
    if (left.z === 0n)
        return right;
    if (right.z === 0n)
        return left;
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
    const xDifferenceCubed = fieldMod(xDifference * xDifferenceSquared);
    const leftScaledX = fieldMod(leftX * xDifferenceSquared);
    const x = fieldMod((yDifference * yDifference) - xDifferenceCubed - (2n * leftScaledX));
    const y = fieldMod((yDifference * (leftScaledX - x)) - (leftY * xDifferenceCubed));
    const z = fieldMod(xDifference * left.z * right.z);
    return { x, y, z };
};
const multiplySecp256k1Point = (point, scalar) => {
    let result = SECP256K1_INFINITY;
    let addend = point;
    let remaining = scalar;
    for (let bit = 0; bit < 256; bit += 1) {
        if ((remaining & 1n) === 1n) {
            result = addSecp256k1Points(result, addend);
        }
        remaining >>= 1n;
        if (bit < 255)
            addend = doubleSecp256k1Point(addend);
    }
    return remaining === 0n ? result : SECP256K1_INFINITY;
};
const affineSecp256k1Point = (point) => {
    if (point.z === 0n)
        return undefined;
    const inverseZ = modularPower(point.z, SECP256K1_FIELD - 2n, SECP256K1_FIELD);
    const inverseZSquared = fieldMod(inverseZ * inverseZ);
    const x = fieldMod(point.x * inverseZSquared);
    const y = fieldMod(point.y * inverseZSquared * inverseZ);
    if (fieldMod((y * y) - (x * x * x) - 7n) !== 0n)
        return undefined;
    return { x, y };
};
const writeFieldElement = (target, offset, value) => {
    let remaining = value;
    for (let index = 31; index >= 0; index -= 1) {
        target[offset + index] = numberFrom(remaining & 0xffn);
        remaining >>= 8n;
    }
};
/** Package-internal strict EIP-191 recovery shared by Runtime and receipt verification. */
export const recoverPortableContentHashSigner = (contentHash, signature) => {
    if (!isContentHash(contentHash) || !isSignature65(signature)) {
        return undefined;
    }
    try {
        const r = bigintFrom(`0x${stringSlice(signature, 2, 66)}`);
        const s = bigintFrom(`0x${stringSlice(signature, 66, 130)}`);
        const recovery = stringSlice(signature, 130, 132) === "1b" ? 0 : 1;
        const digest = portableEip191Digest(contentHash);
        const ySquared = (r * r % SECP256K1_FIELD * r + 7n) % SECP256K1_FIELD;
        const yRoot = modularPower(ySquared, (SECP256K1_FIELD + 1n) >> 2n, SECP256K1_FIELD);
        if (yRoot * yRoot % SECP256K1_FIELD !== ySquared)
            return undefined;
        const rootIsOdd = (yRoot & 1n) === 1n;
        const y = rootIsOdd === (recovery === 1)
            ? yRoot
            : SECP256K1_FIELD - yRoot;
        const recoveredR = { x: r, y, z: 1n };
        const rInverse = modularPower(r, SECP256K1_ORDER - 2n, SECP256K1_ORDER);
        const message = bigintFrom(digest) % SECP256K1_ORDER;
        const messageFactor = ((SECP256K1_ORDER - message) * rInverse) % SECP256K1_ORDER;
        const signatureFactor = s * rInverse % SECP256K1_ORDER;
        const publicKey = addSecp256k1Points(multiplySecp256k1Point(recoveredR, signatureFactor), multiplySecp256k1Point(SECP256K1_BASE, messageFactor));
        const affine = affineSecp256k1Point(publicKey);
        if (affine === undefined)
            return undefined;
        const publicKeyBytes = new HostUint8Array(64);
        writeFieldElement(publicKeyBytes, 0, affine.x);
        writeFieldElement(publicKeyBytes, 32, affine.y);
        return `0x${stringSlice(keccak256Bytes(publicKeyBytes), 26)}`;
    }
    catch {
        return undefined;
    }
};
export const verifyPortableRuntimeAuthorizationSignature = (expectedAddress, challenge, signature) => {
    if (!isEthereumAddress(expectedAddress) || !isSignature65(signature))
        return false;
    try {
        const signer = recoverPortableContentHashSigner(hashPortableRuntimeAuthorizationChallenge(challenge), signature);
        return signer !== undefined && signer === stringToLowerCase(expectedAddress);
    }
    catch {
        return false;
    }
};
/** Exact immutable intent content; actor-claimed time is intentionally absent. */
export const portableIntentProjection = (request, binding, adapterProfile) => {
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
const sameOptionalScalar = (left, right, key) => Object.hasOwn(left, key) === Object.hasOwn(right, key) &&
    (!Object.hasOwn(left, key) || left[key] === right[key]);
const sameIntent = (left, right) => left.intentId === right.intentId &&
    left.nonce === right.nonce &&
    left.actorId === right.actorId &&
    left.action === right.action &&
    left.resource === right.resource &&
    left.roleId === right.roleId &&
    left.roleTenureId === right.roleTenureId &&
    sameOptionalScalar(left, right, "amount") &&
    sameOptionalScalar(left, right, "counterpartyId") &&
    sameOptionalScalar(left, right, "termsCommitment");
const candidateMeetsAdministrativeRequirements = (validated, path, requirements) => {
    const root = recognizedRootForPath(validated, path);
    if (root?.principalId !== requirements.requiredPrincipalId)
        return false;
    const graph = selectCandidateGraph(validated, path, requirements.request.actorId);
    const controllingIds = createSet();
    for (let pathIndex = 0; pathIndex < graph.paths.length; pathIndex += 1) {
        const selectedPath = graph.paths[pathIndex];
        for (let index = 0; index < selectedPath.grants.length; index += 1) {
            setAdd(controllingIds, selectedPath.grants[index].authorityId);
        }
    }
    for (let index = 0; index < requirements.requiredAuthorityIds.length; index += 1) {
        if (!setHas(controllingIds, requirements.requiredAuthorityIds[index])) {
            return false;
        }
    }
    return true;
};
const evaluateAuthorityAlgebra = (context) => {
    const globalProhibitions = relevantGlobalProhibitions(context.validated, context.request);
    const matchingGlobal = createSet();
    for (let index = 0; index < globalProhibitions.length; index += 1) {
        const prohibition = globalProhibitions[index];
        if (prohibitionIsActive(context.validated, prohibition, context.evaluationTime) &&
            prohibitionMatchesAmount(prohibition, context.request))
            setAdd(matchingGlobal, prohibition.authorityId);
    }
    const globalFailure = leastIdentifier(matchingGlobal);
    if (globalFailure !== undefined) {
        const evidence = context.replayEvidence === undefined
            ? Object.freeze([])
            : authorityDecisionEvidence(context.replayEvidence);
        return boundedResult(denialResult(context.operationVersion, context.assurance, Object.freeze([
            Object.freeze({
                code: "PROHIBITED",
                subjectId: context.request.actorId,
                failingAuthorityId: globalFailure,
                authorityPathIds: Object.freeze([]),
                evidence,
            }),
        ])), context.operationVersion, context.assurance);
    }
    const candidates = [];
    mapForEach(context.validated.paths, (path) => {
        const terminal = path.grants[path.grants.length - 1];
        if (path.effectivelyIndependent &&
            terminal.granteeId === context.request.actorId &&
            (context.administrativeRequirements === undefined ||
                candidateMeetsAdministrativeRequirements(context.validated, path, context.administrativeRequirements)))
            arrayPush(candidates, path);
    });
    let winner;
    const candidateFailures = [];
    for (let index = 0; index < candidates.length; index += 1) {
        const candidate = candidates[index];
        const evaluation = evaluateCandidate(context.validated, candidate, context.request, context.evaluationTime, globalProhibitions);
        if (evaluation.status === "SUCCESS") {
            const successful = candidatePlan(context, evaluation);
            if (winner === undefined ||
                compareSuccessfulCandidates(successful, winner) < 0)
                winner = successful;
        }
        else {
            arrayPush(candidateFailures, { evaluation, path: candidate });
        }
    }
    if (winner !== undefined)
        return winner;
    const decisionEvidence = context.replayEvidence === undefined
        ? Object.freeze([])
        : authorityDecisionEvidence(context.replayEvidence);
    if (candidateFailures.length === 0) {
        return boundedResult(simpleDenial(context.operationVersion, context.assurance, "NO_AUTHORITY", decisionEvidence, context.request.actorId), context.operationVersion, context.assurance);
    }
    const failures = [];
    for (let index = 0; index < candidateFailures.length; index += 1) {
        const failure = candidateFailures[index];
        const terminal = failure.path.grants[failure.path.grants.length - 1];
        arrayPush(failures, Object.freeze({
            code: failure.evaluation.code,
            rootAuthorityId: failure.path.rootAuthorityId,
            terminalAuthorityId: terminal.authorityId,
            failingAuthorityId: failure.evaluation.failingAuthorityId,
            authorityPathIds: failure.path.authorityIds,
            evidence: decisionEvidence,
        }));
    }
    return boundedResult(denialResult(context.operationVersion, context.assurance, Object.freeze(failures)), context.operationVersion, context.assurance);
};
/**
 * Raw supplied-scope authority evaluation. It never claims consequential or
 * replay-verified authority.
 */
export const evaluatePortableAuthorityPath = (input) => {
    const operationVersion = PORTABLE_AUTHORITY_EVALUATION_VERSION;
    const captured = capturePortableAuthorityOperation(input, "AUTHORITY_PATH_EVALUATION");
    if (captured.status !== "CAPTURED") {
        return indeterminate(operationVersion, captured.status === "UNSUPPORTED_VERSION"
            ? "UNSUPPORTED_VERSION"
            : "INVALID_INPUT");
    }
    const capture = captured.capture;
    const body = capture.value;
    const scopeValue = body.scope;
    const requestValue = body.request;
    if (!rawCaptureTimeCollectionsAreValid(capture) ||
        !exactRecord(capture, scopeValue, Object.freeze([
            "domain",
            "policyVersion",
            "rootRecognitionPolicy",
            "historyHead",
            "evaluationTime",
            "recognizedRoots",
            "globalPolicySourceId",
        ])) ||
        !domainIsValid(capture, scopeValue.domain) ||
        !historyHeadIsValid(capture, scopeValue.historyHead) ||
        !Array.isArray(scopeValue.recognizedRoots) ||
        identifierStatus(scopeValue.policyVersion) !== "VALID" ||
        identifierStatus(scopeValue.rootRecognitionPolicy) !== "VALID" ||
        identifierStatus(scopeValue.globalPolicySourceId) !== "VALID" ||
        !requestHasExactShape(capture, requestValue)) {
        return indeterminate(operationVersion, "INVALID_INPUT");
    }
    if (!isU53(scopeValue.evaluationTime)) {
        return indeterminate(operationVersion, "CAUSAL_TIME_INVALID");
    }
    const scope = scopeValue;
    const request = requestValue;
    if (scope.evaluationTime < scope.historyHead.canonicalTime) {
        return indeterminate(operationVersion, "CAUSAL_TIME_INVALID");
    }
    if (scope.rootRecognitionPolicy !== PORTABLE_ROOT_RECOGNITION_POLICY) {
        return simpleDenial(operationVersion, "SUPPLIED_SCOPE", "POLICY_MISMATCH");
    }
    const requestFailure = requestProblem(requestValue);
    if (requestFailure !== undefined) {
        return simpleDenial(operationVersion, "SUPPLIED_SCOPE", requestFailure);
    }
    const construction = rawCorpusFromCapture(capture);
    if (construction.status === "INVALID_INPUT") {
        return indeterminate(operationVersion, "INVALID_INPUT");
    }
    if (construction.status === "INVALID_DELEGATION") {
        return simpleDenial(operationVersion, "SUPPLIED_SCOPE", "INVALID_DELEGATION");
    }
    const validation = validateAuthorityCorpus(construction.corpus);
    if (validation.status === "INVALID_INPUT") {
        return indeterminate(operationVersion, "INVALID_INPUT");
    }
    if (validation.status === "INVALID_DELEGATION") {
        return simpleDenial(operationVersion, "SUPPLIED_SCOPE", "INVALID_DELEGATION");
    }
    const authority = evaluateAuthorityAlgebra(Object.freeze({
        operationVersion,
        assurance: "SUPPLIED_SCOPE",
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
const stagePortableStateAuthorization = (state, body, administrativeRequirements) => {
    const operationVersion = PORTABLE_AUTHORIZATION_VERSION;
    const requestValue = body.request;
    const bindingValue = body.binding;
    const consequential = body.consequential;
    const binding = bindingValue;
    const evidenceContext = createReplayEvidenceContext(state);
    const expectedHistoryHead = body.expectedHistoryHead;
    const headEvidence = Object.freeze([
        replayEventReference(evidenceContext, state.events.length - 1),
    ]);
    if (!sameHistoryHead(expectedHistoryHead, state.head)) {
        return indeterminate(operationVersion, "HISTORY_RELATION_UNVERIFIED", "SUPPLIED_SCOPE", headEvidence);
    }
    if (!isU53(body.evaluationTime) ||
        body.evaluationTime < state.head.canonicalTime) {
        return indeterminate(operationVersion, "CAUSAL_TIME_INVALID", "SUPPLIED_SCOPE", headEvidence);
    }
    const assurance = "REPLAY_VERIFIED";
    const domain = body.domain;
    const policyVersion = body.policyVersion;
    const evaluationTime = body.evaluationTime;
    const request = requestValue;
    const genesisEvidence = Object.freeze([
        replayEventReference(evidenceContext, 0),
    ]);
    const replayDenial = (code, evidence = Object.freeze([]), subjectId) => boundedResult(simpleDenial(operationVersion, assurance, code, evidence, subjectId), operationVersion, assurance);
    if (!sameDomain(domain, state.genesis.domain)) {
        return replayDenial("DOMAIN_MISMATCH", genesisEvidence);
    }
    if (policyVersion !== state.genesis.policyVersion ||
        body.rootRecognitionPolicy !== state.genesis.rootRecognitionPolicy)
        return replayDenial("POLICY_MISMATCH", genesisEvidence);
    const requestFailure = requestProblem(requestValue);
    if (requestFailure !== undefined)
        return replayDenial(requestFailure);
    const corpusValidation = validateAuthorityCorpus(replayCorpus(state));
    if (corpusValidation.status === "INVALID_INPUT") {
        return indeterminate(operationVersion, "STATE_NOT_AUTHORITATIVE", "SUPPLIED_SCOPE");
    }
    if (corpusValidation.status === "INVALID_DELEGATION") {
        return replayDenial("INVALID_DELEGATION", authorityDecisionEvidence(evidenceContext));
    }
    const replayAgents = ownOptional(corpusValidation.value.corpus, "replayAgents");
    const agent = replayAgents === undefined
        ? undefined
        : mapGet(replayAgents, request.actorId);
    if (agent === undefined || agent.terminated) {
        return replayDenial("AGENT_INACTIVE", agentLifecycleEvidence(evidenceContext, request.actorId), request.actorId);
    }
    if (consequential && binding !== undefined) {
        const session = mapGet(state.runtimeSessions, binding.runtimeSessionId);
        if (session === undefined || session.agentId !== agent.id) {
            return replayDenial("SESSION_NOT_FOUND", sessionLifecycleEvidence(evidenceContext, request.actorId, binding.runtimeSessionId), binding.runtimeSessionId);
        }
        if (ownOptional(session, "expiresAt") !== undefined &&
            evaluationTime >= session.expiresAt) {
            return replayDenial("SESSION_EXPIRED", sessionLifecycleEvidence(evidenceContext, request.actorId, binding.runtimeSessionId), binding.runtimeSessionId);
        }
        const credentialKeyId = ownOptional(binding, "credentialKeyId");
        const runtimeSignature = ownOptional(binding, "runtimeSignature");
        if (credentialKeyId === undefined || runtimeSignature === undefined) {
            return replayDenial("SESSION_CREDENTIAL_REQUIRED", sessionLifecycleEvidence(evidenceContext, request.actorId, binding.runtimeSessionId), binding.runtimeSessionId);
        }
        if (credentialKeyId !== session.credentialKeyId) {
            return replayDenial("SESSION_CREDENTIAL_INVALID", sessionLifecycleEvidence(evidenceContext, request.actorId, binding.runtimeSessionId), binding.runtimeSessionId);
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
            if (!verifyPortableRuntimeAuthorizationSignature(session.credentialAddressKey, challenge, runtimeSignature)) {
                return replayDenial("SESSION_CREDENTIAL_INVALID", sessionLifecycleEvidence(evidenceContext, request.actorId, binding.runtimeSessionId), binding.runtimeSessionId);
            }
        }
        if (session.controlEpoch < agent.currentControlEpoch) {
            return replayDenial("SESSION_FENCED", sessionLifecycleEvidence(evidenceContext, request.actorId, binding.runtimeSessionId), binding.runtimeSessionId);
        }
        if (binding.controlEpoch !== session.controlEpoch ||
            binding.controlEpoch !== agent.currentControlEpoch) {
            return replayDenial("STALE_EPOCH", sessionLifecycleEvidence(evidenceContext, request.actorId, binding.runtimeSessionId), binding.runtimeSessionId);
        }
        const role = mapGet(state.roles, binding.roleId);
        const tenure = mapGet(state.tenures, binding.roleTenureId);
        if (role === undefined ||
            tenure === undefined ||
            ownOptional(role, "currentTenureId") !== binding.roleTenureId ||
            tenure.closed ||
            tenure.roleId !== binding.roleId ||
            tenure.agentId !== agent.id) {
            return replayDenial("ROLE_TENURE_NOT_CURRENT", tenureLifecycleEvidence(evidenceContext, binding.roleId, binding.roleTenureId), binding.roleTenureId);
        }
        if (intentId === undefined || nonce === undefined) {
            return replayDenial("INTENT_REQUIRED", intentDecisionEvidence(evidenceContext, request.actorId), request.actorId);
        }
        const declaration = mapGet(state.intentDeclarations, intentId);
        if (declaration === undefined) {
            return replayDenial("INTENT_NOT_DECLARED", intentDecisionEvidence(evidenceContext, request.actorId, intentId, nonce), intentId);
        }
        const projection = portableIntentProjection(request, binding, declaration.data.adapterProfile);
        if (!sameIntent(declaration.data, projection)) {
            return replayDenial("INTENT_MISMATCH", intentDecisionEvidence(evidenceContext, request.actorId, intentId, nonce), intentId);
        }
        if (mapHas(state.intentAdmissions, intentId)) {
            return replayDenial("INTENT_REPLAY", intentDecisionEvidence(evidenceContext, request.actorId, intentId, nonce), intentId);
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
export const createPortableAdministrativePolicyProof = (state, requirements, evaluationTime) => {
    if (Object.hasOwn(requirements.request, "amount"))
        return undefined;
    const candidate = stagePortableStateAuthorization(state, Object.freeze({
        expectedHistoryHead: state.head,
        domain: state.genesis.domain,
        policyVersion: state.genesis.policyVersion,
        rootRecognitionPolicy: state.genesis.rootRecognitionPolicy,
        request: requirements.request,
        evaluationTime,
        consequential: false,
    }), requirements);
    if (candidate.decision !== "ALLOW_CANDIDATE")
        return undefined;
    // The administrative restriction applies to the ordinary canonical winner.
    // A capped winner cannot silently fall through to a second candidate.
    const paths = candidate.evaluation.graph.paths;
    for (let pathIndex = 0; pathIndex < paths.length; pathIndex += 1) {
        const path = paths[pathIndex];
        for (let index = 0; index < path.grants.length; index += 1) {
            const constraints = path.grants[index].constraints;
            if (constraints.quantitative ||
                Object.hasOwn(constraints, "maxAmount") ||
                Object.hasOwn(constraints, "maxCumulativeAmount") ||
                Object.hasOwn(constraints, "maxTransactions"))
                return undefined;
        }
    }
    const authorization = finalizeSuccessfulAuthorityCandidate(candidate);
    if (authorization.decision !== "ALLOW" ||
        authorization.scopeAssurance !== "REPLAY_VERIFIED" ||
        authorization.consequential ||
        authorization.proof.usageSnapshot.length !== 0)
        return undefined;
    return authorization.proof;
};
/** Validate a closed administrative event against replay's exact prior state. */
export const validatePortableAdministrativeTransition = (state, event, requirements) => {
    if (event.type !== "OBLIGATION_CREATED" &&
        event.type !== "OBLIGATION_PERFORMANCE_ASSIGNED" &&
        event.type !== "OBLIGATION_STATUS_RECORDED" &&
        event.type !== "OUTCOME_OBSERVATION_RECORDED" &&
        event.type !== "ATTEMPT_DUTY_CREATED" &&
        event.type !== "ATTEMPT_DUTY_ASSIGNED" &&
        event.type !== "ATTEMPT_DUTY_REVIEW_CLOSED")
        return false;
    if ((event.type === "OUTCOME_OBSERVATION_RECORDED" || event.type === "ATTEMPT_DUTY_CREATED" ||
        event.type === "ATTEMPT_DUTY_ASSIGNED") && state.genesis.adapterPolicyHash !== PORTABLE_ADAPTER_POLICY_E5_HASH &&
        state.genesis.adapterPolicyHash !== PORTABLE_ADAPTER_POLICY_E6_HASH)
        return false;
    if (event.type === "ATTEMPT_DUTY_REVIEW_CLOSED" && state.genesis.adapterPolicyHash !== PORTABLE_ADAPTER_POLICY_E6_HASH)
        return false;
    const data = event.data;
    const wrapper = data.administrativeAuthorization;
    const challenge = wrapper.challenge;
    const proof = wrapper.authorityProof;
    if (canonicalEncode(challenge.domain) !== canonicalEncode(state.genesis.domain) ||
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
        challenge.roleTenureId !== requirements.roleTenureId)
        return false;
    const actor = mapGet(state.agents, requirements.request.actorId);
    const session = mapGet(state.runtimeSessions, challenge.runtimeSessionId);
    const role = mapGet(state.roles, requirements.roleId);
    const tenure = mapGet(state.tenures, requirements.roleTenureId);
    if (actor === undefined || actor.terminated ||
        session === undefined || session.agentId !== actor.id ||
        (session.expiresAt !== undefined && event.timestamp >= session.expiresAt) ||
        session.credentialKeyId !== challenge.credentialKeyId ||
        session.controlEpoch !== challenge.controlEpoch ||
        actor.currentControlEpoch !== challenge.controlEpoch ||
        role === undefined || role.currentTenureId !== requirements.roleTenureId ||
        tenure === undefined || tenure.closed ||
        tenure.roleId !== requirements.roleId || tenure.agentId !== actor.id)
        return false;
    // Accepted replay enforces one active Session per Agent/current Epoch at
    // admission. With nondecreasing canonical time, none can become active again.
    if (recoverPortableContentHashSigner(hashCanonical(challenge), wrapper.runtimeSignature) !==
        session.credentialAddressKey)
        return false;
    const expected = createPortableAdministrativePolicyProof(state, requirements, event.timestamp);
    return expected !== undefined && canonicalEncode(expected) === canonicalEncode(proof);
};
const occupiedCandidateNonceDenial = (state, candidate) => {
    const context = candidate.context;
    const binding = ownOptional(context, "binding");
    if (!context.consequential || binding === undefined)
        return undefined;
    const nonce = ownOptional(binding, "nonce");
    if (nonce === undefined)
        return undefined;
    const actorReservations = mapGet(state.nonceReservationsByActor, context.request.actorId);
    if (actorReservations === undefined || !mapHas(actorReservations, nonce)) {
        return undefined;
    }
    const evidenceContext = ownOptional(context, "replayEvidence");
    if (evidenceContext === undefined) {
        throw new TypeError("Replay authority candidate lost evidence context.");
    }
    return boundedResult(simpleDenial(context.operationVersion, context.assurance, "NONCE_ALREADY_ADMITTED", intentDecisionEvidence(evidenceContext, context.request.actorId, ownOptional(binding, "intentId"), nonce), nonce), context.operationVersion, context.assurance);
};
const authorizePortableState = (state, body) => {
    const authority = stagePortableStateAuthorization(state, body);
    if (authority.decision !== "ALLOW_CANDIDATE")
        return authority;
    const nonceDenial = occupiedCandidateNonceDenial(state, authority);
    return nonceDenial ?? finalizeSuccessfulAuthorityCandidate(authority);
};
/** Evaluate one provenance-bound, structurally captured AUTHORIZE body. */
export const capturedPortableAuthorizeInputIsStructurallyValid = (capture) => {
    if (!isCapturedCanonicalAuthorityOperation(capture)) {
        throw new TypeError("Portable authority capture lost provenance.");
    }
    const body = capture.value;
    const requestValue = body.request;
    const bindingValue = body.binding;
    if (!Array.isArray(body.events) ||
        !domainIsValid(capture, body.domain) ||
        !historyHeadIsValid(capture, body.expectedHistoryHead) ||
        identifierStatus(body.policyVersion) !== "VALID" ||
        identifierStatus(body.rootRecognitionPolicy) !== "VALID" ||
        !requestHasExactShape(capture, requestValue) ||
        body.authoritative !== true ||
        typeof body.consequential !== "boolean")
        return false;
    const hasBinding = Object.hasOwn(body, "binding");
    return !(hasBinding !== body.consequential ||
        (hasBinding && !bindingIsStructurallyValid(capture, bindingValue)));
};
/** Evaluate one provenance-bound, structurally captured AUTHORIZE body. */
export const authorizeCapturedPortableState = (capture, state) => {
    const operationVersion = PORTABLE_AUTHORIZATION_VERSION;
    if (!capturedPortableAuthorizeInputIsStructurallyValid(capture)) {
        return indeterminate(operationVersion, "INVALID_INPUT");
    }
    const body = capture.value;
    const requestValue = body.request;
    const bindingValue = body.binding;
    const hasBinding = Object.hasOwn(body, "binding");
    return authorizePortableState(state, Object.freeze({
        expectedHistoryHead: body.expectedHistoryHead,
        domain: body.domain,
        policyVersion: body.policyVersion,
        rootRecognitionPolicy: body.rootRecognitionPolicy,
        request: requestValue,
        evaluationTime: body.evaluationTime,
        consequential: body.consequential,
        ...(hasBinding
            ? { binding: bindingValue }
            : {}),
    }));
};
const admissionAuthorizationBranch = (result) => result.decision === "DENY"
    ? Object.freeze({ status: "DENIED", authorization: result })
    : Object.freeze({ status: "INDETERMINATE", authorization: result });
const collidingEventEvidence = (context, eventId) => {
    const evidence = [];
    for (let index = 0; index < context.state.events.length; index += 1) {
        if (context.state.events[index].id === eventId) {
            arrayPush(evidence, replayEventReference(context, index));
            break;
        }
    }
    arrayPush(evidence, replayEventReference(context, context.state.events.length - 1));
    return sortedDistinctEventReferences(evidence);
};
/**
 * Exact pre-proposal admission state machine after one caller capture and one
 * authoritative replay. Prospective event capture/replay remains in the outer
 * admission façade to keep this engine below replay at runtime.
 */
export const capturedPortableIntentAdmissionInputIsStructurallyValid = (capture) => {
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
export const evaluateCapturedPortableIntentAdmissionState = (capture, state) => {
    const operationVersion = PORTABLE_AUTHORIZATION_VERSION;
    if (!capturedPortableIntentAdmissionInputIsStructurallyValid(capture)) {
        return Object.freeze({
            status: "INDETERMINATE",
            authorization: indeterminate(operationVersion, "INVALID_INPUT"),
        });
    }
    const body = capture.value;
    const requestValue = body.request;
    const bindingValue = body.binding;
    const evidenceContext = createReplayEvidenceContext(state);
    const headEvidence = Object.freeze([
        replayEventReference(evidenceContext, state.events.length - 1),
    ]);
    if (!isU53(body.evaluationTime) ||
        body.evaluationTime < state.head.canonicalTime) {
        return Object.freeze({
            status: "INDETERMINATE",
            authorization: indeterminate(operationVersion, "CAUSAL_TIME_INVALID", "SUPPLIED_SCOPE", headEvidence),
        });
    }
    const domain = body.domain;
    const policyVersion = body.policyVersion;
    const expectedHead = body.expectedHistoryHead;
    const request = requestValue;
    const binding = bindingValue;
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
    if (retryProjection !== undefined &&
        sameIntent(declaration.data, retryProjection)) {
        const existing = mapGet(state.intentAdmissions, intentId);
        if (existing !== undefined) {
            return Object.freeze({
                status: "RETRY",
                intentId: intentId,
                existingAdmissionEventId: existing.admissionEventId,
                existingAdmissionHead: existing.admissionHead,
            });
        }
    }
    if (!sameHistoryHead(expectedHead, state.head)) {
        return Object.freeze({
            status: "CONFLICT",
            expectedHead,
            observedHead: state.head,
        });
    }
    if (scopeMatches &&
        requestFailure === undefined &&
        intentId !== undefined &&
        nonce !== undefined &&
        declaration !== undefined &&
        !sameIntent(declaration.data, portableIntentProjection(request, binding, declaration.data.adapterProfile))) {
        const mismatch = boundedResult(simpleDenial(operationVersion, "REPLAY_VERIFIED", "INTENT_MISMATCH", intentDecisionEvidence(evidenceContext, request.actorId, intentId, nonce), intentId), operationVersion, "REPLAY_VERIFIED");
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
    if (completeCredentialKeyId === undefined ||
        completeIntentId === undefined ||
        completeNonce === undefined ||
        completeSignature === undefined) {
        throw new TypeError("Portable admission ALLOW lost consequential binding fields.");
    }
    const admissionEventId = body.admissionEventId;
    for (let index = 0; index < state.events.length; index += 1) {
        if (state.events[index].id !== admissionEventId)
            continue;
        const collision = boundedResult(indeterminate(operationVersion, "INVALID_INPUT", "REPLAY_VERIFIED", collidingEventEvidence(evidenceContext, admissionEventId), admissionEventId), operationVersion, "REPLAY_VERIFIED");
        return Object.freeze({
            status: "INDETERMINATE",
            authorization: collision,
        });
    }
    const authorization = finalizeSuccessfulAuthorityCandidate(authority);
    if (authorization.decision !== "ALLOW") {
        return admissionAuthorizationBranch(authorization);
    }
    return Object.freeze({
        status: "AUTHORIZED",
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
const invalidAdmissionTransition = Object.freeze({
    status: "INVALID",
});
/**
 * Replay-side validation of the complete stored admission evidence at its
 * exact pre-event state. The returned reservations are applied atomically by
 * replay only after every predicate succeeds.
 */
export const validatePortableIntentAdmissionTransition = (state, event) => {
    if (event.type !== "TRANSACTION_INTENT_ADMITTED") {
        return invalidAdmissionTransition;
    }
    const data = event.data;
    const proof = data.authorizationProof;
    if (event.timestamp !== data.evaluationTime ||
        data.evaluationTime !== proof.evaluationTime ||
        data.intentId !== proof.intentId ||
        !sameHistoryHead(data.expectedHistoryHead, state.head) ||
        !sameHistoryHead(proof.historyHead, state.head) ||
        proof.consequential !== true ||
        proof.rootRecognitionPolicy !== PORTABLE_ROOT_RECOGNITION_POLICY)
        return invalidAdmissionTransition;
    const runtimeSignature = data.runtimeSignature;
    if (!isSignature65(runtimeSignature))
        return invalidAdmissionTransition;
    const binding = Object.freeze({
        runtimeSessionId: proof.runtimeSessionId,
        credentialKeyId: proof.credentialKeyId,
        controlEpoch: proof.controlEpoch,
        roleId: proof.roleId,
        roleTenureId: proof.roleTenureId,
        intentId: proof.intentId,
        nonce: proof.nonce,
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
    if (data.runtimeAuthorizationHash !==
        hashPortableRuntimeAuthorizationChallenge(challenge))
        return invalidAdmissionTransition;
    const actor = mapGet(state.agents, proof.request.actorId);
    const session = mapGet(state.runtimeSessions, proof.runtimeSessionId);
    if (actor === undefined ||
        session === undefined ||
        session.agentId !== actor.id ||
        session.credentialKeyId !== proof.credentialKeyId ||
        !verifyPortableRuntimeAuthorizationSignature(session.credentialAddressKey, challenge, runtimeSignature))
        return invalidAdmissionTransition;
    const authorization = authorizePortableState(state, Object.freeze({
        expectedHistoryHead: state.head,
        domain: proof.domain,
        policyVersion: proof.policyVersion,
        rootRecognitionPolicy: proof.rootRecognitionPolicy,
        request: proof.request,
        evaluationTime: proof.evaluationTime,
        consequential: true,
        binding,
    }));
    if (authorization.decision !== "ALLOW" ||
        canonicalEncode(authorization.proof) !== canonicalEncode(proof))
        return invalidAdmissionTransition;
    const declaration = mapGet(state.intentDeclarations, proof.intentId);
    if (declaration === undefined ||
        !sameIntent(declaration.data, portableIntentProjection(proof.request, binding, declaration.data.adapterProfile)) ||
        mapHas(state.intentAdmissions, proof.intentId))
        return invalidAdmissionTransition;
    const usage = [];
    const amount = ownOptional(proof.request, "amount");
    for (let index = 0; index < proof.controllingAuthorityIds.length; index += 1) {
        const authorityId = proof.controllingAuthorityIds[index];
        const authority = mapGet(state.authorities, authorityId);
        if (authority === undefined || authority.grant.kind !== "PERMISSION") {
            return invalidAdmissionTransition;
        }
        const maxTransactions = ownOptional(authority.grant.constraints, "maxTransactions");
        const maxCumulativeAmount = ownOptional(authority.grant.constraints, "maxCumulativeAmount");
        if (maxTransactions === undefined && maxCumulativeAmount === undefined) {
            continue;
        }
        const current = mapGet(state.authorityUsage, authorityId);
        if (current === undefined ||
            (maxCumulativeAmount !== undefined && amount === undefined))
            return invalidAdmissionTransition;
        const admittedTransactionCount = current.admittedTransactionCount +
            (maxTransactions === undefined ? 0 : 1);
        const admittedCumulativeAmount = current.admittedCumulativeAmount +
            (maxCumulativeAmount === undefined ? 0n : amount);
        if (!Number.isSafeInteger(admittedTransactionCount) ||
            admittedTransactionCount > (maxTransactions ?? admittedTransactionCount) ||
            admittedCumulativeAmount >
                (maxCumulativeAmount ?? admittedCumulativeAmount) ||
            admittedCumulativeAmount > MAX_BIGINT)
            return invalidAdmissionTransition;
        arrayPush(usage, Object.freeze({
            authorityId,
            admittedTransactionCount,
            admittedCumulativeAmount,
        }));
    }
    return Object.freeze({
        status: "VALID",
        intentId: proof.intentId,
        actorId: proof.request.actorId,
        nonce: proof.nonce,
        usage: Object.freeze(usage),
    });
};
/** Compact, replay-verified output-limit result used by admission orchestration. */
export const portableAdmissionOutputLimit = () => indeterminate(PORTABLE_AUTHORIZATION_VERSION, "OUTPUT_LIMIT_EXCEEDED", "REPLAY_VERIFIED");
/** Closed replay-authorization indeterminate projection for outer façades. */
export const portableReplayAuthorizationIndeterminate = (code, assurance = "SUPPLIED_SCOPE") => indeterminate(PORTABLE_AUTHORIZATION_VERSION, code, assurance);
