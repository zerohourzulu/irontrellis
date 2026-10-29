import { DUTY_POLICY_VERSION, DUTY_POLICY_RULES_HASH } from "./duty-policy.js";
import { resolvePortableAdapterPolicy, validateKnownPortableAdapterProfile, validatePortableAdapterAcknowledgmentShape, validatePortableAdapterNoEffectShape, REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION, } from "./portable-adapter-engine.js";
import { compareProtocolStrings, captureBoundedCanonicalEventData, isCapturedCanonicalReplayEvent, isCapturedCanonicalReplayBody, isCanonicalCaptureLimitError, isCanonicalEventDataShapeError, } from "./canonical.js";
import { arrayIncludes, arrayIsArray, arrayJoin, arrayPush, bigintFrom, createMap, createSet, createWeakMap, createWeakSet, hostObjectPrototype, jsonStringify, mapGet, mapHas, mapSet, numberIsSafeInteger, objectCreate, objectDefineDataProperty, objectEntries, objectFreeze, objectGetPrototypeOf, objectHasOwn, objectIs, reflectApply, reflectGetOwnPropertyDescriptor, reflectGetPrototypeOf, reflectOwnKeys, regExpTest, setAdd, setHas, stringCharCodeAt, stringSlice, weakMapGet, weakMapSet, weakSetAdd, weakSetHas, } from "./host-intrinsics.js";
const Array = objectFreeze({ isArray: arrayIsArray });
const Number = objectFreeze({ isSafeInteger: numberIsSafeInteger });
const Object = objectFreeze({
    create: objectCreate,
    defineDataProperty: objectDefineDataProperty,
    entries: objectEntries,
    freeze: objectFreeze,
    getPrototypeOf: objectGetPrototypeOf,
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
const MAX_IDENTIFIER_BYTES = 256;
const MAX_PROTOCOL_STRING_BYTES = 4_096;
const MAX_LIST_MEMBERS = 4_096;
const MAX_EVENT_DATA_BYTES = 1_048_576;
const MAX_SET_MEMBERS = 256;
const MAX_AUTHORITY_PATH_DEPTH = 32;
const MAX_REQUIRED_INTERSECTIONS = 32;
const MAX_AUTHORITIES = 1_024;
const MAX_BIGINT = (1n << 256n) - 1n;
const MAX_LOW_S = bigintFrom("0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");
export const CORE_EVENT_TYPES = Object.freeze([
    "DEPLOYMENT_INITIALIZED",
    "PRINCIPAL_CREATED",
    "AGENT_CREATED",
    "ROLE_CREATED",
    "SUCCESSION_RULE_DECLARED",
    "AGENT_APPOINTED",
    "AGENT_UNAPPOINTED",
    "ROLE_TRANSFERRED",
    "RUNTIME_SESSION_ADMITTED",
    "CONTROL_EPOCH_ADVANCED",
    "AUTHORITY_GRANTED",
    "AUTHORITY_REVOKED",
    "TRANSACTION_INTENT_DECLARED",
    "TRANSACTION_INTENT_ADMITTED",
    "TRANSACTION_INTENT_CONSUMED",
    "TRANSACTION_OUTCOME_RECORDED",
    "RECEIPT_RECORDED",
    "OBLIGATION_CREATED",
    "OBLIGATION_PERFORMANCE_ASSIGNED",
    "OBLIGATION_STATUS_RECORDED",
    "AGENT_TERMINATED",
    "OUTCOME_OBSERVATION_RECORDED",
    "ATTEMPT_DUTY_CREATED",
    "ATTEMPT_DUTY_ASSIGNED",
    "ATTEMPT_DUTY_REVIEW_CLOSED",
    "ATTEMPT_DUTY_POLICY_ACTIVATED",
]);
const EVENT_TYPE_RANK = createMap();
for (let rank = 0; rank < CORE_EVENT_TYPES.length; rank += 1) {
    mapSet(EVENT_TYPE_RANK, CORE_EVENT_TYPES[rank], rank);
}
export const isCoreEventType = (value) => typeof value === "string" && mapHas(EVENT_TYPE_RANK, value);
/** The exact zero-based Section 5.1 rank, or undefined for an unknown type. */
export const coreEventTypeRank = (value) => isCoreEventType(value) ? mapGet(EVENT_TYPE_RANK, value) : undefined;
const CORE_SCHEMA_LIMIT_FAILURES = createWeakSet();
/** @internal Authentic provenance for one snapshot-only named hard-limit failure. */
export const isCoreSchemaLimitFailure = (value) => value !== null &&
    typeof value === "object" &&
    weakSetHas(CORE_SCHEMA_LIMIT_FAILURES, value);
const brandSchemaLimitFailure = (value) => {
    weakSetAdd(CORE_SCHEMA_LIMIT_FAILURES, value);
    return value;
};
class ShapeValidator {
    problem;
    failureKind;
    capturedRecordKeys;
    constructor(capturedRecordKeys) {
        Object.defineDataProperty(this, "problem", undefined, true);
        Object.defineDataProperty(this, "failureKind", undefined, true);
        Object.defineDataProperty(this, "capturedRecordKeys", capturedRecordKeys);
    }
    fail(path, message) {
        if (this.problem === undefined) {
            this.problem = `${path}: ${message}`;
            this.failureKind = "SEMANTIC";
        }
        return false;
    }
    failLimit(path, message) {
        if (this.failureKind !== "LIMIT") {
            this.problem = `${path}: ${message}`;
            this.failureKind = "LIMIT";
        }
        return false;
    }
    record(value, path, required, optional = []) {
        if (!isPlainRecord(value)) {
            this.fail(path, "must be a plain protocol record");
            return undefined;
        }
        const allowed = createSet();
        for (let index = 0; index < required.length; index += 1) {
            setAdd(allowed, required[index]);
        }
        for (let index = 0; index < optional.length; index += 1) {
            setAdd(allowed, optional[index]);
        }
        const keys = this.capturedRecordKeys(value);
        if (keys === undefined) {
            this.fail(path, "is not part of the captured record-key snapshot");
            return undefined;
        }
        for (let index = 0; index < keys.length; index += 1) {
            const key = keys[index];
            if (!setHas(allowed, key)) {
                this.fail(`${path}.${key}`, "is not a declared field");
                return undefined;
            }
        }
        for (let index = 0; index < required.length; index += 1) {
            const key = required[index];
            if (!Object.hasOwn(value, key) || value[key] === undefined) {
                this.fail(`${path}.${key}`, "is required");
                return undefined;
            }
        }
        return value;
    }
}
const isPlainRecord = (value) => {
    if (value === null || typeof value !== "object" || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
};
const boundedWellFormedUtf8Status = (value, maximumBytes) => {
    // Every well-formed UTF-16 code unit contributes at least one UTF-8 byte.
    // This preflight rejects proven overflow without scanning hostile tails.
    if (value.length > maximumBytes)
        return "LIMIT";
    let bytes = 0;
    for (let index = 0; index < value.length; index += 1) {
        const unit = stringCharCodeAt(value, index);
        if (unit <= 0x7f) {
            bytes += 1;
        }
        else if (unit <= 0x7ff) {
            bytes += 2;
        }
        else if (unit >= 0xd800 && unit <= 0xdbff) {
            const next = stringCharCodeAt(value, index + 1);
            if (!(next >= 0xdc00 && next <= 0xdfff))
                return "MALFORMED";
            bytes += 4;
            index += 1;
        }
        else if (unit >= 0xdc00 && unit <= 0xdfff) {
            return "MALFORMED";
        }
        else {
            bytes += 3;
        }
        if (bytes > maximumBytes)
            return "LIMIT";
    }
    return "VALID";
};
const identifier = (v, value, path) => {
    if (typeof value !== "string") {
        return v.fail(path, "must be an Identifier");
    }
    const utf8Status = boundedWellFormedUtf8Status(value, MAX_IDENTIFIER_BYTES);
    if (utf8Status === "LIMIT") {
        return v.failLimit(path, "must be an Identifier");
    }
    if (utf8Status === "MALFORMED" ||
        value.length === 0 ||
        regExpTest(/[\u0000-\u001f\u007f]/u, value))
        return v.fail(path, "must be an Identifier");
    return true;
};
const protocolString = (v, value, path) => {
    if (typeof value !== "string") {
        return v.fail(path, "must be a bounded ProtocolString");
    }
    const utf8Status = boundedWellFormedUtf8Status(value, MAX_PROTOCOL_STRING_BYTES);
    if (utf8Status === "LIMIT") {
        return v.failLimit(path, "must be a bounded ProtocolString");
    }
    if (utf8Status === "MALFORMED")
        return v.fail(path, "must be a bounded ProtocolString");
    return true;
};
const u53 = (v, value, path) => {
    if (typeof value !== "number" ||
        !Number.isSafeInteger(value) ||
        value < 0 ||
        Object.is(value, -0)) {
        return v.fail(path, "must be a U53");
    }
    return true;
};
const amount = (v, value, path) => {
    if (typeof value !== "bigint") {
        return v.fail(path, "must be an Amount");
    }
    if (value < -MAX_BIGINT || value > MAX_BIGINT) {
        return v.failLimit(path, "exceeds the 256-bit BigInt magnitude bound");
    }
    if (value < 0n)
        return v.fail(path, "must be an Amount");
    return true;
};
const contentHash = (v, value, path) => {
    if (typeof value !== "string" || !regExpTest(/^0x[0-9a-f]{64}$/, value)) {
        return v.fail(path, "must be a lowercase ContentHash");
    }
    return true;
};
const ethereumAddress = (v, value, path) => {
    if (typeof value !== "string" || !regExpTest(/^0x[0-9a-fA-F]{40}$/, value)) {
        return v.fail(path, "must be an EthereumAddress");
    }
    return true;
};
const chainId = (v, value, path) => {
    if (typeof value !== "string" || !regExpTest(/^[1-9][0-9]*$/, value)) {
        return v.fail(path, "must be a canonical ChainId string");
    }
    const parsed = bigintFrom(value);
    if (parsed < 1n || parsed > MAX_BIGINT) {
        return v.fail(path, "is outside the ChainId bound");
    }
    return true;
};
const signature65 = (v, value, path) => {
    if (typeof value !== "string" || !regExpTest(/^0x[0-9a-f]{130}$/, value)) {
        return v.fail(path, "must be a lowercase 65-byte signature");
    }
    const s = bigintFrom(`0x${stringSlice(value, 66, 130)}`);
    const recovery = stringSlice(value, 130, 132);
    if (s === 0n || s > MAX_LOW_S || (recovery !== "1b" && recovery !== "1c")) {
        return v.fail(path, "must use a low-s value and recovery byte 27 or 28");
    }
    return true;
};
const literal = (v, value, path, allowed) => typeof value === "string" && arrayIncludes(allowed, value)
    ? true
    : v.fail(path, `must be one of ${arrayJoin(allowed, ", ")}`);
const identifierList = (v, value, path, options = {}) => {
    if (!Array.isArray(value))
        return v.fail(path, "must be a dense Identifier list");
    const ownMaximum = Object.hasOwn(options, "maximum")
        ? options.maximum
        : undefined;
    const nonempty = Object.hasOwn(options, "nonempty")
        ? options.nonempty
        : undefined;
    const maximum = ownMaximum ?? MAX_LIST_MEMBERS;
    if (value.length > maximum) {
        return v.failLimit(path, `exceeds the ${maximum}-member set bound`);
    }
    if (nonempty === true && value.length === 0) {
        return v.fail(path, "has invalid list cardinality");
    }
    const seen = createSet();
    for (let index = 0; index < value.length; index += 1) {
        if (!identifier(v, value[index], `${path}[${index}]`))
            return false;
        if (setHas(seen, value[index]))
            return v.fail(`${path}[${index}]`, "duplicates an Identifier");
        setAdd(seen, value[index]);
    }
    return true;
};
const reviewObservationIds = (v, value, path) => {
    if (!identifierList(v, value, path, { maximum: 128 }))
        return false;
    for (let index = 1; index < value.length; index += 1) {
        if (compareProtocolStrings(value[index - 1], value[index]) >= 0)
            return v.fail(path, "must be strictly sorted");
    }
    return true;
};
const enumList = (v, value, path, allowed, nonempty = false) => {
    if (!Array.isArray(value) || (nonempty && value.length === 0)) {
        return v.fail(path, "must be a dense nonempty enum list");
    }
    const seen = createSet();
    for (let index = 0; index < value.length; index += 1) {
        if (!literal(v, value[index], `${path}[${index}]`, allowed))
            return false;
        if (setHas(seen, value[index]))
            return v.fail(`${path}[${index}]`, "duplicates a member");
        setAdd(seen, value[index]);
    }
    return true;
};
const authorizationDomain = (v, value, path) => {
    const record = v.record(value, path, ["protocol", "version", "deploymentId", "chainId", "verifyingContract"]);
    return record !== undefined &&
        record.protocol === "continuity" &&
        record.version === "0.2" &&
        identifier(v, record.deploymentId, `${path}.deploymentId`) &&
        chainId(v, record.chainId, `${path}.chainId`) &&
        ethereumAddress(v, record.verifyingContract, `${path}.verifyingContract`);
};
const versionSet = (v, value, path) => {
    const record = v.record(value, path, [
        "eventSchemaVersion",
        "receiptSchemaVersion",
        "queryEnvelopeVersion",
        "authorizationProofVersion",
        "runtimeAuthorizationVersion",
        "administrativeAuthorizationVersion",
        "signatureScheme",
    ]);
    if (record === undefined)
        return false;
    const expected = {
        eventSchemaVersion: "continuity-event/0.2",
        receiptSchemaVersion: "continuity-receipt/0.2",
        queryEnvelopeVersion: "continuity-query-envelope/0.2",
        authorizationProofVersion: "continuity-authorization-proof/0.2",
        runtimeAuthorizationVersion: "continuity-runtime-authorization/0.2",
        administrativeAuthorizationVersion: "continuity-administrative-authorization/0.2",
        signatureScheme: "eip191-personal-sign-keccak256",
    };
    const expectedEntries = Object.entries(expected);
    for (let index = 0; index < expectedEntries.length; index += 1) {
        const entry = expectedEntries[index];
        const key = entry[0];
        const expectedValue = entry[1];
        if (record[key] !== expectedValue) {
            return v.fail(`${path}.${key}`, `must equal ${expectedValue}`);
        }
    }
    return true;
};
const declaredVersionSet = (v, value, path) => {
    const record = v.record(value, path, [
        "eventSchemaVersion",
        "receiptSchemaVersion",
        "queryEnvelopeVersion",
        "authorizationProofVersion",
        "runtimeAuthorizationVersion",
        "administrativeAuthorizationVersion",
        "signatureScheme",
    ]);
    return record !== undefined &&
        identifier(v, record.eventSchemaVersion, `${path}.eventSchemaVersion`) &&
        identifier(v, record.receiptSchemaVersion, `${path}.receiptSchemaVersion`) &&
        identifier(v, record.queryEnvelopeVersion, `${path}.queryEnvelopeVersion`) &&
        identifier(v, record.authorizationProofVersion, `${path}.authorizationProofVersion`) &&
        identifier(v, record.runtimeAuthorizationVersion, `${path}.runtimeAuthorizationVersion`) &&
        identifier(v, record.administrativeAuthorizationVersion, `${path}.administrativeAuthorizationVersion`) &&
        identifier(v, record.signatureScheme, `${path}.signatureScheme`);
};
const historyHead = (v, value, path) => {
    const record = v.record(value, path, ["hash", "position", "canonicalTime"]);
    return record !== undefined &&
        contentHash(v, record.hash, `${path}.hash`) &&
        u53(v, record.position, `${path}.position`) &&
        u53(v, record.canonicalTime, `${path}.canonicalTime`);
};
const actionRequest = (v, value, path) => {
    const record = v.record(value, path, ["actorId", "action", "resource", "claimedAt"], ["amount", "counterpartyId", "termsCommitment"]);
    return record !== undefined &&
        identifier(v, record.actorId, `${path}.actorId`) &&
        identifier(v, record.action, `${path}.action`) &&
        identifier(v, record.resource, `${path}.resource`) &&
        u53(v, record.claimedAt, `${path}.claimedAt`) &&
        (record.amount === undefined || amount(v, record.amount, `${path}.amount`)) &&
        (record.counterpartyId === undefined ||
            identifier(v, record.counterpartyId, `${path}.counterpartyId`)) &&
        (record.termsCommitment === undefined ||
            contentHash(v, record.termsCommitment, `${path}.termsCommitment`));
};
const evidenceReference = (v, value, path) => {
    if (!isPlainRecord(value) || typeof value.kind !== "string") {
        return v.fail(path, "must be a tagged EvidenceReference record");
    }
    switch (value.kind) {
        case "EVENT": {
            const record = v.record(value, path, [
                "kind",
                "eventId",
                "eventType",
                "position",
                "historyHash",
            ]);
            return record !== undefined &&
                identifier(v, record.eventId, `${path}.eventId`) &&
                (isCoreEventType(record.eventType) || v.fail(`${path}.eventType`, "is not an EventType")) &&
                u53(v, record.position, `${path}.position`) &&
                contentHash(v, record.historyHash, `${path}.historyHash`);
        }
        case "AUTHORITY": {
            const record = v.record(value, path, ["kind", "authorityId", "grantEventId"]);
            return record !== undefined &&
                identifier(v, record.authorityId, `${path}.authorityId`) &&
                identifier(v, record.grantEventId, `${path}.grantEventId`);
        }
        case "RUNTIME_CREDENTIAL": {
            const record = v.record(value, path, ["kind", "keyId", "sessionId", "admissionEventId"]);
            return record !== undefined &&
                identifier(v, record.keyId, `${path}.keyId`) &&
                identifier(v, record.sessionId, `${path}.sessionId`) &&
                identifier(v, record.admissionEventId, `${path}.admissionEventId`);
        }
        case "RECEIPT_COMMITMENT": {
            const record = v.record(value, path, [
                "kind",
                "receiptContentHash",
                "eventId",
                "position",
            ]);
            return record !== undefined &&
                contentHash(v, record.receiptContentHash, `${path}.receiptContentHash`) &&
                identifier(v, record.eventId, `${path}.eventId`) &&
                u53(v, record.position, `${path}.position`);
        }
        case "EXTERNAL": {
            const record = v.record(value, path, ["kind", "evidenceType", "reference", "attesterId"]);
            return record !== undefined &&
                identifier(v, record.evidenceType, `${path}.evidenceType`) &&
                identifier(v, record.reference, `${path}.reference`) &&
                identifier(v, record.attesterId, `${path}.attesterId`);
        }
        default:
            return v.fail(`${path}.kind`, "is not an EvidenceReference kind");
    }
};
const authorityConstraints = (v, value, path, requiredIntersectionMaximum = MAX_REQUIRED_INTERSECTIONS) => {
    const record = v.record(value, path, ["actions", "resources", "quantitative", "maxDelegationDepth", "requiredIntersectionIds"], ["notBefore", "expiresAt", "maxAmount", "maxCumulativeAmount", "maxTransactions"]);
    if (record === undefined)
        return false;
    if (Array.isArray(record.actions) && record.actions.length > MAX_SET_MEMBERS) {
        return v.failLimit(`${path}.actions`, `exceeds the ${MAX_SET_MEMBERS}-member action set bound`);
    }
    if (Array.isArray(record.resources) && record.resources.length > MAX_SET_MEMBERS) {
        return v.failLimit(`${path}.resources`, `exceeds the ${MAX_SET_MEMBERS}-member resource set bound`);
    }
    if (Array.isArray(record.requiredIntersectionIds) &&
        record.requiredIntersectionIds.length > requiredIntersectionMaximum) {
        return v.failLimit(`${path}.requiredIntersectionIds`, `exceeds the ${requiredIntersectionMaximum}-member required-intersection bound`);
    }
    if (!identifierList(v, record.actions, `${path}.actions`, {
        nonempty: true,
        maximum: MAX_SET_MEMBERS,
    }) ||
        !identifierList(v, record.resources, `${path}.resources`, {
            nonempty: true,
            maximum: MAX_SET_MEMBERS,
        }) ||
        typeof record.quantitative !== "boolean" ||
        !u53(v, record.maxDelegationDepth, `${path}.maxDelegationDepth`) ||
        !identifierList(v, record.requiredIntersectionIds, `${path}.requiredIntersectionIds`, {
            maximum: requiredIntersectionMaximum,
        }) ||
        (record.notBefore !== undefined && !u53(v, record.notBefore, `${path}.notBefore`)) ||
        (record.expiresAt !== undefined && !u53(v, record.expiresAt, `${path}.expiresAt`)) ||
        (record.maxAmount !== undefined && !amount(v, record.maxAmount, `${path}.maxAmount`)) ||
        (record.maxCumulativeAmount !== undefined &&
            !amount(v, record.maxCumulativeAmount, `${path}.maxCumulativeAmount`)) ||
        (record.maxTransactions !== undefined &&
            !u53(v, record.maxTransactions, `${path}.maxTransactions`))) {
        if (v.problem === undefined && typeof record.quantitative !== "boolean") {
            v.fail(`${path}.quantitative`, "must be boolean");
        }
        return false;
    }
    if (record.quantitative === false &&
        (record.maxAmount !== undefined || record.maxCumulativeAmount !== undefined)) {
        return v.fail(path, "nonquantitative constraints cannot carry amount ceilings");
    }
    return true;
};
const permissionGrant = (v, value, path) => {
    const record = v.record(value, path, [
        "kind",
        "authorityId",
        "grantorId",
        "granteeId",
        "rootAuthorityId",
        "independent",
        "constraints",
    ], ["parentAuthorityId"]);
    return record !== undefined &&
        record.kind === "PERMISSION" &&
        identifier(v, record.authorityId, `${path}.authorityId`) &&
        identifier(v, record.grantorId, `${path}.grantorId`) &&
        identifier(v, record.granteeId, `${path}.granteeId`) &&
        identifier(v, record.rootAuthorityId, `${path}.rootAuthorityId`) &&
        (record.parentAuthorityId === undefined ||
            identifier(v, record.parentAuthorityId, `${path}.parentAuthorityId`)) &&
        (typeof record.independent === "boolean" || v.fail(`${path}.independent`, "must be boolean")) &&
        authorityConstraints(v, record.constraints, `${path}.constraints`);
};
const prohibitionGrant = (v, value, path) => {
    if (!isPlainRecord(value) || value.kind !== "PROHIBITION") {
        return v.fail(`${path}.kind`, "must be PROHIBITION");
    }
    if (value.scope === "ROOT") {
        const record = v.record(value, path, ["kind", "scope", "authorityId", "grantorId", "rootAuthorityId", "constraints"], ["subjectActorId", "parentAuthorityId"]);
        return record !== undefined &&
            identifier(v, record.authorityId, `${path}.authorityId`) &&
            identifier(v, record.grantorId, `${path}.grantorId`) &&
            identifier(v, record.rootAuthorityId, `${path}.rootAuthorityId`) &&
            (record.subjectActorId === undefined ||
                identifier(v, record.subjectActorId, `${path}.subjectActorId`)) &&
            (record.parentAuthorityId === undefined ||
                identifier(v, record.parentAuthorityId, `${path}.parentAuthorityId`)) &&
            authorityConstraints(v, record.constraints, `${path}.constraints`);
    }
    if (value.scope === "GLOBAL") {
        const record = v.record(value, path, ["kind", "scope", "authorityId", "grantorId", "constraints"], ["subjectActorId"]);
        return record !== undefined &&
            identifier(v, record.authorityId, `${path}.authorityId`) &&
            identifier(v, record.grantorId, `${path}.grantorId`) &&
            (record.subjectActorId === undefined ||
                identifier(v, record.subjectActorId, `${path}.subjectActorId`)) &&
            authorityConstraints(v, record.constraints, `${path}.constraints`);
    }
    return v.fail(`${path}.scope`, "must be ROOT or GLOBAL");
};
const authorityGrant = (v, value, path) => {
    if (!isPlainRecord(value))
        return v.fail(path, "must be an authority grant record");
    if (value.kind === "PERMISSION")
        return permissionGrant(v, value, path);
    if (value.kind === "PROHIBITION")
        return prohibitionGrant(v, value, path);
    return v.fail(`${path}.kind`, "must be PERMISSION or PROHIBITION");
};
const recognizedRoot = (v, value, path) => {
    const record = v.record(value, path, [
        "rootAuthorityId",
        "principalId",
        "principalRecognitionEventId",
        "rootGrantEventId",
    ]);
    return record !== undefined &&
        identifier(v, record.rootAuthorityId, `${path}.rootAuthorityId`) &&
        identifier(v, record.principalId, `${path}.principalId`) &&
        identifier(v, record.principalRecognitionEventId, `${path}.principalRecognitionEventId`) &&
        identifier(v, record.rootGrantEventId, `${path}.rootGrantEventId`);
};
const authorityUsage = (v, value, path) => {
    const record = v.record(value, path, [
        "authorityId",
        "admittedTransactionCount",
        "admittedCumulativeAmount",
    ]);
    return record !== undefined &&
        identifier(v, record.authorityId, `${path}.authorityId`) &&
        u53(v, record.admittedTransactionCount, `${path}.admittedTransactionCount`) &&
        amount(v, record.admittedCumulativeAmount, `${path}.admittedCumulativeAmount`);
};
const authorityEvidence = (v, value, path) => {
    const record = v.record(value, path, ["authorityId", "grantEventId", "grantEventPosition"]);
    return record !== undefined &&
        identifier(v, record.authorityId, `${path}.authorityId`) &&
        identifier(v, record.grantEventId, `${path}.grantEventId`) &&
        u53(v, record.grantEventPosition, `${path}.grantEventPosition`);
};
const permissionGrantList = (v, value, path, nonempty) => {
    if (!Array.isArray(value)) {
        return v.fail(path, "must be a bounded permission path");
    }
    if (value.length > MAX_AUTHORITY_PATH_DEPTH) {
        return v.failLimit(path, `exceeds the ${MAX_AUTHORITY_PATH_DEPTH}-member authority-path bound`);
    }
    if (nonempty && value.length === 0)
        return v.fail(path, "must be a bounded permission path");
    const seen = createSet();
    for (let index = 0; index < value.length; index += 1) {
        if (!permissionGrant(v, value[index], `${path}[${index}]`))
            return false;
        const authorityId = value[index].authorityId;
        if (setHas(seen, authorityId))
            return v.fail(`${path}[${index}]`, "duplicates a path authority");
        setAdd(seen, authorityId);
    }
    return true;
};
const intersectionProof = (v, value, path) => {
    const record = v.record(value, path, [
        "requiredAuthorityId",
        "requiredByAuthorityIds",
        "recognizedRoot",
        "path",
        "effectiveConstraints",
    ]);
    return record !== undefined &&
        identifier(v, record.requiredAuthorityId, `${path}.requiredAuthorityId`) &&
        identifierList(v, record.requiredByAuthorityIds, `${path}.requiredByAuthorityIds`, {
            nonempty: true,
            maximum: MAX_SET_MEMBERS,
        }) &&
        recognizedRoot(v, record.recognizedRoot, `${path}.recognizedRoot`) &&
        permissionGrantList(v, record.path, `${path}.path`, true) &&
        authorityConstraints(v, record.effectiveConstraints, `${path}.effectiveConstraints`, MAX_SET_MEMBERS);
};
const authorizationProof = (v, value, path) => {
    const optionalConsequentialFields = [
        "runtimeSessionId",
        "credentialKeyId",
        "controlEpoch",
        "roleId",
        "roleTenureId",
        "intentId",
        "nonce",
    ];
    const record = v.record(value, path, [
        "proofVersion",
        "domain",
        "policyVersion",
        "rootRecognitionPolicy",
        "historyHead",
        "evaluationTime",
        "request",
        "recognizedRoot",
        "permissionPath",
        "intersections",
        "effectiveConstraints",
        "controllingAuthorityIds",
        "usageSnapshot",
        "authorityEvidence",
        "checkedProhibitionIds",
        "consequential",
    ], optionalConsequentialFields);
    if (record === undefined)
        return false;
    if (Array.isArray(record.intersections) && record.intersections.length > MAX_SET_MEMBERS) {
        return v.failLimit(`${path}.intersections`, `exceeds the ${MAX_SET_MEMBERS}-member proof-intersection bound`);
    }
    if (Array.isArray(record.usageSnapshot) && record.usageSnapshot.length > MAX_SET_MEMBERS) {
        return v.failLimit(`${path}.usageSnapshot`, `exceeds the ${MAX_SET_MEMBERS}-member authority-usage bound`);
    }
    if (Array.isArray(record.authorityEvidence) && record.authorityEvidence.length > MAX_AUTHORITIES) {
        return v.failLimit(`${path}.authorityEvidence`, `exceeds the ${MAX_AUTHORITIES}-member authority-evidence bound`);
    }
    if (record.proofVersion !== "continuity-authorization-proof/0.2" ||
        !authorizationDomain(v, record.domain, `${path}.domain`) ||
        !identifier(v, record.policyVersion, `${path}.policyVersion`) ||
        record.rootRecognitionPolicy !== "declared-principal-root/0.2" ||
        !historyHead(v, record.historyHead, `${path}.historyHead`) ||
        !u53(v, record.evaluationTime, `${path}.evaluationTime`) ||
        !actionRequest(v, record.request, `${path}.request`) ||
        !recognizedRoot(v, record.recognizedRoot, `${path}.recognizedRoot`) ||
        !permissionGrantList(v, record.permissionPath, `${path}.permissionPath`, true) ||
        !Array.isArray(record.intersections) ||
        !authorityConstraints(v, record.effectiveConstraints, `${path}.effectiveConstraints`, MAX_SET_MEMBERS) ||
        !identifierList(v, record.controllingAuthorityIds, `${path}.controllingAuthorityIds`, {
            nonempty: true,
            maximum: MAX_SET_MEMBERS,
        }) ||
        !Array.isArray(record.usageSnapshot) ||
        !Array.isArray(record.authorityEvidence) ||
        record.authorityEvidence.length === 0 ||
        !identifierList(v, record.checkedProhibitionIds, `${path}.checkedProhibitionIds`, {
            maximum: MAX_SET_MEMBERS,
        }) ||
        typeof record.consequential !== "boolean") {
        if (v.problem === undefined)
            v.fail(path, "contains an invalid AuthorizationProof field");
        return false;
    }
    const intersectionIds = createSet();
    for (let index = 0; index < record.intersections.length; index += 1) {
        const member = record.intersections[index];
        if (!intersectionProof(v, member, `${path}.intersections[${index}]`))
            return false;
        const id = member.requiredAuthorityId;
        if (setHas(intersectionIds, id)) {
            return v.fail(`${path}.intersections[${index}]`, "duplicates a required authority");
        }
        setAdd(intersectionIds, id);
    }
    const usageIds = createSet();
    for (let index = 0; index < record.usageSnapshot.length; index += 1) {
        const member = record.usageSnapshot[index];
        if (!authorityUsage(v, member, `${path}.usageSnapshot[${index}]`))
            return false;
        const id = member.authorityId;
        if (setHas(usageIds, id))
            return v.fail(`${path}.usageSnapshot[${index}]`, "duplicates an authority");
        setAdd(usageIds, id);
    }
    const evidenceIds = createSet();
    for (let index = 0; index < record.authorityEvidence.length; index += 1) {
        const member = record.authorityEvidence[index];
        if (!authorityEvidence(v, member, `${path}.authorityEvidence[${index}]`))
            return false;
        const id = member.authorityId;
        if (setHas(evidenceIds, id)) {
            return v.fail(`${path}.authorityEvidence[${index}]`, "duplicates an authority");
        }
        setAdd(evidenceIds, id);
    }
    for (let index = 0; index < optionalConsequentialFields.length; index += 1) {
        const field = optionalConsequentialFields[index];
        const present = Object.hasOwn(record, field) && record[field] !== undefined;
        if (present !== record.consequential) {
            return v.fail(`${path}.${field}`, record.consequential
                ? "is required for a consequential proof"
                : "must be absent from a nonconsequential proof");
        }
    }
    if (record.consequential) {
        return identifier(v, record.runtimeSessionId, `${path}.runtimeSessionId`) &&
            identifier(v, record.credentialKeyId, `${path}.credentialKeyId`) &&
            u53(v, record.controlEpoch, `${path}.controlEpoch`) &&
            identifier(v, record.roleId, `${path}.roleId`) &&
            identifier(v, record.roleTenureId, `${path}.roleTenureId`) &&
            identifier(v, record.intentId, `${path}.intentId`) &&
            identifier(v, record.nonce, `${path}.nonce`);
    }
    return true;
};
const adapterProfile = (v, value, path) => {
    const profile = v.record(value, path, ["profileId", "profileVersion", "descriptorHash"]);
    return profile !== undefined && validateKnownPortableAdapterProfile(profile);
};
// The enclosing capture owns bytes; these records use the original key snapshot,
// so an unknown field originally present as undefined cannot disappear first.
const adapterEvidence = (v, value, path, noEffect = false) => {
    const record = v.record(value, path, ["schemaVersion", "kind", "adapterProfile", "domain", "intentId", "admissionHead", "idempotencyKey", "submissionFingerprint", "result"]);
    if (record === undefined || !adapterProfile(v, record.adapterProfile, `${path}.adapterProfile`) ||
        !authorizationDomain(v, record.domain, `${path}.domain`) ||
        !historyHead(v, record.admissionHead, `${path}.admissionHead`))
        return false;
    const result = record.result;
    if (!isPlainRecord(result))
        return false;
    if (noEffect) {
        if (v.record(result, `${path}.result`, ["kind", "reference"]) === undefined)
            return false;
        return validatePortableAdapterNoEffectShape(record);
    }
    if (result.kind === "SIMULATED_SUBMISSION") {
        if (v.record(result, `${path}.result`, ["kind", "submissionReference"]) === undefined)
            return false;
    }
    else if (result.kind === "LOCAL_PACKET_CREATED") {
        if (v.record(result, `${path}.result`, ["kind", "manifestDigest"]) === undefined ||
            v.record(result.manifestDigest, `${path}.result.manifestDigest`, ["algorithm", "value"]) === undefined)
            return false;
    }
    else if (result.kind === "REMOTE_SERVICE_REPORTED") {
        if (v.record(result, `${path}.result`, ["kind", "reportDigest"]) === undefined ||
            v.record(result.reportDigest, `${path}.result.reportDigest`, ["algorithm", "value"]) === undefined)
            return false;
    }
    else if (result.kind === "LOCAL_DOCUMENT_RELEASED") {
        if (v.record(result, `${path}.result`, ["kind", "publicationManifestDigest"]) === undefined ||
            v.record(result.publicationManifestDigest, `${path}.result.publicationManifestDigest`, ["algorithm", "value"]) === undefined)
            return false;
    }
    else if (result.kind === "LOCAL_ENDPOINT_STATE_CHANGED") {
        if (v.record(result, `${path}.result`, ["kind", "transitionDigest"]) === undefined ||
            v.record(result.transitionDigest, `${path}.result.transitionDigest`, ["algorithm", "value"]) === undefined)
            return false;
    }
    else
        return false;
    return validatePortableAdapterAcknowledgmentShape(record);
};
const transactionIntent = (v, value, path) => {
    const record = v.record(value, path, ["intentId", "nonce", "actorId", "action", "resource", "roleId", "roleTenureId", "adapterProfile"], ["amount", "counterpartyId", "termsCommitment"]);
    return record !== undefined &&
        adapterProfile(v, record.adapterProfile, `${path}.adapterProfile`) &&
        identifier(v, record.intentId, `${path}.intentId`) &&
        identifier(v, record.nonce, `${path}.nonce`) &&
        identifier(v, record.actorId, `${path}.actorId`) &&
        identifier(v, record.action, `${path}.action`) &&
        identifier(v, record.resource, `${path}.resource`) &&
        identifier(v, record.roleId, `${path}.roleId`) &&
        identifier(v, record.roleTenureId, `${path}.roleTenureId`) &&
        (record.amount === undefined || amount(v, record.amount, `${path}.amount`)) &&
        (record.counterpartyId === undefined ||
            identifier(v, record.counterpartyId, `${path}.counterpartyId`)) &&
        (record.termsCommitment === undefined ||
            contentHash(v, record.termsCommitment, `${path}.termsCommitment`));
};
const OBLIGATION_STATUSES = [
    "OPEN",
    "OUTCOME_UNKNOWN",
    "DISPUTED",
    "DISCHARGED",
    "IMPOSSIBLE_OR_ESCALATED",
];
const obligationTransitionPolicy = (v, value, path) => {
    const record = v.record(value, path, [
        "fromStatus",
        "toStatus",
        "acceptedAttesterIds",
        "action",
        "requiredAuthorityIds",
    ]);
    return record !== undefined &&
        literal(v, record.fromStatus, `${path}.fromStatus`, OBLIGATION_STATUSES) &&
        literal(v, record.toStatus, `${path}.toStatus`, OBLIGATION_STATUSES) &&
        identifierList(v, record.acceptedAttesterIds, `${path}.acceptedAttesterIds`, {
            nonempty: true,
            maximum: MAX_SET_MEMBERS,
        }) &&
        identifier(v, record.action, `${path}.action`) &&
        identifierList(v, record.requiredAuthorityIds, `${path}.requiredAuthorityIds`, {
            nonempty: true,
            maximum: MAX_SET_MEMBERS,
        });
};
const obligationRecord = (v, value, path) => {
    const record = v.record(value, path, [
        "obligationId",
        "sourceIntentId",
        "causalReceiptContentHash",
        "durableRoleId",
        "creationRoleTenureId",
        "description",
        "trigger",
        "deadline",
        "status",
        "beneficiaryId",
        "termsCommitment",
        "performanceAssigneeId",
        "successionRuleId",
        "transitionPolicies",
    ], ["counterpartyId"]);
    if (record === undefined)
        return false;
    if (!identifier(v, record.obligationId, `${path}.obligationId`) ||
        !identifier(v, record.sourceIntentId, `${path}.sourceIntentId`) ||
        !contentHash(v, record.causalReceiptContentHash, `${path}.causalReceiptContentHash`) ||
        !identifier(v, record.durableRoleId, `${path}.durableRoleId`) ||
        !identifier(v, record.creationRoleTenureId, `${path}.creationRoleTenureId`) ||
        !protocolString(v, record.description, `${path}.description`) ||
        !identifier(v, record.trigger, `${path}.trigger`) ||
        !u53(v, record.deadline, `${path}.deadline`) ||
        !literal(v, record.status, `${path}.status`, ["OPEN", "OUTCOME_UNKNOWN"]) ||
        !identifier(v, record.beneficiaryId, `${path}.beneficiaryId`) ||
        (record.counterpartyId !== undefined &&
            !identifier(v, record.counterpartyId, `${path}.counterpartyId`)) ||
        !contentHash(v, record.termsCommitment, `${path}.termsCommitment`) ||
        !identifier(v, record.performanceAssigneeId, `${path}.performanceAssigneeId`) ||
        !identifier(v, record.successionRuleId, `${path}.successionRuleId`) ||
        !Array.isArray(record.transitionPolicies) ||
        record.transitionPolicies.length === 0) {
        if (v.problem === undefined)
            v.fail(path, "contains an invalid ObligationRecord field");
        return false;
    }
    const pairs = createSet();
    for (let index = 0; index < record.transitionPolicies.length; index += 1) {
        const member = record.transitionPolicies[index];
        if (!obligationTransitionPolicy(v, member, `${path}.transitionPolicies[${index}]`)) {
            return false;
        }
        const policy = member;
        const pair = `${policy.fromStatus}\u0000${policy.toStatus}`;
        if (setHas(pairs, pair)) {
            return v.fail(`${path}.transitionPolicies[${index}]`, "duplicates a status-transition pair");
        }
        setAdd(pairs, pair);
    }
    return true;
};
const ADMINISTRATIVE_EVENT_TYPES = [
    "OBLIGATION_CREATED",
    "OBLIGATION_PERFORMANCE_ASSIGNED",
    "OBLIGATION_STATUS_RECORDED",
    "OUTCOME_OBSERVATION_RECORDED",
    "ATTEMPT_DUTY_CREATED",
    "ATTEMPT_DUTY_ASSIGNED",
    "ATTEMPT_DUTY_REVIEW_CLOSED",
    "ATTEMPT_DUTY_POLICY_ACTIVATED",
];
const administrativeChallenge = (v, value, path) => {
    const record = v.record(value, path, [
        "version",
        "domain",
        "request",
        "authoritative",
        "consequential",
        "evaluationTime",
        "policyVersion",
        "rootRecognitionPolicy",
        "eventHistoryHash",
        "eventHistoryPosition",
        "transitionEventId",
        "transitionEventType",
        "transitionEffectHash",
        "runtimeSessionId",
        "credentialKeyId",
        "controlEpoch",
        "roleId",
        "roleTenureId",
        "authorityProofHash",
    ]);
    return record !== undefined &&
        record.version === "continuity-administrative-authorization/0.2" &&
        authorizationDomain(v, record.domain, `${path}.domain`) &&
        actionRequest(v, record.request, `${path}.request`) &&
        (record.authoritative === true || v.fail(`${path}.authoritative`, "must be true")) &&
        (record.consequential === true || v.fail(`${path}.consequential`, "must be true")) &&
        u53(v, record.evaluationTime, `${path}.evaluationTime`) &&
        identifier(v, record.policyVersion, `${path}.policyVersion`) &&
        record.rootRecognitionPolicy === "declared-principal-root/0.2" &&
        contentHash(v, record.eventHistoryHash, `${path}.eventHistoryHash`) &&
        u53(v, record.eventHistoryPosition, `${path}.eventHistoryPosition`) &&
        identifier(v, record.transitionEventId, `${path}.transitionEventId`) &&
        literal(v, record.transitionEventType, `${path}.transitionEventType`, ADMINISTRATIVE_EVENT_TYPES) &&
        contentHash(v, record.transitionEffectHash, `${path}.transitionEffectHash`) &&
        identifier(v, record.runtimeSessionId, `${path}.runtimeSessionId`) &&
        identifier(v, record.credentialKeyId, `${path}.credentialKeyId`) &&
        u53(v, record.controlEpoch, `${path}.controlEpoch`) &&
        identifier(v, record.roleId, `${path}.roleId`) &&
        identifier(v, record.roleTenureId, `${path}.roleTenureId`) &&
        contentHash(v, record.authorityProofHash, `${path}.authorityProofHash`);
};
const administrativeAuthorization = (v, value, path) => {
    const record = v.record(value, path, ["challenge", "authorityProof", "runtimeSignature"]);
    return record !== undefined &&
        administrativeChallenge(v, record.challenge, `${path}.challenge`) &&
        authorizationProof(v, record.authorityProof, `${path}.authorityProof`) &&
        signature65(v, record.runtimeSignature, `${path}.runtimeSignature`);
};
const obligationCreatedData = (v, value, path) => {
    const record = v.record(value, path, ["record", "actorId", "administrativeAuthorization"]);
    return record !== undefined &&
        obligationRecord(v, record.record, `${path}.record`) &&
        identifier(v, record.actorId, `${path}.actorId`) &&
        administrativeAuthorization(v, record.administrativeAuthorization, `${path}.administrativeAuthorization`);
};
const dutyPolicyDescriptor = (v, value, path) => {
    const r = v.record(value, path, ["version", "rulesHash", "criteriaProfile", "domain", "genesisHash",
        "baseAdapterPolicyHash", "dutyId", "dutyCreationEventId", "dutyRecordHash", "sourceIntentId",
        "sourceAdmissionEventId", "durableRoleId", "principalId", "incidentSourceDigest", "acceptedAttesterRoleId",
        "dispositionLimit", "contestLimit"]);
    if (!r || r.version !== DUTY_POLICY_VERSION || r.rulesHash !== DUTY_POLICY_RULES_HASH ||
        r.criteriaProfile !== "local-investigation/1" || r.dispositionLimit !== 4 || r.contestLimit !== 2)
        return false;
    const digest = v.record(r.incidentSourceDigest, `${path}.incidentSourceDigest`, ["algorithm", "value"]);
    return digest !== undefined && digest.algorithm === "sha256" && contentHash(v, digest.value, `${path}.incidentSourceDigest.value`) &&
        authorizationDomain(v, r.domain, `${path}.domain`) && contentHash(v, r.genesisHash, `${path}.genesisHash`) &&
        contentHash(v, r.baseAdapterPolicyHash, `${path}.baseAdapterPolicyHash`) && contentHash(v, r.dutyRecordHash, `${path}.dutyRecordHash`) &&
        identifier(v, r.dutyId, `${path}.dutyId`) && identifier(v, r.dutyCreationEventId, `${path}.dutyCreationEventId`) &&
        identifier(v, r.sourceIntentId, `${path}.sourceIntentId`) && identifier(v, r.sourceAdmissionEventId, `${path}.sourceAdmissionEventId`) &&
        identifier(v, r.durableRoleId, `${path}.durableRoleId`) && identifier(v, r.principalId, `${path}.principalId`) &&
        identifier(v, r.acceptedAttesterRoleId, `${path}.acceptedAttesterRoleId`);
};
const attemptDutyRecord = (v, value, path) => {
    const record = v.record(value, path, [
        "dutyId", "sourceIntentId", "sourceAdmissionEventId", "durableRoleId", "creationRoleTenureId",
        "description", "deadline", "performanceAssigneeId", "status",
    ]);
    return record !== undefined &&
        identifier(v, record.dutyId, `${path}.dutyId`) &&
        identifier(v, record.sourceIntentId, `${path}.sourceIntentId`) &&
        identifier(v, record.sourceAdmissionEventId, `${path}.sourceAdmissionEventId`) &&
        identifier(v, record.durableRoleId, `${path}.durableRoleId`) &&
        identifier(v, record.creationRoleTenureId, `${path}.creationRoleTenureId`) &&
        protocolString(v, record.description, `${path}.description`) &&
        u53(v, record.deadline, `${path}.deadline`) &&
        identifier(v, record.performanceAssigneeId, `${path}.performanceAssigneeId`) &&
        literal(v, record.status, `${path}.status`, ["OPEN"]);
};
const LIMIT_IDENTIFIER = Object.freeze({ kind: "IDENTIFIER" });
const LIMIT_BIGINT = Object.freeze({ kind: "BIGINT" });
const limitField = (name, node) => Object.freeze([name, node]);
const limitVariant = (tag, node) => Object.freeze([tag, node]);
const limitRecord = (...fields) => Object.freeze({ kind: "RECORD", fields: Object.freeze(fields) });
const limitList = (member, maximum, boundName) => Object.freeze({
    kind: "LIST",
    member,
    maximum,
    boundName,
});
const limitTaggedRecord = (tagField, variants, common) => Object.freeze({
    kind: "TAGGED_RECORD",
    tagField,
    variants: Object.freeze(variants),
    common,
});
const LIMIT_DOMAIN = limitRecord(limitField("deploymentId", LIMIT_IDENTIFIER));
const LIMIT_ADAPTER_PROFILE = limitRecord(limitField("profileId", LIMIT_IDENTIFIER), limitField("profileVersion", LIMIT_IDENTIFIER));
const LIMIT_ADAPTER_EVIDENCE = limitRecord(limitField("schemaVersion", LIMIT_IDENTIFIER), limitField("kind", LIMIT_IDENTIFIER), limitField("adapterProfile", LIMIT_ADAPTER_PROFILE), limitField("domain", LIMIT_DOMAIN), limitField("intentId", LIMIT_IDENTIFIER), limitField("result", limitRecord(limitField("kind", LIMIT_IDENTIFIER), limitField("reportDigest", limitRecord(limitField("algorithm", LIMIT_IDENTIFIER))), limitField("publicationManifestDigest", limitRecord(limitField("algorithm", LIMIT_IDENTIFIER))), limitField("manifestDigest", limitRecord(limitField("algorithm", LIMIT_IDENTIFIER))), limitField("transitionDigest", limitRecord(limitField("algorithm", LIMIT_IDENTIFIER))))));
const LIMIT_VERSION_SET = limitRecord(limitField("eventSchemaVersion", LIMIT_IDENTIFIER), limitField("receiptSchemaVersion", LIMIT_IDENTIFIER), limitField("queryEnvelopeVersion", LIMIT_IDENTIFIER), limitField("authorizationProofVersion", LIMIT_IDENTIFIER), limitField("runtimeAuthorizationVersion", LIMIT_IDENTIFIER), limitField("administrativeAuthorizationVersion", LIMIT_IDENTIFIER), limitField("signatureScheme", LIMIT_IDENTIFIER));
const LIMIT_ACTION_REQUEST = limitRecord(limitField("actorId", LIMIT_IDENTIFIER), limitField("action", LIMIT_IDENTIFIER), limitField("resource", LIMIT_IDENTIFIER), limitField("amount", LIMIT_BIGINT), limitField("counterpartyId", LIMIT_IDENTIFIER));
const LIMIT_EVIDENCE_REFERENCE = limitTaggedRecord("kind", [
    limitVariant("EVENT", limitRecord(limitField("eventId", LIMIT_IDENTIFIER))),
    limitVariant("AUTHORITY", limitRecord(limitField("authorityId", LIMIT_IDENTIFIER), limitField("grantEventId", LIMIT_IDENTIFIER))),
    limitVariant("RUNTIME_CREDENTIAL", limitRecord(limitField("keyId", LIMIT_IDENTIFIER), limitField("sessionId", LIMIT_IDENTIFIER), limitField("admissionEventId", LIMIT_IDENTIFIER))),
    limitVariant("RECEIPT_COMMITMENT", limitRecord(limitField("eventId", LIMIT_IDENTIFIER))),
    limitVariant("EXTERNAL", limitRecord(limitField("evidenceType", LIMIT_IDENTIFIER), limitField("reference", LIMIT_IDENTIFIER), limitField("attesterId", LIMIT_IDENTIFIER))),
]);
const limitIdentifierSet = (boundName) => limitList(LIMIT_IDENTIFIER, MAX_SET_MEMBERS, boundName);
const limitAuthorityConstraints = (requiredIntersectionMaximum) => limitRecord(limitField("actions", limitIdentifierSet("action set")), limitField("resources", limitIdentifierSet("resource set")), limitField("requiredIntersectionIds", limitList(LIMIT_IDENTIFIER, requiredIntersectionMaximum, "required-intersection set")), limitField("maxAmount", LIMIT_BIGINT), limitField("maxCumulativeAmount", LIMIT_BIGINT));
const LIMIT_GRANT_CONSTRAINTS = limitAuthorityConstraints(MAX_REQUIRED_INTERSECTIONS);
const LIMIT_EFFECTIVE_CONSTRAINTS = limitAuthorityConstraints(MAX_SET_MEMBERS);
const LIMIT_PERMISSION_GRANT = limitRecord(limitField("authorityId", LIMIT_IDENTIFIER), limitField("grantorId", LIMIT_IDENTIFIER), limitField("granteeId", LIMIT_IDENTIFIER), limitField("rootAuthorityId", LIMIT_IDENTIFIER), limitField("parentAuthorityId", LIMIT_IDENTIFIER), limitField("constraints", LIMIT_GRANT_CONSTRAINTS));
const LIMIT_AUTHORITY_GRANT = limitTaggedRecord("kind", [
    limitVariant("PERMISSION", limitRecord(limitField("granteeId", LIMIT_IDENTIFIER), limitField("rootAuthorityId", LIMIT_IDENTIFIER), limitField("parentAuthorityId", LIMIT_IDENTIFIER))),
    limitVariant("PROHIBITION", limitTaggedRecord("scope", [
        limitVariant("ROOT", limitRecord(limitField("rootAuthorityId", LIMIT_IDENTIFIER), limitField("parentAuthorityId", LIMIT_IDENTIFIER))),
        limitVariant("GLOBAL", limitRecord()),
    ], limitRecord(limitField("subjectActorId", LIMIT_IDENTIFIER)))),
], limitRecord(limitField("authorityId", LIMIT_IDENTIFIER), limitField("grantorId", LIMIT_IDENTIFIER), limitField("constraints", LIMIT_GRANT_CONSTRAINTS)));
const LIMIT_RECOGNIZED_ROOT = limitRecord(limitField("rootAuthorityId", LIMIT_IDENTIFIER), limitField("principalId", LIMIT_IDENTIFIER), limitField("principalRecognitionEventId", LIMIT_IDENTIFIER), limitField("rootGrantEventId", LIMIT_IDENTIFIER));
const LIMIT_AUTHORITY_USAGE = limitRecord(limitField("authorityId", LIMIT_IDENTIFIER), limitField("admittedCumulativeAmount", LIMIT_BIGINT));
const LIMIT_AUTHORITY_EVIDENCE = limitRecord(limitField("authorityId", LIMIT_IDENTIFIER), limitField("grantEventId", LIMIT_IDENTIFIER));
const LIMIT_PERMISSION_PATH = limitList(LIMIT_PERMISSION_GRANT, MAX_AUTHORITY_PATH_DEPTH, "authority path");
const LIMIT_INTERSECTION_PROOF = limitRecord(limitField("requiredAuthorityId", LIMIT_IDENTIFIER), limitField("requiredByAuthorityIds", limitIdentifierSet("required-by authority set")), limitField("recognizedRoot", LIMIT_RECOGNIZED_ROOT), limitField("path", LIMIT_PERMISSION_PATH), limitField("effectiveConstraints", LIMIT_EFFECTIVE_CONSTRAINTS));
const LIMIT_AUTHORIZATION_PROOF = limitRecord(limitField("domain", LIMIT_DOMAIN), limitField("policyVersion", LIMIT_IDENTIFIER), limitField("request", LIMIT_ACTION_REQUEST), limitField("recognizedRoot", LIMIT_RECOGNIZED_ROOT), limitField("permissionPath", LIMIT_PERMISSION_PATH), limitField("intersections", limitList(LIMIT_INTERSECTION_PROOF, MAX_SET_MEMBERS, "proof-intersection set")), limitField("effectiveConstraints", LIMIT_EFFECTIVE_CONSTRAINTS), limitField("controllingAuthorityIds", limitIdentifierSet("controlling-authority set")), limitField("usageSnapshot", limitList(LIMIT_AUTHORITY_USAGE, MAX_SET_MEMBERS, "authority-usage set")), limitField("authorityEvidence", limitList(LIMIT_AUTHORITY_EVIDENCE, MAX_AUTHORITIES, "authority-evidence set")), limitField("checkedProhibitionIds", limitIdentifierSet("checked-prohibition set")), limitField("runtimeSessionId", LIMIT_IDENTIFIER), limitField("credentialKeyId", LIMIT_IDENTIFIER), limitField("roleId", LIMIT_IDENTIFIER), limitField("roleTenureId", LIMIT_IDENTIFIER), limitField("intentId", LIMIT_IDENTIFIER), limitField("nonce", LIMIT_IDENTIFIER));
const LIMIT_TRANSACTION_INTENT = limitRecord(limitField("adapterProfile", LIMIT_ADAPTER_PROFILE), limitField("intentId", LIMIT_IDENTIFIER), limitField("nonce", LIMIT_IDENTIFIER), limitField("actorId", LIMIT_IDENTIFIER), limitField("action", LIMIT_IDENTIFIER), limitField("resource", LIMIT_IDENTIFIER), limitField("roleId", LIMIT_IDENTIFIER), limitField("roleTenureId", LIMIT_IDENTIFIER), limitField("amount", LIMIT_BIGINT), limitField("counterpartyId", LIMIT_IDENTIFIER));
const LIMIT_OBLIGATION_TRANSITION_POLICY = limitRecord(limitField("acceptedAttesterIds", limitIdentifierSet("accepted-attester set")), limitField("action", LIMIT_IDENTIFIER), limitField("requiredAuthorityIds", limitIdentifierSet("required-authority set")));
const LIMIT_OBLIGATION_RECORD = limitRecord(limitField("obligationId", LIMIT_IDENTIFIER), limitField("sourceIntentId", LIMIT_IDENTIFIER), limitField("durableRoleId", LIMIT_IDENTIFIER), limitField("creationRoleTenureId", LIMIT_IDENTIFIER), limitField("trigger", LIMIT_IDENTIFIER), limitField("beneficiaryId", LIMIT_IDENTIFIER), limitField("counterpartyId", LIMIT_IDENTIFIER), limitField("performanceAssigneeId", LIMIT_IDENTIFIER), limitField("successionRuleId", LIMIT_IDENTIFIER), limitField("transitionPolicies", limitList(LIMIT_OBLIGATION_TRANSITION_POLICY)));
const LIMIT_ADMINISTRATIVE_CHALLENGE = limitRecord(limitField("domain", LIMIT_DOMAIN), limitField("request", LIMIT_ACTION_REQUEST), limitField("policyVersion", LIMIT_IDENTIFIER), limitField("transitionEventId", LIMIT_IDENTIFIER), limitField("runtimeSessionId", LIMIT_IDENTIFIER), limitField("credentialKeyId", LIMIT_IDENTIFIER), limitField("roleId", LIMIT_IDENTIFIER), limitField("roleTenureId", LIMIT_IDENTIFIER));
const LIMIT_ADMINISTRATIVE_AUTHORIZATION = limitRecord(limitField("challenge", LIMIT_ADMINISTRATIVE_CHALLENGE), limitField("authorityProof", LIMIT_AUTHORIZATION_PROOF));
const LIMIT_OBLIGATION_CREATED_DATA = limitRecord(limitField("record", LIMIT_OBLIGATION_RECORD), limitField("actorId", LIMIT_IDENTIFIER), limitField("administrativeAuthorization", LIMIT_ADMINISTRATIVE_AUTHORIZATION));
const LIMIT_ATTEMPT_DUTY_RECORD = limitRecord(limitField("dutyId", LIMIT_IDENTIFIER), limitField("sourceIntentId", LIMIT_IDENTIFIER), limitField("sourceAdmissionEventId", LIMIT_IDENTIFIER), limitField("durableRoleId", LIMIT_IDENTIFIER), limitField("creationRoleTenureId", LIMIT_IDENTIFIER), limitField("performanceAssigneeId", LIMIT_IDENTIFIER));
const CORE_EVENT_NAMED_LIMITS = createMap();
mapSet(CORE_EVENT_NAMED_LIMITS, "DEPLOYMENT_INITIALIZED", limitRecord(limitField("domain", LIMIT_DOMAIN), limitField("canonicalLineageId", LIMIT_IDENTIFIER), limitField("versions", LIMIT_VERSION_SET), limitField("policyVersion", LIMIT_IDENTIFIER), limitField("globalPolicySourceId", LIMIT_IDENTIFIER)));
mapSet(CORE_EVENT_NAMED_LIMITS, "PRINCIPAL_CREATED", limitRecord(limitField("principalId", LIMIT_IDENTIFIER)));
mapSet(CORE_EVENT_NAMED_LIMITS, "AGENT_CREATED", limitRecord(limitField("agentId", LIMIT_IDENTIFIER), limitField("principalId", LIMIT_IDENTIFIER), limitField("controllerId", LIMIT_IDENTIFIER)));
mapSet(CORE_EVENT_NAMED_LIMITS, "ROLE_CREATED", limitRecord(limitField("roleId", LIMIT_IDENTIFIER), limitField("principalId", LIMIT_IDENTIFIER)));
mapSet(CORE_EVENT_NAMED_LIMITS, "SUCCESSION_RULE_DECLARED", limitRecord(limitField("ruleId", LIMIT_IDENTIFIER), limitField("principalId", LIMIT_IDENTIFIER), limitField("predecessorAgentId", LIMIT_IDENTIFIER), limitField("successorAgentId", LIMIT_IDENTIFIER), limitField("roleId", LIMIT_IDENTIFIER)));
mapSet(CORE_EVENT_NAMED_LIMITS, "AGENT_APPOINTED", limitRecord(limitField("agentId", LIMIT_IDENTIFIER), limitField("roleId", LIMIT_IDENTIFIER), limitField("roleTenureId", LIMIT_IDENTIFIER), limitField("principalId", LIMIT_IDENTIFIER), limitField("successionRuleId", LIMIT_IDENTIFIER)));
mapSet(CORE_EVENT_NAMED_LIMITS, "AGENT_UNAPPOINTED", limitRecord(limitField("agentId", LIMIT_IDENTIFIER), limitField("roleId", LIMIT_IDENTIFIER), limitField("roleTenureId", LIMIT_IDENTIFIER), limitField("principalId", LIMIT_IDENTIFIER)));
mapSet(CORE_EVENT_NAMED_LIMITS, "ROLE_TRANSFERRED", limitRecord(limitField("roleId", LIMIT_IDENTIFIER), limitField("fromAgentId", LIMIT_IDENTIFIER), limitField("fromRoleTenureId", LIMIT_IDENTIFIER), limitField("toAgentId", LIMIT_IDENTIFIER), limitField("toRoleTenureId", LIMIT_IDENTIFIER), limitField("principalId", LIMIT_IDENTIFIER), limitField("successionRuleId", LIMIT_IDENTIFIER)));
mapSet(CORE_EVENT_NAMED_LIMITS, "RUNTIME_SESSION_ADMITTED", limitRecord(limitField("sessionId", LIMIT_IDENTIFIER), limitField("agentId", LIMIT_IDENTIFIER), limitField("controllerId", LIMIT_IDENTIFIER), limitField("credentialKeyId", LIMIT_IDENTIFIER)));
mapSet(CORE_EVENT_NAMED_LIMITS, "CONTROL_EPOCH_ADVANCED", limitRecord(limitField("agentId", LIMIT_IDENTIFIER), limitField("controllerId", LIMIT_IDENTIFIER)));
mapSet(CORE_EVENT_NAMED_LIMITS, "AUTHORITY_GRANTED", limitRecord(limitField("grant", LIMIT_AUTHORITY_GRANT)));
mapSet(CORE_EVENT_NAMED_LIMITS, "AUTHORITY_REVOKED", limitRecord(limitField("authorityId", LIMIT_IDENTIFIER), limitField("revokerId", LIMIT_IDENTIFIER)));
mapSet(CORE_EVENT_NAMED_LIMITS, "TRANSACTION_INTENT_DECLARED", LIMIT_TRANSACTION_INTENT);
mapSet(CORE_EVENT_NAMED_LIMITS, "TRANSACTION_INTENT_ADMITTED", limitRecord(limitField("intentId", LIMIT_IDENTIFIER), limitField("authorizationProof", LIMIT_AUTHORIZATION_PROOF)));
mapSet(CORE_EVENT_NAMED_LIMITS, "TRANSACTION_INTENT_CONSUMED", limitRecord(limitField("intentId", LIMIT_IDENTIFIER), limitField("adapterId", LIMIT_IDENTIFIER), limitField("transactionReference", LIMIT_IDENTIFIER), limitField("acknowledgment", LIMIT_ADAPTER_EVIDENCE), limitField("evidenceReference", LIMIT_EVIDENCE_REFERENCE)));
mapSet(CORE_EVENT_NAMED_LIMITS, "TRANSACTION_OUTCOME_RECORDED", limitRecord(limitField("intentId", LIMIT_IDENTIFIER), limitField("noEffect", LIMIT_ADAPTER_EVIDENCE), limitField("attesterId", LIMIT_IDENTIFIER), limitField("evidenceReference", LIMIT_EVIDENCE_REFERENCE)));
mapSet(CORE_EVENT_NAMED_LIMITS, "RECEIPT_RECORDED", limitRecord(limitField("intentId", LIMIT_IDENTIFIER), limitField("issuerAgentId", LIMIT_IDENTIFIER), limitField("runtimeSessionId", LIMIT_IDENTIFIER), limitField("roleId", LIMIT_IDENTIFIER), limitField("roleTenureId", LIMIT_IDENTIFIER)));
mapSet(CORE_EVENT_NAMED_LIMITS, "OBLIGATION_CREATED", LIMIT_OBLIGATION_CREATED_DATA);
mapSet(CORE_EVENT_NAMED_LIMITS, "ATTEMPT_DUTY_POLICY_ACTIVATED", limitRecord(limitField("actorId", LIMIT_IDENTIFIER), limitField("activationAuthorityId", LIMIT_IDENTIFIER), limitField("descriptor", limitRecord(limitField("domain", LIMIT_DOMAIN), limitField("dutyId", LIMIT_IDENTIFIER), limitField("dutyCreationEventId", LIMIT_IDENTIFIER), limitField("sourceIntentId", LIMIT_IDENTIFIER), limitField("sourceAdmissionEventId", LIMIT_IDENTIFIER), limitField("durableRoleId", LIMIT_IDENTIFIER), limitField("principalId", LIMIT_IDENTIFIER), limitField("acceptedAttesterRoleId", LIMIT_IDENTIFIER))), limitField("administrativeAuthorization", LIMIT_ADMINISTRATIVE_AUTHORIZATION)));
mapSet(CORE_EVENT_NAMED_LIMITS, "ATTEMPT_DUTY_REVIEW_CLOSED", limitRecord(limitField("dutyId", LIMIT_IDENTIFIER), limitField("actorId", LIMIT_IDENTIFIER), limitField("observationEventIds", limitList(LIMIT_IDENTIFIER, 128, "attempt-review-observations")), limitField("administrativeAuthorization", LIMIT_ADMINISTRATIVE_AUTHORIZATION)));
mapSet(CORE_EVENT_NAMED_LIMITS, "OUTCOME_OBSERVATION_RECORDED", limitRecord(limitField("intentId", LIMIT_IDENTIFIER), limitField("sourceAdmissionEventId", LIMIT_IDENTIFIER), limitField("acknowledgment", LIMIT_ADAPTER_EVIDENCE), limitField("actorId", LIMIT_IDENTIFIER), limitField("administrativeAuthorization", LIMIT_ADMINISTRATIVE_AUTHORIZATION)));
mapSet(CORE_EVENT_NAMED_LIMITS, "ATTEMPT_DUTY_CREATED", limitRecord(limitField("record", LIMIT_ATTEMPT_DUTY_RECORD), limitField("actorId", LIMIT_IDENTIFIER), limitField("administrativeAuthorization", LIMIT_ADMINISTRATIVE_AUTHORIZATION)));
mapSet(CORE_EVENT_NAMED_LIMITS, "ATTEMPT_DUTY_ASSIGNED", limitRecord(limitField("dutyId", LIMIT_IDENTIFIER), limitField("fromAgentId", LIMIT_IDENTIFIER), limitField("toAgentId", LIMIT_IDENTIFIER), limitField("actorId", LIMIT_IDENTIFIER), limitField("administrativeAuthorization", LIMIT_ADMINISTRATIVE_AUTHORIZATION)));
mapSet(CORE_EVENT_NAMED_LIMITS, "OBLIGATION_PERFORMANCE_ASSIGNED", limitRecord(limitField("obligationId", LIMIT_IDENTIFIER), limitField("fromAgentId", LIMIT_IDENTIFIER), limitField("toAgentId", LIMIT_IDENTIFIER), limitField("successionRuleId", LIMIT_IDENTIFIER), limitField("actorId", LIMIT_IDENTIFIER), limitField("administrativeAuthorization", LIMIT_ADMINISTRATIVE_AUTHORIZATION)));
mapSet(CORE_EVENT_NAMED_LIMITS, "OBLIGATION_STATUS_RECORDED", limitRecord(limitField("obligationId", LIMIT_IDENTIFIER), limitField("actorId", LIMIT_IDENTIFIER), limitField("action", LIMIT_IDENTIFIER), limitField("administrativeAuthorization", LIMIT_ADMINISTRATIVE_AUTHORIZATION), limitField("attesterId", LIMIT_IDENTIFIER), limitField("evidenceReference", LIMIT_EVIDENCE_REFERENCE)));
mapSet(CORE_EVENT_NAMED_LIMITS, "AGENT_TERMINATED", limitRecord(limitField("agentId", LIMIT_IDENTIFIER), limitField("principalId", LIMIT_IDENTIFIER), limitField("successionRuleId", LIMIT_IDENTIFIER), limitField("roleId", LIMIT_IDENTIFIER), limitField("roleTenureId", LIMIT_IDENTIFIER)));
const preflightNamedLimitNode = (v, value, path, node) => {
    switch (node.kind) {
        case "IDENTIFIER":
            return typeof value !== "string" ||
                boundedWellFormedUtf8Status(value, MAX_IDENTIFIER_BYTES) !== "LIMIT" ||
                v.failLimit(path, "must be an Identifier");
        case "BIGINT":
            return typeof value !== "bigint" ||
                (value >= -MAX_BIGINT && value <= MAX_BIGINT) ||
                v.failLimit(path, "exceeds the 256-bit BigInt magnitude bound");
        case "RECORD": {
            if (!isPlainRecord(value))
                return true;
            for (let index = 0; index < node.fields.length; index += 1) {
                const field = node.fields[index];
                const name = field[0];
                if (Object.hasOwn(value, name) &&
                    value[name] !== undefined &&
                    !preflightNamedLimitNode(v, value[name], `${path}.${name}`, field[1]))
                    return false;
            }
            return true;
        }
        case "LIST": {
            if (!Array.isArray(value))
                return true;
            if (node.maximum !== undefined && value.length > node.maximum) {
                return v.failLimit(path, `exceeds the ${node.maximum}-member ${node.boundName ?? "named list"} bound`);
            }
            if (node.member === undefined)
                return true;
            for (let index = 0; index < value.length; index += 1) {
                if (!preflightNamedLimitNode(v, value[index], `${path}[${index}]`, node.member)) {
                    return false;
                }
            }
            return true;
        }
        case "TAGGED_RECORD": {
            if (!isPlainRecord(value))
                return true;
            if (node.common !== undefined &&
                !preflightNamedLimitNode(v, value, path, node.common))
                return false;
            if (!Object.hasOwn(value, node.tagField))
                return true;
            const tag = value[node.tagField];
            if (typeof tag !== "string")
                return true;
            for (let index = 0; index < node.variants.length; index += 1) {
                const variant = node.variants[index];
                if (variant[0] === tag) {
                    return preflightNamedLimitNode(v, value, path, variant[1]);
                }
            }
            return true;
        }
    }
};
/**
 * Scan only named hard-limit slots in one already captured immutable payload.
 * Semantic shape, spelling, uniqueness, and value checks remain in the ordinary
 * closed-schema pass below; this pass exists solely to enforce Section 5.5's
 * envelope/limit precedence without observing caller-owned data a second time.
 */
const preflightEventNamedLimits = (v, type, value, path = "$.data") => {
    const schema = mapGet(CORE_EVENT_NAMED_LIMITS, type);
    return schema !== undefined && preflightNamedLimitNode(v, value, path, schema);
};
const LIMIT_RECEIPT_PAYLOAD = limitRecord(limitField("domain", LIMIT_DOMAIN), limitField("issuer", limitRecord(limitField("keyId", LIMIT_IDENTIFIER), limitField("agentId", LIMIT_IDENTIFIER), limitField("runtimeSessionId", LIMIT_IDENTIFIER), limitField("roleId", LIMIT_IDENTIFIER), limitField("roleTenureId", LIMIT_IDENTIFIER))), limitField("intent", LIMIT_TRANSACTION_INTENT), limitField("authorization", limitRecord(limitField("policyVersion", LIMIT_IDENTIFIER), limitField("proof", LIMIT_AUTHORIZATION_PROOF))), limitField("result", limitRecord(limitField("consumptionEventId", LIMIT_IDENTIFIER), limitField("adapterId", LIMIT_IDENTIFIER), limitField("transactionReference", LIMIT_IDENTIFIER), limitField("acknowledgment", LIMIT_ADAPTER_EVIDENCE))));
const receiptPayload = (v, value, path) => {
    const payload = v.record(value, path, [
        "schemaVersion", "signatureScheme", "domain", "issuer", "intent",
        "authorization", "issuance", "result", "assurance",
    ]);
    if (payload === undefined)
        return false;
    const issuer = v.record(payload.issuer, `${path}.issuer`, [
        "keyId", "agentId", "runtimeSessionId", "controlEpoch", "roleId", "roleTenureId",
    ]);
    const authorization = v.record(payload.authorization, `${path}.authorization`, [
        "authorizationTime", "policyVersion", "rootRecognitionPolicy", "historyHead", "proof",
    ]);
    const issuance = v.record(payload.issuance, `${path}.issuance`, ["historyHead", "issuedAt"]);
    const result = v.record(payload.result, `${path}.result`, [
        "status", "consumptionEventId", "adapterId", "idempotencyKey", "submissionFingerprint", "transactionReference", "acknowledgment",
    ]);
    const assurance = v.record(payload.assurance, `${path}.assurance`, [
        "finality", "freshness", "externalOutcome",
    ]);
    return issuer !== undefined && authorization !== undefined &&
        issuance !== undefined && result !== undefined && assurance !== undefined &&
        authorizationDomain(v, payload.domain, `${path}.domain`) &&
        identifier(v, issuer.keyId, `${path}.issuer.keyId`) &&
        identifier(v, issuer.agentId, `${path}.issuer.agentId`) &&
        identifier(v, issuer.runtimeSessionId, `${path}.issuer.runtimeSessionId`) &&
        u53(v, issuer.controlEpoch, `${path}.issuer.controlEpoch`) &&
        identifier(v, issuer.roleId, `${path}.issuer.roleId`) &&
        identifier(v, issuer.roleTenureId, `${path}.issuer.roleTenureId`) &&
        transactionIntent(v, payload.intent, `${path}.intent`) &&
        u53(v, authorization.authorizationTime, `${path}.authorization.authorizationTime`) &&
        identifier(v, authorization.policyVersion, `${path}.authorization.policyVersion`) &&
        literal(v, authorization.rootRecognitionPolicy, `${path}.authorization.rootRecognitionPolicy`, ["declared-principal-root/0.2"]) &&
        historyHead(v, authorization.historyHead, `${path}.authorization.historyHead`) &&
        authorizationProof(v, authorization.proof, `${path}.authorization.proof`) &&
        historyHead(v, issuance.historyHead, `${path}.issuance.historyHead`) &&
        u53(v, issuance.issuedAt, `${path}.issuance.issuedAt`) &&
        literal(v, result.status, `${path}.result.status`, ["SUBMITTED"]) &&
        identifier(v, result.consumptionEventId, `${path}.result.consumptionEventId`) &&
        identifier(v, result.adapterId, `${path}.result.adapterId`) &&
        contentHash(v, result.idempotencyKey, `${path}.result.idempotencyKey`) &&
        contentHash(v, result.submissionFingerprint, `${path}.result.submissionFingerprint`) &&
        identifier(v, result.transactionReference, `${path}.result.transactionReference`) &&
        adapterEvidence(v, result.acknowledgment, `${path}.result.acknowledgment`) &&
        literal(v, assurance.finality, `${path}.assurance.finality`, ["LOCAL_ONLY"]) &&
        literal(v, assurance.freshness, `${path}.assurance.freshness`, ["CURRENT_AT_ISSUANCE"]) &&
        literal(v, assurance.externalOutcome, `${path}.assurance.externalOutcome`, ["NOT_PROVEN", "SIMULATED"]);
};
/**
 * @internal Validate an already captured receipt value using its original field
 * presence. The capture owns generic limits; this layer adds named limits and
 * exact schema without wrapping the receipt in an event's 1 MiB data budget.
 */
export const validateCapturedPortableReceiptValue = (capture, kind, value) => {
    const validator = new ShapeValidator(capture.capturedRecordKeys);
    const result = (valid) => valid ? "VALID" : validator.failureKind === "LIMIT" ? "LIMIT" : "INVALID";
    switch (kind) {
        case "DOMAIN":
            return result(preflightNamedLimitNode(validator, value, "$", LIMIT_DOMAIN) &&
                authorizationDomain(validator, value, "$"));
        case "HISTORY_HEAD": return result(historyHead(validator, value, "$"));
        case "IDENTIFIER": return result(identifier(validator, value, "$"));
        case "TIME": return result(u53(validator, value, "$"));
        case "ARTIFACT": {
            // Input-limit failures precede malformed artifacts. Only an exact supported
            // payload dispatch permits this schema-specific scan of captured values.
            // The named-limit walker ignores semantic defects and visits later slots.
            if (isPlainRecord(value) && capture.capturedRecordKeys(value) !== undefined &&
                Object.hasOwn(value, "payload")) {
                const candidate = value.payload;
                if (isPlainRecord(candidate) && capture.capturedRecordKeys(candidate) !== undefined &&
                    Object.hasOwn(candidate, "schemaVersion") && Object.hasOwn(candidate, "signatureScheme") &&
                    candidate.schemaVersion === "continuity-receipt/0.2" &&
                    candidate.signatureScheme === "eip191-personal-sign-keccak256" &&
                    !preflightNamedLimitNode(validator, candidate, "$.payload", LIMIT_RECEIPT_PAYLOAD)) {
                    return "LIMIT";
                }
            }
            const artifact = validator.record(value, "$", ["payload", "contentHash", "signature"]);
            if (artifact === undefined)
                return result(false);
            if (!contentHash(validator, artifact.contentHash, "$.contentHash") ||
                !signature65(validator, artifact.signature, "$.signature"))
                return result(false);
            const payload = artifact.payload;
            if (!isPlainRecord(payload) || capture.capturedRecordKeys(payload) === undefined ||
                !Object.hasOwn(payload, "schemaVersion") || !Object.hasOwn(payload, "signatureScheme")) {
                return "INVALID";
            }
            if (!identifier(validator, payload.schemaVersion, "$.payload.schemaVersion") ||
                !identifier(validator, payload.signatureScheme, "$.payload.signatureScheme"))
                return result(false);
            // A future schema retains common-envelope-first dispatch without being
            // required to have the current payload's closed shape or named slots.
            if (payload.schemaVersion !== "continuity-receipt/0.2" ||
                payload.signatureScheme !== "eip191-personal-sign-keccak256")
                return "UNSUPPORTED";
            return result(receiptPayload(validator, payload, "$.payload"));
        }
    }
};
/** Query input shape, before replay; request scalars retain phase-two classification. */
export const validateCapturedPortableQueryInput = (capture, kind, value) => {
    const v = new ShapeValidator(capture.capturedRecordKeys);
    const scalar = (x) => typeof x === "string" || typeof x === "number" || typeof x === "bigint";
    // Base Identifier and fixed bootstrap bounds are known before interpreter
    // discovery. A malformed base scalar cannot mask one of these input limits.
    for (const name of ["evaluationEvents", "observedEvents"]) {
        const history = value[name];
        if (!Array.isArray(history))
            continue;
        for (let position = 0; position < history.length; position += 1) {
            const event = history[position];
            if (!isPlainRecord(event))
                continue;
            if (!preflightNamedLimitNode(v, event.id, `$.${name}[${position}].id`, LIMIT_IDENTIFIER))
                return false;
            if (position === 0 && event.type === "DEPLOYMENT_INITIALIZED" &&
                !preflightEventNamedLimits(v, "DEPLOYMENT_INITIALIZED", event.data, `$.${name}[0].data`))
                return false;
        }
    }
    // Named Identifier bounds precede replay/time, while disclosure semantics
    // (shape, ordering, duplicates and field selection) remain a later phase.
    if (isPlainRecord(value.disclosure)) {
        for (const name of ["includedFields", "withheldFields"]) {
            const list = value.disclosure[name];
            if (Array.isArray(list))
                for (let i = 0; i < list.length; i += 1) {
                    if (!preflightNamedLimitNode(v, list[i], `$.disclosure.${name}[${i}]`, LIMIT_IDENTIFIER))
                        return false;
                }
        }
    }
    if (!scalar(value.evaluationTime))
        return false;
    if (kind === "SURVIVES")
        return identifier(v, value.targetAgentId, "$.targetAgentId");
    if (!preflightNamedLimitNode(v, value.authorizationDomain, "$.authorizationDomain", LIMIT_DOMAIN) ||
        !authorizationDomain(v, value.authorizationDomain, "$.authorizationDomain"))
        return false;
    const request = v.record(value.request, "$.request", ["actorId", "action", "resource", "claimedAt"], ["amount", "counterpartyId", "termsCommitment"]);
    if (request === undefined)
        return false;
    const scalarKeys = ["actorId", "action", "resource", "claimedAt", "amount", "counterpartyId"];
    for (let i = 0; i < scalarKeys.length; i += 1) {
        if (request[scalarKeys[i]] !== undefined && !scalar(request[scalarKeys[i]]))
            return false;
    }
    // Identifier length is an input bound; designated Amount magnitude is the
    // later INVALID_AMOUNT classification required by3.2.
    const ids = ["actorId", "action", "resource", "counterpartyId"];
    for (let i = 0; i < ids.length; i += 1) {
        if (!preflightNamedLimitNode(v, request[ids[i]], `$.request.${ids[i]}`, LIMIT_IDENTIFIER))
            return false;
    }
    if (value.consequentialBinding === undefined)
        return true;
    const b = v.record(value.consequentialBinding, "$.consequentialBinding", ["runtimeSessionId", "controlEpoch", "roleId", "roleTenureId"], ["credentialKeyId", "intentId", "nonce", "runtimeSignature"]);
    return b !== undefined && identifier(v, b.runtimeSessionId, "$.binding.runtimeSessionId") &&
        u53(v, b.controlEpoch, "$.binding.controlEpoch") && identifier(v, b.roleId, "$.binding.roleId") &&
        identifier(v, b.roleTenureId, "$.binding.roleTenureId") &&
        (b.credentialKeyId === undefined || identifier(v, b.credentialKeyId, "$.binding.credentialKeyId")) &&
        (b.intentId === undefined || identifier(v, b.intentId, "$.binding.intentId")) &&
        (b.nonce === undefined || identifier(v, b.nonce, "$.binding.nonce")) &&
        (b.runtimeSignature === undefined || signature65(v, b.runtimeSignature, "$.binding.runtimeSignature"));
};
/** Closed disclosure schema is evaluated at the later disclosure phase. */
export const validateCapturedPortableQueryDisclosure = (capture, value) => {
    const v = new ShapeValidator(capture.capturedRecordKeys);
    const record = v.record(value, "$.disclosure", ["mode", "includedFields", "withheldFields"]);
    if (record === undefined || record.mode !== "PUBLIC_MINIMAL")
        return false;
    const validList = (candidate) => {
        if (!Array.isArray(candidate) || candidate.length > MAX_LIST_MEMBERS)
            return false;
        for (let i = 0; i < candidate.length; i += 1) {
            if (!identifier(v, candidate[i], "$.disclosure.fields") ||
                (i > 0 && compareProtocolStrings(candidate[i - 1], candidate[i]) >= 0))
                return false;
        }
        return true;
    };
    if (!validList(record.includedFields) || !validList(record.withheldFields))
        return false;
    for (let i = 0; i < record.withheldFields.length; i += 1) {
        if (arrayIncludes(record.includedFields, record.withheldFields[i]))
            return false;
    }
    return true;
};
const validateEventData = (v, type, value) => {
    const path = "$.data";
    switch (type) {
        case "DEPLOYMENT_INITIALIZED": {
            const record = v.record(value, path, [
                "domain",
                "adapterPolicyHash",
                "canonicalLineageId",
                "versions",
                "policyVersion",
                "rootRecognitionPolicy",
                "globalPolicySourceId",
                "timeSource",
                "finality",
            ]);
            return record !== undefined &&
                authorizationDomain(v, record.domain, `${path}.domain`) &&
                resolvePortableAdapterPolicy(record.adapterPolicyHash) !== undefined &&
                identifier(v, record.canonicalLineageId, `${path}.canonicalLineageId`) &&
                versionSet(v, record.versions, `${path}.versions`) &&
                identifier(v, record.policyVersion, `${path}.policyVersion`) &&
                record.rootRecognitionPolicy === "declared-principal-root/0.2" &&
                record.timeSource === "EVENT_TIMESTAMP" &&
                record.finality === "LOCAL_ONLY" &&
                identifier(v, record.globalPolicySourceId, `${path}.globalPolicySourceId`);
        }
        case "PRINCIPAL_CREATED": {
            const record = v.record(value, path, ["principalId"]);
            return record !== undefined && identifier(v, record.principalId, `${path}.principalId`);
        }
        case "AGENT_CREATED": {
            const record = v.record(value, path, [
                "agentId",
                "principalId",
                "controllerId",
                "initialControlEpoch",
            ]);
            return record !== undefined &&
                identifier(v, record.agentId, `${path}.agentId`) &&
                identifier(v, record.principalId, `${path}.principalId`) &&
                identifier(v, record.controllerId, `${path}.controllerId`) &&
                u53(v, record.initialControlEpoch, `${path}.initialControlEpoch`);
        }
        case "ROLE_CREATED": {
            const record = v.record(value, path, ["roleId", "principalId", "exclusive"]);
            return record !== undefined &&
                identifier(v, record.roleId, `${path}.roleId`) &&
                identifier(v, record.principalId, `${path}.principalId`) &&
                (record.exclusive === true || v.fail(`${path}.exclusive`, "must be true"));
        }
        case "SUCCESSION_RULE_DECLARED": {
            const record = v.record(value, path, [
                "ruleId",
                "principalId",
                "predecessorAgentId",
                "successorAgentId",
                "roleId",
                "trigger",
                "permittedEventTypes",
            ]);
            return record !== undefined &&
                identifier(v, record.ruleId, `${path}.ruleId`) &&
                identifier(v, record.principalId, `${path}.principalId`) &&
                identifier(v, record.predecessorAgentId, `${path}.predecessorAgentId`) &&
                identifier(v, record.successorAgentId, `${path}.successorAgentId`) &&
                identifier(v, record.roleId, `${path}.roleId`) &&
                record.trigger === "AGENT_TERMINATED" &&
                enumList(v, record.permittedEventTypes, `${path}.permittedEventTypes`, ["AGENT_TERMINATED", "ROLE_TRANSFERRED", "OBLIGATION_PERFORMANCE_ASSIGNED"], true);
        }
        case "AGENT_APPOINTED": {
            const record = v.record(value, path, ["agentId", "roleId", "roleTenureId", "tenureNumber", "principalId"], ["successionRuleId"]);
            return record !== undefined &&
                identifier(v, record.agentId, `${path}.agentId`) &&
                identifier(v, record.roleId, `${path}.roleId`) &&
                identifier(v, record.roleTenureId, `${path}.roleTenureId`) &&
                u53(v, record.tenureNumber, `${path}.tenureNumber`) &&
                identifier(v, record.principalId, `${path}.principalId`) &&
                (record.successionRuleId === undefined ||
                    identifier(v, record.successionRuleId, `${path}.successionRuleId`));
        }
        case "AGENT_UNAPPOINTED": {
            const record = v.record(value, path, ["agentId", "roleId", "roleTenureId", "principalId"]);
            return record !== undefined &&
                identifier(v, record.agentId, `${path}.agentId`) &&
                identifier(v, record.roleId, `${path}.roleId`) &&
                identifier(v, record.roleTenureId, `${path}.roleTenureId`) &&
                identifier(v, record.principalId, `${path}.principalId`);
        }
        case "ROLE_TRANSFERRED": {
            const record = v.record(value, path, [
                "roleId",
                "fromAgentId",
                "fromRoleTenureId",
                "toAgentId",
                "toRoleTenureId",
                "toTenureNumber",
                "principalId",
                "transferKind",
            ], ["successionRuleId"]);
            return record !== undefined &&
                identifier(v, record.roleId, `${path}.roleId`) &&
                identifier(v, record.fromAgentId, `${path}.fromAgentId`) &&
                identifier(v, record.fromRoleTenureId, `${path}.fromRoleTenureId`) &&
                identifier(v, record.toAgentId, `${path}.toAgentId`) &&
                identifier(v, record.toRoleTenureId, `${path}.toRoleTenureId`) &&
                u53(v, record.toTenureNumber, `${path}.toTenureNumber`) &&
                identifier(v, record.principalId, `${path}.principalId`) &&
                literal(v, record.transferKind, `${path}.transferKind`, ["SUCCESSION", "REASSIGNMENT"]) &&
                (record.successionRuleId === undefined ||
                    identifier(v, record.successionRuleId, `${path}.successionRuleId`));
        }
        case "RUNTIME_SESSION_ADMITTED": {
            const record = v.record(value, path, [
                "sessionId",
                "agentId",
                "controllerId",
                "controlEpoch",
                "credentialKeyId",
                "credentialAddress",
            ], ["expiresAt"]);
            return record !== undefined &&
                identifier(v, record.sessionId, `${path}.sessionId`) &&
                identifier(v, record.agentId, `${path}.agentId`) &&
                identifier(v, record.controllerId, `${path}.controllerId`) &&
                u53(v, record.controlEpoch, `${path}.controlEpoch`) &&
                identifier(v, record.credentialKeyId, `${path}.credentialKeyId`) &&
                ethereumAddress(v, record.credentialAddress, `${path}.credentialAddress`) &&
                (record.expiresAt === undefined || u53(v, record.expiresAt, `${path}.expiresAt`));
        }
        case "CONTROL_EPOCH_ADVANCED": {
            const record = v.record(value, path, ["agentId", "controllerId", "fromEpoch", "toEpoch"]);
            return record !== undefined &&
                identifier(v, record.agentId, `${path}.agentId`) &&
                identifier(v, record.controllerId, `${path}.controllerId`) &&
                u53(v, record.fromEpoch, `${path}.fromEpoch`) &&
                u53(v, record.toEpoch, `${path}.toEpoch`);
        }
        case "AUTHORITY_GRANTED": {
            const record = v.record(value, path, ["grant"]);
            return record !== undefined && authorityGrant(v, record.grant, `${path}.grant`);
        }
        case "AUTHORITY_REVOKED": {
            const record = v.record(value, path, ["authorityId", "revokerId"]);
            return record !== undefined &&
                identifier(v, record.authorityId, `${path}.authorityId`) &&
                identifier(v, record.revokerId, `${path}.revokerId`);
        }
        case "TRANSACTION_INTENT_DECLARED":
            return transactionIntent(v, value, path);
        case "TRANSACTION_INTENT_ADMITTED": {
            const record = v.record(value, path, [
                "intentId",
                "evaluationTime",
                "expectedHistoryHead",
                "authorizationProof",
                "runtimeAuthorizationHash",
                "runtimeSignature",
            ]);
            return record !== undefined &&
                identifier(v, record.intentId, `${path}.intentId`) &&
                u53(v, record.evaluationTime, `${path}.evaluationTime`) &&
                historyHead(v, record.expectedHistoryHead, `${path}.expectedHistoryHead`) &&
                authorizationProof(v, record.authorizationProof, `${path}.authorizationProof`) &&
                contentHash(v, record.runtimeAuthorizationHash, `${path}.runtimeAuthorizationHash`) &&
                signature65(v, record.runtimeSignature, `${path}.runtimeSignature`);
        }
        case "TRANSACTION_INTENT_CONSUMED": {
            const record = v.record(value, path, [
                "intentId",
                "adapterId",
                "idempotencyKey",
                "submissionFingerprint",
                "status",
                "evidenceReference",
                "acknowledgment",
                "transactionReference",
            ]);
            return record !== undefined &&
                identifier(v, record.intentId, `${path}.intentId`) &&
                identifier(v, record.adapterId, `${path}.adapterId`) &&
                contentHash(v, record.idempotencyKey, `${path}.idempotencyKey`) &&
                contentHash(v, record.submissionFingerprint, `${path}.submissionFingerprint`) &&
                record.status === "SUBMITTED" &&
                identifier(v, record.transactionReference, `${path}.transactionReference`) &&
                adapterEvidence(v, record.acknowledgment, `${path}.acknowledgment`) &&
                evidenceReference(v, record.evidenceReference, `${path}.evidenceReference`);
        }
        case "TRANSACTION_OUTCOME_RECORDED": {
            const record = v.record(value, path, [
                "intentId",
                "status",
                "attesterId",
                "evidenceReference",
            ], ["noEffect"]);
            if (record !== undefined && record.status !== "FAILED" &&
                v.record(value, path, ["intentId", "status", "attesterId", "evidenceReference"]) === undefined)
                return false;
            return record !== undefined &&
                identifier(v, record.intentId, `${path}.intentId`) &&
                literal(v, record.status, `${path}.status`, [
                    "CONFIRMED",
                    "FAILED",
                    "DISPUTED",
                    "OUTCOME_UNKNOWN",
                ]) &&
                (record.status === "FAILED"
                    ? adapterEvidence(v, record.noEffect, `${path}.noEffect`, true)
                    : !Object.hasOwn(record, "noEffect")) &&
                identifier(v, record.attesterId, `${path}.attesterId`) &&
                evidenceReference(v, record.evidenceReference, `${path}.evidenceReference`);
        }
        case "RECEIPT_RECORDED": {
            const record = v.record(value, path, [
                "receiptContentHash",
                "receiptArtifactCommitment",
                "intentId",
                "issuerAgentId",
                "runtimeSessionId",
                "controlEpoch",
                "roleId",
                "roleTenureId",
                "authorizationProofHash",
            ]);
            return record !== undefined &&
                contentHash(v, record.receiptContentHash, `${path}.receiptContentHash`) &&
                contentHash(v, record.receiptArtifactCommitment, `${path}.receiptArtifactCommitment`) &&
                identifier(v, record.intentId, `${path}.intentId`) &&
                identifier(v, record.issuerAgentId, `${path}.issuerAgentId`) &&
                identifier(v, record.runtimeSessionId, `${path}.runtimeSessionId`) &&
                u53(v, record.controlEpoch, `${path}.controlEpoch`) &&
                identifier(v, record.roleId, `${path}.roleId`) &&
                identifier(v, record.roleTenureId, `${path}.roleTenureId`) &&
                contentHash(v, record.authorizationProofHash, `${path}.authorizationProofHash`);
        }
        case "OBLIGATION_CREATED":
            return obligationCreatedData(v, value, path);
        case "OUTCOME_OBSERVATION_RECORDED": {
            const record = v.record(value, path, [
                "intentId", "sourceAdmissionEventId", "acknowledgment", "actorId", "administrativeAuthorization",
            ]);
            return record !== undefined &&
                identifier(v, record.intentId, `${path}.intentId`) &&
                identifier(v, record.sourceAdmissionEventId, `${path}.sourceAdmissionEventId`) &&
                isPlainRecord(record.acknowledgment) &&
                record.acknowledgment.schemaVersion === REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION &&
                adapterEvidence(v, record.acknowledgment, `${path}.acknowledgment`) &&
                identifier(v, record.actorId, `${path}.actorId`) &&
                administrativeAuthorization(v, record.administrativeAuthorization, `${path}.administrativeAuthorization`);
        }
        case "ATTEMPT_DUTY_POLICY_ACTIVATED": {
            const record = v.record(value, path, ["actorId", "descriptor", "descriptorHash", "activationAuthorityId", "administrativeAuthorization"]);
            return record !== undefined && identifier(v, record.actorId, `${path}.actorId`) &&
                dutyPolicyDescriptor(v, record.descriptor, `${path}.descriptor`) && contentHash(v, record.descriptorHash, `${path}.descriptorHash`) &&
                identifier(v, record.activationAuthorityId, `${path}.activationAuthorityId`) &&
                administrativeAuthorization(v, record.administrativeAuthorization, `${path}.administrativeAuthorization`);
        }
        case "ATTEMPT_DUTY_CREATED": {
            const record = v.record(value, path, ["record", "actorId", "administrativeAuthorization"]);
            return record !== undefined &&
                attemptDutyRecord(v, record.record, `${path}.record`) &&
                identifier(v, record.actorId, `${path}.actorId`) &&
                administrativeAuthorization(v, record.administrativeAuthorization, `${path}.administrativeAuthorization`);
        }
        case "ATTEMPT_DUTY_REVIEW_CLOSED": {
            const record = v.record(value, path, ["dutyId", "actorId", "observationEventIds", "summaryDigest", "administrativeAuthorization"]);
            return record !== undefined && identifier(v, record.dutyId, `${path}.dutyId`) &&
                identifier(v, record.actorId, `${path}.actorId`) &&
                reviewObservationIds(v, record.observationEventIds, `${path}.observationEventIds`) &&
                contentHash(v, record.summaryDigest, `${path}.summaryDigest`) &&
                administrativeAuthorization(v, record.administrativeAuthorization, `${path}.administrativeAuthorization`);
        }
        case "ATTEMPT_DUTY_ASSIGNED": {
            const record = v.record(value, path, ["dutyId", "fromAgentId", "toAgentId", "actorId", "administrativeAuthorization"]);
            return record !== undefined &&
                identifier(v, record.dutyId, `${path}.dutyId`) &&
                identifier(v, record.fromAgentId, `${path}.fromAgentId`) &&
                identifier(v, record.toAgentId, `${path}.toAgentId`) &&
                identifier(v, record.actorId, `${path}.actorId`) &&
                administrativeAuthorization(v, record.administrativeAuthorization, `${path}.administrativeAuthorization`);
        }
        case "OBLIGATION_PERFORMANCE_ASSIGNED": {
            const record = v.record(value, path, [
                "obligationId",
                "fromAgentId",
                "toAgentId",
                "successionRuleId",
                "actorId",
                "administrativeAuthorization",
            ]);
            return record !== undefined &&
                identifier(v, record.obligationId, `${path}.obligationId`) &&
                identifier(v, record.fromAgentId, `${path}.fromAgentId`) &&
                identifier(v, record.toAgentId, `${path}.toAgentId`) &&
                identifier(v, record.successionRuleId, `${path}.successionRuleId`) &&
                identifier(v, record.actorId, `${path}.actorId`) &&
                administrativeAuthorization(v, record.administrativeAuthorization, `${path}.administrativeAuthorization`);
        }
        case "OBLIGATION_STATUS_RECORDED": {
            const record = v.record(value, path, [
                "obligationId",
                "fromStatus",
                "toStatus",
                "actorId",
                "action",
                "administrativeAuthorization",
                "attesterId",
                "evidenceReference",
            ]);
            return record !== undefined &&
                identifier(v, record.obligationId, `${path}.obligationId`) &&
                literal(v, record.fromStatus, `${path}.fromStatus`, OBLIGATION_STATUSES) &&
                literal(v, record.toStatus, `${path}.toStatus`, OBLIGATION_STATUSES) &&
                identifier(v, record.actorId, `${path}.actorId`) &&
                identifier(v, record.action, `${path}.action`) &&
                administrativeAuthorization(v, record.administrativeAuthorization, `${path}.administrativeAuthorization`) &&
                identifier(v, record.attesterId, `${path}.attesterId`) &&
                evidenceReference(v, record.evidenceReference, `${path}.evidenceReference`);
        }
        case "AGENT_TERMINATED": {
            const record = v.record(value, path, [
                "agentId",
                "principalId",
                "successionRuleId",
                "roleId",
                "roleTenureId",
            ]);
            return record !== undefined &&
                identifier(v, record.agentId, `${path}.agentId`) &&
                identifier(v, record.principalId, `${path}.principalId`) &&
                identifier(v, record.successionRuleId, `${path}.successionRuleId`) &&
                identifier(v, record.roleId, `${path}.roleId`) &&
                identifier(v, record.roleTenureId, `${path}.roleTenureId`);
        }
    }
};
const EVENT_ENVELOPE_FIELDS = Object.freeze([
    "id",
    "type",
    "timestamp",
    "data",
]);
const captureEnvelopeField = (source, key) => {
    let descriptor;
    try {
        descriptor = Reflect.getOwnPropertyDescriptor(source, key);
    }
    catch {
        return {
            ok: false,
            reason: `$.${key}: failed descriptor capture`,
        };
    }
    if (descriptor === undefined) {
        return {
            ok: false,
            reason: `$.${key}: changed during envelope capture`,
        };
    }
    if (Object.hasOwn(descriptor, "value")) {
        return { ok: true, value: descriptor.value };
    }
    if (descriptor.get === undefined)
        return { ok: true, value: undefined };
    try {
        return {
            ok: true,
            value: Reflect.apply(descriptor.get, source, []),
        };
    }
    catch {
        return {
            ok: false,
            reason: `$.${key}: accessor failed during its single capture`,
        };
    }
};
const invalidEvent = (code, reason, failureKind) => {
    const result = { ok: false, code, reason };
    return failureKind === "LIMIT" ? brandSchemaLimitFailure(result) : result;
};
const invalidGenesisProbe = (reason, failureKind) => {
    const result = {
        ok: false,
        code: "EVENT_DATA_INVALID",
        reason,
    };
    return failureKind === "LIMIT" ? brandSchemaLimitFailure(result) : result;
};
const CAPTURED_BASE_EVENT_SOURCES = createWeakMap();
/**
 * @internal Validate one event envelope from the shared replay snapshot.
 * This function never observes caller-owned data and applies no event schema.
 */
export const validateCapturedReplayBaseCandidate = (candidate, eventPosition, source) => {
    const path = `$.events[${eventPosition}]`;
    const capturedEnvelopeKeys = source.capturedRecordKeys(candidate);
    if (capturedEnvelopeKeys !== undefined) {
        const expectedEnvelopeKeys = createSet();
        for (let index = 0; index < EVENT_ENVELOPE_FIELDS.length; index += 1) {
            setAdd(expectedEnvelopeKeys, EVENT_ENVELOPE_FIELDS[index]);
        }
        for (let index = 0; index < capturedEnvelopeKeys.length; index += 1) {
            const key = capturedEnvelopeKeys[index];
            if (!setHas(expectedEnvelopeKeys, key)) {
                return {
                    ok: false,
                    code: "EVENT_ENVELOPE_INVALID",
                    reason: `${path}: event has an undeclared field`,
                };
            }
        }
    }
    const validator = new ShapeValidator(source.capturedRecordKeys);
    const record = validator.record(candidate, path, EVENT_ENVELOPE_FIELDS);
    if (record === undefined) {
        return {
            ok: false,
            code: "EVENT_ENVELOPE_INVALID",
            reason: validator.problem ?? `${path}: invalid base event envelope`,
        };
    }
    if (!identifier(validator, record.id, `${path}.id`) ||
        !protocolString(validator, record.type, `${path}.type`) ||
        !u53(validator, record.timestamp, `${path}.timestamp`)) {
        return {
            ok: false,
            code: "EVENT_ENVELOPE_INVALID",
            reason: validator.problem ?? `${path}: invalid base event scalar`,
        };
    }
    if (!isPlainRecord(record.data)) {
        return {
            ok: false,
            code: "EVENT_ENVELOPE_INVALID",
            reason: `${path}.data: must be a plain protocol record`,
        };
    }
    const dataBytes = source.capturedCanonicalBytes(record.data);
    if (dataBytes === undefined) {
        return {
            ok: false,
            code: "EVENT_ENVELOPE_INVALID",
            reason: `${path}.data: is not part of the shared canonical snapshot`,
        };
    }
    if (dataBytes > MAX_EVENT_DATA_BYTES) {
        return {
            ok: false,
            code: "EVENT_ENVELOPE_INVALID",
            reason: `${path}.data: exceeds the ${MAX_EVENT_DATA_BYTES}-byte event-data byte limit`,
        };
    }
    const baseEvent = Object.freeze({
        eventPosition,
        event: record,
    });
    weakMapSet(CAPTURED_BASE_EVENT_SOURCES, baseEvent, Object.freeze(source));
    return { ok: true, baseEvent };
};
export const validateCapturedReplayBaseEvent = (capture, eventPosition) => {
    if (!isCapturedCanonicalReplayBody(capture) ||
        !Number.isSafeInteger(eventPosition) ||
        eventPosition < 0 ||
        eventPosition >= capture.value.events.length) {
        return {
            ok: false,
            code: "EVENT_ENVELOPE_INVALID",
            reason: "$: invalid captured replay event position",
        };
    }
    return validateCapturedReplayBaseCandidate(capture.value.events[eventPosition], eventPosition, {
        capturedRecordKeys: capture.capturedRecordKeys,
        capturedCanonicalBytes: capture.capturedCanonicalBytes,
    });
};
/** @internal Validate one provenance-bound incremental replay snapshot. */
export const validateIncrementallyCapturedReplayBaseEvent = (capture) => {
    if (!isCapturedCanonicalReplayEvent(capture)) {
        return {
            ok: false,
            code: "EVENT_ENVELOPE_INVALID",
            reason: "$: invalid incremental replay event capture",
        };
    }
    return validateCapturedReplayBaseCandidate(capture.event, capture.eventPosition, {
        capturedRecordKeys: capture.capturedRecordKeys,
        capturedCanonicalBytes: capture.capturedCanonicalBytes,
    });
};
/**
 * @internal Schema-independent discovery probe for a captured genesis-typed
 * base event. It accepts any well-formed declared interpreter identifiers.
 */
export const validateCapturedGenesisVersionProbe = (baseEvent) => {
    const source = weakMapGet(CAPTURED_BASE_EVENT_SOURCES, baseEvent);
    if (source === undefined || baseEvent.event.type !== "DEPLOYMENT_INITIALIZED") {
        return invalidGenesisProbe(source === undefined
            ? "$: is not a captured replay base event"
            : `$.events[${baseEvent.eventPosition}]: is not genesis-typed`);
    }
    const path = `$.events[${baseEvent.eventPosition}].data`;
    const validator = new ShapeValidator(source.capturedRecordKeys);
    if (!preflightEventNamedLimits(validator, "DEPLOYMENT_INITIALIZED", baseEvent.event.data, path)) {
        return invalidGenesisProbe(validator.problem ?? `${path}: invalid GenesisVersionProbe`, validator.failureKind);
    }
    const record = validator.record(baseEvent.event.data, path, [
        "domain",
        "adapterPolicyHash",
        "canonicalLineageId",
        "versions",
        "policyVersion",
        "rootRecognitionPolicy",
        "globalPolicySourceId",
        "timeSource",
        "finality",
    ]);
    if (record === undefined ||
        !authorizationDomain(validator, record.domain, `${path}.domain`) ||
        !contentHash(validator, record.adapterPolicyHash, `${path}.adapterPolicyHash`) ||
        !identifier(validator, record.canonicalLineageId, `${path}.canonicalLineageId`) ||
        !declaredVersionSet(validator, record.versions, `${path}.versions`) ||
        !identifier(validator, record.policyVersion, `${path}.policyVersion`) ||
        (record.rootRecognitionPolicy !== "declared-principal-root/0.2" &&
            !validator.fail(`${path}.rootRecognitionPolicy`, "must equal declared-principal-root/0.2")) ||
        !identifier(validator, record.globalPolicySourceId, `${path}.globalPolicySourceId`) ||
        (record.timeSource !== "EVENT_TIMESTAMP" &&
            !validator.fail(`${path}.timeSource`, "must equal EVENT_TIMESTAMP")) ||
        (record.finality !== "LOCAL_ONLY" &&
            !validator.fail(`${path}.finality`, "must equal LOCAL_ONLY"))) {
        return invalidGenesisProbe(validator.problem ?? `${path}: invalid GenesisVersionProbe`, validator.failureKind);
    }
    const probe = baseEvent.event;
    return {
        ok: true,
        probe,
        versions: probe.data.versions,
    };
};
/**
 * @internal Receipt input-limit phase over already captured base histories.
 * Discover every branch before applying any current-schema payload limit.
 * Only an exact, valid VersionSet dispatches those named slots. Missing or
 * malformed discovery, unknown event types, and all ordinary payload semantics
 * remain for the consuming operation; no transition or artifact is inspected.
 */
export const preflightCapturedPortableReceiptHistoryLimits = (capture, histories) => {
    const supported = [];
    let discoveryLimit = false;
    for (let index = 0; index < histories.length; index += 1) {
        const history = histories[index];
        let exactVersions = false;
        if (history.length > 0) {
            const first = history[0];
            if (isPlainRecord(first) && first.type === "DEPLOYMENT_INITIALIZED") {
                const base = validateCapturedReplayBaseCandidate(first, 0, capture);
                if (base.ok) {
                    const discovery = validateCapturedGenesisVersionProbe(base.baseEvent);
                    if (isCoreSchemaLimitFailure(discovery))
                        discoveryLimit = true;
                    if (discovery.ok) {
                        exactVersions = versionSet(new ShapeValidator(capture.capturedRecordKeys), discovery.versions, `$.histories[${index}][0].data.versions`);
                    }
                }
            }
        }
        arrayPush(supported, exactVersions);
    }
    if (discoveryLimit)
        return "LIMIT";
    for (let index = 0; index < histories.length; index += 1) {
        if (!supported[index])
            continue;
        const history = histories[index];
        const validator = new ShapeValidator(capture.capturedRecordKeys);
        for (let position = 0; position < history.length; position += 1) {
            const event = history[position];
            if (isPlainRecord(event) && isCoreEventType(event.type) &&
                !preflightEventNamedLimits(validator, event.type, event.data, `$.histories[${index}][${position}].data`) && validator.failureKind === "LIMIT") {
                return "LIMIT";
            }
        }
    }
    return "VALID";
};
/**
 * @internal Refine one captured base event under the isolated 0.2 schema.
 * The accepted event is the same immutable object returned by base capture.
 */
export const refineCapturedCoreEvent = (baseEvent) => {
    const source = weakMapGet(CAPTURED_BASE_EVENT_SOURCES, baseEvent);
    if (source === undefined) {
        return invalidEvent("EVENT_ENVELOPE_INVALID", "$: event is not a captured replay base event");
    }
    if (!isCoreEventType(baseEvent.event.type)) {
        return invalidEvent("EVENT_TYPE_UNSUPPORTED", `$.type: unsupported 0.2 EventType ${jsonStringify(baseEvent.event.type)}`);
    }
    const validator = new ShapeValidator(source.capturedRecordKeys);
    if (!preflightEventNamedLimits(validator, baseEvent.event.type, baseEvent.event.data) ||
        !validateEventData(validator, baseEvent.event.type, baseEvent.event.data)) {
        return invalidEvent("EVENT_DATA_INVALID", validator.problem ?? "$.data: invalid closed event payload", validator.failureKind);
    }
    const event = baseEvent.event;
    return {
        ok: true,
        typeRank: mapGet(EVENT_TYPE_RANK, event.type),
        event,
    };
};
/**
 * Capture and validate one experimental 0.2 event before hashing.
 * This checks only portable shape/scalars. History order, uniqueness,
 * referential integrity, signatures, and state-transition predicates remain
 * replay responsibilities.
 */
export const validateCanonicalEventShape = (input) => {
    if (input === null || typeof input !== "object") {
        return invalidEvent("EVENT_ENVELOPE_INVALID", "$: event must be a plain protocol record");
    }
    let prototype;
    try {
        prototype = Reflect.getPrototypeOf(input);
    }
    catch {
        return invalidEvent("EVENT_ENVELOPE_INVALID", "$: failed event prototype capture");
    }
    if (prototype !== Object.prototype && prototype !== null) {
        return invalidEvent("EVENT_ENVELOPE_INVALID", "$: event must be a plain protocol record");
    }
    let ownKeys;
    try {
        ownKeys = Reflect.ownKeys(input);
    }
    catch {
        return invalidEvent("EVENT_ENVELOPE_INVALID", "$: failed event own-key capture");
    }
    const expectedFields = createSet();
    for (let index = 0; index < EVENT_ENVELOPE_FIELDS.length; index += 1) {
        setAdd(expectedFields, EVENT_ENVELOPE_FIELDS[index]);
    }
    for (let index = 0; index < ownKeys.length; index += 1) {
        const key = ownKeys[index];
        if (typeof key !== "string") {
            return invalidEvent("EVENT_ENVELOPE_INVALID", "$: event has a non-string field");
        }
        if (!setHas(expectedFields, key)) {
            return invalidEvent("EVENT_ENVELOPE_INVALID", "$: event has an undeclared field");
        }
    }
    const observedFields = createSet();
    for (let index = 0; index < ownKeys.length; index += 1) {
        setAdd(observedFields, ownKeys[index]);
    }
    for (let index = 0; index < EVENT_ENVELOPE_FIELDS.length; index += 1) {
        const key = EVENT_ENVELOPE_FIELDS[index];
        if (!setHas(observedFields, key)) {
            return invalidEvent("EVENT_ENVELOPE_INVALID", `$.${key}: is required`);
        }
    }
    const envelopeValidator = new ShapeValidator(() => undefined);
    const idCapture = captureEnvelopeField(input, "id");
    if (!idCapture.ok) {
        return invalidEvent("EVENT_ENVELOPE_INVALID", idCapture.reason);
    }
    if (!identifier(envelopeValidator, idCapture.value, "$.id")) {
        return invalidEvent("EVENT_ENVELOPE_INVALID", envelopeValidator.problem);
    }
    const typeCapture = captureEnvelopeField(input, "type");
    if (!typeCapture.ok) {
        return invalidEvent("EVENT_ENVELOPE_INVALID", typeCapture.reason);
    }
    if (!protocolString(envelopeValidator, typeCapture.value, "$.type")) {
        return invalidEvent("EVENT_ENVELOPE_INVALID", envelopeValidator.problem);
    }
    const timestampCapture = captureEnvelopeField(input, "timestamp");
    if (!timestampCapture.ok) {
        return invalidEvent("EVENT_ENVELOPE_INVALID", timestampCapture.reason);
    }
    if (!u53(envelopeValidator, timestampCapture.value, "$.timestamp")) {
        return invalidEvent("EVENT_ENVELOPE_INVALID", envelopeValidator.problem);
    }
    const dataFieldCapture = captureEnvelopeField(input, "data");
    if (!dataFieldCapture.ok) {
        return invalidEvent("EVENT_ENVELOPE_INVALID", dataFieldCapture.reason);
    }
    const rawData = dataFieldCapture.value;
    if (rawData === null || typeof rawData !== "object") {
        return invalidEvent("EVENT_ENVELOPE_INVALID", "$.data: must be a plain protocol record");
    }
    let dataCapture;
    try {
        dataCapture = captureBoundedCanonicalEventData(rawData, input, MAX_EVENT_DATA_BYTES);
    }
    catch (error) {
        if (isCanonicalEventDataShapeError(error)) {
            return invalidEvent("EVENT_ENVELOPE_INVALID", "$.data: must be a plain protocol record");
        }
        if (isCanonicalCaptureLimitError(error, "$", MAX_EVENT_DATA_BYTES)) {
            return invalidEvent("EVENT_DATA_INVALID", `$.data: exceeds the ${MAX_EVENT_DATA_BYTES}-byte event-data byte limit`);
        }
        return invalidEvent("EVENT_DATA_INVALID", "$.data: failed canonical base capture");
    }
    if (!isPlainRecord(dataCapture.value)) {
        return invalidEvent("EVENT_ENVELOPE_INVALID", "$.data: must be a plain protocol record");
    }
    if (!isCoreEventType(typeCapture.value)) {
        return invalidEvent("EVENT_TYPE_UNSUPPORTED", `$.type: unsupported 0.2 EventType ${jsonStringify(typeCapture.value)}`);
    }
    const rootRecordKeys = Object.freeze(["data", "id", "timestamp", "type"]);
    const frozenEvent = Object.create(null);
    Object.defineDataProperty(frozenEvent, "id", idCapture.value, false, true);
    Object.defineDataProperty(frozenEvent, "type", typeCapture.value, false, true);
    Object.defineDataProperty(frozenEvent, "timestamp", timestampCapture.value, false, true);
    Object.defineDataProperty(frozenEvent, "data", dataCapture.value, false, true);
    Object.freeze(frozenEvent);
    const capturedRecordKeys = Object.freeze((candidate) => candidate === frozenEvent
        ? rootRecordKeys
        : dataCapture.capturedRecordKeys(candidate));
    const dataValidator = new ShapeValidator(capturedRecordKeys);
    if (!preflightEventNamedLimits(dataValidator, typeCapture.value, dataCapture.value) ||
        !validateEventData(dataValidator, typeCapture.value, dataCapture.value)) {
        return invalidEvent("EVENT_DATA_INVALID", dataValidator.problem ?? "$.data: invalid closed event payload", dataValidator.failureKind);
    }
    const frozen = frozenEvent;
    return {
        ok: true,
        typeRank: mapGet(EVENT_TYPE_RANK, frozen.type),
        event: frozen,
    };
};
