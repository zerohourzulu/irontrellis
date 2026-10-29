import { portableDutyPolicyActivationRequirements, portableDutyPolicyActivationProofMatches } from "./duty-policy.js";
import { canonicalEncode, compareProtocolStrings, captureBoundedCanonicalReplayBodyIncrementally, getCanonicalReplayBaseFailureMetadata, hashCanonical, isWellFormedUnicode, } from "./canonical.js";
import { refineCapturedCoreEvent, isCoreSchemaLimitFailure, validateCapturedGenesisVersionProbe, validateIncrementallyCapturedReplayBaseEvent, } from "./event-schema.js";
import { validatePortableAdministrativeTransition, validatePortableIntentAdmissionTransition, } from "./portable-authority-engine.js";
import { PORTABLE_ADAPTER_POLICY_E5_HASH, PORTABLE_ADAPTER_POLICY_E6_HASH, REMOTE_SERVICE_REPORT_ADAPTER_ID, SIMULATED_ADAPTER_ID, resolvePortableAdapterPolicy, validatePortableAdapterProfileForPolicy, portableAdapterAcknowledgmentTransactionReference, validatePortableAdapterAcknowledgment, validatePortableAdapterNoEffect, portableAdapterNoEffectEvidence, derivePortableAdapterIdentityForAcceptedAdmission, portableAdapterAcknowledgmentEvidence, samePortableAdapterEvidence, } from "./portable-adapter-engine.js";
import { HostTypeError, arrayIncludes, arrayIsArray, arrayPush, copyArray, copyMap, cloneKeccak256State, createKeccak256State, createMap, createSet, createWeakSet, finalizeKeccak256State, hostObjectPrototype, mapDelete, mapForEach, mapGet, mapHas, mapSet, numberIsSafeInteger, objectDefineDataProperty, objectDefineProperty, objectFreeze, objectHasOwn, reflectApply, reflectGetOwnPropertyDescriptor, reflectGetPrototypeOf, reflectOwnKeys, setAdd, setDelete, setHas, setSize, setToArray, stringToLowerCase, utf8Encode, uint8ArrayLength, updateKeccak256State, weakSetAdd, weakSetHas, } from "./host-intrinsics.js";
const Array = objectFreeze({ isArray: arrayIsArray });
const Number = objectFreeze({ isSafeInteger: numberIsSafeInteger });
const Object = objectFreeze({
    freeze: objectFreeze,
    prototype: hostObjectPrototype,
});
const Reflect = objectFreeze({
    apply: reflectApply,
    getOwnPropertyDescriptor: reflectGetOwnPropertyDescriptor,
    getPrototypeOf: reflectGetPrototypeOf,
    ownKeys: reflectOwnKeys,
});
const TypeError = HostTypeError;
const ownOptional = (record, key) => objectHasOwn(record, key) ? record[key] : undefined;
export const PORTABLE_REPLAY_VERSION = "continuity-replay/0.2";
const EVENT_SCHEMA_VERSION = "continuity-event/0.2";
const RECEIPT_SCHEMA_VERSION = "continuity-receipt/0.2";
const QUERY_ENVELOPE_VERSION = "continuity-query-envelope/0.2";
const AUTHORIZATION_PROOF_VERSION = "continuity-authorization-proof/0.2";
const RUNTIME_AUTHORIZATION_VERSION = "continuity-runtime-authorization/0.2";
const ADMINISTRATIVE_AUTHORIZATION_VERSION = "continuity-administrative-authorization/0.2";
const SIGNATURE_SCHEME = "eip191-personal-sign-keccak256";
const MAX_PROTOCOL_STRING_BYTES = 4_096;
const MAX_AUTHORITY_PATH_DEPTH = 32;
const UTF8_ENCODER = objectFreeze({ encode: utf8Encode });
const EVENT_HISTORY_CANONICAL_PREFIX = UTF8_ENCODER.encode('["continuity-event-history/0.2",[');
const EVENT_HISTORY_CANONICAL_SEPARATOR = UTF8_ENCODER.encode(",");
const EVENT_HISTORY_CANONICAL_SUFFIX = UTF8_ENCODER.encode("]]");
const portableReplayStateBrand = Symbol("continuity.portableReplayState");
const PORTABLE_REPLAY_STATES = createWeakSet();
const reject = (code, eventPosition, eventId) => {
    const result = {
        operationVersion: PORTABLE_REPLAY_VERSION,
        status: "REJECTED",
        code,
    };
    objectDefineDataProperty(result, "eventPosition", eventPosition, false, eventPosition !== undefined);
    objectDefineDataProperty(result, "eventId", eventId, false, eventId !== undefined);
    return Object.freeze(result);
};
const isPlainRecord = (value) => {
    if (value === null || typeof value !== "object") {
        return false;
    }
    let prototype;
    try {
        if (Array.isArray(value))
            return false;
        prototype = Reflect.getPrototypeOf(value);
    }
    catch {
        return false;
    }
    return prototype === Object.prototype || prototype === null;
};
const capturedDescriptorValue = (source, key) => {
    let descriptor;
    try {
        descriptor = Reflect.getOwnPropertyDescriptor(source, key);
    }
    catch {
        return { ok: false };
    }
    if (descriptor === undefined)
        return { ok: false };
    if (objectHasOwn(descriptor, "value")) {
        return { ok: true, value: descriptor.value };
    }
    const getter = ownOptional(descriptor, "get");
    if (getter === undefined)
        return { ok: true, value: undefined };
    try {
        return { ok: true, value: Reflect.apply(getter, source, []) };
    }
    catch {
        return { ok: false };
    }
};
const isBoundedProtocolString = (value) => typeof value === "string" &&
    value.length <= MAX_PROTOCOL_STRING_BYTES &&
    isWellFormedUnicode(value) &&
    uint8ArrayLength(UTF8_ENCODER.encode(value)) <= MAX_PROTOCOL_STRING_BYTES;
const captureReplayOuter = (input) => {
    if (!isPlainRecord(input))
        return { ok: false, code: "INVALID_INPUT" };
    let keys;
    try {
        keys = Reflect.ownKeys(input);
    }
    catch {
        return { ok: false, code: "INVALID_INPUT" };
    }
    if (keys.length !== 2 ||
        (() => {
            for (let index = 0; index < keys.length; index += 1) {
                if (typeof keys[index] !== "string")
                    return true;
            }
            return false;
        })() ||
        !arrayIncludes(keys, "operationVersion") ||
        !arrayIncludes(keys, "events")) {
        return { ok: false, code: "INVALID_INPUT" };
    }
    const operationVersion = capturedDescriptorValue(input, "operationVersion");
    if (!operationVersion.ok || !isBoundedProtocolString(operationVersion.value)) {
        return { ok: false, code: "INVALID_INPUT" };
    }
    if (operationVersion.value !== PORTABLE_REPLAY_VERSION) {
        return { ok: false, code: "UNSUPPORTED_VERSION" };
    }
    const events = capturedDescriptorValue(input, "events");
    if (!events.ok)
        return { ok: false, code: "INVALID_INPUT" };
    return { ok: true, source: input, events: events.value };
};
const captureFailureResult = (error) => {
    const baseFailure = getCanonicalReplayBaseFailureMetadata(error);
    if (baseFailure !== undefined) {
        return reject("INVALID_INPUT", ownOptional(baseFailure, "eventPosition"), ownOptional(baseFailure, "eventId"));
    }
    return reject("INVALID_INPUT");
};
const newEventHistoryHashState = () => {
    const state = createKeccak256State();
    updateKeccak256State(state, EVENT_HISTORY_CANONICAL_PREFIX);
    return state;
};
const newDraft = () => ({
    acceptedEvents: [],
    eventHistoryHashes: [],
    historyHashState: newEventHistoryHashState(),
    eventPositionsById: createMap(),
    genesis: undefined,
    principals: createMap(),
    agents: createMap(),
    reservedAgentIds: createMap(),
    roles: createMap(),
    successionRules: createMap(),
    tenures: createMap(),
    currentTenureIdsByAgent: createMap(),
    runtimeSessions: createMap(),
    runtimeSessionIdsByAgent: createMap(),
    credentialKeyIds: createSet(),
    credentialAddressKeysByAgent: createMap(),
    intentDeclarations: createMap(),
    intentAdmissions: createMap(),
    intentConsumptions: createMap(),
    intentOutcomeStates: createMap(),
    outcomeObservations: createMap(),
    attemptDuties: createMap(),
    attemptDutyReviews: createMap(),
    attemptDutyPolicies: createMap(),
    attemptDutyIdsBySourceIntent: createMap(),
    receiptCommitments: createMap(),
    obligations: createMap(),
    obligationIdsBySourceIntent: createMap(),
    nonceReservationsByActor: createMap(),
    authorities: createMap(),
    recognizedRoots: createMap(),
    authorityUsage: createMap(),
    lastTimestamp: undefined,
});
const activeAgent = (draft, agentId) => {
    const agent = mapGet(draft.agents, agentId);
    return agent === undefined || agent.terminated ? undefined : agent;
};
const addCurrentTenure = (draft, agentId, tenureId) => {
    const current = mapGet(draft.currentTenureIdsByAgent, agentId) ?? createSet();
    setAdd(current, tenureId);
    mapSet(draft.currentTenureIdsByAgent, agentId, current);
};
const removeCurrentTenure = (draft, agentId, tenureId) => {
    const current = mapGet(draft.currentTenureIdsByAgent, agentId);
    if (current !== undefined) {
        setDelete(current, tenureId);
        if (setSize(current) === 0)
            mapDelete(draft.currentTenureIdsByAgent, agentId);
    }
};
const openTenure = (draft, data) => {
    const role = mapGet(draft.roles, data.roleId);
    const successionRuleId = ownOptional(data, "successionRuleId");
    const tenure = Object.freeze({
        id: data.roleTenureId,
        roleId: data.roleId,
        agentId: data.agentId,
        principalId: data.principalId,
        tenureNumber: data.tenureNumber,
        ...(successionRuleId === undefined
            ? {}
            : { successionRuleId }),
        closed: false,
    });
    mapSet(draft.tenures, tenure.id, tenure);
    mapSet(draft.roles, role.id, Object.freeze({
        ...role,
        currentTenureId: tenure.id,
        latestTenureNumber: tenure.tenureNumber,
    }));
    addCurrentTenure(draft, tenure.agentId, tenure.id);
};
const closeTenure = (draft, role, tenure) => {
    mapSet(draft.tenures, tenure.id, Object.freeze({ ...tenure, closed: true }));
    mapSet(draft.roles, role.id, Object.freeze({
        id: role.id,
        principalId: role.principalId,
        latestTenureNumber: role.latestTenureNumber,
    }));
    removeCurrentTenure(draft, tenure.agentId, tenure.id);
};
const applyPrincipalCreated = (draft, data, eventId, eventPosition) => {
    if (mapHas(draft.principals, data.principalId) ||
        mapHas(draft.agents, data.principalId) ||
        mapHas(draft.reservedAgentIds, data.principalId)) {
        return false;
    }
    mapSet(draft.principals, data.principalId, Object.freeze({
        id: data.principalId,
        creationEventId: eventId,
        creationEventPosition: eventPosition,
    }));
    return true;
};
const applyAgentCreated = (draft, data) => {
    if (mapHas(draft.agents, data.agentId) ||
        mapHas(draft.principals, data.agentId) ||
        !mapHas(draft.principals, data.principalId) ||
        data.initialControlEpoch !== 1) {
        return false;
    }
    mapSet(draft.agents, data.agentId, Object.freeze({
        id: data.agentId,
        principalId: data.principalId,
        controllerId: data.controllerId,
        currentControlEpoch: 1,
        terminated: false,
    }));
    return true;
};
const applyRoleCreated = (draft, data) => {
    if (mapHas(draft.roles, data.roleId) || !mapHas(draft.principals, data.principalId)) {
        return false;
    }
    mapSet(draft.roles, data.roleId, Object.freeze({
        id: data.roleId,
        principalId: data.principalId,
        latestTenureNumber: 0,
    }));
    return true;
};
const applySuccessionRuleDeclared = (draft, data) => {
    const role = mapGet(draft.roles, data.roleId);
    if (mapHas(draft.successionRules, data.ruleId) ||
        !mapHas(draft.principals, data.principalId) ||
        role === undefined ||
        role.principalId !== data.principalId ||
        !mapHas(draft.agents, data.predecessorAgentId) ||
        mapHas(draft.principals, data.successorAgentId)) {
        return false;
    }
    mapSet(draft.successionRules, data.ruleId, Object.freeze({ data }));
    const reservations = mapGet(draft.reservedAgentIds, data.successorAgentId) ?? createSet();
    setAdd(reservations, data.ruleId);
    mapSet(draft.reservedAgentIds, data.successorAgentId, reservations);
    return true;
};
const applyAgentAppointed = (draft, data) => {
    const agent = activeAgent(draft, data.agentId);
    const role = mapGet(draft.roles, data.roleId);
    const currentTenureId = role === undefined
        ? undefined
        : ownOptional(role, "currentTenureId");
    const successionRuleId = ownOptional(data, "successionRuleId");
    if (agent === undefined ||
        role === undefined ||
        currentTenureId !== undefined ||
        role.principalId !== data.principalId ||
        mapHas(draft.tenures, data.roleTenureId) ||
        data.tenureNumber !== role.latestTenureNumber + 1) {
        return false;
    }
    if (successionRuleId !== undefined) {
        const rule = mapGet(draft.successionRules, successionRuleId)?.data;
        if (rule === undefined ||
            rule.predecessorAgentId !== data.agentId ||
            rule.roleId !== data.roleId ||
            rule.principalId !== data.principalId) {
            return false;
        }
    }
    openTenure(draft, data);
    return true;
};
const applyAgentUnappointed = (draft, data) => {
    const role = mapGet(draft.roles, data.roleId);
    const tenure = mapGet(draft.tenures, data.roleTenureId);
    const currentTenureId = role === undefined
        ? undefined
        : ownOptional(role, "currentTenureId");
    const successionLock = tenure === undefined
        ? undefined
        : ownOptional(tenure, "successionLock");
    if (role === undefined ||
        tenure === undefined ||
        currentTenureId !== data.roleTenureId ||
        tenure.closed ||
        tenure.agentId !== data.agentId ||
        tenure.roleId !== data.roleId ||
        role.principalId !== data.principalId ||
        tenure.principalId !== data.principalId ||
        successionLock !== undefined) {
        return false;
    }
    closeTenure(draft, role, tenure);
    return true;
};
const applyRoleTransferred = (draft, data) => {
    const role = mapGet(draft.roles, data.roleId);
    const tenure = mapGet(draft.tenures, data.fromRoleTenureId);
    const currentTenureId = role === undefined
        ? undefined
        : ownOptional(role, "currentTenureId");
    const successionLock = tenure === undefined
        ? undefined
        : ownOptional(tenure, "successionLock");
    const successionRuleId = ownOptional(data, "successionRuleId");
    if (role === undefined ||
        tenure === undefined ||
        currentTenureId !== data.fromRoleTenureId ||
        tenure.closed ||
        tenure.agentId !== data.fromAgentId ||
        tenure.roleId !== data.roleId ||
        role.principalId !== data.principalId ||
        activeAgent(draft, data.toAgentId) === undefined ||
        mapHas(draft.tenures, data.toRoleTenureId) ||
        data.toTenureNumber !== role.latestTenureNumber + 1) {
        return false;
    }
    if (data.transferKind === "REASSIGNMENT") {
        if (successionRuleId !== undefined || successionLock !== undefined) {
            return false;
        }
    }
    else {
        if (successionRuleId === undefined || successionLock === undefined) {
            return false;
        }
        const lock = successionLock;
        const rule = mapGet(draft.successionRules, successionRuleId)?.data;
        if (lock.agentId !== data.fromAgentId ||
            lock.principalId !== data.principalId ||
            lock.successionRuleId !== successionRuleId ||
            lock.roleId !== data.roleId ||
            lock.roleTenureId !== data.fromRoleTenureId ||
            rule === undefined ||
            rule.predecessorAgentId !== data.fromAgentId ||
            rule.successorAgentId !== data.toAgentId ||
            rule.roleId !== data.roleId ||
            rule.principalId !== data.principalId ||
            !arrayIncludes(rule.permittedEventTypes, "ROLE_TRANSFERRED")) {
            return false;
        }
    }
    closeTenure(draft, role, tenure);
    // The transfer rule proves this transfer. Only an appointment-declared
    // rule constrains a later termination of the newly opened tenure.
    openTenure(draft, {
        roleId: data.roleId,
        agentId: data.toAgentId,
        roleTenureId: data.toRoleTenureId,
        tenureNumber: data.toTenureNumber,
        principalId: data.principalId,
    });
    return true;
};
const applyRuntimeSessionAdmitted = (draft, event, data) => {
    const agent = activeAgent(draft, data.agentId);
    const expiresAt = ownOptional(data, "expiresAt");
    const addressKey = stringToLowerCase(data.credentialAddress);
    const usedAddresses = mapGet(draft.credentialAddressKeysByAgent, data.agentId) ?? createSet();
    if (agent === undefined ||
        data.controllerId !== agent.controllerId ||
        data.controlEpoch !== agent.currentControlEpoch ||
        mapHas(draft.runtimeSessions, data.sessionId) ||
        setHas(draft.credentialKeyIds, data.credentialKeyId) ||
        setHas(usedAddresses, addressKey)) {
        return false;
    }
    const priorSessionIds = mapGet(draft.runtimeSessionIdsByAgent, data.agentId) ?? [];
    for (let index = 0; index < priorSessionIds.length; index += 1) {
        const sessionId = priorSessionIds[index];
        const session = mapGet(draft.runtimeSessions, sessionId);
        const expiresAt = ownOptional(session, "expiresAt");
        if (session.controlEpoch === agent.currentControlEpoch &&
            (expiresAt === undefined || event.timestamp < expiresAt)) {
            return false;
        }
    }
    const session = Object.freeze({
        id: data.sessionId,
        agentId: data.agentId,
        controllerId: data.controllerId,
        controlEpoch: data.controlEpoch,
        credentialKeyId: data.credentialKeyId,
        credentialAddressKey: addressKey,
        admissionEventId: event.id,
        admissionEventPosition: draft.acceptedEvents.length,
        ...(expiresAt === undefined ? {} : { expiresAt }),
    });
    mapSet(draft.runtimeSessions, session.id, session);
    setAdd(draft.credentialKeyIds, session.credentialKeyId);
    setAdd(usedAddresses, addressKey);
    mapSet(draft.credentialAddressKeysByAgent, data.agentId, usedAddresses);
    const sessionIds = mapGet(draft.runtimeSessionIdsByAgent, data.agentId) ?? [];
    arrayPush(sessionIds, session.id);
    mapSet(draft.runtimeSessionIdsByAgent, data.agentId, sessionIds);
    return true;
};
const applyControlEpochAdvanced = (draft, data) => {
    const agent = activeAgent(draft, data.agentId);
    if (agent === undefined ||
        data.controllerId !== agent.controllerId ||
        data.fromEpoch !== agent.currentControlEpoch ||
        data.toEpoch !== data.fromEpoch + 1 ||
        !Number.isSafeInteger(data.fromEpoch + 1)) {
        return false;
    }
    mapSet(draft.agents, agent.id, Object.freeze({ ...agent, currentControlEpoch: data.toEpoch }));
    return true;
};
const applyTransactionIntentDeclared = (draft, data) => {
    if (mapHas(draft.intentDeclarations, data.intentId) ||
        !mapHas(draft.agents, data.actorId) ||
        !mapHas(draft.roles, data.roleId) ||
        !mapHas(draft.tenures, data.roleTenureId) ||
        draft.genesis === undefined ||
        !validatePortableAdapterProfileForPolicy(draft.genesis.adapterPolicyHash, data.adapterProfile)) {
        return false;
    }
    mapSet(draft.intentDeclarations, data.intentId, Object.freeze({ data }));
    return true;
};
const applyAgentTerminated = (draft, data) => {
    const agent = activeAgent(draft, data.agentId);
    const role = mapGet(draft.roles, data.roleId);
    const tenure = mapGet(draft.tenures, data.roleTenureId);
    const rule = mapGet(draft.successionRules, data.successionRuleId)?.data;
    const currentTenures = mapGet(draft.currentTenureIdsByAgent, data.agentId);
    const currentTenureId = role === undefined
        ? undefined
        : ownOptional(role, "currentTenureId");
    const tenureSuccessionRuleId = tenure === undefined
        ? undefined
        : ownOptional(tenure, "successionRuleId");
    if (agent === undefined ||
        role === undefined ||
        tenure === undefined ||
        rule === undefined ||
        currentTenures === undefined ||
        setSize(currentTenures) !== 1 ||
        !setHas(currentTenures, data.roleTenureId) ||
        currentTenureId !== data.roleTenureId ||
        tenure.closed ||
        tenure.agentId !== data.agentId ||
        tenure.roleId !== data.roleId ||
        agent.principalId !== data.principalId ||
        role.principalId !== data.principalId ||
        rule.principalId !== data.principalId ||
        rule.predecessorAgentId !== data.agentId ||
        rule.roleId !== data.roleId ||
        !arrayIncludes(rule.permittedEventTypes, "AGENT_TERMINATED") ||
        (tenureSuccessionRuleId !== undefined &&
            tenureSuccessionRuleId !== data.successionRuleId)) {
        return false;
    }
    const lock = Object.freeze({ ...data });
    mapSet(draft.agents, agent.id, Object.freeze({ ...agent, terminated: true }));
    mapSet(draft.tenures, tenure.id, Object.freeze({ ...tenure, successionLock: lock }));
    return true;
};
const constraintOwn = (constraints, key) => ownOptional(constraints, key);
const constraintIntervalIsValid = (constraints) => {
    const notBefore = constraintOwn(constraints, "notBefore");
    const expiresAt = constraintOwn(constraints, "expiresAt");
    return notBefore === undefined || expiresAt === undefined || notBefore < expiresAt;
};
const identifierSubset = (child, parent) => {
    for (let index = 0; index < child.length; index += 1) {
        if (!arrayIncludes(parent, child[index]))
            return false;
    }
    return true;
};
const inheritedIdentifiersPresent = (child, parent) => identifierSubset(parent, child);
const constraintsAreAttenuated = (parent, child) => {
    if (!constraintIntervalIsValid(child) ||
        !identifierSubset(child.actions, parent.actions) ||
        !identifierSubset(child.resources, parent.resources) ||
        !inheritedIdentifiersPresent(child.requiredIntersectionIds, parent.requiredIntersectionIds) ||
        parent.maxDelegationDepth === 0 ||
        child.maxDelegationDepth > parent.maxDelegationDepth - 1 ||
        (parent.quantitative && !child.quantitative)) {
        return false;
    }
    const parentNotBefore = constraintOwn(parent, "notBefore");
    const childNotBefore = constraintOwn(child, "notBefore");
    if (parentNotBefore !== undefined &&
        (childNotBefore === undefined || childNotBefore < parentNotBefore))
        return false;
    const parentExpiresAt = constraintOwn(parent, "expiresAt");
    const childExpiresAt = constraintOwn(child, "expiresAt");
    if (parentExpiresAt !== undefined &&
        (childExpiresAt === undefined || childExpiresAt > parentExpiresAt))
        return false;
    const parentMaxAmount = constraintOwn(parent, "maxAmount");
    const childMaxAmount = constraintOwn(child, "maxAmount");
    if (parentMaxAmount !== undefined &&
        (childMaxAmount === undefined || childMaxAmount > parentMaxAmount))
        return false;
    const parentMaxCumulativeAmount = constraintOwn(parent, "maxCumulativeAmount");
    const childMaxCumulativeAmount = constraintOwn(child, "maxCumulativeAmount");
    if (parentMaxCumulativeAmount !== undefined &&
        (childMaxCumulativeAmount === undefined ||
            childMaxCumulativeAmount > parentMaxCumulativeAmount))
        return false;
    const parentMaxTransactions = constraintOwn(parent, "maxTransactions");
    const childMaxTransactions = constraintOwn(child, "maxTransactions");
    return parentMaxTransactions === undefined ||
        (childMaxTransactions !== undefined &&
            childMaxTransactions <= parentMaxTransactions);
};
const authorityEndpointExists = (draft, identifier) => mapHas(draft.principals, identifier) || mapHas(draft.agents, identifier);
const permissionRecord = (draft, authorityId) => {
    const record = mapGet(draft.authorities, authorityId);
    return record?.grant.kind === "PERMISSION" ? record : undefined;
};
const permissionChildRemainsWithinPathLimit = (draft, parentAuthorityId) => {
    let depth = 2;
    let current = permissionRecord(draft, parentAuthorityId)?.grant;
    while (current !== undefined) {
        if (depth > MAX_AUTHORITY_PATH_DEPTH)
            return false;
        const parent = ownOptional(current, "parentAuthorityId");
        if (parent === undefined)
            return true;
        depth += 1;
        current = permissionRecord(draft, parent)?.grant;
    }
    return false;
};
const prohibitionConstraintsAreValid = (constraints) => constraintIntervalIsValid(constraints) &&
    constraints.requiredIntersectionIds.length === 0 &&
    constraints.maxDelegationDepth === 0 &&
    constraintOwn(constraints, "maxCumulativeAmount") === undefined &&
    constraintOwn(constraints, "maxTransactions") === undefined;
const applyAuthorityGranted = (draft, event, data) => {
    const grant = data.grant;
    const position = draft.acceptedEvents.length;
    if (draft.genesis === undefined ||
        mapHas(draft.authorities, grant.authorityId) ||
        !constraintIntervalIsValid(grant.constraints))
        return false;
    if (grant.kind === "PERMISSION") {
        if (!authorityEndpointExists(draft, grant.grantorId) ||
            !authorityEndpointExists(draft, grant.granteeId))
            return false;
        for (let index = 0; index < grant.constraints.requiredIntersectionIds.length; index += 1) {
            if (permissionRecord(draft, grant.constraints.requiredIntersectionIds[index]) === undefined)
                return false;
        }
        const parentAuthorityId = ownOptional(grant, "parentAuthorityId");
        if (parentAuthorityId === undefined) {
            if (!mapHas(draft.principals, grant.grantorId))
                return false;
        }
        else {
            const parent = permissionRecord(draft, parentAuthorityId)?.grant;
            if (parent === undefined ||
                !permissionChildRemainsWithinPathLimit(draft, parentAuthorityId) ||
                grant.grantorId !== parent.granteeId ||
                grant.rootAuthorityId !== parent.rootAuthorityId ||
                !constraintsAreAttenuated(parent.constraints, grant.constraints))
                return false;
        }
    }
    else {
        if (!prohibitionConstraintsAreValid(grant.constraints))
            return false;
        const subjectActorId = ownOptional(grant, "subjectActorId");
        if (subjectActorId !== undefined && !mapHas(draft.agents, subjectActorId)) {
            return false;
        }
        if (grant.scope === "GLOBAL") {
            if (grant.grantorId !== draft.genesis.globalPolicySourceId)
                return false;
        }
        else {
            if (!authorityEndpointExists(draft, grant.grantorId))
                return false;
            const root = mapGet(draft.recognizedRoots, grant.rootAuthorityId);
            if (root === undefined)
                return false;
            const parentAuthorityId = ownOptional(grant, "parentAuthorityId");
            if (grant.grantorId === root.principalId) {
                const rootGrant = permissionRecord(draft, root.rootAuthorityId)?.grant;
                if (parentAuthorityId !== undefined ||
                    rootGrant === undefined ||
                    !constraintsAreAttenuated(rootGrant.constraints, grant.constraints))
                    return false;
            }
            else {
                if (parentAuthorityId === undefined)
                    return false;
                const parent = permissionRecord(draft, parentAuthorityId)?.grant;
                if (parent === undefined ||
                    parent.rootAuthorityId !== grant.rootAuthorityId ||
                    parent.granteeId !== grant.grantorId ||
                    !constraintsAreAttenuated(parent.constraints, grant.constraints))
                    return false;
            }
        }
    }
    const record = Object.freeze({
        grant,
        grantEventId: event.id,
        grantEventPosition: position,
    });
    mapSet(draft.authorities, grant.authorityId, record);
    if (grant.kind === "PERMISSION") {
        if (ownOptional(grant, "parentAuthorityId") === undefined &&
            grant.authorityId === grant.rootAuthorityId) {
            const principal = mapGet(draft.principals, grant.grantorId);
            if (principal !== undefined) {
                mapSet(draft.recognizedRoots, grant.rootAuthorityId, Object.freeze({
                    rootAuthorityId: grant.rootAuthorityId,
                    principalId: principal.id,
                    principalRecognitionEventId: principal.creationEventId,
                    rootGrantEventId: event.id,
                }));
            }
        }
        if (constraintOwn(grant.constraints, "maxTransactions") !== undefined ||
            constraintOwn(grant.constraints, "maxCumulativeAmount") !== undefined) {
            mapSet(draft.authorityUsage, grant.authorityId, Object.freeze({
                authorityId: grant.authorityId,
                admittedTransactionCount: 0,
                admittedCumulativeAmount: 0n,
            }));
        }
    }
    return true;
};
const applyAuthorityRevoked = (draft, event, data) => {
    const record = mapGet(draft.authorities, data.authorityId);
    if (record === undefined || ownOptional(record, "revocationEventId") !== undefined) {
        return false;
    }
    const grant = record.grant;
    let permitted = false;
    if (grant.kind === "PROHIBITION" && grant.scope === "GLOBAL") {
        permitted = data.revokerId === draft.genesis?.globalPolicySourceId;
    }
    else {
        const rootAuthorityId = grant.rootAuthorityId;
        const root = mapGet(draft.recognizedRoots, rootAuthorityId);
        if (root !== undefined) {
            const parentAuthorityId = ownOptional(grant, "parentAuthorityId");
            permitted = data.revokerId === root.principalId ||
                (parentAuthorityId !== undefined && data.revokerId === grant.grantorId);
        }
    }
    if (!permitted)
        return false;
    mapSet(draft.authorities, data.authorityId, Object.freeze({
        ...record,
        revocationEventId: event.id,
        revocationEventPosition: draft.acceptedEvents.length,
        revokerId: data.revokerId,
    }));
    return true;
};
const currentDraftHead = (draft) => {
    if (draft.acceptedEvents.length === 0)
        return undefined;
    const finalPosition = draft.acceptedEvents.length - 1;
    const finalEvent = draft.acceptedEvents[finalPosition];
    const hash = draft.eventHistoryHashes[finalPosition];
    if (hash === undefined) {
        throw new TypeError("Portable replay lost an event-history prefix hash.");
    }
    return Object.freeze({
        hash,
        position: finalPosition,
        canonicalTime: finalEvent.timestamp,
    });
};
const authorityStateForDraft = (draft) => {
    const head = currentDraftHead(draft);
    if (head === undefined || draft.genesis === undefined)
        return undefined;
    return Object.freeze({
        events: draft.acceptedEvents,
        eventHistoryHashes: draft.eventHistoryHashes,
        head,
        genesis: draft.genesis,
        principals: draft.principals,
        agents: draft.agents,
        roles: draft.roles,
        tenures: draft.tenures,
        runtimeSessions: draft.runtimeSessions,
        intentDeclarations: draft.intentDeclarations,
        intentAdmissions: draft.intentAdmissions,
        nonceReservationsByActor: draft.nonceReservationsByActor,
        authorities: draft.authorities,
        recognizedRoots: draft.recognizedRoots,
        authorityUsage: draft.authorityUsage,
    });
};
const applyTransactionIntentAdmitted = (draft, event, admissionHead) => {
    const state = authorityStateForDraft(draft);
    if (state === undefined)
        return false;
    const validation = validatePortableIntentAdmissionTransition(state, event);
    if (validation.status !== "VALID")
        return false;
    if (mapHas(draft.intentAdmissions, validation.intentId))
        return false;
    const existingActorReservations = mapGet(draft.nonceReservationsByActor, validation.actorId);
    if (existingActorReservations !== undefined &&
        mapHas(existingActorReservations, validation.nonce))
        return false;
    for (let index = 0; index < validation.usage.length; index += 1) {
        const update = validation.usage[index];
        if (!mapHas(draft.authorityUsage, update.authorityId))
            return false;
    }
    const admissionEventPosition = draft.acceptedEvents.length;
    const proof = event.data
        .authorizationProof;
    const runtimeSessionId = ownOptional(proof, "runtimeSessionId");
    const credentialKeyId = ownOptional(proof, "credentialKeyId");
    const controlEpoch = ownOptional(proof, "controlEpoch");
    const roleId = ownOptional(proof, "roleId");
    const roleTenureId = ownOptional(proof, "roleTenureId");
    if (runtimeSessionId === undefined ||
        credentialKeyId === undefined ||
        controlEpoch === undefined ||
        roleId === undefined ||
        roleTenureId === undefined)
        return false;
    const declaration = mapGet(draft.intentDeclarations, validation.intentId);
    if (declaration === undefined || draft.genesis === undefined)
        return false;
    const adapterIdentity = derivePortableAdapterIdentityForAcceptedAdmission(event, admissionHead, declaration.data.adapterProfile, draft.genesis.adapterPolicyHash);
    const admission = Object.freeze({
        intentId: validation.intentId,
        actorId: validation.actorId,
        nonce: validation.nonce,
        admissionEventId: event.id,
        admissionEventPosition,
        admissionHead,
        runtimeSessionId,
        credentialKeyId,
        controlEpoch,
        roleId,
        roleTenureId,
        adapterIdentity,
    });
    const reservation = Object.freeze({
        intentId: validation.intentId,
        admissionEventId: event.id,
        admissionEventPosition,
        admissionHead,
    });
    const actorReservations = existingActorReservations ??
        createMap();
    mapSet(draft.intentAdmissions, validation.intentId, admission);
    mapSet(actorReservations, validation.nonce, reservation);
    mapSet(draft.nonceReservationsByActor, validation.actorId, actorReservations);
    for (let index = 0; index < validation.usage.length; index += 1) {
        const update = validation.usage[index];
        mapSet(draft.authorityUsage, update.authorityId, update);
    }
    return true;
};
const admissionBoundControlTupleIsCurrent = (draft, admission, useTime) => admissionControlRecordsMatch(admission, useTime, activeAgent(draft, admission.actorId), mapGet(draft.runtimeSessions, admission.runtimeSessionId), mapGet(draft.roles, admission.roleId), mapGet(draft.tenures, admission.roleTenureId));
const admissionControlRecordsMatch = (admission, useTime, agent, session, role, tenure) => {
    const expiresAt = session === undefined
        ? undefined
        : ownOptional(session, "expiresAt");
    const currentTenureId = role === undefined
        ? undefined
        : ownOptional(role, "currentTenureId");
    return agent !== undefined &&
        !agent.terminated &&
        session !== undefined &&
        session.agentId === admission.actorId &&
        session.credentialKeyId === admission.credentialKeyId &&
        (expiresAt === undefined || useTime < expiresAt) &&
        session.controlEpoch === admission.controlEpoch &&
        agent.currentControlEpoch === admission.controlEpoch &&
        role !== undefined &&
        tenure !== undefined &&
        currentTenureId === admission.roleTenureId &&
        !tenure.closed &&
        tenure.roleId === admission.roleId &&
        tenure.agentId === admission.actorId;
};
/** @internal The reference integration uses the same predicate as consumption. */
export const portableAdmissionControlIsCurrent = (state, intentId, useTime) => {
    if (!isPortableReplayState(state))
        return false;
    const admission = state.intentAdmissions.get(intentId);
    if (admission === undefined)
        return false;
    return admissionControlRecordsMatch(admission, useTime, state.agents.get(admission.actorId), state.runtimeSessions.get(admission.runtimeSessionId), state.roles.get(admission.roleId), state.tenures.get(admission.roleTenureId));
};
const earlierEvidenceReferenceIsValid = (draft, evidence) => {
    switch (evidence.kind) {
        case "EVENT": {
            const position = mapGet(draft.eventPositionsById, evidence.eventId);
            const event = position === undefined
                ? undefined
                : draft.acceptedEvents[position];
            return position !== undefined &&
                event !== undefined &&
                evidence.position === position &&
                evidence.eventType === event.type &&
                evidence.historyHash === draft.eventHistoryHashes[position];
        }
        case "AUTHORITY": {
            const authority = mapGet(draft.authorities, evidence.authorityId);
            return authority !== undefined &&
                evidence.grantEventId === authority.grantEventId;
        }
        case "RUNTIME_CREDENTIAL": {
            const session = mapGet(draft.runtimeSessions, evidence.sessionId);
            return session !== undefined &&
                evidence.keyId === session.credentialKeyId &&
                evidence.admissionEventId === session.admissionEventId;
        }
        case "RECEIPT_COMMITMENT": {
            const receipt = mapGet(draft.receiptCommitments, evidence.receiptContentHash);
            return receipt !== undefined && receipt.eventId === evidence.eventId &&
                receipt.eventPosition === evidence.position;
        }
        case "EXTERNAL":
            return true;
    }
};
const applyTransactionIntentConsumed = (draft, event, nextHead) => {
    const data = event.data;
    const admission = mapGet(draft.intentAdmissions, data.intentId);
    const outcomeState = mapGet(draft.intentOutcomeStates, data.intentId);
    const terminal = outcomeState === undefined
        ? undefined
        : ownOptional(outcomeState, "terminal");
    if (admission === undefined ||
        mapHas(draft.intentConsumptions, data.intentId) ||
        terminal !== undefined ||
        !admissionBoundControlTupleIsCurrent(draft, admission, event.timestamp) ||
        data.adapterId !== admission.adapterIdentity.adapterProfile.profileId ||
        data.idempotencyKey !== admission.adapterIdentity.idempotencyKey ||
        data.submissionFingerprint !==
            admission.adapterIdentity.submissionFingerprint)
        return false;
    const transactionReference = data.transactionReference;
    if (!validatePortableAdapterAcknowledgment(data.acknowledgment, admission.adapterIdentity))
        return false;
    const acknowledgedReference = portableAdapterAcknowledgmentTransactionReference(data.acknowledgment, admission.adapterIdentity);
    if (transactionReference !== acknowledgedReference)
        return false;
    const expectedEvidence = portableAdapterAcknowledgmentEvidence(admission.adapterIdentity, data.acknowledgment);
    if (!samePortableAdapterEvidence(data.evidenceReference, expectedEvidence))
        return false;
    const record = Object.freeze({
        intentId: data.intentId,
        eventId: event.id,
        eventPosition: draft.acceptedEvents.length,
        head: nextHead,
        adapterId: admission.adapterIdentity.adapterProfile.profileId,
        idempotencyKey: data.idempotencyKey,
        submissionFingerprint: data.submissionFingerprint,
        transactionReference,
        acknowledgment: data.acknowledgment,
        evidenceReference: data.evidenceReference,
    });
    mapSet(draft.intentConsumptions, data.intentId, record);
    return true;
};
const applyTransactionOutcomeRecorded = (draft, event, nextHead) => {
    const data = event.data;
    const admission = mapGet(draft.intentAdmissions, data.intentId);
    if (admission === undefined)
        return false;
    const existing = mapGet(draft.intentOutcomeStates, data.intentId);
    const existingTerminal = existing === undefined
        ? undefined
        : ownOptional(existing, "terminal");
    if (existingTerminal !== undefined && data.status !== "DISPUTED") {
        return false;
    }
    const noEffect = ownOptional(data, "noEffect");
    if (data.status === "FAILED") {
        if (noEffect === undefined || data.attesterId !== SIMULATED_ADAPTER_ID ||
            !validatePortableAdapterNoEffect(noEffect, admission.adapterIdentity) ||
            !samePortableAdapterEvidence(data.evidenceReference, portableAdapterNoEffectEvidence(admission.adapterIdentity, noEffect)))
            return false;
    }
    else if (noEffect !== undefined || !earlierEvidenceReferenceIsValid(draft, data.evidenceReference)) {
        return false;
    }
    const record = Object.freeze({
        intentId: data.intentId,
        eventId: event.id,
        eventPosition: draft.acceptedEvents.length,
        head: nextHead,
        status: data.status,
        attesterId: data.attesterId,
        evidenceReference: data.evidenceReference,
        ...(noEffect === undefined ? {} : { noEffect }),
    });
    const terminal = existingTerminal ??
        (data.status === "CONFIRMED" || data.status === "FAILED"
            ? record
            : undefined);
    const outcomeState = Object.freeze({
        latest: record,
        ...(terminal === undefined ? {} : { terminal }),
    });
    mapSet(draft.intentOutcomeStates, data.intentId, outcomeState);
    return true;
};
const applyReceiptRecorded = (draft, event, head) => {
    const data = event.data;
    // Section 5.4 rule 11 intentionally imposes typed existence only. In
    // particular no issuer/control/admission/artifact congruence is inferred.
    if (mapHas(draft.receiptCommitments, data.receiptContentHash) ||
        !mapHas(draft.intentDeclarations, data.intentId) ||
        !mapHas(draft.agents, data.issuerAgentId) ||
        !mapHas(draft.runtimeSessions, data.runtimeSessionId) ||
        !mapHas(draft.roles, data.roleId) ||
        !mapHas(draft.tenures, data.roleTenureId))
        return false;
    mapSet(draft.receiptCommitments, data.receiptContentHash, Object.freeze({
        ...data,
        eventId: event.id,
        eventPosition: draft.acceptedEvents.length,
        head,
    }));
    return true;
};
const obligationStatusRank = (status) => {
    switch (status) {
        case "OPEN": return 0;
        case "OUTCOME_UNKNOWN": return 1;
        case "DISPUTED": return 2;
        case "DISCHARGED": return 3;
        case "IMPOSSIBLE_OR_ESCALATED": return 4;
    }
};
const obligationIsUnresolved = (status) => status !== "DISCHARGED" && status !== "IMPOSSIBLE_OR_ESCALATED";
const identifiersAreStrictlySorted = (ids) => {
    if (ids.length === 0)
        return false;
    for (let index = 1; index < ids.length; index += 1) {
        if (compareProtocolStrings(ids[index - 1], ids[index]) >= 0)
            return false;
    }
    return true;
};
const obligationPoliciesAreValid = (draft, policies) => {
    if (policies.length === 0)
        return false;
    for (let index = 0; index < policies.length; index += 1) {
        const policy = policies[index];
        if (!obligationIsUnresolved(policy.fromStatus) ||
            !identifiersAreStrictlySorted(policy.acceptedAttesterIds) ||
            !identifiersAreStrictlySorted(policy.requiredAuthorityIds))
            return false;
        for (let idIndex = 0; idIndex < policy.requiredAuthorityIds.length; idIndex += 1) {
            if (!mapHas(draft.authorities, policy.requiredAuthorityIds[idIndex])) {
                return false;
            }
        }
        if (index === 0)
            continue;
        const prior = policies[index - 1];
        const fromDifference = obligationStatusRank(policy.fromStatus) -
            obligationStatusRank(prior.fromStatus);
        const toDifference = obligationStatusRank(policy.toStatus) -
            obligationStatusRank(prior.toStatus);
        if (fromDifference < 0 ||
            (fromDifference === 0 && toDifference <= 0))
            return false;
        // Duplicate (from,to) pairs are already a schema failure. For distinct
        // pairs the status ranks completely determine the declared tuple order.
    }
    return true;
};
// An observation authenticates the present recorder, not the provider or the
// truth of an external effect. These reducers cannot consume an intent.
const attemptSource = (draft, intentId) => {
    if (draft.genesis?.adapterPolicyHash !== PORTABLE_ADAPTER_POLICY_E5_HASH &&
        draft.genesis?.adapterPolicyHash !== PORTABLE_ADAPTER_POLICY_E6_HASH)
        return undefined;
    const intent = mapGet(draft.intentDeclarations, intentId)?.data;
    const admission = mapGet(draft.intentAdmissions, intentId);
    if (intent === undefined || admission === undefined ||
        admission.adapterIdentity.adapterProfile.profileId !== REMOTE_SERVICE_REPORT_ADAPTER_ID)
        return undefined;
    const role = mapGet(draft.roles, intent.roleId);
    const tenure = role?.currentTenureId === undefined ? undefined : mapGet(draft.tenures, role.currentTenureId);
    if (role === undefined || tenure === undefined || tenure.closed ||
        activeAgent(draft, tenure.agentId) === undefined)
        return undefined;
    return { intent, admission, role, tenure };
};
const authorizeAttemptRecord = (draft, event, actorId, source, action) => {
    if (actorId !== source.tenure.agentId)
        return false;
    const state = authorityStateForDraft(draft);
    const termsCommitment = ownOptional(source.intent, "termsCommitment");
    return state !== undefined && validatePortableAdministrativeTransition(state, event, {
        request: { actorId, action, resource: source.intent.intentId, claimedAt: event.timestamp,
            ...(termsCommitment === undefined ? {} : { termsCommitment }) },
        requiredPrincipalId: source.role.principalId, requiredAuthorityIds: [],
        roleId: source.role.id, roleTenureId: source.tenure.id,
    });
};
const applyOutcomeObservationRecorded = (draft, event) => {
    const data = event.data;
    const source = attemptSource(draft, data.intentId);
    if (source === undefined || source.admission.admissionEventId !== data.sourceAdmissionEventId ||
        !validatePortableAdapterAcknowledgment(data.acknowledgment, source.admission.adapterIdentity) ||
        data.acknowledgment.result.kind !== "REMOTE_SERVICE_REPORTED" ||
        !authorizeAttemptRecord(draft, event, data.actorId, source, "OBSERVE_OUTCOME"))
        return false;
    const observation = Object.freeze({
        intentId: data.intentId, sourceAdmissionEventId: data.sourceAdmissionEventId,
        acknowledgment: data.acknowledgment, actorId: data.actorId, eventId: event.id,
        eventPosition: draft.acceptedEvents.length, observedAt: event.timestamp,
    });
    const observations = copyArray(mapGet(draft.outcomeObservations, data.intentId) ?? []);
    arrayPush(observations, observation);
    mapSet(draft.outcomeObservations, data.intentId, Object.freeze(observations));
    return true;
};
const applyAttemptDutyCreated = (draft, event) => {
    const data = event.data;
    const record = data.record, source = attemptSource(draft, record.sourceIntentId);
    if (source === undefined || record.sourceAdmissionEventId !== source.admission.admissionEventId ||
        record.durableRoleId !== source.role.id || record.creationRoleTenureId !== source.tenure.id ||
        record.performanceAssigneeId !== source.tenure.agentId || record.status !== "OPEN" ||
        mapHas(draft.attemptDuties, record.dutyId) || mapHas(draft.obligations, record.dutyId) ||
        mapHas(draft.attemptDutyIdsBySourceIntent, record.sourceIntentId) ||
        !authorizeAttemptRecord(draft, event, data.actorId, source, "CREATE_ATTEMPT_DUTY"))
        return false;
    mapSet(draft.attemptDuties, record.dutyId, Object.freeze({ record, creationEventId: event.id,
        creationEventPosition: draft.acceptedEvents.length, creationActorId: data.actorId,
        currentAssigneeId: record.performanceAssigneeId, assignments: Object.freeze([]) }));
    mapSet(draft.attemptDutyIdsBySourceIntent, record.sourceIntentId, record.dutyId);
    return true;
};
const applyAttemptDutyPolicyActivated = (draft, event) => {
    const authorityState = authorityStateForDraft(draft);
    if (!authorityState)
        return false;
    const data = event.data;
    const state = { ...authorityState, attemptDuties: draft.attemptDuties, attemptDutyPolicies: draft.attemptDutyPolicies };
    const requirements = portableDutyPolicyActivationRequirements(state, data, event.timestamp);
    if (!requirements || !validatePortableAdministrativeTransition(authorityState, event, requirements) ||
        !portableDutyPolicyActivationProofMatches(data.administrativeAuthorization.authorityProof, data.activationAuthorityId))
        return false;
    mapSet(draft.attemptDutyPolicies, data.descriptor.dutyId, Object.freeze({
        descriptor: data.descriptor, descriptorHash: data.descriptorHash, activationAuthorityId: data.activationAuthorityId,
        actorId: data.actorId, eventId: event.id, eventPosition: draft.acceptedEvents.length, activatedAt: event.timestamp,
        priorHead: authorityState.head, dispositionCount: 0, contestCount: 0,
    }));
    return true;
};
const applyAttemptDutyReviewClosed = (draft, event) => {
    if (draft.genesis?.adapterPolicyHash !== PORTABLE_ADAPTER_POLICY_E6_HASH)
        return false;
    const data = event.data;
    const duty = mapGet(draft.attemptDuties, data.dutyId);
    if (duty === undefined || duty.currentAssigneeId !== data.actorId)
        return false;
    const source = attemptSource(draft, duty.record.sourceIntentId);
    const observations = mapGet(draft.outcomeObservations, duty.record.sourceIntentId) ?? [];
    if (source === undefined || observations.length !== data.observationEventIds.length ||
        (data.observationEventIds.length > 0 && !identifiersAreStrictlySorted(data.observationEventIds)) ||
        !authorizeAttemptRecord(draft, event, data.actorId, source, "CLOSE_ATTEMPT_DUTY"))
        return false;
    for (let index = 0; index < observations.length; index += 1) {
        if (!arrayIncludes(data.observationEventIds, observations[index].eventId))
            return false;
    }
    const reviews = copyArray(mapGet(draft.attemptDutyReviews, data.dutyId) ?? []);
    arrayPush(reviews, Object.freeze({ dutyId: data.dutyId, actorId: data.actorId,
        observationEventIds: data.observationEventIds, summaryDigest: data.summaryDigest,
        eventId: event.id, eventPosition: draft.acceptedEvents.length, reviewedAt: event.timestamp }));
    mapSet(draft.attemptDutyReviews, data.dutyId, Object.freeze(reviews));
    return true;
};
const applyAttemptDutyAssigned = (draft, event) => {
    const data = event.data;
    const duty = mapGet(draft.attemptDuties, data.dutyId);
    if (duty === undefined)
        return false;
    const source = attemptSource(draft, duty.record.sourceIntentId);
    if (source === undefined || data.fromAgentId !== duty.currentAssigneeId ||
        data.toAgentId === data.fromAgentId || data.toAgentId !== source.tenure.agentId ||
        !authorizeAttemptRecord(draft, event, data.actorId, source, "ASSIGN_ATTEMPT_DUTY"))
        return false;
    const assignments = copyArray(duty.assignments);
    arrayPush(assignments, Object.freeze({ fromAgentId: data.fromAgentId, toAgentId: data.toAgentId,
        actorId: data.actorId, eventId: event.id, eventPosition: draft.acceptedEvents.length, assignedAt: event.timestamp }));
    mapSet(draft.attemptDuties, data.dutyId, Object.freeze({ ...duty,
        currentAssigneeId: data.toAgentId, assignments: Object.freeze(assignments) }));
    return true;
};
const applyObligationCreated = (draft, event, creationHead) => {
    const data = event.data;
    const record = data.record;
    const intent = mapGet(draft.intentDeclarations, record.sourceIntentId)?.data;
    const admission = mapGet(draft.intentAdmissions, record.sourceIntentId);
    const consumption = mapGet(draft.intentConsumptions, record.sourceIntentId);
    const receipt = mapGet(draft.receiptCommitments, record.causalReceiptContentHash);
    const role = mapGet(draft.roles, record.durableRoleId);
    const tenure = mapGet(draft.tenures, record.creationRoleTenureId);
    const rule = mapGet(draft.successionRules, record.successionRuleId)?.data;
    if (mapHas(draft.obligations, record.obligationId) ||
        mapHas(draft.attemptDuties, record.obligationId) ||
        mapHas(draft.obligationIdsBySourceIntent, record.sourceIntentId) ||
        intent === undefined || admission === undefined || consumption === undefined ||
        receipt === undefined || role === undefined || tenure === undefined ||
        rule === undefined ||
        intent.intentId !== admission.intentId ||
        intent.intentId !== consumption.intentId || intent.intentId !== receipt.intentId ||
        !(admission.admissionEventPosition < consumption.eventPosition &&
            consumption.eventPosition < receipt.eventPosition &&
            receipt.eventPosition < draft.acceptedEvents.length) ||
        record.trigger !== consumption.eventId ||
        record.durableRoleId !== intent.roleId || record.durableRoleId !== receipt.roleId ||
        record.creationRoleTenureId !== intent.roleTenureId ||
        record.creationRoleTenureId !== receipt.roleTenureId ||
        ownOptional(role, "currentTenureId") !== tenure.id || tenure.closed ||
        tenure.roleId !== record.durableRoleId ||
        record.performanceAssigneeId !== intent.actorId ||
        tenure.agentId !== record.performanceAssigneeId ||
        data.actorId !== record.performanceAssigneeId ||
        ownOptional(intent, "termsCommitment") !== record.termsCommitment ||
        objectHasOwn(intent, "counterpartyId") !== objectHasOwn(record, "counterpartyId") ||
        ownOptional(intent, "counterpartyId") !== ownOptional(record, "counterpartyId") ||
        rule.roleId !== record.durableRoleId ||
        rule.predecessorAgentId !== record.performanceAssigneeId ||
        rule.principalId !== role.principalId || rule.trigger !== "AGENT_TERMINATED" ||
        !arrayIncludes(rule.permittedEventTypes, "AGENT_TERMINATED") ||
        !arrayIncludes(rule.permittedEventTypes, "ROLE_TRANSFERRED") ||
        !arrayIncludes(rule.permittedEventTypes, "OBLIGATION_PERFORMANCE_ASSIGNED") ||
        !obligationPoliciesAreValid(draft, record.transitionPolicies))
        return false;
    let declarationPosition;
    for (let position = 0; position < admission.admissionEventPosition; position += 1) {
        const earlier = draft.acceptedEvents[position];
        if (earlier.type === "TRANSACTION_INTENT_DECLARED" &&
            earlier.data.intentId === intent.intentId) {
            declarationPosition = position;
            break;
        }
    }
    if (declarationPosition === undefined)
        return false;
    const admissionEvent = draft.acceptedEvents[admission.admissionEventPosition];
    const proof = admissionEvent.data
        .authorizationProof;
    if (receipt.authorizationProofHash !== hashCanonical(proof) ||
        receipt.issuerAgentId !== proof.request.actorId ||
        receipt.runtimeSessionId !== ownOptional(proof, "runtimeSessionId") ||
        receipt.controlEpoch !== ownOptional(proof, "controlEpoch") ||
        receipt.roleId !== ownOptional(proof, "roleId") ||
        receipt.roleTenureId !== ownOptional(proof, "roleTenureId"))
        return false;
    const state = authorityStateForDraft(draft);
    const counterpartyId = ownOptional(record, "counterpartyId");
    if (state === undefined || !validatePortableAdministrativeTransition(state, event, {
        request: {
            actorId: data.actorId,
            action: "OBLIGATE",
            resource: intent.resource,
            claimedAt: event.timestamp,
            termsCommitment: record.termsCommitment,
            ...(counterpartyId === undefined ? {} : { counterpartyId }),
        },
        requiredPrincipalId: role.principalId,
        requiredAuthorityIds: [],
        roleId: role.id,
        roleTenureId: tenure.id,
    }))
        return false;
    mapSet(draft.obligations, record.obligationId, Object.freeze({
        record,
        status: record.status,
        performanceAssigneeId: record.performanceAssigneeId,
        creationEventId: event.id,
        creationEventPosition: draft.acceptedEvents.length,
        creationHead,
    }));
    mapSet(draft.obligationIdsBySourceIntent, record.sourceIntentId, record.obligationId);
    return true;
};
const applyObligationPerformanceAssigned = (draft, event) => {
    const data = event.data;
    const obligation = mapGet(draft.obligations, data.obligationId);
    if (obligation === undefined || !obligationIsUnresolved(obligation.status) ||
        data.fromAgentId !== obligation.performanceAssigneeId ||
        data.successionRuleId !== obligation.record.successionRuleId)
        return false;
    const record = obligation.record;
    const role = mapGet(draft.roles, record.durableRoleId);
    const rule = mapGet(draft.successionRules, data.successionRuleId)?.data;
    const currentTenureId = role === undefined ? undefined : ownOptional(role, "currentTenureId");
    const tenure = currentTenureId === undefined ? undefined : mapGet(draft.tenures, currentTenureId);
    if (role === undefined || rule === undefined || tenure === undefined || tenure.closed ||
        tenure.agentId !== data.toAgentId || tenure.roleId !== record.durableRoleId ||
        rule.roleId !== record.durableRoleId || rule.principalId !== role.principalId ||
        rule.predecessorAgentId !== data.fromAgentId || rule.successorAgentId !== data.toAgentId ||
        rule.trigger !== "AGENT_TERMINATED" ||
        !arrayIncludes(rule.permittedEventTypes, "OBLIGATION_PERFORMANCE_ASSIGNED"))
        return false;
    let terminationPosition;
    let transferPosition;
    for (let position = 0; position < draft.acceptedEvents.length; position += 1) {
        const earlier = draft.acceptedEvents[position];
        if (earlier.type === "AGENT_TERMINATED") {
            const terminated = earlier.data;
            if (terminated.agentId === data.fromAgentId &&
                terminated.principalId === rule.principalId &&
                terminated.successionRuleId === data.successionRuleId &&
                terminated.roleId === record.durableRoleId &&
                terminated.roleTenureId === record.creationRoleTenureId) {
                terminationPosition = position;
            }
        }
        else if (earlier.type === "ROLE_TRANSFERRED") {
            const transferred = earlier.data;
            if (transferred.transferKind === "SUCCESSION" &&
                ownOptional(transferred, "successionRuleId") === data.successionRuleId &&
                transferred.principalId === rule.principalId &&
                transferred.roleId === record.durableRoleId &&
                transferred.fromAgentId === data.fromAgentId &&
                transferred.fromRoleTenureId === record.creationRoleTenureId &&
                transferred.toAgentId === data.toAgentId &&
                transferred.toRoleTenureId === tenure.id)
                transferPosition = position;
        }
    }
    if (terminationPosition === undefined || transferPosition === undefined ||
        terminationPosition >= transferPosition)
        return false;
    const state = authorityStateForDraft(draft);
    if (state === undefined || !validatePortableAdministrativeTransition(state, event, {
        request: {
            actorId: data.actorId, action: "ASSIGN_PERFORMANCE",
            resource: data.obligationId, claimedAt: event.timestamp,
        },
        requiredPrincipalId: rule.principalId,
        requiredAuthorityIds: [],
        roleId: role.id,
        roleTenureId: tenure.id,
    }))
        return false;
    mapSet(draft.obligations, data.obligationId, Object.freeze({
        ...obligation,
        performanceAssigneeId: data.toAgentId,
    }));
    return true;
};
const obligationEvidenceAttributesAttester = (draft, evidence, attesterId) => {
    if (evidence.kind === "EXTERNAL")
        return evidence.attesterId === attesterId;
    if (evidence.kind !== "EVENT" || !earlierEvidenceReferenceIsValid(draft, evidence)) {
        return false;
    }
    const target = draft.acceptedEvents[evidence.position];
    const data = target.data;
    if (ownOptional(data, "attesterId") === attesterId)
        return true;
    const directEvidence = ownOptional(data, "evidenceReference");
    return directEvidence !== undefined && directEvidence.kind === "EXTERNAL" &&
        directEvidence.attesterId === attesterId;
};
const applyObligationStatusRecorded = (draft, event) => {
    const data = event.data;
    const obligation = mapGet(draft.obligations, data.obligationId);
    if (obligation === undefined || !obligationIsUnresolved(obligation.status) ||
        data.fromStatus !== obligation.status)
        return false;
    let policy;
    for (let index = 0; index < obligation.record.transitionPolicies.length; index += 1) {
        const candidate = obligation.record.transitionPolicies[index];
        if (candidate.fromStatus === data.fromStatus && candidate.toStatus === data.toStatus &&
            candidate.action === data.action) {
            policy = candidate;
            break;
        }
    }
    if (policy === undefined || !arrayIncludes(policy.acceptedAttesterIds, data.attesterId) ||
        !obligationEvidenceAttributesAttester(draft, data.evidenceReference, data.attesterId)) {
        return false;
    }
    const role = mapGet(draft.roles, obligation.record.durableRoleId);
    const currentTenureId = role === undefined ? undefined : ownOptional(role, "currentTenureId");
    const state = authorityStateForDraft(draft);
    if (role === undefined || currentTenureId === undefined || state === undefined ||
        !validatePortableAdministrativeTransition(state, event, {
            request: {
                actorId: data.actorId, action: data.action,
                resource: data.obligationId, claimedAt: event.timestamp,
            },
            requiredPrincipalId: role.principalId,
            requiredAuthorityIds: policy.requiredAuthorityIds,
            roleId: role.id,
            roleTenureId: currentTenureId,
        }))
        return false;
    mapSet(draft.obligations, data.obligationId, Object.freeze({
        ...obligation,
        status: data.toStatus,
    }));
    return true;
};
const applyTransition = (draft, event, nextHead) => {
    switch (event.type) {
        case "DEPLOYMENT_INITIALIZED":
            if (draft.acceptedEvents.length !== 0 || draft.genesis !== undefined) {
                return false;
            }
            if (resolvePortableAdapterPolicy(event.data.adapterPolicyHash) === undefined)
                return false;
            draft.genesis = event.data;
            return true;
        case "PRINCIPAL_CREATED":
            return applyPrincipalCreated(draft, event.data, event.id, draft.acceptedEvents.length);
        case "AGENT_CREATED":
            return applyAgentCreated(draft, event.data);
        case "ROLE_CREATED":
            return applyRoleCreated(draft, event.data);
        case "SUCCESSION_RULE_DECLARED":
            return applySuccessionRuleDeclared(draft, event.data);
        case "AGENT_APPOINTED":
            return applyAgentAppointed(draft, event.data);
        case "AGENT_UNAPPOINTED":
            return applyAgentUnappointed(draft, event.data);
        case "ROLE_TRANSFERRED":
            return applyRoleTransferred(draft, event.data);
        case "RUNTIME_SESSION_ADMITTED":
            return applyRuntimeSessionAdmitted(draft, event, event.data);
        case "CONTROL_EPOCH_ADVANCED":
            return applyControlEpochAdvanced(draft, event.data);
        case "TRANSACTION_INTENT_DECLARED":
            return applyTransactionIntentDeclared(draft, event.data);
        case "AGENT_TERMINATED":
            return applyAgentTerminated(draft, event.data);
        case "AUTHORITY_GRANTED":
            return applyAuthorityGranted(draft, event, event.data);
        case "AUTHORITY_REVOKED":
            return applyAuthorityRevoked(draft, event, event.data);
        case "TRANSACTION_INTENT_ADMITTED":
            return applyTransactionIntentAdmitted(draft, event, nextHead);
        case "TRANSACTION_INTENT_CONSUMED":
            return applyTransactionIntentConsumed(draft, event, nextHead);
        case "TRANSACTION_OUTCOME_RECORDED":
            return applyTransactionOutcomeRecorded(draft, event, nextHead);
        case "RECEIPT_RECORDED":
            return applyReceiptRecorded(draft, event, nextHead);
        case "OUTCOME_OBSERVATION_RECORDED":
            return applyOutcomeObservationRecorded(draft, event);
        case "ATTEMPT_DUTY_CREATED":
            return applyAttemptDutyCreated(draft, event);
        case "ATTEMPT_DUTY_ASSIGNED":
            return applyAttemptDutyAssigned(draft, event);
        case "ATTEMPT_DUTY_REVIEW_CLOSED":
            return applyAttemptDutyReviewClosed(draft, event);
        case "ATTEMPT_DUTY_POLICY_ACTIVATED":
            return applyAttemptDutyPolicyActivated(draft, event);
        case "OBLIGATION_CREATED":
            return applyObligationCreated(draft, event, nextHead);
        case "OBLIGATION_PERFORMANCE_ASSIGNED":
            return applyObligationPerformanceAssigned(draft, event);
        case "OBLIGATION_STATUS_RECORDED":
            return applyObligationStatusRecorded(draft, event);
    }
};
const mapOfFrozenArrays = (source) => {
    const result = createMap();
    mapForEach(source, (values, key) => {
        mapSet(result, key, Object.freeze(setToArray(values)));
    });
    return result;
};
const detachedMapView = (snapshot) => Object.freeze(copyMap(snapshot));
const detachedNestedMapView = (snapshot) => {
    const result = createMap();
    mapForEach(snapshot, (nested, key) => {
        mapSet(result, key, Object.freeze(copyMap(nested)));
    });
    return Object.freeze(result);
};
const freezeState = (draft, head) => {
    if (draft.genesis === undefined) {
        throw new TypeError("Portable replay cannot freeze state without genesis.");
    }
    const principals = copyMap(draft.principals);
    const agents = copyMap(draft.agents);
    const reservedAgentIds = mapOfFrozenArrays(draft.reservedAgentIds);
    const roles = copyMap(draft.roles);
    const successionRules = copyMap(draft.successionRules);
    const tenures = copyMap(draft.tenures);
    const runtimeSessions = copyMap(draft.runtimeSessions);
    const intentDeclarations = copyMap(draft.intentDeclarations);
    const intentAdmissions = copyMap(draft.intentAdmissions);
    const intentConsumptions = copyMap(draft.intentConsumptions);
    const intentOutcomeStates = copyMap(draft.intentOutcomeStates);
    const outcomeObservations = copyMap(draft.outcomeObservations);
    const attemptDuties = copyMap(draft.attemptDuties);
    const attemptDutyReviews = copyMap(draft.attemptDutyReviews);
    const attemptDutyPolicies = copyMap(draft.attemptDutyPolicies);
    const receiptCommitments = copyMap(draft.receiptCommitments);
    const obligations = copyMap(draft.obligations);
    const nonceReservationsByActor = createMap();
    mapForEach(draft.nonceReservationsByActor, (reservations, actorId) => {
        mapSet(nonceReservationsByActor, actorId, copyMap(reservations));
    });
    const authorities = copyMap(draft.authorities);
    const recognizedRoots = copyMap(draft.recognizedRoots);
    const authorityUsage = copyMap(draft.authorityUsage);
    // Freezing a Map does not freeze its entry slots. Keep the reducer snapshots
    // closure-private and expose a fresh detached Map for every inspection.
    const state = {
        [portableReplayStateBrand]: true,
        events: Object.freeze(copyArray(draft.acceptedEvents)),
        eventHistoryHashes: Object.freeze(copyArray(draft.eventHistoryHashes)),
        head,
        genesis: draft.genesis,
        get principals() {
            return detachedMapView(principals);
        },
        get agents() {
            return detachedMapView(agents);
        },
        get reservedAgentIds() {
            return detachedMapView(reservedAgentIds);
        },
        get roles() {
            return detachedMapView(roles);
        },
        get successionRules() {
            return detachedMapView(successionRules);
        },
        get tenures() {
            return detachedMapView(tenures);
        },
        get runtimeSessions() {
            return detachedMapView(runtimeSessions);
        },
        get intentDeclarations() {
            return detachedMapView(intentDeclarations);
        },
        get intentAdmissions() {
            return detachedMapView(intentAdmissions);
        },
        get intentConsumptions() {
            return detachedMapView(intentConsumptions);
        },
        get intentOutcomeStates() {
            return detachedMapView(intentOutcomeStates);
        },
        get outcomeObservations() { return detachedMapView(outcomeObservations); },
        get attemptDuties() { return detachedMapView(attemptDuties); },
        get attemptDutyReviews() { return detachedMapView(attemptDutyReviews); },
        get receiptCommitments() {
            return detachedMapView(receiptCommitments);
        },
        get obligations() {
            return detachedMapView(obligations);
        },
        get nonceReservationsByActor() {
            return detachedNestedMapView(nonceReservationsByActor);
        },
        get authorities() {
            return detachedMapView(authorities);
        },
        get recognizedRoots() {
            return detachedMapView(recognizedRoots);
        },
        get authorityUsage() {
            return detachedMapView(authorityUsage);
        },
    };
    // An unactivated state retains the previous enumerable snapshot vocabulary.
    objectDefineProperty(state, "attemptDutyPolicies", {
        enumerable: attemptDutyPolicies.size > 0, configurable: false,
        get: () => detachedMapView(attemptDutyPolicies),
    });
    Object.freeze(state);
    weakSetAdd(PORTABLE_REPLAY_STATES, state);
    return state;
};
const eventFailure = (code, baseEvent) => reject(code, baseEvent.eventPosition, baseEvent.event.id);
const prepareEventHistoryCommitment = (draft, event) => {
    const continuing = cloneKeccak256State(draft.historyHashState);
    if (draft.acceptedEvents.length > 0) {
        updateKeccak256State(continuing, EVENT_HISTORY_CANONICAL_SEPARATOR);
    }
    updateKeccak256State(continuing, UTF8_ENCODER.encode(canonicalEncode(event)));
    const finalizable = cloneKeccak256State(continuing);
    updateKeccak256State(finalizable, EVENT_HISTORY_CANONICAL_SUFFIX);
    const hash = finalizeKeccak256State(finalizable);
    return Object.freeze({
        continuing,
        head: Object.freeze({
            hash,
            position: draft.acceptedEvents.length,
            canonicalTime: event.timestamp,
        }),
    });
};
const reduceCapturedEvent = (draft, capturedEvent) => {
    const baseResult = validateIncrementallyCapturedReplayBaseEvent(capturedEvent);
    if (!baseResult.ok) {
        return reject("INVALID_INPUT", capturedEvent.eventPosition);
    }
    const baseEvent = baseResult.baseEvent;
    const position = baseEvent.eventPosition;
    if (position === 0) {
        if (baseEvent.event.type !== "DEPLOYMENT_INITIALIZED") {
            return eventFailure("GENESIS_REQUIRED", baseEvent);
        }
        const genesisProbe = validateCapturedGenesisVersionProbe(baseEvent);
        if (!genesisProbe.ok) {
            return eventFailure(isCoreSchemaLimitFailure(genesisProbe)
                ? "INVALID_INPUT"
                : "EVENT_DATA_INVALID", baseEvent);
        }
        if (genesisProbe.versions.eventSchemaVersion !== EVENT_SCHEMA_VERSION) {
            return eventFailure("UNSUPPORTED_EVENT_SCHEMA", baseEvent);
        }
        if (genesisProbe.versions.receiptSchemaVersion !== RECEIPT_SCHEMA_VERSION ||
            genesisProbe.versions.queryEnvelopeVersion !== QUERY_ENVELOPE_VERSION ||
            genesisProbe.versions.authorizationProofVersion !==
                AUTHORIZATION_PROOF_VERSION ||
            genesisProbe.versions.runtimeAuthorizationVersion !==
                RUNTIME_AUTHORIZATION_VERSION ||
            genesisProbe.versions.administrativeAuthorizationVersion !==
                ADMINISTRATIVE_AUTHORIZATION_VERSION ||
            genesisProbe.versions.signatureScheme !== SIGNATURE_SCHEME) {
            return eventFailure("UNSUPPORTED_VERSION", baseEvent);
        }
    }
    const refined = refineCapturedCoreEvent(baseEvent);
    if (!refined.ok) {
        return eventFailure(isCoreSchemaLimitFailure(refined)
            ? "INVALID_INPUT"
            : refined.code === "EVENT_TYPE_UNSUPPORTED"
                ? "UNSUPPORTED_EVENT_TYPE"
                : refined.code === "EVENT_DATA_INVALID"
                    ? "EVENT_DATA_INVALID"
                    : "INVALID_INPUT", baseEvent);
    }
    const event = refined.event;
    if (position > 0 && event.type === "DEPLOYMENT_INITIALIZED") {
        return eventFailure("GENESIS_DUPLICATE", baseEvent);
    }
    if (mapHas(draft.eventPositionsById, event.id)) {
        return eventFailure("EVENT_ID_DUPLICATE", baseEvent);
    }
    if (draft.lastTimestamp !== undefined &&
        event.timestamp < draft.lastTimestamp) {
        return eventFailure("EVENT_TIME_REGRESSION", baseEvent);
    }
    const commitment = prepareEventHistoryCommitment(draft, event);
    if (!applyTransition(draft, event, commitment.head)) {
        return eventFailure("TRANSITION_INVALID", baseEvent);
    }
    draft.historyHashState = commitment.continuing;
    arrayPush(draft.acceptedEvents, event);
    arrayPush(draft.eventHistoryHashes, commitment.head.hash);
    mapSet(draft.eventPositionsById, event.id, position);
    draft.lastTimestamp = event.timestamp;
    return undefined;
};
const finishDraft = (draft) => {
    if (draft.acceptedEvents.length === 0) {
        return Object.freeze({ result: reject("GENESIS_REQUIRED") });
    }
    const head = currentDraftHead(draft);
    if (head === undefined) {
        throw new TypeError("Portable replay lost its final history head.");
    }
    const state = freezeState(draft, head);
    if (!weakSetHas(PORTABLE_REPLAY_STATES, state)) {
        throw new TypeError("Portable replay lost reconstructed-state provenance.");
    }
    return Object.freeze({ state });
};
const PORTABLE_REPLAY_KERNELS = createWeakSet();
/** Package-internal provenance check for the replay-derived authority state. */
export const isPortableReplayState = (value) => value !== null &&
    typeof value === "object" &&
    weakSetHas(PORTABLE_REPLAY_STATES, value);
/**
 * @internal Reducer for an event list captured as part of a larger operation.
 * It never stops structural capture: the first semantic replay failure is
 * retained while the canonical layer finishes observing the complete input.
 */
export const createPortableReplayKernel = () => {
    const draft = newDraft();
    let failure;
    let completed;
    const kernel = Object.freeze({
        visit(capturedEvent) {
            if (completed !== undefined) {
                throw new TypeError("Portable replay kernel is already complete.");
            }
            if (failure === undefined) {
                failure = reduceCapturedEvent(draft, capturedEvent);
            }
            return Object.freeze({ status: "CONTINUE" });
        },
        finish() {
            if (completed !== undefined)
                return completed;
            if (failure !== undefined) {
                completed = Object.freeze({ status: "REJECTED", result: failure });
                return completed;
            }
            const final = finishDraft(draft);
            completed = "state" in final
                ? Object.freeze({ status: "ACCEPTED", state: final.state })
                : Object.freeze({ status: "REJECTED", result: final.result });
            return completed;
        },
    });
    weakSetAdd(PORTABLE_REPLAY_KERNELS, kernel);
    return kernel;
};
/**
 * Common Core 0.2 replay for lifecycle, Runtime control, authority, intent,
 * consumption, outcome, receipt commitments, and signed obligation transitions.
 * Every event must pass the supported schema and its complete transition rules.
 */
export const replayPortable = (input) => {
    const outer = captureReplayOuter(input);
    if (!outer.ok)
        return reject(outer.code);
    const draft = newDraft();
    const capture = captureBoundedCanonicalReplayBodyIncrementally(outer.events, outer.source, (capturedEvent) => {
        const failure = reduceCapturedEvent(draft, capturedEvent);
        return failure === undefined
            ? { status: "CONTINUE" }
            : { status: "STOP", result: failure };
    });
    if (capture.status === "CAPTURE_FAILED") {
        return captureFailureResult(capture.error);
    }
    if (capture.status === "STOPPED")
        return capture.result;
    const final = finishDraft(draft);
    if (!("state" in final))
        return final.result;
    const state = final.state;
    const result = {
        operationVersion: PORTABLE_REPLAY_VERSION,
        status: "ACCEPTED",
        head: state.head,
        eventCount: state.events.length,
    };
    objectDefineDataProperty(result, "eventPosition", undefined);
    objectDefineDataProperty(result, "eventId", undefined);
    return Object.freeze(result);
};
