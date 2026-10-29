/** Fixed prospective D1 bridge. No caller-supplied policy program or global edition switch. */
import { canonicalEncode, captureBoundedCanonicalValue, hashCanonical, immutableProtocolValue } from "./canonical.js";
import { PORTABLE_ADAPTER_POLICY_E5_HASH, PORTABLE_ADAPTER_POLICY_E6_HASH, REMOTE_SERVICE_REPORT_ADAPTER_ID } from "./portable-adapter-engine.js";
import { isPortableReplayState } from "./portable-replay.js";
export const DUTY_POLICY_VERSION = "continuity-attempt-disposition/1";
export const DUTY_POLICY_RULES_HASH = "0xf7fb2b7de27abb77c6c3d03af6f61dce11afda5a510af20c8036085cd10a5f94";
export const DUTY_VIEW_VERSION = "continuity-attempt-duty-view/1";
export const DUTY_POLICY_RULES = immutableProtocolValue({
    "version": "continuity-attempt-disposition/1",
    "criteriaProfile": "local-investigation/1",
    "scope": "ONE_EXISTING_E5_OR_E6_ATTEMPT_DUTY",
    "eventTypes": [
        "ATTEMPT_DUTY_POLICY_ACTIVATED",
        "ATTEMPT_DUTY_DISPOSITION_RECORDED",
        "ATTEMPT_DUTY_CONTEST_RECORDED"
    ],
    "activation": {
        "action": "ACTIVATE_DUTY_POLICY",
        "resourcePrefix": "duty-policy:",
        "principal": "EXISTING_SOURCE_ROLE_PRINCIPAL",
        "grant": "EXACT_NONDELEGABLE_UNCAPPED_RECOGNIZED_ROOT",
        "signer": "CURRENT_DUTY_ROLE_OCCUPANT_RUNTIME",
        "activationLimit": 1,
        "changesGenesisOrAdapterPolicy": false
    },
    "attestation": {
        "version": "continuity-duty-finding/1",
        "purposes": [
            "DISPOSITION",
            "CONTEST"
        ],
        "action": "ATTEST_DUTY_FINDING",
        "resourcePrefix": "duty:",
        "acceptedRole": "ONE_PREEXISTING_ROLE_UNDER_SOURCE_PRINCIPAL",
        "findingProof": "RECOMPUTED_FROM_PRIOR_STATE_HASH_BOUND"
    },
    "transition": {
        "action": "RECORD_DUTY_DISPOSITION",
        "resourcePrefix": "duty:",
        "signer": "CURRENT_ASSIGNEE_AND_DUTY_ROLE_OCCUPANT_RUNTIME",
        "signatureOrder": [
            "FINDING",
            "OUTER_EFFECT_INCLUDING_FINDING_SIGNATURE"
        ],
        "postSignEligibility": "BOTH_SIGNERS_AT_FRESH_TIME_AND_UNCHANGED_HEAD"
    },
    "criteria": [
        "SOURCE_REVIEWED",
        "HISTORY_REVIEWED",
        "FINDING_RECORDED",
        "CONTROL_REVIEWED"
    ],
    "criterionStates": [
        "SATISFIED",
        "UNAVAILABLE",
        "UNRESOLVED"
    ],
    "criterionReasonMaxUtf8Bytes": 256,
    "nextStepMaxUtf8Bytes": 512,
    "dispositions": [
        "COMPLETED_UNDER_POLICY",
        "ESCALATED"
    ],
    "viewVersion": "continuity-attempt-duty-view/1",
    "currentViews": [
        "OPEN",
        "COMPLETED_UNDER_POLICY",
        "ESCALATED",
        "NEEDS_REVIEW",
        "CONTESTED"
    ],
    "completion": "ALL_CRITERIA_SATISFIED_WITHOUT_ACCEPTED_CONTEST",
    "outstandingFalseOnlyFor": "CURRENT_COMPLETED_UNDER_POLICY",
    "externalOutcome": "NOT_PROVEN",
    "contest": "PERSISTENT_NO_WITHDRAWAL_OR_ADJUDICATION",
    "documentDigestAlgorithm": "sha256",
    "evidenceIndexVersion": "continuity-duty-evidence-index/1",
    "freshness": "COMPLETE_SOURCE_LIFECYCLE_OBSERVATIONS_REVIEWS_ASSIGNMENTS_AND_CONTESTS",
    "excludeFromFreshness": [
        "DISPOSITIONS",
        "UNRELATED_EVENTS",
        "LATER_CREDENTIAL_OR_AUTHORITY_CHANGES_ALONE"
    ],
    "writerProfile": "continuity-segmented-local/1",
    "limits": {
        "dispositions": 4,
        "contests": 2,
        "reservedAtActivation": 6,
        "releaseUnusedOnCompletion": false,
        "raiseExistingStorageOrShapeLimits": false
    }
});
/** Internal: derive every source fact from a previously verified complete prefix. */
export function derivePortableDutyPolicyDescriptor(state, selection) {
    if (state.genesis.adapterPolicyHash !== PORTABLE_ADAPTER_POLICY_E5_HASH &&
        state.genesis.adapterPolicyHash !== PORTABLE_ADAPTER_POLICY_E6_HASH)
        return undefined;
    const duty = state.attemptDuties.get(selection.dutyId);
    if (!duty)
        return undefined;
    const source = state.intentDeclarations.get(duty.record.sourceIntentId);
    const admission = state.intentAdmissions.get(duty.record.sourceIntentId);
    const role = state.roles.get(duty.record.durableRoleId), attester = state.roles.get(selection.acceptedAttesterRoleId);
    if (!source || !admission || source.data.roleId !== role?.id || !role || !attester ||
        attester.principalId !== role.principalId || duty.record.sourceAdmissionEventId !== admission.admissionEventId ||
        admission.adapterIdentity.adapterProfile.profileId !== REMOTE_SERVICE_REPORT_ADAPTER_ID)
        return undefined;
    return immutableProtocolValue({ version: DUTY_POLICY_VERSION, rulesHash: DUTY_POLICY_RULES_HASH,
        criteriaProfile: "local-investigation/1", domain: state.genesis.domain,
        genesisHash: state.eventHistoryHashes[0], baseAdapterPolicyHash: state.genesis.adapterPolicyHash,
        dutyId: duty.record.dutyId, dutyCreationEventId: duty.creationEventId, dutyRecordHash: hashCanonical(duty.record),
        sourceIntentId: duty.record.sourceIntentId, sourceAdmissionEventId: admission.admissionEventId,
        durableRoleId: role.id, principalId: role.principalId, incidentSourceDigest: selection.incidentSourceDigest,
        acceptedAttesterRoleId: attester.id, dispositionLimit: 4, contestLimit: 2 });
}
/** Pure selection helper; it does not confer authority or mutate a history. */
export function buildPortableDutyPolicyDescriptor(state, input) {
    if (!isPortableReplayState(state))
        throw new TypeError("Duty policy requires authoritative replay state.");
    const capture = captureBoundedCanonicalValue(input, { maxCanonicalBytes: 2048 });
    const value = capture.value;
    const exact = (item, keys) => {
        if (!item || typeof item !== "object" || Array.isArray(item))
            return false;
        const original = capture.capturedRecordKeys(item);
        return original?.length === keys.length && keys.every(k => Object.hasOwn(item, k)) && Object.keys(item).length === keys.length;
    };
    if (!exact(value, ["dutyId", "incidentSourceDigest", "acceptedAttesterRoleId"]) ||
        typeof value.dutyId !== "string" || typeof value.acceptedAttesterRoleId !== "string" ||
        !exact(value.incidentSourceDigest, ["algorithm", "value"]))
        throw new TypeError("Invalid duty policy selection.");
    const digest = value.incidentSourceDigest;
    if (digest.algorithm !== "sha256" || typeof digest.value !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(digest.value)) {
        throw new TypeError("Invalid incident document digest.");
    }
    const descriptor = derivePortableDutyPolicyDescriptor(state, value);
    if (!descriptor)
        throw new TypeError("Duty policy selection does not match the existing case.");
    return descriptor;
}
/** Internal exact-root and immutable-selection requirements, independently rerun during replay. */
export function portableDutyPolicyActivationRequirements(state, data, timestamp) {
    const d = data.descriptor;
    if (state.attemptDutyPolicies.has(d.dutyId))
        return undefined;
    const expected = derivePortableDutyPolicyDescriptor(state, d);
    if (!expected || canonicalEncode(d) !== canonicalEncode(expected) || data.descriptorHash !== hashCanonical(expected))
        return undefined;
    const role = state.roles.get(expected.durableRoleId);
    const tenure = role.currentTenureId === undefined ? undefined : state.tenures.get(role.currentTenureId);
    const actor = state.agents.get(data.actorId);
    if (!tenure || tenure.closed || tenure.agentId !== data.actorId || !actor || actor.terminated)
        return undefined;
    const record = state.authorities.get(data.activationAuthorityId), grant = record?.grant;
    const root = state.recognizedRoots.get(data.activationAuthorityId);
    if (!record || record.revocationEventId !== undefined || !grant || grant.kind !== "PERMISSION" ||
        Object.hasOwn(grant, "parentAuthorityId") || grant.authorityId !== grant.rootAuthorityId ||
        grant.grantorId !== role.principalId || grant.granteeId !== data.actorId || root?.principalId !== role.principalId ||
        root.rootGrantEventId !== record.grantEventId)
        return undefined;
    const c = grant.constraints, resource = `duty-policy:${data.descriptorHash}`;
    if (c.quantitative || c.actions.length !== 1 || c.actions[0] !== "ACTIVATE_DUTY_POLICY" ||
        c.resources.length !== 1 || c.resources[0] !== resource || c.maxDelegationDepth !== 0 ||
        c.expiresAt === undefined || timestamp >= c.expiresAt || (c.notBefore !== undefined && timestamp < c.notBefore) ||
        Object.hasOwn(c, "maxAmount") || Object.hasOwn(c, "maxCumulativeAmount") || Object.hasOwn(c, "maxTransactions"))
        return undefined;
    return { request: { actorId: data.actorId, action: "ACTIVATE_DUTY_POLICY", resource, claimedAt: timestamp },
        // Select the ordinary canonical source-Principal winner first. Requiring the
        // selected ID during candidate filtering could skip an earlier capped root.
        // portableDutyPolicyActivationProofMatches then requires this exact root.
        requiredPrincipalId: role.principalId, requiredAuthorityIds: [],
        roleId: role.id, roleTenureId: tenure.id };
}
/** The selected root must be the main permission path, never a convenient alternate root. */
export function portableDutyPolicyActivationProofMatches(proof, authorityId) {
    return proof.recognizedRoot.rootAuthorityId === authorityId && proof.permissionPath.length === 1 &&
        proof.permissionPath[0].authorityId === authorityId;
}
export function inspectPortableDutyPolicy(state, dutyId) {
    if (!isPortableReplayState(state))
        throw new TypeError("Duty policy requires authoritative replay state.");
    const policy = state.attemptDutyPolicies.get(dutyId), duty = state.attemptDuties.get(dutyId);
    if (!policy || !duty)
        return undefined;
    return immutableProtocolValue({ version: DUTY_VIEW_VERSION, dutyId, dutyDisposition: "OPEN", outstanding: true,
        externalOutcome: "NOT_PROVEN", policy, observedHead: state.head, currentAssigneeId: duty.currentAssigneeId,
        latestAssignmentEventId: duty.assignments.at(-1)?.eventId ?? duty.creationEventId,
        lastRecordedDisposition: null, reasons: ["NO_DISPOSITION_RECORDED"],
        evidenceScope: { kind: "COMPLETE_CAPTURED_HISTORY", head: state.head } });
}
