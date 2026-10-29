/** Host-owned policy selection for one existing investigation duty. No agent tool or dispatch. */
import * as core from "../../core-0.2/src/core/index.ts";
import { type PortableDutyPolicyDescriptor } from "../../core-0.2/src/core/duty-policy.ts";
import type { LocalRuntimeOptions } from "./runtime.ts";
export type DutyPolicySelection = Readonly<{
    duty: string;
    incidentSourceDigest: Readonly<{
        algorithm: "sha256";
        value: core.ContentHash;
    }>;
    attesterRole: string;
}>;
export type DutyPolicyActivation = Readonly<{
    id: string;
    descriptor: PortableDutyPolicyDescriptor;
    activationAuthority: string;
}>;
export type { PortableDutyPolicyDescriptor };
/** Historical inspection only. The supplied handle must come from complete verified replay. */
export declare function inspectContinuationDutyPolicy(history: unknown, duty: string): {
    scope: "CAPTURED_HISTORY_ONLY";
    executionCapability: false;
    head: Readonly<{
        hash: core.ContentHash;
        position: number;
        canonicalTime: number;
    }>;
    policy: Readonly<{
        version: typeof core.DUTY_VIEW_VERSION;
        dutyId: string;
        dutyDisposition: "OPEN";
        outstanding: true;
        externalOutcome: "NOT_PROVEN";
        policy: core.PortableDutyPolicyActivation;
        observedHead: core.PortableHistoryHead;
        currentAssigneeId: string;
        latestAssignmentEventId: string;
        lastRecordedDisposition: null;
        evidenceScope: Readonly<{
            kind: "COMPLETE_CAPTURED_HISTORY";
            head: core.PortableHistoryHead;
        }>;
        reasons: readonly ["NO_DISPOSITION_RECORDED"];
    }> | null;
};
export declare function openLocalDutyPolicy(options: LocalRuntimeOptions): Readonly<{
    describe(input: DutyPolicySelection): {
        descriptor: Readonly<{
            version: typeof core.DUTY_POLICY_VERSION;
            rulesHash: typeof core.DUTY_POLICY_RULES_HASH;
            criteriaProfile: "local-investigation/1";
            domain: core.PortableAuthorizationDomain;
            genesisHash: core.ContentHash;
            baseAdapterPolicyHash: core.ContentHash;
            dutyId: string;
            dutyCreationEventId: string;
            dutyRecordHash: core.ContentHash;
            sourceIntentId: string;
            sourceAdmissionEventId: string;
            durableRoleId: string;
            principalId: string;
            incidentSourceDigest: core.PortableDutyDocumentDigest;
            acceptedAttesterRoleId: string;
            dispositionLimit: 4;
            contestLimit: 2;
        }>;
        descriptorHash: `0x${string}`;
        activationAction: "ACTIVATE_DUTY_POLICY";
        activationResource: string;
        head: Readonly<{
            hash: core.ContentHash;
            position: number;
            canonicalTime: number;
        }>;
        grantsAuthority: false;
    };
    activate(input: DutyPolicyActivation): Promise<{
        eventId: string;
        head: Readonly<{
            hash: core.ContentHash;
            position: number;
            canonicalTime: number;
        }>;
        alreadyRecorded: boolean;
        view: Readonly<{
            version: typeof core.DUTY_VIEW_VERSION;
            dutyId: string;
            dutyDisposition: "OPEN";
            outstanding: true;
            externalOutcome: "NOT_PROVEN";
            policy: core.PortableDutyPolicyActivation;
            observedHead: core.PortableHistoryHead;
            currentAssigneeId: string;
            latestAssignmentEventId: string;
            lastRecordedDisposition: null;
            evidenceScope: Readonly<{
                kind: "COMPLETE_CAPTURED_HISTORY";
                head: core.PortableHistoryHead;
            }>;
            reasons: readonly ["NO_DISPOSITION_RECORDED"];
        }> | undefined;
    }>;
    inspect(duty: string): {
        scope: "CAPTURED_HISTORY_ONLY";
        executionCapability: false;
        head: Readonly<{
            hash: core.ContentHash;
            position: number;
            canonicalTime: number;
        }>;
        policy: Readonly<{
            version: typeof core.DUTY_VIEW_VERSION;
            dutyId: string;
            dutyDisposition: "OPEN";
            outstanding: true;
            externalOutcome: "NOT_PROVEN";
            policy: core.PortableDutyPolicyActivation;
            observedHead: core.PortableHistoryHead;
            currentAssigneeId: string;
            latestAssignmentEventId: string;
            lastRecordedDisposition: null;
            evidenceScope: Readonly<{
                kind: "COMPLETE_CAPTURED_HISTORY";
                head: core.PortableHistoryHead;
            }>;
            reasons: readonly ["NO_DISPOSITION_RECORDED"];
        }> | null;
    };
}>;
export type LocalDutyPolicy = ReturnType<typeof openLocalDutyPolicy>;
