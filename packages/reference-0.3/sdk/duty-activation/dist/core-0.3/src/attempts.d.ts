import * as core from "../../core-0.2/src/core/index.ts";
import { type VerifiedHistory } from "./history.ts";
import type { LocalRuntimeOptions } from "./runtime.ts";
import type { WriteResult } from "./local-owner.ts";
export type OutcomeObservation = Readonly<{
    id: string;
    intent: string;
    acknowledgment: core.RemoteServiceReportAcknowledgment;
}>;
export type AttemptDuty = Readonly<{
    id: string;
    intent: string;
    description: string;
    deadline: number;
}>;
export type AttemptDutyAssignment = Readonly<{
    id: string;
    duty: string;
}>;
export type AttemptDutyReview = Readonly<{
    id: string;
    duty: string;
    summaryDigest: core.ContentHash;
}>;
/** Application-owned recording authority. No adapter, URL or dispatch callback. */
export declare function openLocalAttemptRecorder(options: LocalRuntimeOptions): Readonly<{
    observe(input: OutcomeObservation): Promise<WriteResult>;
    createDuty(input: AttemptDuty): Promise<WriteResult>;
    reviewDuty(input: AttemptDutyReview): Promise<WriteResult>;
    assignDuty(input: AttemptDutyAssignment): Promise<WriteResult>;
}>;
export type LocalAttemptRecorder = ReturnType<typeof openLocalAttemptRecorder>;
/** Replay-only inspection. Recorded reports establish neither truth nor power. */
export declare function inspectAttemptHistory(input: unknown): {
    scope: "CAPTURED_HISTORY_ONLY";
    executionCapability: false;
    head: Readonly<{
        hash: core.ContentHash;
        position: number;
        canonicalTime: number;
    }>;
    attempts: {
        intentId: string;
        sourceAdmissionEventId: string;
        originalActorId: string;
        originalSessionId: string;
        originalControlEpoch: number;
        durableRoleId: string;
        observations: readonly Readonly<{
            intentId: string;
            sourceAdmissionEventId: string;
            acknowledgment: core.RemoteServiceReportAcknowledgment;
            actorId: string;
            eventId: string;
            eventPosition: number;
            observedAt: number;
        }>[];
        reportStatus: "REPORT_RECORDED" | "DIVERGENT_REPORTS" | "NO_RECORDED_REPORTS";
        duty: Readonly<{
            record: core.PortableAttemptDutyRecord;
            creationEventId: string;
            creationEventPosition: number;
            creationActorId: string;
            currentAssigneeId: string;
            assignments: readonly import("../../core-0.2/src/core/portable-replay.ts").PortableAttemptDutyAssignment[];
        }> | {
            disposition: Readonly<{
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
            record: core.PortableAttemptDutyRecord;
            creationEventId: string;
            creationEventPosition: number;
            creationActorId: string;
            currentAssigneeId: string;
            assignments: readonly import("../../core-0.2/src/core/portable-replay.ts").PortableAttemptDutyAssignment[];
        } | {
            reviews: readonly Readonly<{
                dutyId: string;
                actorId: string;
                observationEventIds: readonly string[];
                summaryDigest: core.ContentHash;
                eventId: string;
                eventPosition: number;
                reviewedAt: number;
            }>[];
            reviewStatus: import("../../core-0.2/src/core/portable-attempt-review.ts").PortableAttemptDutyReviewStatus;
            record: core.PortableAttemptDutyRecord;
            creationEventId: string;
            creationEventPosition: number;
            creationActorId: string;
            currentAssigneeId: string;
            assignments: readonly import("../../core-0.2/src/core/portable-replay.ts").PortableAttemptDutyAssignment[];
        } | null;
        externalOutcome: "NOT_PROVEN";
    }[];
};
export declare function inspectContinuationAttempts(history: VerifiedHistory): {
    scope: "CAPTURED_HISTORY_ONLY";
    executionCapability: false;
    head: Readonly<{
        hash: core.ContentHash;
        position: number;
        canonicalTime: number;
    }>;
    attempts: {
        intentId: string;
        sourceAdmissionEventId: string;
        originalActorId: string;
        originalSessionId: string;
        originalControlEpoch: number;
        durableRoleId: string;
        observations: readonly Readonly<{
            intentId: string;
            sourceAdmissionEventId: string;
            acknowledgment: core.RemoteServiceReportAcknowledgment;
            actorId: string;
            eventId: string;
            eventPosition: number;
            observedAt: number;
        }>[];
        reportStatus: "REPORT_RECORDED" | "DIVERGENT_REPORTS" | "NO_RECORDED_REPORTS";
        duty: Readonly<{
            record: core.PortableAttemptDutyRecord;
            creationEventId: string;
            creationEventPosition: number;
            creationActorId: string;
            currentAssigneeId: string;
            assignments: readonly import("../../core-0.2/src/core/portable-replay.ts").PortableAttemptDutyAssignment[];
        }> | {
            disposition: Readonly<{
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
            record: core.PortableAttemptDutyRecord;
            creationEventId: string;
            creationEventPosition: number;
            creationActorId: string;
            currentAssigneeId: string;
            assignments: readonly import("../../core-0.2/src/core/portable-replay.ts").PortableAttemptDutyAssignment[];
        } | {
            reviews: readonly Readonly<{
                dutyId: string;
                actorId: string;
                observationEventIds: readonly string[];
                summaryDigest: core.ContentHash;
                eventId: string;
                eventPosition: number;
                reviewedAt: number;
            }>[];
            reviewStatus: import("../../core-0.2/src/core/portable-attempt-review.ts").PortableAttemptDutyReviewStatus;
            record: core.PortableAttemptDutyRecord;
            creationEventId: string;
            creationEventPosition: number;
            creationActorId: string;
            currentAssigneeId: string;
            assignments: readonly import("../../core-0.2/src/core/portable-replay.ts").PortableAttemptDutyAssignment[];
        } | null;
        externalOutcome: "NOT_PROVEN";
    }[];
};
