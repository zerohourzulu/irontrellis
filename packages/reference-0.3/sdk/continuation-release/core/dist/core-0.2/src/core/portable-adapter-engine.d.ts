import { type ContentHash } from "./canonical.ts";
import type { AcceptedCanonicalEventShape } from "./event-schema.ts";
import type { PortableAuthorizationDomain } from "./portable-replay.ts";
export declare const PORTABLE_ADAPTER_IDEMPOTENCY_VERSION: "continuity-adapter-idempotency/0.2";
export declare const PORTABLE_ADAPTER_SUBMISSION_VERSION: "continuity-adapter-submission/0.2";
export declare const PORTABLE_ADAPTER_NO_EFFECT_VERSION: "continuity-adapter-no-effect/0.2";
export declare const PORTABLE_ADAPTER_ACKNOWLEDGMENT_VERSION: "continuity-adapter-acknowledgment/0.2";
export declare const SIMULATED_ADAPTER_ID: "adapter:simulated";
export declare const LOCAL_EVIDENCE_PACKET_ADAPTER_ID: "adapter:local-evidence-packet";
export declare const LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID: "adapter:local-synthetic-endpoint-state";
export declare const LOCAL_SYNTHETIC_ENDPOINT_STATE_ACKNOWLEDGMENT_VERSION: "continuity-local-endpoint-state-ack/1";
export declare const LOCAL_DOCUMENT_RELEASE_ADAPTER_ID: "adapter:local-document-release";
export declare const LOCAL_DOCUMENT_RELEASE_ACKNOWLEDGMENT_VERSION: "continuity-local-document-release-ack/1";
export declare const REMOTE_SERVICE_REPORT_ADAPTER_ID: "adapter:remote-service-report";
export declare const REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION: "continuity-remote-service-report-ack/1";
export declare const MAX_PORTABLE_ADAPTER_EVIDENCE_BYTES = 4096;
type AdapterId = typeof REMOTE_SERVICE_REPORT_ADAPTER_ID | typeof LOCAL_DOCUMENT_RELEASE_ADAPTER_ID | typeof SIMULATED_ADAPTER_ID | typeof LOCAL_EVIDENCE_PACKET_ADAPTER_ID | typeof LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID;
export type PortableAdapterProfile = Readonly<{
    profileId: AdapterId;
    profileVersion: "1";
    descriptorHash: ContentHash;
}>;
export declare const PORTABLE_ADAPTER_POLICY_HASH: `0x${string}`;
export declare const approvedPortableAdapterProfile: (profileId: unknown) => PortableAdapterProfile;
export declare const PORTABLE_ADAPTER_POLICY_E2_HASH: `0x${string}`;
export declare const PORTABLE_ADAPTER_POLICY_E3_HASH: `0x${string}`;
export declare const PORTABLE_ADAPTER_POLICY_E4_HASH: `0x${string}`;
export declare const PORTABLE_ATTEMPT_OBSERVATION_DUTY_EXTENSION: "continuity-attempt-observation-duty/1";
export declare const PORTABLE_ADAPTER_POLICY_E5_HASH: `0x${string}`;
export declare const PORTABLE_ATTEMPT_DUTY_REVIEW_EXTENSION: "continuity-attempt-duty-review/1";
declare const e6Extensions: readonly ["continuity-attempt-observation-duty/1", "continuity-attempt-duty-review/1"];
export declare const PORTABLE_ADAPTER_POLICY_E6_HASH: `0x${string}`;
export type ImmutablePolicy = Readonly<{
    edition: "E1" | "E2" | "E3" | "E4" | "E5" | "E6";
    hash: ContentHash;
    profiles: readonly PortableAdapterProfile[];
    semanticExtension?: typeof PORTABLE_ATTEMPT_OBSERVATION_DUTY_EXTENSION;
    semanticExtensions?: typeof e6Extensions;
}>;
/** Exact genesis selector. Missing/unknown values never select a default. */
export declare const resolvePortableAdapterPolicy: (hash: unknown) => ImmutablePolicy | undefined;
export declare const approvedPortableAdapterProfileForPolicy: (hash: unknown, profileId: unknown) => PortableAdapterProfile;
/** @internal Shape/configuration only. Never authorizes membership in a history. */
export declare const knownPortableAdapterProfile: (profileId: unknown) => PortableAdapterProfile;
/** @internal Exact schema expected for a known complete tuple; not history authority. */
export declare const knownPortableAdapterAcknowledgmentVersion: (profile: unknown) => typeof PORTABLE_ADAPTER_ACKNOWLEDGMENT_VERSION | typeof REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION | typeof LOCAL_DOCUMENT_RELEASE_ACKNOWLEDGMENT_VERSION | typeof LOCAL_SYNTHETIC_ENDPOINT_STATE_ACKNOWLEDGMENT_VERSION;
export type PortableAdapterHistoryHead = Readonly<{
    hash: ContentHash;
    position: number;
    canonicalTime: number;
}>;
export type PortableAdapterIdentity = Readonly<{
    idempotencyKey: ContentHash;
    submissionFingerprint: ContentHash;
    durableEventHistoryHash: ContentHash;
    adapterNoEffectReference: ContentHash;
    adapterProfile: PortableAdapterProfile;
    domain: PortableAuthorizationDomain;
    intentId: string;
    admissionHead: PortableAdapterHistoryHead;
}>;
type EvidenceIdentity = Pick<PortableAdapterIdentity, "adapterProfile" | "domain" | "intentId" | "admissionHead" | "idempotencyKey" | "submissionFingerprint">;
type EvidenceIdentityFor<Id extends AdapterId> = Omit<EvidenceIdentity, "adapterProfile"> & {
    adapterProfile: Readonly<Omit<PortableAdapterProfile, "profileId"> & {
        profileId: Id;
    }>;
};
export type PortableSimulatedAdapterAcknowledgment = Readonly<EvidenceIdentityFor<typeof SIMULATED_ADAPTER_ID> & {
    schemaVersion: typeof PORTABLE_ADAPTER_ACKNOWLEDGMENT_VERSION;
    kind: "ACKNOWLEDGMENT";
    result: Readonly<{
        kind: "SIMULATED_SUBMISSION";
        submissionReference: ContentHash;
    }>;
}>;
export type PortableLocalPacketAdapterAcknowledgment = Readonly<EvidenceIdentityFor<typeof LOCAL_EVIDENCE_PACKET_ADAPTER_ID> & {
    schemaVersion: typeof PORTABLE_ADAPTER_ACKNOWLEDGMENT_VERSION;
    kind: "ACKNOWLEDGMENT";
    result: Readonly<{
        kind: "LOCAL_PACKET_CREATED";
        manifestDigest: Readonly<{
            algorithm: "sha256";
            value: ContentHash;
        }>;
    }>;
}>;
export type LocalSyntheticEndpointStateAcknowledgment = Readonly<EvidenceIdentityFor<typeof LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID> & {
    schemaVersion: typeof LOCAL_SYNTHETIC_ENDPOINT_STATE_ACKNOWLEDGMENT_VERSION;
    kind: "ACKNOWLEDGMENT";
    result: Readonly<{
        kind: "LOCAL_ENDPOINT_STATE_CHANGED";
        transitionDigest: Readonly<{
            algorithm: "keccak256";
            value: ContentHash;
        }>;
    }>;
}>;
export type LocalDocumentReleaseAcknowledgment = Readonly<EvidenceIdentityFor<typeof LOCAL_DOCUMENT_RELEASE_ADAPTER_ID> & {
    schemaVersion: typeof LOCAL_DOCUMENT_RELEASE_ACKNOWLEDGMENT_VERSION;
    kind: "ACKNOWLEDGMENT";
    result: Readonly<{
        kind: "LOCAL_DOCUMENT_RELEASED";
        publicationManifestDigest: Readonly<{
            algorithm: "sha256";
            value: ContentHash;
        }>;
    }>;
}>;
/** Adapter-retained provider report digest only; not external truth, success, settlement or cancellation. */
export type RemoteServiceReportAcknowledgment = Readonly<EvidenceIdentityFor<typeof REMOTE_SERVICE_REPORT_ADAPTER_ID> & {
    schemaVersion: typeof REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION;
    kind: "ACKNOWLEDGMENT";
    result: Readonly<{
        kind: "REMOTE_SERVICE_REPORTED";
        reportDigest: Readonly<{
            algorithm: "sha256";
            value: ContentHash;
        }>;
    }>;
}>;
export type PortableAdapterAcknowledgment = RemoteServiceReportAcknowledgment | LocalDocumentReleaseAcknowledgment | PortableSimulatedAdapterAcknowledgment | PortableLocalPacketAdapterAcknowledgment | LocalSyntheticEndpointStateAcknowledgment;
export type PortableAdapterNoEffect = Readonly<EvidenceIdentity & {
    schemaVersion: typeof PORTABLE_ADAPTER_NO_EFFECT_VERSION;
    kind: "NO_EFFECT";
    result: Readonly<{
        kind: "SIMULATED_NO_EFFECT";
        reference: ContentHash;
    }>;
}>;
export type PortableAdapterExternalEvidence = Readonly<{
    kind: "EXTERNAL";
    evidenceType: typeof PORTABLE_ADAPTER_ACKNOWLEDGMENT_VERSION | typeof REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION | typeof LOCAL_DOCUMENT_RELEASE_ACKNOWLEDGMENT_VERSION | typeof LOCAL_SYNTHETIC_ENDPOINT_STATE_ACKNOWLEDGMENT_VERSION | typeof PORTABLE_ADAPTER_NO_EFFECT_VERSION;
    reference: string;
    attesterId: AdapterId;
}>;
export declare const isLocalPacketManifestReference: (value: unknown) => value is ContentHash;
export declare const validatePortableAdapterProfile: (value: unknown) => value is PortableAdapterProfile;
export declare const validatePortableAdapterProfileForPolicy: (hash: unknown, value: unknown) => value is PortableAdapterProfile;
/** @internal Shape-only recognition is deliberately distinct from genesis membership. */
export declare const validateKnownPortableAdapterProfile: (value: unknown) => value is PortableAdapterProfile;
export declare const derivePortableAdapterIdempotencyKey: (domain: PortableAuthorizationDomain, intentId: string) => ContentHash;
export declare const derivePortableAdapterNoEffectReference: (idempotencyKey: ContentHash, submissionFingerprint: ContentHash) => ContentHash;
/** Internal: profile comes from the already accepted declaration, not an unsigned caller default. */
export declare const derivePortableAdapterIdentityForAcceptedAdmission: (admissionEvent: AcceptedCanonicalEventShape, admissionHead: PortableAdapterHistoryHead, adapterProfile: PortableAdapterProfile, adapterPolicyHash: ContentHash) => PortableAdapterIdentity;
export declare const createPortableAdapterAcknowledgment: (identity: PortableAdapterIdentity, transactionReference?: string) => PortableAdapterAcknowledgment;
/** Digest syntax/identity only; the executor/reader must verify the retained canonical transition. */
export declare const createLocalSyntheticEndpointStateAcknowledgment: (identity: PortableAdapterIdentity, transitionDigest: ContentHash) => LocalSyntheticEndpointStateAcknowledgment;
/** Digest syntax/identity only; external artifact inspection establishes retained publication. */
export declare const createLocalDocumentReleaseAcknowledgment: (identity: PortableAdapterIdentity, publicationManifestDigest: ContentHash) => LocalDocumentReleaseAcknowledgment;
/** Digest syntax/identity only. The adapter retains the provider report; its truth and effect remain separate. */
export declare const createRemoteServiceReportAcknowledgment: (identity: PortableAdapterIdentity, reportDigest: ContentHash) => RemoteServiceReportAcknowledgment;
export declare const createPortableAdapterNoEffect: (identity: PortableAdapterIdentity) => PortableAdapterNoEffect;
export declare const validatePortableAdapterAcknowledgment: (value: unknown, identity: PortableAdapterIdentity) => boolean;
/** Validate the complete paired ACK against the admitted identity before projecting its reference. */
export declare const portableAdapterAcknowledgmentTransactionReference: (value: unknown, identity: PortableAdapterIdentity) => ContentHash;
export declare const validatePortableAdapterNoEffect: (value: unknown, identity: PortableAdapterIdentity) => boolean;
export declare const validatePortableAdapterAcknowledgmentShape: (value: unknown) => boolean;
export declare const validatePortableAdapterNoEffectShape: (value: unknown) => boolean;
export declare const portableAdapterAcknowledgmentEvidence: (identity: PortableAdapterIdentity, acknowledgment: PortableAdapterAcknowledgment) => PortableAdapterExternalEvidence;
export declare const portableAdapterNoEffectEvidence: (identity: PortableAdapterIdentity, noEffect: PortableAdapterNoEffect) => PortableAdapterExternalEvidence;
export declare const samePortableAdapterEvidence: (left: Readonly<Record<string, unknown>>, right: PortableAdapterExternalEvidence) => boolean;
export {};
