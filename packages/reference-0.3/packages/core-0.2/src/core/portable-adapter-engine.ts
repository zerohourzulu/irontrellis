import { types as nodeTypes } from "node:util";
const isProxy = nodeTypes.isProxy;
import { canonicalEncode, captureBoundedCanonicalValue, hashCanonical, type ContentHash } from "./canonical.ts";
import type { AcceptedCanonicalEventShape } from "./event-schema.ts";
import type { PortableAuthorizationDomain } from "./portable-replay.ts";
import {
  HostTypeError, arrayIsArray, objectEntries, objectFreeze, objectHasOwn,
  numberIsSafeInteger, objectIs, regExpTest, stringToLowerCase, utf8Encode, bigintFrom, arrayPush,
  hostObjectPrototype, objectCreate, objectDefineDataProperty, reflectGetPrototypeOf, reflectOwnKeys, reflectGetOwnPropertyDescriptor,
  createWeakSet, weakSetHas, weakSetAdd, weakSetDelete,
} from "./host-intrinsics.ts";

export const PORTABLE_ADAPTER_IDEMPOTENCY_VERSION = "continuity-adapter-idempotency/0.2" as const;
export const PORTABLE_ADAPTER_SUBMISSION_VERSION = "continuity-adapter-submission/0.2" as const;
export const PORTABLE_ADAPTER_NO_EFFECT_VERSION = "continuity-adapter-no-effect/0.2" as const;
export const PORTABLE_ADAPTER_ACKNOWLEDGMENT_VERSION = "continuity-adapter-acknowledgment/0.2" as const;
export const SIMULATED_ADAPTER_ID = "adapter:simulated" as const;
export const LOCAL_EVIDENCE_PACKET_ADAPTER_ID = "adapter:local-evidence-packet" as const;
export const LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID = "adapter:local-synthetic-endpoint-state" as const;
export const LOCAL_SYNTHETIC_ENDPOINT_STATE_ACKNOWLEDGMENT_VERSION = "continuity-local-endpoint-state-ack/1" as const;
export const LOCAL_DOCUMENT_RELEASE_ADAPTER_ID = "adapter:local-document-release" as const;
export const LOCAL_DOCUMENT_RELEASE_ACKNOWLEDGMENT_VERSION = "continuity-local-document-release-ack/1" as const;
export const REMOTE_SERVICE_REPORT_ADAPTER_ID = "adapter:remote-service-report" as const;
export const REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION = "continuity-remote-service-report-ack/1" as const;
export const MAX_PORTABLE_ADAPTER_EVIDENCE_BYTES = 4096;
type AdapterId = typeof REMOTE_SERVICE_REPORT_ADAPTER_ID | typeof LOCAL_DOCUMENT_RELEASE_ADAPTER_ID | typeof SIMULATED_ADAPTER_ID | typeof LOCAL_EVIDENCE_PACKET_ADAPTER_ID | typeof LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID;
export type PortableAdapterProfile = Readonly<{ profileId: AdapterId; profileVersion: "1"; descriptorHash: ContentHash }>;
const descriptors = objectFreeze([
  objectFreeze({ profileId: LOCAL_EVIDENCE_PACKET_ADAPTER_ID, profileVersion: "1", acknowledgmentSchemaVersion: PORTABLE_ADAPTER_ACKNOWLEDGMENT_VERSION, replayRuleId: "continuity-adapter-replay/local-packet/1" }),
  objectFreeze({ profileId: SIMULATED_ADAPTER_ID, profileVersion: "1", acknowledgmentSchemaVersion: PORTABLE_ADAPTER_ACKNOWLEDGMENT_VERSION, replayRuleId: "continuity-adapter-replay/simulated/1" }),
]);
export const PORTABLE_ADAPTER_POLICY_HASH = hashCanonical({ schemaVersion: "continuity-adapter-policy/0.2", profiles: descriptors });
const localProfile: PortableAdapterProfile = objectFreeze({ profileId: LOCAL_EVIDENCE_PACKET_ADAPTER_ID, profileVersion: "1", descriptorHash: hashCanonical(descriptors[0]) });
const simulatedProfile: PortableAdapterProfile = objectFreeze({ profileId: SIMULATED_ADAPTER_ID, profileVersion: "1", descriptorHash: hashCanonical(descriptors[1]) });
export const approvedPortableAdapterProfile = (profileId: unknown): PortableAdapterProfile => {
  if (profileId === LOCAL_EVIDENCE_PACKET_ADAPTER_ID) return localProfile;
  if (profileId === SIMULATED_ADAPTER_ID) return simulatedProfile;
  throw new HostTypeError("Unsupported fixed adapter profile.");
};
// E1's descriptor bytes/order and legacy policy hash above are immutable.
const endpointStateDescriptor = objectFreeze({ profileId: LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID, profileVersion: "1",
  acknowledgmentSchemaVersion: LOCAL_SYNTHETIC_ENDPOINT_STATE_ACKNOWLEDGMENT_VERSION,
  replayRuleId: "continuity-adapter-replay/local-endpoint-state/1" });
const e2Descriptors = objectFreeze([descriptors[0], endpointStateDescriptor, descriptors[1]]);
export const PORTABLE_ADAPTER_POLICY_E2_HASH = hashCanonical({ schemaVersion: "continuity-adapter-policy/0.2", profiles: e2Descriptors });
const endpointStateProfile: PortableAdapterProfile = objectFreeze({ profileId: LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID,
  profileVersion: "1", descriptorHash: hashCanonical(endpointStateDescriptor) });
const documentReleaseDescriptor = objectFreeze({ profileId: LOCAL_DOCUMENT_RELEASE_ADAPTER_ID, profileVersion: "1",
  acknowledgmentSchemaVersion: LOCAL_DOCUMENT_RELEASE_ACKNOWLEDGMENT_VERSION,
  replayRuleId: "continuity-adapter-replay/local-document-release/1" });
const e3Descriptors = objectFreeze([documentReleaseDescriptor, descriptors[0], endpointStateDescriptor, descriptors[1]]);
export const PORTABLE_ADAPTER_POLICY_E3_HASH = hashCanonical({ schemaVersion: "continuity-adapter-policy/0.2", profiles: e3Descriptors });
const documentReleaseProfile: PortableAdapterProfile = objectFreeze({ profileId: LOCAL_DOCUMENT_RELEASE_ADAPTER_ID,
  profileVersion: "1", descriptorHash: hashCanonical(documentReleaseDescriptor) });
// Experimental E4 adds one fixed report profile; earlier descriptor bytes/order remain unchanged.
const remoteServiceReportDescriptor = objectFreeze({ profileId: REMOTE_SERVICE_REPORT_ADAPTER_ID, profileVersion: "1",
  acknowledgmentSchemaVersion: REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION,
  replayRuleId: "continuity-adapter-replay/remote-service-report/1" });
const e4Descriptors = objectFreeze([documentReleaseDescriptor, descriptors[0], endpointStateDescriptor, remoteServiceReportDescriptor, descriptors[1]]);
export const PORTABLE_ADAPTER_POLICY_E4_HASH = hashCanonical({ schemaVersion: "continuity-adapter-policy/0.2", profiles: e4Descriptors });
export const PORTABLE_ATTEMPT_OBSERVATION_DUTY_EXTENSION = "continuity-attempt-observation-duty/1" as const;
export const PORTABLE_ADAPTER_POLICY_E5_HASH = hashCanonical({ schemaVersion: "continuity-adapter-policy/0.2",
  profiles: e4Descriptors, semanticExtension: PORTABLE_ATTEMPT_OBSERVATION_DUTY_EXTENSION });
export const PORTABLE_ATTEMPT_DUTY_REVIEW_EXTENSION = "continuity-attempt-duty-review/1" as const;
const e6Extensions = objectFreeze([PORTABLE_ATTEMPT_OBSERVATION_DUTY_EXTENSION, PORTABLE_ATTEMPT_DUTY_REVIEW_EXTENSION] as const);
export const PORTABLE_ADAPTER_POLICY_E6_HASH = hashCanonical({ schemaVersion: "continuity-adapter-policy/0.2",
  profiles: e4Descriptors, semanticExtensions: e6Extensions });
const remoteServiceReportProfile: PortableAdapterProfile = objectFreeze({ profileId: REMOTE_SERVICE_REPORT_ADAPTER_ID,
  profileVersion: "1", descriptorHash: hashCanonical(remoteServiceReportDescriptor) });
export type ImmutablePolicy = Readonly<{ edition: "E1" | "E2" | "E3" | "E4" | "E5" | "E6"; hash: ContentHash;
  profiles: readonly PortableAdapterProfile[]; semanticExtension?: typeof PORTABLE_ATTEMPT_OBSERVATION_DUTY_EXTENSION; semanticExtensions?: typeof e6Extensions }>;
const e1Policy: ImmutablePolicy = objectFreeze({ edition: "E1", hash: PORTABLE_ADAPTER_POLICY_HASH,
  profiles: objectFreeze([localProfile, simulatedProfile]) });
const e2Policy: ImmutablePolicy = objectFreeze({ edition: "E2", hash: PORTABLE_ADAPTER_POLICY_E2_HASH,
  profiles: objectFreeze([localProfile, endpointStateProfile, simulatedProfile]) });
const e3Policy: ImmutablePolicy = objectFreeze({ edition: "E3", hash: PORTABLE_ADAPTER_POLICY_E3_HASH,
  profiles: objectFreeze([documentReleaseProfile, localProfile, endpointStateProfile, simulatedProfile]) });
const e4Policy: ImmutablePolicy = objectFreeze({ edition: "E4", hash: PORTABLE_ADAPTER_POLICY_E4_HASH,
  profiles: objectFreeze([documentReleaseProfile, localProfile, endpointStateProfile, remoteServiceReportProfile, simulatedProfile]) });
const e5Policy: ImmutablePolicy = objectFreeze({ edition: "E5", hash: PORTABLE_ADAPTER_POLICY_E5_HASH,
  profiles: e4Policy.profiles, semanticExtension: PORTABLE_ATTEMPT_OBSERVATION_DUTY_EXTENSION });
const e6Policy: ImmutablePolicy = objectFreeze({ edition: "E6", hash: PORTABLE_ADAPTER_POLICY_E6_HASH,
  profiles: e4Policy.profiles, semanticExtensions: e6Extensions });
/** Exact genesis selector. Missing/unknown values never select a default. */
export const resolvePortableAdapterPolicy = (hash: unknown): ImmutablePolicy | undefined => {
  if (hash === PORTABLE_ADAPTER_POLICY_HASH) return e1Policy;
  if (hash === PORTABLE_ADAPTER_POLICY_E2_HASH) return e2Policy;
  if (hash === PORTABLE_ADAPTER_POLICY_E3_HASH) return e3Policy;
  if (hash === PORTABLE_ADAPTER_POLICY_E4_HASH) return e4Policy;
  if (hash === PORTABLE_ADAPTER_POLICY_E5_HASH) return e5Policy;
  if (hash === PORTABLE_ADAPTER_POLICY_E6_HASH) return e6Policy;
  return undefined;
};
export const approvedPortableAdapterProfileForPolicy = (hash: unknown, profileId: unknown): PortableAdapterProfile => {
  const policy = resolvePortableAdapterPolicy(hash);
  if (policy !== undefined) {
    for (let index = 0; index < policy.profiles.length; index++) {
      const profile = policy.profiles[index]!;
      if (profile.profileId === profileId) return profile;
    }
  }
  throw new HostTypeError("Profile is not a member of the selected fixed adapter policy.");
};
/** @internal Shape/configuration only. Never authorizes membership in a history. */
export const knownPortableAdapterProfile = (profileId: unknown): PortableAdapterProfile => {
  if (profileId === REMOTE_SERVICE_REPORT_ADAPTER_ID) return remoteServiceReportProfile;
  if (profileId === LOCAL_DOCUMENT_RELEASE_ADAPTER_ID) return documentReleaseProfile;
  if (profileId === LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID) return endpointStateProfile;
  return approvedPortableAdapterProfile(profileId);
};
/** @internal Exact schema expected for a known complete tuple; not history authority. */
export const knownPortableAdapterAcknowledgmentVersion = (profile: unknown):
  typeof PORTABLE_ADAPTER_ACKNOWLEDGMENT_VERSION | typeof REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION | typeof LOCAL_DOCUMENT_RELEASE_ACKNOWLEDGMENT_VERSION | typeof LOCAL_SYNTHETIC_ENDPOINT_STATE_ACKNOWLEDGMENT_VERSION => {
  const v = capture(profile);
  if (!closed(v, ["profileId", "profileVersion", "descriptorHash"]) || !same(v, knownPortableAdapterProfile(v.profileId))) {
    throw new HostTypeError("Unsupported adapter profile tuple.");
  }
  switch (v.profileId) {
    case SIMULATED_ADAPTER_ID:
    case LOCAL_EVIDENCE_PACKET_ADAPTER_ID: return PORTABLE_ADAPTER_ACKNOWLEDGMENT_VERSION;
    case LOCAL_DOCUMENT_RELEASE_ADAPTER_ID: return LOCAL_DOCUMENT_RELEASE_ACKNOWLEDGMENT_VERSION;
    case LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID: return LOCAL_SYNTHETIC_ENDPOINT_STATE_ACKNOWLEDGMENT_VERSION;
    case REMOTE_SERVICE_REPORT_ADAPTER_ID: return REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION;
    default: throw new HostTypeError("Unsupported adapter acknowledgment schema.");
  }
};
export type PortableAdapterHistoryHead = Readonly<{ hash: ContentHash; position: number; canonicalTime: number }>;
export type PortableAdapterIdentity = Readonly<{
  idempotencyKey: ContentHash; submissionFingerprint: ContentHash; durableEventHistoryHash: ContentHash;
  adapterNoEffectReference: ContentHash; adapterProfile: PortableAdapterProfile;
  domain: PortableAuthorizationDomain; intentId: string; admissionHead: PortableAdapterHistoryHead;
}>;
type EvidenceIdentity = Pick<PortableAdapterIdentity, "adapterProfile" | "domain" | "intentId" | "admissionHead" | "idempotencyKey" | "submissionFingerprint">;
type EvidenceIdentityFor<Id extends AdapterId> = Omit<EvidenceIdentity, "adapterProfile"> & {
  adapterProfile: Readonly<Omit<PortableAdapterProfile, "profileId"> & { profileId: Id }>;
};
export type PortableSimulatedAdapterAcknowledgment = Readonly<EvidenceIdentityFor<typeof SIMULATED_ADAPTER_ID> & {
  schemaVersion: typeof PORTABLE_ADAPTER_ACKNOWLEDGMENT_VERSION; kind: "ACKNOWLEDGMENT";
  result: Readonly<{ kind: "SIMULATED_SUBMISSION"; submissionReference: ContentHash }>;
}>;
export type PortableLocalPacketAdapterAcknowledgment = Readonly<EvidenceIdentityFor<typeof LOCAL_EVIDENCE_PACKET_ADAPTER_ID> & {
  schemaVersion: typeof PORTABLE_ADAPTER_ACKNOWLEDGMENT_VERSION; kind: "ACKNOWLEDGMENT";
  result: Readonly<{ kind: "LOCAL_PACKET_CREATED"; manifestDigest: Readonly<{ algorithm: "sha256"; value: ContentHash }> }>;
}>;
export type LocalSyntheticEndpointStateAcknowledgment = Readonly<EvidenceIdentityFor<typeof LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID> & {
  schemaVersion: typeof LOCAL_SYNTHETIC_ENDPOINT_STATE_ACKNOWLEDGMENT_VERSION; kind: "ACKNOWLEDGMENT";
  result: Readonly<{ kind: "LOCAL_ENDPOINT_STATE_CHANGED"; transitionDigest: Readonly<{ algorithm: "keccak256"; value: ContentHash }> }>;
}>;
export type LocalDocumentReleaseAcknowledgment = Readonly<EvidenceIdentityFor<typeof LOCAL_DOCUMENT_RELEASE_ADAPTER_ID> & {
  schemaVersion: typeof LOCAL_DOCUMENT_RELEASE_ACKNOWLEDGMENT_VERSION; kind: "ACKNOWLEDGMENT";
  result: Readonly<{ kind: "LOCAL_DOCUMENT_RELEASED"; publicationManifestDigest: Readonly<{ algorithm: "sha256"; value: ContentHash }> }>;
}>;
/** Adapter-retained provider report digest only; not external truth, success, settlement or cancellation. */
export type RemoteServiceReportAcknowledgment = Readonly<EvidenceIdentityFor<typeof REMOTE_SERVICE_REPORT_ADAPTER_ID> & {
  schemaVersion: typeof REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION; kind: "ACKNOWLEDGMENT";
  result: Readonly<{ kind: "REMOTE_SERVICE_REPORTED"; reportDigest: Readonly<{ algorithm: "sha256"; value: ContentHash }> }>;
}>;
export type PortableAdapterAcknowledgment = RemoteServiceReportAcknowledgment | LocalDocumentReleaseAcknowledgment | PortableSimulatedAdapterAcknowledgment | PortableLocalPacketAdapterAcknowledgment | LocalSyntheticEndpointStateAcknowledgment;
export type PortableAdapterNoEffect = Readonly<EvidenceIdentity & {
  schemaVersion: typeof PORTABLE_ADAPTER_NO_EFFECT_VERSION; kind: "NO_EFFECT";
  result: Readonly<{ kind: "SIMULATED_NO_EFFECT"; reference: ContentHash }>;
}>;
export type PortableAdapterExternalEvidence = Readonly<{
  kind: "EXTERNAL"; evidenceType: typeof PORTABLE_ADAPTER_ACKNOWLEDGMENT_VERSION | typeof REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION | typeof LOCAL_DOCUMENT_RELEASE_ACKNOWLEDGMENT_VERSION | typeof LOCAL_SYNTHETIC_ENDPOINT_STATE_ACKNOWLEDGMENT_VERSION | typeof PORTABLE_ADAPTER_NO_EFFECT_VERSION;
  reference: string; attesterId: AdapterId;
}>;

/** One raw descriptor-only snapshot. No getter/setter or second caller read. */
const snapshot = (input: unknown): unknown => {
  const active = createWeakSet<object>();
  let units = 0;
  const string = (value: string): void => {
    if (value.length > 4096) throw new HostTypeError("Adapter input exceeds its finite bound.");
    units += utf8Encode(value).length;
    if (units > 4096) throw new HostTypeError("Adapter input exceeds its finite bound.");
  };
  const visit = (value: unknown, depth: number): unknown => {
    if (++units > 4096 || depth > 16) throw new HostTypeError("Adapter input exceeds its finite bound.");
    if (typeof value === "string") { string(value); return value; }
    if (value === null || value === undefined || typeof value === "boolean" || typeof value === "number") return value;
    if ((typeof value === "object" || typeof value === "function") && isProxy(value)) throw new HostTypeError("Proxy adapter input is unsupported.");
    if (typeof value !== "object" || arrayIsArray(value)) throw new HostTypeError("Adapter fields must be data records or scalars.");
    const prototype = reflectGetPrototypeOf(value);
    if (prototype !== null && prototype !== hostObjectPrototype) throw new HostTypeError("Adapter records must be plain.");
    if (weakSetHas(active, value)) throw new HostTypeError("Cyclic adapter data.");
    const keys = reflectOwnKeys(value);
    if (keys.length > 256) throw new HostTypeError("Adapter record has too many fields.");
    weakSetAdd(active, value);
    try {
      const copy = objectCreate(null) as Record<string, unknown>;
      for (let index = 0; index < keys.length; index++) {
        const key = keys[index]!;
        if (typeof key !== "string") throw new HostTypeError("Adapter keys must be strings.");
        string(key);
        const descriptor = reflectGetOwnPropertyDescriptor(value, key);
        if (descriptor === undefined || !objectHasOwn(descriptor, "value") || descriptor.enumerable !== true ||
            objectHasOwn(descriptor, "get") || objectHasOwn(descriptor, "set")) throw new HostTypeError("Adapter accessors/nonenumerable fields are unsupported.");
        objectDefineDataProperty(copy, key, visit(descriptor.value, depth + 1), false, true);
      }
      return objectFreeze(copy);
    } finally { weakSetDelete(active, value); }
  };
  return visit(input, 0);
};

/** Only captured snapshots are inspected below. Original undefined keys may not disappear. */
const capture = (value: unknown): unknown => {
  const captured = captureBoundedCanonicalValue(snapshot(value), { maxCanonicalBytes: MAX_PORTABLE_ADAPTER_EVIDENCE_BYTES });
  const inspect = (node: unknown): void => {
    if (node === null || typeof node !== "object") return;
    if (arrayIsArray(node)) {
      for (let index = 0; index < node.length; index++) inspect(node[index]);
      return;
    }
    const keys = captured.capturedRecordKeys(node);
    if (keys === undefined) throw new HostTypeError("Missing adapter capture provenance.");
    for (let index = 0; index < keys.length; index++) {
      const key = keys[index]!;
      if (!objectHasOwn(node, key)) throw new HostTypeError("Undefined adapter fields are not permitted.");
      inspect((node as Record<string, unknown>)[key]);
    }
  };
  inspect(captured.value);
  return captured.value;
};
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !arrayIsArray(value);
const closed = (value: unknown, keys: readonly string[]): value is Record<string, unknown> => {
  if (!record(value) || objectEntries(value).length !== keys.length) return false;
  for (let index = 0; index < keys.length; index++) if (!objectHasOwn(value, keys[index]!)) return false;
  return true;
};
const same = (left: unknown, right: unknown): boolean => canonicalEncode(left) === canonicalEncode(right);
export const isLocalPacketManifestReference = (value: unknown): value is ContentHash => typeof value === "string" && regExpTest(/^0x[0-9a-f]{64}$/, value);
const identifier = (value: unknown): value is string => typeof value === "string" && value.length > 0 && utf8Encode(value).length <= 256 && !regExpTest(/[\u0000-\u001f\u007f]/u, value);
const u53 = (value: unknown): value is number => typeof value === "number" && numberIsSafeInteger(value) && value >= 0 && !objectIs(value, -0);
export const validatePortableAdapterProfile = (value: unknown): value is PortableAdapterProfile => {
  try {
    const v = capture(value);
    return closed(v, ["profileId", "profileVersion", "descriptorHash"]) && same(v, approvedPortableAdapterProfile(v.profileId));
  } catch { return false; }
};
export const validatePortableAdapterProfileForPolicy = (hash: unknown, value: unknown): value is PortableAdapterProfile => {
  try {
    const v = capture(value);
    return closed(v, ["profileId", "profileVersion", "descriptorHash"]) && same(v, approvedPortableAdapterProfileForPolicy(hash, v.profileId));
  } catch { return false; }
};
/** @internal Shape-only recognition is deliberately distinct from genesis membership. */
export const validateKnownPortableAdapterProfile = (value: unknown): value is PortableAdapterProfile => {
  try {
    const v = capture(value);
    return closed(v, ["profileId", "profileVersion", "descriptorHash"]) && same(v, knownPortableAdapterProfile(v.profileId));
  } catch { return false; }
};
const domainValid = (value: unknown): value is PortableAuthorizationDomain =>
  closed(value, ["protocol", "version", "deploymentId", "chainId", "verifyingContract"]) &&
  value.protocol === "continuity" && value.version === "0.2" && identifier(value.deploymentId) &&
  typeof value.chainId === "string" && value.chainId.length <= 78 && regExpTest(/^[1-9][0-9]*$/, value.chainId) &&
  bigintFrom(value.chainId) <= (1n << 256n) - 1n &&
  typeof value.verifyingContract === "string" && regExpTest(/^0x[0-9a-fA-F]{40}$/, value.verifyingContract);
export const derivePortableAdapterIdempotencyKey = (domain: PortableAuthorizationDomain, intentId: string): ContentHash => hashCanonical([
  PORTABLE_ADAPTER_IDEMPOTENCY_VERSION, domain.protocol, domain.version, domain.deploymentId,
  domain.chainId, stringToLowerCase(domain.verifyingContract), intentId,
]);
export const derivePortableAdapterNoEffectReference = (idempotencyKey: ContentHash, submissionFingerprint: ContentHash): ContentHash => hashCanonical([
  PORTABLE_ADAPTER_NO_EFFECT_VERSION, SIMULATED_ADAPTER_ID, idempotencyKey, submissionFingerprint,
]);
const identitySnapshot = (identity: unknown): PortableAdapterIdentity => {
  const v = capture(identity);
  if (!record(v)) throw new HostTypeError("Adapter identity must be a record.");
  const keys = ["idempotencyKey", "submissionFingerprint", "durableEventHistoryHash", "adapterNoEffectReference", "adapterProfile", "domain", "intentId", "admissionHead"];
  if (objectHasOwn(v, "operationVersion")) {
    if (v.operationVersion !== PORTABLE_ADAPTER_SUBMISSION_VERSION) throw new HostTypeError("Wrong adapter identity operation version.");
    arrayPush(keys, "operationVersion");
  }
  if (!closed(v, keys) || !validateKnownPortableAdapterProfile(v.adapterProfile) || !domainValid(v.domain) || !identifier(v.intentId) ||
      !closed(v.admissionHead, ["hash", "position", "canonicalTime"]) || !isLocalPacketManifestReference(v.admissionHead.hash) ||
      !u53(v.admissionHead.position) || !u53(v.admissionHead.canonicalTime) ||
      !isLocalPacketManifestReference(v.submissionFingerprint) || v.durableEventHistoryHash !== v.admissionHead.hash ||
      v.idempotencyKey !== derivePortableAdapterIdempotencyKey(v.domain, v.intentId) ||
      v.adapterNoEffectReference !== derivePortableAdapterNoEffectReference(v.idempotencyKey as ContentHash, v.submissionFingerprint)) {
    throw new HostTypeError("Invalid or inconsistent adapter identity.");
  }
  return v as unknown as PortableAdapterIdentity;
};
/** Internal: profile comes from the already accepted declaration, not an unsigned caller default. */
export const derivePortableAdapterIdentityForAcceptedAdmission = (
  admissionEvent: AcceptedCanonicalEventShape, admissionHead: PortableAdapterHistoryHead, adapterProfile: PortableAdapterProfile,
  adapterPolicyHash: ContentHash,
): PortableAdapterIdentity => {
  if (admissionEvent.type !== "TRANSACTION_INTENT_ADMITTED" || admissionHead.canonicalTime !== admissionEvent.timestamp || !validatePortableAdapterProfileForPolicy(adapterPolicyHash, adapterProfile)) {
    throw new HostTypeError("Adapter identity requires an accepted admission, inclusive head and declared profile.");
  }
  const data = admissionEvent.data as unknown as { intentId: string; authorizationProof: { domain: PortableAuthorizationDomain } };
  const domain = data.authorizationProof.domain, intentId = data.intentId;
  const idempotencyKey = derivePortableAdapterIdempotencyKey(domain, intentId);
  const submissionFingerprint = hashCanonical({ version: PORTABLE_ADAPTER_SUBMISSION_VERSION, intentId, admissionEvent, durableEventHistoryHash: admissionHead.hash });
  return objectFreeze({ idempotencyKey, submissionFingerprint, durableEventHistoryHash: admissionHead.hash,
    adapterNoEffectReference: derivePortableAdapterNoEffectReference(idempotencyKey, submissionFingerprint),
    adapterProfile: approvedPortableAdapterProfileForPolicy(adapterPolicyHash, adapterProfile.profileId), domain, intentId, admissionHead });
};
const evidenceIdentity = (identity: PortableAdapterIdentity): EvidenceIdentity => objectFreeze({
  adapterProfile: identity.adapterProfile, domain: identity.domain, intentId: identity.intentId,
  admissionHead: identity.admissionHead, idempotencyKey: identity.idempotencyKey, submissionFingerprint: identity.submissionFingerprint,
});
export const createPortableAdapterAcknowledgment = (identity: PortableAdapterIdentity, transactionReference?: string): PortableAdapterAcknowledgment => {
  const i = identitySnapshot(identity);
  let result: PortableAdapterAcknowledgment["result"];
  if (i.adapterProfile.profileId === SIMULATED_ADAPTER_ID) {
    if (transactionReference !== undefined && transactionReference !== i.submissionFingerprint) throw new HostTypeError("Simulator reference must equal its fingerprint.");
    result = objectFreeze({ kind: "SIMULATED_SUBMISSION", submissionReference: i.submissionFingerprint });
  } else if (i.adapterProfile.profileId === LOCAL_EVIDENCE_PACKET_ADAPTER_ID) {
    if (!isLocalPacketManifestReference(transactionReference)) throw new HostTypeError("Local packet ACK requires an exact SHA-256 manifest reference.");
    result = objectFreeze({ kind: "LOCAL_PACKET_CREATED", manifestDigest: objectFreeze({ algorithm: "sha256", value: transactionReference }) });
  } else {
    throw new HostTypeError("Local endpoint state requires its separately versioned acknowledgment constructor.");
  }
  return capture(objectFreeze({ schemaVersion: PORTABLE_ADAPTER_ACKNOWLEDGMENT_VERSION, kind: "ACKNOWLEDGMENT", ...evidenceIdentity(i), result })) as PortableAdapterAcknowledgment;
};
/** Digest syntax/identity only; the executor/reader must verify the retained canonical transition. */
export const createLocalSyntheticEndpointStateAcknowledgment = (
  identity: PortableAdapterIdentity, transitionDigest: ContentHash,
): LocalSyntheticEndpointStateAcknowledgment => {
  const i = identitySnapshot(identity);
  if (i.adapterProfile.profileId !== LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID || !isLocalPacketManifestReference(transitionDigest)) {
    throw new HostTypeError("Local endpoint state ACK requires its exact profile and a Keccak-256 transition digest.");
  }
  return capture(objectFreeze({ schemaVersion: LOCAL_SYNTHETIC_ENDPOINT_STATE_ACKNOWLEDGMENT_VERSION, kind: "ACKNOWLEDGMENT",
    ...evidenceIdentity(i), result: objectFreeze({ kind: "LOCAL_ENDPOINT_STATE_CHANGED",
      transitionDigest: objectFreeze({ algorithm: "keccak256", value: transitionDigest }) }) })) as LocalSyntheticEndpointStateAcknowledgment;
};
/** Digest syntax/identity only; external artifact inspection establishes retained publication. */
export const createLocalDocumentReleaseAcknowledgment = (
  identity: PortableAdapterIdentity, publicationManifestDigest: ContentHash,
): LocalDocumentReleaseAcknowledgment => {
  const i = identitySnapshot(identity);
  if (i.adapterProfile.profileId !== LOCAL_DOCUMENT_RELEASE_ADAPTER_ID || !isLocalPacketManifestReference(publicationManifestDigest) || publicationManifestDigest.length !== 66) {
    throw new HostTypeError("Local document release ACK requires its exact profile and a SHA-256 publication manifest digest.");
  }
  return capture(objectFreeze({ schemaVersion: LOCAL_DOCUMENT_RELEASE_ACKNOWLEDGMENT_VERSION, kind: "ACKNOWLEDGMENT",
    ...evidenceIdentity(i), result: objectFreeze({ kind: "LOCAL_DOCUMENT_RELEASED",
      publicationManifestDigest: objectFreeze({ algorithm: "sha256", value: publicationManifestDigest }) }) })) as LocalDocumentReleaseAcknowledgment;
};
/** Digest syntax/identity only. The adapter retains the provider report; its truth and effect remain separate. */
export const createRemoteServiceReportAcknowledgment = (
  identity: PortableAdapterIdentity, reportDigest: ContentHash,
): RemoteServiceReportAcknowledgment => {
  const i = identitySnapshot(identity);
  if (i.adapterProfile.profileId !== REMOTE_SERVICE_REPORT_ADAPTER_ID || !isLocalPacketManifestReference(reportDigest) || reportDigest.length !== 66) {
    throw new HostTypeError("Remote service report ACK requires its exact profile and a SHA-256 report digest.");
  }
  return capture(objectFreeze({ schemaVersion: REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION, kind: "ACKNOWLEDGMENT",
    ...evidenceIdentity(i), result: objectFreeze({ kind: "REMOTE_SERVICE_REPORTED",
      reportDigest: objectFreeze({ algorithm: "sha256", value: reportDigest }) }) })) as RemoteServiceReportAcknowledgment;
};
export const createPortableAdapterNoEffect = (identity: PortableAdapterIdentity): PortableAdapterNoEffect => {
  const i = identitySnapshot(identity);
  if (i.adapterProfile.profileId !== SIMULATED_ADAPTER_ID) throw new HostTypeError("Local packet profile cannot establish no effect.");
  return capture(objectFreeze({ schemaVersion: PORTABLE_ADAPTER_NO_EFFECT_VERSION, kind: "NO_EFFECT", ...evidenceIdentity(i),
    result: objectFreeze({ kind: "SIMULATED_NO_EFFECT", reference: i.adapterNoEffectReference }) })) as PortableAdapterNoEffect;
};
const localReference = (value: unknown): string | undefined => {
  if (!record(value) || !record(value.result) || !record(value.result.manifestDigest)) return undefined;
  return typeof value.result.manifestDigest.value === "string" ? value.result.manifestDigest.value : undefined;
};
export const validatePortableAdapterAcknowledgment = (value: unknown, identity: PortableAdapterIdentity): boolean => {
  try {
    const v = capture(value), i = identitySnapshot(identity);
    switch (i.adapterProfile.profileId) {
      case REMOTE_SERVICE_REPORT_ADAPTER_ID: {
        if (!record(v) || !record(v.result) || !record(v.result.reportDigest) || !isLocalPacketManifestReference(v.result.reportDigest.value)) return false;
        return same(v, createRemoteServiceReportAcknowledgment(i, v.result.reportDigest.value));
      }
      case SIMULATED_ADAPTER_ID: return same(v, createPortableAdapterAcknowledgment(i));
      case LOCAL_EVIDENCE_PACKET_ADAPTER_ID: return same(v, createPortableAdapterAcknowledgment(i, localReference(v)));
      case LOCAL_DOCUMENT_RELEASE_ADAPTER_ID: {
        if (!record(v) || !record(v.result) || !record(v.result.publicationManifestDigest) || !isLocalPacketManifestReference(v.result.publicationManifestDigest.value)) return false;
        return same(v, createLocalDocumentReleaseAcknowledgment(i, v.result.publicationManifestDigest.value));
      }
      case LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID: {
        if (!record(v) || !record(v.result) || !record(v.result.transitionDigest) || !isLocalPacketManifestReference(v.result.transitionDigest.value)) return false;
        return same(v, createLocalSyntheticEndpointStateAcknowledgment(i, v.result.transitionDigest.value));
      }
      default: return false;
    }
  } catch { return false; }
};
/** Validate the complete paired ACK against the admitted identity before projecting its reference. */
export const portableAdapterAcknowledgmentTransactionReference = (
  value: unknown, identity: PortableAdapterIdentity,
): ContentHash => {
  const captured = capture(value), i = identitySnapshot(identity);
  if (!validatePortableAdapterAcknowledgment(captured, i)) throw new HostTypeError("ACK does not match admitted identity.");
  const ack = captured as PortableAdapterAcknowledgment;
  switch (ack.result.kind) {
    case "SIMULATED_SUBMISSION": return ack.result.submissionReference;
    case "LOCAL_PACKET_CREATED": return ack.result.manifestDigest.value;
    case "LOCAL_DOCUMENT_RELEASED": return ack.result.publicationManifestDigest.value;
    case "LOCAL_ENDPOINT_STATE_CHANGED": return ack.result.transitionDigest.value;
    case "REMOTE_SERVICE_REPORTED": return ack.result.reportDigest.value;
    default: throw new HostTypeError("Unsupported adapter acknowledgment result.");
  }
};
export const validatePortableAdapterNoEffect = (value: unknown, identity: PortableAdapterIdentity): boolean => {
  try { return same(capture(value), createPortableAdapterNoEffect(identity)); } catch { return false; }
};
/** Shape-only checks for captured schemas: these do not authenticate an admission. */
const shapeIdentity = (v: unknown): PortableAdapterIdentity => {
  if (!record(v) || !record(v.admissionHead) || !isLocalPacketManifestReference(v.idempotencyKey) || !isLocalPacketManifestReference(v.submissionFingerprint)) throw new HostTypeError("Malformed evidence identity.");
  return identitySnapshot({ adapterProfile: v.adapterProfile, domain: v.domain, intentId: v.intentId,
    admissionHead: v.admissionHead, idempotencyKey: v.idempotencyKey, submissionFingerprint: v.submissionFingerprint,
    durableEventHistoryHash: v.admissionHead.hash, adapterNoEffectReference: derivePortableAdapterNoEffectReference(v.idempotencyKey, v.submissionFingerprint) });
};
export const validatePortableAdapterAcknowledgmentShape = (value: unknown): boolean => {
  try { const v = capture(value); return validatePortableAdapterAcknowledgment(v, shapeIdentity(v)); } catch { return false; }
};
export const validatePortableAdapterNoEffectShape = (value: unknown): boolean => {
  try { const v = capture(value); return validatePortableAdapterNoEffect(v, shapeIdentity(v)); } catch { return false; }
};
export const portableAdapterAcknowledgmentEvidence = (identity: PortableAdapterIdentity, acknowledgment: PortableAdapterAcknowledgment): PortableAdapterExternalEvidence => {
  const i = identitySnapshot(identity), ack = capture(acknowledgment);
  if (!validatePortableAdapterAcknowledgment(ack, i)) throw new HostTypeError("ACK does not match admitted identity.");
  return objectFreeze({ kind: "EXTERNAL", evidenceType: (ack as PortableAdapterAcknowledgment).schemaVersion, reference: hashCanonical(ack), attesterId: i.adapterProfile.profileId });
};
export const portableAdapterNoEffectEvidence = (identity: PortableAdapterIdentity, noEffect: PortableAdapterNoEffect): PortableAdapterExternalEvidence => {
  const i = identitySnapshot(identity), value = capture(noEffect);
  if (!validatePortableAdapterNoEffect(value, i)) throw new HostTypeError("No-effect data does not match admitted simulator identity.");
  return objectFreeze({ kind: "EXTERNAL", evidenceType: PORTABLE_ADAPTER_NO_EFFECT_VERSION, reference: hashCanonical(value), attesterId: SIMULATED_ADAPTER_ID });
};
export const samePortableAdapterEvidence = (left: Readonly<Record<string, unknown>>, right: PortableAdapterExternalEvidence): boolean =>
  left.kind === right.kind && left.evidenceType === right.evidenceType && left.reference === right.reference && left.attesterId === right.attesterId;
