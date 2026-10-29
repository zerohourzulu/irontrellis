/**
 * Adapter editions E1–E6: the fixed adapter profiles a genesis may select, the
 * adapter identity derived for an accepted admission, and the acknowledgment /
 * no-effect shapes replay validates on consumption, outcome and observation
 * events (spec 03 §H, spec 01 §F.2–F.5, §D.11).
 *
 * Policy and descriptor hashes are keccak constants: they are *identifiers*
 * chosen once in Continuity and stay byte-identical in every format. Values
 * derived per history (idempotency key, submission fingerprint, no-effect
 * reference, evidence references) use the history's hash algorithm, which the
 * authorization domain determines: `continuity` → keccak-256, `irontrellis` →
 * sha256.
 */
import { types as nodeTypes } from "node:util";
import { canonicalEncode, captureValue } from "./canonical.ts";
import { hashCanonical } from "./hash.ts";
import { EngineError } from "./errors.ts";
import type { AdapterProfile, AuthorizationDomain, CanonicalEvent, ContentHash, HashAlgorithm, HistoryHead } from "./types.ts";

export const ADAPTER_IDEMPOTENCY_VERSION = "continuity-adapter-idempotency/0.2";
export const ADAPTER_SUBMISSION_VERSION = "continuity-adapter-submission/0.2";
export const ADAPTER_NO_EFFECT_VERSION = "continuity-adapter-no-effect/0.2";
export const ADAPTER_ACKNOWLEDGMENT_VERSION = "continuity-adapter-acknowledgment/0.2";
export const ADAPTER_POLICY_SCHEMA_VERSION = "continuity-adapter-policy/0.2";
export const SIMULATED_ADAPTER_ID = "adapter:simulated";
export const LOCAL_EVIDENCE_PACKET_ADAPTER_ID = "adapter:local-evidence-packet";
export const LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID = "adapter:local-synthetic-endpoint-state";
export const LOCAL_SYNTHETIC_ENDPOINT_STATE_ACKNOWLEDGMENT_VERSION = "continuity-local-endpoint-state-ack/1";
export const LOCAL_DOCUMENT_RELEASE_ADAPTER_ID = "adapter:local-document-release";
export const LOCAL_DOCUMENT_RELEASE_ACKNOWLEDGMENT_VERSION = "continuity-local-document-release-ack/1";
export const REMOTE_SERVICE_REPORT_ADAPTER_ID = "adapter:remote-service-report";
export const REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION = "continuity-remote-service-report-ack/1";
export const ATTEMPT_OBSERVATION_DUTY_EXTENSION = "continuity-attempt-observation-duty/1";
export const ATTEMPT_DUTY_REVIEW_EXTENSION = "continuity-attempt-duty-review/1";
export const MAX_ADAPTER_EVIDENCE_BYTES = 4096;

export type AdapterId =
  | typeof SIMULATED_ADAPTER_ID
  | typeof LOCAL_EVIDENCE_PACKET_ADAPTER_ID
  | typeof LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID
  | typeof LOCAL_DOCUMENT_RELEASE_ADAPTER_ID
  | typeof REMOTE_SERVICE_REPORT_ADAPTER_ID;
export type AdapterEdition = "E1" | "E2" | "E3" | "E4" | "E5" | "E6";
export type AdapterDescriptor = Readonly<{
  profileId: AdapterId;
  profileVersion: "1";
  acknowledgmentSchemaVersion: string;
  replayRuleId: string;
}>;
export type AdapterPolicy = Readonly<{
  edition: AdapterEdition;
  hash: ContentHash;
  profiles: readonly AdapterProfile[];
  semanticExtension?: string;
  semanticExtensions?: readonly string[];
}>;
export type AdapterIdentity = Readonly<{
  idempotencyKey: ContentHash;
  submissionFingerprint: ContentHash;
  durableEventHistoryHash: ContentHash;
  adapterNoEffectReference: ContentHash;
  adapterProfile: AdapterProfile;
  domain: AuthorizationDomain;
  intentId: string;
  admissionHead: HistoryHead;
}>;
export type AdapterExternalEvidence = Readonly<{ kind: "EXTERNAL"; evidenceType: string; reference: ContentHash; attesterId: AdapterId }>;
export type AdapterAcknowledgment = Readonly<Record<string, unknown>> & Readonly<{ schemaVersion: string; result: Readonly<Record<string, unknown>> }>;
export type AdapterNoEffect = Readonly<Record<string, unknown>>;

// ---------------------------------------------------------------- descriptors, profiles, policies

const descriptor = (profileId: AdapterId, acknowledgmentSchemaVersion: string, rule: string): AdapterDescriptor =>
  Object.freeze({ profileId, profileVersion: "1", acknowledgmentSchemaVersion, replayRuleId: `continuity-adapter-replay/${rule}/1` });
const PACKET = descriptor(LOCAL_EVIDENCE_PACKET_ADAPTER_ID, ADAPTER_ACKNOWLEDGMENT_VERSION, "local-packet");
const SIMULATED = descriptor(SIMULATED_ADAPTER_ID, ADAPTER_ACKNOWLEDGMENT_VERSION, "simulated");
const ENDPOINT_STATE = descriptor(LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID, LOCAL_SYNTHETIC_ENDPOINT_STATE_ACKNOWLEDGMENT_VERSION, "local-endpoint-state");
const DOCUMENT_RELEASE = descriptor(LOCAL_DOCUMENT_RELEASE_ADAPTER_ID, LOCAL_DOCUMENT_RELEASE_ACKNOWLEDGMENT_VERSION, "local-document-release");
const REMOTE_REPORT = descriptor(REMOTE_SERVICE_REPORT_ADAPTER_ID, REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION, "remote-service-report");
export const ADAPTER_DESCRIPTORS: Readonly<Record<AdapterId, AdapterDescriptor>> = Object.freeze({
  [LOCAL_EVIDENCE_PACKET_ADAPTER_ID]: PACKET,
  [SIMULATED_ADAPTER_ID]: SIMULATED,
  [LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID]: ENDPOINT_STATE,
  [LOCAL_DOCUMENT_RELEASE_ADAPTER_ID]: DOCUMENT_RELEASE,
  [REMOTE_SERVICE_REPORT_ADAPTER_ID]: REMOTE_REPORT,
});

const profileOf = (d: AdapterDescriptor): AdapterProfile =>
  Object.freeze({ profileId: d.profileId, profileVersion: "1", descriptorHash: hashCanonical(d, "keccak256") });
const PROFILES: Readonly<Record<AdapterId, AdapterProfile>> = Object.freeze({
  [LOCAL_EVIDENCE_PACKET_ADAPTER_ID]: profileOf(PACKET),
  [SIMULATED_ADAPTER_ID]: profileOf(SIMULATED),
  [LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID]: profileOf(ENDPOINT_STATE),
  [LOCAL_DOCUMENT_RELEASE_ADAPTER_ID]: profileOf(DOCUMENT_RELEASE),
  [REMOTE_SERVICE_REPORT_ADAPTER_ID]: profileOf(REMOTE_REPORT),
});
const isAdapterId = (value: unknown): value is AdapterId => typeof value === "string" && Object.hasOwn(PROFILES, value);

// Descriptor order inside each edition is part of the hashed bytes: keep it.
const E4_DESCRIPTORS = Object.freeze([DOCUMENT_RELEASE, PACKET, ENDPOINT_STATE, REMOTE_REPORT, SIMULATED]);
const policy = (edition: AdapterEdition, descriptors: readonly AdapterDescriptor[], extra: Readonly<Record<string, unknown>> = {}): AdapterPolicy =>
  Object.freeze({
    edition,
    hash: hashCanonical({ schemaVersion: ADAPTER_POLICY_SCHEMA_VERSION, profiles: descriptors, ...extra }, "keccak256"),
    profiles: Object.freeze(descriptors.map((d) => PROFILES[d.profileId])),
    ...extra,
  }) as AdapterPolicy;
const E6_EXTENSIONS = Object.freeze([ATTEMPT_OBSERVATION_DUTY_EXTENSION, ATTEMPT_DUTY_REVIEW_EXTENSION]);
const POLICIES: readonly AdapterPolicy[] = Object.freeze([
  policy("E1", [PACKET, SIMULATED]),
  policy("E2", [PACKET, ENDPOINT_STATE, SIMULATED]),
  policy("E3", [DOCUMENT_RELEASE, PACKET, ENDPOINT_STATE, SIMULATED]),
  policy("E4", E4_DESCRIPTORS),
  policy("E5", E4_DESCRIPTORS, { semanticExtension: ATTEMPT_OBSERVATION_DUTY_EXTENSION }),
  policy("E6", E4_DESCRIPTORS, { semanticExtensions: E6_EXTENSIONS }),
]);
export const ADAPTER_POLICY_HASHES: Readonly<Record<AdapterEdition, ContentHash>> = Object.freeze({
  E1: POLICIES[0]!.hash, E2: POLICIES[1]!.hash, E3: POLICIES[2]!.hash, E4: POLICIES[3]!.hash, E5: POLICIES[4]!.hash, E6: POLICIES[5]!.hash,
});
export const ADAPTER_POLICY_HASH = ADAPTER_POLICY_HASHES.E1;
export const ADAPTER_POLICY_E2_HASH = ADAPTER_POLICY_HASHES.E2;
export const ADAPTER_POLICY_E3_HASH = ADAPTER_POLICY_HASHES.E3;
export const ADAPTER_POLICY_E4_HASH = ADAPTER_POLICY_HASHES.E4;
export const ADAPTER_POLICY_E5_HASH = ADAPTER_POLICY_HASHES.E5;
export const ADAPTER_POLICY_E6_HASH = ADAPTER_POLICY_HASHES.E6;

/** Exact genesis selector: unknown or missing values never select a default. */
export const resolveAdapterPolicy = (hash: unknown): AdapterPolicy | undefined => POLICIES.find((p) => p.hash === hash);
export const policyEnablesAttemptDuties = (hash: unknown): boolean => hash === ADAPTER_POLICY_E5_HASH || hash === ADAPTER_POLICY_E6_HASH;
export const policyEnablesAttemptReviews = (hash: unknown): boolean => hash === ADAPTER_POLICY_E6_HASH;

export const approvedAdapterProfileForPolicy = (hash: unknown, profileId: unknown): AdapterProfile => {
  const found = resolveAdapterPolicy(hash)?.profiles.find((p) => p.profileId === profileId);
  if (found === undefined) throw new EngineError("ADAPTER_PROFILE_UNKNOWN", "Profile is not a member of the selected fixed adapter policy.");
  return found;
};
/** E1-only helper kept for API parity: packet and simulated profiles. */
export const approvedAdapterProfile = (profileId: unknown): AdapterProfile => approvedAdapterProfileForPolicy(ADAPTER_POLICY_HASH, profileId);
/** Configuration only, never history authority: any of the five profiles. */
export const knownAdapterProfile = (profileId: unknown): AdapterProfile => {
  if (!isAdapterId(profileId)) throw new EngineError("ADAPTER_PROFILE_UNKNOWN", "Unsupported fixed adapter profile.");
  return PROFILES[profileId];
};
export const knownAdapterAcknowledgmentVersion = (profile: unknown): string => {
  const v = captureAdapterValue(profile);
  if (!closed(v, PROFILE_KEYS) || !same(v, knownAdapterProfile(v.profileId))) {
    throw new EngineError("ADAPTER_PROFILE_UNKNOWN", "Unsupported adapter profile tuple.");
  }
  return ADAPTER_DESCRIPTORS[v.profileId as AdapterId].acknowledgmentSchemaVersion;
};

// ---------------------------------------------------------------- adapter input capture (spec 03 §H.3)

const isProxy = nodeTypes.isProxy;
const ASCII = /^[\x00-\x7f]*$/;
const utf8Length = (s: string): number => (ASCII.test(s) ? s.length : Buffer.byteLength(s, "utf8"));

/**
 * Descriptor-only snapshot of adapter evidence: plain records and scalars only
 * (no arrays, proxies, accessors, non-enumerable or undefined fields), ≤ 256
 * keys per record, depth ≤ 16, ≤ 4096 units, then a strict canonical capture
 * bounded to 4096 canonical bytes. Throws on any violation.
 */
export const captureAdapterValue = (input: unknown): unknown => {
  const active = new WeakSet<object>();
  let units = 0;
  const fail = (message: string): never => { throw new EngineError("ADAPTER_INPUT_INVALID", message); };
  const string = (value: string): void => {
    if (value.length > MAX_ADAPTER_EVIDENCE_BYTES) fail("Adapter input exceeds its finite bound.");
    units += utf8Length(value);
    if (units > MAX_ADAPTER_EVIDENCE_BYTES) fail("Adapter input exceeds its finite bound.");
  };
  const visit = (value: unknown, depth: number): unknown => {
    if (++units > MAX_ADAPTER_EVIDENCE_BYTES || depth > 16) fail("Adapter input exceeds its finite bound.");
    if (typeof value === "string") { string(value); return value; }
    if (value === undefined) fail("Undefined adapter fields are not permitted.");
    if (value === null || typeof value === "boolean" || typeof value === "number") return value;
    if ((typeof value === "object" || typeof value === "function") && isProxy(value)) fail("Proxy adapter input is unsupported.");
    if (typeof value !== "object" || Array.isArray(value)) fail("Adapter fields must be data records or scalars.");
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== null && prototype !== Object.prototype) fail("Adapter records must be plain.");
    if (active.has(value as object)) fail("Cyclic adapter data.");
    const keys = Reflect.ownKeys(value as object);
    if (keys.length > 256) fail("Adapter record has too many fields.");
    active.add(value as object);
    try {
      const copy: Record<string, unknown> = {};
      for (const key of keys) {
        if (typeof key !== "string") fail("Adapter keys must be strings.");
        string(key as string);
        const d = Reflect.getOwnPropertyDescriptor(value as object, key);
        if (d === undefined || !Object.hasOwn(d, "value") || d.enumerable !== true) fail("Adapter accessors/nonenumerable fields are unsupported.");
        copy[key as string] = visit(d!.value, depth + 1);
      }
      return copy;
    } finally {
      active.delete(value as object);
    }
  };
  return captureValue(visit(input, 0), { maxTotalBytes: MAX_ADAPTER_EVIDENCE_BYTES });
};

type Rec = Record<string, unknown>;
const record = (value: unknown): value is Rec => value !== null && typeof value === "object" && !Array.isArray(value);
const closed = (value: unknown, keys: readonly string[]): value is Rec =>
  record(value) && Object.keys(value).length === keys.length && keys.every((k) => Object.hasOwn(value, k));
const same = (left: unknown, right: unknown): boolean => canonicalEncode(left) === canonicalEncode(right);
const PROFILE_KEYS = ["profileId", "profileVersion", "descriptorHash"] as const;
const HEAD_KEYS = ["hash", "position", "canonicalTime"] as const;
const HEX64 = /^0x[0-9a-f]{64}$/;
export const isLocalPacketManifestReference = (value: unknown): value is ContentHash => typeof value === "string" && HEX64.test(value);
const identifier = (value: unknown): value is string =>
  typeof value === "string" && value.length > 0 && utf8Length(value) <= 256 && !/[\u0000-\u001f\u007f]/u.test(value);
const u53 = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0);
const guarded = (check: () => boolean): boolean => { try { return check(); } catch { return false; } };

export const validateAdapterProfile = (value: unknown): value is AdapterProfile =>
  guarded(() => { const v = captureAdapterValue(value); return closed(v, PROFILE_KEYS) && same(v, approvedAdapterProfile(v.profileId)); });
export const validateAdapterProfileForPolicy = (hash: unknown, value: unknown): value is AdapterProfile =>
  guarded(() => { const v = captureAdapterValue(value); return closed(v, PROFILE_KEYS) && same(v, approvedAdapterProfileForPolicy(hash, v.profileId)); });
/** Shape-only recognition, deliberately distinct from genesis membership. */
export const validateKnownAdapterProfile = (value: unknown): value is AdapterProfile =>
  guarded(() => { const v = captureAdapterValue(value); return closed(v, PROFILE_KEYS) && same(v, knownAdapterProfile(v.profileId)); });

// ---------------------------------------------------------------- domains and derived identity values

const MAX_CHAIN = (1n << 256n) - 1n;
const legacyDomainValid = (v: Rec): boolean =>
  closed(v, ["protocol", "version", "deploymentId", "chainId", "verifyingContract"]) &&
  v.protocol === "continuity" && v.version === "0.2" && identifier(v.deploymentId) &&
  typeof v.chainId === "string" && v.chainId.length <= 78 && /^[1-9][0-9]*$/.test(v.chainId) && BigInt(v.chainId) <= MAX_CHAIN &&
  typeof v.verifyingContract === "string" && /^0x[0-9a-fA-F]{40}$/.test(v.verifyingContract);
const trellisDomainValid = (v: Rec): boolean =>
  closed(v, ["protocol", "version", "deploymentId"]) && v.protocol === "irontrellis" && (v.version === "1" || v.version === "2") && identifier(v.deploymentId);
export const validateAdapterDomain = (value: unknown): value is AuthorizationDomain =>
  record(value) && (value.protocol === "irontrellis" ? trellisDomainValid(value) : legacyDomainValid(value));
/** The hash algorithm a domain's history uses: format 1 histories are sha256, legacy keccak-256. */
export const hashAlgorithmForDomain = (domain: Readonly<{ protocol?: unknown }>): HashAlgorithm =>
  domain.protocol === "irontrellis" ? "sha256" : "keccak256";

export const deriveAdapterIdempotencyKey = (domain: AuthorizationDomain, intentId: string): ContentHash => {
  const algorithm = hashAlgorithmForDomain(domain);
  return "verifyingContract" in domain
    ? hashCanonical([ADAPTER_IDEMPOTENCY_VERSION, domain.protocol, domain.version, domain.deploymentId, domain.chainId, domain.verifyingContract.toLowerCase(), intentId], algorithm)
    : hashCanonical([ADAPTER_IDEMPOTENCY_VERSION, domain.protocol, domain.version, domain.deploymentId, intentId], algorithm);
};
export const deriveAdapterNoEffectReference = (idempotencyKey: ContentHash, submissionFingerprint: ContentHash, algorithm: HashAlgorithm): ContentHash =>
  hashCanonical([ADAPTER_NO_EFFECT_VERSION, SIMULATED_ADAPTER_ID, idempotencyKey, submissionFingerprint], algorithm);

const IDENTITY_KEYS = ["idempotencyKey", "submissionFingerprint", "durableEventHistoryHash", "adapterNoEffectReference", "adapterProfile", "domain", "intentId", "admissionHead"];
/** Validated snapshots of frozen identities (the ones replay stores) are reused: an identity is checked once per history. */
const VALIDATED_IDENTITIES = new WeakMap<object, AdapterIdentity>();
const identitySnapshot = (identity: unknown): AdapterIdentity => {
  const cacheable = identity !== null && typeof identity === "object" && Object.isFrozen(identity);
  const cached = cacheable ? VALIDATED_IDENTITIES.get(identity as object) : undefined;
  if (cached !== undefined) return cached;
  const v = captureAdapterValue(identity);
  const invalid = (): never => { throw new EngineError("ADAPTER_IDENTITY_INVALID", "Invalid or inconsistent adapter identity."); };
  if (!record(v)) invalid();
  const keys = [...IDENTITY_KEYS];
  if (Object.hasOwn(v as Rec, "operationVersion")) {
    if ((v as Rec).operationVersion !== ADAPTER_SUBMISSION_VERSION) invalid();
    keys.push("operationVersion");
  }
  const i = v as Rec;
  if (!closed(i, keys) || !validateKnownAdapterProfile(i.adapterProfile) || !validateAdapterDomain(i.domain) || !identifier(i.intentId) ||
      !closed(i.admissionHead, HEAD_KEYS) || !isLocalPacketManifestReference(i.admissionHead.hash) ||
      !u53(i.admissionHead.position) || !u53(i.admissionHead.canonicalTime) ||
      !isLocalPacketManifestReference(i.submissionFingerprint) || i.durableEventHistoryHash !== i.admissionHead.hash ||
      i.idempotencyKey !== deriveAdapterIdempotencyKey(i.domain, i.intentId) ||
      i.adapterNoEffectReference !== deriveAdapterNoEffectReference(i.idempotencyKey as ContentHash, i.submissionFingerprint, hashAlgorithmForDomain(i.domain))) {
    invalid();
  }
  const snapshot = i as unknown as AdapterIdentity;
  if (cacheable) VALIDATED_IDENTITIES.set(identity as object, snapshot);
  return snapshot;
};

/** The identity of an accepted admission; `admissionHead` is the head *including* the admission event. */
export const deriveAdapterIdentityForAcceptedAdmission = (
  admissionEvent: CanonicalEvent, admissionHead: HistoryHead, adapterProfile: AdapterProfile, adapterPolicyHash: ContentHash,
): AdapterIdentity => {
  if (admissionEvent.type !== "TRANSACTION_INTENT_ADMITTED" || admissionHead.canonicalTime !== admissionEvent.timestamp ||
      !validateAdapterProfileForPolicy(adapterPolicyHash, adapterProfile)) {
    throw new EngineError("ADAPTER_IDENTITY_INVALID", "Adapter identity requires an accepted admission, inclusive head and declared profile.");
  }
  const data = admissionEvent.data as { intentId: string; authorizationProof: { domain: AuthorizationDomain } };
  const domain = data.authorizationProof.domain;
  const algorithm = hashAlgorithmForDomain(domain);
  const idempotencyKey = deriveAdapterIdempotencyKey(domain, data.intentId);
  const submissionFingerprint = hashCanonical(
    { version: ADAPTER_SUBMISSION_VERSION, intentId: data.intentId, admissionEvent, durableEventHistoryHash: admissionHead.hash }, algorithm);
  return Object.freeze({
    idempotencyKey, submissionFingerprint, durableEventHistoryHash: admissionHead.hash,
    adapterNoEffectReference: deriveAdapterNoEffectReference(idempotencyKey, submissionFingerprint, algorithm),
    adapterProfile: approvedAdapterProfileForPolicy(adapterPolicyHash, adapterProfile.profileId),
    domain, intentId: data.intentId, admissionHead,
  });
};

// ---------------------------------------------------------------- acknowledgment and no-effect shapes (spec 03 §H.5)

const evidenceIdentity = (i: AdapterIdentity): Rec => ({
  adapterProfile: i.adapterProfile, domain: i.domain, intentId: i.intentId,
  admissionHead: i.admissionHead, idempotencyKey: i.idempotencyKey, submissionFingerprint: i.submissionFingerprint,
});
const ackOf = (schemaVersion: string, i: AdapterIdentity, result: Rec): AdapterAcknowledgment =>
  captureAdapterValue({ schemaVersion, kind: "ACKNOWLEDGMENT", ...evidenceIdentity(i), result }) as AdapterAcknowledgment;
const noEffectOf = (i: AdapterIdentity): AdapterNoEffect => {
  if (i.adapterProfile.profileId !== SIMULATED_ADAPTER_ID) throw new EngineError("ADAPTER_INPUT_INVALID", "Only the simulated profile can establish no effect.");
  return captureAdapterValue({ schemaVersion: ADAPTER_NO_EFFECT_VERSION, kind: "NO_EFFECT", ...evidenceIdentity(i),
    result: { kind: "SIMULATED_NO_EFFECT", reference: i.adapterNoEffectReference } }) as AdapterNoEffect;
};
type AckShape = Readonly<{ schemaVersion: string; kind: string; digestKey: string; algorithm: string; message: string }>;
const ACK_SHAPES: Readonly<Record<AdapterId, AckShape>> = Object.freeze({
  [SIMULATED_ADAPTER_ID]: { schemaVersion: ADAPTER_ACKNOWLEDGMENT_VERSION, kind: "SIMULATED_SUBMISSION", digestKey: "submissionReference", algorithm: "", message: "Simulator reference must equal its fingerprint." },
  [LOCAL_EVIDENCE_PACKET_ADAPTER_ID]: { schemaVersion: ADAPTER_ACKNOWLEDGMENT_VERSION, kind: "LOCAL_PACKET_CREATED", digestKey: "manifestDigest", algorithm: "sha256", message: "Local packet ACK requires an exact SHA-256 manifest reference." },
  [LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID]: { schemaVersion: LOCAL_SYNTHETIC_ENDPOINT_STATE_ACKNOWLEDGMENT_VERSION, kind: "LOCAL_ENDPOINT_STATE_CHANGED", digestKey: "transitionDigest", algorithm: "keccak256", message: "Local endpoint state ACK requires its exact profile and a Keccak-256 transition digest." },
  [LOCAL_DOCUMENT_RELEASE_ADAPTER_ID]: { schemaVersion: LOCAL_DOCUMENT_RELEASE_ACKNOWLEDGMENT_VERSION, kind: "LOCAL_DOCUMENT_RELEASED", digestKey: "publicationManifestDigest", algorithm: "sha256", message: "Local document release ACK requires its exact profile and a SHA-256 publication manifest digest." },
  [REMOTE_SERVICE_REPORT_ADAPTER_ID]: { schemaVersion: REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION, kind: "REMOTE_SERVICE_REPORTED", digestKey: "reportDigest", algorithm: "sha256", message: "Remote service report ACK requires its exact profile and a SHA-256 report digest." },
});
/** The acknowledgment the identity's profile prescribes for `digest` (the fingerprint itself for the simulator). */
const expectedAck = (i: AdapterIdentity, digest: unknown): AdapterAcknowledgment => {
  const shape = ACK_SHAPES[i.adapterProfile.profileId as AdapterId];
  if (shape === undefined || !isLocalPacketManifestReference(digest)) throw new EngineError("ADAPTER_INPUT_INVALID", shape?.message ?? "Unsupported adapter profile.");
  const result = shape.algorithm === "" ? { kind: shape.kind, [shape.digestKey]: digest } : { kind: shape.kind, [shape.digestKey]: { algorithm: shape.algorithm, value: digest } };
  return ackOf(shape.schemaVersion, i, result);
};
const digestFor = (profileId: AdapterId, digest: unknown) => (identity: unknown): AdapterAcknowledgment => {
  const i = identitySnapshot(identity);
  if (i.adapterProfile.profileId !== profileId) throw new EngineError("ADAPTER_INPUT_INVALID", ACK_SHAPES[profileId].message);
  return expectedAck(i, digest);
};

export const createAdapterAcknowledgment = (identity: unknown, transactionReference?: string): AdapterAcknowledgment => {
  const i = identitySnapshot(identity);
  if (i.adapterProfile.profileId === SIMULATED_ADAPTER_ID) {
    if (transactionReference !== undefined && transactionReference !== i.submissionFingerprint) throw new EngineError("ADAPTER_INPUT_INVALID", ACK_SHAPES[SIMULATED_ADAPTER_ID].message);
    return expectedAck(i, i.submissionFingerprint);
  }
  if (i.adapterProfile.profileId === LOCAL_EVIDENCE_PACKET_ADAPTER_ID) return expectedAck(i, transactionReference);
  throw new EngineError("ADAPTER_INPUT_INVALID", "This profile requires its separately versioned acknowledgment constructor.");
};
export const createLocalSyntheticEndpointStateAcknowledgment = (identity: unknown, transitionDigest: unknown): AdapterAcknowledgment =>
  digestFor(LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID, transitionDigest)(identity);
export const createLocalDocumentReleaseAcknowledgment = (identity: unknown, publicationManifestDigest: unknown): AdapterAcknowledgment =>
  digestFor(LOCAL_DOCUMENT_RELEASE_ADAPTER_ID, publicationManifestDigest)(identity);
export const createRemoteServiceReportAcknowledgment = (identity: unknown, reportDigest: unknown): AdapterAcknowledgment =>
  digestFor(REMOTE_SERVICE_REPORT_ADAPTER_ID, reportDigest)(identity);
export const createAdapterNoEffect = (identity: unknown): AdapterNoEffect => noEffectOf(identitySnapshot(identity));

/** The digest a captured acknowledgment carries in its result, when structurally present. */
const carriedDigest = (v: unknown, shape: AckShape): unknown => {
  if (!record(v) || !record(v.result)) return undefined;
  const slot = v.result[shape.digestKey];
  return shape.algorithm === "" ? slot : record(slot) ? slot.value : undefined;
};
export type AdapterAcknowledgmentEvaluation = Readonly<{ acknowledgment: AdapterAcknowledgment; transactionReference: ContentHash; evidence: AdapterExternalEvidence }>;
/**
 * Validates an acknowledgment against an identity once and returns everything
 * replay needs from it: the captured value, its transaction reference and the
 * EXTERNAL evidence it produces. Undefined when the acknowledgment is not the
 * one the identity's profile prescribes (canonical equality, spec 03 §H.5).
 */
export const evaluateAdapterAcknowledgment = (value: unknown, identity: unknown): AdapterAcknowledgmentEvaluation | undefined => {
  try {
    const v = captureAdapterValue(value), i = identitySnapshot(identity);
    const shape = ACK_SHAPES[i.adapterProfile.profileId as AdapterId];
    if (shape === undefined) return undefined;
    const digest = i.adapterProfile.profileId === SIMULATED_ADAPTER_ID ? i.submissionFingerprint : carriedDigest(v, shape);
    if (!isLocalPacketManifestReference(digest) || !same(v, expectedAck(i, digest))) return undefined;
    const acknowledgment = v as AdapterAcknowledgment;
    return Object.freeze({
      acknowledgment, transactionReference: digest,
      evidence: Object.freeze({ kind: "EXTERNAL" as const, evidenceType: acknowledgment.schemaVersion, reference: hashCanonical(v, hashAlgorithmForDomain(i.domain)), attesterId: i.adapterProfile.profileId as AdapterId }),
    });
  } catch { return undefined; }
};
export const validateAdapterAcknowledgment = (value: unknown, identity: unknown): boolean => evaluateAdapterAcknowledgment(value, identity) !== undefined;
/** The transaction reference an acknowledgment carries; throws unless the ACK matches the identity. */
export const adapterAcknowledgmentTransactionReference = (value: unknown, identity: unknown): ContentHash => {
  const evaluation = evaluateAdapterAcknowledgment(value, identity);
  if (evaluation === undefined) throw new EngineError("ADAPTER_ACKNOWLEDGMENT_INVALID", "ACK does not match admitted identity.");
  return evaluation.transactionReference;
};
export const adapterAcknowledgmentEvidence = (identity: unknown, acknowledgment: unknown): AdapterExternalEvidence => {
  const evaluation = evaluateAdapterAcknowledgment(acknowledgment, identity);
  if (evaluation === undefined) throw new EngineError("ADAPTER_ACKNOWLEDGMENT_INVALID", "ACK does not match admitted identity.");
  return evaluation.evidence;
};
export type AdapterNoEffectEvaluation = Readonly<{ noEffect: AdapterNoEffect; evidence: AdapterExternalEvidence }>;
export const evaluateAdapterNoEffect = (value: unknown, identity: unknown): AdapterNoEffectEvaluation | undefined => {
  try {
    const v = captureAdapterValue(value), i = identitySnapshot(identity);
    if (!same(v, noEffectOf(i))) return undefined;
    return Object.freeze({ noEffect: v as AdapterNoEffect, evidence: Object.freeze({
      kind: "EXTERNAL" as const, evidenceType: ADAPTER_NO_EFFECT_VERSION, reference: hashCanonical(v, hashAlgorithmForDomain(i.domain)), attesterId: SIMULATED_ADAPTER_ID }) });
  } catch { return undefined; }
};
export const validateAdapterNoEffect = (value: unknown, identity: unknown): boolean => evaluateAdapterNoEffect(value, identity) !== undefined;
export const adapterNoEffectEvidence = (identity: unknown, noEffect: unknown): AdapterExternalEvidence => {
  const evaluation = evaluateAdapterNoEffect(noEffect, identity);
  if (evaluation === undefined) throw new EngineError("ADAPTER_ACKNOWLEDGMENT_INVALID", "No-effect data does not match admitted simulator identity.");
  return evaluation.evidence;
};

/** Shape-only identity rebuilt from the evidence's own fields; it authenticates no admission. */
const shapeIdentity = (v: unknown): AdapterIdentity => {
  if (!record(v) || !record(v.admissionHead) || !isLocalPacketManifestReference(v.idempotencyKey) || !isLocalPacketManifestReference(v.submissionFingerprint) ||
      !record(v.domain)) {
    throw new EngineError("ADAPTER_IDENTITY_INVALID", "Malformed evidence identity.");
  }
  return identitySnapshot({
    adapterProfile: v.adapterProfile, domain: v.domain, intentId: v.intentId, admissionHead: v.admissionHead,
    idempotencyKey: v.idempotencyKey, submissionFingerprint: v.submissionFingerprint, durableEventHistoryHash: v.admissionHead.hash,
    adapterNoEffectReference: deriveAdapterNoEffectReference(v.idempotencyKey, v.submissionFingerprint, hashAlgorithmForDomain(v.domain)),
  });
};
export const validateAdapterAcknowledgmentShape = (value: unknown): boolean =>
  guarded(() => { const v = captureAdapterValue(value); return validateAdapterAcknowledgment(v, shapeIdentity(v)); });
export const validateAdapterNoEffectShape = (value: unknown): boolean =>
  guarded(() => { const v = captureAdapterValue(value); return validateAdapterNoEffect(v, shapeIdentity(v)); });
export const sameAdapterEvidence = (left: Readonly<Record<string, unknown>>, right: AdapterExternalEvidence): boolean =>
  left.kind === right.kind && left.evidenceType === right.evidenceType && left.reference === right.reference && left.attesterId === right.attesterId;
