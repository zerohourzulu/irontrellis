/**
 * Receipts (spec 03 §G, spec 04 §C.2): the signed artifact a runtime issues for
 * a consumed intent, its verification along eight independent axes, the
 * RECEIPT_RECORDED record proposal and the artifact commitment.
 *
 * The payload hashes with the history's algorithm (selected by the payload's
 * domain) and is signed with the issuer session's credential scheme.
 */
import { canonicalEncode, captureValue, CanonicalError, compareProtocolStrings, isIdentifier, isU53, isContentHash, isAmount, isAmountString, wireAmounts } from "./canonical.ts";
import { sessionExpiredAt } from "./session-auth.ts";
import { hashCanonical, hashEventHistoryPrefixes } from "./hash.ts";
import { detectFormat, replay as replayEvents, withProspectiveEvent } from "./replay.ts";
import { evaluateReceiptPolicy } from "./authority.ts";
import { suiteFor, recoverContentHashSigner } from "./crypto/suites.ts";
import {
  SIMULATED_ADAPTER_ID, REMOTE_SERVICE_REPORT_ADAPTER_ID, LOCAL_EVIDENCE_PACKET_ADAPTER_ID, LOCAL_DOCUMENT_RELEASE_ADAPTER_ID,
  LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID, hashAlgorithmForDomain, validateAdapterAcknowledgmentShape, validateKnownAdapterProfile, type AdapterAcknowledgment,
} from "./adapter-editions.ts";
import { isDomain, isHead, sameDomain, sameHead, type ReplayFn } from "./admission.ts";
import { EVENT_TYPES, type AuthorizationDomain, type AuthorizationProof, type CanonicalEvent, type ContentHash, type EvidenceReference, type HashAlgorithm, type HexSignature, type HistoryHead, type ReplayState, type SignatureScheme, type TransactionIntent, type U53 } from "./types.ts";

export const RECEIPT_VERIFICATION_VERSION = "continuity-receipt-verification/0.2" as const;
export const RECEIPT_RECORD_ADMISSION_VERSION = "continuity-receipt-record-admission/0.2" as const;
export const RECEIPT_ARTIFACT_COMMITMENT_TAG = "continuity-receipt-artifact-commitment/0.2" as const;
/** SPEC §8.5: the commitment tag of a format-2 (`irontrellis-receipt/2`) artifact; `/0.2` and `/1` artifacts keep the legacy tag. */
export const RECEIPT_ARTIFACT_COMMITMENT_TAG_2 = "irontrellis-receipt-artifact-commitment/2" as const;
export const RECEIPT_SCHEMA_VERSION_2 = "irontrellis-receipt/2" as const;
const commitmentTagOf = (schemaVersion: unknown): string => (schemaVersion === RECEIPT_SCHEMA_VERSION_2 ? RECEIPT_ARTIFACT_COMMITMENT_TAG_2 : RECEIPT_ARTIFACT_COMMITMENT_TAG);
/** A format-2 artifact spells Amounts as decimal strings (SPEC §3.4); the others carry bigints. */
const amountShaped = (v: unknown, schemaVersion: unknown): boolean => (schemaVersion === RECEIPT_SCHEMA_VERSION_2 ? isAmountString(v) : isAmount(v));
export const RECEIPT_LIMITATIONS = Object.freeze(["NO_CANONICAL_ISSUANCE_WITNESS", "NO_PUBLIC_FINALITY_PROOF", "NO_EXTERNAL_OUTCOME_PROOF"] as const);
export const RECEIPT_AXIS_CODES = Object.freeze([
  "CONTENT_HASH_MATCH", "CONTENT_HASH_MISMATCH", "SIGNATURE_VALID", "SIGNATURE_INVALID", "ISSUER_AUTHENTICATED", "ISSUER_NOT_AUTHENTICATED",
  "HISTORICAL_AUTHORIZATION_VALID", "HISTORICAL_AUTHORIZATION_INVALID", "RECORDED_HASH_MATCH", "RECORDED_POSITION_MISMATCH", "RECORD_NOT_AVAILABLE",
  "LOCAL_ONLY", "NOT_PROVEN", "SIMULATED", "CURRENT", "STALE", "VERIFIER_TIME_BEHIND_OBSERVED_HEAD", "FUTURE_ISSUANCE", "DEPENDENCY_FAILED",
  "DEPENDENCY_UNAVAILABLE", "DOMAIN_MISMATCH", "RECEIPT_FIELDS_MISMATCH", "SUBMISSION_EVIDENCE_MISSING", "ISSUANCE_HISTORY_UNVERIFIED", "OBSERVED_HISTORY_DIVERGES",
] as const);
export type ReceiptLimitation = (typeof RECEIPT_LIMITATIONS)[number];
export type ReceiptAxisCode = (typeof RECEIPT_AXIS_CODES)[number];
export type ReceiptAxisStatus = "PASS" | "FAIL" | "UNAVAILABLE" | "UNVERIFIED";
export type ReceiptAxis = Readonly<{ status: ReceiptAxisStatus; primaryCode: ReceiptAxisCode; causes: readonly [ReceiptAxisCode, ...ReceiptAxisCode[]]; evidence: readonly EvidenceReference[] }>;
export type ReceiptPayload = Readonly<{
  schemaVersion: string; signatureScheme: SignatureScheme; domain: AuthorizationDomain;
  issuer: Readonly<{ keyId: string; agentId: string; runtimeSessionId: string; controlEpoch: U53; roleId: string; roleTenureId: string }>;
  intent: TransactionIntent;
  authorization: Readonly<{ authorizationTime: U53; policyVersion: string; rootRecognitionPolicy: string; historyHead: HistoryHead; proof: AuthorizationProof }>;
  issuance: Readonly<{ historyHead: HistoryHead; issuedAt: U53 }>;
  result: Readonly<{ status: "SUBMITTED"; consumptionEventId: string; adapterId: string; idempotencyKey: ContentHash; submissionFingerprint: ContentHash; transactionReference: string; acknowledgment: AdapterAcknowledgment }>;
  assurance: Readonly<{ finality: "LOCAL_ONLY"; freshness: "CURRENT_AT_ISSUANCE"; externalOutcome: "NOT_PROVEN" | "SIMULATED" }>;
}>;
export type ReceiptArtifact = Readonly<{ payload: ReceiptPayload; contentHash: ContentHash; signature: HexSignature }>;
export type ReceiptVerificationInput = Readonly<{ operationVersion: typeof RECEIPT_VERIFICATION_VERSION; artifact: ReceiptArtifact; issuanceEvents: readonly CanonicalEvent[]; observedEvents: readonly CanonicalEvent[]; expectedDomain: AuthorizationDomain; verifierTime: U53 }>;
export type ReceiptVerificationEvaluated = Readonly<{
  operationVersion: typeof RECEIPT_VERIFICATION_VERSION; status: "EVALUATED";
  contentIntegrity: ReceiptAxis; signaturePossession: ReceiptAxis; issuerAuthentication: ReceiptAxis; historicalAuthorization: ReceiptAxis;
  canonicalInclusion: ReceiptAxis; finality: ReceiptAxis; freshness: ReceiptAxis; externalOutcome: ReceiptAxis;
  authentic: boolean; historical: boolean; valid: boolean; current: boolean; limitations: readonly ReceiptLimitation[];
}>;
export type ReceiptVerificationIndeterminate = Readonly<{ operationVersion: typeof RECEIPT_VERIFICATION_VERSION; status: "INDETERMINATE";
  code: "INVALID_INPUT" | "MALFORMED_ARTIFACT" | "UNSUPPORTED_RECEIPT_VERSION" | "UNSUPPORTED_VERSION" | "STATE_NOT_AUTHORITATIVE" | "OUTPUT_LIMIT_EXCEEDED"; limitations: readonly ReceiptLimitation[] }>;
export type ReceiptVerificationResult = ReceiptVerificationEvaluated | ReceiptVerificationIndeterminate;
export type ReceiptRecordAdmissionInput = Readonly<{ operationVersion: typeof RECEIPT_RECORD_ADMISSION_VERSION; artifact: ReceiptArtifact; events: readonly CanonicalEvent[]; expectedHistoryHead: HistoryHead; expectedDomain: AuthorizationDomain; recordEventId: string }>;
export type ReceiptRecordAdmissionResult =
  | Readonly<{ operationVersion: typeof RECEIPT_RECORD_ADMISSION_VERSION; status: "ADMITTED"; recordEvent: CanonicalEvent; newHead: HistoryHead; verification: ReceiptVerificationEvaluated }>
  | Readonly<{ operationVersion: typeof RECEIPT_RECORD_ADMISSION_VERSION; status: "REJECTED"; verification: ReceiptVerificationEvaluated }>
  | Readonly<{ operationVersion: typeof RECEIPT_RECORD_ADMISSION_VERSION; status: "INDETERMINATE"; code: "INVALID_INPUT" | "UNSUPPORTED_VERSION" | "STATE_NOT_AUTHORITATIVE" | "OUTPUT_LIMIT_EXCEEDED"; verification?: ReceiptVerificationIndeterminate }>
  | Readonly<{ operationVersion: typeof RECEIPT_RECORD_ADMISSION_VERSION; status: "CONFLICT"; expectedHead: HistoryHead; observedHead: HistoryHead }>;
export type ReceiptRecordProposal =
  | Exclude<ReceiptRecordAdmissionResult, { status: "ADMITTED" }>
  | Readonly<{ operationVersion: typeof RECEIPT_RECORD_ADMISSION_VERSION; status: "PROPOSED"; expectedHead: HistoryHead; recordEvent: CanonicalEvent; newHead: HistoryHead; verification: ReceiptVerificationEvaluated }>;
export type CreateReceiptInput = Readonly<{ events: readonly CanonicalEvent[]; intentId: string; issuedAt: U53; externalOutcome: "NOT_PROVEN" | "SIMULATED" }>;
export type ReceiptSigner = Readonly<{ keyId: string; signHash: (hash: ContentHash) => Promise<HexSignature> }>;

type Rec = Record<string, unknown>;
const isRecord = (v: unknown): v is Rec => v !== null && typeof v === "object" && !Array.isArray(v);
const closed = (v: unknown, required: readonly string[], optional: readonly string[] = []): v is Rec =>
  isRecord(v) && required.every((k) => Object.hasOwn(v, k)) && Object.keys(v).every((k) => required.includes(k) || optional.includes(k));
const same = (a: unknown, b: unknown): boolean => canonicalEncode(a) === canonicalEncode(b);
const SUPPORTED_PAIRS: readonly (readonly [string, string])[] = [
  ["continuity-receipt/0.2", "eip191-personal-sign-keccak256"], ["irontrellis-receipt/1", "ed25519"], ["irontrellis-receipt/1", "eip191-personal-sign-keccak256"],
  [RECEIPT_SCHEMA_VERSION_2, "ed25519"], [RECEIPT_SCHEMA_VERSION_2, "eip191-personal-sign-keccak256"],
];
const PROOF_KEYS = ["proofVersion", "domain", "policyVersion", "rootRecognitionPolicy", "historyHead", "evaluationTime", "request", "recognizedRoot", "permissionPath", "intersections", "effectiveConstraints", "controllingAuthorityIds", "usageSnapshot", "authorityEvidence", "checkedProhibitionIds", "consequential"];
const PROOF_RUNTIME_KEYS = ["runtimeSessionId", "credentialKeyId", "controlEpoch", "roleId", "roleTenureId", "intentId", "nonce"];
const isIntent = (v: unknown, schemaVersion: unknown): v is TransactionIntent =>
  closed(v, ["adapterProfile", "intentId", "nonce", "actorId", "action", "resource", "roleId", "roleTenureId"], schemaVersion === RECEIPT_SCHEMA_VERSION_2 ? ["amount", "counterpartyId", "termsCommitment", "metric"] : ["amount", "counterpartyId", "termsCommitment"]) &&
  validateKnownAdapterProfile(v.adapterProfile) && ["intentId", "nonce", "actorId", "action", "resource", "roleId", "roleTenureId"].every((k) => isIdentifier(v[k])) &&
  (!Object.hasOwn(v, "amount") || amountShaped(v.amount, schemaVersion)) && (!Object.hasOwn(v, "counterpartyId") || isIdentifier(v.counterpartyId)) && (!Object.hasOwn(v, "termsCommitment") || isContentHash(v.termsCommitment)) &&
  (!Object.hasOwn(v, "metric") || isIdentifier(v.metric));
const isProof = (v: unknown, schemaVersion: unknown): v is AuthorizationProof =>
  closed(v, PROOF_KEYS, PROOF_RUNTIME_KEYS) && isDomain(v.domain) && isIdentifier(v.policyVersion) && isHead(v.historyHead) && isU53(v.evaluationTime) &&
  closed(v.request, ["actorId", "action", "resource", "claimedAt"], schemaVersion === RECEIPT_SCHEMA_VERSION_2 ? ["amount", "counterpartyId", "termsCommitment", "metric"] : ["amount", "counterpartyId", "termsCommitment"]) && typeof v.consequential === "boolean" &&
  Array.isArray(v.permissionPath) && v.permissionPath.length > 0 && Array.isArray(v.controllingAuthorityIds) && Array.isArray(v.intersections) && isRecord(v.recognizedRoot);

/** Closed-shape validation of an artifact; the payload's version pair selects support. */
export const validateReceiptArtifact = (v: unknown): "VALID" | "INVALID" | "UNSUPPORTED" => {
  if (!closed(v, ["payload", "contentHash", "signature"]) || !isContentHash(v.contentHash) || typeof v.signature !== "string") return "INVALID";
  const p = v.payload;
  if (!isRecord(p) || !isIdentifier(p.schemaVersion) || !isIdentifier(p.signatureScheme)) return "INVALID";
  if (!SUPPORTED_PAIRS.some(([schema, scheme]) => schema === p.schemaVersion && scheme === p.signatureScheme)) return "UNSUPPORTED";
  const ok = closed(p, ["schemaVersion", "signatureScheme", "domain", "issuer", "intent", "authorization", "issuance", "result", "assurance"]) &&
    suiteFor(p.signatureScheme as SignatureScheme).isSignature(v.signature) && isDomain(p.domain) &&
    closed(p.issuer, ["keyId", "agentId", "runtimeSessionId", "controlEpoch", "roleId", "roleTenureId"]) &&
    ["keyId", "agentId", "runtimeSessionId", "roleId", "roleTenureId"].every((k) => isIdentifier((p.issuer as Rec)[k])) && isU53((p.issuer as Rec).controlEpoch) &&
    isIntent(p.intent, p.schemaVersion) &&
    closed(p.authorization, ["authorizationTime", "policyVersion", "rootRecognitionPolicy", "historyHead", "proof"]) &&
    isU53((p.authorization as Rec).authorizationTime) && isIdentifier((p.authorization as Rec).policyVersion) && (p.authorization as Rec).rootRecognitionPolicy === "declared-principal-root/0.2" &&
    isHead((p.authorization as Rec).historyHead) && isProof((p.authorization as Rec).proof, p.schemaVersion) &&
    closed(p.issuance, ["historyHead", "issuedAt"]) && isHead((p.issuance as Rec).historyHead) && isU53((p.issuance as Rec).issuedAt) &&
    closed(p.result, ["status", "consumptionEventId", "adapterId", "idempotencyKey", "submissionFingerprint", "transactionReference", "acknowledgment"]) &&
    (p.result as Rec).status === "SUBMITTED" && ["consumptionEventId", "adapterId", "transactionReference"].every((k) => isIdentifier((p.result as Rec)[k])) &&
    isContentHash((p.result as Rec).idempotencyKey) && isContentHash((p.result as Rec).submissionFingerprint) && validateAdapterAcknowledgmentShape((p.result as Rec).acknowledgment) &&
    closed(p.assurance, ["finality", "freshness", "externalOutcome"]) && (p.assurance as Rec).finality === "LOCAL_ONLY" && (p.assurance as Rec).freshness === "CURRENT_AT_ISSUANCE" &&
    ((p.assurance as Rec).externalOutcome === "NOT_PROVEN" || (p.assurance as Rec).externalOutcome === "SIMULATED");
  return ok ? "VALID" : "INVALID";
};

export const receiptRecordDataForArtifact = (artifact: ReceiptArtifact, algorithm: HashAlgorithm = hashAlgorithmForDomain(artifact.payload.domain)) => Object.freeze({
  receiptContentHash: artifact.contentHash,
  receiptArtifactCommitment: hashCanonical([commitmentTagOf(artifact.payload.schemaVersion), artifact.contentHash, artifact.signature], algorithm),
  intentId: artifact.payload.intent.intentId, issuerAgentId: artifact.payload.issuer.agentId, runtimeSessionId: artifact.payload.issuer.runtimeSessionId,
  controlEpoch: artifact.payload.issuer.controlEpoch, roleId: artifact.payload.issuer.roleId, roleTenureId: artifact.payload.issuer.roleTenureId,
  authorizationProofHash: hashCanonical(artifact.payload.authorization.proof, algorithm),
});
/** Valid-shape-only commitment derivation; never content integrity or authority. */
export const receiptArtifactCommitment = (artifact: unknown): ContentHash => {
  const value = captureValue(artifact), status = validateReceiptArtifact(value);
  if (status !== "VALID") throw new TypeError(`Invalid portable receipt artifact: ${status}.`);
  const accepted = value as ReceiptArtifact;
  return hashCanonical([commitmentTagOf(accepted.payload.schemaVersion), accepted.contentHash, accepted.signature], hashAlgorithmForDomain(accepted.payload.domain));
};

// ---------------------------------------------------------------- verification (spec 03 §G.3)
type Source = Readonly<{ events: readonly CanonicalEvent[]; hashes: readonly ContentHash[] }>;
type Plan = Readonly<{ source: Source; position: number }>;
type Policy = ReturnType<typeof evaluateReceiptPolicy>;
const plan = (source: Source, position: number): Plan[] => position >= 0 && position < source.events.length ? [{ source, position }] : [];
const planKey = (p: Plan): string => { const e = p.source.events[p.position] as CanonicalEvent; return canonicalEncode([e.id, e.type, p.position, p.source.hashes[p.position]]); };
const union = (...groups: readonly (readonly Plan[])[]): Plan[] => { const m = new Map<string, Plan>(); for (const g of groups) for (const p of g) m.set(planKey(p), p); return [...m.values()]; };
const bindHead = (source: Source, items: readonly Plan[]): Plan[] => union(items, plan(source, source.events.length - 1));
const controlEvidence = (source: Source, state: ReplayState, issuer: ReceiptPayload["issuer"], time: U53): Plan[] => {
  const items: Plan[] = []; let latestEpoch = -1, firstFailure = -1;
  source.events.forEach((e, position) => {
    const d = e.data;
    if (e.type === "AGENT_CREATED" && d.agentId === issuer.agentId) { items.push(...plan(source, position)); latestEpoch = position; }
    if (e.type === "RUNTIME_SESSION_ADMITTED" && d.sessionId === issuer.runtimeSessionId) items.push(...plan(source, position));
    if (e.type === "ROLE_CREATED" && d.roleId === issuer.roleId) items.push(...plan(source, position));
    if ((e.type === "AGENT_APPOINTED" && d.roleTenureId === issuer.roleTenureId) || (e.type === "ROLE_TRANSFERRED" && d.toRoleTenureId === issuer.roleTenureId)) items.push(...plan(source, position));
    if (e.type === "CONTROL_EPOCH_ADVANCED" && d.agentId === issuer.agentId) latestEpoch = position;
    const failure = (e.type === "AGENT_TERMINATED" && d.agentId === issuer.agentId) ||
      (e.type === "CONTROL_EPOCH_ADVANCED" && d.agentId === issuer.agentId && typeof d.toEpoch === "number" && d.toEpoch > issuer.controlEpoch) ||
      (e.type === "AGENT_UNAPPOINTED" && d.roleTenureId === issuer.roleTenureId) || (e.type === "ROLE_TRANSFERRED" && d.fromRoleTenureId === issuer.roleTenureId);
    if (failure && firstFailure < 0) firstFailure = position;
  });
  items.push(...plan(source, latestEpoch), ...plan(source, firstFailure));
  const session = state.runtimeSessions.get(issuer.runtimeSessionId);
  if (session?.expiresAt !== undefined && time >= session.expiresAt) items.push(...plan(source, session.admissionEventPosition));
  return bindHead(source, items);
};
const authorityEvidence = (source: Source, state: ReplayState, proof: AuthorizationProof, policy: Policy): Plan[] => {
  const items: Plan[] = [], records = state.authorities;
  for (const named of proof.authorityEvidence) {
    const r = records.get(named.authorityId);
    if (r !== undefined && r.grantEventId === named.grantEventId && r.grantEventPosition === named.grantEventPosition) items.push(...plan(source, r.grantEventPosition));
  }
  for (const id of new Set([...proof.checkedProhibitionIds, ...policy.checkedProhibitionIds])) {
    const r = records.get(id);
    if (r === undefined) continue;
    items.push(...plan(source, r.grantEventPosition));
    if (r.grant.kind === "PROHIBITION" && r.revocationEventPosition !== undefined) items.push(...plan(source, r.revocationEventPosition));
  }
  for (const id of policy.decisiveAuthorityIds) {
    const r = records.get(id);
    if (r === undefined) continue;
    items.push(...plan(source, r.grantEventPosition));
    if (r.revocationEventPosition !== undefined) items.push(...plan(source, r.revocationEventPosition));
  }
  for (const id of policy.decisiveAgentIds) items.push(...plan(source, source.events.findIndex((e) => e.type === "AGENT_TERMINATED" && e.data.agentId === id)));
  return bindHead(source, items);
};
const intentEvidence = (source: Source, intentId: string): Plan[] => bindHead(source, source.events.flatMap((e, position) =>
  (e.type === "TRANSACTION_INTENT_DECLARED" || e.type === "TRANSACTION_INTENT_ADMITTED" || e.type === "TRANSACTION_INTENT_CONSUMED") && e.data.intentId === intentId ? plan(source, position) : []));
const materialize = (items: readonly Plan[]): readonly EvidenceReference[] => Object.freeze(items
  .map(({ source, position }): EvidenceReference => { const e = source.events[position] as CanonicalEvent; return Object.freeze({ kind: "EVENT", eventId: e.id, eventType: e.type, position, historyHash: source.hashes[position] as ContentHash }); })
  .sort((a, b) => compareProtocolStrings(a.eventId, b.eventId) || compareProtocolStrings(a.eventType, b.eventType) || a.position - b.position || compareProtocolStrings(a.historyHash, b.historyHash)));
const axis = (status: ReceiptAxisStatus, primaryCode: ReceiptAxisCode, evidence: readonly Plan[] = [], future = false): ReceiptAxis =>
  Object.freeze({ status, primaryCode, causes: Object.freeze(future ? [primaryCode, "FUTURE_ISSUANCE"] : [primaryCode]) as ReceiptAxis["causes"], evidence: materialize(evidence) });
export const assuranceFor = (adapterId: string): "SIMULATED" | "NOT_PROVEN" | undefined =>
  adapterId === SIMULATED_ADAPTER_ID ? "SIMULATED"
    : [REMOTE_SERVICE_REPORT_ADAPTER_ID, LOCAL_EVIDENCE_PACKET_ADAPTER_ID, LOCAL_DOCUMENT_RELEASE_ADAPTER_ID, LOCAL_SYNTHETIC_ENDPOINT_STATE_ADAPTER_ID].includes(adapterId) ? "NOT_PROVEN" : undefined;
const intrinsicFieldsMatch = (P: ReceiptPayload): boolean => {
  const p = P.authorization.proof, i = P.issuer, r = p.request, ack = P.result.acknowledgment;
  const projection = { intentId: p.intentId, nonce: p.nonce, actorId: r.actorId, action: r.action, resource: r.resource, roleId: p.roleId, roleTenureId: p.roleTenureId, adapterProfile: ack.adapterProfile,
    ...(r.amount === undefined ? {} : { amount: r.amount }), ...(r.counterpartyId === undefined ? {} : { counterpartyId: r.counterpartyId }), ...(r.termsCommitment === undefined ? {} : { termsCommitment: r.termsCommitment }) };
  const profile = ack.adapterProfile as { profileId?: unknown } | undefined;
  return same(P.intent, projection) && same(ack.domain, P.domain) && ack.intentId === P.intent.intentId && profile?.profileId === P.result.adapterId &&
    assuranceFor(P.result.adapterId) !== undefined && P.assurance.externalOutcome === assuranceFor(P.result.adapterId) &&
    P.authorization.authorizationTime === p.evaluationTime && P.authorization.policyVersion === p.policyVersion && P.authorization.rootRecognitionPolicy === p.rootRecognitionPolicy &&
    sameHead(P.authorization.historyHead, p.historyHead) && i.agentId === r.actorId && i.keyId === p.credentialKeyId && i.runtimeSessionId === p.runtimeSessionId &&
    i.controlEpoch === p.controlEpoch && i.roleId === p.roleId && i.roleTenureId === p.roleTenureId;
};
const canonicalFieldsMatch = (state: ReplayState, P: ReceiptPayload): boolean => {
  const declaration = state.intentDeclarations.get(P.intent.intentId), session = state.runtimeSessions.get(P.issuer.runtimeSessionId), tenure = state.tenures.get(P.issuer.roleTenureId);
  // A format-2 payload spells the intent's amount as a string; the state holds the engine amount.
  return (declaration === undefined || same(P.intent, P.schemaVersion === RECEIPT_SCHEMA_VERSION_2 ? wireAmounts(declaration.data) : declaration.data)) &&
    (session === undefined || (session.agentId === P.issuer.agentId && session.credentialKeyId === P.issuer.keyId && session.controlEpoch === P.issuer.controlEpoch)) &&
    (tenure === undefined || (tenure.agentId === P.issuer.agentId && tenure.roleId === P.issuer.roleId));
};
const submissionMatches = (state: ReplayState, P: ReceiptPayload): boolean => {
  const c = state.intentConsumptions.get(P.intent.intentId), r = P.result;
  return c !== undefined && c.eventId === r.consumptionEventId && c.adapterId === r.adapterId && c.idempotencyKey === r.idempotencyKey &&
    c.submissionFingerprint === r.submissionFingerprint && c.transactionReference === r.transactionReference && same(c.acknowledgment, r.acknowledgment);
};
/** Spec 03 §G.4: the artifact's issuer tuple is current in `state` at `time`. */
export const receiptControlIsCurrent = (state: ReplayState, P: ReceiptPayload, time: U53): boolean => {
  const i = P.issuer, agent = state.agents.get(i.agentId), session = state.runtimeSessions.get(i.runtimeSessionId), role = state.roles.get(i.roleId), tenure = state.tenures.get(i.roleTenureId);
  return agent !== undefined && !agent.terminated && agent.currentControlEpoch === i.controlEpoch && session !== undefined && session.agentId === i.agentId &&
    session.credentialKeyId === i.keyId && session.controlEpoch === i.controlEpoch && !sessionExpiredAt(state, session, time) && // A-149.0
    role !== undefined && role.currentTenureId === i.roleTenureId && tenure !== undefined && !tenure.closed && tenure.roleId === i.roleId && tenure.agentId === i.agentId &&
    P.authorization.proof.request.actorId === i.agentId && state.genesis.policyVersion === P.authorization.policyVersion && state.genesis.rootRecognitionPolicy === P.authorization.rootRecognitionPolicy;
};
/** The signer's credential: recovered for EIP-191, or the session credential when an Ed25519 signature verifies against it. */
const recoverSigner = (scheme: SignatureScheme, hash: ContentHash, signature: HexSignature, credential: string | undefined): string | undefined => {
  if (scheme === "eip191-personal-sign-keccak256") return recoverContentHashSigner(hash, signature);
  return credential !== undefined && suiteFor(scheme).verify(hash, signature, credential) ? credential : undefined;
};
const indeterminate = (code: ReceiptVerificationIndeterminate["code"]): ReceiptVerificationIndeterminate =>
  Object.freeze({ operationVersion: RECEIPT_VERIFICATION_VERSION, status: "INDETERMINATE", code, limitations: RECEIPT_LIMITATIONS });
const foreignGenesis = (events: readonly unknown[], replayFn: ReplayFn): boolean => {
  const r = replayFn(events.slice(0, 1));
  return r.status === "REJECTED" && (r.code === "UNSUPPORTED_VERSION" || r.code === "UNSUPPORTED_EVENT_SCHEMA");
};
const isCoreEvent = (e: unknown): boolean => isRecord(e) && (EVENT_TYPES as readonly unknown[]).includes(e.type);

/**
 * The reference's receipt-operation occurrence bound, kept for legacy
 * histories only. A reference receipt operation carries its histories whole
 * (verification: issuance and observed; record admission: the prospective
 * history twice) and refuses once they hold more than 4096 events together:
 * verification with INVALID_INPUT (so creation over more than 2048 events
 * fails its self-check), record admission with OUTPUT_LIMIT_EXCEEDED from
 * 2048 events. Nothing in a receipt's evidence cites the whole history — every
 * axis cites the genesis, the head and the events relevant to the receipt (the
 * issuer's control records, the intent's lifecycle, the proof's authority
 * events, the record occupant) — so format-1 histories drop this bound and keep
 * only the 4096-reference evidence limit.
 */
const RECEIPT_EVENT_OCCURRENCES = 4096;
const LEGACY_FORMAT = "continuity-event/0.2";
/** Portable verification: the bound applies unless every supplied (non-empty) history declares format 1. */
const historyOccurrences = (issuance: readonly unknown[], observed: readonly unknown[]): number =>
  [issuance, observed].some((events) => events.length > 0 && detectFormat(events) !== "irontrellis-event/1") ? issuance.length + observed.length : 0;
/** The state forms: `issuanceEvents = observedEvents = state.events`. */
const stateOccurrences = (state: ReplayState): number => (state.format === LEGACY_FORMAT ? 2 * state.events.length : 0);

type VerificationArguments = Readonly<{ artifact: ReceiptArtifact; expectedDomain: AuthorizationDomain; time: U53; issuance?: readonly unknown[]; observed?: readonly unknown[] }>;
const VERIFICATION_KEYS = ["operationVersion", "artifact", "expectedDomain", "verifierTime"];
/**
 * Spec 03 §G.3 steps before replay; `withEvents` selects the portable shape (with issuance and observed histories).
 * `occurrences` (state forms) is the legacy history-occurrence count the omitted histories stand for.
 */
const parseVerification = (input: unknown, withEvents: boolean, occurrences = 0): VerificationArguments | ReceiptVerificationIndeterminate => {
  if (!isRecord(input)) return indeterminate("INVALID_INPUT");
  if (input.operationVersion !== RECEIPT_VERIFICATION_VERSION) return indeterminate("UNSUPPORTED_RECEIPT_VERSION");
  if (!closed(input, withEvents ? [...VERIFICATION_KEYS, "issuanceEvents", "observedEvents"] : VERIFICATION_KEYS)) return indeterminate("INVALID_INPUT");
  let expectedDomain: unknown, time: unknown, issuance: unknown, observed: unknown, artifactValue: unknown;
  try {
    expectedDomain = captureValue(input.expectedDomain); time = captureValue(input.verifierTime);
    if (withEvents) { issuance = captureValue(input.issuanceEvents); observed = captureValue(input.observedEvents); }
  } catch { return indeterminate("INVALID_INPUT"); }
  if (!isDomain(expectedDomain) || !isU53(time) || (withEvents && (!Array.isArray(issuance) || !Array.isArray(observed)))) return indeterminate("INVALID_INPUT");
  // The reference bounds the captured histories before it reads the artifact.
  if ((withEvents ? historyOccurrences(issuance as unknown[], observed as unknown[]) : occurrences) > RECEIPT_EVENT_OCCURRENCES) return indeterminate("INVALID_INPUT");
  try { artifactValue = captureValue(input.artifact); } catch (error) { return indeterminate(error instanceof CanonicalError && error.limit ? "INVALID_INPUT" : "MALFORMED_ARTIFACT"); }
  const artifactStatus = validateReceiptArtifact(artifactValue);
  if (artifactStatus === "UNSUPPORTED") return indeterminate("UNSUPPORTED_RECEIPT_VERSION");
  if (artifactStatus !== "VALID") return indeterminate("MALFORMED_ARTIFACT");
  return { artifact: artifactValue as ReceiptArtifact, expectedDomain, time, ...(withEvents ? { issuance: issuance as unknown[], observed: observed as unknown[] } : {}) };
};

/** Replays both histories (issuance up to the payload's issuance head) once each, then evaluates. */
export const verifyReceipt = (input: unknown, replayFn: ReplayFn = replayEvents): ReceiptVerificationResult => {
  const parsed = parseVerification(input, true);
  if ("status" in parsed) return parsed;
  const { artifact, expectedDomain, time } = parsed, issuance = parsed.issuance as readonly unknown[], observed = parsed.observed as readonly unknown[];
  // Discover both genesis interpreters before either supported-schema replay.
  if (foreignGenesis(issuance, replayFn) || foreignGenesis(observed, replayFn)) return indeterminate("UNSUPPORTED_VERSION");
  const p = artifact.payload.issuance.historyHead.position, prefix = issuance.slice(0, Math.min(p + 1, issuance.length));
  const historicalReplay = replayFn(prefix), currentReplay = replayFn(observed);
  if (historicalReplay.status !== "ACCEPTED" || currentReplay.status !== "ACCEPTED") return indeterminate("STATE_NOT_AUTHORITATIVE");
  return evaluateReceipt(artifact, expectedDomain, time, { issuance, observed, old: historicalReplay.state, current: currentReplay.state });
};

/**
 * `verifyReceipt` with `issuanceEvents = observedEvents = state.events`, over
 * an already-replayed, accepted `state`; `input` is the portable input without
 * the two histories. Replay-free whenever the receipt was issued at the head of
 * `state` (or later); a receipt issued at an older head needs the state of that
 * prefix, which is replayed (once) with `replayFn`.
 */
export const verifyReceiptState = (state: ReplayState, input: unknown, replayFn: ReplayFn = replayEvents): ReceiptVerificationResult => {
  const parsed = parseVerification(input, false, stateOccurrences(state));
  return "status" in parsed ? parsed : verifyOnState(state, parsed.artifact, parsed.expectedDomain, parsed.time, replayFn);
};

/** The state of `state.events.slice(0, position + 1)`: `state` itself when that is the whole history, else a replay. */
const prefixState = (state: ReplayState, position: number, replayFn: ReplayFn): ReplayState | undefined => {
  if (position + 1 >= state.events.length) return state;
  const replayed = replayFn(state.events.slice(0, position + 1));
  return replayed.status === "ACCEPTED" ? replayed.state : undefined;
};
const verifyOnState = (state: ReplayState, artifact: ReceiptArtifact, expectedDomain: AuthorizationDomain, time: U53, replayFn: ReplayFn): ReceiptVerificationResult => {
  const old = prefixState(state, artifact.payload.issuance.historyHead.position, replayFn);
  if (old === undefined) return indeterminate("STATE_NOT_AUTHORITATIVE");
  return evaluateReceipt(artifact, expectedDomain, time, { issuance: state.events, observed: state.events, old, current: state, issuanceHashes: state.eventHistoryHashes });
};

/**
 * Spec 03 §G.3 after replay: `old` is the state of the issuance prefix,
 * `current` the state of `observed`. `issuanceHashes`, when supplied, are the
 * prefix hashes of `issuance` (saves rehashing a history already replayed).
 */
type ReplayedHistories = Readonly<{ issuance: readonly unknown[]; observed: readonly unknown[]; old: ReplayState; current: ReplayState; issuanceHashes?: readonly ContentHash[] }>;
const evaluateReceipt = (artifact: ReceiptArtifact, expectedDomain: AuthorizationDomain, time: U53, histories: ReplayedHistories): ReceiptVerificationResult => {
  const { issuance, observed } = histories, P = artifact.payload, p = P.issuance.historyHead.position;
  // A candidate record at p+1 is relationship evidence only; it must still name a core event type.
  if (issuance.length > p + 1 && !isCoreEvent(issuance[p + 1])) return indeterminate("STATE_NOT_AUTHORITATIVE");
  const { old, current } = histories, algorithm = old.hashAlgorithm;
  const related = (issuance.length === p + 1 || issuance.length === p + 2) && p < issuance.length && sameHead(P.issuance.historyHead, old.head);
  let divergentPosition = -1;
  // One and the same history cannot diverge from itself (every accepted event encodes canonically).
  if (issuance !== observed) {
    for (let i = 0; i < Math.min(p + 1, issuance.length); i += 1) if (observed[i] === undefined || !same(issuance[i], observed[i])) { divergentPosition = i; break; }
    if (divergentPosition < 0 && issuance.length > p + 1 && observed.length > p + 1 && !same(issuance[p + 1], observed[p + 1])) divergentPosition = p + 1;
  }
  const divergent = divergentPosition >= 0;
  const oldSource: Source = { events: old.events, hashes: old.eventHistoryHashes }, currentSource: Source = { events: current.events, hashes: current.eventHistoryHashes };
  const issuanceSource: Source = issuance.length === old.events.length ? oldSource
    : { events: issuance as readonly CanonicalEvent[], hashes: histories.issuanceHashes?.length === issuance.length ? histories.issuanceHashes : hashEventHistoryPrefixes(issuance, old.format) };
  const domainPlans = union(plan(issuanceSource, 0), plan(currentSource, 0));
  const domainMismatch = !same(P.domain, P.authorization.proof.domain) || !sameDomain(P.domain, expectedDomain) || !sameDomain(P.domain, old.genesis.domain) ||
    !sameDomain(P.domain, current.genesis.domain) || !sameDomain(P.authorization.proof.domain, expectedDomain);
  const integrity = hashCanonical(P, algorithm) === artifact.contentHash;
  const session = old.runtimeSessions.get(P.issuer.runtimeSessionId), credentialMissing = session === undefined;
  const recovered = recoverSigner(P.signatureScheme, artifact.contentHash, artifact.signature, session?.credentialAddressKey);
  const issuerMatches = recovered !== undefined && session !== undefined && session.agentId === P.issuer.agentId && session.credentialKeyId === P.issuer.keyId && session.credentialAddressKey === recovered;
  const fieldsMatch = intrinsicFieldsMatch(P) && (!related || canonicalFieldsMatch(old, P));
  const submission = !related || submissionMatches(old, P);
  const proofMissing = related && (old.intentDeclarations.get(P.intent.intentId) === undefined || old.intentAdmissions.get(P.intent.intentId) === undefined);
  const admitted = old.intentAdmissions.get(P.intent.intentId);
  const admittedProofMatches = admitted !== undefined && same((old.events[admitted.admissionEventPosition] as CanonicalEvent).data.authorizationProof, P.authorization.proof);
  const oldPolicy = evaluateReceiptPolicy(old, P.authorization.proof, P.issuance.issuedAt), newPolicy = evaluateReceiptPolicy(current, P.authorization.proof, time);
  const historicalLive = related && P.issuance.issuedAt >= old.head.canonicalTime && admittedProofMatches && receiptControlIsCurrent(old, P, P.issuance.issuedAt) && oldPolicy.live;
  const newLive = receiptControlIsCurrent(current, P, time) && newPolicy.live;
  const occupant = observed[p + 1] as CanonicalEvent | undefined;
  // A-51: a format-2 record carries the issuer session's `recordAuthorization` beside the artifact-derived data.
  const occupantData = occupant === undefined ? undefined : (({ recordAuthorization: _signed, ...rest }) => rest)(occupant.data as Rec);
  const recordMatches = occupant !== undefined && occupant.type === "RECEIPT_RECORDED" && occupant.timestamp === P.issuance.issuedAt && same(occupantData, receiptRecordDataForArtifact(artifact, algorithm));
  const relationshipPlans = union(occupant === undefined ? plan(oldSource, oldSource.events.length - 1) : plan(currentSource, p + 1),
    divergent ? plan(issuanceSource, divergentPosition) : [], divergent ? plan(currentSource, divergentPosition) : []);
  const issuerPlans = domainMismatch ? domainPlans : union(domainPlans, controlEvidence(oldSource, old, P.issuer, P.issuance.issuedAt));
  const historicalPlans = domainMismatch ? domainPlans : union(issuerPlans, authorityEvidence(oldSource, old, P.authorization.proof, oldPolicy), intentEvidence(oldSource, P.intent.intentId));
  const inclusionPlans = domainMismatch ? domainPlans : relationshipPlans;
  const freshnessPlans = domainMismatch ? domainPlans : union(relationshipPlans, controlEvidence(currentSource, current, P.issuer, time), authorityEvidence(currentSource, current, P.authorization.proof, newPolicy));
  if (issuerPlans.length + historicalPlans.length + inclusionPlans.length + freshnessPlans.length > 4096) return indeterminate("OUTPUT_LIMIT_EXCEEDED");
  const issuerAxis = domainMismatch ? axis("FAIL", "DOMAIN_MISMATCH", issuerPlans) : !related ? axis("UNVERIFIED", "ISSUANCE_HISTORY_UNVERIFIED", issuerPlans)
    : credentialMissing ? axis("UNVERIFIED", "DEPENDENCY_UNAVAILABLE", issuerPlans) : !issuerMatches ? axis("FAIL", "ISSUER_NOT_AUTHENTICATED", issuerPlans) : axis("PASS", "ISSUER_AUTHENTICATED", issuerPlans);
  const historicalAxis = domainMismatch ? axis("FAIL", "DOMAIN_MISMATCH", historicalPlans) : !fieldsMatch ? axis("FAIL", "RECEIPT_FIELDS_MISMATCH", historicalPlans)
    : !submission ? axis("FAIL", "SUBMISSION_EVIDENCE_MISSING", historicalPlans) : !integrity ? axis("FAIL", "DEPENDENCY_FAILED", historicalPlans)
    // An available admission can contradict this proof even when the claimed credential is absent.
    : related && !proofMissing && (!admittedProofMatches || ((!historicalLive || issuerAxis.status === "FAIL") && !credentialMissing)) ? axis("FAIL", "HISTORICAL_AUTHORIZATION_INVALID", historicalPlans)
    : !related ? axis("UNVERIFIED", "ISSUANCE_HISTORY_UNVERIFIED", historicalPlans) : proofMissing || credentialMissing ? axis("UNVERIFIED", "DEPENDENCY_UNAVAILABLE", historicalPlans)
    : axis("PASS", "HISTORICAL_AUTHORIZATION_VALID", historicalPlans);
  const inclusionAxis = domainMismatch ? axis("FAIL", "DOMAIN_MISMATCH", inclusionPlans) : divergent ? axis("UNVERIFIED", "OBSERVED_HISTORY_DIVERGES", inclusionPlans)
    : !related ? axis("UNVERIFIED", "ISSUANCE_HISTORY_UNVERIFIED", inclusionPlans) : occupant !== undefined && !recordMatches ? axis("FAIL", "RECORDED_POSITION_MISMATCH", inclusionPlans)
    : occupant === undefined ? axis("UNAVAILABLE", "RECORD_NOT_AVAILABLE", inclusionPlans) : axis("PASS", "RECORDED_HASH_MATCH", inclusionPlans);
  const freshnessAxis = domainMismatch ? axis("UNVERIFIED", "DOMAIN_MISMATCH", freshnessPlans) : divergent ? axis("UNVERIFIED", "OBSERVED_HISTORY_DIVERGES", freshnessPlans)
    : !related ? axis("UNVERIFIED", "ISSUANCE_HISTORY_UNVERIFIED", freshnessPlans)
    : time < current.head.canonicalTime ? axis("UNVERIFIED", "VERIFIER_TIME_BEHIND_OBSERVED_HEAD", freshnessPlans, P.issuance.issuedAt > time)
    : P.issuance.issuedAt > time ? axis("FAIL", "FUTURE_ISSUANCE", freshnessPlans) : !newLive ? axis("FAIL", "STALE", freshnessPlans) : axis("PASS", "CURRENT", freshnessPlans);
  const authentic = integrity && recovered !== undefined && issuerAxis.status === "PASS", historical = authentic && historicalAxis.status === "PASS";
  return Object.freeze({
    operationVersion: RECEIPT_VERIFICATION_VERSION, status: "EVALUATED",
    contentIntegrity: axis(integrity ? "PASS" : "FAIL", integrity ? "CONTENT_HASH_MATCH" : "CONTENT_HASH_MISMATCH"),
    signaturePossession: axis(recovered === undefined ? "FAIL" : "PASS", recovered === undefined ? "SIGNATURE_INVALID" : "SIGNATURE_VALID"),
    issuerAuthentication: issuerAxis, historicalAuthorization: historicalAxis, canonicalInclusion: inclusionAxis, finality: axis("PASS", "LOCAL_ONLY"), freshness: freshnessAxis,
    externalOutcome: axis("UNVERIFIED", P.assurance.externalOutcome === "SIMULATED" ? "SIMULATED" : "NOT_PROVEN"),
    authentic, historical, valid: historical, current: historical && inclusionAxis.status === "PASS" && freshnessAxis.status === "PASS",
    limitations: inclusionAxis.status === "PASS" ? RECEIPT_LIMITATIONS.slice(1) : RECEIPT_LIMITATIONS,
  });
};

// ---------------------------------------------------------------- record proposal (spec 03 §G.7)
type RecordIndeterminate = Extract<ReceiptRecordAdmissionResult, { status: "INDETERMINATE" }>;
const recordIndeterminate = (code: RecordIndeterminate["code"], verification?: ReceiptVerificationIndeterminate): RecordIndeterminate =>
  Object.freeze({ operationVersion: RECEIPT_RECORD_ADMISSION_VERSION, status: "INDETERMINATE", code, ...(verification === undefined ? {} : { verification }) });
const mapVerificationCode = (code: ReceiptVerificationIndeterminate["code"]): RecordIndeterminate["code"] =>
  code === "MALFORMED_ARTIFACT" ? "INVALID_INPUT" : code === "UNSUPPORTED_RECEIPT_VERSION" ? "UNSUPPORTED_VERSION" : code;

const RECORD_KEYS = ["operationVersion", "artifact", "expectedHistoryHead", "expectedDomain", "recordEventId"];
/** Spec 03 §G.7 capture and structure; `withEvents` selects the portable shape. */
const parseRecord = (input: unknown, withEvents: boolean): Readonly<{ value: Rec }> | Readonly<{ result: RecordIndeterminate }> => {
  const refuse = (code: RecordIndeterminate["code"]) => ({ result: recordIndeterminate(code) });
  if (!isRecord(input)) return refuse("INVALID_INPUT");
  if (input.operationVersion !== RECEIPT_RECORD_ADMISSION_VERSION) return refuse("UNSUPPORTED_VERSION");
  // A-51: a format-2 record carries the issuer session's `recordAuthorization` (signed by the caller over the lifecycle challenge).
  if (!closed(input, withEvents ? [...RECORD_KEYS, "events"] : RECORD_KEYS, ["recordAuthorization"])) return refuse("INVALID_INPUT");
  let value: Rec;
  try { value = captureValue(input) as Rec; } catch { return refuse("INVALID_INPUT"); }
  if ((withEvents && !Array.isArray(value.events)) || !isHead(value.expectedHistoryHead) || !isDomain(value.expectedDomain) || !isIdentifier(value.recordEventId)) return refuse("INVALID_INPUT");
  return { value };
};

/** Pure prospective composition; PROPOSED never claims persistence. Replays `input.events` once. */
export const proposeReceiptRecord = (input: unknown, replayFn: ReplayFn = replayEvents): ReceiptRecordProposal => {
  const parsed = parseRecord(input, true);
  if ("result" in parsed) return parsed.result;
  const value = parsed.value, events = value.events as readonly unknown[];
  if (foreignGenesis(events, replayFn)) return recordIndeterminate("UNSUPPORTED_VERSION");
  const replayed = replayFn(events);
  if (replayed.status !== "ACCEPTED") return recordIndeterminate("STATE_NOT_AUTHORITATIVE");
  return proposeRecordOnState(replayed.state, value, replayFn);
};

/**
 * `proposeReceiptRecord` over an already-replayed, accepted `state`; `input` is
 * the portable input without `events`. The RECEIPT_RECORDED event is verified
 * and applied on a private fork of `state` (`withProspectiveEvent`); nothing is
 * replayed unless the artifact was issued at a head older than the parent of
 * `state`'s head (then that prefix is replayed once with `replayFn`).
 */
export const proposeReceiptRecordState = (state: ReplayState, input: unknown, replayFn: ReplayFn = replayEvents): ReceiptRecordProposal => {
  const parsed = parseRecord(input, false);
  return "result" in parsed ? parsed.result : proposeRecordOnState(state, parsed.value, replayFn);
};

const proposeRecordOnState = (state: ReplayState, value: Rec, replayFn: ReplayFn): ReceiptRecordProposal => {
  const expectedHead = value.expectedHistoryHead as HistoryHead, recordEventId = value.recordEventId as string, expectedDomain = value.expectedDomain as AuthorizationDomain;
  if (!sameHead(state.head, expectedHead)) return Object.freeze({ operationVersion: RECEIPT_RECORD_ADMISSION_VERSION, status: "CONFLICT", expectedHead, observedHead: state.head });
  if (state.eventPositionsById.has(recordEventId)) return recordIndeterminate("INVALID_INPUT");
  const artifactStatus = validateReceiptArtifact(value.artifact);
  if (artifactStatus === "UNSUPPORTED") return recordIndeterminate("UNSUPPORTED_VERSION");
  if (artifactStatus !== "VALID") return recordIndeterminate("INVALID_INPUT");
  const artifact = value.artifact as ReceiptArtifact, count = state.events.length;
  // Legacy: the reference's occurrence bound over the prospective history carried twice (refused from 2048 events). Format 1: unbounded.
  if (state.format === LEGACY_FORMAT && (count >= RECEIPT_EVENT_OCCURRENCES || (count + 1) * 2 > RECEIPT_EVENT_OCCURRENCES)) return recordIndeterminate("OUTPUT_LIMIT_EXCEEDED");
  const signed = value.recordAuthorization;
  if ((signed !== undefined) !== (state.format === "irontrellis-event/2")) return recordIndeterminate("INVALID_INPUT");
  const recordData = receiptRecordDataForArtifact(artifact, state.hashAlgorithm);
  const recordEvent: CanonicalEvent = Object.freeze({ id: recordEventId, type: "RECEIPT_RECORDED", timestamp: artifact.payload.issuance.issuedAt, data: signed === undefined ? recordData : Object.freeze({ ...recordData, recordAuthorization: signed }) });
  // Verification over issuance = observed = [...events, recordEvent], as spec 03 §G.7 composes it.
  const prospective = withProspectiveEvent(state, recordEvent);
  if (!prospective.ok) {
    const unreplayable = indeterminate("STATE_NOT_AUTHORITATIVE");
    return recordIndeterminate(mapVerificationCode(unreplayable.code), unreplayable);
  }
  const next = prospective.state, parsed = parseVerification({ operationVersion: RECEIPT_VERIFICATION_VERSION, artifact, expectedDomain, verifierTime: artifact.payload.issuance.issuedAt }, false);
  // The issuance prefix is `state` itself in the ordinary case (issued at the head, recorded as the next event).
  const verification = "status" in parsed ? parsed
    : artifact.payload.issuance.historyHead.position + 1 === state.events.length
      ? evaluateReceipt(parsed.artifact, parsed.expectedDomain, parsed.time, { issuance: next.events, observed: next.events, old: state, current: next, issuanceHashes: next.eventHistoryHashes })
      : verifyOnState(next, parsed.artifact, parsed.expectedDomain, parsed.time, replayFn);
  if (verification.status === "INDETERMINATE") return recordIndeterminate(mapVerificationCode(verification.code), verification);
  if (!verification.current) return Object.freeze({ operationVersion: RECEIPT_RECORD_ADMISSION_VERSION, status: "REJECTED", verification });
  return Object.freeze({ operationVersion: RECEIPT_RECORD_ADMISSION_VERSION, status: "PROPOSED", expectedHead, recordEvent, newHead: prospective.head, verification });
};

// ---------------------------------------------------------------- creation (spec 03 §G.2)
type CreationArguments = Readonly<{ intentId: string; issuedAt: U53; externalOutcome: "NOT_PROVEN" | "SIMULATED" }>;
const parseCreation = (input: unknown, withEvents: boolean): Rec & CreationArguments => {
  let stable: Rec;
  try { stable = captureValue(input) as Rec; } catch { throw new TypeError("Malformed local receipt creation input."); }
  if (!closed(stable, withEvents ? ["events", "intentId", "issuedAt", "externalOutcome"] : ["intentId", "issuedAt", "externalOutcome"]) || typeof stable.intentId !== "string" || !isU53(stable.issuedAt) ||
      (stable.externalOutcome !== "NOT_PROVEN" && stable.externalOutcome !== "SIMULATED") || (withEvents && !Array.isArray(stable.events))) throw new TypeError("Malformed local receipt creation input.");
  return stable as Rec & CreationArguments;
};
const CAUSALLY_INVALID = "Receipt issuance requires a causally valid accepted prefix.";

/** Signs a receipt for a consumed intent over the whole current history; the artifact is not a record witness. Replays `input.events` once. */
export const createReceipt = async (input: CreateReceiptInput, signer: ReceiptSigner, replayFn: ReplayFn = replayEvents): Promise<ReceiptArtifact> => {
  const stable = parseCreation(input, true), replayed = replayFn(stable.events as readonly unknown[]);
  if (replayed.status !== "ACCEPTED" || stable.issuedAt < replayed.state.head.canonicalTime) throw new TypeError(CAUSALLY_INVALID);
  return createOnState(replayed.state, stable, signer);
};

/**
 * `createReceipt` over an already-replayed, accepted `state` (`input` without
 * `events`); never replays. `state` must not change while the signer runs: a
 * head that moved during signing is refused (TypeError) rather than verified
 * against a different history.
 */
export const createReceiptState = async (state: ReplayState, input: Omit<CreateReceiptInput, "events">, signer: ReceiptSigner): Promise<ReceiptArtifact> => {
  const stable = parseCreation(input, false);
  if (stable.issuedAt < state.head.canonicalTime) throw new TypeError(CAUSALLY_INVALID);
  return createOnState(state, stable, signer);
};

const createOnState = async (state: ReplayState, stable: CreationArguments, signer: ReceiptSigner): Promise<ReceiptArtifact> => {
  const issuedAt = stable.issuedAt, head = state.head;
  const admission = state.intentAdmissions.get(stable.intentId), consumption = state.intentConsumptions.get(stable.intentId), declaration = state.intentDeclarations.get(stable.intentId);
  if (admission === undefined || consumption === undefined || declaration === undefined) throw new TypeError("Receipt issuance requires exact admitted and consumed intent evidence.");
  if (stable.externalOutcome !== assuranceFor(consumption.adapterId)) throw new TypeError("Receipt assurance must match the admitted adapter profile.");
  const proof = (state.events[admission.admissionEventPosition] as CanonicalEvent).data.authorizationProof as AuthorizationProof;
  const session = state.runtimeSessions.get(admission.runtimeSessionId);
  const payload = captureValue({
    schemaVersion: state.genesis.versions.receiptSchemaVersion ?? "continuity-receipt/0.2", signatureScheme: session?.credentialScheme ?? state.signatureScheme, domain: proof.domain,
    issuer: { keyId: admission.credentialKeyId, agentId: admission.actorId, runtimeSessionId: admission.runtimeSessionId, controlEpoch: admission.controlEpoch, roleId: admission.roleId, roleTenureId: admission.roleTenureId },
    intent: state.genesis.versions.receiptSchemaVersion === RECEIPT_SCHEMA_VERSION_2 ? wireAmounts(declaration.data) : declaration.data,
    authorization: { authorizationTime: proof.evaluationTime, policyVersion: proof.policyVersion, rootRecognitionPolicy: proof.rootRecognitionPolicy, historyHead: proof.historyHead, proof },
    issuance: { historyHead: state.head, issuedAt },
    result: { status: "SUBMITTED", consumptionEventId: consumption.eventId, adapterId: consumption.adapterId, idempotencyKey: consumption.idempotencyKey,
      submissionFingerprint: consumption.submissionFingerprint, transactionReference: consumption.transactionReference, acknowledgment: consumption.acknowledgment },
    assurance: { finality: "LOCAL_ONLY", freshness: "CURRENT_AT_ISSUANCE", externalOutcome: stable.externalOutcome },
  }) as ReceiptPayload;
  if (!receiptControlIsCurrent(state, payload, issuedAt) || !evaluateReceiptPolicy(state, proof, issuedAt).live || signer.keyId !== admission.credentialKeyId || typeof signer.signHash !== "function") {
    throw new TypeError("Receipt signer or issuance authority is not current.");
  }
  const contentHash = hashCanonical(payload, state.hashAlgorithm);
  const artifact: ReceiptArtifact = Object.freeze({ payload, contentHash, signature: await signer.signHash(contentHash) });
  if (!sameHead(state.head, head)) throw new TypeError("Receipt issuance history changed while signing.");
  const verification = verifyReceiptState(state, { operationVersion: RECEIPT_VERIFICATION_VERSION, artifact, expectedDomain: proof.domain, verifierTime: issuedAt });
  if (verification.status !== "EVALUATED" || !verification.historical) throw new TypeError("Signer did not return a valid historically authorized receipt artifact.");
  return artifact;
};
