/**
 * Format 2 session authorization (SPEC §6.2) and the intent-declaration challenge (SPEC §8.6).
 *
 * Every session-signed event (◇) carries a binding `{runtimeSessionId, credentialKeyId, controlEpoch}` and a signature
 * by that session's credential over `hashCanonical(challenge)`. `sessionAuthorizationFailure` applies the §6.2 checks
 * in the SPEC's order and is shared by declarations (E1), refusals, effects, counterparty-receipt wrappers (E2) and
 * reconciliation observations (A-71).
 */
import { suiteFor } from "./crypto/suites.ts";
import { hashCanonical } from "./hash.ts";
import { INTENT_DECLARATION_VERSION, LIFECYCLE_AUTHORIZATION_VERSION, TRELLIS2_FORMAT } from "./events.ts";
import type { AuthorizationDomain, CanonicalEvent, ContentHash, HistoryHead, ReplayState, RuntimeSessionRecord, U53 } from "./types.ts";

export type SessionBinding = Readonly<{ runtimeSessionId: string; credentialKeyId: string; controlEpoch: U53 }>;

/**
 * A-52.2: a session is expired at `t` when `t ≥ expiresAt`; in a format-2 state (after any migrated prefix) a session
 * without `expiresAt` — only a migrated prefix session can lack it (A-22.1) — is expired: it signed the prefix only.
 * Inside a prefix the transitions run on the source-format view, where a missing expiry keeps its format-1 meaning.
 */
export const sessionExpiredAt = (state: ReplayState, session: Readonly<{ expiresAt?: U53 }>, t: U53): boolean =>
  session.expiresAt === undefined ? state.format === TRELLIS2_FORMAT : t >= session.expiresAt;

export type SessionAuthorizationOutcome =
  | Readonly<{ ok: true; session: RuntimeSessionRecord }>
  | Readonly<{ ok: false; reason: string; code?: "SESSION_FENCED" }>;
/**
 * SPEC §6.2 with A-29 / A-58.5, in order: the session exists and its `credentialKeyId` matches; **SESSION_FENCED** when
 * the session's `controlEpoch` is not its agent's current epoch (checked first, before every other §6.2 check; the caller
 * reports the code `SESSION_FENCED`); the session's agent is active; the binding's `controlEpoch` equals the session's
 * (§6.2's epoch comparison, which after the fence only catches a binding that differs from the session record); the
 * session is not expired at `timestamp` (A-52.2); the recorded `hash` equals the recomputed challenge hash; the signature
 * verifies under the session's credential and scheme. Returns the reason (and `code` for the fence), or the session.
 */
export function sessionAuthorizationFailure(
  state: ReplayState, binding: SessionBinding, timestamp: U53, expectedHash: ContentHash, recordedHash: unknown, signature: unknown,
): SessionAuthorizationOutcome {
  const session = state.runtimeSessions.get(binding.runtimeSessionId);
  if (session === undefined) return { ok: false, reason: `session ${binding.runtimeSessionId} does not exist` };
  if (session.credentialKeyId !== binding.credentialKeyId) return { ok: false, reason: "credentialKeyId does not match the session" };
  const agent = state.agents.get(session.agentId);
  if (agent !== undefined && session.controlEpoch !== agent.currentControlEpoch) return { ok: false, code: "SESSION_FENCED", reason: `session ${binding.runtimeSessionId} belongs to control epoch ${session.controlEpoch}; its agent is at ${agent.currentControlEpoch}` };
  if (agent === undefined || agent.terminated) return { ok: false, reason: "the session's agent is not active" };
  if (session.controlEpoch !== binding.controlEpoch) return { ok: false, reason: "controlEpoch is not the session's epoch" };
  if (sessionExpiredAt(state, session, timestamp)) return { ok: false, reason: "the session has expired" };
  if (recordedHash !== expectedHash) return { ok: false, reason: "recorded hash differs from the recomputed challenge hash" };
  try {
    const suite = suiteFor(session.credentialScheme);
    if (!suite.isSignature(signature) || !suite.isCredential(session.credentialAddressKey) || !suite.verify(expectedHash, signature, session.credentialAddressKey)) {
      return { ok: false, reason: "the session signature does not verify" };
    }
  } catch {
    return { ok: false, reason: "the session signature does not verify" };
  }
  return { ok: true, session };
}
/** A-58.5: the replay code of a failed session authorization — SESSION_FENCED for the fence, else the type's own code. */
export const sessionFailureCode = <C extends string>(outcome: Readonly<{ code?: "SESSION_FENCED" }>, typeCode: C): C | "SESSION_FENCED" => outcome.code ?? typeCode;

// ---------------------------------------------------------------- A-51: the lifecycle authorization of types 14–16

/** A-51.1: the nested binding + signature of a format-2 consumption, outcome or receipt record. */
export type LifecycleAuthorization = SessionBinding & Readonly<{ hash: ContentHash; signature: string }>;
/** A-51.2: `effectHash = hashCanonical(data without recordAuthorization)`. */
export const lifecycleEffectHash = (data: Readonly<Record<string, unknown>>): ContentHash => {
  const { recordAuthorization: _omitted, ...effect } = data;
  return hashCanonical(effect, "sha256");
};
/**
 * A-51.2: `{version: "irontrellis-lifecycle-authorization/2", domain, eventId, eventType, timestamp, effectHash,
 * eventHistoryHash, eventHistoryPosition, runtimeSessionId, credentialKeyId, controlEpoch}` over the head before the event.
 */
export function lifecycleChallenge(domain: AuthorizationDomain, event: Readonly<Pick<CanonicalEvent, "id" | "type" | "timestamp" | "data">>, previousHead: Readonly<Pick<HistoryHead, "hash" | "position">>, binding: SessionBinding): Readonly<Record<string, unknown>> {
  return Object.freeze({
    version: LIFECYCLE_AUTHORIZATION_VERSION, domain, eventId: event.id, eventType: event.type, timestamp: event.timestamp, effectHash: lifecycleEffectHash(event.data),
    eventHistoryHash: previousHead.hash, eventHistoryPosition: previousHead.position,
    runtimeSessionId: binding.runtimeSessionId, credentialKeyId: binding.credentialKeyId, controlEpoch: binding.controlEpoch,
  });
}
export const lifecycleAuthorizationHash = (domain: AuthorizationDomain, event: Readonly<Pick<CanonicalEvent, "id" | "type" | "timestamp" | "data">>, previousHead: Readonly<Pick<HistoryHead, "hash" | "position">>, binding: SessionBinding): ContentHash =>
  hashCanonical(lifecycleChallenge(domain, event, previousHead, binding), "sha256");

/** The intent fields the §8.6 challenge binds (the event's `data` without `declarationAuthorization`, Amount as written). */
export type IntentDeclarationFields = Readonly<{
  intentId: string; nonce: string; actorId: string; action: string; resource: string; roleId: string; roleTenureId: string;
  adapterProfile: Readonly<Record<string, unknown>>; amount?: string | bigint; counterpartyId?: string; termsCommitment?: string; metric?: string;
}>;
/** SPEC §8.6: the intent-declaration challenge; `previousHead` is the head before the declaration. */
// ---------------------------------------------------------------- A-54 / A-59: the one switch

/**
 * A-54 (founder-approved 2026-10-11) with A-59: in profile `"g3"` every session-signed challenge built after the final
 * envelope is fixed — §8.6 declaration, §10.1 refusal, §10.2 effect, §11.2 wrapper — also binds the event's `eventId`,
 * `eventType` and `timestamp` (the `/2` literals are kept; §8.2's runtime challenge is unchanged). `"frozen-r2.3"`
 * reproduces the r2.3 challenges the 86 frozen `conformance/v2` vectors were signed under (the r2.3 record; the suite
 * regenerated under g3 is `conformance/v2-g3`). The default is `"g3"`; `"frozen-r2.3"` is selected with
 * `IRONTRELLIS_CHALLENGE_PROFILE=frozen-r2.3` or `setChallengeProfile`. A history is verified under one profile;
 * nothing retries the other structure.
 */
export type ChallengeProfile = "frozen-r2.3" | "g3";
export const CHALLENGE_PROFILES: readonly ChallengeProfile[] = Object.freeze(["frozen-r2.3", "g3"]);
const profileFromEnvironment = (value: string | undefined): ChallengeProfile => {
  if (value === undefined || value === "") return "g3";
  if ((CHALLENGE_PROFILES as readonly string[]).includes(value)) return value as ChallengeProfile;
  throw new TypeError(`IRONTRELLIS_CHALLENGE_PROFILE: unknown challenge profile ${JSON.stringify(value)} (expected one of ${CHALLENGE_PROFILES.join(", ")})`);
};
let CHALLENGE_PROFILE: ChallengeProfile = profileFromEnvironment(process.env.IRONTRELLIS_CHALLENGE_PROFILE);
export const challengeProfile = (): ChallengeProfile => CHALLENGE_PROFILE;
export function setChallengeProfile(profile: ChallengeProfile): void {
  if (!CHALLENGE_PROFILES.includes(profile)) throw new TypeError(`unknown challenge profile ${String(profile)}`);
  CHALLENGE_PROFILE = profile;
}
/** The final envelope a session signs over in profile g3 (the event's id and timestamp; the type is the challenge's own). */
export type ChallengeEnvelope = Readonly<{ id: string; timestamp: number }>;
const envelopeFields = (eventType: string, envelope: ChallengeEnvelope | undefined): Readonly<Record<string, unknown>> => {
  if (CHALLENGE_PROFILE !== "g3") return {};
  if (envelope === undefined) throw new TypeError(`A-54: the ${eventType} challenge of profile g3 needs the final envelope (eventId, timestamp)`);
  return { eventId: envelope.id, eventType, timestamp: envelope.timestamp };
};

export function intentDeclarationChallenge(domain: AuthorizationDomain, data: IntentDeclarationFields, previousHead: Readonly<Pick<HistoryHead, "hash" | "position">>, binding: SessionBinding, envelope?: ChallengeEnvelope): Readonly<Record<string, unknown>> {
  return Object.freeze({
    version: INTENT_DECLARATION_VERSION, domain, ...envelopeFields("TRANSACTION_INTENT_DECLARED", envelope), intentId: data.intentId, nonce: data.nonce, actorId: data.actorId, action: data.action, resource: data.resource,
    roleId: data.roleId, roleTenureId: data.roleTenureId, adapterProfile: data.adapterProfile,
    amount: data.amount === undefined ? null : typeof data.amount === "bigint" ? data.amount.toString() : data.amount,
    counterpartyId: data.counterpartyId ?? null, termsCommitment: data.termsCommitment ?? null, metric: data.metric ?? null,
    eventHistoryHash: previousHead.hash, eventHistoryPosition: previousHead.position,
    runtimeSessionId: binding.runtimeSessionId, credentialKeyId: binding.credentialKeyId, controlEpoch: binding.controlEpoch,
  });
}
export const intentDeclarationHash = (domain: AuthorizationDomain, data: IntentDeclarationFields, previousHead: Readonly<Pick<HistoryHead, "hash" | "position">>, binding: SessionBinding, envelope?: ChallengeEnvelope): ContentHash =>
  hashCanonical(intentDeclarationChallenge(domain, data, previousHead, binding, envelope), "sha256");

// ---------------------------------------------------------------- refusal, effect and counterparty-receipt challenges (SPEC §10–§11)

export const REFUSAL_AUTHORIZATION_VERSION = "irontrellis-refusal-authorization/2";
export const EFFECT_AUTHORIZATION_VERSION = "irontrellis-effect-authorization/2";
export const COUNTERPARTY_RECORD_AUTHORIZATION_VERSION = "irontrellis-counterparty-record-authorization/2";
type Rec = Readonly<Record<string, unknown>>;
const requestFields = (r: Rec): Rec => {
  const out: Record<string, unknown> = { actorId: r.actorId, action: r.action, resource: r.resource, claimedAt: r.claimedAt };
  for (const key of ["amount", "counterpartyId", "termsCommitment", "metric"]) if (Object.hasOwn(r, key)) out[key] = typeof r[key] === "bigint" ? (r[key] as bigint).toString() : r[key];
  return Object.freeze(out);
};
/** SPEC §10.1: the refusal challenge over the event's `data` (without `refusalAuthorization`). */
export function refusalChallenge(domain: AuthorizationDomain, d: Rec, envelope?: ChallengeEnvelope): Rec {
  const head = d.expectedHistoryHead as HistoryHead;
  return Object.freeze({
    version: REFUSAL_AUTHORIZATION_VERSION, domain, ...envelopeFields("REQUEST_REFUSED", envelope), refusalId: d.refusalId, refusalSource: d.refusalSource, request: requestFields(d.request as Rec), evaluationTime: d.evaluationTime,
    eventHistoryHash: head.hash, eventHistoryPosition: head.position, decision: d.decision, code: d.code, budgetId: d.budgetId ?? null, connector: d.connector ?? null,
    runtimeSessionId: d.runtimeSessionId, credentialKeyId: d.credentialKeyId, controlEpoch: d.controlEpoch,
  });
}
/** SPEC §10.2: the effect challenge; `previousHead` is the head before the event. */
export function effectChallenge(domain: AuthorizationDomain, d: Rec, previousHead: Readonly<Pick<HistoryHead, "hash" | "position">>, envelope?: ChallengeEnvelope): Rec {
  return Object.freeze({
    version: EFFECT_AUTHORIZATION_VERSION, domain, ...envelopeFields("EFFECT_RECORDED", envelope), effectId: d.effectId, intentId: d.intentId, measurer: d.measurer, metric: d.metric, unit: d.unit, amount: d.amount,
    observedAt: d.observedAt, detailDigest: d.detailDigest, eventHistoryHash: previousHead.hash, eventHistoryPosition: previousHead.position,
    runtimeSessionId: d.runtimeSessionId, credentialKeyId: d.credentialKeyId, controlEpoch: d.controlEpoch,
  });
}
/** SPEC §11.2: `envelopeSigningHash` (without the signature) and `envelopeDigest` (with it). */
export function envelopeSigningHash(envelope: Rec): ContentHash {
  const { signature: _signature, ...body } = envelope;
  return hashCanonical(body, "sha256");
}
export const envelopeDigest = (envelope: Rec): ContentHash => hashCanonical(envelope, "sha256");
/** SPEC §11.2: the session-signed wrapper challenge. */
export function counterpartyRecordChallenge(domain: AuthorizationDomain, d: Rec, previousHead: Readonly<Pick<HistoryHead, "hash" | "position">>, envelope?: ChallengeEnvelope): Rec {
  return Object.freeze({
    version: COUNTERPARTY_RECORD_AUTHORIZATION_VERSION, domain, ...envelopeFields("COUNTERPARTY_RECEIPT_RECORDED", envelope), intentId: d.intentId, envelopeDigest: envelopeDigest(d.envelope as Rec), eventHistoryHash: previousHead.hash, eventHistoryPosition: previousHead.position,
    runtimeSessionId: d.runtimeSessionId, credentialKeyId: d.credentialKeyId, controlEpoch: d.controlEpoch,
  });
}

// ---------------------------------------------------------------- A-71: the reconciliation observation (type 42, SPEC §10.3)

export const RECONCILIATION_AUTHORIZATION_VERSION = "irontrellis-reconciliation-authorization/2";
/**
 * A-71.2: `{version, domain, eventId, eventType: "RECONCILIATION_OBSERVED", timestamp, observationId, reconcilerAgentId,
 * source, call, match, eventHistoryHash, eventHistoryPosition, runtimeSessionId, credentialKeyId, controlEpoch}` with
 * `source`, `call` and `match` exactly as written in `data`. Type 42 is new in the A-54 form: the envelope is always bound
 * (no `frozen-r2.3` variant exists).
 */
export function reconciliationChallenge(domain: AuthorizationDomain, d: Rec, envelope: ChallengeEnvelope): Rec {
  const head = d.expectedHistoryHead as HistoryHead;
  return Object.freeze({
    version: RECONCILIATION_AUTHORIZATION_VERSION, domain, eventId: envelope.id, eventType: "RECONCILIATION_OBSERVED", timestamp: envelope.timestamp,
    observationId: d.observationId, reconcilerAgentId: d.reconcilerAgentId, source: d.source, call: d.call, match: d.match,
    eventHistoryHash: head.hash, eventHistoryPosition: head.position, runtimeSessionId: d.runtimeSessionId, credentialKeyId: d.credentialKeyId, controlEpoch: d.controlEpoch,
  });
}
export const OBSERVATION_ID_VERSION = "irontrellis-observation-id/2";
/** A-71.6: the derived `observationId` — `hashCanonical(["irontrellis-observation-id/2", reconcilerAgentId, streamId, eventRef, eventDigest])`. */
export const derivedObservationId = (reconcilerAgentId: string, source: Readonly<{ streamId: string; eventRef: string; eventDigest: string }>): ContentHash =>
  hashCanonical([OBSERVATION_ID_VERSION, reconcilerAgentId, source.streamId, source.eventRef, source.eventDigest], "sha256");
