/**
 * Owner key epochs (format 1): which owner keys are in force at a
 * history position, the key-set rules of `OWNER_KEYS_ROTATED`, head
 * attestations judged by position, and a standalone check of a rotation event
 * for a party that holds the prior key sets but not the history (a remote
 * witness).
 *
 * Positions. The genesis key set governs from position 0. A rotation at
 * position `r` is itself authorized by the set in force at `r` (the set before
 * it) and opens a new epoch with `fromPosition: r + 1`. The set "at position p"
 * is the epoch with the greatest `fromPosition <= p`; it is the set that must
 * sign a control event at position p and the set that must sign a head
 * attestation (pin, anchors log, witness statement) of the head at position p.
 * So the head that ends with the rotation (position r) is still attested under
 * the old set, and every later head under the new one; an attestation of an
 * older head keeps verifying after its key was retired.
 *
 * Pre-rotation (docs/HISTORY-FORMAT.md §7). An epoch may carry a commitment to
 * the digests of its next keys (`nextKeyDigests`, `ownerKeyDigest`), fixed by
 * the event that opens it: the genesis for epoch 0, the rotation for any later
 * one. A rotation out of a committed epoch must reveal committed keys, prove
 * possession of one (`nextKeyAuthorizations`, signatures over the event's own
 * control-authorization challenge) and commit again, so a leaked current key
 * alone can neither rotate nor replace the commitment. An uncommitted epoch
 * rotates freely; a rotation out of it that keeps every key must add a
 * commitment (the commitment-only rotation, how a history without one gets one).
 */
import { canonicalEncode, isContentHash, isU53 } from "./canonical.ts";
import { suiteFor } from "./crypto/suites.ts";
import { ADDITIONAL_CONTROL_AUTHORIZATIONS, controlAuthorizationHash, controlEffectHash, declaredDigestFailure, declaredKeyFailure, isFormat2, ownerKeyDigest, TRELLIS2_FORMAT, TRELLIS_FORMAT, validateEvent } from "./events.ts";
import { attestationHorizon, controlThreshold, credentialId, effectiveThreshold, isAttestedPolicy, MAX_TIME, ownerPolicyFailure, prEffective, rotationThreshold, sameOwnerPolicy, signerClass, type SignerClass } from "./owner-policy.ts";
import { projectionHeadAt, rootAt } from "./state-records.ts";
import { HEAD_ATTESTATION_VERSION, HEAD_ATTESTATION_VERSION_2, verifyHeadAttestation } from "./signer.ts";
import type {
  AuthorizationDomain, CanonicalEvent, ContentHash, HashAlgorithm, HumanAttestation, OwnerKey, OwnerKeyEpoch, OwnerPolicy, ReplayCode, ReplayState, SignatureScheme, U53,
} from "./types.ts";

export { OWNER_KEY_DIGEST_VERSION, ownerKeyDigest } from "./events.ts";

/** A replay state or its owner key epochs. */
type EpochSource = Readonly<{ ownerKeyEpochs: readonly OwnerKeyEpoch[] }> | readonly OwnerKeyEpoch[];

const epochsOf = (source: EpochSource): readonly OwnerKeyEpoch[] =>
  Array.isArray(source) ? source as readonly OwnerKeyEpoch[] : (source as Readonly<{ ownerKeyEpochs: readonly OwnerKeyEpoch[] }>).ownerKeyEpochs;

/**
 * The owner keys in force for an event at `position`, and for the head at
 * `position` (a head attestation or witness statement of that head): the epoch
 * with the greatest `fromPosition <= position`. Accepts a replay state or its
 * `ownerKeyEpochs`. A position past the head gets the current set; a negative
 * or non-integer position gets none. Legacy histories have no owner keys.
 */
export function ownerKeysAt(source: EpochSource, position: number): readonly OwnerKey[] {
  return ownerKeyEpochAt(source, position)?.keys ?? [];
}
/** The owner key epoch in force at `position` (greatest `fromPosition <= position`), or undefined. */
export function ownerKeyEpochAt(source: EpochSource, position: number): OwnerKeyEpoch | undefined {
  if (!isU53(position)) return undefined;
  const epochs = epochsOf(source);
  for (let index = epochs.length - 1; index >= 0; index -= 1) {
    const epoch = epochs[index]!;
    if (epoch.fromPosition <= position) return epoch;
  }
  return undefined;
}
/** A-91.4 `P(p)`: the owner approval policy in force at `position` as written (`undefined`: the default `{threshold: 1}`). */
export const ownerPolicyAt = (source: EpochSource, position: number): OwnerPolicy | undefined => ownerKeyEpochAt(source, position)?.policy;
/**
 * A-114.0 `t_set(p)`: the timestamp of the event that opened the epoch in force at `position` (the genesis for epoch 0).
 * Reads the replayed events; `undefined` when the opening event is not held (a bare epoch list).
 */
export const epochOpenedAt = (state: Readonly<{ events: readonly CanonicalEvent[]; ownerKeyEpochs: readonly OwnerKeyEpoch[] }>, position: number): U53 | undefined => {
  const epoch = ownerKeyEpochAt(state, position);
  return epoch === undefined ? undefined : state.events[Math.max(0, epoch.fromPosition - 1)]?.timestamp;
};
/** A-108.1 `G(e, p)`: the rotation carries `ownerPolicy`, or the epoch in force (`epoch`) carries `policy` as written. */
export const policyGuard = (event: CanonicalEvent, epoch: OwnerKeyEpoch | undefined): boolean => Object.hasOwn(event.data, "ownerPolicy") || epoch?.policy !== undefined;

/**
 * A-97.2 / A-114.0 `adm(e)`: the keys that may sign a ◆ event at a position whose epoch in force is `epoch`. The keys in
 * force, extended for an `OWNER_KEYS_ROTATED` under `recovery: "COMMITTED_NEXT_KEYS"` by every key the rotation reveals
 * (its key id is not in force) whose digest is in the epoch's commitment `D`. Decided from `e.data` and the epoch record
 * before any signature is verified.
 */
export function admissibleKeys(epoch: OwnerKeyEpoch | undefined, event: CanonicalEvent): readonly OwnerKey[] {
  const keys = epoch?.keys ?? [];
  if (event.type !== "OWNER_KEYS_ROTATED" || epoch?.policy?.recovery !== "COMMITTED_NEXT_KEYS" || epoch.nextKeyDigests === undefined) return keys;
  const committed = epoch.nextKeyDigests;
  const recovery = (event.data.ownerKeys as readonly OwnerKey[]).filter((key) => !keys.some((current) => current.keyId === key.keyId) && committed.includes(ownerKeyDigest(key)));
  return recovery.length === 0 ? keys : [...keys, ...recovery];
}
/**
 * A-110.1 `isRecovery(e)` (structural): a rotation under `recovery` with a signer entry (`controlAuthorization` or a
 * co-signature) naming a revealed committed key. Decided before verification; reported, never a replay input of its own.
 */
export function isRecoveryRotation(epoch: OwnerKeyEpoch | undefined, event: CanonicalEvent): boolean {
  const admissible = admissibleKeys(epoch, event);
  if (admissible.length === (epoch?.keys.length ?? 0)) return false;
  const signers = [event.data.controlAuthorization, ...((event.data[ADDITIONAL_CONTROL_AUTHORIZATIONS] ?? []) as readonly unknown[])].map((entry) => (entry as { keyId?: unknown } | null)?.keyId);
  return admissible.slice(epoch!.keys.length).some((key) => signers.includes(key.keyId));
}

const sameKey = (a: OwnerKey, b: OwnerKey): boolean => a.scheme === b.scheme && suiteFor(a.scheme).normalizeCredential(a.credential) === suiteFor(b.scheme).normalizeCredential(b.credential);

/**
 * The key-set rules of `OWNER_KEYS_ROTATED` against the epochs before it; the
 * reason on failure (replay reports it as `TRANSITION_INVALID`). For each key of
 * the new set, in order:
 *  1. a key id that appeared in any earlier epoch must name the same key
 *     (scheme and credential) — "bound to a different key" otherwise;
 *  2. such an id must be in the current set: a retired id never returns;
 *  3. a new key id must not carry a credential any earlier epoch declared (a
 *     retired key does not come back under another name, and a current key
 *     gets no alias).
 * Keys carried over (same id, same key) are allowed; the schema already
 * guarantees 1..64 keys with distinct ids.
 */
export function ownerKeyRotationFailure(epochs: readonly OwnerKeyEpoch[], keys: readonly OwnerKey[]): string | undefined {
  const current = epochs.at(-1)?.keys ?? [];
  const seen = new Map<string, OwnerKey>();
  for (const epoch of epochs) for (const key of epoch.keys) if (!seen.has(key.keyId)) seen.set(key.keyId, key);
  for (const key of keys) {
    const earlier = seen.get(key.keyId);
    if (earlier !== undefined) {
      if (!sameKey(earlier, key)) return `owner key rotation: key id ${key.keyId} was already bound to a different key`;
      if (!current.some((candidate) => candidate.keyId === key.keyId)) return `owner key rotation: retired owner key id ${key.keyId} cannot return`;
      continue;
    }
    for (const other of seen.values()) {
      if (sameKey(other, key)) return `owner key rotation: the key of new key id ${key.keyId} was already declared as ${other.keyId}`;
    }
  }
  return undefined;
}

export type ControlSignatureContext = Readonly<{
  domain: AuthorizationDomain;
  /** The head before the event; `null` only at position 0. */
  previousHead: Readonly<{ hash: ContentHash; position: U53 }> | null;
  /** The owner keys in force at the event's position (`ownerKeysAt(state, position)`). */
  keys: readonly OwnerKey[];
  algorithm: HashAlgorithm;
}>;

/**
 * docs/HISTORY-FORMAT.md §7 control authorization of one schema-valid format-1 control event:
 * `data.controlAuthorization = { keyId, signature }` by one of `keys` over the
 * challenge that binds the domain, the event id, type and time, the head before
 * it and the hash of its effect. The reason on failure, `undefined` when it verifies.
 */
export function controlSignatureFailure(event: CanonicalEvent, context: ControlSignatureContext): string | undefined {
  const authorization = event.data.controlAuthorization;
  if (authorization === null || typeof authorization !== "object" || Array.isArray(authorization)) return "control event is unsigned";
  const { keyId, signature } = authorization as { keyId?: unknown; signature?: unknown };
  if (Object.keys(authorization).length !== 2 || typeof keyId !== "string") return "control authorization is malformed";
  const ownerKey = context.keys.find((key) => key.keyId === keyId);
  const position = context.previousHead === null ? 0 : context.previousHead.position + 1;
  if (ownerKey === undefined) return `owner key ${keyId} is not an owner key in force at position ${position}`;
  const suite = suiteFor(ownerKey.scheme);
  if (!suite.isSignature(signature)) return "control signature is malformed";
  const hash = controlAuthorizationHash({
    domain: context.domain, eventId: event.id, eventType: event.type, timestamp: event.timestamp,
    previousHead: context.previousHead === null ? null : { hash: context.previousHead.hash, position: context.previousHead.position },
    effectHash: controlEffectHash(event, context.algorithm),
  }, context.algorithm);
  return suite.verify(hash, signature, suite.normalizeCredential(ownerKey.credential)) ? undefined : "control signature does not verify";
}

/** One signature of a ◆ event (`controlAuthorization` first, then each co-signature) as the quorum rule sees it. */
export type ControlSigner = Readonly<{ keyId: string; class: SignerClass; counts: boolean }>;
/** A-92.2 steps 2–6 failed: the reason, `required` = `M_eff(e)` and `present` = the counting signatures (A-92.6). */
export type ControlQuorumFailure = Readonly<{ reason: string; required: number; present: number }>;
/**
 * What the counting rule reads beside the signatures: `required` is `M_eff(e)` as A-92.2 step 0 decides it
 * (`controlThreshold(policy, event, σ(p))`); `epochKeys` is `K(p)` (default: `keys`, which is `adm(e)`); `exempt` is
 * `X(e) = PR_eff ∨ isRestoration ∨ isCheckpoint` and `restoration` is `isRestoration(e)` (A-107.2; both read only under
 * `ATTESTED`).
 */
export type QuorumRule = Readonly<{ keys: readonly OwnerKey[]; policy: OwnerPolicy | undefined; required: number; epochKeys?: readonly OwnerKey[]; exempt?: boolean; restoration?: boolean }>;
type QuorumContext = ControlSignatureContext & QuorumRule;

/** A-107.2: whether a signer of class `klass` is in the counting set `C(e)` of an event of `type`. */
const countsAs = (attested: boolean, type: string, klass: SignerClass, exempt: boolean, restoration: boolean): boolean => {
  if (!attested) return !(klass === "AGENT" && type === "OWNER_KEYS_ROTATED");
  if (type === "OWNER_KEYS_ROTATED") return klass === "HUMAN" || (restoration && klass === "LAPSED");
  return klass === "HUMAN" || klass === "AGENT" || (exempt && klass === "LAPSED");
};
/**
 * The quorum of a ◆ event under its pre-event policy (A-92.1 with A-107.2): `required` (`M_eff`, from step 0), and each
 * signature of `S` (`controlAuthorization`, then `additionalControlAuthorizations` in order) with its class `cls` at the
 * event's timestamp and whether it is in the counting set. Report-level; it verifies nothing.
 */
export function controlQuorum(event: CanonicalEvent, rule: QuorumRule): Readonly<{ required: number; signers: readonly ControlSigner[] }> {
  const entries = [event.data.controlAuthorization, ...((event.data[ADDITIONAL_CONTROL_AUTHORIZATIONS] ?? []) as readonly unknown[])];
  const attested = isAttestedPolicy(rule.policy), epochKeys = rule.epochKeys ?? rule.keys;
  const signers = entries.map((entry): ControlSigner => {
    const keyId = String((entry as { keyId?: unknown } | null | undefined)?.keyId);
    const key = rule.keys.find((candidate) => candidate.keyId === keyId);
    const klass: SignerClass = key === undefined ? (attested ? "NONE" : "HUMAN") : signerClass(rule.policy, epochKeys, key, event.timestamp);
    return Object.freeze({ keyId, class: klass, counts: countsAs(attested, event.type, klass, rule.exempt === true, rule.restoration === true) });
  });
  return Object.freeze({ required: rule.required, signers: Object.freeze(signers) });
}
/**
 * A-92.2 step 0 for a format-2 ◆ event at `position` (replay and the writer's pre-checks share it): the signature context
 * over `adm(e)` and the counting rule (`M_eff`, `K(p)`, `X(e)` and `isRestoration`, A-107.2), all decided from `e.data`,
 * the epoch record and the state before the event, before any signature is verified.
 */
export function controlRuleAt(state: ReplayState, event: CanonicalEvent, position: U53): ControlSignatureContext & QuorumRule {
  const epoch = ownerKeyEpochAt(state, position), policy = epoch?.policy;
  const attested = isAttestedPolicy(policy);
  const restoration = attested && isRestoration(event, epoch, epochOpenedAt(state, position) ?? 0);
  return {
    domain: state.genesis.domain, previousHead: position === 0 ? null : { hash: state.eventHistoryHashes[position - 1]!, position: position - 1 },
    keys: admissibleKeys(epoch, event), algorithm: state.hashAlgorithm, policy, required: controlThreshold(policy, event, state), epochKeys: epoch?.keys ?? [],
    restoration, exempt: attested && (restoration || event.type === "STATE_CHECKPOINT" || prEffective(event, state)),
  };
}
/**
 * A-119.1 rule T2 for a ◆ event at `position ≥ 1` that passed control authorization under `rule`: under `ATTESTED`, with at
 * most one human-class counting signer, the timestamp is the head's or at most `min(H(p), MAXT − 1)`. The reason and the
 * horizon, or `undefined`.
 */
export function singleSignerTimeFailure(state: ReplayState, event: CanonicalEvent, position: U53, rule: QuorumRule): Readonly<{ reason: string; horizon: U53 }> | undefined {
  if (position === 0 || !isAttestedPolicy(rule.policy)) return undefined;
  const horizon = Math.min(attestationHorizon(rule.policy)!, MAX_TIME - 1);
  if (event.timestamp === state.head.canonicalTime || event.timestamp <= horizon || humanClassCount(controlQuorum(event, rule).signers) >= 2) return undefined;
  return { reason: `time: a single human signer may not advance time past the attestation horizon (${horizon}) (A-119.1)`, horizon };
}
/**
 * A-109.1 rule T1 for a ◇ or ▲ event at `position ≥ 1` under an `ATTESTED` policy in force: its timestamp stays before the
 * expiry of every statement still unexpired at the head (`τ(p)`), so every crossing of an attestation expiry is
 * owner-signed. The reason and the expiry crossed, or `undefined`.
 */
export function attestationExpiryFailure(state: ReplayState, event: CanonicalEvent, position: U53): Readonly<{ reason: string; expiresAt: U53 }> | undefined {
  const policy = ownerKeyEpochAt(state, position)?.policy;
  if (position === 0 || !isAttestedPolicy(policy)) return undefined;
  const tau = state.head.canonicalTime;
  const crossed = policy!.attestations!.find((statement) => statement.expiresAt > tau && event.timestamp >= statement.expiresAt);
  return crossed === undefined ? undefined : { reason: `time: a session-signed event may not pass an owner attestation's expiry (${crossed.expiresAt}) (A-109.1)`, expiresAt: crossed.expiresAt };
}
/** The keys of `adm(e)` (`rule.keys`) with the class each has at the event's timestamp and whether it would count (A-107.2). */
export function eligibleSigners(event: CanonicalEvent, rule: QuorumRule): readonly (OwnerKey & Readonly<{ class: SignerClass; counts: boolean }>)[] {
  const attested = isAttestedPolicy(rule.policy), epochKeys = rule.epochKeys ?? rule.keys;
  return Object.freeze(rule.keys.map((key) => {
    const klass = signerClass(rule.policy, epochKeys, key, event.timestamp);
    return Object.freeze({ keyId: key.keyId, scheme: key.scheme, credential: key.credential, class: klass, counts: countsAs(attested, event.type, klass, rule.exempt === true, rule.restoration === true) });
  }));
}
/** A-119 Terms `hc(e)`: the number of human-class (`HUMAN` or `LAPSED`) counting signers. */
export const humanClassCount = (signers: readonly ControlSigner[]): number => signers.filter((signer) => signer.counts && (signer.class === "HUMAN" || signer.class === "LAPSED")).length;

/**
 * A-92.2 steps 2–6 for a ◆ event whose `controlAuthorization` verified (step 1, `controlSignatureFailure`), all
 * `CONTROL_AUTHORIZATION_INVALID`, first failure wins: (2) `additionalControlAuthorizations` is present iff
 * `M_eff(e) ≥ 2`; (3) every co-signature is by a key of `adm(e)` (`context.keys`) over the same `/2` challenge;
 * (4) the key ids and the credentials of all signatures are pairwise distinct; (5) the counting signatures number at
 * least `M_eff(e)`; (6) the floor: one counting signature is `HUMAN` (under `ATTESTED` on an `X(e)` event, `HUMAN` or
 * `LAPSED`; none on a rotation, whose counting set is human-class already). Under the default policy and without
 * co-signatures nothing applies (A-104.1 (20)): `undefined` at once.
 */
export function controlQuorumFailure(event: CanonicalEvent, context: QuorumContext): ControlQuorumFailure | undefined {
  const cosigned = Object.hasOwn(event.data, ADDITIONAL_CONTROL_AUTHORIZATIONS);
  if (context.policy === undefined && !cosigned) return undefined;
  const { required, signers } = controlQuorum(event, context);
  const present = signers.filter((signer) => signer.counts).length;
  const failed = (reason: string): ControlQuorumFailure => Object.freeze({ reason, required, present });
  if (cosigned !== required >= 2) {
    return failed(cosigned ? `additionalControlAuthorizations is present but ${event.type} needs ${required} signature (A-92.2 step 2)` : `${event.type} needs ${required} owner signatures: additionalControlAuthorizations is missing (A-92.2 step 2)`);
  }
  const position = context.previousHead === null ? 0 : context.previousHead.position + 1;
  const entries = (event.data[ADDITIONAL_CONTROL_AUTHORIZATIONS] ?? []) as readonly Readonly<{ keyId: string; signature: string }>[];
  if (entries.length > 0) {
    const hash = controlAuthorizationHash({
      domain: context.domain, eventId: event.id, eventType: event.type, timestamp: event.timestamp,
      previousHead: context.previousHead === null ? null : { hash: context.previousHead.hash, position: context.previousHead.position },
      effectHash: controlEffectHash(event, context.algorithm),
    }, context.algorithm);
    for (const [index, entry] of entries.entries()) {
      const key = context.keys.find((candidate) => candidate.keyId === entry.keyId);
      if (key === undefined) return failed(`additionalControlAuthorizations[${index}]: owner key ${entry.keyId} is not an owner key in force at position ${position} (A-92.2 step 3)`);
      const suite = suiteFor(key.scheme);
      if (!suite.isSignature(entry.signature) || !suite.verify(hash, entry.signature, suite.normalizeCredential(key.credential))) {
        return failed(`additionalControlAuthorizations[${index}]: the signature of ${entry.keyId} does not verify over the control challenge (A-92.2 step 3)`);
      }
    }
  }
  const keyIds = signers.map((signer) => signer.keyId);
  const credentials = keyIds.map((keyId) => credentialId(context.keys.find((key) => key.keyId === keyId)!));
  for (let index = 1; index < signers.length; index += 1) {
    if (keyIds.indexOf(keyIds[index]!) !== index) return failed(`owner key ${keyIds[index]} signs ${event.type} twice; signers must be distinct keys (A-92.2 step 4)`);
    if (credentials.indexOf(credentials[index]!) !== index) return failed(`owner keys ${keyIds[credentials.indexOf(credentials[index]!)]} and ${keyIds[index]} are one credential; signers must be distinct keys (A-92.2 step 4)`);
  }
  const attested = isAttestedPolicy(context.policy);
  if (present < required) {
    const why = attested ? " (A-107.2: NONE never counts; LAPSED counts only on a power-reducing event, a restoration or a checkpoint; AGENT never on OWNER_KEYS_ROTATED)" : present < signers.length ? " (AGENT keys never count on OWNER_KEYS_ROTATED)" : "";
    return failed(`${event.type} needs ${required} counting owner signatures, has ${present}${why} (A-92.2 step 5)`);
  }
  if (event.type === "OWNER_KEYS_ROTATED") return undefined;
  const floor = (signer: ControlSigner): boolean => signer.counts && (signer.class === "HUMAN" || (attested && context.exempt === true && signer.class === "LAPSED"));
  if (!signers.some(floor)) {
    return failed(attested ? `${event.type} has no counting ${context.exempt === true ? "HUMAN or LAPSED" : "HUMAN"} signer; an agent key never authorizes alone (A-92.2 step 6, A-107.2)` : `${event.type} is signed by AGENT keys only; an agent key never authorizes alone (A-92.2 step 6)`);
  }
  return undefined;
}

/**
 * A-101.1: control authorization of a `STATE_CHECKPOINT` against the epoch record in force at its position alone (A-92.2
 * with the pre-event policy `epoch.policy`: `M_eff(35)` counting signatures, `LAPSED` counting under `ATTESTED`); the
 * export verifier's authenticating checkpoint. The reason, or `undefined`.
 */
export function checkpointAuthorizationFailure(event: CanonicalEvent, context: Omit<ControlSignatureContext, "keys"> & Readonly<{ epoch: OwnerKeyEpoch | undefined }>): string | undefined {
  const policy = context.epoch?.policy, keys = context.epoch?.keys ?? [];
  const signature = { domain: context.domain, previousHead: context.previousHead, keys, algorithm: context.algorithm };
  const failure = controlSignatureFailure(event, signature);
  if (failure !== undefined) return failure;
  return controlQuorumFailure(event, { ...signature, policy, required: effectiveThreshold(policy, "STATE_CHECKPOINT"), epochKeys: keys, exempt: isAttestedPolicy(policy), restoration: false })?.reason;
}

/**
 * A-111.3 (report-level): the class of the owner key `keyId` that signed a statement of the head at `position` with
 * `canonicalTime`, under the policy of the epoch in force there, when that signer is unqualified (`AGENT`, `NONE` or
 * `LAPSED`; under `DECLARED` only `AGENT`); `undefined` for a qualified signer, a key not in force, or no policy.
 */
export function unqualifiedHeadSigner(source: EpochSource, position: number, canonicalTime: U53, keyId: string): SignerClass | undefined {
  const epoch = ownerKeyEpochAt(source, position);
  const key = epoch?.keys.find((candidate) => candidate.keyId === keyId);
  if (epoch?.policy === undefined || key === undefined) return undefined;
  const klass = signerClass(epoch.policy, epoch.keys, key, canonicalTime);
  return (isAttestedPolicy(epoch.policy) ? klass === "HUMAN" : klass !== "AGENT") ? undefined : klass;
}

/**
 * A-101.0 with A-111.1 (c): whether a `/2` head attestation signed by `key` for a head at `canonicalTime` may seed a
 * resume (or serve as an export view's asserted root). `atHead` is the epoch in force at `head.position`, `last` the
 * append epoch (in force after the file's head, A-120.0; for an export view, its last epoch). (a) Under `atHead.policy`
 * at `canonicalTime`: not `AGENT`, and `HUMAN` under `ATTESTED`. (b) Under `last.policy`, by credential: no key of `last`
 * with the signer's credential is classed `AGENT`, and under `ATTESTED` the credential is the subject of a statement in
 * that policy (any interval). (c) `M_eff(STATE_CHECKPOINT) = 1` under `last.policy`. The reason (for `FULL_REPLAY`), or
 * `undefined`. Under the default policy nothing applies.
 */
export function resumeRootFailure(key: OwnerKey, canonicalTime: U53, atHead: OwnerKeyEpoch, last: OwnerKeyEpoch): string | undefined {
  const before = atHead.policy, after = last.policy;
  const klass = signerClass(before, atHead.keys, key, canonicalTime);
  if (klass === "AGENT" || (isAttestedPolicy(before) && klass !== "HUMAN")) {
    return `the attestation's signer ${key.keyId} is ${klass} at ${canonicalTime} under the policy in force at the attested head; it is not a resume root (A-101.0 (a))`;
  }
  const id = credentialId(key);
  const classes = after?.keyClasses as Readonly<Record<string, string>> | undefined;
  const agent = last.keys.find((candidate) => credentialId(candidate) === id && classes !== undefined && Object.hasOwn(classes, candidate.keyId) && classes[candidate.keyId] === "AGENT");
  if (agent !== undefined) return `the attestation's signer credential is the AGENT key ${agent.keyId} under the policy in force after the head; it is not a resume root (A-101.0 (b))`;
  if (isAttestedPolicy(after) && !(after!.attestations ?? []).some((statement) => credentialId(statement.subject) === id)) {
    return `the attestation's signer ${key.keyId} has no human attestation in the ATTESTED policy in force after the head; it is not a resume root (A-101.0 (b))`;
  }
  const required = effectiveThreshold(after, "STATE_CHECKPOINT");
  if (required !== 1) return `a checkpoint needs ${required} owner signatures under the policy in force after the head, so no single-key head attestation is a resume root; only an in-file STATE_CHECKPOINT is (A-111.1 (c))`;
  return undefined;
}

/**
 * True iff `attestation` is a well-formed head attestation signed by an owner
 * key in force at the position of the head it names (`ownerKeysAt`), for this
 * history's domain and hash algorithm. Whether that head is a prefix of the
 * history is a separate check. Never throws.
 */
export function verifyHeadAttestationAt(attestation: unknown, state: ReplayState): boolean {
  if (attestation === null || typeof attestation !== "object") return false;
  const position = ((attestation as { head?: unknown }).head as { position?: unknown } | null | undefined)?.position;
  // U53 as canonical encoding defines it: -0 is not a position (fuzz VAST-FUZZ-01 F4).
  if (!isU53(position)) return false;
  // A format-2 history carries `/2` attestations and every other format `/1` (SPEC §7.4); the other version never verifies.
  const version = (attestation as { version?: unknown }).version;
  if (version !== (isFormat2(state.format) ? HEAD_ATTESTATION_VERSION_2 : HEAD_ATTESTATION_VERSION)) return false;
  return verifyHeadAttestation(attestation, state.genesis.domain, ownerKeysAt(state, position), state.hashAlgorithm);
}

/** The four facts of SPEC §7.4 and `valid = all`. */
export type HeadAttestationFacts = Readonly<{ signatureValid: boolean; prefix: boolean; stateRootValid: boolean; projectionValid: boolean; valid: boolean }>;
/**
 * SPEC §7.4 verification of a head attestation against a replayed history: `signatureValid` (the body names this
 * history's domain and the signature verifies under an owner key in force at `head.position`), `prefix` (the history's
 * head hash at that position equals `head.hash`), `stateRootValid` (`rootAt(head.position)`), `projectionValid` (the
 * §12 head at that position, or both `null`). For legacy and format-1 histories the last two are `true`. Never throws.
 * A state a store resumed from a snapshot (SPEC §7.5) holds roots only from the snapshot position on: an attestation of
 * an earlier position reads `stateRootValid: false` there; judge it on a full replay (`store.verify()` does).
 */
export function verifyHeadAttestationFacts(attestation: unknown, state: ReplayState): HeadAttestationFacts {
  const facts = (signatureValid: boolean, prefix: boolean, stateRootValid: boolean, projectionValid: boolean): HeadAttestationFacts =>
    Object.freeze({ signatureValid, prefix, stateRootValid, projectionValid, valid: signatureValid && prefix && stateRootValid && projectionValid });
  if (attestation === null || typeof attestation !== "object") return facts(false, false, false, false);
  const a = attestation as { head?: { hash?: unknown; position?: unknown } | null; stateRoot?: unknown; projectionHead?: unknown };
  const position = a.head === null || typeof a.head !== "object" ? undefined : a.head.position;
  // -0 is not a position (canonical U53): it was taken as 0 here, so `prefix` disagreed with the Python verifier (fuzz VAST-FUZZ-01 F4).
  const at = isU53(position) && position <= state.head.position ? position : undefined;
  const signatureValid = verifyHeadAttestationAt(attestation, state);
  const prefix = at !== undefined && state.eventHistoryHashes[at] === a.head?.hash;
  if (!isFormat2(state.format)) return facts(signatureValid, prefix, true, true);
  const stateRootValid = at !== undefined && rootAt(state, at) === a.stateRoot;
  const projectionValid = at !== undefined && projectionHeadAt(state, at) === a.projectionHead;
  return facts(signatureValid, prefix, stateRootValid, projectionValid);
}

/** True iff `key` (id, scheme and credential) is an owner key in force at `position`. */
export function ownerKeyInForce(source: EpochSource, position: number, key: Readonly<{ keyId: string; scheme: string; credential: string }>): boolean {
  return ownerKeysAt(source, position).some((candidate) => candidate.keyId === key.keyId && candidate.scheme === key.scheme &&
    sameKey(candidate, { keyId: key.keyId, scheme: candidate.scheme, credential: key.credential }));
}

/** What the challenge of an owner key event binds: needed to check the revealed keys' `nextKeyAuthorizations`. */
export type OwnerKeyEventContext = Readonly<{
  domain: AuthorizationDomain;
  /** The head before the event (its position + 1 is the event's position). */
  previousHead: Readonly<{ hash: ContentHash; position: U53 }>;
  algorithm: HashAlgorithm;
}>;
export type OwnerKeyEventOutcome =
  | Readonly<{
    ok: true;
    /** The epochs after the rotation (it appends one). */
    epochs: readonly OwnerKeyEpoch[];
    /** The epoch in force after the event: its first position and keys. */
    fromPosition: U53;
    keys: readonly OwnerKey[];
    /** The rotation satisfied the commitment of the epoch it left. */
    preRotated: boolean;
    /** The rotation keeps every owner key and only adds a next-key commitment (a commitment-only rotation). */
    commitmentOnly: boolean;
    /** A-96.1 (format 2, `policies` option): the rotation keeps every owner key and changes the policy as written. */
    policyRotation: boolean;
    /** The commitment of the epoch in force after the event, when it has one. */
    nextKeyDigests?: readonly ContentHash[];
  }>
  | Readonly<{ ok: false; reason: string }>;

const freezeKeys = (keys: readonly OwnerKey[]): readonly OwnerKey[] =>
  Object.freeze(keys.map((key) => Object.freeze({ keyId: key.keyId, scheme: key.scheme, credential: key.credential })));

/** True iff `keys` is exactly the current set: every key carried over, none added (a rotation that changes no key). */
export const keepsEveryOwnerKey = (current: readonly OwnerKey[], keys: readonly OwnerKey[]): boolean =>
  keys.length === current.length && keys.every((key) => current.some((candidate) => candidate.keyId === key.keyId && sameKey(candidate, key)));

/**
 * A-107.3 with A-118.2 `isRestoration(e)` (decided from `e.data`, the epoch record and `t_set` before any signature is
 * counted): under an `ATTESTED` policy in force, a policy rotation (every key kept, the policy changed as written) to an
 * `ATTESTED` policy that keeps every field but `attestations` and `labels` as written, keeps the commitment (presence and
 * set), keeps the set of subject credentials, and whose every statement is carried as written or renews the statement of
 * its subject: `max(a.notBefore, t_set) < a'.notBefore ≤ e.timestamp` and `a'.expiresAt > a.expiresAt`.
 */
export function isRestoration(event: CanonicalEvent, epoch: OwnerKeyEpoch | undefined, tSet: U53): boolean {
  const before = epoch?.policy, after = event.data.ownerPolicy as OwnerPolicy | undefined;
  if (event.type !== "OWNER_KEYS_ROTATED" || !isAttestedPolicy(before) || after === undefined || after.humanFloor !== "ATTESTED") return false;
  if (!keepsEveryOwnerKey(epoch!.keys, event.data.ownerKeys as readonly OwnerKey[]) || sameOwnerPolicy(after, before)) return false;
  const same = (a: unknown, b: unknown): boolean => (a === undefined || b === undefined ? a === b : canonicalEncode(a) === canonicalEncode(b));
  if (!(["threshold", "byType", "keyClasses", "attesters", "recovery", "acknowledged"] as const).every((field) => same(after[field], before![field]))) return false;
  const next = event.data.nextKeyDigests as readonly ContentHash[] | undefined, committed = epoch!.nextKeyDigests;
  if ((next === undefined) !== (committed === undefined) || (next !== undefined && (next.length !== committed!.length || !next.every((digest) => committed!.includes(digest))))) return false;
  const old = before!.attestations ?? [], renewed = after.attestations ?? [];
  const subjects = (list: readonly HumanAttestation[]): string => list.map((a) => credentialId(a.subject)).sort().join("\n");
  if (subjects(old) !== subjects(renewed)) return false;
  return renewed.every((statement) => {
    if (old.some((carried) => same(carried, statement))) return true;
    const previous = old.find((a) => credentialId(a.subject) === credentialId(statement.subject))!;
    return Math.max(previous.notBefore, tSet) < statement.notBefore && statement.notBefore <= event.timestamp && statement.expiresAt > previous.expiresAt;
  });
}

/**
 * The `OWNER_KEYS_ROTATED` events behind a history's epochs, by kind: `keyRotations` changed the owner keys,
 * `policyRotations` kept every key and changed the owner approval policy as written (A-96.3), `commitmentRotations`
 * kept every key and the policy and only committed next keys (`owner commit-next-key`).
 */
export function ownerKeyRotationCounts(source: EpochSource): Readonly<{ keyRotations: number; commitmentRotations: number; policyRotations: number }> {
  const epochs = epochsOf(source);
  let commitmentRotations = 0, policyRotations = 0;
  for (let index = 1; index < epochs.length; index += 1) {
    const before = epochs[index - 1]!, after = epochs[index]!;
    if (!keepsEveryOwnerKey(before.keys, after.keys)) continue;
    if (sameOwnerPolicy(before.policy, after.policy)) commitmentRotations += 1;
    else policyRotations += 1;
  }
  return Object.freeze({ keyRotations: epochs.length - 1 - commitmentRotations - policyRotations, commitmentRotations, policyRotations });
}

/**
 * A-117.3 (under `G(e, p)`, at the HF1 §7.2 digest-rule stage): no digest the rotation introduces (`nextKeyDigests` minus
 * the commitment in force) names a credential of `foreign(σ(p))` (`foreignDigests`, replay only), an attester of the
 * policy in force or an attester of the resulting policy. A carried digest is not re-tested. The reason, or `undefined`.
 */
const introducedDigestFailure = (next: readonly ContentHash[], current: OwnerKeyEpoch, policy: OwnerPolicy | undefined, foreignDigests: (() => ReadonlySet<ContentHash>) | undefined): string | undefined => {
  const introduced = next.filter((digest) => current.nextKeyDigests?.includes(digest) !== true);
  if (introduced.length === 0) return undefined;
  const attesters = [...(current.policy?.attesters ?? []), ...(policy?.attesters ?? [])];
  const attester = attesters.find((entry) => introduced.includes(ownerKeyDigest(entry)));
  if (attester !== undefined) return `owner key rotation: next-key digest ${ownerKeyDigest(attester)} names attester ${attester.keyId}; commit to a dedicated key (A-117.3)`;
  const foreign = foreignDigests?.();
  const named = foreign === undefined ? undefined : introduced.find((digest) => foreign.has(digest));
  return named === undefined ? undefined : `owner key rotation: next-key digest ${named} names a session or counterparty credential of this history; commit to a dedicated key (A-110.2, A-117.3)`;
};

/**
 * The owner-key rules of a schema-valid, owner-signed `OWNER_KEYS_ROTATED` at
 * `context.previousHead.position + 1`, against the epochs before it (replay
 * reports a failure as `TRANSITION_INVALID`): the key-set rules
 * (`ownerKeyRotationFailure`); every entry of `nextKeyAuthorizations` must be a
 * signature, over the event's own control-authorization challenge, by a key the
 * rotation reveals (a key of the new set not carried over from the current
 * one). When the epoch it leaves has a commitment, the rotation must satisfy
 * it: every revealed key's digest is in the commitment, at least one key is
 * revealed and signs `nextKeyAuthorizations` (proof of possession), and the
 * rotation carries the commitment of the new epoch (`nextKeyDigests`). Out of
 * an uncommitted epoch the rotation is free and may start a commitment; one
 * that keeps every key must (a commitment-only rotation; without
 * `nextKeyDigests` it would change nothing and is refused). No digest may name
 * a key the history declared.
 *
 * `options.policies` (format 2: replay, and `verifyRotationEvent` for a witness, the snapshot resume and the export
 * verifier): HF1 §7.1–7.2 as read for format 2 with owner approval policies (A-96.2).
 * Under the guard `G(e, p)` (A-108.1: `ownerPolicy` in the event or `policy` in the epoch it leaves) rule 4 is per
 * revealed key (A-108.2: exactly one `nextKeyAuthorizations` entry per revealed key) and no introduced `nextKeyDigests`
 * entry may be the digest of a foreign or attester credential (A-117.3: `options.foreignDigests`, the session and
 * counterparty credentials of the state before the event, replay only; the attester clause needs only the epoch
 * record and applies without it, G63-X-5; a carried digest is not re-tested).
 * A rotation that keeps every key and whose `ownerPolicy` differs as written from the epoch's `policy` is a policy
 * rotation: out of a committed epoch it carries no `nextKeyAuthorizations` and restates the commitment unchanged (rule 3
 * and rule 4 are waived for it); out of an uncommitted epoch it may start a commitment. The new epoch records the policy
 * as written. Without the option (format 1) HF1 applies literally, and no epoch carries a policy.
 */
export function ownerKeyEventTransition(epochs: readonly OwnerKeyEpoch[], event: CanonicalEvent, context: OwnerKeyEventContext, options: Readonly<{ policies?: boolean; foreignDigests?: () => ReadonlySet<ContentHash> }> = {}): OwnerKeyEventOutcome {
  const current = epochs.at(-1);
  const position = context.previousHead.position + 1;
  if (current === undefined) return { ok: false, reason: "no owner keys are in force" };
  const declared = epochs.flatMap((epoch) => epoch.keys);
  if (event.type !== "OWNER_KEYS_ROTATED") return { ok: false, reason: `${event.type} is not an owner key event` };
  const keys = freezeKeys(event.data.ownerKeys as readonly OwnerKey[]);
  const rule = ownerKeyRotationFailure(epochs, keys);
  if (rule !== undefined) return { ok: false, reason: rule };
  const revealed = keys.filter((key) => !current.keys.some((candidate) => candidate.keyId === key.keyId));
  const authorizations = (event.data.nextKeyAuthorizations ?? []) as readonly Readonly<{ keyId: string; scheme: SignatureScheme; signature: string }>[];
  const policy = options.policies === true ? event.data.ownerPolicy as OwnerPolicy | undefined : undefined;
  const policyRotation = options.policies === true && keepsEveryOwnerKey(current.keys, keys) && !sameOwnerPolicy(policy, current.policy);
  const guarded = options.policies === true && policyGuard(event, current);
  const commitment = current.nextKeyDigests;
  if (policyRotation && commitment !== undefined) {
    // A-96.2 (i): out of a committed epoch a policy rotation reveals nothing and carries the commitment over unchanged.
    if (Object.hasOwn(event.data, "nextKeyAuthorizations")) return { ok: false, reason: "owner key rotation: a policy rotation reveals no key" };
    const digests = event.data.nextKeyDigests as readonly ContentHash[] | undefined;
    if (digests === undefined || digests.length !== commitment.length || !digests.every((digest) => commitment.includes(digest))) {
      return { ok: false, reason: "owner key rotation: a policy rotation carries the current commitment unchanged" };
    }
  }
  if (authorizations.length > 0) {
    const challenge = controlAuthorizationHash({
      domain: context.domain, eventId: event.id, eventType: event.type, timestamp: event.timestamp,
      previousHead: { hash: context.previousHead.hash, position: context.previousHead.position }, effectHash: controlEffectHash(event, context.algorithm),
    }, context.algorithm);
    for (const proof of authorizations) {
      const key = revealed.find((candidate) => candidate.keyId === proof.keyId);
      if (key === undefined) return { ok: false, reason: `owner key rotation: next-key authorization by ${proof.keyId} names no owner key this rotation reveals` };
      if (proof.scheme !== key.scheme) return { ok: false, reason: `owner key rotation: next-key authorization by ${proof.keyId} uses scheme ${proof.scheme}, not the key's ${key.scheme}` };
      const suite = suiteFor(key.scheme);
      if (!suite.isSignature(proof.signature) || !suite.verify(challenge, proof.signature, suite.normalizeCredential(key.credential))) {
        return { ok: false, reason: `owner key rotation: next-key authorization by ${proof.keyId} does not verify` };
      }
    }
  }
  if (commitment !== undefined && !policyRotation) {
    for (const key of revealed) {
      if (!commitment.includes(ownerKeyDigest(key))) {
        return { ok: false, reason: `owner key rotation: new owner key ${key.keyId} is not one of the next keys the owner keys in force committed to (pre-rotation)` };
      }
    }
    if (revealed.length === 0) return { ok: false, reason: "owner key rotation: the owner keys in force committed to next keys; the rotation must reveal at least one of them" };
    // A-108.2: under G(e, p) rule 4 is per revealed key (exactly one proof each); HF1's literal text otherwise.
    if (guarded && revealed.some((key) => authorizations.filter((proof) => proof.keyId === key.keyId).length !== 1)) {
      return { ok: false, reason: "owner key rotation: every revealed key must prove possession" };
    }
    if (authorizations.length === 0) {
      return { ok: false, reason: "owner key rotation: no revealed next key signed nextKeyAuthorizations; a rotation out of a committed epoch must prove possession of a committed key" };
    }
    if (event.data.nextKeyDigests === undefined) {
      return { ok: false, reason: "owner key rotation: a pre-rotated rotation must commit to the next keys of the new owner key set (nextKeyDigests)" };
    }
  }
  const commitmentOnly = keepsEveryOwnerKey(current.keys, keys) && !policyRotation;
  if (commitmentOnly && event.data.nextKeyDigests === undefined) {
    return { ok: false, reason: "owner key rotation: a rotation that keeps every owner key changes nothing unless it adds a next-key commitment (nextKeyDigests)" };
  }
  const next = event.data.nextKeyDigests === undefined ? undefined : Object.freeze((event.data.nextKeyDigests as readonly ContentHash[]).slice());
  if (next !== undefined) {
    const clash = declaredDigestFailure("owner key rotation", [...declared, ...keys], next);
    if (clash !== undefined) return { ok: false, reason: clash };
    const introduced = guarded ? introducedDigestFailure(next, current, policy, options.foreignDigests) : undefined;
    if (introduced !== undefined) return { ok: false, reason: introduced };
  }
  const epoch: OwnerKeyEpoch = Object.freeze({ fromPosition: position + 1, keys, ...(next === undefined ? {} : { nextKeyDigests: next }), ...(policy === undefined ? {} : { policy }) });
  return Object.freeze({
    ok: true as const, epochs: Object.freeze([...epochs, epoch]), fromPosition: position + 1, keys, preRotated: commitment !== undefined && !policyRotation, commitmentOnly, policyRotation,
    ...(next === undefined ? {} : { nextKeyDigests: next }),
  });
}

/**
 * The result of `verifyRotationEvent`: `fromPosition`/`keys` are the new epoch, `preRotated` says whether the rotation
 * satisfied the commitment of the epoch it left (the witness-side supersede rule needs this), `commitmentOnly` whether it
 * kept every key and only added a commitment, `nextKeyDigests` is the new epoch's commitment and `epochs` the extended list.
 * A-100.1 / A-120.1 (format 2): `policyRotation`, `restoration` and `recovery` say what kind of rotation it was,
 * `quorum` is the counting listing (`M_eff` and every signature with its class, A-95.6), `openedAt` is the new epoch's
 * `t_set` (the rotation's timestamp) and `stateChecked` is always `false`: the rules that read the replayed state
 * (A-117.2, the `foreign` clauses of A-117.3 and A-117.4) are not checked here; full replay is the authority.
 * A refusal with `notJudged` was not decided: the context lacked what one rule needs (`"T2"`: the head's `canonicalTime`).
 */
export type RotationVerification =
  | Readonly<{
    ok: true; event: CanonicalEvent; position: U53; fromPosition: U53; keys: readonly OwnerKey[]; reason?: string; epochs: readonly OwnerKeyEpoch[];
    preRotated: boolean; commitmentOnly: boolean; nextKeyDigests?: readonly ContentHash[];
    policyRotation: boolean; restoration: boolean; recovery: boolean; quorum: Readonly<{ required: number; signers: readonly ControlSigner[] }>;
    openedAt: U53; stateChecked: false;
  }>
  | Readonly<{ ok: false; code: ReplayCode; reason: string; notJudged?: "T2" }>;
/** @see RotationVerification (an owner key event is a rotation). */
export type KeyEventVerification = RotationVerification;

export type RotationContext = Readonly<{
  domain: AuthorizationDomain;
  /**
   * The head the rotation extends (its signed `previousHead`): the rotation sits at `previousHead.position + 1`.
   * `canonicalTime` is `τ` for rule T2 (A-119.1, A-120.1); without it a rotation that T2 would decide is refused as
   * not judged (`notJudged: "T2"`).
   */
  previousHead: Readonly<{ hash: ContentHash; position: U53; canonicalTime?: U53 }>;
  /**
   * The owner key epochs known before the rotation (genesis first, `fromPosition` 0), each with the next-key
   * commitment it made (`nextKeyDigests`) and, in format 2, the owner approval policy it was set with (`policy`, copied
   * as written; absent: the default). Required: seed it from the genesis
   * (`{ fromPosition: 0, keys: genesis.ownerKeys, nextKeyDigests: genesis.nextKeyDigests, policy: genesis.ownerPolicy }`),
   * so that epoch 0's commitment and policy are enforced. A bare key set is refused (`INVALID_INPUT`), because it would
   * silently drop a commitment.
   */
  epochs: readonly OwnerKeyEpoch[];
  /** A-114.0 `t_set` of each epoch (the timestamp of the event that opened it; the genesis for epoch 0), parallel to `epochs`. Needed under `ATTESTED`. */
  openedAt?: readonly U53[];
  /** Format 2: the history's id, `recordHash(0)`, which a statement set after the genesis must name (A-107.4). Needed when the rotation sets statements. */
  historyId?: ContentHash;
  /**
   * A-131.1: the export key-event verifier without the event before the rotation omits T2 and reports it as not judged.
   * Only that verifier sets it; a witness and the snapshot resume hold the head before the rotation and apply T2 in full.
   */
  omitT2?: boolean;
  /** Default `sha256` (format 1). */
  algorithm?: HashAlgorithm;
}>;
export type KeyEventContext = RotationContext;

/** Why `epochs` is not a usable epoch list (non-empty, genesis first, increasing positions, key sets, commitments), or undefined. */
function epochsShapeFailure(epochs: unknown): string | undefined {
  if (!Array.isArray(epochs) || epochs.length === 0) return "epochs must be a non-empty list";
  let previous = -1;
  for (const [index, epoch] of epochs.entries()) {
    if (epoch === null || typeof epoch !== "object" || Array.isArray(epoch)) return `epoch ${index} is not a record`;
    const { fromPosition, keys, nextKeyDigests, policy } = epoch as Record<string, unknown>;
    if (!isU53(fromPosition)) return `epoch ${index} has no fromPosition`;
    if (index === 0 ? fromPosition !== 0 : (fromPosition as number) <= previous) return index === 0 ? "the first epoch must start at the genesis (fromPosition 0)" : `epoch ${index} does not start after epoch ${index - 1}`;
    previous = fromPosition as number;
    if (!Array.isArray(keys) || keys.length === 0) return `epoch ${index} has no owner keys`;
    if (nextKeyDigests !== undefined && (!Array.isArray(nextKeyDigests) || nextKeyDigests.length === 0 || !nextKeyDigests.every(isContentHash))) {
      return `epoch ${index} has a malformed nextKeyDigests`;
    }
    if (policy !== undefined && (policy === null || typeof policy !== "object" || Array.isArray(policy) || !Number.isSafeInteger((policy as { threshold?: unknown }).threshold))) {
      return `epoch ${index} has a malformed policy`;
    }
  }
  return undefined;
}

/**
 * Checks an `OWNER_KEYS_ROTATED` event without the history, as a remote witness, the snapshot resume and the export
 * verifier must. Format 1: the closed schema at position `previousHead.position + 1`, the owner signature over the
 * control challenge with `previousHead` by a key in force there, the key-set rules against `epochs`, and the
 * pre-rotation rules against the commitment `epochs` records for the epoch it leaves (`ownerKeyEventTransition`).
 *
 * Format 2 (a `version: "2"` domain): `acceptSF` of A-120.1, row 26 of Appendix A in its order without the rules that
 * read the replayed state. Control authorization under A-92.2 with the pre-event policy of the epoch in force
 * (`epochs[i].policy`, default `{threshold: 1}`), over the admissible signer set of A-97.2 and the counting rules of
 * A-107.2 (`CONTROL_AUTHORIZATION_INVALID`); rule T2 with `τ = previousHead.canonicalTime` (`TRANSITION_INVALID`); the
 * §3.3 key test and the validity of the resulting policy, with `historyId` (`EVENT_DATA_INVALID`); HF1 §7.1–7.2 as read
 * for format 2, with A-117.3's attester clause (G63-X-5) but not its `foreign` one (`TRANSITION_INVALID`). The new epoch
 * records `policy` as written.
 *
 * On success the new set governs from `fromPosition = previousHead.position + 2` and `epochs` is the extended list. It
 * does NOT establish that `previousHead` is the head this history really has (the caller's chaining rule does), nor the
 * event-id uniqueness, time-order and foreign-credential checks only a full replay can make (`stateChecked: false`).
 * A-120.2: a rotation full replay accepts is accepted here, and on an accepted history the epochs are those of replay.
 */
export function verifyRotationEvent(event: unknown, context: RotationContext): RotationVerification {
  const type = "OWNER_KEYS_ROTATED";
  const what = "a rotation";
  const previous = context.previousHead;
  if (previous === null || typeof previous !== "object" || !isU53(previous.position)) {
    return { ok: false, code: "INVALID_INPUT", reason: `${what} needs the head before it` };
  }
  const position = previous.position + 1;
  // The rotation is a format-2 event under a format-2 domain (`version: "2"`, SPEC §7.4), else format 1.
  const format2 = context.domain.version === "2";
  const validation = validateEvent(event, format2 ? TRELLIS2_FORMAT : TRELLIS_FORMAT, position);
  if (!validation.ok) return validation;
  const valid = validation.event;
  if (valid.type !== type) return { ok: false, code: "INVALID_INPUT", reason: `expected ${type}, got ${valid.type}` };
  if (Object.hasOwn(context, "keys")) {
    return { ok: false, code: "INVALID_INPUT", reason: `${what} is checked against epochs seeded from the genesis (with its nextKeyDigests), not a bare key set` };
  }
  const shape = epochsShapeFailure(context.epochs);
  if (shape !== undefined) return { ok: false, code: "INVALID_INPUT", reason: `${what} needs the owner key epochs in force before it: ${shape}` };
  const epochs = context.epochs;
  if (context.openedAt !== undefined && (!Array.isArray(context.openedAt) || context.openedAt.length !== epochs.length || !context.openedAt.every(isU53))) {
    return { ok: false, code: "INVALID_INPUT", reason: `${what}: openedAt must give one t_set per epoch` };
  }
  if (previous.canonicalTime !== undefined && !isU53(previous.canonicalTime)) {
    return { ok: false, code: "INVALID_INPUT", reason: `${what}: previousHead.canonicalTime is not a U53` };
  }
  const algorithm = context.algorithm ?? "sha256";
  const previousHead = { hash: previous.hash, position: previous.position };
  const index = epochs.findLastIndex((epoch) => epoch.fromPosition <= position);
  const epoch = epochs[index]!, policy = format2 ? epoch.policy : undefined;
  const attested = isAttestedPolicy(policy);
  const tSet = context.openedAt?.[index];
  if (attested && tSet === undefined) return { ok: false, code: "INVALID_INPUT", reason: `${what} under an ATTESTED policy needs the t_set of the epoch in force (openedAt)` };
  const restoration = attested && isRestoration(valid, epoch, tSet!);
  const rule: QuorumRule = {
    keys: format2 ? admissibleKeys(epoch, valid) : epoch.keys, policy, required: rotationThreshold(policy), epochKeys: epoch.keys, restoration, exempt: restoration,
  };
  const signature = { domain: context.domain, previousHead, keys: rule.keys, algorithm };
  const failure = controlSignatureFailure(valid, signature);
  if (failure !== undefined) return { ok: false, code: "CONTROL_AUTHORIZATION_INVALID", reason: failure };
  if (format2) {
    const quorum = controlQuorumFailure(valid, { ...signature, ...rule });
    if (quorum !== undefined) return { ok: false, code: "CONTROL_AUTHORIZATION_INVALID", reason: quorum.reason };
    // A-119.1 T2, τ = previousHead.canonicalTime (A-120.1). Decided without τ whenever τ cannot change the verdict.
    if (attested && context.omitT2 !== true) {
      const horizon = Math.min(attestationHorizon(policy)!, MAX_TIME - 1);
      if (valid.timestamp > horizon && humanClassCount(controlQuorum(valid, rule).signers) < 2) {
        if (previous.canonicalTime === undefined) {
          return { ok: false, code: "INVALID_INPUT", notJudged: "T2", reason: `${what} past the attestation horizon (${horizon}) with one human signer needs the canonicalTime of the head before it (A-119.1, A-120.1): not judged` };
        }
        if (valid.timestamp !== previous.canonicalTime) {
          return { ok: false, code: "TRANSITION_INVALID", reason: `time: a single human signer may not advance time past the attestation horizon (${horizon}) (A-119.1)` };
        }
      }
    }
    const keys = valid.data.ownerKeys as readonly OwnerKey[], next = valid.data.ownerPolicy as OwnerPolicy | undefined;
    if (next?.attestations !== undefined && next.attestations.length > 0 && context.historyId === undefined) {
      return { ok: false, code: "INVALID_INPUT", reason: `${what} that sets human attestations needs the history's id (recordHash(0), A-107.4)` };
    }
    const invalid = declaredKeyFailure(valid) ?? (next === undefined ? undefined : ownerPolicyFailure(next, keys, {
      setting: { domain: context.domain, timestamp: valid.timestamp, nextKeyDigests: (valid.data.nextKeyDigests ?? []) as readonly ContentHash[], genesis: false, previous: policy, ...(context.historyId === undefined ? {} : { historyId: context.historyId }) },
    }));
    if (invalid !== undefined) return { ok: false, code: "EVENT_DATA_INVALID", reason: invalid };
  }
  const outcome = ownerKeyEventTransition(epochs, valid, { domain: context.domain, previousHead, algorithm }, { policies: format2 });
  if (!outcome.ok) return { ok: false, code: "TRANSITION_INVALID", reason: outcome.reason };
  return Object.freeze({
    ok: true as const, event: valid, position, fromPosition: outcome.fromPosition, keys: outcome.keys,
    ...(typeof valid.data.reason === "string" ? { reason: valid.data.reason } : {}), epochs: outcome.epochs,
    preRotated: outcome.preRotated, commitmentOnly: outcome.commitmentOnly, ...(outcome.nextKeyDigests === undefined ? {} : { nextKeyDigests: outcome.nextKeyDigests }),
    policyRotation: outcome.policyRotation, restoration, recovery: format2 && isRecoveryRotation(epoch, valid), quorum: controlQuorum(valid, rule),
    openedAt: valid.timestamp, stateChecked: false as const,
  });
}
