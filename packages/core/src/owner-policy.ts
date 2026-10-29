/**
 * Owner approval policy (A-91, A-99, A-102; format 2): the optional `ownerPolicy` of the genesis (row 0) and of
 * `OWNER_KEYS_ROTATED` (row 26). The policy belongs to an owner key epoch (`OwnerKeyEpoch.policy`, copied as written):
 * the genesis sets epoch 0's, every accepted rotation sets the next epoch's, and a rotation without `ownerPolicy` sets
 * the default `{threshold: 1}`. Every ◆ event is authorized under the policy in force BEFORE it (A-91.4), including the
 * rotation that replaces it.
 *
 * This module holds the pure parts: the thresholds (`M_eff` with power reduction by effect, A-106.2; `M_rot`), the class
 * of a key (a function of its credential, A-99), "as written" equality, and the validity rules of A-91.2 at the setting
 * event (all `EVENT_DATA_INVALID`). The shape check (C4) is in events.ts and the quorum rule (A-92.2) in owner-keys.ts.
 *
 * Human attestation (A-93 with A-98, A-107, A-118, A-119; the G6.x holds were lifted on 2026-10-12): the class function
 * `cls` (A-107.1 / A-118.4), the statements' validity at the setting event (A-93.2 with A-97.5, A-107.4, A-117.4, A-118)
 * and the attestation horizon `H` used by rule T2 (A-119.1).
 */
import { canonicalEncode } from "./canonical.ts";
import { ed25519KeyCheck } from "./crypto/ed25519-point.ts";
import { suiteFor } from "./crypto/suites.ts";
import { hashCanonical } from "./hash.ts";
import { ownerKeyDigest } from "./owner-key-digest.ts";
import { CONTROL_EVENT_TYPES } from "./types.ts";
import type { BudgetRecord } from "./budgets.ts";
import type { AuthorityRecord, AuthorizationDomain, CanonicalEvent, ContentHash, EventType, HumanAttestation, OwnerKey, OwnerKeyClass, OwnerKeyEpoch, OwnerPolicy, ReplayState, U53 } from "./types.ts";
import { readonlySet } from "./readonly-collections.ts";

export type { OwnerKeyClass, OwnerPolicy } from "./types.ts";

/** The policy of an epoch set without `ownerPolicy` (A-91.0). */
export const DEFAULT_OWNER_POLICY: OwnerPolicy = Object.freeze({ threshold: 1 });
/** A-92.0: at most 63 co-signatures beside `controlAuthorization` (64 signers, the owner-key bound). */
export const MAX_ADDITIONAL_CONTROL_AUTHORIZATIONS = 63;
/** A-93.1: the human-attestation fields of `ownerPolicy`. */
export const ATTESTATION_POLICY_FIELDS = Object.freeze(["humanFloor", "attesters", "attestations"] as const);
/** A-93.1: the signed statement's version literal (Appendix C). */
export const HUMAN_ATTESTATION_VERSION = "irontrellis-human-attestation/1";
/** A-116 Terms `MAXT = 2^53 − 1`, the largest U53 time. */
export const MAX_TIME: U53 = Number.MAX_SAFE_INTEGER;

/** A-116.2 `PR_types` (seven names): the types whose events may reduce power (the policy-time bounds; `prEffective` decides per event). */
export const PR_TYPES: ReadonlySet<EventType> = readonlySet<EventType>(["AUTHORITY_REVOKED", "CONTROL_EPOCH_ADVANCED", "AGENT_TERMINATED", "AGENT_UNAPPOINTED", "BUDGET_DECLARED", "BUDGET_UPDATED", "COUNTERPARTY_RETIRED"]);
/** A-116.2 rule 11 `LOW_types = PR_types ∪ {STATE_CHECKPOINT}`: the only types whose `byType` value may be below `threshold`. */
export const LOW_TYPES: ReadonlySet<EventType> = readonlySet<EventType>([...PR_TYPES, "STATE_CHECKPOINT"]);

/**
 * The `byType` value of `type` under `policy` (absent = default): `byType[type] ?? threshold`. This is `M_eff` of every
 * event of a type outside `PR_TYPES` (and of `OWNER_KEYS_ROTATED`, `M_rot`); for a ◆ event use `controlThreshold`.
 */
export const effectiveThreshold = (policy: OwnerPolicy | undefined, type: EventType): number =>
  policy?.byType?.[type] ?? policy?.threshold ?? 1;
/**
 * `M_eff(e)` (A-92.1 as amended by A-106.2 and A-116.2), A-92.2 step 0: decided from `e.data`, the policy in force and the pre-event
 * state `state`, before any signature is verified. A `byType` value below `threshold` applies to a `PR_TYPES` event only
 * when the event reduces power by effect (`prEffective`); otherwise the event needs `threshold`.
 */
export const controlThreshold = (policy: OwnerPolicy | undefined, event: CanonicalEvent, state: ReplayState): number => {
  const required = effectiveThreshold(policy, event.type);
  return policy !== undefined && required < policy.threshold && PR_TYPES.has(event.type) && !prEffective(event, state) ? policy.threshold : required;
};

const coveredBy = (old: readonly string[] | null, next: readonly string[] | null | undefined): boolean => next === null || (old !== null && next !== undefined && old.every((item) => next.includes(item)));
const capNotRaised = (old: string | number | null, next: unknown): boolean =>
  next === null ? old === null : old === null || BigInt(next as string | number) <= BigInt(old);
/** A-116 Terms `rollsOver(B)`: a FIXED_WINDOW budget that carries unused amounts (§9.5 applies to it). */
const rollsOver = (budget: BudgetRecord): boolean => budget.period.kind === "FIXED_WINDOW" && budget.period.carryUnused;
const own = (record: object | undefined, key: string): string | undefined => (record !== undefined && Object.hasOwn(record, key) ? (record as Record<string, string>)[key] : undefined);
/** A-127.2 / A-203.1: every unrevoked PROHIBITION record, with no activity or window term (decidable from the state alone). */
const unrevokedProhibitions = (state: ReplayState): AuthorityRecord[] =>
  [...state.authorities.values()].filter((record) => record.revocationEventId === undefined && record.grant.kind === "PROHIBITION");
/** A-116 Terms `anc(prohibition, σ)`: the records reached by following `grant.parentAuthorityId` (stops at a record without one, a dangling id or a cycle). */
const ancestors = (state: ReplayState, prohibition: AuthorityRecord): AuthorityRecord[] => {
  const seen = new Set<string>(), found: AuthorityRecord[] = [];
  for (let parent = own(prohibition.grant, "parentAuthorityId"); parent !== undefined && !seen.has(parent); parent = own(state.authorities.get(parent)?.grant, "parentAuthorityId")) {
    const record = state.authorities.get(parent);
    if (record === undefined) break;
    seen.add(parent);
    found.push(record);
  }
  return found;
};
/** A-116 Terms: `id ∈ anc(prohibition, σ)`. */
const inAncestry = (state: ReplayState, prohibition: AuthorityRecord, id: string): boolean => ancestors(state, prohibition).some((record) => record.grant.authorityId === id);
/**
 * A-127.2: whether `agentId` is on the anchor path of `prohibition`: its grantor, or the grantor or grantee of a record
 * of `anc(prohibition, σ)`. Terminating such an actor ends the prohibition with its path (ASM-2 as restated, A-127.1).
 */
const onAnchorPath = (state: ReplayState, prohibition: AuthorityRecord, agentId: string): boolean =>
  prohibition.grant.grantorId === agentId || ancestors(state, prohibition).some((record) => record.grant.grantorId === agentId || own(record.grant, "granteeId") === agentId);

/**
 * A-116.1 `PR_eff(e, σ)` (replaces the A-106.2 table): whether `event` reduces power by its effect on `state` (the state
 * before it, `t = e.timestamp`), exactly per the table, one case per row. A budget is a stop rule (r4 §9): declaring one,
 * lowering a cap, widening `subjects` and moving `expiresAt` later reduce power. Pure; decided before any signature is
 * counted; types outside `PR_TYPES`: false.
 */
export function prEffective(event: CanonicalEvent, state: ReplayState): boolean {
  const d = event.data;
  switch (event.type) {
    case "AUTHORITY_REVOKED": {
      // A PERMISSION under which no unrevoked prohibition is delegated (X-2: the prohibition would lose effect with it).
      const id = d.authorityId as string, record = state.authorities.get(id);
      return record !== undefined && record.revocationEventId === undefined && record.grant.kind === "PERMISSION" &&
        !unrevokedProhibitions(state).some((prohibition) => inAncestry(state, prohibition, id));
    }
    case "CONTROL_EPOCH_ADVANCED": {
      // An ACTIVE agent at fromEpoch, a later toEpoch, and no session of the agent at toEpoch (R3F-4; vacuous here, DEVIATIONS).
      const agent = state.agents.get(d.agentId as string);
      return agent !== undefined && !agent.terminated && agent.currentControlEpoch === d.fromEpoch && (d.toEpoch as number) > (d.fromEpoch as number) &&
        !(state.runtimeSessionIdsByAgent.get(agent.id) ?? []).some((id) => state.runtimeSessions.get(id)?.controlEpoch === d.toEpoch);
    }
    case "AGENT_TERMINATED": {
      // A-127.2 / A-203.1: an ACTIVE agent on no unrevoked prohibition's anchor path (its grantor, or the grantor or grantee of
      // a record in anc): an unrevoked prohibition, active or not yet valid, must not die with its path under a lowered
      // threshold; fence the agent instead.
      const agent = state.agents.get(d.agentId as string);
      return agent !== undefined && !agent.terminated && !unrevokedProhibitions(state).some((prohibition) => onAnchorPath(state, prohibition, agent.id));
    }
    case "AGENT_UNAPPOINTED": {
      // No budget that can still match the agent through the role at a time >= t (ACTIVE, selects the role and the agent, not expired).
      const agentId = d.agentId as string, roleId = d.roleId as string;
      for (const value of state.budgets.values()) {
        const b = value as BudgetRecord;
        if (b.status === "ACTIVE" && b.subjects.roleIds !== null && b.subjects.roleIds.includes(roleId) && (b.subjects.actorIds === null || b.subjects.actorIds.includes(agentId)) &&
            !(b.expiresAt !== null && b.expiresAt <= event.timestamp)) return false;
      }
      return true;
    }
    case "BUDGET_DECLARED": return true; // a new stop rule only denies (§9.4)
    case "BUDGET_UPDATED": {
      const old = state.budgets.get(d.budgetId as string) as BudgetRecord | undefined;
      if (old === undefined || old.status !== "ACTIVE" || rollsOver(old)) return false;
      const subjects = d.subjects as Readonly<Record<string, readonly string[] | null>>;
      return capNotRaised(old.amountCap, d.amountCap) && capNotRaised(old.countCap, d.countCap) && capNotRaised(old.perOperationCap, d.perOperationCap) &&
        (["actorIds", "roleIds", "actions", "resources"] as const).every((key) => coveredBy(old.subjects[key], subjects[key])) &&
        (old.expiresAt === null ? d.expiresAt === null : d.expiresAt === null || (d.expiresAt as number) >= old.expiresAt);
    }
    case "COUNTERPARTY_RETIRED": return (state.counterparties.get(d.counterpartyId as string) as { status?: string } | undefined)?.status === "ACTIVE";
    default: return false;
  }
}
/** `M_rot(P)` (A-91.2 rule 4): what an `OWNER_KEYS_ROTATED` needs; never below `threshold`. */
export const rotationThreshold = (policy: OwnerPolicy | undefined): number => effectiveThreshold(policy, "OWNER_KEYS_ROTATED");

/** §3.3 credential identity: the scheme and the normalised credential. */
export const credentialId = (key: Readonly<{ scheme: OwnerKey["scheme"]; credential: string }>): string =>
  `${key.scheme}\u0000${suiteFor(key.scheme).normalizeCredential(key.credential)}`;

/**
 * The class of a key under `policy` (A-92.1 as amended by A-99): `AGENT` when the policy classes ANY key id of `keys`
 * that carries the same credential as `AGENT`, else `HUMAN` (by declaration, a label, not evidence). Without a policy
 * every key is `HUMAN`.
 */
export function ownerKeyClass(policy: OwnerPolicy | undefined, keys: readonly OwnerKey[], key: Readonly<{ scheme: OwnerKey["scheme"]; credential: string }>): OwnerKeyClass {
  const classes = policy?.keyClasses;
  if (classes === undefined) return "HUMAN";
  const id = credentialId(key);
  return keys.some((k) => classes[k.keyId] === "AGENT" && credentialId(k) === id) ? "AGENT" : "HUMAN";
}

/** An A-151 report finding, never a policy-validity failure or a timestamp-specific quorum verdict. */
export type CheckpointPolicyListing = Readonly<{
  fromPosition: U53;
  policy: OwnerPolicy;
  checkpointThreshold: number;
  nonAgentCredentials: number;
}>;
/**
 * A-151.2: list every epoch whose explicit STATE_CHECKPOINT override exceeds its distinct non-AGENT
 * credentials. Classification is by credential across all aliases (A-99), not by key id or current
 * PHL attestation validity. This is report-only: the policy remains valid and replay is unchanged.
 */
export function checkpointPolicyListings(epochs: readonly OwnerKeyEpoch[]): readonly CheckpointPolicyListing[] {
  const listings: CheckpointPolicyListing[] = [];
  for (const epoch of epochs) {
    const policy = epoch.policy, threshold = policy?.byType?.STATE_CHECKPOINT;
    if (policy === undefined || threshold === undefined) continue;
    const nonAgent = new Set(epoch.keys.filter((key) => ownerKeyClass(policy, epoch.keys, key) !== "AGENT").map(credentialId));
    if (threshold > nonAgent.size) listings.push(Object.freeze({
      fromPosition: epoch.fromPosition, policy, checkpointThreshold: threshold, nonAgentCredentials: nonAgent.size,
    }));
  }
  return Object.freeze(listings);
}

// ---------------------------------------------------------------- human attestation (A-93, A-107, A-118, A-119)

/** A-107.1 classes: `LAPSED` (a statement that expired) and `NONE` (no statement, or one not yet started) exist only under `ATTESTED`. */
export type SignerClass = OwnerKeyClass | "LAPSED" | "NONE";
/** A-114.0 `isAtt(P)`: the strict floor; absent `humanFloor` has `DECLARED` semantics. */
export const isAttestedPolicy = (policy: OwnerPolicy | undefined): boolean => policy?.humanFloor === "ATTESTED";
/** `stmt(P, c)`: the statement whose subject has the credential of `key` (at most one, A-93.2 rule 4). */
export const statementOf = (policy: OwnerPolicy | undefined, key: Readonly<{ scheme: OwnerKey["scheme"]; credential: string }>): HumanAttestation | undefined => {
  const id = credentialId(key);
  return policy?.attestations?.find((statement) => credentialId(statement.subject) === id);
};
/**
 * A-107.1 / A-118.4 `cls(P, K, D, t, c)`, total over every credential (`keys` = `K`, the epoch's keys, for `agentCred`):
 * `DECLARED`: `AGENT` if `agentCred(c)` else `HUMAN`; `ATTESTED`: `HUMAN` while its statement is valid (`notBefore ≤ t <
 * expiresAt`), else `AGENT` if `agentCred(c)`, else `LAPSED` once the statement expired, else `NONE` (no statement, or one
 * that has not started). Never a function of a key id or of the event.
 */
export function signerClass(policy: OwnerPolicy | undefined, keys: readonly OwnerKey[], key: Readonly<{ scheme: OwnerKey["scheme"]; credential: string }>, t: U53): SignerClass {
  const agent = ownerKeyClass(policy, keys, key) === "AGENT";
  if (!isAttestedPolicy(policy)) return agent ? "AGENT" : "HUMAN";
  const statement = statementOf(policy, key);
  if (statement !== undefined && statement.notBefore <= t && t < statement.expiresAt) return "HUMAN";
  if (agent) return "AGENT";
  return statement !== undefined && t >= statement.expiresAt ? "LAPSED" : "NONE";
}
/** A-116 Terms `H(p)`: the attestation horizon, the latest `expiresAt` of the policy's statements (`undefined` without any). */
export const attestationHorizon = (policy: OwnerPolicy | undefined): U53 | undefined =>
  policy?.attestations?.reduce((horizon, statement) => Math.max(horizon, statement.expiresAt), 0);
/** Appendix C (A-95.4): what an attester signs, `hashCanonical(statement without signature, "sha256")`. */
export const humanAttestationHash = (statement: HumanAttestation): ContentHash => {
  const { signature: _signature, ...body } = statement;
  return hashCanonical(body, "sha256");
};
const sameKey = (a: OwnerKey, b: OwnerKey): boolean => a.keyId === b.keyId && a.scheme === b.scheme && credentialId(a) === credentialId(b);
const sameValue = (a: unknown, b: unknown): boolean => (a === undefined || b === undefined ? a === b : canonicalEncode(a) === canonicalEncode(b));

/**
 * What the human-attestation rules read from the event that sets the policy (row 0 or 26): the genesis domain (the
 * statements' `audience`), the event's timestamp (`t_set`), the resulting commitment `D`, whether it is the genesis, the
 * policy in force before it (`P(p)`, for carried statements), `recordHash(0)` (for `historyId`) and `foreign(σ(p))`.
 */
export type PolicySetting = Readonly<{
  domain: AuthorizationDomain; timestamp: U53; nextKeyDigests: readonly ContentHash[]; genesis: boolean;
  previous?: OwnerPolicy | undefined; historyId?: ContentHash; foreign?: () => ReadonlySet<string>;
}>;
/**
 * A-91.2 rule 8: A-93.2 with A-97.5, A-107.4, A-112 (R2F-10), A-107.5 (a) and A-118.3 (b), A-117.4 and A-118.1, for the
 * resulting keys `keys`; the reason (`EVENT_DATA_INVALID`) or `undefined`. In order: (1) presence; (2) attesters: distinct
 * key ids and credentials, the §3.3 key test, never an owner credential, a committed digest or a foreign credential, at
 * least two under `ATTESTED`; (3) every statement: audience, attester, signature, subject (a member of `K` or a committed
 * key), interval, freshness (waived for a carried statement), not an `AGENT` credential, `historyId`; (4) one statement
 * per subject credential; (5) under `ATTESTED`: enough statements valid at `t_set` for `M_rot`, and every `PR_types`
 * value at most the started statements. Without `setting` (a writer's early check) only (1), (2) without the foreign
 * test and (4) apply; replay always passes it.
 */
export function attestationFailure(policy: OwnerPolicy, keys: readonly OwnerKey[], setting?: PolicySetting): string | undefined {
  const attested = isAttestedPolicy(policy);
  const attesters = policy.attesters ?? [], statements = policy.attestations ?? [];
  if (policy.attestations !== undefined && policy.attesters === undefined) return `${P}.attesters: attestations need attesters (A-93.2 rule 1)`;
  if (attested && (policy.attesters === undefined || policy.attestations === undefined)) return `${P}: humanFloor ATTESTED needs attesters and attestations (A-93.2 rule 1)`;
  const owners = new Set(keys.map(credentialId)), digests = new Set(setting?.nextKeyDigests ?? []);
  for (const [index, attester] of attesters.entries()) {
    const at = `${P}.attesters[${index}]`;
    if (attesters.findIndex((other) => other.keyId === attester.keyId) !== index) return `${at}.keyId: repeats an attester key id (A-93.1)`;
    if (attesters.findIndex((other) => credentialId(other) === credentialId(attester)) !== index) return `${at}.credential: repeats an attester credential (A-93.1)`;
    const check = ed25519KeyCheck(Buffer.from(attester.credential.slice(2), "hex"));
    if (check !== "OK") return `${at}.credential: is not a usable Ed25519 key (${check}; A-32.2)`;
    if (owners.has(credentialId(attester))) return `${at}.credential: is an owner credential; an owner key never attests (A-93.2 rule 2)`;
    if (digests.has(ownerKeyDigest(attester))) return `${at}.credential: is committed as a next owner key (A-93.2 rule 2, A-97.5)`;
    if (setting?.foreign?.().has(credentialId(attester)) === true) return `${at}.credential: is a session or counterparty credential of this history (A-117.4)`;
  }
  if (attested && attesters.length < 2) return `${P}.attesters: humanFloor ATTESTED needs at least two attesters (A-93.2 rule 2, A-112)`;
  const carried = (statement: HumanAttestation): boolean => setting?.previous?.attestations?.some((old) => sameValue(old, statement)) === true;
  for (const [index, statement] of statements.entries()) {
    const at = `${P}.attestations[${index}]`;
    if (statements.findIndex((other) => credentialId(other.subject) === credentialId(statement.subject)) !== index) return `${at}.subject: a second statement about one credential (A-93.2 rule 4)`;
    if (setting === undefined) continue;
    const attester = attesters.find((entry) => entry.keyId === statement.attesterKeyId);
    if (!sameValue(statement.audience, setting.domain)) return `${at}.audience: is not this history's domain (A-93.2 rule 3)`;
    if (attester === undefined) return `${at}.attesterKeyId: names no attester of the policy (A-93.2 rule 3)`;
    const suite = suiteFor("ed25519");
    if (!suite.isSignature(statement.signature) || !suite.verify(humanAttestationHash(statement), statement.signature, suite.normalizeCredential(attester.credential))) {
      return `${at}.signature: does not verify under attester ${attester.keyId} (A-93.2 rule 3)`;
    }
    if (!keys.some((key) => sameKey(key, statement.subject)) && !digests.has(ownerKeyDigest(statement.subject))) return `${at}.subject: is neither an owner key of ownerKeys nor a committed next key (A-93.2 rule 3)`;
    if (!(statement.notBefore < statement.expiresAt)) return `${at}: notBefore must be before expiresAt (A-93.2 rule 3)`;
    const isCarried = carried(statement);
    if (!isCarried && !(statement.expiresAt > setting.timestamp)) return `${at}.expiresAt: the statement has expired at the setting event (A-93.2 rule 3; a carried statement is exempt, A-118.1)`;
    if (ownerKeyClass(policy, keys, statement.subject) === "AGENT") return `${at}.subject: is classed AGENT by keyClasses (A-93.2 rule 3)`;
    if (setting.genesis ? statement.historyId !== undefined : !isCarried && statement.historyId !== setting.historyId) {
      return `${at}.historyId: ${setting.genesis ? "must be absent at the genesis" : "a statement set after the genesis names this history (recordHash(0)) unless it is carried"} (A-107.4)`;
    }
  }
  if (!attested || setting === undefined) return undefined;
  const credentials = [...new Set(keys.map(credentialId))];
  const statementFor = (id: string): HumanAttestation | undefined => statements.find((statement) => credentialId(statement.subject) === id);
  const valid = credentials.filter((id) => { const a = statementFor(id); return a !== undefined && a.notBefore <= setting.timestamp && setting.timestamp < a.expiresAt; }).length;
  if (valid < Math.max(1, rotationThreshold(policy))) return `${P}.attestations: ${valid} owner credential(s) are attested at the setting event; ATTESTED needs ${Math.max(1, rotationThreshold(policy))} (A-93.2 rule 5, A-107.5 (a))`;
  const started = credentials.filter((id) => { const a = statementFor(id); return a !== undefined && a.notBefore <= setting.timestamp; }).length;
  for (const [type, value] of entries(policy.byType)) {
    if (PR_TYPES.has(type as EventType) && value > started) return `${P}.byType.${type}: ${value} exceeds the ${started} owner credential(s) with a started statement; reducing power never needs an agent key (A-118.3)`;
  }
  return undefined;
}

/** "As written" equality (A-96.1): canonical encodings equal; an absent policy differs from every present one. */
export const sameOwnerPolicy = (a: OwnerPolicy | undefined, b: OwnerPolicy | undefined): boolean =>
  a === undefined || b === undefined ? a === b : canonicalEncode(a) === canonicalEncode(b);
/** The default policy, absent or written out as exactly `{threshold: 1}` (the writer's POLICY_RESET test, A-96.4). */
export const isDefaultOwnerPolicy = (policy: OwnerPolicy | undefined): boolean => policy === undefined || sameOwnerPolicy(policy, DEFAULT_OWNER_POLICY);

const P = "$.data.ownerPolicy";
const entries = <T>(map: Readonly<Record<string, T>> | undefined): readonly (readonly [string, T])[] => (map === undefined ? [] : Object.entries(map));

/**
 * A-91.2 (with A-99.0 and A-102) for a schema-valid `ownerPolicy` against `keys`, the `ownerKeys` of the same event
 * (the resulting epoch's keys); the reason on failure (`EVENT_DATA_INVALID`), `undefined` when valid. The rules, in
 * order: (1) `threshold` and every `byType` value ≤ N, the number of distinct credentials; (3) every `byType` key names
 * a ◆ type; (4) `byType.OWNER_KEYS_ROTATED` ≥ `threshold`; (5) every `keyClasses` and `labels` key is a key id of
 * `keys`, and (A-99) the credentials of `keys` are pairwise distinct; (6) some key is not `AGENT`, and the non-`AGENT`
 * credentials number at least `M_rot` (no lock-out); (7) `acknowledged` needs `threshold = 1` and no `byType`;
 * (8) human attestation (`attestationFailure`, with the setting event's `setting`); (9) no policy in a migrated genesis; (10, A-106.3) a `PR_TYPES` value is at most the
 * non-`AGENT` credentials; (11, A-116.2) only `LOW_TYPES` values may be below `threshold`. Rule 2 (the floor of 1) is
 * the C4 range.
 */
export function ownerPolicyFailure(policy: OwnerPolicy, keys: readonly OwnerKey[], options: Readonly<{ migrated?: boolean; setting?: PolicySetting }> = {}): string | undefined {
  const credentials = keys.map(credentialId);
  const n = new Set(credentials).size;
  const byType = entries(policy.byType);
  if (policy.threshold > n) return `${P}.threshold: ${policy.threshold} exceeds the ${n} distinct owner credential(s) of ownerKeys (A-91.2 rule 1)`;
  for (const [type, value] of byType) if (value > n) return `${P}.byType.${type}: ${value} exceeds the ${n} distinct owner credential(s) of ownerKeys (A-91.2 rule 1)`;
  for (const [type] of byType) if (!CONTROL_EVENT_TYPES.has(type as EventType)) return `${P}.byType.${type}: is not the name of a control (◆) event type (A-91.2 rule 3)`;
  const rotation = policy.byType?.OWNER_KEYS_ROTATED;
  if (rotation !== undefined && rotation < policy.threshold) return `${P}.byType.OWNER_KEYS_ROTATED: ${rotation} is below threshold ${policy.threshold} (A-91.2 rule 4)`;
  const keyIds = new Set(keys.map((key) => key.keyId));
  for (const [keyId] of entries(policy.keyClasses)) if (!keyIds.has(keyId)) return `${P}.keyClasses.${keyId}: names no key of ownerKeys (A-91.2 rule 5)`;
  for (const [keyId] of entries(policy.labels)) if (!keyIds.has(keyId)) return `${P}.labels.${keyId}: names no key of ownerKeys (A-91.2 rule 5)`;
  if (n !== keys.length) {
    const index = credentials.findIndex((id, i) => credentials.indexOf(id) !== i);
    return `$.data.ownerKeys[${index}].credential: repeats the credential of ${keys[credentials.indexOf(credentials[index]!)]!.keyId}; under an ownerPolicy owner credentials are pairwise distinct (A-99)`;
  }
  const humans = keys.filter((key) => ownerKeyClass(policy, keys, key) !== "AGENT").length;
  const required = rotationThreshold(policy);
  if (humans === 0) return `${P}.keyClasses: every owner key is AGENT; at least one must not be (A-91.2 rule 6)`;
  if (humans < required) return `${P}: ${humans} non-AGENT owner credential(s) cannot reach the rotation threshold ${required}; the policy could never be changed by humans (A-91.2 rule 6)`;
  if (policy.acknowledged !== undefined && (policy.threshold !== 1 || policy.byType !== undefined)) {
    return `${P}.acknowledged: SINGLE_SIGNER requires threshold 1 and no byType (A-91.2 rule 7, A-102)`;
  }
  const attestation = attestationFailure(policy, keys, options.setting);
  if (attestation !== undefined) return attestation;
  if (options.migrated === true) return `${P}: a migrated genesis carries no ownerPolicy; the first native rotation after the prefix may set one (A-91.2 rule 9)`;
  for (const [type, value] of byType) {
    if (PR_TYPES.has(type as EventType) && value > humans) return `${P}.byType.${type}: ${value} exceeds the ${humans} non-AGENT owner credential(s); reducing power never needs an agent key (A-91.2 rule 10, A-106.3)`;
  }
  for (const [type, value] of byType) {
    if (value < policy.threshold && !LOW_TYPES.has(type as EventType)) return `${P}.byType.${type}: ${value} is below threshold ${policy.threshold}; only a power-reducing type or STATE_CHECKPOINT may be lowered (A-91.2 rule 11, A-116.2)`;
  }
  return undefined;
}
