/**
 * Format 2 state records, leaves, root and projection (SPEC-IRONTRELLIS-CORE-v2 §7.1–7.2, §12).
 *
 * One pure module: every §7.2 record kind, in SPEC order, derived from the replay state (plus the event that
 * created or changed it, read by position), the §7.1 leaf hash, the sorted leaf list and its RFC 6962 root
 * (`transparency/merkle.ts rootOf` over the leaves — it does not re-prefix them), and the §12 projection row
 * and chain. Replay calls `applyStateRecords` after every accepted event; nothing here validates anything.
 *
 * Two kinds are NOT derived from the format-1 state: `usage` (a format-2 counter kept in `state.usageCounters`, distinct
 * from `authorityUsage`) and `nonce` (created at declaration, `state.nonceRecords`). The budget, counterparty,
 * refusal and effect kinds are read from their own maps (filled by E2's transitions).
 *
 * ---- Derivation table (SPEC §7.1 invariant: every ReplayState field is re-derivable from records + events) ----
 * | ReplayState field                        | record kind / field it is rebuilt from                                      |
 * |------------------------------------------|-----------------------------------------------------------------------------|
 * | format, hashAlgorithm, signatureScheme   | genesis (versions)                                                          |
 * | events                                   | the history file (records cite events by `position`)                        |
 * | eventHistoryHashes[p], head, lastTimestamp | event[p].recordHash / timestamp (the last `event` record is the head)     |
 * | eventPositionsById                       | event[p].eventId → p                                                        |
 * | genesis                                  | genesis + ownerKeyEpoch["0"] (ownerKeys, nextKeyDigests, ownerPolicy)       |
 * | ownerKeyEpochs                           | ownerKeyEpoch[*] (fromPosition, keys, nextKeyDigests, policy?)              |
 * | principals                               | principal (principalId, eventId, position)                                  |
 * | agents (+ creation/termination refs)     | agent (status, controlEpoch, eventId, position, terminatedEventId/Position) |
 * | reservedAgentIds                         | succession[*].rule.successorAgentId → ruleId                                |
 * | roles (latestTenureNumber)               | role (currentTenureId) + max tenureNumber over tenure[*] with that roleId    |
 * | successionRules                          | succession[*].rule                                                          |
 * | tenures (closed, successionRuleId, lock) | tenure (status ENDED ⇒ closed; successionRuleId from the AGENT_APPOINTED     |
 * |                                          | event at tenure.position; successionLock ⇔ the AGENT_TERMINATED event at     |
 * |                                          | agent.terminatedPosition names the tenure; it persists after the tenure ends |
 * | currentTenureIdsByAgent                  | tenure[*] with status CURRENT, grouped by agentId                            |
 * | runtimeSessions, runtimeSessionIdsByAgent, credentialKeyIds, credentialAddressKeysByAgent | session[*] (ordered by position) |
 * | intentDeclarations, declarationPositions | intent (declarationPosition → the declaration event's data; declarationDigest) |
 * | intentAdmissions                         | intent.admissionPosition → the admission event (proof fields) + adapter identity derivation |
 * | intentConsumptions                       | intent.consumptionPosition → the consumption event                         |
 * | intentOutcomeStates                      | intent.outcomes[] (the format-1 latest/terminal rule)                               |
 * | outcomeObservations                      | intent.observations[] → the observation events                              |
 * | attemptDuties, attemptDutyReviews, attemptDutyIdsBySourceIntent | duty (record, assignments, reviews → events)          |
 * | attemptDutyPolicies, attemptDutyDispositions (E4) | duty.policy (priorHead full head = event[position−1]'s head: recordHash + timestamp; eventPosition = position) and duty.dispositions |
 * | receiptCommitments                       | receipt (+ the RECEIPT_RECORDED event at position)                          |
 * | obligations, obligationIdsBySourceIntent | obligation                                                                  |
 * | nonceReservationsByActor                 | intent[*] with admissionPosition ≠ null (actorId, nonce, admission refs)     |
 * | nonceRecords                             | nonce[*]                                                                    |
 * | authorities, recognizedRoots             | authority (grant, revocation); roots = root PERMISSIONs whose grantor is a principal |
 * | authorityUsage                           | intent[*] admissions (controllingAuthorityIds + request.amount, capped dimension only) |
 * | usageCounters                            | usage[*]                                                                    |
 * | anchors                                  | anchor[*]                                                                   |
 * | boundWitnesses, boundPolicy              | witnessBinding[*] (eventId/position from boundAtPosition), witnessPolicy     |
 * | shadowHashes                             | shadow (count; the hashes are recomputed by the reader, SPEC §16.2 step 3)  |
 * | stateRecords, stateRoots, projectionHeads| the records themselves; roots and projection heads are recomputed per position |
 * | budgets, budgetUsage, counterparties, refusals, effects | budget, budgetUsage, counterparty, refusal, effect (E2)     |
 * | reconciliationObservations, reconciliationCursors, the (streamId, eventRef) index | observation, reconciliation-cursor (A-71) |
 */
import { canonicalEncode, compareProtocolStrings, wireAmounts } from "./canonical.ts";
import { createHash, hash as oneShotHash } from "node:crypto";
import { bytesToHex, hashCanonical, hexToBytes } from "./hash.ts";
import { PROJECTION_VERSION, signedControlEffect } from "./events.ts";
import { rootOfLeaves, type UndoList } from "./state-roots.ts";
import { CONTROL_EVENT_TYPES, EVENT_TYPE_CODES, SESSION_SIGNED_EVENT_TYPES } from "./types.ts";
import type { CanonicalEvent, ContentHash, OutcomeRecord, ReplayState, StateRecordEntry, U53 } from "./types.ts";
import type { MutableReplayState } from "./state.ts";

type Rec = Readonly<Record<string, unknown>>;

/** The §7.2 kinds, in SPEC order. */
export const STATE_RECORD_KINDS = Object.freeze([
  "event", "genesis", "ownerKeyEpoch", "principal", "agent", "role", "tenure", "succession", "session", "authority", "usage", "nonce", "intent",
  "receipt", "obligation", "duty", "anchor", "witnessBinding", "witnessPolicy", "shadow", "budget", "budgetUsage", "counterparty", "refusal", "effect",
  "observation", "reconciliation-cursor",
] as const);
export type StateRecordKind = (typeof STATE_RECORD_KINDS)[number];

export const recordKey = (kind: string, key: string): string => `${kind}\u0000${key}`;
/** A-71.4: the `reconciliation-cursor` key of a (reconciler, stream) pair, `hashCanonical([reconcilerAgentId, streamId])`. */
export const reconciliationCursorKey = (reconcilerAgentId: string, streamId: string): string => hashCanonical([reconcilerAgentId, streamId], "sha256");
/** `position` as a 16-digit zero-padded decimal (the `event` and `anchor` keys). */
export const positionKey = (position: number): string => String(position).padStart(16, "0");
const UTF8 = new TextEncoder();
const ZERO = new Uint8Array([0]);
const ZERO32 = new Uint8Array(32);
const sha256 = (...parts: readonly Uint8Array[]): Uint8Array => {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return new Uint8Array(hash.digest());
};
/** One-shot SHA-256 (`crypto.hash`, no hasher object per call): the leaf and node hashes of the root are the engine's hottest path. */
const sha256Once = (data: Uint8Array | string): Uint8Array => oneShotHash("sha256", data, "buffer") as unknown as Uint8Array;
const hex = (bytes: Uint8Array): ContentHash => `0x${bytesToHex(bytes)}`;

// ---- a fast canonical encoder for the §7.2 records (plain JSON data the engine itself built: no bigints, no cycles)
//
// Byte-identical to `canonicalEncode` on its domain (keys in `compareProtocolStrings` order, `undefined` members dropped,
// JSON string escaping of `"`, `\` and the control characters only, numbers as `String(n)`); anything outside the domain
// (a bigint, a marker record, a non-finite number, a lone surrogate) falls back to `canonicalEncode`, which validates. The
// generic encoder validates and charges every string (SPEC §3.1 limits) on every call; the records were validated when
// their events were, so the leaf computation (≈ recordCount per append, A-4) skips that work. Tested equal in
// `format2-state.test.mjs` over every record of the test histories.
class Fallback extends Error {}
const compareKeyStrings = (left: string, right: string): number => {
  const shared = left.length < right.length ? left.length : right.length;
  for (let index = 0; index < shared; index += 1) {
    let a = left.charCodeAt(index), b = right.charCodeAt(index);
    if (a === b) continue;
    if (a >= 0xd800 || b >= 0xd800) {
      if (a >= 0xd800 && a <= 0xdfff) a += 0x2000; else if (a >= 0xe000) a -= 0x800;
      if (b >= 0xd800 && b <= 0xdfff) b += 0x2000; else if (b >= 0xe000) b -= 0x800;
    }
    return a < b ? -1 : 1;
  }
  return left.length === right.length ? 0 : left.length < right.length ? -1 : 1;
};
const HEX2 = Array.from({ length: 32 }, (_v, i) => i.toString(16).padStart(2, "0"));
const PLAIN = /^[^"\\\u0000-\u001f\ud800-\udfff]*$/;
const fastString = (value: string): string => {
  if (PLAIN.test(value)) return `"${value}"`;
  let out = "\"", start = 0;
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdfff) {
      // A surrogate pair is fine; a lone surrogate is not well-formed: let the validating encoder decide.
      const next = value.charCodeAt(index + 1);
      if (unit > 0xdbff || !(next >= 0xdc00 && next <= 0xdfff)) throw new Fallback();
      index += 1;
      continue;
    }
    if (unit >= 0x20 && unit !== 0x22 && unit !== 0x5c) continue; // only C0 controls, the quote and the backslash are escaped
    if (start < index) out += value.slice(start, index);
    out += unit === 0x22 ? "\\\"" : unit === 0x5c ? "\\\\" : `\\u00${HEX2[unit]}`;
    start = index + 1;
  }
  return `${out}${start < value.length ? value.slice(start) : ""}"`;
};
const fastNode = (value: unknown): string => {
  switch (typeof value) {
    case "string": return fastString(value);
    case "number": if (!Number.isFinite(value) || Object.is(value, -0)) throw new Fallback(); return String(value);
    case "boolean": return value ? "true" : "false";
    case "object": {
      if (value === null) return "null";
      if (Array.isArray(value)) { let out = "["; for (let i = 0; i < value.length; i += 1) { if (value[i] === undefined) throw new Fallback(); out += (i === 0 ? "" : ",") + fastNode(value[i]); } return `${out}]`; }
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) throw new Fallback();
      const keys = Object.keys(value).sort(compareKeyStrings);
      let out = "{", members = 0;
      for (const key of keys) {
        const field = (value as Rec)[key];
        if (field === undefined) continue;
        if (key.startsWith("$continuity.")) throw new Fallback();
        out += `${members === 0 ? "" : ","}${fastString(key)}:${fastNode(field)}`;
        members += 1;
      }
      return `${out}}`;
    }
    default: throw new Fallback();
  }
};
/** The canonical text of a §7.2 record (fast path; the validating encoder decides anything unusual). */
export function canonicalRecordText(record: Rec): string {
  try { return fastNode(record); } catch (error) { if (error instanceof Fallback) return canonicalEncode(record); throw error; }
}

/** SPEC §7.1: `leaf = sha256(0x00 ‖ utf8(kind) ‖ 0x00 ‖ utf8(key) ‖ 0x00 ‖ sha256(utf8(canonical(record))))`. */
export function leafOf(kind: string, key: string, record: Rec): Uint8Array {
  const inner = sha256Once(canonicalRecordText(record));
  const preimage = Buffer.concat([ZERO, UTF8.encode(kind), ZERO, UTF8.encode(key), ZERO, inner]);
  return sha256Once(preimage);
}
/** (kind, key) byte order; equivalent to comparing `kind\u0000key` in UTF-8 byte order (NUL sorts first and kinds carry none). */
export const compareRecordKeys = (a: string, b: string): number => compareProtocolStrings(a, b);
/**
 * SPEC §7.1: the RFC 6962 MTH over the §7.1 leaves in (kind, key) order (`MTH([]) = sha256("")`, `MTH([l]) = l`,
 * `MTH(L) = sha256(0x01 ‖ MTH(L[0:k]) ‖ MTH(L[k:n]))`, k the largest power of two < n), computed bottom-up in O(n)
 * hashes by `state-roots.ts` (the same code keeps the incremental cache). Equal to `transparency/merkle.ts rootOf`
 * over the same leaves (tested).
 */
export { rootOfLeaves };
/** The §7.1 root of a record set given as `{kind, key, record}` entries in any order (the from-scratch computation). */
export function stateRootOfRecords(records: Iterable<Readonly<{ kind: string; key: string; record: Rec }>>): Readonly<{ root: ContentHash; count: number }> {
  const entries = [...records].map((entry) => ({ k: recordKey(entry.kind, entry.key), leaf: leafOf(entry.kind, entry.key, entry.record) }));
  entries.sort((a, b) => compareRecordKeys(a.k, b.k));
  return Object.freeze({ root: rootOfLeaves(entries.map((entry) => entry.leaf)), count: entries.length });
}

// ---------------------------------------------------------------- projection (SPEC §12)

type Fields = readonly [actor: string | null, subject: string | null, amount: string | null];
const str = (value: unknown): string | null => (typeof value === "string" ? value : null);
/** SPEC §12.2: the (actor, subject, amount) selection of every type. Amounts are the event's own decimal strings. */
export function projectionFields(event: CanonicalEvent): Fields {
  const d = event.data as Rec & { grant?: Rec & { constraints?: Rec }; record?: Rec; descriptor?: Rec; request?: Rec; measurer?: Rec; envelope?: Rec; authorizationProof?: Rec & { request?: Rec } };
  switch (event.type) {
    case "DEPLOYMENT_INITIALIZED": return [null, str(d.canonicalLineageId), null];
    case "PRINCIPAL_CREATED": return [null, str(d.principalId), null];
    case "AGENT_CREATED": return [str(d.agentId), str(d.principalId), null];
    case "ROLE_CREATED": return [null, str(d.roleId), null];
    case "SUCCESSION_RULE_DECLARED": return [str(d.predecessorAgentId), str(d.ruleId), null];
    case "AGENT_APPOINTED": case "AGENT_UNAPPOINTED": return [str(d.agentId), str(d.roleTenureId), null];
    case "ROLE_TRANSFERRED": return [str(d.toAgentId), str(d.toRoleTenureId), null];
    case "RUNTIME_SESSION_ADMITTED": return [str(d.agentId), str(d.sessionId), null];
    case "CONTROL_EPOCH_ADVANCED": return [str(d.agentId), str(d.controllerId), null];
    case "AUTHORITY_GRANTED": {
      const g = d.grant!;
      return [g.kind === "PERMISSION" ? str(g.granteeId) : str(g.subjectActorId), str(g.authorityId), str(g.constraints?.maxAmount)];
    }
    case "AUTHORITY_REVOKED": return [str(d.revokerId), str(d.authorityId), null];
    case "TRANSACTION_INTENT_DECLARED": return [str(d.actorId), str(d.intentId), str(d.amount)];
    case "TRANSACTION_INTENT_ADMITTED": return [str(d.authorizationProof?.request?.actorId), str(d.intentId), str(d.authorizationProof?.request?.amount)];
    case "TRANSACTION_INTENT_CONSUMED": case "TRANSACTION_OUTCOME_RECORDED": case "OUTCOME_OBSERVATION_RECORDED": return [null, str(d.intentId), null];
    case "RECEIPT_RECORDED": return [str(d.issuerAgentId), str(d.intentId), null];
    case "OBLIGATION_CREATED": return [str(d.actorId), str(d.record?.obligationId), null];
    case "OBLIGATION_PERFORMANCE_ASSIGNED": return [str(d.toAgentId), str(d.obligationId), null];
    case "OBLIGATION_STATUS_RECORDED": return [str(d.actorId), str(d.obligationId), null];
    case "AGENT_TERMINATED": return [str(d.agentId), str(d.roleTenureId), null];
    case "ATTEMPT_DUTY_CREATED": return [str(d.actorId), str(d.record?.dutyId), null];
    case "ATTEMPT_DUTY_ASSIGNED": return [str(d.toAgentId), str(d.dutyId), null];
    case "ATTEMPT_DUTY_REVIEW_CLOSED": case "ATTEMPT_DUTY_DISPOSITION_RECORDED": case "ATTEMPT_DUTY_CONTEST_RECORDED": return [str(d.actorId), str(d.dutyId), null];
    case "ATTEMPT_DUTY_POLICY_ACTIVATED": return [str(d.actorId), str(d.descriptor?.dutyId), null];
    case "ANCHOR_RECORDED": return [null, str(d.anchor), null];
    case "OWNER_KEYS_ROTATED": return [null, str((d.ownerKeys as readonly Rec[] | undefined)?.[0]?.keyId), null];
    case "WITNESSES_BOUND": return [null, str((d.witnesses as readonly Rec[] | undefined)?.[0]?.verifierKey), null];
    case "WITNESSES_UNBOUND": return [null, str((d.verifierKeys as readonly unknown[] | undefined)?.[0]), null];
    case "BUDGET_DECLARED": case "BUDGET_UPDATED": return [null, str(d.budgetId), str(d.amountCap)];
    case "BUDGET_CLOSED": return [null, str(d.budgetId), null];
    case "STATE_CHECKPOINT": return [null, str(d.checkpointId), null];
    case "COUNTERPARTY_REGISTERED": case "COUNTERPARTY_RETIRED": return [null, str(d.counterpartyId), null];
    case "REQUEST_REFUSED": return [str(d.request?.actorId), str(d.refusalId), str(d.request?.amount)];
    case "EFFECT_RECORDED": return [str(d.measurer?.id), str(d.intentId), str(d.amount)];
    case "COUNTERPARTY_RECEIPT_RECORDED": return [str(d.envelope?.counterpartyId), str(d.intentId), str(d.envelope?.amount)];
    case "RECONCILIATION_OBSERVED": { const call = d.call as Rec | undefined; return [str(d.reconcilerAgentId), str(call?.actorId), str(call?.amount)]; }
  }
}
const be64 = (n: number): Uint8Array => { const out = new Uint8Array(8); new DataView(out.buffer).setBigUint64(0, BigInt(n)); return out; };
const be16 = (n: number): Uint8Array => new Uint8Array([(n >> 8) & 0xff, n & 0xff]);
const be256 = (decimal: string): Uint8Array => {
  let value = BigInt(decimal);
  const out = new Uint8Array(32);
  for (let index = 31; index >= 0; index -= 1) { out[index] = Number(value & 0xffn); value >>= 8n; }
  return out;
};
const idHash = (id: string | null): Uint8Array => (id === null ? ZERO32 : sha256(UTF8.encode(id)));
/** SPEC §12.1: the 160-byte row of an accepted event. */
export function projectionRow(event: CanonicalEvent, position: number, eventHash: ContentHash): Uint8Array {
  const [actor, subject, amount] = projectionFields(event);
  const flags = (CONTROL_EVENT_TYPES.has(event.type) ? 1 : 0) | (SESSION_SIGNED_EVENT_TYPES.has(event.type) ? 2 : 0) | (amount !== null ? 4 : 0);
  const row = new Uint8Array(160);
  row.set(be64(position), 0);
  row.set(be64(event.timestamp), 8);
  row.set(be16(EVENT_TYPE_CODES.get(event.type)!), 16);
  row.set(be16(flags), 18);
  row.set(idHash(actor), 20);
  row.set(idHash(subject), 52);
  row.set(amount === null ? ZERO32 : be256(amount), 84);
  row.set(hexToBytes(eventHash), 116);
  return row;
}
const PROJECTION_PREFIX = UTF8.encode(PROJECTION_VERSION);
/** SPEC §12.3: `projectionHead(p) = sha256("irontrellis-projection/2" ‖ 0x00 ‖ projectionHead(p−1) ‖ row(p))`, `projectionHead(−1) = 0^32`. */
export function projectionHeadAfter(previous: ContentHash | null, row: Uint8Array): ContentHash {
  return hex(sha256(PROJECTION_PREFIX, ZERO, previous === null ? ZERO32 : hexToBytes(previous), row));
}
/** The projection heads of a whole event list (a standalone reference computation). */
export function projectionHeadsOf(events: readonly CanonicalEvent[], eventHashes: readonly ContentHash[]): readonly ContentHash[] {
  const heads: ContentHash[] = [];
  let previous: ContentHash | null = null;
  events.forEach((event, position) => { previous = projectionHeadAfter(previous, projectionRow(event, position, eventHashes[position]!)); heads.push(previous); });
  return Object.freeze(heads);
}

// ---------------------------------------------------------------- record derivations (SPEC §7.2), one per kind

const nullable = <T>(value: T | undefined): T | null => (value === undefined ? null : value);
const NO_REFS: Rec = Object.freeze({});
const refsOf = (state: ReplayState, kind: string, id: string): Rec => state.recordRefs.get(`${kind}\u0000${id}`) ?? NO_REFS;
const byteSort = (ids: readonly string[]): readonly string[] => [...ids].sort(compareProtocolStrings);
const dataAt = (state: ReplayState, position: number): Rec => state.events[position]!.data;
const eventAt = (state: ReplayState, position: number): CanonicalEvent => state.events[position]!;
/**
 * `sha256(canonical(data))` of the event at `position` (the intent and duty records' digests). A record is re-derived
 * every time its intent or duty moves, so the digest of the same (frozen, never mutated) event data is kept per data
 * object instead of re-encoding it each time; unfrozen data is hashed every time.
 */
const DIGESTS = new WeakMap<object, ContentHash>();
const digestOf = (state: ReplayState, position: number): ContentHash => {
  const data = dataAt(state, position);
  if (!Object.isFrozen(data)) return hashCanonical(data, "sha256");
  let digest = DIGESTS.get(data);
  if (digest === undefined) { digest = hashCanonical(data, "sha256"); DIGESTS.set(data, digest); }
  return digest;
};

type Derivation = (state: ReplayState, key: string) => Rec | undefined;
const derive: Readonly<Record<Exclude<StateRecordKind, "event">, Derivation>> = {
  genesis: (state) => {
    const { ownerKeys: _keys, nextKeyDigests: _digests, ownerPolicy: _policy, ...genesis } = dataAt(state, 0);
    return genesis;
  },
  ownerKeyEpoch: (state, key) => {
    const epoch = state.ownerKeyEpochs[Number(key)];
    // A-91.3: `policy` present iff the epoch was set with one, as written; never `null` (the stated exception to the null rule).
    return epoch === undefined ? undefined : {
      epoch: Number(key), fromPosition: epoch.fromPosition, keys: epoch.keys.map((k) => ({ keyId: k.keyId, scheme: k.scheme, credential: k.credential })), nextKeyDigests: nullable(epoch.nextKeyDigests),
      ...(epoch.policy === undefined ? {} : { policy: epoch.policy }),
    };
  },
  principal: (state, key) => {
    const p = state.principals.get(key);
    return p === undefined ? undefined : { principalId: p.id, eventId: p.creationEventId, position: p.creationEventPosition };
  },
  agent: (state, key) => {
    const a = state.agents.get(key), r = refsOf(state, "agent", key);
    return a === undefined ? undefined : {
      agentId: a.id, principalId: a.principalId, controllerId: a.controllerId, controlEpoch: a.currentControlEpoch, status: a.terminated ? "TERMINATED" : "ACTIVE",
      eventId: r.eventId, position: r.position, terminatedEventId: nullable(r.terminatedEventId), terminatedPosition: nullable(r.terminatedPosition),
    };
  },
  role: (state, key) => {
    const r = state.roles.get(key), refs = refsOf(state, "role", key);
    return r === undefined ? undefined : { roleId: r.id, principalId: r.principalId, exclusive: true, currentTenureId: nullable(r.currentTenureId), eventId: refs.eventId, position: refs.position };
  },
  tenure: (state, key) => {
    const t = state.tenures.get(key), r = refsOf(state, "tenure", key);
    return t === undefined ? undefined : {
      roleTenureId: t.id, roleId: t.roleId, agentId: t.agentId, tenureNumber: t.tenureNumber, status: t.closed ? "ENDED" : "CURRENT",
      eventId: r.eventId, position: r.position, endedEventId: nullable(r.endedEventId), endedPosition: nullable(r.endedPosition),
    };
  },
  succession: (state, key) => {
    const rule = state.successionRules.get(key), r = refsOf(state, "succession", key);
    if (rule === undefined) return undefined;
    // A-187.2 / AR-09 finding 9: the record stores the §6.1 effect through the function the challenge uses, so the two cannot diverge.
    return { rule: signedControlEffect(dataAt(state, r.position as number)), eventId: r.eventId, position: r.position };
  },
  session: (state, key) => {
    const s = state.runtimeSessions.get(key);
    return s === undefined ? undefined : {
      sessionId: s.id, agentId: s.agentId, controllerId: s.controllerId, controlEpoch: s.controlEpoch, credentialKeyId: s.credentialKeyId, credentialScheme: s.credentialScheme,
      credential: s.credentialAddressKey, expiresAt: nullable(s.expiresAt), eventId: s.admissionEventId, position: s.admissionEventPosition,
    };
  },
  authority: (state, key) => {
    const a = state.authorities.get(key);
    if (a === undefined) return undefined;
    // The grant as written (the event's own strings), with the three id lists sorted by byte order.
    const written = dataAt(state, a.grantEventPosition).grant as Rec & { constraints: Rec };
    const c = written.constraints;
    const grant = { ...written, constraints: { ...c, actions: byteSort(c.actions as readonly string[]), resources: byteSort(c.resources as readonly string[]), requiredIntersectionIds: byteSort(c.requiredIntersectionIds as readonly string[]) } };
    return {
      grant, eventId: a.grantEventId, position: a.grantEventPosition, revoked: a.revocationEventId !== undefined, revokerId: nullable(a.revokerId),
      revocationEventId: nullable(a.revocationEventId), revocationPosition: nullable(a.revocationEventPosition),
    };
  },
  usage: (state, key) => {
    const u = state.usageCounters.get(key);
    return u === undefined ? undefined : { authorityId: u.authorityId, admittedTransactionCount: u.admittedTransactionCount, admittedCumulativeAmount: u.admittedCumulativeAmount.toString() };
  },
  nonce: (state, key) => {
    const n = state.nonceRecords.get(key);
    return n === undefined ? undefined : { actorId: n.actorId, nonce: n.nonce, intentId: n.intentId, position: n.position };
  },
  intent: (state, key) => {
    const declaration = state.intentDeclarations.get(key);
    const position = (state as MutableReplayState).declarationPositions.get(key);
    if (declaration === undefined || position === undefined) return undefined;
    const d = dataAt(state, position) as Rec & { adapterProfile: Rec };
    const admission = state.intentAdmissions.get(key), consumption = state.intentConsumptions.get(key), outcomes = state.intentOutcomeStates.get(key);
    const observations = state.outcomeObservations.get(key) ?? [];
    const latest = outcomes === undefined ? undefined : (outcomes.terminal ?? outcomes.latest);
    const status = latest !== undefined ? latest.status : consumption !== undefined ? "CONSUMED" : admission !== undefined ? "ADMITTED" : "DECLARED";
    return {
      intentId: key, status, actorId: d.actorId, action: d.action, resource: d.resource, amount: nullable(d.amount), metric: d.metric ?? "amount",
      counterpartyId: nullable(d.counterpartyId), termsCommitment: nullable(d.termsCommitment), roleId: d.roleId, roleTenureId: d.roleTenureId, nonce: d.nonce,
      adapterProfile: d.adapterProfile, declarationEventId: eventAt(state, position).id, declarationPosition: position, declarationDigest: nullable(declaration.declarationDigest ?? undefined),
      admissionEventId: nullable(admission?.admissionEventId), admissionPosition: nullable(admission?.admissionEventPosition), admissionDigest: admission === undefined ? null : digestOf(state, admission.admissionEventPosition),
      consumptionEventId: nullable(consumption?.eventId), consumptionPosition: nullable(consumption?.eventPosition), consumptionDigest: consumption === undefined ? null : digestOf(state, consumption.eventPosition),
      outcomes: ((refsOf(state, "intentOutcomes", key).outcomes as readonly OutcomeRecord[] | undefined) ?? []).map((o) => ({ eventId: o.eventId, position: o.eventPosition, status: o.status, digest: digestOf(state, o.eventPosition) })),
      observations: observations.map((o) => ({ eventId: o.eventId, position: o.eventPosition, digest: digestOf(state, o.eventPosition) })),
    };
  },
  receipt: (state, key) => {
    const r = state.receiptCommitments.get(key);
    return r === undefined ? undefined : { receiptContentHash: r.receiptContentHash, receiptArtifactCommitment: r.receiptArtifactCommitment, intentId: r.intentId, issuerAgentId: r.issuerAgentId, eventId: r.eventId, position: r.eventPosition };
  },
  obligation: (state, key) => {
    const o = state.obligations.get(key), r = refsOf(state, "obligation", key);
    return o === undefined ? undefined : {
      record: dataAt(state, o.creationEventPosition).record, status: o.status, performanceAssigneeId: o.performanceAssigneeId, eventId: o.creationEventId, position: o.creationEventPosition,
      assignmentEventId: nullable(r.assignmentEventId), assignmentPosition: nullable(r.assignmentPosition), statusEventId: nullable(r.statusEventId), statusPosition: nullable(r.statusPosition),
    };
  },
  duty: (state, key) => {
    const duty = state.attemptDuties.get(key);
    if (duty === undefined) return undefined;
    const reviews = state.attemptDutyReviews.get(key) ?? [];
    // SPEC §13 (E4): `policy` from the activation record (the descriptor as written by the activation event, `position`, the
    // short `priorHead` — the in-memory record keeps the full head and `eventPosition`, see `duty-policy.ts DutyPolicyActivation`),
    // `dispositions` = the accepted dispositions and contests in position order.
    const policy = state.attemptDutyPolicies.get(key);
    return {
      // A-16.1: `status` is `record.status` as written (always "OPEN" at creation, see `applyAttemptDutyCreated`); format 2 never
      // sets CLOSED — the review state is the derived `attemptDutyReviewStatus`, `reviewClosedEventId` the latest review's event id.
      record: dataAt(state, duty.creationEventPosition).record, status: duty.record.status as string, creationActorId: duty.creationActorId, currentAssigneeId: duty.currentAssigneeId,
      eventId: duty.creationEventId, position: duty.creationEventPosition,
      assignments: duty.assignments.map((a) => ({ eventId: a.eventId, position: a.eventPosition, toAgentId: a.toAgentId })),
      reviews: reviews.map((r) => ({ eventId: r.eventId, position: r.eventPosition, digest: digestOf(state, r.eventPosition) })),
      reviewClosedEventId: nullable(reviews.at(-1)?.eventId),
      policy: policy === undefined ? null : {
        descriptor: dataAt(state, policy.eventPosition).descriptor, descriptorHash: policy.descriptorHash, activationAuthorityId: policy.activationAuthorityId, actorId: policy.actorId,
        eventId: policy.eventId, position: policy.eventPosition, activatedAt: policy.activatedAt, priorHead: { hash: policy.priorHead.hash, position: policy.priorHead.position },
        dispositionCount: policy.dispositionCount, contestCount: policy.contestCount,
      },
      dispositions: (state.attemptDutyDispositions.get(key) ?? []).map((r) => ({ eventId: r.eventId, position: r.position, type: r.type, findingHash: r.findingHash })),
    };
  },
  anchor: (state, key) => {
    const position = Number(key);
    const a = state.anchors.find((anchor) => anchor.eventPosition === position);
    return a === undefined ? undefined : { position, eventId: a.eventId, anchor: a.anchor, head: { hash: a.head.hash, position: a.head.position, canonicalTime: a.head.canonicalTime } };
  },
  witnessBinding: (state, key) => {
    const w = state.boundWitnesses.find((witness) => witness.verifierKey === key);
    if (w === undefined) return undefined;
    const policy = dataAt(state, w.eventPosition).policy as Rec;
    return { url: w.url, verifierKey: w.verifierKey, name: nullable(w.name), boundAtPosition: w.eventPosition, policy: { quorum: policy.quorum, requireOnOpen: policy.requireOnOpen, maxUnwitnessedEvents: policy.maxUnwitnessedEvents } };
  },
  witnessPolicy: (state) => {
    const position = (state as MutableReplayState).boundPolicyPosition;
    const policy = state.boundPolicy;
    return policy === undefined || position === undefined ? undefined : { policy: { quorum: policy.quorum, requireOnOpen: policy.requireOnOpen, maxUnwitnessedEvents: policy.maxUnwitnessedEvents }, position };
  },
  shadow: (state) => {
    const hashes = state.shadowHashes;
    return hashes === undefined ? undefined : { count: hashes.length, root: rootOfLeaves(hashes.map(hexToBytes)) };
  },
  // TODO(E2): the budget, counterparty, refusal and effect records are kept in their own maps by E2's transitions (SPEC §9–§11).
  budget: (state, key) => state.budgets.get(key),
  budgetUsage: (state, key) => state.budgetUsage.get(key),
  counterparty: (state, key) => state.counterparties.get(key),
  refusal: (state, key) => state.refusals.get(key),
  effect: (state, key) => state.effects.get(key),
  observation: (state, key) => state.reconciliationObservations.get(key),
  "reconciliation-cursor": (state, key) => state.reconciliationCursors.get(key),
};

/** The §7.2 `event` record of an accepted event (one per position; carries the id index, order and per-position hashes). */
export function eventRecord(event: CanonicalEvent, position: number, eventHash: ContentHash, recordHash: ContentHash): Rec {
  const [actor, subject] = projectionFields(event);
  return { position, eventId: event.id, type: event.type, timestamp: event.timestamp, eventHash, recordHash, actorId: actor, subjectId: subject };
}

/** The (kind, key) pairs an accepted event may have created or changed, besides its own `event` record. */
type DerivedKind = Exclude<StateRecordKind, "event">;
function touchedKeys(state: ReplayState, event: CanonicalEvent, position: number): readonly (readonly [DerivedKind, string])[] {
  // A migrated history's `shadow` record commits to the source hashes as they grow: it changes with every prefix event (SPEC §16.2 step 3).
  const shadow = (state as MutableReplayState).shadow;
  const prefix: readonly (readonly [DerivedKind, string])[] = state.shadowHashes !== undefined && (event.type === "DEPLOYMENT_INITIALIZED" || (shadow !== undefined && position <= shadow.until)) ? [["shadow", "0"]] : [];
  return [...prefix, ...touchedByType(state, event, position)];
}
function touchedByType(state: ReplayState, event: CanonicalEvent, position: number): readonly (readonly [DerivedKind, string])[] {
  const d = event.data as Rec & { grant?: Rec; record?: Rec; descriptor?: Rec; envelope?: Rec; witnesses?: readonly Rec[]; verifierKeys?: readonly string[]; ownerKeys?: readonly Rec[] };
  const id = (value: unknown): string => value as string;
  switch (event.type) {
    case "DEPLOYMENT_INITIALIZED": return [["genesis", "0"], ["ownerKeyEpoch", "0"]];
    case "PRINCIPAL_CREATED": return [["principal", id(d.principalId)]];
    case "AGENT_CREATED": return [["agent", id(d.agentId)]];
    case "ROLE_CREATED": return [["role", id(d.roleId)]];
    case "SUCCESSION_RULE_DECLARED": return [["succession", id(d.ruleId)]];
    case "AGENT_APPOINTED": case "AGENT_UNAPPOINTED": return [["tenure", id(d.roleTenureId)], ["role", id(d.roleId)]];
    case "ROLE_TRANSFERRED": return [["tenure", id(d.fromRoleTenureId)], ["tenure", id(d.toRoleTenureId)], ["role", id(d.roleId)]];
    case "RUNTIME_SESSION_ADMITTED": return [["session", id(d.sessionId)]];
    case "CONTROL_EPOCH_ADVANCED": return [["agent", id(d.agentId)]];
    case "AUTHORITY_GRANTED": return [["authority", id(d.grant!.authorityId)]];
    case "AUTHORITY_REVOKED": return [["authority", id(d.authorityId)]];
    case "TRANSACTION_INTENT_DECLARED": return [["intent", id(d.intentId)], ["nonce", hashCanonical([d.actorId, d.nonce], "sha256")]];
    case "TRANSACTION_INTENT_ADMITTED": {
      const proof = d.authorizationProof as Rec & { controllingAuthorityIds: readonly string[] };
      return [["intent", id(d.intentId)], ...proof.controllingAuthorityIds.map((authorityId) => ["usage", authorityId] as const), ...[...state.budgetUsage.keys()].map((key) => ["budgetUsage", key] as const)];
    }
    case "TRANSACTION_INTENT_CONSUMED": case "TRANSACTION_OUTCOME_RECORDED": case "OUTCOME_OBSERVATION_RECORDED": return [["intent", id(d.intentId)]];
    case "RECEIPT_RECORDED": return [["receipt", id(d.receiptContentHash)]];
    case "OBLIGATION_CREATED": return [["obligation", id(d.record!.obligationId)]];
    case "OBLIGATION_PERFORMANCE_ASSIGNED": case "OBLIGATION_STATUS_RECORDED": return [["obligation", id(d.obligationId)]];
    case "AGENT_TERMINATED": return [["agent", id(d.agentId)], ["tenure", id(d.roleTenureId)]];
    case "ATTEMPT_DUTY_CREATED": return [["duty", id(d.record!.dutyId)]];
    case "ATTEMPT_DUTY_ASSIGNED": case "ATTEMPT_DUTY_REVIEW_CLOSED": case "ATTEMPT_DUTY_DISPOSITION_RECORDED": case "ATTEMPT_DUTY_CONTEST_RECORDED": return [["duty", id(d.dutyId)]];
    case "ATTEMPT_DUTY_POLICY_ACTIVATED": return [["duty", id(d.descriptor!.dutyId)]];
    case "ANCHOR_RECORDED": return [["anchor", positionKey(position)]];
    case "OWNER_KEYS_ROTATED": return [["ownerKeyEpoch", String(state.ownerKeyEpochs.length - 1)]];
    case "WITNESSES_BOUND": return [...d.witnesses!.map((w) => ["witnessBinding", id(w.verifierKey)] as const), ["witnessPolicy", "0"]];
    case "WITNESSES_UNBOUND": return [...d.verifierKeys!.map((key) => ["witnessBinding", key] as const), ["witnessPolicy", "0"]];
    case "BUDGET_DECLARED": case "BUDGET_UPDATED": case "BUDGET_CLOSED": return [["budget", id(d.budgetId)]];
    case "STATE_CHECKPOINT": return [];
    case "COUNTERPARTY_REGISTERED": case "COUNTERPARTY_RETIRED": return [["counterparty", id(d.counterpartyId)]];
    case "REQUEST_REFUSED": return [["refusal", id(d.refusalId)]];
    case "EFFECT_RECORDED": return [["effect", id(d.effectId)]];
    case "COUNTERPARTY_RECEIPT_RECORDED": return [["counterparty", id(d.envelope!.counterpartyId)]];
    case "RECONCILIATION_OBSERVED": {
      const source = d.source as Rec;
      return [["observation", id(d.observationId)], ["reconciliation-cursor", reconciliationCursorKey(id(d.reconcilerAgentId), id(source.streamId))]];
    }
  }
}

/**
 * An upper bound of `R(p) − R(p−1)` for `event` at `position` on the pre-event `state` (A-3 capacity): its own `event`
 * record, every touched key not yet present, up to 16 new `budgetUsage` records for an admission (§9.4: at most 16
 * matching budgets are charged) and a slack of 2 for keys only known after the transition (a rotation's new epoch).
 * Never smaller than the exact delta; replay computes the exact one when the bound matters (replay.ts).
 */
export function upperRecordDelta(state: ReplayState, event: CanonicalEvent, position: number): number {
  let keys: readonly (readonly [DerivedKind, string])[];
  try { keys = touchedKeys(state, event, position); } catch { return 1 + 64; }
  const seen = new Set<string>();
  let created = 0;
  for (const [kind, key] of keys) {
    const k = recordKey(kind, key);
    if (seen.has(k)) continue;
    seen.add(k);
    if (!state.stateRecords.has(k)) created += 1;
  }
  return 1 + created + 2 + (event.type === "TRANSACTION_INTENT_ADMITTED" ? 16 : 0);
}

/** The record of `(kind, key)` derived from the state, or `undefined` when no such record exists (any more). */
export function deriveRecord(state: ReplayState, kind: StateRecordKind, key: string): Rec | undefined {
  if (kind === "event") return state.stateRecords.get(recordKey("event", key))?.record;
  return derive[kind](state, key);
}

// ---------------------------------------------------------------- the incremental leaf map

const indexOfKey = (keys: readonly string[], key: string): number => {
  let low = 0, high = keys.length;
  while (low < high) {
    const mid = (low + high) >>> 1;
    if (compareRecordKeys(keys[mid]!, key) < 0) low = mid + 1; else high = mid;
  }
  return low;
};
const sameLeaf = (a: Uint8Array, b: Uint8Array): boolean => {
  for (let index = 0; index < 32; index += 1) if (a[index] !== b[index]) return false;
  return true;
};
const setRecord = (state: MutableReplayState, kind: string, key: string, record: Rec | undefined, changes: RecordChange[], undo: (readonly [string, StateRecordEntry | undefined])[]): void => {
  const k = recordKey(kind, key);
  const previous = state.stateRecords.get(k);
  if (record === undefined) {
    if (previous === undefined) return;
    state.stateRecords.delete(k);
    const at = indexOfKey(state.sortedRecordKeys, k);
    if (state.sortedRecordKeys[at] === k) { state.sortedRecordKeys.splice(at, 1); state.rootLog.removed(at); }
    undo.push([k, previous]);
    changes.push({ kind, key, record: undefined });
    return;
  }
  const frozen = wireAmounts(record);
  const entry: StateRecordEntry = Object.freeze({ kind, key, record: frozen, leaf: leafOf(kind, key, frozen) });
  state.stateRecords.set(k, entry);
  if (previous === undefined) {
    const at = indexOfKey(state.sortedRecordKeys, k);
    state.sortedRecordKeys.splice(at, 0, k);
    state.rootLog.inserted(at, entry.leaf);
  } else if (state.rootLog.tree !== undefined && !sameLeaf(previous.leaf, entry.leaf)) {
    state.rootLog.updated(indexOfKey(state.sortedRecordKeys, k), entry.leaf);
  }
  undo.push([k, previous]);
  changes.push({ kind, key, record: frozen });
};
/** One record an event created, changed or removed (`record` undefined); the store's snapshot journal reads them. */
export type RecordChange = Readonly<{ kind: string; key: string; record: Rec | undefined }>;

/**
 * After an accepted format-2 event at `position`: recompute the records it touched, add its `event` record, log what
 * they replaced (`rootAt(position)` is computed on first read, `state-roots.ts`), and append the projection row's head.
 */
export function applyStateRecords(state: MutableReplayState, event: CanonicalEvent, position: number, eventHash: ContentHash, recordHash: ContentHash): void {
  const changes: RecordChange[] = [], undo: (readonly [string, StateRecordEntry | undefined])[] = [];
  for (const [kind, key] of touchedKeys(state, event, position)) setRecord(state, kind, key, derive[kind](state, key), changes, undo);
  setRecord(state, "event", positionKey(position), eventRecord(event, position, eventHash, recordHash), changes, undo);
  state.lastRecordChanges = changes;
  // rootAt(position) is computed where it is read (state-roots.ts): the undo list lets an earlier position's root be recomputed.
  state.rootLog.logUndo(position, undo as UndoList);
  if (state.genesis.projection !== null) state.projectionHeads.push(projectionHeadAfter(state.projectionHeads.at(-1) ?? null, projectionRow(event, position, eventHash)));
}

/** The §7.2 record set of a format-2 state in (kind, key) order (empty for other formats). */
export function stateRecordsOf(state: ReplayState): readonly StateRecordEntry[] {
  const sorted = (state as MutableReplayState).sortedRecordKeys ?? [...state.stateRecords.keys()].sort(compareRecordKeys);
  return Object.freeze(sorted.map((k) => state.stateRecords.get(k)!));
}
/** `rootAt(head.position)` and the leaf count of a format-2 state; `undefined` for other formats. */
export function stateRootOf(state: ReplayState): Readonly<{ root: ContentHash; count: U53 }> | undefined {
  const root = state.stateRoots.at(-1);
  return root === undefined ? undefined : Object.freeze({ root, count: state.stateRecords.size });
}
/** `rootAt(p)` (SPEC §7.1) — computed on first read from the records at `p` and kept (`state-roots.ts`). */
export const rootAt = (state: ReplayState, position: number): ContentHash | undefined => state.stateRoots[position];
/** `projectionHead(p)` (SPEC §12.3), `null` when the genesis turned the projection off. */
export const projectionHeadAt = (state: ReplayState, position: number): ContentHash | null | undefined =>
  state.genesis.projection === null ? null : state.projectionHeads[position];
/** Every record derived from scratch (the from-state computation the incremental map must agree with; test helper and E3 rebuild cross-check). */
export function deriveAllRecords(state: ReplayState): readonly Readonly<{ kind: string; key: string; record: Rec }>[] {
  const out: { kind: string; key: string; record: Rec }[] = [];
  const add = (kind: DerivedKind, key: string): void => { const record = derive[kind](state, key); if (record !== undefined) out.push({ kind, key, record: wireAmounts(record) }); };
  for (const entry of state.stateRecords.values()) if (entry.kind === "event") out.push({ kind: "event", key: entry.key, record: entry.record });
  add("genesis", "0");
  state.ownerKeyEpochs.forEach((_epoch, index) => add("ownerKeyEpoch", String(index)));
  for (const key of state.principals.keys()) add("principal", key);
  for (const key of state.agents.keys()) add("agent", key);
  for (const key of state.roles.keys()) add("role", key);
  for (const key of state.tenures.keys()) add("tenure", key);
  for (const key of state.successionRules.keys()) add("succession", key);
  for (const key of state.runtimeSessions.keys()) add("session", key);
  for (const key of state.authorities.keys()) add("authority", key);
  for (const key of state.usageCounters.keys()) add("usage", key);
  for (const key of state.nonceRecords.keys()) add("nonce", key);
  for (const key of state.intentDeclarations.keys()) add("intent", key);
  for (const key of state.receiptCommitments.keys()) add("receipt", key);
  for (const key of state.obligations.keys()) add("obligation", key);
  for (const key of state.attemptDuties.keys()) add("duty", key);
  for (const anchor of state.anchors) add("anchor", positionKey(anchor.eventPosition));
  for (const witness of state.boundWitnesses) add("witnessBinding", witness.verifierKey);
  add("witnessPolicy", "0");
  add("shadow", "0");
  for (const key of state.budgets.keys()) add("budget", key);
  for (const key of state.budgetUsage.keys()) add("budgetUsage", key);
  for (const key of state.counterparties.keys()) add("counterparty", key);
  for (const key of state.refusals.keys()) add("refusal", key);
  for (const key of state.effects.keys()) add("effect", key);
  for (const key of state.reconciliationObservations.keys()) add("observation", key);
  for (const key of state.reconciliationCursors.keys()) add("reconciliation-cursor", key);
  return Object.freeze(out);
}
