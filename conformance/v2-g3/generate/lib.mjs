// IronTrellis Core — format 2 conformance generator library.
//
// ROLE OF THIS FILE (read before porting anything from it):
//   * `crypto` section: canonical encoding, SHA-256 and Ed25519 are taken from the
//     frozen rc.1-final engine build (unchanged in format 2) and from node:crypto.
//     These are mechanical and may be used by anyone.
//   * `format 2 primitives` section: the record chain, challenge preimages,
//     projection rows and state-root derivation. These implement SPEC-IRONTRELLIS-CORE-v2.md
//     §4–§7 and §12 byte for byte. They are a SPEC ORACLE for those sections: the
//     Python port must be written from the spec text, then checked against the
//     vectors — not transcribed from here.
//   * `budget oracle` section: the budget decision procedure of SPEC §9. SPEC ORACLE.
//
// Nothing here is an engine. It never reads a store file, never signs with a key it
// did not derive from the published test seeds (TEST-KEYS.md), never contacts anything.
import { createHash, createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from 'node:crypto';
import { join } from 'node:path';

const DIST = process.env.IRONTRELLIS_RC1_DIST ?? '/home/claude/work/itc/scratch/rc1/packages/core/dist';
export const core = await import(join(DIST, 'index.js'));
export const rc1signer = await import(join(DIST, 'signer.js'));
export const merkle = await import(join(DIST, 'transparency/merkle.js'));

// ---------------------------------------------------------------- constants (SPEC §3)
export const V2 = Object.freeze({
  eventSchemaVersion: 'irontrellis-event/2',
  storeLineVersion: 'irontrellis-portable-file-store/2',
  recordChainVersion: 'irontrellis-record/2',
  stateDerivationVersion: 'irontrellis-state/2',
  projectionVersion: 'irontrellis-projection/2',
  receiptSchemaVersion: 'irontrellis-receipt/2',
  controlAuthorizationVersion: 'irontrellis-control-authorization/2',
  queryEnvelopeVersion: 'continuity-query-envelope/0.2',
  authorizationProofVersion: 'irontrellis-authorization-proof/2',
  runtimeAuthorizationVersion: 'irontrellis-runtime-authorization/2',
  administrativeAuthorizationVersion: 'irontrellis-administrative-authorization/2',
  intentDeclarationVersion: 'irontrellis-intent-declaration/2',
  refusalAuthorizationVersion: 'irontrellis-refusal-authorization/2',
  effectAuthorizationVersion: 'irontrellis-effect-authorization/2',
  counterpartyReceiptVersion: 'irontrellis-counterparty-receipt/2',
  exportVersion: 'irontrellis-export/2',
  migratedMarkerVersion: 'irontrellis-migrated/1',
  counterpartyRecordVersion: 'irontrellis-counterparty-record-authorization/2',
  headAttestationVersion: 'irontrellis-head-attestation/2',
  policyVersion: 'irontrellis-local-owner/2',
  rootRecognitionPolicy: 'declared-principal-root/0.2',
  ownerKeyDigestVersion: 'irontrellis-owner-key-digest/1',
});
export const GENESIS_VERSIONS = (signatureScheme = 'ed25519') => Object.freeze({
  eventSchemaVersion: V2.eventSchemaVersion,
  historyHashAlgorithm: 'sha256',
  recordChainVersion: V2.recordChainVersion,
  stateDerivationVersion: V2.stateDerivationVersion,
  projectionVersion: V2.projectionVersion,
  receiptSchemaVersion: V2.receiptSchemaVersion,
  controlAuthorizationVersion: V2.controlAuthorizationVersion,
  queryEnvelopeVersion: V2.queryEnvelopeVersion,
  authorizationProofVersion: V2.authorizationProofVersion,
  runtimeAuthorizationVersion: V2.runtimeAuthorizationVersion,
  administrativeAuthorizationVersion: V2.administrativeAuthorizationVersion,
  signatureScheme,
});

/** The 41 event types of format 2 in their canonical order; the index is the projection type code (SPEC §12). */
export const EVENT_TYPES = Object.freeze([
  'DEPLOYMENT_INITIALIZED', 'PRINCIPAL_CREATED', 'AGENT_CREATED', 'ROLE_CREATED', 'SUCCESSION_RULE_DECLARED', 'AGENT_APPOINTED', 'AGENT_UNAPPOINTED',
  'ROLE_TRANSFERRED', 'RUNTIME_SESSION_ADMITTED', 'CONTROL_EPOCH_ADVANCED', 'AUTHORITY_GRANTED', 'AUTHORITY_REVOKED', 'TRANSACTION_INTENT_DECLARED',
  'TRANSACTION_INTENT_ADMITTED', 'TRANSACTION_INTENT_CONSUMED', 'TRANSACTION_OUTCOME_RECORDED', 'RECEIPT_RECORDED', 'OBLIGATION_CREATED',
  'OBLIGATION_PERFORMANCE_ASSIGNED', 'OBLIGATION_STATUS_RECORDED', 'AGENT_TERMINATED', 'OUTCOME_OBSERVATION_RECORDED', 'ATTEMPT_DUTY_CREATED',
  'ATTEMPT_DUTY_ASSIGNED', 'ATTEMPT_DUTY_REVIEW_CLOSED', 'ANCHOR_RECORDED', 'OWNER_KEYS_ROTATED', 'WITNESSES_BOUND', 'WITNESSES_UNBOUND',
  // ported from Continuity preview.10.2 (positions 29–31)
  'ATTEMPT_DUTY_POLICY_ACTIVATED', 'ATTEMPT_DUTY_DISPOSITION_RECORDED', 'ATTEMPT_DUTY_CONTEST_RECORDED',
  // new in format 2 (positions 32–40)
  'BUDGET_DECLARED', 'BUDGET_UPDATED', 'BUDGET_CLOSED', 'STATE_CHECKPOINT', 'COUNTERPARTY_REGISTERED', 'COUNTERPARTY_RETIRED',
  'REQUEST_REFUSED', 'EFFECT_RECORDED', 'COUNTERPARTY_RECEIPT_RECORDED',
]);
export const CONTROL_TYPES = new Set([
  'PRINCIPAL_CREATED', 'AGENT_CREATED', 'ROLE_CREATED', 'SUCCESSION_RULE_DECLARED', 'AGENT_APPOINTED', 'AGENT_UNAPPOINTED', 'ROLE_TRANSFERRED',
  'RUNTIME_SESSION_ADMITTED', 'CONTROL_EPOCH_ADVANCED', 'AUTHORITY_GRANTED', 'AUTHORITY_REVOKED', 'AGENT_TERMINATED', 'ANCHOR_RECORDED', 'OWNER_KEYS_ROTATED',
  'WITNESSES_BOUND', 'WITNESSES_UNBOUND', 'BUDGET_DECLARED', 'BUDGET_UPDATED', 'BUDGET_CLOSED', 'STATE_CHECKPOINT', 'COUNTERPARTY_REGISTERED', 'COUNTERPARTY_RETIRED',
]);
export const SESSION_SIGNED_TYPES = new Set(['TRANSACTION_INTENT_DECLARED', 'TRANSACTION_INTENT_ADMITTED', 'REQUEST_REFUSED', 'EFFECT_RECORDED', 'COUNTERPARTY_RECEIPT_RECORDED']);

// ---------------------------------------------------------------- crypto (mechanical)
export const canonical = (value) => core.canonicalEncode(value);
export const sha256 = (bytes) => createHash('sha256').update(bytes).digest();
export const hex = (bytes) => `0x${Buffer.from(bytes).toString('hex')}`;
export const unhex = (h) => Buffer.from(h.slice(2), 'hex');
export const ZERO32 = Buffer.alloc(32);
/** hashCanonical: 0x + sha256 over the UTF-8 canonical text. */
export const hashCanonical = (value) => hex(sha256(Buffer.from(canonical(value), 'utf8')));
export const be64 = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
export const be16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
export const be256 = (decimal) => { let v = BigInt(decimal); const b = Buffer.alloc(32); for (let i = 31; i >= 0; i--) { b[i] = Number(v & 0xffn); v >>= 8n; } return b; };
const utf8 = (s) => Buffer.from(s, 'utf8');
const seedHex = (n) => `0x${n.toString(16).padStart(64, '0')}`;
/** Deterministic Ed25519 key from a 32-byte seed integer (TEST-KEYS.md). */
export const keyFromSeed = (keyId, n) => core.keyPairFromPrivateKey('ed25519', keyId, seedHex(n));
export const signerOf = (pair) => core.signHashWith(pair);
export const verifyEd25519 = (credentialHex, hashHex, signatureHex) => {
  const pub = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), unhex(credentialHex)]), format: 'der', type: 'spki' });
  return nodeVerify(null, unhex(hashHex), pub, unhex(signatureHex));
};
export const ownerKeyDigest = (key) => hashCanonical({ version: V2.ownerKeyDigestVersion, scheme: key.scheme, credential: key.credential.toLowerCase() });

// ---------------------------------------------------------------- format 2 primitives (SPEC ORACLE for §4–§7, §12)
/** SPEC §4.2: eventHash = sha256(utf8(canonical(event))). */
export const eventHash = (event) => sha256(utf8(canonical(event)));
/** SPEC §4.3: recordHash(p) = sha256(utf8("irontrellis-record/2") ‖ 0x00 ‖ prev ‖ eventHash ‖ be64(p)). */
export const recordHash = (prev, evHash, position) => sha256(Buffer.concat([utf8(V2.recordChainVersion), Buffer.from([0]), prev, evHash, be64(position)]));

/** Builds the heads and store lines of an event list (SPEC §4). Returns per-position {eventHash, recordHash, head}. */
export function chain(events) {
  const rows = [];
  let prev = ZERO32;
  events.forEach((event, p) => {
    const eh = eventHash(event);
    const rh = recordHash(prev, eh, p);
    rows.push({ eventHash: hex(eh), recordHash: hex(rh), head: { hash: hex(rh), position: p, canonicalTime: event.timestamp } });
    prev = rh;
  });
  return rows;
}
export const storeLines = (events) => {
  const rows = chain(events);
  return events.map((event, p) => JSON.stringify({ version: V2.storeLineVersion, previousHash: p === 0 ? null : rows[p - 1].recordHash, event, recordHash: rows[p].recordHash }) + '\n').join('');
};

/** SPEC §6.1: the control-authorization challenge of format 2. */
export const controlChallenge = (domain, event, previousHead) => ({
  version: V2.controlAuthorizationVersion, domain, eventId: event.id, eventType: event.type, timestamp: event.timestamp,
  previousHead: previousHead === null ? null : { hash: previousHead.hash, position: previousHead.position },
  effectHash: hashCanonical(effectOf(event.data)),
});
export const effectOf = (data) => { const { controlAuthorization: _a, nextKeyAuthorizations: _n, ...effect } = data; return effect; };
export async function signControl(domain, event, previousHead, pair) {
  const h = hashCanonical(controlChallenge(domain, event, previousHead));
  const signature = await signerOf(pair)(h);
  return { ...event, data: { ...event.data, controlAuthorization: { keyId: pair.keyId, signature } } };
}

/** SPEC §8.2: the runtime-authorization challenge of format 2 (amounts are decimal strings). */
export const runtimeChallenge = (domain, request, evaluationTime, policyVersion, head, binding) => ({
  version: V2.runtimeAuthorizationVersion, domain, request: normalizedRequest(request), authoritative: true, consequential: true, evaluationTime,
  policyVersion, rootRecognitionPolicy: V2.rootRecognitionPolicy, eventHistoryHash: head.hash, eventHistoryPosition: head.position,
  runtimeSessionId: binding.runtimeSessionId, credentialKeyId: binding.credentialKeyId, controlEpoch: binding.controlEpoch, roleId: binding.roleId,
  roleTenureId: binding.roleTenureId, intentId: binding.intentId, nonce: binding.nonce,
});
export const normalizedRequest = (r) => {
  const out = { actorId: r.actorId, action: r.action, resource: r.resource, claimedAt: r.claimedAt };
  for (const k of ['amount', 'counterpartyId', 'termsCommitment', 'metric']) if (Object.hasOwn(r, k)) out[k] = r[k];
  return out;
};
/**
 * A-54 (founder-approved 2026-10-11) with A-59: the §8.6, §10.1, §10.2 and §11.2 session challenges bind the final
 * envelope — `eventId`, `eventType` (the challenge's own literal) and `timestamp`. `envelope` is the event being signed
 * ({id, timestamp}); a caller fixes it before hashing. The §8.2 runtime challenge is unchanged (A-59.2).
 */
const envelopeFields = (eventType, envelope) => {
  if (envelope === undefined || typeof envelope.id !== 'string' || !Number.isSafeInteger(envelope.timestamp)) throw new Error(`A-54: the ${eventType} challenge needs the final envelope {id, timestamp}`);
  return { eventId: envelope.id, eventType, timestamp: envelope.timestamp };
};
/** SPEC §8.6 + A-54: intent-declaration challenge. `head` is the head before the event. */
export const declarationChallenge = (domain, data, head, session, envelope) => ({
  version: V2.intentDeclarationVersion, domain, ...envelopeFields('TRANSACTION_INTENT_DECLARED', envelope), intentId: data.intentId, nonce: data.nonce, actorId: data.actorId, action: data.action, resource: data.resource,
  roleId: data.roleId, roleTenureId: data.roleTenureId, adapterProfile: data.adapterProfile, amount: data.amount ?? null, counterpartyId: data.counterpartyId ?? null,
  termsCommitment: data.termsCommitment ?? null, metric: data.metric ?? null, eventHistoryHash: head.hash, eventHistoryPosition: head.position,
  runtimeSessionId: session.runtimeSessionId, credentialKeyId: session.credentialKeyId, controlEpoch: session.controlEpoch,
});
/** SPEC §10.1 + A-59: refusal challenge. */
export const refusalChallenge = (domain, d, envelope) => ({
  version: V2.refusalAuthorizationVersion, domain, ...envelopeFields('REQUEST_REFUSED', envelope), refusalId: d.refusalId, refusalSource: d.refusalSource, request: normalizedRequest(d.request), evaluationTime: d.evaluationTime,
  eventHistoryHash: d.expectedHistoryHead.hash, eventHistoryPosition: d.expectedHistoryHead.position, decision: d.decision, code: d.code,
  budgetId: d.budgetId ?? null, connector: d.connector ?? null, runtimeSessionId: d.runtimeSessionId, credentialKeyId: d.credentialKeyId, controlEpoch: d.controlEpoch,
});
/** SPEC §10.2 + A-54: effect challenge. */
export const effectChallenge = (domain, d, head, envelope) => ({
  version: V2.effectAuthorizationVersion, domain, ...envelopeFields('EFFECT_RECORDED', envelope), effectId: d.effectId, intentId: d.intentId, measurer: d.measurer, metric: d.metric, unit: d.unit, amount: d.amount,
  observedAt: d.observedAt, detailDigest: d.detailDigest, eventHistoryHash: head.hash, eventHistoryPosition: head.position,
  runtimeSessionId: d.runtimeSessionId, credentialKeyId: d.credentialKeyId, controlEpoch: d.controlEpoch,
});
/** SPEC §11.2 + A-54: counterparty envelope digest (over the envelope without its signature) and record challenge. */
export const envelopeSigningHash = (envelope) => { const { signature: _s, ...body } = envelope; return hashCanonical(body); };
export const envelopeDigest = (envelope) => hashCanonical(envelope);
export const counterpartyRecordChallenge = (domain, d, head, envelope) => ({
  version: V2.counterpartyRecordVersion, domain, ...envelopeFields('COUNTERPARTY_RECEIPT_RECORDED', envelope), intentId: d.intentId, envelopeDigest: envelopeDigest(d.envelope), eventHistoryHash: head.hash, eventHistoryPosition: head.position,
  runtimeSessionId: d.runtimeSessionId, credentialKeyId: d.credentialKeyId, controlEpoch: d.controlEpoch,
});
/** SPEC §7.4: head attestation of format 2 (the domain is carried as a plain label; head.hash already commits to the genesis). */
export const attestationBody = (domain, head, stateRoot, projectionHead) => ({ version: V2.headAttestationVersion, domain, head, stateRoot, projectionHead });
export const MAX_AMOUNT = (1n << 256n) - 1n;

// ---------------------------------------------------------------- projection rows (SPEC §12)
const sid = (s) => (s === undefined || s === null ? ZERO32 : sha256(utf8(s)));
/** actor / subject / amount selection per type (SPEC §12.2 table). */
export function projectionFields(event) {
  const d = event.data, t = event.type;
  const g = d.grant;
  switch (t) {
    case 'DEPLOYMENT_INITIALIZED': return [null, d.canonicalLineageId, null];
    case 'PRINCIPAL_CREATED': return [null, d.principalId, null];
    case 'AGENT_CREATED': return [d.agentId, d.principalId, null];
    case 'ROLE_CREATED': return [null, d.roleId, null];
    case 'SUCCESSION_RULE_DECLARED': return [d.predecessorAgentId, d.ruleId, null];
    case 'AGENT_APPOINTED': case 'AGENT_UNAPPOINTED': return [d.agentId, d.roleTenureId, null];
    case 'ROLE_TRANSFERRED': return [d.toAgentId, d.toRoleTenureId, null];
    case 'RUNTIME_SESSION_ADMITTED': return [d.agentId, d.sessionId, null];
    case 'CONTROL_EPOCH_ADVANCED': return [d.agentId, d.controllerId, null];
    case 'AUTHORITY_GRANTED': return [g.kind === 'PERMISSION' ? g.granteeId : (g.subjectActorId ?? null), g.authorityId, g.constraints.maxAmount ?? null];
    case 'AUTHORITY_REVOKED': return [d.revokerId, d.authorityId, null];
    case 'TRANSACTION_INTENT_DECLARED': return [d.actorId, d.intentId, d.amount ?? null];
    case 'TRANSACTION_INTENT_ADMITTED': return [d.authorizationProof.request.actorId, d.intentId, d.authorizationProof.request.amount ?? null];
    case 'TRANSACTION_INTENT_CONSUMED': case 'TRANSACTION_OUTCOME_RECORDED': case 'OUTCOME_OBSERVATION_RECORDED': return [null, d.intentId, null];
    case 'RECEIPT_RECORDED': return [d.issuerAgentId, d.intentId, null];
    case 'OBLIGATION_CREATED': return [d.actorId, d.record.obligationId, null];
    case 'OBLIGATION_PERFORMANCE_ASSIGNED': return [d.toAgentId, d.obligationId, null];
    case 'OBLIGATION_STATUS_RECORDED': return [d.actorId, d.obligationId, null];
    case 'AGENT_TERMINATED': return [d.agentId, d.roleTenureId, null];
    case 'ATTEMPT_DUTY_CREATED': return [d.actorId, d.record.dutyId, null];
    case 'ATTEMPT_DUTY_ASSIGNED': return [d.toAgentId, d.dutyId, null];
    case 'ATTEMPT_DUTY_REVIEW_CLOSED': case 'ATTEMPT_DUTY_POLICY_ACTIVATED': case 'ATTEMPT_DUTY_DISPOSITION_RECORDED': case 'ATTEMPT_DUTY_CONTEST_RECORDED': return [d.actorId, d.dutyId ?? d.descriptor?.dutyId ?? null, null];
    case 'ANCHOR_RECORDED': return [null, d.anchor, null];
    case 'OWNER_KEYS_ROTATED': return [null, d.ownerKeys[0].keyId, null];
    case 'WITNESSES_BOUND': return [null, d.witnesses[0].verifierKey, null];
    case 'WITNESSES_UNBOUND': return [null, d.verifierKeys[0], null];
    case 'BUDGET_DECLARED': case 'BUDGET_UPDATED': return [null, d.budgetId, d.amountCap ?? null];
    case 'BUDGET_CLOSED': return [null, d.budgetId, null];
    case 'STATE_CHECKPOINT': return [null, d.checkpointId, null];
    case 'COUNTERPARTY_REGISTERED': case 'COUNTERPARTY_RETIRED': return [null, d.counterpartyId, null];
    case 'REQUEST_REFUSED': return [d.request.actorId, d.refusalId, d.request.amount ?? null];
    case 'EFFECT_RECORDED': return [d.measurer.id, d.intentId, d.amount];
    case 'COUNTERPARTY_RECEIPT_RECORDED': return [d.envelope.counterpartyId, d.intentId, d.envelope.amount];
    default: throw new Error(`no projection for ${t}`);
  }
}
/** SPEC §12.1: the 160-byte row. */
export function projectionRow(event, position, evHash) {
  const [actor, subject, amount] = projectionFields(event);
  const flags = (CONTROL_TYPES.has(event.type) ? 1 : 0) | (SESSION_SIGNED_TYPES.has(event.type) ? 2 : 0) | (amount !== null ? 4 : 0);
  return Buffer.concat([be64(position), be64(event.timestamp), be16(EVENT_TYPES.indexOf(event.type)), be16(flags), sid(actor), sid(subject), amount === null ? ZERO32 : be256(amount), evHash, Buffer.alloc(12)]);
}
/** SPEC §12.3: projectionHead(p) = sha256(utf8("irontrellis-projection/2") ‖ 0x00 ‖ projectionHead(p−1) ‖ row(p)); projectionHead(−1) = 0^32. */
export function projectionHeads(events) {
  let prev = ZERO32; const out = [];
  events.forEach((event, p) => { const row = projectionRow(event, p, eventHash(event)); prev = sha256(Buffer.concat([utf8(V2.projectionVersion), Buffer.from([0]), prev, row])); out.push({ head: hex(prev), row: hex(row) }); });
  return out;
}

// ---------------------------------------------------------------- state root (SPEC §7, SPEC ORACLE)
/** leaf = sha256(0x00 ‖ utf8(kind) ‖ 0x00 ‖ utf8(key) ‖ 0x00 ‖ sha256(utf8(canonical(record)))) */
export const stateLeaf = (kind, key, record) => sha256(Buffer.concat([Buffer.from([0]), utf8(kind), Buffer.from([0]), utf8(key), Buffer.from([0]), sha256(utf8(canonical(record)))]));
const byteCompare = (a, b) => Buffer.compare(utf8(a), utf8(b));
/** records: Map of "kind\u0000key" → record. Root = RFC 6962 MTH over leaves sorted by (kind, key) byte order; empty → sha256(""). */
export function stateRoot(records) {
  const entries = [...records.entries()].map(([k, record]) => { const [kind, key] = k.split('\u0000'); return { kind, key, record }; });
  entries.sort((a, b) => byteCompare(a.kind, b.kind) || byteCompare(a.key, b.key));
  const leaves = entries.map((e) => stateLeaf(e.kind, e.key, e.record));
  return { root: hex(merkleRoot(leaves)), count: leaves.length };
}
/** RFC 6962 §2.1 Merkle tree hash over already-hashed leaves (the leaf hashing of §7.1 replaces 6962's 0x00-prefixed leaf hash). */
export function merkleRoot(leaves) {
  if (leaves.length === 0) return sha256(Buffer.alloc(0));
  if (leaves.length === 1) return leaves[0];
  let k = 1; while (k * 2 < leaves.length) k *= 2;
  return sha256(Buffer.concat([Buffer.from([1]), merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k))]));
}

// ---------------------------------------------------------------- budget oracle (SPEC §9, SPEC ORACLE)
const big = (s) => BigInt(s);
const str = (b) => b.toString();
const minBig = (a, b) => (a < b ? a : b);
/** SPEC §9.2 matching. `rolesOf(actorId)` returns the Set of roleIds the actor currently holds (CURRENT tenures) at the evaluated state. */
export function budgetMatches(b, req, t, rolesOf) {
  if (b.status !== 'ACTIVE') return false;
  if (b.notBefore !== null && t < b.notBefore) return false;
  if (b.expiresAt !== null && t >= b.expiresAt) return false;
  if (b.subjects.actorIds !== null && !b.subjects.actorIds.includes(req.actorId)) return false;
  if (b.subjects.roleIds !== null) { const held = rolesOf(req.actorId); if (!b.subjects.roleIds.some((r) => held.has(r))) return false; }
  if (b.subjects.actions !== null && !b.subjects.actions.includes(req.action)) return false;
  if (b.subjects.resources !== null && !b.subjects.resources.includes(req.resource)) return false;
  return (req.metric ?? 'amount') === b.metric;
}
/** SPEC §9.3. */
export const periodIndex = (b, t) => (b.period.kind === 'NONE' ? 0 : t < b.period.originMs ? null : Math.floor((t - b.period.originMs) / b.period.lengthMs));
/**
 * SPEC §9.5 rollover, closed form (SPEC ORACLE). usage: Map "budgetId\u0000k" → {amount (bigint), count}.
 * f(p0) = c0; f(j+1) = min(carryCap, max(0, amountCap + f(j) − used(j))). Idle stretches of n periods: f(j+n) = min(carryCap, f(j) + n·amountCap).
 * The start (p0, c0) is the budget's carryBase (frozen at the last BUDGET_UPDATED) when k > carryBase.periodIndex, else (firstPeriod, 0).
 * Work is O(number of periods with usage between p0 and k), never O(k).
 */
export function carryIn(b, k, usage) {
  if (b.period.kind === 'NONE' || !b.period.carryUnused || b.amountCap === null) return 0n;
  const cap = big(b.amountCap), ccap = big(b.period.carryCap);
  let p0 = b.firstPeriod, c0 = 0n;
  if (b.carryBase !== null) {
    if (k === b.carryBase.periodIndex) return big(b.carryBase.carryIn);           // the frozen value itself
    if (k > b.carryBase.periodIndex) { p0 = b.carryBase.periodIndex; c0 = big(b.carryBase.carryIn); }
    // k < carryBase.periodIndex: a view of the past, computed from (firstPeriod, 0) under the current caps
  }
  if (k <= p0) return 0n;
  const used = [...usage.entries()].filter(([key]) => key.startsWith(`${b.budgetId}\u0000`)).map(([key, u]) => [Number(key.split('\u0000')[1]), u.amount])
    .filter(([j]) => j >= p0 && j < k).sort((x, y) => x[0] - y[0]);
  let cur = p0, carry = c0;
  for (const [j, amount] of used) {
    if (j > cur) carry = minBig(ccap, carry + BigInt(j - cur) * cap);           // idle stretch cur..j−1
    let unused = cap + carry - amount; if (unused < 0n) unused = 0n;
    carry = minBig(ccap, unused); cur = j + 1;
  }
  if (k > cur) carry = minBig(ccap, carry + BigInt(k - cur) * cap);
  return carry;
}
/** SPEC §9.4: allowed(B,k) = min(MAX, amountCap + carryIn); remainingAmount = max(0, allowed − used). Saturating, so every stored Amount stays ≤ MAX. */
export function remainingAmountOf(b, k, usage) {
  if (b.amountCap === null) return null;
  const u = usage.get(`${b.budgetId}\u0000${k}`) ?? { amount: 0n, count: 0 };
  const allowed = minBig(MAX_AMOUNT, big(b.amountCap) + carryIn(b, k, usage));
  const r = allowed - u.amount; return r < 0n ? 0n : r;
}
/** Evaluate budgets for an ALLOW-ed request; returns null (pass) or {code, budgetId}. Budgets are checked in byte order of budgetId (SPEC §9.4). */
export function evaluateBudgets(budgets, usage, req, t, rolesOf) {
  const matching = [...budgets.values()].filter((b) => budgetMatches(b, req, t, rolesOf)).sort((a, b) => byteCompare(a.budgetId, b.budgetId));
  if (matching.length > 16) return { code: 'BUDGET_SET_TOO_LARGE', budgetId: matching[16].budgetId };
  const amount = req.amount === undefined ? 0n : big(req.amount);
  for (const b of matching) {
    const k = periodIndex(b, t);
    if (k === null) return { code: 'BUDGET_PERIOD_UNDEFINED', budgetId: b.budgetId };
    const u = usage.get(`${b.budgetId}\u0000${k}`) ?? { amount: 0n, count: 0 };
    if (b.perOperationCap !== null && amount > big(b.perOperationCap)) return { code: 'BUDGET_PER_OPERATION_EXCEEDED', budgetId: b.budgetId };
    if (b.countCap !== null && u.count + 1 > b.countCap) return { code: 'BUDGET_COUNT_EXCEEDED', budgetId: b.budgetId };
    if (b.amountCap !== null && amount > remainingAmountOf(b, k, usage)) return { code: 'BUDGET_AMOUNT_EXCEEDED', budgetId: b.budgetId };
    if (u.amount + amount > MAX_AMOUNT) return { code: 'AMOUNT_OVERFLOW', budgetId: b.budgetId };   // SPEC §9.4 step 5 (closure; reachable only without amountCap)
  }
  return null;
}
/** Charge an admission (SPEC §9.6): every matching budget's current period gets amount and count. */
export function chargeBudgets(budgets, usage, req, t, rolesOf) {
  const amount = req.amount === undefined ? 0n : big(req.amount);
  for (const b of [...budgets.values()].filter((b) => budgetMatches(b, req, t, rolesOf))) {
    const k = periodIndex(b, t); const key = `${b.budgetId}\u0000${k}`;
    const u = usage.get(key) ?? { amount: 0n, count: 0 };
    usage.set(key, { amount: u.amount + amount, count: u.count + 1 });
  }
}
/** SPEC §9.7 headroom view (pure; `at` is any U53). */
export function headroom(budgets, usage, budgetId, t) {
  const b = budgets.get(budgetId); if (b === undefined) return null;
  const k = periodIndex(b, t);
  const active = b.status === 'ACTIVE' && (b.notBefore === null || t >= b.notBefore) && (b.expiresAt === null || t < b.expiresAt) && k !== null;
  const u = k === null ? { amount: 0n, count: 0 } : (usage.get(`${b.budgetId}\u0000${k}`) ?? { amount: 0n, count: 0 });
  const carry = k === null ? 0n : carryIn(b, k, usage);
  const remainingAmount = b.amountCap === null ? null : str(k === null ? big(b.amountCap) : remainingAmountOf(b, k, usage));
  const remainingCount = b.countCap === null ? null : Math.max(0, b.countCap - u.count);
  return { budgetId, active, periodIndex: k, usedAmount: str(u.amount), usedCount: u.count, carryIn: str(carry), remainingAmount, remainingCount };
}
export const usageRecordsFor = (usage) => [...usage.entries()].map(([k, u]) => { const [budgetId, period] = k.split('\u0000'); return { budgetId, periodIndex: Number(period), amount: str(u.amount), count: u.count }; });
