#!/usr/bin/env node
// IronTrellis Core — format 2 conformance vector generator (architect's copy).
//
//   IRONTRELLIS_RC1_DIST=<rc.1-final>/packages/core/dist node generate.mjs [--check]
//
// How the histories are built (see README.md in conformance/v2/):
//   1. The unchanged-semantics prefix of every history (principals, agents, roles,
//      sessions, grants, intents and admissions) is produced by the frozen
//      rc.1-final engine as a FORMAT-1 "twin", so the authorization proofs inside
//      the admissions are the engine's own, not hand-written.
//   2. The twin is transcribed to format 2 (SPEC §16.3): amounts become decimal
//      strings, the genesis declares the format-2 literals, consumptions are
//      dropped, control events are re-signed over the format-2 challenge, and
//      admissions are re-signed over the format-2 runtime challenge with the
//      format-2 heads. New format-2 events are inserted where the scenario says.
//   3. Expectations for the unchanged semantics come from the twin (the engine);
//      expectations for the new rules come from lib.mjs (SPEC ORACLE).
// The output files are byte-deterministic (fixed seeds, scripted clock, counter ids).
import { mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import * as L from './lib.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = dirname(HERE);
const CHECK = process.argv.includes('--check');
const WORK = join(tmpdir(), `irontrellis-v2-generate-${process.pid}`);
rmSync(WORK, { recursive: true, force: true }); mkdirSync(WORK, { recursive: true });
const { core, rc1signer } = L;

// ---------------------------------------------------------------- keys (TEST-KEYS.md)
const OWNER = L.keyFromSeed('owner:1', 0x1001);
const NEXT = L.keyFromSeed('owner:2', 0x1102);
const SESSION_KEYS = { spender: L.keyFromSeed('key:spender', 0x2004), gateway: L.keyFromSeed('key:gateway', 0x2005) };
const COUNTERPARTY = L.keyFromSeed('acme:1', 0x3001);
const STRANGER = L.keyFromSeed('stranger:1', 0x3999);
const ownerSigner = rc1signer.signerFromKeyPair(OWNER);
const DOMAIN1 = Object.freeze({ protocol: 'irontrellis', version: '1', deploymentId: 'irontrellis-conformance-v2' });
const DOMAIN = Object.freeze({ protocol: 'irontrellis', version: '2', deploymentId: 'irontrellis-conformance-v2' });

const plainBig = (v) => JSON.parse(JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? { '$continuity.bigint': x.toString() } : x)));
/** Amount markers → decimal strings, deeply (SPEC §3.4). */
const stringsForAmounts = (v) => {
  if (Array.isArray(v)) return v.map(stringsForAmounts);
  if (v && typeof v === 'object') {
    const keys = Object.keys(v);
    if (keys.length === 1 && keys[0] === '$continuity.bigint') return v['$continuity.bigint'];
    const out = {}; for (const k of keys) out[k] = stringsForAmounts(v[k]); return out;
  }
  return v;
};
const clone = (v) => JSON.parse(JSON.stringify(v));

// ---------------------------------------------------------------- twin: the format-1 prefix built by the rc.1-final engine
async function buildTwin() {
  const name = 'budget';
  let tick = 100, counter = 0;
  const historyFile = join(WORK, `${name}.jsonl`);
  const config = {
    historyFile, domain: DOMAIN1, owner: 'operations', controller: 'operator', format: core.TRELLIS_FORMAT,
    now: () => tick, ids: () => `${name}:${(counter += 1)}`, signer: ownerSigner, nextSigner: rc1signer.signerFromKeyPair(NEXT),
  };
  const step = async (p) => { const r = await p; tick += 1; return r; };
  const owner = await core.createLocalOwner(config);
  const spender = SESSION_KEYS.spender;
  await step(owner.createAgent({ id: 'spender' }));
  await step(owner.createRole({ id: 'cashier' }));
  await step(owner.appoint({ agent: 'spender', role: 'cashier', tenure: 'cashier:1', number: 1 }));
  await step(owner.admitRuntime({ session: 'session:spender', agent: 'spender', epoch: 1, key: 'key:spender', credential: spender.credential, expiresAt: 5000 }));
  await step(owner.createAgent({ id: 'gateway' }));   // the connector's own agent and session (SPEC §10.1 CONNECTOR refusals, §10.2 measurer)
  await step(owner.admitRuntime({ session: 'session:gateway', agent: 'gateway', epoch: 1, key: 'key:gateway', credential: SESSION_KEYS.gateway.credential, expiresAt: 5000 }));
  await step(owner.grant({ id: 'metered', to: 'spender', actions: ['spend'], resources: ['petty-cash', 'petty-cash-2', 'petty-cash-3', 'petty-cash-4'], expiresAt: 5000, maxAmount: 100n }));
  const sim = core.openLocalSimulation({ ...config, session: 'session:spender', signHash: core.signHashWith(spender) });
  const spend = (id, amount, resource = 'petty-cash') => ({ id, action: 'spend', resource, role: 'cashier', tenure: 'cashier:1', termsCommitment: core.commitTerms({ purpose: id }), amount });
  const marks = {};
  for (const [id, amount, at] of [['spend:1', 60n, null], ['spend:2', 30n, null], ['spend:3', 5n, null], ['spend:4', 55n, 1100]]) {
    if (at !== null) tick = at;
    const r = await step(sim.run(spend(id, amount)));
    if (r.invocation?.status !== 'SUBMITTED') throw new Error(`${id} failed: ${JSON.stringify(r)}`);
    marks[id] = tick;
  }
  const events = core.openHistoryStore(historyFile).state().events.map((e) => plainBig(e));
  return { events, config, historyFile, sessionKey: spender };
}

// ---------------------------------------------------------------- v2 state tracker (SPEC §7.2 records; SPEC ORACLE)
const posKey = (p) => String(p).padStart(16, '0');
function tracker() {
  const records = new Map();
  const set = (kind, key, record) => records.set(`${kind}\u0000${key}`, record);
  const get = (kind, key) => records.get(`${kind}\u0000${key}`);
  const budgets = new Map(); const usage = new Map();
  const sortedGrant = (g) => ({ ...g, constraints: { ...g.constraints, actions: [...g.constraints.actions].sort(byteSort), resources: [...g.constraints.resources].sort(byteSort), requiredIntersectionIds: [...g.constraints.requiredIntersectionIds].sort(byteSort) } });
  /** Roles the actor currently holds (CURRENT tenures) — SPEC §9.2 roleIds matching. */
  const rolesOf = (actorId) => { const held = new Set(); for (const [k, r] of records) if (k.startsWith('tenure\u0000') && r.agentId === actorId && r.status === 'CURRENT') held.add(r.roleId); return held; };
  const apply = (event, position) => {
    const d = event.data;
    switch (event.type) {
      case 'DEPLOYMENT_INITIALIZED': {
        const { ownerKeys, nextKeyDigests, ...genesis } = d;
        set('genesis', '0', genesis);
        set('ownerKeyEpoch', '0', { epoch: 0, fromPosition: 0, keys: ownerKeys, nextKeyDigests: nextKeyDigests ?? null });
        break;
      }
      case 'PRINCIPAL_CREATED': set('principal', d.principalId, { principalId: d.principalId, eventId: event.id, position }); break;
      case 'AGENT_CREATED': set('agent', d.agentId, { agentId: d.agentId, principalId: d.principalId, controllerId: d.controllerId, controlEpoch: d.initialControlEpoch, status: 'ACTIVE', eventId: event.id, position, terminatedEventId: null, terminatedPosition: null }); break;
      case 'ROLE_CREATED': set('role', d.roleId, { roleId: d.roleId, principalId: d.principalId, exclusive: d.exclusive, currentTenureId: null, eventId: event.id, position }); break;
      case 'AGENT_APPOINTED':
        set('tenure', d.roleTenureId, { roleTenureId: d.roleTenureId, roleId: d.roleId, agentId: d.agentId, tenureNumber: d.tenureNumber, status: 'CURRENT', eventId: event.id, position, endedEventId: null, endedPosition: null });
        set('role', d.roleId, { ...get('role', d.roleId), currentTenureId: d.roleTenureId }); break;
      case 'RUNTIME_SESSION_ADMITTED':
        set('session', d.sessionId, { sessionId: d.sessionId, agentId: d.agentId, controllerId: d.controllerId, controlEpoch: d.controlEpoch, credentialKeyId: d.credentialKeyId, credentialScheme: d.credentialScheme, credential: (d.credentialPublicKey ?? d.credentialAddress).toLowerCase(), expiresAt: d.expiresAt ?? null, eventId: event.id, position }); break;
      case 'AUTHORITY_GRANTED': set('authority', d.grant.authorityId, { grant: sortedGrant(d.grant), eventId: event.id, position, revoked: false, revokerId: null, revocationEventId: null, revocationPosition: null }); break;
      case 'AUTHORITY_REVOKED': set('authority', d.authorityId, { ...get('authority', d.authorityId), revoked: true, revokerId: d.revokerId, revocationEventId: event.id, revocationPosition: position }); break;
      case 'TRANSACTION_INTENT_DECLARED':
        set('intent', d.intentId, { intentId: d.intentId, status: 'DECLARED', actorId: d.actorId, action: d.action, resource: d.resource, amount: d.amount ?? null, metric: d.metric ?? 'amount',
          counterpartyId: d.counterpartyId ?? null, termsCommitment: d.termsCommitment ?? null, roleId: d.roleId, roleTenureId: d.roleTenureId, nonce: d.nonce, adapterProfile: d.adapterProfile,
          declarationEventId: event.id, declarationPosition: position, declarationDigest: d.declarationAuthorization.hash,
          admissionEventId: null, admissionPosition: null, admissionDigest: null, consumptionEventId: null, consumptionPosition: null, consumptionDigest: null,
          outcomes: [], observations: [] });
        set('nonce', L.hashCanonical([d.actorId, d.nonce]), { actorId: d.actorId, nonce: d.nonce, intentId: d.intentId, position });
        break;
      case 'TRANSACTION_INTENT_ADMITTED': {
        const intent = get('intent', d.intentId);
        set('intent', d.intentId, { ...intent, status: 'ADMITTED', admissionEventId: event.id, admissionPosition: position, admissionDigest: L.hashCanonical(d) });
        const req = d.authorizationProof.request;
        for (const authorityId of d.authorizationProof.controllingAuthorityIds) {
          const u = get('usage', authorityId) ?? { authorityId, admittedTransactionCount: 0, admittedCumulativeAmount: '0' };
          set('usage', authorityId, { authorityId, admittedTransactionCount: u.admittedTransactionCount + 1, admittedCumulativeAmount: (BigInt(u.admittedCumulativeAmount) + BigInt(req.amount ?? '0')).toString() });
        }
        L.chargeBudgets(budgets, usage, { ...req, metric: intent.metric }, d.evaluationTime, rolesOf);
        for (const r of L.usageRecordsFor(usage)) set('budgetUsage', `${r.budgetId}/${r.periodIndex}`, r);
        break;
      }
      case 'BUDGET_DECLARED': {
        const b = { ...L.effectOf(d), status: 'ACTIVE', declaredAtPosition: position, firstPeriod: L.periodIndex({ period: d.period }, Math.max(event.timestamp, d.notBefore ?? 0)) ?? 0, carryBase: null, updatedAtPosition: null, closedAtPosition: null };
        budgets.set(d.budgetId, b); set('budget', d.budgetId, b); break;
      }
      case 'BUDGET_UPDATED': {
        const old = budgets.get(d.budgetId);
        const k = L.periodIndex(old, event.timestamp);
        const carryBase = old.period.kind === 'FIXED_WINDOW' && old.period.carryUnused && k !== null ? { periodIndex: k, carryIn: L.carryIn(old, k, usage).toString() } : null;
        const b = { ...old, subjects: d.subjects, amountCap: d.amountCap, countCap: d.countCap, perOperationCap: d.perOperationCap, expiresAt: d.expiresAt, carryBase, updatedAtPosition: position };
        budgets.set(d.budgetId, b); set('budget', d.budgetId, b); break;
      }
      case 'BUDGET_CLOSED': { const b = { ...budgets.get(d.budgetId), status: 'CLOSED', closedAtPosition: position }; budgets.set(d.budgetId, b); set('budget', d.budgetId, b); break; }
      case 'STATE_CHECKPOINT': break; // only the event record below (SPEC §7.3)
      case 'COUNTERPARTY_REGISTERED': { const prev = get('counterparty', d.counterpartyId); set('counterparty', d.counterpartyId, { counterpartyId: d.counterpartyId, keys: d.keys, status: 'ACTIVE', lastReceiptDigest: prev?.lastReceiptDigest ?? null, receiptCount: prev?.receiptCount ?? 0, position }); break; }
      case 'COUNTERPARTY_RETIRED': set('counterparty', d.counterpartyId, { ...get('counterparty', d.counterpartyId), status: 'RETIRED' }); break;
      case 'REQUEST_REFUSED': set('refusal', d.refusalId, { refusalId: d.refusalId, refusalSource: d.refusalSource, decision: d.decision, code: d.code, budgetId: d.budgetId ?? null, actorId: d.request.actorId, action: d.request.action, resource: d.request.resource, amount: d.request.amount ?? null, evaluationTime: d.evaluationTime, eventId: event.id, position }); break;
      case 'EFFECT_RECORDED': set('effect', d.effectId, { effectId: d.effectId, intentId: d.intentId, measurerKind: d.measurer.kind, measurerId: d.measurer.id, metric: d.metric, unit: d.unit, amount: d.amount, observedAt: d.observedAt, eventId: event.id, position }); break;
      case 'COUNTERPARTY_RECEIPT_RECORDED': {
        const c = get('counterparty', d.envelope.counterpartyId);
        set('counterparty', c.counterpartyId, { ...c, lastReceiptDigest: L.envelopeDigest(d.envelope), receiptCount: c.receiptCount + 1 }); break;
      }
      default: throw new Error(`tracker: unsupported ${event.type}`);
    }
    // SPEC §7.2 `event` record: one per accepted event (id index, order, per-position hashes, projection subjects)
    const [actor, subject] = L.projectionFields(event);
    const eh = L.eventHash(event);
    const prev = position === 0 ? L.ZERO32 : L.unhex(get('event', posKey(position - 1)).recordHash);
    set('event', posKey(position), { position, eventId: event.id, type: event.type, timestamp: event.timestamp, eventHash: L.hex(eh), recordHash: L.hex(L.recordHash(prev, eh, position)), actorId: actor ?? null, subjectId: subject ?? null });
  };
  return { records, budgets, usage, apply, rolesOf, root: () => L.stateRoot(records) };
}
const byteSort = (a, b) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));

// ---------------------------------------------------------------- v2 history assembly
/** Sequential builder: every event is finalized (signed, hashed) against the head before it. */
class Builder {
  constructor(domain) { this.domain = domain; this.events = []; this.rows = []; this.proj = []; this.state = tracker(); this.twin = []; this.counter = 0; }
  get head() { return this.rows.length === 0 ? null : this.rows.at(-1).head; }
  id(prefix) { this.counter += 1; return `${prefix}:${this.counter}`; }
  push(event, twinIndex = null) {
    const p = this.events.length;
    const eh = L.eventHash(event);
    const prev = p === 0 ? L.ZERO32 : L.unhex(this.rows[p - 1].recordHash);
    const rh = L.recordHash(prev, eh, p);
    this.rows.push({ eventHash: L.hex(eh), recordHash: L.hex(rh), head: { hash: L.hex(rh), position: p, canonicalTime: event.timestamp } });
    const prevProj = p === 0 ? L.ZERO32 : L.unhex(this.proj[p - 1]);
    this.proj.push(L.hex(L.sha256(Buffer.concat([Buffer.from(L.V2.projectionVersion, 'utf8'), Buffer.from([0]), prevProj, L.projectionRow(event, p, eh)]))));
    this.events.push(event); this.twin.push(twinIndex);
    this.state.apply(event, p);
    return p;
  }
  async control(event, twinIndex = null, pair = OWNER) { return this.push(await L.signControl(this.domain, event, this.head, pair), twinIndex); }
  stateRootAt() { return this.state.root(); }
}

const session = { runtimeSessionId: 'session:spender', credentialKeyId: 'key:spender', controlEpoch: 1 };
const gatewaySession = { runtimeSessionId: 'session:gateway', credentialKeyId: 'key:gateway', controlEpoch: 1 };
const signSession = async (hash) => core.signHashWith(SESSION_KEYS.spender)(hash);
const signGateway = async (hash) => core.signHashWith(SESSION_KEYS.gateway)(hash);

async function transcribeAndBuild(twin) {
  const b = new Builder(DOMAIN);
  const v1 = twin.events;
  const findIndex = (type, pred = () => true) => v1.findIndex((e) => e.type === type && pred(e));
  // --- genesis
  {
    const g = clone(v1[0]);
    g.data = { ...g.data, domain: DOMAIN, versions: L.GENESIS_VERSIONS('ed25519'), policyVersion: L.V2.policyVersion, nextKeyDigests: [L.ownerKeyDigest(NEXT)] };
    b.push(g, 0);
  }
  const controlTwins = (fromIndex, toIndexExclusive) => v1.slice(fromIndex, toIndexExclusive).map((e, i) => [e, fromIndex + i]);
  const grantIndex = findIndex('AUTHORITY_GRANTED');
  for (const [e, i] of controlTwins(1, grantIndex + 1)) {
    const ev = stringsForAmounts(clone(e)); delete ev.data.controlAuthorization;
    await b.control(ev, i);
  }
  const t0 = b.head.canonicalTime;
  // --- budgets declared after the grant (SPEC §9.2)
  const budget = (budgetId, extra) => ({
    budgetId, subjects: { actorIds: ['spender'], roleIds: null, actions: ['spend'], resources: ['petty-cash'] }, metric: 'amount',
    period: { kind: 'NONE' }, amountCap: null, countCap: null, perOperationCap: null, notBefore: null, expiresAt: null, ...extra,
  });
  const declared = {};
  const declare = async (data) => { declared[data.budgetId] = data; return b.control({ id: b.id('budget'), type: 'BUDGET_DECLARED', timestamp: b.head.canonicalTime, data }); };
  await declare(budget('b-amount', { period: { kind: 'FIXED_WINDOW', lengthMs: 1000, originMs: 0, carryUnused: true, carryCap: '50' }, amountCap: '100' }));
  await declare(budget('c-count', { countCap: 2 }));
  // --- intents and admissions from the twin, with new records interleaved
  const intentIdx = (id) => findIndex('TRANSACTION_INTENT_DECLARED', (e) => e.data.intentId === id);
  const admitIdx = (id) => findIndex('TRANSACTION_INTENT_ADMITTED', (e) => e.data.intentId === id);
  const pushIntent = async (id) => {
    const i = intentIdx(id); const ev = stringsForAmounts(clone(v1[i]));
    const h = L.hashCanonical(L.declarationChallenge(DOMAIN, ev.data, b.head, session));
    ev.data = { ...ev.data, declarationAuthorization: { ...session, hash: h, signature: await signSession(h) } };
    return b.push(ev, i);
  };
  const pushAdmission = async (id) => {
    const i = admitIdx(id); const ev = stringsForAmounts(clone(v1[i]));
    const head = b.head; const proof = ev.data.authorizationProof;
    proof.proofVersion = L.V2.authorizationProofVersion; proof.domain = DOMAIN; proof.policyVersion = L.V2.policyVersion; proof.historyHead = head;
    ev.data.expectedHistoryHead = head;
    const challenge = L.runtimeChallenge(DOMAIN, proof.request, ev.data.evaluationTime, L.V2.policyVersion, head, { ...session, roleId: proof.roleId, roleTenureId: proof.roleTenureId, intentId: proof.intentId, nonce: proof.nonce });
    ev.data.runtimeAuthorizationHash = L.hashCanonical(challenge);
    ev.data.runtimeSignature = await signSession(ev.data.runtimeAuthorizationHash);
    return b.push(ev, i);
  };
  const refusals = [];
  /** A refusal evaluated at the current head: decision from the twin engine (authority) + budget oracle. */
  const pushRefusal = async (refusalId, request, evaluationTime, source) => {
    const head = b.head;
    const verdict = evaluateAt(b, twin, request, evaluationTime);
    if (verdict.decision === 'ALLOW') throw new Error(`refusal ${refusalId} would be ALLOW`);
    const data = {
      refusalId, refusalSource: source ?? (verdict.budgetId ? 'BUDGET' : 'CORE'), request, evaluationTime, expectedHistoryHead: head, decision: verdict.decision, code: verdict.code,
      ...(verdict.budgetId ? { budgetId: verdict.budgetId } : {}), ...session,
    };
    const h = L.hashCanonical(L.refusalChallenge(DOMAIN, data));
    const ev = { id: b.id('refusal'), type: 'REQUEST_REFUSED', timestamp: evaluationTime, data: { ...data, refusalAuthorization: { hash: h, signature: await signSession(h) } } };
    refusals.push({ ev, verdict });
    return b.push(ev);
  };
  await pushIntent('spend:1'); await pushAdmission('spend:1');
  await pushIntent('spend:2'); await pushAdmission('spend:2');
  const tR = b.head.canonicalTime;
  const req = (amount, resource = 'petty-cash') => ({ actorId: 'spender', action: 'spend', resource, claimedAt: tR, amount: String(amount) });
  await pushRefusal('refusal:amount', req(20), tR);           // b-amount: 90+20 > 100
  await pushRefusal('refusal:count', req(5), tR);             // c-count: 2+1 > 2
  await pushRefusal('refusal:core', req(101), tR, 'CORE');    // authority AMOUNT_EXCEEDED
  await declare(budget('d-perop', { subjects: { actorIds: null, roleIds: null, actions: ['spend'], resources: ['petty-cash-2'] }, perOperationCap: '40' }));
  await declare(budget('e-future', { subjects: { actorIds: null, roleIds: null, actions: null, resources: ['petty-cash-3'] }, period: { kind: 'FIXED_WINDOW', lengthMs: 1000, originMs: 2000, carryUnused: false, carryCap: null }, amountCap: '10' }));
  await declare(budget('f-expired', { subjects: { actorIds: null, roleIds: null, actions: null, resources: ['petty-cash-4'] }, amountCap: '1', expiresAt: 1050 }));
  await declare(budget('g-role', { subjects: { actorIds: null, roleIds: ['cashier'], actions: ['spend'], resources: ['petty-cash-4'] }, perOperationCap: '30' }));   // a role budget (SPEC §9.2): follows the role, not the agent
  await pushRefusal('refusal:perop', req(45, 'petty-cash-2'), tR);
  // connector refusal: attested, not re-derived
  {
    const data = { refusalId: 'refusal:connector', refusalSource: 'CONNECTOR', request: req(7), evaluationTime: tR, expectedHistoryHead: b.head, decision: 'DENY', code: 'CONNECTOR_REFUSED', connector: { connectorId: 'gateway', refusalCode: 'UPSTREAM_UNAVAILABLE', detailDigest: L.hashCanonical({ note: 'synthetic' }) }, ...gatewaySession };
    const h = L.hashCanonical(L.refusalChallenge(DOMAIN, data));
    b.push({ id: b.id('refusal'), type: 'REQUEST_REFUSED', timestamp: tR, data: { ...data, refusalAuthorization: { hash: h, signature: await signGateway(h) } } });   // signed by the connector's own session (SPEC §10.1)
  }
  const checkpoints = [];
  const checkpoint = async (checkpointId) => {
    const { root, count } = b.stateRootAt(); const head = b.head;
    const data = { checkpointId, head: { hash: head.hash, position: head.position }, stateRoot: root, recordCount: count, derivationVersion: L.V2.stateDerivationVersion, projectionHead: b.proj.at(-1) };
    checkpoints.push(data);
    return b.control({ id: b.id('checkpoint'), type: 'STATE_CHECKPOINT', timestamp: head.canonicalTime, data });
  };
  await checkpoint('cp:1');
  // effect for spend:1
  {
    const data = { effectId: 'effect:1', intentId: 'spend:1', measurer: { kind: 'SESSION', id: 'spender' }, metric: 'amount', unit: 'units', amount: '60', observedAt: b.head.canonicalTime, detailDigest: null, ...session };
    const h = L.hashCanonical(L.effectChallenge(DOMAIN, data, b.head));
    b.push({ id: b.id('effect'), type: 'EFFECT_RECORDED', timestamp: b.head.canonicalTime, data: { ...data, effectAuthorization: { hash: h, signature: await signSession(h) } } });
  }
  await b.control({ id: b.id('counterparty'), type: 'COUNTERPARTY_REGISTERED', timestamp: b.head.canonicalTime, data: { counterpartyId: 'acme', keys: [{ keyId: COUNTERPARTY.keyId, scheme: 'ed25519', credential: COUNTERPARTY.credential }] } });
  const envelopes = [];
  const receipt = async (intentId, amount, prev) => {
    const intent = b.events.find((e) => e.type === 'TRANSACTION_INTENT_DECLARED' && e.data.intentId === intentId);
    const body = { version: L.V2.counterpartyReceiptVersion, historyId: b.rows[0].recordHash, counterpartyId: 'acme', keyId: COUNTERPARTY.keyId, logicalId: intentId, intentDigest: intent.data.declarationAuthorization.hash, payloadDigest: L.hashCanonical({ payload: intentId }), amount, outcome: 'DELIVERED', observedAt: b.head.canonicalTime, previousReceiptDigest: prev };
    const envelope = { ...body, signature: await core.signHashWith(COUNTERPARTY)(L.hashCanonical(body)) };
    envelopes.push(envelope);
    const data = { intentId, envelope, ...session };
    const h = L.hashCanonical(L.counterpartyRecordChallenge(DOMAIN, data, b.head));
    return b.push({ id: b.id('cpr'), type: 'COUNTERPARTY_RECEIPT_RECORDED', timestamp: b.head.canonicalTime, data: { ...data, recordAuthorization: { hash: h, signature: await signSession(h) } } });
  };
  await receipt('spend:1', '60', null);
  await receipt('spend:2', '30', L.envelopeDigest(envelopes[0]));
  await b.control({ id: b.id('budget'), type: 'BUDGET_UPDATED', timestamp: b.head.canonicalTime, data: { budgetId: 'c-count', subjects: declared['c-count'].subjects, amountCap: null, countCap: 3, perOperationCap: null, expiresAt: null } });
  await pushIntent('spend:3'); await pushAdmission('spend:3');
  await b.control({ id: b.id('budget'), type: 'BUDGET_CLOSED', timestamp: b.head.canonicalTime, data: { budgetId: 'c-count' } });
  await checkpoint('cp:2');
  await pushIntent('spend:4'); await pushAdmission('spend:4');   // t = 1100, period 1 of b-amount, carry 5
  await checkpoint('cp:3');
  // cap lowering with rollover frozen (SPEC §9.5 carryBase): b-amount 100 → 60 at t = 1100 (period 1, carryIn 5 frozen)
  await b.control({ id: b.id('budget'), type: 'BUDGET_UPDATED', timestamp: b.head.canonicalTime, data: { budgetId: 'b-amount', subjects: declared['b-amount'].subjects, amountCap: '60', countCap: null, perOperationCap: null, expiresAt: null } });
  // subjects update with usage retained (SPEC §9.1): d-perop now also covers petty-cash-3
  await b.control({ id: b.id('budget'), type: 'BUDGET_UPDATED', timestamp: b.head.canonicalTime, data: { budgetId: 'd-perop', subjects: { actorIds: null, roleIds: null, actions: ['spend'], resources: ['petty-cash-2', 'petty-cash-3'] }, amountCap: null, countCap: null, perOperationCap: '40', expiresAt: null } });
  await checkpoint('cp:4');
  return { b, refusals, checkpoints, envelopes, declared };
}

/** Decision at the builder's current head: authority from the twin engine (format 1, same semantics), then budgets (oracle). */
function evaluateAt(b, twin, request, evaluationTime) {
  const maxTwin = Math.max(...b.twin.filter((x) => x !== null));
  const prefix = twin.events.slice(0, maxTwin + 1);
  const r = core.replay(core.jsonParseWithBigints(JSON.stringify(prefix)));
  if (r.status !== 'ACCEPTED') throw new Error(`twin prefix rejected: ${r.code}`);
  const req1 = { ...request }; if (req1.amount !== undefined) req1.amount = { '$continuity.bigint': req1.amount }; delete req1.metric;
  const body = core.jsonParseWithBigints(JSON.stringify({
    operationVersion: 'continuity-authorization/0.2', expectedHistoryHead: plainBig(r.head), domain: DOMAIN1, policyVersion: 'irontrellis-local-owner/1',
    rootRecognitionPolicy: L.V2.rootRecognitionPolicy, request: req1, evaluationTime, authoritative: true, consequential: false,
  }));
  const a = plainBig(core.authorizePortable({ ...body, events: core.jsonParseWithBigints(JSON.stringify(prefix)) }, core.replay));
  const base = {
    decision: a.decision, code: a.code ?? null, scopeAssurance: a.scopeAssurance ?? null,
    controllingAuthorityIds: a.proof?.controllingAuthorityIds ?? null, failureCodes: (a.failures ?? []).map((f) => f.code), budgetId: null,
  };
  if (a.decision !== 'ALLOW') return base;
  const verdict = L.evaluateBudgets(b.state.budgets, b.state.usage, request, evaluationTime, b.state.rolesOf);
  if (verdict === null) return base;
  return { decision: 'DENY', code: verdict.code, scopeAssurance: 'REPLAY_VERIFIED', controllingAuthorityIds: null, failureCodes: [verdict.code], budgetId: verdict.budgetId };
}

// ---------------------------------------------------------------- vectors
const vectors = [];
const outputs = new Map();
const add = (v) => vectors.push(v);
const replayVector = (id, topic, purpose, events, expect) => add({ id: `replay/v2/${id}`, kind: 'replay', topic, purpose, input: { operationVersion: 'continuity-replay/0.2' }, events, expect });
const accepted = (b, upto = b.events.length) => ({ status: 'ACCEPTED', head: b.rows[upto - 1].head, code: null, stateRoot: null, projectionHead: b.proj[upto - 1] });

async function main() {
  const twin = await buildTwin();
  const { b, refusals, checkpoints, envelopes, declared } = await transcribeAndBuild(twin);
  const H = b.events; const historyRef = 'budget-v2';
  outputs.set(`histories/${historyRef}.json`, `${JSON.stringify(H, null, 1)}\n`);
  outputs.set(`histories/${historyRef}.jsonl`, L.storeLines(H));
  outputs.set(`histories/${historyRef}-twin-format1.json`, `${JSON.stringify(twin.events, null, 1)}\n`);
  const finalRoot = b.stateRootAt();
  const full = { ...accepted(b), stateRoot: finalRoot.root };
  const posOf = (type, pred = () => true) => H.findIndex((e) => e.type === type && pred(e));

  // ---- replay: acceptance and prefixes
  replayVector('accepts-budget-history', 'format-2-chain', 'The complete format-2 budget history replays; the head is the record-chain tip (SPEC §4.3), the state root is the §7 derivation over the final state and the projection head the §12 chain.', H, full);
  for (const cp of checkpoints.slice(0, -1)) {   // the last checkpoint ends the history: the full-history vector covers it
    const p = posOf('STATE_CHECKPOINT', (e) => e.data.checkpointId === cp.checkpointId);
    const rootAtP = (() => { const t = tracker(); for (let i = 0; i <= p; i++) t.apply(H[i], i); return t.root().root; })();
    replayVector(`accepts-prefix-through-${cp.checkpointId.replace(':', '-')}`, 'format-2-chain', `The prefix ending with ${cp.checkpointId} replays; the result's stateRoot is rootAt(${p}), the root AFTER the checkpoint's own event record (the checkpoint's data.stateRoot is rootAt(${p - 1}), the state before it).`, H.slice(0, p + 1), { ...accepted(b, p + 1), stateRoot: rootAtP });
  }
  replayVector('accepts-genesis-only', 'format-2-chain', 'A format-2 history of one event: the head is recordHash(0) = sha256("irontrellis-record/2" ‖ 0x00 ‖ 0^32 ‖ eventHash ‖ be64(0)); the state has three records (genesis, ownerKeyEpoch 0, event 0).', H.slice(0, 1), { ...accepted(b, 1), stateRoot: (() => { const t = tracker(); t.apply(H[0], 0); return t.root().root; })() });

  // ---- replay: chain and encoding refusals
  const mutate = (fn, upto = H.length) => { const copy = clone(H.slice(0, upto)); fn(copy); return copy; };
  const rejected = (code) => ({ status: 'REJECTED', head: null, code, stateRoot: null, projectionHead: null });
  replayVector('rejects-bigint-marker-amount', 'format-2-encoding', 'A format-2 event that spells an Amount as the legacy {"$continuity.bigint"} marker is a schema violation (SPEC §3.4).', mutate((c) => { const i = c.findIndex((e) => e.type === 'TRANSACTION_INTENT_DECLARED'); c[i].data.amount = { '$continuity.bigint': c[i].data.amount }; }), rejected('EVENT_DATA_INVALID'));
  replayVector('rejects-negative-amount', 'format-2-encoding', 'Format 2 Amounts are non-negative decimal strings; "-1" is a schema violation.', mutate((c) => { const i = c.findIndex((e) => e.type === 'TRANSACTION_INTENT_DECLARED'); c[i].data.amount = '-1'; }), rejected('EVENT_DATA_INVALID'));
  replayVector('rejects-leading-zero-amount', 'format-2-encoding', 'An Amount with a leading zero ("060") is not canonical.', mutate((c) => { const i = c.findIndex((e) => e.type === 'TRANSACTION_INTENT_DECLARED'); c[i].data.amount = '0' + c[i].data.amount; }), rejected('EVENT_DATA_INVALID'));
  replayVector('rejects-format1-literals-in-format2-genesis', 'format-2-encoding', 'A genesis that declares eventSchemaVersion irontrellis-event/2 but the format-1 control-authorization literal is refused.', mutate((c) => { c[0].data.versions = { ...c[0].data.versions, controlAuthorizationVersion: 'irontrellis-control-authorization/1' }; }), rejected('UNSUPPORTED_VERSION'));
  replayVector('rejects-domain-version-1-in-format2', 'format-2-encoding', 'A format-2 genesis must declare domain.version "2".', mutate((c) => { c[0].data.domain = { ...c[0].data.domain, version: '1' }; }), rejected('EVENT_DATA_INVALID'));
  replayVector('rejects-moved-control-event', 'format-2-chain', 'A control event signed over the head before it cannot be moved: swapping two control events breaks both signatures.', mutate((c) => { const i = c.findIndex((e) => e.type === 'ROLE_CREATED'); [c[i], c[i + 1]] = [c[i + 1], c[i]]; }), rejected('CONTROL_AUTHORIZATION_INVALID'));
  replayVector('rejects-budget-declared-without-owner-signature', 'budgets', 'BUDGET_DECLARED is a control event; without controlAuthorization it is refused.', mutate((c) => { const i = c.findIndex((e) => e.type === 'BUDGET_DECLARED'); delete c[i].data.controlAuthorization; }), rejected('CONTROL_AUTHORIZATION_INVALID'));
  replayVector('rejects-budget-with-no-cap', 'budgets', 'A budget must cap at least one dimension (SPEC §9.1).', mutate((c) => { const i = c.findIndex((e) => e.type === 'BUDGET_DECLARED'); c[i].data.amountCap = null; c[i].data.countCap = null; c[i].data.perOperationCap = null; }), rejected('EVENT_DATA_INVALID'));
  replayVector('rejects-budget-window-zero-length', 'budgets', 'A FIXED_WINDOW period needs lengthMs ≥ 1.', mutate((c) => { const i = c.findIndex((e) => e.type === 'BUDGET_DECLARED'); c[i].data.period = { ...c[i].data.period, lengthMs: 0 }; }), rejected('EVENT_DATA_INVALID'));
  replayVector('rejects-duplicate-budget-id', 'budgets', 'Declaring a budgetId twice (a properly owner-signed second BUDGET_DECLARED) is TRANSITION_INVALID.', await (async () => { const i = posOf('BUDGET_DECLARED'); const c = clone(H.slice(0, i + 1)); c.push(await L.signControl(DOMAIN, { id: 'budget:dup', type: 'BUDGET_DECLARED', timestamp: c[i].timestamp, data: L.effectOf(c[i].data) }, b.rows[i].head, OWNER)); return c; })(), rejected('TRANSITION_INVALID'));
  replayVector('rejects-update-of-unknown-budget', 'budgets', 'A properly signed BUDGET_UPDATED for a budget that was never declared is TRANSITION_INVALID.', await (async () => { const i = posOf('BUDGET_UPDATED'); const c = clone(H.slice(0, i + 1)); c[i] = await L.signControl(DOMAIN, { ...c[i], data: { ...L.effectOf(c[i].data), budgetId: 'nobody' } }, b.rows[i - 1].head, OWNER); return c; })(), rejected('TRANSITION_INVALID'));
  replayVector('rejects-tampered-budget-declaration', 'budgets', 'Changing a declared cap after signing breaks the owner signature (the effect hash is signed).', mutate((c) => { const i = c.findIndex((e) => e.type === 'BUDGET_DECLARED'); c[i].data.amountCap = '1000'; }, posOf('BUDGET_DECLARED') + 1), rejected('CONTROL_AUTHORIZATION_INVALID'));
  replayVector('rejects-admission-over-budget', 'budgets', 'spend:2 re-declared and re-admitted at amount 45 (authority allows ≤ 100; b-amount has 60 used of 100): a correctly signed admission the budgets refuse is TRANSITION_INVALID, because replay re-derives the decision and finds DENY.', await (async () => { const iD = posOf('TRANSACTION_INTENT_DECLARED', (e) => e.data.intentId === 'spend:2'); const iA = posOf('TRANSACTION_INTENT_ADMITTED', (e) => e.data.intentId === 'spend:2'); const bb = new Builder(DOMAIN); for (let i = 0; i < iD; i++) { bb.events.push(H[i]); bb.rows.push(b.rows[i]); bb.proj.push(b.proj[i]); bb.state.apply(H[i], i); }
    const decl = clone(H[iD]); delete decl.data.declarationAuthorization; decl.data.amount = '45'; const hd = L.hashCanonical(L.declarationChallenge(DOMAIN, decl.data, bb.head, session)); decl.data = { ...decl.data, declarationAuthorization: { ...session, hash: hd, signature: await signSession(hd) } }; bb.push(decl);
    const adm = clone(H[iA]); const pr = adm.data.authorizationProof; pr.request.amount = '45'; pr.historyHead = bb.head; adm.data.expectedHistoryHead = bb.head; adm.data.runtimeAuthorizationHash = L.hashCanonical(L.runtimeChallenge(DOMAIN, pr.request, adm.data.evaluationTime, L.V2.policyVersion, bb.head, { ...session, roleId: pr.roleId, roleTenureId: pr.roleTenureId, intentId: pr.intentId, nonce: pr.nonce })); adm.data.runtimeSignature = await signSession(adm.data.runtimeAuthorizationHash); return [...bb.events, adm]; })(), rejected('TRANSITION_INVALID'));
  // signed intents
  replayVector('rejects-unsigned-intent-declaration', 'signed-intents', 'A format-2 TRANSACTION_INTENT_DECLARED without declarationAuthorization is a schema violation (SPEC §8.6).', mutate((c) => { const i = c.findIndex((e) => e.type === 'TRANSACTION_INTENT_DECLARED'); delete c[i].data.declarationAuthorization; }, posOf('TRANSACTION_INTENT_DECLARED') + 1), rejected('EVENT_DATA_INVALID'));
  replayVector('rejects-intent-declaration-with-wrong-signature', 'signed-intents', 'A declaration signed by a key that is not the session credential is DECLARATION_AUTHORIZATION_INVALID.', mutate((c) => { const i = c.findIndex((e) => e.type === 'TRANSACTION_INTENT_DECLARED'); c[i].data.declarationAuthorization.signature = '0x' + 'ab'.repeat(64); }, posOf('TRANSACTION_INTENT_DECLARED') + 1), rejected('DECLARATION_AUTHORIZATION_INVALID'));
  replayVector('rejects-intent-declaration-with-altered-amount', 'signed-intents', 'The declaration signature binds the amount: changing it after signing fails verification.', mutate((c) => { const i = c.findIndex((e) => e.type === 'TRANSACTION_INTENT_DECLARED'); c[i].data.amount = '61'; }, posOf('TRANSACTION_INTENT_DECLARED') + 1), rejected('DECLARATION_AUTHORIZATION_INVALID'));
  replayVector('rejects-duplicate-nonce-declaration', 'signed-intents', 'The nonce record is created at declaration (SPEC §7.2, §8.6): a correctly signed second declaration with the same (actorId, nonce) and a new intentId is TRANSITION_INVALID.', await (async () => { const iD = posOf('TRANSACTION_INTENT_DECLARED', (e) => e.data.intentId === 'spend:1'); const c = clone(H.slice(0, iD + 1)); const decl = clone(H[iD]); delete decl.data.declarationAuthorization; decl.id = 'operation:dup'; decl.data.intentId = 'spend:dup'; const hd = L.hashCanonical(L.declarationChallenge(DOMAIN, decl.data, b.rows[iD].head, session)); decl.data = { ...decl.data, declarationAuthorization: { ...session, hash: hd, signature: await signSession(hd) } }; c.push(decl); return c; })(), rejected('TRANSITION_INVALID'));
  // refusals
  const rPos = (id) => posOf('REQUEST_REFUSED', (e) => e.data.refusalId === id);
  replayVector('rejects-refusal-not-reproduced', 'refusals', 'A correctly signed BUDGET refusal whose recorded code/budgetId differ from the re-derived decision at its head is REFUSAL_NOT_REPRODUCED.', await (async () => { const i = rPos('refusal:amount'); const c = clone(H.slice(0, i + 1)); const d = { ...c[i].data }; delete d.refusalAuthorization; d.code = 'BUDGET_COUNT_EXCEEDED'; d.budgetId = 'c-count'; const h = L.hashCanonical(L.refusalChallenge(DOMAIN, d)); c[i].data = { ...d, refusalAuthorization: { hash: h, signature: await signSession(h) } }; return c; })(), rejected('REFUSAL_NOT_REPRODUCED'));
  replayVector('rejects-refusal-with-tampered-code', 'refusals', 'Changing the code after signing breaks the session signature: REFUSAL_AUTHORIZATION_INVALID (checked before re-derivation).', mutate((c) => { const i = rPos('refusal:amount'); c[i].data.code = 'BUDGET_COUNT_EXCEEDED'; c[i].data.budgetId = 'c-count'; }, rPos('refusal:amount') + 1), rejected('REFUSAL_AUTHORIZATION_INVALID'));
  replayVector('rejects-refusal-that-would-be-allowed', 'refusals', 'A refusal recorded for a request the state allows (amount 5 at that head) is REFUSAL_NOT_REPRODUCED; the signature is valid, the claim is false.', await (async () => { const c = clone(H.slice(0, rPos('refusal:amount') + 1)); const i = rPos('refusal:amount'); const d = { ...c[i].data }; delete d.refusalAuthorization; d.request = { ...d.request, amount: '5' }; const h = L.hashCanonical(L.refusalChallenge(DOMAIN, d)); c[i].data = { ...d, refusalAuthorization: { hash: h, signature: await signSession(h) } }; return c; })(), rejected('REFUSAL_NOT_REPRODUCED'));
  replayVector('rejects-refusal-with-stale-head', 'refusals', 'A refusal must cite the head immediately before it; an earlier head is TRANSITION_INVALID.', await (async () => { const i = rPos('refusal:amount'); const c = clone(H.slice(0, i + 1)); const d = { ...c[i].data }; delete d.refusalAuthorization; d.expectedHistoryHead = b.rows[i - 2].head; const h = L.hashCanonical(L.refusalChallenge(DOMAIN, d)); c[i].data = { ...d, refusalAuthorization: { hash: h, signature: await signSession(h) } }; return c; })(), rejected('TRANSITION_INVALID'));
  replayVector('rejects-connector-refusal-without-connector', 'refusals', 'refusalSource CONNECTOR requires the connector record; a BUDGET source may not carry one (closed schema, SPEC §10.1).', mutate((c) => { const i = rPos('refusal:connector'); delete c[i].data.connector; }, rPos('refusal:connector') + 1), rejected('EVENT_DATA_INVALID'));
  replayVector('rejects-refusal-signed-by-stranger', 'refusals', 'A refusal signed by a key other than the named session credential is REFUSAL_AUTHORIZATION_INVALID.', await (async () => { const i = rPos('refusal:core'); const c = clone(H.slice(0, i + 1)); c[i].data.refusalAuthorization.signature = await core.signHashWith(STRANGER)(c[i].data.refusalAuthorization.hash); return c; })(), rejected('REFUSAL_AUTHORIZATION_INVALID'));
  // checkpoints
  const cpPos = (id) => posOf('STATE_CHECKPOINT', (e) => e.data.checkpointId === id);
  replayVector('rejects-checkpoint-with-wrong-state-root', 'checkpoints', 'A STATE_CHECKPOINT whose stateRoot is not the §7 root of the state before it is STATE_ROOT_MISMATCH (owner-signed, so the signature is re-made here).', await (async () => { const i = cpPos('cp:1'); const c = clone(H.slice(0, i + 1)); const d = L.effectOf(c[i].data); d.stateRoot = '0x' + '11'.repeat(32); c[i] = await L.signControl(DOMAIN, { ...c[i], data: d }, b.rows[i - 1].head, OWNER); return c; })(), rejected('STATE_ROOT_MISMATCH'));
  replayVector('rejects-checkpoint-with-wrong-record-count', 'checkpoints', 'recordCount must equal the number of state records (leaves).', await (async () => { const i = cpPos('cp:1'); const c = clone(H.slice(0, i + 1)); const d = L.effectOf(c[i].data); d.recordCount += 1; c[i] = await L.signControl(DOMAIN, { ...c[i], data: d }, b.rows[i - 1].head, OWNER); return c; })(), rejected('STATE_ROOT_MISMATCH'));
  replayVector('rejects-checkpoint-with-wrong-projection-head', 'checkpoints', 'projectionHead must equal the §12 projection chain at the head before the checkpoint.', await (async () => { const i = cpPos('cp:1'); const c = clone(H.slice(0, i + 1)); const d = L.effectOf(c[i].data); d.projectionHead = '0x' + '22'.repeat(32); c[i] = await L.signControl(DOMAIN, { ...c[i], data: d }, b.rows[i - 1].head, OWNER); return c; })(), rejected('PROJECTION_HEAD_MISMATCH'));
  replayVector('rejects-checkpoint-citing-other-head', 'checkpoints', 'A checkpoint must cite the head immediately before it.', await (async () => { const i = cpPos('cp:1'); const c = clone(H.slice(0, i + 1)); const d = L.effectOf(c[i].data); d.head = { hash: b.rows[i - 2].head.hash, position: i - 2 }; c[i] = await L.signControl(DOMAIN, { ...c[i], data: d }, b.rows[i - 1].head, OWNER); return c; })(), rejected('TRANSITION_INVALID'));
  // effects
  replayVector('rejects-effect-for-unknown-intent', 'effects', 'EFFECT_RECORDED needs an admitted intent.', await (async () => { const i = posOf('EFFECT_RECORDED'); const c = clone(H.slice(0, i + 1)); const d = { ...c[i].data }; delete d.effectAuthorization; d.intentId = 'spend:99'; const h = L.hashCanonical(L.effectChallenge(DOMAIN, d, b.rows[i - 1].head)); c[i].data = { ...d, effectAuthorization: { hash: h, signature: await signSession(h) } }; return c; })(), rejected('TRANSITION_INVALID'));
  replayVector('rejects-effect-with-tampered-amount', 'effects', 'The effect signature binds the measured amount.', mutate((c) => { const i = posOf('EFFECT_RECORDED'); c[i].data.amount = '61'; }, posOf('EFFECT_RECORDED') + 1), rejected('EFFECT_AUTHORIZATION_INVALID'));
  // counterparty receipts
  const cprPos = (n) => H.map((e, i) => (e.type === 'COUNTERPARTY_RECEIPT_RECORDED' ? i : -1)).filter((i) => i >= 0)[n];
  replayVector('rejects-receipt-from-unregistered-counterparty', 'counterparty-receipts', 'A correctly wrapped envelope naming a counterparty that is not registered is TRANSITION_INVALID.', await (async () => { const i = cprPos(0); const c = clone(H.slice(0, i + 1)); const d = clone(c[i].data); delete d.recordAuthorization; const { signature: _s, ...body } = d.envelope; body.counterpartyId = 'nobody'; d.envelope = { ...body, signature: await core.signHashWith(COUNTERPARTY)(L.hashCanonical(body)) }; const h = L.hashCanonical(L.counterpartyRecordChallenge(DOMAIN, d, b.rows[i - 1].head)); c[i].data = { ...d, recordAuthorization: { hash: h, signature: await signSession(h) } }; return c; })(), rejected('TRANSITION_INVALID'));
  replayVector('rejects-receipt-with-bad-counterparty-signature', 'counterparty-receipts', 'An envelope whose signature does not verify under the registered key is COUNTERPARTY_SIGNATURE_INVALID.', await (async () => { const i = cprPos(0); const c = clone(H.slice(0, i + 1)); const d = clone(c[i].data); delete d.recordAuthorization; d.envelope.signature = await core.signHashWith(STRANGER)(L.envelopeSigningHash(d.envelope)); const h = L.hashCanonical(L.counterpartyRecordChallenge(DOMAIN, d, b.rows[i - 1].head)); c[i].data = { ...d, recordAuthorization: { hash: h, signature: await signSession(h) } }; return c; })(), rejected('COUNTERPARTY_SIGNATURE_INVALID'));
  replayVector('rejects-receipt-chain-break', 'counterparty-receipts', 'The second envelope must cite the digest of the first accepted envelope from the same counterparty.', await (async () => { const i = cprPos(1); const c = clone(H.slice(0, i + 1)); const d = clone(c[i].data); delete d.recordAuthorization; const { signature: _s, ...body } = d.envelope; body.previousReceiptDigest = null; d.envelope = { ...body, signature: await core.signHashWith(COUNTERPARTY)(L.hashCanonical(body)) }; const h = L.hashCanonical(L.counterpartyRecordChallenge(DOMAIN, d, b.rows[i - 1].head)); c[i].data = { ...d, recordAuthorization: { hash: h, signature: await signSession(h) } }; return c; })(), rejected('TRANSITION_INVALID'));
  replayVector('rejects-receipt-with-altered-envelope', 'counterparty-receipts', 'Altering the envelope after both signatures breaks the counterparty signature, which is checked first: COUNTERPARTY_SIGNATURE_INVALID.', mutate((c) => { const i = cprPos(0); c[i].data.envelope.outcome = 'UNKNOWN'; }, cprPos(0) + 1), rejected('COUNTERPARTY_SIGNATURE_INVALID'));
  replayVector('rejects-receipt-for-other-history', 'counterparty-receipts', 'The envelope binds the history (historyId = recordHash(0)); an envelope signed for another history is TRANSITION_INVALID even with valid signatures.', await (async () => { const i = cprPos(0); const c = clone(H.slice(0, i + 1)); const d = clone(c[i].data); delete d.recordAuthorization; const { signature: _s, ...body } = d.envelope; body.historyId = '0x' + '66'.repeat(32); d.envelope = { ...body, signature: await core.signHashWith(COUNTERPARTY)(L.hashCanonical(body)) }; const h = L.hashCanonical(L.counterpartyRecordChallenge(DOMAIN, d, b.rows[i - 1].head)); c[i].data = { ...d, recordAuthorization: { hash: h, signature: await signSession(h) } }; return c; })(), rejected('TRANSITION_INVALID'));
  replayVector('rejects-receipt-intent-digest-mismatch', 'counterparty-receipts', 'The envelope binds the intent (intentDigest = the declaration challenge hash); a digest of another intent is TRANSITION_INVALID.', await (async () => { const i = cprPos(0); const c = clone(H.slice(0, i + 1)); const d = clone(c[i].data); delete d.recordAuthorization; const { signature: _s, ...body } = d.envelope; body.intentDigest = '0x' + '77'.repeat(32); d.envelope = { ...body, signature: await core.signHashWith(COUNTERPARTY)(L.hashCanonical(body)) }; const h = L.hashCanonical(L.counterpartyRecordChallenge(DOMAIN, d, b.rows[i - 1].head)); c[i].data = { ...d, recordAuthorization: { hash: h, signature: await signSession(h) } }; return c; })(), rejected('TRANSITION_INVALID'));
  replayVector('rejects-reregistering-active-counterparty', 'counterparty-receipts', 'Registering a counterpartyId that is ACTIVE again is TRANSITION_INVALID (owner-signed, so the signature is re-made).', await (async () => { const i = posOf('COUNTERPARTY_REGISTERED'); const c = clone(H.slice(0, i + 1)); c.push(await L.signControl(DOMAIN, { id: 'counterparty:dup', type: 'COUNTERPARTY_REGISTERED', timestamp: c[i].timestamp, data: L.effectOf(c[i].data) }, b.rows[i].head, OWNER)); return c; })(), rejected('TRANSITION_INVALID'));
  replayVector('rejects-receipt-wrapper-stale', 'counterparty-receipts', 'A valid counterparty envelope whose session wrapper was signed over a different envelope digest is RECORD_AUTHORIZATION_INVALID.', await (async () => { const i = cprPos(0); const c = clone(H.slice(0, i + 1)); const d = clone(c[i].data); const { signature: _s, ...body } = d.envelope; body.outcome = 'UNKNOWN'; d.envelope = { ...body, signature: await core.signHashWith(COUNTERPARTY)(L.hashCanonical(body)) }; c[i].data = d; return c; })(), rejected('RECORD_AUTHORIZATION_INVALID'));

  // admission metric rule (SPEC §8.3), refusal binding rules (§10.1), measurer rule (§10.2), budget schema (§9.1)
  replayVector('rejects-admission-metric-mismatch', 'budgets', 'An admission whose request.metric ("bytes") differs from the declared intent\'s metric (absent = "amount") is TRANSITION_INVALID, so a session cannot choose which budgets are checked and charged.', await (async () => { const iA = posOf('TRANSACTION_INTENT_ADMITTED', (e) => e.data.intentId === 'spend:1'); const c = clone(H.slice(0, iA + 1)); const adm = c[iA]; const pr = adm.data.authorizationProof; pr.request = { ...pr.request, metric: 'bytes' }; adm.data.runtimeAuthorizationHash = L.hashCanonical(L.runtimeChallenge(DOMAIN, pr.request, adm.data.evaluationTime, L.V2.policyVersion, b.rows[iA - 1].head, { ...session, roleId: pr.roleId, roleTenureId: pr.roleTenureId, intentId: pr.intentId, nonce: pr.nonce })); adm.data.runtimeSignature = await signSession(adm.data.runtimeAuthorizationHash); return c; })(), rejected('TRANSITION_INVALID'));
  replayVector('rejects-refusal-actor-mismatch', 'refusals', 'A CORE/BUDGET refusal must be signed by a session of the actor it names (request.actorId); spender\'s session refusing on behalf of "other" is TRANSITION_INVALID.', await (async () => { const i = rPos('refusal:amount'); const c = clone(H.slice(0, i + 1)); const d = { ...c[i].data }; delete d.refusalAuthorization; d.request = { ...d.request, actorId: 'other' }; const h = L.hashCanonical(L.refusalChallenge(DOMAIN, d)); c[i].data = { ...d, refusalAuthorization: { hash: h, signature: await signSession(h) } }; return c; })(), rejected('TRANSITION_INVALID'));
  replayVector('rejects-refusal-evaluation-time-mismatch', 'refusals', 'A refusal\'s evaluationTime must equal the event timestamp (as for admissions); a later evaluation time is TRANSITION_INVALID.', await (async () => { const i = rPos('refusal:amount'); const c = clone(H.slice(0, i + 1)); const d = { ...c[i].data }; delete d.refusalAuthorization; d.evaluationTime = c[i].timestamp + 1; const h = L.hashCanonical(L.refusalChallenge(DOMAIN, d)); c[i].data = { ...d, refusalAuthorization: { hash: h, signature: await signSession(h) } }; return c; })(), rejected('TRANSITION_INVALID'));
  replayVector('rejects-connector-refusal-by-other-session', 'refusals', 'A CONNECTOR refusal must be signed by the connector\'s own session: connector.connectorId must equal the signing session\'s agent. Signed by spender\'s session it is TRANSITION_INVALID.', await (async () => { const i = rPos('refusal:connector'); const c = clone(H.slice(0, i + 1)); const d = { ...c[i].data, ...session }; delete d.refusalAuthorization; const h = L.hashCanonical(L.refusalChallenge(DOMAIN, d)); c[i].data = { ...d, refusalAuthorization: { hash: h, signature: await signSession(h) } }; return c; })(), rejected('TRANSITION_INVALID'));
  replayVector('rejects-effect-measurer-mismatch', 'effects', 'For measurer.kind SESSION, measurer.id must be the signing session\'s agent; "other" is TRANSITION_INVALID.', await (async () => { const i = posOf('EFFECT_RECORDED'); const c = clone(H.slice(0, i + 1)); const d = { ...c[i].data, measurer: { kind: 'SESSION', id: 'other' } }; delete d.effectAuthorization; const h = L.hashCanonical(L.effectChallenge(DOMAIN, d, b.rows[i - 1].head)); c[i].data = { ...d, effectAuthorization: { hash: h, signature: await signSession(h) } }; return c; })(), rejected('TRANSITION_INVALID'));
  replayVector('rejects-budget-update-without-cap', 'budgets', 'A BUDGET_UPDATED that leaves every cap null is a schema violation (SPEC §9.1).', mutate((c) => { const i = c.findIndex((e) => e.type === 'BUDGET_UPDATED'); c[i].data.countCap = null; }, posOf('BUDGET_UPDATED') + 1), rejected('EVENT_DATA_INVALID'));
  replayVector('rejects-budget-carry-without-carry-cap', 'budgets', 'carryUnused: true requires a non-null carryCap (SPEC §9.1, B-4): the rollover is then bounded.', mutate((c) => { const i = c.findIndex((e) => e.type === 'BUDGET_DECLARED'); c[i].data.period = { ...c[i].data.period, carryCap: null }; }, posOf('BUDGET_DECLARED') + 1), rejected('EVENT_DATA_INVALID'));
  replayVector('rejects-budget-with-unknown-subject-key', 'budgets', 'subjects is a closed record of actorIds, roleIds, actions, resources; an extra key is a schema violation.', mutate((c) => { const i = c.findIndex((e) => e.type === 'BUDGET_DECLARED'); c[i].data.subjects = { ...c[i].data.subjects, tenantIds: ['x'] }; }, posOf('BUDGET_DECLARED') + 1), rejected('EVENT_DATA_INVALID'));

  // ---- authorization at the final head (t = 1100; b-amount period 1, cap lowered to 60 with rollover 5 frozen → remaining 10)
  const head = b.head; const t = head.canonicalTime;
  const authVector = (id, purpose, request, evaluationTime = t) => {
    const expect = evaluateAt(b, twin, request, evaluationTime);
    add({ id: `authorization/v2/${id}`, kind: 'authorization', topic: 'budgets', purpose, history: { ref: historyRef, eventCount: H.length, head }, input: {
      operationVersion: 'continuity-authorization/0.2', expectedHistoryHead: head, domain: DOMAIN, policyVersion: L.V2.policyVersion, rootRecognitionPolicy: L.V2.rootRecognitionPolicy,
      request, evaluationTime, authoritative: true, consequential: false }, expect });
    return expect;
  };
  const rq = (amount, resource = 'petty-cash', extra = {}) => ({ actorId: 'spender', action: 'spend', resource, claimedAt: t, amount: String(amount), ...extra });
  const must = (got, decision, code) => { if (got.decision !== decision || got.code !== code) throw new Error(`unexpected ${JSON.stringify(got)} wanted ${decision}/${code}`); };
  must(authVector('allow-within-carry', 'Period 1 of b-amount after the cap was lowered 100 → 60 at t=1100: the rollover of 5 earned under the old cap is frozen (carryBase), so allowed = 60 + 5, used 55: amount 10 is allowed exactly.', rq(10)), 'ALLOW', null);
  must(authVector('deny-amount-over-carry', 'Amount 11 exceeds 60 + 5 − 55 (the frozen rollover is not re-priced by the lower cap).', rq(11)), 'DENY', 'BUDGET_AMOUNT_EXCEEDED');
  must(authVector('allow-role-budget-within', 'g-role (roleIds [cashier], actorIds null, perOperationCap 30 on petty-cash-4) matches spender through the CURRENT cashier tenure: amount 30 is allowed (f-expired no longer matches).', rq(30, 'petty-cash-4')), 'ALLOW', null);
  must(authVector('deny-role-budget-per-operation', 'Amount 35 on petty-cash-4 fails g-role, which matches by role, not by actor: BUDGET_PER_OPERATION_EXCEEDED with budgetId g-role.', rq(35, 'petty-cash-4')), 'DENY', 'BUDGET_PER_OPERATION_EXCEEDED');
  must(authVector('deny-after-subjects-update', 'd-perop\'s subjects were updated to cover petty-cash-3 (usage retained): amount 41 there fails d-perop before e-future is consulted.', rq(41, 'petty-cash-3')), 'DENY', 'BUDGET_PER_OPERATION_EXCEEDED');
  must(authVector('allow-per-operation-at-cap', 'd-perop caps a single operation on petty-cash-2 at 40.', rq(40, 'petty-cash-2')), 'ALLOW', null);
  must(authVector('deny-per-operation-over-cap', 'Amount 41 on petty-cash-2 exceeds d-perop perOperationCap 40.', rq(41, 'petty-cash-2')), 'DENY', 'BUDGET_PER_OPERATION_EXCEEDED');
  must(authVector('authority-denial-precedes-budgets', 'Amount 101 exceeds the grant maxAmount 100: the authority code wins, no budget is consulted.', rq(101)), 'DENY', 'AMOUNT_EXCEEDED');
  must(authVector('deny-period-undefined', 'e-future (origin 2000) has no period at t < 2000: BUDGET_PERIOD_UNDEFINED.', rq(1, 'petty-cash-3')), 'DENY', 'BUDGET_PERIOD_UNDEFINED');
  must(authVector('allow-when-budget-expired', 'f-expired expired at 1050; at t it no longer matches.', rq(5, 'petty-cash-4')), 'ALLOW', null);
  must(authVector('allow-after-budget-closed', 'c-count (countCap 3, closed) no longer matches; only b-amount applies.', rq(3)), 'ALLOW', null);
  must(authVector('allow-zero-amount', 'A zero amount passes every cap.', rq(0)), 'ALLOW', null);
  must(authVector('allow-other-metric-not-matched', 'A request with metric "bytes" matches no budget (all declare "amount"); authority still decides.', rq(5, 'petty-cash', { metric: 'bytes' })), 'ALLOW', null);
  must(authVector('indeterminate-causal-time', 'An evaluation time before the head is CAUSAL_TIME_INVALID regardless of budgets.', rq(1), 500), 'INDETERMINATE', 'CAUSAL_TIME_INVALID');
  // at the cp:2 head (period 0, c-count closed, usage 95/3)
  {
    const p = cpPos('cp:2'); const h2 = b.rows[p].head;
    const sub = clone(b); // evaluate on the prefix: rebuild a prefix tracker
    const bp = new Builder(DOMAIN); for (let i = 0; i <= p; i++) { bp.events.push(H[i]); bp.rows.push(b.rows[i]); bp.proj.push(b.proj[i]); bp.twin.push(b.twin[i]); bp.state.apply(H[i], i); }
    const req2 = (amount) => ({ actorId: 'spender', action: 'spend', resource: 'petty-cash', claimedAt: h2.canonicalTime, amount: String(amount) });
    const ex = (id, purpose, request) => { const expect = evaluateAt(bp, twin, request, h2.canonicalTime); add({ id: `authorization/v2/${id}`, kind: 'authorization', topic: 'budgets', purpose, history: { ref: historyRef, eventCount: p + 1, head: h2 }, input: { operationVersion: 'continuity-authorization/0.2', expectedHistoryHead: h2, domain: DOMAIN, policyVersion: L.V2.policyVersion, rootRecognitionPolicy: L.V2.rootRecognitionPolicy, request, evaluationTime: h2.canonicalTime, authoritative: true, consequential: false }, expect }); return expect; };
    must(ex('period-0-allow-last-five', 'At cp:2 (period 0) b-amount has used 95 of 100: amount 5 is allowed.', req2(5)), 'ALLOW', null);
    must(ex('period-0-deny-six', 'Amount 6 exceeds the remaining 5 of period 0.', req2(6)), 'DENY', 'BUDGET_AMOUNT_EXCEEDED');
    void sub;
  }
  // headroom
  const hr = (id, purpose, budgetId, at, eventCount = H.length) => {
    const bp = new Builder(DOMAIN); for (let i = 0; i < eventCount; i++) { bp.events.push(H[i]); bp.rows.push(b.rows[i]); bp.proj.push(b.proj[i]); bp.state.apply(H[i], i); }
    add({ id: `headroom/v2/${id}`, kind: 'headroom', topic: 'headroom', purpose, history: { ref: historyRef, eventCount, head: b.rows[eventCount - 1].head }, input: { budgetId, at }, expect: L.headroom(bp.state.budgets, bp.state.usage, budgetId, at) });
  };
  hr('b-amount-period-1', 'Headroom of b-amount at t=1100 after the cap lowering (60, carryBase {1, 5}): period 1, used 55, carryIn 5 (frozen), remaining 10.', 'b-amount', 1100);
  hr('b-amount-period-0-view', 'The same state viewed at t=500 (period 0, before the carry base): used 95, carryIn 0, remaining max(0, 60 − 95) = 0 under the current cap (a pure view).', 'b-amount', 500);
  hr('b-amount-future-period-carries-cap', 'At t=2500 (period 2): rollover from the base: unused(1) = 60 + 5 − 55 = 10 → carryIn 10, remaining 70.', 'b-amount', 2500);
  hr('b-amount-far-future-idle-stretch', 'At t=1,000,000,500 (period 1,000,000) after 999,998 idle periods: closed form min(carryCap 50, 10 + n·60) = 50 → remaining 110, computed in O(periods with usage), never O(elapsed periods).', 'b-amount', 1000000500);
  hr('b-amount-before-lowering', 'At the cp:3 head (before BUDGET_UPDATED lowered the cap): period 1, used 55, carryIn 5, remaining 50.', 'b-amount', 1100, cpPos('cp:3') + 1);
  hr('c-count-closed', 'A closed budget reports active:false with its last usage.', 'c-count', 1100);
  hr('e-future-before-origin', 'Before its origin a FIXED_WINDOW budget has periodIndex null and is not active.', 'e-future', 1100);
  hr('unknown-budget', 'An unknown budgetId yields null.', 'nobody', 1100);
  hr('c-count-before-update', 'At cp:1 (before BUDGET_UPDATED) c-count shows countCap 2 fully used.', 'c-count', 300, cpPos('cp:1') + 1);

  // ---- attestations (SPEC §7.4)
  const att = async (id, purpose, body, pair, expect) => { const signature = await core.signHashWith(pair)(L.hashCanonical(body)); add({ id: `attestation/v2/${id}`, kind: 'attestation', topic: 'attestation', purpose, history: { ref: historyRef, eventCount: H.length, head }, input: { attestation: { ...body, keyId: pair.keyId, scheme: 'ed25519', signature } }, expect }); };
  await att('valid-final-head', 'An owner attestation of the final head with the matching state root and projection head.', L.attestationBody(DOMAIN, head, finalRoot.root, b.proj.at(-1)), OWNER, { signatureValid: true, prefix: true, stateRootValid: true, projectionValid: true, valid: true });
  await att('wrong-state-root', 'A valid signature over a wrong state root: signatureValid and prefix hold, stateRootValid does not.', L.attestationBody(DOMAIN, head, '0x' + '33'.repeat(32), b.proj.at(-1)), OWNER, { signatureValid: true, prefix: true, stateRootValid: false, projectionValid: true, valid: false });
  await att('wrong-projection-head', 'A valid signature over a wrong projection head.', L.attestationBody(DOMAIN, head, finalRoot.root, '0x' + '44'.repeat(32)), OWNER, { signatureValid: true, prefix: true, stateRootValid: true, projectionValid: false, valid: false });
  await att('stranger-key', 'An attestation by a key that is not an owner key in force.', L.attestationBody(DOMAIN, head, finalRoot.root, b.proj.at(-1)), STRANGER, { signatureValid: false, prefix: true, stateRootValid: true, projectionValid: true, valid: false });
  { const p = cpPos('cp:1'); const h1 = b.rows[p].head; const cp = checkpoints[0];
    const bp = new Builder(DOMAIN); for (let i = 0; i <= p; i++) { bp.state.apply(H[i], i); }
    await att('earlier-head', 'An attestation of an earlier head (cp:1) verifies against the full history: prefix, root and projection at that position.', L.attestationBody(DOMAIN, h1, bp.state.root().root, b.proj[p]), OWNER, { signatureValid: true, prefix: true, stateRootValid: true, projectionValid: true, valid: true });
    void cp; }
  await att('head-not-a-prefix', 'A head whose hash is not the record hash at its position.', L.attestationBody(DOMAIN, { ...head, hash: '0x' + '55'.repeat(32) }, finalRoot.root, b.proj.at(-1)), OWNER, { signatureValid: true, prefix: false, stateRootValid: true, projectionValid: true, valid: false });

  await att('wrong-domain-label', 'The body names the domain; an attestation whose domain label is not this history\'s domain is reported signatureValid false (the signature may verify over the bytes, but the body is not an attestation of this history).', { ...L.attestationBody(DOMAIN, head, finalRoot.root, b.proj.at(-1)), domain: { ...DOMAIN, deploymentId: 'elsewhere' } }, OWNER, { signatureValid: false, prefix: true, stateRootValid: true, projectionValid: true, valid: false });

  // ---- export view (SPEC §15): cp:1 → cp:3, roots at both positions pinned
  {
    const rootAt = (p) => { const t = tracker(); for (let i = 0; i <= p; i++) t.apply(H[i], i); return t.root(); };
    const from = cpPos('cp:1'), to = cpPos('cp:3'); const rf = rootAt(from), rt = rootAt(to);
    add({ id: 'export/v2/cp-1-to-cp-3', kind: 'export', topic: 'export', purpose: 'The export view from the cp:1 position to the cp:3 position: both ends carry the head, the §7 root at that position (the state after the event at that position) and the projection head; the events and the checkpoints in range are listed.', history: { ref: historyRef, eventCount: H.length, head },
      input: { fromPosition: from, toPosition: to, include: { fromRecords: false, toRecords: false, inclusion: [] } },
      expect: { version: L.V2.exportVersion, domain: DOMAIN, genesisEventHash: b.rows[0].eventHash, from: { position: from, head: b.rows[from].head, stateRoot: rf.root, projectionHead: b.proj[from], recordCount: rf.count }, to: { position: to, head: b.rows[to].head, stateRoot: rt.root, projectionHead: b.proj[to], recordCount: rt.count }, eventCount: to - from + 1, checkpointIds: H.slice(from, to + 1).filter((e) => e.type === 'STATE_CHECKPOINT').map((e) => e.data.checkpointId) } });
  }

  // ---- format-1 and legacy read checks (references to the frozen suites + one inline each)
  const v1 = JSON.parse(readFileSync(join(HERE, '..', '..', '..', 'inputs-ref', 'v1-accepts-signed-handover.json'), 'utf8'));
  add({ ...v1, id: 'replay/v2/still-reads-format-1-history', topic: 'format-1-read', purpose: 'A format-1 history (copied verbatim from conformance/v1 accepts-signed-handover) still replays under IronTrellis Core; stateRoot and projectionHead are null for formats other than 2.', expect: { ...v1.expect, stateRoot: null, projectionHead: null } });
  const legacy = JSON.parse(readFileSync(join(HERE, '..', '..', '..', 'inputs-ref', 'legacy-accepts-handover.json'), 'utf8'));
  add({ ...legacy, id: 'replay/v2/still-reads-legacy-history', topic: 'legacy-read', purpose: 'A continuity-event/0.2 history (copied verbatim from conformance/legacy) still replays; stateRoot and projectionHead are null.', expect: { ...legacy.expect, code: null, stateRoot: null, projectionHead: null } });
  replayVector('rejects-format2-event-kind-in-format1-history', 'format-1-read', 'A format-1 history carrying a format-2 event kind (BUDGET_DECLARED) is UNSUPPORTED_EVENT_TYPE, as before.', [...v1.events, { id: 'x:budget', type: 'BUDGET_DECLARED', timestamp: v1.events.at(-1).timestamp, data: declared['b-amount'] }], rejected('UNSUPPORTED_EVENT_TYPE'));

  // ---- write outputs
  const byTopic = {};
  for (const v of vectors) { byTopic[v.topic] ??= {}; byTopic[v.topic][v.kind] = (byTopic[v.topic][v.kind] ?? 0) + 1; }
  const manifest = { suite: 'v2', format: L.V2.eventSchemaVersion, vectorCount: vectors.length, byTopic, histories: { [historyRef]: { eventCount: H.length, head, stateRoot: finalRoot.root, recordCount: finalRoot.count, projectionHead: b.proj.at(-1) } },
    vectors: vectors.map((v) => ({ id: v.id, kind: v.kind, topic: v.topic, purpose: v.purpose })) };
  outputs.set('vectors.json', `${JSON.stringify(vectors, null, 1)}\n`);
  outputs.set('MANIFEST.json', `${JSON.stringify(manifest, null, 1)}\n`);
  // self-check report: every signature in the history verifies; every state root recomputes; every store line parses
  const check = selfCheck(H, b, checkpoints);
  outputs.set('SELF-CHECK.json', `${JSON.stringify(check, null, 1)}\n`);
  let differs = 0;
  for (const [rel, text] of outputs) {
    const file = join(OUT, rel);
    if (CHECK) { if (!existsSync(file) || readFileSync(file, 'utf8') !== text) { differs += 1; console.error(`differs: ${rel}`); } }
    else { mkdirSync(dirname(file), { recursive: true }); writeFileSync(file, text); }
  }
  console.log(JSON.stringify({ vectors: vectors.length, byTopic, events: H.length, stateRoot: finalRoot.root, records: finalRoot.count, selfCheck: check.ok, differs }));
  if (CHECK && differs) process.exit(1);
}

function selfCheck(H, b, checkpoints) {
  const findings = [];
  const credOf = (runtimeSessionId) => (runtimeSessionId === 'session:gateway' ? SESSION_KEYS.gateway : SESSION_KEYS.spender).credential;
  const sessionCred = SESSION_KEYS.spender.credential;
  H.forEach((e, p) => {
    const prevHead = p === 0 ? null : b.rows[p - 1].head;
    if (L.CONTROL_TYPES.has(e.type)) {
      const h = L.hashCanonical(L.controlChallenge(DOMAIN, e, prevHead));
      if (!L.verifyEd25519(OWNER.credential, h, e.data.controlAuthorization.signature)) findings.push(`control signature fails at ${p}`);
    }
    if (e.type === 'TRANSACTION_INTENT_DECLARED') { const a = e.data.declarationAuthorization; const d = { ...e.data }; delete d.declarationAuthorization; if (a.hash !== L.hashCanonical(L.declarationChallenge(DOMAIN, d, prevHead, session)) || !L.verifyEd25519(sessionCred, a.hash, a.signature)) findings.push(`declaration at ${p}`); }
    if (e.type === 'TRANSACTION_INTENT_ADMITTED') { const d = e.data; const pr = d.authorizationProof; const ch = L.runtimeChallenge(DOMAIN, pr.request, d.evaluationTime, L.V2.policyVersion, prevHead, { ...session, roleId: pr.roleId, roleTenureId: pr.roleTenureId, intentId: pr.intentId, nonce: pr.nonce }); if (d.runtimeAuthorizationHash !== L.hashCanonical(ch) || !L.verifyEd25519(sessionCred, d.runtimeAuthorizationHash, d.runtimeSignature) || d.expectedHistoryHead.hash !== prevHead.hash) findings.push(`admission at ${p}`); }
    if (e.type === 'REQUEST_REFUSED') { const d = { ...e.data }; const a = d.refusalAuthorization; delete d.refusalAuthorization; if (a.hash !== L.hashCanonical(L.refusalChallenge(DOMAIN, d)) || !L.verifyEd25519(credOf(d.runtimeSessionId), a.hash, a.signature) || d.expectedHistoryHead.position !== p - 1 || d.evaluationTime !== e.timestamp) findings.push(`refusal at ${p}`); }
    if (e.type === 'EFFECT_RECORDED') { const d = { ...e.data }; const a = d.effectAuthorization; delete d.effectAuthorization; if (a.hash !== L.hashCanonical(L.effectChallenge(DOMAIN, d, prevHead)) || !L.verifyEd25519(sessionCred, a.hash, a.signature)) findings.push(`effect at ${p}`); }
    if (e.type === 'COUNTERPARTY_RECEIPT_RECORDED') { const d = { ...e.data }; const a = d.recordAuthorization; delete d.recordAuthorization; if (!L.verifyEd25519(COUNTERPARTY.credential, L.envelopeSigningHash(d.envelope), d.envelope.signature) || a.hash !== L.hashCanonical(L.counterpartyRecordChallenge(DOMAIN, d, prevHead)) || !L.verifyEd25519(sessionCred, a.hash, a.signature)) findings.push(`counterparty receipt at ${p}`); }
    if (e.type === 'STATE_CHECKPOINT') { const t = tracker(); for (let i = 0; i < p; i++) t.apply(H[i], i); const r = t.root(); if (r.root !== e.data.stateRoot || r.count !== e.data.recordCount || e.data.projectionHead !== b.proj[p - 1] || e.data.head.hash !== prevHead.hash) findings.push(`checkpoint at ${p}`); }
  });
  H.forEach((e, p) => { if (p > 0 && e.timestamp < H[p - 1].timestamp) findings.push(`time regression at ${p}`); if (!L.EVENT_TYPES.includes(e.type)) findings.push(`unknown type at ${p}`); });
  // chain recomputation from the store lines
  const lines = L.storeLines(H).split('\n').filter(Boolean).map((l) => JSON.parse(l));
  let prev = null; lines.forEach((l, p) => { if (l.previousHash !== prev || l.recordHash !== b.rows[p].recordHash) findings.push(`store line ${p}`); prev = l.recordHash; });
  const projection = L.projectionHeads(H); if (projection.at(-1).head !== b.proj.at(-1)) findings.push('projection chain');
  // the §7.2 event records re-derive the chain
  H.forEach((e, p) => { const r = b.state.records.get(`event\u0000${String(p).padStart(16, '0')}`); if (!r || r.recordHash !== b.rows[p].recordHash || r.eventHash !== b.rows[p].eventHash) findings.push(`event record ${p}`); });
  return { ok: findings.length === 0, findings, checkedEvents: H.length, checkpoints: checkpoints.length, sha256OfHistoryJsonl: createHash('sha256').update(L.storeLines(H)).digest('hex') };
}

await main();
