#!/usr/bin/env node
/**
 * ENGINE-DERIVED owner-policy vectors (G6 round 1: ADDENDA-G6 A-91/A-92, ADDENDA-G6.1 A-96/A-99/A-102; round 2: ADDENDA-G6.2
 * A-106, A-108, A-110.2–3, A-112; round 3: ADDENDA-G6.3 A-116, A-117): owner approval policies, co-signatures, policy
 * rotations, power reduction by effect and credential separation, in the format-2 suite layout of conformance/v2-regenerated.
 *
 *   pnpm --filter @ramex-labs/irontrellis build
 *   node conformance/v2-owner-policy/generate.mjs            # write
 *   node conformance/v2-owner-policy/generate.mjs --check    # exit 1 when a fresh generation differs from the files
 *
 * The expectations are this engine's own answers (packages/core/dist), projected as conformance/adapters/node.mjs
 * answers a replay; they are not acceptance. The architect's generator and the independent checker define the
 * owner-policy group; `compare-checker.mjs` diffs this engine against the checker's self-built pins. The names are the
 * rulings' (A-91.7, A-92.7, A-96.5, A-97.7, A-99.2, A-102, A-106.6, A-108.5, A-110.5, A-116.6, A-117.5); `builder-*`
 * names are this suite's own. Retired (A-108.5): `rejects-duplicate-credential`.
 * Human-attestation names live in conformance/v2-human-attestation; the three A-117.5 attester names are here.
 * Deterministic: fixed seeds (MANIFEST.json `keys`), ids and timestamps; regenerating yields byte-identical files.
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = dirname(dirname(HERE));
const CHECK = process.argv.includes('--check');
const core = await import(join(ROOT, 'packages/core/dist/index.js'));
const { signerFromKeyPair } = await import(join(ROOT, 'packages/core/dist/signer.js'));
const { replay, keyPairFromPrivateKey, controlAuthorizationHash, controlEffectHash, ownerKeyDigest, FORMAT2_VERSIONS, ADAPTER_POLICY_HASH } = core;
if (core.challengeProfile() !== 'g3') throw new Error(`this suite is generated under profile g3; this process runs ${core.challengeProfile()} (unset IRONTRELLIS_CHALLENGE_PROFILE)`);

// ================================================================ identities

const DOMAIN = Object.freeze({ protocol: 'irontrellis', version: '2', deploymentId: 'irontrellis-conformance-v2' });
const KEYS = {};
const key = (keyId, n) => {
  const seed = `0x${n.toString(16).padStart(64, '0')}`;
  const pair = keyPairFromPrivateKey('ed25519', keyId, seed);
  KEYS[keyId] = { keyId, scheme: 'ed25519', seed, credential: pair.credential };
  return pair;
};
const O1 = key('owner:1', 0x1001); // conformance/v2 TEST-KEYS
const O2 = key('owner:2', 0x5002), O3 = key('owner:3', 0x5003);
const A1 = key('agent:1', 0x5101), A2 = key('agent:2', 0x5102);
const NEXT1 = key('next:1', 0x5201), NEXT2 = key('next:2', 0x5202), NEXT3 = key('next:3', 0x5203);
const STRANGER = key('stranger:1', 0x3999); // conformance/v2 TEST-KEYS
const SESSION1 = key('session:1', 0x5301), COUNTERPARTY1 = key('counterparty:1', 0x5401);
const pub = (p) => ({ keyId: p.keyId, scheme: 'ed25519', credential: p.credential });
/** A key id bound to another key's credential (A-99: refused under a policy, today's behaviour without one). */
const alias = (keyId, p) => ({ keyId, scheme: 'ed25519', credential: p.credential });
const digest = (p) => ownerKeyDigest(p);

// ================================================================ events

const genesis = (name, keys, extra = {}) => ({
  id: `event:${name}:genesis`, type: 'DEPLOYMENT_INITIALIZED', timestamp: 100,
  data: {
    adapterPolicyHash: ADAPTER_POLICY_HASH, canonicalLineageId: `lineage:${name}`, domain: DOMAIN, finality: 'LOCAL_ONLY', globalPolicySourceId: `policy:${name}`,
    ownerKeys: keys, policyVersion: 'irontrellis-local-owner/2', rootRecognitionPolicy: 'declared-principal-root/0.2', timeSource: 'EVENT_TIMESTAMP',
    versions: { ...FORMAT2_VERSIONS, signatureScheme: 'ed25519' }, ...extra,
  },
});
const accepted = (events) => { const r = replay(events); if (r.status !== 'ACCEPTED') throw new Error(`a base history is refused: ${r.code} at ${r.position}: ${r.reason}`); return r; };
/** `event` signed at the end of `events`: the first signer's controlAuthorization, the others' co-signatures, `proofs` as nextKeyAuthorizations. */
const signed = (events, event, [first, ...rest], proofs = []) => {
  const head = accepted(events).head;
  const hash = controlAuthorizationHash({ domain: DOMAIN, eventId: event.id, eventType: event.type, timestamp: event.timestamp, previousHead: { hash: head.hash, position: head.position }, effectHash: controlEffectHash(event, 'sha256') }, 'sha256');
  const entry = (p) => ({ keyId: p.keyId, signature: signerFromKeyPair(p).signHashSync(hash) });
  return {
    ...event,
    data: {
      ...event.data, controlAuthorization: entry(first), ...(rest.length === 0 ? {} : { additionalControlAuthorizations: rest.map(entry) }),
      ...(proofs.length === 0 ? {} : { nextKeyAuthorizations: proofs.map((p) => ({ keyId: p.keyId, scheme: 'ed25519', signature: entry(p).signature })) }),
    },
  };
};
let serial = 0;
const at = (events) => events.at(-1).timestamp + 1;
const principal = (events) => ({ id: `event:principal:${++serial}`, type: 'PRINCIPAL_CREATED', timestamp: at(events), data: { principalId: 'operations' } });
/** Round 2 (G6.2) histories: one principal each, outside the round-1 `serial` so the round-1 vectors and the pinned history keep their bytes. */
const principalG62 = (events) => ({ id: 'event:principal:g62', type: 'PRINCIPAL_CREATED', timestamp: at(events), data: { principalId: 'operations' } });
const agent = (events, id) => ({ id: `event:agent:${id}`, type: 'AGENT_CREATED', timestamp: at(events), data: { agentId: id, principalId: 'operations', controllerId: 'operator', initialControlEpoch: 1 } });
const role = (events, id) => ({ id: `event:role:${id}`, type: 'ROLE_CREATED', timestamp: at(events), data: { roleId: id, principalId: 'operations', exclusive: true } });
const rotation = (events, id, data) => ({ id: `event:rotation:${id}`, type: 'OWNER_KEYS_ROTATED', timestamp: at(events), data });
/** A control event of `type` with fixed `data`, timed after the history so far. */
const ev = (type, id, data) => (events) => ({ id: `event:${id}`, type, timestamp: at(events), data });
/** A STATE_CHECKPOINT of the head of `events` (SPEC §7.3). */
const checkpoint = (events) => {
  const r = accepted(events);
  return { id: `event:checkpoint:${events.length}`, type: 'STATE_CHECKPOINT', timestamp: at(events), data: { checkpointId: `checkpoint:${events.length}`, derivationVersion: 'irontrellis-state/2', head: { hash: r.head.hash, position: r.head.position }, projectionHead: r.projectionHead, recordCount: r.state.stateRecords.size, stateRoot: r.stateRoot } };
};
/** A session of agent `bea` whose credential is `p`'s public key. */
const session = (id, p) => ev('RUNTIME_SESSION_ADMITTED', `session:${id}`, { agentId: 'bea', controlEpoch: 1, controllerId: 'operator', credentialKeyId: `key:${id}`, credentialPublicKey: p.credential, credentialScheme: 'ed25519', expiresAt: 900, sessionId: `session:${id}` });
const counterparty = (id, p) => ev('COUNTERPARTY_REGISTERED', `counterparty:${id}`, { counterpartyId: id, keys: [{ credential: p.credential, keyId: `${id}:1`, scheme: 'ed25519' }] });
/** `events` plus one signed event (the next event is built from the history so far). */
const then = (events, make, signers, proofs) => [...events, signed(events, make(events), signers, proofs)];

// ================================================================ vectors

const vectors = [];
const histories = {};
const TOPICS = ['policy-schema-and-validity', 'quorum', 'power-reduction', 'policy-rotations', 'recovery', 'credentials', 'migration'];
const projected = (events) => {
  const r = replay(events);
  return r.status === 'ACCEPTED'
    ? { expect: { status: 'ACCEPTED', head: r.head, code: null, stateRoot: r.stateRoot, projectionHead: r.projectionHead }, rejection: undefined }
    : { expect: { status: 'REJECTED', head: null, code: r.code, stateRoot: null, projectionHead: null }, rejection: { code: r.code, position: r.position } };
};
/** A replay vector; `expected` (`ACCEPTED` or `CODE@position`) is asserted against the engine so a drift fails the generation. */
const vector = (name, topic, purpose, events, expected, history) => {
  const { expect, rejection } = projected(events);
  const got = expect.status === 'ACCEPTED' ? 'ACCEPTED' : `${rejection.code}@${rejection.position}`;
  if (got !== expected) throw new Error(`${name}: expected ${expected}, the engine answers ${got}${rejection === undefined ? '' : ` (${replay(events).reason})`}`);
  vectors.push({
    id: `replay/v2op/${name}`, kind: 'replay', topic, purpose, input: { operationVersion: 'continuity-replay/0.2' },
    ...(history === undefined ? { events } : { history: { ref: history, eventCount: events.length } }), expect, ...(rejection === undefined ? {} : { rejection }),
  });
};
const at0 = (name, purpose, keys, policy, expected = 'EVENT_DATA_INVALID@0', extra = {}) =>
  vector(name, 'policy-schema-and-validity', purpose, [genesis(name, keys, { ...extra, ownerPolicy: policy })], expected);

// ---- A-91.7: schema and validity (EVENT_DATA_INVALID at the genesis)
const K3 = [pub(O1), pub(O2), pub(O3)];
{
  const g = genesis('policy-2of3', K3, { ownerPolicy: { threshold: 2 } });
  vector('accepts-genesis-policy-2of3', 'policy-schema-and-validity', 'A-91: a genesis with three owner keys and {threshold: 2}; the principal is signed by owner:1 with owner:2 co-signing.', then([g], principal, [O1, O2]), 'ACCEPTED');
}
{
  const g = genesis('bytype', K3, { ownerPolicy: { threshold: 1, byType: { AGENT_CREATED: 2 } } });
  const h = then([g], principal, [O1]);
  vector('accepts-bytype-raised-threshold', 'policy-schema-and-validity', 'A-91: byType raises AGENT_CREATED to 2 while the principal needs 1.', then(h, (e) => agent(e, 'bea'), [O1, O2]), 'ACCEPTED');
  vector('accepts-unlisted-type-uses-default', 'policy-schema-and-validity', 'A-92.1: a type byType does not name (ROLE_CREATED) uses threshold 1.', then(h, (e) => role(e, 'reviewer'), [O2]), 'ACCEPTED');
}
{
  const g = genesis('labels', [pub(O1)], { ownerPolicy: { threshold: 1, labels: { 'owner:1': 'operations laptop' }, acknowledged: 'SINGLE_SIGNER' } });
  vector('accepts-labels-and-acknowledged', 'policy-schema-and-validity', 'A-91.1: labels and acknowledged are replay-ignored annotations; the root changes only through the data.', then([g], principal, [O1]), 'ACCEPTED');
}
at0('rejects-threshold-above-n', 'A-91.2 rule 1: threshold 4 with three distinct owner credentials.', K3, { threshold: 4 });
at0('rejects-zero-threshold', 'A-91.1 / A-102 X-9: threshold 0 is outside 1..64 (C4).', K3, { threshold: 0 });
at0('rejects-unknown-bytype-key', 'A-91.2 rule 3: a byType key that names no type.', K3, { threshold: 1, byType: { NOT_A_TYPE: 1 } });
at0('builder-rejects-bytype-session-type', 'A-91.2 rule 3: a byType key that names a session (◇) type.', K3, { threshold: 1, byType: { TRANSACTION_INTENT_DECLARED: 1 } });
at0('rejects-bytype-rotation-below-default', 'A-91.2 rule 4: byType.OWNER_KEYS_ROTATED below threshold.', K3, { threshold: 2, byType: { OWNER_KEYS_ROTATED: 1 } });
at0('rejects-keyclass-unknown-key', 'A-91.2 rule 5: keyClasses names a key id outside ownerKeys.', K3, { threshold: 1, keyClasses: { 'agent:9': 'AGENT' } });
at0('rejects-all-agent-owners', 'A-91.2 rule 6: every owner key is AGENT.', [pub(A1)], { threshold: 1, keyClasses: { 'agent:1': 'AGENT' } });
at0('rejects-human-lockout', 'A-91.2 rule 6: one human and one agent at threshold 2: humans alone could never change the policy.', [pub(O1), pub(A1)], { threshold: 2, keyClasses: { 'agent:1': 'AGENT' } });
at0('rejects-acknowledged-with-threshold-2', 'A-91.2 rule 7: acknowledged SINGLE_SIGNER with threshold 2.', K3, { threshold: 2, acknowledged: 'SINGLE_SIGNER' });
at0('rejects-acknowledged-with-bytype', 'A-102 (X-19) rule 7: acknowledged SINGLE_SIGNER with a byType raise.', K3, { threshold: 1, acknowledged: 'SINGLE_SIGNER', byType: { AUTHORITY_GRANTED: 3 } });
at0('builder-rejects-empty-labels', 'A-91.1: an empty map is refused (C4).', K3, { threshold: 1, labels: {} });
at0('builder-rejects-null-in-policy', 'A-91.1: a null anywhere in ownerPolicy is refused (C4).', K3, { threshold: 1, byType: { ROLE_CREATED: null } });
at0('builder-rejects-label-65-characters', 'A-91.1: a label of 65 characters (A-89.2 measure).', K3, { threshold: 1, labels: { 'owner:1': 'x'.repeat(65) } });
at0('rejects-bytype-power-reducing-above-non-agent', 'A-91.2 rule 10 (A-106.3): byType.AGENT_TERMINATED 3 with two non-AGENT credentials: reducing power would need an agent key.', [pub(O1), pub(O2), pub(A1)], { threshold: 1, byType: { AGENT_TERMINATED: 3 }, keyClasses: { 'agent:1': 'AGENT' } });
at0('rejects-bytype-below-threshold-for-non-reducing-type', 'A-91.2 rule 11 (A-106.2): byType.BUDGET_CLOSED 1 under threshold 2; closing a budget removes a stop rule, so it is never lowered.', K3, { threshold: 2, byType: { BUDGET_CLOSED: 1 } });
{
  const g = genesis('checkpoint-low', K3, { ownerPolicy: { threshold: 2, byType: { STATE_CHECKPOINT: 1 } } });
  vector('accepts-bytype-below-threshold-for-checkpoint', 'policy-schema-and-validity', 'A-91.2 rule 11 (A-106.2): STATE_CHECKPOINT may be lowered to 1 under threshold 2; a checkpoint signed by owner:1 alone.',
    then(then([g], principalG62, [O1, O2]), checkpoint, [O1]), 'ACCEPTED');
}
{
  const g = genesis('tampered', [pub(O1), pub(O2)]);
  const h = then([g], principal, [O1]);
  const good = signed(h, rotation(h, 'tampered', { ownerKeys: [pub(O1), pub(O2)], nextKeyDigests: [digest(NEXT1)], ownerPolicy: { threshold: 2 } }), [O1]);
  const tampered = { ...good, data: { ...good.data, ownerPolicy: { threshold: 1 } } };
  vector('rejects-tampered-policy', 'policy-schema-and-validity', 'A-92.0: ownerPolicy is bound by effectHash: changed after signing, the control signature fails before any policy check.', [...h, tampered], 'CONTROL_AUTHORIZATION_INVALID@2');
}

// ---- A-92.7: the quorum (CONTROL_AUTHORIZATION_INVALID)
{
  const g = genesis('quorum', K3, { nextKeyDigests: [digest(NEXT1)], ownerPolicy: { threshold: 2 } });
  const h = then([g], principal, [O1, O2]);
  vector('accepts-rotation-with-quorum', 'quorum', 'A-92.2: a pre-rotated key rotation (owner:3 replaced by the committed next:1) signed 2-of-3 under the epoch-0 policy, setting the new epoch\'s policy.',
    then(h, (e) => rotation(e, 'quorum', { ownerKeys: [pub(O1), pub(O2), pub(NEXT1)], nextKeyDigests: [digest(NEXT2)], ownerPolicy: { threshold: 2 } }), [O1, O3], [NEXT1]), 'ACCEPTED');
  vector('accepts-surplus-authorizations', 'quorum', 'A-92.2 step 3: three signatures where two are needed; the surplus verifies and is permitted.', then([g], principal, [O1, O2, O3]), 'ACCEPTED');
  vector('rejects-duplicate-keyid', 'quorum', 'A-92.2 step 4: owner:1 signs twice.', then([g], principal, [O1, O1]), 'CONTROL_AUTHORIZATION_INVALID@1');
  vector('rejects-out-of-epoch-signer', 'quorum', 'A-92.2 step 3: a co-signature by a key that is not an owner key in force.', then(h, (e) => agent(e, 'bea'), [O1, STRANGER]), 'CONTROL_AUTHORIZATION_INVALID@2');
  const bad = signed([g], principal([g]), [O1, O2, O3]);
  bad.data.additionalControlAuthorizations[1].signature = signed([g], principal([g]), [O1, O3]).data.additionalControlAuthorizations[0].signature.replace(/.$/, (c) => (c === '0' ? '1' : '0'));
  vector('rejects-unverifiable-surplus-entry', 'quorum', 'A-92.2 step 3: a surplus co-signature that does not verify is refused even though two valid signatures remain.', [g, bad], 'CONTROL_AUTHORIZATION_INVALID@1');
  vector('rejects-missing-array-under-m2', 'quorum', 'A-92.2 step 2: M_eff = 2 and no additionalControlAuthorizations.', then([g], principal, [O1]), 'CONTROL_AUTHORIZATION_INVALID@1');
  const moved = signed(h, role(h, 'moved'), [O1, O2]);
  const between = then(h, (e) => agent(e, 'bea'), [O1, O2]);
  vector('rejects-moved-multikey-event', 'quorum', 'A-92.0: a 2-of-3 event signed for position 2 placed at position 3: the /2 challenge binds the head before it.', [...between, { ...moved, timestamp: between.at(-1).timestamp }], 'CONTROL_AUTHORIZATION_INVALID@3');
}
{
  const g = genesis('below', K3, { ownerPolicy: { threshold: 3 } });
  vector('rejects-below-threshold', 'quorum', 'A-92.2 step 5: two signatures where three are needed.', then([g], principal, [O1, O2]), 'CONTROL_AUTHORIZATION_INVALID@1');
}
{
  const g = genesis('m1', [pub(O1), pub(O2)]);
  vector('rejects-extra-authorizations-under-m1', 'quorum', 'A-92.2 step 2: a co-signature under the default policy (M_eff = 1) is refused, not ignored.', then([g], principal, [O1, O2]), 'CONTROL_AUTHORIZATION_INVALID@1');
}
{
  const g = genesis('agents', [pub(O1), pub(O2), pub(A1)], { ownerPolicy: { threshold: 2, keyClasses: { 'agent:1': 'AGENT' } } });
  const h = then([g], principal, [O1, A1]);
  vector('accepts-agent-cosigner', 'quorum', 'A-92.1: an AGENT key counts as a co-signer on an ordinary control event (2-of-3 with owner:1).', then(h, (e) => agent(e, 'bea'), [O2, A1]), 'ACCEPTED');
  vector('rejects-agent-counted-on-rotation', 'quorum', 'A-92.1: on OWNER_KEYS_ROTATED the counting set excludes agents: owner:1 plus agent:1 is one counting signature of two.',
    then(h, (e) => rotation(e, 'agent', { ownerKeys: [pub(O1), pub(O2), pub(A1)], nextKeyDigests: [digest(NEXT1)], ownerPolicy: { threshold: 2, keyClasses: { 'agent:1': 'AGENT' } } }), [O1, A1]), 'CONTROL_AUTHORIZATION_INVALID@2');
}
{
  const g = genesis('agent-alone', [pub(O1), pub(A1)], { ownerPolicy: { threshold: 1, keyClasses: { 'agent:1': 'AGENT' } } });
  vector('rejects-agent-alone-m1', 'quorum', 'A-92.2 step 6: at M_eff = 1 an AGENT key alone is refused.', then([g], principal, [A1]), 'CONTROL_AUTHORIZATION_INVALID@1');
  const g2 = genesis('agents-alone', [pub(O1), pub(O2), pub(A1), pub(A2)], { ownerPolicy: { threshold: 2, keyClasses: { 'agent:1': 'AGENT', 'agent:2': 'AGENT' } } });
  const h = then(then([g2], principal, [O1, O2]), (e) => agent(e, 'bea'), [O1, A1]);
  vector('rejects-agent-alone-m2', 'quorum', 'A-92.2 step 6: at M_eff = 2 two AGENT keys reach the count but no human signs.', then(h, (e) => agent(e, 'cal'), [A1, A2]), 'CONTROL_AUTHORIZATION_INVALID@3');
}

// ---- A-106.6: power reduction by effect (all DECLARED, threshold 2, the named type at 1 in byType, one human signing alone)
const BUDGET = { budgetId: 'b-pay', subjects: { actorIds: null, roleIds: null, actions: ['pay'], resources: null }, metric: 'amount', period: { kind: 'NONE' }, amountCap: '1000', countCap: 10, perOperationCap: null, notBefore: null, expiresAt: 5000 };
const budgetUpdate = (changes) => ({ budgetId: BUDGET.budgetId, subjects: BUDGET.subjects, amountCap: BUDGET.amountCap, countCap: BUDGET.countCap, perOperationCap: BUDGET.perOperationCap, expiresAt: BUDGET.expiresAt, ...changes });
{
  const g = genesis('pr-budget', K3, { ownerPolicy: { threshold: 2, byType: { BUDGET_UPDATED: 1 } } });
  const h = then(then([g], principalG62, [O1, O2]), ev('BUDGET_DECLARED', 'budget:pay', BUDGET), [O1, O2]);
  const update = (id, changes) => ev('BUDGET_UPDATED', `budget:${id}`, budgetUpdate(changes));
  vector('accepts-budget-update-lowering-cap-at-pr-threshold', 'power-reduction', 'A-106.2: a BUDGET_UPDATED that lowers amountCap and widens subjects to null reduces power: M_eff = byType 1, owner:1 alone.',
    then(h, update('lower', { amountCap: '500', subjects: { actorIds: null, roleIds: null, actions: null, resources: null } }), [O1]), 'ACCEPTED');
  vector('rejects-budget-update-raising-cap-at-pr-threshold', 'power-reduction', 'A-106.2: raising amountCap alone is not PR_eff: M_eff = threshold 2 and additionalControlAuthorizations is absent (A-92.2 step 2).',
    then(h, update('raise', { amountCap: '2000' }), [O1]), 'CONTROL_AUTHORIZATION_INVALID@3');
  vector('rejects-budget-update-narrowing-subjects-at-pr-threshold', 'power-reduction', 'A-106.2: narrowing subjects (actorIds null to [bea]) frees every other actor from the stop rule: M_eff = 2.',
    then(h, update('narrow', { subjects: { ...BUDGET.subjects, actorIds: ['bea'] } }), [O1]), 'CONTROL_AUTHORIZATION_INVALID@3');
  vector('rejects-budget-update-earlier-expiry-at-pr-threshold', 'power-reduction', 'A-106.2: moving expiresAt earlier (5000 to 4000) ends the stop rule sooner: M_eff = 2.',
    then(h, update('expire', { expiresAt: 4000 }), [O1]), 'CONTROL_AUTHORIZATION_INVALID@3');
}
{
  const g = genesis('pr-authority', K3, { ownerPolicy: { threshold: 2, byType: { AUTHORITY_REVOKED: 1 } } });
  let h = then(then([g], principalG62, [O1, O2]), (e) => agent(e, 'bea'), [O1, O2]);
  h = then(h, ev('AUTHORITY_GRANTED', 'grant:root', { grant: { authorityId: 'root', constraints: { actions: ['pay'], maxDelegationDepth: 1, quantitative: false, requiredIntersectionIds: [], resources: ['ledger'] }, granteeId: 'bea', grantorId: 'operations', independent: true, kind: 'PERMISSION', rootAuthorityId: 'root' } }), [O1, O2]);
  h = then(h, ev('AUTHORITY_GRANTED', 'grant:freeze-ban', { grant: { authorityId: 'freeze-ban', constraints: { actions: ['freeze'], maxDelegationDepth: 0, quantitative: false, requiredIntersectionIds: [], resources: ['ledger'] }, grantorId: 'policy:pr-authority', kind: 'PROHIBITION', scope: 'GLOBAL' } }), [O1, O2]);
  vector('accepts-permission-revocation-at-pr-threshold', 'power-reduction', 'A-106.2: revoking an unrevoked PERMISSION reduces power: M_eff = byType 1, owner:1 alone.',
    then(h, ev('AUTHORITY_REVOKED', 'revoke:root', { authorityId: 'root', revokerId: 'operations' }), [O1]), 'ACCEPTED');
  vector('rejects-prohibition-revocation-at-pr-threshold', 'power-reduction', 'A-106.2: revoking a GLOBAL PROHIBITION widens power and is never PR_eff: M_eff = 2.',
    then(h, ev('AUTHORITY_REVOKED', 'revoke:freeze-ban', { authorityId: 'freeze-ban', revokerId: 'policy:pr-authority' }), [O1]), 'CONTROL_AUTHORIZATION_INVALID@5');
}
{
  const g = genesis('pr-unappoint', K3, { ownerPolicy: { threshold: 2, byType: { AGENT_UNAPPOINTED: 1 } } });
  let h = then(then(then([g], principalG62, [O1, O2]), (e) => agent(e, 'bea'), [O1, O2]), (e) => role(e, 'treasury'), [O1, O2]);
  h = then(h, ev('AGENT_APPOINTED', 'appoint:bea', { agentId: 'bea', principalId: 'operations', roleId: 'treasury', roleTenureId: 'treasury:1', tenureNumber: 1 }), [O1, O2]);
  const unappoint = ev('AGENT_UNAPPOINTED', 'unappoint:bea', { agentId: 'bea', principalId: 'operations', roleId: 'treasury', roleTenureId: 'treasury:1' });
  vector('accepts-unappoint-without-role-budget-at-pr-threshold', 'power-reduction', 'A-106.2: ending a tenure no active budget selects by role reduces power: M_eff = byType 1, owner:1 alone.', then(h, unappoint, [O1]), 'ACCEPTED');
  const budgeted = then(h, ev('BUDGET_DECLARED', 'budget:treasury', { ...BUDGET, budgetId: 'b-treasury', subjects: { actorIds: null, roleIds: ['treasury'], actions: null, resources: null } }), [O1, O2]);
  vector('rejects-unappoint-with-role-budget-at-pr-threshold', 'power-reduction', 'A-106.2: an active budget selects the role, so the unappointment releases the agent from it: M_eff = 2.', then(budgeted, unappoint, [O1]), 'CONTROL_AUTHORIZATION_INVALID@6');
}

// ---- A-96.5: policy rotations (HF1 §7.2 as read for format 2)
{
  const committed = genesis('policy-rotation', [pub(O1), pub(O2)], { nextKeyDigests: [digest(NEXT1)], ownerPolicy: { threshold: 2 } });
  const h = then([committed], principal, [O1, O2]);
  const policyRotation = (id, data) => (e) => rotation(e, id, { ownerKeys: [pub(O1), pub(O2)], ...data });
  const first = then(h, policyRotation('first', { nextKeyDigests: [digest(NEXT1)], ownerPolicy: { threshold: 1 } }), [O1, O2]);
  vector('accepts-policy-rotation-same-keys', 'policy-rotations', 'A-96.2 (i), re-specified: out of a committed epoch, same keys, a new policy, the commitment carried unchanged and no nextKeyAuthorizations.', first, 'ACCEPTED');
  vector('accepts-second-policy-rotation', 'policy-rotations', 'A-96: a second policy rotation in the same committed lineage, authorized by the first one\'s policy (M_rot = 1).',
    then(first, policyRotation('second', { nextKeyDigests: [digest(NEXT1)], ownerPolicy: { threshold: 2, labels: { 'owner:2': 'phone' } } }), [O2]), 'ACCEPTED');
  vector('rejects-policy-rotation-dropping-commitment', 'policy-rotations', 'A-96.2 (i) rule 5: a policy rotation out of a committed epoch without nextKeyDigests.', then(h, policyRotation('drop', { ownerPolicy: { threshold: 1 } }), [O1, O2]), 'TRANSITION_INVALID@2');
  vector('rejects-policy-rotation-replacing-commitment', 'policy-rotations', 'A-96.2 (i) rule 5: a policy rotation that commits to another next key.', then(h, policyRotation('replace', { nextKeyDigests: [digest(NEXT2)], ownerPolicy: { threshold: 1 } }), [O1, O2]), 'TRANSITION_INVALID@2');
  vector('rejects-same-keys-same-policy', 'policy-rotations', 'A-96.1: same keys, the same policy as written and the same commitment: the rotation changes nothing.', then(h, policyRotation('same', { nextKeyDigests: [digest(NEXT1)], ownerPolicy: { threshold: 2 } }), [O1, O2]), 'TRANSITION_INVALID@2');
  vector('rejects-policy-rotation-with-next-key-authorizations', 'policy-rotations', 'A-96.2 (i): a policy rotation reveals no key, so a nextKeyAuthorizations array is refused.',
    then(h, policyRotation('proof', { nextKeyDigests: [digest(NEXT1)], ownerPolicy: { threshold: 1 } }), [O1, O2], [NEXT1]), 'TRANSITION_INVALID@2');
  vector('builder-accepts-rotation-resetting-policy', 'policy-rotations', 'A-91.0 / A-96.4: replay is literal: a rotation without ownerPolicy sets the default policy (the writer refuses it as POLICY_RESET unless asked).',
    then(h, policyRotation('reset', { nextKeyDigests: [digest(NEXT1)] }), [O1, O2]), 'ACCEPTED');
}
{
  const uncommitted = genesis('policy-commitment', [pub(O1), pub(O2)], { ownerPolicy: { threshold: 2 } });
  const h = then([uncommitted], principal, [O1, O2]);
  vector('accepts-policy-rotation-adding-commitment', 'policy-rotations', 'A-96.2 (ii): out of an uncommitted epoch a policy rotation may start a commitment.',
    then(h, (e) => rotation(e, 'commit', { ownerKeys: [pub(O1), pub(O2)], nextKeyDigests: [digest(NEXT1)], ownerPolicy: { threshold: 1 } }), [O1, O2]), 'ACCEPTED');
  vector('builder-accepts-policy-rotation-without-commitment', 'policy-rotations', 'A-96.2 (ii): out of an uncommitted epoch a policy rotation needs no commitment.',
    then(h, (e) => rotation(e, 'plain', { ownerKeys: [pub(O1), pub(O2)], ownerPolicy: { threshold: 1 } }), [O1, O2]), 'ACCEPTED');
}
{
  const g = genesis('recovery', [pub(O1)], { nextKeyDigests: [digest(NEXT1)], ownerPolicy: { threshold: 1 } });
  const h = then([g], principal, [O1]);
  vector('rejects-recovery-without-option', 'policy-rotations', 'A-97.7 / HF1 §7.1 item 1: without `recovery` a committed next key is not an admissible signer of the rotation that reveals it.',
    then(h, (e) => rotation(e, 'recovery', { ownerKeys: [pub(NEXT1)], nextKeyDigests: [digest(NEXT2)], ownerPolicy: { threshold: 1 } }), [NEXT1], [NEXT1]), 'CONTROL_AUTHORIZATION_INVALID@2');
}

{
  // A-108.2: HF1 §7.2 rule 4 per revealed key under G(e, p); the same history without ownerPolicy anywhere is HF1 literal.
  const partial = (extra) => {
    const g = genesis('partial-proofs', [pub(O1)], { nextKeyDigests: [digest(NEXT1), digest(NEXT2)], ...extra });
    return then(then([g], principalG62, [O1]), (e) => rotation(e, 'partial', { ownerKeys: [pub(NEXT1), pub(NEXT2)], nextKeyDigests: [digest(NEXT3)], ...extra }), [O1], [NEXT1]);
  };
  vector('rejects-partial-next-key-proofs-under-policy', 'policy-rotations', 'A-108.2: two committed keys revealed, one proof, under a policy: every revealed key must prove possession.', partial({ ownerPolicy: { threshold: 1 } }), 'TRANSITION_INVALID@2');
  vector('accepts-partial-next-key-proofs-without-policy', 'policy-rotations', 'A-108.1: the same rotation with no ownerPolicy anywhere: HF1 rule 4 as written (one proof suffices).', partial({}), 'ACCEPTED');
}

// ---- A-99.2 / A-92.7 / A-110.5: credentials
at0('rejects-duplicate-credential-in-owner-keys', 'A-99: under a policy owner credentials are pairwise distinct (owner:1b carries owner:1\'s credential).', [pub(O1), alias('owner:1b', O1), pub(O2)], { threshold: 1 });
serial += 1; // the retired `rejects-duplicate-credential` (A-108.5) built a principal here: the later ids keep their bytes
{
  const g = genesis('duplicate-rotation', [pub(O1), pub(O2)], { ownerPolicy: { threshold: 1 } });
  const h = then([g], principal, [O1]);
  vector('rejects-duplicate-credential-on-rotation', 'credentials', 'A-99: a rotation carrying ownerPolicy with one credential under two key ids: EVENT_DATA_INVALID after control authorization and the key test.',
    then(h, (e) => rotation(e, 'alias', { ownerKeys: [pub(O1), pub(O2), alias('owner:2b', O2)], ownerPolicy: { threshold: 1 } }), [O1]), 'EVENT_DATA_INVALID@2');
  const plain = genesis('duplicate-plain', [pub(O1), alias('owner:1b', O1)]);
  vector('accepts-duplicate-credential-without-policy', 'credentials', 'A-99.1: without ownerPolicy anywhere, two key ids on one credential stay valid (today\'s behaviour).', then([plain], principal, [{ ...O1, keyId: 'owner:1b' }]), 'ACCEPTED');
}

{
  // A-110.2: no commitment to a session or counterparty credential under G(e, p); no session or counterparty on an owner or committed credential under a policy.
  const P1 = { ownerPolicy: { threshold: 1 } }, K2 = [pub(O1), pub(O2)];
  const withSession = then(then(then([genesis('foreign-session', K2, P1)], principalG62, [O1]), (e) => agent(e, 'bea'), [O1]), session('s1', SESSION1), [O1]);
  vector('rejects-commitment-to-session-credential', 'credentials', 'A-110.2: a commitment-only rotation naming the digest of an admitted session credential.',
    then(withSession, (e) => rotation(e, 'commit-session', { ownerKeys: K2, nextKeyDigests: [digest(SESSION1)], ...P1 }), [O1]), 'TRANSITION_INVALID@4');
  const withCounterparty = then(then([genesis('foreign-counterparty', K2, P1)], principalG62, [O1]), counterparty('acme', COUNTERPARTY1), [O1]);
  vector('rejects-commitment-to-counterparty-credential', 'credentials', 'A-110.2: a commitment-only rotation naming the digest of a registered counterparty key.',
    then(withCounterparty, (e) => rotation(e, 'commit-counterparty', { ownerKeys: K2, nextKeyDigests: [digest(COUNTERPARTY1)], ...P1 }), [O1]), 'TRANSITION_INVALID@3');
  const committed = (extra) => then(then([genesis('committed-session', K2, { nextKeyDigests: [digest(SESSION1)], ...extra })], principalG62, [O1]), (e) => agent(e, 'bea'), [O1]);
  vector('rejects-session-admission-of-committed-credential', 'credentials', 'A-110.2: while the epoch carries a policy, a session whose credential is a committed next key.', then(committed(P1), session('s1', SESSION1), [O1]), 'TRANSITION_INVALID@3');
  vector('accepts-session-admission-of-committed-credential-without-policy', 'credentials', 'A-110.2 guard: the same admission with no ownerPolicy anywhere is accepted (A-32.3 lists it outside replay).', then(committed({}), session('s1', SESSION1), [O1]), 'ACCEPTED');
  const owned = then(then([genesis('owner-session', K2, P1)], principalG62, [O1]), (e) => agent(e, 'bea'), [O1]);
  vector('rejects-session-admission-of-owner-credential-under-policy', 'credentials', 'A-110.2: under a policy, a session whose credential is owner:2\'s.', then(owned, session('s2', O2), [O1]), 'TRANSITION_INVALID@3');
  const committedCounterparty = then([genesis('committed-counterparty', K2, { nextKeyDigests: [digest(COUNTERPARTY1)], ...P1 })], principalG62, [O1]);
  vector('rejects-counterparty-registration-of-committed-credential', 'credentials', 'A-110.2: while the epoch carries a policy, a counterparty key that is a committed next key.', then(committedCounterparty, counterparty('acme', COUNTERPARTY1), [O1]), 'TRANSITION_INVALID@2');
  // A-110.3: a revealed key may not carry a session credential under G(e, p) (out of an uncommitted epoch every new key is revealed).
  const revealing = then(then(then([genesis('revealed-session', [pub(O1)], P1)], principalG62, [O1]), (e) => agent(e, 'bea'), [O1]), session('s1', SESSION1), [O1]);
  vector('rejects-revealed-key-equal-to-session-credential', 'credentials', 'A-110.3: a rotation revealing a key whose credential is an admitted session credential: EVENT_DATA_INVALID at the key test.',
    then(revealing, (e) => rotation(e, 'reveal-session', { ownerKeys: [pub(O1), alias('owner:s', SESSION1)], ...P1 }), [O1]), 'EVENT_DATA_INVALID@4');
}

// ---- G6.3 (ADDENDA-G6.3): A-116.6 PR_eff narrowed, A-117.5 credential separation. Own ids (`principalG63`) so every earlier vector keeps its bytes.
const principalG63 = (events) => ({ id: 'event:principal:g63', type: 'PRINCIPAL_CREATED', timestamp: at(events), data: { principalId: 'operations' } });
const SESSION2 = key('session:2', 0x5302);
{
  // A-116.1 BUDGET_UPDATED: a budget that rolls over is never PR_eff (X-1: an update before its first period accrues carry over periods it never had).
  const g = genesis('pr-rollover', K3, { ownerPolicy: { threshold: 2, byType: { BUDGET_UPDATED: 1 } } });
  const rolling = { ...BUDGET, budgetId: 'b-roll', period: { kind: 'FIXED_WINDOW', lengthMs: 100, originMs: 0, carryUnused: true, carryCap: '300' }, notBefore: 1000, expiresAt: null };
  const h = then(then([g], principalG63, [O1, O2]), ev('BUDGET_DECLARED', 'budget:roll', rolling), [O1, O2]);
  vector('rejects-budget-update-of-rollover-budget-at-pr-threshold', 'power-reduction', 'A-116.1: a FIXED_WINDOW carryUnused budget restated unchanged before its first period is not PR_eff: M_eff = threshold 2, the array is absent (A-92.2 step 2).',
    then(h, ev('BUDGET_UPDATED', 'budget:roll:update', { budgetId: 'b-roll', subjects: rolling.subjects, amountCap: rolling.amountCap, countCap: rolling.countCap, perOperationCap: rolling.perOperationCap, expiresAt: null }), [O1]), 'CONTROL_AUTHORIZATION_INVALID@3');
}
{
  // A-116.1 BUDGET_DECLARED: always PR_eff; a zero amountCap over a role, one human at byType 1.
  const g = genesis('pr-declare', K3, { ownerPolicy: { threshold: 2, byType: { BUDGET_DECLARED: 1 } } });
  let h = then(then(then([g], principalG63, [O1, O2]), (e) => agent(e, 'bea'), [O1, O2]), (e) => role(e, 'treasury'), [O1, O2]);
  h = then(h, ev('AGENT_APPOINTED', 'appoint:bea', { agentId: 'bea', principalId: 'operations', roleId: 'treasury', roleTenureId: 'treasury:1', tenureNumber: 1 }), [O1, O2]);
  vector('accepts-budget-declared-at-pr-threshold', 'power-reduction', 'A-116.1: declaring a budget (a zero amountCap over the treasury role) is always PR_eff: M_eff = byType 1, owner:1 alone.',
    then(h, ev('BUDGET_DECLARED', 'budget:zero', { ...BUDGET, budgetId: 'b-zero', subjects: { actorIds: null, roleIds: ['treasury'], actions: null, resources: null }, amountCap: '0', countCap: null, expiresAt: null }), [O1]), 'ACCEPTED');
}
{
  // A-116.1 AUTHORITY_REVOKED and AGENT_TERMINATED: a live prohibition delegated under the permission, or granted by the agent, keeps the ordinary quorum.
  const grant = (authorityId, extra) => ({ authorityId, constraints: { actions: ['pay'], maxDelegationDepth: 2, quantitative: false, requiredIntersectionIds: [], resources: ['vendor'] }, independent: true, kind: 'PERMISSION', rootAuthorityId: 'root', ...extra });
  const forest = (name, extra = {}) => {
    const g = genesis(name, K3, { ownerPolicy: { threshold: 2, byType: { AUTHORITY_REVOKED: 1, AGENT_TERMINATED: 1 } } });
    let h = then([g], principalG63, [O1, O2]);
    for (const id of ['bea', 'cal', 'dan']) h = then(h, (e) => agent(e, id), [O1, O2]);
    h = then(h, ev('AUTHORITY_GRANTED', 'grant:root', { grant: grant('root', { granteeId: 'bea', grantorId: 'operations', constraints: { ...grant('root').constraints, maxDelegationDepth: 3 } }) }), [O1, O2]);
    h = then(h, ev('AUTHORITY_GRANTED', 'grant:cal', { grant: grant('g-cal', { granteeId: 'cal', grantorId: 'bea', parentAuthorityId: 'root' }) }), [O1, O2]);
    h = then(h, ev('AUTHORITY_GRANTED', 'grant:stop', { grant: { authorityId: 'g-stop', constraints: { ...grant('x').constraints, maxDelegationDepth: 0 }, grantorId: 'cal', kind: 'PROHIBITION', parentAuthorityId: 'g-cal', rootAuthorityId: 'root', scope: 'ROOT', subjectActorId: 'dan', ...extra } }), [O1, O2]);
    return h;
  };
  const h = forest('pr-dependent');
  vector('rejects-permission-revocation-with-dependent-prohibition-at-pr-threshold', 'power-reduction', 'A-116.1 (X-2): the PROHIBITION g-stop is delegated under g-cal, so revoking g-cal is not PR_eff: M_eff = 2, the array is absent.',
    then(h, ev('AUTHORITY_REVOKED', 'revoke:cal', { authorityId: 'g-cal', revokerId: 'operations' }), [O1]), 'CONTROL_AUTHORIZATION_INVALID@8');
  let t = then(h, (e) => role(e, 'desk'), [O1, O2]);
  t = then(t, ev('AGENT_APPOINTED', 'appoint:cal', { agentId: 'cal', principalId: 'operations', roleId: 'desk', roleTenureId: 'desk:1', tenureNumber: 1 }), [O1, O2]);
  t = then(t, ev('SUCCESSION_RULE_DECLARED', 'rule:cal', { permittedEventTypes: ['AGENT_TERMINATED'], predecessorAgentId: 'cal', principalId: 'operations', roleId: 'desk', ruleId: 'rule:cal', successorAgentId: 'dan', trigger: 'AGENT_TERMINATED' }), [O1, O2]);
  vector('rejects-termination-of-prohibition-grantor-at-pr-threshold', 'power-reduction', 'A-116.1 (ASM-2): cal granted the live PROHIBITION g-stop, so terminating cal is not PR_eff: M_eff = 2, the array is absent.',
    then(t, ev('AGENT_TERMINATED', 'terminate:cal', { agentId: 'cal', principalId: 'operations', roleId: 'desk', roleTenureId: 'desk:1', successionRuleId: 'rule:cal' }), [O1]), 'CONTROL_AUTHORIZATION_INVALID@11');
  // A-127.2 (G6.4): bea granted no prohibition, but bea is the grantee of root and the grantor of g-cal, both in anc(g-stop):
  // terminating bea would end g-stop with its anchor path, so it is not PR_eff (it was under G6.3).
  let b = then(forest('pr-ancestor'), (e) => role(e, 'desk'), [O1, O2]);
  b = then(b, ev('AGENT_APPOINTED', 'appoint:bea', { agentId: 'bea', principalId: 'operations', roleId: 'desk', roleTenureId: 'desk:1', tenureNumber: 1 }), [O1, O2]);
  b = then(b, ev('SUCCESSION_RULE_DECLARED', 'rule:bea', { permittedEventTypes: ['AGENT_TERMINATED'], predecessorAgentId: 'bea', principalId: 'operations', roleId: 'desk', ruleId: 'rule:bea', successorAgentId: 'dan', trigger: 'AGENT_TERMINATED' }), [O1, O2]);
  vector('rejects-termination-of-prohibition-ancestor-at-pr-threshold', 'power-reduction', 'A-127.2: bea is on the anchor path of the live PROHIBITION g-stop (grantee of root, grantor of g-cal), so terminating bea is not PR_eff: M_eff = 2, the array is absent.',
    then(b, ev('AGENT_TERMINATED', 'terminate:bea', { agentId: 'bea', principalId: 'operations', roleId: 'desk', roleTenureId: 'desk:1', successionRuleId: 'rule:bea' }), [O1]), 'CONTROL_AUTHORIZATION_INVALID@11');
}
{
  // A-116.1 AGENT_UNAPPOINTED: only a budget that can still match the agent through the role blocks.
  const g = genesis('pr-unappoint-g63', K3, { ownerPolicy: { threshold: 2, byType: { AGENT_UNAPPOINTED: 1 } } });
  let h = then(then(then([g], principalG63, [O1, O2]), (e) => agent(e, 'bea'), [O1, O2]), (e) => role(e, 'treasury'), [O1, O2]);
  h = then(h, ev('AGENT_APPOINTED', 'appoint:bea', { agentId: 'bea', principalId: 'operations', roleId: 'treasury', roleTenureId: 'treasury:1', tenureNumber: 1 }), [O1, O2]);
  const unappoint = ev('AGENT_UNAPPOINTED', 'unappoint:bea', { agentId: 'bea', principalId: 'operations', roleId: 'treasury', roleTenureId: 'treasury:1' });
  const roleBudget = (id, extra) => ev('BUDGET_DECLARED', `budget:${id}`, { ...BUDGET, budgetId: `b-${id}`, subjects: { actorIds: null, roleIds: ['treasury'], actions: null, resources: null }, ...extra });
  const expired = then(h, (e) => roleBudget('expired', { expiresAt: at(e) })(e), [O1, O2]);
  vector('accepts-unappoint-with-expired-role-budget-at-pr-threshold', 'power-reduction', 'A-116.1: the role budget expired (expiresAt <= t), so it can never match again: PR_eff, owner:1 alone.', then(expired, unappoint, [O1]), 'ACCEPTED');
  const other = then(h, roleBudget('other', { subjects: { actorIds: ['cal'], roleIds: ['treasury'], actions: null, resources: null } }), [O1, O2]);
  vector('accepts-unappoint-with-role-budget-naming-other-actor-at-pr-threshold', 'power-reduction', 'A-116.1: the role budget names actor cal only, so it never matches bea: PR_eff, owner:1 alone.', then(other, unappoint, [O1]), 'ACCEPTED');
}
at0('rejects-bytype-below-threshold-for-anchor', 'A-116.2 rule 11: ANCHOR_RECORDED left LOW_types; byType.ANCHOR_RECORDED 1 under threshold 2.', K3, { threshold: 2, byType: { ANCHOR_RECORDED: 1 } });
{
  const g = genesis('declare-low', K3, { ownerPolicy: { threshold: 2, byType: { BUDGET_DECLARED: 1 } } });
  vector('accepts-bytype-below-threshold-for-budget-declared', 'policy-schema-and-validity', 'A-116.2 rule 11: BUDGET_DECLARED is one of the seven PR_types and may be lowered to 1 under threshold 2.', then([g], principalG63, [O1, O2]), 'ACCEPTED');
}
{
  // A-117.2: under a policy every owner key is foreign-free; a policy-free history that admitted owner:2's credential as a session credential cannot adopt one (R3F-1).
  const K2 = [pub(O1), pub(O2)];
  const h = then(then(then([genesis('adopt-session-owner', K2)], principalG63, [O1]), (e) => agent(e, 'bea'), [O1]), session('s-owner', O2), [O1]);
  vector('rejects-policy-adoption-with-session-owner-credential', 'credentials', 'A-117.2 (R3F-1): owner:2\'s credential is a session credential; the rotation adopting a policy keeps owner:2: EVENT_DATA_INVALID at the key test.',
    then(h, (e) => rotation(e, 'adopt', { ownerKeys: K2, ownerPolicy: { threshold: 1 } }), [O1]), 'EVENT_DATA_INVALID@4');
  // A-117.3 (X-3): a policy-free commitment to a key that later became a session credential is carried by the adopting rotation (not re-tested) and is dead under the policy.
  const committed = then(then(then([genesis('adopt-carry', [pub(O1)], { nextKeyDigests: [digest(SESSION2)] })], principalG63, [O1]), (e) => agent(e, 'bea'), [O1]), session('s-committed', SESSION2), [O1]);
  const adopted = then(committed, (e) => rotation(e, 'adopt-carry', { ownerKeys: [pub(O1)], nextKeyDigests: [digest(SESSION2)], ownerPolicy: { threshold: 1 } }), [O1]);
  vector('accepts-policy-adoption-carrying-foreign-commitment', 'credentials', 'A-117.3 (X-3): the adopting policy rotation restates the carried commitment to session:2\'s credential; a carried digest is not re-tested.', adopted, 'ACCEPTED');
  vector('rejects-reveal-of-foreign-committed-key-under-policy', 'credentials', 'A-117.2: revealing the carried commitment (session:2\'s credential as owner key rt:1) under the policy: EVENT_DATA_INVALID at the key test.',
    then(adopted, (e) => rotation(e, 'reveal-carry', { ownerKeys: [alias('rt:1', SESSION2)], nextKeyDigests: [digest(NEXT2)], ownerPolicy: { threshold: 1 } }), [O1], [{ ...SESSION2, keyId: 'rt:1' }]), 'EVENT_DATA_INVALID@5');
}

// ---- A-117.4 / A-117.3: attesters are never foreign, never committed, never admitted as sessions (group 3 of the lifted holds)
{
  const AT1 = key('attester:1', 0x5501), AT2 = key('attester:2', 0x5502), SESSION3 = key('session:3', 0x5303);
  const sign = (body) => ({ ...body, signature: signerFromKeyPair(AT1).signHashSync(core.humanAttestationHash({ ...body, signature: '' })) });
  const statement = (p) => sign({ version: 'irontrellis-human-attestation/1', audience: DOMAIN, subject: pub(p), profile: 'phl:ceremony/1', attesterKeyId: 'attester:1', evidenceDigest: `0x${'ab'.repeat(32)}`, notBefore: 0, expiresAt: 5000 });
  const K2 = [pub(O1), pub(O2)];
  const ATTESTED = { threshold: 1, humanFloor: 'ATTESTED', attesters: [pub(AT1), pub(AT2)], attestations: [statement(O1), statement(O2)] };
  const h = then([genesis('attester-in-force', K2, { ownerPolicy: ATTESTED })], principalG63, [O1]);
  vector('rejects-commitment-to-attester-in-force', 'credentials', 'A-117.3 (ce34): one rotation drops the attesters and commits to attester:1: an introduced digest names an attester in force.',
    then(h, (e) => rotation(e, 'commit-attester', { ownerKeys: K2, nextKeyDigests: [digest(AT1)], ownerPolicy: { threshold: 1 } }), [O1]), 'TRANSITION_INVALID@2');
  vector('rejects-session-admission-of-attester-credential-under-policy', 'credentials', 'A-117.4 (X-11): under a policy a session may not use an attester credential of that policy (row 8).',
    then(then(h, (e) => agent(e, 'bea'), [O1]), session('s-attester', AT1), [O1]), 'TRANSITION_INVALID@3');
  const withSession = then(then(then([genesis('attester-session', K2)], principalG63, [O1]), (e) => agent(e, 'bea'), [O1]), session('s3', SESSION3), [O1]);
  vector('rejects-policy-with-attester-equal-to-session-credential', 'credentials', 'A-117.4: a policy naming an admitted session credential as an attester: EVENT_DATA_INVALID at the rotation.',
    then(withSession, (e) => rotation(e, 'attester-session', { ownerKeys: K2, ownerPolicy: { threshold: 1, attesters: [pub(SESSION3), pub(AT2)] } }), [O1]), 'EVENT_DATA_INVALID@4');
}

// ---- A-97.7 / A-108.5 / A-110: recovery through committed next keys (`recovery: "COMMITTED_NEXT_KEYS"`), group 2 of the lifted holds
{
  const R1 = { threshold: 1, recovery: 'COMMITTED_NEXT_KEYS' };
  const single = then([genesis('recovery-single', [pub(O1)], { nextKeyDigests: [digest(NEXT1), digest(NEXT2)], ownerPolicy: R1 })], principalG63, [O1]);
  vector('accepts-recovery-rotation-next-key-only', 'recovery', 'A-97.2: under recovery a committed next key signs the rotation that reveals it (M_rot = 1), with its proof of possession; owner:1 is lost.',
    then(single, (e) => rotation(e, 'recover', { ownerKeys: [pub(NEXT1)], nextKeyDigests: [digest(NEXT3)], ownerPolicy: R1 }), [NEXT1], [NEXT1]), 'ACCEPTED');
  vector('rejects-recovery-unrevealed-next-key', 'recovery', 'A-110.1: next:2 is committed but the rotation does not reveal it, so it is not admissible: A-92.2 step 1.',
    then(single, (e) => rotation(e, 'unrevealed', { ownerKeys: [pub(NEXT1)], nextKeyDigests: [digest(NEXT3)], ownerPolicy: R1 }), [NEXT2], [NEXT1]), 'CONTROL_AUTHORIZATION_INVALID@2');
  vector('rejects-recovery-uncommitted-key', 'recovery', 'A-97.2: a revealed key whose digest is not committed is not admissible; refused at step 1, before HF1 rule 2.',
    then(single, (e) => rotation(e, 'uncommitted', { ownerKeys: [pub(NEXT3)], nextKeyDigests: [digest(NEXT2)], ownerPolicy: R1 }), [NEXT3], [NEXT3]), 'CONTROL_AUTHORIZATION_INVALID@2');
  vector('builder-rejects-recovery-without-proof', 'recovery', 'A-108.2: the recovery signer is a revealed key and must still prove possession (the epoch carries a policy).',
    then(single, (e) => rotation(e, 'no-proof', { ownerKeys: [pub(NEXT1)], nextKeyDigests: [digest(NEXT3)], ownerPolicy: R1 }), [NEXT1]), 'TRANSITION_INVALID@2');
  const R2 = { threshold: 2, recovery: 'COMMITTED_NEXT_KEYS' };
  const pair = then([genesis('recovery-pair', [pub(O1), pub(O2)], { nextKeyDigests: [digest(NEXT1)], ownerPolicy: R2 })], principalG63, [O1, O2]);
  vector('accepts-recovery-rotation-mixed-quorum', 'recovery', 'A-97.4: M_rot = 2 reached by one current key (owner:1) and one revealed committed key (next:1); owner:2 is replaced.',
    then(pair, (e) => rotation(e, 'mixed', { ownerKeys: [pub(O1), pub(NEXT1)], nextKeyDigests: [digest(NEXT2)], ownerPolicy: R2 }), [O1, NEXT1], [NEXT1]), 'ACCEPTED');
  const twice = { ...NEXT1, keyId: 'next:1b' };
  vector('rejects-duplicate-credential-on-recovery', 'recovery', 'A-108.5: one committed credential revealed under two key ids, both signing: A-92.2 step 4.',
    then(pair, (e) => rotation(e, 'twice', { ownerKeys: [pub(NEXT1), alias('next:1b', NEXT1)], nextKeyDigests: [digest(NEXT2)], ownerPolicy: R2 }), [NEXT1, twice], [NEXT1, twice]), 'CONTROL_AUTHORIZATION_INVALID@2');
  const RA = { threshold: 2, keyClasses: { 'agent:1': 'AGENT' }, recovery: 'COMMITTED_NEXT_KEYS' };
  const agents = then([genesis('recovery-agent', [pub(O1), pub(O2), pub(A1)], { nextKeyDigests: [digest(NEXT1)], ownerPolicy: RA })], principalG63, [O1, O2]);
  vector('rejects-recovery-agent-counted', 'recovery', 'A-97.4: M_rot = 2 with one revealed key and one AGENT key: agents never count on a rotation.',
    then(agents, (e) => rotation(e, 'agent', { ownerKeys: [pub(NEXT1), pub(O2), pub(A1)], nextKeyDigests: [digest(NEXT2)], ownerPolicy: RA }), [NEXT1, A1], [NEXT1]), 'CONTROL_AUTHORIZATION_INVALID@2');
}

// ---- A-91.5: the migrated prefix (builder-pinned in A-91.7)
{
  const migrated = JSON.parse(readFileSync(join(ROOT, 'conformance/v2-regenerated/histories/migrated-legacy-v2.json'), 'utf8'));
  const g = { ...migrated[0], data: { ...migrated[0].data, ownerPolicy: { threshold: 1 } } };
  vector('rejects-policy-in-migrated-genesis', 'migration', 'A-91.2 rule 9: a migrated genesis carries no ownerPolicy.', [g], 'EVENT_DATA_INVALID@0');
  const inside = migrated.findIndex((e, q) => q > 0 && core.CONTROL_EVENT_TYPES.has(e.type));
  const events = migrated.slice(0, inside + 1);
  events[inside] = { ...events[inside], data: { ...events[inside].data, additionalControlAuthorizations: [{ keyId: 'owner:1', signature: `0x${'11'.repeat(64)}` }] } };
  vector('rejects-additional-authorizations-in-prefix', 'migration', 'A-91.5: additionalControlAuthorizations inside a migrated prefix: EVENT_DATA_INVALID at C4, coded against migratedFrom.', events, `EVENT_DATA_INVALID@${inside}`);
}


// ---- the pinned root (A-91.7 `accepts-policy-history`): ownerKeyEpoch.policy at epoch 0, 1 and 2
{
  const K = [pub(O1), pub(O2), pub(O3), pub(A1)];
  const g = genesis('policy-history', K, { nextKeyDigests: [digest(NEXT1)], ownerPolicy: { threshold: 2, keyClasses: { 'agent:1': 'AGENT' }, labels: { 'owner:1': 'operations laptop' } } });
  let h = then([g], principal, [O1, O2]);
  h = then(h, (e) => agent(e, 'bea'), [O2, A1]);                                                                 // an agent co-signer counts here
  h = then(h, (e) => rotation(e, 'policy', { ownerKeys: K, nextKeyDigests: [digest(NEXT1)], ownerPolicy: { threshold: 2, byType: { ROLE_CREATED: 3 }, keyClasses: { 'agent:1': 'AGENT' } } }), [O1, O3, A1]); // policy rotation; the agent does not count
  h = then(h, (e) => role(e, 'reviewer'), [O1, O2, O3]);
  h = then(h, (e) => rotation(e, 'keys', { ownerKeys: [pub(O1), pub(O2), pub(NEXT1), pub(A1)], nextKeyDigests: [digest(NEXT3)], ownerPolicy: { threshold: 2, keyClasses: { 'agent:1': 'AGENT' } } }), [O1, O2], [NEXT1]);
  h = then(h, (e) => agent(e, 'cal'), [NEXT1, A1]);
  histories['policy-history'] = h;
  vector('accepts-policy-history', 'policy-rotations', 'A-91.7 pinned root: the owner key epoch records carry `policy` at epoch 0 (genesis), 1 (a policy rotation out of the committed epoch) and 2 (a pre-rotated key rotation); agent co-signers count on ordinary events and never on rotations.', h, 'ACCEPTED', 'policy-history');
}

// ================================================================ outputs

vectors.sort((a, b) => TOPICS.indexOf(a.topic) - TOPICS.indexOf(b.topic));
const ids = new Set();
for (const v of vectors) { if (ids.has(v.id)) throw new Error(`duplicate vector id ${v.id}`); ids.add(v.id); }
const sha256 = (text) => createHash('sha256').update(text).digest('hex');
const outputs = new Map();
for (const [name, events] of Object.entries(histories)) outputs.set(`histories/${name}.json`, `${JSON.stringify(events, null, 1)}\n`);
outputs.set('vectors.json', `${JSON.stringify(vectors, null, 1)}\n`);
const summary = (events) => { const r = accepted(events); return { eventCount: events.length, head: r.head, stateRoot: r.stateRoot, recordCount: r.state.stateRecords.size, projectionHead: r.projectionHead }; };
const manifest = {
  schemaVersion: 'irontrellis-conformance/2', suite: 'v2-owner-policy', protocol: 'irontrellis', format: 'irontrellis-event/2', challengeProfile: 'g3', engineDerived: true,
  generatedFrom: { reference: '@ramex-labs/irontrellis (packages/core)', replay: core.REPLAY_VERSION, rulings: ['ADDENDA-G6 A-91, A-92', 'ADDENDA-G6.1 A-96, A-99, A-102 (round 1)', 'ADDENDA-G6.2 A-106, A-108, A-110.2–3, A-112 (round 2)', 'ADDENDA-G6.3 A-116, A-117 (round 3)', 'ADDENDA-G6.1 A-97 with ADDENDA-G6.2 A-110 (recovery, holds lifted 2026-10-12)', 'ADDENDA-G6.4 A-127.2 (AGENT_TERMINATED anchor path)'], retired: ['rejects-duplicate-credential (A-108.5)', 'builder-rejects-recovery-held and builder-rejects-human-floor-held (holds lifted 2026-10-12)'] },
  note: 'ENGINE-DERIVED owner-policy vectors (G6 rounds 1 to 3). Not acceptance: the architect\'s generator and the independent checker define the owner-policy group. Every G6.x hold was lifted on 2026-10-12 (founder); the human-attestation group is conformance/v2-human-attestation. `node conformance/v2-owner-policy/generate.mjs --check` reproduces these files byte for byte.',
  domain: DOMAIN,
  keys: KEYS,
  topics: TOPICS,
  histories: Object.fromEntries(Object.entries(histories).map(([name, events]) => [name, { ...summary(events), sha256: sha256(outputs.get(`histories/${name}.json`)) }])),
  pinnedPositions: Object.fromEntries(Object.entries(histories).map(([name, events]) => [name, events.map((_e, p) => p)])),
  counts: { replay: vectors.length, total: vectors.length, byTopic: Object.fromEntries(TOPICS.map((t) => [t, vectors.filter((v) => v.topic === t).length])) },
  vectors: vectors.map((v) => ({ id: v.id, kind: v.kind, topic: v.topic, purpose: v.purpose, sha256: sha256(JSON.stringify(v)) })),
};
outputs.set('MANIFEST.json', `${JSON.stringify(manifest, null, 1)}\n`);

const HISTORIES = join(HERE, 'histories');
const produced = new Set([...outputs.keys()].filter((path) => path.startsWith('histories/')).map((path) => path.slice('histories/'.length)));
const stale = existsSync(HISTORIES) ? readdirSync(HISTORIES).filter((file) => !produced.has(file)) : [];
if (CHECK) {
  const differ = [...outputs].filter(([path, text]) => { const file = join(HERE, path); return !existsSync(file) || readFileSync(file, 'utf8') !== text; }).map(([path]) => `conformance/v2-owner-policy/${path}`);
  differ.push(...stale.map((file) => `conformance/v2-owner-policy/histories/${file} (not generated)`));
  if (differ.length > 0) { console.error(`a fresh generation differs:\n  ${differ.join('\n  ')}`); process.exit(1); }
  console.log(`conformance/v2-owner-policy is up to date (${vectors.length} vectors over ${Object.keys(histories).length} histories)`);
} else {
  mkdirSync(HISTORIES, { recursive: true });
  for (const file of stale) rmSync(join(HISTORIES, file));
  for (const [path, text] of outputs) writeFileSync(join(HERE, path), text);
  console.log(`wrote ${vectors.length} replay vectors over ${Object.keys(histories).length} histories`);
}
