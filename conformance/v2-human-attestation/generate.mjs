#!/usr/bin/env node
/**
 * ENGINE-DERIVED human-attestation vectors (`humanFloor: "ATTESTED"`): ADDENDA-G6 A-93, ADDENDA-G6.1 A-97 (attested
 * recovery) and A-98, ADDENDA-G6.2 A-106.6, A-107, A-109 (rule T1) and A-112 (two attesters), ADDENDA-G6.3 A-118
 * (statements) and A-119 (rule T2, the horizon). The G6.x holds were lifted on 2026-10-12; precedence G6.3 > G6.2 > G6.1 >
 * G6. Same layout as conformance/v2-owner-policy.
 *
 *   pnpm --filter @ramex-labs/irontrellis build
 *   node conformance/v2-human-attestation/generate.mjs            # write
 *   node conformance/v2-human-attestation/generate.mjs --check    # exit 1 when a fresh generation differs from the files
 *
 * The expectations are this engine's own answers (packages/core/dist); they are not acceptance. The architect's generator
 * and the independent checker define the group; conformance/v2-owner-policy/compare-checker.mjs diffs this engine against
 * the checker's self-built pins. Names are the rulings' (A-93.9, A-97.7, A-98.8, A-106.6, A-107.7, A-109.4, A-112,
 * A-118.6, A-119.4) as G6.3 specifies them; `builder-*` names are this suite's own. Every `ATTESTED` policy names two
 * attesters (A-112). Deterministic: fixed seeds (MANIFEST.json `keys`), ids and timestamps.
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
const { replay, keyPairFromPrivateKey, controlAuthorizationHash, controlEffectHash, ownerKeyDigest, intentDeclarationHash, humanAttestationHash, FORMAT2_VERSIONS, ADAPTER_POLICY_HASH, MAX_TIME } = core;
if (core.challengeProfile() !== 'g3') throw new Error(`this suite is generated under profile g3; this process runs ${core.challengeProfile()} (unset IRONTRELLIS_CHALLENGE_PROFILE)`);

// ================================================================ identities

const DOMAIN = Object.freeze({ protocol: 'irontrellis', version: '2', deploymentId: 'irontrellis-conformance-v2-attest' });
const KEYS = {};
const key = (keyId, n) => {
  const seed = `0x${n.toString(16).padStart(64, '0')}`;
  const pair = keyPairFromPrivateKey('ed25519', keyId, seed);
  KEYS[keyId] = { keyId, scheme: 'ed25519', seed, credential: pair.credential };
  return pair;
};
const O1 = key('owner:1', 0x7001), O2 = key('owner:2', 0x7002), O3 = key('owner:3', 0x7003);
const A1 = key('agent:1', 0x7101);
const NEXT1 = key('next:1', 0x7201), NEXT2 = key('next:2', 0x7202);
const AT1 = key('attester:1', 0x7301), AT2 = key('attester:2', 0x7302), AT3 = key('attester:3', 0x7303);
const STRANGER = key('stranger:1', 0x7999), SESSION1 = key('session:1', 0x7401);
const pub = (p) => ({ keyId: p.keyId, scheme: 'ed25519', credential: p.credential });
const digest = (p) => ownerKeyDigest(p);
const sha = (text) => `0x${createHash('sha256').update(text).digest('hex')}`;
/** A-93.1 / A-107.4: `attester`'s statement about `subject` for `[notBefore, expiresAt)` (`extra`: `historyId`, or a tampered field). */
const statement = (subject, attester, notBefore, expiresAt, extra = {}) => {
  const body = { version: 'irontrellis-human-attestation/1', audience: DOMAIN, subject: pub(subject), profile: 'phl:ceremony/1', attesterKeyId: attester.keyId, evidenceDigest: sha(`evidence:${subject.keyId}:${notBefore}`), notBefore, expiresAt, ...extra };
  return { ...body, signature: signerFromKeyPair(attester).signHashSync(humanAttestationHash({ ...body, signature: '' })) };
};
const ATTESTERS = [pub(AT1), pub(AT2)];
/** An ATTESTED policy over `statements` with the two attesters; `extra` adds threshold, byType, keyClasses, recovery. */
const attested = (statements, extra = {}) => ({ threshold: 1, humanFloor: 'ATTESTED', attesters: ATTESTERS, attestations: statements, ...extra });

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
const historyId = (events) => accepted(events.slice(0, 1)).head.hash;
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
const at = (events) => events.at(-1).timestamp + 1;
/** A control event of `type` (`timestamp`: given, else one after the history so far). */
const ev = (type, id, data, timestamp) => (events) => ({ id: `event:${id}`, type, timestamp: timestamp ?? at(events), data });
const then = (events, make, signers, proofs) => [...events, signed(events, make(events), signers, proofs)];
const principal = ev('PRINCIPAL_CREATED', 'principal', { principalId: 'operations' });
const agent = (id, timestamp) => ev('AGENT_CREATED', `agent:${id}`, { agentId: id, principalId: 'operations', controllerId: 'operator', initialControlEpoch: 1 }, timestamp);
const fence = (id, timestamp, from = 1) => ev('CONTROL_EPOCH_ADVANCED', `fence:${id}:${from}`, { agentId: id, controllerId: 'operator', fromEpoch: from, toEpoch: from + 1 }, timestamp);
const GRANT = { authorityId: 'root', constraints: { actions: ['pay'], maxDelegationDepth: 1, quantitative: false, requiredIntersectionIds: [], resources: ['vendor'] }, granteeId: 'bea', grantorId: 'operations', independent: true, kind: 'PERMISSION', rootAuthorityId: 'root' };
const grant = (timestamp, extra = {}) => ev('AUTHORITY_GRANTED', `grant:${extra.authorityId ?? 'root'}`, { grant: { ...GRANT, ...extra } }, timestamp);
/** A GLOBAL PROHIBITION granted by the history's global policy source (`policy:<name>`). */
const ban = (name) => ev('AUTHORITY_GRANTED', 'grant:ban', { grant: { authorityId: 'ban', constraints: { actions: ['freeze'], maxDelegationDepth: 0, quantitative: false, requiredIntersectionIds: [], resources: ['vendor'] }, grantorId: `policy:${name}`, kind: 'PROHIBITION', scope: 'GLOBAL' } });
const revoke = (authorityId, timestamp) => ev('AUTHORITY_REVOKED', `revoke:${authorityId}`, { authorityId, revokerId: 'operations' }, timestamp);
const rotation = (id, data, timestamp) => ev('OWNER_KEYS_ROTATED', `rotation:${id}`, data, timestamp);
const checkpoint = (timestamp) => (events) => {
  const r = accepted(events);
  return { id: `event:checkpoint:${events.length}`, type: 'STATE_CHECKPOINT', timestamp: timestamp ?? at(events), data: { checkpointId: `checkpoint:${events.length}`, derivationVersion: 'irontrellis-state/2', head: { hash: r.head.hash, position: r.head.position }, projectionHead: r.projectionHead, recordCount: r.state.stateRecords.size, stateRoot: r.stateRoot } };
};
const BUDGET = { budgetId: 'b-pay', subjects: { actorIds: null, roleIds: null, actions: ['pay'], resources: null }, metric: 'amount', period: { kind: 'NONE' }, amountCap: '1000', countCap: null, perOperationCap: null, notBefore: null, expiresAt: null };
/** A session of agent bea (role desk, tenure desk:1) with `p`'s key, and a TRANSACTION_INTENT_DECLARED it signs at `timestamp` (a ◇ event). */
const session = ev('RUNTIME_SESSION_ADMITTED', 'session:bea', { agentId: 'bea', controlEpoch: 1, controllerId: 'operator', credentialKeyId: 'key:bea', credentialPublicKey: SESSION1.credential, credentialScheme: 'ed25519', expiresAt: MAX_TIME, sessionId: 'session:bea' });
const declaration = (events, id, timestamp) => {
  const head = accepted(events).head, binding = { runtimeSessionId: 'session:bea', credentialKeyId: 'key:bea', controlEpoch: 1 };
  const fields = { intentId: id, nonce: `nonce:${id}`, actorId: 'bea', action: 'pay', resource: 'vendor', roleId: 'desk', roleTenureId: 'desk:1', adapterProfile: core.approvedAdapterProfile(core.SIMULATED_ADAPTER_ID), amount: '5' };
  const event = { id: `event:intent:${id}`, type: 'TRANSACTION_INTENT_DECLARED', timestamp };
  const hash = intentDeclarationHash(DOMAIN, fields, { hash: head.hash, position: head.position }, binding, event);
  return [...events, { ...event, data: { ...fields, declarationAuthorization: { ...binding, hash, signature: signerFromKeyPair(SESSION1).signHashSync(hash) } } }];
};

// ================================================================ vectors

const vectors = [];
const histories = {};
const TOPICS = ['policy-validity', 'counting', 'lapse-and-reduction', 'restoration', 'statements', 'recovery', 'time'];
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
    id: `replay/v2ha/${name}`, kind: 'replay', topic, purpose, input: { operationVersion: 'continuity-replay/0.2' },
    ...(history === undefined ? { events } : { history: { ref: history, eventCount: events.length } }), expect, ...(rejection === undefined ? {} : { rejection }),
  });
};
const at0 = (name, purpose, keys, policy, extra = {}) => vector(name, 'policy-validity', purpose, [genesis(name, keys, { ...extra, ownerPolicy: policy })], 'EVENT_DATA_INVALID@0');

const K2 = [pub(O1), pub(O2)], K3 = [pub(O1), pub(O2), pub(O3)];
const live = (p, expiresAt = 1000, attester = AT1) => statement(p, attester, 0, expiresAt);

// ---- A-93.9: statements at the setting event, the strict floor and counting
{
  const g = genesis('floor', K2, { ownerPolicy: attested([live(O1), live(O2, 1000, AT2)]) });
  vector('accepts-attested-floor-genesis', 'policy-validity', 'A-93: a genesis under humanFloor ATTESTED with two attesters and a valid statement for each owner key; owner:1 signs the principal.', then([g], principal, [O1]), 'ACCEPTED');
}
{
  const g = genesis('plus-agent', [...K2, pub(A1)], { ownerPolicy: attested([live(O1), live(O2)], { threshold: 2, keyClasses: { 'agent:1': 'AGENT' } }) });
  vector('accepts-ordinary-event-attested-plus-agent', 'counting', 'A-107.2: on an ordinary ◆ event the counting set is HUMAN and AGENT entries with one HUMAN: owner:1 plus agent:1 at threshold 2.', then([g], principal, [O1, A1]), 'ACCEPTED');
}
{
  const g = genesis('declared', K2, { ownerPolicy: { threshold: 1, humanFloor: 'DECLARED', attesters: ATTESTERS, attestations: [live(O1)] } });
  vector('accepts-declared-floor-ignores-attestations', 'counting', 'A-93.3: under DECLARED a key without a statement is HUMAN by declaration: owner:2 signs alone.', then([g], principal, [O2]), 'ACCEPTED');
}
{
  const g = genesis('non-counting', K3, { ownerPolicy: attested([live(O1), live(O2)], { threshold: 2 }) });
  vector('accepts-non-counting-signature-present', 'counting', 'A-93.3: owner:3 has no statement (NONE); its verifying co-signature is permitted and does not count.', then([g], principal, [O1, O2, O3]), 'ACCEPTED');
  const single = genesis('unattested-signer', K3, { ownerPolicy: attested([live(O1), live(O2)]) });
  vector('rejects-attested-floor-without-attested-signer', 'counting', 'A-107.2: owner:3 is declared HUMAN but has no statement: NONE counts nowhere (M_eff 1).', then([single], principal, [O3]), 'CONTROL_AUTHORIZATION_INVALID@1');
}
{
  const g = genesis('expired-at', K2, { ownerPolicy: attested([live(O1, 150), live(O2)]) });
  const h = then(then([g], principal, [O2]), agent('bea'), [O2]);
  vector('rejects-expired-at-timestamp', 'counting', 'A-93.3: owner:1\'s statement expires at 150; at t = 150 (equality fails) it is LAPSED, which never counts on AUTHORITY_GRANTED.', then(h, grant(150), [O1]), 'CONTROL_AUTHORIZATION_INVALID@3');
}
{
  const g = genesis('not-yet', K2, { ownerPolicy: attested([live(O1), statement(O2, AT2, 500, 1000)]) });
  vector('rejects-not-yet-valid', 'counting', 'A-107.1: owner:2\'s statement starts at 500; at 101 it is NONE and cannot sign alone.', then([g], principal, [O2]), 'CONTROL_AUTHORIZATION_INVALID@1');
  vector('builder-accepts-statement-once-started', 'counting', 'A-107.1: the same key at t = 500 is HUMAN.', then([g], ev('PRINCIPAL_CREATED', 'principal', { principalId: 'operations' }, 500), [O2]), 'ACCEPTED');
}
at0('rejects-unknown-attester', 'A-93.2 rule 3: attesterKeyId names no attester of the policy.', K2, attested([live(O1), statement(O2, AT3, 0, 1000)]));
{
  const forged = { ...live(O2), signature: live(O1).signature };
  at0('rejects-forged-attestation-signature', 'A-93.2 rule 3: the statement\'s signature does not verify under its attester.', K2, attested([live(O1), forged]));
}
{
  const body = { ...live(O2), audience: { ...DOMAIN, deploymentId: 'another-deployment' } };
  const wrong = { ...body, signature: signerFromKeyPair(AT1).signHashSync(humanAttestationHash({ ...body, signature: '' })) };
  at0('rejects-wrong-audience', 'A-93.2 rule 3: a statement signed for another deployment\'s domain.', K2, attested([live(O1), wrong]));
}
at0('rejects-subject-not-owner-or-next', 'A-93.2 rule 3: the subject is neither an owner key nor a committed next key.', K2, attested([live(O1), live(STRANGER)]));
at0('rejects-attester-equals-owner', 'A-93.2 rule 2: owner:2 is named as an attester.', K2, { ...attested([live(O1)]), attesters: [pub(AT1), pub(O2)] });
at0('rejects-agent-classed-subject', 'A-93.2 rule 3: a statement about a key the policy classes AGENT.', [...K2, pub(A1)], attested([live(O1), live(A1)], { keyClasses: { 'agent:1': 'AGENT' } }));
at0('rejects-expired-at-setting', 'A-93.2 rule 3: expiresAt 100 is not after the setting event (t_set 100).', K2, attested([live(O1), live(O2, 100)]));
at0('rejects-attestations-without-attesters', 'A-93.2 rule 1: attestations need attesters.', K2, { threshold: 1, attestations: [live(O1)] });
at0('rejects-single-attester-under-attested', 'A-112 (R2F-10): ATTESTED needs at least two attesters.', K2, { ...attested([live(O1), live(O2)]), attesters: [pub(AT1)] });
at0('rejects-lockout-no-valid-attestation-at-set', 'A-107.5 (a): no owner statement is valid at t_set (every one starts at 500).', K2, attested([statement(O1, AT1, 500, 1000), statement(O2, AT2, 500, 1000)]));
at0('rejects-bytype-power-reducing-above-attested', 'A-107.5 (b) as A-118.3: byType.AUTHORITY_REVOKED 3 with two statements.', K3, attested([live(O1), live(O2)], { byType: { AUTHORITY_REVOKED: 3 } }));
at0('rejects-bytype-power-reducing-above-started-statements', 'A-118.3 (ce32): byType.AUTHORITY_REVOKED 2 with one started statement (owner:2 starts at 500).', K2, attested([live(O1), statement(O2, AT2, 500, 1000)], { byType: { AUTHORITY_REVOKED: 2 } }));
at0('rejects-attester-equals-next-key', 'A-97.5: an attester whose digest is committed as a next owner key.', K2, { ...attested([live(O1), live(O2)]), attesters: [pub(AT1), pub(NEXT1)] }, { nextKeyDigests: [digest(NEXT1)] });
{
  const g = genesis('started-only', K2, { ownerPolicy: attested([live(O1), statement(O2, AT2, 500, 1000)], { byType: { AUTHORITY_REVOKED: 1 } }) });
  const h = then(then(then([g], principal, [O1]), agent('bea'), [O1]), grant(), [O1]);
  vector('accepts-power-reducing-by-started-statements-without-agent', 'lapse-and-reduction', 'A-118.3: byType.AUTHORITY_REVOKED 1 is within the one started statement; owner:1 revokes alone.', then(h, revoke('root'), [O1]), 'ACCEPTED');
}
{
  // The first activation (DECLARED to ATTESTED) is authorized by the declared policy and must itself satisfy A-107.5 (a).
  const g = genesis('activation', K2, { ownerPolicy: { threshold: 2 } });
  const h = then([g], principal, [O1, O2]);
  vector('rejects-activation-below-rotation-quorum', 'policy-validity', 'A-93.2 rule 5: activating ATTESTED with one valid statement under M_rot = 2.',
    then(h, rotation('activate', { ownerKeys: K2, ownerPolicy: attested([statement(O1, AT1, 0, 1000, { historyId: historyId(h) }), statement(O2, AT2, 500, 1000, { historyId: historyId(h) })], { threshold: 2 }) }), [O1, O2]), 'EVENT_DATA_INVALID@2');
  vector('builder-accepts-activation-of-attested-floor', 'policy-validity', 'A-93.2: the same activation with both statements valid at t_set.',
    then(h, rotation('activate', { ownerKeys: K2, ownerPolicy: attested([statement(O1, AT1, 0, 1000, { historyId: historyId(h) }), statement(O2, AT2, 0, 1000, { historyId: historyId(h) })], { threshold: 2 }) }), [O1, O2]), 'ACCEPTED');
}
{
  const g = genesis('supply-old', K3, { ownerPolicy: attested([live(O1), live(O2)]) });
  vector('rejects-new-attestation-supplies-old-quorum', 'counting', 'A-93.3: a rotation that attests owner:3 cannot be signed by owner:3 (NONE under the policy before it).',
    then([g], rotation('supply', { ownerKeys: K3, ownerPolicy: attested([live(O1), live(O2), statement(O3, AT1, 0, 1000, { historyId: historyId([g]) })]) }), [O3]), 'CONTROL_AUTHORIZATION_INVALID@1');
  const g2 = genesis('unattested-rotation', K3, { ownerPolicy: attested([live(O1), live(O2)], { byType: { OWNER_KEYS_ROTATED: 2 } }) });
  vector('rejects-attested-rotation-with-unattested-human', 'counting', 'A-107.2: on OWNER_KEYS_ROTATED only HUMAN counts: owner:1 plus owner:3 (NONE) is one of two.',
    then([g2], rotation('unattested', { ownerKeys: K3, ownerPolicy: attested([live(O1), live(O2)]) }), [O1, O3]), 'CONTROL_AUTHORIZATION_INVALID@1');
}

// ---- A-98.8 / A-106.6: lapsed keys reduce, restore or checkpoint only
{
  const g = genesis('lapse', K3, { ownerPolicy: attested([live(O1, 150), live(O2, 150), live(O3)], { threshold: 2 }) });
  const h = then(then(then(then([g], principal, [O1, O2]), agent('bea'), [O1, O2]), grant(), [O1, O2]), ban('lapse'), [O1, O2]);
  vector('accepts-power-reducing-by-lapsed-keys', 'lapse-and-reduction', 'A-107.2: AUTHORITY_REVOKED of a PERMISSION at t >= expiresAt by two LAPSED keys (PR_eff: LAPSED counts).', then(h, revoke('root', 150), [O1, O2]), 'ACCEPTED');
  vector('rejects-grant-by-lapsed-keys', 'lapse-and-reduction', 'A-107.2: AUTHORITY_GRANTED is not PR_eff: LAPSED keys never count on it.', then(h, grant(150, { authorityId: 'second' }), [O1, O2]), 'CONTROL_AUTHORIZATION_INVALID@5');
  vector('rejects-prohibition-revocation-by-lapsed-keys', 'lapse-and-reduction', 'A-106.6: revoking a PROHIBITION is never PR_eff: LAPSED keys do not count.', then(h, revoke('ban', 150), [O1, O2]), 'CONTROL_AUTHORIZATION_INVALID@5');
  vector('accepts-checkpoint-by-lapsed-keys', 'lapse-and-reduction', 'A-107.2 (R2F-11): STATE_CHECKPOINT counts LAPSED keys (it adds no authority).', then(h, checkpoint(160), [O1, O2]), 'ACCEPTED');
  const budgeted = then(h, ev('BUDGET_DECLARED', 'budget', BUDGET), [O1, O2]);
  vector('rejects-budget-raise-by-lapsed-keys', 'lapse-and-reduction', 'A-106.6: raising a cap is not PR_eff: LAPSED keys do not count.',
    then(budgeted, ev('BUDGET_UPDATED', 'budget:raise', { budgetId: 'b-pay', subjects: BUDGET.subjects, amountCap: '9000', countCap: null, perOperationCap: null, expiresAt: null }, 150), [O1, O2]), 'CONTROL_AUTHORIZATION_INVALID@6');
}
{
  const g = genesis('fence-agent', [...K2, pub(A1)], { ownerPolicy: attested([live(O1, 150), live(O2)], { threshold: 2, keyClasses: { 'agent:1': 'AGENT' } }) });
  const h = then(then([g], principal, [O1, O2]), agent('bea'), [O1, O2]);
  vector('accepts-fence-by-lapsed-and-agent', 'lapse-and-reduction', 'A-107.2: a fence (PR_eff) at M_eff = 2 by one LAPSED key and one AGENT key; at 200 owner:2\'s statement keeps the horizon at 1000 (T2 does not bind).', then(h, fence('bea', 200), [O1, A1]), 'ACCEPTED');
  vector('rejects-lapsed-and-agent-advancing-past-horizon', 'time', 'A-119.1 (T2): the same pair at 1001, past the horizon 1000: one human-class signer cannot advance time there.', then(h, fence('bea', 1001), [O1, A1]), 'TRANSITION_INVALID@3');
}
{
  const g = genesis('revoked-key', K3, { ownerPolicy: attested([live(O1), live(O2), live(O3)]) });
  const h = then(then([g], principal, [O1]), agent('bea'), [O1]);
  const dropped = then(h, rotation('drop', { ownerKeys: K3, ownerPolicy: attested([live(O1), live(O2)]) }), [O1]);
  vector('rejects-revoked-key-on-power-reducing', 'lapse-and-reduction', 'A-107.1: a policy rotation removed owner:3\'s statement; owner:3 is NONE and cannot fence even though the fence is PR_eff.', then(dropped, fence('bea'), [O3]), 'CONTROL_AUTHORIZATION_INVALID@4');
}
{
  const g = genesis('not-yet-pr', K2, { ownerPolicy: attested([live(O1), statement(O2, AT2, 500, 1000)]) });
  vector('rejects-not-yet-valid-on-power-reducing', 'lapse-and-reduction', 'A-107.1 (G61-X-7): a statement that has not started is NONE, also on a PR_eff fence.', then(then(then([g], principal, [O1]), agent('bea'), [O1]), fence('bea'), [O2]), 'CONTROL_AUTHORIZATION_INVALID@3');
}

// ---- A-107.3 with A-118.2: restoration (a policy rotation that renews or carries every statement)
{
  const base = (name, statements, extra = {}, genesisExtra = {}) => then(then([genesis(name, statements.keys, { ...genesisExtra, ownerPolicy: attested(statements.list, { threshold: 2, ...extra }) })], principal, [O1, O2]), agent('bea'), [O1, O2]);
  const two = { keys: K2, list: [live(O1, 150), live(O2, 150)] };
  const renew = (h, p, attester = AT1) => statement(p, attester, 190, 2000, { historyId: historyId(h) });
  const restore = (h, list, extra = {}, data = {}) => rotation('restore', { ownerKeys: h[0].data.ownerKeys, ownerPolicy: attested(list, { threshold: 2, ...extra }), ...data }, 200);
  let h = base('restore', two);
  vector('accepts-restoration-rotation-by-lapsed-keys', 'restoration', 'A-107.3: both statements expired; the lapsed quorum renews them (notBefore in (t_set, e.timestamp], later expiry) and nothing else.', then(h, (e) => restore(e, [renew(e, O1), renew(e, O2, AT2)])(e), [O1, O2]), 'ACCEPTED');
  vector('rejects-restoration-changing-attesters', 'restoration', 'A-107.3 (3): changing attesters is not a restoration; lapsed keys do not count on a rotation.', then(h, (e) => restore(e, [renew(e, O1), renew(e, O2, AT1)], { attesters: [pub(AT1), pub(AT3)] })(e), [O1, O2]), 'CONTROL_AUTHORIZATION_INVALID@3');
  vector('rejects-restoration-changing-threshold', 'restoration', 'A-107.3 (3): changing the threshold is not a restoration.', then(h, (e) => rotation('restore', { ownerKeys: K2, ownerPolicy: attested([renew(e, O1), renew(e, O2, AT2)], { threshold: 1 }) }, 200)(e), [O1, O2]), 'CONTROL_AUTHORIZATION_INVALID@3');
  vector('rejects-key-rotation-by-lapsed-keys', 'restoration', 'A-107.2: a key rotation counts HUMAN only.', then(h, (e) => rotation('keys', { ownerKeys: [pub(O1), pub(O3)], ownerPolicy: attested([renew(e, O1), statement(O3, AT2, 190, 2000, { historyId: historyId(e) })], { threshold: 2 }) }, 200)(e), [O1, O2]), 'CONTROL_AUTHORIZATION_INVALID@3');
  vector('rejects-restoration-adding-commitment', 'restoration', 'A-107.3 (4): out of an uncommitted epoch a restoration adds no commitment.', then(h, (e) => restore(e, [renew(e, O1), renew(e, O2, AT2)], {}, { nextKeyDigests: [digest(NEXT1)] })(e), [O1, O2]), 'CONTROL_AUTHORIZATION_INVALID@3');
  vector('rejects-restoration-with-stale-statements', 'restoration', 'A-107.5 (a): a restoration renewing owner:1 and carrying owner:2 expired leaves one valid statement at t_set under M_rot = 2.', then(h, (e) => restore(e, [renew(e, O1), live(O2, 150)])(e), [O1, O2]), 'EVENT_DATA_INVALID@3');
  vector('rejects-restoration-renewal-with-future-notbefore', 'restoration', 'A-118.2 (X-4): a renewal must have started at the event (notBefore <= e.timestamp).', then(h, (e) => restore(e, [renew(e, O1), statement(O2, AT2, 300, 2000, { historyId: historyId(e) })])(e), [O1, O2]), 'CONTROL_AUTHORIZATION_INVALID@3');
  vector('rejects-restoration-with-stashed-statement', 'restoration', 'A-107.3 (6): a "renewal" with the embedded statement\'s notBefore is not later: not a restoration.', then(h, (e) => restore(e, [renew(e, O1), statement(O2, AT2, 0, 2000, { historyId: historyId(e) })])(e), [O1, O2]), 'CONTROL_AUTHORIZATION_INVALID@3');
  vector('rejects-restoration-with-stashed-statement-below-t-set', 'restoration', 'A-118.2: a renewal\'s notBefore (50) must be later than the epoch\'s opening (t_set 100).', then(h, (e) => restore(e, [renew(e, O1), statement(O2, AT2, 50, 2000, { historyId: historyId(e) })])(e), [O1, O2]), 'CONTROL_AUTHORIZATION_INVALID@3');
  const three = { keys: K3, list: [live(O1, 150), live(O2, 150), live(O3, 150)] };
  h = base('restore-three', three, { byType: { CONTROL_EPOCH_ADVANCED: 1 } });
  const carriedExpired = then(h, (e) => restore(e, [renew(e, O1), renew(e, O2, AT2), live(O3, 150)], { byType: { CONTROL_EPOCH_ADVANCED: 1 } })(e), [O1, O2]);
  vector('accepts-restoration-carrying-expired-coowner', 'restoration', 'A-107.4 / A-118.1: two renewed, owner:3\'s expired statement carried; owner:3 is LAPSED afterwards and fences alone (byType 1).', then(carriedExpired, fence('bea', 201), [O3]), 'ACCEPTED');
  vector('rejects-restoration-dropping-subject', 'restoration', 'A-107.3 (5): a restoration keeps every subject.', then(h, (e) => restore(e, [renew(e, O1), renew(e, O2, AT2)], { byType: { CONTROL_EPOCH_ADVANCED: 1 } })(e), [O1, O2]), 'CONTROL_AUTHORIZATION_INVALID@3');
  const twoOfThree = { keys: K3, list: [live(O1, 150), live(O2, 150)] };
  h = base('restore-add', twoOfThree);
  vector('rejects-restoration-adding-subject', 'restoration', 'A-107.3 (5): owner:3 had no statement; a fresh one is not a restoration.', then(h, (e) => restore(e, [renew(e, O1), renew(e, O2, AT2), statement(O3, AT1, 190, 2000, { historyId: historyId(e) })])(e), [O1, O2]), 'CONTROL_AUTHORIZATION_INVALID@3');
  h = base('restore-bytype', three, { byType: { AUTHORITY_REVOKED: 3 } });
  vector('accepts-restoration-with-pr-bytype-above-renewed', 'restoration', 'A-118.3 (C5): byType.AUTHORITY_REVOKED 3 with two renewals and one carried statement (carried expired statements have started).', then(h, (e) => restore(e, [renew(e, O1), renew(e, O2, AT2), live(O3, 150)], { byType: { AUTHORITY_REVOKED: 3 } })(e), [O1, O2]), 'ACCEPTED');
  // X-10: the epoch in force opened at 120 (a policy rotation by the HUMAN quorum); a renewal dated 110 predates it.
  h = base('restore-epoch', two);
  const reopened = then(h, (e) => rotation('labels', { ownerKeys: K2, ownerPolicy: attested(two.list, { threshold: 2, labels: { 'owner:1': 'laptop' } }) }, 120)(e), [O1, O2]);
  vector('rejects-restoration-with-statement-predating-epoch', 'restoration', 'A-118.2 (X-10): the epoch opened at 120; a renewal with notBefore 110 cannot replace the embedded statement.',
    then(reopened, (e) => rotation('restore', { ownerKeys: K2, ownerPolicy: attested([statement(O1, AT1, 110, 2000, { historyId: historyId(e) }), renew(e, O2, AT2)], { threshold: 2 }) }, 200)(e), [O1, O2]), 'CONTROL_AUTHORIZATION_INVALID@4');
  // A-96.5: a restoration out of a committed epoch restates the commitment unchanged.
  const committed = base('renewal', { keys: K2, list: [live(O1, 300), live(O2, 300)] }, {}, { nextKeyDigests: [digest(NEXT1)] });
  vector('accepts-renewal-by-policy-rotation', 'restoration', 'A-93.6 / A-96.5: a renewal by policy rotation out of a committed epoch, signed by the HUMAN quorum, carrying the commitment.',
    then(committed, (e) => rotation('renew', { ownerKeys: K2, nextKeyDigests: [digest(NEXT1)], ownerPolicy: attested([statement(O1, AT1, 102, 2000, { historyId: historyId(e) }), statement(O2, AT2, 102, 2000, { historyId: historyId(e) })], { threshold: 2 }) }, 103)(e), [O1, O2]), 'ACCEPTED');
}

// ---- A-107.4 / A-118.1: historyId and the carry waiver
{
  const g = genesis('history-id', K3, { ownerPolicy: attested([live(O1), live(O2), live(O3, 150)], { threshold: 2 }) });
  const h = then(then([g], principal, [O1, O2]), agent('bea'), [O1, O2]);
  const rotate = (list, extra = {}) => rotation('history', { ownerKeys: K3, ownerPolicy: attested(list, { threshold: 2, ...extra }) }, 200);
  vector('rejects-attestation-without-history-id-after-genesis', 'statements', 'A-107.4: a statement set after the genesis that is not carried needs historyId.', then(h, rotate([live(O1), live(O2), statement(O3, AT1, 190, 2000)]), [O1, O2]), 'EVENT_DATA_INVALID@3');
  vector('rejects-attestation-wrong-history-id', 'statements', 'A-107.4: historyId names another history.', then(h, rotate([live(O1), live(O2), statement(O3, AT1, 190, 2000, { historyId: sha('another history') })]), [O1, O2]), 'EVENT_DATA_INVALID@3');
  vector('accepts-carried-genesis-statement-without-history-id', 'statements', 'A-107.4: carried genesis statements keep their form (no historyId); the renewed one names this history.', then(h, (e) => rotate([live(O1), live(O2), statement(O3, AT1, 190, 2000, { historyId: historyId(e) })])(e), [O1, O2]), 'ACCEPTED');
  const carried = then(h, rotate([live(O1), live(O2), live(O3, 150)], { byType: { CONTROL_EPOCH_ADVANCED: 1 } }), [O1, O2]);
  vector('accepts-policy-rotation-carrying-expired-coowner', 'statements', 'A-118.1 (X-5): two HUMAN keys add a byType entry and carry owner:3\'s expired statement; owner:3 is LAPSED afterwards and fences alone.', then(carried, fence('bea', 201), [O3]), 'ACCEPTED');
}

// ---- A-97.7: attested recovery (a pre-attested committed next key)
{
  const R = (list, extra = {}) => attested(list, { recovery: 'COMMITTED_NEXT_KEYS', ...extra });
  const g = genesis('pre-attested', K2, { nextKeyDigests: [digest(NEXT1)], ownerPolicy: R([live(O1), live(O2), live(NEXT1, 1000, AT2)]) });
  const h = then([g], principal, [O1]);
  vector('accepts-pre-attested-next-key-rotation', 'recovery', 'A-97.3: a committed next key with a valid statement is HUMAN and signs the recovery rotation that reveals it.',
    then(h, rotation('recover', { ownerKeys: [pub(NEXT1), pub(O2)], nextKeyDigests: [digest(NEXT2)], ownerPolicy: R([live(O2), live(NEXT1, 1000, AT2)]) }), [NEXT1], [NEXT1]), 'ACCEPTED');
  const g2 = genesis('unattested-next', K2, { nextKeyDigests: [digest(NEXT1)], ownerPolicy: R([live(O1), live(O2)]) });
  vector('rejects-unattested-next-key-recovery', 'recovery', 'A-97.3: a revealed committed key without a statement is NONE and never counts.',
    then(then([g2], principal, [O1]), rotation('recover', { ownerKeys: [pub(NEXT1), pub(O2)], nextKeyDigests: [digest(NEXT2)], ownerPolicy: R([live(O2)]) }), [NEXT1], [NEXT1]), 'CONTROL_AUTHORIZATION_INVALID@2');
}

// ---- A-109.4 (T1) and A-119.4 (T2): time
{
  const g = genesis('time-session', K2, { ownerPolicy: attested([live(O1, 1000), live(O2, 1000)]) });
  let h = then(then(then([g], principal, [O1]), agent('bea'), [O1]), ev('ROLE_CREATED', 'role:desk', { roleId: 'desk', principalId: 'operations', exclusive: true }), [O1]);
  h = then(then(h, ev('AGENT_APPOINTED', 'appoint:bea', { agentId: 'bea', principalId: 'operations', roleId: 'desk', roleTenureId: 'desk:1', tenureNumber: 1 }), [O1]), session, [O1]);
  vector('rejects-session-event-crossing-attestation-expiry', 'time', 'A-109.1 (T1): a session-signed declaration at t = expiresAt (1000) of statements unexpired at the head.', declaration(h, 'i1', 1000), 'TRANSITION_INVALID@6');
  vector('accepts-session-event-before-expiry', 'time', 'A-109.1: the same declaration at expiresAt - 1.', declaration(h, 'i1', 999), 'ACCEPTED');
  const owner = then(then(h, agent('cal'), [O1]), fence('cal', 1000), [O1]);
  vector('accepts-control-event-crossing-expiry', 'time', 'A-109.1: an owner-signed fence at expiresAt; its signer is LAPSED there (PR_eff, M_eff 1) and T2 admits it (1000 <= H).', owner, 'ACCEPTED');
  vector('accepts-session-event-after-owner-crossed', 'time', 'A-109.1: once an owner event crossed the expiry, a session event after it is not bounded by that statement.', declaration(owner, 'i2', 1001), 'ACCEPTED');
}
{
  const g = genesis('horizon', K2, { ownerPolicy: attested([live(O1, 150), live(O2, 150)], { threshold: 2, byType: { CONTROL_EPOCH_ADVANCED: 1, STATE_CHECKPOINT: 1 } }) });
  const h = then(then([g], principal, [O1, O2]), agent('bea'), [O1, O2]);
  vector('rejects-single-signer-advancing-past-horizon', 'time', 'A-119.1 (T2): a PR_eff fence by one LAPSED key at H + 1 (151).', then(h, fence('bea', 151), [O1]), 'TRANSITION_INVALID@3');
  vector('accepts-single-signer-advancing-to-horizon', 'time', 'A-119.1: the same fence at H (150); every key is LAPSED afterwards.', then(h, fence('bea', 150), [O1]), 'ACCEPTED');
  const past = then(h, ev('BUDGET_DECLARED', 'budget', BUDGET, 300), [O1, O2]);
  vector('accepts-two-human-signers-advancing-past-horizon', 'time', 'A-119.1: two human-class (LAPSED) signers on a PR_eff BUDGET_DECLARED at 300 > H: hc = 2.', past, 'ACCEPTED');
  vector('accepts-single-signer-at-head-time-past-horizon', 'time', 'A-119.1: past the horizon a single signer writes at the head\'s time (300).', then(past, fence('bea', 300), [O1]), 'ACCEPTED');
  vector('accepts-checkpoint-by-lapsed-key-crossing-expiry', 'time', 'A-119.2: with STATE_CHECKPOINT 1 one LAPSED key carries time to the expiry (150).', then(h, checkpoint(150), [O2]), 'ACCEPTED');
}
{
  const g = genesis('max-time', K2, { ownerPolicy: attested([live(O1, MAX_TIME), live(O2, MAX_TIME)]) });
  const h = then(then([g], principal, [O1]), agent('bea'), [O1]);
  vector('rejects-single-signer-at-max-time', 'time', 'A-119.1: with H = 2^53 - 1 a single HUMAN signer may still not write 2^53 - 1 (the cap is MAXT - 1).', then(h, fence('bea', MAX_TIME), [O1]), 'TRANSITION_INVALID@3');
  vector('builder-accepts-single-signer-at-max-time-minus-one', 'time', 'A-119.1 / L12 erratum: 2^53 - 2 is admitted.', then(h, fence('bea', MAX_TIME - 1), [O1]), 'ACCEPTED');
}

// ---- the pinned root (A-93.9 `accepts-attestation-history`): attesters and statements in the epoch records
{
  const K = [pub(O1), pub(O2), pub(O3), pub(A1)];
  const P0 = attested([live(O1, 500), live(O2, 500), live(O3, 2000, AT2), live(NEXT1, 2000, AT2)], { threshold: 2, keyClasses: { 'agent:1': 'AGENT' } });
  const g = genesis('attestation-history', K, { nextKeyDigests: [digest(NEXT1)], ownerPolicy: P0 });
  let h = then([g], principal, [O1, O2]);
  h = then(h, agent('bea'), [O3, A1]);                                                                       // HUMAN plus AGENT
  h = then(h, (e) => rotation('renew', { ownerKeys: K, nextKeyDigests: [digest(NEXT1)], ownerPolicy: { ...P0, attestations: [statement(O1, AT1, 102, 3000, { historyId: historyId(e) }), live(O2, 500), live(O3, 2000, AT2), live(NEXT1, 2000, AT2)] } }, 103)(e), [O1, O3]); // a restoration-shaped renewal by the HUMAN quorum
  h = then(h, fence('bea', 600), [O2, A1]);                                                                  // owner:2 LAPSED plus AGENT on a PR_eff fence
  h = then(h, checkpoint(601), [O1, O2]);
  histories['attestation-history'] = h;
  vector('accepts-attestation-history', 'statements', 'A-93.9 pinned root: the owner key epoch records carry attesters and statements (a pre-attested next key included); HUMAN, AGENT and LAPSED signers each count where A-107.2 says.', h, 'ACCEPTED', 'attestation-history');
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
  schemaVersion: 'irontrellis-conformance/2', suite: 'v2-human-attestation', protocol: 'irontrellis', format: 'irontrellis-event/2', challengeProfile: 'g3', engineDerived: true,
  generatedFrom: { reference: '@ramex-labs/irontrellis (packages/core)', replay: core.REPLAY_VERSION, rulings: ['ADDENDA-G6 A-93', 'ADDENDA-G6.1 A-97, A-98', 'ADDENDA-G6.2 A-106.6, A-107, A-109, A-112', 'ADDENDA-G6.3 A-118, A-119'], precedence: 'G6.3 > G6.2 > G6.1 > G6', holds: 'lifted 2026-10-12 (founder)' },
  note: 'ENGINE-DERIVED human-attestation vectors (humanFloor ATTESTED). Not acceptance: the architect\'s generator and the independent checker define the group. `node conformance/v2-human-attestation/generate.mjs --check` reproduces these files byte for byte.',
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
  const differ = [...outputs].filter(([path, text]) => { const file = join(HERE, path); return !existsSync(file) || readFileSync(file, 'utf8') !== text; }).map(([path]) => `conformance/v2-human-attestation/${path}`);
  differ.push(...stale.map((file) => `conformance/v2-human-attestation/histories/${file} (not generated)`));
  if (differ.length > 0) { console.error(`a fresh generation differs:\n  ${differ.join('\n  ')}`); process.exit(1); }
  console.log(`conformance/v2-human-attestation is up to date (${vectors.length} vectors over ${Object.keys(histories).length} histories)`);
} else {
  mkdirSync(HISTORIES, { recursive: true });
  for (const file of stale) rmSync(join(HISTORIES, file));
  for (const [path, text] of outputs) writeFileSync(join(HERE, path), text);
  console.log(`wrote ${vectors.length} replay vectors over ${Object.keys(histories).length} histories`);
}
