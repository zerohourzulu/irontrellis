#!/usr/bin/env node
/**
 * Generates the format-1 (`irontrellis-event/1`) conformance vectors with the
 * TypeScript core as the executable reference.
 *
 *   pnpm --filter @ramex-labs/irontrellis build
 *   node conformance/v1/generate.mjs            # write
 *   node conformance/v1/generate.mjs --check    # exit 1 when a fresh generation differs from the files
 *
 * Output: conformance/v1/vectors.json, conformance/v1/MANIFEST.json,
 * conformance/v1/histories/*.json (+ the .jsonl store files the histories were
 * written as) and the vector-count table in conformance/README.md. Everything is
 * deterministic: fixed Ed25519 seeds (next keys included), counter-based event
 * ids and a scripted clock, so regenerating yields byte-identical files.
 * Expectations are the reference engine's own answers projected exactly as the
 * adapters project them; a vector is only kept when that projection matches
 * the intent stated in its `purpose`.
 *
 * The histories are built first; the vectors follow grouped by topic (TOPICS).
 * Every replay vector pins its rejection `code` (`null` when accepted).
 */
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = dirname(dirname(HERE));
const CHECK = process.argv.includes('--check');
const core = await import(join(ROOT, 'packages/core/dist/index.js'));
const signer = await import(join(ROOT, 'packages/core/dist/signer.js'));
const transparency = await import(join(ROOT, 'packages/core/dist/transparency/index.js'));
const internal = await import(join(ROOT, 'packages/core/dist/internal-format1.js')); // A-185.3 / A-194: the format-1 writer is test tooling
const { createLocalOwner, openLocalSimulation, openLocalRuntime, commitTerms, keyPairFromPrivateKey, signHashWith, migrateHistory, openHistoryStore, replay, authorizePortable, survivesPortable, publicQueryDisclosure, TRELLIS_FORMAT } = core;

const WORK = join(HERE, '.work');
const HISTORIES = join(HERE, 'histories');
rmSync(WORK, { recursive: true, force: true });
mkdirSync(WORK, { recursive: true });

const DOMAIN = Object.freeze({ protocol: 'irontrellis', version: '1', deploymentId: 'irontrellis-conformance-v1' });
const seed = (n) => `0x${n.toString(16).padStart(64, '0')}`;
const ownerKey = keyPairFromPrivateKey('ed25519', 'owner:1', seed(0x1001));
/** The next key every history commits to in its genesis, unless it opts out (`nextKey: false`). */
const nextKey = keyPairFromPrivateKey('ed25519', 'owner:2', seed(0x1102));
const nextNextKey = keyPairFromPrivateKey('ed25519', 'owner:3', seed(0x1103));
const runtimeKey = (n) => { const pair = keyPairFromPrivateKey('ed25519', `key:${n}`, seed(0x2000 + n)); return { credential: pair.credential, signHash: signHashWith(pair) }; };
const encode = (_k, v) => (typeof v === 'bigint' ? { '$continuity.bigint': v.toString() } : v);
const plain = (v) => JSON.parse(JSON.stringify(v, encode));
const revive = (v) => core.jsonParseWithBigints(JSON.stringify(v));
const ownerSigner = signer.signerFromKeyPair(ownerKey);
const ok = (pair) => ({ keyId: pair.keyId, scheme: 'ed25519', credential: pair.credential });
const digestOf = (pair) => core.ownerKeyDigest(pair);

/** The legacy (continuity-event/0.2) handover fixture: the source of migrated-v1 and of the legacy-history refusals. */
const LEGACY_FIXTURE = JSON.parse(readFileSync(join(ROOT, 'packages/reference-0.2/tests/fixtures/handover-history.json'), 'utf8'));

/** Files this run produces (published path → text); written, or compared with `--check`, at the end. */
const outputs = new Map();

/**
 * A scripted history: deterministic ids (`<name>:<n>`) and a clock that advances one unit per write. Its genesis commits
 * the owner key to `nextKey` (createLocalOwner's default, with a caller signer so no key file is generated); a history
 * that opts out passes `nextKey: false`.
 */
function scripted(name, extra = {}) {
  let tick = 100, counter = 0;
  const historyFile = join(WORK, `${name}.jsonl`);
  const config = {
    historyFile, domain: DOMAIN, owner: 'operations', controller: 'operator', format: TRELLIS_FORMAT, [internal.FORMAT1_TEST_TOOLING]: true,
    now: () => tick, ids: () => `${name}:${(counter += 1)}`, signer: ownerSigner, nextSigner: signer.signerFromKeyPair(nextKey), ...extra,
  };
  if (config.nextKey === false) delete config.nextSigner;
  const step = async (promise) => { const result = await promise; tick += 1; return result; };
  return { config, historyFile, step, tick: () => tick };
}

const readStore = (file) => openHistoryStore(file).state().events.map((e) => plain(e));
const histories = {};
const save = (name, events, storeFile) => {
  histories[name] = events;
  outputs.set(`histories/${name}.json`, `${JSON.stringify(events, null, 1)}\n`);
  if (storeFile) outputs.set(`histories/${name}.jsonl`, readFileSync(storeFile, 'utf8'));
};
const headOf = (events) => { const r = replay(revive(events)); if (r.status !== 'ACCEPTED') throw new Error(`history rejected: ${r.code} ${r.reason}`); return plain(r.head); };
/** `list` extended by `unsigned`, owner-signed by `by` over the head of `list`. */
const signedOn = async (list, unsigned, by = ownerSigner) => {
  const head = replay(revive(list)).state.head;
  return [...list, plain(await signer.signControlEvent(by, { timestamp: head.canonicalTime, ...unsigned }, DOMAIN, head, 'sha256'))];
};
/** An `OWNER_KEYS_ROTATED` at the end of `list`, signed by `by`, with proofs by `reveal` ([keyId, signer]) over its challenge. */
const rotateOn = async (list, id, data, by, reveal = []) => {
  const head = revive(headOf(list));
  const signed = await signer.signControlEvent(by, { id, type: 'OWNER_KEYS_ROTATED', timestamp: list.at(-1).timestamp, data }, DOMAIN, head, 'sha256');
  if (reveal.length === 0) return [...list, plain(signed)];
  const challenge = core.controlAuthorizationHash({ domain: DOMAIN, eventId: signed.id, eventType: signed.type, timestamp: signed.timestamp, previousHead: { hash: head.hash, position: head.position }, effectHash: core.controlEffectHash(signed, 'sha256') }, 'sha256');
  const proofs = await Promise.all(reveal.map(async ([keyId, s]) => ({ keyId, scheme: 'ed25519', signature: await s.signHash(challenge) })));
  return [...list, plain({ ...signed, data: { ...signed.data, nextKeyAuthorizations: proofs } })];
};

// ================================================================ histories

// ---------------------------------------------------------------- handover-v1: a signed handover with an obligation and an assignment (+ handover-anchored-v1)

const handover = {};
{
  const h = scripted('handover');
  const owner = await createLocalOwner(h.config);
  const bea = runtimeKey(1), alex = runtimeKey(2);
  await h.step(owner.createAgent({ id: 'bea' }));
  await h.step(owner.createAgent({ id: 'alex' }));
  await h.step(owner.createRole({ id: 'reviewer' }));
  await h.step(owner.declareSuccession({ id: 'handover', from: 'bea', to: 'alex', role: 'reviewer' }));
  await h.step(owner.appoint({ agent: 'bea', role: 'reviewer', tenure: 'shift:1', number: 1, succession: 'handover' }));
  await h.step(owner.admitRuntime({ session: 'session:bea', agent: 'bea', epoch: 1, key: 'key:bea', credential: bea.credential, expiresAt: 900 }));
  await h.step(owner.admitRuntime({ session: 'session:alex', agent: 'alex', epoch: 1, key: 'key:alex', credential: alex.credential, expiresAt: 900 }));
  await h.step(owner.grant({ id: 'collect', to: 'bea', actions: ['read', 'OBLIGATE'], resources: ['incident:42'], expiresAt: 800 }));
  await h.step(owner.grant({ id: 'review', to: 'alex', actions: ['record-collection-disposition'], resources: ['duty:42'], expiresAt: 800 }));
  await h.step(owner.grant({ id: 'progress', to: 'alex', actions: ['read'], resources: ['progress:42'], expiresAt: 800 }));
  const op = { id: 'operation:42', action: 'read', resource: 'incident:42', role: 'reviewer', tenure: 'shift:1', termsCommitment: commitTerms({ subject: 'Synthetic incident review' }) };
  const sim = openLocalSimulation({ ...h.config, session: 'session:bea', signHash: bea.signHash });
  const run = await h.step(sim.run(op));
  if (run.invocation?.status !== 'SUBMITTED') throw new Error(`simulation failed: ${JSON.stringify(run)}`);
  const receipt = await h.step(sim.recordReceipt(op));
  if (receipt.recording?.status !== 'ADMITTED') throw new Error('receipt not admitted');
  const runtime = openLocalRuntime({ ...h.config, session: 'session:bea', signHash: bea.signHash });
  await h.step(runtime.obligate({ id: 'duty:42', operation: op.id, description: 'Review the collected material.', deadline: 700, succession: 'handover', reviewAuthority: 'review' }));
  handover.before = readStore(h.historyFile).length;
  await h.step(owner.succeed({ id: 'handover:42', rule: 'handover', fromAgent: 'bea', fromTenure: 'shift:1', toAgent: 'alex', toTenure: 'shift:2', role: 'reviewer', number: 2 }));
  await h.step(owner.grant({ id: 'assign', to: 'alex', actions: ['ASSIGN_PERFORMANCE'], resources: ['duty:42'], expiresAt: 800 }));
  const successor = openLocalRuntime({ ...h.config, session: 'session:alex', signHash: alex.signHash });
  await h.step(successor.assign({ id: 'assign:42', obligation: 'duty:42' }));
  await h.step(owner.revoke('collect'));
  handover.events = readStore(h.historyFile);
  save('handover-v1', handover.events, h.historyFile);
  // An anchor through a custom anchor target, recorded as an owner-signed ANCHOR_RECORDED (the same history, one event longer).
  const store = internal.openHistoryStoreInternal(h.historyFile, { signer: ownerSigner, readOnlyFormats: false });
  const target = { kind: 'custom', name: 'custom', submit: async (attestation) => ({ witness: 'conformance-fixture', attestedHash: attestation.head.hash }), verify: async () => true };
  handover.anchor = (await core.anchorHead(store, ownerSigner, target, { id: 'handover:anchor', anchoredAt: h.tick() })).event;
  handover.anchored = readStore(h.historyFile);
  save('handover-anchored-v1', handover.anchored, h.historyFile);
}

// ---------------------------------------------------------------- authority-v1: the authority corpus (delegation, intersections, prohibitions, time, quantities)

{
  const h = scripted('authority');
  const owner = await createLocalOwner(h.config);
  const lead = runtimeKey(3);
  for (const id of ['lead', 'analyst', 'intern', 'cadet', 'novice', 'clerk', 'guard', 'buyer', 'visitor', 'heir']) await h.step(owner.createAgent({ id }));
  await h.step(owner.createRole({ id: 'treasury' }));
  await h.step(owner.appoint({ agent: 'lead', role: 'treasury', tenure: 'treasury:1', number: 1 }));
  await h.step(owner.admitRuntime({ session: 'session:lead', agent: 'lead', epoch: 1, key: 'key:lead', credential: lead.credential, expiresAt: 900 }));
  await h.step(owner.grant({ id: 'root', to: 'lead', actions: ['read', 'write', 'pay'], resources: ['ledger', 'vault'], expiresAt: 800, delegable: 2, maxAmount: 1000n }));
  await h.step(owner.delegate({ id: 'analyst-read', from: 'lead', parent: 'root', to: 'analyst', actions: ['read'], resources: ['ledger'], expiresAt: 700, delegable: 1, maxAmount: 500n }));
  await h.step(owner.grant({ id: 'dual', to: 'analyst', actions: ['write'], resources: ['ledger'], expiresAt: 800, independent: false }));
  await h.step(owner.delegate({ id: 'write-with-dual', from: 'lead', parent: 'root', to: 'analyst', actions: ['write'], resources: ['ledger'], expiresAt: 700, requires: ['dual'], maxAmount: 500n }));
  await h.step(owner.grant({ id: 'approval', to: 'analyst', actions: ['write'], resources: ['vault'], expiresAt: 800, independent: false }));
  await h.step(owner.grant({ id: 'write-needs-approval', to: 'clerk', actions: ['write'], resources: ['vault'], expiresAt: 800, requires: ['approval'] }));
  await h.step(owner.prohibit({ id: 'no-vault-payments', root: 'root', actions: ['pay'], resources: ['vault'], expiresAt: 800, maxAmount: 1000n }));
  await h.step(owner.grant({ id: 'freezer', to: 'guard', actions: ['freeze'], resources: ['ledger'], expiresAt: 800 }));
  await h.step(owner.prohibit({ id: 'freeze-ban', global: true, actions: ['freeze'], resources: ['ledger'] }));
  await h.step(owner.grant({ id: 'temp', to: 'intern', actions: ['read'], resources: ['vault'], expiresAt: 800 }));
  await h.step(owner.revoke('temp'));
  await h.step(owner.grant({ id: 'short', to: 'cadet', actions: ['write'], resources: ['ledger'], expiresAt: 101 }));
  await h.step(owner.grant({ id: 'future', to: 'novice', actions: ['pay'], resources: ['ledger'], notBefore: 900, expiresAt: 1000 }));
  await h.step(owner.grant({ id: 'budget', to: 'buyer', actions: ['pay'], resources: ['ledger'], expiresAt: 800, maxAmount: 100n }));
  const spender = runtimeKey(4), stamper = runtimeKey(5);
  await h.step(owner.createAgent({ id: 'spender' }));
  await h.step(owner.createAgent({ id: 'stamper' }));
  await h.step(owner.createRole({ id: 'cashier' }));
  await h.step(owner.createRole({ id: 'registrar' }));
  await h.step(owner.appoint({ agent: 'spender', role: 'cashier', tenure: 'cashier:1', number: 1 }));
  await h.step(owner.appoint({ agent: 'stamper', role: 'registrar', tenure: 'registrar:1', number: 1 }));
  await h.step(owner.admitRuntime({ session: 'session:spender', agent: 'spender', epoch: 1, key: 'key:spender', credential: spender.credential, expiresAt: 900 }));
  await h.step(owner.admitRuntime({ session: 'session:stamper', agent: 'stamper', epoch: 1, key: 'key:stamper', credential: stamper.credential, expiresAt: 900 }));
  await h.step(owner.grant({ id: 'metered', to: 'spender', actions: ['spend'], resources: ['petty-cash'], expiresAt: 800, maxAmount: 100n, maxCumulativeAmount: 100n, maxTransactions: 3 }));
  await h.step(owner.grant({ id: 'counted', to: 'stamper', actions: ['stamp'], resources: ['forms'], expiresAt: 800, maxTransactions: 1 }));
  const spendSim = openLocalSimulation({ ...h.config, session: 'session:spender', signHash: spender.signHash });
  const spend = (id, amount) => ({ id, action: 'spend', resource: 'petty-cash', role: 'cashier', tenure: 'cashier:1', termsCommitment: commitTerms({ purpose: id }), amount });
  for (const [id, amount] of [['spend:1', 60n], ['spend:2', 30n]]) {
    const run = await h.step(spendSim.run(spend(id, amount)));
    if (run.invocation?.status !== 'SUBMITTED') throw new Error(`${id} failed: ${JSON.stringify(run)}`);
  }
  const stampSim = openLocalSimulation({ ...h.config, session: 'session:stamper', signHash: stamper.signHash });
  const stamp = await h.step(stampSim.run({ id: 'stamp:1', action: 'stamp', resource: 'forms', role: 'registrar', tenure: 'registrar:1', termsCommitment: commitTerms({ purpose: 'stamp:1' }) }));
  if (stamp.invocation?.status !== 'SUBMITTED') throw new Error(`stamp failed: ${JSON.stringify(stamp)}`);
  await h.step(owner.createAgent({ id: 'leaver' }));
  await h.step(owner.createRole({ id: 'desk' }));
  await h.step(owner.declareSuccession({ id: 'desk-succession', from: 'leaver', to: 'heir', role: 'desk' }));
  await h.step(owner.appoint({ agent: 'leaver', role: 'desk', tenure: 'desk:1', number: 1, succession: 'desk-succession' }));
  await h.step(owner.grant({ id: 'leaver-read', to: 'leaver', actions: ['read'], resources: ['ledger'], expiresAt: 800 }));
  await h.step(owner.terminate({ agent: 'leaver', succession: 'desk-succession', role: 'desk', tenure: 'desk:1' }));
  save('authority-v1', readStore(h.historyFile), h.historyFile);
}

// ---------------------------------------------------------------- migrated-v1: the legacy handover fixture re-recorded under format 1

const migration = {};
{
  const source = join(ROOT, 'packages/reference-0.2/tests/fixtures/handover-history.jsonl');
  const target = join(WORK, 'migrated.jsonl');
  // A real Continuity 0.x history is unpinned (acceptUnpinnedSource); the migration commits the new owner key to a next key in the genesis.
  migration.nextKey = keyPairFromPrivateKey('ed25519', 'owner:2', seed(0x1201));
  const result = await migrateHistory({ source, target, signer: ownerSigner, nextSigner: signer.signerFromKeyPair(migration.nextKey), now: () => 1000, acceptUnpinnedSource: true });
  migration.events = readStore(target);
  save('migrated-v1', migration.events, target);
  if (migration.events[0].data.migratedFrom.position !== 25) throw new Error('unexpected migration position');
  if (JSON.stringify(migration.events[0].data.nextKeyDigests) !== JSON.stringify([digestOf(migration.nextKey)]) || JSON.stringify(result.nextKeyDigests) !== JSON.stringify(migration.events[0].data.nextKeyDigests)) throw new Error('the migrated genesis must commit to the next key');
}

// ---------------------------------------------------------------- rotation-v1: the opt-out history (no next-key commitment), rotated by the key in force alone

const rotation = {};
{
  rotation.newKey = keyPairFromPrivateKey('ed25519', 'owner:2', seed(0x1002));
  rotation.strangerKey = keyPairFromPrivateKey('ed25519', 'owner:stranger', seed(0x1003));
  const h = scripted('rotation', { nextKey: false });
  const owner = await createLocalOwner(h.config);
  await h.step(owner.createAgent({ id: 'bea' }));
  await h.step(owner.grant({ id: 'read', to: 'bea', actions: ['read'], resources: ['ledger'], expiresAt: 900 }));
  rotation.before = readStore(h.historyFile).length;
  const rotated = await h.step(owner.rotateOwnerKey({ newSigner: signer.signerFromKeyPair(rotation.newKey), reason: 'scheduled rotation', nextKey: false }));
  rotation.position = rotated.head.position;
  await h.step(owner.createAgent({ id: 'alex' }));
  await h.step(owner.revoke('read'));
  rotation.events = readStore(h.historyFile);
  save('rotation-v1', rotation.events, h.historyFile);
  const events = rotation.events;
  if (events[0].data.nextKeyDigests !== undefined || events[rotation.position].type !== 'OWNER_KEYS_ROTATED' || events[rotation.position].data.nextKeyDigests !== undefined) throw new Error('rotation-v1 must carry no commitment');
  if (events[rotation.position + 1].data.controlAuthorization.keyId !== 'owner:2') throw new Error('unexpected rotation history');
}

// ---------------------------------------------------------------- pre-rotation-v1: the genesis commitment, then a pre-rotated rotation

const preRotation = {};
{
  const h = scripted('pre-rotation');
  const owner = await createLocalOwner(h.config);
  await h.step(owner.createAgent({ id: 'bea' }));
  await h.step(owner.grant({ id: 'read', to: 'bea', actions: ['read'], resources: ['ledger'], expiresAt: 900 }));
  preRotation.before = readStore(h.historyFile).length;
  const rotated = await h.step(owner.rotateOwnerKey({ nextSigner: signer.signerFromKeyPair(nextKey), newNextSigner: signer.signerFromKeyPair(nextNextKey), reason: 'scheduled pre-rotated rotation' }));
  if (!rotated.preRotated) throw new Error('expected a pre-rotated rotation');
  await h.step(owner.createAgent({ id: 'alex' }));
  preRotation.events = readStore(h.historyFile);
  save('pre-rotation-v1', preRotation.events, h.historyFile);
  const events = preRotation.events;
  if (JSON.stringify(events[0].data.nextKeyDigests) !== JSON.stringify([digestOf(nextKey)]) || events[rotated.head.position].data.nextKeyAuthorizations?.[0]?.keyId !== 'owner:2') throw new Error('unexpected pre-rotation history');
}

// ---------------------------------------------------------------- witness-bound-v1: owner-signed WITNESSES_BOUND / WITNESSES_UNBOUND over handover-v1

const binding = {};
{
  // What createLocalOwner / witness add / removeWitness write. Replay validates the events (a closed schema; each REGISTERED
  // receipt verified with its witness's key against this very genesis; the policy quorum against the witnesses bound after
  // the event; an accepted loss against the history) and applies them to the bound witnesses.
  const noteKey = (name, fill) => transparency.noteSignerFromSeed(name, new Uint8Array(32).fill(fill));
  const signerA = noteKey('witness-a.example.org', 0x51), signerB = noteKey('witness-b.example.org', 0x52);
  const vkeyOf = (s) => transparency.verifierKey(s.name, s.publicKey);
  binding.witnesses = [
    { url: 'https://witness-a.example.org', verifierKey: vkeyOf(signerA), name: 'witness-a' },
    { url: 'https://witness-b.example.org', verifierKey: vkeyOf(signerB) },
  ];
  // A witness's signed receipt of the REGISTERED leaf of a genesis (a one-leaf log; fixed receivedAt), as the witness returns it.
  binding.registrationOf = (noteSigner, genesis, origin) => {
    const entry = { version: transparency.WITNESS_ENTRY_VERSION, kind: 'REGISTERED', historyId: new core.HistoryHasher(TRELLIS_FORMAT).push(revive(genesis)), genesis, receivedAt: 1_767_225_600_000 };
    const tree = new transparency.MerkleTree();
    tree.append(transparency.entryLeafHash(entry));
    const checkpoint = transparency.signNote(transparency.formatCheckpoint(origin, 1, tree.root(1)), noteSigner);
    return plain(transparency.buildReceipt({ origin, verifierKey: vkeyOf(noteSigner), entry, index: 0, checkpoint, inclusionProof: tree.inclusionProof(0, 1) }));
  };
  binding.signerA = signerA;
  binding.registrationA = binding.registrationOf(signerA, handover.events[0], 'witness-a.example.org/log');
  binding.policy = (quorum, maxUnwitnessedEvents = 100) => ({ quorum, requireOnOpen: true, maxUnwitnessedEvents });
  const [a, b] = binding.witnesses;
  binding.bound = await signedOn(handover.events, { id: 'binding:1', type: 'WITNESSES_BOUND', data: core.witnessBindingEvent({ action: 'BIND', witnesses: [{ ...a, registration: binding.registrationA }, b], policy: binding.policy(2) }).data });
  binding.events = await signedOn(binding.bound, { id: 'binding:2', type: 'WITNESSES_UNBOUND', data: core.witnessBindingEvent({ action: 'UNBIND', witnesses: [b], policy: binding.policy(1) }).data });
  const state = replay(revive(binding.events)).state;
  if (core.boundWitnessesOf(state).map((w) => w.url).join() !== a.url) throw new Error('binding history: expected one bound witness');
  if (JSON.stringify(core.boundPolicyOf(state)) !== JSON.stringify(binding.policy(1))) throw new Error('binding history: expected the UNBIND policy in force');
  if (core.boundRegistrationOf(state, a.verifierKey)?.index !== 0) throw new Error('binding history: expected the verified registration');
  save('witness-bound-v1', binding.events);
}

// ================================================================ vectors

const TOPICS = ['genesis-and-control-signatures', 'owner-keys', 'anchors-and-witness-bindings', 'migration', 'authorization', 'survives', 'attestation'];
const vectors = [];
let topic;
const section = (name) => { if (!TOPICS.includes(name)) throw new Error(`unknown topic ${name}`); topic = name; };

// ---------------------------------------------------------------- projections (identical to the adapters)

const projectAuthorize = (result) => ({
  decision: result.decision, code: result.code ?? null, scopeAssurance: result.scopeAssurance ?? null,
  controllingAuthorityIds: plain(result.proof?.controllingAuthorityIds ?? null), failureCodes: (result.failures ?? []).map((f) => f.code),
});
const projectSurvives = (result) => {
  if (!Object.hasOwn(result, 'answer')) return { established: false, code: result.code, epistemicStatus: result.epistemicStatus };
  const a = result.answer;
  return {
    established: true, exists: a.exists, lifecycleStatus: a.lifecycleStatus, obligationIds: a.obligations.map((r) => r.obligationId).sort(),
    currentAssignments: a.currentPerformanceAssignments.map((r) => ({ obligationId: r.obligationId, assigneeId: r.assigneeId, successionRuleId: r.successionRuleId ?? null })),
    currentRoleTenureCount: a.currentRoleTenures.length, transferredRoleTenureCount: a.transferredRoleTenures.length,
    invalidatedAuthorityIds: a.invalidatedAuthorityDependencies.map((r) => r.authorityId).sort(), unresolvedIntentIds: a.unresolvedIntents.map((r) => r.intentId).sort(),
  };
};

/** The format-1 facts a replay establishes, projected exactly as the adapters report them (a vector declares the ones it tests). */
const FACTS = {
  boundWitnesses: (state) => state.boundWitnesses.map((w) => w.verifierKey),
  boundPolicy: (state) => plain(state.boundPolicy ?? null),
  nextKeyDigests: (state) => plain(state.ownerKeyEpochs.at(-1)?.nextKeyDigests ?? null),
};
/**
 * A replay vector: `expect` pins the status, the head (`null` when rejected), the rejection `code` (`null` when accepted)
 * and any declared `facts`. `expected` is the code the vector is about (`null`: accepted); the generator refuses to write a
 * vector whose reference answer differs, and a reason when given.
 */
function replayVector(id, purpose, events, expected, options = {}) {
  const result = replay(revive(events));
  const code = result.status === 'REJECTED' ? result.code : null;
  if (code !== expected.code) throw new Error(`${id}: expected ${expected.code ?? 'ACCEPTED'}, got ${code ?? 'ACCEPTED'} (${result.reason ?? ''})`);
  if (expected.reason !== undefined && result.reason !== expected.reason) throw new Error(`${id}: expected reason ${expected.reason}, got ${result.reason ?? ''}`);
  const facts = Object.fromEntries((options.facts ?? []).map((name) => [name, result.status === 'ACCEPTED' ? FACTS[name](result.state) : null]));
  for (const [name, value] of Object.entries(options.expectFacts ?? {})) {
    if (JSON.stringify(facts[name]) !== JSON.stringify(value)) throw new Error(`${id}: ${name} expected ${JSON.stringify(value)}, got ${JSON.stringify(facts[name])}`);
  }
  const expect = { status: result.status, head: result.status === 'ACCEPTED' ? plain(result.head) : null, code, ...facts };
  vectors.push({ id, kind: 'replay', topic, purpose, input: { operationVersion: core.REPLAY_VERSION }, events, expect, ...(result.status === 'REJECTED' ? { rejection: { code: result.code, position: result.position ?? null } } : {}) });
}
const ACCEPTED = Object.freeze({ code: null });
const rejected = (code, reason) => Object.freeze({ code, ...(reason === undefined ? {} : { reason }) });
/** An owner head attestation judged against a history prefix: signed by a key in force at its position (`ownerKeysAt`), and a prefix of the history. */
function attestationVector(id, purpose, ref, eventCount, attestation, expected) {
  const events = histories[ref].slice(0, eventCount);
  const result = replay(revive(events));
  if (result.status !== 'ACCEPTED') throw new Error(`${id}: history rejected`);
  const state = result.state, a = plain(attestation), p = a.head.position;
  const expect = { signatureValid: core.verifyHeadAttestationAt(a, state), prefix: Number.isSafeInteger(p) && p >= 0 && p <= state.head.position && state.eventHistoryHashes[p] === a.head.hash };
  expect.valid = expect.signatureValid && expect.prefix;
  for (const [key, value] of Object.entries(expected)) if (expect[key] !== value) throw new Error(`${id}: ${key} expected ${value}, got ${expect[key]}`);
  vectors.push({ id, kind: 'attestation', topic, purpose, history: { ref, eventCount, head: plain(result.head) }, input: { attestation: a }, expect });
}
function authorizationVector(id, purpose, ref, request, options = {}) {
  const events = histories[ref];
  const head = headOf(events);
  const input = {
    operationVersion: core.AUTHORIZATION_VERSION, expectedHistoryHead: options.head ?? head, domain: options.domain ?? events[0].data.domain, policyVersion: options.policyVersion ?? events[0].data.policyVersion,
    rootRecognitionPolicy: 'declared-principal-root/0.2', request: plain(request), evaluationTime: options.at ?? head.canonicalTime, authoritative: true, consequential: false,
  };
  const result = authorizePortable({ ...revive(input), events: revive(events) }, replay);
  const expect = projectAuthorize(result);
  if (options.expectCode !== undefined && expect.code !== options.expectCode) throw new Error(`${id}: expected ${options.expectCode}, got ${JSON.stringify(expect)}`);
  if (options.expectDecision !== undefined && expect.decision !== options.expectDecision) throw new Error(`${id}: expected ${options.expectDecision}, got ${JSON.stringify(expect)}`);
  vectors.push({ id, kind: 'authorization', topic, purpose, history: { ref, eventCount: events.length, head }, input, expect });
}
function survivesVector(id, purpose, ref, agent, eventCount, checks) {
  const events = histories[ref].slice(0, eventCount);
  const head = headOf(events);
  const input = { operationVersion: core.QUERY_VERSION, targetAgentId: agent, evaluationTime: head.canonicalTime };
  const result = survivesPortable({ operationVersion: core.QUERY_VERSION, observedEvents: revive(events), targetAgentId: agent, evaluationTime: head.canonicalTime, disclosure: publicQueryDisclosure('SURVIVES') }, replay);
  const expect = projectSurvives(result);
  for (const [key, value] of Object.entries(checks)) if (JSON.stringify(expect[key]) !== JSON.stringify(value)) throw new Error(`${id}: ${key} expected ${JSON.stringify(value)}, got ${JSON.stringify(expect[key])}`);
  vectors.push({ id, kind: 'survives', topic, purpose, history: { ref, eventCount, head }, input, expect });
}

// ---------------------------------------------------------------- genesis and control signatures

section('genesis-and-control-signatures');
{
  const events = handover.events;
  replayVector('replay/v1/accepts-signed-handover', 'A format-1 handover history with owner-signed control events, a simulated admission, a receipt, an obligation and a succession replays to a stable head.', events, ACCEPTED);
  replayVector('replay/v1/accepts-prefix-before-handover', 'Every prefix of a valid format-1 history is valid: the history as it stood before the succession.', events.slice(0, handover.before), ACCEPTED);
  const controlIndex = events.findIndex((e) => e.type === 'AUTHORITY_GRANTED');
  const unsigned = events.map((e, i) => (i === controlIndex ? { ...e, data: Object.fromEntries(Object.entries(e.data).filter(([k]) => k !== 'controlAuthorization')) } : e));
  replayVector('replay/v1/rejects-unsigned-control-event', 'A control event without its owner signature is refused (CONTROL_AUTHORIZATION_INVALID).', unsigned, rejected('CONTROL_AUTHORIZATION_INVALID'));
  const tampered = events.map((e, i) => {
    if (i !== controlIndex) return e;
    const sig = e.data.controlAuthorization.signature;
    const flipped = `${sig.slice(0, 10)}${sig[10] === '0' ? '1' : '0'}${sig.slice(11)}`;
    return { ...e, data: { ...e.data, controlAuthorization: { ...e.data.controlAuthorization, signature: flipped } } };
  });
  replayVector('replay/v1/rejects-tampered-control-signature', 'A control event whose signature bytes were altered is refused (CONTROL_AUTHORIZATION_INVALID).', tampered, rejected('CONTROL_AUTHORIZATION_INVALID'));
  const grants = events.map((e, i) => [e, i]).filter(([e]) => e.type === 'AUTHORITY_GRANTED').map(([, i]) => i);
  const moved = events.slice();
  [moved[grants[1]], moved[grants[2]]] = [events[grants[2]], events[grants[1]]];
  replayVector('replay/v1/rejects-moved-control-event', 'Two independently valid, signed grants swapped in position are refused (CONTROL_AUTHORIZATION_INVALID): each signature binds the head before its event.', moved, rejected('CONTROL_AUTHORIZATION_INVALID'));
  const forged = events.map((e, i) => (i === controlIndex ? { ...e, data: { ...e.data, grant: { ...e.data.grant, constraints: { ...e.data.grant.constraints, expiresAt: 999999 } } } } : e));
  replayVector('replay/v1/rejects-altered-control-effect', 'Editing the content of a signed grant (its expiry) invalidates the owner signature over its effect hash (CONTROL_AUTHORIZATION_INVALID).', forged, rejected('CONTROL_AUTHORIZATION_INVALID'));
  const unknownKey = events.map((e, i) => (i === controlIndex ? { ...e, data: { ...e.data, controlAuthorization: { ...e.data.controlAuthorization, keyId: 'owner:unknown' } } } : e));
  replayVector('replay/v1/rejects-undeclared-owner-key', 'A control event claiming a key id the genesis does not declare is refused (CONTROL_AUTHORIZATION_INVALID).', unknownKey, rejected('CONTROL_AUTHORIZATION_INVALID'));
}

// ---------------------------------------------------------------- owner keys: the genesis commitment, rotation, pre-rotation, commitment-only rotation

section('owner-keys');
{
  // The genesis commitment (every history but the opt-out one carries it).
  const genesis = preRotation.events[0];
  const prefix = preRotation.events.slice(0, preRotation.before);
  replayVector('replay/v1/accepts-genesis-commitment', 'The genesis commits the owner keys to the digest of their next key (nextKeyDigests, part of the history id; pre-rotation from the first event); createLocalOwner writes it by default.', prefix, ACCEPTED,
    { facts: ['nextKeyDigests'], expectFacts: { nextKeyDigests: [digestOf(nextKey)] } });
  const withDigests = (nextKeyDigests) => [{ ...genesis, data: { ...genesis.data, nextKeyDigests } }];
  replayVector('replay/v1/rejects-genesis-commitment-naming-an-owner-key', 'A genesis whose next-key commitment names one of its own owner keys is refused (EVENT_DATA_INVALID): a declared key can never be revealed as a next key.', withDigests([digestOf(nextKey), digestOf(ownerKey)]), rejected('EVENT_DATA_INVALID'));
  replayVector('replay/v1/rejects-genesis-commitment-duplicate-digest', 'A genesis whose next-key commitment repeats a digest is refused by the closed schema (EVENT_DATA_INVALID).', withDigests([digestOf(nextKey), digestOf(nextKey)]), rejected('EVENT_DATA_INVALID'));
  replayVector('replay/v1/rejects-genesis-commitment-empty', 'A genesis whose next-key commitment is empty is refused by the closed schema (EVENT_DATA_INVALID): a genesis without a commitment leaves nextKeyDigests out.', withDigests([]), rejected('EVENT_DATA_INVALID'));

  // Rotation out of an uncommitted epoch (the opt-out history, rotation-v1): the key in force alone rotates.
  const events = rotation.events, r = rotation.position;
  const newSigner = signer.signerFromKeyPair(rotation.newKey), strangerSigner = signer.signerFromKeyPair(rotation.strangerKey);
  replayVector('replay/v1/accepts-owner-key-rotation', 'On a history created without a next-key commitment, OWNER_KEYS_ROTATED signed by the current owner key replaces the owner key set: the control events after it are signed by the new key and the history replays.', events, ACCEPTED,
    { facts: ['nextKeyDigests'], expectFacts: { nextKeyDigests: null } });
  const upToRotation = events.slice(0, r + 1), beforeRotation = events.slice(0, r);
  replayVector('replay/v1/rejects-control-event-signed-by-retired-key', 'After a rotation the retired owner key can no longer sign a control event (CONTROL_AUTHORIZATION_INVALID), although it signed every control event before the rotation.',
    await signedOn(upToRotation, { id: 'rotation:late', type: 'AGENT_CREATED', timestamp: events[r].timestamp, data: { agentId: 'late', principalId: 'operations', controllerId: 'operator', initialControlEpoch: 1 } }), rejected('CONTROL_AUTHORIZATION_INVALID'));
  replayVector('replay/v1/rejects-rotation-signed-by-unknown-key', 'A rotation signed by a key the history never declared is refused (CONTROL_AUTHORIZATION_INVALID): only a key in force may replace the owner keys.',
    await rotateOn(beforeRotation, 'rotation:stranger', { ownerKeys: [{ ...ok(rotation.strangerKey), keyId: 'owner:stranger' }] }, strangerSigner), rejected('CONTROL_AUTHORIZATION_INVALID'));
  replayVector('replay/v1/rejects-retired-key-id-reuse', 'A rotation that brings a retired key id back is refused (TRANSITION_INVALID), even when signed by the key in force: a retired key never returns.',
    await rotateOn(events, 'rotation:back', { ownerKeys: [ok(ownerKey)] }, newSigner), rejected('TRANSITION_INVALID'));
  replayVector('replay/v1/rejects-rotation-rebinding-a-key-id', 'A rotation that keeps a key id but binds it to a different public key is refused (TRANSITION_INVALID).',
    await rotateOn(beforeRotation, 'rotation:rebound', { ownerKeys: [{ ...ok(rotation.newKey), keyId: 'owner:1' }] }, ownerSigner), rejected('TRANSITION_INVALID'));
  replayVector('replay/v1/rejects-rotation-in-legacy-history', 'A legacy (continuity-event/0.2) history has no owner keys: OWNER_KEYS_ROTATED is UNSUPPORTED_EVENT_TYPE there.',
    [...LEGACY_FIXTURE, { id: 'rotation:legacy', type: 'OWNER_KEYS_ROTATED', timestamp: LEGACY_FIXTURE.at(-1).timestamp, data: { ownerKeys: [ok(rotation.newKey)] } }], rejected('UNSUPPORTED_EVENT_TYPE'));
  replayVector('replay/v1/accepts-rotation-without-commitment', 'An owner key epoch without a commitment rotates freely, signed by the current key alone, and may start a commitment for the new set (nextKeyDigests).',
    await rotateOn(beforeRotation, 'rotation:starts-commitment', { ownerKeys: [ok(nextKey)], nextKeyDigests: [digestOf(nextNextKey)] }, ownerSigner), ACCEPTED,
    { facts: ['nextKeyDigests'], expectFacts: { nextKeyDigests: [digestOf(nextNextKey)] } });
  replayVector('replay/v1/accepts-commitment-only-rotation', 'An owner key epoch without a commitment gets one by a rotation that keeps every owner key and carries nextKeyDigests (the commitment-only rotation that owner commit-next-key records); the same key keeps signing.',
    await rotateOn(beforeRotation, 'commit:later', { ownerKeys: [ok(ownerKey)], reason: 'next-key commitment', nextKeyDigests: [digestOf(nextKey)] }, ownerSigner), ACCEPTED,
    { facts: ['nextKeyDigests'], expectFacts: { nextKeyDigests: [digestOf(nextKey)] } });
  replayVector('replay/v1/rejects-carry-over-rotation-without-commitment', 'A rotation that keeps every owner key and carries no nextKeyDigests changes nothing and is refused (TRANSITION_INVALID).',
    await rotateOn(beforeRotation, 'rotation:noop', { ownerKeys: [ok(ownerKey)], reason: 'nothing' }, ownerSigner), rejected('TRANSITION_INVALID'));

  // Rotation out of a committed epoch (pre-rotation-v1): only a pre-rotated rotation.
  const nextSigner = signer.signerFromKeyPair(nextKey);
  const stranger = keyPairFromPrivateKey('ed25519', 'owner:stranger', seed(0x1109));
  replayVector('replay/v1/accepts-pre-rotated-rotation', 'A rotation out of a committed epoch that reveals the committed key, carries that key\'s signature over the event\'s control-authorization challenge (nextKeyAuthorizations) and commits the new set to its own next key is accepted; the revealed key signs from the next position on.', preRotation.events, ACCEPTED,
    { facts: ['nextKeyDigests'], expectFacts: { nextKeyDigests: [digestOf(nextNextKey)] } });
  replayVector('replay/v1/rejects-rotation-to-uncommitted-key', 'A rotation out of a committed epoch to a key the commitment does not name is refused (TRANSITION_INVALID), although the current key signed it and the new key proved possession: the current key alone cannot rotate.',
    await rotateOn(prefix, 'rotation:uncommitted', { ownerKeys: [ok(stranger)], nextKeyDigests: [digestOf(nextNextKey)] }, ownerSigner, [['owner:stranger', signer.signerFromKeyPair(stranger)]]), rejected('TRANSITION_INVALID'));
  replayVector('replay/v1/rejects-revealed-key-without-proof', 'Revealing the committed public key without a signature by it (no nextKeyAuthorizations) is refused (TRANSITION_INVALID): the public key alone proves nothing.',
    await rotateOn(prefix, 'rotation:no-proof', { ownerKeys: [ok(nextKey)], nextKeyDigests: [digestOf(nextNextKey)] }, ownerSigner), rejected('TRANSITION_INVALID'));
  replayVector('replay/v1/rejects-pre-rotated-rotation-without-next-commitment', 'A rotation out of a committed epoch that reveals and proves the committed key but carries no nextKeyDigests is refused (TRANSITION_INVALID): the commitment chain must continue.',
    await rotateOn(prefix, 'rotation:no-next', { ownerKeys: [ok(nextKey)] }, ownerSigner, [['owner:2', nextSigner]]), rejected('TRANSITION_INVALID'));
  replayVector('replay/v1/rejects-commitment-only-rotation-out-of-committed-epoch', 'A rotation that keeps every owner key and commits to another next key, out of an epoch that already has a commitment, is refused (TRANSITION_INVALID), although the key in force signed it: it reveals no committed key, so a leaked current key cannot replace the commitment.',
    await rotateOn(prefix, 'commit:second', { ownerKeys: [ok(ownerKey)], reason: 'next-key commitment', nextKeyDigests: [digestOf(stranger)] }, ownerSigner), rejected('TRANSITION_INVALID'));
}

// ---------------------------------------------------------------- anchors and witness bindings

section('anchors-and-witness-bindings');
{
  const base = handover.events;
  replayVector('replay/v1/accepts-anchor', 'An ANCHOR_RECORDED event whose anchored head is a prefix of this history is accepted.', handover.anchored, ACCEPTED);
  const badAnchorUnsigned = { ...handover.anchor, data: { ...Object.fromEntries(Object.entries(handover.anchor.data).filter(([k]) => k !== 'controlAuthorization')), anchoredHead: { ...handover.anchor.data.anchoredHead, hash: `0x${'cd'.repeat(32)}` } } };
  replayVector('replay/v1/rejects-bad-anchor', 'A correctly signed anchor whose anchored head hash is not a prefix hash of this history is refused (TRANSITION_INVALID).',
    await signedOn(base, plain(badAnchorUnsigned)), rejected('TRANSITION_INVALID'));

  const { witnesses, registrationA, policy } = binding;
  const facts = ['boundWitnesses', 'boundPolicy'];
  replayVector('replay/v1/accepts-witness-bindings', 'Owner-signed WITNESSES_BOUND (two remote witnesses, the first with its signed REGISTERED receipt of this genesis, and the policy minimum) then WITNESSES_UNBOUND (the second) replay; the history binds the first witness under the newest policy. A verifier that does not speak the witness protocol still reports the bindings.', binding.events, ACCEPTED,
    { facts, expectFacts: { boundWitnesses: [witnesses[0].verifierKey], boundPolicy: policy(1) } });
  const [bind] = binding.events.slice(base.length);
  const forged = { ...bind, data: { ...bind.data, witnesses: [{ ...bind.data.witnesses[0], url: 'https://attacker.example.org' }, bind.data.witnesses[1]] } };
  replayVector('replay/v1/rejects-altered-witness-binding', 'A binding whose witness list was edited after signing is refused: the owner signature covers every witness (CONTROL_AUTHORIZATION_INVALID).', [...base, forged], rejected('CONTROL_AUTHORIZATION_INVALID'));
  const bindWith = (data, list = base) => signedOn(list, { id: 'binding:bad', type: 'WITNESSES_BOUND', data });
  replayVector('replay/v1/rejects-witness-binding-with-malformed-receipt', 'A binding whose registration is not a witness receipt (here: a receipt record with its inclusion proof removed) is refused, although the owner signed it (TRANSITION_INVALID).',
    await bindWith({ witnesses: [{ ...witnesses[0], registration: (({ inclusionProof: _proof, ...rest }) => rest)(registrationA) }], policy: policy(1) }), rejected('TRANSITION_INVALID'));
  replayVector('replay/v1/rejects-witness-binding-with-another-witness-receipt', 'A binding that files witness A\'s receipt under witness B\'s verifier key is refused: a registration must be signed by the witness it binds (TRANSITION_INVALID).',
    await bindWith({ witnesses: [{ ...witnesses[1], registration: registrationA }], policy: policy(1) }), rejected('TRANSITION_INVALID'));
  replayVector('replay/v1/rejects-witness-binding-receipt-with-unknown-field', 'A binding whose registration is witness A\'s valid receipt of this history plus a field a witness receipt does not have is refused: the receipt record is closed (TRANSITION_INVALID).',
    await bindWith({ witnesses: [{ ...witnesses[0], registration: { ...registrationA, comment: 'not part of a receipt' } }], policy: policy(1) }), rejected('TRANSITION_INVALID'));
  const foreign = binding.registrationOf(binding.signerA, { ...base[0], id: 'another-genesis' }, 'witness-a.example.org/log');
  replayVector('replay/v1/rejects-witness-binding-with-another-history-receipt', 'A binding whose registration is witness A\'s valid receipt of another history\'s REGISTERED leaf is refused: it must name this genesis (TRANSITION_INVALID).',
    await bindWith({ witnesses: [{ ...witnesses[0], registration: foreign }], policy: policy(1) }), rejected('TRANSITION_INVALID'));
  replayVector('replay/v1/rejects-witness-binding-with-malformed-policy', 'A binding whose policy minimum has quorum 0 is refused by the closed schema (EVENT_DATA_INVALID).',
    await bindWith({ witnesses: [witnesses[0]], policy: { quorum: 0, requireOnOpen: true, maxUnwitnessedEvents: 100 } }), rejected('EVENT_DATA_INVALID'));
  replayVector('replay/v1/rejects-witness-binding-without-policy', 'A binding without its policy minimum is refused by the closed schema (EVENT_DATA_INVALID): every binding event states the policy in force after it.',
    await bindWith({ witnesses: [witnesses[0]] }), rejected('EVENT_DATA_INVALID'));
  replayVector('replay/v1/rejects-witness-binding-quorum-above-bound', 'A binding whose policy quorum (2) exceeds the witnesses bound after it (1) is refused (TRANSITION_INVALID).',
    await bindWith({ witnesses: [witnesses[0]], policy: policy(2) }), rejected('TRANSITION_INVALID'));
  replayVector('replay/v1/rejects-witness-binding-with-invalid-url', 'A binding whose witness URL carries a query string is refused by the closed schema (EVENT_DATA_INVALID): a witness URL is http(s)://host[/path] without userinfo, query, fragment or trailing slash.',
    await bindWith({ witnesses: [{ ...witnesses[0], url: 'https://witness-a.example.org/log?token=1' }], policy: policy(1) }), rejected('EVENT_DATA_INVALID'));
  replayVector('replay/v1/rejects-witness-binding-with-duplicate-verifier-key', 'A binding that names one verifier key twice is refused by the closed schema (EVENT_DATA_INVALID).',
    await bindWith({ witnesses: [witnesses[0], { ...witnesses[0], url: 'https://witness-a2.example.org' }], policy: policy(1) }), rejected('EVENT_DATA_INVALID'));
  const extra = Array.from({ length: 16 }, (_, n) => {
    const s = transparency.noteSignerFromSeed(`witness-${n}.example.org`, new Uint8Array(32).fill(0x60 + n));
    return { url: `https://witness-${n}.example.org`, verifierKey: transparency.verifierKey(s.name, s.publicKey) };
  });
  replayVector('replay/v1/rejects-witness-binding-above-sixteen-bound', 'A binding of sixteen more witnesses on a history that already binds one (seventeen bound after it) is refused (TRANSITION_INVALID): at most sixteen remote witnesses are bound.',
    await bindWith({ witnesses: extra, policy: policy(1) }, binding.events), rejected('TRANSITION_INVALID'));
  replayVector('replay/v1/rejects-witness-binding-in-legacy-history', 'A legacy (continuity-event/0.2) history has no owner keys and binds no witness: WITNESSES_BOUND is UNSUPPORTED_EVENT_TYPE there.',
    [...LEGACY_FIXTURE, { id: 'binding:legacy', type: 'WITNESSES_BOUND', timestamp: LEGACY_FIXTURE.at(-1).timestamp, data: { witnesses: [witnesses[0]], policy: policy(1) } }], rejected('UNSUPPORTED_EVENT_TYPE'));
  replayVector('replay/v1/accepts-rebinding-a-bound-witness', 'Binding a witness the history already binds (the same verifier key) re-binds it in place: its URL, name and registration are replaced and it is still bound once (how a witness bound while unreachable gets its REGISTERED receipt later).',
    await bindWith({ witnesses: [{ ...witnesses[0], url: 'https://witness-a.example.org/v2', registration: registrationA }], policy: policy(1) }, binding.events), ACCEPTED,
    { facts, expectFacts: { boundWitnesses: [witnesses[0].verifierKey], boundPolicy: policy(1) } });
  replayVector('replay/v1/rejects-unbinding-of-unbound-witness', 'An unbinding that names a witness the history does not bind is refused (TRANSITION_INVALID).',
    await signedOn(binding.events, { id: 'binding:3', type: 'WITNESSES_UNBOUND', data: { verifierKeys: [witnesses[1].verifierKey], policy: policy(1) } }), rejected('TRANSITION_INVALID'));
  const containedLoss = { reason: 'restored a backup', heads: [{ verifierKey: witnesses[1].verifierKey, head: headOf(base) }] };
  replayVector('replay/v1/rejects-accepted-loss-of-a-contained-head', 'An unbinding that records an accepted loss of a head this history contains is refused: nothing was lost (TRANSITION_INVALID).',
    await signedOn(binding.bound, { id: 'binding:loss', type: 'WITNESSES_UNBOUND', data: { verifierKeys: [witnesses[1].verifierKey], policy: policy(1), acceptedLoss: containedLoss } }), rejected('TRANSITION_INVALID'));
  const lostHead = { hash: `0x${'ee'.repeat(32)}`, position: base.length + 5, canonicalTime: headOf(binding.bound).canonicalTime + 5 };
  replayVector('replay/v1/rejects-accepted-loss-of-a-witness-not-unbound', 'An unbinding whose accepted loss names a witness the event does not unbind (here: the one that stays bound) is refused (TRANSITION_INVALID): a loss is accepted only for a witness being unbound.',
    await signedOn(binding.bound, { id: 'binding:loss', type: 'WITNESSES_UNBOUND', data: { verifierKeys: [witnesses[1].verifierKey], policy: policy(1), acceptedLoss: { reason: 'restored a backup', heads: [{ verifierKey: witnesses[0].verifierKey, head: lostHead }] } } }), rejected('TRANSITION_INVALID'));
  replayVector('replay/v1/accepts-unbinding-with-accepted-loss', 'An unbinding that records an accepted loss (the owner\'s reason and a head the witness holds that this copy lacks) is accepted; the witness is no longer bound.',
    await signedOn(binding.bound, { id: 'binding:loss', type: 'WITNESSES_UNBOUND', data: { verifierKeys: [witnesses[1].verifierKey], policy: policy(1), acceptedLoss: { reason: 'restored a backup', heads: [{ verifierKey: witnesses[1].verifierKey, head: lostHead }] } } }), ACCEPTED,
    { facts, expectFacts: { boundWitnesses: [witnesses[0].verifierKey], boundPolicy: policy(1) } });
  // An anchor is evidence about a head: whatever its receipt holds, it binds, unbinds and re-policies nothing.
  const anchorWith = async (list, id, anchor, receipt) => {
    const at = replay(revive(list)).state.head;
    return signedOn(list, { id, type: 'ANCHOR_RECORDED', data: { anchoredHead: plain(at), anchor, receipt, anchoredAt: at.canonicalTime } });
  };
  const bindingShaped = { action: 'UNBIND', historyId: headOf(base.slice(0, 1)).hash, witnesses: [witnesses[0]], policy: { quorum: 1, requireOnOpen: false, maxUnwitnessedEvents: 1_000_000 } };
  replayVector('replay/v1/anchor-shaped-like-a-binding-binds-nothing', 'An owner-signed ANCHOR_RECORDED (anchor "custom") whose receipt is shaped like an unbinding of the bound witness is accepted as an anchor and changes nothing: the history still binds the witness under the signed policy.',
    await anchorWith(binding.events, 'anchor:binding-shaped', 'custom', bindingShaped), ACCEPTED, { facts, expectFacts: { boundWitnesses: [witnesses[0].verifierKey], boundPolicy: policy(1) } });
  replayVector('replay/v1/anchor-shaped-like-a-binding-binds-nothing-without-bindings', 'On a history that binds no witness, an ANCHOR_RECORDED whose receipt is shaped like a binding of witness A binds nothing (no bound witnesses, no policy).',
    await anchorWith(base, 'anchor:binding-shaped', 'custom', { ...bindingShaped, action: 'BIND', policy: policy(1) }), ACCEPTED, { facts, expectFacts: { boundWitnesses: [], boundPolicy: null } });
  replayVector('replay/v1/rejects-unknown-anchor-kind', 'ANCHOR_RECORDED.data.anchor names one of the anchor kinds local-head-file, rekor-v2 or custom: an anchor naming another ("http-witness") is refused by the closed schema (EVENT_DATA_INVALID).',
    await anchorWith(base, 'anchor:http', 'http-witness', bindingShaped), rejected('EVENT_DATA_INVALID'));
}

// ---------------------------------------------------------------- migration

section('migration');
{
  const events = migration.events;
  replayVector('replay/v1/accepts-migrated-history', 'A format-1 history migrated from the legacy handover fixture (26 events re-recorded verbatim under owner signatures, runtime signatures verified against the legacy shadow heads) replays; its genesis commits the new owner key to a next key.', events, ACCEPTED,
    { facts: ['nextKeyDigests'], expectFacts: { nextKeyDigests: [digestOf(migration.nextKey)] } });
  const declaration = events.findIndex((e) => e.type === 'TRANSACTION_INTENT_DECLARED');
  replayVector('replay/v1/rejects-truncated-migrated-prefix', 'Dropping a re-recorded event inside the migrated prefix breaks the legacy shadow heads the runtime-signed admission binds; the replay is refused inside the prefix (TRANSITION_INVALID).', [...events.slice(0, declaration), ...events.slice(declaration + 1)], rejected('TRANSITION_INVALID'));
  const prefixEnd = events[0].data.migratedFrom.position;
  replayVector('replay/v1/rejects-incomplete-migrated-prefix', 'A migrated history cut off before the end of its declared prefix (head position below migratedFrom.position) is refused once the replay completes: TRANSITION_INVALID, migrated prefix incomplete. Every event present is valid on its own, so only the completed-replay check catches it.', events.slice(0, prefixEnd), rejected('TRANSITION_INVALID', 'migrated prefix incomplete'));
  // A genesis that claims a shorter prefix, with every owner-signed event re-signed over the new heads: only the prefix rule can catch it.
  const shortened = [{ ...events[0], data: { ...events[0].data, migratedFrom: { ...events[0].data.migratedFrom, position: 24 } } }];
  {
    const hasher = new core.HistoryHasher(TRELLIS_FORMAT);
    let previous = { hash: hasher.push(revive(shortened[0])), position: 0 };
    for (const event of events.slice(1)) {
      let next = event;
      if (event.data?.controlAuthorization !== undefined) {
        const { controlAuthorization: _old, ...data } = event.data;
        next = plain(await signer.signControlEvent(ownerSigner, revive({ ...event, data }), revive(events[0].data.domain), previous, 'sha256'));
      }
      shortened.push(next);
      previous = { hash: hasher.push(revive(next)), position: previous.position + 1 };
    }
  }
  replayVector('replay/v1/rejects-shortened-migrated-prefix', 'A genesis that claims a shorter migrated prefix than the one re-recorded is refused (TRANSITION_INVALID), even with every owner signature redone over it: the legacy shadow hash at the claimed end is not the source head.', shortened, rejected('TRANSITION_INVALID'));
  // Inside a migrated legacy prefix the events re-record legacy ones, so a runtime session admission keeps the legacy
  // credential shape (an Ethereum address); an ed25519 admission there is refused, never applied to the legacy shadow view.
  const at = events.findIndex((e) => e.type === 'RUNTIME_SESSION_ADMITTED');
  const prefix = events.slice(0, at);
  const { credentialAddress: _address, controlAuthorization: _authorization, ...legacySession } = events[at].data;
  const unsigned = { id: 'migrated:ed25519-session', type: 'RUNTIME_SESSION_ADMITTED', timestamp: events[at].timestamp,
    data: { ...legacySession, sessionId: 'session:ed25519', credentialScheme: 'ed25519', credentialPublicKey: runtimeKey(9).credential } };
  const hasher = new core.HistoryHasher(TRELLIS_FORMAT);
  let previous;
  for (const [position, event] of prefix.entries()) previous = { hash: hasher.push(revive(event)), position }; // a migrated prefix alone is not ACCEPTED (incomplete), so no headOf
  const signed = await signer.signControlEvent(ownerSigner, revive(unsigned), revive(events[0].data.domain), previous, 'sha256');
  replayVector('replay/v1/rejects-ed25519-session-in-migrated-prefix', 'An owner-signed ed25519 runtime session admission inside a migrated legacy prefix is refused (EVENT_DATA_INVALID): the prefix re-records legacy events, whose session credentials are Ethereum addresses.',
    [...prefix, plain(signed)], rejected('EVENT_DATA_INVALID'));
  // The same place, an owner-signed witness binding: a migrated prefix re-records legacy events only.
  const bindingUnsigned = { id: 'migrated:binding', type: 'WITNESSES_BOUND', timestamp: events[at].timestamp, data: { witnesses: [binding.witnesses[0]], policy: binding.policy(1) } };
  const bindingSigned = await signer.signControlEvent(ownerSigner, revive(bindingUnsigned), revive(events[0].data.domain), previous, 'sha256');
  replayVector('replay/v1/rejects-witness-binding-in-migrated-prefix', 'An owner-signed WITNESSES_BOUND inside a migrated legacy prefix is refused (TRANSITION_INVALID): the prefix re-records legacy events, and a witness binding is not one.',
    [...prefix, plain(bindingSigned)], rejected('TRANSITION_INVALID'));
}

// ---------------------------------------------------------------- authorization

section('authorization');
{
  const at = headOf(handover.events).canonicalTime;
  const headVector = headOf(handover.events);
  authorizationVector('authorization/v1/successor-may-exercise-its-own-grant', 'The successor may do what it was separately granted.', 'handover-v1', { actorId: 'alex', action: 'read', resource: 'progress:42', claimedAt: at }, { expectDecision: 'ALLOW' });
  authorizationVector('authorization/v1/successor-does-not-inherit-collection', 'The successor holds the duty and must NOT inherit the power that created it.', 'handover-v1', { actorId: 'alex', action: 'read', resource: 'incident:42', claimedAt: at }, { expectDecision: 'DENY' });
  authorizationVector('authorization/v1/predecessor-refused-after-handover', 'A terminated agent is refused before any authority is considered (AGENT_INACTIVE).', 'handover-v1', { actorId: 'bea', action: 'read', resource: 'incident:42', claimedAt: at }, { expectCode: 'AGENT_INACTIVE' });
  authorizationVector('authorization/v1/history-relation-unverified', 'An expected head that is not the replayed head yields INDETERMINATE HISTORY_RELATION_UNVERIFIED.', 'handover-v1', { actorId: 'alex', action: 'read', resource: 'progress:42', claimedAt: at }, { head: { ...headVector, hash: `0x${'ab'.repeat(32)}` }, expectCode: 'HISTORY_RELATION_UNVERIFIED' });
  authorizationVector('authorization/v1/causal-time-invalid', 'An evaluation time before the head is not causal (CAUSAL_TIME_INVALID).', 'handover-v1', { actorId: 'alex', action: 'read', resource: 'progress:42', claimedAt: 1 }, { at: at - 1, expectCode: 'CAUSAL_TIME_INVALID' });
  authorizationVector('authorization/v1/domain-mismatch', 'A request under a different deployment is refused (DOMAIN_MISMATCH).', 'handover-v1', { actorId: 'alex', action: 'read', resource: 'progress:42', claimedAt: at }, { domain: { ...DOMAIN, deploymentId: 'elsewhere' }, expectCode: 'DOMAIN_MISMATCH' });

  const corpusAt = headOf(histories['authority-v1']).canonicalTime;
  const req = (actorId, action, resource, extra = {}) => ({ actorId, action, resource, claimedAt: corpusAt, ...extra });
  authorizationVector('authorization/v1/allow-via-delegation-with-intersection', 'A delegated grant that requires an intersection partner held by the actor is allowed; the proof controls the delegation chain and the partner.', 'authority-v1', req('analyst', 'write', 'ledger', { amount: 50n }), { expectDecision: 'ALLOW' });
  authorizationVector('authorization/v1/allow-via-delegation', 'A plain delegation from the lead to the analyst is allowed.', 'authority-v1', req('analyst', 'read', 'ledger', { amount: 5n }), { expectDecision: 'ALLOW' });
  authorizationVector('authorization/v1/missing-intersection', 'A grant whose required intersection partner is not held by the actor fails MISSING_INTERSECTION.', 'authority-v1', req('clerk', 'write', 'vault'), { expectCode: 'MISSING_INTERSECTION' });
  authorizationVector('authorization/v1/prohibited-root', 'A ROOT prohibition on the root grant blocks the lead\'s otherwise valid payment from the vault.', 'authority-v1', req('lead', 'pay', 'vault', { amount: 10n }), { expectCode: 'PROHIBITED' });
  authorizationVector('authorization/v1/prohibited-global', 'A GLOBAL prohibition by the policy source blocks an action any grant would allow.', 'authority-v1', req('guard', 'freeze', 'ledger'), { expectCode: 'PROHIBITED' });
  authorizationVector('authorization/v1/revoked', 'A revoked grant fails REVOKED.', 'authority-v1', req('intern', 'read', 'vault'), { expectCode: 'REVOKED' });
  authorizationVector('authorization/v1/expired', 'A grant whose expiry passed fails EXPIRED.', 'authority-v1', req('cadet', 'write', 'ledger'), { expectCode: 'EXPIRED' });
  authorizationVector('authorization/v1/not-yet-valid', 'A grant whose notBefore lies ahead fails NOT_YET_VALID.', 'authority-v1', req('novice', 'pay', 'ledger'), { expectCode: 'NOT_YET_VALID' });
  authorizationVector('authorization/v1/amount-required', 'A quantitative grant needs an amount in the request (AMOUNT_REQUIRED).', 'authority-v1', req('buyer', 'pay', 'ledger'), { expectCode: 'AMOUNT_REQUIRED' });
  authorizationVector('authorization/v1/amount-exceeded', 'An amount above the per-request ceiling fails AMOUNT_EXCEEDED.', 'authority-v1', req('buyer', 'pay', 'ledger', { amount: 101n }), { expectCode: 'AMOUNT_EXCEEDED' });
  authorizationVector('authorization/v1/amount-within-cap', 'An amount at the ceiling is allowed.', 'authority-v1', req('buyer', 'pay', 'ledger', { amount: 100n }), { expectDecision: 'ALLOW' });
  authorizationVector('authorization/v1/cumulative-amount-exceeded', 'Two admissions consumed 90 of a 100 cumulative budget; 20 more fails CUMULATIVE_AMOUNT_EXCEEDED.', 'authority-v1', req('spender', 'spend', 'petty-cash', { amount: 20n }), { expectCode: 'CUMULATIVE_AMOUNT_EXCEEDED' });
  authorizationVector('authorization/v1/cumulative-amount-honoured', 'The remaining 10 of the cumulative budget is still allowed after two admissions.', 'authority-v1', req('spender', 'spend', 'petty-cash', { amount: 10n }), { expectDecision: 'ALLOW' });
  authorizationVector('authorization/v1/transaction-count-exceeded', 'One admission exhausted a single-transaction grant (TRANSACTION_COUNT_EXCEEDED).', 'authority-v1', req('stamper', 'stamp', 'forms'), { expectCode: 'TRANSACTION_COUNT_EXCEEDED' });
  authorizationVector('authorization/v1/agent-inactive', 'A terminated agent is refused (AGENT_INACTIVE) even though its grant is live.', 'authority-v1', req('leaver', 'read', 'ledger'), { expectCode: 'AGENT_INACTIVE' });
  authorizationVector('authorization/v1/no-authority', 'An active agent holding no grant at all fails NO_AUTHORITY.', 'authority-v1', req('visitor', 'read', 'ledger'), { expectCode: 'NO_AUTHORITY' });
  authorizationVector('authorization/v1/successor-not-yet-appointed', 'The designated successor gains nothing from the succession rule before the transfer: the leaver\'s grant does not follow.', 'authority-v1', req('heir', 'read', 'ledger'), { expectCode: 'NO_AUTHORITY' });

  authorizationVector('authorization/v1/migrated-successor-may-exercise-its-own-grant', 'Decisions on the migrated history match the legacy fixture: the successor may do what it was separately granted.', 'migrated-v1', { actorId: 'b:first-look', action: 'record-review-progress', resource: 'obligation:first-look', claimedAt: 1000 }, { expectDecision: 'ALLOW' });
  authorizationVector('authorization/v1/migrated-successor-does-not-inherit-collection', 'Decisions on the migrated history match the legacy fixture: the successor does not inherit the collection power.', 'migrated-v1', { actorId: 'b:first-look', action: 'collect-evidence-packet', resource: 'resource:first-look', claimedAt: 1000 }, { expectCode: 'ACTION_NOT_ALLOWED' });
}

// ---------------------------------------------------------------- SURVIVES

section('survives');
{
  const count = handover.events.length;
  survivesVector('survives/v1/predecessor-after-handover', 'The terminated predecessor keeps the duty visible; its assignment moved to the successor; its grant was revoked.', 'handover-v1', 'bea', count,
    { lifecycleStatus: 'TERMINATED', obligationIds: ['duty:42'], currentAssignments: [{ obligationId: 'duty:42', assigneeId: 'alex', successionRuleId: 'handover' }], currentRoleTenureCount: 0, transferredRoleTenureCount: 1, invalidatedAuthorityIds: ['collect'] });
  survivesVector('survives/v1/successor-after-handover', 'The successor holds the tenure and the assignment and keeps its own grants.', 'handover-v1', 'alex', count,
    { lifecycleStatus: 'ACTIVE', obligationIds: ['duty:42'], currentRoleTenureCount: 1, invalidatedAuthorityIds: [] });
  survivesVector('survives/v1/predecessor-before-handover', 'Before the succession the predecessor is active, holds the tenure and owns the open duty.', 'handover-v1', 'bea', handover.before,
    { lifecycleStatus: 'ACTIVE', obligationIds: ['duty:42'], currentRoleTenureCount: 1, currentAssignments: [{ obligationId: 'duty:42', assigneeId: 'bea', successionRuleId: 'handover' }] });
  survivesVector('survives/v1/unknown-agent', 'An agent the history never created is ABSENT.', 'handover-v1', 'nobody', count, { exists: false, lifecycleStatus: 'ABSENT' });
  survivesVector('survives/v1/migrated-predecessor-after-handover', 'SURVIVES on the migrated history matches the legacy fixture for the terminated predecessor.', 'migrated-v1', 'a:first-look', migration.events.length,
    { lifecycleStatus: 'TERMINATED', obligationIds: ['obligation:first-look'], currentAssignments: [{ obligationId: 'obligation:first-look', assigneeId: 'b:first-look', successionRuleId: 'succession:first-look' }] });
}

// ---------------------------------------------------------------- head attestations across a rotation

section('attestation');
{
  const events = rotation.events, r = rotation.position;
  const newSigner = signer.signerFromKeyPair(rotation.newKey);
  const state = replay(revive(events)).state;
  const headAt = (p) => ({ hash: state.eventHistoryHashes[p], position: p, canonicalTime: events[p].timestamp });
  const attest = (s, p) => signer.attestHead(s, DOMAIN, headAt(p), 'sha256');
  attestationVector('attestation/v1/pre-rotation-head-by-retired-key-verifies', 'An attestation of a head before the rotation, signed by the key that was in force then, still verifies after that key was retired.', 'rotation-v1', events.length, await attest(ownerSigner, rotation.before - 1), { valid: true });
  attestationVector('attestation/v1/rotation-head-by-retired-key-verifies', 'The head that ends with the rotation belongs to the old key set: the retired key\'s attestation of it verifies.', 'rotation-v1', events.length, await attest(ownerSigner, r), { valid: true });
  attestationVector('attestation/v1/rotation-head-by-new-key-fails', 'The new key governs only from the position after the rotation: its attestation of the rotation head itself does not verify.', 'rotation-v1', events.length, await attest(newSigner, r), { valid: false, signatureValid: false });
  attestationVector('attestation/v1/post-rotation-head-by-retired-key-fails', 'An attestation of a head after the rotation signed by the retired key does not verify.', 'rotation-v1', events.length, await attest(ownerSigner, r + 1), { valid: false, signatureValid: false });
  attestationVector('attestation/v1/post-rotation-head-by-new-key-verifies', 'An attestation of a head after the rotation signed by the new key verifies.', 'rotation-v1', events.length, await attest(newSigner, events.length - 1), { valid: true });
  attestationVector('attestation/v1/foreign-head-by-new-key-fails', 'A correctly signed attestation of a head this history does not contain is not an attestation of this history (prefix false).', 'rotation-v1', events.length, await signer.attestHead(newSigner, DOMAIN, { ...headAt(events.length - 1), hash: `0x${'ef'.repeat(32)}` }, 'sha256'), { valid: false, signatureValid: true, prefix: false });
}

// ================================================================ outputs

vectors.sort((a, b) => TOPICS.indexOf(a.topic) - TOPICS.indexOf(b.topic)); // stable: emission order within a topic
const ids = new Set();
for (const v of vectors) { if (ids.has(v.id)) throw new Error(`duplicate vector id ${v.id}`); ids.add(v.id); }
for (const v of vectors) if (v.kind === 'replay' && !Object.hasOwn(v.expect, 'code')) throw new Error(`${v.id}: a replay vector must pin its code`);

const sha256 = (text) => createHash('sha256').update(text).digest('hex');
outputs.set('vectors.json', `${JSON.stringify(vectors, null, 1)}\n`);
const KINDS = ['replay', 'authorization', 'survives', 'attestation'];
const countOf = (list) => ({ ...Object.fromEntries(KINDS.map((kind) => [kind, list.filter((v) => v.kind === kind).length])), total: list.length });
const manifest = {
  schemaVersion: 'irontrellis-conformance/1', protocol: 'irontrellis', format: TRELLIS_FORMAT,
  generatedFrom: { reference: '@ramex-labs/irontrellis (packages/core)', authorization: core.AUTHORIZATION_VERSION, replay: core.REPLAY_VERSION, query: core.QUERY_VERSION },
  note: 'Format-1 conformance vectors generated by conformance/v1/generate.mjs with the TypeScript core as the executable reference. A conforming implementation reproduces every `expect` from the corresponding `input` (histories under conformance/v1/histories). Regeneration is deterministic: `node conformance/v1/generate.mjs --check` reproduces these files byte for byte.',
  ownerKey: { keyId: ownerKey.keyId, scheme: ownerKey.scheme, credential: ownerKey.credential, seed: seed(0x1001), note: 'test key only' },
  nextKey: { keyId: nextKey.keyId, scheme: nextKey.scheme, credential: nextKey.credential, seed: seed(0x1102), note: 'the next key the genesis commitments name (test key only); rotation-v1 has no commitment' },
  topics: TOPICS,
  histories: Object.fromEntries(Object.entries(histories).map(([name, events]) => [name, { eventCount: events.length, head: headOf(events), sha256: sha256(outputs.get(`histories/${name}.json`)) }])),
  counts: { ...countOf(vectors), byTopic: Object.fromEntries(TOPICS.map((name) => [name, countOf(vectors.filter((v) => v.topic === name))])) },
  vectors: vectors.map((v) => ({ id: v.id, kind: v.kind, topic: v.topic, purpose: v.purpose, sha256: sha256(JSON.stringify(v)) })),
};
outputs.set('MANIFEST.json', `${JSON.stringify(manifest, null, 1)}\n`);

// The vector-count table of conformance/README.md (the one place counts are stated), between its markers.
const legacyVectors = JSON.parse(readFileSync(join(ROOT, 'conformance/legacy/vectors.json'), 'utf8'));
const row = (cells) => `| ${cells.join(' | ')} |`;
const table = [
  '<!-- vector-counts:begin (generated by conformance/v1/generate.mjs; do not edit) -->',
  row(['Suite', 'Topic', ...KINDS, 'total']),
  row(['---', '---', ...KINDS.map(() => '---:'), '---:']),
  row(['`legacy/`', 'Continuity 0.2.2 (byte-identical)', ...Object.values(countOf(legacyVectors))]),
  ...TOPICS.map((name) => row(['`v1/`', name, ...Object.values(countOf(vectors.filter((v) => v.topic === name)))])),
  row(['`v1/`', '**all**', ...Object.values(countOf(vectors)).map((n) => `**${n}**`)]),
  '<!-- vector-counts:end -->',
].join('\n');
const README = join(ROOT, 'conformance/README.md');
const readme = readFileSync(README, 'utf8');
const markers = /<!-- vector-counts:begin[^\n]*-->[\s\S]*?<!-- vector-counts:end -->/;
if (!markers.test(readme)) throw new Error('conformance/README.md has no vector-counts markers');
const readmeText = readme.replace(markers, table);

// ---------------------------------------------------------------- write, or compare with --check

rmSync(WORK, { recursive: true, force: true });
const produced = new Set([...outputs.keys()].filter((path) => path.startsWith('histories/')).map((path) => path.slice('histories/'.length)));
const stale = existsSync(HISTORIES) ? readdirSync(HISTORIES).filter((file) => !produced.has(file)) : [];
if (CHECK) {
  const differ = [...outputs].filter(([path, text]) => { const file = join(HERE, path); return !existsSync(file) || readFileSync(file, 'utf8') !== text; }).map(([path]) => `conformance/v1/${path}`);
  if (readmeText !== readme) differ.push('conformance/README.md (vector counts)');
  differ.push(...stale.map((file) => `conformance/v1/histories/${file} (not generated)`));
  if (differ.length > 0) {
    console.error(`a fresh generation differs:\n  ${differ.join('\n  ')}`);
    process.exit(1);
  }
  console.log(`conformance/v1 is up to date (${vectors.length} vectors over ${Object.keys(histories).length} histories)`);
} else {
  mkdirSync(HISTORIES, { recursive: true });
  for (const file of stale) rmSync(join(HISTORIES, file));
  for (const [path, text] of outputs) writeFileSync(join(HERE, path), text);
  if (readmeText !== readme) writeFileSync(README, readmeText);
  const c = manifest.counts;
  console.log(`wrote ${c.total} vectors (${c.replay} replay, ${c.authorization} authorization, ${c.survives} survives, ${c.attestation} attestation) over ${Object.keys(histories).length} histories`);
}
