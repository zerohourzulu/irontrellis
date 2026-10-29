/**
 * Seeds: valid inputs produced by the real engine, from which the mutators
 * start. Deterministic (fixed Ed25519 seeds, counter ids, scripted clocks, a
 * witness with a fixed key), so a campaign is reproducible from its seed.
 *
 *  - replay seeds: the format-1 conformance histories (conformance/v1/histories),
 *    the legacy reference fixtures, and the events of the store seeds below;
 *  - store seeds: history directories written through the owner API
 *    (`createLocalOwner`): JSONL file, owner-attested pin, local anchor log
 *    (`.anchors`), and for the witnessed one the side file `.witness.json`
 *    written by a live witness server. Every event type the owner API writes
 *    appears: grants, delegations, prohibitions, revocations, roles,
 *    appointments, successions, runtime admissions, simulated invocations and
 *    receipts, obligations, assignments, next-key commitments, pre-rotated and
 *    plain owner key rotations, local anchor-log anchors and witness bindings;
 *  - the key registry: every private key those histories were signed with, so
 *    a mutated control event can be re-signed (to get past the signature and
 *    exercise the transition rules behind it).
 */
import { createHash } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ROOT, core, internal, plain, signerLib, t, witness as witnessModule } from './env.mjs';

export const SEED_VERSION = 'irontrellis-fuzz-seeds/1';
/**
 * What the cached seeds were built with: the digest of this file, which holds every builder. A cache built by other
 * builders is rebuilt (the directory name stays).
 */
const SEED_LAYOUT = createHash('sha256').update(readFileSync(new URL(import.meta.url))).digest('hex').slice(0, 16);
const hexSeed = (n) => `0x${n.toString(16).padStart(64, '0')}`;
const pair = (keyId, n) => core.keyPairFromPrivateKey('ed25519', keyId, hexSeed(n));
const signerOf = (p) => signerLib.signerFromKeyPair(p);

/** Every owner/runtime key the seed histories use (conformance v1 generator seeds included). */
const KNOWN_KEYS = [
  ['owner:1', 0x1001], ['owner:2', 0x1002], ['owner:stranger', 0x1003], ['owner:2', 0x1102], ['owner:3', 0x1103], ['owner:stranger', 0x1109],
  ['owner:1', 0x3001], ['owner:2', 0x3002], ['owner:3', 0x3003],
  ['fuzz:owner:1', 0x7001], ['fuzz:owner:2', 0x7002], ['fuzz:owner:3', 0x7003],
  ['fuzz:rot:1', 0x7011], ['fuzz:rot:2', 0x7012], ['fuzz:rot:3', 0x7013], ['fuzz:rot:4', 0x7014],
  ['fuzz:wit:1', 0x7021], ['fuzz:wit:2', 0x7022], ['fuzz:wit:3', 0x7023],
  ['fuzz:late:1', 0x7031], ['fuzz:late:2', 0x7032], ['fuzz:late:3', 0x7033], ['fuzz:owner:4', 0x7004], ['owner:2', 0x1201],
];

/** credential (lowercase) → Signer, for re-signing mutated control events. */
export function keyRegistry() {
  const registry = new Map();
  for (const [keyId, n] of KNOWN_KEYS) {
    const p = pair(keyId, n);
    registry.set(p.credential.toLowerCase(), signerOf(p));
  }
  return registry;
}

const readJson = (file) => JSON.parse(readFileSync(file, 'utf8'));

/** Event arrays (wire form) the replay-level targets start from. */
export function replaySeeds(extra = []) {
  const seeds = [];
  const v1 = join(ROOT, 'conformance/v1/histories');
  for (const file of readdirSync(v1).filter((f) => f.endsWith('.json')).sort()) seeds.push({ name: `v1/${file.slice(0, -5)}`, events: readJson(join(v1, file)) });
  const legacy = join(ROOT, 'packages/reference-0.2/tests/fixtures');
  for (const file of ['handover-history.json', 'handover-denied-history.json', 'mandate-history.json']) seeds.push({ name: `legacy/${file.slice(0, -5)}`, events: readJson(join(legacy, file)) });
  return [...seeds, ...extra];
}

// ---------------------------------------------------------------- store seeds (written through the owner API)

const DOMAIN = (name) => Object.freeze({ protocol: 'irontrellis', version: '1', deploymentId: `fuzz:${name}` });

function scripted(dir, name, extra = {}) {
  let tick = 100, counter = 0;
  const historyFile = join(dir, 'history.jsonl');
  const config = {
    historyFile, domain: DOMAIN(name), owner: 'operations', controller: 'operator', format: core.TRELLIS_FORMAT, [internal.FORMAT1_TEST_TOOLING]: true,
    now: () => tick, ids: () => `${name}:${(counter += 1)}`, ...extra,
  };
  const step = async (promise) => { const result = await promise; tick += 1; return result; };
  return { config, historyFile, step, tick: () => tick, clock: () => tick };
}

const runtimeKey = (n) => { const p = pair(`key:${n}`, 0x2000 + n); return { credential: p.credential, signHash: core.signHashWith(p) }; };

async function buildHandover(dir) {
  const owner1 = signerOf(pair('fuzz:owner:1', 0x7001)), next = signerOf(pair('fuzz:owner:2', 0x7002));
  const h = scripted(dir, 'handover', { signer: owner1, nextSigner: next });
  const owner = await core.createLocalOwner(h.config);
  const bea = runtimeKey(1), alex = runtimeKey(2);
  await h.step(owner.createAgent({ id: 'bea' }));
  await h.step(owner.createAgent({ id: 'alex' }));
  await h.step(owner.createRole({ id: 'reviewer' }));
  await h.step(owner.declareSuccession({ id: 'handover', from: 'bea', to: 'alex', role: 'reviewer' }));
  await h.step(owner.appoint({ agent: 'bea', role: 'reviewer', tenure: 'shift:1', number: 1, succession: 'handover' }));
  await h.step(owner.admitRuntime({ session: 'session:bea', agent: 'bea', epoch: 1, key: 'key:bea', credential: bea.credential, expiresAt: 900 }));
  await h.step(owner.admitRuntime({ session: 'session:alex', agent: 'alex', epoch: 1, key: 'key:alex', credential: alex.credential, expiresAt: 900 }));
  await h.step(owner.grant({ id: 'collect', to: 'bea', actions: ['read', 'OBLIGATE'], resources: ['incident:42'], expiresAt: 800, delegable: 1 }));
  await h.step(owner.delegate({ id: 'collect-sub', from: 'bea', parent: 'collect', to: 'alex', actions: ['read'], resources: ['incident:42'], expiresAt: 700 }));
  await h.step(owner.grant({ id: 'budget', to: 'alex', actions: ['pay'], resources: ['ledger'], expiresAt: 800, maxAmount: 500n, maxCumulativeAmount: 900n }));
  await h.step(owner.grant({ id: 'review', to: 'alex', actions: ['record-collection-disposition'], resources: ['duty:42'], expiresAt: 800 }));
  await h.step(owner.prohibit({ id: 'no-delete', global: true, actions: ['delete'], resources: ['incident:42'] }));
  const op = { id: 'operation:42', action: 'read', resource: 'incident:42', role: 'reviewer', tenure: 'shift:1', termsCommitment: core.commitTerms({ subject: 'fuzz seed' }) };
  const sim = core.openLocalSimulation({ ...h.config, session: 'session:bea', signHash: bea.signHash });
  const run = await h.step(sim.run(op));
  if (run.invocation?.status !== 'SUBMITTED') throw new Error(`seed simulation failed: ${JSON.stringify(run)}`);
  const receipt = await h.step(sim.recordReceipt(op));
  if (receipt.recording?.status !== 'ADMITTED') throw new Error('seed receipt not admitted');
  const runtime = core.openLocalRuntime({ ...h.config, session: 'session:bea', signHash: bea.signHash });
  await h.step(runtime.obligate({ id: 'duty:42', operation: op.id, description: 'Review it.', deadline: 700, succession: 'handover', reviewAuthority: 'review' }));
  await h.step(owner.succeed({ id: 'handover:42', rule: 'handover', fromAgent: 'bea', fromTenure: 'shift:1', toAgent: 'alex', toTenure: 'shift:2', role: 'reviewer', number: 2 }));
  await h.step(owner.grant({ id: 'assign', to: 'alex', actions: ['ASSIGN_PERFORMANCE'], resources: ['duty:42'], expiresAt: 800 }));
  const successor = core.openLocalRuntime({ ...h.config, session: 'session:alex', signHash: alex.signHash });
  await h.step(successor.assign({ id: 'assign:42', obligation: 'duty:42' }));
  await h.step(owner.revoke('collect'));
  // Format-1 seeds: the store writer opens them only with the explicit opt-in (SPEC §16.1; KNOWN-ISSUES 19, DEVIATIONS 49).
  const store = internal.openHistoryStoreInternal(h.historyFile, { signer: owner1, readOnlyFormats: false });
  await core.anchorHead(store, owner1, core.localAnchorLog(core.anchorsPathFor(h.historyFile)), { id: 'handover:anchor:1', anchoredAt: h.tick() });
  await h.step(owner.createAgent({ id: 'late' }));
  await store.flush();
  store.close();
}

async function buildRotation(dir) {
  const k1 = signerOf(pair('fuzz:rot:1', 0x7011)), k2 = signerOf(pair('fuzz:rot:2', 0x7012)), k3 = signerOf(pair('fuzz:rot:3', 0x7013)), k4 = signerOf(pair('fuzz:rot:4', 0x7014));
  const h = scripted(dir, 'rotation', { signer: k1, nextSigner: k2 });
  const owner = await core.createLocalOwner(h.config);
  await h.step(owner.createAgent({ id: 'bea' }));
  await h.step(owner.createRole({ id: 'desk', exclusive: true }));
  await h.step(owner.appoint({ agent: 'bea', role: 'desk', tenure: 'desk:1', number: 1 }));
  await h.step(owner.grant({ id: 'read', to: 'bea', actions: ['read'], resources: ['ledger'], expiresAt: 900, maxTransactions: 3 }));
  const store = internal.openHistoryStoreInternal(h.historyFile, { signer: k1, readOnlyFormats: false });
  await core.anchorHead(store, k1, core.localAnchorLog(core.anchorsPathFor(h.historyFile)), { id: 'rotation:anchor:1', anchoredAt: h.tick() });
  store.close();
  const rotated = await h.step(owner.rotateOwnerKey({ nextSigner: k2, newNextSigner: k3, reason: 'fuzz seed pre-rotated rotation' }));
  if (!rotated.preRotated) throw new Error('seed: expected a pre-rotated rotation');
  await h.step(owner.createAgent({ id: 'alex' }));
  await h.step(owner.unappoint({ agent: 'bea', role: 'desk', tenure: 'desk:1' }));
  await h.step(owner.rotateOwnerKey({ nextSigner: k3, newNextSigner: k4, reason: 'second rotation' }));
  await h.step(owner.advanceEpoch({ agent: 'alex', from: 1, to: 2 }));
  const later = internal.openHistoryStoreInternal(h.historyFile, { signer: k3, readOnlyFormats: false });
  await core.anchorHead(later, k3, core.localAnchorLog(core.anchorsPathFor(h.historyFile)), { id: 'rotation:anchor:2', anchoredAt: h.tick() });
  later.close();
}

/** A witness server with a fixed key and clock, in-process on 127.0.0.1:0. */
export async function startFixedWitness(dataDir, { name = 'fuzz.witness', seed = 0x55, now } = {}) {
  const lib = await witnessModule();
  lib.initDataDir(dataDir, name);
  const signerKey = t.formatSignerKey(name, new Uint8Array(32).fill(seed));
  const signer = t.parseSignerKey(signerKey);
  const verifierKey = t.verifierKey(name, signer.publicKey);
  writeFileSync(join(dataDir, lib.KEY_FILE), `${JSON.stringify({ version: lib.KEY_FILE_VERSION, name, publicKey: t.encodeBase64(signer.publicKey), verifierKey, privateKey: signerKey }, null, 2)}\n`, { mode: 0o600 });
  const silent = { info() {}, warn() {}, error() {} };
  return lib.serve({
    dataDir, listen: '127.0.0.1:0', logger: silent, ...(now === undefined ? {} : { now }),
    configOverride: { adminTokenHashes: [lib.hashToken(ADMIN_TOKEN)], rateLimit: { perIpPerMinute: 0, perHistoryPerMinute: 0, monitoringPerIpPerMinute: 0 } },
  });
}
export const ADMIN_TOKEN = 'itw_fuzz-admin-token-0123456789abcdef';

async function buildWitnessed(dir) {
  let clock = 1_800_000_000_000;
  const server = await startFixedWitness(join(dir, 'witness-data'), { now: () => (clock += 7) });
  try {
    const k1 = signerOf(pair('fuzz:wit:1', 0x7021)), k2 = signerOf(pair('fuzz:wit:2', 0x7022)), k3 = signerOf(pair('fuzz:wit:3', 0x7023));
    const h = scripted(dir, 'witnessed', {
      signer: k1, nextSigner: k2,
      witness: { witnesses: [{ url: server.url, verifierKey: server.witness.verifierKey, name: 'fuzz-witness', token: ADMIN_TOKEN }], quorum: 1, mode: 'sync', maxUnwitnessedEvents: 50 },
    });
    const owner = await core.createLocalOwner(h.config);
    await h.step(owner.createAgent({ id: 'bea' }));
    await h.step(owner.grant({ id: 'read', to: 'bea', actions: ['read'], resources: ['ledger'], expiresAt: 900 }));
    await owner.flush?.();
    await h.step(owner.rotateOwnerKey({ nextSigner: k2, newNextSigner: k3, reason: 'witnessed rotation' }));
    await h.step(owner.createAgent({ id: 'alex' }));
    await owner.flush?.();
    await owner.checkWitnesses({ force: true });
  } finally {
    await server.close();
  }
}

async function buildLegacy(dir) {
  copyFileSync(join(ROOT, 'packages/reference-0.2/tests/fixtures/handover-history.jsonl'), join(dir, 'history.jsonl'));
}

async function buildMigrated(dir) {
  const k = signerOf(pair('fuzz:owner:3', 0x7003)), next = signerOf(pair('fuzz:owner:4', 0x7004));
  // Migrate a copy: migration fences its source with a `.migrated` marker beside it (SPEC §16.2 step 6), which must not land in the tree.
  const source = join(dir, 'source.jsonl');
  copyFileSync(join(ROOT, 'packages/reference-0.2/tests/fixtures/handover-history.jsonl'), source);
  await core.migrateHistory({ source, target: join(dir, 'history.jsonl'), signer: k, nextSigner: next, now: () => 1000, acceptUnpinnedSource: true });
}

/** A history created without a commitment that commits later (a commitment-only rotation), then rotates onto the committed key. */
async function buildCommitLater(dir) {
  const k1 = signerOf(pair('fuzz:late:1', 0x7031)), k2 = signerOf(pair('fuzz:late:2', 0x7032)), k3 = signerOf(pair('fuzz:late:3', 0x7033));
  const h = scripted(dir, 'commit-later', { signer: k1, nextKey: false });
  const owner = await core.createLocalOwner(h.config);
  await h.step(owner.createAgent({ id: 'bea' }));
  await h.step(owner.commitNextKey({ nextSigner: k2 }));
  await h.step(owner.grant({ id: 'read', to: 'bea', actions: ['read'], resources: ['ledger'], expiresAt: 900 }));
  const rotated = await h.step(owner.rotateOwnerKey({ nextSigner: k2, newNextSigner: k3, reason: 'onto the key committed later' }));
  if (!rotated.preRotated) throw new Error('seed: expected a pre-rotated rotation');
  await h.step(owner.createAgent({ id: 'alex' }));
  await owner.flush();
}

const BUILDERS = { handover: buildHandover, rotation: buildRotation, witnessed: buildWitnessed, legacy: buildLegacy, migrated: buildMigrated, 'commit-later': buildCommitLater };
export const STORE_FILES = ['history.jsonl', 'history.jsonl.head', 'history.jsonl.anchors', 'history.jsonl.witness.json'];

/**
 * Builds (or reuses) the store seeds under `cacheDir` and returns
 * `[{ name, files: { 'history.jsonl': Buffer, … }, events }]`.
 */
export const SEED_CACHE = join(tmpdir(), `irontrellis-fuzz-seeds-${SEED_VERSION.split('/')[1]}-${process.getuid?.() ?? 'u'}`);
export async function storeSeeds(cacheDir = SEED_CACHE) {
  const manifest = join(cacheDir, 'MANIFEST.json');
  const ready = () => { try { const m = readJson(manifest); return m.version === SEED_VERSION && m.layout === SEED_LAYOUT; } catch { return false; } };
  if (!ready()) {
    // Built aside and renamed into place, so concurrent harnesses (parallel test files) never see a partial cache.
    const building = `${cacheDir}.building-${process.pid}-${Date.now()}`;
    for (const [name, build] of Object.entries(BUILDERS)) {
      const dir = join(building, name);
      mkdirSync(dir, { recursive: true });
      await build(dir);
    }
    writeFileSync(join(building, 'MANIFEST.json'), JSON.stringify({ version: SEED_VERSION, layout: SEED_LAYOUT, seeds: Object.keys(BUILDERS) }));
    if (!ready()) {
      if (existsSync(cacheDir)) renameSync(cacheDir, `${cacheDir}.stale-${process.pid}-${Date.now()}`);
      try { renameSync(building, cacheDir); } catch { /* another builder won the race: use its cache */ }
    }
    rmSync(building, { recursive: true, force: true });
    if (!ready()) throw new Error(`fuzz seeds could not be prepared in ${cacheDir}`);
  }
  const seeds = [];
  for (const name of Object.keys(BUILDERS)) {
    const dir = join(cacheDir, name);
    const files = {};
    for (const file of STORE_FILES) if (existsSync(join(dir, file))) files[file] = readFileSync(join(dir, file));
    const store = core.openHistoryStore(join(dir, 'history.jsonl'), { inspect: true, witness: false });
    const events = store.readAll().map((event) => plain(event));
    store.close();
    seeds.push({ name, files, events });
  }
  return seeds;
}
