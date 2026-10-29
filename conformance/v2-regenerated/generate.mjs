#!/usr/bin/env node
/**
 * ENGINE-DERIVED format-2 (`irontrellis-event/2`) conformance vectors: the builder's regenerated suite (BUILD §5),
 * a port of conformance/v1/generate.mjs to format 2.
 *
 *   pnpm --filter @ramex-labs/irontrellis build
 *   node conformance/v2-regenerated/generate.mjs            # write
 *   node conformance/v2-regenerated/generate.mjs --check    # exit 1 when a fresh generation differs from the files
 *
 * The expectations are this engine's own answers (packages/core/dist), projected exactly as conformance/adapters/node.mjs
 * projects them, as in v1; they are not a SPEC oracle. The architect's suites (conformance/v2, conformance/v2-g3) are the
 * oracle-derived ones; G2.5 cross-checks the roots pinned here independently (RESULTS/PINNED-ROOTS.json).
 * Signed under the session-challenge profile g3 (A-54, founder-approved 2026-10-11; A-59), the engine default.
 *
 * Output: vectors.json, MANIFEST.json, histories/*.json (+ the .jsonl store files they were written as),
 * glossary.json (A-70.1). Deterministic: the published seeds of conformance/v2/TEST-KEYS.md (plus the seeds listed in
 * MANIFEST.json `keys`), counter ids, scripted clocks and fixed migration ids; regenerating yields byte-identical files.
 * The histories are built first; the vectors follow grouped by topic (TOPICS). Every replay vector pins its code.
 */
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync, existsSync, copyFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = dirname(dirname(HERE));
const CHECK = process.argv.includes('--check');
const core = await import(join(ROOT, 'packages/core/dist/index.js'));
const signer = await import(join(ROOT, 'packages/core/dist/signer.js'));
const {
  createLocalOwner, createLocalReviewOwner, openLocalOwner, openLocalSimulation, openLocalRuntime, openLocalExecution, openLocalAttemptRecorder, commitTerms,
  keyPairFromPrivateKey, signHashWith, migrateHistory, openHistoryStore, replay, authorizePortable, survivesPortable, publicQueryDisclosure,
} = core;
// The TEST-ONLY capacity hook is not on a public subpath (step 5b review); the generator loads its module file.
const { setCapacityLimitsForTests } = await import(join(ROOT, 'packages/core/dist/capacity.js'));

if (core.challengeProfile() !== 'g3') throw new Error(`the regenerated suite is signed under profile g3; this process runs ${core.challengeProfile()} (unset IRONTRELLIS_CHALLENGE_PROFILE)`);

const WORK = join(HERE, '.work');
const HISTORIES = join(HERE, 'histories');
rmSync(WORK, { recursive: true, force: true });
mkdirSync(WORK, { recursive: true });

// ================================================================ identities (conformance/v2/TEST-KEYS.md, plus the seeds below)

/** The domain of conformance/v2 (TEST-KEYS.md): both suites share identities. */
const DOMAIN = Object.freeze({ protocol: 'irontrellis', version: '2', deploymentId: 'irontrellis-conformance-v2' });
const seed = (n) => `0x${n.toString(16).padStart(64, '0')}`;
const KEYS = {};
/** A published test key; `label` names it in MANIFEST.json `keys` when one key id has different seeds in different histories. */
const key = (keyId, n, scheme = 'ed25519', label = keyId) => { const pair = keyPairFromPrivateKey(scheme, keyId, seed(n)); KEYS[label] = { keyId, scheme, seed: seed(n), credential: pair.credential }; return pair; };
const OWNER = key('owner:1', 0x1001);          // TEST-KEYS: owner key of epoch 0
const NEXT = key('owner:2', 0x1102);           // TEST-KEYS: the committed next key
const NEXT_NEXT = key('owner:3', 0x1103);      // as conformance/v1: the next key's own commitment
const ROTATED = key('owner:rotated', 0x1002);  // as conformance/v1 rotation-v1: the key an uncommitted epoch rotates to
const SPENDER = key('key:spender', 0x2004);    // TEST-KEYS
const GATEWAY = key('key:gateway', 0x2005);    // TEST-KEYS
const ACME = key('acme:1', 0x3001);            // TEST-KEYS
const STRANGER = key('stranger:1', 0x3999);    // TEST-KEYS
const BEA = key('key:bea', 0x2101);
const ALEX = key('key:alex', 0x2102);
const CAL = key('key:cal', 0x2103);
const ACME2 = key('acme:2', 0x3002);
const EIP191 = key('key:eip191', 0x2201, 'eip191-personal-sign-keccak256');
const ownerSigner = signer.signerFromKeyPair(OWNER);
const nextSigner = signer.signerFromKeyPair(NEXT);
/** A-40.3: the fixed migration id of every migration twin (as packages/core/test/format2-migrate.test.mjs). */
const MIGRATION_ID = `0x${'4d'.repeat(32)}`;

// ================================================================ plumbing

/** Files this run produces (published path → text); written, or compared with `--check`, at the end. */
const outputs = new Map();
const histories = {};
/** Format-2 events are plain JSON (Amounts are decimal strings); a bigint here is a bug. */
const plain2 = (v) => JSON.parse(JSON.stringify(v, (_k, x) => { if (typeof x === 'bigint') throw new Error('a bigint in a format-2 event'); return x; }));
/** Format-1 and legacy events carry the {"$continuity.bigint"} marker on the wire. */
const plainMarked = (v) => JSON.parse(JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? { '$continuity.bigint': x.toString() } : x)));
const isFormat2 = (events) => events[0]?.data?.versions?.eventSchemaVersion === 'irontrellis-event/2';
const engineEvents = (events) => (isFormat2(events) ? events : core.jsonParseWithBigints(JSON.stringify(events)));
const readStore = (file) => { const store = openHistoryStore(file, { inspect: true }); try { return store.state().events.map((e) => plain2(e)); } finally { store.close?.(); } };
const save = (name, events, storeFile) => {
  if (histories[name] !== undefined) throw new Error(`history ${name} saved twice`);
  histories[name] = events;
  outputs.set(`histories/${name}.json`, `${JSON.stringify(events, null, 1)}\n`);
  if (storeFile) outputs.set(`histories/${name}.jsonl`, readFileSync(storeFile, 'utf8'));
  return events;
};
const accepted = (events) => { const r = replay(engineEvents(events)); if (r.status !== 'ACCEPTED') throw new Error(`history rejected: ${r.code} at ${r.position} (${r.reason})`); return r; };
const headOf = (events) => accepted(events).head;
const clone = (v) => JSON.parse(JSON.stringify(v));

/**
 * A scripted format-2 history: deterministic ids (`<name>:<n>`), a clock the caller moves, the published owner key
 * committed to the published next key (createLocalOwner's default shape, with caller signers so no key file is written).
 */
function scripted(name, extra = {}) {
  const clock = { t: 100 };
  let counter = 0;
  const historyFile = join(WORK, `${name}.jsonl`);
  const config = {
    historyFile, domain: DOMAIN, owner: 'operations', controller: 'operator', now: () => clock.t, ids: () => `${name}:${(counter += 1)}`,
    signer: ownerSigner, nextSigner, witness: false, refusalPolicy: { coalesceMs: 0, maxPerMinute: 1_000_000 }, ...extra,
  };
  if (config.nextKey === false) delete config.nextSigner;
  const session = (sessionId, pair, more = {}) => ({ ...config, session: sessionId, signHash: signHashWith(pair), ...more });
  return { name, config, historyFile, clock, session, events: () => readStore(historyFile) };
}
const op = (id, extra = {}) => ({ id, intentId: id, action: 'read', resource: 'incident:42', role: 'reviewer', tenure: 'shift:1', termsCommitment: commitTerms({ subject: id }), ...extra });

// ---------------------------------------------------------------- session-signed events built by hand (negative vectors)

/**
 * Re-signs a lifecycle event (types 14–16) as the next event after `prefix` (A-51.2), with `mutate` applied to the
 * authorization; an event copied from earlier in the history takes the head's time (timestamps never decrease).
 */
async function signLifecycle(prefix, event, sessionId, pair, mutate = (a) => a, epoch = 1) {
  const r = accepted(prefix);
  const binding = { runtimeSessionId: sessionId, credentialKeyId: pair.keyId, controlEpoch: epoch };
  const { recordAuthorization: _old, ...data } = event.data;
  const envelope = { id: event.id, type: event.type, timestamp: Math.max(event.timestamp, r.head.canonicalTime) };
  const hash = core.lifecycleAuthorizationHash(r.state.genesis.domain, { ...envelope, data }, r.head, binding);
  return { ...envelope, data: { ...data, recordAuthorization: mutate({ ...binding, hash, signature: await signHashWith(pair)(hash) }) } };
}
/** A REQUEST_REFUSED as the next event after `prefix`, signed (§10.1, A-59) by `pair` for `binding`. */
async function signRefusal(prefix, id, data, binding, pair, mutate = (a) => a) {
  const r = accepted(prefix);
  const at = data.evaluationTime;
  const d = { ...data, expectedHistoryHead: r.head, ...binding };
  const envelope = { id, type: 'REQUEST_REFUSED', timestamp: at };
  const hash = core.hashCanonical(core.refusalChallenge(r.state.genesis.domain, d, envelope), 'sha256');
  return { ...envelope, data: { ...d, refusalAuthorization: mutate({ hash, signature: await signHashWith(pair)(hash) }) } };
}
/** A COUNTERPARTY_RECEIPT_RECORDED wrapper as the next event after `prefix` (§11.2, A-54). */
async function signWrapper(prefix, id, data, binding, pair, mutate = (a) => a) {
  const r = accepted(prefix);
  const envelope = { id, type: 'COUNTERPARTY_RECEIPT_RECORDED', timestamp: r.head.canonicalTime };
  const d = { ...data, ...binding };
  const hash = core.hashCanonical(core.counterpartyRecordChallenge(r.state.genesis.domain, d, r.head, envelope), 'sha256');
  return { ...envelope, data: { ...d, recordAuthorization: mutate({ hash, signature: await signHashWith(pair)(hash) }) } };
}
/** A RECONCILIATION_OBSERVED as the next event after `prefix` (§10.3, A-71.2), signed by `pair` for `binding`; `data` overrides the defaults. */
async function signObservation(prefix, id, data, binding, pair, { timestamp, mutate = (a) => a } = {}) {
  const r = accepted(prefix);
  const envelope = { id, type: 'RECONCILIATION_OBSERVED', timestamp: timestamp ?? r.head.canonicalTime };
  const d = { expectedHistoryHead: plainMarked(r.head), ...data, ...binding };
  const hash = core.hashCanonical(core.reconciliationChallenge(r.state.genesis.domain, d, envelope), 'sha256');
  return { ...envelope, data: { ...d, observationAuthorization: mutate({ hash, signature: await signHashWith(pair)(hash) }) } };
}
/** A signature with one hex digit of its first byte changed (a tampered signature). */
const signFlip = (signature) => `${signature.slice(0, 2)}${signature[2] === '0' ? '1' : '0'}${signature.slice(3)}`;
/** A control event signed by the owner key over the head of `prefix` (§6.1). */
const signControl = async (prefix, unsigned, by = ownerSigner) => {
  const r = accepted(prefix);
  return plain2(await signer.signControlEvent(by, { timestamp: r.head.canonicalTime, ...unsigned }, r.state.genesis.domain, r.head, 'sha256'));
};
/** A counterparty envelope (§11.2) signed by `pair`. */
const envelopeFor = async (events, intentId, amount, previousReceiptDigest, pair = ACME, counterpartyId = 'acme', extra = {}) => {
  const state = accepted(events).state;
  const body = { version: 'irontrellis-counterparty-receipt/2', historyId: state.eventHistoryHashes[0], counterpartyId, keyId: pair.keyId, logicalId: intentId,
    intentDigest: state.intentDeclarations.get(intentId).declarationDigest, payloadDigest: core.hashCanonical({ payload: intentId }, 'sha256'), amount, outcome: 'DELIVERED',
    observedAt: state.head.canonicalTime, previousReceiptDigest, ...extra };
  return { ...body, signature: await signHashWith(pair)(core.envelopeSigningHash(body)) };
};

// ================================================================ vectors

const TOPICS = [
  'genesis-and-control-signatures', 'owner-keys', 'anchors-and-witness-bindings', 'migration', 'authorization', 'survives', 'attestation',
  'state-records', 'lifecycle-authorization', 'duty-policy', 'budgets', 'effects', 'counterparties', 'capacity', 'checkpoints', 'eip191-sessions',
  'export', 'read-only', 'observation', 'session-time-horizon',
];
const vectors = [];
let topic;
const section = (name) => { if (!TOPICS.includes(name)) throw new Error(`unknown topic ${name}`); topic = name; };
const REPLAY_INPUT = Object.freeze({ operationVersion: 'continuity-replay/0.2' });

/** Runs `fn` with the test-only hard limits of capacity.ts lowered (the replay vectors that carry `input.testCapacityLimits`). */
const withLimits = (limits, fn) => { if (limits === undefined) return fn(); setCapacityLimitsForTests(limits); try { return fn(); } finally { setCapacityLimitsForTests(); } };
/** `source` is an event list (carried inline) or `{ref, eventCount}` (a prefix of a saved history). */
const eventsOf = (source) => (Array.isArray(source) ? source : histories[source.ref].slice(0, source.eventCount));
const sourceFields = (source) => (Array.isArray(source) ? { events: source } : { history: { ref: source.ref, eventCount: source.eventCount } });
const ACCEPT = Object.freeze({ code: null });
const reject = (code, position) => Object.freeze({ code, ...(position === undefined ? {} : { position }) });

/**
 * A replay vector: `expect` pins status, head (null when rejected), code (null when accepted), stateRoot and
 * projectionHead (null unless an accepted format-2 history), as the node adapter answers. `expected` is the code the vector
 * is about (and its position when given); the generator refuses to write a vector whose engine answer differs.
 */
function replayVector(id, purpose, source, expected, options = {}) {
  const events = eventsOf(source);
  const result = withLimits(options.testCapacityLimits, () => replay(engineEvents(events)));
  const code = result.status === 'REJECTED' ? result.code : null;
  if (code !== expected.code) throw new Error(`${id}: expected ${expected.code ?? 'ACCEPTED'}, got ${code ?? 'ACCEPTED'} at ${result.position} (${result.reason ?? ''})`);
  if (expected.position !== undefined && result.position !== expected.position) throw new Error(`${id}: expected position ${expected.position}, got ${result.position} (${result.reason ?? ''})`);
  const ok = result.status === 'ACCEPTED';
  const expect = { status: result.status, head: ok ? plainMarked(result.head) : null, code, stateRoot: ok ? (result.stateRoot ?? null) : null, projectionHead: ok ? (result.projectionHead ?? null) : null };
  const input = options.testCapacityLimits === undefined ? REPLAY_INPUT : { ...REPLAY_INPUT, testCapacityLimits: options.testCapacityLimits };
  vectors.push({ id, kind: 'replay', topic, purpose, input, ...sourceFields(source), expect, ...(ok ? {} : { rejection: { code: result.code, position: result.position ?? null } }) });
  return result;
}
const projectAuthorize = (result) => ({
  decision: result.decision, code: result.code ?? null, scopeAssurance: result.scopeAssurance ?? null,
  controllingAuthorityIds: plainMarked(result.proof?.controllingAuthorityIds ?? null), failureCodes: (result.failures ?? []).map((f) => f.code), budgetId: result.budgetId ?? null,
});
/** `ref` names a saved history, or is an event list carried inline (G6.5: the decision vectors that pin no new history root). */
function authorizationVector(id, purpose, ref, request, options = {}) {
  const inline = Array.isArray(ref);
  const events = inline ? ref : options.eventCount === undefined ? histories[ref] : histories[ref].slice(0, options.eventCount);
  const r = accepted(events), head = plainMarked(r.head), genesis = events[0].data;
  const input = {
    operationVersion: core.AUTHORIZATION_VERSION, expectedHistoryHead: options.head ?? head, domain: options.domain ?? genesis.domain, policyVersion: genesis.policyVersion,
    rootRecognitionPolicy: 'declared-principal-root/0.2', request, evaluationTime: options.at ?? head.canonicalTime, authoritative: true, consequential: false,
  };
  const expect = projectAuthorize(authorizePortable({ ...input, events: engineEvents(events) }, replay));
  if (options.expectCode !== undefined && expect.code !== options.expectCode) throw new Error(`${id}: expected ${options.expectCode}, got ${JSON.stringify(expect)}`);
  if (options.expectDecision !== undefined && expect.decision !== options.expectDecision) throw new Error(`${id}: expected ${options.expectDecision}, got ${JSON.stringify(expect)}`);
  if (options.expectBudgetId !== undefined && expect.budgetId !== options.expectBudgetId) throw new Error(`${id}: expected budget ${options.expectBudgetId}, got ${JSON.stringify(expect)}`);
  if (options.expectScope !== undefined && expect.scopeAssurance !== options.expectScope) throw new Error(`${id}: expected scope ${options.expectScope}, got ${JSON.stringify(expect)}`);
  if (options.expectControlling !== undefined && JSON.stringify(expect.controllingAuthorityIds) !== JSON.stringify(options.expectControlling)) throw new Error(`${id}: expected controlling ${JSON.stringify(options.expectControlling)}, got ${JSON.stringify(expect)}`);
  vectors.push({ id, kind: 'authorization', topic, purpose, ...(inline ? { events } : { history: { ref, eventCount: events.length, head } }), input, expect });
  return expect;
}
/**
 * G6.5 A-136.4: a supplied-scope (raw path, spec02 §7.1) evaluation, `evaluateAuthorityPath`, over an input carried as
 * JSON (the 0.2 transport: bigints as `$continuity.bigint` markers, decoded by the engine's capture). Projected as
 * `authorize`.
 */
function authorityEvaluationVector(id, purpose, input, options = {}) {
  const expect = projectAuthorize(core.evaluateAuthorityPath(clone(input)));
  if (options.expectCode !== undefined && expect.code !== options.expectCode) throw new Error(`${id}: expected ${options.expectCode}, got ${JSON.stringify(expect)}`);
  if (options.expectDecision !== undefined && expect.decision !== options.expectDecision) throw new Error(`${id}: expected ${options.expectDecision}, got ${JSON.stringify(expect)}`);
  if (options.expectScope !== undefined && expect.scopeAssurance !== options.expectScope) throw new Error(`${id}: expected scope ${options.expectScope}, got ${JSON.stringify(expect)}`);
  if (options.expectControlling !== undefined && JSON.stringify(expect.controllingAuthorityIds) !== JSON.stringify(options.expectControlling)) throw new Error(`${id}: expected controlling ${JSON.stringify(options.expectControlling)}, got ${JSON.stringify(expect)}`);
  vectors.push({ id, kind: 'authority-evaluation', topic, purpose, input, expect });
  return expect;
}
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
function survivesVector(id, purpose, ref, agent, eventCount, checks) {
  const events = histories[ref].slice(0, eventCount), head = plainMarked(headOf(events));
  const input = { operationVersion: core.QUERY_VERSION, targetAgentId: agent, evaluationTime: head.canonicalTime };
  // Format 2: the state API (the portable continuity-query-envelope/0.2 reads legacy and format 1 only), as the node adapter answers.
  const expect = projectSurvives(isFormat2(events) ? core.observeHistory(events, { at: head.canonicalTime }).survives(agent)
    : survivesPortable({ operationVersion: core.QUERY_VERSION, observedEvents: engineEvents(events), targetAgentId: agent, evaluationTime: head.canonicalTime, disclosure: publicQueryDisclosure('SURVIVES') }, replay));
  for (const [k, v] of Object.entries(checks)) if (JSON.stringify(expect[k]) !== JSON.stringify(v)) throw new Error(`${id}: ${k} expected ${JSON.stringify(v)}, got ${JSON.stringify(expect[k])}`);
  vectors.push({ id, kind: 'survives', topic, purpose, history: { ref, eventCount, head }, input, expect });
}
function attestationVector(id, purpose, ref, eventCount, attestation, expected) {
  const events = histories[ref].slice(0, eventCount), r = accepted(events);
  const { signatureValid, prefix, stateRootValid, projectionValid, valid } = core.verifyHeadAttestationFacts(plain2(attestation), r.state);
  const expect = { signatureValid, prefix, stateRootValid, projectionValid, valid };
  for (const [k, v] of Object.entries(expected)) if (expect[k] !== v) throw new Error(`${id}: ${k} expected ${v}, got ${expect[k]}`);
  vectors.push({ id, kind: 'attestation', topic, purpose, history: { ref, eventCount, head: plainMarked(r.head) }, input: { attestation: plain2(attestation) }, expect });
}
function headroomVector(id, purpose, ref, budgetId, at, checks = {}, eventCount = histories[ref].length) {
  const events = histories[ref].slice(0, eventCount), r = accepted(events);
  const expect = plain2(core.headroom(r.state, budgetId, at) ?? null);
  for (const [k, v] of Object.entries(checks)) if (JSON.stringify(expect?.[k]) !== JSON.stringify(v)) throw new Error(`${id}: ${k} expected ${JSON.stringify(v)}, got ${JSON.stringify(expect?.[k])}`);
  vectors.push({ id, kind: 'headroom', topic, purpose, history: { ref, eventCount, head: plainMarked(r.head) }, input: { budgetId, at }, expect });
}
function dutyViewVector(id, purpose, ref, dutyId, checks = {}, eventCount = histories[ref].length) {
  const events = histories[ref].slice(0, eventCount), r = accepted(events);
  const expect = plain2(core.inspectDutyPolicyState(r.state, dutyId) ?? null);
  for (const [k, v] of Object.entries(checks)) if (JSON.stringify(expect?.[k]) !== JSON.stringify(v)) throw new Error(`${id}: ${k} expected ${JSON.stringify(v)}, got ${JSON.stringify(expect?.[k])}`);
  vectors.push({ id, kind: 'duty-view', topic, purpose, history: { ref, eventCount, head: plainMarked(r.head) }, input: { dutyId }, expect });
}
/** The export op as the node adapter answers it (the evidence arrays it strips are verified by the export-verify kind). */
const ADAPTER_STRIPPED = ['events', 'checkpoints', 'fromRecords', 'toRecords', 'inclusion'];
function exportVector(id, purpose, ref, fromPosition, toPosition, include, checks = {}) {
  const events = histories[ref], r = accepted(events);
  const view = plain2(core.exportView(engineEvents(events), { fromPosition, toPosition, include }));
  for (const k of ADAPTER_STRIPPED) delete view[k];
  for (const [k, v] of Object.entries(checks)) if (JSON.stringify(view[k]) !== JSON.stringify(v)) throw new Error(`${id}: ${k} expected ${JSON.stringify(v)}, got ${JSON.stringify(view[k])}`);
  vectors.push({ id, kind: 'export', topic, purpose, history: { ref, eventCount: events.length, head: plainMarked(r.head) }, input: { fromPosition, toPosition, include }, expect: view });
}
/** A-65: the verifier's answer over a view (as exported and JSON round-tripped, or edited), projected as the node adapter answers `verify-export`. */
const projectVerification = (v) => ({
  ok: v.ok, code: v.code ?? null, missingPositions: v.missingPositions === undefined ? null : [...v.missingPositions],
  from: { position: v.from.position, stateRoot: v.from.stateRoot, verified: v.from.verified, authenticated: v.from.authenticated },
  to: { position: v.to.position, stateRoot: v.to.stateRoot, verified: v.to.verified, authenticated: v.to.authenticated }, eventCount: v.eventCount,
});
function exportVerifyVector(id, purpose, view, checks) {
  const expect = projectVerification(core.verifyExportView(clone(view)));
  for (const [k, v] of Object.entries(checks)) if (JSON.stringify(expect[k]) !== JSON.stringify(v)) throw new Error(`${id}: ${k} expected ${JSON.stringify(v)}, got ${JSON.stringify(expect[k])}`);
  vectors.push({ id, kind: 'export-verify', topic, purpose, input: { view: clone(view) }, expect });
}

/**
 * FORMAT_READ_ONLY (SPEC §16.1, A-41): what an owner write answers for a history stored as `files.lines`, with its pin
 * (`files.pin`, the `.head` file) and its migration marker (`files.marker`, the `.migrated` file) when given; the write
 * is signed by `files.ownerKey` ({keyId, scheme, seed}, a published test key) when given.
 */
async function writerOpen({ lines, pin, marker, ownerKey }) {
  const dir = join(WORK, `writer-open-${vectors.length}`);
  mkdirSync(dir, { recursive: true });
  const historyFile = join(dir, 'history.jsonl');
  writeFileSync(historyFile, lines);
  if (pin !== undefined) writeFileSync(`${historyFile}.head`, pin);
  if (marker !== undefined) writeFileSync(strictStore.migratedMarkerPathFor(historyFile), marker);
  try {
    const inspected = openHistoryStore(historyFile, { inspect: true, allowUnpinned: true }), state = inspected.state();
    inspected.close?.();
    const owner = openLocalOwner({ historyFile, domain: state.genesis.domain, owner: state.events[1]?.data?.principalId ?? 'operations', controller: 'operator', now: () => state.head.canonicalTime + 1,
      ...(ownerKey === undefined ? {} : { signer: signer.signerFromKeyPair(keyPairFromPrivateKey(ownerKey.scheme, ownerKey.keyId, ownerKey.seed)) }) });
    await owner.createAgent({ id: 'probe' });
    return { written: true, code: null, reason: null };
  } catch (error) {
    return { written: false, code: error.code ?? 'ERROR', reason: error.detail?.reason ?? null };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
async function writerOpenVector(id, purpose, files, expected) {
  const expect = await writerOpen(files);
  for (const [k, v] of Object.entries(expected)) if (expect[k] !== v) throw new Error(`${id}: ${k} expected ${v}, got ${JSON.stringify(expect)}`);
  vectors.push({ id, kind: 'writer-open', topic, purpose, input: files, expect });
}

// ================================================================ histories

// ---------------------------------------------------------------- lifecycle-v2: a run (declaration, admission, consumption) and a receipt record; cal's session; then bea's epoch advance (A-60, A-61)

const lifecycle = {};
{
  const h = scripted('lifecycle');
  const owner = await createLocalOwner(h.config);
  await owner.createAgent({ id: 'bea' });
  await owner.createRole({ id: 'reviewer' });
  await owner.appoint({ agent: 'bea', role: 'reviewer', tenure: 'shift:1', number: 1 });
  await owner.admitRuntime({ session: 'session:bea', agent: 'bea', epoch: 1, key: 'key:bea', credential: BEA.credential, expiresAt: 10_000_000 });
  await owner.grant({ id: 'read', to: 'bea', actions: ['read'], resources: ['incident:42'], expiresAt: 10_000_000 });
  h.clock.t = 101;
  const sim = openLocalSimulation(h.session('session:bea', BEA));
  if ((await sim.run(op('op:1'))).status !== 'SIMULATION_RESULT') throw new Error('lifecycle: run');
  h.clock.t = 102;
  if ((await sim.recordReceipt(op('op:1'))).recording.status !== 'ADMITTED') throw new Error('lifecycle: receipt');
  await owner.createAgent({ id: 'cal' });
  await owner.admitRuntime({ session: 'session:cal', agent: 'cal', epoch: 1, key: 'key:cal', credential: CAL.credential, expiresAt: 10_000_000 });
  await owner.registerCounterparty({ counterpartyId: 'acme', keys: [{ keyId: 'acme:1', scheme: 'ed25519', credential: ACME.credential }] });
  lifecycle.events = save('lifecycle-v2', h.events(), h.historyFile);
  h.clock.t = 103;
  await owner.advanceEpoch({ agent: 'bea', from: 1, to: 2 });
  lifecycle.fenced = save('lifecycle-fenced-v2', h.events(), h.historyFile);
}

// ---------------------------------------------------------------- migration twins (SPEC §16.2): legacy handover (prefix end 25) and format-1 handover-v1 (21), A-62 twins

/**
 * The migration twins use the parameters of packages/core/test/format2-migrate.test.mjs (owner key seed 0x7e…7e under key id
 * owner:1, no next key, clock 5000, MIGRATION_ID), so their pinned heads and roots are the core tests' PINNED values.
 */
const MIGRATION_OWNER_SEED = `0x${'7e'.repeat(32)}`;
const migrationOwner = signer.signerFromKeyPair(keyPairFromPrivateKey('ed25519', 'owner:1', MIGRATION_OWNER_SEED));
const strictStore = await import(join(ROOT, 'packages/core/dist/store.js'));
const internalFormat1 = await import(join(ROOT, 'packages/core/dist/internal-format1.js')); // A-185.3: the earlier writers are test tooling
const LEGACY_FIXTURE = JSON.parse(readFileSync(join(ROOT, 'packages/reference-0.2/tests/fixtures/handover-history.json'), 'utf8'));
/** The reference's synthetic fixture credential (packages/core/test/helpers/duty-fixture.mjs FIXTURE_KEY). */
const FIXTURE_KEY = keyPairFromPrivateKey('eip191-personal-sign-keccak256', 'key', `0x${'11'.repeat(32)}`);
const migrations = {};
async function migrateTwin(name, sourceEvents, options = {}) {
  const dir = join(WORK, `migrate-${name}`);
  mkdirSync(dir, { recursive: true });
  const source = join(dir, 'source.jsonl'), target = join(dir, 'target.jsonl');
  if (options.copyFrom !== undefined) copyFileSync(options.copyFrom, source);
  else strictStore.createHistoryStore(source, core.jsonParseWithBigints(JSON.stringify(sourceEvents)), { readOnlyFormats: false }).close?.();
  const result = await migrateHistory({ source, target, now: () => 5000, signer: migrationOwner, nextKey: false, migrationId: MIGRATION_ID, ...(options.acceptUnpinnedSource ? { acceptUnpinnedSource: true } : {}),
    ...(options.sessionTimeHorizonMs === undefined ? {} : { sessionTimeHorizonMs: options.sessionTimeHorizonMs }) });
  const events = save(name, readStore(target), target);
  return { result, events, sourceLines: readFileSync(source, 'utf8'), marker: readFileSync(strictStore.migratedMarkerPathFor(source), 'utf8') };
}
migrations.legacy = await migrateTwin('migrated-legacy-v2', LEGACY_FIXTURE);
migrations.format1 = await migrateTwin('migrated-format1-v2', null, { copyFrom: join(ROOT, 'conformance/v1/histories/handover-v1.jsonl'), acceptUnpinnedSource: true });
if (migrations.legacy.events[0].data.migratedFrom.position !== 25 || migrations.format1.events[0].data.migratedFrom.position !== 21) throw new Error('unexpected migration prefix ends');
// A-62: a legacy source extended by an agent and its session WITHOUT expiresAt (legacy grammar), keyed by the reference fixture credential.
{
  const last = LEGACY_FIXTURE.at(-1);
  const principalId = LEGACY_FIXTURE.find((e) => e.type === 'PRINCIPAL_CREATED').data.principalId;
  const extra = [
    { id: 'event:a62:agent', type: 'AGENT_CREATED', timestamp: last.timestamp, data: { agentId: 'connector:a62', principalId, controllerId: 'controller:a62', initialControlEpoch: 1 } },
    { id: 'event:a62:session', type: 'RUNTIME_SESSION_ADMITTED', timestamp: last.timestamp, data: { sessionId: 'session:a62', agentId: 'connector:a62', controllerId: 'controller:a62', controlEpoch: 1, credentialKeyId: 'key:a62', credentialAddress: FIXTURE_KEY.credential } },
  ];
  migrations.noExpiry = await migrateTwin('migrated-no-expiry-v2', [...LEGACY_FIXTURE, ...extra]);
  if (JSON.stringify(migrations.noExpiry.result.sessionsWithoutExpiry) !== '["session:a62"]') throw new Error('A-62: expected one session without expiry');
}

// ---------------------------------------------------------------- rich-v2: every §7.2 kind (the scenario of packages/core/test/helpers/format2-histories.mjs richHistory, deterministic)

const editions = await import(join(ROOT, 'packages/core/dist/adapter-editions.js'));
const admission = await import(join(ROOT, 'packages/core/dist/admission.js'));
const administration = await import(join(ROOT, 'packages/core/dist/administration.js'));
/** A remote-service-report adapter whose reply is lost (OUTCOME_UNKNOWN); its identity is kept for a later observation. */
const lostReplyAdapter = () => {
  const held = { identity: undefined };
  const unknown = (submission) => {
    held.identity = admission.deriveAdapterIdentity(submission);
    return { status: 'OUTCOME_UNKNOWN', idempotencyKey: held.identity.idempotencyKey, submissionFingerprint: held.identity.submissionFingerprint };
  };
  const adapter = { adapterProfile: editions.approvedAdapterProfileForPolicy(editions.ADAPTER_POLICY_E6_HASH, editions.REMOTE_SERVICE_REPORT_ADAPTER_ID), submit: async (s) => unknown(s), reconcile: (s) => unknown(s) };
  Object.defineProperty(adapter, 'adapterProfile', { value: adapter.adapterProfile, writable: false, configurable: false, enumerable: true });
  return { adapter, held };
};
/** A simulated adapter that retains a FAILED result (with a no-effect proof) for the named intents, SUBMITTED otherwise. */
const simulatedAdapter = (failIntentIds) => {
  const results = new Map(), profile = editions.approvedAdapterProfile(editions.SIMULATED_ADAPTER_ID);
  const retained = (identity) => {
    const prior = results.get(identity.idempotencyKey);
    if (prior === undefined) return undefined;
    const common = { status: 'RETRY', idempotencyKey: identity.idempotencyKey, submissionFingerprint: identity.submissionFingerprint, retainedEvidence: prior.evidence };
    return prior.status === 'SUBMITTED' ? { ...common, acknowledgment: prior.acknowledgment } : { ...common, noEffect: prior.noEffect };
  };
  return {
    adapterProfile: profile,
    reconcile(input) { const identity = admission.deriveAdapterIdentity(input); return retained(identity) ?? { status: 'OUTCOME_UNKNOWN', idempotencyKey: identity.idempotencyKey, submissionFingerprint: identity.submissionFingerprint }; },
    async submit(input) {
      const identity = admission.deriveAdapterIdentity(input), prior = retained(identity);
      if (prior !== undefined) return prior;
      const { idempotencyKey, submissionFingerprint } = identity;
      let result;
      if (failIntentIds.includes(input.intentId)) { const noEffect = editions.createAdapterNoEffect(identity); result = { status: 'FAILED', idempotencyKey, submissionFingerprint, evidence: editions.adapterNoEffectEvidence(identity, noEffect), noEffect }; }
      else { const acknowledgment = editions.createAdapterAcknowledgment(identity); result = { status: 'SUBMITTED', idempotencyKey, submissionFingerprint, evidence: editions.adapterAcknowledgmentEvidence(identity, acknowledgment), acknowledgment }; }
      results.set(idempotencyKey, result);
      return result;
    },
  };
};
const budgetOf = (budgetId, extra = {}) => ({ budgetId, subjects: { actorIds: null, roleIds: null, actions: ['pay'], resources: null }, metric: 'amount', period: { kind: 'NONE' }, amountCap: '10000', countCap: null, perOperationCap: null, notBefore: null, expiresAt: null, ...extra });
/** Positions of the rich history where a §7.2 kind first appears (pinned as accepted prefixes). */
const rich = { marks: {} };
{
  const h = scripted('rich');
  const c = await createLocalReviewOwner(h.config);
  const mark = (label) => { rich.marks[label] = readStore(h.historyFile).length; };
  for (const id of ['a', 'b', 'c']) await c.createAgent({ id });
  await c.createRole({ id: 'reviewer' });
  await c.declareSuccession({ id: 'handover', from: 'a', to: 'b', role: 'reviewer' });
  await c.appoint({ agent: 'a', role: 'reviewer', tenure: 'shift:1', number: 1, succession: 'handover' });
  await c.admitRuntime({ session: 'session:a', agent: 'a', epoch: 1, key: 'key:bea', credential: BEA.credential, expiresAt: 1000 });
  await c.admitRuntime({ session: 'session:b', agent: 'b', epoch: 1, key: 'key:alex', credential: ALEX.credential, expiresAt: 1000 });
  await c.admitRuntime({ session: 'session:c', agent: 'c', epoch: 1, key: 'key:eip191', address: EIP191.credential, expiresAt: 1000 });
  mark('sessions');
  h.clock.t = 101;
  await c.grant({ id: 'collect', to: 'a', actions: ['read', 'OBLIGATE'], resources: ['incident:42', 'incident:41'], expiresAt: 900, notBefore: 50 });
  await c.grant({ id: 'count', to: 'c', actions: ['ping'], resources: ['svc'], expiresAt: 900, maxTransactions: 2 });
  await c.grant({ id: 'review', to: 'b', actions: ['record-collection-disposition'], resources: ['duty:42'], expiresAt: 900 });
  await c.grant({ id: 'quant', to: 'a', actions: ['pay'], resources: ['vendor'], expiresAt: 900, maxAmount: 2500n, maxCumulativeAmount: 5000n, maxTransactions: 3 });
  await c.grant({ id: 'c-read', to: 'c', actions: ['read'], resources: ['incident:42'], expiresAt: 150 });
  await c.grant({ id: 'c-mixed', to: 'c', actions: ['write', 'read'], resources: ['doc:2', 'doc:1'], expiresAt: 900 });
  await c.declareBudget(budgetOf('b-pay', { period: { kind: 'FIXED_WINDOW', lengthMs: 1000, originMs: 0, carryUnused: true, carryCap: '500' }, amountCap: '4000' }));
  await c.declareBudget(budgetOf('b-role', { subjects: { actorIds: null, roleIds: ['reviewer'], actions: null, resources: null }, countCap: 50 }));
  await c.registerCounterparty({ counterpartyId: 'acme', keys: [{ keyId: 'acme:1', scheme: 'ed25519', credential: ACME.credential }] });
  mark('budgets-and-counterparty');
  const a = h.session('session:a', BEA), b = h.session('session:b', ALEX);
  h.clock.t = 102;
  const read = op('operation:42', { termsCommitment: commitTerms({ subject: 'Synthetic incident review' }) });
  const sim = openLocalSimulation(a);
  if ((await sim.run(read)).invocation.status !== 'SUBMITTED') throw new Error('rich: run');
  mark('intent-consumed');
  h.clock.t = 103;
  if ((await sim.recordReceipt(read)).recording.status !== 'ADMITTED') throw new Error('rich: receipt');
  mark('receipt');
  const pay = { id: 'pay:1', intentId: 'pay:1', action: 'pay', resource: 'vendor', role: 'reviewer', tenure: 'shift:1', amount: 1200n, counterparty: 'acme', termsCommitment: commitTerms({ invoice: 1 }) };
  if ((await sim.run(pay)).invocation.status !== 'SUBMITTED') throw new Error('rich: pay');
  mark('budget-usage');
  const failed = await openLocalExecution(a, simulatedAdapter(['op:fail']), 'SIMULATION').run(op('op:fail', { resource: 'incident:41', termsCommitment: commitTerms({ subject: 'fails' }) }));
  if (failed.invocation.status !== 'FAILED') throw new Error(`rich: failed run ${failed.invocation.status}`);
  mark('outcome');
  h.clock.t = 104;
  const runtimeA = openLocalRuntime(a);
  await runtimeA.obligate({ id: 'duty:42', operation: read.id, description: 'Review the collected material.', deadline: 800, succession: 'handover', reviewAuthority: 'review' });
  mark('obligation');
  const envelope = await envelopeFor(readStore(h.historyFile), 'pay:1', '1200', null);
  await runtimeA.recordCounterpartyReceipt({ intentId: 'pay:1', envelope });
  await runtimeA.recordEffect({ effectId: 'effect:1', intentId: 'pay:1', measurer: { kind: 'SESSION', id: 'a' }, metric: 'amount', unit: 'cent', amount: 1200n, observedAt: 103 });
  await runtimeA.recordEffect({ effectId: 'effect:2', intentId: 'pay:1', measurer: { kind: 'COUNTERPARTY', id: 'acme' }, metric: 'amount', unit: 'cent', amount: 1200n, observedAt: 104, detailDigest: core.envelopeDigest(envelope) });
  await runtimeA.recordRefusal({ refusalId: 'refusal:1', request: { actorId: 'a', action: 'pay', resource: 'nowhere', claimedAt: 104, amount: 1n } });
  mark('effects-and-refusal');
  h.clock.t = 105;
  await c.revoke('quant');
  h.clock.t = 106;
  for (const [id, action] of [['a-duty', 'CREATE_ATTEMPT_DUTY'], ['a-observe', 'OBSERVE_OUTCOME'], ['a-close', 'CLOSE_ATTEMPT_DUTY'], ['a-ticket', 'create-ticket']]) {
    await c.grant({ id, to: 'a', actions: [action], resources: [action === 'create-ticket' ? 'queue:security' : 'ticket:1'], expiresAt: 900 });
  }
  const { adapter, held } = lostReplyAdapter();
  h.clock.t = 107;
  if ((await openLocalExecution(a, adapter, 'REMOTE_REPORT').run(op('ticket:1', { action: 'create-ticket', resource: 'queue:security', termsCommitment: commitTerms({ title: 'Review this synthetic incident' }) }))).invocation.status !== 'OUTCOME_UNKNOWN') throw new Error('rich: attempt');
  const recorder = openLocalAttemptRecorder(a);
  h.clock.t = 108;
  await recorder.createDuty({ id: 'investigation', intent: 'ticket:1', description: 'Find out whether the ticket exists.', deadline: 800 });
  mark('attempt-duty');
  h.clock.t = 109;
  await recorder.observe({ id: 'late-report', intent: 'ticket:1', acknowledgment: editions.createRemoteServiceReportAcknowledgment(held.identity, `0x${'ab'.repeat(32)}`) });
  mark('observation');
  h.clock.t = 110;
  await recorder.reviewDuty({ id: 'review-1', duty: 'investigation', summaryDigest: `0x${'cd'.repeat(32)}` });
  await c.checkpoint({ checkpointId: 'cp:manual' });
  mark('checkpoint');
  h.clock.t = 111;
  await c.updateBudget({ budgetId: 'b-pay', subjects: { actorIds: null, roleIds: null, actions: ['pay'], resources: null }, amountCap: '3000', countCap: 10, perOperationCap: '2000', expiresAt: null });
  h.clock.t = 120;
  await c.succeed({ id: 'handover:1', rule: 'handover', fromAgent: 'a', fromTenure: 'shift:1', toAgent: 'b', toTenure: 'shift:2', role: 'reviewer', number: 2 });
  mark('succession');
  h.clock.t = 121;
  await c.grant({ id: 'assign', to: 'b', actions: ['ASSIGN_PERFORMANCE'], resources: ['duty:42'], expiresAt: 900 });
  h.clock.t = 122;
  await openLocalRuntime(b).assign({ id: 'assign:42', obligation: 'duty:42' });
  h.clock.t = 123;
  await c.grant({ id: 'b-assign', to: 'b', actions: ['ASSIGN_ATTEMPT_DUTY'], resources: ['ticket:1'], expiresAt: 900 });
  h.clock.t = 124;
  await openLocalAttemptRecorder(b).assignDuty({ id: 'reassign', duty: 'investigation' });
  mark('assignments');
  h.clock.t = 125;
  await c.advanceEpoch({ agent: 'c', from: 1, to: 2 });
  await c.closeBudget({ budgetId: 'b-role' });
  await c.retireCounterparty({ counterpartyId: 'acme' });
  h.clock.t = 126;
  await c.rotateOwnerKey({ nextSigner, newNextSigner: signer.signerFromKeyPair(NEXT_NEXT), reason: 'scheduled pre-rotated rotation' });
  mark('owner-key-epoch');
  await c.createAgent({ id: 'd' });
  h.clock.t = 127;
  const store = openHistoryStore(h.historyFile, { signer: nextSigner, witness: false });
  // A custom anchor target with a fixed receipt (as conformance/v1): the local anchor log stamps the wall clock.
  const target = { kind: 'custom', name: 'custom', submit: async (attestation) => ({ witness: 'conformance-fixture', attestedHash: attestation.head.hash }), verify: async () => true };
  await core.anchorHead(store, nextSigner, target, { id: 'anchor:1', anchoredAt: 127 });
  rich.anchorMark = store.state().events.length;
  const domain = store.state().genesis.domain;
  rich.policy = { quorum: 1, requireOnOpen: false, maxUnwitnessedEvents: 1000 };
  rich.witnesses = [
    { url: 'https://witness-a.example.org', verifierKey: 'witness-a.example.org+07c49b56+AcBQxWN6RPqGKf/zzMziMAyzYqY9mdlfxUFFJm9DMkRa', name: 'witness-a' },
    { url: 'https://witness-b.example.org', verifierKey: 'witness-b.example.org+8708f444+ASASy5DKYOjl2Nr2biJy0iM+BIbVV+jGYUHtiSAXfX63' },
  ];
  store.append(await signer.signControlEvent(nextSigner, { id: 'bind:1', type: 'WITNESSES_BOUND', timestamp: 127, data: { witnesses: rich.witnesses, policy: rich.policy } }, domain, store.head(), 'sha256'));
  rich.boundMark = store.state().events.length;
  store.append(await signer.signControlEvent(nextSigner, { id: 'unbind:1', type: 'WITNESSES_UNBOUND', timestamp: 128, data: { verifierKeys: [rich.witnesses[1].verifierKey], policy: rich.policy } }, domain, store.head(), 'sha256'));
  store.close?.();
  rich.marks.anchor = rich.anchorMark;
  rich.marks['witness-binding'] = rich.boundMark;
  rich.events = save('rich-v2', readStore(h.historyFile), h.historyFile);
  rich.marks.final = rich.events.length;
}

// ---------------------------------------------------------------- budgets-v2: A-50 saturated rollover (amountCap near MAX), the roleIds budget
const MAX = (1n << 256n) - 1n;
const budgetsH = {};
{
  const h = scripted('budgets');
  const owner = await createLocalOwner(h.config);
  await owner.createAgent({ id: 'spender' });
  await owner.createRole({ id: 'cashier' });
  await owner.appoint({ agent: 'spender', role: 'cashier', tenure: 'cashier:1', number: 1 });
  await owner.admitRuntime({ session: 'session:spender', agent: 'spender', epoch: 1, key: 'key:spender', credential: SPENDER.credential, expiresAt: 10_000_000 });
  await owner.grant({ id: 'spend', to: 'spender', actions: ['spend'], resources: ['big', 'petty-cash'], expiresAt: 10_000_000, maxAmount: MAX });
  // A-50: allowed(k) = min(MAX, cap + carryIn(k)); unused(k) = allowed(k) − used(k) (saturated before the subtraction).
  await owner.declareBudget({ budgetId: 'b-sat', subjects: { actorIds: null, roleIds: null, actions: ['spend'], resources: ['big'] }, metric: 'amount',
    period: { kind: 'FIXED_WINDOW', lengthMs: 1000, originMs: 0, carryUnused: true, carryCap: '100' }, amountCap: (MAX - 10n).toString(), countCap: null, perOperationCap: null, notBefore: null, expiresAt: null });
  budgetsH.declared = h.events().length;
  h.clock.t = 1100;
  const sim = openLocalSimulation(h.session('session:spender', SPENDER));
  const spend = (id, amount, resource) => ({ id, intentId: id, action: 'spend', resource, role: 'cashier', tenure: 'cashier:1', amount, termsCommitment: commitTerms({ purpose: id }) });
  const r = await sim.run(spend('spend:big', MAX - 50n, 'big'));
  if (r.invocation?.status !== 'SUBMITTED') throw new Error(`budgets: A-50 spend ${JSON.stringify(r.status)}`);
  // A receipt record of an amount-bearing intent (the receipt policy compares the format-2 proof in its wire form).
  if ((await sim.recordReceipt(spend('spend:big', MAX - 50n, 'big'))).recording?.status !== 'ADMITTED') throw new Error('budgets: receipt');
  budgetsH.events = save('budgets-v2', h.events(), h.historyFile);
}

// ---------------------------------------------------------------- reserve-v2: the control-event reserve at a test-only lowered cap (capacity.ts setCapacityLimitsForTests)
const reserve = {};
{
  const h = scripted('reserve');
  const owner = await createLocalOwner(h.config);
  await owner.createAgent({ id: 'bea' });
  await owner.admitRuntime({ session: 'session:bea', agent: 'bea', epoch: 1, key: 'key:bea', credential: BEA.credential, expiresAt: 10_000_000 });
  await owner.grant({ id: 'read', to: 'bea', actions: ['read'], resources: ['incident:42'], expiresAt: 10_000_000 });
  reserve.base = h.events().length;
  reserve.records = accepted(h.events()).state.stateRecords.size;
  const runtime = openLocalRuntime(h.session('session:bea', BEA));
  await runtime.recordRefusal({ refusalId: 'refusal:reserve', request: { actorId: 'bea', action: 'write', resource: 'incident:42', claimedAt: 100 } });
  for (const id of ['x1', 'x2', 'x3']) await owner.createAgent({ id });
  reserve.events = save('reserve-v2', h.events(), h.historyFile);
  // records after: base R0; refusal +2 (refusal, event); every agent +2 (agent, event).
  const sizes = reserve.events.map((_, p) => accepted(reserve.events.slice(0, p + 1)).state.stateRecords.size);
  reserve.sizes = sizes;
}

// ---------------------------------------------------------------- budget-set-v2: 256 budgets (17 of them match one request), for BUDGET_SET_TOO_LARGE and the 257th declaration
const budgetSet = {};
{
  const h = scripted('budget-set');
  const owner = await createLocalOwner(h.config);
  await owner.createAgent({ id: 'spender' });
  await owner.createRole({ id: 'cashier' });
  await owner.appoint({ agent: 'spender', role: 'cashier', tenure: 'cashier:1', number: 1 });
  await owner.grant({ id: 'spend', to: 'spender', actions: ['spend'], resources: ['wide', 'narrow'], expiresAt: 10_000_000, maxAmount: 1000n });
  const id = (n) => `b-${String(n).padStart(3, '0')}`;
  for (let n = 0; n < 256; n += 1) {
    await owner.declareBudget({ budgetId: id(n), subjects: { actorIds: null, roleIds: null, actions: ['spend'], resources: [n < 17 ? 'wide' : `r-${n}`] }, metric: 'amount', period: { kind: 'NONE' }, amountCap: '1000', countCap: null, perOperationCap: null, notBefore: null, expiresAt: null });
    if (n === 15) budgetSet.sixteen = h.events().length;
  }
  budgetSet.events = save('budget-set-v2', h.events(), h.historyFile);
  budgetSet.id = id;
}

// ---------------------------------------------------------------- effects-v2: 64 effects on one admitted intent (SPEC §10.2 EFFECT_LIMIT is the 65th)
const effects = {};
{
  const h = scripted('effects');
  const owner = await createLocalOwner(h.config);
  await owner.createAgent({ id: 'bea' });
  await owner.createRole({ id: 'reviewer' });
  await owner.appoint({ agent: 'bea', role: 'reviewer', tenure: 'shift:1', number: 1 });
  await owner.admitRuntime({ session: 'session:bea', agent: 'bea', epoch: 1, key: 'key:bea', credential: BEA.credential, expiresAt: 10_000_000 });
  await owner.grant({ id: 'pay', to: 'bea', actions: ['pay'], resources: ['vendor'], expiresAt: 10_000_000, maxAmount: 1000n });
  const options = h.session('session:bea', BEA);
  if ((await openLocalSimulation(options).run(op('pay:1', { action: 'pay', resource: 'vendor', amount: 640n }))).status !== 'SIMULATION_RESULT') throw new Error('effects: run');
  const runtime = openLocalRuntime(options);
  for (let n = 1; n <= 64; n += 1) await runtime.recordEffect({ effectId: `effect:${n}`, intentId: 'pay:1', measurer: { kind: 'SESSION', id: 'bea' }, metric: 'amount', unit: 'cent', amount: 10n, observedAt: 100 });
  effects.events = save('effects-v2', h.events(), h.historyFile);
}

// ---------------------------------------------------------------- counterparty-v2: a receipt chain kept across retirement and re-registration with a new key (SPEC §11)
const counterparty = {};
{
  const h = scripted('counterparty');
  const owner = await createLocalOwner(h.config);
  await owner.createAgent({ id: 'bea' });
  await owner.createRole({ id: 'reviewer' });
  await owner.appoint({ agent: 'bea', role: 'reviewer', tenure: 'shift:1', number: 1 });
  await owner.admitRuntime({ session: 'session:bea', agent: 'bea', epoch: 1, key: 'key:bea', credential: BEA.credential, expiresAt: 10_000_000 });
  await owner.grant({ id: 'pay', to: 'bea', actions: ['pay'], resources: ['vendor'], expiresAt: 10_000_000, maxAmount: 1000n });
  await owner.registerCounterparty({ counterpartyId: 'acme', keys: [{ keyId: 'acme:1', scheme: 'ed25519', credential: ACME.credential }] });
  const options = h.session('session:bea', BEA), sim = openLocalSimulation(options), runtime = openLocalRuntime(options);
  for (const id of ['pay:1', 'pay:2']) if ((await sim.run(op(id, { action: 'pay', resource: 'vendor', amount: 10n, counterparty: 'acme' }))).status !== 'SIMULATION_RESULT') throw new Error(`counterparty: ${id}`);
  const first = await envelopeFor(h.events(), 'pay:1', '10', null);
  await runtime.recordCounterpartyReceipt({ intentId: 'pay:1', envelope: first });
  counterparty.firstDigest = core.envelopeDigest(first);
  await owner.retireCounterparty({ counterpartyId: 'acme' });
  counterparty.retired = h.events().length;
  await owner.registerCounterparty({ counterpartyId: 'acme', keys: [{ keyId: 'acme:2', scheme: 'ed25519', credential: ACME2.credential }] });
  counterparty.reregistered = h.events().length;
  await runtime.recordCounterpartyReceipt({ intentId: 'pay:2', envelope: await envelopeFor(h.events(), 'pay:2', '10', counterparty.firstDigest, ACME2) });
  counterparty.events = save('counterparty-v2', h.events(), h.historyFile);
}

// ---------------------------------------------------------------- handover-budget-v2: a roleIds budget keeps matching the successor after the handover, usage retained (T6)
const handoverBudget = {};
{
  const h = scripted('handover-budget');
  const owner = await createLocalOwner(h.config);
  await owner.createAgent({ id: 'bea' });
  await owner.createAgent({ id: 'alex' });
  await owner.createRole({ id: 'reviewer' });
  await owner.declareSuccession({ id: 'handover', from: 'bea', to: 'alex', role: 'reviewer' });
  await owner.appoint({ agent: 'bea', role: 'reviewer', tenure: 'shift:1', number: 1, succession: 'handover' });
  await owner.admitRuntime({ session: 'session:bea', agent: 'bea', epoch: 1, key: 'key:bea', credential: BEA.credential, expiresAt: 10_000_000 });
  await owner.admitRuntime({ session: 'session:alex', agent: 'alex', epoch: 1, key: 'key:alex', credential: ALEX.credential, expiresAt: 10_000_000 });
  await owner.grant({ id: 'spend-bea', to: 'bea', actions: ['spend'], resources: ['petty-cash'], expiresAt: 10_000_000, maxAmount: 1000n });
  await owner.grant({ id: 'spend-alex', to: 'alex', actions: ['spend'], resources: ['petty-cash'], expiresAt: 10_000_000, maxAmount: 1000n });
  await owner.declareBudget({ budgetId: 'b-role', subjects: { actorIds: null, roleIds: ['reviewer'], actions: ['spend'], resources: null }, metric: 'amount', period: { kind: 'NONE' }, amountCap: null, countCap: 2, perOperationCap: null, notBefore: null, expiresAt: null });
  const spend = (id, tenure) => op(id, { action: 'spend', resource: 'petty-cash', tenure, amount: 5n });
  if ((await openLocalSimulation(h.session('session:bea', BEA)).run(spend('spend:bea', 'shift:1'))).status !== 'SIMULATION_RESULT') throw new Error('handover-budget: bea');
  handoverBudget.beforeHandover = h.events().length;
  h.clock.t = 200;
  await owner.succeed({ id: 'handover:1', rule: 'handover', fromAgent: 'bea', fromTenure: 'shift:1', toAgent: 'alex', toTenure: 'shift:2', role: 'reviewer', number: 2 });
  handoverBudget.afterHandover = h.events().length;
  if ((await openLocalSimulation(h.session('session:alex', ALEX)).run(spend('spend:alex', 'shift:2'))).status !== 'SIMULATION_RESULT') throw new Error('handover-budget: alex');
  handoverBudget.events = save('handover-budget-v2', h.events(), h.historyFile);
}

// ---------------------------------------------------------------- checkpoints-v2: genesis checkpointPolicy everyEvents 4 (SPEC §7.3, A-46/A-66)
const checkpoints = {};
{
  const h = scripted('checkpoints', { checkpointPolicy: { everyEvents: 4 } });
  const owner = await createLocalOwner(h.config);
  for (const id of ['a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9']) { h.clock.t += 1; await owner.createAgent({ id }); }
  checkpoints.events = save('checkpoints-v2', h.events(), h.historyFile);
  checkpoints.positions = checkpoints.events.map((e, p) => (e.type === 'STATE_CHECKPOINT' ? p : -1)).filter((p) => p >= 0);
  if (checkpoints.positions.length < 2) throw new Error(`checkpoints: expected automatic checkpoints, got ${checkpoints.positions}`);
}

// ---------------------------------------------------------------- capacity-v2: genesis capacity.maxStateRecords (SPEC §5.1, A-3 step 3, A-56.24)
const capacityH = {};
{
  const probe = scripted('capacity-probe');
  const build = async (h) => {
    const owner = await createLocalOwner(h.config);
    await owner.createAgent({ id: 'bea' });
    await owner.admitRuntime({ session: 'session:bea', agent: 'bea', epoch: 1, key: 'key:bea', credential: BEA.credential, expiresAt: 10_000_000 });
    await owner.grant({ id: 'read', to: 'bea', actions: ['read'], resources: ['incident:42'], expiresAt: 10_000_000 });
    return { owner, runtime: openLocalRuntime(h.session('session:bea', BEA)) };
  };
  await build(probe);
  const base = accepted(probe.events()).state.stateRecords.size;
  // One refusal (+2 records) fits exactly; the next refusal is refused by the writer; a control event is still admitted.
  const h = scripted('capacity', { maxStateRecords: base + 2 });
  const { owner, runtime } = await build(h);
  await runtime.recordRefusal({ refusalId: 'refusal:1', request: { actorId: 'bea', action: 'write', resource: 'incident:42', claimedAt: 100 } });
  capacityH.atCap = h.events().length;
  let refused = null;
  try { await runtime.recordRefusal({ refusalId: 'refusal:2', request: { actorId: 'bea', action: 'delete', resource: 'incident:42', claimedAt: 100 } }); } catch (error) { refused = error.code; }
  if (refused !== 'CAPACITY_EXCEEDED') throw new Error(`capacity: the writer should refuse the second refusal with CAPACITY_EXCEEDED, got ${refused}`);
  await owner.createAgent({ id: 'late' });
  capacityH.events = save('capacity-v2', h.events(), h.historyFile);
  capacityH.base = base;
}

// ---------------------------------------------------------------- duty-policy-v2: the SPEC §13 duty policy on an EIP-191 deployment (packages/core/test/helpers/duty-fixture.mjs, deterministic)

const DUTY_DIGEST = (c) => ({ algorithm: 'sha256', value: `0x${c.repeat(64)}` });
const DUTY_CHECKLIST = () => Object.fromEntries(['SOURCE_REVIEWED', 'HISTORY_REVIEWED', 'FINDING_RECORDED', 'CONTROL_REVIEWED'].map((k) => [k, { state: 'SATISFIED', reason: 'Reviewed; remaining outside uncertainty stated.' }]));
const unknownOutcome = (input) => { const identity = admission.deriveAdapterIdentity(input); return { status: 'OUTCOME_UNKNOWN', idempotencyKey: identity.idempotencyKey, submissionFingerprint: identity.submissionFingerprint }; };
/**
 * describe → activate → dispose (COMPLETED_UNDER_POLICY) → review (NEEDS_REVIEW) → contest (CONTESTED); `stopAfter` ends the
 * scenario early. The session is the reference's EIP-191 fixture credential (declarations, admissions and duty findings are
 * EIP-191 signatures).
 */
async function dutyHistory(name, { maxEvents, stopAfter } = {}) {
  const h = scripted(name, { owner: 'owner', controller: 'controller', signatureScheme: 'eip191-personal-sign-keccak256', ...(maxEvents === undefined ? {} : { maxEvents }) });
  const marks = {};
  const mark = (label) => { marks[label] = h.events().length; };
  const owner = await createLocalReviewOwner(h.config);
  await owner.createAgent({ id: 'worker' });
  await owner.createAgent({ id: 'replacement' });
  await owner.createRole({ id: 'role' });
  await owner.appoint({ agent: 'worker', role: 'role', tenure: 'tenure', number: 1 });
  await owner.declareSuccession({ id: 'succession', from: 'worker', to: 'replacement', role: 'role' });
  await owner.admitRuntime({ agent: 'worker', session: 'session', epoch: 1, key: 'key', address: FIXTURE_KEY.credential, scheme: 'eip191-personal-sign-keccak256', expiresAt: 10000 });
  await owner.grant({ id: 'work', to: 'worker', actions: ['inspect'], resources: ['incident'], expiresAt: 10000, maxTransactions: 1 });
  await owner.grant({ id: 'record', to: 'worker', actions: ['OBLIGATE', 'ASSIGN_PERFORMANCE', 'record-collection-disposition', 'OBSERVE_OUTCOME', 'CREATE_ATTEMPT_DUTY', 'ASSIGN_ATTEMPT_DUTY', 'CLOSE_ATTEMPT_DUTY'], resources: ['incident', 'job', 'duty'], expiresAt: 10000 });
  const options = h.session('session', FIXTURE_KEY);
  const adapter = { adapterProfile: editions.approvedAdapterProfileForPolicy(editions.ADAPTER_POLICY_E6_HASH, editions.REMOTE_SERVICE_REPORT_ADAPTER_ID), submit: async (input) => unknownOutcome(input), reconcile: unknownOutcome };
  const job = { id: 'job', intentId: 'job', action: 'inspect', resource: 'incident', role: 'role', tenure: 'tenure', termsCommitment: commitTerms({ case: 'synthetic' }) };
  if ((await openLocalExecution(options, adapter, 'REMOTE_REPORT').run(job)).invocation.status !== 'OUTCOME_UNKNOWN') throw new Error(`${name}: job`);
  await openLocalAttemptRecorder(options).createDuty({ id: 'duty', intent: 'job', description: 'Investigate the unknown result', deadline: 10000 });
  mark('duty-created');
  const duties = core.openLocalDutyPolicy(options);
  const selection = duties.describe({ duty: 'duty', incidentSourceDigest: DUTY_DIGEST('a'), attesterRole: 'role' });
  await owner.grant({ id: 'activation', to: 'worker', actions: [selection.activationAction], resources: [selection.activationResource], expiresAt: 1000 });
  await duties.activate({ id: 'activate', descriptor: selection.descriptor, activationAuthority: 'activation' });
  mark('activated');
  const capacity = owner.capacity();
  if (stopAfter === 'activated') return { h, owner, options, marks, capacity, events: save(name, h.events(), h.historyFile) };
  const resource = `duty:${selection.descriptorHash}`;
  await owner.grant({ id: 'finding', to: 'worker', actions: ['ATTEST_DUTY_FINDING'], resources: [resource], expiresAt: 1000 });
  await owner.grant({ id: 'disposition', to: 'worker', actions: ['RECORD_DUTY_DISPOSITION'], resources: [resource], expiresAt: 1000 });
  const authorities = { attestationAuthority: 'finding', dispositionAuthority: 'disposition' };
  await duties.dispose({ id: 'complete', duty: 'duty', disposition: 'COMPLETED_UNDER_POLICY', checklist: DUTY_CHECKLIST(), reportDigest: DUTY_DIGEST('b'), nextStep: null, ...authorities });
  mark('completed');
  if (stopAfter === 'completed') return { h, owner, options, marks, capacity, events: save(name, h.events(), h.historyFile) };
  await openLocalAttemptRecorder(options).reviewDuty({ id: 'after-completion', duty: 'duty', summaryDigest: `0x${'e'.repeat(64)}` });
  mark('needs-review');
  await duties.contest({ id: 'challenge', duty: 'duty', targetDispositionId: 'duty-disposition:complete', reason: 'Incident material may have been incomplete.', reportDigest: DUTY_DIGEST('c'), ...authorities });
  mark('contested');
  return { h, owner, options, marks, capacity, events: save(name, h.events(), h.historyFile) };
}
const duty = await dutyHistory('duty-policy-v2');
// CAPACITY_CONTROL_ONLY with the duty quota (SPEC §5.2, §13.5, A-2): maxEvents exactly at the committed space after the activation.
const dutyCapped = {};
{
  const probe = await dutyHistory('duty-capacity-probe', { stopAfter: 'activated' });
  delete histories['duty-capacity-probe']; outputs.delete('histories/duty-capacity-probe.json'); outputs.delete('histories/duty-capacity-probe.jsonl');
  dutyCapped.maxEvents = probe.marks.activated + probe.capacity.lifecycleReserved + probe.capacity.dutyReserved;
  if (probe.capacity.dutyReserved !== 6) throw new Error(`duty quota: expected 6 reserved slots, got ${probe.capacity.dutyReserved}`);
  const x = await dutyHistory('duty-capacity-v2', { maxEvents: dutyCapped.maxEvents, stopAfter: 'completed' });
  let refused = null;
  try { await openLocalRuntime(x.options).recordRefusal({ refusalId: 'refusal:growth', request: { actorId: 'worker', action: 'export', resource: 'incident', claimedAt: 100 } }); } catch (error) { refused = error.code; }
  if (refused !== 'CAPACITY_CONTROL_ONLY') throw new Error(`duty capacity: the writer should refuse growth with CAPACITY_CONTROL_ONLY, got ${refused}`);
  Object.assign(dutyCapped, x);
}

// ---------------------------------------------------------------- the conformance/v1 histories re-expressed in format 2

const transparency = await import(join(ROOT, 'packages/core/dist/transparency/index.js'));
/** The runtime keys of conformance/v1 (seed 0x2000 + n, the same key ids), so the v1 histories are the format-1 twins of these. */
const runtimeKey = (keyId, n) => key(keyId, 0x2000 + n, 'ed25519', `${keyId} (conformance/v1 seed)`);
const ok = (pair) => ({ keyId: pair.keyId, scheme: 'ed25519', credential: pair.credential });

// handover-v2 (+ handover-anchored-v2): a signed handover with an obligation and an assignment
const handover = {};
{
  const h = scripted('handover');
  const owner = await createLocalOwner(h.config);
  const step = async (p) => { const r = await p; h.clock.t += 1; return r; };
  const bea = runtimeKey('key:bea', 1), alex = runtimeKey('key:alex', 2);
  await step(owner.createAgent({ id: 'bea' }));
  await step(owner.createAgent({ id: 'alex' }));
  await step(owner.createRole({ id: 'reviewer' }));
  await step(owner.declareSuccession({ id: 'handover', from: 'bea', to: 'alex', role: 'reviewer' }));
  await step(owner.appoint({ agent: 'bea', role: 'reviewer', tenure: 'shift:1', number: 1, succession: 'handover' }));
  await step(owner.admitRuntime({ session: 'session:bea', agent: 'bea', epoch: 1, key: 'key:bea', credential: bea.credential, expiresAt: 900 }));
  await step(owner.admitRuntime({ session: 'session:alex', agent: 'alex', epoch: 1, key: 'key:alex', credential: alex.credential, expiresAt: 900 }));
  await step(owner.grant({ id: 'collect', to: 'bea', actions: ['read', 'OBLIGATE'], resources: ['incident:42'], expiresAt: 800 }));
  await step(owner.grant({ id: 'review', to: 'alex', actions: ['record-collection-disposition'], resources: ['duty:42'], expiresAt: 800 }));
  await step(owner.grant({ id: 'progress', to: 'alex', actions: ['read'], resources: ['progress:42'], expiresAt: 800 }));
  const read = op('operation:42', { termsCommitment: commitTerms({ subject: 'Synthetic incident review' }) });
  const sim = openLocalSimulation(h.session('session:bea', bea));
  if ((await step(sim.run(read))).invocation?.status !== 'SUBMITTED') throw new Error('handover: run');
  if ((await step(sim.recordReceipt(read))).recording?.status !== 'ADMITTED') throw new Error('handover: receipt');
  await step(openLocalRuntime(h.session('session:bea', bea)).obligate({ id: 'duty:42', operation: read.id, description: 'Review the collected material.', deadline: 700, succession: 'handover', reviewAuthority: 'review' }));
  handover.before = h.events().length;
  await step(owner.succeed({ id: 'handover:42', rule: 'handover', fromAgent: 'bea', fromTenure: 'shift:1', toAgent: 'alex', toTenure: 'shift:2', role: 'reviewer', number: 2 }));
  await step(owner.grant({ id: 'assign', to: 'alex', actions: ['ASSIGN_PERFORMANCE'], resources: ['duty:42'], expiresAt: 800 }));
  await step(openLocalRuntime(h.session('session:alex', alex)).assign({ id: 'assign:42', obligation: 'duty:42' }));
  await step(owner.revoke('collect'));
  handover.events = save('handover-v2', h.events(), h.historyFile);
  const store = openHistoryStore(h.historyFile, { signer: ownerSigner, witness: false });
  const target = { kind: 'custom', name: 'custom', submit: async (attestation) => ({ witness: 'conformance-fixture', attestedHash: attestation.head.hash }), verify: async () => true };
  handover.anchor = plain2((await core.anchorHead(store, ownerSigner, target, { id: 'handover:anchor', anchoredAt: h.clock.t })).event);
  store.close?.();
  handover.anchored = save('handover-anchored-v2', h.events(), h.historyFile);
}

// authority-v2: the authorization corpus (delegation, intersections, prohibitions, time, quantities)
{
  const h = scripted('authority');
  const owner = await createLocalOwner(h.config);
  const step = async (p) => { const r = await p; h.clock.t += 1; return r; };
  const lead = runtimeKey('key:lead', 3);
  for (const id of ['lead', 'analyst', 'intern', 'cadet', 'novice', 'clerk', 'guard', 'buyer', 'visitor', 'heir']) await step(owner.createAgent({ id }));
  await step(owner.createRole({ id: 'treasury' }));
  await step(owner.appoint({ agent: 'lead', role: 'treasury', tenure: 'treasury:1', number: 1 }));
  await step(owner.admitRuntime({ session: 'session:lead', agent: 'lead', epoch: 1, key: 'key:lead', credential: lead.credential, expiresAt: 900 }));
  await step(owner.grant({ id: 'root', to: 'lead', actions: ['read', 'write', 'pay'], resources: ['ledger', 'vault'], expiresAt: 800, delegable: 2, maxAmount: 1000n }));
  await step(owner.delegate({ id: 'analyst-read', from: 'lead', parent: 'root', to: 'analyst', actions: ['read'], resources: ['ledger'], expiresAt: 700, delegable: 1, maxAmount: 500n }));
  await step(owner.grant({ id: 'dual', to: 'analyst', actions: ['write'], resources: ['ledger'], expiresAt: 800, independent: false }));
  await step(owner.delegate({ id: 'write-with-dual', from: 'lead', parent: 'root', to: 'analyst', actions: ['write'], resources: ['ledger'], expiresAt: 700, requires: ['dual'], maxAmount: 500n }));
  await step(owner.grant({ id: 'approval', to: 'analyst', actions: ['write'], resources: ['vault'], expiresAt: 800, independent: false }));
  await step(owner.grant({ id: 'write-needs-approval', to: 'clerk', actions: ['write'], resources: ['vault'], expiresAt: 800, requires: ['approval'] }));
  await step(owner.prohibit({ id: 'no-vault-payments', root: 'root', actions: ['pay'], resources: ['vault'], expiresAt: 800, maxAmount: 1000n }));
  await step(owner.grant({ id: 'freezer', to: 'guard', actions: ['freeze'], resources: ['ledger'], expiresAt: 800 }));
  await step(owner.prohibit({ id: 'freeze-ban', global: true, actions: ['freeze'], resources: ['ledger'] }));
  await step(owner.grant({ id: 'temp', to: 'intern', actions: ['read'], resources: ['vault'], expiresAt: 800 }));
  await step(owner.revoke('temp'));
  await step(owner.grant({ id: 'short', to: 'cadet', actions: ['write'], resources: ['ledger'], expiresAt: 101 }));
  await step(owner.grant({ id: 'future', to: 'novice', actions: ['pay'], resources: ['ledger'], notBefore: 900, expiresAt: 1000 }));
  await step(owner.grant({ id: 'budget', to: 'buyer', actions: ['pay'], resources: ['ledger'], expiresAt: 800, maxAmount: 100n }));
  const spender = runtimeKey('key:spender', 4), stamper = runtimeKey('key:stamper', 5);
  await step(owner.createAgent({ id: 'spender' }));
  await step(owner.createAgent({ id: 'stamper' }));
  await step(owner.createRole({ id: 'cashier' }));
  await step(owner.createRole({ id: 'registrar' }));
  await step(owner.appoint({ agent: 'spender', role: 'cashier', tenure: 'cashier:1', number: 1 }));
  await step(owner.appoint({ agent: 'stamper', role: 'registrar', tenure: 'registrar:1', number: 1 }));
  await step(owner.admitRuntime({ session: 'session:spender', agent: 'spender', epoch: 1, key: 'key:spender', credential: spender.credential, expiresAt: 900 }));
  await step(owner.admitRuntime({ session: 'session:stamper', agent: 'stamper', epoch: 1, key: 'key:stamper', credential: stamper.credential, expiresAt: 900 }));
  await step(owner.grant({ id: 'metered', to: 'spender', actions: ['spend'], resources: ['petty-cash'], expiresAt: 800, maxAmount: 100n, maxCumulativeAmount: 100n, maxTransactions: 3 }));
  await step(owner.grant({ id: 'counted', to: 'stamper', actions: ['stamp'], resources: ['forms'], expiresAt: 800, maxTransactions: 1 }));
  const spendSim = openLocalSimulation(h.session('session:spender', spender));
  for (const [id, amount] of [['spend:1', 60n], ['spend:2', 30n]]) {
    const run = await step(spendSim.run({ id, intentId: id, action: 'spend', resource: 'petty-cash', role: 'cashier', tenure: 'cashier:1', termsCommitment: commitTerms({ purpose: id }), amount }));
    if (run.invocation?.status !== 'SUBMITTED') throw new Error(`authority: ${id}`);
  }
  const stamp = await step(openLocalSimulation(h.session('session:stamper', stamper)).run({ id: 'stamp:1', intentId: 'stamp:1', action: 'stamp', resource: 'forms', role: 'registrar', tenure: 'registrar:1', termsCommitment: commitTerms({ purpose: 'stamp:1' }) }));
  if (stamp.invocation?.status !== 'SUBMITTED') throw new Error('authority: stamp');
  await step(owner.createAgent({ id: 'leaver' }));
  await step(owner.createRole({ id: 'desk' }));
  await step(owner.declareSuccession({ id: 'desk-succession', from: 'leaver', to: 'heir', role: 'desk' }));
  await step(owner.appoint({ agent: 'leaver', role: 'desk', tenure: 'desk:1', number: 1, succession: 'desk-succession' }));
  await step(owner.grant({ id: 'leaver-read', to: 'leaver', actions: ['read'], resources: ['ledger'], expiresAt: 800 }));
  await step(owner.terminate({ agent: 'leaver', succession: 'desk-succession', role: 'desk', tenure: 'desk:1' }));
  save('authority-v2', h.events(), h.historyFile);
}

// rotation-v2: the opt-out history (no next-key commitment), rotated by the key in force alone
const rotation = {};
{
  const h = scripted('rotation', { nextKey: false });
  const owner = await createLocalOwner(h.config);
  const step = async (p) => { const r = await p; h.clock.t += 1; return r; };
  await step(owner.createAgent({ id: 'bea' }));
  await step(owner.grant({ id: 'read', to: 'bea', actions: ['read'], resources: ['ledger'], expiresAt: 900 }));
  rotation.before = h.events().length;
  const rotated = await step(owner.rotateOwnerKey({ newSigner: signer.signerFromKeyPair(ROTATED), reason: 'scheduled rotation', nextKey: false }));
  rotation.position = rotated.head.position;
  await step(owner.createAgent({ id: 'alex' }));
  await step(owner.revoke('read'));
  rotation.events = save('rotation-v2', h.events(), h.historyFile);
  if (rotation.events[0].data.nextKeyDigests !== undefined || rotation.events[rotation.position].type !== 'OWNER_KEYS_ROTATED') throw new Error('rotation-v2: unexpected shape');
}

// pre-rotation-v2: the genesis commitment, then a pre-rotated rotation
const preRotation = {};
{
  const h = scripted('pre-rotation');
  const owner = await createLocalOwner(h.config);
  const step = async (p) => { const r = await p; h.clock.t += 1; return r; };
  await step(owner.createAgent({ id: 'bea' }));
  await step(owner.grant({ id: 'read', to: 'bea', actions: ['read'], resources: ['ledger'], expiresAt: 900 }));
  preRotation.before = h.events().length;
  const rotated = await step(owner.rotateOwnerKey({ nextSigner, newNextSigner: signer.signerFromKeyPair(NEXT_NEXT), reason: 'scheduled pre-rotated rotation' }));
  if (!rotated.preRotated) throw new Error('pre-rotation-v2: expected a pre-rotated rotation');
  preRotation.position = rotated.head.position;
  await step(owner.createAgent({ id: 'alex' }));
  preRotation.events = save('pre-rotation-v2', h.events(), h.historyFile);
}

// witness-bound-v2: owner-signed WITNESSES_BOUND / WITNESSES_UNBOUND over handover-v2
const binding = {};
{
  const noteKey = (name, fill) => transparency.noteSignerFromSeed(name, new Uint8Array(32).fill(fill));
  const signerA = noteKey('witness-a.example.org', 0x51), signerB = noteKey('witness-b.example.org', 0x52);
  const vkeyOf = (s) => transparency.verifierKey(s.name, s.publicKey);
  binding.witnesses = [{ url: 'https://witness-a.example.org', verifierKey: vkeyOf(signerA), name: 'witness-a' }, { url: 'https://witness-b.example.org', verifierKey: vkeyOf(signerB) }];
  binding.policy = (quorum, maxUnwitnessedEvents = 100) => ({ quorum, requireOnOpen: true, maxUnwitnessedEvents });
  const [a, b] = binding.witnesses;
  binding.bound = [...handover.events, await signControl(handover.events, { id: 'binding:1', type: 'WITNESSES_BOUND', data: { witnesses: [a, b], policy: binding.policy(2) } })];
  binding.events = save('witness-bound-v2', [...binding.bound, await signControl(binding.bound, { id: 'binding:2', type: 'WITNESSES_UNBOUND', data: { verifierKeys: [b.verifierKey], policy: binding.policy(1) } })]);
}

// ---------------------------------------------------------------- observation-v2: A-71 type 42 (post-E5) — a reconciler matching an admission and a refusal, an
// unmatched event, an equivocation, a second equivocation by another reconciler (A-86, A-89.5), a second stream; observation-cap-v2: the same setup at maxEvents
const observation = {};
const observationPsp = (eventRef, digest, streamId = 'psp') => ({ streamId, eventRef, eventDigest: `0x${digest.repeat(64)}` });
async function observationSetup(name, extra = {}) {
  const h = scripted(name, extra);
  const owner = await createLocalOwner(h.config);
  for (const id of ['spender', 'gateway', 'cal']) await owner.createAgent({ id });
  await owner.createRole({ id: 'payer' });
  await owner.appoint({ agent: 'spender', role: 'payer', tenure: 'shift:1', number: 1 });
  for (const [id, pair] of [['spender', SPENDER], ['gateway', GATEWAY], ['cal', CAL]]) await owner.admitRuntime({ session: `session:${id}`, agent: id, epoch: 1, key: pair.keyId, credential: pair.credential, expiresAt: 10_000_000 });
  await owner.grant({ id: 'pay', to: 'spender', actions: ['pay'], resources: ['vendor'], expiresAt: 10_000_000 });
  h.clock.t = 101;
  const spender = h.session('session:spender', SPENDER);
  if ((await openLocalSimulation(spender).run(op('pay:1', { action: 'pay', resource: 'vendor', role: 'payer', amount: 250n }))).status !== 'SIMULATION_RESULT') throw new Error(`${name}: pay:1`);
  await openLocalRuntime(spender).recordRefusal({ refusalId: 'refusal:1', request: { actorId: 'spender', action: 'pay', resource: 'elsewhere', claimedAt: 101 } });
  h.clock.t = 102;
  return h;
}
{
  const h = await observationSetup('observation');
  const gateway = openLocalRuntime(h.session('session:gateway', GATEWAY)), cal = openLocalRuntime(h.session('session:cal', CAL));
  const mark = (label) => { observation[label] = h.events().length; };
  await gateway.recordObservation({ source: observationPsp('ch_1', '1'), call: { actorId: 'spender', action: 'pay', resource: 'vendor', amount: 250n }, decision: { intentId: 'pay:1' } });
  mark('matchedAdmission');
  await gateway.recordObservation({ source: observationPsp('ch_2', '2'), call: { actorId: 'spender', observedAt: 90 }, decision: { refusalId: 'refusal:1' } });
  mark('matchedRefusal');
  await gateway.recordObservation({ source: observationPsp('ch_3', 'a'), call: { actorId: 'spender' } });
  mark('unmatched');
  await gateway.recordObservation({ source: observationPsp('ch_3', 'b'), call: { actorId: 'spender', resource: 'vendor' } });
  mark('equivocation');
  await cal.recordObservation({ source: observationPsp('ch_3', 'c'), call: { actorId: 'spender' } });
  mark('secondEquivocation');
  await cal.recordObservation({ source: observationPsp('ch_3', 'a', 'psp-eu'), call: { actorId: 'spender' } });
  observation.events = save('observation-v2', h.events(), h.historyFile);
  // The cap: S (events + lifecycle reservations) of the same setup without observations, so the next growth event is refused.
  const probe = accepted((await observationSetup('observation-probe')).events()), c = core.capacityOf(probe.state);
  observation.cap = save('observation-cap-v2', (await observationSetup('observation-cap', { maxEvents: c.eventCount + c.lifecycleReserved + c.dutyReserved })).events());
}

// ================================================================ vectors by topic

// ---------------------------------------------------------------- migration (SPEC §16.2; A-40, A-52, A-62)

section('migration');
{
  for (const [key, name, label] of [['legacy', 'migrated-legacy-v2', 'the legacy (continuity-event/0.2) handover fixture'], ['format1', 'migrated-format1-v2', 'the format-1 conformance/v1 handover-v1 history']]) {
    const m = migrations[key], events = m.events, end = events[0].data.migratedFrom.position;
    replayVector(`replay/v2r/accepts-${name}`, `A format-2 history migrated from ${label} (prefix positions 0…${end} transcribed, fenced source) replays; the final head and root are pinned (G2.5).`, { ref: name, eventCount: events.length }, ACCEPT);
    replayVector(`replay/v2r/${name}-prefix-incomplete`, `The same history cut inside its migrated prefix (position ${end - 1}) is refused once the replay completes (TRANSITION_INVALID): every event present is valid on its own.`, { ref: name, eventCount: end }, reject('TRANSITION_INVALID'));
    const declaration = events.findIndex((e) => e.type === 'TRANSACTION_INTENT_DECLARED');
    replayVector(`replay/v2r/${name}-truncated-prefix`, 'Dropping a transcribed event inside the migrated prefix breaks the source shadow heads the next signed event binds (TRANSITION_INVALID inside the prefix).', [...events.slice(0, declaration), ...events.slice(declaration + 1)], reject('TRANSITION_INVALID'));
  }
  // A-62: a legacy session without expiresAt.
  const ne = migrations.noExpiry.events, sp = ne.findIndex((e) => e.id === 'event:a62:session');
  if ('expiresAt' in ne[sp].data) throw new Error('A-62.1: transcription must preserve the absent expiresAt');
  replayVector('replay/v2r/a62-omitted-expiry-round-trip', 'A-62.1–2: a migrated prefix session WITHOUT expiresAt (the legacy grammar) is transcribed with the field absent and replays; its §7.2 session record normalizes the expiry to null.', { ref: 'migrated-no-expiry-v2', eventCount: ne.length }, ACCEPT);
  const nulled = clone(ne); nulled[sp].data.expiresAt = null;
  replayVector('replay/v2r/a62-explicit-null-expiry-in-prefix', 'A-62.1: an explicit JSON null expiresAt inside a migrated prefix is not source grammar (EVENT_DATA_INVALID at that position).', nulled, reject('EVENT_DATA_INVALID', sp));
  const state = accepted(ne).state, at = ne.at(-1).timestamp + 1;
  const post = await signRefusal(ne, 'event:a62:refusal', { refusalId: 'r:a62', refusalSource: 'CONNECTOR', request: { actorId: 'a:first-look', action: 'pay', resource: 'vendor', claimedAt: at }, evaluationTime: at,
    decision: 'DENY', code: 'CONNECTOR_REFUSED', connector: { connectorId: 'connector:a62', refusalCode: 'UPSTREAM', detailDigest: `0x${'00'.repeat(32)}` } }, { runtimeSessionId: 'session:a62', credentialKeyId: 'key:a62', controlEpoch: 1 }, FIXTURE_KEY);
  replayVector('replay/v2r/a62-null-expiry-session-after-prefix', 'A-52.2 / A-62.3: after the prefix the null-expiry session is expired for every purpose: its CONNECTOR refusal is REFUSAL_AUTHORIZATION_INVALID.', [...ne, post], reject('REFUSAL_AUTHORIZATION_INVALID', ne.length));
  const fresh = plain2(await signer.signControlEvent(migrationOwner, { id: 'event:a62:fresh', type: 'RUNTIME_SESSION_ADMITTED', timestamp: at,
    data: { sessionId: 'session:a62b', agentId: 'connector:a62', controllerId: 'controller:a62', controlEpoch: 1, credentialKeyId: 'key:a62b', credentialScheme: 'eip191-personal-sign-keccak256', credentialAddress: keyPairFromPrivateKey('eip191-personal-sign-keccak256', 'key:a62b', `0x${'33'.repeat(32)}`).credential, expiresAt: at + 1000 } },
    state.genesis.domain, state.head, 'sha256'));
  replayVector('replay/v2r/a62-fresh-session-after-prefix', 'A-62.3: the null-expiry session never blocks a fresh finite-expiry admission for the same agent and epoch after the prefix.', [...ne, fresh], ACCEPT);
}

// ---------------------------------------------------------------- state records: every §7.2 kind, roots pinned where each first appears

section('state-records');
{
  const kindsAt = (count) => [...new Set(core.stateRecordsOf(accepted(rich.events.slice(0, count)).state).map((e) => e.kind))].sort();
  let previous = [];
  for (const [label, count] of Object.entries(rich.marks).sort((x, y) => x[1] - y[1])) {
    const kinds = kindsAt(count), added = kinds.filter((k) => !previous.includes(k));
    replayVector(`replay/v2r/rich-through-${label}`, `The rich history through position ${count - 1} (${label}) replays; its stateRoot pins the record set${added.length ? `, where the kinds ${added.join(', ')} first appear` : ''} (G2.5 re-derives it from RESULTS/records).`, { ref: 'rich-v2', eventCount: count }, ACCEPT);
    previous = kinds;
  }
  const all = kindsAt(rich.events.length);
  rich.kinds = all;
  for (const required of ['agent', 'anchor', 'authority', 'budget', 'budgetUsage', 'counterparty', 'duty', 'effect', 'event', 'genesis', 'intent', 'nonce', 'obligation', 'ownerKeyEpoch', 'principal', 'receipt', 'refusal', 'role', 'session', 'succession', 'tenure', 'usage', 'witnessBinding', 'witnessPolicy']) {
    if (!all.includes(required)) throw new Error(`state-records: no ${required} record in the rich history (kinds: ${all.join(', ')})`);
  }
}

// ---------------------------------------------------------------- lifecycle authorization (types 14–16, A-51): A-60 unknown intents, A-61 dual faults

section('lifecycle-authorization');
{
  const base = lifecycle.events, end = base.length, fenced = lifecycle.fenced, fend = fenced.length;
  const at = (type) => base.findIndex((e) => e.type === type);
  const pc = at('TRANSACTION_INTENT_CONSUMED'), pr = at('RECEIPT_RECORDED');
  const consumption = base[pc], receipt = base[pr];
  const BEA_SESSION = ['session:bea', BEA], CAL_SESSION = ['session:cal', CAL];
  const broken = (a) => ({ ...a, signature: `0x${'5a'.repeat(64)}` });
  replayVector('replay/v2r/lifecycle-history', 'A run (declaration, admission, consumption) and a receipt record, each type 14–16 event carrying its recordAuthorization (A-51), replay.', { ref: 'lifecycle-v2', eventCount: end }, ACCEPT);
  // A-51.4: the authorization stage precedes the type's preconditions.
  replayVector('replay/v2r/a51-consumption-wrong-signer', 'A-51.3: cal\'s session signs a consumption of bea\'s intent (valid signature, wrong signer; also already consumed): RECORD_AUTHORIZATION_INVALID, the binding stage precedes the preconditions.',
    [...base, await signLifecycle(base, { ...consumption, id: 'event:again' }, ...CAL_SESSION)], reject('RECORD_AUTHORIZATION_INVALID', end));
  replayVector('replay/v2r/a51-consumption-right-signer-precondition', 'The same consumption signed by bea\'s own session fails only its precondition (already consumed): TRANSITION_INVALID.',
    [...base, await signLifecycle(base, { ...consumption, id: 'event:again' }, ...BEA_SESSION)], reject('TRANSITION_INVALID', end));
  // A-60: intent resolution after the signature, before the signer binding, for all three types.
  const evidence = { kind: 'EVENT', eventId: base[pc].id, position: pc, eventType: 'TRANSACTION_INTENT_CONSUMED', historyHash: headOf(base.slice(0, pc + 1)).hash };
  const unknown = {
    consumption: { ...consumption, id: 'event:unknown-consumption', data: { ...consumption.data, intentId: 'intent:unknown' } },
    outcome: { id: 'event:unknown-outcome', type: 'TRANSACTION_OUTCOME_RECORDED', timestamp: base.at(-1).timestamp, data: { intentId: 'intent:unknown', status: 'CONFIRMED', attesterId: 'adapter:remote', evidenceReference: evidence } },
    receipt: { ...receipt, id: 'event:unknown-receipt', data: { ...receipt.data, intentId: 'intent:unknown', receiptContentHash: `0x${'cd'.repeat(32)}` } },
  };
  for (const [name, event] of Object.entries(unknown)) {
    replayVector(`replay/v2r/a60-${name}-unknown-intent`, `A-60: a ${event.type} naming an intent that was never declared, validly signed by bea's session: TRANSITION_INVALID (intent resolution follows the signature check).`,
      [...base, await signLifecycle(base, event, ...BEA_SESSION)], reject('TRANSITION_INVALID', end));
    replayVector(`replay/v2r/a60-${name}-unknown-intent-bad-signature`, `A-60: the same ${event.type} with a broken signature: RECORD_AUTHORIZATION_INVALID (the signature is checked before the intent is resolved).`,
      [...base, await signLifecycle(base, event, ...BEA_SESSION, broken)], reject('RECORD_AUTHORIZATION_INVALID', end));
    if (name !== 'receipt') {
      replayVector(`replay/v2r/a60-${name}-unknown-intent-wrong-signer`, `A-60: the same ${event.type} validly signed by cal's session: still TRANSITION_INVALID (a missing intent never selects the binding code).`,
        [...base, await signLifecycle(base, event, ...CAL_SESSION)], reject('TRANSITION_INVALID', end));
    }
  }
  // A-61.3: type 16 inherited runtimeSessionId / controlEpoch vs the nested recordAuthorization → schema.
  const again = (data) => ({ ...receipt, id: 'event:receipt-again', data: { ...receipt.data, receiptContentHash: `0x${'ab'.repeat(32)}`, ...data } });
  replayVector('replay/v2r/a61-receipt-inherited-session-mismatch', 'A-61.3: a RECEIPT_RECORDED whose inherited runtimeSessionId (session:cal) differs from its nested recordAuthorization (session:bea): EVENT_DATA_INVALID.',
    [...base, await signLifecycle(base, again({ runtimeSessionId: 'session:cal' }), ...BEA_SESSION)], reject('EVENT_DATA_INVALID', end));
  replayVector('replay/v2r/a61-receipt-inherited-epoch-mismatch', 'A-61.3: a RECEIPT_RECORDED whose inherited controlEpoch (2) differs from its nested recordAuthorization (1): EVENT_DATA_INVALID.',
    [...base, await signLifecycle(base, again({ controlEpoch: 2 }), ...BEA_SESSION)], reject('EVENT_DATA_INVALID', end));
  replayVector('replay/v2r/a61-receipt-again-accepted', 'The same second receipt record with matching inherited fields, signed by the issuer\'s own session, is accepted.',
    [...base, await signLifecycle(base, again({}), ...BEA_SESSION)], ACCEPT);
  // A-61.1 / A-58.5: the fence once the session is found and its credentialKeyId matches; dual faults.
  replayVector('replay/v2r/lifecycle-fenced-history', 'bea\'s control epoch advanced from 1 to 2 after the receipt: the history replays and session:bea (epoch 1) is fenced from here on.', { ref: 'lifecycle-fenced-v2', eventCount: fend }, ACCEPT);
  replayVector('replay/v2r/a61-fence-and-bad-signature', 'A-61.1: a consumption by the fenced session:bea with a broken signature: SESSION_FENCED (the fence precedes the hash and the signature).',
    [...fenced, await signLifecycle(fenced, { ...consumption, id: 'event:again' }, ...BEA_SESSION, broken)], reject('SESSION_FENCED', fend));
  replayVector('replay/v2r/a61-credential-mismatch-and-fence', 'A-61.1: the fenced session:bea named with credentialKeyId key:cal: the key mismatch fails first with the type\'s code, RECORD_AUTHORIZATION_INVALID, before the fence is reached.',
    [...fenced, await signLifecycle(fenced, { ...consumption, id: 'event:again' }, ...BEA_SESSION, (a) => ({ ...a, credentialKeyId: 'key:cal' }))], reject('RECORD_AUTHORIZATION_INVALID', fend));
  replayVector('replay/v2r/a61-missing-session', 'A-61.1: a consumption naming a session that was never admitted: RECORD_AUTHORIZATION_INVALID.',
    [...fenced, await signLifecycle(fenced, { ...consumption, id: 'event:again' }, ...BEA_SESSION, (a) => ({ ...a, runtimeSessionId: 'session:nobody' }))], reject('RECORD_AUTHORIZATION_INVALID', fend));
  const refusalData = { refusalId: 'r:fenced', refusalSource: 'CORE', request: { actorId: 'bea', action: 'read', resource: 'nowhere', claimedAt: 1 }, evaluationTime: fenced.at(-1).timestamp, decision: 'DENY', code: 'RESOURCE_NOT_ALLOWED' };
  replayVector('replay/v2r/a58-refusal-fence-and-wrong-hash', 'A-58.5: a refusal by the fenced session:bea whose hash is wrong: SESSION_FENCED, not REFUSAL_AUTHORIZATION_INVALID.',
    [...fenced, await signRefusal(fenced, 'event:refusal', refusalData, { runtimeSessionId: 'session:bea', credentialKeyId: 'key:bea', controlEpoch: 1 }, BEA, (a) => ({ ...a, hash: `0x${'22'.repeat(32)}` }))], reject('SESSION_FENCED', fend));
  const envelope = await envelopeFor(fenced, 'op:1', '0', null);
  const wrapperBinding = { runtimeSessionId: 'session:bea', credentialKeyId: 'key:bea', controlEpoch: 1 };
  replayVector('replay/v2r/a61-wrapper-fence-valid-envelope', 'A wrapper with a valid counterparty envelope signed by the fenced session:bea: SESSION_FENCED.',
    [...fenced, await signWrapper(fenced, 'event:cpr', { intentId: 'op:1', envelope }, wrapperBinding, BEA)], reject('SESSION_FENCED', fend));
  const badEnvelope = { ...envelope, signature: await signHashWith(STRANGER)(core.envelopeSigningHash(envelope)) };
  replayVector('replay/v2r/a61-wrapper-fence-and-bad-counterparty-signature', 'A-61.2: the same wrapper whose envelope signature is not acme\'s: COUNTERPARTY_SIGNATURE_INVALID — the §11.2 counterparty checks precede session authorization, so the fence is not reached.',
    [...fenced, await signWrapper(fenced, 'event:cpr', { intentId: 'op:1', envelope: badEnvelope }, wrapperBinding, BEA)], reject('COUNTERPARTY_SIGNATURE_INVALID', fend));
}

// ---------------------------------------------------------------- budgets (SPEC §9; A-50)

section('budgets');
{
  const H = budgetsH.events;
  replayVector('replay/v2r/budgets-history', 'A budget whose amountCap is MAX − 10 with a carry cap of 100, an admission of MAX − 50 in period 1 and its receipt record replay.', { ref: 'budgets-v2', eventCount: H.length }, ACCEPT);
  headroomVector('headroom/v2r/a50-saturated-rollover', 'A-50: unused(k) = min(MAX, cap + carryIn(k)) − used(k). Period 1: carryIn 100, allowed MAX, used MAX − 50, so unused 50 and period 2 carries 50 (the unsaturated recurrence would carry min(100, 140) = 100).',
    'budgets-v2', 'b-sat', 2500, { periodIndex: 2, carryIn: '50', usedAmount: '0' });
  headroomVector('headroom/v2r/a50-period-1', 'A-50: period 1 of the same budget: carryIn min(100, MAX − 10) = 100, remaining min(MAX, MAX − 10 + 100) − (MAX − 50) = 50.',
    'budgets-v2', 'b-sat', 1100, { periodIndex: 1, carryIn: '100', remainingAmount: '50' });
}

// ---------------------------------------------------------------- capacity: the control-event reserve at a test-only lowered cap

section('capacity');
{
  const S = reserve.sizes, p = reserve.base;         // p: the refusal (◇); p+1…p+3: three AGENT_CREATED (◆)
  const afterRefusal = S[p];
  if (S[p] !== reserve.records + 2 || S[p + 1] !== afterRefusal + 2 || S[p + 2] !== afterRefusal + 4 || S[p + 3] !== afterRefusal + 6) throw new Error(`reserve: unexpected record counts ${S.slice(p - 1).join(',')}`);
  const atThreshold = { maxStateRecords: afterRefusal + 4, reservedStateRecords: 4 };    // T_R = R(refusal), HARD = T_R + 4
  const belowThreshold = { maxStateRecords: afterRefusal + 3, reservedStateRecords: 4 }; // T_R = R(refusal) − 1
  const note = (l) => `testCapacityLimits {maxStateRecords ${l.maxStateRecords}, reservedStateRecords ${l.reservedStateRecords}}: T_R = ${l.maxStateRecords - l.reservedStateRecords}, HARD = ${l.maxStateRecords}`;
  replayVector('replay/v2r/reserve-nonconrol-at-threshold', `Founder addendum / A-0.1, ${note(atThreshold)}: a REQUEST_REFUSED (◇) that brings the history exactly to T_R (${afterRefusal} records) is admitted — the reserve is judged after the event, R(p) > T_R.`,
    { ref: 'reserve-v2', eventCount: p + 1 }, ACCEPT, { testCapacityLimits: atThreshold });
  replayVector('replay/v2r/reserve-nonconrol-above-threshold', `${note(belowThreshold)}: the same REQUEST_REFUSED (◇) ends one record above T_R: CAPACITY_RESERVED.`,
    { ref: 'reserve-v2', eventCount: p + 1 }, reject('CAPACITY_RESERVED', p), { testCapacityLimits: belowThreshold });
  replayVector('replay/v2r/reserve-control-admitted-to-cap', `${note(atThreshold)}: two AGENT_CREATED (◆) after T_R use the reserve and reach the cap exactly (${afterRefusal + 4} records): admitted.`,
    { ref: 'reserve-v2', eventCount: p + 3 }, ACCEPT, { testCapacityLimits: atThreshold });
  replayVector('replay/v2r/reserve-control-at-cap', `${note(atThreshold)}: a third AGENT_CREATED (◆) would end above the cap: CAPACITY_EXCEEDED, control events included.`,
    { ref: 'reserve-v2', eventCount: p + 4 }, reject('CAPACITY_EXCEEDED', p + 3), { testCapacityLimits: atThreshold });
  replayVector('replay/v2r/reserve-history-default-limits', 'The same history under the SPEC limits (no override) replays.', { ref: 'reserve-v2', eventCount: reserve.events.length }, ACCEPT);
}

// ---------------------------------------------------------------- export views (SPEC §15; A-53, A-65), the A-70.1 glossary fixture

section('export');
const glossary = {};
{
  const H = rich.events, last = H.length - 1;
  const cp = H.findIndex((e) => e.type === 'STATE_CHECKPOINT');
  const effect2 = H.findIndex((e) => e.type === 'EFFECT_RECORDED' && e.data.effectId === 'effect:2');
  // A-70.1: genesisEventHash = eventHash(e₀) (an event hash); historyId = genesisHash = recordHash(0) (the record-chain hash).
  const genesisOnly = accepted(H.slice(0, 1));
  glossary.genesisEventHash = core.eventHash(engineEvents(H.slice(0, 1))[0], 'sha256');
  glossary.historyId = genesisOnly.head.hash;
  if (glossary.genesisEventHash === glossary.historyId) throw new Error('A-70.1: the two genesis hashes must differ');
  exportVector('export/v2r/a70-glossary-genesis-hashes', 'A-70.1 glossary fixture: the export view of the genesis alone states genesisEventHash = eventHash(e₀) and historyId = recordHash(0) (= the head hash at position 0, the genesisHash of the envelope); they differ and are never substituted for each other.',
    'rich-v2', 0, 0, { fromRecords: false, toRecords: false, inclusion: [] }, { genesisEventHash: glossary.genesisEventHash, historyId: glossary.historyId });
  exportVector('export/v2r/rich-checkpoint-to-head', 'The export view from the manual checkpoint to the head with every evidence selector except attestations: the dependency closure (A-53, A-65.3) in referencedEvents, the owner key rotation in keyEvents.',
    'rich-v2', cp, last, { fromRecords: true, toRecords: true, inclusion: [], referencedEvents: true, keyEvents: true });
  // A-65 round trips: the full view as exported, JSON round-tripped, verified; then edited copies.
  const viewOf = (from, to, include) => plain2(core.exportView(engineEvents(H), { fromPosition: from, toPosition: to, include }));
  const full = viewOf(effect2 - 1, effect2 + 2, { fromRecords: true, toRecords: true, referencedEvents: true, keyEvents: true });
  exportVerifyVector('export-verify/v2r/a65-round-trip-with-from-records', 'A-65: a view over the COUNTERPARTY effect (from = its position − 1) with fromRecords, toRecords, referencedEvents and keyEvents, JSON round-tripped: the verifier rebuilds from the records, applies the range and checks both roots (ok).',
    full, { ok: true, code: null });
  const missing = clone(full); missing.referencedEvents = missing.referencedEvents.filter((e) => H[e.position].type !== 'COUNTERPARTY_RECEIPT_RECORDED');
  exportVerifyVector('export-verify/v2r/a65-missing-envelope-body', 'A-53.2 / A-65.3: the same view without the type-40 body the COUNTERPARTY effect cites (A-36.1): EXPORT_DEPENDENCIES_MISSING with that position; the transition is not claimed valid.',
    missing, { ok: false, code: 'EXPORT_DEPENDENCIES_MISSING' });
  const unsorted = clone(full); unsorted.referencedEvents = [...unsorted.referencedEvents].reverse();
  if (unsorted.referencedEvents.length < 2) throw new Error('export: need two referenced events to unsort');
  exportVerifyVector('export-verify/v2r/a65-unsorted-evidence', 'A-65.1: referencedEvents not sorted ascending by position: INVALID_INPUT.', unsorted, { ok: false, code: 'INVALID_INPUT' });
  const nulled = clone(full); nulled.keyEvents = null;
  exportVerifyVector('export-verify/v2r/a65-null-evidence-field', 'A-65.1: an evidence field present as explicit null: INVALID_INPUT.', nulled, { ok: false, code: 'INVALID_INPUT' });
  const extra = clone(full); extra.comment = 'not part of a view';
  exportVerifyVector('export-verify/v2r/a65-unknown-key', 'A-65.1: an unknown top-level key: INVALID_INPUT.', extra, { ok: false, code: 'INVALID_INPUT' });
  exportVerifyVector('export-verify/v2r/a65-from-zero-without-records', 'A-65.4: from = 0 without fromRecords: the verifier applies the genesis from events[0] once, then 1…to (ok).',
    viewOf(0, 6, {}), { ok: true, code: null });
  exportVerifyVector('export-verify/v2r/a65-from-zero-with-records', 'A-65.4: from = 0 with fromRecords: the verifier starts from the rebuilt post-genesis state and reaches the same root (ok).',
    viewOf(0, 6, { fromRecords: true }), { ok: true, code: null });
  const migrated = migrations.format1.events, mEnd = migrated[0].data.migratedFrom.position;
  const prefixView = plain2(core.exportView(engineEvents(migrated), { fromPosition: mEnd - 2, toPosition: migrated.length - 1, include: { fromRecords: true, referencedEvents: true } }));
  exportVerifyVector('export-verify/v2r/a65-inside-migrated-prefix', 'A-65.3: a view whose from + 1 lies inside a migrated prefix carries every prefix body 1…from (the shadow head is a sequential chain): ok.', prefixView, { ok: true, code: null });
}

// ---------------------------------------------------------------- FORMAT_READ_ONLY (SPEC §16.1, A-41)

section('read-only');
{
  // Small histories written by the earlier writers (the format named explicitly: test/compatibility path, A-30), then migrated.
  const earlier = async (name, format) => {
    const h = scripted(name, { format, nextKey: false, domain: core.createLocalDomain({ format, ids: () => 'read-only' }), [internalFormat1.FORMAT1_TEST_TOOLING]: true });
    if (format === core.LEGACY_FORMAT) { delete h.config.signer; }
    const owner = await createLocalOwner(h.config);
    await owner.createAgent({ id: 'bea' });
    // The pin's pinnedAt is the store's wall clock (unsigned bookkeeping): fixed to the pinned head's time so the vector is deterministic.
    const pinOf = (path) => { const pin = JSON.parse(readFileSync(path, 'utf8')); return `${JSON.stringify({ ...pin, pinnedAt: pin.canonicalTime })}\n`; };
    const files = (path) => ({ lines: readFileSync(path, 'utf8'), ...(existsSync(`${path}.head`) ? { pin: pinOf(`${path}.head`) } : {}) });
    const source = files(h.historyFile), target = join(WORK, `${name}-2.jsonl`);
    await migrateHistory({ source: h.historyFile, target, now: () => 5000, signer: migrationOwner, nextKey: false, migrationId: MIGRATION_ID });
    return { source, fenced: { ...source, marker: readFileSync(strictStore.migratedMarkerPathFor(h.historyFile), 'utf8') }, target: files(target) };
  };
  const legacy = await earlier('read-only-legacy', core.LEGACY_FORMAT), format1 = await earlier('read-only-format1', core.TRELLIS_FORMAT);
  await writerOpenVector('writer-open/v2r/legacy-history-is-read-only', 'An owner write to a legacy (continuity-event/0.2) history: FORMAT_READ_ONLY {reason: LEGACY} — migrate it to format 2.', legacy.source, { code: 'FORMAT_READ_ONLY', reason: 'LEGACY' });
  await writerOpenVector('writer-open/v2r/format1-history-is-read-only', 'An owner write to a format-1 history (with its pin): FORMAT_READ_ONLY {reason: FORMAT_1}.', format1.source, { code: 'FORMAT_READ_ONLY', reason: 'FORMAT_1' });
  await writerOpenVector('writer-open/v2r/fenced-legacy-source-is-read-only', 'An owner write to a migrated (fenced) legacy source next to its .migrated marker: FORMAT_READ_ONLY {reason: MIGRATED}.', legacy.fenced, { code: 'FORMAT_READ_ONLY', reason: 'MIGRATED' });
  await writerOpenVector('writer-open/v2r/fenced-format1-source-is-read-only', 'An owner write to a migrated (fenced) format-1 source next to its .migrated marker: FORMAT_READ_ONLY {reason: MIGRATED}.', format1.fenced, { code: 'FORMAT_READ_ONLY', reason: 'MIGRATED' });
  await writerOpenVector('writer-open/v2r/format2-target-is-writable', 'The format-2 target of the format-1 migration (with its pin) accepts an owner write signed by its owner key.', { ...format1.target, ownerKey: { keyId: 'owner:1', scheme: 'ed25519', seed: MIGRATION_OWNER_SEED } }, { written: true });
}

// ---------------------------------------------------------------- budgets: the budget set bound, the 257th budget, a roleIds budget across a handover

section('budgets');
{
  const req = (resource) => ({ actorId: 'spender', action: 'spend', resource, claimedAt: 100, amount: '1' });
  authorizationVector('authorization/v2r/budget-set-sixteen-matching', 'Sixteen budgets match the request (b-000…b-015): every one is checked and the request is allowed (SPEC §9.4).', 'budget-set-v2', req('wide'), { eventCount: budgetSet.sixteen, expectDecision: 'ALLOW' });
  authorizationVector('authorization/v2r/budget-set-too-large', 'Seventeen budgets match the request: DENY BUDGET_SET_TOO_LARGE naming the 17th in byte order of budgetId (b-016), before any budget is evaluated.', 'budget-set-v2', req('wide'), { expectCode: 'BUDGET_SET_TOO_LARGE', expectBudgetId: budgetSet.id(16) });
  authorizationVector('authorization/v2r/budget-set-other-resource', 'A request on a resource one budget covers is unaffected by the 256 others.', 'budget-set-v2', req('narrow'), { expectDecision: 'ALLOW', expectBudgetId: null });
  const H = budgetSet.events;
  replayVector('replay/v2r/budget-256-accepted', 'A history may declare 256 budgets (SPEC §9.1).', { ref: 'budget-set-v2', eventCount: H.length }, ACCEPT);
  const b257 = await signControl(H, { id: 'budget:257', type: 'BUDGET_DECLARED', data: { budgetId: 'b-256', subjects: { actorIds: null, roleIds: null, actions: ['spend'], resources: ['r-256'] }, metric: 'amount', period: { kind: 'NONE' }, amountCap: '1000', countCap: null, perOperationCap: null, notBefore: null, expiresAt: null } });
  replayVector('replay/v2r/budget-257th-refused', 'A correctly owner-signed 257th BUDGET_DECLARED is TRANSITION_INVALID: at most 256 budgets per history, closed ones included (SPEC §9.1).', [...H, b257], reject('TRANSITION_INVALID', H.length));

  const HB = handoverBudget.events;
  replayVector('replay/v2r/handover-budget-history', 'A roleIds budget (countCap 2) charged by bea, then the handover to alex, then alex\'s operation charged to the same budget, replays.', { ref: 'handover-budget-v2', eventCount: HB.length }, ACCEPT);
  headroomVector('headroom/v2r/role-budget-before-handover', 'Before the handover the role budget has one use (bea\'s).', 'handover-budget-v2', 'b-role', 200, { usedCount: 1, remainingCount: 1 }, handoverBudget.afterHandover - 1);
  headroomVector('headroom/v2r/role-budget-usage-retained', 'After the handover and alex\'s operation the same budget shows both uses: usage is retained and the budget follows the role (T6 budget survives handover).', 'handover-budget-v2', 'b-role', 200, { usedCount: 2, remainingCount: 0 });
  authorizationVector('authorization/v2r/role-budget-follows-successor', 'A third operation by the successor alex (holding the reviewer role now): DENY BUDGET_COUNT_EXCEEDED on b-role — the budget matched by role, not by agent.', 'handover-budget-v2',
    { actorId: 'alex', action: 'spend', resource: 'petty-cash', claimedAt: 200, amount: '5' }, { expectCode: 'BUDGET_COUNT_EXCEEDED', expectBudgetId: 'b-role' });
}

// ---------------------------------------------------------------- effects: at most 64 per intent

section('effects');
{
  const H = effects.events, r = accepted(H);
  replayVector('replay/v2r/effects-sixty-four', 'Sixty-four EFFECT_RECORDED for one admitted intent replay (SPEC §10.2).', { ref: 'effects-v2', eventCount: H.length }, ACCEPT);
  const d = { effectId: 'effect:65', intentId: 'pay:1', measurer: { kind: 'SESSION', id: 'bea' }, metric: 'amount', unit: 'cent', amount: '10', observedAt: 100, detailDigest: null, runtimeSessionId: 'session:bea', credentialKeyId: 'key:bea', controlEpoch: 1 };
  const envelope = { id: 'event:effect-65', type: 'EFFECT_RECORDED', timestamp: r.head.canonicalTime };
  const hash = core.hashCanonical(core.effectChallenge(r.state.genesis.domain, d, r.head, envelope), 'sha256');
  replayVector('replay/v2r/effects-sixty-fifth', 'A validly signed 65th EFFECT_RECORDED for the same intent: EFFECT_LIMIT.', [...H, { ...envelope, data: { ...d, effectAuthorization: { hash, signature: await signHashWith(BEA)(hash) } } }], reject('EFFECT_LIMIT', H.length));
}

// ---------------------------------------------------------------- counterparties: re-registration keeps the receipt chain

section('counterparties');
{
  const H = counterparty.events, last = H.length - 1;
  replayVector('replay/v2r/counterparty-chain-across-reregistration', 'acme\'s first receipt (key acme:1), retirement, re-registration with key acme:2, and a second receipt that cites the first envelope\'s digest: the chain is kept across the re-registration (SPEC §11.1).', { ref: 'counterparty-v2', eventCount: H.length }, ACCEPT);
  const prefix = H.slice(0, last), binding = { runtimeSessionId: 'session:bea', credentialKeyId: 'key:bea', controlEpoch: 1 };
  replayVector('replay/v2r/counterparty-chain-restarted', 'The second receipt with previousReceiptDigest null (a restarted chain): TRANSITION_INVALID.',
    [...prefix, await signWrapper(prefix, H[last].id, { intentId: 'pay:2', envelope: await envelopeFor(prefix, 'pay:2', '10', null, ACME2) }, binding, BEA)], reject('TRANSITION_INVALID', last));
  replayVector('replay/v2r/counterparty-retired-key-id', 'The second receipt naming the key acme:1, which the re-registration did not keep: TRANSITION_INVALID (the ACTIVE/keyId check precedes the signature, A-61.2).',
    [...prefix, await signWrapper(prefix, H[last].id, { intentId: 'pay:2', envelope: await envelopeFor(prefix, 'pay:2', '10', counterparty.firstDigest, ACME) }, binding, BEA)], reject('TRANSITION_INVALID', last));
  const current = await envelopeFor(prefix, 'pay:2', '10', counterparty.firstDigest, ACME2);
  const oldKeySigned = { ...current, signature: await signHashWith(ACME)(core.envelopeSigningHash(current)) };
  replayVector('replay/v2r/counterparty-signed-by-retired-key', 'The second receipt naming acme:2 but signed by the retired acme:1 key: COUNTERPARTY_SIGNATURE_INVALID.',
    [...prefix, await signWrapper(prefix, H[last].id, { intentId: 'pay:2', envelope: oldKeySigned }, binding, BEA)], reject('COUNTERPARTY_SIGNATURE_INVALID', last));
  const whileRetired = H.slice(0, counterparty.retired);
  replayVector('replay/v2r/counterparty-receipt-while-retired', 'A receipt while acme is RETIRED: TRANSITION_INVALID.',
    [...whileRetired, await signWrapper(whileRetired, 'event:cpr-retired', { intentId: 'pay:2', envelope: await envelopeFor(whileRetired, 'pay:2', '10', counterparty.firstDigest, ACME) }, binding, BEA)], reject('TRANSITION_INVALID', whileRetired.length));
}

// ---------------------------------------------------------------- capacity: the declared maxStateRecords

section('capacity');
{
  const H = capacityH.events, at = capacityH.atCap;
  replayVector('replay/v2r/max-state-records-history', `capacity.maxStateRecords ${capacityH.base + 2}: one refusal fits exactly; after it the owner still creates an agent (control events are never refused by a declared limit, A-1).`, { ref: 'capacity-v2', eventCount: H.length }, ACCEPT);
  const prefix = H.slice(0, at);
  const over = await signRefusal(prefix, 'event:refusal-over', { refusalId: 'refusal:2', refusalSource: 'CORE', request: { actorId: 'bea', action: 'delete', resource: 'incident:42', claimedAt: 100 }, evaluationTime: 100, decision: 'DENY', code: 'ACTION_NOT_ALLOWED' }, { runtimeSessionId: 'session:bea', credentialKeyId: 'key:bea', controlEpoch: 1 }, BEA);
  replayVector('replay/v2r/max-state-records-exceeded', 'A second validly signed refusal at the declared cap: CAPACITY_EXCEEDED (non-control events only).', [...prefix, over], reject('CAPACITY_EXCEEDED', at));
}

// ---------------------------------------------------------------- checkpoints: everyEvents

section('checkpoints');
{
  const H = checkpoints.events;
  replayVector('replay/v2r/checkpoint-policy-every-events', `A history whose genesis declares checkpointPolicy {everyEvents: 4}: the writer appended STATE_CHECKPOINTs at positions ${checkpoints.positions.join(', ')} and the history replays.`, { ref: 'checkpoints-v2', eventCount: H.length }, ACCEPT);
  for (const p of checkpoints.positions) replayVector(`replay/v2r/checkpoint-policy-prefix-${p}`, `The prefix ending with the automatic checkpoint at ${p}: its stateRoot pins rootAt(${p}); the checkpoint carries rootAt(${p - 1}).`, { ref: 'checkpoints-v2', eventCount: p + 1 }, ACCEPT);
  const p = checkpoints.positions[0], prefix = H.slice(0, p);
  const { controlAuthorization: _a, ...data } = H[p].data;
  replayVector('replay/v2r/checkpoint-policy-wrong-root', 'The first automatic checkpoint re-signed with a wrong stateRoot: STATE_ROOT_MISMATCH.', [...prefix, await signControl(prefix, { id: H[p].id, type: 'STATE_CHECKPOINT', data: { ...data, stateRoot: `0x${'11'.repeat(32)}` } })], reject('STATE_ROOT_MISMATCH', p));
}

// ---------------------------------------------------------------- duty policy (SPEC §13)

section('duty-policy');
{
  const H = duty.events, m = duty.marks;
  const views = [['duty-created', 'before the activation the duty has no policy view (null)', null], ['activated', 'after the activation: OPEN, outstanding', 'OPEN'],
    ['completed', 'after the dual-signature COMPLETED_UNDER_POLICY disposition', 'COMPLETED_UNDER_POLICY'], ['needs-review', 'a later same-duty review stales the completion', 'NEEDS_REVIEW'], ['contested', 'an accepted contest', 'CONTESTED']];
  for (const [label, purpose, state] of views) {
    replayVector(`replay/v2r/duty-through-${label}`, `The duty-policy history through position ${m[label] - 1} (${label}) replays; its stateRoot pins the duty record.`, { ref: 'duty-policy-v2', eventCount: m[label] }, ACCEPT);
    dutyViewVector(`duty-view/v2r/${label}`, `SPEC §13.3 view of duty "duty" ${purpose}.`, 'duty-policy-v2', 'duty', state === null ? {} : { dutyDisposition: state }, m[label]);
  }
  const pa = H.findIndex((e) => e.type === 'ATTEMPT_DUTY_POLICY_ACTIVATED'), pd = H.findIndex((e) => e.type === 'ATTEMPT_DUTY_DISPOSITION_RECORDED');
  const mut = (p, fn) => { const c = clone(H.slice(0, p + 1)); fn(c[p]); return c; };
  replayVector('replay/v2r/duty-disposition-unknown-key', 'A disposition event with a field the closed schema does not declare: EVENT_DATA_INVALID.', mut(pd, (e) => { e.data.extra = 1; }), reject('EVENT_DATA_INVALID', pd));
  replayVector('replay/v2r/duty-disposition-rules-hash', 'A disposition whose rulesHash is not the pinned keccak-256 literal of the rules (A-15): EVENT_DATA_INVALID.', mut(pd, (e) => { e.data.rulesHash = `0x${'00'.repeat(32)}`; }), reject('EVENT_DATA_INVALID', pd));
  replayVector('replay/v2r/duty-disposition-unknown-disposition', 'A finding whose disposition is neither COMPLETED_UNDER_POLICY nor ESCALATED: EVENT_DATA_INVALID.', mut(pd, (e) => { e.data.finding.challenge.operation.disposition = 'DONE'; }), reject('EVENT_DATA_INVALID', pd));
  replayVector('replay/v2r/duty-disposition-reason-too-long', 'A checklist reason longer than 256 bytes: EVENT_DATA_INVALID.', mut(pd, (e) => { e.data.finding.challenge.operation.checklist.SOURCE_REVIEWED.reason = 'x'.repeat(300); }), reject('EVENT_DATA_INVALID', pd));
  replayVector('replay/v2r/duty-finding-altered', 'The signed finding changed to ESCALATED without a nextStep after signing: the finding no longer validates against the state before it (TRANSITION_INVALID).', mut(pd, (e) => { e.data.finding.challenge.operation.disposition = 'ESCALATED'; }), reject('TRANSITION_INVALID', pd));
  replayVector('replay/v2r/duty-second-activation', 'A copy of the activation appended at the end: a duty is activated once (TRANSITION_INVALID).', [...H, { ...H[pa], id: 'activate-again', timestamp: H.at(-1).timestamp }], reject('TRANSITION_INVALID', H.length));
  replayVector('replay/v2r/duty-disposition-replayed', 'The disposition appended again under a new id after the contest: its finding was signed over another head (TRANSITION_INVALID).', [...H, { ...H[pd], id: 'duty-disposition:again', timestamp: H.at(-1).timestamp }], reject('TRANSITION_INVALID', H.length));
}

// ---------------------------------------------------------------- capacity: maxEvents counts the duty quota

section('capacity');
{
  const H = dutyCapped.events;
  replayVector('replay/v2r/duty-quota-history', `capacity.maxEvents ${dutyCapped.maxEvents} = the events after the activation + the lifecycle reservations + the duty quota (6): the grants (control) and a disposition (within the quota) are admitted.`, { ref: 'duty-capacity-v2', eventCount: H.length }, ACCEPT);
  const growth = await signRefusal(H, 'event:refusal-growth', { refusalId: 'refusal:growth', refusalSource: 'CORE', request: { actorId: 'worker', action: 'export', resource: 'incident', claimedAt: 100 }, evaluationTime: H.at(-1).timestamp, decision: 'DENY', code: 'ACTION_NOT_ALLOWED' },
    { runtimeSessionId: 'session', credentialKeyId: 'key', controlEpoch: 1 }, FIXTURE_KEY);
  replayVector('replay/v2r/duty-quota-growth-refused', 'A validly signed refusal (growth, A-2) when the committed space (events + lifecycle reservations + the remaining duty quota) fills maxEvents: CAPACITY_CONTROL_ONLY.', [...H, growth], reject('CAPACITY_CONTROL_ONLY', H.length));
}

// ---------------------------------------------------------------- EIP-191 sessions (SPEC §8.1)

section('eip191-sessions');
{
  const H = duty.events, pd = H.findIndex((e) => e.type === 'TRANSACTION_INTENT_DECLARED'), pa = H.findIndex((e) => e.type === 'TRANSACTION_INTENT_ADMITTED');
  replayVector('replay/v2r/eip191-declaration-and-admission', 'A deployment whose genesis declares signatureScheme eip191-personal-sign-keccak256: the session\'s declaration (§8.6, g3 challenge) and admission (§8.2) are EIP-191 signatures over the challenge hash, recovered to the session\'s credentialAddress.', { ref: 'duty-policy-v2', eventCount: pa + 1 }, ACCEPT);
  const tampered = clone(H.slice(0, pd + 1)); tampered[pd].data.declarationAuthorization.signature = signFlip(tampered[pd].data.declarationAuthorization.signature);
  replayVector('replay/v2r/eip191-declaration-bad-signature', 'The declaration\'s EIP-191 signature with one byte changed recovers another address: DECLARATION_AUTHORIZATION_INVALID.', tampered, reject('DECLARATION_AUTHORIZATION_INVALID', pd));
  const other = clone(H.slice(0, pd + 1)); other[pd].id = `${other[pd].id}:moved`;
  replayVector('replay/v2r/eip191-declaration-moved-id', 'A-54 (g3): the declaration\'s event id is bound by the challenge — changing it breaks the EIP-191 signature (DECLARATION_AUTHORIZATION_INVALID).', other, reject('DECLARATION_AUTHORIZATION_INVALID', pd));
}

// ---------------------------------------------------------------- the conformance/v1 topics in format 2: genesis and control signatures

section('genesis-and-control-signatures');
{
  const events = handover.events;
  replayVector('replay/v2r/accepts-signed-handover', 'A format-2 handover history with owner-signed control events (§6.1 /2 challenge over the record-chain head), a simulated admission, a receipt, an obligation and a succession replays.', { ref: 'handover-v2', eventCount: events.length }, ACCEPT);
  replayVector('replay/v2r/accepts-prefix-before-handover', 'Every prefix of a valid history is valid: the history as it stood before the succession.', { ref: 'handover-v2', eventCount: handover.before }, ACCEPT);
  const controlIndex = events.findIndex((e) => e.type === 'AUTHORITY_GRANTED');
  const unsigned = events.map((e, i) => (i === controlIndex ? { ...e, data: Object.fromEntries(Object.entries(e.data).filter(([k]) => k !== 'controlAuthorization')) } : e));
  replayVector('replay/v2r/rejects-unsigned-control-event', 'A control event without its owner signature is refused (CONTROL_AUTHORIZATION_INVALID).', unsigned, reject('CONTROL_AUTHORIZATION_INVALID', controlIndex));
  const tampered = events.map((e, i) => (i === controlIndex ? { ...e, data: { ...e.data, controlAuthorization: { ...e.data.controlAuthorization, signature: signFlip(e.data.controlAuthorization.signature) } } } : e));
  replayVector('replay/v2r/rejects-tampered-control-signature', 'A control event whose signature bytes were altered is refused (CONTROL_AUTHORIZATION_INVALID).', tampered, reject('CONTROL_AUTHORIZATION_INVALID', controlIndex));
  const grants = events.map((e, i) => [e, i]).filter(([e]) => e.type === 'AUTHORITY_GRANTED').map(([, i]) => i);
  const moved = events.slice(); [moved[grants[1]], moved[grants[2]]] = [events[grants[2]], events[grants[1]]];
  replayVector('replay/v2r/rejects-moved-control-event', 'Two independently valid, signed grants swapped in position are refused: each signature binds the head before its event (CONTROL_AUTHORIZATION_INVALID).', moved, reject('CONTROL_AUTHORIZATION_INVALID', grants[1]));
  const forged = events.map((e, i) => (i === controlIndex ? { ...e, data: { ...e.data, grant: { ...e.data.grant, constraints: { ...e.data.grant.constraints, expiresAt: 999999 } } } } : e));
  replayVector('replay/v2r/rejects-altered-control-effect', 'Editing a signed grant\'s expiry invalidates the owner signature over its effect hash (CONTROL_AUTHORIZATION_INVALID).', forged, reject('CONTROL_AUTHORIZATION_INVALID', controlIndex));
  const unknownKey = events.map((e, i) => (i === controlIndex ? { ...e, data: { ...e.data, controlAuthorization: { ...e.data.controlAuthorization, keyId: 'owner:unknown' } } } : e));
  replayVector('replay/v2r/rejects-undeclared-owner-key', 'A control event claiming a key id the genesis does not declare is refused (CONTROL_AUTHORIZATION_INVALID).', unknownKey, reject('CONTROL_AUTHORIZATION_INVALID', controlIndex));
}

// ---------------------------------------------------------------- owner keys

section('owner-keys');
{
  const digestOf = (pair) => core.ownerKeyDigest(pair);
  const rotateOn = async (list, id, data, by, reveal = []) => {
    const r = accepted(list), head = r.head, domain = r.state.genesis.domain;
    const signed = plain2(await signer.signControlEvent(by, { id, type: 'OWNER_KEYS_ROTATED', timestamp: list.at(-1).timestamp, data }, domain, head, 'sha256'));
    if (reveal.length === 0) return [...list, signed];
    const challenge = core.controlAuthorizationHash({ domain, eventId: signed.id, eventType: signed.type, timestamp: signed.timestamp, previousHead: { hash: head.hash, position: head.position }, effectHash: core.controlEffectHash(signed, 'sha256') }, 'sha256');
    const proofs = await Promise.all(reveal.map(async ([keyId, s]) => ({ keyId, scheme: 'ed25519', signature: await s.signHash(challenge) })));
    return [...list, { ...signed, data: { ...signed.data, nextKeyAuthorizations: proofs } }];
  };
  const prefix = preRotation.events.slice(0, preRotation.before);
  replayVector('replay/v2r/accepts-genesis-commitment', 'The format-2 genesis commits the owner keys to the digest of their next key (nextKeyDigests).', { ref: 'pre-rotation-v2', eventCount: preRotation.before }, ACCEPT);
  const genesis = preRotation.events[0];
  replayVector('replay/v2r/rejects-genesis-commitment-naming-an-owner-key', 'A genesis whose next-key commitment names one of its own owner keys is refused (EVENT_DATA_INVALID).', [{ ...genesis, data: { ...genesis.data, nextKeyDigests: [digestOf(NEXT), digestOf(OWNER)] } }], reject('EVENT_DATA_INVALID', 0));
  replayVector('replay/v2r/rejects-genesis-commitment-empty', 'A genesis whose next-key commitment is empty is refused (EVENT_DATA_INVALID).', [{ ...genesis, data: { ...genesis.data, nextKeyDigests: [] } }], reject('EVENT_DATA_INVALID', 0));
  const events = rotation.events, r = rotation.position, beforeRotation = events.slice(0, r);
  const rotatedSigner = signer.signerFromKeyPair(ROTATED), strangerSigner = signer.signerFromKeyPair(STRANGER);
  replayVector('replay/v2r/accepts-owner-key-rotation', 'On a history created without a next-key commitment, OWNER_KEYS_ROTATED signed by the current owner key replaces the owner key set; later control events are signed by the new key.', { ref: 'rotation-v2', eventCount: events.length }, ACCEPT);
  replayVector('replay/v2r/rejects-control-event-signed-by-retired-key', 'After a rotation the retired owner key can no longer sign a control event (CONTROL_AUTHORIZATION_INVALID).',
    [...events.slice(0, r + 1), await signControl(events.slice(0, r + 1), { id: 'rotation:late', type: 'AGENT_CREATED', data: { agentId: 'late', principalId: 'operations', controllerId: 'operator', initialControlEpoch: 1 } })], reject('CONTROL_AUTHORIZATION_INVALID', r + 1));
  replayVector('replay/v2r/rejects-rotation-signed-by-unknown-key', 'A rotation signed by a key the history never declared is refused (CONTROL_AUTHORIZATION_INVALID).', await rotateOn(beforeRotation, 'rotation:stranger', { ownerKeys: [ok(STRANGER)] }, strangerSigner), reject('CONTROL_AUTHORIZATION_INVALID', r));
  replayVector('replay/v2r/rejects-retired-key-id-reuse', 'A rotation that brings a retired key id back is refused (TRANSITION_INVALID).', await rotateOn(events, 'rotation:back', { ownerKeys: [ok(OWNER)] }, rotatedSigner), reject('TRANSITION_INVALID', events.length));
  replayVector('replay/v2r/rejects-rotation-rebinding-a-key-id', 'A rotation that keeps a key id but binds it to a different public key is refused (TRANSITION_INVALID).', await rotateOn(beforeRotation, 'rotation:rebound', { ownerKeys: [{ ...ok(ROTATED), keyId: 'owner:1' }] }, ownerSigner), reject('TRANSITION_INVALID', r));
  replayVector('replay/v2r/accepts-commitment-only-rotation', 'An uncommitted epoch gets a commitment by a rotation that keeps every owner key and carries nextKeyDigests.', await rotateOn(beforeRotation, 'commit:later', { ownerKeys: [ok(OWNER)], reason: 'next-key commitment', nextKeyDigests: [digestOf(NEXT)] }, ownerSigner), ACCEPT);
  replayVector('replay/v2r/rejects-carry-over-rotation-without-commitment', 'A rotation that keeps every owner key and carries no nextKeyDigests changes nothing (TRANSITION_INVALID).', await rotateOn(beforeRotation, 'rotation:noop', { ownerKeys: [ok(OWNER)], reason: 'nothing' }, ownerSigner), reject('TRANSITION_INVALID', r));
  replayVector('replay/v2r/accepts-pre-rotated-rotation', 'A rotation out of a committed epoch that reveals the committed key with its proof (nextKeyAuthorizations) and commits the new set to its own next key is accepted.', { ref: 'pre-rotation-v2', eventCount: preRotation.events.length }, ACCEPT);
  replayVector('replay/v2r/rejects-rotation-to-uncommitted-key', 'A rotation out of a committed epoch to a key the commitment does not name is refused (TRANSITION_INVALID).',
    await rotateOn(prefix, 'rotation:uncommitted', { ownerKeys: [ok(STRANGER)], nextKeyDigests: [digestOf(NEXT_NEXT)] }, ownerSigner, [['stranger:1', strangerSigner]]), reject('TRANSITION_INVALID', prefix.length));
  replayVector('replay/v2r/rejects-revealed-key-without-proof', 'Revealing the committed key without its signature (no nextKeyAuthorizations) is refused (TRANSITION_INVALID).', await rotateOn(prefix, 'rotation:no-proof', { ownerKeys: [ok(NEXT)], nextKeyDigests: [digestOf(NEXT_NEXT)] }, ownerSigner), reject('TRANSITION_INVALID', prefix.length));
  replayVector('replay/v2r/rejects-pre-rotated-rotation-without-next-commitment', 'A pre-rotated rotation without nextKeyDigests is refused (TRANSITION_INVALID): the commitment chain must continue.', await rotateOn(prefix, 'rotation:no-next', { ownerKeys: [ok(NEXT)] }, ownerSigner, [['owner:2', nextSigner]]), reject('TRANSITION_INVALID', prefix.length));
}

// ---------------------------------------------------------------- anchors and witness bindings

section('anchors-and-witness-bindings');
{
  const base = handover.events;
  replayVector('replay/v2r/accepts-anchor', 'An ANCHOR_RECORDED event whose anchored head is a prefix of this history is accepted; the anchor state record is pinned.', { ref: 'handover-anchored-v2', eventCount: handover.anchored.length }, ACCEPT);
  const { controlAuthorization: _a, ...anchorData } = handover.anchor.data;
  replayVector('replay/v2r/rejects-bad-anchor', 'A correctly signed anchor whose anchored head hash is not a prefix hash of this history is refused (TRANSITION_INVALID).',
    [...base, await signControl(base, { id: handover.anchor.id, type: 'ANCHOR_RECORDED', data: { ...anchorData, anchoredHead: { ...anchorData.anchoredHead, hash: `0x${'cd'.repeat(32)}` } } })], reject('TRANSITION_INVALID', base.length));
  const { witnesses, policy } = binding;
  replayVector('replay/v2r/accepts-witness-bindings', 'Owner-signed WITNESSES_BOUND (two witnesses, quorum 2) then WITNESSES_UNBOUND (the second, quorum 1) replay; the witnessBinding and witnessPolicy records are pinned.', { ref: 'witness-bound-v2', eventCount: binding.events.length }, ACCEPT);
  const bind = binding.events[base.length];
  replayVector('replay/v2r/rejects-altered-witness-binding', 'A binding whose witness list was edited after signing is refused (CONTROL_AUTHORIZATION_INVALID).', [...base, { ...bind, data: { ...bind.data, witnesses: [{ ...bind.data.witnesses[0], url: 'https://attacker.example.org' }, bind.data.witnesses[1]] } }], reject('CONTROL_AUTHORIZATION_INVALID', base.length));
  const bindWith = async (data, list = base) => [...list, await signControl(list, { id: 'binding:bad', type: 'WITNESSES_BOUND', data })];
  replayVector('replay/v2r/rejects-witness-binding-with-malformed-policy', 'A binding whose policy minimum has quorum 0 is refused (EVENT_DATA_INVALID).', await bindWith({ witnesses: [witnesses[0]], policy: { quorum: 0, requireOnOpen: true, maxUnwitnessedEvents: 100 } }), reject('EVENT_DATA_INVALID', base.length));
  replayVector('replay/v2r/rejects-witness-binding-without-policy', 'A binding without its policy minimum is refused (EVENT_DATA_INVALID).', await bindWith({ witnesses: [witnesses[0]] }), reject('EVENT_DATA_INVALID', base.length));
  replayVector('replay/v2r/rejects-witness-binding-quorum-above-bound', 'A binding whose quorum (2) exceeds the witnesses bound after it (1) is refused (TRANSITION_INVALID).', await bindWith({ witnesses: [witnesses[0]], policy: policy(2) }), reject('TRANSITION_INVALID', base.length));
  replayVector('replay/v2r/rejects-witness-binding-with-invalid-url', 'A witness URL with a query string is refused (EVENT_DATA_INVALID).', await bindWith({ witnesses: [{ ...witnesses[0], url: 'https://witness-a.example.org/log?token=1' }], policy: policy(1) }), reject('EVENT_DATA_INVALID', base.length));
  replayVector('replay/v2r/rejects-witness-binding-with-duplicate-verifier-key', 'A binding naming one verifier key twice is refused (EVENT_DATA_INVALID).', await bindWith({ witnesses: [witnesses[0], { ...witnesses[0], url: 'https://witness-a2.example.org' }], policy: policy(1) }), reject('EVENT_DATA_INVALID', base.length));
  const extra = Array.from({ length: 16 }, (_, n) => { const s = transparency.noteSignerFromSeed(`witness-${n}.example.org`, new Uint8Array(32).fill(0x60 + n)); return { url: `https://witness-${n}.example.org`, verifierKey: transparency.verifierKey(s.name, s.publicKey) }; });
  replayVector('replay/v2r/rejects-witness-binding-above-sixteen-bound', 'Sixteen more witnesses on a history that binds one (seventeen after it) are refused (TRANSITION_INVALID).', await bindWith({ witnesses: extra, policy: policy(1) }, binding.events), reject('TRANSITION_INVALID', binding.events.length));
  replayVector('replay/v2r/accepts-rebinding-a-bound-witness', 'Binding a witness already bound re-binds it in place.', await bindWith({ witnesses: [{ ...witnesses[0], url: 'https://witness-a.example.org/v2' }], policy: policy(1) }, binding.events), ACCEPT);
  replayVector('replay/v2r/rejects-unbinding-of-unbound-witness', 'An unbinding that names a witness the history does not bind is refused (TRANSITION_INVALID).',
    [...binding.events, await signControl(binding.events, { id: 'binding:3', type: 'WITNESSES_UNBOUND', data: { verifierKeys: [witnesses[1].verifierKey], policy: policy(1) } })], reject('TRANSITION_INVALID', binding.events.length));
  const lostHead = { hash: `0x${'ee'.repeat(32)}`, position: base.length + 5, canonicalTime: headOf(binding.bound).canonicalTime + 5 };
  replayVector('replay/v2r/rejects-accepted-loss-of-a-contained-head', 'An accepted loss of a head this history contains is refused (TRANSITION_INVALID).',
    [...binding.bound, await signControl(binding.bound, { id: 'binding:loss', type: 'WITNESSES_UNBOUND', data: { verifierKeys: [witnesses[1].verifierKey], policy: policy(1), acceptedLoss: { reason: 'restored a backup', heads: [{ verifierKey: witnesses[1].verifierKey, head: plainMarked(headOf(base)) }] } } })], reject('TRANSITION_INVALID', binding.bound.length));
  replayVector('replay/v2r/accepts-unbinding-with-accepted-loss', 'An unbinding that records an accepted loss of a head this copy lacks is accepted.',
    [...binding.bound, await signControl(binding.bound, { id: 'binding:loss', type: 'WITNESSES_UNBOUND', data: { verifierKeys: [witnesses[1].verifierKey], policy: policy(1), acceptedLoss: { reason: 'restored a backup', heads: [{ verifierKey: witnesses[1].verifierKey, head: lostHead }] } } })], ACCEPT);
  const anchorWith = async (list, id, anchor, receipt) => { const at = plainMarked(headOf(list)); return [...list, await signControl(list, { id, type: 'ANCHOR_RECORDED', data: { anchoredHead: at, anchor, receipt, anchoredAt: at.canonicalTime } })]; };
  const bindingShaped = { action: 'UNBIND', historyId: headOf(base.slice(0, 1)).hash, witnesses: [witnesses[0]], policy: { quorum: 1, requireOnOpen: false, maxUnwitnessedEvents: 1_000_000 } };
  replayVector('replay/v2r/anchor-shaped-like-a-binding-binds-nothing', 'An ANCHOR_RECORDED whose receipt is shaped like an unbinding changes no binding (the stateRoot pins the unchanged witness records).', await anchorWith(binding.events, 'anchor:binding-shaped', 'custom', bindingShaped), ACCEPT);
  replayVector('replay/v2r/rejects-unknown-anchor-kind', 'An anchor naming a kind other than local-head-file, rekor-v2 or custom is refused (EVENT_DATA_INVALID).', await anchorWith(base, 'anchor:http', 'http-witness', bindingShaped), reject('EVENT_DATA_INVALID', base.length));
}

// ---------------------------------------------------------------- authorization (the v1 corpus; decisions on the migrated twins)

section('authorization');
{
  const at = headOf(handover.events).canonicalTime, head = plainMarked(headOf(handover.events));
  authorizationVector('authorization/v2r/successor-may-exercise-its-own-grant', 'The successor may do what it was separately granted.', 'handover-v2', { actorId: 'alex', action: 'read', resource: 'progress:42', claimedAt: at }, { expectDecision: 'ALLOW' });
  authorizationVector('authorization/v2r/successor-does-not-inherit-collection', 'The successor holds the duty and must not inherit the power that created it.', 'handover-v2', { actorId: 'alex', action: 'read', resource: 'incident:42', claimedAt: at }, { expectDecision: 'DENY' });
  authorizationVector('authorization/v2r/predecessor-refused-after-handover', 'A terminated agent is refused before any authority is considered (AGENT_INACTIVE).', 'handover-v2', { actorId: 'bea', action: 'read', resource: 'incident:42', claimedAt: at }, { expectCode: 'AGENT_INACTIVE' });
  authorizationVector('authorization/v2r/history-relation-unverified', 'An expected head that is not the replayed head yields INDETERMINATE HISTORY_RELATION_UNVERIFIED.', 'handover-v2', { actorId: 'alex', action: 'read', resource: 'progress:42', claimedAt: at }, { head: { ...head, hash: `0x${'ab'.repeat(32)}` }, expectCode: 'HISTORY_RELATION_UNVERIFIED' });
  authorizationVector('authorization/v2r/causal-time-invalid', 'An evaluation time before the head is not causal (CAUSAL_TIME_INVALID).', 'handover-v2', { actorId: 'alex', action: 'read', resource: 'progress:42', claimedAt: 1 }, { at: at - 1, expectCode: 'CAUSAL_TIME_INVALID' });
  authorizationVector('authorization/v2r/domain-mismatch', 'A request under a different deployment is refused (DOMAIN_MISMATCH).', 'handover-v2', { actorId: 'alex', action: 'read', resource: 'progress:42', claimedAt: at }, { domain: { ...DOMAIN, deploymentId: 'elsewhere' }, expectCode: 'DOMAIN_MISMATCH' });
  const corpusAt = headOf(histories['authority-v2']).canonicalTime;
  const req = (actorId, action, resource, extra = {}) => ({ actorId, action, resource, claimedAt: corpusAt, ...extra });
  const cases = [
    ['allow-via-delegation-with-intersection', 'A delegated grant requiring an intersection partner the actor holds is allowed.', req('analyst', 'write', 'ledger', { amount: '50' }), { expectDecision: 'ALLOW' }],
    ['allow-via-delegation', 'A plain delegation is allowed.', req('analyst', 'read', 'ledger', { amount: '5' }), { expectDecision: 'ALLOW' }],
    ['missing-intersection', 'A required intersection partner not held: MISSING_INTERSECTION.', req('clerk', 'write', 'vault'), { expectCode: 'MISSING_INTERSECTION' }],
    ['prohibited-root', 'A ROOT prohibition blocks the lead\'s payment from the vault.', req('lead', 'pay', 'vault', { amount: '10' }), { expectCode: 'PROHIBITED' }],
    ['prohibited-global', 'A GLOBAL prohibition blocks an action any grant would allow.', req('guard', 'freeze', 'ledger'), { expectCode: 'PROHIBITED' }],
    ['revoked', 'A revoked grant fails REVOKED.', req('intern', 'read', 'vault'), { expectCode: 'REVOKED' }],
    ['expired', 'An expired grant fails EXPIRED.', req('cadet', 'write', 'ledger'), { expectCode: 'EXPIRED' }],
    ['not-yet-valid', 'A grant whose notBefore lies ahead fails NOT_YET_VALID.', req('novice', 'pay', 'ledger'), { expectCode: 'NOT_YET_VALID' }],
    ['amount-required', 'A quantitative grant needs an amount (AMOUNT_REQUIRED).', req('buyer', 'pay', 'ledger'), { expectCode: 'AMOUNT_REQUIRED' }],
    ['amount-exceeded', 'An amount above the ceiling fails AMOUNT_EXCEEDED; format-2 Amounts are decimal strings.', req('buyer', 'pay', 'ledger', { amount: '101' }), { expectCode: 'AMOUNT_EXCEEDED' }],
    ['amount-within-cap', 'An amount at the ceiling is allowed.', req('buyer', 'pay', 'ledger', { amount: '100' }), { expectDecision: 'ALLOW' }],
    ['cumulative-amount-exceeded', 'Two admissions used 90 of 100: 20 more fails CUMULATIVE_AMOUNT_EXCEEDED.', req('spender', 'spend', 'petty-cash', { amount: '20' }), { expectCode: 'CUMULATIVE_AMOUNT_EXCEEDED' }],
    ['cumulative-amount-honoured', 'The remaining 10 is allowed.', req('spender', 'spend', 'petty-cash', { amount: '10' }), { expectDecision: 'ALLOW' }],
    ['transaction-count-exceeded', 'One admission exhausted a single-transaction grant (TRANSACTION_COUNT_EXCEEDED).', req('stamper', 'stamp', 'forms'), { expectCode: 'TRANSACTION_COUNT_EXCEEDED' }],
    ['agent-inactive', 'A terminated agent is refused (AGENT_INACTIVE).', req('leaver', 'read', 'ledger'), { expectCode: 'AGENT_INACTIVE' }],
    ['no-authority', 'An active agent holding no grant fails NO_AUTHORITY.', req('visitor', 'read', 'ledger'), { expectCode: 'NO_AUTHORITY' }],
    ['successor-not-yet-appointed', 'The designated successor gains nothing before the transfer.', req('heir', 'read', 'ledger'), { expectCode: 'NO_AUTHORITY' }],
  ];
  for (const [id, purpose, request, options] of cases) authorizationVector(`authorization/v2r/${id}`, purpose, 'authority-v2', request, options);
  authorizationVector('authorization/v2r/migrated-successor-may-exercise-its-own-grant', 'Decisions on the history migrated from legacy match the legacy fixture: the successor may do what it was separately granted.', 'migrated-legacy-v2', { actorId: 'b:first-look', action: 'record-review-progress', resource: 'obligation:first-look', claimedAt: 5000 }, { expectDecision: 'ALLOW' });
  authorizationVector('authorization/v2r/migrated-successor-does-not-inherit-collection', 'The successor does not inherit the collection power (legacy-migrated history).', 'migrated-legacy-v2', { actorId: 'b:first-look', action: 'collect-evidence-packet', resource: 'resource:first-look', claimedAt: 5000 }, { expectCode: 'ACTION_NOT_ALLOWED' });
}

// ---------------------------------------------------------------- SURVIVES

section('survives');
{
  const count = handover.events.length;
  survivesVector('survives/v2r/predecessor-after-handover', 'The terminated predecessor keeps the duty visible; its assignment moved to the successor; its grant was revoked.', 'handover-v2', 'bea', count,
    { lifecycleStatus: 'TERMINATED', obligationIds: ['duty:42'], currentAssignments: [{ obligationId: 'duty:42', assigneeId: 'alex', successionRuleId: 'handover' }], currentRoleTenureCount: 0, transferredRoleTenureCount: 1, invalidatedAuthorityIds: ['collect'] });
  survivesVector('survives/v2r/successor-after-handover', 'The successor holds the tenure and the assignment.', 'handover-v2', 'alex', count, { lifecycleStatus: 'ACTIVE', obligationIds: ['duty:42'], currentRoleTenureCount: 1, invalidatedAuthorityIds: [] });
  survivesVector('survives/v2r/predecessor-before-handover', 'Before the succession the predecessor is active and owns the open duty.', 'handover-v2', 'bea', handover.before, { lifecycleStatus: 'ACTIVE', obligationIds: ['duty:42'], currentRoleTenureCount: 1 });
  survivesVector('survives/v2r/unknown-agent', 'An agent the history never created is ABSENT.', 'handover-v2', 'nobody', count, { exists: false, lifecycleStatus: 'ABSENT' });
  survivesVector('survives/v2r/migrated-predecessor-after-handover', 'SURVIVES on the legacy-migrated history matches the legacy fixture.', 'migrated-legacy-v2', 'a:first-look', migrations.legacy.events.length,
    { lifecycleStatus: 'TERMINATED', obligationIds: ['obligation:first-look'], currentAssignments: [{ obligationId: 'obligation:first-look', assigneeId: 'b:first-look', successionRuleId: 'succession:first-look' }] });
}

// ---------------------------------------------------------------- head attestations (/2) across a rotation

section('attestation');
{
  const events = rotation.events, r = rotation.position;
  const rotatedSigner = signer.signerFromKeyPair(ROTATED);
  const commitmentAt = (p) => { const x = accepted(events.slice(0, p + 1)); return { head: plainMarked(x.head), commitment: { stateRoot: x.stateRoot, projectionHead: x.projectionHead } }; };
  const attest = async (s, p, edit = (c) => c) => { const { head, commitment } = edit(commitmentAt(p)); return plain2(await signer.attestHead(s, DOMAIN, head, 'sha256', commitment)); };
  attestationVector('attestation/v2r/pre-rotation-head-by-retired-key-verifies', 'An attestation (/2, with stateRoot and projectionHead) of a head before the rotation, signed by the key then in force, still verifies.', 'rotation-v2', events.length, await attest(ownerSigner, rotation.before - 1), { valid: true });
  attestationVector('attestation/v2r/rotation-head-by-retired-key-verifies', 'The rotation head belongs to the old key set.', 'rotation-v2', events.length, await attest(ownerSigner, r), { valid: true });
  attestationVector('attestation/v2r/rotation-head-by-new-key-fails', 'The new key governs only after the rotation.', 'rotation-v2', events.length, await attest(rotatedSigner, r), { valid: false, signatureValid: false });
  attestationVector('attestation/v2r/post-rotation-head-by-retired-key-fails', 'A head after the rotation signed by the retired key does not verify.', 'rotation-v2', events.length, await attest(ownerSigner, r + 1), { valid: false, signatureValid: false });
  attestationVector('attestation/v2r/post-rotation-head-by-new-key-verifies', 'A head after the rotation signed by the new key verifies.', 'rotation-v2', events.length, await attest(rotatedSigner, events.length - 1), { valid: true });
  attestationVector('attestation/v2r/foreign-head-by-new-key-fails', 'A correctly signed attestation of a head this history does not contain: prefix false.', 'rotation-v2', events.length, await attest(rotatedSigner, events.length - 1, (c) => ({ ...c, head: { ...c.head, hash: `0x${'ef'.repeat(32)}` } })), { valid: false, signatureValid: true, prefix: false });
  attestationVector('attestation/v2r/wrong-state-root', 'A valid signature over a wrong stateRoot: stateRootValid false.', 'rotation-v2', events.length, await attest(rotatedSigner, events.length - 1, (c) => ({ ...c, commitment: { ...c.commitment, stateRoot: `0x${'33'.repeat(32)}` } })), { valid: false, stateRootValid: false, signatureValid: true });
}

// ---------------------------------------------------------------- Amount encoding negatives (SPEC §3.3, A-7)

section('budgets');
{
  const H = budgetsH.events, pd = H.findIndex((e) => e.type === 'TRANSACTION_INTENT_DECLARED');
  const withAmount = (amount) => { const c = clone(H.slice(0, pd + 1)); c[pd].data.amount = amount; return c; };
  replayVector('replay/v2r/amount-as-json-number', 'A-7: an Amount written as a JSON number is not a §3.3 decimal string: EVENT_DATA_INVALID.', withAmount(5), reject('EVENT_DATA_INVALID', pd));
  replayVector('replay/v2r/amount-79-digits', 'A-7: an Amount of 79 decimal digits (above the 78 digits of MAX): EVENT_DATA_INVALID.', withAmount('1'.repeat(79)), reject('EVENT_DATA_INVALID', pd));
  replayVector('replay/v2r/amount-max-plus-one', 'A-7: MAX + 1 = 2^256 as a decimal string: EVENT_DATA_INVALID.', withAmount((MAX + 1n).toString()), reject('EVENT_DATA_INVALID', pd));
}

// ---------------------------------------------------------------- reconciliation observations (type 42, post-E5: A-71 with A-86, A-87, A-89, A-90)

section('observation');
{
  const H = observation.events, at = (label) => ({ ref: 'observation-v2', eventCount: observation[label] });
  const GW = { runtimeSessionId: 'session:gateway', credentialKeyId: GATEWAY.keyId, controlEpoch: 1 }, CB = { runtimeSessionId: 'session:cal', credentialKeyId: CAL.keyId, controlEpoch: 1 };
  const UNSUPPLIED = ['action', 'observedAt', 'resource'];
  const data = (who, source, extra = {}) => ({ observationId: core.derivedObservationId(who, source), reconcilerAgentId: who, source, call: { actorId: 'spender', unsupplied: UNSUPPLIED }, match: { result: 'UNMATCHED' }, ...extra });
  const admission = H.findIndex((e) => e.type === 'TRANSACTION_INTENT_ADMITTED'), declaration = H.findIndex((e) => e.type === 'TRANSACTION_INTENT_DECLARED');
  replayVector('replay/v2r/a71-accepts-matched-admission', 'A-71.3: a MATCHED observation citing an earlier TRANSACTION_INTENT_ADMITTED whose proof.request.actorId is call.actorId is accepted; its observation and reconciliation-cursor records (count 1, A-89.1) enter the root, R + 3 (A-87).', at('matchedAdmission'), ACCEPT);
  replayVector('replay/v2r/a71-accepts-matched-refusal', 'A-71.3: a MATCHED observation citing an earlier REQUEST_REFUSED of call.actorId is accepted (R + 2: the cursor of the pair already exists).', at('matchedRefusal'), ACCEPT);
  replayVector('replay/v2r/a71-accepts-unmatched', 'A-71.3: an UNMATCHED observation (no match.position) is accepted.', at('unmatched'), ACCEPT);
  replayVector('replay/v2r/a71-accepts-equivocation', 'A-71.3 / A-86.1: the same (streamId, eventRef) with another eventDigest is accepted with equivocates = the earliest observation of the key.', at('equivocation'), ACCEPT);
  replayVector('replay/v2r/a71-accepts-second-equivocation', 'A-86.4: a third digest of the key, here by another reconciler (A-89.5: one index for the whole history), is accepted; equivocates still names the earliest.', at('secondEquivocation'), ACCEPT);
  replayVector('replay/v2r/a71-accepts-observation-history', 'The whole observation history (A-71.9): every new record kind, an eventRef seen on a second stream as a distinct key; root and projection head pinned (row 42: code 42, flag bit 1, bit 2 iff call.amount).', { ref: 'observation-v2', eventCount: H.length }, ACCEPT);
  const p = H.length, ts = H.at(-1).timestamp + 1;
  // Duplicates (A-86): the same digest under the key, whoever reports it and whatever came between.
  replayVector('replay/v2r/a71-rejects-duplicate', 'A-71.3 step 6: a re-emission of an accepted observation (same derived id, fresh envelope and timestamp): OBSERVATION_DUPLICATE.',
    [...H, await signObservation(H, 'obs:dup', data('gateway', observationPsp('ch_1', '1'), { call: { actorId: 'spender', action: 'pay', resource: 'vendor', amount: '250', unsupplied: ['observedAt'] }, match: { result: 'MATCHED', position: admission } }), GW, GATEWAY, { timestamp: ts })], reject('OBSERVATION_DUPLICATE', p));
  const eq = H.slice(0, observation.equivocation);
  replayVector('replay/v2r/a71-rejects-duplicate-after-equivocation', 'A-86.4: O1 (digest a) then O2 (digest b, an accepted equivocation); O2 re-emitted with a fresh envelope and the same derived id: OBSERVATION_DUPLICATE (any accepted digest of the key, not only the earliest).',
    [...eq, await signObservation(eq, 'obs:dup-eq', data('gateway', observationPsp('ch_3', 'b'), { call: { actorId: 'spender', resource: 'vendor', unsupplied: ['action', 'observedAt'] } }), GW, GATEWAY, { timestamp: eq.at(-1).timestamp + 5 })], reject('OBSERVATION_DUPLICATE', eq.length));
  replayVector('replay/v2r/a71-rejects-duplicate-by-another-reconciler', 'A-89.5: one (streamId, eventRef) index for the whole history: another reconciler\'s report of the same digest is OBSERVATION_DUPLICATE.',
    [...H, await signObservation(H, 'obs:dup-cal', data('cal', observationPsp('ch_2', '2')), CB, CAL)], reject('OBSERVATION_DUPLICATE', p));
  // Bindings (TRANSITION_INVALID).
  replayVector('replay/v2r/a71-rejects-matched-wrong-actor', 'A-71.3 step 5: the cited admission\'s actor is not call.actorId: TRANSITION_INVALID.',
    [...H, await signObservation(H, 'obs:actor', data('gateway', observationPsp('ch_9', '9'), { call: { actorId: 'cal', unsupplied: UNSUPPLIED }, match: { result: 'MATCHED', position: admission } }), GW, GATEWAY)], reject('TRANSITION_INVALID', p));
  replayVector('replay/v2r/a71-rejects-matched-later-position', 'A-71.3 step 5: match.position is not before the observation\'s own position: TRANSITION_INVALID.',
    [...H, await signObservation(H, 'obs:later', data('gateway', observationPsp('ch_9', '9'), { match: { result: 'MATCHED', position: p } }), GW, GATEWAY)], reject('TRANSITION_INVALID', p));
  replayVector('replay/v2r/a71-rejects-matched-non-decision-type', 'A-71.3 step 5: the cited event is a TRANSACTION_INTENT_DECLARED, neither an admission nor a refusal: TRANSITION_INVALID.',
    [...H, await signObservation(H, 'obs:declaration', data('gateway', observationPsp('ch_9', '9'), { match: { result: 'MATCHED', position: declaration } }), GW, GATEWAY)], reject('TRANSITION_INVALID', p));
  replayVector('replay/v2r/a71-rejects-stale-head', 'A-71.3 step 4: expectedHistoryHead is not the head immediately before the event: TRANSITION_INVALID.',
    [...H, await signObservation(H, 'obs:stale', data('gateway', observationPsp('ch_9', '9'), { expectedHistoryHead: plainMarked(headOf(H.slice(0, -1))) }), GW, GATEWAY)], reject('TRANSITION_INVALID', p));
  replayVector('replay/v2r/a71-rejects-reconciler-not-signer', 'A-71.3 step 3: reconcilerAgentId names cal while gateway\'s session signs: TRANSITION_INVALID.',
    [...H, await signObservation(H, 'obs:reconciler', data('cal', observationPsp('ch_9', '9')), GW, GATEWAY)], reject('TRANSITION_INVALID', p));
  // Authorization (A-89.3): forged → OBSERVATION_AUTHORIZATION_INVALID, unsigned → EVENT_DATA_INVALID; the fence first.
  const good = await signObservation(H, 'obs:auth', data('gateway', observationPsp('ch_9', '9')), GW, GATEWAY);
  const edited = (mutate) => { const e = clone(good); mutate(e.data); return [...H, e]; };
  replayVector('replay/v2r/a71-rejects-tampered-digest', 'A-71.2: source.eventDigest changed after signing (the challenge binds source as written): OBSERVATION_AUTHORIZATION_INVALID.', edited((d) => { d.source.eventDigest = `0x${'e'.repeat(64)}`; }), reject('OBSERVATION_AUTHORIZATION_INVALID', p));
  replayVector('replay/v2r/a71-rejects-forged-signature', 'A-89.3: a well-formed signature that does not verify ("forged"): OBSERVATION_AUTHORIZATION_INVALID.', edited((d) => { d.observationAuthorization.signature = signFlip(d.observationAuthorization.signature); }), reject('OBSERVATION_AUTHORIZATION_INVALID', p));
  replayVector('replay/v2r/a71-rejects-unsigned', 'A-89.3: no observationAuthorization ("unsigned"): EVENT_DATA_INVALID (closed schema).', edited((d) => { delete d.observationAuthorization; }), reject('EVENT_DATA_INVALID', p));
  replayVector('replay/v2r/a71-rejects-owner-signed', 'A-71.1: an observation carrying a controlAuthorization (an owner key never signs one): EVENT_DATA_INVALID.', edited((d) => { d.controlAuthorization = { keyId: 'owner:1', signature: `0x${'11'.repeat(64)}` }; }), reject('EVENT_DATA_INVALID', p));
  const fenced = [...H, await signControl(H, { id: 'obs:advance-cal', type: 'CONTROL_EPOCH_ADVANCED', data: { agentId: 'cal', controllerId: 'operator', fromEpoch: 1, toEpoch: 2 } })];
  replayVector('replay/v2r/a71-rejects-fenced-session', 'A-71.3 step 2: cal\'s epoch advanced; its session signs an observation: SESSION_FENCED (the fence first).',
    [...fenced, await signObservation(fenced, 'obs:fenced', data('cal', observationPsp('ch_9', '9')), CB, CAL)], reject('SESSION_FENCED', fenced.length));
  // Schema (A-71.1, A-89.2, A-89.4).
  const schema = async (id, purpose, extra, expected) => replayVector(id, purpose, [...H, await signObservation(H, `obs:${id.split('/').at(-1)}`, data('gateway', observationPsp('ch_8', '8'), extra), GW, GATEWAY)], expected);
  await schema('replay/v2r/a71-rejects-unsupplied-not-matching', 'A-71.1: call.action is present and also named in call.unsupplied: EVENT_DATA_INVALID.', { call: { actorId: 'spender', action: 'pay', unsupplied: UNSUPPLIED } }, reject('EVENT_DATA_INVALID', p));
  await schema('replay/v2r/a71-rejects-unsupplied-unordered', 'A-71.1: call.unsupplied not in byte order: EVENT_DATA_INVALID.', { call: { actorId: 'spender', unsupplied: ['resource', 'action', 'observedAt'] } }, reject('EVENT_DATA_INVALID', p));
  await schema('replay/v2r/a71-rejects-matched-without-position', 'A-71.1: match.position is present iff MATCHED: EVENT_DATA_INVALID.', { match: { result: 'MATCHED' } }, reject('EVENT_DATA_INVALID', p));
  const astral = '\u{1F600}';
  await schema('replay/v2r/a71-rejects-resource-129-code-points', 'A-89.2: call.resource of 129 code points (100 ASCII + 29 astral characters, 158 UTF-16 units): EVENT_DATA_INVALID.', { call: { actorId: 'spender', resource: `${'r'.repeat(100)}${astral.repeat(29)}`, unsupplied: ['action', 'observedAt'] } }, reject('EVENT_DATA_INVALID', p));
  await schema('replay/v2r/a71-accepts-resource-128-code-points', 'A-89.2 / A-89.4: call.resource of 128 code points (156 UTF-16 units) and call.observedAt far after the event time (no bound): accepted.', { call: { actorId: 'spender', resource: `${'r'.repeat(100)}${astral.repeat(28)}`, observedAt: 9_000_000_000_000, unsupplied: ['action'] } }, ACCEPT);
  // Capacity (A-71.8): growth in RESERVE_CLASS.
  const cap = observation.cap;
  replayVector('replay/v2r/a71-rejects-at-max-events', 'A-71.8: at capacity.maxEvents (S(p) = M) an observation is growth (ΔS = +1): CAPACITY_CONTROL_ONLY.',
    [...cap, await signObservation(cap, 'obs:cap', data('gateway', observationPsp('ch_1', '1')), GW, GATEWAY)], reject('CAPACITY_CONTROL_ONLY', cap.length));
  // Other formats and the migrated prefix (A-71.0, A-78).
  const m = migrations.format1.events, inPrefix = m.findIndex((e, q) => q > 0 && core.CONTROL_EVENT_TYPES.has(e.type));
  const typed = clone(m); typed[inPrefix] = { ...typed[inPrefix], type: 'RECONCILIATION_OBSERVED' };
  replayVector('replay/v2r/a71-rejects-inside-migrated-prefix', 'A-78.1: type 42 inside a migrated (format-1) prefix: EVENT_DATA_INVALID at its position (schema stage, coded against migratedFrom).', typed, reject('EVENT_DATA_INVALID', inPrefix));
  const v1 = JSON.parse(readFileSync(join(ROOT, 'conformance/v1/histories/handover-v1.json'), 'utf8'));
  replayVector('replay/v2r/a71-rejects-in-format1-history', 'A-71.0: type 42 in a format-1 history: UNSUPPORTED_EVENT_TYPE.',
    [...v1, { id: 'obs:format1', type: 'RECONCILIATION_OBSERVED', timestamp: v1.at(-1).timestamp, data: good.data }], reject('UNSUPPORTED_EVENT_TYPE', v1.length));
  // Export (§15): a range through the equivocation, verified from the records (the duplicate index is rebuilt from the observation records).
  const view = plain2(core.exportView(engineEvents(H), { fromPosition: observation.unmatched - 1, toPosition: H.length - 1, include: { fromRecords: true, toRecords: true, referencedEvents: true } }));
  exportVerifyVector('export-verify/v2r/a71-observation-range', 'A-71.4: a view from the first ch_3 observation to the head with fromRecords, toRecords and referencedEvents: the verifier rebuilds the observation records and the (streamId, eventRef) index, applies the equivocations and reaches the to root (ok).', view, { ok: true, code: null });
}

// ---------------------------------------------------------------- G6.5: authorization/v2r decision vectors (A-133.7, A-134, A-135.4, Programme 3 ASM-1 family (c), A-136.4)
// Non-frozen; the events are carried inline so no new history root is pinned (RESULTS/PINNED-ROOTS.json unchanged).

section('authorization');
{
  // A-133.7: actor `wide` holds two independent roots; the §4.6 winner a-main carries 257 request-relevant ROOT
  // prohibitions, all revoked (listed in checkedProhibitionIds "regardless of activity", so the §6.3 preflight refuses).
  const h = scripted('output-limit');
  const owner = await createLocalOwner(h.config);
  await owner.createAgent({ id: 'wide' });
  await owner.grant({ id: 'a-main', to: 'wide', actions: ['pay'], resources: ['vendor'], expiresAt: 10_000_000, delegable: 1 });
  await owner.grant({ id: 'z-fallback', to: 'wide', actions: ['pay'], resources: ['vendor'], expiresAt: 10_000_000 });
  const prohibitionIds = Array.from({ length: 257 }, (_, i) => `x-${String(i).padStart(3, '0')}`);
  for (const id of prohibitionIds) await owner.prohibit({ id, root: 'a-main', subject: 'wide', actions: ['pay'], resources: ['vendor'], expiresAt: 10_000_000 });
  for (const id of prohibitionIds) await owner.revoke(id);
  const before = h.events();
  await owner.revoke('a-main');
  const after = h.events();
  const pay = (events) => ({ actorId: 'wide', action: 'pay', resource: 'vendor', claimedAt: headOf(events).canonicalTime });
  authorizationVector('authorization/v2r/indeterminate-output-limit-257-revoked-root-prohibitions', 'G6.5 A-133.7 (the `before` corpus): the winner a-main lists its 257 revoked ROOT prohibitions in checkedProhibitionIds, so the §6.3 preflight refuses: INDETERMINATE / OUTPUT_LIMIT_EXCEEDED (a proof-size refusal, outside ASM-1; E-31 makes it a candidate failure in a later format minor).',
    before, pay(before), { expectCode: 'OUTPUT_LIMIT_EXCEEDED' });
  const fallback = authorizePortable({ operationVersion: core.AUTHORIZATION_VERSION, events: after, expectedHistoryHead: plainMarked(headOf(after)), domain: DOMAIN, policyVersion: after[0].data.policyVersion,
    rootRecognitionPolicy: 'declared-principal-root/0.2', request: pay(after), evaluationTime: headOf(after).canonicalTime, authoritative: true, consequential: false }, replay);
  if (fallback.proof?.recognizedRoot.rootAuthorityId !== 'z-fallback' || fallback.proof.checkedProhibitionIds.length !== 0) throw new Error('A-133.7 after: expected z-fallback with no checked prohibitions');
  authorizationVector('authorization/v2r/allow-fallback-root-after-oversized-winner-revoked', 'G6.5 A-133.7 (the `after` corpus): revoking a-main makes z-fallback the winner; its proof fits (recognizedRoot z-fallback, checkedProhibitionIds []): ALLOW. Under A-133.2 the pre-preflight verdict was allow on both sides.',
    after, pay(after), { expectDecision: 'ALLOW', expectControlling: ['z-fallback'] });
}
{
  // A-134, A-135.4 and Programme 3's family (c): grants without maxCumulativeAmount, usage brought near or to MAX by admissions.
  const MAX_AMOUNT = (1n << 256n) - 1n;
  const h = scripted('overflow');
  const owner = await createLocalOwner(h.config);
  const actors = [['solo', SPENDER], ['pair', BEA], ['maxed', ALEX]];
  for (const [id, pair] of actors) {
    await owner.createAgent({ id });
    await owner.createRole({ id: `desk-${id}` });
    await owner.appoint({ agent: id, role: `desk-${id}`, tenure: `desk-${id}:1`, number: 1 });
    await owner.admitRuntime({ session: `session:${id}`, agent: id, epoch: 1, key: pair.keyId, credential: pair.credential, expiresAt: 10_000_000 });
  }
  const uncapped = (id, to) => owner.grant({ id, to, actions: ['spend'], resources: ['petty-cash'], expiresAt: 10_000_000, maxAmount: MAX_AMOUNT });
  await uncapped('o-solo', 'solo');
  await uncapped('o-first', 'pair');
  await uncapped('o-second', 'pair');
  await uncapped('a-main', 'maxed');
  await uncapped('z-fallback', 'maxed');
  for (const [id, pair, amount] of [['solo', SPENDER, MAX_AMOUNT - 1n], ['pair', BEA, MAX_AMOUNT - 1n], ['maxed', ALEX, MAX_AMOUNT]]) {
    const run = await openLocalSimulation(h.session(`session:${id}`, pair)).run({ id: `spend:${id}`, intentId: `spend:${id}`, action: 'spend', resource: 'petty-cash', role: `desk-${id}`, tenure: `desk-${id}:1`, termsCommitment: commitTerms({ purpose: id }), amount });
    if (run.invocation?.status !== 'SUBMITTED') throw new Error(`overflow: spend:${id} ${JSON.stringify(run.status)}`);
  }
  const events = h.events(), state = accepted(events).state;
  if (state.usageCounters.get('o-solo')?.admittedCumulativeAmount !== MAX_AMOUNT - 1n || state.usageCounters.get('o-first')?.admittedCumulativeAmount !== MAX_AMOUNT - 1n || state.usageCounters.get('a-main')?.admittedCumulativeAmount !== MAX_AMOUNT || state.usageCounters.has('o-second') || state.usageCounters.has('z-fallback')) throw new Error('overflow: usage counters');
  const spend = (actorId, amount) => ({ actorId, action: 'spend', resource: 'petty-cash', claimedAt: headOf(events).canonicalTime, amount });
  authorizationVector('authorization/v2r/deny-amount-overflow-single-root', 'G6.5 A-135.4: usage MAX − 1 on the only root (no maxCumulativeAmount), amount "2": the candidate fails the §4.2 overflow set: DENY / AMOUNT_OVERFLOW (source CORE, no budget).',
    events, spend('solo', '2'), { expectCode: 'AMOUNT_OVERFLOW', expectBudgetId: null });
  authorizationVector('authorization/v2r/allow-second-root-when-first-would-overflow', 'G6.5 A-135.4: the same, plus a byte-later root with fresh usage: the overflowing candidate fails and the other wins: ALLOW on o-second.',
    events, spend('pair', '2'), { expectDecision: 'ALLOW', expectControlling: ['o-second'] });
  authorizationVector('authorization/v2r/allow-fallback-root-when-winner-usage-at-max', 'G6.5 A-135, Programme 3 ASM-1 family (c): admitted usage at MAX on a-main, a request of 1, zero prohibitions: AMOUNT_OVERFLOW is candidate-local, so z-fallback wins: ALLOW (also after revoking a-main; build1 placed the check after winner selection and answered DENY / AMOUNT_OVERFLOW here).',
    events, spend('maxed', '1'), { expectDecision: 'ALLOW', expectControlling: ['z-fallback'] });
  authorizationVector('authorization/v2r/indeterminate-request-amount-over-max', 'G6.5 A-134.1: request.amount = MAX + 1 (a decimal string over MAX) is not a §3.3 Amount: a capture failure before causal time, INDETERMINATE / INVALID_INPUT (SUPPLIED_SCOPE), never DENY INVALID_AMOUNT.',
    events, spend('solo', (MAX_AMOUNT + 1n).toString()), { expectCode: 'INVALID_INPUT', expectScope: 'SUPPLIED_SCOPE' });
}
{
  // A-136.4: the raw path (spec02 §7.1). Generic limits and primitive grammars at deep capture (before causal time);
  // the named limits at step 7 (after causal time).
  const MAX_AMOUNT = (1n << 256n) - 1n;
  const head = { hash: `0x${'ab'.repeat(32)}`, position: 7, canonicalTime: 100 };
  const domain = { protocol: 'continuity', version: '0.2', deploymentId: 'irontrellis-conformance-v2r-raw', chainId: '31337', verifyingContract: '0x0000000000000000000000000000000000003002' };
  const raw = (constraints) => ({
    operationVersion: core.AUTHORITY_EVALUATION_VERSION,
    scope: { domain, policyVersion: 'raw/0.2', rootRecognitionPolicy: 'declared-principal-root/0.2', historyHead: head, evaluationTime: -1, globalPolicySourceId: 'policy',
      recognizedRoots: [{ rootAuthorityId: 'r', principalId: 'P', principalRecognitionEventId: 'ev-p', rootGrantEventId: 'ev-r' }] },
    request: { actorId: 'A', action: 'pay', resource: 'x', claimedAt: 100 },
    permissions: [{ kind: 'PERMISSION', authorityId: 'r', grantorId: 'P', granteeId: 'A', rootAuthorityId: 'r', independent: true, constraints: { actions: ['pay'], resources: ['x'], quantitative: false, maxDelegationDepth: 0, requiredIntersectionIds: [], ...constraints } }],
    prohibitions: [], authorityEvidence: [{ authorityId: 'r', grantEventId: 'ev-r', grantEventPosition: 1 }], revokedAuthorityIds: [], usage: [],
  });
  authorityEvaluationVector('authorization/v2r/causal-time-beats-named-list-limit', 'G6.5 A-136.4: 257 actions (a named limit, §7.1 step 7) with evaluationTime = −1: CAUSAL_TIME_INVALID (step 4) comes first.',
    raw({ actions: ['pay', ...Array.from({ length: 256 }, (_, i) => `a-${String(i).padStart(3, '0')}`)] }), { expectCode: 'CAUSAL_TIME_INVALID' });
  authorityEvaluationVector('authorization/v2r/amount-grammar-beats-causal-time', 'G6.5 A-136.4: maxAmount = MAX + 1 (the Amount grammar, deep capture) with evaluationTime = −1: INVALID_INPUT comes first.',
    raw({ quantitative: true, maxAmount: { '$continuity.bigint': (MAX_AMOUNT + 1n).toString() } }), { expectCode: 'INVALID_INPUT' });
}
{
  // G6.9 A-166: the §4.2 overflow set on supplied usage (the raw path, spec02 §7.1), both disjuncts (A-135.1, A-156.1).
  // The raw path needs a usage record for exactly the capped grants, so the A-135 pair is carried here by a
  // maxTransactions-only grant (the replayed twins above use uncapped grants, whose usage only a history supplies).
  const MAX_AMOUNT = (1n << 256n) - 1n, COUNT_MAX = Number.MAX_SAFE_INTEGER;
  const big = (n) => ({ '$continuity.bigint': n.toString() });
  const head = { hash: `0x${'ab'.repeat(32)}`, position: 7, canonicalTime: 100 };
  const domain = { protocol: 'continuity', version: '0.2', deploymentId: 'irontrellis-conformance-v2r-raw', chainId: '31337', verifyingContract: '0x0000000000000000000000000000000000003002' };
  const grant = (authorityId, caps) => ({ kind: 'PERMISSION', authorityId, grantorId: 'P', granteeId: 'A', rootAuthorityId: authorityId, independent: true,
    constraints: { actions: ['spend'], resources: ['petty-cash'], quantitative: true, maxDelegationDepth: 0, requiredIntersectionIds: [], ...caps } });
  const supplied = (grants, usage, amount) => ({
    operationVersion: core.AUTHORITY_EVALUATION_VERSION,
    scope: { domain, policyVersion: 'raw/0.2', rootRecognitionPolicy: 'declared-principal-root/0.2', historyHead: head, evaluationTime: 100, globalPolicySourceId: 'policy',
      recognizedRoots: grants.map((g) => ({ rootAuthorityId: g.authorityId, principalId: 'P', principalRecognitionEventId: 'ev-p', rootGrantEventId: `ev-${g.authorityId}` })) },
    request: { actorId: 'A', action: 'spend', resource: 'petty-cash', claimedAt: 100, amount: big(amount) },
    permissions: grants, prohibitions: [],
    authorityEvidence: grants.map((g, i) => ({ authorityId: g.authorityId, grantEventId: `ev-${g.authorityId}`, grantEventPosition: 1 + i })),
    revokedAuthorityIds: [],
    usage: usage.map(([authorityId, admittedTransactionCount, admittedCumulativeAmount]) => ({ authorityId, admittedTransactionCount, admittedCumulativeAmount: big(admittedCumulativeAmount) })),
  });
  const cumulativeCapped = (id) => grant(id, { maxCumulativeAmount: big(1000n) });
  const countCapped = (id) => grant(id, { maxTransactions: 5 });
  authorityEvaluationVector('authorization/v2r/deny-count-overflow-single-root', 'G6.9 A-166 (the A-156 count disjunct on supplied usage): admittedTransactionCount 2^53 − 1 and admittedCumulativeAmount 0 on the only root, a grant with maxCumulativeAmount 1000 and no maxTransactions, amount 1 within the cap: the candidate fails the §4.2 overflow set: DENY / AMOUNT_OVERFLOW (SUPPLIED_SCOPE).',
    supplied([cumulativeCapped('o-solo')], [['o-solo', COUNT_MAX, 0n]], 1n), { expectCode: 'AMOUNT_OVERFLOW', expectScope: 'SUPPLIED_SCOPE' });
  authorityEvaluationVector('authorization/v2r/allow-second-root-when-first-count-would-overflow', 'G6.9 A-166: the same, plus a byte-later root with fresh usage: the candidate whose count would overflow fails and the other wins: ALLOW on o-second.',
    supplied([cumulativeCapped('o-first'), cumulativeCapped('o-second')], [['o-first', COUNT_MAX, 0n], ['o-second', 0, 0n]], 1n), { expectDecision: 'ALLOW', expectScope: 'SUPPLIED_SCOPE', expectControlling: ['o-second'] });
  authorityEvaluationVector('authorization/v2r/deny-amount-overflow-raw-count-capped-grant', 'G6.9 A-166 (the A-135 amount disjunct on supplied usage): admittedCumulativeAmount MAX under a grant with maxTransactions 5 only, the count 1 below the cap, amount 1: DENY / AMOUNT_OVERFLOW (SUPPLIED_SCOPE).',
    supplied([countCapped('o-solo')], [['o-solo', 1, MAX_AMOUNT]], 1n), { expectCode: 'AMOUNT_OVERFLOW', expectScope: 'SUPPLIED_SCOPE' });
  authorityEvaluationVector('authorization/v2r/deny-amount-overflow-single-root-supplied-scope', 'G6.9 A-166: the supplied-scope twin of deny-amount-overflow-single-root: usage MAX − 1 on the only root (a maxTransactions-only grant, count below the cap), amount 2: DENY / AMOUNT_OVERFLOW (SUPPLIED_SCOPE).',
    supplied([countCapped('o-solo')], [['o-solo', 1, MAX_AMOUNT - 1n]], 2n), { expectCode: 'AMOUNT_OVERFLOW', expectScope: 'SUPPLIED_SCOPE' });
  authorityEvaluationVector('authorization/v2r/allow-second-root-when-first-would-overflow-supplied-scope', 'G6.9 A-166: the supplied-scope twin of allow-second-root-when-first-would-overflow: usage MAX − 1 on o-first, fresh usage on the byte-later o-second, amount 2: ALLOW on o-second.',
    supplied([countCapped('o-first'), countCapped('o-second')], [['o-first', 1, MAX_AMOUNT - 1n], ['o-second', 0, 0n]], 2n), { expectDecision: 'ALLOW', expectScope: 'SUPPLIED_SCOPE', expectControlling: ['o-second'] });
}

// ---------------------------------------------------------------- G6.7 A-149: a migrated null-expiry session after the prefix, as attester and as outer session
// A format-1 E6 source whose worker holds a session WITHOUT expiresAt (format-1 grammar), migrated to format 2; after the
// prefix the worker gets a fresh session, a job, a duty and an activated duty policy natively. The two findings are
// built against an in-memory copy of the state in which the prefix session carries an expiry (the writer refuses them,
// rightly), so they are validly signed and refused only by replay. Inline events: no history root is added.

section('migration');
{
  const OLD = BEA, NEW = ALEX; // session:old (prefix, no expiry) and session:new (post-prefix, finite expiry)
  const src = scripted('a149-source', { owner: 'owner', controller: 'controller', format: 'irontrellis-event/1', domain: { ...DOMAIN, version: '1' }, [internalFormat1.FORMAT1_TEST_TOOLING]: true });
  const owner = await createLocalReviewOwner(src.config);
  await owner.createAgent({ id: 'worker' });
  await owner.createRole({ id: 'role' });
  await owner.appoint({ agent: 'worker', role: 'role', tenure: 'tenure', number: 1 });
  const sourceEvents = src.events(), sourceState = accepted(sourceEvents).state;
  const oldSession = plainMarked(await signer.signControlEvent(ownerSigner, { id: 'a149-source:session-old', type: 'RUNTIME_SESSION_ADMITTED', timestamp: src.clock.t,
    data: { sessionId: 'session:old', agentId: 'worker', controllerId: 'controller', controlEpoch: 1, credentialKeyId: OLD.keyId, credentialScheme: 'ed25519', credentialPublicKey: OLD.credential } },
    sourceState.genesis.domain, sourceState.head, sourceState.hashAlgorithm));
  const dir = join(WORK, 'migrate-a149');
  mkdirSync(dir, { recursive: true });
  const source = join(dir, 'source.jsonl'), target = join(dir, 'target.jsonl');
  strictStore.createHistoryStore(source, core.jsonParseWithBigints(JSON.stringify([...sourceEvents, oldSession])), { readOnlyFormats: false }).close?.();
  const migrated = await migrateHistory({ source, target, now: () => 5000, signer: migrationOwner, nextKey: false, migrationId: MIGRATION_ID, acceptUnpinnedSource: true });
  if (JSON.stringify(migrated.sessionsWithoutExpiry) !== '["session:old"]') throw new Error(`A-149: expected session:old without expiry, got ${JSON.stringify(migrated.sessionsWithoutExpiry)}`);
  const clock = { t: 5000 };
  let counter = 0;
  const targetDomain = accepted(readStore(target)).state.genesis.domain;
  const config = { historyFile: target, domain: targetDomain, owner: 'owner', controller: 'controller', now: () => clock.t, ids: () => `a149:${(counter += 1)}`, signer: migrationOwner, witness: false, refusalPolicy: { coalesceMs: 0, maxPerMinute: 1_000_000 } };
  const t = openLocalOwner(config);
  await t.admitRuntime({ session: 'session:new', agent: 'worker', epoch: 1, key: NEW.keyId, credential: NEW.credential, expiresAt: 10_000_000 });
  await t.grant({ id: 'work', to: 'worker', actions: ['inspect'], resources: ['incident'], expiresAt: 10_000_000, maxTransactions: 1 });
  await t.grant({ id: 'record', to: 'worker', actions: ['OBLIGATE', 'ASSIGN_PERFORMANCE', 'record-collection-disposition', 'OBSERVE_OUTCOME', 'CREATE_ATTEMPT_DUTY', 'ASSIGN_ATTEMPT_DUTY', 'CLOSE_ATTEMPT_DUTY'], resources: ['incident', 'job', 'duty'], expiresAt: 10_000_000 });
  const options = { ...config, session: 'session:new', signHash: signHashWith(NEW) };
  const adapter = { adapterProfile: editions.approvedAdapterProfileForPolicy(editions.ADAPTER_POLICY_E6_HASH, editions.REMOTE_SERVICE_REPORT_ADAPTER_ID), submit: async (input) => unknownOutcome(input), reconcile: unknownOutcome };
  const job = { id: 'job', intentId: 'job', action: 'inspect', resource: 'incident', role: 'role', tenure: 'tenure', termsCommitment: commitTerms({ case: 'a149' }) };
  if ((await openLocalExecution(options, adapter, 'REMOTE_REPORT').run(job)).invocation.status !== 'OUTCOME_UNKNOWN') throw new Error('A-149: job');
  await openLocalAttemptRecorder(options).createDuty({ id: 'duty', intent: 'job', description: 'Investigate the unknown result', deadline: 10_000_000 });
  const duties = core.openLocalDutyPolicy(options);
  const selection = duties.describe({ duty: 'duty', incidentSourceDigest: DUTY_DIGEST('a'), attesterRole: 'role' });
  await t.grant({ id: 'activation', to: 'worker', actions: [selection.activationAction], resources: [selection.activationResource], expiresAt: 10_000_000 });
  await duties.activate({ id: 'activate', descriptor: selection.descriptor, activationAuthority: 'activation' });
  const resource = `duty:${selection.descriptorHash}`;
  await t.grant({ id: 'finding', to: 'worker', actions: ['ATTEST_DUTY_FINDING'], resources: [resource], expiresAt: 10_000_000 });
  await t.grant({ id: 'disposition', to: 'worker', actions: ['RECORD_DUTY_DISPOSITION'], resources: [resource], expiresAt: 10_000_000 });
  const base = readStore(target);
  clock.t += 1;
  /** A disposition finding with the given attester and outer sessions, signed against a state copy in which session:old has an expiry. */
  const finding = async (id, attester, outer) => {
    const state = accepted(base).state;
    const prefixSession = state.runtimeSessions.get('session:old');
    if (prefixSession.expiresAt !== undefined) throw new Error('A-149: session:old should carry no expiry');
    state.runtimeSessions.set('session:old', Object.freeze({ ...prefixSession, expiresAt: 10_000_000 }));
    const transition = { id: `duty-disposition:${id}`, type: 'ATTEMPT_DUTY_DISPOSITION_RECORDED', timestamp: clock.t, data: {
      dutyId: 'duty', actorId: 'worker', attesterId: 'worker', attesterRuntimeSessionId: attester.session, attestationAuthorityId: 'finding', dispositionAuthorityId: 'disposition',
      operation: { disposition: 'COMPLETED_UNDER_POLICY', checklist: DUTY_CHECKLIST(), reportDigest: DUTY_DIGEST('b'), nextStep: null } } };
    const input = { expectedDomain: targetDomain, expectedHistoryHead: state.head, runtimeSessionId: outer.session, transition };
    const prepared = administration.prepareDutyFinding(state, input);
    const attached = administration.attachDutyFinding(state, input, await signHashWith(attester.pair)(prepared.signingHash));
    const outerHash = administration.prepareAdministrativeEventState(state, attached).signingHash;
    return plain2(administration.attachAdministrativeSignatureState(state, attached, await signHashWith(outer.pair)(outerHash)).event);
  };
  const OLD_S = { session: 'session:old', pair: OLD }, NEW_S = { session: 'session:new', pair: NEW };
  const control = await finding('control', NEW_S, NEW_S);
  if (replay(engineEvents([...base, control])).status !== 'ACCEPTED') throw new Error('A-149: the control finding (both sessions fresh) must replay');
  replayVector('replay/v2r/migrated-null-expiry-attester-after-prefix', 'G6.7 A-149: a migrated prefix session without expiry (session:old, null in its §7.2 record) attests a duty finding after the prefix, the outer transition signed by a fresh session: the attester session is expired for every purpose (§6.2 step 4, §16.2 step 3, A-52.2), so the §13.2 attester-eligibility step refuses: TRANSITION_INVALID at the finding.',
    [...base, await finding('attester', OLD_S, NEW_S)], reject('TRANSITION_INVALID', base.length));
  const outerOld = [...base, await finding('outer', NEW_S, OLD_S)];
  const outerCode = replay(engineEvents(outerOld)).code;
  replayVector('replay/v2r/migrated-null-expiry-outer-session-after-prefix', `G6.7 A-149: the same finding attested by the fresh session, the outer transition signed by the prefix session without expiry: it fails §6.2 step 4 with the type's code (${outerCode}).`,
    outerOld, reject(outerCode, base.length));
}

// ---------------------------------------------------------------- G6.8 A-157: PublicKey32 hex case at C4; A-148.1: bit 2 of a null amountCap
// A-157: r4 §3.3 PublicKey32 is `0x` + 64 lowercase hex, a C4 grammar; a format-2 event carrying an uppercase key is
// EVENT_DATA_INVALID at its position, before control authorization and the §3.3 point test (nothing is lowercased).
// Each vector has a lowercase twin the generator requires to replay ACCEPTED, so the vector differs only in case.

section('owner-keys');
{
  const upper = (key) => { if (!/[a-f]/.test(key.slice(2))) throw new Error('A-157: key without a-f'); return `0x${key.slice(2).toUpperCase()}`; };
  const rotatedSigner = signer.signerFromKeyPair(ROTATED);
  const events = rotation.events;
  const withAgent = [...events, await signControl(events, { id: 'a157:agent', type: 'AGENT_CREATED', data: { agentId: 'a157', principalId: 'operations', controllerId: 'operator', initialControlEpoch: 1 } }, rotatedSigner)];
  const session = (credentialPublicKey) => signControl(withAgent, { id: 'a157:session', type: 'RUNTIME_SESSION_ADMITTED',
    data: { sessionId: 'session:a157', agentId: 'a157', controllerId: 'operator', controlEpoch: 1, credentialKeyId: STRANGER.keyId, credentialScheme: 'ed25519', credentialPublicKey, expiresAt: 10_000_000 } }, rotatedSigner);
  if (replay(engineEvents([...withAgent, await session(STRANGER.credential)])).status !== 'ACCEPTED') throw new Error('A-157: the lowercase session twin must replay');
  replayVector('replay/v2r/rejects-session-public-key-uppercase-hex', 'G6.8 A-157: a RUNTIME_SESSION_ADMITTED (type 8) whose credentialPublicKey is written with A–F, correctly owner-signed (its lowercase twin replays): PublicKey32 is 0x + 64 lowercase hex (r4 §3.3, Appendix C row 8), a C4 grammar, so EVENT_DATA_INVALID at its position; no lowercasing applies (A-157.1).',
    [...withAgent, await session(upper(STRANGER.credential))], reject('EVENT_DATA_INVALID', withAgent.length));
  // Type 26 out of the committed epoch of pre-rotation-v2, revealing the committed key NEXT (owner:2) with its proof.
  const prefix = preRotation.events.slice(0, preRotation.before);
  const reveal = async (credential) => {
    const r = accepted(prefix), head = r.head, domain = r.state.genesis.domain;
    const data = { ownerKeys: [{ ...ok(NEXT), credential }], nextKeyDigests: [core.ownerKeyDigest(NEXT_NEXT)] };
    const signed = plain2(await signer.signControlEvent(ownerSigner, { id: 'a157:rotation', type: 'OWNER_KEYS_ROTATED', timestamp: prefix.at(-1).timestamp, data }, domain, head, 'sha256'));
    const challenge = core.controlAuthorizationHash({ domain, eventId: signed.id, eventType: signed.type, timestamp: signed.timestamp, previousHead: { hash: head.hash, position: head.position }, effectHash: core.controlEffectHash(signed, 'sha256') }, 'sha256');
    return [...prefix, { ...signed, data: { ...signed.data, nextKeyAuthorizations: [{ keyId: NEXT.keyId, scheme: 'ed25519', signature: await nextSigner.signHash(challenge) }] } }];
  };
  if (replay(engineEvents(await reveal(NEXT.credential))).status !== 'ACCEPTED') throw new Error('A-157: the lowercase rotation twin must replay');
  replayVector('replay/v2r/rejects-owner-key-uppercase-hex', 'G6.8 A-157: an OWNER_KEYS_ROTATED (type 26) out of a committed epoch revealing the committed key with A–F (the ownerKeyDigest of the lowercased key matches, the proof is valid, the lowercase twin replays): a non-lowercase PublicKey32 is EVENT_DATA_INVALID at C4, before the §3.3 point test and the digest check.',
    await reveal(upper(NEXT.credential)), reject('EVENT_DATA_INVALID', prefix.length));
}

// A-148.1: §12.1 bit 2 is set iff the §12.2-selected amount slot holds an Amount; type 32 with amountCap null (countCap set)
// clears it and zeroes bytes 84–115. The generator checks the row against its amountCap "0" twin (which sets bit 2).
section('budgets');
{
  const rotatedSigner = signer.signerFromKeyPair(ROTATED);
  const events = rotation.events;
  const budget = (amountCap) => signControl(events, { id: 'a148:budget', type: 'BUDGET_DECLARED', data: { budgetId: 'b-null-cap', subjects: { actorIds: null, roleIds: null, actions: ['spend'], resources: null },
    metric: 'amount', period: { kind: 'NONE' }, amountCap, countCap: 3, perOperationCap: null, notBefore: null, expiresAt: null } }, rotatedSigner);
  const nulled = await budget(null), zero = await budget('0');
  const flags = (event) => { const row = core.projectionRow(event, events.length, `0x${'11'.repeat(32)}`); return [(row[19] & 4) !== 0, row.subarray(84, 116).every((b) => b === 0)].join(); };
  if (flags(nulled) !== 'false,true' || flags(zero) !== 'true,true') throw new Error(`A-148.1: row flags ${flags(nulled)} / ${flags(zero)}`);
  const twin = replay(engineEvents([...events, zero]));
  const result = replayVector('replay/v2r/projection-null-amount-cap-clears-bit2', 'G6.7 A-148.1: a BUDGET_DECLARED (type 32) with amountCap null and countCap 3: bit 2 of its §12.1 projection row is clear and bytes 84–115 are zero (an explicit null at a nullable slot is not an Amount); the projection head is pinned, and differs from the amountCap "0" twin, which sets bit 2.',
    [...events, nulled], ACCEPT);
  if (twin.status !== 'ACCEPTED' || twin.projectionHead === result.projectionHead) throw new Error('A-148.1: the "0" twin must replay with a different projection head');
}

// ---------------------------------------------------------------- session time horizon (A-179.6; MANIFEST revisions 3 and 4)

section('session-time-horizon');
{
  const HZ = 1000, BEA_BINDING = { runtimeSessionId: 'session:bea', credentialKeyId: 'key:bea', controlEpoch: 1 }, CAL_BINDING = { runtimeSessionId: 'session:cal', credentialKeyId: 'key:cal', controlEpoch: 1 };
  const refusal = (prefix, id, actor, binding, pair, at, code = 'ACTION_NOT_ALLOWED') => signRefusal(prefix, id, { refusalId: `r:${id}`, refusalSource: 'CORE', request: { actorId: actor, action: 'delete', resource: 'incident:42', claimedAt: at }, evaluationTime: at, decision: 'DENY', code }, binding, pair);
  const name = (n) => `replay/v2r/session-time-horizon/${n}`;
  // horizon-v2: H = 1000; every owner event at 100 (ownerTime 100); bea's run at 1100 (the bound); a checkpoint at 1500 (ownerTime 1500);
  // bea's run at 2500 (the new bound); a power-reducing fence of cal written at max(now, head) = 2500 (clamped: ownerTime stays 1500).
  const h = scripted('horizon', { sessionTimeHorizonMs: HZ });
  const owner = await createLocalOwner(h.config);
  await owner.createAgent({ id: 'bea' });
  await owner.createAgent({ id: 'cal' });
  await owner.createRole({ id: 'reviewer' });
  await owner.appoint({ agent: 'bea', role: 'reviewer', tenure: 'shift:1', number: 1 });
  await owner.admitRuntime({ session: 'session:bea', agent: 'bea', epoch: 1, key: 'key:bea', credential: BEA.credential, expiresAt: 10_000_000 });
  await owner.admitRuntime({ session: 'session:cal', agent: 'cal', epoch: 1, key: 'key:cal', credential: CAL.credential, expiresAt: 10_000_000 });
  await owner.grant({ id: 'read', to: 'bea', actions: ['read'], resources: ['incident:42'], expiresAt: 10_000_000 });
  const base = h.events();
  const sim = openLocalSimulation(h.session('session:bea', BEA));
  h.clock.t = 100 + HZ;
  if ((await sim.run(op('op:sth:1'))).status !== 'SIMULATION_RESULT') throw new Error('horizon: run at the bound');
  const atBound = h.events().length;
  h.clock.t = 1500;
  await owner.checkpoint();
  const afterCheckpoint = h.events().length;
  h.clock.t = 1500 + HZ;
  if ((await sim.run(op('op:sth:2'))).status !== 'SIMULATION_RESULT') throw new Error('horizon: run at the new bound');
  const afterSecond = h.events().length;
  h.clock.t = 50; // the owner's clock is behind the head: the fence is written at max(now, head) (A-22.3) and does not advance time
  await owner.advanceEpoch({ agent: 'cal', from: 1, to: 2 });
  const events = save('horizon-v2', h.events(), h.historyFile);
  if (events.at(-1).type !== 'CONTROL_EPOCH_ADVANCED' || events.at(-1).timestamp !== events.at(-2).timestamp) throw new Error('horizon: the fence must be clamped to the head');
  replayVector(name('accepts-at-the-bound'), `A-179.3: H = ${HZ}, ownerTime 100: bea's declaration, admission and consumption at 1100 (= ownerTime + H) are accepted.`, { ref: 'horizon-v2', eventCount: atBound }, ACCEPT);
  replayVector(name('accepts-refusal-at-the-bound'), 'A-179.3: a validly signed refusal by bea at exactly ownerTime + H is accepted.', [...base, await refusal(base, 'event:sth:at', 'bea', BEA_BINDING, BEA, 100 + HZ)], ACCEPT);
  replayVector(name('rejects-refusal-past-the-bound'), 'A-179.3: the same refusal one ms past ownerTime + H: TRANSITION_INVALID ("time: a session-signed event may not pass the session time horizon").',
    [...base, await refusal(base, 'event:sth:past', 'bea', BEA_BINDING, BEA, 100 + HZ + 1)], reject('TRANSITION_INVALID', base.length));
  replayVector(name('accepts-past-the-old-bound-after-a-checkpoint'), 'A-179.2: a STATE_CHECKPOINT at 1500 advances time, so ownerTime moves to 1500 and bea\'s run at 2500 is accepted.', { ref: 'horizon-v2', eventCount: afterSecond }, ACCEPT);
  replayVector(name('accepts-clamped-power-reducing-event'), 'A-179.2 / A-22.3: a power-reducing fence written at the head\'s time (the owner\'s clock behind) is accepted and does not move ownerTime.', { ref: 'horizon-v2', eventCount: events.length }, ACCEPT);
  replayVector(name('rejects-past-the-bound-after-a-clamped-fence'), 'A-179.2: after the clamped fence ownerTime is still 1500: bea\'s refusal at 2501 (past 1500 + H) is TRANSITION_INVALID.',
    [...events, await refusal(events, 'event:sth:clamped', 'bea', BEA_BINDING, BEA, 1500 + HZ + 1)], reject('TRANSITION_INVALID', events.length));
  replayVector(name('rejects-fenced-session-past-the-bound'), 'A-179.3 / A-172.1: cal\'s session is fenced; its refusal past the bound is TRANSITION_INVALID (T3, an envelope check, precedes the fence), not SESSION_FENCED.',
    [...events, await refusal(events, 'event:sth:fenced-past', 'cal', CAL_BINDING, CAL, 1500 + HZ + 1)], reject('TRANSITION_INVALID', events.length));
  replayVector(name('rejects-fenced-session-within-the-bound'), 'The same fenced session at the bound: T3 passes and the fence refuses (SESSION_FENCED).',
    [...events, await refusal(events, 'event:sth:fenced-at', 'cal', CAL_BINDING, CAL, 1500 + HZ)], reject('SESSION_FENCED', events.length));
  // An admission past the bound (revision 4, independent review JOB76-04): bea's admission of op:sth:1 moved to 1101 after its declaration
  // (1100) and re-signed there by bea's session, so T3 is its only fault. The same move on a twin history with H = 1001 replays.
  const movedAdmission = async (prefixAndAdmission, at) => {
    const declaration = prefixAndAdmission.findIndex((e) => e.type === 'TRANSACTION_INTENT_DECLARED');
    const admission = clone(prefixAndAdmission[declaration + 1]), prefix = prefixAndAdmission.slice(0, declaration + 1);
    if (admission.type !== 'TRANSACTION_INTENT_ADMITTED') throw new Error('horizon: expected the admission after the declaration');
    const d = admission.data, p = d.authorizationProof;
    const hashAt = (when) => core.hashRuntimeAuthorizationChallenge(core.createRuntimeAuthorizationChallenge({ domain: p.domain, request: { ...p.request, claimedAt: when }, evaluationTime: when,
      policyVersion: p.policyVersion, historyHead: d.expectedHistoryHead, binding: { runtimeSessionId: p.runtimeSessionId, credentialKeyId: p.credentialKeyId, controlEpoch: p.controlEpoch,
        roleId: p.roleId, roleTenureId: p.roleTenureId, intentId: p.intentId, nonce: p.nonce } }), 'sha256');
    if (hashAt(admission.timestamp) !== d.runtimeAuthorizationHash) throw new Error('horizon: the rebuilt challenge must reproduce the written admission\'s hash');
    admission.timestamp = at; d.evaluationTime = at; p.evaluationTime = at; p.request.claimedAt = at;
    d.runtimeAuthorizationHash = hashAt(at); d.runtimeSignature = await signHashWith(BEA)(d.runtimeAuthorizationHash);
    return [...prefix, admission];
  };
  const declaration = events.findIndex((e) => e.type === 'TRANSACTION_INTENT_DECLARED');
  const twin = scripted('horizon-twin', { sessionTimeHorizonMs: HZ + 1 });
  {
    const twinOwner = await createLocalOwner(twin.config);
    await twinOwner.createAgent({ id: 'bea' });
    await twinOwner.createRole({ id: 'reviewer' });
    await twinOwner.appoint({ agent: 'bea', role: 'reviewer', tenure: 'shift:1', number: 1 });
    await twinOwner.admitRuntime({ session: 'session:bea', agent: 'bea', epoch: 1, key: 'key:bea', credential: BEA.credential, expiresAt: 10_000_000 });
    await twinOwner.grant({ id: 'read', to: 'bea', actions: ['read'], resources: ['incident:42'], expiresAt: 10_000_000 });
    twin.clock.t = 100 + HZ;
    if ((await openLocalSimulation(twin.session('session:bea', BEA)).run(op('op:sth:1'))).status !== 'SIMULATION_RESULT') throw new Error('horizon: twin run');
    const twinEvents = twin.events(), twinDeclaration = twinEvents.findIndex((e) => e.type === 'TRANSACTION_INTENT_DECLARED');
    accepted(await movedAdmission(twinEvents.slice(0, twinDeclaration + 2), 100 + HZ + 1)); // throws unless the moved, re-signed admission replays under H = 1001
  }
  replayVector(name('rejects-admission-past-the-bound'), 'A-179.3: an admission (◇) one ms past ownerTime + H, re-signed by bea\'s session at that time so that T3 is its only fault: TRANSITION_INVALID, decided before the admission\'s own checks.',
    await movedAdmission(events.slice(0, declaration + 2), 100 + HZ + 1), reject('TRANSITION_INVALID', declaration + 1));
  // Values near 2^53 − 1: H = 1 with ownerTime 2^53 − 6 (revision 4, independent review JOB76-01: revision 3 set the clock to 2^53 − 5).
  const MAX = Number.MAX_SAFE_INTEGER;
  const m = scripted('horizon-max', { sessionTimeHorizonMs: 1 });
  m.clock.t = MAX - 6;
  const mOwner = await createLocalOwner(m.config);
  await mOwner.createAgent({ id: 'bea' });
  await mOwner.admitRuntime({ session: 'session:bea', agent: 'bea', epoch: 1, key: 'key:bea', credential: BEA.credential, expiresAt: MAX });
  const near = save('horizon-max-v2', m.events(), m.historyFile);
  replayVector(name('accepts-near-max-at-the-bound'), 'A-179.3 near 2^53 − 1: H = 1, ownerTime 2^53 − 6; a refusal at 2^53 − 5 (difference 1) is accepted.', [...near, await refusal(near, 'event:sth:max-at', 'bea', BEA_BINDING, BEA, MAX - 5, 'NO_AUTHORITY')], ACCEPT);
  replayVector(name('rejects-near-max-past-the-bound'), 'A-179.3 near 2^53 − 1: the same refusal at 2^53 − 2 (difference 4 > 1): TRANSITION_INVALID; the difference is exact for U53.', [...near, await refusal(near, 'event:sth:max-past', 'bea', BEA_BINDING, BEA, MAX - 2, 'NO_AUTHORITY')], reject('TRANSITION_INVALID', near.length));
  // Revision 4 (a): the difference form at the top of U53, H = 10 with ownerTime 2^53 − 6.
  const o = scripted('horizon-overflow', { sessionTimeHorizonMs: 10 });
  o.clock.t = MAX - 6;
  const oOwner = await createLocalOwner(o.config);
  await oOwner.createAgent({ id: 'bea' });
  await oOwner.admitRuntime({ session: 'session:bea', agent: 'bea', epoch: 1, key: 'key:bea', credential: BEA.credential, expiresAt: MAX });
  const over = save('horizon-overflow-v2', o.events(), o.historyFile);
  replayVector(name('accepts-near-max-when-ownertime-plus-h-exceeds-max'), 'A-179.3, r5.2 rule T3: "e.timestamp − ownerTime(p−1) ≤ sessionTimeHorizonMs (a difference…)". H = 10, ownerTime 2^53 − 6; a refusal at 2^53 − 1 (difference 5 ≤ 10) is accepted, although the sum ownerTime + H = 2^53 + 4 is past 2^53 − 1. An implementation that computes that sum and wraps it would refuse this event.',
    [...over, await refusal(over, 'event:sth:overflow', 'bea', BEA_BINDING, BEA, MAX - 1, 'NO_AUTHORITY')], ACCEPT);
  // Migrated histories (A-179.1 migrate option): the prefix is exempt (¬inPrefix); the first post-prefix event is subject.
  const f1 = await migrateTwin('migrated-horizon-format1-v2', null, { copyFrom: join(ROOT, 'conformance/v1/histories/handover-v1.jsonl'), acceptUnpinnedSource: true, sessionTimeHorizonMs: 1 });
  replayVector(name('accepts-migrated-prefix-exempt'), 'A-179.3: the format-1 handover-v1 history migrated with H = 1: its transcribed prefix has session events 2 and 3 ms past ownerTime (positions 15, 16), exempt as prefix events; the history replays.', { ref: 'migrated-horizon-format1-v2', eventCount: f1.events.length }, ACCEPT);
  const lg = await migrateTwin('migrated-horizon-legacy-v2', LEGACY_FIXTURE, { sessionTimeHorizonMs: 1 });
  const lgEvents = lg.events, lgAt = lgEvents.at(-1).timestamp + 2;
  const connectorRefusal = await signRefusal(lgEvents, 'event:sth:post-prefix', { refusalId: 'r:sth:post-prefix', refusalSource: 'CONNECTOR', request: { actorId: 'a:first-look', action: 'pay', resource: 'vendor', claimedAt: lgAt }, evaluationTime: lgAt,
    decision: 'DENY', code: 'CONNECTOR_REFUSED', connector: { connectorId: 'b:first-look', refusalCode: 'UPSTREAM', detailDigest: `0x${'00'.repeat(32)}` } }, { runtimeSessionId: 'session:first-look:b', credentialKeyId: 'key:first-look:b', controlEpoch: 1 }, FIXTURE_KEY);
  replayVector(name('rejects-first-post-prefix-event-past-the-bound'), 'A-179.3: the legacy handover fixture migrated with H = 1 (ownerTime 24 at the prefix end, 25): the first post-prefix event, a refusal at 27, is subject to T3: TRANSITION_INVALID.',
    [...lgEvents, connectorRefusal], reject('TRANSITION_INVALID', lgEvents.length));
}

// ================================================================ outputs

vectors.sort((a, b) => TOPICS.indexOf(a.topic) - TOPICS.indexOf(b.topic)); // stable: emission order within a topic
const ids = new Set();
for (const v of vectors) { if (ids.has(v.id)) throw new Error(`duplicate vector id ${v.id}`); ids.add(v.id); }
for (const v of vectors) if (v.kind === 'replay' && !Object.hasOwn(v.expect, 'code')) throw new Error(`${v.id}: a replay vector must pin its code`);

const sha256 = (text) => createHash('sha256').update(text).digest('hex');
/**
 * The positions this suite pins per history (RESULTS/PINNED-ROOTS.json, G2.5): the head of every history, every prefix an
 * accepted replay vector replays, and every STATE_CHECKPOINT p with p − 1 (its data.stateRoot is rootAt(p − 1)).
 */
const pinned = Object.fromEntries(Object.keys(histories).filter((name) => isFormat2(histories[name])).map((name) => [name, new Set([histories[name].length - 1])]));
for (const v of vectors) if (v.kind === 'replay' && v.history !== undefined && v.expect.status === 'ACCEPTED' && v.input.testCapacityLimits === undefined) pinned[v.history.ref]?.add(v.history.eventCount - 1);
for (const [name, events] of Object.entries(histories)) events.forEach((e, p) => { if (e.type === 'STATE_CHECKPOINT' && pinned[name]) { pinned[name].add(p); pinned[name].add(p - 1); } });
const summary = (events) => { const r = accepted(events); return { eventCount: events.length, head: plainMarked(r.head), stateRoot: r.stateRoot ?? null, recordCount: r.state.stateRecords?.size ?? null, projectionHead: r.projectionHead ?? null }; };

outputs.set('vectors.json', `${JSON.stringify(vectors, null, 1)}\n`);
outputs.set('glossary.json', `${JSON.stringify({ note: 'A-70.1: genesisEventHash = eventHash(e₀) is an event hash; historyId and genesisHash are two names for the record-chain hash recordHash(0). Never substitute genesisEventHash for either. History: rich-v2.', history: 'rich-v2', ...glossary, genesisHash: glossary.historyId, equal: false }, null, 1)}\n`);
const KINDS = ['replay', 'authorization', 'survives', 'attestation', 'headroom', 'export', 'duty-view', 'export-verify', 'writer-open', 'authority-evaluation'];
const countOf = (list) => ({ ...Object.fromEntries(KINDS.map((kind) => [kind, list.filter((v) => v.kind === kind).length])), total: list.length });
const manifest = {
  schemaVersion: 'irontrellis-conformance/2', suite: 'v2-regenerated', protocol: 'irontrellis', format: 'irontrellis-event/2', challengeProfile: 'g3', engineDerived: true,
  // A-184.2: revision 2 ("marker path form, A-184") regenerates the two writer-open vectors whose migration marker named a
  // builder-host absolute path; their markers now carry the relative target (A-184.1). Every outcome, root and head is unchanged.
  // A-184.2 / A-179.6: revision 3 adds the session-time-horizon group (new histories and vectors only; nothing earlier changes).
  // Revision 4 (r5.2 P.8, the group is builder-pinned; coordinator GO 2026-10-22T20:56:45Z): the near-max clock at 2^53 − 6, the moved
  // admission re-signed, and one added vector; histories horizon-max-v2 changed, horizon-overflow-v2 added; nothing outside the group changes.
  revision: { number: 4, label: 'session time horizon near 2^53 − 1, independent review JOB76-01 and JOB76-04', previousManifestSha256: '740d6e04792ce2ad33501c1c5468cf40c79760e0ac23e476476b413562fc9f1e',
    changedVectors: ['replay/v2r/session-time-horizon/rejects-admission-past-the-bound', 'replay/v2r/session-time-horizon/accepts-near-max-at-the-bound', 'replay/v2r/session-time-horizon/rejects-near-max-past-the-bound'],
    addedVectors: ['replay/v2r/session-time-horizon/accepts-near-max-when-ownertime-plus-h-exceeds-max'],
    changedHistories: ['horizon-max-v2'], addedHistories: ['horizon-overflow-v2'],
    previous: [{ number: 3, label: 'session time horizon, A-179.6', previousManifestSha256: '9c4ff45981012d9da901e1aa90f5549cfaa5ca75dd5b6a864a082901b129d52a',
      addedVectors: vectors.filter((v) => v.topic === 'session-time-horizon' && v.id !== 'replay/v2r/session-time-horizon/accepts-near-max-when-ownertime-plus-h-exceeds-max').map((v) => v.id) },
    { number: 2, label: 'marker path form, A-184', previousManifestSha256: 'f62421660228d44090a1bba8f05b39ce9ab1853b4935acd235d32ca6a9d2f132',
      changedVectors: ['writer-open/v2r/fenced-legacy-source-is-read-only', 'writer-open/v2r/fenced-format1-source-is-read-only'] }] },
  generatedFrom: { reference: '@ramex-labs/irontrellis (packages/core)', authorization: core.AUTHORIZATION_VERSION, replay: core.REPLAY_VERSION, query: core.QUERY_VERSION },
  note: 'ENGINE-DERIVED format-2 vectors (BUILD §5): the expectations are this engine\'s answers, projected as conformance/adapters/node.mjs answers; not a SPEC oracle. G2.5 cross-checks the pinned roots independently. Signed under the session-challenge profile g3 (A-54 founder-approved 2026-10-11, A-59). `node conformance/v2-regenerated/generate.mjs --check` reproduces these files byte for byte.',
  domain: DOMAIN,
  keys: { ...KEYS, 'owner:1 (migration twins)': { scheme: 'ed25519', seed: MIGRATION_OWNER_SEED, note: 'the owner key of every migration target (packages/core/test/format2-migrate.test.mjs)' }, 'key (reference fixture)': { scheme: FIXTURE_KEY.scheme, seed: `0x${'11'.repeat(32)}`, credential: FIXTURE_KEY.credential } },
  migrationId: MIGRATION_ID,
  topics: TOPICS,
  histories: Object.fromEntries(Object.entries(histories).map(([name, events]) => [name, { ...summary(events), sha256: sha256(outputs.get(`histories/${name}.json`)) }])),
  pinnedPositions: Object.fromEntries(Object.entries(pinned).map(([name, set]) => [name, [...set].sort((a, b) => a - b)])),
  counts: { ...countOf(vectors), byTopic: Object.fromEntries(TOPICS.map((name) => [name, countOf(vectors.filter((v) => v.topic === name))])) },
  vectors: vectors.map((v) => ({ id: v.id, kind: v.kind, topic: v.topic, purpose: v.purpose, sha256: sha256(JSON.stringify(v)) })),
};
outputs.set('MANIFEST.json', `${JSON.stringify(manifest, null, 1)}\n`);

// ---------------------------------------------------------------- write, or compare with --check

rmSync(WORK, { recursive: true, force: true });
const produced = new Set([...outputs.keys()].filter((path) => path.startsWith('histories/')).map((path) => path.slice('histories/'.length)));
const stale = existsSync(HISTORIES) ? readdirSync(HISTORIES).filter((file) => !produced.has(file)) : [];
if (CHECK) {
  const differ = [...outputs].filter(([path, text]) => { const file = join(HERE, path); return !existsSync(file) || readFileSync(file, 'utf8') !== text; }).map(([path]) => `conformance/v2-regenerated/${path}`);
  differ.push(...stale.map((file) => `conformance/v2-regenerated/histories/${file} (not generated)`));
  if (differ.length > 0) { console.error(`a fresh generation differs:\n  ${differ.join('\n  ')}`); process.exit(1); }
  console.log(`conformance/v2-regenerated is up to date (${vectors.length} vectors over ${Object.keys(histories).length} histories)`);
} else {
  mkdirSync(HISTORIES, { recursive: true });
  for (const file of stale) rmSync(join(HISTORIES, file));
  for (const [path, text] of outputs) writeFileSync(join(HERE, path), text);
  const c = manifest.counts;
  console.log(`wrote ${c.total} vectors (${KINDS.map((k) => `${c[k]} ${k}`).join(', ')}) over ${Object.keys(histories).length} histories`);
}
