/**
 * Legacy → format 2 migration (SPEC §16.2; retargeted from the rc.1 legacy → format 1 tests, same parity rule).
 *
 * Comparison rule. Source S = s_0..s_n (legacy genesis s_0); target T = t_0..t_n
 * where t_0 is the migration genesis and t_k re-records s_k (k ≥ 1) verbatim
 * except for `controlAuthorization` on control events and `credentialScheme`
 * on sessions. Positions therefore align (t_k ↔ s_k) and every event id is
 * unchanged. The engine's answers on T equal its answers on S after dropping
 * the fields that name the *history itself* rather than the decision:
 * hashes (`hash`, `historyHash`, algorithm-dependent), the domain (trellis vs
 * legacy shape), the genesis policy/version literals (`versions`), and the migration-only
 * `controlAuthorization` / `credentialScheme` data. Everything else —
 * decisions, codes, paths, constraints, evidence positions and event ids,
 * usage, duties, attributions, survives projections, ALLOW proofs — must be
 * deep-equal, with one deliberate exception: DENY / INDETERMINATE evidence.
 * A format-1 state cites only the events relevant to the refused request
 * where a legacy state cites every authority event, so for those results
 * the decision, code, scopeAssurance and each failure's code, subject,
 * root/terminal/failing authority and authority path must be equal, and each
 * failure's migrated evidence must be a subset of the source's (by event id)
 * that still cites the failing authority's grant event and the head
 * (`assertDecisionParity`, test/decision-parity.mjs).
 */
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

const { migrateHistory } = await import("../src/migrate.ts");
const { createLocalDomain, createLocalOwner, openLocalOwner, verifyHistory } = await import("../src/owner.ts");
const { createHistoryStore: createHistoryStoreStrict, openHistoryStore: openHistoryStoreStrict } = await import("../src/store.ts");
// Fixture writes to legacy and format-1 files (SPEC §16.1: those formats open read only by default; format 2 is the wire). These tests cover the earlier store writer, so the fence is off here.
const createHistoryStore = (path, events, options = {}) => createHistoryStoreStrict(path, events, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true, ...options });
const openHistoryStore = (path, options = {}) => openHistoryStoreStrict(path, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true, ...options });
const { authorizeState, ROOT_RECOGNITION_POLICY } = await import("../src/authority.ts");
const { whyState, responsibleState, survivesState, publicQueryDisclosure } = await import("../src/queries.ts");
const { LEGACY_FORMAT, TRELLIS_FORMAT, TRELLIS2_FORMAT } = await import("../src/events.ts");
const { IronTrellisError } = await import("../src/input.ts");
const { invertTranscription } = await import("../src/transcription.ts");

import { fixturesRoot as FIXTURES } from "./reference.mjs";
import { assertDecisionParity } from "./decision-parity.mjs";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling
const revive = (_k, v) => (v !== null && typeof v === "object" && typeof v["$continuity.bigint"] === "string" ? BigInt(v["$continuity.bigint"]) : v);
const load = (name) => JSON.parse(readFileSync(`${FIXTURES}${name}`, "utf8"), revive);
// BUILD §4's comparison projection: the history-naming fields, the format-2-only fields (`budgetId`, `stateRoot`, `projectionHead`, the migration-only
// `sourceControlAuthorization` / `declarationAuthorization`), Amount markers ↔ strings normalised to strings.
const DROPPED = new Set(["hash", "historyHash", "domain", "authorizationDomain", "policyVersion", "proofVersion", "version", "operationVersion", "controlAuthorization", "credentialScheme", "eventHistoryHash", "versions",
  "sourceControlAuthorization", "declarationAuthorization", "declarationDigest", "budgetId", "stateRoot", "projectionHead", "metric"]);
const strip = (value) => {
  if (Array.isArray(value)) return value.map(strip);
  if (value !== null && typeof value === "object") {
    const out = {};
    for (const [key, item] of Object.entries(value)) if (!DROPPED.has(key)) out[key] = strip(item);
    return out;
  }
  return typeof value === "bigint" ? value.toString() : value;
};

/** Every (actor, action, resource) the history's grants mention, plus a stranger, at the head time and far later. */
function questions(state) {
  const actors = [...state.agents.keys(), "stranger"], pairs = new Map();
  for (const { grant } of state.authorities.values()) for (const action of grant.constraints.actions) for (const resource of grant.constraints.resources) pairs.set(`${action}\0${resource}`, { action, resource });
  const out = [];
  for (const actor of actors) for (const { action, resource } of pairs.values()) out.push({ actorId: actor, action, resource });
  return out;
}
function answersOf(state, at) {
  const genesis = state.genesis, requests = questions(state).map((q) => ({ ...q, claimedAt: at }));
  const disclosure = (kind) => publicQueryDisclosure(kind), query = { authorizationDomain: genesis.domain, evaluationTime: at };
  return {
    authorize: requests.map((request) => authorizeState(state, { expectedHistoryHead: state.head, domain: genesis.domain, policyVersion: genesis.policyVersion, rootRecognitionPolicy: ROOT_RECOGNITION_POLICY, request, evaluationTime: at, consequential: false })),
    why: requests.map((request) => whyState(state, state, { ...query, request, disclosure: disclosure("WHY") })),
    responsible: requests.map((request) => responsibleState(state, state, { ...query, request, disclosure: disclosure("RESPONSIBLE") })),
    survives: [...state.agents.keys(), "stranger"].map((targetAgentId) => survivesState(state, { targetAgentId, evaluationTime: at, disclosure: disclosure("SURVIVES") })),
  };
}
const T_path = (p) => openHistoryStoreStrict(p).path;
/** A fresh copy of a source history (file + pin): a migrated source is fenced, so each further migration case needs its own copy (SPEC §16.2 step 6). */
const freshCopy = (source, name) => {
  const copy = join(dirname(source), `${name}.jsonl`);
  writeFileSync(copy, readFileSync(source));
  if (existsSync(`${source}.head`)) writeFileSync(`${copy}.head`, readFileSync(`${source}.head`));
  return copy;
};
/** Migrate a legacy file and assert the SPEC §16.2 shape plus decision parity at several times. */
async function migrateAndCompare(t, source, dir) {
  const target = join(dir, "migrated.jsonl");
  const before = readFileSync(source);
  const result = await migrateHistory({ source, target, now: () => 5000 });
  assert.deepEqual(readFileSync(source), before, "the source is left untouched");
  const S = openHistoryStore(source).state(), T = openHistoryStore(target).state();
  assert.equal(S.format, LEGACY_FORMAT);
  assert.equal(T.format, TRELLIS2_FORMAT);
  assert.equal(result.phase, "FENCED");
  assert.deepEqual(result.sourceHead, S.head);
  assert.deepEqual(result.targetHead, T.head);
  assert.equal(result.eventCount, S.events.length);
  assert.equal(T.events.length, S.events.length);
  assert.deepEqual(T.genesis.migratedFrom, { format: LEGACY_FORMAT, historyHash: S.head.hash, position: S.head.position, recordHash: JSON.parse(readFileSync(source, "utf8").trim().split("\n").at(-1)).recordHash,
    genesis: S.genesis, genesisEventId: S.events[0].id, genesisTimestamp: S.events[0].timestamp, versions: S.genesis.versions,
    // A-40.2–3: a legacy source has no source attestation; the migration id is the plan's random value.
    sourceAttestation: null, migrationId: T.genesis.migratedFrom.migrationId });
  assert.match(T.genesis.migratedFrom.migrationId, /^0x[0-9a-f]{64}$/);
  assert.deepEqual(T.shadowHashes, S.eventHistoryHashes, "the legacy shadow reproduces the source prefix hashes");
  assert.notDeepEqual(T.eventHistoryHashes, S.eventHistoryHashes);
  assert.equal(T.genesis.versions.signatureScheme, S.signatureScheme);
  assert.deepEqual(T.genesis.domain, { protocol: "irontrellis", version: "2", deploymentId: S.genesis.domain.deploymentId });
  // The fence: the source opens read only with the target named; its bytes are untouched (asserted above by content).
  const fenced = openHistoryStoreStrict(source);
  assert.equal(fenced.readOnlyReason(), "MIGRATED");
  assert.throws(() => fenced.append({ id: "x", type: "PRINCIPAL_CREATED", timestamp: 1, data: { principalId: "x" } }), (e) => e.code === "FORMAT_READ_ONLY" && e.detail.reason === "MIGRATED" && e.detail.target === T_path(target));
  fenced.close();
  assert.equal(T.genesis.globalPolicySourceId, S.genesis.globalPolicySourceId);
  assert.equal(T.genesis.canonicalLineageId, S.genesis.canonicalLineageId);
  assert.equal(T.events[0].id, S.events[0].id);
  assert.equal(T.events[0].timestamp, S.events[0].timestamp);
  for (let k = 1; k < S.events.length; k += 1) {
    const s = S.events[k], m = T.events[k];
    assert.equal(m.id, s.id); assert.equal(m.type, s.type); assert.equal(m.timestamp, s.timestamp);
    // SPEC §16.2 step 3: the inversion of the transcription is the source event (markers restored, additions dropped).
    assert.deepEqual(invertTranscription(m, LEGACY_FORMAT).data, s.data, `event ${k} is re-recorded verbatim up to the transcription`);
    assert.equal(m.data.controlAuthorization !== undefined, ["PRINCIPAL_CREATED", "AGENT_CREATED", "ROLE_CREATED", "SUCCESSION_RULE_DECLARED", "AGENT_APPOINTED", "AGENT_UNAPPOINTED", "ROLE_TRANSFERRED", "RUNTIME_SESSION_ADMITTED", "CONTROL_EPOCH_ADVANCED", "AUTHORITY_GRANTED", "AUTHORITY_REVOKED", "AGENT_TERMINATED"].includes(s.type));
    assert.equal(m.data.sourceControlAuthorization, undefined, "legacy control events had no authorization to keep");
    if (s.type === "RUNTIME_SESSION_ADMITTED") assert.equal(m.data.credentialScheme, S.signatureScheme);
    if (s.type === "TRANSACTION_INTENT_DECLARED") assert.equal(m.data.declarationAuthorization, null);
  }
  assert.deepEqual([...T.agents.keys()], [...S.agents.keys()]);
  assert.deepEqual([...T.authorities.keys()], [...S.authorities.keys()]);
  for (const at of [S.head.canonicalTime, S.head.canonicalTime + 1, S.head.canonicalTime + 100_000]) {
    const expected = answersOf(S, at), actual = answersOf(T, at);
    for (const kind of ["authorize", "why", "responsible", "survives"]) assertDecisionParity(actual[kind], expected[kind], { strip, state: T, message: `${kind} at ${at}` });
  }
  const verification = verifyHistory(target);
  assert.equal(verification.controlSignatures, "VERIFIED");
  assert.equal(verification.chain, "OK");
  return { S, T, target };
}

test("mandate fixture: a control-only legacy history migrates verbatim and answers identically", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-migrate-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const source = join(dir, "mandate.jsonl");
  createHistoryStore(source, load("mandate-history.json"));
  const { T } = await migrateAndCompare(t, source, dir);
  assert.equal(T.events.length, 7);
  // A re-run with the same plan verifies the outputs and reports the same result (SPEC §16.2 step 7); another target is refused (the source is fenced).
  const again = await migrateHistory({ source, target: join(dir, "migrated.jsonl"), now: () => 1 });
  assert.equal(again.phase, "FENCED");
  assert.deepEqual(again.targetHead, T.head);
  await assert.rejects(migrateHistory({ source, target: join(dir, "other.jsonl"), now: () => 1 }), (e) => e.code === "MIGRATION_UNSUPPORTED" && e.detail.reason === "SOURCE_FENCED");
  // A target file that exists without a plan is never adopted.
  writeFileSync(join(dir, "stray.jsonl"), "");
  await assert.rejects(migrateHistory({ source: freshCopy(source, "mandate-2"), target: join(dir, "stray.jsonl"), now: () => 1 }), (e) => e.code === "HISTORY_EXISTS");
});

test("A-184.1: the marker names its target relative to the source's directory; paths reached through a symlinked directory compare after canonicalising", async (t) => {
  const { mkdirSync, realpathSync, symlinkSync } = await import("node:fs");
  const { migrationStatus } = await import("../src/migrate.ts");
  const { readMigratedMarker } = await import("../src/store.ts");
  const root = mkdtempSync(join(tmpdir(), "irontrellis-migrate-link-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const real = join(root, "real"), link = join(root, "link");
  mkdirSync(join(real, "out"), { recursive: true });
  symlinkSync(real, link, "dir");
  createHistoryStore(join(real, "mandate.jsonl"), load("mandate-history.json"));
  // Migrate through the symlink; the marker is written beside the source with the relative form.
  const result = await migrateHistory({ source: join(link, "mandate.jsonl"), target: join(link, "out", "mandate-2.jsonl"), now: () => 5000 });
  assert.equal(result.phase, "FENCED");
  assert.equal(readMigratedMarker(join(real, "mandate.jsonl")).target, "out/mandate-2.jsonl");
  // The fenced source names the canonical target, whichever path opens it.
  for (const source of [join(real, "mandate.jsonl"), join(link, "mandate.jsonl")]) {
    const fenced = openHistoryStoreStrict(source);
    assert.throws(() => fenced.append({ id: "x", type: "PRINCIPAL_CREATED", timestamp: 1, data: { principalId: "x" } }),
      (e) => e.code === "FORMAT_READ_ONLY" && e.detail.reason === "MIGRATED" && e.detail.target === realpathSync(join(real, "out", "mandate-2.jsonl")));
    fenced.close();
  }
  // A re-run naming the target by the other path is the same target (not SOURCE_FENCED); another target still is.
  const again = await migrateHistory({ source: join(real, "mandate.jsonl"), target: join(real, "out", "mandate-2.jsonl"), now: () => 1 });
  assert.equal(again.phase, "FENCED");
  await assert.rejects(migrateHistory({ source: join(link, "mandate.jsonl"), target: join(link, "out", "other.jsonl"), now: () => 1 }), (e) => e.code === "MIGRATION_UNSUPPORTED" && e.detail.reason === "SOURCE_FENCED");
  const status = migrationStatus(result.plan);
  assert.equal(status.phase, "FENCED");
  assert.deepEqual(status.problems, []);
  // A reader accepts the absolute form too (a marker an older writer made).
  const marker = readMigratedMarker(join(real, "mandate.jsonl"));
  writeFileSync(join(real, "mandate.jsonl.migrated"), `${JSON.stringify({ ...marker, target: join(link, "out", "mandate-2.jsonl") })}\n`);
  assert.deepEqual(migrationStatus(result.plan).problems, []);
});

test("SDK legacy history: agents, roles, grants, delegations, prohibitions, revocations, sessions, succession and termination migrate; the target is a working owner history", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-migrate-sdk-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const { generateKeyPair } = await import("../src/crypto/suites.ts");
  let tick = 100;
  const domain = createLocalDomain({ format: LEGACY_FORMAT, [FORMAT1_TEST_TOOLING]: true });
  const config = { historyFile: join(dir, "legacy.jsonl"), domain, owner: "operations", controller: "operator", now: () => tick, format: LEGACY_FORMAT, [FORMAT1_TEST_TOOLING]: true };
  const c = await createLocalOwner(config);
  for (const id of ["a", "b", "c"]) await c.createAgent({ id });
  await c.createRole({ id: "reviewer" });
  await c.declareSuccession({ id: "handover", from: "a", to: "b", role: "reviewer" });
  await c.appoint({ agent: "a", role: "reviewer", tenure: "shift:1", number: 1, succession: "handover" });
  await c.admitRuntime({ session: "s:a", agent: "a", epoch: 1, key: "k:a", address: generateKeyPair("eip191-personal-sign-keccak256", "x").credential, expiresAt: 1000 });
  tick = 101;
  await c.grant({ id: "collect", to: "a", actions: ["read", "OBLIGATE"], resources: ["incident:42", "incident:41"], expiresAt: 900, notBefore: 50, delegable: 1 });
  await c.delegate({ id: "sub", to: "c", from: "a", parent: "collect", actions: ["read"], resources: ["incident:42"], expiresAt: 800, notBefore: 50 });
  await c.grant({ id: "quant", to: "a", actions: ["pay"], resources: ["vendor"], expiresAt: 900, maxAmount: 2500n, maxCumulativeAmount: 5000n, maxTransactions: 3 });
  await c.prohibit({ id: "no-c", actions: ["read"], resources: ["incident:42"], subject: "c", root: "collect", expiresAt: 700, notBefore: 50 });
  await c.prohibit({ id: "freeze", actions: ["pay"], resources: ["vendor"], global: true, notBefore: 600 });
  await c.grant({ id: "b-read", to: "b", actions: ["read"], resources: ["incident:42"], expiresAt: 900 });
  tick = 102;
  await c.revoke("b-read");
  await c.advanceEpoch({ agent: "a", from: 1, to: 2 });
  tick = 103;
  await c.succeed({ id: "h1", rule: "handover", fromAgent: "a", fromTenure: "shift:1", toAgent: "b", toTenure: "shift:2", role: "reviewer", number: 2 });
  await c.unappoint({ agent: "b", role: "reviewer", tenure: "shift:2" });
  const { T, target } = await migrateAndCompare(t, config.historyFile, dir);
  assert.equal(T.genesis.policyVersion, "irontrellis-local-owner/2");
  // The migrated history is an owner history: same owner, a format-2 domain with the same deployment name, the migration's key file.
  const migrated = openLocalOwner({ historyFile: target, domain: { protocol: "irontrellis", version: "2", deploymentId: domain.deploymentId }, owner: "operations", controller: "operator", now: () => 5000 });
  assert.equal(migrated.format, TRELLIS2_FORMAT);
  assert.equal(migrated.authorize({ actor: "a", action: "read", resource: "incident:42" }).decision, "DENY");
  assert.equal(migrated.authorize({ actor: "a", action: "read", resource: "incident:42" }).evidence.code, "AGENT_INACTIVE");
  assert.equal(migrated.authorize({ actor: "c", action: "read", resource: "incident:42" }, { at: 200 }).evidence.code, "PROHIBITED");
  assert.equal(migrated.authorize({ actor: "c", action: "read", resource: "incident:42" }, { at: 750 }).decision, c.authorize({ actor: "c", action: "read", resource: "incident:42" }, { at: 750 }).decision);
  await migrated.createAgent({ id: "d" });
  await migrated.grant({ id: "d-read", to: "d", actions: ["read"], resources: ["incident:42"], expiresAt: 9000 });
  assert.equal(migrated.authorize({ actor: "d", action: "read", resource: "incident:42" }).decision, "ALLOW");
  assert.equal(migrated.capacity().maxEvents, null);
  assert.equal(migrated.verify().controlSignatures, "VERIFIED");
  assert.equal(migrated.handover("a").terminated, true);
  assert.throws(() => openLocalOwner({ ...config, historyFile: target }), (e) => e.code === "PROFILE_MISMATCH");
});

for (const fixture of ["handover-history.json", "handover-denied-history.json", "mandate-history.json"]) {
  test(`${fixture}: runtime-signed lifecycle events re-record verbatim against the legacy shadow`, async (t) => {
    const dir = mkdtempSync(join(tmpdir(), "irontrellis-migrate-lifecycle-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const source = join(dir, "source.jsonl");
    createHistoryStore(source, load(fixture));
    const { S, T } = await migrateAndCompare(t, source, dir);
    for (const name of ["intentAdmissions", "intentConsumptions", "receiptCommitments", "obligations", "intentOutcomeStates", "runtimeSessions", "tenures", "authorities", "agents"]) {
      assert.deepEqual([...T[name].keys()], [...S[name].keys()], name);
      assert.deepEqual(strip([...T[name].values()]), strip([...S[name].values()]), name);
    }
    for (const [intentId, admission] of S.intentAdmissions) assert.deepEqual(T.intentAdmissions.get(intentId).admissionHead, admission.admissionHead, "recorded heads are the legacy heads");
    for (const [id, receipt] of S.receiptCommitments) assert.deepEqual(T.receiptCommitments.get(id).head, receipt.head);
  });
}

test("the jsonl fixture migrates up to its first runtime-signed event: a control-only prefix is a faithful migration", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-migrate-prefix-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const events = openHistoryStore(`${FIXTURES}handover-history.jsonl`).readAll();
  const cut = events.findIndex((e) => e.type === "TRANSACTION_INTENT_ADMITTED");
  const source = join(dir, "prefix.jsonl");
  createHistoryStore(source, events.slice(0, cut));
  const { T } = await migrateAndCompare(t, source, dir);
  assert.equal(T.events.length, cut);
  assert.equal(T.genesis.policyVersion, "irontrellis-local-owner/2"); // A-52.4: always rewritten, also for a non-SDK source literal (E3 carried it verbatim)
  assert.notEqual(events[0].data.policyVersion, "irontrellis-local-owner/2");
});

test("a format-2 source or a missing source is refused", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-migrate-bad-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const trellis = await createLocalOwner({ historyFile: join(dir, "t.jsonl"), domain: createLocalDomain(), owner: "o", controller: "c", now: () => 1 });
  await trellis.createAgent({ id: "a" });
  await assert.rejects(migrateHistory({ source: join(dir, "t.jsonl"), target: join(dir, "x.jsonl"), now: () => 1 }), (e) => e.code === "MIGRATION_UNSUPPORTED" && e.detail.reason === "SOURCE_FORMAT_2");
  await assert.rejects(migrateHistory({ source: join(dir, "missing.jsonl"), target: join(dir, "y.jsonl"), now: () => 1 }), (e) => e.code === "READ_UNAVAILABLE");
  assert.equal(existsSync(join(dir, "x.jsonl")), false);
});

test("L5: a legacy source without a matching pin is refused unless the caller opts in; an existing target key is refused", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-migrate-pin-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const { referenceCore02 } = await import("./reference.mjs");
  const { PortableFileEventStore } = await referenceCore02("indexer/portable-file-event-store.ts");
  const history = load("handover-history.json");
  const refused = (reason) => (e) => e.code === "MIGRATION_UNSUPPORTED" && e.detail?.reason === reason;
  // Written by the reference (Continuity) store: no pin, as with most existing legacy histories.
  const unpinned = join(dir, "continuity.jsonl");
  new PortableFileEventStore(unpinned).appendAll(history);
  await assert.rejects(migrateHistory({ source: unpinned, target: join(dir, "a.jsonl"), now: () => 5000 }), (e) => refused("SOURCE_UNPINNED")(e) && /acceptUnpinnedSource/.test(e.message));
  assert.equal(existsSync(join(dir, "a.jsonl")), false);
  assert.equal(existsSync(join(dir, "a.jsonl.owner-key.json")), false, "a refused migration leaves no key file behind");
  // The review's case: a truncated copy (`head -5`), which drops later events, is not laundered into a signed history.
  const truncated = join(dir, "truncated.jsonl");
  writeFileSync(truncated, `${readFileSync(unpinned, "utf8").split("\n").slice(0, 5).join("\n")}\n`);
  await assert.rejects(migrateHistory({ source: truncated, target: join(dir, "b.jsonl"), now: () => 5000 }), refused("SOURCE_UNPINNED"));
  // Pinned but behind the file (another writer appended after the last pin): refused too.
  const ahead = join(dir, "ahead.jsonl");
  createHistoryStore(ahead, history.slice(0, 4));
  new PortableFileEventStore(ahead).appendAll(history.slice(4));
  await assert.rejects(migrateHistory({ source: ahead, target: join(dir, "c.jsonl"), now: () => 5000 }), (e) => refused("SOURCE_PIN_MISMATCH")(e) && e.detail.pinnedHeadStatus === "AHEAD");
  // Explicit opt-in migrates the unpinned source.
  const result = await migrateHistory({ source: unpinned, target: join(dir, "d.jsonl"), now: () => 5000, acceptUnpinnedSource: true });
  assert.equal(result.eventCount, history.length);
  assert.equal(verifyHistory(join(dir, "d.jsonl")).ok, true);
  // A key file already at the target is not adopted silently (L2).
  const { createOwnerKeyFile } = await import("../src/signer.ts");
  createOwnerKeyFile(join(dir, "e.jsonl.owner-key.json"), "owner:planted");
  const unpinned2 = freshCopy(unpinned, "continuity-2");
  await assert.rejects(migrateHistory({ source: unpinned2, target: join(dir, "e.jsonl"), now: () => 5000, acceptUnpinnedSource: true }), (e) => e.code === "KEY_EXISTS");
  const reused = await migrateHistory({ source: unpinned2, target: join(dir, "e.jsonl"), now: () => 5000, acceptUnpinnedSource: true, reuseExistingKey: true });
  assert.equal(reused.ownerKeyId, "owner:planted");
});

test("migrate to a key reference: the target's owner key is held by a real OpenSSH agent; no key material is written", { skip: existsSync("/usr/bin/ssh-agent") && existsSync("/usr/bin/ssh-add") && existsSync("/usr/bin/ssh-keygen") ? false : "OpenSSH is not installed" }, async (t) => {
  const { scratchDir, sshKeygen, startSshAgent } = await import("./helpers/ssh-agent.mjs");
  const custody = await import("../src/custody/index.ts");
  const { createOwnerKeyFile, loadOwnerKeyFile } = await import("../src/signer.ts");
  const dir = scratchDir(t, "itm-");
  const agent = await startSshAgent(t, dir);
  const key = sshKeygen(dir, "owner1"), other = sshKeygen(dir, "other1");
  agent.add(key.file);
  const ref = custody.keyReference({ keyId: "owner:1", publicKey: key.publicKey, signer: { kind: "ssh-agent", socket: agent.socket } });
  const history = load("handover-history.json");
  const source = join(dir, "legacy.jsonl");
  createHistoryStore(source, history); // pinned legacy source
  const target = join(dir, "t.jsonl");
  const result = await migrateHistory({ source, target, now: () => 5000, ownerKeyReference: ref });
  assert.equal(result.eventCount, history.length);
  assert.equal(result.ownerKeyId, "owner:1");
  const keyFile = `${target}.owner-key.json`;
  assert.equal(loadOwnerKeyFile(keyFile).custody.holder, "reference");
  assert.equal(/privateKey/.test(readFileSync(keyFile, "utf8")), false, "the key file is a reference, no secret");
  const report = verifyHistory(target);
  assert.equal(report.ok, true, JSON.stringify(report.failures));
  assert.equal(report.pinnedHeadStatus, "MATCHES", "the pin was attested by the agent-held key");
  const genesis = JSON.parse(readFileSync(target, "utf8").split("\n")[0]);
  assert.equal(JSON.stringify(genesis).includes(key.publicKey.slice(2)), true, "the genesis names the agent-held key");
  // The owner key once: a signer and a reference together are refused.
  let n = 0;
  const fresh = () => freshCopy(source, `legacy-${(n += 1)}`);
  await assert.rejects(migrateHistory({ source: fresh(), target: join(dir, "x.jsonl"), now: () => 5000, ownerKeyReference: ref, signer: loadOwnerKeyFile(keyFile) }), (e) => e.code === "INVALID_INPUT");
  // A key file already at the target: refused; with reuseExistingKey adopted only if it names the referenced key.
  createOwnerKeyFile(join(dir, "p.jsonl.owner-key.json"), "owner:planted");
  await assert.rejects(migrateHistory({ source: fresh(), target: join(dir, "p.jsonl"), now: () => 5000, ownerKeyReference: ref }), (e) => e.code === "KEY_EXISTS");
  await assert.rejects(migrateHistory({ source: fresh(), target: join(dir, "p.jsonl"), now: () => 5000, ownerKeyReference: ref, reuseExistingKey: true }), (e) => e.code === "KEY_EXISTS" && /is a key file \(not a reference\)/.test(e.message));
  assert.equal(existsSync(join(dir, "p.jsonl")), false);
  // Review block 5, M1: a key file WITH private key material for the very key the reference names is not adopted either
  // (the operator asked for the key to be held by a signer), nor a reference to the same key in another signer.
  const planted = createOwnerKeyFile(join(dir, "q.jsonl.owner-key.json"), "owner:1");
  const plantedRef = custody.keyReference({ keyId: "owner:1", publicKey: planted.credential, signer: { kind: "ssh-agent", socket: agent.socket } });
  await assert.rejects(migrateHistory({ source: fresh(), target: join(dir, "q.jsonl"), now: () => 5000, ownerKeyReference: plantedRef, reuseExistingKey: true }), (e) => e.code === "KEY_EXISTS" && /not a reference/.test(e.message));
  assert.equal(existsSync(join(dir, "q.jsonl")), false);
  writeFileSync(join(dir, "s.jsonl.owner-key.json"), readFileSync(keyFile), { mode: 0o600 });
  const otherSocket = custody.keyReference({ keyId: "owner:1", publicKey: key.publicKey, signer: { kind: "ssh-agent", socket: join(dir, "elsewhere.sock") } });
  await assert.rejects(migrateHistory({ source: fresh(), target: join(dir, "s.jsonl"), now: () => 5000, ownerKeyReference: otherSocket, reuseExistingKey: true }), (e) => e.code === "KEY_EXISTS" && /in another signer/.test(e.message));
  writeFileSync(join(dir, "r.jsonl.owner-key.json"), readFileSync(keyFile), { mode: 0o600 });
  const reused = await migrateHistory({ source: fresh(), target: join(dir, "r.jsonl"), now: () => 5000, ownerKeyReference: ref, reuseExistingKey: true });
  assert.equal(reused.ownerKeyId, "owner:1");
  // An agent that does not hold the key: the migration fails before any target byte, and leaves no reference behind.
  const missing = custody.keyReference({ keyId: "owner:1", publicKey: other.publicKey, signer: { kind: "ssh-agent", socket: agent.socket } });
  await assert.rejects(migrateHistory({ source: fresh(), target: join(dir, "m.jsonl"), now: () => 5000, ownerKeyReference: missing }), (e) => e.code === "KEY_UNAVAILABLE");
  assert.equal(existsSync(join(dir, "m.jsonl")), false);
  assert.equal(existsSync(join(dir, "m.jsonl.owner-key.json")), false, "a failed migration leaves no key reference behind");
  // Review block 5, M2: a genesis-only source signs no control event, so without the possession proof the first signature
  // would be the pin, after the target was written. Now it fails before any byte, and a held key migrates it.
  const genesisOnly = join(dir, "g.jsonl");
  createHistoryStore(genesisOnly, history.slice(0, 1));
  await assert.rejects(migrateHistory({ source: genesisOnly, target: join(dir, "gm.jsonl"), now: () => 5000, ownerKeyReference: missing }), (e) => e.code === "KEY_UNAVAILABLE");
  assert.equal(existsSync(join(dir, "gm.jsonl")), false, "no target");
  assert.equal(existsSync(join(dir, "gm.jsonl.owner-key.json")), false, "no reference");
  assert.equal(existsSync(join(dir, "gm.jsonl.head")), false, "no pin");
  const single = await migrateHistory({ source: genesisOnly, target: join(dir, "g1.jsonl"), now: () => 5000, ownerKeyReference: ref });
  assert.equal(single.eventCount, 1);
  assert.equal(verifyHistory(join(dir, "g1.jsonl")).pinnedHeadStatus, "MATCHES");
  // A dead agent (nothing listening): the same, nothing on disk.
  const dead = custody.keyReference({ keyId: "owner:1", publicKey: key.publicKey, signer: { kind: "ssh-agent", socket: join(dir, "dead.sock") } });
  await assert.rejects(migrateHistory({ source: freshCopy(genesisOnly, "g-2"), target: join(dir, "gd.jsonl"), now: () => 5000, ownerKeyReference: dead }), (e) => e.code === "SIGNER_FAILED" || e.code === "KEY_UNAVAILABLE");
  assert.equal(existsSync(join(dir, "gd.jsonl")) || existsSync(join(dir, "gd.jsonl.owner-key.json")), false);
});
