// Migration to format 2 (SPEC §16.2, A-17; BUILD T4): the Amount path list in both directions on every path (and
// UNEXPECTED_AMOUNT_FIELD); legacy → 2 and format-1 → 2 with the final head and root pinned (the E5 regenerated suite
// reuses them); the `shadow` record and a rebuild (T2) at every split of a migrated history, prefix positions included;
// a format-1 source that was itself migrated (SOURCE_ALREADY_MIGRATED), an unpinned format-1 source (acceptUnpinnedSource),
// a source with a rotation in the prefix; the fence (`.migrated`: read-only with the target named; a marker whose
// sourceHead mismatches fails the open with MIGRATION_MARKER_INVALID; the source bytes never change); the plan (refused
// with different contents); `migrationStatus` phases; T4: `migrate` killed at steps 1, 2/5 and 6 — the source stays
// byte-identical, `--status` reports the actual phase, a re-run completes, the fenced source opens read only; the
// capacity pre-check (a source whose transcription would hit the reserve is refused up front, nothing written).
import { test } from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const core = await import("../src/index.ts");
const { migrateHistory, migrationStatus, migrationPlanPathFor } = await import("../src/migrate.ts");
const { AMOUNT_PATHS, convertAmounts, markerOutsideAmountPaths, transcribeData, invertTranscription } = await import("../src/transcription.ts");
const { createHistoryStore: createStrict, openHistoryStore, migratedMarkerPathFor, MIGRATED_MARKER_VERSION } = await import("../src/store.ts");
const { setCapacityLimitsForTests } = await import("../src/capacity.ts");
const { keyPairFromPrivateKey, generateKeyPair, signHashWith } = await import("../src/crypto/suites.ts");
const { signerFromKeyPair } = await import("../src/signer.ts");
const { createLocalDomain, createLocalOwner } = await import("../src/owner.ts");
const { openLocalSimulation, commitTerms } = await import("../src/simulation.ts");
const { LEGACY_FORMAT, TRELLIS_FORMAT, TRELLIS2_FORMAT } = await import("../src/events.ts");
import { fixturesRoot as FIXTURES } from "./reference.mjs";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling

const ROOT = join(import.meta.dirname, "..", "..", "..");
const V1 = join(ROOT, "conformance", "v1", "histories");
const WORKER = fileURLToPath(new URL("./migrate-worker.mjs", import.meta.url));
const OWNER_KEY = `0x${"7e".repeat(32)}`;
const owner = () => signerFromKeyPair(keyPairFromPrivateKey("ed25519", "owner:1", OWNER_KEY));
const revive = (_k, v) => (v !== null && typeof v === "object" && typeof v["$continuity.bigint"] === "string" ? BigInt(v["$continuity.bigint"]) : v);
const load = (name) => JSON.parse(readFileSync(`${FIXTURES}${name}`, "utf8"), revive);
const sha = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
const createHistoryStore = (path, events, options = {}) => createStrict(path, events, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true, ...options });
const workspace = (t) => { const dir = mkdtempSync(join(tmpdir(), "irontrellis-f2-migrate-")); t.after(() => rmSync(dir, { recursive: true, force: true })); return dir; };
const code = (value, reason) => (e) => e.code === value && (reason === undefined || e.detail?.reason === reason);
const records = (state) => core.stateRecordsOf(state).map((e) => ({ kind: e.kind, key: e.key, record: e.record }));
const accepted = (events) => { const r = core.replay(events); assert.equal(r.status, "ACCEPTED", `${r.code} ${r.reason} @${r.position}`); return r; };
const run = (source, target, cut) => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, ["--experimental-strip-types", WORKER, source, target, cut, OWNER_KEY], { stdio: ["ignore", "pipe", "pipe"] });
  let out = "", err = "";
  child.stdout.on("data", (chunk) => { out += chunk; });
  child.stderr.on("data", (chunk) => { err += chunk; });
  child.on("error", reject);
  child.on("exit", (status, signal) => resolve({ status, signal, out, err }));
});

// The pinned results of the two reference migrations (deterministic: fixed owner key, no next key, fixed clock). The E5
// regenerated suite reuses them; a change here is a format change (SPEC §19) or a bug.
/** A-40.3: the fixed migration id of the pinned twins (the regenerated suite pins migration roots at G2.5). */
export const MIGRATION_ID = `0x${"4d".repeat(32)}`;
// G2-APPLY: re-pinned after A-40.2–3 (sourceAttestation, migrationId MIGRATION_ID) and A-52.4 (policyVersion rewrite); E3 had legacy head 0x193ecc0e…8dc9 root 0xf730a74d…2050, format 1 head 0x74571c59…942c root 0x7b2a1378…26a1.
export const PINNED = {
  legacy: { source: "handover-history.json (packages/reference-0.2 fixture, pinned by this store)", position: 25, recordCount: 50, head: "0xc3616653aee88016b2a02132a95b0b87ae03ba86be5477aaa8676400fb190156", stateRoot: "0x389fa6ec00c5690bdf4e243843fea8f77df36bb313f2ee55fa8321f70ada308f" },
  format1: { source: "conformance/v1/histories/handover-v1.jsonl", position: 21, recordCount: 43, head: "0xc4d3eac042b0b420635a8beb657d91fd7ee5d8d42841113cd0841d9d0cbdf09d", stateRoot: "0xf3b573bd6ba9b45af056cb4e544b22f944834b39c1f757f9175bb69aacdcbb62" },
};

test("the Amount path list converts every path in both directions and refuses a marker anywhere else", () => {
  const c = { maxAmount: 7n, maxCumulativeAmount: 9n, actions: ["a"], resources: ["r"], quantitative: true, maxDelegationDepth: 0, requiredIntersectionIds: [] };
  const grant = { id: "g", type: "AUTHORITY_GRANTED", timestamp: 1, data: { grant: { kind: "PERMISSION", authorityId: "g", grantorId: "o", granteeId: "a", rootAuthorityId: "g", independent: true, constraints: c }, controlAuthorization: { keyId: "k", signature: "0x" + "1".repeat(128) } } };
  const declared = { id: "d", type: "TRANSACTION_INTENT_DECLARED", timestamp: 1, data: { intentId: "i", nonce: "n", actorId: "a", action: "x", resource: "y", roleId: "r", roleTenureId: "t", amount: 5n, adapterProfile: { profileId: "p", profileVersion: "1", descriptorHash: "0x" + "0".repeat(64) } } };
  const proof = {
    request: { actorId: "a", action: "x", resource: "y", claimedAt: 1, amount: 5n }, effectiveConstraints: c, permissionPath: [{ constraints: c }, { constraints: { ...c, maxAmount: 1n } }],
    intersections: [{ requiredAuthorityId: "q", effectiveConstraints: c, path: [{ constraints: c }, { constraints: c }] }], usageSnapshot: [{ authorityId: "g", admittedTransactionCount: 1, admittedCumulativeAmount: 3n }, { authorityId: "h", admittedTransactionCount: 0, admittedCumulativeAmount: 0n }],
  };
  const admitted = { id: "m", type: "TRANSACTION_INTENT_ADMITTED", timestamp: 1, data: { intentId: "i", authorizationProof: proof, runtimeSignature: "0x" } };
  const bigints = (value) => JSON.stringify(value, (_k, v) => (typeof v === "bigint" ? `<${v}>` : v));
  const strings = (value) => JSON.stringify(value, (_k, v) => (typeof v === "bigint" ? "BIGINT-LEFT" : v));
  for (const event of [grant, declared, admitted]) {
    const wire = convertAmounts(event.type, event.data, "toWire");
    assert.ok(!strings(wire).includes("BIGINT-LEFT"), `${event.type}: every Amount converted to a string`);
    assert.equal(markerOutsideAmountPaths(event.type, event.data), undefined);
    const back = convertAmounts(event.type, wire, "toEngine");
    assert.equal(bigints(back), bigints(event.data), `${event.type}: a bijection on the listed paths`);
    // Every listed path was exercised: the wire form holds a string where the engine form held a bigint.
    for (const path of AMOUNT_PATHS[event.type]) {
      const at = (value, segments) => segments.reduce((acc, seg) => (seg.endsWith("[]") ? acc?.[seg.slice(0, -2)]?.[0] : acc?.[seg]), value);
      assert.equal(typeof at(wire, path.split(".")), "string", `${event.type}: ${path} converted`);
      assert.equal(typeof at(back, path.split(".")), "bigint", `${event.type}: ${path} inverted`);
    }
  }
  assert.equal(AMOUNT_PATHS.AUTHORITY_GRANTED.length + AMOUNT_PATHS.TRANSACTION_INTENT_DECLARED.length + AMOUNT_PATHS.TRANSACTION_INTENT_ADMITTED.length, 2 + 1 + 10, "the exhaustive list of SPEC §16.2 step 2(a)");
  // A marker anywhere else is UNEXPECTED_AMOUNT_FIELD (an unlisted field of a listed type; any field of another type).
  assert.equal(markerOutsideAmountPaths("AUTHORITY_GRANTED", { grant: { constraints: { maxTransactions: 3n } } }), "$.data.grant.constraints.maxTransactions");
  assert.throws(() => transcribeData({ id: "x", type: "RECEIPT_RECORDED", timestamp: 1, data: { intentId: "i", amount: 1n } }, LEGACY_FORMAT, "ed25519"), code("MIGRATION_UNSUPPORTED", "UNEXPECTED_AMOUNT_FIELD"));
  assert.throws(() => transcribeData({ ...admitted, data: { ...admitted.data, authorizationProof: { ...proof, evaluationTime: 2n } } }, TRELLIS_FORMAT, "ed25519"), code("MIGRATION_UNSUPPORTED", "UNEXPECTED_AMOUNT_FIELD"));
  // Steps (c), (d), (f) and their inversion.
  const f1Control = { ...grant, data: { ...grant.data } };
  const t1 = transcribeData(f1Control, TRELLIS_FORMAT, "ed25519");
  assert.deepEqual(t1.sourceControlAuthorization, grant.data.controlAuthorization);
  assert.equal(t1.controlAuthorization, undefined);
  assert.deepEqual(invertTranscription({ ...grant, data: { ...t1, controlAuthorization: { keyId: "new", signature: "0x" + "2".repeat(128) } } }, TRELLIS_FORMAT).data, grant.data);
  const tLegacy = transcribeData(grant, LEGACY_FORMAT, "eip191-personal-sign-keccak256");
  assert.equal(tLegacy.sourceControlAuthorization, undefined, "legacy control events had no authorization");
  const session = { id: "s", type: "RUNTIME_SESSION_ADMITTED", timestamp: 1, data: { sessionId: "s", agentId: "a", controllerId: "c", controlEpoch: 1, credentialKeyId: "k", credentialAddress: "0x" + "ab".repeat(20), expiresAt: 9 } };
  const tSession = transcribeData(session, LEGACY_FORMAT, "eip191-personal-sign-keccak256");
  assert.equal(tSession.credentialScheme, "eip191-personal-sign-keccak256");
  assert.deepEqual(invertTranscription({ ...session, data: tSession }, LEGACY_FORMAT).data, session.data);
  const tDeclared = transcribeData(declared, LEGACY_FORMAT, "x");
  assert.equal(tDeclared.declarationAuthorization, null);
  assert.deepEqual(invertTranscription({ ...declared, data: tDeclared }, LEGACY_FORMAT).data, declared.data);
});

/** The state after events 0..k of a migrated history (a prefix inside the migrated prefix is not a complete history: applied event by event). */
const prefixState = (events, k) => {
  const state = core.createReplayState(TRELLIS2_FORMAT);
  for (const event of events.slice(0, k + 1)) { const r = core.applyEvent(state, event); assert.ok(r.ok, `${r.code} ${r.reason}`); }
  return state;
};
/** T2 over a migrated history: rebuild at every split (prefix positions re-establish the shadow context) and replay the tail. */
function rebuildEverywhere(events) {
  const full = accepted(events);
  for (let k = 0; k < events.length; k += 1) {
    const prefix = { state: prefixState(events, k) };
    const state = core.rebuildReplayState(records(prefix.state), events);
    assert.deepEqual(core.stateRootOf(state), core.stateRootOf(prefix.state), `root at ${k}`);
    assert.deepEqual(state.shadowHashes, prefix.state.shadowHashes, `shadow hashes at ${k}`);
    const tail = core.replayFrom(state, events.slice(k + 1));
    assert.equal(tail.status, "ACCEPTED", `tail from ${k}: ${tail.code} ${tail.reason} @${tail.position}`);
    assert.equal(tail.stateRoot, full.stateRoot, `final root from ${k}`);
    assert.equal(core.canonicalEncode(records(state)), core.canonicalEncode(records(full.state)), `records from ${k}`);
  }
  return full;
}

test("legacy → 2: the pinned head and root, the shadow record at every prefix position, a rebuild at every split, the fence", async (t) => {
  const dir = workspace(t);
  const source = join(dir, "legacy.jsonl");
  createHistoryStore(source, load("handover-history.json"));
  const before = sha(source), target = join(dir, "legacy-2.jsonl");
  const result = await migrateHistory({ source, target, now: () => 5000, signer: owner(), nextKey: false, migrationId: MIGRATION_ID });
  assert.equal(sha(source), before, "the source bytes never change");
  const T = openHistoryStore(target).state(), S = openHistoryStore(source).state();
  assert.equal(T.events.length, S.events.length);
  assert.equal(result.phase, "FENCED");
  t.diagnostic(`legacy → 2: head ${result.targetHead.hash} position ${result.targetHead.position} root ${result.stateRoot} records ${T.stateRecords.size}`);
  // The pinned values (fixed inputs: the fixture, owner:1 = 0x7e…, no next key, clock 5000).
  assert.equal(result.targetHead.position, 25);
  assert.equal(result.targetHead.hash, PINNED.legacy.head);
  assert.equal(result.stateRoot, PINNED.legacy.stateRoot);
  assert.equal(T.stateRecords.size, PINNED.legacy.recordCount);
  // The shadow record (A-17.3): {count: p+1, root: MTH(shadow hashes 0..p)} at every prefix position; unchanged afterwards.
  for (const k of [0, 1, 10, S.head.position]) {
    const prefix = { state: prefixState(T.events, k) };
    const shadow = core.deriveRecord(prefix.state, "shadow", "0");
    assert.equal(shadow.count, k + 1);
    assert.deepEqual(prefix.state.shadowHashes, S.eventHistoryHashes.slice(0, k + 1));
  }
  const full = rebuildEverywhere(T.events);
  assert.equal(full.stateRoot, result.stateRoot);
  // A resume of the target (its snapshot was written at migration) answers as the full replay.
  const resumed = openHistoryStore(target, { trust: "CHECKPOINT_RESUME" });
  assert.equal(resumed.loadedBy(), "CHECKPOINT_RESUME");
  assert.equal(core.stateRootOf(resumed.state()).root, result.stateRoot);
  resumed.close();
  // The fence and the status.
  assert.deepEqual(migrationStatus(result.plan).phase, "FENCED");
  assert.equal(migrationStatus(result.plan).verified, true);
  const fenced = openHistoryStore(source);
  assert.equal(fenced.readOnlyReason(), "MIGRATED");
  assert.throws(() => fenced.append({ id: "x", type: "PRINCIPAL_CREATED", timestamp: 1, data: { principalId: "x" } }), code("FORMAT_READ_ONLY", "MIGRATED"));
  fenced.close();
  // A marker whose sourceHead is not the file's head: the open fails.
  const marker = JSON.parse(readFileSync(migratedMarkerPathFor(source), "utf8"));
  writeFileSync(migratedMarkerPathFor(source), `${JSON.stringify({ ...marker, sourceHead: { ...marker.sourceHead, position: marker.sourceHead.position - 1 } })}\n`);
  assert.throws(() => openHistoryStore(source), code("MIGRATION_MARKER_INVALID"));
  writeFileSync(migratedMarkerPathFor(source), "{}\n");
  assert.throws(() => openHistoryStore(source), code("MIGRATION_MARKER_INVALID"));
  writeFileSync(migratedMarkerPathFor(source), `${JSON.stringify(marker)}\n`);
  assert.equal(openHistoryStore(source).readOnlyReason(), "MIGRATED");
  assert.equal(sha(source), before);
});

test("format 1 → 2: the pinned head and root, sourceControlAuthorization kept, a rebuild at every split; an already-migrated format-1 source and a rotation in the prefix are refused; an unpinned source needs acceptUnpinnedSource", async (t) => {
  const dir = workspace(t);
  const source = join(dir, "handover-v1.jsonl");
  copyFileSync(join(V1, "handover-v1.jsonl"), source); // a format-1 store file without its pin
  await assert.rejects(migrateHistory({ source, target: join(dir, "x.jsonl"), now: () => 5000, signer: owner(), nextKey: false, migrationId: MIGRATION_ID }), code("MIGRATION_UNSUPPORTED", "SOURCE_UNPINNED"));
  assert.equal(existsSync(join(dir, "x.jsonl")), false);
  const before = sha(source), target = join(dir, "handover-2.jsonl");
  const result = await migrateHistory({ source, target, now: () => 5000, signer: owner(), nextKey: false, migrationId: MIGRATION_ID, acceptUnpinnedSource: true });
  assert.equal(sha(source), before);
  const T = openHistoryStore(target).state(), S = openHistoryStore(source, { allowUnpinned: true }).state();
  assert.equal(S.format, TRELLIS_FORMAT);
  assert.equal(T.format, TRELLIS2_FORMAT);
  assert.deepEqual(T.shadowHashes, S.eventHistoryHashes, "the sha256 wrapper shadow reproduces the format-1 prefix hashes");
  assert.deepEqual(T.genesis.migratedFrom.versions, S.genesis.versions);
  for (let k = 1; k < S.events.length; k += 1) {
    const s = S.events[k], m = T.events[k];
    assert.deepEqual(invertTranscription(m, TRELLIS_FORMAT).data, s.data, `event ${k}`);
    if (core.CONTROL_EVENT_TYPES.has(s.type)) assert.deepEqual(m.data.sourceControlAuthorization, s.data.controlAuthorization, `event ${k} keeps the /1 authorization`);
  }
  t.diagnostic(`format 1 → 2: head ${result.targetHead.hash} position ${result.targetHead.position} root ${result.stateRoot} records ${T.stateRecords.size}`);
  assert.equal(result.targetHead.position, S.head.position);
  assert.equal(result.targetHead.hash, PINNED.format1.head);
  assert.equal(result.stateRoot, PINNED.format1.stateRoot);
  assert.equal(T.stateRecords.size, PINNED.format1.recordCount);
  const full = rebuildEverywhere(T.events);
  assert.equal(full.stateRoot, result.stateRoot);
  // The prefix's runtime-signed structures were validated against the source's heads: the admissions carry format-1 heads.
  for (const [id, admission] of S.intentAdmissions) assert.deepEqual(T.intentAdmissions.get(id).admissionHead, admission.admissionHead);
  // A format-1 source that was itself migrated from legacy (two shadow levels) is refused and stays readable.
  const migrated = join(dir, "migrated-v1.jsonl");
  copyFileSync(join(V1, "migrated-v1.jsonl"), migrated);
  await assert.rejects(migrateHistory({ source: migrated, target: join(dir, "m2.jsonl"), now: () => 5000, signer: owner(), nextKey: false, migrationId: MIGRATION_ID, acceptUnpinnedSource: true }), code("MIGRATION_UNSUPPORTED", "SOURCE_ALREADY_MIGRATED"));
  assert.equal(openHistoryStore(migrated, { allowUnpinned: true }).state().genesis.migratedFrom.format, LEGACY_FORMAT);
  assert.equal(existsSync(join(dir, "m2.jsonl")), false);
  // A format-1 source with an owner key rotation: the prefix admits no rotation (HF1 §11, SPEC §16.2); refused before any write.
  const rotation = join(dir, "rotation-v1.jsonl");
  copyFileSync(join(V1, "rotation-v1.jsonl"), rotation);
  await assert.rejects(migrateHistory({ source: rotation, target: join(dir, "r2.jsonl"), now: () => 5000, signer: owner(), nextKey: false, migrationId: MIGRATION_ID, acceptUnpinnedSource: true }), (e) => e.code === "MIGRATION_UNSUPPORTED" && e.detail.reason === "SOURCE_KEY_ROTATED" && /rotat/.test(e.message)); // A-63.1: at plan time
  assert.equal(existsSync(join(dir, "r2.jsonl")), false);
});

test("format 1 → 2 of an engine-built history with amounts, admissions, receipts, obligations and a handover: every answer equals the source's under the comparison projection", async (t) => {
  const dir = workspace(t);
  let tick = 100, n = 0;
  const config = { historyFile: join(dir, "f1.jsonl"), domain: createLocalDomain({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true }), owner: "operations", controller: "operator", now: () => tick, format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true, nextKey: false, migrationId: MIGRATION_ID, ids: () => `e:${(n += 1)}`, witness: false };
  const c = await createLocalOwner(config);
  const pair = generateKeyPair("ed25519", "key:a");
  for (const id of ["a", "b"]) await c.createAgent({ id });
  await c.createRole({ id: "reviewer" });
  await c.declareSuccession({ id: "handover", from: "a", to: "b", role: "reviewer" });
  await c.appoint({ agent: "a", role: "reviewer", tenure: "shift:1", number: 1, succession: "handover" });
  await c.admitRuntime({ session: "s:a", agent: "a", epoch: 1, key: "k:a", credential: pair.credential, expiresAt: 1000 });
  await c.grant({ id: "quant", to: "a", actions: ["pay"], resources: ["vendor"], expiresAt: 900, maxAmount: 2500n, maxCumulativeAmount: 5000n, maxTransactions: 3 });
  await c.grant({ id: "collect", to: "a", actions: ["OBLIGATE"], resources: ["vendor"], expiresAt: 900 }); // uncapped: a capped grant cannot back an administrative proof
  await c.grant({ id: "review", to: "b", actions: ["record-collection-disposition"], resources: ["duty:42"], expiresAt: 900 });
  const a = { ...config, session: "s:a", signHash: signHashWith(pair) };
  const op = { id: "op:1", action: "pay", resource: "vendor", role: "reviewer", tenure: "shift:1", amount: 1200n, termsCommitment: commitTerms({ invoice: 1 }) };
  const sim = openLocalSimulation(a);
  tick = 102;
  assert.equal((await sim.run(op)).invocation.status, "SUBMITTED");
  tick = 103;
  assert.equal((await sim.recordReceipt(op)).recording.status, "ADMITTED");
  tick = 104;
  const { openLocalRuntime } = await import("../src/runtime.ts");
  await openLocalRuntime(a).obligate({ id: "duty:42", operation: op.id, description: "Review.", deadline: 800, succession: "handover", reviewAuthority: "review" });
  tick = 120;
  await c.succeed({ id: "handover:1", rule: "handover", fromAgent: "a", fromTenure: "shift:1", toAgent: "b", toTenure: "shift:2", role: "reviewer", number: 2 });
  const source = config.historyFile, target = join(dir, "f2.jsonl");
  const result = await migrateHistory({ source, target, now: () => 5000, signer: owner(), nextKey: false, migrationId: MIGRATION_ID });
  const S = openHistoryStore(source, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true }).state(), T = openHistoryStore(target).state();
  assert.equal(T.events.length, S.events.length);
  rebuildEverywhere(T.events);
  const usage = core.deriveRecord(T, "usage", "quant");
  assert.deepEqual(usage, { authorityId: "quant", admittedTransactionCount: 1, admittedCumulativeAmount: "1200" });
  assert.deepEqual(T.authorityUsage.get("quant"), S.authorityUsage.get("quant"));
  assert.equal(core.deriveRecord(T, "intent", "op:1").amount, "1200");
  assert.equal(core.deriveRecord(T, "intent", "op:1").declarationDigest, null);
  // The comparison projection (BUILD §4): amounts as strings, literals and format-2-only fields removed; answers equal.
  const strip = (value) => JSON.stringify(value, (key, v) => (["hash", "historyHash", "domain", "authorizationDomain", "policyVersion", "proofVersion", "version", "operationVersion", "eventHistoryHash", "versions", "budgetId", "stateRoot", "projectionHead"].includes(key) ? undefined : typeof v === "bigint" ? v.toString() : v));
  const questions = [{ actor: "a", action: "pay", resource: "vendor", amount: 100n }, { actor: "b", action: "pay", resource: "vendor", amount: 100n }, { actor: "b", action: "record-collection-disposition", resource: "duty:42" }, { actor: "a", action: "OBLIGATE", resource: "vendor" }];
  for (const at of [120, 2000]) {
    const oS = core.observeState(S, { at }), oT = core.observeState(T, { at });
    for (const q of questions) {
      assert.equal(strip(oT.authorize(q).evidence.decision), strip(oS.authorize(q).evidence.decision), `${at} ${q.actor} ${q.action}`);
      assert.equal(strip(oT.authorize(q).evidence.code), strip(oS.authorize(q).evidence.code));
      assert.equal(strip(oT.responsible(q).answer?.attributions ?? oT.responsible(q).epistemicStatus), strip(oS.responsible(q).answer?.attributions ?? oS.responsible(q).epistemicStatus));
    }
    assert.equal(strip(oT.survives("a").answer), strip(oS.survives("a").answer));
  }
  assert.equal(result.phase, "FENCED");
});

test("T4: migrate killed at steps 1, 2/5 and 6 — the source stays byte-identical, --status reports the phase, a re-run completes, the fenced source opens read only", async (t) => {
  for (const cut of ["plan-written", "line-appended", "target-written", "before-fence"]) {
    const dir = workspace(t);
    const source = join(dir, "legacy.jsonl");
    createHistoryStore(source, load("handover-history.json"));
    const before = sha(source), target = join(dir, "t2.jsonl"), plan = migrationPlanPathFor(target);
    const result = await run(source, target, cut);
    assert.equal(result.signal, "SIGKILL", `${cut}: ${result.out} ${result.err}`);
    assert.ok(result.out.includes(`CUT ${cut}`), `${cut}: ${result.out}`);
    assert.equal(sha(source), before, `${cut}: the source is byte-identical`);
    assert.equal(existsSync(plan), true, `${cut}: the plan was written first`);
    const status = migrationStatus(plan);
    const expectedPhase = { "plan-written": "PLANNED", "line-appended": "WRITTEN", "target-written": "PINNED", "before-fence": "PINNED" }[cut];
    assert.equal(status.phase, expectedPhase, `${cut}: ${JSON.stringify(status)}`);
    assert.equal(status.outputs.fence, false);
    if (cut === "line-appended") assert.equal(status.outputs.pin, false, "the target file is on disk without its pin");
    assert.equal(status.verified, true, `${cut}: ${status.problems.join("; ")}`);
    // A dead migration's writer lock on the target (when it got that far) is reclaimable like any other after 60 s; the re-run uses a fresh store handle.
    for (const lock of [`${target}.writer-lock`]) if (existsSync(lock)) { const { utimesSync } = await import("node:fs"); const old = Date.now() - 120_000; writeFileSync(lock, JSON.stringify({ ...JSON.parse(readFileSync(lock, "utf8")), createdAt: old })); utimesSync(lock, old / 1000, old / 1000); }
    const again = await migrateHistory({ source, target, now: () => 5000, signer: owner(), nextKey: false, migrationId: MIGRATION_ID, acceptUnpinnedSource: true });
    assert.equal(again.phase, "FENCED", cut);
    assert.equal(sha(source), before);
    assert.equal(migrationStatus(plan).phase, "FENCED");
    assert.equal(migrationStatus(plan).verified, true);
    const fenced = openHistoryStore(source);
    assert.equal(fenced.readOnlyReason(), "MIGRATED");
    fenced.close();
    assert.equal(core.stateRootOf(openHistoryStore(target).state()).root, again.stateRoot);
    t.diagnostic(`${cut}: phase after the kill ${status.phase}; re-run FENCED`);
  }
});

test("the plan: a re-run with the same plan verifies; a plan with different contents is refused; a different owner key is a different plan", async (t) => {
  const dir = workspace(t);
  const source = join(dir, "legacy.jsonl");
  createHistoryStore(source, load("mandate-history.json"));
  const target = join(dir, "t2.jsonl");
  const first = await migrateHistory({ source, target, now: () => 5000, signer: owner(), nextKey: false, migrationId: MIGRATION_ID });
  const plan = JSON.parse(readFileSync(first.plan, "utf8"));
  assert.equal(plan.version, "irontrellis-migration-plan/1");
  assert.deepEqual(Object.keys(plan).sort(), ["createdAt", "migrationId", "ownerKey", "source", "sourceFormat", "sourceHead", "target", "version"]); // + migrationId (A-40.3)
  const other = signerFromKeyPair(keyPairFromPrivateKey("ed25519", "owner:1", `0x${"5a".repeat(32)}`));
  await assert.rejects(migrateHistory({ source, target, now: () => 5000, signer: other, nextKey: false, migrationId: MIGRATION_ID }), code("MIGRATION_UNSUPPORTED", "PLAN_MISMATCH"));
  const same = await migrateHistory({ source, target, now: () => 9000, signer: owner(), nextKey: false, migrationId: MIGRATION_ID });
  assert.deepEqual(same.targetHead, first.targetHead);
  assert.equal(readFileSync(first.plan, "utf8"), JSON.stringify(plan) + "\n", "the plan is not rewritten");
});

test("capacity: a source whose transcription would hit the format-2 reserve is refused up front; nothing is written", async (t) => {
  const dir = workspace(t);
  const source = join(dir, "legacy.jsonl");
  createHistoryStore(source, load("handover-history.json"));
  const target = join(dir, "t2.jsonl");
  setCapacityLimitsForTests({ maxStateRecords: 40, reservedStateRecords: 10 });
  try {
    await assert.rejects(migrateHistory({ source, target, now: () => 5000, signer: owner(), nextKey: false, migrationId: MIGRATION_ID }), (e) => e.code === "MIGRATION_UNSUPPORTED" && e.detail.reason === "CAPACITY" && ["CAPACITY_RESERVED", "CAPACITY_EXCEEDED"].includes(e.detail.code));
  } finally { setCapacityLimitsForTests(); }
  assert.equal(existsSync(target), false);
  assert.equal(existsSync(migrationPlanPathFor(target)), false, "a refused migration leaves no plan behind");
  assert.equal(existsSync(migratedMarkerPathFor(source)), false);
  assert.equal(openHistoryStore(source, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true }).readOnlyReason(), undefined);
  assert.equal(MIGRATED_MARKER_VERSION, "irontrellis-migrated/1");
});
