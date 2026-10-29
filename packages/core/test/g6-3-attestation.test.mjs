// Human attestation (`humanFloor: "ATTESTED"`; the G6.x holds were lifted on 2026-10-12): the class function (A-107.1 /
// A-118.4), the attestation horizon, and the writer's pre-checks for rules T1 (A-109.1, `{expiresAt}`) and T2 (A-119.4,
// `{horizon}`). Replay itself is pinned by conformance/v2-human-attestation.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const core = await import("../src/index.ts");
const { signerClass, attestationHorizon, humanAttestationHash, createLocalDomain, createLocalOwner } = core;
const { keyPairFromPrivateKey } = await import("../src/crypto/suites.ts");
const { signerFromKeyPair } = await import("../src/signer.ts");
const { generateKeyPair, signHashWith } = await import("../src/crypto/suites.ts");

const pair = (keyId, n) => keyPairFromPrivateKey("ed25519", keyId, `0x${n.toString(16).padStart(64, "0")}`);
const pub = (p) => ({ keyId: p.keyId, scheme: "ed25519", credential: p.credential });
const O1 = pair("owner:1", 0x8001), O2 = pair("owner:2", 0x8002), A1 = pair("agent:1", 0x8101), AT1 = pair("attester:1", 0x8301), AT2 = pair("attester:2", 0x8302);
const statement = (domain, subject, attester, notBefore, expiresAt) => {
  const body = { version: "irontrellis-human-attestation/1", audience: domain, subject: pub(subject), profile: "phl:ceremony/1", attesterKeyId: attester.keyId, evidenceDigest: `0x${"cd".repeat(32)}`, notBefore, expiresAt };
  return { ...body, signature: signerFromKeyPair(attester).signHashSync(humanAttestationHash({ ...body, signature: "" })) };
};

test("A-107.1 / A-118.4 cls: DECLARED is HUMAN or AGENT; ATTESTED is HUMAN while valid, AGENT, LAPSED once expired, NONE otherwise", () => {
  const domain = createLocalDomain();
  const keys = [pub(O1), pub(O2), pub(A1)];
  const declared = { threshold: 1, keyClasses: { "agent:1": "AGENT" } };
  assert.deepEqual([O1, O2, A1].map((k) => signerClass(declared, keys, k, 5)), ["HUMAN", "HUMAN", "AGENT"]);
  assert.deepEqual([O1, A1].map((k) => signerClass(undefined, keys, k, 5)), ["HUMAN", "HUMAN"]);
  const attested = { ...declared, humanFloor: "ATTESTED", attesters: [pub(AT1), pub(AT2)], attestations: [statement(domain, O1, AT1, 10, 20)] };
  assert.deepEqual([9, 10, 19, 20, 99].map((t) => signerClass(attested, keys, O1, t)), ["NONE", "HUMAN", "HUMAN", "LAPSED", "LAPSED"]);
  assert.equal(signerClass(attested, keys, O2, 15), "NONE", "no statement");
  assert.equal(signerClass(attested, keys, A1, 15), "AGENT");
  assert.equal(attestationHorizon(attested), 20);
  assert.equal(attestationHorizon(declared), undefined);
});

async function attestedOwner(t, expiries) {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-g63-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const domain = createLocalDomain();
  let tick = 1000;
  const ownerPolicy = { threshold: 1, byType: { STATE_CHECKPOINT: 1 }, humanFloor: "ATTESTED", attesters: [pub(AT1), pub(AT2)],
    attestations: [statement(domain, O1, AT1, 0, expiries[0]), statement(domain, O2, AT2, 0, expiries[1])] };
  const handle = await createLocalOwner({ historyFile: join(dir, "history.jsonl"), domain, owner: "operations", controller: "operator", now: () => tick, signer: signerFromKeyPair(O1), witness: false, coOwnerKeys: [pub(O2)], ownerPolicy });
  return { handle, at: (time) => { tick = time; } };
}

test("A-119.4 / A-172.2 writer pre-check: a single human-class signer past the attestation horizon is TRANSITION_REJECTED {reason: ATTESTATION_HORIZON, horizon}; at the horizon it writes", async (t) => {
  const { handle, at } = await attestedOwner(t, [1500, 5000]);
  await handle.createAgent({ id: "bea" });
  at(6000); // owner:1 is LAPSED (1500), the horizon is 5000
  await assert.rejects(handle.advanceEpoch({ agent: "bea", from: 1, to: 2 }), (e) => e.code === "TRANSITION_REJECTED" && e.detail.reason === "ATTESTATION_HORIZON" && e.detail.horizon === 5000);
  at(5000);
  const result = await handle.advanceEpoch({ agent: "bea", from: 1, to: 2 }); // PR_eff: a LAPSED key counts; T2 admits t = H
  assert.equal(result.head.position, 3);
  await assert.rejects(handle.createRole({ id: "desk" }), (e) => e.code === "CONTROL_AUTHORIZATION_INVALID"); // not PR_eff: LAPSED never counts
  const report = handle.verify();
  assert.equal(report.ok, true);
  // A-111.3 (report-level): the pin of the fence's head is signed by owner:1, LAPSED at 5000.
  assert.match(report.notes.join("\n"), /HEAD_SIGNER_UNQUALIFIED: the pin's attestation at position 3 is signed by owner:1, LAPSED at 5000/);
});

test("A-119.1: once every statement expired, a single LAPSED signer stays within the horizon (the writer refuses before signing)", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-g63-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const domain = createLocalDomain();
  let tick = 1000;
  const ownerPolicy = { threshold: 1, humanFloor: "ATTESTED", attesters: [pub(AT1), pub(AT2)], attestations: [statement(domain, O1, AT1, 0, 1500), statement(domain, O2, AT2, 0, 1500)] };
  const handle = await createLocalOwner({ historyFile: join(dir, "history.jsonl"), domain, owner: "operations", controller: "operator", now: () => tick, signer: signerFromKeyPair(O1), witness: false, coOwnerKeys: [pub(O2)], ownerPolicy });
  await handle.createAgent({ id: "bea" });
  tick = 9000; // both statements expired; a fence (PR_eff) by the LAPSED owner:1 is admitted only up to H = 1500, so the writer stays at the head
  const fenced = await handle.advanceEpoch({ agent: "bea", from: 1, to: 2 }).catch((error) => error);
  assert.equal(fenced.code, "TRANSITION_REJECTED");
  assert.deepEqual(fenced.detail, { reason: "ATTESTATION_HORIZON", horizon: 1500 });
  assert.equal(handle.verify().ok, true);
});

test("A-109.1 rule T1 (the writer's pre-check reads the same function): a session event at an unexpired statement's expiry, with {expiresAt}", async () => {
  const { readFileSync } = await import("node:fs");
  const vectors = JSON.parse(readFileSync(new URL("../../../conformance/v2-human-attestation/vectors.json", import.meta.url), "utf8"));
  const crossing = vectors.find((v) => v.id.endsWith("/rejects-session-event-crossing-attestation-expiry")).events;
  const before = core.replay(crossing.slice(0, -1));
  assert.equal(before.status, "ACCEPTED");
  const event = crossing.at(-1);
  assert.deepEqual(core.attestationExpiryFailure(before.state, event, before.head.position + 1)?.expiresAt, 1000);
  assert.equal(core.attestationExpiryFailure(before.state, { ...event, timestamp: 999 }, before.head.position + 1), undefined);
});

test("A-109.1 / A-172.2 writer pre-check through the API: a session write that would pass an unexpired statement's expiry is TRANSITION_REJECTED {reason: ATTESTATION_EXPIRY, expiresAt}; nothing is written", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-g63-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const domain = createLocalDomain();
  let tick = 1000;
  const ownerPolicy = { threshold: 1, humanFloor: "ATTESTED", attesters: [pub(AT1), pub(AT2)], attestations: [statement(domain, O1, AT1, 0, 1500), statement(domain, O2, AT2, 0, 5000)] };
  const config = { historyFile: join(dir, "history.jsonl"), domain, owner: "operations", controller: "operator", now: () => tick, witness: false };
  const handle = await createLocalOwner({ ...config, signer: signerFromKeyPair(O1), coOwnerKeys: [pub(O2)], ownerPolicy });
  await handle.createAgent({ id: "bea" });
  await handle.createRole({ id: "reviewer" });
  await handle.appoint({ agent: "bea", role: "reviewer", tenure: "shift:1", number: 1 });
  const session = generateKeyPair("ed25519", "key:1");
  await handle.admitRuntime({ session: "session:1", agent: "bea", epoch: 1, key: "key:1", credential: session.credential, expiresAt: 10_000_000 });
  await handle.grant({ id: "read", to: "bea", actions: ["read"], resources: ["incident:42"], expiresAt: 10_000_000 });
  // JOB75-03 / JOB75-05: the session signer is counted; a T1 refusal asks for no signature on any session-signed path.
  let calls = 0;
  const inner = signHashWith(session);
  const sessionConfig = { ...config, session: "session:1", signHash: async (h) => { calls += 1; return inner(h); } };
  const runtime = core.openLocalSimulation(sessionConfig);
  const op = (id) => ({ id, intentId: id, action: "read", resource: "incident:42", role: "reviewer", tenure: "shift:1", termsCommitment: core.commitTerms({ subject: id }) });
  const t1 = (e) => e.code === "TRANSITION_REJECTED" && e.detail?.reason === "ATTESTATION_EXPIRY" && e.detail.expiresAt === 1500;
  const head = handle.verify().head;
  tick = 1500; // owner:1's statement (expiry 1500) is unexpired at the head (1000): a session event may not reach it (T1)
  await assert.rejects(runtime.run(op("op:1")), t1);
  assert.equal(calls, 0, "declaration: no signature asked");
  assert.deepEqual(handle.verify().head, head, "nothing was written");
  // Step 5c P2: the admission path. The declaration is signed at 1499; the clock reaches the expiry before the admission is.
  const counted = { ...sessionConfig, signHash: async (h) => { const signature = await sessionConfig.signHash(h); if (calls === 1) tick = 1500; return signature; } };
  tick = 1499; calls = 0;
  await assert.rejects(core.openLocalSimulation(counted).run(op("op:t1-adm")), t1);
  assert.equal(calls, 1, "admission: only the declaration (before the expiry) was signed");
  // Step 5d P2-6: the durable coordinator's consumption record. Declaration and admission are signed before the expiry; the
  // record is refused before its signature, reported not recorded with the inherited reason TRANSITION_REJECTED (step 5c).
  const late = { ...sessionConfig, signHash: async (h) => { const signature = await sessionConfig.signHash(h); if (calls === 2) tick = 1500; return signature; } };
  tick = 1499; calls = 0;
  const disposed = await core.openLocalSimulation(late).run(op("op:t1-rec"));
  assert.equal(calls, 2, "the consumption record asked for no signature");
  assert.equal(disposed.invocation?.status, "OUTCOME_UNKNOWN", JSON.stringify(disposed));
  assert.deepEqual([disposed.invocation.recorded, disposed.invocation.notRecorded.reason], [false, "TRANSITION_REJECTED"]);
  assert.match(disposed.invocation.notRecorded.message, /expir/i);
  assert.equal(handle.exportHistory().some((e) => e.type === "TRANSACTION_INTENT_CONSUMED" && e.data.intentId === "op:t1-rec"), false);
  tick = 1499;
  assert.equal((await runtime.run(op("op:2"))).status, "SIMULATION_RESULT");
  tick = 1500; calls = 0;
  await assert.rejects(core.openLocalRuntime(sessionConfig).recordEffect({ effectId: "effect:t1", intentId: "op:2", measurer: { kind: "SESSION", id: "bea" }, metric: "amount", unit: "cent", amount: 1n, observedAt: 1000 }), t1);
  assert.equal(calls, 0, "signed append: no signature asked");
  await assert.rejects(runtime.recordReceipt(op("op:2")), t1);
  assert.equal(calls, 0, "receipt: no signature asked");
});

test("A-119.3 with A-172.2: an automatic checkpoint that rule T2 refuses (one tick past the horizon, one LAPSED signer) is CHECKPOINT_SUPPRESSED {reason: NO_SIGNER}, never STORE_FAILED", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-g63-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const domain = createLocalDomain();
  let armed = false, calls = 0;
  const now = () => (!armed ? 1000 : ++calls <= 2 ? 1500 : 1501); // the two fences at H = 1500, the due checkpoint at 1501
  const ownerPolicy = { threshold: 1, byType: { STATE_CHECKPOINT: 1 }, humanFloor: "ATTESTED", attesters: [pub(AT1), pub(AT2)], attestations: [statement(domain, O1, AT1, 0, 1500), statement(domain, O2, AT2, 0, 1500)] };
  const handle = await createLocalOwner({ historyFile: join(dir, "history.jsonl"), domain, owner: "operations", controller: "operator", now, signer: signerFromKeyPair(O1), witness: false, coOwnerKeys: [pub(O2)], ownerPolicy, checkpointPolicy: { everyEvents: 2 } });
  await handle.createAgent({ id: "bea" });
  armed = true;
  await handle.advanceEpoch({ agent: "bea", from: 1, to: 2 }); // PR_eff: the LAPSED owner:1 counts; T2 admits t = H
  const result = await handle.advanceEpoch({ agent: "bea", from: 2, to: 3 });
  assert.equal(result.checkpoint?.code, "CHECKPOINT_SUPPRESSED");
  assert.equal(result.checkpoint?.reason, "NO_SIGNER");
  assert.equal(handle.exportHistory().at(-1).type, "CONTROL_EPOCH_ADVANCED", "no checkpoint written");
  assert.equal(handle.verify().ok, true);
});

test("JOB75-05 / A-109.1: the ▲ prepare step refuses rule T1 before signing (TRANSITION_REJECTED {ATTESTATION_EXPIRY}, not masked as a preparation failure); just before the expiry the obligation is written", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-g63-t1-admin-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const domain = createLocalDomain();
  let tick = 1000;
  const ownerPolicy = { threshold: 1, humanFloor: "ATTESTED", attesters: [pub(AT1), pub(AT2)], attestations: [statement(domain, O1, AT1, 0, 1500), statement(domain, O2, AT2, 0, 5000)] };
  const config = { historyFile: join(dir, "h.jsonl"), domain, owner: "operations", controller: "operator", now: () => tick, nextKey: false, witness: false };
  const owner = await createLocalOwner({ ...config, signer: signerFromKeyPair(O1), coOwnerKeys: [pub(O2)], ownerPolicy });
  const pair = keyPairFromPrivateKey("ed25519", "k:a", `0x${"3c".repeat(32)}`);
  for (const id of ["a", "b"]) await owner.createAgent({ id });
  await owner.createRole({ id: "reviewer" });
  await owner.declareSuccession({ id: "handover", from: "a", to: "b", role: "reviewer" });
  await owner.appoint({ agent: "a", role: "reviewer", tenure: "shift:1", number: 1, succession: "handover" });
  await owner.admitRuntime({ session: "s:a", agent: "a", epoch: 1, key: "k:a", credential: pair.credential, expiresAt: 4000 });
  await owner.grant({ id: "quant", to: "a", actions: ["pay"], resources: ["vendor"], expiresAt: 3900 });
  await owner.grant({ id: "collect", to: "a", actions: ["OBLIGATE"], resources: ["vendor"], expiresAt: 3900 });
  await owner.grant({ id: "review", to: "b", actions: ["record-collection-disposition"], resources: ["duty:42"], expiresAt: 3900 });
  let calls = 0;
  const inner = signHashWith(pair);
  const a = { ...config, session: "s:a", signHash: async (h) => { calls += 1; return inner(h); } };
  const op = { id: "op:1", action: "pay", resource: "vendor", role: "reviewer", tenure: "shift:1", termsCommitment: core.commitTerms({ invoice: 1 }) };
  const sim = core.openLocalSimulation(a);
  tick = 1100; await sim.run(op);
  tick = 1200; await sim.recordReceipt(op);
  const obligation = { id: "duty:42", operation: op.id, description: "Review.", deadline: 3800, succession: "handover", reviewAuthority: "review" };
  const t1 = (e) => e.code === "TRANSITION_REJECTED" && e.detail?.reason === "ATTESTATION_EXPIRY" && e.detail.expiresAt === 1500;
  tick = 1500; calls = 0; // owner:1's statement expires at 1500 and is unexpired at the head (1200)
  const head = core.replay(owner.exportHistory()).head;
  await assert.rejects(core.openLocalRuntime(a).obligate(obligation), t1);
  assert.equal(calls, 0, "no signature asked");
  assert.deepEqual(core.replay(owner.exportHistory()).head, head, "nothing was written");
  tick = 1499;
  assert.equal(typeof (await core.openLocalRuntime(a).obligate(obligation)).eventId, "string");
});
