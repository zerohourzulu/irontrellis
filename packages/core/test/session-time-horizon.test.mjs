// A-179 (A-22.6): the session time horizon. Genesis `sessionTimeHorizonMs` (A-179.1), the derived `ownerTime` (A-179.2), rule
// T3 in replay (A-179.3) and the writer contract (A-179.4): an appending call refuses with TRANSITION_REJECTED
// {reason: SESSION_TIME_HORIZON, ownerTime, horizonMs} before signing; refusal recording reports the not-recorded reason
// SESSION_TIME_HORIZON; a spooled entry stays spooled. The regenerated suite's session-time-horizon group pins replay.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const core = await import("../src/index.ts");
const { createLocalDomain, createLocalOwner, openLocalRuntime, commitTerms, replay } = core;
const { generateKeyPair, signHashWith } = await import("../src/crypto/suites.ts");
const { ownerTimeOf, sessionTimeHorizonFailure } = await import("../src/session-time.ts");
const { rebuildReplayState } = await import("../src/state-rebuild.ts");

const H = 1000;
const horizonRefusalOf = (ownerTime, horizonMs) => (e) => e.code === "TRANSITION_REJECTED" && e.detail?.reason === "SESSION_TIME_HORIZON" && e.detail.ownerTime === ownerTime && e.detail.horizonMs === horizonMs;
const horizonRefusal = (ownerTime) => horizonRefusalOf(ownerTime, H);

/** Owner `operations`, agent `bea` (role `reviewer`, tenure shift:1), session:1 (ed25519), grant `read` on incident:42; genesis horizon H. */
async function setup(t, extra = {}) {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-sth-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let tick = 100;
  const config = { historyFile: join(dir, "history.jsonl"), domain: createLocalDomain(), owner: "operations", controller: "operator", now: () => tick, witness: false, sessionTimeHorizonMs: H, ...extra };
  const owner = await createLocalOwner(config);
  await owner.createAgent({ id: "bea" });
  await owner.createRole({ id: "reviewer" });
  await owner.appoint({ agent: "bea", role: "reviewer", tenure: "shift:1", number: 1 });
  const pair = generateKeyPair("ed25519", "key:1");
  await owner.admitRuntime({ session: "session:1", agent: "bea", epoch: 1, key: "key:1", credential: pair.credential, expiresAt: 10_000_000 });
  await owner.grant({ id: "read", to: "bea", actions: ["read"], resources: ["incident:42"], expiresAt: 10_000_000 });
  const sessionConfig = { ...config, session: "session:1", signHash: signHashWith(pair) };
  const op = (id, extra2 = {}) => ({ id, intentId: id, action: "read", resource: "incident:42", role: "reviewer", tenure: "shift:1", termsCommitment: commitTerms({ subject: id }), ...extra2 });
  const state = () => replay(owner.exportHistory()).state;
  return { dir, config, owner, sessionConfig, op, state, at: (n) => (tick = n) };
}

test("A-179.1: the genesis carries sessionTimeHorizonMs as written; 0 is refused (INVALID_INPUT at the API, EVENT_DATA_INVALID in replay); absent and null set no horizon", async (t) => {
  const f = await setup(t);
  const genesis = f.owner.exportHistory()[0];
  assert.equal(genesis.data.sessionTimeHorizonMs, H);
  const record = core.stateRecordsOf(f.state()).find((r) => r.kind === "genesis").record;
  assert.equal(record.sessionTimeHorizonMs, H, "the genesis record copies it as written");
  await assert.rejects(createLocalOwner({ ...f.config, historyFile: join(f.dir, "zero.jsonl"), sessionTimeHorizonMs: 0 }), (e) => e.code === "INVALID_INPUT");
  const zero = structuredClone(f.owner.exportHistory().slice(0, 1));
  zero[0].data.sessionTimeHorizonMs = 0;
  assert.equal(replay(zero).code, "EVENT_DATA_INVALID");
  const none = await createLocalOwner({ ...f.config, historyFile: join(f.dir, "none.jsonl"), sessionTimeHorizonMs: undefined });
  assert.equal(Object.hasOwn(none.exportHistory()[0].data, "sessionTimeHorizonMs"), false, "absent stays absent");
  const explicit = await createLocalOwner({ ...f.config, historyFile: join(f.dir, "null.jsonl"), sessionTimeHorizonMs: null });
  assert.equal(explicit.exportHistory()[0].data.sessionTimeHorizonMs, null);
});

test("A-179.3 / A-179.4: a session write at ownerTime + H is written; past it the writer refuses before signing; an owner event that advances time moves ownerTime", async (t) => {
  const f = await setup(t);
  const runtime = openLocalRuntime(f.sessionConfig);
  const sim = core.openLocalSimulation(f.sessionConfig);
  assert.equal(ownerTimeOf(f.state()), 100, "every owner event so far was at 100");
  f.at(100 + H); // at the bound: accepted
  assert.equal((await sim.run(f.op("op:1"))).status, "SIMULATION_RESULT");
  const head = f.state().head;
  f.at(100 + H + 1); // one past it: refused before anything is signed
  await assert.rejects(sim.run(f.op("op:2")), horizonRefusal(100));
  await assert.rejects(runtime.recordEffect({ effectId: "effect:1", intentId: "op:1", measurer: { kind: "SESSION", id: "bea" }, metric: "amount", unit: "cent", amount: 1n, observedAt: 100 }), horizonRefusal(100));
  assert.deepEqual(f.state().head, head, "nothing was written");
  // A time-advancing owner event moves ownerTime; the session writes again.
  await f.owner.createAgent({ id: "cal" });
  assert.equal(ownerTimeOf(f.state()), 100 + H + 1);
  assert.equal((await sim.run(f.op("op:2"))).status, "SIMULATION_RESULT");
  assert.equal(f.owner.verify().ok, true);
});

test("A-179.2: a clamped power-reducing event (written at the head's time, A-22.3) does not move ownerTime", async (t) => {
  const f = await setup(t);
  const sim = core.openLocalSimulation(f.sessionConfig);
  f.at(100 + H);
  await sim.run(f.op("op:1")); // the head is now at 1100, a session event
  f.at(50); // the owner's clock is behind the head: the power-reducing fence is written at max(now, head) = 1100 (A-22.3)
  await f.owner.advanceEpoch({ agent: "bea", from: 1, to: 2 });
  const s = f.state();
  assert.equal(s.events.at(-1).type, "CONTROL_EPOCH_ADVANCED");
  assert.equal(s.events.at(-1).timestamp, s.events.at(-2).timestamp, "clamped to the head's time");
  assert.equal(ownerTimeOf(s), 100, "the clamped event does not advance time, so ownerTime stays");
});

test("A-179.3: replay refuses a session event past ownerTime + H with TRANSITION_INVALID right after T1, before the type's own checks; control events and the bound itself are not refused", async (t) => {
  const f = await setup(t);
  const sim = core.openLocalSimulation(f.sessionConfig);
  f.at(100 + H);
  await sim.run(f.op("op:1"));
  const events = f.owner.exportHistory();
  const last = events.findLastIndex((e) => e.type !== "STATE_CHECKPOINT" && !core.CONTROL_EVENT_TYPES.has(e.type));
  assert.equal(replay(events).status, "ACCEPTED");
  // The same session event one ms later: T3 refuses it before its signature is checked (the signature no longer matches).
  const moved = structuredClone(events.slice(0, last + 1));
  moved[last].timestamp += 1;
  const r = replay(moved);
  assert.deepEqual([r.status, r.code, r.position, r.reason], ["REJECTED", "TRANSITION_INVALID", last, "time: a session-signed event may not pass the session time horizon"]);
  // The function the writers share gives the same verdict on the state before it.
  const before = replay(events.slice(0, last)).state;
  assert.equal(sessionTimeHorizonFailure(before, moved[last], last)?.ownerTime, 100);
  assert.equal(sessionTimeHorizonFailure(before, events[last], last), undefined);
  // Without the genesis field nothing is refused (the frozen and pinned histories never carry it). Step 5d P1-3: the earlier check
  // deleted the field from the tampered history, which then failed for another reason whatever T3 did. Instead: the shared
  // function on the same state with no horizon passes the moved event, and a fresh history with no horizon replays a session
  // event far past 100 + H.
  assert.equal(sessionTimeHorizonFailure({ ...before, genesis: { ...before.genesis, sessionTimeHorizonMs: null } }, moved[last], last), undefined);
  const g = await setup(t, { sessionTimeHorizonMs: null });
  g.at(100 + H + 1);
  assert.equal((await core.openLocalSimulation(g.sessionConfig).run(g.op("op:1"))).status, "SIMULATION_RESULT");
  const unguarded = g.owner.exportHistory();
  assert.equal(unguarded[0].data.sessionTimeHorizonMs ?? null, null);
  assert.ok(unguarded.some((e) => e.type === "TRANSACTION_INTENT_ADMITTED" && e.timestamp === 100 + H + 1));
  assert.equal(replay(unguarded).status, "ACCEPTED");
});

test("A-179.2 / A-189: the record-only rebuild reproduces ownerTime", async (t) => {
  const f = await setup(t);
  const sim = core.openLocalSimulation(f.sessionConfig);
  f.at(700);
  await f.owner.createAgent({ id: "cal" });
  f.at(900);
  await sim.run(f.op("op:1"));
  const events = f.owner.exportHistory(), live = replay(events).state;
  for (let k = 1; k < events.length; k += 1) {
    const prefix = replay(events.slice(0, k + 1)).state;
    const rebuilt = rebuildReplayState(core.stateRecordsOf(prefix).map((e) => ({ kind: e.kind, key: e.key, record: e.record })), events);
    // Step 5d P2-12: compare the derived values (a missing field on both sides would have passed).
    const expected = ownerTimeOf(prefix);
    assert.notEqual(expected, undefined, `ownerTime is defined at ${k}`);
    assert.equal(ownerTimeOf(rebuilt), expected, `at ${k}`);
  }
  assert.equal(ownerTimeOf(live), 700);
});

test("A-179.4: a refusal past the horizon is not recorded (SESSION_TIME_HORIZON, the decision unaffected); a spooled entry stays spooled until ownerTime moves", async (t) => {
  const f = await setup(t);
  const runtime = openLocalRuntime(f.sessionConfig);
  const denied = (at) => ({ actorId: "bea", action: "delete", resource: "incident:42", claimedAt: at });
  f.at(100 + H + 1);
  assert.deepEqual(await runtime.recordRefusal({ request: denied(100 + H + 1) }), { recorded: false, reason: "SESSION_TIME_HORIZON" });
  assert.ok(core.REFUSAL_NOT_RECORDED_REASONS.includes("SESSION_TIME_HORIZON"));
  // A spooled entry of this actor: the drain keeps it while the horizon holds.
  const spool = core.refusalSpoolPathFor(f.config.historyFile);
  const { claimedAt: _drop, ...request } = denied(0);
  writeFileSync(spool, `${JSON.stringify({ version: core.REFUSAL_SPOOL_VERSION, refusalId: "refusal:spooled", attemptedAt: 50, request })}\n`);
  const kept = await core.drainRefusalSpool(f.config.historyFile, runtime, "bea", () => 100 + H + 1, () => false);
  assert.deepEqual(kept.map((o) => o.outcome), ["SESSION_TIME_HORIZON"]);
  assert.equal(core.spooledRefusalCount(f.config.historyFile), 1, "the engine inspection surface counts it");
  // An owner event moves ownerTime: the next drain records it.
  await f.owner.createAgent({ id: "cal" });
  const drained = await core.drainRefusalSpool(f.config.historyFile, runtime, "bea", () => 100 + H + 1, () => false);
  assert.deepEqual(drained.map((o) => o.outcome), ["RECORDED"]);
  assert.equal(core.spooledRefusalCount(f.config.historyFile), 0);
  assert.equal(f.owner.verify().ok, true);
});

test("A-179.4: the ▲ pre-check sits in the administrative prepare step: an OBLIGATION_CREATED past ownerTime + H is refused before signing (TRANSITION_REJECTED {SESSION_TIME_HORIZON}); at the bound it is written", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-sth-admin-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let tick = 100;
  const HZ = 3; // ownerTime 100: the run at 102 and the receipt at 103 pass; an obligation at 104 is past the bound
  const config = { historyFile: join(dir, "h.jsonl"), domain: createLocalDomain(), owner: "operations", controller: "operator", now: () => tick, nextKey: false, witness: false, sessionTimeHorizonMs: HZ };
  const owner = await createLocalOwner(config);
  const { keyPairFromPrivateKey } = await import("../src/crypto/suites.ts");
  const pair = keyPairFromPrivateKey("ed25519", "k:a", `0x${"3c".repeat(32)}`);
  for (const id of ["a", "b"]) await owner.createAgent({ id });
  await owner.createRole({ id: "reviewer" });
  await owner.declareSuccession({ id: "handover", from: "a", to: "b", role: "reviewer" });
  await owner.appoint({ agent: "a", role: "reviewer", tenure: "shift:1", number: 1, succession: "handover" });
  await owner.admitRuntime({ session: "s:a", agent: "a", epoch: 1, key: "k:a", credential: pair.credential, expiresAt: 1000 });
  await owner.grant({ id: "quant", to: "a", actions: ["pay"], resources: ["vendor"], expiresAt: 900 });
  await owner.grant({ id: "collect", to: "a", actions: ["OBLIGATE"], resources: ["vendor"], expiresAt: 900 });
  await owner.grant({ id: "review", to: "b", actions: ["record-collection-disposition"], resources: ["duty:42"], expiresAt: 900 });
  const a = { ...config, session: "s:a", signHash: signHashWith(pair) };
  const op = { id: "op:1", action: "pay", resource: "vendor", role: "reviewer", tenure: "shift:1", termsCommitment: commitTerms({ invoice: 1 }) };
  const sim = core.openLocalSimulation(a);
  tick = 102; await sim.run(op);
  tick = 103; await sim.recordReceipt(op);
  const obligation = { id: "duty:42", operation: op.id, description: "Review.", deadline: 800, succession: "handover", reviewAuthority: "review" };
  // Past the bound: the writer refuses before signing, and nothing is written (step 5c P2: the session signer is counted).
  tick = 100 + HZ + 1;
  const before = replay(owner.exportHistory()).state;
  let calls = 0;
  const counted = { ...a, signHash: async (h) => { calls += 1; return signHashWith(pair)(h); } };
  await assert.rejects(openLocalRuntime(counted).obligate(obligation), horizonRefusalOf(100, HZ));
  assert.equal(calls, 0, "the ▲ prepare step asked for no signature");
  assert.deepEqual(replay(owner.exportHistory()).head, before.head, "nothing was written");
  // An owner event that advances time moves ownerTime: the obligation is written.
  await owner.createAgent({ id: "c" });
  assert.equal(typeof (await openLocalRuntime(a).obligate(obligation)).eventId, "string");
  // The prepare step itself refuses that same transition on the state before the owner event (the duty and coordinator
  // writers append without appendEvent, so the ▲ check must live there).
  const written = owner.exportHistory().at(-1);
  assert.equal(written.type, "OBLIGATION_CREATED");
  const { administrativeAuthorization: _auth, ...data } = written.data;
  const transition = { id: "obligation:past", type: written.type, timestamp: 100 + HZ + 1, data };
  assert.throws(() => core.prepareAdministrativeEventState(before, { expectedDomain: before.genesis.domain, expectedHistoryHead: before.head, transition, runtimeSessionId: "s:a" }), horizonRefusalOf(100, HZ));
  assert.doesNotThrow(() => core.prepareAdministrativeEventState(before, { expectedDomain: before.genesis.domain, expectedHistoryHead: before.head, transition: { ...transition, timestamp: 100 + HZ }, runtimeSessionId: "s:a" }), "at the bound the prepare step passes");
  assert.equal(owner.verify().ok, true);
});

test("A-179.4: declareBudget warns when H ≥ a FIXED_WINDOW lengthMs (the budget is declared either way); a longer window, a NONE period or no horizon gives no warning", async (t) => {
  const f = await setup(t);
  const budget = (id, period) => ({ budgetId: id, subjects: { actorIds: null, roleIds: null, actions: ["spend"], resources: null }, metric: "amount", period, amountCap: "100", countCap: null, perOperationCap: null, notBefore: null, expiresAt: null });
  const window = (lengthMs) => ({ kind: "FIXED_WINDOW", lengthMs, originMs: 0, carryUnused: false, carryCap: null });
  const covered = await f.owner.declareBudget(budget("b-equal", window(H)));
  assert.match(covered.warning, /^SESSION_TIME_HORIZON_COVERS_WINDOW: .*1000 ms.*1000 ms/);
  assert.equal(f.state().budgets.has("b-equal"), true, "declared either way");
  assert.match((await f.owner.declareBudget(budget("b-short", window(H - 1)))).warning, /COVERS_WINDOW/);
  assert.equal((await f.owner.declareBudget(budget("b-long", window(H + 1)))).warning, undefined);
  assert.equal((await f.owner.declareBudget(budget("b-none", { kind: "NONE" }))).warning, undefined);
  const plain = await setup(t, { sessionTimeHorizonMs: undefined });
  assert.equal((await plain.owner.declareBudget(budget("b-plain", window(1)))).warning, undefined, "no horizon, no warning");
});

test("JOB75-03 / A-179.4: no session signature is asked for an event rule T3 refuses: run()'s declaration and admission, a signed append (recordEffect) and a receipt (the ▲ prepare step: the obligation test above)", async (t) => {
  const f = await setup(t);
  let calls = 0, onSign = () => {};
  const inner = f.sessionConfig.signHash;
  const counted = { ...f.sessionConfig, signHash: async (h) => { calls += 1; onSign(); return inner(h); } };
  const sim = core.openLocalSimulation(counted), runtime = openLocalRuntime(counted);
  const past = 100 + H + 1;
  // 1. The declaration: refused before the first signature.
  f.at(past); calls = 0;
  await assert.rejects(sim.run(f.op("op:t3-decl")), horizonRefusal(100));
  assert.equal(calls, 0, "declaration: no signature asked");
  // 2. The admission: the declaration is signed at the bound, then the clock passes it before the admission is signed.
  f.at(100 + H); calls = 0; onSign = () => { if (calls === 1) f.at(past); };
  await assert.rejects(sim.run(f.op("op:t3-adm")), horizonRefusal(100));
  assert.equal(calls, 1, "admission: only the declaration (within the bound) was signed");
  onSign = () => {};
  // 3. A signed append (EFFECT_RECORDED) and 4. a receipt, both on an operation run within the bound.
  f.at(100 + H); assert.equal((await sim.run(f.op("op:t3-ok"))).status, "SIMULATION_RESULT");
  f.at(past); calls = 0;
  await assert.rejects(runtime.recordEffect({ effectId: "effect:t3", intentId: "op:t3-ok", measurer: { kind: "SESSION", id: "bea" }, metric: "amount", unit: "cent", amount: 1n, observedAt: 100 }), horizonRefusal(100));
  assert.equal(calls, 0, "signed append: no signature asked");
  await assert.rejects(sim.recordReceipt(f.op("op:t3-ok")), horizonRefusal(100));
  assert.equal(calls, 0, "receipt: no signature asked");
});

test("step 5c P1-a / A-179.4: the durable coordinator's consumption record is refused before the session signs it when the clock passes the horizon after the admission; nothing is recorded", async (t) => {
  const f = await setup(t);
  let calls = 0;
  const inner = f.sessionConfig.signHash;
  // The run signs the declaration (1), the admission (2) and then the consumption record (3); the clock passes the bound
  // right after the admission is signed, so the consumption is stamped past ownerTime + H.
  const counted = { ...f.sessionConfig, signHash: async (h) => { calls += 1; const signature = await inner(h); if (calls === 2) f.at(100 + H + 1); return signature; } };
  f.at(100 + H);
  const before = f.owner.exportHistory().length;
  const result = await core.openLocalSimulation(counted).run(f.op("op:p1a"));
  assert.equal(calls, 2, "the consumption record asked for no signature");
  assert.equal(result.invocation?.status, "OUTCOME_UNKNOWN", JSON.stringify(result));
  assert.equal(result.invocation.recorded, false);
  assert.equal(result.invocation.notRecorded.reason, "SESSION_TIME_HORIZON", "r5.2 §10.1.1 item 7's not-recorded reason");
  const after = f.owner.exportHistory();
  assert.deepEqual(after.slice(before).map((e) => e.type), ["TRANSACTION_INTENT_DECLARED", "TRANSACTION_INTENT_ADMITTED"], "no consumption or outcome event was written");
});
