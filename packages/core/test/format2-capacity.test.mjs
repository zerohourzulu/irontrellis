// Capacity as a replay step (SPEC §5.2 + the control-event reserve addendum): the declared maxEvents rule of format 2
// (control events always admitted), the declared maxStateRecords, the reserve (CAPACITY_RESERVED for ◇/▲, ◆ admitted)
// and the hard cap (CAPACITY_EXCEEDED for everything), in records and in bytes, through replay, the store and the owner
// API; replay's canonical byte count equals the store's file size; format 1 keeps rc.1's API-only capacity.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling

const core = await import("../src/index.ts");
const { createLocalDomain, createLocalOwner, openLocalSimulation, commitTerms, capacityLimits, replay, capacityOf } = core;
const { setCapacityLimitsForTests } = await import("../src/capacity.ts"); // a test hook; not on a public subpath (step 5b review)
const { generateKeyPair, signHashWith } = await import("../src/crypto/suites.ts");
const { openHistoryStore } = await import("../src/store.ts");
const { TRELLIS_FORMAT } = await import("../src/events.ts");

const code = (value) => (e) => e.code === value;
async function setup(t, options = {}) {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-f2-capacity-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let tick = 100;
  const config = { historyFile: join(dir, "history.jsonl"), domain: createLocalDomain(), owner: "operations", controller: "operator", now: () => tick, ...options };
  const owner = await createLocalOwner(config);
  await owner.createAgent({ id: "bea" });
  await owner.createRole({ id: "reviewer" });
  await owner.appoint({ agent: "bea", role: "reviewer", tenure: "shift:1", number: 1 });
  const pair = generateKeyPair("ed25519", "key:1");
  await owner.admitRuntime({ session: "session:1", agent: "bea", epoch: 1, key: "key:1", credential: pair.credential, expiresAt: 10_000_000 });
  await owner.grant({ id: "read", to: "bea", actions: ["read"], resources: ["incident:42"], expiresAt: 10_000_000 });
  const runtime = openLocalSimulation({ ...config, session: "session:1", signHash: signHashWith(pair) });
  const op = (id) => ({ id, intentId: id, action: "read", resource: "incident:42", role: "reviewer", tenure: "shift:1", termsCommitment: commitTerms({ id }) });
  return { owner, config, runtime, op, now: (n) => (tick = n) };
}
const last = (owner) => owner.exportHistory().at(-1);

test("format 2 maxEvents: control events are always admitted; a new declaration is CAPACITY_CONTROL_ONLY; lifecycle records of declared jobs fit; replay agrees with the API", async (t) => {
  // 7 setup events (genesis, principal, agent, role, appointment, session, grant); a job needs 12 slots.
  const f = await setup(t, { maxEvents: 21 });
  const c = f.owner.capacity();
  assert.equal(c.eventCount, 7);
  assert.equal(c.canDeclareJob, true);
  assert.equal(c.reserved, false);
  assert.equal((await f.runtime.run(f.op("op:1"))).status, "SIMULATION_RESULT"); // declaration + admission (+ consumption in simulation)
  const after = f.owner.capacity();
  assert.equal(after.declaredJobs, 1);
  assert.equal(after.lifecycleReserved, 9); // 11 lifecycle types − admitted − consumed
  assert.equal(after.mode, "OPEN"); // 10 events + 9 reserved = 19 < 21
  assert.equal(after.canDeclareJob, false); // a job needs 12 free slots
  // A second job cannot start (◇ growth: 11 + 9 + 11 > 21); control events still can (format 2 rule); the first job's receipt still fits.
  await assert.rejects(f.runtime.run(f.op("op:2")), code("CAPACITY_CONTROL_ONLY"));
  for (let i = 0; i < 12; i += 1) await f.owner.createAgent({ id: `agent:${i}` });
  assert.equal(f.owner.capacity().mode, "CONTROL_ONLY");
  assert.ok(f.owner.exportHistory().length > 21, "control events passed the declared budget");
  assert.equal((await f.runtime.recordReceipt(f.op("op:1"))).status, "RECEIPT_RESULT");
  // Replay of the file agrees: every event accepted; appending a declaration to the replayed state is refused with the replay code.
  const events = f.owner.exportHistory();
  const r = replay(events);
  assert.equal(r.status, "ACCEPTED");
  assert.deepEqual(capacityOf(r.state), f.owner.capacity());
  const declaration = events.find((e) => e.type === "TRANSACTION_INTENT_DECLARED");
  const again = { ...declaration, id: "event:dup-declaration", data: { ...declaration.data, intentId: "op:9", nonce: "operation:op:9" } };
  const rr = replay([...events, again]);
  assert.equal(rr.status, "REJECTED");
  // (the forged declaration fails its signature before capacity: "first failure wins" — the capacity verdict is reached only by a well-formed event)
  assert.equal(rr.code, "DECLARATION_AUTHORIZATION_INVALID");
});

test("CAPACITY_CONTROL_ONLY is reported with the replay code when the declaration itself would be the overflow", async (t) => {
  const f = await setup(t, { maxEvents: 8 });
  await assert.rejects(f.runtime.run(f.op("op:1")), code("CAPACITY_CONTROL_ONLY"));
  assert.equal(f.owner.exportHistory().some((e) => e.type === "TRANSACTION_INTENT_DECLARED"), false);
  await f.owner.createAgent({ id: "cal" }); // ◆ always admitted
  assert.equal(last(f.owner).type, "AGENT_CREATED");
});

test("declared maxStateRecords: at the cap every ◇/▲ event is CAPACITY_EXCEEDED while control events are admitted", async (t) => {
  const f = await setup(t);
  const records = f.owner.stateRoot().recordCount;
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-f2-capacity-msr-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  // A-3 step 3 (judged after the event, R(p) > maxStateRecords): with the cap at the setup's records + 2 the declaration
  // itself (three records) is refused; at + 3 it fits exactly and the admission (more records) is refused.
  const h = await setup(t, { maxStateRecords: records + 2 });
  await assert.rejects(h.runtime.run(h.op("op:1")), code("CAPACITY_EXCEEDED"));
  assert.equal(h.owner.exportHistory().some((e) => e.type === "TRANSACTION_INTENT_DECLARED"), false);
  const g = await setup(t, { maxStateRecords: records + 3 });
  assert.equal(g.owner.capacity().maxStateRecords, records + 3);
  const run = await g.runtime.run(g.op("op:1"));
  assert.equal(run.status, "NOT_ADMITTED");
  assert.equal(run.admission.result.status, "INDETERMINATE");
  assert.equal(run.admission.result.replayCode, "CAPACITY_EXCEEDED");
  assert.equal(last(g.owner).type, "TRANSACTION_INTENT_DECLARED");
  assert.equal(g.owner.stateRoot().recordCount, records + 3);
  assert.equal(g.owner.capacity().mode, "CONTROL_ONLY"); // A-13: a declared limit reached
  await assert.rejects(g.runtime.recordRefusal({ request: { actorId: "bea", action: "read", resource: "nowhere", claimedAt: 100 } }), code("CAPACITY_EXCEEDED"));
  await g.owner.createAgent({ id: "cal" });
  await g.owner.checkpoint();
  const events = g.owner.exportHistory();
  assert.equal(replay(events).status, "ACCEPTED");
  const refusal = { id: "event:x", type: "REQUEST_REFUSED", timestamp: 100, data: {} };
  const r = replay([...events, refusal]);
  assert.equal(r.code, "EVENT_DATA_INVALID"); // schema first (SPEC §5 order); capacity is the last check
});

test("the hard limits and the control-event reserve, in records and in bytes (test-only lowered limits): three regimes", async (t) => {
  t.after(() => setCapacityLimitsForTests());
  const f = await setup(t);
  const events = f.owner.exportHistory();
  const state = replay(events).state;
  const records = state.stateRecords.size, bytes = state.canonicalBytes;
  assert.equal(bytes, statSync(f.config.historyFile).size, "replay's canonical line bytes equal the store's file size");
  const genesis = events[0], principal = events[1];
  const control = { ...events[2], id: "event:ctl" }; // a signed control event re-used as a probe would fail its signature; probe with capacityVerdict directly
  const probe = (limits, event) => { setCapacityLimitsForTests(limits); const verdict = core.capacityVerdict(state, event, core.formatTwoLineBytes(state.events.length, 100)); return verdict?.code; };
  const session = { ...events.find((e) => e.type === "TRANSACTION_INTENT_DECLARED") ?? { type: "TRANSACTION_INTENT_DECLARED", data: {} }, id: "event:probe", type: "TRANSACTION_INTENT_DECLARED" };
  // Below the reserve: everything admitted.
  assert.equal(probe({ maxStateRecords: records + 100, reservedStateRecords: 10 }, session), undefined);
  assert.equal(probe({ maxStateRecords: records + 100, reservedStateRecords: 10 }, control), undefined);
  // In the reserve (records ≥ max − reserve): ◇/▲ refused, ◆ admitted.
  assert.equal(probe({ maxStateRecords: records + 5, reservedStateRecords: 10 }, session), "CAPACITY_RESERVED");
  assert.equal(probe({ maxStateRecords: records + 5, reservedStateRecords: 10 }, control), undefined);
  assert.equal(probe({ maxStateRecords: records + 5, reservedStateRecords: 10 }, { ...events[0], id: "event:cp", type: "STATE_CHECKPOINT" }), undefined);
  // At the cap: everything refused.
  assert.equal(probe({ maxStateRecords: records, reservedStateRecords: 10 }, session), "CAPACITY_EXCEEDED");
  assert.equal(probe({ maxStateRecords: records, reservedStateRecords: 10 }, control), "CAPACITY_EXCEEDED");
  // Bytes: the same three regimes against the canonical line bytes.
  assert.equal(probe({ maxFileBytes: bytes + 10_000, reservedFileBytes: 1000 }, session), undefined);
  assert.equal(probe({ maxFileBytes: bytes + 500, reservedFileBytes: 1000 }, session), "CAPACITY_RESERVED");
  assert.equal(probe({ maxFileBytes: bytes + 500, reservedFileBytes: 1000 }, control), undefined);
  assert.equal(probe({ maxFileBytes: bytes + 50, reservedFileBytes: 1000 }, control), "CAPACITY_EXCEEDED"); // the probe line (100 + overhead bytes) would cross the cap
  setCapacityLimitsForTests();
  assert.deepEqual(capacityLimits(), { maxStateRecords: 1_048_576, maxFileBytes: 1024 ** 3, reservedStateRecords: 4096, reservedFileBytes: 16 * 1024 * 1024 });
  assert.equal(core.RESERVED_STATE_RECORDS, 4096);
  assert.equal(core.RESERVED_FILE_BYTES, 16 * 1024 * 1024);

  // End to end through the owner API, the store and replay: a reserve of 3 records below a cap of records + 6 (T_R = records + 3).
  // A-0.1/A-3: the reserve is judged AFTER the event (R(p) > T_R), the hard cap too (R(p) > HARD): no event overshoots the cap.
  setCapacityLimitsForTests({ maxStateRecords: records + 6, reservedStateRecords: 3 });
  assert.equal(f.owner.capacity().reserved, false);
  const run = await f.runtime.run(f.op("op:1")); // declaration adds 3 records (intent, nonce, event) → records + 3 = T_R: admitted; the admission would cross T_R
  assert.equal(run.status, "NOT_ADMITTED");
  assert.equal(run.admission.result.replayCode, "CAPACITY_RESERVED");
  assert.equal(f.owner.capacity().mode, "RESERVED");
  await assert.rejects(f.runtime.recordRefusal({ request: { actorId: "bea", action: "read", resource: "nowhere", claimedAt: 100 } }), code("CAPACITY_RESERVED"));
  assert.equal(f.owner.capacity().reserved, true);
  await f.owner.createAgent({ id: "cal" }); // ◆ admitted in the reserve (agent + event records: records + 5 ≤ the cap)
  await assert.rejects(f.owner.createAgent({ id: "dan" }), code("CAPACITY_EXCEEDED")); // records + 7 > the cap: refused (A-3 step 1, R(p) > HARD)
  await f.owner.checkpoint(); // one event record: records + 6 = the cap, admitted
  assert.equal(f.owner.capacity().mode, "FULL");
  await assert.rejects(f.owner.checkpoint(), code("CAPACITY_EXCEEDED")); // R(p−1) ≥ HARD: every event refused
  const full = f.owner.exportHistory();
  assert.equal(replay(full).status, "ACCEPTED");
  assert.equal(openHistoryStore(f.config.historyFile).state().head.position, full.length - 1);
  // Under the real limits the same file is far from any regime.
  setCapacityLimitsForTests();
  assert.equal(replay(full).status, "ACCEPTED");
  assert.equal(f.owner.capacity().reserved, false);
  assert.equal(genesis.type, "DEPLOYMENT_INITIALIZED"); assert.equal(principal.type, "PRINCIPAL_CREATED");
});

test("format 1 keeps rc.1's capacity: the replay step does not apply, control events are refused at maxEvents by the API", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-f2-capacity-f1-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const owner = await createLocalOwner({ historyFile: join(dir, "h.jsonl"), domain: createLocalDomain({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true }), owner: "o", controller: "c", now: () => 1, format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true, maxEvents: 4 });
  await owner.createAgent({ id: "a" });
  await owner.createAgent({ id: "b" });
  await assert.rejects(owner.createAgent({ id: "c" }), code("CAPACITY_CONTROL_ONLY"));
  const report = owner.capacity();
  assert.deepEqual([report.stateRecords, report.maxStateRecords, report.reserved, report.dutyReserved], [0, null, false, 0]);
  const events = owner.exportHistory();
  const extra = { ...events[2], id: "event:x", data: { ...events[2].data, agentId: "zed" } };
  // Replay does not enforce the declared budget in format 1 (G0 Q1): the extra event fails its control signature, not capacity.
  assert.equal(replay([...events, extra]).code, "CONTROL_AUTHORIZATION_INVALID");
});

test("A-0.1 / A-3 / A-13 / A-56.24: RESERVE_CLASS is the full non-control class; the reserve and the caps are judged after the event; record-reducing control events at the hard cap; capacity() fields; no maxStateRecords latch", async (t) => {
  t.after(() => setCapacityLimitsForTests());
  const f = await setup(t);
  const state = replay(f.owner.exportHistory()).state;
  const records = state.stateRecords.size;
  // RESERVE_CLASS: every non-control type incl. 14–16, no control type, not the genesis (A-0.1.1, A-56.1).
  for (const type of ["TRANSACTION_INTENT_CONSUMED", "TRANSACTION_OUTCOME_RECORDED", "RECEIPT_RECORDED", "TRANSACTION_INTENT_DECLARED", "REQUEST_REFUSED", "OBLIGATION_CREATED", "ATTEMPT_DUTY_POLICY_ACTIVATED"]) assert.ok(core.RESERVE_CLASS.has(type), type);
  for (const type of ["AUTHORITY_REVOKED", "STATE_CHECKPOINT", "BUDGET_DECLARED", "WITNESSES_UNBOUND", "DEPLOYMENT_INITIALIZED"]) assert.equal(core.RESERVE_CLASS.has(type), false, type);
  assert.equal(core.RESERVE_CLASS.size, core.EVENT_TYPES.length - 1 - core.CONTROL_EVENT_TYPES.size);
  assert.deepEqual([core.HARD_RECORDS, core.HARD_BYTES, core.RESERVE_THRESHOLD_RECORDS, core.RESERVE_THRESHOLD_BYTES], [1_048_576, 1_073_741_824, 1_044_480, 1_056_964_608]);
  const at = (type, recordsAfter, limits = { maxStateRecords: records + 11, reservedStateRecords: 10 }) => { setCapacityLimitsForTests(limits); return core.capacityVerdict(state, { id: "x", type, timestamp: 1, data: {} }, 200, undefined, recordsAfter)?.code; };
  // T_R = records + 1 here. Judged AFTER the event: the state before is below T_R, yet an event ending above it is refused.
  assert.equal(at("REQUEST_REFUSED", records + 1), undefined); // R(p) = T_R: not above
  assert.equal(at("REQUEST_REFUSED", records + 2), "CAPACITY_RESERVED"); // crossing T_R: refused (A-0 as written would have admitted it: R(p−1) < T_R)
  assert.equal(at("TRANSACTION_INTENT_CONSUMED", records + 2), "CAPACITY_RESERVED"); // the A-3 type-14 case under A-0.1
  assert.equal(at("AGENT_CREATED", records + 2), undefined); // control events use the reserve
  // Absolute limits, every event (A-3 step 1): R(p) > HARD; R(p−1) ≥ HARD refuses a record-reducing control event too.
  assert.equal(at("AGENT_CREATED", records + 12), "CAPACITY_EXCEEDED");
  assert.equal(at("WITNESSES_UNBOUND", records - 1, { maxStateRecords: records, reservedStateRecords: 10 }), "CAPACITY_EXCEEDED"); // removes a record, still refused at the cap
  assert.equal(at("WITNESSES_UNBOUND", records - 1, { maxStateRecords: records + 1, reservedStateRecords: 10 }), undefined);
  setCapacityLimitsForTests();
  // A-56.24: no permanent control-only latch — the declared maxStateRecords refuses a non-control event only while ITS resulting count exceeds it.
  const view = (size, maxStateRecords) => Object.create(state, { stateRecords: { value: { size } }, genesis: { value: { ...state.genesis, capacity: { maxEvents: null, maxStateRecords } } } });
  assert.equal(core.capacityVerdict(view(50, 50), { id: "x", type: "REQUEST_REFUSED", timestamp: 1, data: {} }, 200)?.code, "CAPACITY_EXCEEDED");
  assert.equal(core.capacityVerdict(view(49, 50), { id: "x", type: "REQUEST_REFUSED", timestamp: 1, data: {} }, 200, undefined, 50), undefined); // after a record-removing control event: room again
  // A-13: capacity() fields; controlAlwaysAdmitted dropped.
  const c = f.owner.capacity();
  assert.equal("controlAlwaysAdmitted" in c, false);
  assert.equal(c.mode, "OPEN");
  assert.equal(c.fileBytes, state.canonicalBytes);
  assert.equal(c.stateRecords, records);
  assert.deepEqual(c.reserveThresholds, { stateRecords: 1_044_480, fileBytes: 1_056_964_608 });
  assert.deepEqual(c.hardLimits, { stateRecords: 1_048_576, fileBytes: 1_073_741_824 });
});

test("A-2: a REQUEST_REFUSED at maxEvents is growth → CAPACITY_CONTROL_ONLY (writer and replay)", async (t) => {
  const f = await setup(t, { maxEvents: 8 });
  // 7 setup events; a refusal would be the 8th event plus nothing reserved: S(p) = 8 ≤ 8 admitted; the next one is refused.
  await f.runtime.recordRefusal({ request: { actorId: "bea", action: "read", resource: "nowhere", claimedAt: 100 } });
  await assert.rejects(f.runtime.recordRefusal({ request: { actorId: "bea", action: "write", resource: "nowhere", claimedAt: 100 } }), code("CAPACITY_CONTROL_ONLY"));
  assert.equal(f.owner.capacity().mode, "CONTROL_ONLY");
});
