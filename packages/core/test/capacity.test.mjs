/**
 * Capacity policy tests (port of Core 0.3 tests/core-0.3/capacity.test.mjs).
 *
 * The expectations changed with DESIGN §7: there is no 8-event control
 * reserve and no INCOMPATIBLE state; `CAPACITY_RESERVED` became
 * `CAPACITY_CONTROL_ONLY`; revocations, epoch advances, terminations,
 * transfers, receipts and obligation status changes are always admitted, even
 * past the budget; the lifecycle reservation of a declared job still keeps a
 * different job from spending its recovery space.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling

const { createLocalDomain: createLocalDomainDefault, createLocalOwner: createLocalOwnerDefault, openLocalOwner: openLocalOwnerDefault } = await import("../src/owner.ts");
// These tests cover the format-1 (and legacy) owner API; the API writes format 2 by default (SPEC §19), so format 1 is named for every handle and domain made here.
const createLocalDomain = (options = {}) => createLocalDomainDefault({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true, ...options });
const createLocalOwner = (options) => createLocalOwnerDefault({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true, ...options });
const openLocalOwner = (options) => openLocalOwnerDefault({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true, ...options });
const { openLocalSimulation, commitTerms } = await import("../src/simulation.ts");
const { capacityOf, assertCapacityTransition, LEGACY_CAPACITY_PROFILE } = await import("../src/capacity.ts");
const { openHistoryStore: openHistoryStoreStrict } = await import("../src/store.ts");
// Fixture writes to legacy and format-1 files (SPEC §16.1: those formats open read only by default; format 2 is the wire). These tests cover the earlier store writer, so the fence is off here.
const openHistoryStore = (path, options = {}) => openHistoryStoreStrict(path, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true, ...options });
const { replay } = await import("../src/replay.ts");
const { generateKeyPair, signHashWith } = await import("../src/crypto/suites.ts");
const { LEGACY_FORMAT, TRELLIS_FORMAT } = await import("../src/events.ts");
const { EngineError } = await import("../src/errors.ts");

const code = (c) => (e) => e.code === c;
const JOB_FOOTPRINT = 12; // one declaration + eleven lifecycle record types
async function setup(t) {
  const directory = mkdtempSync(join(tmpdir(), "irontrellis-capacity-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const pair = generateKeyPair("eip191-personal-sign-keccak256", "key");
  const config = { historyFile: join(directory, "history.jsonl"), domain: createLocalDomain({ format: LEGACY_FORMAT, [FORMAT1_TEST_TOOLING]: true }), owner: "owner", controller: "host", now: () => 100, format: LEGACY_FORMAT, [FORMAT1_TEST_TOOLING]: true };
  const owner = await createLocalOwner(config);
  await owner.createAgent({ id: "worker" });
  await owner.createAgent({ id: "successor" });
  await owner.createRole({ id: "role" });
  await owner.appoint({ agent: "worker", role: "role", tenure: "tenure", number: 1 });
  await owner.declareSuccession({ id: "succession", from: "worker", to: "successor", role: "role" });
  await owner.admitRuntime({ session: "session", agent: "worker", epoch: 1, key: "key", address: pair.credential, expiresAt: 1000 });
  await owner.grant({ id: "permission", to: "worker", actions: ["read"], resources: ["doc"], expiresAt: 1000 });
  const options = { ...config, session: "session", signHash: signHashWith(pair) };
  const op = { id: "job", action: "read", resource: "doc", role: "role", tenure: "tenure", termsCommitment: commitTerms({ case: "synthetic" }) };
  const runtime = openLocalSimulation(options);
  // Raw writes construct fixtures only; not a supported application path.
  const fill = (n) => {
    const raw = openHistoryStore(config.historyFile), count = raw.readAll().length;
    raw.appendAll(Array.from({ length: n }, (_, i) => ({ id: `padding:${count}:${i}`, type: "AGENT_CREATED", timestamp: 100, data: { agentId: `padding:${count}:${i}`, principalId: "owner", controllerId: "host", initialControlEpoch: 1 } })));
  };
  const capacity = () => owner.capacity();
  const free = () => { const c = capacity(); return c.maxEvents - c.eventCount - c.lifecycleReserved; };
  return { pair, directory, config, owner, options, op, runtime, fill, capacity, free };
}
const count = (owner, type) => owner.exportHistory().filter((e) => e.type === type).length;

test("legacy profile: 96 events, lifecycle reservation, no control reserve, revocation always admitted", async (t) => {
  const f = await setup(t);
  const fresh = f.capacity();
  assert.equal(fresh.profile, "continuity-managed-capacity/1");
  assert.equal(fresh.maxEvents, LEGACY_CAPACITY_PROFILE.maxEvents);
  assert.deepEqual([fresh.mode, fresh.canDeclareJob, fresh.lifecycleReserved, fresh.declaredJobs, fresh.controlAlwaysAdmitted, fresh.pointInTimeOnly, fresh.grantsAuthority], ["OPEN", true, 0, 0, true, true, false]);
  assert.equal("controlReserved" in fresh, false);
  await f.runtime.run(f.op);
  assert.equal(f.capacity().declaredJobs, 1);
  assert.equal(f.capacity().lifecycleReserved, 9); // ADMITTED and CONSUMED already recorded
  f.fill(f.free());
  const drained = f.capacity();
  assert.equal(drained.mode, "CONTROL_ONLY");
  assert.equal(drained.canDeclareJob, false);
  assert.equal(drained.eventCount + drained.lifecycleReserved, drained.maxEvents);
  const before = readFileSync(f.config.historyFile);
  await assert.rejects(f.owner.createAgent({ id: "extra" }), code("CAPACITY_CONTROL_ONLY"));
  await assert.rejects(f.owner.grant({ id: "more", to: "worker", actions: ["read"], resources: ["doc"], expiresAt: 1000 }), code("CAPACITY_CONTROL_ONLY"));
  await assert.rejects(f.runtime.run({ ...f.op, id: "extra-job" }), code("CAPACITY_CONTROL_ONLY"));
  assert.deepEqual(readFileSync(f.config.historyFile), before);
  // Lifecycle records of the admitted job still fit: they spend their own reservation.
  const reopened = openLocalSimulation(f.options);
  assert.equal((await reopened.run(f.op)).status, "RECONCILIATION_ONLY");
  assert.equal((await reopened.recordReceipt(f.op)).status, "RECEIPT_RESULT");
  const afterReceipt = f.capacity();
  assert.equal(afterReceipt.eventCount, drained.eventCount + 1);
  assert.equal(afterReceipt.lifecycleReserved, drained.lifecycleReserved - 1);
  assert.equal((await reopened.recordReceipt(f.op)).status, "ALREADY_RECORDED");
  assert.equal(f.capacity().eventCount, afterReceipt.eventCount);
  // Control that withdraws or transfers power is always admitted, even past the budget (Core 0.3 refused with CAPACITY_RESERVED / INCOMPATIBLE).
  const owner = openLocalOwner(f.config);
  await owner.revoke("permission");
  await owner.advanceEpoch({ agent: "worker", from: 1, to: 2 });
  await owner.succeed({ id: "handover", rule: "succession", fromAgent: "worker", fromTenure: "tenure", toAgent: "successor", toTenure: "next", role: "role", number: 2 });
  const full = f.capacity();
  assert.equal(full.mode, "CONTROL_ONLY");
  assert.equal(full.remainingPhysicalEvents, full.maxEvents - full.eventCount);
  assert.ok(full.eventCount + full.lifecycleReserved > full.maxEvents);
  assert.deepEqual(capacityOf(openHistoryStore(f.config.historyFile).state()), full);
  assert.deepEqual(capacityOf(replay(owner.exportHistory()).state), full);
  await assert.rejects(owner.createAgent({ id: "still-refused" }), code("CAPACITY_CONTROL_ONLY"));
});

test("failed signing retains the original reservation; a different job cannot spend it", async (t) => {
  const f = await setup(t);
  f.fill(f.free() - JOB_FOOTPRINT);
  let calls = 0;
  const runtime = openLocalSimulation({ ...f.options, signHash: async () => { calls++; throw Error("unavailable"); } });
  await assert.rejects(runtime.run(f.op), code("SIGNER_FAILED"));
  assert.equal(calls, 1);
  assert.equal(f.capacity().declaredJobs, 1);
  assert.equal(f.free(), 0);
  assert.equal(f.capacity().mode, "CONTROL_ONLY");
  const before = readFileSync(f.config.historyFile);
  await assert.rejects(f.runtime.run({ ...f.op, id: "other" }), code("CAPACITY_CONTROL_ONLY"));
  assert.deepEqual(readFileSync(f.config.historyFile), before);
  assert.equal((await f.runtime.run(f.op)).status, "SIMULATION_RESULT");
});

test("signer cannot let another managed writer spend recovery space", async (t) => {
  const f = await setup(t);
  f.fill(f.free() - JOB_FOOTPRINT);
  const runtime = openLocalSimulation({ ...f.options, signHash: async (hash) => {
    await assert.rejects(f.owner.createAgent({ id: "intruder" }), code("CAPACITY_CONTROL_ONLY"));
    return f.options.signHash(hash);
  } });
  assert.equal((await runtime.run(f.op)).invocation.status, "SUBMITTED");
  assert.equal(f.capacity().mode, "CONTROL_ONLY");
});

test("control during signing denies stale admission while keeping the reservation", async (t) => {
  const f = await setup(t);
  f.fill(f.free() - JOB_FOOTPRINT);
  let first = true;
  const runtime = openLocalSimulation({ ...f.options, signHash: async (hash) => { if (first) { first = false; await f.owner.revoke("permission"); } return f.options.signHash(hash); } });
  await assert.rejects(runtime.run(f.op), code("HISTORY_CONFLICT"));
  assert.equal(count(f.owner, "TRANSACTION_INTENT_ADMITTED"), 0);
  assert.equal(count(f.owner, "AUTHORITY_REVOKED"), 1); // the revocation was admitted with zero free space
  assert.equal(f.capacity().declaredJobs, 1);
});

test("over-budget history remains readable, refuses new work and still admits control", async (t) => {
  const f = await setup(t);
  f.fill(97 - f.capacity().eventCount);
  assert.equal(f.capacity().mode, "CONTROL_ONLY");
  assert.equal(f.capacity().remainingPhysicalEvents, 0);
  assert.equal(f.owner.exportHistory().length, 97);
  await assert.rejects(f.runtime.run(f.op), code("CAPACITY_CONTROL_ONLY"));
  await assert.rejects(f.owner.createAgent({ id: "extra" }), code("CAPACITY_CONTROL_ONLY"));
  assert.equal(f.owner.exportHistory().length, 97);
  await f.owner.revoke("permission"); // Core 0.3: CAPACITY_INCOMPATIBLE; IronTrellis never blocks a revocation
  assert.equal(f.owner.exportHistory().length, 98);
  assert.equal(f.owner.authorize({ actor: "worker", action: "read", resource: "doc" }).decision, "DENY");
});

test("wide events are refused by the legacy per-event bounds; the policy is a pure function of the replayed state", async (t) => {
  const f = await setup(t), before = readFileSync(f.config.historyFile), resources = Array.from({ length: 32 }, (_, i) => `resource:${i}`);
  // 32 array members are the bound; the grant below carries 33 (one action + 32 resources).
  await assert.rejects(f.owner.grant({ id: "wide", to: "worker", actions: ["read"], resources, expiresAt: 1000 }), code("CAPACITY_EVENT_LIMIT"));
  assert.deepEqual(readFileSync(f.config.historyFile), before);
  const state = openHistoryStore(f.config.historyFile).state();
  assert.throws(() => assertCapacityTransition(state, [{ id: "x", type: "AGENT_CREATED", timestamp: 100, data: { agentId: "x", principalId: "owner", controllerId: "host", initialControlEpoch: 1, resources: [...resources, "one-more"] } }]), (e) => e instanceof EngineError && e.code === "CAPACITY_EVENT_LIMIT");
  assertCapacityTransition(state, [{ id: "x", type: "AGENT_CREATED", timestamp: 100, data: { agentId: "x", principalId: "owner", controllerId: "host", initialControlEpoch: 1 } }]);
});

test("format 1: unlimited by default; a genesis budget refuses growth in CONTROL_ONLY mode but never a revocation", async (t) => {
  const directory = mkdtempSync(join(tmpdir(), "irontrellis-capacity-1-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const base = { domain: createLocalDomain(), owner: "owner", controller: "host", now: () => 100 };
  const unlimited = await createLocalOwner({ ...base, historyFile: join(directory, "unlimited.jsonl") });
  assert.deepEqual([unlimited.capacity().profile, unlimited.capacity().maxEvents, unlimited.capacity().mode, unlimited.capacity().canDeclareJob, unlimited.capacity().remainingPhysicalEvents], ["irontrellis-capacity/1", null, "OPEN", true, null]);
  for (let i = 0; i < 40; i++) await unlimited.createAgent({ id: `agent:${i}` });
  assert.equal(unlimited.capacity().mode, "OPEN");
  await unlimited.grant({ id: "wide", to: "agent:0", actions: ["read"], resources: Array.from({ length: 32 }, (_, i) => `resource:${i}`), expiresAt: 1000 });
  // A new history starts with two events: genesis (which carries the next-key commitment) and principal.
  const budget = await createLocalOwner({ ...base, historyFile: join(directory, "budget.jsonl"), maxEvents: 6 });
  assert.equal(budget.exportHistory().length, 2);
  assert.equal(budget.capacity().maxEvents, 6);
  for (const id of ["a", "b", "c", "d"]) await budget.createAgent({ id });
  assert.equal(budget.capacity().mode, "CONTROL_ONLY");
  assert.equal(budget.capacity().remainingPhysicalEvents, 0);
  await assert.rejects(budget.createAgent({ id: "e" }), code("CAPACITY_CONTROL_ONLY"));
  await assert.rejects(budget.grant({ id: "g", to: "a", actions: ["read"], resources: ["doc"], expiresAt: 1000 }), code("CAPACITY_CONTROL_ONLY"));
  const almost = await createLocalOwner({ ...base, historyFile: join(directory, "almost.jsonl"), maxEvents: 4 });
  await almost.createAgent({ id: "a" });
  await almost.grant({ id: "g", to: "a", actions: ["read"], resources: ["doc"], expiresAt: 1000 });
  await assert.rejects(almost.createAgent({ id: "b" }), code("CAPACITY_CONTROL_ONLY"));
  await almost.revoke("g");
  await almost.advanceEpoch({ agent: "a", from: 1, to: 2 });
  assert.equal(almost.exportHistory().length, 6);
  assert.equal(almost.capacity().mode, "CONTROL_ONLY");
  assert.equal(almost.format, TRELLIS_FORMAT);
});

// ---------------------------------------------------------------- real processes: the lock and the reservation hold across process death
const WORKER = `
import { readFileSync } from "node:fs";
const { openLocalSimulation } = await import(${JSON.stringify(new URL("../src/simulation.ts", import.meta.url).href)});
const { keyPairFromPrivateKey, signHashWith } = await import(${JSON.stringify(new URL("../src/crypto/suites.ts", import.meta.url).href)});
const { FORMAT1_TEST_TOOLING } = await import(${JSON.stringify(new URL("../src/internal-format1.ts", import.meta.url).href)}); // A-206.1: the src copy's mark
const [file, mode, id] = process.argv.slice(1);
const data = JSON.parse(readFileSync(file, "utf8"));
const sign = signHashWith(keyPairFromPrivateKey("eip191-personal-sign-keccak256", "key", data.privateKey));
const open = () => openLocalSimulation({ ...data.config, [FORMAT1_TEST_TOOLING]: true, now: () => 100, session: "session", signHash: async (hash) => {
  if (mode === "kill") { process.kill(process.pid, "SIGKILL"); await new Promise(() => {}); }
  return sign(hash);
} });
// store.ts #reload reads the file before the pinned head, so an open that lands between a
// concurrent writer's append and its pin sees a spurious ROLLBACK_DETECTED, or (a multi-page line still being
// copied) an incomplete last record; retry once (reported to the store owner).
let runtime;
try { runtime = open(); } catch (error) { if (error.code !== "ROLLBACK_DETECTED" && error.code !== "INVALID_HISTORY") throw error; runtime = open(); }
try { const result = await runtime.run({ ...data.op, id: id ?? data.op.id }); console.log(JSON.stringify({ status: result.status, admitted: result.admission?.status })); }
catch (error) { console.log(JSON.stringify({ refused: error.code ?? error.name })); }
`;
function child(f, mode, id) {
  const { writeFileSync } = require("node:fs");
  const file = join(f.directory, `worker-${id.replaceAll(":", "-")}.json`);
  writeFileSync(file, JSON.stringify({ privateKey: f.pair.privateKey, config: { ...f.config, now: undefined }, op: f.op }), { mode: 0o600 });
  return new Promise((resolve, reject) => {
    const p = spawn(process.execPath, ["--experimental-strip-types", "--input-type=module", "-e", WORKER, file, mode, id], { stdio: ["ignore", "pipe", "pipe"] });
    let output = "", errors = "";
    p.stdout.on("data", (x) => (output += x));
    p.stderr.on("data", (x) => (errors += x));
    p.on("error", reject);
    p.on("exit", (exitCode, signal) => resolve({ code: exitCode, signal, output, errors }));
  });
}
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);

test("real process death after declaration preserves reservation and permits only the original job", async (t) => {
  const f = await setup(t);
  f.fill(f.free() - JOB_FOOTPRINT);
  const result = await child(f, "kill", "job");
  // Windows has no signals: a process.kill(pid, "SIGKILL") there is TerminateProcess, seen by the parent as exit code 1.
  if (process.platform === "win32") assert.equal(result.code, 1, result.errors);
  else assert.equal(result.signal, "SIGKILL", result.errors);
  assert.equal(f.capacity().declaredJobs, 1);
  assert.equal(f.free(), 0);
  await assert.rejects(f.runtime.run({ ...f.op, id: "replacement-id" }), code("CAPACITY_CONTROL_ONLY"));
  assert.equal((await f.runtime.run(f.op)).invocation.status, "SUBMITTED");
  assert.equal(count(f.owner, "TRANSACTION_INTENT_ADMITTED"), 1);
});

test("two real process contenders cannot reserve the final job space twice", async (t) => {
  const f = await setup(t);
  f.fill(f.free() - JOB_FOOTPRINT);
  const results = await Promise.all([child(f, "run", "job:a"), child(f, "run", "job:b")]);
  for (const r of results) { assert.equal(r.code, 0, r.errors); assert.equal(r.signal, null); }
  assert.equal(f.capacity().declaredJobs, 1);
  assert.equal(count(f.owner, "TRANSACTION_INTENT_ADMITTED"), 1);
  assert.equal(f.capacity().mode, "CONTROL_ONLY");
});
