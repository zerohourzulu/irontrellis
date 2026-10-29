import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { referenceCore03 } from "./reference.mjs";
import { loadFactor } from "./helpers/timing.mjs";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling

const { createLocalDomain, createLocalOwner, openLocalOwner } = await import("../src/owner.ts");
const { openLocalSimulation, commitTerms } = await import("../src/simulation.ts");
const { openLocalRuntime } = await import("../src/runtime.ts");
const { openHistoryStore: openHistoryStoreStrict } = await import("../src/store.ts");
// Fixture writes to legacy and format-1 files (SPEC §16.1: those formats open read only by default; format 2 is the wire). These tests cover the earlier store writer, so the fence is off here.
const openHistoryStore = (path, options = {}) => openHistoryStoreStrict(path, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true, ...options });
const { generateKeyPair, signHashWith } = await import("../src/crypto/suites.ts");
const { LEGACY_FORMAT, TRELLIS_FORMAT } = await import("../src/events.ts");

const code = (value) => (e) => e.code === value;
const key = (format) => {
  const pair = generateKeyPair(format === LEGACY_FORMAT ? "eip191-personal-sign-keccak256" : "ed25519", "k");
  return { credential: pair.credential, signHash: signHashWith(pair) };
};
async function setup(t, format) {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-handover-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let tick = 100;
  const config = { historyFile: join(dir, "history.jsonl"), domain: createLocalDomain({ format }), owner: "operations", controller: "operator", now: () => tick, format, [FORMAT1_TEST_TOOLING]: true };
  const owner = await createLocalOwner(config), a = key(format), b = key(format);
  for (const id of ["bea", "alex"]) await owner.createAgent({ id });
  await owner.createRole({ id: "reviewer" });
  await owner.declareSuccession({ id: "handover", from: "bea", to: "alex", role: "reviewer" });
  await owner.appoint({ agent: "bea", role: "reviewer", tenure: "shift:1", number: 1, succession: "handover" });
  await owner.admitRuntime({ session: "session:bea", agent: "bea", epoch: 1, key: "key:bea", credential: a.credential, expiresAt: 200 });
  await owner.admitRuntime({ session: "session:alex", agent: "alex", epoch: 1, key: "key:alex", credential: b.credential, expiresAt: 200 });
  await owner.grant({ id: "collect", to: "bea", actions: ["read", "OBLIGATE"], resources: ["incident:42"], expiresAt: 180 });
  await owner.grant({ id: "review", to: "alex", actions: ["record-collection-disposition"], resources: ["duty:42"], expiresAt: 180 });
  const options = { ...config, session: "session:bea", signHash: a.signHash };
  const op = { id: "operation:42", action: "read", resource: "incident:42", role: "reviewer", tenure: "shift:1", termsCommitment: commitTerms({ subject: "Synthetic incident review" }) };
  const sim = openLocalSimulation(options), runtime = openLocalRuntime(options);
  const duty = { id: "duty:42", operation: op.id, description: "Review the collected material.", deadline: 170, succession: "handover", reviewAuthority: "review" };
  const handover = { id: "handover:42", rule: "handover", fromAgent: "bea", fromTenure: "shift:1", toAgent: "alex", toTenure: "shift:2", role: "reviewer", number: 2 };
  return { owner, config, options, op, sim, runtime, duty, handover, a, b, now: (n) => (tick = n) };
}
const count = (owner, type) => owner.exportHistory().filter((e) => e.type === type).length;

for (const format of [LEGACY_FORMAT, TRELLIS_FORMAT]) {
  const label = format === LEGACY_FORMAT ? "legacy" : "format 1";

  test(`${label}: a real simulated acknowledgment and signed receipt create a duty; succession grants no powers`, async (t) => {
    const { owner, config, options, op, sim, runtime, duty, handover, b } = await setup(t, format);
    await assert.rejects(runtime.obligate(duty), code("RECEIPT_UNAVAILABLE"));
    assert.equal((await sim.run(op)).invocation.status, "SUBMITTED");
    await assert.rejects(runtime.obligate(duty), code("RECEIPT_UNAVAILABLE"));
    assert.equal((await sim.recordReceipt(op)).recording.status, "ADMITTED");
    const created = await runtime.obligate(duty);
    assert.ok(created.eventId);
    const before = readFileSync(config.historyFile);
    assert.equal((await runtime.obligate(duty)).eventId, created.eventId);
    assert.deepEqual(readFileSync(config.historyFile), before);
    // The offboarding summary before the handover: one open duty held by bea, live grants that will not follow.
    const report = owner.handover("bea");
    assert.deepEqual(report.openDuties.map((d) => [d.kind, d.id, d.assignee, d.status]), [["OBLIGATION", "duty:42", "bea", "OPEN"]]);
    assert.deepEqual(report.liveGrants.map((g) => [g.authorityId, g.followsSuccession]), [["collect", false]]);
    assert.deepEqual(report.sessions.map((s) => [s.sessionId, s.current]), [["session:bea", true]]);
    assert.equal(report.survives.epistemicStatus, "ESTABLISHED");
    assert.equal((await owner.succeed(handover)).status, "HANDOVER_RECORDED");
    await assert.rejects(sim.run({ ...op, id: "old-process" }), code("RUNTIME_NOT_CURRENT"));
    assert.equal(owner.authorize({ actor: "alex", action: "read", resource: "incident:42" }).decision, "DENY");
    const after = owner.handover("bea");
    assert.equal(after.terminated, true);
    assert.deepEqual(after.tenures, []);
    assert.deepEqual(after.openDuties.map((d) => d.assignee), ["bea"]);
    assert.deepEqual(after.sessions.map((s) => s.current), [false]);
    const replacement = openLocalRuntime({ ...options, session: "session:alex", signHash: b.signHash });
    await assert.rejects(replacement.assign({ id: "assign:42", obligation: duty.id }));
    await owner.grant({ id: "assign", to: "alex", actions: ["ASSIGN_PERFORMANCE"], resources: [duty.id], expiresAt: 180 });
    const assigned = await replacement.assign({ id: "assign:42", obligation: duty.id });
    const completed = readFileSync(config.historyFile);
    assert.equal((await replacement.assign({ id: "assign:42", obligation: duty.id })).eventId, assigned.eventId);
    assert.equal((await openLocalOwner(config).succeed(handover)).status, "HANDOVER_RECORDED");
    assert.deepEqual(readFileSync(config.historyFile), completed);
    const events = owner.exportHistory();
    assert.equal(events.filter((e) => e.type === "OBLIGATION_CREATED").length, 1);
    assert.equal(events.find((e) => e.type === "OBLIGATION_PERFORMANCE_ASSIGNED").data.toAgentId, "alex");
    assert.equal(events.find((e) => e.type === "OBLIGATION_CREATED").data.record.status, "OPEN");
    assert.equal(owner.survives("bea").epistemicStatus, "ESTABLISHED");
    assert.deepEqual(owner.handover("alex").openDuties.map((d) => d.id), ["duty:42"]);
    assert.deepEqual(owner.handover("bea").openDuties, []);
  });

  test(`${label}: handover resumes after a failed second write and preserves retirement`, async (t) => {
    const { owner, config, handover } = await setup(t, format);
    const proto = Object.getPrototypeOf(openHistoryStore(config.historyFile)), original = proto.appendAtExpectedHead;
    proto.appendAtExpectedHead = function (event, head) { if (event.type === "ROLE_TRANSFERRED") throw Error("injected write failure"); return original.call(this, event, head); };
    try {
      await assert.rejects(owner.succeed(handover), (e) => e.code === "WRITE_UNCONFIRMED" && e.mayHaveCommitted === true);
    } finally {
      proto.appendAtExpectedHead = original;
    }
    assert.equal(owner.exportHistory().at(-1).type, "AGENT_TERMINATED");
    assert.equal((await openLocalOwner(config).succeed(handover)).status, "HANDOVER_RECORDED");
    assert.equal(count(owner, "AGENT_TERMINATED"), 1);
    assert.equal(count(owner, "ROLE_TRANSFERRED"), 1);
    await assert.rejects(owner.succeed({ ...handover, toTenure: "substituted" }), code("OPERATION_CONFLICT"));
  });

  test(`${label}: invalid handover is fully validated before retirement`, async (t) => {
    const { owner, config, handover } = await setup(t, format);
    const before = readFileSync(config.historyFile);
    await assert.rejects(owner.succeed({ ...handover, toAgent: "unregistered" }), code("TRANSITION_REJECTED"));
    assert.deepEqual(readFileSync(config.historyFile), before);
  });

  test(`${label}: signed duty creation rejects changed data for the same durable identity`, async (t) => {
    const { sim, op, runtime, duty } = await setup(t, format);
    await sim.run(op);
    await sim.recordReceipt(op);
    await runtime.obligate(duty);
    await assert.rejects(runtime.obligate({ ...duty, description: "Different work" }), code("OPERATION_CONFLICT"));
  });

  test(`${label}: revocation or expiry during duty signing cannot create the duty`, async (t) => {
    const { sim, op, options, a, owner, duty } = await setup(t, format);
    await sim.run(op);
    await sim.recordReceipt(op);
    const changed = openLocalRuntime({ ...options, signHash: async (hash) => { await owner.revoke("collect"); return a.signHash(hash); } });
    await assert.rejects(changed.obligate(duty), code("HISTORY_CONFLICT"));
    assert.equal(count(owner, "OBLIGATION_CREATED"), 0);
  });

  test(`${label}: administrative producer failures surface as stable owner-API codes, never as raw producer errors`, async (t) => {
    const { sim, op, options, a, owner, duty, runtime } = await setup(t, format);
    await sim.run(op);
    await sim.recordReceipt(op);
    // No OBLIGATE grant: the producer's PREPARE:POLICY_UNAVAILABLE becomes TRANSITION_REJECTED, with the phase:code kept in message and detail.
    await owner.revoke("collect");
    await assert.rejects(runtime.obligate(duty), (e) => e.name === "IronTrellisError" && e.code === "TRANSITION_REJECTED" && e.message.includes("PREPARE:POLICY_UNAVAILABLE") &&
      e.detail?.producerError === "PREPARE:POLICY_UNAVAILABLE" && e.detail.phase === "PREPARE" && e.detail.code === "POLICY_UNAVAILABLE");
    await owner.grant({ id: "collect-again", to: "bea", actions: ["OBLIGATE"], resources: ["incident:42"], expiresAt: 180 });
    // A throwing session signer (SIGN:SIGNER_FAILED) is SIGNER_FAILED; the signer's own error does not leak.
    const failing = openLocalRuntime({ ...options, signHash: async () => { throw new Error("private detail"); } });
    await assert.rejects(failing.obligate(duty), (e) => e.name === "IronTrellisError" && e.code === "SIGNER_FAILED" && !e.message.includes("private"));
    // A malformed signature is refused when the signed event is verified (VERIFY:INVALID_SIGNATURE → TRANSITION_REJECTED).
    const garbled = openLocalRuntime({ ...options, signHash: async () => "0x1234" });
    await assert.rejects(garbled.obligate(duty), (e) => e.code === "TRANSITION_REJECTED" && e.detail?.producerError === "VERIFY:INVALID_SIGNATURE");
    assert.equal(count(owner, "OBLIGATION_CREATED"), 0);
    assert.ok((await openLocalRuntime({ ...options, signHash: a.signHash }).obligate(duty)).eventId);
  });

  test(`${label}: administrative signing uses current policy after a slow signer returns`, async (t) => {
    const { sim, op, options, a, owner, duty, now } = await setup(t, format);
    await sim.run(op);
    await sim.recordReceipt(op);
    const slow = openLocalRuntime({ ...options, signHash: async (hash) => { now(181); return a.signHash(hash); } });
    await assert.rejects(slow.obligate(duty));
    assert.equal(count(owner, "OBLIGATION_CREATED"), 0);
  });
}

test("legacy: the reference Core 0.3 runtime completes a handover started by the port (and vice versa)", async (t) => {
  const legacy = await referenceCore03("local-owner.ts");
  const { owner, config, handover, op, sim, runtime, duty } = await setup(t, LEGACY_FORMAT);
  await sim.run(op);
  await sim.recordReceipt(op);
  await runtime.obligate(duty);
  const theirs = legacy.openLocalOwner({ historyFile: config.historyFile, domain: config.domain, owner: config.owner, controller: config.controller, now: config.now });
  assert.equal(theirs.succeed(handover).status, "HANDOVER_RECORDED");
  assert.equal((await owner.succeed(handover)).status, "HANDOVER_RECORDED");
  assert.equal(count(owner, "AGENT_TERMINATED"), 1);
  assert.deepEqual(JSON.stringify(theirs.survives("bea")), JSON.stringify(owner.survives("bea")));
});

// ---------------------------------------------------------------- long histories: the job path never snapshots or replays the history
const { approvedAdapterProfile, SIMULATED_ADAPTER_ID } = await import("../src/adapter-editions.ts");
/** A format-1 history of `total` events: the usual setup, then unrelated intent declarations by bea (no owner signature needed), appended without fsync. */
async function longHistory(t, total) {
  const context = await setup(t, TRELLIS_FORMAT);
  const store = openHistoryStore(context.config.historyFile, { fsync: false }), profile = approvedAdapterProfile(SIMULATED_ADAPTER_ID);
  const start = store.readAll().length;
  store.appendAll(Array.from({ length: total - start }, (_, k) => ({ id: `filler:${k}`, type: "TRANSACTION_INTENT_DECLARED", timestamp: 100, data: {
    intentId: `filler:${k}`, nonce: `nonce:${k}`, adapterProfile: profile, actorId: "bea", action: "read", resource: "incident:42", roleId: "reviewer", roleTenureId: "shift:1",
    termsCommitment: `0x${k.toString(16).padStart(64, "0")}` } })));
  assert.equal(store.readAll().length, total);
  return context;
}
const timed = async (f) => { const started = performance.now(); const value = await f(); return { value, ms: performance.now() - started }; };

// The bound is on the job (`run()`): it reads the store's cached state and never copies or replays the history. Opening the
// simulation replays the file once (the store's open path, ~70 µs/event); that one-time cost is reported under TRACE, not bounded here.
test("format 1: a simulated job on a 2,000-event history completes in under 200 ms", async (t) => {
  const { options, op } = await longHistory(t, 2_000);
  const opened = await timed(() => openLocalSimulation(options));
  const job = await timed(() => opened.value.run(op));
  if (process.env.TRACE) process.stderr.write(`2,000 events: open ${opened.ms.toFixed(1)} ms, run ${job.ms.toFixed(1)} ms\n`);
  assert.equal(job.value.status, "SIMULATION_RESULT");
  assert.equal(job.value.invocation.status, "SUBMITTED");
  // Scaled by the machine's current speed (helpers/timing.mjs; 1 on a quiet host), like the other timing bounds: a
  // loaded CI host must not fail it, an order-of-magnitude regression still does.
  const factor = loadFactor();
  assert.ok(job.ms < 200 * factor, `run() took ${job.ms.toFixed(1)} ms (bound 200 ms × load factor ${factor.toFixed(2)})`);
  // A repeat reconciles the original attempt (the adapter reads the same cached state).
  assert.equal((await opened.value.run(op)).status, "RECONCILIATION_ONLY");
});

test("format 1: a simulated job past the old 4,096-event adapter bound (5,000 events) is admitted, submitted and receipted", async (t) => {
  const { options, op, runtime, duty, owner } = await longHistory(t, 5_000);
  const sim = openLocalSimulation(options);
  const job = await timed(() => sim.run(op));
  if (process.env.TRACE) process.stderr.write(`5,000 events: run ${job.ms.toFixed(1)} ms\n`);
  assert.equal(job.value.status, "SIMULATION_RESULT");
  assert.equal(job.value.admission.status, "ADMITTED");
  assert.equal(job.value.invocation.status, "SUBMITTED");
  const reconciled = await sim.run(op);
  assert.equal(reconciled.status, "RECONCILIATION_ONLY");
  assert.equal(reconciled.result.status, "RETRY");
  assert.equal((await sim.recordReceipt(op)).recording.status, "ADMITTED");
  assert.ok((await runtime.obligate(duty)).eventId);
  assert.equal(owner.exportHistory().length, 5_000 + 5); // declaration, admission, consumption, receipt, obligation
});
