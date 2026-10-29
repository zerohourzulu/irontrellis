// T8 long case (BUILD §4): a format-2 history of ≥ 1,100 events and > 6 MiB of canonical event text, written through the
// API (padding grants with long resource lists, simulated admissions, receipt records, an activated duty policy with a
// disposition and a contest). The store reopened from its snapshot (CHECKPOINT_RESUME) and a copy reopened by full replay
// give the same answers to authorize, why, responsible, survives, headroom, capacity, the record set and the root, as does
// replay of the event list; inspectAttemptHistory agrees; receipt create/verify, a new admission and the duty events
// written through each reopened handle at the same clock are byte-identical. Reopen times are reported (t.diagnostic).
// Slow (about a minute on the build machine): it builds the history through the API once. The resumed store is the one the
// owner leaves after an owner-signed checkpoint at the head (a snapshot is seeded only from an owner-signed root, A-19/A-20).
import { test } from "node:test";
import assert from "node:assert/strict";
import { copyFileSync, readdirSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";

const core = await import("../src/index.ts");
const { observeState } = await import("../src/observation.ts");
const { headroom } = await import("../src/budgets.ts");
const { capacityOf } = await import("../src/capacity.ts");
const { openHistoryStore, storeCounters, resetStoreCountersForTests } = await import("../src/store.ts");
const { createReceiptState, verifyReceiptState, RECEIPT_VERIFICATION_VERSION } = await import("../src/receipts.ts");
const { dispositionFixture, signHash } = await import("./helpers/duty-fixture.mjs");

const json = (value) => JSON.stringify(value, (_key, v) => (typeof v === "bigint" ? `${v.toString()}n` : v instanceof Map ? [...v] : v instanceof Set ? [...v] : v));
const records = (state) => core.stateRecordsOf(state).map((e) => json({ kind: e.kind, key: e.key, record: e.record })).join("\n");
// The owner API takes at most 32 actions and 32 resources of at most 128 characters per grant: about 8.6 KB of canonical text.
const PADDING = 800, LIST = 32;
const resourceOf = (n, r) => `archive/${String(n).padStart(4, "0")}/${String(r).padStart(2, "0")}/${"x".repeat(108)}`;
const actionOf = (r) => `archive-${String(r).padStart(2, "0")}-${"y".repeat(100)}`;

function answersOf(state, grid) {
  const out = { root: core.stateRootOf(state), projectionHead: core.projectionHeadAt(state, state.head.position), head: state.head, records: records(state), capacity: capacityOf(state), at: {} };
  for (const at of grid.times) {
    const o = observeState(state, { at });
    out.at[at] = {
      authorize: grid.requests.map((q) => o.authorize(q).evidence), why: grid.requests.map((q) => o.why(q)), responsible: grid.requests.map((q) => o.responsible(q)),
      survives: grid.agents.map((agent) => o.survives(agent)), headroom: grid.budgets.map((id) => headroom(state, id, at)), duty: o.inspectDutyPolicy("duty"),
    };
  }
  return json(out);
}

test("T8: a ≥ 1,100-event, > 6 MiB format-2 history answers from its snapshot exactly as a full replay; writes through both reopened handles are byte-identical", { timeout: 900_000 }, async (t) => {
  const started = performance.now();
  const x = await dispositionFixture(t);
  const { owner } = x;
  await owner.grant({ id: "pay", to: "worker", actions: ["pay"], resources: ["vendor"], expiresAt: 10000, maxAmount: 1_000_000n });
  await owner.declareBudget({ budgetId: "b-pay", subjects: { actorIds: null, roleIds: ["role"], actions: ["pay"], resources: null }, metric: "amount", period: { kind: "FIXED_WINDOW", lengthMs: 1000, originMs: 0, carryUnused: true, carryCap: "100" }, amountCap: "100000", countCap: null, perOperationCap: null, notBefore: null, expiresAt: null });
  const sim = core.openLocalSimulation(x.setupOptions);
  const pay = (n) => ({ id: `pay:${n}`, intentId: `pay:${n}`, action: "pay", resource: "vendor", role: "role", tenure: "tenure", amount: BigInt(n + 1), termsCommitment: core.commitTerms({ invoice: n }) });
  for (let n = 0; n < PADDING; n += 1) {
    await owner.grant({ id: `pad:${n}`, to: "replacement", actions: Array.from({ length: LIST }, (_, r) => actionOf(r)), resources: Array.from({ length: LIST }, (_, r) => resourceOf(n, r)), expiresAt: 10000 });
    if (n % 8 === 0) assert.equal((await sim.run(pay(n))).invocation.status, "SUBMITTED");
    if (n % 16 === 0) assert.equal((await sim.recordReceipt(pay(n))).recording.status, "ADMITTED");
    if (n === PADDING / 2) await x.duties.dispose(x.input);
  }
  await x.duties.contest(x.contest("long-case"));
  // The owner signs a checkpoint at the head: a snapshot resumes only from an owner-signed root (A-19, A-20); the
  // runtime and duty handles above append without one.
  await owner.checkpoint({ checkpointId: "cp:t8" });
  const events = x.events;
  const canonicalBytes = events.reduce((sum, e) => sum + Buffer.byteLength(core.canonicalEncode(e)), 0);
  assert.ok(events.length >= 1100, `${events.length} events`);
  assert.ok(canonicalBytes > 6 * 1024 * 1024, `${canonicalBytes} canonical bytes`);
  const types = new Set(events.map((e) => e.type));
  for (const type of ["TRANSACTION_INTENT_DECLARED", "TRANSACTION_INTENT_ADMITTED", "TRANSACTION_INTENT_CONSUMED", "RECEIPT_RECORDED", "ATTEMPT_DUTY_POLICY_ACTIVATED", "ATTEMPT_DUTY_DISPOSITION_RECORDED", "ATTEMPT_DUTY_CONTEST_RECORDED"]) assert.ok(types.has(type), type);
  const built = performance.now();

  // A copy without the snapshot: the history, its pin and its keys.
  const copy = mkdtempSync(join(tmpdir(), "irontrellis-t8-copy-"));
  t.after(() => rmSync(copy, { recursive: true, force: true }));
  const file = x.config.historyFile, name = file.slice(x.dir.length + 1);
  for (const entry of readdirSync(x.dir)) if (entry.startsWith(name) && !entry.includes(".state")) copyFileSync(join(x.dir, entry), join(copy, entry));
  const copyFile = join(copy, name);

  resetStoreCountersForTests();
  let t0 = performance.now();
  const resumed = openHistoryStore(file, { trust: "CHECKPOINT_RESUME", witness: false });
  const stateR = resumed.state();
  const resumeMs = performance.now() - t0;
  assert.equal(resumed.loadedBy(), "CHECKPOINT_RESUME", JSON.stringify(storeCounters));
  assert.equal(storeCounters.resumes, 1, "the reopen resumed from the snapshot");
  t0 = performance.now();
  const replayed = openHistoryStore(copyFile, { trust: "FULL_REPLAY", witness: false });
  const stateF = replayed.state();
  const fullMs = performance.now() - t0;
  t0 = performance.now();
  const direct = core.replay(events);
  const replayMs = performance.now() - t0;
  assert.equal(direct.status, "ACCEPTED");

  const grid = {
    requests: [
      { actor: "worker", action: "pay", resource: "vendor", amount: 5n }, { actor: "worker", action: "pay", resource: "vendor", amount: 10n ** 9n }, { actor: "worker", action: "inspect", resource: "incident" },
      { actor: "replacement", action: actionOf(3), resource: resourceOf(7, 3) }, { actor: "replacement", action: actionOf(3), resource: "elsewhere" }, { actor: "nobody", action: "pay", resource: "vendor" },
    ],
    agents: ["worker", "replacement", "nobody"], budgets: ["b-pay", "none"], times: [x.now(), x.now() + 2000],
  };
  const answers = answersOf(direct.state, grid);
  assert.equal(answersOf(stateR, grid), answers, "the snapshot-resumed store answers as the full replay");
  assert.equal(answersOf(stateF, grid), answers, "the fully replayed store answers as the replay of the event list");
  assert.deepEqual(json(core.inspectAttemptHistory(resumed.readAll())), json(core.inspectAttemptHistory(events)), "inspectAttemptHistory");
  // Receipt create/verify over each state.
  const intentId = "pay:1500";
  assert.equal((await sim.run(pay(1500))).invocation.status, "SUBMITTED"); // a consumed intent at the head, not yet receipted
  const after = x.events, stateAfterR = openHistoryStore(file, { trust: "CHECKPOINT_RESUME", witness: false }).state(), stateAfterF = core.replay(after).state;
  const receiptInput = { intentId, issuedAt: x.now(), externalOutcome: "SIMULATED" };
  const artifactR = await createReceiptState(stateAfterR, receiptInput, { keyId: "key", signHash }), artifactF = await createReceiptState(stateAfterF, receiptInput, { keyId: "key", signHash });
  assert.equal(json(artifactR), json(artifactF), "receipt create");
  const verifyInput = { operationVersion: RECEIPT_VERIFICATION_VERSION, artifact: artifactR, expectedDomain: x.config.domain, verifierTime: x.now() };
  assert.equal(json(verifyReceiptState(stateAfterR, verifyInput)), json(verifyReceiptState(stateAfterF, verifyInput)), "receipt verify");
  const verified = verifyReceiptState(stateAfterF, verifyInput);
  assert.equal(verified.status, "EVALUATED");
  for (const axis of ["contentIntegrity", "signaturePossession", "issuerAuthentication", "historicalAuthorization", "freshness"]) assert.equal(verified[axis].status, "PASS", axis);
  // Writes at the same clock through a handle on each copy: admission (run), receipt record, a second disposition — byte-identical events.
  for (const entry of readdirSync(x.dir)) if (entry.startsWith(name) && !entry.includes(".state")) copyFileSync(join(x.dir, entry), join(copy, entry));
  const write = async (historyFile, trust) => {
    const options = { ...x.setupOptions, historyFile, trust };
    const before = core.openLocalOwner({ ...x.config, historyFile, trust }).exportHistory().length;
    assert.equal((await core.openLocalSimulation(options).run(pay(2000))).invocation.status, "SUBMITTED");
    assert.equal((await core.openLocalSimulation(options).recordReceipt(pay(2000))).recording.status, "ADMITTED");
    const duties = core.openLocalDutyPolicy({ ...x.options, historyFile, trust, signHash, attester: { session: "session", signHash } });
    await duties.dispose({ ...x.input, id: "escalate", disposition: "ESCALATED", nextStep: "Investigate the contest with the existing Principal." });
    return core.openLocalOwner({ ...x.config, historyFile, trust }).exportHistory().slice(before);
  };
  const writtenR = await write(file, "CHECKPOINT_RESUME"), writtenF = await write(copyFile, "FULL_REPLAY");
  assert.equal(writtenR.length, 5);
  assert.equal(json(writtenR), json(writtenF), "admission, receipt record and duty disposition written from the snapshot equal those written after a full replay");
  t.diagnostic(`T8: ${events.length} events, ${canonicalBytes} canonical bytes (${(canonicalBytes / 1048576).toFixed(2)} MiB), file ${statSync(file).size} bytes, ${direct.state.stateRecords.size} records; build ${((built - started) / 1000).toFixed(1)} s`);
  t.diagnostic(`T8 reopen: snapshot resume ${resumeMs.toFixed(0)} ms, store full replay ${fullMs.toFixed(0)} ms, replay(events) ${replayMs.toFixed(0)} ms`);
});
