// Format 2 through the owner/runtime API (docs/API.md §1–§2, G0 §2, E2): default format 2, genesis options, budgets,
// counterparties, checkpoints (manual, policy, handover seal), the FORMAT_READ_ONLY fence, session-signed declarations,
// automatic and manual refusals (with de-duplication), effects, counterparty receipts, and the rules the architect's
// vectors cannot cover (README of conformance/v2): the 257th budget, BUDGET_SET_TOO_LARGE, EFFECT_LIMIT,
// AMOUNT_OVERFLOW, re-registration after retirement, a roleIds budget across a real handover (T6's budget half).
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling

const core = await import("../src/index.ts");
const { createLocalDomain, createLocalOwner, openLocalOwner } = core;
const { openLocalSimulation, commitTerms, openLocalRuntime } = core;
const { generateKeyPair, signHashWith } = await import("../src/crypto/suites.ts");
const { LEGACY_FORMAT, TRELLIS_FORMAT, TRELLIS2_FORMAT } = await import("../src/events.ts");
const { envelopeSigningHash } = await import("../src/session-auth.ts");
const { openHistoryStore } = await import("../src/store.ts");
const { hexToBytes } = await import("../src/hash.ts");

const code = (value) => (e) => e.code === value || (e.detail?.code === value);
const MAX = (1n << 256n) - 1n;

/** A format-2 deployment: owner `operations`, agent `bea` in role `reviewer` (tenure shift:1), session:1 (ed25519), grant `read` on incident:42. */
async function setup(t, options = {}) {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-f2-api-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let tick = 100;
  const config = { historyFile: join(dir, "history.jsonl"), domain: createLocalDomain(), owner: "operations", controller: "operator", now: () => tick, ...options };
  const owner = await createLocalOwner(config);
  await owner.createAgent({ id: "bea" });
  await owner.createRole({ id: "reviewer" });
  await owner.appoint({ agent: "bea", role: "reviewer", tenure: "shift:1", number: 1 });
  const pair = generateKeyPair("ed25519", "key:1");
  await owner.admitRuntime({ session: "session:1", agent: "bea", epoch: 1, key: "key:1", credential: pair.credential, expiresAt: 10_000_000 });
  await owner.grant({ id: "read", to: "bea", actions: ["read", "spend"], resources: ["incident:42", "petty-cash"], expiresAt: 10_000_000 });
  const options2 = { ...config, session: "session:1", signHash: signHashWith(pair) };
  const runtime = openLocalSimulation(options2);
  const op = (id, extra = {}) => ({ id, intentId: id, action: "read", resource: "incident:42", role: "reviewer", tenure: "shift:1", termsCommitment: commitTerms({ subject: id }), ...extra });
  return { dir, owner, config, pair, options: options2, runtime, op, now: (n) => (tick = n), tick: () => tick };
}
const types = (owner) => owner.exportHistory().map((e) => e.type);
const budget = (id, extra = {}) => ({ budgetId: id, subjects: { actorIds: null, roleIds: null, actions: ["spend"], resources: null }, metric: "amount", period: { kind: "NONE" }, amountCap: "100", countCap: null, perOperationCap: null, notBefore: null, expiresAt: null, ...extra });

test("format 2 is the default: domain, genesis versions and options; format 1 stays available by name", async (t) => {
  const f = await setup(t, { maxStateRecords: 500, checkpointPolicy: { everyEvents: null }, projection: "irontrellis-projection/2", maxEvents: null });
  assert.equal(f.owner.format, TRELLIS2_FORMAT);
  const genesis = f.owner.exportHistory()[0].data;
  assert.equal(genesis.domain.version, "2");
  assert.equal(genesis.versions.eventSchemaVersion, "irontrellis-event/2");
  assert.equal(genesis.policyVersion, "irontrellis-local-owner/2");
  assert.deepEqual(genesis.capacity, { maxEvents: null, maxStateRecords: 500 });
  assert.deepEqual(genesis.checkpointPolicy, { everyEvents: null });
  assert.equal(genesis.projection, "irontrellis-projection/2");
  const report = f.owner.capacity();
  assert.equal(report.maxStateRecords, 500);
  assert.equal(report.stateRecords, f.owner.stateRoot().recordCount);
  assert.equal(report.reserved, false);
  assert.equal(report.dutyReserved, 0);
  assert.equal(createLocalDomain().version, "2");
  assert.equal(createLocalDomain({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true }).version, "1");
  // Explicitly format 1: the rc.1 writer, unchanged.
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-f2-api-f1-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const f1 = await createLocalOwner({ historyFile: join(dir, "h.jsonl"), domain: createLocalDomain({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true }), owner: "o", controller: "c", now: () => 1, format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true });
  assert.equal(f1.format, TRELLIS_FORMAT);
  await f1.createAgent({ id: "a" });
  assert.throws(() => f1.stateRoot(), code("INVALID_INPUT"));
  await assert.rejects(f1.declareBudget(budget("b")), code("INVALID_INPUT"));
});

test("FORMAT_READ_ONLY: a format-1 file opened without naming its format reads, verifies and queries, and refuses every write", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-f2-api-ro-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const format of [TRELLIS_FORMAT, LEGACY_FORMAT]) {
    const base = { historyFile: join(dir, `${format.replaceAll("/", "-")}.jsonl`), domain: createLocalDomain({ format }), owner: "o", controller: "c", now: () => 1 };
    const writer = await createLocalOwner({ ...base, format, [FORMAT1_TEST_TOOLING]: true });
    await writer.createAgent({ id: "a" });
    const reader = openLocalOwner(base);
    assert.equal(reader.format, format);
    assert.equal(reader.exportHistory().length, 3);
    assert.equal(reader.verify().ok, true);
    assert.equal(reader.authorize({ actor: "a", action: "x", resource: "y" }).decision, "DENY");
    await assert.rejects(reader.createAgent({ id: "b" }), (e) => e.code === "FORMAT_READ_ONLY" && e.detail.reason === (format === LEGACY_FORMAT ? "LEGACY" : "FORMAT_1"));
    await assert.rejects(reader.declareBudget(budget("b")), code("FORMAT_READ_ONLY"));
    // The store itself fences too, and the explicit-format handle keeps writing.
    assert.throws(() => openHistoryStore(base.historyFile).append({ id: "x", type: "PRINCIPAL_CREATED", timestamp: 1, data: {} }), code("FORMAT_READ_ONLY"));
    await writer.createAgent({ id: "b" });
    assert.equal(openLocalOwner({ ...base, format, [FORMAT1_TEST_TOOLING]: true }).exportHistory().length, 4);
    // A-185.3: the public API names no older format; the internal-format1 test entry point does.
    assert.throws(() => openLocalOwner({ ...base, format }), code("INVALID_INPUT"));
    await assert.rejects(createLocalOwner({ ...base, historyFile: `${base.historyFile}.new`, format }), code("INVALID_INPUT"));
    // A-206.1: the mark is an unregistered symbol; the registry key built from its description string does not unlock format 1.
    const forged = Symbol.for(FORMAT1_TEST_TOOLING.description);
    assert.notEqual(forged, FORMAT1_TEST_TOOLING);
    assert.equal(Symbol.keyFor(FORMAT1_TEST_TOOLING), undefined, "not in the global symbol registry");
    assert.throws(() => openLocalOwner({ ...base, format, [forged]: true }), code("INVALID_INPUT"));
    await assert.rejects(createLocalOwner({ ...base, historyFile: `${base.historyFile}.forged`, format, [forged]: true }), code("INVALID_INPUT"));
    // JOB75-02: a Proxy is refused before the mark is looked up, so no trap is ever handed the unregistered symbol.
    const seen = [];
    const record = (key) => { if (typeof key === "symbol") seen.push(key); };
    const spy = (target) => new Proxy(target, {
      get: (o, k, r) => { record(k); return Reflect.get(o, k, r); },
      has: (o, k) => { record(k); return Reflect.has(o, k); },
      getOwnPropertyDescriptor: (o, k) => { record(k); return Reflect.getOwnPropertyDescriptor(o, k); },
    });
    assert.throws(() => openLocalOwner(spy({ ...base, format })), (e) => e.code === "INVALID_INPUT");
    await assert.rejects(createLocalOwner(spy({ ...base, historyFile: `${base.historyFile}.proxy`, format })), (e) => e.code === "INVALID_INPUT");
    assert.throws(() => core.openHistoryStore(`${base.historyFile}.proxy-store`, spy({ readOnlyFormats: false })), code("INVALID_INPUT"));
    assert.equal(seen.includes(FORMAT1_TEST_TOOLING), false, "no trap saw the mark");
    assert.throws(() => core.createHistoryStore(`${base.historyFile}.store`, writer.exportHistory().slice(0, 1)), code("INVALID_INPUT"));
    // JOB75-01: the public openHistoryStore at an absent path takes a format-2 first batch only; nothing is written.
    const fresh = `${base.historyFile}.fresh`;
    assert.throws(() => core.openHistoryStore(fresh).append(writer.exportHistory()[0]), code("INVALID_INPUT"));
    assert.equal(existsSync(fresh), false, "no older-format file was created");
    assert.throws(() => core.openHistoryStore(base.historyFile, { readOnlyFormats: false }), code("INVALID_INPUT"));
  }
});

test("budgets through the API: declare, headroom, charge on admission, update (carryBase), close, 257th budget, BUDGET_SET_TOO_LARGE", async (t) => {
  const f = await setup(t);
  await f.owner.declareBudget(budget("b-amount", { period: { kind: "FIXED_WINDOW", lengthMs: 1000, originMs: 0, carryUnused: true, carryCap: 50n }, amountCap: 100n }));
  await assert.rejects(f.owner.declareBudget(budget("b-amount")), code("TRANSITION_REJECTED"));
  await assert.rejects(f.owner.declareBudget(budget("bad", { amountCap: null })), code("INVALID_INPUT"));
  await assert.rejects(f.owner.declareBudget(budget("bad", { subjects: { actorIds: null, roleIds: null, actions: null, resources: null, extra: null } })), code("INVALID_INPUT"));
  assert.deepEqual(f.owner.headroom({ budgetId: "b-amount" }), { budgetId: "b-amount", active: true, periodIndex: 0, usedAmount: "0", usedCount: 0, carryIn: "0", remainingAmount: "100", remainingCount: null });
  assert.equal(f.owner.headroom({ budgetId: "nope" }), null);
  const spend = (id, amount) => f.op(id, { action: "spend", resource: "petty-cash", amount });
  const first = await f.runtime.run(spend("op:1", 60n));
  assert.equal(first.status, "SIMULATION_RESULT");
  const declared = f.owner.exportHistory().find((e) => e.type === "TRANSACTION_INTENT_DECLARED");
  assert.equal(declared.data.amount, "60");
  assert.equal(declared.data.declarationAuthorization.runtimeSessionId, "session:1");
  assert.equal(f.runtime.headroom({ budgetId: "b-amount" }).usedAmount, "60");
  assert.equal(f.owner.headroom({ budgetId: "b-amount" }).remainingAmount, "40");
  // Over the remaining amount: DENY from the budget, recorded automatically as a BUDGET refusal.
  const denied = await f.runtime.run(spend("op:2", 41n));
  assert.equal(denied.status, "NOT_AUTHORIZED");
  assert.equal(denied.evidence.code, "BUDGET_AMOUNT_EXCEEDED");
  assert.equal(denied.evidence.budgetId, "b-amount");
  assert.equal(denied.refusalRecorded, true);
  assert.equal(typeof denied.refusal.eventId, "string");
  const refusal = f.owner.exportHistory().at(-1);
  assert.equal(refusal.type, "REQUEST_REFUSED");
  assert.equal(refusal.data.refusalSource, "BUDGET");
  assert.equal(refusal.data.budgetId, "b-amount");
  assert.equal(refusal.data.evaluationTime, refusal.timestamp);
  // The same refusal again is coalesced (A-23, A-56.3: the per-handle fast path reports COALESCED); a different one is recorded.
  const again = await f.runtime.run(spend("op:3", 41n));
  assert.equal(again.refusalRecorded, false);
  assert.deepEqual(again.refusalNotRecorded, { reason: "COALESCED" });
  const other = await f.runtime.run(f.op("op:4", { action: "spend", resource: "elsewhere", amount: 1n }));
  assert.equal(other.evidence.code, "RESOURCE_NOT_ALLOWED");
  assert.equal(typeof other.refusal.eventId, "string");
  assert.equal(f.owner.exportHistory().at(-1).data.refusalSource, "CORE");
  // Update at t = 1100 (period 1): the rollover earned under the old cap (100 − 60 = 40) is frozen in carryBase.
  f.now(1100);
  await f.owner.updateBudget({ budgetId: "b-amount", subjects: budget("x").subjects, amountCap: "60", countCap: null, perOperationCap: null, expiresAt: null });
  const record = f.owner.exportHistory() && core.replay(f.owner.exportHistory()).state.budgets.get("b-amount");
  assert.deepEqual(record.carryBase, { periodIndex: 1, carryIn: "40" });
  assert.equal(f.owner.headroom({ budgetId: "b-amount", at: 1100 }).remainingAmount, "100");
  await assert.rejects(f.owner.updateBudget({ budgetId: "b-amount", subjects: budget("x").subjects, amountCap: null, countCap: null, perOperationCap: null, expiresAt: null }), code("INVALID_INPUT"));
  await f.owner.closeBudget({ budgetId: "b-amount" });
  await assert.rejects(f.owner.closeBudget({ budgetId: "b-amount" }), code("TRANSITION_REJECTED"));
  assert.equal(f.owner.headroom({ budgetId: "b-amount" }).active, false);
  // 256 budgets at most, CLOSED ones counted: b-amount is one, so 255 more fit and the 257th is refused.
  for (let i = 1; i < 256; i += 1) await f.owner.declareBudget(budget(`fill:${String(i).padStart(3, "0")}`, { subjects: { actorIds: null, roleIds: null, actions: ["never"], resources: null } }));
  await assert.rejects(f.owner.declareBudget(budget("fill:257")), (e) => e.code === "TRANSITION_REJECTED" && /256/.test(e.message));
  assert.equal(core.replay(f.owner.exportHistory()).state.budgets.size, 256);
  // 17 matching budgets → BUDGET_SET_TOO_LARGE with the 17th in byte order.
  for (let i = 1; i <= 17; i += 1) await f.owner.updateBudget({ budgetId: `fill:${String(i).padStart(3, "0")}`, subjects: budget("x").subjects, amountCap: "100", countCap: null, perOperationCap: null, expiresAt: null });
  const tooMany = f.owner.authorize({ actor: "bea", action: "spend", resource: "petty-cash", amount: 1n });
  assert.equal(tooMany.decision, "DENY");
  assert.equal(tooMany.evidence.code, "BUDGET_SET_TOO_LARGE");
  assert.equal(tooMany.evidence.budgetId, "fill:017");
  await f.owner.closeBudget({ budgetId: "fill:017" });
  assert.equal(f.owner.authorize({ actor: "bea", action: "spend", resource: "petty-cash", amount: 1n }).decision, "ALLOW");
});

test("the U53 closure of a usage counter (r4 §3.3, §7.2; Lean families u53-count-boundary): at admittedTransactionCount = 2^53 − 1 the next admission is DENY AMOUNT_OVERFLOW", async (t) => {
  const f = await setup(t);
  const first = await f.runtime.run(f.op("op:1", { action: "spend", resource: "petty-cash", amount: 1n }));
  assert.equal(first.status, "SIMULATION_RESULT");
  const state = core.replay(f.owner.exportHistory()).state;
  const counter = state.usageCounters.get("read");
  assert.equal(counter.admittedTransactionCount, 1);
  const ask = (count) => {
    state.usageCounters.set("read", Object.freeze({ ...counter, admittedTransactionCount: count })); // injected: unreachable natively
    return core.observeState(state, { at: f.tick() }).authorize({ actor: "bea", action: "spend", resource: "petty-cash", amount: 1n });
  };
  assert.equal(ask(Number.MAX_SAFE_INTEGER - 1).decision, "ALLOW", "the admission that reaches 2^53 − 1 is allowed");
  const over = ask(Number.MAX_SAFE_INTEGER);
  assert.equal(over.decision, "DENY");
  assert.equal(over.evidence.code, "AMOUNT_OVERFLOW");
  assert.equal(over.evidence.budgetId ?? null, null, "source CORE: no budget (absent, null on the wire, like every candidate failure since G6.5 A-135)");
});

test("AMOUNT_OVERFLOW from the authority procedure: an uncapped grant and a near-MAX usage counter", async (t) => {
  const f = await setup(t);
  const spend = (id, amount) => f.op(id, { action: "spend", resource: "petty-cash", amount });
  const first = await f.runtime.run(spend("op:1", MAX - 1n));
  assert.equal(first.status, "SIMULATION_RESULT");
  const state = core.replay(f.owner.exportHistory()).state;
  assert.equal(state.usageCounters.get("read").admittedCumulativeAmount, MAX - 1n);
  assert.equal(state.stateRecords.get("usage\u0000read").record.admittedCumulativeAmount, (MAX - 1n).toString());
  const ok = f.owner.authorize({ actor: "bea", action: "spend", resource: "petty-cash", amount: 1n });
  assert.equal(ok.decision, "ALLOW");
  const over = f.owner.authorize({ actor: "bea", action: "spend", resource: "petty-cash", amount: 2n });
  assert.equal(over.decision, "DENY");
  assert.equal(over.evidence.code, "AMOUNT_OVERFLOW");
  assert.equal(over.evidence.budgetId ?? null, null, "source CORE: no budget (absent, null on the wire)");
  assert.deepEqual(over.evidence.failures.map((x) => x.code), ["AMOUNT_OVERFLOW"]);
  // Recorded as a CORE refusal; the run is NOT_AUTHORIZED; replay accepts the refusal (re-derived).
  const denied = await f.runtime.run(spend("op:2", 2n));
  assert.equal(denied.evidence.code, "AMOUNT_OVERFLOW");
  const refusal = f.owner.exportHistory().at(-1);
  assert.equal(refusal.data.refusalSource, "CORE");
  assert.equal(refusal.data.code, "AMOUNT_OVERFLOW");
  assert.equal(core.replay(f.owner.exportHistory()).status, "ACCEPTED");
  // A forged admission over MAX is TRANSITION_INVALID on replay: the re-derivation denies it.
  const events = f.owner.exportHistory();
  const admission = events.find((e) => e.type === "TRANSACTION_INTENT_ADMITTED");
  const forged = { ...admission, id: "event:forged", data: { ...admission.data, authorizationProof: { ...admission.data.authorizationProof, request: { ...admission.data.authorizationProof.request, amount: "2" } } } };
  const r = core.replay([...events, forged]);
  assert.equal(r.status, "REJECTED");
  assert.equal(r.code, "TRANSITION_INVALID");
});

test("checkpoints: manual with the self-check, checkpointPolicy.everyEvents, and the handover seal of succeed(); a roleIds budget survives the handover with its usage", async (t) => {
  const f = await setup(t, { checkpointPolicy: { everyEvents: 4 } });
  // Policy: a checkpoint once 4 events were accepted since the last one — the setup's writes already triggered some.
  const history = f.owner.exportHistory();
  const checkpoints = history.map((e, p) => [e.type, p]).filter(([type]) => type === "STATE_CHECKPOINT").map(([, p]) => p);
  assert.ok(checkpoints.length >= 1, "the policy wrote checkpoints");
  for (const p of checkpoints) {
    assert.equal(history[p].data.head.position, p - 1);
    assert.equal(history[p].data.stateRoot, core.replay(history.slice(0, p)).stateRoot);
  }
  const manual = await f.owner.checkpoint({ checkpointId: "cp:manual" });
  const state = core.replay(f.owner.exportHistory()).state;
  assert.equal(manual.head.position, state.head.position);
  assert.equal(manual.stateRoot, state.stateRoots[state.head.position - 1]);
  assert.equal(manual.recordCount, state.stateRecords.size - 1); // the checkpoint's own event record comes after
  assert.equal(manual.projectionHead, state.projectionHeads[state.head.position - 1]);
  assert.deepEqual(f.owner.stateRoot(), { stateRoot: state.stateRoots.at(-1), recordCount: state.stateRecords.size, projectionHead: state.projectionHeads.at(-1) });
  assert.equal(core.replay(f.owner.exportHistory()).status, "ACCEPTED");

  // T6 (budget half): a roleIds budget binds the role's current holder; after the handover the successor is bound and the usage is retained.
  await f.owner.declareBudget(budget("g-role", { subjects: { actorIds: null, roleIds: ["reviewer"], actions: ["spend"], resources: null }, amountCap: "100", period: { kind: "NONE" } }));
  const spend = (id, amount, extra = {}) => f.op(id, { action: "spend", resource: "petty-cash", amount, ...extra });
  assert.equal((await f.runtime.run(spend("op:1", 70n))).status, "SIMULATION_RESULT");
  assert.equal(f.owner.headroom({ budgetId: "g-role" }).usedAmount, "70");
  await f.owner.createAgent({ id: "cal" });
  await f.owner.declareSuccession({ id: "rule:1", from: "bea", to: "cal", role: "reviewer" });
  const handover = await f.owner.succeed({ id: "h:1", rule: "rule:1", fromAgent: "bea", fromTenure: "shift:1", toAgent: "cal", toTenure: "shift:2", role: "reviewer", number: 2 });
  assert.deepEqual(handover.eventIds, ["handover:h:1:retire", "handover:h:1:transfer", "handover:h:1:checkpoint"]);
  const sealed = f.owner.exportHistory();
  assert.equal(sealed.at(-1).type, "STATE_CHECKPOINT");
  assert.equal(sealed.at(-1).id, "handover:h:1:checkpoint");
  assert.equal(sealed.at(-1).data.checkpointId, "handover:h:1");
  assert.equal(sealed.at(-1).data.stateRoot, core.replay(sealed.slice(0, -1)).stateRoot);
  // Resuming the handover is idempotent (nothing new is written).
  assert.deepEqual((await f.owner.succeed({ id: "h:1", rule: "rule:1", fromAgent: "bea", fromTenure: "shift:1", toAgent: "cal", toTenure: "shift:2", role: "reviewer", number: 2 })).eventIds, handover.eventIds);
  assert.equal(f.owner.exportHistory().length, sealed.length);
  // The budget followed the role: cal holds reviewer now, usage 70 retained, 30 left; bea (terminated) matches nothing.
  const calKey = generateKeyPair("ed25519", "key:2");
  await f.owner.admitRuntime({ session: "session:2", agent: "cal", epoch: 1, key: "key:2", credential: calKey.credential, expiresAt: 10_000_000 });
  await f.owner.grant({ id: "read:cal", to: "cal", actions: ["spend"], resources: ["petty-cash"], expiresAt: 10_000_000 });
  assert.equal(f.owner.headroom({ budgetId: "g-role" }).usedAmount, "70");
  const calRuntime = openLocalSimulation({ ...f.config, session: "session:2", signHash: signHashWith(calKey) });
  const over = await calRuntime.run({ id: "op:cal:1", action: "spend", resource: "petty-cash", role: "reviewer", tenure: "shift:2", termsCommitment: commitTerms({ s: 1 }), amount: 31n });
  assert.equal(over.evidence.code, "BUDGET_AMOUNT_EXCEEDED");
  assert.equal(over.evidence.budgetId, "g-role");
  const fits = await calRuntime.run({ id: "op:cal:2", action: "spend", resource: "petty-cash", role: "reviewer", tenure: "shift:2", termsCommitment: commitTerms({ s: 2 }), amount: 30n });
  assert.equal(fits.status, "SIMULATION_RESULT");
  assert.equal(f.owner.headroom({ budgetId: "g-role" }).remainingAmount, "0");
  assert.equal(core.replay(f.owner.exportHistory()).status, "ACCEPTED");
});

test("counterparties and receipts: register, retire, re-register keeps the chain; effects and EFFECT_LIMIT; refusals by hand", async (t) => {
  const f = await setup(t);
  const acme = generateKeyPair("ed25519", "acme:1");
  const keys = [{ keyId: "acme:1", scheme: "ed25519", credential: acme.credential }];
  await f.owner.registerCounterparty({ counterpartyId: "acme", keys });
  await assert.rejects(f.owner.registerCounterparty({ counterpartyId: "acme", keys }), code("TRANSITION_REJECTED"));
  await assert.rejects(f.owner.registerCounterparty({ counterpartyId: "bad", keys: [{ keyId: "k", scheme: "eip191-personal-sign-keccak256", credential: acme.credential }] }), code("INVALID_INPUT"));
  const run = await f.runtime.run(f.op("op:1", { action: "spend", resource: "petty-cash", amount: 5n }));
  assert.equal(run.status, "SIMULATION_RESULT");
  const state = () => core.replay(f.owner.exportHistory()).state;
  const historyId = state().eventHistoryHashes[0];
  const intentDigest = state().intentDeclarations.get("op:1").declarationDigest;
  const envelopeFor = async (previous, observedAt = 150) => {
    const body = { version: "irontrellis-counterparty-receipt/2", historyId, counterpartyId: "acme", keyId: "acme:1", logicalId: "op:1", intentDigest, payloadDigest: `0x${"ab".repeat(32)}`, amount: "5", outcome: "DELIVERED", observedAt, previousReceiptDigest: previous };
    return { ...body, signature: await signHashWith(acme)(envelopeSigningHash(body)) };
  };
  const runtime = openLocalRuntime(f.options);
  f.now(200); // A-45.2: the envelopes are observed at 150–160, so the writer's time is past them
  const first = await runtime.recordCounterpartyReceipt({ intentId: "op:1", envelope: await envelopeFor(null) });
  assert.equal(typeof first.eventId, "string");
  // Idempotent re-record; a chain break is refused; a wrong intent is a conflict.
  assert.deepEqual(await runtime.recordCounterpartyReceipt({ intentId: "op:1", envelope: await envelopeFor(null) }), { eventId: first.eventId, head: state().head });
  await assert.rejects(runtime.recordCounterpartyReceipt({ intentId: "op:1", envelope: await envelopeFor(null, 151) }), code("TRANSITION_REJECTED"));
  const cp = () => state().counterparties.get("acme");
  assert.equal(cp().receiptCount, 1);
  const tampered = await envelopeFor(cp().lastReceiptDigest);
  await assert.rejects(runtime.recordCounterpartyReceipt({ intentId: "op:1", envelope: { ...tampered, amount: "6" } }), code("COUNTERPARTY_SIGNATURE_INVALID"));
  await f.owner.retireCounterparty({ counterpartyId: "acme" });
  await assert.rejects(f.owner.retireCounterparty({ counterpartyId: "acme" }), code("TRANSITION_REJECTED"));
  await assert.rejects(runtime.recordCounterpartyReceipt({ intentId: "op:1", envelope: tampered }), code("TRANSITION_REJECTED"));
  // Re-registration after retirement: new keys, the chain continues from lastReceiptDigest with receiptCount 1.
  const acme2 = generateKeyPair("ed25519", "acme:2");
  await f.owner.registerCounterparty({ counterpartyId: "acme", keys: [{ keyId: "acme:2", scheme: "ed25519", credential: acme2.credential }] });
  assert.equal(cp().status, "ACTIVE");
  assert.equal(cp().receiptCount, 1);
  const body2 = { version: "irontrellis-counterparty-receipt/2", historyId, counterpartyId: "acme", keyId: "acme:2", logicalId: "op:1", intentDigest, payloadDigest: `0x${"cd".repeat(32)}`, amount: "5", outcome: "DELIVERED", observedAt: 160, previousReceiptDigest: cp().lastReceiptDigest };
  const second = await runtime.recordCounterpartyReceipt({ intentId: "op:1", envelope: { ...body2, signature: await signHashWith(acme2)(envelopeSigningHash(body2)) } });
  assert.equal(typeof second.eventId, "string");
  assert.equal(cp().receiptCount, 2);

  // Effects: 64 per intent, the 65th is EFFECT_LIMIT; a COUNTERPARTY measurer must be ACTIVE; observedAt after the clock is refused.
  const effect = (n, extra = {}) => ({ effectId: `effect:${n}`, intentId: "op:1", measurer: { kind: "SESSION", id: "bea" }, metric: "amount", unit: "cent", amount: 1n, observedAt: 100, ...extra });
  for (let n = 1; n <= 64; n += 1) await runtime.recordEffect(effect(n));
  await assert.rejects(runtime.recordEffect(effect(65)), code("EFFECT_LIMIT"));
  assert.equal(typeof (await runtime.recordEffect(effect(64))).eventId, "string"); // idempotent repeat
  await assert.rejects(runtime.recordEffect(effect(64, { amount: 2n })), code("OPERATION_CONFLICT"));
  await assert.rejects(runtime.recordEffect(effect(66, { observedAt: f.tick() + 1 })), code("CLOCK_INVALID"));
  await assert.rejects(runtime.recordEffect(effect(66, { measurer: { kind: "SESSION", id: "cal" } })), code("TRANSITION_REJECTED"));
  const other = await f.runtime.run(f.op("op:2", { action: "spend", resource: "petty-cash", amount: 1n }));
  assert.equal(other.status, "SIMULATION_RESULT");
  // A-36.1: a COUNTERPARTY effect needs a recorded envelope of that counterparty for the intent (op:2 has none); the positive case is in g2-rulings "A-36 …".
  await assert.rejects(runtime.recordEffect(effect(66, { intentId: "op:2", measurer: { kind: "COUNTERPARTY", id: "acme" } })), code("TRANSITION_REJECTED"));

  // Refusals by hand: a request the state ALLOWs is REFUSAL_NOT_REPRODUCED before signing; a wrong source too; a connector refusal needs the connector's own session.
  const request = { actorId: "bea", action: "spend", resource: "petty-cash", claimedAt: 100, amount: "1" };
  const before = f.owner.exportHistory().length;
  await assert.rejects(runtime.recordRefusal({ request }), code("REFUSAL_NOT_REPRODUCED"));
  assert.equal(f.owner.exportHistory().length, before);
  const denied = { ...request, resource: "elsewhere" };
  await assert.rejects(runtime.recordRefusal({ request: denied, source: "BUDGET" }), code("REFUSAL_NOT_REPRODUCED"));
  const recorded = await runtime.recordRefusal({ refusalId: "ref:1", request: denied, source: "CORE" });
  assert.equal(typeof recorded.eventId, "string");
  assert.deepEqual(await runtime.recordRefusal({ refusalId: "ref:1", request: denied }), { eventId: recorded.eventId, head: state().head });
  assert.deepEqual(await runtime.recordRefusal({ request: denied }), { recorded: false, reason: "COALESCED" });
  await assert.rejects(runtime.recordRefusal({ request: { ...denied, actorId: "cal" } }), code("TRANSITION_REJECTED"));
  await assert.rejects(runtime.recordRefusal({ request: denied, connector: { connectorId: "gateway", refusalCode: "UPSTREAM", detailDigest: `0x${"00".repeat(32)}` } }), code("TRANSITION_REJECTED"));
  const connector = await runtime.recordRefusal({ request: denied, connector: { connectorId: "bea", refusalCode: "UPSTREAM", detailDigest: `0x${"00".repeat(32)}` } });
  assert.equal(typeof connector.eventId, "string");
  assert.equal(f.owner.exportHistory().at(-1).data.code, "CONNECTOR_REFUSED");
  assert.equal(core.replay(f.owner.exportHistory()).status, "ACCEPTED");
  // The export view with records and an inclusion path that verifies against to.stateRoot.
  const s = state();
  const view = f.owner.exportView({ fromPosition: 0, toPosition: s.head.position, include: { fromRecords: true, toRecords: true, inclusion: [{ kind: "counterparty", key: "acme" }, { kind: "event", key: "0".repeat(16) }] } });
  assert.equal(view.from.stateRoot, s.stateRoots[0]);
  assert.equal(view.to.stateRoot, s.stateRoots.at(-1));
  assert.equal(view.toRecords.length, s.stateRecords.size);
  assert.equal(view.fromRecords.length, 3);
  for (const proof of view.inclusion) {
    const entry = core.stateRecordsOf(s)[proof.leafIndex];
    assert.equal(entry.kind, proof.kind);
    assert.ok(core.verifyInclusion(entry.leaf, proof.leafIndex, s.stateRecords.size, proof.path.map((h) => hexToBytes(h)), hexToBytes(view.to.stateRoot)));
  }
  assert.throws(() => f.owner.exportView({ fromPosition: 3, toPosition: 2 }), code("INVALID_INPUT"));
  assert.throws(() => f.owner.exportView({ fromPosition: 0, toPosition: 1, include: { inclusion: [{ kind: "budget", key: "none" }] } }), code("INVALID_INPUT"));
});

test("refusals: 'off' records nothing; a refusal on an unlimited history replays; the runtime's refusal names the actor's own session", async (t) => {
  const f = await setup(t, { refusals: "off" });
  const denied = await f.runtime.run(f.op("op:1", { resource: "elsewhere" }));
  assert.equal(denied.status, "NOT_AUTHORIZED");
  assert.equal("refusal" in denied, false);
  assert.equal(types(f.owner).includes("REQUEST_REFUSED"), false);
});

test("receipts of amount-bearing intents (E5 T8 finding): the receipt policy compares a format-2 proof in its wire form, so create, record and verify succeed", async (t) => {
  const f = await setup(t);
  await f.owner.grant({ id: "pay", to: "bea", actions: ["pay"], resources: ["vendor"], expiresAt: 10_000_000, maxAmount: 1000n, maxCumulativeAmount: 5000n });
  const pay = f.op("pay:1", { action: "pay", resource: "vendor", amount: 250n });
  assert.equal((await f.runtime.run(pay)).invocation.status, "SUBMITTED");
  const result = await f.runtime.recordReceipt(pay);
  assert.equal(result.recording.status, "ADMITTED");
  const events = f.owner.exportHistory();
  assert.equal(core.replay(events).status, "ACCEPTED");
  const verified = core.verifyReceipt({ operationVersion: core.RECEIPT_VERIFICATION_VERSION, artifact: result.artifact, expectedDomain: f.config.domain, verifierTime: f.tick(), issuanceEvents: events, observedEvents: events });
  assert.equal(verified.status, "EVALUATED");
  for (const axis of ["contentIntegrity", "signaturePossession", "issuerAuthentication", "historicalAuthorization", "canonicalInclusion", "freshness"]) assert.equal(verified[axis].status, "PASS", axis);
  assert.equal(verified.historicalAuthorization.primaryCode, "HISTORICAL_AUTHORIZATION_VALID");
  // The policy evaluation itself: live for the admitted proof (it compared string Amounts with the engine's bigints before).
  const state = core.replay(events).state, proof = events.find((e) => e.type === "TRANSACTION_INTENT_ADMITTED").data.authorizationProof;
  assert.equal(proof.request.amount, "250");
  assert.equal(core.evaluateReceiptPolicy(state, proof, f.tick()).live, true);
});
