// G2-APPLY: tests for the addenda applied after the E4 merge (earlier-addenda items routed to the lead, then the G2 list).
// One test (or more) per ruling; each fails without the ruling.
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling

const core = await import("../src/index.ts");
const { createLocalDomain, createLocalOwner, openLocalRuntime, openLocalSimulation, commitTerms, replay } = core;
const { generateKeyPair, signHashWith } = await import("../src/crypto/suites.ts");

// The architect's history as regenerated under A-54 / A-59 (signed under the default profile g3), and the frozen r2.3 record.
const V2 = join(import.meta.dirname, "..", "..", "..", "conformance", "v2-g3");
const ARCHITECT = JSON.parse(readFileSync(join(V2, "histories", "budget-v2.json"), "utf8"));
const FROZEN_R23 = JSON.parse(readFileSync(join(import.meta.dirname, "..", "..", "..", "conformance", "v2", "histories", "budget-v2.json"), "utf8"));
const code = (value) => (e) => e.code === value;
const clone = (value) => JSON.parse(JSON.stringify(value));

async function setup(t, options = {}) {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-g2-"));
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
  const runtimeOf = (extra = {}) => openLocalSimulation({ ...config, session: "session:1", signHash: signHashWith(pair), ...extra });
  const runtime = runtimeOf();
  const op = (id, extra = {}) => ({ id, intentId: id, action: "read", resource: "incident:42", role: "reviewer", tenure: "shift:1", termsCommitment: commitTerms({ id }), ...extra });
  return { owner, config, runtime, runtimeOf, op, pair, now: (n) => (tick = n), tick: () => tick };
}
const refused = (n) => ({ actorId: "bea", action: "read", resource: `nowhere:${n}`, claimedAt: 100 });

// ---------------------------------------------------------------- step 2: earlier addenda routed to the lead

test("A-23 / A-56.3: refusals coalesce against the actor's latest refusal record (any handle, younger than coalesceMs) and are rate-limited per actor", async (t) => {
  const f = await setup(t);
  const first = await f.runtime.recordRefusal({ request: refused(1) });
  assert.equal(typeof first.eventId, "string");
  // A fresh handle (no process-lifetime key) still coalesces against the history's latest refusal of the actor.
  const fresh = f.runtimeOf();
  assert.deepEqual(await fresh.recordRefusal({ request: refused(1) }), { recorded: false, reason: "COALESCED" });
  // Older than coalesceMs (60 s): recorded again.
  f.now(100 + 60_000);
  assert.equal(typeof (await f.runtimeOf().recordRefusal({ request: refused(1) })).eventId, "string");
  // Rate limit: 6 per actor per minute (the bucket refilled over the minute that passed: 6 tokens, one spent above).
  const results = [];
  for (let n = 2; n <= 8; n += 1) results.push(await f.runtimeOf().recordRefusal({ request: refused(n) }));
  const limited = results.filter((r) => r.recorded === false);
  assert.equal(results.length - limited.length, 5);
  assert.ok(limited.every((r) => r.reason === "RATE_LIMITED"), JSON.stringify(limited));
  // A minute later the bucket has refilled.
  f.now(100 + 120_000);
  assert.equal(typeof (await f.runtimeOf().recordRefusal({ request: refused(9) })).eventId, "string");
  assert.equal(replay(f.owner.exportHistory()).status, "ACCEPTED");
  // A-179.4 adds SESSION_TIME_HORIZON to the one list (§10.1.1 item 7).
  assert.deepEqual([...core.REFUSAL_NOT_RECORDED_REASONS], ["COALESCED", "RATE_LIMITED", "SPOOLED", "RECORD_DEADLINE", "NOT_REPRODUCED_AT_DRAIN", "SESSION_TIME_HORIZON"]);
});

test("A-11 / A-56.3: run() returns the decision with refusalRecorded and, when not recorded, the reason (never an exception)", async (t) => {
  const f = await setup(t, { refusalPolicy: { maxPerMinute: 1 } });
  const denied = await f.runtime.run(f.op("op:1", { resource: "elsewhere:1" }));
  assert.equal(denied.status, "NOT_AUTHORIZED");
  assert.equal(denied.refusalRecorded, true);
  assert.equal(typeof denied.refusal.eventId, "string");
  const coalesced = await f.runtimeOf().run(f.op("op:2", { resource: "elsewhere:1" }));
  assert.equal(coalesced.refusalRecorded, false);
  assert.equal(coalesced.refusalNotRecorded.reason, "COALESCED");
  const limited = await f.runtimeOf().run(f.op("op:3", { resource: "elsewhere:2" }));
  assert.equal(limited.status, "NOT_AUTHORIZED");
  assert.equal(limited.refusalRecorded, false);
  assert.equal(limited.refusalNotRecorded.reason, "RATE_LIMITED");
  assert.equal("deduplicated" in limited, false);
});

test("A-22.1 / A-58.4: a native format-2 session admission without expiresAt, or with expiresAt null, is EVENT_DATA_INVALID", () => {
  const position = ARCHITECT.findIndex((e) => e.type === "RUNTIME_SESSION_ADMITTED");
  for (const mutate of [(d) => { delete d.expiresAt; }, (d) => { d.expiresAt = null; }]) {
    const events = clone(ARCHITECT.slice(0, position + 1));
    mutate(events[position].data);
    const r = replay(events);
    assert.equal(r.status, "REJECTED");
    assert.equal(r.code, "EVENT_DATA_INVALID");
    assert.equal(r.position, position);
  }
});

test("A-22.3: a power-reducing owner write with a clock behind the head is written at head.canonicalTime and reports CLOCK_BEHIND_HEAD; other writes keep CLOCK_INVALID", async (t) => {
  const f = await setup(t);
  f.now(500);
  await f.owner.createAgent({ id: "cal" });
  f.now(400);
  await assert.rejects(f.owner.createAgent({ id: "dan" }), code("CLOCK_INVALID"));
  const revoked = await f.owner.revoke("read");
  assert.deepEqual(revoked.clock, { code: "CLOCK_BEHIND_HEAD", skewMs: 100 });
  assert.equal(f.owner.exportHistory().at(-1).timestamp, 500);
  assert.equal(replay(f.owner.exportHistory()).status, "ACCEPTED");
  assert.equal(core.POWER_REDUCING_TYPES.size, 8);
});

test("A-22.4: run() refuses with CLOCK_AHEAD_OF_READER when the head is dated more than 300 s ahead of the reader's clock", async (t) => {
  const f = await setup(t);
  f.now(400_000);
  await f.owner.createAgent({ id: "cal" });
  f.now(400_000 - 300_001);
  await assert.rejects(f.runtime.run(f.op("op:1")), code("CLOCK_AHEAD_OF_READER"));
  f.now(400_000 - 1000);
  await assert.rejects(f.runtime.run(f.op("op:1")), code("CLOCK_INVALID"));
  assert.equal(core.clockAheadOfReader({ canonicalTime: 400_000 }, 99_999), true);
  assert.equal(core.clockAheadOfReader({ canonicalTime: 400_000 }, 100_000), false);
});

test("A-26: a budget with metric null matches every metric and is charged by requests of two different metrics", async (t) => {
  const f = await setup(t);
  await f.owner.declareBudget({ budgetId: "b-any", subjects: { actorIds: ["bea"], roleIds: null, actions: ["spend"], resources: null }, metric: null, period: { kind: "NONE" }, amountCap: "100", countCap: null, perOperationCap: null, notBefore: null, expiresAt: null });
  const spend = (id, metric, amount) => f.op(id, { action: "spend", resource: "petty-cash", amount, ...(metric === undefined ? {} : { metric }) });
  assert.equal((await f.runtime.run(spend("op:1", undefined, 30n))).status, "SIMULATION_RESULT");
  assert.equal((await f.runtime.run(spend("op:2", "tokens", 50n))).status, "SIMULATION_RESULT");
  assert.equal(f.owner.headroom({ budgetId: "b-any" }).usedAmount, "80");
  const denied = await f.runtime.run(spend("op:3", "cents", 21n));
  assert.equal(denied.status, "NOT_AUTHORIZED");
  assert.equal(denied.evidence.code, "BUDGET_AMOUNT_EXCEEDED");
  assert.equal(core.replay(f.owner.exportHistory()).state.budgets.get("b-any").metric, null);
});

// ---------------------------------------------------------------- step 3: A-51 (types 14–16 session-signed), A-58.5 (fence first)

/** A format-2 history with a consumption and a receipt record (both signed by bea's session:1), then an agent cal with its own session. */
async function lifecycleHistory(t) {
  const f = await setup(t);
  const op = f.op("op:1");
  assert.equal((await f.runtime.run(op)).status, "SIMULATION_RESULT");
  assert.equal((await f.runtime.recordReceipt(op)).recording.status, "ADMITTED");
  const calPair = generateKeyPair("ed25519", "key:cal");
  await f.owner.createAgent({ id: "cal" });
  await f.owner.admitRuntime({ session: "session:cal", agent: "cal", epoch: 1, key: "key:cal", credential: calPair.credential, expiresAt: 10_000_000 });
  const events = f.owner.exportHistory();
  const state = replay(events).state;
  const sessions = { "session:1": { pair: f.pair, key: "key:1" }, "session:cal": { pair: calPair, key: "key:cal" } };
  /** Signs `event` (data without recordAuthorization) as the next event after `prefix` with `sessionId`. */
  const signAs = async (prefix, event, sessionId, mutate = (a) => a) => {
    const head = replay(prefix).head;
    const binding = { runtimeSessionId: sessionId, credentialKeyId: sessions[sessionId].key, controlEpoch: 1 };
    const { recordAuthorization: _old, ...data } = event.data;
    const hash = core.lifecycleAuthorizationHash(state.genesis.domain, { ...event, data }, head, binding);
    const signature = await signHashWith(sessions[sessionId].pair)(hash);
    return { ...event, data: { ...data, recordAuthorization: mutate({ ...binding, hash, signature }) } };
  };
  return { f, events, state, signAs, sessions };
}
const positionOf = (events, type) => events.findIndex((e) => e.type === type);
const rejectsAt = (events, position, expected) => {
  const r = replay(events);
  assert.equal(r.status, "REJECTED", `expected ${expected} at ${position}`);
  assert.equal(r.code, expected, r.reason);
  assert.equal(r.position, position);
};

test("A-51.1 / A-51.2: consumptions and receipt records written by the API carry recordAuthorization over irontrellis-lifecycle-authorization/2 with the envelope bound; missing → EVENT_DATA_INVALID", async (t) => {
  const { events, state } = await lifecycleHistory(t);
  assert.equal(replay(events).status, "ACCEPTED");
  assert.equal(core.LIFECYCLE_AUTHORIZATION_VERSION, "irontrellis-lifecycle-authorization/2");
  for (const type of ["TRANSACTION_INTENT_CONSUMED", "RECEIPT_RECORDED"]) {
    const p = positionOf(events, type);
    const event = events[p];
    const a = event.data.recordAuthorization;
    assert.deepEqual(Object.keys(a).sort(), ["controlEpoch", "credentialKeyId", "hash", "runtimeSessionId", "signature"]);
    const { recordAuthorization: _a, ...data } = event.data;
    const challenge = core.lifecycleChallenge(state.genesis.domain, event, replay(events.slice(0, p)).head, a);
    assert.deepEqual(Object.keys(challenge).sort(), ["controlEpoch", "credentialKeyId", "domain", "effectHash", "eventHistoryHash", "eventHistoryPosition", "eventId", "eventType", "runtimeSessionId", "timestamp", "version"]);
    assert.equal(challenge.effectHash, core.hashCanonical(data, "sha256"));
    assert.equal(a.hash, core.hashCanonical(challenge, "sha256"));
    // Missing → schema failure.
    const missing = clone(events.slice(0, p + 1));
    delete missing[p].data.recordAuthorization;
    rejectsAt(missing, p, "EVENT_DATA_INVALID");
    // The timestamp is bound (A-51.2): the same signature at another timestamp is refused.
    const moved = clone(events.slice(0, p + 1));
    moved[p].timestamp += 1;
    rejectsAt(moved, p, "RECORD_AUTHORIZATION_INVALID");
  }
});

test("A-51.3 / A-51.4 / A-60 / A-61.3: tampered hash, signature or binding and a wrong signer are RECORD_AUTHORIZATION_INVALID before the preconditions; an unknown intent after a valid signature is TRANSITION_INVALID; a type-16 inherited/nested mismatch is EVENT_DATA_INVALID", async (t) => {
  const { events, signAs } = await lifecycleHistory(t);
  const pc = positionOf(events, "TRANSACTION_INTENT_CONSUMED"), pr = positionOf(events, "RECEIPT_RECORDED");
  const tail = events.slice(pr + 1); // cal, session:cal
  // Re-order: put the extra sessions before the lifecycle events is not possible (control signatures bind the head); sign at the end instead.
  const base = events, end = base.length;
  const consumption = base[pc], receipt = base[pr];
  // Re-signing a consumption at the end of the history cannot pass its preconditions (already consumed): good for precedence tests.
  for (const [name, mutate] of [["hash", (a) => ({ ...a, hash: `0x${"11".repeat(32)}` })], ["signature", (a) => ({ ...a, signature: `0x${"5a".repeat(64)}` })], ["keyId", (a) => ({ ...a, credentialKeyId: "key:cal" })]]) {
    const forged = clone(base.slice(0, pc + 1));
    forged[pc] = await signAs(base.slice(0, pc), consumption, "session:1", mutate);
    rejectsAt(forged, pc, "RECORD_AUTHORIZATION_INVALID");
    assert.ok(name);
  }
  // Wrong signer: cal's session signs bea's consumption (valid signature, wrong actor) — at the end, where it also fails the precondition (already consumed): the authorization code wins.
  const wrong = [...base, { ...await signAs(base, { ...consumption, id: "event:again" }, "session:cal") }];
  rejectsAt(wrong, end, "RECORD_AUTHORIZATION_INVALID");
  // Right signer, valid signature at the end: only the precondition fails → TRANSITION_INVALID (so the case above was decided by the signer binding).
  rejectsAt([...base, await signAs(base, { ...consumption, id: "event:again" }, "session:1")], end, "TRANSITION_INVALID");
  // Type 16: the receipt's inherited runtimeSessionId / controlEpoch must equal the nested (signing) binding — a schema rule (A-61.3: EVENT_DATA_INVALID).
  rejectsAt([...base, await signAs(base, { ...receipt, id: "event:receipt-again", data: { ...receipt.data, receiptContentHash: `0x${"ab".repeat(32)}`, runtimeSessionId: "session:cal" } }, "session:1")], end, "EVENT_DATA_INVALID");
  rejectsAt([...base, await signAs(base, { ...receipt, id: "event:receipt-again", data: { ...receipt.data, receiptContentHash: `0x${"ab".repeat(32)}`, controlEpoch: 2 } }, "session:1")], end, "EVENT_DATA_INVALID");
  // A-60: valid signature + unknown intent → TRANSITION_INVALID (intent resolution precedes the signer binding) for all three types; bad signature + unknown intent → RECORD_AUTHORIZATION_INVALID.
  const po = positionOf(base, "TRANSACTION_OUTCOME_RECORDED");
  for (const [p, signer] of [[pc, "session:1"], [pr, "session:1"], ...(po >= 0 ? [[po, "session:1"]] : [])]) {
    const unknown = { ...base[p], id: `event:unknown-${p}`, data: { ...base[p].data, intentId: "intent:unknown", ...(base[p].type === "RECEIPT_RECORDED" ? { receiptContentHash: `0x${"cd".repeat(32)}` } : {}) } };
    rejectsAt([...base, await signAs(base, unknown, signer)], end, "TRANSITION_INVALID");
    rejectsAt([...base, await signAs(base, unknown, signer, (a) => ({ ...a, signature: `0x${"5a".repeat(64)}` }))], end, "RECORD_AUTHORIZATION_INVALID");
    // Wrong signer + unknown intent: still TRANSITION_INVALID (a missing entry never selects the binding code). (A receipt
    // signed by another session differs from its inherited runtimeSessionId: schema first, A-61.3.)
    if (unknown.type !== "RECEIPT_RECORDED") rejectsAt([...base, await signAs(base, unknown, "session:cal")], end, "TRANSITION_INVALID");
  }
  // The same with the issuer's own session is accepted (receipts are "typed existence only" on the format-1 side).
  assert.equal(replay([...base, await signAs(base, { ...receipt, id: "event:receipt-again", data: { ...receipt.data, receiptContentHash: `0x${"ab".repeat(32)}` } }, "session:1")]).status, "ACCEPTED");
  assert.equal(tail.length, 2);
});

test("A-51.3: an outcome may be signed by the intent's actor or by an admitted attester agent; adapter attester ids need no agent record", async (t) => {
  const { events, signAs } = await lifecycleHistory(t);
  const pc = positionOf(events, "TRANSACTION_INTENT_CONSUMED");
  const evidence = { kind: "EVENT", eventId: events[pc].id, position: pc, eventType: "TRANSACTION_INTENT_CONSUMED", historyHash: replay(events.slice(0, pc + 1)).head.hash };
  const outcome = (attesterId, id = "event:outcome") => ({ id, type: "TRANSACTION_OUTCOME_RECORDED", timestamp: events.at(-1).timestamp, data: { intentId: "op:1", status: "CONFIRMED", attesterId, evidenceReference: evidence } });
  assert.equal(replay([...events, await signAs(events, outcome("adapter:remote"), "session:1")]).status, "ACCEPTED"); // the actor; a free-text attester
  assert.equal(replay([...events, await signAs(events, outcome("cal"), "session:cal")]).status, "ACCEPTED"); // the admitted attester agent
  rejectsAt([...events, await signAs(events, outcome("adapter:remote"), "session:cal")], events.length, "RECORD_AUTHORIZATION_INVALID"); // neither
});

test("A-51.5: at most 16 outcomes and 16 receipt records per intent (TRANSITION_INVALID); A-51.6: rows of types 14–16 set flag bit 1", async (t) => {
  const { events, signAs } = await lifecycleHistory(t);
  const pc = positionOf(events, "TRANSACTION_INTENT_CONSUMED"), pr = positionOf(events, "RECEIPT_RECORDED");
  const evidence = { kind: "EVENT", eventId: events[pc].id, position: pc, eventType: "TRANSACTION_INTENT_CONSUMED", historyHash: replay(events.slice(0, pc + 1)).head.hash };
  let history = [...events];
  for (let n = 1; n <= 17; n += 1) {
    const event = await signAs(history, { id: `event:outcome:${n}`, type: "TRANSACTION_OUTCOME_RECORDED", timestamp: events.at(-1).timestamp, data: { intentId: "op:1", status: n === 1 ? "CONFIRMED" : "DISPUTED", attesterId: "adapter:remote", evidenceReference: evidence } }, "session:1");
    if (n === 17) { rejectsAt([...history, event], history.length, "TRANSITION_INVALID"); break; }
    history.push(event);
  }
  assert.equal(replay(history).status, "ACCEPTED");
  assert.equal(core.MAX_OUTCOMES_PER_INTENT, 16);
  history = [...events];
  for (let n = 2; n <= 17; n += 1) {
    const event = await signAs(history, { ...events[pr], id: `event:receipt:${n}`, data: { ...events[pr].data, receiptContentHash: `0x${n.toString(16).padStart(64, "0")}` } }, "session:1");
    if (n === 17) { rejectsAt([...history, event], history.length, "TRANSITION_INVALID"); break; }
    history.push(event);
  }
  const state = replay(history).state;
  assert.equal(core.receiptCountOf(state, "op:1"), 16);
  // The count is rebuilt from the records (T2 invariant).
  assert.equal(core.receiptCountOf(core.rebuildReplayState(core.stateRecordsOf(state).map((e) => ({ kind: e.kind, key: e.key, record: e.record })), history), "op:1"), 16);
  for (const p of [pc, pr]) {
    const row = core.projectionRow(history[p], p, core.eventHash ? core.eventHash(history[p]) : `0x${"00".repeat(32)}`);
    assert.equal(row[19] & 2, 2, `bit 1 at ${p}`);
    assert.equal(row[19] & 1, 0);
  }
});

test("A-58.5 / A-29: SESSION_FENCED is checked first — before the hash, the signature and the type's own code — for 14–16, refusals and admissions", async (t) => {
  const { f, events, signAs } = await lifecycleHistory(t);
  const pc = positionOf(events, "TRANSACTION_INTENT_CONSUMED");
  await f.owner.advanceEpoch({ agent: "bea", from: 1, to: 2 }); // bea's sessions (epoch 1) are fenced now
  const fenced = f.owner.exportHistory();
  // A consumption with a broken signature by a fenced session: SESSION_FENCED, not RECORD_AUTHORIZATION_INVALID.
  const broken = await signAs(fenced, { ...events[pc], id: "event:again" }, "session:1", (a) => ({ ...a, signature: `0x${"00".repeat(64)}` }));
  rejectsAt([...fenced, broken], fenced.length, "SESSION_FENCED");
  // A refusal by the fenced session with a wrong hash: SESSION_FENCED, not REFUSAL_AUTHORIZATION_INVALID.
  const refusal = { id: "event:refusal", type: "REQUEST_REFUSED", timestamp: fenced.at(-1).timestamp, data: {
    refusalId: "r:1", refusalSource: "CORE", request: { actorId: "bea", action: "read", resource: "nowhere", claimedAt: 1 }, evaluationTime: fenced.at(-1).timestamp,
    expectedHistoryHead: replay(fenced).head, decision: "DENY", code: "RESOURCE_NOT_ALLOWED", runtimeSessionId: "session:1", credentialKeyId: "key:1", controlEpoch: 1,
    refusalAuthorization: { hash: `0x${"22".repeat(32)}`, signature: `0x${"00".repeat(64)}` } } };
  rejectsAt([...fenced, refusal], fenced.length, "SESSION_FENCED");
  // The API reports the fence as such too.
  await assert.rejects(f.runtime.recordRefusal({ request: refused(1) }), (e) => e.code === "RUNTIME_NOT_CURRENT" || e.code === "SESSION_FENCED");
});

test("A-58.5: an admission and the outer session of a ▲ event are fenced first (SESSION_FENCED before the type's other checks)", async (t) => {
  const { f, events } = await lifecycleHistory(t);
  await f.owner.advanceEpoch({ agent: "bea", from: 1, to: 2 });
  const fenced = f.owner.exportHistory();
  const admission = events[positionOf(events, "TRANSACTION_INTENT_ADMITTED")];
  // The re-appended admission also fails its preconditions (already admitted, stale head): the fence is reported.
  rejectsAt([...fenced, { ...admission, id: "event:admission-again", timestamp: fenced.at(-1).timestamp }], fenced.length, "SESSION_FENCED");
  // ▲: the duty fixture's worker session signs ATTEMPT_DUTY_CREATED; after an epoch advance a re-appended copy is fenced first.
  const { fixture } = await import("./helpers/duty-fixture.mjs");
  const d = await fixture(t);
  const created = d.events.find((e) => e.type === "ATTEMPT_DUTY_CREATED");
  await d.owner.advanceEpoch({ agent: "worker", from: 1, to: 2 });
  const after = d.events;
  rejectsAt([...after, { ...created, id: "event:duty-again", timestamp: after.at(-1).timestamp }], after.length, "SESSION_FENCED");
});

test("A-51.5: at most 64 assignments and 64 reviews per duty and 64 observations per intent (TRANSITION_INVALID); reviews end to end through the API", async (t) => {
  const { fixture } = await import("./helpers/duty-fixture.mjs");
  const d = await fixture(t, { policy: "E6" });
  const recorder = core.openLocalAttemptRecorder(d.setupOptions);
  for (let n = 1; n <= 64; n += 1) await recorder.reviewDuty({ id: `r:${n}`, duty: "duty", summaryDigest: `0x${n.toString(16).padStart(64, "0")}` });
  await assert.rejects(recorder.reviewDuty({ id: "r:65", duty: "duty", summaryDigest: `0x${"ff".repeat(32)}` }), (e) => e.code === "TRANSITION_REJECTED");
  const state = core.replay(d.events).state;
  assert.equal(core.replay(d.events).status, "ACCEPTED");
  assert.equal(state.attemptDutyReviews.get("duty").length, 64);
  // Assignments and observations: the same bound helper (an assignment needs the role to move each time; an observation a remote report).
  const { adminListBound } = await import("../src/state.ts");
  const duty = state.attemptDuties.get("duty");
  const withLists = (assignments, observations) => Object.create(state, {
    attemptDuties: { value: new Map([["duty", { ...duty, assignments: Array.from({ length: assignments }) }]]) },
    outcomeObservations: { value: new Map([[duty.record.sourceIntentId, Array.from({ length: observations })]]) },
  });
  const assign = { id: "x", type: "ATTEMPT_DUTY_ASSIGNED", timestamp: 1, data: { dutyId: "duty" } };
  const observe = { id: "y", type: "OUTCOME_OBSERVATION_RECORDED", timestamp: 1, data: { intentId: duty.record.sourceIntentId } };
  assert.equal(adminListBound(withLists(63, 63), assign), undefined);
  assert.equal(adminListBound(withLists(64, 63), assign)?.code, "TRANSITION_INVALID");
  assert.equal(adminListBound(withLists(63, 63), observe), undefined);
  assert.equal(adminListBound(withLists(63, 64), observe)?.code, "TRANSITION_INVALID");
  assert.deepEqual([core.MAX_ASSIGNMENTS_PER_DUTY, core.MAX_REVIEWS_PER_DUTY, core.MAX_OBSERVATIONS_PER_INTENT], [64, 64, 64]);
});

// ---------------------------------------------------------------- A-49 (canonical escaping), A-34 (strict parsing)

test("A-49: every C0 character is escaped as lowercase \\u00xx (\\b \\t \\n \\f \\r included), non-BMP characters are UTF-8, a lone surrogate is refused; a signed format-2 event carrying them replays", async (t) => {
  assert.equal(core.canonicalEncode("a\b\t\n\f\r\u0001\u001f\"\\é😀"), "\"a\\u0008\\u0009\\u000a\\u000c\\u000d\\u0001\\u001f\\\"\\\\é😀\"");
  assert.notEqual(core.canonicalEncode("\n"), JSON.stringify("\n")); // never the host serializer's short escapes
  assert.throws(() => core.canonicalEncode("\ud800"));
  assert.throws(() => core.canonicalEncode("x\udfffy"));
  // Signed fixture: a duty disposition whose checklist reasons (ProtocolStrings) carry the five short-escape characters and a
  // non-BMP character; the finding (attester) and the outer administrative authorization are signed over the canonical text.
  const { dispositionFixture, checklist } = await import("./helpers/duty-fixture.mjs");
  const d = await dispositionFixture(t);
  const reasons = checklist();
  reasons.SOURCE_REVIEWED.reason = "a\bb\tc\nd\fe\rf 😀";
  await d.duties.dispose({ ...d.input, checklist: reasons });
  const text = readFileSync(d.config.historyFile, "utf8").trimEnd().split("\n").at(-1);
  assert.ok(text.includes("a\\u0008b\\u0009c\\u000ad\\u000ce\\u000df 😀"), text.slice(0, 400));
  assert.equal(core.replay(d.events).status, "ACCEPTED");
  const last = d.events.at(-1);
  assert.equal(last.type, "ATTEMPT_DUTY_DISPOSITION_RECORDED");
  assert.equal(core.eventHash(last), `0x${createHash("sha256").update(core.canonicalEncode(last)).digest("hex")}`);
});

test("A-34: format-2 store lines are parsed strictly — 1.0, -0, 1e2, a duplicate key and a lone-surrogate escape are INVALID_HISTORY at their position; Amounts \"12\\n\" and fullwidth digits are EVENT_DATA_INVALID; __proto__ and constructor are ordinary ids", async (t) => {
  const { openHistoryStore } = await import("../src/store.ts");
  const { writeFileSync } = await import("node:fs");
  const f = await setup(t);
  await f.owner.createAgent({ id: "__proto__" });
  await f.owner.createAgent({ id: "constructor" });
  await f.owner.declareBudget({ budgetId: "toString", subjects: { actorIds: ["__proto__"], roleIds: null, actions: null, resources: null }, metric: null, period: { kind: "NONE" }, amountCap: "5", countCap: null, perOperationCap: null, notBefore: null, expiresAt: null });
  const state = replay(f.owner.exportHistory()).state;
  assert.equal(replay(f.owner.exportHistory()).status, "ACCEPTED");
  assert.equal(state.agents.get("__proto__").id, "__proto__");
  assert.equal(state.agents.get("constructor").id, "constructor");
  assert.ok(core.stateRecordsOf(state).some((e) => e.kind === "agent" && e.key === "__proto__"));
  const path = f.config.historyFile;
  const original = readFileSync(path, "utf8");
  const lines = original.trimEnd().split("\n");
  const last = lines.length - 1;
  const ts = JSON.parse(lines[last]).event.timestamp;
  const variants = {
    fraction: lines[last].replace(`"timestamp":${ts}`, `"timestamp":${ts}.0`),
    exponent: lines[last].replace(`"timestamp":${ts}`, `"timestamp":${ts / 100}e2`),
    duplicate: lines[last].replace(`"budgetId":"toString"`, `"budgetId":"toString","budgetId":"toString"`),
    surrogate: lines[last].replace(`"metric":null`, `"metric":null,"x":"\\ud800"`),
  };
  for (const [name, line] of Object.entries(variants)) {
    assert.notEqual(line, lines[last], name);
    writeFileSync(path, [...lines.slice(0, last), line].join("\n") + "\n");
    let thrown; try { openHistoryStore(path, { witness: false }).state(); } catch (e) { thrown = e; }
    assert.ok(thrown?.code === "INVALID_HISTORY" && thrown.detail?.position === last, `${name}: ${thrown?.code} ${JSON.stringify(thrown?.detail)} ${thrown?.message} ${line.slice(-300)}`);
  }
  // -0 (the epoch of an agent) on an earlier line.
  const agentLine = lines.findIndex((l) => l.includes(`"agentId":"constructor"`));
  writeFileSync(path, [...lines.slice(0, agentLine), lines[agentLine].replace(`"initialControlEpoch":1`, `"initialControlEpoch":-0`)].join("\n") + "\n");
  assert.throws(() => openHistoryStore(path, { witness: false }).state(), (e) => e.code === "INVALID_HISTORY" && e.detail?.position === agentLine);
  writeFileSync(path, original);
  // Whole-string scalar grammars: a trailing newline or fullwidth digits in an Amount (A-34.2).
  const events = clone(f.owner.exportHistory());
  for (const amount of ["12\n", "１２", " 12", "12 "]) {
    const mutated = clone(events);
    mutated.at(-1).data.amountCap = amount;
    rejectsAt(mutated, events.length - 1, "EVENT_DATA_INVALID");
  }
  // The architect's vectors parse under the strict parser (A-34 "builder confirms").
  assert.equal(core.strictJsonProblem(readFileSync(join(V2, "vectors.json"), "utf8")), undefined);
  for (const line of readFileSync(join(V2, "histories", "budget-v2.jsonl"), "utf8").trimEnd().split("\n")) assert.equal(core.strictJsonProblem(line), undefined);
  for (const [text, code] of [["1.0", "INVALID_NUMBER"], ["-0", "INVALID_NUMBER"], ["1e2", "INVALID_NUMBER"], ["9007199254740992", "INVALID_NUMBER"], ['{"a":1,"a":1}', "DUPLICATE_KEY"], ['"\\udc00"', "LONE_SURROGATE"], ["﻿{}", "BOM"]]) {
    assert.equal(core.strictJsonProblem(text)?.code, code, text);
  }
  assert.equal(core.strictJsonProblem('{"__proto__":1,"constructor":-9007199254740991,"s":"\\ud83d\\ude00"}'), undefined);
});

// ---------------------------------------------------------------- A-53 (export view transitions), A-47.1 (historyId)

const roundTrip = (view) => JSON.parse(JSON.stringify(view));
test("A-53 / A-47.1: the verifier applies from+1…to; from == to is the identity; from = 0 applies the genesis once; the cp-1/cp-3 range; historyId = recordHash(0)", () => {
  const state = replay(ARCHITECT).state;
  const historyId = state.eventHistoryHashes[0];
  for (const [from, to] of [[24, 36], [24, 24], [0, 0], [0, 5], [36, 36], [ARCHITECT.length - 1, ARCHITECT.length - 1]]) {
    const view = core.exportViewState(state, { fromPosition: from, toPosition: to, include: { fromRecords: true, referencedEvents: true } });
    assert.equal(view.historyId, historyId);
    assert.equal(view.eventCount, to - from + 1);
    const result = core.verifyExportView(roundTrip(view));
    assert.equal(result.ok, true, `${from}..${to}: ${result.failures.join("; ")}`);
    assert.equal(result.to.stateRoot, core.rootAt(state, to));
    // A wrong historyId is refused.
    const forged = roundTrip(view);
    forged.historyId = `0x${"99".repeat(32)}`;
    assert.equal(core.verifyExportView(forged).ok, false);
  }
  // Without referencedEvents the rebuild still needs the genesis body: EXPORT_DEPENDENCIES_MISSING naming position 0, no transition claimed.
  const bare = core.exportViewState(state, { fromPosition: 24, toPosition: 36, include: { fromRecords: true } });
  const result = core.verifyExportView(roundTrip(bare));
  assert.equal(result.ok, false);
  assert.equal(result.code, "EXPORT_DEPENDENCIES_MISSING");
  assert.deepEqual(result.missingPositions, [0]);
});

test("A-53.2: a duty range whose latest finding precedes from needs that body (include.referencedEvents); without it the verifier returns EXPORT_DEPENDENCIES_MISSING and claims no transition", async (t) => {
  const { dispositionFixture } = await import("./helpers/duty-fixture.mjs");
  const d = await dispositionFixture(t);
  await d.duties.dispose(d.input);
  const disposedAt = d.events.length - 1;
  await d.owner.createAgent({ id: "spacer" });
  d.setTime(110);
  await d.duties.contest(d.contest("first"));
  const events = d.events, state = replay(events).state;
  const from = disposedAt + 1, to = events.length - 1;
  const view = core.exportViewState(state, { fromPosition: from, toPosition: to, include: { fromRecords: true, referencedEvents: true } });
  assert.ok(view.referencedEvents.some((e) => e.position === disposedAt), `the disposition at ${disposedAt} is a dependency: ${view.referencedEvents.map((e) => e.position)}`);
  const ok = core.verifyExportView(roundTrip(view));
  assert.equal(ok.ok, true, ok.failures.join("; "));
  assert.equal(ok.code, undefined);
  const lacking = roundTrip(view);
  lacking.referencedEvents = lacking.referencedEvents.filter((e) => e.position !== disposedAt);
  const result = core.verifyExportView(lacking);
  assert.equal(result.ok, false);
  assert.equal(result.code, "EXPORT_DEPENDENCIES_MISSING");
  assert.ok(result.missingPositions.includes(disposedAt));
  assert.equal(result.to.verified, false);
  // A referenced body that does not hash to its event record is refused.
  const tampered = roundTrip(view);
  const body = tampered.referencedEvents.find((e) => e.position === disposedAt);
  body.event.timestamp += 1;
  assert.equal(core.verifyExportView(tampered).ok, false);
});

// ---------------------------------------------------------------- A-50 (rollover over the saturated effective allowance), A-44.1

test("A-50: a saturated period, then a zero-cap update and an admission by a fresh authority — carryBase freezes the saturated recurrence and decides", async (t) => {
  const MAX = (1n << 256n) - 1n;
  const f = await setup(t);
  await f.owner.grant({ id: "spend:1", to: "bea", actions: ["spend"], resources: ["vault"], expiresAt: 10_000_000 });
  await f.owner.declareBudget({ budgetId: "sat", subjects: { actorIds: ["bea"], roleIds: null, actions: ["spend"], resources: null }, metric: "amount",
    period: { kind: "FIXED_WINDOW", lengthMs: 1000, originMs: 0, carryUnused: true, carryCap: MAX.toString() }, amountCap: MAX.toString(), countCap: null, perOperationCap: null, notBefore: null, expiresAt: null });
  const spend = (id, amount) => f.op(id, { action: "spend", resource: "vault", amount });
  f.now(100); assert.equal((await f.runtime.run(spend("p0", 10n))).status, "SIMULATION_RESULT"); // period 0: used 10 → f(1) = MAX − 10
  f.now(1100); assert.equal((await f.runtime.run(spend("p1", 10n))).status, "SIMULATION_RESULT"); // period 1: cap + f(1) saturates at MAX → f(2) = MAX − 10 (unamended: MAX)
  const state = () => replay(f.owner.exportHistory()).state;
  assert.equal(core.headroom(state(), "sat", 2100).carryIn, (MAX - 10n).toString());
  f.now(2100);
  await f.owner.updateBudget({ budgetId: "sat", subjects: { actorIds: ["bea"], roleIds: null, actions: ["spend"], resources: null }, amountCap: "0", countCap: null, perOperationCap: null, expiresAt: null });
  assert.deepEqual(state().budgets.get("sat").carryBase, { periodIndex: 2, carryIn: (MAX - 10n).toString() });
  // A fresh authority (its usage counter starts at 0, so the authority procedure cannot overflow): the budget decides.
  await f.owner.revoke("spend:1");
  await f.owner.grant({ id: "spend:2", to: "bea", actions: ["spend"], resources: ["vault"], expiresAt: 10_000_000 });
  const denied = await f.runtime.run(spend("p2-over", MAX - 9n)); // allowed = min(MAX, 0 + (MAX − 10)) = MAX − 10
  assert.equal(denied.status, "NOT_AUTHORIZED");
  assert.equal(denied.evidence.code, "BUDGET_AMOUNT_EXCEEDED");
  assert.equal(denied.evidence.budgetId, "sat");
  assert.equal((await f.runtime.run(spend("p2-at", MAX - 10n))).status, "SIMULATION_RESULT");
  assert.equal(replay(f.owner.exportHistory()).status, "ACCEPTED");
});

test("A-44.1 / A-50: carryIn from the rollover index equals the A-50 recurrence evaluated period by period, on random usage patterns, including after BUDGET_UPDATED reset carryBase", async () => {
  const budgets = await import("../src/budgets.ts");
  const { createReplayState } = await import("../src/replay.ts");
  const MAX = (1n << 256n) - 1n;
  let seed = 0xa50;
  const rnd = () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648; };
  const pick = (items) => items[Math.floor(rnd() * items.length)];
  const min = (x, y) => (x < y ? x : y);
  let checked = 0;
  for (let iteration = 0; iteration < 300; iteration += 1) {
    const cap = BigInt(pick(["0", "1", "50", "100", (MAX - 1n).toString(), MAX.toString()])), C = BigInt(pick(["0", "60", "1000", MAX.toString()]));
    const firstPeriod = Math.floor(rnd() * 3);
    const carryBase = rnd() < 0.4 ? { periodIndex: firstPeriod + Math.floor(rnd() * 5), carryIn: pick(["0", "7", (MAX - 3n).toString()]) } : null;
    const b = { budgetId: "b", subjects: { actorIds: null, roleIds: null, actions: null, resources: null }, metric: "amount", period: { kind: "FIXED_WINDOW", lengthMs: 10, originMs: 0, carryUnused: true, carryCap: C.toString() },
      amountCap: cap.toString(), countCap: null, perOperationCap: null, notBefore: null, expiresAt: null, status: "ACTIVE", declaredAtPosition: 1, firstPeriod, carryBase, updatedAtPosition: null, closedAtPosition: null };
    const state = createReplayState("irontrellis-event/2");
    state.budgets.set("b", b);
    const used = new Map();
    for (let j = 0; j < 40; j += 1) if (rnd() < 0.35) { const amount = BigInt(pick(["0", "1", "40", "100", (MAX - 2n).toString(), MAX.toString()])); used.set(j, amount); state.budgetUsage.set(budgets.usageKey("b", j), { budgetId: "b", periodIndex: j, amount: amount.toString(), count: 1 }); }
    for (let k = 0; k < 45; k += 1) {
      // The recurrence of A-50, one period at a time (no closed form, no index).
      let p0 = firstPeriod, f = 0n, expected;
      if (carryBase !== null && k === carryBase.periodIndex) expected = BigInt(carryBase.carryIn);
      else {
        if (carryBase !== null && k > carryBase.periodIndex) { p0 = carryBase.periodIndex; f = BigInt(carryBase.carryIn); }
        if (k <= p0) expected = 0n;
        else { for (let j = p0; j < k; j += 1) { let unused = min(MAX, cap + f) - (used.get(j) ?? 0n); if (unused < 0n) unused = 0n; f = min(C, unused); } expected = f; }
      }
      assert.equal(budgets.carryIn(state, b, k), expected, `iteration ${iteration}, k ${k}`);
      checked += 1;
    }
  }
  assert.ok(checked >= 13_000);
});

// ---------------------------------------------------------------- A-32 (Ed25519 profile)

test("A-32.1: the verifier is cofactorless with the pre-checks — S ≥ L, a non-canonical R or A, a small-order A and a mixed-order key's cofactored-only signature are refused", async () => {
  const { createHash, randomBytes } = await import("node:crypto");
  const E = await import("../src/crypto/ed25519-point.ts");
  const { suiteFor } = await import("../src/crypto/suites.ts");
  const suite = suiteFor("ed25519");
  const sha512 = (data) => createHash("sha512").update(data).digest();
  const hex = (bytes) => `0x${Buffer.from(bytes).toString("hex")}`;
  const le = E.ed25519PointOps.littleEndian, bytes = E.ed25519PointOps.toBytes, L = E.ED25519_L;
  const scalar = () => le(randomBytes(64)) % L;
  /** Signs the 32-byte `message` with secret scalar `a` and public encoding `A` (which may differ from [a]B: a mixed-order key). */
  const signWith = (a, A, message, r = scalar()) => {
    const R = E.ed25519PointOps.base(r);
    const k = le(sha512(Buffer.concat([R, A, message]))) % L;
    return { signature: Buffer.concat([R, bytes((r + k * a) % L)]), k, R };
  };
  const message = randomBytes(32), hash = hex(message);
  // An ordinary key: accepted, and S + L (same [S]B) refused by the S < L pre-check.
  const a = scalar(), A = E.ed25519PointOps.base(a);
  const good = signWith(a, A, message);
  assert.equal(suite.verify(hash, hex(good.signature), hex(A)), true);
  assert.equal(E.verifyExact(message, good.signature, A, sha512), true);
  const S = le(good.signature.subarray(32));
  if (S + L < (1n << 256n)) assert.equal(suite.verify(hash, hex(Buffer.concat([good.R, bytes(S + L)])), hex(A)), false);
  assert.equal(suite.verify(hash, hex(Buffer.concat([good.R, bytes(L)])), hex(A)), false); // S = L
  // A non-canonical R: y + p for a small y would exceed 255 bits; use the sign-bit form of x = 0 (y = 1, sign set): never canonical.
  const badR = bytes(1n); badR[31] |= 0x80;
  assert.equal(E.isCanonicalEncoding(badR), false);
  assert.equal(suite.verify(hash, hex(Buffer.concat([badR, good.signature.subarray(32)])), hex(A)), false);
  // Small-order keys (identity, order 2): any "signature" refused before the library is asked.
  const identity = E.ed25519PointOps.identity();
  const order2 = bytes((1n << 255n) - 20n); // y = p − 1, x = 0
  for (const key of [identity, order2]) {
    assert.equal(E.ed25519KeyCheck(key), "SMALL_ORDER");
    assert.equal(suite.verify(hash, hex(Buffer.concat([identity, bytes(0n)])), hex(key)), false);
  }
  // A non-canonical A (y ≥ p).
  const nonCanonical = bytes((1n << 255n) - 19n + 2n); // y = p + 2
  assert.equal(E.ed25519KeyCheck(nonCanonical), "NON_CANONICAL");
  assert.equal(suite.verify(hash, hex(good.signature), hex(nonCanonical)), false);
  // The cofactorless equation: a mixed-order key A' = [a]B + T (T of order 8) and a signature that satisfies only the
  // cofactored equation [8][S]B = [8]R + [8][k]A' (k ≢ 0 mod 8) — refused by the library and by the exact reference.
  const T = Buffer.from("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "hex");
  assert.equal(E.ed25519KeyCheck(T), "SMALL_ORDER");
  const mixed = E.ed25519PointOps.add(A, T);
  assert.equal(E.ed25519KeyCheck(mixed), "NOT_IN_PRIME_SUBGROUP");
  let cofactoredOnly;
  for (let attempt = 0; attempt < 64 && cofactoredOnly === undefined; attempt += 1) { const s = signWith(a, mixed, message); if (s.k % 8n !== 0n) cofactoredOnly = s; }
  assert.ok(cofactoredOnly, "a k not divisible by 8");
  const eight = (p) => Buffer.from(E.ed25519PointOps.multiply(p, 8n)).toString("hex");
  const lhs = eight(E.ed25519PointOps.base(le(cofactoredOnly.signature.subarray(32))));
  const rhs = eight(E.ed25519PointOps.add(cofactoredOnly.R, E.ed25519PointOps.multiply(mixed, cofactoredOnly.k)));
  assert.equal(lhs, rhs, "the cofactored equation holds");
  assert.equal(E.verifyExact(message, cofactoredOnly.signature, mixed, sha512), false);
  assert.equal(suite.verify(hash, hex(cofactoredOnly.signature), hex(mixed)), false, "node:crypto (OpenSSL) is cofactorless");
});

test("A-32.2 / A-32.3 / A-32.4: declared keys must be canonical, not small-order and in the prime subgroup (EVENT_DATA_INVALID); one key, one role at the writer", async (t) => {
  const E = await import("../src/crypto/ed25519-point.ts");
  const hex = (bytes) => `0x${Buffer.from(bytes).toString("hex")}`;
  const p = ARCHITECT.findIndex((e) => e.type === "RUNTIME_SESSION_ADMITTED");
  const T = Buffer.from("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "hex");
  const mixed = E.ed25519PointOps.add(Buffer.from(ARCHITECT[p].data.credentialPublicKey.slice(2), "hex"), T);
  // A-79.2: the session key is tested after control authorization, so each edit is re-signed by the architect's owner key
  // (TEST-KEYS seed 0x1001); unsigned, the dual fault is CONTROL_AUTHORIZATION_INVALID.
  const { signerFromKeyPair: fromPair } = await import("../src/signer.ts");
  const owner = fromPair(core.keyPairFromPrivateKey("ed25519", "owner:1", `0x${(0x1001).toString(16).padStart(64, "0")}`));
  const head = replay(ARCHITECT.slice(0, p)).head;
  for (const key of [E.ed25519PointOps.identity(), E.ed25519PointOps.toBytes((1n << 255n) - 20n), E.ed25519PointOps.toBytes((1n << 255n) - 17n), mixed]) {
    const events = clone(ARCHITECT.slice(0, p + 1));
    events[p].data.credentialPublicKey = hex(key);
    rejectsAt(events, p, "CONTROL_AUTHORIZATION_INVALID");
    events[p] = clone(await core.signControlEvent(owner, events[p], ARCHITECT[0].data.domain, head, "sha256"));
    rejectsAt(events, p, "EVENT_DATA_INVALID");
  }
  const genesis = clone(ARCHITECT.slice(0, 1));
  genesis[0].data.ownerKeys = [{ ...genesis[0].data.ownerKeys[0], credential: hex(E.ed25519PointOps.identity()) }];
  rejectsAt(genesis, 0, "EVENT_DATA_INVALID");
  // Writer rules: a session admitted with a key equal to an owner key; a counterparty key equal to a session credential; a rebind.
  const f = await setup(t);
  const ownerKey = f.owner.exportHistory()[0].data.ownerKeys[0].credential;
  await assert.rejects(f.owner.admitRuntime({ session: "session:x", agent: "bea", epoch: 1, key: "key:x", credential: ownerKey, expiresAt: 10_000_000 }), (e) => e.code === "INVALID_INPUT" && e.detail?.reason === "CREDENTIAL_REUSE");
  await assert.rejects(f.owner.registerCounterparty({ counterpartyId: "acme", keys: [{ keyId: "k1", scheme: "ed25519", credential: f.pair.credential }] }), (e) => e.code === "INVALID_INPUT" && e.detail?.reason === "CREDENTIAL_REUSE");
  const c1 = generateKeyPair("ed25519", "c1"), c2 = generateKeyPair("ed25519", "c2");
  await f.owner.registerCounterparty({ counterpartyId: "acme", keys: [{ keyId: "k1", scheme: "ed25519", credential: c1.credential }] });
  await assert.rejects(f.owner.registerCounterparty({ counterpartyId: "other", keys: [{ keyId: "k9", scheme: "ed25519", credential: c1.credential }] }), (e) => e.detail?.reason === "CREDENTIAL_REUSE");
  await f.owner.retireCounterparty({ counterpartyId: "acme" });
  await assert.rejects(f.owner.registerCounterparty({ counterpartyId: "acme", keys: [{ keyId: "k1", scheme: "ed25519", credential: c2.credential }] }), (e) => e.detail?.reason === "KEY_REBIND");
  await f.owner.registerCounterparty({ counterpartyId: "acme", keys: [{ keyId: "k1", scheme: "ed25519", credential: c2.credential }], allowKeyRebind: true });
  assert.equal(replay(f.owner.exportHistory()).status, "ACCEPTED");
});

// ---------------------------------------------------------------- A-52 (migrated prefix), A-40 (provenance), A-35 (prefix-only fields)

const { migrateHistory } = await import("../src/migrate.ts");
const { createHistoryStore: createStrictStore, openHistoryStore: openStore } = await import("../src/store.ts");
const { keyPairFromPrivateKey: keyFrom } = await import("../src/crypto/suites.ts");
const { signerFromKeyPair } = await import("../src/signer.ts");
const MIGRATION_ID = `0x${"4d".repeat(32)}`;
const migrationOwner = () => signerFromKeyPair(keyFrom("ed25519", "owner:1", `0x${"7e".repeat(32)}`));

/** A pinned, engine-built format-1 source (owner API, format named) with a declaration, admission, consumption and receipt. */
async function formatOneSource(t) {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-g2-f1-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let tick = 100, n = 0;
  const config = { historyFile: join(dir, "f1.jsonl"), domain: createLocalDomain({ format: "irontrellis-event/1", [FORMAT1_TEST_TOOLING]: true }), owner: "operations", controller: "operator", now: () => tick, format: "irontrellis-event/1", [FORMAT1_TEST_TOOLING]: true, nextKey: false, ids: () => `e:${(n += 1)}`, witness: false };
  const c = await createLocalOwner(config);
  const pair = generateKeyPair("ed25519", "key:a");
  await c.createAgent({ id: "a" });
  await c.createRole({ id: "reviewer" });
  await c.appoint({ agent: "a", role: "reviewer", tenure: "shift:1", number: 1 });
  await c.admitRuntime({ session: "s:a", agent: "a", epoch: 1, key: "k:a", credential: pair.credential, expiresAt: 100_000 });
  await c.grant({ id: "pay", to: "a", actions: ["pay"], resources: ["vendor"], expiresAt: 100_000 });
  const sim = openLocalSimulation({ ...config, session: "s:a", signHash: signHashWith(pair) });
  const op = { id: "op:1", action: "pay", resource: "vendor", role: "reviewer", tenure: "shift:1", termsCommitment: commitTerms({ n: 1 }) };
  tick = 102; await sim.run(op);
  tick = 103; await sim.recordReceipt(op);
  // The head is the owner's last write, so the pin carries the owner's attestation of exactly the source head (A-40.2).
  tick = 104; await c.createRole({ id: "auditor" });
  c.close();
  return { dir, source: config.historyFile, pair, domain: config.domain };
}

test("A-40.2–3 / A-52.4: migratedFrom carries the source pin's attestation (format 1; null for legacy) and the plan's migrationId; policyVersion is always rewritten; a forged attestation is EVENT_DATA_INVALID", async (t) => {
  const { dir, source } = await formatOneSource(t);
  const target = join(dir, "f2.jsonl");
  const result = await migrateHistory({ source, target, now: () => 5000, signer: migrationOwner(), nextKey: false, migrationId: MIGRATION_ID });
  const events = openStore(target).state().events;
  const migrated = events[0].data.migratedFrom;
  assert.equal(migrated.migrationId, MIGRATION_ID);
  assert.equal(migrated.sourceAttestation.version, "irontrellis-head-attestation/1");
  assert.equal(migrated.sourceAttestation.head.hash, migrated.historyHash);
  assert.equal(migrated.sourceAttestation.head.position, migrated.position);
  assert.equal(events[0].data.policyVersion, "irontrellis-local-owner/2");
  assert.deepEqual(result.sessionsWithoutExpiry, []);
  assert.equal(replay(events).status, "ACCEPTED");
  const plan = JSON.parse(readFileSync(result.plan, "utf8"));
  assert.equal(plan.migrationId, MIGRATION_ID);
  // A forged attestation (signature of another body) and a wrong head are EVENT_DATA_INVALID at position 0.
  for (const mutate of [(a) => { a.signature = `0x${"00".repeat(64)}`; }, (a) => { a.head.position -= 1; }]) {
    const forged = clone(events);
    mutate(forged[0].data.migratedFrom.sourceAttestation);
    rejectsAt(forged, 0, "EVENT_DATA_INVALID");
  }
  // A missing migrationId or sourceAttestation: closed schema.
  for (const key of ["migrationId", "sourceAttestation"]) {
    const missing = clone(events);
    delete missing[0].data.migratedFrom[key];
    rejectsAt(missing, 0, "EVENT_DATA_INVALID");
  }
  // A-52.4: a genesis that does not rewrite policyVersion fails like a historyHash mismatch (TRANSITION_INVALID); so does a changed copied field.
  for (const mutate of [(d) => { d.policyVersion = d.migratedFrom.genesis.policyVersion; }, (d) => { d.canonicalLineageId = "lineage:other"; }]) {
    const rewritten = clone(events);
    mutate(rewritten[0].data);
    rejectsAt(rewritten, 0, "TRANSITION_INVALID");
  }
  // Two migrations of copies of one source with fresh ids never share a historyId (A-40.3).
  const copy = join(dir, "copy.jsonl");
  writeFileSync(copy, readFileSync(source));
  writeFileSync(`${copy}.head`, readFileSync(`${source}.head`));
  const other = await migrateHistory({ source: copy, target: join(dir, "f2b.jsonl"), now: () => 5000, signer: migrationOwner(), nextKey: false });
  assert.notEqual(openStore(join(dir, "f2b.jsonl")).state().eventHistoryHashes[0], openStore(target).state().eventHistoryHashes[0]);
  assert.ok(other.targetHead.hash !== result.targetHead.hash);
});

test("A-40.1 / A-52.1 / A-35: in a format-1 prefix every control event carries a sourceControlAuthorization that must verify (CONTROL_AUTHORIZATION_INVALID); prefix declarations carry null and 14–16 no recordAuthorization; native histories refuse both prefix-only fields", async (t) => {
  const { dir, source } = await formatOneSource(t);
  const target = join(dir, "f2.jsonl");
  await migrateHistory({ source, target, now: () => 5000, signer: migrationOwner(), nextKey: false, migrationId: MIGRATION_ID });
  const events = openStore(target).state().events;
  const control = events.findIndex((e, p) => p > 0 && core.CONTROL_EVENT_TYPES.has(e.type));
  // A-40.1: a forged source signature (the /2 one by the new key still verifies: it excludes sourceControlAuthorization).
  const forged = clone(events);
  const sig = forged[control].data.sourceControlAuthorization.signature;
  forged[control].data.sourceControlAuthorization.signature = `${sig.slice(0, -2)}${sig.slice(-2) === "00" ? "01" : "00"}`;
  rejectsAt(forged, control, "CONTROL_AUTHORIZATION_INVALID");
  // A-52.1: absent on a format-1 prefix control event → EVENT_DATA_INVALID.
  const missing = clone(events);
  delete missing[control].data.sourceControlAuthorization;
  rejectsAt(missing, control, "EVENT_DATA_INVALID");
  // Prefix declarations carry null (a signed one is EVENT_DATA_INVALID); prefix 14–16 carry no recordAuthorization.
  const pd = events.findIndex((e) => e.type === "TRANSACTION_INTENT_DECLARED");
  assert.equal(events[pd].data.declarationAuthorization, null);
  const signedInPrefix = clone(events);
  signedInPrefix[pd].data.declarationAuthorization = { runtimeSessionId: "s:a", credentialKeyId: "k:a", controlEpoch: 1, hash: `0x${"11".repeat(32)}`, signature: `0x${"22".repeat(64)}` };
  rejectsAt(signedInPrefix, pd, "EVENT_DATA_INVALID");
  for (const type of ["TRANSACTION_INTENT_CONSUMED", "RECEIPT_RECORDED"]) {
    const p = events.findIndex((e) => e.type === type);
    assert.ok(p > 0 && !("recordAuthorization" in events[p].data), `${type} in the prefix is unsigned`);
    const withAuth = clone(events);
    withAuth[p].data.recordAuthorization = { runtimeSessionId: "s:a", credentialKeyId: "k:a", controlEpoch: 1, hash: `0x${"11".repeat(32)}`, signature: `0x${"22".repeat(64)}` };
    rejectsAt(withAuth, p, "EVENT_DATA_INVALID");
  }
  // A-35.1: native histories refuse `declarationAuthorization: null` and any `sourceControlAuthorization`.
  const nd = ARCHITECT.findIndex((e) => e.type === "TRANSACTION_INTENT_DECLARED");
  const nullNative = clone(ARCHITECT.slice(0, nd + 1));
  nullNative[nd].data.declarationAuthorization = null;
  rejectsAt(nullNative, nd, "EVENT_DATA_INVALID");
  const nc = ARCHITECT.findIndex((e, p) => p > 0 && core.CONTROL_EVENT_TYPES.has(e.type));
  const sourceNative = clone(ARCHITECT.slice(0, nc + 1));
  sourceNative[nc].data.sourceControlAuthorization = { keyId: "x", signature: `0x${"22".repeat(64)}` };
  rejectsAt(sourceNative, nc, "EVENT_DATA_INVALID");
});

test("A-52.2: a migrated session without expiresAt signs the prefix only — after the prefix its events fail §6.2's expiry check with the type's code", async (t) => {
  const { fixturesRoot } = await import("./reference.mjs");
  const { FIXTURE_KEY } = await import("./helpers/duty-fixture.mjs");
  const revive = (_k, v) => (v !== null && typeof v === "object" && typeof v["$continuity.bigint"] === "string" ? BigInt(v["$continuity.bigint"]) : v);
  const legacy = JSON.parse(readFileSync(`${fixturesRoot}handover-history.json`, "utf8"), revive);
  const last = legacy.at(-1), genesis = legacy[0].data;
  // Two more legacy control events (unsigned in legacy): an agent and its session without expiresAt, keyed by the reference's public fixture key.
  const extra = [
    { id: "event:g2:agent", type: "AGENT_CREATED", timestamp: last.timestamp, data: { agentId: "connector:g2", principalId: legacy.find((e) => e.type === "PRINCIPAL_CREATED").data.principalId, controllerId: "controller:g2", initialControlEpoch: 1 } },
    { id: "event:g2:session", type: "RUNTIME_SESSION_ADMITTED", timestamp: last.timestamp, data: { sessionId: "session:g2", agentId: "connector:g2", controllerId: "controller:g2", controlEpoch: 1, credentialKeyId: "key:g2", credentialAddress: FIXTURE_KEY.credential } },
  ];
  const sourceEvents = [...legacy, ...extra];
  assert.equal(replay(sourceEvents).status, "ACCEPTED", "the extended legacy source replays");
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-g2-legacy-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const source = join(dir, "legacy.jsonl"), target = join(dir, "legacy-2.jsonl");
  createStrictStore(source, sourceEvents, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true });
  const result = await migrateHistory({ source, target, now: () => 5000, signer: migrationOwner(), nextKey: false, migrationId: MIGRATION_ID });
  assert.deepEqual(result.sessionsWithoutExpiry, ["session:g2"]);
  const state = openStore(target).state(), events = state.events;
  assert.equal(state.runtimeSessions.get("session:g2").expiresAt, undefined);
  assert.equal(events[0].data.migratedFrom.sourceAttestation, null);
  // After the prefix: a CONNECTOR refusal signed by that session — expired (REFUSAL_AUTHORIZATION_INVALID); the session is valid in the prefix only.
  const at = last.timestamp + 1;
  const d = { refusalId: "r:g2", refusalSource: "CONNECTOR", request: { actorId: "a:first-look", action: "pay", resource: "vendor", claimedAt: at }, evaluationTime: at,
    expectedHistoryHead: state.head, decision: "DENY", code: "CONNECTOR_REFUSED", connector: { connectorId: "connector:g2", refusalCode: "UPSTREAM", detailDigest: `0x${"00".repeat(32)}` },
    runtimeSessionId: "session:g2", credentialKeyId: "key:g2", controlEpoch: 1 };
  const envelope = { id: "event:g2:refusal", type: "REQUEST_REFUSED", timestamp: at };
  const hash = core.hashCanonical(core.refusalChallenge(state.genesis.domain, d, envelope), "sha256");
  const refusal = { ...envelope, data: { ...d, refusalAuthorization: { hash, signature: await signHashWith(FIXTURE_KEY)(hash) } } };
  const r = replay([...events, refusal]);
  assert.equal(r.status, "REJECTED");
  assert.equal(r.code, "REFUSAL_AUTHORIZATION_INVALID");
  assert.match(r.reason, /expired/);
  assert.equal(core.sessionExpiredAt(state, state.runtimeSessions.get("session:g2"), 0), true);
  // A-149.0: the writer-side session checks treat it as expired too (RUNTIME_NOT_CURRENT before anything is signed), and
  // the owner's handover report shows it as not current.
  {
    const principal = legacy.find((e) => e.type === "PRINCIPAL_CREATED").data.principalId;
    const cfg = { historyFile: target, domain: state.genesis.domain, owner: principal, controller: "controller:g2", now: () => at, witness: false };
    // Step 5d P2-10: the session signer is counted, so "before anything is signed" is asserted, not assumed.
    let signed = 0;
    const sign = signHashWith(FIXTURE_KEY);
    const sessionCfg = { ...cfg, session: "session:g2", signHash: async (h) => { signed += 1; return sign(h); } };
    const notCurrent = (e) => e.code === "RUNTIME_NOT_CURRENT";
    await assert.rejects(openLocalRuntime(sessionCfg).recordEffect({ effectId: "effect:g2", intentId: "op:g2", measurer: { kind: "SESSION", id: "session:g2" }, metric: "amount", unit: "cent", amount: 1n, observedAt: at }), notCurrent);
    await assert.rejects(openLocalSimulation(sessionCfg).run({ id: "op:g2", intentId: "op:g2", action: "pay", resource: "vendor", role: "role:g2", tenure: "tenure:g2", termsCommitment: commitTerms({ subject: "g2" }) }), notCurrent);
    assert.equal(signed, 0, "A-149.0: no signature was asked");
    const before = openStore(target).state().head;
    const { openLocalOwner } = core;
    const report = openLocalOwner({ ...cfg, signer: migrationOwner() }).handover("connector:g2");
    assert.deepEqual(report.sessions.map((s) => [s.sessionId, s.current]), [["session:g2", false]]);
    assert.deepEqual(openStore(target).state().head, before, "nothing was written");
  }
  // A-62.2: the §7.2 session record normalizes the absent expiry to null; A-62.1: an explicit null in a prefix event is EVENT_DATA_INVALID.
  const { deriveRecord } = await import("../src/state-records.ts");
  assert.equal(deriveRecord(state, "session", "session:g2").expiresAt, null);
  const sp = events.findIndex((e) => e.id === "event:g2:session");
  assert.equal("expiresAt" in events[sp].data, false, "transcription preserves absence");
  const nulled = clone(events);
  nulled[sp].data.expiresAt = null;
  rejectsAt(nulled, sp, "EVENT_DATA_INVALID");
  // A-62.3: the null-expiry session does not block a fresh finite-expiry admission for the same agent and epoch after the prefix.
  const { signControlEvent } = await import("../src/signer.ts");
  const fresh = await signControlEvent(migrationOwner(), { id: "event:g2:fresh", type: "RUNTIME_SESSION_ADMITTED", timestamp: at,
    data: { sessionId: "session:g2b", agentId: "connector:g2", controllerId: "controller:g2", controlEpoch: 1, credentialKeyId: "key:g2b", credentialScheme: "eip191-personal-sign-keccak256", credentialAddress: keyFrom("eip191-personal-sign-keccak256", "k", `0x${"33".repeat(32)}`).credential, expiresAt: at + 1000 } },
    state.genesis.domain, state.head, state.hashAlgorithm);
  assert.equal(replay([...events, fresh]).status, "ACCEPTED", replay([...events, fresh]).reason);
  assert.equal(genesis.domain.deploymentId, events[0].data.domain.deploymentId);
});

test("A-52.3: a source-derived state record over the §3.1 limits (here an intent with 4,097 outcomes) is MIGRATION_UNSUPPORTED {reason: SOURCE_STATE_LIMIT} — never truncated", async () => {
  const { assertSourceStateLimits } = await import("../src/migrate.ts");
  const outcome = (i) => ({ eventId: `e:${i}`, position: i, status: "SUCCEEDED", digest: `0x${"00".repeat(32)}` });
  const ok = { kind: "intent", key: "i:1", record: { intentId: "i:1", outcomes: Array.from({ length: 4096 }, (_v, i) => outcome(i)) } };
  assert.doesNotThrow(() => assertSourceStateLimits([ok]));
  const over = { kind: "intent", key: "i:2", record: { intentId: "i:2", outcomes: Array.from({ length: 4097 }, (_v, i) => outcome(i)) } };
  assert.throws(() => assertSourceStateLimits([ok, over]), (error) => error.code === "MIGRATION_UNSUPPORTED" && error.detail.reason === "SOURCE_STATE_LIMIT" && error.detail.kind === "intent" && error.detail.key === "i:2");
  // The replay's fast encoder alone would have accepted it (the check is the migration's, A-52.3).
  const { canonicalRecordText } = await import("../src/state-records.ts");
  assert.equal(typeof canonicalRecordText(over.record), "string");
});

test("A-63: a format-1 source with a witness binding or a key rotation is refused at plan time (SOURCE_WITNESS_BOUND / SOURCE_KEY_ROTATED, nothing written); either type inside a prefix is EVENT_DATA_INVALID on replay", async (t) => {
  const ROOT = new URL("../../../", import.meta.url).pathname;
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-g2-a63-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const revive = (_k, v) => (v !== null && typeof v === "object" && typeof v["$continuity.bigint"] === "string" ? BigInt(v["$continuity.bigint"]) : v);
  const witnessed = JSON.parse(readFileSync(join(ROOT, "conformance/v1/histories/witness-bound-v1.json"), "utf8"), revive);
  const bound = Array.isArray(witnessed) ? witnessed : witnessed.events;
  assert.ok(bound.some((e) => e.type === "WITNESSES_BOUND"));
  const source = join(dir, "witness-v1.jsonl");
  createStrictStore(source, bound, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true });
  await assert.rejects(migrateHistory({ source, target: join(dir, "w2.jsonl"), now: () => 5000, signer: migrationOwner(), nextKey: false, migrationId: MIGRATION_ID, acceptUnpinnedSource: true }),
    (e) => e.code === "MIGRATION_UNSUPPORTED" && e.detail.reason === "SOURCE_WITNESS_BOUND" && e.detail.position === bound.findIndex((x) => x.type === "WITNESSES_BOUND"));
  assert.equal(readdirSync(dir).some((name) => name.startsWith("w2")), false, "nothing written");
  // Replay: a rotation or a witness binding placed inside a prefix is EVENT_DATA_INVALID at its position (before any signature check).
  const { source: f1 } = await formatOneSource(t);
  const target = join(dir, "f2.jsonl");
  await migrateHistory({ source: f1, target, now: () => 5000, signer: migrationOwner(), nextKey: false, migrationId: MIGRATION_ID });
  const events = openStore(target).state().events;
  const control = events.findIndex((e, p) => p > 0 && core.CONTROL_EVENT_TYPES.has(e.type));
  for (const type of ["OWNER_KEYS_ROTATED", "WITNESSES_BOUND", "WITNESSES_UNBOUND"]) {
    const forged = clone(events);
    forged[control] = { ...forged[control], type };
    rejectsAt(forged, control, "EVENT_DATA_INVALID");
  }
});

test("A-41: enforcement callers refuse a fenced history always and a never-migrated format-1 history unless enforceFromReadOnlyHistory (warned on every open) or the earlier writer is named", async (t) => {
  const { dir, source, pair, domain } = await formatOneSource(t);
  const base = { historyFile: source, domain, owner: "operations", controller: "operator", now: () => 200, session: "s:a", signHash: signHashWith(pair), witness: false };
  assert.throws(() => openLocalSimulation(base), (e) => e.code === "FORMAT_READ_ONLY" && e.detail.reason === "FORMAT_1" && /enforceFromReadOnlyHistory/.test(e.message));
  const warnings = [];
  const onWarning = (w) => { if (w.code === "IRONTRELLIS_READ_ONLY_ENFORCEMENT") warnings.push(w.message); };
  process.on("warning", onWarning);
  t.after(() => process.off("warning", onWarning));
  const optedIn = openLocalSimulation({ ...base, enforceFromReadOnlyHistory: true });
  assert.equal(optedIn.profile, "EFFECT_FREE_SIMULATION");
  openLocalSimulation({ ...base, enforceFromReadOnlyHistory: true });
  await new Promise((r) => setImmediate(r));
  assert.equal(warnings.length, 2, "one warning per open");
  assert.ok(openLocalSimulation({ ...base, format: "irontrellis-event/1", [FORMAT1_TEST_TOOLING]: true }), "the earlier writer named (A-30)");
  assert.equal(core.enforcementWarning(source, "irontrellis-event/2", false), undefined);
  assert.throws(() => core.enforcementWarning(source, core.LEGACY_FORMAT, false), (e) => e.detail.reason === "LEGACY");
  // Fenced: no opt-in; reads (open, verify) still work.
  await migrateHistory({ source, target: join(dir, "f2.jsonl"), now: () => 5000, signer: migrationOwner(), nextKey: false, migrationId: MIGRATION_ID });
  for (const extra of [{ enforceFromReadOnlyHistory: true }, { format: "irontrellis-event/1", [FORMAT1_TEST_TOOLING]: true }]) {
    assert.throws(() => openLocalSimulation({ ...base, ...extra }), (e) => e.code === "FORMAT_READ_ONLY" && e.detail.reason === "MIGRATED" && e.detail.target === join(dir, "f2.jsonl"));
  }
  assert.equal(openStore(source, { allowUnpinned: true }).state().format, "irontrellis-event/1");
});

test("A-57: a corrupt snapshot with a correct pin is SNAPSHOT_STALE followed by a clean full replay (never misuse); a history whose replay fails reports the store failure, not ATTESTED_STATE_ROOT_MISMATCH", async (t) => {
  const histories = await import("./helpers/format2-histories.mjs");
  const { readSnapshotBase, snapshotPathFor } = await import("../src/snapshot.ts");
  const { openHistoryStore: openRaw, storeCounters, resetStoreCountersForTests } = await import("../src/store.ts");
  const dir = histories.tempDir();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const { config, events } = await histories.richHistory(dir);
  const path = config.historyFile;
  const base = readSnapshotBase(path);
  const goodSnapshot = readFileSync(snapshotPathFor(path));
  // One record value changed: the recomputed root differs from the pin's (valid, correct) signed root.
  const records = base.records.map((e, i) => (i === Math.floor(base.records.length / 2) ? { ...e, record: { ...e.record, tampered: true } } : e));
  writeFileSync(snapshotPathFor(path), `${JSON.stringify({ ...base, records })}\n`);
  resetStoreCountersForTests();
  const store = openRaw(path, { trust: "CHECKPOINT_RESUME", witness: false });
  assert.equal(store.loadedBy(), "FULL_REPLAY");
  assert.equal(storeCounters.fullReplays, 1);
  assert.equal(core.stateRootOf(store.state()).root, replay(events).stateRoot);
  const report = store.verify();
  assert.equal(report.ok, true, report.failures.join("; "));
  assert.equal(report.snapshot, "STALE");
  assert.ok(!report.failures.some((f) => f.startsWith("ATTESTED_STATE_ROOT_MISMATCH")));
  store.close();
  // A broken file line with the good snapshot: the replay fails → the store failure (INVALID_HISTORY / chain break), no misuse inferred.
  writeFileSync(snapshotPathFor(path), goodSnapshot);
  const lines = readFileSync(path, "utf8").split("\n");
  const at = 5;
  lines[at] = lines[at].replace(/"timestamp":(\d+)/, (_m, n) => `"timestamp":${Number(n) + 1}`);
  writeFileSync(path, lines.join("\n"));
  assert.throws(() => openRaw(path, { trust: "FULL_REPLAY", witness: false }).state(), (e) => e.code !== "ATTESTED_STATE_ROOT_MISMATCH" && /INVALID_HISTORY|HASH|CHAIN/i.test(`${e.code} ${e.message}`));
});

test("A-33: a resumed reader's first lazy read of an edited prefix line that keeps its recordHash/previousHash fields fails with INVALID_HISTORY {position}; the snapshot is discarded (SNAPSHOT_STALE) and the full replay fails at the same position", async (t) => {
  const histories = await import("./helpers/format2-histories.mjs");
  const { openHistoryStore: openRaw } = await import("../src/store.ts");
  const dir = histories.tempDir();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const { config, events } = await histories.richHistory(dir);
  const path = config.historyFile;
  const pristine = readFileSync(path, "utf8");
  // A line inside the snapshot's prefix whose body changes but whose stored hash fields stay (same byte length not required: the line offsets are recomputed).
  // A line no resume step reads eagerly (the refusal record; a line the rebuild reads makes the resume itself fall back).
  const at = events.findIndex((e) => e.type === "REQUEST_REFUSED");
  assert.ok(at > 0);
  const edit = (text) => { const lines = text.split("\n"); const r = JSON.parse(lines[at]); r.event.id = `${r.event.id}-edited`; lines[at] = JSON.stringify(r); return lines.join("\n"); };
  for (const path_ of ["events", "export"]) {
    writeFileSync(path, pristine);
    // The snapshot must be the pristine one: reopen once to refresh it.
    openRaw(path, { trust: "CHECKPOINT_RESUME", witness: false }).close();
    writeFileSync(path, edit(pristine));
    const store = openRaw(path, { trust: "CHECKPOINT_RESUME", witness: false });
    assert.equal(store.loadedBy(), "CHECKPOINT_RESUME", "the edited line is in the prefix: the open itself does not read it");
    const read = path_ === "events" ? () => store.state().events[at] : () => core.exportViewState(store.state(), { fromPosition: 0, toPosition: store.state().head.position });
    assert.throws(read, (e) => e.code === "INVALID_HISTORY" && e.detail?.position === at, `${path_}: first lazy read`);
    assert.equal(existsSync(`${path}.state`), false, "the snapshot is discarded");
    assert.equal(openRaw(path, { trust: "CHECKPOINT_RESUME", witness: false, inspect: true }).loadedBy(), "FULL_REPLAY", "a new opener does not resume from it");
    assert.throws(() => store.state(), (e) => e.code === "INVALID_HISTORY" && e.detail.position === at, "the full replay fails at the same position");
    store.close();
  }
  writeFileSync(path, pristine);
});

test("A-58.7: an unknown eventSchemaVersion in a genesis read as format 2 is UNSUPPORTED_EVENT_SCHEMA (SPEC §5); the rc.1 engines' store-level UNSUPPORTED_VERSION stays for legacy and format-1 reads (TS and Python agree there)", async () => {
  const events = await import("../src/events.ts");
  const genesis = clone(ARCHITECT[0]);
  genesis.data.versions.eventSchemaVersion = "irontrellis-event/3";
  assert.equal(events.validateEvent(genesis, "irontrellis-event/2", 0).code, "UNSUPPORTED_EVENT_SCHEMA");
  assert.equal(events.validateEvent(genesis, "irontrellis-event/1", 0).code, "UNSUPPORTED_VERSION");
  assert.equal(events.validateEvent(genesis, core.LEGACY_FORMAT, 0).code, "UNSUPPORTED_VERSION");
  // An in-memory replay has no line format to go on: the history's format is detected from that literal (unknown → the rc.1 path).
  assert.equal(replay([genesis]).code, "UNSUPPORTED_VERSION");
});

test("A-72 / A-56.11: rc.1 capacity.ts's 11-type lifecycle set includes ATTEMPT_DUTY_ASSIGNED and OBLIGATION_CREATED, so a job's first assignment or obligation spends a reservation (not growth) and a repeat assignment is growth under maxEvents", async () => {
  const capacity = await import("../src/capacity.ts");
  const ledger = { capacityIntents: new Map([["i", new Set()]]), capacityDuties: new Map([["d", "i"]]), capacityObligations: new Map(), capacityDutyQuota: new Map(), lifecycleReserved: 11, dutyReserved: 0 };
  const assign = { id: "a1", type: "ATTEMPT_DUTY_ASSIGNED", timestamp: 1, data: { dutyId: "d" } };
  assert.equal(capacity.reservationDelta(ledger, assign), -1, "the first assignment of a job spends its slot: S(p) = S(p−1), not growth");
  capacity.accountCapacity(ledger, assign);
  assert.equal(capacity.reservationDelta(ledger, { ...assign, id: "a2" }), 0, "a repeat assignment adds one to S: growth (A-72.2; A-64.1's second sentence and A-64.2 are withdrawn)");
  assert.equal(capacity.reservationDelta(ledger, { id: "o", type: "OBLIGATION_CREATED", timestamp: 1, data: { record: { obligationId: "o", sourceIntentId: "i" } } }), -1);
});

test("A-36.1 / A-37: a COUNTERPARTY effect cites an earlier envelope of that counterparty for the intent and carries its amount; a SESSION effect is the intent's actor's; a CONNECTOR effect may concern another agent's intent; derived ids are actor-scoped (A-69 literals)", async (t) => {
  const { envelopeDigest, envelopeSigningHash } = await import("../src/session-auth.ts");
  const f = await setup(t);
  await f.owner.createAgent({ id: "gateway" });
  const gw = generateKeyPair("ed25519", "key:gw");
  await f.owner.admitRuntime({ session: "session:gw", agent: "gateway", epoch: 1, key: "key:gw", credential: gw.credential, expiresAt: 10_000_000 });
  const acme = generateKeyPair("ed25519", "acme:1");
  await f.owner.registerCounterparty({ counterpartyId: "acme", keys: [{ keyId: "acme:1", scheme: "ed25519", credential: acme.credential }] });
  await f.owner.grant({ id: "pay", to: "bea", actions: ["pay"], resources: ["vendor"], expiresAt: 10_000_000 });
  // Derived intent id (no raw intentId): hashCanonical(["irontrellis-intent-id/2", actor, operationId]).
  const { intentId: _raw, ...noRaw } = f.op("pay:1", { action: "pay", resource: "vendor", amount: 7n, counterparty: "acme" });
  assert.equal((await f.runtime.run(noRaw)).status, "SIMULATION_RESULT");
  const intentId = core.derivedId("intent", "bea", "pay:1");
  assert.equal(intentId, core.hashCanonical(["irontrellis-intent-id/2", "bea", "pay:1"], "sha256"));
  assert.notEqual(intentId, core.derivedId("intent", "gateway", "pay:1"), "two actors, one operation id: different derived ids");
  assert.deepEqual({ ...core.DERIVED_ID_LITERALS }, { intent: "irontrellis-intent-id/2", effect: "irontrellis-effect-id/2", refusal: "irontrellis-refusal-id/2" });
  const state = () => replay(f.owner.exportHistory()).state;
  assert.ok(state().intentAdmissions.has(intentId));
  const rt = openLocalRuntime({ ...f.config, session: "session:1", signHash: signHashWith(f.pair) });
  const body = { version: "irontrellis-counterparty-receipt/2", historyId: state().eventHistoryHashes[0], counterpartyId: "acme", keyId: "acme:1", logicalId: intentId, intentDigest: state().intentDeclarations.get(intentId).declarationDigest, payloadDigest: `0x${"ab".repeat(32)}`, amount: "7", outcome: "DELIVERED", observedAt: 100, previousReceiptDigest: null };
  const envelope = { ...body, signature: await signHashWith(acme)(envelopeSigningHash(body)) };
  const effect = (extra) => ({ intentId, measurer: { kind: "COUNTERPARTY", id: "acme" }, metric: "amount", unit: "cent", amount: 7n, observedAt: 100, ...extra });
  // Before any envelope: refused.
  await assert.rejects(rt.recordEffect(effect({ effectId: "e:0", detailDigest: envelopeDigest(envelope) })), code("TRANSITION_REJECTED"));
  await rt.recordCounterpartyReceipt({ intentId, envelope });
  await assert.rejects(rt.recordEffect(effect({ effectId: "e:1" })), code("TRANSITION_REJECTED"), "no detailDigest");
  await assert.rejects(rt.recordEffect(effect({ effectId: "e:2", detailDigest: `0x${"cd".repeat(32)}` })), code("TRANSITION_REJECTED"), "another digest");
  await assert.rejects(rt.recordEffect(effect({ effectId: "e:3", detailDigest: envelopeDigest(envelope), amount: 8n })), code("TRANSITION_REJECTED"), "another amount");
  assert.equal(typeof (await rt.recordEffect(effect({ effectId: "e:4", detailDigest: envelopeDigest(envelope), metric: "tokens" }))).eventId, "string", "no metric rule (G2 modification)");
  // A-37.1: the gateway's SESSION effect on bea's intent is refused; its CONNECTOR effect is accepted; bea's own SESSION effect too.
  const gwrt = openLocalRuntime({ ...f.config, session: "session:gw", signHash: signHashWith(gw) });
  await assert.rejects(gwrt.recordEffect({ ...effect({ effectId: "e:5" }), measurer: { kind: "SESSION", id: "gateway" } }), code("TRANSITION_REJECTED"));
  assert.equal(typeof (await gwrt.recordEffect({ ...effect({}), operationId: "op:gw", measurer: { kind: "CONNECTOR", id: "gateway" } })).eventId, "string");
  assert.ok(state().effects.has(core.derivedId("effect", "gateway", "op:gw")), "derived effect id");
  assert.equal(typeof (await rt.recordEffect({ ...effect({ effectId: "e:6" }), measurer: { kind: "SESSION", id: "bea" } })).eventId, "string");
  assert.equal(replay(f.owner.exportHistory()).status, "ACCEPTED");
  // A derived refusal id from an operation id.
  const refusal = await rt.recordRefusal({ operationId: "op:r", request: refused(1) });
  assert.equal(typeof refusal.eventId, "string");
  assert.ok(state().refusals.has(core.derivedId("refusal", "bea", "op:r")));
});

test("A-46 / A-66: everyEvents counts non-checkpoint events and never loops; a failed automatic checkpoint is reported on the committed write (CHECKPOINT_SUPPRESSED {reason}) and retried on the next qualifying write; checkpoint ids are unique (TRANSITION_INVALID)", async (t) => {
  const { signerFromKeyPair } = await import("../src/signer.ts");
  const pair = generateKeyPair("ed25519", "owner:1");
  const base = signerFromKeyPair(pair);
  let armed = false, controlCalls = 0;
  const signer = Object.freeze({ keyId: base.keyId, scheme: base.scheme, credential: base.credential, signHash: async (hash, context) => {
    if (armed && context?.purpose === "control-authorization" && (controlCalls += 1) === 2) throw new Error("the signer is unplugged");
    return base.signHash(hash, context);
  } });
  const f = await setup(t, { checkpointPolicy: { everyEvents: 1 }, signer });
  const types = () => f.owner.exportHistory().map((e) => e.type);
  const before = types().length;
  await f.owner.createRole({ id: "r:1" });
  assert.deepEqual(types().slice(before), ["ROLE_CREATED", "STATE_CHECKPOINT"], "one checkpoint per non-checkpoint event, no loop");
  // The checkpoint's signature fails: the role is committed, the result reports SIGNER_FAILED.
  armed = true; controlCalls = 0;
  const result = await f.owner.createRole({ id: "r:2" });
  armed = false;
  assert.equal(result.checkpoint?.code, "CHECKPOINT_SUPPRESSED");
  assert.equal(result.checkpoint.reason, "SIGNER_FAILED");
  assert.equal(types().at(-1), "ROLE_CREATED");
  assert.ok(replay(f.owner.exportHistory()).state.roles.has("r:2"));
  // The next qualifying write retries once (the counter is derived from the history; the failure did not reset it).
  const next = await f.owner.createRole({ id: "r:3" });
  assert.equal(next.checkpoint, undefined);
  assert.deepEqual(types().slice(-2), ["ROLE_CREATED", "STATE_CHECKPOINT"]);
  // A-46.3: a second checkpoint with an id already used is refused by the replay rule.
  await f.owner.checkpoint({ checkpointId: "cp:same" });
  await assert.rejects(f.owner.checkpoint({ checkpointId: "cp:same" }), (e) => e.code === "TRANSITION_REJECTED" && /already used/.test(e.message));
  assert.equal(replay(f.owner.exportHistory()).status, "ACCEPTED");
});

test("A-38 / A-68: a bounded caller spools a refusal its write cannot finish within recordBudgetMs (SPOOLED, the verdict unchanged); the next call drains it through the actor's session — idempotent if the slow write landed, re-derived at the drain time otherwise (attempt time in the side log), dropped when the state now allows it", async (t) => {
  const { existsSync: exists } = await import("node:fs");
  const f = await setup(t);
  const sign = signHashWith(f.pair);
  let delayMs = 0, failSlow = false;
  const slow = async (hash) => {
    if (delayMs > 0) { await new Promise((r) => setTimeout(r, delayMs)); if (failSlow) throw new Error("the signer gave up"); }
    return sign(hash);
  };
  const bounded = () => f.runtimeOf({ signHash: slow, refusalPolicy: { recordBudgetMs: 40 } });
  const denied = (id, resource) => f.op(id, { resource });
  const spool = core.refusalSpoolPathFor(f.config.historyFile), side = core.refusalSideLogPathFor(f.config.historyFile);
  const refusals = () => replay(f.owner.exportHistory()).state.refusals;
  // 1. The write is slow: SPOOLED, the decision is still NOT_AUTHORIZED; the slow write lands later with the same id.
  delayMs = 200;
  const first = await bounded().run(denied("op:a", "nowhere:a"));
  assert.equal(first.status, "NOT_AUTHORIZED");
  assert.deepEqual(first.refusalNotRecorded, { reason: "SPOOLED" });
  assert.ok(exists(spool));
  await new Promise((r) => setTimeout(r, 400));
  delayMs = 0;
  assert.equal(refusals().size, 1, "the abandoned write recorded it");
  const drained = await bounded().drainRefusals();
  assert.deepEqual(drained.map((d) => d.outcome), ["ALREADY_RECORDED"]);
  assert.equal(refusals().size, 1, "never a second refusal");
  // 2. The slow write fails: the drain records it anew at the drain time; the attempt time is in the side log.
  delayMs = 200; failSlow = true; f.now(200);
  assert.deepEqual((await bounded().run(denied("op:b", "nowhere:b"))).refusalNotRecorded, { reason: "SPOOLED" });
  await new Promise((r) => setTimeout(r, 400));
  delayMs = 0; failSlow = false; f.now(300);
  const second = await bounded().drainRefusals();
  assert.deepEqual(second.map((d) => d.outcome), ["RECORDED"]);
  const recorded = [...refusals().values()].find((r) => r.resource === "nowhere:b");
  assert.equal(recorded.evaluationTime, 300);
  const event = f.owner.exportHistory().find((e) => e.type === "REQUEST_REFUSED" && e.data.refusalId === recorded.refusalId);
  assert.equal(event.data.request.claimedAt, 300, "A-68: the re-derived request's time, never the attempt time");
  const log = readFileSync(side, "utf8").trim().split("\n").map((l) => JSON.parse(l));
  const entry = log.find((l) => l.refusalId === recorded.refusalId);
  assert.deepEqual([entry.attemptedAt, entry.drainedAt, entry.outcome], [200, 300, "RECORDED"], JSON.stringify(log));
  // 3. The state allows it by the drain: dropped with NOT_REPRODUCED_AT_DRAIN.
  delayMs = 200; failSlow = true; f.now(400);
  assert.deepEqual((await bounded().run(denied("op:c", "incident:43"))).refusalNotRecorded, { reason: "SPOOLED" });
  await new Promise((r) => setTimeout(r, 400));
  delayMs = 0; failSlow = false;
  await f.owner.grant({ id: "late", to: "bea", actions: ["read"], resources: ["incident:43"], expiresAt: 10_000_000 });
  f.now(500);
  assert.deepEqual((await bounded().drainRefusals()).map((d) => d.outcome), ["NOT_REPRODUCED_AT_DRAIN"]);
  assert.equal(exists(spool), false);
  assert.equal(replay(f.owner.exportHistory()).status, "ACCEPTED");
});

test("A-45: envelope.observedAt ≤ timestamp (replay, TRANSITION_INVALID before the chain check); the writer refuses an envelope observed after its time (INVALID_INPUT {reason: OBSERVED_AT_AHEAD}) and never advances its clock; counterpartyState()", async (t) => {
  const { counterpartyRecordChallenge, envelopeSigningHash } = await import("../src/session-auth.ts");
  const f = await setup(t);
  const acme = generateKeyPair("ed25519", "acme:1");
  await f.owner.registerCounterparty({ counterpartyId: "acme", keys: [{ keyId: "acme:1", scheme: "ed25519", credential: acme.credential }] });
  await f.owner.grant({ id: "pay", to: "bea", actions: ["pay"], resources: ["vendor"], expiresAt: 10_000_000 });
  await f.runtime.run(f.op("pay:1", { action: "pay", resource: "vendor", amount: 7n, counterparty: "acme" }));
  const state = () => replay(f.owner.exportHistory()).state;
  const rt = openLocalRuntime({ ...f.config, session: "session:1", signHash: signHashWith(f.pair) });
  const envelopeAt = async (observedAt, previous = null) => {
    const body = { version: "irontrellis-counterparty-receipt/2", historyId: state().eventHistoryHashes[0], counterpartyId: "acme", keyId: "acme:1", logicalId: "pay:1", intentDigest: state().intentDeclarations.get("pay:1").declarationDigest, payloadDigest: `0x${"ab".repeat(32)}`, amount: "7", outcome: "DELIVERED", observedAt, previousReceiptDigest: previous };
    return { ...body, signature: await signHashWith(acme)(envelopeSigningHash(body)) };
  };
  f.now(150);
  await assert.rejects(rt.recordCounterpartyReceipt({ intentId: "pay:1", envelope: await envelopeAt(151) }), (e) => e.code === "INVALID_INPUT" && e.detail.reason === "OBSERVED_AT_AHEAD");
  assert.equal(f.tick(), 150, "the writer's clock is untouched");
  assert.deepEqual(rt.counterpartyState("acme"), { counterpartyId: "acme", status: "ACTIVE", lastReceiptDigest: null, receiptCount: 0, keyIds: ["acme:1"] });
  assert.equal(f.owner.counterpartyState("nobody"), null);
  // Replay: an event whose envelope (validly signed by the counterparty and wrapped by the session) is observed after the event time.
  const events = f.owner.exportHistory(), s = state();
  const envelope = await envelopeAt(151);
  const d = { intentId: "pay:1", envelope, runtimeSessionId: "session:1", credentialKeyId: "key:1", controlEpoch: 1 };
  const wrapped = async (timestamp) => {
    const event = { id: "event:cp-ahead", type: "COUNTERPARTY_RECEIPT_RECORDED", timestamp };
    const hash = core.hashCanonical(counterpartyRecordChallenge(s.genesis.domain, d, s.head, event), "sha256");
    return { ...event, data: { ...d, recordAuthorization: { hash, signature: await signHashWith(f.pair)(hash) } } };
  };
  rejectsAt([...events, await wrapped(150)], events.length, "TRANSITION_INVALID");
  assert.equal(replay([...events, await wrapped(151)]).status, "ACCEPTED", "the same envelope at a later event time");
  await rt.recordCounterpartyReceipt({ intentId: "pay:1", envelope: await envelopeAt(150) });
  assert.equal(f.owner.counterpartyState("acme").receiptCount, 1);
});

test("A-43: a runtime handle has no exportView and its headroom answers only for budgets a request by its own actor could match (others null); owner handles are unrestricted", async (t) => {
  const f = await setup(t);
  await f.owner.createAgent({ id: "other" });
  const budget = (budgetId, subjects) => ({ budgetId, subjects: { actorIds: null, roleIds: null, actions: null, resources: null, ...subjects }, metric: "amount", period: { kind: "NONE" }, amountCap: "100", countCap: null, perOperationCap: null, notBefore: null, expiresAt: null });
  await f.owner.declareBudget(budget("b:mine", { actorIds: ["bea"] }));
  await f.owner.declareBudget(budget("b:role", { roleIds: ["reviewer"] }));
  await f.owner.declareBudget(budget("b:other", { actorIds: ["other"] }));
  const rt = openLocalRuntime({ ...f.config, session: "session:1", signHash: signHashWith(f.pair) });
  assert.equal("exportView" in rt, false);
  assert.equal("exportView" in f.runtime, false);
  assert.notEqual(rt.headroom({ budgetId: "b:mine" }), null);
  assert.notEqual(rt.headroom({ budgetId: "b:role" }), null);
  assert.equal(rt.headroom({ budgetId: "b:other" }), null, "as if unknown");
  assert.equal(rt.headroom({ budgetId: "b:none" }), null);
  assert.notEqual(f.owner.headroom({ budgetId: "b:other" }), null, "the owner sees every budget");
  assert.equal(typeof f.owner.exportView({ fromPosition: 0, toPosition: 1 }).historyId, "string");
});

test("A-32.3 / A-36.2 / A-40.2 (reports): verify lists credential reuse, CONNECTOR signers, effects measured in another metric, and what a null sourceAttestation means", async (t) => {
  const { fixturesRoot } = await import("./reference.mjs");
  const { FIXTURE_KEY } = await import("./helpers/duty-fixture.mjs");
  const revive = (_k, v) => (v !== null && typeof v === "object" && typeof v["$continuity.bigint"] === "string" ? BigInt(v["$continuity.bigint"]) : v);
  const legacy = JSON.parse(readFileSync(`${fixturesRoot}handover-history.json`, "utf8"), revive);
  const last = legacy.at(-1), principalId = legacy.find((e) => e.type === "PRINCIPAL_CREATED").data.principalId;
  const agent = (id) => ({ id: `event:${id}`, type: "AGENT_CREATED", timestamp: last.timestamp, data: { agentId: id, principalId, controllerId: "controller:g2", initialControlEpoch: 1 } });
  const session = (id, agentId, key) => ({ id: `event:${id}`, type: "RUNTIME_SESSION_ADMITTED", timestamp: last.timestamp, data: { sessionId: id, agentId, controllerId: "controller:g2", controlEpoch: 1, credentialKeyId: key, credentialAddress: FIXTURE_KEY.credential } });
  const events = [...legacy, agent("x:1"), agent("x:2"), session("s:x1", "x:1", "k:x1"), session("s:x2", "x:2", "k:x2")];
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-g2-notes-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const source = join(dir, "legacy.jsonl");
  createStrictStore(source, events, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true });
  const legacyNotes = openStore(source, { allowUnpinned: true, inspect: true }).verify().notes;
  assert.ok(legacyNotes.some((n) => n.startsWith("CREDENTIAL_REUSE:") && n.includes("s:x1") && n.includes("s:x2")), legacyNotes.join("\n"));
  // Migrated: the null sourceAttestation of a legacy prefix is explained.
  await migrateHistory({ source, target: join(dir, "t.jsonl"), now: () => 5000, signer: migrationOwner(), nextKey: false, migrationId: MIGRATION_ID });
  const migratedNotes = openStore(join(dir, "t.jsonl")).verify().notes;
  assert.ok(migratedNotes.includes("MIGRATED_PREFIX: legacy prefix: control events attested by the migrating key only"), migratedNotes.join("\n"));
  // Format 2: CONNECTOR signers and an effect in another metric.
  const f = await setup(t);
  await f.owner.createAgent({ id: "gateway" });
  const gw = generateKeyPair("ed25519", "key:gw");
  await f.owner.admitRuntime({ session: "session:gw", agent: "gateway", epoch: 1, key: "key:gw", credential: gw.credential, expiresAt: 10_000_000 });
  await f.runtime.run(f.op("op:1"));
  const gwrt = openLocalRuntime({ ...f.config, session: "session:gw", signHash: signHashWith(gw) });
  await gwrt.recordEffect({ effectId: "e:1", intentId: "op:1", measurer: { kind: "CONNECTOR", id: "gateway" }, metric: "tokens", unit: "token", amount: 3n, observedAt: 100 });
  const notes = openStore(f.config.historyFile).verify().notes;
  assert.ok(notes.some((n) => n.startsWith("CONNECTOR_SIGNERS: gateway")), notes.join("\n"));
  assert.ok(notes.some((n) => n.startsWith("EFFECT_METRIC: effect e:1 reports tokens")), notes.join("\n"));
});

test("A-65: the closure carries the type-40 body a COUNTERPARTY effect cites and, for a range starting inside a migrated prefix, every prefix body 1…from; from = 0 verifies with and without fromRecords", async (t) => {
  const { envelopeDigest, envelopeSigningHash } = await import("../src/session-auth.ts");
  const f = await setup(t);
  const acme = generateKeyPair("ed25519", "acme:1");
  await f.owner.registerCounterparty({ counterpartyId: "acme", keys: [{ keyId: "acme:1", scheme: "ed25519", credential: acme.credential }] });
  await f.owner.grant({ id: "pay", to: "bea", actions: ["pay"], resources: ["vendor"], expiresAt: 10_000_000 });
  await f.runtime.run(f.op("pay:1", { action: "pay", resource: "vendor", amount: 7n, counterparty: "acme" }));
  const state0 = replay(f.owner.exportHistory()).state;
  const body = { version: "irontrellis-counterparty-receipt/2", historyId: state0.eventHistoryHashes[0], counterpartyId: "acme", keyId: "acme:1", logicalId: "pay:1", intentDigest: state0.intentDeclarations.get("pay:1").declarationDigest, payloadDigest: `0x${"ab".repeat(32)}`, amount: "7", outcome: "DELIVERED", observedAt: 100, previousReceiptDigest: null };
  const envelope = { ...body, signature: await signHashWith(acme)(envelopeSigningHash(body)) };
  const rt = openLocalRuntime({ ...f.config, session: "session:1", signHash: signHashWith(f.pair) });
  await rt.recordCounterpartyReceipt({ intentId: "pay:1", envelope });
  const receiptAt = f.owner.exportHistory().length - 1;
  await f.owner.createRole({ id: "r:spacer" });
  await rt.recordEffect({ effectId: "e:c", intentId: "pay:1", measurer: { kind: "COUNTERPARTY", id: "acme" }, metric: "amount", unit: "cent", amount: 7n, observedAt: 100, detailDigest: envelopeDigest(envelope) });
  const state = replay(f.owner.exportHistory()).state, head = state.head.position;
  const view = core.exportViewState(state, { fromPosition: receiptAt + 1, toPosition: head, include: { fromRecords: true, referencedEvents: true } });
  assert.ok(view.referencedEvents.some((e) => e.position === receiptAt), "the cited envelope's body");
  assert.equal(core.verifyExportView(JSON.parse(JSON.stringify(view))).ok, true);
  const lacking = JSON.parse(JSON.stringify(view));
  lacking.referencedEvents = lacking.referencedEvents.filter((e) => e.position !== receiptAt);
  const missing = core.verifyExportView(lacking);
  assert.equal(missing.code, "EXPORT_DEPENDENCIES_MISSING");
  assert.ok(missing.missingPositions.includes(receiptAt));
  // A-65.4: from = 0 with and without fromRecords.
  for (const include of [{}, { fromRecords: true }]) assert.equal(core.verifyExportView(JSON.parse(JSON.stringify(core.exportViewState(state, { fromPosition: 0, toPosition: head, include })))).ok, true, JSON.stringify(include));
  // A migrated history: a range starting inside the prefix needs every prefix body 1…from.
  const { source } = await formatOneSource(t);
  const target = join(mkdtempSync(join(tmpdir(), "irontrellis-g2-a65-")), "f2.jsonl");
  await migrateHistory({ source, target, now: () => 5000, signer: migrationOwner(), nextKey: false, migrationId: MIGRATION_ID });
  const migrated = openStore(target).state(), prefixEnd = migrated.genesis.migratedFrom.position, from = Math.max(1, prefixEnd - 2);
  const prefixView = core.exportViewState(migrated, { fromPosition: from, toPosition: migrated.head.position, include: { fromRecords: true, referencedEvents: true } });
  const carried = new Set(prefixView.referencedEvents.map((e) => e.position));
  for (let q = 1; q <= from - 1; q += 1) assert.ok(carried.has(q), `prefix body ${q} of 1…${from - 1}`);
  assert.equal(core.verifyExportView(JSON.parse(JSON.stringify(prefixView))).ok, true, core.verifyExportView(JSON.parse(JSON.stringify(prefixView))).failures.join("; "));
});

// ---------------------------------------------------------------- A-54 (founder-approved 2026-10-11) with A-59, last, behind one switch

test("A-54 / A-59 (profile g3, the default): declarations, refusals, effects and wrappers bind eventId, eventType and timestamp; the writers fix the envelope before signing; frozen-r2.3 stays selectable and verifies the frozen suite", async (t) => {
  const { envelopeSigningHash, envelopeDigest } = await import("../src/session-auth.ts");
  assert.equal(core.challengeProfile(), "g3", "the default since E5 (conformance/v2-g3)");
  assert.equal(replay(ARCHITECT).status, "ACCEPTED");
  t.after(() => core.setChallengeProfile("g3"));
  // The frozen history's first declaration was signed over the r2.3 challenge: refused under g3, accepted under frozen-r2.3.
  const frozen = replay(FROZEN_R23);
  assert.equal(frozen.code, "DECLARATION_AUTHORIZATION_INVALID");
  assert.equal(FROZEN_R23[frozen.position].type, "TRANSACTION_INTENT_DECLARED");
  assert.equal(frozen.position, 11);
  core.setChallengeProfile("frozen-r2.3");
  assert.equal(replay(FROZEN_R23).status, "ACCEPTED");
  assert.equal(replay(ARCHITECT).code, "DECLARATION_AUTHORIZATION_INVALID", "the regenerated history does not verify under frozen-r2.3");
  core.setChallengeProfile("g3");
  // The challenge literals carry the envelope (§8.6, §10.1, §10.2, §11.2); §8.2 is unchanged.
  const env = { id: "event:x", timestamp: 7 };
  assert.deepEqual([core.refusalChallenge(ARCHITECT[0].data.domain, { expectedHistoryHead: { hash: `0x${"00".repeat(32)}`, position: 0 }, request: {} }, env)].map((c) => [c.eventId, c.eventType, c.timestamp]), [["event:x", "REQUEST_REFUSED", 7]]);
  assert.throws(() => core.effectChallenge(ARCHITECT[0].data.domain, {}, { hash: `0x${"00".repeat(32)}`, position: 0 }), /needs the final envelope/);
  // A g3 history written by the API: declaration (run), refusal, effect, counterparty wrapper.
  const f = await setup(t);
  const acme = generateKeyPair("ed25519", "acme:1");
  await f.owner.registerCounterparty({ counterpartyId: "acme", keys: [{ keyId: "acme:1", scheme: "ed25519", credential: acme.credential }] });
  await f.owner.grant({ id: "pay", to: "bea", actions: ["pay"], resources: ["vendor"], expiresAt: 10_000_000 });
  assert.equal((await f.runtime.run(f.op("pay:1", { action: "pay", resource: "vendor", amount: 7n, counterparty: "acme" }))).status, "SIMULATION_RESULT");
  const rt = openLocalRuntime({ ...f.config, session: "session:1", signHash: signHashWith(f.pair) });
  assert.equal(typeof (await rt.recordRefusal({ request: refused(1) })).eventId, "string");
  const s0 = replay(f.owner.exportHistory()).state;
  const body = { version: "irontrellis-counterparty-receipt/2", historyId: s0.eventHistoryHashes[0], counterpartyId: "acme", keyId: "acme:1", logicalId: "pay:1", intentDigest: s0.intentDeclarations.get("pay:1").declarationDigest, payloadDigest: `0x${"ab".repeat(32)}`, amount: "7", outcome: "DELIVERED", observedAt: 100, previousReceiptDigest: null };
  const envelope = { ...body, signature: await signHashWith(acme)(envelopeSigningHash(body)) };
  await rt.recordCounterpartyReceipt({ intentId: "pay:1", envelope });
  await rt.recordEffect({ effectId: "e:1", intentId: "pay:1", measurer: { kind: "COUNTERPARTY", id: "acme" }, metric: "amount", unit: "cent", amount: 7n, observedAt: 100, detailDigest: envelopeDigest(envelope) });
  const events = f.owner.exportHistory();
  assert.equal(replay(events).status, "ACCEPTED");
  // Changing only the envelope (an event id, or a timestamp) of a session-signed event breaks its signature under g3.
  const at = (type) => events.findIndex((e) => e.type === type);
  for (const [type, codeName, mutate] of [
    ["TRANSACTION_INTENT_DECLARED", "DECLARATION_AUTHORIZATION_INVALID", (e) => { e.id = `${e.id}:moved`; }],
    ["REQUEST_REFUSED", "REFUSAL_AUTHORIZATION_INVALID", (e) => { e.id = `${e.id}:moved`; }],
    ["COUNTERPARTY_RECEIPT_RECORDED", "RECORD_AUTHORIZATION_INVALID", (e) => { e.id = `${e.id}:moved`; }],
    ["EFFECT_RECORDED", "EFFECT_AUTHORIZATION_INVALID", (e) => { e.timestamp += 1; }],
  ]) {
    const p = at(type), forged = clone(events.slice(0, p + 1));
    mutate(forged[p]);
    rejectsAt(forged, p, codeName);
  }
  // The residual A-54 closes: under frozen-r2.3 a declaration whose event id is changed still verifies.
  core.setChallengeProfile("frozen-r2.3");
  const pd = FROZEN_R23.findIndex((e) => e.type === "TRANSACTION_INTENT_DECLARED"), moved = clone(FROZEN_R23.slice(0, pd + 1));
  moved[pd].id = `${moved[pd].id}:moved`;
  assert.equal(replay(moved).status, "ACCEPTED", "frozen-r2.3 does not bind the envelope");
  core.setChallengeProfile("g3");
  rejectsAt(moved, pd, "DECLARATION_AUTHORIZATION_INVALID");
  // Under frozen-r2.3 the g3 history's declaration does not verify (one profile per history; nothing retries the other).
  core.setChallengeProfile("frozen-r2.3");
  assert.equal(replay(events).code, "DECLARATION_AUTHORIZATION_INVALID");
  // An unknown profile is refused, never silently mapped to one of the two.
  assert.throws(() => core.setChallengeProfile("r2.4"), /unknown challenge profile/);
});

test("A-54: IRONTRELLIS_CHALLENGE_PROFILE selects frozen-r2.3 at load (the frozen suite verifies), defaults to g3, and refuses an unknown value", () => {
  const index = join(import.meta.dirname, "..", "src", "index.ts");
  const frozenFile = join(import.meta.dirname, "..", "..", "..", "conformance", "v2", "histories", "budget-v2.json");
  const script = `const core = await import(${JSON.stringify(index)}); const events = JSON.parse((await import("node:fs")).readFileSync(${JSON.stringify(frozenFile)}, "utf8")); const r = core.replay(events); console.log(JSON.stringify([core.challengeProfile(), r.status, r.code ?? null]));`;
  const run = (value) => {
    const env = { ...process.env };
    if (value === undefined) delete env.IRONTRELLIS_CHALLENGE_PROFILE; else env.IRONTRELLIS_CHALLENGE_PROFILE = value;
    return spawnSync(process.execPath, ["--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", script], { env, encoding: "utf8" });
  };
  assert.deepEqual(JSON.parse(run("frozen-r2.3").stdout), ["frozen-r2.3", "ACCEPTED", null]);
  assert.deepEqual(JSON.parse(run(undefined).stdout), ["g3", "REJECTED", "DECLARATION_AUTHORIZATION_INVALID"]);
  const bad = run("frozen");
  assert.notEqual(bad.status, 0);
  assert.match(bad.stderr, /unknown challenge profile "frozen"/);
});

test("CHALLENGE-PROFILE-01: frozen-r2.3 is verify-only — an owner write, a session write and a new history are CHALLENGE_PROFILE_READ_ONLY with nothing written; the frozen history still replays ACCEPTED; under g3 the same writes succeed", async (t) => {
  const f = await setup(t);
  t.after(() => core.setChallengeProfile("g3"));
  const dir = join(f.config.historyFile, "..");
  const files = () => Object.fromEntries(readdirSync(dir).map((name) => [name, createHash("sha256").update(readFileSync(join(dir, name))).digest("hex")]));
  const before = files();
  const rt = openLocalRuntime({ ...f.config, session: "session:1", signHash: signHashWith(f.pair) });
  const freshDir = mkdtempSync(join(tmpdir(), "irontrellis-g2-fresh-"));
  t.after(() => rmSync(freshDir, { recursive: true, force: true }));
  const fresh = { ...f.config, historyFile: join(freshDir, "history.jsonl") };
  core.setChallengeProfile("frozen-r2.3");
  assert.equal(replay(FROZEN_R23).status, "ACCEPTED", "verifying under frozen-r2.3 is unchanged");
  await assert.rejects(f.owner.createAgent({ id: "cal" }), code("CHALLENGE_PROFILE_READ_ONLY"));
  await assert.rejects(rt.recordRefusal({ request: refused(1) }), code("CHALLENGE_PROFILE_READ_ONLY"));
  await assert.rejects(createLocalOwner(fresh), code("CHALLENGE_PROFILE_READ_ONLY"));
  assert.deepEqual(files(), before, "nothing is written");
  assert.deepEqual(readdirSync(freshDir), [], "the new history leaves no file (no key file either)");
  core.setChallengeProfile("g3");
  await f.owner.createAgent({ id: "cal" });
  assert.equal(typeof (await rt.recordRefusal({ request: refused(1) })).eventId, "string");
  await createLocalOwner(fresh);
  assert.equal(replay(f.owner.exportHistory()).status, "ACCEPTED");
});

test("A-157 (G6.8): a non-lowercase PublicKey32 is EVENT_DATA_INVALID at C4 in a format-2 event (no lowercasing); the writer refuses it before signing; a mixed-case eip191 address stays accepted and is recorded lowercase", async (t) => {
  const { signerFromKeyPair: fromPair } = await import("../src/signer.ts");
  const owner = fromPair(core.keyPairFromPrivateKey("ed25519", "owner:1", `0x${(0x1001).toString(16).padStart(64, "0")}`));
  const upper = (key) => `0x${key.slice(2).toUpperCase()}`;
  const p = ARCHITECT.findIndex((e) => e.type === "RUNTIME_SESSION_ADMITTED");
  const head = replay(ARCHITECT.slice(0, p)).head;
  for (const edit of [upper, (k) => `0x${k[2].toUpperCase()}${k.slice(3)}`]) {
    const events = clone(ARCHITECT.slice(0, p + 1));
    events[p].data.credentialPublicKey = edit(ARCHITECT[p].data.credentialPublicKey);
    assert.notEqual(events[p].data.credentialPublicKey, ARCHITECT[p].data.credentialPublicKey);
    events[p] = clone(await core.signControlEvent(owner, events[p], ARCHITECT[0].data.domain, head, "sha256"));
    rejectsAt(events, p, "EVENT_DATA_INVALID");
  }
  const genesis = clone(ARCHITECT.slice(0, 1));
  genesis[0].data.ownerKeys = [{ ...genesis[0].data.ownerKeys[0], credential: upper(genesis[0].data.ownerKeys[0].credential) }];
  rejectsAt(genesis, 0, "EVENT_DATA_INVALID");
  // Writer: refused before signing (nothing appended); an eip191 address in mixed case is accepted and recorded lowercase.
  const f = await setup(t);
  const before = f.owner.exportHistory().length;
  const pair = generateKeyPair("ed25519", "key:upper");
  await assert.rejects(f.owner.admitRuntime({ session: "session:u", agent: "bea", epoch: 1, key: "key:upper", credential: upper(pair.credential), expiresAt: 10_000_000 }), (e) => e.code === "INVALID_INPUT" && e.detail?.reason === "PUBLIC_KEY_CASE");
  assert.equal(f.owner.exportHistory().length, before);
  await f.owner.createAgent({ id: "eve" });
  const address = generateKeyPair("eip191-personal-sign-keccak256", "key:eve").credential.toLowerCase();
  const mixed = `0x${address.slice(2).replace(/[a-f]/g, (c, i) => (i % 2 === 0 ? c.toUpperCase() : c))}`;
  assert.notEqual(mixed, address);
  await f.owner.admitRuntime({ session: "session:eve", agent: "eve", epoch: 1, key: "key:eve", credential: mixed, scheme: "eip191-personal-sign-keccak256", expiresAt: 10_000_000 });
  const history = f.owner.exportHistory();
  assert.equal(history.at(-1).data.credentialAddress, mixed);
  const r = replay(history);
  assert.equal(r.status, "ACCEPTED", r.reason);
  assert.equal(r.state.runtimeSessions.get("session:eve").credentialAddressKey, address);
});
