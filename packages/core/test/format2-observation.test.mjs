// A-71 (post-E5) with A-86, A-87, A-89, A-90: type 42 RECONCILIATION_OBSERVED — schema, the reconciliation challenge,
// the replay order (session authorization → reconciler binding → head → match binding → duplicate/equivocation → id →
// capacity), the `observation` and `reconciliation-cursor` records, projection row 42, the writer `recordObservation`
// with its OBSERVATION_DUPLICATE pre-check, the §7.1 rebuild and the A-71.7 listings. The C1 tests of
// ASTRA-DEVTRACK-CORE-CHANGE-REQUESTS.md (unsigned, forged, cross-stream, a crash between append and checkpoint advance,
// reconciler ≠ handle session) are the "C1:" tests below. The architect's ~13 A-71 vectors are not here (they come with
// the independent checker); `conformance/v2-regenerated` carries the engine-derived ones.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const core = await import("../src/index.ts");
const { createLocalDomain, createLocalOwner, openLocalSimulation, openLocalRuntime, commitTerms, replay } = core;
const { keyPairFromPrivateKey, signHashWith } = await import("../src/crypto/suites.ts");
const { rebuildReplayState } = await import("../src/state-rebuild.ts");

const clone = (value) => JSON.parse(JSON.stringify(value));
const digest = (n) => `0x${n.repeat(64)}`;
const keyOf = (n) => keyPairFromPrivateKey("ed25519", `k:${n}`, `0x${n.repeat(32)}`);
const rejectsAt = (events, position, expected, pattern) => {
  const r = replay(events);
  assert.equal(r.status, "REJECTED", `expected ${expected} at ${position}`);
  assert.equal(r.code, expected, r.reason);
  assert.equal(r.position, position, r.reason);
  if (pattern !== undefined) assert.match(r.reason, pattern);
  return r;
};
const accepted = (events) => { const r = replay(events); assert.equal(r.status, "ACCEPTED", `${r.code} ${r.reason}`); return r; };

/**
 * A format-2 history: actor `a` with an admitted run (`op:1`) and a CORE refusal (`refusal:1`); reconcilers `rec` and
 * `rec2` with their own sessions. `rt(name)` is a runtime handle of that session; `sign(...)` builds a signed type-42
 * event as the next event of `events` (any data, any signing session) for the replay tests.
 */
async function observationCase(t, { maxEvents } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-obs-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const clock = { t: 100 };
  let n = 0;
  const config = { historyFile: join(dir, "h.jsonl"), domain: createLocalDomain(), owner: "operations", controller: "operator", now: () => clock.t, ids: () => `e:${(n += 1)}`, nextKey: false, witness: false, ...(maxEvents === undefined ? {} : { maxEvents }) };
  const owner = await createLocalOwner(config);
  const pairs = { a: keyOf("a1"), rec: keyOf("b2"), rec2: keyOf("c3") };
  for (const id of ["a", "rec", "rec2"]) await owner.createAgent({ id });
  await owner.createRole({ id: "payer" });
  await owner.appoint({ agent: "a", role: "payer", tenure: "t:1", number: 1 });
  for (const id of ["a", "rec", "rec2"]) await owner.admitRuntime({ session: `s:${id}`, agent: id, epoch: 1, key: `k:${id}`, credential: pairs[id].credential, expiresAt: 1_000_000 });
  await owner.grant({ id: "pay", to: "a", actions: ["pay"], resources: ["vendor"], expiresAt: 1_000_000 });
  clock.t = 101;
  const sim = openLocalSimulation({ ...config, session: "s:a", signHash: signHashWith(pairs.a) });
  await sim.run({ id: "op:1", intentId: "op:1", action: "pay", resource: "vendor", role: "payer", tenure: "t:1", amount: 250n, termsCommitment: commitTerms({ invoice: 1 }) });
  const rt = (who) => openLocalRuntime({ ...config, session: `s:${who}`, signHash: signHashWith(pairs[who]) });
  await rt("a").recordRefusal({ refusalId: "refusal:1", request: { actorId: "a", action: "pay", resource: "elsewhere", claimedAt: 101 } });
  clock.t = 102;
  const events = () => owner.exportHistory();
  const positionOf = (type, pick = () => true) => events().findIndex((e) => e.type === type && pick(e));
  const sign = async (prefix, data = {}, { who = "rec", id = `obs:${prefix.length}`, timestamp = prefix.at(-1).timestamp, signHash } = {}) => {
    const head = replay(prefix).head;
    const d = {
      observationId: `o:${prefix.length}`, reconcilerAgentId: who, source: { streamId: "stripe", eventRef: "evt_1", eventDigest: digest("1") },
      call: { actorId: "a", unsupplied: ["action", "observedAt", "resource"] }, match: { result: "UNMATCHED" },
      expectedHistoryHead: head, runtimeSessionId: `s:${who}`, credentialKeyId: `k:${who}`, controlEpoch: 1, ...data,
    };
    const hash = core.hashCanonical(core.reconciliationChallenge(prefix[0].data.domain, d, { id, timestamp }), "sha256");
    return { id, type: "RECONCILIATION_OBSERVED", timestamp, data: { ...d, observationAuthorization: { hash, signature: await (signHash ?? signHashWith(pairs[who]))(hash) } } };
  };
  return { dir, config, owner, clock, pairs, rt, events, positionOf, sign };
}
const src = (eventRef, d = "1", streamId = "stripe") => ({ streamId, eventRef, eventDigest: digest(d) });

// ---------------------------------------------------------------- writer and records

test("A-71.6: recordObservation writes a ◇ type-42 event signed by the reconciler's session — MATCHED against an admission or a refusal, UNMATCHED otherwise; the derived id; observation and cursor records", async (t) => {
  const f = await observationCase(t);
  const rec = f.rt("rec");
  const admitted = f.positionOf("TRANSACTION_INTENT_ADMITTED"), refused = f.positionOf("REQUEST_REFUSED");
  const first = await rec.recordObservation({ source: src("pi_1"), call: { actorId: "a", action: "pay", resource: "vendor", amount: 250n }, decision: { intentId: "op:1" } });
  assert.deepEqual(first.match, { result: "MATCHED", position: admitted });
  assert.equal(first.equivocates, null);
  assert.equal(first.observationId, core.hashCanonical(["irontrellis-observation-id/2", "rec", "stripe", "pi_1", digest("1")], "sha256"));
  assert.equal(first.observationId, core.derivedObservationId("rec", src("pi_1")));
  const second = await rec.recordObservation({ source: src("pi_2"), call: { actorId: "a", action: "pay", resource: "elsewhere", observedAt: 99 }, decision: { refusalId: "refusal:1" } });
  assert.deepEqual(second.match, { result: "MATCHED", position: refused });
  const third = await rec.recordObservation({ observationId: "obs:raw", source: src("pi_3"), call: { actorId: "a" }, decision: { intentId: "op:missing" } });
  assert.deepEqual(third.match, { result: "UNMATCHED" });
  const events = f.events(), r = accepted(events);
  const last = events.at(-1);
  assert.equal(last.type, "RECONCILIATION_OBSERVED");
  assert.deepEqual(last.data.call, { actorId: "a", unsupplied: ["action", "observedAt", "resource"] });
  assert.equal("controlAuthorization" in last.data, false);
  assert.deepEqual(core.deriveRecord(r.state, "observation", first.observationId), {
    observationId: first.observationId, reconcilerAgentId: "rec", source: src("pi_1"), call: { actorId: "a", action: "pay", resource: "vendor", amount: "250", unsupplied: ["observedAt"] },
    match: { result: "MATCHED", position: admitted }, equivocates: null, eventId: first.eventId, position: first.head.position,
  });
  // A-89.1: the cursor of (rec, stripe) starts at count 1 and counts every accepted observation of the pair.
  assert.deepEqual(core.deriveRecord(r.state, "reconciliation-cursor", core.reconciliationCursorKey("rec", "stripe")), { reconcilerAgentId: "rec", streamId: "stripe", lastEventRef: "pi_3", lastPosition: third.head.position, count: 3 });
  assert.equal(core.reconciliationCursorKey("rec", "stripe"), core.hashCanonical(["rec", "stripe"], "sha256"));
  // Projection row 42 (A-71.5): code 42, flag bit 1 (◇), bit 2 iff call.amount; actor = reconciler, subject = call.actorId.
  const row = (position) => core.projectionRow(events[position], position, core.deriveRecord(r.state, "event", core.positionKey(position)).eventHash);
  const withAmount = row(first.head.position), without = row(third.head.position);
  assert.equal((withAmount[16] << 8) | withAmount[17], 42);
  assert.equal((withAmount[18] << 8) | withAmount[19], 2 | 4);
  assert.equal((without[18] << 8) | without[19], 2);
  assert.equal(core.EVENT_TYPE_CODES.get("RECONCILIATION_OBSERVED"), 42);
  assert.equal([...core.EVENT_TYPE_CODES.values()].includes(41), false, "code 41 is unassigned (A-71.0)");
  assert.deepEqual(core.projectionFields(events[first.head.position]), ["rec", "a", "250"]);
  const eventRecord = core.deriveRecord(r.state, "event", core.positionKey(first.head.position));
  assert.equal(eventRecord.actorId, "rec");
  assert.equal(eventRecord.subjectId, "a");
});

test("A-87: R grows by 3 for the first observation of a (reconciler, stream) pair and by 2 after (event + observation [+ cursor])", async (t) => {
  const f = await observationCase(t);
  const size = () => replay(f.events()).state.stateRecords.size;
  const rec = f.rt("rec"), rec2 = f.rt("rec2");
  let before = size();
  await rec.recordObservation({ source: src("x1"), call: { actorId: "a" } });
  assert.equal(size() - before, 3);
  before = size();
  await rec.recordObservation({ source: src("x2"), call: { actorId: "a" } });
  assert.equal(size() - before, 2);
  before = size();
  await rec.recordObservation({ source: src("y1", "1", "adyen"), call: { actorId: "a" } });
  assert.equal(size() - before, 3, "a new stream: a new cursor");
  before = size();
  await rec2.recordObservation({ source: src("x3"), call: { actorId: "a" } });
  assert.equal(size() - before, 3, "a new reconciler on the same stream: a new cursor");
});

test("A-86 / A-89.5: a duplicate is any accepted observation of (streamId, eventRef) with the same digest, across reconcilers; another digest is an equivocation whose `equivocates` is the earliest observation of the key; the writer answers OBSERVATION_DUPLICATE before signing, with the accepted position", async (t) => {
  const f = await observationCase(t);
  const rec = f.rt("rec"), rec2 = f.rt("rec2");
  const o1 = await rec.recordObservation({ source: src("evt", "a"), call: { actorId: "a" } });
  const o2 = await rec.recordObservation({ source: src("evt", "b"), call: { actorId: "a" } });
  assert.equal(o2.equivocates, o1.head.position);
  // A-86.4 accepts-second-equivocation: digest C after A and B → accepted, equivocates = the earliest (A's position).
  const o3 = await rec.recordObservation({ source: src("evt", "c"), call: { actorId: "a" } });
  assert.equal(o3.equivocates, o1.head.position);
  // A-86.4 rejects-duplicate-after-equivocation: O2 re-emitted (a crash) → OBSERVATION_DUPLICATE with O2's position; nothing written, nothing signed.
  let signed = 0;
  const counting = openLocalRuntime({ ...f.config, session: "s:rec", signHash: async (h) => { signed += 1; return signHashWith(f.pairs.rec)(h); } });
  const length = f.events().length;
  await assert.rejects(counting.recordObservation({ source: src("evt", "b"), call: { actorId: "a" } }), (e) => e.code === "OBSERVATION_DUPLICATE" && e.detail.position === o2.head.position && e.detail.observationId === o2.observationId);
  assert.equal(signed, 0);
  assert.equal(f.events().length, length);
  // A-89.5: another reconciler's identical report is a duplicate too; its different digest is an equivocation of the same key.
  await assert.rejects(rec2.recordObservation({ source: src("evt", "a"), call: { actorId: "a" } }), (e) => e.code === "OBSERVATION_DUPLICATE" && e.detail.position === o1.head.position);
  assert.equal((await rec2.recordObservation({ source: src("evt", "d"), call: { actorId: "a" } })).equivocates, o1.head.position);
  // Replay: the re-emission with a fresh envelope and the same derived id → OBSERVATION_DUPLICATE (not the id rule, A-86.0).
  const events = f.events();
  const reemitted = await f.sign(events, { observationId: o2.observationId, source: src("evt", "b") }, { id: "fresh-envelope", timestamp: events.at(-1).timestamp + 5 });
  rejectsAt([...events, reemitted], events.length, "OBSERVATION_DUPLICATE");
  // A supplied id that collides (another key) is TRANSITION_INVALID at step 7.
  const collision = await f.sign(events, { observationId: o1.observationId, source: src("evt-other", "a") });
  rejectsAt([...events, collision], events.length, "TRANSITION_INVALID", /observation id/);
  // The A-71.7 listing groups the equivocations by key.
  const notes = core.observationNotes(replay(events).state);
  assert.ok(notes.some((note) => note.startsWith("OBSERVATION_EQUIVOCATION: stripe/evt") && note.includes(`${o1.head.position}, ${o2.head.position}, ${o3.head.position}`)), notes.join("\n"));
});

// ---------------------------------------------------------------- replay order (A-71.3)

test("A-71.3: replay — matched admission and refusal, unmatched; wrong actor, a later position, a non-decision event, a stale head, a reconciler that is not the signer: TRANSITION_INVALID", async (t) => {
  const f = await observationCase(t);
  const events = f.events(), p = events.length;
  const admitted = f.positionOf("TRANSACTION_INTENT_ADMITTED"), refused = f.positionOf("REQUEST_REFUSED"), declared = f.positionOf("TRANSACTION_INTENT_DECLARED");
  accepted([...events, await f.sign(events, { match: { result: "MATCHED", position: admitted } })]);
  accepted([...events, await f.sign(events, { match: { result: "MATCHED", position: refused } })]);
  accepted([...events, await f.sign(events)]);
  rejectsAt([...events, await f.sign(events, { match: { result: "MATCHED", position: admitted }, call: { actorId: "rec", unsupplied: ["action", "observedAt", "resource"] } })], p, "TRANSITION_INVALID", /actor/);
  rejectsAt([...events, await f.sign(events, { match: { result: "MATCHED", position: p } })], p, "TRANSITION_INVALID", /at or after/);
  rejectsAt([...events, await f.sign(events, { match: { result: "MATCHED", position: declared } })], p, "TRANSITION_INVALID", /TRANSACTION_INTENT_ADMITTED or REQUEST_REFUSED/);
  rejectsAt([...events, await f.sign(events, { expectedHistoryHead: replay(events.slice(0, -1)).head })], p, "TRANSITION_INVALID", /head immediately before/);
  rejectsAt([...events, await f.sign(events, { reconcilerAgentId: "rec2" })], p, "TRANSITION_INVALID", /reconcilerAgentId/);
  // Order: a bad signature beats every later step (here a stale head as well).
  const both = await f.sign(events, { expectedHistoryHead: replay(events.slice(0, -1)).head });
  both.data.observationAuthorization.signature = both.data.observationAuthorization.signature.replace(/.$/, (c) => (c === "0" ? "1" : "0"));
  rejectsAt([...events, both], p, "OBSERVATION_AUTHORIZATION_INVALID");
});

test("C1: unsigned (missing or ungrammatical observationAuthorization) is EVENT_DATA_INVALID; forged (a well-formed signature that fails, a tampered digest, a hash unequal to the challenge, an unknown session) is OBSERVATION_AUTHORIZATION_INVALID (A-89.3); a fenced session is SESSION_FENCED", async (t) => {
  const f = await observationCase(t);
  const events = f.events(), p = events.length;
  const good = await f.sign(events);
  const variant = (mutate) => { const e = clone(good); mutate(e.data); return [...events, e]; };
  rejectsAt(variant((d) => { delete d.observationAuthorization; }), p, "EVENT_DATA_INVALID");
  rejectsAt(variant((d) => { d.observationAuthorization.hash = "0xABC"; }), p, "EVENT_DATA_INVALID");
  rejectsAt(variant((d) => { d.observationAuthorization.signature = "0x1234"; }), p, "EVENT_DATA_INVALID");
  rejectsAt(variant((d) => { d.source.eventDigest = digest("9"); }), p, "OBSERVATION_AUTHORIZATION_INVALID");
  rejectsAt(variant((d) => { d.observationAuthorization.hash = digest("7"); }), p, "OBSERVATION_AUTHORIZATION_INVALID");
  rejectsAt([...events, await f.sign(events, {}, { signHash: signHashWith(keyOf("dd")) })], p, "OBSERVATION_AUTHORIZATION_INVALID");
  rejectsAt([...events, await f.sign(events, { runtimeSessionId: "s:nobody" })], p, "OBSERVATION_AUTHORIZATION_INVALID");
  rejectsAt([...events, await f.sign(events, {}, { timestamp: 1_000_000 })], p, "OBSERVATION_AUTHORIZATION_INVALID", /expired/);
  // The envelope is bound (A-54 form): the same signature under another event id fails.
  rejectsAt([...events, { ...clone(good), id: "another-id" }], p, "OBSERVATION_AUTHORIZATION_INVALID");
  // A fenced session: the reconciler's epoch advances.
  f.clock.t = 103;
  await f.owner.advanceEpoch({ agent: "rec", from: 1, to: 2 });
  const later = f.events();
  rejectsAt([...later, await f.sign(later)], later.length, "SESSION_FENCED");
});

test("A-71.1: schema — owner-signed (controlAuthorization), unsupplied not byte-ordered / duplicated / foreign / disagreeing with the call, match.position iff MATCHED, a resource of 129 code points: EVENT_DATA_INVALID; 128 code points and an unbounded observedAt (A-89.4) are accepted", async (t) => {
  const f = await observationCase(t);
  const events = f.events(), p = events.length;
  const bad = async (data) => rejectsAt([...events, await f.sign(events, data)], p, "EVENT_DATA_INVALID");
  const good = await f.sign(events);
  rejectsAt([...events, { ...good, data: { ...good.data, controlAuthorization: { keyId: "owner:1", signature: `0x${"11".repeat(64)}` } } }], p, "EVENT_DATA_INVALID");
  await bad({ call: { actorId: "a", unsupplied: ["resource", "action", "observedAt"] } });
  await bad({ call: { actorId: "a", unsupplied: ["action", "action", "observedAt", "resource"] } });
  await bad({ call: { actorId: "a", unsupplied: ["action", "amount", "observedAt", "resource"] } });
  await bad({ call: { actorId: "a", action: "pay", unsupplied: ["action", "observedAt", "resource"] } });
  await bad({ call: { actorId: "a", unsupplied: ["observedAt", "resource"] } });
  await bad({ match: { result: "MATCHED" } });
  await bad({ match: { result: "UNMATCHED", position: 3 } });
  await bad({ match: { result: "PARTIAL" } });
  await bad({ source: { streamId: "stripe", eventRef: "evt_1", eventDigest: "0xabc" } });
  const astral = "😀";
  await bad({ call: { actorId: "a", resource: `${"r".repeat(100)}${astral.repeat(29)}`, unsupplied: ["action", "observedAt"] } });
  accepted([...events, await f.sign(events, { call: { actorId: "a", resource: `${"r".repeat(100)}${astral.repeat(28)}`, observedAt: Number.MAX_SAFE_INTEGER, unsupplied: ["action"] } })]);
  accepted([...events, await f.sign(events, { call: { actorId: "a", action: "pay", resource: "", observedAt: 0, amount: "0", unsupplied: [] } })]);
});

test("A-71.0 / A-78: type 42 is UNSUPPORTED_EVENT_TYPE in a legacy or format-1 history and EVENT_DATA_INVALID inside a migrated prefix; code 41 names no type", async () => {
  const planted = { id: "o", type: "RECONCILIATION_OBSERVED", timestamp: 1, data: {} };
  assert.equal(core.validateEvent(planted, core.LEGACY_FORMAT, 1).code, "UNSUPPORTED_EVENT_TYPE");
  assert.equal(core.validateEvent(planted, core.TRELLIS_FORMAT, 1).code, "UNSUPPORTED_EVENT_TYPE");
  for (const shadow of [core.LEGACY_FORMAT, core.TRELLIS_FORMAT]) {
    const v = core.validateEvent(planted, core.TRELLIS2_FORMAT, 2, { shadow, migratedUntil: 4 });
    assert.equal(v.code, "EVENT_DATA_INVALID");
    assert.match(v.reason, /inside a migrated prefix/);
  }
  assert.equal(core.EVENT_TYPES.length, 42);
  assert.equal(core.isEventType("RECONCILIATION_OBSERVED"), true);
});

test("A-71.8: capacity — type 42 is in RESERVE_CLASS and growth: refused CAPACITY_CONTROL_ONLY at maxEvents by the writer and by replay", async (t) => {
  const free = await observationCase(t);
  const S = (state) => { const c = core.capacityOf(state); return c.eventCount + c.lifecycleReserved + c.dutyReserved; };
  const f = await observationCase(t, { maxEvents: S(replay(free.events()).state) });
  assert.ok(core.RESERVE_CLASS.has("RECONCILIATION_OBSERVED"));
  await assert.rejects(f.rt("rec").recordObservation({ source: src("cap"), call: { actorId: "a" } }), (e) => e.code === "CAPACITY_CONTROL_ONLY");
  const events = f.events();
  rejectsAt([...events, await f.sign(events)], events.length, "CAPACITY_CONTROL_ONLY");
});

// ---------------------------------------------------------------- C1 writer tests (ASTRA-DEVTRACK C1) and the rebuild

test("C1: cross-stream — an eventRef of stream A recorded under stream B is a distinct key and never dedups against A", async (t) => {
  const f = await observationCase(t);
  const rec = f.rt("rec");
  const a = await rec.recordObservation({ source: src("evt_7", "1", "stream-a"), call: { actorId: "a" } });
  const b = await rec.recordObservation({ source: src("evt_7", "1", "stream-b"), call: { actorId: "a" } });
  assert.equal(b.equivocates, null);
  assert.notEqual(a.observationId, b.observationId);
  const state = accepted(f.events()).state;
  assert.equal(core.observationIndexOf(state, "stream-a", "evt_7").earliest, a.head.position);
  assert.equal(core.observationIndexOf(state, "stream-b", "evt_7").earliest, b.head.position);
});

test("C1: a crash between the durable append and the checkpoint advance — the re-emitted observation answers OBSERVATION_DUPLICATE (recorded: advance), for a plain observation and for an equivocation, with the accepted position", async (t) => {
  const f = await observationCase(t);
  // The adapter's own checkpoint (cursor file): advanced only after a confirmed append, or on OBSERVATION_DUPLICATE.
  const checkpoint = { at: undefined };
  const deliver = async (handle, input, crashBeforeAdvance = false) => {
    try { await handle.recordObservation(input); } catch (error) { if (error.code !== "OBSERVATION_DUPLICATE") throw error; checkpoint.at = input.source.eventRef; return error.detail.position; }
    if (crashBeforeAdvance) throw new Error("crash");
    checkpoint.at = input.source.eventRef;
    return undefined;
  };
  for (const digestOf of ["1", "2"]) {
    const input = { source: src("evt_crash", digestOf), call: { actorId: "a" } };
    await assert.rejects(deliver(f.rt("rec"), input, true), /crash/);
    const recorded = f.events().length - 1;
    assert.equal(checkpoint.at, undefined, "the crash came before the checkpoint advanced");
    // A fresh process re-emits from its old checkpoint: no second event, the accepted position, the checkpoint advances.
    assert.equal(await deliver(f.rt("rec"), input), recorded);
    assert.equal(f.events().length, recorded + 1);
    assert.equal(checkpoint.at, "evt_crash");
    checkpoint.at = undefined;
  }
  assert.equal(replay(f.events()).state.reconciliationObservations.size, 2);
});

test("C1: reconciler ≠ handle session — a reconcilerAgentId that is not the handle's agent is TRANSITION_REJECTED before signing; an owner handle has no recordObservation", async (t) => {
  const f = await observationCase(t);
  let signed = 0;
  const handle = openLocalRuntime({ ...f.config, session: "s:rec", signHash: async (h) => { signed += 1; return signHashWith(f.pairs.rec)(h); } });
  await assert.rejects(handle.recordObservation({ reconcilerAgentId: "rec2", source: src("x"), call: { actorId: "a" } }), (e) => e.code === "TRANSITION_REJECTED");
  // A decision whose actor is not call.actorId would not replay: refused before signing too.
  await assert.rejects(handle.recordObservation({ source: src("y"), call: { actorId: "rec" }, decision: { intentId: "op:1" } }), (e) => e.code === "TRANSITION_REJECTED");
  assert.equal(signed, 0);
  assert.equal("recordObservation" in f.owner, false);
  assert.ok((await handle.recordObservation({ reconcilerAgentId: "rec", source: src("z"), call: { actorId: "a" } })).eventId);
});

test("§7.1 invariant: a state rebuilt from the records (observations, cursors, the derived index) equals a full replay — the same root, the same answers to the next observations", async (t) => {
  const f = await observationCase(t);
  const rec = f.rt("rec"), rec2 = f.rt("rec2");
  await rec.recordObservation({ source: src("k1", "a"), call: { actorId: "a", amount: 5n }, decision: { intentId: "op:1" } });
  await rec.recordObservation({ source: src("k1", "b"), call: { actorId: "a" } });
  await rec2.recordObservation({ source: src("k2", "a", "other"), call: { actorId: "a" } });
  const events = f.events(), full = accepted(events);
  const records = core.stateRecordsOf(full.state).map(({ kind, key, record }) => ({ kind, key, record }));
  const rebuilt = rebuildReplayState(records, [...events]);
  assert.equal(core.stateRootOf(rebuilt).root, full.stateRoot);
  assert.deepEqual([...rebuilt.reconciliationObservations.keys()], [...full.state.reconciliationObservations.keys()]);
  assert.deepEqual([...rebuilt.reconciliationCursors.entries()], [...full.state.reconciliationCursors.entries()]);
  assert.deepEqual(core.observationIndexOf(rebuilt, "stripe", "k1"), core.observationIndexOf(full.state, "stripe", "k1"));
  for (const [data, code] of [[{ source: src("k1", "b") }, "OBSERVATION_DUPLICATE"], [{ source: src("k1", "c") }, undefined], [{ observationId: [...full.state.reconciliationObservations.keys()][0], source: src("k9") }, "TRANSITION_INVALID"]]) {
    const next = await f.sign(events, data);
    const a = core.applyEvent(core.forkReplayState(full.state), next), b = core.applyEvent(core.forkReplayState(rebuilt), next);
    assert.equal(a.ok ? undefined : a.code, code);
    assert.equal(b.ok ? undefined : b.code, code);
  }
});

test("A-71.7: verify lists equivocations, MATCHED observations whose supplied call differs from the cited request, and self-observations", async (t) => {
  const f = await observationCase(t);
  const rec = f.rt("rec"), a = f.rt("a");
  await rec.recordObservation({ source: src("m1"), call: { actorId: "a", action: "pay", resource: "vendor", amount: 999n }, decision: { intentId: "op:1" } });
  await a.recordObservation({ source: src("m2"), call: { actorId: "a" } });
  const report = core.verifyHistory(f.config.historyFile);
  assert.ok(report.notes.some((n) => /^OBSERVATION_MISMATCH: .* amount that differs/.test(n)), report.notes.join("\n"));
  assert.ok(report.notes.some((n) => /^OBSERVATION_SELF: .* reported by a about its own call/.test(n)), report.notes.join("\n"));
});
