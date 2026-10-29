import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { replay } from "../src/replay.ts";
import { inspectAdmittedIntentState } from "../src/admission.ts";
import { DurableAdmissionCoordinator, admittedSubmissionIdentity } from "../src/coordinators.ts";
import { approvedAdapterProfile, SIMULATED_ADAPTER_ID, LOCAL_EVIDENCE_PACKET_ADAPTER_ID } from "../src/adapter-editions.ts";

// Retained public signed histories only: no key loading, derivation or signing.
const revive = (_key, value) => value && typeof value === "object" && typeof value["$continuity.bigint"] === "string" ? BigInt(value["$continuity.bigint"]) : value;
const history = JSON.parse(readFileSync(new URL("../../../conformance/v2-regenerated/histories/lifecycle-v2.json", import.meta.url), "utf8"), revive);
const admissionIndex = history.findIndex((event) => event.type === "TRANSACTION_INTENT_ADMITTED");
const intentId = history[admissionIndex].data.intentId;
const accepted = (events) => { const r = replay(events); assert.equal(r.status, "ACCEPTED", `${r.code}: ${r.reason}`); return r.state; };
const base = accepted(history.slice(0, admissionIndex + 1));
const digest = (value) => createHash("sha256").update(JSON.stringify(value, (_key, item) => typeof item === "bigint" ? { bigint: item.toString() } : item instanceof Map ? { map: [...item] } : item instanceof Set ? { set: [...item] } : item)).digest("hex");
const hash = (byte) => "0x" + byte.repeat(64);

function fixture({ state = base, cached = true } = {}) {
  let locked = false, locks = 0, reads = 0, appends = 0, calls = 0, lockError = false, stateError = false;
  const observations = [];
  const store = {
    readAll() { assert.equal(locked, true); reads++; return state.events; },
    appendAtExpectedHead() { appends++; throw new Error("Resume must not append"); },
    withExclusiveWriter(callback) {
      locks++; if (lockError) throw new Error("Unavailable lock"); assert.equal(locked, false); locked = true;
      try { return callback(store); } finally { locked = false; }
    },
    ...(cached ? { state() { assert.equal(locked, true); reads++; if (stateError) throw new Error("Unavailable state"); return state; } } : {}),
  };
  const adapter = {
    adapterProfile: approvedAdapterProfile(SIMULATED_ADAPTER_ID),
    submit(input) {
      assert.equal(locked, true); calls++;
      const actual = admittedSubmissionIdentity(input); observations.push(actual);
      return Promise.resolve({ status: "OUTCOME_UNKNOWN", idempotencyKey: actual.identity.idempotencyKey, submissionFingerprint: actual.identity.submissionFingerprint });
    },
    reconcile() { throw new Error("Resume must not reconcile"); },
  };
  const make = () => new DurableAdmissionCoordinator(store, adapter, { authoritativeNow: () => state.head.canonicalTime });
  const coordinator = make();
  const admission = base.intentAdmissions.get(intentId);
  const request = () => ({ intentId, admissionEventId: history[admissionIndex].id,
    admissionHead: { ...admission.admissionHead }, submissionIdentity: {
      idempotencyKey: admission.adapterIdentity.idempotencyKey,
      submissionFingerprint: admission.adapterIdentity.submissionFingerprint,
    }, noDispatchStart() { assert.equal(locked, true); return true; } });
  return { store, adapter, coordinator, make, request, observations,
    setState(value) { state = value; }, failLock() { lockError = true; }, failState() { stateError = true; },
    counters: () => ({ locks, reads, appends, calls }),
    resume(req = request(), instance = coordinator) {
      const before = digest(state), prior = { locks, appends, calls };
      const result = instance.resumeInvocation(req);
      assert.equal(digest(state), before, "Every resume path leaves the full observed state unchanged");
      assert.equal(locks, prior.locks + 1, "Exactly one writer-lock entry");
      assert.equal(appends, prior.appends, "Zero appends"); assert.equal(calls, prior.calls, "Zero adapter callbacks during resume");
      assert.equal(Object.isFrozen(result), true);
      return result;
    },
  };
}
const refusal = (f, req, reason) => assert.deepEqual(f.resume(req), { status: "NOT_RESUMABLE", reason });

for (const cached of [true, false]) test(`restart: ${cached ? "cached replay state" : "fresh replay from writer"}, one invoke and single-use capability`, async () => {
  const f = fixture({ cached });
  // A distinct instance has no preparation or invocation WeakMap entries.
  const restarted = f.make(), result = f.resume(f.request(), restarted);
  assert.equal(result.status, "RESUMABLE"); assert.equal(Object.isFrozen(result.capability), true);
  assert.equal(Object.isFrozen(result.capability.admissionHead), true);
  assert.equal((await f.coordinator.invoke(result.capability)).status, "NOT_INVOKED", "Wrong instance cannot consume capability");
  assert.equal((await restarted.invoke(result.capability)).status, "OUTCOME_UNKNOWN");
  assert.equal((await restarted.invoke(result.capability)).status, "NOT_INVOKED");
  assert.equal(f.counters().calls, 1); assert.equal(f.counters().appends, 0);
  assert.deepEqual(f.observations[0].identity, { operationVersion: "continuity-adapter-submission/0.2", ...base.intentAdmissions.get(intentId).adapterIdentity });
});

test("actual retained consumed format-2 prefix is not resumable", () => {
  const f = fixture({ state: accepted(history.slice(0, admissionIndex + 2)) });
  refusal(f, f.request(), "INTENT_NOT_OPEN");
});

const mismatches = [
  ["intent id", (r) => r.intentId += ":different"],
  ["admission event id", (r) => r.admissionEventId += ":different"],
  ["head hash", (r) => r.admissionHead.hash = hash("a")],
  ["head position", (r) => r.admissionHead.position++],
  ["head time", (r) => r.admissionHead.canonicalTime++],
  ["head numeric string", (r) => r.admissionHead.position = String(r.admissionHead.position)],
  ["head extra field", (r) => r.admissionHead.extra = null],
  ["identity key", (r) => r.submissionIdentity.idempotencyKey = hash("b")],
  ["identity fingerprint", (r) => r.submissionIdentity.submissionFingerprint = hash("c")],
  ["identity absent fingerprint", (r) => delete r.submissionIdentity.submissionFingerprint],
  ["identity null fingerprint", (r) => r.submissionIdentity.submissionFingerprint = null],
  ["identity extra field", (r) => r.submissionIdentity.extra = false],
  ["outer extra field", (r) => r.extra = null],
  ["outer symbol", (r) => r[Symbol("unexpected")] = 1],
  ["missing callback", (r) => delete r.noDispatchStart],
  ["nonfunction callback", (r) => r.noDispatchStart = true],
  ["negative-zero head", (r) => r.admissionHead.position = -0],
];
for (const [name, mutate] of mismatches) test(`ADMISSION_MISMATCH: ${name}`, () => {
  const f = fixture(), req = f.request(); let checks = 0; req.noDispatchStart = () => { checks++; return true; }; mutate(req);
  refusal(f, req, "ADMISSION_MISMATCH"); assert.equal(checks, 0); assert.equal(f.counters().calls, 0);
});
for (const value of [undefined, null, false, 0, 1, "true", new Boolean(true), Promise.resolve(true)]) test(`noDispatchStart must be exact true: ${String(value)} (${typeof value})`, () => {
  const f = fixture(), req = f.request(); let checks = 0;
  req.noDispatchStart = () => { checks++; return value; }; refusal(f, req, "DISPATCH_STARTED"); assert.equal(checks, 1);
});
for (const name of ["lock", "state", "callback exception"]) test(`UNAVAILABLE: ${name}`, () => {
  const f = fixture(), req = f.request();
  if (name === "lock") f.failLock(); else if (name === "state") f.failState(); else req.noDispatchStart = () => { throw new Error("Read failed; absence not established"); };
  refusal(f, req, "UNAVAILABLE");
});

test("UNAVAILABLE: custom replay returns refusal", () => {
  const f = fixture({ cached: false });
  const c = new DurableAdmissionCoordinator(f.store, f.adapter, { authoritativeNow: () => base.head.canonicalTime, replay: () => ({ status: "REFUSED" }) });
  assert.deepEqual(f.resume(f.request(), c), { status: "NOT_RESUMABLE", reason: "UNAVAILABLE" });
});
for (const kind of ["different known profile", "malformed profile", "profile accessor"]) test(`ADAPTER_PROFILE_CHANGED: ${kind}, before state read`, () => {
  const f = fixture(); let getterCalls = 0;
  if (kind === "different known profile") f.adapter.adapterProfile = approvedAdapterProfile(LOCAL_EVIDENCE_PACKET_ADAPTER_ID);
  else if (kind === "malformed profile") f.adapter.adapterProfile = { ...f.adapter.adapterProfile, descriptorHash: hash("d") };
  else Object.defineProperty(f.adapter, "adapterProfile", { get() { getterCalls++; return approvedAdapterProfile(SIMULATED_ADAPTER_ID); } });
  refusal(f, f.request(), "ADAPTER_PROFILE_CHANGED"); assert.equal(getterCalls, 0); assert.equal(f.counters().reads, 0);
});

// Trusted-state fault injection isolates otherwise unreachable/corrupt-cache branches.
// These cases are not claims that malformed states can pass actual Core replay.
for (const kind of ["prefix hash differs", "current position behind", "missing prefix hash"]) test(`HISTORY_DIVERGED: trusted-state fault injection ${kind}`, () => {
  const state = { ...base, eventHistoryHashes: [...base.eventHistoryHashes], head: { ...base.head } };
  if (kind === "prefix hash differs") state.eventHistoryHashes[admissionIndex] = hash("e");
  else if (kind === "current position behind") state.head.position = admissionIndex - 1;
  else state.eventHistoryHashes.length = admissionIndex;
  const f = fixture({ state }); refusal(f, f.request(), "HISTORY_DIVERGED");
});
for (const kind of ["nonterminal outcome", "terminal outcome", "effect", "cancelled obligation"]) test(`INTENT_NOT_OPEN: isolated trusted-state ${kind}`, () => {
  const state = { ...base };
  if (kind.includes("outcome")) state.intentOutcomeStates = new Map([[intentId, { latest: { status: "OUTCOME_UNKNOWN" }, ...(kind === "terminal outcome" ? { terminal: { status: "CONFIRMED" } } : {}) }]]);
  else if (kind === "effect") state.effects = new Map([["effect", { intentId }]]);
  else { state.obligationIdsBySourceIntent = new Map([[intentId, "obligation"]]); state.obligations = new Map([["obligation", { status: "CANCELLED" }]]); }
  const f = fixture({ state }); refusal(f, f.request(), "INTENT_NOT_OPEN");
});
test("unrelated intent outcomes, effects and cancellation do not close this admission", () => {
  const state = { ...base, intentOutcomeStates: new Map([["other", { latest: { status: "OUTCOME_UNKNOWN" } }]]), effects: new Map([["effect", { intentId: "other" }]]), obligationIdsBySourceIntent: new Map([["other", "obligation"]]), obligations: new Map([["obligation", { status: "CANCELLED" }]]) };
  const f = fixture({ state }); assert.equal(f.resume().status, "RESUMABLE");
});
test("accepted-prefix continuity permits later head position (isolated state shape)", () => {
  const f = fixture({ state: { ...base, head: { ...base.head, position: admissionIndex + 1 } } });
  assert.equal(f.resume().status, "RESUMABLE");
});
for (const target of ["outer", "head", "identity", "callback"]) test(`caller ${target} accessor refused without invocation`, () => {
  const f = fixture(), req = f.request(); let getters = 0;
  const [object, key] = target === "outer" ? [req, "intentId"] : target === "head" ? [req.admissionHead, "hash"] : target === "identity" ? [req.submissionIdentity, "idempotencyKey"] : [req, "noDispatchStart"];
  Object.defineProperty(object, key, { get() { getters++; throw new Error("Must not run"); }, enumerable: true });
  refusal(f, req, "ADMISSION_MISMATCH"); assert.equal(getters, 0);
});
test("caller data mutations from noDispatchStart cannot change the minted record", async () => {
  const f = fixture(), req = f.request();
  req.noDispatchStart = () => { req.intentId = "different"; req.admissionEventId = "different"; req.admissionHead.hash = hash("f"); req.submissionIdentity.idempotencyKey = hash("f"); return true; };
  const result = f.resume(req); assert.equal(result.status, "RESUMABLE"); assert.equal(result.capability.intentId, intentId);
  assert.equal((await f.coordinator.invoke(result.capability)).status, "OUTCOME_UNKNOWN"); assert.equal(f.counters().calls, 1);
});
test("copied capability has no WeakMap authority", async () => {
  const f = fixture(), result = f.resume(); assert.equal(result.status, "RESUMABLE");
  assert.equal((await f.coordinator.invoke({ ...result.capability })).status, "NOT_INVOKED"); assert.equal(f.counters().calls, 0);
});
test("two resumers may mint distinct capabilities without touching the attempt fence", () => {
  const f = fixture(), a = f.resume(), b = f.resume(f.request(), f.make());
  assert.equal(a.status, "RESUMABLE"); assert.equal(b.status, "RESUMABLE"); assert.notEqual(a.capability, b.capability);
  assert.deepEqual(a.capability, b.capability); assert.equal(f.counters().calls, 0);
});
test("guard order: identity and open-state failures precede attempt callback", () => {
  const state = { ...base, intentOutcomeStates: new Map([[intentId, { latest: { status: "OUTCOME_UNKNOWN" } }]]) };
  const f = fixture({ state }), req = f.request(); let calls = 0;
  req.submissionIdentity.idempotencyKey = hash("f"); req.noDispatchStart = () => { calls++; return true; };
  refusal(f, req, "INTENT_NOT_OPEN"); assert.equal(calls, 0);
});
test("authority remains invoke's guard rather than a new resume predicate", async () => {
  const f = fixture(), result = f.resume(); assert.equal(result.status, "RESUMABLE");
  f.setState({ ...base, runtimeSessions: new Map() });
  assert.equal((await f.coordinator.invoke(result.capability)).status, "NOT_INVOKED"); assert.equal(f.counters().calls, 0);
});
