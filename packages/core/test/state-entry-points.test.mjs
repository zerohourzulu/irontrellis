/**
 * The replay-free state entry points (admission, receipts, administration,
 * coordinators over a HistoryStore) against their portable `events` forms,
 * which stay byte-identical to the reference (see admission/receipts/
 * administration tests). Every state form must return exactly what the
 * portable form returns for `events = state.events`.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";

import { fixturesRoot as FIXTURES, cryptoVectorsPath } from "./reference.mjs";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling
const A = await import("../src/admission.ts");
const R = await import("../src/receipts.ts");
const M = await import("../src/administration.ts");
const editions = await import("../src/adapter-editions.ts");
const { replay, withProspectiveEvent, applyEvent, createReplayState } = await import("../src/replay.ts");
const { createHistoryStore: createHistoryStoreStrict, openHistoryStore: openHistoryStoreStrict } = await import("../src/store.ts");
// Fixture writes to legacy and format-1 files (SPEC §16.1: those formats open read only by default; format 2 is the wire). These tests cover the earlier store writer, so the fence is off here.
const createHistoryStore = (path, events, options = {}) => createHistoryStoreStrict(path, events, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true, ...options });
const openHistoryStore = (path, options = {}) => openHistoryStoreStrict(path, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true, ...options });
const { migrateHistory } = await import("../src/migrate.ts");
const { canonicalEncode } = await import("../src/canonical.ts");
const { createRuntimeAuthorizationChallenge, hashRuntimeAuthorizationChallenge } = await import("../src/authority.ts");
const { keyPairFromPrivateKey, signHashWith, generateKeyPair } = await import("../src/crypto/suites.ts");
const { DurableAdmissionCoordinator, DurableReceiptCoordinator } = await import("../src/coordinators.ts");
const { createLocalDomain, createLocalOwner } = await import("../src/owner.ts");
const { TRELLIS_FORMAT } = await import("../src/events.ts");

const revive = (_k, v) => (v !== null && typeof v === "object" && typeof v["$continuity.bigint"] === "string" ? BigInt(v["$continuity.bigint"]) : v);
const load = (path) => JSON.parse(readFileSync(path, "utf8"), revive);
const norm = (v) => JSON.parse(JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? { $bigint: x.toString() } : x)));
const same = (actual, expected, message) => assert.deepEqual(norm(actual), norm(expected), message);
const vectors = load(cryptoVectorsPath);
const stateOf = (events) => { const r = replay(events); assert.equal(r.status, "ACCEPTED", r.reason); return r.state; };
const headOf = (events) => stateOf(events).head;
const without = (input, ...keys) => Object.fromEntries(Object.entries(input).filter(([k]) => !keys.includes(k)));
/** Outcome of a sync or async call: its value, or the thrown error's class and message. */
const outcome = async (fn) => { try { return { value: norm(await fn()) }; } catch (e) { return { error: `${e?.constructor?.name}:${e?.message}` }; } };

const base = `${FIXTURES}original-core/cases/core02-simulated-r1/`;
const history = load(`${base}export/history.json`), config = load(`${base}case.json`), admissionInput = load(`${base}admission.json`).input, receipt = load(`${base}export/receipt.json`);
const handover = load(`${FIXTURES}handover-history.json`), handoverCase = load(`${FIXTURES}handover-case.json`);
const INTENT = "intent:core02-simulated-r1";
const keyA = signHashWith(keyPairFromPrivateKey("eip191-personal-sign-keccak256", "key:core02-simulated-r1:a", vectors.keys.k1001.privateKey));
const keyB = signHashWith(keyPairFromPrivateKey("eip191-personal-sign-keccak256", "key:core02-simulated-r1:b", vectors.keys.k1003.privateKey));

// ---------------------------------------------------------------- fork isolation
test("withProspectiveEvent: applies the next event to a fork, equals the replayed head and leaves the base state untouched", () => {
  for (const n of [14, 16, 18, 23, 25]) {
    const baseState = stateOf(history.slice(0, n)), before = snapshot(baseState);
    const prospective = withProspectiveEvent(baseState, history[n]);
    assert.equal(prospective.ok, true, `event ${n}`);
    same(prospective.head, headOf(history.slice(0, n + 1)));
    same(snapshot(prospective.state), snapshot(stateOf(history.slice(0, n + 1))), `fork state after event ${n}`);
    same(snapshot(baseState), before, `base untouched by event ${n}`);
  }
  const rejected = withProspectiveEvent(stateOf(history.slice(0, 16)), history[16 - 2]);
  assert.equal(rejected.ok, false); assert.equal(rejected.code, "EVENT_ID_DUPLICATE");
});
/** Every map/set/array of a state, including the nested containers the transitions mutate in place. */
function snapshot(state) {
  const plain = (v) => v instanceof Map ? [...v].map(([k, x]) => [k, plain(x)]) : v instanceof Set ? [...v] : Array.isArray(v) ? v.map(plain) : v;
  const out = {};
  for (const [key, value] of Object.entries(state)) if (value instanceof Map || value instanceof Set || Array.isArray(value) || key === "head") out[key] = plain(value);
  return out;
}

test("migrated history: the state forms keep the portable refusals inside the re-recorded legacy prefix; forks inside it fall back to a private rebuild", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-state-migrated-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  createHistoryStore(join(dir, "legacy.jsonl"), history, { fsync: false });
  await migrateHistory({ source: join(dir, "legacy.jsonl"), target: join(dir, "migrated.jsonl"), now: () => 5000 });
  const migrated = openHistoryStore(join(dir, "migrated.jsonl")).state(), events = migrated.events;
  assert.ok(migrated.genesis.migratedFrom.position > 14);
  const identityInput = { operationVersion: "continuity-adapter-submission/0.2", domain: config.domain, intentId: INTENT, admissionEvent: events[14] };
  same(await outcome(() => A.deriveAdapterIdentityState(migrated, identityInput)), await outcome(() => A.deriveAdapterIdentity({ ...identityInput, admittedHistory: events.slice(0, 15) })));
  assert.match((await outcome(() => A.deriveAdapterIdentityState(migrated, identityInput))).error, /not replay-authoritative/);
  same(A.inspectAdmittedIntentState(migrated, INTENT, 6000), A.inspectAdmittedIntent(events, INTENT, 6000));
  // Inside the prefix the shadow view is bound to the state itself: the fork falls back to a private rebuild.
  const partial = createReplayState(migrated.format);
  for (const event of events.slice(0, 10)) assert.equal(applyEvent(partial, event).ok, true);
  const inside = withProspectiveEvent(partial, events[10]);
  assert.equal(inside.ok, true); assert.equal(partial.events.length, 10);
  const reference = createReplayState(migrated.format);
  for (const event of events.slice(0, 11)) applyEvent(reference, event);
  same(inside.head, reference.head);
});

// ---------------------------------------------------------------- admission
test("proposeIntentAdmissionState equals proposeIntentAdmission on the fixture cases", () => {
  const events = admissionInput.events;
  const cases = [
    admissionInput,
    { ...admissionInput, events: history.slice(0, 15), expectedHistoryHead: admissionInput.expectedHistoryHead },
    { ...admissionInput, events: history.slice(0, 16) },
    { ...admissionInput, binding: { ...admissionInput.binding, runtimeSignature: `0x${"1".repeat(128)}1b` } },
    { ...admissionInput, evaluationTime: 3 },
    { ...admissionInput, admissionEventId: events[5].id },
    { ...admissionInput, request: { ...admissionInput.request, resource: "resource:other" } },
    { ...admissionInput, binding: { ...admissionInput.binding, intentId: "intent:missing" } },
    { ...admissionInput, operationVersion: "continuity-intent-admission/0.3" },
    { ...admissionInput, extra: 1 },
  ];
  for (const input of cases) same(A.proposeIntentAdmissionState(stateOf(input.events), without(input, "events")), A.proposeIntentAdmission(input));
  assert.equal(A.proposeIntentAdmissionState(stateOf(events), admissionInput).status, "INDETERMINATE"); // `events` is not a state-form key
});

test("inspectAdmittedIntentState and deriveAdapterIdentityState equal their portable forms", async () => {
  for (const [n, time, id] of [[26, 30, INTENT], [15, 14, INTENT], [26, 30, "intent:absent"], [26, 10, INTENT], [26, 30, 7]]) {
    same(await outcome(() => A.inspectAdmittedIntentState(stateOf(history.slice(0, n)), id, time)), await outcome(() => A.inspectAdmittedIntent(history.slice(0, n), id, time)));
  }
  const identityInput = { operationVersion: "continuity-adapter-submission/0.2", domain: config.domain, intentId: INTENT, admissionEvent: history[14] };
  const expected = A.deriveAdapterIdentity({ ...identityInput, admittedHistory: history.slice(0, 15) });
  for (const n of [15, 16, 26]) same(A.deriveAdapterIdentityState(stateOf(history.slice(0, n)), identityInput), expected, `state of ${n} events`);
  for (const bad of [{ ...identityInput, intentId: "intent:absent" }, { ...identityInput, domain: { ...config.domain, deploymentId: "other" } }, { ...identityInput, admittedHistory: [] }]) {
    const portable = await outcome(() => A.deriveAdapterIdentity({ admittedHistory: history.slice(0, 15), ...bad }));
    if (!("admittedHistory" in bad)) same(await outcome(() => A.deriveAdapterIdentityState(stateOf(history.slice(0, 15)), bad)), portable);
    else assert.match((await outcome(() => A.deriveAdapterIdentityState(stateOf(history.slice(0, 15)), bad))).error, /malformed adapter identity input/);
  }
});

// ---------------------------------------------------------------- receipts
test("createReceiptState, verifyReceiptState and proposeReceiptRecordState equal their portable forms", async () => {
  const signer = { keyId: "key:core02-simulated-r1:a", signHash: keyA };
  for (const [n, issuedAt, externalOutcome] of [[16, 16, "SIMULATED"], [16, 10, "SIMULATED"], [15, 16, "SIMULATED"], [16, 16, "NOT_PROVEN"], [20, 20, "SIMULATED"]]) {
    same(await outcome(() => R.createReceiptState(stateOf(history.slice(0, n)), { intentId: INTENT, issuedAt, externalOutcome }, signer)),
      await outcome(() => R.createReceipt({ events: history.slice(0, n), intentId: INTENT, issuedAt, externalOutcome }, signer)), `create over ${n} events at ${issuedAt}`);
  }
  same(await R.createReceiptState(stateOf(history.slice(0, 16)), { intentId: INTENT, issuedAt: 16, externalOutcome: "SIMULATED" }, signer), receipt);
  const verify = (artifact, time, domain = config.domain) => ({ operationVersion: R.RECEIPT_VERIFICATION_VERSION, artifact, expectedDomain: domain, verifierTime: time });
  // Issued at the head (no replay), one event later (the recorded receipt), and over the whole history (the older-prefix replay).
  for (const n of [16, 17, 20, 26]) {
    for (const [artifact, time, domain] of [[receipt, 25], [receipt, 16], [receipt, 10], [{ ...receipt, signature: `0x${"1".repeat(128)}1b` }, 25], [receipt, 25, { ...config.domain, deploymentId: "other" }], [{ payload: receipt.payload }, 25]]) {
      const events = history.slice(0, n), input = verify(artifact, time, domain);
      same(R.verifyReceiptState(stateOf(events), input), R.verifyReceipt({ ...input, issuanceEvents: events, observedEvents: events }), `verify over ${n} events at ${time}`);
    }
  }
  const record = (events, extra = {}) => ({ operationVersion: R.RECEIPT_RECORD_ADMISSION_VERSION, artifact: receipt, events, expectedHistoryHead: headOf(events), expectedDomain: config.domain, recordEventId: history[16].id, ...extra });
  const late = await R.createReceipt({ events: history.slice(0, 20), intentId: INTENT, issuedAt: 20, externalOutcome: "SIMULATED" }, signer).catch(() => undefined);
  const cases = [
    record(history.slice(0, 16)), { ...record(history.slice(0, 16)), expectedHistoryHead: headOf(history.slice(0, 15)) }, record(history.slice(0, 17), { recordEventId: "test:second" }),
    record(history.slice(0, 16), { recordEventId: history[3].id }), { ...record(history.slice(0, 16)), operationVersion: "x" }, record(history.slice(0, 18), { recordEventId: "test:late" }),
    record(history.slice(0, 20), { recordEventId: "test:stale" }), ...(late === undefined ? [] : [record(history.slice(0, 20), { artifact: late })]),
  ];
  for (const input of cases) same(R.proposeReceiptRecordState(stateOf(input.events), without(input, "events")), R.proposeReceiptRecord(input), `record ${input.recordEventId}`);
});

// ---------------------------------------------------------------- administration
test("prepare/attach/produce AdministrativeEventState equal their portable forms (spec 04 vectors and failure codes)", async () => {
  for (const v of vectors.administrativeAuthorization) {
    const events = handover.slice(0, v.prefixHead.position + 1), state = stateOf(events);
    const input = { events, expectedDomain: handoverCase.domain, expectedHistoryHead: v.prefixHead, transition: v.unsignedTransition, runtimeSessionId: v.runtimeSessionId };
    const signer = { signHash: signHashWith(keyPairFromPrivateKey("eip191-personal-sign-keccak256", "k", v.signerKey)) };
    same(M.prepareAdministrativeEventState(state, without(input, "events")), M.prepareAdministrativeEvent(input));
    same(await M.produceAdministrativeEventState(state, without(input, "events"), signer), await M.produceAdministrativeEvent(input, signer));
    same(M.attachAdministrativeSignatureState(state, without(input, "events"), v.signature), M.attachAdministrativeSignature(input, v.signature));
    same(await outcome(() => M.attachAdministrativeSignatureState(state, without(input, "events"), `0x${"1".repeat(128)}1b`)), await outcome(() => M.attachAdministrativeSignature(input, `0x${"1".repeat(128)}1b`)));
  }
  const events = handover.slice(0, 18), state = stateOf(events);
  const { administrativeAuthorization: _, ...data } = handover[18].data;
  const input = { events, expectedDomain: handoverCase.domain, expectedHistoryHead: headOf(events), transition: { id: handover[18].id, type: handover[18].type, timestamp: handover[18].timestamp, data }, runtimeSessionId: "session:first-look:a" };
  for (const bad of [{ expectedHistoryHead: headOf(handover.slice(0, 17)) }, { runtimeSessionId: "session:missing" }, { transition: { ...input.transition, timestamp: 3 } }, { extra: 1 }]) {
    same(await outcome(() => M.prepareAdministrativeEventState(state, without({ ...input, ...bad }, "events"))), await outcome(() => M.prepareAdministrativeEvent({ ...input, ...bad })));
  }
  for (const signer of [{ signHash: async () => { throw new Error("down"); } }, { signHash: async () => "0xzz" }, { signHash: () => "0x", extra: 1 }]) {
    same(await outcome(() => M.produceAdministrativeEventState(state, without(input, "events"), signer)), await outcome(() => M.produceAdministrativeEvent(input, signer)));
  }
});

// ---------------------------------------------------------------- coordinators over a file HistoryStore
const simulatedAdapter = () => {
  const results = new Map(), attempts = [], profile = editions.approvedAdapterProfile(editions.SIMULATED_ADAPTER_ID);
  const retained = (identity) => {
    const prior = results.get(identity.idempotencyKey);
    return prior === undefined ? undefined : { status: "RETRY", idempotencyKey: identity.idempotencyKey, submissionFingerprint: identity.submissionFingerprint, retainedEvidence: prior.evidence, acknowledgment: prior.acknowledgment };
  };
  return {
    adapterProfile: profile, attempts,
    reconcile(input) { const i = A.deriveAdapterIdentity(input); return retained(i) ?? { status: "OUTCOME_UNKNOWN", idempotencyKey: i.idempotencyKey, submissionFingerprint: i.submissionFingerprint }; },
    async submit(input) {
      const identity = A.deriveAdapterIdentity(input), prior = retained(identity);
      if (prior !== undefined) return prior;
      const acknowledgment = editions.createAdapterAcknowledgment(identity);
      const result = { status: "SUBMITTED", idempotencyKey: identity.idempotencyKey, submissionFingerprint: identity.submissionFingerprint, evidence: editions.adapterAcknowledgmentEvidence(identity, acknowledgment), acknowledgment };
      results.set(identity.idempotencyKey, result); attempts.push(result);
      return result;
    },
  };
};
/** The store seen through a writer whose `readAll` is forbidden: the coordinators must use `state()`. */
const stateOnly = (store) => ({
  state: () => store.state(),
  readAll() { throw new Error("readAll must not be used"); },
  appendAtExpectedHead: (event, head) => store.appendAtExpectedHead(event, head),
  withExclusiveWriter: (callback) => store.withExclusiveWriter((writer) => callback({ readAll() { throw new Error("readAll must not be used"); }, appendAtExpectedHead: writer.appendAtExpectedHead })),
});

test("coordinators over a HistoryStore use its cached state() and reproduce the fixture history byte for byte", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-state-entry-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = createHistoryStore(join(dir, "history.jsonl"), history.slice(0, 14), { fsync: false }), store = stateOnly(file);
  let now = 15;
  const sim = simulatedAdapter(), sdk = new DurableAdmissionCoordinator(store, sim, { authoritativeNow: () => now });
  const admitted = sdk.admit(sdk.prepareState(file.state(), without(admissionInput, "events")));
  assert.equal(admitted.status, "ADMITTED");
  same(admitted.result.admissionEvent, history[14]);
  same(file.readAll(), history.slice(0, 15));
  // Crash after the adapter accepted the submission, before the consumption was recorded: a restarted
  // coordinator gets RETRY and reconciles from the durable state, never re-submitting.
  const submission = { operationVersion: "continuity-adapter-submission/0.2", domain: config.domain, intentId: INTENT, admissionEvent: history[14], admittedHistory: file.readAll() };
  assert.equal((await sim.submit(submission)).status, "SUBMITTED");
  const recovered = new DurableAdmissionCoordinator(store, sim, { authoritativeNow: () => now });
  const retry = await recovered.commit(recovered.prepareState(file.state(), without(admissionInput, "events")));
  assert.equal(retry.admission.result.status, "RETRY"); assert.equal(retry.invocation.status, "RETRY"); assert.equal(retry.invocation.recorded, true);
  assert.equal(sim.attempts.length, 1);
  same(file.readAll()[15], history[15]);
  // A fresh capability-driven invocation on another intent is covered by the admission suite; here: invoke refuses a used capability.
  assert.equal((await sdk.invoke(admitted.capability)).status, "NOT_INVOKED");
  // Receipt, then the recorded rest of the fixture through the store.
  const artifact = await R.createReceiptState(file.state(), { intentId: INTENT, issuedAt: 16, externalOutcome: "SIMULATED" }, { keyId: "key:core02-simulated-r1:a", signHash: keyA });
  same(artifact, receipt);
  const recorded = new DurableReceiptCoordinator(store).recordState(file.state(), { operationVersion: R.RECEIPT_RECORD_ADMISSION_VERSION, artifact, expectedHistoryHead: file.head(), expectedDomain: config.domain, recordEventId: history[16].id });
  assert.equal(recorded.status, "ADMITTED");
  file.append(history[17]);
  const producer = (event, session) => ({ expectedDomain: config.domain, expectedHistoryHead: file.head(), transition: (({ administrativeAuthorization: _, ...data }) => ({ id: event.id, type: event.type, timestamp: event.timestamp, data }))(event.data), runtimeSessionId: session });
  const obligation = await M.produceAdministrativeEventState(file.state(), producer(history[18], "session:core02-simulated-r1:a"), { signHash: keyA });
  file.append(obligation.event);
  for (const event of history.slice(19, 23)) file.append(event);
  file.append((await M.produceAdministrativeEventState(file.state(), producer(history[23], "session:core02-simulated-r1:b"), { signHash: keyB })).event);
  file.append(history[24]);
  file.append((await M.produceAdministrativeEventState(file.state(), producer(history[25], "session:core02-simulated-r1:b"), { signHash: keyB })).event);
  // The consumption carries the coordinator clock (15), exactly as the fixture recorded it.
  same(file.readAll(), history);
  now = 30;
  assert.equal((await recovered.reconcile(INTENT)).status, "RETRY");
  assert.equal(file.readAll().length, 26);
});

// ---------------------------------------------------------------- benchmark
test("benchmark: proposeIntentAdmissionState over a 2,000-event format-1 state takes < 50 ms", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-state-bench-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let tick = 100, ids = 0;
  const domain = createLocalDomain({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true });
  const owner = await createLocalOwner({ historyFile: join(dir, "history.jsonl"), domain, owner: "operations", controller: "operator", now: () => tick, format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true, ids: () => `bench:${(ids += 1)}` });
  await owner.createAgent({ id: "bea" });
  await owner.createRole({ id: "reviewer" });
  await owner.appoint({ agent: "bea", role: "reviewer", tenure: "shift:1", number: 1 });
  const pair = generateKeyPair("ed25519", "key:1"), sign = signHashWith(pair);
  await owner.admitRuntime({ session: "session:1", agent: "bea", epoch: 1, key: "key:1", credential: pair.credential, expiresAt: 10_000 });
  await owner.grant({ id: "read", to: "bea", actions: ["read"], resources: ["incident:42"], expiresAt: 10_000 });
  const profile = editions.approvedAdapterProfile(editions.SIMULATED_ADAPTER_ID);
  const declaration = (n) => ({ id: `declaration:${n}`, type: "TRANSACTION_INTENT_DECLARED", timestamp: 101, data: {
    intentId: `operation:${n}`, nonce: `nonce:${n}`, adapterProfile: profile, actorId: "bea", action: "read", resource: "incident:42", roleId: "reviewer", roleTenureId: "shift:1",
    termsCommitment: `0x${n.toString(16).padStart(64, "0")}` } });
  const prefix = owner.exportHistory();
  const events = [...prefix, ...Array.from({ length: 2000 - prefix.length }, (_, n) => declaration(n))];
  assert.equal(events.length, 2000);
  const state = stateOf(events);
  assert.equal(state.format, TRELLIS_FORMAT);
  const intent = state.intentDeclarations.get("operation:7").data, head = state.head, evaluationTime = 102;
  const request = { actorId: "bea", action: "read", resource: "incident:42", termsCommitment: intent.termsCommitment, claimedAt: evaluationTime };
  const binding = { runtimeSessionId: "session:1", credentialKeyId: "key:1", controlEpoch: 1, roleId: "reviewer", roleTenureId: "shift:1", intentId: "operation:7", nonce: "nonce:7" };
  const challenge = createRuntimeAuthorizationChallenge({ domain, request, evaluationTime, policyVersion: state.genesis.policyVersion, historyHead: head, binding });
  const input = { operationVersion: A.INTENT_ADMISSION_VERSION, expectedHistoryHead: head, admissionEventId: "admission:bench", domain, policyVersion: state.genesis.policyVersion,
    request, evaluationTime, binding: { ...binding, runtimeSignature: await sign(hashRuntimeAuthorizationChallenge(challenge, state.hashAlgorithm)) } };
  const timings = [];
  let result;
  for (let run = 0; run < 5; run += 1) {
    const started = performance.now();
    result = A.proposeIntentAdmissionState(state, input);
    timings.push(performance.now() - started);
  }
  assert.equal(result.status, "PROPOSED", JSON.stringify(result));
  same(result, A.proposeIntentAdmission({ ...input, events }));
  assert.equal(state.events.length, 2000); assert.equal(state.intentAdmissions.size, 0); // the fork never leaks into the state
  t.diagnostic(`proposeIntentAdmissionState at 2,000 events: first ${timings[0].toFixed(2)} ms, then ${timings.slice(1).map((x) => x.toFixed(2)).join(" / ")} ms`);
  // The median absorbs a GC pause on a loaded machine; the first call (cold authority memo) is reported above.
  const median = [...timings].sort((x, y) => x - y)[2];
  assert.ok(median < 50, `median call took ${median.toFixed(2)} ms`);
});
