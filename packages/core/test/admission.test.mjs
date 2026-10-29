import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { referenceCore as ref, fixturesRoot as FIXTURES, cryptoVectorsPath } from "./reference.mjs";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling
const { proposeIntentAdmission, inspectAdmittedIntent, deriveAdapterIdentity, admissionControlIsCurrent, INTENT_ADMISSION_VERSION } = await import("../src/admission.ts");
const editions = await import("../src/adapter-editions.ts");
const { createRuntimeAuthorizationChallenge, hashRuntimeAuthorizationChallenge } = await import("../src/authority.ts");
const { replay } = await import("../src/replay.ts");
const { keyPairFromPrivateKey, signHashWith } = await import("../src/crypto/suites.ts");
const { DurableAdmissionCoordinator, StoreConflictError } = await import("../src/coordinators.ts");

// ---------------------------------------------------------------- helpers
const revive = (_k, v) => (v !== null && typeof v === "object" && typeof v["$continuity.bigint"] === "string" ? BigInt(v["$continuity.bigint"]) : v);
const load = (path) => JSON.parse(readFileSync(path, "utf8"), revive);
const norm = (v) => JSON.parse(JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? { $bigint: x.toString() } : x)));
const same = (actual, expected) => assert.deepEqual(norm(actual), norm(expected));
const clone = (v) => structuredClone(v);
const fixture = (mode) => {
  const base = `${FIXTURES}original-core/cases/core02-${mode}-r1/`;
  const history = load(`${base}export/history.json`), config = load(`${base}case.json`), input = load(`${base}admission.json`).input;
  const index = history.findIndex((e) => e.type === "TRANSACTION_INTENT_ADMITTED"), admissionEvent = history[index];
  const submission = { operationVersion: "continuity-adapter-submission/0.2", domain: config.domain, intentId: admissionEvent.data.intentId, admissionEvent, admittedHistory: history.slice(0, index + 1) };
  return { history, config, input, index, submission, receipt: load(`${base}export/receipt.json`) };
};
const vectors = load(cryptoVectorsPath);
const KEYS = { a: keyPairFromPrivateKey("eip191-personal-sign-keccak256", "key:core02-simulated-r1:a", vectors.keys.k1001.privateKey) };
const refReplay = (events) => ref.replayPortable({ operationVersion: ref.PORTABLE_REPLAY_VERSION, events });
const headOf = (events) => { const r = replay(events); assert.equal(r.status, "ACCEPTED"); return r.head; };

/** In-memory EventStore with the reference file store's compare-and-set semantics (spec 03 §J.1). */
const memoryStore = (initial = []) => {
  let events = Object.freeze([...initial]);
  let locked = false;
  const readAll = () => events;
  const appendAtExpectedHead = (event, expected) => {
    const observedHead = events.length === 0 ? undefined : headOf(events);
    if (observedHead === undefined || observedHead.hash !== expected.hash || observedHead.position !== expected.position || observedHead.canonicalTime !== expected.canonicalTime) throw new StoreConflictError(observedHead);
    const next = replay([...events, event]);
    if (next.status !== "ACCEPTED") throw new Error(`rejected: ${next.code} ${next.reason ?? ""}`);
    events = Object.freeze([...events, event]);
    return next.head;
  };
  const withExclusiveWriter = (cb) => { if (locked) throw new Error("busy"); locked = true; try { return cb({ readAll, appendAtExpectedHead }); } finally { locked = false; } };
  return { readAll, appendAtExpectedHead: (e, h) => withExclusiveWriter((w) => w.appendAtExpectedHead(e, h)), withExclusiveWriter };
};
/** Port of the reference DeterministicSimulatedAdapter (test helper). */
const simulatedAdapter = ({ failIntentIds = [] } = {}) => {
  const results = new Map(), attempts = [], profile = editions.approvedAdapterProfile(editions.SIMULATED_ADAPTER_ID);
  const identityOf = (input) => { const i = deriveAdapterIdentity(input); assert.equal(i.adapterProfile.profileId, profile.profileId); return i; };
  const retained = (identity) => {
    const prior = results.get(identity.idempotencyKey);
    if (prior === undefined) return undefined;
    if (prior.submissionFingerprint !== identity.submissionFingerprint) return { status: "IDEMPOTENCY_FINGERPRINT_CONFLICT", idempotencyKey: identity.idempotencyKey, retainedFingerprint: prior.submissionFingerprint, suppliedFingerprint: identity.submissionFingerprint };
    const common = { status: "RETRY", idempotencyKey: identity.idempotencyKey, submissionFingerprint: identity.submissionFingerprint, retainedEvidence: prior.evidence };
    return prior.status === "SUBMITTED" ? { ...common, acknowledgment: prior.acknowledgment } : { ...common, noEffect: prior.noEffect };
  };
  return {
    adapterProfile: profile, attempts,
    reconcile(input) { const identity = identityOf(input); return retained(identity) ?? { status: "OUTCOME_UNKNOWN", idempotencyKey: identity.idempotencyKey, submissionFingerprint: identity.submissionFingerprint }; },
    async submit(input) {
      const identity = identityOf(input), prior = retained(identity);
      if (prior !== undefined) return prior;
      const { idempotencyKey, submissionFingerprint } = identity;
      let result;
      if (failIntentIds.includes(input.intentId)) { const noEffect = editions.createAdapterNoEffect(identity); result = { status: "FAILED", idempotencyKey, submissionFingerprint, evidence: editions.adapterNoEffectEvidence(identity, noEffect), noEffect }; }
      else { const acknowledgment = editions.createAdapterAcknowledgment(identity); result = { status: "SUBMITTED", idempotencyKey, submissionFingerprint, evidence: editions.adapterAcknowledgmentEvidence(identity, acknowledgment), acknowledgment }; }
      results.set(idempotencyKey, result);
      attempts.push({ intentId: input.intentId, idempotencyKey, submissionFingerprint, result });
      return result;
    },
  };
};
export { memoryStore, simulatedAdapter, fixture, load, norm, same, vectors, KEYS, headOf };

// ---------------------------------------------------------------- adapter editions
test("adapter editions: policy and profile hashes are the spec constants", () => {
  assert.equal(editions.ADAPTER_POLICY_HASH, "0x00c3498e2744943663475d0187ca979cdd09763b88427781883693c4b8c163a7");
  assert.equal(editions.ADAPTER_POLICY_E2_HASH, ref.PORTABLE_ADAPTER_POLICY_E2_HASH);
  assert.equal(editions.ADAPTER_POLICY_E3_HASH, ref.PORTABLE_ADAPTER_POLICY_E3_HASH);
  assert.equal(editions.ADAPTER_POLICY_E4_HASH, ref.PORTABLE_ADAPTER_POLICY_E4_HASH);
  assert.equal(editions.ADAPTER_POLICY_E5_HASH, "0x32c2a5608c7110f1a291517e136cedf62d59a2cb81be1141dd2705bce307ab29");
  assert.equal(editions.ADAPTER_POLICY_E6_HASH, "0xa90baac702f22f5a5f71141318a7651c1d963bbbee28138bbea835d942d0114c");
  for (const id of [editions.SIMULATED_ADAPTER_ID, editions.LOCAL_EVIDENCE_PACKET_ADAPTER_ID, editions.REMOTE_SERVICE_REPORT_ADAPTER_ID]) {
    same(editions.knownAdapterProfile(id), ref.approvedPortableAdapterProfileForPolicy(ref.PORTABLE_ADAPTER_POLICY_E4_HASH, id));
  }
  assert.equal(editions.resolveAdapterPolicy(editions.ADAPTER_POLICY_E6_HASH).edition, "E6");
  assert.equal(editions.resolveAdapterPolicy("0x" + "1".repeat(64)), undefined);
});

test("adapter editions: acknowledgment validation and evidence agree with the reference on both fixture profiles", () => {
  for (const mode of ["packet", "simulated"]) {
    const f = fixture(mode), identity = deriveAdapterIdentity(f.submission), refIdentity = ref.derivePortableAdapterIdentity(f.submission);
    same(identity, refIdentity);
    const ack = f.history[f.index + 1].data.acknowledgment;
    assert.equal(editions.validateAdapterAcknowledgment(ack, identity), true);
    same(editions.adapterAcknowledgmentEvidence(identity, ack), ref.portableAdapterAcknowledgmentEvidence(refIdentity, ack));
    assert.equal(editions.adapterAcknowledgmentTransactionReference(ack, identity), ref.portableAdapterAcknowledgmentTransactionReference(ack, refIdentity));
    for (const change of [(a) => (a.result.kind = "X"), (a) => (a.extra = true), (a) => (a.domain.deploymentId += "-other"), (a) => a.admissionHead.position++, (a) => (a.idempotencyKey = "0x" + "3".repeat(64))]) {
      const a = clone(ack); change(a);
      assert.equal(editions.validateAdapterAcknowledgment(a, identity), false);
    }
    if (mode === "simulated") {
      const noEffect = editions.createAdapterNoEffect(identity);
      same(noEffect, ref.createPortableAdapterNoEffect(refIdentity));
      same(editions.adapterNoEffectEvidence(identity, noEffect), ref.portableAdapterNoEffectEvidence(refIdentity, noEffect));
      assert.equal(editions.validateAdapterNoEffectShape(noEffect), true);
    } else {
      assert.throws(() => editions.createAdapterNoEffect(identity));
    }
  }
});

// ---------------------------------------------------------------- challenge vectors
test("runtime authorization challenge: hashes and deterministic signatures reproduce the spec 04 vectors", async () => {
  for (const v of vectors.runtimeAuthorizationChallenge) {
    const challenge = createRuntimeAuthorizationChallenge(v.input);
    same(challenge, v.challenge);
    assert.equal(hashRuntimeAuthorizationChallenge(challenge, "keccak256"), v.challengeHash);
    const key = keyPairFromPrivateKey("eip191-personal-sign-keccak256", "k", v.signerKey);
    assert.equal(await signHashWith(key)(v.challengeHash), v.signature, `signature bytes for ${v.label}`);
  }
});

// ---------------------------------------------------------------- proposal differential
const differential = (name, input) => test(`proposeIntentAdmission differential: ${name}`, () => same(proposeIntentAdmission(input), ref.proposePortableIntentAdmission(input)));
for (const mode of ["simulated", "packet"]) {
  const f = fixture(mode);
  differential(`${mode} fixture input → PROPOSED`, f.input);
  differential(`${mode} stale head → CONFLICT`, { ...f.input, events: f.history.slice(0, 15), expectedHistoryHead: f.input.expectedHistoryHead });
  differential(`${mode} history containing the admission → RETRY even with a stale head`, { ...f.input, events: f.history.slice(0, 16) });
  differential(`${mode} bad signature → DENIED SESSION_CREDENTIAL_INVALID`, { ...f.input, binding: { ...f.input.binding, runtimeSignature: `0x${"1".repeat(128)}1b` } });
  differential(`${mode} evaluationTime behind the head → CAUSAL_TIME_INVALID`, { ...f.input, evaluationTime: 3 });
  differential(`${mode} history without genesis → STATE_NOT_AUTHORITATIVE`, { ...f.input, events: f.input.events.slice(1) });
  differential(`${mode} wrong operationVersion → UNSUPPORTED_VERSION`, { ...f.input, operationVersion: "continuity-intent-admission/0.3" });
  differential(`${mode} colliding admission event id → INDETERMINATE INVALID_INPUT`, { ...f.input, admissionEventId: f.input.events[5].id });
  differential(`${mode} intent mismatch → DENIED INTENT_MISMATCH`, { ...f.input, request: { ...f.input.request, resource: "resource:other" } });
  differential(`${mode} missing declaration → DENIED INTENT_NOT_DECLARED`, { ...f.input, binding: { ...f.input.binding, intentId: "intent:missing" } });
  differential(`${mode} extra key → INVALID_INPUT`, { ...f.input, extra: 1 });
}

test("proposeIntentAdmission: a freshly signed admission over a longer history is PROPOSED and byte-identical to the reference", async () => {
  const f = fixture("simulated"), events = f.history.slice(0, 14), head = headOf(events);
  const evaluationTime = 40, request = { ...f.input.request, claimedAt: 40 };
  const base = { runtimeSessionId: f.input.binding.runtimeSessionId, credentialKeyId: f.input.binding.credentialKeyId, controlEpoch: 1, roleId: f.input.binding.roleId, roleTenureId: f.input.binding.roleTenureId, intentId: f.input.binding.intentId, nonce: f.input.binding.nonce };
  const challenge = createRuntimeAuthorizationChallenge({ domain: f.config.domain, request, evaluationTime, policyVersion: f.input.policyVersion, historyHead: head, binding: base });
  const runtimeSignature = await signHashWith(KEYS.a)(hashRuntimeAuthorizationChallenge(challenge, "keccak256"));
  const input = { ...f.input, events, expectedHistoryHead: head, request, evaluationTime, binding: { ...base, runtimeSignature }, admissionEventId: "test:admission-40" };
  const mine = proposeIntentAdmission(input), theirs = ref.proposePortableIntentAdmission(input);
  assert.equal(mine.status, "PROPOSED");
  same(mine, theirs);
  assert.equal(ref.canonicalEncode(mine.admissionEvent), ref.canonicalEncode(theirs.admissionEvent));
  assert.equal(refReplay([...events, mine.admissionEvent]).status, "ACCEPTED");
});

test("inspectAdmittedIntent and deriveAdapterIdentity agree with the reference", () => {
  const f = fixture("simulated");
  same(inspectAdmittedIntent(f.history, f.submission.intentId, 30), ref.inspectPortableAdmittedIntent(f.history, f.submission.intentId, 30));
  same(inspectAdmittedIntent(f.history.slice(0, 15), f.submission.intentId, 14), ref.inspectPortableAdmittedIntent(f.history.slice(0, 15), f.submission.intentId, 14));
  same(inspectAdmittedIntent(f.history, "intent:absent", 30), ref.inspectPortableAdmittedIntent(f.history, "intent:absent", 30));
  assert.throws(() => inspectAdmittedIntent(f.history, f.submission.intentId, 10), TypeError);
  assert.throws(() => deriveAdapterIdentity({ ...f.submission, admittedHistory: f.history }), /exact admission-inclusive prefix/);
  const r = replay(f.history.slice(0, 19));
  assert.equal(admissionControlIsCurrent(r.state, f.submission.intentId, 18), true);
  assert.equal(admissionControlIsCurrent(replay(f.history).state, f.submission.intentId, 30), false);
});

// ---------------------------------------------------------------- coordinator
const coordinator = (store, adapter, now) => new DurableAdmissionCoordinator(store, adapter, { authoritativeNow: now ?? (() => headOf(store.readAll()).canonicalTime + 1) });

test("coordinator: prepare/admit/invoke records the consumption with the deterministic event id and exact result shapes", async () => {
  const f = fixture("simulated"), store = memoryStore(f.input.events), sim = simulatedAdapter(), sdk = coordinator(store, sim);
  const prepared = sdk.prepare(f.input), admitted = sdk.admit(prepared);
  assert.equal(admitted.status, "ADMITTED");
  same(admitted.result.admissionEvent, f.history[14]);
  same(admitted.result.newHead, headOf(f.history.slice(0, 15)));
  assert.deepEqual(sdk.admit(prepared), { status: "INVALID_PREPARATION", reason: "An unused preparation from this coordinator is required." });
  const invoked = await sdk.invoke(admitted.capability);
  assert.equal(invoked.status, "SUBMITTED"); assert.equal(invoked.recorded, true);
  const consumption = store.readAll().at(-1);
  assert.equal(consumption.id, f.history[15].id);
  same({ ...consumption, timestamp: 15 }, f.history[15]);
  assert.deepEqual(await sdk.invoke(admitted.capability), { status: "NOT_INVOKED", reason: "An unused invocation capability is required." });
  assert.equal(sim.attempts.length, 1);
  const again = await sdk.execute(f.input);
  assert.equal(again.admission.status, "NOT_ADMITTED"); assert.equal(again.admission.result.status, "CONFLICT"); assert.equal("invocation" in again, false);
});

test("coordinator: crash between admit and invoke → RETRY → reconcile never submits; retained failure is re-recorded read-only", async () => {
  const f = fixture("simulated"), store = memoryStore(f.input.events);
  const first = coordinator(store, simulatedAdapter());
  assert.equal(first.admit(first.prepare(f.input)).status, "ADMITTED");
  // The process dies here: the capability is gone, only the durable admission remains.
  const sim = simulatedAdapter(), second = coordinator(store, sim);
  const recovered = await second.execute({ ...f.input, events: store.readAll() });
  assert.equal(recovered.admission.status, "NOT_ADMITTED"); assert.equal(recovered.admission.result.status, "RETRY");
  assert.deepEqual(recovered.invocation, { status: "OUTCOME_UNKNOWN", reason: "The adapter cannot establish a definitive outcome.", idempotencyKey: recovered.admission.result.existingAdmissionHead && deriveAdapterIdentity(f.submission).idempotencyKey, submissionFingerprint: deriveAdapterIdentity(f.submission).submissionFingerprint });
  assert.equal(sim.attempts.length, 0); assert.equal(store.readAll().length, 15);
  // An adapter that retained a FAILED result reconciles it into a terminal outcome without another submit.
  const failing = simulatedAdapter({ failIntentIds: [f.submission.intentId] });
  await failing.submit(f.submission);
  const third = coordinator(store, failing), result = await third.reconcile(f.submission.intentId);
  assert.equal(result.status, "RETRY"); assert.equal(result.recorded, true);
  assert.equal(store.readAll().at(-1).type, "TRANSACTION_OUTCOME_RECORDED"); assert.equal(store.readAll().at(-1).data.status, "FAILED");
  assert.equal(store.readAll().at(-1).id, `event:local:failure:${ref.hashCanonical([f.submission.intentId, f.history[14].id]).slice(2)}`);
  const before = store.readAll().length;
  assert.equal((await third.reconcile(f.submission.intentId)).status, "RETRY"); assert.equal(store.readAll().length, before);
  assert.equal((await third.reconcile("intent:absent")).reason, "The original durable admission is unavailable.");
});

test("coordinator: NOT_INVOKED when time is behind the head or the control tuple changed; foreign profiles never persist", async () => {
  const f = fixture("simulated");
  let calls = 0;
  const foreign = { adapterProfile: editions.approvedAdapterProfile(editions.LOCAL_EVIDENCE_PACKET_ADAPTER_ID), submit() { calls++; throw new Error("no"); }, reconcile() { calls++; throw new Error("no"); } };
  const store = memoryStore(f.input.events), sdk = coordinator(store, foreign);
  assert.equal(sdk.admit(sdk.prepare(f.input)).status, "UNAVAILABLE"); assert.equal(store.readAll().length, 14); assert.equal(calls, 0);

  const early = memoryStore(f.input.events), sim = simulatedAdapter(), sdkEarly = coordinator(early, sim, () => 5);
  const ok = sdkEarly.admit(sdkEarly.prepare(f.input));
  assert.equal(ok.status, "ADMITTED");
  assert.deepEqual(await sdkEarly.invoke(ok.capability), { status: "NOT_INVOKED", reason: "Current durable history, time or serialized control could not be established." });

  const fenced = memoryStore(f.input.events), sdkFenced = coordinator(fenced, sim, () => 20);
  const admitted = sdkFenced.admit(sdkFenced.prepare(f.input));
  assert.equal(admitted.status, "ADMITTED");
  fenced.appendAtExpectedHead({ ...f.history[19], timestamp: 19 }, headOf(fenced.readAll()));
  assert.equal(inspectAdmittedIntent(fenced.readAll(), f.submission.intentId, 20).currentControl, false);
  assert.deepEqual(await sdkFenced.invoke(admitted.capability), { status: "NOT_INVOKED", reason: "The original admission is consumed, terminal, replaced or no longer under its admitted control tuple." });
  assert.equal(sim.attempts.length, 0);
});

test("format 1: INTENT_REQUIRED over 5,000 declarations by the actor cites the genesis, the actor's lifecycle and the head (legacy cites every intent)", async (t) => {
  const { mkdtempSync, rmSync } = await import("node:fs"), { tmpdir } = await import("node:os"), { join } = await import("node:path");
  const { createLocalDomain, createLocalOwner } = await import("../src/owner.ts");
  const { TRELLIS_FORMAT } = await import("../src/events.ts");
  const { proposeIntentAdmissionState } = await import("../src/admission.ts");
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-intent-required-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const domain = createLocalDomain({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true });
  const owner = await createLocalOwner({ historyFile: join(dir, "history.jsonl"), domain, owner: "operations", controller: "operator", now: () => 100, format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true });
  await owner.createAgent({ id: "bea" });
  await owner.createRole({ id: "reviewer" });
  await owner.appoint({ agent: "bea", role: "reviewer", tenure: "shift:1", number: 1 });
  const credential = (await import("../src/crypto/suites.ts")).generateKeyPair("ed25519", "key:1").credential;
  await owner.admitRuntime({ session: "session:1", agent: "bea", epoch: 1, key: "key:1", credential, expiresAt: 10_000 });
  const profile = editions.approvedAdapterProfile(editions.SIMULATED_ADAPTER_ID), prefix = owner.exportHistory();
  const events = [...prefix, ...Array.from({ length: 5_000 - prefix.length }, (_, n) => ({ id: `declaration:${n}`, type: "TRANSACTION_INTENT_DECLARED", timestamp: 100, data: {
    intentId: `operation:${n}`, nonce: `nonce:${n}`, adapterProfile: profile, actorId: "bea", action: "read", resource: "incident:42", roleId: "reviewer", roleTenureId: "shift:1" } }))];
  const state = replay(events).state;
  const result = proposeIntentAdmissionState(state, {
    operationVersion: INTENT_ADMISSION_VERSION, expectedHistoryHead: state.head, admissionEventId: "admission:x", domain, policyVersion: state.genesis.policyVersion,
    request: { actorId: "bea", action: "read", resource: "incident:42", claimedAt: 101 }, evaluationTime: 101,
    binding: { runtimeSessionId: "session:1", credentialKeyId: "key:1", controlEpoch: 1, roleId: "reviewer", roleTenureId: "shift:1", runtimeSignature: `0x${"11".repeat(64)}` },
  });
  assert.deepEqual([result.status, result.authorization.code], ["DENIED", "INTENT_REQUIRED"]);
  const cited = result.authorization.failures[0].evidence;
  assert.deepEqual(cited.map((e) => [e.eventType, e.position]).sort((a, b) => a[1] - b[1]), [["DEPLOYMENT_INITIALIZED", 0], ["AGENT_CREATED", events.findIndex((e) => e.type === "AGENT_CREATED")], ["TRANSACTION_INTENT_DECLARED", 4_999]]);
});
