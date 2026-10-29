import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { referenceCore as ref, referenceCore02, fixturesRoot as FIXTURES, cryptoVectorsPath } from "./reference.mjs";
const refAdmin = await referenceCore02("administration/index.ts");
const { prepareAdministrativeEvent, produceAdministrativeEvent, attachAdministrativeSignature, AdministrativeProducerError, administrativeTransitionEffect, deriveAdministrativeRequirements } = await import("../src/administration.ts");
const { createReceipt, RECEIPT_RECORD_ADMISSION_VERSION } = await import("../src/receipts.ts");
const { deriveAdapterIdentity } = await import("../src/admission.ts");
const editions = await import("../src/adapter-editions.ts");
const { replay } = await import("../src/replay.ts");
const { hashCanonical } = await import("../src/hash.ts");
const { canonicalEncode } = await import("../src/canonical.ts");
const { keyPairFromPrivateKey, signHashWith } = await import("../src/crypto/suites.ts");
const { DurableAdmissionCoordinator, DurableReceiptCoordinator, StoreConflictError } = await import("../src/coordinators.ts");

// ---------------------------------------------------------------- helpers
const revive = (_k, v) => (v !== null && typeof v === "object" && typeof v["$continuity.bigint"] === "string" ? BigInt(v["$continuity.bigint"]) : v);
const load = (path) => JSON.parse(readFileSync(path, "utf8"), revive);
const norm = (v) => JSON.parse(JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? { $bigint: x.toString() } : x)));
const same = (actual, expected) => assert.deepEqual(norm(actual), norm(expected));
const vectors = load(cryptoVectorsPath);
const handover = load(`${FIXTURES}handover-history.json`), handoverCase = load(`${FIXTURES}handover-case.json`);
const base = `${FIXTURES}original-core/cases/core02-simulated-r1/`;
const history = load(`${base}export/history.json`), config = load(`${base}case.json`), admissionInput = load(`${base}admission.json`).input, receipt = load(`${base}export/receipt.json`);
const INTENT = "intent:core02-simulated-r1";
const keyFor = (keyId, privateKey) => keyPairFromPrivateKey("eip191-personal-sign-keccak256", keyId, privateKey);
const signerFor = (privateKey) => ({ signHash: signHashWith(keyFor("k", privateKey)) });
const headOf = (events) => { const r = replay(events); assert.equal(r.status, "ACCEPTED", r.reason); return r.head; };
const unsigned = (event) => { const { administrativeAuthorization, ...data } = event.data; return { id: event.id, type: event.type, timestamp: event.timestamp, data }; };
const producerInput = (events, event, runtimeSessionId, domain) => ({ events, expectedDomain: domain, expectedHistoryHead: headOf(events), transition: unsigned(event), runtimeSessionId });
const failsWith = async (fn, message) => {
  let error;
  try { await fn(); } catch (e) { error = e; }
  assert.ok(error instanceof AdministrativeProducerError, `expected AdministrativeProducerError, got ${error}`);
  assert.equal(error.message, message);
};
const refFailsWith = async (fn, message) => {
  let error;
  try { await fn(); } catch (e) { error = e; }
  assert.ok(error instanceof refAdmin.AdministrativeProducerError); assert.equal(error.message, message);
};
const memoryStore = (initial = []) => {
  let events = Object.freeze([...initial]), locked = false;
  const readAll = () => events;
  const appendAtExpectedHead = (event, expected) => {
    const observed = events.length === 0 ? undefined : headOf(events);
    if (observed === undefined || observed.hash !== expected.hash || observed.position !== expected.position || observed.canonicalTime !== expected.canonicalTime) throw new StoreConflictError(observed);
    const next = replay([...events, event]);
    if (next.status !== "ACCEPTED") throw new Error(`rejected: ${next.code} ${next.reason ?? ""}`);
    events = Object.freeze([...events, event]);
    return next.head;
  };
  const withExclusiveWriter = (cb) => { if (locked) throw new Error("busy"); locked = true; try { return cb({ readAll, appendAtExpectedHead }); } finally { locked = false; } };
  return { readAll, appendAtExpectedHead: (e, h) => withExclusiveWriter((w) => w.appendAtExpectedHead(e, h)), withExclusiveWriter };
};
const simulatedAdapter = () => {
  const results = new Map(), attempts = [], profile = editions.approvedAdapterProfile(editions.SIMULATED_ADAPTER_ID);
  const retained = (identity) => {
    const prior = results.get(identity.idempotencyKey);
    if (prior === undefined) return undefined;
    if (prior.submissionFingerprint !== identity.submissionFingerprint) return { status: "IDEMPOTENCY_FINGERPRINT_CONFLICT", idempotencyKey: identity.idempotencyKey, retainedFingerprint: prior.submissionFingerprint, suppliedFingerprint: identity.submissionFingerprint };
    return { status: "RETRY", idempotencyKey: identity.idempotencyKey, submissionFingerprint: identity.submissionFingerprint, retainedEvidence: prior.evidence, acknowledgment: prior.acknowledgment };
  };
  return {
    adapterProfile: profile, attempts,
    reconcile(input) { const i = deriveAdapterIdentity(input); return retained(i) ?? { status: "OUTCOME_UNKNOWN", idempotencyKey: i.idempotencyKey, submissionFingerprint: i.submissionFingerprint }; },
    async submit(input) {
      const identity = deriveAdapterIdentity(input), prior = retained(identity);
      if (prior !== undefined) return prior;
      const acknowledgment = editions.createAdapterAcknowledgment(identity);
      const result = { status: "SUBMITTED", idempotencyKey: identity.idempotencyKey, submissionFingerprint: identity.submissionFingerprint, evidence: editions.adapterAcknowledgmentEvidence(identity, acknowledgment), acknowledgment };
      results.set(identity.idempotencyKey, result); attempts.push(result);
      return result;
    },
  };
};

// ---------------------------------------------------------------- spec 04 §E.5 vectors
test("administrative production reproduces the spec 04 vectors (effect, proof, challenge, signing hash, signature, event, head)", async () => {
  for (const v of vectors.administrativeAuthorization) {
    const events = handover.slice(0, v.prefixHead.position + 1);
    const input = { events, expectedDomain: handoverCase.domain, expectedHistoryHead: v.prefixHead, transition: v.unsignedTransition, runtimeSessionId: v.runtimeSessionId };
    const prepared = prepareAdministrativeEvent(input);
    assert.equal(canonicalEncode(administrativeTransitionEffect(v.signedEvent)), v.transitionEffectCanonicalText);
    assert.equal(prepared.challenge.transitionEffectHash, v.transitionEffectHash);
    same(prepared.authorityProof, v.authorityProof);
    assert.equal(canonicalEncode(prepared.authorityProof), v.authorityProofCanonicalText);
    assert.equal(prepared.challenge.authorityProofHash, v.authorityProofHash);
    assert.equal(canonicalEncode(prepared.challenge), v.challengeCanonicalText);
    assert.equal(prepared.signingHash, v.signingHash);
    const produced = await produceAdministrativeEvent(input, signerFor(v.signerKey));
    assert.equal(produced.event.data.administrativeAuthorization.runtimeSignature, v.signature, `signature bytes for ${v.label}`);
    same(produced.event, v.signedEvent);
    same(produced.replayHead, v.replayHeadAfter);
    same(prepared, refAdmin.prepareAdministrativeEvent(input));
    same(produced, await refAdmin.produceAdministrativeEvent(input, signerFor(v.signerKey)));
    same(attachAdministrativeSignature(input, v.signature), refAdmin.attachAdministrativeSignature(input, v.signature));
  }
});

test("administrative producer failure phases and codes match the reference", async () => {
  const events = handover.slice(0, 18), obligation = handover[18], input = producerInput(events, obligation, "session:first-look:a", handoverCase.domain);
  const cases = [
    ["HEAD_MISMATCH", { ...input, expectedHistoryHead: headOf(handover.slice(0, 17)) }, "PREPARE:HEAD_MISMATCH"],
    ["DOMAIN_MISMATCH", { ...input, expectedDomain: { ...handoverCase.domain, deploymentId: "other" } }, "PREPARE:DOMAIN_MISMATCH"],
    ["SESSION_INVALID", { ...input, runtimeSessionId: "session:missing" }, "PREPARE:SESSION_INVALID"],
    ["UNSUPPORTED_STATUS", { ...input, transition: { ...input.transition, data: { ...input.transition.data, record: { ...input.transition.data.record, status: "OUTCOME_UNKNOWN" } } } }, "PREPARE:UNSUPPORTED_STATUS"],
    ["UNSUPPORTED_OPERATION", { ...input, transition: { ...input.transition, type: "AGENT_CREATED" } }, "PREPARE:UNSUPPORTED_OPERATION"],
    ["INVALID_TRANSITION (timestamp behind head)", { ...input, transition: { ...input.transition, timestamp: 3 } }, "PREPARE:INVALID_TRANSITION"],
    ["INVALID_TRANSITION (extra data field)", { ...input, transition: { ...input.transition, data: { ...input.transition.data, extra: 1 } } }, "PREPARE:INVALID_TRANSITION"],
    ["PREFIX_REJECTED", { ...input, events: events.slice(1) }, "PREPARE:PREFIX_REJECTED"],
    ["CAPTURE:INVALID_INPUT (extra key)", { ...input, extra: 1 }, "CAPTURE:INVALID_INPUT"],
    ["CAPTURE:INVALID_INPUT (undefined field)", { ...input, transition: { ...input.transition, data: { ...input.transition.data, actorId: undefined } } }, "CAPTURE:INVALID_INPUT"],
    ["POLICY_UNAVAILABLE (attempt duty on E1)", { ...input, transition: { id: "x", type: "ATTEMPT_DUTY_CREATED", timestamp: 18, data: { record: { status: "OPEN", sourceIntentId: "intent:first-look" }, actorId: "a:first-look" } } }, "PREPARE:POLICY_UNAVAILABLE"],
  ];
  for (const [name, bad, message] of cases) {
    await failsWith(() => prepareAdministrativeEvent(bad), message);
    await refFailsWith(() => refAdmin.prepareAdministrativeEvent(bad), message);
    void name;
  }
  await failsWith(() => produceAdministrativeEvent(input, { signHash: () => "0x", extra: 1 }), "SIGN:SIGNER_INVALID");
  await failsWith(() => produceAdministrativeEvent(input, { get signHash() { return () => "0x"; } }), "SIGN:SIGNER_INVALID");
  await failsWith(() => produceAdministrativeEvent(input, { signHash: async () => { throw new Error("hsm down"); } }), "SIGN:SIGNER_FAILED");
  await failsWith(() => produceAdministrativeEvent(input, { signHash: async () => "0xzz" }), "VERIFY:INVALID_SIGNATURE");
  await failsWith(() => produceAdministrativeEvent(input, { signHash: async () => `0x${"1".repeat(128)}1b` }), "VERIFY:SIGNED_EVENT_REJECTED");
  await failsWith(() => produceAdministrativeEvent(input, signerFor(vectors.keys.k1003.privateKey)), "VERIFY:SIGNED_EVENT_REJECTED");
  await refFailsWith(() => refAdmin.produceAdministrativeEvent(input, signerFor(vectors.keys.k1003.privateKey)), "VERIFY:SIGNED_EVENT_REJECTED");
  const requirements = deriveAdministrativeRequirements(replay(events).state, input.transition);
  assert.deepEqual(requirements.request, { actorId: "a:first-look", action: "OBLIGATE", resource: "resource:first-look", claimedAt: 18, termsCommitment: obligation.data.record.termsCommitment });
});

test("no 128-event prefix cap: an obligation over a 200-event legacy history signs, replays here and in the reference engine", async () => {
  // Pad the 18-event prefix with 182 principals so the obligation lands at position 200.
  const filler = Array.from({ length: 182 }, (_, i) => ({ id: `filler:principal:${i}`, type: "PRINCIPAL_CREATED", timestamp: 17, data: { principalId: `principal:filler:${i}` } }));
  const events = [...history.slice(0, 18), ...filler];
  assert.equal(events.length, 200);
  const input = producerInput(events, history[18], "session:core02-simulated-r1:a", config.domain);
  const keyA = signHashWith(keyFor("key:core02-simulated-r1:a", vectors.keys.k1001.privateKey));
  const produced = await produceAdministrativeEvent(input, { signHash: keyA });
  assert.equal(produced.event.data.administrativeAuthorization.challenge.eventHistoryPosition, 199);
  const signed = [...events, produced.event];
  same(produced.replayHead, headOf(signed));
  const theirs = ref.replayPortable({ operationVersion: ref.PORTABLE_REPLAY_VERSION, events: signed });
  assert.equal(theirs.status, "ACCEPTED");
  same(theirs.head, produced.replayHead);
  assert.equal(replay(signed).state.obligations.get("obligation:core02-simulated-r1").creationEventPosition, 200);
  await refFailsWith(() => refAdmin.prepareAdministrativeEvent(input), "CAPTURE:INPUT_LIMIT"); // the reference producer still refuses; its replay accepts
});

// ---------------------------------------------------------------- the whole lifecycle, byte-identical to the exported fixture
test("declare → admit → invoke → consume → receipt → obligate → succession → assign → status reproduces the fixture history byte for byte", async () => {
  const store = memoryStore(history.slice(0, 13));
  let now = 15;
  const clock = () => now;
  const sim = simulatedAdapter();
  const keyA = signHashWith(keyFor("key:core02-simulated-r1:a", vectors.keys.k1001.privateKey));
  const keyB = signHashWith(keyFor("key:core02-simulated-r1:b", vectors.keys.k1003.privateKey));
  // declare (an ordinary control-free event; recorded verbatim)
  store.appendAtExpectedHead(history[13], headOf(store.readAll()));
  // admit: the fixture's signed binding proposes exactly the fixture's admission event
  const sdk = new DurableAdmissionCoordinator(store, sim, { authoritativeNow: clock });
  const admitted = sdk.admit(sdk.prepare({ ...admissionInput, events: store.readAll() }));
  assert.equal(admitted.status, "ADMITTED");
  same(admitted.result.admissionEvent, history[14]);
  // crash after the adapter accepted the submission but before the consumption was recorded
  const submission = { operationVersion: "continuity-adapter-submission/0.2", domain: config.domain, intentId: INTENT, admissionEvent: history[14], admittedHistory: store.readAll() };
  assert.equal((await sim.submit(submission)).status, "SUBMITTED");
  const recovered = new DurableAdmissionCoordinator(store, sim, { authoritativeNow: clock });
  const outcome = await recovered.execute({ ...admissionInput, events: store.readAll() });
  assert.equal(outcome.admission.result.status, "RETRY");
  assert.equal(outcome.invocation.status, "RETRY"); assert.equal(outcome.invocation.recorded, true);
  assert.equal(sim.attempts.length, 1);
  same(store.readAll()[15], history[15]);
  // receipt: create with the session key, then record through the receipt coordinator
  const artifact = await createReceipt({ events: store.readAll(), intentId: INTENT, issuedAt: 16, externalOutcome: "SIMULATED" }, { keyId: "key:core02-simulated-r1:a", signHash: keyA });
  same(artifact, receipt);
  const recorded = new DurableReceiptCoordinator(store).record({ operationVersion: RECEIPT_RECORD_ADMISSION_VERSION, artifact, events: store.readAll(), expectedHistoryHead: headOf(store.readAll()), expectedDomain: config.domain, recordEventId: history[16].id });
  assert.equal(recorded.status, "ADMITTED");
  same(store.readAll()[16], history[16]);
  // an OUTCOME_UNKNOWN attestation by the adapter (recorded verbatim)
  store.appendAtExpectedHead(history[17], headOf(store.readAll()));
  // obligate: session a signs the obligation over the 18-event prefix
  const obligated = await produceAdministrativeEvent(producerInput(store.readAll(), history[18], "session:core02-simulated-r1:a", config.domain), { signHash: keyA });
  same(obligated.event, history[18]);
  store.appendAtExpectedHead(obligated.event, headOf(store.readAll()));
  same(store.readAll()[18], history[18]);
  // succession: epoch advance, termination, role transfer, successor session (control events, recorded verbatim)
  for (const event of history.slice(19, 23)) store.appendAtExpectedHead(event, headOf(store.readAll()));
  // assign: the successor signs the performance assignment with its own key
  const assigned = await produceAdministrativeEvent(producerInput(store.readAll(), history[23], "session:core02-simulated-r1:b", config.domain), { signHash: keyB });
  same(assigned.event, history[23]);
  store.appendAtExpectedHead(assigned.event, headOf(store.readAll()));
  store.appendAtExpectedHead(history[24], headOf(store.readAll()));
  // status: OPEN → OUTCOME_UNKNOWN by the successor
  const status = await produceAdministrativeEvent(producerInput(store.readAll(), history[25], "session:core02-simulated-r1:b", config.domain), { signHash: keyB });
  same(status.event, history[25]);
  store.appendAtExpectedHead(status.event, headOf(store.readAll()));
  same(store.readAll(), history);
  assert.equal(hashCanonical(store.readAll(), "keccak256"), hashCanonical(history, "keccak256"));
  same(headOf(store.readAll()), ref.replayPortable({ operationVersion: ref.PORTABLE_REPLAY_VERSION, events: history }).head);
  // the terminated predecessor can no longer sign, and the successor cannot repeat a resolved transition
  await failsWith(() => produceAdministrativeEvent(producerInput(store.readAll(), { ...history[25], id: "test:again" }, "session:core02-simulated-r1:a", config.domain), { signHash: keyA }), "PREPARE:POLICY_UNAVAILABLE");
  now = 30;
  assert.equal((await recovered.reconcile(INTENT)).status, "RETRY");
  assert.equal(store.readAll().length, 26);
});
