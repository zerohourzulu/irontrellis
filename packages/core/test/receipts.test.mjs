import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { referenceCore as ref, fixturesRoot as FIXTURES, cryptoVectorsPath } from "./reference.mjs";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling
const { createReceipt, createReceiptState, verifyReceipt, verifyReceiptState, proposeReceiptRecord, proposeReceiptRecordState, receiptArtifactCommitment, receiptRecordDataForArtifact, validateReceiptArtifact, RECEIPT_VERIFICATION_VERSION, RECEIPT_RECORD_ADMISSION_VERSION } = await import("../src/receipts.ts");
const { replay } = await import("../src/replay.ts");
const { keyPairFromPrivateKey, signHashWith } = await import("../src/crypto/suites.ts");
const { DurableReceiptCoordinator, StoreConflictError } = await import("../src/coordinators.ts");

// ---------------------------------------------------------------- helpers
const revive = (_k, v) => (v !== null && typeof v === "object" && typeof v["$continuity.bigint"] === "string" ? BigInt(v["$continuity.bigint"]) : v);
const load = (path) => JSON.parse(readFileSync(path, "utf8"), revive);
const norm = (v) => JSON.parse(JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? { $bigint: x.toString() } : x)));
const same = (actual, expected) => assert.deepEqual(norm(actual), norm(expected));
const clone = (v) => structuredClone(v);
const vectors = load(cryptoVectorsPath);
const handover = load(`${FIXTURES}handover-history.json`);
const base = `${FIXTURES}original-core/cases/core02-simulated-r1/`;
const history = load(`${base}export/history.json`), config = load(`${base}case.json`), receipt = load(`${base}export/receipt.json`);
const INTENT = "intent:core02-simulated-r1";
const signer = (keyId, key) => ({ keyId, signHash: signHashWith(keyPairFromPrivateKey("eip191-personal-sign-keccak256", keyId, vectors.keys[key].privateKey)) });
const headOf = (events) => { const r = replay(events); assert.equal(r.status, "ACCEPTED"); return r.head; };
const verifyInput = (artifact, issuanceEvents, observedEvents, verifierTime, expectedDomain = config.domain) =>
  ({ operationVersion: RECEIPT_VERIFICATION_VERSION, artifact, issuanceEvents, observedEvents, expectedDomain, verifierTime });
const rehash = (artifact, mutate) => { const a = clone(artifact); mutate(a.payload); a.contentHash = ref.hashCanonical(a.payload); return a; };
const memoryStore = (initial) => {
  let events = Object.freeze([...initial]);
  return {
    readAll: () => events,
    appendAtExpectedHead(event, expected) {
      const observed = headOf(events);
      if (observed.hash !== expected.hash || observed.position !== expected.position) throw new StoreConflictError(observed);
      const next = replay([...events, event]);
      if (next.status !== "ACCEPTED") throw new Error(next.code);
      events = Object.freeze([...events, event]);
      return next.head;
    },
    withExclusiveWriter(cb) { return cb(this); },
  };
};

// ---------------------------------------------------------------- creation vectors (spec 04 §E.4)
test("createReceipt reproduces the spec 04 receipt vectors byte for byte (payload, contentHash, signature, commitment, record data)", async () => {
  const events = handover.slice(0, 16);
  for (const v of vectors.receipt) {
    const issuedAt = v.payload.issuance.issuedAt;
    const artifact = await createReceipt({ events, intentId: "intent:first-look", issuedAt, externalOutcome: "SIMULATED" }, signer("key:first-look:a", "k1001"));
    same(artifact.payload, v.payload);
    assert.equal(ref.canonicalEncode(artifact.payload), v.payloadCanonicalText);
    assert.equal(artifact.contentHash, v.contentHash);
    assert.equal(artifact.signature, v.signature, `signature bytes for issuedAt ${issuedAt}`);
    assert.equal(receiptArtifactCommitment(artifact), v.receiptArtifactCommitment);
    if (v.recordData !== undefined) same(receiptRecordDataForArtifact(artifact), v.recordData);
    const theirs = await ref.createPortableReceipt({ events, intentId: "intent:first-look", issuedAt, externalOutcome: "SIMULATED" }, signer("key:first-look:a", "k1001"));
    same(artifact, theirs);
  }
});

test("createReceipt over the simulated fixture reproduces the exported receipt and its recorded commitment", async () => {
  const events = history.slice(0, 16);
  const artifact = await createReceipt({ events, intentId: INTENT, issuedAt: 16, externalOutcome: "SIMULATED" }, signer("key:core02-simulated-r1:a", "k1001"));
  same(artifact, receipt);
  assert.equal(receiptArtifactCommitment(artifact), history[16].data.receiptArtifactCommitment);
  assert.equal(receiptArtifactCommitment(artifact), ref.portableReceiptArtifactCommitment(artifact));
  same(receiptRecordDataForArtifact(artifact), history[16].data);
});

test("createReceipt refuses in the reference order: malformed input, prefix, evidence, assurance (before signing), signer key", async () => {
  const events = history.slice(0, 16);
  let signs = 0;
  const counting = { keyId: "key:core02-simulated-r1:a", signHash: async () => { signs++; throw new Error("must not sign"); } };
  await assert.rejects(() => createReceipt({ events, intentId: INTENT, issuedAt: -1, externalOutcome: "SIMULATED" }, counting), /Malformed local receipt creation input/);
  await assert.rejects(() => createReceipt({ events, intentId: INTENT, issuedAt: 10, externalOutcome: "SIMULATED" }, counting), /causally valid accepted prefix/);
  await assert.rejects(() => createReceipt({ events: history.slice(0, 15), intentId: INTENT, issuedAt: 16, externalOutcome: "SIMULATED" }, counting), /exact admitted and consumed intent evidence/);
  await assert.rejects(() => createReceipt({ events, intentId: INTENT, issuedAt: 16, externalOutcome: "NOT_PROVEN" }, counting), /must match the admitted adapter profile/);
  await assert.rejects(() => createReceipt({ events, intentId: INTENT, issuedAt: 16, externalOutcome: "SIMULATED" }, { ...counting, keyId: "key:other" }), /not current/);
  assert.equal(signs, 0);
  await assert.rejects(() => createReceipt({ events, intentId: INTENT, issuedAt: 16, externalOutcome: "SIMULATED" }, signer("key:core02-simulated-r1:a", "k1003")), /Signer did not return a valid/);
  await assert.rejects(() => createReceipt({ events: history.slice(0, 20), intentId: INTENT, issuedAt: 20, externalOutcome: "SIMULATED" }, signer("key:core02-simulated-r1:a", "k1001")), /not current/);
});

// ---------------------------------------------------------------- verification matrix (spec 03 §G.3)
const other16 = { ...history[17], timestamp: 16 };
const matrix = [
  ["issuance=prefix17, observed=full26, time 25", verifyInput(receipt, history.slice(0, 17), history, 25)],
  ["issuance=prefix16, observed=prefix16, time 25", verifyInput(receipt, history.slice(0, 16), history.slice(0, 16), 25)],
  ["issuance=prefix15 (too short)", verifyInput(receipt, history.slice(0, 15), history, 25)],
  ["issuance=prefix18 (too long)", verifyInput(receipt, history.slice(0, 18), history, 25)],
  ["observed=prefix17, time 16 → current", verifyInput(receipt, history.slice(0, 17), history.slice(0, 17), 16)],
  ["time 10 (< observed head)", verifyInput(receipt, history.slice(0, 17), history, 10)],
  ["expectedDomain.deploymentId changed", verifyInput(receipt, history.slice(0, 17), history, 25, { ...config.domain, deploymentId: "other" })],
  ["payload.issuance.issuedAt changed (hash stale)", verifyInput({ ...clone(receipt), payload: { ...clone(receipt.payload), issuance: { ...receipt.payload.issuance, issuedAt: 17 } } }, history.slice(0, 17), history, 25)],
  ["signature garbage", verifyInput({ ...receipt, signature: `0x${"1".repeat(128)}1b` }, history.slice(0, 17), history, 25)],
  ["issuer.keyId changed + rehash", verifyInput(rehash(receipt, (p) => (p.issuer.keyId = "key:other")), history.slice(0, 17), history, 25)],
  ["observed forks at p+1 (other event)", verifyInput(receipt, history.slice(0, 17), [...history.slice(0, 16), other16], 25)],
  ["issuance=prefix16, observed=other event at 16", verifyInput(receipt, history.slice(0, 16), [...history.slice(0, 16), other16], 25)],
  ["observed = 10 events (shorter than prefix)", verifyInput(receipt, history.slice(0, 17), history.slice(0, 10), 25)],
  ["signed by another key", verifyInput({ ...receipt, signature: vectors.eip191[2].signature }, history.slice(0, 17), history, 25)],
  ["verifier domain uppercase contract (case-insensitive)", verifyInput(receipt, history.slice(0, 17), history, 25, { ...config.domain, verifyingContract: config.domain.verifyingContract.toUpperCase().replace("0X", "0x") })],
  ["wrong operationVersion", { ...verifyInput(receipt, history.slice(0, 17), history, 25), operationVersion: "continuity-receipt-verification/0.3" }],
  ["malformed artifact (missing signature)", verifyInput({ payload: receipt.payload, contentHash: receipt.contentHash }, history.slice(0, 17), history, 25)],
  ["unsupported payload schema", verifyInput({ ...receipt, payload: { ...receipt.payload, schemaVersion: "continuity-receipt/0.9" } }, history.slice(0, 17), history, 25)],
  ["empty issuance history", verifyInput(receipt, [], history, 25)],
  ["foreign genesis", verifyInput(receipt, [{ ...history[0], data: { ...history[0].data, versions: { ...history[0].data.versions, eventSchemaVersion: "continuity-event/0.9" } } }], history, 25)],
];
for (const [name, input] of matrix) {
  test(`verifyReceipt differential: ${name}`, () => {
    const mine = verifyReceipt(input), theirs = ref.verifyPortableReceipt(input);
    same(mine, theirs);
  });
}
test("verifyReceipt: the verified matrix outcomes hold (authentic/historical/valid/current)", () => {
  const r1 = verifyReceipt(matrix[0][1]);
  assert.deepEqual([r1.authentic, r1.historical, r1.valid, r1.current], [true, true, true, false]);
  assert.equal(r1.freshness.primaryCode, "STALE"); assert.equal(r1.canonicalInclusion.primaryCode, "RECORDED_HASH_MATCH");
  assert.deepEqual(r1.historicalAuthorization.evidence.map((e) => e.position), [2, 14, 6, 8, 13, 0, 4, 7, 15]);
  const r5 = verifyReceipt(matrix[4][1]);
  assert.deepEqual([r5.authentic, r5.historical, r5.valid, r5.current], [true, true, true, true]);
  assert.deepEqual(r5.limitations, ["NO_PUBLIC_FINALITY_PROOF", "NO_EXTERNAL_OUTCOME_PROOF"]);
  const r6 = verifyReceipt(matrix[5][1]);
  assert.deepEqual(r6.freshness.causes, ["VERIFIER_TIME_BEHIND_OBSERVED_HEAD", "FUTURE_ISSUANCE"]);
  assert.equal(verifyReceipt(matrix[2][1]).issuerAuthentication.primaryCode, "ISSUANCE_HISTORY_UNVERIFIED");
  assert.equal(verifyReceipt(matrix[8][1]).signaturePossession.status, "FAIL");
  assert.equal(validateReceiptArtifact(receipt), "VALID");
});

// ---------------------------------------------------------------- record proposal and coordinator (spec 03 §G.7, §J.5)
const recordInput = (events, extra = {}) => ({ operationVersion: RECEIPT_RECORD_ADMISSION_VERSION, artifact: receipt, events, expectedHistoryHead: headOf(events), expectedDomain: config.domain, recordEventId: history[16].id, ...extra });
const recordCases = [
  ["exact prefix → PROPOSED", recordInput(history.slice(0, 16))],
  ["stale head → CONFLICT", { ...recordInput(history.slice(0, 16)), expectedHistoryHead: headOf(history.slice(0, 15)) }],
  ["receipt already recorded → STATE_NOT_AUTHORITATIVE", recordInput(history.slice(0, 17), { recordEventId: "test:second-record" })],
  ["record id collision → INVALID_INPUT", recordInput(history.slice(0, 16), { recordEventId: history[3].id })],
  ["wrong version → UNSUPPORTED_VERSION", { ...recordInput(history.slice(0, 16)), operationVersion: "continuity-receipt-record-admission/0.9" }],
  ["issuer no longer current → REJECTED", recordInput(history.slice(0, 20), { artifact: rehash(receipt, (p) => { p.issuance = { historyHead: headOf(history.slice(0, 20)), issuedAt: 20 }; }) })],
];
for (const [name, input] of recordCases) test(`proposeReceiptRecord differential: ${name}`, () => same(proposeReceiptRecord(input), ref.proposePortableReceiptRecord(input)));

test("proposeReceiptRecord: PROPOSED reproduces the fixture's RECEIPT_RECORDED event and head", () => {
  const proposal = proposeReceiptRecord(recordInput(history.slice(0, 16)));
  assert.equal(proposal.status, "PROPOSED");
  same(proposal.recordEvent, history[16]);
  same(proposal.newHead, headOf(history.slice(0, 17)));
  assert.equal(proposal.verification.current, true);
});

test("DurableReceiptCoordinator records the proposal, reports CONFLICT with the observed head and UNAVAILABLE on opaque failures", () => {
  const store = memoryStore(history.slice(0, 16));
  const admitted = new DurableReceiptCoordinator(store).record(recordInput(history.slice(0, 16)));
  assert.equal(admitted.status, "ADMITTED");
  same(admitted.recordEvent, history[16]); same(admitted.newHead, headOf(history.slice(0, 17)));
  same(store.readAll(), history.slice(0, 17));
  const conflict = new DurableReceiptCoordinator(store).record(recordInput(history.slice(0, 16)));
  assert.equal(conflict.status, "CONFLICT"); same(conflict.observedHead, headOf(history.slice(0, 17)));
  const broken = { ...memoryStore(history.slice(0, 16)), appendAtExpectedHead() { throw new Error("disk"); } };
  assert.deepEqual(new DurableReceiptCoordinator(broken).record(recordInput(history.slice(0, 16))),
    { status: "UNAVAILABLE", recordMayHavePersisted: true, reason: "Receipt persistence could not be established; inspect the durable history before another attempt." });
  const indeterminate = new DurableReceiptCoordinator(store).record({ nope: true });
  assert.deepEqual(indeterminate, { operationVersion: RECEIPT_RECORD_ADMISSION_VERSION, status: "INDETERMINATE", code: "UNSUPPORTED_VERSION" });
});

// ---------------------------------------------------------------- long histories (the reference's receipt occurrence bound is legacy-only)
const { createLocalDomain, createLocalOwner } = await import("../src/owner.ts");
const { openLocalSimulation, commitTerms } = await import("../src/simulation.ts");
const { openHistoryStore: openHistoryStoreStrict } = await import("../src/store.ts");
// Fixture writes to legacy and format-1 files (SPEC §16.1: those formats open read only by default; format 2 is the wire). These tests cover the earlier store writer, so the fence is off here.
const openHistoryStore = (path, options = {}) => openHistoryStoreStrict(path, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true, ...options });
const { generateKeyPair } = await import("../src/crypto/suites.ts");
const { TRELLIS_FORMAT } = await import("../src/events.ts");
const { approvedAdapterProfile, SIMULATED_ADAPTER_ID } = await import("../src/adapter-editions.ts");
const { compareProtocolStrings } = await import("../src/canonical.ts");
const { mkdtempSync, rmSync } = await import("node:fs");
const withoutEvents = ({ events: _events, ...rest }) => rest;
const { tmpdir } = await import("node:os");
const { join } = await import("node:path");

test("format 1: a receipt over a 3,000-event history is created, verified and recorded at position 3,000 (no history-length bound)", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-long-receipt-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const domain = createLocalDomain({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true });
  const config = { historyFile: join(dir, "history.jsonl"), domain, owner: "operations", controller: "operator", now: () => 100, format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true };
  const owner = await createLocalOwner(config), pair = generateKeyPair("ed25519", "key:bea");
  await owner.createAgent({ id: "bea" });
  await owner.createRole({ id: "reviewer" });
  await owner.appoint({ agent: "bea", role: "reviewer", tenure: "shift:1", number: 1 });
  await owner.admitRuntime({ session: "session:bea", agent: "bea", epoch: 1, key: "key:bea", credential: pair.credential, expiresAt: 10_000 });
  await owner.grant({ id: "collect", to: "bea", actions: ["read"], resources: ["incident:42"], expiresAt: 10_000 });
  // Unrelated declarations by the same actor, before and after the receipt's intent: none of them is receipt evidence.
  const profile = approvedAdapterProfile(SIMULATED_ADAPTER_ID), store = openHistoryStore(config.historyFile, { fsync: false });
  const filler = (from, to) => Array.from({ length: to - from }, (_, k) => ({ id: `filler:${k + from}`, type: "TRANSACTION_INTENT_DECLARED", timestamp: 100, data: {
    intentId: `filler:${k + from}`, nonce: `nonce:${k + from}`, adapterProfile: profile, actorId: "bea", action: "read", resource: "incident:42", roleId: "reviewer", roleTenureId: "shift:1",
    termsCommitment: `0x${(k + from).toString(16).padStart(64, "0")}` } }));
  store.appendAll(filler(0, 2_600 - store.readAll().length));
  const sim = openLocalSimulation({ ...config, session: "session:bea", signHash: signHashWith(pair) });
  const op = { id: "operation:42", action: "read", resource: "incident:42", role: "reviewer", tenure: "shift:1", termsCommitment: commitTerms({ subject: "long history" }) };
  assert.equal((await sim.run(op)).invocation.status, "SUBMITTED");
  store.appendAll(filler(2_600, 2_997));
  const events = store.readAll();
  assert.equal(events.length, 3_000);

  // Creation and verification over the whole history (issuance head 2,999), portable and state forms alike.
  const state = replay(events).state, keySigner = { keyId: "key:bea", signHash: signHashWith(pair) };
  const artifact = await createReceipt({ events, intentId: op.id, issuedAt: 100, externalOutcome: "SIMULATED" }, keySigner);
  same(await createReceiptState(state, { intentId: op.id, issuedAt: 100, externalOutcome: "SIMULATED" }, keySigner), artifact);
  assert.equal(artifact.payload.issuance.historyHead.position, 2_999);
  const verified = verifyReceipt(verifyInput(artifact, events, events, 100, domain));
  assert.deepEqual([verified.status, verified.authentic, verified.historical, verified.canonicalInclusion.primaryCode, verified.freshness.primaryCode],
    ["EVALUATED", true, true, "RECORD_NOT_AVAILABLE", "CURRENT"]);
  same(verifyReceiptState(state, { operationVersion: RECEIPT_VERIFICATION_VERSION, artifact, expectedDomain: domain, verifierTime: 100 }), verified);
  // Evidence cites only what the receipt depends on (genesis, issuer control, the intent's lifecycle, the proof's grant, the head), in evidence order.
  const cited = verified.historicalAuthorization.evidence;
  assert.ok(cited.length < 16 && cited.every((e) => !e.eventId.startsWith("filler:") || e.position === 2_999), JSON.stringify(cited));
  for (const type of ["DEPLOYMENT_INITIALIZED", "AGENT_CREATED", "RUNTIME_SESSION_ADMITTED", "AUTHORITY_GRANTED", "TRANSACTION_INTENT_DECLARED", "TRANSACTION_INTENT_ADMITTED", "TRANSACTION_INTENT_CONSUMED"]) {
    assert.ok(cited.some((e) => e.eventType === type), type);
  }
  const order = (a, b) => compareProtocolStrings(a.eventId, b.eventId) || compareProtocolStrings(a.eventType, b.eventType) || a.position - b.position;
  assert.deepEqual(cited, [...cited].sort(order));

  // Record admission at position 3,000: portable, state form and the durable coordinator agree.
  const input = { operationVersion: RECEIPT_RECORD_ADMISSION_VERSION, artifact, events, expectedHistoryHead: state.head, expectedDomain: domain, recordEventId: "receipt:long" };
  const proposal = proposeReceiptRecord(input);
  assert.equal(proposal.status, "PROPOSED", JSON.stringify(proposal).slice(0, 300));
  assert.equal(proposal.newHead.position, 3_000);
  same(proposeReceiptRecordState(state, withoutEvents(input)), proposal);
  const memory = memoryStore(events), admitted = new DurableReceiptCoordinator(memory).record(input);
  assert.equal(admitted.status, "ADMITTED");
  same(admitted.recordEvent, proposal.recordEvent);
  const recorded = memory.readAll();
  assert.equal(recorded.length, 3_001);

  // Verification with the recorded history: issuance (3,000) + observed (3,001) is past the legacy occurrence bound and still evaluated.
  const current = verifyReceipt(verifyInput(artifact, events, recorded, 100, domain));
  assert.deepEqual([current.current, current.canonicalInclusion.primaryCode, current.canonicalInclusion.evidence.map((e) => e.position)], [true, "RECORDED_HASH_MATCH", [3_000]]);
  same(verifyReceiptState(replay(recorded).state, { operationVersion: RECEIPT_VERIFICATION_VERSION, artifact, expectedDomain: domain, verifierTime: 100 }),
    verifyReceipt(verifyInput(artifact, recorded, recorded, 100, domain)));

  // The local SDK path records at the head of a long history too (it was OUTPUT_LIMIT_EXCEEDED from 2,048 events).
  const fresh = await sim.recordReceipt(op);
  assert.equal(fresh.recording.status, "ADMITTED", JSON.stringify(fresh.recording).slice(0, 300));
  assert.equal(fresh.recording.recordEvent.type, "RECEIPT_RECORDED");
  assert.equal(fresh.recording.newHead.position, 3_000);
});

test("legacy: the reference's receipt occurrence bound is unchanged (record from 2,048 events, creation past 2,048, verification past 4,096 carried events)", async () => {
  const declared = history[13];
  const filler = (n) => ({ ...declared, id: `filler:${n}`, timestamp: 15, data: { ...declared.data, intentId: `intent:filler:${n}`, nonce: `nonce:filler:${n}` } });
  const legacyHistory = (length) => [...history.slice(0, 16), ...Array.from({ length: length - 16 }, (_, n) => filler(n))];
  const keySigner = signer("key:core02-simulated-r1:a", "k1001");
  const outcome = async (f) => { try { return await f(); } catch (error) { return { threw: error.message }; } };
  const record = (events) => ({ operationVersion: RECEIPT_RECORD_ADMISSION_VERSION, artifact, events, expectedHistoryHead: headOf(events), expectedDomain: config.domain, recordEventId: "test:record" });
  const at2047 = legacyHistory(2_047), at2048 = legacyHistory(2_048), at2049 = legacyHistory(2_049);
  // (Creation parity is covered above on short histories; the reference is too slow to repeat it at every size here.)
  const artifact = await createReceipt({ events: at2047, intentId: INTENT, issuedAt: 16, externalOutcome: "SIMULATED" }, keySigner);

  // Record admission: 2,047 events are PROPOSED, 2,048 refused before verification (the prospective history, carried twice, would exceed 4,096).
  // (The reference takes ~15 s to verify the 2,047-event proposal; the refusal side of the boundary is compared below.)
  const proposed = proposeReceiptRecord(record(at2047));
  assert.equal(proposed.status, "PROPOSED");
  assert.equal(proposed.newHead.position, 2_047);
  const refused = proposeReceiptRecord(record(at2048));
  assert.deepEqual(refused, { operationVersion: RECEIPT_RECORD_ADMISSION_VERSION, status: "INDETERMINATE", code: "OUTPUT_LIMIT_EXCEEDED" });
  same(refused, ref.proposePortableReceiptRecord(record(at2048)));
  same(proposeReceiptRecordState(replay(at2048).state, withoutEvents(record(at2048))), refused);

  // Verification carries issuance + observed: 4,096 events are evaluated, 4,097 are refused (INVALID_INPUT) before the artifact is read.
  for (const [issuance, observed, status] of [[at2047, at2049, "EVALUATED"], [at2047, legacyHistory(2_050), "INDETERMINATE"], [at2049, at2049, "INDETERMINATE"]]) {
    const input = verifyInput(artifact, issuance, observed, 16), mine = verifyReceipt(input);
    assert.equal(mine.status, status);
    same(mine, ref.verifyPortableReceipt(input));
  }
  assert.equal(verifyReceipt(verifyInput({ payload: receipt.payload }, at2049, at2049, 16)).code, "INVALID_INPUT");
  const stateInput = { operationVersion: RECEIPT_VERIFICATION_VERSION, artifact, expectedDomain: config.domain, verifierTime: 16 };
  assert.equal(verifyReceiptState(replay(at2048).state, stateInput).status, "EVALUATED");
  same(verifyReceiptState(replay(at2049).state, stateInput), verifyReceipt(verifyInput(artifact, at2049, at2049, 16)));

  // Creation over 2,049 events fails its own verification (after signing), as the reference does.
  const creation = { events: at2049, intentId: INTENT, issuedAt: 16, externalOutcome: "SIMULATED" };
  const mine = await outcome(() => createReceipt(creation, keySigner));
  assert.deepEqual(mine, { threw: "Signer did not return a valid historically authorized receipt artifact." });
  assert.deepEqual(await outcome(() => ref.createPortableReceipt(creation, keySigner)), mine);
  assert.deepEqual(await outcome(() => createReceiptState(replay(at2049).state, { intentId: INTENT, issuedAt: 16, externalOutcome: "SIMULATED" }, keySigner)), mine);
});
