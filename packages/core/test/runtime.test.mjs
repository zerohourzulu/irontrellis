import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling

const { createLocalDomain, createLocalOwner, openLocalOwner } = await import("../src/owner.ts");
const { openLocalSimulation, commitTerms } = await import("../src/simulation.ts");
const { generateKeyPair, signHashWith } = await import("../src/crypto/suites.ts");
const { DurableAdmissionCoordinator } = await import("../src/coordinators.ts");
const { LEGACY_FORMAT, TRELLIS_FORMAT } = await import("../src/events.ts");

const code = (value) => (e) => e.code === value;
/** A fresh runtime credential of the scheme the format admits by default (eip191 legacy, ed25519 format 1). */
const credential = (format) => {
  const pair = generateKeyPair(format === LEGACY_FORMAT ? "eip191-personal-sign-keccak256" : "ed25519", "k");
  return { credential: pair.credential, signHash: signHashWith(pair) };
};
async function setup(t, format) {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-runtime-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let tick = 100;
  const config = { historyFile: join(dir, "history.jsonl"), domain: createLocalDomain({ format }), owner: "operations", controller: "operator", now: () => tick, format, [FORMAT1_TEST_TOOLING]: true };
  const owner = await createLocalOwner(config);
  await owner.createAgent({ id: "bea" });
  await owner.createRole({ id: "reviewer" });
  await owner.appoint({ agent: "bea", role: "reviewer", tenure: "shift:1", number: 1 });
  const key = credential(format);
  await owner.admitRuntime({ session: "session:1", agent: "bea", epoch: 1, key: "key:1", credential: key.credential, expiresAt: 200 });
  await owner.grant({ id: "read", to: "bea", actions: ["read"], resources: ["incident:42"], expiresAt: 180 });
  const options = { ...config, session: "session:1", signHash: key.signHash };
  const runtime = openLocalSimulation(options);
  const op = { id: "operation:42", action: "read", resource: "incident:42", role: "reviewer", tenure: "shift:1", termsCommitment: commitTerms({ subject: "Synthetic incident review" }) };
  return { owner, config, key, options, runtime, op, now: (n) => (tick = n) };
}
const count = (owner, type) => owner.exportHistory().filter((e) => e.type === type).length;

for (const format of [LEGACY_FORMAT, TRELLIS_FORMAT]) {
  const label = format === LEGACY_FORMAT ? "legacy" : "format 1";

  test(`${label}: fresh signing, simulation, signed receipt and restarted retry need no fixture keys`, async (t) => {
    const { owner, config, runtime, op, options } = await setup(t, format);
    const first = await runtime.run(op);
    assert.equal(first.status, "SIMULATION_RESULT");
    assert.equal(first.invocation.status, "SUBMITTED");
    assert.equal(first.externalEffect, "NONE_SIMULATED");
    assert.equal(first.admission.status, "ADMITTED");
    assert.equal("capability" in first.admission, false);
    const receipt = await runtime.recordReceipt(op);
    assert.equal(receipt.status, "RECEIPT_RESULT");
    assert.equal(receipt.recording.status, "ADMITTED");
    assert.equal(receipt.artifact.payload.signatureScheme, format === LEGACY_FORMAT ? "eip191-personal-sign-keccak256" : "ed25519");
    const before = readFileSync(config.historyFile);
    const reopened = openLocalSimulation(options);
    assert.equal((await reopened.run(op)).status, "RECONCILIATION_ONLY");
    assert.equal((await reopened.recordReceipt(op)).status, "ALREADY_RECORDED");
    assert.deepEqual(readFileSync(config.historyFile), before);
    assert.equal(openLocalOwner(config).exportHistory().length, owner.exportHistory().length);
    // Lifecycle events are runtime-signed, never owner-signed, in either format.
    assert.equal("controlAuthorization" in owner.exportHistory().find((e) => e.type === "TRANSACTION_INTENT_ADMITTED").data, false);
  });

  test(`${label}: wrong key cannot admit; changing resource or role under an operation ID is refused`, async (t) => {
    const { runtime, options, op, owner } = await setup(t, format);
    const wrong = openLocalSimulation({ ...options, signHash: credential(format).signHash });
    const denied = await wrong.run(op);
    assert.equal(denied.status, "NOT_ADMITTED");
    assert.equal(count(owner, "TRANSACTION_INTENT_ADMITTED"), 0);
    await assert.rejects(runtime.run({ ...op, resource: "incident:43" }), code("OPERATION_CONFLICT"));
    await assert.rejects(runtime.run({ ...op, tenure: "other" }), code("OPERATION_CONFLICT"));
    assert.equal((await runtime.run(op)).invocation.status, "SUBMITTED");
  });

  test(`${label}: role gives no power and denied input creates no declaration`, async (t) => {
    const { runtime, op, owner, config } = await setup(t, format);
    await owner.revoke("read");
    const before = readFileSync(config.historyFile);
    assert.equal((await runtime.run(op)).status, "NOT_AUTHORIZED");
    assert.deepEqual(readFileSync(config.historyFile), before);
  });

  test(`${label}: retiring a live session fences it; fresh session needs a fresh key and operation ID`, async (t) => {
    const { runtime, op, owner, options, config, key } = await setup(t, format);
    await runtime.run(op);
    await owner.advanceEpoch({ agent: "bea", from: 1, to: 2 });
    await assert.rejects(runtime.run({ ...op, id: "second" }), code("RUNTIME_NOT_CURRENT"));
    assert.equal((await runtime.run(op)).status, "RECONCILIATION_ONLY");
    await assert.rejects(owner.admitRuntime({ session: "session:2", agent: "bea", epoch: 2, key: "key:2", credential: key.credential, expiresAt: 200 }), code("TRANSITION_REJECTED"));
    const fresh = credential(format);
    await owner.admitRuntime({ session: "session:2", agent: "bea", epoch: 2, key: "key:2", credential: fresh.credential, expiresAt: 200 });
    const next = openLocalSimulation({ ...options, session: "session:2", signHash: fresh.signHash });
    await assert.rejects(next.run(op), code("OPERATION_CONFLICT"));
    assert.equal((await next.run({ ...op, id: "second" })).invocation.status, "SUBMITTED");
    assert.equal(openLocalOwner(config).exportHistory().filter((e) => e.type === "CONTROL_EPOCH_ADVANCED").length, 1);
  });

  test(`${label}: history change during signing refuses admission; original operation can be inspected and retried`, async (t) => {
    const { options, op, owner, key, runtime } = await setup(t, format);
    let once = true;
    const slow = openLocalSimulation({ ...options, signHash: async (hash) => { if (once) { once = false; await owner.revoke("read"); } return key.signHash(hash); } });
    await assert.rejects(slow.run(op), code("HISTORY_CONFLICT"));
    assert.equal((await runtime.run(op)).status, "NOT_AUTHORIZED");
    assert.equal(count(owner, "TRANSACTION_INTENT_ADMITTED"), 0);
  });

  test(`${label}: expiry during asynchronous signing blocks dispatch`, async (t) => {
    const { options, op, key, now, owner } = await setup(t, format);
    const slow = openLocalSimulation({ ...options, signHash: async (hash) => { now(181); return key.signHash(hash); } });
    assert.equal((await slow.run(op)).status, "NOT_AUTHORIZED");
    assert.equal(count(owner, "TRANSACTION_INTENT_ADMITTED"), 0);
  });

  test(`${label}: retirement during signing is a conflict; expired session cannot issue a new receipt`, async (t) => {
    const { options, op, key, owner, runtime, now } = await setup(t, format);
    const slow = openLocalSimulation({ ...options, signHash: async (hash) => { await owner.advanceEpoch({ agent: "bea", from: 1, to: 2 }); return key.signHash(hash); } });
    await assert.rejects(slow.run(op), code("HISTORY_CONFLICT"));
    await assert.rejects(runtime.recordReceipt(op), code("RECEIPT_UNAVAILABLE"));
    now(201);
    await assert.rejects(runtime.run({ ...op, id: "second" }), code("RUNTIME_NOT_CURRENT"));
  });

  test(`${label}: overlapping same-operation requests produce one admission and one acknowledgment`, async (t) => {
    const { runtime, op, owner } = await setup(t, format);
    const results = await Promise.allSettled([runtime.run(op), runtime.run(op)]);
    assert.equal(results.filter((r) => r.status === "fulfilled" && r.value.status === "SIMULATION_RESULT").length, 1);
    assert.equal(count(owner, "TRANSACTION_INTENT_ADMITTED"), 1);
    assert.equal(count(owner, "TRANSACTION_INTENT_CONSUMED"), 1);
  });

  test(`${label}: mutation while signing cannot replace the captured request`, async (t) => {
    const { options, op, key } = await setup(t, format);
    let saved;
    const selected = { ...op };
    const runtime = openLocalSimulation({ ...options, signHash: async (hash) => { saved = hash; selected.resource = "incident:43"; return key.signHash(hash); } });
    const result = await runtime.run(selected);
    assert.equal(result.invocation.status, "SUBMITTED");
    assert.match(saved, /^0x[0-9a-f]{64}$/);
    assert.equal(result.admission.admissionEvent.data.authorizationProof.request.resource, "incident:42");
  });

  test(`${label}: bad data and signing exceptions do not admit or leak signer errors`, async (t) => {
    const { options, op, owner } = await setup(t, format);
    let gets = 0;
    const malicious = { ...op };
    Object.defineProperty(malicious, "resource", { enumerable: true, get() { gets++; return "incident:42"; } });
    const runtime = openLocalSimulation({ ...options, signHash: async () => { throw Error("private signer detail"); } });
    await assert.rejects(runtime.run(malicious), code("INVALID_INPUT"));
    assert.equal(gets, 0);
    await assert.rejects(runtime.run({ ...op, termsCommitment: undefined }), code("INVALID_INPUT"));
    await assert.rejects(runtime.run(op), (e) => e.code === "SIGNER_FAILED" && !String(e.message).includes("private"));
    assert.equal(count(owner, "TRANSACTION_INTENT_ADMITTED"), 0);
  });

  test(`${label}: receipt signing does not ignore a concurrent history change`, async (t) => {
    const { runtime, options, op, key, owner } = await setup(t, format);
    await runtime.run(op);
    const changed = openLocalSimulation({ ...options, signHash: async (hash) => { await owner.advanceEpoch({ agent: "bea", from: 1, to: 2 }); return key.signHash(hash); } });
    await assert.rejects(changed.recordReceipt(op), code("HISTORY_CONFLICT"));
    assert.equal(count(owner, "RECEIPT_RECORDED"), 0);
  });

  test(`${label}: restart after admission without an acknowledgment preserves UNKNOWN and never resubmits`, async (t) => {
    const { runtime, options, op, owner, config } = await setup(t, format);
    const invoke = DurableAdmissionCoordinator.prototype.invoke;
    DurableAdmissionCoordinator.prototype.invoke = async () => ({ status: "OUTCOME_UNKNOWN", reason: "Injected interruption before invocation" });
    try {
      assert.equal((await runtime.run(op)).invocation.status, "OUTCOME_UNKNOWN");
    } finally {
      DurableAdmissionCoordinator.prototype.invoke = invoke;
    }
    const before = readFileSync(config.historyFile), result = await openLocalSimulation(options).run(op);
    assert.equal(result.status, "RECONCILIATION_ONLY");
    assert.equal(result.result.status, "OUTCOME_UNKNOWN");
    assert.deepEqual(readFileSync(config.historyFile), before);
    assert.equal(count(owner, "TRANSACTION_INTENT_CONSUMED"), 0);
    await assert.rejects(runtime.recordReceipt(op), code("RECEIPT_UNAVAILABLE"));
  });

  test(`${label}: runtime expiration while a receipt signer waits prevents recording`, async (t) => {
    const { runtime, options, op, key, now, owner } = await setup(t, format);
    await runtime.run(op);
    const slow = openLocalSimulation({ ...options, signHash: async (hash) => { now(201); return key.signHash(hash); } });
    await assert.rejects(slow.recordReceipt(op), code("RUNTIME_NOT_CURRENT"));
    assert.equal(count(owner, "RECEIPT_RECORDED"), 0);
  });

  test(`${label}: an additional policy must also allow; its failure or refusal blocks admission`, async (t) => {
    const { options, op, owner } = await setup(t, format);
    const audit = [];
    const policy = (decision) => ({ identity: "policy:test", evaluate: (request) => ({ identity: "policy:test", requestHash: request.requestHash, decision, diagnostics: [] }), record: (evidence) => { audit.push(evidence); } });
    const refused = await openLocalSimulation({ ...options, additionalPolicy: policy("DENY") }).run(op);
    assert.equal(refused.status, "POLICY_REFUSED");
    assert.equal(refused.reason, "DENY");
    assert.equal(audit.length, 1);
    assert.equal(count(owner, "TRANSACTION_INTENT_ADMITTED"), 0);
    const broken = await openLocalSimulation({ ...options, additionalPolicy: { ...policy("ALLOW"), evaluate: () => { throw new Error("secret"); } } }).run(op);
    assert.equal(broken.status, "POLICY_REFUSED");
    assert.equal(broken.reason, "ERROR");
    assert.deepEqual(audit.at(-1).result.diagnostics, ["POLICY_UNAVAILABLE_OR_INVALID"]);
    const allowed = await openLocalSimulation({ ...options, additionalPolicy: policy("ALLOW") }).run(op);
    assert.equal(allowed.status, "SIMULATION_RESULT");
    await assert.rejects(openLocalSimulation({ ...options, additionalPolicy: { ...policy("ALLOW"), record: () => { throw new Error("sink down"); } } }).run({ ...op, id: "other" }), code("POLICY_EVIDENCE_UNAVAILABLE"));
  });
}
