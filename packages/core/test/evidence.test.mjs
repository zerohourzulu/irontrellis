import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling

const { createLocalDomain, createLocalOwner } = await import("../src/owner.ts");
const { openLocalEvidenceTool, selectEvidence } = await import("../src/evidence.ts");
const { openLocalExecution, commitTerms } = await import("../src/execution.ts");
const { createPacketExecutor } = await import("../src/adapters/packet-executor.ts");
const { generateKeyPair, signHashWith } = await import("../src/crypto/suites.ts");
const { LEGACY_FORMAT, TRELLIS_FORMAT, TRELLIS2_FORMAT } = await import("../src/events.ts");

const code = (value) => (e) => e.code === value;
async function setup(t, format) {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "irontrellis-evidence-")));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const inputDirectory = join(dir, "source"), outputDirectory = join(dir, "packets");
  mkdirSync(inputDirectory, { mode: 0o700 });
  mkdirSync(outputDirectory, { mode: 0o700 });
  writeFileSync(join(inputDirectory, "incident.txt"), "Synthetic event: review this.\n", { mode: 0o600 });
  const pair = generateKeyPair(format === LEGACY_FORMAT ? "eip191-personal-sign-keccak256" : "ed25519", "key");
  const config = { historyFile: join(dir, "history.jsonl"), domain: createLocalDomain({ format }), owner: "operations", controller: "operator", now: () => 100, format, [FORMAT1_TEST_TOOLING]: true };
  const owner = await createLocalOwner(config);
  await owner.createAgent({ id: "bea" });
  await owner.createRole({ id: "reviewer" });
  await owner.appoint({ agent: "bea", role: "reviewer", tenure: "shift", number: 1 });
  await owner.admitRuntime({ session: "session", agent: "bea", epoch: 1, key: "key", credential: pair.credential, expiresAt: 200 });
  await owner.grant({ id: "collect", to: "bea", actions: ["collect-evidence-packet"], resources: ["incident:42"], expiresAt: 200 });
  const options = { ...config, session: "session", signHash: signHashWith(pair), inputDirectory, outputDirectory, selection: selectEvidence(inputDirectory), resource: "incident:42", role: "reviewer", tenure: "shift" };
  const tool = openLocalEvidenceTool(options), request = { operationId: "collect:42", resource: "incident:42" };
  return { tool, owner, options, request, config };
}

for (const format of [LEGACY_FORMAT, TRELLIS_FORMAT, TRELLIS2_FORMAT]) {
  const label = format === LEGACY_FORMAT ? "legacy" : format === TRELLIS_FORMAT ? "format 1" : "format 2";

  test(`${label}: protected file collection has durable typed acknowledgment and restart reconciliation`, async (t) => {
    const { tool, request, options, config } = await setup(t, format);
    const answer = await tool.collect(request);
    assert.equal(answer.result.status, "EXECUTION_RESULT");
    assert.equal(answer.result.invocation.status, "SUBMITTED");
    assert.equal(answer.packet.status, "PACKET_VERIFIED");
    const folder = join(options.outputDirectory, createHash("sha256").update(request.operationId).digest("hex"));
    assert.deepEqual(readFileSync(join(folder, "packet/files/incident.txt")), readFileSync(join(options.inputDirectory, "incident.txt")));
    const before = readFileSync(config.historyFile), again = await openLocalEvidenceTool(options).collect(request);
    assert.equal(again.result.status, "RECONCILIATION_ONLY");
    assert.equal(again.packet.status, "PACKET_VERIFIED");
    assert.deepEqual(readFileSync(config.historyFile), before);
    assert.equal((await tool.recordReceipt(request)).recording.status, "ADMITTED");
    assert.equal(tool.inspect(request).status, "PACKET_VERIFIED");
    assert.equal(tool.inspect({ ...request, operationId: "never" }).status, "NOT_STARTED");
  });

  test(`${label}: denial, caller paths and resource substitution cannot copy or create attempt directories`, async (t) => {
    const { tool, owner, request, options } = await setup(t, format);
    await owner.revoke("collect");
    assert.equal((await tool.collect(request)).result.status, "NOT_AUTHORIZED");
    await assert.rejects(tool.collect({ ...request, resource: "incident:other" }), code("INVALID_INPUT"));
    await assert.rejects(tool.collect({ ...request, inputDirectory: "/etc" }), code("INVALID_INPUT"));
    assert.deepEqual(readdirSync(options.outputDirectory), []);
  });

  test(`${label}: old still-live tool is fenced and input changes do not silently change the selected work`, async (t) => {
    const { tool, owner, request, options } = await setup(t, format);
    writeFileSync(join(options.inputDirectory, "incident.txt"), "Changed");
    const changed = await tool.collect(request);
    assert.equal(changed.result.invocation.status, "OUTCOME_UNKNOWN");
    assert.notEqual(changed.packet.status, "PACKET_VERIFIED");
    await owner.advanceEpoch({ agent: "bea", from: 1, to: 2 });
    await assert.rejects(tool.collect({ ...request, operationId: "next" }), code("RUNTIME_NOT_CURRENT"));
    assert.equal((await tool.collect(request)).result.status, "RECONCILIATION_ONLY");
  });

  test(`${label}: retirement cannot interleave the synchronous protected effect; a late original ack remains recoverable`, async (t) => {
    const { options, owner } = await setup(t, format), operationId = "late:42", out = join(options.outputDirectory, "late");
    mkdirSync(out, { mode: 0o700 });
    const termsCommitment = commitTerms({ work: "late acknowledgement test" });
    const packet = createPacketExecutor({ ...options, outputDirectory: out, termsCommitment, intentId: operationId });
    let retirementDuringEffect = false, lateRetirement;
    const adapter = {
      adapterProfile: packet.adapterProfile,
      submit(submission) {
        // The owner's write is synchronous up to the store lock (local key material signs synchronously), so it collides with the held writer lock.
        const attempt = owner.advanceEpoch({ agent: "bea", from: 1, to: 2 }).then(() => assert.fail("must not append during the protected effect"), (error) => {
          assert.equal(error.code, "HISTORY_CONFLICT");
          retirementDuringEffect = true;
        });
        return packet.submit(submission).then(async (result) => { await attempt; lateRetirement = owner.advanceEpoch({ agent: "bea", from: 1, to: 2 }); await lateRetirement; return result; });
      },
      reconcile: (submission) => packet.reconcile(submission),
    };
    const runtime = openLocalExecution(options, adapter, "LOCAL_PACKET");
    const operation = { id: operationId, intentId: operationId, action: "collect-evidence-packet", resource: options.resource, role: options.role, tenure: options.tenure, termsCommitment };
    const result = await runtime.run(operation);
    assert.equal(retirementDuringEffect, true);
    assert.equal(result.invocation.status, "OUTCOME_UNKNOWN");
    assert.equal(packet.inspect().status, "PACKET_VERIFIED");
    const ack = readFileSync(join(out, "ack.json"));
    assert.equal((await runtime.run(operation)).status, "RECONCILIATION_ONLY");
    assert.deepEqual(readFileSync(join(out, "ack.json")), ack);
    assert.equal(owner.exportHistory().filter((e) => e.type === "TRANSACTION_INTENT_CONSUMED").length, 0);
    assert.equal(owner.exportHistory().filter((e) => e.type === "CONTROL_EPOCH_ADVANCED").length, 1);
  });
}
