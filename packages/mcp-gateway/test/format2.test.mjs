// Format 2 in the gateway (SPEC §10, §11, §13; docs/API.md §2; A-38, A-42, A-85): the demo case and its connector
// identity, refusals recorded beside DENY decisions (CORE by the worker's session, CONNECTOR by the gateway's own),
// the upstream's reports recorded as CONNECTOR refusals, effects and counterparty receipts, the duty counts of
// inspectCase on the investigation case, and the historyId pin of gateway.json.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { envelopeSigningHash, generateKeyPair, openHistoryStore, signHashWith } from "@ramex-labs/irontrellis";
import { setup } from "./fixtures.mjs";
import { createGateway } from "../dist/gateway.js";
import { createRecorder } from "../dist/records.js";
import { loadGatewayConfig, readGatewayConfig } from "../dist/config.js";
import { inspectCase } from "../dist/operations.js";

async function fixture(t, options) {
  const root = mkdtempSync(join(tmpdir(), "irontrellis-gateway-f2-")), dir = join(root, "case"), f = await setup(dir, options), gateways = [];
  t.after(async () => { for (const g of gateways) await g.close(); rmSync(root, { recursive: true, force: true, maxRetries: 10 }); });
  return {
    ...f, root, dir,
    control: (kind, value) => writeFileSync(join(dir, `${kind}.control.json`), JSON.stringify(value), { mode: 0o600 }),
    state: () => openHistoryStore(f.config.historyFile).state(),
    async open(extra = {}) { const g = await createGateway({ ...f.config, local: f.local, connectorSigner: f.connectorSigner, ...extra }); gateways.push(g); return g; },
  };
}
const last = (state, type) => state.events.filter((e) => e.type === type).at(-1);

test("the demo case is format 2 with the gateway's own connector agent and session; gateway.json names them and the historyId, and never opts into an older format", async (t) => {
  const f = await fixture(t);
  const state = f.state();
  assert.equal(state.format, "irontrellis-event/2");
  assert.equal(state.runtimeSessions.get("gateway").agentId, "gateway");
  const config = readGatewayConfig(f.configFile);
  assert.deepEqual(config.connector, { session: "gateway", keyFile: join(f.directory, "gateway-connector.key") });
  assert.equal(config.historyId, state.eventHistoryHashes[0]);
  assert.equal(config.enforceFromReadOnlyHistory, undefined);
  assert.equal(typeof loadGatewayConfig(f.configFile).options.connectorSigner.signHash, "function");
  // A-19.4: a configuration pinned to another history is refused before anything is decided.
  writeFileSync(f.configFile, JSON.stringify({ ...config, historyId: `0x${"ab".repeat(32)}` }), { mode: 0o600 });
  assert.throws(() => loadGatewayConfig(f.configFile), (e) => e.code === "HISTORY_IDENTITY_MISMATCH");
});

test("per-call DENY: a fixed resource is recorded as a CORE refusal of the worker's session; a template filled from arguments as a CONNECTOR refusal of the gateway's session, by digest only (A-42)", async (t) => {
  const f = await fixture(t, { mode: "per-call" }), g = await f.open();
  await f.owner.revoke("read");
  await f.owner.revoke("write");
  const fixed = await g.run("create_incident_ticket", { title: "denied" });
  assert.equal(fixed.status, "DENIED");
  assert.equal(fixed.refusal.recorded, true);
  const core = last(f.state(), "REQUEST_REFUSED");
  assert.deepEqual([core.data.refusalSource, core.data.request.actorId, core.data.request.resource, core.data.runtimeSessionId], ["CORE", "worker", "queue:incident", "worker:1"]);
  const templated = await g.run("read_incident", { document: "incident" });
  assert.equal(templated.status, "DENIED");
  assert.equal(templated.refusal.recorded, true);
  const connector = last(f.state(), "REQUEST_REFUSED");
  assert.deepEqual([connector.data.refusalSource, connector.data.request.resource, connector.data.connector.connectorId, connector.data.connector.refusalCode, connector.data.runtimeSessionId],
    ["CONNECTOR", "document:{document}", "gateway", "REVOKED", "gateway"]);
  // Without the connector session nothing is recorded for the template (the hook and gateway rule of A-38.4).
  const plain = await f.open({ connectorSigner: undefined });
  const before = f.state().events.length;
  assert.equal((await plain.run("read_incident", { document: "incident" })).refusal, undefined);
  assert.equal(f.state().events.length, before);
});

test("an upstream's reports: a refusal as a CONNECTOR refusal, a measurement on a recorded call as a CONNECTOR effect bound to the call's intent; nothing without records in the configuration", async (t) => {
  const f = await fixture(t, { mode: "per-call", recordCalls: true });
  const tools = f.config.tools.map((tool) => ({ ...tool, records: ["refusal", "effect"] }));
  const g = await f.open({ tools });
  f.control("tickets", { report: { irontrellis: { effect: { metric: "tickets", unit: "ticket", amount: 1 } } } });
  const made = await g.run("create_incident_ticket", { title: "measured" });
  assert.equal(made.status, "FORWARDED");
  assert.equal(made.effect.recorded, true);
  const effect = last(f.state(), "EFFECT_RECORDED");
  assert.deepEqual([effect.data.intentId, effect.data.measurer, effect.data.metric, effect.data.amount, effect.data.runtimeSessionId], [made.operationId, { kind: "CONNECTOR", id: "gateway" }, "tickets", "1", "gateway"]);
  f.control("tickets", { error: true, report: { irontrellis: { refusal: { code: "QUEUE_CLOSED" } } } });
  const refused = await g.run("create_incident_ticket", { title: "refused upstream" });
  assert.equal(refused.upstreamRefusal.recorded, true);
  const refusal = last(f.state(), "REQUEST_REFUSED");
  assert.deepEqual([refusal.data.refusalSource, refusal.data.code, refusal.data.connector.refusalCode, refusal.data.request.actorId], ["CONNECTOR", "CONNECTOR_REFUSED", "QUEUE_CLOSED", "worker"]);
  // The same replies without `records`: nothing beyond the call itself.
  const silent = await f.open();
  const before = f.state().events.filter((e) => e.type === "EFFECT_RECORDED" || e.type === "REQUEST_REFUSED").length;
  f.control("tickets", { report: { irontrellis: { effect: { metric: "tickets", unit: "ticket", amount: 1 } } } });
  assert.equal((await silent.run("create_incident_ticket", { title: "unmeasured" })).effect, undefined);
  assert.equal(f.state().events.filter((e) => e.type === "EFFECT_RECORDED" || e.type === "REQUEST_REFUSED").length, before);
});

test("a counterparty receipt an upstream returns is wrapped by the gateway's session (SPEC §11.2); a bad signature is not recorded and the decision stands", async (t) => {
  const f = await fixture(t, { mode: "per-call", recordCalls: true });
  const g = await f.open();
  const made = await g.run("create_incident_ticket", { title: "delivered" });
  assert.equal(made.status, "FORWARDED");
  const vendor = generateKeyPair("ed25519", "vendor:1");
  await f.owner.registerCounterparty({ counterpartyId: "vendor", keys: [{ keyId: "vendor:1", scheme: "ed25519", credential: vendor.credential }] });
  const state = f.state();
  const body = {
    version: "irontrellis-counterparty-receipt/2", historyId: state.eventHistoryHashes[0], counterpartyId: "vendor", keyId: "vendor:1", logicalId: made.operationId,
    intentDigest: state.intentDeclarations.get(made.operationId).declarationDigest, payloadDigest: `0x${"cd".repeat(32)}`, amount: "1", outcome: "DELIVERED", observedAt: Date.now() - 1000, previousReceiptDigest: null,
  };
  const envelope = { ...body, signature: await signHashWith(vendor)(envelopeSigningHash(body)) };
  const recorder = createRecorder(f.local, f.connectorSigner);
  assert.deepEqual(await recorder.receipt(made.operationId, { ...envelope, amount: "2" }), { recorded: false, reason: "COUNTERPARTY_SIGNATURE_INVALID" });
  const recorded = await recorder.receipt(made.operationId, envelope);
  assert.equal(recorded.recorded, true);
  const wrapper = last(f.state(), "COUNTERPARTY_RECEIPT_RECORDED");
  assert.deepEqual([wrapper.data.intentId, wrapper.data.runtimeSessionId, wrapper.data.envelope.counterpartyId], [made.operationId, "gateway", "vendor"]);
  assert.equal(f.state().counterparties.get("vendor").receiptCount, 1);
});

test("the investigation case: an unknown outcome with its open duty; inspectCase counts the duty by its view, without ids", async (t) => {
  const f = await fixture(t, { investigation: true });
  assert.deepEqual(f.investigation.duty, "duty:incident-42");
  const state = f.state();
  assert.equal(state.attemptDuties.get("duty:incident-42").record.status, "OPEN");
  const diagnostic = inspectCase({ historyFile: f.config.historyFile, storage: f.config.storage });
  assert.deepEqual(diagnostic.duties, { total: 1, withPolicy: 0, outstanding: 1, byView: { NO_POLICY: 1 } });
  assert.ok(!JSON.stringify(diagnostic).includes("incident-42"), "counts only");
});
