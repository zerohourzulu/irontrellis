import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, existsSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { openHistoryStore } from "@ramex-labs/irontrellis";
import { setup, HOUR } from "./fixtures.mjs";
import { createGateway, resolveResource } from "../dist/gateway.js";

const CLI = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
async function fixture(t, options = {}) {
  const root = mkdtempSync(join(tmpdir(), "irontrellis-percall-test-")), f = await setup(join(root, "case"), { mode: "per-call", ...options }), gateways = [];
  t.after(async () => { for (const g of gateways) await g.close(); rmSync(root, { recursive: true, force: true, maxRetries: 10 }); });
  const dir = join(root, "case");
  return {
    ...f, dir,
    count: (kind) => (existsSync(join(dir, kind + ".calls.jsonl")) ? readFileSync(join(dir, kind + ".calls.jsonl"), "utf8").trim().split("\n").length : 0),
    events: () => openHistoryStore(f.config.historyFile).state().events.length,
    async open(extra = {}) { const g = await createGateway({ ...f.config, local: f.local, ...extra }); gateways.push(g); return g; },
  };
}

test("per-call: an allowed tool is forwarded on every call and nothing is written to the history", async (t) => {
  const f = await fixture(t), g = await f.open(), before = f.events();
  assert.equal(g.mode, "per-call");
  for (let i = 1; i <= 3; i++) {
    const r = await g.run("create_incident_ticket", { title: "Ticket " + i });
    assert.equal(r.status, "FORWARDED");
    assert.equal(r.decision, "ALLOW");
    assert.equal(r.recorded, false);
    assert.equal(r.action, "create_ticket");
    assert.equal(r.resource, "queue:incident");
    assert.equal(r.upstreamResult.content[0].text, "Created local ticket " + i + ": Ticket " + i);
    assert.equal(r.upstreamContentTrust, "UNTRUSTED_DATA");
  }
  assert.equal(f.count("tickets"), 3);
  assert.equal(f.events(), before);
  assert.deepEqual(readFileSync(f.config.historyFile), readFileSync(f.config.historyFile));
});

test("per-call: the resource template is filled from the arguments and checked per call", async (t) => {
  const f = await fixture(t), g = await f.open();
  const allowed = await g.run("read_incident", { document: "incident" });
  assert.equal(allowed.status, "FORWARDED");
  assert.equal(allowed.resource, "document:incident");
  assert.equal(resolveResource("document:{document}", { document: "other" }), "document:other");
  assert.throws(() => resolveResource("document:{missing}", {}), /INVALID_ARGUMENTS/);
  assert.equal(g.why("read_incident", { document: "incident" }).decision, "ALLOW");
  assert.equal(g.status("read_incident").reason, "NOT_A_JOB");
});

test("per-call: DENY answers with the WHY summary and never launches the upstream", async (t) => {
  const f = await fixture(t), g = await f.open();
  await f.owner.revoke("write");
  const denied = await g.run("create_incident_ticket", { title: "Blocked" });
  assert.equal(denied.status, "DENIED");
  assert.equal(denied.reason, "CORE_POLICY");
  assert.equal(denied.decision, "DENY");
  assert.equal(denied.why.decision, "DENY");
  assert.ok(typeof denied.why.code === "string");
  assert.ok(Array.isArray(denied.why.failures));
  assert.equal(denied.executionCapability, false);
  assert.equal(f.count("tickets"), 0);
  // A revocation between two calls takes effect on the next call: the read still works, the write does not.
  assert.equal((await g.run("read_incident", { document: "incident" })).status, "FORWARDED");
  assert.equal(g.why("create_incident_ticket").decision, "DENY");
});

test("per-call: retirement, expiry, unknown tools and injected arguments are refused", async (t) => {
  const f = await fixture(t), g = await f.open();
  assert.equal((await g.run("create_incident_ticket", { title: "x", actor: "operator" })).reason, "INVALID_ARGUMENTS");
  assert.equal((await g.run("grant", { to: "worker" })).reason, "UNKNOWN_TOOL");
  const expired = await f.open({ local: { ...f.local, now: () => Date.now() + 2 * HOUR } });
  assert.equal((await expired.run("create_incident_ticket", { title: "late" })).reason, "RUNTIME_NOT_CURRENT");
  await f.owner.advanceEpoch({ agent: "worker", from: 1, to: 2 });
  assert.equal((await g.run("create_incident_ticket", { title: "retired" })).reason, "RUNTIME_NOT_CURRENT");
  assert.equal(f.count("tickets"), 0);
});

test("per-call with recordCalls: every call is declared, admitted and consumed as its own intent", async (t) => {
  const f = await fixture(t, { recordCalls: true }), g = await f.open(), before = f.events();
  const first = await g.run("create_incident_ticket", { title: "Recorded 1" });
  assert.equal(first.status, "FORWARDED");
  assert.equal(first.recorded, true);
  assert.equal(first.canonicalDisposition, "SUBMITTED");
  assert.ok(first.operationId.startsWith("mcp-call:"));
  const second = await g.run("create_incident_ticket", { title: "Recorded 1" });
  assert.equal(second.status, "FORWARDED");
  assert.notEqual(second.operationId, first.operationId);
  assert.equal(f.count("tickets"), 2);
  assert.equal(f.events(), before + 6);
  const state = openHistoryStore(f.config.historyFile).state();
  assert.equal(state.intentConsumptions.size, 2);
  await f.owner.revoke("write");
  const denied = await g.run("create_incident_ticket", { title: "Recorded 2" });
  assert.equal(denied.status, "DENIED");
  assert.equal(denied.refusal.recorded, true, "the DENY is recorded as a refusal (format 2)");
  assert.equal(f.count("tickets"), 2);
  assert.equal(f.events(), before + 8);
});

test("per-call: the CLI publishes the tools with their annotations and answers DENY as a tool error", async (t) => {
  const f = await fixture(t);
  const client = new Client({ name: "test-host", version: "1" });
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [CLI, "--config", f.configFile], stderr: "pipe" }));
  t.after(() => client.close().catch(() => {}));
  const tools = (await client.listTools()).tools;
  assert.deepEqual(tools.map((x) => x.name), ["read_incident", "create_incident_ticket", "irontrellis_why"]);
  const byName = Object.fromEntries(tools.map((x) => [x.name, x]));
  assert.deepEqual(byName.read_incident.annotations, { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true });
  assert.deepEqual(byName.create_incident_ticket.annotations, { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true });
  const ok = await client.callTool({ name: "create_incident_ticket", arguments: { title: "From the client" } });
  assert.equal(ok.isError, false);
  assert.equal(ok.structuredContent.status, "FORWARDED");
  await f.owner.revoke("write");
  const denied = await client.callTool({ name: "create_incident_ticket", arguments: { title: "Blocked" } });
  assert.equal(denied.isError, true);
  assert.match(denied.content[0].text, /^DENY: /);
  assert.equal(denied.structuredContent.why.decision, "DENY");
  const why = await client.callTool({ name: "irontrellis_why", arguments: { job: "read_incident", arguments: { document: "incident" } } });
  assert.equal(why.structuredContent.decision, "ALLOW");
  assert.equal(f.count("tickets"), 1);
});

test("per-call: recordCalls needs storage, role and tenure; malformed configurations are refused", async (t) => {
  const f = await fixture(t);
  await assert.rejects(f.open({ recordCalls: true }));
  await assert.rejects(f.open({ tools: [{ ...f.config.tools[0], name: "irontrellis_why" }] }));
  await assert.rejects(f.open({ tools: [{ ...f.config.tools[0], resource: "" }] }));
  writeFileSync(f.configFile, JSON.stringify({ ...f.config, recordCalls: true }), { mode: 0o600 });
  const client = new Client({ name: "test-host", version: "1" });
  await assert.rejects(client.connect(new StdioClientTransport({ command: process.execPath, args: [CLI, "--config", f.configFile], stderr: "pipe" })));
});
