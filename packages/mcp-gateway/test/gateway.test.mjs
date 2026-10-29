import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync, readdirSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { generateKeyPair, signHashWith, openHistoryStore } from "@ramex-labs/irontrellis";
import { setup, HOUR } from "./fixtures.mjs";
import { LOCK_FILE, recoverDeadHost } from "../dist/operations.js";
import { createGateway, operationIdentity } from "../dist/gateway.js";
import { captureUpstream, connectUpstream } from "../dist/upstream.js";
const { FORMAT1_TEST_TOOLING } = await import("@ramex-labs/irontrellis/internal-format1"); // A-185.3 / A-194: older formats are test tooling

const CLI = fileURLToPath(new URL("../dist/cli.js", import.meta.url));
const title = { title: "Investigate incident 42" };
async function fixture(t, options) {
  const root = mkdtempSync(join(tmpdir(), "irontrellis-gateway-test-")), f = await setup(join(root, "case"), options), gateways = [];
  t.after(async () => { for (const g of gateways) await g.close(); rmSync(root, { recursive: true, force: true, maxRetries: 10 }); });
  const dir = join(root, "case");
  return {
    ...f, dir,
    control: (kind, value) => writeFileSync(join(dir, kind + ".control.json"), JSON.stringify(value), { mode: 0o600 }),
    count: (kind) => (existsSync(join(dir, kind + ".calls.jsonl")) ? readFileSync(join(dir, kind + ".calls.jsonl"), "utf8").trim().split("\n").length : 0),
    state: () => openHistoryStore(f.config.historyFile).state(),
    async open(extra = {}) { const g = await createGateway({ ...f.config, local: f.local, ...extra }); gateways.push(g); return g; },
  };
}
async function waitFor(predicate) { for (let i = 0; i < 300; i++) { if (predicate()) return; await new Promise((r) => setTimeout(r, 10)); } throw new Error("Condition deadline"); }
const MODERN = { versionNegotiation: { mode: { pin: "2026-07-28" } } };
async function connectCli(t, configFile, options) {
  const client = new Client({ name: "test-host", version: "1" }, options);
  const transport = new StdioClientTransport({ command: process.execPath, args: [CLI, "--config", configFile], stderr: "pipe" });
  await client.connect(transport);
  t.after(() => client.close().catch(() => {}));
  return { client, transport };
}

test("two upstreams perform ordinary MCP operations; exact repeats and restart never repeat effects", async (t) => {
  const f = await fixture(t), g = await f.open();
  writeFileSync(join(f.dir, "incident.txt"), "Test document bytes.");
  const read = await g.run("read_incident", { document: "incident" });
  assert.equal(read.status, "RESPONSE_RETAINED");
  assert.equal(read.upstreamResult.content[0].text, "Test document bytes.");
  const first = await g.run("create_incident_ticket", title);
  assert.equal(first.status, "RESPONSE_RETAINED");
  assert.equal(first.canonicalDisposition, "SUBMITTED");
  assert.equal((await g.run("create_incident_ticket", title)).status, "RECONCILIATION_ONLY");
  await g.close();
  const again = await f.open();
  assert.equal((await again.run("create_incident_ticket", title)).status, "RECONCILIATION_ONLY");
  assert.equal(again.status("create_incident_ticket").canonicalResponseRecorded, true);
  assert.equal(f.count("documents"), 1);
  assert.equal(f.count("tickets"), 1);
  assert.equal(JSON.parse(readFileSync(join(f.dir, "ticket-1.json"))).title, title.title);
  assert.equal(existsSync(join(f.dir, "ticket-2.json")), false);
});

test("client cannot choose actor, operation identity, paths or an unapproved job", async (t) => {
  const f = await fixture(t), g = await f.open();
  for (const extra of [{ operationId: "fresh" }, { businessKey: "fresh" }, { actor: "operator" }, { session: "other" }, { path: "/etc/passwd" }]) {
    assert.equal((await g.run("create_incident_ticket", { ...title, ...extra })).reason, "INVALID_ARGUMENTS");
  }
  assert.equal((await g.run("unknown", {})).reason, "UNKNOWN_TOOL");
  assert.equal(f.count("tickets"), 0);
  assert.equal(f.state().intentAdmissions.size, 0);
});

test("changed arguments or an alias renamed after restart cannot create a second business operation", async (t) => {
  const f = await fixture(t), g = await f.open();
  await g.run("create_incident_ticket", title);
  assert.equal((await g.run("create_incident_ticket", { title: "Changed work" })).reason, "OPERATION_CONFLICT");
  await g.close();
  const operations = structuredClone(f.config.operations);
  operations[1].name = "renamed_ticket";
  const renamed = await f.open({ operations });
  assert.equal((await renamed.run("renamed_ticket", title)).status, "RECONCILIATION_ONLY");
  assert.equal(f.count("tickets"), 1);
});

test("revocation refuses a new job before spawning the upstream", async (t) => {
  const f = await fixture(t), g = await f.open();
  await f.owner.revoke("write");
  const denied = await g.run("create_incident_ticket", title);
  assert.equal(denied.status, "DENIED");
  assert.equal(denied.why.decision, "DENY");
  const why = g.why("create_incident_ticket");
  assert.equal(why.decision, "DENY");
  assert.equal(why.executionCapability, false);
  assert.equal(f.count("tickets"), 0);
  assert.equal(f.state().intentAdmissions.size, 0);
});

test("revocation during asynchronous signing cannot cross the core admission boundary", async (t) => {
  const f = await fixture(t);
  let first = true;
  const local = { ...f.local, async signHash(hash) { if (first) { first = false; await f.owner.revoke("write"); } return f.local.signHash(hash); } };
  const g = await f.open({ local });
  const r = await g.run("create_incident_ticket", title);
  assert.equal(r.reason, "HISTORY_CONFLICT");
  assert.equal(f.count("tickets"), 0);
  assert.equal(f.state().intentAdmissions.size, 0);
});

test("retired worker stays connected but cannot run or inspect; an authorized replacement only inspects", async (t) => {
  const f = await fixture(t), g = await f.open();
  await g.run("create_incident_ticket", title);
  await f.owner.advanceEpoch({ agent: "worker", from: 1, to: 2 });
  assert.equal((await g.run("read_incident", { document: "incident" })).reason, "RUNTIME_NOT_CURRENT");
  assert.equal(g.status("create_incident_ticket").reason, "RUNTIME_NOT_CURRENT");
  const pair = generateKeyPair("ed25519", "replacement:key");
  await f.owner.createAgent({ id: "replacement" });
  await f.owner.createRole({ id: "reviewer" });
  await f.owner.appoint({ agent: "replacement", role: "reviewer", tenure: "review:1", number: 1 });
  await f.owner.admitRuntime({ agent: "replacement", session: "replacement:1", epoch: 1, key: "replacement:key", credential: pair.credential, expiresAt: Date.now() + HOUR });
  await f.owner.grant({ id: "replacement-inspect", to: "replacement", actions: ["inspect-operation"], resources: ["queue:incident"], expiresAt: Date.now() + HOUR });
  const operations = f.config.operations.map((j) => ({ ...j, role: "reviewer", tenure: "review:1" }));
  const replacement = await f.open({ operations, local: { ...f.local, session: "replacement:1", signHash: signHashWith(pair) } });
  assert.equal(replacement.status("create_incident_ticket").status, "RESPONSE_RETAINED");
  assert.equal(replacement.status("read_incident").reason, "INSPECTION_DENIED");
  assert.equal((await replacement.run("create_incident_ticket", title)).reason, "OPERATION_CONFLICT");
  assert.equal(f.count("tickets"), 1);
});

test("inspection permission is distinct from execution and is checked on repeats", async (t) => {
  const f = await fixture(t), g = await f.open();
  await g.run("create_incident_ticket", title);
  await f.owner.revoke("inspect");
  assert.equal(g.status("create_incident_ticket").reason, "INSPECTION_DENIED");
  assert.equal(g.why("create_incident_ticket").reason, "INSPECTION_DENIED");
  assert.equal((await g.run("create_incident_ticket", title)).reason, "INSPECTION_DENIED");
  assert.equal(f.count("tickets"), 1);
});

test("schema drift refuses before admission; no permission is inferred from discovery", async (t) => {
  const f = await fixture(t);
  f.control("tickets", { changed: true });
  const g = await f.open();
  assert.equal((await g.run("create_incident_ticket", title)).reason, "TOOL_CHANGED");
  assert.equal(f.state().intentAdmissions.size, 0);
  assert.equal(f.count("tickets"), 0);
});

test("lost upstream reply after a durable effect remains UNKNOWN across repeats and restart", async (t) => {
  const f = await fixture(t);
  f.control("tickets", { crash: true });
  const g = await f.open();
  assert.equal((await g.run("create_incident_ticket", title)).status, "OUTCOME_UNKNOWN");
  assert.equal((await g.run("create_incident_ticket", title)).status, "OUTCOME_UNKNOWN");
  await g.close();
  const next = await f.open();
  assert.equal((await next.run("create_incident_ticket", title)).status, "OUTCOME_UNKNOWN");
  assert.equal(next.status("create_incident_ticket").dispatchPerformed, false);
  assert.equal(f.count("tickets"), 1);
});

test("timeout is not cancellation or permission to resend", async (t) => {
  const f = await fixture(t);
  // timeoutMs bounds each upstream step (spawn and initialize, tool listing, the call), so it must leave room for
  // starting the upstream process on a loaded machine; the delay only has to outlast the call's own timeout.
  f.control("tickets", { delay: 6000 });
  const g = await f.open({ timeoutMs: 3000 });
  assert.equal((await g.run("create_incident_ticket", title)).status, "OUTCOME_UNKNOWN");
  assert.equal((await g.run("create_incident_ticket", title)).status, "OUTCOME_UNKNOWN");
  assert.equal(f.count("tickets"), 1);
});

test("late response after retirement is retained separately from canonical consumption", async (t) => {
  const f = await fixture(t);
  f.control("tickets", { delay: 300 });
  const g = await f.open();
  const pending = g.run("create_incident_ticket", title);
  await waitFor(() => f.count("tickets") === 1);
  await f.owner.advanceEpoch({ agent: "worker", from: 1, to: 2 });
  const result = await pending;
  assert.equal(result.status, "RESPONSE_RETAINED");
  assert.equal(result.canonicalDisposition, "OUTCOME_UNKNOWN");
  assert.equal(f.state().intentConsumptions.size, 0);
  assert.equal(f.count("tickets"), 1);
});

test("upstream error is retained as an error report, not business success", async (t) => {
  const f = await fixture(t);
  f.control("tickets", { error: true });
  const g = await f.open();
  const result = await g.run("create_incident_ticket", title);
  assert.equal(result.upstreamResult.isError, true);
  assert.equal(result.externalOutcome, "NOT_PROVEN");
  assert.equal((await g.run("create_incident_ticket", title)).status, "RECONCILIATION_ONLY");
  assert.equal(f.count("tickets"), 1);
});

test("a protocol error reply never triggers redelivery", async (t) => {
  const f = await fixture(t);
  f.control("tickets", { protocolError: true });
  const g = await f.open();
  assert.equal((await g.run("create_incident_ticket", title)).status, "OUTCOME_UNKNOWN");
  assert.equal((await g.run("create_incident_ticket", title)).status, "OUTCOME_UNKNOWN");
  assert.equal(f.count("tickets"), 1);
});

test("unsupported upstream content preserves uncertainty without retransmission", async (t) => {
  const f = await fixture(t);
  f.control("tickets", { invalidOutput: true });
  const g = await f.open();
  assert.equal((await g.run("create_incident_ticket", title)).status, "OUTCOME_UNKNOWN");
  assert.equal((await g.run("create_incident_ticket", title)).status, "OUTCOME_UNKNOWN");
  assert.equal(f.count("tickets"), 1);
});

test("missing attempt storage consumes no downstream effect and cannot be repaired by automatic replay", async (t) => {
  const f = await fixture(t), g = await f.open();
  rmSync(f.config.storage, { recursive: true });
  assert.equal((await g.run("create_incident_ticket", title)).status, "OUTCOME_UNKNOWN");
  mkdirSync(f.config.storage, { mode: 0o700 });
  assert.equal((await g.run("create_incident_ticket", title)).status, "OUTCOME_UNKNOWN");
  assert.equal(f.count("tickets"), 0);
  assert.equal(f.state().intentAdmissions.size, 1);
});

test("corrupt retained bytes are refused despite an existing canonical response digest", async (t) => {
  const f = await fixture(t), g = await f.open();
  await g.run("create_incident_ticket", title);
  const path = join(f.config.storage, readdirSync(f.config.storage).find((x) => x.endsWith(".report.json")));
  const report = JSON.parse(readFileSync(path));
  report.result.content[0].text = "forged";
  writeFileSync(path, JSON.stringify(report));
  assert.equal((await g.run("create_incident_ticket", title)).status, "OUTCOME_UNKNOWN");
  assert.equal(g.status("create_incident_ticket").status, "OUTCOME_UNKNOWN");
  assert.equal(f.count("tickets"), 1);
});

test("overlapping calls are explicitly BUSY; no second effect", async (t) => {
  const f = await fixture(t);
  f.control("tickets", { delay: 300 });
  const g = await f.open();
  const first = g.run("create_incident_ticket", title);
  await waitFor(() => f.count("tickets") === 1);
  assert.equal((await g.run("create_incident_ticket", title)).status, "BUSY");
  await first;
  assert.equal(f.count("tickets"), 1);
});

test("duplicate aliases/business jobs and non-object schemas are not silently accepted", async (t) => {
  const f = await fixture(t);
  await assert.rejects(f.open({ operations: [f.config.operations[0], f.config.operations[0]] }));
  const ops = structuredClone(f.config.operations);
  ops[0].approval.inputSchema = { type: "array" };
  await assert.rejects(f.open({ operations: ops }));
  assert.equal(operationIdentity(f.local.domain, "one"), operationIdentity(f.local.domain, "one"));
  assert.notEqual(operationIdentity(f.local.domain, "one"), operationIdentity(f.local.domain, "two"));
});

test("the packaged CLI serves the SDK client, hides host identities and publishes correct annotations", async (t) => {
  const f = await fixture(t), { client } = await connectCli(t, f.configFile);
  const tools = (await client.listTools()).tools;
  assert.deepEqual(tools.map((x) => x.name), ["read_incident", "create_incident_ticket", "irontrellis_status", "irontrellis_why"]);
  const byName = Object.fromEntries(tools.map((x) => [x.name, x]));
  // A read-only upstream approval publishes a read-only, non-destructive job; a mutating job stays destructive and idempotent.
  assert.deepEqual(byName.read_incident.annotations, { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true });
  assert.deepEqual(byName.create_incident_ticket.annotations, { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true });
  assert.equal(byName.irontrellis_status.annotations.readOnlyHint, true);
  assert.equal(byName.irontrellis_why.annotations.readOnlyHint, true);
  const result = await client.callTool({ name: "read_incident", arguments: { document: "incident" } });
  assert.equal(result.isError, false);
  assert.equal(JSON.stringify(result).includes(f.config.keyFile), false);
  const why = await client.callTool({ name: "irontrellis_why", arguments: { job: "read_incident" } });
  assert.equal(why.structuredContent.executionCapability, false);
  assert.equal(why.structuredContent.decision, "ALLOW");
  const status = await client.callTool({ name: "irontrellis_status", arguments: { job: "read_incident" } });
  assert.equal(status.structuredContent.status, "RESPONSE_RETAINED");
  assert.equal(f.count("documents"), 1);
});

test("a 2026-07-28 client gets the same catalog and structured replies as a 2025-era client", async (t) => {
  const f = await fixture(t), legacy = await connectCli(t, f.configFile);
  const listed = (await legacy.client.listTools()).tools;
  const explain = async (client) => { const { evaluationTime, ...why } = (await client.callTool({ name: "irontrellis_why", arguments: { job: "read_incident" } })).structuredContent; assert.equal(typeof evaluationTime, "number"); return why; };
  const why = await explain(legacy.client);
  await legacy.client.close();
  await waitFor(() => !existsSync(join(f.config.storage, LOCK_FILE)));
  const { client } = await connectCli(t, f.configFile, MODERN);
  const strip = ({ name, description, inputSchema, annotations }) => ({ name, description, inputSchema, annotations });
  assert.deepEqual((await client.listTools()).tools.map(strip), listed.map(strip));
  assert.deepEqual(await explain(client), why);
  const unknown = await client.callTool({ name: "not_a_tool", arguments: {} });
  assert.deepEqual([unknown.isError, unknown.structuredContent], [true, { status: "REFUSED", reason: "UNKNOWN_TOOL" }]);
  const injected = await client.callTool({ name: "create_incident_ticket", arguments: { ...title, actor: "operator" } });
  assert.deepEqual([injected.isError, injected.structuredContent.reason], [true, "INVALID_ARGUMENTS"]);
  const read = await client.callTool({ name: "read_incident", arguments: { document: "incident" } });
  assert.deepEqual([read.isError, read.structuredContent.status], [false, "RESPONSE_RETAINED"]);
  assert.equal(f.count("documents"), 1);
  assert.equal(f.count("tickets"), 0);
});

test("an upstream approved at protocol 2026-07-28 runs jobs exactly once; the era is the operator's, never negotiated", async (t) => {
  const f = await fixture(t), g = await f.open({ upstreams: f.config.upstreams.map((u) => ({ ...u, protocol: "2026-07-28" })) });
  writeFileSync(join(f.dir, "incident.txt"), "Modern bytes.");
  const read = await g.run("read_incident", { document: "incident" });
  assert.equal(read.status, "RESPONSE_RETAINED");
  assert.equal(read.upstreamResult.content[0].text, "Modern bytes.");
  assert.equal((await g.run("create_incident_ticket", title)).status, "RESPONSE_RETAINED");
  assert.equal((await g.run("create_incident_ticket", title)).status, "RECONCILIATION_ONLY");
  assert.equal(f.count("tickets"), 1);
  for (const [protocol, era] of [[undefined, "2025-11-25"], ["legacy", "2025-11-25"], ["2026-07-28", "2026-07-28"]]) {
    const connection = await connectUpstream({ ...f.config.upstreams[0], ...(protocol === undefined ? {} : { protocol }) }, 5000);
    try { assert.equal(connection.client.getNegotiatedProtocolVersion(), era); } finally { await connection.close(); }
  }
  const base = { id: "x", command: process.execPath, args: [] };
  assert.equal(captureUpstream(base).protocol, undefined);
  assert.equal(captureUpstream({ ...base, protocol: "legacy" }).protocol, "legacy");
  for (const protocol of ["auto", "2025-06-18", "2026-07-28 ", 20260728]) assert.throws(() => captureUpstream({ ...base, protocol }), (e) => e.code === "INVALID_INPUT" && /"protocol"/.test(e.detail));
});

test("a protocol error from a 2026-07-28 upstream never triggers redelivery", async (t) => {
  const f = await fixture(t);
  f.control("tickets", { protocolError: true });
  const g = await f.open({ upstreams: f.config.upstreams.map((u) => ({ ...u, protocol: "2026-07-28" })) });
  assert.equal((await g.run("create_incident_ticket", title)).status, "OUTCOME_UNKNOWN");
  assert.equal((await g.run("create_incident_ticket", title)).status, "OUTCOME_UNKNOWN");
  assert.equal(f.count("tickets"), 1);
});

test("duplicate keys and oversized raw upstream frames are rejected before SDK interpretation", async (t) => {
  for (const behavior of [{ duplicate: true }, { oversized: true }]) {
    const f = await fixture(t);
    f.control("tickets", behavior);
    const g = await f.open();
    assert.equal((await g.run("create_incident_ticket", title)).status, "OUTCOME_UNKNOWN");
    assert.equal((await g.run("create_incident_ticket", title)).status, "OUTCOME_UNKNOWN");
    assert.equal(f.count("tickets"), 1);
  }
});

test("killing the gateway after an upstream effect does not cause replay after restart", async (t) => {
  const f = await fixture(t);
  f.control("tickets", { delay: 300 });
  const { client, transport } = await connectCli(t, f.configFile);
  const pending = client.callTool({ name: "create_incident_ticket", arguments: title }).catch(() => null);
  await waitFor(() => f.count("tickets") === 1);
  assert.ok(transport.pid);
  process.kill(transport.pid, "SIGKILL");
  await pending;
  await client.close().catch(() => {});
  recoverDeadHost(f.config.storage);
  const restarted = await f.open();
  assert.equal((await restarted.run("create_incident_ticket", title)).status, "OUTCOME_UNKNOWN");
  assert.equal(f.count("tickets"), 1);
});

test("a wrong signing key cannot impersonate the configured runtime", async (t) => {
  const f = await fixture(t), wrong = generateKeyPair("ed25519", "wrong");
  const g = await f.open({ local: { ...f.local, signHash: signHashWith(wrong) } });
  const r = await g.run("create_incident_ticket", title);
  assert.notEqual(r.status, "RESPONSE_RETAINED");
  assert.equal(f.count("tickets"), 0);
  assert.equal(f.state().intentAdmissions.size, 0);
  // The CLI refuses such a configuration at startup.
  writeFileSync(f.config.keyFile, wrong.privateKey + "\n", { mode: 0o600 });
  const client = new Client({ name: "test-host", version: "1" });
  await assert.rejects(client.connect(new StdioClientTransport({ command: process.execPath, args: [CLI, "--config", f.configFile], stderr: "pipe" })));
});

test("report-write failure never returns an unretained response as durable evidence", async (t) => {
  const f = await fixture(t), g = await f.open();
  const op = operationIdentity(f.local.domain, f.config.operations[1].businessKey);
  writeFileSync(join(f.config.storage, op.slice(4) + ".report.json"), "blocked", { mode: 0o600 });
  const r = await g.run("create_incident_ticket", title);
  assert.equal(r.status, "OUTCOME_UNKNOWN");
  assert.equal(r.upstreamResult, undefined);
  assert.equal((await g.run("create_incident_ticket", title)).status, "OUTCOME_UNKNOWN");
  assert.equal(f.count("tickets"), 1);
});

test("permission checks do not mistake an expired session for current authority", async (t) => {
  const f = await fixture(t), g = await f.open({ local: { ...f.local, now: () => Date.now() + 2 * HOUR } });
  assert.equal((await g.run("create_incident_ticket", title)).reason, "RUNTIME_NOT_CURRENT");
  assert.equal(f.count("tickets"), 0);
});

test("an open upstream schema stays pinned while the gateway exposes and enforces a closed schema", async (t) => {
  const f = await fixture(t);
  f.control("tickets", { openSchema: true });
  const operations = structuredClone(f.config.operations);
  delete operations[1].approval.inputSchema.additionalProperties;
  const g = await f.open({ operations });
  assert.equal(g.tools().find((x) => x.name === "create_incident_ticket").inputSchema.additionalProperties, false);
  assert.equal((await g.run("create_incident_ticket", { ...title, session: "injected" })).reason, "INVALID_ARGUMENTS");
  assert.equal(f.count("tickets"), 0);
  assert.equal((await g.run("create_incident_ticket", title)).status, "RESPONSE_RETAINED");
  assert.equal(f.count("tickets"), 1);
});

test("the CLI's setup command creates a connectable case and --help documents both modes", async (t) => {
  const { spawnSync } = await import("node:child_process");
  const help = spawnSync(process.execPath, [CLI, "--help"], { encoding: "utf8" });
  assert.equal(help.status, 0);
  assert.match(help.stdout, /per-call/);
  const root = mkdtempSync(join(tmpdir(), "irontrellis-gateway-setup-"));
  t.after(() => rmSync(root, { recursive: true, force: true, maxRetries: 10 }));
  const made = spawnSync(process.execPath, [CLI, "setup", join(root, "case"), "--mode", "per-call"], { encoding: "utf8" });
  assert.equal(made.status, 0, made.stderr);
  const configFile = made.stdout.match(/MCP configuration: (.*)$/m)[1];
  assert.equal(spawnSync(process.execPath, [CLI, "setup", join(root, "case")], { encoding: "utf8" }).status, 2);
  const { client } = await connectCli(t, configFile);
  assert.deepEqual((await client.listTools()).tools.map((x) => x.name), ["read_incident", "create_incident_ticket", "irontrellis_why"]);
  assert.equal((await client.callTool({ name: "read_incident", arguments: { document: "incident" } })).structuredContent.status, "FORWARDED");
  const bare = spawnSync(process.execPath, [CLI], { encoding: "utf8" });
  assert.equal(bare.status, 2);
  assert.match(bare.stderr, /GATEWAY_CONFIGURATION_UNAVAILABLE/);
});

test("A-185.6: gateway.json path fields take one path validator, not the 128-character identifier check: setup under a deep folder writes a configuration the loader reads; a control character in a path field is refused by name", async (t) => {
  const { readGatewayConfig } = await import("../dist/config.js");
  const root = mkdtempSync(join(tmpdir(), "irontrellis-gateway-deep-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const parent = join(root, ...Array.from({ length: 6 }, (_, n) => `nested-folder-${n}-${"x".repeat(24)}`));
  mkdirSync(parent, { recursive: true });
  const f = await setup(join(parent, "case"), { mode: "per-call", recordCalls: true });
  assert.ok(f.config.historyFile.length > 128 && f.config.storage.length > 128 && f.connector.session === "gateway", f.config.historyFile);
  const loaded = readGatewayConfig(f.configFile);
  assert.equal(loaded.historyFile, f.config.historyFile);
  assert.equal(loaded.storage, f.config.storage);
  assert.equal(loaded.connector.keyFile, f.config.connector.keyFile);
  const raw = JSON.parse(readFileSync(f.configFile, "utf8"));
  for (const [field, edit] of [["historyFile", (c) => { c.historyFile += "\u0001"; }], ["storage", (c) => { c.storage = ""; }], ["connector.keyFile", (c) => { c.connector.keyFile = "k".repeat(4097); }]]) {
    const bad = structuredClone(raw);
    edit(bad);
    writeFileSync(f.configFile, JSON.stringify(bad), { mode: 0o600 });
    assert.throws(() => readGatewayConfig(f.configFile), (e) => e.code === "INVALID_INPUT" && String(e.detail).startsWith(`field "${field}"`), field);
  }
});

test("A-41 / A-85: the demo case is format 2 and its gateway.json never opts in; a never-migrated format-1 history is refused without enforceFromReadOnlyHistory from the configuration (naming the earlier writer's format is not the opt-in), warned on every open with it, and a fenced history is refused always", async (t) => {
  const { migrateHistory, createLocalAttemptOwner, createLocalDomain, TRELLIS_FORMAT } = await import("@ramex-labs/irontrellis");
  const { readGatewayConfig } = await import("../dist/config.js");
  const f = await fixture(t);
  assert.equal(f.state().format, "irontrellis-event/2");
  assert.equal(readGatewayConfig(f.configFile).enforceFromReadOnlyHistory, undefined, "A-85 (2): the generated default is false");
  // A format-1 copy of the case's profile, written through the core's test-only format-1 writer.
  const historyFile = join(f.dir, "format-1.jsonl"), pair = generateKeyPair("ed25519", "key:worker"), now = Date.now();
  const plain = { historyFile, domain: createLocalDomain({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true }), owner: "operator", controller: "host", session: "worker:1", now: Date.now, signHash: signHashWith(pair) };
  const writer = await createLocalAttemptOwner({ ...plain, format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true });
  await writer.createAgent({ id: "worker" });
  await writer.createRole({ id: "analyst" });
  await writer.appoint({ agent: "worker", role: "analyst", tenure: "shift:1", number: 1 });
  await writer.admitRuntime({ agent: "worker", session: "worker:1", epoch: 1, key: "key:worker", credential: pair.credential, expiresAt: now + HOUR });
  await writer.grant({ id: "write", to: "worker", actions: ["create-ticket", "create_ticket"], resources: ["queue:incident"], expiresAt: now + HOUR });
  writer.close();
  const open = (local) => f.open({ historyFile, domain: plain.domain, local });
  await assert.rejects(open(plain), (e) => e.code === "FORMAT_READ_ONLY" && e.detail.reason === "FORMAT_1");
  await assert.rejects(open({ ...plain, format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true }), (e) => e.code === "FORMAT_READ_ONLY" && e.detail.reason === "FORMAT_1", "A-85 (1): config only");
  const written = [];
  const write = process.stderr.write;
  process.stderr.write = (chunk, ...rest) => { if (/enforcing from the format-1 history/.test(String(chunk))) written.push(String(chunk)); return write.call(process.stderr, chunk, ...rest); };
  try {
    for (let n = 0; n < 2; n += 1) assert.ok(await open({ ...plain, enforceFromReadOnlyHistory: true }));
  } finally { process.stderr.write = write; }
  assert.equal(written.length, 2, "one warning per open");
  // A-185.3 (fail closed): the opt-in is read-only. A call the state allows but that must be recorded (declaration,
  // admission, acknowledgment) is refused before dispatch with an actionable reason; no upstream call, no event.
  const eventsBefore = openHistoryStore(historyFile).state().events.length;
  const g = await open({ ...plain, enforceFromReadOnlyHistory: true });
  const refused = await g.run("create_incident_ticket", title).catch((e) => e);
  assert.deepEqual([refused.status, refused.reason], ["REFUSED", "FORMAT_READ_ONLY"], JSON.stringify(refused));
  assert.match(refused.remedy, /legacy\/format-1 and read-only \(SPEC §16\.1\).*run `irontrellis migrate` to write/);
  assert.equal(f.count("tickets"), 0, "nothing was dispatched");
  assert.equal(openHistoryStore(historyFile).state().events.length, eventsBefore, "nothing was recorded");
  // JOB76-05 / A-206.3: a call the state denies would need a refusal record, which cannot be written either: the same
  // FORMAT_READ_ONLY with the remedy, nothing dispatched, nothing recorded.
  const denied = await g.run("read_incident", { document: "incident" }).catch((e) => e);
  assert.deepEqual([denied.status, denied.reason], ["REFUSED", "FORMAT_READ_ONLY"], JSON.stringify(denied));
  assert.match(denied.remedy, /run `irontrellis migrate` to write/);
  assert.equal(f.count("documents"), 0, "nothing was dispatched");
  assert.equal(openHistoryStore(historyFile).state().events.length, eventsBefore, "nothing was recorded");
  await migrateHistory({ source: historyFile, target: join(f.dir, "history-v2.jsonl"), now: () => Date.now() });
  for (const local of [{ ...plain, enforceFromReadOnlyHistory: true }, plain]) {
    await assert.rejects(open(local), (e) => e.code === "FORMAT_READ_ONLY" && e.detail.reason === "MIGRATED");
  }
});

test("A-22.4: the gateway refuses to decide from a head dated more than 300 s past its clock (CLOCK_AHEAD_OF_READER)", async (t) => {
  const f = await fixture(t), g = await f.open({ local: { ...f.local, now: () => Date.now() - 2 * HOUR } });
  assert.equal((await g.run("create_incident_ticket", title)).reason, "CLOCK_AHEAD_OF_READER");
  assert.equal(f.count("tickets"), 0);
});

test("a refusal by the host's own additional policy is reported as DENIED with reason ADDITIONAL_POLICY, not CORE_POLICY", async (t) => {
  const f = await fixture(t);
  const deny = { identity: "policy:host", evaluate: (request) => ({ identity: "policy:host", requestHash: request.requestHash, decision: "DENY", diagnostics: [] }), record: () => {} };
  const g = await f.open({ local: { ...f.local, additionalPolicy: deny } });
  const denied = await g.run("create_incident_ticket", title);
  assert.equal(denied.status, "DENIED");
  assert.equal(denied.reason, "ADDITIONAL_POLICY");
  assert.equal(f.count("tickets"), 0, "nothing dispatched");
});

test("a configuration whose key file or history lies inside storage is refused at load: snapshots copy storage and say keysIncluded: false", async (t) => {
  const { readGatewayConfig } = await import("../dist/config.js");
  const f = await fixture(t, { mode: "per-call", recordCalls: true });
  assert.ok(readGatewayConfig(f.configFile), "the fixture's own layout loads");
  const original = JSON.parse(readFileSync(f.configFile, "utf8"));
  for (const field of ["keyFile", "historyFile"]) {
    writeFileSync(f.configFile, JSON.stringify({ ...original, [field]: join(original.storage, "inside.json") }), { mode: 0o600 });
    assert.throws(() => readGatewayConfig(f.configFile), (e) => e.code === "INVALID_INPUT" && new RegExp(`"${field}" lies inside "storage"`).test(`${e.message} ${e.detail}`), field);
  }
  writeFileSync(f.configFile, JSON.stringify(original), { mode: 0o600 });
});

test("the storage guard judges physical locations by path components: a '..name' file inside storage and a key reached through a symlinked alias of storage are refused", async (t) => {
  const { readGatewayConfig } = await import("../dist/config.js");
  const { symlinkSync, copyFileSync } = await import("node:fs");
  const f = await fixture(t, { mode: "per-call", recordCalls: true });
  const original = JSON.parse(readFileSync(f.configFile, "utf8")), storage = original.storage;
  const refused = (e) => e.code === "INVALID_INPUT" && /lies inside "storage"/.test(`${e.message} ${e.detail}`);
  for (const field of ["keyFile", "historyFile", "connector.keyFile"]) {
    const set = (p) => field === "connector.keyFile" ? { ...original, connector: { ...original.connector, keyFile: p } } : { ...original, [field]: p };
    writeFileSync(f.configFile, JSON.stringify(set(join(storage, "..ordinary-key.json"))), { mode: 0o600 });
    assert.throws(() => readGatewayConfig(f.configFile), refused, `${field}: a '..'-prefixed name inside storage`);
  }
  const alias = join(f.dir, "storage-alias"), name = "copied-session-key.json";
  copyFileSync(original.keyFile, join(storage, name)); symlinkSync(storage, alias);
  writeFileSync(f.configFile, JSON.stringify({ ...original, keyFile: join(alias, name) }), { mode: 0o600 });
  assert.throws(() => readGatewayConfig(f.configFile), refused, "a key reached through a symlinked alias of storage");
  writeFileSync(f.configFile, JSON.stringify({ ...original, keyFile: join(alias, "not-yet-there.json") }), { mode: 0o600 });
  assert.throws(() => readGatewayConfig(f.configFile), refused, "a file that does not exist yet, placed by its parent");
  writeFileSync(f.configFile, JSON.stringify(original), { mode: 0o600 });
  assert.ok(readGatewayConfig(f.configFile), "the fixture's own layout still loads");
});
