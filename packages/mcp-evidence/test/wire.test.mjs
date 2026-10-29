import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawn, spawnSync } from "node:child_process";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { generateKeyPair, openHistoryStore } from "@ramex-labs/irontrellis";
import { createDemo } from "../dist/setup.js";
import { createEvidenceServer, loadEvidenceTool, summary, TOOL_NAME, TOOL_ANNOTATIONS, runDemo } from "../dist/index.js";

const SERVER = fileURLToPath(new URL("../dist/server.js", import.meta.url));
const SETUP = fileURLToPath(new URL("../dist/setup.js", import.meta.url));
const DEMO = fileURLToPath(new URL("../dist/client.js", import.meta.url));
async function setup(t) {
  const root = mkdtempSync(join(tmpdir(), "irontrellis-mcp-wire-"));
  t.after(() => rmSync(root, { recursive: true, force: true, maxRetries: 10 }));
  return { root, ...(await createDemo(join(root, "case"))) };
}
async function connect(t, config, options) {
  const client = new Client({ name: "irontrellis-wire-test", version: "1" }, options);
  const transport = new StdioClientTransport({ command: process.execPath, args: [SERVER, "--config", config], stderr: "pipe" });
  t.after(() => client.close().catch(() => {}));
  await client.connect(transport);
  return client;
}
const call = (client, id = "collection:42", extra = {}) => client.callTool({ name: TOOL_NAME, arguments: { operationId: id, resource: "incident:42", ...extra } });

test("the SDK client collects, retries and fences the still-live old server", async (t) => {
  const { configFile, config, owner } = await setup(t), client = await connect(t, configFile);
  const listing = await client.listTools();
  assert.deepEqual(listing.tools.map((x) => x.name), [TOOL_NAME]);
  assert.deepEqual(listing.tools[0].annotations, { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false });
  assert.deepEqual(listing.tools[0].inputSchema.properties.resource.enum, ["incident:42"]);
  const first = await call(client);
  assert.equal(first.structuredContent.status, "RECORDED");
  assert.equal(first.structuredContent.packetVerified, true);
  assert.equal(first.structuredContent.externalOutcome, "NOT_PROVEN");
  const before = readFileSync(config.historyFile);
  const repeated = await call(client);
  assert.equal(repeated.structuredContent.status, "RECONCILIATION_ONLY");
  assert.deepEqual(readFileSync(config.historyFile), before);
  assert.equal(JSON.stringify(first).includes(config.inputDirectory), false);
  assert.equal(JSON.stringify(first).includes("runtime.key"), false);
  await owner.advanceEpoch({ agent: "bea", from: 1, to: 2 });
  const denied = await call(client, "obsolete:42");
  assert.equal(denied.isError, true);
  assert.equal(denied.structuredContent.reason, "RUNTIME_NOT_CURRENT");
  assert.equal((await client.listTools()).tools.length, 1);
  assert.equal(readdirSync(config.outputDirectory).length, 1);
});

test("a 2026-07-28 client gets the same tool and replies; its operation reconciles for a 2025-era client", async (t) => {
  const { configFile, config } = await setup(t), legacy = await connect(t, configFile);
  const listed = (await legacy.listTools()).tools;
  await legacy.close();
  const modern = await connect(t, configFile, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
  assert.equal(modern.getNegotiatedProtocolVersion(), "2026-07-28");
  const strip = ({ name, title, description, inputSchema, annotations }) => ({ name, title, description, inputSchema, annotations });
  assert.deepEqual((await modern.listTools()).tools.map(strip), listed.map(strip));
  const first = await call(modern);
  assert.deepEqual([first.isError, first.structuredContent.status, first.structuredContent.packetVerified], [false, "RECORDED", true]);
  const injected = await call(modern, "refused", { actor: "operations" });
  assert.deepEqual([injected.isError, injected.structuredContent], [true, { status: "REFUSED", reason: "INVALID_ARGUMENTS" }]);
  const unknown = await modern.callTool({ name: "grant", arguments: {} });
  assert.deepEqual([unknown.isError, unknown.structuredContent], [true, { status: "REFUSED", reason: "UNKNOWN_TOOL" }]);
  await modern.close();
  const again = await connect(t, configFile);
  assert.equal(again.getNegotiatedProtocolVersion(), "2025-11-25");
  assert.equal((await call(again)).structuredContent.status, "RECONCILIATION_ONLY");
  assert.equal(readdirSync(config.outputDirectory).length, 1);
});

test("the MCP caller cannot substitute actor, paths, resource or an arbitrary tool name", async (t) => {
  const { configFile, config } = await setup(t), client = await connect(t, configFile), before = readFileSync(config.historyFile);
  for (const extra of [{ actor: "operations" }, { session: "other" }, { inputDirectory: "/etc" }, { resource: "other" }]) {
    const result = await call(client, "refused", extra);
    assert.equal(result.isError, true);
    assert.equal(result.structuredContent.reason, "INVALID_ARGUMENTS");
  }
  const unknown = await client.callTool({ name: "grant", arguments: { to: "bea" } });
  assert.equal(unknown.isError, true);
  assert.equal(unknown.structuredContent.reason, "UNKNOWN_TOOL");
  assert.deepEqual(readFileSync(config.historyFile), before);
  assert.deepEqual(readdirSync(config.outputDirectory), []);
});

test("revoking the grant denies a new wire call without copying anything", async (t) => {
  const { configFile, config, owner } = await setup(t), client = await connect(t, configFile);
  await owner.revoke("collect");
  const denied = await call(client);
  assert.equal(denied.isError, true);
  assert.equal(denied.structuredContent.status, "DENIED");
  assert.equal(denied.structuredContent.reason, "CORE_POLICY");
  assert.equal(denied.structuredContent.refusal.recorded, true, "the reply says the format-2 denial was recorded");
  assert.match(denied.structuredContent.refusal.eventId, /./);
  assert.deepEqual(readdirSync(config.outputDirectory), []);
  // Format 2 (SPEC §10.1): the denial is recorded as a CORE refusal signed by the agent's own session.
  const state = openHistoryStore(config.historyFile).state();
  assert.equal(state.format, "irontrellis-event/2");
  const refusal = state.events.at(-1);
  assert.equal(refusal.type, "REQUEST_REFUSED");
  assert.deepEqual([refusal.data.refusalSource, refusal.data.request.actorId, refusal.data.code, refusal.data.runtimeSessionId], ["CORE", "bea", "REVOKED", "session:bea"]);
});

test("duplicate keys and overlarge frames terminate before any effect", async (t) => {
  const { configFile, config } = await setup(t);
  for (const input of ['{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/list"}\n', "x".repeat(17000)]) {
    const child = spawn(process.execPath, [SERVER, "--config", configFile], { stdio: ["pipe", "pipe", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (b) => { stderr += b; });
    child.stdin.on("error", () => {});
    const exit = new Promise((accept, reject) => {
      const timer = setTimeout(() => { child.kill(); reject(new Error("wire refusal timeout")); }, 6000);
      child.on("exit", (code) => { clearTimeout(timer); accept(code); });
    });
    child.stdin.end(input);
    assert.equal(await exit, 2);
    assert.match(stderr, /INPUT_REFUSED/);
  }
  assert.deepEqual(readdirSync(config.outputDirectory), []);
});

test("a changed key cannot authenticate as the configured agent", async (t) => {
  const { configFile, config } = await setup(t);
  writeFileSync(config.keyFile, generateKeyPair("ed25519", "other").privateKey + "\n", { mode: 0o600 });
  // The server refuses the configuration at startup: the key is not the admitted session's credential.
  const client = new Client({ name: "irontrellis-wire-test", version: "1" });
  await assert.rejects(client.connect(new StdioClientTransport({ command: process.execPath, args: [SERVER, "--config", configFile], stderr: "pipe" })));
  assert.deepEqual(readdirSync(config.outputDirectory), []);
});

test("an incomplete frame reaches the deadline and leaves no effect", async (t) => {
  const { configFile, config } = await setup(t);
  const child = spawn(process.execPath, [SERVER, "--config", configFile], { stdio: ["pipe", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.on("data", (b) => { stderr += b; });
  child.stdin.on("error", () => {});
  const exit = new Promise((accept, reject) => {
    const timer = setTimeout(() => { child.kill(); reject(new Error("frame deadline did not fire")); }, 8000);
    child.on("exit", (code) => { clearTimeout(timer); accept(code); });
  });
  child.stdin.write("{");
  assert.equal(await exit, 2);
  assert.match(stderr, /FRAME_TIMEOUT/);
  assert.deepEqual(readdirSync(config.outputDirectory), []);
});

test("the in-memory server publishes the annotations and summarizes every core outcome", async (t) => {
  const { configFile } = await setup(t);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const server = createEvidenceServer(loadEvidenceTool(configFile)), client = new Client({ name: "in-memory", version: "1" });
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  t.after(async () => { await client.close(); await server.close(); });
  const tool = (await client.listTools()).tools[0];
  assert.deepEqual(tool.annotations, TOOL_ANNOTATIONS);
  assert.equal(tool.inputSchema.additionalProperties, false);
  assert.equal((await call(client)).structuredContent.status, "RECORDED");
  const packet = { status: "PACKET_VERIFIED", acknowledgment: { kind: "x" } };
  assert.equal(summary({ result: { status: "NOT_AUTHORIZED" }, packet }, "op").reason, "CORE_POLICY");
  assert.equal(summary({ result: { status: "POLICY_REFUSED" }, packet }, "op").reason, "ADDITIONAL_POLICY");
  assert.equal(summary({ result: { status: "NOT_ADMITTED", admission: { status: "STALE" } }, packet }, "op").reason, "STALE");
  assert.equal(summary({ result: { status: "EXECUTION_RESULT", invocation: { status: "OUTCOME_UNKNOWN" } }, packet: { status: "NOT_STARTED" } }, "op").status, "OUTCOME_UNKNOWN");
  assert.deepEqual(summary({ result: { status: "RECONCILIATION_ONLY", result: { status: "RETRY" } }, packet }, "op").acknowledgment, { kind: "x" });
});

test("setup, --help and the demo client run end to end", async (t) => {
  const root = mkdtempSync(join(tmpdir(), "irontrellis-mcp-demo-"));
  t.after(() => rmSync(root, { recursive: true, force: true, maxRetries: 10 }));
  const made = spawnSync(process.execPath, [SETUP, join(root, "case")], { encoding: "utf8" });
  assert.equal(made.status, 0, made.stderr);
  assert.match(made.stdout, /Configuration:/);
  const again = spawnSync(process.execPath, [SETUP, join(root, "case")], { encoding: "utf8" });
  assert.equal(again.status, 2);
  assert.equal(JSON.parse(again.stderr.trim().split("\n").at(-1)).reason, "TARGET_EXISTS");
  // --help prints usage and creates nothing (it used to create a directory named "--help").
  const setupHelp = spawnSync(process.execPath, [SETUP, "--help"], { encoding: "utf8", cwd: root });
  assert.equal(setupHelp.status, 0);
  assert.match(setupHelp.stdout, /Usage: irontrellis-evidence-setup/);
  assert.equal(existsSync(join(root, "--help")), false);
  const noTarget = spawnSync(process.execPath, [SETUP], { encoding: "utf8", cwd: root });
  assert.equal(noTarget.status, 2);
  assert.deepEqual(JSON.parse(noTarget.stderr.trim().split("\n").at(-1)), { status: "REFUSED", reason: "USAGE", detail: "missing the directory to create" });
  const demoHelp = spawnSync(process.execPath, [DEMO, "--help"], { encoding: "utf8" });
  assert.equal(demoHelp.status, 0);
  assert.match(demoHelp.stdout, /Usage: irontrellis-evidence-demo/);
  // A wrong configuration path is a coded refusal with its cause, not a stack trace.
  const badPath = spawnSync(process.execPath, [DEMO, join(root, "absent.json")], { encoding: "utf8" });
  assert.equal(badPath.status, 2);
  assert.doesNotMatch(badPath.stderr, /McpError|\bat /);
  assert.deepEqual(JSON.parse(badPath.stderr.trim()), { status: "REFUSED", reason: "GATEWAY_CONFIGURATION_UNAVAILABLE", detail: "the configuration file does not exist" });
  const help = spawnSync(process.execPath, [SERVER, "--help"], { encoding: "utf8" });
  assert.equal(help.status, 0);
  assert.match(help.stdout, /irontrellis_collect_evidence/);
  const noConfig = spawnSync(process.execPath, [SERVER], { encoding: "utf8" });
  assert.equal(noConfig.status, 2);
  assert.match(noConfig.stderr, /GATEWAY_CONFIGURATION_UNAVAILABLE/);
  const lines = [];
  await runDemo(join(root, "case", "gateway.json"), (line) => lines.push(line));
  assert.equal(lines[0], "Tools: " + TOOL_NAME);
  assert.equal(JSON.parse(lines[1]).status, "RECORDED");
  assert.equal(JSON.parse(lines[2]).status, "RECONCILIATION_ONLY");
});

test("every bin answers --version with the package version, and the package index loads through require()", async () => {
  const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  for (const [file, name] of [[SERVER, "irontrellis-evidence"], [SETUP, "irontrellis-evidence-setup"], [DEMO, "irontrellis-evidence-demo"]]) {
    const r = spawnSync(process.execPath, [file, "--version"], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout, `${name} ${version}\n`);
  }
  // The bin entry points used to await at module level, which made require() of the package throw ERR_REQUIRE_ASYNC_MODULE.
  const index = fileURLToPath(new URL("../dist/index.js", import.meta.url));
  const required = spawnSync(process.execPath, ["-e", `process.stdout.write(typeof require(${JSON.stringify(index)}).createEvidenceServer)`], { encoding: "utf8" });
  assert.equal(required.status, 0, required.stderr);
  assert.equal(required.stdout, "function");
});
