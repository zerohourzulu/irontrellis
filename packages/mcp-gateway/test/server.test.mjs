import { test } from "node:test";
import assert from "node:assert/strict";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { gatewayServer, catalog, reply } from "../dist/server.js";
import { toolAnnotations, whySummary } from "../dist/gateway.js";

const fakeGateway = (mode) => ({
  mode,
  tools: () => [
    { name: "read_incident", description: "read", inputSchema: { type: "object", properties: {}, additionalProperties: false }, annotations: toolAnnotations(undefined, { readOnlyHint: true }, { idempotent: mode === "exactly-once" }) },
    { name: "create_incident_ticket", description: "write", inputSchema: { type: "object", properties: { title: { type: "string" } }, required: ["title"], additionalProperties: false }, annotations: toolAnnotations(undefined, undefined, { idempotent: mode === "exactly-once" }) },
  ],
  run: async (name, args) => (name === "create_incident_ticket" && args.title === "deny" ? { status: "DENIED", reason: "CORE_POLICY", why: { decision: "DENY", code: "NO_AUTHORITY_PATH", failures: [{ code: "AUTHORITY_REVOKED" }] } } : { status: "FORWARDED", name, args }),
  status: (name) => ({ status: "NOT_STARTED", operationId: "mcp:" + name, dispatchPerformed: false }),
  why: (name, args) => ({ status: "EXPLAINED", decision: "ALLOW", name, args }),
  close: async () => {},
});
async function connect(t, gateway) {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const server = gatewayServer(gateway), client = new Client({ name: "in-memory", version: "1" });
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  t.after(async () => { await client.close(); await server.close(); });
  return client;
}

test("annotations: read-only approvals publish read-only tools; jobs are idempotent, per-call tools are not", () => {
  assert.deepEqual(toolAnnotations(undefined, { readOnlyHint: true }, { idempotent: true }), { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true });
  assert.deepEqual(toolAnnotations(undefined, undefined, { idempotent: true }), { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true });
  assert.deepEqual(toolAnnotations(undefined, undefined, { idempotent: false }), { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true });
  assert.deepEqual(toolAnnotations({ title: "Ticket", destructiveHint: false, openWorldHint: false }, { readOnlyHint: true }, { idempotent: false }),
    { title: "Ticket", readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false });
  assert.throws(() => toolAnnotations({ readOnlyHint: "yes" }, undefined, { idempotent: true }));
  assert.throws(() => toolAnnotations({ unknown: true }, undefined, { idempotent: true }));
});

test("the exactly-once catalog carries status and why; the per-call catalog carries why only", async (t) => {
  const once = catalog(fakeGateway("exactly-once")), per = catalog(fakeGateway("per-call"));
  assert.deepEqual(once.map((x) => x.name), ["read_incident", "create_incident_ticket", "irontrellis_status", "irontrellis_why"]);
  assert.deepEqual(per.map((x) => x.name), ["read_incident", "create_incident_ticket", "irontrellis_why"]);
  for (const tool of [...once, ...per]) assert.ok(tool.annotations && typeof tool.annotations.readOnlyHint === "boolean");
  assert.equal(once.find((x) => x.name === "irontrellis_status").annotations.destructiveHint, false);
  const client = await connect(t, fakeGateway("exactly-once"));
  const listed = (await client.listTools()).tools;
  assert.deepEqual(listed.find((x) => x.name === "read_incident").annotations, { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true });
  const status = await client.callTool({ name: "irontrellis_status", arguments: { job: "read_incident" } });
  assert.equal(status.structuredContent.status, "NOT_STARTED");
  const unknown = await client.callTool({ name: "not_a_tool", arguments: {} });
  assert.equal(unknown.isError, true);
  assert.equal(unknown.structuredContent.reason, "UNKNOWN_TOOL");
});

test("a DENY reply is an MCP tool error whose text starts with the WHY summary", async (t) => {
  const client = await connect(t, fakeGateway("per-call"));
  const ok = await client.callTool({ name: "create_incident_ticket", arguments: { title: "fine" } });
  assert.equal(ok.isError, false);
  const denied = await client.callTool({ name: "create_incident_ticket", arguments: { title: "deny" } });
  assert.equal(denied.isError, true);
  assert.match(denied.content[0].text, /^DENY: NO_AUTHORITY_PATH \(AUTHORITY_REVOKED\)\./);
  assert.equal(denied.structuredContent.why.decision, "DENY");
  assert.equal(reply({ status: "OUTCOME_UNKNOWN" }).isError, true);
  assert.equal(reply({ status: "FORWARDED", upstreamResult: { isError: true, content: [] } }).isError, true);
  assert.deepEqual(whySummary({ epistemicStatus: "UNAVAILABLE", code: "EVIDENCE_UNAVAILABLE" }), { decision: "INDETERMINATE", epistemicStatus: "UNAVAILABLE", code: "EVIDENCE_UNAVAILABLE" });
});
