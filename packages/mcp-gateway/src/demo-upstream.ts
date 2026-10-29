#!/usr/bin/env node
/**
 * A synthetic upstream MCP server for the demo case (no IronTrellis imports,
 * no special protocol): `documents` reads incident.txt, `tickets` records a
 * local ticket file. Fault injection for the tests is driven by
 * `<directory>/<kind>.control.json`; without that file it behaves normally.
 */
import { Server, type Tool } from "@modelcontextprotocol/server";
import { serveStdio, StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { Transform } from "node:stream";
import { readFileSync, writeFileSync, existsSync, openSync, fsyncSync, closeSync } from "node:fs";
import { join } from "node:path";

type Control = Readonly<Record<string, unknown>>;
const [directory = ".", kind = "documents"] = process.argv.slice(2);
const control = (): Control => { try { return JSON.parse(readFileSync(join(directory, kind + ".control.json"), "utf8")) as Control; } catch { return {}; } };
const schema: Record<string, unknown> = kind === "documents"
  ? { type: "object", properties: { document: { type: "string", enum: ["incident"] } }, required: ["document"], additionalProperties: false }
  : { type: "object", properties: { title: { type: "string", minLength: 1, maxLength: 120 } }, required: ["title"], additionalProperties: false };
if (control().openSchema) delete schema.additionalProperties;
if (control().changed) (schema.properties as Record<string, unknown>).extra = { type: "string" };
const tool: Tool = kind === "documents"
  ? { name: "read_document", inputSchema: schema as Tool["inputSchema"], annotations: { readOnlyHint: true } }
  : { name: "create_ticket", inputSchema: schema as Tool["inputSchema"] };

function upstreamServer(): Server {
  const server = new Server({ name: "local-" + kind, version: "1" }, { capabilities: { tools: {} } });
  server.setRequestHandler("tools/list", () => ({ tools: [tool] }));
  server.setRequestHandler("tools/call", async ({ params }) => {
    const behavior = control(), args = (params.arguments ?? {}) as Record<string, unknown>;
    let text: string;
    if (kind === "documents") text = readFileSync(join(directory, "incident.txt"), "utf8");
    else {
      const log = join(directory, kind + ".calls.jsonl");
      const number = existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").length + 1 : 1;
      const ticket = openSync(join(directory, "ticket-" + number + ".json"), "wx", 0o600);
      try { writeFileSync(ticket, JSON.stringify({ number, title: args.title }) + "\n"); fsyncSync(ticket); } finally { closeSync(ticket); }
      text = "Created local ticket " + number + ": " + String(args.title);
    }
    const fd = openSync(join(directory, kind + ".calls.jsonl"), "a", 0o600);
    try { writeFileSync(fd, JSON.stringify({ kind, arguments: args }) + "\n"); fsyncSync(fd); } finally { closeSync(fd); }
    if (behavior.crash) process.exit(7);
    if (typeof behavior.delay === "number") await new Promise((r) => setTimeout(r, behavior.delay as number));
    if (behavior.protocolError || behavior.duplicate || behavior.oversized) return { content: [{ type: "text", text: "WIRE_FAULT" }] };
    if (behavior.invalidOutput) return { content: [{ type: "image", mimeType: "image/png", data: "AA==" }] };
    // `report`: the reply's structuredContent (a gateway configured with `records` reads its `irontrellis` block).
    const structured = behavior.report === undefined ? {} : { structuredContent: behavior.report as Record<string, unknown> };
    if (behavior.error) return { isError: true, content: [{ type: "text", text: "The service refused this request." }], ...structured };
    return { content: [{ type: "text", text }], ...structured };
  });
  return server;
}
// Fault injection stays in this fixture: rewrite a marked result into actual wire-level failures.
const output = new Transform({
  transform(chunk: Buffer, _encoding, callback) {
    try {
      const response = JSON.parse(chunk.toString()) as { id?: unknown; result?: { content?: { text?: string }[] } };
      if (response.result?.content?.[0]?.text === "WIRE_FAULT") {
        const b = control();
        if (b.protocolError) return callback(null, JSON.stringify({ jsonrpc: "2.0", id: response.id, error: { code: -32020, message: "Header mismatch" } }) + "\n");
        if (b.duplicate) return callback(null, '{"jsonrpc":"2.0","id":' + JSON.stringify(response.id) + ',"result":{},"result":{"content":[]}}\n');
        if (b.oversized) return callback(null, JSON.stringify({ jsonrpc: "2.0", id: response.id, result: { content: [{ type: "text", text: "x".repeat(70000) }] } }) + "\n");
      }
    } catch { /* pass through */ }
    callback(null, chunk);
  },
});
output.pipe(process.stdout);
// Both protocol eras: a 2025 `initialize` opening and a 2026-07-28 `server/discover` opening.
serveStdio(upstreamServer, { transport: new StdioServerTransport(process.stdin, output) });
