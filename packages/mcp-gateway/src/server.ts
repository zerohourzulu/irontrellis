/**
 * The MCP surface of a gateway: one tool per configured job or per-call tool,
 * plus `irontrellis_status` (exactly-once only) and `irontrellis_why`. Tool
 * results carry the gateway's structured answer; DENY / REFUSED / BUSY /
 * OUTCOME_UNKNOWN and upstream `isError` replies are flagged `isError`.
 *
 * The SDK's low-level `Server` keeps these contracts exact: `McpServer` would
 * answer an unknown tool or invalid arguments with its own error instead of
 * the gateway's structured REFUSED reply. On stdio, `serveStdio` serves both
 * the 2026-07-28 revision and 2025-era (`initialize`) clients.
 */
import { Server, type CallToolResult, type Tool } from "@modelcontextprotocol/server";
import { serveStdio, StdioServerTransport, type StdioServerHandle } from "@modelcontextprotocol/server/stdio";
import type { Readable, Writable } from "node:stream";
import { readFileSync } from "node:fs";
import { guardedInput, type GuardOptions } from "./guard.ts";
import type { Gateway, GatewayResult, ToolAnnotations } from "./gateway.ts";

const packageVersion = (): string => {
  try { return (JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string }).version; } catch { return "0.0.0"; }
};
export const SERVER_INFO = Object.freeze({ name: "irontrellis-mcp-gateway", version: packageVersion() });
const ERROR_STATUSES: ReadonlySet<string> = new Set(["DENIED", "REFUSED", "BUSY", "OUTCOME_UNKNOWN"]);
/** A DENY answer is an MCP tool error whose text opens with the decision and the WHY summary. */
export function reply(value: GatewayResult): CallToolResult {
  const isError = ERROR_STATUSES.has(value.status) || value.upstreamResult?.isError === true;
  const why = value.why as Readonly<{ decision?: string; code?: string; failures?: readonly Readonly<{ code: string }>[] }> | undefined;
  const headline = value.status === "DENIED" && why !== undefined
    ? `DENY: ${why.code ?? "NOT_AUTHORIZED"}${why.failures?.length ? ` (${why.failures.map((f) => f.code).join(", ")})` : ""}. This decision reads the recorded history; it grants nothing.\n`
    : "";
  return { isError, content: [{ type: "text", text: headline + JSON.stringify(value) }], structuredContent: value as Record<string, unknown> };
}
const SELECTION = (names: readonly string[]) => ({ type: "object", properties: { job: { type: "string", enum: [...names] } }, required: ["job"], additionalProperties: false }) as Tool["inputSchema"];
const WHY_SCHEMA = (names: readonly string[]) => ({
  type: "object", properties: { job: { type: "string", enum: [...names] }, arguments: { type: "object", description: "The call arguments that select the resource (per-call tools only)." } },
  required: ["job"], additionalProperties: false,
}) as Tool["inputSchema"];
const READ_ONLY: ToolAnnotations = Object.freeze({ readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false });

/** The full tool catalog as the MCP client sees it, with annotations. */
export function catalog(gateway: Gateway): Tool[] {
  const listed = gateway.tools(), names = listed.map((t) => t.name);
  const tools: Tool[] = listed.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema as Tool["inputSchema"], annotations: t.annotations }));
  if (gateway.mode === "exactly-once") {
    tools.push({ name: "irontrellis_status", description: "Inspect the original approved job without sending it again. Requires current inspection permission.", inputSchema: SELECTION(names), annotations: READ_ONLY });
  }
  tools.push({
    name: "irontrellis_why", inputSchema: WHY_SCHEMA(names), annotations: READ_ONLY,
    description: gateway.mode === "exactly-once"
      ? "Explain the agent's current permission for a job. This explanation is not permission to execute."
      : "Explain the agent's current permission for a tool call with the given arguments. This explanation is not permission to execute.",
  });
  return tools;
}

export function gatewayServer(gateway: Gateway): Server {
  const server = new Server(SERVER_INFO, { capabilities: { tools: {} } });
  const names = new Set(gateway.tools().map((t) => t.name));
  server.setRequestHandler("tools/list", () => ({ tools: catalog(gateway) }));
  const answer = async (name: string, args: Record<string, unknown>): Promise<CallToolResult> => {
    if (name === "irontrellis_status" && gateway.mode === "exactly-once") return reply(gateway.status(String(args.job)));
    if (name === "irontrellis_why") return reply(gateway.why(String(args.job), args.arguments));
    if (!names.has(name)) return reply({ status: "REFUSED", reason: "UNKNOWN_TOOL" });
    return reply(await gateway.run(name, args));
  };
  // The era codec projection is the identity for these object-shaped results; it is applied as the SDK requires of low-level handlers.
  server.setRequestHandler("tools/call", async ({ params }) => server.projectCallToolResult(await answer(params.name, params.arguments ?? {}), undefined));
  return server;
}

export type ServeOptions = Readonly<{ input?: Readable; output?: Writable; guard?: GuardOptions }>;
/**
 * Serve a gateway on stdio behind the strict-JSON input guard, for 2026-07-28 and 2025-era clients alike
 * (no subscriptions). The transport buffer is bounded to one guarded frame. Resolves once serving has started.
 */
export async function serveGateway(gateway: Gateway, options: ServeOptions = {}): Promise<StdioServerHandle> {
  const transport = new StdioServerTransport(guardedInput(options.input ?? process.stdin, options.guard), options.output ?? process.stdout,
    { maxBufferSize: (options.guard?.maxFrameBytes ?? 16384) + 1 });
  return serveStdio(() => gatewayServer(gateway), { legacy: "serve", maxSubscriptions: 0, transport, onerror: () => process.stderr.write("GATEWAY_TRANSPORT_ERROR\n") });
}
