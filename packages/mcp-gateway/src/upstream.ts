/**
 * Upstream MCP servers: configuration capture, the pinned tool approval, and a
 * bounded client (one tool-list page, text/JSON results only, 16 KiB retained).
 * The protocol era is the operator's choice per upstream and is never negotiated:
 * the 2025 `initialize` handshake unless `protocol` is "2026-07-28".
 */
import { isFullyQualifiedPath } from "@ramex-labs/irontrellis/platform";
import { Client } from "@modelcontextprotocol/client";
import { check, data, exact, id, same, type Json } from "./data.ts";
import { ProtectedStdioTransport, type UpstreamFrameRate, type UpstreamConfig, type UpstreamProtocol } from "./stdio.ts";

export type { UpstreamConfig, UpstreamProtocol };
const PROTOCOLS: readonly UpstreamProtocol[] = ["legacy", "2026-07-28"];
/** The operator-approved definition of one upstream tool; discovery must match it exactly before a new admission. */
export type ToolApproval = Readonly<{
  name: string; inputSchema: Json; outputSchema?: Json; annotations?: Json; execution?: Json;
}>;
/** The bounded shape of an upstream reply the gateway retains and forwards. */
export type UpstreamResult = Readonly<{ isError: boolean; content: readonly Readonly<{ type: "text"; text: string }>[]; structuredContent?: unknown }>;
export interface UpstreamConnection {
  readonly client: Client;
  close(): Promise<void>;
  /** Calls `listener` once the connection has closed (at once if it already has): the pool evicts it (GATEWAY-RATE-01). */
  onClose(listener: () => void): void;
  /** Refuse unless the listed tool still matches the approval (TOOL_CHANGED) and the catalog stays bounded. */
  verify(expected: ToolApproval): Promise<void>;
  call(expected: ToolApproval, args: Json): Promise<UpstreamResult>;
}

export function captureUpstream(input: unknown): UpstreamConfig {
  const value = exact(data(input), ["id", "command", "args"], ["cwd", "protocol"]);
  id(value.id);
  check(typeof value.command === "string" && isFullyQualifiedPath(value.command), "INVALID_INPUT", `upstream "${String(value.id)}": "command" must be an absolute path`);
  // Windows runs a .cmd or .bat file only through cmd.exe, and Node refuses to spawn one without a shell (CVE-2024-27980);
  // the gateway never uses a shell (its arguments would be re-parsed). Name the interpreter and pass the script as an argument.
  check(process.platform !== "win32" || !/\.(cmd|bat)$/i.test(value.command as string), "INVALID_INPUT",
    `upstream "${String(value.id)}": "command" is a .cmd or .bat file, which Windows runs only through a shell; name the program itself (e.g. node.exe, with the script in "args")`);
  check(Array.isArray(value.args) && value.args.length <= 32 && value.args.every((a) => typeof a === "string" && a.length <= 2048), "INVALID_INPUT",
    `upstream "${String(value.id)}": "args" must be at most 32 strings of at most 2048 characters`);
  if (value.cwd !== undefined) check(typeof value.cwd === "string" && isFullyQualifiedPath(value.cwd), "INVALID_INPUT", `upstream "${String(value.id)}": "cwd" must be an absolute path`);
  if (value.protocol !== undefined) check(PROTOCOLS.includes(value.protocol as UpstreamProtocol), "INVALID_INPUT", `upstream "${String(value.id)}": "protocol" must be "legacy" or "2026-07-28"`);
  return value as unknown as UpstreamConfig;
}
/** The comparable projection of a tool definition (name, schemas, annotations, execution). */
export function approval(tool: unknown): ToolApproval {
  check(tool !== null && typeof tool === "object");
  const t = tool as Record<string, unknown>;
  return data<ToolApproval>({
    name: id(t.name), inputSchema: t.inputSchema,
    ...(t.outputSchema === undefined ? {} : { outputSchema: t.outputSchema }),
    ...(t.annotations === undefined ? {} : { annotations: t.annotations }),
    ...(t.execution === undefined ? {} : { execution: t.execution }),
  });
}

export async function connectUpstream(config: UpstreamConfig, timeout: number, rate?: UpstreamFrameRate): Promise<UpstreamConnection> {
  const transport = new ProtectedStdioTransport(config, rate);
  // Set before connect: the SDK keeps a transport's own onclose and calls it before its own teardown.
  let closed = false;
  const closeListeners: Array<() => void> = [];
  transport.onclose = () => { closed = true; for (const listener of closeListeners.splice(0)) listener(); };
  // No automatic `input_required` rounds: a fulfilled round re-sends the call, which an exactly-once job must never do.
  const client = new Client({ name: "irontrellis-gateway-upstream", version: "1.0.0" }, {
    capabilities: {}, versionNegotiation: { mode: config.protocol === "2026-07-28" ? { pin: "2026-07-28" } : "legacy" }, inputRequired: { autoFulfill: false },
  });
  // Upstream stderr is never forwarded: a tool may print private payloads or credentials.
  try { await client.connect(transport, { timeout }); } catch (error) { await transport.close(); throw error; }
  return {
    client,
    close: () => client.close(),
    onClose(listener) { if (closed) listener(); else closeListeners.push(listener); },
    async verify(expected) {
      // One bounded page (an explicit cursor): the cursor-less call walks every page, which would allow unbounded discovery.
      const listed = await client.listTools({ cursor: "" }, { timeout, cacheMode: "refresh" });
      check(listed.nextCursor === undefined && listed.tools.length <= 64, "CATALOG_LIMIT");
      const names = new Set<string>();
      for (const t of listed.tools) { check(!names.has(t.name), "CATALOG_CONFLICT"); names.add(t.name); }
      const tool = listed.tools.find((t) => t.name === expected.name);
      check(tool !== undefined && same(approval(tool), expected), "TOOL_CHANGED");
    },
    async call(expected, args) {
      // The approved definition (not a cached listing) drives output validation and disables the SDK's header-mismatch redelivery.
      const raw = await client.callTool({ name: expected.name, arguments: { ...args } }, { timeout, toolDefinition: expected as never }) as Record<string, unknown>;
      check(raw.resultType === undefined || raw.resultType === "complete", "UNSUPPORTED_RESULT");
      check(raw.inputRequests === undefined && raw.task === undefined, "UNSUPPORTED_RESULT");
      check(Array.isArray(raw.content) && raw.content.length <= 16, "UNSUPPORTED_RESULT");
      // Only bounded text/JSON is forwarded. No links, binary content, resources, tasks or input requests.
      const content = (raw.content as unknown[]).map((c) => {
        const item = c as Record<string, unknown>;
        check(item.type === "text" && typeof item.text === "string", "UNSUPPORTED_RESULT");
        return { type: "text" as const, text: item.text };
      });
      const result = data<UpstreamResult>({ isError: raw.isError === true, content, ...(raw.structuredContent === undefined ? {} : { structuredContent: raw.structuredContent }) });
      check(Buffer.byteLength(JSON.stringify(result)) <= 16384, "RESPONSE_LIMIT");
      return result;
    },
  };
}
