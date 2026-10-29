#!/usr/bin/env node
/**
 * `irontrellis-evidence --config /absolute/private/gateway.json` (also
 * installed as `irontrellis-mcp`): a stdio MCP server with one tool,
 * `irontrellis_collect_evidence`, that copies the operator-selected files
 * into a protected packet when the configured agent still holds the
 * authority. One operation id is one operation: a repeat reconciles the
 * original attempt and never copies again.
 *
 * Built on the SDK's low-level `Server` so an unknown tool or invalid
 * arguments keep their structured REFUSED replies; `serveStdio` serves both
 * 2026-07-28 and 2025-era (`initialize`) clients.
 */
import { readFileSync } from "node:fs";
import type { Readable, Writable } from "node:stream";
import { Server, type CallToolResult, type Tool } from "@modelcontextprotocol/server";
import { serveStdio, StdioServerTransport, type StdioServerHandle } from "@modelcontextprotocol/server/stdio";
import { Ajv, AjvJsonSchemaValidator, addFormats } from "@modelcontextprotocol/server/validators/ajv";
import type { LocalEvidenceTool } from "@ramex-labs/irontrellis";
import { ConfigError, describeConfigError, loadEvidenceTool } from "./config.ts";
import { guardedInput, type GuardOptions } from "./guard.ts";
import { isEntryPoint } from "./entry.ts";

const packageVersion = (): string => {
  try { return (JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string }).version; } catch { return "0.0.0"; }
};
export const SERVER_INFO = Object.freeze({ name: "irontrellis-evidence", version: packageVersion() });
export const TOOL_NAME = "irontrellis_collect_evidence";
/** Copies selected files into a new packet directory: not read-only, never destructive, idempotent per operation id, no open-world interaction. */
export const TOOL_ANNOTATIONS = Object.freeze({ readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false });
const SAFE_CODES: ReadonlySet<string> = new Set([
  "INVALID_INPUT", "OPERATION_CONFLICT", "RUNTIME_NOT_CURRENT", "HISTORY_CONFLICT", "HISTORY_LIMIT", "HISTORY_FILE_LIMIT", "CAPACITY_CONTROL_ONLY", "CAPACITY_EVENT_LIMIT",
  "SIGNER_FAILED", "WRITE_UNCONFIRMED", "POLICY_EVIDENCE_UNAVAILABLE", "ROLLBACK_DETECTED", "READ_UNAVAILABLE", "PROFILE_MISMATCH", "CLOCK_INVALID",
]);
/** Whether a core-policy denial left a REQUEST_REFUSED in the history (the gateway's shape): coalesced, rate-limited or failed ones say why not. */
export type RefusalRecord = Readonly<{ recorded: true; eventId?: string } | { recorded: false; reason?: string }>;
export type EvidenceSummary = Readonly<{ operationId: string; status: string; reason?: string; refusal?: RefusalRecord; disposition?: string; packetVerified: boolean; acknowledgment?: unknown; externalOutcome?: "NOT_PROVEN" }>;

/** The agent-facing summary of a collection result: status, disposition and whether the packet verified. */
export function summary(output: Awaited<ReturnType<LocalEvidenceTool["collect"]>>, operationId: string): EvidenceSummary {
  const result = output.result as Readonly<{ status: string; admission?: Readonly<{ status: string }>; invocation?: Readonly<{ status: string }>; result?: Readonly<{ status: string }>;
    refusalRecorded?: boolean; refusal?: Readonly<{ eventId: string }>; refusalNotRecorded?: Readonly<{ reason: string }> }>;
  const packetVerified = output.packet.status === "PACKET_VERIFIED";
  if (result.status === "POLICY_REFUSED") return { operationId, status: "DENIED", reason: "ADDITIONAL_POLICY", packetVerified };
  if (result.status === "NOT_AUTHORIZED") {
    const refusal: RefusalRecord | undefined = result.refusalRecorded === true ? { recorded: true, ...(result.refusal?.eventId === undefined ? {} : { eventId: result.refusal.eventId }) }
      : result.refusalRecorded === false ? { recorded: false, ...(result.refusalNotRecorded?.reason === undefined ? {} : { reason: result.refusalNotRecorded.reason }) } : undefined;
    return { operationId, status: "DENIED", reason: "CORE_POLICY", ...(refusal === undefined ? {} : { refusal }), packetVerified };
  }
  if (result.status === "NOT_ADMITTED") return { operationId, status: "REFUSED", reason: result.admission?.status ?? "NOT_ADMITTED", packetVerified };
  const disposition = result.invocation ?? result.result;
  return {
    operationId,
    status: result.status === "RECONCILIATION_ONLY" ? "RECONCILIATION_ONLY" : disposition?.status === "SUBMITTED" ? "RECORDED" : "OUTCOME_UNKNOWN",
    disposition: disposition?.status ?? "OUTCOME_UNKNOWN", packetVerified,
    ...(packetVerified ? { acknowledgment: (output.packet as Readonly<{ acknowledgment?: unknown }>).acknowledgment } : {}),
    externalOutcome: "NOT_PROVEN",
  };
}
const reply = (value: unknown, isError = false): CallToolResult => ({ isError, content: [{ type: "text", text: JSON.stringify(value) }], structuredContent: value as Record<string, unknown> });

/** The tool definition as published (schema pinned to the configured resource). */
export function toolDefinition(resource: string): Tool {
  return {
    name: TOOL_NAME,
    title: "Collect the selected evidence packet",
    description: "Copy the operator-selected files into a protected evidence packet if the launch-bound runtime still has permission. Keep one operationId for retries; uncertain results are reconciled, never resubmitted. This does not prove the contents true.",
    inputSchema: {
      type: "object",
      properties: {
        operationId: { type: "string", minLength: 1, maxLength: 128, pattern: "^[^\\u0000-\\u001f\\u007f]+$", description: "Stable application-owned id; repeating it reconciles the original attempt." },
        resource: { type: "string", enum: [resource] },
      },
      required: ["operationId", "resource"], additionalProperties: false,
    },
    annotations: { ...TOOL_ANNOTATIONS },
  };
}

export function createEvidenceServer(tool: LocalEvidenceTool): Server {
  const server = new Server(SERVER_INFO, { capabilities: { tools: {} } });
  const definition = toolDefinition(tool.resource);
  // The SDK 1.x engine (draft-07 Ajv with formats), as before; 2.x would default to 2020-12.
  const ajv = new Ajv({ strict: false, validateFormats: true, validateSchema: false, allErrors: true });
  addFormats(ajv);
  const validate = new AjvJsonSchemaValidator(ajv).getValidator<Readonly<{ operationId: string; resource: string }>>(definition.inputSchema as never);
  let busy = false;
  server.setRequestHandler("tools/list", () => ({ tools: [definition] }));
  const answer = async (name: string, raw: Record<string, unknown>): Promise<CallToolResult> => {
    if (name !== TOOL_NAME) return reply({ status: "REFUSED", reason: "UNKNOWN_TOOL" }, true);
    const checked = validate(raw);
    if (!checked.valid) return reply({ status: "REFUSED", reason: "INVALID_ARGUMENTS" }, true);
    const args = checked.data;
    if (busy) return reply({ status: "BUSY", retry: "Repeat the same operationId and arguments." }, true);
    busy = true;
    try {
      const value = summary(await tool.collect(args), args.operationId);
      return reply(value, ["DENIED", "REFUSED", "OUTCOME_UNKNOWN"].includes(value.status));
    } catch (error) {
      const code = (error as { code?: unknown }).code;
      return reply({
        operationId: args.operationId, status: "REFUSED", reason: typeof code === "string" && SAFE_CODES.has(code) ? code : "GATEWAY_UNAVAILABLE",
        mayHaveCommitted: (error as { mayHaveCommitted?: unknown }).mayHaveCommitted === true,
      }, true);
    } finally {
      busy = false;
    }
  };
  // The era codec projection is the identity for these object-shaped results; it is applied as the SDK requires of low-level handlers.
  server.setRequestHandler("tools/call", async (request) => server.projectCallToolResult(await answer(request.params.name, request.params.arguments ?? {}), undefined));
  return server;
}

export type ServeOptions = Readonly<{ input?: Readable; output?: Writable; guard?: GuardOptions }>;
/** Serve the tool on stdio behind the strict-JSON input guard, for 2026-07-28 and 2025-era clients alike (no subscriptions). */
export async function serveEvidence(tool: LocalEvidenceTool, options: ServeOptions = {}): Promise<StdioServerHandle> {
  const transport = new StdioServerTransport(guardedInput(options.input ?? process.stdin, options.guard), options.output ?? process.stdout,
    { maxBufferSize: (options.guard?.maxFrameBytes ?? 16384) + 1 });
  return serveStdio(() => createEvidenceServer(tool), { legacy: "serve", maxSubscriptions: 0, transport, onerror: () => process.stderr.write("MCP_TRANSPORT_ERROR\n") });
}

const USAGE = `◆ IronTrellis evidence MCP server

Usage: irontrellis-evidence --config /absolute/private/gateway.json
       irontrellis-evidence --version

Serves one tool, ${TOOL_NAME}, on stdio. Create a configuration with
irontrellis-evidence-setup <new-directory> and try it with irontrellis-evidence-demo <config>.
`;
/** The `irontrellis-evidence` command line. Called without `await` below, so this module (and the package index) has no top-level await and `require()` of the package works. */
async function cli(args: readonly string[]): Promise<void> {
  if (args.length === 1 && (args[0] === "--help" || args[0] === "-h" || args[0] === "help")) {
    process.stdout.write(USAGE);
    process.exit(0);
  }
  if (args.length === 1 && args[0] === "--version") {
    process.stdout.write(`${SERVER_INFO.name} ${SERVER_INFO.version}\n`);
    return;
  }
  try {
    if (args.length !== 2 || args[0] !== "--config") throw new ConfigError("USAGE", args.length === 0 ? "missing --config <gateway.json>" : "expected exactly --config <gateway.json>");
    await serveEvidence(loadEvidenceTool(args[1]!));
  } catch (error) {
    const code = error instanceof ConfigError ? error.code : typeof (error as { code?: unknown })?.code === "string" ? (error as { code: string }).code : undefined;
    if (code === "USAGE") process.stderr.write(USAGE);
    // One JSON line: a stable code and a detail naming the file, field or limit at fault (never configuration values or keys).
    process.stderr.write(JSON.stringify({
      status: "REFUSED", reason: "GATEWAY_CONFIGURATION_UNAVAILABLE", ...(code !== undefined && /^[A-Z_]{3,60}$/.test(code) ? { code } : {}), detail: describeConfigError(error),
    }) + "\n");
    process.exitCode = 2;
  }
}
if (isEntryPoint(import.meta.url)) void cli(process.argv.slice(2));
