#!/usr/bin/env node
import { realpathSync, readFileSync } from "node:fs";
import { Transform } from "node:stream";
import { fileURLToPath } from "node:url";
import { McpServer } from "@modelcontextprotocol/server";
import {
  serveStdio,
  StdioServerTransport,
} from "@modelcontextprotocol/server/stdio";
import * as z from "zod";
import { loadGateway } from "./config.mjs";
import { parseStrictJson } from "./strict-json.mjs";

function summary(output, operationId) {
  const result = output.result,
    packetVerified = output.packet.status === "PACKET_VERIFIED";
  if (result.status === "POLICY_REFUSED")
    return {
      operationId,
      status: "DENIED",
      reason: "ADDITIONAL_POLICY",
      packetVerified,
    };
  if (result.status === "NOT_AUTHORIZED")
    return {
      operationId,
      status: "DENIED",
      reason: "CORE_POLICY",
      packetVerified,
    };
  if (result.status === "NOT_ADMITTED")
    return {
      operationId,
      status: "REFUSED",
      reason: result.admission.status,
      packetVerified,
    };
  const disposition = result.invocation ?? result.result;
  return {
    operationId,
    status:
      result.status === "RECONCILIATION_ONLY"
        ? "RECONCILIATION_ONLY"
        : disposition.status === "SUBMITTED"
          ? "RECORDED"
          : "OUTCOME_UNKNOWN",
    disposition: disposition.status,
    packetVerified,
    ...(packetVerified ? { acknowledgment: output.packet.acknowledgment } : {}),
    externalOutcome: "NOT_PROVEN",
  };
}
const reply = (value, isError = false) => ({
  isError,
  content: [{ type: "text", text: JSON.stringify(value) }],
  structuredContent: value,
});
export function createGatewayServer(tool) {
  const server = new McpServer(
    { name: "irontrellis-protected-evidence", version: JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')).version },
    { capabilities: { tools: {} } },
  );
  let busy = false;
  server.registerTool(
    "irontrellis_collect_evidence",
    {
      title: "Collect the selected evidence packet",
      description:
        "Copy the operator-selected files into a protected evidence packet if the launch-bound runtime still has permission. Keep one operationId for retries; uncertain results are reconciled, never resubmitted. This does not prove the contents true.",
      inputSchema: z
        .object({
          operationId: z
            .string()
            .min(1)
            .max(128)
            .regex(/^[^\u0000-\u001f\u007f]+$/),
          resource: z.literal(tool.resource),
        })
        .strict(),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async (args) => {
      if (busy)
        return reply(
          {
            status: "BUSY",
            retry: "Repeat the same operationId and arguments.",
          },
          true,
        );
      busy = true;
      try {
        const value = summary(await tool.collect(args), args.operationId);
        return reply(
          value,
          ["DENIED", "REFUSED", "OUTCOME_UNKNOWN"].includes(value.status),
        );
      } catch (error) {
        const safe = [
          "INVALID_INPUT",
          "OPERATION_CONFLICT",
          "RUNTIME_NOT_CURRENT",
          "HISTORY_CONFLICT",
          "HISTORY_LIMIT",
          "SIGNER_FAILED",
          "WRITE_UNCONFIRMED",
          "POLICY_EVIDENCE_UNAVAILABLE",
        ];
        return reply(
          {
            operationId: args.operationId,
            status: "REFUSED",
            reason: safe.includes(error.code)
              ? error.code
              : "GATEWAY_UNAVAILABLE",
            mayHaveCommitted: error.mayHaveCommitted === true,
          },
          true,
        );
      } finally {
        busy = false;
      }
    },
  );
  return server;
}

// Bound and validate original wire JSON before the SDK parses it. No duplicate
// keys, unbounded unfinished frame, or silent invalid UTF-8 normalization.
function guardedInput(source) {
  let pending = Buffer.alloc(0),
    timer,
    messages = 0;
  const input = new Transform({
    transform(chunk, _encoding, callback) {
      try {
        pending = Buffer.concat([pending, chunk]);
        if (pending.length > 65536) throw Error("INPUT_LIMIT");
        let end;
        while ((end = pending.indexOf(10)) !== -1) {
          const frame = pending.subarray(0, end);
          pending = pending.subarray(end + 1);
          if (++messages > 1024) throw Error("MESSAGE_LIMIT");
          parseStrictJson(frame, {
            maxBytes: 16384,
            maxDepth: 12,
            maxNodes: 2048,
          });
          this.push(Buffer.concat([frame, Buffer.from("\n")]));
        }
        if (pending.length > 16384) throw Error("FRAME_LIMIT");
        clearTimeout(timer);
        if (pending.length)
          timer = setTimeout(() => {
            process.stderr.write("FRAME_TIMEOUT\n");
            process.exit(2);
          }, 5000);
        callback();
      } catch {
        callback(Error("INVALID_FRAME"));
      }
    },
    flush(callback) {
      clearTimeout(timer);
      callback(pending.length ? Error("INCOMPLETE_FRAME") : undefined);
    },
  });
  input.on("error", () => {
    process.stderr.write("INPUT_REFUSED\n");
    process.exit(2);
  });
  source.pipe(input);
  return input;
}
export function serveGateway(
  tool,
  { input = process.stdin, output = process.stdout } = {},
) {
  return serveStdio(() => createGatewayServer(tool), {
    legacy: "serve",
    maxSubscriptions: 0,
    transport: new StdioServerTransport(guardedInput(input), output, {
      maxBufferSize: 16384,
    }),
    onerror: () => {
      process.stderr.write("MCP_TRANSPORT_ERROR\n");
    },
  });
}
if (
  process.argv[1] &&
  realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    if (process.argv.length !== 4 || process.argv[2] !== "--config")
      throw Error("CONFIG_REQUIRED");
    serveGateway(loadGateway(process.argv[3]));
  } catch {
    process.stderr.write("GATEWAY_CONFIGURATION_UNAVAILABLE\n");
    process.exitCode = 2;
  }
}
