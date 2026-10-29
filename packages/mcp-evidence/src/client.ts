#!/usr/bin/env node
/**
 * `irontrellis-evidence-demo /absolute/private/gateway.json`: starts the
 * server over stdio with the SDK client (protocol revision 2026-07-28), lists its tool and collects the same
 * operation twice (RECORDED, then RECONCILIATION_ONLY).
 */
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { SERVER_INFO, TOOL_NAME } from "./server.ts";
import { describeConfigError, loadEvidenceTool } from "./config.ts";
import { isEntryPoint } from "./entry.ts";

export async function runDemo(configFile: string, log: (line: string) => void = console.log): Promise<void> {
  const client = new Client({ name: "irontrellis-example-client", version: "1.0.0" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
  const transport = new StdioClientTransport({ command: process.execPath, args: [fileURLToPath(new URL("./server.js", import.meta.url)), "--config", configFile], stderr: "pipe" });
  try {
    await client.connect(transport);
    log("Tools: " + (await client.listTools()).tools.map((t) => t.name).join(", "));
    for (let attempt = 0; attempt < 2; attempt++) {
      const result = await client.callTool({ name: TOOL_NAME, arguments: { operationId: "example:collection", resource: "incident:42" } });
      log(JSON.stringify(result.structuredContent ?? result.content, null, 2));
    }
  } finally {
    await client.close();
  }
}

const USAGE = `◆ IronTrellis evidence demo

Usage: irontrellis-evidence-demo /absolute/private/gateway.json
       irontrellis-evidence-demo --help | --version

Starts the evidence server with that configuration over stdio, lists its tool and
collects the same operation twice (RECORDED, then RECONCILIATION_ONLY). Create a
configuration first with irontrellis-evidence-setup <new-directory>.

A refusal is one JSON line on stderr, exit code 2: {"status":"REFUSED","reason":<CODE>,"detail":<why>}
`;
const refuse = (reason: string, detail: string, usage = false): void => {
  if (usage) process.stderr.write(USAGE);
  process.stderr.write(JSON.stringify({ status: "REFUSED", reason, ...(detail === "" ? {} : { detail }) }) + "\n");
  process.exitCode = 2;
};

/** The `irontrellis-evidence-demo` command line. Called without `await` below, so this module (and the package index) has no top-level await and `require()` of the package works. */
async function cli(args: readonly string[]): Promise<void> {
  if (args.some((a) => a === "--help" || a === "-h" || a === "help")) process.stdout.write(USAGE);
  else if (args.length === 1 && args[0] === "--version") process.stdout.write(`irontrellis-evidence-demo ${SERVER_INFO.version}\n`);
  else if (args.length !== 1) refuse("USAGE", args.length === 0 ? "missing the path of gateway.json" : "expected exactly one configuration path", true);
  else if (args[0]!.startsWith("-")) refuse("USAGE", `unknown option ${JSON.stringify(args[0]!.slice(0, 64))}`, true);
  else {
    // Check the configuration here first, so a wrong path or file is reported with its cause instead of a closed connection.
    let ready = true;
    try {
      loadEvidenceTool(args[0]!);
    } catch (error) {
      ready = false;
      refuse("GATEWAY_CONFIGURATION_UNAVAILABLE", describeConfigError(error));
    }
    if (ready) {
      try {
        await runDemo(args[0]!);
      } catch (error) {
        refuse("DEMO_FAILED", error instanceof Error ? error.message.slice(0, 300) : "the demo could not complete");
      }
    }
  }
}
if (isEntryPoint(import.meta.url)) void cli(process.argv.slice(2));
