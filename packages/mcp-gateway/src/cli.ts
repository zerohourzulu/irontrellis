#!/usr/bin/env node
/**
 * `irontrellis-mcp-gateway --config /absolute/private/gateway.json`
 * Serves the configured gateway on stdio. Startup failures print one JSON line
 * on stderr ({"status":"REFUSED","reason":<CODE>,"detail":<why>}) and exit 2.
 * The detail names the file, setting or limit at fault (bad JSON, a file mode,
 * a relative upstream command, an unknown flag); it never echoes configuration
 * values, keys or payloads.
 */
import { loadGatewayConfig } from "./config.ts";
import { createGateway, type Gateway } from "./gateway.ts";
import { acquireHostLease, type HostLease } from "./operations.ts";
import { SERVER_INFO, serveGateway } from "./server.ts";
import { GatewayError, codeOf, describeError, explained } from "./data.ts";
import { createDemoCase } from "./demo.ts";

const USAGE = `◆ IronTrellis MCP gateway

Usage: irontrellis-mcp-gateway --config /absolute/private/gateway.json
       irontrellis-mcp-gateway setup /absolute/new-directory [--mode exactly-once|per-call] [--record-calls] [--investigation]
       irontrellis-mcp-gateway --help | --version

Serves the operator-approved upstream tools on stdio, exactly once per job
(mode "exactly-once", the default) or authorized on every call (mode "per-call").
"setup" creates a private synthetic case (a format-2 history, disposable keys
for the worker and for the gateway's own session, two local upstream servers,
gateway.json) to connect a client to; it refuses to overwrite. With
--investigation the case also holds a request whose reply was lost and the open
investigation duty over it (duty:incident-42), for the irontrellis duty commands.

A startup refusal is one JSON line on stderr, exit code 2:
  {"status":"REFUSED","reason":"GATEWAY_CONFIGURATION_UNAVAILABLE","code":<CODE>,"detail":<why>}
`;
const usage = (detail: string): never => { throw new GatewayError("USAGE", false, detail); };
const isHelp = (arg: string | undefined): boolean => arg === "--help" || arg === "-h" || arg === "help";

let gateway: Gateway | undefined, lease: HostLease | undefined;
try {
  const args = process.argv.slice(2);
  if (args.some(isHelp)) {
    process.stdout.write(USAGE);
    process.exit(0);
  }
  if (args.length === 1 && args[0] === "--version") {
    process.stdout.write(`${SERVER_INFO.name} ${SERVER_INFO.version}\n`);
    process.exit(0);
  }
  if (args.length === 0) usage("missing --config <gateway.json>");
  if (args[0] === "setup") {
    const target = args[1];
    if (target === undefined) usage("setup needs a directory to create");
    if (target!.startsWith("-")) usage(`setup needs a directory first, not the option ${JSON.stringify(target!.slice(0, 64))}`);
    const rest = args.slice(2);
    let mode: "exactly-once" | "per-call" = "exactly-once", recordCalls = false, investigation = false;
    for (let i = 0; i < rest.length; i++) {
      if (rest[i] === "--mode") {
        if (rest[i + 1] !== "per-call" && rest[i + 1] !== "exactly-once") usage('--mode must be "exactly-once" or "per-call"');
        mode = rest[++i] as typeof mode;
      } else if (rest[i] === "--record-calls") recordCalls = true;
      else if (rest[i] === "--investigation") investigation = true;
      else usage(`unknown setup option ${JSON.stringify(rest[i]!.slice(0, 64))}`);
    }
    const made = await createDemoCase(target!, { mode, recordCalls, investigation }).catch((error: unknown) => {
      throw new GatewayError(codeOf(error) ?? "SETUP_FAILED", false, `setup: ${target} ${describeError(error)}`);
    });
    process.stdout.write(`Private case created (${mode}${recordCalls ? ", recorded calls" : ""}). Keep it private.\nMCP configuration: ${made.configFile}\nHistory: ${made.local.historyFile}\n`);
    if (made.investigation !== undefined) {
      process.stdout.write(`Investigation: ${made.investigation.duty} (attester role ${made.investigation.role}; incident document ${made.investigation.incident}; session ${made.local.session}, key ${made.config.keyFile})\n`);
    }
    process.exit(0);
  }
  if (args[0] !== "--config") usage(`unknown argument ${JSON.stringify(args[0]!.slice(0, 64))}; expected --config <gateway.json> or setup`);
  if (args.length !== 2) usage(args.length < 2 ? "--config needs the path of gateway.json" : `unexpected argument ${JSON.stringify(args[2]!.slice(0, 64))} after --config <gateway.json>`);
  const loaded = loadGatewayConfig(args[1]!);
  if (loaded.storage !== undefined) lease = explained("the storage directory (storage):", () => acquireHostLease(loaded.storage!));
  const inner = await createGateway(loaded.options).catch((error: unknown) => {
    throw new GatewayError(codeOf(error) ?? "INVALID_INPUT", false, `the upstreams, operations or tools in gateway.json: ${describeError(error)}`);
  });
  const owned = (): void => lease?.assertOwned();
  gateway = {
    ...inner,
    run: (name, input) => { owned(); return inner.run(name, input, { assertCurrent: owned }); },
    async close() { await inner.close(); lease?.release(); },
  };
  await serveGateway(gateway);
  const stop = (): void => { gateway!.close().finally(() => process.exit(0)); };
  process.stdin.once("end", stop);
  process.once("SIGTERM", stop);
  // Windows sends no SIGTERM (a stop there terminates the process); Ctrl+Break is its console interrupt.
  if (process.platform === "win32") process.once("SIGBREAK", stop);
} catch (error) {
  const code = codeOf(error);
  if (code === "USAGE") process.stderr.write(USAGE);
  process.stderr.write(JSON.stringify({
    status: "REFUSED", reason: "GATEWAY_CONFIGURATION_UNAVAILABLE", ...(code !== undefined && /^[A-Z_]{3,60}$/.test(code) ? { code } : {}), detail: describeError(error),
  }) + "\n");
  await gateway?.close();
  try { lease?.release(); } catch { /* already released */ }
  process.exitCode = 2;
}
