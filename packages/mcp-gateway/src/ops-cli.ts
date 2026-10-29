#!/usr/bin/env node
/**
 * `irontrellis-mcp-ops <command> [options]`: operator diagnostics and control
 * for one gateway case. Output is JSON on stdout; refusals are JSON on stderr
 * with exit code 2. Nothing here grants an agent anything.
 */
import { readFileSync } from "node:fs";
import { readGatewayConfig } from "./config.ts";
import { GatewayError, codeOf, describeError, explained } from "./data.ts";
import { inspectCase, recoverDeadHost, revokeAuthority, snapshotCase, verifySnapshot } from "./operations.ts";

const USAGE = `◆ IronTrellis MCP gateway operations

Usage: irontrellis-mcp-ops <command> [options]

Commands
  inspect            Counts and capacity of a case; no identities, arguments or paths.
                     --history <file> --storage <dir>   |   --config <gateway.json>
  revoke             Revoke one recorded authority (grant, delegation or prohibition) as the owner.
                     --authority <id> (--history <file> | --config <gateway.json>)
                     Revocation is always admitted; a running gateway sees it on its next call.
  snapshot           Offline private copy into a new directory (its parent must be 0700): the history, its
                     pinned head (<history>.head), local anchor log (<history>.anchors) and remote witness
                     state (<history>.witness.json) when present, every record, and gateway.json when
                     --config is given. Key files are never copied.
                     --history <file> --storage <dir> --directory <new-dir>   |   --config <gateway.json> --directory <new-dir>
  verify             Check a snapshot's checksums and replay its history (does not establish currentness).
                     --directory <snapshot-dir>
  recover-dead-host  Remove the host lease of a same-host process that provably no longer exists.
                     --storage <dir>   |   --config <gateway.json>
  help, --help, -h   This text.
  --version          The package version.

Every result is JSON. A refusal is {"status":"REFUSED","reason":<CODE>,"detail":<why>} on stderr with exit code 2.
`;

type Options = { historyFile?: string; storage?: string; directory?: string; authority?: string; config?: string };
const usage = (detail: string): never => { throw new GatewayError("USAGE", false, detail); };
const FLAGS: Readonly<Record<string, keyof Options>> = { "--history": "historyFile", "--storage": "storage", "--directory": "directory", "--authority": "authority", "--config": "config" };

function parse(args: readonly string[]): Options {
  const options: Options = {};
  for (let i = 0; i < args.length; i += 2) {
    const flag = args[i]!, key = FLAGS[flag];
    if (key === undefined) usage(`unknown option ${JSON.stringify(flag.slice(0, 64))}`);
    if (options[key!] !== undefined) usage(`${flag} is given twice`);
    if (args[i + 1] === undefined) usage(`${flag} needs a value`);
    options[key!] = args[i + 1]!;
  }
  if (options.config !== undefined) {
    const config = explained("gateway.json:", () => readGatewayConfig(options.config!));
    options.historyFile ??= config.historyFile;
    if (config.storage !== undefined) options.storage ??= config.storage;
  }
  return options;
}
const need = (options: Options, keys: readonly (keyof Options)[]): void => {
  const flag = (key: keyof Options): string => Object.keys(FLAGS).find((f) => FLAGS[f] === key)!;
  for (const key of keys) if (options[key] === undefined) usage(`missing ${flag(key)}${key === "historyFile" || key === "storage" ? " (or --config <gateway.json>)" : ""}`);
};

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);
  if (command === "--version" && rest.length === 0) {
    const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
    process.stdout.write(`irontrellis-mcp-ops ${version}\n`);
    return;
  }
  if (command === undefined || command === "help" || command === "--help" || command === "-h" || rest.some((a) => a === "--help" || a === "-h")) {
    process.stdout.write(USAGE);
    if (command === undefined) process.exitCode = 2;
    return;
  }
  const options = parse(rest);
  let result: unknown;
  switch (command) {
    case "inspect": need(options, ["historyFile", "storage"]); result = inspectCase({ historyFile: options.historyFile!, storage: options.storage! }); break;
    case "revoke": need(options, ["historyFile", "authority"]); result = await revokeAuthority({ historyFile: options.historyFile!, authority: options.authority! }); break;
    case "snapshot": need(options, ["historyFile", "storage", "directory"]);
      result = snapshotCase({ historyFile: options.historyFile!, storage: options.storage!, directory: options.directory!, ...(options.config === undefined ? {} : { configFile: options.config }) }); break;
    case "verify": need(options, ["directory"]); result = verifySnapshot(options.directory!); break;
    case "recover-dead-host": need(options, ["storage"]); result = recoverDeadHost(options.storage!); break;
    default: usage(`unknown command ${JSON.stringify(command.slice(0, 64))}`);
  }
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
}

try {
  await main();
} catch (error) {
  const code = codeOf(error) ?? (error instanceof Error ? error.message : "");
  if (code === "USAGE") process.stderr.write(USAGE);
  const detail = describeError(error);
  process.stderr.write(JSON.stringify({ status: "REFUSED", reason: /^[A-Z_]{3,60}$/.test(code) ? code : "OPERATION_UNAVAILABLE", ...(detail === code ? {} : { detail }) }) + "\n");
  process.exitCode = 2;
}
