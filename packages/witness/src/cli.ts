/**
 * The `irontrellis-witness` command (docs/reference/witness-service.md):
 *
 *   init --data <dir> --name <name> [--origin <origin>]
 *   serve --data <dir> [--config <file>] [--listen host:port] [--force-unlock] [--reload-interval <seconds>]
 *   token create --data <dir> [--config <file>]
 *   verifier-key --data <dir>
 *   check-log --data <dir> [--verifier-key <vkey> --origin <origin>]
 *   import-key-events --data <dir> [--config <file>] [--force-unlock] <bundle>...
 *
 * Every command takes `--json`. `serve` logs one JSON object per line to
 * stderr (access log lines carry no bodies).
 */
import { readFileSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { join, resolve } from "node:path";
import { parseVerifierKey } from "@ramex-labs/irontrellis/transparency";
import { ownerOnlyModeEnforced } from "@ramex-labs/irontrellis/platform";
import { checkLog, type CheckReport } from "./check.ts";
import {
  ConfigError, configText, hashToken, initDataDir, isValidOrigin, loadConfig, loadWitnessKey, newAdminToken, parseListen, writePrivateFile, type WitnessConfig,
} from "./config.ts";
import { CONFIG_FILE, DataError, KEY_FILE } from "./log.ts";
import { createWitnessServer, type WitnessServer } from "./server.ts";
import { Witness, type Logger } from "./witness.ts";

export const VERSION: string = (createRequire(import.meta.url)("../package.json") as { version: string }).version;
export const SOFTWARE = `irontrellis-witness ${VERSION}`;

// ---------------------------------------------------------------- output

type Io = Readonly<{ out: (text: string) => void; err: (text: string) => void; env: Readonly<Record<string, string | undefined>>; isTTY: boolean }>;
const processIo = (): Io => ({ out: (text) => process.stdout.write(text), err: (text) => process.stderr.write(text), env: process.env, isTTY: process.stdout.isTTY === true });

const paint = (io: Io, text: string, colour: number): string => (io.isTTY && io.env.NO_COLOR === undefined && io.env.TERM !== "dumb" ? `\u001b[38;5;${colour}m${text}\u001b[0m` : text);
const glyph = (io: Io): string => {
  const locale = io.env.LC_ALL || io.env.LC_CTYPE || io.env.LANG;
  return locale === undefined || locale === "" || /utf-?8/i.test(locale) ? "◆" : "*";
};
const header = (io: Io): string => `${paint(io, `${glyph(io)} irontrellis-witness`, 208)} ${VERSION} ${paint(io, "—", 245)} agents change. the structure holds.`;
const dim = (io: Io, text: string): string => paint(io, text, 245);
const json = (value: unknown): string => `${JSON.stringify(value, null, 2)}\n`;
const rows = (io: Io, pairs: readonly (readonly [string, string])[]): string[] => {
  const width = Math.max(...pairs.map(([key]) => key.length));
  return pairs.map(([key, value]) => `  ${dim(io, key.padEnd(width))}  ${value}`);
};

/** One JSON object per line on stderr: the server log. */
export function jsonLogger(write: (line: string) => void = (line) => process.stderr.write(line)): Logger {
  const at = (level: string) => (message: string, fields: Readonly<Record<string, unknown>> = {}): void => {
    write(`${JSON.stringify({ time: new Date().toISOString(), level, msg: message, ...fields })}\n`);
  };
  return Object.freeze({ info: at("info"), warn: at("warn"), error: at("error") });
}

// ---------------------------------------------------------------- arguments

class UsageError extends Error {}

type Parsed = Readonly<{ positional: string[]; flags: Map<string, string | true> }>;
const VALUE_FLAGS = new Set(["data", "name", "origin", "config", "listen", "verifier-key", "reload-interval"]);
const BOOLEAN_FLAGS = new Set(["json", "help", "version", "force-unlock"]);

function parseArgs(argv: readonly string[]): Parsed {
  const positional: string[] = [];
  const flags = new Map<string, string | true>();
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index] as string;
    if (arg === "-h") { flags.set("help", true); continue; }
    if (arg === "-v") { flags.set("version", true); continue; }
    if (!arg.startsWith("--")) { positional.push(arg); continue; }
    const eq = arg.indexOf("=");
    const name = arg.slice(2, eq < 0 ? undefined : eq);
    if (BOOLEAN_FLAGS.has(name)) {
      if (eq >= 0) throw new UsageError(`--${name} takes no value`);
      flags.set(name, true);
    } else if (VALUE_FLAGS.has(name)) {
      const value = eq >= 0 ? arg.slice(eq + 1) : argv[(index += 1)];
      if (value === undefined || value === "") throw new UsageError(`--${name} needs a value`);
      flags.set(name, value);
    } else {
      throw new UsageError(`unknown option --${name}`);
    }
  }
  return { positional, flags };
}

const flag = (parsed: Parsed, name: string): string | undefined => {
  const value = parsed.flags.get(name);
  return typeof value === "string" ? value : undefined;
};
const requireFlag = (parsed: Parsed, name: string): string => {
  const value = flag(parsed, name);
  if (value === undefined) throw new UsageError(`--${name} is required`);
  return value;
};
const dataDirOf = (parsed: Parsed): string => resolve(requireFlag(parsed, "data"));
const configPathOf = (parsed: Parsed, dataDir: string): string => resolve(flag(parsed, "config") ?? join(dataDir, CONFIG_FILE));

export const HELP = `irontrellis-witness ${VERSION}: a witness server for IronTrellis histories.
It records owner-signed head statements in an append-only Merkle log and
returns signed receipts, so a history cannot be rolled back unnoticed.

Usage:
  irontrellis-witness init --data <dir> --name <name> [--origin <origin>]
      Create the data directory (0700), a checkpoint key and a config; print the verifier key.
  irontrellis-witness serve --data <dir> [--config <file>] [--listen host:port] [--force-unlock] [--reload-interval <seconds>]
      Serve the HTTP API (plain HTTP; put TLS in a reverse proxy). Default listen ${"127.0.0.1:8411"}.
      --reload-interval: re-read the admin token hashes whenever the config file changes, checked
      every <seconds> (0 = off, else at least 1; default 0, and 5 on Windows, which has no SIGHUP).
  irontrellis-witness token create --data <dir> [--config <file>]
      Print a new admin token for registration and store its SHA-256 in the config.
  irontrellis-witness verifier-key --data <dir>
      Print the verifier key clients configure.
  irontrellis-witness check-log --data <dir> [--verifier-key <vkey> --origin <origin>]
      Offline audit: replay the log, re-verify every signature, recompute the tree
      and check every checkpoint. Exit 1 when anything does not verify.
  irontrellis-witness import-key-events --data <dir> [--config <file>] [--force-unlock] <bundle>...
      Offline delivery of owner key-event bundles (irontrellis owner export-key-events)
      while the server is stopped: takes the server lock and runs exactly the checks
      of POST /v1/histories/:id/key-events. Exit 1 when a bundle is refused.

Options:
  --json       machine-readable output
  --help, -h   this help
  --version    print the version

Signals (serve): SIGTERM/SIGINT stop accepting, finish in-flight appends and release
the lock; SIGHUP reloads the admin token hashes from the config. On Windows (no SIGHUP
to send; a hard kill is not graceful, the log's crash recovery covers it): Ctrl+C
(SIGINT), Ctrl+Break (SIGBREAK) and closing the console (SIGHUP) stop the server, and
the token hashes are reloaded by --reload-interval.
`;

// ---------------------------------------------------------------- commands

function cmdInit(parsed: Parsed, io: Io): number {
  const dataDir = dataDirOf(parsed);
  const result = initDataDir(dataDir, requireFlag(parsed, "name"), flag(parsed, "origin"));
  if (parsed.flags.has("json")) {
    io.out(json({ dataDir: result.dataDir, name: result.name, origin: result.origin, verifierKey: result.verifierKey, keyFile: result.keyPath, configFile: result.configPath }));
    return 0;
  }
  io.out([
    header(io), "", "Initialized a witness data directory.",
    ...rows(io, [["data", result.dataDir], ["name", result.name], ["origin", result.origin], ["key file", `${result.keyPath} (0600, keep it secret and backed up)`], ["config", result.configPath]]),
    "", "Verifier key (give this to clients):", `  ${result.verifierKey}`, "",
    dim(io, "Registration needs an admin token by default: irontrellis-witness token create --data <dir>"), "",
  ].join("\n"));
  return 0;
}

function cmdVerifierKey(parsed: Parsed, io: Io): number {
  const key = loadWitnessKey(join(dataDirOf(parsed), KEY_FILE));
  if (parsed.flags.has("json")) io.out(json({ name: key.name, verifierKey: key.verifierKey }));
  else io.out(`${key.verifierKey}\n`);
  return 0;
}

function cmdTokenCreate(parsed: Parsed, io: Io): number {
  const dataDir = dataDirOf(parsed);
  const path = configPathOf(parsed, dataDir);
  const config = loadConfig(path);
  const token = newAdminToken();
  const hash = hashToken(token);
  const updated: WitnessConfig = { ...config, adminTokenHashes: [...config.adminTokenHashes, hash] };
  writePrivateFile(path, configText(updated));
  if (parsed.flags.has("json")) {
    io.out(json({ token, sha256: hash, config: path }));
    return 0;
  }
  io.out([
    header(io), "", "Created an admin token. It is shown once; the config keeps only its SHA-256.", "", `  ${token}`, "",
    ...rows(io, [["sha256", hash], ["config", path]]),
    "", dim(io, "A running server picks it up on SIGHUP (or, on Windows and with --reload-interval, when it next checks the config) or on restart. Remove the hash from adminTokenHashes to revoke it."), "",
  ].join("\n"));
  return 0;
}

function trustFor(parsed: Parsed, dataDir: string): Readonly<{ verifierKey: string; origin: string }> {
  const vkey = flag(parsed, "verifier-key");
  const origin = flag(parsed, "origin");
  if (vkey !== undefined || origin !== undefined) {
    if (vkey === undefined || origin === undefined) throw new UsageError("--verifier-key and --origin go together");
    try {
      parseVerifierKey(vkey);
    } catch {
      throw new UsageError("--verifier-key is not a valid verifier key");
    }
    if (!isValidOrigin(origin)) throw new UsageError("--origin must be one printable ASCII line");
    return { verifierKey: vkey, origin };
  }
  const key = loadWitnessKey(join(dataDir, KEY_FILE));
  const config = loadConfig(configPathOf(parsed, dataDir));
  return { verifierKey: key.verifierKey, origin: config.origin };
}

function cmdCheckLog(parsed: Parsed, io: Io): number {
  const dataDir = dataDirOf(parsed);
  const report: CheckReport = checkLog(dataDir, trustFor(parsed, dataDir));
  if (parsed.flags.has("json")) {
    io.out(json({ status: report.ok ? "VALID" : "INVALID", ...report }));
    return report.ok ? 0 : 1;
  }
  const status = report.ok ? paint(io, "VALID", 35) : paint(io, "INVALID", 203);
  const lines = [
    header(io), "", `Log ${status}`,
    ...rows(io, [
      ["entries", String(report.entries)], ["histories", `${report.histories}${report.equivocatingHistories > 0 ? ` (${report.equivocatingHistories} with recorded equivocations)` : ""}`],
      ["kinds", Object.entries(report.kinds).map(([kind, count]) => `${kind} ${count}`).join(", ")], ["root", report.root],
      ["checkpoints", `${report.checkpoints}${report.lastCheckpointSize === null ? "" : ` (last covers ${report.lastCheckpointSize})`}`],
    ]),
  ];
  for (const problem of report.problems) lines.push(`  ${paint(io, "problem", 203)}  ${problem.file}${problem.line === undefined ? "" : `:${problem.line}`}  ${problem.message}`);
  for (const warning of report.warnings) lines.push(`  ${paint(io, "note", 178)}     ${warning}`);
  lines.push("", dim(io, report.ok
    ? "Every entry follows the witness rules, every owner signature verifies, and every checkpoint matches the log. This establishes the log is internally consistent and signed by this key; it does not show that clients were shown the same log."
    : "The log or its checkpoints do not verify. Do not serve from this directory until the cause is understood; restore from a backup if the log was altered."), "");
  io.out(lines.join("\n"));
  return report.ok ? 0 : 1;
}

export type ImportOutcome = Readonly<{ file: string; status: number; accepted: boolean; historyId?: string; code?: string; message?: string; index?: number; superseded?: boolean }>;

/**
 * `import-key-events`: opens the data directory like `serve` (taking `server.lock`, replaying the log), delivers each
 * bundle through the key-event rules (`Witness#importBundle`, the admin route's checks), signs a checkpoint and closes.
 */
export async function importKeyEvents(options: Readonly<{ dataDir: string; configPath?: string; files: readonly string[]; forceUnlock?: boolean; logger?: Logger; now?: () => number }>): Promise<readonly ImportOutcome[]> {
  const dataDir = resolve(options.dataDir);
  const config = loadConfig(options.configPath ?? join(dataDir, CONFIG_FILE));
  const key = loadWitnessKey(join(dataDir, KEY_FILE));
  if (key.name !== config.name) throw new ConfigError(`the config names the witness ${JSON.stringify(config.name)} but the key is ${JSON.stringify(key.name)}`);
  const bundles = options.files.map((file) => {
    const path = resolve(file);
    let value: unknown;
    try { value = JSON.parse(readFileSync(path, "utf8")); } catch (error) { throw new UsageError(`${path} is not a readable JSON bundle: ${error instanceof Error ? error.message : String(error)}`); }
    return { file: path, value };
  });
  const witness = await Witness.open({
    dataDir, origin: config.origin, signer: key.signer, verifierKey: key.verifierKey, checkpointIntervalMs: 0, maxHistories: config.maxHistories,
    logger: options.logger ?? jsonLogger(), forceUnlock: options.forceUnlock === true, ...(options.now === undefined ? {} : { now: options.now }),
  });
  const outcomes: ImportOutcome[] = [];
  try {
    for (const { file, value } of bundles) {
      const reply = await witness.importBundle(value);
      const body = reply.body as { error?: { code?: string; message?: string }; receipt?: { index?: number }; superseded?: unknown };
      const historyId = (value as { historyId?: unknown } | null)?.historyId;
      outcomes.push(Object.freeze({
        file, status: reply.status, accepted: reply.status === 200 || reply.status === 201, ...(typeof historyId === "string" ? { historyId } : {}),
        ...(body.error === undefined ? {} : { code: body.error.code, message: body.error.message }), ...(typeof body.receipt?.index === "number" ? { index: body.receipt.index } : {}),
        ...(body.superseded === undefined ? {} : { superseded: true }),
      }));
    }
  } finally {
    await witness.close();
  }
  return Object.freeze(outcomes);
}

async function cmdImportKeyEvents(parsed: Parsed, files: readonly string[], io: Io): Promise<number> {
  if (files.length === 0) throw new UsageError("usage: irontrellis-witness import-key-events --data <dir> <bundle>...");
  const dataDir = dataDirOf(parsed);
  const outcomes = await importKeyEvents({ dataDir, configPath: configPathOf(parsed, dataDir), files, forceUnlock: parsed.flags.has("force-unlock"), logger: jsonLogger(() => undefined) });
  const ok = outcomes.every((outcome) => outcome.accepted);
  if (parsed.flags.has("json")) {
    io.out(json({ status: ok ? "IMPORTED" : "REFUSED", outcomes }));
    return ok ? 0 : 1;
  }
  const lines = [header(io), ""];
  for (const outcome of outcomes) {
    lines.push(`${outcome.accepted ? paint(io, outcome.status === 201 ? "IMPORTED" : "ALREADY RECORDED", 35) : paint(io, "REFUSED", 203)}  ${outcome.file}`);
    lines.push(...rows(io, [
      ["history", outcome.historyId ?? "—"], ...(outcome.index === undefined ? [] : [["leaf", String(outcome.index)] as const]),
      ...(outcome.superseded === true ? [["superseded", "yes: a pre-rotated rotation overrode heads signed after the last good head"] as const] : []),
      ...(outcome.code === undefined ? [] : [[outcome.code, outcome.message ?? ""] as const]),
    ]));
  }
  lines.push("", dim(io, "Every bundle got the checks of POST /v1/histories/:id/key-events: owner signatures and the key-event rules against the epochs this witness knows. Start the server again to serve the new entries."), "");
  io.out(lines.join("\n"));
  return ok ? 0 : 1;
}

export type ServeHandle = Readonly<{ witness: Witness; server: WitnessServer; url: string; config: WitnessConfig; close(): Promise<void> }>;

/** The default of `serve --reload-interval`, in milliseconds: off (SIGHUP reloads) except on Windows, which has no SIGHUP to send. */
export const defaultReloadIntervalMs = (platform: NodeJS.Platform = process.platform): number => (platform === "win32" ? 5000 : 0);

/** Re-reads the admin token hashes from `configPath` into the running server; a config that does not load keeps the previous tokens. */
export function reloadAdminTokens(server: Pick<WitnessServer, "setAdminTokenHashes">, configPath: string, logger: Logger, why: string): boolean {
  try {
    server.setAdminTokenHashes(loadConfig(configPath).adminTokenHashes);
    logger.info("reloaded admin token hashes", { trigger: why });
    return true;
  } catch (error) {
    logger.error("config reload failed; keeping the previous tokens", { trigger: why, error: error instanceof Error ? error.message : String(error) });
    return false;
  }
}

/**
 * The portable alternative to SIGHUP (`serve --reload-interval`): every `intervalMs` the config file's size, mtime and
 * inode are compared with the last look, and a change reloads the admin token hashes. The timer does not keep the
 * process alive. Returns the function that stops watching.
 */
export function watchAdminTokens(server: Pick<WitnessServer, "setAdminTokenHashes">, configPath: string, intervalMs: number, logger: Logger): () => void {
  const look = (): string => {
    try {
      const info = statSync(configPath, { bigint: true });
      return `${info.size}:${info.mtimeNs}:${info.ino}`;
    } catch (error) {
      return `unreadable:${(error as NodeJS.ErrnoException | null)?.code ?? "?"}`;
    }
  };
  let last = look();
  const timer = setInterval(() => {
    const now = look();
    if (now === last) return;
    last = now;
    reloadAdminTokens(server, configPath, logger, "config changed");
  }, intervalMs);
  timer.unref();
  return () => clearInterval(timer);
}

type SignalName = "SIGTERM" | "SIGINT" | "SIGHUP" | "SIGBREAK";
/**
 * The signals `serve` answers. POSIX: SIGTERM and SIGINT stop, SIGHUP reloads the admin tokens. Windows delivers no
 * SIGTERM to a Node process (a service stop or `taskkill /F` terminates it outright) and has no SIGHUP to send: Node
 * raises SIGINT on Ctrl+C, SIGBREAK on Ctrl+Break and SIGHUP when the console window closes, and all three stop.
 */
export function serveSignals(platform: NodeJS.Platform = process.platform): Readonly<Record<SignalName, "stop" | "reload">> {
  return platform === "win32"
    ? Object.freeze({ SIGTERM: "stop", SIGINT: "stop", SIGBREAK: "stop", SIGHUP: "stop" }) as Readonly<Record<SignalName, "stop" | "reload">>
    : Object.freeze({ SIGTERM: "stop", SIGINT: "stop", SIGHUP: "reload" }) as Readonly<Record<SignalName, "stop" | "reload">>;
}

/** Starts the witness server (used by `serve`, and by tests in-process). */
export async function serve(options: Readonly<{
  dataDir: string; configPath?: string; listen?: string; forceUnlock?: boolean; logger?: Logger; now?: () => number; configOverride?: Partial<WitnessConfig>;
}>): Promise<ServeHandle> {
  const dataDir = resolve(options.dataDir);
  const logger = options.logger ?? jsonLogger();
  const configPath = options.configPath ?? join(dataDir, CONFIG_FILE);
  const loaded = loadConfig(configPath);
  const config: WitnessConfig = { ...loaded, ...(options.listen === undefined ? {} : { listen: options.listen }), ...options.configOverride };
  const { host, port } = parseListen(config.listen);
  const key = loadWitnessKey(join(dataDir, KEY_FILE));
  if (key.name !== config.name) throw new ConfigError(`the config names the witness ${JSON.stringify(config.name)} but the key is ${JSON.stringify(key.name)}`);
  if (ownerOnlyModeEnforced() && (statSync(dataDir).mode & 0o077) !== 0) logger.warn("the data directory is accessible by other users; chmod 700 it", { dataDir });
  const witness = await Witness.open({
    dataDir, origin: config.origin, signer: key.signer, verifierKey: key.verifierKey, checkpointIntervalMs: config.checkpointIntervalMs,
    maxHistories: config.maxHistories, logger, forceUnlock: options.forceUnlock === true, ...(options.now === undefined ? {} : { now: options.now }),
  });
  const server = createWitnessServer({ witness, config, software: SOFTWARE, logger, ...(options.now === undefined ? {} : { now: options.now }) });
  let address;
  try {
    address = await server.listen(host, port);
  } catch (error) {
    await witness.close();
    throw error;
  }
  const hostText = address.family === "IPv6" ? `[${address.address}]` : address.address;
  const url = `http://${hostText}:${address.port}`;
  // Every start-up warning precedes "listening", the readiness line supervisors and tests wait for.
  if (config.registration === "token" && config.adminTokenHashes.length === 0) logger.warn("registration needs an admin token but none is configured; run: irontrellis-witness token create", {});
  logger.info("listening", { url, origin: witness.origin, verifierKey: witness.verifierKey, entries: witness.size, registration: config.registration, software: SOFTWARE });
  return Object.freeze({ witness, server, url, config, close: () => server.close() });
}

/** The shortest `serve --reload-interval` (seconds; 0 turns the reload off): a stat of the config file per interval. */
export const MIN_RELOAD_INTERVAL_SECONDS = 1;

async function cmdServe(parsed: Parsed): Promise<number | undefined> {
  const dataDir = dataDirOf(parsed);
  const configPath = configPathOf(parsed, dataDir);
  const logger = jsonLogger();
  const listen = flag(parsed, "listen");
  const reloadText = flag(parsed, "reload-interval");
  const reloadSeconds = reloadText === undefined ? defaultReloadIntervalMs() / 1000 : Number(reloadText);
  if (!Number.isFinite(reloadSeconds) || reloadSeconds < 0 || reloadSeconds > 86_400 || (reloadText !== undefined && !/^[0-9]+(\.[0-9]+)?$/.test(reloadText))) {
    throw new UsageError(`--reload-interval is a number of seconds: 0 (off) or ${MIN_RELOAD_INTERVAL_SECONDS} to 86400`);
  }
  // An interval that rounds to 0 ms would be a busy polling loop. Refused, not clamped, so the operator
  // sees that the value was not used.
  if (reloadSeconds !== 0 && reloadSeconds < MIN_RELOAD_INTERVAL_SECONDS) {
    throw new UsageError(`--reload-interval ${reloadText} is below the minimum of ${MIN_RELOAD_INTERVAL_SECONDS} second (0 turns the reload off)`);
  }
  const handle = await serve({ dataDir, configPath, ...(listen === undefined ? {} : { listen }), forceUnlock: parsed.flags.has("force-unlock"), logger });
  let stopping = false;
  const stop = (signal: string): void => {
    if (stopping) return;
    stopping = true;
    logger.info("shutting down", { signal });
    handle.close().then(() => {
      logger.info("stopped", { entries: handle.witness.size });
      process.exit(0);
    }, (error: unknown) => {
      logger.error("shutdown failed", { error: error instanceof Error ? error.message : String(error) });
      process.exit(1);
    });
  };
  for (const [signal, action] of Object.entries(serveSignals())) {
    process.on(signal as SignalName, action === "stop" ? () => stop(signal) : () => { reloadAdminTokens(handle.server, configPath, logger, signal); });
  }
  if (reloadSeconds > 0) watchAdminTokens(handle.server, configPath, Math.round(reloadSeconds * 1000), logger);
  return undefined;
}

/** Runs one command; resolves to its exit code (`undefined` for `serve`, which runs until a signal). */
export async function main(argv: readonly string[], io: Io = processIo()): Promise<number | undefined> {
  let parsed: Parsed;
  try {
    parsed = parseArgs(argv);
  } catch (error) {
    io.err(`irontrellis-witness: ${(error as Error).message}\nRun irontrellis-witness --help for usage.\n`);
    return 2;
  }
  const asJson = parsed.flags.has("json");
  if (parsed.flags.has("version")) {
    io.out(asJson ? json({ name: "irontrellis-witness", version: VERSION }) : `${VERSION}\n`);
    return 0;
  }
  const [command, sub, ...rest] = parsed.positional;
  if (parsed.flags.has("help") || command === undefined || command === "help") {
    io.out(HELP);
    return command === undefined && !parsed.flags.has("help") ? 2 : 0;
  }
  try {
    const extra = command === "token" || command === "import-key-events" ? rest : [sub, ...rest].filter((value) => value !== undefined);
    if (extra.length > 0 && command !== "import-key-events") throw new UsageError(`unexpected argument ${JSON.stringify(extra[0])}`);
    switch (command) {
      case "init": return cmdInit(parsed, io);
      case "serve": return await cmdServe(parsed);
      case "verifier-key": return cmdVerifierKey(parsed, io);
      case "check-log": return cmdCheckLog(parsed, io);
      case "import-key-events": return await cmdImportKeyEvents(parsed, [sub, ...rest].filter((value): value is string => value !== undefined), io);
      case "token":
        if (sub !== "create") throw new UsageError("usage: irontrellis-witness token create --data <dir>");
        return cmdTokenCreate(parsed, io);
      default:
        throw new UsageError(`unknown command ${JSON.stringify(command)}`);
    }
  } catch (error) {
    const usage = error instanceof UsageError;
    const known = usage || error instanceof ConfigError || error instanceof DataError;
    const message = known ? (error as Error).message : `unexpected error: ${error instanceof Error ? error.message : String(error)}`;
    if (asJson) io.out(json({ error: { code: usage ? "USAGE" : error instanceof DataError ? "DATA" : error instanceof ConfigError ? "CONFIG" : "INTERNAL", message } }));
    else io.err(`irontrellis-witness: ${message}\n${usage ? "Run irontrellis-witness --help for usage.\n" : ""}`);
    return usage ? 2 : 1;
  }
}
