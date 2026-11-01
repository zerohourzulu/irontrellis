/**
 * EXPERIMENTAL, opt-in and off by default: the resident guard, `irontrellis-hook daemon`. One long-lived process of the
 * user keeps each history's owner handle open and answers the hook's events over a Unix socket; the host's hook command
 * becomes the thin client `irontrellis-hook-client` (bin/irontrellis-hook-client.mjs), which runs today's hook instead
 * whenever the daemon cannot answer. Nothing changes for a user who does not start it.
 *
 * The same decision, nothing weakened: every event runs the hook's own `runHook` (config, route-session record,
 * protective rules, CONFIG_CHANGED, witness check, decideTool, refusal recording, reply text). Two inputs differ, both
 * through `HookIo`: the owner handle comes from a cache (`ownerFor`), and the protective rules read the client's
 * environment (`protectEnv`), never the daemon's. A cached handle is reused only while every file whose name starts with
 * the history's (the history, its pin, snapshot, journal, anchor log, witness state, key files and side directories) and
 * the out-of-band witness policy file have the same identity (dev, inode, mode, size, mtime ns, ctime ns) and the pin the
 * same bytes; any change, the guard's own writes included, means the full verifying open on the next event.
 *
 * What the engine reads from the process environment (the witness policy, the challenge profile, the ssh-agent socket)
 * is the daemon's own. A client whose values differ is told to run the hook (`fallback`), so its answer stays the hook's.
 *
 * Same-user mode only: the socket's directory must belong to this user with no group or other access, and the socket is
 * 0600, so only this user (and root) can connect. Node has no peer-credential call, so a separate-user mode (the daemon
 * under the owner's OS user, the agent under another) waits for a reviewed peer-identity proof; see the hooks README.
 * Requests are served one at a time: the handle is shared, and a session start writes through it.
 *
 * Wire format, one request per connection: a JSON line {v, protocol, event, stdin, env, cwd} in (`stdin`: the hook's
 * standard input as text, parsed here exactly as cli.ts parses it), a JSON line out: {stdout, stderr, exitCode} as cli.ts
 * would write them, or {fallback: reason} when the client must run the hook itself.
 */
import { createHash } from "node:crypto";
import { createConnection, createServer, type Server, type Socket } from "node:net";
import { chmodSync, lstatSync, mkdirSync, readdirSync, readFileSync, realpathSync, statSync, unlinkSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { enforcementWarning, readGenesisLine, type LocalOwner } from "@ramex-labs/irontrellis";
import { CONFIG_ENV, type HookConfig } from "./config.ts";
import { STATE_HOME_ENV, defaultStateHome } from "./paths.ts";
import { failOpenForRoute, openOwner, replyFailure, runHook } from "./hook.ts";
import type { Reply } from "./protocols/types.ts";
import { protocolFor } from "./protocols/index.ts";

export const DAEMON_PROTOCOL = 1;
export const MAX_REQUEST_BYTES = 4 * 1024 * 1024;
export const SOCKET_ENV = "IRONTRELLISD_SOCKET";
/**
 * IRONTRELLISD_SOCKET; else `$XDG_RUNTIME_DIR/irontrellis/irontrellisd.sock` (the per-user runtime directory, 0700 under
 * root's /run/user); else `<state home>/run/irontrellisd.sock`. Both clients apply the same rule to their own environment.
 */
export const defaultSocketPath = (env: Readonly<Record<string, string | undefined>>): string => {
  const named = env[SOCKET_ENV], runtime = env.XDG_RUNTIME_DIR;
  if (named !== undefined && named !== "") return named;
  if (runtime !== undefined && runtime.startsWith("/")) return join(runtime, "irontrellis", "irontrellisd.sock");
  return join(defaultStateHome(env), "run", "irontrellisd.sock");
};
/** What the hook reads from its environment (config.ts, paths.ts, route.ts, protect.ts): the only variables a request may carry. */
export const CLIENT_ENV: readonly string[] = Object.freeze([
  "CLAUDE_PROJECT_DIR", "CLAUDE_CONFIG_DIR", "CLAUDE_PLUGIN_ROOT", "CLAUDE_CODE_PLUGIN_CACHE_DIR", "CODEX_HOME", "HOME", "PATH", "SSH_AUTH_SOCK",
  CONFIG_ENV, STATE_HOME_ENV, "IRONTRELLIS_WITNESS_POLICY", "IRONTRELLIS_CHALLENGE_PROFILE",
]);
/** What the engine reads from the process environment: the daemon's own; a client with other values runs the hook. */
export const ENGINE_ENV: readonly string[] = Object.freeze(["IRONTRELLIS_WITNESS_POLICY", "IRONTRELLIS_CHALLENGE_PROFILE", "SSH_AUTH_SOCK"]);

const identity = (path: string): string => {
  const s = lstatSync(path, { bigint: true });
  return `${s.dev}:${s.ino}:${s.mode}:${s.size}:${s.mtimeNs}:${s.ctimeNs}`;
};

/**
 * The identity of what an open reads: every entry of the history's directory named like the history (the file and every
 * `<history>.*` side file or directory), the pin's bytes, and the out-of-band witness policy file. A superset of what the
 * store reads, so a side file added to the store later is covered without a change here.
 */
export function historyFingerprint(history: string, env: Readonly<Record<string, string | undefined>> = process.env): string {
  const dir = dirname(history), base = basename(history);
  let names: string[];
  try { names = readdirSync(dir).filter((n) => n === base || n.startsWith(`${base}.`)).sort(); } catch { return "unreadable"; }
  const parts = names.map((name) => {
    try {
      const pin = name === `${base}.head` ? `:${createHash("sha256").update(readFileSync(join(dir, name))).digest("hex")}` : "";
      return `${name}:${identity(join(dir, name))}${pin}`;
    } catch { return `${name}:-`; }
  });
  const policy = env.IRONTRELLIS_WITNESS_POLICY;
  if (policy !== undefined && policy !== "") { try { parts.push(`policy:${identity(policy)}`); } catch { parts.push("policy:-"); } }
  return parts.join("|");
}

type Entry = { owner: LocalOwner; print: string };
const closeOwner = (owner: LocalOwner): void => { (owner as { close?: () => void }).close?.(); };

/** Warm owner handles, one per (history, owner, controller, domain, historyId). */
export class OwnerCache {
  readonly #entries = new Map<string, Entry>();
  readonly stats = { hits: 0, opens: 0 };

  readonly ownerFor = (config: HookConfig, now: () => number, onWarning: (warning: string) => void): LocalOwner => {
    const key = JSON.stringify([config.history, config.owner, config.controller, config.domain ?? null, config.historyId ?? null]);
    const before = historyFingerprint(config.history);
    const hit = this.#entries.get(key);
    if (hit !== undefined && hit.print === before) {
      // What openOwner does on every open besides the open itself: the A-41 opt-in warning, read from line 0.
      const warning = enforcementWarning(config.history, readGenesisLine(config.history)?.format, config.enforceFromReadOnlyHistory);
      if (warning !== undefined) onWarning(warning);
      this.stats.hits += 1;
      return hit.owner;
    }
    if (hit !== undefined) { this.#entries.delete(key); closeOwner(hit.owner); }
    const owner = openOwner(config, now, "enforce", onWarning);
    this.stats.opens += 1;
    // Cached only if nothing changed while it was opened (an open may rewrite the snapshot: then the next event reopens once).
    const after = historyFingerprint(config.history);
    if (after === before) this.#entries.set(key, { owner, print: after });
    else this.#entries.set(key, { owner, print: "changed while opening" });
    return owner;
  };

  close(): void { for (const { owner } of this.#entries.values()) closeOwner(owner); this.#entries.clear(); }
}

export type DaemonReply = Readonly<{ stdout: string; stderr: string; exitCode: number }> | Readonly<{ fallback: string }>;

const isRecord = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const isEnv = (v: unknown): v is Record<string, string> => isRecord(v) && Object.values(v).every((x) => typeof x === "string");

/** As cli.ts `emit` writes a reply: stdout as given; a non-empty stderr always ends with a newline (cli.ts `err`). */
const emitted = (reply: Reply): DaemonReply =>
  ({ stdout: reply.stdout, stderr: reply.stderr === "" || reply.stderr.endsWith("\n") ? reply.stderr : `${reply.stderr}\n`, exitCode: reply.exitCode });

/**
 * Answer one request as `irontrellis-hook <agent> <event>` would (cli.ts main → runHook), with a warm owner handle; or
 * tell the client to run the hook itself when this process could answer differently (an unknown agent or event, whose
 * wording is cli.ts's; engine settings that differ from the client's).
 */
export async function answerRequest(cache: OwnerCache, raw: unknown, daemonEnv: Readonly<Record<string, string | undefined>> = process.env): Promise<DaemonReply> {
  if (!isRecord(raw) || raw.v !== DAEMON_PROTOCOL || typeof raw.protocol !== "string" || typeof raw.event !== "string" || typeof raw.stdin !== "string" || !isEnv(raw.env) || typeof raw.cwd !== "string") {
    return { fallback: "MALFORMED_REQUEST" };
  }
  const { protocol: agent, event, stdin, cwd } = raw as { protocol: string; event: string; stdin: string; cwd: string };
  const protocol = protocolFor(agent);
  if (protocol === undefined || !protocol.events.includes(event)) return { fallback: "UNKNOWN_AGENT_OR_EVENT" };
  const sent = raw.env as Record<string, string>;
  const env: Record<string, string> = {};
  for (const name of CLIENT_ENV) if (Object.hasOwn(sent, name)) env[name] = sent[name]!;
  for (const name of ENGINE_ENV) if ((env[name] ?? "") !== (daemonEnv[name] ?? "")) return { fallback: `ENGINE_ENV ${name}` };
  Object.freeze(env);
  // cli.ts: a tool event the hook cannot read is refused (exit 2 / deny) unless the config says failOpen.
  const isToolEvent = protocol.toolEvents.includes(event);
  const unreadable = (message: string): DaemonReply => emitted(replyFailure(protocol, `irontrellis-hook: ${message}`, isToolEvent, isToolEvent && failOpenForRoute(env, cwd)));
  let payload: unknown;
  try { payload = stdin.trim() === "" ? {} : JSON.parse(stdin); } catch { return unreadable(`stdin is not JSON (${event})`); }
  if (!isRecord(payload)) return unreadable(`stdin must be a JSON object (${event})`);
  try {
    return emitted(await runHook(protocol, event, payload, { env, cwd, now: () => Date.now(), ownerFor: cache.ownerFor, protectEnv: env }));
  } catch (error) {
    return unreadable(error instanceof Error ? error.message : String(error));
  }
}

/**
 * Why another user could move the socket's directory aside, or undefined: every directory above `dir` (symlinks
 * resolved) must belong to this user or root and be writable by nobody else, unless it is root's and sticky (/tmp).
 * The client applies the same rule before it connects (bin/irontrellis-hook-client.mjs).
 */
export function unsafeAncestor(dir: string, uid: number | undefined = process.getuid?.()): string | undefined {
  let at = realpathSync(dir);
  for (let parent = dirname(at); parent !== at; at = parent, parent = dirname(at)) {
    const s = statSync(parent);
    if (s.uid !== uid && s.uid !== 0) return `${parent} belongs to uid ${s.uid}`;
    if ((s.mode & 0o022) !== 0 && !((s.mode & 0o1000) !== 0 && s.uid === 0)) return `${parent} is writable by others (mode ${(s.mode & 0o7777).toString(8)})`;
  }
  return undefined;
}

/** The socket directory must be this user's alone (no group or other bits), under directories only this user or root can change; created 0700 when missing. */
function checkSocketDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const s = lstatSync(dir);
  const uid = process.getuid?.();
  if (!s.isDirectory()) throw new Error(`irontrellis-hook daemon: ${dir} is not a directory`);
  if (uid !== undefined && s.uid !== uid) throw new Error(`irontrellis-hook daemon: ${dir} belongs to uid ${s.uid}, not this user (${uid})`);
  if ((s.mode & 0o077) !== 0) throw new Error(`irontrellis-hook daemon: ${dir} has mode ${(s.mode & 0o777).toString(8)}; it must be 700 (no group or other access)`);
  const unsafe = unsafeAncestor(dir, uid);
  if (unsafe !== undefined) throw new Error(`irontrellis-hook daemon: ${unsafe}, so another user could replace ${dir}; put the socket under directories only you (or root) can write (XDG_RUNTIME_DIR, or IRONTRELLISD_SOCKET on both sides; or create them with umask 022)`);
}

/** A socket at `path` that a live daemon answers on: true; a stale one (connection refused): false. */
const answering = (path: string): Promise<boolean> => new Promise((resolve) => {
  const probe = createConnection(path);
  probe.once("connect", () => { probe.destroy(); resolve(true); });
  probe.once("error", () => resolve(false));
});

export type Daemon = Readonly<{ server: Server; cache: OwnerCache; socketPath: string; stats: { answered: number; fallbacks: number }; close: () => Promise<void> }>;

/** Start serving on the Unix socket `socketPath`. Refuses a directory others can reach and a socket a live daemon holds. */
export async function startDaemon(socketPath: string): Promise<Daemon> {
  if (process.platform === "win32") throw new Error("irontrellis-hook daemon: Unix sockets only; not on Windows");
  checkSocketDir(dirname(socketPath));
  try {
    const s = lstatSync(socketPath);
    if (!s.isSocket() || s.uid !== process.getuid?.()) throw new Error(`irontrellis-hook daemon: ${socketPath} exists and is not this user's socket`);
    if (await answering(socketPath)) throw new Error(`irontrellis-hook daemon: a daemon already answers on ${socketPath}`);
    unlinkSync(socketPath); // a stale socket of an earlier daemon
  } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  const cache = new OwnerCache();
  const stats = { answered: 0, fallbacks: 0 };
  let queue: Promise<unknown> = Promise.resolve();
  const serve = (socket: Socket): void => {
    const chunks: Buffer[] = [];
    let size = 0, done = false;
    socket.setTimeout(30_000, () => socket.destroy());
    socket.on("error", () => { /* the client went away */ });
    socket.on("data", (chunk: Buffer) => {
      if (done) return;
      size += chunk.length;
      if (size > MAX_REQUEST_BYTES) { done = true; socket.end(`${JSON.stringify({ fallback: "REQUEST_TOO_LARGE" })}\n`); return; }
      chunks.push(chunk);
      if (chunk.indexOf(0x0a) === -1) return;
      done = true;
      const line = Buffer.concat(chunks).toString("utf8").split("\n", 1)[0]!;
      queue = queue.then(async () => {
        let reply: DaemonReply;
        try { reply = await answerRequest(cache, JSON.parse(line)); } catch { reply = { fallback: "DAEMON_ERROR" }; }
        if ("fallback" in reply) stats.fallbacks += 1; else stats.answered += 1;
        socket.end(`${JSON.stringify(reply)}\n`);
      });
    });
  };
  const server = createServer({ allowHalfOpen: false }, serve);
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(socketPath, () => resolve()); });
  chmodSync(socketPath, 0o600);
  const close = async (): Promise<void> => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await queue.catch(() => undefined);
    cache.close();
    try { unlinkSync(socketPath); } catch { /* gone */ }
  };
  return { server, cache, socketPath, stats, close };
}
