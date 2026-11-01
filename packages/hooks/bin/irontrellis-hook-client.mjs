#!/usr/bin/env node
// EXPERIMENTAL, opt-in: the thin client of the resident guard (`irontrellis-hook daemon`, src/daemon.ts). The same command
// line and standard input as `irontrellis-hook <agent> <event>`; it imports nothing from the engine, so a call costs a Node
// start and one socket round trip instead of a verifying open of the history.
//
// It never decides anything itself. Whenever the daemon cannot give the hook's answer (no socket; a socket or directory
// that is not this user's alone; a refused or broken connection; a timeout; a reply it cannot read; or the daemon's own
// "run the hook" answer) it runs this package's irontrellis-hook with the same arguments, standard input and environment,
// and exits with its code. A refusal the daemon recorded before failing is not recorded twice: its id comes from the host's
// tool-call id.
//
// IRONTRELLISD_SOCKET names the socket; the default is $XDG_RUNTIME_DIR/irontrellis/irontrellisd.sock, else
// <IRONTRELLIS_HOME, else ~/.irontrellis>/run/irontrellisd.sock.
import { connect } from "node:net";
import { lstatSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

/** The variables the hook reads (src/daemon.ts CLIENT_ENV; a test keeps the two lists equal): nothing else is sent. */
const CLIENT_ENV = Object.freeze([
  "CLAUDE_PROJECT_DIR", "CLAUDE_CONFIG_DIR", "CLAUDE_PLUGIN_ROOT", "CLAUDE_CODE_PLUGIN_CACHE_DIR", "CODEX_HOME", "HOME", "PATH", "SSH_AUTH_SOCK",
  "IRONTRELLIS_HOOK_CONFIG", "IRONTRELLIS_HOME", "IRONTRELLIS_WITNESS_POLICY", "IRONTRELLIS_CHALLENGE_PROFILE",
]);
const TIMEOUT_MS = 15_000;
const HOOK = join(dirname(fileURLToPath(import.meta.url)), "irontrellis-hook.mjs");

/** The daemon's rule (src/daemon.ts defaultSocketPath), applied to this process's environment. */
const socketPath = (env) => {
  if (env.IRONTRELLISD_SOCKET) return env.IRONTRELLISD_SOCKET;
  if (env.XDG_RUNTIME_DIR?.startsWith("/")) return join(env.XDG_RUNTIME_DIR, "irontrellis", "irontrellisd.sock");
  const home = env.IRONTRELLIS_HOME ? resolve(env.IRONTRELLIS_HOME) : join(homedir(), ".irontrellis");
  return join(home, "run", "irontrellisd.sock");
};
/**
 * The daemon's own rule (src/daemon.ts): the socket and its directory belong to this user, nobody else can reach the
 * directory, and every directory above it (symlinks resolved) is this user's or root's and writable by nobody else,
 * unless it is root's and sticky (/tmp).
 */
const trusted = (path) => {
  const uid = process.getuid?.();
  try {
    const dir = lstatSync(dirname(path)), socket = lstatSync(path);
    if (uid === undefined || !dir.isDirectory() || dir.uid !== uid || (dir.mode & 0o077) !== 0 || !socket.isSocket() || socket.uid !== uid) return false;
    let at = realpathSync(dirname(path));
    for (let parent = dirname(at); parent !== at; at = parent, parent = dirname(at)) {
      const s = statSync(parent);
      if (s.uid !== uid && s.uid !== 0) return false;
      if ((s.mode & 0o022) !== 0 && !((s.mode & 0o1000) !== 0 && s.uid === 0)) return false;
    }
    return true;
  } catch { return false; }
};

async function main() {
  const [agent, event] = process.argv.slice(2);
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const stdin = Buffer.concat(chunks);
  const runHook = () => {
    const r = spawnSync(process.execPath, [HOOK, ...process.argv.slice(2)], { input: stdin, stdio: ["pipe", "inherit", "inherit"], env: process.env });
    process.exitCode = r.status ?? 2;
  };
  const path = socketPath(process.env);
  if (agent === undefined || event === undefined || !trusted(path)) return runHook();
  const env = {};
  for (const name of CLIENT_ENV) if (process.env[name] !== undefined) env[name] = process.env[name];
  const reply = await new Promise((done) => {
    let text = "", settled = false;
    const finish = (value) => { if (!settled) { settled = true; socket.destroy(); done(value); } };
    const socket = connect(path);
    socket.setEncoding("utf8");
    socket.setTimeout(TIMEOUT_MS, () => finish(undefined));
    socket.on("connect", () => socket.write(`${JSON.stringify({ v: 1, protocol: agent, event, stdin: stdin.toString("utf8"), env, cwd: process.cwd() })}\n`));
    socket.on("data", (d) => { text += d; });
    socket.on("error", () => finish(undefined));
    socket.on("end", () => { try { finish(JSON.parse(text)); } catch { finish(undefined); } });
  });
  const answered = reply !== null && typeof reply === "object" && typeof reply.stdout === "string" && typeof reply.stderr === "string" && Number.isInteger(reply.exitCode);
  if (!answered) return runHook();
  if (reply.stdout !== "") process.stdout.write(reply.stdout);
  if (reply.stderr !== "") process.stderr.write(reply.stderr);
  process.exitCode = reply.exitCode;
}

await main();
