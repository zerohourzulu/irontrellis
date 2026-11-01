/**
 * The resident guard (EXPERIMENTAL, src/daemon.ts) against the hook, as a release gate: one sequence of host events played
 * through `irontrellis-hook <agent> <event>` and through `irontrellis-hook-client <agent> <event>` with a running daemon,
 * each pass from the same saved project and state, must give the same replies byte for byte (stdout, stderr, exit code),
 * and the daemon must have answered them itself (not sent them back to the hook). The sequence covers allow, deny and
 * ask; the protective rules; malformed input; owner changes made outside the guard (a grant, a revoke, a large grant set
 * past the evidence bound); a file tool's path that is not a string; an anchor log that cannot be read under failOpen; a
 * second host; and an unknown agent (sent back to the hook by design). Build first (pnpm -r build): the bins run dist/.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { openLocalOwner } from "@ramex-labs/irontrellis";
import { CLIENT_ENV, startDaemon } from "../dist/daemon.js";

const BIN = resolve(fileURLToPath(new URL("../bin/irontrellis-hook.mjs", import.meta.url)));
const CLIENT = resolve(fileURLToPath(new URL("../bin/irontrellis-hook-client.mjs", import.meta.url)));
const C_CLIENT = resolve(fileURLToPath(new URL("../contrib/irontrellis-hook-client.c", import.meta.url)));
/** A compiled contrib/irontrellis-hook-client.c, when the gate built one: the agreement test then plays a third pass through it. */
const C_BINARY = process.env.IRONTRELLIS_TEST_C_CLIENT;
const DAY = 86_400_000;
const RISK = "--i-understand-same-user-risk";
const unix = process.platform !== "win32";

/**
 * A short directory for the socket (Unix socket paths are limited to about 100 bytes), under directories only this user
 * or root can write, as the daemon requires: /tmp on Linux (a test runner's TMPDIR may sit under group-writable
 * directories), the per-user temporary directory elsewhere.
 */
const socketDir = (t) => {
  let base = mkdtempSync(process.platform === "linux" ? "/tmp/itd-" : join(tmpdir(), "itd-"));
  if (base.length > 80) { rmSync(base, { recursive: true, force: true }); base = mkdtempSync("/tmp/itd-"); }
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const dir = join(base, "run");
  mkdirSync(dir, { mode: 0o700 });
  return dir;
};
const startChild = (env, socket) => new Promise((resolveStart, reject) => {
  const child = spawn(process.execPath, [BIN, "daemon", "--socket", socket], { env, stdio: ["ignore", "pipe", "pipe"] });
  let out = "", err = "";
  child.stdout.on("data", (d) => { out += d; if (out.includes("listening")) resolveStart({ child, stderr: () => err }); });
  child.stderr.on("data", (d) => { err += d; });
  child.once("exit", (code) => reject(new Error(`daemon exited ${code}: ${out}${err}`)));
});
const stopChild = ({ child, stderr }) => new Promise((done) => { child.removeAllListeners("exit"); child.once("exit", () => done(stderr())); child.kill("SIGTERM"); });

test("both clients' lists of variables are the daemon's (CLIENT_ENV)", () => {
  for (const [file, start, end] of [[CLIENT, "const CLIENT_ENV", "]);"], [C_CLIENT, "CLIENT_ENV[] = {", "};"]]) {
    const text = readFileSync(file, "utf8"), at = text.indexOf(start);
    assert.ok(at >= 0, file);
    assert.deepEqual([...text.slice(at, text.indexOf(end, at)).matchAll(/"([A-Z_]+)"/g)].map((m) => m[1]), [...CLIENT_ENV], file);
  }
});

test("startDaemon refuses a socket directory others can reach, and a socket a live daemon already answers on", { skip: !unix }, async (t) => {
  const dir = socketDir(t);
  chmodSync(dir, 0o755);
  await assert.rejects(startDaemon(join(dir, "s.sock")), /must be 700/);
  chmodSync(dir, 0o700);
  const first = await startDaemon(join(dir, "s.sock"));
  t.after(() => first.close());
  await assert.rejects(startDaemon(join(dir, "s.sock")), /already answers/);
});

test("a socket directory under a directory others can write: the daemon refuses it, and a client finding one turns to the hook", { skip: !unix || process.getuid?.() === 0 }, async (t) => {
  const dir = socketDir(t), parent = join(dir, "..");
  const daemon = await startDaemon(join(dir, "s.sock"));
  t.after(() => daemon.close());
  const env = { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: process.env.HOME ?? "/", NO_COLOR: "1", IRONTRELLISD_SOCKET: join(dir, "s.sock") };
  // Asynchronous, so this process's daemon could answer if the client (wrongly) connected.
  const client = () => new Promise((done) => {
    const c = spawn(process.execPath, [CLIENT, "claude-code", "PreToolUse"], { env, stdio: ["pipe", "pipe", "pipe"] });
    let stderr = "";
    c.stderr.on("data", (d) => { stderr += d; });
    c.once("exit", (status) => done({ status, stderr }));
    c.stdin.end("not json");
  });
  const trustedRun = await client();
  assert.equal(trustedRun.status, 2);
  assert.equal(daemon.stats.answered, 1, "a safe directory: the daemon answers");
  chmodSync(parent, 0o777);
  try {
    const unsafeRun = await client();
    assert.deepEqual([unsafeRun.status, unsafeRun.stderr], [trustedRun.status, trustedRun.stderr], "the hook's own answer");
    assert.equal(daemon.stats.answered, 1, "the client did not use the daemon");
    await assert.rejects(startDaemon(join(dir, "t.sock")), /is writable by others \(mode 777\)/);
  } finally { chmodSync(parent, 0o700); }
});

test("agreement (release gate): the daemon answers a host-event sequence byte for byte as the hook does, from the same saved state", { skip: !unix }, async (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "irontrellis-daemon-")));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const project = join(root, "app"), state = join(root, "state");
  mkdirSync(project); mkdirSync(state);
  const socket = join(socketDir(t), "irontrellisd.sock");
  const env = { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: process.env.HOME ?? root, NO_COLOR: "1", IRONTRELLIS_HOME: state, CLAUDE_PROJECT_DIR: project, IRONTRELLISD_SOCKET: socket };
  const cli = (args) => spawnSync(process.execPath, [BIN, ...args], { cwd: project, env, encoding: "utf8" });
  assert.equal(cli(["init", "--allow", "run-shell", "--expires", "+1d", RISK]).status, 0);
  const config = JSON.parse(readFileSync(join(project, "irontrellis-hook.json"), "utf8"));
  const history = resolve(project, config.history);
  const ownerOf = () => openLocalOwner({ historyFile: history, domain: config.domain, owner: config.owner, controller: config.controller, now: () => Date.now() });
  const base = { session_id: "cc-1", transcript_path: `${project}/.claude/t.jsonl`, cwd: project, permission_mode: "default" };
  assert.equal(spawnSync(process.execPath, [BIN, "claude-code", "SessionStart"], { cwd: project, env, input: JSON.stringify({ ...base, hook_event_name: "SessionStart", source: "startup" }), encoding: "utf8" }).status, 0);
  const saved = join(root, "saved");
  cpSync(project, join(saved, "app"), { recursive: true }); cpSync(state, join(saved, "state"), { recursive: true });
  const restore = () => {
    rmSync(project, { recursive: true, force: true }); rmSync(state, { recursive: true, force: true });
    cpSync(join(saved, "app"), project, { recursive: true }); cpSync(join(saved, "state"), state, { recursive: true });
  };
  let n = 0;
  const tool = (tool_name, tool_input, session = "cc-1") => ["claude-code", "PreToolUse", JSON.stringify({ ...base, session_id: session, hook_event_name: "PreToolUse", tool_name, tool_input, tool_use_id: `toolu_${(n += 1)}` })];
  // The sequence: [agent, event, stdin] calls, with owner changes between them (made outside the guard, alike in both passes).
  const sequence = async (call) => {
    n = 0;
    const r = [];
    const play = (agent, event, stdin) => r.push(call(agent, event, stdin));
    play(...tool("Bash", { command: "ls" }));                                                 // ALLOW: no decision
    play(...tool("Read", { file_path: `${project}/a.txt` }));                                  // read-only
    play(...tool("Deploy", { target: "prod" }));                                               // unmapped: ask
    play(...tool("Write", { file_path: history, content: "" }));                               // protective: the history
    play(...tool("Write", { file_path: join(project, "irontrellis-hook.json"), content: "{}" })); // protective: the config
    play(...tool("Bash", { command: "irontrellis grant g --to claude-code --actions write-file" })); // protective: a control command
    play(...tool("Write", { file_path: [join(project, ".claude", "settings.json")], content: "{}" })); // a path that is not a string
    play(...tool("Write", { file_path: `${project}/a.txt`, content: "x" }));                    // no grant: DENY
    play(...tool("Bash", { command: "ls" }, "cc-unknown"));                                    // no session
    play("claude-code", "PreToolUse", "not json");
    play("claude-code", "PreToolUse", "");
    play("claude-code", "PreToolUse", "[1,2]");
    play("claude-code", "PreToolUse", JSON.stringify({ ...base, hook_event_name: "PreToolUse", tool_input: {} }));
    play("codex", "PreToolUse", JSON.stringify({ session_id: "thr-1", cwd: project, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, tool_use_id: "call_1" }));
    play("gemini", "PreToolUse", "{}");                                                        // unknown agent: the hook's own answer
    let owner = ownerOf();
    await owner.grant({ id: "grant:write", to: "claude-code", actions: ["write-file"], resources: [`repo:${project}`], expiresAt: Date.now() + DAY });
    play(...tool("Write", { file_path: `${project}/a.txt`, content: "x" }));                    // granted outside the guard: ALLOW
    await owner.revoke("grant:write");
    play(...tool("Write", { file_path: `${project}/a.txt`, content: "x" }));                    // revoked: DENY REVOKED
    owner = ownerOf();
    for (let i = 0; i < 80; i += 1) await owner.grant({ id: `grant:server-${i}`, to: "claude-code", actions: ["call-mcp"], resources: [`mcp:server-${i}`], expiresAt: Date.now() + DAY });
    play(...tool("mcp__github__create_issue", { title: "x" }));                                 // past the evidence bound: refused, recorded
    play(...tool("Bash", { command: "ls" }));                                                 // still ALLOW on the large grant set
    writeFileSync(join(project, "irontrellis-hook.json"), JSON.stringify({ ...config, failOpen: true }));
    writeFileSync(`${history}.anchors`, "not an anchor log entry\n");
    play(...tool("Bash", { command: "ls" }));                                                 // a finding: refused even with failOpen
    play("claude-code", "SessionEnd", JSON.stringify({ ...base, hook_event_name: "SessionEnd", reason: "other" }));
    return r;
  };
  const run = (command) => (agent, event, stdin) => {
    const x = spawnSync(command[0], [...command.slice(1), agent, event], { cwd: project, env: { ...env, IRONTRELLISD_FALLBACK: BIN }, input: stdin, encoding: "utf8" });
    return { agent, event, status: x.status, stdout: x.stdout, stderr: x.stderr };
  };
  const viaHook = await sequence(run([process.execPath, BIN]));
  const through = async (command) => {
    restore();
    const daemon = await startChild(env, socket);
    let replies, stopped;
    try { replies = await sequence(run(command)); } finally { stopped = await stopChild(daemon); }
    return { replies, stopped };
  };
  const { replies: viaDaemon, stopped } = await through([process.execPath, CLIENT]);
  assert.equal(viaDaemon.length, viaHook.length);
  for (let i = 0; i < viaHook.length; i += 1) assert.deepEqual(viaDaemon[i], viaHook[i], `call ${i + 1} (${viaHook[i].agent} ${viaHook[i].event})`);
  if (C_BINARY !== undefined && C_BINARY !== "") {
    const viaC = await through([C_BINARY]);
    for (let i = 0; i < viaHook.length; i += 1) assert.deepEqual(viaC.replies[i], viaHook[i], `C client, call ${i + 1} (${viaHook[i].agent} ${viaHook[i].event})`);
    assert.match(viaC.stopped, new RegExp(`stopped \\(${viaHook.length - 1} answered, 1 sent to the hook;`), viaC.stopped);
  }
  // The replies cover what the sequence means to show (so a hook change cannot make the comparison vacuous).
  const codes = viaHook.map((r) => r.status);
  assert.ok(codes.filter((c) => c === 2).length >= 8, `refusals: ${codes}`);
  assert.match(viaHook[6].stderr, /file_path is not a string/);
  assert.match(viaHook[17].stderr, /OUTPUT_LIMIT_EXCEEDED; INDETERMINATE/);
  assert.match(viaHook[19].stderr, /ANCHOR_LOG_UNREADABLE/);
  // The daemon answered every call itself but the unknown agent's, which it sends back to the hook.
  assert.match(stopped, new RegExp(`stopped \\(${viaHook.length - 1} answered, 1 sent to the hook;`), stopped);
  assert.equal(existsSync(socket), false, "the socket is removed at stop");
});

test("with no daemon the client is the hook: the same reply, through the hook", { skip: !unix }, (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "irontrellis-daemon-none-")));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const env = { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: root, NO_COLOR: "1", IRONTRELLIS_HOME: join(root, "state"), IRONTRELLISD_SOCKET: join(root, "missing", "s.sock") };
  for (const program of [BIN, CLIENT]) {
    const r = spawnSync(process.execPath, [program, "claude-code", "PreToolUse"], { cwd: root, env, input: "not json", encoding: "utf8" });
    assert.equal(r.status, 2, `${program}: ${r.stderr}`);
  }
  const hook = spawnSync(process.execPath, [BIN, "--version"], { env, encoding: "utf8" }), client = spawnSync(process.execPath, [CLIENT, "--version"], { env, encoding: "utf8" });
  assert.deepEqual([client.status, client.stdout], [hook.status, hook.stdout]);
});
