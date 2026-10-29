/**
 * The two Claude Code install routes of one guard (src/route.ts; founder 4bu; the coordinator's design OK of 2026-10-23):
 * the plugin's entry point `irontrellis-hook plugin claude-code <event>` and its launcher, the route states and their
 * precedence, the choice the user makes, the guard's protection of its own switches, and two copies of the guard running
 * the same events. Every run has its own HOME (the user's Claude settings), IRONTRELLIS_HOME (the choice file) and PATH.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, renameSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { openHistoryStore } from "@ramex-labs/irontrellis";
import { HOOK_WRAPPER, codexHooksSetting, hookEntryProgram } from "../dist/index.js";

const BIN = resolve(fileURLToPath(new URL("../bin/irontrellis-hook.mjs", import.meta.url)));
const PLUGIN = resolve(fileURLToPath(new URL("../../../plugins/irontrellis", import.meta.url)));
const LAUNCH = join(PLUGIN, "scripts", "launch.sh");
const RISK = "--i-understand-same-user-risk";
const fresh = (prefix) => realpathSync(mkdtempSync(join(tmpdir(), prefix)));

/** A sandbox: a home (with .claude), a state home, a bin directory on PATH holding `irontrellis-hook` → BIN, and a project. */
function sandbox() {
  const root = fresh("irontrellis-route-"), home = join(root, "home"), state = join(root, "state"), bin = join(root, "bin"), project = join(root, "project");
  for (const d of [home, state, bin, project]) mkdirSync(d, { recursive: true });
  symlinkSync(BIN, join(bin, "irontrellis-hook"));
  const env = { HOME: home, IRONTRELLIS_HOME: state, PATH: `${bin}${delimiter}${dirname(process.execPath)}${delimiter}/usr/bin${delimiter}/bin`, CLAUDE_PROJECT_DIR: project, NO_COLOR: "1" };
  const run = (args, { stdin = "", cwd = project, extra = {} } = {}) => {
    const r = spawnSync(process.execPath, [BIN, ...args], { cwd, input: stdin, encoding: "utf8", env: { ...env, ...extra } });
    let json; try { json = r.stdout.trim() === "" ? undefined : JSON.parse(r.stdout); } catch { json = undefined; }
    return claudeDeny(args, { code: r.status, stdout: r.stdout, stderr: r.stderr, json });
  };
  const runAsync = (args, stdin) => new Promise((done) => {
    const child = spawn(process.execPath, [BIN, ...args], { cwd: project, env, stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "", stderr = ""; child.stdout.on("data", (d) => { stdout += d; }); child.stderr.on("data", (d) => { stderr += d; });
    child.on("close", (code) => done({ code, stdout, stderr })); child.stdin.end(stdin);
  });
  const plugin = (event, payload, extra) => run(["plugin", "claude-code", event], { stdin: JSON.stringify(payload), extra });
  const hook = (event, payload) => run(["claude-code", event], { stdin: JSON.stringify(payload) });
  const init = (allow) => { const r = run(["init", "--agent", "claude-code", RISK, ...(allow === undefined ? [] : ["--allow", allow, "--expires", "+1d"])]); assert.equal(r.code, 0, r.stderr); return r; };
  const settings = (file, doc) => { mkdirSync(dirname(file), { recursive: true }); writeFileSync(file, `${JSON.stringify(doc, null, 2)}\n`); };
  return { root, home, state, bin, project, env, run, runAsync, plugin, hook, init, settings, choiceFile: join(state, "route-choices.json") };
}
/**
 * A Claude Code PreToolUse deny, on either route, is exit 2 with the reason on stderr and nothing on stdout (the
 * coordinator's GO for proposal A): such a reply is given the deny's JSON shape so the checks below
 * read it alike, and a deny that comes back as JSON, or at exit 0, fails at once.
 */
function claudeDeny(args, r) {
  const at = args.indexOf("claude-code");
  if (at < 0 || args[at + 1] !== "PreToolUse") return r;
  assert.notEqual(r.json?.hookSpecificOutput?.permissionDecision, "deny", `a Claude Code deny must be exit 2, not JSON: ${r.stdout}`);
  if (r.code !== 2 || r.stdout !== "") return r;
  assert.match(r.stderr, /^\nIronTrellis · DENY: /, "a Claude Code deny's stderr starts with a newline (its own line under Claude Code's label), then the state word");
  return { ...r, json: { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: r.stderr.slice(1).split("\n")[0] } } };
}
const ev = {
  start: (s, session = "cc-1", source = "startup") => ({ session_id: session, cwd: s.project, hook_event_name: "SessionStart", source }),
  tool: (s, tool_name, tool_input, session = "cc-1", tool_use_id = "toolu_1") => ({ session_id: session, cwd: s.project, hook_event_name: "PreToolUse", tool_name, tool_input, tool_use_id }),
  stop: (s, session = "cc-1") => ({ session_id: session, cwd: s.project, hook_event_name: "Stop", stop_hook_active: false }),
};
const decision = (r) => r.json?.hookSpecificOutput?.permissionDecision;
const assertDeny = (r, why) => { assert.equal(r.code, 2, `exit 2: ${r.stdout}${r.stderr}`); assert.equal(r.stdout, ""); assert.equal(decision(r), "deny", r.stdout + r.stderr); if (why !== undefined) assert.match(r.json.hookSpecificOutput.permissionDecisionReason, why); };
const assertQuiet = (r) => { assert.equal(r.code, 0, r.stderr); assert.equal(r.stdout, "", r.stdout); };
const historyOf = (s) => resolve(s.project, JSON.parse(readFileSync(join(s.project, "irontrellis-hook.json"), "utf8")).history);
const typesOf = (s) => openHistoryStore(historyOf(s)).state().events.map((e) => e.type);

// ---------------------------------------------------------------- states A and B

test("undecided: a notice at each session start (startup, resume, clear; not after a compaction), tool calls left to the host, and the agent cannot choose or set up", () => {
  const s = sandbox();
  const start = s.plugin("SessionStart", ev.start(s));
  assert.equal(start.code, 0);
  // RA-05: resume and clear show it again, as the docs now say.
  for (const source of ["resume", "clear"]) assert.match(s.plugin("SessionStart", ev.start(s, "cc-1", source)).json.systemMessage, /Choose one/, source);
  assert.match(start.json.systemMessage, /not set up here\. Choose one: type it here with the `!` prefix, or run it in your own terminal:/);
  assert.match(start.json.systemMessage, /1\. ! irontrellis-hook choose 1 +proceed without IronTrellis/);
  assert.match(start.json.systemMessage, /2\. ! irontrellis-hook choose 2 +set IronTrellis up here \(the plugin route/);
  assert.match(start.json.systemMessage, /3\. ! irontrellis-hook choose 3 +use the hook route/);
  assert.match(start.json.systemMessage, /`! irontrellis-hook choose --status`/);
  // The agent is told what to say if the session ends with no choice (founder's live check 01), and not to choose itself.
  const context = start.json.hookSpecificOutput.additionalContext;
  assert.match(context, /^The user has been told: IronTrellis is enabled for /);
  assert.match(context, /Only the user may make this choice: do not run `irontrellis-hook choose`, `init` or `pin-runtime` yourself/);
  assert.match(context, /Your choice about IronTrellis for this project hasn't been made yet, so you'll see this setup prompt next time, unless you run `! irontrellis-hook choose 1` \(or 2 or 3\)\./);
  assertQuiet(s.plugin("SessionStart", ev.start(s, "cc-1", "compact")));
  assertQuiet(s.plugin("PreToolUse", ev.tool(s, "Write", { file_path: join(s.project, "a.txt"), content: "x" })));
  assertQuiet(s.plugin("PreToolUse", ev.tool(s, "Bash", { command: "ls -la" })));
  assertDeny(s.plugin("PreToolUse", ev.tool(s, "Bash", { command: "irontrellis-hook choose --decline" })),
    /^IronTrellis · DENY: installation policy: only you, the human operator, may choose whether this project uses IronTrellis; I, the agent, am not allowed to run `irontrellis-hook choose`\. You can run it yourself: in Claude Code, type it with the `!` prefix, for example `! irontrellis-hook choose 1` .*Your choice is saved for this project\.$/);
  assertDeny(s.plugin("PreToolUse", ev.tool(s, "Bash", { command: "irontrellis-hook choose 2" })), /not allowed to run `irontrellis-hook choose`/);
  assertDeny(s.plugin("PreToolUse", ev.tool(s, "Bash", { command: "irontrellis-hook init --agent claude-code" })), /^IronTrellis · DENY: installation policy: .*not allowed to run `irontrellis-hook init`\. .*`! irontrellis-hook choose 2` sets up the plugin route/);
  assert.doesNotMatch(s.plugin("PreToolUse", ev.tool(s, "Bash", { command: "irontrellis-hook choose 1" })).stdout, /history/, "the choice is not said to go into the history");
  assertDeny(s.plugin("PreToolUse", ev.tool(s, "Write", { file_path: s.choiceFile, content: "{}" })), /route choice is the user's/);
  assertDeny(s.plugin("PreToolUse", ev.tool(s, "Bash", { command: `echo '{}' > ${s.choiceFile}` })), /route choice is the user's/);
  assertQuiet(s.plugin("Stop", ev.stop(s)));
  assert.equal(existsSync(s.choiceFile), false);
});

test("declined: recorded per user (0600), silent, still refuses the agent's choice; reset returns to undecided; a corrupt choice file reads as no choice", () => {
  const s = sandbox();
  const chosen = s.run(["choose", "--decline"]);
  assert.equal(chosen.code, 0, chosen.stderr);
  assert.equal(statSync(s.choiceFile).mode & 0o777, 0o600);
  assert.equal(JSON.parse(readFileSync(s.choiceFile, "utf8")).projects[s.project].choice, "declined");
  assert.match(s.run(["choose", "--status"]).stdout, /route:\s+declined/);
  assertQuiet(s.plugin("SessionStart", ev.start(s)));
  assertQuiet(s.plugin("PreToolUse", ev.tool(s, "Write", { file_path: join(s.project, "a.txt"), content: "x" })));
  assertDeny(s.plugin("PreToolUse", ev.tool(s, "Bash", { command: "irontrellis-hook choose --reset" })));
  assert.equal(s.run(["choose", "--reset"]).code, 0);
  assert.match(s.plugin("SessionStart", ev.start(s)).json.systemMessage, /Choose one/);
  writeFileSync(s.choiceFile, "not json", { mode: 0o600 });
  assert.match(s.run(["choose", "--status"]).stdout, /choice:\s+none .*unreadable/);
  assert.equal(s.run(["choose"]).code, 1, "exactly one flag");
});

// ---------------------------------------------------------------- precedence: D/E > C > B > A

test("precedence: a decline is refused for a configured project, and a decline planted for it leaves the guard running", () => {
  const s = sandbox();
  s.init();
  const refused = s.run(["choose", "--decline"]);
  assert.equal(refused.code, 1);
  assert.match(refused.stderr, /is set up \(plugin\); a choice applies only to a project without IronTrellis/);
  writeFileSync(s.choiceFile, JSON.stringify({ version: "irontrellis-route-choice/1", projects: { [s.project]: { choice: "declined", at: "2026-10-23T00:00:00.000Z" } } }), { mode: 0o600 });
  assert.match(s.run(["choose", "--status"]).stdout, /route:\s+plugin/);
  s.plugin("SessionStart", ev.start(s));
  assertDeny(s.plugin("PreToolUse", ev.tool(s, "Bash", { command: "ls" })), /IronTrellis · DENY/);
});

test("a verified hook route makes the plugin step aside; with the plugin enabled too, the hook warns once at session start", () => {
  const s = sandbox();
  s.init();
  const installed = s.run(["install", "claude-code", "--write"]);
  assert.equal(installed.code, 0, installed.stderr);
  assert.match(s.run(["choose", "--status"]).stdout, /route:\s+hook \(verified hook entries/);
  assertQuiet(s.plugin("SessionStart", ev.start(s)));
  assertQuiet(s.plugin("PreToolUse", ev.tool(s, "Bash", { command: "ls" })));
  s.settings(join(s.home, ".claude", "settings.json"), { enabledPlugins: { "irontrellis@irontrellis": true } });
  assert.match(s.run(["choose", "--status"]).stdout, /route:\s+both/);
  assert.match(s.hook("SessionStart", ev.start(s, "cc-2")).json.systemMessage, /the IronTrellis plugin for Claude Code \(`irontrellis` in \/plugin\) is also enabled here; it is stepping aside/);
  assertQuiet(s.plugin("PreToolUse", ev.tool(s, "Bash", { command: "ls" }, "cc-2")));
  // install itself says so when the plugin is enabled
  assert.match(s.run(["install", "claude-code", "--dry-run"]).stderr, /the IronTrellis plugin for Claude Code \(`irontrellis` in \/plugin\) is enabled for this project too/);
});

test("a planted look-alike hook entry is not a hook route: the plugin keeps guarding and status names the entry", () => {
  const s = sandbox();
  s.init();
  const fake = join(s.root, "fake"); mkdirSync(fake);
  writeFileSync(join(fake, "irontrellis-hook"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
  const entry = (event, timeout, command) => [{ hooks: [{ type: "command", command, timeout }] }];
  const settingsFile = join(s.project, ".claude", "settings.json");
  // a different program named irontrellis-hook, a no-op mentioning it, and one event missing
  s.settings(settingsFile, { hooks: {
    SessionStart: entry("SessionStart", 30, `${join(fake, "irontrellis-hook")} claude-code SessionStart`),
    PreToolUse: entry("PreToolUse", 30, "true # irontrellis-hook claude-code PreToolUse"),
    Stop: entry("Stop", 30, "irontrellis-hook claude-code Stop"),
  } });
  const status = s.run(["choose", "--status"]).stdout;
  assert.match(status, /route:\s+plugin/);
  assert.match(status, /unrecognized IronTrellis hook entry: .*SessionStart/);
  assert.match(status, /unrecognized IronTrellis hook entry: .*PreToolUse/);
  s.plugin("SessionStart", ev.start(s));
  assertDeny(s.plugin("PreToolUse", ev.tool(s, "Bash", { command: "ls" })), /IronTrellis · DENY/);
});

test("the verified route is exactly what install writes: /bin/sh, the wrapper, absolute node and launcher, install's keys; async, an extra key, shell characters or an older form is not", () => {
  const s = sandbox();
  s.init();
  assert.equal(s.run(["install", "claude-code", "--write"]).code, 0);
  const file = join(s.project, ".claude", "settings.json"), written = JSON.parse(readFileSync(file, "utf8"));
  const command = written.hooks.PreToolUse[0].hooks[0].command;
  const form = /^\/bin\/sh -c '(.+)' (\/\S*node) (\/\S*\/bin\/irontrellis-hook\.mjs) claude-code PreToolUse$/.exec(command);
  assert.ok(form !== null, command);
  assert.equal(form[1], HOOK_WRAPPER); assert.equal(realpathSync(form[3]), realpathSync(BIN));
  assert.match(s.run(["choose", "--status"]).stdout, /route:\s+hook/);
  const variant = (change) => { const doc = structuredClone(written); change(doc); s.settings(file, doc); return s.run(["choose", "--status"]).stdout; };
  assert.match(variant((d) => { d.hooks.PreToolUse[0].hooks[0].async = true; }), /route:\s+plugin/, "async: true");
  // post5-11 (KI 61): install's PreToolUse entry carries "onFailure": "block", and only that one.
  assert.deepEqual(Object.fromEntries(Object.entries(written.hooks).map(([e, g]) => [e, g[0].hooks[0].onFailure ?? null])), { SessionStart: null, PreToolUse: "block", Stop: null, SessionEnd: null });
  assert.match(variant((d) => { delete d.hooks.PreToolUse[0].hooks[0].onFailure; }), /route:\s+plugin/, "PreToolUse without onFailure (a timeout would not block)");
  assert.match(variant((d) => { d.hooks.PreToolUse[0].hooks[0].onFailure = "continue"; }), /route:\s+plugin/, "onFailure continue");
  assert.match(variant((d) => { d.hooks.Stop[0].hooks[0].onFailure = "block"; }), /route:\s+plugin/, "onFailure on another event");
  assert.match(variant((d) => { d.hooks.Stop[0].hooks[0].statusMessage = "x"; }), /route:\s+plugin/, "an extra handler key");
  assert.match(variant((d) => { d.hooks.SessionEnd[0].description = "x"; }), /route:\s+plugin/, "an extra group key");
  assert.match(variant((d) => { d.hooks.SessionStart[0].hooks[0].command = "irontrellis-hook claude-code SessionStart"; }), /route:\s+plugin/, "the old bare command");
  assert.match(variant((d) => { d.hooks.SessionStart[0].hooks[0].command = `${form[2]} ${form[3]} claude-code SessionStart`; }), /route:\s+plugin/, "3e3cf1d's form without the wrapper");
  for (const node of ["/tmp/$HOME/node", "/tmp/`id`/node", "/tmp/a;b/node"]) {
    assert.match(variant((d) => { d.hooks.PreToolUse[0].hooks[0].command = `${hookEntryProgram(node, form[3])} claude-code PreToolUse`; }), /route:\s+plugin/, node);
  }
  assert.match(variant((d) => { d.hooks.PreToolUse[0].hooks[0].command = command.replace("' /", "'  /"); }), /route:\s+plugin/, "any other spacing");
  // install rewrites the old bare command to the absolute form.
  assert.equal(s.run(["install", "claude-code", "--write"]).code, 0);
  assert.match(s.run(["choose", "--status"]).stdout, /route:\s+hook/);
});

// ---------------------------------------------------------------- what the guard protects in a set-up project

/** A guarded sandbox and a PreToolUse caller with CLAUDE_CONFIG_DIR and CLAUDE_PLUGIN_ROOT set; each call has its own tool-use id. */
function guarded(allow = "write-file,run-shell") {
  const s = sandbox();
  s.init(allow);
  const config = join(s.root, "claude-config"), pluginRoot = join(s.root, "plugin-root");
  mkdirSync(config, { recursive: true }); mkdirSync(join(pluginRoot, "scripts"), { recursive: true });
  writeFileSync(join(pluginRoot, "scripts", "launch.sh"), "# the launcher\n");
  const extra = { CLAUDE_CONFIG_DIR: config, CLAUDE_PLUGIN_ROOT: pluginRoot };
  let n = 0;
  const call = (tool, input, more = {}, how = ["claude-code", "PreToolUse"]) => s.run(how, { stdin: JSON.stringify(ev.tool(s, tool, input, "cc-1", `toolu_p${++n}`)), extra: { ...extra, ...more } });
  const denied = (tool, input, label, more) => { const r = call(tool, input, more); assert.equal(decision(r), "deny", `${label}: ${r.stdout}${r.stderr}`); assert.match(r.json.hookSpecificOutput.permissionDecisionReason, /protected/, label); };
  const notProtected = (tool, input, label, more) => { const r = call(tool, input, more); assert.doesNotMatch(r.stdout + r.stderr, /protected/, label); };
  s.run(["claude-code", "SessionStart"], { stdin: JSON.stringify(ev.start(s)), extra });
  return { ...s, config, pluginRoot, extra, call, denied, notProtected };
}

test("IronTrellis's own state, one path at a time: the config (also by IRONTRELLIS_HOOK_CONFIG), the choice file, the runtime pin, session keys, the owner key", () => {
  const s = guarded();
  const config = join(s.project, "irontrellis-hook.json");
  s.denied("Write", { file_path: config, content: "{}" }, "the config");
  s.denied("Bash", { command: `rm ${config}` }, "rm the config");
  s.denied("Delete", { path: config }, "Delete the config");
  s.denied("Write", { file_path: s.choiceFile, content: "{}" }, "the choice file");
  s.denied("Write", { file_path: join(s.state, "plugin-runtime"), content: "/tmp/node\n/tmp/x\n" }, "the runtime pin");
  s.denied("Write", { file_path: join(`${historyOf(s)}.sessions`, "x.json"), content: "{}" }, "session keys");
  s.denied("Write", { file_path: `${historyOf(s)}.owner-key.json`, content: "{}" }, "the owner key");
  assertDeny(s.call("Bash", { command: "irontrellis-hook pin-runtime" }), /^IronTrellis · DENY: installation policy: only you, the human operator, may set IronTrellis up; I, the agent, am not allowed to run `irontrellis-hook pin-runtime`\. .*`! irontrellis-hook pin-runtime`.* \(PROTECTED_COMMAND\)$/);
  assertDeny(s.call("Bash", { command: "irontrellis-hook choose 1" }), /^IronTrellis · DENY: installation policy: .*`irontrellis-hook choose`.*\(PROTECTED_COMMAND\)$/);
  assertDeny(s.call("Bash", { command: "irontrellis grant x --to y" }), /^IronTrellis · DENY: protected: IronTrellis control commands are for the operator, not the agent \(irontrellis grant\) \(PROTECTED_COMMAND\)$/);
  // The config named by IRONTRELLIS_HOOK_CONFIG (elsewhere) is protected at its own path.
  const elsewhere = join(s.root, "elsewhere.json"); cpSync(config, elsewhere);
  s.denied("Write", { file_path: elsewhere, content: "{}" }, "the IRONTRELLIS_HOOK_CONFIG target", { IRONTRELLIS_HOOK_CONFIG: elsewhere });
  // init wrote the plugin's runtime pin: this node and the launcher's real path, 0600.
  const pin = readFileSync(join(s.state, "plugin-runtime"), "utf8").split("\n");
  assert.equal(realpathSync(pin[0]), realpathSync(process.execPath)); assert.equal(pin[1], realpathSync(BIN));
  assert.equal(statSync(join(s.state, "plugin-runtime")).mode & 0o777, 0o600);
});

test("Claude Code's configuration, whole: settings files, .claude.json, .mcp.json, the .claude trees, plugins, the guard's packages, interpreter and launcher; parents too", async () => {
  const s = guarded();
  const local = join(s.project, ".claude", "settings.local.json"), project = join(s.project, ".claude", "settings.json");
  s.settings(project, { permissions: { allow: [] } });
  // (i) whole settings files, every tool that writes, any key.
  s.denied("Write", { file_path: project, content: JSON.stringify({ permissions: { allow: ["Read"] } }) }, "a permissions-only change");
  s.denied("Edit", { file_path: project, old_string: '"allow"', new_string: '"deny"' }, "Edit");
  s.denied("MultiEdit", { file_path: project, edits: [{ old_string: '"allow"', new_string: '"deny"' }] }, "MultiEdit");
  s.denied("NotebookEdit", { notebook_path: project, new_source: "{}" }, "NotebookEdit");
  s.denied("Delete", { path: project }, "Delete");
  s.denied("Write", { file_path: local, content: JSON.stringify({ env: { IRONTRELLIS_HOOK_BIN: "/usr/bin/true" } }) }, "creating settings.local.json");
  // A case variant is the same file where the file system folds case (macOS, Windows); on Linux it is another file, which Claude Code does not read.
  if (process.platform !== "linux") s.denied("Write", { file_path: join(s.project, ".CLAUDE", "Settings.Local.json"), content: "{}" }, "a case variant");
  s.denied("Write", { file_path: join(s.config, "settings.json"), content: "{}" }, "CLAUDE_CONFIG_DIR/settings.json");
  s.denied("Write", { file_path: join(s.home, ".claude", "settings.json"), content: "{}" }, "~/.claude/settings.json");
  // (ii), (iii) the state file and the project's MCP servers.
  for (const file of [join(s.home, ".claude.json"), join(s.config, ".claude.json"), join(s.project, ".mcp.json")]) s.denied("Write", { file_path: file, content: "{}" }, file);
  // (iv) the whole .claude trees: agents, skills, commands, hooks, CLAUDE.md, the plugin cache; a second "irontrellis" plugin.
  for (const file of [join(s.project, ".claude", "agents", "a.md"), join(s.project, ".claude", "commands", "c.md"), join(s.project, ".claude", "skills", "x", "SKILL.md"),
    join(s.config, "hooks", "h.sh"), join(s.home, ".claude", "CLAUDE.md"), join(s.home, ".claude", "plugins", "cache", "m", "p", "1", "hooks", "hooks.json"), join(s.config, "plugins", "x")]) s.denied("Write", { file_path: file, content: "" }, file);
  s.denied("Write", { file_path: join(s.project, ".claude", "skills", "x", ".claude-plugin", "plugin.json"), content: JSON.stringify({ name: "irontrellis" }) }, "a second irontrellis plugin under .claude/skills");
  const cache = join(s.root, "plugin-cache");
  s.denied("Write", { file_path: join(cache, "plugins", "x"), content: "" }, "CLAUDE_CODE_PLUGIN_CACHE_DIR", { CLAUDE_CODE_PLUGIN_CACHE_DIR: cache });
  // ... except Claude Code's own data under the config directory (auto memory, plans, todos), checked through symlinks.
  s.notProtected("Write", { file_path: join(s.config, "projects", "p", "memory", "m.md"), content: "x" }, "auto memory");
  s.notProtected("Write", { file_path: join(s.config, "plans", "plan.md"), content: "x" }, "a plan");
  mkdirSync(join(s.config, "projects", "p"), { recursive: true });
  symlinkSync(project, join(s.config, "projects", "p", "link.json"));
  s.denied("Write", { file_path: join(s.config, "projects", "p", "link.json"), content: "{}" }, "a symlink in projects/ to a settings file");
  s.denied("Delete", { path: join(s.config, "projects") }, "deleting projects/ itself");
  // A symlink (dangling: its target does not exist yet) to a settings file is the settings file.
  symlinkSync(local, join(s.project, "alias.json"));
  s.denied("Write", { file_path: join(s.project, "alias.json"), content: "{}" }, "a dangling symlink to settings.local.json");
  // (v) the plugin root (also through a symlink) and the installed hooks and core packages ...
  s.denied("Write", { file_path: join(s.pluginRoot, "scripts", "launch.sh"), content: "exit 0\n" }, "CLAUDE_PLUGIN_ROOT");
  symlinkSync(s.pluginRoot, join(s.project, "plugin-link"));
  s.denied("Write", { file_path: join(s.project, "plugin-link", "scripts", "launch.sh"), content: "exit 0\n" }, "the plugin root through a symlink");
  const hooksRoot = resolve(dirname(BIN), "..");
  s.denied("Write", { file_path: join(hooksRoot, "dist", "cli.js"), content: "" }, "the hooks package");
  s.denied("Write", { file_path: fileURLToPath(import.meta.resolve("@ramex-labs/irontrellis")), content: "" }, "the core package");
  // ... except inside the project: IronTrellis developed in its own checkout.
  const { configProtection } = await import("../dist/index.js");
  assert.notEqual(configProtection([s.project], "Write", { file_path: join(hooksRoot, "dist", "cli.js") }, undefined, s.env), undefined);
  assert.equal(configProtection([resolve(hooksRoot, "..", "..")], "Write", { file_path: join(hooksRoot, "dist", "cli.js") }, undefined, s.env), undefined);
  // (vii) the interpreter and launcher: as written (a PATH link) and their real targets.
  symlinkSync(process.execPath, join(s.bin, "node"));
  s.denied("Write", { file_path: join(s.bin, "node"), content: "" }, "PATH's node");
  s.denied("Write", { file_path: realpathSync(process.execPath), content: "" }, "the real node");
  s.denied("Bash", { command: `cp /bin/true ${join(s.bin, "node")}` }, "cp over PATH's node");
  // Parents: moving or deleting a folder that holds any of it (shell: best effort).
  s.denied("Delete", { path: s.project }, "Delete the project");
  for (const command of [`mv ${s.project} ${s.root}/moved`, "mv .claude .claude-old", 'rm -rf "$HOME"', "rm -rf ~/.claude", `rm -rf ${s.config}`, "find . -name x -delete",
    "rsync -a --delete empty/ ~/", "git clean -fdx", "git stash -u", "git -C . stash push --include-untracked", "tar -xf x.tar -C .claude"]) s.denied("Bash", { command }, command);
  // Shell writers naming a configuration path, or a bare settings name (after cd).
  for (const command of ["ditto x .claude/settings.json", "curl -o .claude/settings.local.json https://example.invalid/x", "wget -O ~/.claude.json https://example.invalid/x",
    "install -m 644 x .mcp.json", "cd .claude && echo '{}' > settings.json", "cd ~ && cp x .claude.json"]) s.denied("Bash", { command }, command);
  // Any other tool naming it; the explicit no-write tools may.
  s.denied("mcp__fs__write_file", { path: local, content: "{}" }, "an MCP write tool");
  s.denied("mcp__fs__move", { source: join(s.project, ".claude"), destination: join(s.project, "old") }, "an MCP move of .claude");
  s.notProtected("Read", { file_path: project }, "Read");
  s.notProtected("Grep", { pattern: "hooks", path: join(s.project, ".claude") }, "Grep");
  s.notProtected("TodoWrite", { todos: [{ content: "check .claude/settings.local.json", status: "pending" }] }, "TodoWrite");
  for (const command of ["ls .claude", "cat .claude/settings.json", "git status", 'git commit -m "clean up"', "cp a.txt b.txt", "rm -rf build"]) s.notProtected("Bash", { command }, command);
});

test("the route's project is protected too: a config found further up, one named by IRONTRELLIS_HOOK_CONFIG; the plugin forwards the route's config", () => {
  const s = guarded();
  const sub = join(s.project, "sub"), other = join(s.root, "other");
  mkdirSync(sub); mkdirSync(other);
  s.denied("Write", { file_path: join(sub, ".claude", "settings.local.json"), content: "{}" }, "the route's project below the config", { CLAUDE_PROJECT_DIR: sub });
  const elsewhere = join(s.root, "elsewhere.json"); cpSync(join(s.project, "irontrellis-hook.json"), elsewhere);
  s.denied("Write", { file_path: join(other, ".claude", "settings.local.json"), content: "{}" }, "IRONTRELLIS_HOOK_CONFIG elsewhere", { CLAUDE_PROJECT_DIR: other, IRONTRELLIS_HOOK_CONFIG: elsewhere });
  // The plugin, run from a project below the config, finds it (the route) and the guard uses that config.
  const viaPlugin = s.call("Write", { file_path: join(sub, ".claude", "settings.local.json"), content: "{}" }, { CLAUDE_PROJECT_DIR: sub }, ["plugin", "claude-code", "PreToolUse"]);
  assert.equal(decision(viaPlugin), "deny", viaPlugin.stdout + viaPlugin.stderr);
  assert.match(viaPlugin.json.hookSpecificOutput.permissionDecisionReason, /protected/);
});

test("a session admitted under the plugin route whose config vanishes or changes is refused, never undecided; the event's cwd does not pick the project", () => {
  const s = sandbox();
  s.init("write-file");
  s.plugin("SessionStart", ev.start(s));
  const record = join(s.state, "route-sessions", `${createHash("sha256").update("cc-1", "utf8").digest("hex")}.json`);
  assert.equal(JSON.parse(readFileSync(record, "utf8")).state, "plugin");
  assert.equal(statSync(record).mode & 0o777, 0o600);
  const config = join(s.project, "irontrellis-hook.json"), aside = join(s.root, "aside.json");
  renameSync(config, aside); // git clean -fdx, git stash -u, a rename of the project: the config is gone
  assertDeny(s.plugin("PreToolUse", ev.tool(s, "Write", { file_path: join(s.project, "a.txt"), content: "x" })), /admitted under the plugin route .* gone/);
  assert.equal(s.plugin("Stop", ev.stop(s)).code, 1, "a warning on the other events");
  assertQuiet(s.plugin("PreToolUse", ev.tool(s, "Bash", { command: "ls" }, "cc-other")), "another session is undecided");
  renameSync(aside, config);
  assert.doesNotMatch(s.plugin("PreToolUse", ev.tool(s, "Write", { file_path: join(s.project, "a.txt"), content: "x" })).stdout, /admitted under/);
  // A different config for the same session: refused too.
  const elsewhere = join(s.root, "elsewhere.json"); cpSync(config, elsewhere);
  assertDeny(s.plugin("PreToolUse", ev.tool(s, "Bash", { command: "ls" }), { IRONTRELLIS_HOOK_CONFIG: elsewhere }), /admitted under the plugin route .* now using/);
  // The event's cwd (it follows the agent's cd) never selects the project: CLAUDE_PROJECT_DIR does.
  const unconfigured = join(s.root, "unconfigured"); mkdirSync(unconfigured);
  assertDeny(s.plugin("PreToolUse", { ...ev.tool(s, "Bash", { command: "ls" }), cwd: unconfigured }), /IronTrellis · DENY/);
  // SessionEnd forgets the session's route.
  s.plugin("SessionEnd", { session_id: "cc-1", cwd: s.project, hook_event_name: "SessionEnd", reason: "exit" });
  assert.equal(existsSync(record), false);
});

test("in undecided and declined the agent cannot set IronTrellis up: no irontrellis-hook.json, no runtime pin, no pin-runtime", () => {
  const s = sandbox();
  assertDeny(s.plugin("PreToolUse", ev.tool(s, "Write", { file_path: join(s.project, "irontrellis-hook.json"), content: "{}" })), /user's act/);
  assertDeny(s.plugin("PreToolUse", ev.tool(s, "Bash", { command: "echo '{}' > irontrellis-hook.json" })), /user's act/);
  assertDeny(s.plugin("PreToolUse", ev.tool(s, "Write", { file_path: join(s.state, "plugin-runtime"), content: "/x\n/y\n" })), /user's act/);
  assertDeny(s.plugin("PreToolUse", ev.tool(s, "Bash", { command: "irontrellis-hook pin-runtime" })), /^IronTrellis · DENY: installation policy: only you, the human operator, may set IronTrellis up/);
  assert.equal(s.run(["choose", "--decline"]).code, 0);
  assertDeny(s.plugin("PreToolUse", ev.tool(s, "Write", { file_path: join(s.project, "irontrellis-hook.json"), content: "{}" })), /user's act/);
});

// ---------------------------------------------------------------- hardening 3

test("nested Claude Code configuration, the shell's read-only rule, package managers, Monitor and MCP moves, the checkout-only exemption", async () => {
  const s = guarded();
  // P0: a .claude segment, .claude.json or .mcp.json anywhere under the project (Claude Code discovers nested skills).
  for (const file of [join(s.project, "sub", ".claude", "skills", "x", "SKILL.md"), join(s.project, "a", "b", ".mcp.json"), join(s.project, "c", ".claude.json"), join(s.root, "elsewhere", ".claude", "agents", "a.md")]) s.denied("Write", { file_path: file, content: "" }, file);
  s.notProtected("Write", { file_path: join(s.config, "projects", "p", "memory", "m.md"), content: "x" }, "auto memory, still exempt");
  s.notProtected("Write", { file_path: join(s.project, "src", "claude.md"), content: "x" }, "a name without the dot segment");
  // P1-5: a shell segment naming configuration may only read it.
  for (const command of ["touch .claude/x", "mkfifo .claude/settings.local.json", "mknod .mcp.json p", "sed -n 1p .claude/settings.json", "awk 1 .claude/settings.json", "vim sub/.claude/skills/x/SKILL.md", "python3 -c pass .claude", "git checkout -- .claude", "env A=1 touch .mcp.json"]) s.denied("Bash", { command }, command);
  for (const command of ["cat .claude/settings.json", "head -5 .mcp.json", "grep -r hooks .claude", "jq . .claude/settings.json", "git log -- .claude", "git diff .claude/settings.json", "wc -l .claude/settings.json", "ls -la sub/.claude"]) s.notProtected("Bash", { command }, command);
  // P1-4: package managers that could replace the guard or its node (best effort).
  for (const command of ["npm install -g @ramex-labs/irontrellis-hooks@latest", "npm i -g left-pad", "npm uninstall @ramex-labs/irontrellis-hooks", "npm link", "pnpm add -g x", "yarn global add x", "bun remove -g x",
    "brew upgrade", "brew upgrade node", "brew uninstall node@22", "brew unlink node", "sudo npm install -g x"]) s.denied("Bash", { command }, command);
  for (const command of ["npm install", "npm i lodash", "pnpm add -D typescript", "brew install jq", "brew upgrade jq", "npm test"]) s.notProtected("Bash", { command }, command);
  // P2: Monitor runs commands; an MCP tool that moves or deletes may not take a folder holding a guarded path.
  s.denied("Monitor", { command: "rm -rf .claude" }, "Monitor");
  s.denied("mcp__fs__move_file", { source: s.project, destination: join(s.root, "moved") }, "an MCP move of the project");
  s.notProtected("mcp__fs__list_directory", { path: s.project }, "an MCP listing of the project");
  // ... and a folder holding the IronTrellis history (kept outside the home) cannot be moved either.
  s.denied("Bash", { command: `mv ${dirname(historyOf(s))} ${s.root}/moved-history` }, "the history's folder");
  // P1-1: the code exemption is for the IronTrellis checkout only (its root package.json is the workspace), not its node_modules.
  const { configProtection } = await import("../dist/index.js");
  const hooksRoot = resolve(dirname(BIN), ".."), write = { file_path: join(hooksRoot, "dist", "cli.js") };
  assert.equal(configProtection([resolve(hooksRoot, "..", "..")], "Write", write, undefined, s.env), undefined, "the checkout");
  assert.notEqual(configProtection([resolve(hooksRoot, "..")], "Write", write, undefined, s.env), undefined, "a folder that is not the workspace");
  assert.notEqual(configProtection([hooksRoot], "Write", write, undefined, s.env), undefined, "the hooks package as a project");
});

test("FIFOs are refused, not read: a settings file or a config that is a FIFO does not hang the guard", () => {
  const s = sandbox();
  s.init("write-file");
  mkdirSync(join(s.project, ".claude"), { recursive: true });
  const fifo = (path) => { const r = spawnSync("/usr/bin/mkfifo", [path]); assert.equal(r.status, 0, r.stderr?.toString()); };
  fifo(join(s.project, ".claude", "settings.local.json"));
  const timed = (args, stdin, extra) => spawnSync(process.execPath, [BIN, ...args], { cwd: s.project, input: stdin, encoding: "utf8", env: { ...s.env, ...extra }, timeout: 15_000 });
  const status = timed(["choose", "--status"], "");
  assert.equal(status.signal, null, "choose --status returned"); assert.match(status.stdout, /route:\s+plugin/);
  s.plugin("SessionStart", ev.start(s));
  const call = timed(["plugin", "claude-code", "PreToolUse"], JSON.stringify(ev.tool(s, "Bash", { command: "ls" })));
  assert.equal(call.signal, null, "the plugin returned"); assert.equal(call.status, 2); assert.equal(call.stdout, ""); assert.match(call.stderr, /^\nIronTrellis · DENY: /);
  // The config itself replaced by a FIFO: refused (cannot read it), promptly.
  const other = join(s.root, "fifo-project"); mkdirSync(other); fifo(join(other, "irontrellis-hook.json"));
  const viaFifo = timed(["claude-code", "PreToolUse"], JSON.stringify({ ...ev.tool(s, "Bash", { command: "ls" }), cwd: other }), { CLAUDE_PROJECT_DIR: other });
  assert.equal(viaFifo.signal, null, "the hook returned"); assert.equal(viaFifo.status, 2, viaFifo.stdout); assert.match(viaFifo.stderr, /not a regular file/);
});

test("the hook route: the wrapper refuses a missing node or launcher; the route's project picks the config and is protected without CLAUDE_PROJECT_DIR; init warns about planted settings", () => {
  const s = sandbox();
  const runEntry = (node, launcher, event) => spawnSync("/bin/sh", ["-c", `${hookEntryProgram(node, launcher)} claude-code ${event}`], { cwd: s.project, input: "{}", encoding: "utf8", env: s.env });
  assert.equal(runEntry(process.execPath, join(s.root, "gone", "bin", "irontrellis-hook.mjs"), "PreToolUse").status, 2, "a missing launcher blocks the tool call");
  assert.equal(runEntry(process.execPath, join(s.root, "gone", "bin", "irontrellis-hook.mjs"), "Stop").status, 1, "and only warns on the other events");
  assert.equal(runEntry(join(s.root, "no-node"), realpathSync(BIN), "PreToolUse").status, 2, "a missing node blocks the tool call");
  // Planted settings before init: warned about.
  s.settings(join(s.project, ".claude", "settings.local.json"), { disableAllHooks: true, env: { NODE_OPTIONS: "--require /tmp/x.js" } });
  const init = s.run(["init", "--agent", "claude-code"]);
  assert.equal(init.code, 0, init.stderr);
  assert.match(init.stdout + init.stderr, /disableAllHooks": true/); assert.match(init.stdout + init.stderr, /gives the hooks NODE_OPTIONS: check that you set it yourself/); // post5-10: one sentence by default
  rmSync(join(s.project, ".claude", "settings.local.json"));
  s.hook("SessionStart", ev.start(s));
  // The route's project picks the config: the event's cwd (with a broken config of its own) does not.
  const other = join(s.root, "other"); mkdirSync(other); writeFileSync(join(other, "irontrellis-hook.json"), "{ broken");
  const away = join(s.root, "away"); mkdirSync(away);
  const fromAway = spawnSync(process.execPath, [BIN, "claude-code", "PreToolUse"], { cwd: away, input: JSON.stringify({ ...ev.tool(s, "Write", { file_path: join(s.project, "a.txt"), content: "x" }), cwd: other }), encoding: "utf8", env: s.env });
  assert.doesNotMatch(fromAway.stdout + fromAway.stderr, /broken|not valid JSON/, "the project's config was used");
  // Without CLAUDE_PROJECT_DIR, a config named elsewhere still protects the hook's own project.
  const elsewhere = join(s.root, "elsewhere.json"); cpSync(join(s.project, "irontrellis-hook.json"), elsewhere);
  const { CLAUDE_PROJECT_DIR: _drop, ...noProject } = s.env;
  const near = spawnSync(process.execPath, [BIN, "claude-code", "PreToolUse"], { cwd: away, input: JSON.stringify({ ...ev.tool(s, "Write", { file_path: join(away, ".claude", "settings.local.json"), content: "{}" }), cwd: away }), encoding: "utf8", env: { ...noProject, IRONTRELLIS_HOOK_CONFIG: elsewhere } });
  assert.equal(near.status, 2, near.stdout + near.stderr); assert.equal(near.stdout, ""); assert.match(near.stderr, /^\nIronTrellis · DENY: /);
});

// ---------------------------------------------------------------- hardening 4

test("hardening 4: node_modules anywhere, glued redirections, reading programs that write, extraction into the cwd, runners and shells before a package manager", async () => {
  const s = guarded();
  // 1. The checkout exemption excludes any node_modules segment, not only the root's.
  const { inIronTrellisCheckout } = await import("../dist/index.js");
  const checkout = join(s.root, "checkout"); mkdirSync(join(checkout, "packages", "x", "node_modules", "dep"), { recursive: true });
  writeFileSync(join(checkout, "package.json"), JSON.stringify({ name: "irontrellis-workspace" }));
  assert.equal(inIronTrellisCheckout([checkout], join(checkout, "packages", "hooks", "dist", "cli.js")), true);
  assert.equal(inIronTrellisCheckout([checkout], join(checkout, "packages", "x", "node_modules", "dep", "index.js")), false, "a nested node_modules");
  assert.equal(inIronTrellisCheckout([checkout], join(checkout, "node_modules", "@ramex-labs", "irontrellis-hooks", "dist", "cli.js")), false, "the root's node_modules");
  assert.equal(inIronTrellisCheckout([s.project], join(s.project, "packages", "hooks", "dist", "cli.js")), false, "not the workspace");
  // 2. A redirection glued to a path.
  for (const command of ["echo x >.claude/settings.json", "echo x >>.mcp.json", "cat a 2>.claude/err", "ls 1>.claude/x", "echo x &>.claude/y", "echo x >sub/.claude/skills/s/SKILL.md"]) s.denied("Bash", { command }, command);
  // ... and to a guarded path that is not a Claude Code name (only the path check sees it).
  const hooksDist = join(resolve(dirname(BIN), ".."), "dist", "cli.js");
  for (const command of [`echo x >${hooksDist}`, `cat a 2>>${hooksDist}`, `echo x >${join(s.pluginRoot, "scripts", "launch.sh")}`]) s.denied("Bash", { command }, command);
  // 3. Reading programs in a form that writes or runs something.
  for (const command of ["sort -o .claude/settings.json a", "sort --output=.claude/x a", "uniq a .claude/x", "xxd -r a .claude/x", "git -c core.pager=x log -- .claude", "git diff --output=.claude/x",
    "git log --output .claude/x", "git grep -O x .claude", "rg --pre ./x foo .claude", "rg --pre-glob '*' foo .claude", "file -C -m .claude/x", "less -o .claude/x a"]) s.denied("Bash", { command }, command);
  for (const command of ["sort .claude/settings.json", "uniq .claude/x", "xxd .claude/x", "git log -- .claude", "rg hooks .claude"]) s.notProtected("Bash", { command }, command);
  // 4. Extraction, patching and checkout into a folder holding Claude Code's configuration (the cwd when no target is named).
  for (const command of ["tar -xf /tmp/x.tar", "unzip /tmp/x.zip", "git apply /tmp/p.diff", "patch -p1 < /tmp/p.diff", "git checkout main", "git switch other", "git restore .", "git stash", "git reset --hard HEAD~1", "git am /tmp/p.mbox"]) s.denied("Bash", { command }, command);
  const sub = join(s.project, "sub2"); mkdirSync(join(sub, ".claude"), { recursive: true });
  const elsewhere = join(s.root, "plain"); mkdirSync(elsewhere);
  s.denied("Bash", { command: `tar -xf /tmp/x.tar -C ${sub}` }, "tar into a folder with a .claude");
  s.notProtected("Bash", { command: `tar -xf /tmp/x.tar -C ${elsewhere}` }, "tar into a plain folder elsewhere");
  s.notProtected("Bash", { command: "git reset HEAD~1" }, "a soft reset");
  s.notProtected("Bash", { command: "tar -czf /tmp/out.tar build" }, "creating an archive");
  // 6. Runners with option values, assignments, --prefix and shells before a package manager.
  for (const command of ["nice -n 5 npm i -g x", "timeout 30 npm install -g x", "timeout -s KILL 30 npm i -g x", "stdbuf -oL npm i -g x", "npm_config_global=true npm install x", "npm install --prefix /usr/local x",
    'bash -c "npm i -g x"', "sh -c 'brew upgrade'", "sudo -u root npm i -g x", "env -u HOME npm i -g x"]) s.denied("Bash", { command }, command);
  s.notProtected("Bash", { command: "nice -n 5 npm test" }, "nice npm test");
});

test("hardening 4: the guard failing on PreToolUse is a refusal on both routes (a crash, a deleted dist/); init warns about DYLD_ and LD_PRELOAD", () => {
  const s = sandbox();
  const crash = join(s.root, "crash-hooks"); mkdirSync(join(crash, "bin"), { recursive: true });
  writeFileSync(join(crash, "package.json"), JSON.stringify({ name: "@ramex-labs/irontrellis-hooks" }));
  writeFileSync(join(crash, "bin", "irontrellis-hook.mjs"), "import './missing-dist.js';\n"); // like a deleted dist/: the import throws, exit 1
  const launcher = join(realpathSync(crash), "bin", "irontrellis-hook.mjs");
  // The hook route's wrapper: a crash is exit 2 on PreToolUse; the other events pass the guard's own exit code through.
  const runEntry = (node, event) => spawnSync("/bin/sh", ["-c", `${hookEntryProgram(node, launcher)} claude-code ${event}`], { cwd: s.project, input: "{}", encoding: "utf8", env: s.env });
  assert.equal(runEntry(process.execPath, "PreToolUse").status, 2, "a crash on PreToolUse refuses");
  assert.equal(runEntry(process.execPath, "Stop").status, 1, "a crash elsewhere is a warning");
  assert.equal(runEntry(s.root, "PreToolUse").status, 2, "a directory is not the node");
  // The plugin's launch.sh with the pin on that launcher.
  writeFileSync(join(s.state, "plugin-runtime"), `${process.execPath}\n${launcher}\n`, { mode: 0o600 });
  const minimal = { HOME: s.home, IRONTRELLIS_HOME: s.state, CLAUDE_PROJECT_DIR: s.project, PATH: "/usr/bin:/bin" };
  const launch = (event, payload) => spawnSync("/bin/sh", [LAUNCH, event], { cwd: s.project, input: JSON.stringify(payload), encoding: "utf8", env: minimal });
  const refused = launch("PreToolUse", ev.tool(s, "Bash", { command: "ls" }));
  assert.equal(refused.status, 2); assert.match(refused.stderr, /the guard failed \(exit 1\); refusing/);
  assert.equal(launch("Stop", ev.stop(s)).status, 1);
  // 7. init warns about DYLD_* and LD_PRELOAD in the settings' env.
  s.settings(join(s.project, ".claude", "settings.json"), { env: { DYLD_INSERT_LIBRARIES: "/tmp/x.dylib", LD_PRELOAD: "/tmp/x.so" } });
  const init = s.run(["init", "--agent", "claude-code"]);
  assert.equal(init.code, 0, init.stderr); assert.match(init.stdout + init.stderr, /gives the hooks DYLD_INSERT_LIBRARIES, LD_PRELOAD: check that you set them yourself/);
  assert.match(s.run(["init", "--agent", "claude-code", "--force", "--verbose"]).stderr, /DYLD_INSERT_LIBRARIES, LD_PRELOAD in "env"/, "--verbose: the full warning");
});

test("failOpen (the user's explicit choice) passes a load error on PreToolUse with a warning through both routes; off, it refuses; a guard that cannot start refuses either way", () => {
  const s = sandbox();
  s.init("write-file");
  s.hook("SessionStart", ev.start(s));
  const configFile = join(s.project, "irontrellis-hook.json"), config = JSON.parse(readFileSync(configFile, "utf8"));
  const history = historyOf(s); renameSync(history, `${history}.aside`); // a load error: the history is gone
  const call = JSON.stringify(ev.tool(s, "Write", { file_path: join(s.project, "a.txt"), content: "x" }));
  const viaWrapper = (launcher = realpathSync(BIN)) => spawnSync("/bin/sh", ["-c", `${hookEntryProgram(process.execPath, launcher)} claude-code PreToolUse`], { cwd: s.project, input: call, encoding: "utf8", env: s.env });
  writeFileSync(join(s.state, "plugin-runtime"), `${process.execPath}\n${realpathSync(BIN)}\n`, { mode: 0o600 });
  const viaLaunch = () => spawnSync("/bin/sh", [LAUNCH, "PreToolUse"], { cwd: s.project, input: call, encoding: "utf8", env: { HOME: s.home, IRONTRELLIS_HOME: s.state, CLAUDE_PROJECT_DIR: s.project, PATH: "/usr/bin:/bin" } });
  assert.equal(viaWrapper().status, 2, "failOpen off: refused");
  assert.equal(viaLaunch().status, 2, "failOpen off: refused by the plugin too");
  writeFileSync(configFile, `${JSON.stringify({ ...config, failOpen: true }, null, 2)}\n`);
  for (const [route, r] of [["hook", viaWrapper()], ["plugin", viaLaunch()]]) {
    assert.equal(r.status, 0, `${route}: ${r.stderr}`);
    assert.match(JSON.parse(r.stdout).systemMessage, /IronTrellis could not check this call and lets it through \("failOpen": true\)/, route);
    assert.notEqual(r.stderr, "", `${route}: the error is on stderr too`);
  }
  // A guard that cannot start (its dist/ gone) cannot read failOpen: refused.
  const crash = join(s.root, "crash-hooks"); mkdirSync(join(crash, "bin"), { recursive: true });
  writeFileSync(join(crash, "package.json"), JSON.stringify({ name: "@ramex-labs/irontrellis-hooks" })); writeFileSync(join(crash, "bin", "irontrellis-hook.mjs"), "import './missing-dist.js';\n");
  assert.equal(viaWrapper(join(realpathSync(crash), "bin", "irontrellis-hook.mjs")).status, 2);
});

test("hardening 5: clustered sort and xxd options, npx and corepack before a package manager, more git commands that write the work tree", () => {
  const s = guarded();
  for (const command of ["sort -uo .claude/settings.json a", "sort -ro .claude/x a", "xxd -pr .claude/x", "npx npm@10 i -g x", "npx -y npm i -g @ramex-labs/irontrellis-hooks", "corepack npm install -g x", "corepack pnpm add -g x",
    "git pull", "git merge other", "git rebase main", "git cherry-pick abc123", "git revert abc123", "git read-tree -u HEAD", "git read-tree -mu HEAD"]) s.denied("Bash", { command }, command);
  for (const command of ["sort -u .claude/settings.json", "xxd -p .claude/x", "npx prettier --check src", "git read-tree HEAD", "git log --oneline"]) s.notProtected("Bash", { command }, command);
});

test("failOpen comes from the config the session was admitted under: a config at the event's cwd or named in the environment later does not change it", () => {
  const s = sandbox();
  s.init("write-file");
  s.hook("SessionStart", ev.start(s));
  const record = join(s.state, "route-sessions", `${createHash("sha256").update("cc-1", "utf8").digest("hex")}.json`);
  const configFile = join(s.project, "irontrellis-hook.json");
  assert.equal(JSON.parse(readFileSync(record, "utf8")).config, realpathSync(configFile), "the hook route records the admitted config");
  // Another folder with a failOpen config (the agent cannot write one; a second project of the user's could hold one).
  const other = join(s.root, "other"); mkdirSync(other);
  const lenient = join(other, "irontrellis-hook.json");
  writeFileSync(lenient, `${JSON.stringify({ ...JSON.parse(readFileSync(configFile, "utf8")), failOpen: true }, null, 2)}\n`);
  const tool = (extra, payload = ev.tool(s, "Write", { file_path: join(s.project, "a.txt"), content: "x" })) => s.run(["claude-code", "PreToolUse"], { stdin: JSON.stringify({ ...payload, cwd: other }), extra });
  // A malformed event and an error while answering (the history gone): refused, whatever the event's cwd or the env names.
  assert.equal(tool({ IRONTRELLIS_HOOK_CONFIG: lenient }, { ...ev.tool(s, "Bash", { command: "ls" }), tool_name: 7 }).code, 2, "malformed, env names a failOpen config");
  const history = historyOf(s); renameSync(history, `${history}.aside`);
  assert.equal(tool({}).code, 2, "load error, a failOpen config at the event's cwd");
  assert.equal(tool({ IRONTRELLIS_HOOK_CONFIG: lenient }).code, 2, "load error, the env names a failOpen config");
  // The admitted config's own failOpen is honoured.
  writeFileSync(configFile, `${JSON.stringify({ ...JSON.parse(readFileSync(configFile, "utf8")), failOpen: true }, null, 2)}\n`);
  const passed = tool({});
  assert.equal(passed.code, 0); assert.match(passed.json.systemMessage, /lets it through \("failOpen": true\)/);
  renameSync(`${history}.aside`, history);
  // The final SessionEnd forgets the session's route.
  s.hook("SessionEnd", { session_id: "cc-1", cwd: s.project, hook_event_name: "SessionEnd", reason: "exit" });
  assert.equal(existsSync(record), false);
});

// ---------------------------------------------------------------- two copies of the guard

test("two copies of the guard: one admission (the key intact), one refusal per tool call, one handover per stop", async () => {
  const s = sandbox();
  s.init();
  const [a, b] = await Promise.all([s.runAsync(["claude-code", "SessionStart"], JSON.stringify(ev.start(s))), s.runAsync(["claude-code", "SessionStart"], JSON.stringify(ev.start(s)))]);
  assert.equal(a.code, 0, a.stderr); assert.equal(b.code, 0, b.stderr);
  // The hook also admits its own connector session (hooks:<host>:…); this host session is admitted once.
  const admitted = openHistoryStore(historyOf(s)).state().events.filter((e) => e.type === "RUNTIME_SESSION_ADMITTED" && String(e.data.sessionId).startsWith("session:cc-1"));
  assert.equal(admitted.length, 1, JSON.stringify(admitted.map((e) => e.data.sessionId)));
  const keyFile = join(`${historyOf(s)}.sessions`, `${createHash("sha256").update("cc-1", "utf8").digest("hex")}.json`);
  assert.equal(typeof JSON.parse(readFileSync(keyFile, "utf8")).privateKey, "string", "the session key is intact");
  const tool = JSON.stringify(ev.tool(s, "Bash", { command: "ls" }, "cc-1", "toolu_same"));
  const [d1, d2] = await Promise.all([s.runAsync(["claude-code", "PreToolUse"], tool), s.runAsync(["claude-code", "PreToolUse"], tool)]);
  for (const d of [d1, d2]) { assert.equal(d.code, 2, d.stdout + d.stderr); assert.equal(d.stdout, ""); assert.match(d.stderr, /^\nIronTrellis · DENY: /); }
  assertDeny(s.hook("PreToolUse", JSON.parse(tool)));
  assert.equal(typesOf(s).filter((t) => t === "REQUEST_REFUSED").length, 1, "one refusal for one tool call");
  const [h1, h2] = await Promise.all([s.runAsync(["claude-code", "Stop"], JSON.stringify(ev.stop(s))), s.runAsync(["claude-code", "Stop"], JSON.stringify(ev.stop(s)))]);
  assert.equal(h1.code, 0, h1.stderr); assert.equal(h2.code, 0, h2.stderr);
  const handover = join(`${historyOf(s)}.handovers`, `${createHash("sha256").update("cc-1", "utf8").digest("hex")}.json`);
  assert.equal(JSON.parse(readFileSync(handover, "utf8")).hostSessionId, "cc-1");
});

// ---------------------------------------------------------------- the plugin's files and launcher

test("plugin files: manifest, marketplace, the four hooks with install's timeouts, the skill's front matter", () => {
  const manifest = JSON.parse(readFileSync(join(PLUGIN, ".claude-plugin", "plugin.json"), "utf8"));
  assert.equal(manifest.name, "irontrellis");
  const pkg = JSON.parse(readFileSync(join(PLUGIN, "..", "..", "packages", "hooks", "package.json"), "utf8"));
  assert.equal(manifest.version, pkg.version);
  // The icon (BRAND-001: the badge for app icons): a square PNG in the plugin, 512 to 2048 px (Claude Code's validator), the brand kit's file.
  assert.equal(manifest.icon, "./assets/irontrellis-badge-512.png");
  const icon = readFileSync(join(PLUGIN, manifest.icon));
  assert.deepEqual([...icon.subarray(0, 8)], [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], "a PNG");
  assert.deepEqual([icon.readUInt32BE(16), icon.readUInt32BE(20)], [512, 512], "512 × 512");
  assert.ok(icon.length < 2 * 1024 * 1024);
  assert.deepEqual(icon, readFileSync(join(PLUGIN, "..", "..", "brand", "logo", "png", "irontrellis-badge-512.png")), "the brand kit's badge, unchanged");
  const market = JSON.parse(readFileSync(join(PLUGIN, "..", "..", ".claude-plugin", "marketplace.json"), "utf8"));
  assert.equal(market.name, "irontrellis");
  // The marketplace's description is a first prominent mention in marketing text: IronTrellis™ (founder 4bz, BRAND-001 p. 8).
  assert.match(market.metadata.description, /^IronTrellis™: /);
  assert.equal(resolve(PLUGIN, "..", "..", market.plugins[0].source), PLUGIN);
  const hooks = JSON.parse(readFileSync(join(PLUGIN, "hooks", "hooks.json"), "utf8")).hooks;
  assert.deepEqual(Object.fromEntries(Object.entries(hooks).map(([e, g]) => [e, g[0].hooks[0].timeout])), { SessionStart: 30, PreToolUse: 30, Stop: 30, SessionEnd: 10 });
  for (const [e, g] of Object.entries(hooks)) assert.equal(g[0].hooks[0].command, `/bin/sh "\${CLAUDE_PLUGIN_ROOT}/scripts/launch.sh" ${e}`);
  // post5-11 (KI 61): a PreToolUse hook that times out refuses the call; the other events carry no onFailure.
  assert.deepEqual(Object.fromEntries(Object.entries(hooks).map(([e, g]) => [e, g[0].hooks[0].onFailure ?? null])), { SessionStart: null, PreToolUse: "block", Stop: null, SessionEnd: null });
  assert.equal(existsSync(join(PLUGIN, "scripts", "launch.mjs")), false, "no node launcher looked up on PATH");
  const skill = readFileSync(join(PLUGIN, "skills", "irontrellis-handover", "SKILL.md"), "utf8");
  assert.match(skill, /^---\nname: irontrellis-handover\ndescription: .+\n---\n/);
});

test("launcher (launch.sh): the pinned node and launcher by absolute path, exit 2 only for PreToolUse; without a pin it refuses only in a configured project", () => {
  const s = sandbox();
  const minimal = { HOME: s.home, IRONTRELLIS_HOME: s.state, CLAUDE_PROJECT_DIR: s.project, PATH: "/usr/bin:/bin" }; // no node, no irontrellis-hook
  const launch = (event, payload, env = s.env) => spawnSync("/bin/sh", [LAUNCH, event], { cwd: s.project, input: JSON.stringify(payload), encoding: "utf8", env });
  // No pin, not set up: irontrellis-hook from PATH shows the notice; without it, a static notice and nothing refused.
  assert.match(JSON.parse(launch("SessionStart", ev.start(s)).stdout).systemMessage, /Choose one/);
  const bare = launch("SessionStart", ev.start(s), minimal);
  assert.equal(bare.status, 0, bare.stderr); assert.match(JSON.parse(bare.stdout).systemMessage, /irontrellis-hook command is not installed/);
  assert.equal(launch("PreToolUse", ev.tool(s, "Bash", { command: "ls" }), minimal).status, 0, "nothing is set up: nothing to refuse");
  // The pin (pin-runtime; init writes it too): the guard runs without PATH (no node on it).
  assert.equal(s.run(["pin-runtime"]).code, 0);
  const pinned = launch("SessionStart", ev.start(s), minimal);
  assert.equal(pinned.status, 0, pinned.stderr); assert.match(JSON.parse(pinned.stdout).systemMessage, /Choose one/);
  // A blocking answer is exit 2 on PreToolUse only (a launcher that exits 2, inside a hooks package).
  const fake = join(s.root, "fake-hooks"); mkdirSync(join(fake, "bin"), { recursive: true });
  writeFileSync(join(fake, "package.json"), JSON.stringify({ name: "@ramex-labs/irontrellis-hooks" }));
  writeFileSync(join(fake, "bin", "irontrellis-hook.mjs"), "process.exit(2)\n");
  const pin = (node, launcher) => writeFileSync(join(s.state, "plugin-runtime"), `${node}\n${launcher}\n`, { mode: 0o600 });
  pin(process.execPath, join(realpathSync(fake), "bin", "irontrellis-hook.mjs"));
  assert.equal(launch("SessionStart", ev.start(s), minimal).status, 1, "a blocking answer on SessionStart is only a warning");
  assert.equal(launch("Stop", ev.stop(s), minimal).status, 1);
  assert.equal(launch("PreToolUse", ev.tool(s, "Bash", { command: "ls" }), minimal).status, 2);
  // A broken pin refuses tool calls: a missing node, a launcher outside a hooks package, a symlinked launcher.
  pin(join(s.root, "no-such-node"), realpathSync(BIN));
  const broken = launch("PreToolUse", ev.tool(s, "Bash", { command: "ls" }), minimal);
  assert.equal(broken.status, 2); assert.match(broken.stderr, /^\nIronTrellis · DENY: the pinned node .* is missing/, "a refusal says IronTrellis denied the call");
  const brokenStop = launch("Stop", ev.stop(s), minimal);
  assert.equal(brokenStop.status, 1); assert.match(brokenStop.stderr, /^IronTrellis: the pinned node/, "a warning is not a denial");
  const stray = join(s.root, "bin2"); mkdirSync(stray); writeFileSync(join(stray, "irontrellis-hook.mjs"), "process.exit(0)\n");
  pin(process.execPath, join(realpathSync(stray), "irontrellis-hook.mjs"));
  assert.equal(launch("PreToolUse", ev.tool(s, "Bash", { command: "ls" }), minimal).status, 2, "not in the hooks package");
  symlinkSync(realpathSync(BIN), join(fake, "bin", "link.mjs"));
  pin(process.execPath, join(realpathSync(fake), "bin", "irontrellis-hook.mjs"));
  writeFileSync(join(s.state, "plugin-runtime"), `${process.execPath}\n${join(realpathSync(fake), "bin", "link.mjs")}\n`);
  assert.equal(launch("PreToolUse", ev.tool(s, "Bash", { command: "ls" }), minimal).status, 2, "not the launcher's name");
  // No PATH lookups with a pin: a planted grep or dirname earlier on PATH does not pass a stray launcher; NODE_* is unset.
  // The planted tools work like the real ones (grep always "finds" the package) and leave a mark when used.
  const planted = join(s.root, "planted"), used = join(s.root, "planted-used"); mkdirSync(planted);
  writeFileSync(join(planted, "grep"), `#!/bin/sh\n: > ${JSON.stringify(used)}\nexit 0\n`); chmodSync(join(planted, "grep"), 0o755);
  writeFileSync(join(planted, "dirname"), `#!/bin/sh\n: > ${JSON.stringify(used)}\nexec /usr/bin/dirname "$@"\n`); chmodSync(join(planted, "dirname"), 0o755);
  // A launcher by the right name in another package: only the planted grep would pass it.
  const other = join(s.root, "other-package"); mkdirSync(join(other, "bin"), { recursive: true });
  writeFileSync(join(other, "package.json"), JSON.stringify({ name: "not-irontrellis" })); writeFileSync(join(other, "bin", "irontrellis-hook.mjs"), "process.exit(0)\n");
  pin(process.execPath, join(realpathSync(other), "bin", "irontrellis-hook.mjs"));
  assert.equal(launch("PreToolUse", ev.tool(s, "Bash", { command: "ls" }), { ...minimal, PATH: `${planted}:/usr/bin:/bin` }).status, 2, "a launcher outside the hooks package is refused");
  assert.equal(existsSync(used), false, "no tool was looked up on the agent-reachable PATH");
  const marker = join(s.root, "node-options-ran"), preload = join(s.root, "preload.cjs");
  writeFileSync(preload, `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "x");\n`);
  assert.equal(s.run(["pin-runtime"]).code, 0);
  launch("SessionStart", ev.start(s), { ...minimal, NODE_OPTIONS: `--require ${preload}` });
  assert.equal(existsSync(marker), false, "NODE_OPTIONS did not reach the guard's node");
  // No pin in a configured project: refused.
  rmSync(join(s.state, "plugin-runtime"));
  writeFileSync(join(s.project, "irontrellis-hook.json"), "{}");
  assert.equal(launch("PreToolUse", ev.tool(s, "Bash", { command: "ls" }), minimal).status, 2, "a configured project fails closed without the pin");
  assert.equal(launch("Stop", ev.stop(s), minimal).status, 1);
});

// ---------------------------------------------------------------- the founder's live check 01 (post5-05)

test("live check 01, the bug: the plugin route never reports both routes; a settings hook does, worded by whether it is the verified entry", () => {
  const s = sandbox();
  s.init();
  s.settings(join(s.project, ".claude", "settings.local.json"), { enabledPlugins: { "irontrellis@irontrellis": true } });
  assert.match(s.run(["choose", "--status"]).stdout, /route:\s+plugin/);
  // The plugin's own entry point (as launch.sh runs it) and the launcher itself: no both-routes warning.
  const start = s.plugin("SessionStart", ev.start(s));
  assert.equal(start.code, 0, start.stderr);
  assert.doesNotMatch(start.stdout + start.stderr, /also enabled/);
  assert.equal(s.run(["pin-runtime"]).code, 0);
  const minimal = { HOME: s.home, IRONTRELLIS_HOME: s.state, CLAUDE_PROJECT_DIR: s.project, PATH: "/usr/bin:/bin" };
  const launched = spawnSync("/bin/sh", [LAUNCH, "SessionStart"], { cwd: s.project, input: JSON.stringify(ev.start(s, "cc-2")), encoding: "utf8", env: minimal });
  assert.equal(launched.status, 0, launched.stderr);
  assert.doesNotMatch(launched.stdout + launched.stderr, /also enabled/);
  // A settings hook that is not install's entry (here the command run directly) with the plugin enabled: both run the guard.
  const direct = s.hook("SessionStart", ev.start(s, "cc-3"));
  assert.match(direct.json.systemMessage, /IronTrellis plugin for Claude Code \(`irontrellis` in \/plugin\) is also enabled here, and this settings hook is not the entry `irontrellis-hook install claude-code --write` writes, so both run the guard/);
  assert.doesNotMatch(direct.json.systemMessage, /stepping aside/);
  // The verified hook route with the plugin enabled: the plugin steps aside, the hook says so.
  assert.equal(s.run(["install", "claude-code", "--write"]).code, 0);
  assert.match(s.run(["choose", "--status"]).stdout, /route:\s+both/);
  assert.match(s.hook("SessionStart", ev.start(s, "cc-4")).json.systemMessage, /IronTrellis plugin for Claude Code \(`irontrellis` in \/plugin\) is also enabled here; it is stepping aside, and this hook is the one guard/);
  // The plugin not enabled: no warning from either.
  s.settings(join(s.project, ".claude", "settings.local.json"), { enabledPlugins: [] });
  assert.doesNotMatch(s.hook("SessionStart", ev.start(s, "cc-5")).stdout, /also enabled/);
});

test("live check 01: choose 1, 2 and 3 are the notice's choices (the user's, never the agent's); anything else is refused; choose 2 names no hook-route install", () => {
  const s = sandbox();
  const one = s.run(["choose", "1"]);
  assert.equal(one.code, 0, one.stderr);
  assert.match(one.stdout, /IronTrellis is off for /);
  assert.equal(JSON.parse(readFileSync(s.choiceFile, "utf8")).projects[s.project].choice, "declined");
  assert.equal(s.run(["choose", "--reset"]).code, 0);
  const three = s.run(["choose", "3"]);
  assert.equal(three.code, 0, three.stderr);
  assert.equal(JSON.parse(readFileSync(s.choiceFile, "utf8")).projects[s.project].choice, "use-hook");
  assert.match(s.plugin("SessionStart", ev.start(s)).json.systemMessage, /you chose the hook route, which is not set up yet\. Type these here with the `!` prefix/);
  for (const bad of [["choose", "4"], ["choose", "0"], ["choose", "constructor"], ["choose", "1", "--decline"], ["choose", "2", "--reset"], ["choose", "1", "2"]]) {
    const r = s.run(bad);
    assert.equal(r.code, 1, `${bad.join(" ")}: ${r.stdout}`);
  }
  // 2: init --agent claude-code here (the plugin route), then a new session.
  const two = s.run(["choose", "2"]);
  assert.equal(two.code, 0, two.stderr);
  assert.match(two.stdout, /^IronTrellis is set up here \(the plugin route\)\. Start a new Claude Code session in this project/);
  // The plugin route's next steps leave out the hook route's install (the coordinator, 2026-10-23); the grant hint stays.
  assert.doesNotMatch(two.stdout, /install claude-code/);
  assert.match(two.stdout, /next:\n {2}irontrellis --history .* grant <id> --to claude-code --actions write-file/);
  // A plain init keeps it: the user may want the hook route.
  const plain = sandbox().run(["init", "--agent", "claude-code"]);
  assert.equal(plain.code, 0, plain.stderr);
  assert.match(plain.stdout, /next:\n {2}irontrellis-hook install claude-code --write {8}# add the hooks to \.claude\/settings\.json\n {2}irontrellis --history /);
  assert.equal(existsSync(join(s.project, "irontrellis-hook.json")), true);
  assert.match(s.run(["choose", "--status"]).stdout, /route:\s+plugin/);
  assert.equal(s.run(["choose", "2"]).code, 1, "init refuses an existing config");
  // The help names them.
  assert.match(s.run(["--help"]).stdout, /irontrellis-hook choose 1 \| 2 \| 3 +the notice's choices: 1 = --decline, 2 = init --agent claude-code \(the plugin route\), 3 = --use-hook/);
});

test("post5-09: irontrellis-hook init ends with what to publish (the history id the config pins, the first owner key), also in --json", () => {
  const s = sandbox();
  const human = s.run(["init", "--agent", "claude-code"]);
  assert.equal(human.code, 0, human.stderr);
  const pinned = JSON.parse(readFileSync(join(s.project, "irontrellis-hook.json"), "utf8")).historyId;
  const block = /\nPublish these where readers can check them independently of this file:\n {2}history id {2}(0x[0-9a-f]{64})\n {2}owner key {3}(0x[0-9a-f]{64})\nA reader checks them with: irontrellis --history (\S+) verify --expect-history-id (0x[0-9a-f]{64}) --expect-owner-key (0x[0-9a-f]{64})\n$/.exec(human.stdout);
  assert.ok(block, human.stdout);
  assert.equal(block[1], pinned);
  assert.equal(block[4], pinned);
  assert.equal(block[5], block[2]);
  const again = sandbox().run(["init", "--agent", "claude-code", "--json"]);
  assert.equal(again.code, 0, again.stderr);
  const doc = JSON.parse(again.stdout);
  assert.match(doc.publish.historyId, /^0x[0-9a-f]{64}$/);
  assert.equal(doc.publish.ownerKeys.length, 1);
  assert.match(doc.publish.ownerKeys[0], /^0x[0-9a-f]{64}$/);
});

test("live check 01: IronTrellis's own skill is not referred to the user (exact name); another skill is as the policy says", () => {
  const s = guarded();
  const own = s.call("Skill", { skill: "irontrellis:irontrellis-handover" });
  assert.equal(own.code, 0, own.stderr);
  assert.equal(own.stdout, "", "no decision: the host's own permissions apply");
  assert.match(own.stderr, /irontrellis:irontrellis-handover is IronTrellis's own skill; not checked/);
  for (const skill of ["other:irontrellis-handover", "irontrellis:irontrellis-handover-x", "irontrellis-handover", "Irontrellis:irontrellis-handover"]) {
    const r = s.call("Skill", { skill });
    assert.equal(decision(r), "ask", `${skill}: ${r.stdout}`);
    assert.match(r.json.hookSpecificOutput.permissionDecisionReason, /no policy rule matches tool "Skill"/);
  }
  assert.equal(decision(s.call("Skill", { skill: ["irontrellis:irontrellis-handover"] })), "ask", "not a string: not the own skill");
});

test("live check 01: statusline prints one line for Claude Code's statusLine: not set up, declined, guarded by the plugin or the hook route", () => {
  const s = sandbox();
  const line = (stdin = "", extra) => { const r = s.run(["statusline"], { stdin, extra }); assert.equal(r.code, 0, r.stderr); return r.stdout; };
  assert.equal(line(), "IronTrellis: not set up\n");
  assert.equal(s.run(["choose", "1"]).code, 0);
  assert.equal(line(), "IronTrellis: declined for this project\n");
  assert.equal(s.run(["choose", "3"]).code, 0);
  assert.equal(line(), "IronTrellis: not set up (hook route chosen)\n");
  assert.equal(s.run(["choose", "--reset"]).code, 0);
  s.init();
  assert.equal(line(), "IronTrellis: set up, but not guarded (enable the IronTrellis plugin, or install the hook)\n");
  s.settings(join(s.project, ".claude", "settings.local.json"), { enabledPlugins: { "irontrellis@irontrellis": true } });
  assert.equal(line(), "IronTrellis: guarded (plugin route)\n");
  assert.equal(s.run(["install", "claude-code", "--write"]).code, 0);
  assert.equal(line(), "IronTrellis: guarded (hook route; the plugin steps aside)\n");
  s.settings(join(s.project, ".claude", "settings.local.json"), { enabledPlugins: [] });
  assert.equal(line(), "IronTrellis: guarded (hook route)\n");
  // Claude Code's statusLine JSON names the project: another, unset project reads as not set up.
  const other = join(s.root, "other"); mkdirSync(other);
  assert.equal(line(JSON.stringify({ session_id: "x", cwd: other, workspace: { current_dir: other, project_dir: other } }), { CLAUDE_PROJECT_DIR: "" }), "IronTrellis: not set up\n");
  assert.equal(line(JSON.stringify({ cwd: s.project }), { CLAUDE_PROJECT_DIR: "" }), "IronTrellis: guarded (hook route)\n");
  assert.equal(line("not json"), "IronTrellis: guarded (hook route)\n", "unreadable input: the working directory's project");
  // The agent may read it: statusline is not a control command.
  const g = guarded();
  assert.doesNotMatch(g.call("Bash", { command: "irontrellis-hook statusline" }).stdout, /deny/);
});

test("live check 01 and BRAND-001: a refusal says IronTrellis · DENY, then the plain fact: grant denials, protected calls, a guard that cannot check (exit 2), the plugin's choice refusals", () => {
  const s = guarded("write-file");
  const shell = s.call("Bash", { command: "ls" });
  assertDeny(shell, /^IronTrellis · DENY: claude-code may not run shell commands in project \([A-Z_]+; .*run-shell on repo:.*; head \d+\)$/);
  assertDeny(s.call("Write", { file_path: join(s.project, ".claude", "settings.json"), content: "{}" }), /^IronTrellis · DENY: protected: .*\(PROTECTED_PATH\)$/);
  // A tool event the guard cannot read: exit 2, and the text starts with "IronTrellis denied:".
  const unreadable = s.run(["claude-code", "PreToolUse"], { stdin: "not json", extra: s.extra });
  assert.equal(unreadable.code, 2);
  assert.match(unreadable.stderr, /^\nIronTrellis · DENY: stdin is not JSON \(PreToolUse\)/);
  // A non-blocking error is not called a denial.
  const stop = s.run(["claude-code", "Stop"], { stdin: "not json", extra: s.extra });
  assert.notEqual(stop.code, 2);
  assert.doesNotMatch(stop.stderr, /denied/);
});

test("item 4 (the coordinator's GO for proposal A): every Claude Code deny source exits 2, the reason on stderr and nothing on stdout, on both routes; none exits 0", () => {
  const seen = [];
  const check = (label, r) => {
    seen.push(label);
    assert.equal(r.code, 2, `${label}: exit ${r.code} ${r.stdout}${r.stderr}`);
    assert.equal(r.stdout, "", `${label}: stdout`);
    assert.match(r.stderr, /^\nIronTrellis · DENY: /, label);
  };
  // Not set up: the choice and setup refusals (the plugin route; there is no settings hook without a config).
  const u = sandbox();
  check("choice: choose 1", u.plugin("PreToolUse", ev.tool(u, "Bash", { command: "irontrellis-hook choose 1" })));
  check("choice: init", u.plugin("PreToolUse", ev.tool(u, "Bash", { command: "irontrellis-hook init --agent claude-code" })));
  check("choice: the choice file", u.plugin("PreToolUse", ev.tool(u, "Write", { file_path: u.choiceFile, content: "{}" })));
  check("setup: an irontrellis-hook.json", u.plugin("PreToolUse", ev.tool(u, "Write", { file_path: join(u.project, "irontrellis-hook.json"), content: "{}" })));
  // Guarded (write-file granted, run-shell not): both routes.
  const s = sandbox();
  s.init("write-file");
  const routes = [["plugin", (p) => s.plugin("PreToolUse", p)], ["hook", (p) => s.hook("PreToolUse", p)]];
  for (const [route, call] of routes) check(`${route}: the session was never started`, call(ev.tool(s, "Bash", { command: "ls" }, `never-${route}`)));
  s.plugin("SessionStart", ev.start(s));
  let n = 0;
  for (const [route, call] of routes) {
    const at = (tool, input) => call(ev.tool(s, tool, input, "cc-1", `toolu_walk${++n}`));
    check(`${route}: the policy (no run-shell grant)`, at("Bash", { command: "ls" }));
    check(`${route}: protective, the config`, at("Write", { file_path: join(s.project, "irontrellis-hook.json"), content: "{}" }));
    check(`${route}: protective, a control command`, at("Bash", { command: "irontrellis grant g --to x" }));
    check(`${route}: protective, setting IronTrellis up`, at("Bash", { command: "irontrellis-hook pin-runtime" }));
    check(`${route}: protective, Claude Code's settings`, at("Write", { file_path: join(s.project, ".claude", "settings.json"), content: "{}" }));
    check(`${route}: protective, the owner key`, at("Read", { file_path: `${historyOf(s)}.owner-key.json` }));
  }
  // A PreToolUse the guard cannot read is a refusal too (a blocking error).
  check("hook: unreadable", s.run(["claude-code", "PreToolUse"], { stdin: "not json" }));
  check("plugin: unreadable", s.run(["plugin", "claude-code", "PreToolUse"], { stdin: "not json" }));
  // The route-session check: the config this session was admitted under is gone.
  const config = join(s.project, "irontrellis-hook.json"), aside = join(s.root, "aside.json");
  renameSync(config, aside);
  check("plugin: the admitted route's config is gone", s.plugin("PreToolUse", ev.tool(s, "Bash", { command: "ls" }, "cc-1", "toolu_walk_gone")));
  renameSync(aside, config);
  // The read-only history and the clock refusals are walked in hook.test.mjs (exit 2 asserted there); the helper above
  // (claudeDeny) also fails any Claude Code deny anywhere in these files that comes back as JSON.
  assert.equal(seen.length, 21);
  // ask, allow and defer stay JSON at exit 0 (or no output): an unmapped tool is still an ask.
  const ask = s.hook("PreToolUse", ev.tool(s, "Deploy", { target: "prod" }, "cc-1", "toolu_walk_ask"));
  assert.equal(ask.code, 0); assert.equal(decision(ask), "ask");
});

test("post5-10 F1: the notice says what leaving without a choice does (also on the hook-route path); the agent still gets the sign-off sentence", () => {
  const s = sandbox();
  const leave = "If you leave without choosing, you'll see this again next time.";
  const start = s.plugin("SessionStart", ev.start(s));
  assert.equal(start.json.systemMessage.split("\n").at(-1), leave);
  assert.match(start.json.hookSpecificOutput.additionalContext, /If this session ends and the user has made no choice, say so when you sign off/);
  assert.equal(s.run(["choose", "3"]).code, 0);
  assert.equal(s.plugin("SessionStart", ev.start(s, "cc-2")).json.systemMessage.split("\n").at(-1), leave);
});

test("post5-10 F2: plain init where the IronTrellis plugin is enabled is on the plugin route (no hook install step); with the hook route chosen it keeps the step", () => {
  const s = sandbox();
  s.settings(join(s.project, ".claude", "settings.local.json"), { enabledPlugins: { "irontrellis@irontrellis": true } });
  const r = s.run(["init", "--agent", "claude-code"]);
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /^IronTrellis is set up here, and you're on the plugin route: the IronTrellis plugin is enabled, so no hook install is needed\. Start a new Claude Code session/);
  assert.doesNotMatch(r.stdout, /install claude-code/);
  assert.equal(JSON.parse(s.run(["init", "--agent", "claude-code", "--force", "--json"]).stdout).pluginRoute, true);
  const h = sandbox();
  h.settings(join(h.project, ".claude", "settings.local.json"), { enabledPlugins: { "irontrellis@irontrellis": true } });
  assert.equal(h.run(["choose", "3"]).code, 0);
  const hook = h.run(["init", "--agent", "claude-code"]);
  assert.equal(hook.code, 0, hook.stderr);
  assert.match(hook.stdout, /^IronTrellis is set up for .* \(Claude Code\)\.\n/);
  assert.match(hook.stdout, /next:\n {2}irontrellis-hook install claude-code --write/);
  // Another agent's init never looks at the Claude Code plugin.
  const codex = s.run(["init", "--agent", "codex", "--dir", join(s.root, "home")]);
  assert.equal(codex.code, 0, codex.stderr);
  assert.match(codex.stdout, /next:\n {2}irontrellis-hook install codex --write/);
});

test("post5-10 F4: init and choose 2 print a few plain lines by default (the warnings one sentence each, ~ for the home), --verbose every step and the full warnings", () => {
  const s = sandbox();
  const project = join(s.home, "work"); mkdirSync(project);
  const r = s.run(["choose", "2"], { cwd: project, extra: { CLAUDE_PROJECT_DIR: project, IRONTRELLIS_HOME: "" } });
  assert.equal(r.code, 0, r.stderr);
  const lines = r.stdout.split("\n");
  assert.equal(lines[0], "IronTrellis is set up here (the plugin route). Start a new Claude Code session in this project: the guard admits a session when it starts.");
  assert.match(lines[1], /^Its history and keys are in ~\/\.irontrellis\/projects\/[0-9a-f]{16}\/, outside the project: back that folder up separately\.$/);
  // The grant's resource keeps the project's full path (it is a name, not a path the shell expands); nothing else does.
  assert.match(r.stdout, new RegExp(` --resources repo:${project.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} --expires`));
  assert.ok(!r.stdout.replace(/ --resources repo:\S+/, "").includes(`${s.home}/`), "no full home path but the grant's resource");
  assert.doesNotMatch(r.stdout, /config .* written and verified|plugin runtime/, "the steps are behind --verbose");
  assert.match(r.stderr, /^\nWarnings \(irontrellis doctor ~\/\.irontrellis\/projects\/[0-9a-f]{16}\/history\.jsonl explains them; --verbose shows every note\):\n {2}- Same OS user: the agent runs as you, so it could read the owner key; here IronTrellis is a tripwire, not a boundary\.\n {2}- The next owner key is on this machine, beside the owner key: move it offline, or it cannot protect a rotation\.\n$/);
  assert.match(r.stdout, /\nPublish these where readers can check them independently of this file:\n/);
  const v = sandbox();
  const verbose = v.run(["choose", "2", "--verbose"]);
  assert.equal(verbose.code, 0, verbose.stderr);
  assert.match(verbose.stdout, /^irontrellis-hook init \(Claude Code\)\n {2}history .* created/);
  assert.match(verbose.stdout, /\n {2}plugin runtime .* written/);
  assert.match(verbose.stdout, /IronTrellis is set up here \(the plugin route\)\. Start a new Claude Code session in this project: the guard admits a session when it starts\.\n$/);
  assert.match(verbose.stderr, /WARNING: same-user layout/);
  assert.match(verbose.stderr, /move it offline; pre-rotation only protects you if the next key is not on this host/);
  // The disableAllHooks and env warnings stay, in one sentence each.
  const w = sandbox();
  w.settings(join(w.project, ".claude", "settings.json"), { disableAllHooks: true, env: { NODE_OPTIONS: "--x" } });
  const warned = w.run(["init", "--agent", "claude-code"]);
  assert.equal(warned.code, 0, warned.stderr);
  assert.match(warned.stderr, /\n {2}- .*\.claude\/settings\.json sets "disableAllHooks": true, so IronTrellis does not guard this project\.\n/);
  assert.match(warned.stderr, /\n {2}- .*\.claude\/settings\.json gives the hooks NODE_OPTIONS: check that you set it yourself\.\n/);
  // --json carries them too; a reused history (--force) has no new next key, so: same user, disableAllHooks, env.
  assert.equal(JSON.parse(w.run(["init", "--agent", "claude-code", "--force", "--json"]).stdout).notes.length, 3);
});

test("post5-10 F5: the statusline says guarded from the next session for a session the guard did not admit, guarded once it is", () => {
  const s = sandbox();
  s.settings(join(s.project, ".claude", "settings.local.json"), { enabledPlugins: { "irontrellis@irontrellis": true } });
  const line = (session) => { const r = s.run(["statusline"], { stdin: JSON.stringify({ session_id: session, cwd: s.project, workspace: { project_dir: s.project } }) }); assert.equal(r.code, 0, r.stderr); return r.stdout; };
  assert.equal(line("cc-1"), "IronTrellis: not set up\n");
  assert.equal(s.run(["choose", "2"]).code, 0);
  assert.equal(line("cc-1"), "IronTrellis: guarded from the next session (plugin route; this session is not admitted)\n");
  // A tool call in that session is refused (it was never admitted) and does not make it admitted.
  assertDeny(s.plugin("PreToolUse", ev.tool(s, "Write", { file_path: join(s.project, "a.txt"), content: "x" })), /SESSION_NOT_FOUND/);
  assert.equal(line("cc-1"), "IronTrellis: guarded from the next session (plugin route; this session is not admitted)\n");
  assert.equal(s.plugin("SessionStart", ev.start(s, "cc-2")).code, 0);
  assert.equal(line("cc-2"), "IronTrellis: guarded (plugin route)\n");
  // Without a session id (run by hand), as before.
  assert.equal(s.run(["statusline"]).stdout, "IronTrellis: guarded (plugin route)\n");
  // The hook route too; once the session ends its key is released and it is not admitted any more.
  assert.equal(s.run(["install", "claude-code", "--write"]).code, 0);
  assert.equal(line("cc-3"), "IronTrellis: guarded from the next session (hook route; the plugin steps aside; this session is not admitted)\n");
  assert.equal(s.hook("SessionEnd", { session_id: "cc-2", cwd: s.project, hook_event_name: "SessionEnd", reason: "exit" }).code, 0);
  assert.equal(line("cc-2"), "IronTrellis: guarded from the next session (hook route; the plugin steps aside; this session is not admitted)\n");
});

test("post5-10: the printed reader command quotes the history path when it needs it and keeps ~ unquoted, so the shell reads the path back", () => {
  const s = sandbox();
  for (const [history, expected] of [[join(s.home, "it's a dir", "h.jsonl"), "~/'it'\\''s a dir/h.jsonl'"], [join(s.root, "a b", "h.jsonl"), null]]) {
    const dir = join(s.root, `p${expected === null ? 2 : 1}`); mkdirSync(dir);
    const r = s.run(["init", "--agent", "codex", "--dir", dir, "--history", history]);
    assert.equal(r.code, 0, r.stderr);
    const command = /A reader checks them with: irontrellis (.*)\n$/.exec(r.stdout)[1];
    if (expected !== null) assert.ok(command.startsWith(`--history ${expected} verify`), command);
    const words = spawnSync("/bin/sh", ["-c", `printf '%s\\n' ${command}`], { encoding: "utf8", env: { HOME: s.home, PATH: "/usr/bin:/bin" } }).stdout.split("\n");
    assert.equal(words[0], "--history");
    assert.equal(words[1], history);
    assert.equal(words[2], "verify");
  }
});

test("post5-11: init says the history is outside the project for a sibling folder whose name starts with the project's (path, not prefix)", () => {
  const s = sandbox();
  const sibling = `${s.project}2`; mkdirSync(sibling);
  const r = s.run(["init", "--agent", "codex", "--history", join(sibling, "h.jsonl")]);
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /\nIts history and keys are in .*project2\/, outside the project: back that folder up separately\.\n/);
  const v = s.run(["init", "--agent", "codex", "--force", "--verbose", "--history", join(sibling, "h.jsonl")]);
  assert.match(v.stdout, /\nstate: .*project2 holds the history.*; it is outside the project and out of version control, so back it up separately\n/);
});

test("post5-12 (independent review A, RA-01): a path through a symlink then .. is checked where the file system takes it (file tools and shell)", () => {
  const s = guarded();
  mkdirSync(join(s.project, ".claude", "agents", "child"), { recursive: true });
  writeFileSync(join(s.project, ".claude", "agents", "reviewer.md"), "original\n");
  symlinkSync(join(s.project, ".claude", "agents", "child"), join(s.project, "link"));
  const raw = `${s.project}/link/../reviewer.md`; // as text: join/resolve would collapse the .. and lose the case
  assert.equal(readFileSync(raw, "utf8"), "original\n", "the OS reads .claude/agents/reviewer.md through it");
  s.denied("Write", { file_path: raw, content: "changed" }, "Write link/../reviewer.md");
  s.denied("Edit", { file_path: raw, old_string: "original", new_string: "changed" }, "Edit link/../reviewer.md");
  s.denied("Bash", { command: "printf changed > link/../reviewer.md" }, "Bash, relative to the project");
  s.denied("Bash", { command: `printf changed > ${raw}` }, "Bash, absolute");
  // A link chain, and a link whose target is relative, are followed too; an ordinary file beside the link is not protected.
  symlinkSync("link", join(s.project, "link2"));
  s.denied("Write", { file_path: `${s.project}/link2/../reviewer.md`, content: "x" }, "a chain of two links");
  mkdirSync(join(s.project, "docs", "deep"), { recursive: true });
  symlinkSync("deep", join(s.project, "docs", "rel"));
  s.notProtected("Write", { file_path: `${s.project}/docs/rel/../notes.md`, content: "x" }, "docs/rel/.. is docs/");
  assert.equal(readFileSync(join(s.project, ".claude", "agents", "reviewer.md"), "utf8"), "original\n");
});

test("post5-12 (independent review A, RA-01 and RA-07): in a project not set up, the choice file and the runtime pin are found from the event's cwd and through symlinks", () => {
  const s = sandbox();
  const other = join(s.root, "elsewhere"); mkdirSync(other);
  const choice = (file_path, cwd) => s.plugin("PreToolUse", { ...ev.tool(s, "Write", { file_path, content: "{}" }), cwd });
  // Relative to the event's cwd (the agent's), not the hook process's (the project).
  assertDeny(choice("route-choices.json", s.state), /route choice is the user's/);
  assertDeny(choice("plugin-runtime", s.state), /setting IronTrellis up is the user's act/);
  // Through a symlinked folder and ..
  mkdirSync(join(s.state, "sub"));
  symlinkSync(join(s.state, "sub"), join(other, "via"));
  assertDeny(choice(`${other}/via/../route-choices.json`, other), /route choice is the user's/);
  // An ordinary file elsewhere stays the host's to decide.
  assertQuiet(choice(join(other, "route-choices.json"), other));
});

test("post5-12 (independent review A, RA-06): with failOpen and a history that cannot be read, protected calls are still refused on both routes; ordinary calls get failOpen", () => {
  const s = sandbox();
  s.init("write-file");
  s.hook("SessionStart", ev.start(s));
  const configFile = join(s.project, "irontrellis-hook.json"), config = JSON.parse(readFileSync(configFile, "utf8"));
  writeFileSync(configFile, `${JSON.stringify({ ...config, failOpen: true }, null, 2)}\n`);
  const history = historyOf(s); renameSync(history, `${history}.aside`); // the history is gone
  writeFileSync(join(s.state, "plugin-runtime"), `${process.execPath}\n${realpathSync(BIN)}\n`, { mode: 0o600 });
  const viaWrapper = (call) => spawnSync("/bin/sh", ["-c", `${hookEntryProgram(process.execPath, realpathSync(BIN))} claude-code PreToolUse`], { cwd: s.project, input: JSON.stringify(call), encoding: "utf8", env: s.env });
  const viaLaunch = (call) => spawnSync("/bin/sh", [LAUNCH, "PreToolUse"], { cwd: s.project, input: JSON.stringify(call), encoding: "utf8", env: { HOME: s.home, IRONTRELLIS_HOME: s.state, CLAUDE_PROJECT_DIR: s.project, PATH: "/usr/bin:/bin" } });
  for (const [route, run] of [["hook", viaWrapper], ["plugin", viaLaunch]]) {
    for (const [label, tool, input, why] of [
      ["a control command", "Bash", { command: "irontrellis grant g --to claude-code --actions run-shell" }, /protected: IronTrellis control commands/],
      ["the Claude Code settings", "Write", { file_path: join(s.project, ".claude", "settings.json"), content: "{}" }, /PROTECTED_PATH|Claude Code's configuration/],
      ["the config", "Write", { file_path: configFile, content: "{}" }, /protected/],
    ]) {
      const r = run(ev.tool(s, tool, input));
      assert.equal(r.status, 2, `${route}, ${label}: exit ${r.status} ${r.stdout}${r.stderr}`);
      assert.equal(r.stdout, "", `${route}, ${label}: no failOpen message`);
      assert.match(r.stderr, why, `${route}, ${label}`);
    }
    const ordinary = run(ev.tool(s, "Write", { file_path: join(s.project, "a.txt"), content: "x" }));
    assert.equal(ordinary.status, 0, `${route}: ${ordinary.stderr}`);
    assert.match(JSON.parse(ordinary.stdout).systemMessage, /lets it through \("failOpen": true\)/, `${route}: an ordinary call is failOpen's`);
  }
});

test("post5-12 (independent review A, RA-04): with disableAllHooks the statusline says set up, but not guarded, on either route; choose --status warns", () => {
  const s = sandbox();
  s.init();
  s.settings(join(s.project, ".claude", "settings.local.json"), { enabledPlugins: { "irontrellis@irontrellis": true } });
  const line = () => s.run(["statusline"]).stdout;
  assert.equal(line(), "IronTrellis: guarded (plugin route)\n");
  s.settings(join(s.project, ".claude", "settings.json"), { disableAllHooks: true });
  assert.equal(line(), "IronTrellis: set up, but not guarded (Claude Code's disableAllHooks is on)\n");
  assert.match(s.run(["choose", "--status"]).stdout, /warning: Claude Code's "disableAllHooks": true is set, so no hook runs/);
  // A later settings file that turns it back off wins (user, then project, then local).
  s.settings(join(s.project, ".claude", "settings.local.json"), { enabledPlugins: { "irontrellis@irontrellis": true }, disableAllHooks: false });
  assert.equal(line(), "IronTrellis: guarded (plugin route)\n");
  s.settings(join(s.project, ".claude", "settings.local.json"), { enabledPlugins: { "irontrellis@irontrellis": true } });
  assert.equal(s.run(["install", "claude-code", "--write", "--allow-disabled"]).code, 0);
  assert.equal(line(), "IronTrellis: set up, but not guarded (Claude Code's disableAllHooks is on)\n", "the hook route too");
});

test("post5-12 (independent review A, RA-03): on the hook route, a call under another config than the session was admitted with is refused (CONFIG_CHANGED)", () => {
  const s = guarded("write-file");
  const alternate = join(s.root, "alternate.json"); cpSync(join(s.project, "irontrellis-hook.json"), alternate);
  const same = s.call("Write", { file_path: join(s.project, "a.txt"), content: "x" });
  assert.notEqual(decision(same), "deny", same.stderr);
  assertDeny(s.call("Write", { file_path: join(s.project, "b.txt"), content: "x" }, { IRONTRELLIS_HOOK_CONFIG: alternate }), /this session was admitted under the config .* \(CONFIG_CHANGED\)$/);
});

test("post5-12 (independent review A, RA-08, RA-09): a file tool's path is a literal name; on Linux a name in other case is another folder", () => {
  const s = guarded();
  symlinkSync(historyOf(s), join(s.project, "its.txt"));
  writeFileSync(join(s.project, "it's.txt"), "ordinary");
  s.notProtected("Write", { file_path: join(s.project, "it's.txt"), content: "x" }, "it's.txt is not its.txt");
  s.denied("Write", { file_path: join(s.project, "its.txt"), content: "x" }, "its.txt is the history (a symlink)");
  const upper = s.call("Bash", { command: "printf x > .CLAUDE/agents/a.md" }), bare = s.call("Bash", { command: "printf x > SETTINGS.JSON" });
  if (process.platform === "linux") {
    assert.doesNotMatch(upper.stdout + upper.stderr, /protected/, "Linux: .CLAUDE is another folder");
    assert.doesNotMatch(bare.stdout + bare.stderr, /protected/, "Linux: SETTINGS.JSON is another file");
  } else {
    assert.match(upper.json?.hookSpecificOutput?.permissionDecisionReason ?? "", /protected/, "macOS and Windows: the same folder");
  }
});

test("post5-12 (independent review A, RA-10, RA-11, D-01): a resource is 128 Unicode scalar values; the printed grant quotes --to; a symlinked spelling of the project renders the same resource", () => {
  const s = sandbox();
  // RA-10: a project path whose repo resource is at most 128 scalar values (and within the core's 256 UTF-8 bytes for an
  // Identifier) but more than 128 UTF-16 units.
  const ascii = "repo:".length + `${s.root}/`.length, emoji = Math.min(128 - ascii, Math.floor((256 - ascii) / 4));
  if (ascii + 2 * emoji > 128) {
    const project = join(s.root, "😀".repeat(emoji)); mkdirSync(project);
    assert.ok([...`repo:${project}`].length <= 128 && Buffer.byteLength(`repo:${project}`) <= 256 && `repo:${project}`.length > 128);
    const at = { cwd: project, extra: { CLAUDE_PROJECT_DIR: project } };
    assert.equal(s.run(["init", "--agent", "claude-code", "--allow", "write-file", "--expires", "+1d"], at).code, 0);
    s.run(["claude-code", "SessionStart"], { ...at, stdin: JSON.stringify({ ...ev.start(s, "u-1"), cwd: project }) });
    const r = s.run(["claude-code", "PreToolUse"], { ...at, stdin: JSON.stringify({ ...ev.tool(s, "Write", { file_path: join(project, "a.txt"), content: "x" }, "u-1"), cwd: project }) });
    assert.notEqual(decision(r), "ask", `the grant applies: ${r.stdout}${r.stderr}`);
    assert.notEqual(decision(r), "deny", r.stderr);
  }
  // RA-11: an agent id with a space is quoted in the printed grant.
  const two = sandbox();
  const printed = two.run(["init", "--agent", "claude-code", "--agent-id", "worker one"]);
  assert.equal(printed.code, 0, printed.stderr);
  assert.match(printed.stdout, / grant <id> --to 'worker one' --actions write-file /);
  // D-01: CLAUDE_PROJECT_DIR as a symlink to the project renders the same repo:<project> the grant names.
  const three = sandbox();
  three.init("write-file");
  const alias = join(three.root, "alias"); symlinkSync(three.project, alias);
  const via = { cwd: alias, extra: { CLAUDE_PROJECT_DIR: alias } };
  three.run(["claude-code", "SessionStart"], { ...via, stdin: JSON.stringify({ ...ev.start(three, "a-1"), cwd: alias }) });
  const w = three.run(["claude-code", "PreToolUse"], { ...via, stdin: JSON.stringify({ ...ev.tool(three, "Write", { file_path: join(alias, "a.txt"), content: "x" }, "a-1"), cwd: alias }) });
  assert.notEqual(decision(w), "deny", `through the alias: ${w.stderr}`);
});

test("post5-13 (independent review A, RA-14): before the choice file exists, a Write through a symlinked parent of the state home is refused, and a state home reached through a symlink still matches", () => {
  const s = sandbox();
  const write = (file_path, extra) => s.plugin("PreToolUse", ev.tool(s, "Write", { file_path, content: "{}" }), extra);
  // The review's reproduction: an alias (a symlink to the state home) inside the project, the choice file not there yet.
  const alias = join(s.project, "state-alias"); symlinkSync(s.state, alias);
  assert.equal(existsSync(s.choiceFile), false);
  assertDeny(write(join(alias, "route-choices.json")), /route choice is the user's/);
  assertDeny(write(join(alias, "plugin-runtime")), /setting IronTrellis up is the user's act/);
  assert.equal(existsSync(s.choiceFile), false);
  assert.match(s.run(["choose", "--status"]).stdout, /route:\s+undecided/);
  // IRONTRELLIS_HOME itself through a symlink: the real path of the missing file is refused too.
  const linkedHome = join(s.root, "linked-home"); symlinkSync(s.state, linkedHome);
  assertDeny(write(join(s.state, "route-choices.json"), { IRONTRELLIS_HOME: linkedHome }), /route choice is the user's/);
  assertDeny(write(join(linkedHome, "route-choices.json"), { IRONTRELLIS_HOME: s.state }), /route choice is the user's/);
  assert.equal(existsSync(s.choiceFile), false);
  // The coordinator's re-check (M02, M03): HOME reached through a symlink, no IRONTRELLIS_HOME, nothing there yet; the agent
  // names the physical spelling of the choice file and of the pin.
  const realHome = join(s.root, "real-home"); mkdirSync(realHome); const linkHome = join(s.root, "link-home"); symlinkSync(realHome, linkHome);
  const viaHome = { HOME: linkHome, IRONTRELLIS_HOME: "" };
  assertDeny(write(join(realHome, ".irontrellis", "route-choices.json"), viaHome), /route choice is the user's/);
  assertDeny(write(join(realHome, ".irontrellis", "plugin-runtime"), viaHome), /setting IronTrellis up is the user's act/);
  assertDeny(write(join(linkHome, ".irontrellis", "..", ".irontrellis", "route-choices.json"), viaHome), /route choice is the user's/);
  assert.equal(existsSync(join(realHome, ".irontrellis")), false);
});

test("post5-13 (live check B of the Codex route): init --agent codex warns when a Codex config turns hooks off; install codex gives PreToolUse 120 s; Codex refusals say to use your own terminal", () => {
  // The config reader.
  assert.equal(codexHooksSetting("[features]\nhooks = false\n"), false);
  assert.equal(codexHooksSetting("[features]\ncodex_hooks=false # old name\n"), false);
  assert.equal(codexHooksSetting("features.hooks = false\n[features]\nhooks = true\n"), true, "the last value wins");
  assert.equal(codexHooksSetting("[other]\nhooks = false\n# [features] hooks = false\n"), undefined);
  // init: the project's config and the user's (HOME/.codex, or CODEX_HOME); the project's overrides.
  const s = sandbox();
  s.settings(join(s.project, ".codex", "config.toml"), {}); writeFileSync(join(s.project, ".codex", "config.toml"), "[features]\nhooks = false\n");
  const r = s.run(["init", "--agent", "codex"]);
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stderr, /\n {2}- .*\.codex\/config\.toml turns Codex's hooks off \(\[features\] hooks = false\), so IronTrellis does not guard this project\.\n/);
  assert.match(s.run(["init", "--agent", "codex", "--force", "--verbose"]).stderr, /WARNING: .*\.codex\/config\.toml sets \[features\] hooks = false: Codex runs no hooks there/);
  const u = sandbox();
  mkdirSync(join(u.home, ".codex"), { recursive: true }); writeFileSync(join(u.home, ".codex", "config.toml"), "[features]\nhooks = false\n");
  assert.match(u.run(["init", "--agent", "codex"]).stderr, /turns Codex's hooks off/, "the user's config");
  mkdirSync(join(u.project, ".codex"), { recursive: true }); writeFileSync(join(u.project, ".codex", "config.toml"), "[features]\nhooks = true\n");
  assert.doesNotMatch(u.run(["init", "--agent", "codex", "--force"]).stderr, /turns Codex's hooks off/, "the project's config turns them back on");
  // install codex: PreToolUse 120 s (Codex lets a timed-out hook's call through).
  assert.equal(u.run(["install", "codex", "--write"]).code, 0);
  const written = JSON.parse(readFileSync(join(u.project, ".codex", "hooks.json"), "utf8")).hooks;
  assert.deepEqual(Object.fromEntries(Object.entries(written).map(([e, g]) => [e, g[0].hooks[0].timeout])), { SessionStart: 30, PreToolUse: 120, Stop: 30, SessionEnd: 3 });
  // Under Codex an operator command is refused without Claude Code's ! advice.
  const c = sandbox();
  assert.equal(c.run(["init", "--agent", "codex", "--allow", "run-shell", "--expires", "+1d", RISK]).code, 0);
  c.run(["codex", "SessionStart"], { stdin: JSON.stringify({ ...ev.start(c, "x-1"), model: "m" }) });
  for (const cmd of ["irontrellis-hook choose 1", "irontrellis-hook init --agent codex", "irontrellis-hook pin-runtime"]) {
    const d = c.run(["codex", "PreToolUse"], { stdin: JSON.stringify({ ...ev.tool(c, "Bash", { command: cmd }, "x-1"), model: "m" }) });
    const reason = JSON.parse(d.stdout).hookSpecificOutput.permissionDecisionReason;
    assert.match(reason, /installation policy: only you, the human operator, may .*Run it yourself in your own terminal\./, cmd);
    assert.doesNotMatch(reason, /`!|! irontrellis-hook/, `${cmd}: no ! prefix under Codex`);
  }
});

