// Block 4 phase B: `irontrellis doctor`, through the built CLI. Every finding code, each at the level the plan gives
// it, with the fix; read-only (no file changes, no signature asked of an agent, no command signer started); exit 0
// without a FAIL, 1 with one, 2 on a usage error; --as-agent (and a REAL second OS user when this runs as root).
// The Vault findings are in custody-vault.test.mjs. Build first (pnpm -r build).
import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { commandSignerScript, fakeKey, haveOpenSsh, scratchDir, sshKeygen, startFakeAgent, startSshAgent } from "../../core/test/helpers/ssh-agent.mjs";
import { startFakeWitness } from "../../core/test/helpers/fake-witness.mjs";

const here = fileURLToPath(new URL(".", import.meta.url));
const BIN = resolve(here, "../bin/irontrellis.mjs");
assert.ok(existsSync(resolve(here, "../dist/doctor.js")), "build the package first: pnpm build");
const core = await import("@ramex-labs/irontrellis");
const { LEGACY, olderHistory } = await import("./older-formats.mjs");
const { sizeFindings, platformFindings, witnessStateFindings, SUCCESSOR_EVENTS } = await import("../dist/doctor.js");
const skipNoSsh = haveOpenSsh ? {} : { skip: "OpenSSH is not installed" };
const isRoot = typeof process.getuid === "function" && process.getuid() === 0;

/** The CLI in a child process (never blocking this one: fake agents and witnesses run here). */
const cli = (args, env = {}, options = {}) => new Promise((done) => {
  const child = spawn(process.execPath, [BIN, ...args], { env: { ...process.env, NO_COLOR: "1", IRONTRELLIS_HOOK_CONFIG: "", ...env }, ...options });
  let stdout = "", stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  child.on("close", (code) => {
    let value;
    try { value = JSON.parse(stdout); } catch { value = undefined; }
    done({ code, stdout, stderr, value });
  });
});
const ok = (r, what = "expected exit 0") => { assert.equal(r.code, 0, `${what}\n${r.stdout}\n${r.stderr}`); return r; };
const doctor = async (history, extra = [], env = {}, options = {}) => {
  const r = await cli(["doctor", history, "--json", ...extra], env, options);
  assert.ok(r.value !== undefined, `doctor printed no JSON:\n${r.stdout}\n${r.stderr}`);
  return { ...r, findings: r.value.findings, codes: r.value.findings.map((f) => `${f.level} ${f.code}`), find: (code) => r.value.findings.find((f) => f.code === code) };
};
/** `level code` must be among the findings; returns the finding. */
const has = (d, level, code) => {
  const hit = d.findings.find((f) => f.code === code && f.level === level);
  assert.ok(hit !== undefined, `expected ${level} ${code}; got:\n${d.codes.join("\n")}`);
  if (level !== "OK") assert.ok(typeof hit.fix === "string" && hit.fix.length > 10, `${code} has a fix`);
  return hit;
};
/** Every file under `dir`: size and mtime (doctor must change none, and create none). */
const snapshot = (dir) => {
  const out = {};
  const walk = (d) => { for (const name of readdirSync(d)) { const p = join(d, name); const st = statSync(p); if (st.isDirectory()) walk(p); else if (!st.isSocket()) out[p] = `${st.size}:${st.mtimeMs}`; } };
  walk(dir);
  return out;
};

// ---------------------------------------------------------------- pure checks

test("doctor units: history size against the successor guideline and the hard limit; platform notes (win32 mode checks off, root); the witness state", () => {
  const f1 = core.TRELLIS_FORMAT, limit = core.HISTORY_FILE_LIMITS[f1];
  assert.deepEqual(sizeFindings(10_000, 12, f1).map((f) => `${f.level} ${f.code}`), ["OK HISTORY_SIZE"]);
  assert.deepEqual(sizeFindings(10_000, SUCCESSOR_EVENTS, f1).map((f) => `${f.level} ${f.code}`), ["WARN HISTORY_SUCCESSOR_ADVISED"]);
  assert.deepEqual(sizeFindings(501 * 1024 * 1024, 10, f1).map((f) => `${f.level} ${f.code}`), ["WARN HISTORY_SUCCESSOR_ADVISED"]);
  const near = sizeFindings(Math.ceil(limit * 0.95), 10, f1);
  assert.deepEqual(near.map((f) => `${f.level} ${f.code}`), ["FAIL HISTORY_NEAR_FILE_LIMIT"]);
  assert.match(near[0].fix, /successor/);
  assert.deepEqual(sizeFindings(40 * 1024 * 1024, 10, core.LEGACY_FORMAT).map((f) => f.code), ["HISTORY_SUCCESSOR_ADVISED"], "legacy: half of its 64 MiB limit");
  const win = platformFindings("win32", undefined);
  assert.deepEqual(win.map((f) => `${f.level} ${f.code}`), ["WARN PLATFORM_WIN32_MODES_OFF"]);
  assert.match(win[0].message, /0600 mode and owner-uid checks .* are off/);
  assert.match(win[0].fix, /icacls/);
  assert.deepEqual(platformFindings("linux", 1000).map((f) => f.code), ["PLATFORM_POSIX"]);
  assert.deepEqual(platformFindings("darwin", 0).map((f) => `${f.level} ${f.code}`), ["OK PLATFORM_POSIX", "WARN RUNNING_AS_ROOT"]);
  const quiet = { rotationIncomplete: false, unwitnessedEvents: 0, witnesses: [{ url: "https://w.example", bound: true, registered: true }] };
  assert.deepEqual(witnessStateFindings(quiet), []);
  const loud = witnessStateFindings({
    alarm: { code: "ROLLBACK_DETECTED", message: "the witness holds a later head" }, rejected: { url: "https://w.example", code: "UNAUTHORIZED", message: "bad token" },
    rotationPending: { position: 9 }, rotationIncomplete: true, unwitnessedEvents: 3,
    witnesses: [{ url: "http://w.example:8080", bound: true, registered: false }, { url: "http://127.0.0.1:9", bound: true, registered: true }, { url: "http://x.example", bound: false, registered: false }],
  });
  assert.deepEqual(loud.map((f) => `${f.level} ${f.code}`), ["FAIL WITNESS_ALARM", "FAIL WITNESS_REJECTED", "WARN ROTATION_PENDING", "WARN ROTATION_INCOMPLETE", "WARN UNWITNESSED_EVENTS", "WARN WITNESS_INSECURE_HTTP", "WARN WITNESS_UNREGISTERED"]);
  for (const f of loud) assert.ok(f.fix.length > 5, f.code);
});

// ---------------------------------------------------------------- key files on the host

test("doctor on a default history (key files): custody, readable key material, no witness, no hooks; read-only; --as-agent makes readable key material a FAIL (exit 1); usage errors exit 2", async (t) => {
  const dir = scratchDir(t, "itdoc-");
  const history = join(dir, "h.jsonl");
  ok(await cli(["init", "--history", history]));
  const init = await cli(["init", "--history", join(dir, "h2.jsonl")]);
  assert.match(init.stdout, /irontrellis doctor .*h2\.jsonl/, "init points at doctor");
  const before = snapshot(dir);
  const d = await doctor(history);
  assert.equal(d.code, 0, d.stdout);
  assert.deepEqual(snapshot(dir), before, "doctor wrote nothing");
  has(d, "OK", "PLATFORM_POSIX");
  if (isRoot) has(d, "WARN", "RUNNING_AS_ROOT");
  has(d, "OK", "HISTORY_SIZE");
  has(d, "OK", "HISTORY_VERIFIES");
  has(d, "WARN", "OWNER_KEY_FILE_ON_HOST");
  has(d, "WARN", "NEXT_KEY_ON_HOST");
  assert.match(has(d, "WARN", "KEY_MATERIAL_READABLE").fix, /another OS user.*CUSTODY\.md §8/);
  has(d, "OK", "WITNESS_POLICY_NOT_SET");
  has(d, "WARN", "NO_WITNESS");
  has(d, "WARN", "HOOKS_NOT_FOUND");
  assert.equal(d.value.ok, true);
  assert.deepEqual(d.value.summary, { ok: d.findings.filter((f) => f.level === "OK").length, warn: d.findings.filter((f) => f.level === "WARN").length, fail: 0 });
  // Human output: levels, codes and fixes.
  const human = await cli(["doctor", "--history", history]);
  assert.equal(human.code, 0);
  assert.match(human.stdout, /WARN {2}OWNER_KEY_FILE_ON_HOST/);
  assert.match(human.stdout, /fix: /);
  assert.match(human.stdout, /\d+ OK · \d+ WARN · 0 FAIL/);
  assert.equal((await cli(["doctor"], { IRONTRELLIS_HISTORY: history })).code, 0, "IRONTRELLIS_HISTORY names it too");
  // As the agent's user: the same readable key material is a FAIL.
  const agentView = await doctor(history, ["--as-agent"]);
  assert.equal(agentView.code, 1);
  assert.equal(agentView.value.asAgent, true);
  has(agentView, "FAIL", "KEY_MATERIAL_READABLE");
  // A key file readable by others: a FAIL of its own (and the loader refuses it: custody says unreadable).
  chmodSync(`${history}.owner-key.json`, 0o644);
  const loose = await doctor(history);
  assert.equal(loose.code, 1);
  has(loose, "FAIL", "KEY_FILE_MODE");
  has(loose, "WARN", "KEY_FILE_UNREADABLE");
  chmodSync(`${history}.owner-key.json`, 0o600);
  // No commitment: commit-next-key was never run on this one.
  const bare = join(dir, "bare.jsonl");
  ok(await cli(["init", "--history", bare, "--no-next-key"]));
  has(await doctor(bare), "WARN", "NO_NEXT_KEY_COMMITMENT");
  // Usage errors: 2.
  assert.equal((await cli(["doctor", history, "extra"])).code, 2);
  assert.equal((await cli(["doctor", history, "--history", history])).code, 2);
  assert.equal((await cli(["doctor"], { IRONTRELLIS_HISTORY: "" })).code, 2);
  assert.equal((await cli(["doctor", history, "--no-such-flag"])).code, 2);
  const help = await cli(["doctor", "--help"]);
  assert.match(help.stdout, /--as-agent/);
  assert.match((await cli(["--help"])).stdout, /doctor/);
});

test("doctor FAILs: no history, an unreadable history, a history that does not verify; legacy histories have no custody; after a rotation the retired key file is reported", async (t) => {
  const dir = scratchDir(t, "itdoc-");
  const missing = await doctor(join(dir, "none.jsonl"));
  assert.equal(missing.code, 1);
  has(missing, "FAIL", "HISTORY_NOT_FOUND");
  writeFileSync(join(dir, "garbage.jsonl"), "this is not a history\n");
  const garbage = await doctor(join(dir, "garbage.jsonl"));
  assert.equal(garbage.code, 1);
  has(garbage, "FAIL", "HISTORY_UNREADABLE");
  // A pin whose attestation was tampered with.
  const history = join(dir, "h.jsonl");
  ok(await cli(["init", "--history", history]));
  ok(await cli(["agent", "create", "bea", "--history", history]));
  const pin = JSON.parse(readFileSync(`${history}.head`, "utf8"));
  pin.attestation.signature = `0x${"00".repeat(64)}`;
  writeFileSync(`${history}.head`, JSON.stringify(pin), { mode: 0o600 });
  const bad = await doctor(history);
  assert.equal(bad.code, 1);
  assert.match(has(bad, "FAIL", "HISTORY_VERIFY_FAILED").message, /PIN_ATTESTATION/);
  // Legacy.
  const legacy = await olderHistory(join(dir, "legacy.jsonl"), LEGACY);
  const l = await doctor(legacy);
  has(l, "WARN", "LEGACY_FORMAT");
  assert.ok(!l.findings.some((f) => f.area === "custody" && f.code !== "LEGACY_FORMAT"));
  // A rotation with the next key file: the retired key's file stays on the host.
  const r = join(dir, "r.jsonl");
  ok(await cli(["init", "--history", r]));
  ok(await cli(["owner", "rotate-key", "--history", r]));
  const rotated = await doctor(r);
  has(rotated, "WARN", "RETIRED_KEY_FILE");
  assert.match(has(rotated, "WARN", "KEY_MATERIAL_READABLE").message, /retired/);
});

// ---------------------------------------------------------------- hooks and the witness policy

test("doctor and the hooks: config not found, invalid, for another history, not installed, installed; the protect list covers the signer paths, and a retired reference's signer is a gap; the witness policy variable", async (t) => {
  const dir = scratchDir(t, "itdoc-");
  const project = join(dir, "project");
  mkdirSync(project);
  const history = join(dir, "h.jsonl");
  const pair = core.generateKeyPair("ed25519", "owner:1");
  const program = commandSignerScript(dir, pair.privateKey, "ok");
  ok(await cli(["init", "--history", history, "--signer", "command", "--public-key", pair.credential, "--signer-command", JSON.stringify([process.execPath, program]), "--no-next-key"]));
  const config = join(project, "irontrellis-hook.json");
  const hooks = (extra = {}) => doctor(history, ["--offline"], extra, { cwd: project });
  has(await hooks(), "WARN", "HOOKS_NOT_FOUND");
  writeFileSync(config, "{ not json");
  has(await hooks(), "WARN", "HOOKS_CONFIG_INVALID");
  writeFileSync(config, JSON.stringify({ version: "irontrellis-hook-config/1", history: join(dir, "other.jsonl") }));
  has(await hooks(), "WARN", "HOOKS_OTHER_HISTORY");
  writeFileSync(config, JSON.stringify({ version: "irontrellis-hook-config/1", history: "../h.jsonl" }));
  const notInstalled = await hooks();
  // The remedy names the command as it runs: the agent is a positional argument (there is no --protocol flag).
  const remedy = JSON.stringify(has(notInstalled, "WARN", "HOOKS_NOT_INSTALLED"));
  assert.match(remedy, /irontrellis-hook install claude-code\|codex\|cursor --write/);
  assert.doesNotMatch(remedy, /--protocol/);
  assert.match(has(notInstalled, "OK", "HOOKS_PROTECT_COVERS").message, new RegExp(program.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  mkdirSync(join(project, ".claude"));
  writeFileSync(join(project, ".claude", "settings.json"), JSON.stringify({ hooks: { PreToolUse: [{ hooks: [{ type: "command", command: "irontrellis-hook pre-tool-use" }] }] } }));
  assert.match(has(await hooks(), "OK", "HOOKS_INSTALLED").message, /Claude Code/);
  // post5-13 (live check B of the Codex route): Codex hooks installed, but a Codex config turns hooks off; the project's wins.
  mkdirSync(join(project, ".codex"));
  writeFileSync(join(project, ".codex", "hooks.json"), JSON.stringify({ hooks: { PreToolUse: [{ hooks: [{ type: "command", command: "irontrellis-hook codex PreToolUse" }] }] } }));
  const codexHome = join(dir, "codex-home"); mkdirSync(codexHome);
  writeFileSync(join(codexHome, "config.toml"), "[features]\nhooks = false\n");
  assert.match(has(await hooks({ CODEX_HOME: codexHome }), "WARN", "HOOKS_DISABLED").message, /config\.toml sets \[features\] hooks = false: Codex runs no hooks/);
  writeFileSync(join(project, ".codex", "config.toml"), "[features]\nhooks = true\n");
  assert.equal((await hooks({ CODEX_HOME: codexHome })).stdout.includes("HOOKS_DISABLED"), false, "the project's config turns them back on");
  rmSync(join(project, ".codex"), { recursive: true });
  // The two Claude Code routes (hooks/src/route.ts): that entry is not the one install writes, so it is flagged; the plugin
  // route counts as installed; the plugin and the exact hook entries together are flagged as installed twice.
  has(await hooks(), "WARN", "HOOKS_ENTRY_UNRECOGNIZED");
  const userHome = join(dir, "home");
  mkdirSync(join(userHome, ".claude"), { recursive: true });
  writeFileSync(join(userHome, ".claude", "settings.json"), JSON.stringify({ enabledPlugins: { "irontrellis@irontrellis": true } }));
  // install's form: this node and the hooks package's launcher, by absolute path (the old bare command is not recognized).
  const launcher = realpathSync(fileURLToPath(new URL("../../hooks/bin/irontrellis-hook.mjs", import.meta.url)));
  const hooksPackage = await import(new URL("../../hooks/dist/index.js", import.meta.url).href);
  const doctorModule = await import(new URL("../dist/doctor.js", import.meta.url).href);
  assert.equal(doctorModule.HOOK_WRAPPER, hooksPackage.HOOK_WRAPPER, "doctor's copy of the hook wrapper is the hooks package's");
  const exactEntry = (event, timeout) => [{ hooks: [{ type: "command", command: `${hooksPackage.hookEntryProgram(process.execPath, launcher)} claude-code ${event}`, timeout }] }];
  const settingsPath = join(project, ".claude", "settings.json"), original = readFileSync(settingsPath, "utf8");
  writeFileSync(settingsPath, JSON.stringify({ hooks: { SessionStart: exactEntry("SessionStart", 30), PreToolUse: exactEntry("PreToolUse", 30), Stop: exactEntry("Stop", 30), SessionEnd: exactEntry("SessionEnd", 10) } }));
  const twice = await hooks({ HOME: userHome });
  has(twice, "WARN", "HOOKS_INSTALLED_TWICE");
  assert.equal(twice.stdout.includes("HOOKS_ENTRY_UNRECOGNIZED"), false, "the exact entries are recognized");
  const bare = (event, timeout) => [{ hooks: [{ type: "command", command: `irontrellis-hook claude-code ${event}`, timeout }] }];
  writeFileSync(settingsPath, JSON.stringify({ hooks: { SessionStart: bare("SessionStart", 30), PreToolUse: bare("PreToolUse", 30), Stop: bare("Stop", 30), SessionEnd: bare("SessionEnd", 10) } }));
  assert.equal((await hooks({ HOME: userHome })).stdout.includes("HOOKS_INSTALLED_TWICE"), false, "the old bare command is not the hook route");
  has(await hooks({ HOME: userHome }), "WARN", "HOOKS_ENTRY_UNRECOGNIZED");
  const configHome = join(dir, "claude-config"); mkdirSync(configHome);
  writeFileSync(join(configHome, "settings.json"), JSON.stringify({ enabledPlugins: { "irontrellis@irontrellis": true } }));
  writeFileSync(settingsPath, "{}");
  assert.match(has(await hooks({ CLAUDE_CONFIG_DIR: configHome }), "OK", "HOOKS_INSTALLED").message, /the IronTrellis plugin/, "CLAUDE_CONFIG_DIR holds the user's settings");
  writeFileSync(settingsPath, "{}");
  assert.match(has(await hooks({ HOME: userHome }), "OK", "HOOKS_INSTALLED").message, /the IronTrellis plugin/);
  writeFileSync(settingsPath, original);
  // --hook-config and IRONTRELLIS_HOOK_CONFIG name it from anywhere.
  has(await doctor(history, ["--offline", "--hook-config", config]), "OK", "HOOKS_INSTALLED");
  has(await doctor(history, ["--offline"], { IRONTRELLIS_HOOK_CONFIG: config }), "OK", "HOOKS_INSTALLED");
  // A retired key reference: the hooks derive its signer too (a retired key still signs head statements a witness accepts).
  const oldProgram = join(dir, "old-kms-sign.mjs");
  writeFileSync(`${history}.owner-key.owner-0.retired.json`, JSON.stringify({ version: "irontrellis-owner-key-ref/1", keyId: "owner:0", scheme: "ed25519", publicKey: core.generateKeyPair("ed25519", "x").credential, signer: { kind: "command", argv: [oldProgram] } }), { mode: 0o600 });
  const gap = await hooks();
  assert.match(has(gap, "OK", "HOOKS_PROTECT_COVERS").message, /old-kms-sign/);
  // The out-of-band witness policy: not set (above), relative, missing (FAIL), writable by others, fine.
  has(await hooks({ IRONTRELLIS_WITNESS_POLICY: "policy.json" }), "WARN", "WITNESS_POLICY_RELATIVE");
  const missingPolicy = await hooks({ IRONTRELLIS_WITNESS_POLICY: join(dir, "missing-policy.json") });
  assert.equal(missingPolicy.code, 1);
  has(missingPolicy, "FAIL", "WITNESS_POLICY_MISSING");
  const policy = join(dir, "irontrellis-witness-policy.json");
  writeFileSync(policy, JSON.stringify({ quorum: 1 }), { mode: 0o666 });
  chmodSync(policy, 0o666);
  const writable = await hooks({ IRONTRELLIS_WITNESS_POLICY: policy });
  has(writable, "WARN", "WITNESS_POLICY_WRITABLE");
  chmodSync(policy, 0o644);
  has(await hooks({ IRONTRELLIS_WITNESS_POLICY: policy }), "OK", "WITNESS_POLICY");
  has(await doctor(history, ["--offline", "--as-agent"], { IRONTRELLIS_WITNESS_POLICY: policy }, { cwd: project }), "FAIL", "WITNESS_POLICY_WRITABLE");
});

// ---------------------------------------------------------------- signers: never asked to sign

test("doctor with the owner key in an ssh-agent only LISTS identities: reachable, key not listed, unreachable, no socket, --offline, --as-agent; a loose reference is refused", skipNoSsh, async (t) => {
  const dir = scratchDir(t, "itdoc-");
  const one = fakeKey(core.generateKeyPair, "owner:1"), two = fakeKey(core.generateKeyPair, "owner:2");
  const agent = await startFakeAgent(t, dir, { keys: [one, two] });
  const history = join(dir, "h.jsonl");
  const env = { SSH_AUTH_SOCK: agent.socket };
  ok(await cli(["init", "--history", history, "--signer", "ssh-agent", "--public-key", one.pair.credential, "--next-public-key", two.pair.credential], env));
  const signed = agent.requests.length;
  assert.ok(signed > 0, "init signed through the agent");
  const before = snapshot(dir);
  const d = await doctor(history, [], env);
  assert.equal(d.code, 0, d.stdout);
  assert.equal(agent.requests.length, signed, "doctor asked the agent for no signature");
  assert.deepEqual(snapshot(dir), before);
  has(d, "OK", "OWNER_KEY_REFERENCE");
  has(d, "OK", "NEXT_KEY_OFF_HOST");
  has(d, "OK", "NO_KEY_MATERIAL_ON_HOST");
  assert.match(has(d, "OK", "SIGNER_REACHABLE").message, /lists the key \(only listed; nothing was signed\)/);
  // As the agent's user with the owner's agent socket (review block 4, H2): a FAIL, from the reference and from the environment.
  const agentView = await doctor(history, ["--as-agent"], env);
  assert.equal(agentView.code, 1);
  has(agentView, "FAIL", "SIGNER_USABLE_BY_THIS_USER");
  has(agentView, "FAIL", "SSH_AGENT_HOLDS_OWNER_KEY");
  assert.equal(agent.requests.length, signed, "still no sign request: identities are only listed");
  has(await doctor(history, ["--offline"], env), "OK", "SIGNER_NOT_CHECKED");
  has(await doctor(history, [], { SSH_AUTH_SOCK: "" }), "WARN", "SIGNER_UNREACHABLE");
  has(await doctor(history, ["--as-agent"], { SSH_AUTH_SOCK: "" }), "OK", "SIGNER_NOT_REACHABLE");
  const other = await startFakeAgent(t, dir, { keys: [two], name: "other.sock" });
  has(await doctor(history, [], { SSH_AUTH_SOCK: other.socket }), "WARN", "SIGNER_KEY_NOT_LISTED");
  has(await doctor(history, ["--as-agent"], { SSH_AUTH_SOCK: other.socket }), "OK", "SIGNER_KEY_NOT_LISTED");
  assert.equal(other.requests.length, 0);
  has(await doctor(history, [], { SSH_AUTH_SOCK: join(dir, "no-agent.sock") }), "WARN", "SIGNER_UNREACHABLE");
  chmodSync(`${history}.owner-key.json`, 0o644);
  // A reference the loaders refuse (review block 4, H1 and M3): a FAIL, and its signer is never contacted.
  const connections = { count: 0 };
  const watched = await startFakeAgent(t, dir, { keys: [one, two], name: "watched.sock" });
  watched.server.on("connection", () => { connections.count += 1; });
  const loose = JSON.parse(readFileSync(`${history}.owner-key.json`, "utf8"));
  loose.signer = { kind: "ssh-agent", socket: watched.socket };
  writeFileSync(`${history}.owner-key.json`, JSON.stringify(loose), { mode: 0o644 });
  chmodSync(`${history}.owner-key.json`, 0o644);
  const refused = await doctor(history, [], env);
  assert.equal(refused.code, 1);
  assert.match(has(refused, "FAIL", "REFERENCE_REFUSED").message, /its signer was not contacted/);
  assert.equal(connections.count, 0, "the socket named by the refused reference received no connection");
  assert.ok(!refused.findings.some((f) => f.area === "signer"), "no signer finding for a refused reference");
  chmodSync(`${history}.owner-key.json`, 0o600);
});

test("doctor with a real ssh-agent holding both keys: NEXT_KEY_SAME_SIGNER and the next key's signer checked by listing", skipNoSsh, async (t) => {
  const dir = scratchDir(t, "itdoc-");
  const agent = await startSshAgent(t, dir);
  const k1 = sshKeygen(dir, "o1"), k2 = sshKeygen(dir, "o2");
  agent.add(k1.file);
  agent.add(k2.file);
  const history = join(dir, "h.jsonl");
  const env = { SSH_AUTH_SOCK: agent.socket };
  ok(await cli(["signer", "ref", "--out", join(dir, "next.ref"), "--next", "--key-id", "owner:2", "--signer", "ssh-agent", "--public-key", k2.pub], env));
  ok(await cli(["init", "--history", history, "--signer", "ssh-agent", "--public-key", k1.pub, "--next-key-ref", join(dir, "next.ref")], env));
  const d = await doctor(history, [], env);
  has(d, "WARN", "NEXT_KEY_SAME_SIGNER");
  assert.equal(d.findings.filter((f) => f.code === "SIGNER_REACHABLE").length, 2, "current and next key listed");
});

test("doctor with a command signer never starts it (not checked); a missing program; --as-agent", async (t) => {
  const dir = scratchDir(t, "itdoc-");
  const pair = core.generateKeyPair("ed25519", "owner:1");
  const log = join(dir, "purposes.log");
  const program = commandSignerScript(dir, pair.privateKey, "ok", "logging.mjs", { logFile: log });
  const history = join(dir, "h.jsonl");
  ok(await cli(["init", "--history", history, "--signer", "command", "--public-key", pair.credential, "--signer-command", JSON.stringify([program]), "--no-next-key"]));
  writeFileSync(log, "");
  const d = await doctor(history);
  assert.match(has(d, "OK", "SIGNER_NOT_CHECKED").message, /only started to sign/);
  assert.equal(readFileSync(log, "utf8"), "", "the signing program was never started");
  has(await doctor(history, ["--as-agent"]), "WARN", "SIGNER_USABLE_BY_THIS_USER");
  const ref = JSON.parse(readFileSync(`${history}.owner-key.json`, "utf8"));
  ref.signer.argv = [join(dir, "gone.mjs")];
  writeFileSync(`${history}.owner-key.json`, JSON.stringify(ref), { mode: 0o600 });
  has(await doctor(history), "WARN", "SIGNER_PROGRAM_MISSING");
  assert.equal(readFileSync(log, "utf8"), "");
});

// ---------------------------------------------------------------- witnesses

test("doctor and a bound witness: reachable (one GET /v1/witness), down, --offline, and a URL now serving another witness key (FAIL)", async (t) => {
  const dir = scratchDir(t, "itdoc-");
  const w = await startFakeWitness({ name: "doctor-witness" });
  let wOpen = true;
  t.after(() => (wOpen ? w.close() : undefined));
  const history = join(dir, "h.jsonl");
  ok(await cli(["init", "--history", history, "--witness", w.url, "--verifier-key", w.verifierKey, "--mode", "sync"]));
  const before = snapshot(dir);
  const asked = w.state.requests.length;
  const d = await doctor(history);
  assert.equal(d.code, 0, d.stdout);
  assert.deepEqual(snapshot(dir), before, "doctor wrote nothing (witness side file included)");
  assert.deepEqual(w.state.requests.slice(asked), ["GET /v1/witness"], "one read-only request");
  has(d, "OK", "WITNESS_REACHABLE");
  assert.match(has(d, "OK", "WITNESS_BOUND").message, /1 bound witness/);
  has(await doctor(history, ["--offline"]), "OK", "WITNESS_NOT_CHECKED");
  w.down = true;
  has(await doctor(history), "WARN", "WITNESS_UNREACHABLE");
  w.down = false;
  // Another witness answering at the bound URL.
  const port = Number(new URL(w.url).port);
  await w.close();
  wOpen = false;
  const impostor = createServer((req, res) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ version: "irontrellis-witness/1", origin: "impostor", verifierKey: "impostor+00000000+AAAA" })); });
  await new Promise((done) => impostor.listen(port, "127.0.0.1", done));
  t.after(() => new Promise((done) => impostor.close(done)));
  const mismatch = await doctor(history);
  assert.equal(mismatch.code, 1);
  has(mismatch, "FAIL", "WITNESS_KEY_MISMATCH");
});

// ---------------------------------------------------------------- a real second OS user

test("doctor run as another OS user (the agent's), with --as-agent: it cannot read the owner key material (OK); without read access to the history the hooks could not work (FAIL, with the fix)", { skip: isRoot ? false : "needs root to run a child as another OS user" }, async (t) => {
  const dir = scratchDir(t, "itdoc-");
  chmodSync(dir, 0o755);
  const history = join(dir, "h.jsonl");
  ok(await cli(["init", "--history", history]));
  const asNobody = (extra = []) => doctor(history, ["--as-agent", "--offline", ...extra], { PATH: process.env.PATH, HOME: "/nonexistent" }, { uid: 65534, gid: 65534, cwd: dir });
  const denied = await asNobody();
  assert.equal(denied.code, 1);
  assert.match(has(denied, "FAIL", "HISTORY_UNREADABLE").fix, /hooks run as the agent's OS user/);
  // The recipe: the history and its pin readable by the agent's user, the key files 0600 and the owner's.
  for (const name of readdirSync(dir)) if (!name.includes(".owner-")) chmodSync(join(dir, name), 0o644);
  const d = await asNobody();
  assert.equal(d.code, 0, d.stdout);
  assert.match(d.value.user, /uid 65534/);
  assert.match(has(d, "OK", "KEY_FILES_NOT_READABLE").message, /key files or key references/);
  has(d, "OK", "HISTORY_NOT_WRITABLE");
  assert.ok(!d.findings.some((f) => f.code === "KEY_FILE_UNREADABLE"), "judged as the agent, an unreadable key file is the point");
});

test("review block 4: a world-readable Vault reference naming a loopback listener gets ZERO requests (H1, same user); a loose directory; the agent's environment (H2)", async (t) => {
  const dir = scratchDir(t, "itdoc-");
  const history = join(dir, "h.jsonl");
  ok(await cli(["init", "--history", history, "--no-next-key"]));
  let requests = 0;
  const listener = createServer((req, res) => { requests += 1; res.writeHead(404); res.end("{}"); });
  await new Promise((done) => listener.listen(0, "127.0.0.1", done));
  t.after(() => new Promise((done) => listener.close(done)));
  const tokenFile = join(dir, "git-credentials");
  writeFileSync(tokenFile, "https://owner:ghp_SECRET@github.com\n", { mode: 0o600 });
  writeFileSync(`${history}.owner-key.json`, JSON.stringify({ version: "irontrellis-owner-key-ref/1", keyId: "owner:1", scheme: "ed25519", publicKey: `0x${"11".repeat(32)}`,
    signer: { kind: "vault-transit", address: `http://127.0.0.1:${listener.address().port}`, key: "owner", keyVersion: 1, tokenFile } }), { mode: 0o644 });
  chmodSync(`${history}.owner-key.json`, 0o644);
  const d = await doctor(history, [], { VAULT_TOKEN: "hvs.owner" });
  assert.equal(d.code, 1);
  has(d, "FAIL", "REFERENCE_REFUSED");
  assert.equal(requests, 0, "nothing was sent to the address the refused reference names");
  assert.ok(!d.stdout.includes("ghp_SECRET"));
  // M1 as the owner: a group-writable directory without the sticky bit.
  chmodSync(dir, 0o775);
  has(await doctor(history, ["--offline"]), "WARN", "HISTORY_DIR_LOOSE");
  chmodSync(dir, 0o700);
  // H2 as the agent's user (same user here): a readable ~/.vault-token, VAULT_TOKEN, a clean environment.
  const home = join(dir, "home");
  mkdirSync(home);
  writeFileSync(join(home, ".vault-token"), "hvs.agent", { mode: 0o600 });
  const agentView = await doctor(history, ["--as-agent", "--offline"], { HOME: home, VAULT_TOKEN: "hvs.x" });
  has(agentView, "FAIL", "VAULT_TOKEN_FILE_READABLE");
  has(agentView, "FAIL", "VAULT_TOKEN_IN_ENVIRONMENT");
  has(agentView, "FAIL", "HISTORY_DIR_WRITABLE");
  has(await doctor(history, ["--as-agent", "--offline"], { HOME: join(dir, "nohome"), VAULT_TOKEN: "", SSH_AUTH_SOCK: "" }), "OK", "NO_SIGNER_CREDENTIALS");
  assert.equal(requests, 0);
});

test("doctor WARNs about refusals waiting in the spool (not yet in the history), and is silent when there are none", async (t) => {
  const dir = scratchDir(t, "itdoc-");
  const history = join(dir, "h.jsonl");
  ok(await cli(["init", "--history", history]));
  assert.equal((await doctor(history, ["--offline"])).find("REFUSALS_SPOOLED"), undefined);
  const entry = { version: "irontrellis-refusal-spool/1", refusalId: "refusal:1", attemptedAt: 1, request: { actorId: "bea", action: "write-file", resource: "repo:x" } };
  writeFileSync(`${history}.refusals.spool`, `${JSON.stringify(entry)}\n${JSON.stringify({ ...entry, refusalId: "refusal:2" })}\n`, { mode: 0o600 });
  const warned = has(await doctor(history, ["--offline"]), "WARN", "REFUSALS_SPOOLED");
  assert.match(warned.message, /2 refusals wait in .*refusals\.spool, not yet in the history/);
});
