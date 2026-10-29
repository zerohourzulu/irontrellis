/**
 * Block 4 (owner-key custody): the hook with an owner key held by a REAL ssh-agent. SessionStart admits the runtime
 * session with control events signed through the agent (and pins attested through it), tool decisions read the history
 * without the key, and the protective rules cover the key references and the signer: the agent socket, ssh-add, the
 * command signer's program, and reference files kept elsewhere.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createLocalDomain, createLocalOwner, keyReference, openHistoryStore, verifyHistory } from "@ramex-labs/irontrellis";
import { custodyCommand, protection, protectedTargets, validateConfig } from "../dist/index.js";
import { haveOpenSsh, scratchDir, sshKeygen, startSshAgent } from "../../core/test/helpers/ssh-agent.mjs";

const BIN = resolve(fileURLToPath(new URL("../bin/irontrellis-hook.mjs", import.meta.url)));
const STATE_HOME = mkdtempSync(join(tmpdir(), "irontrellis-home-"));
const skipNoSsh = haveOpenSsh ? {} : { skip: "OpenSSH is not installed" };

function run(args, { cwd, stdin = "", env = {} } = {}) {
  const r = spawnSync(process.execPath, [BIN, ...args], { cwd, input: stdin, encoding: "utf8", env: { ...process.env, NO_COLOR: "1", IRONTRELLIS_HOME: STATE_HOME, ...env } });
  let json;
  try { json = r.stdout.trim() === "" ? undefined : JSON.parse(r.stdout); } catch { json = undefined; }
  return claudeDeny(args, { code: r.status, stdout: r.stdout, stderr: r.stderr, json });
}
/** A Claude Code PreToolUse deny is exit 2 with the reason on stderr and nothing on stdout (item 4); read in the deny's JSON shape. */
function claudeDeny(args, r) {
  const at = args.indexOf("claude-code");
  if (at < 0 || args[at + 1] !== "PreToolUse") return r;
  assert.notEqual(r.json?.hookSpecificOutput?.permissionDecision, "deny", `a Claude Code deny must be exit 2, not JSON: ${r.stdout}`);
  if (r.code !== 2 || r.stdout !== "") return r;
  assert.match(r.stderr, /^\nIronTrellis · DENY: /, "a Claude Code deny's stderr starts with a newline (its own line under Claude Code's label), then the state word");
  return { ...r, json: { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: r.stderr.slice(1).split("\n")[0] } } };
}
const sessionStart = (dir, session = "cc-custody-1") => ({ session_id: session, transcript_path: `${dir}/t.jsonl`, cwd: dir, permission_mode: "default", hook_event_name: "SessionStart", source: "startup" });
const preToolUse = (dir, tool_name, tool_input, session = "cc-custody-1") => ({ session_id: session, transcript_path: `${dir}/t.jsonl`, cwd: dir, permission_mode: "default", hook_event_name: "PreToolUse", tool_name, tool_input, tool_use_id: "toolu_1" });

test("the hook with the owner key in a real ssh-agent: init reuses the history, SessionStart admits through the agent, tool calls cannot reach the agent, the references or ssh-add", skipNoSsh, async (t) => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "irontrellis-hook-custody-")));
  const keys = scratchDir(t, "ihk-");
  const agent = await startSshAgent(t, keys);
  const owner1 = sshKeygen(keys, "owner1"), next1 = sshKeygen(keys, "next1");
  agent.add(owner1.file);
  const history = join(keys, "h.jsonl");
  // The reference names no socket: this process (as the hook will) finds the agent through SSH_AUTH_SOCK.
  const saved = process.env.SSH_AUTH_SOCK;
  process.env.SSH_AUTH_SOCK = agent.socket;
  t.after(() => { if (saved === undefined) delete process.env.SSH_AUTH_SOCK; else process.env.SSH_AUTH_SOCK = saved; });
  const owner = await createLocalOwner({
    historyFile: history, domain: createLocalDomain(), owner: "principal:alice", controller: "controller:ops", now: () => Date.now(),
    ownerKeyReference: keyReference({ keyId: "owner:1", publicKey: owner1.pub, signer: { kind: "ssh-agent" } }), nextPublicKey: next1.pub,
  });
  owner.close();
  const env = { SSH_AUTH_SOCK: agent.socket };
  const init = run(["init", "--history", history, "--json"], { cwd: dir, env });
  assert.equal(init.code, 0, init.stderr);
  assert.ok(init.json.warnings.some((w) => /the owner key is held by ssh-agent at \$SSH_AUTH_SOCK/.test(w) && /is only a reference \(no secret\)/.test(w)), init.json.warnings.join("\n"));
  assert.ok(!init.json.warnings.some((w) => /same-user layout/.test(w)), "no key file to read: the same-user key warning is replaced");
  // SessionStart: the agent (and the role) are created and the session admitted, every control event signed through the agent.
  const before = openHistoryStore(history, { witness: false }).state().events.length;
  const start = run(["claude-code", "SessionStart"], { cwd: dir, stdin: JSON.stringify(sessionStart(dir)), env });
  assert.equal(start.code, 0, start.stderr);
  assert.match(start.json.hookSpecificOutput.additionalContext, /runtime session:cc-custody-1, epoch 1/);
  const state = openHistoryStore(history, { witness: false }).state();
  assert.ok(state.events.length > before);
  assert.ok(state.events.slice(before).every((e) => e.data.controlAuthorization?.keyId === "owner:1"), "signed by the owner key the agent holds");
  const report = verifyHistory(history);
  assert.equal(report.ok, true, report.failures.join("; "));
  assert.equal(report.pinnedAttestation, "VERIFIED", "the hook's pins are attested through the agent before it replies");
  // A tool decision reads the history; it signs nothing and needs no agent.
  const read = run(["claude-code", "PreToolUse"], { cwd: dir, stdin: JSON.stringify(preToolUse(dir, "Write", { file_path: `${dir}/a`, content: "" })), env: { SSH_AUTH_SOCK: "" } });
  assert.equal(read.code, 2, read.stderr);
  assert.equal(read.json.hookSpecificOutput.permissionDecision, "deny");
  assert.match(read.json.hookSpecificOutput.permissionDecisionReason, /^IronTrellis · DENY: .* \(NO_AUTHORITY; /);
  // The protective rules: the agent socket, ssh-add, the key references.
  const decide = (tool, input) => run(["claude-code", "PreToolUse"], { cwd: dir, stdin: JSON.stringify(preToolUse(dir, tool, input)), env }).json.hookSpecificOutput;
  for (const [tool, input, reason] of [
    // Both rules apply; since the block 4 review (L5) the custody command rule (ssh-keygen -Y sign, SSH_AUTH_SOCK) answers first.
    ["Bash", { command: `SSH_AUTH_SOCK=${agent.socket} ssh-keygen -Y sign -f k.pub -n file msg` }, /the signer that holds the IronTrellis owner key|held by an ssh-agent/],
    ["Bash", { command: "ssh-add -D" }, /held by an ssh-agent; ssh-add is for the operator/],
    ["Bash", { command: "echo hi && /usr/bin/ssh-add -L" }, /ssh-add is for the operator/],
    ["Bash", { command: "ssh''-add -d ~/.ssh/id_ed25519" }, /ssh-add is for the operator/],
    ["Bash", { command: "cat ~/keys/owner-2.owner-next-key-ref.json" }, /"\.owner-next-key-ref\."/],
    ["Write", { file_path: join(keys, "h.jsonl.owner-key.json"), content: "{}" }, /"\.owner-key\.json"/],
    ["Bash", { command: `irontrellis signer test --key current` }, /control commands are for the operator, not the agent \(irontrellis signer\)/],
  ]) {
    const out = decide(tool, input);
    assert.equal(out.permissionDecision, "deny", `${tool} ${JSON.stringify(input)}`);
    assert.match(out.permissionDecisionReason, reason, `${tool} ${JSON.stringify(input)}`);
  }
});

test("protective rules for custody (unit): the command signer's program is protected; ssh-add only when an ssh-agent holds a key; reference names and version literals always", async (t) => {
  const keys = scratchDir(t, "ihk-");
  const history = join(keys, "h.jsonl");
  const program = join(keys, "kms-sign.mjs");
  const { writeFileSync } = await import("node:fs");
  writeFileSync(`${history}.owner-key.json`, JSON.stringify({ version: "irontrellis-owner-key-ref/1", keyId: "owner:1", scheme: "ed25519", publicKey: `0x${"11".repeat(32)}`, signer: { kind: "command", argv: [process.execPath, program] } }), { mode: 0o600 });
  const config = validateConfig({ history, owner: "o", controller: "c", agentId: "a", policy: { sideEffecting: [], readOnly: [] } }, join(keys, "irontrellis-hook.json"));
  assert.ok(protectedTargets(config).some((target) => target.path === program), "the signing program is a protected path");
  assert.equal(protection(config, "Write", { file_path: program, content: "" }, keys)?.code, "PROTECTED_PATH");
  assert.equal(protection(config, "Bash", { command: "ssh-add -L" }, keys), undefined, "no ssh-agent holds a key of this history: ssh-add is not a custody command here");
  assert.equal(custodyCommand("ssh-add -L"), "ssh-add");
  assert.equal(custodyCommand("git push"), undefined);
  for (const text of ["irontrellis-owner-key-ref/1", "x.owner-key-ref.json", "irontrellis-sign-request"]) {
    assert.equal(protection(config, "Bash", { command: `grep -r ${text} /` }, keys)?.code, "PROTECTED_PATH", text);
  }
});

test("protective rules for a Vault Transit key (unit): the token file (or ~/.vault-token) and the CA file are protected paths; the vault CLI is a custody command only then", async (t) => {
  const keys = scratchDir(t, "ihv-");
  const history = join(keys, "h.jsonl");
  const tokenFile = join(keys, "owner.vault-token"), caFile = join(keys, "vault-ca.pem");
  const { writeFileSync, rmSync } = await import("node:fs");
  const ref = (signer, path = `${history}.owner-key.json`) => writeFileSync(path, JSON.stringify({ version: "irontrellis-owner-key-ref/1", keyId: "owner:1", scheme: "ed25519", publicKey: `0x${"22".repeat(32)}`, signer }), { mode: 0o600 });
  const config = validateConfig({ history, owner: "o", controller: "c", agentId: "a", policy: { sideEffecting: [], readOnly: [] } }, join(keys, "irontrellis-hook.json"));
  assert.equal(protection(config, "Bash", { command: "vault write transit/sign/owner input=AAAA" }, keys), undefined, "no Vault key: vault is not a custody command");
  ref({ kind: "vault-transit", address: "https://vault.example:8200", mount: "transit", key: "owner", keyVersion: 1, tokenFile, caFile });
  const targets = protectedTargets(config).map((target) => target.path);
  assert.ok(targets.includes(tokenFile) && targets.includes(caFile), "token and CA files are protected");
  assert.equal(protection(config, "Read", { file_path: tokenFile }, keys)?.code, "PROTECTED_PATH");
  assert.equal(protection(config, "Bash", { command: `cat ${caFile}` }, keys)?.code, "PROTECTED_PATH");
  for (const command of ["vault write transit/sign/owner input=AAAA", "VAULT_ADDR=x /usr/local/bin/vault token lookup", "v'au'lt read transit/keys/owner"]) {
    const hit = protection(config, "Bash", { command }, keys);
    assert.equal(hit?.code, "PROTECTED_COMMAND", command);
    assert.match(hit.reason, /Vault Transit/);
  }
  assert.equal(protection(config, "Bash", { command: "ls vault-notes/" }, keys), undefined);
  // Without a tokenFile the Vault CLI's ~/.vault-token is the token the owner's process uses: protected.
  ref({ kind: "vault-transit", address: "https://vault.example:8200", mount: "transit", key: "owner", keyVersion: 1 });
  assert.ok(protectedTargets(config, { HOME: "/home/owner" }).some((target) => target.path === "/home/owner/.vault-token"));
  rmSync(`${history}.owner-key.json`);
  // A next key in Vault counts too.
  ref({ kind: "vault-transit", address: "https://vault.example:8200", key: "next", keyVersion: 2, tokenFile }, `${history}.owner-next-key.json`);
  assert.ok(protectedTargets(config).some((target) => target.path === tokenFile));
});

test("custody tripwires added by the block 4 review (L5): variable indirection, ssh-keygen -Y sign, the agent socket, bao, curl with the Vault token or sign path; unreadable references apply every rule", async (t) => {
  const keys = scratchDir(t, "ihl5-");
  const history = join(keys, "h.jsonl");
  const { writeFileSync, chmodSync } = await import("node:fs");
  const config = validateConfig({ history, owner: "o", controller: "c", agentId: "a", policy: { sideEffecting: [], readOnly: [] } }, join(keys, "irontrellis-hook.json"));
  const ref = (signer) => writeFileSync(`${history}.owner-key.json`, JSON.stringify({ version: "irontrellis-owner-key-ref/1", keyId: "owner:1", scheme: "ed25519", publicKey: `0x${"33".repeat(32)}`, signer }), { mode: 0o600 });
  const denied = (command) => protection(config, "Bash", { command }, keys)?.code === "PROTECTED_COMMAND";
  ref({ kind: "ssh-agent" });
  for (const command of ["s=ssh-add; $s -D", "ssh-keygen -Y sign -f ~/.ssh/owner.pub -n file msg", "python3 -c 'import os,socket;s=socket.socket(socket.AF_UNIX);s.connect(os.environ[\"SSH_AUTH_SOCK\"])'", "socat - UNIX-CONNECT:$SSH_AUTH_SOCK"]) assert.ok(denied(command), command);
  assert.ok(!denied("ssh-keygen -t ed25519 -f new"), "ssh-keygen without -Y sign is fine");
  ref({ kind: "vault-transit", address: "https://vault.example:8200", key: "owner", keyVersion: 1 });
  for (const command of ["bao write transit/sign/owner input=A", "curl -H \"X-Vault-Token: $VAULT_TOKEN\" $VAULT_ADDR/v1/transit/sign/owner", "wget --header=X-Vault-Token:abc https://v/v1/transit/sign/owner", "V=vault; $V read transit/keys/owner", "cat ~/.vault-token"]) assert.ok(denied(command), command);
  assert.ok(!denied("git push"));
  // The hook cannot read the owner's 0600 reference (it runs as the agent's user): every custody rule applies.
  if (typeof process.getuid === "function" && process.getuid() !== 0) {
    chmodSync(`${history}.owner-key.json`, 0o000);
    assert.ok(denied("ssh-add -L") && denied("vault write transit/sign/owner input=A"));
  } else {
    const { custodyOf } = await import("../dist/index.js");
    const { spawnSync } = await import("node:child_process");
    chmodSync(keys, 0o755);
    const probe = `import("${resolve(fileURLToPath(new URL("../dist/index.js", import.meta.url)))}").then((m) => { const c = m.validateConfig({ history: ${JSON.stringify(history)}, owner: "o", controller: "c", agentId: "a", policy: { sideEffecting: [], readOnly: [] } }, ${JSON.stringify(join(keys, "irontrellis-hook.json"))}); const u = m.custodyOf(c, { HOME: "/nonexistent" }); console.log(JSON.stringify(u)); })`;
    const r = spawnSync(process.execPath, ["-e", probe], { uid: 65534, gid: 65534, encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    const seen = JSON.parse(r.stdout);
    assert.equal(seen.sshAgent, true);
    assert.equal(seen.vault, true);
    assert.ok(typeof custodyOf === "function");
  }
});
