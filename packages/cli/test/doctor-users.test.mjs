// Block 4 review regressions that need two OS users (PoC 01/01b and 02 of REVIEW-BLOCK4.md): the owner is this process
// (root), the agent is uid/gid 65534 (nobody/nogroup, present on Linux distributions and GitHub's ubuntu runners). Runs
// only as root: locally as the build user here, and in CI through `sudo node --test` (the "two OS users" step).
//  H1: a reference the agent planted (its own, 0644) naming a loopback "Vault" and a token file is refused by the owner's
//      doctor: FAIL REFERENCE_REFUSED and ZERO requests to the listener, nothing read from the token file.
//  H2/M1: in the recommended layout (directory 0750 owner:agent-group, history 0640, reference 0600) doctor --as-agent
//      run as the agent's user FAILs on VAULT_TOKEN in its environment and on an SSH_AUTH_SOCK that holds the owner key,
//      never says a plain OK about signers it cannot see (SIGNER_NOT_EVALUATED), and FAILs a writable directory.
import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmodSync, chownSync, existsSync, readdirSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { commandSignerScript, fakeKey, scratchDir, startFakeAgent } from "../../core/test/helpers/ssh-agent.mjs";

const here = fileURLToPath(new URL(".", import.meta.url));
const BIN = resolve(here, "../bin/irontrellis.mjs");
const core = await import("@ramex-labs/irontrellis");
const AGENT = 65534;
const isRoot = typeof process.getuid === "function" && process.getuid() === 0;
const skip = isRoot && process.platform === "linux" ? false : "needs root on Linux to run a child as another OS user (CI runs this file with sudo)";

const cli = (args, { env = {}, uid, cwd } = {}) => new Promise((done) => {
  const base = uid === undefined ? { ...process.env } : { PATH: process.env.PATH, HOME: "/nonexistent" };
  const child = spawn(process.execPath, [BIN, ...args], { env: { ...base, NO_COLOR: "1", IRONTRELLIS_HOOK_CONFIG: "", ...env }, ...(uid === undefined ? {} : { uid, gid: AGENT }), ...(cwd === undefined ? {} : { cwd }) });
  let stdout = "", stderr = "";
  child.stdout.on("data", (c) => { stdout += c; });
  child.stderr.on("data", (c) => { stderr += c; });
  child.on("close", (code) => { let value; try { value = JSON.parse(stdout); } catch { value = undefined; } done({ code, stdout, stderr, value }); });
});
const has = (r, level, code) => {
  assert.ok(r.value !== undefined, `${r.stdout}\n${r.stderr}`);
  const hit = r.value.findings.find((f) => f.level === level && f.code === code);
  assert.ok(hit !== undefined, `expected ${level} ${code}; got:\n${r.value.findings.map((f) => `${f.level} ${f.code}`).join("\n")}`);
  return hit;
};

/** A history owned by this process (root) in `dir`, its owner key behind a command signer (a reference, 0600). */
async function ownerHistory(dir, dirMode) {
  chmodSync(dir, dirMode);
  chownSync(dir, 0, AGENT);
  const pair = core.generateKeyPair("ed25519", "owner:1");
  const program = commandSignerScript(dir, pair.privateKey, "ok");
  const history = join(dir, "h.jsonl");
  const init = await cli(["init", "--history", history, "--signer", "command", "--public-key", pair.credential, "--signer-command", JSON.stringify([process.execPath, program]), "--no-next-key", "--json"]);
  assert.equal(init.code, 0, init.stdout + init.stderr);
  // The recipe (docs/CUSTODY.md §8): the history and its pin readable by the agent's group, key files the owner's.
  for (const name of readdirSync(dir)) {
    if (name.startsWith("h.jsonl") && !name.includes(".owner-")) { chownSync(join(dir, name), 0, AGENT); chmodSync(join(dir, name), 0o640); }
  }
  return { history, pair };
}

test("H1 (PoC 01/01b): a reference the agent planted is refused by the owner's doctor, which sends NOTHING to the address it names", { skip }, async (t) => {
  const dir = scratchDir(t, "itdu-");
  const { history } = await ownerHistory(dir, 0o770); // the misconfiguration under test: the agent's group may write the directory
  let requests = 0;
  const listener = createServer((req, res) => { requests += 1; res.writeHead(404); res.end("{}"); });
  await new Promise((done) => listener.listen(0, "127.0.0.1", done));
  t.after(() => new Promise((done) => listener.close(done)));
  const secret = join(dir, "owner-secret.txt");
  writeFileSync(secret, "hvs.OWNER-SECRET-TOKEN\n", { mode: 0o600 });
  // The agent (uid 65534) swaps the owner's reference for its own, world-readable, naming its listener and the owner's file.
  const plant = `const fs = require("fs"); fs.renameSync(${JSON.stringify(`${history}.owner-key.json`)}, ${JSON.stringify(join(dir, ".old"))});
fs.writeFileSync(${JSON.stringify(`${history}.owner-key.json`)}, JSON.stringify({ version: "irontrellis-owner-key-ref/1", keyId: "owner:1", scheme: "ed25519", publicKey: "0x" + "11".repeat(32),
  signer: { kind: "vault-transit", address: "http://127.0.0.1:${listener.address().port}", key: "owner", keyVersion: 1, tokenFile: ${JSON.stringify(secret)} } }), { mode: 0o644 });`;
  const planted = await new Promise((done) => spawn(process.execPath, ["-e", plant], { uid: AGENT, gid: AGENT, stdio: "inherit" }).on("close", done));
  assert.equal(planted, 0, "the agent could plant (the directory is group-writable)");
  const d = await cli(["doctor", history, "--json"], { env: { VAULT_TOKEN: "hvs.OWNER-ENV-TOKEN" } });
  assert.equal(d.code, 1);
  has(d, "FAIL", "REFERENCE_REFUSED");
  has(d, "WARN", "HISTORY_DIR_LOOSE");
  assert.equal(requests, 0, "no request reached the address the planted reference names");
  assert.ok(!d.stdout.includes("OWNER-SECRET") && !d.stdout.includes("OWNER-ENV-TOKEN"));
  // A symbolic link to another 0600 reference of the owner is refused as well (L4).
  const other = join(dir, "other.owner-key-ref.json");
  core.writeKeyReferenceFile(other, core.keyReference({ keyId: "owner:1", publicKey: `0x${"22".repeat(32)}`, signer: { kind: "vault-transit", address: `http://127.0.0.1:${listener.address().port}`, key: "x", keyVersion: 1 } }));
  const { rmSync, symlinkSync } = await import("node:fs");
  rmSync(`${history}.owner-key.json`);
  symlinkSync(other, `${history}.owner-key.json`);
  const linked = await cli(["doctor", history, "--json"], { env: { VAULT_TOKEN: "hvs.OWNER-ENV-TOKEN" } });
  assert.match(has(linked, "FAIL", "REFERENCE_REFUSED").message, /symbolic link/);
  assert.equal(requests, 0);
  // As the agent: the writable directory is a FAIL (M1).
  has(await cli(["doctor", history, "--json", "--as-agent", "--offline"], { uid: AGENT }), "FAIL", "HISTORY_DIR_WRITABLE");
});

test("H2/M1 (PoC 02): the recommended layout, doctor --as-agent as the agent's user: VAULT_TOKEN and the owner's ssh-agent in its environment are FAILs; signers it cannot see are SIGNER_NOT_EVALUATED, never a plain OK", { skip }, async (t) => {
  const dir = scratchDir(t, "itdu-");
  const { history, pair } = await ownerHistory(dir, 0o750);
  const asAgent = (env = {}, extra = []) => cli(["doctor", history, "--json", "--as-agent", ...extra], { uid: AGENT, env });
  // Clean environment: no FAIL, but not all-OK either: this run cannot see the signer.
  const clean = await asAgent();
  assert.equal(clean.code, 0, clean.stdout);
  assert.match(has(clean, "WARN", "SIGNER_NOT_EVALUATED").message, /not checked: .* unreadable as this user/);
  has(clean, "OK", "HISTORY_NOT_WRITABLE");
  has(clean, "OK", "NO_SIGNER_CREDENTIALS");
  has(clean, "OK", "KEY_FILES_NOT_READABLE");
  assert.ok(clean.value.summary.warn > 0);
  // PoC 02: the owner's Vault token in the agent's environment.
  const token = await asAgent({ VAULT_TOKEN: "hvs.owner-token" });
  assert.equal(token.code, 1);
  has(token, "FAIL", "VAULT_TOKEN_IN_ENVIRONMENT");
  // An SSH_AUTH_SOCK that reaches an agent holding the owner key (listed only).
  const sockDir = scratchDir(t, "itdu-s-");
  chmodSync(sockDir, 0o755);
  const owner = { pair, seed: Buffer.from(pair.privateKey.slice(2), "hex"), publicKey: Buffer.from(pair.credential.slice(2), "hex") };
  const agent = await startFakeAgent(t, sockDir, { keys: [owner, fakeKey(core.generateKeyPair, "x")] });
  chmodSync(agent.socket, 0o777);
  const sock = await asAgent({ SSH_AUTH_SOCK: agent.socket });
  assert.equal(sock.code, 1);
  has(sock, "FAIL", "SSH_AGENT_HOLDS_OWNER_KEY");
  assert.equal(agent.requests.length, 0, "only listed, never asked to sign");
  const offline = await asAgent({ SSH_AUTH_SOCK: agent.socket }, ["--offline"]);
  has(offline, "WARN", "SSH_AUTH_SOCK_NOT_CHECKED");
  const unrelated = await startFakeAgent(t, sockDir, { keys: [fakeKey(core.generateKeyPair, "y")], name: "other.sock" });
  chmodSync(unrelated.socket, 0o777);
  has(await asAgent({ SSH_AUTH_SOCK: unrelated.socket }), "OK", "SSH_AGENT_NO_OWNER_KEY");
  // The owner's run of the two-run procedure names the signer.
  const ownerRun = await cli(["doctor", history, "--json"]);
  has(ownerRun, "OK", "SIGNER_NOT_CHECKED");
  assert.ok(existsSync(`${history}.owner-key.json`));
});
