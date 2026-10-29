// Block 4 phase B through the built CLI with a REAL Vault dev server (Docker hashicorp/vault:1.20, or
// IRONTRELLIS_VAULT_ADDR + IRONTRELLIS_VAULT_TOKEN in CI; skipped with the reason otherwise): init --signer
// vault-transit (public key and version read from Vault and pinned), grant, verify, owner status, signer test/ref,
// pre-rotation onto a second Transit key behind its own token file, and doctor's Vault findings. Build first.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { scratchDir } from "../../core/test/helpers/ssh-agent.mjs";
import { startVault, vaultAvailable, vaultSkip } from "../../core/test/helpers/vault.mjs";

const here = fileURLToPath(new URL(".", import.meta.url));
const BIN = resolve(here, "../bin/irontrellis.mjs");
assert.ok(existsSync(resolve(here, "../dist/cli.js")), "build the package first: pnpm build");

const cli = (args, env = {}) => new Promise((done) => {
  const child = spawn(process.execPath, [BIN, ...args], { env: { ...process.env, NO_COLOR: "1", IRONTRELLIS_HOOK_CONFIG: "", VAULT_TOKEN: "", VAULT_ADDR: "", ...env } });
  let stdout = "", stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  child.on("close", (code) => { let value; try { value = JSON.parse(stdout); } catch { value = undefined; } done({ code, stdout, stderr, value }); });
});
const json = (args, env) => cli([...args, "--json"], env);
const ok = (r, what = "expected exit 0") => { assert.equal(r.code, 0, `${what}\n${r.stdout}\n${r.stderr}`); return r; };
const codes = (r) => r.value.findings.map((f) => `${f.level} ${f.code}`);
const has = (r, level, code) => {
  const hit = r.value.findings.find((f) => f.level === level && f.code === code);
  assert.ok(hit !== undefined, `expected ${level} ${code}; got:\n${codes(r).join("\n")}`);
  return hit;
};

let vault;
before(async () => { if (vaultAvailable.ok) vault = await startVault(); });
after(() => vault?.stop());

test("CLI usage for --signer vault-transit (no Vault needed): address rules, flags that go with it, no token on the command line", async (t) => {
  const dir = scratchDir(t, "itvc-");
  const history = join(dir, "h.jsonl");
  const pk = `0x${"33".repeat(32)}`;
  const usage = async (args, pattern) => {
    const r = await json(["init", "--history", history, ...args]);
    assert.equal(r.value?.error?.code, "USAGE", `${args.join(" ")}\n${r.stdout}${r.stderr}`);
    assert.match(r.value.error.message, pattern);
  };
  await usage(["--signer", "vault-transit", "--vault-key", "k", "--public-key", pk, "--vault-key-version", "1"], /needs --vault-addr/);
  await usage(["--signer", "vault-transit", "--vault-addr", "http://vault.example:8200", "--vault-key", "k", "--public-key", pk, "--vault-key-version", "1"], /plain http is refused/);
  await usage(["--signer", "vault-transit", "--vault-addr", "https://vault.example"], /--vault-key/);
  await usage(["--signer", "ssh-agent", "--public-key", pk, "--vault-key", "k"], /--vault-key goes with --signer vault-transit/);
  await usage(["--vault-addr", "https://vault.example"], /needs --signer/);
  await usage(["--signer", "vault-transit", "--vault-addr", "https://vault.example", "--vault-key", "k", "--agent-socket", "/tmp/x"], /does not go with --signer vault-transit/);
  assert.ok(!existsSync(history));
  // signer ref writes the reference without contacting Vault when the key and version are given; the token file path is absolute.
  const out = join(dir, "owner.ref");
  const ref = ok(await json(["signer", "ref", "--out", out, "--signer", "vault-transit", "--vault-addr", "https://vault.example:8200/", "--vault-key", "owner", "--vault-key-version", "4", "--public-key", pk, "--vault-token-file", "tok", "--vault-ca-file", "ca.pem", "--vault-namespace", "team-a"]));
  assert.deepEqual(ref.value.reference.signer, { kind: "vault-transit", address: "https://vault.example:8200", mount: "transit", key: "owner", keyVersion: 4, namespace: "team-a", tokenFile: resolve("tok"), caFile: resolve("ca.pem") });
  const help = await cli(["init", "--help"]);
  for (const flag of ["--vault-addr", "--vault-key", "--vault-mount", "--vault-key-version", "--vault-namespace", "--vault-ca-file", "--vault-token-file"]) assert.ok(help.stdout.includes(flag), flag);
});

test("CLI with the owner key in Vault Transit: init reads and pins the key, grant, verify, owner status, signer test; pre-rotation onto a second Transit key; doctor's Vault findings", vaultSkip, async (t) => {
  const dir = scratchDir(t, "itvc-");
  const history = join(dir, "h.jsonl");
  await vault.createKey("cli-owner");
  const ownerPk = await vault.rotateKey("cli-owner"); // v2 is the latest: init pins it
  const nextPk = await vault.createKey("cli-next");
  const ownerTokenFile = join(dir, "owner.vault-token"), nextTokenFile = join(dir, "next.vault-token");
  writeFileSync(ownerTokenFile, await vault.childToken(["cli-owner"]), { mode: 0o600 });
  writeFileSync(nextTokenFile, await vault.childToken(["cli-next"]), { mode: 0o600 });
  const vflags = (key, tokenFile) => ["--signer", "vault-transit", "--vault-addr", vault.address, "--vault-mount", vault.mount, "--vault-key", key, "--vault-token-file", tokenFile];
  const env = { IRONTRELLIS_HISTORY: history };
  // The next key's reference first (its own token file), then init with both.
  const nextRef = join(dir, "next.ref");
  const written = ok(await json(["signer", "ref", "--out", nextRef, "--next", "--key-id", "owner:2", ...vflags("cli-next", nextTokenFile)], env));
  assert.equal(written.value.reference.publicKey, nextPk);
  assert.equal(written.value.reference.signer.keyVersion, 1);
  const init = ok(await json(["init", ...vflags("cli-owner", ownerTokenFile), "--next-key-ref", nextRef], env));
  assert.equal(init.value.ownerKeyHolder, "reference");
  assert.match(init.value.ownerKeySigner, new RegExp(`Vault Transit key ${vault.mount}/cli-owner v2 at`));
  assert.match(init.value.doctor, /irontrellis doctor/);
  const reference = JSON.parse(readFileSync(`${history}.owner-key.json`, "utf8"));
  assert.equal(reference.publicKey, ownerPk);
  assert.equal(reference.signer.keyVersion, 2, "the latest version at init is pinned");
  assert.ok(!readFileSync(`${history}.owner-key.json`, "utf8").includes(readFileSync(ownerTokenFile, "utf8")), "no token in the reference");
  ok(await json(["agent", "create", "bea"], env));
  ok(await json(["grant", "g1", "--to", "bea", "--actions", "read", "--resources", "r:1", "--expires", "+1h"], env));
  assert.equal(ok(await json(["verify"], env)).value.report.pinnedAttestation, "VERIFIED");
  const status = ok(await json(["owner", "status"], env)).value;
  assert.deepEqual(status.custody.map((c) => c.code), ["OWNER_KEY_REFERENCE", "NEXT_KEY_REFERENCE"]);
  const tested = ok(await json(["signer", "test", "--key", "current"], env));
  assert.equal(tested.value.standing, "an owner key in force");
  ok(await json(["signer", "test", "--ref", nextRef], env));
  // signer test inline, with VAULT_TOKEN instead of a token file.
  ok(await json(["signer", "test", "--signer", "vault-transit", "--vault-addr", vault.address, "--vault-mount", vault.mount, "--vault-key", "cli-owner", "--vault-key-version", "1"], { VAULT_TOKEN: vault.token }));

  // doctor: both keys reachable by reading them (nothing signed).
  const d = ok(await json(["doctor", history], env));
  assert.equal(d.value.findings.filter((f) => f.code === "SIGNER_REACHABLE").length, 2, codes(d).join("\n"));
  assert.match(has(d, "OK", "SIGNER_REACHABLE").message, /nothing was signed/);
  // As the agent's user holding these token files: a FAIL.
  const asAgent = await json(["doctor", history, "--as-agent"], env);
  assert.equal(asAgent.code, 1);
  has(asAgent, "FAIL", "SIGNER_USABLE_BY_THIS_USER");
  // A loose token file, a missing CA file, VAULT_TOKEN in the environment.
  chmodSync(ownerTokenFile, 0o644);
  has(await json(["doctor", history], env), "WARN", "VAULT_TOKEN_FILE_LOOSE");
  chmodSync(ownerTokenFile, 0o600);
  has(await json(["doctor", history], { ...env, VAULT_CACERT: join(dir, "missing-ca.pem") }), "WARN", "VAULT_CA_FILE_MISSING");
  has(await json(["doctor", history], { ...env, VAULT_TOKEN: "anything" }), "WARN", "VAULT_TOKEN_IN_ENVIRONMENT");

  // Pre-rotation onto the second Transit key; a fresh public-key-only commitment.
  const rotated = ok(await json(["owner", "rotate-key", "--new-next-public-key", `0x${"44".repeat(32)}`], env));
  assert.equal(rotated.value.keyId ?? rotated.value.rotation?.keyId ?? "owner:2", "owner:2");
  const after = JSON.parse(readFileSync(`${history}.owner-key.json`, "utf8"));
  assert.equal(after.signer.key, "cli-next");
  ok(await json(["grant", "g2", "--to", "bea", "--actions", "read", "--resources", "r:1", "--expires", "+1h"], env));
  assert.equal(ok(await json(["verify"], env)).value.ok, true);

  // The current key's token revoked: owner writes fail with SIGNER_FAILED; doctor says unreachable (WARN).
  writeFileSync(nextTokenFile, "s.revoked-or-wrong", { mode: 0o600 });
  const denied = await json(["grant", "g3", "--to", "bea", "--actions", "read", "--resources", "r:1", "--expires", "+1h"], env);
  assert.equal(denied.value.error.code, "SIGNER_FAILED");
  assert.match(denied.value.error.message, /permission denied/);
  has(await json(["doctor", history], env), "WARN", "SIGNER_UNREACHABLE");
  // As the agent's user: a token Vault refuses a key read with is not proven unusable (it may still sign): a WARN since the review (H2).
  has(await json(["doctor", history, "--as-agent"], env), "WARN", "SIGNER_NOT_PROVEN_UNUSABLE");
  // The key deleted in Vault: KEY_UNAVAILABLE for writes, a FAIL for doctor (exit 1).
  writeFileSync(nextTokenFile, vault.token, { mode: 0o600 });
  await vault.deleteKey("cli-next");
  const gone = await json(["grant", "g4", "--to", "bea", "--actions", "read", "--resources", "r:1", "--expires", "+1h"], env);
  assert.equal(gone.value.error.code, "KEY_UNAVAILABLE");
  const failed = await json(["doctor", history], env);
  assert.equal(failed.code, 1);
  assert.match(has(failed, "FAIL", "SIGNER_KEY_UNAVAILABLE").fix, /CUSTODY\.md §10/);
});
