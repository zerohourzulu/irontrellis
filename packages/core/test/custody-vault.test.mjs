// Block 4 phase B: the HashiCorp Vault Transit signer against a REAL Vault dev server (Docker `hashicorp/vault:1.20`,
// or IRONTRELLIS_VAULT_ADDR + IRONTRELLIS_VAULT_TOKEN in CI; see helpers/vault.mjs). The Vault tests skip with the
// reason when neither is available. Every signature Vault returns is verified locally (referenceSigner).
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { scratchDir } from "./helpers/ssh-agent.mjs";
import { selfSignedCert, startSilentServer, startVault, startVaultProxy, vaultAvailable, vaultSkip } from "./helpers/vault.mjs";

const custody = await import("../src/custody/index.ts");
const signerLib = await import("../src/signer.ts");
const { generateKeyPair } = await import("../src/crypto/suites.ts");
const { createLocalOwner, openLocalOwner, createLocalDomain, verifyHistory } = await import("../src/owner.ts");

const HASH = `0x${"cd".repeat(32)}`;
const code = (expected, reason) => (e) => e.code === expected && (reason === undefined || e.detail?.reason === reason);
let clock = 8_000_000;
const now = () => (clock += 1);

let vault;
before(async () => { if (vaultAvailable.ok) vault = await startVault(); });
after(() => vault?.stop());

/** A vault-transit signer record for `key` pinned to `version` (the token from VAULT_TOKEN unless `extra` says otherwise). */
const spec = (key, version = 1, extra = {}) => ({ kind: "vault-transit", address: vault.address, mount: vault.mount, key, keyVersion: version, ...extra });
const vaultRef = (key, publicKey, version = 1, extra = {}, keyId = "owner:1", next = false) => custody.keyReference({ keyId, publicKey, signer: spec(key, version, extra), next });
/** Runs `fn` with VAULT_TOKEN set to `token` (restored afterwards). */
async function withToken(token, fn) {
  const before = process.env.VAULT_TOKEN;
  if (token === undefined) delete process.env.VAULT_TOKEN; else process.env.VAULT_TOKEN = token;
  try { return await fn(); } finally { if (before === undefined) delete process.env.VAULT_TOKEN; else process.env.VAULT_TOKEN = before; }
}

async function history(t, dir, ownerRef, options = {}) {
  const historyFile = join(dir, "h.jsonl");
  const config = { historyFile, domain: createLocalDomain(), owner: "owner", controller: "controller", now };
  const owner = await createLocalOwner({ ...config, ownerKeyReference: ownerRef, ...options });
  t.after(() => owner.close());
  return { historyFile, config, owner, open: (more = {}) => openLocalOwner({ ...config, ...more }), pin: () => JSON.parse(readFileSync(`${historyFile}.head`, "utf8")) };
}
const grant = (owner, id = "g1") => owner.grant({ id, to: "bea", actions: ["read"], resources: ["r:1"], expiresAt: 9_000_000_000 });

// ---------------------------------------------------------------- the reference (no Vault needed)

test("vault-transit references: https only (plain http to loopback only), the key version pinned, no token field, paths absolute; describe and identity", () => {
  const pk = generateKeyPair("ed25519", "k").credential;
  const ref = (signer) => custody.keyReference({ keyId: "owner:1", publicKey: pk, signer });
  const ok = ref({ kind: "vault-transit", address: "https://vault.example:8200/", key: "owner", keyVersion: 3, namespace: "/team-a/", tokenFile: "/etc/it/token", caFile: "/etc/it/ca.pem" });
  assert.deepEqual(ok.signer, { kind: "vault-transit", address: "https://vault.example:8200", mount: "transit", key: "owner", keyVersion: 3, namespace: "team-a", tokenFile: "/etc/it/token", caFile: "/etc/it/ca.pem" });
  const signer = custody.referenceSigner(ok);
  assert.equal(signer.custody.description, "Vault Transit key transit/owner v3 at https://vault.example:8200 (namespace team-a)");
  assert.equal(signer.custody.identity, "vault-transit:https://vault.example:8200|team-a|token:/etc/it/token");
  assert.equal(signer.signHashSync, undefined, "a Vault signer is asynchronous only");
  for (const address of ["http://127.0.0.1:8200", "http://localhost:8200", "http://[::1]:8200"]) assert.equal(ref({ kind: "vault-transit", address, key: "k", keyVersion: 1 }).signer.address, address);
  const refused = [
    [{ address: "http://vault.example:8200", key: "k", keyVersion: 1 }, /plain http is refused/],
    [{ address: "ftp://vault.example", key: "k", keyVersion: 1 }, /must be https/],
    [{ address: "https://user:pw@vault.example", key: "k", keyVersion: 1 }, /credentials/],
    [{ address: "https://vault.example", key: "k" }, /keyVersion must be the pinned key version/],
    [{ address: "https://vault.example", key: "k", keyVersion: 0 }, /keyVersion/],
    [{ address: "https://vault.example", key: "k", keyVersion: 1, token: "s.abc" }, /never holds the Vault token/],
    [{ address: "https://vault.example", key: "../sys", keyVersion: 1 }, /key must be/],
    [{ address: "https://vault.example", key: "k", keyVersion: 1, mount: "a/../b" }, /mount must be/],
    [{ address: "https://vault.example", key: "k", keyVersion: 1, tokenFile: "token" }, /tokenFile must be an absolute path/],
    [{ address: "https://vault.example", key: "k", keyVersion: 1, caFile: "ca.pem" }, /caFile must be an absolute path/],
    [{ address: "https://vault.example", key: "k", keyVersion: 1, timeoutMs: 5 }, /timeoutMs/],
    [{ address: "https://vault.example", key: "k", keyVersion: 1, extra: 1 }, /unknown vault-transit signer field/],
  ];
  for (const [signer, pattern] of refused) {
    assert.throws(() => ref({ kind: "vault-transit", ...signer }), (e) => e.code === "KEY_UNAVAILABLE" && e.detail.reason === "REFERENCE_INVALID" && pattern.test(e.message), JSON.stringify(signer));
  }
  assert.ok(custody.signerBackendKinds().includes("vault-transit"));
  // Token sources: tokenFile, then VAULT_TOKEN, then ~/.vault-token (never the token itself).
  const parsed = ok.signer;
  assert.deepEqual(custody.vaultTokenSource(parsed, {}), { source: "tokenFile", path: "/etc/it/token" });
  const { tokenFile: _drop, ...noFile } = parsed;
  assert.deepEqual(custody.vaultTokenSource(noFile, { VAULT_TOKEN: "x", HOME: "/home/u" }), { source: "VAULT_TOKEN" });
  assert.deepEqual(custody.vaultTokenSource(noFile, { HOME: "/home/u" }), { source: "vault-token-file", path: "/home/u/.vault-token" });
  assert.equal(custody.vaultCaFile(noFile, {}), "/etc/it/ca.pem");
});

test("vault-transit transport failures without Vault: unreachable, silent (timeout), no token → SIGNER_FAILED with the reason", async (t) => {
  const pk = generateKeyPair("ed25519", "k").credential;
  const dir = scratchDir(t);
  const silent = await startSilentServer();
  t.after(() => silent.close());
  const signerAt = (address, extra = {}) => custody.referenceSigner(custody.keyReference({ keyId: "owner:1", publicKey: pk, signer: { kind: "vault-transit", address, key: "k", keyVersion: 1, ...extra } }));
  await withToken("t", async () => {
    await assert.rejects(signerAt("http://127.0.0.1:1").signHash(HASH), code("SIGNER_FAILED", "UNREACHABLE"));
    const started = Date.now();
    await assert.rejects(signerAt(silent.address, { timeoutMs: 300 }).signHash(HASH), (e) => code("SIGNER_FAILED", "TIMEOUT")(e) && /did not answer within 300 ms/.test(e.message));
    assert.ok(Date.now() - started < 5000);
  });
  await withToken(undefined, async () => {
    const home = process.env.HOME;
    process.env.HOME = dir; // no ~/.vault-token here
    try {
      await assert.rejects(signerAt(silent.address).signHash(HASH), (e) => code("SIGNER_FAILED", "NO_TOKEN")(e) && /VAULT_TOKEN is not set/.test(e.message));
      await assert.rejects(signerAt(silent.address, { tokenFile: join(dir, "missing") }).signHash(HASH), (e) => code("SIGNER_FAILED", "NO_TOKEN")(e) && /token file .* cannot be read/.test(e.message));
    } finally { process.env.HOME = home; }
  });
});

// ---------------------------------------------------------------- against a real Vault

test("real Vault: a Transit ed25519 key signs the 32-byte hash (PureEdDSA, verified locally); token from VAULT_TOKEN, a token file or ~/.vault-token; the namespace header is sent", vaultSkip, async (t) => {
  const dir = scratchDir(t);
  const pk = await vault.createKey("sig");
  const info = await withToken(vault.token, () => custody.readVaultKey({ kind: "vault-transit", address: vault.address, mount: vault.mount, key: "sig" }));
  assert.equal(info.type, "ed25519");
  assert.equal(info.latestVersion, 1);
  assert.equal(info.publicKeys.get(1), pk);
  const signer = custody.referenceSigner(vaultRef("sig", pk));
  const signature = await withToken(vault.token, () => signer.signHash(HASH, { purpose: "signer-test" }));
  assert.match(signature, /^0x[0-9a-f]{128}$/);
  // The token from a file named by the reference (VAULT_TOKEN unset), and from ~/.vault-token.
  const tokenFile = join(dir, "vault-token");
  writeFileSync(tokenFile, `${vault.token}\n`, { mode: 0o600 });
  await withToken(undefined, () => custody.referenceSigner(vaultRef("sig", pk, 1, { tokenFile })).signHash(HASH));
  const home = process.env.HOME;
  process.env.HOME = dir;
  writeFileSync(join(dir, ".vault-token"), vault.token, { mode: 0o600 });
  try { await withToken(undefined, () => signer.signHash(HASH)); } finally { process.env.HOME = home; }
  // Namespace (Vault Enterprise; the open-source dev server ignores the header): sent from the reference or VAULT_NAMESPACE.
  const proxy = await startVaultProxy(vault.address);
  t.after(() => proxy.close());
  const viaProxy = (extra) => custody.referenceSigner(custody.keyReference({ keyId: "owner:1", publicKey: pk, signer: { ...spec("sig", 1, extra), address: proxy.address } }));
  await withToken(vault.token, () => viaProxy({ namespace: "team-a/prod" }).signHash(HASH));
  assert.ok(proxy.requests.length === 2 && proxy.requests.every((r) => r.headers["x-vault-namespace"] === "team-a/prod"));
  assert.deepEqual(proxy.requests.map((r) => `${r.method} ${r.path}`), [`GET /v1/${vault.mount}/keys/sig`, `POST /v1/${vault.mount}/sign/sig`]);
  process.env.VAULT_NAMESPACE = "env-ns";
  try { await withToken(vault.token, () => viaProxy({}).signHash(HASH)); } finally { delete process.env.VAULT_NAMESPACE; }
  assert.equal(proxy.requests.at(-1).headers["x-vault-namespace"], "env-ns");
  assert.ok(!JSON.stringify(proxy.requests).includes("prehashed\":true"));
});

test("real Vault: init, grant and pin through a Transit key; the pin is attested by Vault; verify passes; a least-privilege token suffices", vaultSkip, async (t) => {
  const dir = scratchDir(t);
  const pk = await vault.createKey("owner-a");
  const child = await vault.childToken(["owner-a"]);
  await withToken(child, async () => {
    const h = await history(t, dir, vaultRef("owner-a", pk));
    assert.equal(JSON.parse(readFileSync(`${h.historyFile}.owner-key.json`, "utf8")).signer.keyVersion, 1);
    assert.ok(!readFileSync(`${h.historyFile}.owner-key.json`, "utf8").includes(child), "the token is never in the reference");
    await h.owner.createAgent({ id: "bea" });
    await grant(h.owner);
    assert.equal(h.pin().attestation.keyId, "owner:1");
    const st = h.owner.ownerKeyStatus();
    assert.equal(st.custody[0].code, "OWNER_KEY_REFERENCE");
    const report = verifyHistory(h.historyFile);
    assert.equal(report.ok, true, report.failures.join("; "));
    // doctor's non-signing check: the key read only.
    const check = await custody.checkVaultKey(custody.parseKeyReference(JSON.parse(readFileSync(`${h.historyFile}.owner-key.json`, "utf8"))).signer, { keyId: "owner:1", publicKey: pk });
    assert.equal(check.ok, true, check.message);
  });
});

test("real Vault: pre-rotation where the next key is a second Transit key behind its own token file; the same token for both is NEXT_KEY_SAME_SIGNER", vaultSkip, async (t) => {
  const dir = scratchDir(t);
  const pk1 = await vault.createKey("pre-1"), pk2 = await vault.createKey("pre-2");
  const nextTokenFile = join(dir, "next-token");
  writeFileSync(nextTokenFile, await vault.childToken(["pre-2"]), { mode: 0o600 });
  await withToken(await vault.childToken(["pre-1"]), async () => {
    const h = await history(t, dir, vaultRef("pre-1", pk1), { nextKeyReference: vaultRef("pre-2", pk2, 1, { tokenFile: nextTokenFile }, "owner:2", true) });
    const st = h.owner.ownerKeyStatus();
    assert.equal(st.nextKeyOnHost, false);
    assert.deepEqual(st.warnings.map((w) => w.code), [], "a separate token (policy) for the next key is a separate holder");
    await h.owner.createAgent({ id: "bea" });
    const rotated = await h.owner.rotateOwnerKey({ newNextPublicKey: generateKeyPair("ed25519", "n3").credential, reason: "scheduled" });
    assert.equal(rotated.preRotated, true);
    assert.equal(rotated.keyId, "owner:2");
    const now2 = signerLib.loadOwnerKeyFile(`${h.historyFile}.owner-key.json`);
    assert.equal(now2.credential, pk2);
    assert.match(now2.custody.description, /pre-2 v1/);
    await grant(h.owner);
    assert.equal(h.pin().attestation.keyId, "owner:2");
    const report = verifyHistory(h.historyFile);
    assert.equal(report.ok, true, report.failures.join("; "));
  });
  // Same token source for owner and next key: one holder.
  const dir2 = scratchDir(t);
  const pk3 = await vault.createKey("pre-3"), pk4 = await vault.createKey("pre-4");
  await withToken(vault.token, async () => {
    const h = await history(t, dir2, vaultRef("pre-3", pk3), { nextKeyReference: vaultRef("pre-4", pk4, 1, {}, "owner:2", true) });
    assert.deepEqual(h.owner.ownerKeyStatus().warnings.map((w) => w.code), ["NEXT_KEY_SAME_SIGNER"]);
  });
});

test("real Vault: a rotated Transit key keeps signing with the pinned version; a signature with another version, a version Vault no longer holds or below min_encryption_version is KEY_UNAVAILABLE", vaultSkip, async (t) => {
  const dir = scratchDir(t);
  const pk1 = await vault.createKey("rot");
  await withToken(vault.token, async () => {
    const h = await history(t, dir, vaultRef("rot", pk1));
    await h.owner.createAgent({ id: "bea" });
    const pk2 = await vault.rotateKey("rot");
    assert.notEqual(pk2, pk1);
    await grant(h.owner, "after-vault-rotation");
    assert.equal(h.pin().attestation.keyId, "owner:1", "still the pinned v1: a Vault rotation does not switch the owner key");
    assert.equal(verifyHistory(h.historyFile).ok, true);
    // A reference pinned to v2 with v1's public key: Vault holds v2 with another public key.
    await assert.rejects(custody.referenceSigner(vaultRef("rot", pk1, 2)).signHash(HASH), code("KEY_UNAVAILABLE", "PUBLIC_KEY_MISMATCH"));
    // A version Vault does not have.
    await assert.rejects(custody.referenceSigner(vaultRef("rot", pk1, 7)).signHash(HASH), (e) => code("KEY_UNAVAILABLE", "VERSION_UNAVAILABLE")(e) && /holds v1, v2/.test(e.message));
    // Vault answering with another version than the pinned one (a proxy rewrites key_version): refused, not used.
    const proxy = await startVaultProxy(vault.address, { rewrite: ({ path, body }) => (path.includes("/sign/") ? { body: { ...body, key_version: 2 } } : undefined) });
    t.after(() => proxy.close());
    const viaProxy = custody.referenceSigner(custody.keyReference({ keyId: "owner:1", publicKey: pk1, signer: { ...spec("rot", 1), address: proxy.address } }));
    await assert.rejects(viaProxy.signHash(HASH), (e) => code("KEY_UNAVAILABLE", "VERSION_MISMATCH")(e) && /v2, not the pinned v1/.test(e.message));
    // min_encryption_version above the pinned version: Vault no longer signs with it; nothing is appended.
    await vault.configKey("rot", { min_encryption_version: 2 });
    const before = h.owner.exportHistory().length;
    await assert.rejects(grant(h.owner, "refused"), code("KEY_UNAVAILABLE", "VERSION_UNAVAILABLE"));
    assert.equal(h.owner.exportHistory().length, before, "nothing appended");
    await vault.configKey("rot", { min_encryption_version: 1 });
    await grant(h.owner, "again");
  });
});

test("real Vault: a revoked token is SIGNER_FAILED, a deleted key KEY_UNAVAILABLE, a reference with another public key KEY_UNAVAILABLE, a forged signature SIGNER_FAILED; nothing is appended and recovery works", vaultSkip, async (t) => {
  const dir = scratchDir(t);
  const pk = await vault.createKey("fail");
  const other = await vault.createKey("fail-other");
  const child = await vault.childToken(["fail"]);
  const h = await withToken(child, () => history(t, dir, vaultRef("fail", pk)));
  await withToken(child, () => h.owner.createAgent({ id: "bea" }));
  const count = () => h.owner.exportHistory().length;
  const base = count();
  // Revoked token.
  await vault.revokeToken(child);
  await withToken(child, async () => {
    await assert.rejects(grant(h.owner, "revoked"), (e) => code("SIGNER_FAILED", "PERMISSION_DENIED")(e) && /permission denied/.test(e.message));
  });
  assert.equal(count(), base);
  // A reference naming key "fail" with the public key of "fail-other": refused before signing.
  await withToken(vault.token, async () => {
    await assert.rejects(custody.referenceSigner(vaultRef("fail", other)).signHash(HASH), (e) => code("KEY_UNAVAILABLE", "PUBLIC_KEY_MISMATCH")(e) && /holds another public key/.test(e.message));
    // A forged signature (a proxy replaces Vault's answer): verified locally, SIGNER_FAILED, never used.
    const forged = `vault:v1:${Buffer.alloc(64, 7).toString("base64")}`;
    const proxy = await startVaultProxy(vault.address, { answer: ({ path, json }) => (path.includes("/sign/") ? { ...json, data: { ...json.data, signature: forged } } : undefined) });
    t.after(() => proxy.close());
    await assert.rejects(custody.referenceSigner(custody.keyReference({ keyId: "owner:1", publicKey: pk, signer: { ...spec("fail", 1), address: proxy.address } })).signHash(HASH), code("SIGNER_FAILED", "SIGNATURE_INVALID"));
    // Deleted key.
    await vault.deleteKey("fail");
    await assert.rejects(grant(h.owner, "deleted"), (e) => code("KEY_UNAVAILABLE", "KEY_NOT_FOUND")(e) && /deleted, never created/.test(e.message));
    assert.equal(count(), base);
    const check = await custody.checkVaultKey(custody.parseKeyReference(JSON.parse(readFileSync(`${h.historyFile}.owner-key.json`, "utf8"))).signer, { keyId: "owner:1", publicKey: pk });
    assert.equal(check.ok, false);
    assert.equal(check.reason, "KEY_NOT_FOUND");
  });
  // Recovery with a working token on a history whose key still exists is covered above; here the key is gone for good:
  // the history stays verifiable, and the next key (none committed here) is the documented way out (docs/CUSTODY.md §10).
  assert.equal(verifyHistory(h.historyFile).ok, true);
  assert.ok(existsSync(`${h.historyFile}.owner-key.json`));
});

test("real Vault over https with a private CA: refused without the CA (TLS), signs with caFile or VAULT_CACERT", vaultSkip, async (t) => {
  const dir = scratchDir(t);
  const tls = selfSignedCert(dir);
  if (tls === undefined) { t.skip("openssl is not available to make a test certificate"); return; }
  const pk = await vault.createKey("tls");
  const proxy = await startVaultProxy(vault.address, { tls });
  t.after(() => proxy.close());
  assert.match(proxy.address, /^https:/);
  const at = (extra = {}) => custody.referenceSigner(custody.keyReference({ keyId: "owner:1", publicKey: pk, signer: { ...spec("tls", 1, extra), address: proxy.address } }));
  await withToken(vault.token, async () => {
    await assert.rejects(at().signHash(HASH), (e) => code("SIGNER_FAILED", "TLS")(e) && /--vault-ca-file/.test(e.message));
    await at({ caFile: tls.certFile }).signHash(HASH);
    await assert.rejects(at({ caFile: join(dir, "missing.pem") }).signHash(HASH), code("SIGNER_FAILED", "CA_FILE"));
    process.env.VAULT_CACERT = tls.certFile;
    try { await at().signHash(HASH); } finally { delete process.env.VAULT_CACERT; }
  });
});
