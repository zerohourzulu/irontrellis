// Regression tests for the independent block 4 review:
// M2 (command signer cwd, PATH, relative file arguments), L2 (process-group kill, stderr caps), L3 (Vault request
// errors, VAULT_NAMESPACE), L4 (symbolic links refused, checked reference reader, an external signer asked only for a key
// in force), L6 (ssh-agent framing: several messages per chunk, dripped answers).
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { join } from "node:path";
import { commandSignerScript, ed25519Blob, fakeKey, scratchDir } from "./helpers/ssh-agent.mjs";

const custody = await import("../src/custody/index.ts");
const signerLib = await import("../src/signer.ts");
const { generateKeyPair } = await import("../src/crypto/suites.ts");
const { createLocalOwner, openLocalOwner, createLocalDomain } = await import("../src/owner.ts");

const HASH = `0x${"ab".repeat(32)}`;
const code = (expected, reason) => (e) => e.code === expected && (reason === undefined || e.detail?.reason === reason);
const refFor = (publicKey, signer, next = false) => custody.keyReference({ keyId: next ? "owner:2" : "owner:1", publicKey, signer, next });
let clock = 9_100_000;
const now = () => (clock += 1);

test("M2: a command signer runs in the file-system root with PATH=/usr/bin:/bin; relative file arguments are refused", async (t) => {
  const dir = scratchDir(t);
  const pair = generateKeyPair("ed25519", "owner:1");
  // What the child sees: its cwd and PATH.
  const probe = join(dir, "probe.mjs");
  const seen = join(dir, "seen.json");
  writeFileSync(probe, `import { writeFileSync } from "node:fs";\nwriteFileSync(${JSON.stringify(seen)}, JSON.stringify({ cwd: process.cwd(), path: process.env.PATH }));\nprocess.exit(3);\n`);
  const planted = join(dir, "attack");
  mkdirSync(planted);
  writeFileSync(join(planted, "signer.mjs"), `require("fs").writeFileSync(${JSON.stringify(join(dir, "pwned"))}, "ran");`);
  const before = process.cwd();
  process.chdir(planted);
  t.after(() => process.chdir(before));
  const saved = process.env.PATH;
  process.env.PATH = `${planted}:${saved}`;
  t.after(() => { process.env.PATH = saved; });
  await assert.rejects(custody.referenceSigner(refFor(pair.credential, { kind: "command", argv: [process.execPath, probe] })).signHash(HASH), code("SIGNER_FAILED", "EXIT"));
  assert.deepEqual(JSON.parse(readFileSync(seen, "utf8")), { cwd: "/", path: "/usr/bin:/bin" });
  // PoC 03a: a relative script argument, resolved against an agent-writable cwd, is refused at parse time.
  for (const argv of [[process.execPath, "signer.mjs"], [process.execPath, "./signer.mjs"], [process.execPath, "--script=lib/sign.js"], [process.execPath, "~/kms.py"]]) {
    assert.throws(() => refFor(pair.credential, { kind: "command", argv }), (e) => e.code === "KEY_UNAVAILABLE" && /relative path/.test(e.message), JSON.stringify(argv));
  }
  assert.equal(existsSync(join(dir, "pwned")), false);
  // Resource names, ARNs and URLs pass as they are.
  refFor(pair.credential, { kind: "command", argv: ["/usr/bin/node", "/opt/gcp-kms-sign.mjs", "--version-name", "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1", "arn:aws:kms:us-east-1:1:key/abc", "https://kms.example/v1"] });
  // PATH comes only from the reference's `path` (absolute directories); passEnv/env cannot set it.
  assert.throws(() => refFor(pair.credential, { kind: "command", argv: ["/bin/true"], passEnv: ["PATH"] }), /PATH is not taken/);
  assert.throws(() => refFor(pair.credential, { kind: "command", argv: ["/bin/true"], path: "bin:/usr/bin" }), /absolute directories/);
  assert.equal(refFor(pair.credential, { kind: "command", argv: ["/bin/true"], path: "/opt/kms/bin:/usr/bin" }).signer.path, "/opt/kms/bin:/usr/bin");
  // A working signer still works from the root.
  const ok = commandSignerScript(dir, pair.privateKey, "ok");
  await custody.referenceSigner(refFor(pair.credential, { kind: "command", argv: [process.execPath, ok] })).signHash(HASH);
});

test("L2: a timeout kills the signer's whole process group (grandchildren too); stderr in messages is capped and redacted", { skip: process.platform === "win32" ? "POSIX process groups" : false }, async (t) => {
  const dir = scratchDir(t);
  const pair = generateKeyPair("ed25519", "owner:1");
  const marker = join(dir, "grandchild-alive");
  const script = join(dir, "grandchild.sh");
  writeFileSync(script, `#!/bin/sh\n(sleep 2; echo late > ${marker}) &\nsleep 30\n`, { mode: 0o700 });
  chmodSync(script, 0o700);
  const started = Date.now();
  await assert.rejects(custody.referenceSigner(refFor(pair.credential, { kind: "command", argv: [script], timeoutMs: 300 })).signHash(HASH), code("SIGNER_FAILED", "TIMEOUT"));
  assert.ok(Date.now() - started < 2000, "the error comes at the timeout");
  await new Promise((resolve) => setTimeout(resolve, 2500));
  assert.equal(existsSync(marker), false, "the grandchild was killed with the group");
  const tail = custody.stderrTail(Buffer.from(`line one\n\u001b[31mcolour\u0007\ntoken=hvs.CAESIsecretsecretsecret authorization: Bearer abc\n${"A".repeat(60)}\n`));
  assert.ok(!/hvs\.CAES|Bearer abc|\u001b|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/.test(tail), tail);
  assert.match(tail, /\[redacted\]/);
  assert.ok(custody.stderrTail(Buffer.from("x".repeat(5000).replace(/x/g, "x "))).length <= 245);
});

test("L3: VAULT_NAMESPACE with a line break is refused as SIGNER_FAILED/NAMESPACE_INVALID (no ReferenceError, no header sent)", async () => {
  const ref = refFor(`0x${"11".repeat(32)}`, { kind: "vault-transit", address: "http://127.0.0.1:1", key: "owner", keyVersion: 1 });
  const saved = { t: process.env.VAULT_TOKEN, n: process.env.VAULT_NAMESPACE };
  process.env.VAULT_TOKEN = "hvs.x";
  process.env.VAULT_NAMESPACE = "team\r\nX-Injected: 1";
  try {
    await assert.rejects(custody.referenceSigner(ref).signHash(HASH), code("SIGNER_FAILED", "NAMESPACE_INVALID"));
    const check = await custody.checkVaultKey(ref.signer, { keyId: "owner:1", publicKey: ref.publicKey });
    assert.equal(check.ok, false);
    assert.equal(check.reason, "NAMESPACE_INVALID");
  } finally {
    if (saved.t === undefined) delete process.env.VAULT_TOKEN; else process.env.VAULT_TOKEN = saved.t;
    if (saved.n === undefined) delete process.env.VAULT_NAMESPACE; else process.env.VAULT_NAMESPACE = saved.n;
  }
});

test("L4: key files and references are never followed through symbolic links; readKeyReferenceFile applies the loader's checks", (t) => {
  const dir = scratchDir(t);
  const pair = generateKeyPair("ed25519", "owner:1");
  const real = join(dir, "real.owner-key-ref.json");
  signerLib.writeKeyReferenceFile(real, refFor(pair.credential, { kind: "command", argv: ["/bin/true"] }));
  const link = join(dir, "h.jsonl.owner-key.json");
  symlinkSync(real, link);
  assert.throws(() => signerLib.loadOwnerKeyFile(link), (e) => e.code === "KEY_UNAVAILABLE" && e.detail?.reason === "SYMLINK");
  assert.throws(() => signerLib.readKeyReferenceFile(link), (e) => e.code === "KEY_UNAVAILABLE" && /symbolic link/.test(e.message));
  assert.equal(signerLib.readKeyReferenceFile(real).publicKey, pair.credential);
  chmodSync(real, 0o644);
  assert.throws(() => signerLib.readKeyReferenceFile(real), (e) => e.code === "KEY_UNAVAILABLE" && /mode 0644/.test(e.message));
  chmodSync(real, 0o600);
  assert.throws(() => signerLib.readKeyReferenceFile(real, "next"), /not a next-key key reference/);
  const material = join(dir, "material.json");
  signerLib.createOwnerKeyFile(material, "owner:9");
  assert.throws(() => signerLib.readKeyReferenceFile(material), /not a key reference/);
  const symlinkedKey = join(dir, "x.owner-key.json");
  symlinkSync(material, symlinkedKey);
  assert.throws(() => signerLib.loadOwnerKeyFile(symlinkedKey), (e) => e.detail?.reason === "SYMLINK");
});

test("L4: an owner write asks an external signer only for a key in force (another reference swapped in asks nobody)", async (t) => {
  const dir = scratchDir(t);
  const pair = generateKeyPair("ed25519", "owner:1"), other = generateKeyPair("ed25519", "owner:1");
  const log = join(dir, "asked.log");
  writeFileSync(log, "");
  const good = commandSignerScript(dir, pair.privateKey, "ok", "good.mjs", { logFile: log });
  const historyFile = join(dir, "h.jsonl");
  const config = { historyFile, domain: createLocalDomain(), owner: "owner", controller: "controller", now };
  const owner = await createLocalOwner({ ...config, ownerKeyReference: refFor(pair.credential, { kind: "command", argv: [process.execPath, good] }) });
  owner.close();
  const asked = readFileSync(log, "utf8");
  // Another key's reference swapped in (a different public key, its own signer logging every request).
  const otherLog = join(dir, "other.log");
  writeFileSync(otherLog, "");
  const otherSigner = commandSignerScript(dir, other.privateKey, "ok", "other.mjs", { logFile: otherLog });
  const swapped = signerLib.writeKeyReferenceFile(join(dir, "swapped.json"), refFor(other.credential, { kind: "command", argv: [process.execPath, otherSigner] }));
  const reopened = openLocalOwner({ ...config, signer: swapped });
  t.after(() => reopened.close());
  await assert.rejects(reopened.createAgent({ id: "mallory" }), code("CONTROL_AUTHORIZATION_INVALID"));
  assert.equal(readFileSync(otherLog, "utf8"), "", "the signer of a key not in force was never asked");
  assert.equal(readFileSync(log, "utf8"), asked);
});

test("L6: the ssh-agent client parses answers dripped byte by byte and fails at once on a second, unsolicited message in the same chunk", async (t) => {
  const dir = scratchDir(t);
  const key = fakeKey(generateKeyPair);
  const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
  const str = (b) => Buffer.concat([u32(Buffer.from(b).length), Buffer.from(b)]);
  const frame = (type, body) => Buffer.concat([u32(body.length + 1), Buffer.from([type]), body]);
  const identities = frame(12, Buffer.concat([u32(1), str(ed25519Blob(key.publicKey)), str("k")]));
  const serve = async (name, onRequest) => {
    const socket = join(dir, name);
    const server = createServer((c) => { c.on("error", () => {}); c.on("data", () => onRequest(c)); });
    await new Promise((resolve) => server.listen(socket, resolve));
    t.after(() => new Promise((resolve) => server.close(resolve)));
    return socket;
  };
  // Dripped: every byte in its own write.
  const drip = await serve("drip.sock", (c) => { let i = 0; const next = () => { if (i < identities.length) { c.write(identities.subarray(i, i + 1)); i += 1; setImmediate(next); } }; next(); });
  const listed = await custody.listAgentIdentities({ socket: drip, timeoutMs: 5000 });
  assert.equal(listed.length, 1);
  assert.equal(listed[0].publicKey.toString("hex"), key.publicKey.toString("hex"));
  // Two messages in one chunk: the second is unsolicited → MALFORMED at once, not a timeout.
  const doubled = await serve("double.sock", (c) => c.write(Buffer.concat([identities, identities])));
  const started = Date.now();
  const ref = refFor(`0x${key.publicKey.toString("hex")}`, { kind: "ssh-agent", socket: doubled, timeoutMs: 5000 });
  await assert.rejects(custody.referenceSigner(ref).signHash(HASH), (e) => e.code === "SIGNER_FAILED" && e.detail?.reason === "MALFORMED");
  assert.ok(Date.now() - started < 2000, "failed at once");
});

test("L7: an owner write does not hold the writer lock while it waits for a slow signer's pin attestation", async (t) => {
  const dir = scratchDir(t);
  const { openHistoryStore } = await import("../src/store.ts");
  const pair = generateKeyPair("ed25519", "owner:1");
  const prog = join(dir, "slow.mjs");
  writeFileSync(prog, `import { createPrivateKey, sign } from "node:crypto";
const c = []; for await (const x of process.stdin) c.push(x); const r = JSON.parse(Buffer.concat(c));
if (r.purpose === "head-attestation") await new Promise((s) => setTimeout(s, 1500));
const k = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from("${pair.privateKey.slice(2)}", "hex")]), format: "der", type: "pkcs8" });
process.stdout.write(JSON.stringify({ signature: sign(null, Buffer.from(r.message, "base64"), k).toString("base64") }));`);
  const historyFile = join(dir, "h.jsonl");
  const owner = await createLocalOwner({ historyFile, domain: createLocalDomain(), owner: "o", controller: "c", now: () => Date.now(), nextKey: false,
    ownerKeyReference: refFor(pair.credential, { kind: "command", argv: [process.execPath, prog] }) });
  t.after(() => owner.close());
  const writing = owner.createAgent({ id: "bea" });
  await new Promise((resolve) => setTimeout(resolve, 700));
  const other = openHistoryStore(historyFile, { inspect: true, allowUnpinned: true });
  try { other.withExclusiveWriter(() => {}); } finally { other.close(); }
  await writing;
});

test("a command signer's own error message is redacted and bounded like its stderr (a token or control characters never pass)", async (t) => {
  const dir = scratchDir(t);
  const pair = generateKeyPair("ed25519", "owner:1");
  const leaky = join(dir, "leaky.mjs");
  const secret = "ab".repeat(20);
  writeFileSync(leaky, `process.stdout.write(JSON.stringify({ error: { message: "upstream said token=${secret} \\u001b[31m" + "x".repeat(400) } })); process.exit(1);\n`);
  await assert.rejects(custody.referenceSigner(refFor(pair.credential, { kind: "command", argv: [process.execPath, leaky] })).signHash(HASH), (e) => {
    assert.equal(e.code, "SIGNER_FAILED");
    assert.doesNotMatch(e.message, new RegExp(secret));
    assert.match(e.message, /\[redacted\]/);
    assert.doesNotMatch(e.message, /\u001b/);
    assert.ok(e.message.length < 600, `bounded: ${e.message.length}`);
    return true;
  });
});

test("realistic Vault and AWS signer errors keep no token, Bearer value, key= value or long secret; a plain 'no such key version' stays readable", async (t) => {
  const dir = scratchDir(t);
  const pair = generateKeyPair("ed25519", "owner:1");
  const cases = [
    // Vault transit, a short (legacy) service token after the word "token", and a modern hvs. token.
    ["Error making API request. URL: PUT https://vault.example:8200/v1/transit/sign/owner Code: 403. Errors: * permission denied (token s.Xy7Kp2Qa9Lm3Zt8Rv1Wn5Bc4)", ["s.Xy7Kp2Qa9Lm3Zt8Rv1Wn5Bc4"]],
    ["vault: invalid token hvs.CAESIJ3pX8kq2LmZ9tR7vW1nB5c4Gh6Dj0Fs8Yu2Io4Pa3Qw", ["hvs.CAESIJ3pX8kq2LmZ9tR7vW1nB5c4Gh6Dj0Fs8Yu2Io4Pa3Qw"]],
    ["Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvd25lciJ9.c2lnbmF0dXJl", ["eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvd25lciJ9.c2lnbmF0dXJl"]],
    // AWS: a presigned URL's security token and an access key in a key= form.
    ["An error occurred (ExpiredTokenException) when calling the Sign operation: request X-Amz-Security-Token=IQoJb3JpZ2luX2VjEJr expired; aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", ["IQoJb3JpZ2luX2VjEJr", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]],
  ];
  for (const [message, secrets] of cases) {
    const script = join(dir, `err-${secrets[0].length}.mjs`);
    writeFileSync(script, `process.stdout.write(JSON.stringify({ error: { message: ${JSON.stringify(message)} } })); process.exit(1);\n`);
    await assert.rejects(custody.referenceSigner(refFor(pair.credential, { kind: "command", argv: [process.execPath, script] })).signHash(HASH), (e) => {
      for (const secret of secrets) assert.doesNotMatch(e.message, new RegExp(secret.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")), message);
      assert.match(e.message, /\[redacted\]/);
      return true;
    });
  }
});

test("authorization schemes keep their name and lose their credential, on both signer error paths", async (t) => {
  const dir = scratchDir(t);
  const pair = generateKeyPair("ed25519", "owner:1");
  const { signerMessage } = await import("../src/custody/command.ts");
  assert.equal(signerMessage("no such key version"), ": no such key version");
  const cases = [
    ["Authorization: Bearer s.ExampleShortTokenOnly", ["s.ExampleShortTokenOnly"], /Bearer \[redacted\]/],
    ["Authorization: Basic dXNlcjpwYXNz", ["dXNlcjpwYXNz"], /Basic \[redacted\]/],
    ["Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261025/us-east-1/kms/aws4_request, SignedHeaders=host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6",
      ["AKIDEXAMPLE/20261025", "5d672d79c15b13162d9279b0855cfba6"], /Credential=\[redacted\]/],
  ];
  for (const errorCode of ["KEY_UNAVAILABLE", "OTHER"]) {
    for (const [message, secrets, kept] of cases) {
      const script = join(dir, `auth-${errorCode}-${secrets[0].length}.mjs`);
      writeFileSync(script, `process.stdout.write(JSON.stringify({ error: { code: ${JSON.stringify(errorCode)}, message: ${JSON.stringify(message)} } })); process.exit(1);\n`);
      await assert.rejects(custody.referenceSigner(refFor(pair.credential, { kind: "command", argv: [process.execPath, script] })).signHash(HASH), (e) => {
        for (const secret of secrets) assert.equal(e.message.includes(secret), false, `${errorCode}: ${message}`);
        assert.match(e.message, kept);
        return true;
      });
    }
  }
});

test("every secret name is redacted after any delimiter (whitespace, '=', ':', with spaces), in a signer's message and its stderr", async () => {
  const { signerMessage, stderrTail } = await import("../src/custody/command.ts");
  const secret = "s.ShortSecret01";
  for (const name of ["token", "Bearer", "secret", "password", "passwd", "authorization", "api_key", "credential", "signature"]) {
    for (const delimiter of ["=", ": ", ":", " = ", " : ", " "]) {
      const form = `${name}${delimiter}${secret}`;
      for (const [path, out] of [["signerMessage", signerMessage(`upstream said ${form} today`)], ["stderrTail", stderrTail(Buffer.from(`upstream said ${form} today\n`))]]) {
        assert.equal(out.includes(secret), false, `${path}: ${form} -> ${out}`);
        assert.match(out, /\[redacted\]/, `${path}: ${form}`);
      }
    }
  }
  // The scheme keeps its name; a plain word after "key" stays in a signer's message.
  assert.equal(signerMessage(`Authorization: Bearer ${secret}`), ": Authorization: Bearer [redacted]");
  assert.equal(signerMessage("no such key version"), ": no such key version");
});
