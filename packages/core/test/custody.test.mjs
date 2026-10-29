// Block 4 (owner-key custody, phase A): key references, the ssh-agent signer against a REAL OpenSSH agent (and a fake
// one for misbehaviour), the command signer, public-key-only next keys, pre-rotation onto a key a signer holds, and the
// crash windows of a rotation whose next key is external. Every signature a backend returns is verified locally.
import { test } from "node:test";
import assert from "node:assert/strict";
import { chownSync, chmodSync, existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { connect } from "node:net";
import { join } from "node:path";
import { commandSignerScript, fakeKey, haveOpenSsh, scratchDir, sshKeygen, startFakeAgent, startSshAgent } from "./helpers/ssh-agent.mjs";
import { startFakeWitness } from "./helpers/fake-witness.mjs";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling

const custody = { ...(await import("../src/custody/index.ts")), setAgentConnectorForTests: (await import("../src/custody/ssh-agent.ts")).setAgentConnectorForTests }; // the hook is not on a public subpath (step 5b review)
const signerLib = await import("../src/signer.ts");
const { TRELLIS_FORMAT } = await import("../src/events.ts");
const { generateKeyPair, suiteFor } = await import("../src/crypto/suites.ts");
const { createLocalOwner: createLocalOwnerDefault, openLocalOwner: openLocalOwnerDefault, createLocalDomain: createLocalDomainDefault, verifyHistory, verifyHistoryWithWitnesses, setRotationFaultForTests, RotationFault } = await import("../src/owner.ts");
// These tests cover the format-1 (and legacy) owner API; the API writes format 2 by default (SPEC §19), so format 1 is named for every handle and domain made here.
const createLocalOwner = (options) => createLocalOwnerDefault({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true, ...options });
const openLocalOwner = (options) => openLocalOwnerDefault({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true, ...options });
const createLocalDomain = (options = {}) => createLocalDomainDefault({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true, ...options });
const { openHistoryStore: openHistoryStoreStrict } = await import("../src/store.ts");
// Fixture writes to legacy and format-1 files (SPEC §16.1: those formats open read only by default; format 2 is the wire). These tests cover the earlier store writer, so the fence is off here.
const openHistoryStore = (path, options = {}) => openHistoryStoreStrict(path, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true, ...options });
const { ownerKeyDigest } = await import("../src/owner-keys.ts");
const { resetWitnessViews } = await import("../src/witness-session.ts");
const { pendingRotationPathFor } = await import("../src/rotation-pending.ts");

const skipNoSsh = haveOpenSsh ? {} : { skip: "OpenSSH (ssh-agent, ssh-add, ssh-keygen) is not installed" };
const HASH = `0x${"ab".repeat(32)}`;
const code = (expected, reason) => (e) => e.code === expected && (reason === undefined || e.detail?.reason === reason);
const bytes = (path) => (existsSync(path) ? readFileSync(path) : undefined);
let clock = 7_000_000;
const now = () => (clock += 1);

/** A reference to `key` (an sshKeygen result, or anything with publicKey) in the agent at `socket`. */
const agentRef = (key, socket, keyId = "owner:1", next = false) => custody.keyReference({ keyId, publicKey: key.publicKey, signer: { kind: "ssh-agent", socket }, next });

/** A fresh history whose owner key is held by `ownerRef` (and whatever else `options` says). */
async function history(t, dir, ownerRef, options = {}) {
  const historyFile = join(dir, "h.jsonl");
  const domain = createLocalDomain();
  const config = { historyFile, domain, owner: "owner", controller: "controller", now };
  const owner = await createLocalOwner({ ...config, ownerKeyReference: ownerRef, ...options });
  t.after(() => owner.close());
  return { historyFile, config, owner, open: (more = {}) => openLocalOwner({ ...config, ...more }), pin: () => JSON.parse(readFileSync(`${historyFile}.head`, "utf8")) };
}
const grant = (owner, id = "g1") => owner.grant({ id, to: "bea", actions: ["read"], resources: ["r:1"], expiresAt: 9_000_000_000 });

// ---------------------------------------------------------------- formats

test("public keys: 0x hex, bare hex and OpenSSH lines are accepted; FIDO and non-Ed25519 keys are refused with the reason", () => {
  const pair = generateKeyPair("ed25519", "k");
  const line = custody.sshPublicKeyOf(pair.credential, "me@host");
  assert.match(line, /^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]+=* me@host$/);
  for (const text of [pair.credential, pair.credential.slice(2).toUpperCase(), line, `  ${line}  `]) assert.equal(custody.parsePublicKey(text), pair.credential.toLowerCase());
  const pub = Buffer.from(pair.credential.slice(2), "hex");
  const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
  const s = (x) => Buffer.concat([u32(Buffer.from(x).length), Buffer.from(x)]);
  const sk = `sk-ssh-ed25519@openssh.com ${Buffer.concat([s("sk-ssh-ed25519@openssh.com"), s(pub), s("ssh:")]).toString("base64")}`;
  assert.throws(() => custody.parsePublicKey(sk), (e) => e.code === "INVALID_INPUT" && /FIDO/.test(e.message));
  assert.throws(() => custody.parsePublicKey("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ"), (e) => e.code === "INVALID_INPUT" && /only ssh-ed25519/.test(e.message));
  assert.throws(() => custody.parsePublicKey("ecdsa-sha2-nistp256 AAAA"), (e) => /only ssh-ed25519/.test(e.message));
  assert.throws(() => custody.parsePublicKey(`ssh-ed25519 ${Buffer.concat([s("ssh-rsa"), s(pub)]).toString("base64")}`), (e) => /not a well-formed/.test(e.message));
  assert.throws(() => custody.parsePublicKey("0x1234"), (e) => e.code === "INVALID_INPUT");
});

test("key references: written 0600 and exclusive, loaded without contacting the signer, refused when loose, foreign, unknown or of the other role", (t) => {
  const dir = scratchDir(t);
  const pair = generateKeyPair("ed25519", "owner:1");
  const ref = custody.keyReference({ keyId: "owner:1", publicKey: pair.credential, signer: { kind: "ssh-agent", socket: join(dir, "nowhere.sock") } });
  const path = join(dir, "h.jsonl.owner-key.json");
  signerLib.writeKeyReferenceFile(path, ref);
  if (process.platform !== "win32") assert.equal(statSync(path).mode & 0o777, 0o600);
  assert.throws(() => signerLib.writeKeyReferenceFile(path, ref), code("KEY_EXISTS"));
  const text = JSON.parse(readFileSync(path, "utf8"));
  assert.deepEqual(Object.keys(text), ["version", "keyId", "scheme", "publicKey", "signer"]);
  assert.equal(text.version, custody.OWNER_KEY_REF_VERSION);
  const loaded = signerLib.loadOwnerKeyFile(path); // the socket does not exist: nothing is contacted by a load
  assert.equal(loaded.signHashSync, undefined, "a reference signs asynchronously only");
  assert.equal(loaded.credential, pair.credential);
  assert.equal(loaded.custody.holder, "reference");
  assert.equal(loaded.custody.signer, "ssh-agent");
  assert.equal(signerLib.keyFileHolder(path, "owner"), "reference");
  assert.throws(() => signerLib.loadNextOwnerKeyFile(path), (e) => e.code === "KEY_UNAVAILABLE" && /is an owner key file/.test(e.message));
  const nextPath = join(dir, "next.owner-next-key-ref.json");
  signerLib.writeKeyReferenceFile(nextPath, custody.withReferenceVersion(ref, custody.OWNER_NEXT_KEY_REF_VERSION, "owner:2"));
  assert.equal(signerLib.loadNextOwnerKeyFile(nextPath).keyId, "owner:2");
  assert.throws(() => signerLib.loadOwnerKeyFile(nextPath), (e) => e.code === "KEY_UNAVAILABLE" && /is a next-key file/.test(e.message));
  if (process.platform !== "win32") {
    chmodSync(path, 0o644);
    assert.throws(() => signerLib.loadOwnerKeyFile(path), (e) => e.code === "KEY_UNAVAILABLE" && /mode 0644/.test(e.message));
    chmodSync(path, 0o600);
    if (process.getuid?.() === 0) {
      // A reference decides which program signs as the owner: one another user owns is never used.
      chownSync(path, 65534, 65534);
      assert.throws(() => signerLib.loadOwnerKeyFile(path), (e) => e.code === "KEY_UNAVAILABLE" && /owned by uid 65534/.test(e.message));
      chownSync(path, 0, 0);
    }
  }
  const bad = (record, pattern) => {
    writeFileSync(path, JSON.stringify(record), { mode: 0o600 });
    assert.throws(() => signerLib.loadOwnerKeyFile(path), (e) => e.code === "KEY_UNAVAILABLE" && pattern.test(e.message), JSON.stringify(record));
  };
  bad({ ...text, signer: { kind: "hsm-of-the-future" } }, /signer kind "hsm-of-the-future", which this installation does not know/);
  bad({ ...text, extra: 1 }, /unknown field/);
  bad({ ...text, scheme: "eip191-personal-sign-keccak256" }, /scheme must be ed25519/);
  bad({ ...text, publicKey: "0x12" }, /not an Ed25519 public key/);
  bad({ ...text, signer: { kind: "ssh-agent", socket: 5 } }, /socket must be a non-empty path/);
  bad({ ...text, signer: { kind: "command", argv: ["relative/sign"] } }, /argv\[0\] must be an absolute path/);
  bad({ ...text, signer: { kind: "command", argv: ["/bin/true"], shell: true } }, /unknown command signer field/);
});

test("the backend registry is extensible: a registered kind signs (verified locally), a built-in kind cannot be replaced", async (t) => {
  const dir = scratchDir(t);
  const pair = generateKeyPair("ed25519", "owner:1");
  const sign = signerLib.signerFromKeyPair(pair);
  let asked = 0;
  custody.registerSignerBackend({
    kind: "test-hsm", parse: (spec) => ({ kind: "test-hsm", slot: spec.slot }), describe: (spec) => `test HSM slot ${spec.slot}`, identity: (spec) => String(spec.slot),
    async sign(_spec, key, message, context) { asked += 1; assert.equal(context.purpose, "signer-test"); return Buffer.from((await sign.signHash(`0x${Buffer.from(message).toString("hex")}`)).slice(2), "hex"); },
  });
  assert.ok(custody.signerBackendKinds().includes("test-hsm"));
  assert.throws(() => custody.registerSignerBackend({ kind: "ssh-agent", parse: (x) => x, describe: () => "", identity: () => "", sign: async () => new Uint8Array() }), /built in/);
  const path = join(dir, "hsm.ref.json");
  signerLib.writeKeyReferenceFile(path, custody.keyReference({ keyId: "owner:1", publicKey: pair.credential, signer: { kind: "test-hsm", slot: 3 } }));
  const signer = signerLib.loadOwnerKeyFile(path);
  assert.equal(signer.custody.description, "test HSM slot 3");
  const signature = await signer.signHash(HASH, { purpose: "signer-test" });
  assert.equal(suiteFor("ed25519").verify(HASH, signature, pair.credential), true);
  assert.equal(asked, 1);
});

// ---------------------------------------------------------------- the ssh-agent signer against a real OpenSSH agent

test("ssh-agent (real OpenSSH agent): signs the 32-byte hash as plain Ed25519; a key removed from the agent is KEY_UNAVAILABLE; a declined confirmation and a dead agent are SIGNER_FAILED", skipNoSsh, async (t) => {
  const dir = scratchDir(t);
  const agent = await startSshAgent(t, dir);
  const key = sshKeygen(dir, "owner1");
  agent.add(key.file);
  const signer = custody.referenceSigner(agentRef(key, agent.socket));
  const signature = await signer.signHash(HASH, { purpose: "signer-test" });
  assert.equal(suiteFor("ed25519").verify(HASH, signature, key.publicKey), true, "the agent's ssh-ed25519 signature is the Ed25519 signature over the hash");
  assert.equal(await signer.signHash(HASH), signature, "Ed25519 is deterministic");
  // Not in the agent: a clean KEY_UNAVAILABLE that names the key.
  agent.remove(`${key.file}.pub`);
  await assert.rejects(signer.signHash(HASH), (e) => code("KEY_UNAVAILABLE", "KEY_NOT_IN_AGENT")(e) && e.message.includes(key.pub.split(" ").slice(0, 2).join(" ")) && /ssh-add/.test(e.message));
  // Confirm mode (ssh-add -c) with no way to ask (no ssh-askpass here): the agent refuses, as when a person declines in 1Password.
  agent.add(key.file, ["-c"]);
  await assert.rejects(signer.signHash(HASH), (e) => code("SIGNER_FAILED", "REFUSED")(e) && /refused to sign/.test(e.message));
  agent.remove(`${key.file}.pub`);
  agent.add(key.file);
  assert.equal(await signer.signHash(HASH), signature);
  // A dead agent.
  await agent.kill();
  await assert.rejects(signer.signHash(HASH), code("SIGNER_FAILED", "UNREACHABLE"));
  // No agent at all: no socket in the reference and no SSH_AUTH_SOCK.
  const saved = process.env.SSH_AUTH_SOCK;
  delete process.env.SSH_AUTH_SOCK;
  try {
    const noSocket = custody.referenceSigner(custody.keyReference({ keyId: "owner:1", publicKey: key.publicKey, signer: { kind: "ssh-agent" } }));
    if (process.platform !== "win32") await assert.rejects(noSocket.signHash(HASH), code("SIGNER_FAILED", "NO_AGENT"));
  } finally { if (saved !== undefined) process.env.SSH_AUTH_SOCK = saved; }
});

test("ssh-agent: an IronTrellis key file converted to OpenSSH format (signer to-ssh) is loaded by ssh-add and signs as the same key", skipNoSsh, async (t) => {
  const dir = scratchDir(t);
  const agent = await startSshAgent(t, dir);
  const keyFile = join(dir, "h.jsonl.owner-key.json");
  const local = signerLib.createOwnerKeyFile(keyFile, "owner:1");
  const record = JSON.parse(readFileSync(keyFile, "utf8"));
  const sshFile = join(dir, "owner1.ssh");
  writeFileSync(sshFile, custody.openSshPrivateKey(Buffer.from(record.privateKey.slice(2), "hex"), Buffer.from(record.credential.slice(2), "hex"), "irontrellis owner:1"), { mode: 0o600 });
  agent.add(sshFile);
  assert.equal(agent.list().trim().split(" ").slice(0, 2).join(" "), custody.sshPublicKeyOf(local.credential));
  const viaAgent = custody.referenceSigner(custody.keyReference({ keyId: "owner:1", publicKey: local.credential, signer: { kind: "ssh-agent", socket: agent.socket } }));
  assert.equal(await viaAgent.signHash(HASH), await local.signHash(HASH), "the agent signs exactly as the key file did");
});

// ---------------------------------------------------------------- misbehaving agents (fake)

test("ssh-agent (fake agent): a wrong, altered, malformed or mislabelled signature is SIGNER_FAILED and never returned; silence times out; a FIDO-only key is refused", async (t) => {
  const dir = scratchDir(t);
  const k = fakeKey(generateKeyPair);
  for (const [behaviour, reason] of [["wrong-signature", "SIGNATURE_INVALID"], ["flipped", "SIGNATURE_INVALID"], ["malformed", "MALFORMED"], ["rsa-type", "MALFORMED"], ["refuse", "REFUSED"]]) {
    const fake = await startFakeAgent(t, dir, { keys: [k], behaviour, name: `${behaviour}.sock` });
    const signer = custody.referenceSigner(agentRef({ publicKey: k.pair.credential }, fake.socket));
    await assert.rejects(signer.signHash(HASH), code("SIGNER_FAILED", reason), behaviour);
    assert.equal(fake.requests.length, 1);
    assert.equal(fake.requests[0].toString("hex"), HASH.slice(2), "the agent is asked to sign exactly the 32 bytes of the hash");
  }
  const silent = await startFakeAgent(t, dir, { keys: [k], behaviour: "silent", name: "silent.sock" });
  const slow = custody.referenceSigner(custody.keyReference({ keyId: "owner:1", publicKey: k.pair.credential, signer: { kind: "ssh-agent", socket: silent.socket, timeoutMs: 300 } }));
  const started = Date.now();
  await assert.rejects(slow.signHash(HASH), code("SIGNER_FAILED", "TIMEOUT"));
  assert.ok(Date.now() - started < 3000);
  const fido = await startFakeAgent(t, dir, { keys: [{ ...k, type: "sk" }], name: "fido.sock" });
  await assert.rejects(custody.referenceSigner(agentRef({ publicKey: k.pair.credential }, fido.socket)).signHash(HASH), code("KEY_UNAVAILABLE", "FIDO_KEY"));
});

test("ssh-agent on Windows: the default is the OpenSSH named pipe \\\\.\\pipe\\openssh-ssh-agent (SSH_AUTH_SOCK wins when set); the pipe code path runs against a fake connector", async (t) => {
  assert.equal(custody.agentSocketPath({}, {}, "win32"), "\\\\.\\pipe\\openssh-ssh-agent");
  assert.equal(custody.WINDOWS_AGENT_PIPE, "\\\\.\\pipe\\openssh-ssh-agent");
  assert.equal(custody.agentSocketPath({}, { SSH_AUTH_SOCK: "\\\\.\\pipe\\custom" }, "win32"), "\\\\.\\pipe\\custom");
  assert.equal(custody.agentSocketPath({ socket: "\\\\.\\pipe\\named" }, { SSH_AUTH_SOCK: "x" }, "win32"), "\\\\.\\pipe\\named");
  assert.equal(custody.agentSocketPath({}, {}, "linux"), undefined, "POSIX without SSH_AUTH_SOCK has no default");
  const dir = scratchDir(t);
  const k = fakeKey(generateKeyPair);
  const fake = await startFakeAgent(t, dir, { keys: [k], name: "pipe.sock" });
  const opened = [];
  const saved = process.env.SSH_AUTH_SOCK;
  delete process.env.SSH_AUTH_SOCK;
  custody.setAgentConnectorForTests((path) => { opened.push(path); return connect(fake.socket); }, { platform: "win32" });
  t.after(() => { custody.setAgentConnectorForTests(undefined); if (saved !== undefined) process.env.SSH_AUTH_SOCK = saved; });
  const signer = custody.referenceSigner(custody.keyReference({ keyId: "owner:1", publicKey: k.pair.credential, signer: { kind: "ssh-agent" } }));
  const signature = await signer.signHash(HASH);
  assert.deepEqual(opened, ["\\\\.\\pipe\\openssh-ssh-agent"], "the named pipe is opened (net.connect takes pipe names on Windows)");
  assert.equal(suiteFor("ed25519").verify(HASH, signature, k.pair.credential), true);
  assert.match(signer.custody.description, /ssh-agent at \$SSH_AUTH_SOCK/);
});

// ---------------------------------------------------------------- the command signer

test("command signer: the protocol (JSON on stdin, {signature} on stdout), a minimal environment, and every failure: timeout, non-zero exit, garbage, a wrong signature, KEY_UNAVAILABLE", async (t) => {
  const dir = scratchDir(t);
  const pair = generateKeyPair("ed25519", "owner:1");
  const ref = (mode, extra = {}) => custody.keyReference({ keyId: "owner:1", publicKey: pair.credential, signer: { kind: "command", argv: [process.execPath, commandSignerScript(dir, pair.privateKey, mode)], ...extra } });
  const ok = custody.referenceSigner(ref("ok"));
  assert.equal(suiteFor("ed25519").verify(HASH, await ok.signHash(HASH, { purpose: "head-attestation" }), pair.credential), true);
  // The script itself as argv[0] (shebang, executable) works too.
  const direct = custody.referenceSigner(custody.keyReference({ keyId: "owner:1", publicKey: pair.credential, signer: { kind: "command", argv: [commandSignerScript(dir, pair.privateKey, "ok", "direct.mjs")] } }));
  assert.equal(await direct.signHash(HASH), await ok.signHash(HASH));
  // Minimal environment: a secret of this process does not reach the program unless passEnv names it.
  process.env.IRONTRELLIS_TEST_SECRET = "s3cret";
  t.after(() => { delete process.env.IRONTRELLIS_TEST_SECRET; });
  const envOf = (signer) => { const e = custody.commandEnvironment(signer); return Object.keys(e); };
  const plain = ref("env");
  assert.ok(!envOf(plain.signer).includes("IRONTRELLIS_TEST_SECRET"));
  assert.ok(envOf(ref("env", { passEnv: ["IRONTRELLIS_TEST_SECRET"] }).signer).includes("IRONTRELLIS_TEST_SECRET"));
  // Since the block 4 review (M2) the caller's PATH is never passed: /usr/bin:/bin, or the reference's own `path`.
  assert.deepEqual(custody.commandEnvironment({ kind: "command", argv: ["/x"], env: { KMS_KEY: "projects/p/keys/k" } }, { PATH: "/home/agent/bin:/bin", SECRET: "x" }), { PATH: custody.COMMAND_SIGNER_PATH, KMS_KEY: "projects/p/keys/k" });
  assert.deepEqual(custody.commandEnvironment({ kind: "command", argv: ["/x"], path: "/opt/kms/bin:/usr/bin" }, { PATH: "/tmp" }), { PATH: "/opt/kms/bin:/usr/bin" });
  assert.equal(suiteFor("ed25519").verify(HASH, await custody.referenceSigner(plain).signHash(HASH), pair.credential), true);
  // Failures: nothing is returned, and the reason is in detail.
  const started = Date.now();
  await assert.rejects(custody.referenceSigner(ref("sleep", { timeoutMs: 400 })).signHash(HASH), (e) => code("SIGNER_FAILED", "TIMEOUT")(e) && /did not answer within 400 ms/.test(e.message));
  assert.ok(Date.now() - started < 5000, "the program is killed at the timeout");
  await assert.rejects(custody.referenceSigner(ref("exit")).signHash(HASH), (e) => code("SIGNER_FAILED", "EXIT")(e) && e.detail.exitCode === 3 && /permission denied for key/.test(e.message));
  await assert.rejects(custody.referenceSigner(ref("garbage")).signHash(HASH), code("SIGNER_FAILED", "MALFORMED"));
  await assert.rejects(custody.referenceSigner(ref("wrong")).signHash(HASH), (e) => code("SIGNER_FAILED", "SIGNATURE_INVALID")(e) && /does not verify against owner key owner:1/.test(e.message));
  await assert.rejects(custody.referenceSigner(ref("key-unavailable")).signHash(HASH), (e) => code("KEY_UNAVAILABLE", "KEY_NOT_HELD")(e) && /no such key version/.test(e.message));
  const missing = custody.referenceSigner(custody.keyReference({ keyId: "owner:1", publicKey: pair.credential, signer: { kind: "command", argv: [join(dir, "no-such-program")] } }));
  await assert.rejects(missing.signHash(HASH), code("SIGNER_FAILED", "SPAWN"));
});

// ---------------------------------------------------------------- the owner API with a key a real agent holds

test("owner key held by a real ssh-agent: init, grant and pin (attested through the agent); a dead agent is SIGNER_FAILED and a removed key KEY_UNAVAILABLE, with nothing appended", skipNoSsh, async (t) => {
  const dir = scratchDir(t);
  const agent = await startSshAgent(t, dir);
  const key = sshKeygen(dir, "owner1"), next = sshKeygen(dir, "next1");
  agent.add(key.file);
  const h = await history(t, dir, agentRef(key, agent.socket), { nextPublicKey: next.pub });
  assert.equal(signerLib.loadOwnerKeyFile(`${h.historyFile}.owner-key.json`).custody.holder, "reference");
  assert.equal(existsSync(`${h.historyFile}.owner-next-key.json`), false, "a public-key-only next key writes nothing");
  await h.owner.createAgent({ id: "bea" });
  const written = await grant(h.owner);
  // The write returns once the pin carries the owner's attestation, signed through the agent.
  assert.equal(h.pin().attestation.head.hash, written.head.hash);
  assert.equal(h.pin().attestation.keyId, "owner:1");
  const report = verifyHistory(h.historyFile);
  assert.equal(report.ok, true, report.failures.join("; "));
  assert.equal(report.pinnedAttestation, "VERIFIED");
  const st = h.owner.ownerKeyStatus();
  assert.equal(st.commitment.nextKeyDigests[0], ownerKeyDigest({ scheme: "ed25519", credential: next.publicKey }));
  assert.deepEqual(st.custody.map((c) => [c.role, c.code, c.level]), [["current", "OWNER_KEY_REFERENCE", "OK"], ["next", "NEXT_KEY_OFF_HOST", "OK"]]);
  assert.deepEqual(st.warnings, []);
  // The key taken out of the agent: KEY_UNAVAILABLE, and neither the file nor the pin moved.
  const before = [bytes(h.historyFile), bytes(`${h.historyFile}.head`)];
  agent.remove(`${key.file}.pub`);
  await assert.rejects(grant(h.owner, "g2"), (e) => e.code === "KEY_UNAVAILABLE" && e.detail.reason === "KEY_NOT_IN_AGENT");
  assert.deepEqual([bytes(h.historyFile), bytes(`${h.historyFile}.head`)], before, "nothing appended");
  // The agent dies (as when it refuses): SIGNER_FAILED, nothing appended.
  agent.add(key.file);
  await agent.kill();
  await assert.rejects(grant(h.owner, "g3"), (e) => e.code === "SIGNER_FAILED" && e.detail.reason === "UNREACHABLE");
  assert.deepEqual([bytes(h.historyFile), bytes(`${h.historyFile}.head`)], before, "nothing appended");
  // A new agent with the key: writing works again from a fresh open.
  const again = await startSshAgent(t, scratchDir(t, "itc2-"));
  again.add(key.file);
  const moved = custody.keyReference({ keyId: "owner:1", publicKey: key.publicKey, signer: { kind: "ssh-agent", socket: again.socket } });
  writeFileSync(`${h.historyFile}.owner-key.json`, custody.keyReferenceText(moved), { mode: 0o600 });
  const reopened = h.open();
  await grant(reopened, "g4");
  assert.equal(verifyHistory(h.historyFile).pinnedAttestation, "VERIFIED");
  reopened.close();
});

test("owner key held by a fake agent that returns a wrong signature: SIGNER_FAILED at creation (no history file) and on a write (nothing appended)", async (t) => {
  const dir = scratchDir(t);
  const k = fakeKey(generateKeyPair);
  const bad = await startFakeAgent(t, dir, { keys: [k], behaviour: "wrong-signature" });
  const historyFile = join(dir, "h.jsonl");
  await assert.rejects(createLocalOwner({ historyFile, domain: createLocalDomain(), owner: "o", controller: "c", now, ownerKeyReference: agentRef({ publicKey: k.pair.credential }, bad.socket) }),
    (e) => e.code === "SIGNER_FAILED" && e.detail.reason === "SIGNATURE_INVALID");
  assert.equal(existsSync(historyFile), false);
  assert.equal(existsSync(`${historyFile}.owner-key.json`), false, "the reference written for the creation is removed again");
  const good = await startFakeAgent(t, dir, { keys: [k], name: "good.sock" });
  const h = await history(t, dir, agentRef({ publicKey: k.pair.credential }, good.socket));
  const before = [bytes(h.historyFile), bytes(`${h.historyFile}.head`)];
  writeFileSync(`${h.historyFile}.owner-key.json`, custody.keyReferenceText(agentRef({ publicKey: k.pair.credential }, bad.socket)), { mode: 0o600 });
  const reopened = h.open();
  await assert.rejects(reopened.createAgent({ id: "x" }), (e) => e.code === "SIGNER_FAILED" && e.detail.reason === "SIGNATURE_INVALID");
  assert.deepEqual([bytes(h.historyFile), bytes(`${h.historyFile}.head`)], before, "a wrong signature is never written");
  reopened.close();
});

test("owner key held by a command signer: create, write, commit a next key by public key only, rotate onto the next key's own command signer", async (t) => {
  const dir = scratchDir(t);
  const one = generateKeyPair("ed25519", "owner:1"), two = generateKeyPair("ed25519", "owner:2"), three = generateKeyPair("ed25519", "owner:3");
  const cmd = (pair) => ({ kind: "command", argv: [process.execPath, commandSignerScript(dir, pair.privateKey, "ok", `${pair.keyId.replace(":", "-")}.mjs`)] });
  const h = await history(t, dir, custody.keyReference({ keyId: "owner:1", publicKey: one.credential, signer: cmd(one) }), { nextKey: false });
  await h.owner.createAgent({ id: "bea" });
  const committed = await h.owner.commitNextKey({ nextPublicKey: custody.sshPublicKeyOf(two.credential) });
  assert.equal(committed.nextKeyFile, undefined);
  assert.equal(committed.keyId, "owner:2", "the next free key id is proposed");
  // The rotation needs the committed key's signer: without it, KEY_UNAVAILABLE and nothing written.
  await assert.rejects(h.owner.rotateOwnerKey(), code("KEY_UNAVAILABLE"));
  const nextRef = join(dir, "two.owner-next-key-ref.json");
  signerLib.writeKeyReferenceFile(nextRef, custody.keyReference({ keyId: "owner:2", publicKey: two.credential, signer: cmd(two), next: true }));
  const rotated = await h.owner.rotateOwnerKey({ nextKeyFile: nextRef, newNextPublicKey: three.credential });
  assert.equal(rotated.preRotated, true);
  assert.equal(rotated.keyId, "owner:2");
  assert.equal(rotated.nextKeyFile, undefined, "the new next key is a public key only");
  const now2 = signerLib.loadOwnerKeyFile(`${h.historyFile}.owner-key.json`);
  assert.equal(now2.credential, two.credential);
  assert.equal(now2.custody.holder, "reference", "the promoted owner key is still held by its signer");
  const retired = signerLib.loadOwnerKeyFile(rotated.retiredKeyFile);
  assert.equal(retired.credential, one.credential);
  assert.equal(retired.custody.holder, "reference", "a retired reference is archived as it was");
  const event = h.owner.exportHistory().find((e) => e.id === rotated.eventId);
  assert.equal(event.data.nextKeyAuthorizations[0].keyId, "owner:2", "the revealed key's proof, signed by its command signer");
  await grant(h.owner);
  const report = verifyHistory(h.historyFile);
  assert.equal(report.ok, true, report.failures.join("; "));
  assert.equal(h.pin().attestation.keyId, "owner:2");
});

test("pre-rotation where the next key is a second key of the same real ssh-agent: committed by reference, NEXT_KEY_SAME_SIGNER, rotated without the next key ever existing as a file", skipNoSsh, async (t) => {
  const dir = scratchDir(t);
  const agent = await startSshAgent(t, dir);
  const k1 = sshKeygen(dir, "owner1"), k2 = sshKeygen(dir, "owner2"), k3 = sshKeygen(dir, "owner3");
  agent.add(k1.file);
  agent.add(k2.file);
  const h = await history(t, dir, agentRef(k1, agent.socket), { nextKeyReference: agentRef(k2, agent.socket, "owner:2", true) });
  const nextPath = `${h.historyFile}.owner-next-key.json`;
  assert.equal(JSON.parse(readFileSync(nextPath, "utf8")).version, custody.OWNER_NEXT_KEY_REF_VERSION);
  const st = h.owner.ownerKeyStatus();
  assert.equal(st.nextKeyOnHost, false, "a reference is not a key on the host");
  assert.equal(st.nextKeyFile.holder, "reference");
  assert.deepEqual(st.warnings.map((w) => w.code), ["NEXT_KEY_SAME_SIGNER"], "both keys in one agent: whoever can use it can rotate");
  await h.owner.createAgent({ id: "bea" });
  // Rotate: the second agent key signs its proof; a third key (public only) becomes the next commitment.
  const rotated = await h.owner.rotateOwnerKey({ newNextPublicKey: k3.pub, reason: "scheduled" });
  assert.equal(rotated.preRotated, true);
  assert.equal(rotated.keyId, "owner:2");
  assert.equal(existsSync(nextPath), false, "the revealed next key's reference was consumed (it is the owner key reference now)");
  assert.equal(signerLib.loadOwnerKeyFile(`${h.historyFile}.owner-key.json`).credential, k2.publicKey);
  for (const file of [k1.file, k2.file, k3.file]) assert.ok(!readFileSync(`${h.historyFile}`, "utf8").includes(readFileSync(file, "utf8").split("\n")[1]), "no private key material near the history");
  await grant(h.owner);
  assert.equal(h.pin().attestation.keyId, "owner:2");
  const after = h.owner.ownerKeyStatus();
  assert.deepEqual(after.custody.map((c) => [c.role, c.keyId ?? null, c.code]), [["current", "owner:2", "OWNER_KEY_REFERENCE"], ["next", null, "NEXT_KEY_OFF_HOST"], ["retired", "owner:1", "RETIRED_KEY_REFERENCE"]]);
  const report = verifyHistory(h.historyFile);
  assert.equal(report.ok, true, report.failures.join("; "));
  // The retired key cannot sign new control events, even though the agent still holds it.
  const stale = openLocalOwner({ ...h.config, signer: signerLib.loadOwnerKeyFile(rotated.retiredKeyFile) });
  await assert.rejects(stale.createAgent({ id: "mallory" }), code("CONTROL_AUTHORIZATION_INVALID"));
  stale.close();
});

test("witness-cache seals with an asynchronous signer: an owner write seals what it learned (readers then skip the network); an owner-keyed read never asks the signer for a seal", async (t) => {
  const dir = scratchDir(t);
  const pair = generateKeyPair("ed25519", "owner:1");
  const log = join(dir, "purposes.log");
  writeFileSync(log, "");
  const w = await startFakeWitness({ name: "custody-seal", seed: 431 });
  t.after(() => w.close());
  const policy = { witnesses: [{ url: w.url, verifierKey: w.verifierKey }], mode: "sync", requireOnOpen: true, cacheMs: 600_000 };
  const argv = [process.execPath, commandSignerScript(dir, pair.privateKey, "ok", "logging.mjs", { logFile: log })];
  const h = await history(t, dir, custody.keyReference({ keyId: "owner:1", publicKey: pair.credential, signer: { kind: "command", argv } }), { nextKey: false, witness: policy });
  await h.owner.createAgent({ id: "bea" });
  const purposes = () => readFileSync(log, "utf8").trim().split("\n");
  assert.ok(purposes().includes("cache-seal"), `the owner write sealed its witness answer: ${purposes().join(", ")}`);
  const side = JSON.parse(readFileSync(`${h.historyFile}.witness.json`, "utf8"));
  assert.ok(Object.values(side.witnesses).every((entry) => entry.latest?.seal?.keyId === "owner:1"), "the seal is in the side file when the write returns");
  h.owner.close();
  // A fresh keyless reader under requireOnOpen: the owner-sealed answer opens the gate without a network call.
  resetWitnessViews();
  const asked = w.state.requests.length;
  const reader = openHistoryStore(h.historyFile);
  assert.equal(reader.state().head.position, openHistoryStore(h.historyFile, { inspect: true, witness: false }).state().head.position);
  assert.equal(reader.witnessStatus().witnesses[0].source, "sealed-cache");
  assert.equal(w.state.requests.length, asked, "no network call");
  reader.close();
  // An owner-keyed process that only reads (a hook deciding a tool call): its check asks the witness, never the signer.
  const before = purposes().length;
  resetWitnessViews();
  const keyed = h.open({ witness: policy });
  await keyed.checkWitnesses({ force: true });
  assert.ok(keyed.authorize({ actor: "bea", action: "read", resource: "r:1" }).decision !== undefined);
  // (Its flush() would be an owner command: a submission round, which may seal.)
  assert.deepEqual(purposes().slice(before).filter((p) => p === "cache-seal"), [], "a read asks the signer for nothing");
  keyed.close();
});

// ---------------------------------------------------------------- crash safety of a rotation with an external next key

/**
 * The two-phase rotation's crash windows (docs/reference/witness-operations.md §7.1) with the owner key and the committed next key held by a
 * real ssh-agent (the next key committed by reference) and the new next key committed by reference to a third agent key:
 * every window ends in one consistent state on the next open, with the reference files in the right places.
 */
for (const [window, expectAppended] of [["after-stage", false], ["after-record", false], ["after-delivery", true], ["after-append", true], ["after-owner-key-swap", true]]) {
  test(`crash window ${window} with the owner and next keys in an ssh-agent: recovered on the next open or write`, skipNoSsh, async (t) => {
    const dir = scratchDir(t);
    const agent = await startSshAgent(t, dir);
    const k1 = sshKeygen(dir, "owner1"), k2 = sshKeygen(dir, "owner2"), k3 = sshKeygen(dir, "owner3");
    for (const k of [k1, k2, k3]) agent.add(k.file);
    const w = await startFakeWitness({ name: `custody-crash-${window}`, seed: 400 + window.length });
    t.after(() => w.close());
    const policy = { witnesses: [{ url: w.url, verifierKey: w.verifierKey }], mode: "sync" };
    const h = await history(t, dir, agentRef(k1, agent.socket), { nextKeyReference: agentRef(k2, agent.socket, "owner:2", true), witness: policy });
    await h.owner.createAgent({ id: "bea" });
    await h.owner.flush();
    const r = openHistoryStore(h.historyFile, { inspect: true, witness: false }).state().head.position + 1;
    setRotationFaultForTests(window);
    await assert.rejects(h.owner.rotateOwnerKey({ newNextKeyReference: agentRef(k3, agent.socket, "owner:3", true), reason: `crash ${window}` }), (e) => e instanceof RotationFault);
    setRotationFaultForTests(undefined);
    h.owner.close();
    resetWitnessViews();
    const next = h.open({ witness: policy });
    await next.createAgent({ id: "after-crash" });
    await next.flush();
    const state = openHistoryStore(h.historyFile, { inspect: true, witness: false }).state();
    assert.equal(state.events[r].type === "OWNER_KEYS_ROTATED", expectAppended, `rotation ${expectAppended ? "completed" : "discarded"}`);
    for (const pending of [pendingRotationPathFor(h.historyFile), `${h.historyFile}.owner-key.pending.json`, `${h.historyFile}.owner-next-key.pending.json`]) assert.equal(existsSync(pending), false, pending);
    const ownerNow = signerLib.loadOwnerKeyFile(`${h.historyFile}.owner-key.json`), nextNow = signerLib.loadNextOwnerKeyFile(`${h.historyFile}.owner-next-key.json`);
    assert.equal(ownerNow.custody.holder, "reference");
    assert.equal(nextNow.custody.holder, "reference");
    assert.equal(ownerNow.credential, expectAppended ? k2.publicKey : k1.publicKey, "the owner key reference names the key in force");
    assert.equal(nextNow.credential, expectAppended ? k3.publicKey : k2.publicKey, "the next-key reference names the committed next key");
    const report = await verifyHistoryWithWitnesses(h.historyFile, { witness: policy });
    assert.equal(report.ok, true, report.failures.join("\n"));
    if (!expectAppended) {
      const rotated = await next.rotateOwnerKey({ newNextPublicKey: k3.pub });
      assert.equal(rotated.keyId, "owner:2", "a new rotation works after the discarded one");
    }
    next.close();
  });
}

test("a prepared rotation onto an external next key that is never committed leaves the next-key reference in place; the staged files go on the next open", skipNoSsh, async (t) => {
  const dir = scratchDir(t);
  const agent = await startSshAgent(t, dir);
  const k1 = sshKeygen(dir, "owner1"), k2 = sshKeygen(dir, "owner2");
  agent.add(k1.file);
  agent.add(k2.file);
  const h = await history(t, dir, agentRef(k1, agent.socket), { nextKeyReference: agentRef(k2, agent.socket, "owner:2", true) });
  const nextBytes = bytes(`${h.historyFile}.owner-next-key.json`);
  const prepared = await h.owner.prepareOwnerKeyRotation({ newNextPublicKey: generateKeyPair("ed25519", "x").credential });
  assert.ok(existsSync(prepared.files.pendingKeyFile), "the promoted reference is staged");
  assert.equal(signerLib.loadOwnerKeyFile(prepared.files.pendingKeyFile).credential, k2.publicKey);
  h.owner.close(); // "crash": never committed
  const reopened = h.open();
  assert.equal(existsSync(`${h.historyFile}.owner-key.pending.json`), false, "the staged reference no epoch declares is removed");
  assert.deepEqual(bytes(`${h.historyFile}.owner-next-key.json`), nextBytes, "the committed next key's reference is untouched");
  const rotated = await reopened.rotateOwnerKey({ newNextPublicKey: generateKeyPair("ed25519", "y").credential });
  assert.equal(rotated.keyId, "owner:2");
  reopened.close();
});
