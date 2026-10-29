// Block 4 (owner-key custody) through the built CLI: `init --signer ssh-agent` / `--owner-key-ref`, `signer ref|test|list|to-ssh`,
// `owner commit-next-key --public-key|--next-key-ref`, `owner rotate-key --next-key-ref`, `owner status` custody, verify
// --accept-rollback, repin and anchor with a key a REAL ssh-agent holds, and the command signer. Build first (pnpm -r build).
import test from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { commandSignerScript, fakeKey, haveOpenSsh, scratchDir, sshKeygen, startFakeAgent, startSshAgent } from "../../core/test/helpers/ssh-agent.mjs";

const here = fileURLToPath(new URL(".", import.meta.url));
const BIN = resolve(here, "../bin/irontrellis.mjs");
assert.ok(existsSync(resolve(here, "../dist/cli.js")), "build the package first: pnpm build");
const core = await import("@ramex-labs/irontrellis");
const skipNoSsh = haveOpenSsh ? {} : { skip: "OpenSSH is not installed" };

const run = (args, env = {}) => {
  const result = spawnSync(process.execPath, [BIN, ...args], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1", ...env } });
  return { code: result.status, stdout: result.stdout, stderr: result.stderr };
};
const json = (args, env) => {
  const r = run([...args, "--json"], env);
  let value;
  try { value = JSON.parse(r.stdout); } catch (error) { assert.fail(`not one JSON document (${error.message}):\n${r.stdout}\n${r.stderr}`); }
  return { ...r, value };
};
/** The CLI without blocking this process (a fake agent served by this process must keep answering). */
const jsonAsync = (args, env = {}) => new Promise((done) => {
  const child = spawn(process.execPath, [BIN, ...args, "--json"], { env: { ...process.env, NO_COLOR: "1", ...env } });
  let stdout = "", stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  child.on("close", (code) => done({ code, stdout, stderr, value: JSON.parse(stdout) }));
});
const ok = (r, what = "expected exit 0") => { assert.equal(r.code, 0, `${what}\n${r.stdout}\n${r.stderr}`); return r; };
const bytes = (path) => (existsSync(path) ? readFileSync(path) : undefined);

test("CLI with the owner key in a real ssh-agent: init, grant, verify, owner status, signer test/list; pre-rotation onto a second agent key; a removed key and a dead agent fail cleanly", skipNoSsh, async (t) => {
  const dir = scratchDir(t, "itcli-");
  const agent = await startSshAgent(t, dir);
  const k1 = sshKeygen(dir, "owner1"), k2 = sshKeygen(dir, "owner2"), k3 = sshKeygen(dir, "owner3");
  agent.add(k1.file);
  const history = join(dir, "h.jsonl");
  const env = { IRONTRELLIS_HISTORY: history, SSH_AUTH_SOCK: agent.socket };
  // init: the owner key in the agent, the next key committed by public key only.
  const init = ok(json(["init", "--signer", "ssh-agent", "--public-key", k1.pub, "--next-public-key", k2.pub], env));
  assert.equal(init.value.ownerKeyHolder, "reference");
  assert.match(init.value.ownerKeySigner, /^ssh-agent at \$SSH_AUTH_SOCK/);
  assert.equal(init.value.nextKeyCommitted, true);
  assert.equal(init.value.nextKeyFile, null);
  assert.deepEqual(init.value.warnings, []);
  assert.deepEqual(init.value.custody.map((c) => c.code), ["OWNER_KEY_REFERENCE", "NEXT_KEY_OFF_HOST"]);
  assert.equal(JSON.parse(readFileSync(`${history}.owner-key.json`, "utf8")).version, "irontrellis-owner-key-ref/1");
  assert.ok(!existsSync(`${history}.owner-next-key.json`));
  ok(json(["agent", "create", "bea"], env));
  ok(json(["grant", "g1", "--to", "bea", "--actions", "read", "--resources", "r:1", "--expires", "+1h"], env));
  const verified = ok(json(["verify"], env));
  assert.equal(verified.value.report.pinnedAttestation, "VERIFIED", "each pin attested through the agent before the command returned");
  // signer test / list.
  const tested = ok(json(["signer", "test", "--key", "current"], env));
  assert.equal(tested.value.standing, "an owner key in force");
  assert.equal(tested.value.sshPublicKey, k1.pub.split(" ").slice(0, 2).join(" "));
  const listed = ok(json(["signer", "list"], env));
  assert.deepEqual(listed.value.keys.map((k) => [k.type, k.usable, k.publicKey]), [["ssh-ed25519", true, k1.publicKey]]);
  const human = ok(run(["owner", "status"], env));
  assert.match(human.stdout, /custody\n  current  owner:1 +OK +held by a signer · ssh-agent at \$SSH_AUTH_SOCK/);
  assert.match(human.stdout, /NEXT_KEY_OFF_HOST/);
  // Pre-rotation: the next key is the second agent key; it never exists as a file beside the history.
  agent.add(k2.file);
  const ref2 = join(dir, "owner2.owner-next-key-ref.json");
  ok(json(["signer", "ref", "--out", ref2, "--next", "--signer", "ssh-agent", "--public-key", k2.pub, "--key-id", "owner:2"], env));
  const testedNext = ok(json(["signer", "test", "--ref", ref2], env));
  assert.equal(testedNext.value.standing, "the committed next key");
  const rotated = ok(json(["owner", "rotate-key", "--next-key-ref", ref2, "--new-next-key-ref", (() => {
    const ref3 = join(dir, "owner3.owner-next-key-ref.json");
    ok(json(["signer", "ref", "--out", ref3, "--next", "--signer", "ssh-agent", "--agent-socket", agent.socket, "--public-key", k3.pub, "--key-id", "owner:3"], env));
    return ref3;
  })(), "--reason", "scheduled"], env));
  assert.equal(rotated.value.preRotated, true);
  assert.equal(rotated.value.keyId, "owner:2");
  // The new next key is in the same agent (its reference names the socket, the owner key's reference uses $SSH_AUTH_SOCK: the
  // same agent all the same): whoever can use that agent can rotate, and owner status says so.
  assert.deepEqual(rotated.value.custody.map((c) => [c.role, c.code]), [["current", "OWNER_KEY_REFERENCE"], ["next", "NEXT_KEY_SAME_SIGNER"], ["retired", "RETIRED_KEY_REFERENCE"]]);
  assert.deepEqual(rotated.value.warnings.map((w) => w.code), ["NEXT_KEY_SAME_SIGNER"]);
  assert.equal(JSON.parse(readFileSync(`${history}.owner-next-key.json`, "utf8")).publicKey, k3.publicKey);
  ok(json(["agent", "create", "cid"], env));
  const status = ok(json(["owner", "status"], env)).value;
  assert.equal(status.ownerKeys[0].keyId, "owner:2");
  assert.equal(ok(json(["verify"], env)).value.report.pinnedAttestation, "VERIFIED");
  // The key taken out of the agent: KEY_UNAVAILABLE, nothing appended.
  const before = [bytes(history), bytes(`${history}.head`)];
  agent.remove(`${k2.file}.pub`);
  const missing = json(["agent", "create", "dee"], env);
  assert.equal(missing.code, 1);
  assert.equal(missing.value.error.code, "KEY_UNAVAILABLE");
  assert.equal(missing.value.error.context.reason, "KEY_NOT_IN_AGENT");
  assert.match(missing.value.error.message, /does not hold owner key owner:2/);
  assert.deepEqual([bytes(history), bytes(`${history}.head`)], before);
  const humanMissing = run(["agent", "create", "dee"], env);
  assert.match(humanMissing.stderr, /^error: KEY_UNAVAILABLE — the ssh-agent at .* does not hold owner key owner:2/);
  // The agent dies: SIGNER_FAILED, nothing appended.
  agent.add(k2.file);
  await agent.kill();
  const dead = json(["grant", "g2", "--to", "bea", "--actions", "read", "--resources", "r:1", "--expires", "+1h"], env);
  assert.equal(dead.value.error.code, "SIGNER_FAILED");
  assert.equal(dead.value.error.context.reason, "UNREACHABLE");
  assert.deepEqual([bytes(history), bytes(`${history}.head`)], before);
  const deadTest = json(["signer", "test", "--key", "current"], env);
  assert.equal(deadTest.code, 1);
  assert.equal(deadTest.value.error.code, "SIGNER_FAILED");
});

test("CLI: init --owner-key-ref with a command signer; commit-next-key --public-key; rotate-key --next-key-ref onto a second command signer; repin, verify --accept-rollback and anchor wait for the signer", async (t) => {
  const dir = scratchDir(t, "itcli-");
  const one = core.generateKeyPair("ed25519", "owner:1"), two = core.generateKeyPair("ed25519", "owner:2");
  const argvOf = (pair, mode = "ok") => JSON.stringify([process.execPath, commandSignerScript(dir, pair.privateKey, mode, `${pair.keyId.replace(":", "-")}-${mode}.mjs`)]);
  const history = join(dir, "h.jsonl");
  const env = { IRONTRELLIS_HISTORY: history };
  const ref1 = join(dir, "owner1.owner-key-ref.json");
  const refOut = ok(json(["signer", "ref", "--out", ref1, "--signer", "command", "--signer-command", argvOf(one), "--public-key", one.credential, "--comment", "kms key 1"], env));
  assert.equal(refOut.value.reference.comment, "kms key 1");
  assert.equal(json(["signer", "ref", "--out", ref1, "--signer", "command", "--signer-command", argvOf(one), "--public-key", one.credential], env).value.error.code, "KEY_EXISTS", "never overwritten");
  ok(json(["init", "--owner-key-ref", ref1, "--no-next-key"], env));
  const plain = ok(json(["owner", "status"], env)).value;
  assert.deepEqual(plain.warnings.map((w) => w.code), ["NO_NEXT_KEY_COMMITMENT"]);
  const committed = ok(json(["owner", "commit-next-key", "--public-key", core.sshPublicKeyOf(two.credential)], env));
  assert.equal(committed.value.nextKeyHolder, "public-key-only");
  assert.equal(committed.value.nextKeyFile, null);
  ok(json(["agent", "create", "bea"], env));
  const ref2 = join(dir, "owner2.owner-next-key-ref.json");
  ok(json(["signer", "ref", "--out", ref2, "--next", "--key-id", "owner:2", "--signer", "command", "--signer-command", argvOf(two), "--public-key", two.credential], env));
  // --next-key-ref refuses an owner key reference (a next key must be named as one).
  assert.equal(json(["owner", "rotate-key", "--next-key-ref", ref1], env).value.error.code, "KEY_UNAVAILABLE");
  const rotated = ok(json(["owner", "rotate-key", "--next-key-ref", ref2, "--new-next-public-key", core.generateKeyPair("ed25519", "x").credential], env));
  assert.equal(rotated.value.keyId, "owner:2");
  assert.equal(rotated.value.nextKeyFile, null);
  ok(json(["agent", "create", "cid"], env)); // the rotation head itself stays attested by the retired key
  // repin: attested by the command signer and awaited before the command returns.
  const repinned = ok(json(["repin"], env));
  assert.equal(repinned.value.pinnedAttestation, "VERIFIED");
  // verify --accept-rollback with an asynchronous signer: the report is taken after the re-pin's attestation.
  unlinkSync(`${history}.head`);
  assert.equal(json(["verify"], env).value.report.pinnedHeadStatus, "MISSING");
  const accepted = ok(json(["verify", "--accept-rollback"], env));
  assert.equal(accepted.value.report.pinnedAttestation, "VERIFIED");
  // anchor: the attestation, the control event and the pin after it, all through the command signer.
  const anchored = ok(json(["anchor"], env));
  assert.equal(anchored.value.recorded, "anchor");
  assert.equal(ok(json(["verify"], env)).value.report.pinnedAttestation, "VERIFIED");
  // A command signer that answers with a wrong signature: SIGNER_FAILED, nothing appended.
  const before = [bytes(history), bytes(`${history}.head`)];
  const wrong = core.keyReference({ keyId: "owner:2", publicKey: two.credential, signer: { kind: "command", argv: JSON.parse(argvOf(two, "wrong")) } });
  writeFileSync(`${history}.owner-key.json`, core.keyReferenceText(wrong), { mode: 0o600 });
  const refused = json(["agent", "create", "mallory"], env);
  assert.equal(refused.value.error.code, "SIGNER_FAILED");
  assert.equal(refused.value.error.context.reason, "SIGNATURE_INVALID");
  assert.deepEqual([bytes(history), bytes(`${history}.head`)], before);
  // Usage errors are caught before anything is opened.
  assert.equal(json(["init", "--history", join(dir, "x.jsonl"), "--signer", "ssh-agent"], {}).value.error.code, "USAGE");
  assert.equal(json(["init", "--history", join(dir, "x.jsonl"), "--signer", "command", "--public-key", one.credential, "--signer-command", "not json"], {}).value.error.code, "USAGE");
  assert.equal(json(["init", "--history", join(dir, "x.jsonl"), "--signer", "ssh-agent", "--public-key", "ssh-rsa AAAAB3"], {}).value.error.code, "USAGE");
  assert.equal(json(["init", "--history", join(dir, "x.jsonl"), "--signer", "command", "--public-key", one.credential, "--signer-command", "[\"relative/prog\"]"], {}).value.error.code, "USAGE");
  assert.equal(json(["init", "--history", join(dir, "x.jsonl"), "--agent-socket", "/tmp/x"], {}).value.error.code, "USAGE");
});

test("CLI signer to-ssh: an existing owner key file moves into a real ssh-agent and the history keeps working through a reference", skipNoSsh, async (t) => {
  const dir = scratchDir(t, "itcli-");
  const agent = await startSshAgent(t, dir);
  const history = join(dir, "h.jsonl");
  const env = { IRONTRELLIS_HISTORY: history, SSH_AUTH_SOCK: agent.socket };
  ok(json(["init"], env));
  const before = ok(json(["owner", "status"], env)).value;
  assert.equal(before.custody[0].code, "OWNER_KEY_FILE_ON_HOST");
  assert.equal(before.custody[0].level, "WARN");
  const out = join(dir, "owner1.ssh");
  const exported = ok(json(["signer", "to-ssh", "--key", "current", "--out", out], env)).value;
  assert.equal((await import("node:fs")).statSync(out).mode & 0o777, 0o600);
  agent.add(out);
  // The documented recipe: the key file goes offline, a reference takes its place.
  const keyFile = `${history}.owner-key.json`;
  (await import("node:fs")).renameSync(keyFile, join(dir, "offline-owner-key.json"));
  ok(json(["signer", "ref", "--out", keyFile, "--signer", "ssh-agent", "--public-key", exported.sshPublicKey, "--key-id", "owner:1"], env));
  assert.equal(ok(json(["signer", "test", "--key", "current"], env)).value.standing, "an owner key in force");
  ok(json(["agent", "create", "bea"], env));
  const after = ok(json(["owner", "status"], env)).value;
  assert.equal(after.custody[0].code, "OWNER_KEY_REFERENCE");
  assert.equal(after.custody[0].level, "OK");
});

test("CLI: a fake ssh-agent that returns a signature by another key is refused at init (nothing created)", async (t) => {
  const dir = scratchDir(t, "itcli-");
  const k = fakeKey(core.generateKeyPair);
  const fake = await startFakeAgent(t, dir, { keys: [k], behaviour: "wrong-signature" });
  const history = join(dir, "h.jsonl");
  const r = await jsonAsync(["init", "--history", history, "--signer", "ssh-agent", "--agent-socket", fake.socket, "--public-key", core.sshPublicKeyOf(k.pair.credential)]);
  assert.equal(r.value.error.code, "SIGNER_FAILED");
  assert.equal(r.value.error.context.reason, "SIGNATURE_INVALID");
  assert.equal(existsSync(history), false);
  assert.equal(existsSync(`${history}.owner-key.json`), false);
});

test("CLI help lists the custody commands and flags", () => {
  const help = ok(run(["--help"])).stdout;
  assert.match(help, /key custody\n  signer test +ask the signer/);
  for (const [command, flags] of [
    [["init", "--help"], ["--owner-key-ref", "--signer", "--public-key", "--agent-socket", "--signer-command", "--next-public-key", "--next-key-ref"]],
    [["owner", "commit-next-key", "--help"], ["--public-key", "--next-key-ref"]],
    [["owner", "rotate-key", "--help"], ["--next-key-ref", "--new-next-public-key", "--new-next-key-ref"]],
    [["signer", "test", "--help"], ["--ref", "--key"]],
  ]) {
    const text = ok(run(command)).stdout;
    for (const flag of flags) assert.ok(text.includes(flag), `${command.join(" ")} documents ${flag}`);
  }
});

test("CLI: init --next-key-ref (the next key in its own command signer) and a rotation that finds it beside the history; commit-next-key --next-key-ref", async (t) => {
  const dir = scratchDir(t, "itcli-");
  const pairs = ["owner:1", "owner:2", "owner:3", "owner:4"].map((keyId) => core.generateKeyPair("ed25519", keyId));
  const argvOf = (pair) => JSON.stringify([process.execPath, commandSignerScript(dir, pair.privateKey, "ok", `${pair.keyId.replace(":", "-")}.mjs`)]);
  const history = join(dir, "h.jsonl");
  const env = { IRONTRELLIS_HISTORY: history };
  const refs = pairs.map((pair, i) => {
    const out = join(dir, `${pair.keyId.replace(":", "-")}.${i === 0 ? "owner-key-ref" : "owner-next-key-ref"}.json`);
    ok(json(["signer", "ref", "--out", out, ...(i === 0 ? [] : ["--next"]), "--key-id", pair.keyId, "--signer", "command", "--signer-command", argvOf(pair), "--public-key", pair.credential], env));
    return out;
  });
  const init = ok(json(["init", "--owner-key-ref", refs[0], "--next-key-ref", refs[1]], env));
  assert.equal(init.value.nextKeyFile, `${history}.owner-next-key.json`);
  assert.deepEqual(init.value.custody.map((c) => c.code), ["OWNER_KEY_REFERENCE", "NEXT_KEY_REFERENCE"], "two commands with different programs: not the same signer");
  assert.deepEqual(init.value.warnings, []);
  ok(json(["agent", "create", "bea"], env));
  // No --next-key-ref: the reference beside the history names the committed key.
  const rotated = ok(json(["owner", "rotate-key", "--new-next-key-ref", refs[2]], env));
  assert.equal(rotated.value.keyId, "owner:2");
  assert.equal(JSON.parse(readFileSync(`${history}.owner-next-key.json`, "utf8")).publicKey, pairs[2].credential);
  ok(json(["agent", "create", "cid"], env));
  assert.equal(ok(json(["verify"], env)).value.ok, true);
  // A second history without a commitment gets one by reference.
  const other = join(dir, "o.jsonl");
  ok(json(["init", "--history", other, "--owner-key-ref", refs[0], "--no-next-key"], {}));
  const committed = ok(json(["--history", other, "owner", "commit-next-key", "--next-key-ref", refs[3]], {}));
  assert.equal(committed.value.nextKeyHolder, "reference");
  assert.equal(committed.value.nextKeyFile, `${other}.owner-next-key.json`);
  assert.equal(committed.value.keyId, "owner:4");
});

test("review block 4 L1: a write whose pin attestation fails after the append is WRITTEN_UNATTESTED (exit 4, context.written, the event id), not a failure that wrote nothing", async (t) => {
  const dir = scratchDir(t, "itcli-");
  const pair = core.generateKeyPair("ed25519", "owner:1");
  const flag = join(dir, "fail-attestation");
  const prog = join(dir, "flaky.mjs");
  writeFileSync(prog, `import { createPrivateKey, sign } from "node:crypto";
import { existsSync } from "node:fs";
const c = []; for await (const x of process.stdin) c.push(x); const r = JSON.parse(Buffer.concat(c));
if (r.purpose === "head-attestation" && existsSync(${JSON.stringify(flag)})) { process.stderr.write("declined"); process.exit(3); }
const k = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from("${pair.privateKey.slice(2)}", "hex")]), format: "der", type: "pkcs8" });
process.stdout.write(JSON.stringify({ signature: sign(null, Buffer.from(r.message, "base64"), k).toString("base64") }));`);
  const history = join(dir, "h.jsonl");
  const env = { IRONTRELLIS_HISTORY: history };
  ok(json(["init", "--signer", "command", "--public-key", pair.credential, "--signer-command", JSON.stringify([process.execPath, prog]), "--no-next-key"], env));
  ok(json(["agent", "create", "bea"], env));
  ok(json(["grant", "g1", "--to", "bea", "--actions", "read", "--resources", "r:1", "--expires", "+1h"], env));
  writeFileSync(flag, "");
  const revoked = json(["revoke", "g1"], env);
  assert.equal(revoked.code, 4, revoked.stdout);
  assert.equal(revoked.value.error.code, "WRITTEN_UNATTESTED");
  assert.equal(revoked.value.error.context.written, true);
  assert.match(revoked.value.error.context.eventId, /./);
  assert.equal(revoked.value.error.context.cause.code, "SIGNER_FAILED");
  assert.match(revoked.value.error.message, /IS recorded/);
  const human = run(["revoke", "g1"], env);
  assert.notEqual(human.code, 4, "a second revoke is refused before any write");
  const events = JSON.parse(run(["export"], env).stdout);
  assert.equal(events.filter((e) => e.type === "AUTHORITY_REVOKED").length, 1, "the revocation is in the history");
  // A failure BEFORE the write stays SIGNER_FAILED, exit 1.
  const { rmSync } = await import("node:fs");
  rmSync(flag);
  const broken = JSON.parse(readFileSync(`${history}.owner-key.json`, "utf8"));
  broken.signer.argv = [join(dir, "gone.mjs")];
  writeFileSync(`${history}.owner-key.json`, JSON.stringify(broken), { mode: 0o600 });
  const before = json(["agent", "create", "cid"], env);
  assert.equal(before.code, 1);
  assert.equal(before.value.error.code, "SIGNER_FAILED");
});

test("migrate --signer ssh-agent / --owner-key-ref: the migrated history's owner key is held by a real ssh-agent", skipNoSsh, async (t) => {
  const dir = scratchDir(t, "itmig-");
  const agent = await startSshAgent(t, dir);
  const k1 = sshKeygen(dir, "owner1"), k2 = sshKeygen(dir, "owner2");
  agent.add(k1.file);
  const env = { SSH_AUTH_SOCK: agent.socket };
  const fixture = resolve(here, "../../reference-0.2/tests/fixtures/handover-history.jsonl");
  // No host fallback path (publication hygiene, as S5-27): without the vendored fixture the test skips and says why.
  if (!existsSync(fixture)) { t.skip(`the vendored legacy fixture ${fixture} is absent`); return; }
  const legacy = readFileSync(fixture);
  // A migrated source is fenced (SPEC §16.2 step 6): every migration case below gets its own copy of the legacy file.
  let copies = 0;
  const fresh = () => { const copy = join(dir, `legacy-${(copies += 1)}.jsonl`); writeFileSync(copy, legacy); return copy; };
  const source = fresh();
  // Inline: --signer ssh-agent --public-key.
  const target = join(dir, "t.jsonl");
  const migrated = ok(json(["migrate", source, target, "--accept-unpinned-source", "--signer", "ssh-agent", "--public-key", k1.pub], env));
  assert.equal(migrated.value.eventCount, 26);
  assert.equal(migrated.value.ownerKeyId, "owner:1");
  assert.equal(migrated.value.ownerKeyHolder, "reference");
  assert.match(migrated.value.ownerKeySigner, /^ssh-agent at \$SSH_AUTH_SOCK/);
  assert.equal(JSON.parse(readFileSync(`${target}.owner-key.json`, "utf8")).version, "irontrellis-owner-key-ref/1");
  const verified = ok(json(["--history", target, "verify"], env));
  assert.equal(verified.value.report.pinnedAttestation, "VERIFIED", "the target pin was attested through the agent");
  assert.equal(verified.value.report.controlSignatures, "VERIFIED", "every re-recorded control event was signed through the agent");
  // A reference file: --owner-key-ref; the human output names the signer.
  const ref = join(dir, "owner1.owner-key-ref.json");
  ok(json(["signer", "ref", "--out", ref, "--signer", "ssh-agent", "--public-key", k1.pub], env));
  const human = ok(run(["migrate", fresh(), join(dir, "r.jsonl"), "--accept-unpinned-source", "--owner-key-ref", ref], env));
  assert.match(human.stdout, /owner key +owner:1 held by ssh-agent at \$SSH_AUTH_SOCK .* is a reference \(no secret; mode 0600\)/);
  // Usage: the key once; --key-id only with --signer.
  const twice = json(["migrate", fresh(), join(dir, "u.jsonl"), "--accept-unpinned-source", "--owner-key-ref", ref, "--signer", "ssh-agent", "--public-key", k1.pub], env);
  assert.equal(twice.value.error.code, "USAGE");
  assert.match(twice.value.error.message, /give the owner key once/);
  assert.equal(json(["migrate", fresh(), join(dir, "u.jsonl"), "--accept-unpinned-source", "--owner-key-ref", ref, "--key-id", "owner:9"], env).value.error.code, "USAGE");
  assert.ok(!existsSync(join(dir, "u.jsonl")) && !existsSync(join(dir, "u.jsonl.owner-key.json")));
  // Review block 5, M1: --reuse-existing-key with a signer adopts only a reference to the same key in the same signer.
  // A plain key file (private key on disk) for that very key is refused, not reported as "a reference (no secret)".
  const plantedKey = core.createOwnerKeyFile(join(dir, "p.jsonl.owner-key.json"), "owner:1");
  const plantedPub = `ssh-ed25519 ${Buffer.concat([Buffer.from([0, 0, 0, 11]), Buffer.from("ssh-ed25519"), Buffer.from([0, 0, 0, 32]), Buffer.from(plantedKey.credential.slice(2), "hex")]).toString("base64")}`;
  const adopted = json(["migrate", fresh(), join(dir, "p.jsonl"), "--accept-unpinned-source", "--reuse-existing-key", "--signer", "ssh-agent", "--agent-socket", join(dir, "none.sock"), "--public-key", plantedPub], env);
  assert.equal(adopted.code, 1);
  assert.equal(adopted.value.error.code, "KEY_EXISTS", JSON.stringify(adopted.value));
  assert.match(adopted.value.error.message, /is a key file \(not a reference\)/);
  assert.ok(!existsSync(join(dir, "p.jsonl")));
  // The same reference reused: accepted, and the holder is read from the file.
  writeFileSync(join(dir, "q.jsonl.owner-key.json"), readFileSync(`${target}.owner-key.json`), { mode: 0o600 });
  const reusedRef = ok(json(["migrate", fresh(), join(dir, "q.jsonl"), "--accept-unpinned-source", "--reuse-existing-key", "--signer", "ssh-agent", "--public-key", k1.pub], env));
  assert.equal(reusedRef.value.ownerKeyHolder, "reference");
  // A key the agent does not hold: refused before any target byte; no reference is left behind.
  const missing = json(["migrate", fresh(), join(dir, "m.jsonl"), "--accept-unpinned-source", "--signer", "ssh-agent", "--public-key", k2.pub], env);
  assert.equal(missing.code, 1);
  assert.equal(missing.value.error.code, "KEY_UNAVAILABLE");
  assert.ok(!existsSync(join(dir, "m.jsonl")) && !existsSync(join(dir, "m.jsonl.owner-key.json")));
});

// init and anchor append without write(); a signer failure after their append is WRITTEN_UNATTESTED (exit 4) too.
test("anchor and init whose pin attestation fails after the append are WRITTEN_UNATTESTED (exit 4), not \"nothing written\"", async (t) => {
  const dir = scratchDir(t, "itcli-");
  const pair = core.generateKeyPair("ed25519", "owner:1");
  const flag = join(dir, "fail-attestation"), prog = join(dir, "flaky.mjs");
  writeFileSync(prog, `import { createPrivateKey, sign } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
const c = []; for await (const x of process.stdin) c.push(x); const r = JSON.parse(Buffer.concat(c));
// The flag holds how many more head attestations to sign before declining (anchor attests the head before its append).
if (r.purpose === "head-attestation" && existsSync(${JSON.stringify(flag)})) {
  const left = Number(readFileSync(${JSON.stringify(flag)}, "utf8") || "0");
  if (left <= 0) { process.stderr.write("declined"); process.exit(3); }
  writeFileSync(${JSON.stringify(flag)}, String(left - 1));
}
const k = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from("${pair.privateKey.slice(2)}", "hex")]), format: "der", type: "pkcs8" });
process.stdout.write(JSON.stringify({ signature: sign(null, Buffer.from(r.message, "base64"), k).toString("base64") }));`);
  const signer = ["--signer", "command", "--public-key", pair.credential, "--signer-command", JSON.stringify([process.execPath, prog]), "--no-next-key"];
  const env = { IRONTRELLIS_HISTORY: join(dir, "h.jsonl") };
  ok(json(["init", ...signer], env));
  writeFileSync(flag, "1"); // the anchor's own attestation of the head is signed; the pin after the append is declined
  const anchored = json(["anchor"], env);
  assert.equal(anchored.code, 4, anchored.stdout);
  assert.equal(anchored.value.error.code, "WRITTEN_UNATTESTED");
  assert.match(anchored.value.error.context.eventId, /./);
  assert.ok(JSON.parse(run(["export"], env).stdout).some((e) => e.type === "ANCHOR_RECORDED"), "the anchor is in the history");
  writeFileSync(flag, "0");
  const created = json(["init", "--history", join(dir, "second.jsonl"), ...signer], {});
  assert.equal(created.code, 4, created.stdout);
  assert.equal(created.value.error.code, "WRITTEN_UNATTESTED");
});
