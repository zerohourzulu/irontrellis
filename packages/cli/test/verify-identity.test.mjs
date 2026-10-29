// verify and export verify confirm a history's identity from outside the file (founder decision 4cb): --expect-history-id,
// --expect-owner-key and --expect-owner-keys. A substitute history (the same events signed under other keys) verifies
// clean on its own terms and is refused only against the published id and keys.
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createLocalOwner, createLocalDomain, keyPairFromPrivateKey, signHashWith, sshPublicKeyOf } from "@ramex-labs/irontrellis";

const BIN = fileURLToPath(new URL("../bin/irontrellis.mjs", import.meta.url));
// Public, synthetic test-only seeds. No user key or live service is used.
const pair = (id, n) => keyPairFromPrivateKey("ed25519", id, `0x${n.toString(16).padStart(64, "0")}`);
const publicKey = ({ keyId, scheme, credential }) => ({ keyId, scheme, credential });
const run = (args) => spawnSync(process.execPath, [BIN, ...args], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } });
const json = (args) => { const r = run([...args, "--json"]); return { code: r.status, doc: JSON.parse(r.stdout), stderr: r.stderr }; };
const verifyArgs = (history, ...rest) => ["verify", "--history", history, "--no-remote", ...rest];

/** A history written by `owner` (with co-owner keys `co`); the same calls on the same domain give the same events but for the keys. */
async function history(dir, name, owner, co = [], domain = createLocalDomain()) {
  const file = join(dir, `${name}.jsonl`);
  const handle = await createLocalOwner({ historyFile: file, domain, owner: "operations", controller: "operator", now: () => 1000,
    signer: { ...publicKey(owner), signHash: signHashWith(owner) }, ...(co.length === 0 ? {} : { coOwnerKeys: co.map(publicKey) }) });
  await handle.flush(); handle.close();
  return file;
}
const tempDir = (t) => { const dir = mkdtempSync(join(tmpdir(), "irontrellis-4cb-")); t.after(() => rmSync(dir, { recursive: true, force: true })); return dir; };

test("4cb: verify states the identity it read; with the published history id and owner keys it confirms them", async (t) => {
  const dir = tempDir(t), o1 = pair("owner:1", 0x4cb01);
  const file = await history(dir, "h", o1);
  const plain = json(verifyArgs(file));
  assert.equal(plain.code, 0, plain.stderr);
  assert.equal(plain.doc.ok, true);
  const { historyId, ownerKeys } = plain.doc.identity;
  assert.match(historyId, /^0x[0-9a-f]{64}$/);
  assert.deepEqual(ownerKeys, [o1.credential]);
  assert.equal(plain.doc.identity.confirmed, false);
  assert.deepEqual(plain.doc.identity.mismatches, []);
  // Without the options the human report says, in plain words, where the identity came from.
  const human = run(verifyArgs(file));
  assert.equal(human.status, 0, human.stderr);
  assert.match(human.stdout, /history id +0x[0-9a-f]{64} \(read from the file\)/);
  assert.match(human.stdout, /The history id and the first owner keys were read from the file itself, not confirmed against a source outside it: a substitute history signed with other keys would verify the same way\./);
  // A match passes and says so.
  const matched = json(verifyArgs(file, "--expect-history-id", historyId, "--expect-owner-key", o1.credential));
  assert.equal(matched.code, 0, matched.stderr);
  assert.equal(matched.doc.ok, true);
  assert.equal(matched.doc.identity.confirmed, true);
  assert.match(run(verifyArgs(file, "--expect-history-id", historyId.toUpperCase().replace("0X", "0x"), "--expect-owner-key", o1.credential)).stdout,
    /The history id and the first owner keys match the values you gave from outside the file\./);
  // One part alone confirms only that part.
  const idOnly = run(verifyArgs(file, "--expect-history-id", historyId));
  assert.equal(idOnly.status, 0);
  assert.match(idOnly.stdout, /The history id matches the value you gave; the first owner key set was read from the file itself, not confirmed against a source outside it\./);
});

test("4cb: a wrong history id is refused before anything else is checked (HISTORY_ID_MISMATCH, expected and found)", async (t) => {
  const dir = tempDir(t), o1 = pair("owner:1", 0x4cb02);
  const file = await history(dir, "h", o1);
  const found = json(verifyArgs(file)).doc.identity.historyId;
  const wrong = `0x${"ab".repeat(32)}`;
  const r = json(verifyArgs(file, "--expect-history-id", wrong, "--expect-owner-key", o1.credential));
  assert.equal(r.code, 1);
  assert.equal(r.doc.ok, false);
  assert.equal(r.doc.error.code, "HISTORY_ID_MISMATCH");
  assert.deepEqual(r.doc.identity.mismatches.map((m) => [m.code, m.expected, m.found]), [["HISTORY_ID_MISMATCH", wrong, found]]);
  assert.match(r.doc.failures[0], /^HISTORY_ID_MISMATCH: the history id is 0x[0-9a-f]{64}, not the expected 0x(ab){32}$/);
  assert.equal(r.doc.report, undefined, "nothing else was checked");
  assert.match(run(verifyArgs(file, "--expect-history-id", wrong)).stdout, /This is not the history you named: its identity differs from the values you gave\./);
  // --accept-rollback re-pins (a write); a mismatch stops before it.
  const bytes = readFileSync(file), pin = readFileSync(`${file}.head`);
  assert.equal(run(["verify", "--history", file, "--accept-rollback", "--expect-history-id", wrong]).status, 1);
  assert.deepEqual(readFileSync(file), bytes);
  assert.deepEqual(readFileSync(`${file}.head`), pin);
  // A malformed value is a usage error (exit 1, like every failure), not a verdict.
  const malformed = run(verifyArgs(file, "--expect-history-id", "0x1234"));
  assert.equal(malformed.status, 1);
  assert.match(malformed.stderr, /USAGE.*--expect-history-id needs 0x \+ 64 hex/s);
});

test("4cb: the owner keys are compared as a set: a missing key or an extra key is refused (OWNER_KEYS_MISMATCH); order and key ids do not matter", async (t) => {
  const dir = tempDir(t), o1 = pair("owner:1", 0x4cb11), o2 = pair("owner:2", 0x4cb12), other = pair("owner:1", 0x4cb13);
  const file = await history(dir, "h", o1, [o2]);
  const id = json(verifyArgs(file)).doc.identity.historyId;
  assert.deepEqual(json(verifyArgs(file)).doc.identity.ownerKeys, [o1.credential, o2.credential].sort());
  // Both, in either order, with --expect-owner-key repeated or comma-separated.
  assert.equal(run(verifyArgs(file, "--expect-history-id", id, "--expect-owner-key", o2.credential, "--expect-owner-key", o1.credential)).status, 0);
  assert.equal(run(verifyArgs(file, "--expect-history-id", id, "--expect-owner-key", `${o1.credential},${o2.credential}`)).status, 0);
  // The history has a key the verifier did not expect.
  const missing = json(verifyArgs(file, "--expect-owner-key", o1.credential));
  assert.equal(missing.code, 1);
  assert.equal(missing.doc.error.code, "OWNER_KEYS_MISMATCH");
  assert.deepEqual(missing.doc.identity.mismatches[0].expected, [o1.credential]);
  assert.deepEqual(missing.doc.identity.mismatches[0].found, [o1.credential, o2.credential].sort());
  assert.match(missing.doc.failures[0], new RegExp(`^OWNER_KEYS_MISMATCH: .* \\(not expected ${o2.credential}\\)$`));
  // The verifier expects a key the history does not have.
  const extra = json(verifyArgs(file, "--expect-owner-key", [o1.credential, o2.credential, other.credential].join(",")));
  assert.equal(extra.code, 1);
  assert.equal(extra.doc.error.code, "OWNER_KEYS_MISMATCH");
  assert.match(extra.doc.failures[0], new RegExp(`\\(missing ${other.credential}\\)$`));
  // Both parts wrong: both codes, the id's first.
  const both = json(verifyArgs(file, "--expect-history-id", `0x${"cd".repeat(32)}`, "--expect-owner-key", other.credential));
  assert.deepEqual(both.doc.identity.mismatches.map((m) => m.code), ["HISTORY_ID_MISMATCH", "OWNER_KEYS_MISMATCH"]);
  assert.equal(both.doc.error.code, "HISTORY_ID_MISMATCH");
});

test("4cb: --expect-owner-keys reads a file of keys (0x hex or OpenSSH lines; blank lines and # comments skipped)", async (t) => {
  const dir = tempDir(t), o1 = pair("owner:1", 0x4cb21), o2 = pair("owner:2", 0x4cb22);
  const file = await history(dir, "h", o1, [o2]);
  const keys = join(dir, "published-keys.txt");
  writeFileSync(keys, `# the owner keys of this history, as published\n\n${sshPublicKeyOf(o1.credential, "owner one")}\n${o2.credential.toUpperCase().replace("0X", "0x")}\n`);
  const r = json(verifyArgs(file, "--expect-owner-keys", keys));
  assert.equal(r.code, 0, r.stderr);
  assert.deepEqual(r.doc.identity.expected.ownerKeys, [o1.credential, o2.credential].sort());
  writeFileSync(join(dir, "empty.txt"), "# nothing\n");
  assert.match(run(verifyArgs(file, "--expect-owner-keys", join(dir, "empty.txt"))).stderr, /USAGE.*lists no key/s);
  writeFileSync(join(dir, "bad.txt"), "not a key\n");
  const bad = run(verifyArgs(file, "--expect-owner-keys", join(dir, "bad.txt")));
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /USAGE.*bad\.txt:1/s);
  assert.match(run(verifyArgs(file, "--expect-owner-keys", join(dir, "absent.txt"))).stderr, /FILE_NOT_FOUND/);
  assert.equal(existsSync(join(dir, "absent.txt")), false);
});

test("4cb: a substitute history (the same events signed under new keys) passes on its own, with the caveat, and is refused under the published id and keys", async (t) => {
  const dir = tempDir(t), domain = createLocalDomain();
  const real = pair("owner:1", 0x4cb31), forged = pair("owner:1", 0x4cb32);
  const original = await history(dir, "original", real, [], domain);
  const substitute = await history(dir, "substitute", forged, [], domain);
  const published = json(verifyArgs(original)).doc.identity;
  // The substitute is internally consistent: it verifies, and only the caveat says what that rests on.
  const alone = run(verifyArgs(substitute));
  assert.equal(alone.status, 0, alone.stdout + alone.stderr);
  assert.match(alone.stdout, /^VERIFIED/m);
  assert.match(alone.stdout, /a substitute history signed with other keys would verify the same way/);
  // Same owner, controller, domain and time: the events differ only by the keys they carry and their signatures.
  const lines = (f) => readFileSync(f, "utf8").trim().split("\n").length;
  assert.equal(lines(substitute), lines(original));
  // Under the published values it is refused, with both codes.
  const r = json(verifyArgs(substitute, "--expect-history-id", published.historyId, "--expect-owner-key", published.ownerKeys[0]));
  assert.equal(r.code, 1);
  assert.deepEqual(r.doc.identity.mismatches.map((m) => m.code), ["HISTORY_ID_MISMATCH", "OWNER_KEYS_MISMATCH"]);
  assert.deepEqual(r.doc.identity.mismatches[1].found, [forged.credential]);
  // Only the published keys (no id) still tell them apart.
  assert.equal(json(verifyArgs(substitute, "--expect-owner-key", real.credential)).doc.error.code, "OWNER_KEYS_MISMATCH");
  assert.equal(run(verifyArgs(original, "--expect-history-id", published.historyId, "--expect-owner-key", real.credential)).status, 0);
});

test("4cb: export verify checks the view's history id first and its first owner keys after the view verified", async (t) => {
  const dir = tempDir(t), o1 = pair("owner:1", 0x4cb41), forged = pair("owner:1", 0x4cb42);
  const file = await history(dir, "h", o1);
  const id = json(verifyArgs(file)).doc.identity.historyId;
  const exported = run(["export", "--history", file, "--view"]);
  assert.equal(exported.status, 0, exported.stderr);
  const view = join(dir, "view.json");
  writeFileSync(view, exported.stdout);
  assert.equal(JSON.parse(exported.stdout).historyId, id, "the id the CLI derives from genesisEventHash is the view's and init's historyId");
  const plain = json(["export", "verify", view]);
  assert.equal(plain.code, 0, plain.stderr);
  assert.deepEqual([plain.doc.identity.historyId, plain.doc.identity.ownerKeys, plain.doc.identity.confirmed], [id, [o1.credential], false]);
  assert.match(run(["export", "verify", view]).stdout, /not confirmed against a source outside it/);
  const matched = json(["export", "verify", view, "--expect-history-id", id, "--expect-owner-key", o1.credential]);
  assert.equal(matched.code, 0, matched.stderr);
  assert.equal(matched.doc.identity.confirmed, true);
  const wrongId = json(["export", "verify", view, "--expect-history-id", `0x${"ef".repeat(32)}`]);
  assert.equal(wrongId.code, 1);
  assert.equal(wrongId.doc.code, "HISTORY_ID_MISMATCH");
  assert.equal(wrongId.doc.from, undefined, "the view was not checked");
  assert.equal(wrongId.doc.identity.ownerKeys, null);
  const wrongKey = json(["export", "verify", view, "--expect-history-id", id, "--expect-owner-key", forged.credential]);
  assert.equal(wrongKey.code, 1);
  assert.equal(wrongKey.doc.code, "OWNER_KEYS_MISMATCH");
  assert.deepEqual(wrongKey.doc.identity.mismatches[0].found, [o1.credential]);
});

// ---------------------------------------------------------------- post5-09: the re-check and what init publishes

const { main } = await import("../dist/cli.js");
const { IDENTITY_TEST_SEAMS } = await import("../dist/identity.js");
/** verify in this process (the test seams are module state), with --json. */
async function verifyHere(args) {
  let stdout = "";
  const code = await main([...args, "--json"], { stdout: (text) => { stdout += text; }, stderr: () => {} });
  return { code, doc: JSON.parse(stdout) };
}
const replace = (target, source) => { for (const suffix of ["", ".head"]) writeFileSync(`${target}${suffix}`, readFileSync(`${source}${suffix}`)); };

test("post5-09: a file replaced between the identity read and the verification is refused with HISTORY_CHANGED, also when it is put back before the re-check", async (t) => {
  const dir = tempDir(t), domain = createLocalDomain();
  const real = pair("owner:1", 0x4cb51), forged = pair("owner:1", 0x4cb52);
  const original = await history(dir, "original", real, [], domain);
  const substitute = await history(dir, "substitute", forged, [], domain);
  const saved = join(dir, "saved");
  replace(saved, original);
  const { historyId } = json(verifyArgs(original)).doc.identity;
  const args = verifyArgs(original, "--expect-history-id", historyId, "--expect-owner-key", real.credential);
  t.after(() => { delete IDENTITY_TEST_SEAMS.afterIdentity; delete IDENTITY_TEST_SEAMS.beforeRecheck; });
  // No swap: the re-check runs and passes.
  let rechecked = 0;
  IDENTITY_TEST_SEAMS.beforeRecheck = () => { rechecked += 1; };
  const same = await verifyHere(args);
  assert.equal(same.code, 0, JSON.stringify(same.doc.failures));
  assert.equal(same.doc.identity.confirmed, true);
  assert.equal(rechecked, 1);
  // Without values given there is nothing to re-check.
  await verifyHere(verifyArgs(original));
  assert.equal(rechecked, 1);
  // The substitute is put in place after the identity read: the verification judges it, the re-check refuses.
  IDENTITY_TEST_SEAMS.afterIdentity = () => replace(original, substitute);
  delete IDENTITY_TEST_SEAMS.beforeRecheck;
  const swapped = await verifyHere(args);
  assert.equal(swapped.code, 1);
  assert.equal(swapped.doc.ok, false);
  assert.equal(swapped.doc.error.code, "HISTORY_CHANGED");
  assert.match(swapped.doc.failures[0], /^HISTORY_CHANGED: the history id changed during the verification/);
  assert.equal(swapped.doc.identity.confirmed, false);
  assert.match(swapped.doc.identity.changed, /^HISTORY_CHANGED: /);
  // A → B → A: the substitute is verified and the original put back before the re-check; the judged head is not on its chain.
  replace(original, saved);
  IDENTITY_TEST_SEAMS.beforeRecheck = () => replace(original, saved);
  const restored = await verifyHere(args);
  assert.equal(restored.code, 1);
  assert.equal(restored.doc.error.code, "HISTORY_CHANGED");
  assert.match(restored.doc.failures[0], /^HISTORY_CHANGED: the head the verification judged \(position \d+\) is not on the chain of the file whose identity was checked$/);
  // The human report says what that means.
  delete IDENTITY_TEST_SEAMS.afterIdentity; delete IDENTITY_TEST_SEAMS.beforeRecheck;
  replace(original, saved);
  let text = "";
  IDENTITY_TEST_SEAMS.afterIdentity = () => replace(original, substitute);
  await main(args, { stdout: (s) => { text += s; }, stderr: () => {} });
  assert.match(text, /The file changed while it was being verified, so the identity checked first may not be the verified file's/);
});

test("post5-09: irontrellis init ends with what to publish (also in --json), in the form verify --expect-… takes", async (t) => {
  const dir = tempDir(t);
  const file = join(dir, "h.jsonl");
  const created = run(["--history", file, "init"]);
  assert.equal(created.status, 0, created.stderr);
  const { historyId, ownerKeys } = json(verifyArgs(file)).doc.identity;
  const tail = created.stdout.trimEnd().split("\n").slice(-4);
  assert.deepEqual(tail.slice(0, 3), ["Publish these where readers can check them independently of this file:", `  history id  ${historyId}`, `  owner key   ${ownerKeys[0]}`]);
  assert.equal(tail[3], `A reader checks them with: irontrellis --history ${file} verify --expect-history-id ${historyId} --expect-owner-key ${ownerKeys[0]}`);
  // The printed command, as printed, confirms the history.
  const printed = tail[3].replace(/^A reader checks them with: irontrellis /, "").split(" ");
  const confirmed = json([...printed, "--no-remote"]);
  assert.equal(confirmed.code, 0, confirmed.stderr);
  assert.equal(confirmed.doc.identity.confirmed, true);
  const second = json(["--history", join(dir, "h2.jsonl"), "init"]);
  assert.equal(second.code, 0);
  const identity = json(verifyArgs(join(dir, "h2.jsonl"))).doc.identity;
  assert.deepEqual(second.doc.publish, { historyId: identity.historyId, ownerKeys: identity.ownerKeys });
});

test("post5-10: irontrellis init's reader command quotes a history path the shell would split, and the command, run by a shell, confirms the history", async (t) => {
  const dir = join(tempDir(t), "it's a dir");
  mkdirSync(dir);
  const file = join(dir, "h.jsonl");
  const created = run(["--history", file, "init"]);
  assert.equal(created.status, 0, created.stderr);
  const line = created.stdout.trimEnd().split("\n").at(-1);
  assert.ok(line.startsWith(`A reader checks them with: irontrellis --history '${file.replace(/'/g, "'\\''")}' verify `), line);
  const command = line.replace(/^A reader checks them with: /, "");
  const r = spawnSync("/bin/sh", ["-c", `irontrellis() { "$IT_NODE" "$IT_BIN" "$@"; }; ${command} --no-remote --json`], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1", IT_NODE: process.execPath, IT_BIN: BIN } });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(r.stdout).identity.confirmed, true);
});

