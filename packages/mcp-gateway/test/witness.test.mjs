// Remote witnesses and the gateway (docs/WITNESS.md §5): the gateway opens the history through the core store, which
// picks up the witness policy from <history>.witness.json and the history's bindings; no gateway configuration changes.
// With requireOnOpen the gateway confirms the history with the witnesses before serving, and a history rolled back
// behind the witness is refused. The witness is the core's in-test fake.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { setup } from "./fixtures.mjs";
import { createGateway } from "../dist/gateway.js";
import { revokeAuthority, snapshotCase, verifySnapshot } from "../dist/operations.js";
import { startFakeWitness } from "../../core/test/helpers/fake-witness.mjs";

test("the gateway honours the side-file witness policy: it serves a witnessed history and refuses one rolled back behind the witness", async (t) => {
  const w = await startFakeWitness({ name: "gateway-witness" });
  const root = mkdtempSync(join(tmpdir(), "irontrellis-gateway-witness-"));
  const gateways = [];
  t.after(async () => { for (const g of gateways) await g.close(); await w.close(); rmSync(root, { recursive: true, force: true, maxRetries: 10 }); });
  const f = await setup(join(root, "case"), { mode: "per-call" });
  const added = await f.owner.addWitness({ url: w.url, verifierKey: w.verifierKey }, { mode: "sync", requireOnOpen: true, cacheMs: 0 });
  assert.equal(added.submitted, true);
  const open = async () => { const g = await createGateway({ ...f.config, local: f.local }); gateways.push(g); return g; };
  const requests = w.state.requests.length;
  const g = await open();
  assert.ok(w.state.requests.length > requests, "the gateway asked the witness before serving (requireOnOpen)");
  assert.equal((await g.run("create_incident_ticket", { title: "first" })).status, "FORWARDED");
  const history = f.local.historyFile;
  const old = { file: readFileSync(history), head: readFileSync(`${history}.head`) };
  // The operator revokes the grant through the gateway's operations (an owner write, witnessed before the process ends).
  const revoked = await revokeAuthority({ historyFile: history, authority: "write" });
  const historyId = JSON.parse(readFileSync(`${history}.witness.json`, "utf8")).historyId;
  assert.deepEqual(w.latest(historyId), revoked.head);
  // An older copy (grant still live) is put back with its own attested pin: the gateway refuses to start on it.
  writeFileSync(history, old.file);
  writeFileSync(`${history}.head`, old.head);
  await assert.rejects(open(), (error) => error.code === "ROLLBACK_DETECTED" || /ROLLBACK_DETECTED/.test(String(error?.message)));
});

test("exactly-once with requireOnOpen: every run confirms the history with the witness, and the per-call handles start from that answer", async (t) => {
  const w = await startFakeWitness({ name: "gateway-witness-once" });
  const root = mkdtempSync(join(tmpdir(), "irontrellis-gateway-witness-"));
  const gateways = [];
  t.after(async () => { for (const g of gateways) await g.close(); await w.close(); rmSync(root, { recursive: true, force: true, maxRetries: 10 }); });
  const f = await setup(join(root, "case"), { mode: "exactly-once" });
  await f.owner.addWitness({ url: w.url, verifierKey: w.verifierKey }, { mode: "sync", requireOnOpen: true, cacheMs: 0 });
  const g = await createGateway({ ...f.config, local: f.local });
  gateways.push(g);
  const before = w.state.requests.filter((r) => r.startsWith("GET /v1/histories/")).length;
  const result = await g.run("create_incident_ticket", { title: "witnessed" });
  assert.equal(result.status, "RESPONSE_RETAINED", JSON.stringify(result));
  assert.ok(w.state.requests.filter((r) => r.startsWith("GET /v1/histories/")).length > before, "the run asked the witness (cacheMs 0)");
});

test("a snapshot copies the remote witness side file (policy, remembered checkpoints) and verifies offline even under requireOnOpen", async (t) => {
  const w = await startFakeWitness({ name: "gateway-witness-snapshot" });
  const root = realpathSync(mkdtempSync(join(tmpdir(), "irontrellis-gateway-witness-")));
  t.after(async () => { await w.close(); rmSync(root, { recursive: true, force: true, maxRetries: 10 }); });
  const f = await setup(join(root, "case"));
  await f.owner.addWitness({ url: w.url, verifierKey: w.verifierKey }, { mode: "sync", quorum: 1, requireOnOpen: false, cacheMs: 0 });
  const history = f.local.historyFile;
  const directory = join(root, "snapshot");
  const made = snapshotCase({ historyFile: history, storage: f.config.storage, directory });
  assert.equal(made.witnessState, true);
  assert.ok(readdirSync(directory).includes("history.jsonl.witness.json"));
  assert.deepEqual(readFileSync(join(directory, "history.jsonl.witness.json")), readFileSync(`${history}.witness.json`));
  const copied = JSON.parse(readFileSync(join(directory, "history.jsonl.witness.json"), "utf8"));
  assert.equal(copied.policy.mode, "sync");
  assert.ok(Object.values(copied.witnesses).some((entry) => entry.checkpoint !== undefined), "the remembered checkpoint travels with the copy");
  const verified = verifySnapshot(directory);
  assert.equal(verified.witnessState, true);
  assert.equal(verified.status, "PRIVATE_SNAPSHOT_VERIFIED");
  // The side file is covered by the manifest checksums.
  const sidePath = join(directory, "history.jsonl.witness.json");
  const requiring = `${JSON.stringify({ ...copied, policy: { ...copied.policy, requireOnOpen: true } })}\n`;
  writeFileSync(sidePath, requiring, { mode: 0o600 });
  assert.throws(() => verifySnapshot(directory), /SNAPSHOT_MISMATCH/);
  // A copy whose policy asks for a witness check before every read still verifies offline, with the witness down:
  // the snapshot check does not establish currentness, so it neither asks the witnesses nor waits for them.
  const manifestPath = join(directory, "snapshot.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const row = manifest.files.find((file) => file.path === "history.jsonl.witness.json");
  row.bytes = Buffer.byteLength(requiring);
  row.sha256 = createHash("sha256").update(requiring).digest("hex");
  writeFileSync(manifestPath, JSON.stringify(manifest), { mode: 0o600 });
  w.down = true;
  assert.equal(verifySnapshot(directory).status, "PRIVATE_SNAPSHOT_VERIFIED");
});

test("a snapshot never copies a witness registration token: the copied side file's policy has every token removed, the live one keeps it", async (t) => {
  const w = await startFakeWitness({ name: "gateway-witness-token", seed: 31, token: "itw_snapshot-secret" });
  const root = realpathSync(mkdtempSync(join(tmpdir(), "irontrellis-gateway-witness-")));
  t.after(async () => { await w.close(); rmSync(root, { recursive: true, force: true, maxRetries: 10 }); });
  const f = await setup(join(root, "case"));
  await f.owner.addWitness({ url: w.url, verifierKey: w.verifierKey, token: "itw_snapshot-secret" }, { mode: "sync" });
  const history = f.local.historyFile;
  assert.equal(JSON.parse(readFileSync(`${history}.witness.json`, "utf8")).policy.witnesses[0].token, "itw_snapshot-secret");
  const directory = join(root, "snapshot");
  const made = snapshotCase({ historyFile: history, storage: f.config.storage, directory });
  assert.equal(made.witnessState, true);
  const copiedText = readFileSync(join(directory, "history.jsonl.witness.json"), "utf8");
  assert.ok(!copiedText.includes("itw_snapshot-secret"), "no token anywhere in the snapshot's side file");
  for (const name of readdirSync(directory)) {
    if (name !== "records") assert.ok(!readFileSync(join(directory, name), "utf8").includes("itw_snapshot-secret"), name);
  }
  const copied = JSON.parse(copiedText);
  assert.equal(copied.policy.witnesses[0].token, undefined);
  assert.equal(copied.policy.witnesses[0].verifierKey, w.verifierKey, "the rest of the policy travels");
  assert.equal(JSON.parse(readFileSync(`${history}.witness.json`, "utf8")).policy.witnesses[0].token, "itw_snapshot-secret", "the live side file is untouched");
  assert.equal(verifySnapshot(directory).status, "PRIVATE_SNAPSHOT_VERIFIED", "the manifest covers the stripped copy");
});

test("irontrellis-mcp-ops snapshot and inspect from a fresh process on a requireOnOpen case: offline copies, never gated on the witness check (and never claiming currentness); rollback evidence still refuses", async (t) => {
  const { spawn } = await import("node:child_process");
  const { fileURLToPath } = await import("node:url");
  const OPS = fileURLToPath(new URL("../dist/ops-cli.js", import.meta.url));
  // Asynchronous child: the fake witness in this process must be able to answer it.
  const ops = (...args) => new Promise((done) => {
    const child = spawn(process.execPath, [OPS, ...args]);
    let stdout = "", stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("close", (status) => done({ status, stdout, stderr }));
  });
  const w = await startFakeWitness({ name: "gateway-witness-ops" });
  const root = realpathSync(mkdtempSync(join(tmpdir(), "irontrellis-gateway-witness-")));
  t.after(async () => { await w.close(); rmSync(root, { recursive: true, force: true, maxRetries: 10 }); });
  const f = await setup(join(root, "case"));
  await f.owner.addWitness({ url: w.url, verifierKey: w.verifierKey }, { mode: "sync", requireOnOpen: true, cacheMs: 0 });
  const history = f.local.historyFile;
  const location = ["--history", history, "--storage", f.config.storage];
  const requests = w.state.requests.length;
  const made = await ops("snapshot", ...location, "--directory", join(root, "snapshot-1"));
  assert.equal(made.status, 0, made.stderr);
  const result = JSON.parse(made.stdout);
  assert.equal(result.status, "PRIVATE_SNAPSHOT_CREATED");
  assert.equal(result.remoteWitnessCheck, "SKIPPED");
  assert.equal(result.currentnessEstablished, false);
  assert.equal(result.witnessState, true);
  assert.equal(w.state.requests.length, requests, "offline: the witness was not asked");
  const inspected = await ops("inspect", ...location);
  assert.equal(inspected.status, 0, inspected.stderr);
  assert.ok(JSON.parse(inspected.stdout).warnings.includes("REMOTE_WITNESS_NOT_CHECKED"));
  const verified = await ops("verify", "--directory", join(root, "snapshot-1"));
  assert.equal(verified.status, 0, verified.stderr);
  // The witness down changes nothing for an offline copy.
  w.down = true;
  assert.equal((await ops("snapshot", ...location, "--directory", join(root, "snapshot-2"))).status, 0);
  w.down = false;
  // A case without requireOnOpen is not marked.
  const plain = await setup(join(root, "plain"));
  const plainMade = await ops("snapshot", "--history", plain.local.historyFile, "--storage", plain.config.storage, "--directory", join(root, "snapshot-plain"));
  assert.equal(JSON.parse(plainMade.stdout).remoteWitnessCheck, "NOT_REQUIRED");
  // Evidence of a rollback (the side file remembers a later witnessed head than the history holds) still refuses.
  const old = { file: readFileSync(history), head: readFileSync(`${history}.head`) };
  await revokeAuthority({ historyFile: history, authority: "write" });
  writeFileSync(history, old.file);
  writeFileSync(`${history}.head`, old.head);
  const refused = await ops("snapshot", ...location, "--directory", join(root, "snapshot-3"));
  assert.equal(refused.status, 2);
  assert.equal(JSON.parse(refused.stderr.trim().split("\n").at(-1)).reason, "ROLLBACK_DETECTED");
});
