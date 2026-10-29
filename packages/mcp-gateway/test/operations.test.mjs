import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, realpathSync, rmSync, readFileSync, readdirSync, statSync, writeFileSync, symlinkSync, chmodSync, existsSync, truncateSync } from "node:fs";
import { tmpdir, hostname } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { anchorHead, loadOwnerKeyFile, localAnchorLog, openHistoryStore, ownerKeyPathFor } from "@ramex-labs/irontrellis";
import { setup } from "./fixtures.mjs";
import { acquireHostLease, recoverDeadHost, inspectCase, snapshotCase, verifySnapshot, revokeAuthority } from "../dist/operations.js";
import { createGateway } from "../dist/gateway.js";

const OPS = fileURLToPath(new URL("../dist/ops-cli.js", import.meta.url));
const ops = (...args) => spawnSync(process.execPath, [OPS, ...args], { encoding: "utf8" });
async function fixture(t) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "irontrellis-ops-"))), f = await setup(join(root, "case"));
  t.after(() => rmSync(root, { recursive: true, force: true, maxRetries: 10 }));
  return { ...f, root, location: { historyFile: f.local.historyFile, storage: f.config.storage } };
}

test("one live host owns a case, release is idempotent and cannot be force-reclaimed", async (t) => {
  const f = await fixture(t), lease = acquireHostLease(f.config.storage);
  assert.throws(() => acquireHostLease(f.config.storage), /HOST_ALREADY_OWNED/);
  assert.throws(() => recoverDeadHost(f.config.storage), /HOST_STILL_RUNNING/);
  lease.assertOwned();
  lease.release();
  lease.release();
  const next = acquireHostLease(f.config.storage);
  next.release();
});

test("explicit dead same-host recovery changes no history or authority", async (t) => {
  const f = await fixture(t), child = spawnSync(process.execPath, ["-e", "process.stdout.write(String(process.pid))"]), pid = Number(child.stdout.toString());
  const before = readFileSync(f.local.historyFile);
  writeFileSync(join(f.config.storage, "gateway-host.lock.json"), JSON.stringify({ version: "irontrellis-gateway-host/1", host: hostname(), pid, nonce: "fixture" }), { mode: 0o600 });
  assert.equal(recoverDeadHost(f.config.storage).historyChanged, false);
  assert.deepEqual(readFileSync(f.local.historyFile), before);
  acquireHostLease(f.config.storage).release();
});

test("different host, bad metadata and symlink leases are never reclaimed", async (t) => {
  const f = await fixture(t), path = join(f.config.storage, "gateway-host.lock.json");
  writeFileSync(path, JSON.stringify({ version: "irontrellis-gateway-host/1", host: "another-host", pid: 99999999, nonce: "fixture" }), { mode: 0o600 });
  assert.throws(() => recoverDeadHost(f.config.storage), /HOST_RECOVERY_UNVERIFIED/);
  rmSync(path);
  writeFileSync(path, "{}", { mode: 0o600 });
  assert.throws(() => recoverDeadHost(f.config.storage));
  rmSync(path);
  symlinkSync(f.local.historyFile, path);
  assert.throws(() => recoverDeadHost(f.config.storage));
});

test("a replaced lease is detected and never removed by the former owner", async (t) => {
  const f = await fixture(t), lease = acquireHostLease(f.config.storage), path = join(f.config.storage, "gateway-host.lock.json");
  const record = JSON.parse(readFileSync(path));
  record.nonce = "replacement";
  writeFileSync(path, JSON.stringify(record));
  assert.throws(() => lease.assertOwned(), /HOST_NOT_OWNED/);
  assert.throws(() => lease.release(), /HOST_NOT_OWNED/);
});

test("inspection reports counts, capacity and chain status without private content or paths", async (t) => {
  const f = await fixture(t);
  writeFileSync(join(f.config.storage, "private.json"), "secret:should-not-appear", { mode: 0o600 });
  const result = inspectCase(f.location), text = JSON.stringify(result);
  assert.ok(result.eventCount > 0);
  assert.equal(result.maxEvents, null);
  assert.equal(result.mode, "OPEN");
  assert.equal(result.chain, "OK");
  assert.equal(result.rollback, false);
  assert.equal(result.format, "irontrellis-event/2");
  assert.equal(text.includes("secret"), false);
  assert.equal(text.includes(f.root), false);
  assert.equal(text.includes("worker"), false);
});

test("private offline snapshot verifies without signing keys or live restore authority", async (t) => {
  const f = await fixture(t), directory = join(f.root, "snapshot");
  writeFileSync(join(f.config.storage, "note.json"), "{}", { mode: 0o600 });
  assert.equal(snapshotCase({ ...f.location, directory }).status, "PRIVATE_SNAPSHOT_CREATED");
  const verified = verifySnapshot(directory);
  assert.equal(verified.currentnessEstablished, false);
  assert.equal(verified.restoreAuthorized, false);
  const manifest = JSON.parse(readFileSync(join(directory, "snapshot.json")));
  assert.equal(manifest.files.some((row) => row.path.includes("key")), false);
  assert.equal(inspectCase(f.location).leasePresent, false);
  assert.throws(() => snapshotCase({ ...f.location, directory }), /SNAPSHOT_TARGET_INVALID/);
});

test("snapshot refuses an active gateway, a public directory and symlink records", async (t) => {
  const f = await fixture(t), directory = join(f.root, "snapshot"), lease = acquireHostLease(f.config.storage);
  assert.throws(() => snapshotCase({ ...f.location, directory }), /HOST_ALREADY_OWNED/);
  lease.release();
  symlinkSync(f.config.keyFile, join(f.config.storage, "link.json"));
  assert.throws(() => snapshotCase({ ...f.location, directory }));
  assert.equal(existsSync(join(f.config.storage, "gateway-host.lock.json")), false);
});

test("snapshot checksum alteration and unlisted additions are refused", async (t) => {
  const f = await fixture(t), directory = join(f.root, "snapshot");
  snapshotCase({ ...f.location, directory });
  writeFileSync(join(directory, "records", "injected.json"), "{}", { mode: 0o600 });
  assert.throws(() => verifySnapshot(directory), /SNAPSHOT_INVALID/);
  rmSync(join(directory, "records", "injected.json"));
  writeFileSync(join(directory, "history.jsonl"), "changed", { mode: 0o600 });
  assert.throws(() => verifySnapshot(directory), /SNAPSHOT_MISMATCH/);
});

test("unsafe record permissions and oversized files are refused in diagnostics", async (t) => {
  const f = await fixture(t), path = join(f.config.storage, "bad.json");
  writeFileSync(path, "{}", { mode: 0o644 });
  // Windows: mode bits are synthetic and not checked (docs/PLATFORMS.md §3); the size check below applies everywhere.
  if (process.platform !== "win32") assert.throws(() => inspectCase(f.location), /PRIVATE_FILE_INVALID/);
  chmodSync(path, 0o600);
  writeFileSync(path, Buffer.alloc(131073));
  assert.throws(() => inspectCase(f.location), /PRIVATE_FILE_INVALID/);
});

test("revoke writes one control event, is idempotent and takes effect on the running gateway", async (t) => {
  const f = await fixture(t), g = await createGateway({ ...f.config, local: f.local });
  t.after(() => g.close());
  assert.equal(g.why("create_incident_ticket").decision, "ALLOW");
  const before = openHistoryStore(f.local.historyFile).state().events.length;
  const revoked = await revokeAuthority({ historyFile: f.local.historyFile, authority: "write" });
  assert.equal(revoked.status, "AUTHORITY_REVOKED");
  assert.equal(revoked.authorityChanged, true);
  assert.equal(openHistoryStore(f.local.historyFile).state().events.length, before + 1);
  assert.equal(g.why("create_incident_ticket").decision, "DENY");
  const denied = await g.run("create_incident_ticket", { title: "after revocation" });
  assert.equal(denied.status, "DENIED");
  // Format 2 (SPEC §10.1): the DENY is recorded as a CORE refusal signed by the worker's own session.
  assert.equal(denied.refusal.recorded, true);
  const refusal = openHistoryStore(f.local.historyFile).state().events.at(-1);
  assert.equal(refusal.type, "REQUEST_REFUSED");
  assert.deepEqual([refusal.data.refusalSource, refusal.data.request.actorId, refusal.data.code], ["CORE", "worker", "REVOKED"]);
  const again = await revokeAuthority({ historyFile: f.local.historyFile, authority: "write" });
  assert.equal(again.status, "ALREADY_REVOKED");
  assert.equal(again.eventId, revoked.eventId);
  assert.equal(openHistoryStore(f.local.historyFile).state().events.length, before + 2);
  await assert.rejects(revokeAuthority({ historyFile: f.local.historyFile, authority: "absent" }), /UNKNOWN_AUTHORITY/);
});

test("after a revoke, a job that already ran reconciles with its retained reply and is not sent again", async (t) => {
  const f = await fixture(t), g = await createGateway({ ...f.config, local: f.local });
  t.after(() => g.close());
  const first = await g.run("create_incident_ticket", { title: "before revocation" });
  assert.equal(first.status, "RESPONSE_RETAINED");
  assert.equal((await revokeAuthority({ historyFile: f.local.historyFile, authority: "write" })).status, "AUTHORITY_REVOKED");
  const repeat = await g.run("create_incident_ticket", { title: "before revocation" });
  assert.equal(repeat.status, "RECONCILIATION_ONLY");
  assert.ok(first.upstreamResult !== undefined);
  assert.deepEqual(repeat.upstreamResult, first.upstreamResult);
  assert.equal(readdirSync(f.directory).filter((n) => n.startsWith("ticket-")).length, 1);
});

test("the ops CLI has --help, revoke, inspect by --config, and bounded refusals", async (t) => {
  const f = await fixture(t);
  for (const flag of ["--help", "-h", "help"]) {
    const help = ops(flag);
    assert.equal(help.status, 0);
    assert.match(help.stdout, /Usage: irontrellis-mcp-ops/);
    assert.match(help.stdout, /revoke/);
  }
  const none = ops();
  assert.equal(none.status, 2);
  assert.match(none.stdout, /Usage/);
  const inspect = ops("inspect", "--config", f.configFile);
  assert.equal(inspect.status, 0, inspect.stderr);
  assert.equal(JSON.parse(inspect.stdout).mode, "OPEN");
  const revoke = ops("revoke", "--config", f.configFile, "--authority", "read");
  assert.equal(revoke.status, 0, revoke.stderr);
  assert.equal(JSON.parse(revoke.stdout).status, "AUTHORITY_REVOKED");
  const byHistory = ops("revoke", "--history", f.local.historyFile, "--authority", "read");
  assert.equal(JSON.parse(byHistory.stdout).status, "ALREADY_REVOKED");
  const unknown = ops("revoke", "--history", f.local.historyFile, "--authority", "absent");
  assert.equal(unknown.status, 2);
  assert.deepEqual(JSON.parse(unknown.stderr.trim().split("\n").at(-1)), { status: "REFUSED", reason: "UNKNOWN_AUTHORITY" });
  const bad = ops("frobnicate", "--storage", f.config.storage);
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /Usage/);
  assert.deepEqual(JSON.parse(bad.stderr.trim().split("\n").at(-1)), { status: "REFUSED", reason: "USAGE", detail: 'unknown command "frobnicate"' });
  const flag = ops("inspect", "--bogus", "x");
  assert.deepEqual(JSON.parse(flag.stderr.trim().split("\n").at(-1)), { status: "REFUSED", reason: "USAGE", detail: 'unknown option "--bogus"' });
  assert.equal(ops("snapshot", "--help").status, 0);
  const missing = ops("inspect", "--history", f.local.historyFile);
  assert.equal(missing.status, 2);
  assert.match(JSON.parse(missing.stderr.trim().split("\n").at(-1)).detail, /missing --storage/);
  if (process.platform !== "win32") { // Windows: mode bits are synthetic and not checked (docs/PLATFORMS.md §3)
    chmodSync(f.configFile, 0o644);
    const exposed = JSON.parse(ops("inspect", "--config", f.configFile).stderr.trim().split("\n").at(-1));
    assert.equal(exposed.reason, "STORAGE_UNAVAILABLE");
    assert.match(exposed.detail, /^gateway\.json: has mode 0644; it must be owner-only \(0600\)$/);
  }
});

test("a snapshot holds the pinned head, the anchor log and gateway.json, and never a key file", async (t) => {
  const f = await fixture(t), directory = join(f.root, "snapshot"), history = f.local.historyFile;
  const signer = loadOwnerKeyFile(ownerKeyPathFor(history));
  await anchorHead(openHistoryStore(history, { signer }), signer, localAnchorLog(history + ".anchors"), { id: "event:anchor:snapshot-test", anchoredAt: Date.now() });
  assert.ok(existsSync(history + ".head") && existsSync(history + ".anchors") && existsSync(ownerKeyPathFor(history)));
  const made = ops("snapshot", "--config", f.configFile, "--directory", directory);
  assert.equal(made.status, 0, made.stderr);
  assert.deepEqual({ ...JSON.parse(made.stdout), files: undefined }, { status: "PRIVATE_SNAPSHOT_CREATED", files: undefined, pinnedHead: true, anchors: true, witnessState: false, configuration: true, keysIncluded: false, restoreAuthorized: false, remoteWitnessCheck: "NOT_REQUIRED", currentnessEstablished: false });
  assert.deepEqual(readdirSync(directory).sort(), ["gateway.json", "history.jsonl", "history.jsonl.anchors", "history.jsonl.head", "records", "snapshot.json"]);
  for (const [copy, original] of [["history.jsonl", history], ["history.jsonl.head", history + ".head"], ["history.jsonl.anchors", history + ".anchors"], ["gateway.json", f.configFile]]) {
    assert.deepEqual(readFileSync(join(directory, copy)), readFileSync(original), copy);
  }
  const manifest = JSON.parse(readFileSync(join(directory, "snapshot.json")));
  assert.equal(manifest.files.some((row) => /key/.test(row.path)), false);
  const verified = verifySnapshot(directory);
  assert.equal(verified.pinnedHeadStatus, "MATCHES");
  assert.equal(verified.anchors, true);
  assert.equal(verified.configuration, true);
  writeFileSync(join(directory, "history.jsonl.head"), "{}", { mode: 0o600 });
  assert.throws(() => verifySnapshot(directory), /SNAPSHOT_MISMATCH/);
  // Without --config there is no gateway.json to copy, and a missing pin is simply not copied.
  const bare = join(f.root, "bare");
  rmSync(history + ".anchors");
  assert.equal(snapshotCase({ ...f.location, directory: bare }).anchors, false);
  assert.deepEqual(readdirSync(bare).sort(), ["history.jsonl", "history.jsonl.head", "records", "snapshot.json"]);
  assert.equal(verifySnapshot(bare).configuration, false);
});

test("snapshot into a directory whose parent is not 0700 says why", { skip: process.platform === "win32" && "Windows has no POSIX modes: the directory's ACL protects it (docs/PLATFORMS.md §3)" }, async (t) => {
  const f = await fixture(t), parent = join(f.root, "shared");
  mkdirSync(parent, { mode: 0o755 });
  chmodSync(parent, 0o755);
  const refused = ops("snapshot", "--config", f.configFile, "--directory", join(parent, "snapshot"));
  assert.equal(refused.status, 2);
  const line = JSON.parse(refused.stderr.trim().split("\n").at(-1));
  assert.equal(line.reason, "STORAGE_UNAVAILABLE");
  assert.match(line.detail, /the snapshot's parent directory: .*shared has mode 0755; it must be owner-only \(0700\)/);
});

test("the operator tools read histories up to the core store's limit and name the limit beyond it", async (t) => {
  const f = await fixture(t);
  // Past the former 8 MiB cap of the operator tools (about 1,000 large grants here; about 10,000 ordinary events).
  const actions = Array.from({ length: 32 }, (_, i) => `act:${"y".repeat(110)}:${i}`), resources = Array.from({ length: 32 }, (_, i) => `document:${"x".repeat(110)}:${i}`);
  for (let n = 0; statSync(f.local.historyFile).size <= 8 * 1024 * 1024 + 4096; n++) {
    await f.owner.grant({ id: `bulk:${n}`, to: "worker", actions, resources, expiresAt: Date.now() + 3600000 });
  }
  const inspected = ops("inspect", "--config", f.configFile);
  assert.equal(inspected.status, 0, inspected.stderr);
  assert.equal(JSON.parse(inspected.stdout).limits.historyBytes, 1024 * 1024 * 1024);
  const directory = join(f.root, "snapshot");
  assert.equal(ops("snapshot", "--config", f.configFile, "--directory", directory).status, 0);
  assert.equal(ops("verify", "--directory", directory).status, 0);
  // A (sparse) file over the largest store limit is refused before it is read, naming its size and the limit.
  const huge = join(f.root, "huge.jsonl");
  writeFileSync(huge, "", { mode: 0o600 });
  truncateSync(huge, 1024 * 1024 * 1024 + 1);
  assert.throws(() => inspectCase({ historyFile: huge, storage: f.config.storage }), (error) =>
    error.code === "PRIVATE_FILE_TOO_LARGE" && /is 1073741825 bytes; the limit is 1073741824 bytes/.test(error.detail));
  const refused = JSON.parse(ops("inspect", "--history", huge, "--storage", f.config.storage).stderr.trim().split("\n").at(-1));
  assert.equal(refused.reason, "PRIVATE_FILE_TOO_LARGE");
  assert.match(refused.detail, /the limit is 1073741824 bytes/);
});

test("irontrellis-mcp-ops and irontrellis-mcp-gateway answer --version with the package version", () => {
  const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  const r = ops("--version");
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, `irontrellis-mcp-ops ${version}\n`);
  const gateway = spawnSync(process.execPath, [fileURLToPath(new URL("../dist/cli.js", import.meta.url)), "--version"], { encoding: "utf8" });
  assert.equal(gateway.status, 0, gateway.stderr);
  assert.equal(gateway.stdout, `irontrellis-mcp-gateway ${version}\n`);
});

test("a case with more record files than one snapshot manifest can list is refused before anything is written (no partial directory)", async (t) => {
  const f = await fixture(t), directory = join(f.root, "too-large");
  // About 352 recorded calls (two files each) already outgrow the 128 KiB manifest; 800 files is well past it.
  for (let n = 0; n < 800; n += 1) writeFileSync(join(f.config.storage, `${n.toString(16).padStart(64, "0")}.report.json`), "{}", { mode: 0o600 });
  assert.throws(() => snapshotCase({ ...f.location, directory }), (e) => e.code === "SNAPSHOT_TOO_LARGE" && /800 record files/.test(e.detail ?? e.message));
  assert.equal(existsSync(directory), false, "no partial snapshot directory");
});
