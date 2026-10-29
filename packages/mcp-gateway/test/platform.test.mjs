// Windows readiness of the gateway (docs/PLATFORMS.md): upstream commands must be drive-qualified and cannot be .cmd or
// .bat files (Windows runs those only through a shell, which the gateway never uses); private-file mode checks do not
// apply to Windows's synthetic modes; the directory fsync of a durable create is skipped there. The win32 branches run
// with `process.platform` reporting "win32" (the file system stays POSIX).
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { captureUpstream } from "../dist/upstream.js";
import { durableCreate, isPrivateMode, readPrivate, syncDirectory } from "../dist/data.js";
import { snapshotCase } from "../dist/operations.js";
import { setup } from "./fixtures.mjs";

async function asPlatform(value, fn) {
  const descriptor = Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { ...descriptor, value });
  try { return await fn(); } finally { Object.defineProperty(process, "platform", descriptor); }
}
const workspace = (t) => { const dir = mkdtempSync(join(tmpdir(), "irontrellis-gateway-platform-")); t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 10 })); return dir; };

test("upstream command on win32: drive-qualified, and never a .cmd/.bat (no shell)", async () => {
  const upstream = (command, cwd) => captureUpstream({ id: "u", command, args: ["server.js"], ...(cwd === undefined ? {} : { cwd }) });
  if (process.platform !== "win32") assert.equal(upstream("/usr/bin/node").command, "/usr/bin/node");
  await asPlatform("win32", () => {
    assert.equal(upstream("C:\\Program Files\\nodejs\\node.exe", "D:\\work").command, "C:\\Program Files\\nodejs\\node.exe");
    for (const command of ["C:\\Users\\me\\AppData\\Roaming\\npm\\npx.cmd", "C:\\tools\\server.BAT"]) {
      assert.throws(() => upstream(command), (e) => e.code === "INVALID_INPUT" && /only through a shell/.test(e.detail), command);
    }
    assert.throws(() => upstream("\\tools\\node.exe"), (e) => e.code === "INVALID_INPUT" && /absolute path/.test(e.detail));
    assert.throws(() => upstream("C:\\tools\\node.exe", "\\work"), (e) => e.code === "INVALID_INPUT" && /"cwd" must be an absolute path/.test(e.detail));
  });
});

test("private files on win32: the synthetic mode is not held against them; a durable create skips the directory fsync", async (t) => {
  if (process.platform !== "win32") assert.equal(isPrivateMode(0o100644), false);
  assert.equal(isPrivateMode(0o100600), true);
  const dir = workspace(t);
  const file = join(dir, "record.json");
  writeFileSync(file, JSON.stringify({ a: 1 }), { mode: 0o644 });
  chmodSync(file, 0o644);
  if (process.platform !== "win32") assert.throws(() => readPrivate(file), (e) => e.code === "STORAGE_UNAVAILABLE" && /owner-only/.test(e.detail));
  await asPlatform("win32", () => {
    assert.equal(isPrivateMode(0o100666), true);
    assert.deepEqual(readPrivate(file), { a: 1 });
    syncDirectory(join(dir, "absent"));
    durableCreate(join(dir, "created.json"), { b: 2 });
  });
  assert.deepEqual(readPrivate(join(dir, "created.json")), { b: 2 });
  if (process.platform !== "win32") assert.throws(() => syncDirectory(join(dir, "absent")), (e) => e.code === "ENOENT");
});

test("a snapshot directory inside the case's storage is refused, whatever the separator (path.relative, not a \"/\" prefix)", async (t) => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "irontrellis-gateway-platform-")));
  t.after(() => rmSync(root, { recursive: true, force: true, maxRetries: 10 }));
  const f = await setup(join(root, "case"));
  const location = { historyFile: f.local.historyFile, storage: f.config.storage };
  for (const directory of [f.config.storage, join(f.config.storage, "snapshot"), join(f.config.storage, "..snapshot")]) {
    assert.throws(() => snapshotCase({ ...location, directory }), (e) => e.code === "SNAPSHOT_TARGET_INVALID" || e.code === "STORAGE_UNAVAILABLE", directory);
  }
  assert.throws(() => snapshotCase({ ...location, directory: join(f.config.storage, "..snapshot") }), (e) => e.code === "SNAPSHOT_TARGET_INVALID");
});
