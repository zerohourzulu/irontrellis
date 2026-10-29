// Windows readiness (docs/PLATFORMS.md): the portable file-system helpers of src/platform.ts with the win32 branches
// driven through their `platform` option, and the engine paths that use them run with `process.platform` set to
// "win32" (the fs calls stay POSIX: this checks the branches, not NTFS). Also the line-ending rules of the store:
// a history converted to CRLF replays to the same state (the record hash covers the canonical encoding, not the
// bytes), a byte order mark is refused and named.
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const platform = await import("../src/platform.ts");
const { openHistoryStore } = await import("../src/store.ts");
const { createLocalDomain, createLocalOwner, openLocalOwner } = await import("../src/index.ts");
const { minimumWitnessPolicy, WITNESS_POLICY_ENV } = await import("../src/witness-state.ts");
const { createOwnerKeyFile, loadOwnerKeyFile } = await import("../src/signer.ts");

const workspace = (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-platform-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
};
/** Assertions about the host's own POSIX behaviour (the win32 branches are driven explicitly either way). */
const POSIX = process.platform !== "win32";
const errno = (code) => Object.assign(new Error(`${code}: simulated`), { code });

/** Runs `fn` with `process.platform` reporting `value` (restored afterwards, also when `fn` rejects). */
async function asPlatform(value, fn) {
  const descriptor = Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { ...descriptor, value });
  try {
    return await fn();
  } finally {
    Object.defineProperty(process, "platform", descriptor);
  }
}

// ---------------------------------------------------------------- replaceFileSync

test("replaceFileSync on win32: EPERM, EACCES and EBUSY are retried with a growing pause until the rename succeeds", () => {
  for (const code of ["EPERM", "EACCES", "EBUSY"]) {
    let calls = 0;
    const pauses = [];
    const attempts = platform.replaceFileSync("a", "b", {
      platform: "win32", sleep: (ms) => pauses.push(ms),
      rename: () => { calls += 1; if (calls < 4) throw errno(code); },
    });
    assert.equal(attempts, 4);
    assert.deepEqual(pauses, [5, 10, 20]);
  }
});

test("replaceFileSync on win32: the retries stop at the time budget and the last error is thrown", () => {
  const pauses = [];
  assert.throws(() => platform.replaceFileSync("a", "b", {
    platform: "win32", budgetMs: 100, sleep: (ms) => pauses.push(ms), rename: () => { throw errno("EBUSY"); },
  }), (e) => e.code === "EBUSY");
  assert.equal(pauses.reduce((a, b) => a + b, 0), 100, `paused ${pauses.join("+")}`);
  assert.deepEqual(pauses, [5, 10, 20, 40, 25]);
  // The default budget is bounded (seconds, not graceful-fs's minute).
  assert.equal(platform.REPLACE_RETRY_BUDGET_MS, 3000);
});

test("replaceFileSync: a non-transient error on win32, and every error elsewhere, is thrown at once", () => {
  for (const [os, code] of [["win32", "ENOENT"], ["win32", "EXDEV"], ["linux", "EPERM"], ["linux", "EACCES"], ["darwin", "EBUSY"]]) {
    let calls = 0;
    assert.throws(() => platform.replaceFileSync("a", "b", {
      platform: os, sleep: () => assert.fail("no pause"), rename: () => { calls += 1; throw errno(code); },
    }), (e) => e.code === code);
    assert.equal(calls, 1, `${os} ${code}`);
  }
});

test("replaceFileSync replaces an existing file (a real rename)", (t) => {
  const dir = workspace(t);
  writeFileSync(join(dir, "target"), "old");
  writeFileSync(join(dir, "temp"), "new");
  assert.equal(platform.replaceFileSync(join(dir, "temp"), join(dir, "target")), 1);
  assert.equal(readFileSync(join(dir, "target"), "utf8"), "new");
  assert.equal(existsSync(join(dir, "temp")), false);
});

test("isWindowsTransientError: only EPERM, EACCES and EBUSY, and only on win32", () => {
  for (const code of platform.WINDOWS_TRANSIENT_ERROR_CODES) {
    assert.equal(platform.isWindowsTransientError(errno(code), { platform: "win32" }), true);
    assert.equal(platform.isWindowsTransientError(errno(code), { platform: "linux" }), false);
  }
  assert.equal(platform.isWindowsTransientError(errno("EEXIST"), { platform: "win32" }), false);
  assert.equal(platform.isWindowsTransientError(new Error("no code"), { platform: "win32" }), false);
  assert.equal(platform.isWindowsTransientError(null, { platform: "win32" }), false);
});

// ---------------------------------------------------------------- syncDirectorySync

test("syncDirectorySync: skipped on win32 (never opens the directory); strict elsewhere unless best effort", (t) => {
  const dir = workspace(t);
  const missing = join(dir, "absent");
  assert.equal(platform.syncDirectorySync(missing, { platform: "win32" }), false, "win32 does not even look");
  assert.throws(() => platform.syncDirectorySync(missing, { platform: "linux" }), (e) => e.code === "ENOENT");
  assert.equal(platform.syncDirectorySync(missing, { platform: "linux", bestEffort: true }), false);
  assert.equal(platform.syncDirectorySync(dir, { platform: "linux" }), true);
});

// ---------------------------------------------------------------- modes and paths

test("ownerOnlyModeEnforced: false on win32 only", () => {
  assert.equal(platform.ownerOnlyModeEnforced({ platform: "win32" }), false);
  for (const os of ["linux", "darwin", "freebsd"]) assert.equal(platform.ownerOnlyModeEnforced({ platform: os }), true);
});

test("isFullyQualifiedPath: a drive letter or UNC prefix on win32; path.posix.isAbsolute elsewhere", () => {
  const win = (p) => platform.isFullyQualifiedPath(p, { platform: "win32" });
  for (const p of ["C:\\policy.json", "c:/policy.json", "D:\\a\\b", "\\\\server\\share\\p.json", "//server/share/p.json", "\\\\?\\C:\\p.json"]) assert.equal(win(p), true, p);
  for (const p of ["\\policy.json", "/policy.json", "C:policy.json", "policy.json", ".\\p.json", "..\\p.json", "", "\\\\"]) assert.equal(win(p), false, p);
  const posix = (p) => platform.isFullyQualifiedPath(p, { platform: "linux" });
  for (const p of ["/etc/irontrellis-witness-policy.json", "/"]) assert.equal(posix(p), true, p);
  for (const p of ["relative/p.json", "C:\\p.json", ""]) assert.equal(posix(p), false, p);
});

// ---------------------------------------------------------------- the engine under win32

test("win32: the minimum witness policy file needs a drive-letter or UNC path (a rooted \\x depends on the current drive)", async (t) => {
  const dir = workspace(t);
  const file = join(dir, "irontrellis-witness-policy.json");
  writeFileSync(file, JSON.stringify({ witnesses: [], quorum: 0 }), { mode: 0o666 });
  chmodSync(file, 0o666);
  if (POSIX) assert.throws(() => minimumWitnessPolicy({ [WITNESS_POLICY_ENV]: file }), (e) => e.code === "WITNESS_UNREADABLE" && /writable by group or others/.test(e.message));
  // (The mode check itself is `ownerOnlyModeEnforced()`, false on win32 above; a POSIX temporary path cannot pass the
  // win32 path check, so the two are not combined here.)
  await asPlatform("win32", () => {
    for (const path of ["\\irontrellis-witness-policy.json", "/etc/irontrellis-witness-policy.json", "C:irontrellis-witness-policy.json", "policy.json"]) {
      assert.throws(() => minimumWitnessPolicy({ [WITNESS_POLICY_ENV]: path }),
        (e) => e.code === "WITNESS_UNREADABLE" && /drive letter or a UNC prefix/.test(e.message), path);
    }
    // A fully qualified path passes the path check (and then fails to be read here, on a POSIX host).
    assert.throws(() => minimumWitnessPolicy({ [WITNESS_POLICY_ENV]: "C:\\ProgramData\\IronTrellis\\irontrellis-witness-policy.json" }),
      (e) => e.code === "WITNESS_UNREADABLE" && /cannot be read/.test(e.message));
  });
});

test("win32: an owner key file is not refused for its (synthetic) mode", async (t) => {
  const dir = workspace(t);
  const path = join(dir, "h.jsonl.owner-key.json");
  createOwnerKeyFile(path);
  chmodSync(path, 0o666);
  if (POSIX) assert.throws(() => loadOwnerKeyFile(path), (e) => e.code === "KEY_UNAVAILABLE");
  await asPlatform("win32", () => assert.equal(loadOwnerKeyFile(path).keyId, "owner:1"));
});

test("win32: a history is created, written, pinned and reopened without a directory fsync (the pin by replaceFileSync)", async (t) => {
  const dir = workspace(t);
  const historyFile = join(dir, "history.jsonl");
  await asPlatform("win32", async () => {
    const domain = createLocalDomain();
    const owner = await createLocalOwner({ historyFile, domain, owner: "operations", controller: "operator", now: () => 1_000 });
    await owner.createAgent({ id: "agent:win" });
    const head = owner.handover("agent:win").head;
    owner.close?.();
    const again = openLocalOwner({ historyFile, domain, owner: "operations", controller: "operator", now: () => 2_000 });
    await again.createAgent({ id: "agent:win2" });
    assert.equal(again.handover("agent:win2").head.position, head.position + 1);
    again.close?.();
  });
  const store = openHistoryStore(historyFile);
  assert.equal(store.verify().chain, "OK");
  assert.equal(store.verify().pinnedHeadStatus, "MATCHES");
});

// ---------------------------------------------------------------- line endings

test("a history converted to CRLF line endings replays to the same state; a byte order mark is refused and named", async (t) => {
  const dir = workspace(t);
  const historyFile = join(dir, "history.jsonl");
  const domain = createLocalDomain();
  const owner = await createLocalOwner({ historyFile, domain, owner: "operations", controller: "operator", now: () => 1_000 });
  await owner.createAgent({ id: "agent:é" });
  owner.close?.();
  const lf = readFileSync(historyFile);
  const expected = openHistoryStore(historyFile).state();

  // What an editor or git's autocrlf does: a CR before every LF. JSON whitespace outside the record, which the record
  // hash (over the canonical encoding) does not cover: the same events, the same heads, the same pin.
  const crlf = Buffer.from(lf.toString("utf8").replace(/\n/g, "\r\n"));
  writeFileSync(historyFile, crlf);
  const store = openHistoryStore(historyFile);
  assert.equal(store.state().head.hash, expected.head.hash);
  assert.deepEqual(store.state().eventHistoryHashes, expected.eventHistoryHashes);
  assert.equal(store.verify().chain, "OK");
  assert.equal(store.verify().pinnedHeadStatus, "MATCHES");

  // Anything that changes a value is still caught: a CR inside a string is a different event.
  writeFileSync(historyFile, Buffer.from(lf.toString("utf8").replace('"agent:é"', '"agent:é\\r"')));
  assert.throws(() => openHistoryStore(historyFile).state(), (e) => e.code === "INVALID_HISTORY" || /integrity/.test(e.message));

  // A UTF-8 byte order mark (Notepad before Windows 10 1903 added one) is refused, with a message that says so.
  writeFileSync(historyFile, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), lf]));
  assert.throws(() => openHistoryStore(historyFile).state(), (e) => /byte order mark/.test(e.message));
});
