// Windows readiness of the evidence bins (docs/PLATFORMS.md): the entry-point check that decides whether a compiled
// module runs its command line compares paths without case on win32, where npm's .cmd shim or a shell may spell the
// drive or a directory differently from the module URL; and the private configuration is not refused for its
// synthetic mode there.
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { isEntryPoint } from "../dist/entry.js";
import { privateFile } from "../dist/config.js";

async function asPlatform(value, fn) {
  const descriptor = Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { ...descriptor, value });
  try { return await fn(); } finally { Object.defineProperty(process, "platform", descriptor); }
}

test("isEntryPoint: the same file (through symlinks); case-insensitive on win32 only", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-evidence-platform-"));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 10 }));
  const file = join(dir, "server.js");
  writeFileSync(file, "");
  const url = pathToFileURL(file).href;
  assert.equal(isEntryPoint(url, file), true);
  assert.equal(isEntryPoint(url, join(dir, "client.js")), false);
  assert.equal(isEntryPoint(url, undefined), false);
  assert.equal(isEntryPoint(url, file.toUpperCase(), "linux"), false);
  assert.equal(isEntryPoint(url, file.toUpperCase(), "win32"), true);
});

test("the private configuration file: refused for group/other bits on POSIX, not on win32 (the ACL protects it)", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-evidence-platform-"));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 10 }));
  const file = join(dir, "gateway.json");
  writeFileSync(file, "{}");
  chmodSync(file, 0o644);
  if (process.platform !== "win32") assert.throws(() => privateFile(file, 1024), (e) => e.code === "CONFIG_UNAVAILABLE" && /owner-only/.test(e.detail));
  await asPlatform("win32", () => assert.equal(privateFile(file, 1024).toString(), "{}"));
});
