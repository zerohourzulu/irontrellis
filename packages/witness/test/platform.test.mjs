// Windows readiness of the witness (docs/PLATFORMS.md): the signals `serve` answers per platform, the portable
// admin-token reload that stands in for SIGHUP, the skipped directory fsync, the mode checks that do not apply to
// Windows's synthetic modes, and the named CRLF defect in log.jsonl. The win32 branches run with `process.platform`
// reporting "win32" (the file system stays POSIX).
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tempDir as makeTemp } from "./helpers.mjs";

const tempDir = (t) => { const { dir, cleanup } = makeTemp("irontrellis-witness-platform-"); t.after(cleanup); return dir; };

const cli = await import("../dist/cli.js");
const config = await import("../dist/config.js");
const log = await import("../dist/log.js");

async function asPlatform(value, fn) {
  const descriptor = Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { ...descriptor, value });
  try { return await fn(); } finally { Object.defineProperty(process, "platform", descriptor); }
}
const POSIX = process.platform !== "win32";
const collecting = () => {
  const lines = [];
  const at = (level) => (message, fields = {}) => lines.push({ level, message, ...fields });
  return { lines, logger: { info: at("info"), warn: at("warn"), error: at("error") } };
};
const until = async (predicate, ms = 5000) => {
  const deadline = Date.now() + ms;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error("timed out");
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
};

test("serve signals: SIGHUP reloads on POSIX; on Windows (no SIGHUP to send, no SIGTERM delivered) SIGINT, SIGBREAK and SIGHUP stop", () => {
  for (const os of ["linux", "darwin"]) assert.deepEqual({ ...cli.serveSignals(os) }, { SIGTERM: "stop", SIGINT: "stop", SIGHUP: "reload" });
  assert.deepEqual({ ...cli.serveSignals("win32") }, { SIGTERM: "stop", SIGINT: "stop", SIGBREAK: "stop", SIGHUP: "stop" });
  assert.equal(cli.defaultReloadIntervalMs("win32"), 5000);
  assert.equal(cli.defaultReloadIntervalMs("linux"), 0);
  assert.match(cli.HELP, /--reload-interval/);
});

test("watchAdminTokens: a changed config reloads the token hashes; a config that no longer loads keeps the previous ones", async (t) => {
  const dir = tempDir(t);
  const init = config.initDataDir(join(dir, "data"), "platform.witness");
  const loaded = config.loadConfig(init.configPath);
  const seen = [];
  const { lines, logger } = collecting();
  const stop = cli.watchAdminTokens({ setAdminTokenHashes: (hashes) => seen.push([...hashes]) }, init.configPath, 20, logger);
  t.after(stop);
  const hash = config.hashToken(config.newAdminToken());
  config.writePrivateFile(init.configPath, config.configText({ ...loaded, adminTokenHashes: [hash] }));
  await until(() => seen.length === 1);
  assert.deepEqual(seen[0], [hash]);
  assert.ok(lines.some((line) => line.message === "reloaded admin token hashes" && line.trigger === "config changed"));
  writeFileSync(init.configPath, "{ not json", { mode: 0o600 });
  await until(() => lines.some((line) => line.level === "error"));
  assert.equal(seen.length, 1, "an unreadable config is not applied");
  assert.match(lines.find((line) => line.level === "error").message, /keeping the previous tokens/);
});

test("serve --reload-interval takes 0 (off) or 1..86400 seconds; anything else is a usage error before the server starts", async (t) => {
  const dir = tempDir(t);
  let errors = "";
  const io = { out: () => {}, err: (text) => { errors += text; }, env: {}, isTTY: false };
  for (const bad of ["x", "-1", "86401", "1e3", ""]) assert.equal(await cli.main(["serve", "--data", dir, "--reload-interval", bad], io), 2, bad);
  // Review block 3, L4: 0.0001 rounded to setInterval(0), a busy loop. Below the minimum is refused (not clamped), clearly.
  assert.equal(cli.MIN_RELOAD_INTERVAL_SECONDS, 1);
  for (const small of ["0.0001", "0.0004", "0.05", "0.5", "0.999"]) {
    errors = "";
    assert.equal(await cli.main(["serve", "--data", dir, "--reload-interval", small], io), 2, small);
    assert.match(errors, new RegExp(`--reload-interval ${small.replace(".", "\\.")} is below the minimum of 1 second \\(0 turns the reload off\\)`), small);
  }
});

test("fsyncDir is skipped on win32 (a directory cannot be fsynced there); elsewhere a missing directory is an error", async (t) => {
  const missing = join(tempDir(t), "absent");
  if (POSIX) assert.throws(() => log.fsyncDir(missing), (e) => e.code === "ENOENT");
  await asPlatform("win32", () => log.fsyncDir(missing));
});

test("the witness key is not refused for its (synthetic) mode on win32; it is on POSIX", async (t) => {
  const dir = tempDir(t);
  const init = config.initDataDir(join(dir, "data"), "modes.witness");
  chmodSync(init.keyPath, 0o644);
  if (POSIX) assert.throws(() => config.loadWitnessKey(init.keyPath), /accessible by other users/);
  await asPlatform("win32", () => assert.equal(config.loadWitnessKey(init.keyPath).name, "modes.witness"));
});

test("log.jsonl with CRLF line endings is refused, and the message says why", () => {
  const good = '{"entry":{},"index":0}';
  assert.throws(() => log.parseLogLine({ text: `${good}\r`, offset: 0, length: good.length + 2, lineNumber: 1 }),
    (e) => e instanceof log.DataError && /carriage return/.test(e.message) && /LF line endings/.test(e.message));
  assert.throws(() => log.parseLogLine({ text: '{"index":0,"entry":{}}', offset: 0, length: 23, lineNumber: 1 }),
    (e) => e instanceof log.DataError && /not in canonical form$/.test(e.message));
});
