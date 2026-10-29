// The irontrellis-witness command, spawned as users run it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { BIN, buildHistory, t, tempDir, witnessLib } from "./helpers.mjs";

const run = (args, options = {}) => spawnSync(process.execPath, [BIN, ...args], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1", ...options.env } });

test("--version, --help, usage errors", () => {
  const version = run(["--version"]);
  assert.equal(version.status, 0);
  assert.equal(version.stdout.trim(), JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version);
  assert.deepEqual(JSON.parse(run(["--version", "--json"]).stdout), { name: "irontrellis-witness", version: version.stdout.trim() });
  const help = run(["--help"]);
  assert.equal(help.status, 0);
  for (const command of ["init", "serve", "token create", "verifier-key", "check-log", "--json"]) assert.ok(help.stdout.includes(command), command);
  assert.equal(run([]).status, 2);
  const unknown = run(["frobnicate"]);
  assert.equal(unknown.status, 2);
  assert.match(unknown.stderr, /unknown command/);
  assert.equal(run(["init", "--bogus"]).status, 2);
  assert.equal(run(["init", "--name", "x"]).status, 2, "--data is required");
  assert.equal(run(["token", "delete", "--data", "/tmp/x"]).status, 2);
  const json = run(["verifier-key", "--data", "/nonexistent/dir", "--json"]);
  assert.equal(json.status, 1);
  assert.equal(JSON.parse(json.stdout).error.code, "CONFIG");
});

test("init, verifier-key, token create, check-log", () => {
  const { dir, cleanup } = tempDir();
  try {
    const data = join(dir, "data");
    const init = run(["init", "--data", data, "--name", "cli.witness", "--json"]);
    assert.equal(init.status, 0, init.stderr);
    const result = JSON.parse(init.stdout);
    assert.equal(result.origin, "irontrellis-witness/cli.witness");
    assert.doesNotThrow(() => t.parseVerifierKey(result.verifierKey));
    if (process.platform !== "win32") assert.equal(statSync(data).mode & 0o777, 0o700); // POSIX modes (Windows: ACLs, docs/PLATFORMS.md §3)
    if (process.platform !== "win32") assert.equal(statSync(join(data, "witness-key.json")).mode & 0o777, 0o600); // POSIX modes (Windows: ACLs, docs/PLATFORMS.md §3)
    if (process.platform !== "win32") assert.equal(statSync(join(data, "config.json")).mode & 0o777, 0o600); // POSIX modes (Windows: ACLs, docs/PLATFORMS.md §3)
    const keyFile = JSON.parse(readFileSync(join(data, "witness-key.json"), "utf8"));
    assert.equal(keyFile.version, "irontrellis-witness-key/1");
    assert.match(keyFile.privateKey, /^PRIVATE\+KEY\+cli\.witness\+/);
    assert.equal(run(["init", "--data", data, "--name", "cli.witness"]).status, 1, "refuses an initialized directory");
    assert.equal(run(["init", "--data", join(dir, "bad"), "--name", "has space"]).status, 1);
    const custom = JSON.parse(run(["init", "--data", join(dir, "custom"), "--name", "c", "--origin", "example.com/log", "--json"]).stdout);
    assert.equal(custom.origin, "example.com/log");

    const human = run(["init", "--data", join(dir, "human"), "--name", "h"]);
    assert.match(human.stdout, /◆ irontrellis-witness/);
    assert.match(human.stdout, /Verifier key/);

    assert.equal(run(["verifier-key", "--data", data]).stdout.trim(), result.verifierKey);
    assert.equal(JSON.parse(run(["verifier-key", "--data", data, "--json"]).stdout).verifierKey, result.verifierKey);

    const token = JSON.parse(run(["token", "create", "--data", data, "--json"]).stdout);
    assert.match(token.token, /^itw_[A-Za-z0-9_-]{43}$/);
    const config = JSON.parse(readFileSync(join(data, "config.json"), "utf8"));
    assert.deepEqual(config.adminTokenHashes, [witnessLib.hashToken(token.token)]);
    if (process.platform !== "win32") assert.equal(statSync(join(data, "config.json")).mode & 0o777, 0o600); // POSIX modes (Windows: ACLs, docs/PLATFORMS.md §3)
    const second = run(["token", "create", "--data", data]);
    assert.equal(second.status, 0);
    assert.match(second.stdout, /shown once/);
    assert.equal(JSON.parse(readFileSync(join(data, "config.json"), "utf8")).adminTokenHashes.length, 2);

    const check = run(["check-log", "--data", data]);
    assert.equal(check.status, 0);
    assert.match(check.stdout, /Log VALID/);
    const checkJson = JSON.parse(run(["check-log", "--data", data, "--json"]).stdout);
    assert.equal(checkJson.status, "VALID");
    assert.equal(checkJson.entries, 0);
    // An auditor with only the verifier key and origin.
    assert.equal(run(["check-log", "--data", data, "--verifier-key", result.verifierKey, "--origin", result.origin]).status, 0);
    assert.equal(run(["check-log", "--data", data, "--verifier-key", result.verifierKey]).status, 2);

    // A group-readable key is refused (POSIX; Windows modes are synthetic, the ACL protects the key: docs/PLATFORMS.md §3).
    if (process.platform !== "win32") {
      chmodSync(join(data, "witness-key.json"), 0o644);
      const loose = run(["verifier-key", "--data", data]);
      assert.equal(loose.status, 1);
      assert.match(loose.stderr, /chmod 600/);
      chmodSync(join(data, "witness-key.json"), 0o600);
    }

    // A config with an unknown key is refused (a typo must not weaken a limit).
    writeFileSync(join(data, "config.json"), JSON.stringify({ ...config, rateLimits: {} }), { mode: 0o600 });
    const typo = run(["token", "create", "--data", data]);
    assert.equal(typo.status, 1);
    assert.match(typo.stderr, /unknown config key "rateLimits"/);
  } finally {
    cleanup();
  }
});

// Windows cannot deliver SIGHUP or a catchable SIGTERM to another process: there the tokens are reloaded by
// --reload-interval, and a SIGTERM is TerminateProcess, so the lock stays behind and the next start reclaims it.
const WINDOWS = process.platform === "win32";
test("serve: listens, SIGHUP (or --reload-interval) reloads admin tokens, SIGTERM shuts down gracefully and releases the lock", { timeout: 60_000 }, async (context) => {
  const { dir, cleanup } = tempDir();
  try {
    assert.equal(run(["init", "--data", dir, "--name", "serve.witness"]).status, 0);
    const child = spawn(process.execPath, [BIN, "serve", "--data", dir, "--listen", "127.0.0.1:0", ...(WINDOWS ? ["--reload-interval", "1"] : [])], { stdio: ["ignore", "pipe", "pipe"] });
    // A failed assertion must not leave the server running (the test file would never exit).
    context.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL"); });
    const logs = [];
    const url = await new Promise((resolve, reject) => {
      let buffer = "";
      child.stderr.on("data", (chunk) => {
        buffer += chunk;
        let newline;
        while ((newline = buffer.indexOf("\n")) >= 0) {
          const line = JSON.parse(buffer.slice(0, newline));
          buffer = buffer.slice(newline + 1);
          logs.push(line);
          if (line.msg === "listening") resolve(line.url);
        }
      });
      child.on("exit", () => reject(new Error("exited")));
    });
    assert.ok(logs.some((line) => line.level === "warn" && /no.*token|none is configured/.test(line.msg)), "warns that registration has no token");
    assert.ok(existsSync(join(dir, "server.lock")));
    const second = run(["serve", "--data", dir, "--listen", "127.0.0.1:0"]);
    assert.equal(second.status, 1);
    assert.match(second.stderr, /holds the lock/);

    const h = await buildHistory({ name: "serve" });
    const register = (token) => fetch(`${url}/v1/histories`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify({ genesis: h.genesis }) });
    const token = JSON.parse(run(["token", "create", "--data", dir, "--json"]).stdout).token;
    if (!WINDOWS) assert.equal((await register(token)).status, 401, "not loaded yet");
    if (!WINDOWS) child.kill("SIGHUP");
    for (let i = 0; i < (WINDOWS ? 200 : 50) && !logs.some((line) => /reloaded/.test(line.msg)); i += 1) await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal((await register(token)).status, 201);

    const exited = new Promise((resolve) => child.on("exit", (code, signal) => resolve({ code, signal })));
    child.kill("SIGTERM");
    if (WINDOWS) {
      assert.deepEqual(await exited, { code: null, signal: "SIGTERM" });
      assert.equal(existsSync(join(dir, "server.lock")), true, "a terminated server leaves its lock");
    } else {
      assert.deepEqual(await exited, { code: 0, signal: null });
      assert.equal(existsSync(join(dir, "server.lock")), false);
    }
    assert.equal(JSON.parse(run(["check-log", "--data", dir, "--json"]).stdout).entries, 1);
  } finally {
    cleanup();
  }
});
