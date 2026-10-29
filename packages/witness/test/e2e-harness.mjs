// End-to-end harness (not a test file): the REAL `irontrellis-witness` server as a child process (init, token create,
// serve on an ephemeral port), a programmable HTTP proxy in front of it (the attacker-controlled network, a witness
// that goes down and comes back behind a stable URL, a switch between two witness instances), and runners for the
// real `irontrellis` CLI and `irontrellis-hook` binaries. Every child and server is tracked and killed by `cleanup()`.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createServer, request as httpRequest } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { BIN, core, packageRoot, t } from "./helpers.mjs";
import { FORMAT1_TEST_TOOLING } from "@ramex-labs/irontrellis/internal-format1"; // A-206.1: the dist copy's mark, as `core`

export { core, t, BIN };
export const CLI_BIN = resolve(packageRoot, "../cli/bin/irontrellis.mjs");
export const HOOK_BIN = resolve(packageRoot, "../hooks/bin/irontrellis-hook.mjs");
export const PYTHON_SRC = resolve(packageRoot, "../../python/src");
for (const bin of [CLI_BIN, HOOK_BIN]) assert.ok(existsSync(bin), `missing ${bin}`);
assert.ok(existsSync(resolve(packageRoot, "../cli/dist/cli.js")) && existsSync(resolve(packageRoot, "../hooks/dist/cli.js")), "build first: pnpm -r build");

/**
 * The process-wide view cache of the core witness session (what "this process" learned from the witnesses). The test
 * process plays several owner processes; `freshProcess()` forgets that view, as a new process would. Imported by file
 * URL from the same dist module the package root uses, so it is the same module instance.
 */
const session = await import(pathToFileURL(resolve(packageRoot, "../core/dist/witness-session.js")).href);
export const freshProcess = () => session.resetWitnessViews();

// ---------------------------------------------------------------- scratch space and cleanup

/** Per-test scratch space; `cleanup()` kills every child and server started through it, then removes the directory. */
export function scratch(prefix = "itw-e2e-") {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), prefix)));
  const closers = [];
  return {
    dir,
    path: (...parts) => join(dir, ...parts),
    defer: (close) => { closers.push(close); },
    async cleanup() {
      for (const close of closers.reverse()) {
        try { await close(); } catch { /* best effort */ }
      }
      rmSync(dir, { recursive: true, force: true, maxRetries: 10 });
    },
  };
}

/** Polls `predicate` (sync or async) every 10 ms until it is truthy; fails after `timeoutMs`. */
export async function waitFor(predicate, { timeoutMs = 10_000, what = "condition" } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await predicate();
    if (value) return value;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((done) => setTimeout(done, 10));
  }
}

// ---------------------------------------------------------------- the real witness server

const witnessCli = (args) => {
  const result = spawnSync(process.execPath, [BIN, ...args], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } });
  return { code: result.status, stdout: result.stdout, stderr: result.stderr, json: (() => { try { return JSON.parse(result.stdout); } catch { return undefined; } })() };
};

/** `irontrellis-witness check-log --data <dir> --json` (offline audit; the server may be running). */
export function checkLog(dataDir) {
  const result = witnessCli(["check-log", "--data", dataDir, "--json"]);
  assert.ok(result.json !== undefined, `check-log printed no JSON: ${result.stdout}\n${result.stderr}`);
  return { ...result.json, exitCode: result.code };
}

/**
 * A real witness server: `init` (unless `keyFrom` names another data dir whose key file is copied in: a second
 * instance with the same key and another log), `token create`, then `serve` on 127.0.0.1:0 as a child process.
 */
export async function startWitnessServer(space, { name = "e2e.witness", sub = `witness-${name}`, keyFrom, config = {} } = {}) {
  const dataDir = space.path(sub);
  const init = witnessCli(["init", "--data", dataDir, "--name", name, "--json"]);
  assert.equal(init.code, 0, init.stdout + init.stderr);
  if (keyFrom !== undefined) writeFileSync(join(dataDir, "witness-key.json"), readFileSync(join(keyFrom, "witness-key.json")), { mode: 0o600 });
  const token = witnessCli(["token", "create", "--data", dataDir, "--json"]);
  assert.equal(token.code, 0, token.stdout + token.stderr);
  if (Object.keys(config).length > 0) {
    const path = join(dataDir, "config.json");
    writeFileSync(path, JSON.stringify({ ...JSON.parse(readFileSync(path, "utf8")), ...config }), { mode: 0o600 });
  }
  const verifierKey = witnessCli(["verifier-key", "--data", dataDir]).stdout.trim();
  const server = { dataDir, name, verifierKey, token: token.json.token, origin: `irontrellis-witness/${name}`, child: undefined, url: undefined, logs: [], exited: undefined, starts: 0 };

  server.start = async () => {
    const child = spawn(process.execPath, [BIN, "serve", "--data", dataDir, "--listen", "127.0.0.1:0"], { stdio: ["ignore", "ignore", "pipe"], env: { ...process.env, NO_COLOR: "1" } });
    server.child = child;
    server.starts += 1;
    server.exited = new Promise((done) => child.on("exit", (code, signal) => done({ code, signal })));
    server.url = await new Promise((done, fail) => {
      let buffer = "";
      child.stderr.on("data", (chunk) => {
        buffer += chunk;
        let newline;
        while ((newline = buffer.indexOf("\n")) >= 0) {
          const line = buffer.slice(0, newline);
          buffer = buffer.slice(newline + 1);
          let parsed;
          try { parsed = JSON.parse(line); } catch { parsed = { raw: line }; }
          server.logs.push(parsed);
          if (parsed.msg === "listening") done(parsed.url);
        }
      });
      child.on("exit", (code, signal) => fail(new Error(`witness server exited early (${code ?? signal}): ${JSON.stringify(server.logs.slice(-3))}`)));
    });
    return server.url;
  };
  /** Stops the server (SIGTERM: graceful; SIGKILL: crash) and waits for the process to end. */
  server.stop = async (signal = "SIGTERM") => {
    const child = server.child;
    if (child === undefined || child.exitCode !== null || child.signalCode !== null) return server.exited;
    child.kill(signal);
    const exit = await server.exited;
    server.child = undefined;
    return exit;
  };
  space.defer(() => server.stop("SIGKILL"));
  await server.start();
  return server;
}

// ---------------------------------------------------------------- witness HTTP reads (straight to the server)

export async function http(base, method, path, body, headers = {}) {
  const init = { method, headers: { ...headers } };
  if (body !== undefined) { init.body = typeof body === "string" ? body : JSON.stringify(body); init.headers["content-type"] ??= "application/json"; }
  const response = await fetch(`${base}${path}`, init);
  const text = await response.text();
  let json;
  try { json = JSON.parse(text); } catch { json = undefined; }
  return { status: response.status, text, json };
}

/** The witness's current checkpoint, verified with its key: `{ size, root }`. */
export async function checkpointOf(server) {
  const note = (await http(server.url, "GET", "/v1/checkpoint")).text;
  const parsed = t.parseCheckpoint(t.openNote(note, [server.verifierKey]).body);
  return { size: parsed.size, rootB64: t.encodeBase64(parsed.root), note };
}

/** Every leaf of the witness log (paged). */
export async function entriesOf(server) {
  const { size } = await checkpointOf(server);
  const all = [];
  for (let start = 0; start < size; start += 1000) all.push(...(await http(server.url, "GET", `/v1/entries?start=${start}&end=${Math.min(size, start + 1000)}`)).json.entries);
  return all;
}

/** The leaves of one history, summarised: `HEAD <position> <keyId>`, `ROTATED <previous>-><rotationHead>`, `EQUIVOCATION <position>`, `REGISTERED`. */
export async function historyLog(server, historyId) {
  return (await entriesOf(server)).filter((entry) => entry.historyId === historyId).map((entry) => {
    switch (entry.kind) {
      case "HEAD": return `HEAD ${entry.signedStatement.statement.head.position} ${entry.signedStatement.keyId}`;
      case "ROTATED": return `ROTATED ${entry.previousHead.position}->${entry.rotationHead.position}`;
      case "EQUIVOCATION": return `EQUIVOCATION ${entry.first.statement.head.position}`;
      default: return entry.kind;
    }
  });
}

/** `GET /v1/histories/:id` straight from the server (`undefined` when 404). */
export async function witnessHistory(server, historyId) {
  const reply = await http(server.url, "GET", `/v1/histories/${historyId}`);
  if (reply.status === 404) return undefined;
  assert.equal(reply.status, 200, reply.text);
  return reply.json;
}
export const witnessLatest = async (server, historyId) => (await witnessHistory(server, historyId))?.latest?.head ?? null;

// ---------------------------------------------------------------- the attacker-controlled network: a proxy

/**
 * An HTTP proxy on 127.0.0.1:0 in front of `target` (a server object or a URL; switchable). Controls:
 *  - `down = true`: every connection is reset (a witness that is down, behind a stable URL);
 *  - `before(request)`: awaited before forwarding (pause a POST, run something in between); may return a
 *    `{ status, body, headers? }` to answer without forwarding;
 *  - `transform(request, response)`: may return a replacement `{ status?, body }` for the response;
 *  - `log`: every request as `METHOD path` (without the query).
 * `request` = `{ method, path, query, url, body }` (`path` without the query, `query` its URLSearchParams, `url` as
 * sent, body text); `response` = `{ status, body, headers }`.
 */
export async function startProxy(space, target) {
  const proxy = { target, down: false, before: undefined, transform: undefined, log: [], url: undefined };
  const targetUrl = () => (typeof proxy.target === "string" ? proxy.target : proxy.target?.url);
  const forward = (base, method, path, headers, body) => new Promise((done, fail) => {
    const url = new URL(path, base);
    const outgoing = httpRequest(url, { method, headers: { ...headers, host: url.host } }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => done({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks).toString("utf8") }));
      response.on("error", fail);
    });
    outgoing.on("error", fail);
    outgoing.end(body);
  });
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", async () => {
      // `path` without the query (answers about a history carry `?nonce=`, docs/reference/witness-protocol.md §9.8); `url` as sent.
      const parsed = new URL(req.url, "http://proxy.invalid");
      const request = { method: req.method, path: parsed.pathname, query: parsed.searchParams, url: req.url, body: Buffer.concat(chunks).toString("utf8") };
      proxy.log.push(`${req.method} ${parsed.pathname}`);
      const reset = () => { req.socket.destroy(); };
      try {
        if (proxy.down) return reset();
        const early = await proxy.before?.(request);
        if (proxy.down) return reset();
        let response = early;
        if (response === undefined) {
          const base = targetUrl();
          if (base === undefined) return reset();
          const headers = { ...req.headers };
          delete headers.host;
          delete headers.connection;
          delete headers["content-length"];
          if (request.body !== "") headers["content-length"] = String(Buffer.byteLength(request.body));
          response = await forward(base, req.method, req.url, headers, request.body === "" ? undefined : request.body);
          const replaced = await proxy.transform?.(request, response);
          if (replaced !== undefined) response = { ...response, ...replaced };
        }
        const body = typeof response.body === "string" ? response.body : JSON.stringify(response.body);
        const contentType = response.headers?.["content-type"] ?? "application/json";
        res.writeHead(response.status ?? 200, { "content-type": contentType, "content-length": Buffer.byteLength(body) });
        res.end(body);
      } catch {
        reset();
      }
    });
  });
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  proxy.url = `http://127.0.0.1:${server.address().port}`;
  proxy.close = () => new Promise((done) => { server.closeAllConnections?.(); server.close(() => done()); });
  space.defer(() => proxy.close());
  return proxy;
}

/**
 * A gate for the proxy's `before`: `gate.hold(match)` makes the first request matching `match` wait until
 * `gate.release()`; `await gate.reached` resolves when it arrived.
 */
export function gate() {
  let reach, release;
  const g = { armed: false, reached: new Promise((done) => { reach = done; }), released: new Promise((done) => { release = done; }) };
  g.hold = (match) => {
    g.armed = true;
    return async (request) => {
      if (!g.armed || !match(request)) return undefined;
      g.armed = false;
      reach(request);
      await g.released;
      return undefined;
    };
  };
  g.release = () => release();
  return g;
}

// ---------------------------------------------------------------- the real CLI and hook binaries

function runChild(bin, args, { env = {}, cwd, stdin } = {}) {
  return new Promise((done) => {
    const child = spawn(process.execPath, [bin, ...args], { cwd, env: { ...process.env, NO_COLOR: "1", ...env } });
    let stdout = "", stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("close", (code) => {
      let json;
      try { json = stdout.trim() === "" ? undefined : JSON.parse(stdout); } catch { json = undefined; }
      done({ code, stdout, stderr, json });
    });
    child.stdin.end(stdin ?? "");
  });
}

/** The `irontrellis` CLI on one history (`--json` is added when `json: true`). */
export function cliFor(historyFile, extraEnv = {}) {
  const env = { IRONTRELLIS_HISTORY: historyFile, ...extraEnv };
  const run = (args, options = {}) => runChild(CLI_BIN, [...args, ...(options.json ? ["--json"] : [])], { env });
  run.ok = async (args, options = {}) => {
    const result = await run(args, options);
    assert.equal(result.code, 0, `irontrellis ${args.join(" ")} exited ${result.code}\n${result.stdout}\n${result.stderr}`);
    return result;
  };
  return run;
}

/** `irontrellis-hook <args>` with stdin, in `cwd`, with its own state home. */
export function hookRunner(stateHome, extraEnv = {}) {
  return (args, { cwd, stdin = "" }) => runChild(HOOK_BIN, args, { cwd, stdin, env: { IRONTRELLIS_HOME: stateHome, ...extraEnv } });
}

// ---------------------------------------------------------------- history files

export const SIDE_FILES = ["", ".head", ".anchors", ".witness.json"];
/** The history and every side file an attacker on the host can write. */
export const snapshotFiles = (historyFile) => Object.fromEntries(SIDE_FILES.map((suffix) => [suffix, existsSync(historyFile + suffix) ? readFileSync(historyFile + suffix) : undefined]));
/** Puts files back as an attacker would (absent in the snapshot: deleted). */
export const restoreFiles = (historyFile, snap) => {
  for (const [suffix, bytes] of Object.entries(snap)) {
    if (bytes === undefined) rmSync(historyFile + suffix, { force: true });
    else writeFileSync(historyFile + suffix, bytes, { mode: 0o600 });
  }
};

/** The replayed state of a history file, bypassing every witness check (what is on disk). */
export const diskState = (historyFile) => core.openHistoryStore(historyFile, { inspect: true, witness: false }).state();
export const diskHead = (historyFile) => diskState(historyFile).head;
export const historyIdOf = (historyFile) => diskState(historyFile).eventHistoryHashes[0];
export const headOf = (head) => ({ hash: head.hash, position: head.position, canonicalTime: head.canonicalTime });

/** An owner handle (library) on a CLI-created history: domain from the genesis, owner and controller as given. */
export function ownerOn(historyFile, options = {}) {
  const state = diskState(historyFile);
  // The file's own format is named: format 2 (what the CLI creates) is the default writer; a format-1 file a test wrote through the core's test-only format-1 writer stays writable that way (the internal-format1 mark, A-185.3).
  return core.openLocalOwner({ historyFile, domain: state.genesis.domain, owner: options.owner ?? "ops", controller: options.controller ?? "ops", now: () => Date.now(), format: state.format, [FORMAT1_TEST_TOOLING]: true, ...options.extra });
}

export const rollbackWith = (reason) => (error) => error?.code === "ROLLBACK_DETECTED" && (reason === undefined || error.detail?.reason === reason);

/** A witness config entry for the library policy. */
export const witnessConfig = (server, url = server.url, extra = {}) => ({ url, verifierKey: server.verifierKey, token: server.token, ...extra });
