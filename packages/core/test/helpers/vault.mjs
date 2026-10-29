// Test helpers for the Vault Transit signer (block 4 phase B): a REAL Vault dev server per test file, either
//   * started here with Docker: `docker run -d --rm -p 127.0.0.1:0:8200 -e VAULT_DEV_ROOT_TOKEN_ID=<random> hashicorp/vault:1.20`, or
//   * given by the environment (CI's service container): IRONTRELLIS_VAULT_ADDR (loopback http) + IRONTRELLIS_VAULT_TOKEN (a root token).
// Each file gets its own Transit mount (`it-<random>`), so files can share one server. `vaultSkip` is the node:test
// option that skips a test with the reason when neither is available (CI without Docker stays green).
// Also: a loopback proxy in front of Vault that can rewrite requests and answers (a signature with another key
// version, a forged signature, captured headers), and a silent server (timeouts). Not a test file.
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, request } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const VAULT_IMAGE = process.env.IRONTRELLIS_VAULT_IMAGE ?? "hashicorp/vault:1.20";

const external = process.env.IRONTRELLIS_VAULT_ADDR !== undefined && process.env.IRONTRELLIS_VAULT_ADDR !== "" && process.env.IRONTRELLIS_VAULT_TOKEN !== undefined;

function availability() {
  if (external) return { ok: true, mode: "external" };
  if (process.env.IRONTRELLIS_SKIP_VAULT === "1") return { ok: false, reason: "IRONTRELLIS_SKIP_VAULT=1" };
  const docker = spawnSync("docker", ["image", "inspect", "--format", "{{.Id}}", VAULT_IMAGE], { encoding: "utf8", timeout: 15_000 });
  if (docker.error !== undefined) return { ok: false, reason: `Vault tests need Docker (docker: ${docker.error.code ?? docker.error.message}) or IRONTRELLIS_VAULT_ADDR + IRONTRELLIS_VAULT_TOKEN` };
  if (docker.status !== 0) return { ok: false, reason: `Vault tests need the ${VAULT_IMAGE} image (docker pull ${VAULT_IMAGE}) or IRONTRELLIS_VAULT_ADDR + IRONTRELLIS_VAULT_TOKEN: ${(docker.stderr || "").trim().split("\n")[0]}` };
  return { ok: true, mode: "docker" };
}
export const vaultAvailable = availability();
/** `test(name, vaultSkip, fn)`: skipped, with the reason, when no Vault can be had. */
export const vaultSkip = vaultAvailable.ok ? {} : { skip: vaultAvailable.reason };

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * A Vault dev server with a fresh Transit mount. Returns { address, token, mount, api, createKey, rotateKey, publicKeyOf,
 * deleteKey, childToken, revokeToken, stop }. `stop()` removes the container (when this helper started one).
 */
export async function startVault() {
  let address, token, container;
  if (vaultAvailable.mode === "external") {
    address = process.env.IRONTRELLIS_VAULT_ADDR.replace(/\/+$/, "");
    token = process.env.IRONTRELLIS_VAULT_TOKEN;
  } else {
    token = `root-${randomBytes(12).toString("hex")}`;
    const run = spawnSync("docker", ["run", "-d", "--rm", "-p", "127.0.0.1:0:8200", "-e", `VAULT_DEV_ROOT_TOKEN_ID=${token}`, VAULT_IMAGE], { encoding: "utf8", timeout: 60_000 });
    if (run.status !== 0) throw new Error(`docker run ${VAULT_IMAGE} failed: ${run.stderr}`);
    container = run.stdout.trim();
    const port = spawnSync("docker", ["port", container, "8200/tcp"], { encoding: "utf8" }).stdout.trim().split("\n")[0];
    address = `http://${port.replace(/^0\.0\.0\.0/, "127.0.0.1")}`;
  }
  const api = async (method, path, body, as = token) => {
    const res = await fetch(`${address}/v1/${path}`, { method, headers: { "X-Vault-Token": as, "Content-Type": "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const text = await res.text();
    let json;
    try { json = text === "" ? undefined : JSON.parse(text); } catch { json = undefined; }
    return { status: res.status, json, text };
  };
  const deadline = Date.now() + 60_000;
  for (;;) {
    try {
      const health = await fetch(`${address}/v1/sys/health`);
      if (health.status === 200) break;
    } catch { /* starting */ }
    if (Date.now() > deadline) throw new Error(`Vault at ${address} did not become healthy`);
    await sleep(200);
  }
  const mount = `it-${randomBytes(4).toString("hex")}`;
  const must = async (what, promise, ok = [200, 204]) => {
    const r = await promise;
    if (!ok.includes(r.status)) throw new Error(`${what}: HTTP ${r.status} ${r.text}`);
    return r;
  };
  await must("enable transit", api("POST", `sys/mounts/${mount}`, { type: "transit" }));
  const publicKeyOf = async (name, version) => {
    const r = await must(`read ${name}`, api("GET", `${mount}/keys/${name}`));
    const v = version ?? r.json.data.latest_version;
    return `0x${Buffer.from(r.json.data.keys[String(v)].public_key, "base64").toString("hex")}`;
  };
  return {
    address, token, mount, api, publicKeyOf,
    /** Creates an ed25519 key; returns its v1 public key (0x hex). */
    async createKey(name, options = {}) {
      await must(`create ${name}`, api("POST", `${mount}/keys/${name}`, { type: "ed25519", ...options }));
      return publicKeyOf(name, 1);
    },
    /** Rotates the key (a new version); returns the new version's public key. */
    async rotateKey(name) { await must(`rotate ${name}`, api("POST", `${mount}/keys/${name}/rotate`)); return publicKeyOf(name); },
    async configKey(name, config) { await must(`config ${name}`, api("POST", `${mount}/keys/${name}/config`, config)); },
    async deleteKey(name) {
      await must(`allow deletion of ${name}`, api("POST", `${mount}/keys/${name}/config`, { deletion_allowed: true }));
      await must(`delete ${name}`, api("DELETE", `${mount}/keys/${name}`));
    },
    /** A token whose policy may read and sign with `keys` only (the least privilege docs/CUSTODY.md recommends). */
    async childToken(keys) {
      const policy = `p-${randomBytes(4).toString("hex")}`;
      const rules = keys.map((k) => `path "${mount}/sign/${k}" { capabilities = ["update"] }\npath "${mount}/keys/${k}" { capabilities = ["read"] }`).join("\n");
      await must("write policy", api("PUT", `sys/policies/acl/${policy}`, { policy: rules }));
      const r = await must("create token", api("POST", "auth/token/create", { policies: [policy], no_default_policy: true, ttl: "1h" }));
      return r.json.auth.client_token;
    },
    async revokeToken(child) { await must("revoke token", api("POST", "auth/token/revoke", { token: child })); },
    stop() {
      if (container !== undefined) spawnSync("docker", ["rm", "-f", "-v", container], { encoding: "utf8", timeout: 30_000 });
      else void api("DELETE", `sys/mounts/${mount}`).catch(() => {});
    },
  };
}

/**
 * A loopback HTTP proxy in front of `target` (http://127.0.0.1:port). `rewrite({ method, path, headers, body })` may
 * return { body } (a new request body object) and `answer({ path, status, json })` may return a replacement JSON
 * answer. `requests` records every request's method, path and headers.
 */
export async function startVaultProxy(target, { rewrite, answer, tls } = {}) {
  const requests = [];
  const handler = (req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      let body = Buffer.concat(chunks);
      requests.push({ method: req.method, path: req.url, headers: { ...req.headers } });
      if (rewrite !== undefined && body.length > 0) {
        const changed = rewrite({ method: req.method, path: req.url, headers: req.headers, body: JSON.parse(body.toString("utf8")) });
        if (changed?.body !== undefined) body = Buffer.from(JSON.stringify(changed.body));
      }
      const url = new URL(req.url, target);
      const headers = { ...req.headers, host: url.host, "content-length": String(body.length) };
      const upstream = request(url, { method: req.method, headers }, (up) => {
        const out = [];
        up.on("data", (c) => out.push(c));
        up.on("end", () => {
          let text = Buffer.concat(out).toString("utf8");
          if (answer !== undefined) {
            let json; try { json = JSON.parse(text); } catch { json = undefined; }
            const replaced = answer({ path: req.url, status: up.statusCode, json });
            if (replaced !== undefined) text = JSON.stringify(replaced);
          }
          res.writeHead(up.statusCode, { "content-type": "application/json" });
          res.end(text);
        });
      });
      upstream.on("error", (e) => { res.writeHead(502); res.end(JSON.stringify({ errors: [e.message] })); });
      upstream.end(body);
    });
  };
  const server = tls === undefined ? createServer(handler) : createHttpsServer({ key: tls.key, cert: tls.cert }, handler);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { address: `${tls === undefined ? "http" : "https"}://127.0.0.1:${server.address().port}`, requests, close: () => new Promise((resolve) => { server.closeAllConnections?.(); server.close(resolve); }) };
}

/** A loopback server that accepts connections and never answers (for timeouts). */
export async function startSilentServer() {
  const sockets = new Set();
  const server = createServer(() => { /* never answers */ });
  server.on("connection", (s) => { sockets.add(s); s.on("close", () => sockets.delete(s)); });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { address: `http://127.0.0.1:${server.address().port}`, close: () => { for (const s of sockets) s.destroy(); return new Promise((resolve) => server.close(resolve)); } };
}

/** A self-signed certificate for 127.0.0.1 (openssl): { key, cert, certFile } (the cert is its own CA). `undefined` without openssl. */
export function selfSignedCert(dir) {
  const out = dir ?? mkdtempSync(join(tmpdir(), "itv-"));
  const r = spawnSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2", "-subj", "/CN=127.0.0.1",
    "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", join(out, "tls.key"), "-out", join(out, "tls.crt")], { encoding: "utf8", timeout: 30_000 });
  if (r.status !== 0) return undefined;
  const result = { key: readFileSync(join(out, "tls.key")), cert: readFileSync(join(out, "tls.crt")), certFile: join(out, "tls.crt") };
  if (dir === undefined) rmSync(out, { recursive: true, force: true });
  return result;
}
