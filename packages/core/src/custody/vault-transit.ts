/**
 * The HashiCorp Vault Transit signer: a key reference whose `signer` is
 *
 *   { kind: "vault-transit", address: "https://vault.example:8200", mount: "transit", key: "irontrellis-owner",
 *     keyVersion: 1, namespace?: "team-a", tokenFile?: "/abs/token", caFile?: "/abs/ca.pem", timeoutMs?: 30000 }
 *
 * asks Vault for an Ed25519 signature over the 32-byte hash IronTrellis signs (docs/CUSTODY.md §7):
 *
 *   1. `GET /v1/<mount>/keys/<key>`: the key must be an `ed25519` key, not derived, whose version `keyVersion`
 *      exists, is not below `min_encryption_version`, and holds exactly the reference's public key. Anything else
 *      is KEY_UNAVAILABLE (the key missing, trimmed, replaced, or another key under that name).
 *   2. `POST /v1/<mount>/sign/<key>` with `{ input: base64(message), key_version: <pinned>, prehashed: false }`:
 *      PureEdDSA over the 32 bytes (Vault 1.19+ answers `prehashed: true` for ed25519 with "only Pure Ed25519
 *      signatures supported"; Ed25519ph would be a different signature). `hash_algorithm` is "not valid for …
 *      ed25519", `signature_algorithm` applies to RSA only and `marshaling_algorithm` to ECDSA P-256 only, so none
 *      is sent. The answer `vault:v<N>:<base64>` must carry the pinned version N (else KEY_UNAVAILABLE): a Vault
 *      key rotation never silently switches the owner key. `referenceSigner` then verifies the 64 bytes locally.
 *
 * The token is never part of the reference: it comes from the reference's `tokenFile`, else `VAULT_TOKEN`, else
 * `~/.vault-token` (the Vault CLI's token file). The namespace is the reference's `namespace`, else
 * `VAULT_NAMESPACE`; the CA bundle the reference's `caFile`, else `VAULT_CACERT`. Plain `http:` is refused unless
 * the host is loopback (the witness rule, without an override: the token travels in every request).
 *
 * Transport: `node:https` / `node:http` (zero dependencies). Node's global `fetch` cannot take a private CA bundle
 * without undici's dispatcher, which is not a public Node API, so both calls use one code path that can. No proxy
 * is used and redirects are not followed (a redirect is SIGNER_FAILED). One timeout (`timeoutMs`, default 30 s)
 * covers both calls. Failures that are not about the key (unreachable, sealed, permission denied — a revoked or
 * expired token —, timeouts, malformed answers) are SIGNER_FAILED with `detail.reason`.
 */
import { readFileSync } from "node:fs";
import { request as httpRequest, type IncomingMessage } from "node:http";
import { request as httpsRequest } from "node:https";
import { homedir } from "node:os";
import { join } from "node:path";
import { EngineError } from "../errors.ts";
import { isFullyQualifiedPath } from "../platform.ts";
import { isLoopbackHost } from "../witness-client.ts";
import type { ReferencedKey, SignerBackend, SignerSpec } from "./registry.ts";

export const DEFAULT_VAULT_TIMEOUT_MS = 30_000;
export const DEFAULT_VAULT_MOUNT = "transit";
const MAX_ANSWER = 1024 * 1024;
const SEGMENT = /^[A-Za-z0-9_.-]{1,128}$/;
const TOKEN = /^[\x21-\x7e]{1,4096}$/;

type Env = Readonly<Record<string, string | undefined>>;
const failed = (message: string, detail: Readonly<Record<string, unknown>>): EngineError => new EngineError("SIGNER_FAILED", message, { signer: "vault-transit", ...detail });
const unavailable = (message: string, detail: Readonly<Record<string, unknown>>): EngineError => new EngineError("KEY_UNAVAILABLE", message, { signer: "vault-transit", ...detail });

const checkPath = (value: unknown, what: string): string => {
  if (typeof value !== "string" || value.length > 4096 || value.includes("\0") || !isFullyQualifiedPath(value)) throw new Error(`vault-transit signer: ${what} must be an absolute path`);
  return value;
};

/** `https://host[:port]` (or `http://` to a loopback host), without a trailing slash, credentials, query or fragment. */
export function normalizeVaultAddress(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048) throw new Error("vault-transit signer: address must be the Vault URL, e.g. https://vault.example:8200");
  let url: URL;
  try { url = new URL(value); } catch { throw new Error(`vault-transit signer: address ${JSON.stringify(value)} is not a URL`); }
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error(`vault-transit signer: address must be https:// (got ${url.protocol})`);
  if (url.username !== "" || url.password !== "" || url.search !== "" || url.hash !== "") throw new Error("vault-transit signer: address must not carry credentials, a query or a fragment");
  if (url.protocol === "http:" && !isLoopbackHost(url.hostname)) {
    throw new Error(`vault-transit signer: plain http is refused for ${url.host}, which is not loopback: the Vault token travels in every request; use https (with caFile for a private CA)`);
  }
  return `${url.protocol}//${url.host}${url.pathname.replace(/\/+$/, "")}`;
}

const parseSpec = (spec: Readonly<Record<string, unknown>>): SignerSpec => {
  const allowed = ["kind", "address", "mount", "key", "keyVersion", "namespace", "tokenFile", "caFile", "timeoutMs"];
  const extra = Object.keys(spec).filter((key) => !allowed.includes(key));
  if (extra.length > 0) {
    const secret = extra.find((key) => /token|secret|password/i.test(key));
    throw new Error(secret !== undefined
      ? `vault-transit signer: ${secret} is not allowed: a reference never holds the Vault token (use tokenFile, VAULT_TOKEN or ~/.vault-token)`
      : `unknown vault-transit signer field(s): ${extra.join(", ")} (allowed: address, mount, key, keyVersion, namespace, tokenFile, caFile, timeoutMs)`);
  }
  const address = normalizeVaultAddress(spec.address);
  const mount = spec.mount === undefined ? DEFAULT_VAULT_MOUNT : spec.mount;
  if (typeof mount !== "string" || mount.length > 512 || !mount.replace(/^\/+|\/+$/g, "").split("/").every((part) => SEGMENT.test(part) && part !== "." && part !== "..")) {
    throw new Error("vault-transit signer: mount must be the Transit mount path (letters, digits, _ . - and /), e.g. transit");
  }
  if (typeof spec.key !== "string" || !SEGMENT.test(spec.key) || spec.key === "." || spec.key === "..") throw new Error("vault-transit signer: key must be the Transit key name (letters, digits, _ . -)");
  if (!Number.isSafeInteger(spec.keyVersion) || (spec.keyVersion as number) < 1) {
    throw new Error("vault-transit signer: keyVersion must be the pinned key version (an integer ≥ 1): a Vault key rotation must not silently switch the owner key");
  }
  if (spec.namespace !== undefined && (typeof spec.namespace !== "string" || spec.namespace.length > 512 || !validNamespace(spec.namespace))) {
    throw new Error("vault-transit signer: namespace must be a Vault namespace path (letters, digits, _ . - and /)");
  }
  if (spec.timeoutMs !== undefined && !(Number.isSafeInteger(spec.timeoutMs) && (spec.timeoutMs as number) >= 100 && (spec.timeoutMs as number) <= 600_000)) {
    throw new Error("vault-transit signer: timeoutMs must be an integer from 100 to 600000");
  }
  return Object.freeze({
    kind: "vault-transit", address, mount: (mount as string).replace(/^\/+|\/+$/g, ""), key: spec.key, keyVersion: spec.keyVersion as number,
    ...(spec.namespace === undefined ? {} : { namespace: (spec.namespace as string).replace(/^\/+|\/+$/g, "") }),
    ...(spec.tokenFile === undefined ? {} : { tokenFile: checkPath(spec.tokenFile, "tokenFile") }),
    ...(spec.caFile === undefined ? {} : { caFile: checkPath(spec.caFile, "caFile") }),
    ...(spec.timeoutMs === undefined ? {} : { timeoutMs: spec.timeoutMs as number }),
  });
};

/** Where the token for `spec` comes from (never the token itself): the reference's tokenFile, VAULT_TOKEN, or ~/.vault-token. */
export function vaultTokenSource(spec: SignerSpec, env: Env = process.env): Readonly<{ source: "tokenFile" | "VAULT_TOKEN" | "vault-token-file"; path?: string }> {
  if (typeof spec.tokenFile === "string") return { source: "tokenFile", path: spec.tokenFile };
  if (env.VAULT_TOKEN !== undefined && env.VAULT_TOKEN !== "") return { source: "VAULT_TOKEN" };
  return { source: "vault-token-file", path: join(env.HOME !== undefined && env.HOME !== "" ? env.HOME : homedir(), ".vault-token") };
}
/** The CA bundle file `spec` uses, if any (the reference's caFile, else VAULT_CACERT). */
export function vaultCaFile(spec: SignerSpec, env: Env = process.env): string | undefined {
  if (typeof spec.caFile === "string") return spec.caFile;
  return env.VAULT_CACERT !== undefined && env.VAULT_CACERT !== "" ? env.VAULT_CACERT : undefined;
}
const validNamespace = (value: string): boolean => value.replace(/^\/+|\/+$/g, "").split("/").every((part) => SEGMENT.test(part));
/** The namespace: the reference's, else `VAULT_NAMESPACE` (checked with the same rule: a header value must never carry anything else). */
function namespaceOf(spec: SignerSpec, env: Env): string | undefined {
  if (typeof spec.namespace === "string") return spec.namespace;
  const value = env.VAULT_NAMESPACE;
  if (value === undefined || value === "") return undefined;
  if (value.length > 512 || !validNamespace(value)) throw failed("VAULT_NAMESPACE is not a Vault namespace path (letters, digits, _ . - and /); nothing was signed", { reason: "NAMESPACE_INVALID" });
  return value.replace(/^\/+|\/+$/g, "");
}

function tokenOf(spec: SignerSpec, env: Env): string {
  const from = vaultTokenSource(spec, env);
  let token: string;
  if (from.source === "VAULT_TOKEN") token = env.VAULT_TOKEN!.trim();
  else {
    try { token = readFileSync(from.path!, "utf8").trim(); } catch (error) {
      const code = (error as NodeJS.ErrnoException).code ?? String(error);
      throw failed(from.source === "tokenFile"
        ? `the Vault token file ${from.path} named by the key reference cannot be read (${code}); nothing was signed`
        : `no Vault token: VAULT_TOKEN is not set and ${from.path} cannot be read (${code}); log in (vault login) or set tokenFile in the reference; nothing was signed`,
        { reason: "NO_TOKEN", tokenSource: from.source, path: from.path });
    }
  }
  if (!TOKEN.test(token)) throw failed(`the Vault token (${from.source === "VAULT_TOKEN" ? "VAULT_TOKEN" : from.path}) is empty or not one line of visible characters; nothing was signed`, { reason: "NO_TOKEN", tokenSource: from.source });
  return token;
}

type Answer = Readonly<{ status: number; body: unknown; text: string }>;

/** One Vault API call. Resolves with any HTTP status; rejects with SIGNER_FAILED for transport problems and the deadline. */
function call(spec: SignerSpec, method: "GET" | "POST", path: string, token: string, body: unknown, deadline: number, env: Env): Promise<Answer> {
  const url = new URL(`${spec.address as string}/v1/${path}`);
  let namespace: string | undefined;
  try { namespace = namespaceOf(spec, env); } catch (error) { return Promise.reject(error); }
  const caFile = vaultCaFile(spec, env);
  let ca: Buffer | undefined;
  if (caFile !== undefined && url.protocol === "https:") {
    try { ca = readFileSync(caFile); } catch (error) {
      return Promise.reject(failed(`the Vault CA file ${caFile} cannot be read (${(error as NodeJS.ErrnoException).code ?? String(error)}); nothing was signed`, { reason: "CA_FILE", caFile }));
    }
  }
  const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body), "utf8");
  const remaining = deadline - Date.now();
  const where = `Vault at ${spec.address as string}`;
  if (remaining <= 0) return Promise.reject(failed(`${where} did not answer in time; nothing was signed`, { reason: "TIMEOUT", address: spec.address }));
  return new Promise((resolve, reject) => {
    let settled = false;
    // Declared before anything can call `finish` (a synchronous throw from the request).
    let timer: NodeJS.Timeout | undefined;
    const finish = (error: EngineError | undefined, answer?: Answer): void => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      if (error !== undefined) reject(error); else resolve(answer!);
    };
    const headers: Record<string, string> = { "X-Vault-Token": token, "X-Vault-Request": "true", Accept: "application/json" };
    if (namespace !== undefined) headers["X-Vault-Namespace"] = namespace;
    if (payload !== undefined) { headers["Content-Type"] = "application/json"; headers["Content-Length"] = String(payload.length); }
    const options = { method, headers, agent: false as const, ...(ca === undefined ? {} : { ca }) };
    const onAnswer = (res: IncomingMessage): void => {
      const chunks: Buffer[] = [];
      let size = 0;
      res.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_ANSWER) { req.destroy(); finish(failed(`${where} answered with more than ${MAX_ANSWER} bytes`, { reason: "MALFORMED", address: spec.address })); return; }
        chunks.push(chunk);
      });
      res.on("error", (error) => finish(failed(`${where}: the answer broke off (${error.message}); nothing was signed`, { reason: "UNREACHABLE", address: spec.address })));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        let parsed: unknown;
        try { parsed = text === "" ? undefined : JSON.parse(text); } catch { parsed = undefined; }
        finish(undefined, { status: res.statusCode ?? 0, body: parsed, text });
      });
    };
    let req: ReturnType<typeof httpRequest>;
    try {
      req = url.protocol === "https:" ? httpsRequest(url, options, onAnswer) : httpRequest(url, options, onAnswer);
    } catch (error) {
      finish(failed(`${where} cannot be asked: ${error instanceof Error ? error.message : String(error)}`, { reason: "UNREACHABLE", address: spec.address }));
      return;
    }
    timer = setTimeout(() => {
      req.destroy();
      finish(failed(`${where} did not answer within ${spec.timeoutMs ?? DEFAULT_VAULT_TIMEOUT_MS} ms; nothing was signed`, { reason: "TIMEOUT", address: spec.address }));
    }, remaining);
    req.on("error", (error: NodeJS.ErrnoException) => {
      const tls = /certificate|self[- ]signed|CERT_|SSL|TLS/i.test(`${error.code ?? ""} ${error.message}`);
      finish(failed(`${where} cannot be reached (${error.code ?? error.message})${tls ? ": TLS verification failed (a private CA needs caFile / --vault-ca-file or VAULT_CACERT)" : ""}; nothing was signed`,
        { reason: tls ? "TLS" : "UNREACHABLE", address: spec.address, cause: error.code ?? error.message }));
    });
    req.end(payload);
  });
}

const errorsOf = (answer: Answer): string => {
  const errors = (answer.body as { errors?: unknown } | undefined)?.errors;
  const list = Array.isArray(errors) ? errors.filter((e): e is string => typeof e === "string").map((e) => e.replace(/\s+/g, " ").trim()).filter((e) => e !== "") : [];
  return list.length > 0 ? list.join("; ").slice(0, 400) : answer.text.slice(0, 200).trim() || `HTTP ${answer.status}`;
};

/** SIGNER_FAILED for an answer that is not about the key (permission, sealed, server errors, redirects). */
function httpFailure(spec: SignerSpec, answer: Answer, what: string): EngineError {
  const why = errorsOf(answer);
  const where = `Vault at ${spec.address as string}`;
  if (answer.status === 403) {
    return failed(`${where} refused to ${what}: permission denied (${why}); the token is revoked, expired, or its policy lacks this path; nothing was signed`, { reason: "PERMISSION_DENIED", status: 403, address: spec.address });
  }
  if (answer.status === 503) return failed(`${where} is sealed or in standby (${why}); nothing was signed`, { reason: "SEALED", status: 503, address: spec.address });
  if (answer.status >= 300 && answer.status < 400) return failed(`${where} redirected (HTTP ${answer.status}); redirects are not followed: name the active node in the reference; nothing was signed`, { reason: "REDIRECT", status: answer.status, address: spec.address });
  return failed(`${where} could not ${what} (HTTP ${answer.status}: ${why}); nothing was signed`, { reason: "HTTP_ERROR", status: answer.status, address: spec.address });
}

/** A Transit key as `GET /v1/<mount>/keys/<key>` describes it (public keys as `0x` + 64 hex). */
export type VaultKeyInfo = Readonly<{
  name: string; type: string; derived: boolean; latestVersion: number; minEncryptionVersion: number;
  /** version → `0x` public key, for the versions Vault still holds. */
  publicKeys: ReadonlyMap<number, `0x${string}`>;
}>;

const keyPath = (spec: SignerSpec): string => `${spec.mount as string}/keys/${encodeURIComponent(spec.key as string)}`;
const describeKey = (spec: SignerSpec): string => `Transit key ${spec.mount as string}/${spec.key as string}${typeof spec.keyVersion === "number" ? ` v${spec.keyVersion}` : ""} at ${spec.address as string}`;

async function readKey(spec: SignerSpec, token: string, deadline: number, env: Env): Promise<VaultKeyInfo> {
  const answer = await call(spec, "GET", keyPath(spec), token, undefined, deadline, env);
  if (answer.status === 404) {
    throw unavailable(`Vault has no ${describeKey(spec)} (deleted, never created, or another mount); nothing was signed`, { reason: "KEY_NOT_FOUND", address: spec.address, mount: spec.mount, key: spec.key });
  }
  if (answer.status !== 200) throw httpFailure(spec, answer, `read ${describeKey(spec)}`);
  const data = (answer.body as { data?: Record<string, unknown> } | undefined)?.data;
  if (data === undefined || data === null || typeof data !== "object" || typeof data.keys !== "object" || data.keys === null) {
    throw failed(`Vault at ${spec.address as string} answered the key read with no key data`, { reason: "MALFORMED", address: spec.address });
  }
  const publicKeys = new Map<number, `0x${string}`>();
  for (const [version, entry] of Object.entries(data.keys as Record<string, unknown>)) {
    const raw = entry !== null && typeof entry === "object" ? (entry as { public_key?: unknown }).public_key : undefined;
    if (!/^[1-9][0-9]{0,8}$/.test(version) || typeof raw !== "string") continue;
    const bytes = Buffer.from(raw, "base64");
    if (bytes.length === 32) publicKeys.set(Number(version), `0x${bytes.toString("hex")}`);
  }
  return Object.freeze({
    name: typeof data.name === "string" ? data.name : spec.key as string, type: typeof data.type === "string" ? data.type : "(unknown)", derived: data.derived === true,
    latestVersion: Number.isSafeInteger(data.latest_version) ? data.latest_version as number : 0,
    minEncryptionVersion: Number.isSafeInteger(data.min_encryption_version) ? data.min_encryption_version as number : 0,
    publicKeys,
  });
}

/**
 * Reads the Transit key a vault-transit `signer` record names (no signature is asked for): its type, versions and
 * public keys. `spec.keyVersion` may be absent here (the CLI reads the latest version to pin it). Throws like `sign`.
 */
export async function readVaultKey(spec: Readonly<Record<string, unknown>>, env: Env = process.env): Promise<VaultKeyInfo> {
  const parsed = parseSpec({ ...spec, keyVersion: spec.keyVersion ?? 1 });
  const checked = spec.keyVersion === undefined ? Object.freeze({ ...parsed, keyVersion: undefined }) as SignerSpec : parsed;
  const deadline = Date.now() + (typeof parsed.timeoutMs === "number" ? parsed.timeoutMs : DEFAULT_VAULT_TIMEOUT_MS);
  return readKey(checked, tokenOf(parsed, env), deadline, env);
}

/** Why `info` cannot sign for `key` with the pinned version, or `undefined` when it can. */
function keyDefect(spec: SignerSpec, info: VaultKeyInfo, key: Readonly<{ keyId: string; publicKey: string }>): EngineError | undefined {
  const version = spec.keyVersion as number;
  const detail = { address: spec.address, mount: spec.mount, key: spec.key, keyVersion: version, keyId: key.keyId };
  if (info.type !== "ed25519") return unavailable(`Vault ${describeKey(spec)} is a ${info.type} key; an IronTrellis owner key is ed25519; nothing was signed`, { ...detail, reason: "WRONG_KEY_TYPE", type: info.type });
  if (info.derived) return unavailable(`Vault ${describeKey(spec)} is a derived key (each signature needs a context); IronTrellis needs a plain ed25519 key; nothing was signed`, { ...detail, reason: "DERIVED_KEY" });
  const publicKey = info.publicKeys.get(version);
  if (publicKey === undefined) {
    return unavailable(`Vault ${describeKey(spec)} does not hold version ${version} (it holds ${[...info.publicKeys.keys()].map((v) => `v${v}`).join(", ") || "none"}; latest v${info.latestVersion}); the pinned owner key cannot sign there; nothing was signed`,
      { ...detail, reason: "VERSION_UNAVAILABLE", latestVersion: info.latestVersion });
  }
  if (version < info.minEncryptionVersion) {
    return unavailable(`Vault ${describeKey(spec)} no longer signs with version ${version} (min_encryption_version is ${info.minEncryptionVersion}); nothing was signed`,
      { ...detail, reason: "VERSION_UNAVAILABLE", minEncryptionVersion: info.minEncryptionVersion });
  }
  if (publicKey !== key.publicKey.toLowerCase()) {
    return unavailable(`Vault ${describeKey(spec)} holds another public key (${publicKey}) than owner key ${key.keyId} (${key.publicKey}): the key was replaced or the reference names the wrong key; nothing was signed`,
      { ...detail, reason: "PUBLIC_KEY_MISMATCH", vaultPublicKey: publicKey, publicKey: key.publicKey });
  }
  return undefined;
}

/**
 * A reachability and key check for doctor: reads the key (no signature, nothing a person approves) and reports
 * whether the pinned version holds the reference's public key. Never throws.
 */
export async function checkVaultKey(spec: SignerSpec, key: Readonly<{ keyId: string; publicKey: string }>, env: Env = process.env): Promise<Readonly<{ ok: boolean; code?: string; reason?: string; message: string }>> {
  try {
    const deadline = Date.now() + Math.min(typeof spec.timeoutMs === "number" ? spec.timeoutMs : DEFAULT_VAULT_TIMEOUT_MS, 10_000);
    const info = await readKey(spec, tokenOf(spec, env), deadline, env);
    const defect = keyDefect(spec, info, key);
    if (defect !== undefined) return { ok: false, code: defect.code, reason: (defect.detail as { reason?: string }).reason ?? "", message: defect.message };
    return { ok: true, message: `${describeKey(spec)} holds ${key.keyId}${info.latestVersion !== spec.keyVersion ? ` (latest is v${info.latestVersion}; the reference stays pinned to v${spec.keyVersion as number})` : ""}` };
  } catch (error) {
    const e = error instanceof EngineError ? error : failed(error instanceof Error ? error.message : String(error), { reason: "BACKEND_ERROR" });
    return { ok: false, code: e.code, reason: (e.detail as { reason?: string } | undefined)?.reason ?? "", message: e.message };
  }
}

const SIGNATURE = /^vault:v([1-9][0-9]{0,8}):([A-Za-z0-9+/]+={0,2})$/;

export const VAULT_TRANSIT_BACKEND: SignerBackend = Object.freeze({
  kind: "vault-transit",
  parse: parseSpec,
  describe(spec: SignerSpec): string {
    return `Vault Transit key ${spec.mount as string}/${spec.key as string} v${spec.keyVersion as number} at ${spec.address as string}${typeof spec.namespace === "string" ? ` (namespace ${spec.namespace})` : ""}`;
  },
  // The holder is the Vault server (and namespace) reached with one credential: two keys a single token can sign
  // with are one custody (NEXT_KEY_SAME_SIGNER), however many key names there are. A next key behind its own token
  // file (a policy granting only that key) is a different holder.
  identity(spec: SignerSpec): string {
    return `${spec.address as string}|${typeof spec.namespace === "string" ? spec.namespace : ""}|token:${typeof spec.tokenFile === "string" ? spec.tokenFile : "VAULT_TOKEN or ~/.vault-token"}`;
  },
  async sign(spec: SignerSpec, key: ReferencedKey, message: Uint8Array): Promise<Uint8Array> {
    const env = process.env;
    const version = spec.keyVersion as number;
    const deadline = Date.now() + (typeof spec.timeoutMs === "number" ? spec.timeoutMs : DEFAULT_VAULT_TIMEOUT_MS);
    const token = tokenOf(spec, env);
    const defect = keyDefect(spec, await readKey(spec, token, deadline, env), key);
    if (defect !== undefined) throw defect;
    const answer = await call(spec, "POST", `${spec.mount as string}/sign/${encodeURIComponent(spec.key as string)}`, token,
      { input: Buffer.from(message).toString("base64"), key_version: version, prehashed: false }, deadline, env);
    if (answer.status === 400 && /signing key not found|key not found/i.test(errorsOf(answer))) {
      throw unavailable(`Vault has no ${describeKey(spec)} any more; nothing was signed`, { reason: "KEY_NOT_FOUND", address: spec.address, mount: spec.mount, key: spec.key });
    }
    if (answer.status !== 200) {
      if (/key version/i.test(errorsOf(answer))) {
        throw unavailable(`Vault refused to sign with ${describeKey(spec)}: ${errorsOf(answer)}; nothing was signed`, { reason: "VERSION_UNAVAILABLE", status: answer.status, address: spec.address, keyVersion: version });
      }
      throw httpFailure(spec, answer, `sign with ${describeKey(spec)}`);
    }
    const data = (answer.body as { data?: { signature?: unknown; key_version?: unknown } } | undefined)?.data;
    const match = typeof data?.signature === "string" ? SIGNATURE.exec(data.signature) : null;
    if (match === null) throw failed(`Vault at ${spec.address as string} did not answer with a vault:v<N>:<base64> signature`, { reason: "MALFORMED", address: spec.address });
    const signedWith = Number(match[1]);
    if (signedWith !== version || (data!.key_version !== undefined && data!.key_version !== version)) {
      throw unavailable(`Vault signed with ${spec.mount as string}/${spec.key as string} v${signedWith}, not the pinned v${version}: the signature is not used and nothing was written with it`,
        { reason: "VERSION_MISMATCH", keyVersion: version, signedWith, address: spec.address });
    }
    const signature = Buffer.from(match[2]!, "base64");
    if (signature.length !== 64) throw failed(`Vault returned ${signature.length} signature bytes; an Ed25519 signature has 64`, { reason: "MALFORMED", address: spec.address });
    return new Uint8Array(signature);
  },
});
