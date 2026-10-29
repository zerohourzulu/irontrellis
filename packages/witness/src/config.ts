/**
 * The witness configuration file (`config.json`, 0600) and the witness key
 * file (`witness-key.json`, 0600) in the data directory (docs/reference/witness-service.md §4.2,
 * §4.6). The key file holds the checkpoint signing key as a signed-note
 * signer key string (`PRIVATE+KEY+<name>+<hash>+<base64>`).
 */
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { chmodSync, closeSync, fsyncSync, mkdirSync, openSync, readFileSync, statSync, writeSync } from "node:fs";
import { dirname, join } from "node:path";
import { encodeBase64, generateNoteKey, isValidNoteKeyName, LATEST_NOTE_VERSION, parseSignerKey, verifierKey as verifierKeyOf } from "@ramex-labs/irontrellis/transparency";
import type { NoteSigner } from "@ramex-labs/irontrellis/transparency";
import { ownerOnlyModeEnforced, replaceFileSync } from "@ramex-labs/irontrellis/platform";
import { CONFIG_FILE, fsyncDir, KEY_FILE } from "./log.ts";

export const KEY_FILE_VERSION = "irontrellis-witness-key/1";
export const DEFAULT_LISTEN = "127.0.0.1:8411";

/** Token buckets per minute; 0 disables a limit. `monitoringPerIpPerMinute`: the separate, more generous per-address bucket of `/healthz` and `/metrics`. */
export type RateLimitConfig = Readonly<{ perIpPerMinute: number; perHistoryPerMinute: number; monitoringPerIpPerMinute: number }>;
export type WitnessConfig = Readonly<{
  name: string;
  origin: string;
  listen: string;
  registration: "open" | "token";
  /** SHA-256 (lowercase hex) of each admin token accepted for registration. */
  adminTokenHashes: readonly string[];
  /** Token buckets; 0 disables a limit. */
  rateLimit: RateLimitConfig;
  maxHistories: number;
  checkpointIntervalMs: number;
  /** false; true (the peer is a trusted proxy: the client is the last X-Forwarded-For address); or the trusted proxy addresses. */
  trustProxy: boolean | readonly string[];
  requestTimeoutMs: number;
  /** When set, `GET /metrics` needs `Authorization: Bearer <metricsToken>` (401 otherwise). The config file is mode 0600. */
  metricsToken?: string;
}>;

export const DEFAULTS = Object.freeze({
  listen: DEFAULT_LISTEN,
  registration: "token" as const,
  adminTokenHashes: Object.freeze([]) as readonly string[],
  rateLimit: Object.freeze({ perIpPerMinute: 1200, perHistoryPerMinute: 600, monitoringPerIpPerMinute: 6000 }),
  maxHistories: 10_000,
  checkpointIntervalMs: 0,
  trustProxy: false as boolean | readonly string[],
  requestTimeoutMs: 10_000,
});

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

const isRecord = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const NAME = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const isCount = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

/** A witness name (also the checkpoint key name): letters, digits and `._:/-`, at most 128 characters. */
export const isValidWitnessName = (name: unknown): name is string => typeof name === "string" && NAME.test(name) && isValidNoteKeyName(name);
/** An origin: one printable line (the first line of every checkpoint). */
export const isValidOrigin = (origin: unknown): origin is string => typeof origin === "string" && origin.length > 0 && origin.length <= 256 && /^[\x21-\x7e][\x20-\x7e]*$/.test(origin) && !origin.endsWith(" ") &&
  origin !== LATEST_NOTE_VERSION; // the first line of the signed latest notes: a checkpoint must never look like one (docs/reference/witness-protocol.md §9.8)
export const defaultOrigin = (name: string): string => `irontrellis-witness/${name}`;

/** Parses `host:port` (IPv6 as `[::1]:8411`). */
export function parseListen(listen: string): Readonly<{ host: string; port: number }> {
  const match = /^(?:\[([0-9a-fA-F:.]+)\]|([^:[\]]+)):(\d{1,5})$/.exec(listen);
  const port = match === null ? NaN : Number(match[3]);
  if (match === null || !Number.isInteger(port) || port < 0 || port > 65_535) throw new ConfigError(`listen must be host:port (got ${JSON.stringify(listen)})`);
  return { host: (match[1] ?? match[2]) as string, port };
}

/** Validates a parsed config object and fills the defaults. Unknown keys are refused (a typo must not silently weaken a limit). */
export function normalizeConfig(value: unknown): WitnessConfig {
  if (!isRecord(value)) throw new ConfigError("the config must be a JSON object");
  const known = ["name", "origin", "listen", "registration", "adminTokenHashes", "rateLimit", "maxHistories", "checkpointIntervalMs", "trustProxy", "requestTimeoutMs", "metricsToken"];
  for (const key of Object.keys(value)) if (!known.includes(key)) throw new ConfigError(`unknown config key ${JSON.stringify(key)}`);
  if (!isValidWitnessName(value.name)) throw new ConfigError("name must be 1..128 of letters, digits and ._:/- (it names the checkpoint key)");
  const origin = value.origin ?? defaultOrigin(value.name);
  if (!isValidOrigin(origin)) throw new ConfigError(`origin must be one printable ASCII line other than ${LATEST_NOTE_VERSION}`);
  const listen = value.listen ?? DEFAULTS.listen;
  if (typeof listen !== "string") throw new ConfigError("listen must be a string");
  parseListen(listen);
  const registration = value.registration ?? DEFAULTS.registration;
  if (registration !== "open" && registration !== "token") throw new ConfigError('registration must be "open" or "token"');
  const hashes = value.adminTokenHashes ?? [];
  if (!Array.isArray(hashes) || !hashes.every((hash) => typeof hash === "string" && HEX64.test(hash))) throw new ConfigError("adminTokenHashes must be lowercase SHA-256 hex strings");
  const rate = value.rateLimit ?? DEFAULTS.rateLimit;
  if (!isRecord(rate) || Object.keys(rate).some((key) => key !== "perIpPerMinute" && key !== "perHistoryPerMinute" && key !== "monitoringPerIpPerMinute")) {
    throw new ConfigError("rateLimit must be { perIpPerMinute, perHistoryPerMinute, monitoringPerIpPerMinute }");
  }
  const perIp = rate.perIpPerMinute ?? DEFAULTS.rateLimit.perIpPerMinute;
  const perHistory = rate.perHistoryPerMinute ?? DEFAULTS.rateLimit.perHistoryPerMinute;
  const monitoring = rate.monitoringPerIpPerMinute ?? DEFAULTS.rateLimit.monitoringPerIpPerMinute;
  if (!isCount(perIp) || !isCount(perHistory) || !isCount(monitoring)) throw new ConfigError("rate limits are non-negative integers (0 disables)");
  const maxHistories = value.maxHistories ?? DEFAULTS.maxHistories;
  if (!isCount(maxHistories) || maxHistories === 0) throw new ConfigError("maxHistories must be a positive integer");
  const interval = value.checkpointIntervalMs ?? DEFAULTS.checkpointIntervalMs;
  if (!isCount(interval) || interval > 60_000) throw new ConfigError("checkpointIntervalMs must be 0..60000");
  const trustProxy = value.trustProxy ?? DEFAULTS.trustProxy;
  if (typeof trustProxy !== "boolean" && !(Array.isArray(trustProxy) && trustProxy.every((entry) => typeof entry === "string" && entry.length > 0))) {
    throw new ConfigError("trustProxy must be a boolean or a list of proxy addresses");
  }
  const timeout = value.requestTimeoutMs ?? DEFAULTS.requestTimeoutMs;
  if (!isCount(timeout) || timeout < 100) throw new ConfigError("requestTimeoutMs must be at least 100");
  const metricsToken = value.metricsToken;
  if (metricsToken !== undefined && (typeof metricsToken !== "string" || !/^[\x21-\x7e]{16,512}$/.test(metricsToken))) {
    throw new ConfigError("metricsToken must be 16..512 visible ASCII characters (it is sent as Authorization: Bearer <metricsToken>)");
  }
  return Object.freeze({
    name: value.name, origin, listen, registration, adminTokenHashes: Object.freeze([...hashes] as string[]),
    rateLimit: Object.freeze({ perIpPerMinute: perIp, perHistoryPerMinute: perHistory, monitoringPerIpPerMinute: monitoring }), maxHistories, checkpointIntervalMs: interval,
    trustProxy: typeof trustProxy === "boolean" ? trustProxy : Object.freeze([...trustProxy] as string[]), requestTimeoutMs: timeout,
    ...(metricsToken === undefined ? {} : { metricsToken }),
  });
}

export function loadConfig(path: string): WitnessConfig {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (error) {
    throw new ConfigError(`cannot read the config ${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new ConfigError(`${path} is not valid JSON`);
  }
  try {
    return normalizeConfig(value);
  } catch (error) {
    throw new ConfigError(`${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/** Writes a file atomically (temp file, fsync, rename, fsync dir) with mode 0600 (on Windows the rename retries sharing violations, and the mode is the ACL's business). */
export function writePrivateFile(path: string, text: string, exclusive = false): void {
  const temp = exclusive ? path : `${path}.tmp-${process.pid}`;
  const fd = openSync(temp, exclusive ? "wx" : "w", 0o600);
  try {
    writeSync(fd, text);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  chmodSync(temp, 0o600);
  if (!exclusive) replaceFileSync(temp, path);
  fsyncDir(dirname(path));
}

/** The config as stored (defaults spelled out so operators see them). */
export const configText = (config: WitnessConfig): string => `${JSON.stringify(config, null, 2)}\n`;

// ---------------------------------------------------------------- key file

export type WitnessKey = Readonly<{ name: string; signer: NoteSigner; verifierKey: string }>;

/** Refuses a secret file other users can read (like ssh). Not on Windows, whose mode bits are synthetic: there the ACL protects it (docs/PLATFORMS.md §3). */
export function assertPrivate(path: string, what: string): void {
  if (!ownerOnlyModeEnforced()) return;
  const mode = statSync(path).mode & 0o777;
  if ((mode & 0o077) !== 0) throw new ConfigError(`${what} ${path} is accessible by other users (mode ${mode.toString(8).padStart(4, "0")}); run chmod 600 on it`);
}

export function loadWitnessKey(path: string): WitnessKey {
  let value: unknown;
  try {
    value = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw new ConfigError(`cannot read the witness key ${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
  assertPrivate(path, "the witness key");
  if (!isRecord(value) || value.version !== KEY_FILE_VERSION || typeof value.name !== "string" || typeof value.privateKey !== "string" || typeof value.publicKey !== "string") {
    throw new ConfigError(`${path} is not an ${KEY_FILE_VERSION} key file`);
  }
  let signer: NoteSigner;
  try {
    signer = parseSignerKey(value.privateKey);
  } catch (error) {
    throw new ConfigError(`${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (signer.name !== value.name || encodeBase64(signer.publicKey) !== value.publicKey) throw new ConfigError(`${path}: the name or public key does not match the private key`);
  return Object.freeze({ name: signer.name, signer, verifierKey: verifierKeyOf(signer.name, signer.publicKey) });
}

export type InitResult = Readonly<{ dataDir: string; name: string; origin: string; verifierKey: string; keyPath: string; configPath: string }>;

/** `irontrellis-witness init`: creates the data directory (0700), a new key (0600) and a default config (0600). Refuses an initialized directory. */
export function initDataDir(dataDir: string, name: string, origin?: string): InitResult {
  if (!isValidWitnessName(name)) throw new ConfigError("--name must be 1..128 of letters, digits and ._:/-");
  const effectiveOrigin = origin ?? defaultOrigin(name);
  if (!isValidOrigin(effectiveOrigin)) throw new ConfigError("--origin must be one printable ASCII line");
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  chmodSync(dataDir, 0o700);
  const keyPath = join(dataDir, KEY_FILE);
  const configPath = join(dataDir, CONFIG_FILE);
  for (const path of [keyPath, configPath, join(dataDir, "log.jsonl")]) {
    try {
      statSync(path);
      throw new ConfigError(`${dataDir} is already initialized (${path} exists)`);
    } catch (error) {
      if (error instanceof ConfigError) throw error;
    }
  }
  const { signerKey, verifierKey } = generateNoteKey(name);
  const signer = parseSignerKey(signerKey);
  writePrivateFile(keyPath, `${JSON.stringify({ version: KEY_FILE_VERSION, name, publicKey: encodeBase64(signer.publicKey), verifierKey, privateKey: signerKey }, null, 2)}\n`, true);
  const config = normalizeConfig({ name, origin: effectiveOrigin });
  writePrivateFile(configPath, configText(config), true);
  return Object.freeze({ dataDir, name, origin: effectiveOrigin, verifierKey, keyPath, configPath });
}

// ---------------------------------------------------------------- admin tokens

export const hashToken = (token: string): string => createHash("sha256").update(token, "utf8").digest("hex");

/** A new admin token (`itw_` + 43 base64url characters, 256 bits). */
export const newAdminToken = (): string => `itw_${randomBytes(32).toString("base64url")}`;

/** Constant-time: compares the token's hash against every configured hash, without an early exit. */
export function tokenMatches(token: string, hashes: readonly string[]): boolean {
  const digest = createHash("sha256").update(token, "utf8").digest();
  let match = false;
  for (const hash of hashes) {
    const expected = Buffer.from(hash, "hex");
    if (expected.length === digest.length && timingSafeEqual(expected, digest)) match = true;
  }
  return match;
}
