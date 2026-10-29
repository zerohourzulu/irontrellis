/**
 * The private evidence configuration (`gateway.json`, 0600): history, owner
 * profile, the runtime session, its role tenure, the fixed resource, the
 * selected input files, the packet directory and the key file. Every choice
 * is made here by the operator; none of them is a tool argument.
 */
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync } from "node:fs";
import { keyPairFromPrivateKey, openHistoryStore, openLocalEvidenceTool, signHashWith, type AdditionalPolicy, type EvidenceToolOptions, type LocalEvidenceTool } from "@ramex-labs/irontrellis";
import { ownerOnlyModeEnforced } from "@ramex-labs/irontrellis/platform";
import { parseStrictJson } from "./strict-json.ts";

/** A coded configuration refusal; `detail` names the file, field or limit at fault, never a configuration value or key. */
export class ConfigError extends Error {
  readonly code: string;
  readonly detail: string | undefined;
  constructor(code: string, detail?: string) { super(code); this.name = "ConfigError"; this.code = code; this.detail = detail; }
}
const fail = (code = "CONFIG_UNAVAILABLE", detail?: string): never => { throw new ConfigError(code, detail); };
const ERRNO: Readonly<Record<string, string>> = { ENOENT: "does not exist", EACCES: "permission denied", ELOOP: "is a symbolic link (refused)", ENOTDIR: "a component of the path is not a directory", EISDIR: "is a directory" };
const JSON_ERRORS: Readonly<Record<string, string>> = {
  INVALID_JSON: "is not valid JSON", INVALID_UTF8: "is not valid UTF-8", DUPLICATE_KEY: "has a duplicate key", INVALID_JSON_NUMBER: "has a non-finite number",
  JSON_BYTES_EXCEEDED: "is too large", JSON_NODES_EXCEEDED: "has too many values", JSON_DEPTH_EXCEEDED: "is nested too deeply",
};
const errnoOf = (error: unknown): string | undefined =>
  error !== null && typeof error === "object" && typeof (error as { code?: unknown }).code === "string" ? (error as { code: string }).code : undefined;
/** One operator-facing sentence for any error raised while loading or serving a configuration (bounded, no configuration values). */
export function describeConfigError(error: unknown): string {
  const code = errnoOf(error);
  const text = error instanceof ConfigError ? error.detail ?? error.code
    : code !== undefined && ERRNO[code] !== undefined ? ERRNO[code]!
    : code !== undefined && JSON_ERRORS[code] !== undefined ? JSON_ERRORS[code]!
    : code !== undefined && error instanceof Error && error.message !== code ? `${code}: ${error.message}`
    : code ?? (error instanceof Error ? error.message : "unknown error");
  return text.length > 300 ? text.slice(0, 297) + "..." : text;
}
const explained = <T>(label: string, step: () => T): T => {
  try { return step(); } catch (error) { throw new ConfigError(errnoOf(error) ?? "CONFIG_UNAVAILABLE", `${label} ${describeConfigError(error)}`); }
};

/** Owner-only permission bits; not checked on Windows, whose mode bits are synthetic (the ACL protects the file there). */
const ownerOnly = (mode: number): boolean => !ownerOnlyModeEnforced() || (mode & 0o077) === 0;
/** Bytes of an owner-only, unlinked regular file, read through O_NOFOLLOW (Windows has none: the lstat below refuses a link) and checked against its lstat. */
export function privateFile(path: unknown, maximum: number): Buffer {
  if (typeof path !== "string") return fail("CONFIG_UNAVAILABLE", "path is not a string");
  const before = lstatSync(path);
  if (!before.isFile() || before.isSymbolicLink()) fail("CONFIG_UNAVAILABLE", "is not a regular file");
  if (before.nlink !== 1) fail("CONFIG_UNAVAILABLE", `has ${before.nlink} hard links; it must have exactly one`);
  if (!ownerOnly(before.mode)) fail("CONFIG_UNAVAILABLE", `has mode 0${(before.mode & 0o777).toString(8)}; it must be owner-only (0600)`);
  if (before.size > maximum) fail("CONFIG_UNAVAILABLE", `is ${before.size} bytes; the limit is ${maximum} bytes`);
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.dev !== before.dev || stat.ino !== before.ino || stat.nlink !== 1 || !ownerOnly(stat.mode) || stat.size > maximum) fail();
    const bytes = readFileSync(fd);
    if (bytes.length > maximum) fail();
    return bytes;
  } finally {
    closeSync(fd);
  }
}

const FIELDS = ["historyFile", "domain", "owner", "controller", "session", "role", "tenure", "resource", "inputDirectory", "outputDirectory", "selection", "keyFile"] as const;
export type EvidenceConfigFile = Readonly<Record<(typeof FIELDS)[number], unknown>> & Readonly<{ historyFile: string; session: string; keyFile: string; resource: string }>;

export function readEvidenceConfig(configFile: string): EvidenceConfigFile {
  const config = explained("the configuration file", () => parseStrictJson(privateFile(configFile, 16384), { maxBytes: 16384, maxDepth: 12, maxNodes: 2048 })) as Record<string, unknown> | null;
  if (config === null || typeof config !== "object" || Array.isArray(config)) return fail("CONFIG_UNAVAILABLE", "the configuration file must hold a JSON object");
  const missing = FIELDS.find((k) => !Object.hasOwn(config, k)), unknown = Object.keys(config).find((k) => !(FIELDS as readonly string[]).includes(k));
  if (missing !== undefined) fail("CONFIG_UNAVAILABLE", `the configuration file is missing the field "${missing}"`);
  if (unknown !== undefined) fail("CONFIG_UNAVAILABLE", `the configuration file has an unknown field "${unknown.slice(0, 64)}"`);
  for (const key of ["historyFile", "session", "keyFile", "resource", "owner", "controller", "role", "tenure"]) if (typeof config[key] !== "string") fail("CONFIG_UNAVAILABLE", `the field "${key}" must be a string`);
  return config as EvidenceConfigFile;
}

/** Open the configured evidence tool with the session's signing key; a key that is not the session's credential is refused. */
export function loadEvidenceTool(configFile: string, options: Readonly<{ additionalPolicy?: AdditionalPolicy }> = {}): LocalEvidenceTool {
  const config = readEvidenceConfig(configFile);
  const key = explained("the key file (keyFile)", () => privateFile(config.keyFile, 128)).toString("utf8").trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(key)) fail("CONFIG_UNAVAILABLE", "the key file (keyFile) does not hold a 0x-prefixed 32-byte hex private key");
  const session = explained("the history (historyFile):", () => openHistoryStore(config.historyFile).state()).runtimeSessions.get(config.session);
  if (session === undefined) return fail("RUNTIME_NOT_CURRENT", 'the history has no runtime session named by "session"');
  const pair = keyPairFromPrivateKey(session.credentialScheme, session.credentialKeyId, key);
  if (pair.credential.toLowerCase() !== session.credentialAddressKey.toLowerCase()) fail("KEY_MISMATCH", "the key file does not hold the admitted session's key");
  const toolOptions = {
    ...(config as unknown as Omit<EvidenceToolOptions, "now" | "signHash">), now: Date.now, signHash: signHashWith(pair),
    ...(options.additionalPolicy === undefined ? {} : { additionalPolicy: options.additionalPolicy }),
  } as EvidenceToolOptions;
  return openLocalEvidenceTool(toolOptions);
}
