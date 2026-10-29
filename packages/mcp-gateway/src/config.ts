/**
 * The private gateway configuration file (`gateway.json`, 0600): history,
 * owner profile, the runtime session and its key file, storage, upstreams and
 * either exactly-once `operations` or per-call `tools`. The signing scheme is
 * taken from the admitted session; the key must be the session's credential.
 */
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { keyPairFromPrivateKey, openHistoryStore, signHashWith, type AuthorizationDomain, type ContentHash, type LocalExecutionOptions } from "@ramex-labs/irontrellis";
import { check, exact, explained, id, isPrivateMode, readPrivate, type Json, pathField } from "./data.ts";
import type { GatewayOptions, Job, PerCallTool } from "./gateway.ts";
import type { UpstreamConfig } from "./upstream.ts";

export type GatewayConfigFile = Readonly<{
  historyFile: string; domain: AuthorizationDomain; owner: string; controller: string; session: string; keyFile: string;
  upstreams: readonly UpstreamConfig[]; timeoutMs?: number;
  /** A-41.2: keep enforcing from a never-migrated legacy or format-1 history (warned on every open). Set by hand only (A-85). */
  enforceFromReadOnlyHistory?: boolean;
  /** The gateway's own owner-admitted session and its key file: it signs CONNECTOR refusals, effects and receipt wrappers. */
  connector?: Readonly<{ session: string; keyFile: string }>;
  /** A-19.4: the history this gateway serves, `recordHash(0)` (irontrellis init and setup print it); another file is HISTORY_IDENTITY_MISMATCH. */
  historyId?: string;
  mode?: "exactly-once" | "per-call"; storage?: string; operations?: readonly Job[]; tools?: readonly PerCallTool[]; recordCalls?: boolean; role?: string; tenure?: string;
}>;
export type LoadedConfig = Readonly<{ config: GatewayConfigFile; options: GatewayOptions; storage: string | undefined }>;

/** The 0x-prefixed 32-byte private key from an owner-only, unlinked, unshared file. */
export function readKeyFile(path: string): string {
  // Windows has no O_NOFOLLOW: a symbolic link is refused by name first there.
  if (constants.O_NOFOLLOW === undefined) check(!lstatSync(path).isSymbolicLink(), "KEY_UNAVAILABLE", "is a symbolic link");
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  let key: string;
  try {
    const s = fstatSync(fd);
    check(s.isFile() && s.nlink === 1, "KEY_UNAVAILABLE", "is not a regular file with a single link");
    check(isPrivateMode(s.mode), "KEY_UNAVAILABLE", `has mode 0${(s.mode & 0o777).toString(8)}; it must be owner-only (0600)`);
    check(s.size <= 128, "KEY_UNAVAILABLE", "is larger than a private key file can be");
    key = readFileSync(fd, "utf8").trim();
  } finally {
    closeSync(fd);
  }
  check(/^0x[0-9a-fA-F]{64}$/.test(key), "KEY_UNAVAILABLE", "does not hold a 0x-prefixed 32-byte hex private key");
  return key;
}

/** Parse the configuration file without touching the history or the key (for diagnostics). */
export function readGatewayConfig(path: string): GatewayConfigFile {
  const raw = exact(readPrivate<Json>(path), ["historyFile", "domain", "owner", "controller", "session", "keyFile", "upstreams"],
    ["timeoutMs", "mode", "storage", "operations", "tools", "recordCalls", "role", "tenure", "enforceFromReadOnlyHistory", "connector", "historyId"]);
  check(raw.historyId === undefined || (typeof raw.historyId === "string" && /^0x[0-9a-f]{64}$/.test(raw.historyId)), "INVALID_INPUT", 'field "historyId" must be 0x + 64 lowercase hex');
  if (raw.connector !== undefined) {
    const connector = explained('field "connector"', () => exact(raw.connector, ["session", "keyFile"]));
    explained('field "connector.session"', () => id(connector.session));
    explained('field "connector.keyFile"', () => pathField(connector.keyFile)); // A-185.6: a path, not an identifier
  }
  check(raw.enforceFromReadOnlyHistory === undefined || typeof raw.enforceFromReadOnlyHistory === "boolean", "INVALID_INPUT", 'field "enforceFromReadOnlyHistory" must be a boolean');
  for (const key of ["historyFile", "keyFile"] as const) explained(`field "${key}"`, () => pathField(raw[key])); // A-185.6
  for (const key of ["owner", "controller", "session"] as const) explained(`field "${key}"`, () => id(raw[key]));
  if (raw.storage !== undefined) explained('field "storage"', () => pathField(raw.storage));
  const mode = raw.mode ?? "exactly-once";
  check(mode === "exactly-once" || mode === "per-call", "INVALID_INPUT", 'field "mode" must be "exactly-once" or "per-call"');
  if (mode === "exactly-once") {
    check(typeof raw.storage === "string" && Array.isArray(raw.operations), "INVALID_INPUT", 'mode "exactly-once" needs "storage" and an "operations" array');
    check(raw.tools === undefined && raw.recordCalls === undefined, "INVALID_INPUT", 'mode "exactly-once" does not take "tools" or "recordCalls"');
  } else {
    check(Array.isArray(raw.tools) && raw.operations === undefined, "INVALID_INPUT", 'mode "per-call" needs a "tools" array and no "operations"');
    check(raw.recordCalls !== true || typeof raw.storage === "string", "INVALID_INPUT", '"recordCalls": true needs "storage"');
  }
  // A snapshot copies every record file in storage and reports keysIncluded: false, so no key file and no history (whose
  // owner key lies beside it) may be inside storage: that makes the report true by construction.
  if (typeof raw.storage === "string") {
    // Physical locations, so a symlinked alias of storage (or of a parent) does not hide a key inside it; a file that does not
    // exist yet is placed by its parent's physical location. The relative path is judged by components: "..x" is a name.
    const physical = (path: string): string => {
      const absolute = resolve(path);
      try { return realpathSync(absolute); } catch { /* not there yet */ }
      try { return resolve(realpathSync(dirname(absolute)), basename(absolute)); } catch { return absolute; }
    };
    const storage = physical(raw.storage);
    const inside = (path: string): boolean => {
      const rel = relative(storage, physical(path));
      return rel === "" || (!isAbsolute(rel) && rel !== ".." && !rel.startsWith(`..${sep}`));
    };
    const connectorKey = (raw.connector as Readonly<{ keyFile?: unknown }> | undefined)?.keyFile;
    for (const [field, value] of [["historyFile", raw.historyFile], ["keyFile", raw.keyFile], ["connector.keyFile", connectorKey]] as const) {
      if (typeof value === "string") check(!inside(value), "INVALID_INPUT", `field "${field}" lies inside "storage": snapshots copy storage, so keep keys and the history outside it`);
    }
  }
  return raw as unknown as GatewayConfigFile;
}

/** Load the configuration and bind the runtime signer; refuses a key that is not the admitted session's credential. */
export function loadGatewayConfig(path: string): LoadedConfig {
  const config = explained("gateway.json", () => readGatewayConfig(path));
  const state = explained("the history (historyFile):", () => openHistoryStore(config.historyFile, { trust: "CHECKPOINT_RESUME", ...(config.historyId === undefined ? {} : { historyId: config.historyId as ContentHash }) }).state());
  const session = state.runtimeSessions.get(config.session);
  check(session !== undefined, "RUNTIME_NOT_CURRENT", 'the history has no runtime session named by "session"');
  const pair = keyPairFromPrivateKey(session.credentialScheme, session.credentialKeyId, explained("the key file (keyFile)", () => readKeyFile(config.keyFile)));
  check(pair.credential.toLowerCase() === session.credentialAddressKey.toLowerCase(), "KEY_MISMATCH", "the key file does not hold the admitted session's key");
  let connector: Readonly<{ session: string; signHash: ReturnType<typeof signHashWith> }> | undefined;
  if (config.connector !== undefined) {
    const own = state.runtimeSessions.get(config.connector.session);
    check(own !== undefined, "RUNTIME_NOT_CURRENT", 'the history has no runtime session named by "connector.session"');
    const ownPair = keyPairFromPrivateKey(own.credentialScheme, own.credentialKeyId, explained("the connector key file (connector.keyFile)", () => readKeyFile(config.connector!.keyFile)));
    check(ownPair.credential.toLowerCase() === own.credentialAddressKey.toLowerCase(), "KEY_MISMATCH", "the connector key file does not hold the admitted connector session's key");
    connector = { session: config.connector.session, signHash: signHashWith(ownPair) };
  }
  const local: LocalExecutionOptions = {
    historyFile: config.historyFile, domain: config.domain, owner: config.owner, controller: config.controller, session: config.session, now: Date.now, signHash: signHashWith(pair),
    ...(config.enforceFromReadOnlyHistory === true ? { enforceFromReadOnlyHistory: true } : {}), ...(config.historyId === undefined ? {} : { historyId: config.historyId as ContentHash }),
  };
  const common = { local, upstreams: config.upstreams, ...(config.timeoutMs === undefined ? {} : { timeoutMs: config.timeoutMs }), ...(connector === undefined ? {} : { connectorSigner: connector }) };
  const options: GatewayOptions = config.mode === "per-call"
    ? { ...common, mode: "per-call", tools: config.tools!, ...(config.recordCalls === undefined ? {} : { recordCalls: config.recordCalls }),
        ...(config.storage === undefined ? {} : { storage: config.storage }), ...(config.role === undefined ? {} : { role: config.role }), ...(config.tenure === undefined ? {} : { tenure: config.tenure }) }
    : { ...common, mode: "exactly-once", storage: config.storage!, operations: config.operations! };
  return { config, options, storage: config.storage };
}
