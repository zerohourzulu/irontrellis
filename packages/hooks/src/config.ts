/**
 * `irontrellis-hook.json`: where the history is, who owns it, which agent the
 * host runs as, and how tool calls map to (action, resource). Found through
 * `IRONTRELLIS_HOOK_CONFIG` or by walking up from the working directory (and
 * from the event's cwd). A relative path in it is relative to the file's
 * directory, which is also the `${project}` template value; `init` writes an
 * absolute `history` under ~/.irontrellis/projects/ by default (see paths.ts).
 */
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { isFullyQualifiedPath } from "@ramex-labs/irontrellis/platform";
import type { AuthorizationDomain } from "@ramex-labs/irontrellis";
import { PROTOCOL_IDS, type ProtocolId } from "./protocols/types.ts";
import { canonicalProject, readRegularFile } from "./paths.ts";

export const CONFIG_FILE = "irontrellis-hook.json";
export const CONFIG_ENV = "IRONTRELLIS_HOOK_CONFIG";
export const CONFIG_VERSION = "irontrellis-hook-config/1";

export class HookConfigError extends Error {
  readonly code = "CONFIG_INVALID" as const;
  constructor(message: string) {
    super(message);
    this.name = "HookConfigError";
  }
}

export type Rule = Readonly<{ tool: string; action: string; resource: string }>;
export type Policy = Readonly<{ sideEffecting: readonly Rule[]; readOnly: readonly string[]; unmapped: "ask" | "deny" }>;
/**
 * What the hook answers when IronTrellis has no objection. "defer" (the
 * default) returns no decision, so the host's own permission check still runs;
 * "allow" answers allow, which on Claude Code and Codex skips the host's own
 * permission prompt for that call.
 */
export type Decisions = Readonly<{ onAllow: "defer" | "allow"; onReadOnly: "defer" | "allow" }>;
export type HookConfig = Readonly<{
  /** Directory of the config file; `${project}` in templates and the base of relative paths. */
  project: string;
  path: string;
  history: string;
  owner: string;
  controller: string;
  /** The genesis domain; read from the history when absent. */
  domain: AuthorizationDomain | undefined;
  agentId: string;
  roleId: string | undefined;
  protocol: ProtocolId | undefined;
  /** Runtime session lifetime in milliseconds (default 24 h). */
  sessionTtlMs: number;
  /** What an `ask` becomes on a host event that cannot ask (Codex PreToolUse, Cursor preToolUse). */
  askFallback: "deny" | "allow";
  /** Tool-event failures (missing history, replay error) refuse the call unless true. */
  failOpen: boolean;
  /** A-41.2: keep enforcing from a never-migrated legacy or format-1 history (a warning on every open). Set by hand only (A-85). */
  enforceFromReadOnlyHistory: boolean;
  /** The hook's own connector agent (`hooks:<host>`): its session signs CONNECTOR refusals only (docs/API.md §2). */
  connector: Readonly<{ agentId: string }> | undefined;
  /** A-19.4: the history this hook enforces from, `recordHash(0)`; a file whose line 0 differs is HISTORY_IDENTITY_MISMATCH. */
  historyId: string | undefined;
  decisions: Decisions;
  policy: Policy;
}>;

// 1–128 Unicode scalar values (A-89.2, A-170.3; RA-10): the u flag counts code points, and a lone surrogate is refused.
const IDENTIFIER = /^(?!.*\p{Cs})[^\u0000-\u001f\u007f]{1,128}$/u;
const fail = (message: string): never => { throw new HookConfigError(message); };
const isRecord = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const id = (v: unknown, what: string): string => (typeof v === "string" && IDENTIFIER.test(v) ? v : fail(`${what} must be a string of 1–128 printable characters`));

const rule = (v: unknown, index: number): Rule => {
  if (!isRecord(v)) return fail(`policy.sideEffecting[${index}] must be an object`);
  const keys = Object.keys(v).filter((k) => !["tool", "action", "resource"].includes(k));
  if (keys.length > 0) return fail(`policy.sideEffecting[${index}] has unknown keys: ${keys.join(", ")}`);
  return Object.freeze({ tool: id(v.tool, `policy.sideEffecting[${index}].tool`), action: id(v.action, `policy.sideEffecting[${index}].action`), resource: id(v.resource, `policy.sideEffecting[${index}].resource`) });
};

const policyOf = (v: unknown): Policy => {
  if (!isRecord(v)) return fail("policy must be an object with sideEffecting and readOnly");
  const keys = Object.keys(v).filter((k) => !["sideEffecting", "readOnly", "unmapped"].includes(k));
  if (keys.length > 0) return fail(`policy has unknown keys: ${keys.join(", ")}`);
  if (!Array.isArray(v.sideEffecting)) return fail("policy.sideEffecting must be an array of { tool, action, resource }");
  if (!Array.isArray(v.readOnly) || !v.readOnly.every((t) => typeof t === "string" && IDENTIFIER.test(t))) return fail("policy.readOnly must be an array of tool names");
  if (v.unmapped !== undefined && v.unmapped !== "ask" && v.unmapped !== "deny") return fail('policy.unmapped must be "ask" or "deny"');
  return Object.freeze({ sideEffecting: Object.freeze(v.sideEffecting.map(rule)), readOnly: Object.freeze([...v.readOnly] as string[]), unmapped: (v.unmapped as "ask" | "deny" | undefined) ?? "ask" });
};

const deferOrAllow = (v: unknown, what: string): "defer" | "allow" | undefined =>
  v === undefined ? undefined : v === "defer" || v === "allow" ? v : fail(`${what} must be "defer" or "allow"`);
const decisionsOf = (v: unknown): Decisions => {
  if (v === undefined) return Object.freeze({ onAllow: "defer", onReadOnly: "defer" });
  if (!isRecord(v)) return fail("decisions must be an object { onAllow, onReadOnly }");
  const keys = Object.keys(v).filter((k) => !["onAllow", "onReadOnly"].includes(k));
  if (keys.length > 0) return fail(`decisions has unknown keys: ${keys.join(", ")}`);
  return Object.freeze({ onAllow: deferOrAllow(v.onAllow, "decisions.onAllow") ?? "defer", onReadOnly: deferOrAllow(v.onReadOnly, "decisions.onReadOnly") ?? "defer" });
};

const KNOWN = ["version", "history", "owner", "controller", "domain", "agentId", "roleId", "protocol", "sessionTtlMs", "askFallback", "failOpen", "enforceFromReadOnlyHistory", "connector", "historyId", "decisions", "policy"];

/** Validate a parsed config document. `path` is the file it came from (its directory is the project). */
export function validateConfig(raw: unknown, path: string): HookConfig {
  if (!isRecord(raw)) return fail("the config must be a JSON object");
  const unknown = Object.keys(raw).filter((k) => !KNOWN.includes(k));
  if (unknown.length > 0) return fail(`unknown keys: ${unknown.join(", ")}`);
  if (raw.version !== undefined && raw.version !== CONFIG_VERSION) return fail(`version must be "${CONFIG_VERSION}"`);
  // The project as init records it (canonicalProject: through symlinks), so a symlinked spelling of the project's folder
  // renders the same repo:<project> resource the grants name (independent review A, D-01).
  const project = canonicalProject(dirname(resolve(path)));
  if (typeof raw.history !== "string" || raw.history.length === 0 || raw.history.includes("\0")) return fail("history must be a file path");
  const owner = id(raw.owner, "owner");
  const controller = raw.controller === undefined ? "controller:irontrellis-hook" : id(raw.controller, "controller");
  const agentId = id(raw.agentId, "agentId");
  const roleId = raw.roleId === undefined ? undefined : id(raw.roleId, "roleId");
  if (raw.protocol !== undefined && !PROTOCOL_IDS.includes(raw.protocol as ProtocolId)) return fail(`protocol must be one of ${PROTOCOL_IDS.join(", ")}`);
  if (raw.sessionTtlMs !== undefined && !(typeof raw.sessionTtlMs === "number" && Number.isSafeInteger(raw.sessionTtlMs) && raw.sessionTtlMs > 0)) return fail("sessionTtlMs must be a positive integer");
  if (raw.askFallback !== undefined && raw.askFallback !== "deny" && raw.askFallback !== "allow") return fail('askFallback must be "deny" or "allow"');
  if (raw.failOpen !== undefined && typeof raw.failOpen !== "boolean") return fail("failOpen must be a boolean");
  if (raw.enforceFromReadOnlyHistory !== undefined && typeof raw.enforceFromReadOnlyHistory !== "boolean") return fail("enforceFromReadOnlyHistory must be a boolean");
  if (raw.domain !== undefined && !isRecord(raw.domain)) return fail("domain must be the history's genesis domain object");
  if (raw.connector !== undefined && (!isRecord(raw.connector) || Object.keys(raw.connector).some((k) => k !== "agentId"))) return fail("connector must be { agentId }");
  const connector = raw.connector === undefined ? undefined : Object.freeze({ agentId: id((raw.connector as Record<string, unknown>).agentId, "connector.agentId") });
  if (raw.historyId !== undefined && !(typeof raw.historyId === "string" && /^0x[0-9a-f]{64}$/.test(raw.historyId))) return fail("historyId must be 0x + 64 lowercase hex (irontrellis-hook init writes it)");
  if (connector !== undefined && connector.agentId === agentId) return fail("connector.agentId must differ from agentId (the connector is the hook's own agent)");
  return Object.freeze({
    project, path: resolve(path), history: isFullyQualifiedPath(raw.history) ? raw.history : resolve(project, raw.history), owner, controller,
    domain: raw.domain as AuthorizationDomain | undefined, agentId, roleId, protocol: raw.protocol as ProtocolId | undefined,
    sessionTtlMs: (raw.sessionTtlMs as number | undefined) ?? 24 * 3_600_000, askFallback: (raw.askFallback as "deny" | "allow" | undefined) ?? "deny",
    failOpen: raw.failOpen === true, enforceFromReadOnlyHistory: raw.enforceFromReadOnlyHistory === true, connector, historyId: raw.historyId as string | undefined, decisions: decisionsOf(raw.decisions), policy: policyOf(raw.policy),
  });
}

/** Walk up from `start` looking for the config file. */
export function findConfigFile(start: string): string | undefined {
  let dir = resolve(start);
  for (;;) {
    const candidate = resolve(dir, CONFIG_FILE);
    if (existsSync(candidate)) return candidate;
    const parent = dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
}

/** Resolve and load the config: the env override, then the working directory, then the event's cwd. */
export function loadConfig(env: Readonly<Record<string, string | undefined>>, cwd: string, eventCwd?: string): HookConfig {
  const fromEnv = env[CONFIG_ENV];
  const path = fromEnv !== undefined && fromEnv !== "" ? resolve(cwd, fromEnv) : (findConfigFile(cwd) ?? (eventCwd === undefined ? undefined : findConfigFile(eventCwd)));
  if (path === undefined) return fail(`no ${CONFIG_FILE} found from ${cwd}${eventCwd === undefined ? "" : ` or ${eventCwd}`} (run: irontrellis-hook init, or set ${CONFIG_ENV})`);
  return loadConfigFile(path);
}

export function loadConfigFile(path: string): HookConfig {
  let text: string;
  try { text = readRegularFile(path, 1_048_576); } catch { return fail(`cannot read ${path} (or it is not a regular file)`); }
  let raw: unknown;
  try { raw = JSON.parse(text); } catch (error) { return fail(`${path} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`); }
  try { return validateConfig(raw, path); } catch (error) { return fail(`${path}: ${error instanceof Error ? error.message : String(error)}`); }
}
