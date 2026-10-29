/**
 * `init` (create the history and the config) and `install` (the host's hook
 * settings). Both are operator commands run by a person, never by the host.
 */
import { rendersToolInput } from "./policy.ts";
import { randomBytes } from "node:crypto";
import { chmodSync, closeSync, existsSync, fchmodSync, fsyncSync, mkdirSync, openSync, readFileSync, realpathSync, renameSync, statSync, unlinkSync, writeFileSync, writeSync } from "node:fs";
import { basename, dirname, join, relative, resolve, isAbsolute } from "node:path";
import { homedir, hostname } from "node:os";
import {
  createLocalDomain, createLocalOwner, generateKeyPair, loadOwnerKeyFile, NEXT_KEY_ON_HOST_WARNING, nextOwnerKeyPathFor, openHistoryStore, openLocalOwner, type AuthorizationDomain, type LocalOwner,
} from "@ramex-labs/irontrellis";
import { CONFIG_FILE, CONFIG_VERSION, loadConfigFile, validateConfig, type HookConfig } from "./config.ts";

import { ensureAgent, openOwner, releaseSessionKey, sessionKeys } from "./hook.ts";
import { CONNECTOR_KEY_VERSION, DEFAULT_HISTORY_NAME, RUNTIME_PIN_NAME, canonicalProject, readRegularFile, connectorKeyFile, defaultStateDir, ensurePrivateDir, ownerKeyPath, readPrivateJson, writePrivateFile } from "./paths.ts";
import { claudeSettingsFiles, EARLIER_HOOK_WRAPPERS, HOOK_PATH_UNSAFE, HOOK_WRAPPER, hookEntryProgram, onPath, OWN_LAUNCHER, shellWords } from "./protect.ts";
import type { InstallEntry, Protocol } from "./protocols/types.ts";
import { pluginEnabled } from "./route.ts";

/** The longest resource a grant may name (A-89.2, the core's validation). */
const MAX_RESOURCE_CHARS = 128;
/** The core's bound on any Identifier, a resource included: 256 bytes of UTF-8. */
const MAX_RESOURCE_BYTES = 256;

export type InitOptions = Readonly<{
  protocol: Protocol;
  project: string;
  /** Explicit history path (relative to the project); default `<stateHome>/projects/<hash>/history.jsonl`. */
  history: string | undefined;
  /** Base of the per-user state; default `~/.irontrellis` (IRONTRELLIS_HOME). */
  stateHome: string;
  owner: string | undefined;
  controller: string | undefined;
  agentId: string | undefined;
  roleId: string | undefined;
  /** Actions to grant on `repo:<project>` right away (e.g. run-shell, write-file); none by default. */
  allow: readonly string[];
  expiresAt: number;
  force: boolean;
  /** Required to grant run-shell: on one OS user, run-shell reaches the owner key (see README). */
  acceptSameUserRisk: boolean;
  now: () => number;
  /** How a path is shown in `notes` (the command shortens the home directory to ~); default as is. */
  showPath?: (path: string) => string;
}>;
export type InitResult = Readonly<{
  configFile: string; history: string; stateDir: string; ownerKey: string; created: boolean; steps: readonly string[]; grant: string | undefined; config: HookConfig;
  /** `.gitignore` files written into project-local state directories. */
  gitignores: readonly string[];
  /** Printed prominently by the command (with --verbose or --json). */
  warnings: readonly string[];
  /** The same warnings in one sentence each, for the command's default output (founder's live check 02). */
  notes: readonly string[];
}>;

/** Codex's config files, user (CODEX_HOME, else ~/.codex) then project; a later one overrides. */
export const codexConfigFiles = (project: string, env: Readonly<Record<string, string | undefined>>): readonly string[] =>
  [join(env.CODEX_HOME !== undefined && env.CODEX_HOME !== "" ? env.CODEX_HOME : join(env.HOME !== undefined && env.HOME !== "" ? env.HOME : homedir(), ".codex"), "config.toml"), join(project, ".codex", "config.toml")];

/**
 * What a Codex config.toml says about hooks: `hooks` (or the older `codex_hooks`) under `[features]`, or `features.hooks`
 * at the top level; the last value wins; undefined when it says nothing. A plain line reader, not a TOML parser: enough for
 * this one key (a comment after it, spaces around `=`).
 */
export function codexHooksSetting(text: string): boolean | undefined {
  let table = "", value: boolean | undefined;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s#.*$|^#.*$/, "").trim();
    const header = /^\[\s*([^\]]+?)\s*\]$/.exec(line);
    if (header !== null) { table = header[1]!.replace(/\s+/g, ""); continue; }
    const kv = /^([A-Za-z0-9_.-]+)\s*=\s*(true|false)$/.exec(line);
    if (kv === null) continue;
    const key = table === "" ? kv[1]! : `${table}.${kv[1]}`;
    if (key === "features.hooks" || key === "features.codex_hooks") value = kv[2] === "true";
  }
  return value;
}

/** Actions that let the agent run arbitrary programs as this OS user. */
export const SHELL_ACTIONS: readonly string[] = Object.freeze(["run-shell"]);

/**
 * The same-user layout warning when the owner key is held by a signer (a key reference: docs/CUSTODY.md). The agent
 * cannot read the key, but whatever can reach the signer can ask it to sign: the boundary is the signer's own gate.
 */
export const signerHeldWarning = (ownerKey: string, held: string): string => [
  `NOTE: the owner key is held by ${held}; ${ownerKey} is only a reference (no secret). The agent cannot read the key, but`,
  "anything that can reach that signer as this OS user (the agent's shell, a script it wrote) can ask it to sign as the owner",
  "unless every use needs a person's approval (1Password, ssh-add -c with an askpass, a hardware key with touch) or the signer",
  "is out of the agent's reach (another OS user, no SSH_AUTH_SOCK in the agent's environment). IronTrellis refuses tool calls",
  "that reference the signer's socket or run ssh-add, but that is a tripwire, not a boundary (docs/CUSTODY.md).",
].join("\n");

export const sameUserWarning = (ownerKey: string, stateDir: string): string => [
  "WARNING: same-user layout. The agent host, this hook and the owner key run as the same OS user.",
  `There is no hard boundary between the agent and the owner key (${ownerKey}): anything the agent can run as this user`,
  "(a shell command, a script it wrote earlier) can read the key and record grants the owner never made, and the",
  "history would verify clean. IronTrellis refuses tool calls that reference its state or run its control commands,",
  "but that is a tripwire, not a boundary. Under this layout any run-shell grant is equivalent to owner authority.",
  `For a real boundary, run the hook as a separate OS user that alone owns ${stateDir} (mode 0700),`,
  "or keep the owner key in a KMS/HSM signer (core `signer` option) that the agent's user cannot use.",
].join("\n");

/** The signer that holds the owner key when `<history>.owner-key.json` is a key reference, else `undefined`. Never throws. */
const heldBy = (ownerKey: string): string | undefined => {
  try { const signer = loadOwnerKeyFile(ownerKey); return signer.custody?.holder === "reference" ? signer.custody.description : undefined; } catch { return undefined; }
};

const isInside = (parent: string, child: string): boolean => { const r = relative(parent, child); return r === "" || (!r.startsWith("..") && !isAbsolute(r)); };

/** The outermost directory on the way from `project` to `dir` that does not exist yet (inside the project only). */
const firstMissingInside = (project: string, dir: string): string | undefined => {
  if (!isInside(project, dir) || dir === project) return undefined;
  let missing: string | undefined;
  for (let d = dir; d !== project && isInside(project, d); d = dirname(d)) if (!existsSync(d)) missing = d;
  return missing;
};

/** Create (or reuse) the history, the agent and the role, write the config, and optionally grant the first actions. */
export async function init(options: InitOptions): Promise<InitResult> {
  const project = canonicalProject(options.project);
  const configFile = resolve(project, CONFIG_FILE);
  if (existsSync(configFile) && !options.force) throw new Error(`${configFile} exists (use --force to rewrite it)`);
  const shellGrant = options.allow.filter((a) => SHELL_ACTIONS.includes(a));
  const defaultLayout = options.history === undefined;
  const historyPath = defaultLayout ? join(defaultStateDir(project, options.stateHome), DEFAULT_HISTORY_NAME) : resolve(project, options.history!);
  const stateDir = dirname(historyPath);
  const ownerKey = ownerKeyPath(historyPath);
  const held = heldBy(ownerKey);
  const show = options.showPath ?? ((p: string): string => p);
  const warnings = [held === undefined ? sameUserWarning(ownerKey, stateDir) : signerHeldWarning(ownerKey, held)];
  const notes = [held === undefined
    ? "Same OS user: the agent runs as you, so it could read the owner key; here IronTrellis is a tripwire, not a boundary."
    : `The owner key is held by ${held}: anything running as you can ask it to sign, unless each use needs your approval.`];
  if (shellGrant.length > 0 && !options.acceptSameUserRisk) {
    throw new Error(`refusing --allow ${shellGrant.join(",")}: on the same OS user a run-shell grant is equivalent to owner authority (the agent's shell can read ${ownerKey}). ` +
      "Pass --i-understand-same-user-risk to grant it anyway, or run the hook as a separate OS user (see README, Limitations).");
  }
  // A grant's resource is at most 128 characters (A-89.2): refuse before anything is written, not after the history exists.
  const resource = `repo:${project}`;
  // The core also bounds an Identifier at 256 UTF-8 bytes, which a path of multi-byte characters reaches first.
  if (options.allow.length > 0 && ([...resource].length > MAX_RESOURCE_CHARS || Buffer.byteLength(resource, "utf8") > MAX_RESOURCE_BYTES)) {
    throw new Error(`refusing --allow: the grant's resource ${resource} is ${[...resource].length} characters (${Buffer.byteLength(resource, "utf8")} bytes in UTF-8), more than the ${MAX_RESOURCE_CHARS} characters or ${MAX_RESOURCE_BYTES} bytes a resource may have; ` +
      "run init without --allow and grant on a shorter resource with `irontrellis grant`, or move the project to a shorter path");
  }
  const steps: string[] = [];
  const gitignores: string[] = [];
  let owner: LocalOwner;
  let created = false;
  let domain: AuthorizationDomain;
  let ownerId: string;
  let controllerId: string;
  const agentId = options.agentId ?? options.protocol.id;
  if (existsSync(historyPath)) {
    // The config must name the owner (and the agent's controller) the history records, or every hook call fails.
    if (!existsSync(ownerKey)) throw new Error(`the owner key for ${historyPath} is not at ${ownerKey}; the hook needs it to create the agent and admit sessions`);
    const store = openHistoryStore(historyPath);
    if (store.format === undefined) throw new Error(`history ${historyPath} has no events`);
    const state = store.state();
    domain = state.genesis.domain;
    const principal = state.events.find((e) => e.type === "PRINCIPAL_CREATED");
    if (principal === undefined) throw new Error(`history ${historyPath} records no owner (no PRINCIPAL_CREATED event)`);
    const recordedOwner = String(principal.data.principalId);
    if (options.owner !== undefined && options.owner !== recordedOwner) throw new Error(`--owner ${options.owner} does not match the owner recorded in ${historyPath} (${recordedOwner})`);
    ownerId = recordedOwner;
    const agentEvent = state.events.find((e) => e.type === "AGENT_CREATED" && e.data.agentId === agentId);
    const recordedController = agentEvent === undefined ? undefined : String(agentEvent.data.controllerId);
    if (options.controller !== undefined && recordedController !== undefined && options.controller !== recordedController) {
      throw new Error(`--controller ${options.controller} does not match the controller recorded for ${agentId} in ${historyPath} (${recordedController})`);
    }
    controllerId = options.controller ?? recordedController ?? "controller:irontrellis-hook";
    // SPEC §16.1, A-85: the hook writes format 2 only; a legacy, format-1 or fenced history is migrated first (init never
    // sets "enforceFromReadOnlyHistory": an operator who keeps enforcing from an older file sets it by hand).
    const readOnly = store.readOnlyReason();
    if (readOnly !== undefined) {
      throw new Error(readOnly === "MIGRATED"
        ? `history ${historyPath} was migrated to format 2 and is kept read only; run init with --history <the migration target>`
        : `history ${historyPath} is a ${readOnly === "LEGACY" ? "legacy" : "format-1"} history, which this release reads but does not write: migrate it (irontrellis migrate ${historyPath} <target.jsonl>) and run init with --history <target.jsonl>`);
    }
    owner = openLocalOwner({ historyFile: historyPath, domain, owner: ownerId, controller: controllerId, now: options.now });
    steps.push(`history ${historyPath} reused (${state.head.position + 1} events, owner ${ownerId})`);
  } else {
    ownerId = options.owner ?? "principal:owner";
    controllerId = options.controller ?? "controller:irontrellis-hook";
    const missing = firstMissingInside(project, stateDir);
    if (defaultLayout) {
      ensurePrivateDir(options.stateHome);
      ensurePrivateDir(join(options.stateHome, "projects"));
    }
    ensurePrivateDir(stateDir);
    if (defaultLayout || missing !== undefined) chmodSync(stateDir, 0o700);
    if (missing !== undefined) {
      // A project-local state directory must never be committed (it holds private keys).
      const gitignore = join(missing, ".gitignore");
      writeFileSync(gitignore, "# IronTrellis state: history, owner key, session keys. Never commit.\n*\n", { flag: "wx" });
      gitignores.push(gitignore);
      steps.push(`${gitignore} written (the directory holds private keys)`);
    }
    domain = createLocalDomain();
    owner = await createLocalOwner({ historyFile: historyPath, domain, owner: ownerId, controller: controllerId, now: options.now });
    created = true;
    steps.push(`history ${historyPath} created (owner key ${ownerKey}, mode 0600; committed next owner key ${nextOwnerKeyPathFor(historyPath)}, mode 0600)`);
    // Pre-rotation: only the committed next key can rotate the owner key, and only while it is not on this host.
    warnings.push(`NOTE: the next owner key ${nextOwnerKeyPathFor(historyPath)} was written beside the owner key: ${NEXT_KEY_ON_HOST_WARNING} (irontrellis owner status; rotate with irontrellis owner rotate-key --next-key <file>).`);
    notes.push("The next owner key is on this machine, beside the owner key: move it offline, or it cannot protect a rotation.");
  }
  if (isInside(project, historyPath)) {
    const ignored = gitignores.length > 0 || existsSync(join(stateDir, ".gitignore"));
    warnings.push(`NOTE: the history and owner key are inside the project (${historyPath}), where the agent's own file tools can reach them. ` +
      "The protective rules refuse tool calls that name them, but the default layout (no --history) keeps them under ~/.irontrellis/projects/." +
      (ignored ? "" : ` Add "${relative(project, historyPath)}*" to .gitignore: it holds the owner key, session keys and handovers.`));
    notes.push(`The history and owner key are inside the project, where the agent's file tools can reach them${ignored ? "" : `; add "${relative(project, historyPath)}*" to .gitignore`}.`);
  }
  const policy = options.protocol.defaultPolicy();
  // A-42.3: a rule whose resource renders tool input is recorded by digest only (CONNECTOR refusal, never the rendered text).
  for (const rule of policy.sideEffecting) {
    if (rendersToolInput(rule.resource)) warnings.push(`NOTE: the rule for ${rule.tool} renders tool input into its resource (${rule.resource}); its refusals are recorded as CONNECTOR refusals carrying the template and a digest of the rendered request, never the tool input itself (A-42).`);
  }
  const raw = {
    version: CONFIG_VERSION,
    history: historyPath,
    owner: ownerId, controller: controllerId, domain,
    agentId, roleId: options.roleId ?? "role:coding-agent", protocol: options.protocol.id,
    sessionTtlMs: 24 * 3_600_000, askFallback: "deny", failOpen: false, connector: { agentId: connectorAgentId(agentId) },
    historyId: openHistoryStore(historyPath, { inspect: true, witness: false }).state().eventHistoryHashes[0],
    decisions: { onAllow: "defer", onReadOnly: "defer" },
    policy: { sideEffecting: policy.sideEffecting, readOnly: policy.readOnly, unmapped: "ask" },
  };
  const config = validateConfig(raw, configFile);
  steps.push(...(await ensureAgent(owner, config)));
  steps.push(...(await ensureConnector(owner, config, options.now())));
  let grantId: string | undefined;
  if (options.allow.length > 0) {
    grantId = `grant:${config.agentId}:${options.now()}`;
    await owner.grant({ id: grantId, to: config.agentId, actions: [...new Set(options.allow)], resources: [`repo:${project}`], expiresAt: options.expiresAt });
    steps.push(`granted ${options.allow.join(", ")} on repo:${project} to ${config.agentId} until ${new Date(options.expiresAt).toISOString()} (${grantId})`);
  }
  // Verify before reporting success: the config, read back from disk, opens the history as the hook will.
  verifyConfig(config);
  writeFileSync(configFile, `${JSON.stringify(raw, null, 2)}\n`);
  const written = loadConfigFile(configFile);
  const head = verifyConfig(written);
  steps.push(`config ${configFile} written and verified (owner ${written.owner}, agent ${written.agentId}, controller ${written.controller}, head ${head})`);
  if (options.protocol.id === "codex") {
    // Codex runs no hook at all when its config turns hooks off (live check B of the Codex route): the user's to check.
    // The user's config, then the project's: the last value wins.
    let off: string | undefined;
    for (const file of codexConfigFiles(project, process.env)) {
      let text: string;
      try { text = readRegularFile(file, 1_048_576); } catch { continue; }
      const setting = codexHooksSetting(text);
      if (setting !== undefined) off = setting ? undefined : file;
    }
    if (off !== undefined) {
      warnings.push(`WARNING: ${off} sets [features] hooks = false: Codex runs no hooks there, so IronTrellis does not guard this project. Check it in your own terminal.`);
      notes.push(`${show(off)} turns Codex's hooks off ([features] hooks = false), so IronTrellis does not guard this project.`);
    }
  }
  if (options.protocol.id === "claude-code") {
    // Settings that would switch the guard off or run code beside it, found before the guard protects them: the user's to check.
    for (const file of claudeSettingsFiles(project, process.env)) {
      let doc: unknown;
      try { doc = JSON.parse(readRegularFile(file)); } catch { continue; }
      if (!isRecord(doc)) continue;
      const env = isRecord(doc.env) ? Object.keys(doc.env).filter((k) => /^(PATH$|NODE_|IRONTRELLIS_|CLAUDE_CONFIG_DIR$|DYLD_|LD_PRELOAD$|LD_LIBRARY_PATH$|LD_AUDIT$)/.test(k)) : [];
      if (doc.disableAllHooks === true) {
        warnings.push(`WARNING: ${file} sets "disableAllHooks": true: Claude Code runs no hooks there, so IronTrellis does not guard this project. Check it in your own terminal.`);
        notes.push(`${show(file)} sets "disableAllHooks": true, so IronTrellis does not guard this project.`);
      }
      if (env.length > 0) {
        warnings.push(`WARNING: ${file} sets ${env.join(", ")} in "env", which Claude Code gives the hooks: check that you set ${env.length === 1 ? "it" : "them"} yourself.`);
        notes.push(`${show(file)} gives the hooks ${env.join(", ")}: check that you set ${env.length === 1 ? "it" : "them"} yourself.`);
      }
    }
    // The plugin's launch.sh runs exactly this node and launcher (rewritten at every init, so a pin planted earlier does not survive).
    const pin = pinRuntime(options.stateHome);
    steps.push(`plugin runtime ${pin.file} written (node ${pin.node}, launcher ${pin.launcher})`);
  }
  return { configFile, history: historyPath, stateDir, ownerKey, created, steps, grant: grantId, config: written, gitignores, warnings, notes };
}

// ---------------------------------------------------------------- the interpreter and launcher, by absolute path

/**
 * The node to name in hook entries and the plugin's runtime pin: the PATH entry that resolves to this process's node (it
 * survives an upgrade that moves the real binary, e.g. Homebrew's /opt/homebrew/bin/node), else process.execPath.
 */
export function stableNode(env: Readonly<Record<string, string | undefined>> = process.env): string {
  const exec = realpathSync(process.execPath), named = onPath(process.platform === "win32" ? "node.exe" : "node", env);
  try { if (named !== undefined && realpathSync(named) === exec) return named; } catch { /* fall through */ }
  return process.execPath;
}
/** The command `install claude-code --write` writes by default: `/bin/sh -c '<HOOK_WRAPPER>' <node> <this package's launcher>` (no PATH lookup). */
export const hookCommand = (env: Readonly<Record<string, string | undefined>> = process.env): string => {
  const node = stableNode(env), launcher = realpathSync(OWN_LAUNCHER);
  if (HOOK_PATH_UNSAFE.test(node) || HOOK_PATH_UNSAFE.test(launcher)) throw new Error(`cannot write a hook entry for ${JSON.stringify(node)} ${JSON.stringify(launcher)}: a path with shell characters ($, quotes, ;, |, …); pass --command`);
  return hookEntryProgram(node, launcher);
};
/** Write the plugin's runtime pin (`<state home>/plugin-runtime`: the node, then the launcher's realpath; 0600). */
export function pinRuntime(stateHome: string, env: Readonly<Record<string, string | undefined>> = process.env): Readonly<{ file: string; node: string; launcher: string }> {
  const node = stableNode(env), launcher = realpathSync(OWN_LAUNCHER), file = join(stateHome, RUNTIME_PIN_NAME);
  if (/[\n\r]/.test(node + launcher)) throw new Error(`cannot pin a node or launcher path with a line break (${JSON.stringify(node)}, ${JSON.stringify(launcher)})`);
  ensurePrivateDir(stateHome);
  writePrivateFile(file, `${node}\n${launcher}\n`);
  return { file, node, launcher };
}

/** Open the history exactly as the hook does and read the agent; returns the head position. */
function verifyConfig(config: HookConfig): number {
  const owner = openOwner(config, () => Date.now());
  const report = owner.handover(config.agentId);
  const events = owner.exportHistory();
  const agent = events.find((e) => e.type === "AGENT_CREATED" && e.data.agentId === config.agentId);
  if (agent !== undefined && String(agent.data.controllerId) !== config.controller) throw new Error(`config check failed: ${config.agentId} is controlled by ${String(agent.data.controllerId)}, not ${config.controller}`);
  return report.head.position;
}

// ---------------------------------------------------------------- the hook's connector identity

/** `hooks:<host>` (docs/API.md §2), as an identifier: the host name's unusual characters become `-`. */
export const connectorAgentId = (agentId: string): string => {
  const host = hostname().toLowerCase().replace(/[^a-z0-9.-]+/g, "-").slice(0, 64) || "host";
  const id = `hooks:${host}`;
  return id === agentId ? `${id}:connector` : id;
};
/** One year: the connector session outlives agent sessions; init renews it when it expired or its key file is gone. */
const CONNECTOR_TTL_MS = 365 * 86_400_000;

/**
 * The hook's own agent and runtime session, created under the owner key (never by an agent): it signs CONNECTOR refusals
 * only (A-42 rendered resources, A-38.4 agents without a current session). Its key is kept in `<history>.connector.json`
 * (owner-only, under the protect list's history prefix). Idempotent: a current session with its key file is reused.
 */
export async function ensureConnector(owner: LocalOwner, config: HookConfig, now: number): Promise<readonly string[]> {
  if (config.connector === undefined || owner.format !== "irontrellis-event/2") return [];
  const agentId = config.connector.agentId, keyFile = connectorKeyFile(config.history), steps: string[] = [];
  if (!owner.exportHistory().some((e) => e.type === "AGENT_CREATED" && e.data.agentId === agentId)) {
    await owner.createAgent({ id: agentId });
    steps.push(`connector agent ${agentId} created (it signs CONNECTOR refusals only)`);
  }
  const held = readPrivateJson(keyFile) as Record<string, unknown> | null;
  if (held !== null && typeof held === "object" && held.version === CONNECTOR_KEY_VERSION && held.agentId === agentId && typeof held.sessionId === "string") {
    const session = owner.runtimeSession(held.sessionId);
    if (session !== null && session.controlEpoch === session.agentControlEpoch && !session.agentTerminated && (session.expiresAt === undefined || now < session.expiresAt)) return steps;
  }
  const sessionId = `${agentId}:${now}`;
  const pair = generateKeyPair("ed25519", sessionId);
  const epoch = owner.handover(agentId).sessions.reduce((max, s) => Math.max(max, s.controlEpoch), 1);
  await owner.admitRuntime({ session: sessionId, agent: agentId, epoch, key: sessionId, credential: pair.credential, expiresAt: now + CONNECTOR_TTL_MS });
  writePrivateFile(keyFile, `${JSON.stringify({ version: CONNECTOR_KEY_VERSION, agentId, sessionId, keyId: pair.keyId, scheme: pair.scheme, credential: pair.credential, privateKey: pair.privateKey, admittedAt: now }, null, 2)}\n`);
  steps.push(`connector session ${sessionId} admitted until ${new Date(now + CONNECTOR_TTL_MS).toISOString()} (key ${keyFile}, mode 0600)`);
  return steps;
}

// ---------------------------------------------------------------- session list / release (operator)

export type SessionEntry = Readonly<{ hostSessionId: string | undefined; sessionId: string; keyFile: string; current: boolean; released: boolean }>;

/** The session key files held for the config's agent, with whether each session is current in the history. */
export function listSessions(config: HookConfig, now: number): readonly SessionEntry[] {
  const owner = openOwner(config, () => now, "admin");
  const sessions = owner.handover(config.agentId, { at: now }).sessions;
  return sessionKeys(config).map((k) => ({ hostSessionId: k.hostSessionId, sessionId: k.sessionId, keyFile: k.path, current: sessions.some((s) => s.sessionId === k.sessionId && s.current), released: k.released }));
}

/** Release one host session (or all): its private key is removed, and the next SessionStart fences it. */
export function releaseSessions(config: HookConfig, hostSessionId: string | undefined, now: number): readonly SessionEntry[] {
  const keys = sessionKeys(config).filter((k) => hostSessionId === undefined || k.hostSessionId === hostSessionId);
  const released = new Set(keys.filter((k) => releaseSessionKey(k, now)).map((k) => k.path));
  return listSessions(config, now).filter((e) => released.has(e.keyFile));
}

// ---------------------------------------------------------------- install

const isRecord = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

/** One change `install` makes (or would make) to the settings file. */
export type InstallChange = Readonly<{
  /** added: our handler was missing; updated: our handler differed (old command/timeout); unchanged; removed: a duplicate of ours; setting: a top-level key we need was absent. */
  kind: "added" | "updated" | "unchanged" | "removed" | "setting";
  /** Where, e.g. `hooks.PreToolUse` or `version`. */
  path: string;
  before?: unknown;
  after?: unknown;
}>;
export type SettingsPlan = Readonly<{ settings: Record<string, unknown>; changes: readonly InstallChange[]; changed: boolean }>;

/** Canonical JSON (sorted keys) for comparing handlers regardless of key order. */
const canonical = (value: unknown): string => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (isRecord(value)) return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
  return JSON.stringify(value);
};
const unquote = (token: string): string => token.replace(/^["']+|["']+$/g, "");
/** `irontrellis-hook` as a program: by name or path, with a Windows or script suffix. */
const isHookProgram = (token: string): boolean => /^irontrellis-hook(\.cmd|\.ps1|\.js|\.mjs|\.exe)?$/i.test(unquote(token).split(/[\\/]/).pop() ?? "");
/** For the look-alike net: quotes, backslashes, carets and backticks removed, lower case. */
const normalized = (text: string): string => text.replace(/['"\\`^]/g, "").toLowerCase();

/** The handlers in one event entry: a Claude Code / Codex matcher group (`{ hooks: [...] }`) or a Cursor handler itself. */
const handlersOf = (entry: unknown): readonly unknown[] =>
  isRecord(entry) && Array.isArray(entry.hooks) ? entry.hooks : isRecord(entry) && typeof entry.command === "string" ? [entry] : [];
/** A matcher group that applies to every tool: no matcher, `""` or `"*"`. */
const isCatchAll = (group: Record<string, unknown>): boolean => group.matcher === undefined || group.matcher === "" || group.matcher === "*";

/**
 * The program part is the hook itself: `irontrellis-hook` (by name or path) as the only token, or after `npx` and its
 * flags (`--no-install`, `-y`, `-p <pkg>` …). A wrapper (`env X=1 audit irontrellis-hook`, `a; irontrellis-hook`) is
 * not: keeping or dropping it is the operator's call, so such an entry is refused unless it is given as `--command`.
 */
const isPlainHookProgram = (program: string): boolean => {
  // The forms install writes, any node (a node upgrade must not make an entry foreign): `/bin/sh -c '<HOOK_WRAPPER>' <node>
  // <launcher>` now, and `<node> <launcher>` (3e3cf1d).
  const quoted = shellWords(program);
  const isNode = (w: string): boolean => /^node(\.exe)?$/i.test(w.split(/[\\/]/).pop() ?? "");
  if (quoted.length === 5 && quoted[0] === "/bin/sh" && quoted[1] === "-c" && [HOOK_WRAPPER, ...EARLIER_HOOK_WRAPPERS].includes(quoted[2]!) && isNode(quoted[3]!) && isHookProgram(quoted[4]!)) return true;
  if (quoted.length === 2 && isNode(quoted[0]!) && isHookProgram(quoted[1]!)) return true;
  const tokens = program.split(/\s+/);
  if (tokens.length === 1) return isHookProgram(tokens[0]!);
  if (tokens[0] !== "npx") return false;
  let i = 1;
  while (i < tokens.length - 1) {
    const t = tokens[i]!;
    if (t === "-p" || t === "--package") { i += 2; continue; }
    if (/^(--no-install|--yes|-y|--no|-q|--quiet|--package=\S+)$/.test(t)) { i += 1; continue; }
    return false;
  }
  return i === tokens.length - 1 && isHookProgram(tokens[i]!);
};

export type PlanOptions = Readonly<{
  /** The command IronTrellis's entries run now (`install --command`). */
  command?: string;
  /** An earlier `--command` whose entries are IronTrellis's too, to be replaced (`install --replace-command`). */
  replaceCommand?: string;
}>;

type Verdict = "ours" | "foreign" | Readonly<{ ambiguous: string }>;

/**
 * Classify a handler found under `event`. Ours: the command ends with exactly ` <agent> <event>` and its program is the
 * plain hook, the `--command` given now or the `--replace-command`. Anything else that mentions irontrellis-hook
 * (any case, quotes and escapes removed) or ends with the ` <agent> <event>` tail is ambiguous (refused with a hint).
 */
const classify = (handler: unknown, agent: string, event: string, options: PlanOptions): Verdict => {
  const text = isRecord(handler) && typeof handler.command === "string" ? handler.command.trim() : undefined;
  const tail = ` ${agent} ${event}`;
  if (text !== undefined && text.endsWith(tail)) {
    const program = text.slice(0, -tail.length).trim();
    if (program !== "" && (program === options.command?.trim() || program === options.replaceCommand?.trim() || isPlainHookProgram(program))) return "ours";
    return { ambiguous: `it runs ${JSON.stringify(program)} with this event's IronTrellis arguments (if it is an earlier IronTrellis entry, pass --replace-command ${JSON.stringify(program)}; to keep a wrapper, pass it as --command)` };
  }
  if (normalized(JSON.stringify(handler)).includes("irontrellis-hook")) return { ambiguous: "it mentions irontrellis-hook but is not an entry install writes" };
  if (text !== undefined && normalized(text).trimEnd().endsWith(normalized(tail))) return { ambiguous: "it ends with this event's IronTrellis arguments" };
  return "foreign";
};

/** The agent id and command our entry was built with (`<command> <agent> <event>`). */
const entryIdentity = (entry: InstallEntry): { agent: string; command: string } => {
  const hooks = entry.content.hooks as Record<string, readonly unknown[]>;
  const [event, entries] = Object.entries(hooks)[0]!;
  const text = (handlersOf(entries[0])[0] as { command: string }).command;
  const words = text.slice(0, -(event.length + 1)).trimEnd();
  const agent = words.slice(words.lastIndexOf(" ") + 1);
  return { agent, command: words.slice(0, words.length - agent.length).trimEnd() };
};

/**
 * Plan the merge of our hook entries into an existing settings document. Only IronTrellis's own handlers are
 * touched (see `classify`): a missing one is added, one with an old command or timeout is replaced in place, and
 * duplicates of ours in the same event are removed. Ours counts as installed only in a catch-all group (no matcher,
 * `""` or `"*"`); a copy under any other matcher would run for those tools only, so the document is refused rather than
 * "repaired". Every other key, event and handler is kept, in its order. Refuses (throws) a document
 * it cannot merge safely: not an object, `hooks` or an event list of the wrong type, or an ambiguous handler.
 */
export function planSettings(existing: unknown, entry: InstallEntry, file = entry.path, options: PlanOptions = {}): SettingsPlan {
  if (existing !== undefined && !isRecord(existing)) throw new Error(`${file} is not a JSON object; refusing to overwrite it (fix or move it aside, then install again)`);
  const identity = entryIdentity(entry), agent = identity.agent;
  const opts: PlanOptions = { command: options.command ?? identity.command, ...(options.replaceCommand === undefined ? {} : { replaceCommand: options.replaceCommand }) };
  const base: Record<string, unknown> = { ...(existing ?? {}) };
  const changes: InstallChange[] = [];
  for (const [key, value] of Object.entries(entry.content)) {
    if (key !== "hooks") {
      if (base[key] === undefined) { base[key] = value; changes.push({ kind: "setting", path: key, after: value }); }
      continue;
    }
    if (base.hooks !== undefined && !isRecord(base.hooks)) throw new Error(`${file}: "hooks" is not an object; refusing to overwrite it`);
    const hooks: Record<string, unknown> = { ...((base.hooks as Record<string, unknown> | undefined) ?? {}) };
    for (const [event, ourEntries] of Object.entries(value as Record<string, readonly unknown[]>)) {
      const path = `hooks.${event}`;
      if (hooks[event] !== undefined && !Array.isArray(hooks[event])) throw new Error(`${file}: "${path}" is not a list; refusing to overwrite it`);
      const ourHandler = handlersOf(ourEntries[0])[0] as Record<string, unknown>;
      const current: unknown[] = [...((hooks[event] as unknown[] | undefined) ?? [])];
      // Locate our handlers: [entry index, handler index or -1 for a Cursor-style handler entry].
      const found: [number, number][] = [];
      const check = (h: unknown, where: string): boolean => {
        const verdict = classify(h, agent, event, opts);
        if (verdict === "ours") return true;
        if (verdict !== "foreign") throw ambiguous(file, `${path}${where}`, h, verdict.ambiguous);
        return false;
      };
      current.forEach((e, i) => {
        if (isRecord(e) && Array.isArray(e.hooks)) {
          e.hooks.forEach((h, j) => {
            if (!check(h, "")) return;
            if (!isCatchAll(e)) {
              throw new Error(`${file}: ${path} has IronTrellis's hook under matcher ${JSON.stringify(e.matcher)}, so it would run only for those tools; refusing to count it as installed or to change the file (remove that entry or its matcher group by hand, then install again): ${JSON.stringify(h)}`);
            }
            found.push([i, j]);
          });
        } else if (check(e, "")) found.push([i, -1]);
      });
      if (found.length === 0) {
        current.push(...ourEntries);
        changes.push({ kind: "added", path, after: ourHandler });
      } else {
        const handlerAt = ([i, j]: [number, number]): unknown => (j < 0 ? current[i] : (current[i] as { hooks: unknown[] }).hooks[j]);
        const [first, ...duplicates] = found;
        const before = handlerAt(first!);
        // Duplicates first, from the end, so earlier indices stay valid; a matcher group left empty goes too.
        for (const [i, j] of [...duplicates].reverse()) {
          changes.push({ kind: "removed", path, before: handlerAt([i, j]) });
          if (j < 0) { current.splice(i, 1); continue; }
          const group = { ...(current[i] as Record<string, unknown>) }, list = [...(group.hooks as unknown[])];
          list.splice(j, 1);
          if (list.length === 0) current.splice(i, 1);
          else { group.hooks = list; current[i] = group; }
        }
        if (canonical(before) === canonical(ourHandler)) changes.push({ kind: "unchanged", path, after: ourHandler });
        else {
          const [i, j] = first!;
          if (j < 0) current[i] = ourHandler;
          else { const group = { ...(current[i] as Record<string, unknown>) }, list = [...(group.hooks as unknown[])]; list[j] = ourHandler; group.hooks = list; current[i] = group; }
          changes.push({ kind: "updated", path, before, after: ourHandler });
        }
      }
      hooks[event] = current;
    }
    base.hooks = hooks;
  }
  return { settings: base, changes, changed: changes.some((c) => c.kind !== "unchanged") };
}

const ambiguous = (file: string, path: string, handler: unknown, why: string): Error =>
  new Error(`${file}: ${path} has an entry install cannot classify: ${JSON.stringify(handler)}; ${why}. Refusing to change the file: edit or remove that entry by hand, then install again`);

/** Merge our entries into an existing settings document (see `planSettings`); returns the merged document. */
export function mergeSettings(existing: unknown, entry: InstallEntry, options: PlanOptions = {}): Record<string, unknown> {
  return planSettings(existing, entry, entry.path, options).settings;
}

/**
 * The first number literal in `text` (outside strings) that JSON cannot write back as it is (`12345678901234567890`,
 * `1.0`, `1e3`, `-0`): rewriting would silently change it.
 */
export function lossyNumber(text: string): { literal: string; rewritten: string } | undefined {
  const re = /"(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;
  for (let m = re.exec(text); m !== null; m = re.exec(text)) {
    const literal = m[0];
    if (literal.startsWith("\"")) continue;
    const rewritten = JSON.stringify(JSON.parse(literal));
    if (rewritten !== literal) return { literal, rewritten };
  }
  return undefined;
}

/** A minimal unified diff (3 lines of context) between two texts, for `install --dry-run`. */
export function unifiedDiff(before: string, after: string, name: string): string {
  const a = before === "" ? [] : before.replace(/\n$/, "").split("\n"), b = after.replace(/\n$/, "").split("\n");
  const n = a.length, m = b.length;
  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i -= 1) for (let j = m - 1; j >= 0; j -= 1) lcs[i]![j] = a[i] === b[j] ? lcs[i + 1]![j + 1]! + 1 : Math.max(lcs[i + 1]![j]!, lcs[i]![j + 1]!);
  const ops: { op: " " | "-" | "+"; line: string; ai: number; bi: number }[] = [];
  let i = 0, j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && a[i] === b[j]) { ops.push({ op: " ", line: a[i]!, ai: i, bi: j }); i += 1; j += 1; }
    else if (i < n && (j >= m || lcs[i + 1]![j]! >= lcs[i]![j + 1]!)) { ops.push({ op: "-", line: a[i]!, ai: i, bi: j }); i += 1; }
    else { ops.push({ op: "+", line: b[j]!, ai: i, bi: j }); j += 1; }
  }
  const changed = ops.flatMap((o, k) => (o.op === " " ? [] : [k]));
  if (changed.length === 0) return "";
  // Hunks: each change with 3 lines of context, merged where they touch.
  const ranges: [number, number][] = [];
  for (const k of changed) {
    const lo = Math.max(0, k - 3), hi = Math.min(ops.length, k + 4), last = ranges[ranges.length - 1];
    if (last !== undefined && lo <= last[1]) last[1] = Math.max(last[1], hi); else ranges.push([lo, hi]);
  }
  const out = [`--- ${name}${before === "" ? " (new file)" : ""}`, `+++ ${name}`];
  for (const [lo, hi] of ranges) {
    const hunk = ops.slice(lo, hi);
    const aCount = hunk.filter((o) => o.op !== "+").length, bCount = hunk.filter((o) => o.op !== "-").length;
    out.push(`@@ -${hunk[0]!.ai + (aCount === 0 ? 0 : 1)},${aCount} +${hunk[0]!.bi + (bCount === 0 ? 0 : 1)},${bCount} @@`);
    for (const o of hunk) out.push(`${o.op}${o.line}`);
  }
  return `${out.join("\n")}\n`;
}

export type InstallResult = Readonly<{
  file: string;
  /** The file was written (only with write, when something changed). */
  written: boolean;
  /** Something in the file would change (false: already up to date, nothing written). */
  changed: boolean;
  changes: readonly InstallChange[];
  /** Unified diff of the file, before → after ("" when nothing changes). */
  diff: string;
  /** Loud notes for the operator (a `disableAllHooks` accepted with allowDisabled). */
  warnings: readonly string[];
  settings: Record<string, unknown>;
  snippet: InstallEntry;
}>;
export type InstallOptions = Readonly<{ replaceCommand?: string; allowDisabled?: boolean }>;

/** The file's indentation (first indented line), so a rewrite keeps its style; 2 spaces for a new file. */
const indentOf = (text: string): string | number => /\n([ \t]+)\S/.exec(text)?.[1] ?? 2;

/** Settings files that switch every hook off (Claude Code `disableAllHooks`), this one or a local override beside it. */
function disabledBy(protocol: Protocol, file: string, settings: unknown): string[] {
  const found: string[] = [];
  if (isRecord(settings) && settings.disableAllHooks === true) found.push(file);
  if (protocol.id === "claude-code") {
    const local = join(dirname(file), "settings.local.json");
    if (existsSync(local)) {
      try { const doc: unknown = JSON.parse(readRegularFile(local)); if (isRecord(doc) && doc.disableAllHooks === true) found.push(local); } catch { /* not ours to judge */ }
    }
  }
  return found;
}

/**
 * Write `text` over `file` atomically: a temporary file in the directory of the real target
 * (a symlinked settings file stays a symlink), the target's mode, fsync, a re-check that the file still holds exactly
 * what was read (`expected`; undefined: it did not exist), rename, directory fsync.
 */
export function writeSettingsAtomically(file: string, text: string, expected: string | undefined): void {
  const target = expected === undefined ? file : realpathSync(file);
  const dir = dirname(target);
  mkdirSync(dir, { recursive: true });
  const mode = expected === undefined ? 0o644 : statSync(target).mode & 0o7777;
  const temporary = join(dir, `.${basename(target)}.irontrellis-${process.pid}-${randomBytes(4).toString("hex")}.tmp`);
  const fd = openSync(temporary, "wx", mode);
  try {
    try { writeSync(fd, text); fchmodSync(fd, mode); fsyncSync(fd); } finally { closeSync(fd); }
    const now = existsSync(target) ? readRegularFile(target) : undefined;
    if (now !== expected) throw new Error(`${file} changed while install was running (another program wrote it); nothing was written: run install again`);
    renameSync(temporary, target);
  } catch (error) {
    try { unlinkSync(temporary); } catch { /* already renamed or gone */ }
    throw error;
  }
  if (process.platform !== "win32") {
    try { const d = openSync(dir, "r"); try { fsyncSync(d); } finally { closeSync(d); } } catch { /* best effort */ }
  }
}

/**
 * Plan (and with `write`, apply) our hook entries in the host's settings file. Malformed JSON, a document that
 * cannot be merged safely, numbers JSON cannot write back exactly, or hooks switched off (`disableAllHooks`, unless
 * `allowDisabled`) are refused with a message and the file is left as it is. A file already up to date is not
 * rewritten (idempotent, byte for byte); a changed one is replaced atomically.
 */
export function install(protocol: Protocol, project: string, command: string, write: boolean, options: InstallOptions = {}): InstallResult {
  const snippet = protocol.install(command);
  const file = resolve(project, snippet.path);
  let existing: unknown, text: string | undefined;
  if (existsSync(file)) {
    text = readRegularFile(file);
    try { existing = JSON.parse(text); } catch (error) {
      throw new Error(`${file} is not valid JSON (${error instanceof Error ? error.message : String(error)}); refusing to overwrite it: fix it or move it aside, then install again`);
    }
  }
  const warnings: string[] = [];
  const disabled = disabledBy(protocol, file, existing);
  if (disabled.length > 0) {
    const note = `WARNING: "disableAllHooks": true in ${disabled.join(" and ")}: the host runs NO hooks, so IronTrellis would not guard anything`;
    if (options.allowDisabled !== true) throw new Error(`${note}; refusing to report the hooks as installed (remove the setting, or pass --allow-disabled to install anyway)`);
    warnings.push(note);
  }
  // Both install routes (route.ts): with the IronTrellis plugin for Claude Code enabled, the plugin steps aside once these entries
  // are written and verified; say so, so that one route is chosen deliberately.
  if (protocol.id === "claude-code" && pluginEnabled(project, process.env)) {
    warnings.push("NOTE: the IronTrellis plugin for Claude Code (`irontrellis` in /plugin) is enabled for this project too; once these hook entries are in place it steps aside and this hook is the one guard (choose one route per project: disable the plugin, or remove these entries)");
  }
  const plan = planSettings(existing, snippet, file, { command, ...(options.replaceCommand === undefined ? {} : { replaceCommand: options.replaceCommand }) });
  if (plan.changed && text !== undefined) {
    const lossy = lossyNumber(text);
    if (lossy !== undefined) throw new Error(`${file} holds the number ${lossy.literal}, which JSON cannot write back exactly (it would become ${lossy.rewritten}); refusing to rewrite the file: write that value as a string or add the hooks by hand`);
  }
  const after = `${JSON.stringify(plan.settings, null, text === undefined ? 2 : indentOf(text))}${text === undefined || text.endsWith("\n") ? "\n" : ""}`;
  const diff = plan.changed ? unifiedDiff(text ?? "", after, snippet.path) : "";
  let written = false;
  if (write && plan.changed) {
    writeSettingsAtomically(file, after, text);
    written = true;
  }
  return { file, written, changed: plan.changed, changes: plan.changes, diff, warnings, settings: plan.settings, snippet };
}

/** Human lines for `install`'s changes. */
export function describeChanges(changes: readonly InstallChange[]): string[] {
  const cmd = (h: unknown): string => (isRecord(h) ? `${String(h.command)}${h.timeout === undefined ? "" : ` (timeout ${String(h.timeout)})`}${h.failClosed === true ? " failClosed" : ""}${typeof h.onFailure === "string" ? ` onFailure ${h.onFailure}` : ""}` : JSON.stringify(h));
  return changes.map((c) => {
    switch (c.kind) {
      case "added": return `  + ${c.path}: ${cmd(c.after)}`;
      case "updated": return `  ~ ${c.path}: ${cmd(c.before)}  ->  ${cmd(c.after)}`;
      case "removed": return `  - ${c.path}: ${cmd(c.before)} (duplicate)`;
      case "setting": return `  + ${c.path}: ${JSON.stringify(c.after)}`;
      default: return `  = ${c.path}: ${cmd(c.after)}`;
    }
  });
}
