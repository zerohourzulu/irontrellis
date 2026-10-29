/**
 * The two install routes of the Claude Code guard (founder 4bu; the coordinator's design OK of 2026-10-23): the
 * `irontrellis` Claude Code plugin and the hook entries `irontrellis-hook install claude-code --write` writes. They run the
 * same guard; each detects the other, and only one decides.
 *
 * States of a project (the realpath of CLAUDE_PROJECT_DIR, else the working directory), in this order of precedence:
 *   hook      a verified hook route: for all four events, the project or user settings hold exactly the entry install
 *             writes, `<absolute node> <this package's launcher> claude-code <Event>`. The plugin steps aside.
 *   both      as hook, with the plugin enabled too: the plugin steps aside, the hook warns once at SessionStart.
 *   plugin    an irontrellis-hook.json is found (or IRONTRELLIS_HOOK_CONFIG names one): the plugin runs the guard.
 *   declined  not set up, and the user chose `irontrellis-hook choose --decline` for this project: the plugin is silent.
 *   undecided not set up and no choice: the plugin shows a notice at each session start (not after a compaction) and leaves tool calls to the host.
 * A stored choice never applies once a config or a verified hook route exists: only an unconfigured project is declined.
 * In undecided and declined the plugin still refuses the agent's own attempts to choose, set up or edit the choice; these
 * shell-pattern refusals are best effort (a command can build a path dynamically). In plugin, hook and both the guard
 * protects Claude Code's whole configuration and its own (protect.ts, rule 3).
 * The route a session is admitted under is recorded per host session: when its config later vanishes or changes, the
 * plugin refuses the session's tool calls rather than treating the project as undecided.
 */
import { accessSync, constants, existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, resolve } from "node:path";
import { CONFIG_ENV, CONFIG_FILE, findConfigFile } from "./config.ts";
import { canonicalProject, CHOICE_FILE_NAME, choiceFile, ensurePrivateDir, physicalPath, readPrivateJson, realpathLoose, readRegularFile, removePrivateFile, routeSessionFile, runtimePinFile, writePrivateFile } from "./paths.ts";
import { claudeSettingsFiles, commandSpellings, controlCommand, FILE_TOOLS, HOOK_PATH_UNSAFE, hookEntryProgram, OWN_LAUNCHER, setupRefusal, SHELL_TOOLS, shellWords } from "./protect.ts";
import { protocolFor } from "./protocols/index.ts";
import type { Reply } from "./protocols/types.ts";

export const ROUTE_CHOICE_VERSION = "irontrellis-route-choice/1";
export type RouteChoice = "declined" | "use-hook";
export type RouteState = "undecided" | "declined" | "plugin" | "hook" | "both";
type Env = Readonly<Record<string, string | undefined>>;

/** The events and timeouts `install claude-code --write` writes (protocols/claude-code.ts). */
export const CLAUDE_EVENTS: Readonly<Record<string, number>> = Object.freeze({ SessionStart: 30, PreToolUse: 30, Stop: 30, SessionEnd: 10 });
/** The events whose entry also carries `"onFailure": "block"` (a timeout refuses the call, KI 61). */
export const BLOCK_ON_FAILURE: readonly string[] = Object.freeze(["PreToolUse"]);
/** This package's own launcher; a verified hook route must run it. */
export const OWN_BIN = OWN_LAUNCHER;

const isRecord = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const realOrSelf = (p: string): string => { try { return realpathSync(p); } catch { return p; } };

// ---------------------------------------------------------------- the choice store

/** The choice file (paths.ts): `<state home>/route-choices.json`, the state home being ~/.irontrellis or IRONTRELLIS_HOME. */
export { CHOICE_FILE_NAME, choiceFile };
export type ChoiceDocument = Readonly<{ projects: Readonly<Record<string, Readonly<{ choice: RouteChoice; at: string }>>>; corrupt: boolean }>;

export function readChoices(env: Env): ChoiceDocument {
  const file = choiceFile(env);
  if (!existsSync(file)) return { projects: {}, corrupt: false };
  const doc = readPrivateJson(file, 1_048_576);
  if (!isRecord(doc) || doc.version !== ROUTE_CHOICE_VERSION || !isRecord(doc.projects)) return { projects: {}, corrupt: true };
  const projects: Record<string, { choice: RouteChoice; at: string }> = {};
  for (const [key, value] of Object.entries(doc.projects)) {
    if (isRecord(value) && (value.choice === "declined" || value.choice === "use-hook") && typeof value.at === "string") projects[key] = { choice: value.choice, at: value.at };
  }
  return { projects, corrupt: false };
}

/** Record (or with `choice` undefined, remove) this project's choice; the file is written whole, 0600, by rename. */
export function writeChoice(env: Env, project: string, choice: RouteChoice | undefined, now: number): string {
  const file = choiceFile(env), current = readChoices(env);
  const projects: Record<string, unknown> = { ...current.projects };
  if (choice === undefined) delete projects[project];
  else projects[project] = { choice, at: new Date(now).toISOString() };
  writePrivateFile(file, `${JSON.stringify({ version: ROUTE_CHOICE_VERSION, projects }, null, 2)}\n`);
  return file;
}

// ---------------------------------------------------------------- the settings files

/** The settings files Claude Code reads hooks and enabled plugins from (the user's in CLAUDE_CONFIG_DIR when set): protect.ts. */
export const settingsFiles = (project: string, env: Env): readonly string[] => claudeSettingsFiles(project, env);
const readSettings = (file: string): Record<string, unknown> | undefined => {
  try { const doc: unknown = JSON.parse(readRegularFile(file)); return isRecord(doc) ? doc : undefined; } catch { return undefined; }
};

/** Whether the `irontrellis` plugin is enabled (user, then project, then local settings; a later file overrides). */
export function pluginEnabled(project: string, env: Env): boolean {
  let enabled = false;
  for (const file of settingsFiles(project, env)) {
    const plugins = readSettings(file)?.enabledPlugins;
    if (!isRecord(plugins)) continue;
    for (const [key, value] of Object.entries(plugins)) if (key.split("@")[0] === "irontrellis" && typeof value === "boolean") enabled = value;
  }
  return enabled;
}

/**
 * Whether Claude Code's settings switch every hook off (`"disableAllHooks": true`; user, then project, then local, a later
 * file overriding): then neither route runs the guard (independent review A, RA-04).
 */
export function hooksDisabled(project: string, env: Env): boolean {
  let disabled = false;
  for (const file of settingsFiles(project, env)) {
    const value = readSettings(file)?.disableAllHooks;
    if (typeof value === "boolean") disabled = value;
  }
  return disabled;
}

export type HookRoute = Readonly<{ verified: boolean; unrecognized: readonly string[]; files: readonly string[] }>;

/** An absolute, executable regular file (the interpreter a hook entry names). */
const executable = (p: string): boolean => { try { return statSync(p).isFile() && (accessSync(p, constants.X_OK), true); } catch { return false; } };
const sameKeys = (o: Record<string, unknown>, keys: readonly string[]): boolean => Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k));

/**
 * The hook route in the settings files. Verified: for every one of the four events, some catch-all group (keys `hooks`,
 * and `matcher` "", "*" or absent) holds a handler with exactly install's keys, `type: "command"`, install's timeout (and for
 * PreToolUse `"onFailure": "block"`) and
 * exactly the command install writes, `/bin/sh -c '<HOOK_WRAPPER>' <node> <launcher> claude-code <Event>`, where <node> is
 * an absolute executable, <launcher> resolves through symlinks to this package's own launcher, and neither holds a shell
 * metacharacter. Any other handler that mentions
 * irontrellis-hook (any case, quotes and escapes removed) is listed as unrecognized; it never makes the plugin step aside.
 */
export function hookRoute(project: string, env: Env, ownBin: string = OWN_BIN): HookRoute {
  const own = realOrSelf(ownBin), found = new Set<string>(), unrecognized: string[] = [], files: string[] = [];
  for (const file of settingsFiles(project, env)) {
    const hooks = readSettings(file)?.hooks;
    if (!isRecord(hooks)) continue;
    for (const [event, groups] of Object.entries(hooks)) {
      if (!Array.isArray(groups)) continue;
      for (const group of groups) {
        if (!isRecord(group) || !Array.isArray(group.hooks)) continue;
        const catchAll = (group.matcher === undefined || group.matcher === "" || group.matcher === "*") && (sameKeys(group, ["hooks"]) || sameKeys(group, ["matcher", "hooks"]));
        for (const handler of group.hooks) {
          if (!isRecord(handler)) continue;
          const command = typeof handler.command === "string" ? handler.command.trim() : "";
          const mentions = JSON.stringify(handler).replace(/['"\\`^]/g, "").toLowerCase().includes("irontrellis-hook");
          // Exactly install's entry, rebuilt from its node and launcher: no other quoting, metacharacter or word passes.
          const words = shellWords(command), node = words[3] ?? "", launcher = words[4] ?? "";
          const keys = BLOCK_ON_FAILURE.includes(event) ? ["type", "command", "timeout", "onFailure"] : ["type", "command", "timeout"];
          const ok = catchAll && sameKeys(handler, keys) && handler.type === "command" && Object.hasOwn(CLAUDE_EVENTS, event) && handler.timeout === CLAUDE_EVENTS[event] &&
            (!BLOCK_ON_FAILURE.includes(event) || handler.onFailure === "block") &&
            words.length === 7 && !HOOK_PATH_UNSAFE.test(node) && !HOOK_PATH_UNSAFE.test(launcher) && command === `${hookEntryProgram(node, launcher)} claude-code ${event}` &&
            isAbsolute(node) && executable(node) && isAbsolute(launcher) && realOrSelf(launcher) === own;
          if (ok) { found.add(event); if (!files.includes(file)) files.push(file); }
          else if (mentions) unrecognized.push(`${file}: ${event}: ${command === "" ? JSON.stringify(handler) : command}`);
        }
      }
    }
  }
  return { verified: Object.keys(CLAUDE_EVENTS).every((e) => found.has(e)), unrecognized, files };
}

// ---------------------------------------------------------------- the state

export type RouteStatus = Readonly<{ project: string; state: RouteState; config: string | undefined; hook: HookRoute; pluginEnabled: boolean; hooksDisabled: boolean; choice: RouteChoice | undefined; choiceFile: string; choiceCorrupt: boolean }>;

export const projectOf = (env: Env, cwd: string): string => canonicalProject(env.CLAUDE_PROJECT_DIR !== undefined && env.CLAUDE_PROJECT_DIR !== "" ? env.CLAUDE_PROJECT_DIR : cwd);

export function routeStatus(env: Env, cwd: string, ownBin: string = OWN_BIN): RouteStatus {
  const project = projectOf(env, cwd);
  const fromEnv = env[CONFIG_ENV];
  const config = fromEnv !== undefined && fromEnv !== "" ? resolve(cwd, fromEnv) : findConfigFile(project);
  const hook = hookRoute(project, env, ownBin), enabled = pluginEnabled(project, env);
  const choices = readChoices(env), choice = choices.projects[project]?.choice;
  const state: RouteState = hook.verified ? (enabled ? "both" : "hook") : config !== undefined ? "plugin" : choice === "declined" ? "declined" : "undecided";
  return { project, state, config, hook, pluginEnabled: enabled, hooksDisabled: hooksDisabled(project, env), choice, choiceFile: choiceFile(env), choiceCorrupt: choices.corrupt };
}

/**
 * `irontrellis-hook statusline` (founder's live check 01): one line for Claude Code's `statusLine` setting, which the
 * user adds to their own settings (IronTrellis never writes it; in a guarded project the agent cannot change it). Guarded
 * means a route that runs the guard is in place: a verified hook route, or a config with the plugin enabled.
 * `admitted` (founder's live check 02): false when the statusLine input names a session the guard did not admit at
 * SessionStart, such as the session in which `choose 2` set the project up; undefined when no session is named.
 */
export function statusLine(status: RouteStatus, admitted?: boolean): string {
  // Claude Code runs no hook at all: whatever is set up, nothing guards this project (RA-04).
  if (status.hooksDisabled && (status.state === "hook" || status.state === "both" || (status.state === "plugin" && status.pluginEnabled))) return "IronTrellis: set up, but not guarded (Claude Code's disableAllHooks is on)";
  const later = admitted === false ? "guarded from the next session" : "guarded";
  const notThis = admitted === false ? "; this session is not admitted" : "";
  switch (status.state) {
    case "hook": return `IronTrellis: ${later} (hook route${notThis})`;
    case "both": return `IronTrellis: ${later} (hook route; the plugin steps aside${notThis})`;
    case "plugin": return status.pluginEnabled ? `IronTrellis: ${later} (plugin route${notThis})` : "IronTrellis: set up, but not guarded (enable the IronTrellis plugin, or install the hook)";
    case "declined": return "IronTrellis: declined for this project";
    case "undecided": return status.choice === "use-hook" ? "IronTrellis: not set up (hook route chosen)" : "IronTrellis: not set up";
  }
}

// ---------------------------------------------------------------- the plugin's events

/**
 * The notice (founder's live check 01): numbered choices the user types here with Claude Code's `!` prefix (the command
 * then runs as the user's own, outside the hooks) or in their own terminal; `choose 1|2|3` are the short forms of
 * `--decline`, `init --agent claude-code` (the plugin route) and `--use-hook`.
 */
/** Founder's live check 02: `/exit` gives Claude no turn to remind the user, so the notice says it itself. */
export const LEAVE_LINE = "If you leave without choosing, you'll see this again next time.";
export const NOTICE_LINES = (status: RouteStatus): readonly string[] => status.choice === "use-hook" ? [
  `IronTrellis is enabled for ${status.project}; you chose the hook route, which is not set up yet. Type these here with the \`!\` prefix, or run them in your own terminal:`,
  "  ! irontrellis-hook init --agent claude-code",
  "  ! irontrellis-hook install claude-code --write",
  "Then start a new session. `! irontrellis-hook choose --status` shows this project's setting.",
  LEAVE_LINE,
] : [
  `IronTrellis is enabled for ${status.project} but not set up here. Choose one: type it here with the \`!\` prefix, or run it in your own terminal:`,
  "  1. ! irontrellis-hook choose 1   proceed without IronTrellis in this project",
  "  2. ! irontrellis-hook choose 2   set IronTrellis up here (the plugin route; then start a new session)",
  "  3. ! irontrellis-hook choose 3   use the hook route instead (then init, and install claude-code --write)",
  "`! irontrellis-hook choose --status` shows this project's setting.",
  LEAVE_LINE,
];

/**
 * What the agent is told beside the notice (SessionStart additionalContext): the user's choices, that only the user may
 * make one, and (founder's live check 01) what to say if the session ends with no choice made.
 */
export const NOTICE_CONTEXT = (status: RouteStatus): string => [
  `The user has been told: ${NOTICE_LINES(status).join("\n")}`,
  "Only the user may make this choice: do not run `irontrellis-hook choose`, `init` or `pin-runtime` yourself (IronTrellis refuses them); suggest the `!` command instead.",
  "If this session ends and the user has made no choice, say so when you sign off: \"Your choice about IronTrellis for this project hasn't been made yet, so you'll see this setup prompt next time, unless you run `! irontrellis-hook choose 1` (or 2 or 3).\"",
].join("\n");

/**
 * In undecided and declined: the agent may not make the choice for the user or set IronTrellis up: not run `choose`,
 * `init` or `pin-runtime`, not write the choice file or the plugin's runtime pin, not create an irontrellis-hook.json
 * (best effort for shell commands; a file tool is refused by its path).
 */
export function choiceProtection(env: Env, toolName: string, toolInput: Readonly<Record<string, unknown>>, cwd?: string): string | undefined {
  // Each also through its longest existing prefix (realpathLoose): a state home reached through a symlink must match while
  // the file does not exist yet (RA-14, where realOrSelf falls back to the unresolved path).
  const file = choiceFile(env), pin = runtimePinFile(env);
  const spellings_ = (f: string): string[] => [...new Set([f, realOrSelf(f), realpathLoose(f), physicalPath(f, "/")])];
  const files = spellings_(file), pins = spellings_(pin);
  const SETUP = "setting IronTrellis up is the user's act, not the agent's";
  if (FILE_TOOLS.includes(toolName)) {
    const target = ["file_path", "notebook_path", "path", "target_file"].map((k) => toolInput[k]).find((v): v is string => typeof v === "string");
    if (target === undefined) return undefined;
    // A relative path is the agent's: from the event's cwd (RA-07), not this process's; lexically and as the file system
    // takes it (each symlink followed before a later `..`, RA-01).
    const base = cwd !== undefined && isAbsolute(cwd) ? cwd : process.cwd();
    const ats = [realOrSelf(resolve(base, target)), realpathLoose(resolve(base, target)), physicalPath(target, base)];
    if (ats.some((at) => files.includes(at))) return "the IronTrellis route choice is the user's, not the agent's";
    if (ats.some((at) => pins.includes(at) || basename(at).toLowerCase() === CONFIG_FILE)) return SETUP;
    return undefined;
  }
  if (!SHELL_TOOLS.includes(toolName)) return undefined;
  const raw = toolInput.command ?? toolInput.cmd;
  const command = typeof raw === "string" ? raw : Array.isArray(raw) ? raw.filter((x): x is string => typeof x === "string").join(" ") : "";
  if (command === "") return undefined;
  const hit = controlCommand(command);
  if (hit !== undefined) return setupRefusal(hit) ?? `choosing or setting up IronTrellis is for the user, not the agent (${hit})`;
  const spellings = commandSpellings(command);
  if (spellings.some((s) => s.includes(CHOICE_FILE_NAME) || files.some((f) => s.includes(f)))) return "the IronTrellis route choice is the user's, not the agent's";
  if (spellings.some((s) => s.toLowerCase().includes(CONFIG_FILE) || pins.some((f) => s.includes(f)))) return SETUP;
  return undefined;
}

// ---------------------------------------------------------------- the route a session was admitted under

export type RouteSession = Readonly<{ state: RouteState; project: string; config: string | undefined }>;
const GUARDED: readonly RouteState[] = ["plugin", "hook", "both"];

export function readRouteSession(env: Env, hostSessionId: string): RouteSession | undefined {
  const doc = readPrivateJson(routeSessionFile(env, hostSessionId));
  if (!isRecord(doc) || doc.version !== ROUTE_SESSION_VERSION || typeof doc.state !== "string" || !GUARDED.includes(doc.state as RouteState) || typeof doc.project !== "string") return undefined;
  return { state: doc.state as RouteState, project: doc.project, config: typeof doc.config === "string" ? doc.config : undefined };
}
export function writeRouteSession(env: Env, hostSessionId: string, session: RouteSession, now: number): void {
  const file = routeSessionFile(env, hostSessionId);
  ensurePrivateDir(dirname(dirname(file))); ensurePrivateDir(dirname(file));
  writePrivateFile(file, `${JSON.stringify({ version: ROUTE_SESSION_VERSION, ...session, at: new Date(now).toISOString() })}\n`);
}
export const ROUTE_SESSION_VERSION = "irontrellis-route-session/1";

export type PluginIo = Readonly<{ env: Env; cwd: string; now?: () => number }>;

/**
 * One plugin hook event. `forward` runs the guard itself with the config the route found (the plugin route); the other
 * states answer here. The route's project is CLAUDE_PROJECT_DIR, else the project the session was admitted in, else the
 * hook's own working directory (never the event's cwd, which follows the agent's `cd`). A session admitted under plugin,
 * hook or both whose config has since vanished or changed is refused (PreToolUse) or warned about (the other events),
 * never treated as undecided. The plugin exits 2 only for PreToolUse; a failure on any other event is a warning (exit 1).
 */
export async function pluginEvent(eventName: string, payload: Readonly<Record<string, unknown>>, io: PluginIo, forward: (config: string, project: string) => Promise<Reply>): Promise<Reply> {
  const protocol = protocolFor("claude-code")!;
  const sessionId = typeof payload.session_id === "string" ? payload.session_id : "";
  const admitted = sessionId === "" ? undefined : readRouteSession(io.env, sessionId);
  const hasProjectDir = io.env.CLAUDE_PROJECT_DIR !== undefined && io.env.CLAUDE_PROJECT_DIR !== "";
  const status = routeStatus(hasProjectDir || admitted === undefined ? io.env : { ...io.env, CLAUDE_PROJECT_DIR: admitted.project }, io.cwd);
  const toolName = typeof payload.tool_name === "string" ? payload.tool_name : "";
  const toolInput = isRecord(payload.tool_input) ? payload.tool_input : {};
  const deny = (reason: string): Reply => protocol.replyTool({ kind: "tool", sessionId, cwd: undefined, toolName, toolInput, toolUseId: undefined, canAsk: true, mcpServer: undefined, deferTo: undefined }, { verdict: "deny", reason });
  const guarded = GUARDED.includes(status.state);
  const end = (reply: Reply): Reply => { if (eventName === "SessionEnd" && sessionId !== "") removePrivateFile(routeSessionFile(io.env, sessionId)); return reply; };
  if (admitted !== undefined && (!guarded || (status.state === "plugin" && admitted.config !== undefined && status.config !== admitted.config))) {
    const why = `this session was admitted under the ${admitted.state} route (config ${admitted.config ?? "none"}), which is now ${guarded ? `using ${status.config ?? "no config"}` : "gone (the config is missing or unreadable)"}; restore it, or end the session, in your own terminal`;
    return end(eventName === "PreToolUse" ? deny(`IronTrellis · DENY: ${why}`) : protocol.replyError(`IronTrellis: ${why}`, false));
  }
  if (guarded && sessionId !== "" && (admitted === undefined || admitted.state !== status.state)) {
    try { writeRouteSession(io.env, sessionId, { state: status.state, project: status.project, config: status.config }, (io.now ?? Date.now)()); } catch (error) {
      const why = `IronTrellis · DENY: cannot record this session's route (${error instanceof Error ? error.message : String(error)})`;
      if (eventName === "PreToolUse") return deny(why);
    }
  }
  if (status.state === "plugin") return end(await forward(status.config!, status.project));
  if (status.state === "hook" || status.state === "both") return end(protocol.replyIgnored()); // the settings hook is the one guard
  const quiet = protocol.replyIgnored();
  if (eventName === "PreToolUse") {
    const why = choiceProtection(io.env, toolName, toolInput, typeof payload.cwd === "string" ? payload.cwd : undefined);
    if (why !== undefined) return deny(`IronTrellis · DENY: ${why}`);
    return quiet; // nothing is set up, so nothing is enforced: the host's own permissions apply
  }
  if (eventName === "SessionStart" && status.state === "undecided") {
    // At each session start: startup, resume and clear show it (RA-05: the docs say so); after a compaction it is not shown again.
    if (payload.source === "compact") return quiet;
    return protocol.replySessionStart(NOTICE_CONTEXT(status), NOTICE_LINES(status).join("\n"));
  }
  return quiet;
}
