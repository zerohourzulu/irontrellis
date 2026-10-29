/**
 * The `irontrellis-hook` command.
 *
 *   irontrellis-hook <agent> <event>            answer one hook invocation (stdin JSON → stdout JSON, exit code)
 *   irontrellis-hook init [--agent <a>] …       create the history and irontrellis-hook.json
 *   irontrellis-hook install <agent> [--write] [--dry-run] [--replace-command c] [--allow-disabled]  print, merge in, or preview the host's hook settings
 *   irontrellis-hook check <agent> <tool> …     dry-run a tool decision (no host involved)
 *   irontrellis-hook session list|release …     the session keys the hook holds (operator)
 *
 * Hook invocations write only the host's answer to stdout; everything meant for
 * a person goes to stderr. Exit codes follow the host protocol (see src/protocols).
 */
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { isAbsolute, relative, resolve } from "node:path";
import type { Readable, Writable } from "node:stream";
import { openHistoryStore, ownerKeysAt } from "@ramex-labs/irontrellis";
import { runHook, openOwner, decideTool, failOpenForRoute, replyFailure, sessionAdmitted, type HookIo } from "./hook.ts";
import { pluginEnabled, pluginEvent, readChoices, routeStatus, statusLine, writeChoice } from "./route.ts";
import { homeShort, shellPath, shellQuote } from "./protect.ts";
import { CONFIG_ENV, loadConfig, loadConfigFile } from "./config.ts";
import { defaultStateHome } from "./paths.ts";
import { protocolFor, PROTOCOL_IDS } from "./protocols/index.ts";
import { describeChanges, hookCommand, init, install, listSessions, pinRuntime, releaseSessions } from "./setup.ts";

/**
 * Verification threads for the hook's process, which opens (replays) the history once per tool call and exits:
 * one worker, not the library's min(4, cores - 1), unless IRONTRELLIS_VERIFY_THREADS says otherwise. One
 * worker takes most of the gain (10,000 events: 2.99 s sequential, 1.93 s with one, 2.13 s with two on
 * 2 vCPUs) without starting four per tool call on a developer machine (docs/history/PERFORMANCE-2026-09-26.md §5.1). The bin applies it.
 */
export const HOOK_VERIFY_THREADS = 1;
export const VERSION: string = (createRequire(import.meta.url)("../package.json") as { version: string }).version;

export type CliIo = Readonly<{ stdin: Readable; stdout: Writable; stderr: Writable; env: Readonly<Record<string, string | undefined>>; cwd: string; now?: () => number }>;

const USAGE = `irontrellis-hook ${VERSION} — run coding agents under IronTrellis (formerly Continuity)

usage:
  irontrellis-hook <agent> <event>                 hook entry point; reads the host's event JSON from stdin
  irontrellis-hook init [options]                  create the history (outside the project) and irontrellis-hook.json
  irontrellis-hook install <agent> [--write|--dry-run]  print, merge into, or preview the host's hook settings
  irontrellis-hook check <agent> <tool> [--input <json>]   dry-run one tool decision
  irontrellis-hook session list [--json]           the session keys the hook holds for the agent
  irontrellis-hook session release <host-session-id> | --all   release a session that ended without SessionEnd
  irontrellis-hook choose --status | --decline | --use-hook | --reset   this project's Claude Code install route (plugin or hook)
  irontrellis-hook choose 1 | 2 | 3                the notice's choices: 1 = --decline, 2 = init --agent claude-code (the plugin route), 3 = --use-hook
  irontrellis-hook statusline                      one line for Claude Code's statusLine setting: whether IronTrellis guards this project
  irontrellis-hook pin-runtime                     record this node and launcher for the IronTrellis plugin (init does it too)
  irontrellis-hook plugin claude-code <event>      the IronTrellis plugin's entry point in Claude Code (reads the event JSON from stdin)

agents:  ${PROTOCOL_IDS.join(", ")}
events:  claude-code: SessionStart PreToolUse Stop SessionEnd (PostToolUse, UserPromptSubmit accepted, ignored)
         codex:       SessionStart PreToolUse Stop SessionEnd (PostToolUse, UserPromptSubmit accepted, ignored)
         cursor:      sessionStart beforeShellExecution beforeMCPExecution preToolUse stop sessionEnd (afterFileEdit, beforeSubmitPrompt accepted, ignored)

init options:
  --agent <a>          host (default claude-code); also the agent id unless --agent-id is given
  --dir <path>         project directory (default the working directory)
  --history <path>     history file (default ~/.irontrellis/projects/<sha256(project)[0:16]>/history.jsonl,
                       outside the project; IRONTRELLIS_HOME moves ~/.irontrellis)
  --owner <id>         principal id (default principal:owner)
  --controller <id>    controller id (default controller:irontrellis-hook)
  --agent-id <id>      the agent as recorded in the history
  --role <id>          role to appoint the agent to (default role:coding-agent)
  --allow <a,b>        grant these actions on repo:<project> now (e.g. run-shell,write-file); nothing by default
  --expires <t>        expiry of that grant: ms, ISO-8601 or +7d (default +30d)
  --i-understand-same-user-risk
                       required with --allow run-shell: on one OS user, run-shell can read the owner key,
                       so a run-shell grant is equivalent to owner authority
  --force              rewrite an existing irontrellis-hook.json
  --verbose            print every step and the full warnings (also for choose 2); by default, a few lines with each
                       warning in one sentence (irontrellis doctor explains them)
install options:
  --dir <path>         project directory (default the working directory)
  --command <cmd>      how the host should invoke the hook (default for claude-code: this node and this package's
                       launcher, by absolute path; for codex and cursor: irontrellis-hook)
  --write              merge into the settings file instead of printing: adds or replaces only IronTrellis's own
                       hook entries (the plain irontrellis-hook, npx … irontrellis-hook or --command, followed by
                       "<agent> <Event>", in a group for every tool), keeps everything else, prints what changed and
                       the diff; writes atomically; a file already up to date is not rewritten
  --dry-run            show what --write would change (the changes and a diff of the file); writes nothing
  --replace-command <cmd>
                       an earlier --command whose entries are IronTrellis's too: replace them (otherwise an entry
                       running "<cmd> <agent> <Event>" that is not the plain hook is refused as ambiguous)
  --allow-disabled     install although the settings switch every hook off ("disableAllHooks": true); refused otherwise
  --json               machine output
`;

// ---------------------------------------------------------------- tiny option parser

type Options = { positionals: string[]; flags: Map<string, string | true> };
const parse = (argv: readonly string[]): Options => {
  const positionals: string[] = [], flags = new Map<string, string | true>();
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (!arg.startsWith("--")) { positionals.push(arg); continue; }
    const eq = arg.indexOf("=");
    const name = eq < 0 ? arg.slice(2) : arg.slice(2, eq);
    if (eq >= 0) { flags.set(name, arg.slice(eq + 1)); continue; }
    const next = argv[i + 1];
    if (BOOLEAN.has(name) || next === undefined || next.startsWith("--")) flags.set(name, true);
    else { flags.set(name, next); i += 1; }
  }
  return { positionals, flags };
};
const BOOLEAN: ReadonlySet<string> = new Set(["write", "dry-run", "allow-disabled", "force", "json", "help", "version", "i-understand-same-user-risk", "all", "verbose"]);
const str = (o: Options, name: string): string | undefined => { const v = o.flags.get(name); return typeof v === "string" ? v : undefined; };
const flag = (o: Options, name: string): boolean => o.flags.get(name) === true;

const DURATION = /^\+(\d+)(ms|s|m|h|d)$/;
const UNIT: Readonly<Record<string, number>> = { ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 };
const parseTime = (text: string, now: number): number => {
  if (/^\d+$/.test(text)) return Number(text);
  const d = DURATION.exec(text);
  if (d !== null) return now + Number(d[1]) * UNIT[d[2]!]!;
  const parsed = Date.parse(text);
  if (Number.isNaN(parsed)) throw new Error(`--expires: "${text}" is not milliseconds, an ISO-8601 date or a duration like +7d`);
  return parsed;
};

const readAll = (stream: Readable): Promise<string> => new Promise((resolveText, reject) => {
  const chunks: Buffer[] = [];
  stream.on("data", (chunk: Buffer | string) => chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk));
  stream.on("end", () => resolveText(Buffer.concat(chunks).toString("utf8")));
  stream.on("error", reject);
});

// ---------------------------------------------------------------- commands

/**
 * What the owner publishes for readers (founder decision 4cb): the history id and the first owner keys, in the form
 * `irontrellis verify --expect-history-id / --expect-owner-key` takes (0x hex, lowercase, the key set sorted).
 */
function publishable(history: string): Readonly<{ historyId: string; ownerKeys: readonly string[] }> {
  const store = openHistoryStore(history, { inspect: true, witness: false });
  try {
    const state = store.state();
    return { historyId: state.eventHistoryHashes[0]!, ownerKeys: [...new Set(ownerKeysAt(state, 0).map((k) => k.credential.toLowerCase()))].sort() };
  } finally { store.close(); }
}

/**
 * `init`, and `choose 2` (chosen: init for the plugin route). The plugin route leaves the hook route's install out of the
 * next steps; plain `init` is on it too when the IronTrellis plugin is enabled for the project and the hook route was not
 * chosen (founder's live check 02). The default output is a few plain lines: what is set up, the warnings in one
 * sentence each, the next steps and what to publish, with the home directory as ~; `--verbose` prints every step and the
 * full warnings, as before.
 */
async function initCommand(o: ReturnType<typeof parse>, io: CliIo, now: () => number, chosen: boolean): Promise<number> {
  const out = (text: string): void => { io.stdout.write(text); };
  const err = (text: string): void => { io.stderr.write(text.endsWith("\n") ? text : `${text}\n`); };
  const protocol = protocolFor(str(o, "agent") ?? "claude-code");
  if (protocol === undefined) throw new Error(`--agent must be one of ${PROTOCOL_IDS.join(", ")}`);
  const allow = (str(o, "allow") ?? "").split(",").map((a) => a.trim()).filter((a) => a.length > 0);
  const home = io.env.HOME !== undefined && io.env.HOME !== "" ? io.env.HOME : homedir();
  const short = (p: string): string => homeShort(p, home), word = (p: string): string => shellPath(p, home);
  const result = await init({
    protocol, project: resolve(io.cwd, str(o, "dir") ?? "."), history: str(o, "history"), stateHome: defaultStateHome(io.env), owner: str(o, "owner"), controller: str(o, "controller"),
    agentId: str(o, "agent-id"), roleId: str(o, "role"), allow, expiresAt: parseTime(str(o, "expires") ?? "+30d", now()), force: flag(o, "force"),
    acceptSameUserRisk: flag(o, "i-understand-same-user-risk"), now, showPath: short,
  });
  const project = result.config.project;
  const onPlugin = chosen || (protocol.id === "claude-code" && pluginEnabled(project, io.env) && readChoices(io.env).projects[project]?.choice !== "use-hook");
  const publish = publishable(result.history);
  const verbose = flag(o, "verbose");
  // The warnings go to stderr, so they are seen even with --json.
  if (flag(o, "json") || verbose) err(`\n${result.warnings.join("\n\n")}\n`);
  if (flag(o, "json")) {
    out(`${JSON.stringify({ configFile: result.configFile, history: result.history, stateDir: result.stateDir, ownerKey: result.ownerKey, created: result.created, steps: result.steps, grant: result.grant ?? null, gitignores: result.gitignores, warnings: result.warnings, notes: result.notes, pluginRoute: onPlugin, publish }, null, 2)}\n`);
    return 0;
  }
  const fromProject = relative(project, result.stateDir), inside = fromProject === "" || (!fromProject.startsWith("..") && !isAbsolute(fromProject));
  const newSession = "Start a new Claude Code session in this project: the guard admits a session when it starts.";
  if (verbose) {
    out(`irontrellis-hook init (${protocol.name})\n${result.steps.map((s) => `  ${s}\n`).join("")}`);
    out(`state: ${result.stateDir} holds the history, the owner key, session keys and handovers (0700/0600)${inside ? "" : "; it is outside the project and out of version control, so back it up separately"}\n`);
  } else {
    out(`${chosen ? `IronTrellis is set up here (the plugin route). ${newSession}`
      : onPlugin ? `IronTrellis is set up here, and you're on the plugin route: the IronTrellis plugin is enabled, so no hook install is needed. ${newSession}`
      : `IronTrellis is set up for ${short(project)} (${protocol.name}).`}\n`);
    out(`Its history and keys are in ${short(result.stateDir)}/${inside ? ", inside the project" : ", outside the project: back that folder up separately"}.\n`);
    // The warnings stay, one sentence each (stderr, as above); doctor explains them.
    err(`\nWarnings (irontrellis doctor ${word(result.history)} explains them; --verbose shows every note):\n${result.notes.map((n) => `  - ${n}`).join("\n")}\n`);
  }
  // The plugin route has no install step (the coordinator, 2026-10-23); the grant names the project's full path (a resource, not a path the shell expands).
  const next = [
    ...(onPlugin ? [] : [`  irontrellis-hook install ${protocol.id} --write        # add the hooks to ${protocol.install("irontrellis-hook").path}`]),
    ...(result.grant === undefined ? [`  irontrellis --history ${word(result.history)} grant <id> --to ${shellQuote(result.config.agentId)} --actions write-file --resources ${shellQuote(`repo:${project}`)} --expires +7d`] : []),
  ];
  if (next.length > 0) out(`${verbose ? "" : "\n"}next:\n${next.map((line) => `${line}\n`).join("")}`);
  out(`\nPublish these where readers can check them independently of this file:\n  history id  ${publish.historyId}\n${publish.ownerKeys.map((k) => `  owner key   ${k}\n`).join("")}`);
  out(`A reader checks them with: irontrellis --history ${word(result.history)} verify --expect-history-id ${publish.historyId}${publish.ownerKeys.map((k) => ` --expect-owner-key ${k}`).join("")}\n`);
  if (verbose && onPlugin) out(`${chosen ? "IronTrellis is set up here (the plugin route)." : "You're on the plugin route: the IronTrellis plugin is enabled here, so no hook install is needed."} ${newSession}\n`);
  return 0;
}

export async function main(argv: readonly string[], io: CliIo): Promise<number> {
  const o = parse(argv);
  const now = io.now ?? (() => Date.now());
  const hookIo: HookIo = { env: io.env, cwd: io.cwd, now };
  const [first, second] = o.positionals;
  const out = (text: string): void => { io.stdout.write(text); };
  const err = (text: string): void => { io.stderr.write(text.endsWith("\n") ? text : `${text}\n`); };
  // `--version` alone has no positional: check it before the usage fallback, or it prints the usage and exits 1.
  if (!flag(o, "help") && (flag(o, "version") || first === "version")) { out(`${VERSION}\n`); return 0; }
  if (first === undefined || flag(o, "help") || first === "help") { out(USAGE); return first === undefined && !flag(o, "help") ? 1 : 0; }
  try {
    switch (first) {
      case "init": return await initCommand(o, io, now, false);
      case "install": {
        const protocol = protocolFor(second ?? "");
        if (protocol === undefined) throw new Error(`install needs an agent: ${PROTOCOL_IDS.join(", ")}`);
        const dryRun = flag(o, "dry-run");
        const replaceCommand = str(o, "replace-command");
        const result = install(protocol, resolve(io.cwd, str(o, "dir") ?? "."), str(o, "command") ?? (protocol.id === "claude-code" ? hookCommand(io.env) : "irontrellis-hook"), flag(o, "write") && !dryRun, {
          ...(replaceCommand === undefined ? {} : { replaceCommand }), ...(flag(o, "allow-disabled") ? { allowDisabled: true } : {}),
        });
        for (const warning of result.warnings) err(warning);
        if (flag(o, "json")) {
          out(`${JSON.stringify({ file: result.file, written: result.written, changed: result.changed, changes: result.changes, diff: result.diff, warnings: result.warnings, settings: result.settings }, null, 2)}\n`);
          return 0;
        }
        const summary = describeChanges(result.changes).join("\n");
        if (dryRun) {
          out(result.changed ? `would update ${result.file}:\n${summary}\n\n${result.diff}` : `${result.file} is up to date; nothing would change:\n${summary}\n`);
          return 0;
        }
        if (flag(o, "write")) {
          out(result.written ? `updated ${result.file}:\n${summary}\n\n${result.diff}` : `${result.file} is up to date; nothing written:\n${summary}\n`);
          return 0;
        }
        out(`${JSON.stringify(result.settings, null, 2)}\n`);
        err(`# ${protocol.name} hook settings for ${result.file} (rerun with --write to merge them in, --dry-run to see the diff)\n${summary}`);
        return 0;
      }
      case "check": {
        const protocol = protocolFor(second ?? "");
        const tool = o.positionals[2];
        if (protocol === undefined || tool === undefined) throw new Error(`check needs an agent (${PROTOCOL_IDS.join(", ")}) and a tool name`);
        const input = str(o, "input");
        const config = loadConfig(io.env, resolve(io.cwd, str(o, "dir") ?? "."));
        const owner = openOwner(config, now);
        // A dry run has no host session, so the session check is skipped; everything else is as the hook decides.
        const decision = decideTool(owner, config, {
          kind: "tool", sessionId: "check", cwd: config.project, toolName: tool, toolInput: input === undefined ? {} : (JSON.parse(input) as Record<string, unknown>),
          toolUseId: undefined, canAsk: true, mcpServer: undefined, deferTo: undefined,
        }, now(), { checkSession: false });
        out(flag(o, "json") ? `${JSON.stringify(decision)}\n` : `${decision.verdict.toUpperCase()}  ${decision.reason}\n`);
        return decision.verdict === "deny" ? 2 : 0;
      }
      case "session": {
        const config = loadConfig(io.env, resolve(io.cwd, str(o, "dir") ?? "."));
        if (second === "list") {
          const entries = listSessions(config, now());
          if (flag(o, "json")) { out(`${JSON.stringify(entries, null, 2)}\n`); return 0; }
          out(entries.length === 0 ? `no session keys held for ${config.agentId}\n` : entries.map((e) => `${e.released ? "released" : e.current ? "live    " : "stale   "}  ${e.hostSessionId ?? "?"}  ${e.sessionId}  ${e.keyFile}\n`).join(""));
          return 0;
        }
        if (second === "release") {
          const host = o.positionals[2];
          if (host === undefined && !flag(o, "all")) throw new Error("session release needs a host session id or --all");
          const released = releaseSessions(config, host, now());
          out(released.length === 0 ? "nothing released\n" : released.map((e) => `released ${e.hostSessionId ?? "?"} (${e.sessionId}); the next SessionStart fences it\n`).join(""));
          return released.length === 0 ? 1 : 0;
        }
        throw new Error("session needs list or release");
      }
      case "pin-runtime": {
        const pin = pinRuntime(defaultStateHome(io.env), io.env);
        out(`plugin runtime ${pin.file} written: the IronTrellis plugin runs ${pin.node} ${pin.launcher}\n`);
        return 0;
      }
      case "choose": {
        // The notice's numbers (founder's live check 01): 1 = --decline, 2 = init --agent claude-code, 3 = --use-hook.
        const NUMBERS: Readonly<Record<string, string>> = { "1": "decline", "2": "init", "3": "use-hook" };
        const numbered = second !== undefined && Object.hasOwn(NUMBERS, second) ? NUMBERS[second] : undefined;
        if (second !== undefined && (numbered === undefined || o.positionals.length > 2)) throw new Error(`choose: "${second}" is not 1, 2 or 3 (1 = --decline, 2 = init --agent claude-code, 3 = --use-hook)`);
        if (numbered === "init") {
          if (["status", "decline", "use-hook", "reset"].some((f) => flag(o, f))) throw new Error("choose 2 takes no other choice");
          const dir = str(o, "dir");
          return await initCommand(parse(["init", "--agent", "claude-code", ...(dir === undefined ? [] : ["--dir", dir]), ...(flag(o, "verbose") ? ["--verbose"] : [])]), io, now, true);
        }
        const status = routeStatus(io.env, resolve(io.cwd, str(o, "dir") ?? "."));
        const picks = numbered !== undefined ? [numbered, ...["status", "decline", "use-hook", "reset"].filter((f) => flag(o, f))] : ["status", "decline", "use-hook", "reset"].filter((f) => flag(o, f));
        if (picks.length !== 1) throw new Error("choose needs exactly one of 1, 2, 3, --status, --decline, --use-hook, --reset");
        const describeStatus = (s: typeof status): string => [
          `project: ${s.project}`,
          `route:   ${s.state}${s.state === "plugin" ? ` (config ${s.config})` : s.state === "hook" || s.state === "both" ? ` (verified hook entries in ${s.hook.files.join(", ")})` : ""}`,
          `plugin:  ${s.pluginEnabled ? "enabled" : "not enabled"} in the Claude Code settings`,
          `choice:  ${s.choice ?? "none"} (${s.choiceFile}${s.choiceCorrupt ? "; the file is unreadable and is treated as no choice" : ""})`,
          ...s.hook.unrecognized.map((u) => `warning: unrecognized IronTrellis hook entry: ${u}`),
          ...(s.hooksDisabled ? ["warning: Claude Code's \"disableAllHooks\": true is set, so no hook runs and IronTrellis guards nothing here"] : []),
        ].join("\n");
        if (picks[0] === "status") { out(flag(o, "json") ? `${JSON.stringify(status, null, 2)}\n` : `${describeStatus(status)}\n`); return 0; }
        if (picks[0] === "reset") { const file = writeChoice(io.env, status.project, undefined, now()); out(`no route choice for ${status.project} (${file})\n`); return 0; }
        // A choice is for an unconfigured project only: with a config or a verified hook route the guard runs whatever is stored.
        if (status.state === "plugin" || status.state === "hook" || status.state === "both") {
          err(`irontrellis-hook choose: ${status.project} is set up (${status.state}); a choice applies only to a project without IronTrellis`);
          return 1;
        }
        const file = writeChoice(io.env, status.project, picks[0] === "decline" ? "declined" : "use-hook", now());
        out(picks[0] === "decline"
          ? `IronTrellis is off for ${status.project} (recorded in ${file}); the plugin stays silent here. Undo: irontrellis-hook choose --reset\n`
          : `the hook route is chosen for ${status.project} (recorded in ${file}); finish it:\n  irontrellis-hook init --agent claude-code\n  irontrellis-hook install claude-code --write\n`);
        return 0;
      }
      case "statusline": {
        // Claude Code's statusLine command gets the session's JSON on stdin (workspace.project_dir, cwd); run by hand, a terminal.
        let dir = str(o, "dir"), session: string | undefined;
        try {
          const text = (io.stdin as { isTTY?: boolean }).isTTY === true ? "" : await readAll(io.stdin);
          const doc: unknown = text.trim() === "" ? undefined : JSON.parse(text);
          const workspace = doc !== null && typeof doc === "object" ? (doc as Record<string, unknown>).workspace : undefined;
          const from = workspace !== null && typeof workspace === "object" ? (workspace as Record<string, unknown>).project_dir : undefined;
          const cwd = doc !== null && typeof doc === "object" ? (doc as Record<string, unknown>).cwd : undefined;
          const id = doc !== null && typeof doc === "object" ? (doc as Record<string, unknown>).session_id : undefined;
          if (dir === undefined) dir = typeof from === "string" && from !== "" ? from : typeof cwd === "string" && cwd !== "" ? cwd : undefined;
          if (typeof id === "string" && id !== "") session = id;
        } catch { /* no session JSON: the working directory's project */ }
        try {
          const env = dir === undefined ? io.env : { ...io.env, CLAUDE_PROJECT_DIR: resolve(io.cwd, dir) };
          const status = routeStatus(env, io.cwd);
          // Founder's live check 02: a guarded project, but this session started before it was set up (not admitted).
          let admitted: boolean | undefined;
          if (session !== undefined && status.config !== undefined && ["plugin", "hook", "both"].includes(status.state)) {
            try { admitted = sessionAdmitted(loadConfigFile(status.config), session); } catch { admitted = undefined; }
          }
          out(`${statusLine(status, admitted)}\n`);
        } catch (error) {
          out(`IronTrellis: status unavailable (${error instanceof Error ? error.message : String(error)})\n`);
        }
        return 0;
      }
      case "plugin": {
        const protocol = protocolFor("claude-code")!;
        const event = o.positionals[2];
        if (second !== "claude-code" || event === undefined || !protocol.events.includes(event)) { err(`irontrellis-hook plugin: usage: plugin claude-code <${protocol.events.join("|")}>`); return 1; }
        const emit = (reply: { stdout: string; stderr: string; exitCode: number }): number => { if (reply.stdout !== "") out(reply.stdout); if (reply.stderr !== "") err(reply.stderr); return reply.exitCode; };
        let payload: Record<string, unknown> = {};
        try {
          const text = await readAll(io.stdin), parsed: unknown = text.trim() === "" ? {} : JSON.parse(text);
          if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) payload = parsed as Record<string, unknown>;
          else throw new Error("stdin must be a JSON object");
        } catch (error) {
          // Unreadable input: the guard refuses it where it enforces (exit 2 for a tool call), and only there.
          const status = routeStatus(io.env, io.cwd);
          if (status.state !== "plugin") return 0;
          return emit(replyFailure(protocol, `irontrellis-hook: ${error instanceof Error ? error.message : String(error)} (${event})`, protocol.toolEvents.includes(event), failOpenForRoute(io.env, io.cwd)));
        }
        // `via: "plugin"`: this guard runs for the plugin, not for a settings hook (the both-routes warning is the hook's to give).
        return emit(await pluginEvent(event, payload, { env: io.env, cwd: io.cwd, now }, (config, project) => runHook(protocol, event, payload, { ...hookIo, env: { ...io.env, [CONFIG_ENV]: config, CLAUDE_PROJECT_DIR: project }, via: "plugin" })));
      }
      default: {
        const protocol = protocolFor(first);
        if (protocol === undefined) { err(`irontrellis-hook: unknown command or agent "${first}" (agents: ${PROTOCOL_IDS.join(", ")})\n${USAGE}`); return 1; }
        if (second === undefined || !protocol.events.includes(second)) { err(`irontrellis-hook: ${protocol.name} event must be one of ${protocol.events.join(", ")}`); return 1; }
        const emit = (reply: { stdout: string; stderr: string; exitCode: number }): number => {
          if (reply.stdout !== "") out(reply.stdout);
          if (reply.stderr !== "") err(reply.stderr);
          return reply.exitCode;
        };
        // A tool event the hook cannot read is refused (exit 2 / deny) unless the config says failOpen.
        const isToolEvent = protocol.toolEvents.includes(second);
        const unreadable = (message: string): number => emit(replyFailure(protocol, `irontrellis-hook: ${message}`, isToolEvent, isToolEvent && failOpenForRoute(io.env, io.cwd)));
        try {
          const text = await readAll(io.stdin);
          let payload: unknown;
          try { payload = text.trim() === "" ? {} : JSON.parse(text); } catch { return unreadable(`stdin is not JSON (${second})`); }
          if (payload === null || typeof payload !== "object" || Array.isArray(payload)) return unreadable(`stdin must be a JSON object (${second})`);
          return emit(await runHook(protocol, second, payload as Record<string, unknown>, hookIo));
        } catch (error) {
          return unreadable(error instanceof Error ? error.message : String(error));
        }
      }
    }
  } catch (error) {
    err(`irontrellis-hook: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  }
}
