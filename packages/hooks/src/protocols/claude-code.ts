/**
 * Claude Code hooks.
 *
 * Source: "Hooks reference", https://code.claude.com/docs/en/hooks
 * (the former https://docs.claude.com/en/docs/claude-code/hooks redirects
 * there), read on 2026-09-24. Field names relied on:
 *
 * Configuration (`.claude/settings.json`, `~/.claude/settings.json`,
 * `.claude/settings.local.json`):
 *   { "hooks": { "<EventName>": [ { "matcher"?: string, "hooks": [ { "type": "command", "command": string, "timeout"?: seconds, "onFailure"?: "continue" | "block" } ] } ] } }
 *   A missing or empty matcher matches every tool. Matchers made only of letters,
 *   digits, `_`, `-`, spaces, `,` and `|` are exact names (or lists); anything
 *   else is an unanchored JavaScript regular expression.
 *
 * stdin (all events): session_id, transcript_path, cwd, hook_event_name, permission_mode,
 *   and (v2.1.257+) scratchpad_dir, prompt_id, effort. PreToolUse adds tool_name,
 *   tool_input, tool_use_id. SessionStart adds source ("startup" | "resume" |
 *   "clear" | "compact" | "fork"). SessionEnd adds reason ("clear" | "resume" |
 *   "logout" | "prompt_input_exit" | "other"). Stop adds stop_hook_active and
 *   last_assistant_message. Tool names: "Bash" ({command}), "Write" ({file_path,
 *   content}), "Edit" ({file_path, old_string, new_string}), MCP tools as
 *   "mcp__<server>__<tool>".
 *
 * stdout (exit 0, JSON):
 *   PreToolUse:   { "hookSpecificOutput": { "hookEventName": "PreToolUse", "permissionDecision": "allow" | "deny" | "ask", "permissionDecisionReason": string } }
 *                 "deny" shows the reason to Claude; "ask" shows it to the user in the permission prompt;
 *                 "allow" bypasses the permission system for that call. Exit 0 with no
 *                 output is no decision: the normal permission flow runs. The hook
 *                 therefore answers nothing (verdict "defer") unless the config opts
 *                 into "allow" (decisions.onAllow / decisions.onReadOnly).
 *   All events:   "systemMessage": string is shown to the user.
 *   SessionStart: { "hookSpecificOutput": { "hookEventName": "SessionStart", "additionalContext": string } }
 *                 (hookEventName is required; plain-text stdout is also added as context.)
 *   SessionEnd:   output is discarded; the hooks share a 1.5 s budget unless a longer timeout is configured.
 *   Stop:         { "decision": "block", "reason": string } keeps Claude working; anything else lets it stop.
 * IronTrellis answers a PreToolUse deny with exit 2 and the reason on stderr (stdout empty); ask and allow are JSON at exit 0.
 * Exit codes: 0 = success (JSON parsed); 2 = block (PreToolUse: the tool call is
 *   refused and stderr is the reason shown to Claude; SessionStart: blocks the
 *   session); other = non-blocking error, stderr shown to the user.
 */
import { json, objOrUndefined, str, type HookEvent, type InstallEntry, type Protocol, type Reply, type ToolDecision } from "./types.ts";

/** A refusal's text, starting "IronTrellis · DENY:" (BRAND-001; an "IronTrellis: " or "irontrellis-hook: " opening is replaced, any other kept after it). */
export const deniedText = (message: string): string => {
  if (message.startsWith("IronTrellis · DENY:")) return message;
  const opening = ["IronTrellis: ", "irontrellis-hook: "].find((o) => message.startsWith(o));
  return `IronTrellis · DENY: ${opening === undefined ? message : message.slice(opening.length)}`;
};

/**
 * A Claude Code refusal's stderr starts with a newline, so the refusal stands on its own line under the label Claude Code puts in
 * front of an exit-2 error ("PreToolUse:<tool> hook error: [<the hook's command>]:"; the harness, r03 on 2.1.309).
 */
export const DENY_LEAD = "\n";

export const CLAUDE_CODE_EVENTS = Object.freeze(["SessionStart", "PreToolUse", "PostToolUse", "UserPromptSubmit", "Stop", "SessionEnd"]);

const parse = (eventName: string, payload: Readonly<Record<string, unknown>>): HookEvent => {
  const sessionId = str(payload.session_id), cwd = str(payload.cwd);
  switch (eventName) {
    case "SessionStart":
      return sessionId === undefined ? { kind: "ignored", sessionId, note: "SessionStart without session_id" } : { kind: "session-start", sessionId, cwd, source: str(payload.source) };
    case "PreToolUse": {
      // Fail closed: a tool event the hook cannot read is refused (unless failOpen), never waved through.
      const toolName = str(payload.tool_name), toolInput = objOrUndefined(payload.tool_input);
      if (sessionId === undefined) return { kind: "malformed", note: "PreToolUse without a string session_id" };
      if (toolName === undefined) return { kind: "malformed", note: "PreToolUse without a string tool_name" };
      if (toolInput === undefined) return { kind: "malformed", note: "PreToolUse without a tool_input object" };
      return { kind: "tool", sessionId, cwd, toolName, toolInput, toolUseId: str(payload.tool_use_id), canAsk: true, mcpServer: undefined, deferTo: undefined };
    }
    case "SessionEnd":
      return sessionId === undefined ? { kind: "ignored", sessionId, note: "SessionEnd without session_id" } : { kind: "session-end", sessionId, cwd, reason: str(payload.reason), final: true };
    case "Stop":
      // Stop fires at the end of every assistant turn; the handover snapshot is refreshed but the session stays open.
      return sessionId === undefined ? { kind: "ignored", sessionId, note: "Stop without session_id" } : { kind: "session-end", sessionId, cwd, reason: "stop", final: false };
    default:
      return { kind: "ignored", sessionId, note: `${eventName} is accepted but not acted on` };
  }
};

export const claudeCode: Protocol = Object.freeze({
  id: "claude-code" as const,
  name: "Claude Code",
  docs: "https://code.claude.com/docs/en/hooks",
  docsCheckedOn: "2026-09-24",
  events: CLAUDE_CODE_EVENTS,
  toolEvents: Object.freeze(["PreToolUse"]),
  parse,
  replySessionStart: (context: string, warning?: string): Reply => ({
    stdout: json({ ...(warning === undefined ? {} : { systemMessage: warning }), hookSpecificOutput: { hookEventName: "SessionStart", additionalContext: context } }),
    stderr: warning ?? "", exitCode: 0,
  }),
  replyTool: (_event: Extract<HookEvent, { kind: "tool" }>, decision: ToolDecision): Reply => (decision.verdict === "defer"
    // No decision: Claude Code's own permission rules and prompt apply. The reason goes to stderr (debug output only).
    ? { stdout: "", stderr: decision.reason, exitCode: 0 }
    // A deny is exit 2 with the reason on stderr (the coordinator's GO for proposal A, 2026-10-23): it refuses the call even
    // where Claude Code would not read the JSON. Claude Code 2.1.309 shows it as "PreToolUse:<tool> hook error: [<the hook's
    // command>]: <reason>" and adds which plugin it came from; a JSON deny would show without the bracketed command (the
    // harness, r01). ask and allow stay JSON at exit 0: ignored, they fall back to Claude Code's own checks.
    : decision.verdict === "deny"
      ? { stdout: "", stderr: `${DENY_LEAD}${deniedText(decision.reason)}`, exitCode: 2 }
      : { stdout: json({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: decision.verdict, permissionDecisionReason: decision.reason } }), stderr: "", exitCode: 0 }),
  replySessionEnd: (summary: string): Reply => ({ stdout: "", stderr: summary, exitCode: 0 }),
  replyIgnored: (): Reply => ({ stdout: "", stderr: "", exitCode: 0 }),
  // A blocking error refuses the call (exit 2): Claude Code shows "PreToolUse:<tool> hook error: <stderr>", so the text says
  // first that IronTrellis refused it (DENY, founder's live check 01 and BRAND-001), not that something broke.
  replyError: (message: string, blocking: boolean): Reply => ({ stdout: "", stderr: blocking ? `${DENY_LEAD}${deniedText(message)}` : message, exitCode: blocking ? 2 : 1 }),
  // failOpen: exit 0 (the wrapper turns any other failure into a refusal) and a systemMessage the user sees.
  replyFailOpen: (message: string): Reply => ({ stdout: json({ systemMessage: `IronTrellis could not check this call and lets it through ("failOpen": true): ${message}` }), stderr: message, exitCode: 0 }),
  install: (command: string): InstallEntry => {
    // PreToolUse fails closed on a timeout too (KI 61): Claude Code's "onFailure": "block" counts a hook that times out, cannot
    // start or exits with another code as exit 2. Claude Code ignores the key on Stop and SessionEnd, and SessionStart guards no action.
    const hook = (event: string, timeout: number, extra: Readonly<Record<string, unknown>> = {}) => [{ hooks: [{ type: "command", command: `${command} claude-code ${event}`, timeout, ...extra }] }];
    return {
      path: ".claude/settings.json",
      content: { hooks: { SessionStart: hook("SessionStart", 30), PreToolUse: hook("PreToolUse", 30, { onFailure: "block" }), Stop: hook("Stop", 30), SessionEnd: hook("SessionEnd", 10) } },
    };
  },
  defaultPolicy: () => ({
    sideEffecting: [
      { tool: "Bash", action: "run-shell", resource: "repo:${project}" },
      { tool: "Write", action: "write-file", resource: "repo:${project}" },
      { tool: "Edit", action: "write-file", resource: "repo:${project}" },
      { tool: "MultiEdit", action: "write-file", resource: "repo:${project}" },
      { tool: "NotebookEdit", action: "write-file", resource: "repo:${project}" },
      { tool: "mcp__*", action: "call-mcp", resource: "mcp:${server}" },
    ],
    readOnly: ["Read", "Grep", "Glob", "LS", "WebFetch", "WebSearch", "TodoWrite", "TodoRead", "Task", "AskUserQuestion", "NotebookRead", "BashOutput", "ToolSearch", "EnterPlanMode", "ExitPlanMode"],
  }),
});
