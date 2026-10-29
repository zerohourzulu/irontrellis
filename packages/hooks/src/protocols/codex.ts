/**
 * OpenAI Codex CLI hooks.
 *
 * Source: "Hooks", https://developers.openai.com/codex/hooks (redirects to
 * https://learn.chatgpt.com/docs/hooks), read on 2026-09-24. Codex has a
 * first-class hooks mechanism whose shape deliberately mirrors Claude Code's.
 * Field names relied on:
 *
 * Configuration: `<repo>/.codex/hooks.json` or `~/.codex/hooks.json` (also
 *   inline `[hooks]` tables in config.toml):
 *   { "hooks": { "<EventName>": [ { "matcher"?: regex, "hooks": [ { "type": "command", "command": string, "timeout"?: seconds } ] } ] } }
 *   Hooks are on by default in current releases (`[features] hooks = false` turns
 *   them off; `codex_hooks` is the deprecated alias). Non-managed hooks need a
 *   one-time trust review through the `/hooks` command inside Codex.
 *
 * Events: SessionStart, UserPromptSubmit, PreToolUse, PermissionRequest,
 *   PostToolUse, PreCompact, PostCompact, SubagentStart, SubagentStop, Stop,
 *   Interrupt, SessionEnd.
 *
 * stdin (all events): session_id, transcript_path (string | null), cwd,
 *   hook_event_name, model; turn-scoped events add permission_mode and turn_id.
 *   SessionStart adds source; PreToolUse/PostToolUse add tool_name, tool_input,
 *   tool_use_id; SessionEnd adds reason (documented as always "other").
 *   Tool names: shell commands are "Bash" ({command}); file edits are
 *   "apply_patch" ({command: <patch text>}, matcher aliases Edit and Write);
 *   MCP tools are "mcp__<server>__<tool>"; other local functions use their
 *   function name (update_plan, spawn_agent, ...).
 *
 * stdout (exit 0, JSON):
 *   PreToolUse:   { "hookSpecificOutput": { "hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": string } }
 *                 or "allow" (optionally with "updatedInput"); exit 0 with no output is
 *                 no decision (Codex's own approval policy applies), which is what
 *                 the hook answers by default when it has no objection. The docs state that
 *                 permissionDecision "ask" is "parsed but not supported yet", so
 *                 this module never emits it: an `ask` decision becomes the
 *                 configured `askFallback` ("deny" by default) with a reason that says so.
 *   SessionStart: { "hookSpecificOutput": { "hookEventName": "SessionStart", "additionalContext": string } }
 *                 (added as developer context; openai/codex issue #45999 reports
 *                 0.154.0 rejecting a top-level additionalContext, hence the nested form).
 *   Stop:         { "decision": "block", "reason": string } continues the turn.
 *   SessionEnd:   1 s default timeout, 3 s maximum — the handover write must be quick.
 * Exit codes: 0 = success; 2 = blocking decision for PreToolUse, PostToolUse and
 *   UserPromptSubmit with the reason on stderr; other = hook failure, reported,
 *   execution continues.
 */
import { json, objOrUndefined, str, type HookEvent, type InstallEntry, type Protocol, type Reply, type ToolDecision } from "./types.ts";

export const CODEX_EVENTS = Object.freeze(["SessionStart", "PreToolUse", "PostToolUse", "UserPromptSubmit", "Stop", "SessionEnd"]);

const parse = (eventName: string, payload: Readonly<Record<string, unknown>>): HookEvent => {
  const sessionId = str(payload.session_id), cwd = str(payload.cwd);
  switch (eventName) {
    case "SessionStart":
      return sessionId === undefined ? { kind: "ignored", sessionId, note: "SessionStart without session_id" } : { kind: "session-start", sessionId, cwd, source: str(payload.source) };
    case "PreToolUse": {
      const toolName = str(payload.tool_name), toolInput = objOrUndefined(payload.tool_input);
      if (sessionId === undefined) return { kind: "malformed", note: "PreToolUse without a string session_id" };
      if (toolName === undefined) return { kind: "malformed", note: "PreToolUse without a string tool_name" };
      if (toolInput === undefined) return { kind: "malformed", note: "PreToolUse without a tool_input object" };
      return { kind: "tool", sessionId, cwd, toolName, toolInput, toolUseId: str(payload.tool_use_id), canAsk: false, mcpServer: undefined, deferTo: undefined };
    }
    case "SessionEnd":
      return sessionId === undefined ? { kind: "ignored", sessionId, note: "SessionEnd without session_id" } : { kind: "session-end", sessionId, cwd, reason: str(payload.reason), final: true };
    case "Stop":
      return sessionId === undefined ? { kind: "ignored", sessionId, note: "Stop without session_id" } : { kind: "session-end", sessionId, cwd, reason: "stop", final: false };
    default:
      return { kind: "ignored", sessionId, note: `${eventName} is accepted but not acted on` };
  }
};

export const codex: Protocol = Object.freeze({
  id: "codex" as const,
  name: "OpenAI Codex CLI",
  docs: "https://developers.openai.com/codex/hooks",
  docsCheckedOn: "2026-09-24",
  events: CODEX_EVENTS,
  toolEvents: Object.freeze(["PreToolUse"]),
  parse,
  replySessionStart: (context: string, warning?: string): Reply => ({ stdout: json({ hookSpecificOutput: { hookEventName: "SessionStart", additionalContext: context } }), stderr: warning ?? "", exitCode: 0 }),
  replyTool: (_event: Extract<HookEvent, { kind: "tool" }>, decision: ToolDecision): Reply => (decision.verdict === "defer"
    ? { stdout: "", stderr: decision.reason, exitCode: 0 }
    // `ask` never reaches here: hook.ts applies askFallback when canAsk is false.
    : { stdout: json({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: decision.verdict, permissionDecisionReason: decision.reason } }), stderr: "", exitCode: 0 }),
  replySessionEnd: (summary: string): Reply => ({ stdout: "", stderr: summary, exitCode: 0 }),
  replyIgnored: (): Reply => ({ stdout: "", stderr: "", exitCode: 0 }),
  replyFailOpen: (message: string): Reply => ({ stdout: "", stderr: message, exitCode: 1 }), // as before: a non-blocking error
  replyError: (message: string, blocking: boolean): Reply => ({ stdout: "", stderr: message, exitCode: blocking ? 2 : 1 }),
  install: (command: string): InstallEntry => {
    const hook = (event: string, timeout: number) => [{ hooks: [{ type: "command", command: `${command} codex ${event}`, timeout }] }];
    // Codex 0.163.0 has no failure policy for a hook (no counterpart of Claude Code's "onFailure": "block"): a PreToolUse
    // hook that times out lets the call through (KI 61; live check B). So its timeout is generous: 120 s, not 30.
    return {
      path: ".codex/hooks.json",
      content: { hooks: { SessionStart: hook("SessionStart", 30), PreToolUse: hook("PreToolUse", 120), Stop: hook("Stop", 30), SessionEnd: hook("SessionEnd", 3) } },
    };
  },
  defaultPolicy: () => ({
    sideEffecting: [
      { tool: "Bash", action: "run-shell", resource: "repo:${project}" },
      { tool: "apply_patch", action: "write-file", resource: "repo:${project}" },
      { tool: "Write", action: "write-file", resource: "repo:${project}" },
      { tool: "Edit", action: "write-file", resource: "repo:${project}" },
      { tool: "mcp__*", action: "call-mcp", resource: "mcp:${server}" },
    ],
    readOnly: ["update_plan", "view_image", "web_search", "read_file", "list_dir", "grep_files"],
  }),
});
