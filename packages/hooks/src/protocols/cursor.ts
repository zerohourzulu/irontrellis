/**
 * Cursor agent hooks.
 *
 * Source: "Hooks", https://cursor.com/docs/agent/hooks, read on 2026-09-24.
 * Field names relied on:
 *
 * Configuration: `<project>/.cursor/hooks.json` or `~/.cursor/hooks.json`:
 *   { "version": 1, "hooks": { "<hookName>": [ { "command": string, "timeout"?: seconds, "matcher"?: regex, "failClosed"?: boolean } ] } }
 *
 * Hooks used here: sessionStart, beforeShellExecution, beforeMCPExecution,
 *   preToolUse, stop, sessionEnd (afterFileEdit is accepted and ignored: it
 *   fires after the edit and cannot refuse it).
 *
 * stdin (all hooks): conversation_id, generation_id, model, hook_event_name,
 *   cursor_version, workspace_roots (array), user_email, transcript_path.
 *   sessionStart adds session_id, is_background_agent, composer_mode.
 *   sessionEnd adds session_id, reason ("completed" | "aborted" | "error" |
 *   "window_close" | "user_close"), duration_ms, final_status.
 *   beforeShellExecution: command, cwd.
 *   beforeMCPExecution: tool_name, tool_input, mcp_server_name, and url (HTTP
 *   servers) or command (stdio servers).
 *   preToolUse: tool_name ("Shell", "Read", "Write", "Grep", "Delete", "Task",
 *   MCP tools), tool_input, tool_use_id, cwd.
 *   stop: status ("completed" | "aborted" | "error"), loop_count.
 *   This module keys the IronTrellis session on conversation_id (present on every
 *   hook) and falls back to session_id when conversation_id is absent.
 *
 * stdout (exit 0, JSON):
 *   beforeShellExecution / beforeMCPExecution: { "permission": "allow" | "deny" | "ask", "user_message"?: string, "agent_message"?: string }
 *   preToolUse: { "permission": "allow" | "deny", "user_message"?, "agent_message"? } — the schema
 *                accepts "ask" but it "isn't enforced for this hook", so an `ask`
 *                decision becomes the configured `askFallback` ("deny" by default).
 *   sessionStart: { "additional_context": string }
 *   stop / sessionEnd: output ignored (stop may carry followup_message; not used).
 *   "invalid JSON or a response that doesn't match the hook's schema blocks the action."
 * Exit codes: 0 = success (JSON used); 2 = block (same as permission "deny");
 *   other = hook failed, action proceeds unless "failClosed": true.
 */
import { json, objOrUndefined, str, type HookEvent, type InstallEntry, type Protocol, type Reply, type ToolDecision } from "./types.ts";

export const CURSOR_EVENTS = Object.freeze(["sessionStart", "beforeShellExecution", "beforeMCPExecution", "preToolUse", "afterFileEdit", "beforeSubmitPrompt", "stop", "sessionEnd"]);

const SHELL_TOOL = "Shell";

const TOOL_EVENTS = Object.freeze(["beforeShellExecution", "beforeMCPExecution", "preToolUse"]);

const parse = (eventName: string, payload: Readonly<Record<string, unknown>>): HookEvent => {
  const sessionId = str(payload.conversation_id) ?? str(payload.session_id);
  const roots = Array.isArray(payload.workspace_roots) ? payload.workspace_roots.filter((r): r is string => typeof r === "string") : [];
  const cwd = str(payload.cwd) ?? roots[0];
  if (sessionId === undefined) {
    // Fail closed on the permission hooks; the others have nothing to refuse.
    return TOOL_EVENTS.includes(eventName) ? { kind: "malformed", note: `${eventName} without conversation_id or session_id` } : { kind: "ignored", sessionId, note: `${eventName} without conversation_id or session_id` };
  }
  switch (eventName) {
    case "sessionStart":
      return { kind: "session-start", sessionId, cwd, source: str(payload.composer_mode) };
    case "beforeShellExecution": {
      const command = str(payload.command);
      if (command === undefined) return { kind: "malformed", note: "beforeShellExecution without a string command" };
      return { kind: "tool", sessionId, cwd, toolName: SHELL_TOOL, toolInput: { command, cwd: str(payload.cwd) ?? "" }, toolUseId: undefined, canAsk: true, mcpServer: undefined, deferTo: undefined };
    }
    case "beforeMCPExecution": {
      const server = str(payload.mcp_server_name), tool = str(payload.tool_name), toolInput = objOrUndefined(payload.tool_input);
      if (tool === undefined) return { kind: "malformed", note: "beforeMCPExecution without a string tool_name" };
      if (toolInput === undefined) return { kind: "malformed", note: "beforeMCPExecution without a tool_input object" };
      // Normalised to the Claude Code / Codex spelling so one policy rule (`mcp__*`) covers all three hosts.
      const toolName = tool.startsWith("mcp__") ? tool : `mcp__${server ?? "unknown"}__${tool}`;
      return { kind: "tool", sessionId, cwd, toolName, toolInput, toolUseId: undefined, canAsk: true, mcpServer: server, deferTo: undefined };
    }
    case "preToolUse": {
      const toolName = str(payload.tool_name), toolInput = objOrUndefined(payload.tool_input);
      if (toolName === undefined) return { kind: "malformed", note: "preToolUse without a string tool_name" };
      if (toolInput === undefined) return { kind: "malformed", note: "preToolUse without a tool_input object" };
      const server = str(payload.mcp_server_name);
      const isMcp = server !== undefined || toolName.startsWith("mcp__");
      // Shell and MCP calls have their own (ask-capable) gates, installed together with this one; preToolUse defers to them.
      const deferTo = toolName === SHELL_TOOL ? "beforeShellExecution" : isMcp ? "beforeMCPExecution" : undefined;
      return { kind: "tool", sessionId, cwd, toolName, toolInput, toolUseId: str(payload.tool_use_id), canAsk: false, mcpServer: server, deferTo };
    }
    case "sessionEnd":
      return { kind: "session-end", sessionId, cwd, reason: str(payload.reason), final: true };
    case "stop":
      return { kind: "session-end", sessionId, cwd, reason: str(payload.status) ?? "stop", final: false };
    default:
      return { kind: "ignored", sessionId, note: `${eventName} is accepted but not acted on` };
  }
};

// Cursor's permission hooks must answer a permission ("invalid JSON or a response that doesn't match the
// hook's schema blocks the action"), so "defer" is rendered as "allow"; the docs do not say that a hook's
// allow skips Cursor's own approval settings.
const permission = (decision: ToolDecision): Reply => ({
  stdout: json({ permission: decision.verdict === "defer" ? "allow" : decision.verdict, user_message: decision.reason, agent_message: decision.reason }), stderr: "", exitCode: 0,
});

export const cursor: Protocol = Object.freeze({
  id: "cursor" as const,
  name: "Cursor",
  docs: "https://cursor.com/docs/agent/hooks",
  docsCheckedOn: "2026-09-24",
  events: CURSOR_EVENTS,
  toolEvents: TOOL_EVENTS,
  parse,
  replySessionStart: (context: string, warning?: string): Reply => ({ stdout: json({ additional_context: context }), stderr: warning ?? "", exitCode: 0 }),
  replyTool: (_event: Extract<HookEvent, { kind: "tool" }>, decision: ToolDecision): Reply => permission(decision),
  replySessionEnd: (summary: string): Reply => ({ stdout: json({}), stderr: summary, exitCode: 0 }),
  // A permission hook that answers nothing is treated as a schema mismatch, which blocks: always answer.
  replyIgnored: (): Reply => ({ stdout: json({ permission: "allow", continue: true }), stderr: "", exitCode: 0 }),
  replyFailOpen: (message: string): Reply => ({ stdout: "", stderr: message, exitCode: 1 }), // as before: a non-blocking error
  replyError: (message: string, blocking: boolean): Reply => ({ stdout: blocking ? json({ permission: "deny", user_message: message, agent_message: message }) : "", stderr: message, exitCode: blocking ? 2 : 1 }),
  install: (command: string): InstallEntry => {
    const hook = (event: string, timeout: number, extra: Record<string, unknown> = {}) => [{ command: `${command} cursor ${event}`, timeout, ...extra }];
    return {
      path: ".cursor/hooks.json",
      content: {
        version: 1,
        hooks: {
          sessionStart: hook("sessionStart", 30),
          beforeShellExecution: hook("beforeShellExecution", 30, { failClosed: true }),
          beforeMCPExecution: hook("beforeMCPExecution", 30, { failClosed: true }),
          preToolUse: hook("preToolUse", 30, { failClosed: true }),
          stop: hook("stop", 30),
          sessionEnd: hook("sessionEnd", 10),
        },
      },
    };
  },
  defaultPolicy: () => ({
    sideEffecting: [
      { tool: "Shell", action: "run-shell", resource: "repo:${project}" },
      { tool: "Write", action: "write-file", resource: "repo:${project}" },
      { tool: "Edit", action: "write-file", resource: "repo:${project}" },
      { tool: "Delete", action: "write-file", resource: "repo:${project}" },
      { tool: "mcp__*", action: "call-mcp", resource: "mcp:${server}" },
    ],
    readOnly: ["Read", "Grep", "Glob", "ListDir", "Task", "WebSearch", "WebFetch"],
  }),
});
