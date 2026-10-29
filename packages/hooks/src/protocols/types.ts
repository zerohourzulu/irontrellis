/**
 * The protocol-independent shape of a hook invocation. Each protocol module
 * (claude-code.ts, codex.ts, cursor.ts) parses its host's stdin JSON into a
 * `HookEvent`, and renders the hook's decision back into the host's stdout
 * JSON and exit code. Everything between the two — session admission, the
 * authority check, the handover record — is protocol-independent (hook.ts).
 */

export type ProtocolId = "claude-code" | "codex" | "cursor";
export const PROTOCOL_IDS: readonly ProtocolId[] = Object.freeze(["claude-code", "codex", "cursor"]);

export type HookEvent =
  | Readonly<{ kind: "session-start"; sessionId: string; cwd: string | undefined; source: string | undefined }>
  | Readonly<{
      kind: "tool"; sessionId: string; cwd: string | undefined; toolName: string; toolInput: Readonly<Record<string, unknown>>; toolUseId: string | undefined;
      /** Whether this host event honours an `ask` answer; when false the hook applies `askFallback`. */
      canAsk: boolean;
      /** The MCP server name when the host reports it separately (Cursor). */
      mcpServer: string | undefined;
      /** Set when this event is a duplicate of a more specific gate the host also runs (Cursor preToolUse for shell/MCP). */
      deferTo: string | undefined;
    }>
  | Readonly<{ kind: "session-end"; sessionId: string; cwd: string | undefined; reason: string | undefined; final: boolean }>
  | Readonly<{ kind: "ignored"; sessionId: string | undefined; note: string }>
  /** A tool event (PreToolUse, beforeShellExecution, …) that could not be parsed or validated: refused unless failOpen. */
  | Readonly<{ kind: "malformed"; note: string }>;

/**
 * allow / deny / ask are the host's own answers. "defer" is no decision: the
 * hook has no objection and leaves the call to the host's own permission check
 * (Claude Code and Codex: exit 0 with no stdout; Cursor, whose permission hooks
 * must answer, gets `permission: "allow"`).
 */
export type Verdict = "allow" | "deny" | "ask" | "defer";
export type ToolDecision = Readonly<{
  verdict: Verdict; reason: string;
  /** A-38 (format 2): a DENY the grants decided (re-derivable): the request the hook records as a refusal of the host session. */
  refusal?: Readonly<{ action: string; resource: string; code: string; template: string; rendersToolInput: boolean; withoutSession?: boolean }>;
}>;
/** What the process writes and returns. `stdout` is the host's protocol answer; `stderr` is for humans (and, on exit 2, the host's blocking reason). */
export type Reply = Readonly<{ stdout: string; stderr: string; exitCode: number }>;

export type InstallEntry = Readonly<{ path: string; content: Readonly<Record<string, unknown>> }>;

export interface Protocol {
  readonly id: ProtocolId;
  readonly name: string;
  /** Primary documentation this module was written against, with the date it was read. */
  readonly docs: string;
  readonly docsCheckedOn: string;
  /** Event names this hook accepts on the command line, in the host's spelling. */
  readonly events: readonly string[];
  /** The subset of `events` that gate a tool call: a malformed payload there fails closed. */
  readonly toolEvents: readonly string[];
  parse(eventName: string, payload: Readonly<Record<string, unknown>>): HookEvent;
  /** `warning` is for the person running the host (e.g. a session that was not admitted), shown where the host supports it. */
  replySessionStart(context: string, warning?: string): Reply;
  replyTool(event: Extract<HookEvent, { kind: "tool" }>, decision: ToolDecision): Reply;
  replySessionEnd(summary: string): Reply;
  replyIgnored(): Reply;
  /** The host-level error reply: `blocking` asks the host to refuse the action (tool events), otherwise the error is non-blocking. */
  replyError(message: string, blocking: boolean): Reply;
  /**
   * A tool event's error the user chose to let through (`"failOpen": true`): the call goes to the host's own permissions,
   * with the error shown. Not a blocking exit, so the hook wrapper and the plugin's launcher pass it on.
   */
  replyFailOpen(message: string): Reply;
  /** The settings file (relative to the project) and the hook entries `install` prints or merges. */
  install(command: string): InstallEntry;
  /** The tool → (action, resource) mapping `init` writes for this host. */
  defaultPolicy(): Readonly<{ sideEffecting: readonly Readonly<{ tool: string; action: string; resource: string }>[]; readOnly: readonly string[] }>;
}

export const str = (value: unknown): string | undefined => (typeof value === "string" && value.length > 0 ? value : undefined);
export const obj = (value: unknown): Readonly<Record<string, unknown>> =>
  value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
/** A JSON object, or undefined for anything else (absent, null, array, scalar). */
export const objOrUndefined = (value: unknown): Readonly<Record<string, unknown>> | undefined =>
  value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
export const json = (value: unknown): string => `${JSON.stringify(value)}\n`;
