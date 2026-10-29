/**
 * Tool → (action, resource) mapping. A rule's `tool` is an exact tool name or a
 * glob (`*` matches any run of characters, `mcp__*`). Its `resource` is a
 * template over `${project}`, `${cwd}`, `${tool}`, `${server}` and `${mcpTool}`
 * (from `mcp__<server>__<tool>`), and any top-level string field of the host's
 * tool_input (`${file_path}`, `${command}`). The rendered resource has to be a
 * history identifier (1–128 printable characters), because grants match
 * resources exactly; a template that does not resolve leaves the call unmapped.
 */
import type { Policy, Rule } from "./config.ts";

export type Mapping =
  | Readonly<{ kind: "read-only"; tool: string }>
  | Readonly<{ kind: "side-effect"; tool: string; action: string; resource: string; rule: Rule }>
  | Readonly<{ kind: "unmapped"; tool: string; why: string }>;

export type TemplateContext = Readonly<{ project: string; cwd: string | undefined; tool: string; server: string | undefined; toolInput: Readonly<Record<string, unknown>> }>;

// 1–128 Unicode scalar values (A-89.2, A-170.3; RA-10): the u flag counts code points, and a lone surrogate is refused.
const IDENTIFIER = /^(?!.*\p{Cs})[^\u0000-\u001f\u007f]{1,128}$/u;

const globToRegExp = (glob: string): RegExp => new RegExp(`^${glob.split("*").map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`);
export const toolMatches = (pattern: string, tool: string): boolean => (pattern.includes("*") ? globToRegExp(pattern).test(tool) : pattern === tool);

/** `mcp__<server>__<tool>` → { server, tool }; anything else → undefined. */
export const mcpParts = (tool: string): { server: string; tool: string } | undefined => {
  const match = /^mcp__(.+?)__(.+)$/.exec(tool);
  return match === null ? undefined : { server: match[1]!, tool: match[2]! };
};

/** Render a resource template; returns undefined when a variable is missing or the result is not an identifier. */
export function renderTemplate(template: string, ctx: TemplateContext): string | undefined {
  const mcp = mcpParts(ctx.tool);
  let missing = false;
  const rendered = template.replace(/\$\{([A-Za-z0-9_.]+)\}/g, (_m, name: string) => {
    let value: unknown;
    switch (name) {
      case "project": value = ctx.project; break;
      case "cwd": value = ctx.cwd; break;
      case "tool": value = ctx.tool; break;
      case "server": value = ctx.server ?? mcp?.server; break;
      case "mcpTool": value = mcp?.tool; break;
      default: value = ctx.toolInput[name.startsWith("tool_input.") ? name.slice("tool_input.".length) : name];
    }
    if (typeof value !== "string" || value.length === 0) { missing = true; return ""; }
    return value;
  });
  return missing || !IDENTIFIER.test(rendered) ? undefined : rendered;
}

/** A-42: whether a resource template renders tool input (any variable other than project, cwd, tool, server, mcpTool). */
export function rendersToolInput(template: string): boolean {
  for (const m of template.matchAll(/\$\{([A-Za-z0-9_.]+)\}/g)) if (!["project", "cwd", "tool", "server", "mcpTool"].includes(m[1]!)) return true;
  return false;
}

/** First matching rule wins; read-only names are checked first so a broad glob cannot swallow them. */
export function mapTool(policy: Policy, ctx: TemplateContext): Mapping {
  const tool = ctx.tool;
  if (policy.readOnly.some((name) => toolMatches(name, tool))) return { kind: "read-only", tool };
  const rule = policy.sideEffecting.find((r) => toolMatches(r.tool, tool));
  if (rule === undefined) return { kind: "unmapped", tool, why: `no policy rule matches tool "${tool}"` };
  const resource = renderTemplate(rule.resource, ctx);
  if (resource === undefined) return { kind: "unmapped", tool, why: `resource template "${rule.resource}" does not resolve to an identifier for tool "${tool}"` };
  return { kind: "side-effect", tool, action: rule.action, resource, rule };
}

/** The distinct (action, resource) pairs a policy can produce without a tool call — what a session "may" or "may not" do. */
export function staticCapabilities(policy: Policy, project: string): readonly Readonly<{ action: string; resource: string }>[] {
  const seen = new Map<string, { action: string; resource: string }>();
  for (const rule of policy.sideEffecting) {
    const resource = renderTemplate(rule.resource, { project, cwd: undefined, tool: rule.tool, server: undefined, toolInput: {} });
    if (resource === undefined) continue;
    seen.set(`${rule.action}\u0000${resource}`, { action: rule.action, resource });
  }
  return [...seen.values()];
}
