/**
 * `@ramex-labs/irontrellis-mcp`: the IronTrellis evidence MCP server. The
 * exports are host-side plumbing (configuration, server factory, demo setup).
 */
export { createEvidenceServer, serveEvidence, summary, toolDefinition, TOOL_NAME, TOOL_ANNOTATIONS, SERVER_INFO } from "./server.ts";
export type { EvidenceSummary, ServeOptions } from "./server.ts";
export { loadEvidenceTool, readEvidenceConfig, privateFile, ConfigError } from "./config.ts";
export type { EvidenceConfigFile } from "./config.ts";
export { createDemo, HOUR } from "./setup.ts";
export type { Demo } from "./setup.ts";
export { runDemo } from "./client.ts";
export { guardedInput } from "./guard.ts";
export type { GuardOptions } from "./guard.ts";
export { parseStrictJson, StrictJsonError } from "./strict-json.ts";
