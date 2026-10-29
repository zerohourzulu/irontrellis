/**
 * `@ramex-labs/irontrellis-mcp-gateway`: operator-approved upstream MCP tools
 * behind IronTrellis, as exactly-once jobs or per-call authorized tools.
 * Everything exported here is privileged host configuration.
 */
export { createGateway, operationIdentity, publicError, toolAnnotations, whySummary, resolveResource, RESERVED_TOOL_NAMES, GatewayError } from "./gateway.ts";
export type {
  Gateway, GatewayMode, GatewayOptions, ExactlyOnceOptions, PerCallOptions, Job, PerCallTool, ToolAnnotations, ToolListing, GatewayResult, RunOptions,
} from "./gateway.ts";
export { gatewayServer, serveGateway, catalog, reply, SERVER_INFO } from "./server.ts";
export type { ServeOptions } from "./server.ts";
export { captureUpstream, approval, connectUpstream } from "./upstream.ts";
export type { ToolApproval, UpstreamConfig, UpstreamConnection, UpstreamResult } from "./upstream.ts";
export { ProtectedStdioTransport } from "./stdio.ts";
export { guardedInput } from "./guard.ts";
export type { GuardOptions } from "./guard.ts";
export { parseStrictJson, StrictJsonError } from "./strict-json.ts";
export { acquireHostLease, recoverDeadHost, inspectCase, snapshotCase, verifySnapshot, revokeAuthority, LOCK_FILE } from "./operations.ts";
export type { HostLease, CaseLocation, CaseDiagnostic, RevocationRequest, RevocationResult } from "./operations.ts";
export { initializeAccessPolicy, openAccessPolicy, issuerUrl } from "./access-policy.ts";
export type { AccessPolicy, AccessBinding, AccessIdentity, AccessPolicyDefinition } from "./access-policy.ts";
export { loadGatewayConfig, readGatewayConfig, readKeyFile } from "./config.ts";
export type { GatewayConfigFile, LoadedConfig } from "./config.ts";
export { createDemoCase, HOUR } from "./demo.ts";
export type { DemoCase, DemoOptions } from "./demo.ts";
export * from "./anchor-profile/index.ts";
export { LIVE_ANCHOR_CHAIN } from "./anchor-barrier.ts";
export type { LiveAnchoringOptions, ResumeHorizon, AnchorInstanceObservation } from "./anchor-barrier.ts";
