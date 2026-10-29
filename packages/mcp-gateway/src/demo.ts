/**
 * The synthetic demo case: a format-2 history with one worker, its runtime session (disposable Ed25519 key) and three
 * grants, the gateway's own connector agent and session (it signs CONNECTOR refusals and effects, SPEC §10), two
 * ordinary upstream MCP servers (documents, tickets) and a gateway configuration file, in exactly-once or per-call mode.
 * With `investigation`, the case also holds one restriction request whose reply was lost (an unknown outcome) and the
 * open investigation duty over it, which the duty-policy commands continue (SPEC §13). Used by
 * `irontrellis-mcp-gateway setup` and by the tests.
 */
import { mkdirSync, writeFileSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  REMOTE_SERVICE_REPORT_ADAPTER_ID, approvedAdapterProfileForPolicy, commitTerms, createLocalDomain, createLocalAttemptOwner, deriveAdapterIdentity, generateKeyPair,
  openHistoryStore, openLocalAttemptRecorder, openLocalExecution, signHashWith, type KeyPair, type LocalExecutionOptions, type LocalOwner,
} from "@ramex-labs/irontrellis";
import type { GatewayConfigFile } from "./config.ts";
import { pathField } from "./data.ts";

export const HOUR = 3600000;
const DAY = 24 * HOUR;
export type DemoOptions = Readonly<{ mode?: "exactly-once" | "per-call"; recordCalls?: boolean; maxEvents?: number; investigation?: boolean }>;
export type DemoCase = Readonly<{
  local: LocalExecutionOptions; owner: LocalOwner; config: GatewayConfigFile; configFile: string; pair: KeyPair; directory: string;
  /** The gateway's own connector identity: agent `gateway`, session `gateway`, its key pair. */
  connector: Readonly<{ agent: string; session: string; pair: KeyPair }>;
  /** The connector's signer as the gateway options take it (`createGateway({ ...config, local, connectorSigner })`). */
  connectorSigner: Readonly<{ session: string; signHash: ReturnType<typeof signHashWith> }>;
  /** With `investigation`: the open attempt duty and the intent whose outcome is unknown. */
  investigation?: Readonly<{ duty: string; intent: string; role: string; incident: string }>;
}>;

/** The investigation case's ids (SPEC §13): the duty the duty-policy commands continue. */
export const INVESTIGATION = Object.freeze({ duty: "duty:incident-42", intent: "intent:incident-42-restrict", role: "analyst" });

export async function createDemoCase(target: string, { mode = "exactly-once", recordCalls = false, maxEvents, investigation = false }: DemoOptions = {}): Promise<DemoCase> {
  mkdirSync(target, { mode: 0o700 });
  const directory = realpathSync(target);
  mkdirSync(join(directory, "records"), { mode: 0o700 });
  writeFileSync(join(directory, "incident.txt"), "Synthetic incident: investigate document access.\n", { mode: 0o600 });
  const pair = generateKeyPair("ed25519", "key:worker"), connectorPair = generateKeyPair("ed25519", "key:gateway"), now = Date.now();
  const local: LocalExecutionOptions = {
    historyFile: join(directory, "history.jsonl"), domain: createLocalDomain(), owner: "operator", controller: "host", session: "worker:1", now: Date.now, signHash: signHashWith(pair),
  };
  const owner = await createLocalAttemptOwner({ ...local, ...(maxEvents === undefined ? {} : { maxEvents }) });
  await owner.createAgent({ id: "worker" });
  await owner.createRole({ id: "analyst" });
  await owner.appoint({ agent: "worker", role: "analyst", tenure: "shift:1", number: 1 });
  await owner.admitRuntime({ agent: "worker", session: local.session, epoch: 1, key: "key:worker", credential: pair.credential, expiresAt: now + HOUR });
  // The connector identity (docs/API.md §2): created here under the owner key, never by an agent.
  await owner.createAgent({ id: "gateway" });
  await owner.admitRuntime({ agent: "gateway", session: "gateway", epoch: 1, key: "key:gateway", credential: connectorPair.credential, expiresAt: now + 30 * DAY });
  await owner.grant({ id: "read", to: "worker", actions: ["read-document", "read_document"], resources: ["document:incident"], expiresAt: now + HOUR });
  await owner.grant({ id: "write", to: "worker", actions: ["create-ticket", "create_ticket"], resources: ["queue:incident"], expiresAt: now + HOUR });
  await owner.grant({ id: "inspect", to: "worker", actions: ["inspect-operation"], resources: ["document:incident", "queue:incident"], expiresAt: now + HOUR });
  let opened: Readonly<{ duty: string; intent: string; role: string }> | undefined;
  if (investigation) opened = await openInvestigation(owner, local, now);
  const upstreamServer = fileURLToPath(new URL("./demo-upstream.js", import.meta.url));
  const upstreams = ["documents", "tickets"].map((id) => ({ id, command: process.execPath, args: [upstreamServer, directory, id] }));
  const readApproval = { name: "read_document", inputSchema: { type: "object", properties: { document: { type: "string", enum: ["incident"] } }, required: ["document"], additionalProperties: false }, annotations: { readOnlyHint: true } };
  const ticketApproval = { name: "create_ticket", inputSchema: { type: "object", properties: { title: { type: "string", minLength: 1, maxLength: 120 } }, required: ["title"], additionalProperties: false } };
  const operations = [
    { name: "read_incident", upstream: "documents", tool: "read_document", businessKey: "incident:42:read", action: "read-document", resource: "document:incident", role: "analyst", tenure: "shift:1", approval: readApproval },
    { name: "create_incident_ticket", upstream: "tickets", tool: "create_ticket", businessKey: "incident:42:ticket", action: "create-ticket", resource: "queue:incident", role: "analyst", tenure: "shift:1", approval: ticketApproval },
  ];
  const tools = [
    { name: "read_incident", upstream: "documents", tool: "read_document", resource: "document:{document}", approval: readApproval },
    { name: "create_incident_ticket", upstream: "tickets", tool: "create_ticket", resource: "queue:incident", approval: ticketApproval },
  ];
  const connector = { session: "gateway", keyFile: join(directory, "gateway-connector.key") };
  // A-19.4: the configuration names the history it serves (recordHash(0) of the genesis line).
  const historyId = owner.exportHistory().length > 0 ? openHistoryStore(local.historyFile, { inspect: true, witness: false }).state().eventHistoryHashes[0]! : undefined;
  const base = { historyFile: local.historyFile, domain: local.domain, owner: local.owner, controller: local.controller, session: local.session, keyFile: join(directory, "worker.key"), upstreams, connector, ...(historyId === undefined ? {} : { historyId }) };
  const config: GatewayConfigFile = mode === "per-call"
    ? { ...base, mode, tools, ...(recordCalls ? { recordCalls: true, storage: join(directory, "records"), role: "analyst", tenure: "shift:1" } : {}) }
    : { ...base, mode, storage: join(directory, "records"), operations };
  // A-185.6: setup validates the path fields with the loader's own validator, so it never writes a config the loader refuses.
  for (const path of [config.historyFile, config.keyFile, connector.keyFile, ...(config.storage === undefined ? [] : [config.storage])]) pathField(path);
  writeFileSync(config.keyFile, pair.privateKey + "\n", { mode: 0o600 });
  writeFileSync(connector.keyFile, connectorPair.privateKey + "\n", { mode: 0o600 });
  const configFile = join(directory, "gateway.json");
  writeFileSync(configFile, JSON.stringify(config, null, 2) + "\n", { mode: 0o600 });
  return {
    local, owner, config, configFile, pair, directory, connector: { agent: "gateway", session: "gateway", pair: connectorPair },
    connectorSigner: { session: "gateway", signHash: signHashWith(connectorPair) },
    ...(opened === undefined ? {} : { investigation: { ...opened, incident: join(directory, "incident.txt") } }),
  };
}

/**
 * The investigation case: the worker asked a remote service to restrict access to the incident document; the service's
 * reply was lost (OUTCOME_UNKNOWN, nothing proves the outside result), and the worker opened an investigation duty over
 * that attempt. The service is simulated here: no upstream is contacted.
 */
async function openInvestigation(owner: LocalOwner, local: LocalExecutionOptions, now: number): Promise<Readonly<{ duty: string; intent: string; role: string }>> {
  const { duty, intent, role } = INVESTIGATION;
  await owner.grant({ id: "restrict", to: "worker", actions: ["restrict-access"], resources: ["document:incident"], expiresAt: now + HOUR, maxTransactions: 1 });
  await owner.grant({ id: "investigate", to: "worker", actions: ["CREATE_ATTEMPT_DUTY", "ASSIGN_ATTEMPT_DUTY", "CLOSE_ATTEMPT_DUTY", "OBSERVE_OUTCOME"], resources: ["document:incident", intent, duty], expiresAt: now + DAY });
  const state = owner.exportHistory()[0]!.data as { adapterPolicyHash: `0x${string}` };
  const unknown = (input: Parameters<typeof deriveAdapterIdentity>[0]) => {
    const identity = deriveAdapterIdentity(input);
    return { status: "OUTCOME_UNKNOWN" as const, idempotencyKey: identity.idempotencyKey, submissionFingerprint: identity.submissionFingerprint };
  };
  const adapter = { adapterProfile: approvedAdapterProfileForPolicy(state.adapterPolicyHash, REMOTE_SERVICE_REPORT_ADAPTER_ID), submit: async (input: never) => unknown(input), reconcile: unknown };
  await openLocalExecution(local, adapter as never, "REMOTE_REPORT").run({
    id: intent, intentId: intent, action: "restrict-access", resource: "document:incident", role, tenure: "shift:1", termsCommitment: commitTerms({ case: "incident 42", request: "restrict access" }),
  });
  await openLocalAttemptRecorder(local).createDuty({ id: duty, intent, description: "Find out whether access to the incident document was restricted; the service's reply was lost.", deadline: now + 3 * DAY });
  return { duty, intent, role };
}
