/**
 * The IronTrellis MCP gateway (privileged host factory; never hand the handle
 * or its options to an agent).
 *
 * Two modes over the same core and the same upstream servers:
 *
 * - `exactly-once` (default): each operator-defined job is one durable
 *   business operation. The first admitted call is forwarded once; a repeat,
 *   a retry after a lost reply or a restart reconciles the original attempt
 *   and never forwards again. Changed arguments are refused.
 * - `per-call`: upstream tools are exposed as ordinary MCP tools. Every call
 *   is authorized (actor = the configured agent, action = the tool name,
 *   resource = the configured template) and forwarded on ALLOW; a DENY is
 *   answered with the WHY summary. Nothing is written to the history unless
 *   `recordCalls: true`, which declares and admits each call as its own
 *   intent through the execution API.
 */
import { randomUUID } from "node:crypto";
import type { JsonSchemaValidator } from "@modelcontextprotocol/server";
import { Ajv, AjvJsonSchemaValidator, addFormats } from "@modelcontextprotocol/server/validators/ajv";
import {
  ADAPTER_POLICY_E5_HASH, ADAPTER_POLICY_E6_HASH, ADAPTER_SUBMISSION_VERSION, REMOTE_SERVICE_REPORT_ADAPTER_ID,
  adapterAcknowledgmentEvidence, approvedAdapterProfileForPolicy, admittedSubmissionIdentity, createRemoteServiceReportAcknowledgment,
  clockAheadOfReader, enforcementWarning, REFUSAL_POLICY_DEFAULTS, observeState, openHistoryStore, openLocalExecution,
  type AdapterSubmissionResult, type AuthorizationDomain, type ContentHash, type ExecutionDispatchContext, type HistoryStore, type LocalExecutionOptions, type ReplayState, type RuntimeSessionRecord,
  type TransactionAdapter, type WhyQueryResult,
} from "@ramex-labs/irontrellis";
import { GatewayError, algorithmFor, check, codeOf, data, durableCreate, exact, hash, id, privateDirectory, readPrivate, same, type Json } from "./data.ts";
import { approval, captureUpstream, connectUpstream, type ToolApproval, type UpstreamConfig, type UpstreamConnection, type UpstreamResult } from "./upstream.ts";
import { openAnchorBarrier, type AnchorBarrier, type LiveAnchoringOptions, type SelectedAnchorReport } from "./anchor-barrier.ts";
import { appendBarrier, dispatchPaths, dispatchStarted, readBarrierChain, readDispatchRequest, retainDispatchRequest } from "./dispatch-files.ts";
import { RECORD_KINDS, createRecorder, upstreamReport, type ConnectorIdentity, type RecordKind, type Recorder } from "./records.ts";

// ---------------------------------------------------------------- types

export type GatewayMode = "exactly-once" | "per-call";
/** MCP tool annotations the gateway publishes for a tool. */
export type ToolAnnotations = Readonly<{ title?: string; readOnlyHint?: boolean; destructiveHint?: boolean; idempotentHint?: boolean; openWorldHint?: boolean }>;
/** One exactly-once job: a fixed upstream tool, business key and the authority the call needs. */
export type Job = Readonly<{
  name: string; upstream: string; tool: string; businessKey: string; action: string; resource: string; role: string; tenure: string; approval: ToolApproval;
  /** Published annotations; default derives from `approval.annotations`, else a non-read-only, idempotent, open-world tool. */
  annotations?: ToolAnnotations;
  /** What the upstream's `structuredContent.irontrellis` reports are recorded for this job (format 2; needs the connector session). */
  records?: readonly RecordKind[];
}>;
/** One per-call tool: forwarded on every ALLOW. `resource` may embed `{argument}` placeholders resolved from the call. */
export type PerCallTool = Readonly<{
  name: string; upstream: string; tool: string; resource: string; approval: ToolApproval;
  /** Core action checked for each call; default: the upstream tool name. */
  action?: string;
  annotations?: ToolAnnotations;
  /** As for jobs; `effect` and `receipt` need `recordCalls` (an admitted intent to bind to). */
  records?: readonly RecordKind[];
}>;
type CommonOptions = Readonly<{
  local: LocalExecutionOptions; upstreams: readonly UpstreamConfig[]; timeoutMs?: number;
  /** The gateway's own owner-admitted session and its signer: it signs CONNECTOR refusals, effects and receipt wrappers (SPEC §10, §11). */
  connectorSigner?: ConnectorIdentity;
  /** Privileged live-anchoring integration; node qualification is a separate deployment gate. */
  anchoring?: LiveAnchoringOptions;
}>;
export type ExactlyOnceOptions = CommonOptions & Readonly<{ mode?: "exactly-once"; storage: string; operations: readonly Job[] }>;
export type PerCallOptions = CommonOptions & Readonly<{
  mode: "per-call"; tools: readonly PerCallTool[];
  /** Declare and admit every call as its own intent (needs `storage`, `role` and `tenure`). Default false: no history write per call. */
  recordCalls?: boolean; storage?: string; role?: string; tenure?: string;
}>;
export type GatewayOptions = ExactlyOnceOptions | PerCallOptions;
export type ToolListing = Readonly<{ name: string; description: string; inputSchema: Json; annotations: ToolAnnotations }>;
export type GatewayResult = Readonly<{ status: string; reason?: string; operationId?: string; upstreamResult?: UpstreamResult; [key: string]: unknown }>;
export type RunOptions = Readonly<{ assertCurrent?: () => void }>;
export interface Gateway {
  readonly mode: GatewayMode;
  tools(): readonly ToolListing[];
  run(name: string, input: unknown, options?: RunOptions): Promise<GatewayResult>;
  /** Exactly-once only: the original attempt without contacting the upstream. */
  status(name: string): GatewayResult;
  /** Current permission for a job or tool (per-call: with the arguments that select the resource). This is an explanation, not permission to execute. */
  why(name: string, args?: unknown): GatewayResult;
  close(): Promise<void>;
}

// ---------------------------------------------------------------- shared helpers

/**
 * The gateway's own tool names, which no upstream tool may take. A frozen read-only view over a module-private Set (KNOWN-ISSUES
 * r2.2 59; the gateway cannot import Core's internal readonly-collections): `has`, `size`, `forEach` and iteration, no `add` or
 * `delete`, so a caller in the same process cannot free a reserved name.
 */
const reservedToolNames = new Set(["irontrellis_status", "irontrellis_why"]);
export const RESERVED_TOOL_NAMES: ReadonlySet<string> = Object.freeze({
  has: (name: string) => reservedToolNames.has(name),
  get size() { return reservedToolNames.size; },
  forEach(callback: (value: string, value2: string, set: ReadonlySet<string>) => void, thisArg?: unknown) { for (const name of reservedToolNames) callback.call(thisArg, name, name, RESERVED_TOOL_NAMES); },
  entries: () => reservedToolNames.entries(),
  keys: () => reservedToolNames.keys(),
  values: () => reservedToolNames.values(),
  [Symbol.iterator]: () => reservedToolNames.values(),
});
const TOOL_NAME = /^[A-Za-z][A-Za-z0-9_]{0,47}$/;
const SAFE_CODES: ReadonlySet<string> = new Set([
  "CAPACITY_CONTROL_ONLY", "CAPACITY_EVENT_LIMIT", "CAPACITY_RESERVED", "CAPACITY_INCOMPATIBLE", "INVALID_INPUT", "TOOL_CHANGED", "CATALOG_LIMIT", "CATALOG_CONFLICT",
  "RUNTIME_NOT_CURRENT", "OPERATION_CONFLICT", "HISTORY_CONFLICT", "HISTORY_LIMIT", "HISTORY_FILE_LIMIT", "ROLLBACK_DETECTED", "SIGNER_FAILED", "STORAGE_UNAVAILABLE",
  "INSPECTION_DENIED", "UNKNOWN_TOOL", "INVALID_ARGUMENTS", "PROFILE_MISMATCH", "CLOCK_INVALID", "ACCESS_NOT_CURRENT", "NOT_A_JOB", "RESPONSE_LIMIT", "UNSUPPORTED_RESULT",
  "UPSTREAM_UNAVAILABLE", "HOST_NOT_OWNED", "KEY_UNAVAILABLE", "WRITE_UNCONFIRMED", "TRANSITION_REJECTED", "CLOCK_AHEAD_OF_READER", "FORMAT_READ_ONLY", "HISTORY_IDENTITY_MISMATCH",
  "CHALLENGE_PROFILE_READ_ONLY",
]);
/** The bounded public form of any failure; unknown codes become GATEWAY_UNAVAILABLE. */
export function publicError(error: unknown): GatewayResult {
  const code = codeOf(error);
  const mayHaveCommitted = error !== null && typeof error === "object" && (error as { mayHaveCommitted?: unknown }).mayHaveCommitted === true;
  // A-185.3 (fail closed): the read-only refusal on an opted-in older file names its remedy (a fixed sentence, no path).
  const remedy = error instanceof GatewayError && error.code === "FORMAT_READ_ONLY" && error.detail !== undefined ? { remedy: READ_ONLY_REMEDY } : {};
  return { status: "REFUSED", reason: code !== undefined && SAFE_CODES.has(code) ? code : "GATEWAY_UNAVAILABLE", mayHaveCommitted, ...remedy };
}
/** A-185.3: what an opted-in deployment on a legacy or format-1 file is told when a call must be recorded. */
export const READ_ONLY_REMEDY = "the history is legacy/format-1 and read-only (SPEC §16.1): calls that must be recorded are refused and nothing is dispatched; run `irontrellis migrate` to write";
/** The durable operation id of a business job: derived from the domain and business key, never chosen by a caller. */
export function operationIdentity(domain: AuthorizationDomain, businessKey: string): string {
  return "mcp:" + hash({ version: "irontrellis-mcp-job/1", domain, businessKey: id(businessKey) }, algorithmFor(domain)).slice(2);
}
const DEFAULT_ANNOTATIONS: ToolAnnotations = Object.freeze({ readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true });
/** Published annotations: explicit configuration, else the approved upstream annotations, else the conservative default. Jobs are always idempotent (a repeat reconciles). */
export function toolAnnotations(explicit: unknown, approved: unknown, options: Readonly<{ idempotent: boolean }>): ToolAnnotations {
  const source = explicit ?? approved;
  if (source === undefined) return options.idempotent ? DEFAULT_ANNOTATIONS : { ...DEFAULT_ANNOTATIONS, idempotentHint: false };
  const a = exact(data(source), [], ["title", "readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"]);
  for (const key of ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"]) check(a[key] === undefined || typeof a[key] === "boolean");
  check(a.title === undefined || (typeof a.title === "string" && a.title.length <= 128));
  const readOnly = a.readOnlyHint === true;
  return Object.freeze({
    ...(a.title === undefined ? {} : { title: a.title as string }),
    readOnlyHint: readOnly,
    destructiveHint: readOnly ? false : (a.destructiveHint as boolean | undefined) ?? true,
    idempotentHint: options.idempotent ? true : (a.idempotentHint as boolean | undefined) ?? readOnly,
    openWorldHint: (a.openWorldHint as boolean | undefined) ?? true,
  });
}
/** The bounded, agent-readable summary of a WHY answer. */
export function whySummary(why: WhyQueryResult): Json {
  if (why.epistemicStatus !== "ESTABLISHED") return { decision: "INDETERMINATE", epistemicStatus: why.epistemicStatus, code: why.code };
  const a = why.answer.authorization;
  if (a.decision === "ALLOW") return { decision: "ALLOW", recognizedRoots: why.scope.recognizedRootIds };
  return {
    decision: "DENY", code: a.code,
    failures: a.failures.slice(0, 8).map((f) => ({ code: f.code, ...(f.subjectId === undefined ? {} : { subjectId: f.subjectId }), ...(f.failingAuthorityId === undefined ? {} : { failingAuthorityId: f.failingAuthorityId }) })),
  };
}
// The SDK 1.x engine (draft-07 Ajv with formats): 2.x defaults schemas without `$schema` to 2020-12, which would change what an approved schema accepts.
const ajv = new Ajv({ strict: false, validateFormats: true, validateSchema: false, allErrors: true });
addFormats(ajv);
const schemaValidator = new AjvJsonSchemaValidator(ajv);
function compileSchema(schema: Json): JsonSchemaValidator<Json> {
  try { return schemaValidator.getValidator<Json>(schema as never); } catch { return check(false, "INVALID_INPUT") as never; }
}
/** `{name}` placeholders in a resource template are filled from string/number/boolean arguments; the result must be an identifier. */
export function resolveResource(template: string, args: Json): string {
  const resolved = template.replace(/\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_m, key: string) => {
    const value = args[key];
    check(typeof value === "string" || typeof value === "number" || typeof value === "boolean", "INVALID_ARGUMENTS");
    return String(value);
  });
  check(!/[{}]/.test(resolved), "INVALID_ARGUMENTS");
  try { return id(resolved); } catch { return check(false, "INVALID_ARGUMENTS") as never; }
}

type Runtime = Readonly<{ store: HistoryStore; session: RuntimeSessionRecord; local: LocalExecutionOptions; algorithm: "keccak256" | "sha256"; recorder: Recorder; readOnly?: string }>;
async function openRuntime(options: CommonOptions): Promise<Runtime> {
  check(options !== null && typeof options === "object" && options.local !== null && typeof options.local === "object");
  const local: LocalExecutionOptions = { ...options.local, domain: data<AuthorizationDomain>(options.local.domain) };
  check(typeof local.now === "function" && typeof local.signHash === "function");
  // The store picks up the remote witness policy from <history>.witness.json and the history's bindings. A format-2
  // history resumes from its snapshot with the root recomputed (CHECKPOINT_RESUME, SPEC §7.5); with `historyId` set, a
  // file whose line 0 is another history is HISTORY_IDENTITY_MISMATCH (A-19.4).
  const store = openHistoryStore(local.historyFile, { trust: "CHECKPOINT_RESUME", ...(local.historyId === undefined ? {} : { historyId: local.historyId }) });
  await witnessCheck(store);
  const state = store.state();
  // A-41 / A-85 (1): the gateway is an enforcement caller. A fenced history is refused; a legacy or format-1 history only
  // with `enforceFromReadOnlyHistory` from its configuration (gateway.json, or that field of the options), warned on every
  // open; naming the file's format (the core API's A-30 writer path) is not the opt-in here. The demo case and every
  // history the tools create are format 2; for an opted-in older file the file's own format is named for the execution
  // handle (SPEC §16.1). Format 2 opens in CHECKPOINT_RESUME (the snapshot's root recomputed, SPEC §7.5).
  const warning = enforcementWarning(local.historyFile, state.format, local.enforceFromReadOnlyHistory === true);
  if (warning !== undefined) process.stderr.write(`${warning}\n`);
  // A-38.1: on a format-2 history the gateway's refusal writes are bounded by recordBudgetMs (spooled past it, drained on the next call).
  // A-185.3: an opted-in older file is read-only for the gateway too: its format is not named (no older writer), and every
  // call that must be recorded is refused before dispatch (`readOnly`, fail closed); decisions still read the file.
  const format2 = state.format === "irontrellis-event/2";
  const localWithFormat: LocalExecutionOptions = { ...local, ...(format2 ? { format: state.format } : {}), ...(format2 && local.refusalPolicy === undefined ? { refusalPolicy: REFUSAL_POLICY_DEFAULTS } : {}) };
  check(same(state.genesis.domain, local.domain), "PROFILE_MISMATCH");
  check(state.genesis.adapterPolicyHash === ADAPTER_POLICY_E5_HASH || state.genesis.adapterPolicyHash === ADAPTER_POLICY_E6_HASH, "PROFILE_MISMATCH");
  const session = state.runtimeSessions.get(id(local.session));
  check(session !== undefined && session.controllerId === local.controller, "RUNTIME_NOT_CURRENT");
  const own = options.connectorSigner;
  check(own === undefined || (typeof own.signHash === "function" && state.runtimeSessions.has(id(own.session))), "RUNTIME_NOT_CURRENT");
  const readOnly = format2 ? undefined : `the history ${local.historyFile} is ${state.format === "continuity-event/0.2" ? "legacy" : "format-1"} and read-only (SPEC §16.1): a call that must be recorded is refused and nothing is dispatched; run \`irontrellis migrate\` to write`;
  return { store, session, local: localWithFormat, algorithm: algorithmFor(local.domain), recorder: createRecorder(localWithFormat, own), ...(readOnly === undefined ? {} : { readOnly }) };
}
/**
 * A history whose witness policy says `requireOnOpen` is read only once the
 * remote witnesses confirmed it (ROLLBACK_DETECTED when they hold a head the
 * file lacks). Answers are reused for the policy's `cacheMs`, so this asks the
 * network at most once per `cacheMs`; the handles the core opens per call start
 * from what this process verified.
 */
async function witnessCheck(store: HistoryStore): Promise<void> {
  const status = store.witnessStatus();
  if (status !== undefined && (status.checkRequired || status.policy.requireOnOpen)) await store.checkWitnesses();
}
/** The live state; a mismatch between the file and the configured domain is a profile error, never a silent switch. */
function readState(rt: Runtime): ReplayState {
  const state = rt.store.state();
  check(same(state.genesis.domain, rt.local.domain), "PROFILE_MISMATCH");
  return state;
}
/** The session must be current (agent live, epoch current, not expired) and, when given, hold the role tenure. */
function assertRuntimeCurrent(rt: Runtime, state: ReplayState, at: number, tenure?: Readonly<{ role: string; tenure: string }>): void {
  // A-22.4: a head dated more than MAX_CLOCK_SKEW_MS past this reader's clock is CLOCK_AHEAD_OF_READER (deny); a smaller lag is CLOCK_INVALID.
  check(Number.isSafeInteger(at) && !clockAheadOfReader(state.head, at), "CLOCK_AHEAD_OF_READER");
  check(at >= state.head.canonicalTime, "CLOCK_INVALID");
  const agent = state.agents.get(rt.session.agentId), s = rt.session;
  check(agent !== undefined && !agent.terminated && agent.currentControlEpoch === s.controlEpoch && (s.expiresAt === undefined || at < s.expiresAt), "RUNTIME_NOT_CURRENT");
  if (tenure !== undefined) {
    const t = state.tenures.get(tenure.tenure);
    check(state.roles.get(tenure.role)?.currentTenureId === tenure.tenure && t !== undefined && !t.closed && t.agentId === s.agentId, "RUNTIME_NOT_CURRENT");
  }
}
function upstreamPool(configs: readonly UpstreamConfig[], timeout: number) {
  const servers = new Map<string, UpstreamConfig>();
  for (const c of configs) { check(!servers.has(c.id)); servers.set(c.id, c); }
  const connections = new Map<string, Promise<UpstreamConnection>>();
  return {
    servers,
    connection(serverId: string): Promise<UpstreamConnection> {
      let pending = connections.get(serverId);
      if (pending === undefined) {
        const p = connectUpstream(servers.get(serverId)!, timeout);
        // GATEWAY-RATE-01: a connection that fails or later closes is evicted, so the next governed call reconnects and is
        // verified again before dispatch. A call whose reply was lost stays OUTCOME_UNKNOWN; nothing is re-dispatched.
        const evict = (): void => { if (connections.get(serverId) === p) connections.delete(serverId); };
        p.then((c) => c.onClose(evict), evict);
        connections.set(serverId, p);
        pending = p;
      }
      return pending;
    },
    async close(): Promise<void> {
      await Promise.allSettled([...connections.values()].map((p) => p.then((c) => c.close())));
    },
  };
}
const unknownOutcome = (i: Readonly<{ idempotencyKey: ContentHash; submissionFingerprint: ContentHash }>): AdapterSubmissionResult =>
  ({ status: "OUTCOME_UNKNOWN", idempotencyKey: i.idempotencyKey, submissionFingerprint: i.submissionFingerprint });
type Retained = Readonly<{ version: "irontrellis-mcp-response/1"; attemptDigest: ContentHash; identity: Json; result: UpstreamResult }>;
const reportedOutcome = (report: Retained, i: Json, status: "SUBMITTED" | "RETRY"): AdapterSubmissionResult => {
  const acknowledgment = createRemoteServiceReportAcknowledgment(i, hash(report)), evidence = adapterAcknowledgmentEvidence(i, acknowledgment);
  const base = { idempotencyKey: i.idempotencyKey as ContentHash, submissionFingerprint: i.submissionFingerprint as ContentHash, acknowledgment };
  return status === "RETRY" ? { status, ...base, retainedEvidence: evidence } : { status, ...base, evidence };
};

/** A `run()` refusal report (A-11) as the gateway passes it on. */
const refusalOf = (result: Readonly<{ refusalRecorded?: boolean; refusal?: Readonly<{ eventId: string }>; refusalNotRecorded?: Readonly<{ reason: string }> }>): Record<string, unknown> =>
  result.refusalRecorded === true ? { refusal: { recorded: true, eventId: result.refusal?.eventId } } : result.refusalRecorded === false ? { refusal: { recorded: false, reason: result.refusalNotRecorded?.reason } } : {};
/**
 * The upstream's `structuredContent.irontrellis` reports that the job or tool is configured to record: a refusal (the
 * reply is an error naming a refusal code) as a CONNECTOR refusal; with an admitted intent (`admitted`), a measurement
 * as an effect and a counterparty receipt envelope as its wrapper. Returns what was recorded, by kind.
 */
async function upstreamRecords(rt: Runtime, op: Readonly<{ operationId?: string; action: string; resource: string; records?: readonly RecordKind[] }>, reply: UpstreamResult, admitted: boolean): Promise<Record<string, unknown>> {
  const kinds = op.records ?? [];
  if (kinds.length === 0) return {};
  const said = upstreamReport(reply.structuredContent), out: Record<string, unknown> = {};
  if (kinds.includes("refusal") && reply.isError && said.refusal !== undefined) {
    const r = await rt.recorder.upstreamRefusal({ actorId: rt.session.agentId, action: op.action, resource: op.resource }, said.refusal.code, reply);
    if (r !== undefined) out.upstreamRefusal = r;
  }
  if (admitted && op.operationId !== undefined) {
    if (kinds.includes("effect") && said.effect !== undefined) { const r = await rt.recorder.effect(op.operationId, said.effect, reply); if (r !== undefined) out.effect = r; }
    if (kinds.includes("receipt") && said.counterpartyReceipt !== undefined) { const r = await rt.recorder.receipt(op.operationId, said.counterpartyReceipt); if (r !== undefined) out.counterpartyReceipt = r; }
  }
  return out;
}
const recordsOf = (value: unknown): readonly RecordKind[] | undefined => {
  if (value === undefined) return undefined;
  check(Array.isArray(value) && value.length <= RECORD_KINDS.length && value.every((k) => RECORD_KINDS.includes(k as RecordKind)) && new Set(value).size === value.length, "INVALID_INPUT");
  return value as RecordKind[];
};
/** The denial code of an authorization answer (`DENY`), else the decision itself. */
const denialCode = (evidence: Readonly<{ decision: string; code?: string }>): string => evidence.code ?? evidence.decision;

/**
 * One forwarded, recorded operation: the attempt is retained before the
 * upstream call and the reply after it; the core admits the intent, invokes
 * the adapter once and records the acknowledgment. Shared by exactly-once jobs
 * and per-call `recordCalls`.
 */
type RecordedCall = Readonly<{ operationId: string; action: string; resource: string; role: string; tenure: string; upstream: string; approval: ToolApproval; args: Json; terms: Json; records?: readonly RecordKind[] }>;
function recordedExecution(rt: Runtime, storage: string, pool: ReturnType<typeof upstreamPool>, barrier?: AnchorBarrier) {
  const profile = approvedAdapterProfileForPolicy(readState(rt).genesis.adapterPolicyHash, REMOTE_SERVICE_REPORT_ADAPTER_ID);
  const paths = (operationId: string) => dispatchPaths(storage, operationId);
  const getReport = (operationId: string, identity: Json, terms: Json): Retained => {
    const p = paths(operationId), attempt = readPrivate<Json>(p.attempt), report = readPrivate<Retained>(p.report);
    const expectedIdentity = { operationVersion: ADAPTER_SUBMISSION_VERSION, ...identity };
    check(same(attempt.identity, expectedIdentity) && same(attempt.terms, terms) && report.attemptDigest === hash(attempt) && same(report.identity, expectedIdentity), "STORAGE_UNAVAILABLE");
    check(report.version === "irontrellis-mcp-response/1" && Buffer.byteLength(JSON.stringify(report.result)) <= 16384, "STORAGE_UNAVAILABLE");
    const consumption = readState(rt).intentConsumptions.get(operationId);
    if (consumption !== undefined) {
      const result = consumption.acknowledgment.result as Readonly<{ kind?: unknown; reportDigest?: Readonly<{ value?: unknown }> }>;
      check(result.kind === "REMOTE_SERVICE_REPORTED" && result.reportDigest?.value === hash(report), "STORAGE_UNAVAILABLE");
    }
    return report;
  };
  return {
    getReport, paths,
    async execute(op: RecordedCall, assertCurrent: () => void, wasAdmitted: boolean, alreadyDenied?: () => Promise<GatewayResult | undefined>) {
      // A-185.3, fail closed: on an opted-in older file nothing that must be recorded is dispatched.
      if (rt.readOnly !== undefined) throw new GatewayError("FORMAT_READ_ONLY", false, rt.readOnly);
      const userAssertCurrent = assertCurrent;
      assertCurrent = () => {
        barrier?.assertRunning();
        userAssertCurrent();
        // The historical path retains its existing timing; live anchoring adds current Core control on every poll and fsync guard.
        if (barrier !== undefined) {
          try { assertRuntimeCurrent(rt, readState(rt), rt.local.now(), op); } catch { throw new GatewayError("ACCESS_NOT_CURRENT"); }
          barrier.assertRunning();
        }
      };
      const absent = () => !dispatchStarted(paths(op.operationId).attempt);
      const noDispatch = (reason: string): GatewayResult => {
        barrier?.remember(op.operationId, reason);
        return { status: reason === "DELAYED" || reason === "STOPPED" ? reason : "NOT_DISPATCHED", reason, operationId: op.operationId, dispatchPerformed: false, externalOutcome: "NOT_PROVEN" };
      };
      let upstream: UpstreamConnection | undefined;
      let dispatchContext: ExecutionDispatchContext | undefined, selected: SelectedAnchorReport | undefined, blockedReason: string | undefined;
      const deadline = barrier?.deadline();
      const closedReason = (error: unknown): string => {
        const code = codeOf(error);
        if (["ROLLBACK_DETECTED", "HISTORY_IDENTITY_MISMATCH", "HISTORY_CONFLICT"].includes(code ?? "")) return "HISTORY_DIVERGED";
        return ["STOPPED", "ADMISSION_MISMATCH", "HISTORY_DIVERGED", "INTENT_NOT_OPEN", "RESUME_HORIZON", "DELAYED", "STORAGE_UNAVAILABLE", "TOOL_CHANGED", "DISPATCH_STARTED"].includes(code ?? "") ? code! : "ACCESS_NOT_CURRENT";
      };
      const assertDispatchState = (context: ExecutionDispatchContext): void => {
        const current = readState(rt), admission = current.intentAdmissions.get(context.intentId);
        check(admission !== undefined && admission.admissionEventId === context.admissionEventId && same(admission.admissionHead, context.admissionHead) &&
          admission.adapterIdentity.idempotencyKey === context.submissionIdentity.idempotencyKey && admission.adapterIdentity.submissionFingerprint === context.submissionIdentity.submissionFingerprint, "ADMISSION_MISMATCH");
        check(current.eventHistoryHashes[context.admissionHead.position] === context.admissionHead.hash, "HISTORY_DIVERGED");
        const obligation = current.obligationIdsBySourceIntent.get(context.intentId);
        check(!current.intentConsumptions.has(context.intentId) && !current.intentOutcomeStates.has(context.intentId) &&
          ![...current.effects.values()].some((effect) => effect.intentId === context.intentId) &&
          (obligation === undefined || current.obligations.get(obligation)?.status !== "CANCELLED"), "INTENT_NOT_OPEN");
      };
      if (barrier !== undefined && (!wasAdmitted || absent())) {
        try {
          if (wasAdmitted) {
            const declaration = readState(rt).intentDeclarations.get(op.operationId);
            check(declaration !== undefined && declaration.data.termsCommitment !== undefined, "ADMISSION_MISMATCH");
            const retained = readDispatchRequest(storage, op.operationId, declaration.data.termsCommitment, rt.algorithm);
            check(same(retained.terms, op.terms) && retained.role === op.role && retained.tenure === op.tenure && retained.upstream === op.upstream, "ADMISSION_MISMATCH");
            // Use the originally retained application arguments, never a freshly rendered request.
            op = { ...op, terms: retained.terms, args: data<Json>(retained.terms.arguments) };
          } else retainDispatchRequest(storage, { operationId: op.operationId, role: op.role, tenure: op.tenure, upstream: op.upstream, terms: op.terms }, rt.algorithm);
        } catch (error) { return noDispatch(codeOf(error) === "STORAGE_UNAVAILABLE" ? "STORAGE_UNAVAILABLE" : "ADMISSION_MISMATCH"); }
      }
      if (!wasAdmitted) {
        // Denied work must not launch an upstream process; discovery precedes the signed admission.
        const denied = await alreadyDenied?.();
        if (denied !== undefined) return denied;
        assertCurrent();
        upstream = await pool.connection(op.upstream);
        await upstream.verify(op.approval);
        assertCurrent();
      }
      let report: Retained | undefined, forwardedThisRun = false;
      const adapter: TransactionAdapter = {
        adapterProfile: profile,
        submit(submission) {
          const i = admittedSubmissionIdentity(submission).identity as unknown as Json, p = paths(op.operationId);
          if (barrier !== undefined) {
            try {
              check(absent(), "DISPATCH_STARTED");
              check(dispatchContext !== undefined && selected !== undefined, "DELAYED");
              const current = readState(rt), context = dispatchContext;
              assertDispatchState(context);
              barrier.horizon(context, current, rt.local.now());
              // Exact report selected by the wait is re-read under invoke's writer lock.
              check(barrier.eligible(context, current, selected.evidence.reportDigest) !== undefined, "DELAYED");
              assertCurrent();
              appendBarrier(storage, context, selected.evidence, barrier.profile);
            } catch (error) { blockedReason = closedReason(error); return Promise.resolve(unknownOutcome(i as never)); }
          } else assertCurrent();
          try { durableCreate(p.attempt, { version: "irontrellis-mcp-attempt/1", identity: i, terms: op.terms }); } catch { blockedReason = "STORAGE_UNAVAILABLE"; return Promise.resolve(unknownOutcome(i as never)); }
          // Admission and the durable start precede transmission; a stop after fsync never permits a resend.
          // A later contradictory report also blocks a not-yet-started external effect.
          if (barrier !== undefined) check(barrier.eligible(dispatchContext!, readState(rt), selected!.evidence.reportDigest) !== undefined, "DELAYED");
          assertCurrent();
          forwardedThisRun = true;
          return upstream!.call(op.approval, op.args).then((result) => {
            const attempt = readPrivate(p.attempt);
            const retained: Retained = { version: "irontrellis-mcp-response/1", attemptDigest: hash(attempt), identity: i, result };
            durableCreate(p.report, retained);
            report = retained;
            return reportedOutcome(retained, i, "SUBMITTED");
          }).catch(() => unknownOutcome(i as never));
        },
        reconcile(submission) {
          const i = admittedSubmissionIdentity(submission).identity as unknown as Json;
          try { report = getReport(op.operationId, i, op.terms); return reportedOutcome(report, i, "RETRY"); } catch { return unknownOutcome(i as never); }
        },
      };
      const checkedLocal: LocalExecutionOptions = { ...rt.local, async signHash(h) { assertCurrent(); const signature = await rt.local.signHash(h); assertCurrent(); return signature; } };
      if (barrier !== undefined && wasAdmitted && !absent()) userAssertCurrent(); else assertCurrent();
      await witnessCheck(rt.store);
      // The operation id is the intent id (a raw id, A-37.2): derived from the domain and business key (or a fresh value per
      // recorded call), so a repeat finds its admission under the same id in every format.
      const hooks = barrier === undefined ? undefined : {
        resumeUndispatched: barrier.resumeUndispatched,
        noDispatchStart: () => absent(),
        async beforeInvoke(context: ExecutionDispatchContext) {
          try {
            check(absent(), "DISPATCH_STARTED");
            readBarrierChain(storage, context, barrier.profile);
            // Retain whether this run appended the admission even if eligibility forces another unlocked wait.
            dispatchContext ??= context;
            assertCurrent();
            if (upstream === undefined) { upstream = await pool.connection(op.upstream); await upstream.verify(op.approval); assertCurrent(); }
            selected = await barrier.wait(context, () => readState(rt), () => { assertCurrent(); assertDispatchState(context); }, deadline!, rt.local.now);
            return selected === undefined ? { status: "NOT_DISPATCHED" as const, reason: "DELAYED" } : { status: "READY" as const };
          } catch (error) { return { status: "NOT_DISPATCHED" as const, reason: closedReason(error) }; }
        },
      };
      const execution = openLocalExecution(checkedLocal, adapter, "REMOTE_REPORT", hooks);
      let result: Readonly<{ status: string; reason?: string; invocation?: Readonly<{ status: string }>; result?: Readonly<{ status: string }>; refusalRecorded?: boolean; refusal?: Readonly<{ eventId: string }>; refusalNotRecorded?: Readonly<{ reason: string }> }>;
      do {
        blockedReason = undefined;
        result = await execution.run({ id: op.operationId, intentId: op.operationId, action: op.action, resource: op.resource, role: op.role, tenure: op.tenure, termsCommitment: hash(op.terms, rt.algorithm) });
        // A report can become ineligible between the wait and the locked check. Continue waiting only while no start exists.
      } while (barrier !== undefined && blockedReason === "DELAYED" && absent() && barrier.timeRemaining(deadline!));
      if (barrier !== undefined && absent() && readState(rt).intentAdmissions.has(op.operationId)) {
        return noDispatch(result.reason ?? blockedReason ?? "INTENT_NOT_OPEN");
      }
      // The core may answer with an existing consumption without calling reconcile: load the retained bytes and compare their digest.
      if (report === undefined) {
        try { const admission = readState(rt).intentAdmissions.get(op.operationId); if (admission !== undefined) report = getReport(op.operationId, admission.adapterIdentity as unknown as Json, op.terms); } catch { /* stays unknown */ }
      }
      const invocation = result.invocation ?? result.result;
      const status = result.status === "NOT_AUTHORIZED" || result.status === "POLICY_REFUSED" ? "DENIED" : result.status === "NOT_ADMITTED" ? "REFUSED"
        : report !== undefined ? (forwardedThisRun ? "RESPONSE_RETAINED" : "RECONCILIATION_ONLY") : "OUTCOME_UNKNOWN";
      // The upstream's own reports (format 2, configured per job or tool): recorded once, when the reply was first retained.
      const recorded = status === "RESPONSE_RETAINED" && report !== undefined ? await upstreamRecords(rt, op, report.result, true) : {};
      return {
        status, operationId: op.operationId, coreStatus: result.status, canonicalDisposition: invocation?.status ?? null,
        externalOutcome: "NOT_PROVEN", enforcement: "GATEWAY_ADMISSION",
        ...(forwardedThisRun && dispatchContext?.resumed ? { resumed: true } : {}),
        ...(status === "DENIED" ? { reason: result.status === "POLICY_REFUSED" ? "ADDITIONAL_POLICY" : "CORE_POLICY", ...refusalOf(result) } : {}),
        ...(report === undefined ? {} : { upstreamResult: report.result, upstreamContentTrust: "UNTRUSTED_DATA" }), ...recorded,
      } satisfies GatewayResult;
    },
  };
}

// ---------------------------------------------------------------- exactly-once jobs

type PreparedJob = Job & Readonly<{ inputSchema: Json; validate: JsonSchemaValidator<Json>; operationId: string; published: ToolAnnotations }>;
function prepareJobs(options: ExactlyOnceOptions, domain: AuthorizationDomain, servers: ReadonlyMap<string, UpstreamConfig>): Map<string, PreparedJob> {
  check(Array.isArray(options.operations) && options.operations.length > 0 && options.operations.length <= 32);
  const jobs = new Map<string, PreparedJob>(), business = new Set<string>();
  for (const input of options.operations) {
    const j = exact(data(input), ["name", "upstream", "tool", "businessKey", "action", "resource", "role", "tenure", "approval"], ["annotations", "records"]) as unknown as Job;
    recordsOf(j.records);
    check(TOOL_NAME.test(j.name) && !RESERVED_TOOL_NAMES.has(j.name) && !jobs.has(j.name));
    for (const k of ["upstream", "tool", "businessKey", "action", "resource", "role", "tenure"] as const) id(j[k]);
    check(servers.has(j.upstream) && !business.has(j.businessKey));
    business.add(j.businessKey);
    check(same(approval(j.approval), j.approval) && j.approval.name === j.tool);
    check(j.approval.inputSchema.type === "object", "INVALID_INPUT");
    const inputSchema: Json = { ...j.approval.inputSchema, additionalProperties: false };
    jobs.set(j.name, { ...j, inputSchema, validate: compileSchema(inputSchema), operationId: operationIdentity(domain, j.businessKey),
      published: toolAnnotations(j.annotations, j.approval.annotations, { idempotent: true }) });
  }
  return jobs;
}

async function createExactlyOnceGateway(options: ExactlyOnceOptions): Promise<Gateway> {
  const rt = await openRuntime(options);
  const storage = privateDirectory(options.storage), timeout = options.timeoutMs ?? 5000;
  check(Number.isSafeInteger(timeout) && timeout >= 100 && timeout <= 30000);
  const pool = upstreamPool(data<unknown[]>(options.upstreams).map(captureUpstream), timeout);
  check(pool.servers.size > 0 && pool.servers.size <= 8);
  const jobs = prepareJobs(options, rt.local.domain, pool.servers);
  const barrier = options.anchoring === undefined ? undefined : await openAnchorBarrier(options.anchoring, readState(rt), storage);
  // A-183.2 (iii) / A-195.1: every status() under anchoring carries the profile class and, for TEST, its label.
  const anchorClass = barrier === undefined ? {} : { profileClass: barrier.profileClass, barrierMode: barrier.barrierMode, classLabel: barrier.classLabel };
  /**
   * A-168.4: the operation's whole barrier chain, each record with its digest, and the record dispatch relied on. Barrier
   * records are never appended once the attempt exists, so with an attempt that is the last record; without one, none.
   * A chain that does not validate is listed as ADMISSION_MISMATCH, as the dispatch path would refuse it.
   */
  const barrierListing = (operationId: string, admissionHead: ExecutionDispatchContext["admissionHead"], started: boolean) => {
    if (barrier === undefined) return {};
    try {
      const chain = readBarrierChain(storage, { operationId, admissionHead } as ExecutionDispatchContext, barrier.profile), last = chain.length - 1;
      return {
        barrierChain: chain.map((r, i) => ({ barrierSeq: r.barrierSeq, digest: hash(r), resumed: r.resumed, statementDigest: r.statementDigest, statementHead: r.statementHead,
          profileId: r.profileId, chainId: r.chainId, label: r.label, mode: r.mode, reportDigest: r.reportDigest, reliedOn: started && i === last })),
        reliedOnBarrierDigest: started && last >= 0 ? hash(chain[last]) : null,
      };
    } catch { return { barrierChain: null, barrierChainStatus: "ADMISSION_MISMATCH", reliedOnBarrierDigest: null }; }
  };
  const execution = recordedExecution(rt, storage, pool, barrier);
  const lookup = (name: string): PreparedJob => { const job = jobs.get(name); check(job !== undefined, "UNKNOWN_TOOL"); return job; };
  /** Current permission for `action` on the job's resource, under a current runtime and tenure. */
  const inspectPolicy = (job: PreparedJob, action = "inspect-operation", termsCommitment?: ContentHash) => {
    const state = readState(rt), at = rt.local.now();
    assertRuntimeCurrent(rt, state, at, job);
    const observation = observeState(state, { at }), request = { actor: rt.session.agentId, action, resource: job.resource, ...(termsCommitment === undefined ? {} : { termsCommitment }) };
    const decision = observation.authorize(request);
    return { decision: decision.decision, code: denialCode(decision.evidence as never), head: decision.head.hash, at, why: () => whySummary(observation.why(request)) };
  };
  const termsFor = (job: PreparedJob, args: Json): Json => data({
    version: "irontrellis-mcp-job/1", upstream: pool.servers.get(job.upstream), tool: job.tool, approval: job.approval,
    businessKey: job.businessKey, action: job.action, resource: job.resource, arguments: args,
  });
  let busy = false, closed = false;
  const gateway: Gateway = {
    mode: "exactly-once",
    tools: () => [...jobs.values()].map((j) => ({
      name: j.name, inputSchema: data<Json>(j.inputSchema), annotations: j.published,
      description: `Run the operator-approved ${j.tool} job exactly once. Repeating this job inspects its original attempt; it never creates a new business operation.`,
    })),
    async run(name, input, { assertCurrent = () => {} }: RunOptions = {}) {
      if (busy) return { status: "BUSY" };
      busy = true;
      try {
        check(!closed, "GATEWAY_UNAVAILABLE");
        assertCurrent();
        const job = lookup(name), args = data<Json>(input);
        check(job.validate(args).valid, "INVALID_ARGUMENTS");
        assertCurrent();
        const terms = termsFor(job, args), termsCommitment = hash(terms, rt.algorithm);
        const wasAdmitted = readState(rt).intentAdmissions.has(job.operationId);
        if (wasAdmitted) check(inspectPolicy(job).decision === "ALLOW", "INSPECTION_DENIED");
        return await execution.execute(
          { operationId: job.operationId, action: job.action, resource: job.resource, role: job.role, tenure: job.tenure, upstream: job.upstream, approval: job.approval, args, terms, ...(job.records === undefined ? {} : { records: job.records }) },
          assertCurrent, wasAdmitted,
          async () => {
            const policy = inspectPolicy(job, job.action, termsCommitment);
            if (policy.decision === "ALLOW") return undefined;
            const denied = { status: "DENIED", reason: "CORE_POLICY", decision: policy.decision, action: job.action, resource: job.resource, historyHead: policy.head, evaluationTime: policy.at, why: policy.why(), executionCapability: false };
            // Verdict first (A-38.1): the refusal is recorded within recordBudgetMs, else spooled; the answer is the same either way.
            const refusal = await rt.recorder.decision({ actorId: rt.session.agentId, action: job.action, resource: job.resource });
            return { ...denied, ...(refusal === undefined ? {} : { refusal }) };
          },
        );
      } catch (error) {
        const code = codeOf(error), job = jobs.get(name);
        if (barrier !== undefined && job !== undefined && ["STOPPED", "ACCESS_NOT_CURRENT", "RUNTIME_NOT_CURRENT", "CLOCK_INVALID", "CLOCK_AHEAD_OF_READER", "RESUME_HORIZON", "ROLLBACK_DETECTED", "HISTORY_IDENTITY_MISMATCH", "HISTORY_CONFLICT"].includes(code ?? "")) {
          try {
            const historyChanged = ["ROLLBACK_DETECTED", "HISTORY_IDENTITY_MISMATCH", "HISTORY_CONFLICT"].includes(code ?? "");
            if (!dispatchStarted(execution.paths(job.operationId).attempt) && (historyChanged || readState(rt).intentAdmissions.has(job.operationId))) {
              const reason = historyChanged ? "HISTORY_DIVERGED" : code === "STOPPED" ? "STOPPED" : code === "RESUME_HORIZON" ? code : "ACCESS_NOT_CURRENT";
              barrier.remember(job.operationId, reason);
              return { status: "NOT_DISPATCHED", reason, operationId: job.operationId, dispatchPerformed: false };
            }
          } catch { /* Presence cannot be established; keep the bounded public failure. */ }
        }
        return publicError(error);
      } finally {
        busy = false;
      }
    },
    status(name) {
      try {
        const job = lookup(name);
        check(inspectPolicy(job).decision === "ALLOW", "INSPECTION_DENIED");
        const state = readState(rt), admission = state.intentAdmissions.get(job.operationId), declared = state.intentDeclarations.get(job.operationId);
        if (admission === undefined) return { status: declared !== undefined ? "NOT_ADMITTED" : "NOT_STARTED", operationId: job.operationId, dispatchPerformed: false, ...anchorClass };
        if (!dispatchStarted(execution.paths(job.operationId).attempt)) return {
          ...(barrier?.status(job.operationId) ?? { status: "NOT_DISPATCHED", reason: "NOT_STARTED", dispatchPerformed: false }), operationId: job.operationId,
          ...barrierListing(job.operationId, admission.admissionHead, false),
        };
        let report: Retained | undefined;
        try {
          const attempt = readPrivate<Readonly<{ terms: Json & { upstream: unknown; approval: unknown } }>>(execution.paths(job.operationId).attempt);
          check(hash(attempt.terms, rt.algorithm) === declared!.data.termsCommitment, "STORAGE_UNAVAILABLE");
          // Only the configured resource/tool/contract may be inspected under this alias.
          check(attempt.terms.resource === job.resource && attempt.terms.action === job.action && attempt.terms.tool === job.tool && attempt.terms.businessKey === job.businessKey &&
            same(attempt.terms.upstream, pool.servers.get(job.upstream)) && same(attempt.terms.approval, job.approval), "STORAGE_UNAVAILABLE");
          report = execution.getReport(job.operationId, admission.adapterIdentity as unknown as Json, attempt.terms);
        } catch { /* unknown */ }
        return {
          status: report !== undefined ? "RESPONSE_RETAINED" : "OUTCOME_UNKNOWN", operationId: job.operationId, dispatchPerformed: false,
          responseDigest: report === undefined ? null : hash(report), reportedError: report === undefined ? null : report.result.isError,
          canonicalResponseRecorded: state.intentConsumptions.has(job.operationId), externalOutcome: "NOT_PROVEN",
          ...(barrier === undefined ? {} : { resumeHorizon: barrier.resumeHorizon ?? null }), ...anchorClass,
          ...barrierListing(job.operationId, admission.admissionHead, true),
        };
      } catch (error) {
        return publicError(error);
      }
    },
    why(name) {
      try {
        const job = lookup(name);
        check(inspectPolicy(job).decision === "ALLOW", "INSPECTION_DENIED");
        const state = readState(rt), at = rt.local.now();
        const why = observeState(state, { at }).why({ actor: rt.session.agentId, action: job.action, resource: job.resource });
        return {
          status: "EXPLAINED", ...whySummary(why), action: job.action, resource: job.resource, historyHead: state.head.hash, evaluationTime: at,
          scope: "CURRENT_PERMISSION_ONLY", executionCapability: false,
          notes: "Admission also requires matching original arguments, current runtime, role, schema and available capacity.",
        };
      } catch (error) {
        return publicError(error);
      }
    },
    async close() { closed = true; await pool.close(); },
  };
  return Object.freeze(gateway);
}

// ---------------------------------------------------------------- per-call tools

type PreparedTool = PerCallTool & Readonly<{ action: string; inputSchema: Json; validate: JsonSchemaValidator<Json>; published: ToolAnnotations }>;
function prepareTools(options: PerCallOptions, servers: ReadonlyMap<string, UpstreamConfig>): Map<string, PreparedTool> {
  check(Array.isArray(options.tools) && options.tools.length > 0 && options.tools.length <= 64);
  const tools = new Map<string, PreparedTool>();
  for (const input of options.tools) {
    const t = exact(data(input), ["name", "upstream", "tool", "resource", "approval"], ["action", "annotations", "records"]) as unknown as PerCallTool;
    recordsOf(t.records);
    check(TOOL_NAME.test(t.name) && !RESERVED_TOOL_NAMES.has(t.name) && !tools.has(t.name));
    id(t.upstream); id(t.tool); id(t.resource);
    check(servers.has(t.upstream));
    check(same(approval(t.approval), t.approval) && t.approval.name === t.tool);
    check(t.approval.inputSchema.type === "object", "INVALID_INPUT");
    const inputSchema: Json = { ...t.approval.inputSchema, additionalProperties: false };
    tools.set(t.name, { ...t, action: t.action === undefined ? t.tool : id(t.action), inputSchema, validate: compileSchema(inputSchema),
      published: toolAnnotations(t.annotations, t.approval.annotations, { idempotent: false }) });
  }
  return tools;
}

async function createPerCallGateway(options: PerCallOptions): Promise<Gateway> {
  const rt = await openRuntime(options);
  const timeout = options.timeoutMs ?? 5000;
  check(Number.isSafeInteger(timeout) && timeout >= 100 && timeout <= 30000);
  const recordCalls = options.recordCalls === true;
  check(options.anchoring === undefined || recordCalls, "INVALID_INPUT");
  check(options.recordCalls === undefined || typeof options.recordCalls === "boolean");
  const pool = upstreamPool(data<unknown[]>(options.upstreams).map(captureUpstream), timeout);
  check(pool.servers.size > 0 && pool.servers.size <= 8);
  const tools = prepareTools(options, pool.servers);
  const tenure = recordCalls ? { role: id(options.role), tenure: id(options.tenure) } : undefined;
  const storage = recordCalls ? privateDirectory(options.storage as string) : undefined;
  const barrier = options.anchoring === undefined ? undefined : await openAnchorBarrier(options.anchoring, readState(rt), storage!);
  const execution = recordCalls ? recordedExecution(rt, storage!, pool, barrier) : undefined;
  const lookup = (name: string): PreparedTool => { const tool = tools.get(name); check(tool !== undefined, "UNKNOWN_TOOL"); return tool; };
  /** The per-call decision: actor = the configured agent, action = the tool's action, resource = the resolved template. */
  const decide = (tool: PreparedTool, args: Json) => {
    const resource = resolveResource(tool.resource, args);
    const state = readState(rt), at = rt.local.now();
    assertRuntimeCurrent(rt, state, at, tenure);
    const observation = observeState(state, { at }), action = { actor: rt.session.agentId, action: tool.action, resource };
    const decision = observation.authorize(action);
    return { resource, decision: decision.decision, code: denialCode(decision.evidence as never), head: state.head.hash, at, why: () => whySummary(observation.why(action)) };
  };
  /** A per-call DENY: recorded as a CORE/BUDGET refusal, or (a template rendering arguments) a CONNECTOR refusal by digest (A-42). */
  const denied = async (tool: PreparedTool, d: ReturnType<typeof decide>): Promise<GatewayResult> => {
    const rendered = /\{[A-Za-z_][A-Za-z0-9_]*\}/.test(tool.resource);
    const refusal = await rt.recorder.decision({ actorId: rt.session.agentId, action: tool.action, resource: d.resource }, rendered ? { template: tool.resource, code: d.code } : {});
    return { status: "DENIED", reason: "CORE_POLICY", decision: d.decision, action: tool.action, resource: d.resource, historyHead: d.head, evaluationTime: d.at, why: d.why(), executionCapability: false, ...(refusal === undefined ? {} : { refusal }) };
  };
  let active = 0, closed = false;
  const gateway: Gateway = {
    mode: "per-call",
    tools: () => [...tools.values()].map((t) => ({
      name: t.name, inputSchema: data<Json>(t.inputSchema), annotations: t.published,
      description: `Call the operator-approved ${t.tool} tool. Every call is checked against the agent's current recorded authority before it is forwarded.`,
    })),
    async run(name, input, { assertCurrent = () => {} }: RunOptions = {}) {
      if (recordCalls && active > 0) return { status: "BUSY" };
      active++;
      try {
        check(!closed, "GATEWAY_UNAVAILABLE");
        assertCurrent();
        const tool = lookup(name), args = data<Json>(input);
        check(tool.validate(args).valid, "INVALID_ARGUMENTS");
        const d = decide(tool, args);
        if (d.decision !== "ALLOW") return await denied(tool, d);
        if (execution !== undefined) {
          const terms = data<Json>({ version: "irontrellis-mcp-call/1", upstream: pool.servers.get(tool.upstream), tool: tool.tool, approval: tool.approval, action: tool.action, resource: d.resource, arguments: args });
          const operationId = "mcp-call:" + hash({ version: "irontrellis-mcp-call/1", domain: rt.local.domain, call: randomUUID() }, rt.algorithm).slice(2);
          const result = await execution.execute({ operationId, action: tool.action, resource: d.resource, role: tenure!.role, tenure: tenure!.tenure, upstream: tool.upstream, approval: tool.approval, args, terms, ...(tool.records === undefined ? {} : { records: tool.records }) }, assertCurrent, false);
          return { ...result, status: result.status === "RESPONSE_RETAINED" ? "FORWARDED" : result.status, recorded: true, decision: "ALLOW", action: tool.action, resource: d.resource };
        }
        assertCurrent();
        const upstream = await pool.connection(tool.upstream);
        await upstream.verify(tool.approval);
        assertCurrent();
        // Re-check after discovery: the history may have moved while the upstream started.
        const fresh = decide(tool, args);
        if (fresh.decision !== "ALLOW") return await denied(tool, fresh);
        const upstreamResult = await upstream.call(tool.approval, args);
        // No intent is admitted for an unrecorded call: only an upstream refusal can be recorded (CONNECTOR).
        const reported = await upstreamRecords(rt, { action: tool.action, resource: fresh.resource, ...(tool.records === undefined ? {} : { records: tool.records }) }, upstreamResult, false);
        return { status: "FORWARDED", decision: "ALLOW", action: tool.action, resource: fresh.resource, historyHead: fresh.head, evaluationTime: fresh.at, recorded: false, externalOutcome: "NOT_PROVEN", upstreamResult, upstreamContentTrust: "UNTRUSTED_DATA", ...reported };
      } catch (error) {
        return publicError(error);
      } finally {
        active--;
      }
    },
    status(name) {
      try { lookup(name); return { status: "REFUSED", reason: "NOT_A_JOB", mode: "per-call" }; } catch (error) { return publicError(error); }
    },
    why(name, args) {
      try {
        const tool = lookup(name), given = args === undefined ? {} : data<Json>(args);
        const d = decide(tool, given);
        return { status: "EXPLAINED", ...d.why(), action: tool.action, resource: d.resource, historyHead: d.head, evaluationTime: d.at, scope: "CURRENT_PERMISSION_ONLY", executionCapability: false };
      } catch (error) {
        return publicError(error);
      }
    },
    async close() { closed = true; await pool.close(); },
  };
  return Object.freeze(gateway);
}

/** Privileged host factory. Never expose this handle or its options to agents. */
export function createGateway(options: GatewayOptions): Promise<Gateway> {
  check(options !== null && typeof options === "object");
  const mode = options.mode ?? "exactly-once";
  check(mode === "exactly-once" || mode === "per-call");
  return mode === "per-call" ? createPerCallGateway(options as PerCallOptions) : createExactlyOnceGateway(options as ExactlyOnceOptions);
}
export { GatewayError };
