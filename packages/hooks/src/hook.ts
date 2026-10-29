/**
 * The protocol-independent behaviour of the hook.
 *
 *   session-start  ensure the agent (and role) exist, admit a runtime session
 *                  for the host's session id (serialized: see admitSession),
 *                  answer with the open duties and what the session may and
 *                  may not do
 *   tool           protective rules first (protect.ts: IronTrellis state and
 *                  control commands → deny, cannot be configured away); then
 *                  the session admitted at SessionStart must still be current
 *                  (else deny SESSION_NOT_FOUND / SESSION_FENCED /
 *                  SESSION_EXPIRED); then map the tool to (action, resource)
 *                  and authorize it at now(): ALLOW → defer (no decision; the
 *                  host's own permission check runs) or allow when
 *                  decisions.onAllow is "allow", DENY → deny with the failing
 *                  code and authority, INDETERMINATE or unmapped → ask
 *   session-end    write `<history>.handovers/<sha256(session)>.json` from
 *                  handover(agent) and print a summary; the final
 *                  end also releases the session key
 *
 * Decisions read the history; nothing here executes anything. A tool decision
 * writes only a refusal (a deny by the grants, or a call without a current session); an allowed call is not recorded.
 */
import { existsSync, readdirSync } from "node:fs";
import { basename, isAbsolute, join } from "node:path";
import {
  EngineError, IronTrellisError, LEGACY_FORMAT, MAX_CLOCK_SKEW_MS, TRELLIS_FORMAT, clockAheadOfReader, enforcementWarning, generateKeyPair, jsonStringifyWithBigints, openLocalOwner, readGenesisLine,
  type AuthorizationDomain, type CanonicalEvent, type HandoverReport, type LocalOwner,
} from "@ramex-labs/irontrellis";
import { HookConfigError, loadConfig, loadConfigFile, type HookConfig } from "./config.ts";
import { mapTool, rendersToolInput, staticCapabilities } from "./policy.ts";
import { recordToolRefusal } from "./refusals.ts";
import { canonicalProject, handoversDir, readPrivateJson, removePrivateFile, routeSessionFile, sessionFileName, sessionsDir, withLockFile, writePrivateFile } from "./paths.ts";
import { hookRoute, pluginEnabled, readRouteSession, writeRouteSession } from "./route.ts";
import { protection } from "./protect.ts";
import type { HookEvent, Protocol, Reply, ToolDecision, Verdict } from "./protocols/types.ts";

/** `via`: "plugin" when the IronTrellis plugin's entry point runs this guard (cli.ts `plugin`), else a settings hook. */
export type HookIo = Readonly<{ env: Readonly<Record<string, string | undefined>>; cwd: string; now: () => number; via?: "plugin" | "hook" }>;
export const HANDOVER_VERSION = "irontrellis-hook-handover/1";
export const SESSION_KEY_VERSION = "irontrellis-session-key/1";

// ---------------------------------------------------------------- history access

/**
 * The history's genesis domain when the config does not carry it, as line 0 states it: the owner open that follows
 * replays and verifies the history and refuses a domain that is not its genesis's (PROFILE_MISMATCH), so nothing
 * unverified is acted on (an extra full replay here was the cost of every hook call with such a config).
 */
const domainOf = (config: HookConfig, genesis: ReturnType<typeof readGenesisLine>): AuthorizationDomain => {
  if (config.domain !== undefined) return config.domain;
  const domain = ((genesis?.event as { data?: { domain?: unknown } } | null | undefined)?.data)?.domain;
  if (genesis === undefined || domain === null || typeof domain !== "object") throw new IronTrellisError("INVALID_HISTORY", false, `history ${config.history} has no events`);
  return domain as AuthorizationDomain;
};

/**
 * The owner handle the hook decides and records with. `purpose: "enforce"` (every hook event, `check`, the init
 * verification) applies A-41: a fenced history is refused (`FORMAT_READ_ONLY {reason: MIGRATED}`), a legacy or format-1
 * history needs `enforceFromReadOnlyHistory` in the config (a warning on stderr on every open); `"admin"` (session list
 * and release) only reads and releases keys.
 */
export function openOwner(config: HookConfig, now: () => number, purpose: "enforce" | "admin" = "enforce", onWarning: (warning: string) => void = (w) => { process.stderr.write(`${w}\n`); }): LocalOwner {
  if (!existsSync(config.history)) throw new IronTrellisError("READ_UNAVAILABLE", false, `no history at ${config.history} (run: irontrellis-hook init)`);
  // The hook creates format-2 histories. An older (legacy or format-1, never migrated) file reaches the open below only
  // with "enforceFromReadOnlyHistory": true in the config (A-85: the opt-in comes from the config only; init never sets
  // it); the warning above is printed on every such open. A-185.3: the opt-in is read-only, so such a file opens read only
  // and anything the hook would have to record there (the agent, a session admission) is refused, never done unrecorded
  // (`readOnlyRefusal`). The format is read from line 0 alone: the open below replays and verifies the history (from its
  // snapshot in format 2, CHECKPOINT_RESUME with the root recomputed); a separate inspecting open replayed it in full.
  const genesis = readGenesisLine(config.history);
  const format = genesis?.format;
  if (purpose === "enforce") {
    const warning = enforcementWarning(config.history, format, config.enforceFromReadOnlyHistory);
    if (warning !== undefined) onWarning(warning);
  }
  return openLocalOwner({ historyFile: config.history, domain: domainOf(config, genesis), owner: config.owner, controller: config.controller, now, ...(config.historyId === undefined ? {} : { historyId: config.historyId as `0x${string}` }) });
}

/**
 * A-185.3 (fail closed): a write the hook needs on an opted-in legacy or format-1 history is refused with this explicit,
 * actionable error instead of the store's FORMAT_READ_ONLY; nothing it governs happens without its record.
 */
export function readOnlyRefusal(config: HookConfig, error: unknown): unknown {
  if (!(error instanceof IronTrellisError) || error.code !== "FORMAT_READ_ONLY") return error;
  const reason = (error.detail as { reason?: unknown } | undefined)?.reason;
  if (reason !== "LEGACY" && reason !== "FORMAT_1") return error;
  const kind = reason === "LEGACY" ? "legacy" : "format-1";
  return new IronTrellisError("FORMAT_READ_ONLY", false, `the history ${config.history} is ${kind} and read-only (SPEC §16.1): enforcement from it is read-only, so this session is not admitted and nothing is recorded; run \`irontrellis migrate\` to write`, { reason });
}

/**
 * A-206.3: the history is a legacy or format-1 file the config opted into (`enforceFromReadOnlyHistory`; otherwise the open
 * was refused): "legacy" or "format-1", else undefined. Read from line 0 alone.
 */
export function readOnlyHistoryKind(config: HookConfig): "legacy" | "format-1" | undefined {
  const format = readGenesisLine(config.history)?.format;
  return format === LEGACY_FORMAT ? "legacy" : format === TRELLIS_FORMAT ? "format-1" : undefined;
}

const agentExists = (owner: LocalOwner, agentId: string): boolean => {
  try { owner.handover(agentId); return true; } catch (error) { if (error instanceof IronTrellisError && error.code === "INVALID_INPUT") return false; throw error; }
};

/** The agent's current control epoch from its creation and every recorded advance. */
const currentEpoch = (events: readonly CanonicalEvent[], agentId: string): number => {
  let epoch = 1;
  for (const event of events) {
    if (event.type === "AGENT_CREATED" && event.data.agentId === agentId) epoch = Number(event.data.initialControlEpoch);
    if (event.type === "CONTROL_EPOCH_ADVANCED" && event.data.agentId === agentId) epoch = Number(event.data.toEpoch);
  }
  return epoch;
};

/** Create the agent, the role and the appointment that are missing; every step is idempotent. */
export async function ensureAgent(owner: LocalOwner, config: HookConfig): Promise<readonly string[]> {
  const steps: string[] = [];
  if (!agentExists(owner, config.agentId)) { await owner.createAgent({ id: config.agentId }); steps.push(`agent ${config.agentId} created`); }
  if (config.roleId === undefined) return steps;
  const events = owner.exportHistory();
  if (!events.some((e) => e.type === "ROLE_CREATED" && e.data.roleId === config.roleId)) { await owner.createRole({ id: config.roleId, exclusive: true }); steps.push(`role ${config.roleId} created`); }
  const report = owner.handover(config.agentId);
  if (report.tenures.some((t) => t.roleId === config.roleId)) return steps;
  let latest = 0;
  for (const e of events) {
    if (e.type === "AGENT_APPOINTED" && e.data.roleId === config.roleId) latest = Math.max(latest, Number(e.data.tenureNumber));
    if (e.type === "ROLE_TRANSFERRED" && e.data.roleId === config.roleId) latest = Math.max(latest, Number(e.data.toTenureNumber));
  }
  const number = latest + 1;
  await owner.appoint({ agent: config.agentId, role: config.roleId, tenure: `tenure:${config.roleId}:${number}`, number });
  steps.push(`${config.agentId} appointed to ${config.roleId} (tenure ${number})`);
  return steps;
}

// ---------------------------------------------------------------- session keys

export const sessionKeyFile = (config: HookConfig, hostSessionId: string): string => join(sessionsDir(config.history), sessionFileName(hostSessionId));
export const handoverFile = (config: HookConfig, hostSessionId: string): string => join(handoversDir(config.history), sessionFileName(hostSessionId));

/** A session key file; `released` once the session ended (the private key is then gone, the record of which session it was stays). */
export type SessionKeyRecord = Readonly<{ agentId: string; sessionId: string; hostSessionId: string | undefined; path: string; released: boolean }>;
const readSessionKey = (path: string): SessionKeyRecord | undefined => {
  const raw = readPrivateJson(path);
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const r = raw as Record<string, unknown>;
  if (r.version !== SESSION_KEY_VERSION || typeof r.agentId !== "string" || typeof r.sessionId !== "string") return undefined;
  return { agentId: r.agentId, sessionId: r.sessionId, hostSessionId: typeof r.hostSessionId === "string" ? r.hostSessionId : undefined, path, released: typeof r.privateKey !== "string" };
};

/**
 * Whether SessionStart admitted this host session for the config's agent and it has not ended (its key file holds a key).
 * The statusline's check (founder's live check 02): a session started before the project was set up is not admitted,
 * so the guard refuses its tool calls until a new session starts. The history itself is not opened.
 */
export function sessionAdmitted(config: HookConfig, hostSessionId: string): boolean {
  const key = readSessionKey(sessionKeyFile(config, hostSessionId));
  return key !== undefined && !key.released && key.agentId === config.agentId;
}

/**
 * Release a session: its key file is rewritten without the private key
 * (a tombstone naming the session), so the next SessionStart may fence it and
 * its own later tool calls are refused. Returns false when there was nothing to release.
 */
export function releaseSessionKey(record: SessionKeyRecord, now: number): boolean {
  if (record.released) return false;
  writePrivateFile(record.path, `${JSON.stringify({ version: SESSION_KEY_VERSION, agentId: record.agentId, sessionId: record.sessionId, hostSessionId: record.hostSessionId ?? null, releasedAt: now }, null, 2)}\n`);
  return true;
}

/** Every session key file of this agent in the sessions directory. */
export function sessionKeys(config: HookConfig): readonly SessionKeyRecord[] {
  const dir = sessionsDir(config.history);
  let names: string[];
  try { names = readdirSync(dir); } catch { return []; }
  const out: SessionKeyRecord[] = [];
  for (const name of names) {
    if (!/^[0-9a-f]{64}\.json$/.test(name)) continue;
    const record = readSessionKey(join(dir, name));
    if (record !== undefined && record.agentId === config.agentId) out.push(record);
  }
  return out;
}

export type Admission = Readonly<{
  historySessionId: string | undefined; admitted: boolean; fenced: string | undefined; epoch: number; keyFile: string | undefined;
  /** Set when the session was not admitted because another session of the agent is live and still holds its key. */
  refused: Readonly<{ liveSession: string; expiresAt: number | undefined }> | undefined;
}>;

/**
 * Admit `session:<hostSessionId>` for the agent.
 *
 * - This host session's own admission is still current (resume, compact) and
 *   its key file is present: reused, nothing written.
 * - Another session of the agent is current and its key file is still present
 *   (that host session has not ended): NOT admitted. The history allows one
 *   live session per agent per control epoch, and a new session must not
 *   silently fence a running one, so parallel sessions of the same agent are
 *   serialized: this session's tool calls are refused until the other one
 *   ends (its SessionEnd releases its key) or expires, or the operator
 *   releases it (`irontrellis-hook session release`).
 * - Another session is current but its key was released (its host session
 *   ended, or the operator released it) or is gone: the epoch is advanced,
 *   which fences it, and this one is admitted.
 * - No current session: admitted in the current epoch.
 */
export async function admitSession(owner: LocalOwner, config: HookConfig, hostSessionId: string, now: number): Promise<Admission> {
  // Two copies of the guard starting the same host session (the plugin and the settings hook, or the hook installed twice)
  // serialize here: the second one then finds this session admitted with its key and admits nothing.
  return withLockFile(`${sessionKeyFile(config, hostSessionId)}.admit.lock`, () => admitSessionLocked(owner, config, hostSessionId, now), { waitMs: 20_000 });
}
async function admitSessionLocked(owner: LocalOwner, config: HookConfig, hostSessionId: string, now: number): Promise<Admission> {
  const wanted = `session:${hostSessionId}`;
  const keyFile = sessionKeyFile(config, hostSessionId);
  const report = owner.handover(config.agentId, { at: now });
  const live = report.sessions.find((s) => s.current);
  let epoch = currentEpoch(owner.exportHistory(), config.agentId);
  let fenced: string | undefined;
  if (live !== undefined) {
    const mine = readSessionKey(keyFile);
    if (mine !== undefined && !mine.released && mine.agentId === config.agentId && mine.sessionId === live.sessionId) {
      return { historySessionId: live.sessionId, admitted: false, fenced: undefined, epoch: live.controlEpoch, keyFile, refused: undefined };
    }
    const holder = sessionKeys(config).find((k) => k.sessionId === live.sessionId && !k.released);
    if (holder !== undefined) {
      return { historySessionId: undefined, admitted: false, fenced: undefined, epoch, keyFile: undefined, refused: { liveSession: live.sessionId, expiresAt: live.expiresAt === undefined ? undefined : Number(live.expiresAt) } };
    }
    await owner.advanceEpoch({ agent: config.agentId, from: epoch, to: epoch + 1 });
    epoch += 1;
    fenced = live.sessionId;
  }
  const taken = new Set(owner.handover(config.agentId, { at: now }).sessions.map((s) => s.sessionId));
  let historySessionId = wanted;
  for (let n = 2; taken.has(historySessionId); n += 1) historySessionId = `${wanted}:${n}`;
  const keyId = historySessionId.replace(/^session:/, "key:");
  const scheme = owner.format === LEGACY_FORMAT ? "eip191-personal-sign-keccak256" : "ed25519";
  const pair = generateKeyPair(scheme, keyId);
  writePrivateFile(keyFile, `${JSON.stringify({ version: SESSION_KEY_VERSION, agentId: config.agentId, sessionId: historySessionId, hostSessionId, keyId: pair.keyId, scheme: pair.scheme, credential: pair.credential, privateKey: pair.privateKey, admittedAt: now }, null, 2)}\n`);
  const credential = scheme === "ed25519" ? { credential: pair.credential } : { address: pair.credential };
  try {
    await owner.admitRuntime({ session: historySessionId, agent: config.agentId, epoch, key: keyId, expiresAt: now + config.sessionTtlMs, ...credential });
  } catch (error) {
    removePrivateFile(keyFile);
    throw error;
  }
  return { historySessionId, admitted: true, fenced, epoch, keyFile, refused: undefined };
}

export type SessionStatus =
  | Readonly<{ ok: true; sessionId: string }>
  | Readonly<{ ok: false; code: "SESSION_NOT_FOUND" | "SESSION_FENCED" | "SESSION_EXPIRED"; reason: string }>;

/**
 * Is the session admitted for this host session id at SessionStart still
 * current in the history (recorded, not expired, in the agent's current
 * control epoch, agent not terminated)? Read from the replayed state
 * (`LocalOwner.runtimeSession`): the same rule as HandoverReport.sessions[].current,
 * without the cost of a full handover query, or of exporting the history, on
 * every tool call.
 */
export function sessionStatus(owner: LocalOwner, config: HookConfig, hostSessionId: string, now: number): SessionStatus {
  const key = readSessionKey(sessionKeyFile(config, hostSessionId));
  if (key === undefined || key.agentId !== config.agentId) {
    return { ok: false, code: "SESSION_NOT_FOUND", reason: `no runtime session of ${config.agentId} is admitted for host session ${hostSessionId} (SessionStart did not admit it, or it ended or was released); start a new session` };
  }
  // From the replayed state (session ids are unique in a history; the agent's epoch is its creation epoch advanced by
  // every CONTROL_EPOCH_ADVANCED): exporting the history to scan it cost O(events) per tool call.
  const session = owner.runtimeSession(key.sessionId);
  if (session === null || session.agentId !== config.agentId) return { ok: false, code: "SESSION_NOT_FOUND", reason: `the session recorded for host session ${hostSessionId} (${key.sessionId}) is not in ${config.history}` };
  const epoch = session.controlEpoch, expiresAt = session.expiresAt;
  const expired = expiresAt !== undefined && now >= expiresAt;
  const fenced = epoch !== session.agentControlEpoch;
  if (session.agentTerminated) return { ok: false, code: "SESSION_FENCED", reason: `${key.sessionId}: agent ${config.agentId} is terminated` };
  if (!expired && !fenced && key.released) return { ok: false, code: "SESSION_NOT_FOUND", reason: `${key.sessionId} (host session ${hostSessionId}) has ended or was released; start a new session` };
  if (!expired && !fenced) return { ok: true, sessionId: key.sessionId };
  if (fenced) return { ok: false, code: "SESSION_FENCED", reason: `${key.sessionId} (epoch ${epoch}) was fenced by a newer session of ${config.agentId}` };
  return { ok: false, code: "SESSION_EXPIRED", reason: `${key.sessionId} expired at ${new Date(expiresAt!).toISOString()}; start a new session` };
}

// ---------------------------------------------------------------- wording

const list = (items: readonly string[], empty: string): string => (items.length === 0 ? empty : items.join("; "));
const dutyLine = (d: HandoverReport["openDuties"][number]): string => `${d.description} (${d.kind === "OBLIGATION" ? "obligation" : "duty"} ${d.id}, ${d.status.toLowerCase()})`;

/** What the policy's static (action, resource) pairs come to when authorized now: may / may not. */
export function capabilities(owner: LocalOwner, config: HookConfig, now: number): { may: string[]; mayNot: string[]; indeterminate: string[] } {
  const may: string[] = [], mayNot: string[] = [], indeterminate: string[] = [];
  for (const { action, resource } of staticCapabilities(config.policy, config.project)) {
    const { evidence } = owner.authorize({ actor: config.agentId, action, resource }, { at: now });
    const text = `${action} on ${resource}`;
    if (evidence.decision === "ALLOW") may.push(text);
    else if (evidence.decision === "DENY") mayNot.push(`${text} (${evidence.code})`);
    else indeterminate.push(`${text} (${evidence.code})`);
  }
  return { may, mayNot, indeterminate };
}

/** The session-opening line: "Session … opens with N open duties: …; this session may …; it may not …". */
export function openingContext(owner: LocalOwner, config: HookConfig, admission: Admission, hostSessionId: string, now: number): string {
  if (admission.refused !== undefined) return refusalText(config, admission.refused, hostSessionId);
  const report = owner.handover(config.agentId, { at: now });
  const caps = capabilities(owner, config, now);
  const duties = report.openDuties;
  const parts = [
    `IronTrellis: session ${hostSessionId} (agent ${config.agentId}, runtime ${admission.historySessionId}, epoch ${admission.epoch}${admission.fenced === undefined ? "" : `, fences ${admission.fenced}`}) opens with ${duties.length} open ${duties.length === 1 ? "duty" : "duties"}${duties.length === 0 ? "." : `: ${list(duties.map(dutyLine), "")}.`}`,
    `This session may ${list(caps.may, "do nothing side-effecting through the hook (no live grant)")}.`,
    caps.mayNot.length === 0 ? "" : `It may not ${list(caps.mayNot, "")}.`,
    caps.indeterminate.length === 0 ? "" : `Undecidable now: ${list(caps.indeterminate, "")}.`,
    `Only tool calls routed through irontrellis-hook are checked, against the grants recorded in ${config.history}; a denied call is refused by the host, an unmapped call is referred to the user, and a call IronTrellis does not object to is left to the host's own permission check${config.decisions.onAllow === "allow" ? " (except authorized calls, which are allowed outright: decisions.onAllow is \"allow\")" : ""}.`,
  ];
  return parts.filter((p) => p !== "").join(" ");
}

export function refusalText(config: HookConfig, refused: NonNullable<Admission["refused"]>, hostSessionId: string): string {
  return `IronTrellis: session ${hostSessionId} was NOT admitted: agent ${config.agentId} already has a live session (${refused.liveSession}${refused.expiresAt === undefined ? "" : `, expires ${new Date(refused.expiresAt).toISOString()}`}) whose host session has not ended. ` +
    "Parallel sessions of the same agent are serialized by design, so every tool call in this session will be refused (SESSION_NOT_FOUND). " +
    "End the other session (its SessionEnd releases it), or have the operator run `irontrellis-hook session release`, then start a new session.";
}

export function endingSummary(report: HandoverReport, hostSessionId: string, file: string, reason: string | undefined, final: boolean): string {
  const duties = report.openDuties;
  return [
    `IronTrellis: session ${hostSessionId} ${final ? "ended" : "paused"}${reason === undefined || reason === "stop" ? "" : ` (${reason})`} with ${duties.length} open ${duties.length === 1 ? "duty" : "duties"}${duties.length === 0 ? "" : `: ${list(duties.map(dutyLine), "")}`}.`,
    `Live grants held: ${report.liveGrants.length === 0 ? "none" : report.liveGrants.map((g) => `${g.actions.join(",")} on ${g.resources.join(",")} (${g.authorityId})`).join("; ")}. None of them follows a successor.`,
    `Handover record: ${file}`,
  ].join("\n");
}

// ---------------------------------------------------------------- decisions

/**
 * A refusal in the brand's voice (BRAND-001 p. 2, "Voice in practice"): the state word, then the plain fact, then the
 * code and detail in parentheses, for example "IronTrellis · DENY: claude-code may not write files in app (NO_AUTHORITY;
 * write-file on repo:/home/u/app; head 8)".
 */
export const denyText = (fact: string, detail: string): string => `IronTrellis · DENY: ${fact} (${detail})`;
/** An action and resource in plain words (the default policy's actions; any other action as written). */
const PLAIN_ACTIONS: Readonly<Record<string, string>> = Object.freeze({ "write-file": "write files", "run-shell": "run shell commands", "call-mcp": "call MCP tools" });
export function plainAction(action: string, resource: string): string {
  const what = Object.hasOwn(PLAIN_ACTIONS, action) ? PLAIN_ACTIONS[action]! : action;
  const where = resource.startsWith("repo:") ? `in ${basename(resource.slice("repo:".length)) || resource.slice("repo:".length)}`
    : resource.startsWith("mcp:") ? `on the MCP server ${resource.slice("mcp:".length)}` : `on ${resource}`;
  return `${what} ${where}`;
}

/** The IronTrellis plugin's own skill, as Claude Code's Skill tool names it (plugins/irontrellis/skills/irontrellis-handover). */
export const OWN_SKILL = "irontrellis:irontrellis-handover";

export type DecideOptions = Readonly<{
  /** Check the host session against the history (default true; `check` turns it off). */ checkSession?: boolean;
  /** The route's project, protected beside the config's (protect.ts guardProjects): CLAUDE_PROJECT_DIR, else the project the session was admitted in. */ routeProject?: string;
  /** The clock, for deciding again (bounded) when another writer moved the head past `now` (CAUSAL_TIME_INVALID); see authorizeAtReading. */ clock?: () => number;
}>;

const passed = (config: HookConfig, which: "onAllow" | "onReadOnly", reason: string): ToolDecision =>
  config.decisions[which] === "allow" ? { verdict: "allow", reason } : { verdict: "defer", reason: `${reason}; left to the host's own permission check` };

/** At most this many further decisions after a CAUSAL_TIME_INVALID answer (authorizeAtReading). */
export const MAX_REDECIDE = 3;

/**
 * Decides at `at`, a real clock reading (the hook passes one taken after the history is open). Another copy of the guard
 * may append (its refusal) after that reading and before the head is read; a time before the head is CAUSAL_TIME_INVALID
 * (INDETERMINATE, so "ask"). This mitigates that race, bounded: up to MAX_REDECIDE further decisions, each at a fresh
 * reading of `clock` that is later than the last one used and not before the head. Every time used is a real reading,
 * never the larger of two, so a clock that stepped back still shows a head ahead of it (A-22.4 sees the skew). It is not a
 * race-free guarantee: a head that keeps moving leaves the last INDETERMINATE answer, never an ALLOW. Returns the
 * decision and the reading it was made at.
 */
export function authorizeAtReading<D extends Readonly<{ evidence: Readonly<{ decision: string }>; head: Readonly<{ canonicalTime: number }> }>>(
  authorize: (at: number) => D, at: number, clock?: () => number,
): Readonly<{ d: D; at: number; redecided: number }> {
  let d = authorize(at), used = at, redecided = 0;
  const causal = (x: D): boolean => x.evidence.decision === "INDETERMINATE" && (x.evidence as Readonly<{ code?: unknown }>).code === "CAUSAL_TIME_INVALID";
  while (clock !== undefined && redecided < MAX_REDECIDE && causal(d)) {
    const fresh = clock();
    if (fresh <= used || fresh < d.head.canonicalTime) break;
    used = fresh;
    redecided += 1;
    d = authorize(used);
  }
  return Object.freeze({ d, at: used, redecided });
}

export function decideTool(owner: LocalOwner, config: HookConfig, event: Extract<HookEvent, { kind: "tool" }>, now: number, options: DecideOptions = {}): ToolDecision {
  // 1. Protective rules: IronTrellis state and control commands. Not configurable, not affected by failOpen.
  const guard = protection(config, event.toolName, event.toolInput, event.cwd, options.routeProject === undefined ? process.env : { ...process.env, CLAUDE_PROJECT_DIR: options.routeProject });
  if (guard !== undefined) return { verdict: "deny", reason: denyText(guard.reason, guard.code) };
  if (event.deferTo !== undefined) return { verdict: "defer", reason: `IronTrellis: ${event.toolName} is checked by the ${event.deferTo} hook` };
  // 2. Session fencing: the session admitted at SessionStart must still be current.
  if (options.checkSession !== false) {
    // A-206.3: on an opted-in legacy or format-1 history no session is ever admitted, so every tool call is denied, and the
    // denial says why (FORMAT_READ_ONLY with the remedy), not only SESSION_NOT_FOUND. Nothing is recorded: the file is read-only.
    const older = readOnlyHistoryKind(config);
    if (older !== undefined) return { verdict: "deny", reason: denyText(`the history ${config.history} is ${older} and read-only (SPEC §16.1): no session is admitted from it, so every tool call is denied and nothing is recorded; run \`irontrellis migrate\` to write`, "FORMAT_READ_ONLY") };
    const status = sessionStatus(owner, config, event.sessionId, now);
    if (!status.ok) {
      // A-38.4: a side-effecting call of an agent without a current session is refused and, when the hook has its own
      // connector session, recorded as a CONNECTOR refusal (the code the grants give, else the session's).
      const mapped = mapTool(config.policy, { project: config.project, cwd: event.cwd, tool: event.toolName, server: event.mcpServer, toolInput: event.toolInput });
      const denial = { verdict: "deny" as const, reason: denyText(status.reason, status.code) };
      if (mapped.kind !== "side-effect") return denial;
      const e = owner.authorize({ actor: config.agentId, action: mapped.action, resource: mapped.resource }, { at: now }).evidence;
      return { ...denial, refusal: { action: mapped.action, resource: mapped.resource, code: e.decision === "DENY" ? e.code : status.code, template: mapped.rule.resource, rendersToolInput: rendersToolInput(mapped.rule.resource), withoutSession: true } };
    }
  }
  // The IronTrellis plugin's own skill (founder's live check 01) only explains a refusal and the handover: it is treated as
  // read-only, by its exact name; any other skill is as the policy says (unmapped by default, so referred to the user).
  if (event.toolName === "Skill" && event.toolInput.skill === OWN_SKILL) return passed(config, "onReadOnly", `IronTrellis: ${OWN_SKILL} is IronTrellis's own skill; not checked`);
  const mapping = mapTool(config.policy, { project: config.project, cwd: event.cwd, tool: event.toolName, server: event.mcpServer, toolInput: event.toolInput });
  let decision: ToolDecision;
  switch (mapping.kind) {
    case "read-only":
      decision = passed(config, "onReadOnly", `IronTrellis: ${event.toolName} is read-only under the policy; not checked`);
      break;
    case "unmapped":
      decision = { verdict: config.policy.unmapped, reason: `IronTrellis: ${mapping.why}${config.policy.unmapped === "ask" ? "" : "; refused by policy (unmapped: deny)"}` };
      break;
    case "side-effect": {
      const request = { actor: config.agentId, action: mapping.action, resource: mapping.resource };
      const { d, at } = authorizeAtReading((time) => owner.authorize(request, { at: time }), now, options.clock);
      const e = d.evidence, subject = `${config.agentId} ${mapping.action} on ${mapping.resource}`;
      // A-22.4: a head dated more than 300 s past this host's clock is not decided from (deny).
      if (clockAheadOfReader(d.head, at)) {
        decision = { verdict: "deny", reason: denyText(`the history's head is dated ${d.head.canonicalTime - at} ms ahead of this host's clock (bound ${MAX_CLOCK_SKEW_MS} ms); check the clocks`, "CLOCK_AHEAD_OF_READER") };
        break;
      }
      if (e.decision === "ALLOW") {
        const path = e.proof.permissionPath, terminal = path[path.length - 1];
        decision = passed(config, "onAllow", `IronTrellis · ALLOW: ${subject} (authority ${terminal?.authorityId ?? "?"}, root ${e.proof.recognizedRoot.rootAuthorityId}, head ${d.head.position})`);
      } else if (e.decision === "DENY") {
        const failing = e.failures.map((f) => `${f.code}${f.failingAuthorityId === undefined ? "" : ` at ${f.failingAuthorityId}`}`).slice(0, 4);
        decision = { verdict: "deny", reason: denyText(`${config.agentId} may not ${plainAction(mapping.action, mapping.resource)}`, [e.code, ...failing.filter((f) => f !== e.code), `${mapping.action} on ${mapping.resource}`, `head ${d.head.position}`].join("; ")), refusal: { action: mapping.action, resource: mapping.resource, code: e.code, template: mapping.rule.resource, rendersToolInput: rendersToolInput(mapping.rule.resource) } };
      } else {
        decision = { verdict: "ask", reason: `IronTrellis · INDETERMINATE: ${subject} cannot be decided from the history (${e.code})` };
      }
      break;
    }
  }
  if (decision.verdict !== "ask") return decision;
  if (event.canAsk) return { verdict: "ask", reason: `${decision.reason}; referred to you` };
  const fallback: Verdict = config.askFallback;
  return { verdict: fallback, reason: `${decision.reason}; IronTrellis would ask, but this host event cannot, so askFallback "${fallback}" applies` };
}

// ---------------------------------------------------------------- handover record

export function writeHandover(owner: LocalOwner, config: HookConfig, protocol: Protocol, hostSessionId: string, reason: string | undefined, final: boolean, now: number): { file: string; report: HandoverReport } {
  const report = owner.handover(config.agentId, { at: now });
  const file = handoverFile(config, hostSessionId);
  const sessions = report.sessions.filter((s) => s.sessionId === `session:${hostSessionId}` || s.sessionId.startsWith(`session:${hostSessionId}:`));
  const record = {
    version: HANDOVER_VERSION, protocol: protocol.id, hostSessionId, historySessionIds: sessions.map((s) => s.sessionId), agent: config.agentId, history: config.history,
    endedAt: now, reason: reason ?? null, final,
    summary: { openDuties: report.openDuties.length, liveGrants: report.liveGrants.length, terminated: report.terminated },
    report,
  };
  writePrivateFile(file, `${JSON.stringify(JSON.parse(jsonStringifyWithBigints(record)), null, 2)}\n`);
  return { file, report };
}

// ---------------------------------------------------------------- the entry point

/** Plain words for each pin, anchor-log and witness finding (`detail.reason` of ROLLBACK_DETECTED / ANCHOR_LOG_UNREADABLE / WITNESS_UNREADABLE). */
const HISTORY_FINDINGS: Readonly<Record<string, string>> = Object.freeze({
  BEHIND_PIN: "the history file does not contain its pinned head: events were removed or replaced",
  PIN_MALFORMED: "the pinned head file is malformed, so it cannot vouch for the history",
  PIN_MISSING: "the history's pinned head file is missing, and a deleted pin hides a truncation",
  PIN_UNATTESTED: "the pinned head carries no owner attestation, so it cannot rule out a truncation (anyone who can write the directory can write such a pin)",
  PIN_ATTESTATION_INVALID: "the pinned head's attestation is not a valid signature by the history's owner key",
  PIN_ATTESTED_NOT_PREFIX: "the owner attested a head that the history file no longer contains: events were removed or replaced",
  ANCHOR_LOG_ROLLBACK: "the anchor log holds an owner-attested head that the history file no longer contains: events were removed, or an older copy was restored",
  ANCHOR_LOG_UNREADABLE: "the anchor log cannot be read, so a rollback cannot be ruled out",
  WITNESS_STATE_UNREADABLE: "the remote witness state file (<history>.witness.json) is malformed, so it cannot be used to rule out a rollback",
  WITNESS_AHEAD: "a remote witness holds an owner-signed head past the end of the history file: events were removed, or an older copy was restored",
  WITNESS_FORK: "a remote witness holds an owner-signed head that differs from the history file: the file was rewritten or replaced",
});
/** `irontrellis-hook: ROLLBACK_DETECTED (PIN_UNATTESTED): <plain sentence>…` for a history the engine refused to trust. */
const historyFinding = (error: unknown): string | undefined => {
  if (!(error instanceof IronTrellisError || error instanceof EngineError) || (error.code !== "ROLLBACK_DETECTED" && error.code !== "ANCHOR_LOG_UNREADABLE" && error.code !== "WITNESS_UNREADABLE")) return undefined;
  const reason = (error.detail as { reason?: unknown } | null | undefined)?.reason;
  const plain = typeof reason === "string" ? HISTORY_FINDINGS[reason] : undefined;
  if (plain === undefined) return undefined;
  return `irontrellis-hook: ${error.code} (${String(reason)}): ${plain}. Every tool call is refused until an operator checks the history with irontrellis verify, then restores the latest copy or re-pins it deliberately (verify --accept-rollback). Engine: ${error.message}`;
};

const describe = (error: unknown): string => {
  if (error instanceof HookConfigError) return `irontrellis-hook: ${error.message}`;
  const finding = historyFinding(error);
  if (finding !== undefined) return finding;
  if (error instanceof IronTrellisError || error instanceof EngineError) return `irontrellis-hook: ${error.code}${error.message === error.code ? "" : `: ${error.message}`}`;
  return `irontrellis-hook: ${error instanceof Error ? error.message : String(error)}`;
};

/**
 * Best effort: submit queued head statements to the remote witnesses before the
 * hook process exits. An unreachable witness leaves them queued in the side
 * file (the next owner write or `irontrellis witness sync` submits them); only
 * witness evidence (rollback, equivocation, split view) is an error.
 */
export async function submitWitnessStatements(owner: LocalOwner): Promise<void> {
  if (owner.witnessStatus() === undefined) return;
  try {
    await owner.flush();
  } catch (error) {
    if (error instanceof IronTrellisError && (error.code === "ROLLBACK_DETECTED" || error.code === "WITNESS_SPLIT_VIEW")) throw error;
  }
}

/** Whether the config (if any can be loaded) asks for failOpen; a config that cannot be loaded does not. */
/** An error reply: for a tool event, a refusal, or with failOpen the host's own permissions and a warning; otherwise non-blocking. */
export const replyFailure = (protocol: Protocol, message: string, toolEvent: boolean, failOpen: boolean): Reply =>
  !toolEvent ? protocol.replyError(message, false) : failOpen ? protocol.replyFailOpen(message) : protocol.replyError(message, true);

/**
 * Whether the user chose failOpen for this event's route: the config recorded when the host session was admitted (the
 * route-session record, route.ts) once there is one, so a config at the event's cwd or one named in the environment
 * later cannot change it; before that, or for an event without a readable session id, the route's config
 * (CLAUDE_PROJECT_DIR's, else the hook's working directory's), never the event's cwd (it follows the agent's `cd`).
 */
export function failOpenForRoute(env: HookIo["env"], cwd: string, hostSessionId?: string): boolean {
  try {
    const route = env.CLAUDE_PROJECT_DIR !== undefined && env.CLAUDE_PROJECT_DIR !== "" && isAbsolute(env.CLAUDE_PROJECT_DIR) ? env.CLAUDE_PROJECT_DIR : cwd;
    const record = hostSessionId === undefined || hostSessionId === "" ? undefined : readRouteSession(env, hostSessionId);
    // A record counts for the project it was written in (a host session id seen in another project is not this route).
    if (record?.config !== undefined && record.project === canonicalProject(route)) return loadConfigFile(record.config).failOpen;
    return loadConfig(env, route).failOpen;
  } catch { return false; }
}
/** Earlier name; the event's cwd is no longer consulted (failOpenForRoute). */
export function failOpenFor(env: HookIo["env"], cwd: string, _eventCwd?: string): boolean { return failOpenForRoute(env, cwd); }

/** Run one hook invocation: parse the host event, act, render the host reply. Never throws. */
export async function runHook(protocol: Protocol, eventName: string, payload: Readonly<Record<string, unknown>>, io: HookIo): Promise<Reply> {
  let event: HookEvent;
  const isToolEvent = protocol.toolEvents.includes(eventName);
  try {
    event = protocol.parse(eventName, payload);
  } catch (error) {
    event = { kind: "malformed", note: error instanceof Error ? error.message : String(error) };
  }
  if (event.kind === "ignored") return protocol.replyIgnored();
  if (event.kind === "malformed") {
    const sessionId = typeof payload.session_id === "string" ? payload.session_id : undefined;
    return replyFailure(protocol, `irontrellis-hook: refused a malformed ${eventName} event: ${event.note}`, isToolEvent, isToolEvent && failOpenForRoute(io.env, io.cwd, sessionId));
  }
  let config: HookConfig;
  // The route's project (CLAUDE_PROJECT_DIR, which Claude Code sets for hooks) picks the config, not the event's cwd (it follows `cd`).
  const routeDir = io.env.CLAUDE_PROJECT_DIR !== undefined && io.env.CLAUDE_PROJECT_DIR !== "" && isAbsolute(io.env.CLAUDE_PROJECT_DIR) ? io.env.CLAUDE_PROJECT_DIR : undefined;
  try {
    config = routeDir !== undefined ? loadConfig(io.env, routeDir) : loadConfig(io.env, io.cwd, event.cwd);
  } catch (error) {
    return protocol.replyError(describe(error), event.kind === "tool");
  }
  const now = io.now();
  // A-41.2: the opt-in warning goes after the reply's own stderr text (hosts and tests read its first line).
  const warnings: string[] = [];
  const reply = await answer(protocol, event, config, io, now, (w) => warnings.push(w));
  return warnings.length === 0 ? reply : Object.freeze({ ...reply, stderr: `${reply.stderr}${reply.stderr === "" || reply.stderr.endsWith("\n") ? "" : "\n"}${warnings.map((w) => `${w}\n`).join("")}` });
}

async function answer(protocol: Protocol, event: Exclude<HookEvent, { kind: "ignored" | "malformed" }>, config: HookConfig, io: HookIo, now: number, onWarning: (warning: string) => void): Promise<Reply> {
  // The protective rules need only the config and the call (independent review A, RA-06): they decide before the history is
  // opened, so a history that cannot be read (failOpen or not) never lets a protected call through.
  if (event.kind === "tool") {
    const recorded = readRouteSession(io.env, event.sessionId);
    const routeProject = io.env.CLAUDE_PROJECT_DIR || recorded?.project || io.cwd;
    try {
      const guard = protection(config, event.toolName, event.toolInput, event.cwd, { ...process.env, CLAUDE_PROJECT_DIR: routeProject });
      if (guard !== undefined) return protocol.replyTool(event, { verdict: "deny", reason: denyText(guard.reason, guard.code) });
    } catch (error) {
      return protocol.replyTool(event, { verdict: "deny", reason: denyText(`the protective rules could not check this call (${error instanceof Error ? error.message : String(error)})`, "PROTECTION_FAILED") });
    }
    // A session's config is sticky on the hook route too, as on the plugin route (RA-03): a call under another config than
    // the one the session was admitted with (another IRONTRELLIS_HOOK_CONFIG, a config moved in) is refused.
    // As failOpenForRoute: a record counts for the project it was written in (the same host session id in another project is not this route).
    const here = io.env.CLAUDE_PROJECT_DIR !== undefined && io.env.CLAUDE_PROJECT_DIR !== "" && isAbsolute(io.env.CLAUDE_PROJECT_DIR) ? io.env.CLAUDE_PROJECT_DIR : io.cwd;
    if (recorded?.config !== undefined && recorded.project === canonicalProject(here) && canonicalProject(recorded.config) !== canonicalProject(config.path)) {
      return protocol.replyTool(event, { verdict: "deny", reason: denyText(`this session was admitted under the config ${recorded.config}, and this call would be decided under ${config.path}; restore it, or end the session, in your own terminal`, "CONFIG_CHANGED") });
    }
  }
  try {
    const owner = openOwner(config, io.now, "enforce", onWarning);
    // Remote witnesses come from <history>.witness.json and the history's own bindings. A policy with requireOnOpen is checked
    // here, before any decision reads the history: a rollback the witnesses show refuses the event (fail closed for tools).
    if (owner.witnessStatus()?.checkRequired === true) await owner.checkWitnesses();
    switch (event.kind) {
      case "session-start": {
        let admission: Awaited<ReturnType<typeof admitSession>>;
        try {
          await ensureAgent(owner, config);
          admission = await admitSession(owner, config, event.sessionId, now);
        } catch (error) { throw readOnlyRefusal(config, error); }
        // This process ends with the reply: submit the head statements now (the background worker would not get the chance).
        await submitWitnessStatements(owner);
        // Evaluate after the writes: the head has moved past the clock reading taken above.
        const context = openingContext(owner, config, admission, event.sessionId, Math.max(io.now(), now));
        // Both routes present (route.ts): said once, at session start, by a settings hook only (never when the plugin itself runs
        // this guard, founder's live check 01). With the verified hook route the plugin steps aside; with another entry both run.
        const both = protocol.id === "claude-code" && io.via !== "plugin" && pluginEnabled(config.project, io.env)
          ? hookRoute(config.project, io.env).verified
            ? "IronTrellis: the IronTrellis plugin for Claude Code (`irontrellis` in /plugin) is also enabled here; it is stepping aside, and this hook is the one guard (choose one route per project)."
            : "IronTrellis: the IronTrellis plugin for Claude Code (`irontrellis` in /plugin) is also enabled here, and this settings hook is not the entry `irontrellis-hook install claude-code --write` writes, so both run the guard (choose one route per project)."
          : undefined;
        const warning = [admission.refused === undefined ? undefined : context, both].filter((w): w is string => w !== undefined).join("\n\n");
        // The route this session is admitted under, for failOpen (failOpenForRoute) and the plugin's sticky check: kept as first recorded.
        const routeProject = canonicalProject(io.env.CLAUDE_PROJECT_DIR || io.cwd), recorded = readRouteSession(io.env, event.sessionId);
        if (admission.refused === undefined && (recorded === undefined || recorded.project !== routeProject)) {
          try { writeRouteSession(io.env, event.sessionId, { state: "hook", project: routeProject, config: config.path }, now); } catch { /* failOpen then reads the route's config */ }
        }
        return protocol.replySessionStart(context, warning === "" ? undefined : warning);
      }
      case "tool": {
        const routeProject = io.env.CLAUDE_PROJECT_DIR || readRouteSession(io.env, event.sessionId)?.project || io.cwd;
        // Decide at a reading taken after the history is open (not the larger of it and `now`: a clock that stepped back must
        // still show a head ahead of it, A-22.4). authorizeAtReading mitigates, bounded, a head another copy of the guard moves.
        const decision = decideTool(owner, config, event, io.now(), { routeProject, clock: io.now });
        // A-38: verdict first; a format-2 history records the grant DENY through the agent's session, bounded by
        // recordBudgetMs (spooled past it), and a CONNECTOR refusal through the hook's own session (A-42, A-38.4);
        // nothing is recorded for format 1 or legacy (as in format 1).
        if (decision.refusal !== undefined) {
          try { await recordToolRefusal(config, event.sessionId, decision.refusal, io.now, undefined, event.toolUseId); } catch { /* recording is best effort and bounded; the verdict stands */ }
        }
        return protocol.replyTool(event, decision);
      }
      case "session-end": {
        if (!agentExists(owner, config.agentId)) return protocol.replySessionEnd(`IronTrellis: agent ${config.agentId} is not in ${config.history}; no handover written`);
        // One handover per stop: a second copy of the guard ending the same session finds the lock held and leaves the write to the first.
        const written = await withLockFile(`${handoverFile(config, event.sessionId)}.lock`, () => writeHandover(owner, config, protocol, event.sessionId, event.reason, event.final, now), { waitMs: 0, held: () => undefined });
        if (written === undefined) return protocol.replySessionEnd(`IronTrellis: another copy of the guard is writing this session's handover (${handoverFile(config, event.sessionId)})`);
        const { file, report } = written;
        // The final end releases this host session's key, so the next session may fence it and start.
        const mine = event.final ? readSessionKey(sessionKeyFile(config, event.sessionId)) : undefined;
        const released = mine !== undefined && mine.agentId === config.agentId && releaseSessionKey(mine, now);
        if (event.final) removePrivateFile(routeSessionFile(io.env, event.sessionId)); // the session's route is forgotten with it
        return protocol.replySessionEnd(`${endingSummary(report, event.sessionId, file, event.reason, event.final)}${released ? "\nSession key released." : ""}`);
      }
    }
  } catch (error) {
    return replyFailure(protocol, describe(error), event.kind === "tool", failOpenForRoute(io.env, io.cwd, event.sessionId));
  }
}
