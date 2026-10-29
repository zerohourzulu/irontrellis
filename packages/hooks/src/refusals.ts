/**
 * A-38 for the hook (format-2 histories): a DENY the grants decided is recorded as a `REQUEST_REFUSED` (source CORE,
 * signed by the agent's own session key, which the hook holds for it), bounded by `recordBudgetMs` (default 250 ms,
 * A-38.1): past it the input is spooled beside the history (`SPOOLED`, or `RECORD_DEADLINE` when the spool cannot be
 * written) and the verdict is unchanged. Every such recording first drains this agent's spool (A-38.2, re-derived at the
 * drain time; the attempt time goes to the side log, A-68). The hook's own connector session (`hooks:<host>`, admitted
 * by init, docs/API.md §2) signs CONNECTOR refusals only: a rule rendering tool input (A-42), and a refused call of an
 * agent whose session is not current (A-38.4). Without that session nothing is recorded for those. Format 1 and legacy
 * histories have no refusal records: nothing is recorded, as with format 1 before.
 */
import {
  boundedRefusal, codePointLength, derivedId, hashCanonical, drainRefusalSpool, keyPairFromPrivateKey, openHistoryStore, openLocalRuntime, pendingRotationPathFor, REFUSAL_POLICY_DEFAULTS,
  REFUSAL_SPOOL_VERSION, refusalSpoolPathFor, signHashWith, type AuthorizationDomain, type RefusalResult, type SignatureScheme,
} from "@ramex-labs/irontrellis";
import { appendFileSync, existsSync } from "node:fs";

const appendPrivateLine = (path: string, value: unknown): void => appendFileSync(path, `${JSON.stringify(value)}\n`, { mode: 0o600 });
import type { HookConfig } from "./config.ts";
import { sessionKeyFile } from "./hook.ts";
import { CONNECTOR_KEY_VERSION, connectorKeyFile, readPrivateJson } from "./paths.ts";

export type ToolRefusal = Readonly<{
  action: string; resource: string; code?: string; template?: string; rendersToolInput?: boolean;
  /** A-38.4: the agent has no current session (fenced, expired, released): recorded through the connector session. */
  withoutSession?: boolean;
}>;

/** The hook's own connector runtime, when init admitted one and its key file is here; else `undefined` (nothing to sign with). */
function connectorRuntime(config: HookConfig, domain: AuthorizationDomain, now: () => number, budgetMs: number) {
  if (config.connector === undefined) return undefined;
  const key = readPrivateJson(connectorKeyFile(config.history)) as Record<string, unknown> | null;
  if (key === null || typeof key !== "object" || key.version !== CONNECTOR_KEY_VERSION || key.agentId !== config.connector.agentId || typeof key.privateKey !== "string" || typeof key.sessionId !== "string") return undefined;
  const pair = keyPairFromPrivateKey(key.scheme as SignatureScheme, key.keyId as string, key.privateKey);
  const runtime = openLocalRuntime({
    historyFile: config.history, domain, owner: config.owner, controller: config.controller, now,
    session: key.sessionId, signHash: signHashWith(pair), refusalPolicy: { ...REFUSAL_POLICY_DEFAULTS, recordBudgetMs: budgetMs }, witness: false,
  });
  return { runtime, connectorId: config.connector.agentId };
}
/** The store's refusal of a witness-off append while a prepared rotation is outstanding (checked under the writer lock). */
const rotationPendingRefusal = (error: unknown): boolean =>
  typeof error === "object" && error !== null && (error as { code?: unknown }).code === "WITNESS_UNAVAILABLE" && ((error as { detail?: { reason?: unknown } }).detail?.reason === "ROTATION_PENDING");
const notRecordedWhilePending = (error: unknown): RefusalResult => {
  if (rotationPendingRefusal(error)) return Object.freeze({ recorded: false as const, reason: "ROTATION_PENDING" });
  throw error;
};
const withinBudget = (attempt: Promise<RefusalResult>, budgetMs: number): Promise<RefusalResult> => {
  attempt.catch(() => undefined);
  return Promise.race([attempt, new Promise<RefusalResult>((resolve) => setTimeout(() => resolve(Object.freeze({ recorded: false as const, reason: "RECORD_DEADLINE" })), budgetMs).unref())]);
};
/**
 * A-42: a rule whose resource template renders tool input is recorded as a CONNECTOR refusal through the hook's own
 * session: `request.resource` is the template as configured (unrendered, ≤ 128 characters: code points, A-89.2), `connector.refusalCode` the
 * code derived on the rendered request, `connector.detailDigest` the sha256 of the canonical rendered request, which goes
 * only to the local side log (`<history>.refusals.rendered.log`, deletable), never into the history.
 */
export async function recordToolRefusal(config: HookConfig, hostSessionId: string, request: ToolRefusal, now: () => number,
  budgetMs: number = REFUSAL_POLICY_DEFAULTS.recordBudgetMs, toolUseId: string | undefined = undefined): Promise<RefusalResult | undefined> {
  const store = openHistoryStore(config.history, { inspect: true, witness: false });
  const format = store.format, state = format === "irontrellis-event/2" ? store.state() : undefined;
  store.close();
  if (state === undefined) return undefined;
  const domain = (config.domain ?? state.genesis.domain) as AuthorizationDomain;
  // These handles write with the witnesses off (they sign with session keys), so they skip the ROTATION_PENDING
  // guard. While a prepared owner key rotation is outstanding (docs/reference/witness-operations.md §7.1), a bound witness may already hold its
  // head, and an append on top of its previous head would fork that witness: nothing is appended until an owner process
  // resolves it. A session refusal is spooled (recorded, decided again, by a later drain); a CONNECTOR refusal, which is
  // never spooled, is not recorded.
  const rotationPending = existsSync(pendingRotationPathFor(config.history));
  // One record per denied call: with the host's tool-call id the refusal id is derived from it, so a second copy of the guard
  // deciding the same call (the plugin and the settings hook, or the hook installed twice) finds it recorded (idempotent by id).
  const refusalIdOf = (actor: string): string => derivedId("refusal", actor, toolUseId === undefined ? undefined : `tool:${hostSessionId}:${toolUseId}`);
  if (request.withoutSession === true || request.rendersToolInput === true) {
    // CONNECTOR refusals are attested, not re-derived by replay: recorded directly (bounded), never spooled for re-derivation.
    if (rotationPending) return Object.freeze({ recorded: false as const, reason: "ROTATION_PENDING" });
    const own = connectorRuntime(config, domain, now, budgetMs);
    if (own === undefined || request.code === undefined) return undefined;
    const attemptedAt = now(), refusalId = refusalIdOf(own.connectorId);
    const rendered = { actorId: config.agentId, action: request.action, resource: request.resource, claimedAt: attemptedAt };
    const detailDigest = hashCanonical(rendered, "sha256");
    let resource = request.resource;
    if (request.rendersToolInput === true) {
      if (request.template === undefined || codePointLength(request.template, 128) > 128) return undefined;
      resource = request.template;
      try { appendPrivateLine(`${config.history}.refusals.rendered.log`, { refusalId, detailDigest, rendered }); } catch { return Object.freeze({ recorded: false as const, reason: "RECORD_DEADLINE" }); }
    }
    return withinBudget(own.runtime.recordRefusal({ refusalId, request: { actorId: config.agentId, action: request.action, resource, claimedAt: attemptedAt },
      connector: { connectorId: own.connectorId, refusalCode: request.code, detailDigest } }).catch(notRecordedWhilePending), budgetMs);
  }
  const key = readPrivateJson(sessionKeyFile(config, hostSessionId)) as Record<string, unknown> | null;
  if (key === null || typeof key !== "object" || typeof key.privateKey !== "string" || typeof key.sessionId !== "string" || key.agentId !== config.agentId) return undefined;
  const pair = keyPairFromPrivateKey(key.scheme as SignatureScheme, key.keyId as string, key.privateKey);
  const runtime = openLocalRuntime({
    historyFile: config.history, domain, owner: config.owner, controller: config.controller, now,
    session: key.sessionId, signHash: signHashWith(pair), refusalPolicy: { ...REFUSAL_POLICY_DEFAULTS, recordBudgetMs: budgetMs }, witness: false,
  });
  const refusalId = refusalIdOf(config.agentId);
  const attemptedAt = now();
  const body = { actorId: config.agentId, action: request.action, resource: request.resource };
  const entry = Object.freeze({ version: REFUSAL_SPOOL_VERSION, refusalId, attemptedAt, request: body });
  // A budget of 0 with an attempt that never settles: straight to the spool, nothing appended.
  if (rotationPending) return boundedRefusal(config.history, new Promise<RefusalResult>(() => undefined), entry, 0);
  // One read of the recorded refusals per drain, not one store open per waiting entry.
  const recorded = existsSync(refusalSpoolPathFor(config.history)) ? openHistoryStore(config.history, { inspect: true, witness: false }).state().refusals : undefined;
  // A-38.1: the drain and this refusal share one recordBudgetMs from here; what the drain did not reach stays spooled. The
  // refusal gets what the drain left, and no further wait when the drain reached its deadline: it is spooled at once, though
  // its write may still start alongside a drain write still running. About one budget, not a hard bound (see drainRefusalSpool).
  const recording = performance.now();
  const drained = { deadlineReached: false, writeStillRunning: false }; // filled in by the drain (its DrainReport)
  const left = (): number => drained.deadlineReached ? 0 : Math.max(0, budgetMs - (performance.now() - recording));
  if (recorded !== undefined) await drainRefusalSpool(config.history, runtime, config.agentId, now, (id: string) => recorded.has(id), { deadlineMs: left(), report: drained });
  // The early check above is a fast path; the store's check under the writer lock is the one that decides (a rotation
  // prepared after it): its refusal sends the entry to the spool. The drain keeps an entry it cannot write.
  const attempt = runtime.recordRefusal({ refusalId, request: { ...body, claimedAt: attemptedAt } })
    .catch((error: unknown) => rotationPendingRefusal(error) ? boundedRefusal(config.history, new Promise<RefusalResult>(() => undefined), entry, 0) : Promise.reject(error));
  return boundedRefusal(config.history, attempt, entry, left());
}
