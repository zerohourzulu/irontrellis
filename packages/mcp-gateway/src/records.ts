/**
 * What the gateway records beside its decisions on a format-2 history (SPEC §10, §11; docs/API.md §2):
 *
 * - a CORE or BUDGET refusal for every DENY / INDETERMINATE the history decided, signed by the agent's own session (the
 *   session the gateway acts for), re-derived by the writer before it signs and bounded by `recordBudgetMs` (A-38: past
 *   it the input is spooled beside the history and the next call drains it);
 * - a CONNECTOR refusal, signed by the gateway's own connector session, when the resource template renders tool
 *   arguments (A-42: the template and a digest of the rendered request, never the arguments) or when an upstream
 *   refuses a forwarded call;
 * - an EFFECT_RECORDED measured by the gateway (CONNECTOR) when an upstream reports a measurement for a recorded call;
 * - a COUNTERPARTY_RECEIPT_RECORDED when an upstream returns a receipt envelope its counterparty signed.
 *
 * The decision is always returned first and unchanged: recording never turns a decision into an error (A-11). Nothing
 * is recorded on a legacy or format-1 history, or without the connector session where one is needed.
 */
import {
  boundedRefusal, derivedId, drainRefusalSpool, openHistoryStore, openLocalRuntime, refusalSpoolPathFor, REFUSAL_POLICY_DEFAULTS, REFUSAL_SPOOL_VERSION,
  type ContentHash, type LocalExecutionOptions, type RefusalResult, type SignHash,
} from "@ramex-labs/irontrellis";
import { existsSync } from "node:fs";
import { codeOf, hash, type Json } from "./data.ts";

/** The gateway's own owner-admitted session (agent `gateway` in the demo case). */
export type ConnectorIdentity = Readonly<{ session: string; signHash: SignHash }>;
/** How a recording went, as the gateway reports it beside the decision. */
export type Recorded = Readonly<{ recorded: true; eventId: string }> | Readonly<{ recorded: false; reason: string }>;
/** What an upstream may report in `structuredContent.irontrellis` for a job or tool configured with `records`. */
export type UpstreamReport = Readonly<{
  refusal?: Readonly<{ code: string }>;
  effect?: Readonly<{ metric: string; unit: string; amount: string }>;
  counterpartyReceipt?: Json;
}>;
export const RECORD_KINDS = ["refusal", "effect", "receipt"] as const;
export type RecordKind = (typeof RECORD_KINDS)[number];

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9:._@/+-]{0,127}$/;
const AMOUNT = /^(0|[1-9][0-9]{0,77})$/;
const outcomeOf = (result: RefusalResult | { eventId: string }): Recorded =>
  "eventId" in result ? { recorded: true, eventId: result.eventId } : { recorded: false, reason: result.reason };
// A-179.4: a record past the session time horizon is not signed; its not-recorded reason is SESSION_TIME_HORIZON.
const failed = (error: unknown): Recorded => ({ recorded: false, reason: (error as { detail?: { reason?: unknown } } | null)?.detail?.reason === "SESSION_TIME_HORIZON" ? "SESSION_TIME_HORIZON" : codeOf(error) ?? "WRITE_UNCONFIRMED" });

/** The `structuredContent.irontrellis` block of an upstream reply, kept only when well formed. */
export function upstreamReport(structured: unknown): UpstreamReport {
  const block = (structured as { irontrellis?: unknown } | null | undefined)?.irontrellis;
  if (block === null || typeof block !== "object" || Array.isArray(block)) return {};
  const b = block as Record<string, unknown>, out: Record<string, unknown> = {};
  const refusal = b.refusal as { code?: unknown } | undefined;
  if (typeof refusal?.code === "string" && IDENTIFIER.test(refusal.code)) out.refusal = { code: refusal.code };
  const effect = b.effect as { metric?: unknown; unit?: unknown; amount?: unknown } | undefined;
  const amount = typeof effect?.amount === "number" && Number.isSafeInteger(effect.amount) && effect.amount >= 0 ? String(effect.amount) : effect?.amount;
  if (typeof effect?.metric === "string" && IDENTIFIER.test(effect.metric) && typeof effect.unit === "string" && IDENTIFIER.test(effect.unit) && typeof amount === "string" && AMOUNT.test(amount)) {
    out.effect = { metric: effect.metric, unit: effect.unit, amount };
  }
  if (b.counterpartyReceipt !== null && typeof b.counterpartyReceipt === "object" && !Array.isArray(b.counterpartyReceipt)) out.counterpartyReceipt = b.counterpartyReceipt as Json;
  return Object.freeze(out);
}

export function createRecorder(local: LocalExecutionOptions, connector: ConnectorIdentity | undefined) {
  const historyFile = local.historyFile;
  const format2 = (): boolean => openHistoryStore(historyFile, { inspect: true, witness: false }).format === "irontrellis-event/2";
  const budgetMs = local.refusalPolicy?.recordBudgetMs ?? REFUSAL_POLICY_DEFAULTS.recordBudgetMs;
  const actor = () => openLocalRuntime({ ...local, refusalPolicy: { ...REFUSAL_POLICY_DEFAULTS, ...local.refusalPolicy } });
  const ownSession = () => connector === undefined ? undefined : openLocalRuntime({ ...local, session: connector.session, signHash: connector.signHash, refusalPolicy: { ...REFUSAL_POLICY_DEFAULTS, ...local.refusalPolicy } });
  const connectorId = (): string | undefined => {
    if (connector === undefined) return undefined;
    return openHistoryStore(historyFile, { inspect: true, witness: false }).state().runtimeSessions.get(connector.session)?.agentId;
  };
  /** A CONNECTOR write, bounded like a refusal (A-38.1): a late write keeps running and names the same id. */
  const bounded = async (write: Promise<RefusalResult | { eventId: string }>): Promise<Recorded> => {
    write.catch(() => undefined);
    let timer: NodeJS.Timeout | undefined;
    const deadline = new Promise<Recorded>((resolve) => { timer = setTimeout(() => resolve({ recorded: false, reason: "RECORD_DEADLINE" }), budgetMs); timer.unref(); });
    try { return await Promise.race([write.then(outcomeOf, failed), deadline]); } finally { if (timer !== undefined) clearTimeout(timer); }
  };
  return {
    /**
     * A DENY or INDETERMINATE decision of the history on `request` (actor = the agent the gateway acts for). `template`
     * set: the resource was rendered from tool arguments, so a CONNECTOR refusal carries the template and a digest (A-42).
     */
    async decision(request: Readonly<{ actorId: string; action: string; resource: string }>, options: Readonly<{ template?: string; code?: string }> = {}): Promise<Recorded | undefined> {
      try {
        if (!format2()) return undefined;
        const claimedAt = local.now();
        if (options.template !== undefined) {
          const id = connectorId(), writes = ownSession();
          if (id === undefined || writes === undefined || options.code === undefined) return undefined;
          const detailDigest = hash({ ...request, claimedAt }) as ContentHash;
          return await bounded(writes.recordRefusal({ refusalId: derivedId("refusal", id), request: { actorId: request.actorId, action: request.action, resource: options.template, claimedAt }, connector: { connectorId: id, refusalCode: options.code, detailDigest } }));
        }
        const writes = actor();
        // A-38.2: this agent's spooled refusals first, re-derived at the drain time (the attempt time goes to the side log).
        if (existsSync(refusalSpoolPathFor(historyFile))) {
          await drainRefusalSpool(historyFile, writes, request.actorId, local.now, (refusalId) => openHistoryStore(historyFile, { inspect: true, witness: false }).state().refusals.has(refusalId));
        }
        const refusalId = derivedId("refusal", request.actorId);
        return outcomeOf(await boundedRefusal(historyFile, writes.recordRefusal({ refusalId, request: { ...request, claimedAt } }),
          Object.freeze({ version: REFUSAL_SPOOL_VERSION, refusalId, attemptedAt: claimedAt, request }), budgetMs));
      } catch (error) {
        return failed(error);
      }
    },
    /** An upstream refused a forwarded call: a CONNECTOR refusal (attested, not re-derived) with the upstream's code. */
    async upstreamRefusal(request: Readonly<{ actorId: string; action: string; resource: string }>, code: string, reply: unknown): Promise<Recorded | undefined> {
      try {
        const id = connectorId(), writes = ownSession();
        if (!format2() || id === undefined || writes === undefined) return undefined;
        return await bounded(writes.recordRefusal({ refusalId: derivedId("refusal", id), request: { ...request, claimedAt: local.now() }, connector: { connectorId: id, refusalCode: code, detailDigest: hash(reply) as ContentHash } }));
      } catch (error) {
        return failed(error);
      }
    },
    /** A measurement the upstream reported for an admitted intent, recorded as measured by the gateway (CONNECTOR, SPEC §10.2). */
    async effect(intentId: string, effect: NonNullable<UpstreamReport["effect"]>, reply: unknown): Promise<Recorded | undefined> {
      try {
        const id = connectorId(), writes = ownSession();
        if (!format2() || id === undefined || writes === undefined) return undefined;
        return await bounded(writes.recordEffect({ intentId, operationId: intentId, measurer: { kind: "CONNECTOR", id }, metric: effect.metric, unit: effect.unit, amount: effect.amount, observedAt: local.now(), detailDigest: hash(reply) as ContentHash }));
      } catch (error) {
        return failed(error);
      }
    },
    /** A receipt envelope the upstream's counterparty signed, wrapped by the connector session (SPEC §11.2). */
    async receipt(intentId: string, envelope: Json): Promise<Recorded | undefined> {
      try {
        const writes = ownSession();
        if (!format2() || writes === undefined) return undefined;
        return await bounded(writes.recordCounterpartyReceipt({ intentId, envelope: envelope as never }));
      } catch (error) {
        return failed(error);
      }
    },
  };
}
export type Recorder = ReturnType<typeof createRecorder>;
