/**
 * Signed duty operations (port of Core 0.3 `runtime.ts`): obligations created
 * from an actual recorded operation, acknowledgment and receipt, and their
 * performance assignment after a role transfer. No root grants, role changes
 * or external effects; every event is an administrative transition signed by
 * the session credential and re-checked at the post-signing host time.
 */
import { AdministrativeProducerError, type AdministrativeEventType } from "./administration.ts";
import { IronTrellisError, identifier, record, requireCondition, time } from "./input.ts";
import { configuration, currentState, openStore, type LocalOwnerOptions, type WriteResult } from "./owner.ts";
import { guardedSigner, type SignHash } from "./execution.ts";
import { derivedId, sessionWrites } from "./session-writes.ts";
import { sessionOf, signedTransition } from "./runtime-writes.ts";
import type { CanonicalEvent, ObligationRecord } from "./types.ts";

export type LocalRuntimeOptions = LocalOwnerOptions & Readonly<{ session: string; signHash: SignHash }>;
export type Obligation = Readonly<{ id: string; operation: string; description: string; deadline: number; succession: string; reviewAuthority: string }>;
export type Assignment = Readonly<{ id: string; obligation: string }>;

/** The administrative effect of a recorded event: its data without the signature wrapper. */
export const administrativeEffect = (event: CanonicalEvent): Readonly<Record<string, unknown>> => {
  const { administrativeAuthorization: _signature, ...effect } = event.data;
  return effect;
};
export const description = (value: unknown): string => {
  requireCondition(typeof value === "string" && value.length > 0 && value.length <= 1024 && !/[\u0000-\u001f\u007f]/.test(value));
  return value;
};

/**
 * The local API never lets a raw `AdministrativeProducerError` escape; it maps
 * the producer's `phase:code` onto the owner API's stable codes (the original
 * `phase:code` stays in the message and in `detail`):
 * - `*:HEAD_MISMATCH` (the history moved, e.g. while the signer ran) → HISTORY_CONFLICT;
 * - `SIGN:SIGNER_INVALID` / `SIGN:SIGNER_FAILED` → SIGNER_FAILED;
 * - `CAPTURE:*` (including `CAPTURE:INPUT_LIMIT`) → INVALID_INPUT;
 * - every other `PREPARE:*` / `VERIFY:*` (no grant for the action, stale session, rejected signed event…) → TRANSITION_REJECTED.
 * Anything else is returned unchanged.
 */
export function producerFailure(error: unknown): unknown {
  if (!(error instanceof AdministrativeProducerError)) return error;
  const producer = `${error.phase}:${error.code}`, detail = Object.freeze({ producerError: producer, phase: error.phase, code: error.code });
  const code = error.code === "HEAD_MISMATCH" ? "HISTORY_CONFLICT"
    : error.code === "SIGNER_INVALID" || error.code === "SIGNER_FAILED" ? "SIGNER_FAILED"
    : error.phase === "CAPTURE" ? "INVALID_INPUT"
    : "TRANSITION_REJECTED";
  return new IronTrellisError(code, false, `administrative transition refused (${producer})`, detail);
}

/**
 * Signed duty operations; no root grants, role changes or external effects. Format 2 adds the session-signed records of
 * SPEC §10–§11 (`recordRefusal`, `recordEffect`, `recordCounterpartyReceipt`) and the read-only `headroom` (a runtime handle has no `exportView`).
 */
export function openLocalRuntime(options: LocalRuntimeOptions) {
  const config = configuration(options), sessionId = identifier(options.session), signer = options.signHash;
  requireCondition(typeof signer === "function");
  const store = openStore(config);
  const session = sessionOf(store, config, sessionId);
  const signed = (id: string, type: AdministrativeEventType, data: Readonly<Record<string, unknown>>) => signedTransition(store, config, sessionId, signer, id, type, data);
  const writes = sessionWrites(store, config, sessionId, session, guardedSigner(signer, session));
  return Object.freeze({
    ...writes,
    async obligate(input: Obligation): Promise<WriteResult> {
      const r = record(input, ["id", "operation", "description", "deadline", "succession", "reviewAuthority"]);
      const id = identifier(r.id), succession = identifier(r.succession), reviewAuthority = identifier(r.reviewAuthority);
      const text = description(r.description), deadline = time(r.deadline);
      const state = currentState(store, config);
      // `operation` names the intent: its raw id, or (format 2, A-37.2) the operation id run() derived it from.
      const named = identifier(r.operation);
      const operation = state.intentDeclarations.has(named) || state.format !== "irontrellis-event/2" ? named : derivedId("intent", session.agentId, named);
      const intent = state.intentDeclarations.get(operation)?.data, admission = state.intentAdmissions.get(operation), consumption = state.intentConsumptions.get(operation);
      const receipts = [...state.receiptCommitments.values()].filter((receipt) => receipt.intentId === operation);
      requireCondition(intent !== undefined && admission !== undefined && consumption !== undefined && receipts.length === 1 && intent.termsCommitment !== undefined &&
        admission.runtimeSessionId === sessionId, "RECEIPT_UNAVAILABLE");
      const obligation: ObligationRecord = {
        obligationId: id, sourceIntentId: operation, causalReceiptContentHash: receipts[0]!.receiptContentHash, durableRoleId: intent.roleId, creationRoleTenureId: intent.roleTenureId,
        description: text, trigger: consumption.eventId, deadline, status: "OPEN", beneficiaryId: config.owner, termsCommitment: intent.termsCommitment,
        performanceAssigneeId: session.agentId, successionRuleId: succession,
        ...(intent.counterpartyId === undefined ? {} : { counterpartyId: intent.counterpartyId }),
        transitionPolicies: [{ fromStatus: "OPEN", toStatus: "OUTCOME_UNKNOWN", action: "record-collection-disposition", acceptedAttesterIds: [intent.adapterProfile.profileId], requiredAuthorityIds: [reviewAuthority] }],
      };
      return signed(`obligation:${id}:create`, "OBLIGATION_CREATED", { record: obligation, actorId: session.agentId });
    },
    async assign(input: Assignment): Promise<WriteResult> {
      const r = record(input, ["id", "obligation"]), id = identifier(r.id), obligation = identifier(r.obligation);
      const duty = currentState(store, config).obligations.get(obligation);
      requireCondition(duty !== undefined, "TRANSITION_REJECTED");
      // The original assignee is part of the creation record. A repeat checks the original transition rather than using the newly changed assignee.
      return signed(`assignment:${id}`, "OBLIGATION_PERFORMANCE_ASSIGNED", {
        obligationId: obligation, fromAgentId: duty.record.performanceAssigneeId, toAgentId: session.agentId, successionRuleId: duty.record.successionRuleId, actorId: session.agentId,
      });
    },
  });
}
export type LocalRuntime = ReturnType<typeof openLocalRuntime>;
