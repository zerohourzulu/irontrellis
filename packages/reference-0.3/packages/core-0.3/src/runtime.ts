import { commitHistoryAdministration } from "./history-store/index.ts";
import { openConfiguredEventStore, ConfiguredDirectoryEventStore } from "./configured-store.ts";
import * as core from "../../core-0.2/src/core/index.ts";
import { ManagedLocalEventStore as PortableFileEventStore } from "./capacity.ts";
import {
  prepareAdministrativeEvent,
  produceAdministrativeEvent,
} from "../../core-0.2/src/administration/index.ts";
import {
  ContinuityError,
  identifier,
  record,
  requireCondition,
  time,
} from "./input.ts";
import { configuration, read, append, stateOf } from "./local-store.ts";
import type { LocalOwnerOptions, WriteResult } from "./local-owner.ts";
import type { SignHash } from "./simulation.ts";
export type LocalRuntimeOptions = LocalOwnerOptions &
  Readonly<{ session: string; signHash: SignHash }>;
export type Obligation = Readonly<{
  id: string;
  operation: string;
  description: string;
  deadline: number;
  succession: string;
  reviewAuthority: string;
}>;
export type Assignment = Readonly<{ id: string; obligation: string }>;

/** Signed duty operations; no root grants, role changes or external effects. */
export function openLocalRuntime(options: LocalRuntimeOptions) {
  const config = configuration(options),
    sessionId = identifier(options.session),
    signer = options.signHash;
  requireCondition(typeof signer === "function");
  const store = openConfiguredEventStore(config);
  const session = stateOf(read(store, config)).runtimeSessions.get(sessionId);
  requireCondition(
    session && session.controllerId === config.controller,
    "RUNTIME_NOT_CURRENT",
  );
  const signed = async (
    id: string,
    type: "OBLIGATION_CREATED" | "OBLIGATION_PERFORMANCE_ASSIGNED",
    data: object,
    events: readonly core.PortableCanonicalEvent[],
  ): Promise<WriteResult> => {
    const existing = events.find((e) => e.id === id);
    if (existing) {
      const { administrativeAuthorization: _signature, ...effect } =
        existing.data as Record<string, unknown>;
      requireCondition(
        existing.type === type &&
          core.canonicalEncode(effect) === core.canonicalEncode(data),
        "OPERATION_CONFLICT",
      );
      return Object.freeze({
        eventId: existing.id,
        head: stateOf(events).head,
      });
    }
    if (store instanceof ConfiguredDirectoryEventStore) {
      const committed = await commitHistoryAdministration(store.directoryStore, {
        expectedDomain: config.domain, runtimeSessionId: sessionId,
        transition: {id, type, timestamp: config.now(), data},
      }, {signHash: signer, now: config.now});
      return Object.freeze({eventId: id, head: committed.history.head});
    }
    requireCondition(events.length < 128, "HISTORY_LIMIT");
    const head = stateOf(events).head;
    const transition = { id, type, timestamp: config.now(), data };
    requireCondition(
      transition.timestamp >= head.canonicalTime,
      "CLOCK_INVALID",
    );
    const input = {
      events,
      expectedDomain: config.domain,
      expectedHistoryHead: head,
      transition,
      runtimeSessionId: sessionId,
    };
    const result = await produceAdministrativeEvent(input, {
      signHash: async (hash: core.ContentHash) => {
        try {
          return await signer(hash);
        } catch {
          throw new ContinuityError("SIGNER_FAILED");
        }
      },
    });
    const latest = read(store, config);
    requireCondition(
      stateOf(latest).head.hash === head.hash,
      "HISTORY_CONFLICT",
    );
    // Recheck session and policy at the post-signing host time. This does not
    // change the signed event or create authority from a historical receipt.
    const now = config.now();
    requireCondition(now >= transition.timestamp, "CLOCK_INVALID");
    prepareAdministrativeEvent({
      ...input,
      transition: { ...transition, timestamp: now },
    });
    return append(store, config, result.event, events);
  };
  return Object.freeze({
    async obligate(input: Obligation): Promise<WriteResult> {
      const r = record(input, [
        "id",
        "operation",
        "description",
        "deadline",
        "succession",
        "reviewAuthority",
      ]);
      const id = identifier(r.id),
        operation = identifier(r.operation),
        succession = identifier(r.succession),
        reviewAuthority = identifier(r.reviewAuthority);
      requireCondition(
        typeof r.description === "string" &&
          r.description.length > 0 &&
          r.description.length <= 1024 &&
          !/[\u0000-\u001f\u007f]/.test(r.description),
      );
      const deadline = time(r.deadline),
        events = read(store, config),
        state = stateOf(events);
      const intent = state.intentDeclarations.get(operation)?.data,
        admission = state.intentAdmissions.get(operation),
        consumption = state.intentConsumptions.get(operation);
      const receipts = [...state.receiptCommitments.values()].filter(
        (receipt) => receipt.intentId === operation,
      );
      requireCondition(
        intent &&
          admission &&
          consumption &&
          receipts.length === 1 &&
          intent.termsCommitment &&
          admission.runtimeSessionId === sessionId,
        "RECEIPT_UNAVAILABLE",
      );
      const receipt = receipts[0]!;
      const obligation: core.PortableObligationRecord = {
        obligationId: id,
        sourceIntentId: operation,
        causalReceiptContentHash: receipt.receiptContentHash,
        durableRoleId: intent.roleId,
        creationRoleTenureId: intent.roleTenureId,
        description: r.description,
        trigger: consumption.eventId,
        deadline,
        status: "OPEN",
        beneficiaryId: config.owner,
        termsCommitment: intent.termsCommitment,
        performanceAssigneeId: session.agentId,
        successionRuleId: succession,
        ...(Object.hasOwn(intent, "counterpartyId")
          ? { counterpartyId: intent.counterpartyId! }
          : {}),
        transitionPolicies: [
          {
            fromStatus: "OPEN",
            toStatus: "OUTCOME_UNKNOWN",
            action: "record-collection-disposition",
            acceptedAttesterIds: [intent.adapterProfile.profileId],
            requiredAuthorityIds: [reviewAuthority],
          },
        ],
      };
      return signed(
        `obligation:${id}:create`,
        "OBLIGATION_CREATED",
        { record: obligation, actorId: session.agentId },
        events,
      );
    },
    async assign(input: Assignment): Promise<WriteResult> {
      const r = record(input, ["id", "obligation"]),
        id = identifier(r.id),
        obligation = identifier(r.obligation);
      const events = read(store, config),
        state = stateOf(events),
        duty = state.obligations.get(obligation);
      requireCondition(duty, "TRANSITION_REJECTED");
      // The original assignee is part of the creation record. A repeat checks
      // the original transition rather than using the newly changed assignee.
      return signed(
        `assignment:${id}`,
        "OBLIGATION_PERFORMANCE_ASSIGNED",
        {
          obligationId: obligation,
          fromAgentId: duty.record.performanceAssigneeId,
          toAgentId: session.agentId,
          successionRuleId: duty.record.successionRuleId,
          actorId: session.agentId,
        },
        events,
      );
    },
  });
}
export type LocalRuntime = ReturnType<typeof openLocalRuntime>;
