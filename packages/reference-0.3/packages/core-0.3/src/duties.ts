/** Host-owned policy selection for one existing investigation duty. No agent tool or dispatch. */
import * as core from "../../core-0.2/src/core/index.ts";
import {
  buildPortableDutyPolicyDescriptor, inspectPortableDutyPolicy,
  type PortableDutyPolicyDescriptor,
} from "../../core-0.2/src/core/duty-policy.ts";
import { prepareHistoryDutyFinding } from "../../core-0.2/src/administration/index.ts";
import { commitHistoryDutyFinding } from "./history-store/duty-writer.ts";
import { hasAdministrativeRoom } from "./history-store/capacity.ts";
import { historyDataFields } from "../../core-0.2/src/history/index.ts";
import { verifiedHistorySnapshot } from "../../core-0.2/src/history/index.ts";
import { openConfiguredEventStore, ConfiguredDirectoryEventStore } from "./configured-store.ts";
import { commitHistoryAdministration } from "./history-store/index.ts";
import { configuration, read, stateOf } from "./local-store.ts";
import { identifier, record, requireCondition } from "./input.ts";
import type { LocalRuntimeOptions } from "./runtime.ts";

export type DutyPolicySelection = Readonly<{
  duty: string;
  incidentSourceDigest: Readonly<{ algorithm: "sha256"; value: core.ContentHash }>;
  attesterRole: string;
}>;
export type DutyPolicyActivation = Readonly<{
  id: string;
  descriptor: PortableDutyPolicyDescriptor;
  activationAuthority: string;
}>;
export type DutyCriterion = "SOURCE_REVIEWED" | "HISTORY_REVIEWED" | "FINDING_RECORDED" | "CONTROL_REVIEWED";
export type DutyChecklist = Readonly<Record<DutyCriterion, Readonly<{
  state: "SATISFIED" | "UNAVAILABLE" | "UNRESOLVED"; reason: string;
}>>>;
export type DutyDisposition = Readonly<{
  id: string; duty: string; disposition: "COMPLETED_UNDER_POLICY" | "ESCALATED";
  checklist: DutyChecklist; reportDigest: Readonly<{ algorithm: "sha256"; value: core.ContentHash }>;
  nextStep: string | null; attestationAuthority: string; dispositionAuthority: string;
}>;
export type DutyContest = Readonly<{
  id: string; duty: string; targetDispositionId: string; reason: string;
  reportDigest: Readonly<{ algorithm: "sha256"; value: core.ContentHash }>;
  attestationAuthority: string; dispositionAuthority: string;
}>;
/** Trusted host configuration, never an agent-supplied operation argument. */
export type DutyFindingSigner = Readonly<Pick<LocalRuntimeOptions, "session" | "signHash">>;
export type { PortableDutyPolicyDescriptor };

/** Historical inspection only. The supplied handle must come from complete verified replay. */
export function inspectContinuationDutyPolicy(history: unknown, duty: string) {
  const { state } = verifiedHistorySnapshot(history);
  const dutyId = identifier(duty);
  requireCondition(state.attemptDuties.has(dutyId), "TRANSITION_REJECTED");
  return core.immutableProtocolValue({ scope: "CAPTURED_HISTORY_ONLY" as const,
    executionCapability: false as const, head: state.head,
    policy: inspectPortableDutyPolicy(state, dutyId) ?? null });
}

export function openLocalDutyPolicy(options: LocalRuntimeOptions, findingSigner?: DutyFindingSigner) {
  const config = configuration(options), sessionId = identifier(options.session), signer = options.signHash;
  requireCondition(typeof signer === "function");
  const store = openConfiguredEventStore(config);
  // This writer must use the durable instance/generation/head conditional append.
  requireCondition(store instanceof ConfiguredDirectoryEventStore, "PROFILE_MISMATCH");
  const directoryStore = store.directoryStore;
  const initial = stateOf(read(store, config)), session = initial.runtimeSessions.get(sessionId);
  requireCondition(session && session.controllerId === config.controller, "RUNTIME_NOT_CURRENT");
  const findingConfig = findingSigner === undefined
    ? { session: sessionId, signHash: signer }
    : historyDataFields(findingSigner, ["session", "signHash"]);
  const attesterSessionId = identifier(findingConfig.session), signFinding = findingConfig.signHash;
  requireCondition(typeof signFinding === "function");
  const findingCallback = signFinding as LocalRuntimeOptions["signHash"];
  const attesterSession = initial.runtimeSessions.get(attesterSessionId);
  requireCondition(attesterSession, "RUNTIME_NOT_CURRENT");
  function findingRequest(input: DutyDisposition | DutyContest, contest: boolean) {
    const value = record(input, contest
      ? ["id", "duty", "targetDispositionId", "reason", "reportDigest", "attestationAuthority", "dispositionAuthority"]
      : ["id", "duty", "disposition", "checklist", "reportDigest", "nextStep", "attestationAuthority", "dispositionAuthority"]);
    const type = contest ? "ATTEMPT_DUTY_CONTEST_RECORDED" as const : "ATTEMPT_DUTY_DISPOSITION_RECORDED" as const;
    const id = `${contest ? "duty-contest" : "duty-disposition"}:${identifier(value.id)}`;
    const operation = contest
      ? { targetDispositionEventId: identifier(value.targetDispositionId), reason: value.reason, reportDigest: value.reportDigest }
      : { disposition: value.disposition, checklist: value.checklist, reportDigest: value.reportDigest, nextStep: value.nextStep };
    return { id, type, data: { dutyId: identifier(value.duty), actorId: session!.agentId,
      attesterId: attesterSession!.agentId, attesterRuntimeSessionId: attesterSessionId,
      attestationAuthorityId: identifier(value.attestationAuthority),
      dispositionAuthorityId: identifier(value.dispositionAuthority), operation } };
  }
  function prepareFinding(input: DutyDisposition | DutyContest, contest: boolean) {
    const request = findingRequest(input, contest);
    read(store, config); // Validate the configured domain/host binding for this operation.
    const current = directoryStore.snapshot();
    const transition = { ...request, timestamp: config.now() };
    const prepared = prepareHistoryDutyFinding(current.history, { expectedDomain: config.domain,
      expectedHistoryHead: current.history.head, runtimeSessionId: sessionId, transition });
    requireCondition(hasAdministrativeRoom(current.history, transition, current.manifest.segments.length), "CAPACITY_RESERVED");
    return core.immutableProtocolValue({ ...prepared, head: current.history.head, executionCapability: false as const });
  }
  async function recordFinding(input: DutyDisposition | DutyContest, contest: boolean) {
    const request = findingRequest(input, contest);
    const events = read(store, config), state = stateOf(events);
    const existing = events.find(event => event.id === request.id);
    if (existing) {
      const data = existing.data as any, challenge = data.finding?.challenge;
      const original = { dutyId: data.dutyId, actorId: data.actorId,
        attesterId: challenge?.attesterId, attesterRuntimeSessionId: challenge?.runtimeSessionId,
        attestationAuthorityId: challenge?.attestationAuthorityId,
        dispositionAuthorityId: data.dispositionAuthorityId, operation: challenge?.operation };
      requireCondition(existing.type === request.type &&
        core.canonicalEncode(original) === core.canonicalEncode(request.data), "OPERATION_CONFLICT");
      return core.immutableProtocolValue({ eventId: existing.id, head: state.head, alreadyRecorded: true,
        view: inspectPortableDutyPolicy(state, request.data.dutyId) });
    }
    const result = await commitHistoryDutyFinding(directoryStore, { expectedDomain: config.domain,
      runtimeSessionId: sessionId, transition: { ...request, timestamp: config.now() } }, {
      signFinding: hash => Promise.resolve(findingCallback(hash)),
      signTransition: hash => Promise.resolve(signer(hash)), now: config.now,
    });
    const current = verifiedHistorySnapshot(result.history).state;
    return core.immutableProtocolValue({ eventId: request.id, head: current.head, alreadyRecorded: false,
      view: inspectPortableDutyPolicy(current, request.data.dutyId) });
  }
  return Object.freeze({
    prepareDisposition: (input: DutyDisposition) => prepareFinding(input, false),
    prepareContest: (input: DutyContest) => prepareFinding(input, true),
    dispose: (input: DutyDisposition) => recordFinding(input, false),
    contest: (input: DutyContest) => recordFinding(input, true),
    describe(input: DutyPolicySelection) {
      const value = record(input, ["duty", "incidentSourceDigest", "attesterRole"]);
      const state = stateOf(read(store, config));
      const digest = record(value.incidentSourceDigest, ["algorithm", "value"]);
      requireCondition(digest.algorithm === "sha256" && typeof digest.value === "string" && /^0x[0-9a-f]{64}$/.test(digest.value));
      const descriptor = buildPortableDutyPolicyDescriptor(state, {
        dutyId: identifier(value.duty), acceptedAttesterRoleId: identifier(value.attesterRole),
        incidentSourceDigest: { algorithm: "sha256", value: digest.value as core.ContentHash },
      });
      const descriptorHash = core.hashCanonical(descriptor);
      return core.immutableProtocolValue({ descriptor, descriptorHash,
        activationAction: "ACTIVATE_DUTY_POLICY" as const,
        activationResource: `duty-policy:${descriptorHash}`, head: state.head,
        grantsAuthority: false as const });
    },
    async activate(input: DutyPolicyActivation) {
      const value = record(input, ["id", "descriptor", "activationAuthority"]);
      const eventId = `duty-policy:${identifier(value.id)}`;
      // record() captures and freezes the entire data tree before the signer can yield.
      const descriptor = value.descriptor as PortableDutyPolicyDescriptor;
      const data = { actorId: session.agentId, descriptor, descriptorHash: core.hashCanonical(descriptor),
        activationAuthorityId: identifier(value.activationAuthority) };
      const events = read(store, config), state = stateOf(events);
      const existing = events.find(event => event.id === eventId);
      if (existing) {
        const { administrativeAuthorization: _signature, ...effect } = existing.data as Record<string, unknown>;
        requireCondition(existing.type === "ATTEMPT_DUTY_POLICY_ACTIVATED" &&
          core.canonicalEncode(effect) === core.canonicalEncode(data), "OPERATION_CONFLICT");
        return core.immutableProtocolValue({ eventId, head: state.head, alreadyRecorded: true,
          view: inspectPortableDutyPolicy(state, descriptor.dutyId) });
      }
      const result = await commitHistoryAdministration(store.directoryStore, {
        expectedDomain: config.domain, runtimeSessionId: sessionId,
        transition: { id: eventId, type: "ATTEMPT_DUTY_POLICY_ACTIVATED", timestamp: config.now(), data },
      }, { signHash: signer, now: config.now });
      const current = verifiedHistorySnapshot(result.history).state;
      return core.immutableProtocolValue({ eventId, head: current.head, alreadyRecorded: false,
        view: inspectPortableDutyPolicy(current, descriptor.dutyId) });
    },
    inspect(duty: string) {
      // Also validates the configured domain and host-owner binding on every read.
      const state = stateOf(read(store, config)), dutyId = identifier(duty);
      requireCondition(state.attemptDuties.has(dutyId), "TRANSITION_REJECTED");
      return core.immutableProtocolValue({ scope: "CAPTURED_HISTORY_ONLY" as const,
        executionCapability: false as const, head: state.head,
        policy: inspectPortableDutyPolicy(state, dutyId) ?? null });
    },
  });
}
export type LocalDutyPolicy = ReturnType<typeof openLocalDutyPolicy>;
