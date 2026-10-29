/**
 * `openLocalDutyPolicy` (SPEC §13.4, LEFT-OUT-SWEEP B12; port of Core 0.3 `duties.ts:56-174` and the dual-signature
 * writer `history-store/duty-writer.ts`): host-owned policy selection for one existing investigation duty and the two
 * signatures of a disposition or contest — the attester's finding first, the outer assignee's administrative signature
 * second — with the fresh-eligibility contract of §13.4 (`validateDutyFreshEligibility`, `duty-disposition.ts:106-119`)
 * re-run after each signature returns and again under the writer lock, at a fresh time ≥ the signed time with the head
 * unchanged; the signed challenges are never altered. No agent tool, dispatch or external effect.
 *
 * `describe` → `activate` → `prepareDisposition` / `dispose` → `prepareContest` / `contest` → `inspect`. Idempotent
 * re-record: an identical repeat (same id, same captured request) returns `alreadyRecorded: true` with the current view
 * and signs nothing; a different request under the same id is `OPERATION_CONFLICT`. Capacity: a finding beyond the
 * duty's quota is refused by eligibility (`TRANSITION_REJECTED`) before capacity; a history inside the control-event
 * reserve refuses with `CAPACITY_RESERVED` before any signer runs.
 */
import { canonicalEncode } from "./canonical.ts";
import { assertCapacityTransition } from "./capacity.ts";
import {
  attachAdministrativeSignatureState, attachDutyFinding, prepareAdministrativeEventState, prepareDutyFinding,
  type DutyFindingAdministrativeInput, type PreparedDutyFinding,
} from "./administration.ts";
import { ACTIVATE_DUTY_POLICY_ACTION, buildDutyPolicyDescriptor, inspectDutyPolicyState, validateDutyFreshEligibility, type DutyDocumentDigest, type DutyOperation, type DutyPolicyDescriptor, type DutyPolicyView, type DutyTransitionType } from "./duty-policy.ts";
import { hashCanonical } from "./hash.ts";
import { IronTrellisError, contentHash, identifier, record, requireCondition } from "./input.ts";
import { assertWritable, attested, configuration, currentState, openStore, translate, witnessAfterWrite, witnessBeforeWrite, type Config, type WriteResult } from "./owner.ts";
import { administrativeEffect, producerFailure, type LocalRuntimeOptions } from "./runtime.ts";
import { sessionOf, signedTransition } from "./runtime-writes.ts";
import { assertFresh, guardedSigner, snapshotOf, unchangedSince, type SignHash } from "./execution.ts";
import type { HistoryStore } from "./store.ts";
import type { CanonicalEvent, ContentHash, HistoryHead, ReplayState } from "./types.ts";

export type DutyPolicySelection = Readonly<{ duty: string; incidentSourceDigest: DutyDocumentDigest; attesterRole: string }>;
export type DutyPolicyActivation = Readonly<{ id: string; descriptor: DutyPolicyDescriptor; activationAuthority: string }>;
export type DutyCriterion = "SOURCE_REVIEWED" | "HISTORY_REVIEWED" | "FINDING_RECORDED" | "CONTROL_REVIEWED";
export type DutyChecklist = Readonly<Record<DutyCriterion, Readonly<{ state: "SATISFIED" | "UNAVAILABLE" | "UNRESOLVED"; reason: string }>>>;
export type DutyDisposition = Readonly<{
  id: string; duty: string; disposition: "COMPLETED_UNDER_POLICY" | "ESCALATED"; checklist: DutyChecklist; reportDigest: DutyDocumentDigest; nextStep: string | null;
  attestationAuthority: string; dispositionAuthority: string;
}>;
export type DutyContest = Readonly<{ id: string; duty: string; targetDispositionId: string; reason: string; reportDigest: DutyDocumentDigest; attestationAuthority: string; dispositionAuthority: string }>;
/** Trusted host configuration for the attester's signature (never an agent-supplied operation argument); defaults to the outer session. */
export type DutyFindingSigner = Readonly<{ session: string; signHash: SignHash }>;
export type LocalDutyPolicyOptions = LocalRuntimeOptions & Readonly<{ attester?: DutyFindingSigner }>;
export type DutyDescription = Readonly<{ descriptor: DutyPolicyDescriptor; descriptorHash: ContentHash; activationAction: "ACTIVATE_DUTY_POLICY"; activationResource: string; head: HistoryHead; grantsAuthority: false }>;
export type DutyWriteResult = WriteResult & Readonly<{ alreadyRecorded: boolean; view: DutyPolicyView | null }>;
export type DutyInspection = Readonly<{ scope: "CAPTURED_HISTORY_ONLY"; executionCapability: false; head: HistoryHead; policy: DutyPolicyView | null }>;
export type PreparedDutyOperation = PreparedDutyFinding & Readonly<{ head: HistoryHead; executionCapability: false }>;
export type { DutyPolicyDescriptor, DutyPolicyView };

type Rec = Readonly<Record<string, unknown>>;
type FindingRequest = Readonly<{ id: string; type: DutyTransitionType; data: Readonly<{ dutyId: string; actorId: string; attesterId: string; attesterRuntimeSessionId: string; attestationAuthorityId: string; dispositionAuthorityId: string; operation: DutyOperation }> }>;

const digestOf = (value: unknown): DutyDocumentDigest => {
  const r = record(value, ["algorithm", "value"]);
  requireCondition(r.algorithm === "sha256");
  return Object.freeze({ algorithm: "sha256", value: contentHash(r.value) });
};
const freshInteger = (value: number): boolean => Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0);
/** The capacity verdict on the transition before any signer runs (`duty-writer.ts:30`: CAPACITY_RESERVED before the first callback). */
const assertRoom = (state: ReplayState, probe: CanonicalEvent): void => {
  try { assertCapacityTransition(state, [probe]); } catch (error) { translate(error, "TRANSITION_REJECTED"); }
};

/**
 * `duty-writer.ts commitHistoryDutyFinding`: two independently authorized signatures with no lock held across either
 * callback; fresh eligibility after each signature and again under the writer lock immediately before the append.
 */
async function commitDutyFinding(
  store: HistoryStore, config: Config, sessionId: string, request: FindingRequest, signFinding: SignHash, signTransition: SignHash,
): Promise<WriteResult> {
  assertWritable(store);
  const snapshot = snapshotOf(store, config), state = snapshot.state, head = snapshot.head;
  assertFresh(snapshot);
  const transition = { ...request, timestamp: config.now() };
  requireCondition(freshInteger(transition.timestamp), "CLOCK_INVALID");
  requireCondition(transition.timestamp >= head.canonicalTime, "CLOCK_INVALID");
  const input = { expectedDomain: config.domain, expectedHistoryHead: head, runtimeSessionId: sessionId, transition };
  // `duty-writer.ts:27-30`: both authorities and the complete maximum-signature event shape are checked before either callback; never a placeholder authentication.
  let finding: PreparedDutyFinding;
  try { finding = prepareDutyFinding(state, input); } catch (error) { throw producerFailure(error); }
  assertRoom(state, { id: transition.id, type: transition.type, timestamp: transition.timestamp, data: { dutyId: transition.data.dutyId } });
  let lastTime = transition.timestamp;
  /** `duty-writer.ts:32-38`: the head is unchanged and the clock did not regress; returns the fresh time. */
  const checkRevision = (latest: ReplayState): number => {
    requireCondition(latest.head.hash === head.hash && latest.head.position === head.position, "HISTORY_CONFLICT");
    const fresh = config.now();
    requireCondition(freshInteger(fresh) && fresh >= lastTime, "CLOCK_INVALID");
    lastTime = fresh;
    return fresh;
  };
  const findingSignature = await signFinding(finding.signingHash); // :39
  // :40-41 — the first signature is verified before anything is offered to the second signer.
  let attached: DutyFindingAdministrativeInput;
  try { attached = attachDutyFinding(state, input, findingSignature); } catch (error) { throw producerFailure(error); }
  const afterFinding = unchangedSince(store, config, snapshot), firstTime = checkRevision(afterFinding.state); // :42
  requireCondition(validateDutyFreshEligibility(afterFinding.state, attached.transition, sessionId, firstTime), "TRANSITION_REJECTED"); // :43-44
  let signingHash: ContentHash;
  try { signingHash = prepareAdministrativeEventState(state, attached).signingHash; } catch (error) { throw producerFailure(error); } // :45
  const transitionSignature = await signTransition(signingHash); // :46
  let event: CanonicalEvent;
  try { event = attachAdministrativeSignatureState(state, attached, transitionSignature).event; } catch (error) { throw producerFailure(error); } // :47
  // :48-54 — under the writer lock: head unchanged, fresh time, fresh eligibility for both signers, then the append at exactly that head.
  { const before = witnessBeforeWrite(store); if (before !== undefined) await before; }
  let result: WriteResult;
  try {
    result = store.withExclusiveWriter((writer) => {
      const latest = store.state(), freshTime = checkRevision(latest);
      requireCondition(validateDutyFreshEligibility(latest, attached.transition, sessionId, freshTime), "TRANSITION_REJECTED");
      try { assertCapacityTransition(latest, [event]); } catch (error) { translate(error, "TRANSITION_REJECTED"); }
      return Object.freeze({ eventId: event.id, head: writer.appendAtExpectedHead(event, head) });
    });
  } catch (error) {
    if (error instanceof IronTrellisError) throw error;
    translate(error, "WRITE_UNCONFIRMED");
  }
  await attested(store);
  { const after = witnessAfterWrite(store); if (after !== undefined) { await after; await attested(store); } }
  return result;
}

/** SPEC §13.4: the duty-policy writer over a format-2 history; `options.attester` (or the second argument) signs the finding, `options.signHash` the outer transition. */
export function openLocalDutyPolicy(options: LocalDutyPolicyOptions, findingSigner?: DutyFindingSigner) {
  const { attester: attesterOption, ...runtimeOptions } = options;
  const config = configuration(runtimeOptions), sessionId = identifier(options.session), signer = options.signHash;
  requireCondition(typeof signer === "function");
  const store = openStore(config);
  const session = sessionOf(store, config, sessionId);
  const attester = findingSigner ?? attesterOption;
  requireCondition(attester === undefined || (typeof attester === "object" && attester !== null && typeof attester.signHash === "function"));
  const attesterSessionId = attester === undefined ? sessionId : identifier(attester.session);
  const attesterSession = currentState(store, config).runtimeSessions.get(attesterSessionId);
  requireCondition(attesterSession !== undefined, "RUNTIME_NOT_CURRENT");
  const signFinding = guardedSigner(attester === undefined ? signer : attester.signHash, attesterSession), signOuter = guardedSigner(signer, session);
  const current = (): ReplayState => currentState(store, config);
  const view = (state: ReplayState, dutyId: string): DutyPolicyView | null => inspectDutyPolicyState(state, dutyId);

  /** `duties.ts:73-86`: the captured request of a disposition or contest (the operation payload captured before any signer can yield). */
  const findingRequest = (input: DutyDisposition | DutyContest, contest: boolean): FindingRequest => {
    const value = record(input, contest
      ? ["id", "duty", "targetDispositionId", "reason", "reportDigest", "attestationAuthority", "dispositionAuthority"]
      : ["id", "duty", "disposition", "checklist", "reportDigest", "nextStep", "attestationAuthority", "dispositionAuthority"]);
    const type: DutyTransitionType = contest ? "ATTEMPT_DUTY_CONTEST_RECORDED" : "ATTEMPT_DUTY_DISPOSITION_RECORDED";
    const id = `${contest ? "duty-contest" : "duty-disposition"}:${identifier(value.id)}`;
    const operation = (contest
      ? { targetDispositionEventId: identifier(value.targetDispositionId), reason: value.reason, reportDigest: digestOf(value.reportDigest) }
      : { disposition: value.disposition, checklist: value.checklist, reportDigest: digestOf(value.reportDigest), nextStep: value.nextStep }) as unknown as DutyOperation;
    return Object.freeze({ id, type, data: Object.freeze({
      dutyId: identifier(value.duty), actorId: session.agentId, attesterId: attesterSession.agentId, attesterRuntimeSessionId: attesterSessionId,
      attestationAuthorityId: identifier(value.attestationAuthority), dispositionAuthorityId: identifier(value.dispositionAuthority), operation,
    }) });
  };
  /** The recorded request a finding event implies (`duties.ts:101-108`), for the idempotent repeat. */
  const recordedRequest = (existing: CanonicalEvent): Rec => {
    const data = existing.data, challenge = (data.finding as Rec | undefined)?.challenge as Rec | undefined;
    return {
      dutyId: data.dutyId, actorId: data.actorId, attesterId: challenge?.attesterId, attesterRuntimeSessionId: challenge?.runtimeSessionId,
      attestationAuthorityId: challenge?.attestationAuthorityId, dispositionAuthorityId: data.dispositionAuthorityId, operation: challenge?.operation,
    };
  };
  const existingEvent = (state: ReplayState, id: string): CanonicalEvent | undefined => {
    const position = state.eventPositionsById.get(id);
    return position === undefined ? undefined : state.events[position];
  };
  /** `duties.ts:87-96`: the finding challenge and signing hash at the current head, both authorities and the capacity checked, nothing signed. */
  const prepareFinding = (input: DutyDisposition | DutyContest, contest: boolean): PreparedDutyOperation => {
    const request = findingRequest(input, contest), state = current(), head = state.head;
    const transition = { ...request, timestamp: config.now() };
    let prepared: PreparedDutyFinding;
    try { prepared = prepareDutyFinding(state, { expectedDomain: config.domain, expectedHistoryHead: head, runtimeSessionId: sessionId, transition }); } catch (error) { throw producerFailure(error); }
    assertRoom(state, { id: transition.id, type: transition.type, timestamp: transition.timestamp, data: { dutyId: transition.data.dutyId } });
    return Object.freeze({ ...prepared, head, executionCapability: false as const });
  };
  /** `duties.ts:97-120`: record the finding, or recognise its exact earlier recording by id. */
  const recordFinding = async (input: DutyDisposition | DutyContest, contest: boolean): Promise<DutyWriteResult> => {
    const request = findingRequest(input, contest), state = current();
    const existing = existingEvent(state, request.id);
    if (existing !== undefined) {
      requireCondition(existing.type === request.type && canonicalEncode(recordedRequest(existing)) === canonicalEncode(request.data), "OPERATION_CONFLICT");
      return Object.freeze({ eventId: existing.id, head: state.head, alreadyRecorded: true, view: view(state, request.data.dutyId) });
    }
    const result = await commitDutyFinding(store, config, sessionId, request, signFinding, signOuter);
    return Object.freeze({ ...result, alreadyRecorded: false, view: view(current(), request.data.dutyId) });
  };

  return Object.freeze({
    prepareDisposition: (input: DutyDisposition) => prepareFinding(input, false),
    prepareContest: (input: DutyContest) => prepareFinding(input, true),
    dispose: (input: DutyDisposition) => recordFinding(input, false),
    contest: (input: DutyContest) => recordFinding(input, true),
    /** `duties.ts:126-140`: the descriptor of a selection; confers no authority (the activation grant names `activationResource`). */
    describe(input: DutyPolicySelection): DutyDescription {
      const value = record(input, ["duty", "incidentSourceDigest", "attesterRole"]);
      const state = current(), digest = digestOf(value.incidentSourceDigest);
      let descriptor: DutyPolicyDescriptor;
      try {
        descriptor = buildDutyPolicyDescriptor(state, { dutyId: identifier(value.duty), acceptedAttesterRoleId: identifier(value.attesterRole), incidentSourceDigest: digest });
      } catch (error) {
        throw new IronTrellisError("TRANSITION_REJECTED", false, error instanceof Error ? error.message : "duty policy selection refused");
      }
      const descriptorHash = hashCanonical(descriptor, state.hashAlgorithm);
      return Object.freeze({ descriptor, descriptorHash, activationAction: ACTIVATE_DUTY_POLICY_ACTION, activationResource: `duty-policy:${descriptorHash}`, head: state.head, grantsAuthority: false as const });
    },
    /** `duties.ts:141-164`: the activation (one signature, the ordinary administrative route) or its exact earlier recording. */
    async activate(input: DutyPolicyActivation): Promise<DutyWriteResult> {
      const value = record(input, ["id", "descriptor", "activationAuthority"]);
      const eventId = `duty-policy:${identifier(value.id)}`;
      const state = current();
      // `record()` captured and froze the whole data tree before the signer can yield.
      const descriptor = value.descriptor as DutyPolicyDescriptor;
      requireCondition(descriptor !== null && typeof descriptor === "object" && typeof descriptor.dutyId === "string");
      const data = { actorId: session.agentId, descriptor, descriptorHash: hashCanonical(descriptor, state.hashAlgorithm), activationAuthorityId: identifier(value.activationAuthority) };
      const existing = existingEvent(state, eventId);
      if (existing !== undefined) {
        requireCondition(existing.type === "ATTEMPT_DUTY_POLICY_ACTIVATED" && canonicalEncode(administrativeEffect(existing)) === canonicalEncode(data), "OPERATION_CONFLICT");
        return Object.freeze({ eventId, head: state.head, alreadyRecorded: true, view: view(state, descriptor.dutyId) });
      }
      const result = await signedTransition(store, config, sessionId, signOuter, eventId, "ATTEMPT_DUTY_POLICY_ACTIVATED", data);
      return Object.freeze({ ...result, alreadyRecorded: false, view: view(current(), descriptor.dutyId) });
    },
    /** `duties.ts:165-172`: the view of an existing duty (`policy: null` before an activation); an unknown duty is TRANSITION_REJECTED. */
    inspect(duty: string): DutyInspection {
      const state = current(), dutyId = identifier(duty);
      requireCondition(state.attemptDuties.has(dutyId), "TRANSITION_REJECTED");
      return Object.freeze({ scope: "CAPTURED_HISTORY_ONLY" as const, executionCapability: false as const, head: state.head, policy: view(state, dutyId) });
    },
  });
}
export type LocalDutyPolicy = ReturnType<typeof openLocalDutyPolicy>;
