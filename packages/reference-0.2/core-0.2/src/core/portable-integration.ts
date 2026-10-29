/** Reference integration facts; these do not attest durability or issue authority. */
import {
  canonicalEncode,
  captureBoundedCanonicalReplayBodyIncrementally,
  immutableProtocolInput,
  immutableProtocolValue,
  isWellFormedUnicode,
} from "./canonical.ts";
import type { AcceptedCanonicalEventShape } from "./event-schema.ts";
import { validateCanonicalEventShape } from "./event-schema.ts";
import type { PortableIntentAdmissionEvent } from "./portable-admission.ts";
import {
  PORTABLE_ADAPTER_SUBMISSION_VERSION,
  type PortableAdapterIdentity,
} from "./portable-adapter-engine.ts";
import {
  PORTABLE_REPLAY_VERSION,
  createPortableReplayKernel,
  portableAdmissionControlIsCurrent,
  type PortableAuthorizationDomain,
  type PortableHistoryHead,
  type PortableIntentConsumptionRecord,
  type PortableIntentOutcomeRecord,
  type PortableReplayState,
} from "./portable-replay.ts";

export type PortableAdapterIdentityInput = Readonly<{
  operationVersion: typeof PORTABLE_ADAPTER_SUBMISSION_VERSION;
  domain: PortableAuthorizationDomain;
  intentId: string;
  admissionEvent: PortableIntentAdmissionEvent;
  admittedHistory: readonly AcceptedCanonicalEventShape[];
}>;

export type PortableAdapterIdentityResult = Readonly<PortableAdapterIdentity & {
  operationVersion: typeof PORTABLE_ADAPTER_SUBMISSION_VERSION;
}>;

export type PortableAdmittedIntentInspection =
  | Readonly<{ status: "ABSENT"; head: PortableHistoryHead }>
  | Readonly<{
      status: "ADMITTED";
      head: PortableHistoryHead;
      admissionEvent: PortableIntentAdmissionEvent;
      admissionHead: PortableHistoryHead;
      adapterIdentity: PortableAdapterIdentity;
      currentControl: boolean;
      consumption?: PortableIntentConsumptionRecord;
      terminal?: PortableIntentOutcomeRecord;
      latestOutcome?: PortableIntentOutcomeRecord;
    }>;

const acceptedState = (events: unknown): PortableReplayState => {
  const source = Object.freeze({ operationVersion: PORTABLE_REPLAY_VERSION, events });
  const kernel = createPortableReplayKernel();
  const capture = captureBoundedCanonicalReplayBodyIncrementally(events, source, kernel.visit);
  if (capture.status !== "CAPTURED") {
    throw new TypeError("Portable history could not be captured.");
  }
  const result = kernel.finish();
  if (result.status !== "ACCEPTED") {
    throw new TypeError("Portable history is not replay-authoritative.");
  }
  return result.state;
};

const identifier = (value: unknown): value is string =>
  typeof value === "string" && value.length > 0 && value.length <= 256 &&
  isWellFormedUnicode(value) && !/[\u0000-\u001f\u007f]/u.test(value) &&
  new TextEncoder().encode(value).byteLength <= 256;

/**
 * Reconstruct one admission and its current consumption-control facts from the
 * supplied history. Only the configured coordinator can establish durability,
 * serialize a fresh observation and mint its separate local invocation token.
 */
export const inspectPortableAdmittedIntent = (
  events: unknown,
  intentId: unknown,
  useTime: unknown,
): PortableAdmittedIntentInspection => {
  if (!identifier(intentId)) throw new TypeError("Invalid portable intent identifier.");
  if (typeof useTime !== "number" || !Number.isSafeInteger(useTime) ||
      useTime < 0 || Object.is(useTime, -0)) {
    throw new TypeError("Invalid authoritative use time.");
  }
  const state = acceptedState(events);
  if (useTime < state.head.canonicalTime) {
    throw new TypeError("Authoritative use time precedes the observed durable head.");
  }
  const admission = state.intentAdmissions.get(intentId);
  if (admission === undefined) return Object.freeze({ status: "ABSENT", head: state.head });
  const admissionEvent = state.events[admission.admissionEventPosition] as
    unknown as PortableIntentAdmissionEvent;
  const consumption = state.intentConsumptions.get(intentId);
  const outcome = state.intentOutcomeStates.get(intentId);
  return immutableProtocolValue({
    status: "ADMITTED" as const,
    head: state.head,
    admissionEvent,
    admissionHead: admission.admissionHead,
    adapterIdentity: admission.adapterIdentity,
    currentControl: portableAdmissionControlIsCurrent(state, intentId, useTime),
    ...(consumption === undefined ? {} : { consumption }),
    ...(outcome?.terminal === undefined ? {} : { terminal: outcome.terminal }),
    ...(outcome === undefined ? {} : { latestOutcome: outcome.latest }),
  });
};

/** Valid-input-only Portable Contract §10.1 derivation; rejects before returning. */
export const derivePortableAdapterIdentity = (input: unknown): PortableAdapterIdentityResult => {
  const captured = immutableProtocolInput(input);
  if (captured === null || typeof captured !== "object" || Array.isArray(captured)) {
    throw new TypeError("Adapter identity input must be a closed record.");
  }
  const value = captured as Record<string, unknown>;
  const required = ["operationVersion", "domain", "intentId", "admissionEvent", "admittedHistory"];
  const keys = Object.keys(value);
  if (keys.length !== required.length || required.some((key) => !Object.hasOwn(value, key)) ||
      value.operationVersion !== PORTABLE_ADAPTER_SUBMISSION_VERSION || !identifier(value.intentId)) {
    throw new TypeError("Unsupported or malformed adapter identity input.");
  }
  const state = acceptedState(value.admittedHistory);
  const admission = state.intentAdmissions.get(value.intentId);
  if (admission === undefined || admission.admissionEventPosition !== state.head.position) {
    throw new TypeError("Adapter identity requires the exact admission-inclusive prefix.");
  }
  const event = state.events[admission.admissionEventPosition] as unknown as PortableIntentAdmissionEvent;
  const suppliedEvent = validateCanonicalEventShape(value.admissionEvent);
  const domain = value.domain;
  const domainKeys = ["protocol", "version", "deploymentId", "chainId", "verifyingContract"];
  if (!suppliedEvent.ok || domain === null || typeof domain !== "object" || Array.isArray(domain) ||
      Object.keys(domain).length !== domainKeys.length || domainKeys.some(key => !Object.hasOwn(domain, key)) ||
      canonicalEncode(suppliedEvent.event) !== canonicalEncode(event) ||
      canonicalEncode(value.domain) !== canonicalEncode(event.data.authorizationProof.domain)) {
    throw new TypeError("Adapter identity does not match the exact admitted event and proof domain.");
  }
  return Object.freeze({
    operationVersion: PORTABLE_ADAPTER_SUBMISSION_VERSION,
    ...admission.adapterIdentity,
  });
};
