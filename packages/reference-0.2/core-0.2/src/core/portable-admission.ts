import {
  captureBoundedCanonicalEventData,
  captureBoundedCanonicalValue,
  getCanonicalCaptureLimitErrorMetadata,
  type ContentHash,
} from "./canonical.ts";
import type { AcceptedCanonicalEventShape } from "./event-schema.ts";
import {
  PORTABLE_INTENT_ADMISSION_VERSION,
  capturePortableAuthorityOperation,
  capturedPortableIntentAdmissionInputIsStructurallyValid,
  createPortableRuntimeAuthorizationChallenge,
  evaluateCapturedPortableIntentAdmissionState,
  hashPortableRuntimeAuthorizationChallenge,
  portableAdmissionOutputLimit,
  portableReplayAuthorizationIndeterminate,
  type PortableActionRequest,
  type PortableAuthorizationProof,
  type PortableConsequentialBinding,
  type PortableReplayAuthorizationDeny,
  type PortableReplayAuthorizationIndeterminate,
} from "./portable-authority-engine.ts";
import {
  PORTABLE_REPLAY_VERSION,
  createPortableReplayKernel,
  isPortableReplayState,
  replayPortable,
  type PortableAuthorizationDomain,
  type PortableHistoryHead,
} from "./portable-replay.ts";
import {
  arrayPush,
  copyArray,
  objectFreeze,
} from "./host-intrinsics.ts";

export { PORTABLE_INTENT_ADMISSION_VERSION } from
  "./portable-authority-engine.ts";

const Object = objectFreeze({ freeze: objectFreeze });
const MAX_EVENT_DATA_BYTES = 1_048_576;

export type PortableIntentAdmissionInput = Readonly<{
  operationVersion: typeof PORTABLE_INTENT_ADMISSION_VERSION;
  events: readonly AcceptedCanonicalEventShape[];
  expectedHistoryHead: PortableHistoryHead;
  admissionEventId: string;
  domain: PortableAuthorizationDomain;
  policyVersion: string;
  request: PortableActionRequest;
  evaluationTime: number;
  binding: PortableConsequentialBinding;
}>;

export type PortableIntentAdmissionEvent = Readonly<{
  id: string;
  type: "TRANSACTION_INTENT_ADMITTED";
  timestamp: number;
  data: Readonly<{
    intentId: string;
    evaluationTime: number;
    expectedHistoryHead: PortableHistoryHead;
    authorizationProof: PortableAuthorizationProof;
    runtimeAuthorizationHash: ContentHash;
    runtimeSignature: `0x${string}`;
  }>;
}>;

export type PortableIntentAdmissionResult =
  | Readonly<{
      operationVersion: typeof PORTABLE_INTENT_ADMISSION_VERSION;
      status: "PROPOSED";
      authorization: PortableAuthorizationProof;
      expectedHead: PortableHistoryHead;
      admissionEvent: PortableIntentAdmissionEvent;
      prospectiveHead: PortableHistoryHead;
    }>
  | Readonly<{
      operationVersion: typeof PORTABLE_INTENT_ADMISSION_VERSION;
      status: "RETRY";
      intentId: string;
      existingAdmissionEventId: string;
      existingAdmissionHead: PortableHistoryHead;
    }>
  | Readonly<{
      operationVersion: typeof PORTABLE_INTENT_ADMISSION_VERSION;
      status: "DENIED";
      authorization: PortableReplayAuthorizationDeny;
    }>
  | Readonly<{
      operationVersion: typeof PORTABLE_INTENT_ADMISSION_VERSION;
      status: "INDETERMINATE";
      authorization: PortableReplayAuthorizationIndeterminate;
    }>
  | Readonly<{
      operationVersion: typeof PORTABLE_INTENT_ADMISSION_VERSION;
      status: "CONFLICT";
      expectedHead: PortableHistoryHead;
      observedHead: PortableHistoryHead;
    }>;

const indeterminateResult = (
  authorization: PortableReplayAuthorizationIndeterminate,
): PortableIntentAdmissionResult => Object.freeze({
  operationVersion: PORTABLE_INTENT_ADMISSION_VERSION,
  status: "INDETERMINATE" as const,
  authorization,
});

const outputLimitResult = (): PortableIntentAdmissionResult =>
  indeterminateResult(portableAdmissionOutputLimit());

const boundedAdmissionResult = (
  result: PortableIntentAdmissionResult,
): PortableIntentAdmissionResult => {
  try {
    return captureBoundedCanonicalValue(result).value as
      PortableIntentAdmissionResult;
  } catch (error) {
    if (getCanonicalCaptureLimitErrorMetadata(error) !== undefined) {
      return outputLimitResult();
    }
    throw error;
  }
};

const wrapStateResult = (
  result: Exclude<
    ReturnType<typeof evaluateCapturedPortableIntentAdmissionState>,
    { status: "AUTHORIZED" }
  >,
): PortableIntentAdmissionResult => {
  switch (result.status) {
    case "RETRY":
      return Object.freeze({
        operationVersion: PORTABLE_INTENT_ADMISSION_VERSION,
        status: "RETRY" as const,
        intentId: result.intentId,
        existingAdmissionEventId: result.existingAdmissionEventId,
        existingAdmissionHead: result.existingAdmissionHead,
      });
    case "DENIED":
      return Object.freeze({
        operationVersion: PORTABLE_INTENT_ADMISSION_VERSION,
        status: "DENIED" as const,
        authorization: result.authorization,
      });
    case "INDETERMINATE":
      return indeterminateResult(result.authorization);
    case "CONFLICT":
      return Object.freeze({
        operationVersion: PORTABLE_INTENT_ADMISSION_VERSION,
        status: "CONFLICT" as const,
        expectedHead: result.expectedHead,
        observedHead: result.observedHead,
      });
  }
};

/**
 * Pure Section 7.4 preparation. It captures and evaluates one operation but
 * owns no durable append capability; therefore success is only PROPOSED.
 */
export const proposePortableIntentAdmission = (
  input: unknown,
): PortableIntentAdmissionResult => {
  const kernel = createPortableReplayKernel();
  const captured = capturePortableAuthorityOperation(
    input,
    "INTENT_ADMISSION",
    kernel.visit,
  );
  if (captured.status !== "CAPTURED") {
    return boundedAdmissionResult(indeterminateResult(
      portableReplayAuthorizationIndeterminate(
        captured.status === "UNSUPPORTED_VERSION"
          ? "UNSUPPORTED_VERSION"
          : captured.status === "STATE_NOT_AUTHORITATIVE"
            ? "STATE_NOT_AUTHORITATIVE"
            : "INVALID_INPUT",
      ),
    ));
  }
  if (
    !capturedPortableIntentAdmissionInputIsStructurallyValid(captured.capture)
  ) {
    return boundedAdmissionResult(indeterminateResult(
      portableReplayAuthorizationIndeterminate("INVALID_INPUT"),
    ));
  }

  const replay = kernel.finish();
  if (replay.status === "REJECTED") {
    const replayCode = replay.result.status === "REJECTED"
      ? replay.result.code
      : undefined;
    return boundedAdmissionResult(indeterminateResult(
      portableReplayAuthorizationIndeterminate(
        replayCode === "UNSUPPORTED_VERSION" ||
            replayCode === "UNSUPPORTED_EVENT_SCHEMA" ||
            replayCode === "UNSUPPORTED_EVENT_TYPE"
          ? "UNSUPPORTED_VERSION"
          : "STATE_NOT_AUTHORITATIVE",
      ),
    ));
  }
  if (!isPortableReplayState(replay.state)) {
    return boundedAdmissionResult(indeterminateResult(
      portableReplayAuthorizationIndeterminate("STATE_NOT_AUTHORITATIVE"),
    ));
  }

  const evaluation = evaluateCapturedPortableIntentAdmissionState(
    captured.capture,
    replay.state,
  );
  if (evaluation.status !== "AUTHORIZED") {
    return boundedAdmissionResult(wrapStateResult(evaluation));
  }

  const challenge = createPortableRuntimeAuthorizationChallenge({
    domain: evaluation.authorization.domain,
    request: evaluation.authorization.request,
    evaluationTime: evaluation.evaluationTime,
    policyVersion: evaluation.authorization.policyVersion,
    historyHead: evaluation.expectedHead,
    binding: evaluation.binding,
  });
  const data = Object.freeze({
    intentId: evaluation.binding.intentId,
    evaluationTime: evaluation.evaluationTime,
    expectedHistoryHead: evaluation.expectedHead,
    authorizationProof: evaluation.authorization,
    runtimeAuthorizationHash:
      hashPortableRuntimeAuthorizationChallenge(challenge),
    runtimeSignature: evaluation.binding.runtimeSignature,
  });
  const uncapturedEvent: PortableIntentAdmissionEvent = Object.freeze({
    id: evaluation.admissionEventId,
    type: "TRANSACTION_INTENT_ADMITTED" as const,
    timestamp: evaluation.evaluationTime,
    data,
  });

  let admissionEvent: PortableIntentAdmissionEvent;
  let prospectiveReplayInput: Readonly<{
    operationVersion: typeof PORTABLE_REPLAY_VERSION;
    events: readonly AcceptedCanonicalEventShape[];
  }>;
  try {
    const capturedData = captureBoundedCanonicalEventData(
      data,
      uncapturedEvent,
      MAX_EVENT_DATA_BYTES,
    ).value as PortableIntentAdmissionEvent["data"];
    admissionEvent = Object.freeze({
      id: uncapturedEvent.id,
      type: uncapturedEvent.type,
      timestamp: uncapturedEvent.timestamp,
      data: capturedData,
    });
    const prospectiveEvents = copyArray(replay.state.events);
    arrayPush(
      prospectiveEvents,
      admissionEvent as unknown as AcceptedCanonicalEventShape,
    );
    prospectiveReplayInput = captureBoundedCanonicalValue(Object.freeze({
      operationVersion: PORTABLE_REPLAY_VERSION,
      events: Object.freeze(prospectiveEvents),
    })).value;
  } catch (error) {
    if (getCanonicalCaptureLimitErrorMetadata(error) !== undefined) {
      return outputLimitResult();
    }
    throw error;
  }

  const prospective = replayPortable(prospectiveReplayInput);
  if (prospective.status !== "ACCEPTED") {
    return boundedAdmissionResult(indeterminateResult(
      portableReplayAuthorizationIndeterminate(
        "STATE_NOT_AUTHORITATIVE",
        "REPLAY_VERIFIED",
      ),
    ));
  }

  return boundedAdmissionResult(Object.freeze({
    operationVersion: PORTABLE_INTENT_ADMISSION_VERSION,
    status: "PROPOSED" as const,
    authorization: evaluation.authorization,
    expectedHead: evaluation.expectedHead,
    admissionEvent,
    prospectiveHead: prospective.head,
  }));
};
