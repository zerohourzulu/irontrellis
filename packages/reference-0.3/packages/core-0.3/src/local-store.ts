import { ConfiguredDirectoryEventStore, SEGMENTED_HISTORY_PROFILE } from "./configured-store.ts";
import { randomUUID } from "node:crypto";
import * as core from "../../core-0.2/src/core/index.ts";
import {
  PortableFileEventStore,
  PortableStoreConflictError,
  PortableStoreBusyError,
} from "../../core-0.2/src/indexer/portable-file-event-store.ts";
import {
  createPortableReplayKernel,
  type PortableReplayState,
} from "../../core-0.2/src/core/portable-replay.ts";
import { captureBoundedCanonicalReplayBodyIncrementally } from "../../core-0.2/src/core/canonical.ts";
import {
  ContinuityError,
  identifier,
  record,
  requireCondition,
  time,
} from "./input.ts";
import { captureHistory, observeHistory } from "./observation.ts";
import { assertCapacityTransition } from "./capacity.ts";
import type { LocalOwnerOptions, WriteResult } from "./local-owner.ts";
export const POLICY = "continuity-local-owner/0.3-preview.1";
export function configuration(input: LocalOwnerOptions): Readonly<LocalOwnerOptions> {
  // The clock is a trusted host callback. Capture all data independently; pin
  // its reference once, never interpret a callback received through MCP.
  requireCondition(input !== null && typeof input === "object");
  const clock = input.now;
  requireCondition(typeof clock === "function");
  const data = record(
    {
      ...(input.historyProfile === undefined ? {historyFile: input.historyFile} : {historyBinding: input.historyBinding, historyProfile: input.historyProfile}),
      domain: input.domain,
      owner: input.owner,
      controller: input.controller,
    },
    ["domain", "owner", "controller"], ["historyFile", "historyBinding", "historyProfile"],
  );
  const segmented = data.historyProfile === SEGMENTED_HISTORY_PROFILE;
  requireCondition(segmented ? typeof data.historyBinding === "string" && data.historyFile === undefined && input.historyFile === undefined
    : data.historyProfile === undefined && data.historyBinding === undefined && input.historyBinding === undefined && typeof data.historyFile === "string", "PROFILE_MISMATCH");
  const location = (segmented ? data.historyBinding : data.historyFile) as string;
  requireCondition(location.length > 0 && !location.includes("\0"));
  const domain = record(data.domain, [
    "protocol",
    "version",
    "deploymentId",
    "chainId",
    "verifyingContract",
  ]);
  requireCondition(
    domain.protocol === "continuity" && domain.version === "0.2",
  );
  const selected = {
    protocol: "continuity" as const,
    version: "0.2" as const,
    deploymentId: identifier(domain.deploymentId),
    chainId: identifier(domain.chainId),
    verifyingContract: identifier(domain.verifyingContract),
  };
  const readClock = () => {
    try {
      return time(clock());
    } catch {
      throw new ContinuityError("CLOCK_INVALID");
    }
  };
  return Object.freeze({
    ...(segmented ? {historyBinding: location, historyProfile: SEGMENTED_HISTORY_PROFILE} : {historyFile: location}),
    domain: Object.freeze(selected),
    owner: identifier(data.owner),
    controller: identifier(data.controller),
    now: readClock,
  });
}
export type Config = ReturnType<typeof configuration>;
export function event(
  type: core.PortableCanonicalEvent["type"],
  timestamp: number,
  data: object,
): core.PortableCanonicalEvent {
  return core.immutableProtocolValue({
    id: `event:${randomUUID()}`,
    type,
    timestamp,
    data,
  }) as core.PortableCanonicalEvent;
}
export function read(store: PortableFileEventStore, config: Config) {
  let events: readonly core.PortableCanonicalEvent[];
  try {
    events = store instanceof ConfiguredDirectoryEventStore ? store.readAll() : captureHistory(store.readAll());
  } catch (error) {
    if (error instanceof ContinuityError) throw error;
    throw new ContinuityError("READ_UNAVAILABLE");
  }
  const genesis = events[0]!.data as unknown as {
    domain: core.PortableAuthorizationDomain;
    policyVersion: string;
  };
  requireCondition(
    genesis.policyVersion === POLICY &&
      core.canonicalEncode(genesis.domain) ===
        core.canonicalEncode(config.domain) &&
      events[1]?.type === "PRINCIPAL_CREATED" &&
      (events[1].data as { principalId: string }).principalId === config.owner,
    "PROFILE_MISMATCH",
  );
  return events;
}

export function stateOf(
  events: readonly core.PortableCanonicalEvent[],
): PortableReplayState {
  const kernel = createPortableReplayKernel();
  const captured = captureBoundedCanonicalReplayBodyIncrementally(
    events,
    Object.freeze({ operationVersion: core.PORTABLE_REPLAY_VERSION, events }),
    kernel.visit,
  );
  requireCondition(captured.status === "CAPTURED", "INVALID_HISTORY");
  const result = kernel.finish();
  requireCondition(result.status === "ACCEPTED", "INVALID_HISTORY");
  return result.state;
}
export function append(
  store: PortableFileEventStore,
  config: Config,
  next: core.PortableCanonicalEvent,
  events = read(store, config),
): WriteResult {
  if (!(store instanceof ConfiguredDirectoryEventStore)) assertCapacityTransition(events, [next]);
  const previous = stateOf(events).head;
  requireCondition(next.timestamp >= previous.canonicalTime, "CLOCK_INVALID");
  const checked = core.replayPortable({
    operationVersion: core.PORTABLE_REPLAY_VERSION,
    events: [...events, next],
  });
  requireCondition(checked.status === "ACCEPTED", "TRANSITION_REJECTED");
  try {
    return Object.freeze({
      eventId: next.id,
      head: store.appendAtExpectedHead(next, previous),
    });
  } catch (error) {
    if (error instanceof ContinuityError) throw error;
    if (
      error instanceof PortableStoreConflictError ||
      error instanceof PortableStoreBusyError
    )
      throw new ContinuityError("HISTORY_CONFLICT");
    throw new ContinuityError("WRITE_UNCONFIRMED", true);
  }
}
