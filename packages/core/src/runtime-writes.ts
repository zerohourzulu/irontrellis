/**
 * Step 5d (P2-1): the shared writers of the duty and attempt recorders, `signedTransition` and `sessionOf`. Core-internal: they
 * take an unchecked owner `Config`, so they are on no package subpath (until 5d they were exported from `./runtime`).
 */
import { canonicalEncode } from "./canonical.ts";
import { prepareAdministrativeEventState, produceAdministrativeEventState, type AdministrativeEventType, type ProducedAdministrativeEvent } from "./administration.ts";
import type { HistoryStore } from "./store.ts";
import { requireCondition } from "./input.ts";
import { appendEvent, currentState, type Config, type WriteResult } from "./owner.ts";
import { assertFresh, snapshotOf, unchangedSince, type SignHash } from "./execution.ts";
import { administrativeEffect, producerFailure } from "./runtime.ts";
import type { CanonicalEvent, ContentHash, RuntimeSessionRecord } from "./types.ts";

/**
 * Sign and append one administrative transition, or recognise its exact
 * earlier recording by id. Shared by the duty and attempt recorders. Works on
 * the store's cached state (`produceAdministrativeEventState`): no history
 * snapshot and no replay, whatever the history length.
 */
export async function signedTransition(
  store: HistoryStore, config: Config, sessionId: string, signHash: SignHash, id: string, type: AdministrativeEventType, data: Readonly<Record<string, unknown>>,
): Promise<WriteResult> {
  // SPEC §13.4 (E4): a duty finding needs two callbacks and the fresh-eligibility contract of `openLocalDutyPolicy`
  // (`core-0.3/src/history-store/index.ts:25-29`); this one-signature route refuses it before any signer runs.
  requireCondition(type !== "ATTEMPT_DUTY_DISPOSITION_RECORDED" && type !== "ATTEMPT_DUTY_CONTEST_RECORDED", "DUTY_WRITER_REQUIRED");
  const snapshot = snapshotOf(store, config), state = snapshot.state;
  const position = state.eventPositionsById.get(id);
  if (position !== undefined) {
    const existing = state.events[position] as CanonicalEvent;
    requireCondition(existing.type === type && canonicalEncode(administrativeEffect(existing)) === canonicalEncode(data), "OPERATION_CONFLICT");
    // An exact repeat observes a prior event; it issues no new signature/write.
    return Object.freeze({ eventId: existing.id, head: snapshot.head });
  }
  const head = snapshot.head;
  const transition = { id, type, timestamp: config.now(), data };
  assertFresh(snapshot);
  requireCondition(transition.timestamp >= head.canonicalTime, "CLOCK_INVALID");
  const input = { expectedDomain: config.domain, expectedHistoryHead: head, transition, runtimeSessionId: sessionId };
  let produced: ProducedAdministrativeEvent;
  try {
    // The cached state is live: an append while the signer runs surfaces as VERIFY:HEAD_MISMATCH (→ HISTORY_CONFLICT).
    produced = await produceAdministrativeEventState(state, input, { signHash: (hash: ContentHash) => signHash(hash) });
  } catch (error) {
    throw producerFailure(error);
  }
  const latest = unchangedSince(store, config, snapshot);
  // Recheck session and policy at the post-signing host time. The original signature binds the original record time;
  // this fresh evaluation cannot change it, and prevents authority expiry during async signing.
  const now = config.now();
  requireCondition(now >= transition.timestamp, "CLOCK_INVALID");
  try { prepareAdministrativeEventState(latest.state, { ...input, transition: { ...transition, timestamp: now } }); } catch (error) { throw producerFailure(error); }
  return appendEvent(store, config, latest.state, produced.event, head);
}

/** The session behind a runtime handle; refuses a session admitted under another controller. */
export function sessionOf(store: HistoryStore, config: Config, sessionId: string): RuntimeSessionRecord {
  const session = currentState(store, config).runtimeSessions.get(sessionId);
  requireCondition(session !== undefined && session.controllerId === config.controller, "RUNTIME_NOT_CURRENT");
  return session;
}

