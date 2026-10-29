/**
 * The replay reducer (spec 01 §D.5–D.6): one event at a time, in the exact
 * check order of the reference engine, over a `MutableReplayState`. Chain
 * hashes come from the incremental `HistoryHasher`; a rejected event never
 * touches the state. Signed transitions are delegated to the authority engine
 * through `ReplayHooks`, and format-1 control events are checked here against
 * the owner keys in force at their position (docs/HISTORY-FORMAT.md §7, `ownerKeysAt`).
 */
import { CanonicalError } from "./canonical.ts";
import { sessionTimeHorizonFailure } from "./session-time.ts";
import { validateAdministrativeTransition, validateIntentAdmissionTransition } from "./authority.ts";
import { accountCapacity, capacityVerdict, formatTwoLineBytes } from "./capacity.ts";
import { CONTROL_EVENT_TYPES } from "./types.ts";
import { attestationExpiryFailure, controlQuorumFailure, controlRuleAt, controlSignatureFailure, ownerKeyEpochAt, ownerKeysAt, policyGuard, singleSignerTimeFailure } from "./owner-keys.ts";
import { credentialId, ownerPolicyFailure } from "./owner-policy.ts";
import { declaredKeyFailure, formatOfSchemaVersion, isFormat2, isTrellis, LEGACY_FORMAT, TRELLIS_FORMAT, legacyProjection, validateEvent } from "./events.ts";
import { invertTranscription } from "./transcription.ts";
import { type HistoryHasher, RecordChain } from "./hash.ts";
import { applyStateRecords, upperRecordDelta } from "./state-records.ts";
import { applyTransition, createReplayState, EMPTY_HEAD, foreignCredentialIds, forkReplayState, forkShadowView, type AdministrativeValidation, type MutableReplayState, type ReplayHooks } from "./state.ts";
import type { CanonicalEvent, ContentHash, HistoryFormat, HistoryHead, OwnerKey, OwnerPolicy, ReplayCode, ReplayResult, ReplayState, U53 } from "./types.ts";

export { createReplayState, EMPTY_HEAD, applyTransition, admissionControlIsCurrent, intentAdmissionIsCurrent, earlierEvidenceIsValid, constraintsAreAttenuated, forkReplayState } from "./state.ts";
export type { MutableReplayState, ReplayHooks, IntentAdmissionValidation, AdministrativeValidation, AnchorRecord, ShadowContext, TransitionFailure } from "./state.ts";

export const REPLAY_VERSION = "continuity-replay/0.2";

/** The engine's own validators; wrapped so the (cyclic) authority module is touched only at call time. */
export const defaultReplayHooks: ReplayHooks = Object.freeze({
  validateIntentAdmissionTransition: (state, event, position, nextHead) => validateIntentAdmissionTransition(state, event, position, nextHead),
  validateAdministrativeTransition: (state, event, position, requirements): AdministrativeValidation =>
    validateAdministrativeTransition(state, event, position, requirements),
});

/** Which format a raw history claims, read loosely from the genesis `versions.eventSchemaVersion`. */
export const detectFormat = (events: readonly unknown[]): HistoryFormat | undefined => {
  const genesis = events[0];
  if (genesis === null || typeof genesis !== "object") return undefined;
  const data = (genesis as { data?: unknown }).data;
  if (data === null || typeof data !== "object") return undefined;
  const versions = (data as { versions?: unknown }).versions;
  if (versions === null || typeof versions !== "object") return undefined;
  return formatOfSchemaVersion((versions as { eventSchemaVersion?: unknown }).eventSchemaVersion);
};

export type ApplyResult = Readonly<{ ok: true; event: CanonicalEvent; head: HistoryHead }> | Readonly<{ ok: false; code: ReplayCode; reason: string }>;
/**
 * Writer-only: `deferQuorum` checks every rule but A-92.2 steps 2–6 (the co-signatures a two-phase writer collects before
 * it submits, A-92.4). Replay never sets it; a submit checks the full rule.
 */
export type ApplyOptions = Readonly<{ deferQuorum?: boolean }>;
const rejected = (code: ReplayCode, reason: string): ApplyResult => ({ ok: false, code, reason });

/**
 * docs/HISTORY-FORMAT.md §7: every format-1 control event is signed, over the head *before*
 * it, by an owner key in force at its position (`ownerKeysAt`: the genesis set
 * until the first OWNER_KEYS_ROTATED, whose own signature is still checked
 * against the set before it). Format 2 (SPEC §6.1): the same check over the `/2`
 * challenge, whose `previousHead` is the chain head `{recordHash(p−1), p−1}`
 * (`state.head` holds exactly that); the literal follows the genesis domain.
 */
const controlAuthorizationFailure = (state: MutableReplayState, event: CanonicalEvent, position: U53, deferQuorum = false): Readonly<{ code: ReplayCode; reason: string }> | undefined => {
  // Format 2 (A-92.2): step 0 (A-115.1, `controlRuleAt`) fixes M_eff (with PR_eff, A-116.1), adm(e) (A-97.2), isRestoration
  // (A-107.3 with A-118.2) and isCheckpoint from the data, the epoch record and σ(p) before any signature is verified; step
  // 1 is the format-1 check; steps 2–6 are the quorum under the pre-event policy P(p) with the counting of A-107.2; then T2.
  const format2 = isFormat2(state.format);
  const context = format2 ? controlRuleAt(state, event, position) : {
    domain: state.genesis.domain, previousHead: position === 0 ? null : { hash: state.head.hash, position: state.head.position },
    keys: ownerKeysAt(state, position), algorithm: state.hashAlgorithm,
  };
  const unsigned = controlSignatureFailure(event, context);
  if (unsigned !== undefined) return { code: "CONTROL_AUTHORIZATION_INVALID", reason: unsigned };
  if (!format2 || deferQuorum) return undefined;
  const rule = context as ReturnType<typeof controlRuleAt>;
  const quorum = controlQuorumFailure(event, rule);
  if (quorum !== undefined) return { code: "CONTROL_AUTHORIZATION_INVALID", reason: quorum.reason };
  const time = singleSignerTimeFailure(state, event, position, rule);
  return time === undefined ? undefined : { code: "TRANSITION_INVALID", reason: time.reason };
};
/**
 * A-117.2 (row 26, the §3.3 key-test stage, under `G(e, p)`): every key of `ownerKeys`, kept, revealed or a recovery
 * signer, has a credential outside `foreign(σ(p))` (every session and counterparty credential of the state before the
 * event). The reason, or `undefined`. At row 0 the rule is vacuous (`σ(0)` has no records).
 */
const foreignOwnerKeyFailure = (state: MutableReplayState, event: CanonicalEvent, position: U53): string | undefined => {
  if (!policyGuard(event, ownerKeyEpochAt(state, position))) return undefined;
  const foreign = foreignCredentialIds(state);
  const index = (event.data.ownerKeys as readonly OwnerKey[]).findIndex((key) => foreign.has(credentialId(key)));
  return index < 0 ? undefined : `$.data.ownerKeys[${index}].credential: is a session or counterparty credential of this history; under an owner approval policy every owner key is a dedicated key (A-117.2)`;
};

/**
 * Validate and apply one raw event at the next position. Check order (spec 01
 * §G.10): capture → genesis position → type → schema → GENESIS_DUPLICATE →
 * EVENT_ID_DUPLICATE → EVENT_TIME_REGRESSION → control authorization (format 1)
 * → TRANSITION_INVALID. On failure the state is unchanged.
 */
export const applyEvent = (state: MutableReplayState, raw: unknown, hooks: ReplayHooks = defaultReplayHooks, options: ApplyOptions = {}): ApplyResult => {
  const position = state.events.length;
  // Inside a migrated prefix the transition sees the source's shadow: source domain, hashing and pre-event head (SPEC §16.2 step 3).
  const shadow = state.shadow !== undefined && position >= 1 && position <= state.shadow.until ? state.shadow : undefined;
  const migratedUntil = position > 0 ? state.genesis.migratedFrom?.position : undefined;
  const validation = validateEvent(raw, state.format, position, shadow === undefined && migratedUntil === undefined ? undefined : { ...(shadow === undefined ? {} : { shadow: shadow.sourceFormat }), ...(migratedUntil === undefined ? {} : { migratedUntil }) });
  if (!validation.ok) return validation;
  const event = validation.event;
  if (position > 0 && event.type === "DEPLOYMENT_INITIALIZED") return rejected("GENESIS_DUPLICATE", "a second genesis is not allowed");
  if (state.eventPositionsById.has(event.id)) return rejected("EVENT_ID_DUPLICATE", `event id ${event.id} already accepted`);
  if (state.lastTimestamp !== undefined && event.timestamp < state.lastTimestamp) return rejected("EVENT_TIME_REGRESSION", "timestamps must not decrease");
  if (isFormat2(state.format) && position > 0 && !CONTROL_EVENT_TYPES.has(event.type)) {
    const expiry = attestationExpiryFailure(state, event, position);
    if (expiry !== undefined) return rejected("TRANSITION_INVALID", expiry.reason);
    // A-179.3 rule T3, immediately after T1 (A-172.1): guarded by a non-null genesis sessionTimeHorizonMs; ¬inPrefix(p).
    const horizon = sessionTimeHorizonFailure(state, event, position);
    if (horizon !== undefined) return rejected("TRANSITION_INVALID", horizon.reason);
  }
  if (isTrellis(state.format) && CONTROL_EVENT_TYPES.has(event.type)) {
    const failure = controlAuthorizationFailure(state, event, position, options.deferQuorum === true);
    if (failure !== undefined) return rejected(failure.code, failure.reason);
  }
  // Hash into a clone so a rejected transition leaves the running hasher untouched.
  const hasher = state.hasher.clone();
  let hash: HistoryHead["hash"];
  try {
    hash = hasher.push(event);
  } catch (error) {
    return rejected("INVALID_INPUT", error instanceof CanonicalError ? error.reason : "history commitment failed");
  }
  const nextHead: HistoryHead = Object.freeze({ hash, position, canonicalTime: event.timestamp });
  let shadowHasher: HistoryHasher | undefined, shadowHead: HistoryHead | undefined, projected: CanonicalEvent | undefined;
  if (shadow !== undefined) {
    shadowHasher = shadow.hasher.clone();
    // The event as the source held it: the format-1 host drops the format-1 additions; the format-2 host inverts the transcription.
    projected = shadow.events === undefined ? legacyProjection(event) : invertTranscription(event, shadow.sourceFormat);
    let shadowHash: HistoryHead["hash"];
    try {
      shadowHash = shadowHasher.push(projected);
    } catch (error) {
      return rejected("INVALID_INPUT", error instanceof CanonicalError ? error.reason : "shadow commitment failed");
    }
    if (position === shadow.until && shadowHash !== shadow.expectedHash) return rejected("TRANSITION_INVALID", "the re-recorded prefix does not reproduce migratedFrom.historyHash");
    // A-40.1: a format-1 source's control event keeps its own /1 authorization (restored by the inversion); it MUST verify
    // as the format-1 verifier checks it, in the shadow context: the source genesis owner keys (no rotation in a prefix),
    // the source challenge over the shadow head before the event.
    if (isFormat2(state.format) && shadow.sourceFormat === TRELLIS_FORMAT && CONTROL_EVENT_TYPES.has(event.type)) {
      const view = shadow.view;
      const failure = controlSignatureFailure(projected, {
        domain: view.genesis.domain, previousHead: { hash: view.head.hash, position: view.head.position },
        keys: (view.genesis.ownerKeys ?? []) as never, algorithm: view.hashAlgorithm,
      });
      if (failure !== undefined) return rejected("CONTROL_AUTHORIZATION_INVALID", `sourceControlAuthorization at ${position}: ${failure} (A-40.1)`);
    }
    shadowHead = Object.freeze({ hash: shadowHash, position, canonicalTime: event.timestamp });
  }
  // A-32.2 / A-79.2: a session credential (8) or rotated owner key (26) failing the §3.3 declaration test, after control authorization,
  // with A-117.2 for every owner key under G(e, p). A-91.2 / A-115.1 row 26: then the resulting owner approval policy's validity
  // (EVENT_DATA_INVALID), before HF1's rules.
  if (isFormat2(state.format)) {
    const rotation = event.type === "OWNER_KEYS_ROTATED";
    const failure = declaredKeyFailure(event) ?? (rotation ? foreignOwnerKeyFailure(state, event, position) : undefined) ??
      (rotation && event.data.ownerPolicy !== undefined ? ownerPolicyFailure(event.data.ownerPolicy as OwnerPolicy, event.data.ownerKeys as readonly OwnerKey[], {
        setting: {
          domain: state.genesis.domain, timestamp: event.timestamp, nextKeyDigests: (event.data.nextKeyDigests ?? []) as readonly ContentHash[], genesis: false,
          previous: ownerKeyEpochAt(state, position)?.policy, historyId: state.eventHistoryHashes[0]!, foreign: () => foreignCredentialIds(state),
        },
      }) : undefined);
    if (failure !== undefined) return rejected("EVENT_DATA_INVALID", failure);
  }
  // Capacity (SPEC §5.2 as amended by A-0.1/A-3) is the last replay check of format 2. Its verdict depends on the
  // pre-event state, the line bytes and `R(p)`, the leaf count AFTER the event. The verdict is decided cheaply when it is
  // the same at both bounds of `R(p)` (`R(p−1) + 1` … `upperRecordDelta`), which is every event away from the limits;
  // otherwise the transition and the records run on a private fork to count `R(p)` exactly. A refused event still runs
  // its transition on a fork first, so that an event failing both reports the transition's code ("first failure wins")
  // and the state stays untouched either way. Inside a migrated prefix (no fork) the upper bound decides (unreachable for
  // an accepted history: `migrate` refuses a source that cannot fit up front). Format 1 and legacy keep the format-1
  // API-side-only capacity (G0 Q1).
  const format2 = isFormat2(state.format);
  const lineBytes = format2 ? formatTwoLineBytes(position, (hasher as RecordChain).lastEventBytes) : 0;
  if (format2) {
    const lower = state.stateRecords.size + 1, upper = state.stateRecords.size + upperRecordDelta(state, event, position);
    const atLower = capacityVerdict(state, event, lineBytes, undefined, lower);
    const atUpper = capacityVerdict(state, event, lineBytes, undefined, upper);
    if (atLower !== undefined || atUpper !== undefined) {
      const fork = forkReplayState(state);
      if (fork === undefined) {
        const verdict = atLower?.code === atUpper?.code ? atLower : atUpper;
        if (verdict !== undefined) return rejected(verdict.code, verdict.reason);
      } else {
        const trial = applyTransition(fork, event, position, nextHead, redirectedHooks(hooks, fork, state));
        if (trial !== undefined) return rejected(trial.code, trial.reason);
        let verdict = atLower?.code === atUpper?.code ? atLower : undefined;
        if (verdict === undefined && atLower?.code !== atUpper?.code) {
          // The exact R(p): the event's records on the fork (the commit steps the records read, then the record update).
          fork.events.push(event);
          fork.eventHistoryHashes.push(hash);
          fork.eventPositionsById.set(event.id, position);
          fork.lastTimestamp = event.timestamp;
          fork.head = nextHead;
          applyStateRecords(fork, event, position, (hasher as RecordChain).lastEventHash!, hash);
          verdict = capacityVerdict(state, event, lineBytes, undefined, fork.stateRecords.size);
        }
        if (verdict !== undefined) return rejected(verdict.code, verdict.reason);
      }
    }
  }
  // A format-2 host's prefix transition runs on the view with the inverted event (source shapes, engine amounts), SPEC §16.2 step 3.
  const target = shadow?.view ?? state, applied = shadow?.events !== undefined ? projected! : event, appliedHead = shadowHead ?? nextHead;
  // A-40.2 / A-80: the source attestation signs the full source head; its canonicalTime (as the format-1 engine defines it: the head event's
  // timestamp) is checked once the prefix is replayed, EVENT_DATA_INVALID at migratedFrom.position. The event is then rejected whatever
  // its transition decides, so the transition runs on a scratch copy of the view: its failure is still reported first, and the shared
  // maps stay untouched (r4 §5).
  if (shadow !== undefined && position === shadow.until) {
    const attested = (state.genesis.migratedFrom as { sourceAttestation?: { head?: { canonicalTime?: unknown } } | null } | undefined)?.sourceAttestation;
    if (attested !== undefined && attested !== null && attested.head?.canonicalTime !== event.timestamp) {
      const scratch = forkShadowView(target);
      const failure = applyTransition(scratch, applied, position, appliedHead, redirectedHooks(hooks, scratch, target));
      return failure !== undefined ? rejected(failure.code, failure.reason)
        : rejected("EVENT_DATA_INVALID", "migratedFrom.sourceAttestation does not attest the source head's canonicalTime (A-40.2, A-80)");
    }
  }
  const failure = applyTransition(target, applied, position, appliedHead, hooks);
  if (failure !== undefined) return rejected(failure.code, failure.reason);
  if (shadow !== undefined && shadowHasher !== undefined && shadowHead !== undefined) {
    shadow.hasher = shadowHasher;
    shadow.hashes.push(shadowHead.hash);
    shadow.view.head = shadowHead;
    if (shadow.events !== undefined) {
      shadow.events.push(projected!);
      if (position === shadow.until) shadow.events.length = 0; // the prefix is complete: nothing reads the view again
    }
  }
  state.hasher = hasher;
  state.events.push(event);
  state.eventHistoryHashes.push(hash);
  state.eventPositionsById.set(event.id, position);
  // A-179.2: ownerTime moves only on an accepted control event that advances time (prefix events count); e_0 starts it.
  if (position === 0 || (CONTROL_EVENT_TYPES.has(event.type) && state.lastTimestamp !== undefined && event.timestamp > state.lastTimestamp)) state.ownerTime = event.timestamp;
  state.lastTimestamp = event.timestamp;
  state.head = nextHead;
  // Format 2 (SPEC §7.1, §12): the state records touched by the event, its own `event` record, rootAt(position) and the projection head.
  if (format2) {
    applyStateRecords(state, event, position, (hasher as RecordChain).lastEventHash!, hash);
    accountCapacity(state, event);
    state.canonicalBytes += lineBytes;
  }
  return { ok: true, event, head: nextHead };
};

/** Hooks that validate against `base` when handed the fork `own` (the fork still equals the base while a transition checks). */
const redirectedHooks = (hooks: ReplayHooks, own: ReplayState, base: ReplayState): ReplayHooks => ({
  validateIntentAdmissionTransition: (s, event, position, nextHead) => hooks.validateIntentAdmissionTransition(s === own ? base : s, event, position, nextHead),
  validateAdministrativeTransition: (s, event, position, requirements) => hooks.validateAdministrativeTransition(s === own ? base : s, event, position, requirements),
});

/**
 * A *completed* replay of a migrated history must have consumed the whole
 * declared legacy prefix (docs/HISTORY-FORMAT.md §11); a shorter history is rejected here (and
 * by the store's open path), while `applyEvent` stays incremental so that the
 * prefix can be written event by event.
 */
export const incompleteMigration = (state: ReplayState): Readonly<{ code: ReplayCode; reason: string }> | undefined => {
  const until = state.genesis.migratedFrom?.position;
  return until !== undefined && state.events.length > 0 && state.events.length - 1 < until
    ? { code: "TRANSITION_INVALID", reason: "migrated prefix incomplete" } : undefined;
};

/** Continue replaying `events` onto `state`; rejection positions are absolute. */
export const replayFrom = (state: MutableReplayState, events: readonly unknown[], hooks: ReplayHooks = defaultReplayHooks): ReplayResult => {
  for (const raw of events) {
    const result = applyEvent(state, raw, hooks);
    if (!result.ok) return Object.freeze({ status: "REJECTED", code: result.code, position: state.events.length, reason: result.reason });
  }
  if (state.events.length === 0) return Object.freeze({ status: "REJECTED", code: "GENESIS_REQUIRED" });
  const incomplete = incompleteMigration(state);
  if (incomplete !== undefined) return Object.freeze({ status: "REJECTED", ...incomplete, position: state.events.length });
  if (isFormat2(state.format)) {
    return Object.freeze({
      status: "ACCEPTED", state: state as ReplayState, head: state.head, eventCount: state.events.length,
      stateRoot: state.stateRoots.at(-1)!, projectionHead: state.genesis.projection === null ? null : state.projectionHeads.at(-1)!,
    });
  }
  return Object.freeze({ status: "ACCEPTED", state: state as ReplayState, head: state.head, eventCount: state.events.length });
};

export type ProspectiveResult =
  | Readonly<{ ok: true; state: ReplayState; event: CanonicalEvent; head: HistoryHead }>
  | Readonly<{ ok: false; code: ReplayCode; reason: string }>;

/**
 * "Would `raw` be accepted as the next event of `state`, and with which head?"
 * without replaying the history and without touching `state`: `raw` is applied
 * to a copy-on-write fork (`forkReplayState`). The result equals the last step
 * of `replay([...state.events, raw])` for any accepted `state`.
 *
 * The signed-transition validators run while the fork still equals `state`
 * (every transition checks before it writes), so they are handed `state`
 * itself and reuse its authority memo instead of rebuilding one for the fork.
 * The returned `state` reads through to the argument: use it before the
 * argument changes (e.g. before the store appends), then drop it.
 */
export const withProspectiveEvent = (state: ReplayState, raw: unknown, hooks: ReplayHooks = defaultReplayHooks, options: ApplyOptions = {}): ProspectiveResult => {
  let fork = forkReplayState(state);
  if (fork === undefined) {
    // Still inside a migrated legacy prefix: rebuild privately (rare, never for an accepted history).
    fork = createReplayState(state.format);
    for (const event of state.events) if (!applyEvent(fork, event, hooks).ok) return { ok: false, code: "TRANSITION_INVALID", reason: "the base state does not replay" };
    const result = applyEvent(fork, raw, hooks, options);
    return result.ok ? { ok: true, state: fork, event: result.event, head: result.head } : result;
  }
  const result = applyEvent(fork, raw, redirectedHooks(hooks, fork, state), options);
  return result.ok ? { ok: true, state: fork, event: result.event, head: result.head } : result;
};

/** Replay a raw history from scratch; the format is detected from the genesis (unknown → legacy rules decide the rejection). */
export const replay = (events: readonly unknown[], hooks: ReplayHooks = defaultReplayHooks): ReplayResult => {
  if (!Array.isArray(events)) return Object.freeze({ status: "REJECTED", code: "INVALID_INPUT", reason: "events must be an array" });
  return replayFrom(createReplayState(detectFormat(events) ?? LEGACY_FORMAT), events, hooks);
};
