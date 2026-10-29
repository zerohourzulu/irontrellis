/**
 * Capacity policy (docs/API.md §8; SPEC §5.2 for format 2). Finite ledger space is a *point-in-time*
 * observation that never grants authority and, unlike Core 0.3's managed
 * profile, never blocks a revocation: control events that withdraw or
 * transfer power are always admitted, and there is no control reserve.
 *
 * A declared job reserves one slot per lifecycle record type it has not yet
 * produced (the Core 0.3 lifecycle reservation), so admitted work can always
 * finish. When `eventCount + reserved` reaches `maxEvents` the history is in
 * CONTROL_ONLY mode: new agents, roles, grants, sessions and jobs are refused
 * with `CAPACITY_CONTROL_ONLY` (format 1); in format 2 a declared capacity never
 * refuses a control event (◆), only ◇/▲ growth (SPEC §5.2).
 *
 * Format 2 adds (SPEC §4.5, §5.2 and the control-event reserve addendum of BUILD-INSTRUCTIONS):
 * - `capacity.maxStateRecords`: at or above it every ◇/▲ event is `CAPACITY_EXCEEDED` (each accepted event adds its
 *   own `event` record); ◆ events are admitted;
 * - the hard limits `MAX_STATE_RECORDS` (1,048,576 records) and `MAX_FILE_BYTES` (1 GiB): at them every event is
 *   `CAPACITY_EXCEEDED`, control events included;
 * - the reserve below each hard limit (`RESERVED_STATE_RECORDS` = 4096 records, `RESERVED_FILE_BYTES` = 16 MiB): at or
 *   above `MAX − reserve` every ◇/▲ event is `CAPACITY_RESERVED` while ◆ control events (a retirement, a checkpoint,
 *   a revocation, the migration's last events) are still admitted;
 * - the duty quota of SPEC §13.5 (`dutyReserved`: 4 + 2 slots per activated duty policy, never released), counted
 *   with `lifecycleReserved` in the `maxEvents` rule (the activation itself is E4's).
 *
 * G2-APPLY (addenda A-0.1, A-1, A-2, A-3, A-13, A-56.1/7/8/24): one order — (1) absolute limits for every event
 * (`R(p−1) ≥ HARD_RECORDS`, `R(p) > HARD_RECORDS`, `B(p) > HARD_BYTES` → `CAPACITY_EXCEEDED`), (2) the reserve for every
 * event in `RESERVE_CLASS` (the full non-control class, types 14–16 included) judged AFTER the event (`R(p) > T_R` or
 * `B(p) > T_B` → `CAPACITY_RESERVED`), (3) the declared `maxStateRecords` (`R(p) > max` → `CAPACITY_EXCEEDED`,
 * non-control; no permanent latch: removing records restores room, A-56.24), (4) the declared `maxEvents` (A-2's growth
 * rule → `CAPACITY_CONTROL_ONLY`). `R(p)` is the leaf count after the event; replay computes it exactly (on a fork when
 * the bounds disagree); a writer's pre-signing check refuses only when the verdict at the lower bound `R(p−1) + 1` and at
 * the upper bound agree, so a writer never refuses with a code the replay would not give (A-1.1).
 *
 * The same verdict (`capacityVerdict`) is the last replay check of format 2 (`replay.ts applyEvent`) and the owner
 * API's pre-signing check (`assertCapacityTransition`); the store applies the byte limits to the file it writes.
 * **Bytes:** replay counts the canonical store line of every accepted event (`formatTwoLineBytes`: exactly the bytes
 * `store.ts encodeLine` writes for format 2, so a file this store wrote has `state.canonicalBytes === file size`);
 * the store checks its actual file size. For a file written by another producer (non-canonical event text) the two
 * counts differ by the whitespace/key-order slack of that producer; both apply the same thresholds.
 */
import { canonicalEncode } from "./canonical.ts";
import { EngineError } from "./errors.ts";
import { isFormat2 } from "./events.ts";
import type { MutableReplayState, TransitionFailure } from "./state.ts";
import { upperRecordDelta } from "./state-records.ts";
import { ALWAYS_ADMITTED_EVENT_TYPES, CONTROL_EVENT_TYPES, EVENT_TYPES, type CanonicalEvent, type EventType, type ReplayState, type U53 } from "./types.ts";
import { readonlySet } from "./readonly-collections.ts";

export type CapacityProfile = "irontrellis-capacity/1" | "continuity-managed-capacity/1";
export type CapacityReport = Readonly<{
  profile: CapacityProfile;
  eventCount: U53;
  maxEvents: number | null;
  /** A-13: describes the head (A-56.7: one event may still be refused under A-3 before the mode changes). FULL: no event fits (an absolute limit is reached); RESERVED: at or above a reserve threshold; CONTROL_ONLY: a declared limit reached. Format 1/legacy: OPEN | CONTROL_ONLY. */
  mode: "OPEN" | "CONTROL_ONLY" | "RESERVED" | "FULL";
  canDeclareJob: boolean;
  lifecycleReserved: U53;
  declaredJobs: U53;
  remainingPhysicalEvents: number | null;
  /** the format-1 engine's field, kept for format 1 and legacy only; A-13 drops it for format 2 (absent). */
  controlAlwaysAdmitted?: true;
  pointInTimeOnly: true;
  grantsAuthority: false;
  /** Format 2 (SPEC §7.1): the number of §7.2 state records (leaves); 0 for other formats. */
  stateRecords: U53;
  /** Format 2 (SPEC §5.1): the declared cap on state records (`null` = none declared). */
  maxStateRecords: number | null;
  /** Format 2 (A-0): the history is at or above a reserve threshold (`mode` RESERVED or FULL). */
  reserved: boolean;
  /** Format 2 (SPEC §13.5): the slots reserved for activated duty policies' dispositions and contests. */
  dutyReserved: U53;
  /** Format 2 (A-13): `B` at the head, the canonical §4.1 line bytes of events 0…head (A-3); 0 for other formats. */
  fileBytes: number;
  /** Format 2 (A-13): `T_R`, `T_B` (the hard limits minus the reserve). */
  reserveThresholds: Readonly<{ stateRecords: number; fileBytes: number }>;
  /** Format 2 (A-13): `HARD_RECORDS`, `HARD_BYTES`. */
  hardLimits: Readonly<{ stateRecords: number; fileBytes: number }>;
}>;

/** Legacy histories keep the Core 0.3 physical budget and per-event bounds (minus the 8-event control reserve). */
export const LEGACY_CAPACITY_PROFILE = Object.freeze({
  version: "continuity-managed-capacity/1" as const, maxEvents: 96, maxEventBytes: 8192, maxEventArrayMembers: 32, maxEventDepth: 16,
});
export const CAPACITY_PROFILE = "irontrellis-capacity/1" as const;

// ---------------------------------------------------------------- format-2 hard limits and the control-event reserve

/** SPEC §4.5: at most 1,048,576 state records per history (a hard limit: at it every event is refused). */
export const MAX_STATE_RECORDS = 1_048_576;
/** SPEC §4.5: the hard file cap of a format-2 history, 1 GiB. */
export const MAX_FILE_BYTES = 1024 * 1024 * 1024;
/** Addendum: the last 4096 state records below the hard cap admit control events only (`CAPACITY_RESERVED` for ◇/▲). */
export const RESERVED_STATE_RECORDS = 4096;
/** Addendum: the last 16 MiB below the file cap admit control events only. */
export const RESERVED_FILE_BYTES = 16 * 1024 * 1024;
/** A-3 names: `HARD_RECORDS`, `HARD_BYTES` (= `MAX_STATE_RECORDS`, `MAX_FILE_BYTES`), `T_R`, `T_B`. */
export const HARD_RECORDS = MAX_STATE_RECORDS;
export const HARD_BYTES = MAX_FILE_BYTES;
export const RESERVE_THRESHOLD_RECORDS = MAX_STATE_RECORDS - RESERVED_STATE_RECORDS; // T_R = 1,044,480
export const RESERVE_THRESHOLD_BYTES = MAX_FILE_BYTES - RESERVED_FILE_BYTES; // T_B = 1,056,964,608
/**
 * A-3 step 2 as amended by A-0.1 (binding) and A-56.1: `RESERVE_CLASS` is the ONE constant set of the event types the
 * reserve refuses — the full non-control class: every ◇ and ▲ type and the lifecycle types 14–16. Only ◆ control events
 * (and the genesis, which is never subject to capacity) may use the reserve.
 */
export const RESERVE_CLASS: ReadonlySet<EventType> = readonlySet<EventType>(EVENT_TYPES.filter((type) => type !== "DEPLOYMENT_INITIALIZED" && !CONTROL_EVENT_TYPES.has(type)));
/**
 * A-2 (a): the format-1 engine's always-admitted NON-control types (a lifecycle record of an already declared job, or a duty
 * review); never consulted for control events (A-1.3: declared limits never refuse a control event).
 */
export const ALWAYS_ADMITTED_NON_CONTROL: ReadonlySet<EventType> = readonlySet<EventType>([
  "TRANSACTION_INTENT_CONSUMED", "TRANSACTION_OUTCOME_RECORDED", "RECEIPT_RECORDED", "OBLIGATION_PERFORMANCE_ASSIGNED", "OBLIGATION_STATUS_RECORDED",
  "OUTCOME_OBSERVATION_RECORDED", "ATTEMPT_DUTY_REVIEW_CLOSED",
]);
/** SPEC §13.5: the slots an activated duty policy reserves for its dispositions and contests. */
export const DUTY_DISPOSITION_QUOTA = 4;
export const DUTY_CONTEST_QUOTA = 2;

export type CapacityLimits = Readonly<{ maxStateRecords: number; maxFileBytes: number; reservedStateRecords: number; reservedFileBytes: number }>;
const DEFAULT_LIMITS: CapacityLimits = Object.freeze({ maxStateRecords: MAX_STATE_RECORDS, maxFileBytes: MAX_FILE_BYTES, reservedStateRecords: RESERVED_STATE_RECORDS, reservedFileBytes: RESERVED_FILE_BYTES });
let limits: CapacityLimits = DEFAULT_LIMITS;
/** The hard limits in force (the SPEC constants unless a test lowered them). */
export const capacityLimits = (): CapacityLimits => limits;
/**
 * TEST ONLY. Lowers the format-2 hard limits for this process so a unit test can reach the reserve and the cap with a
 * few events; `setCapacityLimitsForTests()` restores the SPEC constants. Never call it in production code: the limits
 * are part of the format (SPEC §4.5), and a history accepted under lowered limits is not a conforming history.
 */
export function setCapacityLimitsForTests(override?: Partial<CapacityLimits>): CapacityLimits {
  limits = override === undefined ? DEFAULT_LIMITS : Object.freeze({ ...DEFAULT_LIMITS, ...override });
  return limits;
}

/** The bytes of the format-2 store line of an event whose canonical text is `eventBytes` long (`store.ts encodeLine`). */
export const formatTwoLineBytes = (position: number, eventBytes: number): number =>
  // {"version":"irontrellis-portable-file-store/2","previousHash":<null | "0x"+64>,"event":<event>,"recordHash":"<0x+64>"}\n
  `{"version":"irontrellis-portable-file-store/2","previousHash":`.length + (position === 0 ? 4 : 68) + `,"event":`.length + eventBytes + `,"recordHash":"`.length + 66 + `"}\n`.length;

// ---------------------------------------------------------------- lifecycle and duty reservations

const LIFECYCLE: ReadonlySet<EventType> = new Set<EventType>([
  "TRANSACTION_INTENT_ADMITTED", "TRANSACTION_INTENT_CONSUMED", "TRANSACTION_OUTCOME_RECORDED", "RECEIPT_RECORDED",
  "OUTCOME_OBSERVATION_RECORDED", "ATTEMPT_DUTY_CREATED", "ATTEMPT_DUTY_ASSIGNED", "ATTEMPT_DUTY_REVIEW_CLOSED",
  "OBLIGATION_CREATED", "OBLIGATION_PERFORMANCE_ASSIGNED", "OBLIGATION_STATUS_RECORDED",
]);
/** A declaration plus one slot per lifecycle record type. */
const JOB_FOOTPRINT = 1 + LIFECYCLE.size;

/**
 * The reservation ledger (format 2 keeps it in the replay state, updated at every commit, so the replay step is O(1)
 * per event; format 1 and legacy rebuild it by a scan, as the format-1 engine did). `capacityIntents` maps every declared job to the
 * lifecycle record types it has produced; `capacityDuties`/`capacityObligations` map their ids to the job;
 * `capacityDutyQuota` counts dispositions and contests per activated duty policy (SPEC §13.5); the two sums are kept
 * in step. The fields are top-level map and number fields of the state so that `forkReplayState` overlays them.
 */
export type CapacityLedger = {
  capacityIntents: Map<string, Set<EventType>>; capacityDuties: Map<string, string>; capacityObligations: Map<string, string>;
  capacityDutyQuota: Map<string, Readonly<{ dispositions: number; contests: number }>>;
  lifecycleReserved: number; dutyReserved: number;
};
export const newCapacityLedger = (): CapacityLedger => ({ capacityIntents: new Map(), capacityDuties: new Map(), capacityObligations: new Map(), capacityDutyQuota: new Map(), lifecycleReserved: 0, dutyReserved: 0 });
/** The job an event belongs to, and whether it is a lifecycle record of it (the format-1 attribution). */
const jobOf = (r: CapacityLedger, event: CanonicalEvent): string | undefined => {
  const d = event.data as Readonly<Record<string, unknown>>;
  const record = d.record as Readonly<Record<string, unknown>> | undefined;
  switch (event.type) {
    case "ATTEMPT_DUTY_CREATED": case "OBLIGATION_CREATED": return record?.sourceIntentId as string | undefined;
    case "ATTEMPT_DUTY_ASSIGNED": case "ATTEMPT_DUTY_REVIEW_CLOSED": return r.capacityDuties.get(d.dutyId as string);
    case "OBLIGATION_PERFORMANCE_ASSIGNED": case "OBLIGATION_STATUS_RECORDED": return r.capacityObligations.get(d.obligationId as string);
    default: return typeof d.intentId === "string" ? d.intentId : undefined;
  }
};
/**
 * The change of `lifecycleReserved + dutyReserved` the event would cause (read-only): a new job reserves its lifecycle
 * (+11), a lifecycle record of a known job spends one slot (−1), a duty-policy activation reserves 4 + 2, a disposition
 * or contest within quota spends one; everything else 0.
 */
export const reservationDelta = (r: CapacityLedger, event: CanonicalEvent): number => {
  const d = event.data as Readonly<Record<string, unknown>>;
  if (event.type === "TRANSACTION_INTENT_DECLARED") return typeof d.intentId === "string" && !r.capacityIntents.has(d.intentId) ? LIFECYCLE.size : 0;
  if (LIFECYCLE.has(event.type)) {
    const intent = jobOf(r, event);
    const seen = intent === undefined ? undefined : r.capacityIntents.get(intent);
    return seen !== undefined && !seen.has(event.type) ? -1 : 0;
  }
  if (event.type === "ATTEMPT_DUTY_POLICY_ACTIVATED") {
    const dutyId = (d.descriptor as { dutyId?: unknown } | undefined)?.dutyId;
    return typeof dutyId === "string" && !r.capacityDutyQuota.has(dutyId) ? DUTY_DISPOSITION_QUOTA + DUTY_CONTEST_QUOTA : 0;
  }
  if (event.type === "ATTEMPT_DUTY_DISPOSITION_RECORDED" || event.type === "ATTEMPT_DUTY_CONTEST_RECORDED") {
    const quota = r.capacityDutyQuota.get(d.dutyId as string);
    if (quota === undefined) return 0;
    // An over-quota record (refused by eligibility before capacity, SPEC §13.5) never manufactures a negative reserve.
    return (event.type === "ATTEMPT_DUTY_DISPOSITION_RECORDED" ? quota.dispositions < DUTY_DISPOSITION_QUOTA : quota.contests < DUTY_CONTEST_QUOTA) ? -1 : 0;
  }
  return 0;
};
/** Attribute one accepted event to its job and mark the lifecycle record type it produced; keeps the running sums. */
export const accountCapacity = (r: CapacityLedger, event: CanonicalEvent): void => {
  const d = event.data as Readonly<Record<string, unknown>>;
  const record = d.record as Readonly<Record<string, unknown>> | undefined;
  const delta = reservationDelta(r, event);
  if (event.type === "TRANSACTION_INTENT_DECLARED" && delta > 0) r.capacityIntents.set(d.intentId as string, new Set());
  if (event.type === "ATTEMPT_DUTY_CREATED" && record !== undefined) r.capacityDuties.set(record.dutyId as string, record.sourceIntentId as string);
  if (event.type === "OBLIGATION_CREATED" && record !== undefined) r.capacityObligations.set(record.obligationId as string, record.sourceIntentId as string);
  if (LIFECYCLE.has(event.type)) {
    const intent = jobOf(r, event);
    if (intent !== undefined) r.capacityIntents.get(intent)?.add(event.type);
    r.lifecycleReserved += delta;
    return;
  }
  if (event.type === "ATTEMPT_DUTY_POLICY_ACTIVATED") {
    if (delta > 0) r.capacityDutyQuota.set((d.descriptor as { dutyId: string }).dutyId, Object.freeze({ dispositions: 0, contests: 0 }));
    r.dutyReserved += delta;
  } else if (event.type === "ATTEMPT_DUTY_DISPOSITION_RECORDED" || event.type === "ATTEMPT_DUTY_CONTEST_RECORDED") {
    const quota = r.capacityDutyQuota.get(d.dutyId as string);
    if (quota !== undefined) {
      const disposition = event.type === "ATTEMPT_DUTY_DISPOSITION_RECORDED";
      r.capacityDutyQuota.set(d.dutyId as string, Object.freeze({ dispositions: quota.dispositions + (disposition ? 1 : 0), contests: quota.contests + (disposition ? 0 : 1) }));
    }
    r.dutyReserved += delta;
  } else r.lifecycleReserved += delta;
};
/** A ledger rebuilt by a scan (format 1 and legacy). */
const scannedLedger = (state: ReplayState): CapacityLedger => {
  const r = newCapacityLedger();
  for (const event of state.events) accountCapacity(r, event);
  return r;
};
/** The ledger of a state: the incremental one of format 2, else a scan. */
const ledgerOf = (state: ReplayState): CapacityLedger => (isFormat2(state.format) ? (state as MutableReplayState) : scannedLedger(state));
/** A private copy of a ledger (the sets are copied; the quota records are replaced, never mutated). */
const cloneLedger = (r: CapacityLedger): CapacityLedger => ({
  capacityIntents: new Map([...r.capacityIntents].map(([k, v]) => [k, new Set(v)])), capacityDuties: new Map(r.capacityDuties), capacityObligations: new Map(r.capacityObligations),
  capacityDutyQuota: new Map(r.capacityDutyQuota), lifecycleReserved: r.lifecycleReserved, dutyReserved: r.dutyReserved,
});

const maxEventsOf = (state: ReplayState): number | null =>
  state.format === "continuity-event/0.2" ? LEGACY_CAPACITY_PROFILE.maxEvents : (state.genesis.capacity?.maxEvents ?? null);
const maxStateRecordsOf = (state: ReplayState): number | null => (isFormat2(state.format) ? (state.genesis.capacity?.maxStateRecords ?? null) : null);
/** Format 2 (A-13 `mode` RESERVED): the head is at or above a reserve threshold (`R ≥ T_R` or `B ≥ T_B`). */
const inReserve = (state: ReplayState): boolean =>
  isFormat2(state.format) && (state.stateRecords.size >= limits.maxStateRecords - limits.reservedStateRecords || state.canonicalBytes >= limits.maxFileBytes - limits.reservedFileBytes);
/** Format 2 (A-13 `mode` FULL): no event fits — the record cap is reached (A-3 step 1 refuses every event) or the file is at its cap. */
const isFull = (state: ReplayState): boolean => isFormat2(state.format) && (state.stateRecords.size >= limits.maxStateRecords || state.canonicalBytes >= limits.maxFileBytes);

const report = (state: ReplayState, eventCount: number, ledger: CapacityLedger, declaredJobs: number = ledger.capacityIntents.size): CapacityReport => {
  const maxEvents = maxEventsOf(state);
  const reserved = ledger.lifecycleReserved + ledger.dutyReserved;
  const free = maxEvents === null ? Number.POSITIVE_INFINITY : maxEvents - eventCount - reserved;
  const format2 = isFormat2(state.format);
  const maxStateRecords = maxStateRecordsOf(state);
  const declaredReached = free < 1 || (format2 && maxStateRecords !== null && state.stateRecords.size >= maxStateRecords);
  const mode = isFull(state) ? "FULL" : inReserve(state) ? "RESERVED" : declaredReached ? "CONTROL_ONLY" : "OPEN";
  return Object.freeze({
    profile: state.format === "continuity-event/0.2" ? LEGACY_CAPACITY_PROFILE.version : CAPACITY_PROFILE,
    eventCount, maxEvents, mode, canDeclareJob: free >= JOB_FOOTPRINT && mode === "OPEN",
    lifecycleReserved: ledger.lifecycleReserved, declaredJobs, remainingPhysicalEvents: maxEvents === null ? null : Math.max(0, maxEvents - eventCount),
    ...(format2 ? {} : { controlAlwaysAdmitted: true as const }), pointInTimeOnly: true, grantsAuthority: false,
    stateRecords: format2 ? state.stateRecords.size : 0, maxStateRecords, reserved: inReserve(state) || isFull(state), dutyReserved: ledger.dutyReserved,
    fileBytes: format2 ? state.canonicalBytes : 0,
    reserveThresholds: Object.freeze({ stateRecords: limits.maxStateRecords - limits.reservedStateRecords, fileBytes: limits.maxFileBytes - limits.reservedFileBytes }),
    hardLimits: Object.freeze({ stateRecords: limits.maxStateRecords, fileBytes: limits.maxFileBytes }),
  });
};

/** Per-event bounds of the legacy managed profile (a single wide event cannot swallow the budget). */
const withinLegacyBounds = (event: CanonicalEvent): boolean => {
  let arrays = 0, valid = true;
  const visit = (value: unknown, depth: number): void => {
    if (depth > LEGACY_CAPACITY_PROFILE.maxEventDepth) { valid = false; return; }
    if (Array.isArray(value)) { arrays += value.length; for (const item of value) visit(item, depth + 1); }
    else if (value !== null && typeof value === "object") for (const item of Object.values(value)) visit(item, depth + 1);
  };
  visit(event, 0);
  return valid && arrays <= LEGACY_CAPACITY_PROFILE.maxEventArrayMembers && Buffer.byteLength(canonicalEncode(event)) <= LEGACY_CAPACITY_PROFILE.maxEventBytes;
};

/** Point-in-time capacity of a replayed history. Unlimited format-1 histories skip the lifecycle scan entirely. */
export function capacityOf(state: ReplayState): CapacityReport {
  if (!isFormat2(state.format) && maxEventsOf(state) === null) return report(state, state.events.length, newCapacityLedger(), state.intentDeclarations.size);
  return report(state, state.events.length, ledgerOf(state));
}

/**
 * SPEC §5.2 as amended by A-0/A-0.1/A-1/A-2/A-3 (format 2): the verdict on `event` as the next event of `state`, with
 * `lineBytes` the bytes its store line would add and `recordsAfter` = `R(p)`, the leaf count after the event (default:
 * the lower bound `R(p−1) + 1`, every accepted event adds its own `event` record). Order (first failure wins):
 * 1. absolute limits, every event: `R(p−1) ≥ HARD_RECORDS`, `R(p) > HARD_RECORDS`, `B(p) > HARD_BYTES` → `CAPACITY_EXCEEDED`;
 * 2. reserve, `RESERVE_CLASS` only, judged after the event: `R(p) > T_R` or `B(p) > T_B` → `CAPACITY_RESERVED`;
 * 3. declared `maxStateRecords`, non-control: `R(p) > maxStateRecords` → `CAPACITY_EXCEEDED`;
 * 4. declared `maxEvents`, non-control (A-2): not one of the format-1 engine's always-admitted non-control types, growth
 *    (`S(p) > S(p−1)`) and `S(p) > maxEvents` → `CAPACITY_CONTROL_ONLY`.
 * `ledger` is the state's unless the caller accounts a batch on a private copy. `undefined` = admitted. The verdict is
 * monotone in `recordsAfter` (a larger `R(p)` fails at the same or an earlier step).
 */
export function capacityVerdict(state: ReplayState, event: CanonicalEvent, lineBytes: number, ledger: CapacityLedger = ledgerOf(state), recordsAfter?: number): TransitionFailure | undefined {
  const before = state.stateRecords.size, after = recordsAfter ?? before + 1, bytesAfter = state.canonicalBytes + lineBytes;
  if (before >= limits.maxStateRecords) return { code: "CAPACITY_EXCEEDED", reason: `the history holds ${before} state records, the hard limit (${limits.maxStateRecords}); the history is terminal` };
  if (after > limits.maxStateRecords) return { code: "CAPACITY_EXCEEDED", reason: `the event would bring the history to ${after} state records, above the hard limit (${limits.maxStateRecords})` };
  if (bytesAfter > limits.maxFileBytes) return { code: "CAPACITY_EXCEEDED", reason: `the history file would exceed ${limits.maxFileBytes} bytes, the hard limit; the history is terminal` };
  if (!RESERVE_CLASS.has(event.type)) return undefined; // control events (and the genesis) are never refused by the reserve or a declared limit (A-1.3)
  const thresholdRecords = limits.maxStateRecords - limits.reservedStateRecords, thresholdBytes = limits.maxFileBytes - limits.reservedFileBytes;
  if (after > thresholdRecords) return { code: "CAPACITY_RESERVED", reason: `the event would bring the history to ${after} state records, inside the last ${limits.reservedStateRecords} below the hard limit, which admit control events only` };
  if (bytesAfter > thresholdBytes) return { code: "CAPACITY_RESERVED", reason: `the event would bring the history file inside the last ${limits.reservedFileBytes} bytes below the file cap, which admit control events only` };
  const maxStateRecords = maxStateRecordsOf(state);
  if (maxStateRecords !== null && after > maxStateRecords) return { code: "CAPACITY_EXCEEDED", reason: `the event would bring the history to ${after} state records, above its declared capacity.maxStateRecords (${maxStateRecords}); only control events are admitted` };
  const maxEvents = maxEventsOf(state);
  if (maxEvents === null || ALWAYS_ADMITTED_NON_CONTROL.has(event.type)) return undefined;
  // A-2: S(p) = eventCount + lifecycleReserved + dutyReserved after the event; growth iff S(p) > S(p−1), i.e. delta ≥ 0.
  const delta = reservationDelta(ledger, event);
  const after2 = state.events.length + 1 + ledger.lifecycleReserved + ledger.dutyReserved + delta;
  if (delta >= 0 && after2 > maxEvents) return { code: "CAPACITY_CONTROL_ONLY", reason: `history is full (${maxEvents} events): only control events and lifecycle records of declared jobs are admitted` };
  return undefined;
}

/**
 * The bounds of `R(p)` for `event` as the next event of `state` (format 2): `lower = R(p−1) + 1` (its own `event`
 * record) and an upper bound from the records the event can create (`upperRecordDelta`, state-records.ts).
 */
export type RecordBounds = Readonly<{ lower: number; upper: number }>;
/**
 * The writer's pre-signing verdict (A-1.1): the replay verdict when it is the same at both bounds of `R(p)` (it then
 * equals the exact one, by monotonicity), else `undefined` — the replay step at the append decides with the exact count
 * and the same code.
 */
export function boundedCapacityVerdict(state: ReplayState, event: CanonicalEvent, lineBytes: number, bounds: RecordBounds, ledger: CapacityLedger = ledgerOf(state)): TransitionFailure | undefined {
  const atLower = capacityVerdict(state, event, lineBytes, ledger, bounds.lower);
  const atUpper = bounds.upper === bounds.lower ? atLower : capacityVerdict(state, event, lineBytes, ledger, bounds.upper);
  return atLower?.code === atUpper?.code ? atLower : undefined;
}

/**
 * Refuse `next` when it would push the history past its budget. Always-admitted
 * types (revocations, terminations, epoch advances, receipts, obligation status
 * changes …) pass regardless; lifecycle records of declared jobs consume their
 * own reservation and therefore always fit. Format 2 applies `capacityVerdict`
 * (the replay rule) event by event over a private ledger, so a refused write is
 * reported with the replay's code before anything is signed.
 */
export function assertCapacityTransition(state: ReplayState, next: readonly CanonicalEvent[]): void {
  const legacy = state.format === "continuity-event/0.2";
  if (legacy && next.some((event) => !withinLegacyBounds(event))) throw new EngineError("CAPACITY_EVENT_LIMIT", "event exceeds the legacy per-event bounds");
  if (isFormat2(state.format)) {
    // A single event (the common write) reads the state's ledger as it is; a batch accounts on a private copy.
    const ledger = next.length > 1 ? cloneLedger(ledgerOf(state)) : ledgerOf(state);
    let records = state.stateRecords.size, bytes = state.canonicalBytes, count = state.events.length;
    for (const event of next) {
      const lineBytes = formatTwoLineBytes(count, Buffer.byteLength(canonicalEncode(event)));
      // Each event of a batch sees the records, bytes and events the earlier ones add (one `event` record each, at least).
      const view = Object.create(state, { stateRecords: { value: { size: records, has: (k: string) => state.stateRecords.has(k) } }, canonicalBytes: { value: bytes }, events: { value: { length: count } } }) as ReplayState;
      // A-1.1: refuse before signing only when the verdict does not depend on the exact R(p) (the replay at the append decides otherwise, with the same code).
      const upper = records + upperRecordDelta(state, event, count);
      const failure = boundedCapacityVerdict(view, event, lineBytes, { lower: records + 1, upper }, ledger);
      if (failure !== undefined) throw new EngineError(failure.code, failure.reason);
      if (next.length > 1) accountCapacity(ledger, event);
      records += 1; bytes += lineBytes; count += 1;
    }
    return;
  }
  const maxEvents = maxEventsOf(state);
  if (maxEvents === null) return;
  const r = scannedLedger(state);
  let count = state.events.length, committed = count + r.lifecycleReserved;
  for (const event of next) {
    accountCapacity(r, event);
    count += 1;
    const after = count + r.lifecycleReserved;
    // A lifecycle record spends its own reservation (committed space unchanged); only growth is subject to the budget.
    if (!ALWAYS_ADMITTED_EVENT_TYPES.has(event.type) && after > committed && after > maxEvents) {
      throw new EngineError("CAPACITY_CONTROL_ONLY", `history is full (${maxEvents} events): only revocations, terminations and lifecycle records are admitted`);
    }
    committed = after;
  }
}
