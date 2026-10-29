/**
 * Input capture for the local owner API (port of Core 0.3 `input.ts`).
 *
 * The facade accepts data, never behaviour: getters, proxies, symbols, cycles,
 * sparse arrays and executable object shapes are refused before any user code
 * could run. Errors thrown to callers are `IronTrellisError` (the Core 0.3
 * `ContinuityError`, kept as an alias) with a stable `code`.
 */
import { types } from "node:util";
import { captureValue, codePointLength, isProtocolString } from "./canonical.ts";

export type IronTrellisErrorCode =
  // Core 0.3 codes, all kept in the type for compatibility. CAPACITY_INCOMPATIBLE/BATCH/EXPECTED_HEAD and HISTORY_LIMIT are never
  // raised by this engine (docs/API.md §8: the 256/252/128-event caps are gone). CAPACITY_RESERVED is raised again for format 2:
  // the control-event reserve below the hard limits (SPEC §5.2 addendum; `capacity.ts`).
  | "CAPACITY_RESERVED"
  | "CAPACITY_INCOMPATIBLE"
  | "CAPACITY_EVENT_LIMIT"
  | "CAPACITY_BATCH_UNSUPPORTED"
  | "CAPACITY_EXPECTED_HEAD_REQUIRED"
  | "INVALID_INPUT"
  | "INVALID_HISTORY"
  | "HISTORY_LIMIT"
  | "HISTORY_EXISTS"
  | "PROFILE_MISMATCH"
  | "CLOCK_INVALID"
  | "HISTORY_CONFLICT"
  | "POLICY_EVIDENCE_UNAVAILABLE"
  | "RUNTIME_NOT_CURRENT"
  | "OPERATION_CONFLICT"
  | "SIGNER_FAILED"
  | "RECEIPT_UNAVAILABLE"
  /**
   * The writer declines a transition (SPEC §18 [A-8] [A-12]). Under an ATTESTED owner policy (A-172.2) `detail.reason` is
   * `ATTESTATION_EXPIRY` (`detail.expiresAt`: a session-signed or administrative event would pass an attestation's expiry,
   * A-109.1) or `ATTESTATION_HORIZON` (`detail.horizon`: a control event whose single human-class signer would advance time
   * past the attestation horizon, A-119.4).
   */
  | "TRANSITION_REJECTED"
  | "READ_UNAVAILABLE"
  | "WRITE_UNCONFIRMED"
  // IronTrellis additions (docs/API.md §11)
  | "ROLLBACK_DETECTED"
  | "CONTROL_AUTHORIZATION_INVALID"
  | "KEY_UNAVAILABLE"
  | "CAPACITY_CONTROL_ONLY"
  | "HISTORY_FILE_LIMIT"
  | "MIGRATION_UNSUPPORTED"
  | "KEY_EXISTS"
  | "ANCHOR_LOG_UNREADABLE"
  // Remote witnesses (docs/WITNESS.md)
  | "WITNESS_UNREADABLE"
  | "WITNESS_UNAVAILABLE"
  | "WITNESS_SPLIT_VIEW"
  | "WITNESS_REJECTED"
  // IronTrellis Core, format 2 (SPEC §18; G0 §2)
  /** A legacy or format-1 file, or a migrated source, refuses writes (`detail: {reason: "LEGACY" | "FORMAT_1" | "MIGRATED", target?}`). */
  | "FORMAT_READ_ONLY"
  /** CHALLENGE-PROFILE-01: a format-2 write while the process runs the verify-only `frozen-r2.3` challenge profile (`detail: {profile}`); nothing is written. */
  | "CHALLENGE_PROFILE_READ_ONLY"
  | "MIGRATION_MARKER_INVALID"
  /** Informational (reported, never thrown): a snapshot was discarded and rebuilt. */
  | "SNAPSHOT_STALE"
  /** Addendum A-19.4: the file is not the history the handle was configured for (`historyId` ≠ `recordHash(0)`). */
  | "HISTORY_IDENTITY_MISMATCH"
  /** Addendum A-20.3: a valid owner attestation (pin or anchor log) over a state root the history does not have — key misuse evidence. */
  | "ATTESTED_STATE_ROOT_MISMATCH"
  /** The API refuses to write a checkpoint whose root disagrees with its own state (a self-check that must never fire). */
  | "CHECKPOINT_MISMATCH"
  | "DUTY_WRITER_REQUIRED"
  /** SPEC §5.2: a hard limit (state records, file bytes) or the declared `maxStateRecords`. */
  | "CAPACITY_EXCEEDED"
  /** SPEC §10.2: the 65th effect of an intent. */
  | "EFFECT_LIMIT"
  /** SPEC §11.2: the counterparty envelope's signature does not verify. */
  | "COUNTERPARTY_SIGNATURE_INVALID"
  /** The writer re-derived the refusal before signing and the state decides otherwise (ALLOW, or another code). */
  | "REFUSAL_NOT_REPRODUCED"
  /** A-22.4: an enforcement reader found the head's time more than `maxClockSkewMs` (default 300 s) ahead of its clock; it denies regardless of failOpen. */
  | "CLOCK_AHEAD_OF_READER"
  /** A-29 / A-58.5: the signing session belongs to an earlier control epoch of its agent (format-2 replay code, passed through by the API). */
  | "SESSION_FENCED"
  /**
   * A-71.6 / A-86.2: `recordObservation`'s pre-check (and the replay code): an observation with this `(streamId, eventRef,
   * eventDigest)` is already accepted — recorded; the reconciler advances its checkpoint (`detail.position`, informative).
   */
  | "OBSERVATION_DUPLICATE"
  /**
   * The replay verdict code (SPEC Appendix A). Kept in this union for type compatibility; the API no longer throws it
   * (A-172.2): the A-109.1 / A-119.4 writer pre-checks refuse with `TRANSITION_REJECTED` and a `detail.reason`.
   */
  | "TRANSITION_INVALID";
/** @deprecated alias kept for one release; use `IronTrellisErrorCode`. */
export type ContinuityErrorCode = IronTrellisErrorCode;

export class IronTrellisError extends Error {
  readonly code: IronTrellisErrorCode;
  /** True when an I/O failure may have left bytes behind: inspect the file, never retry blindly. */
  readonly mayHaveCommitted: boolean;
  /** Machine-readable context for some codes (e.g. the administrative producer's `{ producerError: "PREPARE:POLICY_UNAVAILABLE", phase, code }`). */
  readonly detail: unknown;
  constructor(code: IronTrellisErrorCode, mayHaveCommitted = false, message?: string, detail?: unknown) {
    super(message ?? code);
    this.name = "IronTrellisError";
    this.code = code;
    this.mayHaveCommitted = mayHaveCommitted;
    this.detail = detail;
  }
}
/** @deprecated alias kept for one release; the class is `IronTrellisError`. */
export const ContinuityError = IronTrellisError;
export type ContinuityError = IronTrellisError;

export function requireCondition(value: unknown, code: IronTrellisErrorCode = "INVALID_INPUT"): asserts value {
  if (!value) throw new IronTrellisError(code);
}

/** Copy `input` from own data descriptors only; any accessor, proxy, symbol key, cycle or exotic shape is refused unread. */
export function captureData(input: unknown, maxBytes = 16_384, maxNodes = 2048, maxDepth = 16): unknown {
  let nodes = 0;
  const ancestors = new Set<object>();
  const copy = (value: unknown, depth: number): unknown => {
    requireCondition(++nodes <= maxNodes && depth <= maxDepth);
    if (value === null || ["string", "number", "bigint", "boolean"].includes(typeof value)) return value;
    requireCondition(typeof value === "object" && !types.isProxy(value) && !ancestors.has(value));
    const array = Array.isArray(value), proto = Object.getPrototypeOf(value);
    requireCondition(array ? proto === Array.prototype : proto === Object.prototype || proto === null);
    const keys = Reflect.ownKeys(value);
    requireCondition(keys.length <= maxNodes && keys.every((key) => typeof key === "string"));
    ancestors.add(value);
    try {
      if (array) {
        const length = Object.getOwnPropertyDescriptor(value, "length");
        requireCondition(length !== undefined && Object.hasOwn(length, "value") && Number.isSafeInteger(length.value) && length.value >= 0 && length.value <= maxNodes);
        requireCondition(keys.length === length.value + 1);
        const result: unknown[] = [];
        for (let i = 0; i < length.value; i++) {
          const d = Object.getOwnPropertyDescriptor(value, String(i));
          requireCondition(d !== undefined && d.enumerable && Object.hasOwn(d, "value"));
          result.push(copy(d.value, depth + 1));
        }
        return result;
      }
      const result: Record<string, unknown> = {};
      for (const key of keys as string[]) {
        const d = Object.getOwnPropertyDescriptor(value, key);
        requireCondition(d !== undefined && d.enumerable && Object.hasOwn(d, "value"));
        result[key] = copy(d.value, depth + 1);
      }
      return result;
    } finally {
      ancestors.delete(value);
    }
  };
  const copied = copy(input, 0);
  try {
    return captureValue(copied, { maxTotalBytes: maxBytes });
  } catch {
    throw new IronTrellisError("INVALID_INPUT");
  }
}

/** A closed record: every required key present, no key outside required ∪ optional. */
export function record(input: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  const value = captureData(input);
  requireCondition(value !== null && typeof value === "object" && !Array.isArray(value));
  const r = value as Record<string, unknown>;
  requireCondition(required.every((key) => Object.hasOwn(r, key)) && Object.keys(r).every((key) => required.includes(key) || optional.includes(key)));
  return r;
}
export function identifier(value: unknown): string {
  // Well-formed Unicode too: a lone surrogate otherwise passed here and escaped later as a raw CanonicalError. "1–128
  // characters" counts code points (A-89.2); the event grammar's UTF-8 byte bound still applies where the field is an Identifier.
  requireCondition(typeof value === "string" && value.length > 0 && codePointLength(value, 128) <= 128 && !/[\u0000-\u001f\u007f]/.test(value) && isProtocolString(value));
  return value;
}
export function time(value: unknown): number {
  requireCondition(typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0));
  return value;
}
export function identifiers(value: unknown): readonly string[] {
  requireCondition(Array.isArray(value) && value.length > 0 && value.length <= 32);
  const items = value.map(identifier);
  requireCondition(new Set(items).size === items.length);
  return Object.freeze(items);
}
export function amount(value: unknown): bigint {
  requireCondition(typeof value === "bigint" && value >= 0n && value < (1n << 256n));
  return value;
}
export function contentHash(value: unknown): `0x${string}` {
  requireCondition(typeof value === "string" && /^0x[0-9a-f]{64}$/.test(value));
  return value as `0x${string}`;
}
/** Keeps a field only when the caller supplied it (spread helper for optional event fields); `as` renames it. */
export const optional = <T>(r: Record<string, unknown>, key: string, convert: (value: unknown) => T, as: string = key): Record<string, T> =>
  Object.hasOwn(r, key) ? { [as]: convert(r[key]) } : {};
