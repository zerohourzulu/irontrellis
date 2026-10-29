/**
 * Event envelope and closed per-type data schemas (spec 01 §C) for both history
 * formats, plus the genesis probe, the format-1 control-authorization challenge
 * and the named-limit preflight that decides INVALID_INPUT vs EVENT_DATA_INVALID.
 *
 * Validation runs in two passes over a captured `data` record, exactly like the
 * reference engine: a preflight over *named limit slots* (identifier length,
 * bigint magnitude, list size) whose failures are LIMIT-branded, then the closed
 * schema pass that stops at the first defect. Replay maps LIMIT failures to
 * `INVALID_INPUT` and everything else to `EVENT_DATA_INVALID`.
 */
import { CanonicalError, captureValue, codePointLength, compareProtocolStrings, isAmountString, isProtocolString, RESERVED_KEY_PREFIX } from "./canonical.ts";
import { ed25519KeyCheck } from "./crypto/ed25519-point.ts";
import { suiteFor } from "./crypto/suites.ts";
import { HEAD_ATTESTATION_VERSION, verifyHeadAttestation } from "./signer.ts";
import { hashCanonical } from "./hash.ts";
import { ownerKeyDigest } from "./owner-key-digest.ts";
import { parseVerifierKey } from "./transparency/note.ts";
import {
  ADAPTER_POLICY_HASHES, REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION, resolveAdapterPolicy,
  validateAdapterAcknowledgmentShape, validateAdapterNoEffectShape, validateKnownAdapterProfile,
} from "./adapter-editions.ts";
import { ATTESTATION_POLICY_FIELDS, MAX_ADDITIONAL_CONTROL_AUTHORIZATIONS, ownerPolicyFailure } from "./owner-policy.ts";
import { CONTROL_EVENT_TYPES, EVENT_TYPES, FORMAT2_ONLY_EVENT_TYPES, TRELLIS_ONLY_EVENT_TYPES } from "./types.ts";
import type {
  AuthorizationDomain, CanonicalEvent, ContentHash, EventType, GenesisRecord, HashAlgorithm, HistoryFormat, HistoryHead, OwnerKey, OwnerPolicy, ReplayCode,
  SignatureScheme, U53,
} from "./types.ts";
import { readonlySet } from "./readonly-collections.ts";

export { ADAPTER_POLICY_HASHES };

export const LEGACY_FORMAT: HistoryFormat = "continuity-event/0.2";
export const TRELLIS_FORMAT: HistoryFormat = "irontrellis-event/1";
/** Format 2 (SPEC-IRONTRELLIS-CORE-v2). */
export const TRELLIS2_FORMAT: HistoryFormat = "irontrellis-event/2";
/** `true` for the owner-signed formats (1 and 2): owner keys, control signatures, pins, anchors and witnesses apply. */
export const isTrellis = (format: HistoryFormat): boolean => format !== LEGACY_FORMAT;
export const isFormat2 = (format: HistoryFormat): boolean => format === TRELLIS2_FORMAT;
export const ROOT_RECOGNITION_POLICY = "declared-principal-root/0.2";
export const CONTROL_AUTHORIZATION_VERSION = "irontrellis-control-authorization/1";
/** SPEC §6.1: the control challenge of format 2 (same fields, `previousHead` is the chain head). */
export const CONTROL_AUTHORIZATION_VERSION_2 = "irontrellis-control-authorization/2";
/** SPEC §8.6: the intent-declaration challenge of format 2. */
export const INTENT_DECLARATION_VERSION = "irontrellis-intent-declaration/2";
/** A-51.2: the challenge literal of the session signature on format-2 types 14–16. */
export const LIFECYCLE_AUTHORIZATION_VERSION = "irontrellis-lifecycle-authorization/2";
export const STATE_DERIVATION_VERSION = "irontrellis-state/2";
export const PROJECTION_VERSION = "irontrellis-projection/2";
export const MAX_EVENT_DATA_BYTES = 1_048_576;
/** Exact version literals a legacy genesis must declare (spec 01 §F.1). */
export const LEGACY_VERSIONS: Readonly<Record<string, string>> = Object.freeze({
  eventSchemaVersion: "continuity-event/0.2",
  receiptSchemaVersion: "continuity-receipt/0.2",
  queryEnvelopeVersion: "continuity-query-envelope/0.2",
  authorizationProofVersion: "continuity-authorization-proof/0.2",
  runtimeAuthorizationVersion: "continuity-runtime-authorization/0.2",
  administrativeAuthorizationVersion: "continuity-administrative-authorization/0.2",
  signatureScheme: "eip191-personal-sign-keccak256",
});
/**
 * Format-1 genesis versions (docs/reference/history-events.md §6.1). Every literal is the one actually used on the wire:
 * proofs, runtime/administrative challenges and query envelopes keep the reference's `continuity-…/0.2`
 * literals in format 1. `signatureScheme` is a choice, so it is validated separately.
 */
export const TRELLIS_VERSIONS: Readonly<Record<string, string>> = Object.freeze({
  eventSchemaVersion: "irontrellis-event/1",
  historyHashAlgorithm: "sha256",
  receiptSchemaVersion: "irontrellis-receipt/1",
  controlAuthorizationVersion: "irontrellis-control-authorization/1",
  queryEnvelopeVersion: "continuity-query-envelope/0.2",
  authorizationProofVersion: "continuity-authorization-proof/0.2",
  runtimeAuthorizationVersion: "continuity-runtime-authorization/0.2",
  administrativeAuthorizationVersion: "continuity-administrative-authorization/0.2",
});
/**
 * Format-2 genesis versions (SPEC §5.1): twelve keys, every value exact; `signatureScheme` is a choice and is
 * validated separately. Any other key, a missing key or a different value is `UNSUPPORTED_VERSION`.
 */
export const FORMAT2_VERSIONS: Readonly<Record<string, string>> = Object.freeze({
  eventSchemaVersion: "irontrellis-event/2",
  historyHashAlgorithm: "sha256",
  recordChainVersion: "irontrellis-record/2",
  stateDerivationVersion: "irontrellis-state/2",
  projectionVersion: "irontrellis-projection/2",
  receiptSchemaVersion: "irontrellis-receipt/2",
  controlAuthorizationVersion: "irontrellis-control-authorization/2",
  queryEnvelopeVersion: "continuity-query-envelope/0.2",
  authorizationProofVersion: "irontrellis-authorization-proof/2",
  runtimeAuthorizationVersion: "irontrellis-runtime-authorization/2",
  administrativeAuthorizationVersion: "irontrellis-administrative-authorization/2",
});
const TRELLIS_VERSION_KEYS = Object.freeze([...Object.keys(TRELLIS_VERSIONS), "signatureScheme"]);
const FORMAT2_VERSION_KEYS = Object.freeze([...Object.keys(FORMAT2_VERSIONS), "signatureScheme"]);
const LEGACY_VERSION_KEYS = Object.freeze(Object.keys(LEGACY_VERSIONS));
/** The exact version literals a genesis of `format` must declare (`signatureScheme` aside). */
export const expectedVersionsOf = (format: HistoryFormat): Readonly<Record<string, string>> =>
  format === TRELLIS2_FORMAT ? FORMAT2_VERSIONS : format === TRELLIS_FORMAT ? TRELLIS_VERSIONS : LEGACY_VERSIONS;
export const SIGNATURE_SCHEMES: readonly SignatureScheme[] = Object.freeze(["eip191-personal-sign-keccak256", "ed25519"]);
/** The administrative (▲) event types of legacy and format-1 histories (the reference kernel's seven; its message texts cite exactly these). */
export const ADMINISTRATIVE_EVENT_TYPES: readonly EventType[] = Object.freeze([
  "OBLIGATION_CREATED", "OBLIGATION_PERFORMANCE_ASSIGNED", "OBLIGATION_STATUS_RECORDED", "OUTCOME_OBSERVATION_RECORDED",
  "ATTEMPT_DUTY_CREATED", "ATTEMPT_DUTY_ASSIGNED", "ATTEMPT_DUTY_REVIEW_CLOSED",
]);
/** Format 2 (SPEC §5, §13): the seven plus the ported duty-policy events (types 29–31). */
export const FORMAT2_ADMINISTRATIVE_EVENT_TYPES: readonly EventType[] = Object.freeze([
  ...ADMINISTRATIVE_EVENT_TYPES, "ATTEMPT_DUTY_POLICY_ACTIVATED", "ATTEMPT_DUTY_DISPOSITION_RECORDED", "ATTEMPT_DUTY_CONTEST_RECORDED",
]);
export const administrativeEventTypesOf = (format: HistoryFormat): readonly EventType[] =>
  (format === TRELLIS2_FORMAT || (format === LEGACY_FORMAT && LEGACY_DUTY_POLICY_EVENTS) ? FORMAT2_ADMINISTRATIVE_EVENT_TYPES : ADMINISTRATIVE_EVENT_TYPES);
/**
 * SPEC §5 lists types 29–40 as `UNSUPPORTED_EVENT_TYPE` outside format 2; ruling A-28 makes that list informative for
 * legacy reads: a legacy (Continuity 0.2 / preview.10.x) history is read exactly as the frozen `reference-0.3` oracle reads
 * it, and the oracle (preview.10.2) writes and accepts types 29–31. This single switch therefore admits the three
 * duty-policy events in legacy histories (schema under the legacy literals, the transitions of `state.ts` with the legacy
 * hashes and domain, the legacy administrative challenge version); types 32–40 stay refused. Format 1 never carries them.
 */
export const LEGACY_DUTY_POLICY_EVENTS = true;
export const DUTY_POLICY_EVENT_TYPES: ReadonlySet<EventType> = readonlySet<EventType>(["ATTEMPT_DUTY_POLICY_ACTIVATED", "ATTEMPT_DUTY_DISPOSITION_RECORDED", "ATTEMPT_DUTY_CONTEST_RECORDED"]);
/** SPEC §13.0–13.2 literals (carried verbatim from Continuity preview.10.2). */
export const DUTY_POLICY_VERSION = "continuity-attempt-disposition/1";
export const DUTY_POLICY_RULES_HASH = "0xf7fb2b7de27abb77c6c3d03af6f61dce11afda5a510af20c8036085cd10a5f94";
export const DUTY_FINDING_VERSION = "continuity-duty-finding/1";
export const DUTY_CRITERIA = Object.freeze(["SOURCE_REVIEWED", "HISTORY_REVIEWED", "FINDING_RECORDED", "CONTROL_REVIEWED"]);
export const OBLIGATION_STATUSES = Object.freeze(["OPEN", "OUTCOME_UNKNOWN", "DISPUTED", "DISCHARGED", "IMPOSSIBLE_OR_ESCALATED"]);
/** The `data.anchor` literals of `ANCHOR_RECORDED` (the anchor kind). Remote witnesses are bound by their own events, never by an anchor. */
export const ANCHOR_NAMES = Object.freeze(["local-head-file", "rekor-v2", "custom"]);
/** At most this many remote witnesses are bound to a history, and named by one binding event. */
export const MAX_BOUND_WITNESSES = 16;
export { OWNER_KEY_DIGEST_VERSION, ownerKeyDigest } from "./owner-key-digest.ts";

export const formatOfSchemaVersion = (version: unknown): HistoryFormat | undefined =>
  version === LEGACY_FORMAT ? LEGACY_FORMAT : version === TRELLIS_FORMAT ? TRELLIS_FORMAT : version === TRELLIS2_FORMAT ? TRELLIS2_FORMAT : undefined;
export const isEventType = (value: unknown): value is EventType => typeof value === "string" && (EVENT_TYPES as readonly string[]).includes(value);
export const isControlEvent = (type: EventType): boolean => CONTROL_EVENT_TYPES.has(type);
export const hashAlgorithmOf = (format: HistoryFormat): HashAlgorithm => (isTrellis(format) ? "sha256" : "keccak256");

// ---------------------------------------------------------------- validator core

type Rec = Record<string, unknown>;
/**
 * `shadow`: the event sits in a migrated prefix and names the *source* format (docs/HISTORY-FORMAT.md §11; SPEC §16.2 step 3):
 * nested domains, literals and signatures keep the source's shapes (legacy shapes for a legacy source; format-1 shapes for
 * a format-1 source of a format-2 history), while the event's own envelope, Amount strings and format-2 fields follow `format`.
 */
type V = {
  format: HistoryFormat; shadow?: HistoryFormat; problem?: string; kind?: "SEMANTIC" | "LIMIT"; ghosts?: Map<object, readonly string[]>;
  /** Format 2: the event's position and the genesis `migratedFrom.position` (the positional rules of SPEC §8.6 and §16.2 step 2(c)/(d)). */
  position?: number; migratedUntil?: number;
  /** The event's timestamp (the genesis policy's `t_set`, A-93.2). */
  timestamp?: number;
};
const legacyShapes = (v: V): boolean => v.format === LEGACY_FORMAT || v.shadow === LEGACY_FORMAT;
/** The format whose literals and nested shapes a signed structure carries: the source's inside a migrated prefix. */
const shapesOf = (v: V): HistoryFormat => v.shadow ?? v.format;
const format2 = (v: V): boolean => v.format === TRELLIS2_FORMAT;
/** SPEC §16.2: a field allowed only inside a migrated prefix (`declarationAuthorization: null`, `sourceControlAuthorization`). */
const inMigratedPrefix = (v: V): boolean => v.position !== undefined && v.migratedUntil !== undefined && v.position <= v.migratedUntil;
const fail = (v: V, path: string, message: string): false => {
  if (v.problem === undefined) { v.problem = `${path}: ${message}`; v.kind = "SEMANTIC"; }
  return false;
};
const failLimit = (v: V, path: string, message: string): false => {
  if (v.kind !== "LIMIT") { v.problem = `${path}: ${message}`; v.kind = "LIMIT"; }
  return false;
};
const isPlainRecord = (value: unknown): value is Rec => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
};
/** Closed record: every own key declared, every required key present and not undefined. */
const rec = (v: V, value: unknown, path: string, required: readonly string[], optional: readonly string[] = []): Rec | undefined => {
  if (!isPlainRecord(value)) { fail(v, path, "must be a plain protocol record"); return undefined; }
  for (const key of Object.keys(value)) {
    if (!required.includes(key) && !optional.includes(key)) { fail(v, `${path}.${key}`, "is not a declared field"); return undefined; }
  }
  for (const key of v.ghosts?.get(value) ?? []) {
    if (!required.includes(key) && !optional.includes(key)) { fail(v, `${path}.${key}`, "is not a declared field"); return undefined; }
  }
  for (const key of required) {
    if (!Object.hasOwn(value, key) || value[key] === undefined) { fail(v, `${path}.${key}`, "is required"); return undefined; }
  }
  return value;
};

type Utf8Status = "VALID" | "MALFORMED" | "LIMIT";
const utf8Status = (value: string, maximumBytes: number): Utf8Status => {
  if (value.length > maximumBytes) return "LIMIT";
  let bytes = 0;
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit <= 0x7f) bytes += 1;
    else if (unit <= 0x7ff) bytes += 2;
    else if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return "MALFORMED";
      bytes += 4;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return "MALFORMED";
    else bytes += 3;
    if (bytes > maximumBytes) return "LIMIT";
  }
  return "VALID";
};
const MAX_BIGINT = (1n << 256n) - 1n;
const MAX_LOW_S = BigInt("0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");
const HEX64 = /^0x[0-9a-f]{64}$/;
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/u;

const identifier = (v: V, value: unknown, path: string): value is string => {
  if (typeof value !== "string") return fail(v, path, "must be an Identifier");
  const status = utf8Status(value, 256);
  if (status === "LIMIT") return failLimit(v, path, "must be an Identifier");
  if (status === "MALFORMED" || value.length === 0 || CONTROL_CHARS.test(value)) return fail(v, path, "must be an Identifier");
  return true;
};
const protocolString = (v: V, value: unknown, path: string): value is string => {
  if (typeof value !== "string") return fail(v, path, "must be a bounded ProtocolString");
  const status = utf8Status(value, 4096);
  if (status === "LIMIT") return failLimit(v, path, "must be a bounded ProtocolString");
  return status === "MALFORMED" ? fail(v, path, "must be a bounded ProtocolString") : true;
};
const u53 = (v: V, value: unknown, path: string): value is U53 =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0) ? true : fail(v, path, "must be a U53");
const amount = (v: V, value: unknown, path: string): value is bigint | string => {
  if (format2(v)) {
    // SPEC §3.3: a decimal string, ≤ 78 characters, ≤ 2^256−1, non-negative, no leading zero; a bigint (a marker record
    // decoded by capture) is a schema violation in format 2 (SPEC §3.1).
    return isAmountString(value) || fail(v, path, typeof value === "bigint" ? "must be an Amount string, not a bigint marker" : "must be an Amount");
  }
  if (typeof value !== "bigint") return fail(v, path, "must be an Amount");
  if (value < -MAX_BIGINT || value > MAX_BIGINT) return failLimit(v, path, "exceeds the 256-bit BigInt magnitude bound");
  return value < 0n ? fail(v, path, "must be an Amount") : true;
};
const contentHash = (v: V, value: unknown, path: string): value is ContentHash =>
  typeof value === "string" && HEX64.test(value) ? true : fail(v, path, "must be a lowercase ContentHash");
const ethereumAddress = (v: V, value: unknown, path: string): value is string =>
  typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value) ? true : fail(v, path, "must be an EthereumAddress");
const keyCheckProblem = (value: string): string | undefined => {
  const check = ed25519KeyCheck(Buffer.from(value.slice(2), "hex"));
  return check === "OK" ? undefined : `is not a usable Ed25519 key (${check}; A-32.2)`;
};
/**
 * An Ed25519 key (owner keys, a session's credentialPublicKey, a counterparty key). A-32.2 (format 2): a declared key is a
 * canonical encoding of a point that is not of small order and lies in the prime-order subgroup (EVENT_DATA_INVALID
 * otherwise). The schema stage tests the genesis owner keys and counterparty keys (rows 0, 36, 37); session and rotated
 * owner keys (`declared: false` here) are tested after control authorization (`declaredKeyFailure`, A-79.2). Legacy and
 * format-1 histories keep their format's rule (reported, never refused, A-28).
 */
const publicKeyHex = (v: V, value: unknown, path: string, declared = true): value is string => {
  if (!(typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value))) return fail(v, path, "must be a 32-byte public key");
  // A-157 (r4 §3.3 PublicKey32 = `0x` + 64 lowercase hex, a C4 grammar): a native format-2 event, or any event after a
  // migrated prefix, carrying a non-lowercase key is EVENT_DATA_INVALID here, before control authorization and the §3.3
  // point test; nothing is lowercased first. Inside a migrated format-1 prefix HF1's grammar (any case, compared
  // lowercase) applies as the source oracle applies it (A-52.1, A-28); legacy and format-1 histories keep their rule.
  if (v.format === TRELLIS2_FORMAT && v.shadow === undefined && !inMigratedPrefix(v) && !/^0x[0-9a-f]{64}$/.test(value)) return fail(v, path, "must be 0x + 64 lowercase hex (PublicKey32, r4 §3.3; A-157)");
  const problem = declared && v.format === TRELLIS2_FORMAT ? keyCheckProblem(value) : undefined;
  return problem === undefined || fail(v, path, problem);
};
/**
 * A-32.2 / A-79 (Appendix A rows 8 and 26): a format-2 session credential (8) and every Ed25519 key of a rotation (26) pass
 * the §3.3 declaration test, checked after control authorization (EVENT_DATA_INVALID; a dual fault is
 * CONTROL_AUTHORIZATION_INVALID). Inside a migrated prefix too: `migrate` refuses such a source (SOURCE_KEY_INVALID), so a
 * prefix never carries one (A-79.1).
 */
export const declaredKeyFailure = (event: CanonicalEvent): string | undefined => {
  const d = event.data as Rec;
  if (event.type === "RUNTIME_SESSION_ADMITTED") {
    const problem = d.credentialScheme === "ed25519" ? keyCheckProblem(d.credentialPublicKey as string) : undefined;
    return problem === undefined ? undefined : `$.data.credentialPublicKey: ${problem}`;
  }
  if (event.type !== "OWNER_KEYS_ROTATED") return undefined;
  const keys = d.ownerKeys as readonly Rec[];
  for (let index = 0; index < keys.length; index += 1) {
    const problem = keys[index]!.scheme === "ed25519" ? keyCheckProblem(keys[index]!.credential as string) : undefined;
    if (problem !== undefined) return `$.data.ownerKeys[${index}].credential: ${problem}`;
  }
  return undefined;
};
const chainId = (v: V, value: unknown, path: string): value is string => {
  if (typeof value !== "string" || !/^[1-9][0-9]*$/.test(value)) return fail(v, path, "must be a canonical ChainId string");
  const parsed = BigInt(value);
  return parsed < 1n || parsed > MAX_BIGINT ? fail(v, path, "is outside the ChainId bound") : true;
};
const isSignature65 = (value: unknown): value is string => {
  if (typeof value !== "string" || !/^0x[0-9a-f]{130}$/.test(value)) return false;
  const s = BigInt(`0x${value.slice(66, 130)}`);
  const recovery = value.slice(130, 132);
  return s !== 0n && s <= MAX_LOW_S && (recovery === "1b" || recovery === "1c");
};
const isSignature64 = (value: unknown): value is string => typeof value === "string" && /^0x[0-9a-f]{128}$/.test(value);
/** A runtime signature: legacy demands a low-s secp256k1 signature; format 1 also admits Ed25519's 64 bytes. */
const signature = (v: V, value: unknown, path: string): value is string => {
  if (isSignature65(value)) return true;
  if (!legacyShapes(v) && isSignature64(value)) return true;
  if (typeof value === "string" && /^0x[0-9a-f]{130}$/.test(value)) return fail(v, path, "must use a low-s value and recovery byte 27 or 28");
  return fail(v, path, "must be a lowercase 65-byte signature");
};
export const isHexSignature = (value: unknown, scheme: SignatureScheme): boolean => (scheme === "ed25519" ? isSignature64(value) : isSignature65(value));
const literal = (v: V, value: unknown, path: string, allowed: readonly string[]): value is string =>
  typeof value === "string" && allowed.includes(value) ? true : fail(v, path, `must be one of ${allowed.join(", ")}`);
const identifierList = (v: V, value: unknown, path: string, options: { nonempty?: boolean; maximum?: number } = {}): value is readonly string[] => {
  if (!Array.isArray(value)) return fail(v, path, "must be a dense Identifier list");
  const maximum = options.maximum ?? 4096;
  if (value.length > maximum) return failLimit(v, path, `exceeds the ${maximum}-member set bound`);
  if (options.nonempty === true && value.length === 0) return fail(v, path, "has invalid list cardinality");
  const seen = new Set<string>();
  for (let index = 0; index < value.length; index += 1) {
    const member: unknown = value[index];
    if (!identifier(v, member, `${path}[${index}]`)) return false;
    if (seen.has(member)) return fail(v, `${path}[${index}]`, "duplicates an Identifier");
    seen.add(member);
  }
  return true;
};
const strictlySorted = (ids: readonly string[]): boolean => ids.every((id, index) => index === 0 || compareProtocolStrings(ids[index - 1]!, id) < 0);
const reviewObservationIds = (v: V, value: unknown, path: string): boolean =>
  identifierList(v, value, path, { maximum: 128 }) && (strictlySorted(value) || fail(v, path, "must be strictly sorted"));
const enumList = (v: V, value: unknown, path: string, allowed: readonly string[], nonempty = false): value is readonly string[] => {
  if (!Array.isArray(value) || (nonempty && value.length === 0)) return fail(v, path, "must be a dense nonempty enum list");
  const seen = new Set<string>();
  for (let index = 0; index < value.length; index += 1) {
    const member: unknown = value[index];
    if (!literal(v, member, `${path}[${index}]`, allowed)) return false;
    if (seen.has(member)) return fail(v, `${path}[${index}]`, "duplicates a member");
    seen.add(member);
  }
  return true;
};

// ---------------------------------------------------------------- shared sub-records (spec 01 §C.5)

const domain = (v: V, value: unknown, path: string): boolean => {
  if (!legacyShapes(v)) {
    const r = rec(v, value, path, ["protocol", "version", "deploymentId"]);
    const version = shapesOf(v) === TRELLIS2_FORMAT ? "2" : "1";
    return r !== undefined && r.protocol === "irontrellis" && (r.version === version || fail(v, `${path}.version`, `must equal "${version}"`)) &&
      identifier(v, r.deploymentId, `${path}.deploymentId`);
  }
  const r = rec(v, value, path, ["protocol", "version", "deploymentId", "chainId", "verifyingContract"]);
  return r !== undefined && r.protocol === "continuity" && r.version === "0.2" &&
    identifier(v, r.deploymentId, `${path}.deploymentId`) && chainId(v, r.chainId, `${path}.chainId`) &&
    ethereumAddress(v, r.verifyingContract, `${path}.verifyingContract`);
};
const versionKeys = (v: V): readonly string[] => (format2(v) ? FORMAT2_VERSION_KEYS : v.format === TRELLIS_FORMAT ? TRELLIS_VERSION_KEYS : LEGACY_VERSION_KEYS);
/** Exact version literals; `UNSUPPORTED_*` codes are decided by the reducer from the probe, this is the closed schema. */
const versionSet = (v: V, value: unknown, path: string): boolean => {
  const r = rec(v, value, path, versionKeys(v));
  if (r === undefined) return false;
  const expected = expectedVersionsOf(v.format);
  for (const [key, expectedValue] of Object.entries(expected)) {
    if (r[key] !== expectedValue) return fail(v, `${path}.${key}`, `must equal ${expectedValue}`);
  }
  return v.format === LEGACY_FORMAT || literal(v, r.signatureScheme, `${path}.signatureScheme`, SIGNATURE_SCHEMES);
};
const declaredVersionSet = (v: V, value: unknown, path: string): value is Readonly<Record<string, string>> => {
  // Format 2 (SPEC §5.1): a missing or extra key is UNSUPPORTED_VERSION, decided by the reducer from the probe; the probe only needs identifier values.
  if (format2(v)) {
    if (!isPlainRecord(value)) return fail(v, path, "must be a plain protocol record");
    return Object.keys(value).every((key) => identifier(v, value[key], `${path}.${key}`));
  }
  const r = rec(v, value, path, versionKeys(v));
  return r !== undefined && versionKeys(v).every((key) => identifier(v, r[key], `${path}.${key}`));
};
const historyHead = (v: V, value: unknown, path: string): value is HistoryHead => {
  const r = rec(v, value, path, ["hash", "position", "canonicalTime"]);
  return r !== undefined && contentHash(v, r.hash, `${path}.hash`) && u53(v, r.position, `${path}.position`) && u53(v, r.canonicalTime, `${path}.canonicalTime`);
};
const actionRequest = (v: V, value: unknown, path: string): boolean => {
  // Format 2 (SPEC §8.2): `metric?` names the metric the amount is measured in.
  const r = rec(v, value, path, ["actorId", "action", "resource", "claimedAt"], format2(v) ? ["amount", "counterpartyId", "termsCommitment", "metric"] : ["amount", "counterpartyId", "termsCommitment"]);
  return r !== undefined && identifier(v, r.actorId, `${path}.actorId`) && identifier(v, r.action, `${path}.action`) &&
    identifier(v, r.resource, `${path}.resource`) && u53(v, r.claimedAt, `${path}.claimedAt`) &&
    (r.amount === undefined || amount(v, r.amount, `${path}.amount`)) &&
    (r.counterpartyId === undefined || identifier(v, r.counterpartyId, `${path}.counterpartyId`)) &&
    (r.termsCommitment === undefined || contentHash(v, r.termsCommitment, `${path}.termsCommitment`)) &&
    (r.metric === undefined || identifier(v, r.metric, `${path}.metric`));
};
const evidenceReference = (v: V, value: unknown, path: string): boolean => {
  if (!isPlainRecord(value) || typeof value.kind !== "string") return fail(v, path, "must be a tagged EvidenceReference record");
  switch (value.kind) {
    case "EVENT": {
      const r = rec(v, value, path, ["kind", "eventId", "eventType", "position", "historyHash"]);
      return r !== undefined && identifier(v, r.eventId, `${path}.eventId`) &&
        (isEventType(r.eventType) || fail(v, `${path}.eventType`, "is not an EventType")) &&
        u53(v, r.position, `${path}.position`) && contentHash(v, r.historyHash, `${path}.historyHash`);
    }
    case "AUTHORITY": {
      const r = rec(v, value, path, ["kind", "authorityId", "grantEventId"]);
      return r !== undefined && identifier(v, r.authorityId, `${path}.authorityId`) && identifier(v, r.grantEventId, `${path}.grantEventId`);
    }
    case "RUNTIME_CREDENTIAL": {
      const r = rec(v, value, path, ["kind", "keyId", "sessionId", "admissionEventId"]);
      return r !== undefined && identifier(v, r.keyId, `${path}.keyId`) && identifier(v, r.sessionId, `${path}.sessionId`) &&
        identifier(v, r.admissionEventId, `${path}.admissionEventId`);
    }
    case "RECEIPT_COMMITMENT": {
      const r = rec(v, value, path, ["kind", "receiptContentHash", "eventId", "position"]);
      return r !== undefined && contentHash(v, r.receiptContentHash, `${path}.receiptContentHash`) &&
        identifier(v, r.eventId, `${path}.eventId`) && u53(v, r.position, `${path}.position`);
    }
    case "EXTERNAL": {
      const r = rec(v, value, path, ["kind", "evidenceType", "reference", "attesterId"]);
      return r !== undefined && identifier(v, r.evidenceType, `${path}.evidenceType`) && identifier(v, r.reference, `${path}.reference`) &&
        identifier(v, r.attesterId, `${path}.attesterId`);
    }
    default:
      return fail(v, `${path}.kind`, "is not an EvidenceReference kind");
  }
};
const authorityConstraints = (v: V, value: unknown, path: string, intersectionMaximum = 32): boolean => {
  const r = rec(v, value, path, ["actions", "resources", "quantitative", "maxDelegationDepth", "requiredIntersectionIds"],
    ["notBefore", "expiresAt", "maxAmount", "maxCumulativeAmount", "maxTransactions"]);
  if (r === undefined) return false;
  if (Array.isArray(r.actions) && r.actions.length > 256) return failLimit(v, `${path}.actions`, "exceeds the 256-member action set bound");
  if (Array.isArray(r.resources) && r.resources.length > 256) return failLimit(v, `${path}.resources`, "exceeds the 256-member resource set bound");
  if (Array.isArray(r.requiredIntersectionIds) && r.requiredIntersectionIds.length > intersectionMaximum) {
    return failLimit(v, `${path}.requiredIntersectionIds`, `exceeds the ${intersectionMaximum}-member required-intersection bound`);
  }
  if (!identifierList(v, r.actions, `${path}.actions`, { nonempty: true, maximum: 256 }) ||
      !identifierList(v, r.resources, `${path}.resources`, { nonempty: true, maximum: 256 }) ||
      typeof r.quantitative !== "boolean" || !u53(v, r.maxDelegationDepth, `${path}.maxDelegationDepth`) ||
      !identifierList(v, r.requiredIntersectionIds, `${path}.requiredIntersectionIds`, { maximum: intersectionMaximum }) ||
      (r.notBefore !== undefined && !u53(v, r.notBefore, `${path}.notBefore`)) ||
      (r.expiresAt !== undefined && !u53(v, r.expiresAt, `${path}.expiresAt`)) ||
      (r.maxAmount !== undefined && !amount(v, r.maxAmount, `${path}.maxAmount`)) ||
      (r.maxCumulativeAmount !== undefined && !amount(v, r.maxCumulativeAmount, `${path}.maxCumulativeAmount`)) ||
      (r.maxTransactions !== undefined && !u53(v, r.maxTransactions, `${path}.maxTransactions`))) {
    if (v.problem === undefined && typeof r.quantitative !== "boolean") fail(v, `${path}.quantitative`, "must be boolean");
    return false;
  }
  if (r.quantitative === false && (r.maxAmount !== undefined || r.maxCumulativeAmount !== undefined)) {
    return fail(v, path, "nonquantitative constraints cannot carry amount ceilings");
  }
  return true;
};
const permissionGrant = (v: V, value: unknown, path: string): boolean => {
  const r = rec(v, value, path, ["kind", "authorityId", "grantorId", "granteeId", "rootAuthorityId", "independent", "constraints"], ["parentAuthorityId"]);
  return r !== undefined && r.kind === "PERMISSION" && identifier(v, r.authorityId, `${path}.authorityId`) &&
    identifier(v, r.grantorId, `${path}.grantorId`) && identifier(v, r.granteeId, `${path}.granteeId`) &&
    identifier(v, r.rootAuthorityId, `${path}.rootAuthorityId`) &&
    (r.parentAuthorityId === undefined || identifier(v, r.parentAuthorityId, `${path}.parentAuthorityId`)) &&
    (typeof r.independent === "boolean" || fail(v, `${path}.independent`, "must be boolean")) &&
    authorityConstraints(v, r.constraints, `${path}.constraints`);
};
const prohibitionGrant = (v: V, value: unknown, path: string): boolean => {
  if (!isPlainRecord(value) || value.kind !== "PROHIBITION") return fail(v, `${path}.kind`, "must be PROHIBITION");
  if (value.scope === "ROOT") {
    const r = rec(v, value, path, ["kind", "scope", "authorityId", "grantorId", "rootAuthorityId", "constraints"], ["subjectActorId", "parentAuthorityId"]);
    return r !== undefined && identifier(v, r.authorityId, `${path}.authorityId`) && identifier(v, r.grantorId, `${path}.grantorId`) &&
      identifier(v, r.rootAuthorityId, `${path}.rootAuthorityId`) &&
      (r.subjectActorId === undefined || identifier(v, r.subjectActorId, `${path}.subjectActorId`)) &&
      (r.parentAuthorityId === undefined || identifier(v, r.parentAuthorityId, `${path}.parentAuthorityId`)) &&
      authorityConstraints(v, r.constraints, `${path}.constraints`);
  }
  if (value.scope === "GLOBAL") {
    const r = rec(v, value, path, ["kind", "scope", "authorityId", "grantorId", "constraints"], ["subjectActorId"]);
    return r !== undefined && identifier(v, r.authorityId, `${path}.authorityId`) && identifier(v, r.grantorId, `${path}.grantorId`) &&
      (r.subjectActorId === undefined || identifier(v, r.subjectActorId, `${path}.subjectActorId`)) &&
      authorityConstraints(v, r.constraints, `${path}.constraints`);
  }
  return fail(v, `${path}.scope`, "must be ROOT or GLOBAL");
};
const authorityGrant = (v: V, value: unknown, path: string): boolean => {
  if (!isPlainRecord(value)) return fail(v, path, "must be an authority grant record");
  if (value.kind === "PERMISSION") return permissionGrant(v, value, path);
  if (value.kind === "PROHIBITION") return prohibitionGrant(v, value, path);
  return fail(v, `${path}.kind`, "must be PERMISSION or PROHIBITION");
};
const recognizedRoot = (v: V, value: unknown, path: string): boolean => {
  const keys = ["rootAuthorityId", "principalId", "principalRecognitionEventId", "rootGrantEventId"];
  const r = rec(v, value, path, keys);
  return r !== undefined && keys.every((key) => identifier(v, r[key], `${path}.${key}`));
};
const authorityUsage = (v: V, value: unknown, path: string): boolean => {
  const r = rec(v, value, path, ["authorityId", "admittedTransactionCount", "admittedCumulativeAmount"]);
  return r !== undefined && identifier(v, r.authorityId, `${path}.authorityId`) &&
    u53(v, r.admittedTransactionCount, `${path}.admittedTransactionCount`) && amount(v, r.admittedCumulativeAmount, `${path}.admittedCumulativeAmount`);
};
const authorityEvidence = (v: V, value: unknown, path: string): boolean => {
  const r = rec(v, value, path, ["authorityId", "grantEventId", "grantEventPosition"]);
  return r !== undefined && identifier(v, r.authorityId, `${path}.authorityId`) && identifier(v, r.grantEventId, `${path}.grantEventId`) &&
    u53(v, r.grantEventPosition, `${path}.grantEventPosition`);
};
/** A list of records with a distinct identifier field each; `member` validates each element. */
const distinctList = (v: V, value: readonly unknown[], path: string, member: (v: V, value: unknown, path: string) => boolean, idKey: string, duplicate: string): boolean => {
  const seen = new Set<unknown>();
  for (let index = 0; index < value.length; index += 1) {
    if (!member(v, value[index], `${path}[${index}]`)) return false;
    const id = (value[index] as Rec)[idKey];
    if (seen.has(id)) return fail(v, `${path}[${index}]`, duplicate);
    seen.add(id);
  }
  return true;
};
const permissionGrantList = (v: V, value: unknown, path: string, nonempty: boolean): boolean => {
  if (!Array.isArray(value)) return fail(v, path, "must be a bounded permission path");
  if (value.length > 32) return failLimit(v, path, "exceeds the 32-member authority-path bound");
  if (nonempty && value.length === 0) return fail(v, path, "must be a bounded permission path");
  return distinctList(v, value, path, permissionGrant, "authorityId", "duplicates a path authority");
};
const intersectionProof = (v: V, value: unknown, path: string): boolean => {
  const r = rec(v, value, path, ["requiredAuthorityId", "requiredByAuthorityIds", "recognizedRoot", "path", "effectiveConstraints"]);
  return r !== undefined && identifier(v, r.requiredAuthorityId, `${path}.requiredAuthorityId`) &&
    identifierList(v, r.requiredByAuthorityIds, `${path}.requiredByAuthorityIds`, { nonempty: true, maximum: 256 }) &&
    recognizedRoot(v, r.recognizedRoot, `${path}.recognizedRoot`) && permissionGrantList(v, r.path, `${path}.path`, true) &&
    authorityConstraints(v, r.effectiveConstraints, `${path}.effectiveConstraints`, 256);
};
const CONSEQUENTIAL_FIELDS = ["runtimeSessionId", "credentialKeyId", "controlEpoch", "roleId", "roleTenureId", "intentId", "nonce"] as const;
const authorizationProof = (v: V, value: unknown, path: string): boolean => {
  const r = rec(v, value, path, [
    "proofVersion", "domain", "policyVersion", "rootRecognitionPolicy", "historyHead", "evaluationTime", "request", "recognizedRoot", "permissionPath",
    "intersections", "effectiveConstraints", "controllingAuthorityIds", "usageSnapshot", "authorityEvidence", "checkedProhibitionIds", "consequential",
  ], CONSEQUENTIAL_FIELDS);
  if (r === undefined) return false;
  if (Array.isArray(r.intersections) && r.intersections.length > 256) return failLimit(v, `${path}.intersections`, "exceeds the 256-member proof-intersection bound");
  if (Array.isArray(r.usageSnapshot) && r.usageSnapshot.length > 256) return failLimit(v, `${path}.usageSnapshot`, "exceeds the 256-member authority-usage bound");
  if (Array.isArray(r.authorityEvidence) && r.authorityEvidence.length > 1024) return failLimit(v, `${path}.authorityEvidence`, "exceeds the 1024-member authority-evidence bound");
  if (r.proofVersion !== expectedVersionsOf(shapesOf(v)).authorizationProofVersion || !domain(v, r.domain, `${path}.domain`) ||
      !identifier(v, r.policyVersion, `${path}.policyVersion`) || r.rootRecognitionPolicy !== ROOT_RECOGNITION_POLICY ||
      !historyHead(v, r.historyHead, `${path}.historyHead`) || !u53(v, r.evaluationTime, `${path}.evaluationTime`) ||
      !actionRequest(v, r.request, `${path}.request`) || !recognizedRoot(v, r.recognizedRoot, `${path}.recognizedRoot`) ||
      !permissionGrantList(v, r.permissionPath, `${path}.permissionPath`, true) || !Array.isArray(r.intersections) ||
      !authorityConstraints(v, r.effectiveConstraints, `${path}.effectiveConstraints`, 256) ||
      !identifierList(v, r.controllingAuthorityIds, `${path}.controllingAuthorityIds`, { nonempty: true, maximum: 256 }) ||
      !Array.isArray(r.usageSnapshot) || !Array.isArray(r.authorityEvidence) || r.authorityEvidence.length === 0 ||
      !identifierList(v, r.checkedProhibitionIds, `${path}.checkedProhibitionIds`, { maximum: 256 }) || typeof r.consequential !== "boolean") {
    if (v.problem === undefined) fail(v, path, "contains an invalid AuthorizationProof field");
    return false;
  }
  if (!distinctList(v, r.intersections, `${path}.intersections`, intersectionProof, "requiredAuthorityId", "duplicates a required authority") ||
      !distinctList(v, r.usageSnapshot, `${path}.usageSnapshot`, authorityUsage, "authorityId", "duplicates an authority") ||
      !distinctList(v, r.authorityEvidence, `${path}.authorityEvidence`, authorityEvidence, "authorityId", "duplicates an authority")) return false;
  for (const field of CONSEQUENTIAL_FIELDS) {
    const present = Object.hasOwn(r, field) && r[field] !== undefined;
    if (present !== r.consequential) {
      return fail(v, `${path}.${field}`, r.consequential ? "is required for a consequential proof" : "must be absent from a nonconsequential proof");
    }
  }
  return !r.consequential || (
    identifier(v, r.runtimeSessionId, `${path}.runtimeSessionId`) && identifier(v, r.credentialKeyId, `${path}.credentialKeyId`) &&
    u53(v, r.controlEpoch, `${path}.controlEpoch`) && identifier(v, r.roleId, `${path}.roleId`) && identifier(v, r.roleTenureId, `${path}.roleTenureId`) &&
    identifier(v, r.intentId, `${path}.intentId`) && identifier(v, r.nonce, `${path}.nonce`));
};
const adapterProfile = (v: V, value: unknown, path: string): boolean => {
  const r = rec(v, value, path, ["profileId", "profileVersion", "descriptorHash"]);
  return r !== undefined && validateKnownAdapterProfile(r);
};
const RESULT_DIGESTS: Readonly<Record<string, string | undefined>> = Object.freeze({
  LOCAL_PACKET_CREATED: "manifestDigest", REMOTE_SERVICE_REPORTED: "reportDigest", LOCAL_DOCUMENT_RELEASED: "publicationManifestDigest", LOCAL_ENDPOINT_STATE_CHANGED: "transitionDigest",
});
const adapterEvidence = (v: V, value: unknown, path: string, noEffect = false): boolean => {
  const r = rec(v, value, path, ["schemaVersion", "kind", "adapterProfile", "domain", "intentId", "admissionHead", "idempotencyKey", "submissionFingerprint", "result"]);
  if (r === undefined || !adapterProfile(v, r.adapterProfile, `${path}.adapterProfile`) || !domain(v, r.domain, `${path}.domain`) ||
      !historyHead(v, r.admissionHead, `${path}.admissionHead`)) return false;
  const result = r.result;
  if (!isPlainRecord(result)) return false;
  if (noEffect) return rec(v, result, `${path}.result`, ["kind", "reference"]) !== undefined && validateAdapterNoEffectShape(r);
  if (result.kind === "SIMULATED_SUBMISSION") {
    if (rec(v, result, `${path}.result`, ["kind", "submissionReference"]) === undefined) return false;
  } else {
    const digestKey = typeof result.kind === "string" ? RESULT_DIGESTS[result.kind] : undefined;
    if (digestKey === undefined || rec(v, result, `${path}.result`, ["kind", digestKey]) === undefined ||
        rec(v, result[digestKey], `${path}.result.${digestKey}`, ["algorithm", "value"]) === undefined) return false;
  }
  return validateAdapterAcknowledgmentShape(r);
};
/** A session binding `{runtimeSessionId, credentialKeyId, controlEpoch}` plus `hash` and `signature` (SPEC §6.2, §8.6, §10, §11.2). */
const sessionAuthorization = (v: V, value: unknown, path: string, binding: boolean): boolean => {
  const r = rec(v, value, path, binding ? ["runtimeSessionId", "credentialKeyId", "controlEpoch", "hash", "signature"] : ["hash", "signature"]);
  return r !== undefined && (!binding || (identifier(v, r.runtimeSessionId, `${path}.runtimeSessionId`) && identifier(v, r.credentialKeyId, `${path}.credentialKeyId`) && u53(v, r.controlEpoch, `${path}.controlEpoch`))) &&
    contentHash(v, r.hash, `${path}.hash`) && signature(v, r.signature, `${path}.signature`);
};
/**
 * A-63.1 / A-78.1: types a migrated prefix of either source format never contains — rotations and witness bindings (26–28,
 * refused at plan time) and every format-2-only type from 32 on. A format-1 prefix also never contains 29–31; a legacy
 * prefix reads them as the oracle does (A-28). On replay: EVENT_DATA_INVALID at the schema stage, coded against `migratedFrom`.
 */
export const PREFIX_FORBIDDEN_TYPES: ReadonlySet<string> = readonlySet(["OWNER_KEYS_ROTATED", "WITNESSES_BOUND", "WITNESSES_UNBOUND", ...EVENT_TYPES.slice(32)]);
const prefixForbids = (v: V, type: EventType): boolean =>
  inMigratedPrefix(v) && (PREFIX_FORBIDDEN_TYPES.has(type) || (v.shadow === TRELLIS_FORMAT && DUTY_POLICY_EVENT_TYPES.has(type)));
/**
 * A-51.1 / A-52.1: native format-2 types 14–16 carry `data.recordAuthorization = {runtimeSessionId, credentialKeyId,
 * controlEpoch, hash, signature}` (nested, like `declarationAuthorization`; absence is EVENT_DATA_INVALID by the closed
 * schema); inside a migrated prefix (`1 … migratedFrom.position`) and in legacy/format-1 histories the key is absent
 * (present → EVENT_DATA_INVALID). The rule is keyed on the format and the presence of `migratedFrom` (A-52.5).
 */
const lifecycleSigned = (v: V): boolean => v.format === TRELLIS2_FORMAT && !inMigratedPrefix(v);
/** A-61.3: a type-16 record's inherited `runtimeSessionId`/`controlEpoch` equal its nested `recordAuthorization` values (schema, EVENT_DATA_INVALID). */
const receiptBindingConsistent = (v: V, r: Rec): boolean => {
  if (!lifecycleSigned(v)) return true;
  const nested = r.recordAuthorization as Rec;
  if (nested.runtimeSessionId !== r.runtimeSessionId) return fail(v, `${P}.recordAuthorization.runtimeSessionId`, "must equal the receipt's runtimeSessionId (A-61.3)");
  if (nested.controlEpoch !== r.controlEpoch) return fail(v, `${P}.recordAuthorization.controlEpoch`, "must equal the receipt's controlEpoch (A-61.3)");
  return true;
};
const lifecycleKeys = (v: V): readonly string[] => (lifecycleSigned(v) ? ["recordAuthorization"] : []);
const lifecycleAuthorization = (v: V, r: Rec): boolean => !lifecycleSigned(v) || sessionAuthorization(v, r.recordAuthorization, `${P}.recordAuthorization`, true);
const sessionBindingFields = (v: V, r: Rec, path: string): boolean =>
  identifier(v, r.runtimeSessionId, `${path}.runtimeSessionId`) && identifier(v, r.credentialKeyId, `${path}.credentialKeyId`) && u53(v, r.controlEpoch, `${path}.controlEpoch`);
const transactionIntent = (v: V, value: unknown, path: string): boolean => {
  const base = ["intentId", "nonce", "actorId", "action", "resource", "roleId", "roleTenureId", "adapterProfile"];
  // Format 2 (SPEC §8.6): `metric?` and the required `declarationAuthorization` (null only inside a migrated prefix, SPEC §16.2 step 2(d)).
  const r = format2(v) ? rec(v, value, path, [...base, "declarationAuthorization"], ["amount", "counterpartyId", "termsCommitment", "metric"])
    : rec(v, value, path, base, ["amount", "counterpartyId", "termsCommitment"]);
  if (r === undefined || !adapterProfile(v, r.adapterProfile, `${path}.adapterProfile`) ||
      !["intentId", "nonce", "actorId", "action", "resource", "roleId", "roleTenureId"].every((key) => identifier(v, r[key], `${path}.${key}`)) ||
      !(r.amount === undefined || amount(v, r.amount, `${path}.amount`)) ||
      !(r.counterpartyId === undefined || identifier(v, r.counterpartyId, `${path}.counterpartyId`)) ||
      !(r.termsCommitment === undefined || contentHash(v, r.termsCommitment, `${path}.termsCommitment`)) ||
      !(r.metric === undefined || identifier(v, r.metric, `${path}.metric`))) return false;
  if (!format2(v)) return true;
  if (r.declarationAuthorization === null) return inMigratedPrefix(v) || fail(v, `${path}.declarationAuthorization`, "may be null only inside the migrated prefix");
  // A-52.1: inside a migrated prefix the declaration is the transcribed source event: declarationAuthorization MUST be null.
  if (inMigratedPrefix(v)) return fail(v, `${path}.declarationAuthorization`, "must be null inside the migrated prefix (A-52.1)");
  return sessionAuthorization(v, r.declarationAuthorization, `${path}.declarationAuthorization`, true);
};
const obligationTransitionPolicy = (v: V, value: unknown, path: string): boolean => {
  const r = rec(v, value, path, ["fromStatus", "toStatus", "acceptedAttesterIds", "action", "requiredAuthorityIds"]);
  return r !== undefined && literal(v, r.fromStatus, `${path}.fromStatus`, OBLIGATION_STATUSES) && literal(v, r.toStatus, `${path}.toStatus`, OBLIGATION_STATUSES) &&
    identifierList(v, r.acceptedAttesterIds, `${path}.acceptedAttesterIds`, { nonempty: true, maximum: 256 }) && identifier(v, r.action, `${path}.action`) &&
    identifierList(v, r.requiredAuthorityIds, `${path}.requiredAuthorityIds`, { nonempty: true, maximum: 256 });
};
const obligationRecord = (v: V, value: unknown, path: string): boolean => {
  const r = rec(v, value, path, ["obligationId", "sourceIntentId", "causalReceiptContentHash", "durableRoleId", "creationRoleTenureId", "description", "trigger",
    "deadline", "status", "beneficiaryId", "termsCommitment", "performanceAssigneeId", "successionRuleId", "transitionPolicies"], ["counterpartyId"]);
  if (r === undefined) return false;
  if (!identifier(v, r.obligationId, `${path}.obligationId`) || !identifier(v, r.sourceIntentId, `${path}.sourceIntentId`) ||
      !contentHash(v, r.causalReceiptContentHash, `${path}.causalReceiptContentHash`) || !identifier(v, r.durableRoleId, `${path}.durableRoleId`) ||
      !identifier(v, r.creationRoleTenureId, `${path}.creationRoleTenureId`) || !protocolString(v, r.description, `${path}.description`) ||
      !identifier(v, r.trigger, `${path}.trigger`) || !u53(v, r.deadline, `${path}.deadline`) ||
      !literal(v, r.status, `${path}.status`, ["OPEN", "OUTCOME_UNKNOWN"]) || !identifier(v, r.beneficiaryId, `${path}.beneficiaryId`) ||
      (r.counterpartyId !== undefined && !identifier(v, r.counterpartyId, `${path}.counterpartyId`)) ||
      !contentHash(v, r.termsCommitment, `${path}.termsCommitment`) || !identifier(v, r.performanceAssigneeId, `${path}.performanceAssigneeId`) ||
      !identifier(v, r.successionRuleId, `${path}.successionRuleId`) || !Array.isArray(r.transitionPolicies) || r.transitionPolicies.length === 0) {
    if (v.problem === undefined) fail(v, path, "contains an invalid ObligationRecord field");
    return false;
  }
  const pairs = new Set<string>();
  for (let index = 0; index < r.transitionPolicies.length; index += 1) {
    const member: unknown = r.transitionPolicies[index];
    if (!obligationTransitionPolicy(v, member, `${path}.transitionPolicies[${index}]`)) return false;
    const pair = `${String((member as Rec).fromStatus)}\u0000${String((member as Rec).toStatus)}`;
    if (pairs.has(pair)) return fail(v, `${path}.transitionPolicies[${index}]`, "duplicates a status-transition pair");
    pairs.add(pair);
  }
  return true;
};
const administrativeChallenge = (v: V, value: unknown, path: string): boolean => {
  const r = rec(v, value, path, ["version", "domain", "request", "authoritative", "consequential", "evaluationTime", "policyVersion", "rootRecognitionPolicy",
    "eventHistoryHash", "eventHistoryPosition", "transitionEventId", "transitionEventType", "transitionEffectHash", "runtimeSessionId", "credentialKeyId",
    "controlEpoch", "roleId", "roleTenureId", "authorityProofHash"]);
  return r !== undefined && r.version === expectedVersionsOf(shapesOf(v)).administrativeAuthorizationVersion && domain(v, r.domain, `${path}.domain`) &&
    actionRequest(v, r.request, `${path}.request`) && (r.authoritative === true || fail(v, `${path}.authoritative`, "must be true")) &&
    (r.consequential === true || fail(v, `${path}.consequential`, "must be true")) && u53(v, r.evaluationTime, `${path}.evaluationTime`) &&
    identifier(v, r.policyVersion, `${path}.policyVersion`) && r.rootRecognitionPolicy === ROOT_RECOGNITION_POLICY &&
    contentHash(v, r.eventHistoryHash, `${path}.eventHistoryHash`) && u53(v, r.eventHistoryPosition, `${path}.eventHistoryPosition`) &&
    identifier(v, r.transitionEventId, `${path}.transitionEventId`) && literal(v, r.transitionEventType, `${path}.transitionEventType`, administrativeEventTypesOf(v.format)) &&
    contentHash(v, r.transitionEffectHash, `${path}.transitionEffectHash`) && identifier(v, r.runtimeSessionId, `${path}.runtimeSessionId`) &&
    identifier(v, r.credentialKeyId, `${path}.credentialKeyId`) && u53(v, r.controlEpoch, `${path}.controlEpoch`) &&
    identifier(v, r.roleId, `${path}.roleId`) && identifier(v, r.roleTenureId, `${path}.roleTenureId`) && contentHash(v, r.authorityProofHash, `${path}.authorityProofHash`);
};
const administrativeAuthorization = (v: V, value: unknown, path: string): boolean => {
  const r = rec(v, value, path, ["challenge", "authorityProof", "runtimeSignature"]);
  return r !== undefined && administrativeChallenge(v, r.challenge, `${path}.challenge`) && authorizationProof(v, r.authorityProof, `${path}.authorityProof`) &&
    signature(v, r.runtimeSignature, `${path}.runtimeSignature`);
};
const attemptDutyRecord = (v: V, value: unknown, path: string): boolean => {
  const r = rec(v, value, path, ["dutyId", "sourceIntentId", "sourceAdmissionEventId", "durableRoleId", "creationRoleTenureId", "description", "deadline", "performanceAssigneeId", "status"]);
  return r !== undefined && ["dutyId", "sourceIntentId", "sourceAdmissionEventId", "durableRoleId", "creationRoleTenureId"].every((key) => identifier(v, r[key], `${path}.${key}`)) &&
    protocolString(v, r.description, `${path}.description`) && u53(v, r.deadline, `${path}.deadline`) &&
    identifier(v, r.performanceAssigneeId, `${path}.performanceAssigneeId`) && literal(v, r.status, `${path}.status`, ["OPEN"]);
};
const ownerKeys = (v: V, value: unknown, path: string, declared = true): boolean => {
  if (!Array.isArray(value) || value.length === 0) return fail(v, path, "must be a nonempty owner-key list");
  if (value.length > 64) return failLimit(v, path, "exceeds the 64-member owner-key bound");
  const seen = new Set<unknown>();
  for (let index = 0; index < value.length; index += 1) {
    const p = `${path}[${index}]`;
    const r = rec(v, value[index], p, ["keyId", "scheme", "credential"]);
    if (r === undefined || !identifier(v, r.keyId, `${p}.keyId`) || !literal(v, r.scheme, `${p}.scheme`, SIGNATURE_SCHEMES) ||
        !(r.scheme === "ed25519" ? publicKeyHex(v, r.credential, `${p}.credential`, declared) : ethereumAddress(v, r.credential, `${p}.credential`))) return false;
    if (seen.has(r.keyId)) return fail(v, `${p}.keyId`, "duplicates an owner key id");
    seen.add(r.keyId);
  }
  return true;
};

/** Pre-rotation: 1..64 distinct next-key digests (`ownerKeyDigest`). */
const nextKeyDigests = (v: V, value: unknown, path: string): boolean => {
  if (!Array.isArray(value) || value.length === 0) return fail(v, path, "must be a nonempty next-key digest list");
  if (value.length > 64) return failLimit(v, path, "exceeds the 64-member next-key digest bound");
  const seen = new Set<unknown>();
  for (let index = 0; index < value.length; index += 1) {
    if (!contentHash(v, value[index], `${path}[${index}]`)) return false;
    if (seen.has(value[index])) return fail(v, `${path}[${index}]`, "duplicates a next-key digest");
    seen.add(value[index]);
  }
  return true;
};
/** Pre-rotation: 1..64 proofs of possession `{ keyId, scheme, signature }` by the keys a rotation reveals, one per key id. */
const nextKeyAuthorizations = (v: V, value: unknown, path: string): boolean => {
  if (!Array.isArray(value) || value.length === 0) return fail(v, path, "must be a nonempty next-key authorization list");
  if (value.length > 64) return failLimit(v, path, "exceeds the 64-member next-key authorization bound");
  const seen = new Set<unknown>();
  for (let index = 0; index < value.length; index += 1) {
    const p = `${path}[${index}]`;
    const r = rec(v, value[index], p, ["keyId", "scheme", "signature"]);
    if (r === undefined || !identifier(v, r.keyId, `${p}.keyId`) || !literal(v, r.scheme, `${p}.scheme`, SIGNATURE_SCHEMES)) return false;
    if (!isHexSignature(r.signature, r.scheme as SignatureScheme)) return fail(v, `${p}.signature`, `must be a lowercase ${r.scheme === "ed25519" ? "64" : "65"}-byte signature`);
    if (seen.has(r.keyId)) return fail(v, `${p}.keyId`, "duplicates a next-key authorization key id");
    seen.add(r.keyId);
  }
  return true;
};

/**
 * A commitment that names a key the history already declared can never be revealed (a declared key never returns under
 * a new id): the reason, or `undefined`. Shared by the genesis schema and the rotation rules.
 */
export const declaredDigestFailure = (what: string, declared: readonly Readonly<{ keyId: string; scheme: SignatureScheme; credential: string }>[], digests: readonly ContentHash[]): string | undefined => {
  for (const key of declared) {
    const digest = ownerKeyDigest(key);
    if (digests.includes(digest)) return `${what}: next-key digest ${digest} names owner key ${key.keyId}, which this history already declared; commit to a new key`;
  }
  return undefined;
};

// ---------------------------------------------------------------- owner approval policy and co-signatures (A-91.1, A-92.0; format 2)

/** A pre-composed reason (a path and its message) as the first failure. */
const failText = (v: V, text: string): false => {
  if (v.problem === undefined) { v.problem = text; v.kind = "SEMANTIC"; }
  return false;
};
const countIn = (v: V, value: unknown, path: string, low: number, high: number): boolean =>
  (typeof value === "number" && Number.isSafeInteger(value) && value >= low && value <= high) || fail(v, path, `must be an integer in ${low}..${high}`);
/** A nonempty map (a plain record whose keys are data, not field names); `member` checks each entry. */
const nonemptyMap = (v: V, value: unknown, path: string, member: (key: string, entry: unknown, at: string) => boolean): boolean => {
  if (!isPlainRecord(value)) return fail(v, path, "must be a nonempty map");
  const ghost = v.ghosts?.get(value)?.[0];
  if (ghost !== undefined) return fail(v, `${path}.${ghost}`, "must not be undefined");
  const keys = Object.keys(value);
  if (keys.length === 0) return fail(v, path, "must be a nonempty map");
  return keys.every((key) => member(key, value[key], `${path}.${key}`));
};
const boundedList = (v: V, value: unknown, path: string, high: number, member: (entry: unknown, at: string) => boolean): boolean => {
  if (!Array.isArray(value) || value.length === 0 || value.length > high) return fail(v, path, `must be a list of 1..${high} entries`);
  return value.every((entry, index) => member(entry, `${path}[${index}]`));
};
const ed25519Subject = (v: V, value: unknown, path: string): boolean => {
  const r = rec(v, value, path, ["keyId", "scheme", "credential"]);
  return r !== undefined && identifier(v, r.keyId, `${path}.keyId`) && literal(v, r.scheme, `${path}.scheme`, ["ed25519"]) && publicKeyHex(v, r.credential, `${path}.credential`, false);
};
/** A-93.1 / A-107.4 `HumanAttestation` (the shape at C4; its rules at the setting event, `attestationFailure`). */
const humanAttestation = (v: V, value: unknown, path: string): boolean => {
  const r = rec(v, value, path, ["version", "audience", "subject", "profile", "attesterKeyId", "evidenceDigest", "notBefore", "expiresAt", "signature"], ["historyId"]);
  return r !== undefined && literal(v, r.version, `${path}.version`, ["irontrellis-human-attestation/1"]) && domain(v, r.audience, `${path}.audience`) &&
    ed25519Subject(v, r.subject, `${path}.subject`) && identifier(v, r.profile, `${path}.profile`) && identifier(v, r.attesterKeyId, `${path}.attesterKeyId`) &&
    contentHash(v, r.evidenceDigest, `${path}.evidenceDigest`) && u53(v, r.notBefore, `${path}.notBefore`) && u53(v, r.expiresAt, `${path}.expiresAt`) &&
    (r.historyId === undefined || contentHash(v, r.historyId, `${path}.historyId`)) &&
    (isSignature64(r.signature) || fail(v, `${path}.signature`, "must be a lowercase 64-byte Ed25519 signature"));
};
/**
 * A-91.1 with A-97.1 (`recovery`): the closed `ownerPolicy` schema at C4 (`EVENT_DATA_INVALID`; ranges here, cross-field
 * rules in `ownerPolicyFailure`).
 */
const ownerPolicyShape = (v: V, value: unknown, path: string): boolean => {
  const r = rec(v, value, path, ["threshold"], ["byType", "keyClasses", "labels", "acknowledged", ...ATTESTATION_POLICY_FIELDS, "recovery"]);
  if (r === undefined || !countIn(v, r.threshold, `${path}.threshold`, 1, 64)) return false;
  if (r.byType !== undefined && !nonemptyMap(v, r.byType, `${path}.byType`, (_type, entry, at) => countIn(v, entry, at, 1, 64))) return false;
  if (r.keyClasses !== undefined && !nonemptyMap(v, r.keyClasses, `${path}.keyClasses`, (keyId, entry, at) => identifier(v, keyId, at) && literal(v, entry, at, ["HUMAN", "AGENT"]))) return false;
  const label = (keyId: string, entry: unknown, at: string): boolean => identifier(v, keyId, at) &&
    ((isProtocolString(entry) && entry.length > 0 && codePointLength(entry, 65) <= 64) || fail(v, at, "must be a label of 1..64 characters (A-89.2)"));
  if (r.labels !== undefined && !nonemptyMap(v, r.labels, `${path}.labels`, label)) return false;
  if (r.acknowledged !== undefined && !literal(v, r.acknowledged, `${path}.acknowledged`, ["SINGLE_SIGNER"])) return false;
  if (r.humanFloor !== undefined && !literal(v, r.humanFloor, `${path}.humanFloor`, ["DECLARED", "ATTESTED"])) return false;
  if (r.recovery !== undefined && !literal(v, r.recovery, `${path}.recovery`, ["COMMITTED_NEXT_KEYS"])) return false;
  if (r.attesters !== undefined && !boundedList(v, r.attesters, `${path}.attesters`, 16, (entry, at) => ed25519Subject(v, entry, at))) return false;
  return r.attestations === undefined || boundedList(v, r.attestations, `${path}.attestations`, 64, (entry, at) => humanAttestation(v, entry, at));
};
/** A-92.0 / A-95.2: `additionalControlAuthorizations`, 1..63 `{keyId, signature}` with either §3.3 Signature form (A-102 X-14). */
const additionalControlAuthorizations = (v: V, value: unknown, path: string): boolean =>
  boundedList(v, value, path, MAX_ADDITIONAL_CONTROL_AUTHORIZATIONS, (entry, at) => {
    const r = rec(v, entry, at, ["keyId", "signature"]);
    return r !== undefined && identifier(v, r.keyId, `${at}.keyId`) && (isSignature64(r.signature) || isSignature65(r.signature) || fail(v, `${at}.signature`, "must be a lowercase Signature"));
  });

// ---------------------------------------------------------------- remote witness bindings (WITNESSES_BOUND / WITNESSES_UNBOUND)

/**
 * A remote witness URL as the witness client normalises it: printable ASCII, `http://` or `https://`, an authority
 * without userinfo, no query, fragment or backslash, no trailing slash, at most 2048 characters.
 */
const witnessUrl = (v: V, value: unknown, path: string): boolean =>
  (typeof value === "string" && value.length <= 2048 && /^[\x21-\x7e]+$/.test(value) && /^https?:\/\/[^/@]+(?:\/.*)?$/.test(value) && !/[?#\\]/.test(value) && !value.endsWith("/")) ||
  fail(v, path, "must be a normalised http(s) witness URL");
const witnessVerifierKey = (v: V, value: unknown, path: string): value is string => {
  if (typeof value !== "string") return fail(v, path, "must be a note verifier key");
  try { parseVerifierKey(value); return true; } catch { return fail(v, path, "must be a note verifier key"); }
};
const boundWitness = (v: V, value: unknown, path: string): boolean => {
  const r = rec(v, value, path, ["url", "verifierKey"], ["name", "allowInsecureHttp", "registration"]);
  return r !== undefined && witnessUrl(v, r.url, `${path}.url`) && witnessVerifierKey(v, r.verifierKey, `${path}.verifierKey`) &&
    (r.name === undefined || identifier(v, r.name, `${path}.name`)) &&
    (r.allowInsecureHttp === undefined || r.allowInsecureHttp === true || fail(v, `${path}.allowInsecureHttp`, "must be true when present")) &&
    (r.registration === undefined || isPlainRecord(r.registration) || fail(v, `${path}.registration`, "must be a witness receipt record"));
};
/** The owner-signed policy minimum: quorum 1..16, requireOnOpen, maxUnwitnessedEvents >= 1 (a safe integer). */
const witnessPolicy = (v: V, value: unknown, path: string): boolean => {
  const r = rec(v, value, path, ["quorum", "requireOnOpen", "maxUnwitnessedEvents"]);
  return r !== undefined &&
    ((u53(v, r.quorum, `${path}.quorum`) && r.quorum >= 1 && r.quorum <= MAX_BOUND_WITNESSES) || fail(v, `${path}.quorum`, `must be an integer in 1..${MAX_BOUND_WITNESSES}`)) &&
    (typeof r.requireOnOpen === "boolean" || fail(v, `${path}.requireOnOpen`, "must be boolean")) &&
    ((u53(v, r.maxUnwitnessedEvents, `${path}.maxUnwitnessedEvents`) && r.maxUnwitnessedEvents >= 1) || fail(v, `${path}.maxUnwitnessedEvents`, "must be a positive integer"));
};
/** A dense list of 1..16 members, each checked by `member`, distinct by `keyOf`. */
const witnessList = (v: V, value: unknown, path: string, member: (v: V, value: unknown, path: string) => boolean, keyOf: (value: unknown) => unknown, what: string): boolean => {
  if (!Array.isArray(value)) return fail(v, path, `must be a nonempty ${what} list`);
  if (value.length > MAX_BOUND_WITNESSES) return failLimit(v, path, `exceeds the ${MAX_BOUND_WITNESSES}-member ${what} bound`);
  if (value.length === 0) return fail(v, path, `must be a nonempty ${what} list`);
  const seen = new Set<unknown>();
  for (let index = 0; index < value.length; index += 1) {
    if (!member(v, value[index], `${path}[${index}]`)) return false;
    const key = keyOf(value[index]);
    if (seen.has(key)) return fail(v, `${path}[${index}]`, "duplicates a verifier key");
    seen.add(key);
  }
  return true;
};
const acceptedLoss = (v: V, value: unknown, path: string): boolean => {
  const r = rec(v, value, path, ["reason", "heads"]);
  const lossHead = (v: V, item: unknown, at: string): boolean => {
    const h = rec(v, item, at, ["verifierKey", "head"]);
    return h !== undefined && witnessVerifierKey(v, h.verifierKey, `${at}.verifierKey`) && historyHead(v, h.head, `${at}.head`);
  };
  return r !== undefined && identifier(v, r.reason, `${path}.reason`) && witnessList(v, r.heads, `${path}.heads`, lossHead, (item) => (item as Rec).verifierKey, "accepted-loss head");
};

// ---------------------------------------------------------------- named-limit preflight (spec 01 §C.7)

type Limit = "I" | "B" | { r: Readonly<Record<string, Limit>> } | { l: Limit | undefined; max?: number | undefined; name?: string | undefined }
  | { t: string; common?: Limit; variants: Readonly<Record<string, Limit>> };
const R = (r: Readonly<Record<string, Limit>>): Limit => ({ r });
const L = (l: Limit | undefined, max?: number, name?: string): Limit => (max === undefined ? { l } : { l, max, name });
const T = (t: string, variants: Readonly<Record<string, Limit>>, common?: Limit): Limit => (common === undefined ? { t, variants } : { t, common, variants });
const ids = (...names: string[]): Readonly<Record<string, Limit>> => Object.fromEntries(names.map((n) => [n, "I"]));
const idSet = (name: string): Limit => L("I", 256, name);
const LIMIT_DOMAIN = R(ids("deploymentId"));
const LIMIT_ADAPTER_PROFILE = R(ids("profileId", "profileVersion"));
const LIMIT_DIGEST = R(ids("algorithm"));
const LIMIT_ADAPTER_EVIDENCE = R({ ...ids("schemaVersion", "kind", "intentId"), adapterProfile: LIMIT_ADAPTER_PROFILE, domain: LIMIT_DOMAIN,
  result: R({ kind: "I", reportDigest: LIMIT_DIGEST, publicationManifestDigest: LIMIT_DIGEST, manifestDigest: LIMIT_DIGEST, transitionDigest: LIMIT_DIGEST }) });
const LIMIT_VERSION_SET = R(ids(...LEGACY_VERSION_KEYS, ...TRELLIS_VERSION_KEYS, ...FORMAT2_VERSION_KEYS));
const LIMIT_ACTION_REQUEST = R({ ...ids("actorId", "action", "resource", "counterpartyId", "metric"), amount: "B" });
const LIMIT_EVIDENCE_REFERENCE = T("kind", {
  EVENT: R(ids("eventId")), AUTHORITY: R(ids("authorityId", "grantEventId")), RUNTIME_CREDENTIAL: R(ids("keyId", "sessionId", "admissionEventId")),
  RECEIPT_COMMITMENT: R(ids("eventId")), EXTERNAL: R(ids("evidenceType", "reference", "attesterId")),
});
const limitConstraints = (n: number): Limit => R({ actions: idSet("action set"), resources: idSet("resource set"),
  requiredIntersectionIds: L("I", n, "required-intersection set"), maxAmount: "B", maxCumulativeAmount: "B" });
const LIMIT_GRANT_CONSTRAINTS = limitConstraints(32);
const LIMIT_PERMISSION_GRANT = R({ ...ids("authorityId", "grantorId", "granteeId", "rootAuthorityId", "parentAuthorityId"), constraints: LIMIT_GRANT_CONSTRAINTS });
const LIMIT_AUTHORITY_GRANT = T("kind", {
  PERMISSION: R(ids("granteeId", "rootAuthorityId", "parentAuthorityId")),
  PROHIBITION: T("scope", { ROOT: R(ids("rootAuthorityId", "parentAuthorityId")), GLOBAL: R({}) }, R(ids("subjectActorId"))),
}, R({ ...ids("authorityId", "grantorId"), constraints: LIMIT_GRANT_CONSTRAINTS }));
const LIMIT_RECOGNIZED_ROOT = R(ids("rootAuthorityId", "principalId", "principalRecognitionEventId", "rootGrantEventId"));
const LIMIT_PERMISSION_PATH = L(LIMIT_PERMISSION_GRANT, 32, "authority path");
const LIMIT_AUTHORIZATION_PROOF = R({
  domain: LIMIT_DOMAIN, policyVersion: "I", request: LIMIT_ACTION_REQUEST, recognizedRoot: LIMIT_RECOGNIZED_ROOT, permissionPath: LIMIT_PERMISSION_PATH,
  intersections: L(R({ requiredAuthorityId: "I", requiredByAuthorityIds: idSet("required-by authority set"), recognizedRoot: LIMIT_RECOGNIZED_ROOT,
    path: LIMIT_PERMISSION_PATH, effectiveConstraints: limitConstraints(256) }), 256, "proof-intersection set"),
  effectiveConstraints: limitConstraints(256), controllingAuthorityIds: idSet("controlling-authority set"),
  usageSnapshot: L(R({ authorityId: "I", admittedCumulativeAmount: "B" }), 256, "authority-usage set"),
  authorityEvidence: L(R(ids("authorityId", "grantEventId")), 1024, "authority-evidence set"),
  checkedProhibitionIds: idSet("checked-prohibition set"), ...ids("runtimeSessionId", "credentialKeyId", "roleId", "roleTenureId", "intentId", "nonce"),
});
const LIMIT_TRANSACTION_INTENT = R({ adapterProfile: LIMIT_ADAPTER_PROFILE, ...ids("intentId", "nonce", "actorId", "action", "resource", "roleId", "roleTenureId", "counterpartyId", "metric"), amount: "B",
  declarationAuthorization: R(ids("runtimeSessionId", "credentialKeyId")) });
const LIMIT_OBLIGATION_RECORD = R({ ...ids("obligationId", "sourceIntentId", "durableRoleId", "creationRoleTenureId", "trigger", "beneficiaryId", "counterpartyId", "performanceAssigneeId", "successionRuleId"),
  transitionPolicies: L(R({ acceptedAttesterIds: idSet("accepted-attester set"), action: "I", requiredAuthorityIds: idSet("required-authority set") })) });
const LIMIT_ADMINISTRATIVE_AUTHORIZATION = R({
  challenge: R({ domain: LIMIT_DOMAIN, request: LIMIT_ACTION_REQUEST, ...ids("policyVersion", "transitionEventId", "runtimeSessionId", "credentialKeyId", "roleId", "roleTenureId") }),
  authorityProof: LIMIT_AUTHORIZATION_PROOF,
});
const ADMIN = { administrativeAuthorization: LIMIT_ADMINISTRATIVE_AUTHORIZATION };
const LIMIT_BUDGET_SUBJECTS = R({ actorIds: idSet("actor set"), roleIds: idSet("role set"), actions: idSet("action set"), resources: idSet("resource set") });
const LIMIT_DUTY_DISPOSITION = R({
  ...ids("actorId", "dutyId", "dispositionAuthorityId"), ...ADMIN,
  finding: R({ challenge: R({ domain: LIMIT_DOMAIN, ...ids("activationEventId", "dutyId", "sourceAdmissionEventId", "transitionEventId", "latestAssignmentEventId", "previousDispositionEventId",
    "attesterId", "runtimeSessionId", "credentialKeyId", "roleId", "roleTenureId", "attestationAuthorityId", "dispositionAuthorityId") }) }),
});
const NAMED_LIMITS: Readonly<Record<EventType, Limit>> = Object.freeze({
  DEPLOYMENT_INITIALIZED: R({
    domain: LIMIT_DOMAIN, ...ids("canonicalLineageId", "policyVersion", "globalPolicySourceId"), versions: LIMIT_VERSION_SET, ownerKeys: L(R(ids("keyId")), 64, "owner-key set"),
    nextKeyDigests: L(undefined, 64, "next-key digest set"),
  }),
  PRINCIPAL_CREATED: R(ids("principalId")),
  AGENT_CREATED: R(ids("agentId", "principalId", "controllerId")),
  ROLE_CREATED: R(ids("roleId", "principalId")),
  SUCCESSION_RULE_DECLARED: R(ids("ruleId", "principalId", "predecessorAgentId", "successorAgentId", "roleId")),
  AGENT_APPOINTED: R(ids("agentId", "roleId", "roleTenureId", "principalId", "successionRuleId")),
  AGENT_UNAPPOINTED: R(ids("agentId", "roleId", "roleTenureId", "principalId")),
  ROLE_TRANSFERRED: R(ids("roleId", "fromAgentId", "fromRoleTenureId", "toAgentId", "toRoleTenureId", "principalId", "successionRuleId")),
  RUNTIME_SESSION_ADMITTED: R(ids("sessionId", "agentId", "controllerId", "credentialKeyId")),
  CONTROL_EPOCH_ADVANCED: R(ids("agentId", "controllerId")),
  AUTHORITY_GRANTED: R({ grant: LIMIT_AUTHORITY_GRANT }),
  AUTHORITY_REVOKED: R(ids("authorityId", "revokerId")),
  TRANSACTION_INTENT_DECLARED: LIMIT_TRANSACTION_INTENT,
  TRANSACTION_INTENT_ADMITTED: R({ intentId: "I", authorizationProof: LIMIT_AUTHORIZATION_PROOF }),
  TRANSACTION_INTENT_CONSUMED: R({ ...ids("intentId", "adapterId", "transactionReference"), acknowledgment: LIMIT_ADAPTER_EVIDENCE, evidenceReference: LIMIT_EVIDENCE_REFERENCE }),
  TRANSACTION_OUTCOME_RECORDED: R({ ...ids("intentId", "attesterId"), noEffect: LIMIT_ADAPTER_EVIDENCE, evidenceReference: LIMIT_EVIDENCE_REFERENCE }),
  RECEIPT_RECORDED: R(ids("intentId", "issuerAgentId", "runtimeSessionId", "roleId", "roleTenureId")),
  OBLIGATION_CREATED: R({ record: LIMIT_OBLIGATION_RECORD, actorId: "I", ...ADMIN }),
  OBLIGATION_PERFORMANCE_ASSIGNED: R({ ...ids("obligationId", "fromAgentId", "toAgentId", "successionRuleId", "actorId"), ...ADMIN }),
  OBLIGATION_STATUS_RECORDED: R({ ...ids("obligationId", "actorId", "action", "attesterId"), ...ADMIN, evidenceReference: LIMIT_EVIDENCE_REFERENCE }),
  AGENT_TERMINATED: R(ids("agentId", "principalId", "successionRuleId", "roleId", "roleTenureId")),
  OUTCOME_OBSERVATION_RECORDED: R({ ...ids("intentId", "sourceAdmissionEventId", "actorId"), acknowledgment: LIMIT_ADAPTER_EVIDENCE, ...ADMIN }),
  ATTEMPT_DUTY_CREATED: R({ record: R(ids("dutyId", "sourceIntentId", "sourceAdmissionEventId", "durableRoleId", "creationRoleTenureId", "performanceAssigneeId")), actorId: "I", ...ADMIN }),
  ATTEMPT_DUTY_ASSIGNED: R({ ...ids("dutyId", "fromAgentId", "toAgentId", "actorId"), ...ADMIN }),
  ATTEMPT_DUTY_REVIEW_CLOSED: R({ ...ids("dutyId", "actorId"), observationEventIds: L("I", 128, "attempt-review-observations"), ...ADMIN }),
  ANCHOR_RECORDED: R(ids("anchor")),
  OWNER_KEYS_ROTATED: R({
    ownerKeys: L(R(ids("keyId")), 64, "owner-key set"), reason: "I", nextKeyDigests: L(undefined, 64, "next-key digest set"),
    nextKeyAuthorizations: L(R(ids("keyId")), 64, "next-key authorization set"),
  }),
  WITNESSES_BOUND: R({ witnesses: L(R(ids("name")), MAX_BOUND_WITNESSES, "remote witness set") }),
  WITNESSES_UNBOUND: R({ verifierKeys: L(undefined, MAX_BOUND_WITNESSES, "remote witness set"), acceptedLoss: R({ reason: "I", heads: L(undefined, MAX_BOUND_WITNESSES, "accepted-loss head set") }) }),
  // ---- format 2 (SPEC §5 types 29–40); format-2 Amounts are strings, so "B" nodes are inert for them
  ATTEMPT_DUTY_POLICY_ACTIVATED: R({ ...ids("actorId", "activationAuthorityId"), descriptor: R({ domain: LIMIT_DOMAIN, ...ids("dutyId", "dutyCreationEventId", "sourceIntentId", "sourceAdmissionEventId", "durableRoleId", "principalId", "acceptedAttesterRoleId") }), ...ADMIN }),
  ATTEMPT_DUTY_DISPOSITION_RECORDED: LIMIT_DUTY_DISPOSITION,
  ATTEMPT_DUTY_CONTEST_RECORDED: LIMIT_DUTY_DISPOSITION,
  BUDGET_DECLARED: R({ ...ids("budgetId", "metric"), subjects: LIMIT_BUDGET_SUBJECTS }),
  BUDGET_UPDATED: R({ ...ids("budgetId"), subjects: LIMIT_BUDGET_SUBJECTS }),
  BUDGET_CLOSED: R(ids("budgetId")),
  STATE_CHECKPOINT: R(ids("checkpointId")),
  COUNTERPARTY_REGISTERED: R({ ...ids("counterpartyId"), keys: L(R(ids("keyId")), 16, "counterparty-key set") }),
  COUNTERPARTY_RETIRED: R(ids("counterpartyId")),
  REQUEST_REFUSED: R({ ...ids("refusalId", "code", "budgetId", "runtimeSessionId", "credentialKeyId"), request: LIMIT_ACTION_REQUEST, connector: R(ids("connectorId", "refusalCode")) }),
  EFFECT_RECORDED: R({ ...ids("effectId", "intentId", "metric", "unit", "runtimeSessionId", "credentialKeyId"), measurer: R(ids("id")) }),
  COUNTERPARTY_RECEIPT_RECORDED: R({ ...ids("intentId", "runtimeSessionId", "credentialKeyId"), envelope: R(ids("counterpartyId", "keyId", "logicalId")) }),
  RECONCILIATION_OBSERVED: R({ ...ids("observationId", "reconcilerAgentId", "runtimeSessionId", "credentialKeyId"), source: R(ids("streamId", "eventRef")), call: R({ ...ids("actorId", "action"), unsupplied: L("I") }) }),
});
const preflight = (v: V, value: unknown, path: string, node: Limit): boolean => {
  if (node === "I") return typeof value !== "string" || utf8Status(value, 256) !== "LIMIT" || failLimit(v, path, "must be an Identifier");
  if (node === "B") return typeof value !== "bigint" || (value >= -MAX_BIGINT && value <= MAX_BIGINT) || failLimit(v, path, "exceeds the 256-bit BigInt magnitude bound");
  if ("r" in node) {
    if (!isPlainRecord(value)) return true;
    for (const [name, child] of Object.entries(node.r)) {
      if (Object.hasOwn(value, name) && value[name] !== undefined && !preflight(v, value[name], `${path}.${name}`, child)) return false;
    }
    return true;
  }
  if ("l" in node) {
    if (!Array.isArray(value)) return true;
    if (node.max !== undefined && value.length > node.max) return failLimit(v, path, `exceeds the ${node.max}-member ${node.name ?? "named list"} bound`);
    if (node.l === undefined) return true;
    for (let index = 0; index < value.length; index += 1) if (!preflight(v, value[index], `${path}[${index}]`, node.l)) return false;
    return true;
  }
  if (!isPlainRecord(value)) return true;
  if (node.common !== undefined && !preflight(v, value, path, node.common)) return false;
  const tag = value[node.t];
  const variant = typeof tag === "string" ? node.variants[tag] : undefined;
  return variant === undefined || preflight(v, value, path, variant);
};

// ---------------------------------------------------------------- per-type data shapes (spec 01 §C.6)

const P = "$.data";
const idFields = (v: V, r: Rec, ...keys: string[]): boolean => keys.every((key) => identifier(v, r[key], `${P}.${key}`));
const GENESIS_REQUIRED = ["domain", "adapterPolicyHash", "canonicalLineageId", "versions", "policyVersion", "rootRecognitionPolicy", "globalPolicySourceId", "timeSource", "finality"];
/** The optional genesis keys of format 2 (SPEC §5 row 0); the portable query probe (`queries.ts`) reads the same list. */
export const FORMAT2_GENESIS_OPTIONAL_KEYS: readonly string[] = Object.freeze(["nextKeyDigests", "capacity", "migratedFrom", "checkpointPolicy", "projection", "ownerPolicy", "sessionTimeHorizonMs"]);
const genesisKeys = (v: V): readonly [readonly string[], readonly string[]] =>
  format2(v) ? [[...GENESIS_REQUIRED, "ownerKeys"], FORMAT2_GENESIS_OPTIONAL_KEYS]
    : v.format === TRELLIS_FORMAT ? [[...GENESIS_REQUIRED, "ownerKeys"], ["nextKeyDigests", "capacity", "migratedFrom"]] : [GENESIS_REQUIRED, []];
const genesisData = (v: V, value: unknown): boolean => {
  const trellis = isTrellis(v.format);
  const [required, optional] = genesisKeys(v);
  const r = rec(v, value, P, required, optional);
  if (r === undefined || !domain(v, r.domain, `${P}.domain`) || resolveAdapterPolicy(r.adapterPolicyHash) === undefined ||
      !identifier(v, r.canonicalLineageId, `${P}.canonicalLineageId`) || !versionSet(v, r.versions, `${P}.versions`) ||
      !identifier(v, r.policyVersion, `${P}.policyVersion`) || r.rootRecognitionPolicy !== ROOT_RECOGNITION_POLICY ||
      r.timeSource !== "EVENT_TIMESTAMP" || r.finality !== "LOCAL_ONLY" || !identifier(v, r.globalPolicySourceId, `${P}.globalPolicySourceId`)) return false;
  if (!trellis) return true;
  if (!ownerKeys(v, r.ownerKeys, `${P}.ownerKeys`)) return false;
  if (r.nextKeyDigests !== undefined) {
    // Pre-rotation from the start: epoch 0's commitment, committed by the history id. It may not name a genesis owner key.
    if (!nextKeyDigests(v, r.nextKeyDigests, `${P}.nextKeyDigests`)) return false;
    const clash = declaredDigestFailure("genesis", r.ownerKeys as readonly OwnerKey[], r.nextKeyDigests as readonly ContentHash[]);
    if (clash !== undefined) return fail(v, `${P}.nextKeyDigests`, clash);
  }
  if (r.ownerPolicy !== undefined && !ownerPolicyShape(v, r.ownerPolicy, `${P}.ownerPolicy`)) return false;
  if (r.capacity !== undefined) {
    // Format 2 (SPEC §5.1): `maxStateRecords?` caps the §7.2 state records.
    const c = rec(v, r.capacity, `${P}.capacity`, ["maxEvents"], format2(v) ? ["maxStateRecords"] : []);
    if (c === undefined || !(c.maxEvents === null || u53(v, c.maxEvents, `${P}.capacity.maxEvents`))) return false;
    if (c.maxStateRecords !== undefined && !(c.maxStateRecords === null || u53(v, c.maxStateRecords, `${P}.capacity.maxStateRecords`))) return false;
  }
  if (r.checkpointPolicy !== undefined) {
    const c = rec(v, r.checkpointPolicy, `${P}.checkpointPolicy`, ["everyEvents"]);
    if (c === undefined || !(c.everyEvents === null || (u53(v, c.everyEvents, `${P}.checkpointPolicy.everyEvents`) && (c.everyEvents >= 1 || fail(v, `${P}.checkpointPolicy.everyEvents`, "must be at least 1"))))) return false;
  }
  if (r.projection !== undefined && r.projection !== null && r.projection !== PROJECTION_VERSION) return fail(v, `${P}.projection`, `must be ${PROJECTION_VERSION} or null`);
  // A-179.1: sessionTimeHorizonMs?: U53 ≥ 1 | null (default null); 0 is EVENT_DATA_INVALID (C4).
  if (r.sessionTimeHorizonMs !== undefined && r.sessionTimeHorizonMs !== null &&
      !(u53(v, r.sessionTimeHorizonMs, `${P}.sessionTimeHorizonMs`) && ((r.sessionTimeHorizonMs as number) >= 1 || fail(v, `${P}.sessionTimeHorizonMs`, "must be at least 1")))) return false;
  if (r.migratedFrom !== undefined) {
    // Format 2 (SPEC §16.2 step 4): a legacy or format-1 source, with its `versions` block as written.
    const m = format2(v)
      // A-40.2–3 (founder-approved 2026-10-11): `sourceAttestation` and `migrationId` are part of the closed format-2 record.
      ? rec(v, r.migratedFrom, `${P}.migratedFrom`, ["format", "historyHash", "position", "recordHash", "genesis", "genesisEventId", "genesisTimestamp", "versions", "sourceAttestation", "migrationId"])
      : rec(v, r.migratedFrom, `${P}.migratedFrom`, ["format", "historyHash", "position", "recordHash", "genesis", "genesisEventId", "genesisTimestamp"]);
    if (m === undefined || !literal(v, m.format, `${P}.migratedFrom.format`, format2(v) ? [LEGACY_FORMAT, TRELLIS_FORMAT] : [LEGACY_FORMAT]) || !contentHash(v, m.historyHash, `${P}.migratedFrom.historyHash`) ||
        !u53(v, m.position, `${P}.migratedFrom.position`) || !contentHash(v, m.recordHash, `${P}.migratedFrom.recordHash`) ||
        !identifier(v, m.genesisEventId, `${P}.migratedFrom.genesisEventId`) || !u53(v, m.genesisTimestamp, `${P}.migratedFrom.genesisTimestamp`)) return false;
    // The source genesis is validated under the source schema, exactly as the source history validated it.
    const sourceFormat = m.format as HistoryFormat;
    const source: V = { format: sourceFormat, ...(v.ghosts === undefined ? {} : { ghosts: v.ghosts }) };
    if (!preflight(source, m.genesis, P, NAMED_LIMITS.DEPLOYMENT_INITIALIZED) || !genesisData(source, m.genesis)) {
      if (source.kind === "LIMIT") return failLimit(v, `${P}.migratedFrom.genesis${source.problem?.slice(P.length) ?? ""}`, "invalid source genesis");
      return fail(v, `${P}.migratedFrom.genesis${source.problem?.slice(P.length).replace(/: .*$/, "") ?? ""}`, source.problem?.replace(/^[^:]*: /, "") ?? "invalid source genesis");
    }
    if (m.versions !== undefined) {
      const versions = rec(v, m.versions, `${P}.migratedFrom.versions`, sourceFormat === TRELLIS_FORMAT ? TRELLIS_VERSION_KEYS : LEGACY_VERSION_KEYS);
      if (versions === undefined || !Object.keys(versions).every((key) => identifier(v, versions[key], `${P}.migratedFrom.versions.${key}`))) return false;
      // §16.2 step 4: `versions` is the source `versions` block as written, and the source genesis is stored as written, so
      // the two are equal: the same keys, each value byte for byte; the first difference in canonical key order is named
      // (the coordinator's ruling, 2026-10-26, architect list item 18). A replayer reads the source genesis's own block, so
      // a different copy here would let another reader build other shadow challenges for the same accepted history.
      const written = isPlainRecord((m.genesis as Rec).versions) ? ((m.genesis as Rec).versions as Rec) : {};
      const differing = [...new Set([...Object.keys(versions), ...Object.keys(written)])].sort().find((key) => versions[key] !== written[key]);
      if (differing !== undefined) return fail(v, `${P}.migratedFrom.versions.${differing}`, "must equal migratedFrom.genesis.versions (§16.2 step 4)");
    }
    if (format2(v)) {
      // A-40.3: 32 random bytes drawn at plan time.
      if (!contentHash(v, m.migrationId, `${P}.migratedFrom.migrationId`)) return false;
      // A-40.2: the source pin's `/1` head attestation of (historyHash, position), verified under the source genesis owner keys; null for a legacy source or an unpinned one.
      if (m.sourceAttestation !== null) {
        if (sourceFormat !== TRELLIS_FORMAT) return fail(v, `${P}.migratedFrom.sourceAttestation`, "must be null for a legacy source (A-40.2)");
        // A-80: the `/1` object as written (HF1 §9: `domain` optional, equal to the source genesis domain when present);
        // signed over the object minus keyId/scheme/signature; its head is migratedFrom's (canonicalTime: replay, after the prefix).
        const a = rec(v, m.sourceAttestation, `${P}.migratedFrom.sourceAttestation`, ["version", "head", "keyId", "scheme", "signature"], ["domain"]);
        const head = a === undefined ? undefined : rec(v, a.head, `${P}.migratedFrom.sourceAttestation.head`, ["hash", "position", "canonicalTime"]);
        if (a === undefined || head === undefined) return false;
        const domain = (m.genesis as Rec).domain as AuthorizationDomain;
        const keys = ((m.genesis as Rec).ownerKeys as readonly Readonly<{ keyId: string; scheme: SignatureScheme; credential: string }>[] | undefined) ?? [];
        if (a.version !== HEAD_ATTESTATION_VERSION || (a.domain !== undefined && hashCanonical(a.domain, "sha256") !== hashCanonical(domain, "sha256")) ||
            head.hash !== m.historyHash || head.position !== m.position ||
            !verifyHeadAttestation(a, domain, keys, "sha256")) return fail(v, `${P}.migratedFrom.sourceAttestation`, "is not the source pin's attestation of the migrated head under the source owner keys (A-40.2, A-80)");
      }
    }
  }
  // A-91.2 / A-95.2 row 0: the policy's validity after the §3.3 key test of the genesis owner keys (EVENT_DATA_INVALID).
  if (r.ownerPolicy !== undefined) {
    const failure = ownerPolicyFailure(r.ownerPolicy as OwnerPolicy, r.ownerKeys as readonly OwnerKey[], {
      migrated: r.migratedFrom !== undefined,
      ...(v.timestamp === undefined ? {} : { setting: { domain: r.domain as AuthorizationDomain, timestamp: v.timestamp, nextKeyDigests: (r.nextKeyDigests ?? []) as readonly ContentHash[], genesis: true } }),
    });
    if (failure !== undefined) return failText(v, failure);
  }
  return true;
};
const sessionData = (v: V, value: unknown): boolean => {
  const base = ["sessionId", "agentId", "controllerId", "controlEpoch", "credentialKeyId"];
  if (v.format === LEGACY_FORMAT) {
    const r = rec(v, value, P, [...base, "credentialAddress"], ["expiresAt"]);
    return r !== undefined && idFields(v, r, "sessionId", "agentId", "controllerId") && u53(v, r.controlEpoch, `${P}.controlEpoch`) &&
      identifier(v, r.credentialKeyId, `${P}.credentialKeyId`) && ethereumAddress(v, r.credentialAddress, `${P}.credentialAddress`) &&
      (r.expiresAt === undefined || u53(v, r.expiresAt, `${P}.expiresAt`));
  }
  const r = rec(v, value, P, [...base, "credentialScheme"], ["expiresAt", "credentialAddress", "credentialPublicKey"]);
  if (r === undefined || !idFields(v, r, "sessionId", "agentId", "controllerId") || !u53(v, r.controlEpoch, `${P}.controlEpoch`) ||
      !identifier(v, r.credentialKeyId, `${P}.credentialKeyId`) || !literal(v, r.credentialScheme, `${P}.credentialScheme`, SIGNATURE_SCHEMES) ||
      (r.expiresAt !== undefined && !u53(v, r.expiresAt, `${P}.expiresAt`))) return false;
  // A-22.1 / A-58.4: a native format-2 session carries a U53 `expiresAt` (absent or `null` is EVENT_DATA_INVALID); only a
  // transcribed session inside a migrated prefix may lack it (A-52.1: the source schema made it optional).
  if (v.format === TRELLIS2_FORMAT && !inMigratedPrefix(v) && r.expiresAt === undefined) return fail(v, `${P}.expiresAt`, "is required in a format-2 session admission");
  // A migrated legacy prefix re-records legacy admissions, whose credential is always an Ethereum address; the shadow's
  // legacy view could not hold an ed25519 key (it read `credentialAddress` of such an event and threw).
  if (v.shadow === LEGACY_FORMAT && r.credentialScheme !== "eip191-personal-sign-keccak256") return fail(v, `${P}.credentialScheme`, "must be eip191-personal-sign-keccak256 in a migrated legacy prefix");
  return r.credentialScheme === "ed25519"
    ? publicKeyHex(v, r.credentialPublicKey, `${P}.credentialPublicKey`, false) && (r.credentialAddress === undefined || fail(v, `${P}.credentialAddress`, "must be absent for ed25519"))
    : ethereumAddress(v, r.credentialAddress, `${P}.credentialAddress`) && (r.credentialPublicKey === undefined || fail(v, `${P}.credentialPublicKey`, "must be absent for eip191"));
};
// ---------------------------------------------------------------- format-2 data shapes (SPEC §7.3, §9.1, §10, §11, §13)

const amountOrNull = (v: V, value: unknown, path: string): boolean => value === null || amount(v, value, path);
const u53OrNull = (v: V, value: unknown, path: string): boolean => value === null || u53(v, value, path);
const identifierListOrNull = (v: V, value: unknown, path: string): boolean => value === null || identifierList(v, value, path, { nonempty: true, maximum: 256 });
const shortHead = (v: V, value: unknown, path: string): boolean => {
  const r = rec(v, value, path, ["hash", "position"]);
  return r !== undefined && contentHash(v, r.hash, `${path}.hash`) && u53(v, r.position, `${path}.position`);
};
/** SPEC §9.1 `Subjects`: a closed record of four nullable Identifier lists (1..256, distinct). */
const budgetSubjects = (v: V, value: unknown, path: string): boolean => {
  const r = rec(v, value, path, ["actorIds", "roleIds", "actions", "resources"]);
  return r !== undefined && ["actorIds", "roleIds", "actions", "resources"].every((key) => identifierListOrNull(v, r[key], `${path}.${key}`));
};
/** SPEC §9.1 `period`: `{kind: NONE}` or a fixed window with bounded rollover (`carryUnused` requires `carryCap`). */
const budgetPeriod = (v: V, value: unknown, path: string): boolean => {
  if (!isPlainRecord(value)) return fail(v, path, "must be a budget period record");
  if (value.kind === "NONE") return rec(v, value, path, ["kind"]) !== undefined;
  if (value.kind !== "FIXED_WINDOW") return fail(v, `${path}.kind`, "must be NONE or FIXED_WINDOW");
  const r = rec(v, value, path, ["kind", "lengthMs", "originMs", "carryUnused", "carryCap"]);
  if (r === undefined || !u53(v, r.lengthMs, `${path}.lengthMs`) || !u53(v, r.originMs, `${path}.originMs`) || !amountOrNull(v, r.carryCap, `${path}.carryCap`)) return false;
  if (r.lengthMs < 1) return fail(v, `${path}.lengthMs`, "must be at least 1");
  if (typeof r.carryUnused !== "boolean") return fail(v, `${path}.carryUnused`, "must be boolean");
  if (r.carryUnused && r.carryCap === null) return fail(v, `${path}.carryCap`, "is required when carryUnused is true");
  if (!r.carryUnused && r.carryCap !== null) return fail(v, `${path}.carryCap`, "must be null when carryUnused is false");
  return true;
};
const capsPresent = (r: Rec): boolean => r.amountCap !== null || r.countCap !== null || r.perOperationCap !== null;
const budgetDeclaredData = (v: V, value: unknown): boolean => {
  const r = rec(v, value, P, ["budgetId", "subjects", "metric", "period", "amountCap", "countCap", "perOperationCap", "notBefore", "expiresAt"]);
  if (r === undefined || !identifier(v, r.budgetId, `${P}.budgetId`) || !budgetSubjects(v, r.subjects, `${P}.subjects`) || !(r.metric === null || identifier(v, r.metric, `${P}.metric`)) ||
      !budgetPeriod(v, r.period, `${P}.period`) || !amountOrNull(v, r.amountCap, `${P}.amountCap`) || !u53OrNull(v, r.countCap, `${P}.countCap`) ||
      !amountOrNull(v, r.perOperationCap, `${P}.perOperationCap`) || !u53OrNull(v, r.notBefore, `${P}.notBefore`) || !u53OrNull(v, r.expiresAt, `${P}.expiresAt`)) return false;
  if (!capsPresent(r)) return fail(v, P, "a budget must cap at least one of amountCap, countCap, perOperationCap");
  if (r.notBefore !== null && r.expiresAt !== null && !((r.expiresAt as number) > (r.notBefore as number))) return fail(v, `${P}.expiresAt`, "must be after notBefore");
  return true;
};
const budgetUpdatedData = (v: V, value: unknown): boolean => {
  const r = rec(v, value, P, ["budgetId", "subjects", "amountCap", "countCap", "perOperationCap", "expiresAt"]);
  if (r === undefined || !identifier(v, r.budgetId, `${P}.budgetId`) || !budgetSubjects(v, r.subjects, `${P}.subjects`) || !amountOrNull(v, r.amountCap, `${P}.amountCap`) ||
      !u53OrNull(v, r.countCap, `${P}.countCap`) || !amountOrNull(v, r.perOperationCap, `${P}.perOperationCap`) || !u53OrNull(v, r.expiresAt, `${P}.expiresAt`)) return false;
  return capsPresent(r) || fail(v, P, "an update must leave at least one of amountCap, countCap, perOperationCap");
};
/** SPEC §7.3. */
const checkpointData = (v: V, value: unknown): boolean => {
  const r = rec(v, value, P, ["checkpointId", "head", "stateRoot", "recordCount", "derivationVersion", "projectionHead"]);
  return r !== undefined && identifier(v, r.checkpointId, `${P}.checkpointId`) && shortHead(v, r.head, `${P}.head`) && contentHash(v, r.stateRoot, `${P}.stateRoot`) &&
    u53(v, r.recordCount, `${P}.recordCount`) && (r.derivationVersion === STATE_DERIVATION_VERSION || fail(v, `${P}.derivationVersion`, `must equal ${STATE_DERIVATION_VERSION}`)) &&
    (r.projectionHead === null || contentHash(v, r.projectionHead, `${P}.projectionHead`));
};
/** SPEC §11.1: 1..16 Ed25519 keys with distinct ids. */
const counterpartyKeys = (v: V, value: unknown, path: string): boolean => {
  if (!Array.isArray(value) || value.length === 0) return fail(v, path, "must be a nonempty counterparty-key list");
  if (value.length > 16) return failLimit(v, path, "exceeds the 16-member counterparty-key bound");
  const seen = new Set<unknown>();
  for (let index = 0; index < value.length; index += 1) {
    const p = `${path}[${index}]`;
    const r = rec(v, value[index], p, ["keyId", "scheme", "credential"]);
    if (r === undefined || !identifier(v, r.keyId, `${p}.keyId`) || !(r.scheme === "ed25519" || fail(v, `${p}.scheme`, "must be ed25519")) || !publicKeyHex(v, r.credential, `${p}.credential`)) return false;
    if (seen.has(r.keyId)) return fail(v, `${p}.keyId`, "duplicates a counterparty key id");
    seen.add(r.keyId);
  }
  return true;
};
/** SPEC §10.1. */
const refusalData = (v: V, value: unknown): boolean => {
  const base = ["refusalId", "refusalSource", "request", "evaluationTime", "expectedHistoryHead", "decision", "code", "runtimeSessionId", "credentialKeyId", "controlEpoch", "refusalAuthorization"];
  if (!isPlainRecord(value)) return fail(v, P, "must be a plain protocol record");
  const source = value.refusalSource;
  if (source !== "CORE" && source !== "BUDGET" && source !== "CONNECTOR") return fail(v, `${P}.refusalSource`, "must be CORE, BUDGET or CONNECTOR");
  // `budgetId` is present iff BUDGET, `connector` iff CONNECTOR (closed record per source).
  const r = rec(v, value, P, source === "BUDGET" ? [...base, "budgetId"] : source === "CONNECTOR" ? [...base, "connector"] : base);
  if (r === undefined || !identifier(v, r.refusalId, `${P}.refusalId`) || !actionRequest(v, r.request, `${P}.request`) || !u53(v, r.evaluationTime, `${P}.evaluationTime`) ||
      !historyHead(v, r.expectedHistoryHead, `${P}.expectedHistoryHead`) || !literal(v, r.decision, `${P}.decision`, ["DENY", "INDETERMINATE"]) || !identifier(v, r.code, `${P}.code`) ||
      !sessionBindingFields(v, r, P) || !sessionAuthorization(v, r.refusalAuthorization, `${P}.refusalAuthorization`, false)) return false;
  if (source === "BUDGET" && !identifier(v, r.budgetId, `${P}.budgetId`)) return false;
  if (source === "CONNECTOR") {
    const c = rec(v, r.connector, `${P}.connector`, ["connectorId", "refusalCode", "detailDigest"]);
    if (c === undefined || !identifier(v, c.connectorId, `${P}.connector.connectorId`) || !identifier(v, c.refusalCode, `${P}.connector.refusalCode`) || !contentHash(v, c.detailDigest, `${P}.connector.detailDigest`)) return false;
    if (r.code !== "CONNECTOR_REFUSED") return fail(v, `${P}.code`, "must be CONNECTOR_REFUSED for a CONNECTOR refusal");
  }
  return true;
};
/** SPEC §10.2. */
const effectData = (v: V, value: unknown): boolean => {
  const r = rec(v, value, P, ["effectId", "intentId", "measurer", "metric", "unit", "amount", "observedAt", "detailDigest", "runtimeSessionId", "credentialKeyId", "controlEpoch", "effectAuthorization"]);
  if (r === undefined || !idFields(v, r, "effectId", "intentId", "metric", "unit")) return false;
  const m = rec(v, r.measurer, `${P}.measurer`, ["kind", "id"]);
  return m !== undefined && literal(v, m.kind, `${P}.measurer.kind`, ["SESSION", "CONNECTOR", "COUNTERPARTY"]) && identifier(v, m.id, `${P}.measurer.id`) &&
    amount(v, r.amount, `${P}.amount`) && u53(v, r.observedAt, `${P}.observedAt`) && (r.detailDigest === null || contentHash(v, r.detailDigest, `${P}.detailDigest`)) &&
    sessionBindingFields(v, r, P) && sessionAuthorization(v, r.effectAuthorization, `${P}.effectAuthorization`, false);
};
export const COUNTERPARTY_RECEIPT_VERSION = "irontrellis-counterparty-receipt/2";
/** SPEC §11.2: the counterparty-signed envelope and its session-signed wrapper. */
const counterpartyReceiptData = (v: V, value: unknown): boolean => {
  const r = rec(v, value, P, ["intentId", "envelope", "runtimeSessionId", "credentialKeyId", "controlEpoch", "recordAuthorization"]);
  if (r === undefined || !identifier(v, r.intentId, `${P}.intentId`) || !sessionBindingFields(v, r, P)) return false;
  const e = rec(v, r.envelope, `${P}.envelope`, ["version", "historyId", "counterpartyId", "keyId", "logicalId", "intentDigest", "payloadDigest", "amount", "outcome", "observedAt", "previousReceiptDigest", "signature"]);
  return e !== undefined && (e.version === COUNTERPARTY_RECEIPT_VERSION || fail(v, `${P}.envelope.version`, `must equal ${COUNTERPARTY_RECEIPT_VERSION}`)) &&
    contentHash(v, e.historyId, `${P}.envelope.historyId`) && identifier(v, e.counterpartyId, `${P}.envelope.counterpartyId`) && identifier(v, e.keyId, `${P}.envelope.keyId`) &&
    identifier(v, e.logicalId, `${P}.envelope.logicalId`) && contentHash(v, e.intentDigest, `${P}.envelope.intentDigest`) && contentHash(v, e.payloadDigest, `${P}.envelope.payloadDigest`) &&
    amount(v, e.amount, `${P}.envelope.amount`) && literal(v, e.outcome, `${P}.envelope.outcome`, ["DELIVERED", "REFUSED", "UNKNOWN"]) && u53(v, e.observedAt, `${P}.envelope.observedAt`) &&
    (e.previousReceiptDigest === null || contentHash(v, e.previousReceiptDigest, `${P}.envelope.previousReceiptDigest`)) &&
    (isSignature64(e.signature) || fail(v, `${P}.envelope.signature`, "must be a lowercase 64-byte Ed25519 signature")) &&
    sessionAuthorization(v, r.recordAuthorization, `${P}.recordAuthorization`, false);
};
/** A-71.1: the call facts a reconciler may leave unsupplied (absence is a stated fact, named in `call.unsupplied`). */
export const OBSERVATION_UNSUPPLIABLE = Object.freeze(["action", "observedAt", "resource"] as const);
/**
 * SPEC §10.3 / A-71.1 (Appendix B row 42): closed; `call.unsupplied` a byte-ordered, duplicate-free subset of
 * `["action", "observedAt", "resource"]`, each of those three absent iff named there; `call.amount?` freely optional;
 * `call.resource` a string of at most 128 code points (A-89.2); `match.position` present iff `MATCHED`; no
 * `controlAuthorization` (closed record). A missing or ungrammatical `observationAuthorization` is schema (A-89.3).
 */
const observationData = (v: V, value: unknown): boolean => {
  const r = rec(v, value, P, ["observationId", "reconcilerAgentId", "source", "call", "match", "expectedHistoryHead", "runtimeSessionId", "credentialKeyId", "controlEpoch", "observationAuthorization"]);
  if (r === undefined || !idFields(v, r, "observationId", "reconcilerAgentId")) return false;
  const source = rec(v, r.source, `${P}.source`, ["streamId", "eventRef", "eventDigest"]);
  if (source === undefined || !identifier(v, source.streamId, `${P}.source.streamId`) || !identifier(v, source.eventRef, `${P}.source.eventRef`) || !contentHash(v, source.eventDigest, `${P}.source.eventDigest`)) return false;
  const call = rec(v, r.call, `${P}.call`, ["actorId", "unsupplied"], ["action", "resource", "observedAt", "amount"]);
  if (call === undefined || !identifier(v, call.actorId, `${P}.call.actorId`) || !(call.action === undefined || identifier(v, call.action, `${P}.call.action`)) ||
      !(call.observedAt === undefined || u53(v, call.observedAt, `${P}.call.observedAt`)) || !(call.amount === undefined || amount(v, call.amount, `${P}.call.amount`))) return false;
  if (call.resource !== undefined && !(typeof call.resource === "string" && isProtocolString(call.resource) && codePointLength(call.resource, 128) <= 128)) return fail(v, `${P}.call.resource`, "must be a string of at most 128 characters (A-89.2)");
  const unsupplied = call.unsupplied;
  if (!Array.isArray(unsupplied) || !unsupplied.every((name, index) => (OBSERVATION_UNSUPPLIABLE as readonly unknown[]).includes(name) && (index === 0 || compareProtocolStrings(unsupplied[index - 1] as string, name as string) < 0))) {
    return fail(v, `${P}.call.unsupplied`, "must be a byte-ordered, duplicate-free subset of [\"action\", \"observedAt\", \"resource\"]");
  }
  for (const name of OBSERVATION_UNSUPPLIABLE) if ((call[name] === undefined) !== unsupplied.includes(name)) return fail(v, `${P}.call.${name}`, "must be absent iff named in call.unsupplied (A-71.1)");
  const match = rec(v, r.match, `${P}.match`, ["result"], ["position"]);
  if (match === undefined || !literal(v, match.result, `${P}.match.result`, ["MATCHED", "UNMATCHED"])) return false;
  if ((match.result === "MATCHED") !== (match.position !== undefined)) return fail(v, `${P}.match.position`, "must be present iff the result is MATCHED");
  return (match.position === undefined || u53(v, match.position, `${P}.match.position`)) && historyHead(v, r.expectedHistoryHead, `${P}.expectedHistoryHead`) &&
    sessionBindingFields(v, r, P) && sessionAuthorization(v, r.observationAuthorization, `${P}.observationAuthorization`, false);
};
// ---- SPEC §13 (ported from Continuity preview.10.2, `event-schema.ts`): duty-policy activation, dispositions and contests.
const dutyText = (v: V, value: unknown, path: string, max: number): boolean =>
  (typeof value === "string" && utf8Status(value, max) === "VALID") || fail(v, path, `must be well-formed UTF-8 text of at most ${max} bytes`);
const dutyDigest = (v: V, value: unknown, path: string): boolean => {
  const r = rec(v, value, path, ["algorithm", "value"]);
  return r !== undefined && (r.algorithm === "sha256" || fail(v, `${path}.algorithm`, "must be sha256")) && contentHash(v, r.value, `${path}.value`);
};
/**
 * A-202.1 (r5.2 §13.1–§13.2, Appendix A rows 29–31): in format 2 the §13 literal fields are items of the type's own list,
 * after the outer session fence; the closed schema (C4) checks only their shape here, and replay checks their values
 * after the fence (`dutyLiteralFailure`, state.ts). The legacy duty-policy events keep their source engine's schema order.
 */
const deferDutyLiterals = (v: V): boolean => v.format === TRELLIS2_FORMAT;
const DESCRIPTOR_LITERALS = "descriptor literals must be those of continuity-attempt-disposition/1";
const DISPOSITION_LITERALS = "disposition literals must be those of continuity-attempt-disposition/1";
const FINDING_LITERALS = "finding literals must be those of continuity-duty-finding/1";
const dutyPolicyDescriptor = (v: V, value: unknown, path: string): boolean => {
  const r = rec(v, value, path, ["version", "rulesHash", "criteriaProfile", "domain", "genesisHash", "baseAdapterPolicyHash", "dutyId", "dutyCreationEventId", "dutyRecordHash",
    "sourceIntentId", "sourceAdmissionEventId", "durableRoleId", "principalId", "incidentSourceDigest", "acceptedAttesterRoleId", "dispositionLimit", "contestLimit"]);
  if (r === undefined) return false;
  if (deferDutyLiterals(v)) {
    // Shape only: the literal values are checked after the fence (A-202.1).
    const digest = rec(v, r.incidentSourceDigest, `${path}.incidentSourceDigest`, ["algorithm", "value"]);
    if (!identifier(v, r.version, `${path}.version`) || !contentHash(v, r.rulesHash, `${path}.rulesHash`) || !identifier(v, r.criteriaProfile, `${path}.criteriaProfile`) ||
        !u53(v, r.dispositionLimit, `${path}.dispositionLimit`) || !u53(v, r.contestLimit, `${path}.contestLimit`) || digest === undefined ||
        !identifier(v, digest.algorithm, `${path}.incidentSourceDigest.algorithm`) || !contentHash(v, digest.value, `${path}.incidentSourceDigest.value`)) return false;
  } else if (r.version !== DUTY_POLICY_VERSION || r.rulesHash !== DUTY_POLICY_RULES_HASH || r.criteriaProfile !== "local-investigation/1" || r.dispositionLimit !== 4 || r.contestLimit !== 2) {
    return fail(v, path, DESCRIPTOR_LITERALS);
  }
  return (deferDutyLiterals(v) || dutyDigest(v, r.incidentSourceDigest, `${path}.incidentSourceDigest`)) && domain(v, r.domain, `${path}.domain`) && contentHash(v, r.genesisHash, `${path}.genesisHash`) &&
    contentHash(v, r.baseAdapterPolicyHash, `${path}.baseAdapterPolicyHash`) && contentHash(v, r.dutyRecordHash, `${path}.dutyRecordHash`) &&
    ["dutyId", "dutyCreationEventId", "sourceIntentId", "sourceAdmissionEventId", "durableRoleId", "principalId", "acceptedAttesterRoleId"].every((key) => identifier(v, r[key], `${path}.${key}`));
};
/** The finding operation's reportDigest: in format 2 its `algorithm` literal follows the fence too (the coordinator's A-202.1 scope ruling, 2026-10-26). */
const findingDigest = (v: V, value: unknown, path: string): boolean => {
  if (!deferDutyLiterals(v)) return dutyDigest(v, value, path);
  const r = rec(v, value, path, ["algorithm", "value"]);
  return r !== undefined && identifier(v, r.algorithm, `${path}.algorithm`) && contentHash(v, r.value, `${path}.value`);
};
const dutyFinding = (v: V, value: unknown, path: string): boolean => {
  const f = rec(v, value, path, ["challenge", "runtimeSignature"]);
  if (f === undefined || !signature(v, f.runtimeSignature, `${path}.runtimeSignature`)) return false;
  const cp = `${path}.challenge`;
  const c = rec(v, f.challenge, cp, ["version", "purpose", "domain", "rulesHash", "descriptorHash", "activationEventId", "dutyId", "sourceAdmissionEventId", "transitionEventId", "transitionEventType",
    "evaluationTime", "priorHead", "latestAssignmentEventId", "previousDispositionEventId", "evidenceIndexHash", "operation", "attesterId", "runtimeSessionId", "credentialKeyId", "controlEpoch",
    "roleId", "roleTenureId", "attestationAuthorityId", "dispositionAuthorityId", "authorityProofHash"]);
  if (c === undefined) return false;
  if (deferDutyLiterals(v)) { if (!identifier(v, c.version, `${cp}.version`) || !contentHash(v, c.rulesHash, `${cp}.rulesHash`)) return false; }
  else if (c.version !== DUTY_FINDING_VERSION || c.rulesHash !== DUTY_POLICY_RULES_HASH) return fail(v, cp, FINDING_LITERALS);
  if (!domain(v, c.domain, `${cp}.domain`) || !historyHead(v, c.priorHead, `${cp}.priorHead`) || !u53(v, c.evaluationTime, `${cp}.evaluationTime`) || !u53(v, c.controlEpoch, `${cp}.controlEpoch`)) return false;
  for (const key of ["descriptorHash", "evidenceIndexHash", "authorityProofHash"]) if (!contentHash(v, c[key], `${cp}.${key}`)) return false;
  for (const key of ["activationEventId", "dutyId", "sourceAdmissionEventId", "transitionEventId", "latestAssignmentEventId", "attesterId", "runtimeSessionId", "credentialKeyId", "roleId", "roleTenureId", "attestationAuthorityId", "dispositionAuthorityId"]) {
    if (!identifier(v, c[key], `${cp}.${key}`)) return false;
  }
  if (c.previousDispositionEventId !== null && !identifier(v, c.previousDispositionEventId, `${cp}.previousDispositionEventId`)) return false;
  const op = `${cp}.operation`;
  if (c.purpose === "DISPOSITION" && c.transitionEventType === "ATTEMPT_DUTY_DISPOSITION_RECORDED") {
    const o = rec(v, c.operation, op, ["disposition", "checklist", "reportDigest", "nextStep"]);
    if (o === undefined || !literal(v, o.disposition, `${op}.disposition`, ["COMPLETED_UNDER_POLICY", "ESCALATED"]) || !findingDigest(v, o.reportDigest, `${op}.reportDigest`) ||
        (o.nextStep !== null && !dutyText(v, o.nextStep, `${op}.nextStep`, 512))) return false;
    const checklist = rec(v, o.checklist, `${op}.checklist`, DUTY_CRITERIA);
    if (checklist === undefined) return false;
    for (const key of DUTY_CRITERIA) {
      const r = rec(v, checklist[key], `${op}.checklist.${key}`, ["state", "reason"]);
      if (r === undefined || !literal(v, r.state, `${op}.checklist.${key}.state`, ["SATISFIED", "UNAVAILABLE", "UNRESOLVED"]) || !dutyText(v, r.reason, `${op}.checklist.${key}.reason`, 256)) return false;
    }
    return true;
  }
  if (c.purpose === "CONTEST" && c.transitionEventType === "ATTEMPT_DUTY_CONTEST_RECORDED") {
    const o = rec(v, c.operation, op, ["targetDispositionEventId", "reason", "reportDigest"]);
    return o !== undefined && identifier(v, o.targetDispositionEventId, `${op}.targetDispositionEventId`) && dutyText(v, o.reason, `${op}.reason`, 256) &&
      ((o.reason as string).trim().length > 0 || fail(v, `${op}.reason`, "must not be blank")) && findingDigest(v, o.reportDigest, `${op}.reportDigest`);
  }
  return fail(v, `${cp}.purpose`, "must be DISPOSITION or CONTEST matching the transition type");
};
const dutyDispositionData = (v: V, value: unknown, type: EventType): boolean => {
  const r = rec(v, value, P, ["version", "rulesHash", "dutyId", "actorId", "dispositionAuthorityId", "finding", "administrativeAuthorization"]);
  if (r === undefined) return false;
  if (deferDutyLiterals(v)) { if (!identifier(v, r.version, `${P}.version`) || !contentHash(v, r.rulesHash, `${P}.rulesHash`)) return false; }
  else if (r.version !== DUTY_POLICY_VERSION || r.rulesHash !== DUTY_POLICY_RULES_HASH) return fail(v, P, DISPOSITION_LITERALS);
  if (!idFields(v, r, "dutyId", "actorId", "dispositionAuthorityId") || !dutyFinding(v, r.finding, `${P}.finding`)) return false;
  const challenge = (r.finding as Rec).challenge as Rec;
  if (challenge.transitionEventType !== type) return fail(v, `${P}.finding.challenge.transitionEventType`, `must equal ${type}`);
  return administrativeAuthorization(v, r.administrativeAuthorization, `${P}.administrativeAuthorization`);
};

/**
 * A-202.1: the §13 literal-field checks of a schema-valid format-2 type 29–31 event, run by replay immediately after the
 * outer session fence (state.ts). The same order and reasons as the schema used before: the data's literals (30, 31) or
 * the descriptor's (29), the descriptor's digest algorithm, then the finding challenge's (30, 31) and its reportDigest algorithm.
 * The rule (the coordinator's scope ruling, 2026-10-26; architect list item 17): a check against one fixed literal follows the
 * fence; a shape-selecting or self-consistency check (the finding's `purpose`, `transitionEventType`) stays at C4. `undefined` if all hold.
 */
export const dutyLiteralFailure = (event: Readonly<{ type: string; data: Readonly<Record<string, unknown>> }>): string | undefined => {
  const d = event.data as Rec;
  if (event.type === "ATTEMPT_DUTY_POLICY_ACTIVATED") {
    const r = d.descriptor as Rec, path = `${P}.descriptor`;
    if (r.version !== DUTY_POLICY_VERSION || r.rulesHash !== DUTY_POLICY_RULES_HASH || r.criteriaProfile !== "local-investigation/1" || r.dispositionLimit !== 4 || r.contestLimit !== 2) return `${path}: ${DESCRIPTOR_LITERALS}`;
    if ((r.incidentSourceDigest as Rec).algorithm !== "sha256") return `${path}.incidentSourceDigest.algorithm: must be sha256`;
    return undefined;
  }
  if (event.type === "ATTEMPT_DUTY_DISPOSITION_RECORDED" || event.type === "ATTEMPT_DUTY_CONTEST_RECORDED") {
    if (d.version !== DUTY_POLICY_VERSION || d.rulesHash !== DUTY_POLICY_RULES_HASH) return `${P}: ${DISPOSITION_LITERALS}`;
    const c = (d.finding as Rec).challenge as Rec;
    if (c.version !== DUTY_FINDING_VERSION || c.rulesHash !== DUTY_POLICY_RULES_HASH) return `${P}.finding.challenge: ${FINDING_LITERALS}`;
    if (((c.operation as Rec).reportDigest as Rec).algorithm !== "sha256") return `${P}.finding.challenge.operation.reportDigest.algorithm: must be sha256`;
  }
  return undefined;
};

const validateEventData = (v: V, type: EventType, value: unknown): boolean => {
  switch (type) {
    case "DEPLOYMENT_INITIALIZED": return genesisData(v, value);
    case "PRINCIPAL_CREATED": { const r = rec(v, value, P, ["principalId"]); return r !== undefined && idFields(v, r, "principalId"); }
    case "AGENT_CREATED": {
      const r = rec(v, value, P, ["agentId", "principalId", "controllerId", "initialControlEpoch"]);
      return r !== undefined && idFields(v, r, "agentId", "principalId", "controllerId") && u53(v, r.initialControlEpoch, `${P}.initialControlEpoch`);
    }
    case "ROLE_CREATED": {
      const r = rec(v, value, P, ["roleId", "principalId", "exclusive"]);
      return r !== undefined && idFields(v, r, "roleId", "principalId") && (r.exclusive === true || fail(v, `${P}.exclusive`, "must be true"));
    }
    case "SUCCESSION_RULE_DECLARED": {
      const r = rec(v, value, P, ["ruleId", "principalId", "predecessorAgentId", "successorAgentId", "roleId", "trigger", "permittedEventTypes"]);
      return r !== undefined && idFields(v, r, "ruleId", "principalId", "predecessorAgentId", "successorAgentId", "roleId") && r.trigger === "AGENT_TERMINATED" &&
        enumList(v, r.permittedEventTypes, `${P}.permittedEventTypes`, ["AGENT_TERMINATED", "ROLE_TRANSFERRED", "OBLIGATION_PERFORMANCE_ASSIGNED"], true);
    }
    case "AGENT_APPOINTED": {
      const r = rec(v, value, P, ["agentId", "roleId", "roleTenureId", "tenureNumber", "principalId"], ["successionRuleId"]);
      return r !== undefined && idFields(v, r, "agentId", "roleId", "roleTenureId") && u53(v, r.tenureNumber, `${P}.tenureNumber`) &&
        idFields(v, r, "principalId") && (r.successionRuleId === undefined || idFields(v, r, "successionRuleId"));
    }
    case "AGENT_UNAPPOINTED": {
      const r = rec(v, value, P, ["agentId", "roleId", "roleTenureId", "principalId"]);
      return r !== undefined && idFields(v, r, "agentId", "roleId", "roleTenureId", "principalId");
    }
    case "ROLE_TRANSFERRED": {
      const r = rec(v, value, P, ["roleId", "fromAgentId", "fromRoleTenureId", "toAgentId", "toRoleTenureId", "toTenureNumber", "principalId", "transferKind"], ["successionRuleId"]);
      return r !== undefined && idFields(v, r, "roleId", "fromAgentId", "fromRoleTenureId", "toAgentId", "toRoleTenureId") &&
        u53(v, r.toTenureNumber, `${P}.toTenureNumber`) && idFields(v, r, "principalId") &&
        literal(v, r.transferKind, `${P}.transferKind`, ["SUCCESSION", "REASSIGNMENT"]) && (r.successionRuleId === undefined || idFields(v, r, "successionRuleId"));
    }
    case "RUNTIME_SESSION_ADMITTED": return sessionData(v, value);
    case "CONTROL_EPOCH_ADVANCED": {
      const r = rec(v, value, P, ["agentId", "controllerId", "fromEpoch", "toEpoch"]);
      return r !== undefined && idFields(v, r, "agentId", "controllerId") && u53(v, r.fromEpoch, `${P}.fromEpoch`) && u53(v, r.toEpoch, `${P}.toEpoch`);
    }
    case "AUTHORITY_GRANTED": { const r = rec(v, value, P, ["grant"]); return r !== undefined && authorityGrant(v, r.grant, `${P}.grant`); }
    case "AUTHORITY_REVOKED": { const r = rec(v, value, P, ["authorityId", "revokerId"]); return r !== undefined && idFields(v, r, "authorityId", "revokerId"); }
    case "TRANSACTION_INTENT_DECLARED": return transactionIntent(v, value, P);
    case "TRANSACTION_INTENT_ADMITTED": {
      const r = rec(v, value, P, ["intentId", "evaluationTime", "expectedHistoryHead", "authorizationProof", "runtimeAuthorizationHash", "runtimeSignature"]);
      return r !== undefined && idFields(v, r, "intentId") && u53(v, r.evaluationTime, `${P}.evaluationTime`) &&
        historyHead(v, r.expectedHistoryHead, `${P}.expectedHistoryHead`) && authorizationProof(v, r.authorizationProof, `${P}.authorizationProof`) &&
        contentHash(v, r.runtimeAuthorizationHash, `${P}.runtimeAuthorizationHash`) && signature(v, r.runtimeSignature, `${P}.runtimeSignature`);
    }
    case "TRANSACTION_INTENT_CONSUMED": {
      const r = rec(v, value, P, ["intentId", "adapterId", "idempotencyKey", "submissionFingerprint", "status", "evidenceReference", "acknowledgment", "transactionReference", ...lifecycleKeys(v)]);
      return r !== undefined && lifecycleAuthorization(v, r) && idFields(v, r, "intentId", "adapterId") && contentHash(v, r.idempotencyKey, `${P}.idempotencyKey`) &&
        contentHash(v, r.submissionFingerprint, `${P}.submissionFingerprint`) && r.status === "SUBMITTED" && idFields(v, r, "transactionReference") &&
        adapterEvidence(v, r.acknowledgment, `${P}.acknowledgment`) && evidenceReference(v, r.evidenceReference, `${P}.evidenceReference`);
    }
    case "TRANSACTION_OUTCOME_RECORDED": {
      const keys = ["intentId", "status", "attesterId", "evidenceReference", ...lifecycleKeys(v)];
      const r = rec(v, value, P, keys, ["noEffect"]);
      if (r !== undefined && !lifecycleAuthorization(v, r)) return false;
      // A non-FAILED outcome may not even mention `noEffect`, so the record is re-closed without it.
      if (r !== undefined && r.status !== "FAILED" && rec(v, value, P, keys) === undefined) return false;
      return r !== undefined && idFields(v, r, "intentId") && literal(v, r.status, `${P}.status`, ["CONFIRMED", "FAILED", "DISPUTED", "OUTCOME_UNKNOWN"]) &&
        (r.status === "FAILED" ? adapterEvidence(v, r.noEffect, `${P}.noEffect`, true) : !Object.hasOwn(r, "noEffect")) &&
        idFields(v, r, "attesterId") && evidenceReference(v, r.evidenceReference, `${P}.evidenceReference`);
    }
    case "RECEIPT_RECORDED": {
      const r = rec(v, value, P, ["receiptContentHash", "receiptArtifactCommitment", "intentId", "issuerAgentId", "runtimeSessionId", "controlEpoch", "roleId", "roleTenureId", "authorizationProofHash", ...lifecycleKeys(v)]);
      return r !== undefined && lifecycleAuthorization(v, r) && contentHash(v, r.receiptContentHash, `${P}.receiptContentHash`) && contentHash(v, r.receiptArtifactCommitment, `${P}.receiptArtifactCommitment`) &&
        idFields(v, r, "intentId", "issuerAgentId", "runtimeSessionId") && u53(v, r.controlEpoch, `${P}.controlEpoch`) && idFields(v, r, "roleId", "roleTenureId") &&
        contentHash(v, r.authorizationProofHash, `${P}.authorizationProofHash`) && receiptBindingConsistent(v, r);
    }
    case "OBLIGATION_CREATED": {
      const r = rec(v, value, P, ["record", "actorId", "administrativeAuthorization"]);
      return r !== undefined && obligationRecord(v, r.record, `${P}.record`) && idFields(v, r, "actorId") &&
        administrativeAuthorization(v, r.administrativeAuthorization, `${P}.administrativeAuthorization`);
    }
    case "OUTCOME_OBSERVATION_RECORDED": {
      const r = rec(v, value, P, ["intentId", "sourceAdmissionEventId", "acknowledgment", "actorId", "administrativeAuthorization"]);
      return r !== undefined && idFields(v, r, "intentId", "sourceAdmissionEventId") && isPlainRecord(r.acknowledgment) &&
        r.acknowledgment.schemaVersion === REMOTE_SERVICE_REPORT_ACKNOWLEDGMENT_VERSION && adapterEvidence(v, r.acknowledgment, `${P}.acknowledgment`) &&
        idFields(v, r, "actorId") && administrativeAuthorization(v, r.administrativeAuthorization, `${P}.administrativeAuthorization`);
    }
    case "ATTEMPT_DUTY_CREATED": {
      const r = rec(v, value, P, ["record", "actorId", "administrativeAuthorization"]);
      return r !== undefined && attemptDutyRecord(v, r.record, `${P}.record`) && idFields(v, r, "actorId") &&
        administrativeAuthorization(v, r.administrativeAuthorization, `${P}.administrativeAuthorization`);
    }
    case "ATTEMPT_DUTY_REVIEW_CLOSED": {
      const r = rec(v, value, P, ["dutyId", "actorId", "observationEventIds", "summaryDigest", "administrativeAuthorization"]);
      return r !== undefined && idFields(v, r, "dutyId", "actorId") && reviewObservationIds(v, r.observationEventIds, `${P}.observationEventIds`) &&
        contentHash(v, r.summaryDigest, `${P}.summaryDigest`) && administrativeAuthorization(v, r.administrativeAuthorization, `${P}.administrativeAuthorization`);
    }
    case "ATTEMPT_DUTY_ASSIGNED": {
      const r = rec(v, value, P, ["dutyId", "fromAgentId", "toAgentId", "actorId", "administrativeAuthorization"]);
      return r !== undefined && idFields(v, r, "dutyId", "fromAgentId", "toAgentId", "actorId") &&
        administrativeAuthorization(v, r.administrativeAuthorization, `${P}.administrativeAuthorization`);
    }
    case "OBLIGATION_PERFORMANCE_ASSIGNED": {
      const r = rec(v, value, P, ["obligationId", "fromAgentId", "toAgentId", "successionRuleId", "actorId", "administrativeAuthorization"]);
      return r !== undefined && idFields(v, r, "obligationId", "fromAgentId", "toAgentId", "successionRuleId", "actorId") &&
        administrativeAuthorization(v, r.administrativeAuthorization, `${P}.administrativeAuthorization`);
    }
    case "OBLIGATION_STATUS_RECORDED": {
      const r = rec(v, value, P, ["obligationId", "fromStatus", "toStatus", "actorId", "action", "administrativeAuthorization", "attesterId", "evidenceReference"]);
      return r !== undefined && idFields(v, r, "obligationId") && literal(v, r.fromStatus, `${P}.fromStatus`, OBLIGATION_STATUSES) &&
        literal(v, r.toStatus, `${P}.toStatus`, OBLIGATION_STATUSES) && idFields(v, r, "actorId", "action") &&
        administrativeAuthorization(v, r.administrativeAuthorization, `${P}.administrativeAuthorization`) && idFields(v, r, "attesterId") &&
        evidenceReference(v, r.evidenceReference, `${P}.evidenceReference`);
    }
    case "AGENT_TERMINATED": {
      const r = rec(v, value, P, ["agentId", "principalId", "successionRuleId", "roleId", "roleTenureId"]);
      return r !== undefined && idFields(v, r, "agentId", "principalId", "successionRuleId", "roleId", "roleTenureId");
    }
    case "ANCHOR_RECORDED": {
      const r = rec(v, value, P, ["anchoredHead", "anchor", "receipt", "anchoredAt"]);
      return r !== undefined && historyHead(v, r.anchoredHead, `${P}.anchoredHead`) && literal(v, r.anchor, `${P}.anchor`, ANCHOR_NAMES) &&
        (isPlainRecord(r.receipt) || fail(v, `${P}.receipt`, "must be a plain protocol record")) && u53(v, r.anchoredAt, `${P}.anchoredAt`);
    }
    case "OWNER_KEYS_ROTATED": {
      // The new set has the genesis owner-key shape; `reason` is identifier-shaped text (1..256 UTF-8 bytes, no control characters).
      // Pre-rotation: `nextKeyDigests` commits the new epoch to its next keys; `nextKeyAuthorizations` proves possession of the revealed keys.
      // Format 2 (A-91): `ownerPolicy` sets the next epoch's policy; its validity is checked after control authorization and the key test.
      const r = rec(v, value, P, ["ownerKeys"], ["reason", "nextKeyDigests", "nextKeyAuthorizations", ...(format2(v) ? ["ownerPolicy"] : [])]);
      return r !== undefined && ownerKeys(v, r.ownerKeys, `${P}.ownerKeys`, false) && (r.reason === undefined || identifier(v, r.reason, `${P}.reason`)) &&
        (r.nextKeyDigests === undefined || nextKeyDigests(v, r.nextKeyDigests, `${P}.nextKeyDigests`)) &&
        (r.nextKeyAuthorizations === undefined || nextKeyAuthorizations(v, r.nextKeyAuthorizations, `${P}.nextKeyAuthorizations`)) &&
        (r.ownerPolicy === undefined || ownerPolicyShape(v, r.ownerPolicy, `${P}.ownerPolicy`));
    }
    case "WITNESSES_BOUND": {
      // Each witness (url, verifier key, optional name, allowInsecureHttp and its signed REGISTERED receipt) and the policy minimum.
      const r = rec(v, value, P, ["witnesses", "policy"]);
      return r !== undefined && witnessList(v, r.witnesses, `${P}.witnesses`, boundWitness, (item) => (item as Rec).verifierKey, "remote witness") &&
        witnessPolicy(v, r.policy, `${P}.policy`);
    }
    case "WITNESSES_UNBOUND": {
      const r = rec(v, value, P, ["verifierKeys", "policy"], ["acceptedLoss"]);
      return r !== undefined && witnessList(v, r.verifierKeys, `${P}.verifierKeys`, witnessVerifierKey, (item) => item, "remote witness") &&
        witnessPolicy(v, r.policy, `${P}.policy`) && (r.acceptedLoss === undefined || acceptedLoss(v, r.acceptedLoss, `${P}.acceptedLoss`));
    }
    // ---- format 2 (SPEC §5 types 29–40)
    case "ATTEMPT_DUTY_POLICY_ACTIVATED": {
      const r = rec(v, value, P, ["actorId", "descriptor", "descriptorHash", "activationAuthorityId", "administrativeAuthorization"]);
      return r !== undefined && idFields(v, r, "actorId") && dutyPolicyDescriptor(v, r.descriptor, `${P}.descriptor`) && contentHash(v, r.descriptorHash, `${P}.descriptorHash`) &&
        idFields(v, r, "activationAuthorityId") && administrativeAuthorization(v, r.administrativeAuthorization, `${P}.administrativeAuthorization`);
    }
    case "ATTEMPT_DUTY_DISPOSITION_RECORDED":
    case "ATTEMPT_DUTY_CONTEST_RECORDED": return dutyDispositionData(v, value, type);
    case "BUDGET_DECLARED": return budgetDeclaredData(v, value);
    case "BUDGET_UPDATED": return budgetUpdatedData(v, value);
    case "BUDGET_CLOSED": { const r = rec(v, value, P, ["budgetId"]); return r !== undefined && idFields(v, r, "budgetId"); }
    case "STATE_CHECKPOINT": return checkpointData(v, value);
    case "COUNTERPARTY_REGISTERED": {
      const r = rec(v, value, P, ["counterpartyId", "keys"]);
      return r !== undefined && idFields(v, r, "counterpartyId") && counterpartyKeys(v, r.keys, `${P}.keys`);
    }
    case "COUNTERPARTY_RETIRED": { const r = rec(v, value, P, ["counterpartyId"]); return r !== undefined && idFields(v, r, "counterpartyId"); }
    case "REQUEST_REFUSED": return refusalData(v, value);
    case "EFFECT_RECORDED": return effectData(v, value);
    case "RECONCILIATION_OBSERVED": return observationData(v, value);
    case "COUNTERPARTY_RECEIPT_RECORDED": return counterpartyReceiptData(v, value);
  }
};

// ---------------------------------------------------------------- envelope, genesis probe, public API

export type EventValidation = { ok: true; event: CanonicalEvent } | { ok: false; code: ReplayCode; reason: string };
const invalid = (code: ReplayCode, reason: string): EventValidation => ({ ok: false, code, reason });
const schemaFailure = (v: V, fallback: string): EventValidation =>
  invalid(v.kind === "LIMIT" ? "INVALID_INPUT" : "EVENT_DATA_INVALID", v.problem ?? fallback);
/** Malformed scalars that capture rejects but the reference carried into schema validation (spec 01 §A.3/§G.4). */
const SCALAR_DEFECT = /finite|safe integer|negative zero|well-formed|256-bit|bigint/i;
const captureFailure = (error: unknown): EventValidation => {
  if (error instanceof CanonicalError) {
    return invalid(!error.limit && SCALAR_DEFECT.test(error.reason) ? "EVENT_DATA_INVALID" : "INVALID_INPUT", `$.data: ${error.reason}`);
  }
  return invalid("INVALID_INPUT", "$.data: failed canonical capture");
};

/**
 * Capture drops `undefined`-valued fields, but the closed schemas must still see
 * them (spec 01 §G.6: an undeclared key is rejected even when undefined). This
 * records, per captured record, the keys the raw record held with `undefined`.
 */
const collectGhosts = (raw: unknown, captured: unknown, v: V): void => {
  if (raw === null || typeof raw !== "object" || captured === null || typeof captured !== "object") return;
  if (Array.isArray(raw)) {
    for (let index = 0; index < raw.length; index += 1) collectGhosts(raw[index], (captured as readonly unknown[])[index], v);
    return;
  }
  const record = raw as Rec, copy = captured as Rec;
  let ghosts: string[] | undefined;
  for (const key of Object.keys(record)) {
    const field = record[key];
    if (field === undefined) (ghosts ??= []).push(key);
    else if (field !== null && typeof field === "object") collectGhosts(field, copy[key], v);
  }
  if (ghosts !== undefined) (v.ghosts ??= new Map()).set(copy, ghosts);
};

/** A re-recorded event as the legacy source held it: without the format-1 additions (docs/HISTORY-FORMAT.md §11). */
export const legacyProjection = (event: CanonicalEvent): CanonicalEvent => {
  const added = ["controlAuthorization", ...(event.type === "RUNTIME_SESSION_ADMITTED" ? ["credentialScheme"] : [])].filter((key) => Object.hasOwn(event.data, key));
  if (added.length === 0) return event;
  const data: Record<string, unknown> = { ...event.data };
  for (const key of added) delete data[key];
  return Object.freeze({ id: event.id, type: event.type, timestamp: event.timestamp, data: Object.freeze(data) });
};

/** A-92.0: the co-signatures of a format-2 control event, beside `controlAuthorization`, over the same `/2` challenge. */
export const ADDITIONAL_CONTROL_AUTHORIZATIONS = "additionalControlAuthorizations";
/**
 * The data a control event commits to: everything except its own authorization, its co-signatures (A-92.0) and, in a
 * format-2 history migrated from format 1, the source's `/1` authorization kept as `sourceControlAuthorization` (SPEC
 * §16.2 step 2(c)). The succession rule record stores `signedControlEffect`'s effect (A-187.2); on a
 * `SUCCESSION_RULE_DECLARED` the two are equal, because its closed schema rejects `nextKeyAuthorizations`.
 */
export const controlEffect = (data: Readonly<Record<string, unknown>>): Readonly<Record<string, unknown>> => {
  if (!Object.hasOwn(data, "controlAuthorization") && !Object.hasOwn(data, "sourceControlAuthorization") && !Object.hasOwn(data, ADDITIONAL_CONTROL_AUTHORIZATIONS)) return data;
  const { controlAuthorization: _omitted, sourceControlAuthorization: _source, additionalControlAuthorizations: _cosigned, ...effect } = data;
  return effect;
};
/**
 * The data the owner signatures over a control event cover: the effect without
 * the signatures made over that same challenge — `controlAuthorization`, the
 * co-signatures `additionalControlAuthorizations` (A-92.0, A-95.1) and, on
 * a pre-rotated `OWNER_KEYS_ROTATED`, `nextKeyAuthorizations` (the revealed
 * keys sign the same challenge, so including them would make the signatures
 * circular). Everything else, the new `ownerKeys`, `nextKeyDigests` and
 * `ownerPolicy` included, is bound. Other event types reject
 * `nextKeyAuthorizations` in their closed schema. This is the §6.1 effect: the challenge
 * (`controlEffectHash`) and the succession rule record (A-95.1, A-187.2) both use it.
 */
export const signedControlEffect = (data: Readonly<Record<string, unknown>>): Readonly<Record<string, unknown>> => {
  if (!Object.hasOwn(data, "controlAuthorization") && !Object.hasOwn(data, "nextKeyAuthorizations") && !Object.hasOwn(data, "sourceControlAuthorization") &&
      !Object.hasOwn(data, ADDITIONAL_CONTROL_AUTHORIZATIONS)) return data;
  const { controlAuthorization: _authorization, nextKeyAuthorizations: _proofs, sourceControlAuthorization: _source, additionalControlAuthorizations: _cosigned, ...effect } = data;
  return effect;
};
export const controlEffectHash = (event: CanonicalEvent, algorithm: HashAlgorithm): ContentHash => hashCanonical(signedControlEffect(event.data), algorithm);
export type ControlAuthorizationInput = Readonly<{
  domain: AuthorizationDomain; eventId: string; eventType: EventType; timestamp: U53;
  previousHead: Readonly<{ hash: ContentHash; position: U53 }> | null; effectHash: ContentHash;
}>;
/** The control-authorization literal of a domain: `/2` for a format-2 domain (`version: "2"`), `/1` otherwise (SPEC §6.1). */
export const controlAuthorizationVersionOf = (domain: AuthorizationDomain): string =>
  domain.protocol === "irontrellis" && domain.version === "2" ? CONTROL_AUTHORIZATION_VERSION_2 : CONTROL_AUTHORIZATION_VERSION;
/**
 * The structure an owner key signs for a control event (docs/HISTORY-FORMAT.md §7; SPEC §6.1 for format 2, whose
 * `previousHead` is the chain head `{recordHash(p−1), p−1}`); `previousHead` is the head *before* the event. The
 * version literal is keyed on the domain, which the genesis `versions` block fixes (a format-2 genesis declares
 * `irontrellis-control-authorization/2` and a `version: "2"` domain together, SPEC §5.1).
 */
export const controlAuthorizationChallenge = (input: ControlAuthorizationInput): Readonly<Record<string, unknown>> => Object.freeze({
  version: controlAuthorizationVersionOf(input.domain), domain: input.domain, eventId: input.eventId, eventType: input.eventType, timestamp: input.timestamp,
  previousHead: input.previousHead === null ? null : { hash: input.previousHead.hash, position: input.previousHead.position }, effectHash: input.effectHash,
});
export const controlAuthorizationHash = (input: ControlAuthorizationInput, algorithm: HashAlgorithm): ContentHash =>
  hashCanonical(controlAuthorizationChallenge(input), algorithm);

/** Genesis probe (spec 01 §C.8): closed record with well-formed declared versions, before the exact version comparison. */
const genesisProbe = (v: V, data: unknown): Readonly<Record<string, string>> | undefined => {
  const path = "$.data";
  if (!preflight(v, data, path, NAMED_LIMITS.DEPLOYMENT_INITIALIZED)) return undefined;
  const [required, optional] = genesisKeys(v);
  const r = rec(v, data, path, required, optional);
  if (r === undefined || !domain(v, r.domain, `${path}.domain`) || !contentHash(v, r.adapterPolicyHash, `${path}.adapterPolicyHash`) ||
      !identifier(v, r.canonicalLineageId, `${path}.canonicalLineageId`) || !declaredVersionSet(v, r.versions, `${path}.versions`) ||
      !identifier(v, r.policyVersion, `${path}.policyVersion`) ||
      (r.rootRecognitionPolicy !== ROOT_RECOGNITION_POLICY && !fail(v, `${path}.rootRecognitionPolicy`, `must equal ${ROOT_RECOGNITION_POLICY}`)) ||
      !identifier(v, r.globalPolicySourceId, `${path}.globalPolicySourceId`) ||
      (r.timeSource !== "EVENT_TIMESTAMP" && !fail(v, `${path}.timeSource`, "must equal EVENT_TIMESTAMP")) ||
      (r.finality !== "LOCAL_ONLY" && !fail(v, `${path}.finality`, "must equal LOCAL_ONLY"))) return undefined;
  return r.versions;
};
/** The reducer's genesis-position checks: probe, then schema version, then the remaining version literals. */
const genesisVersionCheck = (v: V, data: unknown): EventValidation | undefined => {
  const versions = genesisProbe(v, data);
  if (versions === undefined) return schemaFailure(v, "$.data: invalid genesis version probe");
  const expected = expectedVersionsOf(v.format);
  if (versions.eventSchemaVersion !== expected.eventSchemaVersion) return invalid("UNSUPPORTED_EVENT_SCHEMA", `$.data.versions.eventSchemaVersion: ${versions.eventSchemaVersion}`);
  for (const [key, value] of Object.entries(expected)) {
    if (versions[key] !== value) return invalid("UNSUPPORTED_VERSION", `$.data.versions.${key}: ${versions[key]}`);
  }
  if (format2(v)) {
    for (const key of Object.keys(versions)) if (!FORMAT2_VERSION_KEYS.includes(key)) return invalid("UNSUPPORTED_VERSION", `$.data.versions.${key}: is not a format-2 version key`);
  }
  if (isTrellis(v.format) && !(SIGNATURE_SCHEMES as readonly string[]).includes(versions.signatureScheme!)) {
    return invalid("UNSUPPORTED_VERSION", `$.data.versions.signatureScheme: ${versions.signatureScheme}`);
  }
  return undefined;
};

/**
 * Envelope + closed per-type schema for one raw event at `position`. The
 * returned event is a frozen record with captured (frozen, canonical-order) data.
 * Check order matches spec 01 §D.6 steps 1–3: capture, genesis position, type, schema.
 */
export type ValidateEventOptions = Readonly<{
  /**
   * The event sits in a migrated history's prefix (docs/HISTORY-FORMAT.md §11; SPEC §16.2 step 3): `true` (or the legacy
   * literal) names a legacy source, the format-1 literal a format-1 source of a format-2 history.
   */
  shadow?: boolean | HistoryFormat;
  /** Format 2: the genesis `migratedFrom.position` (the positional rules of SPEC §8.6 and §16.2 step 2(c)/(d)); absent for a native history. */
  migratedUntil?: number;
}>;
/** SPEC §3.1: a key beginning with `$continuity.` anywhere in format-2 `data` is `EVENT_DATA_INVALID` (the marker record is not representable). */
const reservedKeyPath = (value: unknown, path: string, depth = 0): string | undefined => {
  if (value === null || typeof value !== "object" || depth > 64) return undefined;
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) { const found = reservedKeyPath(value[index], `${path}[${index}]`, depth + 1); if (found !== undefined) return found; }
    return undefined;
  }
  for (const key of Object.keys(value)) {
    if (key.startsWith(RESERVED_KEY_PREFIX)) return `${path}.${key}`;
    const found = reservedKeyPath((value as Rec)[key], `${path}.${key}`, depth + 1);
    if (found !== undefined) return found;
  }
  return undefined;
};
/** SPEC §16.2 step 2(c): a format-1 source's `/1` control authorization kept verbatim, allowed only inside the migrated prefix. */
const sourceControlAuthorizationFailure = (v: V, value: unknown): string | undefined => {
  if (!inMigratedPrefix(v)) return "$.data.sourceControlAuthorization: is allowed only inside the migrated prefix";
  if (v.shadow !== TRELLIS_FORMAT) return "$.data.sourceControlAuthorization: is allowed only in the prefix of a format-1 source (legacy control events had none, A-35.2)";
  const r = rec(v, value, "$.data.sourceControlAuthorization", ["keyId", "signature"]);
  return r !== undefined && identifier(v, r.keyId, "$.data.sourceControlAuthorization.keyId") && (isSignature64(r.signature) || isSignature65(r.signature)) ? undefined : (v.problem ?? "$.data.sourceControlAuthorization: malformed");
};
export const validateEvent = (raw: unknown, format: HistoryFormat, position: number, options?: ValidateEventOptions): EventValidation => {
  if (!isPlainRecord(raw)) return invalid("INVALID_INPUT", "$: event must be a plain protocol record");
  const keys = Reflect.ownKeys(raw);
  if (keys.length !== 4 || !keys.every((k) => k === "id" || k === "type" || k === "timestamp" || k === "data")) {
    return invalid("INVALID_INPUT", "$: event has an invalid envelope");
  }
  const source = options?.shadow === true ? LEGACY_FORMAT : options?.shadow === false ? undefined : options?.shadow;
  const v: V = source !== undefined && (format === TRELLIS_FORMAT ? source === LEGACY_FORMAT : format === TRELLIS2_FORMAT && source !== TRELLIS2_FORMAT) ? { format, shadow: source } : { format };
  if (format === TRELLIS2_FORMAT) { v.position = position; if (options?.migratedUntil !== undefined) v.migratedUntil = options.migratedUntil; }
  const { id, type, timestamp } = raw;
  if (!identifier(v, id, "$.id") || !protocolString(v, type, "$.type") || !u53(v, timestamp, "$.timestamp")) return invalid("INVALID_INPUT", v.problem!);
  v.timestamp = timestamp;
  if (!isPlainRecord(raw.data)) return invalid("INVALID_INPUT", "$.data: must be a plain protocol record");
  if (format === TRELLIS2_FORMAT) {
    const reserved = reservedKeyPath(raw.data, "$.data");
    if (reserved !== undefined) return invalid("EVENT_DATA_INVALID", `${reserved}: reserved key is not representable in format-2 event data`);
  }
  let data: unknown;
  try {
    // Replay bodies nest `data` four containers deep (spec 01 §A.8), leaving 28 levels under it.
    data = captureValue(raw.data, { maxTotalBytes: MAX_EVENT_DATA_BYTES, maxDepth: 29 });
  } catch (error) {
    return captureFailure(error);
  }
  collectGhosts(raw.data, data, v);
  if (position === 0) {
    if (type !== "DEPLOYMENT_INITIALIZED") return invalid("GENESIS_REQUIRED", "$.type: history must begin with DEPLOYMENT_INITIALIZED");
    // A string `versions.eventSchemaVersion` naming no event format this engine implements is refused as such before the
    // probe of the fallback format could misreport it as EVENT_DATA_INVALID (SPEC §19 "refuse unknown literals rather than
    // guess"; parity with the Python verifier, G0 Q4). A non-string value still fails the probe as before.
    const declared = (data as { versions?: unknown }).versions;
    const schemaVersion = isPlainRecord(declared) ? (declared as { eventSchemaVersion?: unknown }).eventSchemaVersion : undefined;
    // A-58.7 (narrows A-31): that is the format-1 engines' store-level code; the format-2 replayer (a history read as format 2,
    // e.g. a store whose lines are `irontrellis-record/2`) keeps SPEC §5's UNSUPPORTED_EVENT_SCHEMA (genesisVersionCheck).
    if (v.format !== TRELLIS2_FORMAT && typeof schemaVersion === "string" && formatOfSchemaVersion(schemaVersion) === undefined) {
      return invalid("UNSUPPORTED_VERSION", `$.data.versions.eventSchemaVersion: ${schemaVersion} is not an event format this engine implements`);
    }
    const failure = genesisVersionCheck(v, data);
    if (failure !== undefined) return failure;
  }
  if (!isEventType(type) || (format === LEGACY_FORMAT && TRELLIS_ONLY_EVENT_TYPES.has(type)) || (format !== TRELLIS2_FORMAT && FORMAT2_ONLY_EVENT_TYPES.has(type) && !(format === LEGACY_FORMAT && LEGACY_DUTY_POLICY_EVENTS && DUTY_POLICY_EVENT_TYPES.has(type)))) {
    return invalid("UNSUPPORTED_EVENT_TYPE", `$.type: unsupported EventType ${JSON.stringify(type)}`);
  }
  // Format-1 and format-2 control events carry `controlAuthorization` beside their effect; the schema sees only the effect.
  const control = isTrellis(format) && CONTROL_EVENT_TYPES.has(type);
  if (control && Object.hasOwn(data as Rec, "sourceControlAuthorization")) {
    const failure = format === TRELLIS2_FORMAT ? sourceControlAuthorizationFailure(v, (data as Rec).sourceControlAuthorization) : "$.data.sourceControlAuthorization: is not a declared field";
    if (failure !== undefined) return invalid("EVENT_DATA_INVALID", failure);
  }
  // A-92.0 / A-91.5: co-signatures on a format-2 control event outside a migrated prefix (C4 shape); anywhere else EVENT_DATA_INVALID.
  if (control && Object.hasOwn(data as Rec, ADDITIONAL_CONTROL_AUTHORIZATIONS)) {
    const path = `$.data.${ADDITIONAL_CONTROL_AUTHORIZATIONS}`;
    if (format !== TRELLIS2_FORMAT) return invalid("EVENT_DATA_INVALID", `${path}: is not a declared field`);
    if (inMigratedPrefix(v)) return invalid("EVENT_DATA_INVALID", `${path}: is not allowed inside the migrated prefix (positions 1..migratedFrom.position, A-91.5)`);
    if (!additionalControlAuthorizations(v, (data as Rec)[ADDITIONAL_CONTROL_AUTHORIZATIONS], path)) return schemaFailure(v, `${path}: malformed`);
  }
  // A-52.1 / A-35.2 (C-30): in the prefix of a format-1 source every control event carries its source authorization.
  if (control && format === TRELLIS2_FORMAT && inMigratedPrefix(v) && v.shadow === TRELLIS_FORMAT && !Object.hasOwn(data as Rec, "sourceControlAuthorization")) {
    return invalid("EVENT_DATA_INVALID", "$.data.sourceControlAuthorization: is required on every control event of a format-1 source's prefix (A-52.1)");
  }
  // A-63.1 / A-78.1: no rotation, witness binding or format-2-only type inside a migrated prefix (29–31 also not in a format-1 prefix).
  if (format === TRELLIS2_FORMAT && prefixForbids(v, type)) {
    return invalid("EVENT_DATA_INVALID", `$.type: ${type} cannot occur inside a migrated prefix (A-63.1 / A-78.1)`);
  }
  const effect = control ? controlEffect(data as Rec) : data;
  if (!preflight(v, effect, P, NAMED_LIMITS[type]) || !validateEventData(v, type, effect)) return schemaFailure(v, "$.data: invalid closed event payload");
  return { ok: true, event: Object.freeze({ id, type, timestamp, data: data as Readonly<Record<string, unknown>> }) };
};

/** Standalone genesis validation for stores and owners: probe + exact versions + closed schema. */
/** Genesis `data` alone; `timestamp` (the genesis event's) enables the owner policy's time rules (A-93.2), else they wait for replay. */
export const validateGenesis = (data: unknown, format: HistoryFormat, timestamp?: number): { ok: true; genesis: GenesisRecord } | { ok: false; reason: string } => {
  const v: V = timestamp === undefined ? { format } : { format, timestamp };
  let captured: unknown;
  try {
    captured = captureValue(data, { maxTotalBytes: MAX_EVENT_DATA_BYTES, maxDepth: 29 });
  } catch (error) {
    return { ok: false, reason: error instanceof CanonicalError ? error.reason : "failed canonical capture" };
  }
  const failure = genesisVersionCheck(v, captured);
  if (failure !== undefined) return { ok: false, reason: failure.ok ? "" : failure.reason };
  if (!preflight(v, captured, P, NAMED_LIMITS.DEPLOYMENT_INITIALIZED) || !genesisData(v, captured)) {
    return { ok: false, reason: v.problem ?? "$.data: invalid genesis record" };
  }
  return { ok: true, genesis: captured as GenesisRecord };
};

/** The credential a RUNTIME_SESSION_ADMITTED event registers, normalised for comparison with recovered signers. */
export const sessionCredential = (data: Readonly<Record<string, unknown>>, format: HistoryFormat): { scheme: SignatureScheme; key: string } => {
  if (format === LEGACY_FORMAT || data.credentialScheme !== "ed25519") {
    return { scheme: "eip191-personal-sign-keccak256", key: (data.credentialAddress as string).toLowerCase() };
  }
  return { scheme: "ed25519", key: (data.credentialPublicKey as string).toLowerCase() };
};
