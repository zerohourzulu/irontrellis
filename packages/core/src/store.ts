/**
 * JSONL history store for both formats (spec 01 §E; docs/HISTORY-FORMAT.md §3, §9).
 *
 * One file, one line per event, each line chained to the previous by its
 * `recordHash`. Legacy files (`continuity-portable-file-store/0.2`) use the
 * reference SDK's tagged-tuple encoding and keccak record hashes, byte for byte,
 * so the reference store keeps reading what this store appends. Format-1 files
 * (`irontrellis-portable-file-store/1`) store the event as plain JSON with
 * bigint markers and sha256 record hashes.
 *
 * The store keeps the replayed state in memory and never replays the whole
 * file on append: every append applies one event to the live state. Before
 * touching the state it compares the file size and the raw bytes of the last
 * line it knows; a file that grew is read from the tail, anything else is
 * re-read in full and checked against the pinned head (`<path>.head`), which
 * turns truncation into `ROLLBACK_DETECTED`. A format-1 or format-2 history with events
 * after genesis must have a pin: deleting the pin is itself reported as a
 * rollback (`PIN_MISSING`), never silently re-pinned. Its pin must also carry
 * an owner attestation of a prefix of the file (every other field of a pin is
 * public: `PIN_UNATTESTED`, `PIN_ATTESTATION_INVALID`, `PIN_ATTESTED_NOT_PREFIX`),
 * and every head the local anchor log `<path>.anchors` holds must be a prefix
 * of the file (`ANCHOR_LOG_ROLLBACK`; an unreadable log is `ANCHOR_LOG_UNREADABLE`).
 * Writers without the owner key, and asynchronous signers until they answer,
 * carry the previous attestation forward. Writers serialise through
 * `<path>.writer-lock`, which records `{pid, hostname, createdAt}` so a lock
 * left by a dead process on this host can be reclaimed after 60 s; a reclaim
 * renames the stale lock aside first, so two reclaimers never both hold it.
 * `verify()` also compares the history with its witnesses (the local log
 * `<path>.anchors` and any given ones).
 */
import { createHash, hash as oneShotHash, type Hash } from "node:crypto";
import { closeSync, existsSync, fstatSync, fsyncSync, linkSync, openSync, readFileSync, readSync, realpathSync, renameSync, statSync, unlinkSync, writeSync, type BigIntStats } from "node:fs";
import { hostname } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { compareProtocolStrings, isContentHash, isU53, jsonParseWithBigints, jsonStringifyWithBigints } from "./canonical.ts";
import { StoreConflictError, type EventStore, type EventStoreWriter } from "./coordinators.ts";
import { EngineError } from "./errors.ts";
import { FORMAT2_ONLY } from "./store-fence.ts";
import { capacityLimits, RESERVE_CLASS } from "./capacity.ts";
import { parseStrictJson } from "./strict-json.ts";
import { LEGACY_FORMAT, TRELLIS2_FORMAT, TRELLIS_FORMAT, hashAlgorithmOf, isFormat2, isTrellis } from "./events.ts";
import { canonicalEncode } from "./canonical.ts";
import { verificationNotes } from "./verify-notes.ts";
import { bytesToHex, createHistoryHasher, eventHash as eventHashOf, hashCanonical, hexToBytes, recordHash as chainRecordHash, recordHashBytes } from "./hash.ts";
import { projectionHeadAt, rootAt } from "./state-records.ts";
import { rebuildReplayState, recomputeRoot, recomputeRootTree, type RecordInput } from "./state-rebuild.ts";
import { appendJournalLine, readSnapshotFiles, recordsAt, SNAPSHOT_JOURNAL_LIMIT, takeRecordChanges, writeSnapshotBase, writeSnapshotBaseRecords, type RecordChange } from "./snapshot.ts";
import { stateRecordsOf } from "./state-records.ts";
import { controlSignatureFailure, ownerKeyEpochAt, ownerKeysAt, resumeRootFailure, verifyRotationEvent } from "./owner-keys.ts";
import { verifyHeadAttestation } from "./signer.ts";
import { challengeProfile } from "./session-auth.ts";
import { HEAD_ATTESTATION_VERSION_2 } from "./signer.ts";
import { applyEvent, createReplayState, defaultReplayHooks, detectFormat, incompleteMigration, type MutableReplayState, type ReplayHooks } from "./replay.ts";
import { attestHead, attestHeadSync, ownerKeyPathFor, type Signer } from "./signer.ts";
import { ownerKeyInForce, unqualifiedHeadSigner, verifyHeadAttestationAt } from "./owner-keys.ts";
import { anchorsPathFor, attestedRootMismatch, checkAnchorLogs, localAnchorLog, type AnchorTarget, type PinnedHeadStatus, type VerificationReport, type VerifyOptions } from "./anchor.ts";
import type { WitnessPolicy } from "./witness-client.ts";
import { openWitnessSession, type WitnessSession, type WitnessStatusReport, type WitnessView } from "./witness-session.ts";
import { judgePendingRotation, pendingRotationPathFor, type PendingRotationRecord } from "./rotation-pending.ts";
import { speculate } from "./crypto/parallel-verify.ts";
import { isWindowsTransientError, replaceFileSync, syncDirectorySync } from "./platform.ts";
import { CONTROL_EVENT_TYPES, type CanonicalEvent, type ContentHash, type EventType, type HexSignature, type HistoryFormat, type HistoryHead, type OwnerKey, type OwnerKeyEpoch, type OwnerPolicy, type ReplayState, type SignatureScheme, type TrellisDomain, type U53 } from "./types.ts";

export type StoreFormat = HistoryFormat;
/** A format-1 head attestation (HF1 §9) or a format-2 one (SPEC §7.4: the body also names the domain, the state root and the projection head). */
export type HeadAttestation =
  | Readonly<{ version: "irontrellis-head-attestation/1"; head: HistoryHead; keyId: string; scheme: SignatureScheme; signature: HexSignature }>
  | Readonly<{ version: "irontrellis-head-attestation/2"; domain: TrellisDomain; head: HistoryHead; stateRoot: ContentHash; projectionHead: ContentHash | null; keyId: string; scheme: SignatureScheme; signature: HexSignature }>;
export type PinnedHead = Readonly<{
  hash: ContentHash; position: U53; canonicalTime: U53; recordHash: ContentHash; pinnedAt: U53; attestation?: HeadAttestation;
  /** Set when `acceptRollback` re-pinned over an older pin. */
  rollbackAcceptedAt?: U53; previousPin?: PinnedHead;
}>;
export type StoreOptions = Readonly<{
  /**
   * When the file does not contain its pinned head (`BEHIND_PIN`), the pin is
   * malformed (`PIN_MALFORMED`), a format-1 or format-2 history with events after genesis
   * has no pin (`PIN_MISSING`), its pin has no valid owner attestation of a
   * prefix of the file (`PIN_UNATTESTED`, `PIN_ATTESTATION_INVALID`,
   * `PIN_ATTESTED_NOT_PREFIX`), or the local anchor log holds a head the file
   * no longer contains (`ANCHOR_LOG_ROLLBACK`): re-pin the file as it is (attested
   * when a signer is configured), recording `rollbackAcceptedAt` and the
   * previous pin, instead of failing with `ROLLBACK_DETECTED`. An anchor log
   * that cannot be read is not accepted (`ANCHOR_LOG_UNREADABLE`).
   */
  acceptRollback?: boolean;
  /**
   * Read (and verify) a format-1 or format-2 history whose pin is missing, whose pin has no
   * valid owner attestation of a prefix of the file, or whose local anchor log
   * holds a later head or cannot be read, instead of failing. Reads only: every
   * write to such a history fails with the problem found (use `acceptRollback`
   * to re-pin deliberately). A file behind its pin or a malformed pin still
   * fails the open.
   */
  allowUnpinned?: boolean;
  /**
   * Open for verification only: a pin problem (rollback, missing, malformed, no
   * valid owner attestation) and the witnesses are left for `verify()` to report
   * instead of thrown, and every write, including `acceptRollback`'s re-pin, is
   * refused.
   */
  inspect?: boolean;
  /** `createHistoryStore` only: use an owner key file already present at `<path>.owner-key.json` instead of refusing with `KEY_EXISTS`. */
  reuseExistingKey?: boolean;
  /** Wait up to this long for another writer's lock before `STORE_BUSY` (default 0: fail at once). */
  lockTimeoutMs?: number;
  /** Attests every pinned head (formats 1 and 2). */
  signer?: Signer;
  hooks?: ReplayHooks;
  /** fsync file, directory and pin after each write (default true). */
  fsync?: boolean;
  /** Host clock for `pinnedAt` and lock timestamps. */
  now?: () => U53;
  /** Re-reads when the pin is ahead of the file (a writer between its append and its pin write); default 3 attempts, 10 ms apart. */
  retry?: Readonly<{ attempts?: number; delayMs?: number }>;
  /**
   * Remote witnesses (format 1; docs/WITNESS.md §5). Default: the policy in
   * `<history>.witness.json`, plus every witness the history binds with an
   * owner-signed binding event (those stay in force whatever the side file
   * says). A policy given here replaces the side file's (the bindings still
   * apply); on `createHistoryStore` it is also written to the side file.
   * `false` turns remote witnesses off for this handle (the caller's own choice;
   * nothing on disk can do that).
   */
  witness?: WitnessPolicy | false;
  /**
   * SPEC §16.1: legacy and format-1 histories open read only; every write to them is `FORMAT_READ_ONLY`
   * (`{reason: "LEGACY" | "FORMAT_1"}`). Default `FORMAT_READ_ONLY_DEFAULT` (on). The local owner API passes `false`
   * only for a handle whose caller named format 1 or legacy explicitly (the earlier writer, kept for compatibility and
   * for the format-1 test suites); a migration tool opens the source read only as well.
   */
  readOnlyFormats?: boolean;
  /**
   * SPEC §7.5: how a format-2 history is read on open. `FULL_REPLAY` (the default here; `verify`, `migrate` and the
   * conformance adapter) replays every event. `CHECKPOINT_RESUME` (the local owner/runtime API's default) resumes from
   * the engine-private snapshot `<history>.state` (+ `.state.journal`) after rollback detection, recomputes the §7.1
   * root from the snapshot's records and requires it to equal an owner-signed root at exactly that position (the pin's
   * attestation or a `STATE_CHECKPOINT`), verifies the file's lines against the trusted `event` records (eagerly for the
   * genesis, every owner key rotation and the signed-root line; lazily, as a line is first read, for the rest), rebuilds
   * the state and replays the tail with full validation. Anything else (absent, torn, stale, unsigned or mismatched
   * snapshot) falls back to a full replay, is reported as `SNAPSHOT_STALE` in `verify()` and rebuilds the snapshot.
   */
  trust?: TrustMode;
  /**
   * Addendum A-19.4: the history this handle expects, `recordHash(0)` of its genesis line (format 2). A file whose line 0
   * hashes to anything else is refused on open with `HISTORY_IDENTITY_MISMATCH`, in every trust mode.
   */
  historyId?: ContentHash;
}>;
export type TrustMode = "FULL_REPLAY" | "CHECKPOINT_RESUME";
/** SPEC §16.1: legacy and format-1 files open read only unless the opener asks for the earlier writer (`readOnlyFormats: false`). */
export const FORMAT_READ_ONLY_DEFAULT = true;
/** SPEC §16.2 step 6: the fence marker beside a migrated source, `<source>.migrated`. */
export const MIGRATED_MARKER_VERSION = "irontrellis-migrated/1";
export const migratedMarkerPathFor = (historyPath: string): string => `${historyPath}.migrated`;
export type MigratedMarker = Readonly<{ version: typeof MIGRATED_MARKER_VERSION; target: string; sourceHead: HistoryHead; targetHead: HistoryHead; migratedAt: U53 }>;
/** A path canonicalised for comparison (A-184.1): symlinks resolved (`realpath`) when the file exists, else its directory's. */
export function canonicalPath(path: string): string {
  const absolute = resolve(path);
  try { return existsSync(absolute) ? realpathSync(absolute) : join(realpathSync(dirname(absolute)), basename(absolute)); } catch { return absolute; }
}
/**
 * A-184.1 (§16.2 step 6): the marker's `target` as written, relative to the directory containing the source file, with `/`
 * separators (a leading run of `..` only); the absolute path with `/` separators when no relative path exists (another
 * Windows drive). Both sides are canonicalised first.
 */
export function markerTargetOf(sourcePath: string, targetPath: string): string {
  const to = canonicalPath(targetPath), rel = relative(dirname(canonicalPath(sourcePath)), to);
  return (rel === "" || isAbsolute(rel) ? to : rel).split(sep).join("/");
}
/** A-184.1: a marker `target` in either form, resolved against the source's directory and canonicalised; compare only these. */
export function markerTargetPath(sourcePath: string, target: string): string {
  return canonicalPath(resolve(dirname(canonicalPath(sourcePath)), target));
}
/** The marker as written, `undefined` when absent; a malformed marker is `MIGRATION_MARKER_INVALID` (it cannot name its target or source). */
export function readMigratedMarker(historyPath: string): MigratedMarker | undefined {
  let text: string;
  try { text = readFileSync(migratedMarkerPathFor(historyPath), "utf8"); } catch (error) {
    if (errnoCode(error) === "ENOENT") return undefined;
    throw unavailable("cannot read the migration marker", error);
  }
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { parsed = undefined; }
  const head = (value: unknown): value is HistoryHead => value !== null && typeof value === "object" && isContentHash((value as HistoryHead).hash) && isU53((value as HistoryHead).position) && isU53((value as HistoryHead).canonicalTime);
  const m = parsed as Record<string, unknown> | undefined;
  if (m === null || m === undefined || typeof m !== "object" || m.version !== MIGRATED_MARKER_VERSION || typeof m.target !== "string" || !head(m.sourceHead) || !head(m.targetHead) || !isU53(m.migratedAt)) {
    throw new EngineError("MIGRATION_MARKER_INVALID", `the migration marker ${migratedMarkerPathFor(historyPath)} is malformed`, { markerPath: migratedMarkerPathFor(historyPath) });
  }
  return Object.freeze({ version: MIGRATED_MARKER_VERSION, target: m.target, sourceHead: m.sourceHead, targetHead: m.targetHead, migratedAt: m.migratedAt });
}
/** Store diagnostics for tests and benchmarks: how many times a file was fully replayed, resumed from its snapshot, or had its snapshot rebuilt. */
export const storeCounters = { fullReplays: 0, resumes: 0, snapshotRebuilds: 0, rootRecomputations: 0 };
export const resetStoreCountersForTests = (): void => { storeCounters.fullReplays = 0; storeCounters.resumes = 0; storeCounters.snapshotRebuilds = 0; storeCounters.rootRecomputations = 0; };
/**
 * TEST ONLY (builder test T3): a hook called at the named write-interruption points of a format-2 write
 * (`before-append`, `line-appended`, `before-pin-replace`, `pin-replaced`, `pin-directory-synced`, `before-journal`,
 * `journal-written`, `base-replaced`, `before-reply`); a test's worker process kills itself there.
 */
let cutHook: ((name: string) => void) | undefined;
export const setStoreCutHookForTests = (hook: ((name: string) => void) | undefined): void => { cutHook = hook; };
const cut = (name: string): void => { cutHook?.(name); };
/** `verifyWithWitnesses` options: `VerifyOptions` plus the remote part. */
export type RemoteVerifyOptions = VerifyOptions & Readonly<{
  /** Ask the remote witnesses (default true). */
  remote?: boolean;
  /** A witness that cannot be reached is a note instead of a failure (REMOTE_WITNESS_UNREACHABLE). */
  allowUnreachableWitness?: boolean;
}>;
export type RepinOptions = Readonly<{
  /** Re-pin even when the pin or an anchor log shows a rollback (recorded as `rollbackAcceptedAt` with the previous pin). */
  acceptRollback?: boolean;
  /** Anchor logs to consult besides `<history>.anchors` (each must implement `entries()`). */
  anchorLogs?: readonly AnchorTarget[];
}>;
export interface HistoryStore extends EventStore {
  readonly path: string;
  readonly format: HistoryFormat | undefined;
  /** SPEC §16.1/§16.2: why this file refuses writes (`FORMAT_READ_ONLY {reason}`), or `undefined` when it is writable. */
  readOnlyReason(): "LEGACY" | "FORMAT_1" | "MIGRATED" | undefined;
  /** SPEC §7.5: how the current state was obtained: a full replay, or a resume from the snapshot (`CHECKPOINT_RESUME`). */
  loadedBy(): "FULL_REPLAY" | "CHECKPOINT_RESUME";
  state(): ReplayState;
  head(): HistoryHead | undefined;
  readAll(): readonly CanonicalEvent[];
  append(event: CanonicalEvent): HistoryHead;
  appendAtExpectedHead(event: CanonicalEvent, expected: HistoryHead): HistoryHead;
  appendAll(events: readonly CanonicalEvent[]): HistoryHead;
  withExclusiveWriter<T>(callback: (writer: EventStoreWriter) => T): T;
  /** Chain, pin, pin attestation, recorded anchors and witnesses; see `VerificationReport.ok` / `failures`. */
  verify(options?: VerifyOptions): VerificationReport;
  pinnedHead(): PinnedHead | undefined;
  /**
   * Re-pins the current head under the writer lock, attested by the configured
   * signer (format 1 needs one: `KEY_UNAVAILABLE` otherwise). Use it to bring the
   * owner's attestation up to the head after writers without the owner key
   * (`PIN_ATTESTED_EARLIER`), or after an asynchronous signer failed. It refuses
   * with `REPIN_REFUSED` (`detail.reason` names the finding) when the current
   * pin cannot vouch for the file (`BEHIND_PIN`, `PIN_MALFORMED`, `PIN_MISSING`,
   * `PIN_UNATTESTED`, `PIN_ATTESTATION_INVALID`, `PIN_ATTESTED_NOT_PREFIX`) or a
   * anchor log (`<history>.anchors` and `options.anchorLogs`) holds a head that is
   * not a prefix of the file (`ANCHOR_LOG_ROLLBACK`) or cannot be read
   * (`ANCHOR_LOG_UNREADABLE`): attesting such a head would launder a truncation.
   * With `acceptRollback` (default: the store's option) it re-pins anyway and
   * records `rollbackAcceptedAt` and the previous pin. A pin that already
   * attests the current head is returned as it is.
   */
  repin(options?: RepinOptions): PinnedHead;
  /**
   * Replaces the signer that attests later pins (after an owner key rotation).
   * Pending asynchronous attestations keep the signer they started with. A
   * signer whose key is not in force at a head never attests it (the pin
   * carries the last valid attestation instead).
   */
  setSigner(signer: Signer | undefined): void;
  /**
   * Resolves once asynchronous head attestations (KMS signers) have been
   * written and, with remote witnesses, once a quorum of them holds the current
   * head (owner-keyed stores: the queued head statements and rotations are
   * submitted now). Rejects with ROLLBACK_DETECTED / WITNESS_SPLIT_VIEW on
   * witness evidence, or with the last witness error (WITNESS_UNAVAILABLE,
   * WITNESS_REJECTED, …) when the witnesses do not hold the head yet.
   */
  flush(): Promise<void>;
  /**
   * Resolves once every head attestation started so far (an asynchronous signer: KMS, ssh-agent, command) has been
   * written to the pin or has failed, and so have the witness-cache seals such a signer was asked for. Never rejects: a
   * failed attestation stays for `flush()` to report. No network.
   */
  attestationsSettled(): Promise<void>;
  /**
   * Asks the remote witnesses for their latest heads now (answers younger than
   * `cacheMs` from this process are reused unless `force`), verifies receipts
   * and checkpoint consistency, and compares them with the file. Throws
   * ROLLBACK_DETECTED (reason WITNESS_AHEAD or WITNESS_FORK; sticky: every
   * later read and write of this handle throws it too), WITNESS_SPLIT_VIEW, or WITNESS_UNAVAILABLE when fewer than
   * `n - quorum + 1` witnesses answered. Lifts the `requireOnOpen` gate.
   * Resolves at once when no remote witness is configured.
   */
  checkWitnesses(options?: Readonly<{ force?: boolean }>): Promise<WitnessView>;
  /** What this handle knows about its remote witnesses, without network; `undefined` when none is configured. */
  witnessStatus(): WitnessStatusReport | undefined;
  /**
   * `verify()` plus the remote witnesses: REMOTE_WITNESS_ROLLBACK,
   * REMOTE_WITNESS_SPLIT_VIEW, REMOTE_WITNESS_INVALID and
   * REMOTE_WITNESS_UNREACHABLE (fails closed unless `allowUnreachableWitness`)
   * failures; UNWITNESSED_TAIL and REMOTE_WITNESS_EQUIVOCATION_RECORDED notes.
   */
  verifyWithWitnesses(options?: RemoteVerifyOptions): Promise<VerificationReport>;
  /**
   * Drops the cached history and refuses any later read or write
   * (`READ_UNAVAILABLE`). Idempotent. It does not wait for pending asynchronous
   * head attestations: `await flush()` first when a KMS signer is configured.
   */
  close(): void;
}

export const PINNED_HEAD_VERSION = "irontrellis-pinned-head/1";
export const LOCK_STALE_MS = 60_000;
const LINE_VERSIONS: Readonly<Record<HistoryFormat, string>> = Object.freeze({
  "continuity-event/0.2": "continuity-portable-file-store/0.2", "irontrellis-event/1": "irontrellis-portable-file-store/1", "irontrellis-event/2": "irontrellis-portable-file-store/2",
});
const FILE_CAPS: Readonly<Record<HistoryFormat, number>> = Object.freeze({ "continuity-event/0.2": 64 * 1024 * 1024, "irontrellis-event/1": 1024 * 1024 * 1024, "irontrellis-event/2": 1024 * 1024 * 1024 });
/** The hard size limit of a history file, per format, in bytes (`HISTORY_FILE_LIMIT` on append; refused on open above it). */
export const HISTORY_FILE_LIMITS: Readonly<Record<HistoryFormat, number>> = FILE_CAPS;
const RECORD_KEYS = "event,previousHash,recordHash,version";
/** Per-line strict decoder; a BOM is kept (and then refused by the JSON parser), never silently dropped. */
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

const invalid = (reason: string, detail?: unknown): EngineError => new EngineError("INVALID_HISTORY", reason, detail);
const errnoCode = (error: unknown): string | undefined => (error as { code?: unknown } | null)?.code as string | undefined;
const messageOf = (error: unknown): string => (error instanceof Error ? error.message : String(error));
const unavailable = (what: string, error: unknown): EngineError => new EngineError("READ_UNAVAILABLE", `${what}: ${messageOf(error)}`, { cause: errnoCode(error) });

// ---------------------------------------------------------------- legacy tagged-tuple encoding (spec 01 §E.2)

/**
 * Writer side. With `sort`, records are emitted the way the reference does after
 * canonical capture: keys in protocol order, inserted into a null-prototype
 * record and enumerated (so integer-like keys come first, as JS enumerates them).
 * Without it, entries keep their current order (the reader's round-trip check).
 */
const encodeTagged = (v: unknown, sort: boolean): unknown => {
  if (v === null) return ["null"];
  if (typeof v === "bigint") return ["bigint", v.toString()];
  if (Array.isArray(v)) return ["array", v.map((x) => encodeTagged(x, sort))];
  if (typeof v === "object") {
    let record = v as Record<string, unknown>;
    if (sort) {
      const ordered: Record<string, unknown> = Object.create(null);
      for (const key of Object.keys(record).sort(compareProtocolStrings)) ordered[key] = record[key];
      record = ordered;
    }
    return ["object", Object.entries(record).map(([k, x]) => [k, encodeTagged(x, sort)])];
  }
  if (typeof v === "string" || typeof v === "boolean" || typeof v === "number") return [typeof v, v];
  throw invalid("unsupported stored value");
};
const decodeTagged = (v: unknown, depth = 0): unknown => {
  if (depth > 128 || !Array.isArray(v)) throw invalid("invalid stored encoding");
  const [tag, body] = v as [unknown, unknown];
  if (tag === "null" && v.length === 1) return null;
  if (v.length !== 2) throw invalid("invalid stored encoding");
  if (tag === "bigint" && typeof body === "string" && /^(0|[1-9][0-9]*)$/.test(body) && body.length <= 78) return BigInt(body);
  if (tag === "string" && typeof body === "string") return body;
  if (tag === "number" && typeof body === "number" && Number.isSafeInteger(body) && body >= 0) return body;
  if (tag === "boolean" && typeof body === "boolean") return body;
  if (tag === "array" && Array.isArray(body)) return body.map((x) => decodeTagged(x, depth + 1));
  if (tag === "object" && Array.isArray(body)) {
    const result: Record<string, unknown> = Object.create(null);
    for (const entry of body) {
      if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== "string" || Object.hasOwn(result, entry[0])) throw invalid("invalid stored object");
      Object.defineProperty(result, entry[0], { value: decodeTagged(entry[1], depth + 1), enumerable: true });
    }
    return result;
  }
  throw invalid("invalid stored encoding");
};

// ---------------------------------------------------------------- lines

type ParsedLine = Readonly<{ event: unknown; recordHash: ContentHash }>;

/** Which line format a file uses, from its first record's `version`. */
const lineFormatOf = (firstLine: string): HistoryFormat => {
  // A byte order mark is what some Windows editors add when they save UTF-8: refused like any other edit, but named.
  if (firstLine.startsWith("\uFEFF")) throw invalid("first record is unparsable: the file starts with a UTF-8 byte order mark (added by an editor?); a history is UTF-8 without one");
  let version: unknown;
  try {
    version = (JSON.parse(firstLine) as { version?: unknown } | null)?.version;
  } catch (error) {
    throw invalid(`first record is unparsable: ${messageOf(error)}`);
  }
  const format = (Object.keys(LINE_VERSIONS) as HistoryFormat[]).find((key) => LINE_VERSIONS[key] === version);
  if (format === undefined) throw invalid(`unknown store format ${String(version)}`);
  return format;
};

/**
 * Every check the reference reader makes (spec 01 §E.4 step 4), for every format. Format 2 (SPEC §4): the line is plain
 * JSON (never marker-decoded, so a planted marker reaches the schema and is `EVENT_DATA_INVALID`) and `recordHash` is the
 * §4.3 chain hash of the event at `position`.
 */
const parseLine = (line: string, format: HistoryFormat, previousHash: ContentHash | null, position: number): ParsedLine => {
  // A-33 / C-37: INVALID_HISTORY (the chain-break store code) names the position of the line it refuses.
  const invalid = (reason: string): EngineError => new EngineError("INVALID_HISTORY", reason, { position });
  const legacy = format === LEGACY_FORMAT;
  let record: unknown;
  try {
    // A-34: a format-2 line is parsed strictly (no duplicate key, integers only within ±(2^53−1), no -0, no lone surrogate).
    record = format === TRELLIS2_FORMAT ? parseStrictJson(line) : legacy ? JSON.parse(line) : jsonParseWithBigints(line);
  } catch (error) {
    throw invalid(`unparsable record: ${messageOf(error)}`);
  }
  if (record === null || typeof record !== "object" || Array.isArray(record) || Object.keys(record).sort().join(",") !== RECORD_KEYS) {
    throw invalid("record must carry exactly version, previousHash, event and recordHash");
  }
  const { version, previousHash: previous, event: stored, recordHash } = record as Record<string, unknown>;
  if (version !== LINE_VERSIONS[format]) throw invalid(`unexpected record version ${String(version)}`);
  if (previous !== previousHash) throw invalid("record hash chain mismatch");
  // Format 1: the event's key order is not significant for hashing (the record hash covers its canonical
  // encoding), so lines written before keys were sorted, or by other writers, stay valid.
  let event = stored;
  if (legacy) {
    event = decodeTagged(stored);
    if (JSON.stringify(encodeTagged(event, false)) !== JSON.stringify(stored)) throw invalid("noncanonical store encoding");
  }
  let hash: ContentHash;
  try {
    hash = format === TRELLIS2_FORMAT ? chainRecordHash(previousHash, event, position) : hashCanonical({ version, previousHash, event }, hashAlgorithmOf(format));
  } catch (error) {
    throw invalid(`record is not canonical: ${messageOf(error)}`);
  }
  if (recordHash !== hash) throw invalid("record integrity check failed");
  return { event, recordHash: hash };
};

/**
 * Format-1 writer: plain JSON (bigint markers) with every record's keys in
 * canonical order (`compareProtocolStrings`, recursively; arrays keep their
 * order), so a line does not depend on the caller's key order. Serialised by
 * hand because JS enumerates integer-like keys first whatever the insertion
 * order. The reader accepts any key order: the record hash is taken over the
 * canonical encoding, so key order in the file is not significant for hashing.
 */
const stringifySorted = (v: unknown): string => {
  if (Array.isArray(v)) return `[${v.map(stringifySorted).join(",")}]`;
  if (v !== null && typeof v === "object") {
    const record = v as Record<string, unknown>;
    const members = Object.keys(record).sort(compareProtocolStrings).filter((key) => record[key] !== undefined)
      .map((key) => `${JSON.stringify(key)}:${stringifySorted(record[key])}`);
    return `{${members.join(",")}}`;
  }
  return jsonStringifyWithBigints(v);
};

/** Format 2 writes the event as its canonical text (SPEC §4.1) and chains with the §4.3 record hash. */
const encodeLine = (format: HistoryFormat, previousHash: ContentHash | null, event: CanonicalEvent, position: number): { bytes: Buffer; recordHash: ContentHash } => {
  const version = LINE_VERSIONS[format];
  const text = format === LEGACY_FORMAT ? JSON.stringify(encodeTagged(event, true)) : format === TRELLIS2_FORMAT ? canonicalEncode(event) : stringifySorted(event);
  const recordHash = format === TRELLIS2_FORMAT ? chainRecordHash(previousHash, event, position) : hashCanonical({ version, previousHash, event }, hashAlgorithmOf(format));
  const previous = previousHash === null ? "null" : `"${previousHash}"`;
  return { bytes: Buffer.from(`{"version":"${version}","previousHash":${previous},"event":${text},"recordHash":"${recordHash}"}\n`), recordHash };
};

/**
 * Offsets of the newline ending each line; the file must end with one. The
 * buffer is split on the byte 0x0A and never decoded as a whole: a format-1
 * history may grow to 1 GiB, past V8's maximum string length (~512 MiB).
 * Splitting on 0x0A is safe for UTF-8, whose multi-byte sequences never contain it.
 */
const lineEnds = (bytes: Buffer): number[] => {
  if (bytes.length === 0 || bytes[bytes.length - 1] !== 0x0a) throw invalid("history file has an incomplete record");
  const ends: number[] = [];
  for (let at = bytes.indexOf(0x0a); at !== -1; at = bytes.indexOf(0x0a, at + 1)) ends.push(at);
  return ends;
};
/** Line `index` as strict UTF-8 text. */
const lineText = (bytes: Buffer, ends: readonly number[], index: number): string => {
  try {
    return UTF8.decode(bytes.subarray(index === 0 ? 0 : ends[index - 1]! + 1, ends[index]));
  } catch {
    throw invalid("not valid UTF-8");
  }
};
const lastLineOf = (bytes: Buffer): Buffer => bytes.subarray(bytes.lastIndexOf(10, bytes.length - 2) + 1);

/**
 * What a full replay in `CHECKPOINT_RESUME` mode collects for the snapshot it rebuilds afterwards (SPEC §7.5): the record
 * set at `baseAt` (the position the pin's attestation signs) and one journal line per later event, so the rebuilt
 * snapshot has an owner-signed root at its base and the resume can use it at once.
 */
type SnapshotPlan = { baseAt: number; baseRecords?: RecordInput[]; baseRoot?: ContentHash | undefined; journal: Array<{ position: number; type: CanonicalEvent["type"]; recordHash: ContentHash; changes: readonly RecordChange[] }> };
/** Parse and apply the lines of `bytes` onto `state`, extending `recordHashes`; the first line chains to its last entry. */
const applyLines = (state: MutableReplayState, recordHashes: ContentHash[], bytes: Buffer, ends: readonly number[], format: HistoryFormat, hooks: ReplayHooks, plan?: SnapshotPlan): void => {
  let previousHash = recordHashes.at(-1) ?? null;
  for (let index = 0; index < ends.length; index += 1) {
    const position = state.events.length;
    let parsed: ParsedLine;
    try {
      parsed = parseLine(lineText(bytes, ends, index), format, previousHash, position);
    } catch (error) {
      throw invalid(`record ${position}: ${messageOf(error)}`, { position });
    }
    const result = applyEvent(state, parsed.event, hooks);
    if (!result.ok) throw invalid(`history rejected at position ${position}: ${result.code} (${result.reason})`, { position, code: result.code });
    recordHashes.push(parsed.recordHash);
    previousHash = parsed.recordHash;
    if (plan !== undefined && format === TRELLIS2_FORMAT) {
      const changes = takeRecordChanges(state);
      if (position === plan.baseAt) { plan.baseRecords = stateRecordsOf(state).map((e) => ({ kind: e.kind, key: e.key, record: e.record })); plan.baseRoot = state.stateRoots[position]; }
      else if (position > plan.baseAt) plan.journal.push({ position, type: result.event.type, recordHash: parsed.recordHash, changes });
    }
  }
};

// ---------------------------------------------------------------- files

/**
 * `digest`: a running SHA-256 of exactly the bytes the cached replay was parsed from (the whole file as read, then
 * each tail another writer appended). `undefined` once this instance has written (its own lines were encoded, not
 * parsed back), so `verify()` then re-parses as before.
 */
type Loaded = {
  format: HistoryFormat | undefined; state: MutableReplayState | undefined; recordHashes: ContentHash[]; size: number; lastLine: Buffer | undefined; error: EngineError | undefined; digest?: Hash | undefined;
  /** SPEC §7.5: the state was resumed from the snapshot (no full replay); `snapshot` says what was found. */
  resumed?: boolean; snapshot?: "USED" | "STALE" | "NONE"; snapshotPosition?: number; journalEnd?: number;
  /** A-101.0: why the pin's attestation was not a resume root (the history was replayed in full). */
  resumeRefusal?: string;
  /** A full replay in resume mode: the snapshot material collected for the rebuild. */
  plan?: SnapshotPlan | undefined;
  /** A-33.2: told when a lazily verified line fails (the store then discards the snapshot). */
  lazyFailure?: { notify?: (error: EngineError) => void };
};

/**
 * What line 0 of the history at `path` claims — its store format and the genesis event as written — read from that line
 * alone, without replaying or verifying anything (the open that follows verifies). For a caller that must name the
 * format, or the genesis domain, before it opens the history (the hook: a full replay just to learn the format was the
 * cost of every tool check). `undefined` for an absent or empty file, or a first line that does not parse.
 */
export function readGenesisLine(path: string): Readonly<{ format: HistoryFormat; event: unknown }> | undefined {
  let fd: number;
  try { fd = openSync(path, "r"); } catch (error) { if (errnoCode(error) === "ENOENT") return undefined; throw unavailable("cannot read history", error); }
  const chunks: Buffer[] = [];
  try {
    const chunk = Buffer.allocUnsafe(64 * 1024);
    for (let total = 0; ;) {
      const read = readSync(fd, chunk, 0, chunk.length, total);
      if (read === 0) break;
      const end = chunk.subarray(0, read).indexOf(10);
      chunks.push(Buffer.from(chunk.subarray(0, end === -1 ? read : end)));
      total += read;
      if (end !== -1 || total > FILE_CAPS[LEGACY_FORMAT]) break;
    }
  } catch (error) {
    throw unavailable("cannot read history", error);
  } finally {
    closeSync(fd);
  }
  const bytes = Buffer.concat(chunks);
  if (bytes.length === 0) return undefined;
  try {
    const line = UTF8.decode(bytes);
    const format = lineFormatOf(line);
    const stored = (JSON.parse(line) as { event?: unknown }).event;
    return Object.freeze({ format, event: format === LEGACY_FORMAT ? decodeTagged(stored) : stored });
  } catch {
    return undefined;
  }
}

/** The whole file; an absent file reads as empty (I/O defects throw READ_UNAVAILABLE). */
const readHistoryBytes = (path: string): Buffer => {
  try {
    return readFileSync(path);
  } catch (error) {
    if (errnoCode(error) === "ENOENT") return Buffer.alloc(0);
    throw unavailable("cannot read history", error);
  }
};

/**
 * Files with at least this many records replay with their Ed25519 verifications on the verification pool
 * (crypto/parallel-verify.ts); smaller ones are not worth the hand-off.
 */
export const SPECULATIVE_REPLAY_MIN_RECORDS = 1_024;

/** A fresh replay of all `ends` lines of `bytes`: the state, or the first defect thrown. */
const replayLines = (bytes: Buffer, ends: readonly number[], format: HistoryFormat, hooks: ReplayHooks, recordHashes: ContentHash[], plan?: SnapshotPlan): MutableReplayState => {
  const state = createReplayState(format);
  applyLines(state, recordHashes, bytes, ends, format, hooks, plan);
  const incomplete = incompleteMigration(state);
  if (incomplete !== undefined) throw invalid(`history rejected: ${incomplete.code} (${incomplete.reason})`, { position: state.events.length, code: incomplete.code });
  return state;
};

/** Full replay of the file's bytes; content defects land in `error`. With `plan`, the snapshot material of SPEC §7.5 is collected on the way. */
const loadBytes = (bytes: Buffer, hooks: ReplayHooks, plan?: SnapshotPlan): Loaded => {
  const loaded: Loaded = { format: undefined, state: undefined, recordHashes: [], size: 0, lastLine: undefined, error: undefined };
  if (bytes.length === 0) return loaded;
  storeCounters.fullReplays += 1;
  loaded.plan = plan;
  loaded.size = bytes.length;
  loaded.lastLine = lastLineOf(bytes);
  try {
    const ends = lineEnds(bytes);
    let first: string;
    try {
      first = lineText(bytes, ends, 0);
    } catch (error) {
      throw invalid(`record 0: ${messageOf(error)}`, { position: 0 });
    }
    const format = lineFormatOf(first);
    loaded.format = format;
    if (bytes.length > FILE_CAPS[format]) throw invalid("history file exceeds the format's size limit");
    // Large files: the signatures are verified on the pool while the replay runs; its result is kept only when every
    // one of them verified (then it is exactly the sequential result, error included), otherwise the file is replayed
    // again sequentially, which finds the exact first defect. Only with the engine's own validators: caller-supplied
    // hooks must never observe a replay whose signature answers were not yet confirmed.
    // Format 2 too (E5): the speculative run collects its snapshot material into a private plan, adopted only with its result.
    const hashes: ContentHash[] = [];
    const speculativePlan: SnapshotPlan | undefined = plan === undefined ? undefined : { baseAt: plan.baseAt, journal: [] };
    const outcome = ends.length >= SPECULATIVE_REPLAY_MIN_RECORDS && (format === TRELLIS_FORMAT || format === TRELLIS2_FORMAT) && hooks === defaultReplayHooks
      ? speculate(() => replayLines(bytes, ends, format, hooks, hashes, speculativePlan))
      : { speculated: false as const };
    if (outcome.speculated && outcome.verified) {
      loaded.recordHashes = hashes;
      loaded.plan = speculativePlan;
      if (outcome.threw) throw outcome.error;
      loaded.state = outcome.value;
    } else {
      loaded.state = replayLines(bytes, ends, format, hooks, loaded.recordHashes, plan);
    }
  } catch (error) {
    loaded.error = error instanceof EngineError ? error : invalid(messageOf(error));
  }
  loaded.digest = createHash("sha256").update(bytes);
  return loaded;
};

/**
 * The lazily verified event array of a resumed state (SPEC §7.5 step 2, the lazy option): element `q` is parsed from
 * the file's line `q` when first read, chained from the trusted `event` record of `q−1` and required to hash to the
 * trusted record of `q` (its `recordHash` commits to the event hash); a line that does not is `INVALID_HISTORY` at that
 * read. The array has exactly `count` elements; the tail replay pushes verified events after them as usual.
 */
const lazyEvents = (bytes: Buffer, ends: readonly number[], format: HistoryFormat, records: readonly EventRecordView[], count: number, failure?: { notify?: (error: EngineError) => void }): CanonicalEvent[] => {
  const target: (CanonicalEvent | undefined)[] = new Array<CanonicalEvent | undefined>(count);
  // A-33.2: the read that found the defect fails with INVALID_HISTORY {position}; the store discards the snapshot.
  const refuse = (q: number, reason: string): never => {
    const error = invalid(`record ${q}: ${reason}`, { position: q });
    failure?.notify?.(error);
    throw error;
  };
  // The writer's own line form (encodeLine): `{"version":V,"previousHash":P,"event":` ‖ canonical(event) ‖ `,"recordHash":R}`.
  const head = (q: number): Buffer => Buffer.from(`{"version":"${LINE_VERSIONS[format]}","previousHash":${q === 0 ? "null" : `"${records[q - 1]!.recordHash}"`},"event":`);
  const tail = (q: number): Buffer => Buffer.from(`,"recordHash":"${records[q]!.recordHash}"}`);
  /**
   * A line in exactly the writer's form, chained from the trusted record of q − 1 and naming the trusted record hash of q:
   * the event text between the two is hashed as it stands, and when its SHA-256 is the trusted record's `eventHash` and the
   * §4.3 record hash recomputed over it is the trusted `recordHash`, that text is byte for byte the canonical text the
   * owner-signed state committed to (a strictly valid JSON text: it was produced by the canonical encoder from an accepted
   * event), so `JSON.parse` of it is the event the strict parse would give. Same facts as the full path (A-33.1: both
   * hashes recomputed, never a stored string trusted), without re-validating and re-encoding text already proven
   * canonical by its hash. `undefined` — and the full path decides, with its exact error — for anything else.
   */
  const verifiedByHash = (q: number): CanonicalEvent | undefined => {
    if (format !== TRELLIS2_FORMAT) return undefined;
    const record = records[q]!, start = q === 0 ? 0 : ends[q - 1]! + 1, end = ends[q]!;
    const before = head(q), after = tail(q);
    if (end - start < before.length + after.length || bytes.compare(before, 0, before.length, start, start + before.length) !== 0 || bytes.compare(after, 0, after.length, end - after.length, end) !== 0) return undefined;
    const text = bytes.subarray(start + before.length, end - after.length);
    const eventHash = oneShotHash("sha256", text, "buffer");
    if (`0x${bytesToHex(eventHash)}` !== record.eventHash) return undefined;
    if (`0x${bytesToHex(recordHashBytes(q === 0 ? null : hexToBytes(records[q - 1]!.recordHash), eventHash, q))}` !== record.recordHash) return undefined;
    let event: { id?: unknown; type?: unknown; timestamp?: unknown; data?: unknown };
    try { event = JSON.parse(UTF8.decode(text)) as typeof event; } catch { return undefined; }
    if (event === null || typeof event !== "object" || event.id !== record.eventId || event.type !== record.type || event.timestamp !== record.timestamp) return undefined;
    return Object.freeze({ id: record.eventId, type: record.type as CanonicalEvent["type"], timestamp: record.timestamp, data: event.data as CanonicalEvent["data"] });
  };
  const verified = (q: number): CanonicalEvent => {
    const fast = verifiedByHash(q);
    if (fast !== undefined) return fast;
    const record = records[q]!;
    let parsed: ParsedLine;
    // A-33.1: parseLine checks the line's `previousHash` against the trusted record of q − 1 and recomputes the record hash
    // from the recomputed event hash (it requires the line's own `recordHash` field to equal it); both recomputed hashes
    // are then compared with the trusted `event` record of q — never a stored string in place of a recomputation.
    try {
      parsed = parseLine(lineText(bytes, ends, q), format, q === 0 ? null : records[q - 1]!.recordHash, q);
    } catch (error) {
      return refuse(q, messageOf(error));
    }
    const event = parsed.event as { id?: unknown; type?: unknown; timestamp?: unknown; data?: unknown };
    let recomputedEventHash: ContentHash | undefined;
    try { recomputedEventHash = eventHashOf(parsed.event); } catch { recomputedEventHash = undefined; }
    if (parsed.recordHash !== record.recordHash || recomputedEventHash !== record.eventHash || event.id !== record.eventId || event.type !== record.type || event.timestamp !== record.timestamp) {
      return refuse(q, "the file's line does not match the owner-signed state's event record");
    }
    return Object.freeze({ id: record.eventId, type: record.type as CanonicalEvent["type"], timestamp: record.timestamp, data: event.data as CanonicalEvent["data"] });
  };
  // The target starts as holes: `get` verifies a line on first touch; `has` and `getOwnPropertyDescriptor` answer for the
  // holes too, so `slice`, spread, `for…of` and `Array.from` see a dense array (a resumed store's export view replays prefixes).
  const index = (key: string | symbol): number | undefined => {
    if (typeof key !== "string" || key.length > 16) return undefined;
    const q = Number(key);
    return Number.isInteger(q) && q >= 0 && q < count && String(q) === key ? q : undefined;
  };
  return new Proxy(target as CanonicalEvent[], {
    get(t, key, receiver) {
      const q = index(key);
      if (q !== undefined && t[q] === undefined) t[q] = verified(q);
      return Reflect.get(t, key, receiver);
    },
    has(t, key) { return index(key) !== undefined || Reflect.has(t, key); },
    getOwnPropertyDescriptor(t, key) {
      const q = index(key);
      if (q !== undefined && t[q] === undefined) t[q] = verified(q);
      return Reflect.getOwnPropertyDescriptor(t, key);
    },
  });
};
type EventRecordView = Readonly<{ eventId: string; type: string; timestamp: number; eventHash: ContentHash; recordHash: ContentHash }>;
/**
 * SPEC §7.5 `CHECKPOINT_RESUME`, steps (2)–(5) (step (1), rollback detection, is `#judge` on the result, exactly as for
 * a full replay, and is never skipped). Chooses the snapshot position `S` with an owner-signed root: the pin's `/2`
 * attestation when it attests exactly `S`, else the latest `STATE_CHECKPOINT` at `S + 1` the journal records; anchors
 * trust in the file's genesis line and every owner key rotation (both parsed and chain-checked eagerly, the rotations'
 * control signatures verified), verifies the signed root's signature under the keys in force, recomputes the §7.1 root
 * from the snapshot's records (never a stored field) and requires equality, rebuilds the state, then replays the tail
 * with full validation. `undefined` whenever the snapshot cannot be used (absent, torn, ahead of the file, no signed
 * root at its position, a mismatch): the caller replays in full and rebuilds it (`SNAPSHOT_STALE`).
 */
/** Addendum A-19.1: the lines that may be `OWNER_KEYS_ROTATED` events, found by scanning every line's bytes for the type name (a parse decides). */
const ROTATION_TOKEN = Buffer.from("OWNER_KEYS_ROTATED");
const rotationLineCandidates = (bytes: Buffer, ends: readonly number[]): number[] => {
  const lines: number[] = [];
  let from = 0, line = 0;
  for (let at = bytes.indexOf(ROTATION_TOKEN, from); at !== -1; at = bytes.indexOf(ROTATION_TOKEN, from)) {
    while (line < ends.length && ends[line]! < at) line += 1;
    if (line >= ends.length) break;
    if (lines.at(-1) !== line) lines.push(line);
    from = ends[line]! + 1;
  }
  return lines;
};
const loadWithSnapshot = (path: string, bytes: Buffer, pin: PinnedHead | undefined, hooks: ReplayHooks, signer: Signer | undefined, reasons?: string[]): Loaded | undefined => {
  if (bytes.length === 0) return undefined;
  const files = readSnapshotFiles(path);
  if (files === undefined) return undefined;
  let ends: number[], format: HistoryFormat;
  try { ends = lineEnds(bytes); format = lineFormatOf(lineText(bytes, ends, 0)); } catch { return undefined; }
  if (format !== TRELLIS2_FORMAT || bytes.length > FILE_CAPS[format]) return undefined;
  const lineCount = ends.length;
  const rotations = rotationLineCandidates(bytes, ends);
  const journalEnd = files.journal.at(-1)?.position ?? files.base.position;
  if (journalEnd > lineCount - 1) return undefined;
  // Candidates with a signed root: the head the pin's attestation signs (the pin's own, or an earlier one carried forward by
  // writers without the owner key), a checkpoint at the next position of a journal line.
  const candidates: Array<{ position: number; checkpointAt?: number }> = [];
  const attested = (pin?.attestation as { head?: { position?: unknown } } | null | undefined)?.head?.position;
  if (pin !== undefined && typeof attested === "number" && Number.isSafeInteger(attested) && attested >= files.base.position && attested <= Math.min(journalEnd, pin.position)) candidates.push({ position: attested });
  for (const line of files.journal) if (line.type === "STATE_CHECKPOINT" && line.position >= files.base.position + 1) candidates.push({ position: line.position - 1, checkpointAt: line.position });
  candidates.sort((a, b) => b.position - a.position);
  for (const candidate of candidates) {
    const loaded = resumeAt(path, bytes, ends, format, files, candidate.position, candidate.checkpointAt, pin, hooks, rotations, signer, reasons);
    if (loaded !== undefined) { loaded.journalEnd = journalEnd; return loaded; }
  }
  return undefined;
};
const resumeAt = (path: string, bytes: Buffer, ends: readonly number[], format: HistoryFormat, files: NonNullable<ReturnType<typeof readSnapshotFiles>>, S: number, checkpointAt: number | undefined, pin: PinnedHead | undefined, hooks: ReplayHooks, rotations: readonly number[], signer: Signer | undefined, reasons?: string[]): Loaded | undefined => {
  try {
    const records = recordsAt(files, S);
    if (records === undefined) return undefined;
    // The trusted event records 0…S (contiguous) and the snapshot's owner key epochs (compared with the file's below, A-19.3).
    const eventRecords: EventRecordView[] = [];
    const claimed: Array<{ epoch: number; fromPosition: number; keys: readonly OwnerKeyLike[]; nextKeyDigests: unknown; policy: unknown }> = [];
    for (const entry of records) {
      if (entry.kind === "event") {
        const r = entry.record as Partial<EventRecordView> & { position?: unknown };
        if (typeof r.position !== "number" || typeof r.eventId !== "string" || typeof r.type !== "string" || typeof r.timestamp !== "number" || !isContentHash(r.eventHash) || !isContentHash(r.recordHash)) return undefined;
        eventRecords[r.position] = { eventId: r.eventId, type: r.type, timestamp: r.timestamp, eventHash: r.eventHash, recordHash: r.recordHash };
      } else if (entry.kind === "ownerKeyEpoch") {
        const r = entry.record as { epoch?: unknown; fromPosition?: unknown; keys?: unknown; nextKeyDigests?: unknown; policy?: unknown };
        if (typeof r.epoch !== "number" || typeof r.fromPosition !== "number" || !Array.isArray(r.keys)) return undefined;
        claimed.push({ epoch: r.epoch, fromPosition: r.fromPosition, keys: r.keys as readonly OwnerKeyLike[], nextKeyDigests: r.nextKeyDigests ?? null, policy: r.policy });
      }
    }
    if (eventRecords.length !== S + 1 || eventRecords.some((r) => r === undefined)) return undefined;
    claimed.sort((a, b) => a.epoch - b.epoch);
    const chained = (q: number): CanonicalEvent => {
      const parsed = parseLine(lineText(bytes, ends, q), format, q === 0 ? null : eventRecords[q - 1]!.recordHash, q);
      const record = eventRecords[q];
      const event = parsed.event as CanonicalEvent;
      if (record !== undefined && (parsed.recordHash !== record.recordHash || event.id !== record.eventId || event.type !== record.type || event.timestamp !== record.timestamp)) throw invalid(`record ${q} does not match the snapshot`);
      return event;
    };
    // Addendum A-19.1: the owner key epochs come from the FILE, never from the snapshot — epoch 0 from the genesis line
    // (chain-checked, with its owner approval policy as written), each later epoch from an OWNER_KEYS_ROTATED line at a
    // position ≤ S found by scanning every line, chain-checked and validated under the epoch before it by the state-free
    // rotation verifier (A-120.1 `acceptSF`: control authorization under the epoch's policy, T2, policy validity, HF1).
    const genesis = chained(0);
    if (genesis.type !== "DEPLOYMENT_INITIALIZED") return undefined;
    const domain = genesis.data.domain as TrellisDomain;
    const genesisKeys = ((genesis.data.ownerKeys as readonly OwnerKeyLike[] | undefined) ?? []) as readonly OwnerKey[];
    const genesisDigests = genesis.data.nextKeyDigests as readonly ContentHash[] | undefined;
    const genesisPolicy = genesis.data.ownerPolicy as OwnerPolicy | undefined;
    let epochs: readonly OwnerKeyEpoch[] = [Object.freeze({
      fromPosition: 0, keys: Object.freeze(genesisKeys.slice()), ...(genesisDigests === undefined ? {} : { nextKeyDigests: Object.freeze(genesisDigests.slice()) }),
      ...(genesisPolicy === undefined ? {} : { policy: genesisPolicy }),
    })];
    const openedAt: number[] = [genesis.timestamp];
    for (const r of rotations) {
      if (r > S) break;
      if (r < 1) return undefined;
      const rotation = chained(r);
      if (rotation.type !== "OWNER_KEYS_ROTATED") continue; // the token sat inside another event's text
      const before = eventRecords[r - 1]!;
      const verdict = verifyRotationEvent(rotation, {
        domain, previousHead: { hash: before.recordHash, position: r - 1, canonicalTime: before.timestamp }, epochs, openedAt, historyId: eventRecords[0]!.recordHash, algorithm: "sha256",
      });
      if (!verdict.ok) return undefined;
      epochs = verdict.epochs;
      openedAt.push(verdict.openedAt);
    }
    // Addendum A-19.3: the snapshot's ownerKeyEpoch records must equal the file-derived epochs (else SNAPSHOT_STALE: fall back).
    const sameKeys = (a: readonly OwnerKeyLike[], b: readonly OwnerKeyLike[]): boolean => a.length === b.length && a.every((k, i) => k.keyId === b[i]!.keyId && k.scheme === b[i]!.scheme && k.credential === b[i]!.credential);
    const samePolicy = (claimedPolicy: unknown, derived: OwnerPolicy | undefined): boolean => claimedPolicy === undefined || derived === undefined ? claimedPolicy === derived : canonicalEncode(claimedPolicy) === canonicalEncode(derived);
    if (claimed.length !== epochs.length || claimed.some((c, index) => c.epoch !== index || c.fromPosition !== epochs[index]!.fromPosition || !sameKeys(c.keys, epochs[index]!.keys) ||
        JSON.stringify(c.nextKeyDigests) !== JSON.stringify(epochs[index]!.nextKeyDigests ?? null) || !samePolicy(c.policy, epochs[index]!.policy))) return undefined;
    const keysAt = (position: number): readonly OwnerKey[] => ownerKeysAt(epochs, position);
    // Addendum A-19.3: a reader holding an owner signer accepts only a seeding root signed by that signer's own key.
    const signedBy = (keyId: unknown, credentialKeys: readonly OwnerKey[]): boolean => signer === undefined || (keyId === signer.keyId && credentialKeys.some((k) => k.keyId === signer.keyId && k.scheme === signer.scheme && k.credential.toLowerCase() === signer.credential.toLowerCase()));
    // The owner-signed root at exactly S (step 3): the pin's attestation of S, or the checkpoint at S + 1.
    let signedRoot: ContentHash, projectionHead: ContentHash | null, recordCount: number | undefined;
    if (checkpointAt === undefined) {
      const attestation = pin?.attestation as HeadAttestation | undefined;
      if (pin === undefined || attestation === undefined || attestation === null || typeof attestation !== "object" || attestation.version !== HEAD_ATTESTATION_VERSION_2 || pin.position < S) return undefined;
      if (attestation.head?.position !== S || attestation.head.hash !== eventRecords[S]!.recordHash) return undefined;
      if (pin.position === S && (pin.hash !== eventRecords[S]!.recordHash || pin.recordHash !== eventRecords[S]!.recordHash)) return undefined;
      if (!verifyHeadAttestation(attestation, domain, keysAt(S), "sha256") || !signedBy(attestation.keyId, keysAt(S))) return undefined;
      signedRoot = attestation.stateRoot;
      projectionHead = attestation.projectionHead;
    } else {
      if (checkpointAt > ends.length - 1) return undefined;
      const checkpoint = parseLine(lineText(bytes, ends, checkpointAt), format, eventRecords[S]!.recordHash, checkpointAt).event as CanonicalEvent;
      if (checkpoint.type !== "STATE_CHECKPOINT") return undefined;
      const d = checkpoint.data as { head: { hash: ContentHash; position: number }; stateRoot: ContentHash; recordCount: number; projectionHead: ContentHash | null };
      if (d.head?.position !== S || d.head.hash !== eventRecords[S]!.recordHash || !isContentHash(d.stateRoot)) return undefined;
      if (controlSignatureFailure(checkpoint, { domain, previousHead: { hash: eventRecords[S]!.recordHash, position: S }, keys: keysAt(checkpointAt), algorithm: "sha256" }) !== undefined) return undefined;
      if (!signedBy((checkpoint.data.controlAuthorization as { keyId?: unknown } | undefined)?.keyId, keysAt(checkpointAt))) return undefined;
      signedRoot = d.stateRoot;
      projectionHead = d.projectionHead;
      recordCount = d.recordCount;
    }
    // Step 3: the root is recomputed from the records, never read from the file.
    const recomputed = recomputeRootTree(records);
    storeCounters.rootRecomputations += 1;
    if (recomputed.root !== signedRoot || (recordCount !== undefined && recomputed.count !== recordCount)) return undefined;
    // Step 4: the state from the records, reading referenced events through the lazily verified array; the projection head is the signed one.
    const lazyFailure: { notify?: (error: EngineError) => void } = {};
    const events = lazyEvents(bytes, ends, format, eventRecords, S + 1, lazyFailure);
    const state = rebuildReplayState(records, events, { projectionHead, canonicalBytes: ends[S]! + 1, leaves: recomputed.leaves, tree: recomputed.tree });
    if (state.head.hash !== eventRecords[S]!.recordHash) return undefined;
    const loaded: Loaded = { format, state, recordHashes: eventRecords.map((r) => r.recordHash), size: bytes.length, lastLine: lastLineOf(bytes), error: undefined, resumed: true, snapshot: "USED", snapshotPosition: S, lazyFailure };
    storeCounters.resumes += 1;
    // Step 5: the tail, with full validation.
    try {
      if (S < ends.length - 1) {
        const offset = ends[S]! + 1;
        applyLines(state, loaded.recordHashes, bytes.subarray(offset), ends.slice(S + 1).map((end) => end - offset), format, hooks);
      }
      const incomplete = incompleteMigration(state);
      if (incomplete !== undefined) throw invalid(`history rejected: ${incomplete.code} (${incomplete.reason})`, { position: state.events.length, code: incomplete.code });
    } catch (error) {
      loaded.error = error instanceof EngineError ? error : invalid(messageOf(error));
    }
    // Addendum A-20.1: a pin attestation seeds a resume only when signed by a key of the epoch in force at the file's CURRENT
    // head (the tail replay validated every later rotation); a key retired at or before the head validates a prefix, never a snapshot.
    if (checkpointAt === undefined && loaded.error === undefined) {
      const attestation = pin!.attestation as HeadAttestation;
      const key = keysAt(S).find((k) => k.keyId === attestation.keyId)!;
      if (!ownerKeyInForce(state, state.head.position, { keyId: attestation.keyId, scheme: attestation.scheme, credential: key?.credential ?? "" })) return undefined;
      // A-101.0 (a)(b) and A-111.1 (c): under owner approval policies the signer's class at the attested head and under the
      // append epoch (in force at head + 1, A-120.0), and a single-key checkpoint threshold there. Otherwise FULL_REPLAY with the reason.
      const refusal = resumeRootFailure(key, attestation.head.canonicalTime, ownerKeyEpochAt(epochs, S)!, state.ownerKeyEpochs.at(-1)!);
      if (refusal !== undefined) { reasons?.push(`the pin's attestation of ${S}: ${refusal}`); return undefined; }
    }
    if (signer !== undefined && loaded.error === undefined && !ownerKeyInForce(state, state.head.position, signer)) return undefined;
    return loaded;
  } catch (error) {
    if (process.env.IRONTRELLIS_DEBUG_RESUME) console.error("resume failed:", error);
    return undefined;
  }
};
type OwnerKeyLike = Readonly<{ keyId: string; scheme: string; credential: string }>;

type CachedReplay = Readonly<{ format: HistoryFormat | undefined; state: MutableReplayState | undefined; recordHashes: readonly ContentHash[]; size: number; lastLine: Buffer | undefined; digest: string | undefined }>;

/**
 * verify() without re-parsing: the bytes are exactly the ones the cached replay was parsed from (same length, same
 * SHA-256 as the running digest of every byte that replay read), so re-parsing them would reproduce the cached record
 * hashes, chain and prefix hashes line for line. Any other bytes fall through to `recheckAgainstCache`.
 */
const cachedIfUnchanged = (bytes: Buffer, cache: CachedReplay): Loaded | undefined => {
  const { format, state, recordHashes, lastLine, digest } = cache;
  if (digest === undefined || format === undefined || state === undefined || lastLine === undefined || bytes.length !== cache.size || bytes.length > FILE_CAPS[format]) return undefined;
  if (incompleteMigration(state) !== undefined || createHash("sha256").update(bytes).digest("hex") !== digest) return undefined;
  return { format, state, recordHashes: recordHashes.slice(), size: bytes.length, lastLine, error: undefined };
};

/**
 * verify() without a second replay: when the raw bytes have the cached size and
 * last line, every line is re-parsed (record hash, chain link, record shape) and
 * re-hashed into the history prefix hashes, and each must equal what the cached
 * replay recorded. Equal record hashes mean the replayed events are the file's
 * events, so the cached state stands for the chain/state check. `undefined`
 * whenever the cache cannot vouch for the bytes; the caller then replays in full.
 */
const recheckAgainstCache = (bytes: Buffer, cache: CachedReplay): Loaded | undefined => {
  const { format, state, recordHashes, lastLine } = cache;
  if (format === undefined || state === undefined || lastLine === undefined || bytes.length !== cache.size || bytes.length > FILE_CAPS[format]) return undefined;
  if (!lastLineOf(bytes).equals(lastLine) || incompleteMigration(state) !== undefined) return undefined;
  try {
    const ends = lineEnds(bytes);
    if (ends.length !== state.events.length || ends.length !== recordHashes.length || lineFormatOf(lineText(bytes, ends, 0)) !== format) return undefined;
    const hasher = createHistoryHasher(format);
    let previousHash: ContentHash | null = null;
    for (let position = 0; position < ends.length; position += 1) {
      const parsed = parseLine(lineText(bytes, ends, position), format, previousHash, position);
      if (parsed.recordHash !== recordHashes[position] || hasher.push(parsed.event) !== state.eventHistoryHashes[position]) return undefined;
      previousHash = parsed.recordHash;
    }
  } catch {
    return undefined;
  }
  return { format, state, recordHashes: recordHashes.slice(), size: bytes.length, lastLine, error: undefined };
};

const readRange = (path: string, offset: number, length: number): Buffer => {
  const fd = openSync(path, "r");
  try {
    const bytes = Buffer.alloc(length);
    let done = 0;
    while (done < length) {
      const count = readSync(fd, bytes, done, length - done, offset + done);
      if (count === 0) throw invalid("history file shrank during read");
      done += count;
    }
    return bytes;
  } finally {
    closeSync(fd);
  }
};

/** Syncs the directory holding `path` (errors propagate; skipped on Windows, which cannot fsync a directory: platform.ts). */
const fsyncDirectory = (path: string): void => {
  syncDirectorySync(dirname(path));
};
const writeFully = (fd: number, bytes: Buffer): void => {
  let done = 0;
  while (done < bytes.length) {
    const count = writeSync(fd, bytes, done, bytes.length - done);
    if (count <= 0) throw new Error("write made no progress");
    done += count;
  }
};
/** Appends `bytes`. A failure to open the file (nothing written) is `READ_UNAVAILABLE`; any later failure is thrown as is (bytes may be on disk). */
const appendBytes = (path: string, bytes: Buffer, fsync: boolean): void => {
  let fd: number;
  try {
    fd = openSync(path, "a", 0o600);
  } catch (error) {
    throw new EngineError("READ_UNAVAILABLE", `cannot open history ${path} for writing (nothing was written): ${messageOf(error)}`, { cause: errnoCode(error), mayHaveCommitted: false, path });
  }
  try {
    writeFully(fd, bytes);
    if (fsync) fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  if (fsync) fsyncDirectory(path);
};
let temporaryCounter = 0;
/** Write-to-temp + rename, so readers see either the old or the new file (the rename retries transient Windows sharing failures: platform.ts). */
const writeAtomically = (path: string, text: string, fsync: boolean, cuts?: Readonly<{ beforeReplace: string; replaced: string; synced: string }>): void => {
  const temporary = `${path}.tmp-${process.pid}-${(temporaryCounter += 1)}`;
  const fd = openSync(temporary, "wx", 0o600);
  try {
    writeFully(fd, Buffer.from(text));
    if (fsync) fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  if (cuts !== undefined) cut(cuts.beforeReplace);
  try {
    replaceFileSync(temporary, path);
  } catch (error) {
    try { unlinkSync(temporary); } catch { /* best effort */ }
    throw error;
  }
  if (cuts !== undefined) cut(cuts.replaced);
  if (fsync) fsyncDirectory(path);
  if (cuts !== undefined) cut(cuts.synced);
};

// ---------------------------------------------------------------- pinned head file

const isPin = (value: unknown): value is PinnedHead => {
  if (value === null || typeof value !== "object") return false;
  const pin = value as Record<string, unknown>;
  return pin.version === PINNED_HEAD_VERSION && isContentHash(pin.hash) && isU53(pin.position) && isU53(pin.canonicalTime) && isContentHash(pin.recordHash) && isU53(pin.pinnedAt);
};
/** `undefined` when absent; a malformed file is `ROLLBACK_DETECTED` (reason PIN_MALFORMED): the pin cannot vouch for anything. */
const readPin = (path: string): PinnedHead | undefined => {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (error) {
    if (errnoCode(error) === "ENOENT") return undefined;
    throw unavailable("cannot read pinned head", error);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = undefined;
  }
  if (!isPin(parsed)) throw new EngineError("ROLLBACK_DETECTED", `pinned head file is malformed: ${path}`, { reason: "PIN_MALFORMED", pinPath: path });
  const { version: _version, ...pin } = parsed as PinnedHead & { version: string };
  return Object.freeze(pin);
};
type Snapshot = Readonly<{ loaded: Loaded; pin: PinnedHead | undefined; malformedPin: EngineError | undefined; status: PinnedHeadStatus }>;
const PIN_PROBLEMS: ReadonlySet<PinnedHeadStatus> = new Set(["ROLLBACK", "MISSING", "MALFORMED"]);
const sleep = (ms: number): void => { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); };
/** A format-1 or format-2 history with events after genesis must be pinned (every writer pins; only its creation can precede the first pin). */
const pinRequired = (state: MutableReplayState | undefined): boolean => state !== undefined && isTrellis(state.format) && state.events.length > 1;
/**
 * A consistent view of pin + file. A writer appends its line before it writes
 * the pin, so the pin is read FIRST: whatever the file then shows is at least as
 * long as that pin. Should the pin still be ahead, or still absent after a
 * history's first write (a slow or reordering filesystem), both are re-read a
 * bounded number of times before the gap is called a rollback.
 */
/**
 * `load` for `snapshot`: reads the file and parses it with `parse`, except when a retry finds exactly the bytes the
 * previous attempt parsed (same length and SHA-256): the result would be the same, so it is reused instead of
 * replaying the file again (a missing or rolled-back pin would otherwise cost `attempts` full replays).
 */
const rereadable = (path: string, parse: (bytes: Buffer, pin: PinnedHead | undefined) => Loaded): ((pin: PinnedHead | undefined) => Loaded) => {
  let previous: { size: number; digest: string; loaded: Loaded } | undefined;
  return (pin) => {
    const bytes = readHistoryBytes(path);
    if (previous !== undefined && previous.size === bytes.length && previous.digest === createHash("sha256").update(bytes).digest("hex")) return previous.loaded;
    const loaded = parse(bytes, pin);
    const digest = loaded.digest?.copy().digest("hex");
    previous = digest === undefined ? undefined : { size: bytes.length, digest, loaded };
    return loaded;
  };
};

const snapshot = (headPath: string, load: (pin: PinnedHead | undefined) => Loaded, attempts: number, delayMs: number): Snapshot => {
  let last: Snapshot | undefined;
  for (let attempt = 0; attempt < Math.max(1, attempts); attempt += 1) {
    if (attempt > 0) sleep(delayMs);
    let pin: PinnedHead | undefined;
    let malformedPin: EngineError | undefined;
    try {
      pin = readPin(headPath);
    } catch (error) {
      if (!(error instanceof EngineError && error.code === "ROLLBACK_DETECTED")) throw error;
      malformedPin = error;
    }
    const loaded = load(pin);
    const status: PinnedHeadStatus = malformedPin !== undefined ? "MALFORMED"
      : pin === undefined ? (pinRequired(loaded.state) ? "MISSING" : "UNPINNED") : pinStatus(pin, loaded.state, loaded.recordHashes);
    last = { loaded, pin, malformedPin, status };
    // A pin ahead of (or missing beside) a *valid* file is worth a second look; an invalid file is reported as such regardless.
    if ((status !== "ROLLBACK" && status !== "MISSING") || loaded.error !== undefined) return last;
  }
  return last!;
};
const pinStatus = (pin: PinnedHead, state: MutableReplayState | undefined, recordHashes: readonly ContentHash[]): PinnedHeadStatus => {
  if (state === undefined || pin.position > state.head.position) return "ROLLBACK";
  if (recordHashes[pin.position] !== pin.recordHash || state.eventHistoryHashes[pin.position] !== pin.hash) return "ROLLBACK";
  return pin.position === state.head.position ? "MATCHES" : "AHEAD";
};
/** The error for a pin problem: each reason says what was found, never more. */
const pinProblemError = (status: PinnedHeadStatus, path: string, headPath: string, pin: PinnedHead | undefined, malformed: EngineError | undefined, state: MutableReplayState | undefined): EngineError => {
  if (status === "MALFORMED") return malformed ?? new EngineError("ROLLBACK_DETECTED", `pinned head file is malformed: ${headPath}`, { reason: "PIN_MALFORMED", pinPath: headPath });
  if (status === "MISSING") {
    return new EngineError("ROLLBACK_DETECTED",
      `history ${path} has events after genesis but its pinned head is missing (pin missing: ${headPath}); deleting the pin hides a truncation, so the file is not trusted. Open with acceptRollback to re-pin it as it is`,
      { reason: "PIN_MISSING", pinPath: headPath, observedHead: state?.head });
  }
  return new EngineError("ROLLBACK_DETECTED", `history ${path} does not contain its pinned head (pinned position ${pin!.position}, file position ${state?.head.position ?? "none"}): events were removed or replaced`,
    { reason: "BEHIND_PIN", pinPath: headPath, pinnedHead: pin, observedHead: state?.head });
};
/**
 * The owner's word for the pin, checked on open (format 1, events after
 * genesis): the pin must carry an attestation by a genesis owner key over a
 * head that is a prefix of the file (position at most the file head, the same
 * history hash there). Every field of a pin is public, so a pin without it can
 * be written by anyone who can write the directory, at any truncated head. The
 * attested head may trail the pin (`PIN_ATTESTED_EARLIER` in `verify()`): writers
 * without the owner key, and an asynchronous signer until it answers, carry the
 * previous attestation forward. `undefined` when the pin is acceptable.
 */
const attestationProblem = (pin: PinnedHead, state: MutableReplayState | undefined, path: string, headPath: string): EngineError | undefined => {
  if (state === undefined || !pinRequired(state)) return undefined;
  const attestation = pin.attestation;
  const where = { pinPath: headPath, pinnedHead: pin, observedHead: state.head };
  if (attestation === undefined) {
    return new EngineError("ROLLBACK_DETECTED",
      `history ${path} has events after genesis but its pinned head (position ${pin.position}, ${headPath}) carries no owner attestation; every field of an unattested pin is public, so it cannot rule out a truncation. Open with acceptRollback to re-pin it as it is, or allowUnpinned to read it`,
      { reason: "PIN_UNATTESTED", ...where });
  }
  if (!verifyHeadAttestationAt(attestation, state)) {
    return new EngineError("ROLLBACK_DETECTED", `the pinned head of history ${path} (${headPath}) carries an attestation that is not a valid signature by an owner key of this history`,
      { reason: "PIN_ATTESTATION_INVALID", ...where });
  }
  const head = attestation.head;
  if (head.position > state.head.position || state.eventHistoryHashes[head.position] !== head.hash) {
    return new EngineError("ROLLBACK_DETECTED",
      `the pinned head of history ${path} carries an owner attestation of position ${head.position}, which is not a prefix of the file (head position ${state.head.position}): events the owner vouched for were removed or replaced`,
      { reason: "PIN_ATTESTED_NOT_PREFIX", ...where, attestedHead: { hash: head.hash, position: head.position, canonicalTime: head.canonicalTime } });
  }
  // Addendum A-20.3: a valid owner signature over a root the history does not have at that position is misuse evidence (checked
  // by every opener that replayed; a resumed state matched the root at the attested position itself, or holds no earlier root).
  if (attestedRootMismatch(attestation, state, head.position)) {
    return new EngineError("ATTESTED_STATE_ROOT_MISMATCH",
      `the pinned head of history ${path} (${headPath}) carries a valid owner attestation of position ${head.position} whose stateRoot or projectionHead is not this history's at that position: the owner key signed a state this history does not have`,
      { reason: "PIN", ...where, attestedHead: { hash: head.hash, position: head.position, canonicalTime: head.canonicalTime }, attestedStateRoot: (attestation as { stateRoot?: unknown }).stateRoot, stateRoot: rootAt(state, head.position) });
  }
  return undefined;
};
type AnchorLogProblems = Readonly<{ rollback?: EngineError; unreadable?: EngineError }>;
/**
 * The anchor logs' view on open and in `repin()`: every head a log holds must
 * be a prefix of the file, exactly as `verify()` judges it (`checkAnchorLogs`).
 * A head past the file or off its history is a rollback (`ANCHOR_LOG_ROLLBACK`); a
 * log that exists but cannot be read cannot rule one out (`ANCHOR_LOG_UNREADABLE`).
 * Entries no owner key signed are left to `verify()` (`ANCHOR_LOG_INVALID`): anyone
 * who can write the log can add them, so they prove nothing either way.
 */
const anchorLogProblems = (path: string, state: MutableReplayState | undefined, format: HistoryFormat | undefined, logs: readonly AnchorTarget[]): AnchorLogProblems => {
  if (format === LEGACY_FORMAT) return {};
  const check = checkAnchorLogs(logs, state, format);
  const misuse = check.heads.find((head) => head.status === "STATE_ROOT_MISMATCH");
  if (misuse !== undefined) {
    // Addendum A-20.3: fail closed on open; `verify()` reports it as a failure line.
    const rollback = new EngineError("ATTESTED_STATE_ROOT_MISMATCH", `anchor log ${misuse.location ?? misuse.log} holds a valid owner attestation of position ${misuse.head.position} (key ${misuse.keyId}) whose stateRoot or projectionHead is not this history's at that position: the owner key signed a state this history does not have`,
      { reason: "ANCHOR_LOG", ...(misuse.location === undefined ? {} : { anchorLogPath: misuse.location }), anchoredHead: misuse.head, observedHead: state?.head });
    return { rollback };
  }
  const removed = check.heads.find((head) => head.status === "NEWER_THAN_FILE" || head.status === "NOT_A_PREFIX");
  const where = (location: string | undefined, name: string): string => (location === undefined ? name : `${name} ${location}`);
  const rollback = removed === undefined ? undefined : new EngineError("ROLLBACK_DETECTED",
    `anchor log ${where(removed.location, removed.log)} holds an owner-attested head at position ${removed.head.position} that ${removed.status === "NEWER_THAN_FILE" ? "is past the end of" : "is not a prefix of"} history ${path} (${state === undefined ? "empty" : `head position ${state.head.position}`}): events were removed or replaced`,
    { reason: "ANCHOR_LOG_ROLLBACK", ...(removed.location === undefined ? {} : { anchorLogPath: removed.location }), anchoredHead: removed.head, observedHead: state?.head });
  const failure = check.failures.find((line) => line.startsWith("ANCHOR_LOG_UNREADABLE: "));
  const location = logs.find((log) => log.location !== undefined && failure?.includes(log.location))?.location;
  const unreadable = failure === undefined ? undefined
    : new EngineError("ANCHOR_LOG_UNREADABLE", failure.slice("ANCHOR_LOG_UNREADABLE: ".length), { reason: "ANCHOR_LOG_UNREADABLE", ...(location === undefined ? {} : { anchorLogPath: location }) });
  return { ...(rollback === undefined ? {} : { rollback }), ...(unreadable === undefined ? {} : { unreadable }) };
};
/** Format 2 (SPEC §7.4): the state root and projection head the attestation of `head` commits to; `undefined` for other formats. */
const attestationCommitment = (state: MutableReplayState, head: HistoryHead): Readonly<{ stateRoot: ContentHash; projectionHead: ContentHash | null }> | undefined => {
  if (!isFormat2(state.format)) return undefined;
  const stateRoot = rootAt(state, head.position), projectionHead = projectionHeadAt(state, head.position);
  return stateRoot === undefined || projectionHead === undefined ? undefined : { stateRoot, projectionHead };
};
/** The pin attests exactly `head` with a valid owner signature. */
const attestsExactly = (pin: PinnedHead | undefined, head: HistoryHead, state: MutableReplayState): boolean =>
  // The pin file is public: its attestation may be any JSON value (null included), never trusted for its shape.
  pin?.attestation !== undefined && pin.attestation !== null && typeof pin.attestation === "object" && pin.hash === head.hash && pin.position === head.position && pin.attestation.head?.hash === head.hash && pin.attestation.head.position === head.position &&
  verifyHeadAttestationAt(pin.attestation, state);
/** A pin attestation that `verify()` can accept: owner-signed, covering a head at or before the pin that is a prefix of the file. */
const attestationCovers = (attestation: HeadAttestation, pin: PinnedHead, state: MutableReplayState): boolean => {
  if ((attestation as unknown) === null || typeof attestation !== "object") return false; // e.g. `"attestation": null` in a planted pin
  const head = (attestation as { head?: unknown }).head as Partial<HistoryHead> | undefined;
  return head !== null && typeof head === "object" && typeof head.position === "number" && Number.isSafeInteger(head.position) && head.position <= pin.position &&
    state.eventHistoryHashes[head.position] === head.hash;
};

type LockView = Readonly<{ vanished: boolean; stale: boolean; info?: BigIntStats; text?: string; holder?: Readonly<Record<string, unknown>> }>;
let reclaimCounter = 0;
/**
 * Same file by device and inode, compared as bigints: on Windows the inode is the 64-bit NTFS file id, which a
 * double rounds once its sequence number is past 31, so two lock files in neighbouring MFT records could compare equal.
 */
const sameFile = (a: BigIntStats | undefined, b: BigIntStats | undefined): boolean => a !== undefined && b !== undefined && a.ino === b.ino && a.dev === b.dev;
const BIG = { bigint: true } as const;

// ---------------------------------------------------------------- the store

const isThenable = (value: unknown): value is PromiseLike<unknown> =>
  value !== null && typeof value === "object" && typeof (value as { then?: unknown }).then === "function";

const SESSIONS = new WeakMap<HistoryStore, WitnessSession>();
/** The witness session of a store (host plumbing for the owner API; not exported from the package root). */
export function witnessSessionOf(store: HistoryStore): WitnessSession | undefined {
  return SESSIONS.get(store);
}

class FileHistoryStore implements HistoryStore {
  readonly path: string;
  readonly #headPath: string;
  readonly #lockPath: string;
  readonly #hooks: ReplayHooks;
  #signer: Signer | undefined;
  readonly #acceptRollback: boolean;
  readonly #allowUnpinned: boolean;
  readonly #inspect: boolean;
  readonly #fsync: boolean;
  readonly #now: () => U53;
  readonly #retryAttempts: number;
  readonly #retryDelayMs: number;
  readonly #lockTimeoutMs: number;
  readonly #readOnlyFormats: boolean;
  readonly #trust: TrustMode;
  readonly #historyId: ContentHash | undefined;
  /** The state came from a snapshot resume (SPEC §7.5); `verify()` then replays in full instead of trusting the cache. */
  #resumed = false;
  #snapshotStatus: "USED" | "STALE" | "NONE" | undefined = undefined;
  /** A-101.0: why the pin's attestation did not seed a resume at the last load (report-level), if it did not. */
  #resumeRefusal: string | undefined = undefined;
  /** The last journal position this instance knows (its own writes, or what the resume read); a mismatch at the next write compacts. */
  #journalEnd: number | undefined = undefined;
  #journalLines = 0;
  /** SPEC §16.2 step 6: the fence marker found beside the file on open. */
  #migrated: MigratedMarker | undefined = undefined;
  #format: HistoryFormat | undefined = undefined;
  #state: MutableReplayState | undefined = undefined;
  #recordHashes: ContentHash[] = [];
  /** Bytes of the file this instance has parsed, and the raw bytes of its last line. */
  #size = 0;
  #lastLine: Buffer | undefined = undefined;
  /** SHA-256 of every byte the cached replay was parsed from (see `Loaded.digest`); `undefined` after this instance wrote. */
  #digest: Hash | undefined = undefined;
  #error: EngineError | undefined = undefined;
  /** A pin problem tolerated for reading (`allowUnpinned`, `inspect`); every write refuses with it. */
  #pinProblem: EngineError | undefined = undefined;
  /** Set after a failed write: the file may hold more than the state does. */
  #stale = false;
  #writing = false;
  /** The writer lock this instance holds (inside `withExclusiveWriter`). */
  #lockFd: number | undefined = undefined;
  #attesting: Promise<void> = Promise.resolve();
  #attestationError: unknown = undefined;
  /** `witness: false`: appends are refused while a prepared rotation is outstanding (checked under the writer lock). */
  #witnessOff = false;
  #closed = false;
  /** Set while a recovered prepared rotation is appended: the pin carries the previous attestation, the owner key signs nothing new. */
  #noAttestation = false;
  readonly #witness: WitnessSession;

  constructor(path: string, options: StoreOptions) {
    const absolute = resolve(path);
    try {
      this.path = existsSync(absolute) ? realpathSync(absolute) : join(realpathSync(dirname(absolute)), basename(absolute));
    } catch (error) {
      throw unavailable("history directory is unavailable", error);
    }
    this.#headPath = `${this.path}.head`;
    this.#lockPath = `${this.path}.writer-lock`;
    this.#hooks = options.hooks ?? defaultReplayHooks;
    this.#signer = options.signer;
    this.#acceptRollback = options.acceptRollback === true;
    this.#allowUnpinned = options.allowUnpinned === true;
    this.#inspect = options.inspect === true;
    this.#fsync = options.fsync !== false;
    this.#now = options.now ?? (() => Date.now());
    this.#retryAttempts = options.retry?.attempts ?? 3;
    this.#retryDelayMs = options.retry?.delayMs ?? 10;
    this.#lockTimeoutMs = Number.isSafeInteger(options.lockTimeoutMs) && options.lockTimeoutMs! > 0 ? options.lockTimeoutMs! : 0;
    this.#readOnlyFormats = options.readOnlyFormats ?? FORMAT_READ_ONLY_DEFAULT;
    this.#witnessOff = options.witness === false;
    this.#trust = options.trust ?? "FULL_REPLAY";
    this.#historyId = options.historyId;
    this.#reload();
    this.#witness = openWitnessSession({
      path: this.path, inspect: this.#inspect, signer: () => this.#signer,
      state: () => {
        this.#assertOpen();
        this.#sync();
        if (this.#error !== undefined) throw this.#error;
        return this.#state;
      },
      locked: (critical) => this.#witnessLocked(critical),
      completePending: (record) => this.#completePending(record),
    }, options.witness);
    this.#witness.opened();
    SESSIONS.set(this, this.#witness);
  }

  readOnlyReason(): "LEGACY" | "FORMAT_1" | "MIGRATED" | undefined {
    return (this.#formatReadOnly()?.detail as { reason: "LEGACY" | "FORMAT_1" | "MIGRATED" } | undefined)?.reason;
  }
  loadedBy(): "FULL_REPLAY" | "CHECKPOINT_RESUME" {
    return this.#resumed ? "CHECKPOINT_RESUME" : "FULL_REPLAY";
  }
  get format(): HistoryFormat | undefined {
    return this.#format;
  }

  // ---- cache maintenance

  #plan: SnapshotPlan | undefined = undefined;
  #adopt(loaded: Loaded): void {
    this.#plan = loaded.plan;
    this.#format = loaded.format;
    this.#state = loaded.state;
    this.#recordHashes = loaded.recordHashes;
    this.#size = loaded.size;
    this.#lastLine = loaded.lastLine;
    this.#digest = loaded.digest;
    this.#error = loaded.error;
    this.#stale = false;
    this.#resumed = loaded.resumed === true;
    this.#snapshotStatus = loaded.snapshot;
    this.#resumeRefusal = loaded.resumeRefusal;
    this.#journalEnd = loaded.journalEnd;
    // A-33.2: a lazily read line that fails discards the snapshot (SNAPSHOT_STALE; the cache files are removed unless
    // inspecting) and the next read replays in full, which fails at the same position with the same code.
    if (loaded.lazyFailure !== undefined) {
      loaded.lazyFailure.notify = () => {
        if (this.#state !== loaded.state) return;
        this.#snapshotDiscarded = true;
        this.#snapshotStatus = "STALE";
        this.#stale = true;
        if (!this.#inspect) for (const file of [`${this.path}.state`, `${this.path}.state.journal`]) { try { unlinkSync(file); } catch { /* a cache */ } }
      };
    }
  }
  /** A-33.2: set once a lazy read failed: this store never resumes from the snapshot again. */
  #snapshotDiscarded = false;

  /** The loader of `#reload`: a snapshot resume first in `CHECKPOINT_RESUME` mode (format 2 only), else — and as the fallback — a full replay. */
  #snapshot(): Snapshot {
    const load = (bytes: Buffer, pin: PinnedHead | undefined): Loaded => {
      if (this.#trust === "CHECKPOINT_RESUME") {
        const reasons: string[] = [];
        const resumed = this.#snapshotDiscarded ? undefined : loadWithSnapshot(this.path, bytes, pin, this.#hooks, this.#signer, reasons);
        if (resumed !== undefined) return resumed;
        // The fallback collects the snapshot's base at the position the pin's attestation signs (an owner-signed root the next resume can use).
        const attested = (pin?.attestation as { head?: { position?: unknown } } | null | undefined)?.head?.position;
        const plan: SnapshotPlan | undefined = typeof attested === "number" && Number.isSafeInteger(attested) && attested >= 0 ? { baseAt: attested, journal: [] } : undefined;
        const full = loadBytes(bytes, this.#hooks, plan);
        if (full.format === TRELLIS2_FORMAT) full.snapshot = this.#snapshotDiscarded || existsSync(`${this.path}.state`) ? "STALE" : "NONE";
        // SPEC §7.5 / A-101.0: FULL_REPLAY with the reason a signed root was not used (report-level).
        if (reasons.length > 0) full.resumeRefusal = reasons[0]!;
        return full;
      }
      return loadBytes(bytes, this.#hooks);
    };
    return snapshot(this.#headPath, rereadable(this.path, load), this.#retryAttempts, this.#retryDelayMs);
  }

  /**
   * Full re-read, then the docs/HISTORY-FORMAT.md §9 comparison against the pinned head
   * (AHEAD is the normal state between pins), the pin's owner attestation and
   * the local anchor log. A rollback, a malformed pin, a missing pin (format 1,
   * events after genesis), a pin without a valid owner attestation of a prefix
   * of the file, and an anchor-log head the file no longer contains fail with
   * ROLLBACK_DETECTED unless accepted; an unreadable anchor log fails with
   * ANCHOR_LOG_UNREADABLE. `allowUnpinned` tolerates all but a file behind its pin
   * and a malformed pin, and `inspect` everything, for reading only.
   */
  #reload(): void {
    const { loaded, pin, malformedPin, status } = this.#snapshot();
    this.#adopt(loaded);
    this.#pinProblem = undefined;
    if (this.#error !== undefined) return;
    // Addendum A-19.4: the configured history identity is the genesis line's own record hash.
    if (this.#historyId !== undefined && this.#recordHashes[0] !== undefined && this.#recordHashes[0] !== this.#historyId) {
      this.#stale = true;
      throw new EngineError("HISTORY_IDENTITY_MISMATCH", `history ${this.path} is not the expected history: its genesis line hashes to ${this.#recordHashes[0]}, not ${this.#historyId}`, { expected: this.#historyId, observed: this.#recordHashes[0] });
    }
    try {
      this.#judge(pin, malformedPin, status);
    } catch (error) {
      // The refused file is cached now: without this, the next call would find the cache current and use it.
      this.#stale = true;
      throw error;
    }
    // SPEC §16.2 step 6: a `.migrated` marker fences the file (read only); one that does not name this file's head fails the open.
    this.#migrated = readMigratedMarker(this.path);
    const state = this.#state;
    if (this.#migrated !== undefined && (state === undefined || this.#migrated.sourceHead.hash !== state.head.hash || this.#migrated.sourceHead.position !== state.head.position)) {
      this.#stale = true;
      throw new EngineError("MIGRATION_MARKER_INVALID", `the migration marker ${migratedMarkerPathFor(this.path)} names a source head (position ${this.#migrated.sourceHead.position}) that is not this file's head (${state === undefined ? "empty" : `position ${state.head.position}`})`, { markerPath: migratedMarkerPathFor(this.path), marker: this.#migrated, observedHead: state?.head });
    }
    // SPEC §7.5: after a full replay in resume mode, the snapshot is rebuilt (under the writer lock when free; never for inspection).
    if (this.#trust === "CHECKPOINT_RESUME" && !this.#resumed && !this.#inspect && state !== undefined && isFormat2(state.format) && this.#snapshotStatus !== undefined) this.#rebuildSnapshot(state);
  }

  /** Writes a fresh base at the head when the writer lock is free (a busy writer maintains its own); failures are ignored (the snapshot is a cache). */
  #rebuildSnapshot(state: MutableReplayState): void {
    if (this.#writing) { this.#writeSnapshotBase(state); return; }
    let fd: number | undefined;
    try { fd = this.#acquireLock(); } catch { return; }
    try { this.#writeSnapshotBase(state); } finally { this.#releaseLock(fd); }
  }
  #writeSnapshotBase(state: MutableReplayState): void {
    try {
      const plan = this.#plan;
      this.#plan = undefined;
      if (plan?.baseRecords !== undefined && plan.baseRoot !== undefined && plan.journal.length <= SNAPSHOT_JOURNAL_LIMIT) {
        // After a full replay: the base at the attested position, then the journal through the head.
        writeSnapshotBaseRecords(this.path, plan.baseAt, plan.baseRoot, plan.baseRecords, () => cut("base-replaced"));
        for (const line of plan.journal) appendJournalLine(this.path, line.position, line.type, line.recordHash, line.changes);
        this.#journalLines = plan.journal.length;
      } else {
        writeSnapshotBase(this.path, state, () => cut("base-replaced"));
        this.#journalLines = 0;
      }
      this.#journalEnd = state.head.position;
      storeCounters.snapshotRebuilds += 1;
    } catch { /* the snapshot is a cache: the next open replays in full */ }
  }
  /** After a write: one journal line per accepted event, or a compaction when the journal is unknown, out of step or long. */
  #snapshotAfterWrite(state: MutableReplayState, previousHead: number | undefined, written: readonly Readonly<{ position: number; type: CanonicalEvent["type"]; recordHash: ContentHash; changes: readonly RecordChange[] }>[]): void {
    if (!isFormat2(state.format)) return;
    cut("before-journal");
    try {
      if (this.#journalEnd === undefined || this.#journalEnd !== previousHead || this.#journalLines + written.length > SNAPSHOT_JOURNAL_LIMIT) { this.#writeSnapshotBase(state); return; }
      for (const line of written) appendJournalLine(this.path, line.position, line.type, line.recordHash, line.changes);
      this.#journalEnd = state.head.position;
      this.#journalLines += written.length;
      cut("journal-written");
    } catch { this.#journalEnd = undefined; }
  }

  /** The pin, its attestation and the local anchor log against the file just adopted (see `#reload`). */
  #judge(pin: PinnedHead | undefined, malformedPin: EngineError | undefined, status: PinnedHeadStatus): void {
    // The pin, then its attestation: the first problem found is the one reported.
    let problem: EngineError | undefined;
    let readable = true;
    if (PIN_PROBLEMS.has(status)) {
      problem = pinProblemError(status, this.path, this.#headPath, pin, malformedPin, this.#state);
      readable = status === "MISSING";
    } else if (pin !== undefined) {
      problem = attestationProblem(pin, this.#state, this.path, this.#headPath);
    }
    const tolerate = (found: EngineError, allowed: boolean): boolean => {
      if (!this.#inspect && !(allowed && this.#allowUnpinned && !this.#acceptRollback)) return false;
      this.#pinProblem ??= found;
      return true;
    };
    // `acceptRollback` rewrites the pin, and an anchor log that cannot be read is never accepted, so it is judged
    // before any re-pin (verify and repin --accept-rollback used to re-pin, then fail on the unreadable log).
    // An open that may read past problems (allowUnpinned, as verify's) records it and re-pins nothing; verify() reports it.
    if (this.#acceptRollback && !this.#inspect) {
      const unreadable = anchorLogProblems(this.path, this.#state, this.#format, [localAnchorLog(anchorsPathFor(this.path))]).unreadable;
      if (unreadable !== undefined) {
        if (!this.#allowUnpinned) throw unreadable;
        this.#pinProblem ??= unreadable;
        return;
      }
    }
    if (problem !== undefined && !tolerate(problem, readable)) {
      if (!this.#acceptRollback) throw problem;
      this.#acceptAsIs(pin);
      return;
    }
    if (this.#inspect) return; // verify() reports the anchor logs
    const witness = anchorLogProblems(this.path, this.#state, this.#format, [localAnchorLog(anchorsPathFor(this.path))]);
    if (witness.rollback !== undefined && !tolerate(witness.rollback, true)) {
      if (!this.#acceptRollback) throw witness.rollback;
      if (this.#state !== undefined && !(pin?.rollbackAcceptedAt !== undefined && attestsExactly(pin, this.#state.head, this.#state))) this.#acceptAsIs(pin);
    }
    if (witness.unreadable !== undefined) {
      // Only allowUnpinned reads past it (and every write then refuses); acceptRollback cannot accept what it cannot see.
      if (!this.#allowUnpinned) throw witness.unreadable;
      this.#pinProblem ??= witness.unreadable;
    }
  }

  /** Accepted rollback: pin the file as it is now (attested when a signer is configured), keeping one level of provenance. */
  #acceptAsIs(pin: PinnedHead | undefined): void {
    if (this.#state === undefined) {
      try { unlinkSync(this.#headPath); } catch { /* absent already */ }
      return;
    }
    const previous = pin === undefined ? undefined : (({ previousPin: _dropped, ...rest }) => rest)(pin);
    this.#pin(this.#state.head, this.#recordHashes.at(-1)!, { rollbackAcceptedAt: this.#now(), ...(previous === undefined ? {} : { previousPin: previous }) });
  }

  #tailIntact(): boolean {
    const last = this.#lastLine;
    if (last === undefined) return this.#size === 0;
    try {
      return readRange(this.path, this.#size - last.length, last.length).equals(last);
    } catch {
      return false;
    }
  }

  /** Bring the cache up to date with the file: unchanged → nothing, grown → tail, otherwise full reload. */
  #sync(): void {
    if (this.#stale) {
      this.#reload();
      return;
    }
    let size: number;
    try {
      size = statSync(this.path).size;
    } catch (error) {
      if (errnoCode(error) !== "ENOENT") throw unavailable("cannot stat history", error);
      size = 0;
    }
    if (size === this.#size && (size === 0 || this.#tailIntact())) return;
    if (size > this.#size && this.#state !== undefined && this.#error === undefined && this.#tailIntact()) {
      this.#extend(size);
      return;
    }
    this.#reload();
  }

  /** Another writer appended: parse only the new bytes onto the live state. */
  #extend(size: number): void {
    const bytes = readRange(this.path, this.#size, size - this.#size);
    this.#size = size;
    this.#lastLine = lastLineOf(bytes);
    this.#digest?.update(bytes);
    try {
      applyLines(this.#state!, this.#recordHashes, bytes, lineEnds(bytes), this.#format!, this.#hooks);
    } catch (error) {
      this.#error = error instanceof EngineError ? error : invalid(messageOf(error));
    }
  }

  #assertOpen(): void {
    if (this.#closed) throw new EngineError("READ_UNAVAILABLE", `history store ${this.path} is closed`);
  }

  #current(): MutableReplayState | undefined {
    this.#assertOpen();
    this.#sync();
    if (this.#error !== undefined) throw this.#error;
    this.#witness.guardRead(this.#state);
    return this.#state;
  }

  // ---- reads

  state(): ReplayState {
    const state = this.#current();
    if (state === undefined) throw new EngineError("HISTORY_EMPTY", `history ${this.path} has no events`);
    return state;
  }
  head(): HistoryHead | undefined {
    return this.#current()?.head;
  }
  readAll(): readonly CanonicalEvent[] {
    return Object.freeze(this.#current()?.events.slice() ?? []);
  }
  pinnedHead(): PinnedHead | undefined {
    return readPin(this.#headPath);
  }
  close(): void {
    this.#witness?.close();
    this.#closed = true;
    this.#state = undefined;
    this.#recordHashes = [];
    this.#lastLine = undefined;
    this.#digest = undefined;
  }
  setSigner(signer: Signer | undefined): void {
    this.#assertOpen();
    if (signer !== undefined && (signer === null || typeof signer !== "object" || typeof signer.keyId !== "string" || typeof signer.signHash !== "function")) {
      throw new EngineError("INVALID_INPUT", "setSigner expects a Signer");
    }
    this.#signer = signer;
  }
  attestationsSettled(): Promise<void> {
    return this.#attesting.then(() => this.#witness.sealsSettled());
  }
  flush(): Promise<void> {
    return this.#attesting.then(() => {
      if (this.#attestationError === undefined) return;
      const error = this.#attestationError;
      this.#attestationError = undefined;
      throw error;
    }).then(() => (this.#closed ? undefined : this.#witness.flush())).then(() => this.#witness.sealsSettled());
  }
  async checkWitnesses(options: Readonly<{ force?: boolean }> = {}): Promise<WitnessView> {
    this.#assertOpen();
    return this.#witness.check(options);
  }
  witnessStatus(): WitnessStatusReport | undefined {
    this.#assertOpen();
    return this.#witness.active ? this.#witness.status() : undefined;
  }

  // ---- writes

  /** Refuses a write this instance may not make, before any state is touched; returns the extra pin fields the write must record. */
  #admitWrite(fresh: boolean, types: readonly EventType[]): Partial<PinnedHead> {
    if (this.#inspect) throw new EngineError("READ_UNAVAILABLE", `history store ${this.path} was opened for inspection only`);
    if (!fresh) {
      const fence = this.#formatReadOnly();
      if (fence !== undefined) throw fence;
    }
    if (this.#pinProblem !== undefined) throw this.#pinProblem;
    this.#witness.guardWrite(this.#state, types);
    this.#assertLockOwned();
    // A handle with the witnesses off skips the witness session's ROTATION_PENDING guard, so it is checked here, under the
    // writer lock, immediately before the append: while a prepared owner key rotation is outstanding (docs/WITNESS.md
    // §7.1) a bound witness may already hold its head, and an append on its previous head would fork that witness.
    if (this.#witnessOff && existsSync(pendingRotationPathFor(this.path))) {
      throw new EngineError("WITNESS_UNAVAILABLE", `history ${this.path}: a prepared owner key rotation (${pendingRotationPathFor(this.path)}) is outstanding; this handle has the witnesses off, so it appends nothing until an owner process completes or discards it`,
        { reason: "ROTATION_PENDING", pendingPath: pendingRotationPathFor(this.path) });
    }
    // The pin was deleted while this instance was open: never re-pin such a file silently.
    if (!fresh && pinRequired(this.#state) && !existsSync(this.#headPath)) {
      if (!this.#acceptRollback) throw pinProblemError("MISSING", this.path, this.#headPath, undefined, undefined, this.#state);
      return { rollbackAcceptedAt: this.#now() };
    }
    return {};
  }

  /**
   * SPEC §16.1: a legacy or format-1 file is read only (`FORMAT_READ_ONLY {reason}`), when `readOnlyFormats` is on.
   * TODO(E3): the `.migrated` fence (SPEC §16.2 step 6): a `<path>.migrated` marker makes the file read only with
   * `{reason: "MIGRATED", target}`, and a marker whose `sourceHead` is not the file's is `MIGRATION_MARKER_INVALID`;
   * this method is the hook point (it runs before every write; `#reload` is the hook point for the open-time check).
   */
  #formatReadOnly(): EngineError | undefined {
    const format = this.#format;
    if (this.#migrated !== undefined) {
      const target = markerTargetPath(this.path, this.#migrated.target);
      return new EngineError("FORMAT_READ_ONLY", `history ${this.path} was migrated to ${target} (marker ${migratedMarkerPathFor(this.path)}): it opens read only (SPEC §16.2); write to the target`, { reason: "MIGRATED", target });
    }
    // Step 5d P0-1 (b): a public (format-2-only) store refuses an older format whatever `readOnlyFormats` says.
    if ((!this.#readOnlyFormats && !FORMAT2_ONLY.has(this)) || format === undefined || format === TRELLIS2_FORMAT) return undefined;
    const reason = format === LEGACY_FORMAT ? "LEGACY" : "FORMAT_1";
    return new EngineError("FORMAT_READ_ONLY", `history ${this.path} is a ${reason === "LEGACY" ? "legacy" : "format-1"} file: it opens read only (SPEC §16.1); migrate it to format 2 to write`, { reason });
  }

  /** Validate the batch on the live state (whole batch before any byte), write once, pin. */
  #write(raws: readonly CanonicalEvent[]): HistoryHead {
    const fresh = this.#state === undefined;
    const extra = this.#admitWrite(fresh, raws.map((raw) => raw.type));
    const format = fresh ? (detectFormat(raws) ?? LEGACY_FORMAT) : this.#format!;
    if (fresh && format !== TRELLIS2_FORMAT && FORMAT2_ONLY.has(this)) {
      throw new EngineError("INVALID_INPUT", `a ${format} genesis: the public store writes format 2 only (SPEC §16.1); the format-1-era writer is test tooling`);
    }
    // CHALLENGE-PROFILE-01: frozen-r2.3 verifies the frozen r2.3 vectors only; a format-2 write under it is refused before any byte.
    if (format === TRELLIS2_FORMAT && challengeProfile() === "frozen-r2.3") {
      throw new EngineError("CHALLENGE_PROFILE_READ_ONLY", "the frozen-r2.3 profile only verifies the 86 frozen r2.3 vectors; format-2 writes use g3 (unset IRONTRELLIS_CHALLENGE_PROFILE)", { profile: "frozen-r2.3" });
    }
    const state = this.#state ?? createReplayState(format);
    const chunks: Buffer[] = [];
    const hashes: ContentHash[] = [];
    const written: Array<{ position: number; type: CanonicalEvent["type"]; recordHash: ContentHash; changes: readonly RecordChange[] }> = [];
    const previousHead = this.#state?.head.position;
    let previousHash = this.#recordHashes.at(-1) ?? null;
    let applied = 0;
    let bytes: Buffer;
    try {
      for (const raw of raws) {
        const position = state.events.length;
        const result = applyEvent(state, raw, this.#hooks);
        if (!result.ok) throw new EngineError(result.code, `event at position ${position} rejected: ${result.reason}`, { position, code: result.code });
        applied += 1;
        const line = encodeLine(format, previousHash, result.event, position);
        chunks.push(line.bytes);
        hashes.push(line.recordHash);
        written.push({ position, type: result.event.type, recordHash: line.recordHash, changes: takeRecordChanges(state) });
        previousHash = line.recordHash;
      }
      bytes = Buffer.concat(chunks);
      if (format === TRELLIS2_FORMAT) {
        // SPEC §5.2 + the control-event reserve, on the file's actual size (the replay step applied the same thresholds
        // to the canonical line bytes event by event; they coincide for a file this store wrote).
        // A-3/A-0.1: judged after each event (B(p) > HARD_BYTES for every event; B(p) > T_B for the reserve class).
        const { maxFileBytes, reservedFileBytes } = capacityLimits();
        let size = this.#size;
        for (let i = 0; i < chunks.length; i += 1) {
          size += chunks[i]!.length;
          if (size > maxFileBytes) throw new EngineError("CAPACITY_EXCEEDED", `history file would exceed ${maxFileBytes} bytes, the hard limit; the history is terminal`);
          if (size > maxFileBytes - reservedFileBytes && RESERVE_CLASS.has(written[i]!.type)) {
            throw new EngineError("CAPACITY_RESERVED", `the last ${reservedFileBytes} bytes below the file cap admit control events only`);
          }
        }
      } else if (this.#size + bytes.length > FILE_CAPS[format]) throw new EngineError("HISTORY_FILE_LIMIT", `history file would exceed ${FILE_CAPS[format]} bytes`);
    } catch (error) {
      // The live state already holds the accepted prefix of the batch; re-read from disk before the next use.
      if (!fresh && applied > 0) this.#stale = true;
      throw error;
    }
    cut("before-append");
    try {
      appendBytes(this.path, bytes, this.#fsync);
      cut("line-appended");
    } catch (error) {
      if (!fresh) this.#stale = true;
      // The file could not even be opened: nothing was written, so this is not an unconfirmed write.
      if (error instanceof EngineError) throw error;
      throw new EngineError("WRITE_UNCONFIRMED", `append failed: ${messageOf(error)}`, { mayHaveCommitted: true, cause: errnoCode(error) });
    }
    this.#state = state;
    this.#format = format;
    this.#size += bytes.length;
    // These lines were encoded here, not parsed back from the file: verify() re-parses them (and everything else) as before.
    this.#digest = undefined;
    this.#recordHashes.push(...hashes);
    this.#lastLine = chunks.at(-1);
    this.#pin(state.head, hashes.at(-1)!, extra);
    this.#snapshotAfterWrite(state, previousHead, written);
    this.#witness.afterAppend(fresh);
    cut("before-reply");
    return state.head;
  }

  /**
   * The attestation the current pin carries over to a head this writer cannot
   * attest itself (no signer, or one that signs asynchronously): kept only while
   * it is a valid owner signature over a prefix of the history, so a pin never
   * loses the owner's word for the part of the history the owner vouched for
   * (and never carries a forged one forward).
   */
  #carriedAttestation(state: MutableReplayState): HeadAttestation | undefined {
    let current: PinnedHead | undefined;
    try {
      current = readPin(this.#headPath);
    } catch {
      return undefined;
    }
    const attestation = current?.attestation;
    if (attestation === undefined || !verifyHeadAttestationAt(attestation, state)) return undefined;
    const head = attestation.head;
    return head.position <= state.head.position && state.eventHistoryHashes[head.position] === head.hash ? attestation : undefined;
  }

  #writePin(head: HistoryHead, recordHash: ContentHash, extra: Partial<PinnedHead> = {}): PinnedHead {
    const state = this.#state!;
    const trellis = isTrellis(state.format);
    // A signer whose key is not in force at this head (retired by a rotation another writer recorded) never attests it: the pin carries the last valid attestation instead.
    const signer = this.#signerAt(state, head);
    const attestation = !trellis ? undefined
      : (signer === undefined ? undefined : attestHeadSync(signer, state.genesis.domain, head, state.hashAlgorithm, attestationCommitment(state, head))) ?? this.#carriedAttestation(state);
    const pin: PinnedHead = Object.freeze({
      hash: head.hash, position: head.position, canonicalTime: head.canonicalTime, recordHash, pinnedAt: this.#now(), ...(attestation === undefined ? {} : { attestation }), ...extra,
    });
    try {
      writeAtomically(this.#headPath, `${JSON.stringify({ version: PINNED_HEAD_VERSION, ...pin })}\n`, this.#fsync, { beforeReplace: "before-pin-replace", replaced: "pin-replaced", synced: "pin-directory-synced" });
    } catch (error) {
      throw new EngineError("WRITE_UNCONFIRMED", `pinned head could not be written: ${messageOf(error)}`, { mayHaveCommitted: true, cause: errnoCode(error) });
    }
    return pin;
  }

  /** The configured signer when its key is an owner key in force at `head` (format 1), else `undefined`. */
  #signerAt(state: MutableReplayState, head: HistoryHead): Signer | undefined {
    if (this.#noAttestation) return undefined;
    const signer = this.#signer;
    return signer !== undefined && ownerKeyInForce(state, head.position, signer) ? signer : undefined;
  }

  #pin(head: HistoryHead, recordHash: ContentHash, extra: Partial<PinnedHead> = {}): PinnedHead {
    const pin = this.#writePin(head, recordHash, extra);
    const state = this.#state!;
    const signer = isTrellis(state.format) ? this.#signerAt(state, head) : undefined;
    const attestsHead = (attestation: HeadAttestation | undefined): boolean => attestation?.head?.hash === head.hash && attestation.head.position === head.position;
    if (attestsHead(pin.attestation) || signer === undefined || !isTrellis(state.format)) return pin;
    // Asynchronous signer: the pin carries the previous attestation meanwhile (never none when there was one). Once the
    // attestation arrives it replaces the carried one, while the pin is still this head, or a later head of the same
    // history whose carried attestation is older than this one.
    const { domain } = state.genesis;
    const algorithm = state.hashAlgorithm;
    const commitment = attestationCommitment(state, head);
    const newer = (current: PinnedHead): boolean => {
      if (current.hash === pin.hash && current.position === pin.position && current.recordHash === pin.recordHash) return true;
      const carried = current.attestation?.head?.position;
      return current.position > head.position && state.eventHistoryHashes[current.position] === current.hash && state.eventHistoryHashes[head.position] === head.hash &&
        (typeof carried !== "number" || carried < head.position);
    };
    this.#attesting = this.#attesting
      .then(async () => {
        const attestation = await attestHead(signer, domain, head, algorithm, commitment);
        // A programmatic Signer's answer is verified before it replaces the carried attestation (the reference
        // signers verify their own); a bad one would make the next open a false PIN_ATTESTATION_INVALID. The pin keeps
        // the earlier attestation, and flush() reports SIGNER_FAILED.
        if (!verifyHeadAttestationAt(attestation, state)) {
          throw new EngineError("SIGNER_FAILED", `the signer's attestation of head ${head.position} does not verify against the owner key in force; the pin keeps its earlier attestation`, { reason: "ATTESTATION_INVALID", position: head.position });
        }
        // The pin is read, judged and rewritten under the writer lock (another writer may be replacing it meanwhile).
        await this.#underPinLock(() => {
          const current = readPin(this.#headPath);
          if (current === undefined || attestsHead(current.attestation) || !newer(current)) return;
          try {
            writeAtomically(this.#headPath, `${JSON.stringify({ version: PINNED_HEAD_VERSION, ...current, attestation })}\n`, this.#fsync);
          } catch (error) {
            throw new EngineError("WRITE_UNCONFIRMED", `pinned head attestation could not be written: ${messageOf(error)}`, { mayHaveCommitted: true, cause: errnoCode(error) });
          }
        });
      })
      .catch((error: unknown) => {
        this.#attestationError = error;
      });
    return pin;
  }

  /**
   * Runs `critical` (synchronous) holding the writer lock: at once when this instance already holds it (a synchronous
   * `withExclusiveWriter` callback on the stack), else acquired with retries for up to `lockTimeoutMs` (at least 5 s).
   * The signature itself is awaited BEFORE this, never under the lock: a person approving a signer's prompt for a minute
   * does not keep other writers out (tested: another store takes the lock while an attestation is pending). Works after `close()` too: a late attestation still lands under the lock.
   */
  async #underPinLock(critical: () => void): Promise<void> {
    if (this.#writing) { critical(); return; }
    const deadline = Date.now() + Math.max(this.#lockTimeoutMs, 5000);
    for (let delay = 2; ; delay = Math.min(delay * 2, 50)) {
      if (!this.#writing) {
        let fd: number | undefined;
        try { fd = this.#acquireLock(); } catch (error) {
          if (!(error instanceof EngineError && error.code === "STORE_BUSY") || Date.now() > deadline) throw error;
        }
        if (fd !== undefined) {
          this.#writing = true;
          this.#lockFd = fd;
          try { critical(); return; } finally {
            this.#writing = false;
            this.#lockFd = undefined;
            this.#releaseLock(fd);
          }
        }
      } else { critical(); return; }
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }

  #appendAt(event: CanonicalEvent, expected: HistoryHead): HistoryHead {
    if (expected === null || typeof expected !== "object") throw new EngineError("INVALID_INPUT", "expected head must be a record");
    const observed = this.head();
    if (observed === undefined || expected.hash !== observed.hash || expected.position !== observed.position || expected.canonicalTime !== observed.canonicalTime) {
      throw new StoreConflictError(observed);
    }
    return this.#write([event]);
  }

  append(event: CanonicalEvent): HistoryHead {
    return this.withExclusiveWriter(() => {
      const observed = this.head();
      return observed === undefined ? this.#write([event]) : this.#appendAt(event, observed);
    });
  }
  appendAtExpectedHead(event: CanonicalEvent, expected: HistoryHead): HistoryHead {
    return this.withExclusiveWriter(() => this.#appendAt(event, expected));
  }
  appendAll(events: readonly CanonicalEvent[]): HistoryHead {
    if (!Array.isArray(events)) throw new EngineError("INVALID_INPUT", "events must be an array");
    return this.withExclusiveWriter(() => {
      if (events.length > 0) {
        this.#current();
        return this.#write(events);
      }
      const head = this.head();
      if (head === undefined) throw new EngineError("HISTORY_EMPTY", "an empty store needs a genesis batch");
      return head;
    });
  }
  repin(options: RepinOptions = {}): PinnedHead {
    if (options === null || typeof options !== "object") throw new EngineError("INVALID_INPUT", "repin options must be a record");
    const acceptRollback = options.acceptRollback ?? this.#acceptRollback;
    const logs = [localAnchorLog(anchorsPathFor(this.path)), ...(options.anchorLogs ?? [])];
    const refused = (finding: EngineError): EngineError => {
      const detail = (finding.detail ?? {}) as Record<string, unknown>;
      const remedy = finding.code === "ANCHOR_LOG_UNREADABLE" ? "make the anchor log readable again (or archive it deliberately), then repin"
        : "check the file (restore the latest copy if events are missing), then repin with acceptRollback to pin it as it is";
      return new EngineError("REPIN_REFUSED", `repin refused: ${finding.message}. Attesting this head could vouch for a history that was cut or replaced; ${remedy}`,
        { ...detail, reason: detail.reason ?? finding.code, cause: finding.code });
    };
    return this.withExclusiveWriter(() => {
      if (this.#inspect) throw new EngineError("READ_UNAVAILABLE", `history store ${this.path} was opened for inspection only`);
      this.#assertOpen();
      try {
        this.#sync();
      } catch (error) {
        if (error instanceof EngineError && (error.code === "ROLLBACK_DETECTED" || error.code === "ANCHOR_LOG_UNREADABLE")) throw refused(error);
        throw error;
      }
      if (this.#error !== undefined) throw this.#error;
      const state = this.#state;
      if (state === undefined) throw new EngineError("HISTORY_EMPTY", `history ${this.path} has no events`);
      // A remote witness that holds a later or another head forbids attesting this one (the owner would vouch for a rolled-back branch).
      this.#witness.guardRead(state);
      this.#assertLockOwned();
      // What the current pin and the anchor logs say, judged afresh under the lock (the open may have tolerated it for reading).
      let pin: PinnedHead | undefined, malformed: EngineError | undefined;
      try {
        pin = readPin(this.#headPath);
      } catch (error) {
        if (!(error instanceof EngineError && error.code === "ROLLBACK_DETECTED")) throw error;
        malformed = error;
      }
      const status: PinnedHeadStatus = malformed !== undefined ? "MALFORMED"
        : pin === undefined ? (pinRequired(state) ? "MISSING" : "UNPINNED") : pinStatus(pin, state, this.#recordHashes);
      const anchorLog = anchorLogProblems(this.path, state, state.format, logs);
      // An unreadable anchor log is refused on its own, before any rollback is accepted: the single finding below would
      // otherwise pick a pin problem ahead of it, and acceptRollback would tolerate that (a truncated history with an
      // unreadable log was re-pinned).
      if (anchorLog.unreadable !== undefined) throw refused(anchorLog.unreadable);
      const finding = PIN_PROBLEMS.has(status) ? pinProblemError(status, this.path, this.#headPath, pin, malformed, state)
        : (pin === undefined ? undefined : attestationProblem(pin, state, this.path, this.#headPath)) ?? anchorLog.rollback ?? anchorLog.unreadable;
      if (finding !== undefined && (!acceptRollback || finding.code === "ANCHOR_LOG_UNREADABLE")) throw refused(finding);
      if (isTrellis(state.format) && this.#signer === undefined) throw new EngineError("KEY_UNAVAILABLE", "re-pinning an owner-signed history needs the owner signer");
      if (isTrellis(state.format) && this.#signerAt(state, state.head) === undefined) {
        throw new EngineError("KEY_UNAVAILABLE", `the owner signer's key ${this.#signer!.keyId} is not an owner key in force at position ${state.head.position} (a rotation retired it); use the current owner key`, { keyId: this.#signer!.keyId });
      }
      // Nothing to do when the pin already is the owner's attestation of this head (an accepted rollback stays recorded).
      if (isTrellis(state.format) && attestsExactly(pin, state.head, state) && (finding === undefined || pin!.rollbackAcceptedAt !== undefined)) return pin!;
      const previous = pin === undefined ? undefined : (({ previousPin: _dropped, ...rest }) => rest)(pin);
      const extra: Partial<PinnedHead> = finding === undefined ? {} : { rollbackAcceptedAt: this.#now(), ...(previous === undefined ? {} : { previousPin: previous }) };
      const written = this.#pin(state.head, this.#recordHashes.at(-1)!, extra);
      this.#pinProblem = undefined;
      return written;
    });
  }

  // ---- lock

  /** What sits at the lock path: its identity, content and whether it is stale (dead local owner, older than 60 s). */
  #inspectLock(): LockView {
    let fd: number;
    try {
      fd = openSync(this.#lockPath, "r");
    } catch (error) {
      return { vanished: errnoCode(error) === "ENOENT", stale: false };
    }
    let info: BigIntStats, text: string;
    try {
      info = fstatSync(fd, BIG);
      text = readFileSync(fd, "utf8");
    } catch {
      return { vanished: false, stale: false };
    } finally {
      closeSync(fd);
    }
    let owner: { pid?: unknown; hostname?: unknown; createdAt?: unknown } | undefined;
    try {
      const parsed: unknown = JSON.parse(text);
      owner = parsed !== null && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as typeof owner : undefined;
    } catch {
      owner = undefined;
    }
    const holder = owner === undefined ? undefined : Object.freeze({ pid: owner.pid, hostname: owner.hostname, createdAt: owner.createdAt });
    const view = (stale: boolean): LockView => ({ vanished: false, stale, info, text, ...(holder === undefined ? {} : { holder }) });
    let age = this.#now() - Number(info.mtimeMs);
    if (typeof owner?.createdAt === "number") age = Math.min(age, this.#now() - owner.createdAt);
    if (age < LOCK_STALE_MS) return view(false);
    // An unreadable lock (e.g. the empty file the reference SDK writes) cannot name its owner; after 60 s we assume a crash.
    if (owner === undefined || typeof owner.pid !== "number") return view(true);
    if (owner.hostname !== hostname()) return view(false); // liveness is unknowable across hosts
    try {
      process.kill(owner.pid, 0);
      return view(false);
    } catch (error) {
      return view(errnoCode(error) === "ESRCH");
    }
  }

  /**
   * Removes the stale lock `view` saw, race-free: the lock is first renamed to a
   * name only this process uses, and deleted only if the renamed file is the
   * very file judged stale (same inode, mtime and content). If another process
   * had already replaced it with its own fresh lock, that lock is linked back
   * (never over a newer one) and this process stays out.
   */
  #reclaimLock(view: LockView): boolean {
    const aside = `${this.#lockPath}.stale-${process.pid}-${(reclaimCounter += 1)}`;
    try {
      renameSync(this.#lockPath, aside);
    } catch (error) {
      return errnoCode(error) === "ENOENT"; // reclaimed by someone else meanwhile: compete for the fresh lock
    }
    let same = false;
    try {
      const info = statSync(aside, BIG);
      same = sameFile(info, view.info) && info.mtimeNs === view.info!.mtimeNs && readFileSync(aside, "utf8") === view.text; // mtimeNs: the exact field (mtimeMs of a BigIntStats is whole milliseconds)
    } catch {
      same = false;
    }
    if (!same) {
      try { linkSync(aside, this.#lockPath); } catch { /* a newer lock is in place; the displaced holder notices before it writes */ }
    }
    try { unlinkSync(aside); } catch { /* best effort */ }
    return same;
  }

  #busy(view: LockView, why: string): EngineError {
    const holder = view.holder === undefined ? (view.text === undefined || view.text === "" ? "" : " (unreadable lock content)")
      : ` (pid ${String(view.holder.pid)} on ${String(view.holder.hostname)}${typeof view.holder.createdAt === "number" ? ` since ${new Date(view.holder.createdAt).toISOString()}` : ""})`;
    return new EngineError("STORE_BUSY", `history ${this.path} ${why}: writer lock ${this.#lockPath}${holder}`, {
      lockPath: this.#lockPath, ...(view.holder === undefined ? {} : { holder: view.holder }), stale: view.stale,
    });
  }

  #acquireLock(): number {
    const deadline = Date.now() + this.#lockTimeoutMs;
    let reclaims = 0, delay = 1, transient = 0;
    for (let attempt = 0; ; attempt += 1) {
      let fd: number;
      try {
        fd = openSync(this.#lockPath, "wx", 0o600);
      } catch (error) {
        // Windows: a lock another process just released can still be delete-pending, and a scanner can hold it open;
        // creating it then fails with EPERM/EACCES/EBUSY instead of EEXIST. Retried briefly (platform.ts), then reported.
        if (isWindowsTransientError(error) && transient < 200) { transient += 1; sleep(Math.min(1 + transient, 20)); continue; }
        if (errnoCode(error) !== "EEXIST") throw unavailable(`cannot create writer lock ${this.#lockPath}`, error);
        const view = this.#inspectLock();
        if (view.vanished && attempt < 100) continue; // released meanwhile
        if (view.stale && reclaims < 3) {
          reclaims += 1;
          if (this.#reclaimLock(view)) continue;
        }
        if (Date.now() < deadline) {
          sleep(Math.min(delay, 50, Math.max(1, deadline - Date.now())));
          delay *= 2;
          continue;
        }
        throw this.#busy(view, this.#lockTimeoutMs > 0 ? `still has an active writer after ${this.#lockTimeoutMs} ms` : "already has an active writer");
      }
      try {
        writeFully(fd, Buffer.from(JSON.stringify({ pid: process.pid, hostname: hostname(), createdAt: this.#now() })));
      } catch (error) {
        closeSync(fd);
        try { unlinkSync(this.#lockPath); } catch { /* best effort */ }
        throw unavailable(`cannot write writer lock ${this.#lockPath}`, error);
      }
      return fd;
    }
  }

  /** The lock path must still be this instance's own lock file (a reclaimer may have displaced it): checked before every append. */
  #assertLockOwned(): void {
    const fd = this.#lockFd;
    if (fd === undefined) return;
    let mine: BigIntStats | undefined, current: BigIntStats | undefined;
    try {
      mine = fstatSync(fd, BIG);
      current = statSync(this.#lockPath, BIG);
    } catch {
      current = undefined;
    }
    if (!sameFile(mine, current)) {
      throw new EngineError("STORE_BUSY", `history ${this.path}: writer lock ${this.#lockPath} was taken over by another process; nothing was written`, { lockPath: this.#lockPath });
    }
  }

  /** Deletes the lock file only while it is still this instance's own. */
  #releaseLock(fd: number): void {
    let mine: BigIntStats | undefined;
    try { mine = fstatSync(fd, BIG); } catch { mine = undefined; }
    try { closeSync(fd); } catch { /* already closed */ }
    for (let attempt = 0; attempt < 5; attempt += 1) {
      let current: BigIntStats;
      try {
        current = statSync(this.#lockPath, BIG);
      } catch (error) {
        // Missing: a reclaimer may be linking it back this very moment; look again briefly.
        if (errnoCode(error) === "ENOENT" && attempt < 4) { sleep(1); continue; }
        return;
      }
      if (sameFile(mine, current)) { try { unlinkSync(this.#lockPath); } catch { /* already gone */ } }
      return;
    }
  }

  /**
   * The witness session's locked sections (docs/WITNESS.md §2: head statements are signed under the writer lock, against
   * the state read under it). Waits while another writer, or this instance, holds the lock (up to `lockTimeoutMs`, at
   * least 5 s): the sections are short (no network), and a busy lock is not a witness failure.
   */
  async #witnessLocked<T>(critical: (state: ReplayState | undefined) => T | Promise<T>): Promise<T> {
    const deadline = Date.now() + Math.max(this.#lockTimeoutMs, 5000);
    for (let delay = 2; ; delay = Math.min(delay * 2, 50)) {
      try {
        return await this.withExclusiveWriter(() => {
          this.#assertOpen();
          this.#sync();
          if (this.#error !== undefined) throw this.#error;
          return critical(this.#state);
        });
      } catch (error) {
        if (!(error instanceof EngineError && error.code === "STORE_BUSY") || Date.now() > deadline) throw error;
      }
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }

  /**
   * Appends an OUTSTANDING prepared rotation record (docs/reference/witness-operations.md §7.1) under the writer lock: re-judged against the
   * file read under the lock, appended through the normal validated append at exactly its `previousHead`, past the
   * session's ROTATION_PENDING guard, and WITHOUT a new owner attestation (the pin carries the previous one): the
   * recovery signs nothing. `undefined` when the record is not OUTSTANDING there (or this store only inspects).
   */
  async #completePending(record: PendingRotationRecord): Promise<HistoryHead | undefined> {
    if (this.#inspect) return undefined;
    return this.#witnessLocked((state) => {
      if (state === undefined || judgePendingRotation(state, record).status !== "OUTSTANDING") return undefined;
      this.#noAttestation = true;
      try {
        return this.#witness.allowingPending(() => this.#appendAt(record.event, record.previousHead));
      } finally {
        this.#noAttestation = false;
      }
    });
  }

  withExclusiveWriter<T>(callback: (writer: EventStoreWriter) => T): T {
    this.#assertOpen();
    if (this.#writing) throw new EngineError("STORE_BUSY", "this store instance already holds its writer lock", { lockPath: this.#lockPath });
    const fd = this.#acquireLock();
    this.#writing = true;
    this.#lockFd = fd;
    let active = true;
    let operating = false;
    const guard = (): void => {
      if (!active) throw new EngineError("WRITER_EXPIRED", "writer capability expired with its callback");
      if (operating) throw new EngineError("STORE_BUSY", "writer operation is not reentrant", { lockPath: this.#lockPath });
    };
    const writer: EventStoreWriter = Object.freeze({
      readAll: () => { guard(); return this.readAll(); },
      appendAtExpectedHead: (event: CanonicalEvent, expected: HistoryHead) => {
        guard();
        operating = true;
        try { return this.#appendAt(event, expected); } finally { operating = false; }
      },
    });
    const release = (): void => {
      active = false;
      this.#writing = false;
      this.#lockFd = undefined;
      this.#releaseLock(fd);
    };
    let result: T;
    try {
      result = callback(writer);
    } catch (error) {
      release();
      throw error;
    }
    // An async callback keeps the lock until it settles (owner control writes sign under the lock).
    if (isThenable(result)) return Promise.resolve(result).finally(release) as unknown as T;
    release();
    return result;
  }

  // ---- verification

  /**
   * Re-reads the whole file and re-checks every record hash, chain link and
   * prefix hash, then judges the pin, its attestation, the recorded anchors and
   * the anchor logs (the local log `<path>.anchors` when present, plus
   * `options.anchorLogs`). When the cached replay matches the bytes (same size,
   * last line and record hashes) it stands in for the replay; otherwise
   * (stale, failed or out-of-date cache) the file is replayed. A file that is
   * not a valid history throws INVALID_HISTORY; everything else is reported,
   * with `ok` false and a reason in `failures` for each problem.
   */
  verify(options: VerifyOptions = {}): VerificationReport {
    return this.#verify(options, true).report;
  }

  async verifyWithWitnesses(options: RemoteVerifyOptions = {}): Promise<VerificationReport> {
    if (options === null || typeof options !== "object") throw new EngineError("INVALID_INPUT", "verify options must be a record");
    if (options.remote === false || !this.#witness.active) return this.verify(options);
    const { report, state } = this.#verify(options, false);
    if (state === undefined || report.format === undefined || !isTrellis(report.format)) return this.verify(options);
    const remote = await this.#witness.remoteFindings(state, { allowUnreachable: options.allowUnreachableWitness === true });
    const failures = [...report.failures, ...remote.failures];
    // "No anchor log holds a head" is about the local anchor log; a remote witness that answered OK says otherwise.
    const notes = [...report.notes.filter((note) => !(remote.status === "OK" && note.startsWith("ANCHOR_LOG_NONE:"))), ...remote.notes];
    // Without enough answers, the recorded evidence (side file, this process) still counts; it can only add failures.
    if (remote.status === "UNREACHABLE") failures.push(...this.#witness.cachedFindings(state).failures);
    return Object.freeze({
      ...report, ok: failures.length === 0, failures: Object.freeze(failures), notes: Object.freeze(notes),
      remoteWitnessStatus: remote.status, remoteWitnesses: remote.witnesses,
    });
  }

  #verify(options: VerifyOptions, cached: boolean): { report: VerificationReport; state: MutableReplayState | undefined } {
    this.#assertOpen();
    const allowUnpinned = options.allowUnpinned ?? this.#allowUnpinned;
    const logs = [localAnchorLog(anchorsPathFor(this.path)), ...(options.anchorLogs ?? [])];
    // A resumed state never stands in for verification: `verify()` is FULL_REPLAY (SPEC §7.5).
    const cache: CachedReplay | undefined = this.#stale || this.#error !== undefined || this.#resumed ? undefined
      : { format: this.#format, state: this.#state, recordHashes: this.#recordHashes, size: this.#size, lastLine: this.#lastLine, digest: this.#digest?.copy().digest("hex") };
    const load = rereadable(this.path, (bytes) =>
      (cache === undefined ? undefined : cachedIfUnchanged(bytes, cache) ?? recheckAgainstCache(bytes, cache)) ?? loadBytes(bytes, this.#hooks));
    const { loaded, pin, status } = snapshot(this.#headPath, load, this.#retryAttempts, this.#retryDelayMs);
    if (loaded.error !== undefined) throw loaded.error;
    const state = loaded.state;
    const trellis = loaded.format !== undefined && isTrellis(loaded.format);
    const failures: string[] = [], notes: string[] = [];
    // Pin.
    switch (status) {
      case "ROLLBACK":
        failures.push(`PIN_ROLLBACK: the history does not contain its pinned head (pinned position ${pin!.position}, file ${state === undefined ? "empty" : `head position ${state.head.position}`}): events were removed or replaced`);
        break;
      case "MALFORMED":
        failures.push(`PIN_MALFORMED: pinned head file is malformed: ${this.#headPath}`);
        break;
      case "MISSING":
        (allowUnpinned ? notes : failures).push(`PIN_MISSING: the history has events after genesis but no pinned head (${this.#headPath}); a deleted pin hides truncation${allowUnpinned ? " (accepted: allowUnpinned)" : ""}`);
        break;
      case "UNPINNED":
        notes.push(state === undefined ? "HISTORY_EMPTY: the history has no events"
          : trellis ? "PIN_UNPINNED: genesis-only history without a pinned head"
            : "PIN_UNPINNED: legacy history without a pinned head: legacy files predate pinning, so truncation of this file cannot be detected until this engine writes to it");
        break;
      default:
        break;
    }
    // Pin attestation (format 1): the owner's word for the pinned history.
    let pinnedAttestation: VerificationReport["pinnedAttestation"];
    let attestedHead: HistoryHead | undefined;
    if (trellis && state !== undefined && pin !== undefined) {
      const attestation = pin.attestation;
      const genesisOnly = state.events.length <= 1;
      if (attestation === undefined) {
        pinnedAttestation = "MISSING";
        (allowUnpinned || genesisOnly ? notes : failures).push(`PIN_ATTESTATION_MISSING: the pinned head carries no owner attestation, so anyone who can write the pin file could have written it${allowUnpinned ? " (accepted: allowUnpinned)" : ""}`);
      } else if ((status === "ROLLBACK" || attestationCovers(attestation, pin, state)) &&
          verifyHeadAttestationAt(attestation, state)) {
        pinnedAttestation = "VERIFIED";
        attestedHead = Object.freeze({ hash: attestation.head.hash, position: attestation.head.position, canonicalTime: attestation.head.canonicalTime });
        if (status !== "ROLLBACK" && attestedRootMismatch(attestation, state, attestedHead.position)) {
          failures.push(`ATTESTED_STATE_ROOT_MISMATCH: the pinned head carries a valid owner attestation of position ${attestedHead.position} whose stateRoot or projectionHead is not this history's at that position: the owner key signed a state this history does not have (PIN)`);
        }
        if (status !== "ROLLBACK" && attestedHead.position < pin.position) {
          notes.push(`PIN_ATTESTED_EARLIER: the owner attested the history up to position ${attestedHead.position}; positions ${attestedHead.position + 1}..${pin.position} were pinned by writers without the owner key`);
        }
      } else {
        pinnedAttestation = "INVALID";
        failures.push("PIN_ATTESTATION_INVALID: the pinned head's attestation is not an owner signature over a head of this history");
      }
    }
    if (pin?.rollbackAcceptedAt !== undefined) {
      notes.push(`ROLLBACK_ACCEPTED: a rollback was accepted at ${pin.rollbackAcceptedAt}${previousPinPosition(pin.previousPin) === undefined ? " (there was no readable previous pin)" : ` (the previous pin was at position ${previousPinPosition(pin.previousPin)})`}`);
    }
    // Anchors recorded in the history.
    const anchors = Object.freeze((state?.anchors ?? []).map((anchor) => Object.freeze({
      head: anchor.head, anchor: anchor.anchor, eventId: anchor.eventId,
      status: state!.eventHistoryHashes[anchor.head.position] === anchor.head.hash ? "PREFIX_OK" as const : "MISMATCH" as const,
    })));
    for (const anchor of anchors) if (anchor.status !== "PREFIX_OK") failures.push(`ANCHOR_MISMATCH: anchor ${anchor.eventId} names a head at position ${anchor.head.position} that is not a prefix of this history`);
    // Anchor logs.
    const anchorLog = checkAnchorLogs(logs, state, loaded.format);
    failures.push(...anchorLog.failures);
    notes.push(...anchorLog.notes);
    // A-111.3 (report-level): the pin and anchor-log heads whose signer is AGENT, NONE or LAPSED at its canonicalTime.
    if (state !== undefined && isFormat2(state.format)) {
      const signed: Array<{ what: string; head: HistoryHead; keyId: string }> = [
        ...(attestedHead !== undefined && pin?.attestation !== undefined ? [{ what: "the pin's attestation", head: attestedHead, keyId: pin.attestation.keyId }] : []),
        ...anchorLog.heads.filter((entry) => entry.status === "PREFIX_OK").map((entry) => ({ what: `the ${entry.log} anchor log head`, head: entry.head, keyId: entry.keyId })),
      ];
      for (const entry of signed) {
        const klass = unqualifiedHeadSigner(state, entry.head.position, entry.head.canonicalTime, entry.keyId);
        if (klass !== undefined) notes.push(`HEAD_SIGNER_UNQUALIFIED: ${entry.what} at position ${entry.head.position} is signed by ${entry.keyId}, ${klass} at ${entry.head.canonicalTime} under the owner approval policy in force there; it is not a resume root (A-101.0, A-111.3)`);
      }
    }
    if (anchorLog.status === "ROLLBACK" && pin?.rollbackAcceptedAt !== undefined) {
      notes.push("ANCHOR_LOG_AFTER_ACCEPTED_ROLLBACK: an anchor log still holds heads the accepted rollback removed; it keeps failing verification until its log is archived deliberately");
    }
    // Remote witnesses: this synchronous check reports what is already known (this process, the side file) and says it did not ask.
    const remote = cached && trellis && this.#witness.active ? this.#witness.cachedFindings(state) : undefined;
    if (remote !== undefined) { failures.push(...remote.failures); notes.push(...remote.notes); }
    // Format 2 (SPEC §7.5): the snapshot's standing at this handle's open (informational), the root and projection head at the head.
    // A-32.3, A-36.2, A-40.2: informational findings (credential reuse, CONNECTOR attribution, prefix provenance).
    if (state !== undefined) notes.push(...verificationNotes(state));
    if (this.#snapshotStatus === "STALE") notes.push("SNAPSHOT_STALE: the snapshot could not be used at open (absent signed root, torn files or a root mismatch); the history was replayed in full and the snapshot rebuilt");
    if (this.#resumeRefusal !== undefined) notes.push(`FULL_REPLAY: ${this.#resumeRefusal}`);
    const stateRoot = state !== undefined && isFormat2(state.format) ? rootAt(state, state.head.position) : undefined;
    const report: VerificationReport = Object.freeze({
      ok: failures.length === 0, failures: Object.freeze(failures), notes: Object.freeze(notes),
      path: this.path, format: loaded.format, head: state?.head, eventCount: state?.events.length ?? 0, chain: "OK" as const,
      ...(stateRoot === undefined ? {} : { stateRoot, projectionHead: projectionHeadAt(state!, state!.head.position) ?? null }),
      ...(this.#snapshotStatus === undefined ? {} : { snapshot: this.#snapshotStatus }),
      ...(pin === undefined ? {} : { pinnedHead: pin }), pinnedHeadStatus: status,
      ...(pinnedAttestation === undefined ? {} : { pinnedAttestation }), ...(attestedHead === undefined ? {} : { attestedHead }),
      ...(pin?.rollbackAcceptedAt === undefined ? {} : { rollbackAcceptedAt: pin.rollbackAcceptedAt }), ...(pin?.previousPin === undefined ? {} : { previousPin: pin.previousPin }),
      anchors, anchorLogStatus: anchorLog.status, anchorLogHeads: anchorLog.heads,
      controlSignatures: trellis ? "VERIFIED" as const : "NOT_APPLICABLE" as const,
      ...(remote === undefined ? {} : { remoteWitnessStatus: remote.status }),
    });
    return { report, state };
  }
}

/** The position a recorded previous pin names, when it is a record with a whole-number position. */
const previousPinPosition = (previous: unknown): number | undefined => {
  if (previous === null || typeof previous !== "object" || Array.isArray(previous)) return undefined;
  const position = (previous as { position?: unknown }).position;
  return typeof position === "number" && Number.isSafeInteger(position) && position >= 0 ? position : undefined;
};

/** Opens (or prepares, when absent) the history at `path`; reads and replays once; checks the pinned head. */
export function openHistoryStore(path: string, options: StoreOptions = {}): HistoryStore {
  return new FileHistoryStore(path, options);
}

/**
 * Creates the file exclusively (mode 0600) and writes the genesis batch;
 * `HISTORY_EXISTS` when the file is there. For a format-1 genesis, an owner key
 * file already at `<path>.owner-key.json` is refused (`KEY_EXISTS`) unless
 * `reuseExistingKey`: a leftover or planted key is never adopted silently.
 */
export function createHistoryStore(path: string, genesis: readonly CanonicalEvent[], options: StoreOptions = {}, format2Only = false): HistoryStore {
  const store = new FileHistoryStore(path, options);
  // P1-b: the public create marks its store before the genesis write, so the fence holds for that first write too.
  if (format2Only) FORMAT2_ONLY.add(store);
  const keyPath = ownerKeyPathFor(store.path);
  const genesisFormat = Array.isArray(genesis) ? detectFormat(genesis) : undefined;
  if (options.reuseExistingKey !== true && genesisFormat !== undefined && isTrellis(genesisFormat) && existsSync(keyPath)) {
    throw new EngineError("KEY_EXISTS", `an owner key file already exists for the new history: ${keyPath}; it is not adopted silently (remove it, or pass reuseExistingKey to use it)`, { keyPath });
  }
  let fd: number;
  try {
    fd = openSync(store.path, "wx", 0o600);
  } catch (error) {
    if (errnoCode(error) === "EEXIST") throw new EngineError("HISTORY_EXISTS", `history already exists: ${store.path}`);
    throw new EngineError("READ_UNAVAILABLE", `cannot create history ${store.path} (nothing was written): ${messageOf(error)}`, { mayHaveCommitted: false, cause: errnoCode(error), path: store.path });
  }
  closeSync(fd);
  try {
    store.appendAll(genesis);
  } catch (error) {
    try { if (statSync(store.path).size === 0) unlinkSync(store.path); } catch { /* leave it */ }
    throw error;
  }
  return store;
}
