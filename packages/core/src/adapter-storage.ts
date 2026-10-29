/**
 * The adapter's storage surface on format 2: the host-selected history store, the replayed state, and the transfer of
 * a history between hosts. Everything here sits on the existing engine: the store is `openHistoryStore` (one JSONL
 * file, its pin, snapshot and writer lock), the state is `replayHistory`, and a transfer is the full export view
 * (SPEC §15, positions 0 to head) cut into a manifest and event-aligned segments. The receiving side stages those
 * pieces durably and hands out the history only after `verifyExportView` accepts the reassembled view.
 *
 * Here a "checkpoint" is a destination's verified copy of another host's history (the cooperative remote's term). It
 * is not the `STATE_CHECKPOINT` event; a transferred history carries its `STATE_CHECKPOINT` events, and the view's
 * verification checks them. Never expose these handles as agent tools.
 */
import { closeSync, fsyncSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync, writeSync, type Stats } from "node:fs";
import { join } from "node:path";
import { types } from "node:util";
import { canonicalEncode, captureValue, isContentHash } from "./canonical.ts";
import { EngineError } from "./errors.ts";
import { TRELLIS2_FORMAT } from "./events.ts";
import { EXPORT_VERSION, exportViewState, verifyExportView, type ExportEndAuthentication, type ExportView } from "./export-view.ts";
import { sha256Hex } from "./hash.ts";
import { captureData, IronTrellisError, type IronTrellisErrorCode } from "./input.ts";
import { replayHistory } from "./observation.ts";
import { translate } from "./owner.ts";
import { replaceFileSync, syncDirectorySync } from "./platform.ts";
import { replay } from "./replay.ts";
import { rootAt } from "./state-records.ts";
import { openHistoryStore, type HistoryStore, type TrustMode } from "./store.ts";
import { parseStrictJson } from "./strict-json.ts";
import type { Signer } from "./signer.ts";
import type { WitnessPolicy } from "./witness-client.ts";
import type { AuthorizationDomain, CanonicalEvent, ContentHash, HistoryHead, ReplayState, U53 } from "./types.ts";

// ---------------------------------------------------------------- the configured store

/** The one store profile: a format-2 history file. */
export const HISTORY_PROFILE = TRELLIS2_FORMAT;

/** The host's selection of a history. Other keys of the host's configuration object are ignored. */
export type HistoryLocation = Readonly<{
  historyFile: string;
  historyProfile?: typeof HISTORY_PROFILE;
  /** A-19.4: `recordHash(0)` of the expected history (`HISTORY_IDENTITY_MISMATCH` otherwise). */
  historyId?: ContentHash;
  /** When given, the genesis domain must be this one (`PROFILE_MISMATCH`). */
  domain?: AuthorizationDomain;
  /** SPEC §7.5; default `CHECKPOINT_RESUME`, as in the local owner API. */
  trust?: TrustMode;
  acceptRollback?: boolean;
  allowUnpinned?: boolean;
  signer?: Signer;
  witness?: WitnessPolicy | false;
  /** Wait this long for another writer's lock before `STORE_BUSY` (default 0). */
  lockTimeoutMs?: number;
}>;
/** The existing history store, opened from a `HistoryLocation`. */
export type ConfiguredEventStore = HistoryStore;

const fail = (code: IronTrellisErrorCode, message?: string, detail?: unknown): never => { throw new IronTrellisError(code, false, message, detail); };
/**
 * The transfer refusals. Like the store's own refusals (`STORE_BUSY`, `STORE_CONFLICT`) they are `EngineError` codes;
 * the selection and input refusals above keep the owner API's `IronTrellisError` codes. Callers match on `code`.
 */
export type TransferErrorCode = "TRANSFER_INVALID" | "TRANSFER_CONFLICT" | "TRANSFER_CHUNK_INVALID" | "TRANSFER_INCOMPLETE" | "TRANSFER_STORAGE_LIMIT" | "TRANSFER_STORAGE_INVALID";
const refuse = (code: TransferErrorCode, message: string, detail?: unknown): never => { throw new EngineError(code, message, detail); };
const isRecord = (v: unknown): v is Readonly<Record<string, unknown>> => v !== null && typeof v === "object" && !Array.isArray(v) && !types.isProxy(v);
/** An own data property of a host record, or `undefined`; an accessor is refused unread. */
const own = (record: object, key: string): unknown => {
  const d = Object.getOwnPropertyDescriptor(record, key);
  if (d === undefined) return undefined;
  if (!Object.hasOwn(d, "value")) fail("INVALID_INPUT", `${key} must be a data property`);
  return d.value;
};

/**
 * Opens the history the trusted host selected, the way the local owner API opens it (same options, same
 * read-only rule for legacy and format-1 files). Refuses a segmented selection (`historyBinding`, another
 * `historyProfile`) and a domain that is not the genesis domain with `PROFILE_MISMATCH`, and a missing file with
 * `READ_UNAVAILABLE`.
 */
export function openConfiguredEventStore(location: HistoryLocation): ConfiguredEventStore {
  if (!isRecord(location)) fail("INVALID_INPUT", "the history location must be a record");
  if (own(location, "historyBinding") !== undefined) fail("PROFILE_MISMATCH", "historyBinding selects a segmented history; IronTrellis keeps one file per history");
  const profile = own(location, "historyProfile");
  if (profile !== undefined && profile !== HISTORY_PROFILE) fail("PROFILE_MISMATCH", `historyProfile must be ${HISTORY_PROFILE}`);
  const historyFile = own(location, "historyFile"), trust = own(location, "trust"), historyId = own(location, "historyId");
  const acceptRollback = own(location, "acceptRollback"), allowUnpinned = own(location, "allowUnpinned"), lockTimeoutMs = own(location, "lockTimeoutMs");
  const signer = own(location, "signer"), witness = own(location, "witness"), domain = own(location, "domain");
  if (typeof historyFile !== "string" || historyFile.length === 0 || historyFile.includes("\0")) fail("INVALID_INPUT", "historyFile must be a non-empty path");
  if (trust !== undefined && trust !== "FULL_REPLAY" && trust !== "CHECKPOINT_RESUME") fail("INVALID_INPUT", "trust must be FULL_REPLAY or CHECKPOINT_RESUME");
  if (historyId !== undefined && !isContentHash(historyId)) fail("INVALID_INPUT", "historyId must be a content hash");
  if (![acceptRollback, allowUnpinned].every((v) => v === undefined || typeof v === "boolean")) fail("INVALID_INPUT", "acceptRollback and allowUnpinned must be booleans");
  if (lockTimeoutMs !== undefined && !(Number.isSafeInteger(lockTimeoutMs) && (lockTimeoutMs as number) >= 0)) fail("INVALID_INPUT", "lockTimeoutMs must be a non-negative integer");
  let expectedDomain: string | undefined;
  if (domain !== undefined) {
    try { expectedDomain = canonicalEncode(domain); } catch { fail("INVALID_INPUT", "domain must be a canonical record"); }
  }
  let store: HistoryStore;
  try {
    store = openHistoryStore(historyFile as string, {
      acceptRollback: acceptRollback === true, allowUnpinned: allowUnpinned === true,
      ...(signer === undefined ? {} : { signer: signer as Signer }), ...(witness === undefined ? {} : { witness: witness as WitnessPolicy | false }),
      trust: (trust as TrustMode | undefined) ?? "CHECKPOINT_RESUME", ...(historyId === undefined ? {} : { historyId: historyId as ContentHash }),
      ...(lockTimeoutMs === undefined ? {} : { lockTimeoutMs: lockTimeoutMs as number }),
    });
  } catch (error) {
    translate(error, "READ_UNAVAILABLE");
  }
  try {
    if (store.format === undefined) fail("READ_UNAVAILABLE", `no history at ${store.path}`);
    if (profile !== undefined && store.format !== HISTORY_PROFILE) fail("PROFILE_MISMATCH", `the history is ${store.format}, not ${HISTORY_PROFILE}`);
    if (expectedDomain !== undefined && canonicalEncode(store.state().genesis.domain) !== expectedDomain) fail("PROFILE_MISMATCH", "the history's genesis domain is not the configured domain");
  } catch (error) {
    store.close();
    if (error instanceof IronTrellisError) throw error;
    translate(error, "READ_UNAVAILABLE");
  }
  return store;
}

// ---------------------------------------------------------------- state

/** Verified histories made here, with their (lazily replayed) state; membership is the brand. */
const verifiedStates = new WeakMap<object, () => ReplayState>();

/** The replayed state of captured events (`INVALID_HISTORY` when they do not replay), or of a `VerifiedHistory`. */
export function stateOf(source: readonly CanonicalEvent[] | VerifiedHistory): ReplayState {
  const known = typeof source === "object" && source !== null ? verifiedStates.get(source) : undefined;
  return known !== undefined ? known() : replayHistory(source);
}

// ---------------------------------------------------------------- transfer: sender

export const TRANSFER_VERSION = "irontrellis-history-transfer/1";
/** The receiver's resource limits, and the segment and part sizes of a transfer. */
export const TRANSFER_STORAGE_LIMITS = Object.freeze({
  bytes: 512 * 1024 * 1024, chunks: 16_384, manifests: 1_024, manifestBytes: 1024 * 1024,
  segments: 4_096, segmentEvents: 64, segmentBytes: 2 * 1024 * 1024, partChars: 4_096,
});
let L: typeof TRANSFER_STORAGE_LIMITS = TRANSFER_STORAGE_LIMITS;
/** TEST ONLY: lower the limits in force (no argument restores `TRANSFER_STORAGE_LIMITS`); returns the limits now in force. */
export function setTransferLimitsForTests(override?: Partial<typeof TRANSFER_STORAGE_LIMITS>): typeof TRANSFER_STORAGE_LIMITS {
  L = Object.freeze({ ...TRANSFER_STORAGE_LIMITS, ...override });
  return L;
}

/** The export view without its rows (`events`) and the lists the rows repeat (`checkpointIds`, `checkpoints`). */
export type ExportViewHeader = Omit<ExportView, "events" | "checkpointIds" | "checkpoints">;
export type TransferSegment = Readonly<{ digest: ContentHash; start: U53; count: U53; bytes: U53 }>;
export type TransferManifest = Readonly<{ version: typeof TRANSFER_VERSION; view: ExportViewHeader; segments: readonly TransferSegment[] }>;
export type HistoryTransfer = Readonly<{ transferId: ContentHash; manifest: TransferManifest; chunks: readonly (readonly string[])[] }>;

export type VerifiedHistory = Readonly<{
  transferId: ContentHash;
  historyId: ContentHash;
  genesisEventHash: ContentHash;
  domain: AuthorizationDomain;
  head: HistoryHead;
  stateRoot: ContentHash;
  projectionHead: ContentHash | null;
  recordCount: U53;
  eventCount: U53;
  events: readonly CanonicalEvent[];
  /** The full view as verified. */
  view: ExportView;
  /** How the head is vouched for beyond the chain (A-27.1): an owner head attestation, a `STATE_CHECKPOINT` right after it, or nothing. */
  headAuthentication: ExportEndAuthentication;
}>;

const utf8 = (text: string): Buffer => Buffer.from(text, "utf8");
const HEADER_REQUIRED = ["version", "domain", "genesisEventHash", "historyId", "from", "to", "eventCount", "fromAuthenticated"];
const HEADER_OPTIONAL = ["keyEvents", "attestations"];

/**
 * The full export view of a format-2 history (positions 0 to head, with its key events and the held head
 * attestation), as a manifest and segments of at most 64 rows, one canonical JSON line each. The source is a history
 * store (its pin attestation is the held head attestation, as in `LocalOwner.exportView`) or a `VerifiedHistory`
 * received earlier (re-sent unchanged). A legacy or format-1 source is `PROFILE_MISMATCH`.
 */
export function createHistoryTransfer(source: HistoryStore | VerifiedHistory): HistoryTransfer {
  let view: ExportView;
  if (typeof source === "object" && source !== null && verifiedStates.has(source)) view = (source as VerifiedHistory).view;
  else {
    const store = source as HistoryStore;
    if (!isRecord(store) || typeof store.state !== "function" || typeof store.pinnedHead !== "function") fail("INVALID_INPUT", "the transfer source must be a history store or a verified history");
    const state = store.state();
    if (state.format !== TRELLIS2_FORMAT) fail("PROFILE_MISMATCH", `only ${TRELLIS2_FORMAT} histories transfer; this one is ${state.format}`);
    const attestation = store.pinnedHead()?.attestation;
    view = exportViewState(state, { fromPosition: 0, toPosition: state.head.position, include: { keyEvents: true, attestations: true } }, { headAttestations: attestation === undefined ? [] : [attestation] });
  }
  const { events: rows, checkpointIds: _ids, checkpoints: _checkpoints, ...header } = view;
  const chunks: (readonly string[])[] = [], segments: TransferSegment[] = [];
  let lines: Buffer[] = [], size = 0, start = 0;
  const close = (): void => {
    const bytes = Buffer.concat(lines), text = bytes.toString("base64"), parts: string[] = [];
    for (let at = 0; at < text.length; at += L.partChars) parts.push(text.slice(at, at + L.partChars));
    chunks.push(Object.freeze(parts));
    segments.push(Object.freeze({ digest: sha256Hex(bytes), start, count: lines.length, bytes: bytes.length }));
    start += lines.length;
    lines = [];
    size = 0;
  };
  for (const row of rows) {
    const line = utf8(`${canonicalEncode(row)}\n`);
    if (line.length > L.segmentBytes) refuse("TRANSFER_INVALID", `the event at ${row.position} is larger than a segment`);
    if (lines.length === L.segmentEvents || size + line.length > L.segmentBytes) close();
    lines.push(line);
    size += line.length;
  }
  close();
  const manifest = validManifest({ version: TRANSFER_VERSION, view: header, segments });
  return Object.freeze({ transferId: manifestId(manifest), manifest, chunks: Object.freeze(chunks) });
}

const manifestBytes = (manifest: TransferManifest): Buffer => utf8(canonicalEncode(manifest));
const manifestId = (manifest: TransferManifest): ContentHash => sha256Hex(manifestBytes(manifest));
const isPosition = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const exactKeys = (v: Readonly<Record<string, unknown>>, required: readonly string[], optional: readonly string[] = []): boolean =>
  required.every((k) => Object.hasOwn(v, k)) && Object.keys(v).every((k) => required.includes(k) || optional.includes(k));

/** A captured, frozen copy of a manifest whose shape holds (`TRANSFER_INVALID` otherwise). The view itself is checked when the rows are in. */
function validManifest(input: unknown): TransferManifest {
  let m: unknown;
  try { m = captureData(input, L.manifestBytes, Number.MAX_SAFE_INTEGER, 40); } catch { return refuse("TRANSFER_INVALID", "the manifest is not a canonical record within the manifest limit"); }
  const bad = (reason: string): never => refuse("TRANSFER_INVALID", `transfer manifest: ${reason}`);
  if (!isRecord(m) || !exactKeys(m, ["version", "view", "segments"]) || m.version !== TRANSFER_VERSION) bad(`not a ${TRANSFER_VERSION} record`);
  const { view, segments } = m as Record<string, unknown>;
  if (!isRecord(view) || !exactKeys(view, HEADER_REQUIRED, HEADER_OPTIONAL) || view.version !== EXPORT_VERSION) bad(`view is not an ${EXPORT_VERSION} header`);
  const h = view as Record<string, unknown>, v = view as Record<string, Record<string, unknown>>;
  const count = h.eventCount;
  if (!isPosition(count) || count < 1 || !isContentHash(h.historyId) || !isContentHash(h.genesisEventHash)) bad("eventCount, historyId or genesisEventHash is malformed");
  if (!isRecord(v.from) || v.from.position !== 0 || !isRecord(v.to) || v.to.position !== (count as number) - 1 || !isContentHash(v.to.stateRoot)) bad("the view must run from 0 to the head of a format-2 history");
  if (!Array.isArray(segments) || segments.length < 1 || segments.length > L.segments) bad(`segments must be a list of 1 to ${L.segments}`);
  let next = 0;
  for (const s of segments as unknown[]) {
    if (!isRecord(s) || !exactKeys(s, ["digest", "start", "count", "bytes"]) || !isContentHash(s.digest) || s.start !== next) bad("segments must be contiguous {digest, start, count, bytes}");
    const seg = s as TransferSegment;
    if (!isPosition(seg.count) || seg.count < 1 || seg.count > L.segmentEvents || !isPosition(seg.bytes) || seg.bytes < 1 || seg.bytes > L.segmentBytes) bad("a segment's count or size is out of bounds");
    next += seg.count;
  }
  if (next !== count) bad("the segments do not cover eventCount");
  const manifest = m as TransferManifest;
  if (manifestBytes(manifest).length > L.manifestBytes) bad("larger than TRANSFER_STORAGE_LIMITS.manifestBytes");
  return manifest;
}

// ---------------------------------------------------------------- transfer: receiver

export type CheckpointStorage = Readonly<{
  begin(manifest: unknown, transferId: string, committedReference: string | null): Readonly<{ transferId: ContentHash }>;
  chunk(transferId: string, index: number, parts: readonly string[]): Readonly<{ transferId: ContentHash; index: U53 }>;
  abort(transferId: string): Readonly<{ transferId: ContentHash }>;
  /** The active transfer, verified. */
  ready(transferId: string): VerifiedHistory;
  /** Any stored transfer, verified. */
  load(transferId: string): VerifiedHistory;
  inspect(): Readonly<{ active: ContentHash | null; bytes: U53; chunks: U53; manifests: U53 }>;
}>;
export type CheckpointStorageHooks = Readonly<{ point?: (name: string) => void }>;

const STORAGE_DIRECTORY = "irontrellis-transfers";
const ACTIVE = "active.json";
const ENTRY = /^([0-9a-f]{64})\.(chunk|manifest)(\.tmp)?$|^active\.json(\.tmp)?$/;
const ACTIVE_BYTES = 1024;
const errno = (error: unknown): string | undefined => (error as { code?: string } | null)?.code;
const fileName = (hash: ContentHash, kind: "chunk" | "manifest"): string => `${hash.slice(2)}.${kind}`;

/**
 * Durable staging, in `<parent>/irontrellis-transfers/`, for histories received through `createHistoryTransfer`:
 * `begin` stores and activates a manifest, `chunk` stores one checked segment, `abort` clears the active transfer, and
 * `ready` (the active transfer) and `load` (any stored one) re-check every chunk and return the history only once
 * `verifyExportView` accepts the reassembled view. Files are content-addressed and written once (temporary file,
 * fsync, rename, directory fsync); `active.json` is replaced atomically. One caller at a time: the destination
 * serializes these calls under its own lock.
 */
export function openCheckpointStorage(parent: string, hooks: CheckpointStorageHooks = {}): CheckpointStorage {
  if (typeof parent !== "string" || parent.length === 0 || parent.includes("\0")) fail("INVALID_INPUT", "parent must be a directory path");
  if (!isRecord(hooks) || (hooks.point !== undefined && typeof hooks.point !== "function")) fail("INVALID_INPUT", "hooks.point must be a function");
  const point = (name: string): void => { hooks.point?.(name); };
  const root = join(parent, STORAGE_DIRECTORY);
  const kindOf = (path: string): Stats | undefined => { try { return lstatSync(path); } catch (error) { if (errno(error) === "ENOENT") return undefined; return fail("READ_UNAVAILABLE", `cannot read ${path}`, { cause: errno(error) }); } };
  if (!kindOf(parent)?.isDirectory()) fail("READ_UNAVAILABLE", `${parent} is not a directory`);
  if (kindOf(root) === undefined) {
    try { mkdirSync(root, { mode: 0o700 }); syncDirectorySync(parent); } catch (error) { fail("WRITE_UNCONFIRMED", `cannot create ${root}`, { cause: errno(error) }); }
  }
  if (!kindOf(root)?.isDirectory()) refuse("TRANSFER_STORAGE_INVALID", `${root} is not a directory`);

  const read = (name: string, limit: number): Buffer | undefined => {
    const info = kindOf(join(root, name));
    if (info === undefined) return undefined;
    if (!info.isFile() || info.size > limit) refuse("TRANSFER_STORAGE_INVALID", `${name} is not a regular file within its limit`);
    try { return readFileSync(join(root, name)); } catch (error) { return fail("READ_UNAVAILABLE", `cannot read ${name}`, { cause: errno(error) }); }
  };
  const write = (name: string, bytes: Uint8Array): void => {
    const path = join(root, name), temporary = `${path}.tmp`;
    try {
      const fd = openSync(temporary, "w", 0o600);
      try {
        for (let done = 0; done < bytes.length;) done += writeSync(fd, bytes, done, bytes.length - done);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      replaceFileSync(temporary, path);
      syncDirectorySync(root);
    } catch (error) {
      throw new IronTrellisError("WRITE_UNCONFIRMED", true, `cannot write ${name}`, { cause: errno(error) });
    }
  };
  /** Every entry is one this storage writes, within its size limit; with the additions, the totals stay within the limits. */
  const bounded = (addBytes = 0, addChunks = 0, addManifests = 0): { bytes: number; chunks: number; manifests: number } => {
    let names: string[];
    try { names = readdirSync(root); } catch (error) { return fail("READ_UNAVAILABLE", `cannot list ${root}`, { cause: errno(error) }); }
    let bytes = 0, chunks = 0, manifests = 0;
    for (const name of names) {
      const match = ENTRY.exec(name);
      if (match === null) refuse("TRANSFER_STORAGE_INVALID", `unexpected entry ${name} in ${root}`);
      const info = kindOf(join(root, name));
      if (info === undefined) continue;
      const limit = match![2] === "chunk" ? L.segmentBytes : match![2] === "manifest" ? L.manifestBytes : ACTIVE_BYTES;
      if (!info.isFile() || info.size > limit) refuse("TRANSFER_STORAGE_INVALID", `${name} is not a regular file within its limit`);
      bytes += info.size;
      if (match![2] === "chunk" && match![3] === undefined) chunks += 1;
      if (match![2] === "manifest" && match![3] === undefined) manifests += 1;
    }
    if (bytes + addBytes > L.bytes || chunks + addChunks > L.chunks || manifests + addManifests > L.manifests) {
      refuse("TRANSFER_STORAGE_LIMIT", "the transfer storage is full", { bytes, chunks, manifests, limits: L });
    }
    return { bytes, chunks, manifests };
  };
  const active = (): ContentHash | null => {
    const bytes = read(ACTIVE, ACTIVE_BYTES);
    if (bytes === undefined) return null;
    let parsed: unknown;
    try { parsed = parseStrictJson(bytes.toString("utf8")); } catch { parsed = undefined; }
    if (!isRecord(parsed) || !exactKeys(parsed, ["transferId"]) || (parsed.transferId !== null && !isContentHash(parsed.transferId))) refuse("TRANSFER_STORAGE_INVALID", `${ACTIVE} is malformed`);
    return (parsed as { transferId: ContentHash | null }).transferId;
  };
  const setActive = (transferId: ContentHash | null): void => {
    bounded(ACTIVE_BYTES);
    write(ACTIVE, utf8(`${canonicalEncode({ transferId })}\n`));
  };
  const idOf = (transferId: unknown): ContentHash => (isContentHash(transferId) ? transferId : refuse("TRANSFER_INVALID", "transferId must be a content hash"));
  /** The stored manifest named `id`; it must hash to `id`. */
  const manifest = (id: ContentHash): TransferManifest => {
    const bytes = read(fileName(id, "manifest"), L.manifestBytes);
    if (bytes === undefined) refuse("TRANSFER_INVALID", `no transfer ${id} was begun here`);
    if (sha256Hex(bytes!) !== id) refuse("TRANSFER_STORAGE_INVALID", `the stored manifest ${id} does not hash to its name`);
    let parsed: unknown;
    try { parsed = parseStrictJson(bytes!.toString("utf8")); } catch { return refuse("TRANSFER_STORAGE_INVALID", `the stored manifest ${id} is not JSON`); }
    return validManifest(parsed);
  };
  const requireActive = (transferId: unknown): Readonly<{ id: ContentHash; m: TransferManifest }> => {
    const id = idOf(transferId);
    if (active() !== id) refuse("TRANSFER_CONFLICT", `${id} is not the active transfer`);
    return { id, m: manifest(id) };
  };
  /** Stores content-addressed bytes once; an existing file with the right digest is kept. */
  const storeOnce = (name: string, bytes: Buffer, limit: number, kind: "chunk" | "manifest"): void => {
    const existing = read(name, limit);
    if (existing !== undefined && existing.equals(bytes)) return;
    bounded(bytes.length, kind === "chunk" && existing === undefined ? 1 : 0, kind === "manifest" && existing === undefined ? 1 : 0);
    write(name, bytes);
  };
  /** The rows of one stored or received segment: canonical lines, at the segment's positions. */
  const rowsOf = (bytes: Buffer, segment: TransferSegment): Readonly<Record<string, unknown>>[] => {
    let text: string;
    try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch { return refuse("TRANSFER_CHUNK_INVALID", "a segment is not UTF-8"); }
    const lines = text.split("\n");
    if (lines.pop() !== "" || lines.length !== segment.count) refuse("TRANSFER_CHUNK_INVALID", `segment ${segment.start}: expected ${segment.count} lines`);
    return lines.map((line, i) => {
      let row: unknown;
      try { row = parseStrictJson(line); } catch { row = undefined; }
      if (!isRecord(row) || row.position !== segment.start + i) refuse("TRANSFER_CHUNK_INVALID", `segment ${segment.start}: line ${i} is not the row at ${segment.start + i}`);
      return row as Readonly<Record<string, unknown>>;
    });
  };
  const verified = new Map<ContentHash, VerifiedHistory>();
  const load = (transferId: unknown): VerifiedHistory => {
    const id = idOf(transferId);
    bounded();
    const m = manifest(id), segments: Buffer[] = [], missing: number[] = [];
    m.segments.forEach((segment, index) => {
      const bytes = read(fileName(segment.digest, "chunk"), L.segmentBytes);
      if (bytes === undefined) { missing.push(index); return; }
      if (bytes.length !== segment.bytes || sha256Hex(bytes) !== segment.digest) refuse("TRANSFER_CHUNK_INVALID", `the stored segment ${index} does not match its digest`);
      segments.push(bytes);
    });
    if (missing.length > 0) refuse("TRANSFER_INCOMPLETE", `transfer ${id} lacks ${missing.length} segment(s)`, { missing });
    // Every byte was just re-checked against the manifest, which hashes to `id`: an earlier verification of `id` stands.
    const cached = verified.get(id);
    if (cached !== undefined) return cached;
    // Rows are captured one by one (frozen canonical copies); the view's lists may exceed a single capture's member limit.
    const rows = m.segments.flatMap((segment, index) => rowsOf(segments[index]!, segment).map((row) => captureValue(row) as ExportView["events"][number]));
    const checkpointData = rows.filter((row) => isRecord(row.event) && row.event.type === "STATE_CHECKPOINT").map((row) => row.event.data);
    const view = Object.freeze({
      ...m.view, events: Object.freeze(rows), checkpointIds: Object.freeze(checkpointData.map((data) => data.checkpointId as string)), checkpoints: Object.freeze(checkpointData),
    }) as ExportView;
    const verification = verifyExportView(view);
    if (!verification.ok) refuse("TRANSFER_INVALID", `transfer ${id}: the export view does not verify`, { failures: verification.failures, ...(verification.code === undefined ? {} : { code: verification.code }) });
    const events = Object.freeze(rows.map((row) => row.event));
    let state: ReplayState | undefined;
    const history: VerifiedHistory = Object.freeze({
      transferId: id, historyId: view.historyId, genesisEventHash: view.genesisEventHash, domain: view.domain as AuthorizationDomain,
      head: view.to.head, stateRoot: view.to.stateRoot!, projectionHead: view.to.projectionHead, recordCount: view.to.recordCount,
      eventCount: view.eventCount, events, view, headAuthentication: verification.to.authenticated,
    });
    verifiedStates.set(history, () => {
      if (state === undefined) {
        const result = replay(events);
        // verifyExportView replayed these events to this head and root; a different outcome is a broken invariant.
        if (result.status !== "ACCEPTED" || result.state.head.hash !== history.head.hash || rootAt(result.state, history.head.position) !== history.stateRoot) return refuse("TRANSFER_INVALID", `transfer ${id}: the events do not replay to the verified head`);
        state = result.state;
      }
      return state!;
    });
    verified.set(id, history);
    return history;
  };

  bounded();
  return Object.freeze({
    begin(input: unknown, transferId: string, committedReference: string | null) {
      const m = validManifest(input), id = idOf(transferId);
      if (manifestId(m) !== id) refuse("TRANSFER_INVALID", "transferId is not the manifest's hash");
      if (committedReference !== null && typeof committedReference !== "string") fail("INVALID_INPUT", "committedReference must be a string or null");
      const existing = active();
      if (existing !== null && existing !== id && existing !== committedReference) refuse("TRANSFER_CONFLICT", `transfer ${existing} is still active`);
      storeOnce(fileName(id, "manifest"), manifestBytes(m), L.manifestBytes, "manifest");
      if (existing !== id) setActive(id);
      point("transfer-begin-synced");
      return Object.freeze({ transferId: id });
    },
    chunk(transferId: string, index: number, parts: readonly string[]) {
      const { id, m } = requireActive(transferId);
      if (!isPosition(index) || index >= m.segments.length) refuse("TRANSFER_CHUNK_INVALID", "index is not a segment of this transfer");
      const maxChars = Math.ceil(L.segmentBytes / 3) * 4;
      if (!Array.isArray(parts) || types.isProxy(parts) || parts.length < 1 || parts.length > Math.ceil(maxChars / L.partChars) || !parts.every((p) => typeof p === "string" && p.length > 0 && p.length <= L.partChars)) {
        refuse("TRANSFER_CHUNK_INVALID", `parts must be 1 to ${Math.ceil(maxChars / L.partChars)} non-empty strings of at most ${L.partChars} characters`);
      }
      const encoded = parts.join(""), segment = m.segments[index]!;
      if (encoded.length > maxChars) refuse("TRANSFER_CHUNK_INVALID", "the chunk is larger than a segment");
      const bytes = Buffer.from(encoded, "base64");
      if (bytes.toString("base64") !== encoded || bytes.length !== segment.bytes || sha256Hex(bytes) !== segment.digest) refuse("TRANSFER_CHUNK_INVALID", `chunk ${index} does not match the segment's size and digest`);
      rowsOf(bytes, segment);
      storeOnce(fileName(segment.digest, "chunk"), bytes, L.segmentBytes, "chunk");
      point("transfer-chunk-synced");
      return Object.freeze({ transferId: id, index });
    },
    abort(transferId: string) {
      const { id } = requireActive(transferId);
      setActive(null);
      return Object.freeze({ transferId: id });
    },
    ready(transferId: string) { return load(requireActive(transferId).id); },
    load,
    inspect() { return Object.freeze({ active: active(), ...bounded() }); },
  });
}
