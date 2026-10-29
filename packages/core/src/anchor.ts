/**
 * Anchoring (docs/HISTORY-FORMAT.md §10): an anchor target receives a signed
 * head attestation and returns a receipt; the receipt is recorded in the
 * history itself as an `ANCHOR_RECORDED` event, so later verification can show
 * that the anchored head is a prefix of the current history. Targets shipped:
 * the local anchor log (`<history>.anchors`, append-only, the offline fallback
 * that `verify()` always reads) and a Sigstore Rekor v2 client (experimental).
 * No target touches the network unless it is called; `fetch` is injectable so
 * tests never do.
 *
 * An anchor is evidence about a head, nothing more: whatever its receipt
 * holds, it never binds, unbinds or re-policies a remote witness. Remote
 * witnesses (the rollback defence, docs/WITNESS.md) are bound only by the
 * owner-signed `WITNESSES_BOUND` / `WITNESSES_UNBOUND` events.
 */
import { closeSync, fsyncSync, openSync, readFileSync, writeSync } from "node:fs";
import { basename, resolve } from "node:path";
import { CanonicalError, captureValue, isU53 } from "./canonical.ts";
import { EngineError } from "./errors.ts";
import { isFormat2, isTrellis, LEGACY_FORMAT } from "./events.ts";
import { projectionHeadAt, rootAt } from "./state-records.ts";
import { hashCanonical, sha256Hex } from "./hash.ts";
import { attestHead, headAttestationHash, signControlEvent, verifyHeadAttestation, type Signer } from "./signer.ts";
import { ownerKeysAt } from "./owner-keys.ts";
import type { HeadAttestation, HistoryStore, PinnedHead } from "./store.ts";
import type { RemoteWitnessReport, RemoteWitnessStatus } from "./witness-session.ts";
import type { AuthorizationDomain, CanonicalEvent, ContentHash, HashAlgorithm, HistoryFormat, HistoryHead, OwnerKey, ReplayState, U53 } from "./types.ts";

export type AnchorKind = "local" | "rekor" | "custom";
/**
 * What an anchor target needs to reconstruct the signed hash and the signing
 * key (an attestation carries neither). `ownerKeysAt` gives the owner keys in
 * force at a head position (owner key rotation, format 1): an attestation of
 * the head at position p must be signed by one of `ownerKeysAt(p)`. Without it,
 * `ownerKeys` stands for every position (enough for a history whose owner keys
 * never rotated). `anchorContextOf(state)` builds both from a replay state.
 */
export type AnchorContext = Readonly<{
  domain: AuthorizationDomain;
  algorithm: HashAlgorithm;
  ownerKeys: readonly OwnerKey[];
  ownerKeysAt?: (position: number) => readonly OwnerKey[];
}>;

/** The anchor context of a replayed history: its domain, hash algorithm, current owner keys and the keys in force at each position. */
export function anchorContextOf(state: ReplayState): AnchorContext {
  return Object.freeze({
    domain: state.genesis.domain, algorithm: state.hashAlgorithm, ownerKeys: ownerKeysAt(state, state.head.position + 1),
    ownerKeysAt: (position: number) => ownerKeysAt(state, position),
  });
}

/**
 * Addendum A-20: a format-2 attestation's `stateRoot`/`projectionHead` against the history's own at `position` (the
 * attestation already verified and `head` a prefix). `false` for other formats and for positions whose root the state
 * does not hold (a resumed state before its snapshot: the full replay of `verify()` holds every root).
 */
export const attestedRootMismatch = (attestation: unknown, state: ReplayState, position: number): boolean => {
  if (!isFormat2(state.format)) return false;
  const a = attestation as { version?: unknown; stateRoot?: unknown; projectionHead?: unknown };
  if (a.version !== "irontrellis-head-attestation/2") return false;
  const root = rootAt(state, position);
  if (root === undefined) return false;
  return root !== a.stateRoot || projectionHeadAt(state, position) !== a.projectionHead;
};
/** The owner keys a context accepts for an attestation of the head at `position`. */
export function contextKeysAt(context: AnchorContext, position: unknown): readonly OwnerKey[] {
  if (context.ownerKeysAt === undefined) return context.ownerKeys;
  return isU53(position) ? context.ownerKeysAt(position) : [];
}
/** `verifyHeadAttestation` against the keys `context` accepts at the attested head's position. */
const verifyInContext = (attestation: unknown, context: AnchorContext): boolean =>
  verifyHeadAttestation(attestation, context.domain, contextKeysAt(context, ((attestation as { head?: { position?: unknown } } | null)?.head)?.position), context.algorithm);
export type Receipt = Readonly<Record<string, unknown>>;
/** One head attestation an anchor log holds. */
export type AnchorLogEntry = Readonly<{ attestation: HeadAttestation; receivedAt?: U53 }>;
export type AnchorTarget = Readonly<{
  kind: AnchorKind;
  name: string;
  submit(attestation: HeadAttestation, context?: AnchorContext): Promise<Receipt>;
  verify?(attestation: HeadAttestation, receipt: Receipt, context?: AnchorContext): Promise<boolean>;
  /** Where the target keeps what it received (the local anchor log: its file, absolute); verify() consults each location once. */
  location?: string;
  /**
   * Every head attestation the target holds, oldest first, read synchronously
   * (the local anchor log reads its file). `undefined` when it holds nothing (no
   * log yet). Throws when the log exists but cannot be read or parsed.
   * `verify()` needs this to compare the log against the history; a target
   * with `entries()` is an anchor log.
   */
  entries?(): readonly AnchorLogEntry[] | undefined;
}>;
/** A head an anchor log holds, as `verify()` judged it against the history. */
export type AnchorLogHead = Readonly<{
  /** The anchor log's name (`ANCHOR_KIND_NAMES`, as `ANCHOR_RECORDED.data.anchor` records it). */
  log: string;
  location?: string;
  head: HistoryHead;
  keyId: string;
  receivedAt?: U53;
  /**
   * PREFIX_OK: signed by an owner key in force at its position and a prefix of the file.
   * NEWER_THAN_FILE: its position is past the file's head (events were removed).
   * NOT_A_PREFIX: the file holds another event history at that position (rewritten or replaced).
   * SIGNATURE_INVALID: not signed by an owner key of this history in force at its position (`ownerKeysAt`).
   * STATE_ROOT_MISMATCH (format 2, addendum A-20): a valid owner signature over a `stateRoot`/`projectionHead` that is not
   * the history's at that position — evidence of owner-key misuse.
   */
  status: "PREFIX_OK" | "NEWER_THAN_FILE" | "NOT_A_PREFIX" | "SIGNATURE_INVALID" | "STATE_ROOT_MISMATCH";
}>;
/**
 * The anchor logs' verdict. OK: at least one head held, all PREFIX_OK. NONE: no
 * anchor log holds anything (informational). ROLLBACK: a held head is newer than
 * the file or not a prefix of it. INVALID: a held head is not owner-signed.
 * UNREADABLE: an anchor log exists but cannot be read or parsed. MISSING: the
 * history records a local anchor whose log was not found. NOT_APPLICABLE:
 * legacy history (anchoring needs format 1). The finding codes are
 * `ANCHOR_LOG_*` (ANCHOR_LOG_ROLLBACK, …); remote witness findings are
 * `REMOTE_WITNESS_*`.
 */
export type AnchorLogStatus = "OK" | "NONE" | "ROLLBACK" | "INVALID" | "UNREADABLE" | "MISSING" | "NOT_APPLICABLE";
export type VerifyOptions = Readonly<{
  /**
   * Accept a format-1 history whose head is not owner-pinned: a missing pin
   * file, or a pin without an owner attestation, is then a note instead of a
   * failure. Defaults to the store's own `allowUnpinned` option.
   */
  allowUnpinned?: boolean;
  /**
   * Anchor logs to consult besides the local log `<history>.anchors` (always
   * consulted when it exists). Each must implement `entries()`.
   */
  anchorLogs?: readonly AnchorTarget[];
}>;
export type PinnedHeadStatus = "MATCHES" | "AHEAD" | "ROLLBACK" | "UNPINNED" | "MISSING" | "MALFORMED";
export type VerificationReport = Readonly<{
  /** True iff `failures` is empty. Callers need not interpret the other fields to decide. */
  ok: boolean;
  /**
   * Each failure as `CODE: explanation` (codes: PIN_ROLLBACK, PIN_MISSING, PIN_MALFORMED, PIN_ATTESTATION_MISSING, PIN_ATTESTATION_INVALID, ANCHOR_MISMATCH, ANCHOR_LOG_ROLLBACK, ANCHOR_LOG_INVALID, ANCHOR_LOG_UNREADABLE, ANCHOR_LOG_MISSING;
   * remote witnesses: REMOTE_WITNESS_ROLLBACK, REMOTE_WITNESS_SPLIT_VIEW, REMOTE_WITNESS_INVALID, REMOTE_WITNESS_UNREACHABLE).
   * Notes add ANCHOR_LOG_NONE, ANCHOR_LOG_IGNORED, UNWITNESSED_TAIL, REMOTE_WITNESS_NOT_CONSULTED, REMOTE_WITNESS_UNREGISTERED, REMOTE_WITNESS_UNREACHABLE (when accepted) and
   * REMOTE_WITNESS_EQUIVOCATION_RECORDED n (a witness recorded conflicting owner-signed heads for the history: see EQUIVOCATION_WARNING).
   */
  failures: readonly string[];
  /** Informational findings that do not fail verification (same `CODE: explanation` shape). */
  notes: readonly string[];
  path: string;
  format: HistoryFormat | undefined;
  head: HistoryHead | undefined;
  eventCount: U53;
  chain: "OK";
  pinnedHead?: PinnedHead;
  /**
   * MATCHES / AHEAD (the file is longer than the pin, normal between pins): fine.
   * ROLLBACK: the file does not contain the pinned head. MALFORMED: the pin file
   * cannot be parsed. MISSING: a format-1 history with events after genesis has
   * no pin file (a failure unless `allowUnpinned`). UNPINNED: no pin and none is
   * required (legacy files predate pinning; empty or genesis-only histories).
   */
  pinnedHeadStatus: PinnedHeadStatus;
  /** Format 1 with a pin: whether the pin carries an owner attestation that verifies (MISSING/INVALID fail verification). */
  pinnedAttestation?: "VERIFIED" | "INVALID" | "MISSING";
  /** The head the pin's verified attestation covers (it trails the pin when the last writers had no owner key). */
  attestedHead?: HistoryHead;
  /** Format 2 (SPEC §7.5): `rootAt(head.position)` and the projection head at the head (`null` with the projection off). */
  stateRoot?: ContentHash;
  projectionHead?: ContentHash | null;
  /** Format 2, when the handle opened in `CHECKPOINT_RESUME` mode: the snapshot was used, found stale (replayed in full, rebuilt) or absent. */
  snapshot?: "USED" | "STALE" | "NONE";
  /** Set when a rollback was accepted (`acceptRollback`) and the pin still records it. */
  rollbackAcceptedAt?: U53;
  previousPin?: PinnedHead;
  anchors: readonly Readonly<{ head: HistoryHead; anchor: string; eventId: string; status: "PREFIX_OK" | "MISMATCH" }>[];
  anchorLogStatus: AnchorLogStatus;
  anchorLogHeads: readonly AnchorLogHead[];
  controlSignatures: "VERIFIED" | "NOT_APPLICABLE";
  /**
   * Remote witnesses (formats 1 and 2, when configured or bound): OK, ROLLBACK,
   * SPLIT_VIEW, INVALID, UNREACHABLE, or NOT_CONSULTED (the
   * synchronous `verify()` does not ask them; `verifyWithWitnesses` does).
   */
  remoteWitnessStatus?: RemoteWitnessStatus;
  /** Per remote witness, as `verifyWithWitnesses` judged it. */
  remoteWitnesses?: readonly RemoteWitnessReport[];
}>;

/** The `ANCHOR_RECORDED.data.anchor` literal recorded for each anchor kind (events.ts ANCHOR_NAMES). */
export const ANCHOR_KIND_NAMES: Readonly<Record<AnchorKind, string>> = Object.freeze({ local: "local-head-file", rekor: "rekor-v2", custom: "custom" });
export const MAX_RECEIPT_BYTES = 65_536;
export const REKOR_DEFAULT_BASE_URL = "https://rekor.sigstore.dev";

type FetchLike = (url: string, init: Readonly<{ method: string; headers: Readonly<Record<string, string>>; body: string }>) => Promise<Readonly<{ ok: boolean; status: number; text(): Promise<string> }>>;
const defaultFetch: FetchLike = (url, init) => globalThis.fetch(url, init);
const messageOf = (error: unknown): string => (error instanceof Error ? error.message : String(error));
const isRecord = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);

/** A receipt is a bounded plain protocol record (≤ 64 KiB canonical), so it can live inside an event. */
export function boundedReceipt(receipt: unknown): Receipt {
  if (!isRecord(receipt)) throw new EngineError("RECEIPT_INVALID", "an anchor receipt must be a plain record");
  try {
    return captureValue(receipt, { maxTotalBytes: MAX_RECEIPT_BYTES, maxDepth: 16 }) as Receipt;
  } catch (error) {
    throw new EngineError("RECEIPT_INVALID", `anchor receipt is not a bounded protocol record: ${error instanceof CanonicalError ? error.reason : messageOf(error)}`);
  }
}
const parseBody = (text: string): Receipt => {
  if (text.trim() === "") return Object.freeze({});
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return Object.freeze({ body: text });
  }
  return boundedReceipt(isRecord(parsed) ? parsed : { value: parsed });
};
const requireContext = (context: AnchorContext | undefined, target: string): AnchorContext => {
  if (context === undefined) throw new EngineError("INVALID_INPUT", `${target} needs the anchor context (domain, algorithm, ownerKeys)`);
  return context;
};

// ---------------------------------------------------------------- local anchor log

/** The local anchor log that `anchorHead` and `verify()` use by default. */
export function anchorsPathFor(historyFile: string): string {
  return `${historyFile}.anchors`;
}

const errnoOf = (error: unknown): string | undefined => (error as { code?: unknown } | null)?.code as string | undefined;
const localEntryHash = (entry: unknown): ContentHash => hashCanonical(entry, "sha256");

/** Parses a local anchor log; `undefined` when absent, `ANCHOR_LOG_UNREADABLE` when unreadable or malformed. */
const readLocalLog = (path: string): readonly AnchorLogEntry[] | undefined => {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (error) {
    if (errnoOf(error) === "ENOENT") return undefined;
    throw new EngineError("ANCHOR_LOG_UNREADABLE", `anchor log ${path} cannot be read: ${messageOf(error)}`, { location: path, cause: errnoOf(error) });
  }
  const entries: AnchorLogEntry[] = [];
  const lines = text.split("\n");
  if (lines.at(-1) !== "") throw new EngineError("ANCHOR_LOG_UNREADABLE", `anchor log ${path} ends with an incomplete line`, { location: path });
  lines.pop();
  lines.forEach((line, index) => {
    let entry: unknown;
    try {
      entry = JSON.parse(line);
    } catch {
      entry = undefined;
    }
    const attestation = isRecord(entry) ? entry.attestation : undefined;
    const head = isRecord(attestation) ? attestation.head : undefined;
    const receivedAt = isRecord(entry) ? entry.receivedAt : undefined;
    // Positions and times are canonical U53s; JSON.parse reads `-0` as -0 (fuzz VAST-FUZZ-01 F4).
    if (!isRecord(attestation) || !isRecord(head) || typeof head.hash !== "string" || !isU53(head.position) ||
      !isU53(head.canonicalTime) || typeof attestation.keyId !== "string" || (receivedAt !== undefined && !isU53(receivedAt))) {
      throw new EngineError("ANCHOR_LOG_UNREADABLE", `anchor log ${path} line ${index + 1} is not an anchor log entry`, { location: path, line: index + 1 });
    }
    entries.push(Object.freeze({ attestation: attestation as unknown as HeadAttestation, ...(receivedAt === undefined ? {} : { receivedAt: receivedAt as U53 }) }));
  });
  return Object.freeze(entries);
};

/**
 * Appends `{attestation, receivedAt}` lines to `path` (by convention
 * `anchorsPathFor(history)`, `<history>.anchors`); the receipt names the entry
 * by its hash. With a context, `submit` refuses an attestation that is not
 * owner-signed and `verify` re-checks the attestation's signature; `verify`
 * without a context answers false. `entries()` lists the log for `verify()`.
 */
export function localAnchorLog(path: string): AnchorTarget {
  const location = resolve(path);
  return Object.freeze({
    kind: "local" as const,
    name: ANCHOR_KIND_NAMES.local,
    location,
    async submit(attestation: HeadAttestation, context?: AnchorContext): Promise<Receipt> {
      if (context !== undefined && !verifyInContext(attestation, context)) {
        throw new EngineError("ANCHOR_LOG_REJECTED", "the local anchor log refuses a head attestation that does not verify against the owner keys");
      }
      const entry = { attestation, receivedAt: Date.now() };
      const fd = openSync(location, "a", 0o600);
      try {
        writeSync(fd, `${JSON.stringify(entry)}\n`);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      return Object.freeze({ file: basename(location), receivedAt: entry.receivedAt, entryHash: localEntryHash(entry) });
    },
    async verify(attestation: HeadAttestation, receipt: Receipt, context?: AnchorContext): Promise<boolean> {
      if (context === undefined || !verifyInContext(attestation, context)) return false;
      let entries: readonly AnchorLogEntry[] | undefined;
      try {
        entries = readLocalLog(location);
      } catch {
        return false;
      }
      const wanted = hashCanonical(attestation, "sha256");
      return (entries ?? []).some((entry) => localEntryHash(entry) === receipt.entryHash && hashCanonical(entry.attestation, "sha256") === wanted);
    },
    entries(): readonly AnchorLogEntry[] | undefined {
      return readLocalLog(location);
    },
  });
}

// ---------------------------------------------------------------- anchor log comparison (used by verify())

export type AnchorLogCheck = Readonly<{ status: AnchorLogStatus; heads: readonly AnchorLogHead[]; failures: readonly string[]; notes: readonly string[] }>;

/**
 * Compares every head the anchor logs hold with the history: each must be signed
 * by an owner key in force at its position (`ownerKeysAt`) and be a prefix of the file (position ≤ head and the
 * same event-history hash there). Logs sharing a `location` are read once.
 * Internal to `verify()`.
 */
export function checkAnchorLogs(logs: readonly AnchorTarget[], state: ReplayState | undefined, format: HistoryFormat | undefined): AnchorLogCheck {
  const seen = new Set<string>();
  const unique = logs.filter((log) => {
    if (typeof log?.entries !== "function") throw new EngineError("INVALID_INPUT", `anchor target ${String(log?.name)} cannot list the heads it holds (entries())`);
    if (log.location === undefined) return true;
    if (seen.has(log.location)) return false;
    seen.add(log.location);
    return true;
  });
  const heads: AnchorLogHead[] = [], failures: string[] = [], notes: string[] = [];
  const where = (log: AnchorTarget): string => (log.location === undefined ? log.name : `${log.name} (${log.location})`);
  if (format === LEGACY_FORMAT) {
    for (const log of unique) {
      try {
        if ((log.entries!()?.length ?? 0) > 0) notes.push(`ANCHOR_LOG_IGNORED: ${where(log)} holds head attestations, but a legacy history cannot be anchored; they were not checked`);
      } catch { /* not applicable either way */ }
    }
    return Object.freeze({ status: "NOT_APPLICABLE", heads: Object.freeze(heads), failures: Object.freeze(failures), notes: Object.freeze(notes) });
  }
  let unreadable = false, rollback = false, invalid = false, held = 0;
  const readable = new Set<string>();
  const context = state === undefined ? undefined : anchorContextOf(state);
  for (const log of unique) {
    let entries: readonly AnchorLogEntry[] | undefined;
    try {
      entries = log.entries!();
    } catch (error) {
      unreadable = true;
      failures.push(`ANCHOR_LOG_UNREADABLE: ${where(log)} cannot be read, so rollback cannot be excluded: ${messageOf(error)}`);
      continue;
    }
    if (entries === undefined) continue;
    if (log.location !== undefined) readable.add(basename(log.location));
    for (const entry of entries) {
      held += 1;
      const { attestation } = entry;
      const head = Object.freeze({ hash: attestation.head.hash, position: attestation.head.position, canonicalTime: attestation.head.canonicalTime });
      let status: AnchorLogHead["status"];
      if (context !== undefined && !verifyInContext(attestation, context)) {
        status = "SIGNATURE_INVALID";
        invalid = true;
        failures.push(`ANCHOR_LOG_INVALID: ${where(log)} holds a head attestation (position ${head.position}, key ${attestation.keyId}) that does not verify against the owner keys of this history in force at that position`);
      } else if (state === undefined || head.position > state.head.position) {
        status = "NEWER_THAN_FILE";
        rollback = true;
        failures.push(`ANCHOR_LOG_ROLLBACK: ${where(log)} holds an owner-attested head at position ${head.position}, but the history ${state === undefined ? "is empty" : `ends at position ${state.head.position}`}: events were removed`);
      } else if (state.eventHistoryHashes[head.position] !== head.hash) {
        status = "NOT_A_PREFIX";
        rollback = true;
        failures.push(`ANCHOR_LOG_ROLLBACK: ${where(log)} holds an owner-attested head at position ${head.position} that is not a prefix of this history: the history was rewritten or replaced`);
      } else if (attestedRootMismatch(attestation, state, head.position)) {
        // Addendum A-20: a valid signature over a wrong root is misuse evidence, reported under its own code.
        status = "STATE_ROOT_MISMATCH";
        invalid = true;
        failures.push(`ATTESTED_STATE_ROOT_MISMATCH: ${where(log)} holds an owner-signed attestation of position ${head.position} (key ${attestation.keyId}) whose stateRoot or projectionHead is not this history's at that position: the owner key signed a state this history does not have (ANCHOR_LOG)`);
      } else {
        status = "PREFIX_OK";
      }
      heads.push(Object.freeze({
        log: log.name, ...(log.location === undefined ? {} : { location: log.location }), head, keyId: attestation.keyId,
        ...(entry.receivedAt === undefined ? {} : { receivedAt: entry.receivedAt }), status,
      }));
    }
  }
  // A history that records local anchors proves its anchor log existed: a log that has gone is a failure, not "no anchor log".
  let missing = false;
  if (state !== undefined) {
    const expected = new Set<string>();
    for (const anchor of state.anchors) {
      if (anchor.anchor !== ANCHOR_KIND_NAMES.local) continue;
      const file = (state.events[anchor.eventPosition]?.data as { receipt?: { file?: unknown } } | undefined)?.receipt?.file;
      if (typeof file === "string") expected.add(file);
    }
    for (const file of expected) {
      if (readable.has(file)) continue;
      missing = true;
      failures.push(`ANCHOR_LOG_MISSING: the history records anchors in the local anchor log "${file}", but that log was not found next to the history or among the given anchor logs`);
    }
  }
  const status: AnchorLogStatus = unreadable ? "UNREADABLE" : rollback ? "ROLLBACK" : invalid ? "INVALID" : missing ? "MISSING" : held > 0 ? "OK" : "NONE";
  if (status === "NONE") notes.push("ANCHOR_LOG_NONE: no anchor log holds a head for this history, so a restored older copy cannot be told apart from the latest one");
  return Object.freeze({ status, heads: Object.freeze(heads), failures: Object.freeze(failures), notes: Object.freeze(notes) });
}

// ---------------------------------------------------------------- rekor anchor (experimental)

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const base64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64");
const hexBytes = (hex: string): Buffer => Buffer.from(hex.slice(2), "hex");

/**
 * Sigstore Rekor v2 (rekor-tiles) `hashedrekord` entry over the head attestation.
 *
 * @experimental Written from the public Rekor v2 API description and never
 * exercised against a live server; not covered by the 1.0 stability promise. Request: `POST {baseUrl}/api/v2/log/entries` with a
 * `CreateEntryRequest` whose `hashedRekordRequestV002` names the sha256 digest
 * of the signed artifact plus the signature and its verifier (protobuf JSON:
 * bytes fields are standard base64). The artifact is the 32-byte attestation
 * hash (`hashCanonical({version, domain, head})`), which is exactly what the
 * owner key signed, so `digest = sha256(artifact bytes)`. Only Ed25519 owner
 * keys are mapped (`PKIX_ED25519`, DER SPKI in `publicKey.rawBytes`); note that
 * Rekor cannot verify a pure-Ed25519 signature from a digest alone and may
 * reject the entry — treat any receipt as unverified until this is validated
 * against a real log. The 2xx body (a `TransparencyLogEntry`) is the receipt.
 */
export function rekorAnchor(options: Readonly<{ baseUrl?: string; fetch?: FetchLike }> = {}): AnchorTarget {
  const baseUrl = (options.baseUrl ?? REKOR_DEFAULT_BASE_URL).replace(/\/+$/, "");
  const fetchImpl = options.fetch ?? defaultFetch;
  return Object.freeze({
    kind: "rekor" as const,
    name: ANCHOR_KIND_NAMES.rekor,
    async submit(attestation: HeadAttestation, context?: AnchorContext): Promise<Receipt> {
      const checked = requireContext(context, "the rekor anchor");
      const { domain, algorithm } = checked;
      const key = contextKeysAt(checked, attestation.head?.position).find((candidate) => candidate.keyId === attestation.keyId && candidate.scheme === attestation.scheme);
      if (key === undefined) throw new EngineError("KEY_UNAVAILABLE", `owner key ${attestation.keyId} is not an owner key in force at position ${String(attestation.head?.position)}`);
      if (key.scheme !== "ed25519") throw new EngineError("UNSUPPORTED_VERSION", "the rekor anchor maps Ed25519 owner keys only");
      const artifact = hexBytes(headAttestationHash(domain, attestation.head, algorithm));
      const body = {
        hashedRekordRequestV002: {
          digest: base64(hexBytes(sha256Hex(artifact))),
          signature: {
            content: base64(hexBytes(attestation.signature)),
            verifier: { publicKey: { rawBytes: base64(Buffer.concat([ED25519_SPKI_PREFIX, hexBytes(key.credential)])) }, keyDetails: "PKIX_ED25519" },
          },
        },
      };
      const response = await fetchImpl(`${baseUrl}/api/v2/log/entries`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json" }, body: JSON.stringify(body) });
      if (!response.ok) throw new EngineError("ANCHOR_LOG_REJECTED", `rekor ${baseUrl} answered ${response.status}`, { status: response.status });
      return parseBody(await response.text());
    },
  });
}

// ---------------------------------------------------------------- recording

/** The `ANCHOR_RECORDED` event (docs/HISTORY-FORMAT.md §10), unsigned: the caller adds the control authorization. */
export function anchorRecordedEvent(attestation: HeadAttestation, target: AnchorTarget, receipt: unknown, anchoredAt: U53, id: string): CanonicalEvent {
  const name = Object.hasOwn(ANCHOR_KIND_NAMES, target.kind) ? ANCHOR_KIND_NAMES[target.kind] : undefined;
  if (name === undefined) throw new EngineError("INVALID_INPUT", `unknown anchor kind ${JSON.stringify(target.kind)} (local, rekor or custom)`);
  return Object.freeze({
    id, type: "ANCHOR_RECORDED" as const, timestamp: anchoredAt,
    data: Object.freeze({ anchoredHead: attestation.head, anchor: name, receipt: boundedReceipt(receipt), anchoredAt }),
  });
}

export type AnchorResult = Readonly<{ attestation: HeadAttestation; receipt: Receipt; event: CanonicalEvent; head: HistoryHead }>;

/**
 * End to end: attest the current head, submit it, then record the receipt as a
 * signed control event under the writer lock. `target` defaults to the local
 * anchor log `<history>.anchors`, the one `verify()` reads.
 */
export async function anchorHead(store: HistoryStore, signer: Signer, target: AnchorTarget | undefined, options: Readonly<{ id: string; anchoredAt: U53 }>): Promise<AnchorResult> {
  target ??= localAnchorLog(anchorsPathFor(store.path));
  const state = store.state();
  if (!isTrellis(state.format)) throw new EngineError("UNSUPPORTED_VERSION", "anchoring needs an owner-signed history (format 1 or 2)");
  const context = anchorContextOf(state);
  // Format 2 (SPEC §7.4): the anchored attestation carries the state root and the projection head.
  const commitment = isFormat2(state.format) ? { stateRoot: rootAt(state, state.head.position)!, projectionHead: projectionHeadAt(state, state.head.position)! } : undefined;
  const attestation = await attestHead(signer, context.domain, state.head, context.algorithm, commitment);
  const receipt = await target.submit(attestation, context);
  const unsigned = anchorRecordedEvent(attestation, target, receipt, options.anchoredAt, options.id);
  const result = await store.withExclusiveWriter(async (writer) => {
    const previous = store.head();
    if (previous === undefined) throw new EngineError("HISTORY_EMPTY", "cannot anchor an empty history");
    const event = await signControlEvent(signer, unsigned, context.domain, previous, context.algorithm);
    return Object.freeze({ attestation, receipt, event, head: writer.appendAtExpectedHead(event, previous) });
  });
  // An asynchronous signer attests the new pin after the append (flush() reports a failure).
  await store.attestationsSettled();
  return result;
}
