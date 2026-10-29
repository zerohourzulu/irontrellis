/**
 * `<history>.rotation.pending.json`: the prepared-rotation record of a two-phase owner key rotation
 * (docs/reference/witness-operations.md §7.1). `rotateOwnerKey` writes it (mode 0600, atomically) after building and signing the
 * rotation in memory and before it hands the rotation to the bound witnesses, and removes it once the rotation is
 * recorded locally (or abandoned). It exists so that a crash between "a witness accepted head r" and "head r is in the
 * file" is completed on the next open or owner write instead of ending as a rollback alarm.
 *
 *   { version: "irontrellis-pending-rotation/1", historyId,
 *     event,                          // the owner-signed OWNER_KEYS_ROTATED event, exactly as it will be appended
 *     previousHead: {hash, position, canonicalTime},   // the file head it extends (r - 1)
 *     head: {hash, position, canonicalTime},           // the head it produces (r), computed with the history hasher
 *     statement,                      // the old-key head statement for r with previous = r - 1 (what the witnesses received)
 *     incoming: {keyId, scheme, credential},           // the new owner key (whose staged key file, if any, must survive a settle)
 *     nextKeyDigests?,                // the new epoch's commitment (whose staged next-key file must survive a settle)
 *     staged: {ownerKey, nextKey},    // which of the two keys were staged as files (a generated or promoted key; not a caller's signer)
 *     createdAt,
 *     seal: {keyId, scheme, signature} }  // the old owner key over everything above (irontrellis-pending-rotation-seal/1)
 *
 * THE FILE IS ATTACKER-WRITABLE. It never makes the owner sign anything, and it never makes the store accept an event
 * the replay rules reject:
 *  - it is only ever judged against the file (`judgePendingRotation`): OUTSTANDING only when the file's head is exactly
 *    `previousHead`, the event passes every replay rule there (owner signature included) and produces exactly `head`,
 *    `statement` is a valid owner-key statement for `head` with `previous = previousHead`, and the seal verifies with an
 *    owner key in force at `head` (so no field, `staged` included, can be edited without an owner key);
 *  - it is completed only when the key files it staged still hold its keys (`pendingRotationKeysMissing`): a genuine
 *    record replayed after its rotation was aborted (its staged keys deleted) never rotates the history to a lost key;
 *  - an OUTSTANDING record is completed (the event appended through the normal validated append, WITHOUT a new owner
 *    attestation of the pinned head) only when a bound witness's fresh, verified answer holds exactly `head`: what a
 *    witness holds was accepted from an owner-key statement, and the event is one anyone could have appended to the file;
 *  - it is discarded only when every bound witness answered and none holds `head`;
 *  - while it is OUTSTANDING and unresolved, writes refuse (WITNESS_UNAVAILABLE, reason ROTATION_PENDING): an append on
 *    top of `previousHead` would fork a witness that already holds `head`;
 *  - paths are never taken from it: the staged key files are the fixed `<history>.owner-key.pending.json` and
 *    `<history>.owner-next-key.pending.json`, kept only while their keys match `incoming` / `nextKeyDigests`.
 */
import { closeSync, fsyncSync, openSync, readFileSync, unlinkSync, writeSync } from "node:fs";
import { dirname } from "node:path";
import { canonicalEncode, isU53, jsonParseWithBigints } from "./canonical.ts";
import { isContentHash } from "./crypto/suites.ts";
import { EngineError } from "./errors.ts";
import { suiteFor } from "./crypto/suites.ts";
import { hashCanonical } from "./hash.ts";
import { ownerKeyDigest, ownerKeysAt } from "./owner-keys.ts";
import { loadNextOwnerKeyFile, loadOwnerKeyFile, pendingNextOwnerKeyPathFor, pendingOwnerKeyPathFor, type Signer } from "./signer.ts";
import { withProspectiveEvent } from "./replay.ts";
import { validateSignedHeadStatement, verifySignedHeadStatement, type SignedHeadStatement } from "./transparency/statement.ts";
import { replaceFileSync, syncDirectorySync } from "./platform.ts";
import type { CanonicalEvent, ContentHash, HistoryHead, OwnerKey, ReplayState } from "./types.ts";

export const PENDING_ROTATION_VERSION = "irontrellis-pending-rotation/1";

export type PendingRotationRecord = Readonly<{
  version: typeof PENDING_ROTATION_VERSION;
  historyId: ContentHash;
  event: CanonicalEvent;
  previousHead: HistoryHead;
  head: HistoryHead;
  statement: SignedHeadStatement;
  incoming: OwnerKey;
  nextKeyDigests?: readonly ContentHash[];
  staged: Readonly<{ ownerKey: boolean; nextKey: boolean }>;
  createdAt: number;
  seal: Readonly<{ keyId: string; scheme: string; signature: string }>;
}>;
export const PENDING_ROTATION_SEAL_VERSION = "irontrellis-pending-rotation-seal/1";

/** The hash the old owner key signs to seal a record: every field but the seal, under the seal version. */
export function pendingRotationSealHash(record: Omit<PendingRotationRecord, "seal">): ContentHash {
  const { seal: _seal, ...rest } = record as PendingRotationRecord;
  return hashCanonical({ version: PENDING_ROTATION_SEAL_VERSION, record: rest }, "sha256");
}

/**
 * Why the key files a record staged no longer hold its keys (`undefined`: they do): the staged owner key file
 * (`<history>.owner-key.pending.json`) must hold `incoming`, the staged next-key file (`<history>.owner-next-key.pending.json`)
 * a key whose digest the event commits to.
 */
export function pendingRotationKeysMissing(historyFile: string, record: PendingRotationRecord): string | undefined {
  if (record.staged.ownerKey) {
    let key: Signer;
    try { key = loadOwnerKeyFile(pendingOwnerKeyPathFor(historyFile)); } catch { return `its staged owner key file ${pendingOwnerKeyPathFor(historyFile)} is gone`; }
    if (key.keyId !== record.incoming.keyId || key.scheme !== record.incoming.scheme || key.credential.toLowerCase() !== record.incoming.credential.toLowerCase()) {
      return `its staged owner key file ${pendingOwnerKeyPathFor(historyFile)} holds another key`;
    }
  }
  if (record.staged.nextKey) {
    let key: Signer;
    try { key = loadNextOwnerKeyFile(pendingNextOwnerKeyPathFor(historyFile)); } catch { return `its staged next-key file ${pendingNextOwnerKeyPathFor(historyFile)} is gone`; }
    const committed = record.event.data.nextKeyDigests as readonly string[] | undefined;
    if (committed === undefined || !committed.includes(ownerKeyDigest(key))) return `its staged next-key file ${pendingNextOwnerKeyPathFor(historyFile)} holds another key`;
  }
  return undefined;
}

/** Where the record lives. */
export function pendingRotationPathFor(historyFile: string): string {
  return `${historyFile}.rotation.pending.json`;
}

const isRecord = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const isHead = (value: unknown): value is HistoryHead =>
  isRecord(value) && Object.keys(value).length === 3 && isContentHash(value.hash) && isU53(value.position) && isU53(value.canonicalTime);
const errnoOf = (error: unknown): string | undefined => (error as { code?: unknown } | null)?.code as string | undefined;

/**
 * The record at `path`: `undefined` when there is none, `null` when the file is there but is not a record (left alone:
 * it blocks nothing, since only a valid OUTSTANDING record does).
 */
export function readPendingRotation(path: string): PendingRotationRecord | null | undefined {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (error) {
    if (errnoOf(error) === "ENOENT") return undefined;
    return null;
  }
  let raw: unknown;
  try { raw = jsonParseWithBigints(text); } catch { return null; }
  if (!isRecord(raw) || raw.version !== PENDING_ROTATION_VERSION || !isContentHash(raw.historyId) || !isRecord(raw.event) || !isHead(raw.previousHead) || !isHead(raw.head)) return null;
  if (validateSignedHeadStatement(raw.statement) !== null || !isU53(raw.createdAt)) return null;
  const incoming = raw.incoming;
  if (!isRecord(incoming) || typeof incoming.keyId !== "string" || typeof incoming.scheme !== "string" || typeof incoming.credential !== "string") return null;
  const digests = raw.nextKeyDigests;
  if (digests !== undefined && !(Array.isArray(digests) && digests.every((digest) => isContentHash(digest)))) return null;
  const staged = raw.staged, seal = raw.seal;
  if (!isRecord(staged) || typeof staged.ownerKey !== "boolean" || typeof staged.nextKey !== "boolean") return null;
  if (!isRecord(seal) || typeof seal.keyId !== "string" || typeof seal.scheme !== "string" || typeof seal.signature !== "string") return null;
  return Object.freeze({
    version: PENDING_ROTATION_VERSION, historyId: raw.historyId, event: raw.event as unknown as CanonicalEvent, previousHead: Object.freeze({ ...raw.previousHead }),
    head: Object.freeze({ ...raw.head }), statement: raw.statement as SignedHeadStatement,
    incoming: Object.freeze({ keyId: incoming.keyId, scheme: incoming.scheme, credential: incoming.credential }) as OwnerKey,
    ...(digests === undefined ? {} : { nextKeyDigests: Object.freeze([...(digests as ContentHash[])]) }),
    staged: Object.freeze({ ownerKey: staged.ownerKey, nextKey: staged.nextKey }), createdAt: raw.createdAt,
    seal: Object.freeze({ keyId: seal.keyId, scheme: seal.scheme, signature: seal.signature }),
  });
}

let temporaryCounter = 0;
/** Writes the record (mode 0600, temp + fsync + rename + directory fsync). */
export function writePendingRotation(path: string, record: PendingRotationRecord): void {
  const temporary = `${path}.tmp-${process.pid}-${(temporaryCounter += 1)}`;
  const fd = openSync(temporary, "wx", 0o600);
  try {
    const bytes = Buffer.from(`${canonicalEncode(record)}\n`);
    let done = 0;
    while (done < bytes.length) done += writeSync(fd, bytes, done, bytes.length - done);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    replaceFileSync(temporary, path);
  } catch (error) {
    try { unlinkSync(temporary); } catch { /* best effort */ }
    throw new EngineError("WRITE_UNCONFIRMED", `the prepared-rotation record ${path} could not be written: ${error instanceof Error ? error.message : String(error)}`);
  }
  fsyncDirectory(path);
}

/** Removes the record (absent is fine). */
export function removePendingRotation(path: string): void {
  try { unlinkSync(path); } catch (error) { if (errnoOf(error) !== "ENOENT") throw error; return; }
  fsyncDirectory(path);
}

const fsyncDirectory = (path: string): void => { syncDirectorySync(dirname(path), { bestEffort: true }); };

/**
 * Where a record stands against the history `state`:
 *  - `RECORDED`: the file holds the event at `head.position` and that head is `head` (the rotation was appended; the
 *    record is left over: remove it and settle the key files);
 *  - `OUTSTANDING`: the file's head is `previousHead`, the event passes every replay rule there and produces exactly
 *    `head`, and `statement` is a valid statement for `head` with `previous = previousHead` by an owner key in force at it;
 *  - `OBSOLETE`: anything else (another history, the file moved on without it, a record that does not verify).
 */
export type PendingRotationJudgement =
  | Readonly<{ status: "RECORDED" }>
  | Readonly<{ status: "OUTSTANDING" }>
  | Readonly<{ status: "OBSOLETE"; reason: string }>;

const sameHead = (a: HistoryHead, b: Readonly<{ hash: string; position: number; canonicalTime?: number }>): boolean =>
  a.hash === b.hash && a.position === b.position && (b.canonicalTime === undefined || a.canonicalTime === b.canonicalTime);

export function judgePendingRotation(state: ReplayState, record: PendingRotationRecord): PendingRotationJudgement {
  if (state.eventHistoryHashes[0] !== record.historyId) return Object.freeze({ status: "OBSOLETE", reason: "the record is for another history" });
  const r = record.head.position;
  if (r !== record.previousHead.position + 1) return Object.freeze({ status: "OBSOLETE", reason: "the record's heads are not consecutive" });
  if (state.head.position >= r && state.eventHistoryHashes[r] === record.head.hash && state.events[r]?.id === record.event.id) return Object.freeze({ status: "RECORDED" });
  if (!sameHead(state.head, record.previousHead)) return Object.freeze({ status: "OBSOLETE", reason: `the history's head (position ${state.head.position}) is not the head the prepared rotation extends (position ${record.previousHead.position})` });
  if (record.event.type !== "OWNER_KEYS_ROTATED") return Object.freeze({ status: "OBSOLETE", reason: "the record's event is not an owner key rotation" });
  let prospective: ReturnType<typeof withProspectiveEvent>;
  try { prospective = withProspectiveEvent(state, record.event); } catch (error) {
    return Object.freeze({ status: "OBSOLETE", reason: `the record's event does not replay: ${error instanceof Error ? error.message : String(error)}` });
  }
  if (!prospective.ok) return Object.freeze({ status: "OBSOLETE", reason: `the record's event is rejected by the replay rules: ${prospective.code}: ${prospective.reason}` });
  if (!sameHead(prospective.head, record.head)) return Object.freeze({ status: "OBSOLETE", reason: "the record's event does not produce the record's head" });
  const statement = record.statement.statement;
  if (statement.historyId !== record.historyId || !sameHead(record.head, statement.head) || statement.previous === null || !sameHead(record.previousHead, statement.previous) ||
    canonicalEncode(statement.domain) !== canonicalEncode(state.genesis.domain) || !verifySignedHeadStatement(record.statement, (position) => ownerKeysAt(state, position)).ok) {
    return Object.freeze({ status: "OBSOLETE", reason: "the record's head statement is not a valid owner-key statement for its head" });
  }
  const sealKey = ownerKeysAt(state, r).find((key) => key.keyId === record.seal.keyId && key.scheme === record.seal.scheme);
  let sealed = false;
  if (sealKey !== undefined) {
    try {
      const suite = suiteFor(sealKey.scheme);
      sealed = suite.isSignature(record.seal.signature) && suite.verify(pendingRotationSealHash(record), record.seal.signature, suite.normalizeCredential(sealKey.credential));
    } catch { sealed = false; }
  }
  if (!sealed) return Object.freeze({ status: "OBSOLETE", reason: "the record's seal does not verify with an owner key in force at its head" });
  return Object.freeze({ status: "OUTSTANDING" });
}
