/**
 * Witness-signed "latest head" answers (docs/reference/witness-protocol.md §9.8). An inclusion
 * proof shows a head is IN the witness log, never that it is the history's
 * LATEST head, so any relay could replay an older genuine `latest`. Every
 * answer that asserts a history's latest head therefore carries a signed note
 * (same witness key, same C2SP signed-note format as the checkpoints) over the
 * client's nonce:
 *
 *   irontrellis-witness-latest/1\n
 *   <origin>\n
 *   <historyId>\n
 *   <nonce>\n
 *   <latest position | none>\n
 *   <latest head hash | none>\n
 *   <leaf index of that HEAD entry | none>\n
 *   <tree size of the accompanying checkpoint>\n
 *   <equivocation count>\n
 *   <supersede count>\n
 *
 * The equivocation count is the number of EQUIVOCATION entries the witness
 * recorded for the history, the supersede count the number of SUPERSEDED entries
 * (a pre-rotated rotation overrode heads an owner key signed after the last good
 * head, docs/reference/witness-operations.md §7.4).
 *
 * Domain separation: a checkpoint's first line is the witness origin, which a
 * witness never sets to `irontrellis-witness-latest/1`, and the second line here
 * is the origin, not a decimal size, so a latest note never parses as a
 * checkpoint and a checkpoint never parses as a latest note.
 *
 * The nonce is base64url without padding (RFC 4648 §5) of 16..64 random bytes,
 * canonical spelling only.
 */
import { randomBytes } from "node:crypto";
import { NoteError, openNote } from "./note.ts";

/** The latest-note version line; a witness origin may never equal it (domain separation from checkpoints). */
export const LATEST_NOTE_VERSION = "irontrellis-witness-latest/1";
export const MIN_NONCE_BYTES = 16;
export const MAX_NONCE_BYTES = 64;

/** The latest head a witness asserts for a history at one tree size, bound to the client's nonce. */
export type LatestNote = Readonly<{
  origin: string;
  historyId: string;
  nonce: string;
  /** `null`: the witness holds no head for the history (registration only). */
  latest: Readonly<{ position: number; hash: string; index: number }> | null;
  treeSize: number;
  equivocations: number;
  /** SUPERSEDED entries recorded for the history (docs/reference/witness-operations.md §7.4). */
  supersedes: number;
}>;

export type LatestNoteFailure = "EXPECTATION_INVALID" | "NOTE_UNVERIFIED" | "LATEST_MALFORMED" | "ORIGIN_MISMATCH" | "HISTORY_MISMATCH" | "NONCE_MISMATCH";
/** What a client asked a witness: the history, the fresh nonce of this request and, once known, the witness origin. */
export type LatestNoteExpectation = Readonly<{ origin?: string; historyId: string; nonce: string }>;
export type LatestNoteVerification =
  | Readonly<{ ok: true; latest: LatestNote; verifiedBy: string[] }>
  | Readonly<{ ok: false; reason: LatestNoteFailure; message: string }>;

const NONCE = /^[A-Za-z0-9_-]+$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const CONTENT_HASH = /^0x[0-9a-f]{64}$/;
/** A single line of note text: non-empty, no control characters (DEL allowed, like the note format). */
const LINE = /^[^\u0000-\u001f]+$/;

/** True iff `nonce` is canonical unpadded base64url of 16..64 bytes. */
export function isValidNonce(nonce: unknown): nonce is string {
  if (typeof nonce !== "string" || nonce.length < 22 || nonce.length > 86 || !NONCE.test(nonce)) return false;
  const bytes = Buffer.from(nonce, "base64url");
  return bytes.length >= MIN_NONCE_BYTES && bytes.length <= MAX_NONCE_BYTES && bytes.toString("base64url") === nonce;
}

/** A fresh nonce: 32 random bytes, base64url without padding. */
export function newNonce(): string {
  return randomBytes(32).toString("base64url");
}

const isWellFormed = (text: string): boolean => (text as string & { isWellFormed(): boolean }).isWellFormed();
const isCount = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

/** The note body (text to sign) for `note`. Throws `NoteError("MALFORMED_LATEST_NOTE")` on a field that cannot be written. */
export function formatLatestNote(note: LatestNote): string {
  const fail = (why: string): never => { throw new NoteError("MALFORMED_LATEST_NOTE", `latest note: ${why}`); };
  if (note === null || typeof note !== "object") fail("fields must be a record");
  if (typeof note.origin !== "string" || !LINE.test(note.origin) || !isWellFormed(note.origin) || note.origin === LATEST_NOTE_VERSION) fail("origin is one line and not a latest-note version");
  if (typeof note.historyId !== "string" || !CONTENT_HASH.test(note.historyId)) fail("historyId is 0x + 64 lowercase hex");
  if (!isValidNonce(note.nonce)) fail("nonce is canonical base64url of 16..64 bytes");
  if (!isCount(note.treeSize)) fail("treeSize is a safe non-negative integer");
  if (!isCount(note.equivocations)) fail("equivocations is a safe non-negative integer");
  if (!isCount(note.supersedes)) fail("supersedes is a safe non-negative integer");
  const latest = note.latest;
  if (latest !== null) {
    if (latest === undefined || typeof latest !== "object" || !isCount(latest.position) || !isCount(latest.index) || typeof latest.hash !== "string" || !CONTENT_HASH.test(latest.hash)) {
      fail("latest is null or { position, hash, index }");
    }
    if (latest.index >= note.treeSize) fail("the latest head's leaf index must be below the tree size");
  }
  return [
    LATEST_NOTE_VERSION, note.origin, note.historyId, note.nonce,
    latest === null ? "none" : String(latest.position), latest === null ? "none" : latest.hash, latest === null ? "none" : String(latest.index),
    String(note.treeSize), String(note.equivocations), String(note.supersedes),
  ].map((line) => `${line}\n`).join("");
}

/** Strict parse of a latest-note body (the text of an opened note). Throws `NoteError("MALFORMED_LATEST_NOTE")`. */
export function parseLatestNote(body: string): LatestNote {
  const fail = (why: string): never => { throw new NoteError("MALFORMED_LATEST_NOTE", `malformed latest note: ${why}`); };
  if (typeof body !== "string" || !body.endsWith("\n") || !isWellFormed(body)) fail("not newline-terminated text");
  const lines = body.slice(0, -1).split("\n");
  if (lines.length !== 10) fail("not ten lines");
  const [version, origin, historyId, nonce, positionText, hash, indexText, sizeText, equivocationText, supersedeText] = lines as [string, string, string, string, string, string, string, string, string, string];
  if (version !== LATEST_NOTE_VERSION) fail(`the first line is not ${LATEST_NOTE_VERSION}`);
  if (!LINE.test(origin) || origin === LATEST_NOTE_VERSION) fail("origin");
  if (!CONTENT_HASH.test(historyId)) fail("historyId");
  if (!isValidNonce(nonce)) fail("nonce");
  const decimal = (text: string, what: string): number => {
    if (!DECIMAL.test(text)) fail(`${what} is not a decimal without leading zeros`);
    const value = Number(text);
    if (!Number.isSafeInteger(value)) fail(`${what} exceeds 2^53 - 1`);
    return value;
  };
  const treeSize = decimal(sizeText, "tree size");
  const equivocations = decimal(equivocationText, "equivocation count");
  const supersedes = decimal(supersedeText, "supersede count");
  const none = [positionText, hash, indexText].filter((text) => text === "none").length;
  if (none !== 0 && none !== 3) fail("position, hash and index are all present or all none");
  let latest: LatestNote["latest"] = null;
  if (none === 0) {
    if (!CONTENT_HASH.test(hash)) fail("head hash");
    const position = decimal(positionText, "position"), index = decimal(indexText, "leaf index");
    if (index >= treeSize) fail("the leaf index is not below the tree size");
    latest = Object.freeze({ position, hash, index });
  }
  return Object.freeze({ origin, historyId, nonce, latest, treeSize, equivocations, supersedes });
}

/**
 * Why `expectation` is not a well-formed expectation (undefined when it is): a plain object (prototype
 * `Object.prototype` or `null`, not an array, `Map` or class instance) whose own keys are `historyId` (a content hash),
 * `nonce` (canonical base64url of 16..64 bytes) and optionally `origin` (one line that is not a latest-note version),
 * each a string of that shape, and nothing else. Any other shape (a `Map`, an array, `null`, a missing or mistyped
 * nonce, a misspelt key) is refused rather than read as "expect nothing", which would let a replayed answer to another
 * nonce pass.
 */
function expectationDefect(expectation: unknown): string | undefined {
  if (expectation === null || typeof expectation !== "object" || Array.isArray(expectation)) return "the expectation is not an object";
  const prototype = Object.getPrototypeOf(expectation);
  if (prototype !== Object.prototype && prototype !== null) return "the expectation is not a plain object";
  const keys = Reflect.ownKeys(expectation);
  for (const key of keys) {
    if (key !== "origin" && key !== "historyId" && key !== "nonce") return `the expectation has an unknown field ${String(key)}`;
    const descriptor = Object.getOwnPropertyDescriptor(expectation, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) return `the expectation field ${key} is not a plain data field`;
  }
  const { origin, historyId, nonce } = expectation as Record<string, unknown>;
  if (typeof historyId !== "string" || !CONTENT_HASH.test(historyId)) return "the expectation needs historyId, a content hash (0x and 64 lowercase hex digits)";
  if (!isValidNonce(nonce)) return "the expectation needs nonce, canonical base64url of 16..64 bytes (the nonce of this request)";
  if (keys.includes("origin") && (typeof origin !== "string" || !LINE.test(origin) || !isWellFormed(origin) || origin === LATEST_NOTE_VERSION)) {
    return "the expectation's origin is not one line naming a witness";
  }
  return undefined;
}

/**
 * Opens a signed latest note with `trustedVerifierKeys` (never a key the
 * answer names), parses it and checks it against what the caller asked:
 * `historyId` and `nonce` (required: without them a replayed answer would
 * pass) and, when given, `origin` (the witness origin from its checkpoints).
 * An expectation of any other shape fails closed with EXPECTATION_INVALID,
 * checked first. Never throws. The caller still checks the head, leaf index
 * and tree size against the receipt that came with it. To read an unverified
 * answer, use `openNote` and `parseLatestNote`.
 */
export function verifyLatestNote(note: unknown, trustedVerifierKeys: readonly string[], expectation: LatestNoteExpectation): LatestNoteVerification {
  const fail = (reason: LatestNoteFailure, message: string): LatestNoteVerification => Object.freeze({ ok: false, reason, message });
  const defect = expectationDefect(expectation);
  if (defect !== undefined) return fail("EXPECTATION_INVALID", defect);
  // Read once, after the check (every field is a plain data property of a plain object).
  const expect = { origin: (expectation as { origin?: string }).origin, historyId: expectation.historyId, nonce: expectation.nonce };
  if (typeof note !== "string") return fail("NOTE_UNVERIFIED", "a latest note is signed note text");
  let body: string, verifiedBy: string[];
  try {
    ({ body, verifiedBy } = openNote(note, trustedVerifierKeys));
  } catch (error) {
    return fail("NOTE_UNVERIFIED", error instanceof NoteError ? `${error.code}: ${error.message}` : String(error));
  }
  let parsed: LatestNote;
  try {
    parsed = parseLatestNote(body);
  } catch (error) {
    return fail("LATEST_MALFORMED", error instanceof Error ? error.message : String(error));
  }
  if (expect.origin !== undefined && parsed.origin !== expect.origin) return fail("ORIGIN_MISMATCH", `the note names origin ${JSON.stringify(parsed.origin)}, not ${JSON.stringify(expect.origin)}`);
  if (parsed.historyId !== expect.historyId) return fail("HISTORY_MISMATCH", `the note is about history ${parsed.historyId}, not ${expect.historyId}`);
  if (parsed.nonce !== expect.nonce) return fail("NONCE_MISMATCH", "the note answers another nonce (a replayed or relayed answer)");
  return Object.freeze({ ok: true, latest: parsed, verifiedBy });
}
