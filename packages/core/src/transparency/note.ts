/**
 * C2SP signed notes and tlog checkpoints (docs/reference/witness-protocol.md §9.4), byte-compatible
 * with `golang.org/x/mod/sumdb/note` (Ed25519 only).
 *
 *   note      = text + "\n" + signature lines          (text ends in "\n")
 *   signature = "— " + name + " " + base64(keyHash(4) || ed25519 signature(64)) + "\n"
 *   keyHash   = SHA-256(name || "\n" || 0x01 || publicKey32)[0:4], a big-endian uint32
 *   verifier  = name + "+" + hex8(keyHash) + "+" + base64(0x01 || publicKey32)
 *   signer    = "PRIVATE+KEY+" + name + "+" + hex8(keyHash) + "+" + base64(0x01 || seed32)
 *
 * A checkpoint (C2SP tlog-checkpoint) is a note whose text is
 * `<origin>\n<size>\n<base64 root>\n` followed by optional extension lines.
 * Base64 is the padded standard alphabet and is decoded strictly (only the
 * canonical spelling is accepted).
 */
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign as nodeSign, verify as nodeVerify, type KeyObject } from "node:crypto";
import { decodeBase64, encodeBase64 } from "./base64.ts";

export type NoteSigner = Readonly<{ name: string; publicKey: Uint8Array; sign(bytes: Uint8Array): Uint8Array }>;
export type ParsedVerifierKey = Readonly<{ name: string; keyHash: Uint8Array; publicKey: Uint8Array }>;
export type OpenedNote = Readonly<{ body: string; verifiedBy: string[] }>;
export type Checkpoint = Readonly<{ origin: string; size: number; root: Uint8Array; extensions: string[] }>;

export type NoteErrorCode =
  | "MALFORMED_NOTE" | "UNVERIFIED_NOTE" | "INVALID_SIGNATURE" | "AMBIGUOUS_KEY" | "INVALID_KEY" | "INVALID_SIGNER" | "MALFORMED_CHECKPOINT" | "MALFORMED_LATEST_NOTE";

/** Every failure of this module. `code` is stable; the message is for humans. */
export class NoteError extends Error {
  readonly code: NoteErrorCode;
  constructor(code: NoteErrorCode, message?: string) {
    super(message ?? code);
    this.name = "NoteError";
    this.code = code;
  }
}

export const ALG_ED25519 = 0x01;
export const MAX_NOTE_SIGNATURES = 100;
const SIGNATURE_PREFIX = "— ";
const UTF8 = new TextEncoder();
const SPKI_ED25519 = Buffer.from("302a300506032b6570032100", "hex");
const PKCS8_ED25519 = Buffer.from("302e020100300506032b657004220420", "hex");
/** Go `unicode.IsSpace`: ASCII whitespace, U+0085, U+00A0 and the Unicode White_Space characters. */
const GO_SPACE = /[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/u;
/** C0 controls other than "\n" (Go's note.Open rejects them; DEL is allowed). */
const CONTROL_EXCEPT_NEWLINE = /[\u0000-\u0009\u000b-\u001f]/;
const HEX8 = /^[0-9a-fA-F]{8}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;

const isWellFormed = (text: string): boolean => (text as string & { isWellFormed(): boolean }).isWellFormed();

/** Non-empty, well-formed, no Unicode space, no "+" (Go `isValidName`). */
export function isValidNoteKeyName(name: unknown): name is string {
  return typeof name === "string" && name.length > 0 && isWellFormed(name) && !GO_SPACE.test(name) && !name.includes("+");
}

const isNoteText = (text: string): boolean => isWellFormed(text) && !CONTROL_EXCEPT_NEWLINE.test(text);

const isPublicKey = (key: unknown): key is Uint8Array => key instanceof Uint8Array && key.length === 32;

const concat = (...parts: readonly Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");

const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((byte, index) => byte === b[index]);

/** keyHash over the algorithm-prefixed key (the Go `keyHash(name, key)`). */
const keyHashOf = (name: string, encodedKey: Uint8Array): Uint8Array =>
  new Uint8Array(createHash("sha256").update(UTF8.encode(name)).update(UTF8.encode("\n")).update(encodedKey).digest().subarray(0, 4));

/** The 4-byte key hash of an Ed25519 note key: SHA-256(name || "\n" || 0x01 || publicKey)[0:4]. */
export function noteKeyHash(name: string, publicKey: Uint8Array): Uint8Array {
  if (!isValidNoteKeyName(name)) throw new NoteError("INVALID_KEY", `invalid note key name ${JSON.stringify(name)}`);
  if (!isPublicKey(publicKey)) throw new NoteError("INVALID_KEY", "an Ed25519 note key is 32 bytes");
  return keyHashOf(name, concat(Uint8Array.of(ALG_ED25519), publicKey));
}

/** `<name>+<hex8 key hash>+<base64(0x01 || publicKey)>`. */
export function verifierKey(name: string, publicKey: Uint8Array): string {
  const hash = noteKeyHash(name, publicKey);
  return `${name}+${hex(hash)}+${encodeBase64(concat(Uint8Array.of(ALG_ED25519), publicKey))}`;
}

/** Parses and checks a verifier key string (name rules, hash, algorithm 0x01, 32-byte key). Throws `NoteError("INVALID_KEY")`. */
export function parseVerifierKey(vkey: string): ParsedVerifierKey {
  if (typeof vkey !== "string") throw new NoteError("INVALID_KEY", "a verifier key is a string");
  const first = vkey.indexOf("+");
  const second = first < 0 ? -1 : vkey.indexOf("+", first + 1);
  if (second < 0) throw new NoteError("INVALID_KEY", "malformed verifier key");
  const name = vkey.slice(0, first);
  const hash8 = vkey.slice(first + 1, second);
  const key = decodeBase64(vkey.slice(second + 1));
  if (!isValidNoteKeyName(name) || !HEX8.test(hash8) || key === undefined || key.length === 0) throw new NoteError("INVALID_KEY", "malformed verifier key");
  const keyHash = Uint8Array.from(Buffer.from(hash8, "hex"));
  if (!bytesEqual(keyHash, keyHashOf(name, key))) throw new NoteError("INVALID_KEY", "verifier key hash does not match its key");
  if (key[0] !== ALG_ED25519) throw new NoteError("INVALID_KEY", "unknown verifier key algorithm");
  if (key.length !== 33) throw new NoteError("INVALID_KEY", "malformed verifier key");
  return Object.freeze({ name, keyHash, publicKey: key.slice(1) });
}

// ---------------------------------------------------------------- signers

const publicKeyObject = (publicKey: Uint8Array): KeyObject =>
  createPublicKey({ key: Buffer.concat([SPKI_ED25519, publicKey]), format: "der", type: "spki" });

const noteSigner = (name: string, privateKey: KeyObject): NoteSigner & Readonly<{ keyHash: Uint8Array }> => {
  if (!isValidNoteKeyName(name)) throw new NoteError("INVALID_SIGNER", `invalid note key name ${JSON.stringify(name)}`);
  if (privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") throw new NoteError("INVALID_SIGNER", "a note signer needs an Ed25519 private key");
  const x = createPublicKey(privateKey).export({ format: "jwk" }).x;
  if (typeof x !== "string") throw new NoteError("INVALID_SIGNER", "cannot derive the public key");
  const publicKey = new Uint8Array(Buffer.from(x, "base64url"));
  return Object.freeze({
    name, publicKey, keyHash: noteKeyHash(name, publicKey),
    sign: (bytes: Uint8Array): Uint8Array => new Uint8Array(nodeSign(null, bytes, privateKey)),
  });
};

/** A note signer from a 32-byte Ed25519 seed (the RFC 8032 private key). */
export function noteSignerFromSeed(name: string, seed: Uint8Array): NoteSigner & Readonly<{ keyHash: Uint8Array }> {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) throw new NoteError("INVALID_SIGNER", "an Ed25519 seed is 32 bytes");
  return noteSigner(name, createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, seed]), format: "der", type: "pkcs8" }));
}

/** A note signer from a node:crypto Ed25519 private KeyObject. */
export function noteSignerFromKeyObject(name: string, privateKey: KeyObject): NoteSigner & Readonly<{ keyHash: Uint8Array }> {
  return noteSigner(name, privateKey);
}

/** Parses `PRIVATE+KEY+<name>+<hex8>+<base64(0x01 || seed32)>` (the Go `NewSigner` format) and checks the key hash. */
export function parseSignerKey(skey: string): NoteSigner & Readonly<{ keyHash: Uint8Array }> {
  const parts = typeof skey === "string" ? /^PRIVATE\+KEY\+([^+]*)\+([^+]*)\+(.*)$/s.exec(skey) : null;
  const key = parts === null ? undefined : decodeBase64(parts[3]);
  if (parts === null || !isValidNoteKeyName(parts[1]) || !HEX8.test(parts[2] as string) || key === undefined || key.length === 0) {
    throw new NoteError("INVALID_SIGNER", "malformed signer key");
  }
  if (key[0] !== ALG_ED25519) throw new NoteError("INVALID_SIGNER", "unknown signer key algorithm");
  if (key.length !== 33) throw new NoteError("INVALID_SIGNER", "malformed signer key");
  const signer = noteSignerFromSeed(parts[1] as string, key.slice(1));
  if (hex(signer.keyHash) !== (parts[2] as string).toLowerCase()) throw new NoteError("INVALID_SIGNER", "signer key hash does not match its key");
  return signer;
}

/** `PRIVATE+KEY+<name>+<hex8>+<base64(0x01 || seed32)>` for a 32-byte seed. */
export function formatSignerKey(name: string, seed: Uint8Array): string {
  const signer = noteSignerFromSeed(name, seed);
  return `PRIVATE+KEY+${name}+${hex(signer.keyHash)}+${encodeBase64(concat(Uint8Array.of(ALG_ED25519), seed))}`;
}

/** A fresh Ed25519 note key: the signer key string (secret) and the verifier key string (public). */
export function generateNoteKey(name: string): Readonly<{ signerKey: string; verifierKey: string }> {
  const { privateKey } = generateKeyPairSync("ed25519");
  const d = privateKey.export({ format: "jwk" }).d;
  if (typeof d !== "string") throw new NoteError("INVALID_SIGNER", "cannot export the generated key");
  const seed = new Uint8Array(Buffer.from(d, "base64url"));
  const signer = noteSignerFromSeed(name, seed);
  return Object.freeze({ signerKey: formatSignerKey(name, seed), verifierKey: verifierKey(name, signer.publicKey) });
}

// ---------------------------------------------------------------- notes

/** Signs `body` (which must end in "\n") with one Ed25519 note key; returns the note text. */
export function signNote(body: string, signer: NoteSigner): string {
  if (typeof body !== "string" || !body.endsWith("\n") || !isNoteText(body)) throw new NoteError("MALFORMED_NOTE", "note text must be well-formed, end in a newline and contain no control characters but newlines");
  if (signer === null || typeof signer !== "object" || !isValidNoteKeyName(signer.name) || !isPublicKey(signer.publicKey)) throw new NoteError("INVALID_SIGNER", "invalid note signer");
  const hash = noteKeyHash(signer.name, signer.publicKey);
  const signature = signer.sign(UTF8.encode(body));
  if (!(signature instanceof Uint8Array) || signature.length !== 64) throw new NoteError("INVALID_SIGNER", "an Ed25519 signature is 64 bytes");
  return `${body}\n${SIGNATURE_PREFIX}${signer.name} ${encodeBase64(concat(hash, signature))}\n`;
}

type Candidate = { vkey: string; publicKey: Uint8Array; key: KeyObject };

/**
 * Opens a signed note: checks its syntax, verifies every signature whose key
 * name and hash match a trusted verifier key, and returns the text and the
 * verifier keys that verified it. Signatures by unknown keys are ignored; a
 * known key with a bad signature, a malformed note, or no verified signature
 * throws `NoteError`.
 */
export function openNote(note: string, verifierKeys: readonly string[]): OpenedNote {
  if (!Array.isArray(verifierKeys)) throw new NoteError("INVALID_KEY", "verifierKeys must be an array of verifier key strings");
  const known = new Map<string, Candidate[]>();
  for (const vkey of new Set(verifierKeys)) {
    const parsed = parseVerifierKey(vkey);
    const id = `${parsed.name}+${hex(parsed.keyHash)}`;
    const list = known.get(id) ?? [];
    // The same key spelled twice (e.g. hex case) is one verifier; two different keys with one name+hash are ambiguous.
    if (!list.some((candidate) => bytesEqual(candidate.publicKey, parsed.publicKey))) list.push({ vkey, publicKey: parsed.publicKey, key: publicKeyObject(parsed.publicKey) });
    known.set(id, list);
  }
  if (typeof note !== "string" || !isNoteText(note)) throw new NoteError("MALFORMED_NOTE", "malformed note");
  const split = note.lastIndexOf("\n\n");
  if (split < 0) throw new NoteError("MALFORMED_NOTE", "malformed note");
  const body = note.slice(0, split + 1);
  const block = note.slice(split + 2);
  if (block.length === 0 || !block.endsWith("\n")) throw new NoteError("MALFORMED_NOTE", "malformed note");
  const lines = block.slice(0, -1).split("\n");
  if (lines.length > MAX_NOTE_SIGNATURES) throw new NoteError("MALFORMED_NOTE", "malformed note");
  const parsed = lines.map((line) => {
    if (!line.startsWith(SIGNATURE_PREFIX)) throw new NoteError("MALFORMED_NOTE", "malformed note");
    const rest = line.slice(SIGNATURE_PREFIX.length);
    const space = rest.indexOf(" ");
    const name = space < 0 ? rest : rest.slice(0, space);
    const b64 = space < 0 ? "" : rest.slice(space + 1);
    const raw = decodeBase64(b64);
    if (!isValidNoteKeyName(name) || b64 === "" || raw === undefined || raw.length < 5) throw new NoteError("MALFORMED_NOTE", "malformed note");
    return { name, hash: raw.subarray(0, 4), signature: raw.subarray(4) };
  });
  const bodyBytes = UTF8.encode(body);
  const verifiedBy: string[] = [];
  const seen = new Set<string>();
  for (const { name, hash, signature } of parsed) {
    const id = `${name}+${hex(hash)}`;
    const candidates = known.get(id);
    if (candidates === undefined) continue;
    if (candidates.length > 1) throw new NoteError("AMBIGUOUS_KEY", `ambiguous key ${id}`);
    if (seen.has(id)) continue;
    seen.add(id);
    const candidate = candidates[0] as Candidate;
    let ok = false;
    try {
      ok = signature.length === 64 && nodeVerify(null, bodyBytes, candidate.key, signature);
    } catch {
      ok = false;
    }
    if (!ok) throw new NoteError("INVALID_SIGNATURE", `invalid signature for key ${id}`);
    verifiedBy.push(candidate.vkey);
  }
  if (verifiedBy.length === 0) throw new NoteError("UNVERIFIED_NOTE", "note has no verifiable signatures");
  return Object.freeze({ body, verifiedBy });
}

// ---------------------------------------------------------------- checkpoints

const isLine = (line: string): boolean => line.length > 0 && !line.includes("\n") && isNoteText(line);

/** The C2SP tlog-checkpoint text: origin, decimal size, base64 root, then any extension lines. */
export function formatCheckpoint(origin: string, size: number, root: Uint8Array, extensions: readonly string[] = []): string {
  if (typeof origin !== "string" || !isLine(origin)) throw new NoteError("MALFORMED_CHECKPOINT", "the origin is one non-empty line");
  if (typeof size !== "number" || !Number.isSafeInteger(size) || size < 0) throw new NoteError("MALFORMED_CHECKPOINT", "the size is a safe non-negative integer");
  if (!(root instanceof Uint8Array) || root.length !== 32) throw new NoteError("MALFORMED_CHECKPOINT", "the root is a 32-byte hash");
  if (!Array.isArray(extensions) || !extensions.every((line) => typeof line === "string" && isLine(line))) throw new NoteError("MALFORMED_CHECKPOINT", "extension lines are non-empty single lines");
  return `${origin}\n${size}\n${encodeBase64(root)}\n${extensions.map((line) => `${line}\n`).join("")}`;
}

/** Strict parse of a checkpoint body (the text of an opened note). Throws `NoteError("MALFORMED_CHECKPOINT")`. */
export function parseCheckpoint(body: string): Checkpoint {
  const fail = (why: string): never => {
    throw new NoteError("MALFORMED_CHECKPOINT", `malformed checkpoint: ${why}`);
  };
  if (typeof body !== "string" || !body.endsWith("\n") || !isNoteText(body)) fail("not newline-terminated note text");
  const lines = body.slice(0, -1).split("\n");
  if (lines.length < 3) fail("fewer than three lines");
  const [origin, sizeText, rootText, ...extensions] = lines as [string, string, string, ...string[]];
  if (origin.length === 0) fail("empty origin");
  if (!DECIMAL.test(sizeText)) fail("size is not a decimal without leading zeros");
  const size = Number(sizeText);
  if (!Number.isSafeInteger(size)) fail("size exceeds 2^53 - 1");
  const root = decodeBase64(rootText);
  if (root === undefined || root.length !== 32) fail("root is not base64 of 32 bytes");
  if (extensions.some((line) => line.length === 0)) fail("empty extension line");
  return Object.freeze({ origin, size, root: root as Uint8Array, extensions });
}
