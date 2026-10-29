/**
 * Owner signing for format 1 (docs/HISTORY-FORMAT.md §7, §9): the `Signer` contract, the
 * Ed25519 owner key file, control-event authorization and head attestations.
 *
 * `signHash` is async because production signers may live in a KMS, an
 * ssh-agent or an external program (key references, custody/). Local key
 * pairs also expose `signHashSync`, which lets the store attest a pinned head
 * atomically with the append; any other signer attests asynchronously, and
 * the owner API waits for that attestation before a write returns.
 */
import { closeSync, constants as fsConstants, fstatSync, fsyncSync, linkSync, lstatSync, openSync, readdirSync, readFileSync, unlinkSync, writeSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { createPrivateKey, sign as nodeSign } from "node:crypto";
import { generateKeyPair, isContentHash, keyPairFromPrivateKey, signHashWith, suiteFor, type KeyPair } from "./crypto/suites.ts";
import { EngineError } from "./errors.ts";
import { ownerOnlyModeEnforced, syncDirectorySync } from "./platform.ts";
import { SIGNATURE_SCHEMES, controlAuthorizationHash, controlEffect, controlEffectHash } from "./events.ts";
import { hashCanonical } from "./hash.ts";
import { canonicalEncode } from "./canonical.ts";
import {
  OWNER_KEY_REF_VERSION, OWNER_NEXT_KEY_REF_VERSION, keyReferenceText, parseKeyReference, referenceSigner, withReferenceVersion, type OwnerKeyReference, type SignerCustody,
} from "./custody/reference.ts";
import type { SignContext } from "./custody/registry.ts";
import type { HeadAttestation } from "./store.ts";
import type { AuthorizationDomain, CanonicalEvent, ContentHash, HashAlgorithm, HexSignature, HistoryHead, OwnerKey, SignatureScheme, TrellisDomain } from "./types.ts";

export const OWNER_KEY_VERSION = "irontrellis-owner-key/1";
/**
 * The version of a next-key file (pre-rotation): the same record as an owner
 * key file under another version literal, so a next key is never loaded as the
 * current owner key by mistake (`loadOwnerKeyFile` refuses it, and
 * `loadNextOwnerKeyFile` refuses an owner key file).
 */
export const OWNER_NEXT_KEY_VERSION = "irontrellis-owner-next-key/1";
export const HEAD_ATTESTATION_VERSION = "irontrellis-head-attestation/1";
/** SPEC §7.4: the format-2 attestation body also names the domain, the state root and the projection head. */
export const HEAD_ATTESTATION_VERSION_2 = "irontrellis-head-attestation/2";
/** What a format-2 attestation commits to besides the head (SPEC §7.4). */
export type AttestationCommitment = Readonly<{ stateRoot: ContentHash; projectionHead: ContentHash | null }>;

export type Signer = Readonly<{
  keyId: string;
  scheme: SignatureScheme;
  credential: string;
  /** `context` is advisory (why the signature is asked for); signers may ignore it. */
  signHash: (hash: ContentHash, context?: SignContext) => Promise<HexSignature>;
  /** Present for local key material; lets the store attest synchronously. */
  signHashSync?: (hash: ContentHash) => HexSignature;
  /** Where the key is held (set by the key-file loaders and `referenceSigner`; absent for a programmatic signer). */
  custody?: SignerCustody;
}>;
export type { SignContext, SignerCustody };

/**
 * Test mode (never set it in production): with `IRONTRELLIS_TEST_ASYNC_SIGNERS=1`, every signer built from local key
 * material has no `signHashSync` and answers after a macrotask, like a KMS, an ssh-agent or a command signer. The
 * owner, rotation, two-phase and witness suites run under it (`pnpm --filter @ramex-labs/irontrellis test:async-signers`)
 * so every owner code path is exercised with an async-only signer.
 */
export const ASYNC_SIGNERS_TEST_ENV = "IRONTRELLIS_TEST_ASYNC_SIGNERS";
const asyncOnlySigners = (): boolean => process.env[ASYNC_SIGNERS_TEST_ENV] === "1";

const errnoCode = (error: unknown): string | undefined => (error as { code?: unknown } | null)?.code as string | undefined;
const messageOf = (error: unknown): string => (error instanceof Error ? error.message : String(error));

/** Ed25519 signing through node:crypto without the async wrapper (the JWK carries seed + public key). */
const ed25519SyncSigner = (pair: KeyPair): ((hash: ContentHash) => HexSignature) => {
  const key = createPrivateKey({
    key: { kty: "OKP", crv: "Ed25519", d: Buffer.from(pair.privateKey.slice(2), "hex").toString("base64url"), x: Buffer.from(pair.credential.slice(2), "hex").toString("base64url") },
    format: "jwk",
  });
  return (hash) => {
    if (!isContentHash(hash)) throw new EngineError("INVALID_INPUT", "signHash expects a lowercase 0x-prefixed 32-byte hash");
    return `0x${nodeSign(null, Buffer.from(hash.slice(2), "hex"), key).toString("hex")}`;
  };
};

/** A `Signer` over local key material (both schemes; `signHashSync` for Ed25519). */
export function signerFromKeyPair(pair: KeyPair, custody?: SignerCustody): Signer {
  const signHash = signHashWith(pair);
  if (asyncOnlySigners()) {
    return Object.freeze({
      keyId: pair.keyId, scheme: pair.scheme, credential: pair.credential, ...(custody === undefined ? {} : { custody }),
      signHash: async (hash: ContentHash): Promise<HexSignature> => { await new Promise((resolve) => setImmediate(resolve)); return signHash(hash); },
    });
  }
  return Object.freeze({
    keyId: pair.keyId, scheme: pair.scheme, credential: pair.credential, signHash,
    ...(pair.scheme === "ed25519" ? { signHashSync: ed25519SyncSigner(pair) } : {}), ...(custody === undefined ? {} : { custody }),
  });
}
const fileCustody = (path: string): SignerCustody => Object.freeze({ holder: "file" as const, description: `key file ${path}`, path });

export function ownerKeyPathFor(historyFile: string): string {
  return `${historyFile}.owner-key.json`;
}
/** A key id as a file-name fragment: every character outside `A-Z a-z 0-9 . _ -` becomes `_` (`owner:1` → `owner_1`). */
export const keyIdFileFragment = (keyId: string): string => keyId.replace(/[^A-Za-z0-9._-]/g, "_");
/**
 * Where an owner key rotation keeps the new key file until the rotation event
 * is recorded (then it replaces `<history>.owner-key.json`). A pending file
 * whose key the history declares in its current owner key set is completed on
 * the next open; one the history never declared is removed.
 */
export function pendingOwnerKeyPathFor(historyFile: string): string {
  return `${historyFile}.owner-key.pending.json`;
}
/**
 * Where a rotation archives the key file of a retired owner key:
 * `<history>.owner-key.<keyId-fragment>.retired.json` (mode 0600). A name that
 * already holds other bytes gets a `-2`, `-3`… suffix
 * (`<history>.owner-key.<fragment>-2.retired.json`), so this is only the first
 * candidate: find a retired key by its key id AND public key with
 * `retiredOwnerKeyFilesFor`, never by file name alone.
 */
export function retiredOwnerKeyPathFor(historyFile: string, keyId: string): string {
  return `${historyFile}.owner-key.${keyIdFileFragment(keyId)}.retired.json`;
}
/** At most this many archived key files are considered per history. */
const MAX_RETIRED_KEY_FILES = 256;
/**
 * Every archived owner key file beside `historyFile`
 * (`<history>.owner-key.*.retired.json`, whatever the key-id fragment or
 * clash suffix), the unsuffixed spellings first. The caller loads each and
 * matches the key id and the public key against the history's owner keys.
 */
export function retiredOwnerKeyFilesFor(historyFile: string): readonly string[] {
  const directory = dirname(historyFile), prefix = `${basename(historyFile)}.owner-key.`;
  let names: string[];
  try { names = readdirSync(directory); } catch { return []; }
  const suffixed = (name: string): boolean => /-[0-9]+\.retired\.json$/.test(name);
  return names
    .filter((name) => name.startsWith(prefix) && name.endsWith(".retired.json") && name.length > prefix.length + ".retired.json".length)
    .sort((a, b) => (suffixed(a) === suffixed(b) ? (a < b ? -1 : a > b ? 1 : 0) : suffixed(a) ? 1 : -1))
    .slice(0, MAX_RETIRED_KEY_FILES)
    .map((name) => join(directory, name));
}

/**
 * Where the pre-committed next owner key of a history is kept:
 * `<history>.owner-next-key.json` (mode 0600, `OWNER_NEXT_KEY_VERSION`). It
 * belongs OFF the agent host: pre-rotation protects the history only while
 * the next key is not where the current key is. `owner rotate-key --next-key`
 * brings it back for the rotation that reveals it.
 */
export function nextOwnerKeyPathFor(historyFile: string): string {
  return `${historyFile}.owner-next-key.json`;
}
/**
 * Where a commitment or a rotation keeps a freshly generated next key until
 * the event that commits to it is recorded (then it replaces
 * `<history>.owner-next-key.json`). One whose digest the owner keys in force
 * committed to is moved into place on the next open; one no epoch ever
 * committed to is removed.
 */
export function pendingNextOwnerKeyPathFor(historyFile: string): string {
  return `${historyFile}.owner-next-key.pending.json`;
}

let keyFileCounter = 0;
/** Writes a key record atomically and exclusively: temp file (0600, fsync) hard-linked to `path`; `KEY_EXISTS` when `path` exists. */
function writeKeyRecord(path: string, version: string, pair: KeyPair): void {
  writeKeyText(path, `${JSON.stringify({ version, keyId: pair.keyId, scheme: pair.scheme, credential: pair.credential, privateKey: pair.privateKey }, null, 2)}\n`);
}
/** `writeKeyRecord` for any key file text (a key reference, too). */
function writeKeyText(path: string, text: string): void {
  const temporary = `${path}.tmp-${process.pid}-${(keyFileCounter += 1)}`;
  let fd: number;
  try {
    fd = openSync(temporary, "wx", 0o600);
  } catch (error) {
    throw new EngineError("KEY_UNAVAILABLE", `cannot create key file: ${messageOf(error)}`, { path });
  }
  try {
    try {
      writeSync(fd, text);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    try {
      linkSync(temporary, path);
    } catch (error) {
      if (errnoCode(error) === "EEXIST") throw new EngineError("KEY_EXISTS", `key file already exists: ${path}`, { keyPath: path });
      throw new EngineError("KEY_UNAVAILABLE", `cannot create key file: ${messageOf(error)}`, { path });
    }
  } finally {
    try { unlinkSync(temporary); } catch { /* already gone */ }
  }
  syncDirectorySync(dirname(path), { bestEffort: true }); // skipped on Windows (platform.ts)
}

/**
 * Generates an Ed25519 next key and writes it as a next-key file
 * (`OWNER_NEXT_KEY_VERSION`, mode 0600, written to a temporary file and linked
 * into place, so the path never holds a partial key). `keyId` is the id the key
 * is proposed to take when a rotation reveals it (the rotation may choose
 * another: the commitment covers the key, not its id). `KEY_EXISTS` if the file
 * is present.
 */
export function createNextOwnerKeyFile(path: string, keyId = "owner:next"): Signer {
  const pair = generateKeyPair("ed25519", keyId);
  writeKeyRecord(path, OWNER_NEXT_KEY_VERSION, pair);
  return signerFromKeyPair(pair, fileCustody(path));
}

/**
 * Writes the key held by the next-key file at `from` as an owner key file at
 * `to` (`OWNER_KEY_VERSION`, key id `keyId`, 0600, atomic and exclusive): what
 * a pre-rotated rotation stages as `<history>.owner-key.pending.json`. The
 * next-key file is left as it is.
 */
export function promoteNextOwnerKeyFile(from: string, to: string, keyId: string): Signer {
  const loaded = readKey(from, "next");
  if (loaded.reference !== undefined) {
    // A next-key REFERENCE becomes an owner key reference: the same key, still held by its signer.
    const promoted = withReferenceVersion(loaded.reference, OWNER_KEY_REF_VERSION, keyId);
    writeKeyText(to, keyReferenceText(promoted));
    return referenceSigner(promoted, to);
  }
  const promoted = keyPairFromPrivateKey(loaded.pair!.scheme, keyId, loaded.pair!.privateKey);
  writeKeyRecord(to, OWNER_KEY_VERSION, promoted);
  return signerFromKeyPair(promoted, fileCustody(to));
}

/**
 * Writes a key reference (docs/HISTORY-FORMAT.md §13.1) to `path` (mode 0600, atomic and exclusive: `KEY_EXISTS` when
 * the file is there). An `irontrellis-owner-key-ref/1` record is an owner key file, an `irontrellis-owner-next-key-ref/1`
 * record a next-key file. Returns its signer (no backend is contacted).
 */
export function writeKeyReferenceFile(path: string, reference: OwnerKeyReference): Signer {
  const checked = parseKeyReference(JSON.parse(keyReferenceText(reference)), "the key reference");
  writeKeyText(path, keyReferenceText(checked));
  return referenceSigner(checked, path);
}

/** Generates an Ed25519 key pair and writes it (mode 0600, exclusive create). `KEY_EXISTS` if the file is present. */
export function createOwnerKeyFile(path: string, keyId = "owner:1"): Signer {
  const pair = generateKeyPair("ed25519", keyId);
  const text = `${JSON.stringify({ version: OWNER_KEY_VERSION, keyId: pair.keyId, scheme: pair.scheme, credential: pair.credential, privateKey: pair.privateKey }, null, 2)}\n`;
  let fd: number;
  try {
    fd = openSync(path, "wx", 0o600);
  } catch (error) {
    if (errnoCode(error) === "EEXIST") throw new EngineError("KEY_EXISTS", `owner key file already exists: ${path}`);
    throw new EngineError("KEY_UNAVAILABLE", `cannot create owner key file: ${messageOf(error)}`);
  }
  try {
    writeSync(fd, text);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  return signerFromKeyPair(pair, fileCustody(path));
}

type LoadedKey = Readonly<{ pair?: KeyPair; reference?: OwnerKeyReference }>;
const MAX_KEY_FILE_BYTES = 64 * 1024;

/**
 * Reads the key file at `path` as an owner key file (`kind` "owner": `OWNER_KEY_VERSION` key material or an
 * `OWNER_KEY_REF_VERSION` reference) or a next-key file ("next": `OWNER_NEXT_KEY_VERSION` / `OWNER_NEXT_KEY_REF_VERSION`).
 * On POSIX the file must be mode 0600 (no group or other access); a reference must also be owned by the user reading it
 * (it decides which program signs as the owner). Any defect is `KEY_UNAVAILABLE`.
 */
/**
 * Opens `path` for a key loader: never through a symbolic link (`O_NOFOLLOW` where the platform has it; elsewhere an
 * `lstat` refusal before the open and a regular-file check on the opened descriptor), then the mode (POSIX: no group or
 * other access) and size checks on that same descriptor, which is the one read. Returns the parsed JSON and the file's
 * owner uid. Any defect is `KEY_UNAVAILABLE`.
 */
function readCheckedJson(path: string, what: string): Readonly<{ record: unknown; uid: number | undefined }> {
  let text: string;
  let fd: number | undefined;
  let uid: number | undefined;
  const noFollow = (fsConstants as { O_NOFOLLOW?: number }).O_NOFOLLOW;
  try {
    if (noFollow === undefined) {
      let link = false;
      try { link = lstatSync(path).isSymbolicLink(); } catch { /* the open reports it */ }
      if (link) throw Object.assign(new Error("symbolic link"), { code: "ELOOP" });
    }
    fd = openSync(path, fsConstants.O_RDONLY | (noFollow ?? 0));
    const stat = fstatSync(fd);
    if (!stat.isFile()) throw new EngineError("KEY_UNAVAILABLE", `${what} ${path} is not a regular file`, { path });
    const mode = stat.mode & 0o777;
    uid = stat.uid;
    // Windows reports synthetic mode bits: the key file is protected by its ACL there (docs/PLATFORMS.md §3).
    if (ownerOnlyModeEnforced() && (mode & 0o077) !== 0) {
      throw new EngineError("KEY_UNAVAILABLE", `${what} ${path} has mode 0${mode.toString(8)}, which lets group or others read it; it must be mode 0600 (chmod 600 ${path})`, { path, mode, requiredMode: 0o600 });
    }
    if (stat.size > MAX_KEY_FILE_BYTES) throw new EngineError("KEY_UNAVAILABLE", `${what} ${path} is too large to be a key file`, { path });
    text = readFileSync(fd, "utf8");
  } catch (error) {
    if (error instanceof EngineError) throw error;
    if (errnoCode(error) === "ELOOP") {
      throw new EngineError("KEY_UNAVAILABLE", `${what} ${path} is a symbolic link: key files and key references are never followed through links (whoever can write the directory could point it at another key); replace it by the file itself`, { path, reason: "SYMLINK" });
    }
    throw new EngineError("KEY_UNAVAILABLE", `${what} unreadable: ${messageOf(error)}`, { path, cause: errnoCode(error) });
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
  try {
    return Object.freeze({ record: JSON.parse(text) as unknown, uid });
  } catch (error) {
    throw new EngineError("KEY_UNAVAILABLE", `${what} unreadable: ${messageOf(error)}`, { path });
  }
}

/** A reference is used only when the user reading it owns it (POSIX): it decides which program signs as the owner. */
function checkReferenceOwner(path: string, uid: number | undefined): void {
  const getuid = (process as { getuid?: () => number }).getuid;
  if (ownerOnlyModeEnforced() && getuid !== undefined && uid !== undefined && uid !== getuid()) {
    throw new EngineError("KEY_UNAVAILABLE", `the key reference ${path} is owned by uid ${uid}, not by this user (uid ${getuid()}): a reference decides which program signs as the owner, so only a file this user owns is used (chown it, or recreate it)`, { path, uid, reason: "FOREIGN_OWNER" });
  }
}

/**
 * Reads a key reference file with the key loaders' checks (no symbolic link; POSIX: mode 0600 and owned by this user),
 * for references handed to the CLI (`--owner-key-ref`, `--next-key-ref`, `signer test --ref`) and for doctor. `kind`
 * "owner" / "next" also requires that version; "any" takes either. A file holding key material, or any defect, is
 * `KEY_UNAVAILABLE`. Nothing is contacted.
 */
export function readKeyReferenceFile(path: string, kind: "owner" | "next" | "any" = "any"): OwnerKeyReference {
  const what = "key reference";
  const { record, uid } = readCheckedJson(path, what);
  const version = record !== null && typeof record === "object" ? (record as { version?: unknown }).version : undefined;
  const wanted = kind === "owner" ? [OWNER_KEY_REF_VERSION] : kind === "next" ? [OWNER_NEXT_KEY_REF_VERSION] : [OWNER_KEY_REF_VERSION, OWNER_NEXT_KEY_REF_VERSION];
  if (!wanted.includes(version as string)) {
    throw new EngineError("KEY_UNAVAILABLE", `${path} is not a${kind === "next" ? " next-key" : kind === "owner" ? "n owner key" : ""} key reference (version ${String(version)})`, { path, version });
  }
  checkReferenceOwner(path, uid);
  return parseKeyReference(record, `${what} ${path}`);
}

/**
 * Reads the key file at `path` as an owner key file (`kind` "owner": `OWNER_KEY_VERSION` key material or an
 * `OWNER_KEY_REF_VERSION` reference) or a next-key file ("next": `OWNER_NEXT_KEY_VERSION` / `OWNER_NEXT_KEY_REF_VERSION`).
 * Never through a symbolic link; on POSIX the file must be mode 0600 (no group or other access); a reference must also be
 * owned by the user reading it (it decides which program signs as the owner). Any defect is `KEY_UNAVAILABLE`.
 */
function readKey(path: string, kind: "owner" | "next"): LoadedKey {
  const what = kind === "next" ? "next-key file" : "owner key file";
  const { record, uid } = readCheckedJson(path, what);
  if (record === null || typeof record !== "object") throw new EngineError("KEY_UNAVAILABLE", `${what} is not a JSON record`);
  const { version: found, keyId, scheme, credential, privateKey } = record as Record<string, unknown>;
  const [material, reference] = kind === "next" ? [OWNER_NEXT_KEY_VERSION, OWNER_NEXT_KEY_REF_VERSION] : [OWNER_KEY_VERSION, OWNER_KEY_REF_VERSION];
  if (found === reference) {
    checkReferenceOwner(path, uid);
    return Object.freeze({ reference: parseKeyReference(record, `${what} ${path}`) });
  }
  if (found !== material) {
    if (found === OWNER_NEXT_KEY_VERSION || found === OWNER_NEXT_KEY_REF_VERSION) {
      throw new EngineError("KEY_UNAVAILABLE", `${path} is a next-key file (${String(found)}), not an owner key file: a pre-committed next key is used only by a rotation that reveals it (owner rotate-key --next-key / --next-key-ref)`, { path, version: found });
    }
    if (found === OWNER_KEY_VERSION || found === OWNER_KEY_REF_VERSION) {
      throw new EngineError("KEY_UNAVAILABLE", `${path} is an owner key file (${String(found)}), not a next-key file`, { path, version: found });
    }
    throw new EngineError("KEY_UNAVAILABLE", `${what} is malformed`);
  }
  if (typeof keyId !== "string" || typeof privateKey !== "string" || !(SIGNATURE_SCHEMES as readonly unknown[]).includes(scheme)) {
    throw new EngineError("KEY_UNAVAILABLE", `${what} is malformed`);
  }
  let pair: KeyPair;
  try {
    pair = keyPairFromPrivateKey(scheme as SignatureScheme, keyId, privateKey);
  } catch (error) {
    throw new EngineError("KEY_UNAVAILABLE", `${kind === "next" ? "next key" : "owner key"} is invalid: ${messageOf(error)}`);
  }
  if (typeof credential === "string" && suiteFor(pair.scheme).normalizeCredential(credential) !== pair.credential) {
    throw new EngineError("KEY_UNAVAILABLE", `${what} credential does not match its private key`);
  }
  return Object.freeze({ pair });
}

const signerOf = (loaded: LoadedKey, path: string): Signer => (loaded.reference !== undefined ? referenceSigner(loaded.reference, path) : signerFromKeyPair(loaded.pair!, fileCustody(path)));

/**
 * Loads an owner key file: key material written by `createOwnerKeyFile`, or a key reference
 * (`irontrellis-owner-key-ref/1`, custody/reference.ts) whose signer is only contacted when it signs. Any defect is
 * `KEY_UNAVAILABLE`. On POSIX systems the file must not be accessible to group or others (mode 0600): a key other
 * users can read is refused, never used. A next-key file (either version) is refused: it is not a current key.
 */
export function loadOwnerKeyFile(path: string): Signer {
  return signerOf(readKey(path, "owner"), path);
}

/**
 * Loads a next-key file written by `createNextOwnerKeyFile`, or a next-key reference
 * (`irontrellis-owner-next-key-ref/1`) (same checks as `loadOwnerKeyFile`, 0600 included); an owner key file is
 * refused. The signer signs a rotation's `nextKeyAuthorizations`; it becomes an owner key only through the rotation
 * that reveals it.
 */
export function loadNextOwnerKeyFile(path: string): Signer {
  return signerOf(readKey(path, "next"), path);
}

/**
 * The key file at `path` read with every loader check (no link, mode, owner of a reference), without contacting any
 * signer: `{ reference }` for a reference, `{ reference: undefined }` for key material. Throws `KEY_UNAVAILABLE` like the
 * loaders (doctor uses it: a signer named by a file the loaders would refuse is never contacted).
 */
export function inspectKeyFile(path: string, kind: "owner" | "next"): Readonly<{ reference: OwnerKeyReference | undefined }> {
  return Object.freeze({ reference: readKey(path, kind).reference });
}

/** What the key file at `path` holds, without contacting any signer: key material or a reference (`owner status`). */
export function keyFileHolder(path: string, kind: "owner" | "next"): "file" | "reference" {
  return readKey(path, kind).reference !== undefined ? "reference" : "file";
}

// ---------------------------------------------------------------- control events

/** Adds `data.controlAuthorization` signed over the docs/HISTORY-FORMAT.md §7 challenge; `previousHead` is the head before the event. */
export async function signControlEvent(
  signer: Signer, event: CanonicalEvent, domain: AuthorizationDomain, previousHead: HistoryHead | null, algorithm: HashAlgorithm,
): Promise<CanonicalEvent> {
  const effect = controlEffect(event.data);
  const hash = controlAuthorizationHash({
    domain, eventId: event.id, eventType: event.type, timestamp: event.timestamp,
    previousHead: previousHead === null ? null : { hash: previousHead.hash, position: previousHead.position },
    effectHash: controlEffectHash({ ...event, data: effect }, algorithm),
  }, algorithm);
  const signature = await signer.signHash(hash, { purpose: "control-authorization" });
  // A migrated format-1 source's own `/1` authorization stays beside the new one (SPEC §16.2 step 2(c)); it is outside the effect hash.
  const source = (event.data as { sourceControlAuthorization?: unknown }).sourceControlAuthorization;
  return Object.freeze({ id: event.id, type: event.type, timestamp: event.timestamp, data: Object.freeze({ ...effect, ...(source === undefined ? {} : { sourceControlAuthorization: source }), controlAuthorization: Object.freeze({ keyId: signer.keyId, signature }) }) });
}

// ---------------------------------------------------------------- head attestations

const attestedHead = (head: HistoryHead): HistoryHead => Object.freeze({ hash: head.hash, position: head.position, canonicalTime: head.canonicalTime });

/** The format-2 attestation body (SPEC §7.4): `{version, domain, head, stateRoot, projectionHead}`. */
export const headAttestationBody2 = (domain: AuthorizationDomain, head: HistoryHead, commitment: AttestationCommitment): Readonly<Record<string, unknown>> =>
  Object.freeze({ version: HEAD_ATTESTATION_VERSION_2, domain, head: attestedHead(head), stateRoot: commitment.stateRoot, projectionHead: commitment.projectionHead });

/** The hash an owner key signs for a head attestation: the `/1` body, or with `commitment` the `/2` body. */
export function headAttestationHash(domain: AuthorizationDomain, head: HistoryHead, algorithm: HashAlgorithm, commitment?: AttestationCommitment): ContentHash {
  return commitment === undefined
    ? hashCanonical({ version: HEAD_ATTESTATION_VERSION, domain, head: attestedHead(head) }, algorithm)
    : hashCanonical(headAttestationBody2(domain, head, commitment), algorithm);
}

const attestation = (signer: Signer, domain: AuthorizationDomain, head: HistoryHead, signature: HexSignature, commitment: AttestationCommitment | undefined): HeadAttestation =>
  commitment === undefined
    ? Object.freeze({ version: HEAD_ATTESTATION_VERSION, head: attestedHead(head), keyId: signer.keyId, scheme: signer.scheme, signature })
    : Object.freeze({ ...(headAttestationBody2(domain, head, commitment) as { version: "irontrellis-head-attestation/2"; domain: TrellisDomain; head: HistoryHead; stateRoot: ContentHash; projectionHead: ContentHash | null }), keyId: signer.keyId, scheme: signer.scheme, signature });

/** A `/1` attestation, or with `commitment` (format 2) a `/2` one. */
export async function attestHead(signer: Signer, domain: AuthorizationDomain, head: HistoryHead, algorithm: HashAlgorithm, commitment?: AttestationCommitment): Promise<HeadAttestation> {
  return attestation(signer, domain, head, await signer.signHash(headAttestationHash(domain, head, algorithm, commitment), { purpose: "head-attestation" }), commitment);
}

/** Synchronous variant; `undefined` when the signer cannot sign synchronously. */
export function attestHeadSync(signer: Signer, domain: AuthorizationDomain, head: HistoryHead, algorithm: HashAlgorithm, commitment?: AttestationCommitment): HeadAttestation | undefined {
  return signer.signHashSync === undefined ? undefined : attestation(signer, domain, head, signer.signHashSync(headAttestationHash(domain, head, algorithm, commitment)), commitment);
}

/**
 * True iff the attestation is well-formed and signed by a declared owner key: a `/1` attestation over
 * `{version, domain, head}`, or a `/2` one over its own body, whose `domain` label must be `domain` (SPEC §7.4: a wrong
 * label is `signatureValid: false`). Never throws.
 */
export function verifyHeadAttestation(attestation: unknown, domain: AuthorizationDomain, ownerKeys: readonly OwnerKey[], algorithm: HashAlgorithm): boolean {
  if (attestation === null || typeof attestation !== "object") return false;
  const { version, head, keyId, scheme, signature } = attestation as Record<string, unknown>;
  if ((version !== HEAD_ATTESTATION_VERSION && version !== HEAD_ATTESTATION_VERSION_2) || head === null || typeof head !== "object" || typeof keyId !== "string") return false;
  const key = ownerKeys.find((candidate) => candidate.keyId === keyId && candidate.scheme === scheme);
  if (key === undefined) return false;
  const { hash, position, canonicalTime } = head as Record<string, unknown>;
  if (!isContentHash(hash) || !Number.isSafeInteger(position) || !Number.isSafeInteger(canonicalTime)) return false;
  try {
    const suite = suiteFor(key.scheme);
    if (!suite.isSignature(signature)) return false;
    const attested = { hash, position: position as number, canonicalTime: canonicalTime as number };
    let challenge: ContentHash;
    if (version === HEAD_ATTESTATION_VERSION) challenge = headAttestationHash(domain, attested, algorithm);
    else {
      const { domain: label, stateRoot, projectionHead } = attestation as Record<string, unknown>;
      if (!isContentHash(stateRoot) || !(projectionHead === null || isContentHash(projectionHead))) return false;
      if (label === null || typeof label !== "object" || canonicalEncode(label) !== canonicalEncode(domain)) return false;
      challenge = headAttestationHash(domain, attested, algorithm, { stateRoot, projectionHead });
    }
    return suite.verify(challenge, signature, suite.normalizeCredential(key.credential));
  } catch {
    return false;
  }
}
