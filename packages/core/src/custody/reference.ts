/**
 * Key references (docs/HISTORY-FORMAT.md §13.1, docs/CUSTODY.md): an owner key
 * file, next-key file or retired-key archive may hold a REFERENCE instead of
 * key material:
 *
 *   { "version": "irontrellis-owner-key-ref/1",        (or irontrellis-owner-next-key-ref/1)
 *     "keyId": "owner:1", "scheme": "ed25519", "publicKey": "0x<64 hex>",
 *     "signer": { "kind": "ssh-agent" | "command" | …, …backend fields },
 *     "comment": "optional, for people" }
 *
 * It holds no secret, but it decides which program signs as the owner, so it
 * is kept like a key file (mode 0600, owned by the user that runs IronTrellis).
 * `referenceSigner` turns it into a `Signer` without `signHashSync`: every
 * signature comes from the backend and is verified locally against `publicKey`
 * before it is returned (a wrong one is SIGNER_FAILED and never used).
 */
import { EngineError } from "../errors.ts";
import { isContentHash, suiteFor } from "../crypto/suites.ts";
import type { Signer } from "../signer.ts";
import type { ContentHash, HexSignature } from "../types.ts";
import { signerBackend, signerBackendKinds, type ReferencedKey, type SignContext, type SignerSpec } from "./registry.ts";
import { parseSshPublicKey, sshPublicKeyLine } from "./ssh-agent.ts";

export const OWNER_KEY_REF_VERSION = "irontrellis-owner-key-ref/1";
export const OWNER_NEXT_KEY_REF_VERSION = "irontrellis-owner-next-key-ref/1";
export type KeyReferenceVersion = typeof OWNER_KEY_REF_VERSION | typeof OWNER_NEXT_KEY_REF_VERSION;

export type OwnerKeyReference = Readonly<{
  version: KeyReferenceVersion;
  keyId: string;
  scheme: "ed25519";
  /** The Ed25519 public key, `0x` + 64 lowercase hex (the history's credential form). */
  publicKey: `0x${string}`;
  signer: SignerSpec;
  comment?: string;
}>;

/** Where a signer's key lives, for `owner status` and doctor. */
export type SignerCustody = Readonly<{
  /** `file`: private key material in a key file on this host; `reference`: a backend holds it; `public-key-only`: nobody here can sign. */
  holder: "file" | "reference" | "public-key-only";
  /** The backend kind of a reference (`ssh-agent`, `command`, …). */
  signer?: string;
  /** One line: `ssh-agent at /run/…`, `key file /x/history.jsonl.owner-key.json`. */
  description: string;
  /** Backend identity (see `SignerBackend.identity`), for the same-signer check. */
  identity?: string;
  path?: string;
}>;

const KEY_ID = /^[^\u0000-\u001f\u007f]{1,128}$/;
const HEX_KEY = /^(?:0x)?[0-9a-fA-F]{64}$/;

/**
 * An Ed25519 public key in any accepted spelling: `0x` + 64 hex, 64 hex, or an OpenSSH line (`ssh-ed25519 AAAA… comment`).
 * Returns the `0x` + 64 lowercase hex form. FIDO (`sk-ssh-ed25519@openssh.com`) and non-Ed25519 keys are refused
 * (INVALID_INPUT with the reason).
 */
export function parsePublicKey(text: string): `0x${string}` {
  if (typeof text !== "string") throw new EngineError("INVALID_INPUT", "a public key must be a string");
  const trimmed = text.trim();
  if (HEX_KEY.test(trimmed)) return `0x${trimmed.replace(/^0x/, "").toLowerCase()}`;
  let raw: Buffer;
  try { raw = parseSshPublicKey(trimmed); } catch (error) { throw new EngineError("INVALID_INPUT", `not an Ed25519 public key: ${error instanceof Error ? error.message : String(error)}`); }
  return `0x${raw.toString("hex")}`;
}
/** The OpenSSH `ssh-ed25519 AAAA…` line of a `0x` public key. */
export function sshPublicKeyOf(publicKey: string, comment?: string): string {
  return sshPublicKeyLine(Buffer.from(parsePublicKey(publicKey).slice(2), "hex"), comment);
}

/**
 * Checks a parsed JSON record as a key reference of `version` (the version literal was already dispatched on). Any
 * defect is KEY_UNAVAILABLE with a message that names `where`.
 */
export function parseKeyReference(value: unknown, where = "key reference"): OwnerKeyReference {
  const bad = (why: string): never => { throw new EngineError("KEY_UNAVAILABLE", `${where} is not a valid key reference: ${why}`, { reason: "REFERENCE_INVALID" }); };
  if (value === null || typeof value !== "object" || Array.isArray(value)) return bad("not a JSON record");
  const r = value as Record<string, unknown>;
  const extra = Object.keys(r).filter((key) => !["version", "keyId", "scheme", "publicKey", "signer", "comment"].includes(key));
  if (extra.length > 0) bad(`unknown field(s) ${extra.join(", ")}`);
  if (r.version !== OWNER_KEY_REF_VERSION && r.version !== OWNER_NEXT_KEY_REF_VERSION) bad(`version ${String(r.version)}`);
  if (typeof r.keyId !== "string" || !KEY_ID.test(r.keyId)) bad("keyId must be 1..128 characters without control characters");
  if (r.scheme !== "ed25519") bad(`scheme must be ed25519 (owner keys held by a signer are Ed25519), got ${String(r.scheme)}`);
  if (typeof r.publicKey !== "string") bad("publicKey is missing");
  let publicKey: `0x${string}`;
  try { publicKey = parsePublicKey(r.publicKey as string); } catch (error) { return bad(error instanceof Error ? error.message : String(error)); }
  if (!suiteFor("ed25519").isCredential(publicKey)) bad("publicKey is not an Ed25519 public key");
  if (r.comment !== undefined && (typeof r.comment !== "string" || r.comment.length > 512)) bad("comment must be a string of at most 512 characters");
  const spec = r.signer;
  if (spec === null || typeof spec !== "object" || Array.isArray(spec)) return bad("signer must be a record with a kind");
  const kind = (spec as Record<string, unknown>).kind;
  if (typeof kind !== "string") return bad("signer.kind is missing");
  const backend = signerBackend(kind);
  if (backend === undefined) {
    throw new EngineError("KEY_UNAVAILABLE", `${where} names signer kind "${kind}", which this installation does not know (known: ${signerBackendKinds().join(", ")})`, { reason: "UNKNOWN_SIGNER", kind });
  }
  let signer: SignerSpec;
  try { signer = backend.parse(spec as Record<string, unknown>); } catch (error) { return bad(error instanceof Error ? error.message : String(error)); }
  return Object.freeze({
    version: r.version as KeyReferenceVersion, keyId: r.keyId as string, scheme: "ed25519" as const, publicKey, signer,
    ...(r.comment === undefined ? {} : { comment: r.comment as string }),
  });
}

/** Builds a reference record (checked like a loaded one). */
export function keyReference(input: Readonly<{ keyId: string; publicKey: string; signer: Readonly<Record<string, unknown>>; next?: boolean; comment?: string }>): OwnerKeyReference {
  return parseKeyReference({
    version: input.next === true ? OWNER_NEXT_KEY_REF_VERSION : OWNER_KEY_REF_VERSION, keyId: input.keyId, scheme: "ed25519", publicKey: input.publicKey, signer: input.signer,
    ...(input.comment === undefined ? {} : { comment: input.comment }),
  }, "the key reference");
}

/** The file text of a reference (pretty JSON, one trailing newline). */
export function keyReferenceText(reference: OwnerKeyReference): string {
  return `${JSON.stringify({
    version: reference.version, keyId: reference.keyId, scheme: reference.scheme, publicKey: reference.publicKey, signer: reference.signer,
    ...(reference.comment === undefined ? {} : { comment: reference.comment }),
  }, null, 2)}\n`;
}

/** The same reference under another version (owner ↔ next) and, optionally, key id. */
export function withReferenceVersion(reference: OwnerKeyReference, version: KeyReferenceVersion, keyId = reference.keyId): OwnerKeyReference {
  return Object.freeze({ ...reference, version, keyId });
}

const signerError = (error: unknown, keyId: string): EngineError => {
  if (error instanceof EngineError && (error.code === "KEY_UNAVAILABLE" || error.code === "SIGNER_FAILED")) return error;
  return new EngineError("SIGNER_FAILED", `the signer for owner key ${keyId} failed: ${error instanceof Error ? error.message : String(error)}`, { keyId, reason: "BACKEND_ERROR" });
};

/**
 * A `Signer` for a key reference. `signHash(hash, context)` asks the backend and verifies the answer against the
 * reference's public key before returning it; there is no `signHashSync`. KEY_UNAVAILABLE: the backend does not hold
 * the key; SIGNER_FAILED: anything else (unreachable, refused, timed out, a signature that does not verify).
 */
export function referenceSigner(reference: OwnerKeyReference, path?: string): Signer {
  const backend = signerBackend(reference.signer.kind);
  if (backend === undefined) throw new EngineError("KEY_UNAVAILABLE", `unknown signer kind ${reference.signer.kind}`, { reason: "UNKNOWN_SIGNER" });
  const suite = suiteFor("ed25519");
  const key: ReferencedKey = Object.freeze({ keyId: reference.keyId, scheme: "ed25519", publicKey: reference.publicKey, publicKeyBytes: new Uint8Array(Buffer.from(reference.publicKey.slice(2), "hex")) });
  const signHash = async (hash: ContentHash, context: SignContext = {}): Promise<HexSignature> => {
    if (!isContentHash(hash)) throw new EngineError("INVALID_INPUT", "signHash expects a lowercase 0x-prefixed 32-byte hash");
    let raw: Uint8Array;
    try { raw = await backend.sign(reference.signer, key, Buffer.from(hash.slice(2), "hex"), context); } catch (error) { throw signerError(error, reference.keyId); }
    const signature = `0x${Buffer.from(raw).toString("hex")}` as HexSignature;
    if (raw.length !== 64 || !suite.isSignature(signature) || !suite.verify(hash, signature, reference.publicKey)) {
      throw new EngineError("SIGNER_FAILED",
        `the ${backend.describe(reference.signer)} returned a signature that does not verify against owner key ${reference.keyId} (${reference.publicKey}); it was not used and nothing was written with it`,
        { keyId: reference.keyId, signer: reference.signer.kind, reason: "SIGNATURE_INVALID" });
    }
    return signature;
  };
  return Object.freeze({
    keyId: reference.keyId, scheme: "ed25519" as const, credential: reference.publicKey, signHash,
    custody: Object.freeze({
      holder: "reference" as const, signer: reference.signer.kind, description: backend.describe(reference.signer), identity: `${reference.signer.kind}:${backend.identity(reference.signer)}`,
      ...(path === undefined ? {} : { path }),
    }),
  });
}

/**
 * A `Signer` that knows only a public key (a next key committed with `--public-key`, whose private half never touches
 * this host). It can be committed to, never asked to sign: `signHash` fails with KEY_UNAVAILABLE.
 */
export function publicKeySigner(publicKey: string, keyId: string): Signer {
  const credential = parsePublicKey(publicKey);
  return Object.freeze({
    keyId, scheme: "ed25519" as const, credential,
    signHash: async (): Promise<HexSignature> => {
      throw new EngineError("KEY_UNAVAILABLE", `only the public key of ${keyId} (${credential}) is known here; its private half is held elsewhere (pass its key reference or next-key file to sign with it)`, { keyId, reason: "PUBLIC_KEY_ONLY" });
    },
    custody: Object.freeze({ holder: "public-key-only" as const, description: `public key only (${sshPublicKeyOf(credential)})` }),
  });
}
