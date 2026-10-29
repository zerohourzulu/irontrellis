/**
 * Signature suites (spec 04 §B–D; docs/reference/history-signatures.md §8.1).
 *
 * A suite turns "a ContentHash was signed by the holder of this credential"
 * into a boolean. The hash handed to `verify` is already the history's hash of
 * the signed structure (keccak-256 for format 0.2, sha256 for format 1); what
 * the suite does with it is scheme-specific:
 *
 *   eip191-personal-sign-keccak256  ECDSA/secp256k1 recovery over
 *                                   keccak256(0x19 ‖ "Ethereum Signed Message:\n32" ‖ hash),
 *                                   credential = Ethereum address (any case, compared lowercase),
 *                                   signature = 0x + 130 lowercase hex (r ‖ s ‖ v), low-s, v ∈ {1b, 1c}.
 *   ed25519                         node:crypto Ed25519 over the 32 raw hash bytes,
 *                                   credential = 0x + 64 hex raw public key,
 *                                   signature = 0x + 128 lowercase hex.
 *
 * Key generation and signing live here too so tests, the CLI and the local
 * owner share one `SignHash`-shaped signer.
 */

import { createPrivateKey, createPublicKey, generateKeyPairSync, createECDH, sign as nodeSign, verify as nodeVerify } from "node:crypto";
import type { KeyObject } from "node:crypto";
import type { ContentHash, HexSignature, SignatureScheme } from "../types.ts";
import { EngineError } from "../errors.ts";
import { keccak256 } from "./keccak.ts";
import { isCanonicalEncoding, scalarIsCanonical, verificationKeyAcceptable } from "./ed25519-point.ts";
import { activeSpeculation } from "./parallel-verify.ts";
import {
  SECP256K1_HALF_N,
  SECP256K1_N,
  addressFromPublicKey,
  bytesToHex,
  encodeCompactSignature,
  hexToBytes,
  isValidPrivateKey,
  publicKeyFromPrivateKey,
  recoverAddress,
  signDigest,
} from "./secp256k1.ts";

export interface SignatureSuite {
  readonly scheme: SignatureScheme;
  /** Strict syntax + numeric acceptance rules for a stored signature. */
  isSignature(value: unknown): value is HexSignature;
  /** Syntax of a credential as declared (case not yet normalised). */
  isCredential(value: unknown): value is string;
  /** The comparison form of a credential (lowercase). */
  normalizeCredential(credential: string): string;
  /** True iff `signature` was produced over `hash` by the holder of `credential`. Never throws. */
  verify(hash: ContentHash, signature: HexSignature, credential: string): boolean;
}

export type KeyPair = {
  keyId: string;
  scheme: SignatureScheme;
  /** Lowercase address (eip191) or 0x + 64 hex raw public key (ed25519). */
  credential: string;
  /** 0x + 64 hex: secp256k1 scalar or Ed25519 seed. */
  privateKey: string;
};

const CONTENT_HASH = /^0x[0-9a-f]{64}$/;
const SIGNATURE_65 = /^0x[0-9a-f]{130}$/;
const SIGNATURE_64 = /^0x[0-9a-f]{128}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const PUBLIC_KEY_32 = /^0x[0-9a-fA-F]{64}$/;
const PRIVATE_KEY_32 = /^0x[0-9a-fA-F]{64}$/;

export function isContentHash(value: unknown): value is ContentHash {
  return typeof value === "string" && CONTENT_HASH.test(value);
}

// ---------------------------------------------------------------- eip191-personal-sign-keccak256

const EIP191_PREFIX = new TextEncoder().encode("\x19Ethereum Signed Message:\n32");

/** keccak256(0x19 ‖ "Ethereum Signed Message:\n32" ‖ raw32(hash)); throws on a malformed hash. */
export function eip191Digest(hash: ContentHash): ContentHash {
  if (!isContentHash(hash)) throw new EngineError("INVALID_INPUT", "eip191Digest expects a lowercase 0x-prefixed 32-byte hash");
  return `0x${bytesToHex(eip191DigestBytes(hash))}`;
}

function eip191DigestBytes(hash: ContentHash): Uint8Array {
  const preimage = new Uint8Array(EIP191_PREFIX.length + 32);
  preimage.set(EIP191_PREFIX, 0);
  preimage.set(hexToBytes(hash), EIP191_PREFIX.length);
  return keccak256(preimage);
}

/** Exactly the legacy `isSignature65`: lowercase 130 hex, 0 < r < n, 0 < s ≤ (n−1)/2, v ∈ {1b, 1c}. */
function isSignature65(value: unknown): value is HexSignature {
  if (typeof value !== "string" || !SIGNATURE_65.test(value)) return false;
  const r = BigInt(`0x${value.slice(2, 66)}`);
  const s = BigInt(`0x${value.slice(66, 130)}`);
  const v = value.slice(130, 132);
  return r > 0n && r < SECP256K1_N && s > 0n && s <= SECP256K1_HALF_N && (v === "1b" || v === "1c");
}

/** Lowercase signer address of `signature` over `hash`, or undefined (legacy `recoverPortableContentHashSigner`). */
export function recoverContentHashSigner(hash: unknown, signature: unknown): string | undefined {
  if (!isContentHash(hash) || !isSignature65(signature)) return undefined;
  try {
    return recoverAddress(eip191DigestBytes(hash), hexToBytes(signature));
  } catch {
    return undefined;
  }
}

const EIP191_SUITE: SignatureSuite = {
  scheme: "eip191-personal-sign-keccak256",
  isSignature: isSignature65,
  isCredential: (value): value is string => typeof value === "string" && ADDRESS.test(value),
  normalizeCredential: (credential) => credential.toLowerCase(),
  verify(hash, signature, credential) {
    if (!ADDRESS.test(credential)) return false;
    const signer = recoverContentHashSigner(hash, signature);
    return signer !== undefined && signer === credential.toLowerCase();
  },
};

// ---------------------------------------------------------------- ed25519

// DER wrappers node:crypto needs around a raw 32-byte Ed25519 key.
const ED25519_PKCS8_PREFIX = hexToBytes("302e020100300506032b657004220420");
const ED25519_SPKI_PREFIX = hexToBytes("302a300506032b6570032100");

function ed25519PublicKeyObject(publicKey32: Uint8Array): KeyObject {
  const der = new Uint8Array(ED25519_SPKI_PREFIX.length + 32);
  der.set(ED25519_SPKI_PREFIX, 0);
  der.set(publicKey32, ED25519_SPKI_PREFIX.length);
  return createPublicKey({ key: Buffer.from(der), format: "der", type: "spki" });
}

function ed25519PrivateKeyObject(seed32: Uint8Array): KeyObject {
  const der = new Uint8Array(ED25519_PKCS8_PREFIX.length + 32);
  der.set(ED25519_PKCS8_PREFIX, 0);
  der.set(seed32, ED25519_PKCS8_PREFIX.length);
  return createPrivateKey({ key: Buffer.from(der), format: "der", type: "pkcs8" });
}

/** Raw 32-byte public key of a KeyObject (public or private), via JWK `x`. */
function ed25519RawPublicKey(key: KeyObject): Uint8Array {
  const jwk = createPublicKey(key).export({ format: "jwk" });
  if (typeof jwk.x !== "string") throw new EngineError("KEY_UNAVAILABLE", "Ed25519 public key export failed");
  return new Uint8Array(Buffer.from(jwk.x, "base64url"));
}

/**
 * Imported public keys, keyed by normalised credential. A history verifies the
 * same few owner/runtime keys thousands of times; importing the SPKI each call
 * costs ~10 µs on top of OpenSSL's ~120 µs verify. `null` remembers a credential
 * that is not a valid point so we do not re-import (and re-throw) for it.
 * Bounded LRU: on a hit the entry moves to the back, the front is evicted.
 */
const ED25519_KEY_CACHE_LIMIT = 4096;
const ed25519KeyCache = new Map<string, KeyObject | null>();

function cachedEd25519PublicKey(credential: string): KeyObject | null {
  const id = credential.toLowerCase();
  const hit = ed25519KeyCache.get(id);
  if (hit !== undefined) {
    ed25519KeyCache.delete(id);
    ed25519KeyCache.set(id, hit);
    return hit;
  }
  let key: KeyObject | null;
  try {
    key = ed25519PublicKeyObject(hexToBytes(id));
  } catch {
    // An arbitrary 32-byte string is not always a valid point; node throws, we say "no".
    key = null;
  }
  if (ed25519KeyCache.size >= ED25519_KEY_CACHE_LIMIT) {
    const oldest = ed25519KeyCache.keys().next().value;
    if (oldest !== undefined) ed25519KeyCache.delete(oldest);
  }
  ed25519KeyCache.set(id, key);
  return key;
}

const ED25519_SUITE: SignatureSuite = {
  scheme: "ed25519",
  isSignature: (value): value is HexSignature => typeof value === "string" && SIGNATURE_64.test(value),
  isCredential: (value): value is string => typeof value === "string" && PUBLIC_KEY_32.test(value),
  normalizeCredential: (credential) => credential.toLowerCase(),
  verify(hash, signature, credential) {
    if (!isContentHash(hash) || !SIGNATURE_64.test(signature) || !PUBLIC_KEY_32.test(credential)) return false;
    // A-32.1 pre-checks, performed by the engine before the library call: S < L, canonical R, canonical A not of small
    // order. The equation itself is OpenSSL's cofactorless ref10 check (encoded comparison of [S]B − [k]A with R), which
    // the A-32 test vectors pin (a signature only a cofactored verifier accepts is refused).
    const raw = hexToBytes(signature);
    if (!scalarIsCanonical(raw.subarray(32)) || !isCanonicalEncoding(raw.subarray(0, 32)) || !verificationKeyAcceptable(hexToBytes(credential.toLowerCase()))) return false;
    const key = cachedEd25519PublicKey(credential);
    if (key === null) return false;
    // Inside a speculative replay (parallel-verify.ts) the OpenSSL call runs on the verification pool; the answer is used
    // only if every queued verification succeeds, otherwise the replay is redone sequentially.
    const speculation = activeSpeculation();
    if (speculation !== undefined) {
      try {
        return speculation.defer(hexToBytes(hash), hexToBytes(signature), hexToBytes(credential), key);
      } catch {
        // Could not queue it (e.g. no memory for a batch): verify it here, a real answer is always acceptable.
      }
    }
    try {
      return nodeVerify(null, hexToBytes(hash), key, hexToBytes(signature));
    } catch {
      return false;
    }
  },
};

// ---------------------------------------------------------------- registry, keys, signing

export function suiteFor(scheme: SignatureScheme): SignatureSuite {
  if (scheme === "eip191-personal-sign-keccak256") return EIP191_SUITE;
  if (scheme === "ed25519") return ED25519_SUITE;
  throw new EngineError("UNSUPPORTED_VERSION", `unsupported signature scheme: ${String(scheme)}`);
}

/**
 * Builds a key pair from a 0x-prefixed 32-byte private key (scalar for
 * secp256k1, seed for Ed25519). Credentials come out in their normalised
 * (lowercase) form.
 */
export function keyPairFromPrivateKey(scheme: SignatureScheme, keyId: string, privateKeyHex: string): KeyPair {
  if (!PRIVATE_KEY_32.test(privateKeyHex)) throw new EngineError("INVALID_INPUT", "private key must be 0x + 64 hex");
  const privateKey = `0x${privateKeyHex.slice(2).toLowerCase()}`;
  if (scheme === "eip191-personal-sign-keccak256") {
    const scalar = BigInt(privateKey);
    if (!isValidPrivateKey(scalar)) throw new EngineError("INVALID_INPUT", "secp256k1 private key out of range");
    const credential = addressFromPublicKey(publicKeyFromPrivateKey(scalar));
    return { keyId, scheme, credential, privateKey };
  }
  if (scheme === "ed25519") {
    const publicKey = ed25519RawPublicKey(ed25519PrivateKeyObject(hexToBytes(privateKey)));
    return { keyId, scheme, credential: `0x${bytesToHex(publicKey)}`, privateKey };
  }
  throw new EngineError("UNSUPPORTED_VERSION", `unsupported signature scheme: ${String(scheme)}`);
}

/** Fresh key material from node:crypto (ECDH keygen for secp256k1, Ed25519 keygen). Dev/test/local-owner use. */
export function generateKeyPair(scheme: SignatureScheme, keyId: string): KeyPair {
  if (scheme === "eip191-personal-sign-keccak256") {
    const ecdh = createECDH("secp256k1");
    ecdh.generateKeys();
    return keyPairFromPrivateKey(scheme, keyId, `0x${bytesToHex(new Uint8Array(ecdh.getPrivateKey())).padStart(64, "0")}`);
  }
  if (scheme === "ed25519") {
    const { privateKey } = generateKeyPairSync("ed25519");
    const jwk = privateKey.export({ format: "jwk" });
    if (typeof jwk.d !== "string") throw new EngineError("KEY_UNAVAILABLE", "Ed25519 key export failed");
    return keyPairFromPrivateKey(scheme, keyId, `0x${bytesToHex(new Uint8Array(Buffer.from(jwk.d, "base64url")))}`);
  }
  throw new EngineError("UNSUPPORTED_VERSION", `unsupported signature scheme: ${String(scheme)}`);
}

/**
 * The application `SignHash` contract for a key pair: EIP-191 personal-sign of
 * the 32 raw hash bytes (deterministic RFC 6979, low-s, v ∈ {1b, 1c}) or Ed25519
 * over the raw bytes. Output is lowercase hex and passes the suite's `isSignature`.
 */
export function signHashWith(keyPair: KeyPair): (hash: ContentHash) => Promise<HexSignature> {
  if (keyPair.scheme === "eip191-personal-sign-keccak256") {
    const scalar = BigInt(keyPair.privateKey);
    if (!isValidPrivateKey(scalar)) throw new EngineError("INVALID_INPUT", "secp256k1 private key out of range");
    return async (hash) => {
      if (!isContentHash(hash)) throw new EngineError("INVALID_INPUT", "signHash expects a lowercase 0x-prefixed 32-byte hash");
      return `0x${bytesToHex(encodeCompactSignature(signDigest(eip191DigestBytes(hash), scalar)))}`;
    };
  }
  if (keyPair.scheme === "ed25519") {
    const key = ed25519PrivateKeyObject(hexToBytes(keyPair.privateKey));
    return async (hash) => {
      if (!isContentHash(hash)) throw new EngineError("INVALID_INPUT", "signHash expects a lowercase 0x-prefixed 32-byte hash");
      return `0x${bytesToHex(new Uint8Array(nodeSign(null, hexToBytes(hash), key)))}`;
    };
  }
  throw new EngineError("UNSUPPORTED_VERSION", `unsupported signature scheme: ${String(keyPair.scheme)}`);
}
