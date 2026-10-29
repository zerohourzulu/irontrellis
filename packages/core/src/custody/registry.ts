/**
 * Owner-key custody: the registry of signer backends a key reference can name
 * (docs/CUSTODY.md). A reference file (`irontrellis-owner-key-ref/1`) holds no
 * secret: it names the key (its Ed25519 public key) and the backend that holds
 * it (`signer.kind`). The backend is asked for a signature over the 32-byte
 * hash IronTrellis signs; `referenceSigner` (reference.ts) verifies every
 * signature locally against the pinned public key before it is used.
 *
 * Adding a backend (`vault-transit` is built this way): implement
 * `SignerBackend` in `custody/<kind>.ts` and add it to `BUILT_IN` below, or call
 * `registerSignerBackend` from host code before loading a reference that names
 * it. `parse` validates the reference's `signer` record (no I/O), `sign`
 * returns the raw 64-byte signature and throws `EngineError` KEY_UNAVAILABLE
 * (the backend does not hold the key) or SIGNER_FAILED (anything else).
 */
import { EngineError } from "../errors.ts";
import type { ContentHash } from "../types.ts";
import { COMMAND_BACKEND } from "./command.ts";
import { SSH_AGENT_BACKEND } from "./ssh-agent.ts";
import { VAULT_TRANSIT_BACKEND } from "./vault-transit.ts";

/** Why a signature is asked for (advisory: a backend may log it; it is not authenticated). */
export type SignPurpose =
  | "control-authorization" | "head-attestation" | "head-statement" | "next-key-proof" | "rotation-seal" | "cache-seal" | "signer-test";
export const SIGN_PURPOSES: readonly SignPurpose[] = Object.freeze([
  "control-authorization", "head-attestation", "head-statement", "next-key-proof", "rotation-seal", "cache-seal", "signer-test",
]);
/** What a caller tells the signer about a signature (optional, advisory). */
export type SignContext = Readonly<{ purpose?: SignPurpose; historyId?: ContentHash }>;

/** The key a backend is asked to use: the reference's key id and its Ed25519 public key. */
export type ReferencedKey = Readonly<{ keyId: string; scheme: "ed25519"; publicKey: `0x${string}`; publicKeyBytes: Uint8Array }>;

/** A backend's normalized `signer` record: plain JSON data, `kind` first. */
export type SignerSpec = Readonly<{ kind: string } & Readonly<Record<string, unknown>>>;

export type SignerBackend = Readonly<{
  kind: string;
  /** Checks and normalizes the reference's `signer` record; throws `Error` with a plain message on a defect. No I/O. */
  parse(spec: Readonly<Record<string, unknown>>): SignerSpec;
  /** One line for `owner status`, `signer test` and doctor, e.g. `ssh-agent at /run/user/1000/ssh.sock`. */
  describe(spec: SignerSpec): string;
  /**
   * What identifies the holder, for "are the current and the next key in the same signer?" (`NEXT_KEY_SAME_SIGNER`):
   * two references with the same kind and identity reach the same key store.
   */
  identity(spec: SignerSpec): string;
  /** A signature over `message` (the 32 bytes of the hash) with `key`: the raw 64-byte Ed25519 signature. */
  sign(spec: SignerSpec, key: ReferencedKey, message: Uint8Array, context: SignContext): Promise<Uint8Array>;
}>;

const BUILT_IN: readonly SignerBackend[] = Object.freeze([SSH_AGENT_BACKEND, COMMAND_BACKEND, VAULT_TRANSIT_BACKEND]);
const backends = new Map<string, SignerBackend>(BUILT_IN.map((backend) => [backend.kind, backend]));

/** The backend registered for `kind`, or `undefined`. */
export function signerBackend(kind: string): SignerBackend | undefined {
  return backends.get(kind);
}
/** Every registered backend kind (built-in first). */
export function signerBackendKinds(): readonly string[] {
  return Object.freeze([...backends.keys()]);
}
/**
 * Registers a backend for references whose `signer.kind` is `backend.kind` (host configuration; call it before loading
 * such a reference). A built-in kind cannot be replaced; registering another kind twice replaces it.
 */
export function registerSignerBackend(backend: SignerBackend): void {
  if (backend === null || typeof backend !== "object" || typeof backend.kind !== "string" || !/^[a-z][a-z0-9-]{0,31}$/.test(backend.kind) ||
      typeof backend.parse !== "function" || typeof backend.sign !== "function" || typeof backend.describe !== "function" || typeof backend.identity !== "function") {
    throw new EngineError("INVALID_INPUT", "registerSignerBackend expects { kind (lowercase, a-z0-9-), parse, describe, identity, sign }");
  }
  if (BUILT_IN.some((builtIn) => builtIn.kind === backend.kind)) throw new EngineError("INVALID_INPUT", `signer backend ${backend.kind} is built in and cannot be replaced`);
  backends.set(backend.kind, Object.freeze({ ...backend }));
}
