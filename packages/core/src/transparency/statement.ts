/**
 * Owner-signed head statements (docs/reference/witness-protocol.md §9.1): "the head of history
 * `historyId` is `head`, and it extends `previous`, the witness's latest head".
 * The owner key signs `hashCanonical(statement, "sha256")` exactly as it signs
 * a head attestation (the suite verifies over the 32 raw hash bytes). Only
 * format-1 (`irontrellis-event/1`) histories are witnessed, so the domain is
 * always a `TrellisDomain` and the hash is always SHA-256.
 */
import { isIdentifier, isU53 } from "../canonical.ts";
import { isContentHash, suiteFor } from "../crypto/suites.ts";
import { EngineError } from "../errors.ts";
import { SIGNATURE_SCHEMES } from "../events.ts";
import { hashCanonical } from "../hash.ts";
import type { Signer } from "../signer.ts";
import type { ContentHash, HexSignature, OwnerKey, SignatureScheme, TrellisDomain, U53 } from "../types.ts";

export const HEAD_STATEMENT_VERSION = "irontrellis-head-statement/1";

export type StatementHead = Readonly<{ hash: ContentHash; position: U53; canonicalTime: U53 }>;
export type StatementPrevious = Readonly<{ hash: ContentHash; position: U53 }>;
export type HeadStatement = Readonly<{
  version: typeof HEAD_STATEMENT_VERSION;
  historyId: ContentHash;
  domain: TrellisDomain;
  head: StatementHead;
  previous: StatementPrevious | null;
}>;
export type SignedHeadStatement = Readonly<{ statement: HeadStatement; keyId: string; scheme: SignatureScheme; signature: HexSignature }>;
export type SignedHeadStatementVerification =
  | Readonly<{ ok: true }>
  | Readonly<{ ok: false; reason: "MALFORMED" | "UNKNOWN_KEY" | "SIGNATURE_INVALID" }>;

const isRecord = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const hasExactKeys = (value: Record<string, unknown>, keys: readonly string[]): boolean => {
  const own = Object.keys(value);
  return own.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
};

const isTrellisDomain = (value: unknown): value is TrellisDomain =>
  // Format 1 and format 2 domains (G0 Q3: head statements stay `/1` on the wire and accept a `version: "2"` domain).
  isRecord(value) && hasExactKeys(value, ["protocol", "version", "deploymentId"]) && value.protocol === "irontrellis" && (value.version === "1" || value.version === "2") && isIdentifier(value.deploymentId);

/**
 * `null` when `statement` is a well-formed head statement, else a short
 * reason. Checks: exact field sets, `version`, content hashes, U53 positions
 * and time, a format-1 domain, and the chaining rule: `previous` is null or
 * `previous.position <= head.position`, and at equal positions the hashes are
 * equal (a re-submission of the same head).
 */
export function validateHeadStatement(statement: unknown): string | null {
  if (!isRecord(statement) || !hasExactKeys(statement, ["version", "historyId", "domain", "head", "previous"])) return "statement must have exactly version, historyId, domain, head, previous";
  const { version, historyId, domain, head, previous } = statement;
  if (version !== HEAD_STATEMENT_VERSION) return `version must be ${HEAD_STATEMENT_VERSION}`;
  if (!isContentHash(historyId)) return "historyId must be a lowercase 0x-prefixed sha256 hash";
  if (!isTrellisDomain(domain)) return "domain must be an irontrellis/1 domain";
  if (!isRecord(head) || !hasExactKeys(head, ["hash", "position", "canonicalTime"]) || !isContentHash(head.hash) || !isU53(head.position) || !isU53(head.canonicalTime)) {
    return "head must be {hash, position, canonicalTime}";
  }
  if (head.position === 0 && head.hash !== historyId) return "the head at position 0 must be the history id";
  if (previous === null) return null;
  if (!isRecord(previous) || !hasExactKeys(previous, ["hash", "position"]) || !isContentHash(previous.hash) || !isU53(previous.position)) {
    return "previous must be null or {hash, position}";
  }
  if (previous.position > head.position) return "previous.position must not exceed head.position";
  if (previous.position === head.position && previous.hash !== head.hash) return "previous and head at the same position must have the same hash";
  if (previous.position === 0 && previous.hash !== historyId) return "previous at position 0 must be the history id";
  return null;
}

/** A detached copy with exactly the statement fields (what is hashed and signed). */
const project = (statement: HeadStatement): HeadStatement => Object.freeze({
  version: HEAD_STATEMENT_VERSION,
  historyId: statement.historyId,
  domain: Object.freeze({ protocol: statement.domain.protocol, version: statement.domain.version, deploymentId: statement.domain.deploymentId }),
  head: Object.freeze({ hash: statement.head.hash, position: statement.head.position, canonicalTime: statement.head.canonicalTime }),
  previous: statement.previous === null ? null : Object.freeze({ hash: statement.previous.hash, position: statement.previous.position }),
});

/** The hash an owner key signs: `hashCanonical(statement, "sha256")`. Throws `EngineError("INVALID_INPUT")` on a malformed statement. */
export function headStatementHash(statement: HeadStatement): ContentHash {
  const reason = validateHeadStatement(statement);
  if (reason !== null) throw new EngineError("INVALID_INPUT", `invalid head statement: ${reason}`);
  return hashCanonical(project(statement), "sha256");
}

const signed = (signer: Signer, statement: HeadStatement, signature: HexSignature): SignedHeadStatement =>
  Object.freeze({ statement: project(statement), keyId: signer.keyId, scheme: signer.scheme, signature });

/** Signs a head statement with an owner `Signer` (the same mechanism as `attestHead`). */
export async function signHeadStatement(signer: Signer, statement: HeadStatement): Promise<SignedHeadStatement> {
  const hash = headStatementHash(statement);
  return signed(signer, statement, await signer.signHash(hash, { purpose: "head-statement", historyId: statement.historyId }));
}

/** Synchronous variant; `undefined` when the signer cannot sign synchronously. */
export function signHeadStatementSync(signer: Signer, statement: HeadStatement): SignedHeadStatement | undefined {
  if (signer.signHashSync === undefined) return undefined;
  const hash = headStatementHash(statement);
  return signed(signer, statement, signer.signHashSync(hash));
}

/** `null` when `signed` has the shape `{statement, keyId, scheme, signature}` with a valid statement; else a reason. Does not check the signature. */
export function validateSignedHeadStatement(signed: unknown): string | null {
  if (!isRecord(signed) || !hasExactKeys(signed, ["statement", "keyId", "scheme", "signature"])) return "signed statement must have exactly statement, keyId, scheme, signature";
  const reason = validateHeadStatement(signed.statement);
  if (reason !== null) return reason;
  if (!isIdentifier(signed.keyId)) return "keyId must be an identifier";
  if (!(SIGNATURE_SCHEMES as readonly unknown[]).includes(signed.scheme)) return "unknown signature scheme";
  if (!suiteFor(signed.scheme as SignatureScheme).isSignature(signed.signature)) return "malformed signature";
  return null;
}

/**
 * Verifies a signed head statement against the owner keys valid at the
 * statement's head position (`ownerKeysAt(head.position)`; the engine's
 * key-epoch helper, or a witness's view of the rotations it received).
 * Never throws: a throwing `ownerKeysAt` counts as `UNKNOWN_KEY`.
 */
export function verifySignedHeadStatement(signed: unknown, ownerKeysAt: (position: number) => readonly OwnerKey[]): SignedHeadStatementVerification {
  if (validateSignedHeadStatement(signed) !== null) return Object.freeze({ ok: false, reason: "MALFORMED" });
  const value = signed as SignedHeadStatement;
  let keys: readonly OwnerKey[];
  try {
    keys = ownerKeysAt(value.statement.head.position);
  } catch {
    return Object.freeze({ ok: false, reason: "UNKNOWN_KEY" });
  }
  const key = Array.isArray(keys) ? keys.find((candidate) => candidate?.keyId === value.keyId && candidate.scheme === value.scheme) : undefined;
  if (key === undefined) return Object.freeze({ ok: false, reason: "UNKNOWN_KEY" });
  try {
    const suite = suiteFor(key.scheme);
    if (suite.verify(headStatementHash(value.statement), value.signature, suite.normalizeCredential(key.credential))) return Object.freeze({ ok: true });
  } catch {
    // fall through
  }
  return Object.freeze({ ok: false, reason: "SIGNATURE_INVALID" });
}
