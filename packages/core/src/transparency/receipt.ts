/**
 * Witness receipts (docs/reference/witness-protocol.md §9.5): an entry, its leaf index, a signed
 * checkpoint of a tree that contains it and the inclusion proof. A receipt is
 * self-contained; verifying it needs only the witness's trusted verifier key.
 */
import { decodeBase64, encodeBase64 } from "./base64.ts";
import { entryLeafHash, validateEntry, type WitnessEntry } from "./entry.ts";
import { verifyInclusion } from "./merkle.ts";
import { NoteError, openNote, parseCheckpoint } from "./note.ts";

export const WITNESS_RECEIPT_VERSION = "irontrellis-witness-receipt/1";

export type WitnessReceipt = Readonly<{
  version: typeof WITNESS_RECEIPT_VERSION;
  witness: Readonly<{ origin: string; verifierKey: string }>;
  entry: WitnessEntry;
  index: number;
  /** Signed note text of a checkpoint whose size is greater than `index`. */
  checkpoint: string;
  /** Base64 audit path, leaf to root (RFC 9162 §2.1.3.1). */
  inclusionProof: string[];
}>;

export type WitnessReceiptFailure =
  | "RECEIPT_MALFORMED" | "NOTE_UNVERIFIED" | "CHECKPOINT_MALFORMED" | "ORIGIN_MISMATCH" | "ENTRY_MALFORMED" | "INDEX_OUT_OF_RANGE" | "INCLUSION_INVALID";

export type WitnessReceiptVerification =
  | Readonly<{ ok: true; checkpoint: Readonly<{ origin: string; size: number; root: Uint8Array }>; index: number; verifiedBy: string[] }>
  | Readonly<{ ok: false; reason: WitnessReceiptFailure; message: string }>;

const isRecord = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const fail = (reason: WitnessReceiptFailure, message: string): WitnessReceiptVerification => Object.freeze({ ok: false, reason, message });

/** Assembles a receipt (the witness server's side). */
export function buildReceipt(input: Readonly<{ origin: string; verifierKey: string; entry: WitnessEntry; index: number; checkpoint: string; inclusionProof: readonly Uint8Array[] }>): WitnessReceipt {
  return Object.freeze({
    version: WITNESS_RECEIPT_VERSION,
    witness: Object.freeze({ origin: input.origin, verifierKey: input.verifierKey }),
    entry: input.entry,
    index: input.index,
    checkpoint: input.checkpoint,
    inclusionProof: Object.freeze(input.inclusionProof.map(encodeBase64)) as string[],
  });
}

/**
 * Verifies a receipt: opens the checkpoint note with `trustedVerifierKeys`
 * (never the key the receipt names), parses the checkpoint, checks the origin
 * against `receipt.witness.origin`, validates the entry, recomputes its leaf
 * hash and verifies the inclusion proof. Never throws.
 */
export function verifyWitnessReceipt(receipt: unknown, trustedVerifierKeys: readonly string[]): WitnessReceiptVerification {
  if (!isRecord(receipt) || receipt.version !== WITNESS_RECEIPT_VERSION || !isRecord(receipt.witness) || typeof receipt.witness.origin !== "string" ||
    typeof receipt.witness.verifierKey !== "string" || typeof receipt.checkpoint !== "string" || !Array.isArray(receipt.inclusionProof) || !Number.isSafeInteger(receipt.index) || (receipt.index as number) < 0) {
    return fail("RECEIPT_MALFORMED", "receipt must be {version, witness: {origin, verifierKey}, entry, index, checkpoint, inclusionProof}");
  }
  let body: string;
  let verifiedBy: string[];
  try {
    ({ body, verifiedBy } = openNote(receipt.checkpoint, trustedVerifierKeys));
  } catch (error) {
    return fail("NOTE_UNVERIFIED", error instanceof NoteError ? `${error.code}: ${error.message}` : String(error));
  }
  let checkpoint: ReturnType<typeof parseCheckpoint>;
  try {
    checkpoint = parseCheckpoint(body);
  } catch (error) {
    return fail("CHECKPOINT_MALFORMED", error instanceof Error ? error.message : String(error));
  }
  if (checkpoint.origin !== receipt.witness.origin) return fail("ORIGIN_MISMATCH", `checkpoint origin ${JSON.stringify(checkpoint.origin)} is not the receipt's witness origin`);
  const entryProblem = validateEntry(receipt.entry);
  if (entryProblem !== null) return fail("ENTRY_MALFORMED", entryProblem);
  const index = receipt.index as number;
  if (index >= checkpoint.size) return fail("INDEX_OUT_OF_RANGE", `leaf index ${index} is not below the checkpoint size ${checkpoint.size}`);
  const proof: Uint8Array[] = [];
  for (const element of receipt.inclusionProof) {
    const bytes = decodeBase64(element);
    if (bytes === undefined || bytes.length !== 32) return fail("INCLUSION_INVALID", "inclusion proof elements are base64 32-byte hashes");
    proof.push(bytes);
  }
  let leaf: Uint8Array;
  try {
    leaf = entryLeafHash(receipt.entry as WitnessEntry);
  } catch (error) {
    return fail("ENTRY_MALFORMED", error instanceof Error ? error.message : String(error));
  }
  if (!verifyInclusion(leaf, index, checkpoint.size, proof, checkpoint.root)) return fail("INCLUSION_INVALID", "the inclusion proof does not lead to the checkpoint root");
  return Object.freeze({ ok: true, checkpoint: Object.freeze({ origin: checkpoint.origin, size: checkpoint.size, root: checkpoint.root }), index, verifiedBy });
}
