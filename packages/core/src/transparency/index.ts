/**
 * `@ramex-labs/irontrellis/transparency`: the witness wire formats
 * (docs/WITNESS.md §9) shared by the witness server and the witness client —
 * RFC 6962 Merkle trees and proofs, C2SP signed notes and checkpoints,
 * owner-signed head statements, witness log entries and receipts.
 */
export { MERKLE_HASH_SIZE, emptyRoot, leafHash, nodeHash, rootOf, MerkleTree, verifyInclusion, verifyConsistency } from "./merkle.ts";
export {
  ALG_ED25519, MAX_NOTE_SIGNATURES, NoteError, isValidNoteKeyName, noteKeyHash, verifierKey, parseVerifierKey, noteSignerFromSeed, noteSignerFromKeyObject,
  parseSignerKey, formatSignerKey, generateNoteKey, signNote, openNote, formatCheckpoint, parseCheckpoint,
} from "./note.ts";
export type { NoteSigner, NoteErrorCode, ParsedVerifierKey, OpenedNote, Checkpoint } from "./note.ts";
export {
  HEAD_STATEMENT_VERSION, validateHeadStatement, headStatementHash, signHeadStatement, signHeadStatementSync, validateSignedHeadStatement, verifySignedHeadStatement,
} from "./statement.ts";
export type { HeadStatement, SignedHeadStatement, StatementHead, StatementPrevious, SignedHeadStatementVerification } from "./statement.ts";
export { WITNESS_ENTRY_VERSION, WITNESS_ENTRY_KINDS, encodeEntry, entryLeafHash, validateEntry } from "./entry.ts";
export type { WitnessEntry, WitnessEntryKind, RegisteredEntry, HeadEntry, RotatedEntry, EquivocationEntry, SupersededEntry } from "./entry.ts";
export { KEY_EVENT_BUNDLE_VERSION, validateKeyEventBundle, keyEventBundlePathFor } from "./bundle.ts";
export type { KeyEventBundle } from "./bundle.ts";
export { WITNESS_RECEIPT_VERSION, buildReceipt, verifyWitnessReceipt } from "./receipt.ts";
export type { WitnessReceipt, WitnessReceiptFailure, WitnessReceiptVerification } from "./receipt.ts";
export { encodeBase64, decodeBase64 } from "./base64.ts";
export { LATEST_NOTE_VERSION, MIN_NONCE_BYTES, MAX_NONCE_BYTES, isValidNonce, newNonce, formatLatestNote, parseLatestNote, verifyLatestNote } from "./latest.ts";
export type { LatestNote, LatestNoteExpectation, LatestNoteFailure, LatestNoteVerification } from "./latest.ts";
