/**
 * Witness log entries (docs/reference/witness-protocol.md §9.3). Each Merkle leaf is the canonical
 * encoding of one entry; `leafHash = SHA-256(0x00 || utf8(canonicalEncode(entry)))`.
 * Entries travel as plain JSON: a bigint anywhere inside (none occur in the
 * events the witness records today) is written as the canonical
 * `{"$continuity.bigint":"…"}` marker, which encodes to the same canonical
 * text as the bigint itself, so the leaf hash survives the round trip.
 */
import { canonicalEncode, isU53 } from "../canonical.ts";
import { isContentHash } from "../crypto/suites.ts";
import { historyIdOfGenesis } from "../hash.ts";
import type { ContentHash, U53 } from "../types.ts";
import { leafHash } from "./merkle.ts";
import { validateSignedHeadStatement, type SignedHeadStatement } from "./statement.ts";

export const WITNESS_ENTRY_VERSION = "irontrellis-witness-entry/1";
export const WITNESS_ENTRY_KINDS = Object.freeze(["REGISTERED", "HEAD", "ROTATED", "EQUIVOCATION", "SUPERSEDED"] as const);

type EntryBase = Readonly<{ version: typeof WITNESS_ENTRY_VERSION; historyId: ContentHash; receivedAt: U53 }>;
export type RegisteredEntry = EntryBase & Readonly<{ kind: "REGISTERED"; genesis: unknown }>;
export type HeadEntry = EntryBase & Readonly<{ kind: "HEAD"; signedStatement: SignedHeadStatement }>;
/** `previousHead` is the head the rotation's controlAuthorization signs (the head before it); `rotationHead` the head ending with it (docs/reference/witness-protocol.md §9.3). */
export type RotatedEntry = EntryBase & Readonly<{ kind: "ROTATED"; rotation: unknown; previousHead: Readonly<{ hash: ContentHash; position: U53 }>; rotationHead: Readonly<{ hash: ContentHash; position: U53 }> }>;
export type EquivocationEntry = EntryBase & Readonly<{ kind: "EQUIVOCATION"; first: SignedHeadStatement; second: SignedHeadStatement }>;
type HeadRef = Readonly<{ hash: ContentHash; position: U53 }>;
/**
 * A pre-rotated rotation overrode the heads the witness held after `chain.statement.previous` (the last good head L,
 * whose HEAD entry is leaf `supersededFromIndex`), docs/reference/witness-operations.md §7.4. The entry describes the superseded RANGE, not
 * each head, so its size does not depend on how many heads a thief pushed: every HEAD entry of this
 * history with a leaf index in (`supersededFromIndex`, `supersededToIndex`) is superseded, `supersededToIndex` being
 * the log size when the supersede was decided (the leaf index of this entry). `supersededLatest` is the head that was
 * the witness's latest and `supersededCount` how many heads it held after L. The superseded heads stay in the log as
 * evidence; the witness's latest head is reset to L, and the HEAD entry for `rotationHead` (the `chain` statement) and
 * the ROTATED entry follow.
 */
export type SupersededEntry = EntryBase & Readonly<{
  kind: "SUPERSEDED"; rotation: unknown; previousHead: HeadRef; rotationHead: HeadRef; chain: SignedHeadStatement;
  supersededFromIndex: U53; supersededToIndex: U53; supersededLatest: Readonly<{ position: U53; hash: ContentHash; index: U53 }>; supersededCount: U53;
}>;
export type WitnessEntry = RegisteredEntry | HeadEntry | RotatedEntry | EquivocationEntry | SupersededEntry;
export type WitnessEntryKind = WitnessEntry["kind"];

const UTF8 = new TextEncoder();
const isRecord = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const hasExactKeys = (value: Record<string, unknown>, keys: readonly string[]): boolean => {
  const own = Object.keys(value);
  return own.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
};

/** The canonical bytes of an entry (the Merkle leaf data). Throws CanonicalError for values the canonical form rejects. */
export function encodeEntry(entry: WitnessEntry): Uint8Array {
  return UTF8.encode(canonicalEncode(entry));
}

/** RFC 6962 leaf hash of the entry's canonical bytes. */
export function entryLeafHash(entry: WitnessEntry): Uint8Array {
  return leafHash(encodeEntry(entry));
}


/** `previousHead` and `rotationHead` are `{hash, position}` and the rotation head directly follows the previous one. */
const headRefsFailure = (entry: Record<string, unknown>): string | null => {
  for (const side of ["previousHead", "rotationHead"]) {
    const head = entry[side];
    if (!isRecord(head) || !hasExactKeys(head, ["hash", "position"]) || !isContentHash(head.hash) || !isU53(head.position)) return `${side} must be {hash, position}`;
  }
  if ((entry.rotationHead as { position: number }).position !== (entry.previousHead as { position: number }).position + 1) return "rotationHead.position must be previousHead.position + 1";
  return null;
};

/**
 * `null` when `entry` is a structurally valid witness entry, else a reason.
 * Checks the exact field set per kind, the version, `historyId`, `receivedAt`
 * (U53) and that the entry is canonically encodable; REGISTERED: `historyId`
 * is the position-0 prefix hash of `genesis`; HEAD: a well-formed signed
 * statement for the same history; ROTATED: an `OWNER_KEYS_ROTATED` event
 * record, `previousHead` and `rotationHead` with
 * `rotationHead.position === previousHead.position + 1`; EQUIVOCATION: two well-formed signed statements
 * for the same history and head position with different head hashes; SUPERSEDED:
 * a ROTATED-like rotation, `previousHead`, `rotationHead`, a well-formed `chain` statement for the same history
 * whose head is `rotationHead` and whose `previous` (the last good head L) is not null and precedes it,
 * the range `supersededFromIndex` < `supersededLatest.index` < `supersededToIndex` (U53 leaf indexes), `supersededLatest`
 * `{position, hash, index}` after L (position above L's), and `supersededCount` from 1 to the number of leaves strictly
 * inside the range. No field grows with the number of superseded heads.
 * Signatures are not verified here (that needs the owner key epochs).
 */
export function validateEntry(entry: unknown): string | null {
  if (!isRecord(entry)) return "entry must be a record";
  if (entry.version !== WITNESS_ENTRY_VERSION) return `version must be ${WITNESS_ENTRY_VERSION}`;
  const common = ["version", "kind", "historyId", "receivedAt"];
  if (!isContentHash(entry.historyId)) return "historyId must be a lowercase 0x-prefixed sha256 hash";
  if (!isU53(entry.receivedAt)) return "receivedAt must be a U53 (ms since epoch)";
  switch (entry.kind) {
    case "REGISTERED": {
      if (!hasExactKeys(entry, [...common, "genesis"])) return "REGISTERED entry fields are version, kind, historyId, genesis, receivedAt";
      if (!isRecord(entry.genesis)) return "genesis must be an event record";
      let id: ContentHash;
      try {
        id = historyIdOfGenesis(entry.genesis);
      } catch (error) {
        return `genesis is not canonically encodable: ${error instanceof Error ? error.message : String(error)}`;
      }
      if (id !== entry.historyId) return "historyId is not the position-0 hash of genesis";
      break;
    }
    case "HEAD": {
      if (!hasExactKeys(entry, [...common, "signedStatement"])) return "HEAD entry fields are version, kind, historyId, signedStatement, receivedAt";
      const reason = validateSignedHeadStatement(entry.signedStatement);
      if (reason !== null) return `signedStatement: ${reason}`;
      if ((entry.signedStatement as SignedHeadStatement).statement.historyId !== entry.historyId) return "signedStatement is for another history";
      break;
    }
    case "ROTATED": {
      if (!hasExactKeys(entry, [...common, "rotation", "previousHead", "rotationHead"])) return "ROTATED entry fields are version, kind, historyId, rotation, previousHead, rotationHead, receivedAt";
      if (!isRecord(entry.rotation) || entry.rotation.type !== "OWNER_KEYS_ROTATED") return "rotation must be an OWNER_KEYS_ROTATED event";
      const refs = headRefsFailure(entry);
      if (refs !== null) return refs;
      break;
    }
    case "SUPERSEDED": {
      if (!hasExactKeys(entry, [...common, "rotation", "previousHead", "rotationHead", "chain", "supersededFromIndex", "supersededToIndex", "supersededLatest", "supersededCount"])) {
        return "SUPERSEDED entry fields are version, kind, historyId, rotation, previousHead, rotationHead, chain, supersededFromIndex, supersededToIndex, supersededLatest, supersededCount, receivedAt";
      }
      if (!isRecord(entry.rotation) || entry.rotation.type !== "OWNER_KEYS_ROTATED") return "rotation must be an OWNER_KEYS_ROTATED event";
      const refs = headRefsFailure(entry);
      if (refs !== null) return refs;
      const reason = validateSignedHeadStatement(entry.chain);
      if (reason !== null) return `chain: ${reason}`;
      const chain = (entry.chain as SignedHeadStatement).statement;
      const rotationHead = entry.rotationHead as HeadRef;
      if (chain.historyId !== entry.historyId) return "chain is for another history";
      if (chain.head.hash !== rotationHead.hash || chain.head.position !== rotationHead.position) return "chain must state rotationHead";
      if (chain.previous === null || chain.previous.position >= rotationHead.position) return "chain.previous (the last good head) must precede rotationHead";
      if (!isU53(entry.supersededFromIndex) || !isU53(entry.supersededToIndex)) return "supersededFromIndex and supersededToIndex must be U53 leaf indexes";
      const latest = entry.supersededLatest;
      if (!isRecord(latest) || !hasExactKeys(latest, ["position", "hash", "index"]) || !isU53(latest.position) || !isContentHash(latest.hash) || !isU53(latest.index)) {
        return "supersededLatest must be {position, hash, index}";
      }
      if (latest.position <= chain.previous.position) return "supersededLatest must come after the last good head";
      const from = entry.supersededFromIndex as number, to = entry.supersededToIndex as number;
      if (!(from < latest.index && latest.index < to)) return "supersededLatest.index must lie strictly between supersededFromIndex and supersededToIndex";
      if (!isU53(entry.supersededCount) || entry.supersededCount < 1 || entry.supersededCount > to - from - 1) return "supersededCount must be from 1 to the number of leaves strictly inside the range";
      break;
    }
    case "EQUIVOCATION": {
      if (!hasExactKeys(entry, [...common, "first", "second"])) return "EQUIVOCATION entry fields are version, kind, historyId, first, second, receivedAt";
      for (const side of ["first", "second"] as const) {
        const reason = validateSignedHeadStatement(entry[side]);
        if (reason !== null) return `${side}: ${reason}`;
        if ((entry[side] as SignedHeadStatement).statement.historyId !== entry.historyId) return `${side} is for another history`;
      }
      const first = (entry.first as SignedHeadStatement).statement.head;
      const second = (entry.second as SignedHeadStatement).statement.head;
      if (first.position !== second.position || first.hash === second.hash) return "an equivocation is two different heads at the same position";
      break;
    }
    default:
      return `kind must be one of ${WITNESS_ENTRY_KINDS.join(", ")}`;
  }
  try {
    canonicalEncode(entry);
  } catch (error) {
    return `entry is not canonically encodable: ${error instanceof Error ? error.message : String(error)}`;
  }
  return null;
}
