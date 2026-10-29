/**
 * Key-event bundles (docs/reference/witness-operations.md §7.3, §9.9): a self-authenticating hand-off of one owner key event
 * (an `OWNER_KEYS_ROTATED` event, commitment-only ones included) to a witness that cannot be reached over the network.
 *
 *   { version: "irontrellis-key-event-bundle/1", historyId,
 *     event,                       // the owner-signed key event, verbatim
 *     previousHead: {hash, position},   // the head before it (what its controlAuthorization signs)
 *     eventHead:    {hash, position},   // the head ending with it (position = previousHead.position + 1)
 *     statement,                   // the head statement for eventHead, signed by the key in force there, previous = previousHead
 *     chain? }                     // rotations only: the same head stated with previous = the last head the owner knew the
 *                                  // witness held, for a supersede (docs/reference/witness-operations.md §7.4)
 *
 * Nothing in a bundle is trusted for being in a bundle: a witness runs exactly the checks of `POST
 * /v1/histories/:id/key-events` on it (owner signatures, the key-event rules against the epochs it knows, the chaining
 * rule for the statement). The admin token or the server lock only gate the channel.
 */
import { isU53 } from "../canonical.ts";
import { isContentHash } from "../crypto/suites.ts";
import type { ContentHash, U53 } from "../types.ts";
import { validateSignedHeadStatement, type SignedHeadStatement } from "./statement.ts";

export const KEY_EVENT_BUNDLE_VERSION = "irontrellis-key-event-bundle/1";

export type KeyEventBundle = Readonly<{
  version: typeof KEY_EVENT_BUNDLE_VERSION;
  historyId: ContentHash;
  event: Readonly<Record<string, unknown>>;
  previousHead: Readonly<{ hash: ContentHash; position: U53 }>;
  eventHead: Readonly<{ hash: ContentHash; position: U53 }>;
  statement: SignedHeadStatement;
  chain?: SignedHeadStatement;
}>;

const isRecord = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const isRef = (value: unknown): value is { hash: ContentHash; position: U53 } =>
  isRecord(value) && Object.keys(value).length === 2 && isContentHash(value.hash) && isU53(value.position);

/** `<history>.key-event-<position>.bundle.json`: where the owner API writes the bundle of the key event at `position`. */
export function keyEventBundlePathFor(historyFile: string, position: number): string {
  return `${historyFile}.key-event-${position}.bundle.json`;
}

/**
 * `null` when `bundle` is a structurally valid key-event bundle, else a reason: the exact field set, the version, a
 * key event (`OWNER_KEYS_ROTATED`), `eventHead.position === previousHead.position + 1`,
 * a well-formed `statement` for this history stating exactly `eventHead`, and an optional `chain` stating
 * `eventHead` with a non-null `previous` before it. Signatures are not verified here (that needs the owner key epochs).
 */
export function validateKeyEventBundle(bundle: unknown): string | null {
  if (!isRecord(bundle)) return "a key-event bundle is a record";
  const allowed = ["version", "historyId", "event", "previousHead", "eventHead", "statement", "chain"];
  const extra = Object.keys(bundle).find((key) => !allowed.includes(key));
  if (extra !== undefined) return `unknown field ${extra}`;
  if (bundle.version !== KEY_EVENT_BUNDLE_VERSION) return `version must be ${KEY_EVENT_BUNDLE_VERSION}`;
  if (!isContentHash(bundle.historyId)) return "historyId must be a lowercase 0x-prefixed sha256 hash";
  const event = bundle.event;
  if (!isRecord(event) || event.type !== "OWNER_KEYS_ROTATED") return "event must be an OWNER_KEYS_ROTATED event";
  if (!isRef(bundle.previousHead) || !isRef(bundle.eventHead)) return "previousHead and eventHead must be {hash, position}";
  if (bundle.eventHead.position !== bundle.previousHead.position + 1) return "eventHead.position must be previousHead.position + 1";
  const statementFailure = (name: "statement" | "chain", value: unknown): string | null => {
    const reason = validateSignedHeadStatement(value);
    if (reason !== null) return `${name}: ${reason}`;
    const statement = (value as SignedHeadStatement).statement;
    if (statement.historyId !== bundle.historyId) return `${name} is for another history`;
    if (statement.head.hash !== (bundle.eventHead as { hash: string }).hash || statement.head.position !== (bundle.eventHead as { position: number }).position) return `${name} must state eventHead`;
    return null;
  };
  const statement = statementFailure("statement", bundle.statement);
  if (statement !== null) return statement;
  if (bundle.chain !== undefined) {
    const chain = statementFailure("chain", bundle.chain);
    if (chain !== null) return chain;
    const previous = (bundle.chain as SignedHeadStatement).statement.previous;
    if (previous === null || previous.position >= bundle.eventHead.position) return "chain.previous must be a head before eventHead";
  }
  return null;
}
