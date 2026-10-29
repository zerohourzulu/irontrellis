/**
 * History files as the store writes them (docs/HISTORY-FORMAT.md §3): parse a
 * JSONL file into wire events, and re-encode wire events into lines with a
 * freshly computed record-hash chain. Record hashes are unkeyed, so anyone who
 * can write the file can re-chain it; the fuzzer does exactly that after
 * mutating an event, so that the store's later defenses (owner signatures, the
 * attested pin, the anchor log) are what has to catch it.
 */
import { core, plain, revive } from './env.mjs';

export const LINE_VERSIONS = { 'continuity-event/0.2': 'continuity-portable-file-store/0.2', 'irontrellis-event/1': 'irontrellis-portable-file-store/1' };
const ALGORITHM = { 'continuity-event/0.2': 'keccak256', 'irontrellis-event/1': 'sha256' };

/** The reference SDK's tagged-tuple encoding (writer side: keys in protocol order, integer-like keys first as JS enumerates). */
function encodeTagged(v) {
  if (v === null) return ['null'];
  if (typeof v === 'bigint') return ['bigint', v.toString()];
  if (Array.isArray(v)) return ['array', v.map(encodeTagged)];
  if (typeof v === 'object') {
    const ordered = Object.create(null);
    for (const key of Object.keys(v).sort(core.compareProtocolStrings)) ordered[key] = v[key];
    return ['object', Object.entries(ordered).map(([k, x]) => [k, encodeTagged(x)])];
  }
  return [typeof v, v];
}
function decodeTagged(v) {
  if (!Array.isArray(v)) throw new Error('not tagged');
  const [tag, body] = v;
  if (tag === 'null') return null;
  if (tag === 'bigint') return { '$continuity.bigint': body };
  if (tag === 'array') return body.map(decodeTagged);
  if (tag === 'object') return Object.fromEntries(body.map(([k, x]) => [k, decodeTagged(x)]));
  return body;
}

/** `{ format, events }` (wire) from a history file's text; throws on anything unparsable. */
export function parseHistory(text) {
  const lines = text.split('\n').filter((line) => line.length > 0);
  if (lines.length === 0) return { format: undefined, events: [] };
  const version = JSON.parse(lines[0]).version;
  const format = Object.keys(LINE_VERSIONS).find((f) => LINE_VERSIONS[f] === version);
  if (format === undefined) throw new Error('unknown line version');
  return { format, events: lines.map((line) => { const record = JSON.parse(line); return format === core.LEGACY_FORMAT ? decodeTagged(record.event) : record.event; }) };
}

/** Lines for `events` (wire) with a recomputed chain; an event the canonical form rejects keeps a best-effort (invalid) hash. */
export function encodeHistory(format, events) {
  const version = LINE_VERSIONS[format];
  let previousHash = null;
  let text = '';
  for (const event of events) {
    let stored, recordHash;
    try {
      const value = revive(event);
      stored = format === core.LEGACY_FORMAT ? encodeTagged(value) : event;
      recordHash = core.hashCanonical({ version, previousHash, event: value }, ALGORITHM[format]);
    } catch {
      stored = format === core.LEGACY_FORMAT ? ['null'] : event;
      recordHash = `0x${'0'.repeat(64)}`;
    }
    text += `${JSON.stringify({ version, previousHash, event: stored, recordHash })}\n`;
    previousHash = recordHash;
  }
  return text;
}

/** A pin for `events[position]` as the store writes it, carrying `attestation` when given. */
export function pinFor(format, events, position, { attestation, pinnedAt = 1 } = {}) {
  const lines = encodeHistory(format, events.slice(0, position + 1)).trimEnd().split('\n');
  const recordHash = JSON.parse(lines.at(-1)).recordHash;
  const state = core.replay(revive(events.slice(0, position + 1))).state;
  const head = state?.head ?? { hash: `0x${'0'.repeat(64)}`, position, canonicalTime: 0 };
  return { version: 'irontrellis-pinned-head/1', hash: head.hash, position: head.position, canonicalTime: head.canonicalTime, recordHash, pinnedAt, ...(attestation === undefined ? {} : { attestation }) };
}

export const toWire = plain;
