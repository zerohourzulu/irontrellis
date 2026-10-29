#!/usr/bin/env node
/**
 * Compare this engine with the independent checker's self-built G6 pins (g25's `H-g6-PINNED.json`): each pin carries its
 * full events, the expected outcome (status, code, position) and, when accepted, the head, state root, record count and
 * projection head. Every pin is replayed here and every difference is printed. A comparison only: the checker's pins are
 * not acceptance (the architect's generator and the checker define the G6 groups).
 *
 * A difference is classified: `RETIRED` (a name the rulings retired, A-108.5), `SUPERSEDED` (a pin whose own expectation
 * a later ruling replaced: the checker's coverage notes name each, or a later pin file re-specifies the same name; where a
 * note states the outcome under G6.3 the engine must give it, else `DIFFER`), `HELD` (a group or field on hold: none since
 * the founder lifted every G6.x hold on 2026-10-12), else `DIFFER`. Several pin files are read in order.
 *
 *   pnpm --filter @ramex-labs/irontrellis build
 *   node conformance/v2-owner-policy/compare-checker.mjs <H-g6-PINNED.json> [<more pins> …] [--json]
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const { replay } = await import(join(ROOT, 'packages/core/dist/index.js'));
const files = process.argv.slice(2).filter((arg) => arg !== '--json');
if (files.length === 0) { console.error('usage: node conformance/v2-owner-policy/compare-checker.mjs <H-g6-PINNED.json> [<more pins> …] [--json]'); process.exit(2); }
/** Names the rulings retired (A-108.5). */
const RETIRED = new Set(['owner-policy/rejects-duplicate-credential']);
/** Groups and fields on hold in this release: none (founder, 2026-10-12: every G6.x hold lifted). */
const HELD_GROUPS = [];
const HELD_FIELD = undefined;
/** Pins a later ruling replaced, as the checker's coverage notes state them (`expect`: the outcome under G6.3, when stated). */
const SUPERSEDED = [
  { file: /H-g6-PINNED/, id: /^human-attestation\//, ruling: 'A-112 R2F-10 (two attesters) and A-107.4 (historyId): the one-attester G6.1 constructions fail at the genesis under G6.2 and are rebuilt in H-g62 (G62-COVERAGE E62-DELTA-1)' },
  { file: /H-g62-PINNED/, id: /^human-attestation\/accepts-fence-by-lapsed-and-agent$/, ruling: 'A-119.1 T2: one LAPSED key with an AGENT co-signer at 200 > H = 100 (G63-COVERAGE E63-DELTA-1)', expect: 'TRANSITION_INVALID@3' },
  { file: /H-g62-PINNED/, id: /^human-attestation\/rejects-restoration-with-stale-statements$/, ruling: 'A-118.2: the renewal has notBefore 300 > e.timestamp 200, so no restoration and the LAPSED signers do not count (G63-COVERAGE E63-DELTA-1)', expect: 'CONTROL_AUTHORIZATION_INVALID@4' },
];
const pins = files.flatMap((file, index) => JSON.parse(readFileSync(file, 'utf8')).map((pin) => ({ pin, file, index })));
const respecified = (id, index) => pins.some((other) => other.pin.id === id && other.index > index);
const outcome = (o) => (o.status === 'ACCEPTED' ? 'ACCEPTED' : `${o.code}@${o.position}`);
const classify = ({ pin, file, index }, agree, ours) => {
  if (agree) return { verdict: 'AGREE' };
  if (RETIRED.has(pin.id)) return { verdict: 'RETIRED' };
  const note = SUPERSEDED.find((entry) => entry.file.test(file) && entry.id.test(pin.id));
  if (note !== undefined) return note.expect === undefined || note.expect === outcome(ours) ? { verdict: 'SUPERSEDED', ruling: note.ruling } : { verdict: 'DIFFER', ruling: `${note.ruling}; expected ${note.expect}` };
  if (respecified(pin.id, index)) return { verdict: 'SUPERSEDED', ruling: 're-specified under the same name by a later pin file' };
  if (HELD_GROUPS.some((group) => pin.id.startsWith(group)) || (HELD_FIELD !== undefined && HELD_FIELD.test(ours.reason ?? ''))) return { verdict: 'HELD' };
  return { verdict: 'DIFFER' };
};

const rows = [];
for (const entry of pins) {
  const { pin } = entry;
  const result = replay(pin.events);
  const ours = result.status === 'ACCEPTED'
    ? { status: 'ACCEPTED', position: result.head.position, head: result.head.hash, stateRoot: result.stateRoot }
    : { status: 'REJECTED', code: result.code, position: result.position, reason: result.reason };
  const theirs = pin.expect.status === 'ACCEPTED'
    ? { status: 'ACCEPTED', position: pin.position, head: pin.head?.hash, stateRoot: pin.stateRoot }
    : { status: 'REJECTED', code: pin.expect.code, position: pin.expect.position };
  const differences = [];
  if (ours.status !== theirs.status) differences.push('status');
  else if (ours.status === 'REJECTED') { if (ours.code !== theirs.code) differences.push('code'); if (ours.position !== theirs.position) differences.push('position'); }
  else { for (const key of ['position', 'head', 'stateRoot']) if (ours[key] !== theirs[key]) differences.push(key); }
  const { verdict, ruling } = classify(entry, differences.length === 0, ours);
  rows.push({ id: pin.id, file: entry.file.split('/').pop(), opts: pin.opts, agree: differences.length === 0, verdict, ...(ruling === undefined ? {} : { ruling }), differences, ours, theirs });
}
if (process.argv.includes('--json')) console.log(JSON.stringify(rows, null, 1));
else {
  const short = (o) => (o.status === 'ACCEPTED' ? `ACCEPTED @${o.position} root ${String(o.stateRoot).slice(0, 10)}` : `${o.code} @${o.position}`);
  for (const row of rows) console.log(`${row.verdict.padEnd(10)} ${row.file} ${row.id}${row.opts === undefined ? '' : ` ${JSON.stringify(row.opts)}`}\n           checker ${short(row.theirs)} | engine ${short(row.ours)}${row.agree ? '' : `  [${row.differences.join(', ')}]${row.ours.reason === undefined ? '' : ` — ${row.ours.reason}`}`}${row.ruling === undefined ? '' : `\n           ${row.ruling}`}`);
  const count = (verdict) => rows.filter((r) => r.verdict === verdict).length;
  console.log(`\n${count('AGREE')}/${rows.length} agree; ${count('RETIRED')} retired, ${count('SUPERSEDED')} superseded, ${count('HELD')} held, ${count('DIFFER')} differ`);
}
