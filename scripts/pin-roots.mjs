#!/usr/bin/env node
/**
 * G2.5 input (BUILD-INSTRUCTIONS §2, §9): every pinned position of every format-2 history of the regenerated suites,
 * re-derived with this engine.
 *
 *   pnpm --filter @ramex-labs/irontrellis build
 *   node scripts/pin-roots.mjs --out <dir>            # writes <dir>/PINNED-ROOTS.json and <dir>/records/<history>-<position>.json
 *
 * Suites: conformance/v2-g3 (the architect suite regenerated per A-54/A-59) and conformance/v2-regenerated (engine-derived).
 * A history is named `<suite>.<ref>`. Pinned positions: every position an accepted replay vector pins (its head), the
 * from/to of every export vector, every STATE_CHECKPOINT p and p − 1 (its data.stateRoot is rootAt(p − 1)), the final
 * head, and the suite MANIFEST's `pinnedPositions` when it lists them; an accepted replay vector that carries its own events
 * pins a prefix of a saved history, or else its own history, named `<suite>.vector:<vector id with / as _>`. Each pin is
 * `{history, position, head, stateRoot, recordCount, projectionHead}`; the record set at that position is
 * `{history, position, head, stateRoot, recordCount, records: [{kind, key, record}]}` in (kind, key) byte order, so a
 * reviewer recomputes every §7.1 leaf from canonical(record) and the root from the leaves. Deterministic: the same
 * tree gives byte-identical files.
 */
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const core = await import(join(ROOT, 'packages/core/dist/index.js'));
const SUITES = ['v2-g3', 'v2-regenerated'];

const args = process.argv.slice(2);
const outIndex = args.indexOf('--out');
if (outIndex < 0 || args[outIndex + 1] === undefined) { console.error('usage: node scripts/pin-roots.mjs --out <dir>'); process.exit(2); }
const OUT = resolve(args[outIndex + 1]);
if (OUT === ROOT || OUT.startsWith(`${ROOT}/`)) { console.error('pin-roots: write the results outside the source tree'); process.exit(2); }

const read = (file) => JSON.parse(readFileSync(file, 'utf8'));
const json = (value) => `${JSON.stringify(value, (_k, v) => { if (typeof v === 'bigint') throw new Error('a bigint in a format-2 record'); return v; }, 1)}\n`;
const isFormat2 = (events) => events[0]?.data?.versions?.eventSchemaVersion === 'irontrellis-event/2';
const byteOrder = (a, b) => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));

const pins = [];
const recordFiles = new Map();
for (const suite of SUITES) {
  const dir = join(ROOT, 'conformance', suite);
  const manifest = read(join(dir, 'MANIFEST.json'));
  const vectors = read(join(dir, 'vectors.json'));
  const saved = new Map(Object.keys(manifest.histories).map((ref) => [ref, read(join(dir, 'histories', `${ref}.json`))]));
  const positions = new Map();
  const add = (ref, p) => { if (!positions.has(ref)) positions.set(ref, new Set()); positions.get(ref).add(p); };
  /** An accepted vector that carries its own events: a prefix of a saved history, or its own history named by the vector id. */
  const inline = new Map();
  const pinned = (v) => v.kind === 'replay' && v.expect.status === 'ACCEPTED' && v.expect.stateRoot !== null && v.input?.testCapacityLimits === undefined;
  for (const v of vectors) {
    if (v.history === undefined) {
      if (!pinned(v)) continue;
      const text = JSON.stringify(v.events);
      const ref = [...saved.keys()].find((r) => saved.get(r).length >= v.events.length && JSON.stringify(saved.get(r).slice(0, v.events.length)) === text);
      if (ref === undefined) inline.set(`vector:${v.id.replaceAll('/', '_')}`, v.events);
      else add(ref, v.events.length - 1);
      continue;
    }
    if (pinned(v)) add(v.history.ref, v.expect.head.position);
    if (v.kind === 'export') { add(v.history.ref, v.input.fromPosition); add(v.history.ref, v.input.toPosition); }
  }
  for (const [ref, list] of Object.entries(manifest.pinnedPositions ?? {})) for (const p of list) add(ref, p);
  for (const [ref, events] of saved) {
    if (!isFormat2(events)) continue;
    add(ref, events.length - 1);
    events.forEach((e, p) => { if (e.type === 'STATE_CHECKPOINT') { add(ref, p); add(ref, p - 1); } });
  }
  for (const [ref, events] of inline) { saved.set(ref, events); add(ref, events.length - 1); }
  for (const ref of [...positions.keys()].sort(byteOrder)) {
    const events = saved.get(ref);
    if (!isFormat2(events)) continue;
    const history = `${suite}.${ref}`;
    for (const position of [...positions.get(ref)].sort((a, b) => a - b)) {
      const result = core.replay(events.slice(0, position + 1));
      if (result.status !== 'ACCEPTED') throw new Error(`${history} at ${position}: ${result.code} ${result.reason ?? ''}`);
      const records = core.stateRecordsOf(result.state).map(({ kind, key, record }) => ({ kind, key, record }));
      records.sort((a, b) => byteOrder(a.kind, b.kind) || byteOrder(a.key, b.key));
      if (records.length !== result.state.stateRecords.size) throw new Error(`${history} at ${position}: record count`);
      const pin = { history, position, head: result.head, stateRoot: result.stateRoot, recordCount: records.length, projectionHead: result.projectionHead ?? null };
      pins.push(pin);
      recordFiles.set(`records/${history}-${position}.json`, json({ ...pin, records }));
    }
  }
}

// The two E3 migration pins (packages/core/test/format2-migrate.test.mjs PINNED), re-derived: the final heads of the migration twins.
const migration = (ref, source) => {
  const last = read(join(ROOT, 'conformance/v2-regenerated/histories', `${ref}.json`)).length - 1;
  const pin = pins.find((p) => p.history === `v2-regenerated.${ref}` && p.position === last);
  if (pin === undefined) throw new Error(`no pin for ${ref}`);
  return { source, ...pin };
};
const output = {
  version: 'irontrellis-pinned-roots/1',
  note: 'G2.5 input: every pinned (history, position) of conformance/v2-g3 and conformance/v2-regenerated, re-derived with this engine (packages/core). Records: records/<history>-<position>.json. Generated by scripts/pin-roots.mjs.',
  suites: Object.fromEntries(SUITES.map((suite) => [suite, { manifestSha256: createHash('sha256').update(readFileSync(join(ROOT, 'conformance', suite, 'MANIFEST.json'))).digest('hex') }])),
  migrationPins: [
    migration('migrated-legacy-v2', 'legacy handover fixture (packages/reference-0.2/tests/fixtures/handover-history.json), prefix end 25'),
    migration('migrated-format1-v2', 'format-1 conformance/v1/histories/handover-v1.jsonl, prefix end 21'),
  ],
  pins,
};

rmSync(join(OUT, 'records'), { recursive: true, force: true });
mkdirSync(join(OUT, 'records'), { recursive: true });
writeFileSync(join(OUT, 'PINNED-ROOTS.json'), json(output));
for (const [path, text] of recordFiles) writeFileSync(join(OUT, path), text);
console.log(`pin-roots: ${pins.length} pins over ${new Set(pins.map((p) => p.history)).size} histories → ${OUT}/PINNED-ROOTS.json, ${recordFiles.size} record files`);
