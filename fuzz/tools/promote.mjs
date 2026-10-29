#!/usr/bin/env node
/**
 * Turns a campaign failure record into a regression vector:
 *
 *   node fuzz/tools/promote.mjs <corpus>/<target>/failures/<hash>.json --id short-name \
 *     --root-cause "why it happened" --fix "what changed" [--description "…"] [--expect '<json>'] [--requires python]
 *
 * The vector gets the minimized input when the record has one (campaigns with --minimize), else the original.
 * With no --expect, the outcome of the fixed code is recorded as the expectation (run it after the fix): the
 * target's `outcome`, which for store vectors is {strict, reader, py}. Refuses to overwrite an existing vector.
 * Hand-made vectors that should regenerate deterministically belong in fuzz/tools/make-regressions.mjs instead.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { REGRESSIONS } from '../lib/env.mjs';
import { createContext, loadTarget } from '../lib/campaign.mjs';

const args = process.argv.slice(2);
const option = (name) => { const i = args.indexOf(`--${name}`); return i < 0 ? undefined : args[i + 1]; };
const file = args.find((a) => a.endsWith('.json') && !a.startsWith('--'));
const id = option('id');
if (!file || !id || !/^[a-z0-9][a-z0-9-]{2,80}$/.test(id)) {
  console.error('usage: promote.mjs <failure.json> --id <kebab-id> --root-cause <text> --fix <text> [--description <text>] [--expect <json>] [--requires python]');
  process.exit(2);
}
const record = JSON.parse(readFileSync(file, 'utf8'));
const input = record.minimized ?? record.input;
let expect = option('expect') === undefined ? undefined : JSON.parse(option('expect'));
const failures = [];
if (expect === undefined) {
  const target = await loadTarget(record.target);
  const context = createContext({ python: true });
  const state = await target.setup(context);
  try {
    const result = await target.check(input, state);
    failures.push(...result.failures);
    expect = result.outcome;
  } finally {
    await target.teardown?.(state);
    context.close();
  }
}
if (failures.length > 0) {
  console.error(`the input still fails (${failures.map((f) => f.key).join(', ')}): fix the defect first`);
  process.exit(1);
}
const vector = {
  id, target: record.target, found: `campaign seed ${record.seed}, iteration ${record.iteration} (${record.key})`,
  description: option('description') ?? record.message, rootCause: option('root-cause') ?? 'TODO', fix: option('fix') ?? 'TODO',
  ...(option('requires') === undefined ? {} : { requires: option('requires') }), input, ...(expect === undefined ? {} : { expect }),
};
const dir = join(REGRESSIONS, record.target);
mkdirSync(dir, { recursive: true });
const out = join(dir, `${id}.json`);
if (existsSync(out)) { console.error(`${out} exists`); process.exit(1); }
writeFileSync(out, `${JSON.stringify(vector, null, 1)}\n`);
console.log(`wrote ${out}`);
