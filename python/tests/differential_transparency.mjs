// Differential-test helper for python/tests/test_transparency.py: runs a batch of witness-format
// checks through the TypeScript core (packages/core/dist/transparency). Reads
// {receipts, notes, checkpoints, statements, entries} JSON on stdin, writes the outcomes as JSON.
// Not a conformance adapter; the pytest suite spawns it once.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const t = await import(join(here, '..', '..', 'packages', 'core', 'dist', 'transparency', 'index.js'));
const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const keysAt = (epochs, position) => {
  let keys = [];
  for (const epoch of epochs) if (epoch.fromPosition <= position) keys = epoch.keys;
  return keys;
};
const input = JSON.parse(readFileSync(0, 'utf8'));
const noteOutcome = (note, keys) => {
  try {
    const opened = t.openNote(note, keys);
    return { ok: true, body: opened.body, verifiedBy: opened.verifiedBy };
  } catch (error) {
    return { ok: false, error: error.code ?? String(error) };
  }
};
const out = {
  receipts: input.receipts.map(({ receipt, keys }) => {
    const r = t.verifyWitnessReceipt(receipt, keys);
    return r.ok ? { ok: true, index: r.index, size: r.checkpoint.size, root: b64(r.checkpoint.root), verifiedBy: r.verifiedBy } : { ok: false, reason: r.reason };
  }),
  notes: input.notes.map(({ note, keys }) => noteOutcome(note, keys)),
  checkpoints: input.checkpoints.map((body) => {
    try {
      const c = t.parseCheckpoint(body);
      return { ok: true, origin: c.origin, size: c.size, root: b64(c.root), extensions: c.extensions };
    } catch (error) {
      return { ok: false, error: error.code ?? String(error) };
    }
  }),
  statements: input.statements.map(({ signed, epochs }) => {
    const r = t.verifySignedHeadStatement(signed, (position) => keysAt(epochs, position));
    return r.ok ? 'OK' : r.reason;
  }),
  entries: input.entries.map((entry) => {
    const reason = t.validateEntry(entry);
    return reason === null ? { valid: true, leafHash: Buffer.from(t.entryLeafHash(entry)).toString('hex') } : { valid: false };
  }),
};
process.stdout.write(JSON.stringify(out));
