/**
 * Target `transparency`: the witness wire formats (docs/WITNESS.md §9) in both
 * cores: signed notes, checkpoints, latest notes (parse and verify), witness
 * receipts, log entries, signed head statements, verifier keys, strict
 * base64, Merkle inclusion and consistency proofs, and (TypeScript only)
 * key-event bundles.
 *
 * Invariants: the "never throws" verifiers never throw and the parsers throw
 * only NoteError; TypeScript and Python agree on every outcome (ok, reason or
 * error code, and the parsed fields); parse∘format identity for checkpoints,
 * latest notes, verifier keys and base64.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ROOT, t } from '../lib/env.mjs';
import { crashFailure } from '../lib/invariants.mjs';
import { Dictionary, clone, mutateText, mutateValue } from '../lib/mutate.mjs';
import { SEED_CACHE, storeSeeds } from '../lib/seeds.mjs';

const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const fromHex = (text) => (typeof text === 'string' && /^([0-9a-f]{2})*$/.test(text) ? new Uint8Array(Buffer.from(text, 'hex')) : undefined);
/** JSON with record keys sorted (the two cores build records in different key orders). */
const stable = (value) => JSON.stringify(value, (_key, v) => (v !== null && typeof v === 'object' && !Array.isArray(v) ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, v[k]])) : v));
const keysAt = (epochs, position) => { let keys = []; for (const epoch of Array.isArray(epochs) ? epochs : []) if (typeof epoch?.fromPosition === "number" && epoch.fromPosition <= position) keys = epoch.keys; return keys; };
const noteError = (where, fn) => { try { return fn(); } catch (error) { if (error instanceof t.NoteError) return { ok: false, error: error.code }; throw Object.assign(error, { where }); } };

/** The TypeScript outcome of one input, in the shape the Python worker answers. */
function tsOutcome(input) {
  switch (input.kind) {
    case 'note': return noteError('openNote', () => { const o = t.openNote(input.note, input.keys); return { ok: true, body: o.body, verifiedBy: o.verifiedBy }; });
    case 'checkpoint': return noteError('parseCheckpoint', () => { const c = t.parseCheckpoint(input.body); return { ok: true, origin: c.origin, size: c.size, root: b64(c.root), extensions: c.extensions }; });
    case 'latest': return noteError('parseLatestNote', () => ({ ok: true, latest: t.parseLatestNote(input.body) }));
    case 'latestVerify': { const r = t.verifyLatestNote(input.note, input.keys, input.expect); return r.ok ? { ok: true, latest: r.latest, verifiedBy: r.verifiedBy } : { ok: false, reason: r.reason }; }
    case 'receipt': { const r = t.verifyWitnessReceipt(input.receipt, input.keys); return r.ok ? { ok: true, index: r.index, size: r.checkpoint.size, root: b64(r.checkpoint.root), verifiedBy: r.verifiedBy } : { ok: false, reason: r.reason }; }
    case 'entry': { const reason = t.validateEntry(input.entry); return reason === null ? { valid: true, leafHash: hex(t.entryLeafHash(input.entry)) } : { valid: false }; }
    case 'statement': { const r = t.verifySignedHeadStatement(input.signed, (p) => keysAt(input.epochs, p)); return { result: r.ok ? 'OK' : r.reason }; }
    case 'verifierKey': return noteError('parseVerifierKey', () => { const k = t.parseVerifierKey(input.key); return { ok: true, name: k.name, keyHash: hex(k.keyHash), publicKey: hex(k.publicKey) }; });
    case 'base64': { const d = t.decodeBase64(input.text); return d === undefined ? { ok: false } : { ok: true, hex: hex(d) }; }
    case 'inclusion': {
      const leaf = fromHex(input.leaf), root = fromHex(input.root), proof = Array.isArray(input.proof) ? input.proof.map(fromHex) : input.proof;
      return { valid: t.verifyInclusion(leaf, input.index, input.size, proof, root) };
    }
    case 'consistency': {
      const from = fromHex(input.fromRoot), to = fromHex(input.toRoot), proof = Array.isArray(input.proof) ? input.proof.map(fromHex) : input.proof;
      return { valid: t.verifyConsistency(input.from, input.to, from, to, proof) };
    }
    case 'bundle': return { reason: t.validateKeyEventBundle(input.bundle) === null ? null : 'invalid' };
    default: return { unsupported: input.kind };
  }
}

/** Parse∘format identity where a canonical text form exists. */
function identityFailures(input, outcome) {
  const failures = [];
  const fail = (key, message) => failures.push({ invariant: 'PARSE_SERIALIZE_IDENTITY', key, message });
  if (input.kind === 'checkpoint' && outcome.ok) {
    const again = t.formatCheckpoint(outcome.origin, outcome.size, t.decodeBase64(outcome.root), outcome.extensions);
    if (again !== input.body) fail('CHECKPOINT_IDENTITY', `formatCheckpoint(parseCheckpoint(body)) differs: ${JSON.stringify(input.body).slice(0, 120)}`);
  }
  if (input.kind === 'latest' && outcome.ok && t.formatLatestNote(outcome.latest) !== input.body) fail('LATEST_IDENTITY', `formatLatestNote(parseLatestNote(body)) differs: ${JSON.stringify(input.body).slice(0, 120)}`);
  if (input.kind === 'base64' && outcome.ok && t.encodeBase64(t.decodeBase64(input.text)) !== input.text) fail('BASE64_IDENTITY', 'encode(decode(text)) differs');
  if (input.kind === 'verifierKey' && outcome.ok) {
    const again = t.verifierKey(outcome.name, fromHex(outcome.publicKey));
    if (again !== input.key && again.toLowerCase() !== input.key.toLowerCase()) fail('VKEY_IDENTITY', `verifierKey(parseVerifierKey(k)) differs beyond hex case: ${input.key}`);
  }
  return failures;
}

export default {
  name: 'transparency',
  async setup(ctx) {
    const V = JSON.parse(readFileSync(join(ROOT, 'conformance/transparency/vectors.json'), 'utf8'));
    const inputs = [];
    for (const v of V.notes) inputs.push({ kind: 'note', note: v.note, keys: v.verifierKeys });
    for (const v of V.checkpoints) inputs.push({ kind: 'checkpoint', body: v.body });
    for (const v of V.latestNotes.parse) inputs.push({ kind: 'latest', body: v.body });
    for (const v of V.latestNotes.verify) inputs.push({ kind: 'latestVerify', note: v.note, keys: v.trustedVerifierKeys, expect: v.expect });
    for (const v of V.receipts) inputs.push({ kind: 'receipt', receipt: v.receipt, keys: v.trustedVerifierKeys });
    for (const v of V.entries) inputs.push({ kind: 'entry', entry: v.entry });
    for (const v of V.statements) inputs.push({ kind: 'statement', signed: v.signed, epochs: v.ownerKeyEpochs });
    for (const v of V.keys.verifierKeys) inputs.push({ kind: 'verifierKey', key: v.vkey });
    for (const v of V.merkle.inclusion) inputs.push({ kind: 'inclusion', leaf: v.leafHash, index: v.index, size: v.size, proof: v.proof, root: v.root });
    for (const v of V.merkle.consistency) inputs.push({ kind: 'consistency', from: v.from, to: v.to, fromRoot: v.fromRoot, toRoot: v.toRoot, proof: v.proof });
    for (const text of ['', 'AA==', 'AAA=', 'AAAA', 'QUJD', '////', 'Zm9vYmFy']) inputs.push({ kind: 'base64', text });
    // Real witness answers from the seeds: held receipts and checkpoints of the side file, and the key-event bundles.
    await storeSeeds();
    for (const name of readdirSync(SEED_CACHE)) {
      let files = [];
      try { files = readdirSync(join(SEED_CACHE, name)); } catch { continue; }
      for (const file of files) {
        if (file.endsWith('.bundle.json')) inputs.push({ kind: 'bundle', bundle: JSON.parse(readFileSync(join(SEED_CACHE, name, file), 'utf8')) });
        if (file.endsWith('.witness.json')) {
          const side = JSON.parse(readFileSync(join(SEED_CACHE, name, file), 'utf8'));
          for (const w of Object.values(side.witnesses ?? {})) {
            if (w.held) inputs.push({ kind: 'receipt', receipt: w.held, keys: [w.verifierKey] });
            if (w.checkpoint?.note) { inputs.push({ kind: 'note', note: w.checkpoint.note, keys: [w.verifierKey] }); inputs.push({ kind: 'checkpoint', body: t.openNote(w.checkpoint.note, [w.verifierKey]).body }); }
          }
        }
      }
    }
    const dict = new Dictionary();
    for (const input of inputs) dict.add(input);
    return { ctx, inputs, dict: dict.freeze(), kinds: [...new Set(inputs.map((i) => i.kind))] };
  },
  seedInputs(state) { return state.inputs; },
  mutate(rng, base, state) {
    const input = clone(base);
    const textField = { note: 'note', checkpoint: 'body', latest: 'body', latestVerify: 'note', verifierKey: 'key', base64: 'text' }[input.kind];
    if (textField && rng.chance(0.7)) {
      input[textField] = typeof input[textField] === 'string' ? mutateText(rng, input[textField], 3) : '';
      if (rng.chance(0.1) && Array.isArray(input.keys)) input.keys = mutateValue(rng, input.keys, state.dict, 1);
      return input;
    }
    const { kind, ...rest } = input;
    // `kind` last: a mutation that adds a "kind" key must not replace the input's kind (the long campaign of seed 41
    // produced kind = [[{ toString: 0 }]], and the feature label below threw a harness TypeError on it).
    return { ...mutateValue(rng, rest, state.dict, 3), kind };
  },
  async check(input, state) {
    const failures = [];
    let ts;
    try { ts = tsOutcome(input); } catch (error) { return { failures: [crashFailure(`transparency.${input.kind}`, error)], features: ['crash'] }; }
    try { failures.push(...identityFailures(input, ts)); } catch (error) { failures.push(crashFailure(`transparency.${input.kind}.identity`, error)); }
    const label = (value) => (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean' || value === undefined || value === null ? String(value) : typeof value);
    const features = [`${label(input.kind)}:${label(ts.ok ?? ts.valid ?? ts.result ?? ts.reason)}:${label(ts.reason ?? ts.error ?? '')}`];
    if (state.ctx.python && input.kind !== 'bundle') {
      const py = await state.ctx.python.request({ op: 'transparency', ...input });
      if (py.crash) failures.push({ invariant: 'UNTYPED_CRASH', key: `PY_CRASH:transparency.${input.kind}:${py.crash.split(':')[0]}:${py.where?.at(-1)}`, message: `python ${input.kind}: ${py.crash}`, detail: py });
      else if (stable(py) !== stable(ts)) {
        failures.push({ invariant: 'TS_PY_DISAGREE', key: `TRANSPARENCY:${input.kind}:ts=${ts.ok ?? ts.valid ?? ts.result}/${ts.reason ?? ts.error ?? ''}:py=${py.ok ?? py.valid ?? py.result}/${py.reason ?? py.error ?? ''}`,
          message: `${input.kind}: TypeScript ${JSON.stringify(ts).slice(0, 200)}, Python ${JSON.stringify(py).slice(0, 200)}` });
      }
    }
    return { failures, features, outcome: { ts } };
  },
};
