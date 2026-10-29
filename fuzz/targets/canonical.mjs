/**
 * Target `canonical`: JSON text → `jsonParseWithBigints` → `canonicalEncode` /
 * `captureValue`, against Python `from_plain(json.loads)` → `canonical_encode`.
 *
 * Invariants: parsing and encoding reject only with SyntaxError (malformed
 * JSON, as documented) or CanonicalError; `captureValue` accepts exactly what
 * `canonicalEncode` accepts and encodes to the same text; the canonical text is
 * a fixpoint (parse∘encode∘parse∘encode = encode); TypeScript and Python agree
 * on acceptance and produce byte-identical canonical text.
 */
import { core } from '../lib/env.mjs';
import { crashFailure } from '../lib/invariants.mjs';
import { Dictionary, mutateText, mutateValue } from '../lib/mutate.mjs';
import { replaySeeds } from '../lib/seeds.mjs';

const reasonClass = (message) => String(message).replace(/at \$[^ ]*/g, 'at $').replace(/\d+/g, 'N').split(' ').slice(0, 8).join(' ');

function tsOutcome(text) {
  let value;
  try {
    value = core.jsonParseWithBigints(text);
  } catch (error) {
    if (error instanceof SyntaxError) return { ok: false, stage: 'parse', error: 'SyntaxError' };
    if (error instanceof core.CanonicalError) return { ok: false, stage: 'parse', error: 'CanonicalError', reason: reasonClass(error.reason) };
    return { crash: crashFailure('jsonParseWithBigints', error) };
  }
  let encoded, captured, encodeError, captureError;
  try { encoded = core.canonicalEncode(value); } catch (error) { encodeError = error; }
  try { captured = core.captureValue(value); } catch (error) { captureError = error; }
  for (const [where, error] of [['canonicalEncode', encodeError], ['captureValue', captureError]]) {
    if (error !== undefined && !(error instanceof core.CanonicalError)) return { crash: crashFailure(where, error) };
  }
  return { ok: encodeError === undefined, stage: 'encode', encoded, captured, captureOk: captureError === undefined, encodeError, captureError, value };
}

export default {
  name: 'canonical',
  async setup(ctx) {
    const dict = new Dictionary();
    const texts = [];
    for (const { events } of replaySeeds()) for (const event of events) { dict.add(event); texts.push(JSON.stringify(event)); }
    texts.push('0', '"x"', 'null', '[]', '{}', '{"$continuity.bigint":"12"}', '[1,{"a":[true,false,null]}]', '{"b":1,"a":2,"é":3,"z":4,"\\u0000":5}');
    return { ctx, dict: dict.freeze(), texts };
  },
  seedInputs(state) { return state.texts.map((text) => ({ text })); },
  mutate(rng, base, state) {
    const roll = rng.float();
    if (roll < 0.04) { // deep nesting past every recursion limit
      const depth = rng.pick([33, 100, 1000, 5000, 20_000, 100_000]);
      const [open, close] = rng.pick([['[', ']'], ['{"a":', '}'], ['[{"x":', '}]']]);
      return { text: `${open.repeat(depth)}${rng.pick(['0', '""', '{"$continuity.bigint":"1"}'])}${close.repeat(depth)}` };
    }
    if (roll < 0.55) {
      try {
        return { text: JSON.stringify(mutateValue(rng, JSON.parse(base.text), state.dict)) };
      } catch { // not JSON, or nested past what the harness's own JSON walk can handle
        return { text: mutateText(rng, base.text) };
      }
    }
    return { text: mutateText(rng, base.text) };
  },
  async check({ text }, state) {
    const failures = [];
    const ts = tsOutcome(text);
    if (ts.crash) return { failures: [ts.crash], features: ['crash'] };
    const features = [`ts:${ts.ok}:${ts.stage}:${ts.error ?? ''}:${reasonClass(ts.encodeError?.reason ?? ts.reason ?? '')}`];
    if (ts.stage === 'encode') {
      if (ts.captureOk !== ts.ok) {
        failures.push({ invariant: 'CAPTURE_ENCODE_DISAGREE', key: `CAPTURE_ENCODE_DISAGREE:${ts.ok}`, message: `canonicalEncode ${ts.ok ? 'accepts' : 'rejects'} but captureValue ${ts.captureOk ? 'accepts' : 'rejects'} (${(ts.encodeError ?? ts.captureError)?.message})` });
      } else if (ts.ok) {
        let again;
        try { again = core.canonicalEncode(ts.captured); } catch (error) { again = `threw ${error.message}`; }
        if (again !== ts.encoded) failures.push({ invariant: 'CAPTURE_ENCODE_DISAGREE', key: 'CAPTURE_REENCODE', message: 'canonicalEncode(captureValue(v)) differs from canonicalEncode(v)' });
        let fixpoint;
        try { fixpoint = core.canonicalEncode(core.jsonParseWithBigints(ts.encoded)); } catch (error) { fixpoint = `threw ${error.message}`; }
        if (fixpoint !== ts.encoded) failures.push({ invariant: 'PARSE_SERIALIZE_IDENTITY', key: 'CANONICAL_FIXPOINT', message: `canonical text is not a fixpoint: ${JSON.stringify(ts.encoded).slice(0, 120)}` });
      }
    }
    if (state.ctx.python) {
      const py = await state.ctx.python.request({ op: 'canonical', text });
      if (py.crash) failures.push({ invariant: 'UNTYPED_CRASH', key: `PY_CRASH:canonical:${py.crash.split(':')[0]}:${py.where?.at(-1)}`, message: `python: ${py.crash}`, detail: py });
      else if (py.ok !== ts.ok) {
        failures.push({ invariant: 'TS_PY_DISAGREE', key: `CANONICAL_ACCEPT:ts=${ts.ok}/${ts.stage}:py=${py.ok}/${py.stage}`, message: `TypeScript ${ts.ok ? 'accepts' : `rejects (${ts.stage})`}, Python ${py.ok ? 'accepts' : `rejects (${py.stage} ${py.error})`}: ${text.slice(0, 160)}` });
      } else if (ts.ok && py.encoded !== ts.encoded) {
        failures.push({ invariant: 'TS_PY_DISAGREE', key: 'CANONICAL_TEXT', message: `canonical texts differ: ts ${JSON.stringify(ts.encoded).slice(0, 100)} py ${JSON.stringify(py.encoded).slice(0, 100)}` });
      }
      features.push(`py:${py.ok}:${py.stage ?? ''}:${py.error ?? ''}`);
    }
    return { failures, features, outcome: { ts: { ok: ts.ok, stage: ts.stage, ...(ts.ok ? { encoded: ts.encoded } : {}) } } };
  },
};
