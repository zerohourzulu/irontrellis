/**
 * Target `events`: one raw event at a position, `validateEvent` (envelope,
 * capture, genesis probe, type, closed per-type schema) against Python
 * `validate_event`.
 *
 * Invariants: `validateEvent` never throws; TypeScript and Python agree on
 * acceptance and on the rejection code; an accepted event re-validates to the
 * same canonical event after a wire round trip (parse∘serialize identity), and
 * both implementations return the same captured event.
 */
import { core, plain } from '../lib/env.mjs';
import { crashFailure } from '../lib/invariants.mjs';
import { Dictionary, clone, mutateValue, put } from '../lib/mutate.mjs';
import { replaySeeds, storeSeeds } from '../lib/seeds.mjs';
import { PYTHON_SKIP_REASON, format2Input } from '../lib/python.mjs';

const pathClass = (reason) => String(reason).split(':')[0].replace(/\[\d+\]/g, '[]');
const canonical = (value) => { try { return core.canonicalEncode(core.jsonParseWithBigints(JSON.stringify(value))); } catch (error) { return `unencodable: ${error.message}`; } };

export default {
  name: 'events',
  async setup(ctx) {
    const dict = new Dictionary();
    const inputs = [];
    const histories = [...replaySeeds(), ...(await storeSeeds()).map((s) => ({ name: `store/${s.name}`, events: s.events }))];
    for (const { events } of histories) {
      const format = core.detectFormat(events) ?? core.LEGACY_FORMAT;
      events.forEach((event, position) => { dict.add(event); inputs.push({ event, format, position }); });
    }
    const byType = new Map();
    for (const input of inputs) { const list = byType.get(input.event.type) ?? []; list.push(input.event); byType.set(input.event.type, list); }
    return { ctx, dict: dict.freeze(), inputs, byType };
  },
  seedInputs(state) { return state.inputs; },
  mutate(rng, base, state) {
    const input = clone(base);
    const roll = rng.float();
    if (roll < 0.08) input.position = rng.pick([0, 1, input.position + 1, 2 ** 20]);
    else if (roll < 0.12) input.format = input.format === core.LEGACY_FORMAT ? core.TRELLIS_FORMAT : core.LEGACY_FORMAT;
    else if (roll < 0.22 && input.event?.data && typeof input.event.data === 'object') { // graft the data of another event of the same (or another) type
      const donors = state.byType.get(rng.chance(0.7) ? input.event.type : rng.pick([...state.byType.keys()])) ?? [];
      if (donors.length) {
        const donor = clone(rng.pick(donors)).data ?? {};
        const keys = Object.keys(donor);
        if (keys.length) { const key = rng.pick(keys); put(input.event.data, key, donor[key]); }
      }
    }
    if (roll >= 0.08) input.event = mutateValue(rng, input.event, state.dict, 3);
    return input;
  },
  async check({ event, format, position }, state) {
    let ts;
    // Both sides validate the same wire object (markers undecoded: the capture decodes them), as the Python worker receives it;
    // structuredClone, not a JSON round trip, which would turn -0 into 0 (the worker receives -0, see lib/python.mjs).
    try { ts = core.validateEvent(structuredClone(event), format, position); } catch (error) {
      return { failures: [crashFailure('validateEvent', error)], features: ['crash'] };
    }
    const failures = [];
    const type = typeof event?.type === 'string' ? event.type.slice(0, 40) : typeof event?.type;
    const features = [`${format}:${type}:${ts.ok}:${ts.code ?? ''}:${pathClass(ts.reason ?? '')}`];
    if (ts.ok) {
      let again;
      try { again = core.validateEvent(core.jsonParseWithBigints(core.jsonStringifyWithBigints(ts.event)), format, position); } catch (error) { again = { ok: false, reason: error.message }; }
      if (!again.ok || canonical(plain(again.event)) !== canonical(plain(ts.event))) {
        failures.push({ invariant: 'PARSE_SERIALIZE_IDENTITY', key: `EVENT_ROUNDTRIP:${type}`, message: `a validated ${type} does not re-validate identically after a wire round trip (${again.reason ?? 'different event'})` });
      }
    }
    if (state.ctx.python && format2Input({ format, event })) features.push(`py:skipped:${PYTHON_SKIP_REASON}`);
    else if (state.ctx.python) {
      const py = await state.ctx.python.request({ op: 'event', event, format, position });
      if (py.crash) failures.push({ invariant: 'UNTYPED_CRASH', key: `PY_CRASH:validate_event:${py.crash.split(':')[0]}:${py.where?.at(-1)}`, message: `python validate_event: ${py.crash}`, detail: py });
      else if (py.ok !== ts.ok || (!ts.ok && py.code !== ts.code)) {
        failures.push({ invariant: 'TS_PY_DISAGREE', key: `EVENT:${type}:ts=${ts.ok ? 'OK' : ts.code}:py=${py.ok ? 'OK' : py.code}`,
          message: `validateEvent ${format} ${type}@${position}: TypeScript ${ts.ok ? 'OK' : `${ts.code} (${ts.reason})`}, Python ${py.ok ? 'OK' : py.code}` });
      } else if (ts.ok && canonical(py.event) !== canonical(plain(ts.event))) {
        failures.push({ invariant: 'TS_PY_DISAGREE', key: `EVENT_CAPTURE:${type}`, message: `validateEvent ${type}: the captured events differ` });
      }
    }
    return { failures, features, outcome: { ts: { ok: ts.ok, code: ts.code ?? null } } };
  },
};
