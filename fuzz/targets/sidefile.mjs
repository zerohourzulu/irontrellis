/**
 * Target `sidefile`: the witness side file `<history>.witness.json` of a
 * history bound to a live witness (the seed's witness, restarted on the
 * port the binding pins), damaged in every field: policy, witnesses, cached
 * `latest` and seals, checkpoints, `held` receipts, split views, rejections,
 * the pending queue.
 *
 * TypeScript: `readWitnessState` (and its parse∘serialize identity), the strict
 * open, `witnessStatus()`, `verify()`, `checkWitnesses({force})` and
 * `verifyWithWitnesses()`, on the current history and on an older copy of it
 * (truncated to a head the owner attested, as a restored backup would be).
 *
 * Invariants: typed errors only (no crash, no unhandled rejection); the side
 * file may only make things stricter: when the pristine side file lets the
 * witness expose the older copy as a rollback, no mutated side file makes it
 * pass (`verifyWithWitnesses().ok`, `checkWitnesses()` resolving).
 */
import { cpSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { core, plain, revive, signerLib } from '../lib/env.mjs';
import { crashFailure, isTypedError } from '../lib/invariants.mjs';
import { Dictionary, clone, mutateText, mutateValue } from '../lib/mutate.mjs';
import { SEED_CACHE, keyRegistry, storeSeeds } from '../lib/seeds.mjs';
import { encodeHistory, parseHistory, pinFor } from '../lib/storefile.mjs';

const SIDE = 'history.jsonl.witness.json';

async function settle(where, fn, failures) {
  try { return { ok: true, value: await fn() }; } catch (error) {
    if (isTypedError(error)) return { ok: false, code: error.code, reason: error.detail?.reason ?? null };
    failures.push(crashFailure(where, error));
    return { ok: false, code: 'CRASH' };
  }
}

export default {
  name: 'sidefile',
  async setup(ctx) {
    const seed = (await storeSeeds()).find((s) => s.name === 'witnessed');
    const { format, events } = parseHistory(seed.files['history.jsonl'].toString('utf8'));
    const side = JSON.parse(seed.files[SIDE].toString('utf8'));
    const url = side.policy?.witnesses?.[0]?.url;
    const work = mkdtempSync(join(tmpdir(), 'irontrellis-fuzz-sidefile-'));
    // The witness, restarted on the port the history's binding pins, from a copy of the seed witness's data.
    let server;
    const seedDir = join(SEED_CACHE, 'witnessed', 'witness-data');
    try {
      const data = join(work, 'witness-data');
      cpSync(seedDir, data, { recursive: true });
      const { witness } = await import('../lib/env.mjs');
      const lib = await witness();
      server = await lib.serve({ dataDir: data, listen: new URL(url).host, forceUnlock: true, logger: { info() {}, warn() {}, error() {} }, configOverride: { rateLimit: { perIpPerMinute: 0, perHistoryPerMinute: 0, monitoringPerIpPerMinute: 0 } } });
    } catch (error) {
      ctx.log(`sidefile: no live witness (${error.message}); network checks run against an unreachable witness`);
    }
    // Older copies: the history cut back to each head from the binding on, with an owner-attested pin for that head.
    const registry = keyRegistry();
    const state = core.replay(revive(events)).state;
    const copies = new Map();
    for (let p = 2; p < events.length; p += 1) {
      const keys = core.ownerKeysAt(state, p);
      const signer = registry.get(keys[0].credential.toLowerCase());
      const head = { hash: state.eventHistoryHashes[p], position: p, canonicalTime: state.events[p].timestamp };
      const attestation = plain(signerLib.attestHeadSync(signer, state.genesis.domain, head, 'sha256'));
      copies.set(p, { history: encodeHistory(format, events.slice(0, p + 1)), pin: `${JSON.stringify(pinFor(format, events, p, { attestation }))}\n` });
    }
    const dict = new Dictionary();
    dict.add(side);
    dict.add(events);
    return { ctx, work, server, seed, side, dict: dict.freeze(), copies, last: events.length - 1, baseline: new Map(), counter: 0 };
  },
  seedInputs(state) {
    return [...state.copies.keys()].map((position) => ({ position, side: JSON.stringify(state.side) }));
  },
  mutate(rng, base, state) {
    const input = clone(base);
    if (rng.chance(0.15)) input.position = rng.pick([...state.copies.keys()]);
    const roll = rng.float();
    if (roll < 0.05) input.side = null;
    else if (roll < 0.25) input.side = mutateText(rng, input.side ?? JSON.stringify(state.side), 2);
    else {
      let doc;
      try { doc = JSON.parse(input.side ?? ''); } catch { doc = clone(state.side); }
      input.side = JSON.stringify(mutateValue(rng, doc, state.dict, 3));
    }
    return input;
  },
  async run(input, state, failures) {
    const dir = join(state.work, `case-${(state.counter += 1)}`);
    cpSync(join(SEED_CACHE, 'witnessed'), dir, { recursive: true, filter: (source) => !source.includes('witness-data') });
    const copy = state.copies.get(input.position);
    writeFileSync(join(dir, 'history.jsonl'), copy.history);
    writeFileSync(join(dir, 'history.jsonl.head'), copy.pin);
    if (input.side === null) rmSync(join(dir, SIDE), { force: true }); else writeFileSync(join(dir, SIDE), input.side);
    const path = join(dir, 'history.jsonl');
    const out = {};
    try {
      const read = await settle('readWitnessState', () => core.readWitnessState(join(dir, SIDE)), failures);
      out.read = read.ok ? 'ok' : read.code;
      if (read.ok) { // parse∘serialize identity of what the reader accepts
        writeFileSync(join(dir, 'again.json'), `${core.jsonStringifyWithBigints(read.value)}\n`);
        const again = await settle('readWitnessState(again)', () => core.readWitnessState(join(dir, 'again.json')), failures);
        if (!again.ok || core.jsonStringifyWithBigints(again.value) !== core.jsonStringifyWithBigints(read.value)) {
          failures.push({ invariant: 'PARSE_SERIALIZE_IDENTITY', key: 'SIDEFILE_ROUNDTRIP', message: `a side file readWitnessState accepts does not read back identically (${again.code ?? 'differs'})` });
        }
      }
      let store;
      const opened = await settle('openHistoryStore', () => { store = core.openHistoryStore(path, {}); return store.state(); }, failures);
      out.open = opened.ok ? 'ok' : `${opened.code}:${opened.reason ?? ''}`;
      if (opened.ok) {
        const status = await settle('witnessStatus', () => store.witnessStatus(), failures);
        out.status = status.ok ? (status.value === undefined ? 'none' : 'some') : status.code;
        const verified = await settle('verify', () => store.verify(), failures);
        out.verify = verified.ok ? verified.value.ok : verified.code;
        const checked = await settle('checkWitnesses', () => store.checkWitnesses({ force: true }), failures);
        out.check = checked.ok ? 'ok' : `${checked.code}:${checked.reason ?? ''}`;
        const remote = await settle('verifyWithWitnesses', () => store.verifyWithWitnesses({}), failures);
        out.remote = remote.ok ? (remote.value.ok ? 'ok' : remote.value.failures.map((f) => f.split(':')[0]).sort().join('+')) : remote.code;
        try { store.close(); } catch { /* closed */ }
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    return out;
  },
  async check(input, state) {
    const failures = [];
    if (!state.baseline.has(input.position)) state.baseline.set(input.position, await this.run({ position: input.position, side: JSON.stringify(state.side) }, state, []));
    const baseline = state.baseline.get(input.position);
    const out = await this.run(input, state, failures);
    // The side file may only make things stricter: a rollback the pristine file lets the witness expose stays exposed.
    const exposed = (o) => o.open !== 'ok' || o.check !== 'ok' || o.remote !== 'ok';
    if (state.server && exposed(baseline) && !exposed(out)) {
      failures.push({ invariant: 'SIDEFILE_WEAKENED', key: `SIDEFILE_WEAKENED:${baseline.open}:${baseline.check}`, message: `with the pristine side file the copy at position ${input.position} is refused (${JSON.stringify(baseline)}); the mutated side file lets it pass (${JSON.stringify(out)})` });
    }
    const features = [`read:${out.read}`, `open:${out.open}:check:${out.check}:remote:${out.remote}:p${input.position === state.last ? 'head' : 'older'}`];
    return { failures, features, outcome: out };
  },
  async teardown(state) {
    await state.server?.close();
    rmSync(state.work, { recursive: true, force: true });
  },
};
