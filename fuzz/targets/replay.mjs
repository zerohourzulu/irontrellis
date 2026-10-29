/**
 * Target `replay`: mutated histories (wire event arrays) through
 *  - the TypeScript engine in-process (`replay`, for the rejection position and the invariants),
 *  - the TypeScript conformance adapter process (conformance/adapters/node.mjs),
 *  - the Python engine and the Python conformance adapter (fuzz/python/worker.py).
 *
 * Invariants: `replay` never throws; TypeScript and Python agree on
 * ACCEPTED/REJECTED, the rejection code and position, and the accepted head;
 * the two conformance adapters give identical answers; an accepted history
 * carries no seed owner signature over altered content; an accepted history
 * re-replays to the same head after a wire round trip; and, on a sample of
 * accepted histories, SURVIVES and authorize answers agree between the
 * adapters (the conformance projections).
 */
import { core, plain, signerLib } from '../lib/env.mjs';
import { controlTemplates, mutateHistory } from '../lib/history.mjs';
import { crashFailure, signatureIndex, signedContentFailures } from '../lib/invariants.mjs';
import { Dictionary, mutateValue } from '../lib/mutate.mjs';
import { NodeAdapter, PYTHON_SKIP_REASON, format2Input } from '../lib/python.mjs';
import { keyRegistry, replaySeeds, storeSeeds } from '../lib/seeds.mjs';

const reasonClass = (reason) => String(reason ?? '').replace(/"[^"]*"/g, 'S').replace(/\b[\w:.-]*\d[\w:.-]*\b/g, 'N').split(/\s+/).slice(0, 9).join(' ');
// Adapter errors: the Python adapter prefixes the exception class (`TypeError: …`), the node adapter does not.
const errorClass = (text) => { const bare = String(text).replace(/^[A-Za-z]*Error: /, ''); return /[A-Z][A-Z_]{4,}/.exec(bare)?.[0] ?? bare.slice(0, 40); };
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

function tsReplay(events) {
  let result;
  // structuredClone, not a JSON round trip: that would turn -0 into 0, which the adapters and Python receive as -0.
  try { result = core.replay(structuredClone(events)); } catch (error) { return { crash: crashFailure('replay', error) }; }
  if (result.status === 'ACCEPTED') return { status: 'ACCEPTED', head: plain(result.head), eventCount: result.eventCount, state: result.state };
  return { status: 'REJECTED', code: result.code, position: result.position ?? null, reason: result.reason };
}

function evaluatorRequests(rng, events, state, registry, dict) {
  const agents = [...(state.agents?.keys?.() ?? [])];
  const agent = agents.length && rng.chance(0.85) ? rng.pick(agents) : 'nobody';
  const head = plain(state.head);
  const at = head.canonicalTime + rng.pick([0, 0, 1, 1000]);
  const survives = { op: 'survives', events, operationVersion: core.QUERY_VERSION, targetAgentId: agent, evaluationTime: at };
  const actions = [], resources = [];
  for (const record of state.authorities?.values?.() ?? []) {
    const c = record?.grant?.constraints;
    if (c) { actions.push(...(c.actions ?? [])); resources.push(...(c.resources ?? [])); }
  }
  const request = { actorId: agent, action: actions.length ? rng.pick(actions) : 'read', resource: resources.length ? rng.pick(resources) : 'ledger', claimedAt: at };
  if (rng.chance(0.3)) request.amount = { '$continuity.bigint': String(rng.pick([1, 50, 100, 101, 1000])) };
  const genesis = events[0].data;
  const authorize = {
    op: 'authorize', events, operationVersion: core.AUTHORIZATION_VERSION, expectedHistoryHead: head, domain: genesis.domain, policyVersion: genesis.policyVersion,
    rootRecognitionPolicy: genesis.rootRecognitionPolicy, request, evaluationTime: at, authoritative: true, consequential: false,
  };
  const requests = [survives, authorize];
  // A head attestation of this history (the key in force at a random head, sometimes mutated): the adapters' verify-attestation.
  if (state.format === core.TRELLIS_FORMAT && registry !== undefined) {
    const p = rng.int(state.events.length);
    const keys = core.ownerKeysAt(state, rng.chance(0.8) ? p : rng.int(state.events.length));
    const signer = keys.length ? registry.get(String(keys[0].credential).toLowerCase()) : undefined;
    if (signer !== undefined) {
      let attestation = plain(signerLib.attestHeadSync(signer, state.genesis.domain, { hash: state.eventHistoryHashes[p], position: p, canonicalTime: state.events[p].timestamp }, state.hashAlgorithm));
      if (rng.chance(0.5)) attestation = mutateValue(rng, attestation, dict, 1);
      requests.push({ op: 'verify-attestation', events, attestation });
    }
  }
  return requests;
}

export default {
  name: 'replay',
  async setup(ctx) {
    const stores = await storeSeeds();
    const histories = [...replaySeeds(), ...stores.map((s) => ({ name: `store/${s.name}`, events: s.events }))];
    const dict = new Dictionary();
    for (const { events } of histories) dict.add(events);
    return {
      ctx, histories, dict: dict.freeze(), registry: keyRegistry(), templates: controlTemplates(histories), index: signatureIndex(histories),
      node: new NodeAdapter(), evaluator: 0,
    };
  },
  seedInputs(state) { return state.histories.map(({ events }) => ({ events })); },
  async mutate(rng, base, state) {
    const format = core.detectFormat(base.events);
    const donors = state.histories.filter((h) => core.detectFormat(h.events) === format);
    let events = await mutateHistory(rng, base.events, { dict: state.dict, donors: donors.length ? donors : state.histories, templates: state.templates, registry: state.registry });
    if (rng.chance(0.25)) events = await mutateHistory(rng, events, { dict: state.dict, donors: donors.length ? donors : state.histories, templates: state.templates, registry: state.registry });
    return { events, evaluate: rng.u32() };
  },
  async check(input, state) {
    const { events } = input;
    const failures = [];
    const ts = tsReplay(events);
    if (ts.crash) return { failures: [ts.crash], features: ['crash'] };
    const features = [`ts:${ts.status}:${ts.code ?? ''}:${reasonClass(ts.reason)}`];
    const outcome = { ts: { status: ts.status, code: ts.code ?? null, position: ts.position ?? null } };
    if (ts.status === 'ACCEPTED') {
      failures.push(...signedContentFailures(state.index, ts.state, 'replay'));
      const again = tsReplay(ts.state.events.map((event) => plain(event)));
      if (again.status !== 'ACCEPTED' || !same(again.head, ts.head)) failures.push({ invariant: 'PARSE_SERIALIZE_IDENTITY', key: 'REPLAY_ROUNDTRIP', message: `an accepted history does not re-replay to the same head (${again.code ?? 'head differs'})` });
    }
    const tsAdapter = await state.node.raw({ op: 'replay', operationVersion: core.REPLAY_VERSION, events });
    if (state.ctx.python && format2Input({ events })) features.push(`py:skipped:${PYTHON_SKIP_REASON}`);
    else if (state.ctx.python) {
      const py = await state.ctx.python.request({ op: 'replay', events });
      const direct = py.direct;
      outcome.py = direct?.crash ? { crash: direct.crash } : { status: direct.status, code: direct.code ?? null, position: direct.position ?? null };
      if (direct.crash) {
        failures.push({ invariant: 'UNTYPED_CRASH', key: `PY_CRASH:replay:${direct.crash.split(':')[0]}:${direct.where?.at(-1)}`, message: `python replay: ${direct.crash}`, detail: direct });
      } else if (direct.status !== ts.status || (ts.status === 'REJECTED' && (direct.code !== ts.code || direct.position !== ts.position))) {
        failures.push({ invariant: 'TS_PY_DISAGREE', key: `REPLAY:ts=${ts.status}/${ts.code ?? ''}:py=${direct.status}/${direct.code ?? ''}${direct.code === ts.code ? ':position' : ''}`,
          message: `replay: TypeScript ${ts.status} ${ts.code ?? ''}@${ts.position ?? ''} (${ts.reason ?? ''}), Python ${direct.status} ${direct.code ?? ''}@${direct.position ?? ''}` });
      } else if (ts.status === 'ACCEPTED' && !same(direct.head, ts.head)) {
        failures.push({ invariant: 'TS_PY_DISAGREE', key: 'REPLAY_HEAD', message: `replay heads differ: ${JSON.stringify(ts.head)} vs ${JSON.stringify(direct.head)}` });
      }
      features.push(`py:${direct.status}:${direct.code ?? ''}`);
      // The conformance adapters, as the vectors see them.
      const pa = py.adapter;
      if (tsAdapter.ok !== pa.ok || (tsAdapter.ok && !same(tsAdapter.result, pa.result)) || (!tsAdapter.ok && errorClass(tsAdapter.error) !== errorClass(pa.error))) {
        failures.push({ invariant: 'TS_PY_DISAGREE', key: `ADAPTER_REPLAY:ts=${tsAdapter.ok ? tsAdapter.result.status : errorClass(tsAdapter.error)}:py=${pa.ok ? pa.result.status : errorClass(pa.error)}`,
          message: `conformance adapters disagree on replay: node ${JSON.stringify(tsAdapter).slice(0, 200)} python ${JSON.stringify(pa).slice(0, 200)}` });
      }
      // Evaluator level on a sample of accepted histories.
      if (ts.status === 'ACCEPTED' && direct.status === 'ACCEPTED' && input.evaluate % 2 === 0) {
        const { Rng } = await import('../lib/prng.mjs');
        for (const request of evaluatorRequests(new Rng(input.evaluate), events, ts.state, state.registry, state.dict)) {
          const [node, python] = await Promise.all([state.node.raw(request), state.ctx.python.request({ op: 'adapter', request })]);
          const nodeView = node.ok ? node.result : { error: errorClass(node.error) };
          const pyView = python.ok ? python.result : { error: errorClass(python.error) };
          if (!same(nodeView, pyView)) {
            failures.push({ invariant: 'TS_PY_DISAGREE', key: `ADAPTER_${request.op.toUpperCase()}:${nodeView.decision ?? nodeView.code ?? nodeView.error ?? ''}:${pyView.decision ?? pyView.code ?? pyView.error ?? ''}`,
              message: `conformance adapters disagree on ${request.op}: node ${JSON.stringify(nodeView).slice(0, 300)} python ${JSON.stringify(pyView).slice(0, 300)}`, detail: { request: { ...request, events: undefined } } });
          }
          features.push(`${request.op}:${nodeView.decision ?? nodeView.lifecycleStatus ?? nodeView.valid ?? nodeView.error}:${nodeView.code ?? nodeView.signatureValid ?? ''}`);
        }
      }
    }
    return { failures, features, outcome };
  },
  async teardown(state) { state.node.close(); },
};
