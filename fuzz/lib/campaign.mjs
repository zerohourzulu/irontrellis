/**
 * Campaign driver: seeded, resumable, time- or iteration-boxed runs of one
 * target, outcome-feature feedback (an input that produces an outcome class
 * never seen before joins the mutation queue), failure de-duplication by
 * failure key, optional minimization, and replay of the regression vectors.
 *
 * Corpus directory layout (`--corpus <dir>`, one per campaign family):
 *   <dir>/<target>/queue/<hash>.json      inputs that produced a new outcome class (mutation bases on resume)
 *   <dir>/<target>/state-<seed>.json      { nextIteration, iterations, features, failures } for --resume
 *   <dir>/<target>/failures/<hash>.json   one record per failure key (first input, minimized input)
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { REGRESSIONS } from './env.mjs';
import { minimize } from './minimize.mjs';
import { Rng } from './prng.mjs';
import { PythonWorker, pythonAvailable, stringifyFaithful } from './python.mjs';

export const TARGETS = ['canonical', 'events', 'replay', 'store', 'sidefile', 'transparency', 'witness-http', 'cli-args'];
const MAX_QUEUE = 3000;
/** The CI smoke budget: deterministic iterations per target (seed 1), sized to finish well inside 60 s on a 2-CPU runner. */
export const SMOKE_ITERATIONS = Object.freeze({ canonical: 1000, events: 800, replay: 120, store: 80, sidefile: 150, transparency: 1000, 'witness-http': 400, 'cli-args': 150 });

export async function loadTarget(name) {
  if (!TARGETS.includes(name)) throw new Error(`unknown target ${name} (${TARGETS.join(', ')})`);
  return (await import(`../targets/${name}.mjs`)).default;
}

const digest = (value) => createHash('sha256').update(stringifyFaithful(value)).digest('hex').slice(0, 16);
const readJson = (file) => JSON.parse(readFileSync(file, 'utf8'));

async function withTimeout(promise, ms, what) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(Object.assign(new Error(`${what} did not finish within ${ms} ms`), { code: 'HANG' })), ms); })]);
  } finally {
    clearTimeout(timer);
  }
}

/** A context for a target: the Python worker when available and wanted. */
export function createContext({ python = true, log = () => {} } = {}) {
  const worker = python && pythonAvailable() ? new PythonWorker() : undefined;
  if (python && worker === undefined) log('python3 with the irontrellis package is not available: differential checks are skipped');
  return { python: worker, log, close: () => worker?.close() };
}

/** Promise rejections nobody handled (an engine that leaves a rejected promise behind is a crash too), drained per check. */
const unhandled = [];
process.on('unhandledRejection', (reason) => { unhandled.push(reason); });

async function checkOnce(target, state, input, timeoutMs) {
  try {
    const result = await withTimeout(target.check(input, state), timeoutMs, `${target.name} check`);
    await new Promise((resolve) => setImmediate(resolve));
    const failures = result.failures ?? [];
    for (const reason of unhandled.splice(0)) {
      failures.push({ invariant: 'UNHANDLED_REJECTION', key: `UNHANDLED_REJECTION:${target.name}:${reason?.name}:${reason?.code ?? ''}:${String(reason?.message).slice(0, 60)}`, message: `unhandled promise rejection: ${String(reason?.stack ?? reason).slice(0, 400)}` });
    }
    return { failures, features: result.features ?? [], outcome: result.outcome };
  } catch (error) {
    const hang = error?.code === 'HANG';
    return { failures: [{ invariant: hang ? 'HANG' : 'HARNESS_ERROR', key: `${hang ? 'HANG' : 'HARNESS_ERROR'}:${target.name}:${String(error?.message).slice(0, 80)}`, message: String(error?.stack ?? error).slice(0, 600) }], features: [], hang };
  }
}

/**
 * Runs one campaign. Stops after `iterations` iterations or `minutes` minutes (whichever first; at least one of them).
 * Returns `{ target, seed, start, iterations, seconds, execPerSecond, features, failures: [{key, count, first, …}] }`.
 */
export async function runCampaign(options) {
  const { target: name, seed = 1, corpus, minimizeFailures = false, resume = false, log = () => {}, iterationTimeoutMs = 60_000 } = options;
  const target = await loadTarget(name);
  const ctx = options.context ?? createContext({ python: options.python !== false, log });
  const dir = corpus === undefined ? undefined : join(corpus, name);
  if (dir) for (const sub of ['queue', 'failures']) mkdirSync(join(dir, sub), { recursive: true });
  const stateFile = dir && join(dir, `state-${seed}.json`);
  const saved = resume && stateFile && existsSync(stateFile) ? readJson(stateFile) : undefined;
  let start = options.start ?? saved?.nextIteration ?? 0;
  const features = new Set(saved?.features ?? []);
  const queue = [];
  if (dir) for (const file of readdirSync(join(dir, 'queue')).sort().slice(0, MAX_QUEUE)) { try { queue.push(readJson(join(dir, 'queue', file))); } catch { /* skip */ } }

  const state = await target.setup(ctx);
  const bases = target.seedInputs(state);
  const failures = new Map();
  const deadline = options.minutes === undefined ? Infinity : Date.now() + options.minutes * 60_000;
  const limit = options.iterations ?? Infinity;
  if (limit === Infinity && deadline === Infinity) throw new Error('give --iterations or --minutes');
  const began = Date.now();
  let done = 0, lastLog = Date.now();
  const persist = () => {
    if (!stateFile) return;
    writeFileSync(stateFile, JSON.stringify({ target: name, seed, nextIteration: start + done, iterations: (saved?.iterations ?? 0) + done, features: [...features].slice(0, 20_000),
      failures: [...failures.values()].map((f) => ({ key: f.key, count: f.count, iteration: f.iteration })) }, null, 1));
  };
  try {
    for (; done < limit && Date.now() < deadline; done += 1) {
      const iteration = start + done;
      const rng = Rng.for(name, seed, iteration);
      const base = queue.length > 0 && rng.chance(0.35) ? rng.pick(queue) : rng.pick(bases);
      let input, result;
      try {
        // Every target sees exactly the JSON form the corpus stores and Python receives (-0 kept): no undefined, NaN,
        // holes or prototypes that only the in-process TypeScript side would see.
        input = JSON.parse(stringifyFaithful(await target.mutate(rng, base, state)));
      } catch (error) { // a harness defect: report it and go on (long campaigns run unattended)
        input = base;
        result = { failures: [{ invariant: 'HARNESS_ERROR', key: `HARNESS_ERROR:${name}:mutate:${String(error?.message).slice(0, 80)}`, message: `mutate failed at iteration ${iteration}: ${String(error?.stack).slice(0, 600)}`, mutate: true }], features: [] };
      }
      result ??= await checkOnce(target, state, input, iterationTimeoutMs);
      if (result.hang && target.reset) await target.reset(state);
      for (const feature of result.features) {
        if (features.has(feature)) continue;
        features.add(feature);
        if (queue.length < MAX_QUEUE) {
          queue.push(input);
          if (dir) writeFileSync(join(dir, 'queue', `${digest(input)}.json`), stringifyFaithful(input));
        }
      }
      for (const failure of result.failures) {
        const known = failures.get(failure.key);
        if (known) { known.count += 1; continue; }
        const record = { target: name, seed, iteration, key: failure.key, invariant: failure.invariant, message: failure.message, detail: failure.detail, count: 1, input };
        failures.set(failure.key, record);
        log(`[${name}] FAILURE ${failure.invariant} at iteration ${iteration}: ${failure.message}`);
        if (minimizeFailures && !failure.mutate) { // a mutator crash does not reproduce from its (unmutated) input
          const shrunk = await minimize(input, async (candidate) => (await checkOnce(target, state, candidate, iterationTimeoutMs)).failures.some((f) => f.key === failure.key),
            { budget: 800, deadlineMs: 90_000, protect: target.protect });
          record.minimized = shrunk.input;
          log(`[${name}]   minimized with ${shrunk.checks} checks: ${JSON.stringify(shrunk.input).length} bytes (from ${JSON.stringify(input).length})`);
        }
        if (dir) writeFileSync(join(dir, 'failures', `${digest(failure.key)}.json`), stringifyFaithful(record, 1));
      }
      if (Date.now() - lastLog > 15_000) {
        lastLog = Date.now();
        log(`[${name}] ${done} iterations, ${(done / ((Date.now() - began) / 1000)).toFixed(1)}/s, ${features.size} outcome classes, ${failures.size} failure keys`);
        persist();
      }
    }
  } finally {
    persist();
    await target.teardown?.(state);
    if (options.context === undefined) ctx.close();
  }
  const seconds = (Date.now() - began) / 1000;
  return {
    target: name, seed, start, iterations: done, seconds: Math.round(seconds * 10) / 10, execPerSecond: Math.round((done / Math.max(seconds, 0.001)) * 10) / 10,
    features: features.size, python: ctx.python !== undefined, failures: [...failures.values()],
  };
}

// ---------------------------------------------------------------- regression vectors

/** Declared-field projection (as conformance/run.mjs): the fields `expected` names must match exactly. */
export function differences(expected, actual, path = '') {
  const kind = (v) => (v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v);
  if (kind(expected) !== kind(actual)) return [`${path || '.'}: expected ${kind(expected)} ${JSON.stringify(expected)?.slice(0, 80)}, got ${kind(actual)} ${JSON.stringify(actual)?.slice(0, 80)}`];
  if (kind(expected) === 'object') return Object.entries(expected).flatMap(([key, value]) => (Object.hasOwn(actual, key) ? differences(value, actual[key], `${path}.${key}`) : [`${path}.${key}: missing`]));
  if (kind(expected) === 'array') return expected.length !== actual.length ? [`${path}: expected ${expected.length} entries, got ${actual.length}`] : expected.flatMap((v, i) => differences(v, actual[i], `${path}[${i}]`));
  return Object.is(expected, actual) ? [] : [`${path || '.'}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`];
}

export function regressionVectors(targets = TARGETS) {
  const out = [];
  for (const name of targets) {
    const dir = join(REGRESSIONS, name);
    if (!existsSync(dir)) continue;
    for (const file of readdirSync(dir).filter((f) => f.endsWith('.json')).sort()) out.push({ file: join(dir, file), vector: readJson(join(dir, file)) });
  }
  return out;
}

/** Replays every regression vector: no invariant may fail, and each declared `expect` projection must match the outcome. */
export async function replayRegressions({ targets = TARGETS, python = true, log = () => {}, context } = {}) {
  const ctx = context ?? createContext({ python, log });
  const results = [];
  try {
    for (const name of targets) {
      const vectors = regressionVectors([name]);
      if (vectors.length === 0) continue;
      const target = await loadTarget(name);
      const state = await target.setup(ctx);
      try {
        for (const { file, vector } of vectors) {
          const result = await checkOnce(target, state, vector.input, 120_000);
          const problems = result.failures.map((f) => `${f.invariant}: ${f.message}`);
          if (vector.expect !== undefined) {
            if (result.outcome === undefined) problems.push('the target reported no outcome to compare with expect');
            else if (vector.requires !== 'python' || ctx.python !== undefined) problems.push(...differences(vector.expect, result.outcome));
          }
          results.push({ target: name, id: vector.id, file, ok: problems.length === 0, problems });
          if (problems.length) log(`[regression] ${vector.id}: ${problems.join('; ')}`);
        }
      } finally {
        await target.teardown?.(state);
      }
    }
  } finally {
    if (context === undefined) ctx.close();
  }
  return results;
}
