/**
 * The deterministic CI smoke run as node:test cases: for each target, its
 * regression vectors, then SMOKE_ITERATIONS iterations of campaign seed 1.
 * Used by packages/{core,witness,cli}/test/fuzz-smoke.test.mjs (the whole smoke
 * run, all targets, stays well under 60 s on a 2-CPU machine). The Python
 * differential runs when python3 can import the package, and is skipped (with a
 * diagnostic) otherwise.
 */
import assert from 'node:assert/strict';
import { SMOKE_ITERATIONS, createContext, replayRegressions, runCampaign } from './campaign.mjs';

export function registerSmokeTests(test, targets) {
  let context;
  test.before(() => { context = createContext({ python: true, log: (line) => test.diagnostic?.(line) }); });
  test.after(() => context?.close());
  for (const target of targets) {
    test(`fuzz smoke: ${target} (regression vectors + ${SMOKE_ITERATIONS[target]} iterations, seed 1)`, async (t) => {
      if (context.python === undefined) t.diagnostic('python3 with the irontrellis package is not available: TypeScript-only invariants');
      const regressions = await replayRegressions({ targets: [target], context });
      const broken = regressions.filter((r) => !r.ok);
      assert.deepEqual(broken.map((r) => `${r.id}: ${r.problems.join('; ')}`), [], 'every regression vector holds');
      const report = await runCampaign({ target, seed: 1, iterations: SMOKE_ITERATIONS[target], context });
      t.diagnostic(`${target}: ${report.iterations} iterations in ${report.seconds} s, ${report.features} outcome classes, ${regressions.length} regression vectors`);
      assert.deepEqual(report.failures.map((f) => `${f.key}\n  ${f.message}\n  input: ${JSON.stringify(f.input).slice(0, 600)}`), [], 'no invariant failed');
    });
  }
}
