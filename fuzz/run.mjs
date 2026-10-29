#!/usr/bin/env node
/**
 * IronTrellis fuzzer and TypeScript/Python differential harness (fuzz/README.md).
 *
 *   node fuzz/run.mjs --target replay --seed 7 --minutes 15 --corpus fuzz-corpus [--resume] [--minimize]
 *   node fuzz/run.mjs --target all --iterations 200 --seed 1
 *   node fuzz/run.mjs --smoke                  # the deterministic CI smoke run (regressions + a few iterations per target)
 *   node fuzz/run.mjs --regressions            # replay fuzz/regressions/** only
 *
 * Options: --target <name|all|a,b> · --seed <n> · --iterations <n> · --minutes <m> (per target) · --start <iteration>
 * · --corpus <dir> · --resume (continue at the iteration the corpus state recorded) · --minimize · --no-python
 * · --json (print the report as JSON). Exit 0: no invariant failed; 1: failures (listed); 2: usage or setup error.
 */
import { REGRESSIONS } from './lib/env.mjs';
import { SMOKE_ITERATIONS, TARGETS, createContext, replayRegressions, runCampaign } from './lib/campaign.mjs';

function parse(argv) {
  const args = { target: undefined, seed: 1, python: true, minimize: false, resume: false, json: false, smoke: false, regressions: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    const value = () => { const v = argv[++i]; if (v === undefined) throw new Error(`${a} needs a value`); return v; };
    if (a === '--target') args.target = value();
    else if (a === '--seed') args.seed = Number(value());
    else if (a === '--iterations') args.iterations = Number(value());
    else if (a === '--minutes') args.minutes = Number(value());
    else if (a === '--start') args.start = Number(value());
    else if (a === '--corpus') args.corpus = value();
    else if (a === '--resume') args.resume = true;
    else if (a === '--minimize') args.minimize = true;
    else if (a === '--no-python') args.python = false;
    else if (a === '--json') args.json = true;
    else if (a === '--smoke') args.smoke = true;
    else if (a === '--regressions') args.regressions = true;
    else if (a === '--help' || a === '-h') { console.log(`targets: ${TARGETS.join(', ')}\nregressions: ${REGRESSIONS}`); process.exit(0); }
    else throw new Error(`unknown argument ${a}`);
  }
  for (const key of ['seed', 'iterations', 'minutes', 'start']) if (args[key] !== undefined && !(Number.isFinite(args[key]) && args[key] >= 0)) throw new Error(`--${key} must be a non-negative number`);
  return args;
}

async function main() {
  let args;
  try { args = parse(process.argv.slice(2)); } catch (error) { console.error(error.message); return 2; }
  const log = args.json ? () => {} : (line) => console.log(line);
  const report = { regressions: [], campaigns: [] };
  const context = createContext({ python: args.python, log });
  try {
    if (args.smoke || args.regressions) {
      report.regressions = await replayRegressions({ context, log });
      log(`regressions: ${report.regressions.filter((r) => r.ok).length}/${report.regressions.length} pass`);
    }
    const targets = args.smoke ? TARGETS : args.target === undefined ? [] : args.target === 'all' ? TARGETS : args.target.split(',');
    for (const target of targets) {
      const iterations = args.smoke ? SMOKE_ITERATIONS[target] : args.iterations;
      if (!args.smoke && iterations === undefined && args.minutes === undefined) { console.error('give --iterations or --minutes'); return 2; }
      const result = await runCampaign({
        target, seed: args.smoke ? 1 : args.seed, iterations, minutes: args.smoke ? undefined : args.minutes, start: args.start, corpus: args.corpus, resume: args.resume,
        minimizeFailures: args.minimize, context, log,
      });
      report.campaigns.push(result);
      log(`[${target}] seed ${result.seed}: ${result.iterations} iterations from ${result.start} in ${result.seconds} s (${result.execPerSecond}/s), ${result.features} outcome classes, ${result.failures.length} failure keys${result.python ? '' : ' (no python)'}`);
      for (const failure of result.failures) log(`  ${failure.count}× ${failure.key}\n     ${failure.message}`);
    }
  } finally {
    context.close();
  }
  if (args.json) console.log(JSON.stringify(report, null, 1));
  const failed = report.regressions.some((r) => !r.ok) || report.campaigns.some((c) => c.failures.length > 0);
  return failed ? 1 : 0;
}

main().then((code) => { process.exitCode = code; }, (error) => { console.error(error?.stack ?? error); process.exitCode = 2; });
