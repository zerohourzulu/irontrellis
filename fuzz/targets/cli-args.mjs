/**
 * Target `cli-args`: the `irontrellis` command line (packages/cli), run in a
 * child process (fuzz/lib/cli-worker.mjs) against a real history made with
 * `irontrellis init` (owner key, next-key commitment, agents, roles, grants).
 * Inputs are argument vectors: valid invocations of every command, then token
 * mutations (drops, duplicates, swaps, `--x=`, `--no-x`, `--`, unknown and
 * repeated options, oversized, negative, non-decimal and unsafe numbers,
 * control characters, lone surrogates, huge lists, other commands' options).
 *
 * Invariants: `main` never rejects and returns an integer exit code; no error is
 * the untyped `FAILED` (an exception the CLI did not classify); with `--json`
 * stdout is exactly one JSON document; nothing is written to the real stdout
 * behind `io` and nothing is left unhandled; the process neither exits nor hangs.
 */
import { fork } from 'node:child_process';
import { cpSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FUZZ, t } from '../lib/env.mjs';
import { clone, interestingString, mutateString } from '../lib/mutate.mjs';

class CliWorker {
  constructor() { this.pending = new Map(); this.id = 0; this.stray = ''; }
  async start() {
    this.child = fork(join(FUZZ, 'lib', 'cli-worker.mjs'), [], { stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
    this.child.stdout.on('data', (chunk) => { this.stray += chunk; });
    this.child.stderr.on('data', (chunk) => { this.stray += chunk; });
    this.exited = undefined;
    this.child.on('exit', (code, signal) => {
      this.exited = `${code ?? signal}`;
      for (const [, waiter] of this.pending) waiter.resolve({ exited: this.exited });
      this.pending.clear();
    });
    await new Promise((resolve) => this.child.once('message', resolve));
    this.child.on('message', (message) => { const waiter = this.pending.get(message.id); if (waiter) { this.pending.delete(message.id); clearTimeout(waiter.timer); waiter.resolve(message.response); } });
  }
  run(request, timeoutMs = 20_000) {
    const id = (this.id += 1);
    return new Promise((resolve) => {
      const timer = setTimeout(() => { this.pending.delete(id); resolve({ hang: true }); }, timeoutMs);
      this.pending.set(id, { resolve, timer });
      this.child.send({ ...request, id });
    });
  }
  async restart() { try { this.child.kill('SIGKILL'); } catch { /* gone */ } await this.start(); }
  close() { try { this.child.kill('SIGKILL'); } catch { /* gone */ } }
}

const vkey = t.verifierKey('fuzz.cli.witness', new Uint8Array(32).fill(3));
const TEMPLATES = [
  ['status'], ['verify'], ['verify', '--allow-unpinned'], ['verify', '--no-remote'], ['repin'], ['export'], ['capacity'], ['owner', 'status'], ['owner', 'export-key-events', '--since', '0'],
  ['owner', 'commit-next-key'], ['owner', 'rotate-key', '--reason', 'fuzz'], ['agent', 'create', 'carol'], ['role', 'create', 'desk2'],
  ['appoint', 'bea', '--role', 'desk', '--tenure', 'desk:9', '--number', '2'], ['unappoint', 'bea', '--role', 'desk', '--tenure', 'desk:1'],
  ['succession', 'declare', 'rule:2', '--from', 'bea', '--to', 'alex', '--role', 'desk'],
  ['succeed', 'handover:9', '--rule', 'rule:1', '--from', 'bea', '--from-tenure', 'desk:1', '--to', 'alex', '--to-tenure', 'desk:2', '--role', 'desk', '--number', '2'],
  ['agent', 'terminate', 'alex', '--succession', 'rule:1', '--role', 'desk', '--tenure', 'desk:1'],
  ['session', 'admit', 's:9', '--agent', 'bea', '--epoch', '1', '--key', 'k:9', '--expires', '+1h', '--new-key', '{dir}/session-key.json'],
  ['session', 'admit', 's:8', '--agent', 'bea', '--epoch', '1', '--key', 'k:8', '--expires', '2030-01-01T00:00:00Z', '--address', `0x${'ab'.repeat(20)}`],
  ['epoch', 'advance', 'bea', '--from', '1', '--to', '2'],
  ['grant', 'g:9', '--to', 'bea', '--actions', 'read,write', '--resources', 'ledger', '--expires', '+30m', '--max-amount', '100', '--max-transactions', '3', '--delegable', '1'],
  ['delegate', 'd:9', '--parent', 'g:1', '--from', 'bea', '--to', 'alex', '--actions', 'read', '--resources', 'ledger', '--expires', '+10m'],
  ['prohibit', 'p:9', '--actions', 'pay', '--resources', 'ledger', '--global'], ['prohibit', 'p:8', '--actions', 'read', '--resources', 'ledger', '--root', 'g:1', '--subject', 'bea'],
  ['revoke', 'g:1'], ['authorize', '--actor', 'bea', '--action', 'read', '--resource', 'ledger', '--amount', '5'],
  ['why', '--actor', 'bea', '--action', 'read', '--resource', 'ledger'], ['responsible', '--actor', 'bea', '--action', 'read', '--resource', 'ledger', '--position', '3'],
  ['why', '--intent', 'intent:1'], ['survives', 'bea'], ['handover', 'bea'], ['anchor', '--witness', 'local'], ['anchor', '--witness', 'http', '--url', 'http://127.0.0.1:1/'],
  ['witness', 'status', '--no-remote'], ['witness', 'add', 'http://127.0.0.1:1', '--verifier-key', vkey, '--allow-offline'], ['witness', 'sync'], ['witness', 'remove', vkey],
  ['migrate', '{dir}/h.jsonl', '{dir}/migrated.jsonl'], ['init', '--history', '{dir}/new.jsonl', '--owner', 'o2', '--no-next-key'], ['init', '--history', '{dir}/legacy.jsonl', '--legacy'],
  ['--help'], ['--version'], ['grant', '--help'], ['help'],
];
const VALUES = ['bea', 'alex', 'desk', 'desk:1', 'g:1', 'rule:1', '0', '1', '-1', '01', '1e3', '9007199254740991', '9007199254740993', '99999999999999999999999999', '+30m', '+0s', '+99999999999d', '2030-01-01', 'yesterday', '',
  'a,b', ',', 'a,,b', ' a ', Array.from({ length: 40 }, (_, i) => `x${i}`).join(','), 'x'.repeat(129), 'x'.repeat(5000), '\u0000', '\u007f', '\ud800', 'é', '--', '-', '-x', '--json', '=', 'true', 'false',
  '{dir}/h.jsonl', '{dir}', '{dir}/nope/x.jsonl', '/dev/null', '.', `0x${'ab'.repeat(20)}`, `0x${'ab'.repeat(32)}`, vkey, 'http://127.0.0.1:1', 'https://[::1]:1', 'file:///etc/passwd', 'local', 'rekor', 'sync', 'async'];

export default {
  name: 'cli-args',
  async setup(ctx) {
    const worker = new CliWorker();
    await worker.start();
    const template = mkdtempSync(join(tmpdir(), 'irontrellis-fuzz-cli-template-'));
    const env = { IRONTRELLIS_HISTORY: join(template, 'h.jsonl') };
    const setupSteps = [['init', '--owner', 'ops', '--controller', 'op'], ['agent', 'create', 'bea'], ['agent', 'create', 'alex'], ['role', 'create', 'desk'],
      ['succession', 'declare', 'rule:1', '--from', 'bea', '--to', 'alex', '--role', 'desk'], ['appoint', 'bea', '--role', 'desk', '--tenure', 'desk:1', '--number', '1', '--succession', 'rule:1'],
      ['grant', 'g:1', '--to', 'bea', '--actions', 'read,pay', '--resources', 'ledger', '--expires', '+1d', '--delegable', '2', '--max-amount', '1000']];
    for (const argv of setupSteps) {
      const result = await worker.run({ argv: [...argv, '--json'], env, cwd: template });
      if (result.code !== 0) throw new Error(`cli-args setup: ${argv.join(' ')} → ${JSON.stringify(result).slice(0, 400)}`);
    }
    const work = mkdtempSync(join(tmpdir(), 'irontrellis-fuzz-cli-'));
    return { ctx, worker, template, work, runs: 0, dir: undefined };
  },
  seedInputs() { return TEMPLATES.map((argv) => ({ argv: [...argv, '--json'] })); },
  mutate(rng, base) {
    const argv = clone(base.argv);
    const count = 1 + rng.small(3);
    for (let m = 0; m < count; m += 1) {
      const i = rng.int(Math.max(1, argv.length));
      switch (rng.int(12)) {
        case 0: argv.splice(i, 1); break;
        case 1: argv.splice(i, 0, argv[i] ?? '--json'); break;
        case 2: { const j = rng.int(argv.length); [argv[i], argv[j]] = [argv[j], argv[i]]; break; }
        case 3: argv.splice(i, 0, rng.pick(VALUES)); break;
        case 4: if (argv[i]?.startsWith('--') && argv[i + 1] !== undefined && !argv[i + 1].startsWith('--')) argv.splice(i, 2, `${argv[i]}=${argv[i + 1]}`); else argv[i] = rng.pick(VALUES); break;
        case 5: argv.splice(i, 0, rng.pick(['--', '--no-json', '--json=false', '--json=true', '--help=false', '--at', '--history', '--owner', '--controller', '--version', '-h', '--unknown'])); break;
        case 6: argv[i] = mutateString(rng, argv[i] ?? ''); break;
        case 7: argv[i] = interestingString(rng); break;
        case 8: argv.splice(i, 0, rng.pick(['--at', '--history', '--owner', '--controller']), rng.pick(VALUES)); break;
        case 9: { const other = rng.pick(TEMPLATES); argv.push(...other.slice(1)); break; }
        case 10: argv.splice(0, argv.length, ...rng.pick(TEMPLATES).slice(0, 2), ...argv.slice(2)); break;
        default: if (argv[i]?.startsWith('--')) argv.splice(i, 0, `--no-${argv[i].slice(2)}`); break;
      }
    }
    return { argv: argv.filter((a) => typeof a === 'string'), json: rng.chance(0.85) };
  },
  async check(input, state) {
    if (state.dir === undefined || state.runs % 25 === 0) {
      if (state.dir) rmSync(state.dir, { recursive: true, force: true });
      state.dir = join(state.work, `case-${state.runs}`);
      cpSync(state.template, state.dir, { recursive: true });
    }
    state.runs += 1;
    const argv = input.argv.map((a) => a.replaceAll('{dir}', state.dir));
    if (input.json !== false && !argv.includes('--json')) argv.push('--json');
    state.worker.stray = '';
    const result = await state.worker.run({ argv, env: { IRONTRELLIS_HISTORY: join(state.dir, 'h.jsonl') }, cwd: state.dir });
    const failures = [];
    const head = argv.slice(0, 2).join(' ').replace(/\{[^}]*\}|[^\x20-\x7e]/g, '?').slice(0, 30);
    if (result.hang) { failures.push({ invariant: 'HANG', key: `CLI_HANG:${head}`, message: `irontrellis ${argv.join(' ').slice(0, 200)} did not finish in 20 s` }); await state.worker.restart(); }
    else if (result.exited !== undefined) { failures.push({ invariant: 'UNTYPED_CRASH', key: `CLI_EXIT:${head}`, message: `the CLI process exited (${result.exited}) during irontrellis ${argv.join(' ').slice(0, 200)}` }); await state.worker.restart(); }
    else if (result.threw) failures.push({ invariant: 'UNTYPED_CRASH', key: `CLI_THREW:${result.threw.slice(0, 60)}`, message: `main() rejected: ${result.threw}`, detail: result.stack });
    else {
      if (!Number.isInteger(result.code)) failures.push({ invariant: 'UNTYPED_CRASH', key: 'CLI_EXIT_CODE', message: `exit code ${result.code}` });
      let document;
      // JSON mode as args.ts decides it: the last --json / --json=true|false / --json true|false (a boolean option
      // takes a following "true" or "false" as its value) / --no-json before a `--`.
      let json = false;
      for (let k = 0; k < argv.length; k += 1) {
        const a = argv[k];
        if (a === '--') break;
        if (a === '--json' && (argv[k + 1] === 'true' || argv[k + 1] === 'false')) { json = argv[k + 1] === 'true'; k += 1; }
        else if (a === '--json' || a === '--json=true') json = true;
        else if (a === '--json=false' || a === '--no-json') json = false;
      }
      // Help is text whatever else is given (cli.ts: `--help` anywhere after the command, or `help` / `--help` / `--version` first).
      const help = /^(--help|help|--version|version)$/.test(argv[0] ?? '') || argv.includes('--help') || argv.includes('--help=true');
      if (json && !help) {
        try { document = JSON.parse(result.stdout); } catch { if (result.stdout.trim() !== '') failures.push({ invariant: 'CLI_OUTPUT', key: `CLI_JSON:${head}`, message: `--json output is not one JSON document: ${result.stdout.slice(0, 200)}` }); }
      }
      const code = document?.error?.code ?? /error: (\S+)/.exec(result.stderr)?.[1];
      if (code === 'FAILED') failures.push({ invariant: 'UNTYPED_CRASH', key: `CLI_FAILED:${head}:${(document?.error?.message ?? result.stderr).slice(0, 50)}`, message: `an unclassified error: ${JSON.stringify(document?.error ?? result.stderr).slice(0, 300)} for irontrellis ${argv.join(' ').slice(0, 200)}` });
      for (const reason of result.unhandled ?? []) failures.push({ invariant: 'UNHANDLED_REJECTION', key: `CLI_UNHANDLED:${reason.slice(0, 60)}`, message: reason });
      if (state.worker.stray.trim() !== '') failures.push({ invariant: 'CLI_OUTPUT', key: `CLI_STRAY_OUTPUT:${head}`, message: `written behind io: ${state.worker.stray.slice(0, 200)}` });
      return { failures, features: [`${head}:${result.code}:${code ?? ''}`], outcome: { code: result.code, error: code ?? null } };
    }
    return { failures, features: ['abnormal'] };
  },
  async teardown(state) {
    state.worker.close();
    rmSync(state.work, { recursive: true, force: true });
    rmSync(state.template, { recursive: true, force: true });
  },
};
