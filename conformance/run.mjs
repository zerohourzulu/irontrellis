#!/usr/bin/env node
/**
 * IronTrellis conformance runner (a port of conformance/legacy/run.py).
 *
 *   node conformance/run.mjs --adapter conformance/adapters/node.mjs [--suite legacy|v1|v2|v2-g3|v2-regenerated|v2-owner-policy|v2-human-attestation|all] [--level verifier|evaluator] [--filter text] [--profile frozen-r2.3|g3] [--json]
 *   node conformance/run.mjs --suite v1 -- python3 conformance/adapters/python.py
 *
 * `--suite all` runs legacy and v1; the format-2 suites run only when named: `v2` (frozen, the r2.3 record),
 * `v2-g3` (the reference generator re-run under the g3 challenge profile), `v2-regenerated` (the engine-derived suite),
 * `v2-owner-policy` and `v2-human-attestation`; any other `conformance/v2-<name>/` in the same layout runs under its MANIFEST.json `challengeProfile`. Each format-2 suite is signed under one session-challenge profile (A-54, A-59.3), which the runner
 * passes to the adapter as IRONTRELLIS_CHALLENGE_PROFILE: `frozen-r2.3` for v2, `g3` for the others;
 * `--profile` overrides it (e.g. to show that v2 does not verify under g3). Their loader and their additions to the protocol (SPEC-IRONTRELLIS-CORE-v2 §17) are
 * described in conformance/v2/README.md: new kinds `export` (verifier level), `headroom` and
 * `duty-view` (evaluator level); replay results also carry `stateRoot` and `projectionHead`,
 * authorization results `budgetId`, attestation results `stateRootValid` and `projectionValid` —
 * each compared only where a vector's `expect` declares it.
 *
 * An adapter is a long-lived process speaking the line protocol of
 * conformance/legacy/ADAPTER.md. `--adapter <file>` runs `.mjs`/`.js` files with
 * node and `.py` files with python3 (`python` on Windows, where python.org and
 * actions/setup-python install no python3; IRONTRELLIS_PYTHON overrides both);
 * anything after `--` is an explicit command.
 * Exit 0 = every selected vector matched, 1 = a completed response disagreed,
 * 2 = input/setup/transport failure, or an adapter that answered a vector with
 * `{"ok":false,…}` (reported per vector as ERROR; the run continues with the
 * next vector, unlike a broken transport). The comparison is the legacy runner's:
 * declared expected-field projections on objects, exact ordered arrays, exact
 * scalars with their JSON types, and tagged BigInt records compared exactly.
 */
import { spawn } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const PYTHON = process.env.IRONTRELLIS_PYTHON || (process.platform === 'win32' ? 'python' : 'python3');

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = dirname(HERE);
const LEVELS = {
  verifier: new Set(['replay', 'survives', 'attestation', 'export', 'export-verify']),
  evaluator: new Set(['replay', 'survives', 'authorization', 'attestation', 'export', 'export-verify', 'headroom', 'duty-view', 'writer-open', 'authority-evaluation']),
};
/** Ops whose result may be JSON null instead of an object (the whole record is compared). */
const NULLABLE_RESULT = new Set(['headroom', 'duty-view']);
const LEGACY_FIXTURES = join(ROOT, 'packages', 'reference-0.2', 'tests', 'fixtures');
/** The session-challenge profile each format-2 suite is signed under (A-54 founder-approved 2026-10-11, A-59). */
export const SUITE_PROFILES = Object.freeze({ v2: 'frozen-r2.3', 'v2-g3': 'g3', 'v2-regenerated': 'g3' });
const PROFILES = new Set(['frozen-r2.3', 'g3']);
/**
 * The profile of a format-2 suite: the table above, or — for a suite dropped in later as `conformance/<name>/` in the
 * format-2 layout (for example the architect's A-71 observation group) — its MANIFEST.json `challengeProfile`.
 */
const suiteProfile = (name) => {
  if (Object.hasOwn(SUITE_PROFILES, name)) return SUITE_PROFILES[name];
  if (!/^v2-[a-z0-9][a-z0-9-]*$/.test(name)) return undefined;
  const manifest = join(HERE, name, 'MANIFEST.json');
  if (!existsSync(manifest)) return undefined;
  const profile = read(manifest).challengeProfile;
  if (!PROFILES.has(profile)) throw new Error(`${manifest}: challengeProfile must be one of ${[...PROFILES].join(', ')}`);
  return profile;
};

class AdapterError extends Error {}
/** The adapter answered one request with a well-formed `{"ok":false,"error":…}`: that vector errs, the transport is intact. */
class AdapterReportedError extends AdapterError {}

/** Strict JSON: duplicate keys and non-finite numbers are invalid responses. */
function strictJson(text) {
  const value = JSON.parse(text, function reviver(key, inner) { return inner; });
  const scan = (raw) => {
    let depth = 0, inString = false, escaped = false;
    const keyStacks = [[]];
    let token = '', expectingKey = [false];
    for (let i = 0; i < raw.length; i += 1) {
      const c = raw[i];
      if (inString) {
        if (escaped) { escaped = false; token += c; continue; }
        if (c === '\\') { escaped = true; token += c; continue; }
        if (c === '"') { inString = false; if (expectingKey[depth]) { const k = JSON.parse(`"${token}"`); if (keyStacks[depth].includes(k)) throw new Error('duplicate JSON key'); keyStacks[depth].push(k); expectingKey[depth] = false; } continue; }
        token += c; continue;
      }
      if (c === '"') { inString = true; token = ''; continue; }
      if (c === '{') { depth += 1; keyStacks[depth] = []; expectingKey[depth] = true; continue; }
      if (c === '[') { depth += 1; keyStacks[depth] = null; expectingKey[depth] = false; continue; }
      if (c === '}' || c === ']') { depth -= 1; continue; }
      if (c === ',' && keyStacks[depth] !== null) expectingKey[depth] = true;
    }
  };
  scan(text);
  if (/\b(NaN|Infinity)\b/.test(text.replace(/"(?:[^"\\]|\\.)*"/g, ''))) throw new Error('non-finite JSON number');
  return value;
}

class Adapter {
  constructor(command, { timeout = 10_000, maxResponse = 1_048_576, maxRequest = 8_388_608, maxStderr = 65_536, profile } = {}) {
    this.timeout = timeout; this.maxResponse = maxResponse; this.maxRequest = maxRequest; this.maxStderr = maxStderr;
    this.stderr = ''; this.buffer = Buffer.alloc(0); this.exited = false; this.exitCode = null;
    const env = profile === undefined ? process.env : { ...process.env, IRONTRELLIS_CHALLENGE_PROFILE: profile };
    this.process = spawn(command[0], command.slice(1), { cwd: ROOT, env, stdio: ['pipe', 'pipe', 'pipe'] });
    this.process.on('exit', (code) => { this.exited = true; this.exitCode = code; });
    this.process.stderr.on('data', (chunk) => { this.stderr += chunk.toString('utf8'); });
    this.waiters = [];
    this.process.stdout.on('data', (chunk) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      if (this.buffer.length > this.maxResponse && this.buffer.indexOf(10) < 0) this.fail('RESPONSE_LIMIT');
      this.drain();
    });
    this.process.stdout.on('end', () => this.fail('ADAPTER_EOF'));
    this.process.on('error', (error) => this.fail(`SPAWN_FAILED: ${error.message}`));
  }
  fail(code) { const waiter = this.waiters.shift(); if (waiter) waiter.reject(new AdapterError(code)); else this.pendingError ??= code; }
  drain() {
    while (this.waiters.length > 0) {
      const end = this.buffer.indexOf(10);
      if (end < 0) return;
      if (end > this.maxResponse) return this.fail('RESPONSE_LIMIT');
      const line = this.buffer.subarray(0, end).toString('utf8');
      this.buffer = this.buffer.subarray(end + 1);
      const waiter = this.waiters.shift();
      if (this.stderr.length > this.maxStderr) return waiter.reject(new AdapterError('STDERR_LIMIT'));
      let answer;
      try { answer = strictJson(line); } catch { return waiter.reject(new AdapterError('INVALID_JSON')); }
      if (answer === null || typeof answer !== 'object' || Array.isArray(answer) || typeof answer.ok !== 'boolean') return waiter.reject(new AdapterError('INVALID_ENVELOPE'));
      const keys = Object.keys(answer).sort().join(',');
      if (keys !== (answer.ok ? 'ok,result' : 'error,ok')) return waiter.reject(new AdapterError('INVALID_ENVELOPE'));
      if (!answer.ok) {
        if (typeof answer.error !== 'string') return waiter.reject(new AdapterError('INVALID_ERROR'));
        return waiter.reject(new AdapterReportedError(`ADAPTER_REPORTED_ERROR: ${answer.error.slice(0, 200)}`));
      }
      // `headroom` and `duty-view` answer a record or null (SPEC-IRONTRELLIS-CORE-v2 §9.7, §13.3); every other result is an object.
      if (answer.result === null ? !waiter.nullable : (typeof answer.result !== 'object' || Array.isArray(answer.result))) return waiter.reject(new AdapterError('INVALID_RESULT'));
      waiter.resolve(answer);
    }
  }
  ask(request) {
    const payload = `${JSON.stringify(request)}\n`;
    if (Buffer.byteLength(payload) > this.maxRequest) return Promise.reject(new AdapterError('REQUEST_LIMIT'));
    if (this.pendingError) return Promise.reject(new AdapterError(this.pendingError));
    if (this.buffer.length > 0) return Promise.reject(new AdapterError('UNSOLICITED_OUTPUT'));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.waiters = this.waiters.filter((w) => w !== waiter); reject(new AdapterError('TIMEOUT')); }, this.timeout);
      const waiter = { nullable: NULLABLE_RESULT.has(request.op), resolve: (v) => { clearTimeout(timer); resolve(v); }, reject: (e) => { clearTimeout(timer); reject(e); } };
      this.waiters.push(waiter);
      this.process.stdin.write(payload, (error) => { if (error) waiter.reject(new AdapterError('ADAPTER_CLOSED_INPUT')); });
      this.drain();
    });
  }
  close() { try { this.process.stdin.end(); } catch {} try { this.process.kill('SIGKILL'); } catch {} }
}

/** Recursive declared-field projection; arrays/scalars and BigInt tags are exact. */
export function differences(expected, actual, path = '') {
  const label = path || '.';
  const kind = (v) => (v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v);
  if (kind(expected) !== kind(actual)) return [`${label}: expected ${kind(expected)}, got ${kind(actual)}`];
  if (kind(expected) === 'object') {
    const out = [];
    if (Object.hasOwn(expected, '$continuity.bigint') && Object.keys(actual).sort().join() !== Object.keys(expected).sort().join()) out.push(`${label}: tagged BigInt keys differ`);
    for (const [key, value] of Object.entries(expected)) {
      const child = `${path}.${key}`;
      if (!Object.hasOwn(actual, key)) out.push(`${child}: required field missing`);
      else out.push(...differences(value, actual[key], child));
    }
    return out;
  }
  if (kind(expected) === 'array') {
    if (expected.length !== actual.length) return [`${label}: expected ${expected.length} entries, got ${actual.length}`];
    return expected.flatMap((a, i) => differences(a, actual[i], `${path}[${i}]`));
  }
  if (typeof expected === 'number' && typeof actual === 'number') {
    // JSON.parse loses the integer/float distinction; compare the values exactly.
    return Object.is(expected, actual) ? [] : [`${label}: expected ${expected}, got ${actual}`];
  }
  return expected === actual ? [] : [`${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`];
}

const read = (file) => JSON.parse(readFileSync(file, 'utf8'));

/** A suite: its vectors plus a resolver from `history.ref` to an event array. */
function loadSuite(name) {
  if (name === 'legacy') {
    const histories = {
      'first-look': read(join(LEGACY_FIXTURES, 'handover-history.json')),
      'no-review-power': read(join(LEGACY_FIXTURES, 'handover-denied-history.json')),
      mandate: read(join(LEGACY_FIXTURES, 'mandate-history.json')),
    };
    histories['mandate-quantitative-only'] = histories.mandate.slice(0, 6);
    return { name, vectors: read(join(HERE, 'legacy', 'vectors.json')), history: (ref) => histories[ref] };
  }
  if (name === 'v1') {
    const file = join(HERE, 'v1', 'vectors.json');
    if (!existsSync(file)) throw new Error(`missing ${file}; run node conformance/v1/generate.mjs`);
    const cache = new Map();
    return {
      name,
      vectors: read(file),
      history: (ref) => {
        if (!cache.has(ref)) cache.set(ref, read(join(HERE, 'v1', 'histories', `${ref}.json`)));
        return cache.get(ref);
      },
    };
  }
  const profile = suiteProfile(name);
  if (profile !== undefined) {
    // conformance/v2/README.md (the same layout for every format-2 suite): `vectors.json` is an array;
    // `history: {ref, eventCount, head}` takes the first `eventCount` events of `histories/<ref>.json`; a vector
    // with `events` carries its own.
    const file = join(HERE, name, 'vectors.json');
    if (!existsSync(file)) throw new Error(`missing ${file}`);
    const vectors = read(file);
    if (!Array.isArray(vectors)) throw new Error(`${file}: expected an array of vectors`);
    const cache = new Map();
    return {
      name,
      vectors,
      passInput: true,
      profile,
      history: (ref, eventCount) => {
        if (!/^[a-z0-9][a-z0-9-]*$/.test(ref)) throw new Error(`${name}: invalid history ref ${JSON.stringify(ref)}`);
        if (!cache.has(ref)) cache.set(ref, read(join(HERE, name, 'histories', `${ref}.json`)));
        const events = cache.get(ref);
        if (!Number.isSafeInteger(eventCount) || eventCount < 1 || eventCount > events.length) throw new Error(`${name}: history ${ref} has ${events.length} events, a vector asks for ${eventCount}`);
        return events;
      },
    };
  }
  throw new Error(`unknown suite ${name}`);
}

function buildRequest(vector, suite) {
  const kind = vector.kind;
  const events = vector.history === undefined ? vector.events : suite.history(vector.history.ref, vector.history.eventCount).slice(0, vector.history.eventCount);
  // The v2 suite passes a replay vector's `input` through unchanged (the legacy-read vector keeps `eventCount`, `eventsSha256`).
  if (kind === 'replay') return suite.passInput ? { op: 'replay', ...vector.input, events: vector.events ?? events } : { op: 'replay', operationVersion: vector.input.operationVersion, events: vector.events ?? events };
  if (kind === 'authorization') return { op: 'authorize', events, ...vector.input };
  if (kind === 'survives') return { op: 'survives', events, ...vector.input };
  if (kind === 'attestation') return { op: 'verify-attestation', events, attestation: vector.input.attestation };
  if (kind === 'headroom') return { op: 'headroom', events, budgetId: vector.input.budgetId, at: vector.input.at };
  if (kind === 'export') return { op: 'export', events, fromPosition: vector.input.fromPosition, toPosition: vector.input.toPosition, include: vector.input.include };
  if (kind === 'duty-view') return { op: 'duty-view', events, dutyId: vector.input.dutyId };
  // conformance/v2-regenerated/README.md: the export verifier over a view, and an owner write to given store files.
  if (kind === 'export-verify') return { op: 'verify-export', view: vector.input.view };
  if (kind === 'writer-open') return { op: 'open-for-write', ...vector.input };
  // G6.5 A-136.4 (v2-regenerated): a supplied-scope raw-path evaluation (spec02 §7.1), its input carried as JSON.
  if (kind === 'authority-evaluation') return { op: 'evaluate-authority', input: vector.input };
  throw new Error(`unknown vector kind ${kind}`);
}

function parseArgs(argv) {
  const args = { suite: 'legacy', level: 'evaluator', filter: '', json: false, timeout: 10_000, adapter: undefined, profile: undefined, command: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--') { args.command = argv.slice(i + 1); break; }
    if (a === '--json') args.json = true;
    else if (a === '--suite') args.suite = argv[++i];
    else if (a === '--level') args.level = argv[++i];
    else if (a === '--filter') args.filter = argv[++i];
    else if (a === '--timeout') args.timeout = Number(argv[++i]) * 1000;
    else if (a === '--adapter') args.adapter = argv[++i];
    else if (a === '--profile') { args.profile = argv[++i]; if (!PROFILES.has(args.profile)) throw new Error(`unknown challenge profile ${args.profile}`); }
    else throw new Error(`unknown argument ${a}`);
  }
  if (args.command.length === 0) {
    if (!args.adapter) throw new Error('an adapter is required: --adapter <file> or -- <command…>');
    const file = resolve(args.adapter);
    args.command = file.endsWith('.py') ? [PYTHON, '-B', file] : [process.execPath, file];
  }
  return args;
}

export async function runSuite(suite, command, { level = 'evaluator', filter = '', timeout = 10_000, profile = suite.profile } = {}) {
  const report = { reportVersion: 'irontrellis-vector-report/1', suite: suite.name, level, profile: profile ?? null, status: 'EXECUTION_ERROR', implementation: null, selected: 0, passed: 0, mismatched: 0, errors: 0, notRun: [], results: [] };
  const selected = suite.vectors.filter((v) => LEVELS[level].has(v.kind) && v.id.includes(filter));
  report.selected = selected.length;
  if (selected.length === 0) { report.errors = 1; report.error = 'NO_VECTORS_SELECTED'; return report; }
  let adapter;
  try {
    adapter = new Adapter(command, { timeout, profile });
    const identity = (await adapter.ask({ op: 'describe' })).result;
    if (typeof identity.implementation !== 'string' || identity.implementation === '') throw new AdapterError('INVALID_DESCRIPTION');
    report.implementation = identity;
    for (const vector of selected) {
      let answer;
      try {
        answer = await adapter.ask(buildRequest(vector, suite));
      } catch (error) {
        if (!(error instanceof AdapterReportedError)) throw error;
        report.results.push({ id: vector.id, status: 'ERROR', error: error.message, purpose: vector.purpose });
        continue;
      }
      const diff = differences(vector.expect, answer.result);
      const result = { id: vector.id, status: diff.length ? 'MISMATCH' : 'PASS' };
      if (diff.length) { result.differences = diff; result.purpose = vector.purpose; }
      report.results.push(result);
    }
    report.status = report.results.some((r) => r.status === 'ERROR') ? 'EXECUTION_ERROR' : report.results.some((r) => r.status === 'MISMATCH') ? 'MISMATCH' : 'MATCH';
  } catch (error) {
    report.errors += 1;
    report.error = String(error?.message ?? error).slice(0, 500);
  } finally {
    adapter?.close();
  }
  const completed = new Set(report.results.map((r) => r.id));
  report.notRun = selected.filter((v) => !completed.has(v.id)).map((v) => v.id);
  report.passed = report.results.filter((r) => r.status === 'PASS').length;
  report.mismatched = report.results.filter((r) => r.status === 'MISMATCH').length;
  report.errors += report.results.filter((r) => r.status === 'ERROR').length;
  return report;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const suites = args.suite === 'all' ? ['legacy', 'v1'] : [args.suite];
  const reports = [];
  for (const name of suites) {
    const suite = loadSuite(name);
    reports.push(await runSuite(suite, args.command, { ...args, profile: args.profile ?? suite.profile }));
  }
  if (args.json) {
    console.log(JSON.stringify(reports, null, 2));
  } else {
    for (const report of reports) {
      console.log(`[${report.suite}${report.profile ? ` profile ${report.profile}` : ''}] ${report.status}: ${report.passed} matched, ${report.mismatched} mismatched, ${report.errors} execution errors, ${report.notRun.length} not run` +
        (report.implementation ? ` (${report.implementation.implementation})` : ''));
      if (report.results.some((r) => r.status !== 'PASS')) {
        // One row per vector, so a suite the adapter does not implement yet reads as a table, not a crash.
        const width = Math.max(...report.results.map((r) => r.id.length));
        for (const result of report.results) {
          const detail = result.status === 'ERROR' ? result.error : result.status === 'MISMATCH' ? `${result.differences.length} difference(s)` : '';
          console.log(`  ${result.status.padEnd(8)} ${result.id.padEnd(width)}  ${detail}`.trimEnd());
          if (result.status === 'MISMATCH') for (const d of result.differences) console.log(`             ${d}`);
        }
      }
      if (report.error) console.log(`  ${report.error}`);
    }
    console.log('Finite selected-vector evidence, not full protocol certification.');
  }
  const worst = Math.max(...reports.map((r) => ({ MATCH: 0, MISMATCH: 1, EXECUTION_ERROR: 2 })[r.status]));
  process.exitCode = worst;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => { console.error(error.message); process.exitCode = 2; });
}
