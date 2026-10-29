/**
 * The persistent Python worker (fuzz/python/worker.py): one process per
 * campaign, JSON lines both ways, restarted after a timeout or an exit.
 * `available()` is false when no python3 can run the package (the
 * differential checks are then skipped and the harness says so).
 */
import { spawn, spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { FUZZ, ROOT } from './env.mjs';

const WORKER = join(FUZZ, 'python', 'worker.py');
const PYTHON = process.env.IRONTRELLIS_FUZZ_PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3');

/**
 * KNOWN-ISSUES 50 (FO-08): the Python checker is format-1 only, so the TypeScript/Python differential runs on legacy and format-1
 * inputs and is skipped for format-2 ones: an input whose genesis declares `irontrellis-event/2`, or a store file whose first
 * line is a format-2 record. Format-1 and legacy seeds keep the differential.
 */
export const PYTHON_SKIP_REASON = 'Python checker is format-1 only, KNOWN-ISSUES 50';
const declaresFormat2 = (event) => event?.data?.versions?.eventSchemaVersion === 'irontrellis-event/2';
export function format2Input({ format, events, event, text } = {}) {
  if (format === 'irontrellis-event/2' || declaresFormat2(event) || (Array.isArray(events) && declaresFormat2(events[0]))) return true;
  if (typeof text === 'string') {
    const first = text.slice(0, text.indexOf('\n') < 0 ? text.length : text.indexOf('\n'));
    try { const line = JSON.parse(first); return line?.version === 'irontrellis-portable-file-store/2' || declaresFormat2(line?.event); } catch { return false; }
  }
  return false;
}

let probed;
export function pythonAvailable() {
  if (probed === undefined) {
    const result = spawnSync(PYTHON, ['-B', '-c', 'import sys; sys.path.insert(0, sys.argv[1]); import irontrellis', join(ROOT, 'python', 'src')], { encoding: 'utf8', timeout: 30_000 });
    probed = result.status === 0;
  }
  return probed;
}

const NEGATIVE_ZERO = '\u0000irontrellis-fuzz:-0\u0000';
/**
 * JSON text that keeps JavaScript's -0 (JSON.stringify writes it as 0): the fuzzer's inputs may hold -0, and both sides
 * must judge the same number. The Python worker reads `-0` back as -0.0 (irontrellis.canonical.json_loads semantics).
 */
export function stringifyFaithful(value, space) {
  return JSON.stringify(value, (_key, v) => (Object.is(v, -0) ? NEGATIVE_ZERO : v), space).replaceAll(JSON.stringify(NEGATIVE_ZERO), '-0');
}

/** A persistent JSON-lines child (the conformance adapter protocol): the Python worker, or a conformance adapter. */
export class LineWorker {
  constructor(command, { timeoutMs = 30_000 } = {}) {
    this.command = command;
    this.timeoutMs = timeoutMs;
    this.child = undefined;
    this.pending = [];
    this.buffer = '';
    this.restarts = 0;
  }

  #start() {
    const child = spawn(this.command[0], this.command.slice(1), { cwd: ROOT, stdio: ['pipe', 'pipe', 'pipe'] });
    this.child = child;
    this.buffer = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      this.buffer += chunk;
      for (let end = this.buffer.indexOf('\n'); end >= 0; end = this.buffer.indexOf('\n')) {
        const line = this.buffer.slice(0, end);
        this.buffer = this.buffer.slice(end + 1);
        const waiter = this.pending.shift();
        if (waiter === undefined) continue;
        clearTimeout(waiter.timer);
        try { waiter.resolve(JSON.parse(line)); } catch (error) { waiter.reject(new Error(`${this.command.at(-1)}: invalid response line: ${error.message}`)); }
      }
    });
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk) => { this.stderr = `${this.stderr ?? ''}${chunk}`.slice(-4000); });
    child.on('exit', (code, signal) => {
      if (this.child === child) this.child = undefined;
      for (const waiter of this.pending.splice(0)) { clearTimeout(waiter.timer); waiter.reject(new Error(`${this.command.at(-1)} exited (${code ?? signal}): ${this.stderr ?? ''}`)); }
    });
    child.stdin.on('error', () => {});
  }

  /** One request, the whole `{ok, result | error}` envelope; rejects on timeout (the worker is then killed and restarted on the next request). */
  raw(message, timeoutMs = this.timeoutMs) {
    if (this.child === undefined) { this.#start(); this.restarts += 1; }
    const child = this.child;
    return new Promise((resolve, reject) => {
      const waiter = { resolve, reject, timer: undefined };
      waiter.timer = setTimeout(() => {
        this.pending = this.pending.filter((w) => w !== waiter);
        try { child.kill('SIGKILL'); } catch { /* gone */ }
        if (this.child === child) this.child = undefined;
        reject(Object.assign(new Error(`${this.command.at(-1)} timed out after ${timeoutMs} ms`), { code: 'WORKER_TIMEOUT' }));
      }, timeoutMs);
      this.pending.push(waiter);
      child.stdin.write(`${stringifyFaithful(message)}\n`);
    });
  }

  /** One request; its `result`, or a rejection carrying the worker's error. */
  async request(message, timeoutMs = this.timeoutMs) {
    const response = await this.raw(message, timeoutMs);
    if (!response.ok) throw new Error(`${this.command.at(-1)} error: ${response.error}`);
    return response.result;
  }

  close() {
    const child = this.child;
    this.child = undefined;
    if (child) { try { child.stdin.end(); } catch { /* gone */ } setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* gone */ } }, 500).unref(); }
  }
}

export class PythonWorker extends LineWorker {
  constructor(options) { super([PYTHON, '-B', WORKER], options); }
}

/** The TypeScript conformance adapter (conformance/adapters/node.mjs) as a persistent process. */
export class NodeAdapter extends LineWorker {
  constructor(options) { super([process.execPath, join(ROOT, 'conformance', 'adapters', 'node.mjs')], options); }
}
