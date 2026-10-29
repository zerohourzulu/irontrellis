/**
 * Speculative parallel Ed25519 verification for the replay of a large history
 * (docs/history/PERFORMANCE-2026-09-26.md §4).
 *
 * Replaying a format-1 file is bound by one Ed25519 verification per control
 * event (and one per runtime or session signature): about half of the time of
 * an open. Inside `speculate(run)`, the Ed25519 suite does every check it
 * always does (syntax, key import) but, instead of calling OpenSSL, it queues
 * the (hash, signature, public key) triple and answers `true`; worker threads
 * (and, at the end, the calling thread) verify the queued triples with the
 * same `node:crypto` primitive while the replay goes on. The outcome of the
 * speculation is used only when EVERY queued verification succeeded: then the
 * speculative run saw exactly the answers a sequential run would have seen and
 * took exactly the same path, so its state, heads and errors are the
 * sequential ones. When any verification failed, or the pool is unavailable,
 * the caller discards the speculative result and replays sequentially, which
 * reproduces the exact first error. Nothing is cached across calls: every
 * signature is verified by OpenSSL on every replay.
 *
 * The calling thread stays synchronous (the store's open is synchronous): it
 * posts batches to the workers and, at the end, claims every triple no worker
 * has claimed yet (so a slow, busy or dead pool never blocks it), then waits
 * with `Atomics.wait` for the ones in flight.
 *
 * `IRONTRELLIS_VERIFY_THREADS=<n>` sets the pool size (0 turns speculation
 * off); the default is `min(4, availableParallelism() - 1)`, so nothing runs
 * in parallel on a single-CPU host.
 */
import { verify as nodeVerify, type KeyObject } from "node:crypto";
import { availableParallelism } from "node:os";
import { Worker } from "node:worker_threads";

/** hash (32) ‖ signature (64) ‖ raw public key (32). */
const ITEM_BYTES = 128;
const BATCH_ITEMS = 256;
/** status[i]: 0 queued, 1 claimed, 2 valid, 3 invalid; status[BATCH_ITEMS] counts finished items. */
const QUEUED = 0, CLAIMED = 1, VALID = 2, INVALID = 3, DONE = BATCH_ITEMS;
/** Give up waiting on a claimed item after this long without progress and verify it here (a crashed worker). */
let stallMs = 5_000;

// A CommonJS worker evaluated from this string: no separate file to resolve from `src/` (tests) or `dist/` (packages).
const WORKER_SOURCE = `
"use strict";
const { parentPort } = require("node:worker_threads");
const { createPublicKey, verify } = require("node:crypto");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const keys = new Map();
const keyOf = (raw) => {
  const id = raw.toString("hex");
  let key = keys.get(id);
  if (key === undefined) {
    try { key = createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: "der", type: "spki" }); } catch { key = null; }
    if (keys.size >= 4096) keys.delete(keys.keys().next().value);
    keys.set(id, key);
  }
  return key;
};
parentPort.on("message", (batch) => {
  const bytes = new Uint8Array(batch.input);
  const status = new Int32Array(batch.status);
  for (let i = 0; i < batch.count; i += 1) {
    if (Atomics.compareExchange(status, i, ${QUEUED}, ${CLAIMED}) !== ${QUEUED}) continue;
    const at = i * ${ITEM_BYTES};
    let ok = false;
    try {
      const key = keyOf(Buffer.from(bytes.slice(at + 96, at + 128)));
      ok = key !== null && verify(null, Buffer.from(bytes.slice(at, at + 32)), key, Buffer.from(bytes.slice(at + 32, at + 96)));
    } catch { ok = false; }
    Atomics.store(status, i, ok ? ${VALID} : ${INVALID});
    Atomics.add(status, ${DONE}, 1);
    Atomics.notify(status, ${DONE});
  }
});
`;

type Batch = { readonly input: SharedArrayBuffer; readonly bytes: Uint8Array; readonly status: Int32Array; readonly keys: KeyObject[]; count: number };

let pool: Worker[] | undefined;
let threadsOverride: number | undefined;
/** The pool size a process chose for itself (`setDefaultVerifyThreads`), used when the environment names none. */
let processDefault: number | undefined;
/** The most threads that can run at once here (`os.availableParallelism()`, 1 when it cannot be read). */
const cpuCount = (): number => {
  try { return Math.max(1, availableParallelism()); } catch { return 1; }
};
/** Speculative runs on this thread: how many, how many were discarded (a verification failed), how many triples were queued. */
const stats = { runs: 0, discarded: 0, queued: 0 };

/** True when IRONTRELLIS_VERIFY_THREADS is set (to anything but blanks): the operator chose the pool size. */
export function verifyThreadsConfigured(): boolean {
  const configured = process.env.IRONTRELLIS_VERIFY_THREADS;
  return configured !== undefined && configured.trim() !== "";
}

/**
 * Pool size: IRONTRELLIS_VERIFY_THREADS when set (0 turns the pool off), else the process's own default
 * (`setDefaultVerifyThreads`, e.g. 0 in the short-lived hook process), else min(4, cores - 1). Always at most
 * `os.availableParallelism()` and 16: more workers than CPUs only add start-up time and memory
 * (measured: 16 workers on 2 vCPUs opened a 3,000-event history 50% slower than none, with 250 MiB RSS).
 */
export function verifyThreads(): number {
  if (threadsOverride !== undefined) return threadsOverride;
  const cap = Math.min(16, cpuCount());
  if (verifyThreadsConfigured()) {
    const n = Number(process.env.IRONTRELLIS_VERIFY_THREADS);
    return Number.isSafeInteger(n) && n >= 0 ? Math.min(n, cap) : 0;
  }
  // A default, not the operator's choice: like the built-in one it leaves a core to the calling thread.
  if (processDefault !== undefined) return Math.min(processDefault, Math.max(0, cpuCount() - 1));
  return Math.max(0, Math.min(4, cpuCount() - 1));
}

/**
 * Sets this process's default pool size, used when IRONTRELLIS_VERIFY_THREADS is not set (the variable always wins);
 * `undefined` restores min(4, cores - 1). Call it before the first history is opened: the pool is started once. A
 * short-lived process that opens one history per run (the hook, once per tool call) passes a low number (the hook: 1)
 * so that a many-core machine does not start four workers per tool call (docs/history/PERFORMANCE-2026-09-26.md §5.1). Like the
 * built-in default it is capped at cores - 1; IRONTRELLIS_VERIFY_THREADS is capped at the core count only.
 */
export function setDefaultVerifyThreads(threads: number | undefined): void {
  if (threads !== undefined && !(Number.isSafeInteger(threads) && threads >= 0)) throw new RangeError("the default verification thread count is a non-negative integer");
  processDefault = threads;
}

function workers(): Worker[] {
  if (pool !== undefined) return pool;
  const wanted = verifyThreads();
  const started: Worker[] = [];
  for (let i = 0; i < wanted; i += 1) {
    try {
      const worker = new Worker(WORKER_SOURCE, { eval: true, name: "irontrellis-verify" });
      // A worker that fails simply stops claiming work; whatever it left is verified by the calling thread.
      worker.on("error", () => undefined);
      worker.unref();
      started.push(worker);
    } catch {
      break;
    }
  }
  pool = started;
  return pool;
}

/** A pool that stopped answering is not used again in this process (every later replay is sequential). */
function retirePool(): void {
  const old = pool ?? [];
  pool = [];
  for (const worker of old) void worker.terminate().catch(() => undefined);
}

const verifyHere = (bytes: Uint8Array, at: number, key: KeyObject): boolean => {
  try {
    return nodeVerify(null, bytes.subarray(at, at + 32), key, bytes.subarray(at + 32, at + 96));
  } catch {
    return false;
  }
};

/** One speculative run's queue of verifications. */
class Speculation {
  readonly #workers: readonly Worker[];
  readonly #batches: Batch[] = [];
  #current: Batch | undefined;
  #failed = false;
  #queued = 0;

  constructor(pool: readonly Worker[]) {
    this.#workers = pool;
  }

  get queued(): number {
    return this.#queued;
  }

  /**
   * Queues one verification and answers optimistically. Once a queued verification is known to have failed, the
   * speculation is void (the caller will replay sequentially): later calls answer `false` so the run ends sooner.
   */
  defer(hash: Uint8Array, signature: Uint8Array, publicKey: Uint8Array, key: KeyObject): boolean {
    if (this.#failed) return false;
    let batch = this.#current;
    if (batch === undefined || batch.count === BATCH_ITEMS) {
      if (batch !== undefined) this.#post(batch);
      if (this.#sweep()) return false;
      const input = new SharedArrayBuffer(BATCH_ITEMS * ITEM_BYTES);
      batch = { input, bytes: new Uint8Array(input), status: new Int32Array(new SharedArrayBuffer((BATCH_ITEMS + 1) * 4)), keys: [], count: 0 };
      this.#current = batch;
      this.#batches.push(batch);
    }
    const at = batch.count * ITEM_BYTES;
    batch.bytes.set(hash, at);
    batch.bytes.set(signature, at + 32);
    batch.bytes.set(publicKey, at + 96);
    batch.keys.push(key);
    batch.count += 1;
    this.#queued += 1;
    return true;
  }

  #post(batch: Batch): void {
    for (const worker of this.#workers) {
      try { worker.postMessage({ input: batch.input, status: batch.status.buffer, count: batch.count }); } catch { /* the calling thread verifies it */ }
    }
  }

  /** Drops finished, all-valid batches from the front; true when a failure is known. */
  #sweep(): boolean {
    while (this.#batches.length > 0) {
      const batch = this.#batches[0]!;
      if (batch === this.#current || Atomics.load(batch.status, DONE) < batch.count) break;
      for (let i = 0; i < batch.count; i += 1) {
        if (batch.status[i] !== VALID) {
          this.#failed = true;
          return true;
        }
      }
      this.#batches.shift();
    }
    return false;
  }

  /** Verifies whatever no worker claimed, waits for the rest; true iff every queued verification succeeded. */
  settle(): boolean {
    for (const batch of this.#batches) {
      const { bytes, status, keys } = batch;
      for (let i = 0; i < batch.count; i += 1) {
        if (Atomics.compareExchange(status, i, QUEUED, CLAIMED) !== QUEUED) continue;
        Atomics.store(status, i, verifyHere(bytes, i * ITEM_BYTES, keys[i]!) ? VALID : INVALID);
        Atomics.add(status, DONE, 1);
      }
    }
    let ok = !this.#failed;
    let dead = false;
    for (const batch of this.#batches) {
      const { bytes, status, keys } = batch;
      let seen = Atomics.load(status, DONE), since = Date.now();
      while (seen < batch.count && !dead) {
        Atomics.wait(status, DONE, seen, Math.min(100, stallMs));
        const now = Atomics.load(status, DONE);
        if (now !== seen) { seen = now; since = Date.now(); continue; }
        // No worker finished anything for stallMs: the pool crashed or was terminated. Verify what it claimed here.
        if (Date.now() - since > stallMs) dead = true;
      }
      if (dead) for (let i = 0; i < batch.count; i += 1) if (Atomics.load(status, i) === CLAIMED) Atomics.store(status, i, verifyHere(bytes, i * ITEM_BYTES, keys[i]!) ? VALID : INVALID);
      for (let i = 0; i < batch.count; i += 1) if (Atomics.load(status, i) !== VALID) ok = false;
    }
    this.#batches.length = 0;
    this.#current = undefined;
    if (dead) retirePool();
    return ok;
  }
}

let active: Speculation | undefined;

/** The speculation in progress on this thread (consulted by the Ed25519 suite), if any. */
export function activeSpeculation(): Speculation | undefined {
  return active;
}

/** Counters since the process started (or the last reset): for tests and diagnostics. */
export function speculationStats(): Readonly<{ runs: number; discarded: number; queued: number; threads: number }> {
  return Object.freeze({ ...stats, threads: pool?.length ?? verifyThreads() });
}

/**
 * Tests only: replace the pool with `threads` workers (`undefined`: back to the environment's setting), optionally
 * with workers that never answer (`stalled`), and reset the counters. Terminates the current workers.
 */
export async function setVerifyThreadsForTests(threads: number | undefined, options: Readonly<{ stalled?: boolean; stallMs?: number }> = {}): Promise<void> {
  const old = pool ?? [];
  pool = undefined;
  threadsOverride = threads;
  stallMs = options.stallMs ?? 5_000;
  stats.runs = 0;
  stats.discarded = 0;
  stats.queued = 0;
  await Promise.all(old.map((worker) => worker.terminate().catch(() => undefined)));
  if (options.stalled === true && threads !== undefined) {
    // Workers that take every item and never finish it: the calling thread must recover them after STALL_MS.
    pool = [];
    for (let i = 0; i < threads; i += 1) {
      const worker = new Worker(`require("node:worker_threads").parentPort.on("message", (b) => { const s = new Int32Array(b.status); for (let i = 0; i < b.count; i += 1) Atomics.compareExchange(s, i, 0, 1); });`, { eval: true });
      worker.unref();
      pool.push(worker);
    }
  }
}

export type SpeculativeOutcome<T> =
  | Readonly<{ speculated: false }>
  | Readonly<{ speculated: true; verified: boolean; queued: number; value?: T; error?: unknown; threw: boolean }>;

/**
 * Runs `run` with Ed25519 verifications deferred to the pool. `{ speculated: false }` (and `run` not called) when
 * no pool is available or a speculation is already running (never nested). With `verified` true the outcome (value
 * or thrown error) is exactly what a sequential run returns; with `verified` false it must be discarded.
 */
export function speculate<T>(run: () => T): SpeculativeOutcome<T> {
  if (active !== undefined) return { speculated: false };
  const pool = workers();
  if (pool.length === 0) return { speculated: false };
  const speculation = new Speculation(pool);
  active = speculation;
  let value: T | undefined, error: unknown, threw = false;
  try {
    value = run();
  } catch (caught) {
    error = caught;
    threw = true;
  } finally {
    active = undefined;
  }
  const verified = speculation.settle();
  stats.runs += 1;
  stats.queued += speculation.queued;
  if (!verified) stats.discarded += 1;
  return threw ? { speculated: true, verified, queued: speculation.queued, error, threw } : { speculated: true, verified, queued: speculation.queued, value: value as T, threw };
}
