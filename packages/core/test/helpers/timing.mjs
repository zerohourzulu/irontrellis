// Timing assertions that stay meaningful on a loaded machine (block 3.2).
//
// A timing test must catch a real regression (an accidental O(n²), a lost
// cache, a replay on every call: slower by an order of magnitude) without
// failing because CI or a shared host is busy. Two tools:
//
//  - `loadFactor()`: runs a fixed CPU-bound calibration (SHA-256 and JSON work,
//    best of five) and returns how much slower this process runs it than the
//    reference machine did when quiet (never below 1). A bound multiplied by
//    it scales with the machine's current speed: under load the calibration
//    slows down with the code under test.
//  - `bestOf(attempts, measure)`: repeats a measurement and keeps the best, so
//    one descheduled run does not decide the verdict.
//
// The budgets themselves stay the documented ones (docs/BENCHMARKS.md).
import { createHash } from "node:crypto";

/** The calibration's best time on the reference machine (2-vCPU Xeon @ 2.1 GHz, quiet), in ms. */
export const REFERENCE_CALIBRATION_MS = 5.0;

const PAYLOAD = Buffer.alloc(256 * 1024, 7);
const DOCUMENT = JSON.stringify(Array.from({ length: 400 }, (_, i) => ({ id: `item:${i}`, value: i, tags: ["a", "b", String(i)] })));

function calibrationOnce() {
  const started = performance.now();
  let sink = 0;
  for (let i = 0; i < 8; i += 1) sink += createHash("sha256").update(PAYLOAD).digest()[0];
  for (let i = 0; i < 20; i += 1) sink += JSON.parse(DOCUMENT).length;
  if (sink < 0) throw new Error("unreachable");
  return performance.now() - started;
}

let cached;
/** How much slower than the (quiet) reference machine this process currently runs; at least 1. */
export function loadFactor({ fresh = false } = {}) {
  if (cached !== undefined && !fresh) return cached;
  calibrationOnce(); // warm up
  let best = Infinity;
  for (let i = 0; i < 5; i += 1) best = Math.min(best, calibrationOnce());
  cached = Math.max(1, best / REFERENCE_CALIBRATION_MS);
  return cached;
}

/** The smallest of `attempts` measurements (each a number, sync or async). */
export async function bestOf(attempts, measure) {
  let best = Infinity;
  for (let i = 0; i < attempts; i += 1) best = Math.min(best, await measure(i));
  return best;
}
