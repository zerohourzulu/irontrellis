/**
 * Shared helpers for the scale benchmarks (`bench/generate.mjs`, `bench/run.mjs`).
 *
 * The benchmarks drive the BUILT packages (`packages/<name>/dist`), exactly as a
 * user of the published artifacts does; build first (`pnpm -r build`). Every
 * script accepts `--root <tree>` (or `IRONTRELLIS_BENCH_ROOT`) to load another
 * checkout's `dist` instead, which is how the before/after tables in
 * docs/PERFORMANCE.md compare two trees on the same history files.
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const HERE = dirname(fileURLToPath(import.meta.url));
export const REPO = dirname(HERE);

/** `--name value` / `--flag` parsing (no dependency); unknown options are an error. */
export function parseArgs(argv, spec) {
  const out = {};
  for (const [key, def] of Object.entries(spec)) out[key] = def.default;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith("--")) throw new Error(`unexpected argument ${arg}`);
    const key = arg.slice(2);
    const def = spec[key];
    if (def === undefined) throw new Error(`unknown option ${arg} (known: ${Object.keys(spec).map((k) => `--${k}`).join(" ")})`);
    if (def.type === "boolean") { out[key] = true; continue; }
    const value = argv[++i];
    if (value === undefined) throw new Error(`${arg} needs a value`);
    out[key] = def.type === "number" ? Number(value.replace(/_/g, "").replace(/k$/i, "000").replace(/m$/i, "000000")) : value;
  }
  return out;
}

export const benchRoot = (given) => resolve(given ?? process.env.IRONTRELLIS_BENCH_ROOT ?? REPO);

/** Imports `relative` (a dist module) from the tree at `root`. */
export async function load(root, relative) {
  const file = join(root, relative);
  if (!existsSync(file)) throw new Error(`missing ${file}: build that tree first (pnpm -r build)`);
  return import(pathToFileURL(file).href);
}

// ---------------------------------------------------------------- statistics

export const sorted = (values) => [...values].sort((a, b) => a - b);
export const median = (values) => {
  if (values.length === 0) return NaN;
  const s = sorted(values), mid = s.length >> 1;
  return s.length % 2 === 1 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
};
/** Nearest-rank percentile (p in 0..100). */
export const percentile = (values, p) => {
  if (values.length === 0) return NaN;
  const s = sorted(values);
  return s[Math.min(s.length - 1, Math.max(0, Math.ceil((p / 100) * s.length) - 1))];
};
export const mean = (values) => values.reduce((a, b) => a + b, 0) / values.length;
export const summary = (values) => ({ n: values.length, median: median(values), mean: mean(values), p50: percentile(values, 50), p99: percentile(values, 99), min: Math.min(...values), max: Math.max(...values) });

export const fmtMs = (ms) => (!Number.isFinite(ms) ? "n/a" : ms < 1 ? `${(ms * 1000).toFixed(0)} µs` : ms < 1000 ? `${ms.toFixed(ms < 10 ? 2 : 1)} ms` : `${(ms / 1000).toFixed(2)} s`);
export const fmtMiB = (bytes) => `${(bytes / 1048576).toFixed(0)} MiB`;

/** Peak resident set of this process so far (bytes), from /proc (VmHWM) or process.resourceUsage(). */
export function peakRss() {
  try {
    const m = /VmHWM:\s+(\d+) kB/.exec(readFileSync("/proc/self/status", "utf8"));
    if (m) return Number(m[1]) * 1024;
  } catch { /* not Linux */ }
  return process.resourceUsage().maxRSS * 1024;
}
