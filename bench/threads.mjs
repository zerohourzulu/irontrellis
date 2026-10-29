#!/usr/bin/env node
/**
 * Verification threads: where the worker pool pays off, and what it costs the hook (docs/history/PERFORMANCE-2026-09-26.md §5.1).
 *
 *   node bench/threads.mjs open --history DIR/10k/history.jsonl [--sizes 256,512,1024,2048,4096,10000] [--threads 0,1,2] [--runs 5]
 *   node bench/threads.mjs hook --history DIR/100k/history.jsonl [--threads default,0,1,2] [--runs 5]
 *
 * `open`: for every size, the first N records of the history (a valid history on its own) are copied to a temporary
 * file and opened in a fresh process per run with IRONTRELLIS_VERIFY_THREADS=<t> (`openHistoryStore` + `state()`: the
 * full replay, with the pool when the file has at least SPECULATIVE_REPLAY_MIN_RECORDS records and t > 0). The
 * table shows the median open time and the median wall time of the whole process (start-up and worker start
 * included), which is what decides the break-even: the pool only helps when the verification it takes off the calling
 * thread outweighs starting and feeding it.
 *
 * `hook`: the latency of one `irontrellis-hook check claude-code Write …` process (config load, the history's open and
 * replay, the protective rules and the decision: what every PreToolUse pays, minus the host's session check) on a
 * copy of the history, with IRONTRELLIS_VERIFY_THREADS unset (`default`: the hook's own default) or set to t.
 *
 * `--root TREE` runs another checkout's build (before/after).
 */
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdtempSync, openSync, readFileSync, readSync, closeSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { availableParallelism, cpus, tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { benchRoot, fmtMs, median, parseArgs } from "./lib.mjs";

const [mode, ...rest] = process.argv.slice(2);
const args = parseArgs(rest, {
  history: { type: "string" }, sizes: { type: "string", default: "256,512,1024,2048,4096,10000" }, threads: { type: "string" },
  runs: { type: "number", default: 5 }, root: { type: "string" }, json: { type: "string" },
});
if (!["open", "hook"].includes(mode ?? "") || args.history === undefined) {
  console.error("usage: node bench/threads.mjs open|hook --history <history.jsonl> [--sizes …] [--threads …] [--runs n] [--root tree] [--json file]");
  process.exit(2);
}
const root = benchRoot(args.root);
const tmp = mkdtempSync(join(tmpdir(), "irontrellis-bench-threads-"));
process.on("exit", () => rmSync(tmp, { recursive: true, force: true }));
const envFor = (threads) => {
  const env = { ...process.env };
  delete env.IRONTRELLIS_VERIFY_THREADS;
  delete env.NODE_OPTIONS;
  if (threads !== "default") env.IRONTRELLIS_VERIFY_THREADS = String(threads);
  return env;
};
console.log(`# ${mode}: ${cpus()[0]?.model ?? "?"}, availableParallelism ${availableParallelism()}, node ${process.version}, root ${root}, ${args.runs} runs, median`);
const results = [];

/** The first `count` records of `file` (a prefix of a valid history is a valid history). */
function prefix(file, count, out) {
  const fd = openSync(file, "r");
  const chunks = [];
  let lines = 0;
  const buffer = Buffer.alloc(1 << 20);
  try {
    for (;;) {
      const n = readSync(fd, buffer, 0, buffer.length, null);
      if (n === 0) break;
      let end = n;
      for (let i = 0; i < n; i += 1) if (buffer[i] === 10 && ++lines === count) { end = i + 1; break; }
      chunks.push(Buffer.from(buffer.subarray(0, end)));
      if (lines >= count) break;
    }
  } finally { closeSync(fd); }
  writeFileSync(out, Buffer.concat(chunks), { mode: 0o600 });
  return lines;
}

if (mode === "open") {
  const threads = (args.threads ?? "0,1,2").split(",");
  const probe = `
    const t0 = performance.now();
    const core = await import(${JSON.stringify(pathToFileURL(join(root, "packages/core/dist/index.js")).href)});
    const pv = await import(${JSON.stringify(pathToFileURL(join(root, "packages/core/dist/crypto/parallel-verify.js")).href)});
    const t1 = performance.now();
    const store = core.openHistoryStore(process.argv[2], { allowUnpinned: true });
    const events = store.state().events.length;
    const t2 = performance.now();
    store.close();
    console.log(JSON.stringify({ events, openMs: t2 - t1, stats: pv.speculationStats(), rss: process.memoryUsage().rss }));
  `;
  // From a file, as a program runs: under \`node -e\` the pool's workers did not take work off the calling thread
  // (measured: the same open with one worker took as long as without).
  const probeFile = join(tmp, "probe.mjs");
  writeFileSync(probeFile, probe);
  for (const size of args.sizes.split(",").map(Number)) {
    const file = join(tmp, `h${size}.jsonl`);
    const records = prefix(args.history, size, file);
    const row = { size: records };
    for (const t of threads) {
      const open = [], wall = [], rss = [];
      let stats;
      for (let run = 0; run < args.runs; run += 1) {
        const started = performance.now();
        const child = spawnSync(process.execPath, [probeFile, file], { env: envFor(t), encoding: "utf8", maxBuffer: 1 << 24 });
        const elapsed = performance.now() - started;
        if (child.status !== 0) throw new Error(`open ${size} threads ${t}: ${child.stderr}`);
        const out = JSON.parse(child.stdout.trim().split("\n").pop());
        open.push(out.openMs); wall.push(elapsed); rss.push(out.rss); stats = out.stats;
      }
      row[`t${t}`] = { open: median(open), wall: median(wall), rssMiB: median(rss) / 1048576, pool: stats.threads, speculated: stats.runs };
    }
    results.push(row);
    console.log(`${String(records).padStart(7)} records  ` + threads.map((t) => {
      const r = row[`t${t}`];
      return `threads=${t}: open ${fmtMs(r.open).padStart(8)}, process ${fmtMs(r.wall).padStart(8)}, ${r.rssMiB.toFixed(0)} MiB${r.speculated ? " (pool)" : ""}`;
    }).join("   "));
  }
} else {
  const threads = (args.threads ?? "default,0,1,2").split(",");
  const project = join(tmp, "project");
  const history = join(tmp, "state", "history.jsonl");
  for (const dir of [project, join(tmp, "state")]) spawnSync("mkdir", ["-p", dir]);
  for (const suffix of ["", ".head", ".anchors"]) if (existsSync(args.history + suffix)) copyFileSync(args.history + suffix, history + suffix);
  const manifest = JSON.parse(readFileSync(join(args.history, "..", "manifest.json"), "utf8"));
  writeFileSync(join(project, "irontrellis-hook.json"), JSON.stringify({
    version: "irontrellis-hook-config/1", history, owner: "operations", controller: "operator", domain: manifest.domain, agentId: manifest.worker?.agent ?? "worker",
    policy: { sideEffecting: [{ tool: "Write", action: "write-file", resource: "repo:${project}" }], readOnly: ["Read"] },
  }, null, 2));
  const bin = join(root, "packages/hooks/bin/irontrellis-hook.mjs");
  const events = readFileSync(history, "utf8").split("\n").length - 1;
  for (const t of threads) {
    const wall = [];
    for (let run = 0; run < args.runs; run += 1) {
      const started = performance.now();
      const child = spawnSync(process.execPath, [bin, "check", "claude-code", "Write", "--input", JSON.stringify({ file_path: join(project, "notes.md"), content: "x" })], { cwd: project, env: envFor(t), encoding: "utf8" });
      wall.push(performance.now() - started);
      if (child.status !== 0 && child.status !== 2) throw new Error(`hook threads ${t}: exit ${child.status}: ${child.stderr}${child.stdout}`);
      if (run === 0) console.log(`  (threads=${t}: ${child.stdout.trim().slice(0, 100)})`);
    }
    results.push({ events, threads: t, median: median(wall), min: Math.min(...wall), max: Math.max(...wall) });
    console.log(`${events} events, IRONTRELLIS_VERIFY_THREADS=${t === "default" ? "(unset)" : t}: hook process median ${fmtMs(median(wall))} (min ${fmtMs(Math.min(...wall))}, max ${fmtMs(Math.max(...wall))})`);
  }
}
if (args.json !== undefined) writeFileSync(args.json, JSON.stringify({ mode, root, runs: args.runs, results }, null, 2) + "\n");
