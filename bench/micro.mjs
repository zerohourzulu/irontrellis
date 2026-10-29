#!/usr/bin/env node
/**
 * Micro-benchmarks of the canonical layer (docs/history/PERFORMANCE-2026-09-26.md §3): the per-event
 * work every replay does several times, measured in isolation so that a change to
 * canonical.ts can be compared across trees.
 *
 *   node bench/micro.mjs                                 # this tree's dist
 *   node bench/micro.mjs --root /path/to/other/tree      # another tree's dist
 *   node --experimental-strip-types bench/micro.mjs --src --root /path/to/tree   # a tree's TypeScript sources
 *
 * Workload: every event of the four format-1 conformance histories (authority, handover, migrated, witness-bound:
 * 126 events of most types) and the store lines of the three that have a `*.jsonl` form (102 lines), repeated `--repeat`
 * times per round.
 *   canonicalEncode   canonicalEncode(event)                 (record hashes, prefix hashes, control-signature hashes)
 *   captureValue      captureValue(event)                    (event validation's deep copy and checks)
 *   hashCanonical     hashCanonical(event, "sha256")         (encode + UTF-8 + SHA-256)
 *   parseLine         jsonParseWithBigints(store line)       (the store reader, one call per line)
 * Reported: the median over `--rounds` rounds (after one warm-up round) of the time per round, and per item.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { benchRoot, median, parseArgs, REPO } from "./lib.mjs";

const args = parseArgs(process.argv.slice(2), {
  root: { type: "string", default: undefined },
  src: { type: "boolean", default: false },
  rounds: { type: "number", default: 9 },
  repeat: { type: "number", default: 60 },
  json: { type: "boolean", default: false },
});
const ROOT = benchRoot(args.root);
const core = await import(pathToFileURL(join(ROOT, args.src ? "packages/core/src/index.ts" : "packages/core/dist/index.js")).href);

// The workload always comes from THIS tree's conformance files, so every tree measures the same bytes.
const HISTORIES = ["authority-v1", "handover-v1", "migrated-v1", "witness-bound-v1"];
const events = [];
const lines = [];
for (const name of HISTORIES) {
  events.push(...core.jsonParseWithBigints(readFileSync(join(REPO, "conformance/v1/histories", `${name}.json`), "utf8")));
  try {
    lines.push(...readFileSync(join(REPO, "conformance/v1/histories", `${name}.jsonl`), "utf8").split("\n").filter(Boolean));
  } catch { /* no store form */ }
}

const measure = (label, items, fn) => {
  const once = () => {
    const started = performance.now();
    for (let r = 0; r < args.repeat; r += 1) for (const item of items) fn(item);
    return performance.now() - started;
  };
  once();
  const times = [];
  for (let i = 0; i < args.rounds; i += 1) times.push(once());
  const ms = median(times);
  return { label, items: items.length * args.repeat, roundMs: ms, perItemUs: (ms * 1000) / (items.length * args.repeat) };
};

let sink = 0;
const results = [
  measure("canonicalEncode", events, (event) => { sink += core.canonicalEncode(event).length; }),
  measure("captureValue", events, (event) => { sink += core.captureValue(event) === event ? 0 : 1; }),
  measure("hashCanonical", events, (event) => { sink += core.hashCanonical(event, "sha256").length; }),
  measure("parseLine", lines, (line) => { sink += core.jsonParseWithBigints(line) === null ? 0 : 1; }),
];
if (sink < 0) throw new Error("unreachable");
if (args.json) console.log(JSON.stringify({ root: ROOT, src: args.src, events: events.length, lines: lines.length, repeat: args.repeat, rounds: args.rounds, results }, null, 2));
else {
  console.log(`canonical micro-benchmarks: ${ROOT} (${args.src ? "src" : "dist"}), ${events.length} events / ${lines.length} lines x ${args.repeat}, median of ${args.rounds} rounds`);
  for (const r of results) console.log(`  ${r.label.padEnd(16)} ${r.roundMs.toFixed(1).padStart(8)} ms per round  ${r.perItemUs.toFixed(2).padStart(7)} µs per item`);
}
