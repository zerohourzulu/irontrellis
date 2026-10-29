// The "before" of BUILD §6's root rows: the 0923d57 root code over the record set of a history the benchmark kept
// (budgets.mjs --dir <dir>), checked equal to this tree's root. 0923d57 hashed this from-scratch root after EVERY
// replayed event, and twice per owner append (the prospective fork and the store).
//   git archive 0923d57 packages/core/src | tar -x -C <old>   (then link packages/core/node_modules into <old>/packages/core)
//   node --experimental-strip-types packages/core/bench/baseline-root.mjs <dir>/bench.jsonl <old>
import { pathToFileURL } from "node:url";
const [history, old] = process.argv.slice(2);
const before = await import(pathToFileURL(`${old}/packages/core/src/state-records.ts`).href);
const core = await import(new URL("../src/index.ts", import.meta.url));
const { openHistoryStore } = await import(new URL("../src/store.ts", import.meta.url));
const store = openHistoryStore(history, { inspect: true, trust: "CHECKPOINT_RESUME" });
const state = store.state();
store.close();
const entries = core.stateRecordsOf(state), leaves = entries.map((e) => e.leaf);
const median = (values) => [...values].sort((a, b) => a - b)[values.length >> 1];
const runs = [], scratch = [];
for (let r = 0; r < 7; r += 1) {
  const t = performance.now();
  const root = before.rootOfLeaves(leaves);
  runs.push(performance.now() - t);
  if (root !== core.rootAt(state, state.head.position)) throw new Error("the 0923d57 root differs");
}
const records = entries.slice(0, 12_000).map((e) => ({ kind: e.kind, key: e.key, record: e.record }));
for (let r = 0; r < 5; r += 1) { const t = performance.now(); before.stateRootOfRecords(records); scratch.push(performance.now() - t); }
console.log(`0923d57 rootOfLeaves over ${leaves.length} leaves (after every replayed event; twice per append): median ${median(runs).toFixed(2)} ms`);
console.log(`0923d57 stateRootOfRecords over ${records.length} records (from scratch): median ${median(scratch).toFixed(1)} ms`);
