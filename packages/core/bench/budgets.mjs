// BUILD §6 performance budgets, every row measured (medians of ≥ 5 runs) on a format-2 history written through the
// public API (bench/format2-history.mjs). Prints the machine, the Node version and one line per row.
//
//   node --experimental-strip-types packages/core/bench/budgets.mjs [--events 10000] [--runs 7] [--dir <path>] [--keep] [--generate-only]
//
// --dir reuses (or creates and keeps) the history in <path> instead of a fresh temporary directory: generating 10,000
// events through the API is itself measured once and reported. The hook row runs the hooks package's own code
// (`openOwner` + `decideTool`) from source: `@ramex-labs/irontrellis` is resolved to packages/core/src by a loader hook.
import { execFileSync, spawnSync } from "node:child_process";
import { closeSync, cpSync, existsSync, fsyncSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync, writeSync } from "node:fs";
import fs from "node:fs";
import { register, syncBuiltinESMExports } from "node:module";
import { cpus, loadavg, tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const args = process.argv.slice(2);
const option = (name, fallback) => { const i = args.indexOf(`--${name}`); return i === -1 ? fallback : args[i + 1]; };
const EVENTS = Number(option("events", 10_000));
const RUNS = Math.max(5, Number(option("runs", 7)));
const KEEP = args.includes("--keep") || option("dir", undefined) !== undefined;
const CORE = new URL("../", import.meta.url), SRC = new URL("src/", CORE), REPO = new URL("../../", CORE);

// The hooks package imports the core by its package name; point it at the sources (no build needed for the benchmark).
register(`data:text/javascript,${encodeURIComponent(`
const SRC = ${JSON.stringify(SRC.href)};
const SUB = { "": "index.ts", "/store": "store.ts", "/platform": "platform.ts", "/local": "local.ts", "/attempts": "attempts.ts", "/custody": "custody/index.ts", "/transparency": "transparency/index.ts" };
export async function resolve(specifier, context, next) {
  if (specifier === "@ramex-labs/irontrellis" || specifier.startsWith("@ramex-labs/irontrellis/")) {
    const sub = specifier.slice("@ramex-labs/irontrellis".length);
    if (SUB[sub] !== undefined) return { url: SRC + SUB[sub], shortCircuit: true, format: "module-typescript" };
  }
  return next(specifier, context);
}`)}`);

const core = await import(new URL("index.ts", SRC));
const storeModule = await import(new URL("store.ts", SRC));
const { openLocalOwner } = await import(new URL("owner.ts", SRC));
const { openLocalRuntime } = await import(new URL("runtime.ts", SRC));
const { openLocalSimulation, commitTerms } = await import(new URL("simulation.ts", SRC));
const signerModule = await import(new URL("signer.ts", SRC));
const { keyPairFromPrivateKey, signHashWith } = await import(new URL("crypto/suites.ts", SRC));
const { recomputeRoot } = await import(new URL("state-rebuild.ts", SRC));
const { RecordTree } = await import(new URL("state-roots.ts", SRC));
const { buildFormat2History, budgetUpdate, BENCH_OWNER } = await import(new URL("bench/format2-history.mjs", CORE));
const hooks = await import(new URL("packages/hooks/src/hook.ts", REPO));
const hookConfig = await import(new URL("packages/hooks/src/config.ts", REPO));

const median = (values) => { const s = [...values].sort((a, b) => a - b); return s.length % 2 === 1 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2; };
const ms = (value) => `${value < 1 ? value.toFixed(3) : value < 100 ? value.toFixed(2) : value.toFixed(0)} ms`;
const time = (fn) => { const t = performance.now(); const result = fn(); return [performance.now() - t, result]; };
const rows = [];
const row = (name, budget, value, unit, pass, detail = "") => { rows.push({ name, budget, value, unit, pass, detail }); console.log(`${pass ? "MET   " : "MISSED"} ${name}: ${value} ${unit} (budget ${budget})${detail === "" ? "" : ` — ${detail}`}`); };

// ---------------------------------------------------------------- machine
const git = (...a) => { try { return execFileSync("git", a, { cwd: fileURLToPath(REPO), encoding: "utf8" }).trim(); } catch { return "?"; } };
console.log(`machine: ${cpus()[0]?.model ?? "?"}, ${cpus().length} cores; ${process.platform} ${process.arch}; Node ${process.version}`);
console.log(`commit: ${git("rev-parse", "--short", "HEAD")}${git("status", "--porcelain", "--untracked-files=no") === "" ? "" : " (+ local changes)"}; ${new Date().toISOString()}`);
console.log(`runs per row: ${RUNS} (median); events: ${EVENTS}; load average at start: ${loadavg().map((l) => l.toFixed(2)).join(" ")}\n`);

// ---------------------------------------------------------------- the history
const given = option("dir", undefined);
const dir = given ?? mkdtempSync(join(tmpdir(), "irontrellis-budgets-"));
if (!KEEP) process.on("exit", () => rmSync(dir, { recursive: true, force: true }));
mkdirSync(dir, { recursive: true });
const metaPath = join(dir, "bench-meta.json");
let meta;
if (existsSync(metaPath)) {
  meta = JSON.parse(readFileSync(metaPath, "utf8"));
  console.log(`history: reused ${meta.historyFile} (generated in ${ms(meta.generationMs)})`);
} else {
  const t = performance.now();
  let reported = 0;
  const built = await buildFormat2History(dir, EVENTS, { onProgress: (n) => { if (n - reported >= 2_000) { reported = n; process.stdout.write(`  … ${n} events (${ms(performance.now() - t)})\n`); } } });
  meta = { historyFile: built.historyFile, generationMs: performance.now() - t, config: { ...built.config, domain: built.config.domain, now: undefined, ids: undefined }, clock: built.clock.t, events: EVENTS };
  await import("node:fs").then((fs) => fs.writeFileSync(metaPath, JSON.stringify(meta)));
  console.log(`history: generated ${EVENTS} events through the owner/runtime API in ${ms(meta.generationMs)} (${ms(meta.generationMs / EVENTS)}/event)`);
}
if (args.includes("--generate-only")) process.exit(0);
// The append and hook rows write: they work on a copy, so a kept history measures the same on every run.
const work = mkdtempSync(join(tmpdir(), "irontrellis-budgets-run-"));
process.on("exit", () => rmSync(work, { recursive: true, force: true }));
for (const name of readdirSync(dir)) if (name.startsWith("bench.jsonl")) cpSync(join(dir, name), join(work, name), { recursive: true });
const historyFile = join(work, "bench.jsonl");
let clock = meta.clock;
let idCounter = 0;
const ownerConfig = (extra = {}) => ({ historyFile, domain: meta.config.domain, owner: BENCH_OWNER, controller: "operator", now: () => (clock += 1), ids: () => `bench:${process.pid}:${(idCounter += 1)}`, witness: false, ...extra });

const readEvents = () => { const store = storeModule.openHistoryStore(historyFile, { inspect: true, trust: "CHECKPOINT_RESUME" }); try { return [...store.readAll()]; } finally { store.close(); } };
const events = readEvents();
const full = core.replay(events);
if (full.status !== "ACCEPTED") throw new Error(`the bench history does not replay: ${full.code} ${full.reason}`);
const bytes = statSync(historyFile).size;
console.log(`at ${events.length} events: recordCount ${full.state.stateRecords.size}, file ${bytes} bytes (${(bytes / events.length).toFixed(0)} B/event), stateRoot ${full.stateRoot}`);
const types = {};
for (const event of events) types[event.type] = (types[event.type] ?? 0) + 1;
console.log(`event mix: ${Object.entries(types).map(([t, n]) => `${t} ${n}`).join(", ")}\n`);

// ---------------------------------------------------------------- full replay
{
  const runs = [];
  for (let r = 0; r < RUNS; r += 1) { const [t, result] = time(() => core.replay(events)); if (result.stateRoot !== full.stateRoot) throw new Error("replay root differs"); runs.push(t); }
  const perEvent = median(runs) / events.length;
  row("full replay (core.replay of the parsed events)", "≤ 0.30 ms/event", perEvent.toFixed(3), "ms/event", perEvent <= 0.30, `median ${ms(median(runs))} for ${events.length} events; runs ${runs.map(ms).join(", ")}`);
  const opens = [];
  for (let r = 0; r < Math.min(RUNS, 5); r += 1) opens.push(time(() => { const s = storeModule.openHistoryStore(historyFile, { inspect: true }); s.state(); s.close(); })[0]);
  console.log(`       (store open, FULL_REPLAY from the file incl. line parsing and chain checks: median ${ms(median(opens))} = ${(median(opens) / events.length).toFixed(3)} ms/event)`);
}

// ---------------------------------------------------------------- state root from scratch at 12,000 records; incremental update
{
  const target = 12_000;
  const state = core.createReplayState(full.state.format);
  for (const event of events) { if (state.stateRecords.size >= target) break; if (!core.applyEvent(state, event).ok) throw new Error("prefix"); }
  const records = core.stateRecordsOf(state).map((e) => ({ kind: e.kind, key: e.key, record: e.record }));
  const expected = core.rootAt(state, state.head.position);
  const scratchRuns = [], leafRuns = [];
  for (let r = 0; r < RUNS; r += 1) {
    const [t, result] = time(() => recomputeRoot(records));
    if (result.root !== expected) throw new Error("scratch root differs");
    scratchRuns.push(t);
  }
  const leaves = core.stateRecordsOf(state).map((e) => e.leaf);
  for (let r = 0; r < RUNS; r += 1) leafRuns.push(time(() => core.rootOfLeaves(leaves))[0]);
  const m = median(scratchRuns);
  row(`state root from scratch, ${records.length} records (canonical text, leaf hashes, MTH)`, "≤ 5 ms", m.toFixed(2), "ms", m <= 5, `at position ${state.head.position}; MTH over the given leaves alone: ${ms(median(leafRuns))}`);
  // Incremental: one record changed in place → its leaf (canonical text, two hashes) + the path in the cached tree.
  const tree = new RecordTree(leaves.slice());
  tree.root();
  const step = Math.floor(records.length / 101), samples = [];
  for (let i = 1; i <= 100; i += 1) {
    const index = i * step, entry = records[index];
    const changed = { ...entry.record, benchTouch: i };
    const t = performance.now();
    tree.update(index, core.leafOf(entry.kind, entry.key, changed));
    tree.root();
    samples.push(performance.now() - t);
  }
  const inc = median(samples);
  row("incremental root update, one record changed in place (leaf + cached path)", "≤ 0.1 ms per changed record", inc.toFixed(4), "ms", inc <= 0.1, `${samples.length} records at spread indices of ${records.length}`);
  // An insertion (every append inserts its `event` record at the end of the event block): the leaves right of it move.
  const keys = core.stateRecordsOf(state).map((e) => core.recordKey(e.kind, e.key));
  const eventEnd = keys.findLastIndex((k) => k.startsWith("event\u0000")) + 1;
  const insertRuns = [];
  for (let r = 0; r < RUNS; r += 1) {
    const t = performance.now();
    tree.insert(eventEnd + r, core.leafOf("event", core.positionKey(1e9 + r), { bench: r }));
    tree.root();
    insertRuns.push(performance.now() - t);
  }
  console.log(`       (an insertion at index ${eventEnd} of ${keys.length} — the next event record — moves ${keys.length - eventEnd} leaves: ${ms(median(insertRuns))}; RFC 6962 over sorted leaves has no O(log n) insertion)`);
}

// ---------------------------------------------------------------- export view, 1,000 events with toRecords
{
  const head = full.state.head.position;
  // Cold every run: a view's ends are computed once per position and then kept by the state, so each run takes a
  // window whose ends no earlier run read (the last 1,000 events, then the window one event earlier, …).
  const window = (from, to, state, shift) => {
    const runs = [];
    for (let r = 0; r < RUNS; r += 1) runs.push(time(() => core.exportViewState(state, { fromPosition: from - r * shift, toPosition: to - r * shift, include: { toRecords: true } }))[0]);
    return median(runs);
  };
  const tail = window(head - 999, head, full.state, 1);
  row("export view, 1,000 events (the last 1,000 of the history) with toRecords", "≤ 80 ms", tail.toFixed(2), "ms", tail <= 80, `from ${head - 999} to ${head} (then each run one event earlier: both ends computed cold), ${full.state.stateRecords.size} toRecords`);
  const firstRuns = [];
  for (let r = 0; r < RUNS; r += 1) { const first = core.replay(events.slice(0, 1000)).state; firstRuns.push(time(() => core.exportViewState(first, { fromPosition: 0, toPosition: 999, include: { toRecords: true } }))[0]); }
  const start = median(firstRuns);
  console.log(`       (a 1,000-event history, from 0 to 999 with toRecords: ${ms(start)})`);
}

// ---------------------------------------------------------------- rollover at period 1,000,000
{
  // The same vector in conformance/v2-g3 (identical id, input and expect): the frozen conformance/v2 history is signed
  // under the frozen-r2.3 challenge profile, and the engine's default profile is g3 (A-54), so it would not replay here.
  const V2 = new URL("conformance/v2-g3/", REPO);
  const vectors = JSON.parse(readFileSync(new URL("vectors.json", V2), "utf8"));
  const vector = vectors.find((v) => v.id === "headroom/v2/b-amount-far-future-idle-stretch");
  const history = JSON.parse(readFileSync(new URL(`histories/${vector.history.ref}.json`, V2), "utf8")).slice(0, vector.history.eventCount);
  const state = core.replay(history).state;
  const answer = core.headroom(state, vector.input.budgetId, vector.input.at);
  if (answer.remainingAmount !== vector.expect.remainingAmount || answer.periodIndex !== vector.expect.periodIndex) throw new Error("headroom vector");
  const runs = [];
  for (let r = 0; r < Math.max(RUNS, 101); r += 1) runs.push(time(() => core.headroom(state, vector.input.budgetId, vector.input.at))[0]);
  const m = median(runs);
  row("rollover at period 1,000,000 (headroom/v2/b-amount-far-future-idle-stretch)", "≤ 0.1 ms", m.toFixed(4), "ms", m <= 0.1, `${runs.length} calls, answer matches the vector`);
}

// ---------------------------------------------------------------- append: owner control event at 10,000 events
{
  // Signer latency excluded: the owner key file's signer, wrapped to time every signature (the control authorization and the pin attestation).
  const keyFile = signerModule.ownerKeyPathFor(historyFile);
  const inner = signerModule.loadOwnerKeyFile(keyFile);
  let signing = 0;
  const timed = (fn) => (...a) => { const t = performance.now(); try { return fn(...a); } finally { signing += performance.now() - t; } };
  const signer = { ...inner, signHashSync: timed(inner.signHashSync), signHash: async (...a) => { const t = performance.now(); try { return await inner.signHash(...a); } finally { signing += performance.now() - t; } } };
  // The time the store spends in fsync (the line, the pin file and its directory), measured by wrapping fs.fsyncSync.
  let syncing = 0;
  const realFsync = fs.fsyncSync;
  fs.fsyncSync = (fd) => { const t = performance.now(); try { return realFsync(fd); } finally { syncing += performance.now() - t; } };
  syncBuiltinESMExports();
  const owner = openLocalOwner(ownerConfig({ signer }));
  owner.stateRoot(); // opened (snapshot resume), as a long-lived writer is
  const samples = [], gross = [], signatures = [], syncs = [], cpu = [];
  for (let i = 0; i < Math.max(RUNS, 21); i += 1) {
    signing = 0; syncing = 0;
    const t = performance.now();
    const result = await owner.updateBudget(budgetUpdate(2_000_000_000 + i));
    const total = performance.now() - t;
    if (result.checkpoint !== undefined) throw new Error("checkpoint suppressed");
    gross.push(total); signatures.push(signing); samples.push(total - signing); syncs.push(syncing); cpu.push(total - signing - syncing);
  }
  fs.fsyncSync = realFsync;
  syncBuiltinESMExports();
  const m = median(samples);
  row(`append at ${events.length} events (owner updateBudget: control signature, pin attestation, snapshot journal; fsync on)`, "≤ 5 ms (signer latency excluded)", m.toFixed(2), "ms", m <= 5,
    `with signing ${ms(median(gross))}; signing alone ${ms(median(signatures))}; of which in fsync ${ms(median(syncs))} (3 per append); without signing and fsync ${ms(median(cpu))}; max ${ms(Math.max(...samples))} (an automatic checkpoint every 256 events lands in one append)`);
  // fsync on this disk, for scale (the store fsyncs the line, the pin file and its directory).
  const probe = join(work, "fsync-probe"), fd = openSync(probe, "w"), fsyncs = [];
  for (let r = 0; r < 21; r += 1) { writeSync(fd, "x"); fsyncs.push(time(() => fsyncSync(fd))[0]); }
  closeSync(fd);
  console.log(`       (one fsync on this disk: median ${ms(median(fsyncs))})`);
  owner.close?.();
}

// ---------------------------------------------------------------- hook PreToolUse check
{
  const config = hookConfig.validateConfig({
    history: historyFile, owner: BENCH_OWNER, controller: "operator", domain: meta.config.domain, agentId: "bot", roleId: "worker", protocol: "claude-code",
    sessionTtlMs: 1e13, decisions: { onAllow: "allow", onReadOnly: "defer" },
    policy: { sideEffecting: [{ tool: "Write", action: "write", resource: "doc:1" }], readOnly: ["Read"], unmapped: "ask" },
  }, join(work, "irontrellis-hook.json"));
  const host = "bench-host-session";
  const now = () => (clock += 1);
  if (!existsSync(hooks.sessionKeyFile(config, host))) {
    const owner = hooks.openOwner(config, now);
    const admission = await hooks.admitSession(owner, config, host, clock);
    if (!admission.admitted) throw new Error(`hook session not admitted: ${JSON.stringify(admission)}`);
    await owner.checkpoint(); // an owner-signed root at the head the next opens resume from
  }
  const event = { kind: "tool", sessionId: host, cwd: work, toolName: "Write", toolInput: { file_path: join(work, "out.txt"), content: "x" }, toolUseId: "t", canAsk: true, mcpServer: undefined, deferTo: undefined };
  const check = () => {
    const owner = hooks.openOwner(config, now);
    const decision = hooks.decideTool(owner, config, event, clock);
    if (decision.verdict !== "allow") throw new Error(`hook decision ${decision.verdict}: ${decision.reason}`);
    return owner;
  };
  const measure = (label) => {
    check(); // the first open after a write may rebuild the snapshot base
    storeModule.resetStoreCountersForTests();
    const runs = [];
    for (let r = 0; r < RUNS; r += 1) runs.push(time(check)[0]);
    const counters = { ...storeModule.storeCounters };
    const snapshotState = JSON.parse(readFileSync(`${historyFile}.state`, "utf8").slice(0, 200).replace(/,"records".*$/s, "}").replace(/,"stateRoot".*$/s, "}"));
    return { m: median(runs), runs, counters, base: snapshotState.position };
  };
  const head0 = core.replay(readEvents()).state.head.position;
  const near = measure("near");
  row(`hook PreToolUse check at ${head0 + 1} events, snapshot at the head (openOwner + decideTool, §7.5 root recomputed)`, "≤ 20 ms", near.m.toFixed(2), "ms", near.m <= 20,
    `runs ${near.runs.map(ms).join(", ")}; store counters over ${RUNS} checks: ${JSON.stringify(near.counters)}`);
  // 256 events after the owner-signed root: runtime-signed refusals by the hook's own session (no owner attestation).
  const keyRecord = JSON.parse(readFileSync(hooks.sessionKeyFile(config, host), "utf8"));
  const pair = keyPairFromPrivateKey(keyRecord.scheme, keyRecord.keyId, keyRecord.privateKey);
  const runtime = openLocalRuntime({ ...ownerConfig(), session: keyRecord.sessionId, signHash: signHashWith(pair) });
  const owner = hooks.openOwner(config, now);
  await owner.checkpoint();
  const sim = openLocalSimulation({ ...ownerConfig(), session: keyRecord.sessionId, signHash: signHashWith(pair) });
  for (let i = 0; i < 85; i += 1) { const run = await sim.run({ id: `tail:${i}`, intentId: `tail:${i}`, action: "spend", resource: "cash", role: "worker", tenure: "t:1", amount: 1n, termsCommitment: commitTerms({ tail: i }) }); if (run.status !== "SIMULATION_RESULT") throw new Error(`tail ${i}: ${run.status}`); }
  const far = measure("far");
  const after = readEvents().length;
  row(`hook PreToolUse check at ${after} events, 256 events after the snapshot's signed root`, "≤ 20 ms", far.m.toFixed(2), "ms", far.m <= 20,
    `runs ${far.runs.map(ms).join(", ")}; store counters over ${RUNS} checks: ${JSON.stringify(far.counters)}`);
  // For scale: the hook as the host runs it, one process per event (the built binary: `pnpm -r build` first).
  const bin = fileURLToPath(new URL("packages/hooks/bin/irontrellis-hook.mjs", REPO));
  if (existsSync(fileURLToPath(new URL("packages/hooks/dist/index.js", REPO)))) {
    writeFileSync(join(work, "irontrellis-hook.json"), JSON.stringify({ history: historyFile, owner: BENCH_OWNER, controller: "operator", domain: meta.config.domain, agentId: "bot", roleId: "worker", protocol: "claude-code",
      sessionTtlMs: 1e13, decisions: { onAllow: "allow", onReadOnly: "defer" }, policy: { sideEffecting: [{ tool: "Write", action: "write", resource: "doc:1" }], readOnly: ["Read"], unmapped: "ask" } }));
    const payload = JSON.stringify({ session_id: host, transcript_path: join(work, "t.jsonl"), cwd: work, permission_mode: "default", hook_event_name: "PreToolUse", tool_name: "Write", tool_input: event.toolInput, tool_use_id: "t" });
    const spawned = [];
    let reply = "";
    for (let r = 0; r < Math.min(RUNS, 5); r += 1) {
      const t = performance.now();
      const result = spawnSync(process.execPath, [bin, "claude-code", "PreToolUse"], { cwd: work, input: payload, encoding: "utf8", env: { ...process.env, IRONTRELLIS_HOME: join(work, "home") } });
      spawned.push(performance.now() - t);
      reply = `exit ${result.status}: ${result.stdout.trim().slice(0, 400)}${result.stderr.trim() === "" ? "" : ` / ${result.stderr.trim().slice(0, 300)}`}`;
    }
    const empty = [];
    for (let r = 0; r < Math.min(RUNS, 5); r += 1) empty.push(time(() => spawnSync(process.execPath, ["-e", "0"]))[0]);
    console.log(`       (the hook binary, one process per PreToolUse as the host runs it: median ${ms(median(spawned))}; an empty node process: ${ms(median(empty))}; reply ${reply})`);
  }
}

// ---------------------------------------------------------------- engine size
{
  let lines = 0;
  const walk = (path) => { for (const entry of readdirSync(path, { withFileTypes: true })) { const p = join(path, entry.name); if (entry.isDirectory()) walk(p); else if (entry.name.endsWith(".ts")) lines += readFileSync(p, "utf8").split("\n").length - 1; } };
  walk(fileURLToPath(SRC));
  console.log(`\nengine size: packages/core/src ${lines} lines (*.ts; the format-1 engine: 24,703)`);
}
console.log(`\n${rows.filter((r) => r.pass).length} of ${rows.length} rows within budget; load average at the end: ${loadavg().map((l) => l.toFixed(2)).join(" ")}`);
if (KEEP) console.log(`history kept in ${dir}`);
