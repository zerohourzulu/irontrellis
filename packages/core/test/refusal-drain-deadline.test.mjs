// A-38.1 / KNOWN-ISSUES 70 (D-02): a bounded caller's drain of the refusal spool and the call's own refusal share one
// recordBudgetMs. Past the deadline no entry is started and an entry whose write outlasts it stays spooled; the call's own
// refusal gets what the drain left (here none, so it is spooled too), and the call answers within about one budget. A
// later drain (or an explicit one) records the rest, and nothing is lost.
import { test } from "node:test";
import assert from "node:assert/strict";
import { appendFileSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { randomBytes } from "node:crypto";

const { createLocalDomain, createLocalOwner, openHistoryStore, openLocalSimulation, commitTerms, spooledRefusalCount } = await import("../src/index.ts");
const { generateKeyPair, signHashWith } = await import("../src/crypto/suites.ts");
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

test("A-38.1 (KNOWN-ISSUES 70): a refused call's drain and its own refusal share one recordBudgetMs; the rest stays spooled and a later drain records it", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-drain-deadline-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let tick = 100;
  const config = { historyFile: join(dir, "history.jsonl"), domain: createLocalDomain(), owner: "operations", controller: "operator", now: () => tick, witness: false };
  const owner = await createLocalOwner(config);
  await owner.createAgent({ id: "bea" });
  await owner.createRole({ id: "reviewer" });
  await owner.appoint({ agent: "bea", role: "reviewer", tenure: "shift:1", number: 1 });
  const pair = generateKeyPair("ed25519", "key:1");
  await owner.admitRuntime({ session: "session:1", agent: "bea", epoch: 1, key: "key:1", credential: pair.credential, expiresAt: 10_000_000 });
  owner.close();
  const sign = signHashWith(pair);
  let mode = "fail";
  // "fail": outlast the budget, then give up (the entry stays spooled); "slow": slow storage, 20 ms a signature.
  const signHash = async (hash) => { if (mode === "fail") { await wait(15); throw new Error("storage gave up (test)"); } if (mode === "slow") await wait(20); return sign(hash); };
  const RAISED = { recordBudgetMs: 50, maxPerMinute: 1_000_000 }; // A-23.2 raised, so every drained entry is a real write
  const runtime = (policy) => openLocalSimulation({ ...config, session: "session:1", signHash, refusalPolicy: policy });
  const op = (n) => ({ id: `op:${n}`, intentId: `op:${n}`, action: "read", resource: `nowhere:${n}`, role: "reviewer", tenure: "shift:1", termsCommitment: commitTerms({ n }) });

  // One refusal spooled through the API, then N - 1 more with the same shape (fresh ids and resources).
  const N = 40;
  const first = await runtime({ recordBudgetMs: 5, maxPerMinute: 1_000_000 }).run(op(0));
  assert.equal(first.refusalNotRecorded?.reason, "SPOOLED");
  await wait(50);
  const spool = `${config.historyFile}.refusals.spool`;
  const [line] = readFileSync(spool, "utf8").trim().split("\n");
  const entry = JSON.parse(line);
  for (let n = 1; n < N; n += 1) {
    appendFileSync(spool, JSON.stringify({ ...entry, refusalId: `0x${randomBytes(32).toString("hex")}`, request: { ...entry.request, resource: `nowhere:${n}` } }) + "\n");
  }
  assert.equal(spooledRefusalCount(config.historyFile), N);
  const spooledIds = readFileSync(spool, "utf8").trim().split("\n").map((l) => JSON.parse(l).refusalId);

  // Slow storage: a drain without a deadline would take about N × 45 ms here (KNOWN-ISSUES 70: 4.4 s for 100).
  mode = "slow"; tick += 60_000;
  const handle = runtime(RAISED);
  const started = performance.now();
  const next = await handle.run(op(N + 1));
  const seconds = (performance.now() - started) / 1000;
  assert.equal(next.status, "NOT_AUTHORIZED");
  t.diagnostic(`a refused call with ${N} spooled entries and a 20 ms store: ${seconds.toFixed(2)} s; its own refusal: ${next.refusalNotRecorded?.reason ?? "recorded"}; left in the spool: ${spooledRefusalCount(config.historyFile)}`);
  // About one 50 ms budget for the drain and the call's own refusal, not a hard bound: 0.06 s alone, 0.16 s and 0.36 s in the
  // loaded full suite (build2-80, build2-81). The unbounded drain took 1.80 s here, so the check is that it stays well below
  // that; the shared budget itself is checked by the SPOOLED assertion below and by the deterministic test.
  assert.ok(seconds < 0.9, `the refused call took ${seconds.toFixed(2)} s`);
  assert.equal(next.refusalNotRecorded?.reason, "SPOOLED", "the drain used the budget, so the call's own refusal waits no further and is spooled");
  assert.ok(spooledRefusalCount(config.historyFile) >= N - 10, "the entries the deadline did not reach stay spooled");
  spooledIds.push(...readFileSync(spool, "utf8").trim().split("\n").map((l) => JSON.parse(l).refusalId).filter((id) => !spooledIds.includes(id)));

  // A later, explicit drain (no deadline) records the rest: every spooled refusal ends in the history.
  await wait(200); // any abandoned write has settled
  mode = "normal";
  const outcomes = await runtime(RAISED).drainRefusals();
  assert.ok(outcomes.every((o) => o.outcome === "RECORDED" || o.outcome === "ALREADY_RECORDED"), JSON.stringify(outcomes.filter((o) => o.outcome !== "RECORDED" && o.outcome !== "ALREADY_RECORDED")));
  assert.equal(spooledRefusalCount(config.historyFile), 0);
  const recorded = new Set(openHistoryStore(config.historyFile).state().refusals.keys());
  assert.deepEqual(spooledIds.filter((id) => !recorded.has(id)), [], "no spooled refusal is lost");
});

test("A-38.1: a drained write that never settles is KEPT at the deadline and the drain returns, reporting the deadline and the write still running; when the write later succeeds the next drain finds it ALREADY_RECORDED and starts no second write (Astra's stalled-write control, review 20261028T214227Z)", async (t) => {
  const { drainRefusalSpool, REFUSAL_SPOOL_VERSION } = await import("../src/refusal-spool.ts");
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-drain-stalled-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const history = join(dir, "history");
  const entry = { version: REFUSAL_SPOOL_VERSION, refusalId: "synthetic-stalled-id", attemptedAt: 1, request: { actorId: "bea", action: "read", resource: "denied" } };
  appendFileSync(`${history}.refusals.spool`, JSON.stringify(entry) + "\n");
  let release;
  const attempt = new Promise((resolve) => { release = resolve; });
  t.after(() => release({}));
  let writes = 0, timer;
  const report = { deadlineReached: false, writeStillRunning: false };
  // A 200 ms deadline (Astra's control used 10 ms): under a loaded test run the deadline, rechecked just before the write,
  // could pass before the first write even started (build2-80: 0 writes), which is correct but not what this test checks.
  const hung = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("the drain did not return while its write stayed unresolved")), 5000); });
  const result = await Promise.race([drainRefusalSpool(history, { recordRefusal: () => { writes += 1; return attempt; } }, "bea", () => 2, () => false, { deadlineMs: 200, report }), hung]);
  clearTimeout(timer);
  assert.deepEqual(result, [{ refusalId: entry.refusalId, outcome: "KEPT" }]);
  assert.equal(writes, 1);
  assert.deepEqual(report, { deadlineReached: true, writeStillRunning: true });
  assert.deepEqual(JSON.parse(readFileSync(`${history}.refusals.spool`, "utf8")), entry, "the entry is back in the spool");
  release({ eventId: "synthetic-event" }); await attempt;
  const again = await drainRefusalSpool(history, { recordRefusal: async () => { throw new Error("must not repeat a completed write"); } }, "bea", () => 3, (id) => id === entry.refusalId);
  assert.deepEqual(again, [{ refusalId: entry.refusalId, outcome: "ALREADY_RECORDED" }]);
});

test("A-38.1: when the drain reaches the shared deadline with a write still running, the call's own refusal waits no further and is spooled, though its own write may still start (deterministic: the drain's write never settles)", { timeout: 10_000 }, async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-drain-own-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let tick = 100;
  const config = { historyFile: join(dir, "history.jsonl"), domain: createLocalDomain(), owner: "operations", controller: "operator", now: () => tick, witness: false };
  const owner = await createLocalOwner(config);
  await owner.createAgent({ id: "bea" });
  await owner.createRole({ id: "reviewer" });
  await owner.appoint({ agent: "bea", role: "reviewer", tenure: "shift:1", number: 1 });
  const pair = generateKeyPair("ed25519", "key:1");
  await owner.admitRuntime({ session: "session:1", agent: "bea", epoch: 1, key: "key:1", credential: pair.credential, expiresAt: 10_000_000 });
  owner.close();
  const sign = signHashWith(pair);
  let mode = "fail", calls = 0;
  // "fail": outlast the budget, then give up (the entry stays spooled); "stall-first": the next signature never settles (the
  // drain's first write), every later one is immediate (the call's own refusal could be written at once if it were tried).
  const signHash = async (hash) => {
    if (mode === "fail") { await wait(15); throw new Error("storage gave up (test)"); }
    calls += 1;
    if (calls === 1) return new Promise(() => undefined);
    return sign(hash);
  };
  const runtime = (policy) => openLocalSimulation({ ...config, session: "session:1", signHash, refusalPolicy: policy });
  const op = (n) => ({ id: `op:${n}`, intentId: `op:${n}`, action: "read", resource: `nowhere:${n}`, role: "reviewer", tenure: "shift:1", termsCommitment: commitTerms({ n }) });
  const first = await runtime({ recordBudgetMs: 5, maxPerMinute: 1_000_000 }).run(op(0));
  assert.equal(first.refusalNotRecorded?.reason, "SPOOLED");
  await wait(50);
  mode = "stall-first"; tick += 60_000;
  const next = await runtime({ recordBudgetMs: 50, maxPerMinute: 1_000_000 }).run(op(1));
  assert.equal(next.status, "NOT_AUTHORIZED");
  assert.equal(next.refusalNotRecorded?.reason, "SPOOLED", "the call's own refusal adds no wait while the drain's write is still running");
  assert.equal(spooledRefusalCount(config.historyFile), 2, "the drained entry and the call's own refusal both wait in the spool");
});
