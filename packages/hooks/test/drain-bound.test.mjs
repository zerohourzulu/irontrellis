/**
 * A-38.1 / KNOWN-ISSUES 70: the hook's deny path drains the refusal spool first. Each waiting entry used to re-open the
 * history to ask whether it was already recorded, so the verdict waited for one store open per entry (measured: 7.6 s
 * for 60 entries at 2,009 events). The drain now reads the recorded refusals once, and the drain and this refusal share
 * one recordBudgetMs, so a large spool on a large history still answers within about one budget.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { appendFileSync, mkdtempSync, realpathSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";
import { createLocalDomain, createLocalOwner, openHistoryStore, openLocalOwner, storeCounters, resetStoreCountersForTests } from "@ramex-labs/irontrellis";

const BIN = resolve(fileURLToPath(new URL("../bin/irontrellis-hook.mjs", import.meta.url)));
const STATE_HOME = mkdtempSync(join(tmpdir(), "irontrellis-home-"));
const run = (args, cwd, stdin = "") => spawnSync(process.execPath, [BIN, ...args], { cwd, input: stdin, encoding: "utf8", env: { ...process.env, NO_COLOR: "1", IRONTRELLIS_HOME: STATE_HOME } });
const sessionStart = (dir) => JSON.stringify({ session_id: "cc-session-1", transcript_path: `${dir}/.claude/transcript.jsonl`, cwd: dir, permission_mode: "default", hook_event_name: "SessionStart", source: "startup" });

test("A-38.1 (KNOWN-ISSUES 70): with 600 refusals waiting on a 300-event history, the hook's deny path opens the history a bounded number of times, answers within about one recordBudgetMs, and spools its own refusal once the drain used the budget", { timeout: 300_000 }, async (t) => {
  const { recordToolRefusal } = await import("../dist/index.js");
  const { loadConfigFile } = await import("../dist/config.js");
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "irontrellis-hook-")));
  const historyFile = join(dir, "history.jsonl");
  const created = await createLocalOwner({ historyFile, domain: createLocalDomain(), owner: "principal:owner", controller: "controller:irontrellis-hook", now: () => Date.now() });
  created.close();
  const init = run(["init", "--history", "history.jsonl", "--allow", "run-shell", "--expires", "+1d", "--i-understand-same-user-risk"], dir);
  assert.equal(init.status, 0, init.stderr);
  const start = run(["claude-code", "SessionStart"], dir, sessionStart(dir));
  assert.equal(start.status, 0, start.stderr);
  const config = loadConfigFile(join(dir, "irontrellis-hook.json"));
  const owner = await openLocalOwner({ historyFile, domain: config.domain, owner: config.owner, controller: config.controller, now: () => Date.now() });
  for (let i = 0; i < 300; i += 1) await owner.createAgent({ id: `filler-${i}` });
  owner.close();
  const WAITING = 600; // enough that the drain always reaches its deadline (each RATE_LIMITED entry costs a side-log fsync)
  const spool = `${historyFile}.refusals.spool`;
  for (let i = 0; i < WAITING; i += 1) {
    appendFileSync(spool, JSON.stringify({ version: "irontrellis-refusal-spool/1", refusalId: `0x${randomBytes(32).toString("hex")}`, attemptedAt: Date.now() - 120_000, request: { actorId: config.agentId, action: "call-mcp", resource: `mcp:waiting-${i}` } }) + "\n");
  }
  // What one open of this history costs here, for a machine-independent bound.
  const opening = performance.now();
  openHistoryStore(historyFile, { inspect: true, witness: false }).state();
  const openSeconds = (performance.now() - opening) / 1000;

  const BUDGET = 250;
  resetStoreCountersForTests();
  const started = performance.now();
  const live = await recordToolRefusal(config, "cc-session-1", { action: "call-mcp", resource: "mcp:live" }, () => Date.now(), BUDGET);
  const seconds = (performance.now() - started) / 1000;
  const opens = storeCounters.resumes + storeCounters.fullReplays;
  t.diagnostic(`${WAITING} waiting, one open ${(openSeconds * 1000).toFixed(0)} ms: the deny path took ${seconds.toFixed(2)} s with ${opens} history opens; live ${JSON.stringify(live)}`);
  // Before: one open per waiting entry (here 600, and about 600 × the open time).
  assert.ok(opens <= 4, `the deny path opened the history ${opens} times`);
  // The drain reached the shared deadline, so the call's own refusal was spooled with no further wait (with a budget of its
  // own it would wait for its write, and come back RATE_LIMITED after the drain's six recorded entries).
  assert.deepEqual(live, { recorded: false, reason: "SPOOLED" });
  // About one recordBudgetMs for the drain and the refusal together, plus the deny path's own store opens before recording
  // starts (three), one read and one rewrite of the waiting spool and the write in progress: not a hard real-time bound, and
  // a loaded full suite stretches it (0.36 s alone and in build2-80/81, 0.42 s on the Linux VM). The bound is generous on
  // purpose: before the fix this deny path took one open per waiting entry (6.94 s for 150, about 30 s for 600). The exact
  // checks are the open count above and the SPOOLED own refusal.
  const bound = BUDGET / 1000 + 10 * openSeconds + 1.0;
  assert.ok(seconds < bound, `the deny path took ${seconds.toFixed(2)} s (bound ${bound.toFixed(2)} s)`);
});
