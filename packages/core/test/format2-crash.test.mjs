// T3 store parity (BUILD §4; LEFT-OUT-SWEEP D4): the seven write-interruption points of reference-0.3's
// history-store.test.mjs ("actual process death at every commit cut") re-expressed against the format-2 store, with the
// snapshot's own cut points added, plus the competing-writer case ("two real processes cannot both commit the same
// expected revision"). A worker process (crash-worker.mjs) is killed with SIGKILL at each point. After each kill the
// file is reopened in both trust modes and must be either detected (ROLLBACK_DETECTED / INVALID_HISTORY /
// WRITE_UNCONFIRMED / STORE_BUSY) or recovered: a state equal to a full replay of the file, every query equal, a
// successful next write after the dead writer's lock is reclaimed, and the snapshot rebuilt where it was torn.
//
//   reference cut            → format-2 store cut
//   before-segment-create    → before-append          (lock held, nothing written)
//   segment-synced           → line-appended          (line written + fsynced, pin not replaced)
//   manifest-file-synced     → before-pin-replace     (pin temp file written and synced, not renamed)
//   before-manifest-replace  → (same point; the pin rename is the atomic step)
//   manifest-replaced        → pin-replaced           (pin renamed, directory not synced)
//   manifest-directory-synced→ pin-directory-synced
//   before-reply             → before-reply           (everything durable, the caller never heard)
//   snapshot (E3)            → before-journal, journal-written, base-replaced (compaction: base written, journal not emptied)
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, rmSync, unlinkSync, utimesSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const core = await import("../src/index.ts");
const { openHistoryStore, storeCounters, resetStoreCountersForTests } = await import("../src/store.ts");
const { readSnapshotFiles, journalPathFor } = await import("../src/snapshot.ts");
const histories = await import("./helpers/format2-histories.mjs");
const { createLocalDomain, createLocalOwner, openLocalOwner } = await import("../src/owner.ts");

const WORKER = fileURLToPath(new URL("./crash-worker.mjs", import.meta.url));
const run = (path, cut, agentId, domain, who = ["operations", "operator"]) => new Promise((resolve, reject) => {
  const child = spawn(process.execPath, ["--experimental-strip-types", WORKER, path, cut, agentId, JSON.stringify(domain), ...who], { stdio: ["ignore", "pipe", "pipe"] });
  let out = "", err = "";
  child.stdout.on("data", (chunk) => { out += chunk; });
  child.stderr.on("data", (chunk) => { err += chunk; });
  child.on("error", reject);
  child.on("exit", (status, signal) => resolve({ status, signal, out, err }));
});
const json = (value) => JSON.stringify(value, (_k, v) => (typeof v === "bigint" ? `${v}n` : v));
/** The answers a state gives (a grid of requests at the head time), for equality between a reopened handle and a full replay. */
const answers = (state) => {
  const o = core.observeState(state);
  return json({ root: core.stateRootOf(state), head: state.head, n: state.events.length, auth: ["a", "b", "c"].map((actor) => o.authorize({ actor, action: "read", resource: "incident:42" }).evidence), survives: o.survives("a"), records: core.stateRecordsOf(state).length });
};
/** Makes the dead worker's lock reclaimable (dead pid, older than LOCK_STALE_MS), as the reference's `recoverLock` does explicitly. */
const ageLock = (path) => {
  const lock = `${path}.writer-lock`;
  if (!existsSync(lock)) return false;
  const holder = JSON.parse(readFileSync(lock, "utf8"));
  const old = Date.now() - 120_000;
  writeFileSync(lock, JSON.stringify({ ...holder, hostname: hostname(), createdAt: old }));
  utimesSync(lock, old / 1000, old / 1000);
  return true;
};

async function fixture(t) {
  const dir = histories.tempDir("irontrellis-t3-");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const { config, events } = await histories.richHistory(dir);
  return { dir, path: config.historyFile, domain: config.domain, events, config };
}

test("T3: process death at every write-interruption point is detected or recovered on reopen with state equal to a full replay", async (t) => {
  const CUTS = ["before-append", "line-appended", "before-pin-replace", "pin-replaced", "pin-directory-synced", "before-journal", "journal-written", "base-replaced", "before-reply"];
  for (const cut of CUTS) {
    const { path, domain, events } = await fixture(t);
    const before = { file: readFileSync(path), pin: readFileSync(`${path}.head`, "utf8"), n: events.length };
    if (cut === "base-replaced") unlinkSync(journalPathFor(path)); // the journal is out of step with the writer's head: the write compacts
    const result = await run(path, cut, `crash:${cut}`, domain);
    assert.equal(result.signal, "SIGKILL", `${cut}: ${result.out} ${result.err}`);
    assert.ok(result.out.includes(`CUT ${cut}`), `${cut}: ${result.out}`);
    const fileGrew = !readFileSync(path).equals(before.file);
    // `base-replaced` can fire at the open-time rebuild (before the append) or at the write's compaction: both are a torn compaction.
    const committed = cut === "base-replaced" ? fileGrew : cut !== "before-append";
    assert.equal(fileGrew, committed, `${cut}: the line is ${committed ? "" : "not "}on disk`);
    // The dead writer's lock: a write is STORE_BUSY until the lock is reclaimable (dead pid, older than 60 s).
    assert.ok(existsSync(`${path}.writer-lock`), `${cut}: the dead writer left its lock`);
    const busy = openHistoryStore(path, { witness: false, allowUnpinned: true });
    assert.throws(() => busy.append({ id: "blocked", type: "PRINCIPAL_CREATED", timestamp: 20_000, data: { principalId: "blocked" } }), (e) => e.code === "STORE_BUSY", `${cut}: a live-looking lock is STORE_BUSY`);
    busy.close();
    ageLock(path);
    // Reopen in both trust modes: equal to a full replay of the bytes on disk; the pin is never behind the file and never ahead of it.
    const full = core.replay(JSON.parse(`[${readFileSync(path, "utf8").trim().split("\n").map((line) => JSON.stringify(JSON.parse(line).event)).join(",")}]`));
    assert.equal(full.status, "ACCEPTED", `${cut}: the file replays`);
    assert.equal(full.state.events.length, before.n + (committed ? 1 : 0));
    for (const trust of ["FULL_REPLAY", "CHECKPOINT_RESUME"]) {
      resetStoreCountersForTests();
      const store = openHistoryStore(path, { witness: false, trust });
      assert.equal(answers(store.state()), answers(full.state), `${cut}/${trust}: state equals a full replay`);
      const report = store.verify();
      assert.equal(report.ok, true, `${cut}/${trust}: ${report.failures.join("; ")}`);
      assert.ok(["MATCHES", "AHEAD"].includes(report.pinnedHeadStatus), `${cut}/${trust}: pin ${report.pinnedHeadStatus}`);
      if (trust === "CHECKPOINT_RESUME") {
        // A torn snapshot is stale (replayed in full, rebuilt); a complete one is used; never a wrong answer either way.
        assert.ok(["USED", "STALE"].includes(report.snapshot), `${cut}: snapshot ${report.snapshot}`);
        if (report.snapshot === "STALE") assert.equal(storeCounters.snapshotRebuilds, 1, `${cut}: rebuilt`);
      }
      store.close();
    }
    // The next writer (another process would do the same) reclaims the stale lock and appends; the snapshot is then current.
    const owner = openLocalOwner({ historyFile: path, domain, owner: "operations", controller: "operator", now: () => 30_000, witness: false });
    await owner.createAgent({ id: `after:${cut}` });
    const reopened = openHistoryStore(path, { witness: false, trust: "CHECKPOINT_RESUME" });
    assert.equal(reopened.loadedBy(), "CHECKPOINT_RESUME", `${cut}: the next open resumes`);
    assert.equal(reopened.state().events.length, full.state.events.length + 1);
    reopened.close();
    t.diagnostic(`${cut}: ${committed ? "committed, recovered" : "not committed, nothing on disk"}; lock STORE_BUSY until reclaimable`);
  }
});

test("T3: a torn journal line (partial write) is skipped, never trusted; the snapshot is rebuilt under the signed root", async (t) => {
  const { path, events } = await fixture(t);
  const files = readSnapshotFiles(path);
  const text = readFileSync(journalPathFor(path), "utf8");
  writeFileSync(journalPathFor(path), text.slice(0, text.length - 40)); // the last line torn
  const torn = readSnapshotFiles(path);
  assert.equal(torn.journal.length, files.journal.length - 1);
  resetStoreCountersForTests();
  const store = openHistoryStore(path, { witness: false, trust: "CHECKPOINT_RESUME" });
  assert.deepEqual(core.stateRootOf(store.state()), core.stateRootOf(core.replay(events).state));
  // Either resumed at an earlier signed root (the tail replayed) or replayed in full: never a wrong state.
  assert.ok(storeCounters.resumes + storeCounters.fullReplays === 1);
  store.close();
});

test("T3: two real processes cannot both commit at the same expected head (one succeeds, the other is STORE_BUSY/HISTORY_CONFLICT)", async (t) => {
  const { path, domain } = await fixture(t);
  const before = openHistoryStore(path, { witness: false }).state().events.length;
  const [a, b] = await Promise.all([run(path, "none", "race:a", domain), run(path, "none", "race:b", domain)]);
  const results = [a, b].map((r) => { try { return JSON.parse(r.out.trim().split("\n").at(-1)); } catch { return { ok: false, raw: r.out + r.err }; } });
  const succeeded = results.filter((r) => r.ok);
  const after = openHistoryStore(path, { witness: false }).state().events.length;
  // Each worker serialises through the writer lock: one appends; the other either appended after it (two events) or lost the lock (HISTORY_CONFLICT from STORE_BUSY).
  assert.ok(succeeded.length >= 1, JSON.stringify(results));
  assert.equal(after, before + succeeded.length, JSON.stringify(results));
  for (const r of results.filter((r) => !r.ok)) assert.ok(["HISTORY_CONFLICT", "STORE_BUSY"].includes(r.code), JSON.stringify(r));
  const store = openHistoryStore(path, { witness: false, trust: "CHECKPOINT_RESUME" });
  assert.equal(store.verify().ok, true);
  store.close();
});

test("T3: a writer that dies between the base write and the journal truncation leaves a usable snapshot (stale journal lines are ignored)", async (t) => {
  const dir = histories.tempDir("irontrellis-t3-");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let tick = 100;
  const config = { historyFile: join(dir, "h.jsonl"), domain: createLocalDomain(), owner: "o", controller: "c", now: () => (tick += 1), witness: false };
  const owner = await createLocalOwner(config);
  for (let n = 0; n < 5; n += 1) await owner.createAgent({ id: `a:${n}` });
  const path = config.historyFile;
  unlinkSync(journalPathFor(path));
  const result = await run(path, "base-replaced", "crash:compaction", config.domain, ["o", "c"]);
  assert.equal(result.signal, "SIGKILL", result.out + result.err);
  ageLock(path);
  const files = readSnapshotFiles(path);
  assert.equal(files.base.position, openHistoryStore(path, { witness: false }).state().head.position, "the base sits at the head the dead writer committed");
  resetStoreCountersForTests();
  const store = openHistoryStore(path, { witness: false, trust: "CHECKPOINT_RESUME" });
  assert.equal(store.loadedBy(), "CHECKPOINT_RESUME");
  assert.equal(store.verify().ok, true);
  store.close();
});
