// Worker for the store test "locking: two processes reclaiming the same stale lock never both hold it".
// argv: <history> <rounds> <barrier dir> <worker id 0|1> <dead pid>.
//
// Rounds are driven by a file barrier, not by the wall clock, so CPU load can slow the test down but cannot change
// what a round looks like. Each round:
//   1. both workers reach the barrier; a stale lock (dead pid, two minutes old) is in place;
//   2. both race `withExclusiveWriter` (lockTimeoutMs 0), which must reclaim the stale lock to get in;
//   3. the winner stays inside its critical section until the other worker has finished its attempt, so the other
//      attempt always meets either the stale lock or the winner's live lock, never an empty path, and must end in
//      STORE_BUSY: exactly one winner per round, independent of scheduling. The loser then tries once more while the
//      winner is still inside (review block 5, M3): a reclaimer that moved the live lock aside without putting it back
//      would let this retry in. Before leaving, the winner checks that the lock path still holds its own lock;
//   4. the winner releases and plants the next stale lock before it enters the next barrier.
// The critical section creates an exclusive marker file: if both workers were ever inside at once, the second `wx`
// fails and counts as a violation. The injected clock sleeps 0–2 ms at random: `now()` runs between reading the lock
// and reclaiming it, so the jitter widens exactly the window a check-then-unlink reclaim loses.
//
// Reclaims are counted at the file-system level: `renameSync` is wrapped (before the store module is loaded, with
// `syncBuiltinESMExports`, so the store's named import sees the wrapper) and every rename of the lock path aside is
// classified by what was moved: the planted stale lock (a reclaim) or a live lock (a displacement, linked back).
import fs, { closeSync, existsSync, futimesSync, openSync, readFileSync, unlinkSync, writeFileSync, writeSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { hostname } from "node:os";
import { join } from "node:path";

const [path, roundsText, barrier, idText, deadPidText] = process.argv.slice(2);
const rounds = Number(roundsText), id = Number(idText), other = 1 - id, deadPid = Number(deadPidText);
const lock = `${path}.writer-lock`, inside = `${path}.inside`;
const sleep = (ms) => { if (ms > 0) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); };

const holderPid = (file) => { try { return JSON.parse(readFileSync(file, "utf8")).pid; } catch { return undefined; } };
let renamedStale = 0, relinkedStale = 0, displaced = 0, relinked = 0;
const realRename = fs.renameSync, realLink = fs.linkSync;
fs.renameSync = (from, to) => {
  realRename(from, to);
  if (String(from) === lock && String(to).includes(".stale-")) {
    if (holderPid(to) === deadPid) renamedStale += 1; else displaced += 1;
  }
};
fs.linkSync = (from, to) => {
  const back = String(to) === lock && String(from).includes(".stale-");
  const pid = back ? holderPid(from) : undefined;
  realLink(from, to);
  if (back && pid === deadPid) relinkedStale += 1;
  else if (back) relinked += 1; // a displaced live lock put back (counted only when the link succeeded)
};
syncBuiltinESMExports();

const { openHistoryStore } = await import("../src/store.ts");
const store = openHistoryStore(path, { now: () => { sleep(Math.floor(Math.random() * 3)); return Date.now(); } });

/** Waits until `file` exists: spins briefly (both workers should leave a barrier together), then polls. */
const waitFor = (file, what) => {
  const deadline = Date.now() + 120_000;
  for (let spins = 0; !existsSync(file); spins += 1) {
    if (Date.now() > deadline) throw new Error(`worker ${id}: timed out waiting for ${what}`);
    if (spins > 2_000) sleep(1);
  }
};
const mark = (name) => writeFileSync(join(barrier, name), "");
const marked = (name) => join(barrier, name);

/** Leaves a lock behind as a crashed writer would (dead pid, two minutes old). The path is free here: the round is over. */
const plantStale = () => {
  const fd = openSync(lock, "wx", 0o600);
  const old = Date.now() - 120_000;
  writeSync(fd, JSON.stringify({ pid: deadPid, hostname: hostname(), createdAt: old }));
  futimesSync(fd, old / 1000, old / 1000);
  closeSync(fd);
};

const outcomes = [], reclaims = [];
let violations = 0, lockLost = 0, retryEntered = 0;
for (let round = 0; round < rounds; round += 1) {
  mark(`ready-${round}-${id}`);
  waitFor(marked(`ready-${round}-${other}`), `the other worker at round ${round}`);
  const before = renamedStale - relinkedStale;
  let outcome;
  try {
    store.withExclusiveWriter(() => {
      let fd;
      try { fd = openSync(inside, "wx"); } catch { violations += 1; outcome = "V"; return; }
      sleep(1);
      mark(`attempted-${round}-${id}`);
      // Hold the lock until the other worker's attempts are over: they must have met this live lock.
      waitFor(marked(`attempted-${round}-${other}`), `the other worker's attempt in round ${round}`);
      // The lock path must still be this worker's lock: not moved aside, deleted or replaced by the other's reclaim.
      if (holderPid(lock) !== process.pid) lockLost += 1;
      closeSync(fd);
      unlinkSync(inside);
      outcome = "W";
    });
  } catch (error) {
    if (error.code !== "STORE_BUSY") throw error;
    outcome = "B";
  }
  if (outcome === "B") {
    // One more attempt while the winner is still inside: it must meet the winner's lock again.
    try {
      store.withExclusiveWriter(() => {
        let fd;
        try { fd = openSync(inside, "wx"); } catch { violations += 1; return; }
        closeSync(fd);
        unlinkSync(inside);
        retryEntered += 1;
      });
    } catch (error) {
      if (error.code !== "STORE_BUSY") throw error;
    }
  }
  if (outcome !== "W") mark(`attempted-${round}-${id}`);
  outcomes.push(outcome);
  reclaims.push(renamedStale - relinkedStale - before);
  if (outcome === "W") plantStale();
  // The loser waits until the winner has planted the next stale lock (the winner marks ready-(round+1) after planting).
}
process.stdout.write(JSON.stringify({ outcomes: outcomes.join(""), reclaims, violations, lockLost, retryEntered, displaced, relinked }));
