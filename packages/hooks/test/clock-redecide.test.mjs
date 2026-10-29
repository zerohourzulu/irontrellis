// authorizeAtReading (hook.ts): the bounded re-decision after CAUSAL_TIME_INVALID, with an injected clock and a fake head.
// The fake authorize answers as the engine does (authority.ts stage): a time before the head is INDETERMINATE
// CAUSAL_TIME_INVALID; otherwise it decides (ALLOW here, so a test shows when a decision was reached). The A-22.4 check
// (clockAheadOfReader) runs on the reading the helper returns, as decideTool does.
import { test } from "node:test";
import assert from "node:assert/strict";
import { MAX_CLOCK_SKEW_MS, clockAheadOfReader } from "@ramex-labs/irontrellis";
import { authorizeAtReading, MAX_REDECIDE } from "../dist/hook.js";

/** A head at `headTimes[i]` on the i-th authorize (the last one repeats); records every time it was asked at. */
function fakeOwner(headTimes) {
  const asked = [];
  const authorize = (at) => {
    const canonicalTime = headTimes[Math.min(asked.length, headTimes.length - 1)];
    asked.push(at);
    const head = { hash: `0x${"ab".repeat(32)}`, position: 7, canonicalTime };
    return at < canonicalTime
      ? { head, evidence: { decision: "INDETERMINATE", code: "CAUSAL_TIME_INVALID" } }
      : { head, evidence: { decision: "ALLOW" } };
  };
  return { authorize, asked };
}
const clockOf = (readings) => { let i = 0; return () => readings[Math.min(i++, readings.length - 1)]; };

test("(a) a clock that stepped back between readings: no decision at a future time, and a head > 300 s ahead is still seen (A-22.4 deny)", () => {
  // The first reading was 1,000,000; after the history was open the clock reads 600,000. The head is at 1,000,000.
  const { authorize, asked } = fakeOwner([1_000_000]);
  const { d, at, redecided } = authorizeAtReading(authorize, 600_000, clockOf([600_001, 600_002]));
  assert.equal(at, 600_000, "the reading used is the post-open reading, never the earlier, larger one");
  assert.deepEqual(asked, [600_000], "a fresh reading still before the head is not decided at");
  assert.equal(redecided, 0);
  assert.equal(d.evidence.code, "CAUSAL_TIME_INVALID");
  assert.ok(Math.max(...asked) <= 600_002, "never asked at a time ahead of the clock");
  assert.equal(clockAheadOfReader(d.head, at), true, `400 s ahead is past the ${MAX_CLOCK_SKEW_MS} ms bound: decideTool denies CLOCK_AHEAD_OF_READER`);
  assert.equal(d.head.canonicalTime - at, 400_000);
});

test("(b) one head advance between the reading and the read of the head: one re-decision at a fresh reading decides normally", () => {
  // Read at 5,000; another guard appends at 5,003 before the head is read; the clock then reads 5,010.
  const { authorize, asked } = fakeOwner([5_003]);
  const { d, at, redecided } = authorizeAtReading(authorize, 5_000, clockOf([5_010]));
  assert.deepEqual(asked, [5_000, 5_010]);
  assert.equal(redecided, 1);
  assert.equal(at, 5_010);
  assert.equal(d.evidence.decision, "ALLOW");
  assert.equal(clockAheadOfReader(d.head, at), false);
});

test("(c) a head that keeps moving: at most MAX_REDECIDE re-decisions, then the INDETERMINATE answer stands (ask, never allow); no race-free claim", () => {
  // Every read of the head finds it 1 ms past the reading just taken.
  const readings = [100, 200, 300, 400, 500, 600];
  const { authorize, asked } = fakeOwner(readings.map((t) => t + 1));
  const { d, at, redecided } = authorizeAtReading(authorize, readings[0], clockOf(readings.slice(1)));
  assert.equal(MAX_REDECIDE, 3);
  assert.equal(redecided, MAX_REDECIDE);
  assert.equal(asked.length, 1 + MAX_REDECIDE, "bounded: the first decision and three more");
  assert.deepEqual(asked, [100, 200, 300, 400]);
  assert.equal(at, 400);
  assert.equal(d.evidence.decision, "INDETERMINATE");
  assert.equal(d.evidence.code, "CAUSAL_TIME_INVALID");
});

test("(d) a fresh reading not later than the one used: no re-decision", () => {
  for (const fresh of [7_000, 6_999]) {
    const { authorize, asked } = fakeOwner([7_005]);
    const { d, at, redecided } = authorizeAtReading(authorize, 7_000, clockOf([fresh]));
    assert.deepEqual(asked, [7_000]);
    assert.equal(redecided, 0);
    assert.equal(at, 7_000);
    assert.equal(d.evidence.code, "CAUSAL_TIME_INVALID");
  }
});

test("no clock, or an answer that is not CAUSAL_TIME_INVALID: decided once, at the reading given", () => {
  const noClock = fakeOwner([9_000]);
  assert.equal(authorizeAtReading(noClock.authorize, 8_000).redecided, 0);
  assert.deepEqual(noClock.asked, [8_000]);
  const decided = fakeOwner([1_000]);
  const r = authorizeAtReading(decided.authorize, 2_000, () => { throw new Error("the clock is not read when the answer stands"); });
  assert.equal(r.d.evidence.decision, "ALLOW");
  assert.deepEqual(decided.asked, [2_000]);
});
