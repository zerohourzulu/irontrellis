/**
 * The per-resource candidate index of the plausible-candidate pass (block 3.2), checked by a differential against a
 * naive reference: the full linear candidate loop over a corpus built from scratch for the same prefix.
 *
 * `evaluateAlgebra` looks for the winner among the candidates whose terminal grant names the requested resource and
 * action first. For an actor with more than 32 candidates that set comes from `candidatesByResource`, which is built
 * on first use and then kept up to date, grant by grant, by `indexCandidate` when the memo is extended (`extendMemo`).
 * A path that is added to `candidatesByActor` but not to an already-built per-resource index is invisible to the
 * pass: the pass then picks a worse winner, or none, and the decision (and its proof) differs from the full loop.
 *
 * Review block 3, M3: the earlier "grown" test ran on legacy generated corpora with a filtered grid and passed with
 * that maintenance removed. This test builds random format-1 histories through the owner API (many overlapping grants
 * to one actor, notBefore/expiresAt, transaction and amount caps, delegations, non-independent grants, `requires`,
 * ROOT and GLOBAL prohibitions, revocations), grows ONE state event by event with `applyEvent`, and after every event
 * compares every request of a grid on that state (the pass forced on, so the index exists from the first query and
 * must be maintained from then on) with the reference. It fails with the index maintenance on grant add removed
 * (checked by mutation when it was written; python/tests/test_candidate_index.py mirrors it for the Python engine).
 *
 * Run alone with: node --test --experimental-strip-types test/candidate-index.test.mjs
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { ACTIONS, RESOURCES, generateCandidateHistory } from "./helpers/candidate-history.mjs";

const A = await import("../src/authority.ts");
const R = await import("../src/replay.ts");
const { createReplayState } = await import("../src/state.ts");
const { TRELLIS_FORMAT } = await import("../src/events.ts");
const { keyPairFromPrivateKey } = await import("../src/crypto/suites.ts");
const { signerFromKeyPair } = await import("../src/signer.ts");
const { createLocalOwner } = await import("../src/owner.ts");
const { openHistoryStore } = await import("../src/store.ts");
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-206.1: the src copy's mark, as the API above
const API = { createLocalOwner, keyPairFromPrivateKey, signerFromKeyPair, openHistoryStore, TRELLIS_FORMAT, FORMAT1_TEST_TOOLING };
const generateHistory = (seed, operations) => generateCandidateHistory(API, seed, operations);

const serialize = (value) => JSON.stringify(value, (_key, x) => (typeof x === "bigint" ? `${x}n` : x));
const bodyFor = (state, request, at) => ({
  expectedHistoryHead: state.head, domain: state.genesis.domain, policyVersion: state.genesis.policyVersion, rootRecognitionPolicy: state.genesis.rootRecognitionPolicy,
  request: { ...request, claimedAt: at }, evaluationTime: at, consequential: false,
});
const GRID = [];
for (const actorId of ["w", "a1"]) for (const action of [...ACTIONS, "nope"]) for (const resource of [...RESOURCES, "rx"]) for (const amount of [undefined, 120n]) {
  GRID.push({ actorId, action, resource, ...(amount === undefined ? {} : { amount }) });
}
const OFFSETS = [0, 150];
/** `IRONTRELLIS_INDEX_DIFF=full` runs more and longer histories (about ten times as long). */
const FULL = process.env.IRONTRELLIS_INDEX_DIFF === "full";

/**
 * The naive reference: the full candidate loop (the pass off) over a corpus validated from scratch. `{ ...state }` is a
 * new memo key, so nothing built for the grown state (memo, candidate lists, index) is reused; at the last event the
 * state itself is also replayed from scratch.
 */
const referenceDecisions = (state, events, at, replayFresh) => {
  const previous = A.setCandidateIndexThresholdForTests(Infinity);
  try {
    let fresh = { ...state };
    if (replayFresh) {
      const replayed = R.replay(events);
      assert.equal(replayed.status, "ACCEPTED", `${replayed.code} at ${replayed.position}`);
      fresh = replayed.state;
    }
    return GRID.flatMap((request) => at.map((t) => serialize(A.authorizeState(fresh, bodyFor(fresh, request, t)))));
  } finally {
    A.setCandidateIndexThresholdForTests(previous);
  }
};

/**
 * Grows one state event by event and compares it with the reference after every event from `from` on, the pass on for
 * actors with more than `threshold` candidates. Returns the number of comparisons and of candidates `w` ended with.
 */
function differential(events, threshold, from, label) {
  const grown = createReplayState(TRELLIS_FORMAT);
  let compared = 0, allows = 0, indexedQueries = 0;
  for (let k = 1; k <= events.length; k += 1) {
    const applied = R.applyEvent(grown, events[k - 1]);
    assert.ok(applied.ok, `${label}: event ${k - 1} ${applied.code}`);
    if (k < from) continue;
    const at = OFFSETS.map((dt) => grown.head.canonicalTime + dt);
    const previous = A.setCandidateIndexThresholdForTests(threshold);
    let actual;
    try {
      actual = GRID.flatMap((request) => at.map((t) => serialize(A.authorizeState(grown, bodyFor(grown, request, t)))));
    } finally {
      A.setCandidateIndexThresholdForTests(previous);
    }
    const expected = referenceDecisions(grown, events.slice(0, k), at, k === events.length || k % 25 === 0);
    for (let i = 0; i < actual.length; i += 1) {
      if (actual[i] !== expected[i]) {
        const request = GRID[Math.floor(i / at.length)];
        assert.fail(`${label}: after event ${k - 1} (${events[k - 1].type}), ${serialize(request)} at ${at[i % at.length]}:\n grown     ${actual[i].slice(0, 600)}\n reference ${expected[i].slice(0, 600)}`);
      }
      if (actual[i].includes('"decision":"ALLOW"')) allows += 1;
    }
    compared += actual.length;
    if (candidatesOf(grown, "w") > threshold) indexedQueries += actual.length / 2;
  }
  return { compared, allows, indexedQueries, candidates: candidatesOf(grown, "w") };
}
const candidatesOf = (state, actor) => [...state.authorities.values()].filter((record) => record.grant.kind === "PERMISSION" && record.grant.granteeId === actor).length;

test("candidate index: a state grown event by event decides as the full loop on a fresh corpus (pass forced on)", async () => {
  let compared = 0, allows = 0;
  for (const seed of FULL ? [1, 2, 3, 4, 5, 6, 8, 9] : [1, 2]) {
    const events = await generateHistory(seed, FULL ? 160 : 90);
    const result = differential(events, 0, 2, `seed ${seed} threshold 0`);
    compared += result.compared;
    allows += result.allows;
    assert.ok(result.candidates >= 15, `seed ${seed}: w has ${result.candidates} candidates`);
  }
  // The grid must exercise the index: a history where every request is denied would pass with any index at all.
  assert.ok(compared > 20_000 && allows > 1_000, `${compared} comparisons, ${allows} ALLOW`);
});

test("candidate index: at the default threshold the index is built past 32 candidates and maintained after that", async () => {
  for (const seed of FULL ? [7, 10, 11] : [7]) {
    const events = await generateHistory(seed, FULL ? 400 : 170);
    // Compared from a little before the actor crosses the threshold (before that both sides run the same linear loop).
    const grants = createReplayState(TRELLIS_FORMAT);
    let from = events.length;
    for (let k = 1; k <= events.length; k += 1) {
      R.applyEvent(grants, events[k - 1]);
      if (candidatesOf(grants, "w") >= 28) { from = k; break; }
    }
    const result = differential(events, 32, from, `seed ${seed} default threshold`);
    // The actor crosses the threshold during the history, so the index is built in the middle of the growth and then
    // extended by later grants, and both the linear and the indexed paths are compared.
    assert.ok(result.candidates > 45 && result.indexedQueries > 1_000, `w ends with ${result.candidates} candidates; ${result.indexedQueries} indexed queries`);
  }
});
