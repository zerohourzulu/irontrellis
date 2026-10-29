// Authorize benchmark: cold (first decision on a freshly replayed state, which
// builds the memoised corpus and indexes) and warm (every later decision on the
// same state) latency of `authorizeState`, plus WHY / RESPONSIBLE / SURVIVES
// through `observeState`, at N events for both formats.
//   node --experimental-strip-types bench/authorize.mjs [eventCount]
import { scenario, median, fmt } from "./scenario.mjs";
const { replay } = await import("../src/replay.ts");
const { authorizeState, ROOT_RECOGNITION_POLICY } = await import("../src/authority.ts");
const { observeState } = await import("../src/observation.ts");

const TARGET = Number(process.argv[2] ?? 10_000);

for (const [format, target] of [["irontrellis-event/1", TARGET], ["continuity-event/0.2", Math.min(TARGET, 4096)]]) {
  const { history, genesis, domain, stats, clock } = await scenario(format, target);
  const actor = `agent:${stats.agents - 2}`; // the last agent may be cut off by the event budget
  const body = (action, resource, head) => ({
    expectedHistoryHead: head, domain, policyVersion: genesis.policyVersion, rootRecognitionPolicy: ROOT_RECOGNITION_POLICY,
    request: { actorId: actor, action, resource, claimedAt: clock }, evaluationTime: clock, consequential: false,
  });
  console.log(`\n${format}: ${history.length} events (${JSON.stringify(stats)}); actor ${actor}`);

  const t0 = performance.now();
  const replayed = replay(history);
  console.log(`replay: ${fmt(performance.now() - t0)}`);
  if (replayed.status !== "ACCEPTED") throw new Error(replayed.code);
  // Cold: the memo is keyed by state object, so a shallow copy of the state is a state the engine has never seen
  // (replaying a format-1 history with admissions already warms the memo, because replay re-derives each proof).
  const cold = [];
  for (let round = 0; round < 15; round += 1) {
    const state = { ...replayed.state };
    const t1 = performance.now();
    const decision = authorizeState(state, body("read", "doc:*", state.head));
    cold.push(performance.now() - t1);
    if (decision.decision !== "ALLOW") throw new Error(`${decision.decision} ${decision.code}`);
  }
  console.log(`authorize cold (first decision on an unseen state, builds the corpus and indexes): median ${fmt(median(cold))}, best ${fmt(Math.min(...cold))}`);

  const state = { ...replayed.state };
  authorizeState(state, body("read", "doc:*", state.head));
  const warm = new Map();
  for (let i = 0; i < 200; i += 1) {
    const allow = i % 2 === 0;
    const t = performance.now();
    const decision = authorizeState(state, body(allow ? "read" : "write", "doc:*", state.head));
    const label = `${decision.decision}${decision.code === undefined ? "" : ` ${decision.code}`}`;
    if (!warm.has(label)) warm.set(label, []);
    warm.get(label).push(performance.now() - t);
    if (allow && decision.decision !== "ALLOW") throw new Error(label);
  }
  for (const [label, times] of warm) console.log(`authorize warm, ${label}: median ${fmt(median(times))} (${times.length} calls)`);

  const observation = observeState(state, { at: clock });
  const action = { actor, action: "read", resource: "doc:*" };
  const time = (label, fn, runs = 20) => {
    const times = [];
    let result;
    for (let i = 0; i < runs; i += 1) { const t = performance.now(); result = fn(); times.push(performance.now() - t); }
    console.log(`${label}: median ${fmt(median(times))}`);
    return result;
  };
  time("why (warm)", () => observation.why(action));
  time("responsible (warm)", () => observation.responsible(action));
  time("survives (warm)", () => observation.survives(actor));
}
