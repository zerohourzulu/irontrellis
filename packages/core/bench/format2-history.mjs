// A deterministic format-2 history for the BUILD §6 benchmarks, written through the public owner / runtime / simulation
// API (real Ed25519 control signatures, runtime-signed declarations and admissions, the store's pin and snapshot):
//
//   setup (12 events): principal, agent `bot` (role `worker`, tenure `t:1`), a runtime session, two grants, a budget.
//   cycle (repeated until `events` is reached; ≈ 1.3 records per event):
//     a simulated operation (TRANSACTION_INTENT_DECLARED / _ADMITTED / _CONSUMED, budget charged),
//     three owner budget updates (BUDGET_UPDATED: control events, one changed record each),
//     every 4th cycle a recorded refusal (REQUEST_REFUSED), every 6th an effect (EFFECT_RECORDED),
//     every 24th cycle an owner grant (AUTHORITY_GRANTED); automatic STATE_CHECKPOINTs per `checkpointEvery`.
//
//   buildFormat2History(dir, events, { checkpointEvery = 256, onProgress }) → { config, runtime, pair, historyFile }
import { join } from "node:path";

const src = new URL("../src/", import.meta.url);
const { createLocalDomain, createLocalOwner } = await import(new URL("owner.ts", src));
const { openLocalSimulation, commitTerms } = await import(new URL("simulation.ts", src));
const { openLocalRuntime } = await import(new URL("runtime.ts", src));
const { keyPairFromPrivateKey, signHashWith } = await import(new URL("crypto/suites.ts", src));

export const BENCH_OWNER = "operations";
export const budgetUpdate = (cap) => ({ budgetId: "b:spend", subjects: { actorIds: null, roleIds: null, actions: ["spend"], resources: null }, amountCap: String(cap), countCap: null, perOperationCap: null, expiresAt: null });

export async function buildFormat2History(dir, events, { checkpointEvery = 256, onProgress } = {}) {
  const clock = { t: 1_000_000 };
  let n = 0;
  const historyFile = join(dir, "bench.jsonl");
  const config = {
    historyFile, domain: createLocalDomain({ ids: () => "bench" }), owner: BENCH_OWNER, controller: "operator", now: () => (clock.t += 1), ids: () => `e:${(n += 1)}`, witness: false,
    checkpointPolicy: { everyEvents: checkpointEvery },
  };
  const owner = await createLocalOwner(config);
  await owner.createAgent({ id: "bot" });
  await owner.createRole({ id: "worker" });
  await owner.appoint({ agent: "bot", role: "worker", tenure: "t:1", number: 1 });
  const pair = keyPairFromPrivateKey("ed25519", "key:bot", `0x${"42".repeat(32)}`);
  await owner.admitRuntime({ session: "s:1", agent: "bot", epoch: 1, key: "key:bot", credential: pair.credential, expiresAt: 1e13 });
  await owner.grant({ id: "g:ops", to: "bot", actions: ["read", "spend", "write"], resources: ["doc:1", "cash"], expiresAt: 1e13 });
  await owner.declareBudget({ budgetId: "b:spend", subjects: { actorIds: null, roleIds: null, actions: ["spend"], resources: null }, metric: "amount", period: { kind: "NONE" }, amountCap: "1000000000", countCap: null, perOperationCap: null, notBefore: null, expiresAt: null });
  const runtimeOptions = { ...config, session: "s:1", signHash: signHashWith(pair) };
  const sim = openLocalSimulation(runtimeOptions);
  const runtime = openLocalRuntime(runtimeOptions);
  const count = () => owner.capacity().eventCount;
  let cycle = 0;
  while (count() < events) {
    cycle += 1;
    const id = `op:${cycle}`;
    const run = await sim.run({ id, intentId: id, action: "spend", resource: "cash", role: "worker", tenure: "t:1", amount: 1n, termsCommitment: commitTerms({ cycle }) });
    if (run.status !== "SIMULATION_RESULT") throw new Error(`cycle ${cycle}: ${run.status}`);
    for (let u = 0; u < 3 && count() < events; u += 1) await owner.updateBudget(budgetUpdate(1_000_000_000 + cycle * 3 + u));
    if (cycle % 4 === 0 && count() < events) await runtime.recordRefusal({ refusalId: `refusal:${cycle}`, request: { actorId: "bot", action: "delete", resource: "doc:1", claimedAt: clock.t } });
    if (cycle % 6 === 0 && count() < events) await runtime.recordEffect({ effectId: `effect:${cycle}`, intentId: id, measurer: { kind: "SESSION", id: "bot" }, metric: "amount", unit: "cent", amount: 1n, observedAt: clock.t });
    if (cycle % 24 === 0 && count() < events) await owner.grant({ id: `g:${cycle}`, to: "bot", actions: ["read"], resources: [`doc:${cycle}`], expiresAt: 1e13 });
    onProgress?.(count());
  }
  return { config, owner, runtimeOptions, pair, historyFile, clock };
}
