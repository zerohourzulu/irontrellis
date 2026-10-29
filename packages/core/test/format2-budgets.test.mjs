// SPEC §9 (budgets) reviewed against the SPEC ORACLE (`conformance/v2/generate/lib.mjs`): a seeded differential over
// random budget sets, usage and requests for `budgetMatches`, `periodIndex`, `carryIn`, `remainingAmount`,
// `budgetCheckAfterAllow` (= `evaluateBudgets`), `chargedUsage` (= `chargeBudgets`) and `headroom`; plus the rules the
// architect's vectors cannot cover (README): saturation at MAX, `carryBase` with `k₀ = null`, `firstPeriod`,
// `expiresAt ≤ timestamp`, the metric rule, and the 17th budget of BUDGET_SET_TOO_LARGE in byte order.
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

const core = await import("../src/index.ts");
const budgets = await import("../src/budgets.ts");
const { createReplayState } = await import("../src/replay.ts");
const V2 = join(import.meta.dirname, "..", "..", "..", "conformance", "v2");
const MAX = (1n << 256n) - 1n;

/** A format-2 state with the given budgets, usage and current role holdings (no events: the budget procedure is pure over these maps). */
const stateWith = ({ budgets: bs = [], usage = [], roles = new Map() }) => {
  const state = createReplayState("irontrellis-event/2");
  for (const b of bs) state.budgets.set(b.budgetId, b);
  for (const u of usage) state.budgetUsage.set(budgets.usageKey(u.budgetId, u.periodIndex), u);
  for (const [actorId, held] of roles) {
    state.currentTenureIdsByAgent.set(actorId, new Set(held.map((roleId) => `${actorId}:${roleId}`)));
    for (const roleId of held) state.tenures.set(`${actorId}:${roleId}`, { id: `${actorId}:${roleId}`, roleId, agentId: actorId, closed: false, tenureNumber: 1 });
  }
  return state;
};
const budget = (budgetId, extra = {}) => Object.freeze({
  budgetId, subjects: { actorIds: null, roleIds: null, actions: null, resources: null }, metric: "amount", period: { kind: "NONE" }, amountCap: "100", countCap: null, perOperationCap: null,
  notBefore: null, expiresAt: null, status: "ACTIVE", declaredAtPosition: 1, firstPeriod: 0, carryBase: null, updatedAtPosition: null, closedAtPosition: null, ...extra,
});
const window = (lengthMs, originMs, carryUnused, carryCap) => ({ kind: "FIXED_WINDOW", lengthMs, originMs, carryUnused, carryCap });

/**
 * The A-50 recurrence as a reference (the frozen lib.mjs carryIn with the amendment): `f(j+1) = min(C, max(0, min(MAX,
 * cap + f(j)) − used(j)))`; idle stretches `min(C, f + n·cap)`; start at carryBase / firstPeriod as SPEC §9.5.
 */
function amendedCarryIn(b, k, usage) {
  if (b.period.kind === "NONE" || !b.period.carryUnused || b.amountCap === null) return 0n;
  const cap = BigInt(b.amountCap), ccap = BigInt(b.period.carryCap);
  let p0 = b.firstPeriod, c0 = 0n;
  if (b.carryBase !== null) {
    if (k === b.carryBase.periodIndex) return BigInt(b.carryBase.carryIn);
    if (k > b.carryBase.periodIndex) { p0 = b.carryBase.periodIndex; c0 = BigInt(b.carryBase.carryIn); }
  }
  if (k <= p0) return 0n;
  const min = (x, y) => (x < y ? x : y);
  const used = [...usage.entries()].filter(([key]) => key.startsWith(`${b.budgetId}\u0000`)).map(([key, u]) => [Number(key.split("\u0000")[1]), u.amount]).filter(([j]) => j >= p0 && j < k).sort((x, y) => x[0] - y[0]);
  let cur = p0, carry = c0;
  for (const [j, amount] of used) {
    if (j > cur) carry = min(ccap, carry + BigInt(j - cur) * cap); // idle stretch (closed form, valid under A-50)
    let unused = min(MAX, cap + carry) - amount; if (unused < 0n) unused = 0n; // A-50: saturated effective allowance
    carry = min(ccap, unused); cur = j + 1;
  }
  if (k > cur) carry = min(ccap, carry + BigInt(k - cur) * cap);
  return carry;
}

// A small deterministic PRNG (mulberry32) so the differential is reproducible.
const prng = (seed) => () => { seed = (seed + 0x6d2b79f5) | 0; let t = Math.imul(seed ^ (seed >>> 15), 1 | seed); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
const pick = (rnd, items) => items[Math.floor(rnd() * items.length)];

test("SPEC §9 differential against lib.mjs (SPEC ORACLE): matching, periods, rollover, checks, charging, headroom (skipped without an rc.1 dist)", async (t) => {
  // IRONTRELLIS_RC1_DIST: packages/core/dist of a built 1.0.0-rc.1 tree, which lib.mjs loads (conformance/v2/README.md). No
  // default path: unset, the test skips and says why; set to a folder without index.js, it fails.
  const dist = process.env.IRONTRELLIS_RC1_DIST;
  if (dist === undefined || dist === "") { t.skip("IRONTRELLIS_RC1_DIST is not set (packages/core/dist of a built 1.0.0-rc.1 tree; conformance/v2/README.md)"); return; }
  const lib = join(V2, "generate", "lib.mjs");
  assert.ok(existsSync(join(dist, "index.js")), `IRONTRELLIS_RC1_DIST=${dist} has no index.js`);
  assert.ok(existsSync(lib), lib);
  const L = await import(lib);
  const rnd = prng(0x5eed);
  const actors = ["a", "b", "c"], actions = ["spend", "read"], resources = ["r1", "r2", "r3"], rolesOfActor = new Map([["a", ["cashier"]], ["b", ["cashier", "clerk"]], ["c", []]]);
  const amountStr = () => pick(rnd, ["0", "1", "5", "10", "40", "60", "99", "100", "101", "250", MAX.toString(), (MAX - 5n).toString()]);
  const maybeList = (items) => (rnd() < 0.5 ? null : items.filter(() => rnd() < 0.6));
  let compared = 0, divergent = 0;
  for (let iteration = 0; iteration < 400; iteration += 1) {
    const n = 1 + Math.floor(rnd() * 20);
    const bs = [];
    for (let i = 0; i < n; i += 1) {
      const kind = rnd() < 0.4 ? { kind: "NONE" } : window(pick(rnd, [100, 1000]), pick(rnd, [0, 500, 2000]), rnd() < 0.6, null);
      if (kind.kind === "FIXED_WINDOW" && kind.carryUnused) kind.carryCap = pick(rnd, ["0", "50", "100", "1000", MAX.toString()]);
      const amountCap = rnd() < 0.8 ? amountStr() : null;
      const subjects = { actorIds: maybeList(actors), roleIds: maybeList(["cashier", "clerk"]), actions: maybeList(actions), resources: maybeList(resources) };
      for (const key of Object.keys(subjects)) if (Array.isArray(subjects[key]) && subjects[key].length === 0) subjects[key] = null;
      const firstPeriod = kind.kind === "NONE" ? 0 : (L.periodIndex({ period: kind }, pick(rnd, [0, 100, 600, 2500])) ?? 0);
      const carryBase = kind.kind === "FIXED_WINDOW" && kind.carryUnused && rnd() < 0.4 ? { periodIndex: firstPeriod + Math.floor(rnd() * 3), carryIn: pick(rnd, ["0", "5", "40"]) } : null;
      bs.push(budget(`b${String(i).padStart(2, "0")}`, {
        subjects, metric: rnd() < 0.85 ? "amount" : "calls", period: kind, amountCap, countCap: rnd() < 0.5 ? null : Math.floor(rnd() * 4),
        perOperationCap: rnd() < 0.7 ? null : amountStr(), notBefore: rnd() < 0.8 ? null : pick(rnd, [0, 100, 3000]), expiresAt: rnd() < 0.8 ? null : pick(rnd, [100, 1200, 5000]),
        status: rnd() < 0.9 ? "ACTIVE" : "CLOSED", firstPeriod, carryBase,
      }));
    }
    const usage = [];
    for (const b of bs) for (let k = 0; k < 4; k += 1) if (rnd() < 0.3) usage.push({ budgetId: b.budgetId, periodIndex: k, amount: amountStr(), count: Math.floor(rnd() * 4) });
    const state = stateWith({ budgets: bs, usage, roles: rolesOfActor });
    const oracleBudgets = new Map(bs.map((b) => [b.budgetId, b]));
    const oracleUsage = new Map(usage.map((u) => [`${u.budgetId}\u0000${u.periodIndex}`, { amount: BigInt(u.amount), count: u.count }]));
    const rolesOf = (actorId) => new Set(rolesOfActor.get(actorId) ?? []);
    for (let q = 0; q < 5; q += 1) {
      const t = pick(rnd, [0, 50, 100, 600, 1100, 2500, 3999, 1_000_000_000]);
      const request = { actorId: pick(rnd, actors), action: pick(rnd, actions), resource: pick(rnd, resources), claimedAt: t, ...(rnd() < 0.8 ? { amount: amountStr() } : {}), ...(rnd() < 0.15 ? { metric: "calls" } : {}) };
      const engine = { ...request, ...(request.amount === undefined ? {} : { amount: BigInt(request.amount) }) };
      // A-50: the engine follows the amended recurrence (saturated effective allowance); the frozen lib.mjs is the
      // unamended one. Where the two recurrences differ (MAX-adjacent inputs only) the request is compared with the
      // amended reference alone and counted as an A-50 divergence of the frozen oracle (reported in the notes).
      let diverges = false;
      for (const b of bs) {
        assert.equal(budgets.budgetMatches(state, b, engine, t), L.budgetMatches(b, request, t, rolesOf), `matches ${b.budgetId}`);
        const k = budgets.periodIndex(b.period, t);
        assert.equal(k, L.periodIndex(b, t));
        if (k !== null) {
          const amended = amendedCarryIn(b, k, oracleUsage);
          assert.equal(budgets.carryIn(state, b, k), amended, `carryIn ${b.budgetId} @${k} (A-50 recurrence)`);
          if (L.carryIn(b, k, oracleUsage) !== amended) { diverges = true; continue; }
          assert.equal(budgets.remainingAmount(state, b, k), L.remainingAmountOf(b, k, oracleUsage), `remaining ${b.budgetId}`);
        }
      }
      if (diverges) { divergent += 1; continue; }
      for (const b of bs) assert.deepEqual(budgets.headroom(state, b.budgetId, t), L.headroom(oracleBudgets, oracleUsage, b.budgetId, t), `headroom ${b.budgetId}`);
      assert.deepEqual(budgets.budgetCheckAfterAllow(state, engine, t), L.evaluateBudgets(oracleBudgets, oracleUsage, request, t, rolesOf), `verdict ${JSON.stringify(request)} at ${t}`);
      // Charging: the oracle mutates its usage map; compare the records the engine would write.
      const oracle = new Map(oracleUsage);
      L.chargeBudgets(oracleBudgets, oracle, request, t, rolesOf);
      const charged = budgets.chargedUsage(state, engine, t).map((u) => [u.budgetId, u.periodIndex, u.amount, u.count]).sort();
      const expected = [...oracle.entries()].filter(([key, u]) => { const before = oracleUsage.get(key); return before === undefined || before.amount !== u.amount || before.count !== u.count; })
        .map(([key, u]) => { const [budgetId, period] = key.split("\u0000"); return [budgetId, Number(period), u.amount.toString(), u.count]; }).filter(([, p]) => Number.isFinite(p)).sort();
      assert.deepEqual(charged, expected, "charging");
      compared += 1;
    }
  }
  assert.ok(compared >= 1900, `compared ${compared}`);
  console.log(`# A-50: ${divergent} of ${compared + divergent} requests reach MAX-adjacent rollover where the frozen lib.mjs carryIn (unamended) differs from the A-50 recurrence`);
});

test("SPEC §9.4 saturation and §9.5 carryBase: allowed = min(MAX, cap + carryIn); AMOUNT_OVERFLOW only without an amountCap; carryBase null when k₀ = null", () => {
  // Saturation: cap MAX with carry 50 → allowed MAX, remaining MAX − used; the charge never exceeds MAX.
  const big = budget("big", { period: window(1000, 0, true, "50"), amountCap: MAX.toString(), firstPeriod: 0 });
  const state = stateWith({ budgets: [big], usage: [{ budgetId: "big", periodIndex: 0, amount: "0", count: 1 }] });
  assert.equal(budgets.carryIn(state, big, 1), 50n); // period 0 unused: min(C, cap + 0 − 0) = 50
  assert.equal(budgets.remainingAmount(state, big, 1), MAX); // min(MAX, MAX + 50) = MAX
  assert.equal(budgets.headroom(state, "big", 1000).remainingAmount, MAX.toString());
  assert.equal(budgets.budgetCheckAfterAllow(state, { actorId: "a", action: "x", resource: "y", claimedAt: 1000, amount: MAX }, 1000), null);
  // AMOUNT_OVERFLOW (step 5) is reachable only without an amountCap: usage MAX − 1, amount 2.
  const open = budget("open", { amountCap: null, countCap: 10 });
  const near = stateWith({ budgets: [open], usage: [{ budgetId: "open", periodIndex: 0, amount: (MAX - 1n).toString(), count: 1 }] });
  assert.equal(budgets.budgetCheckAfterAllow(near, { actorId: "a", action: "x", resource: "y", claimedAt: 1, amount: 1n }, 1), null);
  assert.deepEqual(budgets.budgetCheckAfterAllow(near, { actorId: "a", action: "x", resource: "y", claimedAt: 1, amount: 2n }, 1), { code: "AMOUNT_OVERFLOW", budgetId: "open" });
  // Check order within one budget: PERIOD_UNDEFINED, PER_OPERATION, COUNT, AMOUNT.
  const strict = budget("strict", { period: window(1000, 500, false, null), amountCap: "10", countCap: 1, perOperationCap: "5", firstPeriod: 0 });
  const used = stateWith({ budgets: [strict], usage: [{ budgetId: "strict", periodIndex: 0, amount: "9", count: 1 }] });
  const req = (amount, t) => ({ actorId: "a", action: "x", resource: "y", claimedAt: t, amount });
  assert.deepEqual(budgets.budgetCheckAfterAllow(used, req(1n, 100), 100), { code: "BUDGET_PERIOD_UNDEFINED", budgetId: "strict" });
  assert.deepEqual(budgets.budgetCheckAfterAllow(used, req(6n, 600), 600), { code: "BUDGET_PER_OPERATION_EXCEEDED", budgetId: "strict" });
  assert.deepEqual(budgets.budgetCheckAfterAllow(used, req(1n, 600), 600), { code: "BUDGET_COUNT_EXCEEDED", budgetId: "strict" });
  const amountOnly = stateWith({ budgets: [budget("strict", { period: window(1000, 500, false, null), amountCap: "10", countCap: 5, perOperationCap: "5", firstPeriod: 0 })], usage: [{ budgetId: "strict", periodIndex: 0, amount: "9", count: 1 }] });
  assert.deepEqual(budgets.budgetCheckAfterAllow(amountOnly, req(2n, 600), 600), { code: "BUDGET_AMOUNT_EXCEEDED", budgetId: "strict" });
  assert.equal(budgets.budgetCheckAfterAllow(amountOnly, req(1n, 600), 600), null);
  // carryBase: an update before the origin freezes nothing (k₀ null → carryBase null); after it, the rollover under the old caps.
  const pre = budget("pre", { period: window(1000, 5000, true, "50"), amountCap: "100", firstPeriod: 0, declaredAtPosition: 1 });
  const s2 = stateWith({ budgets: [pre] });
  const update = { subjects: pre.subjects, amountCap: "60", countCap: null, perOperationCap: null, expiresAt: null };
  assert.equal(budgets.updatedBudgetRecord(s2, pre, update, 2, 100).carryBase, null);
  const s3 = stateWith({ budgets: [pre], usage: [{ budgetId: "pre", periodIndex: 0, amount: "30", count: 1 }] });
  assert.deepEqual(budgets.updatedBudgetRecord(s3, pre, update, 2, 6500).carryBase, { periodIndex: 1, carryIn: "50" }); // min(50, 100 + 0 − 30)
  // firstPeriod: declared before the origin → 0; at max(timestamp, notBefore) otherwise; always 0 for NONE.
  const declared = (timestamp, extra) => budgets.declaredBudgetRecord({ ...budget("d", extra), status: undefined }, 1, timestamp);
  assert.equal(declared(100, { period: window(1000, 5000, false, null) }).firstPeriod, 0);
  assert.equal(declared(7200, { period: window(1000, 5000, false, null) }).firstPeriod, 2);
  assert.equal(declared(100, { period: window(1000, 0, false, null), notBefore: 3100 }).firstPeriod, 3);
  assert.equal(declared(9999, { period: { kind: "NONE" } }).firstPeriod, 0);
  // expiresAt ≤ timestamp is accepted and means immediate expiry; a closed budget never matches; the metric rule.
  const expired = budget("expired", { expiresAt: 100 });
  const s4 = stateWith({ budgets: [expired, budget("closed", { status: "CLOSED" }), budget("calls", { metric: "calls" })] });
  assert.equal(budgets.matchingBudgets(s4, req(1n, 100), 100).length, 0);
  assert.equal(budgets.matchingBudgets(s4, req(1n, 99), 99).map((b) => b.budgetId).join(), "expired");
  assert.equal(budgets.matchingBudgets(s4, { ...req(1n, 50), metric: "calls" }, 50).map((b) => b.budgetId).join(), "calls");
  assert.equal(budgets.headroom(s4, "expired", 100).active, false);
  // The 17th matching budget in byte order names BUDGET_SET_TOO_LARGE (not the 17th declared).
  const many = Array.from({ length: 17 }, (_, i) => budget(`z${String(16 - i).padStart(2, "0")}`));
  assert.deepEqual(budgets.budgetCheckAfterAllow(stateWith({ budgets: many }), req(1n, 1), 1), { code: "BUDGET_SET_TOO_LARGE", budgetId: "z16" });
  // roleIds: by roles currently held, not the role acted under.
  const roleBudget = budget("role", { subjects: { actorIds: null, roleIds: ["cashier"], actions: null, resources: null }, perOperationCap: "5" });
  const held = stateWith({ budgets: [roleBudget], roles: new Map([["a", ["cashier"]], ["c", []]]) });
  assert.deepEqual(budgets.budgetCheckAfterAllow(held, req(6n, 1), 1), { code: "BUDGET_PER_OPERATION_EXCEEDED", budgetId: "role" });
  assert.equal(budgets.budgetCheckAfterAllow(held, { ...req(6n, 1), actorId: "c" }, 1), null);
  assert.equal(core.MAX_MATCHING_BUDGETS, 16);
  assert.equal(core.MAX_BUDGETS, 256);
  assert.equal(core.MAX_EFFECTS_PER_INTENT, 64);
});
