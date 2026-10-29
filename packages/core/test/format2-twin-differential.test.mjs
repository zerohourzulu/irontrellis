// BUILD §4 differential: format-2 histories against their format-1 twins under the comparison projection. Pairs: the
// regenerated suite's v1-topic histories (conformance/v2-regenerated, written by the same scripts as conformance/v1 with
// the same ids, keys and clock) against the conformance/v1 histories; the architect's budget-v2 (conformance/v2-g3)
// against its format-1 twin (authorization only: the format-2 history drops the twin's consumptions, by construction).
// Events are paired in order, skipping the format-2-only events (and the twin's consumptions for budget-v2); at every
// paired prefix every authorize / why / responsible / survives answer over a grid of requests is compared after the
// projection: Amount markers ↔ strings, the /1, /0.2 and /2 literals to one token, domains to one token, the
// format-2-only fields (budgetId, stateRoot, projectionHead, attemptDuties, recognizedExtensions, versions) removed,
// the format-2 disclosure's two extra field paths removed, per-position history and event hashes, event ids and the
// positions next to them to the pair index, every other hash or signature alpha-renamed.
// Budget outcomes may differ only as SPEC §9 says (a format-2 DENY with a budget code where the twin allows).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const core = await import("../src/index.ts");
const ROOT = join(import.meta.dirname, "..", "..", "..");
const read = (path) => JSON.parse(readFileSync(join(ROOT, path), "utf8"));
const revive = (events) => core.jsonParseWithBigints(JSON.stringify(events));

const FORMAT2_ONLY = new Set(["BUDGET_DECLARED", "BUDGET_UPDATED", "BUDGET_CLOSED", "STATE_CHECKPOINT", "COUNTERPARTY_REGISTERED", "COUNTERPARTY_RETIRED", "REQUEST_REFUSED", "EFFECT_RECORDED", "COUNTERPARTY_RECEIPT_RECORDED"]);
const DROPPED = new Set(["versions", "budgetId", "stateRoot", "projectionHead", "attemptDuties", "recognizedExtensions"]);
const BUDGET_CODES = new Set(["BUDGET_AMOUNT_EXCEEDED", "BUDGET_COUNT_EXCEEDED", "BUDGET_PER_OPERATION_EXCEEDED", "BUDGET_PERIOD_UNDEFINED", "BUDGET_SET_TOO_LARGE", "AMOUNT_OVERFLOW"]);
const LITERAL = /^(?:continuity|irontrellis)-([a-z][a-z0-9-]*)\/(?:0\.2|1|2)$/;
const HASH = /^0x[0-9a-f]{64}$/, SIGNATURE = /^0x[0-9a-f]{128,130}$/;
/** The format-2 disclosure names two extra answer paths (E3, query-codec.ts): removed with the fields they name. */
const FORMAT2_PATHS = new Set(["authorization.budgetId", "authorization.proof.request.metric"]);

/** Tokens of one side: the history hash, event hash and event id of every paired position become `#H<k>`, `#E<k>`, `#ID<k>`. */
function tokensOf(events, pairedPositions) {
  const state = core.replay(events).state, tokens = new Map();
  pairedPositions.forEach((p, k) => {
    tokens.set(state.eventHistoryHashes[p], `#H${k}`);
    tokens.set(core.eventHash(events[p], state.hashAlgorithm), `#E${k}`);
    tokens.set(events[p].id, `#ID${k}`);
  });
  return tokens;
}
function project(value, tokens) {
  const alpha = new Map();
  const token = (prefix, s) => tokens.get(s) ?? alpha.get(s) ?? (alpha.set(s, `${prefix}${alpha.size}`), alpha.get(s));
  const visit = (v) => {
    if (typeof v === "bigint") return v.toString();
    if (typeof v === "string") {
      if (tokens.has(v)) return tokens.get(v);
      const literal = LITERAL.exec(v);
      if (literal !== null) return `#${literal[1]}`;
      if (HASH.test(v)) return token("#X", v);
      if (SIGNATURE.test(v)) return token("#SIG", v);
      return v;
    }
    if (Array.isArray(v)) return v.filter((item) => !FORMAT2_PATHS.has(item)).map(visit);
    if (v !== null && typeof v === "object") {
      const keys = Object.keys(v);
      if (keys.length === 1 && keys[0] === "$continuity.bigint") return v["$continuity.bigint"];
      if (typeof v.protocol === "string" && typeof v.version === "string" && typeof v.deploymentId === "string") return "#domain";
      const out = {};
      for (const key of keys.sort()) if (!DROPPED.has(key) && v[key] !== undefined) out[key] = visit(v[key]);
      // A position next to a paired history hash (evidence references, heads) is that pair's: the format-2 history interleaves format-2-only events.
      const paired = tokens.get(v.historyHash ?? v.hash);
      if (typeof v.position === "number" && paired !== undefined && paired.startsWith("#H")) out.position = `#P${paired.slice(2)}`;
      // …and so is an `<x>Position` next to its paired `<x>Id` (grantEventPosition / grantEventId, admissionEventPosition, …).
      for (const key of keys) {
        if (!key.endsWith("Position") || typeof v[key] !== "number") continue;
        const id = tokens.get(v[`${key.slice(0, -"Position".length)}Id`]);
        if (id !== undefined && id.startsWith("#ID")) out[key] = `#P${id.slice(3)}`;
      }
      return out;
    }
    return v;
  };
  return JSON.stringify(visit(JSON.parse(JSON.stringify(value, (_k, x) => (typeof x === "bigint" ? { "$continuity.bigint": x.toString() } : x)))));
}

/** The paired positions: both sides in order, skipping the given types (an event id seen on both sides pairs by id). */
function pair(f2, f1, skip2, skip1) {
  const a = f2.map((e, p) => [e, p]).filter(([e]) => !skip2(e)), b = f1.map((e, p) => [e, p]).filter(([e]) => !skip1(e));
  assert.equal(a.length, b.length, "the paired event counts");
  a.forEach(([e2], k) => assert.equal(e2.type, b[k][0].type, `pair ${k}: ${e2.id} / ${b[k][0].id}`));
  return { f2: a.map(([, p]) => p), f1: b.map(([, p]) => p) };
}

/** The grid of a history: every (actor, action, resource) a grant names, with and without an amount, plus a stranger. */
function gridOf(events) {
  const requests = [], seen = new Set();
  for (const e of events) {
    if (e.type !== "AUTHORITY_GRANTED") continue;
    const g = e.data.grant, actor = g.granteeId ?? g.subjectActorId;
    if (actor === undefined) continue;
    for (const action of g.constraints.actions) for (const resource of g.constraints.resources) {
      const key = `${actor}|${action}|${resource}`;
      if (seen.has(key)) continue;
      seen.add(key);
      requests.push({ actor, action, resource }, { actor, action, resource, amount: 50n });
    }
  }
  requests.push({ actor: "nobody", action: "read", resource: "anything" });
  const agents = [...new Set(events.filter((e) => e.type === "AGENT_CREATED").map((e) => e.data.agentId)), "nobody"];
  return { requests, agents };
}

function compare(name, f2, f1, pairs, { kinds = ["authorize", "why", "responsible", "survives"] } = {}) {
  const grid = gridOf(f2);
  const stats = { answers: 0, budgetOutcomes: 0, prefixes: 0 };
  for (let k = 0; k < pairs.f2.length; k += 1) {
    const p2 = pairs.f2[k], p1 = pairs.f1[k];
    const e2 = f2.slice(0, p2 + 1), e1 = revive(f1.slice(0, p1 + 1));
    const t2 = tokensOf(e2, pairs.f2.slice(0, k + 1)), t1 = tokensOf(e1, pairs.f1.slice(0, k + 1));
    const at = Math.max(e2.at(-1).timestamp, e1.at(-1).timestamp);
    const o2 = core.observeHistory(e2, { at }), o1 = core.observeHistory(e1, { at });
    stats.prefixes += 1;
    for (const kind of kinds) {
      const inputs = kind === "survives" ? grid.agents : grid.requests;
      for (const input of inputs) {
        const a2 = o2[kind](input), a1 = o1[kind](input);
        stats.answers += 1;
        const d2 = kind === "authorize" ? a2.evidence : kind === "why" ? a2.answer?.authorization : undefined;
        const d1 = kind === "authorize" ? a1.evidence : kind === "why" ? a1.answer?.authorization : undefined;
        if (d2 !== undefined && d2.decision === "DENY" && BUDGET_CODES.has(d2.code) && d1?.decision === "ALLOW") { stats.budgetOutcomes += 1; continue; }
        assert.equal(project(a2, t2), project(a1, t1), `${name}: ${kind} ${JSON.stringify(input, (_k, v) => (typeof v === "bigint" ? `${v}` : v))} at pair ${k} (positions ${p2} / ${p1})`);
      }
    }
  }
  return stats;
}

const V1 = "conformance/v1/histories", V2R = "conformance/v2-regenerated/histories";
const counts = {};
const skipFormat2 = (e) => FORMAT2_ONLY.has(e.type);
for (const [f2Name, f1Name] of [["handover-v2", "handover-v1"], ["authority-v2", "authority-v1"], ["rotation-v2", "rotation-v1"], ["pre-rotation-v2", "pre-rotation-v1"]]) {
  test(`twin differential: ${V2R}/${f2Name} against its format-1 twin ${V1}/${f1Name}`, (t) => {
    const f2 = read(`${V2R}/${f2Name}.json`), f1 = read(`${V1}/${f1Name}.json`);
    const stats = compare(f2Name, f2, f1, pair(f2, f1, skipFormat2, () => false));
    counts[f2Name] = stats;
    assert.equal(stats.budgetOutcomes, 0, "no budget in these histories");
    t.diagnostic(`${f2Name} ↔ ${f1Name}: ${stats.prefixes} paired prefixes, ${stats.answers} answers compared, ${stats.budgetOutcomes} budget outcomes`);
  });
}
test("twin differential: conformance/v2-g3 budget-v2 against its format-1 twin (authorize and why; budget outcomes per SPEC §9)", (t) => {
  const f2 = read("conformance/v2-g3/histories/budget-v2.json"), f1 = read("conformance/v2-g3/histories/budget-v2-twin-format1.json");
  const stats = compare("budget-v2", f2, f1, pair(f2, f1, skipFormat2, (e) => e.type === "TRANSACTION_INTENT_CONSUMED"), { kinds: ["authorize", "why"] });
  counts["budget-v2"] = stats;
  assert.ok(stats.budgetOutcomes > 0, "the budgets refuse what the twin allows somewhere");
  t.diagnostic(`budget-v2 ↔ twin: ${stats.prefixes} paired prefixes, ${stats.answers} answers compared, ${stats.budgetOutcomes} budget outcomes (format-2 DENY with a budget code, twin ALLOW)`);
});
test("twin differential: totals", (t) => {
  const total = Object.values(counts).reduce((s, c) => ({ answers: s.answers + c.answers, budgetOutcomes: s.budgetOutcomes + c.budgetOutcomes }), { answers: 0, budgetOutcomes: 0 });
  t.diagnostic(`twin differential totals: ${total.answers} answers compared over ${Object.keys(counts).length} pairs, ${total.budgetOutcomes} budget outcomes`);
});
