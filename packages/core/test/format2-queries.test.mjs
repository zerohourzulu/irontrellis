// Format-2 query answers (SPEC §3.4, §8.2, §9.6): Amounts are decimal strings, the WHY answer carries `budgetId` and the
// request's `metric` under the format-2 disclosure (`publicQueryDisclosure(kind, format)`), the reference's disclosure
// is unchanged for legacy and format-1 histories (byte-identical answers), and the format-2 core fields cannot be withheld.
import assert from "node:assert/strict";
import { readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

const core = await import("../src/index.ts");
const histories = await import("./helpers/format2-histories.mjs");
const V2 = join(import.meta.dirname, "..", "..", "..", "conformance", "v2-g3");
const EVENTS = JSON.parse(readFileSync(join(V2, "histories", "budget-v2.json"), "utf8"));
const TWIN = JSON.parse(readFileSync(join(V2, "histories", "budget-v2-twin-format1.json"), "utf8"));
const F2 = core.TRELLIS2_FORMAT;
const bigints = (value) => (JSON.stringify(value, (_k, v) => (typeof v === "bigint" ? "BIGINT" : v)).match(/"BIGINT"/g) ?? []).length;

test("format-2 WHY: budgetId and request.metric are disclosed under the format-2 disclosure; the reference's disclosure refuses them", () => {
  const state = core.replay(EVENTS).state, at = state.head.canonicalTime + 1;
  const query = { authorizationDomain: state.genesis.domain, evaluationTime: at };
  // A per-operation budget denies: the answer names the budget (SPEC §9.6).
  const denied = { actorId: "spender", action: "spend", resource: "petty-cash-2", claimedAt: at, amount: "50" };
  const why = core.whyState(state, state, { ...query, request: denied, disclosure: core.publicQueryDisclosure("WHY", F2) });
  assert.equal(why.epistemicStatus, "ESTABLISHED", why.code);
  assert.equal(why.answer.authorization.decision, "DENY");
  assert.equal(why.answer.authorization.code, "BUDGET_PER_OPERATION_EXCEEDED");
  assert.equal(why.answer.authorization.budgetId, "d-perop");
  assert.equal(core.whyState(state, state, { ...query, request: denied, disclosure: core.publicQueryDisclosure("WHY") }).code, "DISCLOSURE_INVALID");
  // A request naming its metric: the proof echoes it as a string; the amount is a decimal string, never a bigint.
  const metered = { actorId: "spender", action: "spend", resource: "petty-cash", claimedAt: at, amount: "5", metric: "amount" };
  const allowed = core.whyState(state, state, { ...query, request: metered, disclosure: core.publicQueryDisclosure("WHY", F2) });
  assert.equal(allowed.epistemicStatus, "ESTABLISHED", allowed.code);
  assert.equal(allowed.answer.authorization.decision, "ALLOW");
  assert.equal(allowed.answer.authorization.proof.request.metric, "amount");
  assert.equal(allowed.answer.authorization.proof.request.amount, "5");
  assert.equal(allowed.answer.authorization.proof.effectiveConstraints.maxAmount, "100");
  assert.equal(bigints(allowed), 0);
  assert.equal(core.whyState(state, state, { ...query, request: metered, disclosure: core.publicQueryDisclosure("WHY") }).code, "DISCLOSURE_INVALID");
  // The format-2 disclosure is the reference's plus exactly the two format-2 paths; RESPONSIBLE and SURVIVES are unchanged.
  const reference = core.publicQueryDisclosure("WHY"), extended = core.publicQueryDisclosure("WHY", F2);
  assert.deepEqual(extended.includedFields.filter((p) => !reference.includedFields.includes(p)), ["authorization.budgetId", "authorization.proof.request.metric"]);
  assert.equal(reference.includedFields.length, 143);
  assert.equal(extended.includedFields.length, 145);
  for (const kind of ["RESPONSIBLE", "SURVIVES"]) assert.deepEqual(core.publicQueryDisclosure(kind, F2), core.publicQueryDisclosure(kind));
  assert.deepEqual(core.publicQueryDisclosure("WHY", core.TRELLIS_FORMAT), reference);
  assert.deepEqual(core.queryAnswerFieldPaths(F2), core.QUERY_ANSWER_FIELD_PATHS_2);
  assert.deepEqual(core.queryAnswerFieldPaths(), core.QUERY_ANSWER_FIELD_PATHS);
  // The format-2 core fields cannot be withheld (DISCLOSURE_INVALID); the same disclosure is valid against the format-1 twin (reference rule).
  const withholding = { mode: "PUBLIC_MINIMAL", includedFields: reference.includedFields, withheldFields: ["scope.versions.historyHashAlgorithm"] };
  assert.equal(core.whyState(state, state, { ...query, request: { actorId: "gateway", action: "spend", resource: "petty-cash", claimedAt: at }, disclosure: withholding }).code, "DISCLOSURE_INVALID");
  const twin = core.replay(TWIN).state, twinAt = twin.head.canonicalTime + 1;
  const twinWhy = core.whyState(twin, twin, { authorizationDomain: twin.genesis.domain, evaluationTime: twinAt, request: { actorId: "gateway", action: "spend", resource: "petty-cash", claimedAt: twinAt }, disclosure: withholding });
  assert.equal(twinWhy.epistemicStatus, "ESTABLISHED", twinWhy.code);
});

test("format-2 answers carry no bigint anywhere: WHY, RESPONSIBLE, SURVIVES and the observation facade over a rich history", async (t) => {
  const dir = histories.tempDir("irontrellis-f2-queries-");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const { events, grid } = await histories.richHistory(dir);
  const state = core.replay(events).state, at = state.head.canonicalTime + 1;
  const query = { authorizationDomain: state.genesis.domain, evaluationTime: at };
  let established = 0;
  for (const r of grid.requests) {
    const request = { actorId: r.actor, action: r.action, resource: r.resource, claimedAt: at, ...(r.amount === undefined ? {} : { amount: r.amount.toString() }), ...(r.counterparty === undefined ? {} : { counterpartyId: r.counterparty }) };
    for (const kind of ["WHY", "RESPONSIBLE"]) {
      const fn = kind === "WHY" ? core.whyState : core.responsibleState;
      const result = fn(state, state, { ...query, request, disclosure: core.publicQueryDisclosure(kind, F2) });
      assert.equal(bigints(result), 0, `${kind} ${JSON.stringify(request)}`);
      assert.doesNotThrow(() => JSON.stringify(result));
      if (result.epistemicStatus === "ESTABLISHED") established += 1;
    }
  }
  for (const agent of grid.agents) {
    const result = core.survivesState(state, { targetAgentId: agent, evaluationTime: at, disclosure: core.publicQueryDisclosure("SURVIVES", F2) });
    assert.equal(bigints(result), 0, `SURVIVES ${agent}`);
    if (result.epistemicStatus === "ESTABLISHED") established += 1;
  }
  assert.ok(established > 0);
  const o = core.observeState(state);
  for (const r of grid.requests.slice(0, 4)) {
    const action = { actor: r.actor, action: r.action, resource: r.resource, ...(r.amount === undefined ? {} : { amount: r.amount }) };
    assert.equal(bigints(o.why(action)), 0);
    assert.equal(bigints(o.responsible(action)), 0);
    assert.equal(bigints(o.authorize(action)), 0);
  }
  assert.equal(bigints(o.survives("a")), 0);
});

test("A-185.1 (DEVIATIONS 22): the portable query envelope accepts a format-2 history: WHY, RESPONSIBLE and SURVIVES answer exactly as the state API", async (t) => {
  const dir = histories.tempDir("irontrellis-f2-portable-");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const { events, grid } = await histories.richHistory(dir);
  const state = core.replay(events).state, at = state.head.canonicalTime + 1;
  const query = { authorizationDomain: state.genesis.domain, evaluationTime: at };
  const portable = { operationVersion: core.QUERY_VERSION, observedEvents: events };
  let established = 0;
  for (const r of grid.requests) {
    const request = { actorId: r.actor, action: r.action, resource: r.resource, claimedAt: at, ...(r.amount === undefined ? {} : { amount: r.amount.toString() }), ...(r.counterparty === undefined ? {} : { counterpartyId: r.counterparty }) };
    for (const kind of ["WHY", "RESPONSIBLE"]) {
      const input = { ...query, request, disclosure: core.publicQueryDisclosure(kind, F2) };
      const viaState = (kind === "WHY" ? core.whyState : core.responsibleState)(state, state, input);
      const viaEnvelope = (kind === "WHY" ? core.whyPortable : core.responsiblePortable)({ ...portable, evaluationEvents: events, ...input }, core.replay);
      assert.deepEqual(viaEnvelope, viaState, `${kind} ${JSON.stringify(request)}`);
      if (viaEnvelope.epistemicStatus === "ESTABLISHED") established += 1;
    }
  }
  for (const agent of grid.agents) {
    const input = { targetAgentId: agent, evaluationTime: at, disclosure: core.publicQueryDisclosure("SURVIVES", F2) };
    const viaEnvelope = core.survivesPortable({ ...portable, ...input }, core.replay);
    assert.deepEqual(viaEnvelope, core.survivesState(state, input), `SURVIVES ${agent}`);
    if (viaEnvelope.epistemicStatus === "ESTABLISHED") established += 1;
  }
  assert.ok(established > 0, "some answers are ESTABLISHED (not EVIDENCE_UNAVAILABLE or STATE_NOT_AUTHORITATIVE)");
  // A tampered format-2 history is still refused as not authoritative.
  const broken = structuredClone(events);
  broken[1].timestamp = broken[1].timestamp + 1;
  assert.equal(core.survivesPortable({ ...portable, observedEvents: broken, targetAgentId: grid.agents[0], evaluationTime: at, disclosure: core.publicQueryDisclosure("SURVIVES", F2) }, core.replay).code, "STATE_NOT_AUTHORITATIVE");
});
