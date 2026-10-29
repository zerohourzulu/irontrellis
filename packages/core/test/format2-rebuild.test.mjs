// T2 resume equivalence (SPEC §7.1 invariant, BUILD §4): for several format-2 histories and every split point k, the
// state rebuilt from (the records at k + the events) answers every query exactly as the prefix replay at k does, and
// after applying events k+1…n exactly as the full replay does: authorize over a grid of requests, why, responsible,
// survives, headroom, capacity, the record set, the root, the projection head and the record count. The applicable
// negative vectors of the architect's suite reject with the same code at the same position from a rebuilt state. A
// snapshot with one altered record and the original root field is refused by the store (SNAPSHOT_STALE): the root is
// recomputed, never read. Histories: the architect's budget-v2, the E2 scenarios (budgets, refusals, effects,
// counterparties, handover) and a history with obligations, duties (no policy), receipts, consumptions, outcomes,
// observations, a succession and handover, an owner-key rotation, anchors and witness bindings (every §7.2 kind but
// `shadow`, which the migration tests pin).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const core = await import("../src/index.ts");
const { observeState } = await import("../src/observation.ts");
const { headroom } = await import("../src/budgets.ts");
const { capacityOf } = await import("../src/capacity.ts");
const { rebuildReplayState, recomputeRoot } = await import("../src/state-rebuild.ts");
const { openHistoryStore, storeCounters, resetStoreCountersForTests } = await import("../src/store.ts");
const { readSnapshotBase, snapshotPathFor, journalPathFor } = await import("../src/snapshot.ts");
const histories = await import("./helpers/format2-histories.mjs");

const V2 = join(import.meta.dirname, "..", "..", "..", "conformance", "v2-g3");
const ARCHITECT = JSON.parse(readFileSync(join(V2, "histories", "budget-v2.json"), "utf8"));
const VECTORS = JSON.parse(readFileSync(join(V2, "vectors.json"), "utf8"));

const json = (value) => JSON.stringify(value, (_key, v) => (typeof v === "bigint" ? `${v.toString()}n` : v instanceof Map ? [...v] : v instanceof Set ? [...v] : v));
const accepted = (events) => { const r = core.replay(events); assert.equal(r.status, "ACCEPTED", `${r.code} ${r.reason} @${r.position}`); return r; };
const records = (state) => core.stateRecordsOf(state).map((e) => ({ kind: e.kind, key: e.key, record: e.record }));

/** Every answer the state gives: the grid of requests at each time, the agents' survival, headroom per budget, capacity, the record set. */
function answersOf(state, grid) {
  const out = { root: core.stateRootOf(state), projectionHead: core.projectionHeadAt(state, state.head.position), head: state.head, records: records(state).map((r) => json(r)).join("\n") };
  out.capacity = capacityOf(state);
  out.at = {};
  for (const at of grid.times) {
    const o = observeState(state, { at });
    out.at[at] = {
      authorize: grid.requests.map((q) => o.authorize(q).evidence), why: grid.requests.map((q) => o.why(q)), responsible: grid.requests.map((q) => o.responsible(q)),
      survives: grid.agents.map((agent) => o.survives(agent)), headroom: grid.budgets.map((id) => headroom(state, id, at)),
    };
  }
  return json(out);
}
const ARCHITECT_GRID = {
  requests: [{ actor: "spender", action: "spend", resource: "vendor:acme", amount: 10n }, { actor: "spender", action: "spend", resource: "vendor:acme", amount: 500n }, { actor: "spender", action: "read", resource: "vendor:acme" }, { actor: "nobody", action: "spend", resource: "vendor:acme" }],
  agents: ["spender", "nobody"], budgets: [...new Set(ARCHITECT.filter((e) => e.type === "BUDGET_DECLARED").map((e) => e.data.budgetId)), "none"], times: [ARCHITECT.at(-1).timestamp, ARCHITECT.at(-1).timestamp + 100_000],
};
// The architect's actors: read them from the history rather than guessing.
ARCHITECT_GRID.agents = [...new Set(ARCHITECT.filter((e) => e.type === "AGENT_CREATED").map((e) => e.data.agentId)), "nobody"];
ARCHITECT_GRID.requests = ARCHITECT.filter((e) => e.type === "TRANSACTION_INTENT_DECLARED").slice(0, 3).flatMap((e) => [
  { actor: e.data.actorId, action: e.data.action, resource: e.data.resource, ...(e.data.amount === undefined ? {} : { amount: BigInt(e.data.amount) }) },
  { actor: e.data.actorId, action: e.data.action, resource: e.data.resource, amount: 10n ** 20n },
]).concat([{ actor: "nobody", action: "x", resource: "y" }]);

/** T2 over one history: every split k. */
async function t2(t, name, events, grid, splits = events.map((_e, k) => k)) {
  const full = accepted(events);
  const fullAnswers = answersOf(full.state, grid);
  let rebuilt = 0;
  for (const k of splits) {
    const prefix = accepted(events.slice(0, k + 1));
    const state = rebuildReplayState(records(prefix.state), events);
    rebuilt += 1;
    assert.equal(state.head.position, k);
    assert.deepEqual(core.stateRootOf(state), core.stateRootOf(prefix.state), `${name}: root at ${k}`);
    assert.equal(state.projectionHeads[k], prefix.projectionHead, `${name}: projection head at ${k}`);
    assert.equal(answersOf(state, grid), answersOf(prefix.state, grid), `${name}: the rebuilt state at ${k} answers as the prefix replay`);
    // The tail, with full validation, from the rebuilt state.
    const tail = core.replayFrom(state, events.slice(k + 1));
    assert.equal(tail.status, "ACCEPTED", `${name}: tail from ${k}: ${tail.code} ${tail.reason} @${tail.position}`);
    assert.equal(tail.stateRoot, full.stateRoot, `${name}: final root from ${k}`);
    assert.equal(tail.projectionHead, full.projectionHead, `${name}: final projection head from ${k}`);
    assert.equal(answersOf(state, grid), fullAnswers, `${name}: after the tail from ${k} every answer equals the full replay`);
  }
  t.diagnostic(`${name}: ${events.length} events, ${rebuilt} splits`);
}

test("T2: the architect's budget-v2 history rebuilds at every split and answers every query as a full replay", async (t) => {
  await t2(t, "budget-v2", ARCHITECT, ARCHITECT_GRID);
});

test("T2: the E2 scenarios (budgets, refusals, effects, counterparties, handover) rebuild at every split", async (t) => {
  const dir = histories.tempDir();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const { events, grid } = await histories.e2History(dir);
  await t2(t, "e2", events, grid);
});

test("T2: a history with obligations, duties, receipts, consumptions, outcomes, observations, succession, rotation, anchors and witness bindings rebuilds at every split", async (t) => {
  const dir = histories.tempDir();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const { events, grid } = await histories.richHistory(dir);
  const kinds = new Set(core.stateRecordsOf(accepted(events).state).map((e) => e.kind));
  for (const kind of core.STATE_RECORD_KINDS) if (kind !== "shadow") assert.ok(kinds.has(kind), `kind ${kind} is exercised`);
  await t2(t, "rich", events, grid);
});

test("T2: a duty-policy history (activation, disposition, contest) rebuilds at every split: the activation record, the dispositions, the duty view and the quota come back from the duty record (E4 open item 1)", async (t) => {
  const { dispositionFixture } = await import("./helpers/duty-fixture.mjs");
  const f = await dispositionFixture(t);
  await f.duties.dispose(f.input);
  f.setTime(110);
  await f.duties.contest(f.contest("first"));
  const events = f.events;
  assert.ok(events.some((e) => e.type === "ATTEMPT_DUTY_POLICY_ACTIVATED") && events.some((e) => e.type === "ATTEMPT_DUTY_CONTEST_RECORDED"));
  const grid = {
    requests: [{ actor: "worker", action: "inspect", resource: "incident" }, { actor: "worker", action: "RECORD_DUTY_DISPOSITION", resource: f.resource }, { actor: "replacement", action: "inspect", resource: "incident" }],
    agents: ["worker", "replacement"], budgets: ["none"], times: [events.at(-1).timestamp, 5000],
  };
  const dutyOf = (state) => json({
    view: core.inspectDutyPolicyState(state, "duty"), policies: state.attemptDutyPolicies, dispositions: state.attemptDutyDispositions,
    quota: state.capacityDutyQuota, dutyReserved: state.dutyReserved,
  });
  const full = accepted(events);
  const activation = events.findIndex((e) => e.type === "ATTEMPT_DUTY_POLICY_ACTIVATED");
  for (let k = activation - 1; k < events.length; k += 1) {
    const prefix = accepted(events.slice(0, k + 1));
    const state = rebuildReplayState(records(prefix.state), events);
    assert.equal(dutyOf(state), dutyOf(prefix.state), `duty state at ${k}`);
    const tail = core.replayFrom(state, events.slice(k + 1));
    assert.equal(tail.status, "ACCEPTED", `tail from ${k}: ${tail.code} ${tail.reason}`);
    assert.equal(dutyOf(state), dutyOf(full.state), `duty state after the tail from ${k}`);
  }
  await t2(t, "duty-policy", events, grid);
});

test("T2: every applicable negative vector rejects with the same code and position from a rebuilt state", (t) => {
  let checked = 0;
  for (const vector of VECTORS.filter((v) => v.kind === "replay" && Array.isArray(v.events) && v.expect.status === "REJECTED")) {
    const events = vector.events;
    // The longest prefix shared with the architect's history is where a rebuild can start.
    let shared = 0;
    while (shared < events.length && shared < ARCHITECT.length && core.canonicalEncode(events[shared]) === core.canonicalEncode(ARCHITECT[shared])) shared += 1;
    if (shared === 0) continue;
    const expected = core.replay(events);
    assert.equal(expected.status, "REJECTED", vector.id);
    assert.equal(expected.code, vector.expect.code, vector.id);
    for (const k of new Set([0, Math.floor((shared - 1) / 2), shared - 1])) {
      if (k >= expected.position) continue;
      const prefix = accepted(ARCHITECT.slice(0, k + 1));
      const state = rebuildReplayState(records(prefix.state), ARCHITECT);
      const result = core.replayFrom(state, events.slice(k + 1));
      assert.equal(result.status, "REJECTED", `${vector.id} from ${k}`);
      assert.equal(result.code, expected.code, `${vector.id} from ${k}: code`);
      assert.equal(result.position, expected.position, `${vector.id} from ${k}: position`);
      checked += 1;
    }
  }
  t.diagnostic(`negative vectors: ${checked} (vector, split) pairs`);
  assert.ok(checked >= 40, `enough negative vectors apply (${checked})`);
});

test("T2: a snapshot with one altered record and the original root field is refused (the root is recomputed, never read)", async (t) => {
  const dir = histories.tempDir();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const { config, events } = await histories.e2History(dir);
  const path = config.historyFile;
  // The writer left a snapshot: a resume uses it (no full replay). Alter one record, keep the stored root: refused, replayed in full, rebuilt.
  resetStoreCountersForTests();
  const resumed = openHistoryStore(path, { trust: "CHECKPOINT_RESUME", witness: false });
  assert.equal(resumed.loadedBy(), "CHECKPOINT_RESUME");
  assert.equal(storeCounters.fullReplays, 0);
  assert.equal(resumed.verify().snapshot, "USED");
  resumed.close();
  const base = readSnapshotBase(path);
  const altered = { ...base, records: base.records.map((r) => (r.kind === "agent" && r.key === "bea" ? { ...r, record: { ...r.record, status: "ACTIVE", controlEpoch: 7 } } : r)) };
  assert.notEqual(recomputeRoot(altered.records).root, base.stateRoot);
  writeFileSync(snapshotPathFor(path), `${JSON.stringify(altered)}\n`);
  writeFileSync(journalPathFor(path), "");
  resetStoreCountersForTests();
  const fallen = openHistoryStore(path, { trust: "CHECKPOINT_RESUME", witness: false });
  assert.equal(fallen.loadedBy(), "FULL_REPLAY");
  assert.equal(storeCounters.fullReplays, 1);
  assert.equal(storeCounters.resumes, 0);
  const report = fallen.verify();
  assert.equal(report.snapshot, "STALE");
  assert.ok(report.notes.some((note) => note.startsWith("SNAPSHOT_STALE:")), report.notes.join("; "));
  assert.equal(report.stateRoot, accepted(events).stateRoot);
  // The snapshot was rebuilt (its base at the position the pin's attestation signs): the next open resumes again, with the true root.
  assert.equal(storeCounters.snapshotRebuilds, 1);
  const rebuilt = readSnapshotBase(path);
  assert.equal(rebuilt.stateRoot, core.rootAt(accepted(events).state, rebuilt.position));
  assert.equal(recomputeRoot(rebuilt.records).root, rebuilt.stateRoot);
  fallen.close();
  const again = openHistoryStore(path, { trust: "CHECKPOINT_RESUME", witness: false });
  assert.equal(again.loadedBy(), "CHECKPOINT_RESUME");
  assert.deepEqual(core.stateRootOf(again.state()), core.stateRootOf(accepted(events).state));
  again.close();
});

test("T2: snapshot-session-without-expiresAt (G6.7 A-149.1 (b)): a snapshot whose session record lacks the expiresAt key is not a §7.2 record: SNAPSHOT_STALE and FULL_REPLAY; the same record set supplied to the API is INVALID_INPUT", async (t) => {
  const dir = histories.tempDir();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const { config, events } = await histories.e2History(dir);
  const path = config.historyFile;
  const warm = openHistoryStore(path, { trust: "CHECKPOINT_RESUME", witness: false });
  assert.equal(warm.loadedBy(), "CHECKPOINT_RESUME");
  warm.close();
  const base = readSnapshotBase(path);
  const sessions = base.records.filter((r) => r.kind === "session");
  assert.ok(sessions.length > 0 && sessions.every((r) => Object.hasOwn(r.record, "expiresAt")), "every session record carries the key");
  const dropped = { ...base, records: base.records.map((r) => {
    if (r.kind !== "session" || r !== sessions[0]) return r;
    const { expiresAt: _gone, ...record } = r.record;
    return { ...r, record };
  }) };
  assert.throws(() => rebuildReplayState(dropped.records, events), (e) => e.code === "INVALID_INPUT" && /session\.expiresAt/.test(e.message));
  writeFileSync(snapshotPathFor(path), `${JSON.stringify(dropped)}\n`);
  writeFileSync(journalPathFor(path), "");
  resetStoreCountersForTests();
  const fallen = openHistoryStore(path, { trust: "CHECKPOINT_RESUME", witness: false });
  t.after(() => fallen.close());
  assert.equal(fallen.loadedBy(), "FULL_REPLAY");
  assert.equal(storeCounters.resumes, 0);
  const report = fallen.verify();
  assert.equal(report.snapshot, "STALE");
  assert.ok(report.notes.some((note) => note.startsWith("SNAPSHOT_STALE:")), report.notes.join("; "));
  assert.equal(report.stateRoot, accepted(events).stateRoot);
});

// A-189.6: T2 field by field. The rebuilt state equals the live prefix state over every public ReplayState field (Maps by key,
// Sets by membership, records by canonical form; iteration order is outside identity, A-188.2), at rich-v2 46, 47 and 49 (the
// DT-LOCAL-003/004 positions; 49 is the ended tenure that keeps its succession lock, A-189.4) and at every STATE_CHECKPOINT
// position of the v2-regenerated histories; then again after the tail, against the full replay. The per-position logs
// stateRoots and projectionHeads are compared from the resume position on: a rebuilt state starts at k (§7.5). rootLog and
// lastRecordChanges are engine-internal (MutableReplayState only) and are not compared.
const V2R_HISTORIES = join(import.meta.dirname, "..", "..", "..", "conformance", "v2-regenerated", "histories");
const INTERNAL_FIELDS = new Set(["rootLog", "lastRecordChanges"]), PER_POSITION = new Set(["stateRoots", "projectionHeads"]);
const canonicalForm = (v) => {
  if (typeof v === "bigint") return { $bigint: v.toString() };
  if (v instanceof Map) return { $map: [...v].map(([k, x]) => [canonicalForm(k), canonicalForm(x)]).sort((a, b) => (JSON.stringify(a[0]) < JSON.stringify(b[0]) ? -1 : 1)) };
  if (v instanceof Set) return { $set: [...v].map((x) => JSON.stringify(canonicalForm(x))).sort() };
  if (Array.isArray(v)) return v.map(canonicalForm);
  if (v !== null && typeof v === "object") return Object.fromEntries(Object.keys(v).sort().map((k) => [k, canonicalForm(v[k])]));
  return v;
};
function assertSameFields(live, rebuilt, from, label) {
  const fields = [...new Set([...Object.keys(live), ...Object.keys(rebuilt)])].filter((f) => !INTERNAL_FIELDS.has(f));
  for (const f of fields) {
    const a = PER_POSITION.has(f) ? live[f].slice(from) : live[f], b = PER_POSITION.has(f) ? rebuilt[f].slice(from) : rebuilt[f];
    assert.equal(JSON.stringify(canonicalForm(b)), JSON.stringify(canonicalForm(a)), `${label}: field ${f}`);
  }
}

test("T2 (A-189.6): the rebuilt state equals the live state field by field at rich-v2 46, 47, 49 and every v2r checkpoint position, before and after the tail", (t) => {
  let compared = 0;
  for (const file of readdirSync(V2R_HISTORIES).filter((f) => f.endsWith(".json"))) {
    const events = JSON.parse(readFileSync(join(V2R_HISTORIES, file), "utf8"));
    if (!Array.isArray(events)) continue;
    const positions = new Set(events.flatMap((e, p) => (e.type === "STATE_CHECKPOINT" ? [p] : [])));
    if (file === "rich-v2.json") for (const p of [46, 47, 49]) positions.add(p);
    if (positions.size === 0) continue;
    const full = accepted(events);
    for (const k of [...positions].sort((a, b) => a - b)) {
      const prefix = accepted(events.slice(0, k + 1));
      const state = rebuildReplayState(records(prefix.state), events);
      assertSameFields(prefix.state, state, k, `${file} at ${k}`);
      const tail = core.replayFrom(state, events.slice(k + 1));
      assert.equal(tail.status, "ACCEPTED", `${file} tail from ${k}`);
      assertSameFields(full.state, tail.state, k, `${file} after the tail from ${k}`);
      compared++;
    }
  }
  const rich = JSON.parse(readFileSync(join(V2R_HISTORIES, "rich-v2.json"), "utf8"));
  const at49 = rebuildReplayState(records(accepted(rich.slice(0, 50)).state), rich);
  assert.ok([...at49.tenures.values()].some((x) => x.closed && x.successionLock !== undefined), "rich-v2 49: an ended tenure keeps its succession lock (A-189.4)");
  t.diagnostic(`${compared} rebuild positions compared`);
  // Step 5d P2-9: every v2-regenerated checkpoint position plus rich-v2 46, 47 and 49 (12 at MANIFEST revision 4).
  assert.ok(compared >= 12, `rebuild positions compared: ${compared}`);
});
