// DT001 (A-187.3; AR-01, AR-09 finding 9): the succession rule record stores the §6.1 effect through signedControlEffect, the
// function the control challenge uses. (i) The two v2-owner-policy vectors whose SUCCESSION_RULE_DECLARED carries
// additionalControlAuthorizations (048, 049; the event at position 10) reach the corrected roots at the 11-event prefix, the
// same roots the EVM reference computes (CO-01). (ii) Over every vector and history of the seven suites (a whole accepted list,
// else its longest prefix that replays), each succession record equals canonical(signedControlEffect(data)) of its declaring
// event and carries none of the authorization fields. Only the format-2 suites v2-regenerated and v2-owner-policy hold
// succession records; legacy has no histories folder here, and the others declare none (step 5d P2-8 pins the counts).
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";

const core = await import("../src/index.ts");
const { replay, stateRecordsOf, stateRootOf, signedControlEffect, controlEffect, canonicalEncode } = core;
const CONFORMANCE = new URL("../../../conformance/", import.meta.url);
const SUITES = ["legacy", "v1", "v2", "v2-g3", "v2-regenerated", "v2-owner-policy", "v2-human-attestation"];
const read = (u) => JSON.parse(readFileSync(u, "utf8"));
const AUTH_FIELDS = ["controlAuthorization", "sourceControlAuthorization", "additionalControlAuthorizations", "nextKeyAuthorizations"];

function eventLists(suite) {
  const dir = new URL(`${suite}/`, CONFORMANCE);
  if (!existsSync(new URL("vectors.json", dir)) || !existsSync(new URL("histories/", dir))) return [];
  const histories = Object.fromEntries(readdirSync(new URL("histories/", dir)).filter((f) => f.endsWith(".json"))
    .map((f) => [f.slice(0, -5), read(new URL(`histories/${f}`, dir))]));
  const fromVectors = read(new URL("vectors.json", dir))
    .map((v) => ({ id: v.id, events: v.history === undefined ? v.events : histories[v.history.ref]?.slice(0, v.history.eventCount) }))
    .filter((v) => Array.isArray(v.events));
  return [...Object.entries(histories).map(([id, events]) => ({ id, events })), ...fromVectors];
}

function acceptedState(events) {
  try { const whole = replay(events); if (whole.status === "ACCEPTED") return whole.state; } catch { /* fall through to the prefixes */ }
  let state;
  for (let p = 0; p < events.length; p++) {
    let r;
    try { r = replay(events.slice(0, p + 1)); } catch { break; }
    if (r?.state === undefined) break;
    state = r.state;
  }
  return state;
}

test("DT001 (A-187.3 (i)): v2-owner-policy 048/049 reach the corrected roots at the 11-event prefix", () => {
  const vectors = read(new URL("v2-owner-policy/vectors.json", CONFORMANCE));
  const want = {
    "replay/v2op/rejects-termination-of-prohibition-grantor-at-pr-threshold": "0xbee1275b18c69eab7f7c2363bccbcdd9a39a6cbe7036152c49c748019bc60117",
    "replay/v2op/rejects-termination-of-prohibition-ancestor-at-pr-threshold": "0x39ff3d421606a123299e73694a46a0748370e57ee6162f5abc6fc942dbccded5",
  };
  for (const [id, root] of Object.entries(want)) {
    const v = vectors.find((x) => x.id === id);
    assert.ok(v !== undefined, id);
    assert.equal(v.events[10].type, "SUCCESSION_RULE_DECLARED");
    assert.ok(Object.hasOwn(v.events[10].data, "additionalControlAuthorizations"), `${id}: the declaring event is co-signed`);
    const r = replay(v.events.slice(0, 11));
    assert.ok(r.state !== undefined, `${id}: the 11-event prefix is accepted`);
    assert.equal(r.head.position, 10);
    assert.equal(stateRootOf(r.state).root, root, id);
    const [rule] = stateRecordsOf(r.state).filter((x) => x.kind === "succession");
    assert.equal(Object.hasOwn(rule.record.rule, "additionalControlAuthorizations"), false);
  }
});

test("DT001 (A-187.3 (ii)): every succession record in the seven suites equals canonical(signedControlEffect(data))", () => {
  const seen = new Set(), acaEvents = new Set(), perSuite = {};
  let compared = 0, equalByteForm = 0;
  assert.deepEqual(eventLists("legacy"), [], "legacy carries no histories folder: no succession records to compare");
  for (const suite of SUITES) {
    perSuite[suite] = 0;
    for (const { events } of eventLists(suite)) {
      if (!events.some((e) => e?.type === "SUCCESSION_RULE_DECLARED")) continue;
      const state = acceptedState(events);
      if (state === undefined) continue;
      for (const { record } of stateRecordsOf(state).filter((x) => x.kind === "succession")) {
        const event = events[record.position];
        const key = core.eventHash(event); // step 5d P2-8: one record per declaring event, by its hash
        if (seen.has(key)) continue;
        seen.add(key);
        compared++; perSuite[suite]++;
        assert.equal(canonicalEncode(record.rule), canonicalEncode(signedControlEffect(event.data)), `${suite} ${event.id}`);
        for (const f of AUTH_FIELDS) assert.equal(Object.hasOwn(record.rule, f), false, `${suite} ${event.id}: ${f}`);
        // A-192.8 (independent review JOB75-06): the test records the type-4 byte equality of the two functions. Both drop
        // controlAuthorization, sourceControlAuthorization and additionalControlAuthorizations; they differ only on
        // nextKeyAuthorizations, which the closed type-4 schema rejects. So they agree on every succession event, the
        // ACA-bearing ones (CO-01: v2-owner-policy 048/049) included. (Step 5d: the 5b comment here said controlEffect kept the ACA
        // field on 048/049, and its else-branch hid that it does not.)
        const same = canonicalEncode(controlEffect(event.data)) === canonicalEncode(signedControlEffect(event.data));
        if (Object.hasOwn(event.data, "additionalControlAuthorizations")) acaEvents.add(`${suite} ${event.id}`);
        assert.ok(same, `${suite} ${event.id}: controlEffect and signedControlEffect differ`);
        if (same) equalByteForm++;
      }
    }
  }
  assert.deepEqual(perSuite, { legacy: 0, v1: 0, v2: 0, "v2-g3": 0, "v2-regenerated": 11, "v2-owner-policy": 2, "v2-human-attestation": 0 });
  assert.equal(compared, 13);
  assert.equal(equalByteForm, 13, "byte-equal under both functions: every succession record");
  // CO-01: exactly the SUCCESSION_RULE_DECLARED at position 10 of v2-owner-policy 048 and 049.
  assert.deepEqual([...acaEvents].sort(), ["v2-owner-policy event:rule:bea", "v2-owner-policy event:rule:cal"]);
});
