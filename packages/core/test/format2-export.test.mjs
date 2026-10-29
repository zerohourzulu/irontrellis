// Export view (SPEC §15): the architect's vector fields, rows, checkpoints, record sets at both ends (their roots equal the
// pinned roots), inclusion paths verified with `verifyInclusion`, input refusals, and the read-only export of legacy and
// format-1 histories (SPEC §16.1: roots and heads null). The verifier helper `verifyExportView` (rebuild from
// `fromRecords`) is E3's and needs `rebuildReplayState`.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

const core = await import("../src/index.ts");
const { hexToBytes } = await import("../src/hash.ts");
const V2 = join(import.meta.dirname, "..", "..", "..", "conformance", "v2-g3");
const EVENTS = JSON.parse(readFileSync(join(V2, "histories", "budget-v2.json"), "utf8"));
const TWIN = JSON.parse(readFileSync(join(V2, "histories", "budget-v2-twin-format1.json"), "utf8"));
const VECTORS = JSON.parse(readFileSync(join(V2, "vectors.json"), "utf8"));
const vector = VECTORS.find((v) => v.id === "export/v2/cp-1-to-cp-3");

test("export/v2/cp-1-to-cp-3: compared fields, rows, checkpoints and records at both ends", () => {
  const view = core.exportView(EVENTS, { ...vector.input, include: { fromRecords: true, toRecords: true, inclusion: [{ kind: "budget", key: "b-amount" }, { kind: "genesis", key: "0" }, { kind: "event", key: "0000000000000036" }] } });
  for (const key of Object.keys(vector.expect)) assert.deepEqual(view[key], vector.expect[key], key);
  assert.equal(view.events.length, 13);
  assert.equal(view.events[0].position, 24);
  assert.equal(view.events.at(-1).position, 36);
  const state = core.replay(EVENTS).state;
  for (const row of view.events) {
    assert.deepEqual(row.event, state.events[row.position]);
    assert.equal(row.recordHash, state.eventHistoryHashes[row.position]);
    assert.equal(row.eventHash, core.eventHash(row.event));
    assert.match(row.projectionRow, /^0x[0-9a-f]{320}$/);
    assert.equal(row.projectionRow, `0x${Buffer.from(core.projectionRow(row.event, row.position, row.eventHash)).toString("hex")}`);
  }
  assert.deepEqual(view.checkpoints.map((c) => c.checkpointId), ["cp:1", "cp:2", "cp:3"]);
  assert.deepEqual(view.checkpoints, [24, 33, 36].map((p) => EVENTS[p].data));
  // The record sets at both ends reproduce the pinned roots and counts (fromRecords by a prefix replay, toRecords likewise: `to` is not the head).
  assert.equal(view.fromRecords.length, 53);
  assert.equal(view.toRecords.length, 72);
  assert.deepEqual(core.stateRootOfRecords(view.fromRecords), { root: vector.expect.from.stateRoot, count: 53 });
  assert.deepEqual(core.stateRootOfRecords(view.toRecords), { root: vector.expect.to.stateRoot, count: 72 });
  // Every record carries string Amounts (SPEC §7.2) and sits in (kind, key) order.
  const keys = view.toRecords.map((r) => `${r.kind}\u0000${r.key}`);
  assert.deepEqual(keys, [...keys].sort((a, b) => core.compareProtocolStrings(a, b)));
  assert.equal(JSON.stringify(view.toRecords).includes("$continuity"), false);
  // Inclusion paths against to.stateRoot, in the leaf order at `to`.
  const leaves = view.toRecords.map((r) => core.leafOf(r.kind, r.key, r.record));
  for (const proof of view.inclusion) {
    assert.equal(proof.at, "to");
    assert.deepEqual([view.toRecords[proof.leafIndex].kind, view.toRecords[proof.leafIndex].key], [proof.kind, proof.key]);
    assert.ok(core.verifyInclusion(leaves[proof.leafIndex], proof.leafIndex, leaves.length, proof.path.map(hexToBytes), hexToBytes(view.to.stateRoot)), `${proof.kind}/${proof.key}`);
    assert.equal(core.verifyInclusion(leaves[proof.leafIndex], proof.leafIndex, leaves.length, proof.path.map(hexToBytes), hexToBytes(view.from.stateRoot)), false);
  }
  // Without `include`, nothing optional is present; the closed record has exactly the SPEC keys.
  const bare = core.exportViewState(state, { fromPosition: 0, toPosition: 39 });
  assert.deepEqual(Object.keys(bare).sort(), ["checkpointIds", "checkpoints", "domain", "eventCount", "events", "from", "fromAuthenticated", "genesisEventHash", "historyId", "to", "version"]); // + fromAuthenticated (A-27.3), historyId (A-47.1)
  assert.equal(bare.to.recordCount, 75);
  assert.equal(bare.to.stateRoot, core.replay(EVENTS).stateRoot);
  assert.equal(bare.from.recordCount, 3);
  assert.equal(bare.version, "irontrellis-export/2");
});

test("export view input refusals and the read-only export of older formats", () => {
  const state = core.replay(EVENTS).state;
  const refused = (input) => assert.throws(() => core.exportViewState(state, input), (e) => e.code === "INVALID_INPUT");
  refused({ fromPosition: 5, toPosition: 4 });
  refused({ fromPosition: 0, toPosition: 40 });
  refused({ fromPosition: -1, toPosition: 4 });
  refused({ fromPosition: 0, toPosition: 4, extra: true });
  refused({ fromPosition: 0, toPosition: 4, include: { records: true } });
  refused({ fromPosition: 0, toPosition: 4, include: { inclusion: [{ kind: "budget", key: "nope" }] } });
  refused({ fromPosition: 0, toPosition: 4, include: { inclusion: [{ kind: "budget" }] } });
  assert.throws(() => core.exportView([...EVENTS, { id: "x" }], { fromPosition: 0, toPosition: 1 }), (e) => e.code === "INVALID_HISTORY");
  // Format 1: heads and hashes, no roots, no rows, no records; inclusion is refused.
  const twin = core.exportView(TWIN, { fromPosition: 1, toPosition: 5, include: { fromRecords: true, toRecords: true } });
  assert.equal(twin.domain.version, "1");
  assert.equal(twin.genesisEventHash, core.eventHash(TWIN[0]));
  assert.deepEqual([twin.from.stateRoot, twin.from.projectionHead, twin.from.recordCount, twin.to.stateRoot, twin.to.projectionHead, twin.to.recordCount], [null, null, 0, null, null, 0]);
  assert.equal(twin.eventCount, 5);
  assert.equal(twin.events[0].projectionRow, null);
  assert.equal(twin.events[0].recordHash, core.replay(TWIN).state.eventHistoryHashes[1]);
  assert.deepEqual([twin.fromRecords, twin.toRecords], [[], []]);
  assert.throws(() => core.exportView(TWIN, { fromPosition: 0, toPosition: 1, include: { inclusion: [{ kind: "genesis", key: "0" }] } }), (e) => e.code === "INVALID_INPUT");
});
