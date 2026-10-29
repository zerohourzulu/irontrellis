// The verifier of SPEC §15 / addendum A-27 (`verifyExportView`): views from the genesis and from later positions
// (rebuilt from `fromRecords` + `referencedEvents`), the key-event epochs and the attestations of both ends,
// JSON round trips, the read-only formats, a resumed store's export, and tampering with every part of a view.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { rmSync } from "node:fs";
import { test } from "node:test";

const core = await import("../src/index.ts");
const { openHistoryStore } = await import("../src/store.ts");
const histories = await import("./helpers/format2-histories.mjs");
const V2 = join(import.meta.dirname, "..", "..", "..", "conformance", "v2-g3");
const EVENTS = JSON.parse(readFileSync(join(V2, "histories", "budget-v2.json"), "utf8"));
const TWIN = JSON.parse(readFileSync(join(V2, "histories", "budget-v2-twin-format1.json"), "utf8"));
const { fixturesRoot } = await import("./reference.mjs");
const revive = (_key, value) => (value !== null && typeof value === "object" && typeof value["$continuity.bigint"] === "string" ? BigInt(value["$continuity.bigint"]) : value);
const LEGACY = JSON.parse(readFileSync(`${fixturesRoot}handover-history.json`, "utf8"), revive);
const ALL = { fromRecords: true, toRecords: true, referencedEvents: true, keyEvents: true, attestations: true };
const roundTrip = (view) => JSON.parse(JSON.stringify(view));
const okReport = (report, label) => assert.equal(report.ok, true, `${label}: ${report.failures.join("; ")} | ${report.notes.join("; ")}`);

test("verifyExportView: the vector history from the genesis and from later positions, with and without a JSON round trip", () => {
  const state = core.replay(EVENTS).state;
  const genesisEventHash = core.eventHash(EVENTS[0]);
  for (const [from, to] of [[0, 39], [0, 0], [24, 36], [23, 36], [35, 39], [39, 39], [1, 2]]) {
    const view = core.exportViewState(state, { fromPosition: from, toPosition: to, include: { ...ALL, inclusion: [{ kind: "genesis", key: "0" }, { kind: "event", key: String(to).padStart(16, "0") }] } });
    for (const candidate of [view, roundTrip(view)]) {
      const report = core.verifyExportView(candidate, { genesisEventHash });
      okReport(report, `${from}..${to}`);
      assert.equal(report.from.verified, true);
      assert.equal(report.to.verified, true);
      assert.equal(report.from.stateRoot, view.from.stateRoot);
      assert.equal(report.to.stateRoot, view.to.stateRoot);
      assert.equal(report.eventCount, to - from + 1);
      assert.equal(report.ownerKeyEpochs.length, 1);
      // A-27.1: the genesis authenticates `from` at 0; the checkpoint at from + 1 (the vector's cp:1 at 24) authenticates 23; nothing else here.
      assert.equal(report.from.authenticated, from === 0 ? "GENESIS" : from === 23 || from === 35 ? "STATE_CHECKPOINT" : null, `${from}`);
      assert.equal(view.fromAuthenticated, report.from.authenticated !== null);
      // `to` = 38 would be authenticated by cp at 39; the head has no held attestation in a bare state.
      assert.equal(report.to.authenticated, to === 0 ? "GENESIS" : null);
    }
    // The referenced bodies are a strict subset of the events before `from` (none from the genesis).
    assert.ok(view.referencedEvents.every((e) => e.position < from));
    if (from > 0) assert.ok(view.referencedEvents.some((e) => e.position === 0), "the genesis is always referenced");
  }
  // The wrong trusted genesis is refused outright.
  const view = core.exportViewState(state, { fromPosition: 24, toPosition: 36, include: ALL });
  assert.equal(core.verifyExportView(view, { genesisEventHash: `0x${"00".repeat(32)}` }).ok, false);
  // Without the referenced bodies (or without the records) the roots are checked but the transition is not: not ok, and the failure names the option.
  const bare = core.exportViewState(state, { fromPosition: 24, toPosition: 36, include: { fromRecords: true } });
  const partial = core.verifyExportView(bare);
  assert.equal(partial.ok, false);
  assert.equal(partial.from.verified, true);
  assert.equal(partial.to.verified, false);
  assert.match(partial.failures.join(" "), /include\.referencedEvents/);
  const none = core.verifyExportView(core.exportViewState(state, { fromPosition: 24, toPosition: 36 }));
  assert.equal(none.ok, false);
  assert.match(none.failures.join(" "), /include\.fromRecords/);
});

test("verifyExportView: a rich history through the owner handle (rotation, checkpoints, anchors, duties) at many split points", async (t) => {
  const dir = histories.tempDir("irontrellis-export-verify-");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const { config, events } = await histories.richHistory(dir);
  const owner = histories.openLocalOwner({ ...config, witness: false });
  const head = events.length - 1;
  const rotation = events.findIndex((e) => e.type === "OWNER_KEYS_ROTATED");
  const checkpoints = events.map((e, i) => (e.type === "STATE_CHECKPOINT" ? i : -1)).filter((i) => i > 0);
  assert.ok(rotation > 0 && checkpoints.length >= 2);
  const genesisEventHash = core.eventHash(events[0]);
  const splits = new Set([0, 1, 7, 15, checkpoints[0] - 1, checkpoints[0], checkpoints[1] - 1, rotation - 1, rotation, rotation + 1, head - 2, head]);
  let referencedTotal = 0;
  for (const from of splits) {
    const view = owner.exportView({ fromPosition: from, toPosition: head, include: ALL });
    const report = core.verifyExportView(roundTrip(view), { genesisEventHash });
    okReport(report, `${from}..${head}`);
    assert.equal(report.ownerKeyEpochs.length, 2, "the rotation establishes the second epoch (A-27.1)");
    assert.equal(report.ownerKeyEpochs[1].fromPosition, rotation + 1, "the new epoch is in force after the rotation");
    // The head is attested by the store's pin: `to` is authenticated by the held head attestation.
    assert.equal(report.to.authenticated, "HEAD_ATTESTATION", `${from}: ${report.notes.join("; ")}`);
    assert.notEqual(view.attestations.to, null, "A-65.2: the held head attestation of to.head");
    assert.equal(report.from.authenticated, from === 0 ? "GENESIS" : checkpoints.includes(from + 1) ? "STATE_CHECKPOINT" : from === head ? "HEAD_ATTESTATION" : null, `${from}`);
    referencedTotal += view.referencedEvents.length;
    assert.equal(view.keyEvents.length, 1);
    assert.equal(view.keyEvents[0].position, rotation);
  }
  assert.ok(referencedTotal > 0);
  // A view that ends before the head: `to` has no held attestation; A-65.2's shape carries no checkpoint after `to`
  // (only `fromCheckpoint`), so a view ending right before a checkpoint leaves `to` unauthenticated.
  const before = owner.exportView({ fromPosition: 2, toPosition: checkpoints[1] - 1, include: ALL });
  const report = core.verifyExportView(before, { genesisEventHash });
  okReport(report, "ending before a checkpoint");
  assert.equal(report.to.authenticated, null);
  // An identity range right before a checkpoint: fromCheckpoint authenticates from (A-65.2).
  const identity = owner.exportView({ fromPosition: checkpoints[1] - 1, toPosition: checkpoints[1] - 1, include: ALL });
  assert.equal(identity.attestations.fromCheckpoint.position, checkpoints[1]);
  const identityReport = core.verifyExportView(roundTrip(identity), { genesisEventHash });
  okReport(identityReport, "identity range");
  assert.equal(identityReport.from.authenticated, "STATE_CHECKPOINT");
  // A view across the rotation whose keyEvents are left out: the attestations cannot be verified (noted, not failed); the transition still verifies.
  const unkeyed = owner.exportView({ fromPosition: rotation + 1, toPosition: head, include: { fromRecords: true, referencedEvents: true, attestations: true } });
  const partial = core.verifyExportView(unkeyed, { genesisEventHash });
  assert.equal(partial.ok, true, partial.failures.join("; "));
  assert.equal(partial.to.authenticated, null);
  assert.equal(partial.ownerKeyEpochs.length, 1);
  assert.match(partial.notes.join(" "), /keyEvents/);
  owner.close?.();
});

test("verifyExportView: tampering with records, events, roots, bodies, key events and attestations is caught, never thrown", async (t) => {
  const dir = histories.tempDir("irontrellis-export-tamper-");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const { config, events } = await histories.richHistory(dir);
  const owner = histories.openLocalOwner({ ...config, witness: false });
  const head = events.length - 1, rotation = events.findIndex((e) => e.type === "OWNER_KEYS_ROTATED");
  const from = rotation - 3;
  const pristine = roundTrip(owner.exportView({ fromPosition: from, toPosition: head, include: ALL }));
  okReport(core.verifyExportView(pristine), "pristine");
  const tampered = (mutate) => { const copy = roundTrip(pristine); mutate(copy); return core.verifyExportView(copy); };
  const refused = (label, mutate, pattern) => {
    const report = tampered(mutate);
    assert.equal(report.ok, false, `${label}: accepted`);
    if (pattern !== undefined) assert.match(report.failures.join(" | "), pattern, label);
    return report;
  };
  // Records: a value changed (the root no longer matches), a record dropped, one duplicated.
  refused("record value", (v) => { v.fromRecords.find((r) => r.kind === "agent").record.controlEpoch += 1; }, /from\.stateRoot/);
  refused("record dropped", (v) => { v.fromRecords.splice(3, 1); }, /from\.stateRoot/);
  refused("record count", (v) => { v.from.recordCount += 1; }, /recordCount/);
  // Events: a body edited, an event dropped, the order swapped, a hash edited, a checkpoint id list edited.
  refused("event body", (v) => { v.events[2].event.timestamp += 1; }, /eventHash|recordHash|chain/);
  refused("event dropped", (v) => { v.events.splice(1, 1); }, /eventCount|events listed/);
  refused("events swapped", (v) => { [v.events[1], v.events[2]] = [v.events[2], v.events[1]]; }, /out of order/);
  refused("recordHash edited", (v) => { v.events[3].recordHash = `0x${"11".repeat(32)}`; }, /chain/);
  refused("checkpointIds edited", (v) => { v.checkpointIds = ["cp:forged"]; }, /checkpointIds/);
  // Roots: at either end, and the projection head.
  refused("to.stateRoot", (v) => { v.to.stateRoot = `0x${"22".repeat(32)}`; }, /to\.stateRoot/);
  refused("from.stateRoot", (v) => { v.from.stateRoot = `0x${"22".repeat(32)}`; }, /from\.stateRoot/);
  refused("to.projectionHead", (v) => { v.to.projectionHead = `0x${"33".repeat(32)}`; }, /projectionHead/);
  // Bodies: a referenced event's body edited (its event record disagrees), one dropped (the rebuild or replay fails, never throws), an extra one.
  refused("referenced body edited", (v) => { v.referencedEvents[1].event.timestamp += 1; }, /referencedEvents\[/);
  refused("genesis body dropped", (v) => { v.referencedEvents.splice(0, 1); }, /referencedEvents|rebuild|genesis/);
  // Dropping any one body never throws; the root check decides (a body the suffix does not depend on may still verify).
  for (let index = 1; index < pristine.referencedEvents.length; index += 1) {
    const report = tampered((v) => { v.referencedEvents.splice(index, 1); });
    assert.equal(typeof report.ok, "boolean");
    if (!report.ok) assert.ok(report.failures.length > 0);
  }
  refused("referenced beyond from", (v) => { v.referencedEvents.push({ position: v.events[1].position, event: v.events[1].event }); }, /not a position before from/);
  // The genesis: another genesis body (hash mismatch).
  refused("genesis body", (v) => { v.referencedEvents[0].event.data.deploymentId = "other"; }, /genesisEventHash|referencedEvents\[0\]/);
  // Key events: a rotation re-signed by nobody, moved, or with its previous head edited.
  refused("rotation signature", (v) => { v.keyEvents[0].event.data.controlAuthorization.signature = `0x${"44".repeat(64)}`; }, /keyEvents\[/);
  refused("rotation headBefore", (v) => { v.keyEvents[0].headBefore.hash = `0x${"55".repeat(32)}`; }, /keyEvents\[/);
  // Attestations: a head attestation's signature or root edited; a checkpoint moved to the wrong position.
  refused("attestation signature", (v) => { v.attestations.to.signature = `0x${"66".repeat(64)}`; }, /attestations\.to/);
  refused("attestation root", (v) => { v.attestations.to.stateRoot = `0x${"77".repeat(32)}`; }, /attestations\.to/);
  // A-65.1: shape violations are INVALID_INPUT: an explicit null evidence field, unsorted or duplicate positions, unknown item keys, the old shapes.
  for (const [label, mutate] of [
    ["null evidence", (v) => { v.keyEvents = null; }],
    ["unsorted referencedEvents", (v) => { v.referencedEvents.reverse(); }],
    ["duplicate referencedEvents", (v) => { v.referencedEvents.push(v.referencedEvents.at(-1)); }],
    ["extra item key", (v) => { v.referencedEvents[0].eventHash = `0x${"00".repeat(32)}`; }],
    ["old attestations shape", (v) => { v.attestations = { from: [], to: [] }; }],
    ["fromCheckpoint in range", (v) => { v.attestations.fromCheckpoint = { position: v.from.position + 1, event: v.events[1].event, eventHash: v.events[1].eventHash, recordHash: v.events[1].recordHash }; }],
  ]) assert.equal(tampered(mutate).code, "INVALID_INPUT", label);
  refused("fromAuthenticated claim", (v) => { v.fromAuthenticated = "yes"; }, /fromAuthenticated/);
  // Shape: unknown keys, a wrong version, not a record.
  refused("unknown key", (v) => { v.extra = 1; }, /unknown view key/);
  refused("version", (v) => { v.version = "irontrellis-export/1"; }, /version/);
  assert.equal(core.verifyExportView(null).ok, false);
  assert.equal(core.verifyExportView("view").ok, false);
  owner.close?.();
});

test("verifyExportView: legacy and format-1 views (no roots) verify their events from the genesis; a resumed store exports the same view as a full replay", async (t) => {
  for (const [events, label] of [[LEGACY, "legacy"], [TWIN, "format 1"]]) {
    const whole = core.exportView(events, { fromPosition: 0, toPosition: events.length - 1, include: { fromRecords: true, toRecords: true } });
    const report = core.verifyExportView(whole); // (a legacy view holds engine amounts: no JSON round trip here)
    assert.equal(report.ok, true, `${label}: ${report.failures.join("; ")}`);
    assert.equal(report.from.stateRoot, null);
    assert.match(report.notes.join(" "), /no state root/);
    // From a later position nothing but the event hashes can be checked: not ok, nothing thrown.
    const later = core.verifyExportView(core.exportView(events, { fromPosition: 2, toPosition: 4 }));
    assert.equal(later.ok, false);
    assert.equal(later.failures.length, 0, later.failures.join("; "));
    assert.match(later.notes.join(" "), /no state root/);
    assert.equal(core.verifyExportView({ ...core.exportView(events, { fromPosition: 0, toPosition: 3 }), to: { ...whole.to, position: 3 } }).ok, false);
  }
  const dir = histories.tempDir("irontrellis-export-resumed-");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const { config, events } = await histories.richHistory(dir);
  const full = core.replay(events).state;
  const store = openHistoryStore(config.historyFile, { witness: false, trust: "CHECKPOINT_RESUME" });
  assert.equal(store.loadedBy(), "CHECKPOINT_RESUME");
  for (const [from, to] of [[0, events.length - 1], [5, events.length - 1], [5, 9], [events.length - 1, events.length - 1]]) {
    const input = { fromPosition: from, toPosition: to, include: { fromRecords: true, toRecords: true, referencedEvents: true, keyEvents: true } };
    assert.deepEqual(JSON.parse(JSON.stringify(core.exportViewState(store.state(), input))), JSON.parse(JSON.stringify(core.exportViewState(full, input))), `${from}..${to}`);
  }
  store.close();
});
