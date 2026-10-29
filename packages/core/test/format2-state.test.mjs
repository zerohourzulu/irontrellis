// Format 2 (SPEC §7, §12): state records, leaves, roots at every pinned position, projection rows and heads, checkpoints,
// head attestations (§7.4) and the fork safety of the leaf map and projection head.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

const core = await import("../src/index.ts");
const V2 = join(import.meta.dirname, "..", "..", "..", "conformance", "v2-g3");
const EVENTS = JSON.parse(readFileSync(join(V2, "histories", "budget-v2.json"), "utf8"));
const MANIFEST = JSON.parse(readFileSync(join(V2, "MANIFEST.json"), "utf8"));
const VECTORS = JSON.parse(readFileSync(join(V2, "vectors.json"), "utf8"));
const vector = (id) => VECTORS.find((v) => v.id === id);
const replayPrefix = (n) => { const r = core.replay(EVENTS.slice(0, n)); assert.equal(r.status, "ACCEPTED", `${n}: ${r.code} ${r.reason}`); return r; };
const positionOf = (checkpointId) => EVENTS.findIndex((e) => e.type === "STATE_CHECKPOINT" && e.data.checkpointId === checkpointId);

test("format 2: the genesis-only state has three records (genesis, ownerKeyEpoch 0, event 0) and the pinned root", () => {
  const expect = vector("replay/v2/accepts-genesis-only").expect;
  const r = replayPrefix(1);
  const records = core.stateRecordsOf(r.state);
  assert.deepEqual(records.map((e) => `${e.kind}/${e.key}`), ["event/0000000000000000", "genesis/0", "ownerKeyEpoch/0"]);
  assert.equal(r.stateRoot, expect.stateRoot);
  assert.equal(r.projectionHead, expect.projectionHead);
  assert.deepEqual(core.stateRootOf(r.state), { root: expect.stateRoot, count: 3 });
  const genesis = records.find((e) => e.kind === "genesis").record;
  assert.ok(!Object.hasOwn(genesis, "ownerKeys") && !Object.hasOwn(genesis, "nextKeyDigests") && !Object.hasOwn(genesis, "capacity"));
  assert.deepEqual(records.find((e) => e.kind === "ownerKeyEpoch").record, { epoch: 0, fromPosition: 0, keys: EVENTS[0].data.ownerKeys, nextKeyDigests: EVENTS[0].data.nextKeyDigests });
  const event = records.find((e) => e.kind === "event").record;
  assert.equal(event.recordHash, expect.head.hash);
  assert.equal(event.subjectId, EVENTS[0].data.canonicalLineageId);
  assert.equal(event.actorId, null);
});

test("format 2: rootAt(p) at every pinned position equals the architect's root, and the checkpoints carry rootAt(p-1)", () => {
  const full = replayPrefix(EVENTS.length);
  assert.equal(full.stateRoot, MANIFEST.histories["budget-v2"].stateRoot);
  assert.equal(full.state.stateRecords.size, MANIFEST.histories["budget-v2"].recordCount);
  for (const cp of ["cp:1", "cp:2", "cp:3"]) {
    const p = positionOf(cp);
    const expect = vector(`replay/v2/accepts-prefix-through-${cp.replace(":", "-")}`).expect;
    assert.equal(core.rootAt(full.state, p), expect.stateRoot, `${cp} rootAt from the full replay`);
    assert.equal(core.projectionHeadAt(full.state, p), expect.projectionHead, `${cp} projection from the full replay`);
    const prefix = replayPrefix(p + 1);
    assert.equal(prefix.stateRoot, expect.stateRoot, `${cp} prefix replay`);
    assert.equal(prefix.projectionHead, expect.projectionHead);
    assert.deepEqual(prefix.head, expect.head);
  }
  for (const e of EVENTS.filter((e) => e.type === "STATE_CHECKPOINT")) {
    const p = EVENTS.indexOf(e);
    assert.equal(e.data.stateRoot, core.rootAt(full.state, p - 1), `${e.data.checkpointId} cites rootAt(p-1)`);
    assert.equal(e.data.projectionHead, core.projectionHeadAt(full.state, p - 1));
    assert.equal(e.data.head.hash, full.state.eventHistoryHashes[p - 1]);
  }
  // The incremental leaf map agrees with a from-scratch derivation of every record.
  const incremental = core.stateRecordsOf(full.state).map((e) => ({ kind: e.kind, key: e.key, record: e.record }));
  const derived = core.deriveAllRecords(full.state);
  const byKey = (list) => Object.fromEntries(list.map((e) => [`${e.kind}\u0000${e.key}`, core.canonicalEncode(e.record)]));
  assert.deepEqual(byKey(incremental), byKey(derived));
  assert.deepEqual(core.stateRootOfRecords(derived), { root: full.stateRoot, count: 75 });
  // Every kind the architect's history exercises is present.
  const kinds = new Set(incremental.map((e) => e.kind));
  for (const kind of ["event", "genesis", "ownerKeyEpoch", "principal", "agent", "role", "tenure", "session", "authority", "usage", "nonce", "intent", "budget", "budgetUsage", "counterparty", "refusal", "effect"]) assert.ok(kinds.has(kind), kind);
});

test("format 2: the §7.2 usage counter counts every controlling authority and the nonce record is created at declaration", () => {
  const full = replayPrefix(EVENTS.length);
  const usage = core.deriveRecord(full.state, "usage", "metered");
  assert.deepEqual(usage, { authorityId: "metered", admittedTransactionCount: 4, admittedCumulativeAmount: "150" });
  const intent = core.deriveRecord(full.state, "intent", "spend:1");
  assert.equal(intent.status, "ADMITTED");
  assert.equal(intent.amount, "60");
  assert.equal(intent.metric, "amount");
  assert.equal(intent.declarationDigest, EVENTS[11].data.declarationAuthorization.hash);
  const nonceKey = core.hashCanonical(["spender", EVENTS[11].data.nonce], "sha256");
  assert.deepEqual(core.deriveRecord(full.state, "nonce", nonceKey), { actorId: "spender", nonce: EVENTS[11].data.nonce, intentId: "spend:1", position: 11 });
});

test("format 2: checkpoints are checked for head, root, record count and projection head with their own codes", () => {
  for (const [id, code] of [["rejects-checkpoint-with-wrong-state-root", "STATE_ROOT_MISMATCH"], ["rejects-checkpoint-with-wrong-record-count", "STATE_ROOT_MISMATCH"],
    ["rejects-checkpoint-with-wrong-projection-head", "PROJECTION_HEAD_MISMATCH"], ["rejects-checkpoint-citing-other-head", "TRANSITION_INVALID"]]) {
    const r = core.replay(vector(`replay/v2/${id}`).events);
    assert.equal(r.status, "REJECTED", id);
    assert.equal(r.code, code, id);
    assert.equal(r.position, positionOf("cp:1"));
  }
});

test("format 2: head attestations (SPEC §7.4) yield the four facts of every attestation vector", () => {
  const full = replayPrefix(EVENTS.length);
  for (const v of VECTORS.filter((x) => x.kind === "attestation")) {
    const facts = core.verifyHeadAttestationFacts(v.input.attestation, full.state);
    assert.deepEqual(facts, v.expect, v.id);
  }
  // A /1 attestation never verifies for a format-2 history; the store's own pin produces /2 (tested in format2-chain).
  const v1 = { version: "irontrellis-head-attestation/1", head: full.head, keyId: "owner:1", scheme: "ed25519", signature: `0x${"ab".repeat(64)}` };
  assert.equal(core.verifyHeadAttestationFacts(v1, full.state).signatureValid, false);
});

test("format 2: withProspectiveEvent forks the leaf map, the roots and the projection head (copy-on-write)", () => {
  const p = positionOf("cp:1");
  const base = replayPrefix(p).state;
  const rootBefore = core.stateRootOf(base), headBefore = base.projectionHeads.at(-1), count = base.stateRecords.size, sorted = base.sortedRecordKeys.length, roots = base.stateRoots.length;
  const prospective = core.withProspectiveEvent(base, EVENTS[p]);
  assert.equal(prospective.ok, true, prospective.reason);
  assert.equal(prospective.state.stateRecords.size, count + 1);
  assert.equal(prospective.state.stateRoots.at(-1), vector("replay/v2/accepts-prefix-through-cp-1").expect.stateRoot);
  assert.equal(prospective.state.projectionHeads.at(-1), vector("replay/v2/accepts-prefix-through-cp-1").expect.projectionHead);
  // The base is untouched.
  assert.deepEqual(core.stateRootOf(base), rootBefore);
  assert.equal(base.projectionHeads.at(-1), headBefore);
  assert.equal(base.stateRecords.size, count);
  assert.equal(base.sortedRecordKeys.length, sorted);
  assert.equal(base.stateRoots.length, roots);
  assert.equal(base.events.length, p);
  // A rejected prospective event changes nothing either, and the base still accepts the real one.
  const bad = core.withProspectiveEvent(base, vector("replay/v2/rejects-checkpoint-with-wrong-record-count").events.at(-1));
  assert.equal(bad.ok, false);
  assert.equal(bad.code, "STATE_ROOT_MISMATCH");
  assert.deepEqual(core.stateRootOf(base), rootBefore);
  const mutable = core.createReplayState(core.TRELLIS2_FORMAT);
  for (const event of EVENTS.slice(0, p + 1)) assert.equal(core.applyEvent(mutable, event).ok, true);
  assert.equal(mutable.stateRoots.at(-1), prospective.state.stateRoots.at(-1));
});

test("format 2: projection rows and heads agree with the architect's SPEC ORACLE (lib.mjs) when a built rc.1 dist is available", async (t) => {
  // IRONTRELLIS_RC1_DIST: packages/core/dist of a built 1.0.0-rc.1 tree, which lib.mjs loads (conformance/v2/README.md). No
  // default path: unset, the test skips and says why; set to a folder without index.js, it fails.
  const dist = process.env.IRONTRELLIS_RC1_DIST;
  if (dist === undefined || dist === "") { t.skip("IRONTRELLIS_RC1_DIST is not set (packages/core/dist of a built 1.0.0-rc.1 tree; conformance/v2/README.md)"); return; }
  const lib = join(V2, "generate", "lib.mjs");
  assert.ok(existsSync(join(dist, "index.js")), `IRONTRELLIS_RC1_DIST=${dist} has no index.js`);
  assert.ok(existsSync(lib), lib);
  const L = await import(lib);
  const theirs = L.projectionHeads(EVENTS);
  const full = replayPrefix(EVENTS.length);
  EVENTS.forEach((event, position) => {
    const row = core.projectionRow(event, position, core.eventHash(event));
    assert.equal(`0x${Buffer.from(row).toString("hex")}`, theirs[position].row, `row ${position}`);
    assert.equal(full.state.projectionHeads[position], theirs[position].head, `head ${position}`);
    const [actor, subject, amount] = L.projectionFields(event);
    assert.deepEqual(core.projectionFields(event), [actor ?? null, subject ?? null, amount ?? null], `fields ${position}`);
  });
  // The §7.1 leaf and root over the record set: byte-for-byte the oracle's.
  const records = new Map(core.stateRecordsOf(full.state).map((e) => [`${e.kind}\u0000${e.key}`, e.record]));
  assert.deepEqual(L.stateRoot(records), { root: full.stateRoot, count: 75 });
});

test("A-148.1 (G6.7): §12.1 bit 2 is set iff the §12.2-selected slot holds a non-null Amount; a present \"0\" sets it, an absent key or an explicit null clears it and zeroes bytes 84–115", () => {
  const budget = (amountCap) => ({ id: "event:b", type: "BUDGET_DECLARED", timestamp: 7, data: { budgetId: "b", subjects: { actorIds: null, roleIds: null, actions: null, resources: null }, metric: null, period: { kind: "NONE" }, ...(amountCap === undefined ? {} : { amountCap }), countCap: 3, perOperationCap: null, notBefore: null, expiresAt: null } });
  const refusal = (amount) => ({ id: "event:r", type: "REQUEST_REFUSED", timestamp: 7, data: { refusalId: "r", request: { actorId: "a", action: "x", resource: "y", claimedAt: 7, ...(amount === undefined ? {} : { amount }) } } });
  const hash = `0x${"11".repeat(32)}`;
  const flags = (event) => { const row = core.projectionRow(event, 3, hash); return { bit2: (row[19] & 4) !== 0, amountZero: row.subarray(84, 116).every((b) => b === 0) }; };
  assert.deepEqual(flags(budget("0")), { bit2: true, amountZero: true }, "a present \"0\" sets bit 2");
  assert.deepEqual(flags(budget("5")), { bit2: true, amountZero: false });
  assert.deepEqual(flags(budget(null)), { bit2: false, amountZero: true }, "explicit null clears it");
  assert.deepEqual(flags(refusal("0")), { bit2: true, amountZero: true });
  assert.deepEqual(flags(refusal(undefined)), { bit2: false, amountZero: true }, "an absent key clears it");
});
