// The adapter's storage surface on format 2 (`./adapter`): the configured store (selection, refusals, the store's own
// writer lock), `stateOf`, and history transfer through the export view — `createHistoryTransfer` on the sender,
// `openCheckpointStorage` on the receiver — with a round trip between two directories (same root and head, a
// byte-identical replica), re-transfer of a grown history, STATE_CHECKPOINT events carried and checked, durability
// across handles, and every refusal code.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling

const A = await import("../src/adapter.ts");
const { setTransferLimitsForTests } = await import("../src/adapter-storage.ts");
const { createLocalDomain, createLocalOwner } = await import("../src/owner.ts");
const { createHistoryStore, openHistoryStore } = await import("../src/store.ts");
const { TRELLIS_FORMAT } = await import("../src/events.ts");
const { sha256Hex } = await import("../src/hash.ts");
const { richHistory } = await import("./helpers/format2-histories.mjs");

const code = (value) => (error) => {
  assert.equal(error.code, value, `${error.code}: ${error.message}`);
  return true;
};
const temp = (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-adapter-storage-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
};
/** A format-2 owner history with `agents` agents (each one event after the genesis batch). */
async function ownerHistory(dir, agents = 3, options = {}) {
  let tick = 100;
  const config = { historyFile: join(dir, "history.jsonl"), domain: createLocalDomain(), owner: "operations", controller: "operator", now: () => (tick += 1), witness: false, ...options };
  const owner = await createLocalOwner(config);
  for (let i = 0; i < agents; i += 1) await owner.createAgent({ id: `agent-${i}` });
  return { owner, config };
}
/** The manifest and chunks as a remote peer receives them: through JSON. */
const wire = (transfer) => JSON.parse(JSON.stringify(transfer));
const send = (storage, transfer, committed = null) => {
  const t = wire(transfer);
  storage.begin(t.manifest, t.transferId, committed);
  t.chunks.forEach((parts, index) => storage.chunk(t.transferId, index, parts));
  return t.transferId;
};

// ---------------------------------------------------------------- openConfiguredEventStore

test("openConfiguredEventStore opens the host's file as the owner API does, and reads only its own keys", async (t) => {
  const dir = temp(t);
  const { owner, config } = await ownerHistory(dir);
  const store = A.openConfiguredEventStore({ ...config, session: "ignored", signHash: () => {}, historyProfile: A.HISTORY_PROFILE });
  t.after(() => store.close());
  assert.equal(A.HISTORY_PROFILE, "irontrellis-event/2");
  assert.equal(store.format, "irontrellis-event/2");
  const plain = openHistoryStore(config.historyFile, { witness: false });
  assert.equal(store.path, plain.path);
  plain.close();
  assert.deepEqual(store.head(), owner.exportView({ fromPosition: 0, toPosition: store.head().position }).to.head);
  assert.deepEqual(store.readAll(), owner.exportHistory());
  assert.equal(store.loadedBy(), "CHECKPOINT_RESUME");
  const full = A.openConfiguredEventStore({ historyFile: config.historyFile, trust: "FULL_REPLAY", witness: false });
  assert.equal(full.loadedBy(), "FULL_REPLAY");
  assert.deepEqual(full.head(), store.head());
  full.close();
  // The expected identity and domain, when configured, must be the file's.
  const historyId = store.state().eventHistoryHashes[0];
  A.openConfiguredEventStore({ historyFile: config.historyFile, historyId, domain: config.domain, witness: false }).close();
});

test("openConfiguredEventStore refusals: segmented selection, wrong profile or domain, missing file, bad input, wrong identity", async (t) => {
  const dir = temp(t);
  const { config } = await ownerHistory(dir, 1);
  const at = { historyFile: config.historyFile, witness: false };
  assert.throws(() => A.openConfiguredEventStore({ historyProfile: "continuity-segmented-local/1", historyBinding: join(dir, "binding.json") }), code("PROFILE_MISMATCH"));
  assert.throws(() => A.openConfiguredEventStore({ ...at, historyBinding: join(dir, "binding.json") }), code("PROFILE_MISMATCH"));
  assert.throws(() => A.openConfiguredEventStore({ ...at, historyProfile: "irontrellis-event/1" }), code("PROFILE_MISMATCH"));
  assert.throws(() => A.openConfiguredEventStore({ ...at, domain: createLocalDomain() }), code("PROFILE_MISMATCH"));
  assert.throws(() => A.openConfiguredEventStore({ ...at, historyId: `0x${"ab".repeat(32)}` }), code("HISTORY_IDENTITY_MISMATCH"));
  assert.throws(() => A.openConfiguredEventStore({ historyFile: join(dir, "absent.jsonl") }), code("READ_UNAVAILABLE"));
  assert.deepEqual(readdirSync(dir).filter((n) => n.startsWith("absent")), [], "a missing history is never created");
  for (const bad of [null, [], "history.jsonl", { historyFile: "" }, { ...at, trust: "LAZY" }, { ...at, lockTimeoutMs: -1 }, { ...at, acceptRollback: "yes" }, { ...at, historyId: "0x12" }]) {
    assert.throws(() => A.openConfiguredEventStore(bad), code("INVALID_INPUT"), JSON.stringify(bad));
  }
  const getter = Object.defineProperty({ witness: false }, "historyFile", { get: () => config.historyFile, enumerable: true });
  assert.throws(() => A.openConfiguredEventStore(getter), code("INVALID_INPUT"));
  // A format-1 file opens read only (SPEC §16.1), and a selection that names format 2 refuses it.
  const f1 = join(dir, "f1");
  mkdirSync(f1);
  const one = await createLocalOwner({ historyFile: join(f1, "history.jsonl"), domain: createLocalDomain({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true }), owner: "operations", controller: "operator", now: () => 100, format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true, witness: false });
  assert.equal(one.format, TRELLIS_FORMAT);
  const store1 = A.openConfiguredEventStore({ historyFile: join(f1, "history.jsonl"), witness: false });
  assert.equal(store1.readOnlyReason(), "FORMAT_1");
  assert.throws(() => A.createHistoryTransfer(store1), code("PROFILE_MISMATCH"));
  store1.close();
  assert.throws(() => A.openConfiguredEventStore({ historyFile: join(f1, "history.jsonl"), historyProfile: A.HISTORY_PROFILE, witness: false }), code("PROFILE_MISMATCH"));
});

test("locking goes through the store's own writer lock: a second writer is STORE_BUSY, at once or after lockTimeoutMs", async (t) => {
  const dir = temp(t);
  const { config } = await ownerHistory(dir, 1);
  const first = A.openConfiguredEventStore({ historyFile: config.historyFile, witness: false });
  const second = A.openConfiguredEventStore({ historyFile: config.historyFile, witness: false });
  const patient = A.openConfiguredEventStore({ historyFile: config.historyFile, witness: false, lockTimeoutMs: 60 });
  t.after(() => { first.close(); second.close(); patient.close(); });
  const head = first.head(), event = first.readAll().at(-1);
  first.withExclusiveWriter((writer) => {
    assert.ok(readdirSync(dir).includes("history.jsonl.writer-lock"));
    assert.deepEqual(writer.readAll().length, head.position + 1);
    assert.throws(() => second.appendAtExpectedHead(event, head), code("STORE_BUSY"));
    assert.throws(() => second.withExclusiveWriter(() => {}), code("STORE_BUSY"));
    const started = Date.now();
    assert.throws(() => patient.append(event), code("STORE_BUSY"));
    assert.ok(Date.now() - started >= 50, "lockTimeoutMs is honoured");
  });
  assert.ok(!readdirSync(dir).includes("history.jsonl.writer-lock"), "released with the callback");
  // Free again; a stale expected head is the store's conflict, under the lock.
  assert.throws(() => second.appendAtExpectedHead(event, { ...head, position: head.position - 1 }), code("STORE_CONFLICT"));
  assert.equal(second.withExclusiveWriter(() => "ran"), "ran");
});

// ---------------------------------------------------------------- stateOf

test("stateOf replays captured events (INVALID_HISTORY when they do not replay) and returns a verified history's state", async (t) => {
  const dir = temp(t);
  const { config } = await ownerHistory(dir, 2);
  const store = A.openConfiguredEventStore({ historyFile: config.historyFile, witness: false });
  t.after(() => store.close());
  const events = store.readAll();
  const state = A.stateOf(events);
  assert.deepEqual(state.head, store.state().head);
  assert.equal(state.stateRoots[state.head.position], store.state().stateRoots[state.head.position]);
  assert.equal(state.genesis.domain.version, "2");
  const tampered = structuredClone(events);
  tampered.at(-1).data = { ...tampered.at(-1).data, forged: true };
  assert.throws(() => A.stateOf(tampered), code("INVALID_HISTORY"));
  assert.throws(() => A.stateOf([]), code("INVALID_HISTORY"));
  assert.throws(() => A.stateOf(new Proxy(events, {})), code("INVALID_HISTORY"));
  // A look-alike of a verified history is not one: it is read as events and refused.
  const storage = A.openCheckpointStorage(dir);
  const verified = storage.ready(send(storage, A.createHistoryTransfer(store)));
  assert.deepEqual(A.stateOf(verified).head, state.head);
  assert.equal(A.stateOf(verified), A.stateOf(verified), "replayed once, then kept");
  assert.throws(() => A.stateOf({ ...verified }), code("INVALID_HISTORY"));
});

// ---------------------------------------------------------------- createHistoryTransfer

test("createHistoryTransfer: the full export view as a manifest and segments of at most 64 canonical rows", async (t) => {
  const dir = temp(t);
  const { config } = await ownerHistory(dir, 70);
  const store = A.openConfiguredEventStore({ historyFile: config.historyFile, witness: false });
  t.after(() => store.close());
  const transfer = A.createHistoryTransfer(store);
  const { manifest } = transfer, head = store.head();
  assert.equal(manifest.version, "irontrellis-history-transfer/1");
  assert.equal(manifest.version, A.TRANSFER_VERSION);
  assert.deepEqual(Object.keys(manifest.view).sort(), ["attestations", "domain", "eventCount", "from", "fromAuthenticated", "genesisEventHash", "historyId", "keyEvents", "to", "version"]);
  assert.equal(manifest.view.version, A.EXPORT_VERSION);
  assert.equal(manifest.view.eventCount, head.position + 1);
  assert.deepEqual(manifest.view.to.head, head);
  assert.equal(manifest.view.to.stateRoot, store.state().stateRoots[head.position]);
  assert.equal(manifest.view.historyId, store.state().eventHistoryHashes[0]);
  assert.ok(manifest.view.attestations.to !== null, "the pin's head attestation travels with the view");
  assert.deepEqual(manifest.segments.map((s) => s.count), [64, head.position + 1 - 64]);
  assert.deepEqual(manifest.segments.map((s) => s.start), [0, 64]);
  assert.equal(transfer.transferId, sha256Hex(Buffer.from(A.canonicalEncode(manifest))));
  assert.equal(transfer.chunks.length, manifest.segments.length);
  const view = A.exportView(store.readAll(), { fromPosition: 0, toPosition: head.position });
  transfer.chunks.forEach((parts, index) => {
    assert.ok(parts.every((p) => p.length > 0 && p.length <= A.TRANSFER_STORAGE_LIMITS.partChars));
    const bytes = Buffer.from(parts.join(""), "base64"), segment = manifest.segments[index];
    assert.equal(bytes.length, segment.bytes);
    assert.equal(sha256Hex(bytes), segment.digest);
    const rows = bytes.toString("utf8").split("\n").slice(0, -1).map((line) => JSON.parse(line));
    assert.deepEqual(rows, view.events.slice(segment.start, segment.start + segment.count).map((r) => JSON.parse(A.canonicalEncode(r))));
  });
  // Deterministic, and the same from a resumed or a fully replayed store.
  const full = A.openConfiguredEventStore({ historyFile: config.historyFile, witness: false, trust: "FULL_REPLAY" });
  assert.equal(A.createHistoryTransfer(full).transferId, transfer.transferId);
  full.close();
  assert.throws(() => A.createHistoryTransfer({ readAll: () => [] }), code("INVALID_INPUT"));
  assert.throws(() => A.createHistoryTransfer(null), code("INVALID_INPUT"));
});

// ---------------------------------------------------------------- the round trip

test("round trip between two directories: same root and head, a byte-identical replica, durable across handles, relayed unchanged", async (t) => {
  const dir = temp(t);
  const source = join(dir, "source"), destination = join(dir, "destination");
  mkdirSync(source);
  mkdirSync(destination);
  const rich = await richHistory(source);
  const store = A.openConfiguredEventStore({ ...rich.config });
  t.after(() => store.close());
  const head = store.head(), root = store.state().stateRoots[head.position];
  const points = [];
  const storage = A.openCheckpointStorage(destination, { point: (name) => points.push(name) });
  const transfer = A.createHistoryTransfer(store);
  const id = send(storage, transfer);
  assert.deepEqual(points, ["transfer-begin-synced", ...transfer.chunks.map(() => "transfer-chunk-synced")]);
  const history = storage.ready(id);
  assert.equal(history.transferId, id);
  assert.deepEqual(history.head, head);
  assert.equal(history.stateRoot, root);
  assert.equal(history.historyId, store.state().eventHistoryHashes[0]);
  assert.equal(history.eventCount, head.position + 1);
  assert.equal(history.recordCount, store.state().stateRecords.size);
  assert.deepEqual(history.domain, rich.config.domain);
  assert.equal(history.headAuthentication, "HEAD_ATTESTATION");
  assert.deepEqual(history.events, store.readAll());
  assert.ok(Object.isFrozen(history) && Object.isFrozen(history.events) && Object.isFrozen(history.events[0]));
  assert.ok(A.verifyExportView(history.view).ok);
  const state = A.stateOf(history);
  assert.deepEqual(state.head, head);
  assert.equal(state.stateRoots[head.position], root);
  // STATE_CHECKPOINT events travel inside the view and are checked by it.
  const checkpoints = store.readAll().filter((e) => e.type === "STATE_CHECKPOINT");
  assert.ok(checkpoints.length > 0);
  assert.deepEqual(history.view.checkpointIds, checkpoints.map((e) => e.data.checkpointId));
  assert.deepEqual(history.view.checkpoints, checkpoints.map((e) => e.data));
  // The events make a format-2 file byte for byte the source; the replica verifies with the same head and root. Its own
  // pin carries no owner attestation (the receiver holds no owner key), so it reopens for reading with allowUnpinned.
  const replicaPath = join(destination, "replica.jsonl");
  createHistoryStore(replicaPath, history.events, { witness: false }).close();
  assert.equal(readFileSync(replicaPath, "utf8"), readFileSync(store.path, "utf8"));
  assert.throws(() => A.openConfiguredEventStore({ historyFile: replicaPath, witness: false }), code("ROLLBACK_DETECTED"));
  const replica = A.openConfiguredEventStore({ historyFile: replicaPath, historyId: history.historyId, trust: "FULL_REPLAY", allowUnpinned: true, witness: false });
  assert.deepEqual(replica.head(), head);
  assert.equal(replica.state().stateRoots[head.position], root);
  replica.close();
  // Durable: a new handle on the same directory sees the active transfer and loads it.
  const reopened = A.openCheckpointStorage(destination);
  assert.equal(reopened.inspect().active, id);
  assert.deepEqual(reopened.ready(id).head, head);
  assert.deepEqual(reopened.inspect(), { active: id, bytes: reopened.inspect().bytes, chunks: transfer.chunks.length, manifests: 1 });
  // A verified history is re-sent unchanged: the same transfer.
  assert.equal(A.createHistoryTransfer(history).transferId, id);
  assert.throws(() => A.createHistoryTransfer({ ...history }), code("INVALID_INPUT"), "a look-alike is not a verified history");
});

test("a grown history re-transfers over the committed one and reuses the stored prefix segments", async (t) => {
  const dir = temp(t);
  const destination = join(dir, "destination");
  mkdirSync(destination);
  const { owner, config } = await ownerHistory(dir, 66);
  const storage = A.openCheckpointStorage(destination);
  const open = () => A.openConfiguredEventStore({ historyFile: config.historyFile, witness: false });
  const s1 = open(), first = A.createHistoryTransfer(s1);
  s1.close();
  const id1 = send(storage, first);
  const h1 = storage.ready(id1);
  await owner.createAgent({ id: "late" });
  await owner.checkpoint({ checkpointId: "cp:late" });
  const s2 = open(), second = A.createHistoryTransfer(s2);
  t.after(() => s2.close());
  assert.equal(second.manifest.segments[0].digest, first.manifest.segments[0].digest, "rows depend only on their position");
  // Without the committed reference the active first transfer blocks the second.
  assert.throws(() => storage.begin(wire(second).manifest, second.transferId, null), code("TRANSFER_CONFLICT"));
  const id2 = send(storage, second, id1);
  const h2 = storage.ready(id2);
  assert.deepEqual(h2.head, s2.head());
  assert.equal(h2.view.checkpointIds.at(-1), "cp:late");
  assert.equal(h2.events[h1.head.position].id, h1.events.at(-1).id);
  assert.equal(h2.view.events[h1.head.position].recordHash, h1.head.hash, "the destination's prefix check");
  assert.deepEqual(storage.inspect().chunks, 3, "segment 0 is stored once for both transfers");
  assert.equal(storage.inspect().manifests, 2);
  // The earlier transfer still loads by id; only the active one is ready.
  assert.deepEqual(storage.load(id1).head, h1.head);
  assert.throws(() => storage.ready(id1), code("TRANSFER_CONFLICT"));
});

// ---------------------------------------------------------------- refusals

test("checkpoint storage refusals: manifests, ids, conflicts, chunks, incomplete transfers and abort", async (t) => {
  const dir = temp(t);
  const destination = join(dir, "destination");
  mkdirSync(destination);
  const { config } = await ownerHistory(dir, 66);
  const store = A.openConfiguredEventStore({ historyFile: config.historyFile, witness: false });
  t.after(() => store.close());
  const transfer = wire(A.createHistoryTransfer(store)), { manifest, transferId: id, chunks } = transfer;
  const storage = A.openCheckpointStorage(destination);
  // Manifest and id.
  assert.throws(() => storage.begin(manifest, `0x${"00".repeat(32)}`, null), code("TRANSFER_INVALID"));
  assert.throws(() => storage.begin(manifest, "not-a-hash", null), code("TRANSFER_INVALID"));
  for (const broken of [
    { ...manifest, extra: 1 },
    { ...manifest, version: "continuity-checkpoint-transfer/1" },
    { ...manifest, segments: [] },
    { ...manifest, segments: manifest.segments.slice(1) },
    { ...manifest, segments: [{ ...manifest.segments[0], count: 65 }, manifest.segments[1]] },
    { ...manifest, view: { ...manifest.view, events: [] } },
    { ...manifest, view: { ...manifest.view, from: { ...manifest.view.from, position: 1 } } },
    { ...manifest, view: { ...manifest.view, to: { ...manifest.view.to, stateRoot: null } } },
    null, "manifest",
  ]) {
    assert.throws(() => storage.begin(broken, id, null), code("TRANSFER_INVALID"));
  }
  // Nothing is active yet.
  assert.throws(() => storage.chunk(id, 0, chunks[0]), code("TRANSFER_CONFLICT"));
  assert.throws(() => storage.abort(id), code("TRANSFER_CONFLICT"));
  assert.throws(() => storage.load(id), code("TRANSFER_INVALID"), "an unknown transfer");
  assert.deepEqual(storage.begin(manifest, id, null), { transferId: id });
  assert.deepEqual(storage.begin(manifest, id, null), { transferId: id }, "a repeated begin is a no-op");
  // Chunks: index, parts, encoding, digest, rows.
  assert.throws(() => storage.chunk(id, 2, chunks[0]), code("TRANSFER_CHUNK_INVALID"));
  assert.throws(() => storage.chunk(id, -1, chunks[0]), code("TRANSFER_CHUNK_INVALID"));
  assert.throws(() => storage.chunk(id, 0, chunks[1]), code("TRANSFER_CHUNK_INVALID"));
  assert.throws(() => storage.chunk(id, 0, []), code("TRANSFER_CHUNK_INVALID"));
  assert.throws(() => storage.chunk(id, 0, [chunks[0].join("")]), code("TRANSFER_CHUNK_INVALID"), "a part longer than partChars");
  assert.throws(() => storage.chunk(id, 0, [...chunks[0].slice(0, -1), `${chunks[0].at(-1)}\n`]), code("TRANSFER_CHUNK_INVALID"), "non-canonical base64");
  const flipped = [...chunks[0]];
  flipped[0] = `${flipped[0][0] === "A" ? "B" : "A"}${flipped[0].slice(1)}`;
  assert.throws(() => storage.chunk(id, 0, flipped), code("TRANSFER_CHUNK_INVALID"));
  assert.deepEqual(storage.chunk(id, 1, chunks[1]), { transferId: id, index: 1 });
  // Incomplete.
  assert.throws(() => storage.ready(id), (e) => code("TRANSFER_INCOMPLETE")(e) && JSON.stringify(e.detail.missing) === "[0]");
  storage.chunk(id, 0, chunks[0]);
  assert.equal(storage.ready(id).eventCount, manifest.view.eventCount);
  // Abort clears the active transfer; the stored one still loads.
  assert.deepEqual(storage.abort(id), { transferId: id });
  assert.equal(storage.inspect().active, null);
  assert.throws(() => storage.ready(id), code("TRANSFER_CONFLICT"));
  assert.throws(() => storage.chunk(id, 0, chunks[0]), code("TRANSFER_CONFLICT"));
  assert.equal(storage.load(id).transferId, id);
  // A new transfer may begin after an abort.
  assert.deepEqual(storage.begin(manifest, id, null), { transferId: id });
  assert.throws(() => A.openCheckpointStorage(join(dir, "absent")), code("READ_UNAVAILABLE"));
  assert.throws(() => A.openCheckpointStorage(destination, { point: "no" }), code("INVALID_INPUT"));
});

test("a forged history is refused by the export-view check, and changed bytes on disk are caught after verification", async (t) => {
  const dir = temp(t);
  const destination = join(dir, "destination");
  mkdirSync(destination);
  const { config } = await ownerHistory(dir, 3);
  const store = A.openConfiguredEventStore({ historyFile: config.historyFile, witness: false });
  t.after(() => store.close());
  const honest = wire(A.createHistoryTransfer(store));
  /** A self-consistent transfer (digests and id recomputed) over rows changed by `edit`, and a header changed by `header`. */
  const forge = (edit, header = (h) => h) => {
    const bytes = Buffer.from(honest.chunks[0].join(""), "base64");
    const rows = bytes.toString("utf8").split("\n").slice(0, -1).map((line) => JSON.parse(line));
    edit(rows);
    const out = Buffer.from(rows.map((r) => `${A.canonicalEncode(r)}\n`).join(""));
    const manifest = { ...honest.manifest, view: header(honest.manifest.view), segments: [{ ...honest.manifest.segments[0], bytes: out.length, digest: sha256Hex(out) }] };
    return { manifest, transferId: sha256Hex(Buffer.from(A.canonicalEncode(manifest))), chunks: [out.toString("base64").match(/.{1,4096}/g)] };
  };
  const forgeries = [
    forge((rows) => { rows.at(-1).event.data.agentId = "intruder"; }),
    forge(() => {}, (view) => ({ ...view, to: { ...view.to, stateRoot: `0x${"11".repeat(32)}` } })),
    forge((rows) => { rows.at(-1).recordHash = `0x${"22".repeat(32)}`; }),
    forge(() => {}, (view) => ({ ...view, domain: { ...view.domain, deploymentId: "elsewhere" } })),
  ];
  let committed = null;
  for (const forged of forgeries) {
    const storage = A.openCheckpointStorage(destination);
    send(storage, forged, committed);
    assert.throws(() => storage.ready(forged.transferId), (e) => code("TRANSFER_INVALID")(e) && e.detail.failures.length > 0);
    committed = forged.transferId;
  }
  // Verified once, then a stored chunk changes: the next load re-checks the digest instead of trusting the cache.
  const storage = A.openCheckpointStorage(destination);
  const id = send(storage, honest, committed);
  storage.ready(id);
  const chunkFile = join(destination, "irontrellis-transfers", `${honest.manifest.segments[0].digest.slice(2)}.chunk`);
  const original = readFileSync(chunkFile);
  writeFileSync(chunkFile, Buffer.concat([original.subarray(0, -2), Buffer.from(" \n")]));
  assert.throws(() => storage.load(id), code("TRANSFER_CHUNK_INVALID"));
  writeFileSync(chunkFile, original);
  assert.equal(storage.load(id).transferId, id);
});

test("the staging directory: foreign entries, a malformed active pointer, and the storage limits", async (t) => {
  const dir = temp(t);
  const destination = join(dir, "destination");
  mkdirSync(destination);
  const { config } = await ownerHistory(dir, 66);
  const store = A.openConfiguredEventStore({ historyFile: config.historyFile, witness: false });
  t.after(() => store.close());
  const transfer = A.createHistoryTransfer(store);
  const staging = join(destination, "irontrellis-transfers");
  const storage = A.openCheckpointStorage(destination);
  writeFileSync(join(staging, "notes.txt"), "x");
  assert.throws(() => storage.inspect(), code("TRANSFER_STORAGE_INVALID"));
  assert.throws(() => A.openCheckpointStorage(destination), code("TRANSFER_STORAGE_INVALID"));
  rmSync(join(staging, "notes.txt"));
  writeFileSync(join(staging, "active.json"), '{"transferId":"nope"}\n');
  assert.throws(() => storage.inspect(), code("TRANSFER_STORAGE_INVALID"));
  rmSync(join(staging, "active.json"));
  // A leftover temporary file from an interrupted write is tolerated and replaced.
  writeFileSync(join(staging, "active.json.tmp"), "partial");
  const id = send(storage, transfer);
  assert.equal(storage.inspect().active, id);
  // Limits (lowered for the test): manifests, chunks, bytes, segment count.
  t.after(() => setTransferLimitsForTests());
  const used = storage.inspect();
  setTransferLimitsForTests({ manifests: used.manifests });
  const second = await ownerHistory(dir, 0, { historyFile: join(dir, "second.jsonl") });
  const secondStore = A.openConfiguredEventStore({ historyFile: second.config.historyFile, witness: false });
  const other = A.createHistoryTransfer(secondStore);
  secondStore.close();
  assert.throws(() => storage.begin(wire(other).manifest, other.transferId, id), code("TRANSFER_STORAGE_LIMIT"));
  setTransferLimitsForTests({ bytes: used.bytes + 10 });
  assert.throws(() => storage.begin(wire(other).manifest, other.transferId, id), code("TRANSFER_STORAGE_LIMIT"));
  setTransferLimitsForTests({ chunks: used.chunks });
  storage.begin(wire(other).manifest, other.transferId, id);
  assert.throws(() => storage.chunk(other.transferId, 0, wire(other).chunks[0]), code("TRANSFER_STORAGE_LIMIT"));
  setTransferLimitsForTests({ segments: 1 });
  assert.throws(() => A.createHistoryTransfer(store), code("TRANSFER_INVALID"));
  setTransferLimitsForTests();
  storage.chunk(other.transferId, 0, wire(other).chunks[0]);
  assert.equal(storage.ready(other.transferId).eventCount, other.manifest.view.eventCount);
});
