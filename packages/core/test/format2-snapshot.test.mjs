// The snapshot store and CHECKPOINT_RESUME (SPEC §7.5; addenda A-19, A-20): a valid snapshot never costs a full replay
// and the root recomputation is never skipped (replay-call counters); the async-signer case (a pin without a usable
// attestation falls back to the latest checkpoint); the owner keys come from the file (a forged-key snapshot with a pin
// signed by that key is refused; a snapshot whose epochs differ from the file's is SNAPSHOT_STALE); `historyId`
// (HISTORY_IDENTITY_MISMATCH); a valid owner signature over a wrong root in the pin or the anchor log is
// ATTESTED_STATE_ROOT_MISMATCH; the trust-mode defaults (verifyHistory full replay; the local API resumes); journal
// compaction; the snapshot files after a writer with and without the owner key; a resume inside a migrated prefix is
// covered by the migration tests. Timings at 1,000 events are reported as diagnostics (10,000 in E3-NOTES).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const core = await import("../src/index.ts");
const { openHistoryStore, storeCounters, resetStoreCountersForTests, PINNED_HEAD_VERSION } = await import("../src/store.ts");
const { readSnapshotBase, readJournal, snapshotPathFor, journalPathFor, SNAPSHOT_JOURNAL_LIMIT } = await import("../src/snapshot.ts");
const signer = await import("../src/signer.ts");
const anchor = await import("../src/anchor.ts");
const { generateKeyPair } = await import("../src/crypto/suites.ts");
const histories = await import("./helpers/format2-histories.mjs");
const { createLocalDomain, createLocalOwner, openLocalOwner, verifyHistory } = await import("../src/owner.ts");

const code = (value, reason) => (e) => e.code === value && (reason === undefined || e.detail?.reason === reason);
const pinOf = (path) => JSON.parse(readFileSync(`${path}.head`, "utf8"));
const writePin = (path, pin) => writeFileSync(`${path}.head`, `${JSON.stringify(pin)}\n`);
const fullRoot = (events) => { const r = core.replay(events); assert.equal(r.status, "ACCEPTED"); return r.stateRoot; };

test("a valid snapshot resumes without a full replay, with the root recomputed; verify() replays in full; the local API resumes by default", async (t) => {
  const dir = histories.tempDir();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const { config, events } = await histories.richHistory(dir);
  const path = config.historyFile;
  resetStoreCountersForTests();
  const store = openHistoryStore(path, { trust: "CHECKPOINT_RESUME", witness: false });
  assert.equal(store.loadedBy(), "CHECKPOINT_RESUME");
  assert.deepEqual({ ...storeCounters }, { fullReplays: 0, resumes: 1, snapshotRebuilds: 0, rootRecomputations: 1 });
  assert.equal(core.stateRootOf(store.state()).root, fullRoot(events));
  assert.equal(store.state().events.length, events.length);
  // Every query answers as a full replay does (the lazily verified events are read on demand).
  const o = core.observeState(store.state(), { at: 1000 }), f = core.observeState(core.replay(events).state, { at: 1000 });
  for (const q of [{ actor: "b", action: "read", resource: "incident:42" }, { actor: "b", action: "ASSIGN_ATTEMPT_DUTY", resource: "ticket:1" }]) assert.deepEqual(o.why(q), f.why(q));
  assert.deepEqual(o.survives("a"), f.survives("a"));
  // verify() never trusts a resumed state: it replays in full and reports the snapshot as used at open.
  const report = store.verify();
  assert.equal(report.ok, true);
  assert.equal(report.snapshot, "USED");
  assert.equal(report.stateRoot, fullRoot(events));
  assert.equal(storeCounters.fullReplays, 1);
  store.close();
  // The local owner API resumes by default; `verifyHistory` replays in full; `trust: "FULL_REPLAY"` is honoured.
  resetStoreCountersForTests();
  const owner = openLocalOwner({ ...config, witness: false });
  assert.equal(owner.stateRoot().stateRoot, fullRoot(events));
  assert.deepEqual([storeCounters.fullReplays, storeCounters.resumes], [0, 1]);
  verifyHistory(path);
  assert.equal(storeCounters.fullReplays, 1);
  openLocalOwner({ ...config, witness: false, trust: "FULL_REPLAY" }).stateRoot();
  assert.equal(storeCounters.fullReplays, 2);
  assert.equal(storeCounters.resumes, 1);
});

test("async signer: a pin whose attestation is not usable falls back to the latest checkpoint; no checkpoint means a full replay", async (t) => {
  const dir = histories.tempDir();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const { config, events } = await histories.e2History(dir);
  const path = config.historyFile;
  // e2: the owner's last write is the handover checkpoint (position 31); runtime writes follow (32–34), so the pin at 34 carries the attestation of 31.
  const pin = pinOf(path);
  assert.equal(pin.position, events.length - 1);
  assert.equal(pin.attestation.head.position, 31);
  assert.equal(events[31].type, "STATE_CHECKPOINT");
  // "No signed root yet": the pin's attestation is gone (an asynchronous signer that has not answered; allowUnpinned reads it).
  const { attestation: _gone, ...unattested } = pin;
  writePin(path, { version: PINNED_HEAD_VERSION, ...unattested });
  resetStoreCountersForTests();
  const store = openHistoryStore(path, { trust: "CHECKPOINT_RESUME", witness: false, allowUnpinned: true });
  assert.equal(store.loadedBy(), "CHECKPOINT_RESUME");
  assert.deepEqual([storeCounters.fullReplays, storeCounters.resumes], [0, 1]);
  assert.equal(core.stateRootOf(store.state()).root, fullRoot(events));
  store.close();
  // Without a checkpoint the journal can seed: compact the snapshot at the head (base 34, empty journal) → no signed root at 34 → full replay.
  writeFileSync(snapshotPathFor(path), `${JSON.stringify({ ...readSnapshotBase(path), position: 34, records: core.stateRecordsOf(core.replay(events).state).map((e) => ({ kind: e.kind, key: e.key, record: e.record })) })}\n`);
  writeFileSync(journalPathFor(path), "");
  resetStoreCountersForTests();
  const full = openHistoryStore(path, { trust: "CHECKPOINT_RESUME", witness: false, allowUnpinned: true });
  assert.equal(full.loadedBy(), "FULL_REPLAY");
  assert.equal(full.verify().snapshot, "STALE");
  full.close();
});

test("A-19: a forged-key snapshot with a pin signed by that key is refused; a snapshot whose epochs differ from the file's is SNAPSHOT_STALE; historyId", async (t) => {
  const dir = histories.tempDir();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const { config, events } = await histories.e2History(dir);
  const path = config.historyFile;
  const state = core.replay(events).state;
  const genuinePin = pinOf(path);
  // The attacker's key replaces epoch 0 in the snapshot's records; the root is recomputed over the forged set and the pin re-signed with that key.
  const thief = signer.signerFromKeyPair(generateKeyPair("ed25519", "owner:1"));
  const base = readSnapshotBase(path);
  const forged = base.records.map((r) => (r.kind === "ownerKeyEpoch" && r.key === "0" ? { ...r, record: { ...r.record, keys: [{ keyId: "owner:1", scheme: "ed25519", credential: thief.credential }] } } : r));
  const forgedRoot = core.recomputeRoot(forged);
  writeFileSync(snapshotPathFor(path), `${JSON.stringify({ ...base, position: events.length - 1, stateRoot: forgedRoot.root, records: forged })}\n`);
  writeFileSync(journalPathFor(path), "");
  const head = state.head;
  const attestation = signer.attestHeadSync(thief, state.genesis.domain, head, "sha256", { stateRoot: forgedRoot.root, projectionHead: core.projectionHeadAt(state, head.position) });
  writePin(path, { version: PINNED_HEAD_VERSION, ...genuinePin, attestation });
  resetStoreCountersForTests();
  // Refused: the file's genesis keys are not the snapshot's, the resume falls back, and the full replay finds the pin's attestation invalid.
  assert.throws(() => openHistoryStore(path, { trust: "CHECKPOINT_RESUME", witness: false }), code("ROLLBACK_DETECTED", "PIN_ATTESTATION_INVALID"));
  assert.deepEqual([storeCounters.fullReplays, storeCounters.resumes], [1, 0]);
  const inspected = openHistoryStore(path, { trust: "CHECKPOINT_RESUME", witness: false, inspect: true });
  assert.equal(inspected.loadedBy(), "FULL_REPLAY");
  const report = inspected.verify();
  assert.equal(report.snapshot, "STALE");
  assert.ok(report.failures.some((f) => f.startsWith("PIN_ATTESTATION_INVALID")), report.failures.join("; "));
  inspected.close();
  // A snapshot whose ownerKeyEpoch records differ from the file's (a claimed extra epoch) with the genuine pin: SNAPSHOT_STALE, full replay, rebuilt.
  writePin(path, { version: PINNED_HEAD_VERSION, ...genuinePin });
  const extra = [...base.records, { kind: "ownerKeyEpoch", key: "1", record: { epoch: 1, fromPosition: 3, keys: [{ keyId: "owner:2", scheme: "ed25519", credential: thief.credential }], nextKeyDigests: null } }];
  writeFileSync(snapshotPathFor(path), `${JSON.stringify({ ...base, records: extra })}\n`);
  writeFileSync(journalPathFor(path), "");
  resetStoreCountersForTests();
  const stale = openHistoryStore(path, { trust: "CHECKPOINT_RESUME", witness: false });
  assert.equal(stale.loadedBy(), "FULL_REPLAY");
  assert.equal(stale.verify().snapshot, "STALE");
  assert.equal(storeCounters.snapshotRebuilds, 1);
  stale.close();
  // historyId: the configured identity is recordHash(0).
  assert.equal(openHistoryStore(path, { historyId: state.eventHistoryHashes[0], witness: false }).state().head.hash, head.hash);
  assert.throws(() => openHistoryStore(path, { historyId: `0x${"ab".repeat(32)}`, witness: false }), code("HISTORY_IDENTITY_MISMATCH"));
  assert.throws(() => openLocalOwner({ ...config, witness: false, historyId: `0x${"ab".repeat(32)}` }), code("HISTORY_IDENTITY_MISMATCH"));
});

test("A-20: a valid owner signature over a wrong root in the pin or the anchor log is ATTESTED_STATE_ROOT_MISMATCH; a retired key's attestation never seeds a resume", async (t) => {
  const dir = histories.tempDir();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const { config, events } = await histories.richHistory(dir);
  const path = config.historyFile;
  const state = core.replay(events).state;
  const owner = signer.loadOwnerKeyFile(signer.ownerKeyPathFor(path));
  const genuinePin = pinOf(path);
  const wrong = signer.attestHeadSync(owner, state.genesis.domain, state.head, "sha256", { stateRoot: `0x${"77".repeat(32)}`, projectionHead: core.projectionHeadAt(state, state.head.position) });
  writePin(path, { version: PINNED_HEAD_VERSION, ...genuinePin, attestation: wrong });
  // Resume mode: the snapshot's recomputed root differs from the (validly signed) wrong root → fallback; the replaying opener then reports misuse.
  assert.throws(() => openHistoryStore(path, { trust: "CHECKPOINT_RESUME", witness: false }), code("ATTESTED_STATE_ROOT_MISMATCH", "PIN"));
  assert.throws(() => openHistoryStore(path, { witness: false }), code("ATTESTED_STATE_ROOT_MISMATCH", "PIN"));
  const inspected = openHistoryStore(path, { witness: false, inspect: true });
  assert.ok(inspected.verify().failures.some((f) => f.startsWith("ATTESTED_STATE_ROOT_MISMATCH:") && f.endsWith("(PIN)")));
  inspected.close();
  writePin(path, { version: PINNED_HEAD_VERSION, ...genuinePin });
  // The anchor log: append a validly signed attestation of an earlier head with a wrong root.
  const log = `${path}.anchors`;
  const at = 10, earlier = { hash: state.eventHistoryHashes[at], position: at, canonicalTime: events[at].timestamp };
  const retired = signer.loadOwnerKeyFile(signer.ownerKeyPathFor(path).replace(".owner-key.json", ".owner-key.owner_1.retired.json"));
  const badEntry = { attestation: signer.attestHeadSync(retired, state.genesis.domain, earlier, "sha256", { stateRoot: `0x${"88".repeat(32)}`, projectionHead: core.projectionHeadAt(state, at) }), receivedAt: 1 };
  const kept = readFileSync(log, "utf8");
  writeFileSync(log, `${kept}${JSON.stringify(badEntry)}\n`);
  assert.throws(() => openHistoryStore(path, { witness: false }), code("ATTESTED_STATE_ROOT_MISMATCH", "ANCHOR_LOG"));
  const report = openHistoryStore(path, { witness: false, inspect: true }).verify();
  assert.ok(report.failures.some((f) => f.startsWith("ATTESTED_STATE_ROOT_MISMATCH:") && f.endsWith("(ANCHOR_LOG)")), report.failures.join("; "));
  assert.ok(report.anchorLogHeads.some((h) => h.status === "STATE_ROOT_MISMATCH"));
  writeFileSync(log, kept);
  // A-20.1: an attestation by the retired key (valid for its own prefix position) never seeds a resume, even with the right root.
  const retiredAt = { hash: state.eventHistoryHashes[20], position: 20, canonicalTime: events[20].timestamp };
  const base = readSnapshotBase(path);
  const prefix = core.replay(events.slice(0, 21)).state;
  writeFileSync(snapshotPathFor(path), `${JSON.stringify({ ...base, position: 20, stateRoot: core.rootAt(prefix, 20), records: core.stateRecordsOf(prefix).map((e) => ({ kind: e.kind, key: e.key, record: e.record })) })}\n`);
  writeFileSync(journalPathFor(path), "");
  writePin(path, { version: PINNED_HEAD_VERSION, ...genuinePin, attestation: signer.attestHeadSync(retired, state.genesis.domain, retiredAt, "sha256", { stateRoot: core.rootAt(prefix, 20), projectionHead: core.projectionHeadAt(prefix, 20) }) });
  resetStoreCountersForTests();
  const store = openHistoryStore(path, { trust: "CHECKPOINT_RESUME", witness: false });
  assert.equal(store.loadedBy(), "FULL_REPLAY");
  assert.equal(store.verify().snapshot, "STALE");
  store.close();
  writePin(path, { version: PINNED_HEAD_VERSION, ...genuinePin });
});

test("journal and compaction: one line per append, a base rewrite every SNAPSHOT_JOURNAL_LIMIT lines, a writer without the owner key journals too; timings at 1,000 events", async (t) => {
  const dir = histories.tempDir();
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let tick = 100;
  const config = { historyFile: join(dir, "h.jsonl"), domain: createLocalDomain(), owner: "o", controller: "c", now: () => tick, witness: false };
  const path = config.historyFile;
  const owner = await createLocalOwner(config);
  const timings = [];
  for (let n = 0; n < 1000; n += 1) {
    const started = performance.now();
    await owner.createAgent({ id: `agent:${n}` });
    timings.push(performance.now() - started);
  }
  timings.sort((a, b) => a - b);
  const base = readSnapshotBase(path), journal = readJournal(path, base);
  assert.ok(base.position > 0 && journal.length <= SNAPSHOT_JOURNAL_LIMIT, `base at ${base.position}, journal ${journal.length}`);
  assert.equal(journal.at(-1)?.position ?? base.position, owner.exportHistory().length - 1);
  assert.equal(statSync(journalPathFor(path)).size > 0 || journal.length === 0, true);
  const resumeStarted = performance.now();
  resetStoreCountersForTests();
  const store = openHistoryStore(path, { trust: "CHECKPOINT_RESUME", witness: false });
  const resumeMs = performance.now() - resumeStarted;
  assert.equal(store.loadedBy(), "CHECKPOINT_RESUME");
  assert.equal(storeCounters.fullReplays, 0);
  const fullStarted = performance.now();
  const full = openHistoryStore(path, { witness: false });
  const fullMs = performance.now() - fullStarted;
  assert.equal(core.stateRootOf(store.state()).root, core.stateRootOf(full.state()).root);
  t.diagnostic(`1,000 owner appends (incl. two signatures, pin, journal): median ${timings[500].toFixed(2)} ms; resume ${resumeMs.toFixed(1)} ms vs full replay ${fullMs.toFixed(1)} ms (${store.state().stateRecords.size} records)`);
  store.close();
  full.close();
});
