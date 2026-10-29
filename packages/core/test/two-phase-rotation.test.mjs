// Closing review finding M2 on the witness side (WITNESS-DESIGN §11.2–§11.4), against the in-test fake witness:
//  - the two-phase rotation (the default with bound witnesses): every bound witness records head r and the rotation
//    before the local append; abort with nothing written when none does; partial acceptance ("rotation incomplete");
//    an unknown outcome keeps the prepared-rotation record, which the next owner command completes or discards;
//  - recovery after a crash at every step (one test per window), including "a witness holds head r, the file does not":
//    completed, never a rollback alarm, and signed by nobody;
//  - an attacker planting or editing the record: never an owner signature, never an event the replay rules reject;
//  - the genesis commitment at the witness, commitment-only rotations and the key-event bundles (commitNextKey,
//    rotation, export, admin import);
//  - supersede: a pre-rotated emergency rotation overrides what a leaked old key pushed onto a witness; a rotation that
//    is not pre-rotated, or an unknown last good head, fails closed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startFakeWitness } from "./helpers/fake-witness.mjs";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling

const { TRELLIS_FORMAT } = await import("../src/events.ts");
const { createLocalOwner: createLocalOwnerDefault, openLocalOwner: openLocalOwnerDefault, createLocalDomain: createLocalDomainDefault, verifyHistoryWithWitnesses, setRotationFaultForTests, RotationFault } = await import("../src/owner.ts");
// These tests cover the format-1 (and legacy) owner API; the API writes format 2 by default (SPEC §19), so format 1 is named for every handle and domain made here.
const createLocalOwner = (options) => createLocalOwnerDefault({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true, ...options });
const openLocalOwner = (options) => openLocalOwnerDefault({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true, ...options });
const createLocalDomain = (options = {}) => createLocalDomainDefault({ format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true, ...options });
const { openHistoryStore: openHistoryStoreStrict } = await import("../src/store.ts");
// Fixture writes to legacy and format-1 files (SPEC §16.1: those formats open read only by default; format 2 is the wire). These tests cover the earlier store writer, so the fence is off here.
const openHistoryStore = (path, options = {}) => openHistoryStoreStrict(path, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true, ...options });
const { loadOwnerKeyFile, ownerKeyPathFor, pendingOwnerKeyPathFor, pendingNextOwnerKeyPathFor, nextOwnerKeyPathFor, signControlEvent, createOwnerKeyFile } = await import("../src/signer.ts");
const { readWitnessState, witnessStatePathFor } = await import("../src/witness-state.ts");
const { resetWitnessViews } = await import("../src/witness-session.ts");
const { pendingRotationPathFor, readPendingRotation } = await import("../src/rotation-pending.ts");
const tp = await import("../src/transparency/index.ts");

let clock = 5_000_000;
const now = () => (clock += 1);

/** A transport the test can break: `net.hook(url, init)` may return "drop" (never sent) or "lose" (sent, answer lost). */
function network() {
  const net = { hook: undefined };
  net.fetch = async (url, init) => {
    const verdict = net.hook?.(new URL(url), init);
    if (verdict === "drop") throw new TypeError("fetch failed: connection refused (test)");
    const response = await globalThis.fetch(url, init);
    if (verdict === "lose") { await response.text(); throw new TypeError("fetch failed: connection reset (test)"); }
    return response;
  };
  return net;
}
const policyOf = (witnesses, extra = {}) => ({ witnesses: witnesses.map((w) => ({ url: w.url, verifierKey: w.verifierKey })), ...extra });
const isKeyEvents = (url, init) => init.method === "POST" && url.pathname.endsWith("/key-events");
const isHistoryGet = (url, init) => init.method === "GET" && /^\/v1\/histories\/0x[0-9a-f]{64}$/.test(url.pathname);

async function setup(witnesses, extra = {}, events = 2, options = {}) {
  const directory = mkdtempSync(join(tmpdir(), "two-phase-"));
  const historyFile = join(directory, "history.jsonl");
  const domain = createLocalDomain();
  const net = network();
  const policy = policyOf(witnesses, { fetch: net.fetch, ...extra });
  const owner = await createLocalOwner({ historyFile, domain, owner: "owner", controller: "controller", now, witness: policy, ...options });
  for (let n = 0; n < events; n += 1) await owner.createAgent({ id: `agent:${n}` });
  await owner.flush();
  const open = (more = {}) => openLocalOwner({ historyFile, domain, owner: "owner", controller: "controller", now, witness: policy, ...more });
  const disk = () => openHistoryStore(historyFile, { inspect: true, witness: false }).state();
  return { directory, historyFile, domain, owner, open, disk, head: () => disk().head, historyId: () => disk().eventHistoryHashes[0], net, policy };
}
const log = (w, id) => w.entries.filter((e) => e.historyId === id).map((e) =>
  e.kind === "HEAD" ? `HEAD ${e.signedStatement.statement.head.position} ${e.signedStatement.keyId}` : e.kind === "ROTATED" ? `ROTATED ${e.rotationHead.position}` : e.kind);
const pendingFiles = (h) => [pendingRotationPathFor(h.historyFile), pendingOwnerKeyPathFor(h.historyFile), pendingNextOwnerKeyPathFor(h.historyFile)].filter(existsSync);
const pinOf = (h) => JSON.parse(readFileSync(`${h.historyFile}.head`, "utf8"));

// ---------------------------------------------------------------- the normal path

test("two-phase (§11.2): every bound witness records head r (old key) and the rotation before the local append; the record exists only in between", async (t) => {
  const a = await startFakeWitness({ name: "tp-a", seed: 201 }), b = await startFakeWitness({ name: "tp-b", seed: 202 });
  t.after(() => Promise.all([a.close(), b.close()]));
  const h = await setup([a, b], { mode: "sync" });
  const id = h.historyId();
  const oldKey = loadOwnerKeyFile(ownerKeyPathFor(h.historyFile)).keyId;
  const before = h.head();
  const seen = [];
  h.net.hook = (url, init) => {
    if (isKeyEvents(url, init)) {
      // At delivery: the prepared record is on disk, nothing is appended yet, and the rotation travels with its head statement.
      const record = readPendingRotation(pendingRotationPathFor(h.historyFile));
      seen.push({ record: record?.head.position, file: h.head().position, body: JSON.parse(init.body) });
    }
  };
  const rotated = await h.owner.rotateOwnerKey({ reason: "scheduled" });
  h.net.hook = undefined;
  const r = rotated.head.position;
  assert.equal(r, before.position + 1);
  assert.deepEqual(seen.map((s) => [s.record, s.file]), [[r, r - 1], [r, r - 1]]);
  assert.ok(seen.every((s) => s.body.statement.statement.head.position === r && s.body.statement.keyId === oldKey && s.body.statement.statement.previous.position === r - 1));
  assert.deepEqual([...rotated.witnesses.accepted].sort(), [a.url, b.url].sort());
  assert.equal(rotated.emergency, false);
  assert.equal(rotated.rotationIncomplete, false);
  assert.equal(pendingFiles(h).length, 0, "record and staged files are gone");
  for (const w of [a, b]) {
    assert.deepEqual(log(w, id).slice(-2), [`HEAD ${r} ${oldKey}`, `ROTATED ${r}`]);
    assert.deepEqual(w.histories.get(id).epochs.map((e) => e.fromPosition), [0, r + 1]);
    assert.equal(w.histories.get(id).epochs[1].nextKeyDigests.length, 1, "the new epoch's commitment is known to the witness");
  }
  // The bundle is self-authenticating: the statement for r by the old key, previous r - 1.
  const bundle = JSON.parse(readFileSync(rotated.bundle, "utf8"));
  assert.equal(tp.validateKeyEventBundle(bundle), null);
  assert.equal(bundle.statement.keyId, oldKey);
  await h.owner.createAgent({ id: "agent:after" });
  assert.equal(log(a, id).at(-1), `HEAD ${r + 1} ${rotated.keyId}`);
  const report = await verifyHistoryWithWitnesses(h.historyFile);
  assert.equal(report.ok, true, report.failures.join("\n"));
  assert.ok(!report.notes.some((n) => n.startsWith("REMOTE_WITNESS_ROTATION_INCOMPLETE")));
});

test("two-phase: a bound witness not at the head aborts before anything is prepared; --emergency rotates locally first (the previous behaviour)", async (t) => {
  const a = await startFakeWitness({ name: "tp-down-a", seed: 203 }), b = await startFakeWitness({ name: "tp-down-b", seed: 204 });
  t.after(() => Promise.all([a.close(), b.close()]));
  // quorum 2 of 2: a submission round needs n - q + 1 = 1 answer, so the reachable witness is served while the other is down.
  const h = await setup([a, b], { mode: "sync", quorum: 2 });
  const id = h.historyId();
  b.down = true;
  const before = h.head();
  await assert.rejects(h.owner.rotateOwnerKey(), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "ROTATION_NEEDS_WITNESSES" &&
    e.message.startsWith("rotation needs every bound witness; retry, or rotate with --emergency") && e.detail.witnesses.includes(b.url));
  assert.deepEqual(h.head(), before);
  assert.equal(pendingFiles(h).length, 0);
  assert.equal(a.state.keyEventsReceived.filter((body) => body.event.type === "OWNER_KEYS_ROTATED").length, 0, "nothing was sent");
  const rotated = await h.owner.rotateOwnerKey({ emergency: true });
  assert.equal(rotated.emergency, true);
  assert.equal(rotated.rotationIncomplete, true);
  assert.deepEqual(a.histories.get(id).epochs.map((e) => e.fromPosition), [0, rotated.head.position + 1], "delivered afterwards to the reachable witness");
  const status = h.owner.witnessStatus();
  assert.equal(status.witnesses.find((w) => w.url === b.url).pendingRotations, 1, "known to lack it");
  assert.equal(status.rotationIncomplete, true);
  b.down = false;
  await h.owner.flush();
  assert.deepEqual(b.histories.get(id).epochs.map((e) => e.fromPosition), [0, rotated.head.position + 1]);
  assert.equal(h.owner.witnessStatus().rotationIncomplete, false);
});

test("two-phase: a witness refuses during delivery → recorded with the other ('rotation incomplete' in status and verify); the queue delivers later", async (t) => {
  const a = await startFakeWitness({ name: "tp-part-a", seed: 205 }), b = await startFakeWitness({ name: "tp-part-b", seed: 206 });
  t.after(() => Promise.all([a.close(), b.close()]));
  const h = await setup([a, b], { mode: "sync" });
  const id = h.historyId();
  let blocked = true;
  h.net.hook = (url, init) => (blocked && url.origin === new URL(b.url).origin && isKeyEvents(url, init) ? "drop" : undefined);
  const rotated = await h.owner.rotateOwnerKey();
  assert.deepEqual(rotated.witnesses.accepted, [a.url]);
  assert.deepEqual(rotated.witnesses.refused.map((r) => r.url), [b.url], "asked again: b still holds r - 1, a definitive no");
  assert.equal(rotated.rotationIncomplete, true);
  assert.equal(h.owner.witnessStatus().rotationIncomplete, true);
  const report = await verifyHistoryWithWitnesses(h.historyFile, { witness: h.policy });
  assert.equal(report.ok, true, report.failures.join("\n"));
  assert.ok(report.notes.some((n) => n.startsWith("REMOTE_WITNESS_ROTATION_INCOMPLETE") && n.includes(b.url)), report.notes.join("\n"));
  assert.deepEqual(report.remoteWitnesses.find((w) => w.url === b.url).pendingRotationPositions, [rotated.head.position]);
  blocked = false;
  await h.owner.flush();
  assert.deepEqual(b.histories.get(id).epochs.map((e) => e.fromPosition), [0, rotated.head.position + 1]);
  assert.equal(h.owner.witnessStatus().rotationIncomplete, false);
});

test("two-phase: no bound witness accepts → abort cleanly: nothing appended, staged files and record removed, WITNESS_UNAVAILABLE", async (t) => {
  const a = await startFakeWitness({ name: "tp-none-a", seed: 207 }), b = await startFakeWitness({ name: "tp-none-b", seed: 208 });
  t.after(() => Promise.all([a.close(), b.close()]));
  const h = await setup([a, b], { mode: "sync" });
  const before = h.head();
  const keyFile = readFileSync(ownerKeyPathFor(h.historyFile));
  const nextFile = readFileSync(nextOwnerKeyPathFor(h.historyFile));
  h.net.hook = (url, init) => (isKeyEvents(url, init) ? "drop" : undefined);
  await assert.rejects(h.owner.rotateOwnerKey(), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "ROTATION_ABORTED" &&
    e.message.startsWith("rotation needs every bound witness; retry, or rotate with --emergency"));
  h.net.hook = undefined;
  assert.deepEqual(h.head(), before);
  assert.equal(pendingFiles(h).length, 0);
  assert.deepEqual(readFileSync(ownerKeyPathFor(h.historyFile)), keyFile, "the owner key file is untouched");
  assert.deepEqual(readFileSync(nextOwnerKeyPathFor(h.historyFile)), nextFile, "and so is the next key");
  const again = await h.owner.rotateOwnerKey();
  assert.equal(again.head.position, before.position + 1, "a retry rotates normally");
});

test("two-phase: an unknown outcome keeps the record; writes refuse ROTATION_PENDING; the next owner command discards it (no witness holds r)", async (t) => {
  const w = await startFakeWitness({ name: "tp-unknown", seed: 209 });
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync" });
  const before = h.head();
  let delivering = false;
  h.net.hook = (url, init) => {
    if (isKeyEvents(url, init)) { delivering = true; return "drop"; }
    return delivering ? "drop" : undefined; // the witness goes silent: the re-ask gets no answer either
  };
  await assert.rejects(h.owner.rotateOwnerKey(), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "ROTATION_OUTCOME_UNKNOWN");
  assert.deepEqual(h.head(), before);
  assert.equal(pendingFiles(h).length, 3, "record and both staged key files are kept while the outcome is unknown");
  // Any writer is refused while the record is outstanding and the witness cannot say whether it holds r.
  await assert.rejects(h.owner.createAgent({ id: "agent:blocked" }), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "ROTATION_PENDING");
  const plain = openHistoryStore(h.historyFile, { signer: loadOwnerKeyFile(ownerKeyPathFor(h.historyFile)) });
  const state = plain.state();
  const event = await signControlEvent(loadOwnerKeyFile(ownerKeyPathFor(h.historyFile)), { id: "event:plain", type: "AGENT_CREATED", timestamp: now(), data: { agentId: "agent:plain", principalId: "owner", controllerId: "controller", initialControlEpoch: 1 } }, h.domain, state.head, "sha256");
  assert.throws(() => plain.append(event), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "ROTATION_PENDING");
  plain.close();
  // A reopened handle (the settle on open) keeps the staged keys of an outstanding record.
  resetWitnessViews();
  h.open().close();
  assert.equal(pendingFiles(h).length, 3);
  // The witness answers again: it does not hold r, so the record is discarded and the write proceeds.
  h.net.hook = undefined;
  delivering = false;
  const next = h.open();
  await next.createAgent({ id: "agent:after" });
  assert.equal(existsSync(pendingRotationPathFor(h.historyFile)), false);
  assert.equal(h.head().position, before.position + 1);
  assert.notEqual(h.disk().events.at(-1).type, "OWNER_KEYS_ROTATED");
  next.close();
  resetWitnessViews();
  const later = h.open();
  assert.equal(pendingFiles(h).length, 0, "the next settle removes the staged keys no epoch declares");
  const rotated = await later.rotateOwnerKey();
  assert.equal(rotated.witnesses.accepted.length, 1);
});

test("two-phase: an unknown outcome where the witness DID record it: the next owner command completes the append (no rollback alarm)", async (t) => {
  const w = await startFakeWitness({ name: "tp-lost", seed: 210 });
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync" });
  const id = h.historyId();
  const before = h.head();
  let delivering = false;
  h.net.hook = (url, init) => {
    if (isKeyEvents(url, init)) { delivering = true; return "lose"; }
    return delivering ? "drop" : undefined;
  };
  await assert.rejects(h.owner.rotateOwnerKey(), (e) => e.code === "WITNESS_UNAVAILABLE" && e.detail.reason === "ROTATION_OUTCOME_UNKNOWN");
  assert.equal(w.latest(id).position, before.position + 1, "the witness holds head r");
  assert.equal(h.head().position, before.position, "the file does not");
  h.net.hook = undefined;
  resetWitnessViews();
  const next = h.open();
  await next.createAgent({ id: "agent:after" });
  const state = h.disk();
  assert.equal(state.events[before.position + 1].type, "OWNER_KEYS_ROTATED");
  assert.equal(pendingFiles(h).length, 0);
  assert.equal(log(w, id).at(-1).split(" ")[1], String(before.position + 2));
  assert.equal((await verifyHistoryWithWitnesses(h.historyFile, { witness: h.policy })).ok, true);
});

// ---------------------------------------------------------------- crash windows

/**
 * One test per window of the two-phase rotation's crash table (docs/reference/witness-operations.md §7.1): a simulated crash (nothing is
 * cleaned up), then a fresh process. Every window ends in one consistent state, without a rollback alarm.
 */
for (const [window, expectAppended, check] of [
  ["after-stage", false, (h) => assert.equal(existsSync(pendingRotationPathFor(h.historyFile)), false)],
  ["after-record", false, (h, w, id, r) => assert.equal(w.latest(id).position, r - 1, "no witness has it")],
  ["after-delivery", true, (h, w, id, r) => assert.equal(w.latest(id).position, r, "the witness holds head r, the file does not")],
  ["after-append", true, (h) => assert.ok(existsSync(pendingOwnerKeyPathFor(h.historyFile)), "the key files were not swapped")],
  ["after-owner-key-swap", true, (h) => assert.ok(existsSync(pendingNextOwnerKeyPathFor(h.historyFile)), "the next key was not moved")],
]) {
  test(`crash window ${window}: recovered on the next open or owner write`, async (t) => {
    const w = await startFakeWitness({ name: `tp-crash-${window}`, seed: 300 + window.length });
    t.after(() => w.close());
    const h = await setup([w], { mode: "sync" });
    const id = h.historyId();
    const r = h.head().position + 1;
    const oldKey = loadOwnerKeyFile(ownerKeyPathFor(h.historyFile));
    const pinBefore = pinOf(h);
    setRotationFaultForTests(window);
    await assert.rejects(h.owner.rotateOwnerKey({ reason: `crash ${window}` }), (e) => e instanceof RotationFault);
    setRotationFaultForTests(undefined);
    check(h, w, id, r);
    // A fresh process: an owner handle opens (settling what it can locally) and writes.
    resetWitnessViews();
    const next = h.open();
    await next.createAgent({ id: "agent:after-crash" });
    await next.flush();
    const state = h.disk();
    assert.equal(state.events[r].type === "OWNER_KEYS_ROTATED", expectAppended, `rotation ${expectAppended ? "completed" : "discarded"}`);
    assert.equal(pendingFiles(h).length, 0, "no record or staged file is left");
    assert.deepEqual(w.latest(id), { hash: state.head.hash, position: state.head.position, canonicalTime: state.head.canonicalTime });
    const keyNow = loadOwnerKeyFile(ownerKeyPathFor(h.historyFile));
    assert.equal(keyNow.keyId !== oldKey.keyId, expectAppended, "the key file holds the key in force");
    if (window === "after-delivery") {
      // Completed by the recovery, which signs nothing: head r carries no new attestation (the pin carried the older one).
      assert.equal(pinBefore.attestation.head.position, r - 1);
      const heads = w.heads(id).map((s) => `${s.statement.head.position} ${s.keyId}`);
      assert.ok(heads.includes(`${r} ${oldKey.keyId}`) && heads.includes(`${r + 1} ${keyNow.keyId}`), heads.join(", "));
    }
    const report = await verifyHistoryWithWitnesses(h.historyFile, { witness: h.policy });
    assert.equal(report.ok, true, report.failures.join("\n"));
    if (!expectAppended) {
      const rotated = await next.rotateOwnerKey();
      assert.equal(rotated.witnesses.accepted.length, 1, "a new rotation works after the discarded one");
    }
  });
}

test("crash after the witness accepted: verify reports the pending rotation (a note, not a rollback) until an owner command appends it", async (t) => {
  const w = await startFakeWitness({ name: "tp-verify-pending", seed: 311 });
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync" });
  setRotationFaultForTests("after-delivery");
  await assert.rejects(h.owner.rotateOwnerKey(), (e) => e instanceof RotationFault);
  resetWitnessViews();
  const report = await verifyHistoryWithWitnesses(h.historyFile, { witness: h.policy });
  assert.equal(report.ok, true, report.failures.join("\n"));
  assert.equal(report.remoteWitnessStatus, "OK");
  assert.ok(report.notes.some((n) => n.startsWith("REMOTE_WITNESS_ROTATION_PENDING")), report.notes.join("\n"));
  // Without the record, the same file IS a rollback at the witness (the recovery rests on the record, nothing else).
  renameSync(pendingRotationPathFor(h.historyFile), `${pendingRotationPathFor(h.historyFile)}.away`);
  resetWitnessViews();
  const without = await verifyHistoryWithWitnesses(h.historyFile, { witness: h.policy });
  assert.equal(without.remoteWitnessStatus, "ROLLBACK");
  renameSync(`${pendingRotationPathFor(h.historyFile)}.away`, pendingRotationPathFor(h.historyFile));
  resetWitnessViews();
  const owner = h.open();
  await owner.flush();
  assert.equal(h.disk().events.at(-1).type, "OWNER_KEYS_ROTATED");
});

// ---------------------------------------------------------------- an attacker and the record

test("a planted or edited prepared-rotation record never makes the owner sign and never lets a rejected event in", async (t) => {
  const w = await startFakeWitness({ name: "tp-planted", seed: 312 });
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync" });
  const path = pendingRotationPathFor(h.historyFile);
  // 1. Garbage: ignored by the writers, removed by the owner's settle.
  writeFileSync(path, "{ not json", { mode: 0o600 });
  await h.owner.createAgent({ id: "agent:planted-1" });
  resetWitnessViews();
  h.open().close();
  assert.equal(existsSync(path), false);
  // 2. A genuine record from an aborted rotation, replayed: it blocks writes only until the owner asks the witness, which
  //    does not hold its head: discarded, nothing appended, no key file changed, nothing signed for it.
  const head = h.head();
  let capture;
  h.net.hook = (url, init) => {
    if (isKeyEvents(url, init)) { capture = readFileSync(path); return "drop"; }
    return undefined;
  };
  const aborted = h.open();
  await assert.rejects(aborted.rotateOwnerKey(), (e) => e.detail?.reason === "ROTATION_ABORTED");
  h.net.hook = undefined;
  const keyFile = readFileSync(ownerKeyPathFor(h.historyFile));
  writeFileSync(path, capture, { mode: 0o600 });
  const statementsBefore = w.state.statements.length;
  resetWitnessViews();
  const owner = h.open();
  await owner.createAgent({ id: "agent:planted-2" });
  assert.equal(existsSync(path), false, "discarded");
  assert.equal(h.head().position, head.position + 1);
  assert.equal(h.disk().events.at(-1).type, "AGENT_CREATED");
  assert.deepEqual(readFileSync(ownerKeyPathFor(h.historyFile)), keyFile);
  assert.ok(w.state.statements.slice(statementsBefore).every((s) => s.statement.head.position !== head.position + 1 || s.statement.head.hash === h.disk().eventHistoryHashes[head.position + 1]),
    "no statement for the replayed rotation's head");
  // 3. An edited record (its event re-signed by a stranger key, its head recomputed to match): the replay rules reject the
  //    event, so the record is OBSOLETE: it blocks nothing and is never appended, even when a witness is made to hold that head.
  const record = JSON.parse(capture.toString());
  const stranger = createOwnerKeyFile(join(h.directory, "stranger.json"), "owner:stranger");
  const state = h.disk();
  const forged = await signControlEvent(stranger, { ...record.event, id: "event:forged", timestamp: now(), data: { ownerKeys: record.event.data.ownerKeys } }, h.domain, state.head, "sha256");
  writeFileSync(path, JSON.stringify({ ...record, event: forged, previousHead: state.head }), { mode: 0o600 });
  resetWitnessViews();
  const third = h.open();
  await third.createAgent({ id: "agent:planted-3" });
  assert.equal(h.disk().events.at(-1).type, "AGENT_CREATED");
  assert.equal(h.disk().events.some((event) => event.id === "event:forged"), false);
  resetWitnessViews();
  h.open().close();
  assert.equal(existsSync(path), false, "an obsolete record is removed by the owner's settle");
});

test("an aborted rotation's record, captured and replayed: an edited seal-covered field makes it obsolete; replayed to a witness at r - 1, it is never completed without its staged keys (a detected alarm, not a rotation to a lost key)", async (t) => {
  const w = await startFakeWitness({ name: "tp-replay", seed: 334 });
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync" });
  const id = h.historyId();
  const path = pendingRotationPathFor(h.historyFile);
  let capture;
  h.net.hook = (url, init) => {
    if (isKeyEvents(url, init)) { capture = readFileSync(path); return "drop"; }
    return undefined;
  };
  await assert.rejects(h.owner.rotateOwnerKey(), (e) => e.detail?.reason === "ROTATION_ABORTED");
  h.net.hook = undefined;
  assert.equal(pendingFiles(h).length, 0, "a clean abort: record and staged keys removed");
  const record = JSON.parse(capture.toString());
  // Editing any sealed field (here: claiming nothing was staged) breaks the seal: the record is obsolete, writes proceed.
  writeFileSync(path, JSON.stringify({ ...record, staged: { ownerKey: false, nextKey: false } }), { mode: 0o600 });
  const { judgePendingRotation } = await import("../src/rotation-pending.ts");
  assert.equal(judgePendingRotation(h.disk(), readPendingRotation(path)).status, "OBSOLETE");
  // The genuine record, replayed: its owner-signed statement and event go to the witness (still at r - 1), and it is planted again.
  writeFileSync(path, capture, { mode: 0o600 });
  const replay = await fetch(`${w.url}/v1/histories/${id}/key-events`, { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ event: record.event, previousHead: { hash: record.previousHead.hash, position: record.previousHead.position }, eventHead: { hash: record.head.hash, position: record.head.position }, statement: record.statement }) });
  assert.equal(replay.status, 201, "the witness cannot tell a replayed owner-signed rotation from a live one");
  resetWitnessViews();
  const owner = h.open();
  await assert.rejects(owner.createAgent({ id: "agent:after-replay" }), (e) => e.code === "ROLLBACK_DETECTED" && /staged owner key file .* is gone/.test(e.message));
  assert.notEqual(h.disk().events.at(-1).type, "OWNER_KEYS_ROTATED", "never appended: its new owner key is gone");
});

// ---------------------------------------------------------------- commitments and bundles

test("§11.3: a witness learns the genesis commitment from the registration; commitNextKey is a commitment-only rotation it records like any other; a bundle for each key event", async (t) => {
  const w = await startFakeWitness({ name: "tp-commit", seed: 313 });
  t.after(() => w.close());
  // Creation: the genesis carries the commitment, so registering the history is enough (no key event, no bundle).
  const h = await setup([w], {}, 0);
  const id = h.historyId();
  assert.equal(log(w, id).some((line) => line.startsWith("ROTATED")), false, log(w, id).join(" | "));
  const epoch0 = w.histories.get(id).epochs[0];
  assert.ok(epoch0.nextKeyDigests !== undefined);
  assert.deepEqual(epoch0.nextKeyDigests, h.disk().ownerKeyEpochs[0].nextKeyDigests);
  assert.deepEqual(epoch0.nextKeyDigests, h.disk().events[0].data.nextKeyDigests);
  const info = await (await fetch(`${w.url}/v1/histories/${id}`)).json();
  assert.deepEqual(info.epochs[0].nextKeyDigests, epoch0.nextKeyDigests, "the wire serves the commitment");
  assert.deepEqual(await h.owner.exportKeyEvents(), [], "no owner key event yet");
  // A history without a commitment: commitNextKey records a commitment-only rotation (two-phase: the witness first).
  const bare = await setup([w], { mode: "async" }, 1, { nextKey: false });
  const bareId = bare.historyId();
  assert.equal(w.histories.get(bareId).epochs[0].nextKeyDigests, undefined);
  const committed = await bare.owner.commitNextKey();
  assert.equal(committed.emergency, false);
  assert.deepEqual(committed.witnesses.accepted, [w.url]);
  const epochs = w.histories.get(bareId).epochs;
  assert.equal(epochs.length, 2);
  assert.deepEqual(epochs[1].keys, epochs[0].keys, "the owner keys are unchanged");
  assert.deepEqual(epochs[1].nextKeyDigests, committed.nextKeyDigests);
  assert.equal(epochs[1].fromPosition, committed.head.position + 1);
  const bundle = JSON.parse(readFileSync(committed.bundle, "utf8"));
  assert.equal(bundle.event.type, "OWNER_KEYS_ROTATED");
  assert.equal(tp.validateKeyEventBundle(bundle), null);
  // export-key-events regenerates every bundle (the rotation's too, with the retired key's statement).
  const rotated = await bare.owner.rotateOwnerKey();
  assert.equal(rotated.preRotated, true);
  const exported = await bare.owner.exportKeyEvents();
  assert.deepEqual(exported.map((e) => [e.kind, e.position]), [["ROTATED", committed.head.position], ["ROTATED", rotated.head.position]]);
  assert.ok(exported.every((e) => e.error === undefined && existsSync(e.path)));
  assert.deepEqual((await bare.owner.exportKeyEvents({ since: rotated.head.position })).map((e) => e.position), [rotated.head.position]);
});

test("§11.3: a witness cut off during an emergency rotation takes the bundle through the admin route, then the owner continues", async (t) => {
  const a = await startFakeWitness({ name: "tp-bundle-a", seed: 314 }), b = await startFakeWitness({ name: "tp-bundle-b", seed: 315 });
  t.after(() => Promise.all([a.close(), b.close()]));
  const h = await setup([a, b], { mode: "sync" });
  const id = h.historyId();
  let cut = true;
  h.net.hook = (url) => (cut && url.origin === new URL(b.url).origin ? "drop" : undefined);
  const rotated = await h.owner.rotateOwnerKey({ emergency: true });
  const bundle = JSON.parse(readFileSync(rotated.bundle, "utf8"));
  const imported = await fetch(`${b.url}/v1/admin/key-events`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(bundle) });
  assert.equal(imported.status, 201, await imported.clone().text());
  assert.deepEqual(log(b, id).slice(-2).map((line) => line.split(" ")[0]), ["HEAD", "ROTATED"]);
  const again = await fetch(`${b.url}/v1/admin/key-events`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(bundle) });
  assert.equal(again.status, 200, "idempotent");
  cut = false;
  await h.owner.createAgent({ id: "agent:after" });
  await h.owner.flush();
  assert.deepEqual(b.latest(id), a.latest(id));
  assert.equal(h.owner.witnessStatus().rotationIncomplete, false);
});

// ---------------------------------------------------------------- supersede (§11.4)

/** An emergency, pre-rotated rotation while the witness is down, and an attacker with the leaked old key who pushes a head there. */
async function leakedKeyAttack(t, { name, seed, attackerPosition, options = {}, rotation = {} }) {
  const w = await startFakeWitness({ name, seed });
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync" }, 2, options);
  const id = h.historyId();
  const leaked = loadOwnerKeyFile(ownerKeyPathFor(h.historyFile));
  w.down = true;
  const rotated = await h.owner.rotateOwnerKey({ emergency: true, reason: "the owner key leaked", ...rotation });
  h.owner.close();
  w.down = false;
  const last = w.latest(id);
  const state = h.disk();
  const forgedHead = { hash: `0x${"ab".repeat(32)}`, position: attackerPosition(last, rotated.head.position), canonicalTime: last.canonicalTime + 1 };
  const bogus = await tp.signHeadStatement(leaked, { version: tp.HEAD_STATEMENT_VERSION, historyId: id, domain: state.genesis.domain, head: forgedHead, previous: { hash: last.hash, position: last.position } });
  const reply = await fetch(`${w.url}/v1/histories/${id}/heads`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(bogus) });
  assert.equal(reply.status, 201, "the witness has not recorded the rotation: the retired key still counts there (M2)");
  return { w, h, id, rotated, last, bogus, forgedHead };
}

for (const [label, attackerPosition] of [["past the rotation", (last, r) => r + 3], ["at a position ≤ r", (last) => last.position + 1]]) {
  test(`§11.4 supersede: a leaked old key's head ${label} is overridden by the owner's pre-rotated rotation; verify notes REMOTE_WITNESS_SUPERSEDED`, async (tc) => {
    const { w, h, id, rotated, last, bogus } = await leakedKeyAttack(tc, { name: `tp-sup-${label.length}`, seed: 320 + label.length, attackerPosition });
    assert.equal(rotated.preRotated, true);
    resetWitnessViews();
    const owner = h.open();
    await owner.createAgent({ id: "agent:after" });
    await owner.flush();
    const entries = w.entries.filter((e) => e.historyId === id);
    const superseded = entries.find((e) => e.kind === "SUPERSEDED");
    assert.ok(superseded, log(w, id).join(" | "));
    assert.equal(superseded.chain.statement.previous.position, last.position, "the chain resumes from the last good head");
    assert.deepEqual([superseded.supersededLatest.position, superseded.supersededCount], [bogus.statement.head.position, 1]);
    assert.deepEqual(w.latest(id), (({ hash, position, canonicalTime }) => ({ hash, position, canonicalTime }))(h.head()));
    assert.equal(w.histories.get(id).supersedes, 1);
    const report = await verifyHistoryWithWitnesses(h.historyFile, { witness: h.policy });
    assert.equal(report.ok, true, report.failures.join("\n"));
    assert.ok(report.notes.some((n) => n.startsWith("REMOTE_WITNESS_SUPERSEDED 1") && n.includes("the old key was probably compromised")), report.notes.join("\n"));
    assert.equal(report.remoteWitnesses[0].supersedes, 1);
    // The superseded head never counts again: resubmitted, it is 409 SUPERSEDED where the old key is still valid (≤ r),
    // SIGNATURE_INVALID past the rotation the witness now records.
    const resubmitted = await fetch(`${w.url}/v1/histories/${id}/heads`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(bogus) });
    const answer = await resubmitted.json();
    if (bogus.statement.head.position <= rotated.head.position) assert.deepEqual([resubmitted.status, answer.error.code], [409, "SUPERSEDED"]);
    else assert.deepEqual([resubmitted.status, answer.error.code], [400, "SIGNATURE_INVALID"]);
  });
}

test("§11.4: a rotation that is not pre-rotated cannot supersede: the conflict fails closed (ROLLBACK_DETECTED)", async (tc) => {
  const { h } = await leakedKeyAttack(tc, { name: "tp-sup-plain", seed: 330, attackerPosition: (last, r) => r + 2, options: { nextKey: false } });
  resetWitnessViews();
  const owner = h.open();
  await assert.rejects(owner.createAgent({ id: "agent:after" }), (e) => e.code === "ROLLBACK_DETECTED" && /not pre-rotated/.test(e.message));
  const report = await verifyHistoryWithWitnesses(h.historyFile, { witness: h.policy });
  assert.equal(report.remoteWitnessStatus, "ROLLBACK");
  assert.ok(report.notes.some((n) => n.startsWith("NO_NEXT_KEY_COMMITMENT")) === false, "the new epoch did commit");
});

test("§11.4: without a known last good head (no receipt in the process or the side file) the conflict fails closed", async (tc) => {
  const { h, w } = await leakedKeyAttack(tc, { name: "tp-sup-noL", seed: 331, attackerPosition: (last, r) => r + 2 });
  const path = witnessStatePathFor(h.historyFile);
  const doc = JSON.parse(readFileSync(path, "utf8"));
  for (const entry of Object.values(doc.witnesses)) delete entry.held;
  writeFileSync(path, JSON.stringify(doc), { mode: 0o600 });
  resetWitnessViews();
  const owner = h.open();
  await assert.rejects(owner.createAgent({ id: "agent:after" }), (e) => e.code === "ROLLBACK_DETECTED" && /knows no head the witness held/.test(e.message));
  assert.equal(w.entries.some((e) => e.kind === "SUPERSEDED"), false);
});

test("verify recommends a next-key commitment while the owner keys in force have none (the M2 residual)", async (t) => {
  const w = await startFakeWitness({ name: "tp-nocommit", seed: 332 });
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync" }, 1, { nextKey: false });
  const report = await verifyHistoryWithWitnesses(h.historyFile, { witness: h.policy });
  assert.ok(report.notes.some((n) => n.startsWith("NO_NEXT_KEY_COMMITMENT")), report.notes.join("\n"));
  await h.owner.commitNextKey();
  const after = await verifyHistoryWithWitnesses(h.historyFile, { witness: h.policy });
  assert.ok(!after.notes.some((n) => n.startsWith("NO_NEXT_KEY_COMMITMENT")));
});

test("readWitnessState keeps the last good head's receipt (held) of each witness", async (t) => {
  const w = await startFakeWitness({ name: "tp-held", seed: 333 });
  t.after(() => w.close());
  const h = await setup([w], { mode: "sync" }, 1);
  const doc = readWitnessState(witnessStatePathFor(h.historyFile));
  const held = doc.witnesses[w.origin].held;
  assert.equal(held.entry.kind, "HEAD");
  assert.equal(held.entry.signedStatement.statement.head.position, h.head().position);
  assert.equal(tp.verifyWitnessReceipt(held, [w.verifierKey]).ok, true);
});
